"""B-container-only neutral preparation for one-point FI smoke, never a campaign.

Compiles only the selected fixed workload, checks its complete golden, and
collects value-free allocated RF/SMEM and actual physical cache populations.
There is no SARA/GEREM analysis, fault injection, predictor or 10K manifest here.
"""
import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import shutil

from script.execution.campaign import atomic_json, fingerprint
from script.execution.config_options import config_text
from script.execution.ge_batch_experiment import measured, sha
from script.execution.fi_smoke_workload import (LLM_APP, LLM_CASE, LLM_CHECKPOINT,
    SMOKE_CASES, actual_llm_launches, compare_llm_cpu, contract, environment,
    output_spec, packet)


POPULATION_BUDGETS = {"max_decoded_bytes": 8 * 1024**3,
    "max_physical_bytes": 512 * 1024**2, "max_records": 8000010}
RUNTIME_CONFIG = "gcc-9.4.0/cuda-11080/release"


def workload_source_manifest(root, app):
    suffixes = {".cu", ".cuh", ".c", ".h", ".hpp", ".cc", ".cpp", ".json", ".py"}
    result = {}
    for directory in (root / "test_apps" / app, root / "test_apps/common"):
        for path in sorted(directory.rglob("*")):
            if path.is_file() and path.suffix in suffixes and "__pycache__" not in path.parts:
                result[str(path.relative_to(root))] = sha(path)
    return result


def runtime_environment(native, source_fingerprint):
    env = {key: value for key, value in os.environ.items()
        if key not in {"LD_PRELOAD", "LD_AUDIT", "LD_DEBUG", "LD_DEBUG_OUTPUT"}
        and not key.startswith("PTX_SIM_")
        and not (key.startswith("SARA_") and not key.startswith("SARA_"))}
    env.update(GPGPUSIM_ROOT=str(native), GPGPUSIM_CONFIG=RUNTIME_CONFIG,
        CUDA_INSTALL_PATH="/usr/local/cuda", PTXAS_CUDA_INSTALL_PATH="/usr/local/cuda",
        LD_LIBRARY_PATH=str(native / "lib" / RUNTIME_CONFIG) + ":/usr/local/cuda/lib64",
        PATH=str(native / "bin") + ":/usr/local/cuda/bin:/usr/local/bin:/usr/bin:/bin",
        SARA_VALIDATE_CPU="0", SARA_SOURCE_FINGERPRINT=source_fingerprint,
        SARA_POPULATION_REFERENCE_ACTIVE_THREADS="0")
    return env


def capture(case, role, *, binary, native, base_config, destination, assets, timeout, cpu=False):
    """One neutral producer; the native physical hook defines the population."""
    from script.execution.policy import require_container_execution
    require_container_execution()
    if role not in {"fi-golden", "population", "cache-population"}:
        raise ValueError("FI smoke permits only neutral golden and population producers")
    work = Path(destination)
    work.mkdir(parents=True, exist_ok=False)
    workload = contract(case)
    for name, path in assets.items():
        shutil.copy2(path, work / name)
    for path in base_config.parent.iterdir():
        if path.is_file() and path.suffix in {".xml", ".icnt"}:
            shutil.copy2(path, work / path.name)
    cache = role == "cache-population"
    options = {"-profile": "0", "-fi_probe_only": "0", "-total_cycle_rand": "-1",
        "-per_warp": "0", "-kernel_n": "0", "-last_cycle": "0",
        "-exact_trace": "0", "-regfile_trace": "0", "-exact_trace_static_cfg": "0",
        "-cache_state_ledger": "1" if cache else "0"}
    forbidden = {"-population_inventory_file", "-host_copy_ledger_file"}
    if role == "population":
        options["-population_inventory_file"] = str(work / "population.jsonl.gz")
    if cache:
        options.update({"-host_copy_ledger_file": str(work / "memory.jsonl"),
            "-host_copy_ledger_budget_bytes": "2147483648",
            "-cache_data_realizer_version": "2",
            "-cache_data_realizer_identity": "all-active-physical-cache-tag57-and-data-invalid-pending-single-bit-v2"})
    raw = "\n".join(line for line in base_config.read_text().splitlines()
        if not line.split("#", 1)[0].split() or line.split("#", 1)[0].split()[0] not in forbidden)
    (work / "gpgpusim.config").write_text(config_text(raw, options))
    native_files = native / "compiled-source-files.json"
    if not native_files.is_file():
        raise ValueError("smoke requires the actual compiled native source manifest")
    native_source = json.loads(native_files.read_text())
    if not native_source:
        raise ValueError("empty compiled native source manifest")
    atomic_json(work / "native-source-files.json", native_source)
    source_id = fingerprint(native_source)
    env = runtime_environment(native, source_id)
    env.update(environment(case))
    env["SARA_VALIDATE_CPU"] = "1" if cpu else "0"
    # Plain transport avoids the native gzip emitter's old decoded 1-GiB bound.
    # Repacking is lossless after closure; no population span is filtered.
    env["SARA_POPULATION_CODEC"] = "plain" if role == "population" else "gzip"
    if cache:
        env.update(SARA_CACHE_CAPTURE_PROFILE="changes", SARA_CACHE_SEMANTICS_PROFILE="storage-population-v1")
    image_id = env.get("SARA_IMAGE_ID", "")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        raise ValueError("actual Docker image identity required")
    previous_limit = None
    if role == "population":
        import resource
        previous_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
        if previous_limit[1] != resource.RLIM_INFINITY and previous_limit[1] < POPULATION_BUDGETS["max_decoded_bytes"]:
            raise ValueError("complete smoke population exceeds declared file bound")
        resource.setrlimit(resource.RLIMIT_FSIZE, (POPULATION_BUDGETS["max_decoded_bytes"], previous_limit[1]))
    try:
        receipt = measured(["./" + workload["app"], *workload["arguments"]], work,
            work / "run.log", env, timeout)
    finally:
        if previous_limit is not None:
            resource.setrlimit(resource.RLIMIT_FSIZE, previous_limit)
    if role == "population":
        from script.execution.population_repack import pack_closed_population
        plain, packed = work / "population.native.jsonl", work / "population.jsonl.gz"
        packed.rename(plain)
        transport = pack_closed_population(plain, packed,
            max_decoded_bytes=POPULATION_BUDGETS["max_decoded_bytes"],
            max_physical_bytes=POPULATION_BUDGETS["max_physical_bytes"])
        atomic_json(work / "population-repack.json", transport)
        plain.unlink()  # pack_closed_population checked complete decoded SHA/CRC.
    text = (work / "run.log").read_text()
    if "GPGPU-Sim" not in text or "GPUFI_UNSUPPORTED_" in text or "GPUFI_INVALID_CONFIGURATION" in text:
        raise ValueError("actual supported fault-free simulator execution required")
    outputs = packet(work / "run.log", case)
    cycles = re.findall(r"gpu_tot_sim_cycle\s*=\s*(\d+)", text)
    if not cycles or int(cycles[-1]) <= 0:
        raise ValueError("actual positive fault-free GPU cycle count required")
    libraries = {str(path.relative_to(native)): sha(path)
        for path in (native / "lib" / RUNTIME_CONFIG).iterdir() if path.is_file()}
    if not libraries:
        raise ValueError("actual native library identities required")
    result = {"schema": "sara-fi-smoke-neutral-capture-v1", "case": case,
        "arguments": workload["arguments"], "workload_contract": workload,
        "typed_output_contract": workload["typed_output_contract"],
        "cache_state": cache, "cache_data_realizer_version": 2 if cache else 1,
        "collection": role, "minimal_population": False,
        "actual_binary_sha256": sha(binary), "simulator_libraries": libraries,
        "native_source_fingerprint": source_id, "image_id": image_id,
        "base_config_sha256": sha(base_config), "effective_config_sha256": sha(work / "gpgpusim.config"),
        "output": outputs, "gpu_cycles": int(cycles[-1]), "process": receipt,
        "classification_uses_FI_answers": False, "manifest_draws": 0,
        "formal_campaign_admission": False, "predictor_executed": False}
    if role == "population":
        result["population_transport"] = {"native_codec": "plain", "stored_codec": "gzip",
            "decode_budgets": POPULATION_BUDGETS, "logical_population_modified": False}
    if case == LLM_CASE:
        result["actual_computational_launch_uids"] = actual_llm_launches(work / "run.log")
    atomic_json(work / "output-spec.json", output_spec(work / "run.log", case))
    atomic_json(work / "capture.json", result)
    return result


def register_populations(capture_dir):
    """Executor populations from the complete native hook stream, no draws."""
    from script.execution.fault_manifest import FaultPopulation
    from script.execution.population_inventory import read_stream, validate_lifecycle, validate_production_blockers
    metadata = json.loads((capture_dir / "capture.json").read_text())
    stream = read_stream(capture_dir / "population.jsonl.gz", decode_budgets=POPULATION_BUDGETS)
    validate_production_blockers(stream["blockers"])
    if stream["header"].get("schema") != "sara-allocated-population-v1":
        raise ValueError("FI smoke requires full native numeric hook selectors")
    rows = {"rf": [], "smem": []}
    for row in stream["spans"]:
        validate_lifecycle(row, stream["header"])
        if row["mapping_supported"] is not True:
            raise ValueError("unresolved actual storage mapping cannot be omitted")
        if row["component"] == "rf":
            rows["rf"].append({key: row[key] for key in ("component", "target", "cycle_start", "cycle_stop",
                "bit_start", "bit_count", "hook_selectors", "ack_expected")})
        else:
            for address in range(row["byte_start"], row["byte_start"] + row["byte_count"]):
                span = {key: deepcopy(row[key]) for key in ("target", "cycle_start", "cycle_stop",
                    "hook_selectors", "ack_expected", "lifecycle")}
                span["target"]["byte_addr"] = address
                span["ack_expected"]["byte_addr"] = str(address)
                span.update(component="smem", bit_start=8 * address, bit_count=8)
                rows["smem"].append(span)
    result = {}
    for component in ("rf", "smem"):
        if not stream["mass"][component]:
            if rows[component]:
                raise ValueError("zero population mass has nonempty spans")
            result[component] = None
            continue
        inventory = {"schema_version": 1, "population_id": metadata["case"] + "-FI-smoke-" + component,
            "fault_model": "active-allocated-simulator-rf-smem-single-bit-v1",
            "coordinate_system": "simulator_hook_allocated_storage", "time_basis": "simulator_global_cycle",
            "coverage_certified": False, "spans": rows[component]}
        population = FaultPopulation(inventory)
        if population.mass != stream["mass"][component]:
            raise ValueError("smoke executor population changed complete native bit-cycle mass")
        result[component] = {"inventory": inventory, "population": population}
    return result, {"native_mass": stream["mass"], "header": stream["header"],
        "footer": stream["footer"], "transport": stream["transport"]}


def prepare(args):
    from script.execution.policy import require_container_execution
    require_container_execution()
    root = Path(__file__).resolve().parents[2]
    workload = contract(args.case)
    args.output.mkdir(parents=True, exist_ok=False)
    build = args.output / "build"
    build.mkdir()
    binary = build / workload["app"]
    source = (root / "test_apps" / LLM_APP / "forward_prefix2.cu" if args.case == LLM_CASE else
        root / "test_apps" / workload["app"] / "result_gen" / (workload["app"] + "_0.cu"))
    source_files = workload_source_manifest(root, workload["app"])
    compile_argv = ["/usr/local/cuda/bin/nvcc", "-std=c++14", "-g", "--cudart=shared", "-lcudart",
        "-arch=" + args.target, "-I", str(root)]
    if args.case == LLM_CASE:
        compile_argv.append("-DUSE_CUDA")
    compile_argv += [str(source), "-o", str(binary)]
    commands = [compile_argv, ["/usr/local/cuda/bin/cuobjdump", "-xptx", "all", str(binary)]]
    for index, command in enumerate(commands):
        measured(command, build, build / ("compile-%d.log" % index), dict(os.environ), 240)
    ptx = sorted(build.glob("*.ptx"))
    if not ptx:
        raise ValueError("actual emitted target PTX required")
    assets = {workload["app"]: binary}
    assets.update({Path(relative).name: root / "test_apps" / relative
        for relative in workload["env_files"].values()})
    cpu_receipt = None
    if args.case == LLM_CASE:
        if args.checkpoint is None:
            raise ValueError("explicit retained pinned Stories260K checkpoint required; no download path exists")
        from script.execution.tiny_llm_checkpoint import cached_bytes
        _, checkpoint_receipt = cached_bytes(args.checkpoint)
        assets[LLM_CHECKPOINT] = args.checkpoint.resolve(strict=True)
        cpu_binary = build / "CPU-prefix2"
        cpu_source = root / "test_apps" / LLM_APP / "cpu_reference_prefix2.c"
        cpu_compile = ["/usr/bin/gcc", "-O2", "-std=c11", "-D_GNU_SOURCE", "-fopenmp",
            str(cpu_source), "-lm", "-o", str(cpu_binary)]
        measured(cpu_compile, build, build / "compile-cpu.log", dict(os.environ), 240)
        measured([str(cpu_binary), str(args.checkpoint.resolve(strict=True))], build,
            build / "CPU-prefix2.log", dict(os.environ), 600)
        cpu_receipt = {"compile_argv": cpu_compile, "checkpoint": checkpoint_receipt,
            "CPU_source_sha256": sha(cpu_source),
            "CPU_upstream_sha256": sha(root / "test_apps" / LLM_APP / "upstream_cpu/run.c")}
    elif args.checkpoint is not None:
        raise ValueError("checkpoint input belongs only to the authorized final LLM smoke")
    captures = {}
    for role, dirname in (("fi-golden", "golden"), ("population", "common-rf-smem"),
                           ("cache-population", "common-cache")):
        captures[role] = capture(args.case, role, binary=binary, native=args.simulator_root.resolve(strict=True),
            base_config=args.base_config.resolve(strict=True), destination=args.output / dirname,
            assets=assets, timeout=args.timeout, cpu=args.case != LLM_CASE and role == "fi-golden")
    golden = captures["fi-golden"]
    if args.case == LLM_CASE:
        cpu_receipt["complete_output_check"] = compare_llm_cpu(build / "CPU-prefix2.log", args.output / "golden/run.log")
    elif "CPU_ORACLE_PASS application=" + workload["app"] not in (args.output / "golden/run.log").read_text():
        raise ValueError("independent complete-output CPU golden did not pass")
    for name, result in captures.items():
        if any(result[key] != golden[key] for key in ("output", "gpu_cycles", "actual_binary_sha256", "simulator_libraries")):
            raise ValueError("neutral producer changed complete output, cycles, binary or native libraries: " + name)
    result = {"schema": "sara-FI-smoke-preparation-v1", "case": args.case, "application": workload["app"],
        "target": args.target, "typed_output_contract": workload["typed_output_contract"],
        "binary_sha256": sha(binary), "PTX": {path.name: sha(path) for path in ptx},
        "build_commands": commands, "CPU_reference": cpu_receipt,
        "independent_CPU_complete_output_check": True,
        "neutral_profiles_same_complete_output_cycles_and_binary": True,
        "asset_sha256": {name: sha(path) for name, path in assets.items()},
        "workload_source_files_sha256": source_files,
        "workload_source_fingerprint": fingerprint(source_files),
        "preparation_code_sha256": {name: sha(root / name) for name in
            ("script/execution/fi_smoke_prepare.py", "script/execution/fi_smoke_workload.py")},
        "formal_campaign_admission": False, "predictor_executed": False, "FI_executed": False,
        "master_10000_created": False, "smoke_draws_created": 0}
    atomic_json(args.output / "preflight.json", result)
    return result


def main(argv=None):
    from script.execution.policy import require_container_execution
    require_container_execution()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=SMOKE_CASES, required=True)
    parser.add_argument("--target", choices=("sm_75", "sm_86"), required=True)
    for name in ("simulator-root", "base-config", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--timeout", type=int, default=3600)
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 14400:
        parser.error("bounded neutral producer timeout required")
    print(json.dumps(prepare(args), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
