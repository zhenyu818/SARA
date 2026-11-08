"""One FI draw per actual storage group for one fixed application/SM.

The host coordinator serializes applications and SMs. This entry has no next
application, campaign-budget or predictor mode. A fresh neutral preparation is
required; one seed-2026 with-replacement draw is saved for each nonempty group.
Masked, SDC and application DUE are accepted scientific outcomes. Hook/model,
resource and infrastructure failures remain failed smoke checks.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import signal

from script.execution.campaign import CampaignLedger, atomic_json, fingerprint
from script.execution.config_options import config_text
from script.execution.fi_smoke_prepare import (RUNTIME_CONFIG, register_populations,
    runtime_environment, workload_source_manifest)
from script.execution.fi_smoke_workload import SMOKE_CASES, contract, environment, output_spec, packet
from script.execution.ge_batch_experiment import sha


GROUPS = ("rf", "smem", "l1d", "l2", "valid_l1d", "valid_l2")
ARCHITECTURES = {"SM75": "sm_75", "SM86": "sm_86"}


def _fault_base(text, cycles):
    # Strip all scientific observers. Root's run_trial appends only the exact
    # sampled injection options and optional native valid-resident contract.
    absent = {"-population_inventory_file", "-cache_capacity_file", "-host_copy_ledger_file",
        "-host_copy_ledger_budget_bytes", "-exact_trace_file", "-regfile_trace_file"}
    text = "\n".join(line for line in text.splitlines()
        if not line.split("#", 1)[0].split() or line.split("#", 1)[0].split()[0] not in absent)
    return config_text(text, {"-exact_trace": "0", "-regfile_trace": "0",
        "-exact_trace_static_cfg": "0", "-cache_state_ledger": "0",
        "-gpgpu_max_cycle": str(10 * cycles)})


def _check_preparation(prepared, case, architecture, native):
    preflight = json.loads((prepared / "preflight.json").read_text())
    if (preflight.get("schema") != "sara-FI-smoke-preparation-v1" or preflight.get("case") != case
            or preflight.get("target") != ARCHITECTURES[architecture]
            or preflight.get("FI_executed") is not False
            or preflight.get("predictor_executed") is not False
            or preflight.get("master_10000_created") is not False
            or preflight.get("independent_CPU_complete_output_check") is not True
            or preflight.get("neutral_profiles_same_complete_output_cycles_and_binary") is not True):
        raise ValueError("fresh exact fixed-workload smoke preparation required")
    workload = contract(case)
    if preflight.get("application") != workload["app"] or preflight.get("typed_output_contract") != workload["typed_output_contract"]:
        raise ValueError("smoke workload or typed output identity changed")
    root = Path(__file__).resolve().parents[2]
    current_sources = workload_source_manifest(root, workload["app"])
    if (preflight.get("workload_source_files_sha256") != current_sources
            or preflight.get("workload_source_fingerprint") != fingerprint(current_sources)):
        raise ValueError("actual workload source identity changed after smoke preparation")
    for name in ("script/execution/fi_smoke_prepare.py", "script/execution/fi_smoke_workload.py"):
        if preflight.get("preparation_code_sha256", {}).get(name) != sha(root / name):
            raise ValueError("actual neutral preparation code changed before FI smoke")
    native_source_id = fingerprint(json.loads((native / "compiled-source-files.json").read_text()))
    libraries = {str(path.relative_to(native)): sha(path)
        for path in (native / "lib" / RUNTIME_CONFIG).iterdir() if path.is_file()}
    captures = {}
    for dirname, role in (("golden", "fi-golden"), ("common-rf-smem", "population"),
                           ("common-cache", "cache-population")):
        capture = prepared / dirname
        value = json.loads((capture / "capture.json").read_text())
        if (value.get("schema") != "sara-fi-smoke-neutral-capture-v1" or value.get("case") != case
                or value.get("collection") != role or value.get("simulator_libraries") != libraries
                or value.get("typed_output_contract") != workload["typed_output_contract"]
                or value.get("native_source_fingerprint") != native_source_id
                or value.get("image_id") != os.environ.get("SARA_IMAGE_ID")
                or value.get("actual_binary_sha256") != preflight["binary_sha256"]
                or packet(capture / "run.log", case) != value.get("output")
                or sha(capture / workload["app"]) != preflight["binary_sha256"]):
            raise ValueError("neutral smoke capture identity changed: " + dirname)
        for name, expected in preflight["asset_sha256"].items():
            if sha(capture / name) != expected:
                raise ValueError("smoke deployed asset changed: " + name)
        if sha(capture / "gpgpusim.config") != value["effective_config_sha256"]:
            raise ValueError("neutral effective config changed")
        if json.loads((capture / "output-spec.json").read_text()) != output_spec(capture / "run.log", case):
            raise ValueError("complete typed output specification changed after neutral capture")
        captures[dirname] = value
    golden = captures["golden"]
    if any(any(value[key] != golden[key] for key in
               ("output", "gpu_cycles", "actual_binary_sha256", "simulator_libraries"))
           for value in captures.values()):
        raise ValueError("neutral smoke profiles do not share their complete computation")
    return preflight, captures


def execute(args):
    from script.execution.policy import require_container_execution
    require_container_execution()
    # Import the executor only after container admission, never as a local test.
    from script.execution.fi_campaign import run_trial, STOP, validate_site_binding
    from script.execution.cache_valid_resident import cache_populations, attach_valid_resident_contracts
    prepared, native = args.prepared.resolve(strict=True), args.simulator_root.resolve(strict=True)
    preflight, captures = _check_preparation(prepared, args.case, args.architecture, native)
    args.output.mkdir(parents=True, exist_ok=False)
    with (args.output / "smoke.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        workload = contract(args.case)
        registered, register_audit = register_populations(prepared / "common-rf-smem")
        caches = cache_populations(prepared / "common-cache")
        if set(caches) != set(GROUPS[2:]):
            raise ValueError("actual whole and valid-resident L1D/L2 groups required")
        populations = dict(registered, **caches)
        atomic_json(args.output / "register-population-audit.json", register_audit)
        source_id = captures["golden"]["native_source_fingerprint"]
        os.environ.update(runtime_environment(native, source_id))
        def stop(*_):
            STOP.set()
        for signum in (signal.SIGTERM, signal.SIGINT):
            signal.signal(signum, stop)
        summary = {"schema": "sara-FI-one-point-smoke-v1", "case": args.case,
            "application": workload["app"], "architecture": args.architecture,
            "seed": 2026, "sampling": "with_replacement", "draws_per_nonempty_group": 1,
            "group_order": list(GROUPS), "results": [], "complete": False,
            "preflight_sha256": sha(prepared / "preflight.json"),
            "typed_output_contract": workload["typed_output_contract"],
            "formal_campaign_admission": False, "predictor_executed": False,
            "population_accuracy_or_speedup_claim": False,
            "cleanup_policy": "host may remove smoke-only outputs after terminal verification; keep code and minimal fixtures"}
        atomic_json(args.output / "smoke-summary.json", summary)
        for group in GROUPS:
            entry = populations[group]
            if entry is None or entry["population"] is None:
                summary["results"].append({"group": group, "status": "N/A", "population_mass": 0})
                atomic_json(args.output / "smoke-summary.json", summary)
                continue
            if STOP.is_set():
                raise RuntimeError("smoke interrupted before dispatch; no fault outcome")
            population = entry["population"]
            if population.mass <= 0:
                raise ValueError("nonempty smoke group requires positive actual mass")
            component = group.replace("valid_", "")
            stream = "FI-smoke-" + workload["app"] + "-" + args.architecture + "-" + group
            manifest = population.sample(1, 2026, stream)
            if group.startswith("valid_"):
                manifest = attach_valid_resident_contracts(manifest, entry["residencies"])
            if len(manifest["trials"]) != 1 or manifest["sampling"] != "with_replacement" or manifest["seed"] != 2026:
                raise ValueError("exactly one saved random smoke draw required")
            trial = manifest["trials"][0]
            validate_site_binding(trial)
            group_dir = args.output / group
            group_dir.mkdir()
            atomic_json(group_dir / "inventory.json", entry["inventory"])
            atomic_json(group_dir / "manifest.json", manifest)
            capture_dir = prepared / ("common-cache" if component in {"l1d", "l2"} else "common-rf-smem")
            assets = {name: capture_dir / name for name in preflight["asset_sha256"]}
            assets.update({path.name: path for path in capture_dir.iterdir() if path.suffix in {".xml", ".icnt"}})
            asset_sha = {name: sha(path) for name, path in assets.items()}
            golden = captures["golden"]
            spec = {"schema_version": 1, "purpose": "correctness", "campaign_kind": "one-point-FI-smoke-only",
                "command": ["./" + workload["app"], *workload["arguments"]],
                "environment": environment(args.case), "assets": asset_sha, "assets_sha256": asset_sha,
                "typed_output_contract": workload["typed_output_contract"], "retain_work": True,
                "record_trial_costs": False, "validation_only": True,
                "timeout_seconds": args.timeout, "base_config_text": _fault_base(
                    (capture_dir / "gpgpusim.config").read_text(), golden["gpu_cycles"]),
                "population_fingerprint": population.identity, "input_fingerprint": fingerprint(preflight),
                "fault_model": population.inventory["fault_model"], "cache_execution_model": "functional-snapshot-cache-v3",
                "simulation_cycle_watchdog": {"cycle_limit": 10 * golden["gpu_cycles"],
                    "golden_cycles": golden["gpu_cycles"], "factor": 10,
                    "rule": "factor_times_actual_fault_free_cycles",
                    "class": "DUE_detected_execution_budget_exceeded", "administrative_process_timeout_is_DUE": False},
                "formal_campaign_admission": False, "smoke_group": group}
            spec["execution_code"] = {name: sha(Path(__file__).resolve().parents[2] / name) for name in
                ("script/execution/fi_smoke.py", "script/execution/fi_smoke_prepare.py",
                 "script/execution/fi_smoke_workload.py", "script/execution/fi_campaign.py",
                 "script/common/outcome_oracle.py", "script/execution/cache_valid_resident.py",
                 "script/execution/trial_environment.py")}
            ledger = CampaignLedger(group_dir / "records", spec, manifest["trials"], False, target_count=1)
            outputs = json.loads((prepared / "golden/output-spec.json").read_text())
            trial_id, result = run_trial(trial, spec, assets, ledger.directory, prepared / "golden/run.log", outputs)
            if trial_id != trial["trial_id"] or result.get("status") != "complete" or result.get("outcome") not in {"Masked", "SDC", "DUE"}:
                atomic_json(group_dir / "failed-smoke.json", {"trial_id": trial_id, "result": result})
                raise RuntimeError("incomplete FI smoke; inspect actual hook/model/resource failure, not a synthetic label")
            record = ledger.commit(trial_id, result)
            row = {"group": group, "component": component, "status": "complete",
                "outcome": record["outcome"], "population_mass": population.mass,
                "population_fingerprint": population.identity, "manifest_sha256": sha(group_dir / "manifest.json"),
                "record_fingerprint": record["record_fingerprint"], "site_id": trial["site_id"],
                "outcome_required_to_be_Masked": False}
            atomic_json(ledger.completion_path("smoke-completion.json"), row)
            summary["results"].append(row)
            atomic_json(args.output / "smoke-summary.json", summary)
        summary["complete"] = True
        summary["completed_injections"] = sum(row["status"] == "complete" for row in summary["results"])
        atomic_json(args.output / "smoke-summary.json", summary)
        print(json.dumps(summary, sort_keys=True))
    return 0


def main(argv=None):
    from script.execution.policy import require_container_execution
    require_container_execution()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=SMOKE_CASES, required=True)
    parser.add_argument("--architecture", choices=tuple(ARCHITECTURES), required=True)
    for name in ("prepared", "simulator-root", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=3600)
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 14400:
        parser.error("bounded FI smoke timeout required")
    return execute(args)


if __name__ == "__main__":
    raise SystemExit(main())
