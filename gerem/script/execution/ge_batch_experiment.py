"""Small GE-SpMM experiment driver; every scientific command runs in Docker.

An explicit already-built simulator may be supplied as a compilation cache.
Its library, executable, PTX and source identities are recorded, never relabeled
as a newly compiled program. The clean README build produces the same inputs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import time

from script.execution.campaign import atomic_json, fingerprint
from script.execution.process_metrics import MeasuredChild
from script.execution.config_options import config_text
from script.common.outcome_oracle import _load_log_summary, _validate_raw_summary
from script.execution.batch_workload import DEFAULT_CASE, contract, environment, output_regions


def _population_budgets(args, metadata=None):
    explicit = getattr(args, 'population_decode_budgets', None)
    if explicit is not None:
        return explicit
    if metadata is not None:
        recorded = metadata.get('population_transport', {}).get('decode_budgets')
        if recorded is not None:
            return recorded
    if getattr(args, 'case', (metadata or {}).get('case')) == 'pathfinder-multilaunch':
        # File/transport bounds only. This does not change the population or
        # fault labels, and is the same for both SM profiles and every method.
        return dict(max_decoded_bytes=8 * 1024**3,
                    max_physical_bytes=512 * 1024**2, max_records=8000010)
    return None


def sha(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def native_library_fingerprints(runtime):
    """Hash each immutable native inode once, retaining every library name.

    ``runtime`` is the simulator runtime root. Library aliases remain separate
    map entries, but aliases of one physical inode share its read during this
    invocation only. Every alias is checked immediately and again at the end;
    this is neither a persisted digest cache nor permission to trust old bytes.
    """
    runtime = Path(runtime)
    directory = runtime / 'lib' / 'gcc-9.4.0/cuda-11080/release'
    def identity(path):
        observed = path.stat()
        return observed, (observed.st_dev, observed.st_ino, observed.st_size,
            observed.st_mtime_ns, observed.st_ctime_ns)
    _, directory_identity = identity(directory)
    digests, aliases, result = {}, [], {}
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        observed, key = identity(path)
        if not stat.S_ISREG(observed.st_mode):
            continue
        if key not in digests:
            digests[key] = sha(path)
        if identity(path)[1] != key:
            raise ValueError('native library changed during identity loading: ' + path.name)
        aliases.append((path, key))
        result[str(path.relative_to(runtime))] = digests[key]
    for path, key in aliases:
        if identity(path)[1] != key:
            raise ValueError('native library alias changed during identity loading: ' + path.name)
    if identity(directory)[1] != directory_identity:
        raise ValueError('native library directory changed during identity loading')
    return result


def packet(path, case=DEFAULT_CASE, *, text=None):
    """Check all raw outputs once, optionally using this caller's fresh read."""
    from script.execution.method_input_context import current_context, read_text
    context = current_context(path)
    if context is None:
        # Collector/preflight execution is independent: no parsed snapshot from
        # its parent or another method is available or trusted here.
        summary = _load_log_summary(Path(path), text=text)
    else:
        source_text = read_text(path)
        if text is not None and text != source_text:
            raise ValueError('raw-output text differs from this method verified input')
        def load():
            context.count(path, 'raw_output_summary_decodes')
            value = _load_log_summary(Path(path), text=source_text)
            value['output_set'] = frozenset(value['output_set'])
            return value
        summary = context.cached(path, 'raw-output-summary-v1', load)
    check = _validate_raw_summary(summary)
    if not check["valid"]:
        raise ValueError("incomplete raw output: " + str(check))
    result = {name: {key: row[key] for key in ('dtype', 'count', 'hexbytes')}
        for name, row in summary['raw_outputs'].items()}
    expected = {row['name']:(row['dtype'],row['count']) for row in contract(case)['outputs']}
    if {name: (row["dtype"], row["count"]) for name, row in result.items()} != expected:
        raise ValueError("all fixed-workload terminal values must be present")
    return result


def measured(argv, cwd, log, env, timeout, *, persist_diagnostics=True):
    """Execute/reap the real child; optional validation I/O is explicit.

    Complete aggregate methods already have an enclosing performance/resource
    window and retained raw logs. Their nested collectors must not add two
    full-log SHA scans and durable diagnostic receipts inside that window.
    Default standalone/preflight behavior retains the original diagnostics.
    """
    if type(persist_diagnostics) is not bool:
        raise ValueError('explicit diagnostic persistence boolean required')
    begin = time.perf_counter()
    interruption = None
    with Path(log).open("wb") as stream:
        child = MeasuredChild(argv, cwd=str(cwd), env=env, stdout=stream, stderr=-2)
        while child.poll() is None:
            if time.perf_counter() - begin > timeout:
                interruption = "administrative_process_timeout_not_DUE"
                child.stop(grace_seconds=0.1)
                break
            time.sleep(0.05)
    receipt = {"argv": argv, "exit_status": child.returncode,
        "interruption": interruption, "wall_seconds": time.perf_counter() - begin,
        "exclusive_child_metrics": child.metrics()}
    if persist_diagnostics:
        receipt['log_sha256'] = sha(log)
        atomic_json(str(log) + ".process.json", receipt)
    else:
        receipt.update(log_sha256=None, log_bytes_hashed=False,
            separate_process_receipt_persisted=False,
            diagnostic_evidence_policy='raw log retained; optional SHA and process JSON omitted from aggregate task')
    if interruption or child.returncode:
        raise RuntimeError("capture failed, not a fault outcome: " + str(receipt))
    return receipt


def collection_diagnostics_deferred(args):
    """Only a method's fresh minimal collector may omit optional diagnostics."""
    value = getattr(args, 'defer_diagnostics', False)
    if type(value) is not bool:
        raise ValueError('explicit collection diagnostic policy required')
    if value and (not getattr(args, 'minimal_population', False)
            or getattr(args, 'collection', 'sara') not in {'sara', 'gerem-rf', 'gerem-smem', 'gerem-cache'}
            or getattr(args, 'validate_cpu', False)):
        raise ValueError('diagnostic omission is limited to own minimal aggregate collection')
    return value


def native_source_identity(simulator, *, require_compiled_manifest=False):
    """Use the compiled identity; aggregate collection never discovers a tree."""
    simulator = Path(simulator)
    source_manifest = simulator / 'compiled-source-files.json'
    if source_manifest.is_file():
        native_source = json.loads(source_manifest.read_text())
    elif require_compiled_manifest:
        raise ValueError('own aggregate collection requires the compiled native source manifest; no timed recursive discovery')
    else:
        native_source = {str(path.relative_to(simulator)): sha(path)
            for directory in (simulator / 'src', simulator / 'libcuda')
            for path in directory.rglob('*') if path.is_file() and path.suffix in ('.h', '.cc', '.cpp', '.c')}
    if not native_source:
        raise ValueError('compiled native source identities are required')
    return native_source


def capture(args):
    defer_diagnostics = collection_diagnostics_deferred(args)
    workload = contract(getattr(args, 'case', DEFAULT_CASE))
    work = args.output.resolve()
    work.mkdir(parents=True, exist_ok=False)
    base = args.base_config.resolve(strict=True)
    simulator = args.simulator_root.resolve(strict=True)
    executable = args.executable.resolve(strict=True)
    component = getattr(args, 'component', None)
    minimal = bool(getattr(args, 'minimal_population', False))
    if minimal and component not in ('rf', 'smem', 'l1d', 'l2'):
        raise ValueError('minimal collection needs one actual component')
    if minimal and args.cache_state != (component in ('l1d', 'l2')):
        raise ValueError('component and actual cache collection disagree')
    for path in base.parent.iterdir():
        if path.is_file() and path.suffix in (".xml", ".icnt"):
            shutil.copy2(path, work / path.name)
    shutil.copy2(executable, work / workload['app'])
    root = Path(__file__).resolve().parents[2]
    for relative in workload['env_files'].values():
        shutil.copy2(root/'test_apps'/relative, work/Path(relative).name)
    options = {"-profile": "1", "-fi_probe_only": "0", "-exact_trace": "1",
        "-exact_trace_jsonl": "0", "-exact_trace_codec": "gzip",
        "-exact_trace_static_cfg": "0", "-exact_trace_file": str(work / "trace.json.gz"),
        "-regfile_trace": "0", "-population_inventory_file": str(work / "population.jsonl.gz"),
        "-host_copy_ledger_file": str(work / "memory.jsonl"),
        "-host_copy_ledger_budget_bytes": "2147483648",
        "-cache_state_ledger": "1" if args.cache_state else "0"}
    if minimal:
        # Profile 1 also computes legacy per-cycle maximum-register/shader
        # statistics that neither method consumes. Explicit no-injection
        # profile 0 retains the same post-core observer phase without them.
        options.update({'-profile': '0', '-total_cycle_rand': '-1',
            '-per_warp': '0', '-kernel_n': '0', '-last_cycle': '0'})
    if args.cache_state:
        options.update({"-cache_data_realizer_version": "2",
            "-cache_data_realizer_identity": "all-active-physical-cache-tag57-and-data-invalid-pending-single-bit-v2"})
        # Cache geometry/residency already includes its complete population.
        # An additional allocated-RF dump is unrelated to a cache condition.
        options.pop("-population_inventory_file")
    base_text = base.read_text()
    if args.cache_state:
        base_text = "\n".join(line for line in base_text.splitlines()
            if not line.split("#", 1)[0].split() or line.split("#", 1)[0].split()[0] != "-population_inventory_file")
    if not args.cache_state and args.collection != "sara":
        options.pop("-host_copy_ledger_file")
        base_text = "\n".join(line for line in base_text.splitlines()
            if not line.split("#", 1)[0].split() or line.split("#", 1)[0].split()[0] != "-host_copy_ledger_file")
    if args.collection in ("gerem-rf", "gerem-smem", "gerem-cache", "fi-golden", "population", "cache-population"):
        if args.cache_state and args.collection not in ("gerem-cache", "cache-population"):
            raise ValueError("RF def/use collection does not need cache state")
        if args.collection in ("gerem-cache", "cache-population") and not args.cache_state:
            raise ValueError("GEREM cache requires actual physical state and access records")
        # GEREM RF's storage EFM uses actual def/use, not numerical operands,
        # SARA masks, output slicing, or a complete dynamic instruction trace.
        options.update({"-exact_trace": "0", "-exact_trace_static_cfg": "0",
            "-regfile_trace": "1" if args.collection == "gerem-rf" else "0",
            "-regfile_trace_file": str(work / "regfile_trace.bin")})
        own_population = minimal and args.collection in ('gerem-rf', 'gerem-smem')
        if args.collection != "population" and not own_population:
            options.pop("-population_inventory_file", None)
        if args.collection not in ("gerem-cache", "cache-population"):
            options.pop("-host_copy_ledger_file", None)
        absent = set() if args.collection in ("gerem-cache", "cache-population") else {"-host_copy_ledger_file"}
        if args.collection != "population" and not own_population:
            absent.add("-population_inventory_file")
        base_text = "\n".join(line for line in base_text.splitlines()
            if not line.split("#", 1)[0].split() or line.split("#", 1)[0].split()[0] not in absent)
    elif args.collection != "sara":
        raise ValueError("unknown production collection profile")
    (work / "gpgpusim.config").write_text(config_text(base_text, options))
    env = dict(os.environ)
    image_id = env.get("SARA_IMAGE_ID", "")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        raise ValueError("actual Docker image identity must be supplied by the container launcher")
    native_source = native_source_identity(simulator,
        require_compiled_manifest=defer_diagnostics)
    atomic_json(work / "native-source-files.json", native_source)
    native_fingerprint = fingerprint(native_source)
    for name in ("LD_PRELOAD", "LD_AUDIT", "LD_DEBUG", "LD_DEBUG_OUTPUT",
                 "PTX_SIM_KERNELFILE", "PTX_SIM_USE_PTX_FILE", "PTX_SIM_MODE_FUNC"):
        env.pop(name, None)
    runtime_config = "gcc-9.4.0/cuda-11080/release"
    population_enabled = '-population_inventory_file' in options
    population_budgets = _population_budgets(args)
    population_codec = getattr(args, "population_codec",
        "plain" if population_enabled and population_budgets is not None and not minimal else "gzip")
    if population_codec not in ("gzip", "plain"):
        raise ValueError("explicit native population codec required")
    env.update(SARA_VALIDATE_CPU="0", SARA_POPULATION_CODEC=population_codec,
        SARA_SOURCE_FINGERPRINT=native_fingerprint,
        SARA_POPULATION_REFERENCE_ACTIVE_THREADS="0", GPGPUSIM_ROOT=str(simulator),
        GPGPUSIM_CONFIG=runtime_config, CUDA_INSTALL_PATH="/usr/local/cuda",
        PTXAS_CUDA_INSTALL_PATH="/usr/local/cuda",
        LD_LIBRARY_PATH=str(simulator / "lib" / runtime_config) + ":/usr/local/cuda/lib64",
        PATH=str(simulator / "bin") + ":/usr/local/cuda/bin:/usr/local/bin:/usr/bin:/bin")
    if minimal and population_enabled:
        env['SARA_POPULATION_FORMAT'] = 'compact-v2'
        env['SARA_POPULATION_COMPONENT'] = component
    else:
        env.pop('SARA_POPULATION_FORMAT', None)
        env.pop('SARA_POPULATION_COMPONENT', None)
    if args.cache_state:
        env["SARA_CACHE_CAPTURE_PROFILE"] = args.cache_profile
    if args.collection == "gerem-smem":
        env["SARA_GEREM_SMEM_TRACE_FILE"] = str(work / "shared.jsonl")
    else:
        env.pop("SARA_GEREM_SMEM_TRACE_FILE", None)
    if args.collection == "gerem-cache":
        env["SARA_CACHE_SEMANTICS_PROFILE"] = "storage-efm-v1"
    elif args.collection == "cache-population":
        env["SARA_CACHE_SEMANTICS_PROFILE"] = "storage-population-v1"
    else:
        env.pop("SARA_CACHE_SEMANTICS_PROFILE", None)
    env.update(environment(workload['case']))
    env['SARA_VALIDATE_CPU'] = '1' if getattr(args, 'validate_cpu', False) else '0'
    command = ['./'+workload['app'], *workload['arguments']]
    previous_file_limit = None
    if population_enabled and population_codec == 'plain' and population_budgets is not None:
        import resource
        previous_file_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
        limit = population_budgets['max_decoded_bytes']
        if previous_file_limit[1] != resource.RLIM_INFINITY and previous_file_limit[1] < limit:
            raise ValueError('complete plain population needs its declared file bound')
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, previous_file_limit[1]))
    try:
        receipt = measured(command, work, work / "run.log", env, args.timeout,
                           persist_diagnostics=not defer_diagnostics)
    finally:
        if previous_file_limit is not None:
            resource.setrlimit(resource.RLIMIT_FSIZE, previous_file_limit)
    population_transport = None
    if population_enabled and population_codec == "plain":
        from script.execution.population_repack import pack_closed_population
        # The suffix remains the established public filename. Native plain
        # bytes are moved aside only after the producer exits successfully.
        packed = work / "population.jsonl.gz"
        plain = work / "population.native.jsonl"
        packed.rename(plain)
        budgets = population_budgets
        if budgets is None:
            from script.execution.population_transport import DECODED_BYTES, PHYSICAL_BYTES, MAX_RECORDS
            budgets = dict(max_decoded_bytes=DECODED_BYTES,
                max_physical_bytes=PHYSICAL_BYTES, max_records=MAX_RECORDS)
        transport = pack_closed_population(plain, packed,
            max_decoded_bytes=budgets["max_decoded_bytes"],
            max_physical_bytes=budgets["max_physical_bytes"])
        atomic_json(work / "population-repack.json", transport)
        plain.unlink()  # Only after complete CRC and decoded-byte SHA parity.
        population_transport = dict(native_codec='plain', stored_codec='gzip',
            decode_budgets=budgets, logical_population_modified=False,
            repack_receipt='population-repack.json')
    text = (work / "run.log").read_text()
    output = packet(work / "run.log", workload['case'], text=text)
    if "GPGPU-Sim" not in text or "GPUFI_UNSUPPORTED_" in text:
        raise ValueError("actual supported simulator execution required")
    cycles = re.findall(r"gpu_tot_sim_cycle\s*=\s*(\d+)", text)
    libraries = native_library_fingerprints(simulator)
    summary = {"schema": "sara-ge-batch-capture-v1", "case": workload['case'],
        "arguments": [3, 5, 33, 7] if workload['case'] == DEFAULT_CASE else workload['arguments'],
        "workload_contract": workload, "cache_state": args.cache_state,
        "independent_CPU_reference_enabled": getattr(args, 'validate_cpu', False),
        "collection": args.collection,
        "component": component, "minimal_population": minimal,
        "collection_scope": "own complete component domain and own method inputs; no borrowed capture" if minimal else "legacy reference preparation",
        "cache_capture_profile": args.cache_profile if args.cache_state else None,
        "cache_data_realizer_version": 2 if args.cache_state else 1,
        "actual_binary_sha256": sha(executable), "simulator_libraries": libraries,
        "native_source_fingerprint": native_fingerprint, "source_scope": "compiled_native_CXX_source_inputs",
        "image_id": image_id,
        "base_config_sha256": sha(base), "effective_config_sha256": sha(work / "gpgpusim.config"),
        "output": output, "output_fingerprint": fingerprint(output),
        "gpu_cycles": int(cycles[-1]) if cycles else None, "process": receipt,
        "classification_uses_FI_answers": False,
        "scope": "actual off-FI collection; no classification or coverage certificate"}
    if population_transport is not None:
        summary['population_transport'] = population_transport
    atomic_json(work / "capture.json", summary)
    return summary


def prepare_rf(args):
    from script.execution.population_inventory import (read_stream, validate_lifecycle,
        validate_production_blockers)
    from script.execution.fault_manifest import FaultPopulation
    from script.execution.trace_transport import read_trace_document
    work = args.capture.resolve(strict=True)
    metadata = json.loads((work / "capture.json").read_text())
    if metadata["output"] != packet(work / "run.log", metadata['case']):
        raise ValueError("raw output changed after collection")
    if metadata.get('minimal_population'):
        from script.execution.compact_population import prepare_compact_capture
        atomic_json(work / 'output-spec.json', output_regions(work / 'run.log', metadata['case']))
        return prepare_compact_capture(work, 'rf', with_trace=not bool(getattr(args, 'population_only', False)))
    stream = read_stream(work / "population.jsonl.gz",
        decode_budgets=_population_budgets(args, metadata))
    validate_production_blockers(stream["blockers"])
    spans = []
    for row in stream["spans"]:
        validate_lifecycle(row, stream["header"])
        if row["component"] != "rf":
            continue
        if row["mapping_supported"] is not True:
            raise ValueError("actual RF mapping unsupported; do not remove its mass")
        spans.append({key: row[key] for key in ("component", "target", "cycle_start", "cycle_stop",
            "bit_start", "bit_count", "hook_selectors", "ack_expected")})
    app = contract(metadata['case'])['app']
    inventory = {"schema_version": 1, "population_id": ("GE-SpMM" if metadata['case'] == DEFAULT_CASE else app)+"-actual-allocated-RF-v1",
        "fault_model": "active-allocated-simulator-rf-smem-single-bit-v1",
        "coordinate_system": "simulator_hook_allocated_storage", "time_basis": "simulator_global_cycle",
        "coverage_certified": False, "spans": spans}
    pop = FaultPopulation(inventory)
    if pop.mass != stream["mass"]["rf"]:
        raise ValueError("RF canonicalization changed the full emitter population")
    population_only = bool(getattr(args, "population_only", False))
    trace = None
    if not population_only:
        trace, transport = read_trace_document(work / "trace.json.gz")
        if not trace.get("events"):
            raise ValueError("empty actual instruction capture")
    elif metadata.get("collection") != "population":
        raise ValueError("neutral population preparation needs the value-free producer")
    outputs = output_regions(work/'run.log', metadata['case'])
    for filename, value in (("inventory-rf.json", inventory), ("output-spec.json", outputs)):
        destination = work / filename
        if destination.exists():
            if json.loads(destination.read_text()) != value:
                raise ValueError("refuse to replace a frozen input")
        else:
            atomic_json(destination, value)
    if not getattr(args, "no_manifest", False):
        manifest = pop.sample(10000, 2026, "matched-"+("GE-SpMM" if metadata['case'] == DEFAULT_CASE else app)+"-rf")
        manifest_path = work / "manifest-rf-10000.json"
        if manifest_path.exists():
            if json.loads(manifest_path.read_text()) != manifest:
                raise ValueError("refuse to replace an immutable master manifest")
        else:
            atomic_json(manifest_path, manifest)
    roles = [("inventory", "inventory-rf.json"), ("output_spec", "output-spec.json")]
    if not population_only: roles.append(("trace", "trace.json.gz"))
    descriptor = {"schema": "sara-population-inputs-v1" if population_only else "sara-batch-inputs-v1", "case": metadata["case"],
        "arguments": metadata["arguments"], "binary_sha256": metadata["actual_binary_sha256"],
        "simulator_libraries": metadata["simulator_libraries"],
        "population_mass": pop.mass, "population_fingerprint": pop.identity,
        "files": {role: {"path": filename, "sha256": sha(work / filename)} for role, filename in roles},
        "scope": "source-recorded model inputs, not a universal correctness certificate"}
    destination = work / "inputs-rf.json"
    if destination.exists():
        if json.loads(destination.read_text()) != descriptor:
            raise ValueError("frozen analysis input changed")
    else:
        atomic_json(destination, descriptor)
    return {"population_mass": pop.mass, "population_spans": len(spans),
            "dynamic_events": len(trace["events"]) if trace is not None else None, "input_path": str(destination),
            "whole_population_retained": True,
            "manifest_draws": 0 if getattr(args, "no_manifest", False) else 10000}


def prepare_smem(args):
    """Full allocated shared pages; preserve retained objects and owner epochs."""
    from copy import deepcopy
    from script.execution.population_inventory import (read_stream, validate_lifecycle,
        validate_production_blockers)
    from script.execution.fault_manifest import FaultPopulation
    work = args.capture.resolve(strict=True)
    metadata = json.loads((work / "capture.json").read_text())
    if metadata["output"] != packet(work / "run.log", metadata['case']):
        raise ValueError("complete frozen output changed")
    if metadata.get('minimal_population'):
        from script.execution.compact_population import prepare_compact_capture
        atomic_json(work / 'output-spec.json', output_regions(work / 'run.log', metadata['case']))
        return prepare_compact_capture(work, 'smem', with_trace=not bool(getattr(args, 'population_only', False)))
    stream = read_stream(work / "population.jsonl.gz",
        decode_budgets=_population_budgets(args, metadata))
    validate_production_blockers(stream["blockers"])
    if stream['header'].get('shared_identity_contract') != 'actual_allocator_persistent_object_owner_epoch_v1':
        raise ValueError('actual persistent shared identity is required')
    spans = []
    for row in stream['spans']:
        validate_lifecycle(row, stream['header'])
        if row['component'] != 'smem_page': continue
        if row['mapping_supported'] is not True:
            raise ValueError('unresolved shared mapping; do not drop its mass')
        for address in range(row['byte_start'], row['byte_start']+row['byte_count']):
            span = {key:deepcopy(row[key]) for key in ('target','lifecycle','cycle_start',
                'cycle_stop','hook_selectors','ack_expected')}
            span['target']['byte_addr'] = address
            span['ack_expected']['byte_addr'] = str(address)
            spans.append(dict(span,component='smem',bit_start=8*address,bit_count=8))
    inventory = {'schema_version':1,'population_id':contract(metadata['case'])['app']+'-actual-allocated-SMEM-v1',
        'fault_model':'active-allocated-simulator-rf-smem-single-bit-v1',
        'coordinate_system':'simulator_hook_allocated_storage','time_basis':'simulator_global_cycle',
        'coverage_certified':False,'spans':spans}
    pop = FaultPopulation(inventory)
    if not pop.mass or pop.mass != stream['mass']['smem']:
        raise ValueError('shared canonicalization changed the full emitter population')
    neutral = bool(getattr(args,'population_only',False))
    if neutral and metadata['collection'] != 'population':
        raise ValueError('neutral shared preparation requires value-free population capture')
    files = {'inventory-smem.json':inventory,
        'output-spec.json':output_regions(work/'run.log',metadata['case'])}
    if not getattr(args,'no_manifest',False):
        files['manifest-smem-10000.json'] = pop.sample(10000,2026,'matched-'+contract(metadata['case'])['app']+'-smem')
    for name,value in files.items():
        path = work/name
        if path.exists():
            if json.loads(path.read_text()) != value: raise ValueError('frozen shared input changed')
        else: atomic_json(path,value)
    roles = [('inventory','inventory-smem.json'),('output_spec','output-spec.json')]
    if not neutral: roles.append(('trace','trace.json.gz'))
    descriptor = {'schema':'sara-population-inputs-v1' if neutral else 'sara-batch-inputs-v1',
        'case':metadata['case'],'arguments':metadata['arguments'],
        'binary_sha256':metadata['actual_binary_sha256'],'simulator_libraries':metadata['simulator_libraries'],
        'population_mass':pop.mass,'population_fingerprint':pop.identity,
        'files':{role:{'path':name,'sha256':sha(work/name)} for role,name in roles}}
    path = work/'inputs-smem.json'
    if path.exists():
        if json.loads(path.read_text()) != descriptor: raise ValueError('frozen shared descriptor changed')
    else: atomic_json(path,descriptor)
    return {'population_mass':pop.mass,'spans':len(spans),'whole_population_retained':True}


def prepare_cache(args):
    from script.execution.cache_physical_facts import raw_physical
    from script.execution.cache_inventory_core import _inventory, topology_from_config
    from script.execution.fault_manifest import FaultPopulation
    work = args.capture.resolve(strict=True)
    metadata = json.loads((work / "capture.json").read_text())
    outputs = output_regions(work/'run.log', metadata['case'])
    if metadata["output"] != packet(work / "run.log", metadata['case']):
        raise ValueError("complete frozen cache output definition differs")
    path = work / "output-spec.json"
    if path.exists():
        if json.loads(path.read_text()) != outputs: raise ValueError("frozen outputs changed")
    else: atomic_json(path, outputs)
    if metadata.get("cache_data_realizer_version") != 2:
        raise ValueError("whole raw physical cache population requires the frozen v2 invalid-DATA model")
    population_only = bool(getattr(args, "population_only", False))
    if population_only and metadata.get("collection") != "cache-population" and not (
            metadata.get('minimal_population') and metadata.get('collection') == 'gerem-cache'):
        raise ValueError("cache neutral population needs its identity-only producer")
    _, residency = raw_physical(work / "memory.jsonl",
        None if population_only else work / "trace.json.gz",
        None if population_only else work / "trace.json.gz.completeness.json")
    topology = topology_from_config((work / "gpgpusim.config").read_text())
    selected = getattr(args, 'component', None)
    whole, _ = _inventory(residency, topology,
        execution_metadata=not metadata.get('minimal_population', False),
        component=selected if selected in ('l1d', 'l2') else None)
    result = {}
    for component in ((selected,) if selected in ('l1d', 'l2') else ('l1d', 'l2')):
        inventory = dict(whole, fault_model="all-active-physical-cache-tag57-and-data-invalid-pending-single-bit-v2",
                         spans=[row for row in whole["spans"] if row["component"] == component])
        if metadata.get('minimal_population'):
            from script.execution.compact_population import prepare_compact_cache_capture
            result[component] = prepare_compact_cache_capture(work, component, inventory,
                with_trace=not population_only)
            continue
        pop = FaultPopulation(inventory)
        if not pop.mass:
            raise ValueError("empty cache domain cannot be declared applicable")
        files = {"inventory-" + component + ".json": inventory}
        if not getattr(args, "no_manifest", False):
            app = 'GE-SpMM' if metadata['case'] == DEFAULT_CASE else contract(metadata['case'])['app']
            files["manifest-" + component + "-10000.json"] = pop.sample(10000, 2026, "matched-"+app+'-' + component)
        roles = [("output_spec", "output-spec.json"), ("cache_ledger", "memory.jsonl")]
        if not population_only: roles += [("trace", "trace.json.gz"), ("trace_sidecar", "trace.json.gz.completeness.json")]
        descriptor = {"schema": "sara-population-inputs-v1" if population_only else "sara-batch-inputs-v1", "case": metadata["case"],
            "arguments": metadata["arguments"], "binary_sha256": metadata["actual_binary_sha256"],
            "simulator_libraries": metadata["simulator_libraries"],
            "population_mass": pop.mass, "population_fingerprint": pop.identity,
            "files": {role: {"path": name, "sha256": sha(work / name)} for role, name in roles}}
        for name, value in files.items():
            path = work / name
            if path.exists():
                if json.loads(path.read_text()) != value:
                    raise ValueError("refuse to replace a frozen physical population or manifest")
            else: atomic_json(path, value)
        name = "inventory-" + component + ".json"
        descriptor["files"]["inventory"] = {"path": name, "sha256": sha(work / name)}
        path = work / ("inputs-" + component + ".json")
        if path.exists():
            if json.loads(path.read_text()) != descriptor:
                raise ValueError("frozen cache descriptor changed")
        else: atomic_json(path, descriptor)
        result[component] = {"population_mass": pop.mass, "spans": len(inventory["spans"]),
                            "manifest_draws": 0 if getattr(args, "no_manifest", False) else 10000}
    return result


def main(argv=None):
    from script.execution.policy import require_container_execution
    require_container_execution()
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="stage", required=True)
    p = sub.add_parser("capture")
    p.add_argument('--case', default=DEFAULT_CASE)
    p.add_argument('--validate-cpu', action='store_true', help='preflight only; excluded from every formal timed path')
    p.add_argument("--simulator-root", type=Path, required=True)
    p.add_argument("--executable", type=Path, required=True)
    p.add_argument("--base-config", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--cache-state", action="store_true")
    p.add_argument("--collection", choices=("sara", "gerem-rf", "gerem-smem", "gerem-cache", "fi-golden", "population", "cache-population"), default="sara")
    p.add_argument('--component', choices=('rf', 'smem', 'l1d', 'l2'))
    p.add_argument('--minimal-population', action='store_true', help='collect only this method/component domain, without FI selectors or ACK metadata')
    p.add_argument('--defer-diagnostics', action='store_true',
        help='own aggregate collection only: retain raw logs without timed log-SHA/process-JSON evidence work')
    p.add_argument("--cache-profile", choices=("changes", "full"), default="changes")
    p.add_argument("--timeout", type=int, default=1800)
    p = sub.add_parser("prepare-rf")
    p.add_argument("--capture", type=Path, required=True)
    p.add_argument("--no-manifest", action="store_true", help="rates does not construct or read sampled sites")
    p.add_argument("--population-only", action="store_true", help="neutral RF population/manifest; no numeric trace")
    p = sub.add_parser("prepare-smem")
    p.add_argument("--capture", type=Path, required=True)
    p.add_argument("--population-only", action="store_true")
    p.add_argument("--no-manifest", action="store_true")
    p = sub.add_parser("prepare-cache")
    p.add_argument("--capture", type=Path, required=True)
    p.add_argument('--component', choices=('l1d', 'l2'))
    p.add_argument("--population-only", action="store_true")
    p.add_argument("--no-manifest", action="store_true")
    args = parser.parse_args(argv)
    if args.stage == "capture":
        result = capture(args)
        print(json.dumps({key: result[key] for key in ("schema", "case", "cache_state", "gpu_cycles", "output_fingerprint")}))
    elif args.stage == "prepare-rf":
        print(json.dumps(prepare_rf(args)))
    elif args.stage == "prepare-smem":
        print(json.dumps(prepare_smem(args)))
    elif args.stage == "prepare-cache":
        print(json.dumps(prepare_cache(args)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
