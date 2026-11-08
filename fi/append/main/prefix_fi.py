"""B-only append-only aggregate FI ranges from one frozen 10K master.

The native hook, raw-byte oracle, prospective performance window and quiescent
64-record evidence checkpoints are copied unchanged from source07 batch_fi.
Only explicit administrative range admission is added. Earlier ranges are
mounted read-only and verified, never injected again or assigned a new clock.
No module globals/gates are monkeypatched and no diagnostic FI bypass exists.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import time

from script.execution.campaign import atomic_json, fingerprint, requested_prefix, safe_id
from script.execution.method_performance import PerformanceWindow
from script.execution.validation_records import write_chunks, read_chunks
from script.common.outcome_oracle import _load_log_summary, _validate_raw_summary
import shutil
from script.execution.fi_campaign import run_trial, STOP, validate_site_binding
from script.execution.ge_batch_experiment import sha, packet, native_library_fingerprints
from script.execution.sara_batch_campaign import checked_inputs
from script.execution.batch_workload import contract, environment, fixture_assets

OBSERVER_OPTIONS = {"-population_inventory_file", "-host_copy_ledger_file",
    "-exact_trace", "-regfile_trace", "-exact_trace_static_cfg", "-cache_state_ledger"}
CODE_ROOT = Path('/code')
SOURCE_ID = '1cd7cd5c424b45180ce18f4adb4c995d38547564be79ac9b6a7a86d28d4d223e'
NATIVE_SHA = 'e306a1ee85eda5fa42888f20224133eb30170da753e3a3bcf82d75ad88918f10'
IMAGE = 'sha256:6f88c35052e8db66eb00c44700c180c57c69fdcd4569578e5730582ee93c54be'
BASE_DISPATCHER_SHA = '02b38b826b7aa203923deadc438527a6e28d3829b01202004c8a834c81f600c0'
RANGES = ((0,1000),(1000,5000),(5000,10000))
CASES = {
    'GE-SpMM':'spmm-empty-and-tail', 'LayerNorm':'layernorm-full-gpu',
    'Attention':'attention-full-gpu', 'Stencil1D':'stencil-boundary',
    'Convolution1D':'convolution-boundary', 'Softmax':'softmax-stable',
    'GELU':'gelu-bias', 'GEMM':'gemm-nonsquare',
    'MatrixMultiplication':'matrixmul-edge-tiles', 'AdamW':'adamw-independent-state',
    'Pathfinder':'pathfinder-multilaunch', 'Dijkstra':'dijkstra-diamond',
    'MatrixFactorization':'mf-colliding-ratings', 'Render':'render-ray-casting'}


def regular(path):
    path = Path(path)
    if (path != path.resolve(strict=True) or path.is_symlink()
            or not stat.S_ISREG(path.lstat().st_mode)):
        raise ValueError('exact canonical regular input required: ' + str(path))
    return path


def _continuous_cache():
    """Definition-load only the independently pinned administrative cache helper."""
    import importlib.util
    path = regular(Path(__file__).resolve().parent/'continuous_fi_prior_cache.py')
    if sha(path) != 'de50f25bef914ffb8b1327cea74942ae939ab32480013bd625b22c18baf01079':
        raise ValueError('continuous FI cache helper differs from pinned bytes')
    spec = importlib.util.spec_from_file_location('_continuous_FI_sealed_cache', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    if sha(path) != 'de50f25bef914ffb8b1327cea74942ae939ab32480013bd625b22c18baf01079':
        raise ValueError('continuous FI cache helper changed during definition load')
    return module


def _require_frozen_worker(args):
    """Administrative source/native/container admission; no experiment work."""
    from script.execution.policy import require_container_execution
    from script.execution.experiment import scientific_files
    profile = require_container_execution()
    if (profile.role != 'bounded_primary' or profile.cpus != 64 or profile.memory_bytes != 448*1024**3
            or os.environ.get('SARA_IMAGE_ID') != IMAGE):
        raise ValueError('exact B bounded runc CPU-only execution required')
    if not Path('/.dockerenv').exists() or CODE_ROOT != CODE_ROOT.resolve(strict=True):
        raise ValueError('the frozen source must be mounted at /code in B Docker')
    if sha(regular(Path(__file__).resolve())) != args.adapter_sha256:
        raise ValueError('private append-only adapter differs from host-pinned SHA')
    files = _continuous_cache().cached_source_files(args, SOURCE_ID, CODE_ROOT)
    if hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest() != SOURCE_ID:
        raise ValueError('complete source07 scientific file map differs')
    if sha(regular(CODE_ROOT/'script/execution/batch_fi.py')) != BASE_DISPATCHER_SHA:
        raise ValueError('source07 base dispatcher differs')
    native = regular(args.simulator_root/'compiled-source-files.json')
    native_files = json.loads(native.read_text())
    if sha(native) != NATIVE_SHA or not native_files or any(files.get(k) != v for k,v in native_files.items()):
        raise ValueError('native03 compiled-source binding differs')
    return profile


def _readonly_prior_root(path):
    path = Path(path)
    if path != path.resolve(strict=True) or path.is_symlink() or not path.is_dir():
        raise ValueError('exact prior segment directory required')
    if not os.statvfs(path).f_flag & os.ST_RDONLY:
        raise ValueError('earlier sealed roots must be mounted actually read-only')
    return path


def _verify_prior_segments(args, master, descriptor):
    """Quiescent, untimed verification of original seals/logs/costs only."""
    expected = list(RANGES[:RANGES.index((args.begin,args.end))])
    if len(args.prior_segment) != len(expected) or len(args.prior_seal_sha256) != len(expected):
        raise ValueError('all and only earlier sealed ranges are required')
    cache_helper = _continuous_cache()
    prior_cache = cache_helper.load_verified_prior_cache(args, master, descriptor,
        source_id=SOURCE_ID, native_sha=NATIVE_SHA, fingerprint_fn=fingerprint)
    records, seen = [], set()
    for root,seal_sha,(begin,end) in zip(args.prior_segment,args.prior_seal_sha256,expected):
        root = _readonly_prior_root(root)
        if str(root) in seen:
            raise ValueError('duplicate earlier segment root')
        seen.add(str(root))
        seal_path = regular(root/'fi_completion.json')
        if sha(seal_path) != seal_sha:
            raise ValueError('earlier seal differs from host-pinned bytes')
        identity = json.loads(regular(root/'campaign.json').read_text())
        prefix = identity.get('prefix',{})
        if (identity.get('schema') != 'sara-FI-aggregate-with-untimed-evidence-v1'
                or identity.get('target_count') != end-begin
                or identity.get('manifest_fingerprint') != fingerprint(master)
                or identity.get('performance_measurement') is not (not args.untimed)
                or identity.get('dispatch_inputs_sha256') != args.dispatch_inputs_sha256
                or identity.get('spec',{}).get('population_fingerprint') != master['population_fingerprint']
                or identity.get('spec',{}).get('input_fingerprint') != fingerprint(descriptor)
                or identity.get('spec',{}).get('timeout_seconds') != args.timeout
                or identity.get('spec',{}).get('validation_only') is not args.untimed
                or identity.get('spec',{}).get('cache_execution_model') != 'functional-snapshot-cache-v3'
                or identity.get('spec',{}).get('simulation_cycle_watchdog',{}).get('factor') != args.watchdog_factor
                or prefix.get('schema') != 'sara-FI-append-only-range-v1'
                or prefix.get('range') != [begin,end] or prefix.get('cumulative_prefix') != end
                or prefix.get('parent_master_sha256') != args.master_sha256
                or prefix.get('full_master_fingerprint') != fingerprint(master)
                or prefix.get('segment_manifest_fingerprint') != fingerprint(master['trials'][begin:end])
                or prefix.get('source_id') != SOURCE_ID or prefix.get('native_manifest_sha256') != NATIVE_SHA
                or prefix.get('adapter_sha256') != prior_cache['segments'][len(records)]['adapter_sha256']
                or prefix.get('application') != args.application or prefix.get('architecture') != args.architecture
                or prefix.get('component') != args.component
                or prefix.get('FI_workers') != args.jobs
                or prefix.get('population_inventory_sha256') != args.population_inventory_sha256):
            raise ValueError('earlier FI segment belongs to another exact master/source/model/range')
        if prefix.get('preceding_seals') != records:
            raise ValueError('earlier range transitive predecessor chain differs')
        committed_count, counts = cache_helper.cached_counts(prior_cache, len(records), root, identity)
        aggregate = json.loads(regular(root/'aggregate.json').read_text())
        seal = json.loads(seal_path.read_text())
        # Counts are original sealed values authenticated by committed index byte pins.
        if (committed_count != end-begin or seal.get('status') != 'complete'
                or seal.get('aggregate') != aggregate or aggregate.get('complete') is not True
                or aggregate.get('count') != end-begin or aggregate.get('counts') != counts
                or aggregate.get('identity_fingerprint') != fingerprint(identity)):
            raise ValueError('earlier FI segment seal/aggregate/evidence is incomplete')
        cumulative_path = regular(root/'cumulative-aggregate.json')
        cumulative = json.loads(cumulative_path.read_text())
        expected_counts = {key:counts[key]+sum(row['counts'][key] for row in records)
                           for key in ('Masked','SDC','DUE')}
        if (seal.get('cumulative_file') != 'cumulative-aggregate.json'
                or seal.get('cumulative_sha256') != sha(cumulative_path)
                or cumulative.get('schema') != 'sara-FI-prefix-cumulative-aggregate-v1'
                or cumulative.get('count') != end or cumulative.get('counts') != expected_counts
                or cumulative.get('parent_master_sha256') != args.master_sha256
                or cumulative.get('latest_segment_range') != [begin,end]
                or cumulative.get('identity_fingerprint') != fingerprint(identity)
                or cumulative.get('complete') is not True):
            raise ValueError('earlier cumulative aggregate differs from its sealed prefix')
        costs = sorted(root.glob('performance-partial*.json'))
        if not args.untimed:
            final = regular(root/'performance-window.json')
            final_receipt = json.loads(final.read_text())
            if (final_receipt.get('method') != 'FI' or final_receipt.get('aggregate_fsynced') is not True
                    or final_receipt.get('complete') is not True or final_receipt.get('partial') is not False
                    or final_receipt.get('aggregate_file') != 'aggregate.json'
                    or final_receipt.get('component') != args.component
                    or final_receipt.get('task',{}).get('campaign_identity') != fingerprint(identity)):
                raise ValueError('earlier FI segment lacks its original complete timing receipt')
            costs.append(final)
        elif costs or (root/'performance-window.json').exists():
            raise ValueError('untimed resident FI must not acquire a performance clock')
        records.append(dict(range=[begin,end], parent_master_sha256=args.master_sha256,
            campaign_sha256=sha(regular(root/'campaign.json')), seal_sha256=seal_sha,
            aggregate_sha256=sha(regular(root/'aggregate.json')),
            cumulative_sha256=sha(cumulative_path), count=end-begin, counts=counts,
            identity_fingerprint=fingerprint(identity),
            cost_receipts={path.name:sha(regular(path)) for path in costs},
            complete_raw_logs_and_checkpoints_verified=True, previous_draws_executed_again=False))
    return records


def _cumulative_aggregate(args,identity,aggregate):
    preceding = identity['prefix']['preceding_seals']
    counts = {key:aggregate['counts'][key]+sum(row['counts'][key] for row in preceding)
              for key in ('Masked','SDC','DUE')}
    if (sum(counts.values()) != args.end or aggregate['count'] != args.end-args.begin
            or sum(row['count'] for row in preceding) != args.begin):
        raise ValueError('cumulative FI count lost or duplicated an original draw')
    return dict(schema='sara-FI-prefix-cumulative-aggregate-v1',
        count=args.end, counts=counts, complete=True, parent_master_sha256=args.master_sha256,
        full_master_fingerprint=identity['manifest_fingerprint'],
        latest_segment_range=[args.begin,args.end], identity_fingerprint=fingerprint(identity),
        previous_segment_seal_sha256=[row['seal_sha256'] for row in preceding],
        original_draw_ids_and_repeated_sites_retained=True, earlier_draws_executed_again=False,
        administrative_failure_is_DUE=False, outputs_checked_in_full=True,
        performance_measurement=not args.untimed,
        cumulative_persistence_in_latest_segment_window=not args.untimed)


def fault_base(text):
    lines = []
    for line in text.splitlines():
        tokens = line.split("#", 1)[0].split()
        if not tokens or tokens[0] not in OBSERVER_OPTIONS:
            lines.append(line)
    lines += ["-exact_trace 0", "-regfile_trace 0", "-exact_trace_static_cfg 0", "-cache_state_ledger 0"]
    return "\n".join(lines) + "\n"


def _load_common_manifest(args, pop, dispatch_packet):
    """Original full formal packet/master first; range selection only afterwards."""
    from script.execution.fi_dispatch_inputs import read_bound_bytes
    raw = read_bound_bytes(regular(args.site_manifest),dispatch_packet['manifest'])
    if hashlib.sha256(raw).hexdigest() != args.master_sha256:
        raise ValueError('full parent master differs from the host-pinned SHA')
    manifest = json.loads(raw)
    if (manifest.get('seed') != args.seed or args.seed != 2026
            or manifest.get('population_fingerprint') != pop.identity
            or manifest.get('sampling') != 'with_replacement'
            or manifest.get('population_size') != pop.mass
            or len(manifest.get('trials',())) != 10000
            or dispatch_packet['manifest']['draws'] != 10000
            or fingerprint(manifest) != dispatch_packet['manifest']['fingerprint']
            or any(manifest.get('population_contract',{}).get(key) != pop.inventory[key]
                   for key in ('fault_model','coordinate_system','time_basis'))
            or 'parent_draw_range' in manifest or 'parent_master_sha256' in manifest):
        raise ValueError('only the original complete formal seed2026 10K master is admitted')
    requested_prefix(manifest['trials'],10000,dispatch_limit=10000)
    ids = set()
    for draw,row in enumerate(manifest['trials']):
        if (row.get('trial_id') != 'trial-%08d'%draw or type(row.get('draw_index')) is not int
                or row.get('draw_index') != draw
                or row['trial_id'] in ids or row.get('population_fingerprint') != pop.identity
                or row.get('component') != args.component or type(row.get('population_rank')) is not int
                or not 0 <= row['population_rank'] < pop.mass):
            raise ValueError('full master draw order/population identity differs')
        ids.add(row['trial_id'])
        site = {key:row[key] for key in ('population_fingerprint','component','target','cycle','bit')}
        if row.get('site_id') != fingerprint(site):
            raise ValueError('master site hash differs from original physical coordinates')
        validate_site_binding(row)
        if args.population_inventory is not None:
            from script.execution.cache_valid_resident import validate_site_contract
            validate_site_contract(row.get('valid_resident_contract'))
            if args.resident_population.resolve(row['population_rank'])['site_id'] != row['site_id']:
                raise ValueError('resident draw is outside its exact selected population/rank')
    return manifest


def _prepare_fi_dispatch(args, capture, descriptor, pop, manifest, dispatch_packet=None):
    """Load the actual runtime, assets and configuration needed by FI.

    These per-method identity/loading checks are inside the same prospective
    performance window as G/S own-collector identity/loading checks. Creating
    the shared executable, golden and master remains common study setup.
    """
    runtime = args.simulator_root.resolve(strict=True)
    config = "gcc-9.4.0/cuda-11080/release"
    actual_libraries = native_library_fingerprints(runtime)
    if actual_libraries != descriptor["simulator_libraries"]:
        raise ValueError("FI must use the exact simulator bytes of its frozen golden")
    # The simulator/toolchain environment is set by this container driver,
    # never by a sampled trial or a prediction result.
    os.environ.update(GPGPUSIM_ROOT=str(runtime), GPGPUSIM_CONFIG=config,
        CUDA_INSTALL_PATH="/usr/local/cuda", PTXAS_CUDA_INSTALL_PATH="/usr/local/cuda",
        LD_LIBRARY_PATH=str(runtime / "lib" / config) + ":/usr/local/cuda/lib64",
        PATH=str(runtime / "bin") + ":/usr/local/cuda/bin:/usr/local/bin:/usr/bin:/bin")
    for key in ("LD_PRELOAD", "LD_AUDIT", "LD_DEBUG", "LD_DEBUG_OUTPUT"):
        os.environ.pop(key, None)
    if dispatch_packet is None:
        base_text = (capture / 'gpgpusim.config').read_text()
        metadata = json.loads((capture / 'capture.json').read_text())
    else:
        from script.execution.fi_dispatch_inputs import read_bound_bytes, load_bound_json
        base_text = read_bound_bytes(capture / 'gpgpusim.config', dispatch_packet['files']['config']).decode()
        metadata = load_bound_json(capture / 'capture.json', dispatch_packet['files']['capture_metadata'])
    if (descriptor['case'] != CASES[args.application] or metadata.get('case') != descriptor['case']
            or metadata.get('base_config_sha256') != sha(regular(
                CODE_ROOT/'configs/study'/args.architecture/'gpgpusim.config'))):
        raise ValueError('formal application/architecture differ from the actual neutral capture')
    base = fault_base(base_text)
    golden_cycles = metadata['gpu_cycles']
    if type(args.watchdog_factor) is not int or args.watchdog_factor < 2:
        raise ValueError("explicit simulation-cycle watchdog factor >=2 required")
    cycle_watchdog = args.watchdog_factor * golden_cycles
    from script.execution.config_options import config_text
    base = config_text(base, {"-gpgpu_max_cycle": str(cycle_watchdog)})
    workload = contract(descriptor['case'])
    assets = {workload['app']: capture / workload['app']}
    assets.update({name:capture/name for name in fixture_assets(descriptor['case'])})
    assets.update({path.name: path for path in capture.iterdir() if path.suffix in (".xml", ".icnt")})
    asset_digests = {name: sha(path) for name, path in assets.items()}
    if asset_digests[workload['app']] != descriptor.get('binary_sha256'):
        raise ValueError('FI executable differs from its original complete golden')
    if dispatch_packet is not None:
        if (set(assets) != set(dispatch_packet['assets'])
                or any(asset_digests[name] != item['sha256']
                       or assets[name].stat().st_size != item['bytes']
                       for name, item in dispatch_packet['assets'].items())):
            raise ValueError('FI execution assets changed after common preparation')
    spec = {"schema_version": 1, "purpose": "correctness",
        "campaign_kind": "author_requested_original14_append_only_prefix",
        "command": ['./'+workload['app'], *workload['arguments']], "environment": {k:(v[2:] if v.startswith("./") else v) for k,v in environment(descriptor['case']).items()},
        "timeout_seconds": args.timeout, "retain_work": False,
        "assets": {name: str(path) for name,path in assets.items()},
        "defer_evidence": True, "reuse_readonly_assets": True, "base_config_text": base,
        "record_trial_costs": False, "validation_only": args.untimed,
        "input_fingerprint": fingerprint(descriptor), "population_fingerprint": pop.identity,
        "fault_model": pop.inventory["fault_model"],
        "cache_execution_model": "functional-snapshot-cache-v3",
        "simulation_cycle_watchdog": {"cycle_limit": cycle_watchdog,
            "rule": "factor_times_actual_fault_free_cycles", "factor": args.watchdog_factor,
            "golden_cycles": golden_cycles, "class": "DUE_detected_execution_budget_exceeded",
            "administrative_process_timeout_is_DUE": False},
        "assets_sha256": asset_digests,
        "execution_code": {name: sha(CODE_ROOT / name) for name in
            ("script/execution/batch_fi.py", "script/execution/fi_campaign.py", "script/common/outcome_oracle.py",
             "script/execution/batch_workload.py")}}
    identity = dict(schema="sara-FI-aggregate-with-untimed-evidence-v1", spec=spec,
        manifest_fingerprint=(dispatch_packet['manifest']['fingerprint'] if dispatch_packet
                              else fingerprint(manifest)), target_count=args.target_count,
        performance_measurement=not args.untimed, checkpoint_records=64)
    if dispatch_packet is not None:
        identity['dispatch_inputs_sha256'] = args.dispatch_inputs_sha256
        spec['golden_file_binding'] = dispatch_packet['files']['golden']
    identity['prefix'] = dict(schema='sara-FI-append-only-range-v1',
        range=[args.begin,args.end], cumulative_prefix=args.end,
        parent_master_sha256=args.master_sha256, full_master_fingerprint=fingerprint(manifest),
        segment_manifest_fingerprint=fingerprint(manifest['trials'][args.begin:args.end]),
        source_id=SOURCE_ID, native_manifest_sha256=NATIVE_SHA,
        adapter_sha256=args.adapter_sha256, base_dispatcher_sha256=BASE_DISPATCHER_SHA,
        application=args.application, architecture=args.architecture, component=args.component,
        FI_workers=args.jobs,
        population_inventory_sha256=args.population_inventory_sha256,
        preceding_seals=args.verified_prior_segments,
        prior_sealed_roots_read_only=True, old_draws_dispatched_again=False,
        fresh_random_stream_created=False, ordinary_formal_FI_path=True)
    return identity, spec, assets


def _admit_fi_dispatch(args, directory, identity, manifest, window):
    """Persist campaign administration and verify prior evidence while idle.

    Only this resume/evidence work is excluded from a fresh method window;
    actual input, runtime, manifest and output-checker loading are measured.
    """
    meta = directory / 'campaign.json'
    if meta.exists():
        if not args.resume or json.loads(meta.read_text()) != identity:
            raise ValueError('existing FI identity differs or explicit resume is missing')
    else:
        if args.resume:
            raise ValueError('cannot resume absent FI campaign')
        atomic_json(meta, identity)
    if window is not None:
        # Bind before reading old evidence, so any later interrupted dispatch
        # keeps the same campaign/attempt proof as its immutable batch journal.
        window.task['campaign_identity'] = fingerprint(identity)
    completed = load_checkpoints(directory, identity, manifest['trials'][:args.target_count])
    seal = directory / 'fi_completion.json'
    if seal.exists():
        aggregate = json.loads((directory / 'aggregate.json').read_text())
        sealed = json.loads(seal.read_text())
        expected = {name: sum(record['result']['outcome'] == name for record in completed.values())
                    for name in ('Masked', 'SDC', 'DUE')}
        if (len(completed) != args.target_count or sealed.get('aggregate') != aggregate
                or sealed.get('status') != 'complete' or aggregate.get('counts') != expected
                or aggregate.get('identity_fingerprint') != fingerprint(identity)
                or aggregate.get('complete') is not True):
            raise ValueError('FI seal lacks its complete immutable aggregate/evidence')
        cumulative = directory/'cumulative-aggregate.json'
        if (sealed.get('cumulative_file') != cumulative.name
                or sealed.get('cumulative_sha256') != sha(regular(cumulative))
                or json.loads(cumulative.read_text()) != _cumulative_aggregate(args,identity,aggregate)):
            raise ValueError('FI seal lacks its original cumulative prefix aggregate')
        return None
    if (directory / 'aggregate.json').exists() or (directory / 'performance-window.json').exists():
        raise ValueError('terminal FI aggregate lacks its seal; preserve and recover rather than overwrite')
    if window is not None:
        window.task.update(prior_completed_draws=len(completed),
            missing_draws=args.target_count-len(completed))
    return completed


def _execute_locked(args, directory):
    capture = args.capture.resolve(strict=True)
    # Under dispatch.lock a sealed resume performs verification only. Do not
    # create a new clock/receipt for work which has already completed.
    sealed_resume = (directory / 'fi_completion.json').exists()
    window = None if args.untimed or sealed_resume else PerformanceWindow('FI', directory,
        component=args.component, task=dict(protocol='sum immutable partial attempts plus final window',
            performance_attempt_id='FI-%020d' % time.time_ns(), target_draws=args.target_count,
            common_manifest_loading_included=True,
            input_runtime_config_source_identity_loading_included=True,
            shared_setup_creation_and_prior_evidence_verification_excluded=True,
            boundary_kind='actual complete method task; not an intrinsic algorithm-only cost'))
    try:
        with (window.phase('population_input_loading_and_identity_check') if window else nullcontext()):
            from script.execution.fi_dispatch_inputs import load_dispatch_inputs
            dispatch_packet, descriptor, pop = load_dispatch_inputs(regular(args.dispatch_inputs),
                args.dispatch_inputs_sha256, component=args.component, untimed=args.untimed, diagnostic=False)
            if dispatch_packet.get('diagnostic_only') is not False:
                raise ValueError('1K and every later range require the ordinary formal packet')
            if bool(dispatch_packet['resident_selection']) != (args.population_inventory is not None):
                raise ValueError('FI resident packet and explicit subset mode differ')
            if args.population_inventory is not None:
                from script.execution.fault_manifest import FaultPopulation
                raw_subset = regular(args.population_inventory).read_bytes()
                if hashlib.sha256(raw_subset).hexdigest() != args.population_inventory_sha256:
                    raise ValueError('resident inventory changed after administrative admission')
                subset = json.loads(raw_subset)
                args.resident_population = FaultPopulation(subset)
                selection = subset.get('selection',{})
                if (args.resident_population.identity != pop.identity or args.resident_population.mass != pop.mass
                        or dispatch_packet['resident_selection'].get('selected_population_fingerprint') != pop.identity
                        or selection.get('schema') != 'sara-cache-current-valid-selection-v1'
                        or selection.get('data_sector_statuses') != [2,3]
                        or selection.get('readable_filter') is not False
                        or selection.get('future_consumer_filter') is not False
                        or selection.get('outcome_filter') is not False):
                    raise ValueError('resident packet/inventory must retain the exact untimed valid subset')
            if window is not None:
                window.task.update(dispatch_input_kind='frozen shared-preparation packet',
                    full_population_rebuild_in_FI=False, append_only_range=[args.begin,args.end],
                    cumulative_prefix=args.end, earlier_ranges_read_only=True)
        with (window.phase('common_manifest_loading_and_site_binding') if window else nullcontext()):
            master = _load_common_manifest(args,pop,dispatch_packet)
            manifest = dict(master,trials=master['trials'][args.begin:args.end],
                parent_draw_range=[args.begin,args.end],parent_master_sha256=args.master_sha256)
        with (window.validation_checkpoint(workers_idle=True,
                purpose='FI-earlier-sealed-ranges-read-only-verification') if window else nullcontext()):
            args.verified_prior_segments = _verify_prior_segments(args,master,descriptor)
        with (window.phase('runtime_config_asset_and_source_identity_preparation') if window else nullcontext()):
            identity, spec, assets = _prepare_fi_dispatch(args,capture,descriptor,pop,master,dispatch_packet)
        with (window.validation_checkpoint(workers_idle=True,
                purpose='FI-campaign-administration-and-prior-evidence-verification') if window else nullcontext()):
            completed = _admit_fi_dispatch(args, directory, identity, manifest, window)
        if completed is None:
            if window is not None:
                raise ValueError('FI completion changed during its locked admission')
            return 0
        if sealed_resume:
            raise ValueError('existing FI seal did not verify; no fresh dispatch is allowed')
        with (window.phase('complete_output_contract_loading') if window else nullcontext()):
            if dispatch_packet is None:
                outputs = json.loads((capture / 'output-spec.json').read_text())
            else:
                from script.execution.fi_dispatch_inputs import load_bound_json
                outputs = load_bound_json(capture / 'output-spec.json', dispatch_packet['files']['outputs'])
        return dispatch_missing(args, directory, identity, spec, assets, outputs,
            capture / 'run.log', manifest['trials'][:args.target_count], completed, window=window)
    except BaseException as error:
        if window is not None and not window.finished:
            # A malformed input has no accepted campaign identity. Preserve its
            # measured loading failure separately; never fabricate a resumable
            # FI partial/result or silently add it to a valid campaign's clock.
            prefix = ('performance-partial-' if window.task.get('campaign_identity')
                      else 'input-loading-failure-')
            window.save_partial(error, receipt_name=prefix+'%020d.json' % time.time_ns())
        raise


def _attempt_path(directory, trial_id, relative):
    path = Path(relative)
    if (path.is_absolute() or '..' in path.parts or len(path.parts) != 3
            or path.parts[:2] != ('runs', safe_id(trial_id))):
        raise ValueError('FI evidence attempt is outside its original draw')
    actual = (directory / path).resolve(strict=True)
    actual.relative_to(directory.resolve(strict=True))
    if not actual.is_dir():
        raise ValueError('FI evidence attempt directory is missing')
    return actual


def load_checkpoints(directory, identity, trials):
    """Admission only: before a window or inside a quiescent excluded checkpoint."""
    directory = Path(directory)
    by_id = {row['trial_id']: row for row in trials}
    if len(by_id) != len(trials):
        raise ValueError('immutable FI draw IDs must be unique; repeated sites remain legal')
    cost_attempts = set()
    cost_paths = list(directory.glob('performance-partial*.json'))
    if (directory / 'performance-window.json').is_file():
        cost_paths.append(directory / 'performance-window.json')
    for path in cost_paths:
        receipt = json.loads(path.read_text())
        task = receipt.get('task', {})
        if (receipt.get('method') != 'FI' or receipt.get('performance_measurement') is not True
                or not isinstance(task, dict) or task.get('campaign_identity') != fingerprint(identity)
                or not isinstance(task.get('performance_attempt_id'), str)):
            raise ValueError('FI cost receipt is foreign to its dispatch attempt')
        attempt = task['performance_attempt_id']
        if attempt in cost_attempts:
            raise ValueError('FI dispatch attempt has duplicate cost receipts')
        cost_attempts.add(attempt)
    required_completed = set()
    for started in sorted((directory / 'dispatch-batches').glob('*.started.json')):
        settled = started.with_name(started.name.replace('.started.json', '.settled.json'))
        if not settled.is_file():
            raise ValueError('unsettled FI batch retained; recover its attempts before any redispatch')
        begin, end = json.loads(started.read_text()), json.loads(settled.read_text())
        planned, submitted, done = (begin.get('trial_ids'), end.get('submitted_trial_ids'),
                                   end.get('completed_trial_ids'))
        if (begin.get('campaign_identity') != fingerprint(identity)
                or end.get('started_fingerprint') != fingerprint(begin)
                or end.get('status') not in ('complete_batch', 'unfinished')
                or any(not isinstance(value, list) for value in (planned, submitted, done))
                or not 1 <= len(planned) <= 64
                or any(not isinstance(tid, str) for value in (planned, submitted, done) for tid in value)
                or any(tid not in by_id for tid in planned)
                or len(set(planned)) != len(planned) or len(set(submitted)) != len(submitted)
                or len(set(done)) != len(done) or not set(done) <= set(submitted) <= set(planned)
                or (end['status'] == 'complete_batch' and (submitted != planned or done != planned))):
            raise ValueError('FI batch resume journal identity changed')
        if (begin.get('performance_attempt_id') is not None
                and begin['performance_attempt_id'] not in cost_attempts):
            raise ValueError('FI attempt cost receipt is missing; preserve evidence and report incomplete costs')
        required_completed.update(done)
    completed = {}
    for folder in sorted((directory / 'checkpoints').glob('batch-*')):
        checkpoint = folder / 'index.json'
        if not checkpoint.is_file():
            raise ValueError('unsealed FI checkpoint retained; recover it before dispatch, never rerun blindly')
        checkpoint_meta = json.loads(checkpoint.read_text())
        if (checkpoint_meta.get('method') != 'FI'
                or checkpoint_meta.get('identity_fingerprint') != fingerprint(identity)):
            raise ValueError('foreign FI checkpoint identity')
        for record in read_chunks(checkpoint):
            row = record['trial']
            if (record.get('trial_id') != row['trial_id'] or row['trial_id'] in completed
                    or by_id.get(row['trial_id']) != row):
                raise ValueError('foreign or duplicate FI checkpoint draw')
            if (record['result'].get('status') != 'complete'
                    or record['result'].get('outcome') not in {'Masked','SDC','DUE'}):
                raise ValueError('unfinished FI draw in committed checkpoint')
            if record['result'].get('site_id') != row['site_id']:
                raise ValueError('FI checkpoint result belongs to another physical site')
            log = _attempt_path(directory, row['trial_id'], record['result']['attempt']) / 'run.log'
            if sha(log) != record['result'].get('log_sha256'):
                raise ValueError('retained complete FI output evidence changed')
            completed[row['trial_id']] = record
    if not required_completed <= set(completed):
        raise ValueError('settled FI batch lost its committed completed draws; never rerun them')
    return completed


def _durable_log_digest(log):
    with Path(log).open('rb') as stream:
        os.fsync(stream.fileno())
    return sha(log)


def _immutable_json(path, value):
    if Path(path).exists():
        raise FileExistsError('refuse to replace immutable FI administrative/evidence receipt')
    atomic_json(path, value)


def dispatch_missing(args, directory, identity, spec, assets, outputs, golden, trials, completed, *, window=None):
    """Run only missing draws; all old evidence was checked before this call."""
    if spec.get('defer_evidence') is not True:
        raise ValueError('aggregate FI requires per-draw attempt persistence disabled')
    rows = [row for row in trials if row['trial_id'] not in completed]
    batch_number = len(list((directory / 'checkpoints').glob('batch-*')))
    if window is not None:
        if (args.untimed or window.finished or window.active is not None or window.in_checkpoint
                or window.method != 'FI' or window.output != Path(directory)
                or not isinstance(window.task, dict)
                or window.task.get('campaign_identity') != fingerprint(identity)
                or window.task.get('target_draws') != len(trials)
                or not isinstance(window.task.get('performance_attempt_id'), str)):
            raise ValueError('FI dispatch requires its same unfinished input-loading window')
        performance_attempt = window.task['performance_attempt_id']
        window.task.update(prior_completed_draws=len(completed), missing_draws=len(rows))
    else:
        performance_attempt = None if args.untimed else 'FI-%020d' % time.time_ns()
        window = None if args.untimed else PerformanceWindow('FI', directory, component=args.component,
            task=dict(protocol='sum immutable partial attempts plus final window',
                campaign_identity=fingerprint(identity), target_draws=len(trials),
                prior_completed_draws=len(completed), missing_draws=len(rows),
                performance_attempt_id=performance_attempt))
    def phase(name):
        return window.phase(name) if window else nullcontext()
    try:
        if rows:
            with phase('complete_output_checker_preparation'):
                if spec.get('golden_file_binding') is not None:
                    from script.execution.fi_dispatch_inputs import read_bound_bytes
                    text = read_bound_bytes(golden, spec['golden_file_binding']).decode(errors='replace')
                    golden_summary = _load_log_summary(golden, text=text)
                else:
                    golden_summary = _load_log_summary(golden)
                if not _validate_raw_summary(golden_summary, outputs)['valid']:
                    raise ValueError('FI golden output contract invalid')
    except BaseException as error:
        if window is not None and not window.finished:
            window.save_partial(error, receipt_name='performance-partial-%020d.json' % time.time_ns())
        raise
    execution_spec = dict(spec, _golden_summary=golden_summary) if rows else dict(spec)
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: STOP.set())
    def checkpoint_context(purpose='FI-extra-evidence-64'):
        return window.validation_checkpoint(workers_idle=True, purpose=purpose) if window else nullcontext()

    def prepare_evidence(records, *, completed_records):
        directories = set()
        for record in records:
            result = record.get('result', {})
            detail = result.get('oracle', {}).get('detail', {})
            if completed_records:
                # Full native logs already retain every compared byte. Do not
                # persist a second parsed copy, or N copies of the golden.
                detail.pop('raw_output_witness', None)
                detail['complete_raw_witness_in_retained_native_log'] = True
            if result.get('attempt') is not None:
                attempt = _attempt_path(directory, record['trial_id'], result['attempt'])
                directories.update((attempt, attempt.parent, attempt.parent.parent, directory))
                log = attempt / 'run.log'
                if log.is_file():
                    # A committed chunk must never get ahead of its full log.
                    result['log_sha256'] = _durable_log_digest(log)
                elif completed_records:
                    raise ValueError('completed FI execution lacks its full raw-output log')
            for relative in record.get('unreturned_attempts', []):
                attempt = _attempt_path(directory, record['trial_id'], relative)
                directories.update((attempt, attempt.parent, attempt.parent.parent, directory))
                log = attempt / 'run.log'
                if log.is_file():
                    record.setdefault('unreturned_log_sha256', {})[relative] = _durable_log_digest(log)
        for folder in sorted(directories, key=lambda path: len(path.parts), reverse=True):
            descriptor = os.open(str(folder), os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def save_batch(number, records):
        # Deliberate validation persistence is outside the performance clock.
        with checkpoint_context():
            prepare_evidence(records, completed_records=True)
            write_chunks(directory / 'checkpoints' / ('batch-%06d' % number), records,
                         method='FI', identity=identity)
            # Only terminal evidence with its durable index may lose scratch.
            for record in records:
                work = _attempt_path(directory, record['trial_id'], record['result']['attempt']) / 'work'
                if work.exists():
                    shutil.rmtree(work)
    failures = []
    try:
        for offset in range(0, len(rows), 64):
            batch = rows[offset:offset+64]
            results = []
            # An interrupted unsealed batch must never be mistaken for a batch
            # that did not execute. This small administrative journal is outside
            # performance and is immutable; terminal settlement is a new file.
            journal = directory / 'dispatch-batches' / ('batch-%020d.started.json' % time.time_ns())
            started = dict(campaign_identity=fingerprint(identity),
                trial_ids=[row['trial_id'] for row in batch], workers_idle_before_dispatch=True,
                performance_attempt_id=performance_attempt)
            with checkpoint_context('FI-resume-administration-start'):
                before_attempts = {row['trial_id']: set((directory / 'runs' / row['trial_id']).glob('*'))
                                   for row in batch}
                _immutable_json(journal, started)
            with phase('execute_check_%06d' % batch_number):
                with ThreadPoolExecutor(max_workers=args.jobs) as workers:
                    active = {workers.submit(run_trial, row, execution_spec, assets, directory,
                        golden, outputs): row for row in batch if not STOP.is_set()}
                    for future, row in active.items():
                        try:
                            trial_id, result = future.result()
                            if trial_id != row['trial_id']:
                                raise ValueError('worker returned another draw')
                            if result.get('site_id') != row['site_id']:
                                raise ValueError('worker returned another physical site')
                            record = dict(trial_id=trial_id, trial=row, result=result)
                            if result.get('status') == 'complete' and result.get('outcome') in {'Masked','SDC','DUE'}:
                                results.append(record)
                            else:
                                failures.append(record); STOP.set()
                        except BaseException as error:
                            failures.append(dict(trial_id=row['trial_id'], trial=row,
                                error=str(error))); STOP.set()
            if results:
                save_batch(batch_number, results)
                completed.update({r['trial_id']:r for r in results}); batch_number += 1
            if failures or STOP.is_set():
                with checkpoint_context():
                    for failure in failures:
                        if 'result' not in failure:
                            tid = failure['trial_id']
                            failure['unreturned_attempts'] = [str(path.relative_to(directory)) for path in
                                sorted(set((directory / 'runs' / tid).glob('*')) - before_attempts.get(tid, set()))]
                    prepare_evidence(failures, completed_records=False)
                    _immutable_json(directory / ('unfinished-%020d.json' % time.time_ns()),
                                dict(status='unfinished', failures=failures, completed=len(completed),
                                     infrastructure_failure_is_fault_label=False))
                    _immutable_json(journal.with_name(journal.name.replace('.started.json', '.settled.json')),
                        dict(status='unfinished', started_fingerprint=fingerprint(started),
                            submitted_trial_ids=[row['trial_id'] for row in active.values()],
                            completed_trial_ids=[record['trial_id'] for record in results]))
                if window:
                    window.save_partial("unfinished_dispatch", receipt_name="performance-partial-%020d.json" % time.time_ns())
                return 75
            with checkpoint_context('FI-resume-administration-settlement'):
                _immutable_json(journal.with_name(journal.name.replace('.started.json', '.settled.json')),
                    dict(status='complete_batch', started_fingerprint=fingerprint(started),
                        submitted_trial_ids=[row['trial_id'] for row in active.values()],
                        completed_trial_ids=[record['trial_id'] for record in results]))
        counts = {name: sum(r['result']['outcome']==name for r in completed.values())
                  for name in ('Masked','SDC','DUE')}
        aggregate = dict(schema='sara-FI-aggregate-v1', count=len(completed), counts=counts,
            identity_fingerprint=fingerprint(identity), complete=len(completed)==args.target_count,
            administrative_failure_is_DUE=False, outputs_checked_in_full=True,
            per_draw_evidence_in_performance=False, performance_measurement=not args.untimed)
        aggregate.update(resumed_prior_draws=len(trials)-len(rows),
            active_dispatch_missing_draws=len(rows),
            per_draw_save_attempt_disabled=True,
            timing_requires_all_partial_attempt_receipts=not args.untimed)
        if not aggregate['complete']:
            raise ValueError('FI aggregate missing draws')
        # The full-N aggregate is a required output, not postwindow reporting.
        # The segment aggregate keeps the source07 schema for load_fi callers.
        cumulative = _cumulative_aggregate(args,identity,aggregate)
        cumulative_path = directory/'cumulative-aggregate.json'
        with phase('cumulative_aggregate_persistence'):
            if cumulative_path.exists():
                if json.loads(regular(cumulative_path).read_text()) != cumulative:
                    raise ValueError('unsealed cumulative aggregate differs; preserve before recovery')
            else:
                atomic_json(cumulative_path,cumulative)
        if window:
            window.complete(aggregate)
        else:
            atomic_json(directory / 'aggregate.json', aggregate)
        _immutable_json(directory / 'fi_completion.json', dict(status='complete', aggregate=aggregate, checkpoints=batch_number,
                              timed_receipt='performance-window.json' if window else None,
                              cumulative_file=cumulative_path.name,cumulative_sha256=sha(cumulative_path),
                              resumed_prior_draws_not_rerun=bool(args.resume)))
    except BaseException as error:
        if window is not None and not window.finished:
            window.save_partial(error, receipt_name='performance-partial-%020d.json' % time.time_ns())
        raise
    print(json.dumps(aggregate))
    return 0


def execute(args):
    _check_arguments(args)
    profile = _require_frozen_worker(args)
    args.population_inventory_sha256 = sha(regular(args.population_inventory)) if args.population_inventory else None
    if not 1 <= args.jobs <= profile.cpus:
        raise ValueError('FI workers exceed the recorded CPU bound')
    directory = args.output.resolve() / safe_id(args.campaign_id)
    directory.mkdir(parents=True, exist_ok=args.resume)
    # Identity, old log hashes, resume records and dispatch all share this lock.
    with (directory / 'dispatch.lock').open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return _execute_locked(args, directory)


def _check_arguments(args):
    """Pure fixed-range admission, including callers using execute directly."""
    if (type(args.begin) is not int or type(args.end) is not int
            or (args.begin,args.end) not in RANGES or args.seed != 2026
            or args.application not in CASES or args.architecture not in ('SM75','SM86')):
        raise ValueError('only original14/both-SM seed2026 ranges 0:1000,1000:5000,5000:10000')
    if args.target_count is not None and args.target_count != args.end-args.begin:
        raise ValueError('target count must equal this new range length')
    args.target_count = args.end-args.begin
    args.validation = False  # No diagnostic CLI or <=8-point gate bypass.
    for name,value in [('master',args.master_sha256),('adapter',args.adapter_sha256),
            ('dispatch packet',args.dispatch_inputs_sha256)]+[
            ('prior seal',value) for value in args.prior_seal_sha256]:
        if not isinstance(value,str) or re.fullmatch(r'[0-9a-f]{64}',value) is None:
            raise ValueError('exact 64-hex '+name+' SHA required')
    expected_prior = RANGES.index((args.begin,args.end))
    if len(args.prior_segment) != expected_prior or len(args.prior_seal_sha256) != expected_prior:
        raise ValueError('one read-only root and exact seal SHA required for every preceding range')
    if args.untimed != (args.population_inventory is not None) or (args.untimed and args.component not in ('l1d','l2')):
        raise ValueError('only additional Cache resident cohort uses untimed FI and must provide its inventory')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--simulator-root", type=Path, required=True)
    parser.add_argument("--component", choices=("rf", "l1d", "l2", "smem"), required=True)
    parser.add_argument('--application',choices=tuple(CASES),required=True)
    parser.add_argument('--architecture',choices=('SM75','SM86'),required=True)
    parser.add_argument('--begin',type=int,required=True)
    parser.add_argument('--end',type=int,required=True)
    parser.add_argument('--master-sha256',required=True,help='exact full immutable 10K master bytes')
    parser.add_argument('--adapter-sha256',required=True,help='exact private prefix_fi.py bytes pinned by host')
    parser.add_argument('--verified-prior-cache',type=Path,required=True,
        help='actual once-authenticated sealed summary/source context, mounted read-only')
    parser.add_argument('--verified-prior-cache-sha256',required=True)
    parser.add_argument('--continuous-baseline-sha256',required=True)
    parser.add_argument('--continuous-run-id',required=True)
    parser.add_argument('--continuous-freeze-sha256',required=True)
    parser.add_argument('--prior-segment',action='append',type=Path,default=[],
        help='earlier sealed FI campaign directory, actually mounted read-only, in range order')
    parser.add_argument('--prior-seal-sha256',action='append',default=[],
        help='paired host-pinned fi_completion.json SHA, once per --prior-segment')
    parser.add_argument("--site-manifest", type=Path, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--target-count", type=int,
        help='optional redundant guard; must equal end-begin, never the cumulative count')
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=64)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--watchdog-factor", type=int, default=10,
        help="declared execution-cycle DUE monitor; administrative wall timeout remains interruption")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--untimed", action="store_true", help="validation-only FI, no cost table")
    parser.add_argument('--population-inventory', type=Path,
        help='separate valid-resident Cache population, only with --untimed')
    parser.add_argument('--dispatch-inputs', type=Path,required=True,
        help='small source-owned packet generated once in common study preparation')
    parser.add_argument('--dispatch-inputs-sha256',required=True,
        help='exact packet byte SHA pinned by the host job request')
    args = parser.parse_args(argv)
    return execute(args)


if __name__ == "__main__":
    raise SystemExit(main())
