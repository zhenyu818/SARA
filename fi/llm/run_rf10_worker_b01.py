"""Finite actual RF10 timing pilot; unchanged native hook and FI oracle.

The compact SARA population supplies native coordinates, not predictions or
existing FI selectors. The explicit per-draw ordering bridge is provisional
until the unchanged native ACK verifies every requested physical coordinate.
An unmatched attempt stops the finite job and is never a valid FI outcome.
"""
import argparse
from bisect import bisect_left
import csv
import hashlib
import json
import os
from pathlib import Path
import statistics
import sys
import time

sys.path[:0] = ['/code', '/code/script/common', '/code/script/core']


def need(value, message):
    if not value:
        raise RuntimeError(message)


def pin(path):
    path = Path(path)
    need(path == path.resolve(strict=True) and path.is_file(), 'Canonical bound input required')
    before = path.stat()
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            h.update(block)
    after = path.stat()
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'Input changed')
    return dict(bytes=after.st_size, sha256=h.hexdigest())


def fresh(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n');stream.flush();os.fsync(stream.fileno())


def bound_json(path, expected):
    need(pin(path)['sha256'] == expected, 'Exact input pin differs: ' + str(path))
    return json.loads(Path(path).read_bytes())


def draw_coordinates(rows, mass, population, fingerprint):
    ranks = []
    for index in range(10):
        rejection = 0
        limit = (2**256 // mass) * mass
        while True:
            payload = dict(algorithm='sara-sha256-rejection-v1', population=population,
                           seed=2026, stream='stories260k-sm75-rf-timing46',
                           draw=index, rejection=rejection)
            number = int(fingerprint(payload), 16)
            if number < limit:
                ranks.append((number % mass, index));break
            rejection += 1
    wanted = sorted(ranks)
    cursor = 0
    chosen = [None]*10
    next_rank = 0
    for row_index, row in enumerate(rows):
        width = row['bit_count']
        end = cursor + (row['cycle_stop'] - row['cycle_start'])*width
        while next_rank < len(wanted) and wanted[next_rank][0] < end:
            rank, index = wanted[next_rank]
            offset, bit = divmod(rank-cursor, width)
            site = dict(population_fingerprint=population, component='rf', target=dict(row['target']),
                        cycle=row['cycle_start']+offset, bit=row.get('bit_start', 0)+bit)
            chosen[index] = dict(site, site_id=fingerprint(site), population_rank=rank,
                                 native_span_index=row_index, trial_id='trial-%08d'%index, draw_index=index)
            next_rank += 1
        cursor = end
    need(cursor == mass and next_rank == 10 and all(chosen), 'Complete RF population rank resolution')
    return chosen


def bind_native_selectors(rows, trials, footer):
    # Source-pinned native find_active_threads orders kernel, shader, hardware
    # warp and lane. CTA/linear-tid ordering is reconstructed for these exact
    # native contexts; only the actual ACK can finally admit an individual draw.
    kernels = {r['kernel_uid']:r for r in footer['kernels']}
    thread_order = {}
    for row in footer['threads']:
        block = kernels[row['kernel_uid']]['block']
        x, y, z = row['logical_tid']
        key = row['kernel_uid'], row['thread_id']
        need(key not in thread_order, 'Unique actual native thread identity')
        thread_order[key] = x + block[0]*(y + block[1]*z)
    cycles = sorted({r['cycle'] for r in trials})
    snapshots = {cycle:{} for cycle in cycles}
    for row in rows:
        first = bisect_left(cycles, row['cycle_start'])
        stop = bisect_left(cycles, row['cycle_stop'])
        for cycle in cycles[first:stop]:
            target = row['target']
            key = target['kernel'], target['thread']
            registers = snapshots[cycle].setdefault(key, {})
            need(target['register_uid'] not in registers, 'No overlapping active RF register identities')
            registers[target['register_uid']] = target
    evidence = []
    for trial in trials:
        target, cycle = trial['target'], trial['cycle']
        snapshot = snapshots[cycle]
        kernel = target['kernel']
        active = [key for key in snapshot if key[0] == kernel]
        def order(key):
            registers = snapshot[key]
            any_target = next(iter(registers.values()))
            need(all((r['sm'],r['cta_slot']) == (any_target['sm'],any_target['cta_slot'])
                     for r in registers.values()), 'One actual hardware owner per active native thread')
            return any_target['sm'], any_target['cta_slot'], thread_order[key]
        active.sort(key=order)
        key = kernel, target['thread']
        need(key in active and snapshot[key].get(target['register_uid']) == target,
             'Selected target exists in its exact full native RF lifetime')
        thread_index = active.index(key)
        register_index = sorted(snapshot[key]).index(target['register_uid']) + 1
        trial['hook_params'] = {'-components_to_flip':'0', '-total_cycle_rand':str(cycle),
            '-kernel_n':str(kernel), '-per_warp':'0', '-thread_rand':str(thread_index),
            '-register_rand_n':str(register_index), '-reg_bitflip_rand_n':str(trial['bit']+1)}
        fields = dict(thread='thread', register='reg', register_uid='reg_uid', width_bits='width',
                      kernel='kernel', sm='sm', cta_slot='cta_slot')
        trial['ack_expected'] = dict(component='rf', cycle=str(cycle), bit=str(trial['bit']+1),
            **{ack:str(target[name]) for name,ack in fields.items()})
        evidence.append(dict(trial_id=trial['trial_id'], site_id=trial['site_id'],
            thread_index=thread_index, register_index=register_index,
            active_RF_contexts_in_target_kernel=len(active),
            admission='provisional ordering bridge; exact native ACK mandatory; mismatch stops, no replacement'))
    return evidence


def execute(request, out):
    started = time.perf_counter()
    from script.execution.policy import require_container_execution
    from script.execution.job_wrapper import cgroup_counters, validate_cgroup_limits
    from script.execution.population_inventory import read_stream, validate_lifecycle, validate_production_blockers, COMPACT_SCHEMA
    from script.execution.fi_campaign import run_trial, validate_site_binding, fault_records
    from script.execution.ge_batch_experiment import native_library_fingerprints
    from script.execution.batch_fi import fault_base
    from script.execution.config_options import config_text
    from script.execution.campaign import fingerprint
    from script.common.outcome_oracle import validate_raw_outputs, _load_log_summary

    profile = require_container_execution()
    need((profile.role,profile.cpus,profile.memory_bytes)==('bounded_primary',64,448*1024**3), 'B CPU-only fixed resources')
    validate_cgroup_limits(cgroup_counters(), cpus=64, memory=448*1024**3)
    for name, expected in request['source_files'].items():
        need(pin(Path('/code')/name) == expected, 'Unchanged original FI implementation: '+name)
    capture = Path(request['capture'])
    metadata = bound_json(capture/'capture.json', request['capture_metadata_sha256'])
    closure = bound_json(capture/'capture-closure.json', request['closure_sha256'])
    golden = bound_json(capture/'golden-complete.json', request['golden_sha256'])
    descriptor = bound_json(capture/'initial-state/inputs-rf.json',request['descriptor_sha256'])
    need(descriptor['population_mass']==request['population_mass'] and
         descriptor['population_fingerprint']==request['population_fingerprint'], 'Original full semantic RF domain binding')
    native_source = bound_json(capture/'native-source-files.json',request['native_source_map_sha256'])
    need(native_source['src/gpgpu-sim/gpu-sim.cc']=='60419988da90f0bab116ac72f78b23e193d7f58a2ceea67dfb417a813b8598de'
         and native_source['src/gpgpu-sim/shader.cc']=='ea62a132cde525b97d5e31bc2f9ae70d0df518c55a648371fba4b9eb1b1e7a97',
         'Pinned actual native selector ordering source provenance')
    need(closure['complete'] is True and closure['actual_computational_launches']==72
         and closure['all_output_logits']==512 and golden['complete'] is True
         and golden['all_logits_compared']==512 and golden['failed_logits']==0, 'Original full-model normal proof')
    workload = metadata['workload_contract']
    need((workload['model'],workload['layers'],workload['batch'],workload['input_token_ids'],workload['positions'])
         == ('Stories260K',5,1,[1],[0]), 'Exact original single-token full5layer workload')
    need(workload['arguments']==['/checkpoint/stories260K.bin'], 'Original checkpoint alias')
    need(pin('/program/forward_prefix1')['sha256']==metadata['actual_binary_sha256']==request['binary_sha256'], 'Original compiled executable')
    need(pin('/checkpoint/stories260K.bin')['sha256']==request['checkpoint_sha256']==golden['checkpoint_sha256'], 'Original full checkpoint')
    need(native_library_fingerprints(Path('/native'))==metadata['simulator_libraries'], 'Exact original native libraries')
    output_spec = json.loads((capture/'output-spec.json').read_bytes())
    need(validate_raw_outputs(capture/'run.log', output_spec)['valid'] and not fault_records(capture/'run.log'),
         'Original complete fault-free raw golden')
    golden_summary = _load_log_summary(capture/'run.log')
    raw_population = capture/'population.jsonl.gz'
    need(pin(raw_population)['sha256']==request['raw_population_sha256'], 'Exact original complete native population')
    stream = read_stream(raw_population, decode_budgets=metadata['population_transport']['decode_budgets'])
    need(stream['header']['schema']==COMPACT_SCHEMA and stream['header']['component_filter']=='rf', 'Actual full RF native population')
    validate_production_blockers(stream['blockers'])
    rows = stream['spans']
    for row in rows:
        validate_lifecycle(row, stream['header'])
        need(row['component']=='rf' and row['mapping_supported'] is True, 'No dropping unsupported RF mass')
    need(stream['mass']['rf']==request['population_mass'] and request['population_mass']==182005657052,
         'Original full RF fault-space denominator')
    sidecar = bound_json(capture/'trace.json.gz.completeness.json', request['sidecar_sha256'])
    footer = sidecar['capture_footer']
    need(footer['capture_complete'] is True and footer['total_events']==10184930, 'Original complete native thread-order metadata')
    trials = draw_coordinates(rows, request['population_mass'], request['population_fingerprint'], fingerprint)
    bridge = bind_native_selectors(rows, trials, footer)
    for trial in trials: validate_site_binding(trial)
    manifest = dict(schema='stories-RF10-native-coordinate-pilot46-v1', seed=2026,
        sampling='with_replacement', algorithm='sara-sha256-rejection-v1',
        stream='stories260k-sm75-rf-timing46', population_fingerprint=request['population_fingerprint'],
        population_size=request['population_mass'], native_span_order_binding=request['raw_population_sha256'],
        trials=trials, prediction_answers_used=False, original14_masters_modified=False,
        selector_bridge='new source-bound native-order adapter; each draw requires complete unchanged native ACK')
    fresh(out/'manifest-rf10.json', manifest);fresh(out/'mapping-plan.json', bridge)
    del stream, rows, sidecar, footer
    runtime = Path('/native');config='gcc-9.4.0/cuda-11080/release'
    os.environ.update(GPGPUSIM_ROOT=str(runtime), GPGPUSIM_CONFIG=config,
        CUDA_INSTALL_PATH='/usr/local/cuda', PTXAS_CUDA_INSTALL_PATH='/usr/local/cuda',
        LD_LIBRARY_PATH=str(runtime/'lib'/config)+':/usr/local/cuda/lib64',
        PATH=str(runtime/'bin')+':/usr/local/cuda/bin:/usr/local/bin:/usr/bin:/bin')
    for key in ('LD_PRELOAD','LD_AUDIT','LD_DEBUG','LD_DEBUG_OUTPUT'): os.environ.pop(key,None)
    assets = {'LLM_TinyStories260K':Path('/program/forward_prefix1')}
    for item in request['configuration_assets']:
        path=Path('/configuration')/Path(item['path']).name
        need(pin(path)=={k:item[k] for k in ('bytes','sha256')}, 'Original configuration asset')
        assets[path.name]=path
    original = (capture/'gpgpusim.config').read_text()
    need(hashlib.sha256(original.encode()).hexdigest()==metadata['effective_config_sha256'], 'Actual captured configuration identity')
    base = config_text(fault_base(original), {'-gpgpu_max_cycle':str(metadata['gpu_cycles']*10)})
    spec = dict(schema_version=1, purpose='correctness', campaign_kind='author_requested_RF10_timing_pilot',
        command=['./LLM_TinyStories260K','/checkpoint/stories260K.bin'], environment={'SARA_VALIDATE_CPU':'0'},
        timeout_seconds=86400, retain_work=True, reuse_readonly_assets=True, record_trial_costs=True,
        validation_only=False, defer_evidence=False, base_config_text=base,
        assets={name:str(path) for name,path in assets.items()}, assets_sha256={name:pin(path)['sha256'] for name,path in assets.items()},
        population_fingerprint=request['population_fingerprint'], input_fingerprint=fingerprint(metadata),
        fault_model='active-allocated-simulator-rf-smem-single-bit-v1',
        simulation_cycle_watchdog=dict(cycle_limit=metadata['gpu_cycles']*10, golden_cycles=metadata['gpu_cycles'],
            factor=10, rule='existing10x_actual_golden_cycles', administrative_process_timeout_is_DUE=False))
    fresh(out/'FI-spec.json',spec)
    spec['_golden_summary']=golden_summary
    preparation_seconds=time.perf_counter()-started
    fresh(out/'preparation-complete.json',dict(preparation_seconds=preparation_seconds, FI_calls=0,
        original_forward_capture_compile_reexecutions=0, original_native_golden_reused=True,
        actual_draws=10, all_draw_coordinates_frozen=True, selectors_require_actual_ACK=True))
    print(json.dumps(dict(stage='RF10_dispatch', preparation_seconds=preparation_seconds, completed=0)),flush=True)
    run_started=time.perf_counter();records=[];times=[]
    for trial in trials:
        one=time.perf_counter()
        identifier, record=run_trial(trial,spec,assets,out,capture/'run.log',output_spec)
        call_seconds=time.perf_counter()-one
        fresh(out/(identifier+'-result.json'),dict(trial=trial,result=record,complete_call_wall_seconds=call_seconds))
        records.append(record)
        times.append(dict(trial_id=identifier,draw_index=trial['draw_index'],site_id=trial['site_id'],
            cycle=trial['cycle'],status=record['status'],outcome=record.get('outcome'),
            native_process_wall_seconds=record.get('wall_seconds'),complete_call_wall_seconds=call_seconds))
        with (out/'rf10-times.csv').open('a',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=list(times[0]))
            if len(times)==1:writer.writeheader()
            writer.writerow(times[-1])
            stream.flush();os.fsync(stream.fileno())
        need(record['status']=='complete' and record.get('fault_acknowledgement',{}).get('status')=='applied',
             'Unfinished/unmapped/identity-mismatched actual draw; preserve all, do not replace or retry')
        print(json.dumps(dict(stage='RF10_dispatch',completed=len(records),outcome=record['outcome'],
                              native_seconds=record['wall_seconds'],complete_call_seconds=call_seconds)),flush=True)
    dispatch_seconds=time.perf_counter()-run_started
    values=[r['complete_call_wall_seconds'] for r in times]
    native_values=[r['native_process_wall_seconds'] for r in times]
    mean=statistics.mean(values)
    estimates=dict(status='conditional_estimates_only', actual_RF_complete=10,
        per_component_budget=384, total_future_injections=1536, future_FI_executed=0,
        scheduling='sequential; no64x_parallel_speedup_assumed',
        RF384_dispatch_seconds=384*mean, RF384_assuming_same_observed_preparation_seconds=preparation_seconds+384*mean,
        all4_dispatch_seconds_assuming_RF_per_call_cost=1536*mean,
        all4_assuming_RF_per_call_and_RF10_preparation_cost_each=4*(preparation_seconds+384*mean),
        all4_minmax_observed_RF_call_scenario_seconds=[1536*min(values),1536*max(values)],
        assumptions=['Only RF10 is measured; no SMEM/L1D/L2 FI measurements',
            'Other component fault consequences and watchdog frequency can change runtime',
            'RF10 population/mapping preparation is not measured at384 draws',
            'Min/max scenarios are not confidence intervals',
            'Sampling preparation and container startup/exit costs separately reported, not filled with zero'])
    fresh(out/'estimates.json', estimates)
    fresh(out/'complete.json',dict(status='complete', actual_RF_complete=10, requested_RF=10,
        all_actual_ACKs_match=True, SARA_GEREM_predictions_used=False, counts={name:sum(r['outcome']==name for r in records) for name in ('Masked','SDC','DUE')},
        preparation_seconds=preparation_seconds,dispatch_complete_calls_seconds=dispatch_seconds,
        complete_call_mean_seconds=mean,complete_call_min_seconds=min(values),complete_call_max_seconds=max(values),
        native_mean_seconds=statistics.mean(native_values),native_sum_seconds=sum(native_values),
        complete_call_sample_stdev_seconds=statistics.stdev(values),
        worker_to_before_final_completion_persistence_seconds=time.perf_counter()-started,
        outer_Docker_lifecycle_clock='host original actual StartedAt/FinishedAt saved separately after exit',
        estimates=estimates, no_384_experiment_executed=True, no_SARA_analysis_or_recompile_or_capture=True,
        fault_free_golden_forward_reexecutions=0, single_bit_FI_forward_executions=10,
        no_accuracy_claim_from10draws=True, all_failed_and_actual_evidence_preserved=True))


def main():
    p=argparse.ArgumentParser();p.add_argument('--request',type=Path,required=True);p.add_argument('--request-sha256',required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    need(pin(a.request)['sha256']==a.request_sha256, 'Exact host-bound pilot request')
    need(a.output==a.output.resolve(strict=True) and a.output.is_dir() and not tuple(a.output.iterdir()), 'Fresh private FI pilot output')
    try: execute(json.loads(a.request.read_bytes()),a.output)
    except BaseException as error:
        fresh(a.output/'failed.json',dict(status='failed_preserve_no_automatic_retry',error=repr(error),
            FI_complete=False, partial_is_not10complete=True, no_replacement_or_resampling=True))
        raise


if __name__=='__main__':main()
