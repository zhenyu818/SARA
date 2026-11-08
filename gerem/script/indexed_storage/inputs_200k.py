"""200K input/count adapter only; original <=10K loader is not replaced.

Copied frozen v1 load_inputs with only supported count, declared master/proof
binding, and validate_manifest dispatch limit changed. Decoders, population,
raw/index preparation, numerical rules and identity verification are retained.
This module is selected only by the separate 200K workload.
"""
import hashlib
import json
import os
from pathlib import Path
import re
from script.indexed_inputs.inputs import (
    _need,_canonical,_Reads,_own,_identity,_record_facts,decode_rftr,verify_unchanged)

def load_inputs_200k(entry, *, component, budget, pool=None):
    """Load one declared GEREM stratum and the exact requested master prefix."""
    from script.execution.method_input_context import current_context
    from script.execution.checked_method_inputs import checked_inputs
    _need(current_context() is not None and current_context().method == 'gerem',
          'one active GEREM method-local byte/decode context required')
    _need(component in ('rf','smem','l1d','l2') and type(budget) is int and budget == 200000, 'one cold supported stratum/budget required')
    _need(entry['component'] == component, 'selected component differs from plan')
    own = entry['methods']['gerem']['own_input']; root = _canonical(own['root'],True)
    capture = _canonical(own['capture'],True); descriptor_path = _canonical(own['inputs']['path'])
    _need(root in capture.parents and descriptor_path.parent == capture, 'GEREM descriptor/capture must belong to one own root')
    reads = _Reads(root)
    metadata = json.loads(reads.read(own['capture_metadata']['path'],'capture_metadata',own['capture_metadata']))
    descriptor = json.loads(reads.read(descriptor_path,'descriptor',own['inputs']))
    expected_roles = {'inventory','output_spec'} | ({'cache_ledger'} if component in ('l1d','l2') else set())
    _need(descriptor.get('schema') == 'sara-population-inputs-v2' and set(descriptor['files']) == expected_roles, 'population-only own descriptor required; no SARA numeric trace')
    for item in descriptor['files'].values():
        _own(capture,item['path'])
    checked,paths,inventory,population = checked_inputs(descriptor_path,analysis=False)
    _need(checked == descriptor and population.component == component, 'complete checked own domain differs')
    for role,path in paths.items():
        reads.remember(path,descriptor['files'][role]['sha256'],role)
    collection = {'rf':'gerem-rf','smem':'gerem-smem','l1d':'gerem-cache','l2':'gerem-cache'}[component]
    _need(metadata.get('collection') == collection and metadata.get('cache_state') is (component in ('l1d','l2')), 'wrong own collector/cache policy')
    for left,right in (('case','case'),('actual_binary_sha256','binary_sha256'),('arguments','arguments'),('simulator_libraries','simulator_libraries')):
        _need(left in metadata and right in descriptor and metadata[left] == descriptor[right], 'own computation identity differs: '+left)
    _need(re.fullmatch('[0-9a-f]{64}',metadata.get('native_source_fingerprint','')), 'actual native source fingerprint required')
    config = _own(capture,'gpgpusim.config')
    config_raw = reads.read(config,'effective_config')
    _need(hashlib.sha256(config_raw).hexdigest() == metadata.get('effective_config_sha256'), 'actual executed config differs')
    from script.execution.ge_batch_experiment import packet
    log = _own(capture,'run.log'); text = reads.read(log,'own_execution_log').decode('utf8')
    _need(packet(log,descriptor['case'],text=text) == metadata.get('output'), 'own native output/metadata binding differs')
    master_ref = entry['master_200k']
    master_raw = reads.read(master_ref['path'],'complete_200k_extension',master_ref,external=True)
    manifest = json.loads(master_raw)
    proof_ref = entry['master_extension_manifest']
    proof = json.loads(reads.read(proof_ref['path'],'200k_extension_proof',proof_ref,external=True))
    _need(proof.get('schema') == 'gerem-fi-compat-extension-200k-v1' and proof.get('status') == 'PASS', 'completed independent extension proof required')
    matches = [row for row in proof['components'] if row['new_master'] == master_ref]
    _need(len(matches) == 1 and matches[0]['original_master'] == entry['master'] and matches[0]['first_10000_draws_exact'] is True and matches[0]['draws'] == 200000, 'this exact original/new master pair must be certified')
    _need(manifest.get('extension',{}).get('original_master') == entry['master'] and manifest['extension'].get('first_10000_draws_exact') is True, 'new master provenance differs')
    _need(type(manifest.get('seed')) is int and manifest['seed'] == 2026 and len(manifest['trials']) == 200000 and manifest.get('algorithm') == 'sara-sha256-rejection-v1', 'complete seed2026 200K extension required')
    trials = population.validate_manifest(manifest,target_count=budget,seed=2026,dispatch_limit=200000)
    _need(len(trials) == budget, 'requested ordered prefix is incomplete')
    trace = static = rows = residencies = names = None; cache_fact_key = None
    if component == 'rf':
        path = _own(capture,'regfile_trace.bin')
        trace,names,facts = decode_rftr(reads.read(path,'native_rf_def_use'),inventory)
        current_context(path).count(path,'rf_def_use_decodes')
        facts.update(decoded_model_events=len(trace['events']),
            event_count_scope='RFTR storage reads/writes plus allocation births; not dynamic PTX instruction count')
    elif component == 'smem':
        from script.execution.batch_shared_gerem import read_profile
        path = _own(capture,'shared.jsonl'); before = _identity(path)
        trace,static,facts = read_profile(path,inventory,source_fingerprint=metadata['native_source_fingerprint'])
        _need(_identity(path) == before, 'shared profile changed during original closed decode')
        reads.remember(path,facts['def_use_sha256'],'native_shared_def_use')
        facts.update(decoded_model_events=len(trace['events']),
            static_instructions=len(static['events']),
            event_count_scope='shared accesses plus allocation births; static CFG kept separate; not dynamic PTX instruction count')
    else:
        from script.execution.cache_physical_facts import raw_physical
        from script.execution.memory_effect_records import MAX_LEDGER_BYTES
        from script.storage_rules.population_records import PopulationRecordValidator
        path = _own(capture,'memory.jsonl'); _need(paths['cache_ledger'] == path, 'descriptor ledger is not its actual own memory stream')
        before = _identity(path)
        cache_fact_key = (descriptor['files']['cache_ledger']['sha256'],before[2])
        raw_key = ('raw-physical',raw_physical)+cache_fact_key
        raw_hit = pool is not None and raw_key in pool.values
        rows,residencies = (pool.fact(raw_key,path,lambda:raw_physical(path),'raw') if pool is not None
                           else raw_physical(path))
        _need(_identity(path) == before, 'cache ledger changed during original raw closure')
        record_key = ('population-records',PopulationRecordValidator)+cache_fact_key
        record_hit = pool is not None and record_key in pool.values
        report,header,last_cycle,hooks = (pool.fact(record_key,path,
            lambda:_record_facts(rows,PopulationRecordValidator),'record') if pool is not None
            else _record_facts(rows,PopulationRecordValidator))
        _need(header['cache_state_enabled'] is True and header.get('capture_profile') in
            ('storage-population-v1','storage-efm-v1') and before[2] <= header['max_ledger_bytes'] <= MAX_LEDGER_BYTES,
            'actual value-free cache mode or declared ledger byte budget differs')
        _need(report['source_fingerprint'] == header['source_fingerprint'] == metadata['native_source_fingerprint']
            and report['image_id'] == header['image_id'],
            'raw cache producer differs from its actual own capture source')
        _need(report['records'] == len(rows)-1 and report['cache_hook_ticks'] == residencies['hook_ticks']
            and report['cache_bit_cycles'] == residencies['bit_cycles']
            and last_cycle+1 == residencies['cycle_stop']
            and last_cycle-hooks+1 == residencies['first_cycle'],
            'record Validator and complete RLE hook window/domain mass disagree')
        checked_report = {key:report[key] for key in ('schema','records','record_consistency_checked',
            'cache_transport_counts','cache_hook_ticks','cache_bit_cycles','source_fingerprint','image_id',
            'actual_process_pid','retained_worker_authenticity_verified','replay_authorized','mapping_certified','all_gates_pass',
            'capture_profile','functional_operand_equality_checked','actual_optional_bytes_shape_only',
            'functional_null_operands','functional_present_operand_shape_checks')}
        checked_report.update(copy_effects_checked=len(report['copy_effects']),
            symbol_definition_records_checked=len(report['symbol_definition_records']),
            static_initializations_checked=len(report['static_initializations']),
            population_override_counts=report['population_overridden_record_counts'],
            byte_assignment_equality_checked=report['byte_assignment_equality_checked'],
            parameter_byte_equality_checked=report['parameter_byte_equality_checked'],
            static_initializer_byte_equality_checked=report['static_initializer_byte_equality_checked'],
            numerical_payloads_synthesized=False)
        facts = dict(raw_records=len(rows),residency_spans=len(residencies['residency_spans']),
            original_raw_physical_calls=0 if raw_hit else 1,numeric_trace_read=False,SnapshotProfile_used=False,
            own_header_source_binding_verified=True,header_image_id=rows[0]['image_id'],
            original_raw_prefix_and_owner_builder_executed=not raw_hit,
            original_raw_prefix_and_owner_builder_results_verified_or_identically_reused=True,
            population_record_validator_passes=0 if record_hit else 1,record_validator_report=checked_report,
            whole_identical_raw_fact_reused=raw_hit,whole_identical_record_validation_reused=record_hit,
            actual_closed_request_lifecycle_checked=True,validator_RLE_hooks_and_mass_equal=True,
            declared_ledger_byte_budget_checked=True,numeric_trace_or_sidecar_binding_claimed=False,
            individual_raw_row_byte_budget_revalidated=False,
            whole_raw_to_inventory_population_reconstruction_repeated=False)
    value = dict(component=component,descriptor=descriptor,population=population,trials=trials,
        trace=trace,static_trace=static,rows=rows,residencies=residencies,names=names,reads=reads,
        metadata=metadata,profile=facts,cache_fact_key=cache_fact_key,
        master=dict(path=master_ref['path'],bytes=len(master_raw),sha256=master_ref['sha256']))
    verify_unchanged(value)
    return value


