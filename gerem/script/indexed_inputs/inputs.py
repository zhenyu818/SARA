"""The method_v1 own-input gates plus a method-local complete-fact pool.

RFTR decoding follows its native header and <QII> records. Shared-profile
decoding reuses only the source-bound, value-free read_profile adapter. Cache
rows/residencies come from original raw_physical within the invocation byte context.
Metadata byte counts below are unique bound files, never claimed physical I/O.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import struct


class InputPool:
    """No cross-invocation cache, parsed preflight object, or path-only sharing."""
    def __init__(self):
        self.values = {}; self.counts = dict(raw_builds=0,raw_hits=0,record_builds=0,record_hits=0)
        self.closed = False

    def fact(self,key,path,loader,role):
        _need(not self.closed,'input pool already closed')
        before = _identity(path)
        if key in self.values:
            producer,identity,value = self.values[key]
            _need(_identity(producer) == identity,'producer fact input changed')
            self.counts[role+'_hits'] += 1
        else:
            value = loader(); self.values[key] = (path,before,value)
            self.counts[role+'_builds'] += 1
        _need(_identity(path) == before,'consumer fact input changed')
        return value

    def close(self):
        self.values.clear(); self.closed = True

    def statistics(self):
        return dict(self.counts,retained_fact_entries=len(self.values),closed=self.closed,
            sharing='same whole-file SHA/size + decoder/Validator identity; each own binding still checked')


def _record_facts(rows,validator_type):
    checker = validator_type()
    for row in rows: checker.consume(row)
    return checker.report(),checker.header,checker.last_cycle,checker.hooks


def _need(value, message):
    if not value:
        raise ValueError(message)


def _identity(path):
    row = path.stat()
    return tuple(getattr(row,key) for key in
                 ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_nlink'))


def _canonical(path, directory=False):
    path = Path(path).absolute()
    _need(path == path.resolve(strict=True) and path.is_dir() == directory
          and (directory or path.is_file()), 'canonical declared input type required')
    _need(os.statvfs(path).f_flag & os.ST_RDONLY, 'actual read-only own input mount required')
    return path


class _Reads:
    def __init__(self, root):
        self.root, self.files, self.direct_bytes = root, {}, 0

    def remember(self, path, sha256, role, *, external=False):
        path = _canonical(path)
        _need(external or path == self.root or self.root in path.parents, 'input escapes its own root')
        _need(type(sha256) is str and re.fullmatch('[0-9a-f]{64}',sha256), 'complete input SHA required')
        identity = _identity(path)
        old = self.files.get(path)
        _need(old is None or old['identity'] == identity and old['sha256'] == sha256, 'input identity changed')
        self.files[path] = dict(identity=identity,sha256=sha256,role=role)
        return path

    def read(self, path, role, expected=None, *, external=False):
        from script.execution.method_input_context import current_context
        path = _canonical(path); before = _identity(path); context = current_context(path)
        _need(context is not None,'method-local source byte context required')
        raw = context.read_bytes(path)
        _need(before == _identity(path) and len(raw) == before[2], 'input changed while decoded')
        digest = context.digest(path)
        if expected is not None:
            _need(type(expected) is dict and expected.get('path') == str(path)
                  and type(expected.get('bytes')) is int and expected['bytes'] == len(raw)
                  and expected.get('sha256') == digest, 'external input byte identity differs: '+role)
        self.remember(path,digest,role,external=external)
        self.direct_bytes += len(raw)
        return raw

    def summary(self):
        return dict(unique_bound_input_file_bytes=sum(row['identity'][2] for row in self.files.values()),
            decoder_requested_bytes=self.direct_bytes,decoder_direct_read_bytes=None,total_input_read_bytes=None,
            byte_count_scope='decoder byte requests can hit the invocation byte cache; unique bound files are not physical IO; use byte context and process/cgroup IO separately',
            files=[dict(path=str(path),bytes=row['identity'][2],sha256=row['sha256'],role=row['role'])
                   for path,row in self.files.items()])


def _own(capture, relative):
    relative = Path(relative)
    _need(not relative.is_absolute() and '..' not in relative.parts, 'portable own path required')
    path = _canonical(capture/relative)
    _need(capture in path.parents, 'input follows a file outside its own capture')
    return path


def decode_rftr(data, inventory):
    """Preserve RF allocation, UID/kernel identity and same-cycle access order."""
    names, births, spans = {}, {}, {}
    for span in inventory['spans']:
        _need(span['component'] == 'rf', 'RF-only inventory required')
        target = span['target']; key = target['kernel'],target['thread'],target['register_uid']
        name = '%%method_k%d_t%d_u%d' % key
        _need(key not in names or names[key] == (name,target['register']), 'one RF UID has inconsistent names')
        names[key] = name,target['register']
        births[key] = min(births.get(key,span['cycle_start']),span['cycle_start'])
        spans.setdefault(key,[]).append((span['cycle_start'],span['cycle_stop']))
    header, record = struct.Struct('<IHHII'),struct.Struct('<QII')
    _need(len(data) >= header.size and header.unpack_from(data) == (0x52544652,1,16,1,0), 'native RFTR-v1 header required')
    _need((len(data)-header.size) % record.size == 0, 'partial native RFTR record')
    owners = {}
    for key in names:
        owners.setdefault(key[1:],[]).append(key)
    events = [dict(cycle=cycle,_order=-1,kernel_uid=key[0],thread_id=key[1],
        dst_reg=names[key][0],dst_reg_uid=key[2],src_regs=[],src_reg_uids=[],
        allocator_birth_not_PTX_instruction=True) for key,cycle in births.items()]
    previous,excluded = -1,0
    for ordinal,offset in enumerate(range(header.size,len(data),record.size)):
        cycle,thread,raw_uid = record.unpack_from(data,offset)
        _need(cycle >= previous, 'RFTR records are not chronologically ordered'); previous = cycle
        uid,write = raw_uid & 0x7fffffff,bool(raw_uid & 0x80000000)
        candidates = owners.get((thread,uid),[])
        if not candidates:
            excluded += 1  # Native builtins/non-allocated identities are not canonical RF sites.
            continue
        if len(candidates) > 1:
            candidates = [key for key in candidates if any(first <= cycle < stop for first,stop in spans[key])]
        _need(len(candidates) == 1, 'RFTR kernel identity cannot be proved from its own population')
        key = candidates[0]; name = names[key][0]
        events.append(dict(cycle=cycle,_order=ordinal,kernel_uid=key[0],thread_id=thread,
            dst_reg=name if write else None,dst_reg_uid=uid if write else -1,
            src_regs=[] if write else [name],src_reg_uids=[] if write else [uid]))
    events.sort(key=lambda row:(row['cycle'],row['_order']))
    return dict(events=events),names,dict(binary_records=(len(data)-header.size)//record.size,
        excluded_nonpopulation_accesses=excluded,allocated_registers=len(names),
        same_cycle_read_write_order_preserved=True,probability_or_lifetime_index_built=False)


def load_inputs(entry, *, component, budget, pool=None):
    """Load one declared GEREM stratum and the exact requested master prefix."""
    from script.execution.method_input_context import current_context
    from script.execution.checked_method_inputs import checked_inputs
    _need(current_context() is not None and current_context().method == 'gerem',
          'one active GEREM method-local byte/decode context required')
    _need(component in ('rf','smem','l1d','l2') and type(budget) is int and budget in (1000,5000,10000), 'one cold supported stratum/budget required')
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
    master_raw = reads.read(entry['master']['path'],'complete_10k_master',entry['master'],external=True)
    manifest = json.loads(master_raw)
    _need(type(manifest.get('seed')) is int and manifest['seed'] == 2026 and len(manifest['trials']) == 10000, 'same complete seed2026 10K master required')
    trials = population.validate_manifest(manifest,target_count=budget,seed=2026,dispatch_limit=10000)
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
        master=dict(path=entry['master']['path'],bytes=len(master_raw),sha256=entry['master']['sha256']))
    verify_unchanged(value)
    return value


def map_trial(prepared, trial):
    """Translate RF display names only; original draw ID, UID, kernel and bit stay unchanged."""
    if prepared['component'] != 'rf':
        return trial
    target = trial['target']; key = target['kernel'],target['thread'],target['register_uid']
    _need(key in prepared['names'] and prepared['names'][key][1] == target['register'], 'canonical RF alias differs from actual allocation')
    return dict(trial,target=dict(target,register=prepared['names'][key][0]))


def verify_unchanged(prepared):
    for path,row in prepared['reads'].files.items():
        _need(_identity(path) == row['identity'], 'read-only input identity changed before durable result')
