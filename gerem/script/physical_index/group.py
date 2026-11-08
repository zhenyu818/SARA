"""One actual application/architecture, one fresh independent N invocation.

Primary callers use collect_points=False: no per-draw JSON or digest work.
Reference checking is an explicitly separate C workflow and never an A oracle.
"""
from collections import Counter
from contextlib import nullcontext
import gc
import hashlib
import json
import math
from pathlib import Path
from . import MODEL
from script.indexed_inputs.inputs import InputPool,load_inputs,map_trial,verify_unchanged
from script.indexed_inputs.rf_smem import IndexedStorageEFM
from .cache import IndexedCacheEFM,PreparedCacheIndex
from script.storage_rules import rf_smem as method_storage
from script.cache_rules import cache as method_cache
from script.method_group.group_context import make_context
from script.execution.method_input_context import current_context


def _need(ok,message):
    if not ok: raise ValueError(message)


def _phase(factory,name):
    return factory(name) if factory is not None else nullcontext()


def _point(trial,position,answer):
    return dict(draw_index=trial['draw_index'],prefix_position=position,trial_id=trial['trial_id'],
        site_id=trial['site_id'],component=trial['component'],target=trial['target'],cycle=trial['cycle'],
        bit=trial['bit'],original_population_rank=trial['population_rank'],answer=answer)


class PreparedGroup:
    def __init__(self,group,budget,components,pool,inputs,models,cache_indexes,context):
        self.group,self.budget,self.components = group,budget,components
        self.pool,self.inputs,self.models = pool,inputs,models
        self.cache_indexes,self.context = cache_indexes,context
        self.started = self.completed = self.closed = False


def prepare_group(group,*,budget,phase_factory=None):
    _need(type(budget) is int and budget in (1000,5000,10000),'one independent supported N required')
    entries = group['components']; components = tuple(entry['component'] for entry in entries)
    _need(components in (('rf','l1d','l2'),('rf','smem','l1d','l2')),'only actual three/four component groups supported')
    _need(current_context() is None,'one independently owned method invocation required')
    roots = {entry['component']:entry['methods']['gerem']['own_input']['root'] for entry in entries}
    context = make_context(roots,method='gerem',extra_files=tuple(entry['master']['path'] for entry in entries))
    context.__enter__()
    pool = InputPool(); inputs = {}; models = {}; indexes = {}
    try:
        with _phase(phase_factory,'own_input_decode'):
            for entry in entries:
                component = entry['component']
                inputs[component] = load_inputs(entry,component=component,budget=budget,pool=pool)
            identity_fields = ('case','binary_sha256','arguments','simulator_libraries')
            original = inputs['rf']['descriptor']
            _need(all(all(prepared['descriptor'][key] == original[key] for key in identity_fields)
                for prepared in inputs.values()),'all components must describe the same actual computation')
        with _phase(phase_factory,'own_model_preparation'):
            for component in components:
                prepared = inputs[component]
                if component in ('rf','smem'):
                    models[component] = IndexedStorageEFM(prepared['trace'],
                        {'window':prepared['population'].window},prepared['static_trace'])
                else:
                    key = prepared['cache_fact_key']
                    if key not in indexes:
                        indexes[key] = PreparedCacheIndex(prepared['rows'],prepared['residencies'])
                    models[component] = IndexedCacheEFM(prepared['rows'],prepared['residencies'],index=indexes[key])
        return PreparedGroup(group,budget,components,pool,inputs,models,indexes,context)
    except BaseException as error:
        models.clear(); inputs.clear(); indexes.clear(); pool.close(); gc.collect()
        context.__exit__(type(error),error,error.__traceback__)
        raise


def evaluate_group(prepared,*,phase_factory=None,collect_points=False):
    _need(type(prepared) is PreparedGroup and not prepared.started and not prepared.closed,'one fresh prepared group required')
    _need(type(collect_points) is bool,'explicit A/C detail policy required')
    prepared.started = True; accumulators = {}; points = {} if collect_points else None
    digests = {} if collect_points else None
    with _phase(phase_factory,'point_queries'):
        for component in prepared.components:
            inputs,model = prepared.inputs[component],prepared.models[component]
            probabilities,efms,statuses,reasons = [],Counter(),Counter(),Counter(); unknown = 0
            native_efms,unsupported_statuses,unsupported_reasons = Counter(),Counter(),Counter()
            unsupported = 0
            if collect_points: points[component] = []; digest = hashlib.sha256()
            for position,trial in enumerate(inputs['trials']):
                answer = model.query(map_trial(inputs,trial))  # Every draw, including duplicates, is queried.
                _need(type(answer) is dict and {'efm','p_sdc','support_status','reason'} <= set(answer)
                    and answer['efm'] in (None,'benign','dcr','ebc'),'native EFM/probability answer required')
                probability = answer['p_sdc']
                _need(probability is None or type(probability) in (int,float) and math.isfinite(probability)
                    and 0<=probability<=1,'invalid scientific probability')
                if probability is None: unknown += 1
                else: probabilities.append(probability)
                if answer['efm'] is not None: native_efms[answer['efm']] += 1
                if answer['efm'] is None or probability is None:
                    unsupported += 1
                    unsupported_statuses[answer.get('support_status','unreported')] += 1
                    unsupported_reasons[answer.get('reason') or 'unspecified'] += 1
                else: efms[answer['efm']] += 1
                statuses[answer.get('support_status','unreported')] += 1
                reasons[answer.get('reason') or 'unspecified'] += 1
                if collect_points:
                    row = _point(trial,position,answer); points[component].append(row)
                    digest.update((json.dumps(row,allow_nan=False,separators=(',',':'))+'\n').encode())
            accumulators[component] = (probabilities,efms,statuses,reasons,unknown,native_efms,
                unsupported,unsupported_statuses,unsupported_reasons)
            if collect_points: digests[component] = digest.hexdigest()
    result = {}; receipts = {}; statistics = {}
    with _phase(phase_factory,'probability_aggregation'):
        for component in prepared.components:
            inputs,model = prepared.inputs[component],prepared.models[component]
            (probabilities,efms,statuses,reasons,unknown,native_efms,
                unsupported,unsupported_statuses,unsupported_reasons) = accumulators[component]
            total = math.fsum(probabilities); n = prepared.budget
            assumptions = (dict(method_storage.SUPPORTED_SUBSET,
                lookup='serial_order_preserving_indexes_and_static_SIC_core_reuse',
                sic_residual_tolerance=model.sic_tolerance,sic_maximum_iterations=model.sic_max_iterations)
                if component in ('rf','smem') else dict(cache_reconstruction=list(method_cache.RECONSTRUCTION_ASSUMPTIONS)))
            result[component] = dict(schema='gerem-fair-storage-probability-aggregate-v2',status='COMPLETE',method='GEREM',model=MODEL,
                group_id=prepared.group['group_id'],application=prepared.group['application'],architecture=prepared.group['architecture'],
                component=component,planned=n,completed=n,denominator=n,
                efm_counts={name:efms[name] for name in ('benign','dcr','ebc')},
                native_known_efm_counts={name:native_efms[name] for name in ('benign','dcr','ebc')},
                unsupported_draws=unsupported,unsupported_by_status=dict(unsupported_statuses),
                unsupported_by_reason=dict(unsupported_reasons),
                EFM_count_scope='efm_counts require known EFM and probability; native_known_efm_counts separately preserve known EFM even when SIC probability is unsupported',
                support_status_counts=dict(statuses),reason_counts=dict(reasons),p_sdc_sum=total,unknown_draws=unknown,
                p_sdc_mean_known=None if n==unknown else total/(n-unknown),p_sdc_mean_full_N_bounds=[total/n,(total+unknown)/n],
                independent_DUE_probability=None,DUE=None,hard_label_generated=False,unknown_is_not_a_method_EFM=True,
                legacy_query_outcome_not_used_for_hard_label_evaluation=True,
                population_fingerprint=inputs['population'].identity,population_mass=inputs['population'].mass,
                master=inputs['master'],explicit_reproduction_assumptions=assumptions,
                method_original_code_available=False,method_fidelity_fully_certified=False)
            capability = model._index.report if component in ('l1d','l2') else None
            result[component]['cache_capability'] = (None if capability is None else
                {key:capability[key] for key in ('schema','status','writebacks_seen','matched_writebacks',
                    'actual_dirty_replacements','all_observed_writebacks_uniquely_matched','errors',
                    'source_fingerprint','image_id','actual_producer_certified','full_method_fidelity_certified')})
            required_files = []
            for path,identity in inputs['reads'].files.items():
                state = path.stat()
                required_files.append(dict(path=str(path),logical_bytes=state.st_size,
                    allocated_bytes=state.st_blocks*512 if hasattr(state,'st_blocks') else None,
                    role=identity['role']))
            receipts[component] = dict(master=inputs['master'],decoder_profile=inputs['profile'],
                input_bytes=inputs['reads'].summary(),required_raw_input_files=required_files,
                necessary_temporary_files=[],temporary_file_policy='no model temporary files are created by this package',
                peak_disk_space_bytes=None,space_is_current_file_metadata_not_peak=True)
            statistics[component] = model.statistics()
        prepared.completed = True
    evaluated = dict(components=result,input_receipts=receipts,execution_evidence=dict(
        actual_components=list(prepared.components),budget=prepared.budget,model_statistics=statistics,
        input_pool=prepared.pool.statistics(),physical_indexes_built=len(prepared.cache_indexes),
        byte_decode_context=prepared.context.summary(),
        actual_point_query_calls={key:value['queries'] for key,value in statistics.items()},
        no_cross_budget_reuse=True,complete_fault_answers_cached=False,
        per_draw_export_or_digest_work_performed=collect_points,primary_has_optional_point_work=False if not collect_points else None,
        scientific_rules='unchanged method_v1 EFM/first-reader/SIC solver/accepted-WB rules; L2 uses actual active-owner fault-hook coordinates',
        statistics_snapshot='after query/aggregation, before actual cleanup',performance_result=False))
    if collect_points: evaluated.update(ordered_digests=digests,points=points)
    prepared.result = evaluated
    return evaluated


def close_group(prepared,*,phase_factory=None):
    _need(type(prepared) is PreparedGroup and not prepared.closed,'one live group cleanup required')
    with _phase(phase_factory,'own_identity_and_cleanup'):
        try:
            prepared.context.verify_unchanged()
        finally:
            prepared.models.clear(); prepared.cache_indexes.clear(); prepared.inputs.clear(); prepared.pool.close()
            try: prepared.context.__exit__(None,None,None)
            finally:
                prepared.closed = True; gc.collect()
                if hasattr(prepared,'result'):
                    prepared.result['execution_evidence'].update(cleanup_completed=True,
                        input_pool_after_cleanup=prepared.pool.statistics(),byte_context_released=current_context() is None)


def _checked_reference(ref):
    path = Path(ref['path']); before = path.stat(); digest = hashlib.sha256()
    _need(path == path.resolve(strict=True) and path.is_file() and before.st_size == ref['bytes'],'native reference file role differs')
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024**2),b''): digest.update(block)
    after = path.stat()
    _need(all(getattr(before,key) == getattr(after,key) for key in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns'))
        and digest.hexdigest() == ref['sha256'],'native reference bytes changed')
    return path


def _writeback_witness(prepared,result):
    hits = [dict(component=component,prefix_position=row['prefix_position'],trial_id=row['trial_id'])
        for component,rows in result['points'].items() for row in rows
        if row['answer'].get('reason') == 'actual uniquely matched dirty writeback enqueue']
    if hits:
        return dict(status='COVERED_BY_EXISTING_FORMAL_PREFIX',actual_prefix_hits=hits,
                    extra_validation_fault_points=0,old_model_queries=0,new_model_queries=0)
    for component in prepared.components:
        if component not in ('l1d','l2'): continue
        model,inputs = prepared.models[component],prepared.inputs[component]
        for wb in model._index.report['writebacks']:
            copy,owner,when = wb['source_copy'],wb['scope'],wb['cycle']
            if when == 0: continue
            cycle = when-1
            spans = model._index.spans_by.get((component,owner,copy['line']),())
            live = [span for span in spans if method_cache._same(span['copy'],copy) and span['start_cycle']<=cycle<span['end_cycle']]
            if len(live)!=1: continue
            events = model._index.events(component,copy,cycle,when)
            # Conservative selection without extra model queries: WB must be
            # the first raw-sequence event on this copy after the fault cycle.
            if not events or events[0]['sequence'] != wb['writeback_sequence']: continue
            for rectangle in inputs['population'].document['spans']:
                target = rectangle['target']
                if target.get('line') != copy['line'] or target.get('sm' if component=='l1d' else 'bank') != owner: continue
                for address,count in wb['transferred_ranges']:
                    if not count: continue
                    states = live[0]['sector_state']
                    sector = states[(address-copy['block'])//(copy['line_bytes']//len(states))]
                    if sector['status'] not in (2,3): continue
                    bit = copy['line']*(57+8*copy['line_bytes'])+57+(address-copy['block'])*8
                    if component=='l2':
                        active,error = method_cache.l2_active_lines(inputs['residencies'].get('owner_views'),owner,cycle,copy)
                        if error is not None or type(target.get('lines_per_bank')) is not int or target['lines_per_bank'] != active:
                            continue
                        bit += owner*active*(57+8*copy['line_bytes'])
                    trial = dict(component=component,target=dict(target),cycle=cycle,bit=bit)
                    if not inputs['population'].contains(trial): continue
                    old = method_cache.NaiveCacheEFM(inputs['rows'],inputs['residencies'])
                    expected,actual = old.query(trial),model.query(trial)
                    _need(expected == actual and actual.get('reason') == 'actual uniquely matched dirty writeback enqueue',
                          'single actual WB validation point differs from the method rule')
                    return dict(status='ONE_NONFORMAL_NATIVE_POPULATION_POINT_VERIFIED',actual_prefix_hits=[],
                        extra_validation_fault_points=1,old_model_queries=1,new_model_queries=1,
                        trial=trial,answer=actual,source_writeback_association=wb,
                        population_fingerprint=inputs['population'].identity,actual_population_contains=True,
                        included_in_formal_N=False,FI_calls=0,capture_calls=0)
    return dict(status='NO_ELIGIBLE_WRITEBACK_POINT_IN_THIS_GROUP',actual_prefix_hits=[],
                extra_validation_fault_points=0,old_model_queries=0,new_model_queries=0)


def actual_L2_reference_check(group,budget,*,phase_factory=None,collect_points=False):
    """C only: current native L2 input, corrected plain-v2 versus indexed-v2.

    RF/SMEM/L1D are not decoded or queried. Previous L2 Unknown answers are not
    opened as an oracle. Every original ordered draw is queried in both models.
    """
    _need(type(budget) is int and budget in (1000,5000,10000) and type(collect_points) is bool,
        'one actual supported L2 prefix and explicit C detail policy required')
    entries = group['components']; names = tuple(entry['component'] for entry in entries)
    _need(names in (('rf','l1d','l2'),('rf','smem','l1d','l2')) and current_context() is None,
        'one independently owned actual three/four-component invocation required')
    entry = next(item for item in entries if item['component']=='l2')
    roots = {item['component']:item['methods']['gerem']['own_input']['root'] for item in entries}
    context = make_context(roots,method='gerem',extra_files=(entry['master']['path'],))
    context.__enter__();pool = InputPool();prepared = None;plain = None;inputs = None
    try:
        with _phase(phase_factory,'own_input_decode'):
            inputs = load_inputs(entry,component='l2',budget=budget,pool=pool)
        with _phase(phase_factory,'own_model_preparation'):
            index = PreparedCacheIndex(inputs['rows'],inputs['residencies'])
            model = IndexedCacheEFM(inputs['rows'],inputs['residencies'],index=index)
            plain = method_cache.NaiveCacheEFM(inputs['rows'],inputs['residencies'])
        prepared = PreparedGroup(group,budget,('l2',),pool,{'l2':inputs},{'l2':model},
            {inputs['cache_fact_key']:index},context)
        with _phase(phase_factory,'C_full_native_L2_domain_check'):
            from script.execution.cache_inventory_core import _inventory,topology_from_config
            from script.execution.compact_population import semantic_population
            config = Path(entry['methods']['gerem']['own_input']['capture'])/'gpgpusim.config'
            derived,raw_population = _inventory(inputs['residencies'],topology_from_config(context.read_text(config)),
                execution_metadata=False,component='l2')
            own = inputs['population']
            _need(all(raw_population.document[key] == own.document[key] for key in ('coordinate_system','time_basis')),
                'native L2 coordinate/time policy differs')
            # The original raw constructor's fixed v1 fault-model label is not
            # a different physical coordinate set. Retain both labels visibly;
            # compare every complete coordinate after carrying the own label.
            labelled = semantic_population(dict(derived,fault_model=own.inventory['fault_model']))
            encode = lambda value:json.dumps(value,allow_nan=False,sort_keys=True,separators=(',',':'))
            _need(encode(labelled.document) == encode(own.document),
                'full native active-owner L2 population differs from the original own domain')
            domain = dict(full_native_active_owner_domain_equal=True,
                complete_population_fingerprint=own.identity,selected_L2_bit_cycles=own.mass,
                canonical_L2_spans=len(own.document['spans']),
                raw_constructor_fault_model=raw_population.document['fault_model'],
                own_declared_fault_model=own.document['fault_model'],
                only_fault_model_label_carried_for_complete_coordinate_comparison=True,
                backing_capacity_not_substituted_for_fault_hook_geometry=True)
        result = evaluate_group(prepared,phase_factory=phase_factory,collect_points=True)
        with _phase(phase_factory,'C_corrected_plain_L2_ordered_reference'):
            for position,(trial,actual) in enumerate(zip(inputs['trials'],result['points']['l2'])):
                expected = _point(trial,position,plain.query(map_trial(inputs,trial)))
                _need(encode(expected) == encode(actual),'corrected plain/indexed L2 ordered identity or full scientific answer differs')
            _need(len(result['points']['l2']) == len(inputs['trials']) == budget,'complete original L2 prefix required')
            _need(plain.capability_report() == model.capability_report(),
                'corrected plain/indexed complete writeback association capability differs')
        with _phase(phase_factory,'actual_dirty_WB_coverage_validation'):
            writeback = _writeback_witness(prepared,result)
        result['reference_comparison'] = dict(schema='gerem-fair-v2-corrected-L2-reference-v1',status='COMPLETE',
            group_id=group['group_id'],application=group['application'],architecture=group['architecture'],budget=budget,
            component='l2',formal_prefix_queries_per_model=budget,
            plain_v2_queries=budget+writeback['old_model_queries'],
            indexed_v2_queries=budget+writeback['new_model_queries'],
            extra_validation_queries=writeback['old_model_queries']+writeback['new_model_queries'],
            all_ordered_draw_identities_and_full_native_answers_equal=True,
            EFM_probability_Unknown_DUE_and_support_status_equal=True,domain=domain,writeback_coverage=writeback,
            old_v1_L2_Unknown_used_as_oracle=False,unchanged_RF_SMEM_L1D_queries=0,
            SARA_calls=0,FI_calls=0,capture_calls=0,performance_result=False,
            legacy_query_outcome_not_used_for_hard_label_evaluation=True)
        if not collect_points: result.pop('points')
        return result
    finally:
        plain = None
        if prepared is not None:
            close_group(prepared,phase_factory=phase_factory)
        else:
            pool.close();context.__exit__(None,None,None);gc.collect()


