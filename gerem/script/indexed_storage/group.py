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
from script.compatible_cache import cache as method_cache
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
    _need(type(budget) is int and budget in (1000,5000,10000,200000),'one independent supported N required')
    entries = group['components']; components = tuple(entry['component'] for entry in entries)
    _need(components in (('rf','l1d','l2'),('rf','smem','l1d','l2')),'only actual three/four component groups supported')
    _need(current_context() is None,'one independently owned method invocation required')
    roots = {entry['component']:entry['methods']['gerem']['own_input']['root'] for entry in entries}
    extra_files = tuple(entry['master']['path'] for entry in entries)
    if budget == 200000:
        from .inputs_200k import load_inputs_200k
        loader = load_inputs_200k
        extra_files = tuple(dict.fromkeys(extra_files + tuple(entry[key]['path'] for entry in entries
            for key in ('master_200k','master_extension_manifest'))))
    else:
        loader = load_inputs  # Exact original <=10K loader function object.
    context = make_context(roots,method='gerem',extra_files=extra_files)
    context.__enter__()
    pool = InputPool(); inputs = {}; models = {}; indexes = {}
    try:
        for entry in entries:
            component = entry['component']
            with _phase(phase_factory,'own_input_decode_'+component):
                inputs[component] = loader(entry,component=component,budget=budget,pool=pool)
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
    for component in prepared.components:
        with _phase(phase_factory,'point_queries_'+component):
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
            result[component] = dict(schema='gerem-fair-fi-compatible-storage-probability-aggregate-v3',status='COMPLETE',method='GEREM',model=MODEL,
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
        scientific_rules='unchanged v2 EFM/first-reader/SIC/Tag/L2-active rules except actual WB enqueue alone is not an independent DATA consumer',
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


