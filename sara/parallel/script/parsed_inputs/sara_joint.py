"""Serial SARA group: verify four own cores, analyze once, project four domains.

No launches, persistence, cross-method cache, FI input or point replay. The
caller must keep preparation, equality proof and all projection inside its
complete method window and activate one fresh SARA GroupOwnInputContext.
"""
from dataclasses import dataclass
from contextlib import nullcontext
from pathlib import Path

from script.core import batch_backward as batch
from script.core import reg_observed_analyzer as backward
from script.core.batch_smem import smem_regions
from script.core import batch_cache
from script.core.closed_fma_transfer import closed_input_effects
from script.core.closed_loop_transfer import construct as construct_loops
from script.core.exact_sdc_prepare_input import _mark_output_stores
from script.core.sparse_global_image import semantic_image, validate_golden_image
from script.execution import sara_batch_campaign as campaign
from script.execution.campaign import fingerprint
from script.execution.method_input_context import current_context
from script.input_pool.shared_input_pool import GroupOwnInputContext
from script.typed_records.typed_identity import equivalent, TypedIdentityUnsupported, POLICY
from script.parsed_inputs.numeric_parser_reuse import NumericParserPool


COMPONENTS = ('rf', 'smem', 'l1d', 'l2')
OBJECT_TYPES = (backward.TraceEvent, backward.PredInfo, backward.EAExpr,
                backward.MemoryRange, backward.OutputRangeSpec)


class JointInputMismatch(ValueError):
    """Actual own inputs do not prove one complete numerical core."""


def _need(value, message):
    if not value:
        raise JointInputMismatch(message)


def _equivalent(left,right):
    """A True result proves both complete values; False never admits a core."""
    try:
        return equivalent(left,right,object_types=OBJECT_TYPES)
    except TypedIdentityUnsupported as error:
        raise JointInputMismatch(str(error)) from error


def _live_context(inputs):
    from script.execution.policy import require_container_execution
    profile = require_container_execution()
    _need(profile.role in ('bounded_secondary', 'bounded_primary') and profile.cpus >= 1 and profile.memory_bytes >= 1024**3,
          'joint mathematical work is restricted to the B64CPU448GiB container')
    context = current_context()
    _need(type(context) is GroupOwnInputContext and context.method == 'sara'
          and context._token is not None and not context._closed,
          'one exact live externally activated SARA group context required')
    for component, path in inputs.items():
        _need(current_context(path) is context and context.owns(path)
              and context.root_for(path) == context.own_roots[component],
              'descriptor is not in its declared component own root')
    return context


def _checked_binding(context, path, binding, component):
    _need(type(binding) is dict and Path(binding['inputs']) == path
          and binding.get('collection_excluded') is True
          and binding.get('own_inputs_read_only') is True,
          'actual prepared own-binding receipt required: '+component)
    capture = Path(binding['capture'])
    _need(capture == capture.resolve(strict=True) and capture.is_dir()
          and context.root_for(capture/'capture.json') == context.own_roots[component],
          'capture metadata belongs to another component own root')
    _need(context.digest(path) == binding['inputs_sha256']
          and context.digest(capture/'capture.json') == binding['capture_metadata_sha256'],
          'prepared descriptor/capture metadata bytes changed: '+component)
    return context.read_json(capture/'capture.json')


def _union_options():
    # Every original current08/v7 analyze_rf fixes fault_component='rf' even
    # for memory components. Retain that scientific policy. Do not switch to
    # smem_rf/l1d/l2 to request output arrays; those change upstream propagation.
    _need(not backward.env_flag('REG_OBSERVED_COMPONENT_OUTPUT_TRIM', False),
          'trimmed component output cannot supply a complete joint core')
    _need(not backward.env_flag('REG_OBSERVED_FORCE_RF_ADDR_MASKING', False),
          'joint core refuses a changed RF address scientific policy')
    _need(not backward.env_flag('REG_OBSERVED_OMIT_TOP_LEVEL_DIAGNOSTICS', False),
          'joint core requires the original exported uncertainty diagnostics')
    return dict(lite_output=True, lite_output_profile='compat', mask_format='int',
        assume_sorted_events=True, fault_component='rf', emit_cache_sites=True,
        output_component=None, aggregate_only=False,
        control_outcome_policy='submitted_local_sdc')


def _parsed_core(pool,trace,outputs,options,source_path,component):
    parsed,copy_policy,reuse = pool.prepare(trace,outputs,options,
        source_path=source_path,component=component)
    return dict(parsed,copy_policy=copy_policy,numeric_parser_reuse=reuse)


def _cache_preparation(context, paths, metadata):
    ledger, trace, sidecar = (paths[name] for name in ('cache_ledger', 'trace', 'trace_sidecar'))
    dependencies = {'trace': trace, 'sidecar': sidecar}
    transport_sidecar = Path(str(trace)+'.completeness.json')
    transport_sidecar_present = transport_sidecar.exists()
    if transport_sidecar_present:
        context.check_size(transport_sidecar, 16*1024**2)
        dependencies['implicit_trace_transport_sidecar'] = transport_sidecar
    # Keep the original own numeric closure and physical builder/cache. The
    # extra Group publication had no consumer on these distinct dependency
    # bytes and recursively rebuilt an already frozen rows/report tuple.
    value = batch_cache.raw_physical(ledger,trace,sidecar)
    _need(transport_sidecar.exists() == transport_sidecar_present,
          'implicit trace transport sidecar presence changed during preparation')
    if transport_sidecar_present:
        context.key(transport_sidecar)
    return value, dict(dependency_roles=['cache_ledger']+sorted(dependencies),
        implicit_trace_transport_sidecar_present=transport_sidecar_present,
        complete_dependency_bytes_required=True,raw_physical_loader_executed=True,
        group_derived_publication_performed=False,
        original_own_context_physical_cache_retained=True)


def _sections(state, options):
    return dict(parsed_events=state['events'], memory_ranges=state['memory_ranges'],
        effective_output_marking_ranges=state['marked_ranges'], parsed_output_ranges=state['output_ranges'],
        initial_global_image=dict(present=state['image_present'], value=state['semantic_image']),
        numerical_options=options)


@dataclass
class _PrivatePrepared:
    inputs: dict
    bindings: dict
    states: dict
    context: object
    options: dict
    core_input_proof: dict
    consumed: bool = False


def _prepare_joint(inputs, *, bindings):
    """Validate four original own bundles and prove complete core equality.

    bindings are actual fair_overhead_run.bind_prepared receipts produced by
    the upper worker inside this same group context. Their external byte pins
    are checked again here; no old admission or old classified result is used.
    """
    _need(type(inputs) is dict and set(inputs) == set(COMPONENTS)
          and type(bindings) is dict and set(bindings) == set(COMPONENTS),
          'exact four prepared descriptor paths and own bindings required')
    paths = {component: Path(inputs[component]).absolute() for component in COMPONENTS}
    _need(all(path == path.resolve(strict=True) and path.is_file() for path in paths.values()),
          'canonical existing own descriptor files required')
    context, options = _live_context(paths), _union_options()
    states, proof, reference_sections, reference_workload = {}, {}, None, None
    parser_pool,compatible_parse_groups = NumericParserPool(),set()
    for component in COMPONENTS:
        path = paths[component]
        metadata = _checked_binding(context, path, bindings[component], component)
        prepared = campaign.prepare_rates(path)
        descriptor, files, inventory, population, trace, outputs = prepared
        _need(inventory['spans'][0]['component'] == component and population.mass > 0,
              'correct positive complete component population required')
        _need(metadata.get('collection') == 'sara', 'joint SARA cannot consume another method capture')
        for own_key, descriptor_key in (('case', 'case'), ('actual_binary_sha256', 'binary_sha256'),
                ('arguments', 'arguments'), ('simulator_libraries', 'simulator_libraries')):
            _need(own_key in metadata and descriptor_key in descriptor
                  and _equivalent(metadata[own_key],descriptor[descriptor_key]),
                  'actual own computation/descriptor binding differs: '+component+'/'+own_key)
        original = context.read_json(Path(bindings[component]['capture'])/('inputs-'+component+'.json'))
        for role, ref in original['files'].items():
            _need(descriptor['files'].get(role, {}).get('sha256') == ref['sha256'],
                  'SARA companion borrowed a different own capture role: '+component+'/'+role)
        current_workload = {key:descriptor[key] for key in
            ('case', 'binary_sha256', 'arguments', 'simulator_libraries')}
        if reference_workload is None:
            reference_workload = current_workload
        else:
            _need(_equivalent(reference_workload,current_workload),
                  'four SARA bundles describe different computations')
        state = dict(prepared=prepared, descriptor=descriptor, paths=files, inventory=inventory,
            population=population, trace=trace, outputs=outputs, metadata=metadata)
        # Original cache ordering validates closed physical transport and its
        # strict own raw witnesses before its numerical event analysis.
        if component in ('l1d', 'l2'):
            physical, receipt = _cache_preparation(context, files, metadata)
            rows, residencies = physical
            state.update(rows=rows, residencies=residencies,
                joined=batch_cache.join_functional_records(rows, trace['events'], strict_numeric=True),
                physical_preparation=receipt)
        state.update(_parsed_core(parser_pool,trace,outputs,options,files['trace'],component))
        sections = _sections(state, options)
        parse_group = state['numeric_parser_reuse']['parse_group']
        if reference_sections is None:
            reference_sections = sections
            compatible_parse_groups.add(parse_group)
        else:
            for name,value in sections.items():
                # A proven equal complete parser input reuses the SAME source-
                # bound deterministic parse. A distinct group retains the full
                # parsed-field/MRO comparison. Each own validated image remains
                # an independent compatibility check, even on parser hits.
                if name == 'initial_global_image' or parse_group not in compatible_parse_groups:
                    _need(_equivalent(reference_sections[name],value),
                          'own '+component+' differs from RF complete core section: '+name)
            compatible_parse_groups.add(parse_group)
        proof[component] = dict(complete_sections=list(sections),complete_section_count=len(sections),
            events=len(state['events']),
            whole_workload_fields_equal=True,
            descriptor_sha256=context.digest(path), population_fingerprint=population.identity,
            population_mass=population.mass, own_image_validation=state['image_support'],
            own_file_roles={role:dict(path=str(source), sha256=context.digest(source))
                           for role,source in sorted(files.items())},
            event_copy_policy=state['copy_policy'],numeric_parser_reuse=state['numeric_parser_reuse'],
            parsed_core_compatibility_proof='complete_numeric_parser_input_equivalence_or_full_typed_parse_to_RF')
        states[component] = state
    # Every successful RF/other comparison validates BOTH complete structures.
    # RF is therefore fully checked via all three peers; no self scan or
    # unconsumed serialized fingerprint is needed or collected.
    for component in COMPONENTS:
        proof[component].update(complete_typed_core_compatibility_verified=True,
            full_numeric_parser_input_or_parsed_field_types_checked=True,
            comparison_peers=list(COMPONENTS[1:]) if component == 'rf' else ['rf'],
            complete_section_results={name:True for name in reference_sections},
            typed_comparison_policy=POLICY,serialized_core_fingerprints_collected=False,
            own_full_image_mutation_snapshot_collected=False)
    context.verify_unchanged()
    prepared = _PrivatePrepared(paths, dict(bindings), states, context, options, proof)
    prepared.numeric_parser_invocations = parser_pool.invocations
    prepared.numeric_parser_reuse_hits = parser_pool.reuse_hits
    prepared.own_full_golden_validations = parser_pool.golden_validations
    return prepared


def prepare_joint(inputs, *, bindings):
    """Public mutable prepared API: retain complete mutation snapshots/checks."""
    from script.reverse_group_base.sara_joint import prepare_joint as audited_prepare
    return audited_prepare(inputs,bindings=bindings)


def _component_analysis(core, state, component, closed_support, loop_effects, loop_support):
    result = dict(core)
    result['exact_meta'] = dict(core['exact_meta'])
    result['copy_policy'] = state['copy_policy']
    result['exact_meta']['serial_pruned_copy_policy'] = dict(state['copy_policy'])
    result['initial_global_image_support'] = state['image_support']
    result['closed_local_support'] = {key:value for key,value in closed_support.items() if key != 'proof_pairs'}
    result['loop_effects'] = loop_effects if component == 'rf' else []
    result['deductive_loop_support'] = loop_support if component == 'rf' else {
        'status':'not_requested_for_non_RF_projection', 'component':component,
        'proof_consumer':'RF_action_intervals_only', 'executed':False,
        'classification_changed':False, 'implementation_variant':'serial-pruned-v5'}
    result['composition_support'] = dict(input_copy_policy=dict(state['copy_policy']),
        policy='submitted_local_composition_without_blanket_multibit_refusal',
        blanket_refusal_enabled=False, classification_is='model_prediction_not_general_correlated_execution_proof',
        per_origin_replay=False, FI_answers_used=False)
    return result


def _cache_regions(state, analysis):
    """Original batch_cache.analyze_cache projection orchestration, no new math.

    The old public function has no prepared-core parameter. Its raw/strict join
    above and lines145–164 below are retained using the original functions.
    PhysicalBackward is new per component; mutable live/changes are never shared.
    """
    rows, residencies, joined = state['rows'], state['residencies'], state['joined']
    component = state['inventory']['spans'][0]['component']
    filtered = dict(residencies, residency_spans=[row for row in residencies['residency_spans']
                                                if row['component'] == component])
    byte_masks, influences = {}, {}
    for raw in analysis['l1d_fault_sites']:
        item = batch_cache.compact_cache_site_row_to_dict(raw)
        if state['trace']['events'][item['event_index']].get('kind') != 'load':
            continue
        byte_masks[item['event_index'], item['addr']] = tuple(int(item[field]) for field in
            ('observed_mask_this_site', 'due_mask_this_site', 'trace_expanding_mask_this_site'))
    for row in rows:
        if row.get('kind') != 'functional_cache_load_source':
            continue
        index = joined[row['sequence']]['event_ordinal']-1
        for offset, cell in enumerate(row['bytes']):
            influences[row['sequence'], offset] = byte_masks.get((index, cell['address']), (0, 0, 0))
    projection = batch_cache.PhysicalBackward(rows, residencies, influences).propagate()
    projection.residencies = filtered
    projection.tag_support = batch_cache.classify_invalid_tag_suffixes(filtered, rows)
    analysis['cache_projection'] = dict(raw_records=len(rows), physical_histories=len(projection.changes),
        mask_change_events=sum(map(len, projection.changes.values())), per_origin_replay=False,
        snapshot_profile=projection.snapshots.report(),
        tag_support={key:value for key,value in projection.tag_support.items() if key != 'unknown_masks'},
        support_excludes=['unproved_live_tag_effects', 'unproved_batch_semantics'], inflight_windows=0)
    return projection.regions(state['inventory'])


def _summary(state, analysis, sink):
    descriptor, population = state['descriptor'], state['population']
    result = sink.summary(population.mass)
    identity = fingerprint(descriptor)
    component = state['inventory']['spans'][0]['component']
    result.update(mode='rates', component=component, input_fingerprint=identity,
        base_analysis_input_fingerprint=identity, normalized_analysis_input_fingerprint=identity,
        composition_support=analysis.get('composition_support'), closed_local_support=analysis.get('closed_local_support'),
        initial_global_image_support=analysis.get('initial_global_image_support'),
        deductive_loop_support=analysis.get('deductive_loop_support'),
        uncertainty_diagnostics={key:analysis[key] for key in ('addr_alias_unknown_bits', 'addr_alias_unknown_events',
            'addr_same_value_masked_bits', 'control_taint_stats') if key in analysis},
        component_support=analysis.get('smem_projection' if component == 'smem' else 'cache_projection'),
        analysis_code=None, population_fingerprint=population.identity,
        population_identity_kind=descriptor.get('population_identity_kind', 'legacy_rich_inventory_fingerprint'),
        dynamic_events=len(state['events']), shared_manifest_population_fingerprint=None,
        classification_uses_FI_answers=False, sampled_draws=None, validation_only=False,
        timings={'managed_by_enclosing_joint_performance_window':True}, process_resources=None,
        validation_region_buffer='not retained by aggregate joint wrapper',
        cost_boundary='four own-input preparation, equality proof, one numerical core and four complete physical projections in enclosing group window')
    return result


def _evaluate_joint(prepared, *, internal_regions=None):
    """One real detailed numerical call, RF loop proof, four original projections.

    Only the fused caller can supply its own private qualification buffers.
    No external observer runs and no large-domain bit/cycle enumeration or
    mutation fingerprint collection is performed here.
    """
    _need(type(prepared) is _PrivatePrepared and not prepared.consumed, 'one fresh private joint evaluation required')
    _need(_live_context(prepared.inputs) is prepared.context, 'prepared group context ended or changed')
    _need(_union_options() == prepared.options, 'numerical environment changed after preparation')
    prepared.context.verify_unchanged()
    prepared.consumed = True
    base = prepared.states['rf']
    loop_effects, loop_support = construct_loops(base['events'], base['image'])
    effects, closed_support = closed_input_effects(base['events'], base['output_ranges'], include_proof_pairs=False)
    core = backward.analyze(base['events'], memory_ranges=base['memory_ranges'],
        output_ranges=base['output_ranges'], initial_global_image=base['image'],
        proved_input_effects=effects, **prepared.options)
    _need(all(name in core for name in ('read_events', 'smem_fault_sites', 'l1d_fault_sites', 'exact_meta')),
          'detailed union numerical core did not emit all required component sinks')
    components = {}
    for component in COMPONENTS:
        state = prepared.states[component]
        analysis = _component_analysis(core, state, component, closed_support, loop_effects, loop_support)
        if component == 'rf':
            regions = batch.rf_regions(state['inventory'], base['events'], analysis['read_events'],
                analysis['loop_effects'], analysis['deductive_loop_support'])
        elif component == 'smem':
            regions = smem_regions(state['inventory'], base['events'], analysis, state['trace']['events'])
            analysis['smem_projection'] = dict(persistent_object_epoch_checked=True, per_origin_replay=False)
        else:
            regions = _cache_regions(state, analysis)
        sink = batch.RatesSink(retain_classification_digest=False)
        for region in regions:
            sink.consume(region)
            if internal_regions is not None:
                internal_regions[component].append(region)
        components[component] = _summary(state, analysis, sink)
    prepared.context.verify_unchanged()
    return dict(components=components, core_input_proof=prepared.core_input_proof,
        joint_support=dict(numerical_core_invocations=1, numeric_core_invocations=1,
            RF_loop_proof_constructions=1, closed_local_proof_constructions=1,
            common_core_options=prepared.options, complete_parsed_core_identity_verified=True,
            all_four_own_inputs_validated=True, input_identity_verified_before_and_after=True,
            original_projector_math=True, mutable_projection_state_shared=False,
            execution_path='private_fused_non_escaping_no_user_observers',
            prepared_core_mutation_rechecked=False,
            own_full_image_mutation_snapshots_collected=False,
            postprojection_core_digest_guard_collected=False,
            serialized_core_fingerprints_collected=False,
            numeric_parser_invocations=prepared.numeric_parser_invocations,
            numeric_parser_reuse_hits=prepared.numeric_parser_reuse_hits,
            own_full_golden_validations=prepared.own_full_golden_validations,
            own_raw_trace_retained_for_strict_join=True,
            complete_typed_equivalence_policy=POLICY,
            per_component_physical_preparation={name:prepared.states[name]['physical_preparation']
                for name in ('l1d', 'l2')}, no_old_results_or_FI_used=True,
            aggregate_only_analyzer_optimizations_retained=False,
            detailed_union_extra_diagnostics='charged inside group clock; old aggregate-only API cannot emit a union',
            headline_measurement_created_by_wrapper=False))


def evaluate_joint(prepared, *, region_buffer_by_component=None, region_callback=None):
    """Public audit path retains all prepare/re-evaluate/projector mutation checks."""
    from script.reverse_group_base.sara_joint import evaluate_joint as audited_evaluate
    return audited_evaluate(prepared,region_buffer_by_component=region_buffer_by_component,
        region_callback=region_callback)


def _phase_factory(factory):
    """Only the original measured window method or no diagnostic clock.

    No caller-supplied observer/context-manager callback can run between the
    private compatibility proof and its use. Neither phase receives state.
    """
    if factory is None:
        return lambda _name:nullcontext()
    from types import MethodType
    from script.execution.method_performance import PerformanceWindow
    _need(type(factory) is MethodType and type(factory.__self__) is PerformanceWindow
          and factory.__func__ is PerformanceWindow.phase,
          'only the original PerformanceWindow.phase bound method is admitted')
    window = factory.__self__
    return lambda name:PerformanceWindow.phase(window,name)


def evaluate_own_inputs(inputs, *, bindings, phase_factory=None, collect_regions=False):
    """Private serial prepare-and-use path; no mutable prepared object escapes.

    All four first complete typed compatibility proofs, golden validation,
    own physical admission and final input custody remain. Only snapshots and
    repeated whole-object traversals for foreign mutation are uncollected.
    Qualification may request internal Region retention. The four buffers are
    returned only after every projection and final own-input check completes;
    callers cannot supply a callback or an externally retained buffer.
    """
    _need(type(collect_regions) is bool,'explicit internal Region retention boolean required')
    phase = _phase_factory(phase_factory)
    with phase('own_model_preparation_and_common_core_identity'):
        prepared = _prepare_joint(inputs,bindings=bindings)
    regions = {component:[] for component in COMPONENTS} if collect_regions else None
    with phase('one_numeric_core_and_four_complete_projections'):
        evaluated = _evaluate_joint(prepared,internal_regions=regions)
    if collect_regions:
        evaluated['qualification_regions'] = regions
    return evaluated
