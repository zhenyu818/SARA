"""Serial SARA group: verify four own cores, analyze once, project four domains.

No launches, persistence, cross-method cache, FI input or point replay. The
caller must keep preparation, equality proof and all projection inside its
complete method window and activate one fresh SARA GroupOwnInputContext.
"""
from dataclasses import dataclass
import hashlib
import json
import math
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
from script.execution.method_input_context import FrozenDict, FrozenList, current_context
from script.input_pool.shared_input_pool import GroupOwnInputContext
from script.reverse_group_base.group_event_adaptation import analysis_event_input


COMPONENTS = ('rf', 'smem', 'l1d', 'l2')
OBJECT_TYPES = (backward.TraceEvent, backward.PredInfo, backward.EAExpr,
                backward.MemoryRange, backward.OutputRangeSpec)
MAX_DEPTH = 256


class JointInputMismatch(ValueError):
    """Actual own inputs do not prove one complete numerical core."""


def _need(value, message):
    if not value:
        raise JointInputMismatch(message)


def _slots(cls):
    names = []
    for base in reversed(cls.__mro__):
        row = base.__dict__.get('__slots__', ())
        row = (row,) if type(row) is str else row
        for name in row:
            _need(type(name) is str and name not in ('__dict__', '__weakref__')
                  and name not in names, 'opaque or ambiguous parsed-object slot')
            names.append(name)
    _need(bool(names), 'parsed object has no complete declared slots')
    return tuple(names)


def _tokens(value, active=None, depth=0):
    """Complete typed token stream, including every parsed object's MRO slot.

    Finite exact JSON values, tuple/list distinction, None/presence, integer vs
    Boolean and all known parsed types remain distinct. There is no projection
    field allowlist and no old per-input equality result to consult.
    """
    _need(depth <= MAX_DEPTH, 'core comparison depth bound exceeded')
    kind = type(value)
    if value is None:
        yield b'n;'; return
    if kind is bool:
        yield b'b1;' if value else b'b0;'; return
    if kind is int:
        yield b'i'+str(value).encode('ascii')+b';'; return
    if kind is float:
        _need(math.isfinite(value), 'nonfinite core value')
        yield b'f'+value.hex().encode('ascii')+b';'; return
    if kind is str:
        raw = json.dumps(value, ensure_ascii=True).encode('ascii')
        yield b's'+str(len(raw)).encode('ascii')+b':'+raw; return
    if kind in (FrozenDict, FrozenList):
        attrs = object.__getattribute__(value, '__dict__')
        _need(type(attrs) is dict and dict.__len__(attrs) == 0,
              'attributed Frozen core container cannot grant equivalence')
    if kind in (dict, FrozenDict):
        _need(all(type(key) is str for key in dict.keys(value)), 'non-string core mapping key')
        tag = b'dict'
        items = ((key, dict.__getitem__(value, key)) for key in sorted(dict.keys(value)))
    elif kind in (list, FrozenList):
        tag = b'list'
        items = enumerate(list.__iter__(value))
    elif kind is tuple:
        tag = b'tuple'
        items = enumerate(tuple.__iter__(value))
    elif kind in OBJECT_TYPES:
        tag = ('object:'+kind.__module__+'.'+kind.__qualname__).encode('ascii')
        items = ((name, getattr(value, name)) for name in _slots(kind))
    else:
        raise JointInputMismatch('opaque/custom core value: '+kind.__name__)
    active = set() if active is None else active
    identity = id(value)
    _need(identity not in active, 'cyclic core container')
    active.add(identity)
    try:
        yield tag+b'{'
        for key, item in items:
            yield from _tokens(key, active, depth+1)
            yield from _tokens(item, active, depth+1)
        yield b'};'
    finally:
        active.remove(identity)


def typed_digest(value):
    digest = hashlib.sha256()
    for token in _tokens(value):
        digest.update(token)
    return digest.hexdigest()


def _live_context(inputs):
    from script.execution.policy import require_container_execution
    profile = require_container_execution()
    _need(profile.role in ('bounded_secondary', 'bounded_primary') and profile.cpus >= 1 and profile.memory_bytes >= 1024**3,
          'joint mathematical work is restricted to the B64CPU448GiB container')
    context = current_context()
    _need(isinstance(context, GroupOwnInputContext) and context.method == 'sara'
          and context._token is not None and not context._closed,
          'one live externally activated SARA group context required')
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


def _parsed_core(trace, outputs, source_path):
    # Exact existing adaptation/normalization/marking/parsing/validation order.
    # The v2 adapter repeats the qualified full tree proof for this exact live Group.
    raw, copy_policy = analysis_event_input(trace['events'], source_path=source_path)
    raw = batch.normalize_predicate_register_values(raw)
    specs = outputs.get('output_spec', outputs.get('outputs', outputs)) if isinstance(outputs, dict) else outputs
    if not isinstance(specs, list) or not specs:
        raise ValueError('complete actual output range list required')
    marked = [dict(row, base=backward.parse_int(row['base']),
        size=int(row.get('bytes', row.get('size', 0)))) for row in specs]
    _mark_output_stores(raw, marked)
    events = [backward.parse_event(row, index) for index, row in enumerate(raw)]
    image = trace.get('initial_global_image')
    support = validate_golden_image(events, image) if image is not None else None
    return dict(events=events, specs=specs, marked_ranges=marked,
        memory_ranges=backward.parse_memory_ranges(trace.get('memory_ranges', [])),
        output_ranges=backward.parse_output_ranges(specs), image=image,
        image_present='initial_global_image' in trace,
        image_support=support, semantic_image=semantic_image(image) if image is not None else None,
        copy_policy=copy_policy)


def _cache_preparation(context, paths, metadata):
    ledger, trace, sidecar = (paths[name] for name in ('cache_ledger', 'trace', 'trace_sidecar'))
    dependencies = {'trace': trace, 'sidecar': sidecar}
    transport_sidecar = Path(str(trace)+'.completeness.json')
    transport_sidecar_present = transport_sidecar.exists()
    if transport_sidecar_present:
        context.check_size(transport_sidecar, 16*1024**2)
        dependencies['implicit_trace_transport_sidecar'] = transport_sidecar
    built = []
    def loader():
        built.append(True)
        return batch_cache.raw_physical(ledger, trace, sidecar)
    # The transport reader also has an implicit completeness sidecar. Include
    # it independently even if normally the same file as the descriptor role;
    # absence/presence is checked on every call and is part of the key.
    # Closure budget/cache-state parameters are fixed by the original function.
    # Add the own computation/config/collection source metadata conservatively.
    parameters = dict(loader='script.execution.cache_physical_facts.raw_physical',
        closed_numeric_trace=True, expected_budget_bytes=2147483648, expected_cache_state=True,
        implicit_trace_transport_sidecar_present=transport_sidecar_present,
        case=metadata.get('case'), actual_binary_sha256=metadata.get('actual_binary_sha256'),
        effective_config_sha256=metadata.get('effective_config_sha256'),
        native_source_fingerprint=metadata.get('native_source_fingerprint'),
        collection=metadata.get('collection'), simulator_libraries=metadata.get('simulator_libraries'))
    share = getattr(context, 'share_derived', None)
    if share is None:
        value = loader()
    else:
        value = share(ledger, 'sara_joint_closed_numeric_physical_v1', loader,
            dependencies=dependencies, parameters=parameters)
    _need(transport_sidecar.exists() == transport_sidecar_present,
          'implicit trace transport sidecar presence changed during preparation')
    if transport_sidecar_present:
        context.key(transport_sidecar)
    return value, dict(dependency_roles=['cache_ledger']+sorted(dependencies),
        implicit_trace_transport_sidecar_present=transport_sidecar_present,
        complete_dependency_bytes_required=True, raw_physical_loader_executed=bool(built),
        group_derived_sharing_available=share is not None)


def _sections(state, options):
    return dict(parsed_events=state['events'], memory_ranges=state['memory_ranges'],
        effective_output_marking_ranges=state['marked_ranges'], parsed_output_ranges=state['output_ranges'],
        initial_global_image=dict(present=state['image_present'], value=state['semantic_image']),
        numerical_options=options)


@dataclass
class JointPrepared:
    inputs: dict
    bindings: dict
    states: dict
    context: object
    options: dict
    core_input_proof: dict
    consumed: bool = False


def prepare_joint(inputs, *, bindings):
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
    states, proof, workload_key = {}, {}, None
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
                  and typed_digest(metadata[own_key]) == typed_digest(descriptor[descriptor_key]),
                  'actual own computation/descriptor binding differs: '+component+'/'+own_key)
        original = context.read_json(Path(bindings[component]['capture'])/('inputs-'+component+'.json'))
        for role, ref in original['files'].items():
            _need(descriptor['files'].get(role, {}).get('sha256') == ref['sha256'],
                  'SARA companion borrowed a different own capture role: '+component+'/'+role)
        current_workload = typed_digest({key:descriptor[key] for key in
            ('case', 'binary_sha256', 'arguments', 'simulator_libraries')})
        if workload_key is None:
            workload_key = current_workload
        _need(current_workload == workload_key, 'four SARA bundles describe different computations')
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
        state.update(_parsed_core(trace, outputs, files['trace']))
        state['own_image_value_fingerprint'] = typed_digest(state['image'])
        sections = _sections(state, options)
        signatures = {name:typed_digest(value) for name,value in sections.items()}
        if proof:
            for name, digest in signatures.items():
                _need(digest == proof['rf']['sections'][name],
                      'own '+component+' differs from RF complete core section: '+name)
        proof[component] = dict(sections=signatures, events=len(state['events']), workload_fingerprint=workload_key,
            own_full_image_value_fingerprint=state['own_image_value_fingerprint'],
            descriptor_sha256=context.digest(path), population_fingerprint=population.identity,
            population_mass=population.mass, own_image_validation=state['image_support'],
            own_file_roles={role:dict(path=str(source), sha256=context.digest(source))
                           for role,source in sorted(files.items())},
            event_copy_policy=state['copy_policy'])
        states[component] = state
    context.verify_unchanged()
    return JointPrepared(paths, dict(bindings), states, context, options, proof)


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


def evaluate_joint(prepared, *, region_buffer_by_component=None, region_callback=None):
    """One real detailed numerical call, RF loop proof, four original projections.

    The optional callback receives (component, original Region) for full interval
    qualification; no large-domain bit/cycle enumeration is performed here.
    Main aggregation passes neither observer and retains no validation digest.
    """
    _need(type(prepared) is JointPrepared and not prepared.consumed, 'one fresh prepared joint evaluation required')
    _need(_live_context(prepared.inputs) is prepared.context, 'prepared group context ended or changed')
    _need(_union_options() == prepared.options, 'numerical environment changed after preparation')
    if region_buffer_by_component is not None:
        _need(type(region_buffer_by_component) is dict and set(region_buffer_by_component) == set(COMPONENTS)
              and all(callable(getattr(value, 'append', None)) for value in region_buffer_by_component.values()),
              'four explicit qualification region append observers required')
    _need(region_callback is None or callable(region_callback), 'callable component/Region observer required')
    for component in COMPONENTS:
        _need({name:typed_digest(value) for name,value in _sections(prepared.states[component], prepared.options).items()}
              == prepared.core_input_proof[component]['sections'],
              'prepared parsed core changed after equality proof: '+component)
        _need(typed_digest(prepared.states[component]['image'])
              == prepared.core_input_proof[component]['own_full_image_value_fingerprint'],
              'own source image changed after independent golden validation: '+component)
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
    before = typed_digest(dict(events=base['events'], analysis=core))
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
            if region_buffer_by_component is not None:
                region_buffer_by_component[component].append(region)
            if region_callback is not None:
                region_callback(component, region)
        components[component] = _summary(state, analysis, sink)
    _need(typed_digest(dict(events=base['events'], analysis=core)) == before,
          'a component projector mutated retained common numerical events/results')
    prepared.context.verify_unchanged()
    return dict(components=components, core_input_proof=prepared.core_input_proof,
        joint_support=dict(numerical_core_invocations=1, numeric_core_invocations=1,
            RF_loop_proof_constructions=1, closed_local_proof_constructions=1,
            common_core_options=prepared.options, complete_parsed_core_identity_verified=True,
            all_four_own_inputs_validated=True, input_identity_verified_before_and_after=True,
            original_projector_math=True, mutable_projection_state_shared=False,
            per_component_physical_preparation={name:prepared.states[name]['physical_preparation']
                for name in ('l1d', 'l2')}, no_old_results_or_FI_used=True,
            aggregate_only_analyzer_optimizations_retained=False,
            detailed_union_extra_diagnostics='charged inside group clock; old aggregate-only API cannot emit a union',
            headline_measurement_created_by_wrapper=False))
