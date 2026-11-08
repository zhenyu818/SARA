"""Serial SARA over the actual three/four domains and proved core groups.

The fixed driver owns the live context, bindings and complete timer. Four-root
inputs may use the frozen V8 producer scope. Three-root inputs receive no such
privilege and use the unchanged V4 parser/copy guards. Failure to prove sharing
creates another core; own input/physical/golden failures remain failures.
"""
from pathlib import Path

from script.execution.method_input_context import current_context
from script.input_pool.shared_input_pool import GroupOwnInputContext
from script.typed_records.typed_identity import equivalent, TypedIdentityUnsupported, POLICY
from script.parsed_inputs.numeric_parser_reuse import NumericParserPool as OriginalParserPool
from script.readonly_records.private_json_identity import current_witness
from script.verified_inputs.numeric_parser_reuse import NumericParserPool as ProducerParserPool
from script.verified_inputs import sara_joint as original
from script.method_group.group_context import (
    ThreeGroupOwnInputContext, THREE_COMPONENTS, FOUR_COMPONENTS, components_for,
)


WORKLOAD_FIELDS = ('case', 'binary_sha256', 'arguments', 'simulator_libraries')
CONSUMED_OUTPUT_POLICY = 'serial-joint-aggregate-consumers-v1'


def _context(inputs):
    from script.execution.policy import require_container_execution
    profile = require_container_execution()
    original._need(profile.role in ('bounded_secondary', 'bounded_primary') and profile.cpus >= 1 and profile.memory_bytes >= 1024**3, 'SARA requires its declared bounded CPU-only profile')
    components = components_for(inputs)
    context = current_context()
    expected = GroupOwnInputContext if components == FOUR_COMPONENTS else ThreeGroupOwnInputContext
    original._need(type(context) is expected and context.method == 'sara'
        and context._token is not None and not context._closed,
        'one exact live actual-component SARA context required')
    original._need(set(context.own_roots) == set(components), 'input/context component sets differ')
    for component, path in inputs.items():
        original._need(current_context(path) is context and context.owns(path)
            and context.root_for(path) == context.own_roots[component],
            'descriptor belongs to another own component root')
    return components, context


def _optional_equal(left, right):
    try:
        return equivalent(left, right, object_types=original.OBJECT_TYPES)
    except TypedIdentityUnsupported:
        return False


def _compatible(reference, candidate, options):
    # Own actual workloads must match before any core is shared. An unsupported
    # cross-input proof denies only sharing, never original independent math.
    if not _optional_equal(reference['workload'], candidate['workload']):
        return False, 'workload_not_proved_equal'
    first, second = original._sections(reference, options), original._sections(candidate, options)
    same_parse = (reference['numeric_parser_reuse']['parse_group'] ==
                  candidate['numeric_parser_reuse']['parse_group'])
    for name, value in second.items():
        if name == 'initial_global_image' or not same_parse:
            if not _optional_equal(first[name], value):
                return False, 'complete_section_not_proved_equal:' + name
    return True, ('same_successful_parser_group_and_own_image' if same_parse
                  else 'complete_typed_parsed_sections_and_own_image')


def _partition_states(states, components, options):
    groups, membership = [], {}
    for component in components:
        state = states[component]
        for group in groups:
            compatible, route = _compatible(states[group['reference_component']], state, options)
            if compatible:
                group['components'].append(component)
                membership[component] = dict(core_group=group['core_group'],
                    reference_component=group['reference_component'], compatibility_route=route)
                break
        else:
            index = len(groups)
            groups.append(dict(core_group=index, reference_component=component, components=[component]))
            membership[component] = dict(core_group=index, reference_component=component,
                compatibility_route='own_independent_reference_no_cross_input_claim')
    return groups, membership


def _prepare_states(inputs, bindings):
    original._need(type(inputs) is dict and type(bindings) is dict and set(inputs) == set(bindings),
        'actual descriptor and own binding mappings required')
    paths = {name: Path(value).absolute() for name, value in inputs.items()}
    original._need(all(path == path.resolve(strict=True) and path.is_file() for path in paths.values()),
        'canonical existing own descriptor files required')
    components, context = _context(paths)
    options = original._union_options()
    proof = current_witness(context, 'sara') if components == FOUR_COMPONENTS else None
    pool = ProducerParserPool(proof) if components == FOUR_COMPONENTS else OriginalParserPool()
    states, proofs = {}, {}
    for component in components:
        path = paths[component]
        metadata = original._checked_binding(context, path, bindings[component], component)
        prepared = original.campaign.prepare_rates(path)
        descriptor, files, inventory, population, trace, outputs = prepared
        original._need(inventory['spans'][0]['component'] == component and population.mass > 0,
            'correct positive complete own component domain required')
        original._need(metadata.get('collection') == 'sara', 'SARA requires its own capture')
        for own_key, descriptor_key in (('case', 'case'), ('actual_binary_sha256', 'binary_sha256'),
                ('arguments', 'arguments'), ('simulator_libraries', 'simulator_libraries')):
            original._need(own_key in metadata and descriptor_key in descriptor
                and original._equivalent(metadata[own_key], descriptor[descriptor_key]),
                'own computation/descriptor binding differs: '+component+'/'+own_key)
        companion = context.read_json(Path(bindings[component]['capture'])/('inputs-'+component+'.json'))
        for role, ref in companion['files'].items():
            original._need(descriptor['files'].get(role, {}).get('sha256') == ref['sha256'],
                'SARA companion role differs: '+component+'/'+role)
        state = dict(prepared=prepared, descriptor=descriptor, paths=files, inventory=inventory,
            population=population, trace=trace, outputs=outputs, metadata=metadata,
            workload={name:descriptor[name] for name in WORKLOAD_FIELDS})
        if component in ('l1d', 'l2'):
            physical, receipt = original._cache_preparation(context, files, metadata)
            rows, residencies = physical
            state.update(rows=rows, residencies=residencies,
                joined=original.batch_cache.join_functional_records(rows, trace['events'], strict_numeric=True),
                physical_preparation=receipt)
        if components == FOUR_COMPONENTS:
            parsed, copy_policy, reuse = pool.prepare(trace, outputs, options,
                source_path=files['trace'], component=component, output_path=files['output_spec'])
        else:
            parsed, copy_policy, reuse = pool.prepare(trace, outputs, options,
                source_path=files['trace'], component=component)
        state.update(parsed, copy_policy=copy_policy, numeric_parser_reuse=reuse)
        states[component] = state
        proofs[component] = dict(descriptor_sha256=context.digest(path),
            population_fingerprint=population.identity, population_mass=population.mass,
            own_image_validation=state['image_support'],
            own_file_roles={role:dict(path=str(source),sha256=context.digest(source))
                for role,source in sorted(files.items())}, event_copy_policy=copy_policy,
            numeric_parser_reuse=reuse)
    groups, membership = _partition_states(states, components, options)
    for component in components:
        proofs[component].update(membership[component], complete_sections=list(original._sections(states[component],options)),
            shared_core_only_after_complete_compatibility=True,
            unproved_sharing_uses_own_core=True, typed_comparison_policy=POLICY)
    context.verify_unchanged()
    return components, context, options, states, groups, proofs, pool


def _run_core(base, options):
    # Generic certificates replace the application-bound loop constructor.
    # The existing scalar reverse core and its arguments remain unchanged.
    from script.core.generic_counter_loops import construct as counter_construct
    from script.core.generic_bound_loops import construct as bound_construct
    from script.core.closed_control import construct as control_construct
    counter_effects, counter_support = counter_construct(base['events'], base['image'])
    bound_effects, bound_support = bound_construct(base['events'], base['image'])
    control_effects, control_support = control_construct(base['events'])
    loop_effects = counter_effects + bound_effects + control_effects
    loop_support = dict(policy='generic-integer-loop-and-closed-control-v1',
        application_specific_dispatch=False, FI_answers_used=False,
        counter=counter_support, bound=bound_support, closed_control=control_support,
        effects=len(loop_effects),
        construction_seconds=sum(s['construction_seconds'] for s in
            (counter_support,bound_support,control_support)))
    effects, closed_support = original.closed_input_effects(base['events'], base['output_ranges'], include_proof_pairs=False)
    core = original.backward.analyze(base['events'], memory_ranges=base['memory_ranges'],
        output_ranges=base['output_ranges'], initial_global_image=base['image'],
        proved_input_effects=effects, consumed_output_policy='serial-joint-aggregate-consumers-v1',
        **options)
    original._need(all(name in core for name in ('read_events','smem_fault_sites','l1d_fault_sites','exact_meta')),
        'detailed union core lacks required original sinks')
    return core, loop_effects, loop_support, closed_support


def evaluate_own_inputs(inputs, bindings, phase_factory=None, collect_regions=False):
    """Fixed driver entry: no prepared object, context or external observer escapes.

    Caller keeps the live method context through persistence/final verification.
    collect_regions is a qualification-only internal buffer, returned after all
    cores/projectors/checks; no caller callback or externally supplied buffer.
    """
    original._need(type(collect_regions) is bool, 'explicit internal region retention boolean required')
    phase = original._phase_factory(phase_factory)
    with phase('own_model_preparation_and_common_core_identity'):
        components, context, options, states, groups, proofs, pool = _prepare_states(inputs, bindings)
    retained = {name:[] for name in components} if collect_regions else None
    results = {}
    with phase('numeric_core_groups_and_actual_complete_projections'):
        context.verify_unchanged()
        for group in groups:
            base = states[group['reference_component']]
            core, loop_effects, loop_support, closed_support = _run_core(base, options)
            for component in group['components']:
                state = states[component]
                analysis = original._component_analysis(core,state,component,closed_support,loop_effects,loop_support)
                if component == 'rf':
                    regions = original.batch.rf_regions(state['inventory'],base['events'],analysis['read_events'],
                        analysis['loop_effects'],analysis['deductive_loop_support'])
                elif component == 'smem':
                    regions = original.smem_regions(state['inventory'],base['events'],analysis,state['trace']['events'])
                    from script.core.closed_pair_reduction import build as reduction_build, project as reduction_project
                    certificates, reduction_support = reduction_build(base['events'],state['trace']['events'],base['image'])
                    regions = reduction_project(regions,certificates,reduction_support)
                    from script.core.closed_word_flow import ClosedFlow
                    from script.core.closed_memory_boundaries import read_boundaries
                    boundaries, boundary_support = read_boundaries(bindings[component]['capture'],
                        state['image'],len(base['events']),state['metadata']['native_source_fingerprint'])
                    word_flow = ClosedFlow(base['events'],state['trace']['events'],host_boundaries=boundaries,initial_image=state['image'])
                    regions = word_flow.project(regions)
                    reduction_support['correlated_word_flow'] = word_flow.stats
                    reduction_support['memory_boundaries'] = boundary_support
                    analysis['closed_reduction_support'] = reduction_support
                    analysis['smem_projection'] = dict(persistent_object_epoch_checked=True,
                        per_draw_full_path_replay=False, bounded_word_counterfactual=True,
                        refinement='closed-lexicographic-shared-tournament-v1',support=reduction_support)
                else:
                    regions = original._cache_regions(state,analysis)
                sink = original.batch.RatesSink(retain_classification_digest=False)
                for region in regions:
                    sink.consume(region)
                    if retained is not None:
                        retained[component].append(region)
                summary = original._summary(state,analysis,sink)
                summary['cost_boundary'] = 'all actual own-input preparation, compatibility proofs, numerical core groups and actual component projections in enclosing method window'
                results[component] = summary
        context.verify_unchanged()
    evidence = dict(actual_components=list(components), actual_core_groups=groups,
        numeric_core_invocations=len(groups), RF_loop_proof_constructions=len(groups),
        closed_local_proof_constructions=len(groups), all_actual_own_inputs_validated=True,
        common_core_options=options, core_input_proof=proofs,
        numeric_parser_invocations=pool.invocations, numeric_parser_reuse_hits=pool.reuse_hits,
        own_full_golden_validations=pool.golden_validations,
        three_component_producer_fastpath_enabled=False,
        actual_component_count=len(components), N_A_components_fabricated=False,
        unproved_core_equivalence_uses_independent_core=True,
        method_local_serial=True,cross_method_reuse=False,cross_invocation_reuse=False,
        mutable_projection_state_shared=False, original_projectors_retained=True,
        generic_shared_refinements=True, application_specific_RF_loop_dispatch=False,
        consumed_output_policy=CONSUMED_OUTPUT_POLICY,
        qualification_regions_retained=collect_regions)
    value = dict(components={name:results[name] for name in components},execution_evidence=evidence,
        actual_core_groups=groups)
    if retained is not None:
        value['qualification_regions'] = retained
    return value
