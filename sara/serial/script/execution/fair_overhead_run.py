"""Cold-single or warm-sweep own-method protocols; never replay old outputs.

Normal timing has no directory sampler. Resource profiling and optional inner
work breakdown are separate diagnostics, not primary speed-ratio evidence.
"""
import argparse
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys

from script.execution.campaign import atomic_json

BUDGETS = (1000, 5000, 10000)
HEX = re.compile(r'[0-9a-f]{64}\Z')


def requested_budgets(protocol, budgets):
    if protocol == 'warm-sweep' and (budgets is None or tuple(budgets) == BUDGETS):
        return BUDGETS
    if protocol == 'cold-single' and budgets is not None and len(budgets) == 1 and budgets[0] in BUDGETS:
        return tuple(budgets)
    raise ValueError('warm-sweep fixes 1K -> 5K -> 10K; cold-single requires exactly one budget')


def collection_command(args, capture):
    command = [sys.executable, '-m', 'script.execution.ge_batch_experiment', 'capture',
        '--simulator-root', str(args.simulator_root), '--executable', str(args.executable),
        '--base-config', str(args.base_config), '--output', str(capture), '--case', args.case,
        '--component', args.component, '--minimal-population', '--defer-diagnostics']
    if args.component in ('l1d', 'l2'):
        command.append('--cache-state')
    if args.method == 'gerem':
        command += ['--collection', {'rf': 'gerem-rf', 'smem': 'gerem-smem',
            'l1d': 'gerem-cache', 'l2': 'gerem-cache'}[args.component]]
    return command


@contextmanager
def profiling_environment(enabled):
    previous = os.environ.get('SARA_RESOURCE_PROFILE_ONLY')
    if not enabled and previous == '1':
        raise ValueError('normal timing cannot run in a resource-profile-only process')
    if enabled:
        os.environ['SARA_RESOURCE_PROFILE_ONLY'] = '1'
    try:
        yield
    finally:
        if enabled:
            if previous is None:
                os.environ.pop('SARA_RESOURCE_PROFILE_ONLY', None)
            else:
                os.environ['SARA_RESOURCE_PROFILE_ONLY'] = previous


def canonical(path, *, directory=False):
    path = Path(path).absolute()
    if path != path.resolve(strict=True) or path.is_dir() != directory or (not directory and not path.is_file()):
        raise ValueError('canonical input path and exact type required')
    return path


def prepared_paths(args):
    capture, inputs = canonical(args.capture, directory=True), canonical(args.inputs)
    root = canonical(args.own_input_root, directory=True)
    for path in (capture, inputs):
        if path != root and root not in path.parents:
            raise ValueError('capture/descriptor must stay in one explicit own-input root')
        if not os.statvfs(path).f_flag & os.ST_RDONLY:
            raise ValueError('prepared own inputs must be mounted actually read-only')
    if args.method == 'gerem' and inputs.parent != capture:
        raise ValueError('GEREM descriptor must remain in its own capture')
    return capture, inputs, root


def bind_prepared(args, capture, inputs, context):
    metadata_path = capture / 'capture.json'
    if context.digest(metadata_path) != args.capture_metadata_sha256 or context.digest(inputs) != args.inputs_sha256:
        raise ValueError('prepared capture/descriptor external SHA differs')
    metadata, descriptor = context.read_json(metadata_path), context.read_json(inputs)
    collection = {'rf': 'gerem-rf', 'smem': 'gerem-smem', 'l1d': 'gerem-cache',
        'l2': 'gerem-cache'}[args.component] if args.method == 'gerem' else 'sara'
    if (metadata.get('collection') != collection or metadata.get('case') != descriptor.get('case')
            or metadata.get('actual_binary_sha256') != descriptor.get('binary_sha256')
            or metadata.get('arguments') != descriptor.get('arguments')
            or metadata.get('simulator_libraries') != descriptor.get('simulator_libraries')):
        raise ValueError('descriptor is not bound to this method own capture')
    if args.method == 'sara':
        original = context.read_json(capture / ('inputs-' + args.component + '.json'))
        for role, ref in original['files'].items():
            if descriptor['files'].get(role, {}).get('sha256') != ref['sha256']:
                raise ValueError('SARA companion borrowed a different capture role')
    return dict(capture=str(capture), inputs=str(inputs),
        capture_metadata_sha256=args.capture_metadata_sha256, inputs_sha256=args.inputs_sha256,
        collection_excluded=True, own_inputs_read_only=True)


def master_pin(args):
    path = canonical(args.site_manifest)
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.site_manifest_sha256:
        raise ValueError('immutable seed2026 master SHA differs')
    return dict(path=str(path), bytes=len(raw), sha256=args.site_manifest_sha256)


def phase(window, profile, name):
    return profile.phase(name) if profile is not None else window.phase(name)


def budget_references(method, budgets, checkpoints):
    if method == 'sara':
        return [dict(budget=count, aggregate_file='aggregate.json', shared_whole_analysis=True,
            analysis_executions=1, independent_budget_measurement=False) for count in budgets]
    return [dict(budget=row['budget'], aggregate_file=row['aggregate_file'],
        shared_whole_analysis=False, cumulative_same_session=len(budgets) > 1) for row in checkpoints]


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--method', choices=('gerem', 'sara'), required=True)
    parser.add_argument('--scope', choices=('own-acquisition', 'prepared-own-inputs'), required=True)
    parser.add_argument('--protocol', choices=('cold-single', 'warm-sweep'), default='warm-sweep')
    parser.add_argument('--budgets', nargs='+', type=int)
    parser.add_argument('--component', choices=('rf', 'smem', 'l1d', 'l2'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    for name in ('simulator-root', 'executable', 'base-config', 'capture', 'inputs', 'own-input-root', 'site-manifest'):
        parser.add_argument('--' + name, type=Path)
    for name in ('case', 'capture-metadata-sha256', 'inputs-sha256', 'site-manifest-sha256'):
        parser.add_argument('--' + name)
    parser.add_argument('--seed', type=int)
    parser.add_argument('--resource-profile', action='store_true')
    parser.add_argument('--work-breakdown', action='store_true')
    args = parser.parse_args(argv)
    try:
        args.budgets = requested_budgets(args.protocol, args.budgets)
        acquire = ('simulator_root', 'executable', 'base_config', 'case')
        prepared = ('capture', 'inputs', 'own_input_root', 'capture_metadata_sha256', 'inputs_sha256')
        required, forbidden = (acquire, prepared) if args.scope == 'own-acquisition' else (prepared, acquire)
        if any(getattr(args, name) is None for name in required) or any(getattr(args, name) is not None for name in forbidden):
            raise ValueError('supply exactly the own-acquisition or bound prepared-own-inputs arguments')
        for name in ('capture_metadata_sha256', 'inputs_sha256', 'site_manifest_sha256'):
            value = getattr(args, name)
            if value is not None and not HEX.fullmatch(value):
                raise ValueError('external SHA must be lowercase64hex: ' + name)
        if args.method == 'gerem':
            if args.site_manifest is None or args.site_manifest_sha256 is None or args.seed != 2026:
                raise ValueError('GEREM requires an externally pinned immutable seed2026 master')
        elif any(value is not None for value in (args.site_manifest, args.site_manifest_sha256, args.seed)):
            raise ValueError('SARA whole analysis never takes sample/query controls')
    except ValueError as error:
        parser.error(str(error))
    return args


def execute(args):
    from script.execution.policy import require_container_execution
    require_container_execution()
    output = args.output.absolute()
    if os.path.lexists(output) or output.parent != output.parent.resolve(strict=True):
        raise FileExistsError('fresh output with an existing canonical parent required')
    capture = inputs = own_root = None
    if args.scope == 'prepared-own-inputs':
        capture, inputs, own_root = prepared_paths(args)
        if output == own_root or own_root in output.parents:
            raise ValueError('prepared input root cannot contain new output')
    output.mkdir()
    diagnostic = bool(args.resource_profile or args.work_breakdown)
    protocol = dict(schema='sara-fair-own-method-protocol-v1', method=args.method,
        protocol=args.protocol, budgets=list(args.budgets), scope=args.scope,
        acquisition_included=args.scope == 'own-acquisition',
        cost_boundary=('own acquisition through durable aggregate' if args.scope == 'own-acquisition'
            else 'prepared own-input loading, preparation and analysis through durable aggregate; collection excluded'),
        prepared_acquisition_cost_assigned_zero=False,
        comparison_contract=('aggregate-only-cumulative-prefix-v2' if args.protocol == 'warm-sweep'
            else 'aggregate-only-independent-budget-v2'),
        output_contract='durable-aggregate-for-each-requested-prefix-whole-result-reusable',
        input_validation_contract='own-input-identity-checked-before-each-durable-delivery',
        optional_output_policy='aggregate-only',
        performance_measurement=not args.resource_profile,
        resource_profile=args.resource_profile, work_breakdown=args.work_breakdown,
        instrumented_diagnostic=diagnostic, primary_speed_ratio_eligible=not diagnostic,
        instrument_overhead_included=True,
        primary_clock_and_phase_snapshot_overhead_included=not args.resource_profile,
        recursive_resource_sampler_enabled=args.resource_profile,
        warm_same_model_retained=args.method == 'gerem' and args.protocol == 'warm-sweep',
        original_clocks_or_artifacts_modified=False, FI_answers_read=False,
        validation_export_included=False, paired_query_included=False,
        external_output_setup_Docker_startup_included=False,
        disk_cache_coldness_controlled=False)
    window = profile = breakdown = None
    profile_finished = False
    stages, checkpoints = {}, []
    with profiling_environment(args.resource_profile):
        try:
            if args.resource_profile:
                from script.execution.method_resource_profile import ResourceProfile
                profile = ResourceProfile(output)
                if args.method == 'gerem':
                    for count in args.budgets[:-1]:
                        profile.register_output_role('aggregate-%08d.json' % count, 'result')
                if capture is not None:
                    roots = [capture]
                    if inputs.parent != capture and capture not in inputs.parent.parents:
                        roots = [inputs.parent] if inputs.parent in capture.parents else roots + [inputs.parent]
                    for root in roots:
                        profile.register_input_root(root)
            else:
                from script.execution.method_performance import PerformanceWindow
                window = PerformanceWindow('GEREM' if args.method == 'gerem' else 'SARA-rates',
                    output, component=args.component, task=protocol)
            if args.work_breakdown:
                from script.execution.method_work_breakdown import Breakdown
                breakdown = Breakdown()
            if args.scope == 'own-acquisition':
                capture, own_root = output / 'capture', output
                command = collection_command(args, capture)
                with phase(window, profile, 'collection'):
                    if profile is not None:
                        with (output / 'collection.log').open('xb') as log:
                            subprocess.run(command, cwd=Path.cwd(), env=dict(os.environ),
                                stdout=log, stderr=subprocess.STDOUT, check=True, timeout=7200)
                        stages['collection'] = dict(command=command, successful=True,
                            performance_measurement=False, separate_resource_profile=True)
                    else:
                        from script.execution.ge_batch_experiment import measured
                        stages['collection'] = measured(command, Path.cwd(), output / 'collection.log',
                            dict(os.environ), timeout=7200, persist_diagnostics=False)
            from script.execution.method_input_context import OwnInputContext
            with OwnInputContext(own_root) as own_inputs:
                if args.scope == 'prepared-own-inputs':
                    with phase(window, profile, 'prepared_own_input_binding'):
                        stages['prepared_inputs'] = bind_prepared(args, capture, inputs, own_inputs)
                else:
                    from script.execution import ge_batch_experiment as preparation
                    prepare_args = argparse.Namespace(capture=capture, no_manifest=True,
                        population_only=args.method == 'gerem', component=args.component)
                    prepare = (preparation.prepare_cache if args.component in ('l1d', 'l2')
                        else preparation.prepare_smem if args.component == 'smem' else preparation.prepare_rf)
                    with phase(window, profile, 'population_input_preparation'):
                        stages['population_input_preparation'] = prepare(prepare_args)
                    inputs = capture / ('inputs-' + args.component + '.json')
                    if args.method == 'sara':
                        from script.core.sparse_global_image import prepare as prepare_image
                        with phase(window, profile, 'initial_memory_preparation'):
                            stages['initial_memory_preparation'] = prepare_image(capture,
                                output / 'initial-state', Path(__file__).resolve().parents[2],
                                component=args.component, defer_constant_validation=True)
                        inputs = output / 'initial-state' / ('inputs-' + args.component + '.json')
                with phase(window, profile, 'own_model_preparation'):
                    if args.method == 'gerem':
                        from script.execution.batch_gerem import GeremSession
                        session = GeremSession(inputs, capture, args.site_manifest, seed=2026,
                            target_count=args.budgets[-1], output=output / 'own-model', phase_stats=breakdown,
                            aggregate_only=True, expected_manifest_sha256=args.site_manifest_sha256)
                        stages['master'] = session.master_receipt
                    else:
                        from script.execution.sara_batch_campaign import SaraRatesSession
                        if breakdown is not None:
                            with breakdown.activate(), breakdown.phase('own_input_decode_domain'):
                                session = SaraRatesSession(inputs, aggregate_only=True)
                        else:
                            session = SaraRatesSession(inputs, aggregate_only=True)
                if session.component != args.component:
                    raise ValueError('own input component differs from requested stratum')
                if args.method == 'gerem':
                    previous = 0
                    for count in args.budgets:
                        with phase(window, profile, 'prefix_%08d_queries_and_aggregate' % count):
                            aggregate = (session.run_prefix(count) if args.protocol == 'warm-sweep'
                                else session.run_aggregate())
                        final = count == args.budgets[-1]
                        aggregate['cost_boundary'] = protocol['cost_boundary']
                        name = 'aggregate.json' if final else 'aggregate-%08d.json' % count
                        if not final:
                            with phase(window, profile, 'prefix_%08d_own_input_identity_check' % count):
                                own_inputs.verify_unchanged()
                            with phase(window, profile, 'prefix_%08d_durable_persistence' % count):
                                atomic_json(output / name, aggregate)
                        row = dict(budget=count, new_draw_range=[previous, count],
                            aggregate_file=name, cumulative_queried_draws=count,
                            same_session_and_model=True, repeated_old_draw_queries=0)
                        if breakdown is not None:
                            row['cumulative_work_breakdown'] = breakdown.snapshot()
                        if profile is not None:
                            profile.checkpoint('prefix_%08d' % count)
                        elif not final:
                            from script.execution.method_performance import elapsed, snapshot
                            row['cumulative_performance'] = elapsed(window.started, snapshot())
                        checkpoints.append(row)
                        previous = count
                else:
                    with phase(window, profile, 'whole_population_analysis_and_aggregation'):
                        if breakdown is not None:
                            with breakdown.activate(), breakdown.phase('whole_population_analysis_and_aggregation'):
                                aggregate = session.run_rates()
                        else:
                            aggregate = session.run_rates()
                aggregate['cost_boundary'] = protocol['cost_boundary']
                with phase(window, profile, 'final_own_input_identity_check'):
                    own_inputs.verify_unchanged()
                if profile is not None:
                    input_reuse = own_inputs.summary()
                    required = {own_root / row['path'] for row in input_reuse['files']}
                    if args.method == 'gerem':
                        required.update(capture / name for name in ('capture.json', 'gpgpusim.config', 'run.log'))
                        required.add(canonical(args.site_manifest))
                    profile.register_required_inputs(sorted(required))
                if profile is not None:
                    with profile.phase('aggregate_persistence'):
                        atomic_json(output / 'aggregate.json', aggregate)
                    profile.checkpoint('final_aggregate_durable')
                    measurement = None
                else:
                    measurement = window.finish(aggregate)
                    if checkpoints:
                        checkpoints[-1]['cumulative_performance'] = measurement
                    # Optional provenance inventory is assembled after timing;
                    # necessary input validation stays before durable delivery.
                    input_reuse = own_inputs.summary()
            if profile is not None:
                profile_finished = True
                profile.finish()
        except BaseException as error:
            if window is not None and not window.finished:
                window.save_partial(error)
            atomic_json(output / 'incomplete.json', dict(protocol=protocol,
                error=type(error).__name__ + ': ' + str(error), complete=False,
                scientific_failure_label_created=False, automatic_retry=False,
                old_inputs_and_results_modified=False))
            raise
        finally:
            if profile is not None and not profile_finished:
                profile_finished = True
                profile.finish()
    # No diagnostic/provenance file exports occur inside the measured boundary.
    if breakdown is not None:
        atomic_json(output / 'work-breakdown.json', dict(breakdown.snapshot(),
            diagnostic_only=True, primary_speed_ratio_eligible=False,
            per_scope_clock_overhead_included=True))
    atomic_json(output / 'input-reuse.json', dict(input_reuse,
        performance_measurement=False,
        necessary_input_loading_and_validation_in_enclosing_boundary=True,
        optional_metadata_assembly_in_primary_clock=False,
        optional_metadata_export_in_primary_clock=False))
    atomic_json(output / 'protocol.json', dict(protocol, complete=True,
        budget_references=budget_references(args.method, args.budgets, checkpoints),
        checkpoints=checkpoints, stages=stages,
        source_collection_reused=args.scope == 'prepared-own-inputs',
        new_collection=args.scope == 'own-acquisition', aggregate_file='aggregate.json',
        performance_receipt='performance-window.json' if measurement is not None else None,
        resource_profile_receipt='resource-profile.json' if args.resource_profile else None,
        embedded_legacy_timer_annotations_are_not_new_receipts=True,
        performance_window_created=window is not None,
        incomplete_results_promoted=False, validation_or_paired_queries_executed=False))
    return 0


def main(argv=None):
    return execute(arguments(argv))


if __name__ == '__main__':
    raise SystemExit(main())
