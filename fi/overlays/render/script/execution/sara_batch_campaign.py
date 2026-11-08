"""Original batch backward-model evaluation: rates or matched-site queries.

The two modes execute the SAME analyze_rf/rf_regions pipeline. Rates never opens
a site manifest. Predictions see only immutable public inputs, not FI answers.
"""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import time

from script.core.batch_backward import (MODEL, SUPPORT, RatesSink, PairedSink,
    analyze_rf, rf_regions)
from script.execution.campaign import atomic_json, fingerprint, requested_prefix
from script.execution.trace_transport import read_trace_document
from script.core.sparse_global_image import semantic_image
from script.execution.compact_population import (DOMAIN_SCHEMA, SemanticPopulation, read_inventory,
    to_compact_inventory)


def analysis_code_identity(component="rf"):
    root = Path(__file__).resolve().parents[2]
    names = ["script/core/batch_backward.py", "script/core/reg_observed_analyzer.py",
             "script/core/ptx_rcp_semantics.py", "script/core/ptx_native_f32.py",
             "script/core/composition_boundary.py", "script/core/closed_fma_transfer.py"]
    names += ["script/core/ptx_s32_divrem_semantics.py", "script/core/ptx_bfi_semantics.py"]
    names += ["script/core/ptx_u32_rzi_semantics.py"]
    names += ['script/core/sparse_global_image.py','script/core/closed_loop_transfer.py']
    names += ['script/execution/compact_population.py', 'script/execution/population_inventory.py']
    names += ['script/execution/memory_effect_records.py', 'script/execution/method_input_context.py',
              'script/execution/trace_transport.py']
    if component == "smem":
        names += ["script/core/batch_smem.py"]
    if component in ("l1d", "l2"):
        names += ["script/core/batch_cache.py", "script/core/cache_tag_lifetime.py", "script/execution/cache_physical_episodes.py",
                  "script/execution/cache_physical_facts.py", "script/execution/memory_effect_records.py",
                  "script/execution/cache_snapshot_profile.py"]
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}


def checked_inputs(path, *, analysis=True):
    from script.execution.method_input_context import file_digest, read_json
    path = Path(path).resolve(strict=True)
    value = read_json(path)
    schemas = {"sara-batch-inputs-v1", "sara-batch-inputs-v2"} if analysis else {
        "sara-batch-inputs-v1", "sara-population-inputs-v1", "sara-batch-inputs-v2", "sara-population-inputs-v2"}
    if value.get("schema") not in schemas:
        raise ValueError("explicit batch input schema required")
    paths = {}
    required = {"inventory", "output_spec"} | ({"trace"} if analysis else set())
    allowed = required | {"trace", "cache_ledger", "trace_sidecar", "initial_global_image"}
    if not required.issubset(value["files"]) or set(value["files"]) - allowed:
        raise ValueError("unsupported or incomplete analysis input roles")
    for role in sorted(value["files"]):
        if not analysis and not value["schema"].endswith("-v2") and role not in required: continue
        item = value["files"][role]
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("portable input paths must remain within the input bundle")
        source = path.parent / relative
        if file_digest(source) != item["sha256"]:
            raise ValueError("input file hash changed: " + role)
        paths[role] = source
    inventory, population = read_inventory(paths["inventory"])
    if value["schema"].endswith("-v2"):
        if (not isinstance(population, SemanticPopulation)
                or value.get("population_identity_kind") != DOMAIN_SCHEMA
                or value.get("population_fingerprint") != population.identity
                or value.get("population_mass") != population.mass):
            raise ValueError("own compact population descriptor identity/mass disagreement")
    if value["schema"].endswith("-v2"):
        component = population.component
    else:
        if len({row["component"] for row in population.spans}) != 1:
            raise ValueError("one actual component per condition is required")
        component = population.spans[0]["component"]
    if analysis and component in ("l1d", "l2") and not {"cache_ledger", "trace_sidecar"}.issubset(paths):
        raise ValueError("actual cache state/transport and trace close inputs required")
    return value, paths, inventory, population


def evaluate(inputs, *, mode, manifest=None, target_count=None, seed=None, commit=None,
             measure_timing=True, region_buffer=None, prepared=None, defer_provenance=False):
    if mode != 'rates':
        raise ValueError('paired validation must query a completed region capsule; propagation is forbidden')
    clock = time.perf_counter if measure_timing else (lambda: 0.0)
    started = clock()
    if prepared is None:
        prepared = prepare_rates(inputs)
    descriptor, paths, inventory, population, trace, outputs = prepared
    component = inventory['spans'][0]['component']
    preparation_seconds = clock() - started
    query_index_started = clock()
    if manifest is not None or target_count is not None or seed is not None or commit is not None:
        raise ValueError("rates mode does not accept sample/query controls")
    sink = RatesSink()
    query_index_seconds = 0.0
    begin = clock()
    if component == "rf":
        events, analysis = analyze_rf(trace, inventory, output_spec=outputs)
        regions = rf_regions(inventory, events, analysis["read_events"], analysis.get('loop_effects',()),analysis.get('deductive_loop_support'))
    elif component == "smem":
        from script.core.batch_smem import smem_regions
        events, analysis = analyze_rf(trace, inventory, output_spec=outputs)
        regions = smem_regions(inventory, events, analysis, trace["events"])
        analysis["smem_projection"] = {"persistent_object_epoch_checked": True, "per_origin_replay": False}
    else:
        from script.core.batch_cache import analyze_cache
        events, analysis, regions = analyze_cache(trace, inventory, outputs, descriptor, Path(inputs).parent,
                                                  defer_provenance=defer_provenance)
    backward_seconds = clock() - begin
    begin = clock()
    for region in regions:
        sink.consume(region)
        if region_buffer is not None:
            region_buffer.append(region)
    projection_seconds = clock() - begin
    summary = sink.summary(population.mass)
    write_seconds = 0.0
    if mode == "paired" and commit is not None:
        begin = clock()
        for record in sink.records():
            commit(record)
        write_seconds = clock() - begin
    # The compact inventory's transport receipts are evidence, not analysis
    # inputs. A virtual shared-byte view is represented by its unchanged pages.
    normalized_inventory = None if defer_provenance else (to_compact_inventory(inventory)["spans"]
        if descriptor["schema"].endswith("-v2") else inventory)
    summary.update(mode=mode, input_fingerprint=fingerprint(descriptor),
        base_analysis_input_fingerprint=(fingerprint(descriptor) if defer_provenance else fingerprint({'events':trace['events'],
            'memory_ranges':trace.get('memory_ranges',[]),'outputs':outputs,'inventory':normalized_inventory})),
        normalized_analysis_input_fingerprint=(fingerprint(descriptor) if defer_provenance else fingerprint({"events": trace["events"],
            "memory_ranges": trace.get("memory_ranges", []), "outputs": outputs, "inventory": normalized_inventory,
            **({'initial_global_image':semantic_image(trace['initial_global_image'])} if 'initial_global_image' in trace else {}),
            **({"physical_cache_facts":analysis["normalized_cache_input_fingerprint"]} if component in ("l1d", "l2") else {})})),
        composition_support=analysis.get("composition_support"),
        closed_local_support=analysis.get("closed_local_support"),
        initial_global_image_support=analysis.get('initial_global_image_support'),
        deductive_loop_support=analysis.get('deductive_loop_support'),
        uncertainty_diagnostics={key:analysis[key] for key in ('addr_alias_unknown_bits','addr_alias_unknown_events','addr_same_value_masked_bits','control_taint_stats') if key in analysis},
        component_support=analysis.get("smem_projection" if component == "smem" else "cache_projection"),
        analysis_code=None if defer_provenance else analysis_code_identity(component),
        population_fingerprint=population.identity, dynamic_events=len(events),
        population_identity_kind=descriptor.get("population_identity_kind", "legacy_rich_inventory_fingerprint"),
        shared_manifest_population_fingerprint=manifest["population_fingerprint"] if manifest is not None else None,
        classification_uses_FI_answers=False, sampled_draws=len(sink.trials) if mode == "paired" else None,
        timings={"input_preparation_seconds": preparation_seconds,
            "backward_analysis_seconds": backward_seconds,
            "storage_projection_and_sink_seconds": projection_seconds,
            "paired_query_seconds": sink.query_seconds if mode == "paired" else 0.0,
            "paired_index_and_draw_validation_seconds": query_index_seconds,
            "paired_record_write_seconds": write_seconds,
            "wall_seconds_before_summary_write": clock() - started} if measure_timing else {
                "participates_in_performance_measurement": False},
        process_resources={"cpu_user_seconds": resource.getrusage(resource.RUSAGE_SELF).ru_utime,
            "cpu_system_seconds": resource.getrusage(resource.RUSAGE_SELF).ru_stime,
            "max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss} if measure_timing else None,
        validation_only=not measure_timing,
        cost_boundary="analysis invocation; actual upstream acquisition/build/container costs are separately recorded")
    return summary, (sink.records() if mode == "paired" else None)


def prepare_rates(inputs):
    from script.execution.method_input_context import read_json
    descriptor, paths, inventory, population = checked_inputs(inputs)
    # Retain the context's pristine immutable parsed document. Only this small
    # root mapping receives the independent initial-memory companion.
    trace = dict(read_trace_document(paths['trace'])[0])
    if 'initial_global_image' in paths:
        trace['initial_global_image'] = read_json(paths['initial_global_image'])
    outputs = read_json(paths['output_spec'])
    return descriptor, paths, inventory, population, trace, outputs


class SaraRatesSession:
    def __init__(self, inputs):
        self.inputs = Path(inputs)
        self.prepared = prepare_rates(inputs)
        descriptor, _, inventory, population, _, _ = self.prepared
        self.component = inventory['spans'][0]['component']
        self.identity = dict(method=MODEL, support_fingerprint=fingerprint(SUPPORT),
            input_fingerprint=fingerprint(descriptor), component=self.component,
            population_fingerprint=population.identity, population_mass=population.mass,
            population_contract={key: inventory[key] for key in
                ('fault_model', 'coordinate_system', 'time_basis')})
        self.regions, self.summary = [], None

    def run_rates(self):
        if self.summary is not None:
            raise ValueError('the SARA batch core may run only once per session')
        self.summary, _ = evaluate(self.inputs, mode='rates', prepared=self.prepared,
            region_buffer=self.regions, defer_provenance=True, measure_timing=False)
        self.summary.update(validation_only=False, component=self.component,
            timings={'managed_by_enclosing_performance_window': True}, process_resources=None,
            cost_boundary='own acquisition through aggregate fsync in enclosing performance-window.json',
            validation_region_buffer='classified intervals retained in measured RAM; serialized post-window')
        return self.summary

    def export_validation(self, output):
        if self.summary is None:
            raise ValueError('rates must finish before validation export')
        from script.execution.region_capsule import write_capsule
        self.identity['analysis_code'] = analysis_code_identity(self.component)
        inventory = to_compact_inventory(self.prepared[2])
        self.identity['original_inventory_fingerprint'] = fingerprint(inventory)
        receipt = write_capsule(output, self.regions, identity=self.identity, aggregate=self.summary)
        atomic_json(Path(output) / 'original-population.json', inventory)
        return receipt

    def validation_summary(self):
        if self.summary is None:
            raise ValueError('rates must finish before validation provenance')
        return dict(self.summary, analysis_code=self.identity.get('analysis_code') or analysis_code_identity(self.component),
            normalized_analysis_input_fingerprint=fingerprint(self.identity))


def paired_from_capsule(capsule, manifest, *, seed, target_count, output, projection_population=None):
    from script.execution.region_capsule import read_capsule
    from script.execution.validation_records import write_chunks
    receipt, regions = read_capsule(capsule)
    identity, aggregate = receipt['identity'], receipt['aggregate']
    if (identity.get('method') != MODEL or identity.get('support_fingerprint') != fingerprint(SUPPORT)
            or identity.get('analysis_code') != analysis_code_identity(identity['component'])):
        raise ValueError('paired capsule belongs to another frozen model/support/source')
    projection = None
    if projection_population is not None:
        from script.execution.projection_population import validate_projection
        original = json.loads((Path(capsule).parent / 'original-population.json').read_text())
        if fingerprint(original) != identity.get('original_inventory_fingerprint'):
            raise ValueError('capsule own original inventory identity changed')
        trials, projection = validate_projection(manifest, projection_population, original,
            seed=seed, target_count=target_count)
        if (projection['original_population_fingerprint'] != identity['population_fingerprint']
                or projection['original_population_mass'] != aggregate['population_mass']):
            raise ValueError('subset belongs to another classified complete population')
    elif (manifest.get('seed') != seed or seed != 2026 or manifest.get('sampling') != 'with_replacement'
            or manifest.get('population_size') != aggregate['population_mass']
            or any(manifest.get('population_contract', {}).get(key) != value
                   for key, value in identity['population_contract'].items())):
        raise ValueError('paired manifest differs from the classified complete population contract')
    count = requested_prefix(manifest['trials'], target_count, dispatch_limit=10000)
    parent = manifest.get('parent_draw_range')
    if parent is not None and (not isinstance(parent, list) or len(parent) != 2
            or any(type(value) is not int for value in parent) or parent[0] < 0
            or parent[1] - parent[0] != len(manifest['trials'])):
        raise ValueError('invalid immutable parent draw range')
    first, ids = (parent[0] if parent else 0), set()
    for draw, trial in enumerate(manifest['trials']):
        if (not isinstance(trial.get('trial_id'), str) or not trial['trial_id']
                or trial['trial_id'] in ids or trial.get('draw_index') != first + draw
                or trial.get('component') != identity['component']
                or trial.get('population_fingerprint') != manifest.get('population_fingerprint')
                or type(trial.get('population_rank')) is not int
                or not 0 <= trial['population_rank'] < manifest['population_size']):
            raise ValueError('immutable paired draw identity changed')
        ids.add(trial['trial_id'])
        site = {key: trial[key] for key in ('population_fingerprint', 'component', 'target', 'cycle', 'bit')}
        if fingerprint(site) != trial.get('site_id'):
            raise ValueError('paired site hash differs from its original coordinates')
    sink = PairedSink(trials if projection is not None else manifest['trials'][:count])
    for region in regions:
        sink.consume(region)
    summary = sink.summary(aggregate['population_mass'])
    if any(summary[key] != aggregate[key] for key in ('counts', 'classification_digest', 'region_count')):
        raise ValueError('paired capsule differs from the original complete rates result')
    point_identity = dict(identity, master_manifest_fingerprint=fingerprint(manifest), target_count=count)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    write_chunks(output / 'validation-points', sink.records(), method='SARA', identity=point_identity)
    result = dict(summary, mode='paired', validation_only=True, sampled_draws=count,
        population_fingerprint=identity['population_fingerprint'], input_fingerprint=identity['input_fingerprint'],
        base_analysis_input_fingerprint=identity['input_fingerprint'],
        normalized_analysis_input_fingerprint=fingerprint(identity), analysis_code=identity['analysis_code'],
        shared_manifest_population_fingerprint=manifest['population_fingerprint'], classification_uses_FI_answers=False,
        timings={'participates_in_performance_measurement': False}, process_resources=None,
        new_collection=False, new_batch_propagation=False, per_origin_replay=False,
        same_rates_core_result=True, validation_points='validation-points/index.json')
    if projection is not None:
        result['subset_projection'] = projection
    atomic_json(output / 'analysis.json', result)
    return result


def main(argv=None):
    from script.execution.policy import require_container_execution
    require_container_execution()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("rates", "paired"))
    parser.add_argument("--inputs", type=Path)
    parser.add_argument("--region-capsule", type=Path)
    parser.add_argument('--projection-population', type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--campaign-id")
    parser.add_argument("--site-manifest", type=Path)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--target-count", type=int)
    parser.add_argument("--no-timing", action="store_true", help="paired accuracy validation; no performance metrics")
    args = parser.parse_args(argv)
    if args.mode == "rates":
        if (args.no_timing or args.inputs is None or args.region_capsule is not None
                or args.projection_population is not None):
            parser.error("rates requires fresh own inputs and a performance window")
        if any(value is not None for value in (args.site_manifest, args.target_count, args.seed, args.campaign_id)):
            parser.error("rates mode does not take paired controls")
        if args.output.exists():
            raise FileExistsError("never replace a completed rates result")
        from script.execution.method_performance import PerformanceWindow
        window = PerformanceWindow('SARA-rates', args.output,
            task='prepared own-input analysis only; acquisition not included')
        args.output.mkdir(parents=True, exist_ok=False)
        try:
            with window.phase('own_model_preparation'):
                session = SaraRatesSession(args.inputs)
            with window.phase('batch_analysis_and_population_aggregation'):
                aggregate = session.run_rates()
            window.finish(aggregate)
        except BaseException as error:
            if not window.finished:
                window.save_partial(error)
            raise
        session.export_validation(args.output / 'validation-state')
        atomic_json(args.output / 'analysis.json', session.validation_summary())
    else:
        if (not args.no_timing or args.region_capsule is None or args.inputs is not None
                or args.site_manifest is None or args.seed != 2026 or args.target_count is None):
            parser.error('paired requires --no-timing, classified region capsule and immutable seed2026 draws')
        manifest = json.loads(args.site_manifest.read_text())
        paired_from_capsule(args.region_capsule, manifest, seed=args.seed,
            target_count=args.target_count, output=args.output,
            projection_population=args.projection_population)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
