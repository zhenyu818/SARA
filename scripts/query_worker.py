"""Read-only generic grouped model plus exact native sampled-site projection."""
import argparse,json,sys
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
sys.dont_write_bytecode=True
sys.path[:0]=['/code','/code/script/core','/code/script/common']
def main():
    p=argparse.ArgumentParser();p.add_argument('--budget',type=int,required=True)
    p.add_argument('--method',choices=('sara','gerem'),default='sara');args=p.parse_args()
    from script.execution.policy import require_container_execution
    from script.execution.campaign import atomic_json,fingerprint
    from point_records import write_chunks
    require_container_execution()
    group=json.loads(Path('/prepared/input/prepared-group.json').read_bytes())
    if args.method=='gerem':
        from script.indexed_storage.group import prepare_group,evaluate_group,close_group
        prepared=prepare_group(group,budget=args.budget)
        try:
            result=evaluate_group(prepared,collect_points=True)
            for c,points in result['points'].items():
                write_chunks(Path('/out')/c,points,method='GEREM',identity=dict(component=c,draws=args.budget,
                    population_fingerprint=result['components'][c]['population_fingerprint']))
                atomic_json(Path('/out')/(c+'-summary.json'),result['components'][c])
        finally:close_group(prepared)
        atomic_json(Path('/out/complete.json'),dict(status='complete',additional_export=True,method='gerem',draws=args.budget))
        return
    from script.execution.fair_overhead_run import prepared_paths,bind_prepared
    from script.method_group.group_context import make_context,FOUR_COMPONENTS
    from script.serial_entry.group import evaluate_own_inputs
    from script.execution.compact_population import to_compact_inventory,semantic_population
    from script.core.batch_backward import PairedSink
    declarations={e['component']:e['methods']['sara']['own_input'] for e in group['components']}
    context=make_context({c:r['root'] for c,r in declarations.items()},method='sara')
    with context,ExitStack() as scopes:
        if tuple(declarations)==FOUR_COMPONENTS:
            from script.readonly_records.private_json_identity import _private_json_scope
            from script.verified_inputs.purefreeze_reuse import purefreeze_scope
            proof=scopes.enter_context(_private_json_scope(context,'sara'))
            scopes.enter_context(purefreeze_scope(context,'sara',_proof=proof))
        inputs={};bindings={}
        for c,r in declarations.items():
            a=SimpleNamespace(method='sara',component=c,capture=Path(r['capture']),inputs=Path(r['inputs']['path']),
                own_input_root=Path(r['root']),capture_metadata_sha256=r['capture_metadata']['sha256'],inputs_sha256=r['inputs']['sha256'])
            capture,descriptor,_=prepared_paths(a);inputs[c]=descriptor;bindings[c]=bind_prepared(a,capture,descriptor,context)
        result=evaluate_own_inputs(inputs,bindings,collect_regions=True)
        for c,regions in result['qualification_regions'].items():
            descriptor=context.read_json(inputs[c]);inventory_ref=descriptor['files']['inventory']
            inventory=context.read_json(inputs[c].parent/inventory_ref['path'])
            original=to_compact_inventory(inventory)
            master_path=Path('/masters')/c/'manifest.json';manifest=json.loads(master_path.read_bytes())
            population=semantic_population(original)
            trials=population.validate_manifest(manifest,target_count=args.budget,seed=2026,dispatch_limit=10000)
            projection=dict(own_complete_population_fingerprint=population.identity,
                master_population_fingerprint=manifest['population_fingerprint'],population_mass=population.mass,
                all_requested_draws_in_own_domain=True,original_draw_identities_preserved=True)
            sink=PairedSink(trials)
            for region in regions:sink.consume(region)
            summary=sink.summary(result['components'][c]['population_mass'])
            if summary['counts']!=result['components'][c]['counts']:raise ValueError('Point projection changed whole-population counts')
            write_chunks(Path('/out')/c,sink.records(),method='SARA',identity=dict(component=c,
                master_fingerprint=fingerprint(manifest),population_fingerprint=manifest['population_fingerprint'],
                model='serial_generic',draws=args.budget))
            atomic_json(Path('/out')/(c+'-summary.json'),dict(summary,projection=projection))
        context.verify_unchanged()
    atomic_json(Path('/out/complete.json'),dict(status='complete',sampled_draws_per_component=args.budget,
        additional_export=True,FI_answers_used=False,aggregate_performance_clock=False))
if __name__=='__main__':main()
