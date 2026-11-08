"""Administrative full-flow wrapper; fixed scientific modules are never patched.

Each task starts at its executable/configuration, collects its own required
inputs, prepares its own population, and runs one unchanged aggregate method.
Producer and consumer are consecutive under one measured parent cgroup; the
consumer receives only read-only newly produced inputs. No FI is invoked.
"""
import argparse
from contextlib import ExitStack
from copy import deepcopy
import gc
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
from types import SimpleNamespace

sys.dont_write_bytecode=True
sys.path[:0]=['/code','/code/script/common','/code/script/core']
OUT=Path('/out')

def need(ok,message):
    if not ok:raise RuntimeError(message)
def read(p):return json.loads(Path(p).read_bytes())
def pin(p):
    p=Path(p);data=p.read_bytes()
    return dict(path=str(p),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
def saved(p,value):
    from script.execution.campaign import atomic_json
    need(not p.exists(),'fresh persistence only: '+str(p));atomic_json(p,value)
    return pin(p)

def namespace(request):
    import script
    for path in request['package_search_roots']:
        need(os.statvfs(path).f_flag & os.ST_RDONLY,'fixed read-only scientific namespace')
        if path not in script.__path__:script.__path__.append(path)

def baseline(request,window):
    """One separate no-fault/no-observer control, never part of a method clock."""
    from script.execution import ge_batch_experiment as producer
    args=SimpleNamespace(case=request['case'],output=OUT/'capture',
        base_config=Path(request['configuration']),simulator_root=Path('/native'),
        executable=Path(request['binary']),component='rf',minimal_population=True,
        cache_state=False,collection='fi-golden',cache_profile='changes',
        validate_cpu=False,defer_diagnostics=False,timeout=7200)
    with window.phase('independent_plain_fault_free_control'):
        record=producer.capture(args)
    need(record['output']==request['expected_output'] and record['gpu_cycles']==request['expected_cycles'],
         'plain native control changed output/cycles')
    window.complete(dict(status='complete',kind='independent_unprofiled_fault_free_control',
        group_id=request['group']['group_id'],capture=record,new_FI=0,
        predictor_calls=0,primary_method_clock=False,CPU_reference_check=False))
    saved(OUT/'complete.json',dict(status='complete',stage='baseline',C_only=True,new_FI=0))

def produce(request,window):
    from script.execution import ge_batch_experiment as producer
    from script.execution.method_input_context import OwnInputContext
    from script.execution.fault_manifest import FaultPopulation
    from script.core.sparse_global_image import prepare as prepare_image
    group=deepcopy(request['group']);method=request['method'];budget=request['budget']
    root=Path(request['fresh_input_root']);root.mkdir()
    common_cache=None;declarations={};capture_records={}
    for entry in group['components']:
        c=entry['component'];own=root/c;own.mkdir();cap=own/'capture'
        cache=c in ('l1d','l2')
        if cache and common_cache is not None:
            with window.phase('bind_same_cache_collection_'+c):
                # Same freshly produced physical ledger/trace. No cross-method,
                # cross-budget, or historical collection is borrowed.
                cap.mkdir()
                collector_root,collector_members=common_cache
                for relative in sorted(collector_members,key=lambda p:(len(p.parts),str(p))):
                    p=collector_root/relative;target=cap/relative
                    need(not p.is_symlink(),'collector symlink not permitted')
                    if p.is_dir():target.mkdir()
                    elif p.is_file():os.link(p,target)
                    else:need(False,'unexpected collector object')
        else:
            collection='sara' if method=='sara' else 'gerem-cache' if cache else 'gerem-'+c
            with window.phase('necessary_collection_'+('cache' if cache else c)):
                args=SimpleNamespace(case=request['case'],output=cap,
                    base_config=Path(request['configuration']),simulator_root=Path('/native'),
                    executable=Path(request['binary']),component=c,minimal_population=True,
                    cache_state=cache,collection=collection,cache_profile='changes',
                    validate_cpu=False,defer_diagnostics=True,timeout=7200)
                record=producer.capture(args)
                capture_records['cache' if cache else c]=record
            if cache:common_cache=(cap,tuple(p.relative_to(cap) for p in cap.rglob('*')))
        with OwnInputContext(own):
            with window.phase('population_and_descriptor_'+c):
                args=SimpleNamespace(capture=cap,no_manifest=True,population_only=method=='gerem',component=c)
                prepare=producer.prepare_cache if cache else producer.prepare_smem if c=='smem' else producer.prepare_rf
                prepare(args)
            if method=='sara':
                with window.phase('necessary_initial_memory_'+c):
                    prepare_image(cap,own/'initial-state',Path('/native-memory-source'),component=c,defer_constant_validation=True)
                descriptor=own/'initial-state'/('inputs-'+c+'.json')
            else:descriptor=cap/('inputs-'+c+'.json')
        declarations[c]=dict(root=str(own),capture=str(cap),capture_metadata=pin(cap/'capture.json'),inputs=pin(descriptor))
        entry['methods']={method:dict(own_input=declarations[c])}
    sampling_records=[]
    if method=='gerem':
        samples=root/'sampling';samples.mkdir()
        for entry in group['components']:
            c=entry['component'];original=entry['master'];original_path=Path(original['path'])
            with window.phase('necessary_sampling_preparation_'+c):
                need(pin(original_path)==original,'immutable original master input')
                old=read(original_path);inventory=read(original_path.parent/'inventory.json')
                population=FaultPopulation(inventory)
                need(population.identity==old['population_fingerprint'] and population.mass==old['population_size'],
                    'immutable original physical sampling authority')
                # The fixed <=10K loader consumes a 10K master even for a
                # smaller prefix. Count that actual preparation, without
                # changing its established loader or sampling algorithm.
                count=200000 if budget==200000 else 10000
                generated=population.sample(count,2026,old['stream'])
                need(generated['trials'][:10000]==old['trials'] and old['seed']==2026
                     and old['sampling']=='with_replacement','same first10K identities and legal repeated draws')
                master10=dict(old,trials=generated['trials'][:10000])
                fresh10=saved(samples/('master-'+c+'-10000.json'),master10)
                entry['master']=fresh10
                if budget==200000:
                    extended=dict(old,trials=generated['trials'])
                    extended['extension']=dict(schema='gerem-fi-compat-200k-prefix-extension-v1',
                        original_master=fresh10,original_draws=10000,total_draws=200000,
                        first_10000_draws_exact=True,tail_draw_range=[10000,200000],
                        sampler='unchanged FaultPopulation.sample / sara-sha256-rejection-v1',
                        repeat_first10k=False,draw_indices_reset=False,new_FI=False,accuracy_reference_for_200k=False)
                    fresh200=saved(samples/('master-'+c+'-200000.json'),extended)
                    proof=dict(schema='gerem-fi-compat-extension-200k-v1',status='PASS',
                        components=[dict(component=c,original_master=fresh10,new_master=fresh200,
                            first_10000_draws_exact=True,draws=200000)],
                        canonical_original_master=original,original_10K_untouched=True)
                    entry['master_200k']=fresh200
                    entry['master_extension_manifest']=saved(samples/('extension-'+c+'.json'),proof)
                sampling_records.append(dict(component=c,original_master=original,prepared_draws=count,
                    requested_budget=budget,first_10000_exact=True,original_population_mass=population.mass))
                del generated,population,inventory,old,master10
                if budget==200000:del extended
                gc.collect()
    with window.phase('necessary_input_binding_persistence'):
        group_ref=saved(root/'prepared-group.json',group)
    result=dict(status='COMPLETE',method=method,group_id=group['group_id'],budget=budget,
        fresh_inputs=True,group=group_ref,collections=capture_records,sampling=sampling_records,
        no_cross_method_or_budget_reuse=True,FI_calls=0,compilation_calls=0,
        collection_note='one own cache capture supplies both cache descriptors; all other actual component collectors are own',
        sampling_note='fixed small-budget loader receives a freshly prepared immutable10K master; its prefix is selected in the unchanged loader')
    window.complete(result)
    saved(OUT/'complete.json',dict(status='complete',stage='produce',group=group_ref))

def consume(request,window):
    from script.execution.campaign import atomic_json
    group=read(Path(request['fresh_input_root'])/'prepared-group.json')
    method=request['method'];budget=request['budget']
    need(group['group_id']==request['group']['group_id'],'actual prepared group identity')
    if method=='gerem':
        from script.indexed_storage.group import prepare_group,evaluate_group,close_group
        prepared=None;closed=False
        try:
            prepared=prepare_group(group,budget=budget,phase_factory=window.phase)
            evaluated=evaluate_group(prepared,phase_factory=window.phase,collect_points=False)
            need('points' not in evaluated and not evaluated.get('ordered_digests'),'aggregate-only main timing')
            with window.phase('required_component_aggregate_persistence'):
                for c,value in evaluated['components'].items():atomic_json(OUT/(c+'-aggregate.json'),value)
            closed=True;close_group(prepared,phase_factory=window.phase)
        finally:
            if prepared is not None and not closed:close_group(prepared,phase_factory=window.phase)
    else:
        import script.core
        import importlib.util
        for leaf in ('closed_memory_boundaries','closed_address_frontiers','closed_word_flow','generic_counter_loops','generic_bound_loops','closed_control','closed_pair_reduction'):
            name='script.core.'+leaf
            spec=importlib.util.spec_from_file_location(name,'/code/script/core/'+leaf+'.py')
            module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
        from script.method_group.group_context import make_context,FOUR_COMPONENTS
        from script.execution.fair_overhead_run import prepared_paths,bind_prepared
        from script.serial_entry.group import evaluate_own_inputs
        declarations={e['component']:e['methods']['sara']['own_input'] for e in group['components']}
        context=make_context({c:r['root'] for c,r in declarations.items()},method='sara')
        with context,ExitStack() as scopes:
            if tuple(declarations)==FOUR_COMPONENTS:
                from script.readonly_records.private_json_identity import _private_json_scope
                from script.verified_inputs.purefreeze_reuse import purefreeze_scope
                witness=scopes.enter_context(_private_json_scope(context,'sara'))
                scopes.enter_context(purefreeze_scope(context,'sara',_proof=witness))
            inputs={};bindings={}
            with window.phase('prepared_own_input_binding'):
                for c,row in declarations.items():
                    args=SimpleNamespace(method='sara',component=c,capture=Path(row['capture']),
                        inputs=Path(row['inputs']['path']),own_input_root=Path(row['root']),
                        capture_metadata_sha256=row['capture_metadata']['sha256'],inputs_sha256=row['inputs']['sha256'])
                    capture,descriptor,_=prepared_paths(args)
                    inputs[c]=descriptor;bindings[c]=bind_prepared(args,capture,descriptor,context)
            evaluated=evaluate_own_inputs(inputs,bindings,phase_factory=window.phase,collect_regions=False)
            with window.phase('required_component_aggregate_persistence'):
                for c,value in evaluated['components'].items():atomic_json(OUT/(c+'-aggregate.json'),value)
            with window.phase('own_identity_and_cleanup'):context.verify_unchanged()
        gc.collect()
    final=dict(status='COMPLETE',method=method,group_id=group['group_id'],budget=budget,
        result=evaluated,scientific_implementation_changed=True,FI_calls=0,extra_point_export=False,
        primary_full_flow_clock='parent monotonic from first container dispatch through second process exit and required persistence',
        analysis_subwindow_only=True,acquisition_excluded_from_this_subwindow_not_from_parent=True)
    window.complete(final)
    saved(OUT/'complete.json',dict(status='complete',stage='consume',method=method,
        group_id=group['group_id'],budget=budget,actual_components=list(evaluated['components'])))

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--stage',choices=('produce','consume','baseline'),required=True)
    ap.add_argument('--request-sha256',required=True);args=ap.parse_args()
    from script.execution.policy import require_container_execution
    from script.execution.method_performance import PerformanceWindow
    profile=require_container_execution()
    need(profile.cpus >= 1 and profile.memory_bytes >= 1024**3,'declared CPU-only resource profile required')
    need(pin('/request.json')['sha256']==args.request_sha256,'fixed method request')
    need(OUT.is_dir() and not list(OUT.iterdir()),'fresh stage output')
    request=read('/request.json');namespace(request)
    window=PerformanceWindow('SARA-rates' if request['method']=='sara' else 'GEREM',OUT,
        component='actual-applicable-group',task=dict(stage=args.stage,group_id=request['group']['group_id'],
            method=request['method'],budget=request['budget'],primary_total_recorded_by_parent=True))
    try:
        {'produce':produce,'consume':consume,'baseline':baseline}[args.stage](request,window)
    except BaseException as error:
        if not window.finished and window.active is None and not window.in_checkpoint:window.save_partial(repr(error))
        saved(OUT/'failed.json',dict(status='failed_preserve_no_retry',error=repr(error)));raise
if __name__=='__main__':main()
