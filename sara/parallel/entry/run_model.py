"""Necessary real consistency qualification or one full reused-input LLM run."""
import argparse
import ast
from contextlib import ExitStack,contextmanager
import gc
import hashlib
import io
import json
import multiprocessing
import os
from pathlib import Path
import re
import sys
import time
import zlib

sys.dont_write_bytecode=True
sys.path[:0]=['/admin','/code','/code/script/common','/code/script/core']


def need(v,m):
    if not v:raise ValueError(m)


def save(p,v):
    from script.execution.campaign import atomic_json
    need(not Path(p).exists(),'fresh result only')
    atomic_json(Path(p),v)


def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()


@contextmanager
def timed_context(context,window):
    context.__enter__()
    try:yield context
    except BaseException:
        with window.phase('input_context_cleanup'):context.__exit__(*sys.exc_info())
        raise
    else:
        with window.phase('input_context_cleanup'):context.__exit__(None,None,None)


def declarations(request,context):
    from types import SimpleNamespace
    from script.execution.fair_overhead_run import prepared_paths,bind_prepared
    inputs={};bindings={}
    for name,row in request.items():
        args=SimpleNamespace(method='sara',component=name,capture=Path(row['capture']),
            inputs=Path(row['inputs']['path']),own_input_root=Path(row['root']),
            capture_metadata_sha256=row['capture_metadata']['sha256'],inputs_sha256=row['inputs']['sha256'])
        capture,path,_root=prepared_paths(args)
        inputs[name]=path;bindings[name]=bind_prepared(args,capture,path,context)
    return inputs,bindings


SCIENCE=('model','support_policy','support_fingerprint','population_mass','counts','rates',
         'population_fingerprint','component','dynamic_events','unknown_identification_bounds',
         'region_count','classification_digest','classification_digest_policy',
         'sampling_confidence_interval','uncertainty_note','population_identity_kind',
         'classification_uses_FI_answers','sampled_draws')


def region_row(r):
    return dict(component=r.component,target=r.target,start=r.start,stop=r.stop,
        bit_start=r.bit_start,width=r.width,classes=r.classes,unknown_reason=r.unknown_reason)


MEASURED_SUPPORT_KEYS={'analysis_seconds','construction_seconds','projection_work_seconds','projection_seconds'}
def support_science(value,path='',times=None):
    if times is None:times={}
    if isinstance(value,dict):
        result={}
        for key,item in value.items():
            target=path+'/'+str(key)
            if key in MEASURED_SUPPORT_KEYS:
                need(isinstance(item,(int,float)) and item>=0,'actual nonnegative support clock')
                times[target]=item
            else:result[key]=support_science(item,target,times)
        return result
    if isinstance(value,list):return [support_science(item,path+'/'+str(i),times) for i,item in enumerate(value)]
    return value


def check_results(reference,candidate):
    need(set(reference['components'])==set(candidate['components']),'component membership differs')
    checks={}
    for name,left in reference['components'].items():
        right=candidate['components'][name]
        for key in SCIENCE:
            need(key in left and key in right and left[key]==right[key], 'science differs '+name+'/'+key)
        a=reference['qualification_regions'][name];b=candidate['qualification_regions'][name]
        need(len(a)==len(b),'complete ordered region cardinality differs')
        h=hashlib.sha256()
        for x,y in zip(a,b):
            rx,ry=region_row(x),region_row(y)
            need(rx==ry,'full ordered masks/Unknown/identity differ')
            h.update(json.dumps(rx,sort_keys=True,separators=(',',':')).encode()+b'\n')
        # Only implementation presentation fields are excluded here; all
        # classification/support-dependent summaries are otherwise compared.
        measured_support_times={}
        timing_fields={'closed_local_support':('analysis_seconds',),
                       'deductive_loop_support':('construction_seconds','projection_work_seconds')}
        for key in ('closed_local_support','deductive_loop_support','uncertainty_diagnostics','component_support'):
            x,y=left.get(key),right.get(key)
            fields=timing_fields.get(key,())
            if key=='component_support' and isinstance(x,dict) and isinstance(y,dict):
                tx,ty=x.get('tag_support'),y.get('tag_support')
                if isinstance(tx,dict) and isinstance(ty,dict):
                    measured_support_times['component_support.tag_support.analysis_seconds']=dict(
                        serial=tx.get('analysis_seconds'),parallel=ty.get('analysis_seconds'))
                    x=dict(x,tag_support={k:v for k,v in tx.items() if k!='analysis_seconds'})
                    y=dict(y,tag_support={k:v for k,v in ty.items() if k!='analysis_seconds'})
            if isinstance(x,dict) and isinstance(y,dict):
                measured_support_times[key]=dict(serial={f:x[f] for f in fields if f in x},
                    parallel={f:y[f] for f in fields if f in y})
                x={k:v for k,v in x.items() if k not in fields}
                y={k:v for k,v in y.items() if k not in fields}
            extra_x,extra_y={},{}
            x=support_science(x,key,extra_x);y=support_science(y,key,extra_y)
            measured_support_times[key+'/nested']=dict(serial=extra_x,parallel=extra_y)
            if x!=y:
                raise ValueError('scientific support differs '+name+'/'+key+': '+
                    json.dumps(dict(serial=x,parallel=y),sort_keys=True))
        checks[name]=dict(regions=len(a),ordered_complete_region_sha256=h.hexdigest(),
            all_region_fields_equal=True,full_summary_scientific_fields_equal=True,
            population_mass=left['population_mass'],separately_measured_support_times=measured_support_times,
            excluded_from_equality_only_explicit_measured_time_fields=timing_fields)
    return checks


def serial_group(rows,out):
    from script.method_group.group_context import make_context,FOUR_COMPONENTS
    from script.method_group.sara_group import evaluate_own_inputs
    out.mkdir()
    context=make_context({k:v['root'] for k,v in rows.items()},method='sara')
    started=time.perf_counter()
    with context,ExitStack() as scopes:
        if tuple(rows)==FOUR_COMPONENTS:
            from script.readonly_records.private_json_identity import _private_json_scope
            from script.verified_inputs.purefreeze_reuse import purefreeze_scope
            witness=scopes.enter_context(_private_json_scope(context,'sara'))
            scopes.enter_context(purefreeze_scope(context,'sara',_proof=witness))
        inputs,bindings=declarations(rows,context)
        result=evaluate_own_inputs(inputs,bindings,collect_regions=True)
        context.verify_unchanged()
    return result,time.perf_counter()-started


def parallel_group(rows,out,workers):
    from script.parallel_stream.inputs import InputContext
    from script.parallel_stream.group import evaluate
    out.mkdir()
    started=time.perf_counter()
    with InputContext({k:v['root'] for k,v in rows.items()}) as context:
        inputs,bindings=declarations(rows,context)
        result=evaluate(inputs,bindings,context,out,workers=workers,chunk=127,collect_regions=True)
    return result,time.perf_counter()-started


def tiny_inventory():
    from script.execution.population_inventory import read_stream,validate_lifecycle,validate_production_blockers,COMPACT_SCHEMA
    from script.execution.compact_population import SCHEMA,RF_MODEL,semantic_population,core_inventory
    stream=read_stream(Path('/tiny-native/population.jsonl'),codec='plain')
    need(stream['header']['schema']==COMPACT_SCHEMA and stream['header']['component_filter']=='rf','actual complete RF fixture')
    validate_production_blockers(stream['blockers']);spans=[]
    for row in stream['spans']:
        validate_lifecycle(row,stream['header']);need(row['component']=='rf' and row['mapping_supported'] is True,'full native population')
        spans.append({key:value for key,value in row.items() if key!='kind'})
    inv=dict(schema=SCHEMA,schema_version=2,fault_model=RF_MODEL,coordinate_system='simulator_hook_allocated_storage',
        time_basis='simulator_global_cycle',collection_header=stream['header'],collection_window=stream['footer'],
        population_transport=stream['transport'],spans=spans)
    domain=semantic_population(inv);need(domain.mass==stream['mass']['rf'],'tiny population mass')
    return core_inventory(inv),domain


def tiny(out):
    from script.execution.trace_transport import read_trace_document
    from script.core import batch_backward as batch
    from script.core import reg_observed_analyzer as reg
    from script.parallel_stream.inputs import InputContext
    from script.parallel_stream.group import Parser
    from script.typed_records.typed_identity import equivalent
    from ptx_shuffle_down import ShuffleEvent
    from script.core.exact_sdc_prepare_input import _mark_output_stores
    path=Path('/tiny-native/trace.json.gz')
    inv,domain=tiny_inventory()
    log=Path('/tiny-native/run.log').read_text()
    matches=re.findall(r'GPUFI_OUTPUT base=(0x[0-9a-fA-F]+) bytes=(\d+) name=(\S+)',log)
    need(len(matches)==1 and matches[0][1:]==('16','logits'),'all four tiny output roots')
    specs=[dict(space='global',base=int(matches[0][0],16),bytes=16,name='logits')]
    document,_transport=read_trace_document(path)
    raw=batch._legacy_event_deepcopy(document['events'])
    batch.normalize_predicate_register_values(raw);_mark_output_stores(raw,[dict(row,size=row['bytes']) for row in specs])
    expected=[reg.parse_event(row,i) for i,row in enumerate(raw)]
    need(len(expected)==47765,'complete actual tiny stream')
    del raw
    def result(events):
        from script.core.closed_loop_transfer import construct
        from script.core.closed_fma_transfer import closed_input_effects
        ranges=reg.parse_output_ranges(specs)
        loop,support=construct(events,None)
        effects,_closed=closed_input_effects(events,ranges,include_proof_pairs=False)
        analysis=reg.analyze(events,memory_ranges=reg.parse_memory_ranges(document.get('memory_ranges',[])),
            output_ranges=ranges,lite_output=True,lite_output_profile='compat',mask_format='int',
            assume_sorted_events=True,fault_component='rf',emit_cache_sites=True,output_component=None,
            aggregate_only=False,control_outcome_policy='submitted_local_sdc',initial_global_image=None,
            proved_input_effects=effects,rf_identity_inventory=inv,consumed_output_policy='serial-joint-aggregate-consumers-v1')
        sink=batch.RatesSink(retain_classification_digest=False);h=hashlib.sha256();n=0
        for region in batch.rf_regions(inv,events,analysis['read_events'],loop,support):
            sink.consume(region);n+=1;h.update(json.dumps(region_row(region),sort_keys=True,separators=(',',':')).encode()+b'\n')
        return dict(summary=sink.summary(domain.mass),regions=n,ordered_sha256=h.hexdigest(),
            name_identity=analysis['exact_meta']['input_register_identity_support'])
    base=result(expected);proof=[]
    for workers in (1,8):
        with InputContext({'rf':Path('/tiny-native')}) as context:
            parser=Parser(workers,[dict(row,size=row['bytes']) for row in specs],out/('tiny-parser-%d'%workers),chunk=17)
            try:
                loaded=parser.load(context,path,'rf',parse_now=True,limits=(512*1024**2,1024**3))
                events=loaded['events'];need(len(events)==len(expected),'complete parser cardinality')
                types=(reg.TraceEvent,reg.PredInfo,reg.EAExpr,reg.MemoryRange,reg.OutputRangeSpec,ShuffleEvent)
                need(equivalent(expected,events,object_types=types),'all parsed slots/types/native shuffle/UID fields differ')
                observed=result(events);need(observed==base,'tiny complete scientific results differ')
                parser.close_workers()
                need(len(parser.used)==workers,'actual multiple parser workers must process events')
                proof.append(dict(workers=workers,actual_pids=sorted(parser.used),events=len(events),
                    complete_slots_equal=True,complete_RF_result_equal=True,ordered_sha256=base['ordered_sha256'],
                    UID_switches=base['name_identity']['UID_full_write_switches'],
                    predicated_off_identity_observations=base['name_identity']['predicated_off_destination_identity_observations'],
                    chunk=17,cross_chunk_shuffle_preserved=True,temporary=parser.cleanup()))
            except BaseException:parser.close_workers();raise
        del events,loaded;gc.collect()
    return proof


def format_tests(out):
    from script.parallel_stream.inputs import JSONReader
    good=b'{"memory_ranges":[],"events":[{"kind":"inst","s":"\\u4e2d","x":-0.0},{"n":2}],"end":true}'
    accepted=[]
    for step in (1,7,128):
        rows=[];root,count=JSONReader(good[i:i+step] for i in range(0,len(good),step)).document(lambda row,index:rows.append(row))
        need(count==2 and root['end'] is True and rows[0]['s']=='\u4e2d' and str(rows[0]['x'])=='-0.0','chunk boundary JSON fidelity')
        accepted.append(step)
    bad=(b'{"events":[],"events":[]}',b'{"events":[{"x":1,"x":2}]}',b'{"events":[NaN]}',
         b'{"events":[{}]',b'{"events":[]} trailing',b'{"events":[{}],}',b'{"events":[1]}')
    for payload in bad:
        try:JSONReader([payload]).document(lambda _r,_i:None)
        except (ValueError,json.JSONDecodeError,UnicodeError):pass
        else:raise ValueError('malformed complete transport accepted')
    return dict(actual_decoder_good_chunk_sizes=accepted,actual_decoder_refusals=len(bad),mock_scientific_results_used=False)


def allocation_worker(barrier,release):
    payload=bytearray(128*1024**2)
    for i in range(0,len(payload),4096):payload[i]=127
    barrier.wait(timeout=120);release.wait(timeout=120)
    del payload;gc.collect()


def memory_calibration(out):
    ctx=multiprocessing.get_context('spawn');barrier=ctx.Barrier(3);release=ctx.Event()
    processes=[ctx.Process(target=allocation_worker,args=(barrier,release)) for _ in range(2)]
    for p in processes:p.start()
    barrier.wait(timeout=120)
    current=int(Path('/sys/fs/cgroup/memory.current').read_text());peak=int(Path('/sys/fs/cgroup/memory.peak').read_text())
    need(current>=256*1024**2 and peak>=current,'inclusive two-worker kernel accounting')
    release.set()
    for p in processes:p.join(120);need(p.exitcode==0,'allocator child ended')
    after=int(Path('/sys/fs/cgroup/memory.peak').read_text())
    need(after>=peak,'peak must survive child memory release')
    return dict(two_real_worker_pids=[p.pid for p in processes],allocated_bytes_each=128*1024**2,
        inclusive_memory_current_bytes=current,inclusive_memory_peak_bytes=peak,peak_after_release_bytes=after,
        whole_cgroup_counter=True,RSS_summed=False,scientific_model_calls=0)


def qualification(request,out):
    need(request['operation']=='qualification','explicit qualification')
    result=dict(status='running',operation='real_complete_equivalence',full_LLM_run=False)
    result['memory_calibration']=memory_calibration(out)
    save(out/'memory-calibration.json',result['memory_calibration'])
    evidence={}
    for name,ref in request['semantic_evidence'].items():
        raw=Path(ref['read_path']).read_bytes()
        need(len(raw)==ref['bytes'] and hashlib.sha256(raw).hexdigest()==ref['sha256'],'bound actual native serial evidence')
        evidence[name]=dict(reference=ref,document=json.loads(raw))
    need(evidence['native_qualification']['document'].get('qualification')=='PASS'
         and evidence['native_qualification']['document'].get('tested_actual_PTX_outputs') is True,
         'actual independent PTX oracle qualification must already have passed')
    result['preserved_native_semantic_evidence']=evidence
    result['format_tests']=format_tests(out)
    from qualify_rf_authority import verify
    rf_prior=request['semantic_evidence']['prior_RF_authority']
    rf_actual=json.loads(Path(rf_prior['read_path']).read_bytes())
    need(rf_actual['status']=='PASS' and rf_actual['events']==47765,
         'same-source completed RF authority regression reused')
    result['RF_authority_regression']=dict(status='PASS',reused_actual_receipt=rf_prior,
        source_and_RF_rules_identical=True,full_checks=rf_actual)
    from qualify_operand_admission import verify as verify_operands
    result['operand_admission_regression']=verify_operands(out,request)
    completed=[]
    for group in request['groups']:
        rows=group['group_declarations'];name=group['name']
        print(json.dumps(dict(stage='qualification_serial_reference',group=name)),flush=True)
        from script.core import closed_word_flow as operand_module
        from qualify_operand_admission import baseline as operand_baseline
        fixed_evaluator=operand_module.evaluate
        operand_module.evaluate=operand_baseline().evaluate
        try:
            reference,serial_seconds=serial_group(rows,out/(name+'-serial'))
        finally:
            operand_module.evaluate=fixed_evaluator
        candidate,seconds=parallel_group(rows,out/(name+'-parallel'),8)
        check=check_results(reference,candidate)
        actual=candidate['execution_evidence']
        need(len(actual['initialized_parser_pids'])==8 and len(actual['actual_parse_pids'])==8,
             'all eight actual workers must have parsed real events')
        row=dict(group=name,serial_seconds=serial_seconds,parallel_seconds=seconds,
            checks=check,execution_evidence=actual)
        save(out/(name+'-equivalence.json'),row);completed.append(row)
        del reference,candidate;gc.collect()
        print(json.dumps(dict(stage='qualification_group_complete',group=name)),flush=True)
    result.update(status='PASS',complete=True,groups=completed,FI_calls=0,GEREM_calls=0,capture_calls=0,
        same_accepted_serial_rules=True,full_LLM_analysis_admitted_after_parent_terminal_only=True)
    save(out/'qualification-complete.json',result)

def llm(request,out):
    from script.parallel_stream.inputs import InputContext
    from script.parallel_stream.group import evaluate
    from script.execution.method_performance import PerformanceWindow
    from script.execution import stories_static_global_inputs_v1 as static
    from script.execution.stories260k_prefix1_workload import Registration
    # The already prepared actual own descriptors/closures and 512-output proof
    # are external request inputs, never regenerated or numerically replayed.
    proof=request['qualification'];need(digest(proof['read_path'])==proof['sha256'],'actual parallel qualification proof')
    q=json.loads(Path(proof['read_path']).read_bytes());need(q['status']=='PASS' and q['complete'] is True,'real preceding consistency required')
    rows=request['group_declarations'];need(tuple(rows)==('rf','smem','l1d','l2'),'all four actual LLM domains')
    golden=request['golden'];need(digest(golden['read_path'])==golden['sha256'],'actual full512 normal proof')
    g=json.loads(Path(golden['read_path']).read_bytes());need(g['complete'] is True and g['all_logits_compared']==512 and g['failed_logits']==0,'complete512 normal qualification')
    checkpoint=request['checkpoint']
    need(digest(checkpoint['read_path'])==checkpoint['sha256'],'unchanged existing model checkpoint')
    registration=Registration(Path(checkpoint['read_path']),[1])
    window=PerformanceWindow('SARA-rates',out,component='all-actual-applicable',task=dict(
        version='sara-llm-parallel-generic-v1',scientific_source='accepted-serial-generic-with-parallel-operand-admission' ,workload='Stories260K',
        layers=5,batch=1,tokens=[1],position=0,architecture='SM75',outputs=512,
        FI_calls=0,GEREM_calls=0,capture_calls=0,compile_calls=0,not_GEREM_comparison=True,
        main_scope='complete existing-input method container; inner phases separately',full_serial_duplicate=False))
    with static.installed(),registration.installed():
        context=InputContext({k:v['root'] for k,v in rows.items()})
        with timed_context(context,window),ExitStack() as scopes:
            policies=[]
            with window.phase('actual_closed_own_input_bindings'):
                for component,row in rows.items():
                    closure=context.read_json(Path(row['capture'])/'capture-closure.json')
                    need(context.digest(Path(row['capture'])/'capture-closure.json')==row['closure_sha256']
                        and closure['complete'] is True and closure['workload']==registration.descriptor()
                        and closure['checkpoint_sha256']==g['checkpoint_sha256']
                        and closure['golden']['sha256']==golden['sha256'],'actual frozen complete capture closure')
                    policies.append(scopes.enter_context(registration.input_resources(context,row['root'],component)))
                inputs,bindings=declarations(rows,context)
            evaluated=evaluate(inputs,bindings,context,out,workers=8,chunk=1024,
                phase_factory=window.phase,limits=(16*1024**3,128*1024**3),collect_regions=False)
            with window.phase('component_persistence_and_input_receipt'):
                for name,value in evaluated['components'].items():save(out/(name+'-aggregate.json'),value)
                context.verify_unchanged();reuse=context.summary()
    measurement=window.finish(evaluated)
    save(out/'input-reuse.json',reuse)
    save(out/'complete.json',dict(status='complete',whole_all_applicable_components=True,
        method='independent_LLM_parallel_generic',actual_components=list(evaluated['components']),
        actual_core_groups=evaluated['actual_core_groups'],measurement=measurement,
        original_capture_forward_compile_reexecutions=0,FI_calls=0,GEREM_calls=0,
        original_full512_golden=golden,original_partial_serial_timing_used_as_speedup=False,
        numeric_algorithms_and_projection_rules='sara-serial-generic-correction-v1',own_input_resource_adapters=policies))


def main():
    p=argparse.ArgumentParser();p.add_argument('--request',type=Path,required=True);p.add_argument('--request-sha256',required=True)
    p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    from script.execution.policy import require_container_execution
    profile=require_container_execution();need((profile.role,profile.cpus,profile.memory_bytes)==('bounded_primary',64,448*1024**3),'B64/448 runc only')
    need(digest(args.request)==args.request_sha256,'exact source-bound request')
    request=json.loads(args.request.read_bytes());out=args.output
    need(out==out.resolve(strict=True) and out.is_dir() and not tuple(out.iterdir()),'fresh method output')
    need(request['operation'] in ('qualification','LLM'),'finite supported operation')
    try:
        if request['operation']=='qualification':qualification(request,out)
        else:llm(request,out)
    except BaseException as error:
        save(out/'failed.json',dict(status='failed_preserve_no_automatic_retry',operation=request['operation'],
            error=type(error).__name__,message=str(error),partial_outputs_not_complete=True))
        raise


if __name__=='__main__':main()
