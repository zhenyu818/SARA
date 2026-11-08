"""Parallel input preparation with the accepted generic serial SARA rules.

The exact source-pinned serial core constructor and refinement modules are
shared. Work scheduling and private streaming input representation remain the
previous qualified parallel implementation. No FI/GEREM answers are inputs.
"""
from concurrent.futures import ProcessPoolExecutor
from contextlib import nullcontext
import gzip
import multiprocessing
import os
from pathlib import Path
import time

from .inputs import (need,Decoded,JSONReader,canonical,same_spool,ledger_tail_scope)

_MARKED=None


def _initializer(marked,barrier,worker_dir):
    global _MARKED
    _MARKED=marked
    from script.execution.campaign import atomic_json
    atomic_json(Path(worker_dir)/(str(os.getpid())+'.json'),dict(pid=os.getpid(),
        parent_pid=os.getppid(),cgroup=Path('/proc/self/cgroup').read_text(),
        start_method=multiprocessing.get_start_method(),role='original_event_parser'))
    barrier.wait(timeout=120)


def _warm():
    time.sleep(.02)
    return os.getpid()


def _parse(work):
    from script.core import batch_backward as batch
    from script.core import reg_observed_analyzer as backward
    from script.core.exact_sdc_prepare_input import _mark_output_stores
    start,rows=work
    # Process IPC creates the one mutable input batch. The parent's raw cache
    # and shared-memory rows remain pristine, including all unknown fields.
    rows=batch.normalize_predicate_register_values(rows)
    _mark_output_stores(rows,_MARKED)
    return start,[backward.parse_event(row,start+i) for i,row in enumerate(rows)],os.getpid()


def core_with_rf_authority(base, options, rf_inventory):
    """Forward the already validated own RF identity to the unchanged core.

    No identity guard, numeric rule, generic certificate or projector is
    bypassed. This restores the same input authority used by the completed
    earlier parallel implementation, through the accepted generic core API.
    """
    from script.method_group.sara_group import _run_core
    need(rf_inventory is not None and 'rf_identity_inventory' not in options,
         'one explicit own RF physical-width authority required')
    return _run_core(base, dict(options, rf_identity_inventory=rf_inventory))


class Parser:
    def __init__(self,workers,marked,temporary,chunk=1024):
        need(type(workers) is int and 1<=workers<=8,'one to eight parser workers')
        need(type(chunk) is int and chunk>0,'positive parse batch')
        self.workers,self.chunk=workers,chunk
        self.root=Path(temporary);self.root.mkdir(exist_ok=False)
        self.workerdir=self.root/'workers';self.workerdir.mkdir()
        self.pending=[];self.events=[];self.batch=[];self.start=0
        self.used=set();self.trace_number=0;self.spools=[];self.high_spool_bytes=0
        ctx=multiprocessing.get_context('spawn')
        self.pool=ProcessPoolExecutor(max_workers=workers,mp_context=ctx,
            initializer=_initializer,initargs=(marked,ctx.Barrier(workers),str(self.workerdir)))
        warm=[self.pool.submit(_warm) for _ in range(workers)]
        for item in warm:item.result()
        actual=list(self.workerdir.glob('*.json'))
        need(len(actual)==workers,'all actual parser processes must have initialized')
        self.worker_initial_pids=sorted(int(p.stem) for p in actual)
        self.closed=False

    def begin(self):
        need(not self.pending and not self.batch,'previous parser batches not drained')
        self.events=[];self.start=0

    def accept(self,row,index):
        need(index==self.start+len(self.batch),'global event ordering changed')
        self.batch.append(row)
        if len(self.batch)==self.chunk:self.submit()

    def submit(self):
        if not self.batch:return
        self.pending.append(self.pool.submit(_parse,(self.start,self.batch)))
        self.start+=len(self.batch);self.batch=[]
        if len(self.pending)>=2*self.workers:self.drain_one()

    def drain_one(self):
        start,events,pid=self.pending.pop(0).result()
        need(start==len(self.events) and all(event.index==start+i for i,event in enumerate(events)),
             'ordered complete parser merge failed')
        self.used.add(pid);self.events.extend(events)

    def finish(self):
        self.submit()
        while self.pending:self.drain_one()
        events=self.events;self.events=[]
        return events

    def raw_parse(self,rows):
        self.begin()
        for index,row in enumerate(rows):self.accept(row,index)
        return self.finish()

    def load(self,context,path,component,*,parse_now,limits):
        key=context.key(path)
        existing=context.traces.get(key)
        if existing is not None:
            context.verify_unchanged()
            return existing
        from script.execution.memory_effect_records import MAX_ROW_BYTES
        decoder=Decoded(context,path,limits[0],limits[1],MAX_ROW_BYTES)
        spool=self.root/('numeric-input-%d.jsonl.gz'%self.trace_number);self.trace_number+=1
        raw=[] if component!='rf' else None
        if parse_now:self.begin()
        # Canonical input is a temporary comparison stream, not a scientific
        # output or persisted classified point export. Its cost is included.
        with spool.open('xb') as physical:
            with gzip.GzipFile(filename='',mode='wb',fileobj=physical,compresslevel=1,mtime=0) as stream:
                def accept(row,index):
                    stream.write(canonical(row))
                    if raw is not None:raw.append(row)
                    if parse_now:self.accept(row,index)
                root,count=JSONReader(decoder.chunks()).document(accept)
            physical.flush();os.fsync(physical.fileno())
        need(decoder.result is not None and count>0,'full closed positive event stream required')
        events=self.finish() if parse_now else None
        if events is not None:need(len(events)==count,'event parse cardinality differs')
        root['events']=raw
        value=dict(trace=root,events=events,event_count=count,spool=spool,
            tail=decoder.tail,transport=decoder.result,source=Path(path),component=component)
        context.traces[key]=value;self.spools.append(spool)
        self.high_spool_bytes=max(self.high_spool_bytes,sum(p.stat().st_size for p in self.spools))
        context.count(path,'trace_json_decodes');context.count(path,'json_decodes')
        return value

    def close_workers(self):
        if not self.closed:
            self.pool.shutdown(wait=True);self.closed=True

    def cleanup(self):
        self.close_workers()
        sizes=[dict(name=p.name,bytes=p.stat().st_size) for p in self.spools]
        for p in self.spools:p.unlink()
        return dict(temporary_compressed_comparison_spools=sizes,
            temporary_spool_high_water_bytes=self.high_spool_bytes,
            temporary_spools_removed_after_success=True,worker_receipts_retained=True)


def equivalent(a,b):
    from script.typed_records.typed_identity import equivalent as same
    return same(a,b)


def evaluate(inputs,bindings,context,out,*,workers=8,chunk=1024,phase_factory=None,
             limits=(512*1024**2,1024**3),collect_regions=False):
    from script.verified_inputs import sara_joint as original
    from script.method_group.sara_group import _run_core
    from script.execution.checked_method_inputs import checked_inputs
    from script.execution.method_input_context import read_json
    from script.core import sparse_global_image as image_api
    from script.core import reg_observed_analyzer as backward
    from script.core.rf_identity_guard import validate_input_register_name_noninterference
    phase=phase_factory if phase_factory is not None else lambda _name:nullcontext()
    names=tuple(name for name in ('rf','smem','l1d','l2') if name in inputs)
    need(set(inputs)==set(bindings)==set(names) and 'rf' in names,'actual complete applicable own group')
    need(type(collect_regions) is bool,'qualification region retention flag')
    states={};groups=[];proofs={};options=original._union_options();parser=None
    try:
        # Start spawn workers before retaining large inputs; no inherited large
        # analyzer graph or global reverse state is copied into child workers.
        with phase('parallel_parser_startup'):
            outputs=read_json(Path(inputs['rf']).parent/read_json(inputs['rf'])['files']['output_spec']['path'])
            specs=outputs.get('output_spec',outputs.get('outputs',outputs)) if isinstance(outputs,dict) else outputs
            need(isinstance(specs,list) and bool(specs),'complete output spec')
            marked=[dict(row,base=backward.parse_int(row['base']),size=int(row.get('bytes',row.get('size',0)))) for row in specs]
            parser=Parser(workers,marked,Path(out)/'temporary-inputs',chunk)
        for component in names:
            with phase('prepare_'+component):
                path=Path(inputs[component]).absolute()
                metadata=original._checked_binding(context,path,bindings[component],component)
                descriptor,files,inventory,population=checked_inputs(path)
                need(inventory['spans'][0]['component']==component and population.mass>0,
                     'correct own positive physical domain')
                need(metadata.get('collection')=='sara','own SARA input required')
                for own,declared in (('case','case'),('actual_binary_sha256','binary_sha256'),
                        ('arguments','arguments'),('simulator_libraries','simulator_libraries')):
                    need(equivalent(metadata[own],descriptor[declared]),'own workload mismatch '+own)
                companion=context.read_json(Path(bindings[component]['capture'])/('inputs-'+component+'.json'))
                need(all(descriptor['files'].get(role,{}).get('sha256')==ref['sha256']
                         for role,ref in companion['files'].items()),'own companion roles differ')
                current_outputs=read_json(files['output_spec'])
                same_outputs=equivalent(outputs,current_outputs)
                loaded=parser.load(context,files['trace'],component,parse_now=(component=='rf'),limits=limits)
                trace=dict(loaded['trace'])
                image_present='initial_global_image' in files
                image=read_json(files['initial_global_image']) if image_present else None
                if image_present:trace['initial_global_image']=image
                workload={key:descriptor[key] for key in ('case','binary_sha256','arguments','simulator_libraries')}
                state=dict(descriptor=descriptor,paths=files,inventory=inventory,population=population,
                    trace=trace,metadata=metadata,workload=workload,image=image,image_present=image_present,
                    semantic_image=image_api.semantic_image(image) if image_present else None)
                group=None
                for candidate in groups:
                    base=states[candidate['reference_component']]
                    if (same_outputs and equivalent(workload,base['workload'])
                        and equivalent(trace.get('memory_ranges',[]),base['trace'].get('memory_ranges',[]))
                        and equivalent(dict(present=image_present,value=state['semantic_image']),
                                       dict(present=base['image_present'],value=base['semantic_image']))
                        and loaded['event_count']==len(base['events'])
                        and same_spool(loaded['spool'],base['spool'])):
                        group=candidate;break
                if group is None:
                    events=loaded['events']
                    if events is None:
                        need(trace['events'] is not None,'unreused candidate raw events unavailable')
                        # Distinct output specs must receive their own original
                        # output marking. Spawn pool marked specs are immutable;
                        # refuse unsupported changed-workload grouping here.
                        need(same_outputs,'one authorized workload output contract required')
                        events=parser.raw_parse(trace['events'])
                    group=dict(core_group=len(groups),reference_component=component,components=[])
                    groups.append(group)
                else:events=states[group['reference_component']]['events']
                group['components'].append(component)
                state.update(events=events,spool=loaded['spool'],marked_ranges=marked,
                    memory_ranges=backward.parse_memory_ranges(trace.get('memory_ranges',[])),
                    output_ranges=backward.parse_output_ranges(specs),
                    copy_policy=dict(policy='private_streaming_bounded_process_batches_original_parser45',
                        original_raw_event_rows_modified=False,numeric_parser_reused=component!=group['reference_component'],
                        complete_numeric_input_bytes_compared=True,legacy_Frozen_authority_claimed=False))
                state['image_support']=image_api.validate_golden_image(events,image) if image_present else None
                if component in ('l1d','l2'):
                    with ledger_tail_scope(context):
                        physical,receipt=original._cache_preparation(context,files,metadata)
                    rows,residencies=physical
                    state.update(rows=rows,residencies=residencies,
                        joined=original.batch_cache.join_functional_records(rows,trace['events'],strict_numeric=True),
                        physical_preparation=receipt)
                states[component]=state
                proofs[component]=dict(core_group=group['core_group'],population_mass=population.mass,
                    population_identity=population.identity,descriptor_sha256=context.digest(path),
                    full_event_count=loaded['event_count'],transport=loaded['transport'],
                    original_raw_events_retained=trace['events'] is not None,
                    numeric_input_equivalence='full canonical byte comparison excluding exactly two top-level cache join fields',
                    image_support=state['image_support'])
                context.verify_unchanged()
        with phase('parser_workers_drain'):
            parser.close_workers()
        results={};retained={name:[] for name in names} if collect_regions else None
        for group in groups:
            base=states[group['reference_component']]
            with phase('core_%d'%group['core_group']):
                # Same compiled workload and complete own-input matching above
                # establish RF width authority; the unchanged guard checks all
                # UID/name/physical-width and chronological transitions itself.
                need(equivalent(states['rf']['workload'],base['workload']),
                     'RF physical-width authority requires identical compiled workload')
                name_proof=validate_input_register_name_noninterference(base['events'],
                    rf_inventory=states['rf']['inventory'])
                core,loop_effects,loop_support,closed_support=core_with_rf_authority(base,options,states['rf']['inventory'])
                need(all(key in core for key in ('read_events','smem_fault_sites','l1d_fault_sites','exact_meta')),
                     'complete original union core required')
                group['register_identity_support']=name_proof
            for component in group['components']:
                with phase('project_'+component):
                    state=states[component]
                    analysis=original._component_analysis(core,state,component,closed_support,loop_effects,loop_support)
                    if component=='rf':
                        regions=original.batch.rf_regions(state['inventory'],base['events'],analysis['read_events'],
                            analysis['loop_effects'],analysis['deductive_loop_support'])
                    elif component=='smem':
                        regions=original.smem_regions(state['inventory'],base['events'],analysis,state['trace']['events'])
                        from script.core.closed_pair_reduction import build as build_reduction, project as refine_reduction
                        certificates,reduction_support=build_reduction(base['events'],state['trace']['events'],state['image'])
                        regions=refine_reduction(regions,certificates,reduction_support)
                        from script.core.closed_word_flow import ClosedFlow
                        from script.core.closed_memory_boundaries import read_boundaries
                        boundaries,boundary_support=read_boundaries(bindings[component]['capture'],state['image'],
                            len(base['events']),state['metadata']['native_source_fingerprint'])
                        word_flow=ClosedFlow(base['events'],state['trace']['events'],host_boundaries=boundaries,initial_image=state['image'])
                        regions=word_flow.project(regions)
                        reduction_support['correlated_word_flow']=word_flow.stats
                        reduction_support['memory_boundaries']=boundary_support
                        analysis['closed_reduction_support']=reduction_support
                        analysis['smem_projection']=dict(persistent_object_epoch_checked=True,
                            per_draw_full_path_replay=False,bounded_word_counterfactual=True,
                            refinement='closed-lexicographic-shared-tournament-v1',support=reduction_support)
                    else:regions=original._cache_regions(state,analysis)
                    sink=original.batch.RatesSink(retain_classification_digest=False)
                    for region in regions:
                        sink.consume(region)
                        if retained is not None:retained[component].append(region)
                    results[component]=original._summary(state,analysis,sink)
            del core,loop_effects
        with phase('temporary_cleanup'):
            cleanup=parser.cleanup()
            states.clear();context.verify_unchanged()
        value=dict(components=results,actual_core_groups=groups,execution_evidence=dict(
            version='sara-llm-parallel-generic-v1',scientific_rules='sara-serial-generic-correction-v1',
            numerical_reverse_owner_count=1,parser_worker_count=workers,
            initialized_parser_pids=parser.worker_initial_pids,actual_parse_pids=sorted(parser.used),
            bounded_inflight_batches=2*workers,parse_batch_events=chunk,
            inputs=proofs,temporary=cleanup,FI_answers_used=False,
            numerical_or_projection_algorithms_changed=False,whole_event_order_preserved=True,
            optional_point_export_in_method=False,not_GEREM_comparison=True))
        if retained is not None:value['qualification_regions']=retained
        return value
    except BaseException:
        if parser is not None:parser.close_workers()
        # No partial spool/source/result cleanup on failure.
        raise
