"""Bounded shared-word correlated propagation through closed integer dataflow.

One physical word perturbation is applied jointly to every remaining read of
that version. Only closed equality at actual observations certifies Masked.
Control changes and unproved memory effects remain frontiers. Budget exhaustion
retains the old classification. No sample or reference answers enter this module.
"""
from collections import defaultdict
from dataclasses import replace
import bisect
import heapq
import time
from script.core.closed_address_frontiers import uses_global_backing

WORD=0xffffffff
LONG=(1<<64)-1
def signed(v):return v-(1<<32) if v&(1<<31) else v
def complete_word_load(e):
    if e.mem_access_size_bytes!=4:return False
    if e.dst_write_mask==WORD:return True
    # PTX permits a u32 load into a wider register: the upper bits are zero.
    # Admit only an actual full-register write with the expected golden value.
    return (e.dst_write_mask==LONG and e.opcode in ('ld.global.u32','ld.shared.u32')
        and e.dst_val is not None and 0<=int(e.dst_val)<=WORD)
def result_mask(op):
    if op.startswith('setp.') or op.endswith('.pred'):return 1
    if op in ('cvt.u32.u64','cvt.s32.u64','cvt.u32.s64','cvt.s32.s64'):return WORD
    if op in ('cvt.u64.u32','cvt.s64.s32','mul.wide.u32','mul.wide.s32') or op.endswith(('.b64','.u64','.s64')):return LONG
    return WORD
def evaluate(op,args):
    if op in ('or.pred','and.pred','xor.pred') and len(args)==2:
        a,b=map(bool,args);return int((a or b) if op=='or.pred' else (a and b) if op=='and.pred' else a!=b)
    if op=='not.pred' and len(args)==1:return int(not args[0])
    if op=='cvt.u64.u32':return args[0]&WORD
    if op=='cvt.s64.s32':return signed(args[0]&WORD)&LONG
    # Non-saturating integer narrowing preserves the low destination bits.
    # Source signedness does not alter this truncation, unlike widening.
    if op in ('cvt.u32.u64','cvt.s32.u64','cvt.u32.s64','cvt.s32.s64'):return args[0]&WORD
    if op=='mul.wide.u32':return ((args[0]&WORD)*(args[1]&WORD))&LONG
    if op=='mul.wide.s32':return (signed(args[0]&WORD)*signed(args[1]&WORD))&LONG
    if op in ('mov.b64','mov.u64','mov.s64'):return args[0]&LONG
    if op in ('add.s64','add.u64'):return sum(args)&LONG
    if op in ('sub.s64','sub.u64'):return (args[0]-args[1])&LONG
    if op=='shl.b64':return (args[0]<<args[1])&LONG if 0<=args[1]<64 else 0
    if op.startswith('setp.') and len(args)==2 and op.endswith(('.s32','.u32','.s64','.u64')):
        width=64 if op.endswith('64') else 32
        a,b=[v&((1<<width)-1) for v in args]
        if op.endswith(('.s32','.s64')):
            a=a-(1<<width) if a&(1<<(width-1)) else a
            b=b-(1<<width) if b&(1<<(width-1)) else b
        value={'eq':a==b,'ne':a!=b,'lt':a<b,'le':a<=b,'gt':a>b,'ge':a>=b}.get(op.split('.')[1])
        return None if value is None else int(value)
    if op in ('selp.b32','selp.u32','selp.s32') and len(args)==3:
        return args[0] if args[2] else args[1]
    if op in ('mov.b32','mov.u32','mov.s32','copy'):return args[0]&WORD
    if op in ('add.s32','add.u32'):return sum(args)&WORD
    if op in ('sub.s32','sub.u32'):return (args[0]-args[1])&WORD
    if op=='min.s32':return min(map(signed,args))&WORD
    if op=='max.s32':return max(map(signed,args))&WORD
    if op=='min.u32':return min(args)
    if op=='max.u32':return max(args)
    if op=='and.b32':return args[0]&args[1]
    if op=='or.b32':return args[0]|args[1]
    if op=='xor.b32':return args[0]^args[1]
    if op=='not.b32':return (~args[0])&WORD
    return None

class ClosedFlow:
    def __init__(self,events,raw_events,limit=192,host_boundaries=None,initial_image=None):
        t=time.perf_counter()
        self.nodes=[];self.uses=[];self.versions=defaultdict(list);self.cache={};self.limit=limit
        self.pure_expressions={};self.read_expressions={}
        self.stats=dict(policy='bounded-correlated-shared-word-dataflow-v1',FI_answers_used=False,
            application_specific_dispatch=False,per_draw_replay=False,max_changed_nodes=limit,
            queries=0,cache_hits=0,certified_bits=0,budget_refusals=0,frontier_refusals=0,
            equivalent_pure_nodes_reused=0,equivalent_read_nodes_reused=0,global_value_aliases=0)
        regs={};memory={};active={};all_versions=[];partial=set();opaque_uids=set()
        global_memory={};boundary_index=0
        boundaries=host_boundaries or []
        global_closed=host_boundaries is not None and not any(
            e.opcode.startswith(('atom.','red.','sust.','suld.')) or
            (uses_global_backing(e) and e.kind not in ('load','store')) for e in events)
        self.stats['actual_host_boundary_global_flow']=global_closed
        self.address_model=None;self.access={}
        if global_closed and initial_image is not None:
            from script.core.closed_address_frontiers import AddressFrontiers
            self.address_model=AddressFrontiers(events,initial_image,boundaries)
        self.stats['native_closed_address_cases']=self.address_model is not None
        def global_boundary(row):
            self.read_expressions.clear()
            kind=row['kind'];count=row['count']
            if kind in ('d2h','symbol_from','d2d','allocation_frontier'):
                lo=row['source'];hi=lo+count
                self.sink([(n,self.nodes[n][1]) for address,n in global_memory.items() if lo<address+4 and address<hi])
            if kind in ('h2d','symbol_to','memset','d2d','allocation_frontier'):
                lo=row['destination'];hi=lo+count
                for address,n in list(global_memory.items()):
                    if lo<address+4 and address<hi:
                        if not (lo<=address and address+4<=hi):self.sink([(n,self.nodes[n][1])])
                        del global_memory[address]
        for e,r in zip(events,raw_events):
            if e.mem_space=='shared' and e.kind in ('load','store') and (e.pred is None or e.pred.val):
                uid=r.get('shared_storage',{}).get('object_uid');n=e.mem_access_size_bytes if e.kind=='load' else e.store_size_bytes
                if uid is None or n!=4 or e.mem_addr%4:
                    partial.add(e.kernel_uid)
                    if uid is not None:opaque_uids.add(uid)
        for e,r in zip(events,raw_events):
            if global_closed:
                while boundary_index<len(boundaries) and boundaries[boundary_index]['cursor']<=e.index:
                    global_boundary(boundaries[boundary_index]);boundary_index+=1
            keybase=(e.kernel_uid,e.thread_id)
            def source(i):
                width=e.src_width_bits[i] if i<len(e.src_width_bits) else 32
                v=int(e.src_vals[i])&((1<<width)-1 if width in (1,8,16,32,64) else WORD)
                uid=e.src_reg_uids[i] if i<len(e.src_reg_uids) else None
                node=regs.get(keybase+(uid,)) if uid is not None else None
                if node is not None and self.nodes[node][1]!=v:
                    self.add('sink',0,[(node,self.nodes[node][1])]);node=None
                return node,v
            args=[source(i) for i in range(len(e.src_vals))]
            if e.pred is not None:
                p=regs.get(keybase+(e.pred.uid,))
                if p is not None:self.add('sink',0,[(p,self.nodes[p][1])])
                if not e.pred.val:continue
            dst=None
            if e.kind=='load':
                address_proof=(self.address_model.admit(e) if self.address_model and uses_global_backing(e)
                    and complete_word_load(e) else None)
                if address_proof is None:self.sink(args)
                value=int(e.dst_val)&WORD
                if e.mem_space=='shared' and e.kernel_uid not in partial and r.get('shared_storage',{}).get('object_uid') not in opaque_uids:
                    uid=r['shared_storage']['object_uid'];mk=(uid,e.mem_addr)
                    vk=(e.kernel_uid,e.sm_id,e.cta_id,e.mem_addr)
                    version=active.get(mk)
                    if version is None or version['key']!=vk:
                        if version is not None:version['unmodeled_persistent_owner_read']=True
                        version=dict(key=vk,uid=uid,start=e.cycle,reads=[],value=value)
                        active[mk]=version;all_versions.append(version)
                    parent=memory.get(mk)
                    if parent is not None and self.nodes[parent][1]!=value:
                        self.sink([(parent,self.nodes[parent][1])]);parent=None
                    dst=self.add('copy',value,[(parent,value)])
                    version['reads'].append((e.cycle,dst))
                elif global_closed and uses_global_backing(e):
                    if complete_word_load(e) and e.mem_addr%4==0:
                        parent=global_memory.get(e.mem_addr)
                        if parent is not None and self.nodes[parent][1]!=value:
                            self.sink([(parent,self.nodes[parent][1])]);parent=None
                        if address_proof is not None and any(p is not None for p,v in args):
                            a=address_proof
                            # Reuse only an identical read relation with the
                            # same parents and no intervening global write or
                            # host-memory boundary. Do not merge physical
                            # shared-memory origins or memory side effects.
                            relation=(e.opcode,e.dst_write_mask,e.mem_addr,e.mem_access_size_bytes,
                                e.ea_const_offset,a.expr.op,tuple(a.expr.src_indices),a.expr.width_bits,
                                a.effective_mask,a.src_width_bits,tuple(args),parent,value)
                            dst=self.read_expressions.get(relation)
                            if dst is None:
                                dst=self.add('address_load',value,args+[(parent,value)])
                                self.access[dst]=(e,address_proof);self.read_expressions[relation]=dst
                            else:self.stats['equivalent_read_nodes_reused']+=1
                        else:
                            # A full-word read of this exact memory version is
                            # the same value. Shared loads stay distinct: they
                            # are physical fault origins with separate times.
                            dst=parent
                            self.stats['global_value_aliases']+=parent is not None
                    else:
                        self.sink([(n,self.nodes[n][1]) for address,n in global_memory.items()
                            if e.mem_addr<address+4 and address<e.mem_addr+e.mem_access_size_bytes])
                else:dst=None
            elif e.kind=='store':
                if uses_global_backing(e):self.read_expressions.clear()
                i=e.store_data_src_index
                if i>=len(args):self.sink(args);continue
                address_proof=(self.address_model.admit(e) if self.address_model and uses_global_backing(e)
                    and 0<e.store_size_bytes<=8 and self.address_model.dead_original(e,e.store_size_bytes) else None)
                if address_proof is not None and any(p is not None for p,v in args):
                    node=self.add('address_store',0,args);self.access[node]=(e,address_proof)
                    # No clean future reader exists. This store's mutated
                    # destination is checked separately for every certificate.
                    continue
                self.sink([a for j,a in enumerate(args) if j!=i])
                if e.mem_space=='shared' and e.kernel_uid not in partial and r.get('shared_storage',{}).get('object_uid') not in opaque_uids:
                    uid=r['shared_storage']['object_uid'];mk=(uid,e.mem_addr)
                    dstnode=self.add('copy',args[i][1],[args[i]]) if args[i][0] is not None else None
                    memory[mk]=dstnode
                    version=dict(key=(e.kernel_uid,e.sm_id,e.cta_id,e.mem_addr),uid=uid,
                        start=e.cycle,reads=[],value=args[i][1])
                    active[mk]=version;all_versions.append(version)
                elif global_closed and uses_global_backing(e):
                    lo=e.mem_addr;hi=lo+e.store_size_bytes
                    if e.store_size_bytes==4 and lo%4==0:
                        if args[i][0] is None:global_memory.pop(lo,None)
                        else:
                            global_memory[lo]=args[i][0]
                            self.stats['global_value_aliases']+=1
                    else:
                        self.sink([args[i]])
                        for address,n in list(global_memory.items()):
                            if lo<address+4 and address<hi:
                                self.sink([(n,self.nodes[n][1])]);del global_memory[address]
                else:self.sink([args[i]])
            else:
                values=[v for p,v in args];computed=evaluate(e.opcode,values)
                if (computed is not None and e.dst_reg_uid is not None
                    and e.dst_write_mask==result_mask(e.opcode)
                    and int(e.dst_val)&result_mask(e.opcode)==computed):
                    absorbing=(e.opcode=='or.pred' and any(p is None and bool(v) for p,v in args)
                        or e.opcode=='and.pred' and any(p is None and not bool(v) for p,v in args))
                    dst=self.add(e.opcode,computed,args) if not absorbing and any(p is not None for p,v in args) else None
                else:
                    self.sink(args)
            if e.dst_reg_uid is not None:
                old=regs.get(keybase+(e.dst_reg_uid,))
                full_write=(e.kind=='load' and complete_word_load(e)) or e.dst_write_mask==result_mask(e.opcode)
                if not full_write and old is not None:self.sink([(old,self.nodes[old][1])])
                regs[keybase+(e.dst_reg_uid,)]=dst
        if global_closed:
            while boundary_index<len(boundaries):
                global_boundary(boundaries[boundary_index]);boundary_index+=1
        # Every future full-word read is linked across kernels/owner epochs
        # by the native physical object UID. A partial-access object is never
        # certified. A final dead shared word is not an externally observed
        # result and must not be promoted into an artificial output.
        for v in all_versions:
            if not v['reads'] or v['uid'] in opaque_uids or v.get('unmodeled_persistent_owner_read'):continue
            if any(self.nodes[n][1]!=v['value'] for c,n in v['reads']):continue
            self.versions[v['key']].append(v)
        for key,versions in self.versions.items():versions.sort(key=lambda v:v['start'])
        # Eliminate dead temporary values, including values used only by an
        # already constant Boolean guard. Memory side effects remain roots.
        self.relevant=bytearray(len(self.nodes));pending=[i for i,(op,_,_) in enumerate(self.nodes) if op in ('sink','address_store')]
        while pending:
            n=pending.pop()
            if self.relevant[n]:continue
            self.relevant[n]=1
            pending.extend(p for p,v in self.nodes[n][2] if p is not None)
        self.stats.update(nodes=len(self.nodes),word_versions=sum(map(len,self.versions.values())),
                          construction_seconds=time.perf_counter()-t)
        # The table is needed only while constructing this one input's DAG.
        self.pure_expressions.clear();self.read_expressions.clear()

    def add(self,op,value,args):
        args=tuple(args)
        pure=op not in ('copy','sink','address_load','address_store')
        if pure:
            key=(op,value,args)
            if key in self.pure_expressions:
                self.stats['equivalent_pure_nodes_reused']+=1
                return self.pure_expressions[key]
        n=len(self.nodes);self.nodes.append((op,value,tuple(args)));self.uses.append([])
        if pure:self.pure_expressions[key]=n
        for p,v in args:
            if p is not None:self.uses[p].append(n)
        return n
    def sink(self,args):
        if any(p is not None for p,v in args):self.add('sink',0,args)

    def closed(self,seeds,bit):
        key=(tuple(seeds),bit)
        if key in self.cache:self.stats['cache_hits']+=1;return self.cache[key]
        self.stats['queries']+=1
        values={n:self.nodes[n][1]^(1<<bit) for n in seeds};heap=[];queued=set();seen=0;ignored_writes=[]
        for n in seeds:
            for child in self.uses[n]:
                if self.relevant[child] and child not in queued:heapq.heappush(heap,child);queued.add(child)
        while heap:
            n=heapq.heappop(heap);seen+=1
            if seen>self.limit:
                self.stats['budget_refusals']+=1;self.cache[key]=False;return False
            if n in values:continue
            op,golden,args=self.nodes[n]
            if not any(p in values for p,v in args):continue
            if op=='sink':
                self.stats['frontier_refusals']+=1;self.cache[key]=False;return False
            operands=[values.get(p,v) for p,v in args]
            if op=='address_load':
                e,a=self.access[n];current=self.address_model.load(e,a,operands[:-1],operands[-1],ignored_writes)
            elif op=='address_store':
                e,a=self.access[n];current=0 if self.address_model.store(e,a,operands,ignored_writes) else None
            else:current=evaluate(op,operands)
            if current is None:
                self.stats['frontier_refusals']+=1;self.cache[key]=False;return False
            if current==golden:continue
            values[n]=current
            for child in self.uses[n]:
                if self.relevant[child] and child not in queued:heapq.heappush(heap,child);queued.add(child)
        self.stats['certified_bits']+=1;self.cache[key]=True;return True

    def project(self,regions):
        t=time.perf_counter()
        for region in regions:
            d=region.target;addr=d['byte_addr'];base=addr-addr%4
            versions=self.versions.get((d['kernel'],d['sm'],d['cta_id'],base),())
            if not versions or not region.classes['SDC']:
                yield region;continue
            cuts={region.start,region.stop}
            for v in versions:
                for c,n in v['reads']:
                    if region.start<c<region.stop:cuts.add(c)
                if region.start<v['start']<region.stop:cuts.add(v['start'])
            cuts=sorted(cuts)
            starts=[v['start'] for v in versions]
            for lo,hi in zip(cuts,cuts[1:]):
                pos=bisect.bisect_right(starts,lo)-1
                if pos<0:yield replace(region,start=lo,stop=hi);continue
                v=versions[pos];seeds=[n for c,n in v['reads'] if c>lo]
                classes=dict(region.classes);mask=0
                if seeds:
                    for b in range(8):
                        if classes['SDC']&(1<<b) and self.closed(seeds,8*(addr%4)+b):mask|=1<<b
                if mask:
                    classes['SDC']&=~mask;classes['Masked']|=mask
                    self.stats['resolved_bit_cycles']=self.stats.get('resolved_bit_cycles',0)+(hi-lo)*bin(mask).count('1')
                yield replace(region,start=lo,stop=hi,classes=classes)
        self.stats['projection_seconds']=time.perf_counter()-t
