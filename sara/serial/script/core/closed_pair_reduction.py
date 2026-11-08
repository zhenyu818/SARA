"""Closed unsigned lexicographic shared-memory tournament certificates.

No application, sample, FI label or register spelling selects this rule. Static
PTX proves the conditional store diamond. Actual events prove a disjoint,
barrier-separated complete tournament, no escaping temporaries, and no other
shared consumers. Only pre-read intervals are resolved. Persistent shared bytes
must be overwritten before any later kernel reads them. All other paths keep
the original SARA result. This is not a general alternate-path interpreter.
"""
from collections import defaultdict
from dataclasses import replace
import re
import time

WORD=0xffffffff
OPS=('ld.shared.u32','ld.shared.u32','setp.ge.u32','setp.ne.s32',
     'ld.shared.u32','ld.shared.u32','setp.ge.u32','or.pred','and.pred','bra',
     'st.shared.u32','st.shared.u32')

class Refuse(Exception):pass
class Pattern(list):
    pass
def require(x,reason):
    if not x:raise Refuse(reason)

def patterns(text):
    """Only complete source diamonds; names are bound variables, never policy."""
    text=re.sub(r'/\*.*?\*/|//[^\n]*','',text,flags=re.S)
    answer=[]
    for entry in re.finditer(r'\.entry\s+[^\s(]+\s*\([^{}]*\)\s*\{([^{}]*)\}',text):
        rows=[];labels={};pending=''
        for line in entry[1].splitlines():
            line=line.strip()
            if not line:continue
            if line.endswith(':'):labels[line[:-1]]=len(rows);continue
            if line.startswith('.'):continue
            pending+=' '+line
            while ';' in pending:
                statement,pending=pending.split(';',1)
                m=re.fullmatch(r'\s*(?:@(!?%[\w.$]+)\s+)?([\w.]+)\s*(.*?)\s*',statement)
                if m:rows.append((m[1],m[2],tuple(a.strip() for a in m[3].split(','))))
        for i in range(len(rows)-12):
            r=rows[i:i+12]
            if tuple(x[1] for x in r)!=OPS:continue
            a=[x[2] for x in r]
            if any(len(a[j])!=n for j,n in enumerate((2,2,3,3,2,2,3,3,3,1,2,2))):continue
            x,y,ix,iy=a[0][0],a[1][0],a[4][0],a[5][0]
            if len({x,y,ix,iy})!=4:continue
            if (a[2][1:]!=(y,x) or a[3][1:]!=(y,x) or a[6][1:]!=(iy,ix)
                or a[7][1:]!=(a[3][0],a[6][0]) or a[8][1:]!=(a[2][0],a[7][0])
                or r[9][0]!=a[8][0] or any(row[0] for j,row in enumerate(r) if j!=9)
                or a[10]!=(a[0][1],y) or a[11]!=(a[4][1],iy)
                or labels.get(a[9][0])!=i+12 or rows[i+12][1]!='bar.sync'):continue
            if not all(re.fullmatch(r'\[%[\w.$]+(?:\+(?:0x[0-9a-fA-F]+|\d+))?\]',a[j][1]) for j in (0,1,4,5)):continue
            pattern=Pattern(r)
            pattern.entry_rows=rows
            pattern.entry_offset=entry.start()
            pattern.instruction_index=i
            answer.append(pattern)
    return answer

def pc_value(e):
    return int(e.pc,0) if isinstance(e.pc,str) else int(e.pc)

def bind_entry(evs,pats):
    """Bind the full observed PC map to one complete PTX entry.

    The pinned PTX interpreter encodes ordinary PTX instructions in eight
    bytes. Any inconsistent/ambiguous entry or instruction shape is refused;
    register names alone never establish which untaken store body applies.
    """
    observed={}
    for e in evs:
        key=pc_value(e)
        signature=(e.opcode,e.dst_reg,e.pred.reg if e.pred else None)
        require(key not in observed or observed[key]==signature,'nonunique PC shape')
        observed[key]=signature
    byentry={p.entry_offset:p.entry_rows for p in pats}
    candidates=set()
    for e in evs:
        if e.opcode!=OPS[0]:continue
        for p in pats:
            if same_instruction(e,p[0]):
                candidates.add((p.entry_offset,pc_value(e)-8*p.instruction_index))
        if candidates:break
    accepted=[]
    for entry,base in candidates:
        rows=byentry[entry];ok=True
        for pc,(op,dst,pred) in observed.items():
            offset=pc-base
            if offset<0 or offset%8 or offset//8>=len(rows):ok=False;break
            rp,rop,args=rows[offset//8]
            if (rop.removesuffix('.uni') if hasattr(rop,'removesuffix') else rop[:-4] if rop.endswith('.uni') else rop)!=op:
                ok=False;break
            if rp!=pred or (dst is not None and (not args or args[0]!=dst)):
                ok=False;break
        if ok:accepted.append((entry,base))
    require(len(accepted)==1,'ambiguous or unbound complete source entry')
    entry,base=accepted[0]
    return {base+8*p.instruction_index:p for p in pats if p.entry_offset==entry}

def same_instruction(e,row):
    pred,op,args=row
    if e.opcode!=op:return False
    if op=='bra':return e.pred is not None and e.pred.reg==pred and e.src_regs==[pred]
    if e.pred is not None:return False
    if op.startswith('ld.'):
        m=re.fullmatch(r'\[(%[\w.$]+)(?:\+(0x[0-9a-fA-F]+|\d+))?\]',args[1])
        return (m is not None and e.dst_reg==args[0] and e.src_regs==[m[1]]
                and (int(e.src_vals[0])+int(m[2] or '0',0))&WORD==e.mem_addr
                and e.mem_access_size_bytes==4)
    return e.dst_reg==args[0] and tuple(e.src_regs)==args[1:]

def word(e):return int(e.dst_val)&WORD
def pair_result(left,right):return min(left,right)

def build(events,raw_events,image):
    start=time.perf_counter();pats=patterns((image or {}).get('loop_ptx') or '')
    meta=dict(policy='closed-lexicographic-shared-tournament-v1',static_diamonds=len(pats),
        admitted_kernels=0,refused_kernels=[],certified_word_intervals=0,FI_answers_used=False,
        per_draw_replay=False,application_specific_dispatch=False)
    certs=defaultdict(list)
    if not pats:
        meta['construction_seconds']=time.perf_counter()-start;return certs,meta
    kernels=defaultdict(list);actions=defaultdict(list)
    for e,raw in zip(events,raw_events):
        kernels[e.kernel_uid].append(e)
        if e.mem_space=='shared' and e.kind in ('load','store') and (e.pred is None or e.pred.val):
            identity=raw.get('shared_storage',{})
            uid=identity.get('object_uid')
            n=e.mem_access_size_bytes if e.kind=='load' else e.store_size_bytes
            require(uid and n is not None,'actual shared identity/width')
            for j in range(n):actions[uid,e.mem_addr+j].append((e.index,e.kind))
    for kernel,evs in kernels.items():
        try:
            kernel_cert=_kernel(evs,raw_events,pats,actions)
        except Refuse as ex:
            meta['refused_kernels'].append(dict(kernel=kernel,reason=str(ex)));continue
        if kernel_cert:
            meta['admitted_kernels']+=1
            for key,value in kernel_cert.items():certs[key].extend(value)
    for key,rows in certs.items():
        rows.sort()
        require(all(a[1]<=b[0] for a,b in zip(rows,rows[1:])),'overlapping certificates')
    meta['certified_word_intervals']=sum(len(v) for v in certs.values())//4
    meta['construction_seconds']=time.perf_counter()-start
    return dict(certs),meta

def _kernel(evs,raw,pats,actions):
    bound=bind_entry(evs,pats)
    threads=defaultdict(list)
    for e in evs:threads[e.thread_id].append(e)
    nodes=[];owned=set();definitions={};phase_at={}
    for tid,rows in threads.items():
        phase=0;i=0
        while i<len(rows):
            e=rows[i];phase_at[e.index]=phase
            if e.opcode=='bar.sync':phase+=1
            found=None
            if e.opcode==OPS[0] and i+9<len(rows):
                for pat in ([bound[pc_value(e)]] if pc_value(e) in bound else []):
                    if all(same_instruction(rows[i+j],pat[j]) for j in range(10)):
                        found=pat;break
            if found is None:i+=1;continue
            block=rows[i:i+10];x,y,ix,iy=(block[j] for j in (0,1,4,5))
            left=(word(x),word(ix));right=(word(y),word(iy))
            take=bool(block[9].recorded_branch_taken)
            require(take==(right>=left),'golden predicate relation')
            n=10
            if not take:
                require(i+12<len(rows),'complete actual conditional stores')
                for j,(addr,value,reg) in enumerate(((x.mem_addr,right[0],y.dst_reg),(ix.mem_addr,right[1],iy.dst_reg))):
                    s=rows[i+10+j]
                    require(s.opcode=='st.shared.u32' and s.pred is None and s.mem_addr==addr
                        and s.store_size_bytes==4 and s.src_regs[s.store_data_src_index]==reg
                        and int(s.src_vals[s.store_data_src_index])&WORD==value,'actual store diamond')
                block+=rows[i+10:i+12];n=12
            require(rows[i+n].opcode=='bar.sync','actual immediate postdominating barrier')
            identities={tuple(raw[z.index].get('shared_storage',{}).get(k) for k in ('object_uid','owner_epoch','allocator_slot')) for z in (x,y,ix,iy)}
            require(len(identities)==1 and all(v is not None for v in next(iter(identities))),'same actual owner')
            key=(x.mem_addr,ix.mem_addr);other=(y.mem_addr,iy.mem_addr)
            require(len(set(key+other))==4 and all(a%4==0 for a in key+other),'distinct aligned words')
            node=dict(phase=phase,left=key,right=other,lv=left,rv=right,value=pair_result(left,right),
                begin=x.index,end=block[-1].index,end_cycle=block[-1].cycle,
                reads={key:(x.cycle,ix.cycle),other:(y.cycle,iy.cycle)},
                writes={} if take else {key:(rows[i+10].cycle,rows[i+11].cycle)},
                uid=next(iter(identities))[0],owner=next(iter(identities)),target=(x.kernel_uid,x.sm_id,x.cta_id))
            nodes.append(node);owned.update(z.index for z in block)
            for z in block:
                if z.dst_reg_uid is not None and z.dst_write_mask:
                    definitions[z.index]=(z.thread_id,z.dst_reg_uid)
            i+=n
    require(nodes,'no complete runtime diamonds')
    require(len({n['target'] for n in nodes})==1 and len({n['owner'] for n in nodes})==1,'single actual shared owner tournament')
    first=min(n['begin'] for n in nodes);last=max(n['end'] for n in nodes)
    # Every altered temporary must die within its closed diamond, except via
    # the shared pair stores. No golden-only def/use guess crosses a side path.
    for rows in threads.values():
        live={}
        for e in rows:
            read_uids=list(e.src_reg_uids)
            if e.pred is not None:read_uids.append(e.pred.uid)
            if e.index not in owned:
                require(not any(live.get(uid,False) for uid in read_uids if uid is not None),'temporary escapes diamond')
            if e.dst_reg_uid is not None and e.dst_write_mask:
                live[e.dst_reg_uid]=e.index in definitions
    byphase=defaultdict(list)
    for n in nodes:byphase[n['phase']].append(n)
    previous=None;states={};last_use={};snapshots=[]
    init_writes={}
    for e in evs:
        if e.index>=first:break
        if e.mem_space=='shared' and e.kind=='store':
            require(e.pred is None and e.store_size_bytes==4 and e.mem_addr%4==0,'complete initial shared word')
            init_writes[e.mem_addr]=(int(e.src_vals[e.store_data_src_index])&WORD,e.cycle)
    for phase,stage in sorted(byphase.items()):
        pairs=[p for n in stage for p in (n['left'],n['right'])]
        require(len(set(pairs))==len(pairs),'stage inputs are not disjoint')
        require(len({a for p in pairs for a in p})==2*len(pairs),'shared words alias between pairs')
        if previous is not None:require(set(pairs)==previous,'incomplete tournament level')
        current={};bounds={}
        for n in stage:
            for p,v in ((n['left'],n['lv']),(n['right'],n['rv'])):
                require(all(a in init_writes for a in p),'uninitialized input pair')
                expected=states.get(p,tuple(init_writes[a][0] for a in p))
                require(v==expected,'golden stage values differ')
                current[p]=v
                bounds[p]=[(max(last_use.get((p,field),-1),init_writes[a][1]),n['reads'][p][field])
                           for field,a in enumerate(p)]
        snapshots.append((current,bounds))
        states={n['left']:n['value'] for n in stage};previous=set(states)
        for n in stage:
            for p in (n['left'],n['right']):
                for field in range(2):
                    last_use[p,field]=max(n['reads'][p][field],n['writes'].get(p,(-1,-1))[field])
    require(len(states)==1,'not a complete one-root reduction')
    root,rootvalue=next(iter(states.items()))
    addresses={a for values,b in snapshots for p in values for a in p}
    uid=nodes[0]['uid'];target=nodes[0]['target']
    # Shared-memory escape closure: exact actual accesses only; unsupported
    # partial accesses and additional consumers deny the certificate.
    tail_root_reads=set()
    for e in evs:
        if e.mem_space=='shared' and e.kind in ('load','store'):
            require(e.pred is None,'predicated shared access outside modeled diamond')
            if e.index in owned:continue
            if e.kind=='store' and e.index<first and e.mem_addr in addresses:continue
            require(e.kind=='load' and e.index>last and e.mem_addr in root and e.mem_access_size_bytes==4,'unmodeled shared consumer')
            require(word(e)==rootvalue[root.index(e.mem_addr)],'actual root read mismatch')
            tail_root_reads.add(e.mem_addr)
        if e.kind=='store' and e.mem_space!='shared':require(e.index>last,'external side effect before root')
    require(tail_root_reads==set(root),'both root words consumed')
    # Persistent shared storage may survive CTA/kernel reuse; prove future
    # overwritten-before-read bytewise for every possibly affected tree word.
    import bisect
    end=evs[-1].index
    for addr in addresses:
        for j in range(4):
            seq=actions[uid,addr+j];pos=bisect.bisect_right(seq,(end,'z'))
            require(pos==len(seq) or seq[pos][1]=='store','later owner can consume retained altered bytes')
    certificates=defaultdict(list)
    for values,bounds in snapshots:
        ranked=sorted((v,p) for p,v in values.items())
        require(min(values.values())==rootvalue,'stage does not reduce to actual final root')
        for p,v in values.items():
            other=ranked[1][0] if ranked[0][1]==p else ranked[0][0]
            for field,addr in enumerate(p):
                start,stop=bounds[p][field]
                if start>=stop:continue
                mask=0
                for bit in range(32):
                    changed=list(v);changed[field]^=1<<bit
                    if pair_result(tuple(changed),other)==rootvalue:mask|=1<<bit
                for byte in range(4):
                    byte_mask=(mask>>(8*byte))&255
                    if byte_mask:certificates[target+(addr+byte,)].append((start,stop,byte_mask))
    return certificates

def project(regions,certificates,statistics):
    """Split original intervals; preserve every physical bit/cycle exactly."""
    for region in regions:
        t=region.target;key=(t['kernel'],t['sm'],t['cta_id'],t['byte_addr'])
        rows=certificates.get(key)
        if not rows:yield region;continue
        cuts={region.start,region.stop}
        for start,stop,mask in rows:
            if start<region.stop and stop>region.start:cuts.update((max(start,region.start),min(stop,region.stop)))
        cuts=sorted(cuts)
        for start,stop in zip(cuts,cuts[1:]):
            mask=0
            for lo,hi,m in rows:
                if lo<=start and stop<=hi:mask|=m
            classes=dict(region.classes)
            # Retain the original completion/unsupported outcomes. This
            # certificate refines value/control SDC, not a timing-fault model.
            newly=mask&classes['SDC']
            if newly:
                statistics['resolved_bit_cycles']=statistics.get('resolved_bit_cycles',0)+(stop-start)*bin(newly).count('1')
                classes['SDC']&=~newly
                classes['Masked']|=newly
            yield replace(region,start=start,stop=stop,classes=classes)
