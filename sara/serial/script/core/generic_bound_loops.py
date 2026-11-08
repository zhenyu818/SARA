"""Generic increasing integer-loop watchdog lower bounds.

The counter, bound, step, loop body and guard path are derived from PTX. A
bounded integer interpreter visits only the preheader; it never evaluates
loads numerically or executes the large loop. Unknown control retains the
baseline prediction. Straight-line loop bodies have no alternate exit.
"""
from collections import defaultdict
from script.core.generic_counter_loops import parse_single_entry,RFLoopEffect,WORD
from script.core.closed_word_flow import signed
import time

def iterations(value,bound,step):
    if not 0<step<=0x7fffffff or not -0x80000000<=value<=0x7fffffff or not -0x80000000<=bound<=0x7fffffff:return None
    count=max(1,(bound-value+step-1)//step)
    return count if -0x80000000<=value+count*step<=0x7fffffff else None

def loops_from(rows,labels):
    result={}
    safe={'ld','mov','add','sub','mul','mad','fma','cvt','cvta','shl','shr','and','or','xor','not','min','max','setp'}
    for end,b in enumerate(rows):
        if b['op']!='bra' or not b['pred'] or b['pred'].startswith('!') or len(b['args'])!=1 or end<2:continue
        begin=labels.get(b['args'][0],end)
        u,t=rows[end-2:end]
        if (begin>end-2 or u['pred'] or t['pred'] or u['op']!='add.s32' or t['op']!='setp.lt.s32'
            or len(u['args'])!=3 or len(t['args'])!=3 or u['args'][0]!=u['args'][1]
            or t['args'][1]!=u['args'][0] or t['args'][0]!=b['pred']):continue
        counter,bound,step=u['args'][0],t['args'][2],u['args'][2]
        if not bound.startswith('%'):continue
        body=rows[begin:end-2]
        if any(r['pred'] or r['op'].split('.')[0] not in safe or
               (r['args'] and r['args'][0] in (counter,bound,step)) for r in body):continue
        # A load-dependent counter/bound would have been rejected above. The
        # legal scalar load/arithmetic body has no data-dependent early exit.
        result[begin]=dict(counter=counter,bound=bound,step=step,end=end,
                           instructions=end-begin+1)
    return result

def number(token,env):
    if token.startswith('%'):return env.get(token)
    try:return int(token,0)
    except ValueError:return None

def arithmetic(op,vals):
    if any(v is None for v in vals):return None
    bits=64 if op.endswith(('s64','u64','b64')) else 32;mask=(1<<bits)-1
    root=op.split('.')[0]
    if root in ('mov','cvta'):return vals[0]&mask
    if root=='add':return (vals[0]+vals[1])&mask
    if root=='sub':return (vals[0]-vals[1])&mask
    if root=='not':return (~vals[0])&mask
    if root=='and':return vals[0]&vals[1]
    if root=='or':return vals[0]|vals[1]
    if root=='xor':return vals[0]^vals[1]
    if root in ('max','min'):
        v=[signed(x&WORD) for x in vals] if op.endswith('s32') else vals
        return (max(v) if root=='max' else min(v))&mask
    if root=='setp' and len(vals)==2 and op.endswith(('s32','u32')):
        a,b=[signed(v&WORD) for v in vals] if op.endswith('s32') else [v&WORD for v in vals]
        return {'eq':a==b,'ne':a!=b,'lt':a<b,'le':a<=b,'gt':a>b,'ge':a>=b}.get(op.split('.')[1])
    # Address and numerical body expressions are deliberately opaque. They
    # cannot be used to decide a control path unless a value is known.
    return None

def preheader_exceeds(rows,labels,loops,pc,initial,remaining):
    env=dict(initial);steps=0
    while 0<=pc<len(rows) and steps<256:
        if pc in loops:
            loop=loops[pc];v=number(loop['counter'],env);b=number(loop['bound'],env);s=number(loop['step'],env)
            if None not in (v,b,s):
                n=iterations(signed(v&WORD),signed(b&WORD),signed(s&WORD))
                if n is not None and steps+n*loop['instructions']>remaining:return True
            return False
        row=rows[pc];op=row['op'];args=row['args'];pred=row['pred']
        if pred:
            negate=pred.startswith('!');condition=env.get(pred.lstrip('!'))
            if condition is None:return False
            active=bool(condition)^negate
            if not active:pc+=1;steps+=1;continue
        if op=='bra':
            if len(args)!=1 or args[0] not in labels:return False
            pc=labels[args[0]];steps+=1;continue
        root=op.split('.')[0]
        if root in ('ret','exit','call','callp','bar','trap','st','atom','red'):return False
        if not args or not args[0].startswith('%'):return False
        env[args[0]]=arithmetic(op,[number(a,env) for a in args[1:]]) if root!='ld' else None
        pc+=1;steps+=1
    return False

def construct(events,image):
    start=time.perf_counter();stats=dict(policy='generic-monotone-bound-watchdog-v1',FI_answers_used=False,
        application_specific_dispatch=False,source_hash_selects_rules=False,per_draw_replay=False)
    parsed=parse_single_entry((image or {}).get('loop_ptx'));protocol=(image or {}).get('loop_fault_protocol')
    if parsed is None or protocol is None:return [],dict(stats,status='not_admitted',construction_seconds=time.perf_counter()-start)
    rows,labels=parsed;loops=loops_from(rows,labels)
    if not loops or len({e.kernel_uid for e in events})!=1:return [],dict(stats,status='not_admitted',construction_seconds=time.perf_counter()-start)
    if (protocol['golden_cycles']*10!=protocol['cycle_limit'] or protocol.get('max_insn_issue_per_warp')!=1
        or protocol.get('dependent_chain_min_core_cycles')!=1
        or protocol.get('shader_source_sha256')!=image.get('source_files',{}).get('src/gpgpu-sim/shader.cc')):
        raise ValueError('fixed simulator issue/watchdog contract')
    if image.get('source_files',{}).get('src/cuda-sim/memory.cc')!='059e31cb4167b559bcdef39349b5d4b36e9a80b44f30dd09697444108c9cb947':
        return [],dict(stats,status='native_scalar_memory_semantics_unbound',construction_seconds=time.perf_counter()-start)
    for e in events:
        pc=int(e.pc,0) if isinstance(e.pc,str) else int(e.pc)
        if pc%8 or pc//8>=len(rows) or rows[pc//8]['op']!=e.opcode:
            return [],dict(stats,status='source_alignment_refused',construction_seconds=time.perf_counter()-start)
    bounds={l['bound'] for l in loops.values()};envs=defaultdict(dict);last={};effects=[]
    for e in events:
        if e.pred is not None and not e.pred.val:continue
        env=envs[e.kernel_uid,e.thread_id]
        for r,v in zip(e.src_regs,e.src_vals):
            if r and r.startswith('%'):env[r]=int(v)
        if e.opcode.startswith('setp.'):
            for i,r in enumerate(e.src_regs):
                if r not in bounds or e.src_width_bits[i]!=32:continue
                uid=e.src_reg_uids[i];key=(e.kernel_uid,e.thread_id,uid);lo=last.get(key)
                if lo is None or lo>=e.cycle:continue
                mask=0;pc=(int(e.pc,0) if isinstance(e.pc,str) else int(e.pc))//8
                for bit in range(32):
                    mutant=dict(env);mutant[r]=(int(e.src_vals[i])&WORD)^(1<<bit)
                    if preheader_exceeds(rows,labels,loops,pc,mutant,protocol['cycle_limit']-e.cycle):mask|=1<<bit
                if mask:effects.append(RFLoopEffect(*key,lo,e.cycle,due=mask,rule='generic_closed_monotone_loop_issue_lower_bound'))
        for uid in e.src_reg_uids:
            if uid is not None:last[e.kernel_uid,e.thread_id,uid]=e.cycle
        if e.dst_reg_uid is not None:
            last[e.kernel_uid,e.thread_id,e.dst_reg_uid]=e.cycle
            env[e.dst_reg]=arithmetic(e.opcode,[int(v) for v in e.src_vals]) if e.opcode.startswith('setp.') else int(e.dst_val)
    stats.update(status='constructed',loops=len(loops),effects=len(effects),construction_seconds=time.perf_counter()-start,
        assumption='pinned scalar PTX memory/arithmetic execution; no alternate exit; native watchdog; no hardware FIT claim')
    return effects,stats
