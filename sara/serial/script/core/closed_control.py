"""Exact short integer chains ending in an unchanged branch predicate.

All changed input/temporary register versions must die before any other
consumer. This proves the same actual branch and no escaping changed state,
without selecting an application or replaying an alternate path.
"""
from bisect import bisect_right
from collections import defaultdict
from script.core.closed_loop_transfer import RFLoopEffect
from script.core.closed_word_flow import evaluate,WORD,signed
import time

def predicate(op,values):
    parts=op.split('.')
    if len(parts)!=3 or parts[0]!='setp' or parts[2] not in ('s32','u32') or len(values)!=2:return None
    a,b=map(signed,values) if parts[2]=='s32' else values
    return {'eq':a==b,'ne':a!=b,'lt':a<b,'le':a<=b,'gt':a>b,'ge':a>=b}.get(parts[1])

def construct(events):
    start=time.perf_counter();threads=defaultdict(list);effects=[]
    stats=dict(policy='closed-integer-chain-unchanged-branch-v1',FI_answers_used=False,
        application_specific_dispatch=False,per_draw_replay=False,admitted_chains=0)
    for e in events:threads[e.kernel_uid,e.thread_id].append(e)
    for (kernel,thread),rows in threads.items():
        actions=defaultdict(list)
        for i,e in enumerate(rows):
            for uid in e.src_reg_uids:
                if uid is not None:actions[uid].append((i,0))
            if e.pred is not None:actions[e.pred.uid].append((i,0))
            if e.dst_reg_uid is not None:actions[e.dst_reg_uid].append((i,1))
        for end,branch in enumerate(rows):
            if branch.opcode!='bra' or branch.pred is None or end<3:continue
            block=rows[end-3:end];a,b,test=block
            if (any(e.pred is not None or e.kind!='inst' for e in block)
                or a.dst_write_mask!=WORD or b.dst_write_mask!=WORD
                or any(w!=32 for e in block for w in e.src_width_bits)
                or predicate(test.opcode,[int(v)&WORD for v in test.src_vals]) is None
                or test.dst_reg_uid!=branch.pred.uid
                or a.dst_reg_uid not in b.src_reg_uids
                or b.dst_reg_uid not in test.src_reg_uids):continue
            if any(evaluate(e.opcode,[int(v)&WORD for v in e.src_vals]) is None for e in (a,b)):continue
            defined={e.dst_reg_uid for e in block}
            roots={uid for e in block for uid in e.src_reg_uids if uid is not None and uid>=0 and uid not in defined}
            if not roots:continue
            def dead(uid):
                seq=actions[uid];pos=bisect_right(seq,(end,2))
                return pos==len(seq) or seq[pos][1]==1
            if not all(dead(e.dst_reg_uid) for e in (a,b)):continue
            initial={}
            for e in block:
                for uid,v in zip(e.src_reg_uids,e.src_vals):
                    if uid in roots:initial.setdefault(uid,int(v)&WORD)
            def value(uid,bit):
                environment={uid:initial[uid]^(1<<bit)}
                for e in block:
                    args=[environment.get(u,int(v)&WORD) for u,v in zip(e.src_reg_uids,e.src_vals)]
                    v=predicate(e.opcode,args) if e is test else evaluate(e.opcode,args)
                    if v is None:return None
                    environment[e.dst_reg_uid]=v
                return bool(environment[test.dst_reg_uid])
            for uid in roots:
                if not dead(uid):continue
                first=next(e for e in block if uid in e.src_reg_uids)
                first_index=rows.index(first,end-3,end)
                seq=actions[uid];pos=bisect_right(seq,(first_index,-1))-1
                if pos<0:continue
                lo=rows[seq[pos][0]].cycle;hi=first.cycle
                if lo>=hi:continue
                mask=0
                for bit in range(32):
                    if value(uid,bit)==predicate(test.opcode,[int(v)&WORD for v in test.src_vals]):mask|=1<<bit
                if mask:
                    effects.append(RFLoopEffect(kernel,thread,uid,lo,hi,masked=mask,
                        rule='exact_closed_integer_chain_preserves_branch_and_all_escaping_values'))
                    stats['admitted_chains']+=1
    stats.update(effects=len(effects),construction_seconds=time.perf_counter()-start)
    return effects,stats
