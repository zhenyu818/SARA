"""Bounded refusal of unrepresented multi-bit local deltas at value-use boundaries.

The batch core carries individual-bit masks, not a joint changed-word relation.
Several output bits changing together cannot be classified by OR-ing their
independent downstream sensitivities through another computation. Seed Unknown
at this structural boundary. No FI answer, query manifest, tuned threshold or
per-origin program execution is involved. Direct output stores need no such
computational-boundary refusal. Other nonlocal correlations remain limitations.
"""
from functools import lru_cache
from time import perf_counter

POLICY='unknown_multibit_local_delta_before_next_computation-v1'

@lru_cache(maxsize=65536)
def multibit_source_masks(op,values,recorded,width,widths,groups):
    from script.core import reg_observed_analyzer as scalar
    full=scalar.width_mask(scalar.dst_width_bits(op,width))
    baseline=scalar.eval_op_cached(op,values,width)&full
    if recorded is not None and baseline != recorded & full:
        raise scalar.SemanticMismatchError('Composition-boundary local golden differs')
    result=[0]*len(values)
    for group in groups:
        for bit in range(max(widths[i] for i in group)):
            changed=list(values)
            for i in group:
                if bit<widths[i]:changed[i]^=1<<bit
            delta=baseline^(scalar.eval_op_cached(op,tuple(changed),width)&full)
            # More than one changed output bit is precisely the representation
            # boundary, not an empirical error threshold or a fitted score.
            if delta and delta & (delta-1):
                for i in group:
                    if bit<widths[i]:result[i]|=1<<bit
    return tuple(result)

def uncertainty_seeds(events):
    from script.core import reg_observed_analyzer as scalar
    started=perf_counter();definitions={};boundaries=set();by_index={}
    for event in events:
        by_index[event.index]=event
        if event.pred is not None and not event.pred.val:continue
        scope=(event.kernel_uid,event.thread_id)
        if event.kind=='inst' and scalar.canonical_op(event.opcode)!='IDENTITY':
            for uid in event.src_reg_uids:
                producer=definitions.get(scope+(uid,)) if uid>=0 else None
                if producer is not None:boundaries.add(producer)
        if event.dst_reg_uid is not None and event.dst_reg_uid>=0:
            if event.kind=='inst' and scalar.canonical_op(event.opcode)=='IDENTITY' and len(event.src_reg_uids)==1 and event.src_reg_uids[0]>=0:
                # A copy changes the storage/value version, without turning a
                # word perturbation into an independent single-bit relation.
                definitions[scope+(event.dst_reg_uid,)]=definitions.get(scope+(event.src_reg_uids[0],))
            else:definitions[scope+(event.dst_reg_uid,)]=event.index
    seeds={};eligible=0;seeded=0
    for index in sorted(boundaries):
        event=by_index[index]
        if event.kind!='inst' or not event.src_vals:continue
        eligible+=1;op=scalar.canonical_op(event.opcode)
        aliases=scalar.source_value_alias_layout(event.src_reg_uids,len(event.src_vals))
        grouped={i for group in aliases for i in group}
        groups=aliases+tuple((i,) for i,uid in enumerate(event.src_reg_uids) if uid>=0 and i not in grouped)
        if not groups:continue
        width=scalar.instruction_width_bits(event.opcode,event.width_bits)
        widths=tuple(scalar.coerce_width_bits(event.src_width_bits[i],default=width) for i in range(len(event.src_vals)))
        masks=multibit_source_masks(op,tuple(event.src_vals),event.dst_val,width,widths,groups)
        for i,mask in enumerate(masks):
            if mask:
                seeds[(int(event.thread_id),int(event.index),'src',i)]=mask;seeded+=bin(mask).count('1')
    return seeds,{'policy':POLICY,'eligible_value_producers':eligible,'seeded_local_input_bits':seeded,
        'seeded_reads':len(seeds),'analysis_seconds':perf_counter()-started,
        'representation_boundary':'multiple_local_output_bits_before_another_computation',
        'direct_output_store_not_refused_by_this_rule':True,'per_origin_replay':False,'FI_answers_used':False,
        'remaining_limitations':['distinct_value_reconvergence','memory_mediated_correlations','nonlocal_changed_execution']}
