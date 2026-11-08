"""UNVALIDATED proposal: batch shared-byte lifetime projection, no origin replay.

Both sinks consume these regions after the existing single analyze_rf call.
Actual persistent object identity is required; owner changes do not clear data.
"""
from collections import defaultdict

from script.core.batch_backward import reverse_intervals
from script.core.reg_observed_analyzer import compact_smem_site_row_to_dict


def smem_regions(inventory, events, analysis, raw_events):
    if len(events) != len(raw_events):
        raise ValueError('instruction/identity record counts differ')
    slots, objects, owners = {}, {}, set()
    for raw in raw_events:
        identity = raw.get('shared_storage', {})
        if identity.get('schema') != 'sara-actual-shared-owner-v1':
            if raw.get('mem_space') == 'shared':
                raise ValueError('actual persistent shared identity required')
            continue
        scope = (raw['sm_id'], raw['cta_id'])
        uid = identity['object_uid']
        if not uid or not identity['owner_epoch']:
            raise ValueError('unassigned shared object/owner')
        if slots.setdefault(scope, uid) != uid or objects.setdefault(uid, scope) != scope:
            raise ValueError('physical shared scope/object mapping is not bijective')
        # Several logical CTA generations may reuse a slot in one kernel.
        # Population half-open lifetimes bind the particular owner epoch.
        owners.add((raw['kernel_uid'], *scope, uid,
                    identity['owner_epoch'], identity['allocator_slot']))
    byte_masks = {}
    for record in analysis['smem_fault_sites']:
        row = compact_smem_site_row_to_dict(record)
        if row['site_kind'] != 'smem_lds':
            continue
        key = (row['event_index'], row['addr'])
        value = tuple(int(row[name]) for name in ('observed_mask_this_site',
            'due_mask_this_site','trace_expanding_mask_this_site'))
        if any(x < 0 or x > 255 for x in value) or key in byte_masks:
            raise ValueError('duplicate/non-byte shared load sensitivity')
        byte_masks[key] = value
    actions = defaultdict(list)
    for index, (event, raw) in enumerate(zip(events,raw_events)):
        if event.index != index:
            raise ValueError('projection and analysis instruction orders differ')
        if raw.get('mem_space') != 'shared' or event.kind not in ('load','store'):
            continue
        if event.pred is not None and not event.pred.val:
            continue
        size = raw.get('mem_access_size_bytes') if event.kind == 'load' else raw.get('store_size_bytes')
        if type(size) is not int or not 1 <= size <= 8 or event.mem_addr is None:
            raise ValueError('only actual scalar shared access widths are admitted')
        uid = slots[(event.sm_id,event.cta_id)]
        for offset in range(size):
            address = event.mem_addr + offset
            if event.kind == 'load':
                # Missing zero-live loads are not silently guessed Masked.
                value = byte_masks.pop((index,address))
                actions[uid,address].append((event.cycle,2*index,'read',*value,0))
            else:
                actions[uid,address].append((event.cycle,2*index+1,'write',0,0,0,255))
    if byte_masks:
        raise ValueError('unconsumed shared-memory sensitivity record')
    for span in inventory['spans']:
        if span['component'] != 'smem' or span['bit_count'] != 8:
            raise ValueError('complete actual per-byte shared population required')
        target, life = span['target'], span['lifecycle']
        if span['bit_start'] != target['byte_addr']*8:
            raise ValueError('shared bit index does not match injector byte')
        expected = (life['shared_storage_uid'],life['shared_owner_epoch'],life['shared_allocator_slot'])
        if (target['kernel'],target['sm'],target['cta_id'],*expected) not in owners:
            raise ValueError('population owner is absent/inconsistent in actual instruction capture')
        # Future owners may consume retained bytes beyond this query lifetime.
        # The shared reverse_intervals routine includes those actions and all
        # overwrites, but emits only this span's post-core half-open interval.
        yield from reverse_intervals(span,actions.get((expected[0],target['byte_addr']),()))
