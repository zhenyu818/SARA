"""Cheap tag noninterference from actual post-core physical residency histories.

Only an INVALID suffix ending at full tag overwrite or the observed terminal
boundary is resolved. Lookup/miss/alias, pending-fill and dirty semantics are
not guessed. No trial manifest, FI answer, numerical payload or origin replay
is used. Allocation-version change is the native cache_overlay::allocate
contract; invalidation/fill alone do not overwrite a tag.
"""
from collections import defaultdict
from time import perf_counter

TAG_BITS = 57
TAG_UNKNOWN = (1 << TAG_BITS) - 1
POLICY = 'invalid_until_full_tag_overwrite_or_terminal-v1'


def classify_invalid_tag_suffixes(residencies, rows):
    """Return one compact tag Unknown mask per existing residency interval.

    The input has already passed the complete physical-population decoder.
    A geometry change or an unobserved gap refuses the proof. All states from
    the injection interval through its clearing boundary must remain INVALID;
    a same-allocation fill or dirty transition therefore prevents resolution.
    """
    started = perf_counter()
    spans = residencies['residency_spans']
    def version(copy):
        return tuple(copy[k] for k in ('cache_instance','geometry_epoch','line','allocation_version'))
    # Post-hook snapshots alone can hide a fill/invalidation in one cycle.
    # Refuse every tag version participating in such an operational record.
    # A full allocation from an entirely INVALID old state is the sole safe
    # operational boundary: before_allocate clears its tag stamp before use.
    hazards = set()
    for span in spans:
        if any(state['status'] != 0 for state in span['sector_state']):
            hazards.add(version(span['copy']))
    for row in rows:
        kind = row.get('kind')
        if kind not in {'cache_access','cache_fill','cache_response',
                        'functional_cache_load_source','functional_cache_store_intent',
                        'cache_disposition','cache_write_request_sent'}:
            continue
        copies = [row.get(k) for k in ('before_copy','selected_copy','source','destination')]
        before, after = row.get('before'), row.get('after')
        clear_old = bool(before and after
            and all(x['status'] == 0 for x in before['sector_state'])
            and before['copy']['cache_instance'] == after['copy']['cache_instance']
            and before['copy']['geometry_epoch'] == after['copy']['geometry_epoch']
            and before['copy']['line'] == after['copy']['line']
            and after['copy']['allocation_version'] > before['copy']['allocation_version'])
        if before and not clear_old: copies.append(before['copy'])
        if after: copies.append(after['copy'])
        for cell in row.get('bytes', []):
            copies.extend(cell[name]['copy'] for name in ('l1','l2')
                          if cell.get(name) and cell[name].get('copy'))
        hazards.update(version(copy) for copy in copies if copy)
    groups = defaultdict(list)
    for index, span in enumerate(spans):
        copy = span['copy']
        key = (span['component'], span['scope'], copy['cache_instance'], copy['line'])
        history = groups[key]
        if history and history[-1][1]['end_cycle'] > span['start_cycle']:
            raise ValueError('tag proof requires disjoint chronological slot intervals')
        history.append((index, span))
    masks = [TAG_UNKNOWN] * len(spans)
    resolved_mass = 0
    total_mass = 0
    for history in groups.values():
        safe_suffix = False
        following = None
        for index, span in reversed(history):
            copy = span['copy']
            if following is None:
                clears = span['end_cycle'] == residencies['cycle_stop']
            else:
                next_copy = following['copy']
                adjacent = span['end_cycle'] == following['start_cycle']
                same_epoch = copy['geometry_epoch'] == next_copy['geometry_epoch']
                full_overwrite = next_copy['allocation_version'] > copy['allocation_version']
                same_tag_version = (next_copy['allocation_version'] == copy['allocation_version']
                                    and next_copy['tag'] == copy['tag']
                                    and next_copy['block'] == copy['block'])
                clears = adjacent and same_epoch and (full_overwrite or (same_tag_version and safe_suffix))
            invalid = bool(span['sector_state']) and all(state['status'] == 0 for state in span['sector_state'])
            safe_suffix = bool(invalid and clears and version(copy) not in hazards)
            mass = TAG_BITS * (span['end_cycle'] - span['start_cycle'])
            total_mass += mass
            if safe_suffix:
                masks[index] = 0
                resolved_mass += mass
            following = span
    return {'unknown_masks': masks, 'policy': POLICY,
            'tag_bits': TAG_BITS, 'tag_bit_cycles': total_mass,
            'resolved_Masked_tag_bit_cycles': resolved_mass,
            'unknown_tag_bit_cycles': total_mass - resolved_mass,
            'slot_histories': len(groups), 'operational_or_live_versions_refused': len(hazards), 'residency_intervals': len(spans),
            'analysis_seconds': perf_counter() - started,
            'predicate': 'all_sectors_INVALID_until_full_tag_overwrite_or_observed_terminal;fixed_instance_geometry;no_gap;no_live_or_nonclearing_operational_version',
            'preserved_unknown': ['live_tag', 'same_version_fill_or_dirty_transition',
                                 'geometry_change_or_unobserved_lifetime_end', 'operational_version_without_noninterference_proof'],
            'per_origin_replay': False, 'FI_answers_used': False}
