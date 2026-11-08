"""Serial44 finite native full32 DOWN collective support.

Only the complete source-bound native snapshot/dual-write contract is admitted.
This is exact local physical-bit collective sensitivity inside the existing
SARA composition model, not fault replay, hardware validation, or general
independent-thread scheduling support. No old LLM scalar or projection wrapper
is installed. The global backward owner retains its original event order.
"""
from copy import deepcopy
from script.core import reg_observed_analyzer as old
MASK = 0xffffffff
def need(value, reason):
    if not value:
        raise ValueError('serial finite SHFL coverage gate: '+reason)

def integer(value, width=32):
    result = int(value, 0) if isinstance(value, str) else value
    need(type(result) is int and 0 <= result < 1 << width, 'unsigned raw value/width')
    return result

def _source_word(value, role, name, uid):
    """Accept only a uint32 word or its exact native uint64 sign extension.

    The native general trace writes ptx_reg_t.u64 for both registers and
    literals, while shuffle_scalar_input reads the u32 member. The observed
    physical membermask register has container 0xffffffffffffffff and actual
    uint32 mask 0xffffffff. Canonicalize only that signed32 representation;
    group() still checks each word against the independent uint32 native
    prewrite snapshot/controls. No UID or physical RF fault role is removed.
    """
    container = integer(value, 64)
    if container <= MASK:
        return container
    low = container & MASK
    physical = type(uid) is int and uid >= 0 and isinstance(name, str) and not name.startswith('#')
    literal = role > 0 and type(uid) is int and uid == -1 and isinstance(name, str) and name.startswith('#imm_')
    need((physical or literal)
         and low & (1 << 31) and container == ((old.UINT64_MASK ^ MASK) | low),
         'only exact typed signed32 container extension may exceed uint32')
    return low

class ShuffleEvent(old.TraceEvent):
    __slots__ = ('shuffle44',)

def adapt_event(event, raw):
    opcode = str(raw.get('opcode', '')).lower()
    metadata = raw.get('shuffle')
    if not opcode.startswith('shfl.'):
        need(metadata is None, 'shuffle metadata on another instruction')
        return event
    need(opcode == 'shfl.sync.down.b32' and raw.get('kind') == 'inst'
         and event.pred is None and event.width_bits == 32, 'only unpredicated scalar full32 DOWN supported')
    need(isinstance(metadata, dict) and metadata.get('schema') == 'sara-full-warp-shuffle-v1'
         and metadata.get('mode') == 'down'
         and metadata.get('group_update_semantics') == 'all_sources_before_any_destination', 'native atomic metadata missing')
    need(len(event.src_regs) == len(event.src_vals) == len(event.src_reg_uids)
         == len(event.src_width_bits) == 4 and all(width == 32 for width in event.src_width_bits), 'four typed physical read roles required')
    source_values = [_source_word(value, role, event.src_regs[role], event.src_reg_uids[role])
                     for role, value in enumerate(raw['src_vals'])]
    destinations = metadata.get('destinations')
    need(isinstance(destinations, list) and len(destinations) in (1, 2), 'complete data/predicate writes required')
    need([row.get('role') for row in destinations] == ['data']+(['in_range_predicate'] if len(destinations) == 2 else []), 'destination roles/order')
    data = destinations[0]
    need(data.get('width_bits') == 32 and integer(data.get('write_mask')) == MASK
         and type(data.get('register_uid')) is int and data['register_uid'] >= 0, 'actual complete data write')
    if event.dst_reg is not None:
        matching = [row for row in destinations if row.get('register') == event.dst_reg
                    and row.get('register_uid') == event.dst_reg_uid]
        need(len(matching) == 1, 'primary write disagrees with native write vector')
        if matching[0]['role'] == 'data':
            need(event.dst_val is not None and event.dst_val == integer(data['value'])
                 and event.dst_write_mask == MASK, 'primary data value/mask contradicts complete write vector')
    extended = object.__new__(ShuffleEvent)
    for name in old.TraceEvent.__slots__:
        setattr(extended, name, getattr(event, name))
    extended.src_vals = source_values
    extended.dst_reg, extended.dst_reg_uid = data['register'], data['register_uid']
    extended.dst_val, extended.dst_write_mask = integer(data['value']), MASK
    extended.dst_old_val = (_source_word(data['old_value'], 0, data['register'], data['register_uid'])
                            if data.get('old_value_valid') is True else None)
    extended.shuffle44 = deepcopy(metadata)
    return extended

def selection(lane, b, c):
    delta, clamp, segment = b & 31, c & 31, (c >> 8) & 31
    maximum = (lane & segment) | (clamp & (~segment & 31))
    candidate = lane+delta
    valid = candidate <= maximum
    return (candidate if valid else lane), valid

def evaluate_group(data, b, c, membermask, *, mode='down', active32=True, unpredicated=True):
    need(mode == 'down', 'other SHFL modes are not qualified')
    need(all(len(values) == 32 for values in (data, b, c, membermask)), 'full32 scalar arrays')
    data, b, c, membermask = [[integer(value) for value in values] for values in (data, b, c, membermask)]
    if active32 is not True or unpredicated is not True or any(value != MASK for value in membermask):
        return dict(status='outside_finite_native_contract', outputs=None)
    outputs = []
    for lane in range(32):
        source, valid = selection(lane, b[lane], c[lane])
        outputs.append(dict(source_lane=source, in_range=valid, data=data[source], predicate_zero_flag=int(not valid)))
    return dict(status='defined', outputs=outputs)

def group(events, end):
    need(end >= 31, 'truncated group before final lane')
    rows = [events[index] for index in range(end-31, end+1)]
    first = rows[0]
    need(getattr(first, 'shuffle44', None) is not None, 'missing group start')
    context = (first.kernel_uid, first.logical_cta, first.sm_id, first.cta_id,
               first.warp_id, first.pc, first.cycle)
    snapshot = first.shuffle44.get('source_snapshot')
    need(type(first.shuffle44.get('dynamic_group_id')) is int
         and first.shuffle44['dynamic_group_id'] > 0, 'actual positive dynamic group ID')
    need(first.shuffle44.get('source_snapshot_emitted') is True
         and isinstance(snapshot, list) and len(snapshot) == 32, 'complete prewrite snapshot')
    seen, data, controls, writes, origins = set(), [], [], [], {}
    for lane, row in enumerate(rows):
        meta = getattr(row, 'shuffle44', None)
        need(isinstance(meta, dict) and type(meta.get('lane')) is int and meta.get('lane') == lane
             and meta.get('dynamic_group_id') == first.shuffle44.get('dynamic_group_id'), 'contiguous unique full32 group')
        need((row.kernel_uid, row.logical_cta, row.sm_id, row.cta_id, row.warp_id, row.pc, row.cycle) == context,
             'group context/order differs')
        need(row.index == end-31+lane and row.event_ordinal == row.index+1
             and type(row.thread_instruction_ordinal) is int and row.thread_instruction_ordinal > 0,
             'actual global/thread ordinals required')
        need(type(row.thread_id) is int and row.thread_id > 0 and row.thread_id not in seen,
             'actual unique physical thread')
        need(row.logical_tid is not None and row.logical_tid[0] % 32 == lane, 'native full32 lane geometry')
        seen.add(row.thread_id)
        if lane:
            need(meta.get('source_snapshot_emitted') is False and 'source_snapshot' not in meta, 'duplicate snapshot')
        peer = snapshot[lane]
        need(peer.get('lane') == lane and peer.get('thread_id') == row.thread_id
             and peer.get('register') == row.src_regs[0] and peer.get('register_uid') == row.src_reg_uids[0]
             and peer.get('width_bits') == 32 and integer(peer.get('value')) == row.src_vals[0], 'prewrite source identity/value')
        values = tuple(integer(value) for value in row.src_vals)
        need(tuple(integer(meta.get(name)) for name in ('b', 'c', 'membermask')) == values[1:]
             and values[3] == MASK, 'golden full-member-mask and controls')
        data.append(values[0]); controls.append(values[1:])
        names = {}
        for role, (name, uid) in enumerate(zip(row.src_regs, row.src_reg_uids)):
            need(type(uid) is int and uid >= -1, 'physical source UID')
            if uid < 0:
                need(role > 0 and uid == -1 and name == '#imm_' + str(role + 1),
                     'only the exact native integer literal role is nonfaultable')
                continue
            need(isinstance(name, str) and name not in ('', '_') and not name.startswith('#'),
                 'physical shuffle sources require real register names')
            need(name not in names or names[name] == uid, 'ambiguous simultaneous register names')
            names[name] = uid
            key = row.thread_id, uid
            entry = origins.setdefault(key, dict(lane=lane, name=name, roles=[], value=values[role]))
            need(entry['name'] == name and entry['value'] == values[role], 'joint UID alias value/name mismatch')
            entry['roles'].append(role)
        row_writes = []
        for destination in meta['destinations']:
            width = 32 if destination['role'] == 'data' else 1
            need(destination.get('width_bits') == width
                 and integer(destination.get('write_mask'), width) == (1 << width)-1
                 and type(destination.get('old_value_valid')) is bool, 'full actual destination write/old validity')
            need(type(destination.get('register_uid')) is int and destination['register_uid'] >= 0
                 and isinstance(destination.get('register'), str), 'physical destination identity')
            value = integer(destination['value'], width)
            if destination['old_value_valid']:
                if width == 32:
                    _source_word(destination.get('old_value'), 0, destination['register'], destination['register_uid'])
                else:
                    integer(destination.get('old_value'), width)
            source_alias = [role for role, uid in enumerate(row.src_reg_uids)
                            if uid >= 0 and uid == destination['register_uid']]
            if source_alias:
                need(width == 32 and destination['old_value_valid'] is True
                     and all(row.src_regs[role] == destination['register']
                              and row.src_vals[role] == _source_word(destination['old_value'], 0,
                                  destination['register'], destination['register_uid']) for role in source_alias),
                     'destination alias disagrees with actual pre-group source')
            if width == 1:
                need(destination.get('value_encoding') == 'gpgpu_sim_zero_flag', 'predicate encoding')
                value ^= 1
            row_writes.append(dict(destination, logical_value=value, width=width))
        need(len({(item['register'], item['register_uid']) for item in row_writes}) == len(row_writes), 'duplicate destination')
        need(len({item['register_uid'] for item in row_writes}) == len(row_writes), 'overlapping physical destination UIDs')
        need(len({item['register'] for item in row_writes}) == len(row_writes), 'aliased data/predicate destination names')
        writes.append(row_writes)
    for lane, row in enumerate(rows):
        source, valid = selection(lane, controls[lane][0], controls[lane][1])
        meta = row.shuffle44
        need(type(meta.get('source_lane')) is int and meta.get('source_lane') == source
             and meta.get('in_range') is valid, 'golden route disagrees with native DOWN')
        need(writes[lane][0]['logical_value'] == data[source], 'golden peer value mismatch')
        if len(writes[lane]) == 2:
            need(writes[lane][1]['logical_value'] == int(valid), 'golden predicate mismatch')
    need(len({len(values) for values in writes}) == 1, 'one loaded instruction has inconsistent destination arity')
    return rows, data, controls, writes, origins

def influence(data, controls, origins, downstream):
    """One physical RF bit flips every same-UID read role jointly."""
    need(len(data) == len(controls) == len(downstream) == 32, 'full32 influence vectors')
    need(all(len(values) == 3 and all(type(value) is int and 0 <= value <= MASK for value in values)
             and values[2] == MASK for values in controls), 'defined full32 golden controls')
    need(all(len(values) in (1, 2) and all(len(masks) == 4 for masks in values) for values in downstream), 'data/predicate downstream masks')
    result = {}
    golden = [selection(lane, row[0], row[1]) for lane, row in enumerate(controls)]
    for key, origin in origins.items():
        lane, roles = origin['lane'], origin['roles']
        need(type(lane) is int and 0 <= lane < 32 and roles and len(set(roles)) == len(roles)
             and all(type(role) is int and 0 <= role < 4 for role in roles), 'physical origin roles')
        need(all((data[lane] if role == 0 else controls[lane][role-1]) == origin['value'] for role in roles), 'alias prestate disagreement')
        masks = [0, 0, 0, 0]
        if roles == [0]:
            for destination, (source, _valid) in enumerate(golden):
                if source == lane:
                    for kind in range(4):
                        masks[kind] |= downstream[destination][0][kind]
        elif 3 in roles:
            # Nonuniform/invalid participation can affect convergence or hang
            # even when numeric outputs are dead. Dead data is not a proof of
            # Masked for a physical membermask register outside the contract.
            masks[2] = MASK
        else:
            bits = MASK if 0 in roles else ((31 if 1 in roles else 0) | (0x1f1f if 2 in roles else 0))
            for bit in range(32):
                if not bits & (1 << bit):
                    continue
                b, c, _membermask = controls[lane]
                if 1 in roles:
                    b ^= 1 << bit
                if 2 in roles:
                    c ^= 1 << bit
                affected = range(32) if 0 in roles else (lane,)
                for destination in affected:
                    source, valid = selection(destination, b, c) if destination == lane else golden[destination]
                    value = data[source] ^ ((1 << bit) if 0 in roles and source == lane else 0)
                    old_source, old_valid = golden[destination]
                    differences = (value ^ data[old_source], int(valid) ^ int(old_valid))
                    for role, values in enumerate(downstream[destination]):
                        for kind in range(4):
                            if differences[role] & values[kind]:
                                masks[kind] |= 1 << bit
        result[key] = tuple(value & MASK for value in masks)
    return result


def secondary_predicate(event):
    metadata = getattr(event, 'shuffle44', None)
    if metadata is None or len(metadata['destinations']) != 2:
        return None
    return metadata['destinations'][1]['register']


def predicate_source_masks(event):
    """Value-conditioned route-predicate sensitivity, with same-UID roles joint.

    This supplies the existing control dependency seeder. It does not substitute
    the data result for the optional predicate output or convert non-SDC to M.
    """
    metadata = event.shuffle44
    lane = metadata['lane']
    _source, baseline = selection(lane, event.src_vals[1], event.src_vals[2])
    groups = {}
    for role, uid in enumerate(event.src_reg_uids):
        if uid >= 0:
            groups.setdefault(uid, []).append(role)
    result = [0] * 4
    for roles in groups.values():
        if 3 in roles:
            # One lane's changed membermask violates the finite collective
            # contract; it is uncertainty, never a computed branch outcome.
            mask = MASK
        else:
            mask = 0
            relevant = (31 if 1 in roles else 0) | (0x1f1f if 2 in roles else 0)
            for bit in range(32):
                bit_mask = 1 << bit
                if not relevant & bit_mask:
                    continue
                b = event.src_vals[1] ^ (bit_mask if 1 in roles else 0)
                c = event.src_vals[2] ^ (bit_mask if 2 in roles else 0)
                if selection(lane, b, c)[1] != baseline:
                    mask |= bit_mask
        for role in roles:
            result[role] = mask
    return result


def control_signature(event):
    metadata = event.shuffle44
    return repr((metadata['lane'], tuple(event.src_reg_uids),
                 tuple((row['role'], row['register'], row['register_uid'], row['width_bits'],
                        row['write_mask'], row['value']) for row in metadata['destinations'])))


def destination_writes(event):
    return tuple((row['register'], row['register_uid'], integer(row['write_mask'], row['width_bits']))
                 for row in event.shuffle44['destinations'])


class CollectiveContext:
    """One serial global owner; groups are atomic read-before-all-write nodes."""
    def __init__(self, events):
        self.events = events
        self.ends = set()
        self.skip_start = self.skip_end = -1
        self.groups = self.membermask_unknown_reads = 0
        identities = set()
        position = 0
        while position < len(events):
            event = events[position]
            metadata = getattr(event, 'shuffle44', None)
            if metadata is None:
                position += 1
                continue
            need(metadata['lane'] == 0 and position + 31 < len(events), 'full32 group start/closure required')
            rows, _data, _controls, _writes, _origins = group(events, position + 31)
            identity = rows[0].shuffle44['dynamic_group_id']
            need(identity not in identities, 'dynamic group identity reused')
            identities.add(identity)
            self.ends.add(position + 31)
            position += 32

    def visit(self, position, observed, due, trace, escape, append, emit, profile, compact, seeds,
              elide_zero=False, closed_proofs=None):
        if self.skip_start <= position <= self.skip_end:
            return True, 0, 0
        event = self.events[position]
        if getattr(event, 'shuffle44', None) is None:
            return False, 0, 0
        need(position in self.ends, 'collective event order changed')
        need(not closed_proofs or not any(closed_proofs.get(self.events[index].index)
             for index in range(position - 31, position + 1)),
             'No unqualified closed scalar theorem may override a native collective')
        rows, data, controls, writes, origins = group(self.events, position)
        states = observed, due, trace, escape
        downstream = []
        for lane, row in enumerate(rows):
            downstream.append([tuple(state[row.thread_id].get(destination['register'], 0)
                & ((1 << destination['width']) - 1) for state in states) for destination in writes[lane]])
        # Snapshot ALL destinations before killing ANY aliased source/writer.
        for lane, row in enumerate(rows):
            for destination in writes[lane]:
                mask = (1 << destination['width']) - 1
                for state in states:
                    state[row.thread_id][destination['register']] &= ~mask & old.UINT64_MASK
        inputs = influence(data, controls, origins, downstream)
        for key, origin in origins.items():
            tid, _uid = key
            for channel, state in enumerate(states):
                state[tid][origin['name']] |= inputs[key][channel]
            if 3 in origin['roles'] and inputs[key][2]:
                self.membermask_unknown_reads += 1
        zero_records = zero_bits = 0
        for row in rows:
            for role, (name, uid) in enumerate(zip(row.src_regs, row.src_reg_uids)):
                masks = list(inputs.get((row.thread_id, uid), (0, 0, 0, 0)))
                seed = int(seeds.get((row.thread_id, row.index, 'src', role), 0)) & MASK
                masks[2] |= seed
                trace[row.thread_id][name] |= seed
                if emit:
                    if elide_zero and not (masks[0] | masks[1] | masks[2]):
                        zero_records += 1
                        zero_bits += 32
                        continue
                    append(old.build_internal_read_record(profile=profile, event_index=row.index,
                        thread_id=row.thread_id, cycle=row.cycle, read_kind='src', src_index=role,
                        src_reg=name, src_reg_uid=uid, src_width_bits=32,
                        observed_mask_this_read=masks[0], due_mask_this_read=masks[1],
                        trace_expanding_mask_this_read=masks[2],
                        reg_observed_mask_at_read=observed[row.thread_id].get(name, 0),
                        reg_due_mask_at_read=due[row.thread_id].get(name, 0), sm_id=row.sm_id,
                        cta_id=row.cta_id, warp_id=row.warp_id, pc=row.pc, opcode=row.opcode,
                        compact_compute=compact, notes={'serial_native_full32_DOWN': True,
                            'membermask_undefined_is_uncertainty': role == 3}))
        self.groups += 1
        self.skip_start, self.skip_end = position - 31, position
        return True, zero_records, zero_bits
