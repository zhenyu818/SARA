"""Closed single-use 32-bit local relations in the existing batch backward pass.

Only a physical low-word version used exclusively as an input of a pure operator,
whose result reaches one second pure operator and a complete final output store,
is supported. Copies may forward the value; fanout/control/address use, partial
copies and subsequent memory consumption refuse the proof. A context table
evaluates only two local arithmetic operators, never a faulted program origin.
There is no manifest, FI answer, empirical threshold or adjustable path budget.
"""
from collections import defaultdict
from functools import lru_cache
from time import perf_counter

WORD = 0xffffffff
POLICY = 'closed_single_use_32bit_local_pair_to_final_output-v3'


@lru_cache(maxsize=None)
def joint_word_effects(first_op, first_values, second_op, second_values,
                       second_slots, input_groups):
    """One cached local relation, keyed by values/alias pattern, never site ID."""
    from script.core import reg_observed_analyzer as api
    baseline_first = api.eval_op_cached(first_op, first_values, 32) & WORD
    if any(second_values[i] != baseline_first for i in second_slots):
        raise ValueError('closed FMA context has inconsistent intermediate words')
    baseline = api.eval_op_cached(second_op, second_values, 32) & WORD
    result = [0] * len(first_values)
    for group in input_groups:
        for bit in range(32):
            first = list(first_values)
            for i in group:
                first[i] ^= 1 << bit
            changed_word = api.eval_op_cached(first_op, tuple(first), 32) & WORD
            second = list(second_values)
            for i in second_slots:
                second[i] = changed_word
            if api.eval_op_cached(second_op, tuple(second), 32) & WORD != baseline:
                for i in group:
                    result[i] |= 1 << bit
    return tuple(result)


def joint_effects(first_op, first_values, second_values, second_slots, input_groups):
    """Compatibility for retained independent F32->FMA validation tools."""
    return joint_word_effects(first_op, first_values, 'FMA_F32', second_values,
                              second_slots, input_groups)


def closed_input_effects(events, output_ranges, *, include_proof_pairs=True):
    """Return proven per-read (resolved mask, SDC mask) plus compact metadata."""
    if type(include_proof_pairs) is not bool:
        raise ValueError('explicit proof-detail output policy required')
    from script.core import reg_observed_analyzer as api
    started = perf_counter()
    # This theorem excludes unobserved inter-kernel host copies/control. The
    # original batch method still analyzes those workloads, without this proof.
    if len({e.kernel_uid for e in events}) != 1:
        return {}, {'policy': POLICY, 'eligible_pairs': 0,
                    'refusal': 'multiple_kernel_boundaries',
                    'analysis_seconds': perf_counter()-started,
                    'per_origin_replay': False, 'FI_answers_used': False}
    definitions = {}
    reads, produced = {}, {}
    uses = defaultdict(set)
    by_index = {e.index: e for e in events}
    last_read = {}
    for e in events:
        if e.opcode.split('.', 1)[0] in ('atom', 'red', 'call', 'callp'):
            return {}, {'policy': POLICY, 'eligible_pairs': 0,
                        'refusal': 'non_scalar_or_interprocedural_memory_effect',
                        'analysis_seconds': perf_counter()-started,
                        'per_origin_replay': False, 'FI_answers_used': False}
        scope = (e.kernel_uid, e.thread_id)
        if e.pred is not None and e.pred.uid is not None and e.pred.uid >= 0:
            uid = e.pred.uid
            version = definitions.get(scope+(uid,), scope+(uid, 'initial'))
            uses[version].add((e.index, 'predicate', -1))
        if e.pred is not None and not e.pred.val:
            continue
        values = []
        for i, uid in enumerate(e.src_reg_uids):
            version = None if uid is None or uid < 0 else definitions.get(
                scope+(uid,), scope+(uid, 'initial'))
            values.append(version)
            if version is not None:
                role = ('store_data' if e.kind == 'store' and i == e.store_data_src_index
                        else 'address' if e.kind in ('store', 'load')
                        else 'source' if e.kind == 'inst' else 'control')
                uses[version].add((e.index, role, i))
        reads[e.index] = tuple(values)
        if e.kind == 'load' and e.mem_addr is not None:
            size = e.mem_access_size_bytes
            if not isinstance(size, int) or not 0 < size <= 8:
                # Unknown-sized memory reads cannot prove a closed output.
                return {}, {'policy': POLICY, 'eligible_pairs': 0,
                            'refusal': 'unbounded_memory_read',
                            'analysis_seconds': perf_counter()-started,
                            'per_origin_replay': False, 'FI_answers_used': False}
            for offset in range(size):
                last_read[e.mem_space, e.mem_addr+offset] = e.index
        if e.dst_reg_uid is not None and e.dst_reg_uid >= 0:
            uid = e.dst_reg_uid
            write = None if e.dst_write_mask is None else int(e.dst_write_mask) & WORD
            # Track the low32 physical value, not merely the register name.
            # A high-word-only write does not replace this value. A partial
            # low-word write retains a dependency on the old low-word version.
            if write == 0:
                continue
            if write != WORD:
                old = definitions.get(scope+(uid,), scope+(uid, 'initial'))
                uses[old].add((e.index, 'partial_old_destination', -1))
            version = scope+(uid, e.index)
            produced[e.index] = version
            definitions[scope+(uid,)] = version

    def full_word(e):
        return (e.dst_write_mask is not None
                and int(e.dst_write_mask) & WORD == WORD)

    def pure_op(e):
        admitted = {'fma.rn.f32': ('FMA_F32', 3),
                    'mul.f32': ('MUL_F32', 2), 'mul.rn.f32': ('MUL_F32', 2),
                    'add.f32': ('ADD_F32', 2), 'add.rn.f32': ('ADD_F32', 2),
                    'sub.f32': ('SUB_F32', 2), 'sub.rn.f32': ('SUB_F32', 2),
                    'add.u32': ('ADD', 2), 'add.s32': ('ADD', 2),
                    'sub.u32': ('SUB', 2), 'sub.s32': ('SUB', 2),
                    'mul.lo.u32': ('MUL_LO', 2), 'mul.lo.s32': ('MUL_LO', 2),
                    'and.b32': ('AND', 2), 'or.b32': ('OR', 2),
                    'xor.b32': ('XOR', 2), 'not.b32': ('NOT', 1)}
        op, arity = admitted.get(e.opcode, (None, 0))
        if (op is None or e.kind != 'inst' or len(e.src_vals) != arity
                or e.src_width_bits != [32]*arity or e.dst_val is None
                or not full_word(e) or (e.pred is not None and e.pred.val != 1)):
            return None
        return op

    forwarded = {}
    def consumer(version):
        """Find the sole non-copy use, preserving every physical copy version."""
        path = []
        while version not in forwarded:
            path.append(version)
            sites = uses.get(version, set())
            ids = {(index, role) for index, role, _ in sites}
            if len(ids) != 1:
                result = None
                break
            index, role = next(iter(ids))
            e = by_index[index]
            slots = tuple(sorted(i for j, r, i in sites if j == index and r == role))
            if (role == 'source' and e.kind == 'inst'
                    and api.canonical_op(e.opcode) == 'IDENTITY'
                    and len(e.src_vals) == 1 and e.src_width_bits == [32]
                    and full_word(e) and index in produced
                    and (e.pred is None or e.pred.val == 1)):
                version = produced[index]
                continue
            result = (index, role, slots)
            break
        else:
            result = forwarded[version]
        for item in path:
            forwarded[item] = result
        return result

    writers = api.build_output_byte_last_writer_index(events, output_ranges)
    effects = {}
    pairs = [] if include_proof_pairs else None
    eligible_pairs = 0
    for p in events:
        op = pure_op(p)
        if op is None or p.index not in produced:
            continue
        next_use = consumer(produced[p.index])
        if next_use is None or next_use[1] != 'source':
            continue
        c = by_index[next_use[0]]
        second_op = pure_op(c)
        if second_op is None or c.index not in produced:
            continue
        final = consumer(produced[c.index])
        if final is None or final[1] != 'store_data':
            continue
        s = by_index[final[0]]
        if (s.kind != 'store' or s.mem_space != 'global'
                or s.mem_addr is None or s.store_size_bytes != 4
                or s.store_data_byte_offset not in (None, 0)
                or len(final[2]) != 1
                or s.src_width_bits[s.store_data_src_index] != 32
                or any(writers.get(('global', s.mem_addr+i)) != s.index
                       or last_read.get(('global', s.mem_addr+i), -1) > s.index
                       for i in range(4))):
            continue
        groups = []
        seen = set()
        for i, version in enumerate(reads[p.index]):
            if version is None or version in seen:
                continue
            seen.add(version)
            sites = uses[version]
            if {(index, role) for index, role, _ in sites} == {(p.index, 'source')}:
                groups.append(tuple(j for j, v in enumerate(reads[p.index]) if v == version))
        if not groups:
            continue
        pv = tuple(int(v) & WORD for v in p.src_vals)
        cv = tuple(int(v) & WORD for v in c.src_vals)
        if (api.eval_op_cached(op, pv, 32) & WORD != int(p.dst_val) & WORD
                or api.eval_op_cached(second_op, cv, 32) & WORD != int(c.dst_val) & WORD):
            raise api.SemanticMismatchError('closed local-pair golden differs')
        observed = joint_word_effects(op, pv, second_op, cv, next_use[2], tuple(groups))
        for group in groups:
            for i in group:
                effects[(int(p.thread_id), p.index, 'src', i)] = (WORD, observed[i])
        eligible_pairs += 1
        if include_proof_pairs:
            pairs.append({'producer': p.index, 'consumer': c.index, 'first_op': op,
                          'second_op': second_op,
                          'final_store': s.index, 'input_groups': groups,
                          'consumer_slots': next_use[2]})
    return effects, {'policy': POLICY, 'eligible_pairs': eligible_pairs,
                     'resolved_read_count': len(effects),
                     'resolved_local_input_bits': 32*len(effects),
                     'local_contexts_cached': joint_word_effects.cache_info().currsize,
                     **({'proof_pairs': pairs} if include_proof_pairs else {}),
                     'analysis_seconds': perf_counter()-started,
                     'per_origin_replay': False, 'FI_answers_used': False,
                     'proof': 'single_physical_value_use;pure_32bit_local_pair;full_word_copy;final_checked_store;no_later_output_load'}
