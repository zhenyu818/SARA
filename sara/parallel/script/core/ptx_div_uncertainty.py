"""DIV/REM local transfer on the pinned native signed32 model.

The normal quotient is the previously qualified Render03 implementation.
Native-excluded zero-divisor and INT_MIN/-1 *mutations* have no fabricated
quotient or hard class: their precise physical input bit enters the existing
trace/uncertainty channel even for a dead numeric output: an unmodeled
execution-domain mutation is not proved Masked by numeric liveness. An executed golden
instruction outside the native domain remains an admission failure.
"""
from functools import lru_cache

from ptx_s32_divrem_semantics import (
    quotient_s32_words, remainder_s32_words, validate_batch_div_s32_event,
    validate_batch_rem_s32_event, S32DivRemDomainUnavailable)

WORD = (1 << 32) - 1
POLICY = 'sara-serial-signed32-div-rem-defined-local-domain-uncertainty-v3'
CAPABILITIES = dict(raw_opcode='div.s32', width_bits=32,
    normal_rule='Render03_qualified_truncate_toward_zero_signed32_quotient',
    normal_reference_helper_sha256='f945adf804ba2e965a93c7c408217119d1f03511b3fd442b5ba823bb55769e65',
    undefined_mutation='only_the_mutated_physical_input_bit_to_existing_uncertainty_including_dead_numeric_output',
    undefined_predicate_activation='predicate_bit_to_existing_uncertainty',
    baseline_undefined='refuse', same_UID_sources='joint_same_physical_bit_mutation',
    nonfault_literals='excluded_from_RF_input_bit_mutations', basic_block='opaque_instruction_boundary',
    embedded_effective_address_DIV='not_admitted', inferred_FI_outcome=False)


def need(value, message):
    if not value:
        raise ValueError(message)


def words(values):
    need(len(values) == 2 and all(type(value) is int and 0 <= value < 1 << 64 for value in values),
         'DIV requires two native consumed words')
    return tuple(value & WORD for value in values)


def undefined_reason(values):
    left, right = words(values)
    if right == 0:
        return 'native_signed32_zero_divisor_unmodeled'
    if left == 0x80000000 and right == WORD:
        return 'native_signed32_minimum_over_minus_one_unmodeled'
    return None


def validate_event(event):
    return _validate_event(event, 'div.s32')


def validate_remainder_event(event):
    return _validate_event(event, 'rem.s32')


def evaluate(values, operation):
    need(operation in ('div.s32', 'rem.s32'), 'Exact signed32 DIV/REM operation required')
    return (quotient_s32_words if operation == 'div.s32' else remainder_s32_words)(*values)


def _validate_event(event, operation):
    """Actual scalar shape and normal golden; no mutation class is issued here."""
    need(event.opcode == operation and event.kind == 'inst' and type(event.width_bits) is int
         and event.width_bits == 32 and event.mem_addr is None and event.mem_space_raw is None
         and event.src_width_bits == [32, 32] and all(type(width) is int for width in event.src_width_bits)
         and len(event.src_regs) == len(event.src_reg_uids) == 2
         and event.dst_reg not in (None, '_') and type(event.dst_reg_uid) is int and event.dst_reg_uid > 0
         and event.dst_write_mask == WORD, 'DIV exact native scalar32 form required')
    values = words(event.src_vals)
    literal = []
    for index, (name, uid) in enumerate(zip(event.src_regs, event.src_reg_uids), 1):
        is_literal = (type(name) is str and name == '#imm_' + str(index)
                      and type(uid) is int and uid == -1)
        is_register = (type(name) is str and name not in ('', '_') and not name.startswith('#')
                       and type(uid) is int and uid > 0)
        need(is_literal or is_register, 'DIV source must be an actual RF register or bound native integer literal')
        literal.append(is_literal)
    if event.src_reg_uids[0] == event.src_reg_uids[1] and not any(literal):
        need(values[0] == values[1], 'DIV repeated source UID has inconsistent consumed words')
    if event.pred is not None:
        need(type(event.pred.val) is int and event.pred.val in (0, 1)
             and type(event.pred.uid) is int and event.pred.uid > 0, 'DIV actual predicate required')
        if event.pred.val == 0:
            return dict(executed=False, baseline=None, excluded_activation_reason=undefined_reason(values))
    # Preserve the already qualified register-only golden check verbatim.
    if not any(literal):
        baseline = (validate_batch_div_s32_event if operation == 'div.s32' else validate_batch_rem_s32_event)(event)
    else:
        need(type(event.dst_val) is int and 0 <= event.dst_val < 1 << 64,
             'DIV actual golden destination word required')
        baseline = evaluate(values, operation)
        need(baseline == event.dst_val & WORD, 'DIV native literal-form golden mismatch')
    return dict(executed=True, baseline=baseline, excluded_activation_reason=None)


def _groups(aliases, nonfault):
    seen = set()
    for group in aliases:
        need(type(group) is tuple and len(group) >= 2 and len(set(group)) == len(group)
             and all(type(index) is int and 0 <= index < 2 and index not in seen for index in group),
             'DIV disjoint physical source alias groups required')
        need(not any(nonfault[index] for index in group), 'DIV physical alias cannot include a literal')
        seen.update(group)
    return aliases + tuple((index,) for index in range(2) if index not in seen)


@lru_cache(maxsize=65536)
def _transfer(values, recorded, observed, due, uncertain, aliases, nonfault, operation='div.s32'):
    baseline = evaluate(values, operation)
    need(recorded is None or baseline == recorded & WORD, 'DIV local transfer golden mismatch')
    outputs = [[0, 0] for _ in range(3)]
    undefined = [0, 0]
    excluded_cases = 0
    for group in _groups(aliases, nonfault):
        need(all(values[index] == values[group[0]] for index in group),
             'DIV repeated physical source UID has inconsistent words')
        if all(nonfault[index] for index in group):
            continue
        for bit in range(32):
            changed = list(values)
            for index in group:
                changed[index] ^= 1 << bit
            reason = undefined_reason(changed)
            if reason is not None:
                excluded_cases += 1
                for index in group:
                    undefined[index] |= 1 << bit
                    # Numeric deadness is not a proof that an unavailable
                    # execution-domain mutation is harmless. Only this exact
                    # physical bit is uncertain, not all inputs or DIVs.
                    outputs[2][index] |= 1 << bit
                continue
            delta = baseline ^ evaluate(changed, operation)
            for output, mask in zip(outputs, (observed, due, uncertain)):
                if delta & mask:
                    for index in group:
                        output[index] |= 1 << bit
    return tuple(tuple(row) for row in outputs), tuple(undefined), excluded_cases


def transfer_triplet(values, recorded, observed, due, uncertain, width, widths, aliases=(), nonfault=(), operation='div.s32'):
    need(type(width) is int and width == 32 and tuple(widths) == (32, 32)
         and all(type(value) is int for value in widths), 'DIV two full signed32 inputs required')
    values = words(values)
    nonfault = tuple(nonfault) if nonfault else (False, False)
    need(len(nonfault) == 2 and all(type(value) is bool for value in nonfault), 'DIV two nonfault-source flags required')
    outputs, _undefined, _count = _transfer(values, None if recorded is None else int(recorded) & WORD,
        int(observed) & WORD, int(due) & WORD, int(uncertain) & WORD, tuple(aliases), nonfault, operation)
    return tuple(list(row) for row in outputs)


def empty_diagnostics(operation='div.s32'):
    need(operation in ('div.s32', 'rem.s32'), 'Exact signed32 DIV/REM diagnostics required')
    capabilities = dict(CAPABILITIES)
    if operation == 'rem.s32':
        capabilities.update(raw_opcode='rem.s32',
            normal_rule='Render03_qualified_toward_zero_signed32_remainder',
            basic_block='opaque_instruction_boundary', embedded_effective_address_REM='not_admitted')
    return dict(policy=POLICY, operation=operation, capabilities=capabilities, dynamic_events_checked=0,
        executed_golden_events_checked=0, predicated_off_events=0,
        potential_undefined_physical_input_mutations=0, potential_undefined_source_read_bits=0,
        unavailable_predicate_activations=0, by_pc={},
        count_scope='this_operation_only_local_dynamic_instruction_mutation_cases;not_population_mass_or_disjoint_origins',
        global_Unknown_mass_delta_against_prior_failed_whole=None,
        prior_failed_whole_has_no_complete_classification_baseline=True)


def diagnostic_undefined_mutations(values, aliases=(), nonfault=()):
    """Count the two excluded domain targets, not every defined quotient.

    This is an audit-count identity only. Classification still uses the
    unchanged value-conditioned transfer_triplet. Each group is one physical
    source, so an aliased read contributes one case and two source-read bits.
    """
    values = words(values)
    flags = tuple(nonfault) if nonfault else (False, False)
    need(len(flags) == 2 and all(type(value) is bool for value in flags),
         'DIV two nonfault-source flags required')
    need(undefined_reason(values) is None, 'DIV diagnostics require a defined golden domain')
    masks, cases = [0, 0], 0
    for group in _groups(tuple(aliases), flags):
        need(all(values[index] == values[group[0]] for index in group),
             'DIV repeated physical source UID has inconsistent words')
        if all(flags[index] for index in group):
            continue
        bits = set()
        divisor = values[1]
        if 1 in group and divisor and not divisor & (divisor - 1):
            bits.add(divisor)
        differences = []
        possible = True
        for index, target in enumerate((0x80000000, WORD)):
            delta = values[index] ^ target
            if index in group:
                possible &= bool(delta and not delta & (delta - 1))
                differences.append(delta)
            else:
                possible &= delta == 0
        if possible and len(set(differences)) == 1:
            bits.add(differences[0])
        for bit_mask in bits:
            cases += 1
            for index in group:
                masks[index] |= bit_mask
    return tuple(masks), cases


def record_event(diagnostics, event, aliases=(), nonfault=()):
    operation = diagnostics.get('operation', 'div.s32')
    info = _validate_event(event, operation)
    diagnostics['dynamic_events_checked'] += 1
    pc = str(event.pc)
    row = diagnostics['by_pc'].setdefault(pc, dict(events=0, potential_undefined_physical_inputs=0,
        undefined_source_bit_union=[0, 0], unavailable_predicate_activations=0))
    row['events'] += 1
    if not info['executed']:
        diagnostics['predicated_off_events'] += 1
        if info['excluded_activation_reason'] is not None:
            diagnostics['unavailable_predicate_activations'] += 1
            row['unavailable_predicate_activations'] += 1
        return info, (0, 0)
    diagnostics['executed_golden_events_checked'] += 1
    flags = tuple(nonfault) if nonfault else (False, False)
    undefined, cases = diagnostic_undefined_mutations(event.src_vals, tuple(aliases), flags)
    diagnostics['potential_undefined_physical_input_mutations'] += cases
    diagnostics['potential_undefined_source_read_bits'] += sum(bin(mask).count('1') for mask in undefined)
    row['potential_undefined_physical_inputs'] += cases
    for index, mask in enumerate(undefined):
        row['undefined_source_bit_union'][index] |= mask
    return info, undefined
