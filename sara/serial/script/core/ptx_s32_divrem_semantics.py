"""Exact pinned-simulator S32 quotient/remainder, not generic PTX authority.

Negative remainder follows the explicitly chosen toward-zero common model.
The two excluded pairs are refused before arithmetic, never FI DUE. Callers
retain their explicit error/Unknown boundary; the batch REM adapter below
fails incomplete instead of inventing class masks for an unavailable domain.
"""
from ptx_bfi_semantics import uint, require

OPCODES = frozenset(("div.s32", "rem.s32"))


class S32DivRemDomainUnavailable(NotImplementedError):
    pass


def operands(event, values):
    require(event.opcode in OPCODES and event.kind == "inst" and type(event.width_bits) is int and event.width_bits == 32
            and event.mem_addr is None and event.mem_space_raw is None and event.src_width_bits == [32, 32]
            and all(type(width) is int for width in event.src_width_bits)
            and len(values) == len(event.src_regs) == len(event.src_reg_uids) == 2
            and all(type(uid) is int and uid > 0 for uid in event.src_reg_uids)
            and all(isinstance(name, str) and name not in ("", "_") and not name.startswith("#") for name in event.src_regs)
            and event.dst_reg not in (None, "_") and type(event.dst_reg_uid) is int and event.dst_reg_uid > 0
            and event.dst_write_mask == 0xffffffff, "s32_DIV_REM_exact_full_register_shape_required")
    words = [uint(value) & 0xffffffff for value in values]
    return [word - (1 << 32) if word & 0x80000000 else word for word in words]


def require_domain(event, values):
    a, b = operands(event, values)
    if b == 0 or (a == -(1 << 31) and b == -1):
        reason = ("signed32_divisor_or_overflow_unmodeled" if event.opcode == "div.s32"
                  else "signed32_remainder_divisor_or_overflow_unmodeled")
        raise S32DivRemDomainUnavailable(reason)
    return a, b


def remainder_s32_words(left, right):
    """Pinned native scalar_rem_s32 convention; never Python signed modulo."""
    words = [uint(value) & 0xffffffff for value in (left, right)]
    a, b = [word - (1 << 32) if word & 0x80000000 else word for word in words]
    if b == 0 or (a == -(1 << 31) and b == -1):
        raise S32DivRemDomainUnavailable("signed32_remainder_divisor_or_overflow_unmodeled")
    quotient = abs(a) // abs(b)
    if (a < 0) != (b < 0):
        quotient = -quotient
    return (a - b * quotient) & 0xffffffff


def validate_batch_rem_s32_event(event):
    """Functional shape/golden only; assembled-IR authority is checked outside.

    This uniform trace precheck precedes both ordinary and basic-block paths.
    Domain errors in later local single-bit evaluations stay explicit failures,
    never invented fault DUE, zero values or all-Unknown replacement masks.
    """
    require(event.opcode == "rem.s32", "batch_REM_exact_s32_opcode_required")
    operands(event, event.src_vals)
    require(len(event.src_vals) == 2 and all(type(value) is int and 0 <= value < (1 << 64)
            for value in event.src_vals), "batch_REM_raw_consumed_words_required")
    if event.pred is not None:
        require(type(event.pred.val) is int and event.pred.val in (0, 1)
                and type(event.pred.uid) is int and event.pred.uid > 0,
                "batch_REM_actual_effective_predicate_required")
        if event.pred.val == 0:
            return None
    require(type(event.dst_val) is int and 0 <= event.dst_val < (1 << 64),
            "batch_REM_executed_result_required")
    for first in range(2):
        for second in range(first):
            if event.src_reg_uids[first] == event.src_reg_uids[second]:
                require((event.src_vals[first] & 0xffffffff) == (event.src_vals[second] & 0xffffffff),
                        "batch_REM_same_UID_consumed_words_disagree")
    baseline = remainder_s32_words(*event.src_vals)
    require(baseline == (event.dst_val & 0xffffffff), "batch_REM_native_golden_value_mismatch")
    return baseline


def evaluate_s32_divrem(event, values):
    a, b = require_domain(event, values)
    # Python signed // floors; divide magnitudes, then apply the chosen sign.
    quotient = abs(a) // abs(b)
    if (a < 0) != (b < 0): quotient = -quotient
    result = quotient if event.opcode == "div.s32" else a - b * quotient
    return result & 0xffffffff

def quotient_s32_words(left, right):
    """Pinned native scalar_div_s32, signed quotient rounded toward zero."""
    words = [uint(value) & 0xffffffff for value in (left, right)]
    a, b = [word - (1 << 32) if word & 0x80000000 else word for word in words]
    if b == 0 or (a == -(1 << 31) and b == -1):
        raise S32DivRemDomainUnavailable("signed32_divisor_or_overflow_unmodeled")
    quotient = abs(a) // abs(b)
    if (a < 0) != (b < 0):
        quotient = -quotient
    return quotient & 0xffffffff


def validate_batch_div_s32_event(event):
    """DIV functional shape/golden precheck; actual IR authority is external.

    The analyzer calls this before its ordinary/basic-block route split.
    It does not declare unknown or produce masks for an excluded native domain.
    """
    require(event.opcode == "div.s32", "batch_DIV_exact_s32_opcode_required")
    operands(event, event.src_vals)
    require(len(event.src_vals) == 2 and all(type(value) is int and 0 <= value < (1 << 64)
            for value in event.src_vals), "batch_DIV_raw_consumed_words_required")
    if event.pred is not None:
        require(type(event.pred.val) is int and event.pred.val in (0, 1)
                and type(event.pred.uid) is int and event.pred.uid > 0,
                "batch_DIV_actual_effective_predicate_required")
        if event.pred.val == 0:
            return None
    require(type(event.dst_val) is int and 0 <= event.dst_val < (1 << 64),
            "batch_DIV_executed_result_required")
    for first in range(2):
        for second in range(first):
            if event.src_reg_uids[first] == event.src_reg_uids[second]:
                require((event.src_vals[first] & 0xffffffff) == (event.src_vals[second] & 0xffffffff),
                        "batch_DIV_same_UID_consumed_words_disagree")
    baseline = quotient_s32_words(*event.src_vals)
    require(baseline == (event.dst_val & 0xffffffff), "batch_DIV_native_golden_value_mismatch")
    return baseline
