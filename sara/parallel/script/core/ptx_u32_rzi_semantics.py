"""One exact raw-word CVT backend; neutral facts never grant replay scope.

The independent Fraction/literal oracle lives in execution/lm_uint_conversion_oracle.
No host floating arithmetic, caller opcode allowlist or observed-output fallback.
"""
from ptx_bfi_semantics import uint, require

OPCODE = "cvt.rzi.u32.f32"


def u32_rzi_word(source):
    """Pinned native raw32 truncation and default unsigned destination clamp.

    This is total on all raw binary32 words, including NaN/Inf/subnormal and
    negative encodings. It never converts through a host floating-point type.
    A trace container's unused high32 bits do not belong to the consumed word.
    """
    source = uint(source) & 0xffffffff
    exponent, fraction = (source >> 23) & 255, source & 0x7fffff
    if exponent == 255 and fraction:
        return 0
    if source >> 31:
        return 0
    power = exponent - 127
    if power < 0:
        return 0
    if power >= 32:
        return 0xffffffff
    significand = fraction | 0x800000
    return significand << (power - 23) if power >= 23 else significand >> (23 - power)


def evaluate_u32_rzi(event, values):
    require(event.opcode == OPCODE and event.kind == "inst" and event.width_bits == 32
            and len(event.src_width_bits) == 1 and type(event.src_width_bits[0]) is int and event.src_width_bits == [32] and len(values) == len(event.src_regs) == 1
            and len(event.src_reg_uids) == 1 and type(event.src_reg_uids[0]) is int
            and event.src_reg_uids[0] > 0 and not event.src_regs[0].startswith("#")
            and event.dst_reg not in (None, "_") and type(event.dst_reg_uid) is int and event.dst_reg_uid > 0
            and event.dst_write_mask == 0xffffffff and event.mem_addr is None and event.mem_space_raw is None,
            "u32_RZI_exact_full_register_shape_required")
    return u32_rzi_word(values[0])


def validate_batch_u32_rzi_event(event):
    """Full-reg functional/normal check shared by ordinary and block transfer.

    Actual assembled-IR/producer admission remains an independent check. This
    accepts only the native register32 RZI form, never other CVT qualifiers.
    """
    require(type(event.width_bits) is int and event.width_bits == 32
            and isinstance(event.dst_reg, str) and event.dst_reg not in ("", "_")
            and len(event.src_regs) == 1 and isinstance(event.src_regs[0], str)
            and event.src_regs[0] not in ("", "_")
            and len(event.src_vals) == 1 and type(event.src_vals[0]) is int
            and 0 <= event.src_vals[0] < (1 << 64),
            "batch_u32_RZI_full_raw_consumed_word_required")
    baseline = evaluate_u32_rzi(event, event.src_vals)
    if event.pred is not None:
        require(type(event.pred.val) is int and event.pred.val in (0, 1)
                and type(event.pred.uid) is int and event.pred.uid > 0,
                "batch_u32_RZI_actual_effective_predicate_required")
        if event.pred.val == 0:
            return None
    require(type(event.dst_val) is int and 0 <= event.dst_val < (1 << 64),
            "batch_u32_RZI_executed_result_required")
    require(baseline == (event.dst_val & 0xffffffff),
            "batch_u32_RZI_native_golden_value_mismatch")
    return baseline
