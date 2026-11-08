"""Pinned-native cvt.rzi.f32.f32, integral-valued FLOAT output.

Matches ptx_lm_rzi_eq_ops.h cvt_f32_f32_rzi_bits: truncate fractional bits,
retain the sign of zero, keep infinities, canonicalize all NaNs to 0x7fc00000.
No float-to-int conversion, float approximation or ambient host FP mode is used.
The canonical NaN is the pinned simulator's convention, not a hardware payload
claim. This helper supplies local sensitivity inside the existing SARA model.
"""
WORD = 0xffffffff


def need(value, message):
    if not value:
        raise ValueError(message)


def rzi_f32_word(value):
    need(type(value) is int and 0 <= value < 1 << 64, 'F32 RZI native unsigned container required')
    source = value & WORD
    magnitude, sign = source & 0x7fffffff, source & 0x80000000
    if magnitude > 0x7f800000:
        return 0x7fc00000
    exponent = magnitude >> 23
    if exponent < 127:
        return sign
    if exponent >= 150:
        return source
    discarded = 150 - exponent
    return source & ~((1 << discarded) - 1) & WORD


def validate_event(event):
    need(event.opcode == 'cvt.rzi.f32.f32' and event.kind == 'inst'
         and type(event.width_bits) is int and event.width_bits == 32
         and event.mem_addr is None and event.mem_space_raw is None
         and event.src_width_bits == [32] and type(event.src_width_bits[0]) is int
         and len(event.src_regs) == len(event.src_reg_uids) == len(event.src_vals) == 1
         and type(event.src_reg_uids[0]) is int and event.src_reg_uids[0] > 0
         and isinstance(event.src_regs[0], str) and event.src_regs[0] not in ('', '_')
         and not event.src_regs[0].startswith('#')
         and type(event.dst_reg_uid) is int and event.dst_reg_uid > 0
         and event.dst_reg not in (None, '', '_') and event.dst_write_mask == WORD,
         'F32 RZI exact native scalar32 register form required')
    if event.pred is not None:
        need(type(event.pred.val) is int and event.pred.val in (0, 1)
             and type(event.pred.uid) is int and event.pred.uid > 0, 'F32 RZI actual predicate required')
        if not event.pred.val:
            return None
    baseline = rzi_f32_word(event.src_vals[0])
    need(type(event.dst_val) is int and 0 <= event.dst_val < 1 << 64
         and baseline == event.dst_val & WORD, 'F32 RZI actual raw normal golden mismatch')
    return baseline
