"""Exact pinned-native cvt.rni.s32.f32 raw-word scalar conversion.

Native ptx_lm_conversion_ops.h cvt_f32_s32_rni_bits: nearest integer ties-even,
default signed endpoint clamping, NaN -> zero, gradual input subnormals. No
host float conversion or ambient rounding mode. This is local model transfer,
not whole faulted execution replay or a hardware payload guarantee.
"""
WORD = 0xffffffff


def need(value, message):
    if not value:
        raise ValueError(message)


def rni_s32_word(value):
    need(type(value) is int and 0 <= value < 1 << 64, 'RNI native unsigned container required')
    source = value & WORD
    negative = bool(source & 0x80000000)
    exponent, fraction = (source >> 23) & 255, source & 0x7fffff
    if exponent == 255 and fraction:
        return 0
    power = exponent - 127
    if power >= 31:
        return 0x80000000 if negative else 0x7fffffff
    if power < -1:
        return 0
    significand = fraction | 0x800000
    if power >= 23:
        magnitude = significand << (power - 23)
    else:
        shift = 23 - power
        magnitude = significand >> shift
        remainder, midpoint = significand & ((1 << shift) - 1), 1 << (shift - 1)
        magnitude += int(remainder > midpoint or (remainder == midpoint and magnitude & 1))
    return (-magnitude if negative else magnitude) & WORD


def validate_event(event):
    need(event.opcode == 'cvt.rni.s32.f32' and event.kind == 'inst'
         and type(event.width_bits) is int and event.width_bits == 32
         and event.mem_addr is None and event.mem_space_raw is None
         and event.src_width_bits == [32] and type(event.src_width_bits[0]) is int
         and len(event.src_regs) == len(event.src_reg_uids) == len(event.src_vals) == 1
         and type(event.src_reg_uids[0]) is int and event.src_reg_uids[0] > 0
         and isinstance(event.src_regs[0], str) and event.src_regs[0] not in ('', '_')
         and not event.src_regs[0].startswith('#')
         and type(event.dst_reg_uid) is int and event.dst_reg_uid > 0
         and event.dst_reg not in (None, '', '_') and event.dst_write_mask == WORD,
         'RNI exact native scalar32 register form required')
    if event.pred is not None:
        need(type(event.pred.val) is int and event.pred.val in (0, 1)
             and type(event.pred.uid) is int and event.pred.uid > 0, 'RNI actual predicate required')
        if not event.pred.val:
            return None
    baseline = rni_s32_word(event.src_vals[0])
    need(type(event.dst_val) is int and 0 <= event.dst_val < 1 << 64
         and baseline == event.dst_val & WORD, 'RNI normal raw golden mismatch')
    return baseline
