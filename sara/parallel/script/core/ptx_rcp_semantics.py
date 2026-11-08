"""Integer-only nearest-even reciprocal for the CPU simulator's binary32 model.

Only rcp.rn.f32 is admitted by the batch analyzer. NaNs use the same chosen
canonical payload as ptx_sfu_ops.h; no native-GPU NaN identity is claimed.
This instruction transfer is reused by batch propagation, never origin replay.
"""

def rcp_rn_f32(bits):
    if type(bits) is not int or not 0 <= bits < 1 << 32:
        raise ValueError('one raw binary32 word required')
    sign, magnitude = bits & 0x80000000, bits & 0x7fffffff
    if magnitude > 0x7f800000: return 0x7fc00000
    if magnitude == 0: return sign | 0x7f800000
    if magnitude == 0x7f800000: return sign
    field = magnitude >> 23
    significand = (magnitude & 0x7fffff) | (0x800000 if field else 0)
    power = field - 150 if field else -149
    numerator = 1 << max(-power, 0)
    denominator = significand << max(power, 0)
    exponent = numerator.bit_length() - denominator.bit_length()
    below = numerator < denominator << exponent if exponent >= 0 else numerator << -exponent < denominator
    if below:
        exponent -= 1
    shift = 149 if exponent < -126 else 23-exponent
    n, d = numerator << max(shift,0), denominator << max(-shift,0)
    rounded, remainder = divmod(n,d)
    if 2*remainder > d or (2*remainder == d and rounded & 1): rounded += 1
    if exponent < -126: return sign | rounded
    if rounded == 1 << 24: rounded >>= 1; exponent += 1
    if exponent > 127: return sign | 0x7f800000
    return sign | ((exponent+127) << 23) | (rounded-(1 << 23))
