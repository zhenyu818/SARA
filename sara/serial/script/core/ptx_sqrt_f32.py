"""Correctly rounded binary32 sqrt for finite nonnegative inputs.

Pure integer arithmetic; no host float, libm, simulator, mutation or authority.
The caller must independently bind the exact sqrt.rn.f32 instruction and its
execution/numeric context. Its instruction domain remains explicit at the call site.
"""
from math import isqrt


def sqrt_rn_f32(bits):
    """Return raw RNE binary32 bits, preserving the sign of zero.

    For x=m*2**p and e=floor(log2(x)/2), the unrounded 24-bit
    significand is sqrt(m*2**(p-2*e+46)). That integer radicand is
    exact, including for subnormal inputs. Its integer square root q
    is rounded by comparing 4*n with (2*q+1)**2. Carry normalizes q.
    Every nonzero finite binary32 input has a normal binary32 square
    root, so no output underflow or host floating-point state is involved.
    """
    if type(bits) is not int or not 0 <= bits < 1 << 32:
        raise ValueError('sqrt_rn_f32_requires_one_raw_u32')
    magnitude = bits & 0x7fffffff
    if magnitude == 0:
        return bits
    if bits & 0x80000000 or magnitude >= 0x7f800000:
        raise ValueError('sqrt_rn_f32_outside_finite_nonnegative_domain')
    exponent = (bits >> 23) & 0xff
    mantissa = bits & 0x7fffff
    if exponent:
        mantissa |= 1 << 23
        power = exponent - 150
    else:
        power = -149
    result_exponent = (mantissa.bit_length() - 1 + power) // 2
    shift = power - 2 * result_exponent + 46
    if shift < 0:
        raise ArithmeticError('sqrt_rn_f32_internal_exact_scaling_failure')
    radicand = mantissa << shift
    significand = isqrt(radicand)
    comparison = (radicand << 2) - (2 * significand + 1) ** 2
    if comparison > 0 or comparison == 0 and significand & 1:
        significand += 1
    if significand == 1 << 24:
        significand >>= 1
        result_exponent += 1
    if not (1 << 23 <= significand < 1 << 24 and -126 <= result_exponent <= 127):
        raise ArithmeticError('sqrt_rn_f32_internal_normal_result_failure')
    return ((result_exponent + 127) << 23) | (significand - (1 << 23))
