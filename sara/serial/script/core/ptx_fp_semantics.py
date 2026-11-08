"""Finite binary32 PTX arithmetic with one explicit nearest-even rounding.

This is a preparation backend, NOT a certificate for replay classification.
The analyzer/replay allowlists intentionally remain unchanged until independent
GPU PTX conformance evidence has been reviewed for the target architecture.

Operands/results are unsigned raw IEEE-754 binary32 bit patterns. All arithmetic
uses Python integers: finite inputs decode to signed integer * 2**exponent;
FMA forms its exact product and sum before a single final binary32 rounding.
No Python float, math.fma, libc/fenv, or multiply-then-add fallback is used.
Thus external-library availability and the host floating-point environment do
not affect results. Requesting any unavailable backend returns Unknown.

Model scope: one decoded PTX instruction on sm_20+, add/sub/mul with default or
explicit .rn, and fma with explicit .rn. Canonical .ftz then .sat modifiers are
accepted, subject to the conservative exclusions below. Inputs containing any
NaN (including payloads) or infinity, other rounding modes/types/operations,
and legacy sm_1x behavior are unsupported. A finite-input overflow may produce
an infinity result; using it as a later input remains unsupported. Saturation
of negative zero is deliberately unsupported pending a signed-zero contract.

Normative basis: NVIDIA CUDA 11.8 PTX ISA 7.8, floating-point add/sub/mul/fma
sections (9.7.3.3--6), single rounding, default RN, and sign-preserving FTZ:
https://docs.nvidia.com/cuda/archive/11.8.0/parallel-thread-execution/index.html
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Optional, Sequence

BACKEND_ID = "integer-dyadic-binary32-rn-v1"
GPU_CONFORMANCE_REQUIRED = True
_SIGN = 0x80000000
_EXP = 0x7F800000
_FRAC = 0x007FFFFF
_ONE = 0x3F800000
_PATTERN = re.compile(r"(?:(add|sub|mul)(?:\.rn)?|fma\.rn)(\.ftz)?(\.sat)?\.f32\Z")


class UnsupportedFP32(ValueError):
    """Instruction/input semantics are outside the implemented finite model."""


class UnknownFP32(RuntimeError):
    """Required target/backend evidence is unavailable; never a guessed value."""


@dataclass(frozen=True)
class FP32Result:
    status: str
    bits: Optional[int] = None
    reason: str = ""
    backend: Optional[str] = BACKEND_ID
    # A supported model calculation is not GPU conformance certification.
    certified: bool = False

    def require_bits(self) -> int:
        """Convenience adapter which cannot silently consume Unknown results."""
        if self.status == "unsupported":
            raise UnsupportedFP32(self.reason)
        if self.status != "supported" or self.bits is None:
            raise UnknownFP32(self.reason)
        return self.bits


def _flush_subnormal(bits: int) -> int:
    return bits & _SIGN if bits & _EXP == 0 and bits & _FRAC else bits


def _decode(bits: int):
    fraction, exponent = bits & _FRAC, (bits & _EXP) >> 23
    significand = fraction if exponent == 0 else fraction | (1 << 23)
    return (-significand if bits & _SIGN else significand,
            -149 if exponent == 0 else exponent - 150)


def _round_scaled(magnitude: int, shift: int) -> int:
    """Round magnitude * 2**shift to an integer, ties to even."""
    if shift >= 0:
        return magnitude << shift
    divisor = 1 << -shift
    quotient, remainder = divmod(magnitude, divisor)
    twice = remainder << 1
    return quotient + (twice > divisor or (twice == divisor and bool(quotient & 1)))


def _round_binary32(coefficient: int, exponent: int, zero_sign: int = 0) -> int:
    if coefficient == 0:
        return zero_sign & _SIGN
    sign = _SIGN if coefficient < 0 else 0
    magnitude = abs(coefficient)
    leading_exponent = magnitude.bit_length() - 1 + exponent
    if leading_exponent < -126:
        # Every subnormal is an integer multiple of 2**-149. A carry into bit
        # 23 naturally becomes the smallest normal, without double rounding.
        significand = _round_scaled(magnitude, exponent + 149)
        return sign | significand
    significand = _round_scaled(magnitude, exponent - leading_exponent + 23)
    if significand == 1 << 24:
        significand >>= 1
        leading_exponent += 1
    if leading_exponent > 127:
        return sign | _EXP
    return sign | ((leading_exponent + 127) << 23) | (significand - (1 << 23))


def _sum(left, right):
    exponent = min(left[1], right[1])
    coefficient = ((left[0] << (left[1] - exponent))
                   + (right[0] << (right[1] - exponent)))
    return coefficient, exponent


def evaluate_fp32(opcode: str, operand_bits: Sequence[int], *,
                  target_sm: Optional[int] = None,
                  backend: Optional[str] = BACKEND_ID) -> FP32Result:
    """Return supported raw bits, explicit Unsupported, or explicit Unknown.

    ``opcode`` must be the complete PTX arithmetic token (e.g.
    ``fma.rn.ftz.f32``), not a canonicalized opcode with modifiers removed.
    ``target_sm`` is an integer such as 75/86; omission is Unknown. Backend
    selection never silently falls back. ``supported`` describes this finite
    integer model only; ``certified`` is always False in this execution.
    """
    def unsupported(reason):
        return FP32Result("unsupported", reason=reason, backend=backend)

    if backend != BACKEND_ID:
        return FP32Result("unknown", reason="backend_unavailable", backend=backend)
    if target_sm is None:
        return FP32Result("unknown", reason="target_sm_required")
    if type(target_sm) is not int or target_sm < 20:
        return unsupported("target_sm_outside_sm20_plus_model")
    if not isinstance(opcode, str):
        return unsupported("opcode_must_be_complete_ptx_token")
    match = _PATTERN.fullmatch(opcode)
    if match is None:
        return unsupported("opcode_type_rounding_or_modifier_not_supported")
    operation = match.group(1) or "fma"
    ftz, sat = bool(match.group(2)), bool(match.group(3))
    try:
        operands = tuple(operand_bits)
    except TypeError:
        return unsupported("operands_must_be_raw_u32_sequence")
    if len(operands) != (3 if operation == "fma" else 2):
        return unsupported("operand_count_mismatch")
    if any(type(bits) is not int or not 0 <= bits <= 0xFFFFFFFF for bits in operands):
        return unsupported("operands_must_be_raw_u32")
    if any(bits & _EXP == _EXP for bits in operands):
        return unsupported("nonfinite_input_or_nan_payload_not_supported")
    if ftz:
        operands = tuple(_flush_subnormal(bits) for bits in operands)
    if operation == "sub":
        operands = (operands[0], operands[1] ^ _SIGN)
        operation = "add"
    decoded = tuple(_decode(bits) for bits in operands)
    if operation == "mul":
        coefficient = decoded[0][0] * decoded[1][0]
        exponent = decoded[0][1] + decoded[1][1]
        zero_sign = (operands[0] ^ operands[1]) & _SIGN
    elif operation == "add":
        coefficient, exponent = _sum(decoded[0], decoded[1])
        # RN cancellation is +0; only -0 plus -0 produces exact -0.
        zero_sign = _SIGN if all(bits == _SIGN for bits in operands) else 0
    else:
        product = (decoded[0][0] * decoded[1][0], decoded[0][1] + decoded[1][1])
        coefficient, exponent = _sum(product, decoded[2])
        # FMA zero signs follow addition of the exact product and addend.
        product_sign = (operands[0] ^ operands[1]) & _SIGN
        zero_sign = _SIGN if product[0] == 0 and product_sign and operands[2] == _SIGN else 0
    result = _round_binary32(coefficient, exponent, zero_sign)
    if ftz:
        result = _flush_subnormal(result)
    if sat:
        if result == _SIGN:
            return unsupported("sat_negative_zero_requires_conformance_contract")
        if result & _SIGN:
            result = 0
        elif result > _ONE:
            result = _ONE
    return FP32Result("supported", bits=result)
