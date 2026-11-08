"""Exact scalar integer load extension, with explicit container evidence.

PTX ISA 7.8, ld: signed values sign-extend; unsigned/bit values zero-extend
to the declared destination. This module does not infer register width from a
golden value or certify a memory address, volatile ordering, or a fault origin.
"""
import re


def scalar_load_value(opcode, value, *, access_bytes, destination_bits,
                      write_mask, declared_width_verified=False,
                      single_thread_shared=False):
    match = re.fullmatch(r"ld\.(volatile\.)?(global|shared|local|const|param)\.([busf])(8|16|32|64)", opcode)
    if match is None:
        raise NotImplementedError("scalar load opcode/modifiers not modeled")
    volatile, space, kind, bits = match.groups()
    bits = int(bits)
    if volatile and (space != "shared" or single_thread_shared is not True):
        raise NotImplementedError("volatile visibility not certified")
    if (type(destination_bits) is not int or destination_bits not in (8, 16, 32, 64)
            or destination_bits < bits or access_bytes * 8 != bits
            or type(write_mask) is not int or write_mask != (1 << destination_bits) - 1):
        raise NotImplementedError("load width/write contract incomplete")
    if destination_bits != bits and (declared_width_verified is not True or kind == "f"):
        raise NotImplementedError("declared extension width not certified")
    if kind == "f" and bits not in (32, 64):
        raise NotImplementedError("floating load format not modeled")
    value = int(value) & ((1 << bits) - 1)
    if kind == "s" and value & (1 << (bits - 1)):
        value -= 1 << bits
    return value & ((1 << destination_bits) - 1)
