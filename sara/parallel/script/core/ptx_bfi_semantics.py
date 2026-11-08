"""Exact scalar BFI bits and actual-IR consistency; no admission authority.

PTX ISA 7.8 / CUDA 11.8, documentation.1.20: c and d are u32;
their low eight bits select the position and length. This Python backend
does not call the common C++ helper or a host floating-point implementation.
"""
import re


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def uint(value, bits=64):
    if isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]+|[0-9]+", value):
        value = int(value, 16 if value.startswith("0x") else 10)
    require(type(value) is int and 0 <= value < 1 << bits, "BFI_unsigned_bits_required")
    return value


def bitfield_insert(source, base, position, length, *, width):
    """Insert low source bits into base, with bounded unsigned bit arithmetic."""
    require(type(width) is int and width in (32, 64), "BFI_width_must_be_32_or_64")
    source, base, position, length = (uint(value) for value in (source, base, position, length))
    mask = (1 << width) - 1
    position = (position & 0xffffffff) & 0xff
    length = (length & 0xffffffff) & 0xff
    if position >= width or length == 0:
        return base & mask
    stop = min(width, position + length)
    # Per-output-bit construction is independent of the common C++ mask
    # helper. Python shifts are bounded here by width-1, with no float/UB.
    result = base & mask
    for output_bit in range(position, stop):
        bit = 1 << output_bit
        result = (result & ~bit) | (((source >> (output_bit - position)) & 1) << output_bit)
    return result & mask


def validate_bfi_event(event):
    """Check explicit functional columns, not worker authenticity or IR scope."""
    require(event.opcode in ("bfi.b32", "bfi.b64"), "BFI_exact_typed_opcode_required")
    width = 32 if event.opcode == "bfi.b32" else 64
    require(event.kind == "inst" and event.mem_addr is None and event.mem_space_raw is None
            and event.width_bits == width and event.dst_reg not in (None, "_")
            and type(event.dst_reg_uid) is int and event.dst_reg_uid > 0
            and event.dst_write_mask == (1 << width) - 1
            and len(event.src_regs) == len(event.src_vals) == len(event.src_reg_uids) == len(event.src_width_bits) == 4,
            "BFI_one_complete_RF_write_and_four_explicit_sources_required")
    if event.pred is not None:
        require(type(event.pred.val) is int and event.pred.val in (0, 1)
                and type(event.pred.uid) is int and event.pred.uid > 0,
                "BFI_actual_effective_predicate_required")
    for source, (name, uid, bits, value) in enumerate(zip(event.src_regs, event.src_reg_uids,
                                                       event.src_width_bits, event.src_vals)):
        uint(value)
        expected = width if source < 2 else 32
        require(type(bits) is int and type(uid) is int, "BFI_actual_source_width_and_UID_required")
        if name == "#imm_" + str(source + 1):
            # Legacy raw immediates carry the instruction width. They are
            # constants: actual IR below binds their typed u32 low bits.
            require(uid == -1 and bits in (expected, width), "BFI_literal_width_or_UID_changed")
            require(source < 2 or (value & 0xffffffff) <= 255, "BFI_literal_control_outside_legal_u8_range")
        else:
            require(isinstance(name, str) and name != "_" and not name.startswith("#")
                    and uid > 0 and bits == expected, "BFI_register_width_or_UID_changed")
    if event.dst_val is not None:
        uint(event.dst_val)
    require(event.pred is not None and event.pred.val == 0 or event.dst_val is not None,
            "BFI_executed_result_required")
    return width
