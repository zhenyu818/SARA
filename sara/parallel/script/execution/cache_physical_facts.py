"""Shared actual physical-cache facts; no prediction, replay or FI labels."""
from pathlib import Path
import hashlib
import re
from script.execution.memory_effect_records import integer, copy_identity, within, ranges, decode, read_closed_ledger
from script.execution.cache_physical_episodes import ResidencyBuilder


def number(value):
    if isinstance(value, str):
        value = int(value, 0)
    return integer(value)

def physical(copy):
    item = copy_identity(copy)
    return tuple(item[key] for key in ("cache_instance", "geometry_epoch", "line", "allocation_version", "block"))

def event_key(row):
    return tuple(integer(row.get(key), positive=True) for key in ("kernel_uid", "thread_id", "thread_instruction_ordinal"))

def timing_key(row, functional=False):
    return (integer(row.get("dynamic_warp_instruction_uid")), integer(row.get("sm")), integer(row.get("warp")),
            integer(row.get("instruction_issue_cycle" if functional else "instruction_issue")))

def join_functional_records(records, events, *, strict_numeric=False):
    table = {}
    for ordinal, event in enumerate(events, 1):
        if integer(event.get("event_ordinal"), positive=True) != ordinal: raise ValueError("complete_actual_event_order_required")
        key = event_key(event)
        if key in table: raise ValueError("thread_attempt_not_unique")
        table[key] = event
    joined = {}
    witnessed = set()
    for row in records:
        if row.get("kind") not in {"functional_cache_load_source", "functional_cache_store_intent"}: continue
        event = table.get(event_key(row))
        if event is None: raise ValueError("functional_access_has_no_actual_thread_attempt")
        if (row["dynamic_warp_instruction_uid"] != event.get("dynamic_warp_instruction_uid")
                or row["instruction_issue_cycle"] != event.get("instruction_issue_cycle")
                or row["instruction_pc"] != number(event.get("pc")) or row["cycle"] != event.get("cycle")
                or row["sm"] != event.get("sm_id") or row["warp"] != event.get("warp_id")):
            raise ValueError("functional_actual_event_identity_changed")
        write = row["kind"] == "functional_cache_store_intent"
        if event.get("kind") != ("store" if write else "load") or event.get("mem_space") != "global":
            raise ValueError("functional_actual_event_kind_or_namespace")
        predicate = event.get("pred")
        if predicate is not None and predicate.get("val") != 1: raise ValueError("predicated_off_functional_effect")
        count = row["count"]
        if number(event.get("mem_addr")) != row["address"] or event.get("mem_access_size_bytes") != count:
            raise ValueError("scalar_complete_memory_capture_required_vector_pending")
        if write:
            source = integer(event.get("store_data_src_index"))
            # The current scalar writer supplies the low bytes of one source
            # operand. Never compare those bytes with a shifted/vector view
            # while the existing replay engine stores a different slice.
            if strict_numeric and (integer(event.get("store_data_byte_offset", 0)) != 0
                    or integer(event.get("store_size_bytes", count), positive=True) != count
                    or source >= len(event["src_vals"])
                    or source >= len(event["src_width_bits"])
                    or integer(event["src_width_bits"][source], positive=True) < count * 8):
                raise ValueError("complete_unshifted_scalar_store_operand_required")
            value = number(event["src_vals"][source])
        else:
            if event.get("dst_reg") is None or event.get("width_bits", 0) > 64:
                raise ValueError("complete_scalar_load_destination_required")
            value = number(event.get("dst_val"))
        if count > 8 or (value & ((1 << (8*count))-1)).to_bytes(count, "little").hex() != row["actual_operand_bytes"]:
            raise ValueError("actual_functional_operand_bytes_differ_from_raw_event")
        # Explicit .cg always bypasses L1 in both the functional writer and
        # ldst_unit::memory_cycle. .ca/.wb can also bypass under actual config;
        # only their independently observed candidates determine that route.
        if strict_numeric and event.get("opcode") == "ld.global.cg.u32" and row["l1_bypass"] is not True:
            raise ValueError("explicit_cg_actual_L1_bypass_witness_required")
        if event_key(row) in witnessed: raise ValueError("duplicate_scalar_functional_access_witness")
        witnessed.add(event_key(row)); joined[row["sequence"]] = event
    expected = {event_key(event) for event in events if event.get("kind") in {"load", "store"}
                and event.get("mem_space") == "global" and (event.get("pred") is None or event["pred"].get("val") == 1)}
    if witnessed != expected:
        raise ValueError("complete_scalar_functional_access_witness_missing_or_unbound_effect")
    return joined


def raw_physical(ledger, trace=None, sidecar=None):
    """Complete RLE state and actual transport; no virtual-address modulo map."""
    from script.execution.method_input_context import current_context
    context = current_context(ledger)
    if trace is not None:
        read_closed_ledger(ledger, trace, sidecar, expected_budget_bytes=2147483648,
                           expected_cache_state=True)
    if context is not None:
        from script.execution.memory_effect_records import read_ledger_rows
        rows, facts = read_ledger_rows(ledger)
        if trace is None and (not rows or rows[0].get('capture_profile') not in {
                'storage-efm-v1', 'storage-population-v1'}):
            raise ValueError('value-free cache profile must be explicit in the actual producer')
        def build():
            result = _physical_rows(rows, facts['prefix_bytes'], facts['prefix_sha256'])
            context.count(ledger, 'residency_builds')
            return result
        return context.cached(ledger, 'physical-residencies-v1', build)
    rows, builder = [], ResidencyBuilder()
    prefix, prefix_bytes = hashlib.sha256(), 0
    with Path(ledger).open("rb") as stream:
        for line in stream:
            row = decode(line)
            if row.get("sequence") != len(rows):
                raise ValueError("cache ledger sequence gap or duplicate")
            rows.append(row)
            builder.consume(row)
            if row.get("kind") != "close":
                prefix.update(line); prefix_bytes += len(line)
    if not rows or rows[-1].get("kind") != "close":
        raise ValueError("closed cache observation required")
    first, checkpoint = rows[0], rows[-1]["checkpoint"]
    if (re.fullmatch(r"[0-9a-f]{64}", first.get("source_fingerprint", "")) is None
            or re.fullmatch(r"sha256:[0-9a-f]{64}", first.get("image_id", "")) is None
            or first.get("cache_state_enabled") is not True
            or checkpoint["blockers"] or checkpoint["api_count"] != checkpoint["completed_count"]
            or checkpoint["record_count"] != len(rows)-2
            or checkpoint["prefix_bytes"] != prefix_bytes
            or checkpoint["prefix_sha256"] != prefix.hexdigest()):
        raise ValueError("unclosed, blocked, altered or unbound physical observation")
    if trace is None and first.get("capture_profile") not in {"storage-efm-v1", "storage-population-v1"}:
        raise ValueError("value-free cache profile must be explicit in the actual producer")
    for row in rows:
        if any(row.get(field) for field in ("payload", "source_payload", "transport_payload")):
            raise ValueError("realized FI payload is forbidden in prediction input")
    return rows, builder.report()


def _physical_rows(rows, prefix_bytes, prefix_sha256):
    """The same complete physical checks, on already decoded immutable rows."""
    builder = ResidencyBuilder()
    for ordinal, row in enumerate(rows):
        if row.get('sequence') != ordinal:
            raise ValueError('cache ledger sequence gap or duplicate')
        builder.consume(row)
    if not rows or rows[-1].get('kind') != 'close':
        raise ValueError('closed cache observation required')
    first, checkpoint = rows[0], rows[-1]['checkpoint']
    if (re.fullmatch(r'[0-9a-f]{64}', first.get('source_fingerprint', '')) is None
            or re.fullmatch(r'sha256:[0-9a-f]{64}', first.get('image_id', '')) is None
            or first.get('cache_state_enabled') is not True
            or checkpoint['blockers'] or checkpoint['api_count'] != checkpoint['completed_count']
            or checkpoint['record_count'] != len(rows)-2
            or checkpoint['prefix_bytes'] != prefix_bytes
            or checkpoint['prefix_sha256'] != prefix_sha256):
        raise ValueError('unclosed, blocked, altered or unbound physical observation')
    for row in rows:
        if any(row.get(field) for field in ('payload', 'source_payload', 'transport_payload')):
            raise ValueError('realized FI payload is forbidden in prediction input')
    from script.execution.method_input_context import current_context
    # The live own-input consumer separately retains the complete raw ledger.
    # Report still accumulates/deepcopies every access and checks every owner;
    # only the unused duplicate report list is omitted before context.freeze.
    return rows, builder.report(include_timing_records=current_context() is None)


def addressed(row):
    return [row["request_block"] + i for i, bit in enumerate(reversed(row["byte_mask"])) if bit == "1"]
