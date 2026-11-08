#!/usr/bin/env python3
"""Check source-bound v2 capture integrity, separately from replay semantics.

Old traces remain readable for diagnosis, but missing capture evidence is
Unknown. A caller must attest process exit zero and the expected kernel UID
set from its independently retained launch/realization bundle. This checker
neither authenticates arbitrary rewritten artifacts nor proves PTX semantics.
"""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
from script.execution.trace_transport import read_trace_payload

MAX_U64 = (1 << 64) - 1


class IncompleteTrace(ValueError):
    pass


def _require(condition, reason):
    if not condition:
        raise IncompleteTrace(reason)


def _integer(value, minimum=0, maximum=MAX_U64):
    return type(value) is int and minimum <= value <= maximum


def _coordinates(value, *, positive=False):
    _require(isinstance(value, list) and len(value) == 3
             and all(_integer(item, 1 if positive else 0, (1 << 32) - 1) for item in value),
             "invalid_logical_coordinates_or_geometry")
    return tuple(value)


def _pc(value):
    if isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]+", value):
        value = int(value, 16)
    _require(_integer(value), "invalid_program_counter")
    return value


def _object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate_json_object_key")
        result[key] = value
    return result


def _json(payload):
    def invalid_constant(_value):
        raise IncompleteTrace("nonfinite_json_constant")
    return json.loads(payload, object_pairs_hook=_object, parse_constant=invalid_constant)


def check_trace_completeness(trace_path, *, process_exit_status=None, expected_kernel_uids=None):
    """Return Verified only for the complete source-bound capture contract.

    ``expected_kernel_uids`` is mandatory for verification: the captured set
    alone cannot show that an entire launched kernel was omitted. For a paired
    single-launch microprogram this is the sole realized ACK kernel UID, after
    its caller has independently checked the unique launch and normal process.
    Failures remain explicit Unknown; they never fall back to old event masks.
    """
    trace_path = Path(trace_path)
    result = {"schema": "sara-trace-completeness-check-v1", "status": "unknown",
              "valid": False, "formal_trace_complete": False, "reasons": [],
              "evidence_scope": "source_bound_capture_integrity_not_semantics",
              "replay_enablement": False, "automatic_gate_pass": False}
    try:
        _require(type(process_exit_status) is int and process_exit_status == 0,
                 "successful_process_exit_not_attested")
        _require(isinstance(expected_kernel_uids, (list, tuple, set))
                 and bool(expected_kernel_uids)
                 and all(_integer(uid, 1) for uid in expected_kernel_uids)
                 and len(expected_kernel_uids) == len(set(expected_kernel_uids)),
                 "expected_kernel_uid_set_not_attested")
        expected_kernels = set(expected_kernel_uids)
        sidecar_path = Path(str(trace_path) + ".completeness.json")
        sidecar_payload = sidecar_path.read_bytes()
        result["sidecar_sha256"] = hashlib.sha256(sidecar_payload).hexdigest()
        sidecar = _json(sidecar_payload)
        _require(isinstance(sidecar, dict)
                 and sidecar.get("schema") == "sara-trace-completeness-v1"
                 and sidecar.get("trace_schema") == "sara-exact-trace-v2"
                 and sidecar.get("trace_close_succeeded") is True,
                 "successful_v2_trace_close_evidence_missing")
        payload, transport = read_trace_payload(trace_path)
        result["trace_sha256"] = transport["physical_sha256"]
        if transport["codec"] != "plain": result["trace_storage"] = transport
        _require(_integer(sidecar.get("trace_bytes"), 1)
                 and sidecar["trace_bytes"] == len(payload)
                 and sidecar.get("trace_sha256") == transport["decoded_sha256"],
                 "trace_sha256_or_byte_count_mismatch")
        footer = sidecar.get("capture_footer")
        _require(isinstance(footer, dict)
                 and footer.get("schema") == "sara-trace-capture-footer-v1"
                 and footer.get("capture_complete") is True
                 and footer.get("counter_overflow") is False
                 and footer.get("io_error") is False,
                 "normal_complete_capture_footer_missing")
        if sidecar.get("format") == "json":
            document = _json(payload)
            _require(isinstance(document, dict) and document.get("trace_schema") == "sara-exact-trace-v2",
                     "v2_trace_schema_missing")
            _require(json.dumps(document.get("capture_footer"), sort_keys=True)
                     == json.dumps(footer, sort_keys=True), "primary_and_sidecar_footer_disagree")
            events = document.get("events")
        elif sidecar.get("format") == "jsonl":
            events = [_json(line) for line in payload.splitlines() if line.strip()]
        else:
            raise IncompleteTrace("unsupported_capture_format")
        _require(isinstance(events, list) and bool(events)
                 and _integer(footer.get("total_events"), 1)
                 and footer["total_events"] == len(events), "captured_event_total_mismatch")
        observed = {}
        for ordinal, event in enumerate(events, 1):
            _require(isinstance(event, dict) and event.get("opcode_source") == "structured_ptx_ir_v1",
                     "structured_event_metadata_missing")
            _require(_integer(event.get("event_ordinal"), 1)
                     and event["event_ordinal"] == ordinal, "global_event_ordinal_gap_or_duplicate")
            kernel, thread = event.get("kernel_uid"), event.get("thread_id")
            _require(_integer(kernel, 1) and _integer(thread, 1), "event_context_identity_missing")
            cta, tid = _coordinates(event.get("logical_cta")), _coordinates(event.get("logical_tid"))
            key = kernel, thread
            # Each independent next_instr attempt, even predicated-off, emits
            # one event. Per-thread continuity also detects prefix deletion.
            state = observed.setdefault(key, {"count": 0, "cta": cta, "tid": tid,
                                               "first_pc": _pc(event.get("pc"))})
            state["count"] += 1
            _require(_integer(event.get("thread_instruction_ordinal"), 1)
                     and event["thread_instruction_ordinal"] == state["count"],
                     "thread_instruction_ordinal_gap_or_duplicate")
            _require(state["cta"] == cta and state["tid"] == tid, "event_logical_context_changed")
            state["last_pc"] = _pc(event.get("pc"))
        kernels = footer.get("kernels")
        _require(isinstance(kernels, list) and bool(kernels), "normal_kernel_completion_set_missing")
        kernel_map = {}
        for kernel in kernels:
            _require(isinstance(kernel, dict), "invalid_kernel_summary")
            uid = kernel.get("kernel_uid")
            _require(_integer(uid, 1) and uid not in kernel_map
                     and kernel.get("normal_completion") is True
                     and kernel.get("completion_source") == "stream_manager_kernel_is_finished",
                     "kernel_not_normally_completed_or_duplicated")
            grid, block = _coordinates(kernel.get("grid"), positive=True), _coordinates(kernel.get("block"), positive=True)
            geometry = 1
            for extent in grid + block:
                geometry *= extent
            _require(geometry <= MAX_U64 and _integer(kernel.get("expected_threads"), 1)
                     and kernel["expected_threads"] == geometry, "kernel_thread_geometry_count_mismatch")
            kernel_map[uid] = {"grid": grid, "block": block, "expected_threads": geometry,
                               "entry_pc": _pc(kernel.get("entry_pc"))}
        normal_uids = footer.get("normal_kernel_uids")
        _require(isinstance(normal_uids, list) and all(_integer(uid, 1) for uid in normal_uids)
                 and len(normal_uids) == len(set(normal_uids))
                 and set(normal_uids) == set(kernel_map) == expected_kernels,
                 "normal_completed_and_expected_kernel_uid_sets_disagree")
        threads = footer.get("threads")
        _require(isinstance(threads, list) and len(threads) == len(observed), "terminal_thread_set_incomplete")
        summarized, logical, counts = set(), set(), defaultdict(int)
        for thread in threads:
            _require(isinstance(thread, dict), "invalid_thread_summary")
            key = thread.get("kernel_uid"), thread.get("thread_id")
            _require(all(_integer(uid, 1) for uid in key) and key not in summarized
                     and key in observed and key[0] in kernel_map, "terminal_thread_identity_incomplete_or_duplicated")
            summarized.add(key)
            state, kernel = observed[key], kernel_map[key[0]]
            cta, tid = _coordinates(thread.get("logical_cta")), _coordinates(thread.get("logical_tid"))
            _require(cta == state["cta"] and tid == state["tid"]
                     and all(a < b for a, b in zip(cta, kernel["grid"]))
                     and all(a < b for a, b in zip(tid, kernel["block"])), "terminal_logical_thread_outside_geometry")
            logical_key = key[0], cta, tid
            _require(logical_key not in logical, "duplicate_logical_thread_summary")
            logical.add(logical_key)
            counts[key[0]] += 1
            _require(thread.get("terminated") is True
                     and _integer(thread.get("event_count"), 1)
                     and _integer(thread.get("final_attempt_count"), 1)
                     and thread["event_count"] == thread["final_attempt_count"] == state["count"],
                     "terminal_independent_attempt_counter_disagrees")
            _require(_pc(thread.get("first_pc")) == state["first_pc"]
                     == _pc(thread.get("entry_pc")) == kernel["entry_pc"]
                     and _pc(thread.get("last_pc")) == state["last_pc"], "thread_first_last_or_entry_pc_disagrees")
        _require(summarized == set(observed) and set(counts) == expected_kernels
                 and all(counts[uid] == kernel["expected_threads"] for uid, kernel in kernel_map.items()),
                 "observed_thread_set_does_not_cover_expected_kernel_geometry")
        result.update(status="verified", valid=True, formal_trace_complete=True,
                      summary={"total_events": len(events), "thread_count": len(observed),
                               "normal_kernel_uids": sorted(expected_kernels), "capture_format": sidecar["format"]})
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, OverflowError) as error:
        result["reasons"] = [str(error) if isinstance(error, IncompleteTrace)
                             else "capture_evidence_error:" + type(error).__name__ + ":" + str(error)]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--process-exit-status", type=int)
    parser.add_argument("--kernel", type=int, action="append", dest="kernels")
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    result = check_trace_completeness(args.trace, process_exit_status=args.process_exit_status,
                                      expected_kernel_uids=args.kernels)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(text, end="")
    else:
        args.output.write_text(text)
    return 0 if result["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
