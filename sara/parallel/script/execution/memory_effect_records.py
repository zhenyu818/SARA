"""Check independently recorded memory assignments and cache transport, no issuer.

This is an evidence reader. Owned worker/PID/image/source/PTX/runtime/oracle,
read-only payload deployment and semantic applicability are checked elsewhere.
It never accepts a caller certification boolean and never emits a fault outcome.
"""
import hashlib
import io
from script.execution.trace_transport import read_trace_payload
import json
from pathlib import Path
import re

MAX_LEDGER_BYTES = 16 * 1024 ** 3
MAX_ROW_BYTES = 160 * 1024 ** 2
MAX_LIVE_REQUESTS = 100000
HEX = re.compile(r"(?:[0-9a-f]{2})*\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")


def integer(value, *, positive=False):
    if type(value) is not int or value < int(positive) or value > 2 ** 64 - 1:
        raise ValueError("unsigned_integer_required")
    return value


def object_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate_JSON_key")
        out[key] = value
    return out


def decode(line):
    return json.loads(line, object_pairs_hook=object_pairs,
                      parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite_JSON")))


def bytes_hex(value, count):
    if not isinstance(value, str) or not HEX.fullmatch(value) or len(value) != count * 2:
        raise ValueError("complete_hex_bytes_required")
    return value


def payload(value):
    if not isinstance(value, list):
        raise ValueError("typed_payload_array_required")
    out = {}
    for item in value:
        if not isinstance(item, dict) or set(item) != {"address", "mask", "realization_id"}:
            raise ValueError("payload_shape")
        address, mask, rid = integer(item["address"]), integer(item["mask"], positive=True), item["realization_id"]
        if address in out or mask > 255 or not isinstance(rid, str) or not rid:
            raise ValueError("payload_duplicate_or_invalid")
        out[address] = (mask, rid)
    return out


def ranges(value):
    if not isinstance(value, list) or not value:
        raise ValueError("covered_ranges_required")
    result = []
    for row in value:
        if not isinstance(row, list) or len(row) != 2:
            raise ValueError("range_shape")
        base, count = integer(row[0]), integer(row[1], positive=True)
        if base + count > 2 ** 64 or any(base < b + n and b < base + count for b, n in result):
            raise ValueError("overlapping_or_wrapped_ranges")
        result.append((base, count))
    return result


def within(address, intervals):
    return any(base <= address < base + size for base, size in intervals)


def copy_identity(value):
    keys = {"cache_instance", "geometry_epoch", "line", "allocation_version", "block", "tag", "line_bytes", "actual_allocated_lines", "cache_type"}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("actual_copy_identity_shape")
    out = {key: integer(item) for key, item in value.items()}
    if not out["cache_instance"] or not out["geometry_epoch"] or not out["line_bytes"] or out["line"] >= out["actual_allocated_lines"]:
        raise ValueError("actual_copy_allocation_invalid")
    return out


class Validator:
    def __init__(self):
        self.sequence = 0
        self.header = None
        self.requests = {}
        self.allocations = {}
        self.allocation_generations = {}
        self.allocation_count = 0
        self.symbol_definitions = {}
        self.symbol_definition_records = []
        self.static_initializations = []
        self.cache_last_lifetime = 0
        self.copy_effects = []
        self.cache_requests = set()
        self.cache_request_roots = {}
        self.cache_request_parents = {}
        self.cache_sources = {}
        self.cache_source_roots = {}
        self.cache_source_event_roots = {}
        self.kernels = set()
        self.launch_parameters = {}
        self.closed_parameters = {}
        self.retired = set()
        self.shutdown = False
        self.cache_drain = False
        self.closed = False
        self.hooks = 0
        self.last_cycle = None
        self.total_bits = 0
        self.state = {}
        self.expected_cache_owners = None
        self.cache_owners = {}
        self.cache_slots = {}
        self.cache_dirty_owners = set()
        self.cache_owner_bits = {}
        self.cache_bits = 0
        self.cache_pending_keys = set()
        self.cache_pending_cycle = None
        self.cache_counts = {"responses": 0, "fills": 0, "accesses": 0}

    def allocation(self, value, address, count):
        if not isinstance(value, dict):
            raise ValueError("allocation_identity_required")
        for key in ("id", "generation", "size"):
            integer(value.get(key), positive=True)
        for key in ("base", "offset"):
            integer(value.get(key))
        actual = self.allocations.get(value["id"])
        expected = dict(value, offset=0)
        if actual != expected or value["base"] + value["offset"] != address or value["offset"] + count > value["size"]:
            raise ValueError("allocation_lifetime_or_bounds_mismatch")
        return value

    def request(self, row):
        key = integer(row.get("request_id"), positive=True)
        if key not in self.requests:
            raise ValueError("missing_API_request")
        return key, self.requests[key]

    def consume(self, row):
        if not isinstance(row, dict) or self.closed:
            raise ValueError("record_after_close_or_nondict")
        if self.header is None:
            if row.get("kind") != "header" or row.get("schema") != "sara-memory-effects-v2" or row.get("sequence") != 0:
                raise ValueError("header_required")
            if integer(row.get("sequence")) != 0:
                raise ValueError("typed_header_sequence_required")
            if row.get("replay_authorized") is not False or row.get("mapping_certified") is not False:
                raise ValueError("observer_cannot_self_certify")
            if not SHA.fullmatch(str(row.get("source_fingerprint", ""))) or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(row.get("image_id", ""))):
                raise ValueError("owned_source_image_identity_required")
            integer(row.get("pid"), positive=True)
            budget = integer(row.get("max_ledger_bytes"), positive=True)
            if not 1024 ** 2 <= budget <= MAX_LEDGER_BYTES: raise ValueError("ledger_budget_out_of_reviewed_range")
            if type(row.get("cache_state_enabled")) is not bool: raise ValueError("typed_cache_state_mode_required")
            self.header = row
            return
        self.sequence += 1
        if integer(row.get("sequence"), positive=True) != self.sequence:
            raise ValueError("record_sequence_gap_or_duplicate")
        kind = row.get("kind")
        if kind == "close":
            if row.get("schema") != "sara-memory-effects-close-v2" or not self.shutdown or self.kernels or self.cache_requests or not self.cache_drain:
                raise ValueError("normal_drained_close_required")
            if any(r.get("stages") != {"queue", "service_enter", "copy_begin", "copy_end", "service_retired", "api_return"} for r in self.requests.values()):
                raise ValueError("request_lifetime_not_closed")
            if self.header["cache_state_enabled"] and not self.hooks: raise ValueError("enabled_cache_state_missing_whole_window")
            if self.cache_pending_keys: raise ValueError("cache_change_without_actual_hook")
            checkpoint = row.get("checkpoint", {})
            if checkpoint.get("record_count") != self.sequence - 1 or checkpoint.get("blockers") != [] or checkpoint.get("api_count") != len(self.requests) or checkpoint.get("completed_count") != len(self.copy_effects):
                raise ValueError("close_counts_or_blockers")
            if checkpoint.get("replay_authorized") is not False or checkpoint.get("mapping_certified") is not False:
                raise ValueError("close_cannot_self_certify")
            self.closed = True
            return
        integer(row.get("instruction_cursor"))
        if kind in {"blocker", "unmodeled_transfer", "queue_skipped"}:
            raise ValueError("unsupported_or_incomplete_effect:" + str(row.get("reason", row.get("operation", kind))))
        if kind in {"functional_cache_load_source", "functional_cache_store_intent", "functional_cache_unbound", "cache_disposition", "cache_write_request_sent"}:
            from script.execution.cache_semantic_records import validate_extension
            if not self.header.get("cache_state_enabled") or self.header.get("cache_functional_contract") != "actual_functional_cache_candidates_v1":
                raise ValueError("undeclared_functional_cache_contract")
            validate_extension(row, self.cache_requests, self.cache_request_parents,
                values_required=self.header.get("capture_profile") != "storage-population-v1")
        elif kind == "allocation":
            a = row.get("allocation")
            if not isinstance(a, dict) or integer(a.get("id"), positive=True) in self.allocations:
                raise ValueError("duplicate_allocation_id")
            self.allocation_shape(a)
            self.allocation_count += 1
            generation = self.allocation_generations.get(a["base"], 0) + 1
            if a["id"] != self.allocation_count or a["generation"] != generation:
                raise ValueError("allocation_id_or_generation_reused")
            self.allocation_generations[a["base"]] = generation
            if any(a["base"] < b["base"] + b["size"] and b["base"] < a["base"] + a["size"] for b in self.allocations.values()):
                raise ValueError("overlapping_live_allocation")
            self.allocations[a["id"]] = a
        elif kind == "free":
            a = row["allocation"]
            if self.allocations.pop(a.get("id"), None) != a:
                raise ValueError("unmatched_free")
        elif kind == "api_request":
            key = integer(row.get("request_id"), positive=True)
            if key != len(self.requests) + 1 or key in self.requests or len(self.requests) >= MAX_LIVE_REQUESTS:
                raise ValueError("duplicate_request_or_budget")
            for field in ("source", "destination", "count", "supplied_stream_uid", "symbol_handle", "symbol_offset"):
                integer(row.get(field))
            if type(row.get("supplied_stream_null")) is not bool or row.get("copy_kind") not in {"h2d", "d2h", "d2d", "symbol_to", "symbol_from", "memset"}:
                raise ValueError("typed_copy_API_required")
            if row["supplied_stream_null"] != (row["supplied_stream_uid"] == 0):
                raise ValueError("supplied_stream_null_and_UID_disagree")
            self.requests[key] = dict(row, stages=set())
        elif kind in {"queue", "service_enter", "copy_begin", "copy_end", "service_retired", "api_return"}:
            key, r = self.request(row)
            stages = r["stages"]
            if kind in stages:
                raise ValueError("duplicate_request_stage")
            prerequisites = {"queue": set(), "service_enter": {"queue"}, "copy_begin": {"service_enter"},
                "copy_end": {"copy_begin"}, "service_retired": {"copy_end"}, "api_return": {"queue"}}
            if not prerequisites[kind] <= stages:
                raise ValueError("request_stage_order")
            if kind == "queue":
                # CUstream_st assigns UIDs starting at zero. The actual
                # default stream may therefore resolve to UID 0; it is not
                # a missing stream. Nondefault requests still retain their
                # exact supplied UID, independently of this numeric bound.
                r["stream"] = integer(row.get("resolved_stream_uid"))
                if not r["supplied_stream_null"] and r["stream"] != r["supplied_stream_uid"]:
                    raise ValueError("supplied_stream_changed_during_queue_resolution")
            elif kind == "service_enter":
                if integer(row.get("resolved_stream_uid")) != r["stream"] or type(row.get("idle")) is not bool or not isinstance(row.get("gpu_state"), dict):
                    raise ValueError("actual_service_state_required")
                state = row["gpu_state"]
                if state.get("initialized") is not True or state.get("limit_hit") is not False or state.get("deadlock") is not False:
                    raise ValueError("limit_deadlock_or_uninitialized_service")
            elif kind == "copy_begin":
                n = integer(row.get("count"), positive=True)
                if n != r["count"] or row.get("copy_kind") != r["copy_kind"] or row.get("capture_bytes") is not True:
                    raise ValueError("copy_capture_or_arguments")
                if r["copy_kind"] not in {"symbol_to", "symbol_from"} and (row.get("source"), row.get("destination")) != (r["source"], r["destination"]):
                    raise ValueError("helper_API_arguments_differ")
                src, dst = integer(row.get("source")), integer(row.get("destination"))
                if (row.get("symbol_handle"), row.get("symbol_offset")) != (r["symbol_handle"], r["symbol_offset"]):
                    raise ValueError("symbol_request_identity_changed")
                if r["copy_kind"] in {"d2d", "d2h", "symbol_from"}:
                    self.allocation(row.get("source_allocation"), src, n)
                if r["copy_kind"] in {"d2d", "h2d", "symbol_to", "memset"}:
                    self.allocation(row.get("destination_allocation"), dst, n)
                if r["copy_kind"] == "d2d" and src < dst + n and dst < src + n:
                    raise ValueError("overlapping_D2D")
                r["copy"] = row
                integer(row.get("service_sequence"), positive=True)
            elif kind == "copy_end":
                copy = r["copy"]; n = copy["count"]
                if row.get("service_sequence") != copy["service_sequence"]:
                    raise ValueError("helper_sequence_mismatch")
                if row["instruction_cursor"] != copy["instruction_cursor"]:
                    raise ValueError("instruction_executed_inside_copy_helper")
                source = bytes_hex(row.get("source_before"), n)
                if row.get("source_after") != source or row.get("destination_after") != source:
                    raise ValueError("assignment_or_source_stability_mismatch")
                if r["copy_kind"] not in {"d2h", "symbol_from"}:
                    bytes_hex(row.get("destination_before"), n)
                elif row.get("destination_before") is not None:
                    raise ValueError("uninitialized_host_destination_must_not_be_read")
                if r["copy_kind"] == "memset" and source != (format(r["source"], "02x") * n):
                    raise ValueError("memset_literal_mismatch")
                self.copy_effects.append(dict(copy, instruction_cursor_after=row["instruction_cursor"], bytes=source,
                                              effect_kind="output" if r["copy_kind"] in {"d2h", "symbol_from"} else "assignment"))
            elif kind == "service_retired":
                if row.get("service_sequence") != r["copy"]["service_sequence"]:
                    raise ValueError("retirement_helper_mismatch")
                if r["supplied_stream_null"] and "api_return" in stages:
                    raise ValueError("default_stream_return_precedes_retirement")
            elif kind == "api_return":
                if integer(row.get("status")) != 0 or (r["supplied_stream_null"] and "service_retired" not in stages):
                    raise ValueError("API_success_or_synchronous_return_invalid")
            stages.add(kind)
        elif kind == "kernel_parameter_assignment":
            uid = integer(row.get("kernel_uid"), positive=True)
            index = integer(row.get("parameter_index"))
            count = integer(row.get("count"), positive=True)
            integer(row.get("symbol_uid"), positive=True); integer(row.get("address"))
            integer(row.get("entry_pc")); integer(row.get("scalar_type")); integer(row.get("host_source_address"), positive=True)
            if (row.get("schema") != "sara-launch-parameter-assignment-v1" or count > 1024 ** 2
                    or integer(row.get("declared_size_bits"), positive=True) != count * 8
                    or not isinstance(row.get("entry"), str) or not row["entry"]
                    or not isinstance(row.get("symbol_name"), str) or not row["symbol_name"]
                    or integer(row["address"]) + count > 2 ** 64
                    or bytes_hex(row.get("source_bytes"), count) != bytes_hex(row.get("assigned_bytes"), count)):
                raise ValueError("actual_parameter_assignment_required")
            parameters = self.launch_parameters.setdefault(uid, {})
            if uid in self.kernels or uid in self.closed_parameters or index in parameters:
                raise ValueError("parameter_assignment_after_close_launch_or_duplicate")
            if any(row["address"] < p["address"] + p["count"] and p["address"] < row["address"] + count for p in parameters.values()):
                raise ValueError("overlapping_launch_parameter_assignments")
            parameters[index] = row
        elif kind == "kernel_parameters_complete":
            uid = integer(row.get("kernel_uid"), positive=True)
            count = integer(row.get("declared_parameters"))
            if (row.get("schema") != "sara-launch-parameters-complete-v1" or uid in self.kernels or uid in self.closed_parameters
                    or count > 65536 or integer(row.get("observed_parameters")) != count
                    or set(self.launch_parameters.get(uid, {})) != set(range(count))
                    or not isinstance(row.get("entry"), str) or not row["entry"]):
                raise ValueError("complete_actual_launch_parameters_required")
            integer(row.get("entry_pc"))
            if any((p["entry"], p["entry_pc"]) != (row["entry"], row["entry_pc"]) for p in self.launch_parameters.get(uid, {}).values()):
                raise ValueError("launch_parameter_entry_identity_changed")
            self.closed_parameters[uid] = row
        elif kind in {"kernel_launch", "kernel_complete"}:
            uid = integer(row.get("kernel_uid"), positive=True)
            if kind == "kernel_launch":
                if uid in self.kernels:
                    raise ValueError("duplicate_kernel")
                self.kernels.add(uid)
            else:
                if uid not in self.kernels:
                    raise ValueError("unknown_kernel_completion")
                self.kernels.remove(uid)
        elif kind == "cache_drain":
            if self.cache_drain or any(integer(row.get(k)) for k in ("pending_read_bytes", "pending_store_bytes", "inflight_payloads")):
                raise ValueError("cache_fault_bookkeeping_not_drained")
            integer(row.get("resident_error_copies")); self.cache_drain = True
        elif kind == "simulation_thread_joined":
            if self.shutdown or row.get("semaphore_exit_confirmed") is not True:
                raise ValueError("invalid_shutdown")
            self.shutdown = True
        elif kind in {"cache_request_begin", "cache_request_end"}:
            lifetime = integer(row.get("request_lifetime"), positive=True)
            integer(row.get("request_uid"))
            if kind.endswith("begin"):
                if lifetime in self.cache_requests or len(self.cache_requests) >= MAX_LIVE_REQUESTS:
                    raise ValueError("cache_request_reuse_or_budget")
                if lifetime != self.cache_last_lifetime + 1: raise ValueError("cache_request_birth_gap_or_reuse")
                self.cache_last_lifetime = lifetime
                parent, root = integer(row.get("parent_lifetime")), integer(row.get("root_lifetime"), positive=True)
                if (not parent and root != lifetime) or (parent and (parent not in self.cache_requests or self.cache_request_roots.get(parent) != root)):
                    raise ValueError("cache_request_parent_or_root_mismatch")
                self.cache_request_roots[lifetime] = root
                self.cache_request_parents[lifetime] = parent
                self.cache_requests.add(lifetime)
            else:
                if lifetime not in self.cache_requests:
                    raise ValueError("cache_retire_without_birth")
                self.cache_requests.remove(lifetime)
                self.cache_request_roots.pop(lifetime)
                self.cache_request_parents.pop(lifetime)
                for event in self.cache_source_roots.pop(lifetime, set()):
                    self.cache_sources.pop(event, None)
                    self.cache_source_event_roots.pop(event, None)
        elif kind in {"cache_response", "cache_fill", "cache_access"}:
            lifetime = integer(row.get("request_lifetime"), positive=True)
            if lifetime not in self.cache_requests:
                raise ValueError("cache_effect_outside_request_lifetime")
            if self.header.get("cache_state_enabled") and self.header.get("cache_functional_contract") == "actual_functional_cache_candidates_v1":
                from script.execution.cache_semantic_records import validate_request_origin
                validate_request_origin(row, self.cache_requests, self.cache_request_parents)
            if kind == "cache_access":
                self.cache_counts["accesses"] += 1
                if row.get("before_copy") is not None:
                    copy_identity(row["before_copy"])
                if row.get("selected_copy") is not None:
                    copy_identity(row["selected_copy"])
            else:
                covered = ranges(row["ranges"])
                root = integer(row.get("root_lifetime"), positive=True)
                if root != self.cache_request_roots.get(lifetime): raise ValueError("cache_request_root_changed")
                if root not in self.cache_requests: raise ValueError("copy_parent_lifetime_missing")
                self.cache_source_roots.setdefault(root, set()).add(row["sequence"])
                self.cache_source_event_roots[row["sequence"]] = root
                if kind == "cache_response":
                    self.cache_counts["responses"] += 1
                    copy_identity(row["source"])
                    actual = payload(row["payload"])
                    expected = {a: b for a, b in payload(row["source_payload"]).items() if within(a, covered)}
                    forwarded = row["forwarded_bytes"]
                    if not isinstance(forwarded, list) or len(set(forwarded)) != len(forwarded):
                        raise ValueError("forwarded_byte_shape")
                    for address in forwarded:
                        integer(address)
                        if not within(address, covered): raise ValueError("forward_outside_copy")
                        expected.pop(address, None)
                    if actual != expected:
                        raise ValueError("response_payload_differs_from_source")
                    self.cache_sources[row["sequence"]] = (covered, actual)
                else:
                    self.cache_counts["fills"] += 1
                    copy_identity(row["destination"])
                    before, actual, transport = payload(row["destination_before_payload"]), payload(row["destination_payload"]), payload(row["transport_payload"])
                    expected_transport = {}
                    if not isinstance(row.get("source_events"), list) or len(row["source_events"]) != len(set(row["source_events"])):
                        raise ValueError("copy_producer_list_or_duplicate")
                    for event in row["source_events"]:
                        integer(event, positive=True)
                        if event not in self.cache_sources or event >= row["sequence"]:
                            raise ValueError("missing_or_future_copy_producer")
                        if self.cache_source_event_roots.get(event) != root:
                            raise ValueError("copy_producer_from_other_request_root")
                        for address, byte in self.cache_sources[event][1].items():
                            if address in expected_transport and expected_transport[address] != byte:
                                raise ValueError("conflicting_sector_producers")
                            expected_transport[address] = byte
                    if type(row.get("backing_source")) is not bool or row["backing_source"] != (not row["source_events"]) or transport != expected_transport:
                        raise ValueError("unbound_transfer_payload")
                    expected = {a: b for a, b in before.items() if not within(a, covered)}
                    expected.update({a: b for a, b in transport.items() if within(a, covered)})
                    if actual != expected:
                        raise ValueError("fill_must_assign_not_XOR_or_union")
                    self.cache_sources[row["sequence"]] = (covered, {a: b for a, b in actual.items() if within(a, covered)})
        elif kind == "cache_topology":
            owners = row.get("owners")
            if self.expected_cache_owners is not None or not isinstance(owners, list) or not owners or len(set(owners)) != len(owners) or any(not isinstance(k, str) or not re.fullmatch(r"(?:l1d|l2):[0-9]+", k) for k in owners):
                raise ValueError("actual_cache_topology_required")
            self.expected_cache_owners = set(owners)
        elif kind == "cache_owner":
            self.cache_state_change(row)
            key = row.get("key")
            self.cache_owner_shape(row)
            self.cache_owners[key] = row
            self.state[key] = row
            self.cache_dirty_owners.add(key)
        elif kind == "cache_slot":
            self.cache_state_change(row)
            key, owner_key, index = self.cache_slot_shape(row)
            owner = self.cache_owners.get(owner_key)
            if owner is None: raise ValueError("cache_slot_before_actual_owner")
            self.cache_slot_owner_shape(row, owner)
            slots = self.cache_slots.setdefault(owner_key, {})
            if index not in slots: self.cache_dirty_owners.add(owner_key)
            slots[index] = row
            self.state[key] = row
        elif kind == "cache_removed":
            self.cache_state_change(row)
            old = self.state.pop(row.get("key"), None)
            if old is None: raise ValueError("unknown_cache_state_removal")
            if old["kind"] == "cache_owner":
                self.cache_owners.pop(old["key"])
                self.cache_dirty_owners.add(old["key"])
            else:
                owner_key = old["owner_key"]
                self.cache_slots[owner_key].pop(old["copy"]["line"])
                self.cache_dirty_owners.add(owner_key)
        elif kind == "cache_hook":
            self.hooks += 1; cycle = integer(row.get("cycle"))
            if integer(row.get("hook"), positive=True) != self.hooks or (self.last_cycle is not None and cycle != self.last_cycle + 1):
                raise ValueError("cache_hook_gap_or_duplicate")
            if self.cache_pending_cycle is not None and cycle != self.cache_pending_cycle:
                raise ValueError("cache_state_change_hook_cycle_disagrees")
            self.cache_pending_keys.clear(); self.cache_pending_cycle = None
            self.last_cycle = cycle
            if self.expected_cache_owners is None or set(self.cache_owners) != self.expected_cache_owners:
                raise ValueError("whole_cache_owner_missing")
            # The source RLE emits changes, not a reduced physical domain. Only
            # owner geometry or slot membership changes require a full index
            # audit; each changed slot was checked against its actual owner.
            for key in self.cache_dirty_owners:
                owner = self.cache_owners.get(key)
                if owner is None: raise ValueError("whole_cache_owner_missing")
                bits = self.cache_owner_shape(owner)
                slots = self.cache_slots.get(key, {})
                lines = owner["active_lines"]
                if len(slots) != lines or any(index >= lines for index in slots):
                    raise ValueError("missing_raw_cache_slot_or_extra_index")
                for slot in slots.values(): self.cache_slot_owner_shape(slot, owner)
                self.cache_bits += bits - self.cache_owner_bits.get(key, 0)
                self.cache_owner_bits[key] = bits
            self.cache_dirty_owners.clear()
            self.total_bits += self.cache_bits
            if (integer(row.get("active_bit_count")) != self.cache_bits
                    or integer(row.get("cumulative_bit_cycles")) != self.total_bits
                    or integer(row.get("state_keys")) != len(self.state)
                    or integer(row.get("unresolved_expected_bits")) != 0):
                raise ValueError("cache_raw_mass_mismatch")
        elif kind == "symbol_definition":
            uid = integer(row.get("symbol_uid"), positive=True)
            base, size = integer(row.get("base")), integer(row.get("size"), positive=True)
            if (row.get("schema") != "sara-assembled-symbol-definition-v1" or base + size > 2 ** 64
                    or type(row.get("is_const")) is not bool or type(row.get("is_global")) is not bool
                    or row["is_const"] == row["is_global"] or not isinstance(row.get("symbol_name"), str) or not row["symbol_name"]):
                raise ValueError("typed_assembled_symbol_definition_required")
            identity = {key: row[key] for key in ("symbol_uid", "symbol_name", "base", "size", "is_const", "is_global")}
            actual = [a for a in self.allocations.values() if a["allocator"] == "symbol"
                      and (a["symbol_uid"], a["name"], a["base"], a["size"]) == (uid, row["symbol_name"], base, size)]
            if len(actual) != 1 or (uid in self.symbol_definitions and self.symbol_definitions[uid] != identity):
                raise ValueError("symbol_definition_allocation_or_redefinition_mismatch")
            self.symbol_definitions[uid] = identity
            self.symbol_definition_records.append(dict(row))
        elif kind == "static_initialization":
            n = integer(row.get("count"), positive=True)
            if bytes_hex(row.get("literal_bytes"), n) != bytes_hex(row.get("actual_bytes"), n):
                raise ValueError("static_initializer_mismatch")
            # Retain the original row; this reader does not grant initializer
            # semantics. A scoped image issuer still binds/rejects its target.
            self.static_initializations.append(dict(row))
        else:
            raise ValueError("unreviewed_memory_effect_kind:" + str(kind))

    def cache_state_change(self, row):
        key = row.get("key")
        if not isinstance(key, str) or key in self.cache_pending_keys:
            raise ValueError("duplicate_cache_state_change_in_hook")
        if integer(row.get("hook"), positive=True) != self.hooks + 1:
            raise ValueError("cache_state_change_hook_out_of_order")
        if row["kind"] != "cache_removed":
            cycle = integer(row.get("cycle"))
            if ((self.cache_pending_cycle is not None and cycle != self.cache_pending_cycle)
                    or (self.last_cycle is not None and cycle != self.last_cycle + 1)):
                raise ValueError("cache_state_change_hook_cycle_disagrees")
            self.cache_pending_cycle = cycle
        self.cache_pending_keys.add(key)

    @staticmethod
    def cache_owner_shape(owner):
        component = owner.get("component")
        scope = integer(owner.get("scope"))
        key = str(component) + ":" + str(scope)
        if (component not in {"l1d", "l2"} or owner.get("key") != key
                or owner.get("owner_key") != key or type(owner.get("disabled")) is not bool):
            raise ValueError("actual_cache_owner_shape")
        if owner["disabled"]:
            if (owner.get("present") is not False or integer(owner.get("active_lines")) != 0
                    or owner.get("actual_backing_capacity_known") is not False):
                raise ValueError("disabled_cache_owner_nonempty")
            return 0
        if (owner.get("present") is not True or owner.get("actual_backing_capacity_known") is not True
                or owner.get("active_index_allocation_validated") is not True):
            raise ValueError("unresolved_cache_owner")
        lines = integer(owner.get("active_lines"), positive=True)
        capacity = integer(owner.get("actual_allocated_lines"), positive=True)
        width = integer(owner.get("line_bytes"), positive=True)
        cache_type = integer(owner.get("cache_type"))
        if lines > capacity: raise ValueError("cache_capacity_mismatch")
        if cache_type not in (0, 1) or width % (1 if cache_type == 0 else 4):
            raise ValueError("actual_cache_owner_geometry")
        return lines * (57 + width * 8)

    @staticmethod
    def cache_slot_shape(row):
        identity = copy_identity(row.get("copy"))
        owner_key = row.get("owner_key")
        if (not isinstance(owner_key, str) or not re.fullmatch(r"(?:l1d|l2):[0-9]+", owner_key)
                or row.get("key") != owner_key + ":" + str(identity["line"])):
            raise ValueError("canonical_cache_slot_key_required")
        states = row.get("sector_state")
        count = 1 if identity["cache_type"] == 0 else 4 if identity["cache_type"] == 1 else 0
        if not isinstance(states, list) or not count or len(states) != count or identity["line_bytes"] % count:
            raise ValueError("sector_state_shape")
        for state in states:
            if (not isinstance(state, dict) or set(state) != {"status", "readable"}
                    or integer(state["status"]) > 3 or type(state["readable"]) is not bool):
                raise ValueError("typed_sector_state_required")
        return row["key"], owner_key, identity["line"]

    @staticmethod
    def cache_slot_owner_shape(slot, owner):
        item = slot["copy"]
        if (owner["disabled"] or item["line"] >= owner["active_lines"]
                or any(item[name] != owner[name] for name in ("line_bytes", "actual_allocated_lines", "cache_type"))):
            raise ValueError("slot_and_actual_cache_owner_disagree")

    @staticmethod
    def allocation_shape(a):
        for key in ("id", "generation", "size"): integer(a.get(key), positive=True)
        integer(a.get("base")); integer(a.get("offset"))
        if a["offset"] or a["size"] > 2 ** 64 - 1 - a["base"]:
            raise ValueError("invalid_allocation_interval")
        integer(a.get("symbol_uid"))
        if (a.get("allocator") == "symbol") != (a["symbol_uid"] > 0):
            raise ValueError("typed_assembled_symbol_identity_required")
        if not isinstance(a.get("allocator"), str) or not isinstance(a.get("name"), str):
            raise ValueError("allocation_metadata_required")

    def report(self):
        if not self.closed:
            raise ValueError("missing_memory_effect_close")
        return {"schema": "sara-memory-effects-checked-v2", "copy_effects": self.copy_effects,
                "symbol_definitions": [dict(self.symbol_definitions[key]) for key in sorted(self.symbol_definitions)],
                "symbol_definition_records": self.symbol_definition_records,
                "static_initializations": self.static_initializations,
                "cache_transport_counts": self.cache_counts, "cache_hook_ticks": self.hooks,
                "cache_bit_cycles": self.total_bits, "records": self.sequence,
                "record_consistency_checked": True, "source_fingerprint": self.header["source_fingerprint"],
                "image_id": self.header["image_id"], "actual_process_pid": self.header["pid"],
                "retained_worker_authenticity_verified": False,
                "replay_authorized": False, "mapping_certified": False, "all_gates_pass": False}


def read_ledger_rows(ledger):
    """Decode a method's immutable ledger once; retain exact prefix identity.

    This is not a certification shortcut. Closed-ledger and physical-residency
    checkers still consume the rows with their distinct source-bound checks.
    """
    from script.execution.method_input_context import current_context
    context = current_context(ledger)
    if context is None:
        raise ValueError('shared ledger rows require an active own method context')
    context.check_size(ledger, MAX_LEDGER_BYTES)
    def load():
        payload = context.read_bytes(ledger)
        if len(payload) > MAX_LEDGER_BYTES:
            raise ValueError('ledger_byte_budget')
        rows, prefix, prefix_bytes, close = [], hashlib.sha256(), 0, None
        with io.BytesIO(payload) as stream:
            while True:
                line = stream.readline(MAX_ROW_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_ROW_BYTES or not line.endswith(b'\n'):
                    raise ValueError('ledger_row_budget_or_truncation')
                row = decode(line)
                rows.append(row)
                if row.get('kind') == 'close':
                    close = row
                else:
                    prefix.update(line); prefix_bytes += len(line)
        context.count(ledger, 'ledger_decodes')
        context.count(ledger, 'ledger_rows_decoded', len(rows))
        context.count(ledger, 'json_decodes', len(rows))
        return rows, dict(ledger_sha256=context.digest(ledger), ledger_bytes=len(payload),
            prefix_bytes=prefix_bytes, prefix_sha256=prefix.hexdigest(), close=close)
    return context.cached(ledger, 'ledger-rows-v1', load)


def _read_closed_ledger_cached(context, ledger, trace, sidecar, *, expected_budget_bytes, expected_cache_state):
    from script.execution.trace_transport import PHYSICAL_BYTES
    paths = tuple(Path(p) for p in (ledger, trace, sidecar))
    context.check_size(paths[0], MAX_LEDGER_BYTES if expected_budget_bytes is None
                       else integer(expected_budget_bytes, positive=True))
    context.check_size(paths[1], PHYSICAL_BYTES)
    context.check_size(paths[2], 16 * 1024**2)
    # Resolving all dependencies on every call verifies any changed alias too.
    keys = tuple(context.key(path) for path in paths)
    def check():
        rows, facts = read_ledger_rows(paths[0])
        checker = Validator()
        for row in rows:
            checker.consume(row)
        report = checker.report()
        if facts['ledger_bytes'] > checker.header['max_ledger_bytes']:
            raise ValueError('declared_ledger_byte_budget')
        close = facts['close']
        binding = context.read_json(paths[2]).get('host_copy_binding', {})
        if (not isinstance(binding, dict) or binding.get('schema') != 'sara-memory-effects-binding-v2'
                or binding.get('close_succeeded') is not True
                or binding.get('ledger_bytes') != facts['ledger_bytes']
                or binding.get('ledger_sha256') != facts['ledger_sha256']):
            raise ValueError('ledger_sidecar_byte_binding')
        checkpoint = close['checkpoint']
        if ((checkpoint.get('prefix_bytes'), checkpoint.get('prefix_sha256'))
                != (facts['prefix_bytes'], facts['prefix_sha256']) or binding.get('checkpoint') != checkpoint):
            raise ValueError('ledger_prefix_binding')
        payload, transport = read_trace_payload(paths[1])
        if (close.get('trace_sha256') != transport['decoded_sha256']
                or close.get('trace_bytes') != transport['decoded_bytes']):
            raise ValueError('trace_byte_binding')
        tail, marker = payload[-MAX_ROW_BYTES:], b'\n  "host_copy_checkpoint":'
        if tail.count(marker) != 1:
            raise ValueError('unique_terminal_trace_checkpoint_required')
        encoded = tail.split(marker)[1].decode('utf-8')
        parsed, stop = json.JSONDecoder(object_pairs_hook=object_pairs).raw_decode(encoded)
        if parsed != checkpoint or encoded[stop:].strip() != '}':
            raise ValueError('trace_checkpoint_binding')
        report.update(ledger_sha256=facts['ledger_sha256'], trace_sha256=transport['physical_sha256'])
        if transport['codec'] != 'plain':
            report['trace_storage'] = transport
        context.count(ledger, 'ledger_validations')
        return report, checker.header
    report, header = context.cached(ledger, ('closed-ledger-v1', keys), check)
    if expected_budget_bytes is not None and header['max_ledger_bytes'] != integer(expected_budget_bytes, positive=True):
        raise ValueError('source_contract_ledger_budget_mismatch')
    if expected_cache_state is not None and header['cache_state_enabled'] is not expected_cache_state:
        raise ValueError('source_contract_cache_state_mode_mismatch')
    return report


def read_closed_ledger(ledger, trace, sidecar, *, expected_budget_bytes=None, expected_cache_state=None):
    from script.execution.method_input_context import current_context
    context = current_context(ledger)
    if context is not None:
        return _read_closed_ledger_cached(context, ledger, trace, sidecar,
            expected_budget_bytes=expected_budget_bytes, expected_cache_state=expected_cache_state)
    paths = tuple(Path(p) for p in (ledger, trace, sidecar))
    if any(p.is_symlink() or not p.is_file() for p in paths):
        raise ValueError("regular_retained_files_required")
    binding = decode(paths[2].read_text()).get("host_copy_binding", {})
    checker = Validator(); digest = hashlib.sha256(); total = 0; prefix = None; close = None
    with paths[0].open("rb") as stream:
        while True:
            line = stream.readline(MAX_ROW_BYTES + 1)
            if not line: break
            if len(line) > MAX_ROW_BYTES or not line.endswith(b"\n"):
                raise ValueError("ledger_row_budget_or_truncation")
            total += len(line)
            if total > MAX_LEDGER_BYTES: raise ValueError("ledger_byte_budget")
            row = decode(line)
            if row.get("kind") == "close": prefix = (total - len(line), digest.hexdigest()); close = row
            checker.consume(row)
            if total > checker.header["max_ledger_bytes"]: raise ValueError("declared_ledger_byte_budget")
            if expected_budget_bytes is not None and checker.header["max_ledger_bytes"] != integer(expected_budget_bytes, positive=True):
                raise ValueError("source_contract_ledger_budget_mismatch")
            if expected_cache_state is not None and checker.header["cache_state_enabled"] is not expected_cache_state:
                raise ValueError("source_contract_cache_state_mode_mismatch")
            digest.update(line)
    report = checker.report()
    if not isinstance(binding, dict) or binding.get("schema") != "sara-memory-effects-binding-v2" or binding.get("close_succeeded") is not True or binding.get("ledger_bytes") != total or binding.get("ledger_sha256") != digest.hexdigest():
        raise ValueError("ledger_sidecar_byte_binding")
    checkpoint = close["checkpoint"]
    if (checkpoint.get("prefix_bytes"), checkpoint.get("prefix_sha256")) != prefix or binding.get("checkpoint") != checkpoint:
        raise ValueError("ledger_prefix_binding")
    # The ledger binds exact decoded instruction bytes. File provenance binds
    # physical storage separately, so compression cannot change copy ordering.
    payload, transport = read_trace_payload(paths[1])
    if (close.get("trace_sha256") != transport["decoded_sha256"]
            or close.get("trace_bytes") != transport["decoded_bytes"]):
        raise ValueError("trace_byte_binding")
    # Raw capture checker independently validates its footer/full-thread events.
    # The binding below is intentionally acyclic: prefix -> trace -> ledger close.
    # The source-reviewed ordinary writer emits this final top-level field on
    # its own line. Inspect only its bounded tail; the separate completeness
    # reader is responsible for the full capture's JSON/event schema.
    tail = payload[-MAX_ROW_BYTES:]
    marker = b'\n  "host_copy_checkpoint":'
    if tail.count(marker) != 1:
        raise ValueError("unique_terminal_trace_checkpoint_required")
    encoded = tail.split(marker)[1].decode("utf-8")
    parsed, stop = json.JSONDecoder(object_pairs_hook=object_pairs).raw_decode(encoded)
    if parsed != checkpoint or encoded[stop:].strip() != "}":
        raise ValueError("trace_checkpoint_binding")
    report.update(ledger_sha256=digest.hexdigest(), trace_sha256=transport["physical_sha256"])
    if transport["codec"] != "plain": report["trace_storage"] = transport
    return report
