"""Evidence-only full-warp descriptors. This module never authorizes replay.

Caller-supplied capture/PTX/source/membership receipts are checked for mutual
consistency, not independently authenticated. A future issuer must reread their
actual retained evidence. Synthetic fixtures are explicitly labelled. No engine
imports this module, and a successful parse is not a context/semantic token.
"""
import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re


MAX64 = (1 << 64) - 1
PHASE_FILES = frozenset((
    "src/gpgpu-sim/gpu-sim.cc", "src/cuda-sim/cuda-sim.cc", "src/cuda-sim/ptx_sim.h",
    "src/abstract_hardware_model.cc", "src/gpgpu-sim/shader.cc", "libcuda/cuda_runtime_api.cc",
    "src/stream_manager.cc", "src/cuda-sim/cuda-sim.h", "src/cuda-sim/trace_integrity.h",
    "src/cuda-sim/ptx_static_cfg.h", "src/cuda-sim/ptx_shuffle_ops.h",
    "src/cuda-sim/opcode_timing_config.h", "src/cuda-sim/instructions.cc",
))
READ_ROLES = ("data", "b", "c", "membermask")


class GroupEvidenceError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise GroupEvidenceError(reason)


def uint(value, bits=64, minimum=0):
    if isinstance(value, str):
        require(re.fullmatch(r"0x[0-9a-fA-F]+", value) is not None, "invalid_raw_integer")
        value = int(value, 16)
    require(type(value) is int and minimum <= value < 1 << bits, "raw_integer_out_of_range")
    return value


def digest(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
            "missing_exact_sha256")
    return value


def index(value, minimum=0):
    require(type(value) is int, "integer_identity_or_counter_required")
    return uint(value, minimum=minimum)


def coordinates(value, positive=False):
    require(isinstance(value, (list, tuple)) and len(value) == 3, "invalid_coordinates")
    require(all(type(item) is int for item in value), "integer_coordinates_required")
    return tuple(uint(item, 32, 1 if positive else 0) for item in value)


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def strict_json(payload):
    def invalid(_value):
        raise GroupEvidenceError("nonfinite_json_constant")
    return json.loads(payload, object_pairs_hook=_object, parse_constant=invalid)


def register_name(value):
    require(isinstance(value, str) and bool(value) and not value.startswith("#"),
            "real_register_name_required")
    return value


@dataclass(frozen=True)
class RegisterRead:
    lane: int
    role: str
    # Kernel/thread/UID, with name/width validated separately as metadata.
    location: tuple
    name: str
    width_bits: int
    value: int
    literal: bool = False


@dataclass(frozen=True)
class RegisterWrite:
    lane: int
    role: str
    location: tuple
    name: str
    width_bits: int
    value: int
    write_mask: int
    old_value_valid: bool
    old_value: int


@dataclass(frozen=True)
class AtomicGroup:
    group_id: int
    kernel_uid: int
    logical_cta: tuple
    sm_id: int
    cta_id: int
    warp_id: int
    pc: int
    cycle: int
    start_position: int
    end_position: int
    event_ordinals: tuple
    reads: tuple
    writes: tuple


@dataclass(frozen=True)
class ParseReport:
    metadata_consistent: bool
    groups: tuple
    issues: tuple
    binding_identity: tuple
    provenance_kind: str
    total_events: int

    def as_report(self):
        return {
            "schema": "sara-full32-evidence-parser-v1",
            "metadata_consistent": self.metadata_consistent,
            "groups": [asdict(group) for group in self.groups],
            "global_contract_issues": list(self.issues),
            "binding_identity": dict(self.binding_identity),
            "provenance_kind": self.provenance_kind,
            "total_events": self.total_events,
            "receipt_inputs_independently_revalidated": False,
            "scope": "supplied_warp_metadata_consistency_only",
            "replay_enabled": False, "context_authorized": False,
            "semantic_authorized": False, "automatic_gate_pass": False,
            "physical_predicate_container_certified": False,
        }


def _bindings(binding, payload, document):
    require(isinstance(binding, dict) and binding.get("schema") == "sara-full32-parser-input-v1",
            "parser_binding_schema_missing")
    provenance = binding.get("provenance_kind")
    require(provenance in ("synthetic_fixture", "retained_source_bound_diagnostic"),
            "explicit_diagnostic_or_fixture_provenance_required")
    trace_hash = hashlib.sha256(payload).hexdigest()
    require(digest(binding.get("trace_sha256")) == trace_hash, "raw_trace_digest_changed")
    source = digest(binding.get("source_fingerprint"))
    image = binding.get("image_id")
    require(isinstance(image, str) and image.startswith("sha256:"), "image_identity_missing")
    digest(image[7:])
    phase = digest(binding.get("phase_certificate_sha256"))
    phase_files = binding.get("phase_source_files")
    require(isinstance(phase_files, dict) and set(phase_files) == PHASE_FILES,
            "complete_current_phase_source_set_required")
    for value in phase_files.values():
        digest(value)
    ptx = digest(binding.get("loaded_ptx_sha256"))
    capture = binding.get("capture_receipt", {})
    require(capture.get("schema") == "sara-trace-completeness-check-v1"
            and capture.get("valid") is True and capture.get("formal_trace_complete") is True
            and capture.get("trace_sha256") == trace_hash,
            "matching_complete_v2_capture_receipt_required")
    sidecar = digest(capture.get("sidecar_sha256"))
    require(document.get("trace_schema") == "sara-exact-trace-v2", "raw_v2_document_required")
    events = document.get("events")
    footer = document.get("capture_footer", {})
    require(isinstance(events, list) and bool(events) and footer.get("capture_complete") is True
            and footer.get("counter_overflow") is False and footer.get("io_error") is False
            and type(footer.get("total_events")) is int and footer["total_events"] == len(events),
            "matching_normal_capture_footer_required")
    for position, row in enumerate(events):
        require(isinstance(row, dict) and row.get("event_ordinal") == position + 1
                and type(row.get("event_ordinal")) is int
                and row.get("opcode_source") == "structured_ptx_ir_v1",
                "raw_global_ordinal_or_structured_source_missing")
    membership = binding.get("kernel_membership", {})
    require(membership.get("schema") == "sara-full32-membership-input-v1",
            "independent_membership_input_missing")
    digest(membership.get("normal_runtime_log_sha256"))
    uid = index(membership.get("kernel_uid"), minimum=1)
    grid, block = coordinates(membership.get("grid"), True), coordinates(membership.get("block"), True)
    require(block[0] * block[1] * block[2] % 32 == 0, "complete_warp_geometry_required")
    threads = membership.get("threads")
    require(isinstance(threads, list) and bool(threads), "actual_thread_membership_missing")
    expected_count = grid[0] * grid[1] * grid[2] * block[0] * block[1] * block[2]
    require(len(threads) == expected_count, "declared_geometry_member_count_incomplete")
    by_thread, occupied = {}, set()
    for item in threads:
        tid = index(item.get("thread_id"), minimum=1)
        cta, logical = coordinates(item.get("logical_cta")), coordinates(item.get("logical_tid"))
        require(all(c < g for c, g in zip(cta, grid)) and all(t < b for t, b in zip(logical, block)),
                "thread_outside_declared_actual_geometry")
        require(tid not in by_thread and (cta, logical) not in occupied, "nonbijective_thread_membership")
        by_thread[tid] = (cta, logical)
        occupied.add((cta, logical))
    require({index(row.get("kernel_uid"), minimum=1) for row in events} == {uid},
            "single_kernel_diagnostic_scope_required")
    require({index(row.get("thread_id"), minimum=1) for row in events} == set(by_thread),
            "captured_and_independent_thread_sets_disagree")
    for row in events:
        require(by_thread[row["thread_id"]] == (coordinates(row.get("logical_cta")),
                                               coordinates(row.get("logical_tid"))),
                "actual_event_thread_coordinates_changed")
    records = binding.get("loaded_operand_records")
    require(isinstance(records, list) and bool(records), "loaded_operand_records_required")
    operands = {}
    for record in records:
        require(record.get("loaded_ptx_sha256") == ptx and record.get("kernel_uid") == uid,
                "operand_record_loaded_ptx_or_kernel_mismatch")
        digest(record.get("statement_sha256"))
        pc = uint(record.get("pc"))
        require(pc not in operands and type(record.get("kernel_uid")) is int
                and record.get("opcode") == "shfl.sync.down.b32"
                and record.get("mode") == "down", "unique_admitted_loaded_operand_form_required")
        require(isinstance(record.get("sources"), list) and len(record["sources"]) == 4,
                "four_explicit_loaded_source_roles_required")
        require(isinstance(record.get("destinations"), list) and len(record["destinations"]) in (1, 2),
                "loaded_destination_shape_required")
        operands[pc] = record
    identity = tuple(sorted({"trace_sha256": trace_hash, "sidecar_sha256": sidecar,
        "source_fingerprint": source, "image_id": image, "loaded_ptx_sha256": ptx,
        "phase_certificate_sha256": phase,
        "binding_canonical_sha256": hashlib.sha256(json.dumps(binding, sort_keys=True,
                                                              separators=(",", ":")).encode()).hexdigest(),
        "phase_source_files_sha256": hashlib.sha256(json.dumps(phase_files, sort_keys=True,
                                                              separators=(",", ":")).encode()).hexdigest(),
        "operand_records_sha256": hashlib.sha256(json.dumps(records, sort_keys=True,
                                                            separators=(",", ":")).encode()).hexdigest(),
        "membership_sha256": hashlib.sha256(json.dumps(membership, sort_keys=True,
                                                       separators=(",", ":")).encode()).hexdigest()}.items()))
    return identity, provenance, events, by_thread, block, operands


def _parse_group(rows, start, by_thread, block, record):
    first = rows[0]
    metadata = first.get("shuffle", {})
    gid = index(metadata.get("dynamic_group_id"), minimum=1)
    kernel = index(first.get("kernel_uid"), minimum=1)
    cta = coordinates(first.get("logical_cta"))
    sm, cta_id, warp, cycle = (index(first.get(key)) for key in ("sm_id", "cta_id", "warp_id", "cycle"))
    pc = uint(first.get("pc"))
    expected_context = kernel, cta, sm, cta_id, warp, pc, cycle
    snapshot = metadata.get("source_snapshot")
    require(metadata.get("source_snapshot_emitted") is True
            and isinstance(snapshot, list) and len(snapshot) == 32, "one_full32_prewrite_snapshot_required")
    require(all(type(item.get("lane")) is int for item in snapshot)
            and [item.get("lane") for item in snapshot] == list(range(32))
            and len({index(item.get("thread_id"), minimum=1) for item in snapshot}) == 32,
            "snapshot_lane_thread_bijection_required")
    reads, writes, contexts, logical_warps = [], [], set(), set()
    # Every source/destination descriptor is validated before any version map
    # is available; _parse_group does not update architectural/live state.
    for lane, row in enumerate(rows):
        meta = row.get("shuffle", {})
        require(row.get("opcode") == "shfl.sync.down.b32" and row.get("kind") == "inst"
                and row.get("pred") is None and type(row.get("width_bits")) is int
                and row["width_bits"] == 32,
                "unpredicated_scalar_full32_form_required")
        require(not any(row.get(key) is not None for key in ("mem_addr", "mem_space", "ea_expr")),
                "shuffle_memory_effect_not_admitted")
        context = (index(row.get("kernel_uid"), minimum=1), coordinates(row.get("logical_cta")),
                   index(row.get("sm_id")), index(row.get("cta_id")), index(row.get("warp_id")),
                   uint(row.get("pc")), index(row.get("cycle")))
        require(context == expected_context, "group_context_pc_or_cycle_changed")
        require(meta.get("schema") == "sara-full-warp-shuffle-v1"
                and type(meta.get("lane")) is int and meta["lane"] == lane
                and index(meta.get("dynamic_group_id"), minimum=1) == gid
                and meta.get("mode") == "down"
                and meta.get("group_update_semantics") == "all_sources_before_any_destination",
                "complete_ordered_dynamic_group_required")
        if lane:
            require(meta.get("source_snapshot_emitted") is False and "source_snapshot" not in meta,
                    "duplicate_or_misplaced_snapshot")
        thread = index(row.get("thread_id"), minimum=1)
        logical = coordinates(row.get("logical_tid"))
        linear = logical[0] + block[0] * (logical[1] + block[1] * logical[2])
        require(by_thread[thread] == (cta, logical) and linear % 32 == lane
                and thread not in contexts, "group_actual_lane_thread_mapping_changed")
        contexts.add(thread)
        logical_warps.add(linear // 32)
        index(row.get("thread_instruction_ordinal"), minimum=1)
        cols = [row.get(key) for key in ("src_regs", "src_reg_uids", "src_vals", "src_width_bits")]
        require(all(isinstance(col, list) and len(col) == 4 for col in cols),
                "all_four_typed_source_columns_required")
        names, uids, values, widths = cols
        values = [uint(value, 32) for value in values]
        require(all(type(width) is int and width == 32 for width in widths), "shuffle_source_width_changed")
        peer = snapshot[lane]
        require(peer.get("thread_id") == thread and peer.get("register") == names[0]
                and index(peer.get("register_uid")) == uids[0]
                and type(peer.get("width_bits")) is int and peer["width_bits"] == 32
                and uint(peer.get("value"), 32) == values[0], "prewrite_snapshot_or_source_uid_disagrees")
        for source, (role, name, uid, value, expected) in enumerate(zip(
                READ_ROLES, names, uids, values, record["sources"])):
            require(expected.get("role") == role and type(expected.get("width_bits")) is int
                    and expected["width_bits"] == 32,
                    "loaded_source_role_or_width_changed")
            if expected.get("kind") == "register":
                name = register_name(name)
                uid = index(uid)
                require(expected.get("name") == name and index(expected.get("register_uid")) == uid,
                        "loaded_register_identity_changed")
                location = (kernel, thread, uid)
                literal = False
            else:
                require(source > 0 and expected.get("kind") == "literal" and type(uid) is int and uid == -1
                        and name == "#imm_" + str(source + 1)
                        and type(expected.get("value")) is int and expected["value"] == value,
                        "loaded_literal_identity_or_value_changed")
                location, literal = (), True
            reads.append(RegisterRead(lane, role, location, name, 32, value, literal))
        require([uint(meta.get(key), 32) for key in ("b", "c", "membermask")] == values[1:]
                and values[3] == 0xffffffff, "controls_or_full_membermask_disagree")
        selected = uint(meta.get("source_lane"), 5)
        require(type(meta.get("in_range")) is bool, "logical_in_range_required")
        # Independent down-form consistency only; this does not evaluate a
        # mutant or authorize exact SHFL. All32 inputs remain graph parents.
        segment = (values[2] >> 8) & 31
        maximum = (lane & segment) | ((values[2] & 31) & (~segment & 31))
        candidate = lane + (values[1] & 31)
        in_range = candidate <= maximum
        require(meta["in_range"] == in_range and selected == (candidate if in_range else lane),
                "golden_selected_lane_or_in_range_disagrees")
        destinations = meta.get("destinations")
        require(isinstance(destinations, list) and len(destinations) == len(record["destinations"]),
                "complete_loaded_typed_destination_vector_required")
        used_uids = set()
        for number, (dst, expected) in enumerate(zip(destinations, record["destinations"])):
            role, width = ("data", 32) if number == 0 else ("in_range_predicate", 1)
            name, uid = register_name(dst.get("register")), index(dst.get("register_uid"))
            value, old = uint(dst.get("value"), width), uint(dst.get("old_value"), width)
            require(uid not in used_uids and dst.get("role") == expected.get("role") == role
                    and type(dst.get("width_bits")) is int and type(expected.get("width_bits")) is int
                    and dst["width_bits"] == expected["width_bits"] == width
                    and expected.get("name") == name and index(expected.get("register_uid")) == uid
                    and uint(dst.get("write_mask")) == (1 << width) - 1
                    and type(dst.get("old_value_valid")) is bool,
                    "typed_destination_identity_mask_or_old_value_invalid")
            require(dst["old_value_valid"] or old == 0, "invalid_old_value_must_be_explicitly_empty")
            used_uids.add(uid)
            if number:
                require(dst.get("value_encoding") == "gpgpu_sim_zero_flag" and value == (0 if in_range else 1),
                        "optional_predicate_encoding_or_value_wrong")
            else:
                require(value == uint(snapshot[selected].get("value"), 32), "golden_data_write_disagrees_with_snapshot")
            writes.append(RegisterWrite(lane, role, (kernel, thread, uid), name, width, value,
                                        (1 << width) - 1, dst["old_value_valid"], old))
    require(len(logical_warps) == 1, "mixed_logical_warps_in_one_dynamic_group")
    identities, read_values = {}, {}
    for read in reads:
        if read.literal:
            continue
        require(identities.setdefault(read.location, (read.name, read.width_bits)) == (read.name, read.width_bits),
                "same_uid_conflicting_symbol_metadata")
        require(read_values.setdefault(read.location, read.value) == read.value, "same_prewrite_uid_conflicting_values")
    for write in writes:
        require(identities.setdefault(write.location, (write.name, write.width_bits)) == (write.name, write.width_bits),
                "same_uid_conflicting_symbol_metadata")
        if write.location in read_values:
            require(write.old_value_valid and write.old_value == read_values[write.location],
                    "inplace_write_old_value_disagrees_with_prewrite_read")
    return AtomicGroup(gid, kernel, cta, sm, cta_id, warp, pc, cycle, start, start + 32,
                       tuple(row["event_ordinal"] for row in rows), tuple(reads), tuple(writes))


def _bindings_v2(binding, payload, document):
    """Whole original trace consistency; no subtrace or fabricated v1 receipt."""
    require(isinstance(binding, dict) and binding.get("schema")=="sara-full32-parser-input-v2",
            "whole_trace_parser_binding_schema_missing")
    provenance=binding.get("provenance_kind")
    require(provenance in ("synthetic_fixture","retained_source_bound_diagnostic"),
            "explicit_diagnostic_or_fixture_provenance_required")
    trace_hash=hashlib.sha256(payload).hexdigest()
    require(digest(binding.get("trace_sha256"))==trace_hash,"raw_trace_digest_changed")
    source=digest(binding.get("source_fingerprint"));image=binding.get("image_id")
    require(isinstance(image,str) and image.startswith("sha256:"),"image_identity_missing")
    digest(image[7:]);phase=digest(binding.get("phase_certificate_sha256"))
    phase_files=binding.get("phase_source_files")
    require(isinstance(phase_files,dict) and set(phase_files)==PHASE_FILES,"complete_current_phase_source_set_required")
    for value in phase_files.values():digest(value)
    ptx=digest(binding.get("loaded_ptx_sha256"));capture=binding.get("capture_receipt",{})
    require(capture.get("schema")=="sara-trace-completeness-check-v1" and capture.get("valid") is True
            and capture.get("formal_trace_complete") is True and capture.get("trace_sha256")==trace_hash,
            "matching_complete_whole_trace_capture_receipt_required")
    sidecar=digest(capture.get("sidecar_sha256"))
    require(document.get("trace_schema")=="sara-exact-trace-v2","raw_v2_document_required")
    events=document.get("events");footer=document.get("capture_footer",{})
    require(isinstance(events,list) and bool(events) and footer.get("schema")=="sara-trace-capture-footer-v1"
            and footer.get("capture_complete") is True and footer.get("counter_overflow") is False
            and footer.get("io_error") is False and type(footer.get("total_events")) is int
            and footer["total_events"]==len(events),"matching_whole_capture_footer_required")
    memberships=binding.get("membership_by_kernel")
    require(isinstance(memberships,dict) and bool(memberships),"whole_kernel_membership_table_required")
    members,blocks,entries,all_threads,log_hashes={},{},{},set(),set()
    for key,member in memberships.items():
        require(isinstance(key,str) and re.fullmatch(r"[1-9][0-9]*",key) is not None,
                "canonical_kernel_membership_key_required")
        uid=index(int(key),minimum=1)
        require(isinstance(member,dict) and member.get("schema")=="sara-full32-membership-input-v1"
                and index(member.get("kernel_uid"),minimum=1)==uid,"whole_kernel_membership_identity_mismatch")
        entry=member.get("entry")
        require(isinstance(entry,str) and bool(entry) and not any(c.isspace() for c in entry),"actual_kernel_entry_required")
        entries[uid]=entry;log_hashes.add(digest(member.get("normal_runtime_log_sha256")))
        grid,block=coordinates(member.get("grid"),True),coordinates(member.get("block"),True)
        blocks[uid]=block;threads=member.get("threads");count=1
        for extent in grid+block:count*=extent
        require(count<=MAX64 and isinstance(threads,list) and len(threads)==count,"declared_geometry_member_count_incomplete")
        table,occupied={},set()
        for item in threads:
            thread=index(item.get("thread_id"),minimum=1)
            cta,tid=coordinates(item.get("logical_cta")),coordinates(item.get("logical_tid"))
            require(all(a<b for a,b in zip(cta,grid)) and all(a<b for a,b in zip(tid,block)),
                    "thread_outside_declared_actual_geometry")
            require(thread not in table and thread not in all_threads and (cta,tid) not in occupied,
                    "whole_thread_UID_or_geometry_not_bijective")
            table[thread]=(cta,tid);occupied.add((cta,tid));all_threads.add(thread)
        members[uid]=table
    require(len(log_hashes)==1,"whole_kernel_memberships_have_different_runtime_logs")
    normal=footer.get("normal_kernel_uids");captured=capture.get("summary",{}).get("normal_kernel_uids")
    for values in (normal,captured):
        require(isinstance(values,list) and all(type(u) is int and u>0 for u in values)
                and len(set(values))==len(values) and set(values)==set(members),"whole_capture_kernel_sets_disagree")
    kernel_rows=footer.get("kernels")
    require(isinstance(kernel_rows,list) and len(kernel_rows)==len(members),"whole_kernel_footer_missing")
    seen=set();entry_pcs={}
    for row in kernel_rows:
        uid=index(row.get("kernel_uid"),minimum=1)
        require(uid in members and uid not in seen and row.get("normal_completion") is True
                and row.get("completion_source")=="stream_manager_kernel_is_finished"
                and coordinates(row.get("grid"),True)==coordinates(memberships[str(uid)]["grid"],True)
                and coordinates(row.get("block"),True)==blocks[uid]
                and type(row.get("expected_threads")) is int and row["expected_threads"]==len(members[uid]),
                "whole_kernel_footer_identity_geometry_or_completion_mismatch")
        seen.add(uid)
        entry_pcs[uid]=uint(row.get("entry_pc"))
    attempts={};seen_threads=set();previous_cycle=-1;first_pcs={};last_pcs={}
    for position,row in enumerate(events):
        require(isinstance(row,dict) and type(row.get("event_ordinal")) is int
                and row["event_ordinal"]==position+1 and row.get("opcode_source")=="structured_ptx_ir_v1",
                "raw_global_ordinal_or_structured_source_missing")
        uid,thread=index(row.get("kernel_uid"),minimum=1),index(row.get("thread_id"),minimum=1)
        require(uid in members and thread in members[uid]
                and members[uid][thread]==(coordinates(row.get("logical_cta")),coordinates(row.get("logical_tid"))),
                "whole_event_kernel_thread_or_coordinates_changed")
        cycle=index(row.get("cycle"));require(cycle>=previous_cycle,"whole_trace_cycles_not_monotone");previous_cycle=cycle
        attempt=index(row.get("thread_instruction_ordinal"),minimum=1)
        require(attempt==attempts.get(thread,0)+1,"whole_thread_attempt_prefix_gap_or_duplicate")
        attempts[thread]=attempt;seen_threads.add(thread)
        pc=uint(row.get("pc"));first_pcs.setdefault(thread,pc);last_pcs[thread]=pc
        if str(row.get("opcode","")).startswith("shfl."):
            require(blocks[uid][0]*blocks[uid][1]*blocks[uid][2]%32==0,"complete_warp_geometry_required")
    require(seen_threads==all_threads,"whole_captured_and_independent_thread_sets_disagree")
    thread_rows=footer.get("threads")
    require(isinstance(thread_rows,list) and len(thread_rows)==len(all_threads),"whole_thread_footer_missing")
    seen=set()
    for row in thread_rows:
        uid,thread=index(row.get("kernel_uid"),minimum=1),index(row.get("thread_id"),minimum=1)
        require(uid in members and thread in members[uid] and thread not in seen and row.get("terminated") is True
                and members[uid][thread]==(coordinates(row.get("logical_cta")),coordinates(row.get("logical_tid")))
                and type(row.get("event_count")) is int and row["event_count"]==attempts[thread]
                and type(row.get("final_attempt_count")) is int and row["final_attempt_count"]==attempts[thread]
                and uint(row.get("first_pc"))==first_pcs[thread]==uint(row.get("entry_pc"))==entry_pcs[uid]
                and uint(row.get("last_pc"))==last_pcs[thread],
                "whole_thread_footer_identity_termination_or_count_mismatch")
        seen.add(thread)
    summary=capture.get("summary",{})
    require(type(summary.get("total_events")) is int and summary["total_events"]==len(events)
            and type(summary.get("thread_count")) is int and summary["thread_count"]==len(all_threads),
            "whole_capture_summary_event_or_thread_count_mismatch")
    records=binding.get("loaded_operand_records");require(isinstance(records,list) and bool(records),"loaded_operand_records_required")
    operands={}
    for record in records:
        uid=index(record.get("kernel_uid"),minimum=1);pc=uint(record.get("pc"));key=uid,pc
        require(uid in members and record.get("entry")==entries[uid] and record.get("loaded_ptx_sha256")==ptx,
                "operand_record_loaded_module_kernel_or_entry_mismatch")
        digest(record.get("statement_sha256"))
        require(key not in operands and record.get("opcode")=="shfl.sync.down.b32" and record.get("mode")=="down",
                "unique_kernel_PC_loaded_operand_form_required")
        require(isinstance(record.get("sources"),list) and len(record["sources"])==4
                and isinstance(record.get("destinations"),list) and len(record["destinations"]) in (1,2),
                "complete_loaded_source_and_destination_vectors_required")
        operands[key]=record
    identity=tuple(sorted({"parser_input_schema":"sara-full32-parser-input-v2","trace_sha256":trace_hash,
        "sidecar_sha256":sidecar,"source_fingerprint":source,"image_id":image,"loaded_ptx_sha256":ptx,
        "phase_certificate_sha256":phase,
        "binding_canonical_sha256":hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
        "phase_source_files_sha256":hashlib.sha256(json.dumps(phase_files,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
        "operand_records_sha256":hashlib.sha256(json.dumps(records,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
        "membership_sha256":hashlib.sha256(json.dumps(memberships,sort_keys=True,separators=(",",":")).encode()).hexdigest()}.items()))
    return identity,provenance,events,members,blocks,operands


def parse_full32_effects_v2(raw_payload,binding):
    """Same atomic descriptors in original global positions; no new authority."""
    identity,provenance,total_events=(),"unverified_input",0
    try:
        require(isinstance(raw_payload,bytes),"original_raw_trace_bytes_required")
        document=strict_json(raw_payload);require(isinstance(document,dict),"raw_document_not_object")
        identity,provenance,events,members,blocks,operands=_bindings_v2(binding,raw_payload,document)
        total_events=len(events);groups=[];seen=set();used=set();position=0;previous_id=0
        while position<len(events):
            row=events[position]
            if not str(row.get("opcode","")).startswith("shfl."):
                require("shuffle" not in row,"shuffle_metadata_on_nonshuffle_event");position+=1;continue
            uid=index(row.get("kernel_uid"),minimum=1);key=uid,uint(row.get("pc"))
            require(key in operands and position+32<=len(events),"missing_kernel_PC_operand_or_group_tail")
            group=_parse_group(events[position:position+32],position,members[uid],blocks[uid],operands[key])
            require(group.group_id not in seen and group.group_id>previous_id,"reused_or_nonmonotonic_dynamic_group_id")
            seen.add(group.group_id);used.add(key);previous_id=group.group_id;groups.append(group);position+=32
        require(bool(groups),"no_full32_groups_in_supplied_trace")
        require(used==set(operands),"unused_or_missing_kernel_PC_operand_record")
        return ParseReport(True,tuple(groups),(),identity,provenance,total_events)
    except (GroupEvidenceError,ValueError,TypeError,KeyError,IndexError,AttributeError) as error:
        return ParseReport(False,(),(type(error).__name__+":"+str(error),),identity,provenance,total_events)


def parse_full32_effects(raw_payload, binding):
    """Return all descriptors or a global issue, never a silently accepted subset.

    The caller must supply original JSON bytes (not a reserialized projection).
    No filesystem, engine, oracle or simulator is invoked by this pure function.
    """
    if isinstance(binding, dict) and binding.get("schema") == "sara-full32-parser-input-v2":
        return parse_full32_effects_v2(raw_payload, binding)
    identity, provenance, total_events = (), "unverified_input", 0
    try:
        require(isinstance(raw_payload, bytes), "original_raw_trace_bytes_required")
        document = strict_json(raw_payload)
        require(isinstance(document, dict), "raw_document_not_object")
        identity, provenance, events, members, block, operands = _bindings(binding, raw_payload, document)
        total_events = len(events)
        groups, seen, used_pcs, position, previous_id = [], set(), set(), 0, 0
        while position < len(events):
            row = events[position]
            if not str(row.get("opcode", "")).startswith("shfl."):
                require("shuffle" not in row, "shuffle_metadata_on_nonshuffle_event")
                position += 1
                continue
            pc = uint(row.get("pc"))
            require(pc in operands and position + 32 <= len(events), "missing_loaded_operand_or_group_tail")
            group = _parse_group(events[position:position + 32], position, members, block, operands[pc])
            require(group.group_id not in seen and group.group_id > previous_id,
                    "reused_or_nonmonotonic_dynamic_group_id")
            seen.add(group.group_id); used_pcs.add(pc); previous_id = group.group_id
            groups.append(group); position += 32
        require(bool(groups), "no_full32_groups_in_supplied_trace")
        require(used_pcs == set(operands), "unused_or_missing_loaded_shuffle_operand_record")
        return ParseReport(True, tuple(groups), (), identity, provenance, total_events)
    except (GroupEvidenceError, ValueError, TypeError, KeyError, IndexError, AttributeError) as error:
        return ParseReport(False, (), (type(error).__name__ + ":" + str(error),), identity, provenance, total_events)


def check_origin_boundary(report, before_position):
    """Boundary consistency only. Mapping, FI phase and scope remain unproved."""
    require(isinstance(report, ParseReport) and report.metadata_consistent, "complete_group_report_required")
    require(type(before_position) is int and 0 <= before_position <= report.total_events, "invalid_origin_boundary")
    for group in report.groups:
        require(not group.start_position < before_position < group.end_position,
                "origin_boundary_inside_atomic_group")
    return {"boundary_outside_all_groups": True, "mapping_certified": False,
            "phase_certified": False, "replay_enabled": False, "automatic_gate_pass": False}


def materialize_atomic_versions(group, pre_versions, *, next_version):
    """Build candidate edges using supplied live versions; never replay values.

    ``pre_versions`` maps (kernel, thread, UID) to a record containing version,
    name, width_bits and value. It must be the actual live map at this group.
    This helper does not skip intervening ordinary instructions or stitch
    separate groups together. Neither input map nor the group is mutated.
    """
    require(isinstance(group, AtomicGroup), "parsed_atomic_group_required")
    require(isinstance(pre_versions, dict), "explicit_pre_group_live_versions_required")
    next_version = uint(next_version)
    for location, old in pre_versions.items():
        require(isinstance(location, tuple) and len(location) == 3
                and all(type(item) is int and item >= 0 for item in location)
                and location[0] >= 1 and location[1] >= 1 and isinstance(old, dict),
                "typed_live_register_location_required")
        require(type(old.get("width_bits")) is int and old["width_bits"] in (1, 8, 16, 32, 64),
                "typed_live_register_width_required")
        require(type(old.get("value")) is int, "integer_live_register_raw_bits_required")
        uint(old["value"], old["width_bits"])
        register_name(old.get("name"))
    require(all(type(v.get("version")) is int and 0 <= v["version"] < next_version
                for v in pre_versions.values()), "fresh_definition_version_ids_required")
    require(len({v["version"] for v in pre_versions.values()}) == len(pre_versions),
            "distinct_locations_require_distinct_live_versions")
    read_records, parents = [], set()
    # Phase1 resolves every data/control role from the unmodified pre-group map.
    for read in group.reads:
        item = asdict(read)
        if read.literal:
            item["input_version"] = None
        else:
            old = pre_versions.get(read.location)
            require(old is not None and old.get("name") == read.name
                    and old.get("width_bits") == read.width_bits and old.get("value") == read.value,
                    "actual_pre_group_read_version_missing_or_inconsistent")
            item["input_version"] = old["version"]; parents.add(old["version"])
        read_records.append(item)
    # Validate all kills against that same map before allocating any definition.
    kills, locations = [], set()
    for write in group.writes:
        require(write.location not in locations, "duplicate_atomic_write_location")
        locations.add(write.location)
        old = pre_versions.get(write.location)
        require((old is not None) == write.old_value_valid, "old_destination_validity_disagrees_with_live_map")
        if old is not None:
            require(old.get("name") == write.name and old.get("width_bits") == write.width_bits
                    and old.get("value") == write.old_value, "old_destination_live_version_disagrees")
        kills.append({"location": write.location, "killed_version": None if old is None else old["version"],
                      "write_mask": write.write_mask})
    require(next_version + len(group.writes) <= MAX64, "definition_version_counter_overflow")
    after = {key: dict(value) for key, value in pre_versions.items()}
    definitions = []
    # Phase2 allocates all definitions. No definition can be a parent of a
    # definition in this same group, including in-place/control aliases.
    for offset, write in enumerate(group.writes):
        node = next_version + offset
        definitions.append({**asdict(write), "version": node, "parents": tuple(sorted(parents))})
        after[write.location] = {"version": node, "name": write.name,
                                 "width_bits": write.width_bits, "value": write.value}
    return {"reads": tuple(read_records), "kills": tuple(kills), "definitions": tuple(definitions),
            "observable_input_versions": tuple(sorted(parents)), "after_versions": after,
            "next_version": next_version + len(group.writes), "candidate_edges_only": True,
            "replay_enabled": False, "context_authorized": False, "automatic_gate_pass": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--bindings", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--diagnostic-only", action="store_true", required=True)
    args = parser.parse_args(argv)
    require(args.trace.stat().st_size <= 64 * 1024 * 1024, "diagnostic_trace_size_limit")
    report = parse_full32_effects(args.trace.read_bytes(), strict_json(args.bindings.read_bytes()))
    args.output.write_text(json.dumps(report.as_report(), indent=2) + "\n")
    return 0 if report.metadata_consistent else 2


if __name__ == "__main__":
    raise SystemExit(main())
