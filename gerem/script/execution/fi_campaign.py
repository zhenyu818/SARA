"""Run immutable, explicitly resolved FI trials inside the README Docker image.

No random target is selected by this executor. All methods consume the saved
site manifest. A time-window stop is an unfinished attempt, never a DUE. Trial
workers use private files; one locked dispatcher commits atomic trial records.
"""
from datetime import datetime
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
import time

from script.common.outcome_oracle import classify_fi_logs, validate_raw_outputs, _load_log_summary
from script.execution.build_identity import digest
from script.execution.campaign import atomic_json, safe_id
from script.execution.policy import ExecutionWindow, UTC
from script.execution.process_metrics import MeasuredChild, ReapOwnershipError
from script.execution.job_wrapper import cgroup_counters
from script.execution.trial_environment import (explicit_environment as validate_explicit_environment, trial_environment,
    policy_descriptor as trial_environment_descriptor, environment_evidence)

STOP = threading.Event()
POLICY = ExecutionWindow()


def stop_reason():
    return "operator_stop"


def now():
    return datetime.now(UTC).isoformat()


def relative_name(value):
    path = Path(value)
    if path.is_absolute() or not path.parts or any(p in {"..", "."} for p in path.parts):
        raise ValueError("trial assets must have safe relative destinations")
    return path


def configured_text(base, parameters):
    if not isinstance(parameters, dict) or not parameters:
        raise ValueError("trial requires explicit hook parameters")
    allowed = {"-components_to_flip", "-total_cycle_rand", "-thread_rand", "-warp_rand",
               "-register_name", "-register_rand_n", "-reg_bitflip_rand_n", "-kernel_n",
               "-per_warp", "-block_rand", "-block_n", "-shared_mem_bitflip_rand_n",
               "-l1d_shader_rand_n", "-l1d_cache_bitflip_rand_n", "-l2_cache_bitflip_rand_n",
               "-fi_valid_resident_contract"}
    if not set(parameters).issubset(allowed):
        raise ValueError("manifest contains unsupported injection options")
    updates = dict(parameters, **{"-profile": "0", "-exact_trace": "0", "-regfile_trace": "0", "-fi_probe_only": "0"})
    if any(not isinstance(v, str) or not v or any(c.isspace() for c in v) for v in updates.values()):
        raise ValueError("configuration values must be single tokens")
    lines = []
    # Numeric inventory selectors must restore the registered empty default,
    # rather than inherit a stale named selector from the base config. Omitting
    # the option is portable; an empty config argument would consume the next key.
    numeric_rf = "-register_rand_n" in parameters and "-register_name" not in parameters
    for line in base.splitlines():
        parts = line.split()
        if not parts or (parts[0] not in updates and parts[0] not in {"-population_inventory_file", "-cache_capacity_file", "-host_copy_ledger_file", "-host_copy_ledger_budget_bytes", "-cache_state_ledger"} and
                         not (numeric_rf and parts[0] == "-register_name")):
            lines.append(line)
    lines.extend(k + " " + updates[k] for k in sorted(updates))
    return "\n".join(lines) + "\n"


def fault_records(log, *, text=None):
    records = []
    if text is None:
        text = Path(log).read_text(errors="replace")
    for line in text.splitlines():
        if line.startswith("GPUFI_FAULT "):
            records.append(dict(token.split("=", 1) for token in line.split()[1:] if "=" in token))
    return records


def validate_site_binding(trial):
    """The canonical target, acknowledgement and actual hook must name one site."""
    from script.execution.fault_manifest import BIT_OPTION, COMPONENT_OPTION, integer, location_identity
    component = trial["component"]
    target, expected, hooks = trial["target"], trial["ack_expected"], trial["hook_params"]
    location_identity(component, target)
    cycle = integer(trial["cycle"], "site cycle")
    bit = integer(trial["bit"], "site bit")
    if (expected.get("component") != component or str(expected.get("cycle")) != str(cycle)
            or str(expected.get("bit")) != str(bit + 1)):
        raise ValueError("canonical component/cycle/bit disagrees with acknowledgement")
    if (hooks.get("-components_to_flip") != COMPONENT_OPTION[component]
            or hooks.get("-total_cycle_rand") != str(cycle)
            or hooks.get(BIT_OPTION[component]) != str(bit + 1)):
        raise ValueError("manifest injection configuration disagrees with canonical site")
    if component == "rf":
        fields = {"thread": "thread", "register": "reg", "register_uid": "reg_uid",
                  "width_bits": "width", "kernel": "kernel", "sm": "sm", "cta_slot": "cta_slot"}
        width = integer(target.get("width_bits"), "register width", 1)
        if width not in {1, 8, 16, 32, 64, 128} or bit >= width:
            raise ValueError("canonical RF bit exceeds declared register width")
        if "-register_name" in hooks:
            if hooks["-register_name"] != target.get("register"):
                raise ValueError("RF hook register disagrees with canonical register")
        elif not re.fullmatch(r"[1-9][0-9]*", hooks.get("-register_rand_n", "")):
            raise ValueError("RF requires an exact named or inventory-derived numeric selector")
    elif component == "smem":
        fields = {"byte_addr": "byte_addr", "sm": "sm", "cta_slot": "cta_slot", "kernel": "kernel"}
        if integer(target.get("byte_addr"), "shared byte address") != bit // 8:
            raise ValueError("shared bit and byte address disagree")
    else:
        fields = ({"cluster": "cluster", "core": "core", "line": "line"} if component == "l1d"
                  else {"bank": "bank", "line": "line"})
        line_bits = integer(target.get("line_size_bytes"), "cache line size", 1) * 8 + integer(
            target.get("tag_bits"), "cache tag size", 1)
        slot = bit // line_bits
        if component == "l2":
            bank, line = divmod(slot, integer(target.get("lines_per_bank"), "cache lines per bank", 1))
            if bank != integer(target.get("bank"), "cache bank"):
                raise ValueError("cache bit and bank disagree")
        else:
            line = slot
        if line != integer(target.get("line"), "cache line"):
            raise ValueError("cache bit and line disagree")
    for key, ack_key in fields.items():
        if key not in target or ack_key not in expected or str(target[key]) != str(expected[ack_key]):
            raise ValueError("canonical target disagrees with acknowledgement: " + key)


def _validate_resident_cache_data_armed(ack, data_bit, data_bits):
    """Check the existing resident sparse-byte-XOR ACK, not cold eligibility."""
    if (ack.get("component") not in {"l1d", "l2"} or ack.get("kind") != "data"
            or ack.get("storage_model") != "sparse_byte_xor"):
        raise ValueError("armed cache ACK requires the resident sparse-byte-XOR data model")
    fields = {"cycle": 64, "bit": 32, "data_bit": 32, "line": 32, "version": 64}
    fields.update({"cluster": 32, "core": 32} if ack["component"] == "l1d" else {"bank": 32})
    for key, width in fields.items():
        value = ack.get(key)
        if (not isinstance(value, str) or len(value) > 20
                or re.fullmatch(r"0|[1-9][0-9]*", value) is None
                or int(value) >= 1 << width):
            raise ValueError("resident cache ACK has an invalid unsigned field: " + key)
    # An unallocated cold slot has version zero. A future cold-realization
    # protocol needs its own explicit branch; this resident ACK cannot admit it.
    if int(ack["version"]) == 0 or int(ack["bit"]) == 0:
        raise ValueError("resident cache ACK requires positive allocation version and external bit")
    if not 0 <= data_bit < data_bits or int(ack["data_bit"]) != data_bit:
        raise ValueError("resident cache ACK data bit is outside the selected line")
    realization = ack.get("realization_id")
    if (not isinstance(realization, str) or not realization or realization == "none"
            or any(character.isspace() for character in realization)):
        raise ValueError("resident cache ACK lacks a nonempty realization token")
    if not isinstance(ack.get("tag"), str) or re.fullmatch(r"[0-9a-f]{16}", ack["tag"]) is None:
        raise ValueError("resident cache ACK lacks the complete unsigned 64-bit tag")
    for key in ("overlay_before", "overlay_after"):
        if not isinstance(ack.get(key), str) or re.fullmatch(r"[0-9a-f]{2}", ack[key]) is None:
            raise ValueError("resident cache ACK overlay must be a complete unsigned byte")
    if int(ack["overlay_before"], 16) ^ int(ack["overlay_after"], 16) != 1 << (data_bit % 8):
        raise ValueError("resident cache ACK did not flip precisely the requested overlay bit")


def _cross_level_cache_operand_bit(ack, consumption, changed_bit, target, text):
    """Validate literal origin -> issue snapshot -> fill -> later copy chains.

    A timing-service slot is not the source of an already frozen payload. Each
    transported byte instead requires its actual issue key and a previously
    witnessed source copy. Consumer single-bit XOR checks remain in the caller.
    """
    if (ack.get("component") != "l2" or consumption.get("component") != "l1d"
            or ack.get("status") != "armed" or ack.get("kind") != "data"
            or not isinstance(text, str)):
        raise ValueError("cache cross-level consumer lacks a supported resident L2 copy")
    rid = ack.get("realization_id")
    if not rid or rid == "none" or consumption.get("realization_id") != rid:
        raise ValueError("cache cross-level consumer realization differs")

    def decimal(row, name, *, positive=False, bits=64):
        value = row.get(name)
        if (not isinstance(value, str) or re.fullmatch(r"0|[1-9][0-9]*", value) is None
                or len(value) > 20 or int(value) >= 1 << bits or int(value) < int(positive)):
            raise ValueError("invalid cache snapshot lineage unsigned field: " + name)
        return int(value)

    def byte_mask(row):
        value = row.get("mask")
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{2}", value) is None or int(value, 16) == 0:
            raise ValueError("cache snapshot lineage requires a complete nonzero byte mask")
        return int(value, 16)

    def issue_key(row):
        return tuple(decimal(row, key) for key in ("sm", "warp", "pc", "issue"))

    rows = []
    for index, line in enumerate(text.splitlines()):
        if not line.startswith(("GPUFI_CACHE_SNAPSHOT ", "GPUFI_CACHE_COPY ", "GPUFI_FAULT ")):
            continue
        row = {}
        for token in line.split()[1:]:
            if token.count("=") != 1:
                raise ValueError("malformed cache snapshot lineage provenance")
            key, value = token.split("=", 1)
            if key in row or not value:
                raise ValueError("duplicate or empty cache snapshot lineage field")
            row[key] = value
        rows.append((index, line.split()[0], row))
    originals = [i for i, prefix, row in rows if prefix == "GPUFI_FAULT" and row == ack]
    consumers = [i for i, prefix, row in rows if prefix == "GPUFI_FAULT" and row == consumption]
    if len(originals) != 1 or len(consumers) != 1:
        raise ValueError("cache cross-level consumer lacks unique literal ACK/consumer provenance")
    origin_at, consumed_at = originals[0], consumers[0]
    origin_cycle = decimal(ack, "cycle")
    origin_block = int(ack["tag"], 16)  # cache_config::tag equals full block address
    origin_line, origin_version = decimal(ack, "line"), decimal(ack, "version", positive=True)
    fault_byte, fault_mask = origin_block + changed_bit // 8, 1 << (changed_bit % 8)
    consumer_cycle = decimal(consumption, "cycle")
    operand_start = decimal(consumption, "byte_addr")
    operand_width = decimal(consumption, "width", positive=True, bits=32)
    operand_bit = (fault_byte - operand_start) * 8 + changed_bit % 8
    if not 0 <= operand_bit < operand_width:
        raise ValueError("cache origin byte is outside the propagated scalar operand")

    # Each entry is admitted only after its complete earlier source chain.
    # Copy keys retain level, actual owner (when L1), slot/version and block;
    # request issue keys retain the independently logged source snapshot.
    snapshots, copies = {}, {}
    for index, prefix, row in rows:
        if not origin_at < index < consumed_at or row.get("realization_id") != rid:
            continue
        component = row.get("component")
        if prefix == "GPUFI_CACHE_SNAPSHOT":
            if component not in {"l1d", "l2"}:
                raise ValueError("unsupported cache snapshot lineage level")
            cycle = decimal(row, "cycle")
            key = issue_key(row)
            block, line = decimal(row, "block_addr"), decimal(row, "line")
            version = decimal(row, "version", positive=True)
            if (decimal(row, "byte_addr") != fault_byte or byte_mask(row) != fault_mask
                    or not origin_cycle <= cycle <= consumer_cycle):
                continue
            source = (component, key[0] if component == "l1d" else None, line, version, block)
            original = (component == "l2" and (line, version, block)
                        == (origin_line, origin_version, origin_block))
            if not original and (source not in copies or copies[source] > cycle):
                continue
            if key in snapshots:
                raise ValueError("duplicate functional snapshot for the same fault byte and issue key")
            snapshots[key] = cycle
        elif prefix == "GPUFI_CACHE_COPY" and row.get("status") == "fill":
            if component not in {"l1d", "l2"}:
                raise ValueError("unsupported cache fill lineage level")
            cycle = decimal(row, "cycle")
            key = issue_key(row)
            if (key not in snapshots or not snapshots[key] <= cycle <= consumer_cycle
                    or decimal(row, "request_uid", positive=True) <= 0
                    or decimal(row, "byte_addr") != fault_byte or byte_mask(row) != fault_mask):
                continue
            scope = decimal(row, "scope")
            block, line = decimal(row, "block_addr"), decimal(row, "line")
            version = decimal(row, "version", positive=True)
            line_bytes = decimal(row, "line_bytes", positive=True)
            if (line_bytes > 2**32 or block % line_bytes
                    or not block <= fault_byte < block + line_bytes):
                continue
            source = (component, scope if component == "l1d" else None, line, version, block)
            copies[source] = cycle
            physical_bit = (fault_byte - block) * 8 + changed_bit % 8
            if (component == "l1d" and scope == decimal(consumption, "sm")
                    and line == decimal(consumption, "line")
                    and version == decimal(consumption, "version", positive=True)
                    and decimal(consumption, "data_bit", bits=32) == physical_bit):
                return operand_bit
    raise ValueError("cache cross-level consumer lacks ordered origin snapshot and actual L1 byte fill")


def validate_acknowledgement(trial, records, *, log_text=None):
    if any(row.get("status") == "rejected" for row in records):
        raise ValueError("simulator rejected the requested fault configuration")
    primary = [row for row in records if row.get("status") in {"applied", "armed", "cold_armed", "unmapped"}]
    if len(primary) != 1:
        raise ValueError("expected exactly one realized injection acknowledgement")
    ack = primary[0]
    expected = trial.get("ack_expected", {})
    required = {"cycle", "bit", "component"}
    if trial["component"] == "rf":
        required.update({"thread", "reg", "width"})
    elif trial["component"] == "smem":
        required.update({"cta_slot"})
    elif trial["component"] == "l1d":
        required.update({"core", "cluster", "line"})
    else:
        required.update({"bank", "line"})
    if not required.issubset(expected):
        raise ValueError("manifest lacks a complete realized target identity")
    if any(str(ack.get(key)) != str(value) for key, value in expected.items()):
        raise ValueError("requested and realized injection identities differ")
    component = trial["component"]
    canonical_bit = trial["bit"]
    if int(ack["bit"]) != canonical_bit + 1:
        raise ValueError("acknowledgement bit differs from canonical bit")
    if component == "rf":
        changed_bit = canonical_bit
    elif component == "smem":
        changed_bit = canonical_bit % 8
        if int(ack.get("byte_bit", -1)) != changed_bit:
            raise ValueError("shared-memory byte bit differs from the requested flat bit")
    else:
        target = trial["target"]
        tag_bits = target["tag_bits"]
        data_bits = 8 * target["line_size_bytes"]
        in_line = canonical_bit % (tag_bits + data_bits)
        is_tag = in_line < tag_bits
        changed_bit = 63 - in_line if is_tag else in_line - tag_bits
        if ack.get("kind") != ("tag" if is_tag else "data") or int(
                ack.get("tag_bit" if is_tag else "data_bit", -1)) != changed_bit:
            raise ValueError("cache bit layout differs from the requested flat bit")
        if ack["status"] == "armed":
            _validate_resident_cache_data_armed(ack, changed_bit, data_bits)
        elif ack["status"] == "cold_armed":
            if (is_tag or ack.get("ack_schema") != "cache-invalid-pending-v2"
                    or ack.get("realizer_version") != "2"
                    or ack.get("storage_model") != "physical_invalid_pending_xor_v2"
                    or ack.get("fault_model") != "all-active-physical-cache-tag57-and-data-invalid-pending-single-bit-v2"
                    or ack.get("state") not in {"INVALID", "RESERVED"} or ack.get("known_block") != "0"
                    or int(ack.get("line_bytes", 0)) != target["line_size_bytes"]
                    or not ack.get("realization_id") or ack["realization_id"] == "none"):
                raise ValueError("unrecognized actual cold-DATA physical mutation")
            for name in ("cache_instance", "geometry_epoch", "allocated_lines", "active_lines"):
                if not str(ack.get(name, "")).isdecimal() or int(ack[name]) <= 0:
                    raise ValueError("cold DATA lacks actual geometry: " + name)
            if (int(ack["line"]) >= int(ack["active_lines"]) or int(ack["active_lines"]) > int(ack["allocated_lines"])
                    or int(ack["execution_after"]) != int(ack["execution_before"])+1
                    or ack.get("pending_before") != "00"
                    or re.fullmatch(r"[0-9a-f]{2}", ack.get("pending_after", "")) is None
                    or int(ack["pending_after"],16) != 1 << (changed_bit % 8)):
                raise ValueError("cold DATA did not flip exactly the selected physical pending bit")
        for consumption in records:
            if consumption.get("status") != "propagated":
                continue
            if consumption.get("component") != component and not is_tag:
                operand_bit = _cross_level_cache_operand_bit(ack, consumption, changed_bit, target, log_text)
            else:
                if is_tag or int(consumption["data_bit"]) != changed_bit:
                    raise ValueError("cache consumer does not belong to the injected data bit")
                operand_bit = changed_bit - (int(consumption["byte_addr"]) % target["line_size_bytes"]) * 8
            if not 0 <= operand_bit < int(consumption["width"]) or int(consumption["bit"]) != operand_bit + 1:
                raise ValueError("cache fault changed the wrong operand bit")
            if int(consumption["before"], 16) ^ int(consumption["after"], 16) != 1 << operand_bit:
                raise ValueError("cache consumer mutation is not the requested single bit")
    if ack["status"] == "applied":
        if "before" not in ack or "after" not in ack:
            raise ValueError("mutation acknowledgement lacks before/after values")
        if int(ack["before"], 16) ^ int(ack["after"], 16) != 1 << changed_bit:
            raise ValueError("realized mutation did not flip precisely the requested bit")
    return ack


def stop_process(process):
    return process.stop(grace_seconds=0.1)


def oom_snapshot():
    """Read actual container-wide OOM counters; v1 cannot certify this guard."""
    counters = cgroup_counters()
    if counters.get("version") != 2 or not isinstance(counters.get("memory.events"), str):
        raise ValueError("readable cgroup v2 memory.events is required for OOM attribution")
    events = {}
    for line in counters["memory.events"].splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[0] in events or not fields[1].isdigit():
            raise ValueError("invalid cgroup v2 memory.events counters")
        events[fields[0]] = int(fields[1])
    if not {"oom", "oom_kill"}.issubset(events):
        raise ValueError("missing cgroup v2 OOM counters")
    return events


def verify_oom_snapshots(before, after=None):
    # Eight FI workers share a cgroup: attributing a kill to a particular PID
    # would be unjustified. A contaminated container cannot certify any draw.
    for snapshot in (before,) if after is None else (before, after):
        if any(value != 0 for key, value in snapshot.items()
               if key == "oom" or key.startswith("oom_")):
            raise ValueError("container OOM event observed; not a measured DUE")
    if after is not None and (set(before) != set(after) or
                              any(after[key] < value for key, value in before.items())):
        raise ValueError("cgroup memory.events identity or monotonic counters changed")


def measured_process_valid(metrics):
    if (not isinstance(metrics, dict) or metrics.get("reaped") is not True or
            metrics.get("ownership_lost") is not False or
            metrics.get("measurement") != "wait4_for_this_pid" or
            metrics.get("scope") != "child_and_descendants_waited_for_by_child"):
        return False
    for name in ("wall_seconds", "cpu_user_seconds", "cpu_system_seconds", "max_rss_bytes"):
        value = metrics.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            return False
    return type(metrics.get("exit_status")) is int


def explicit_environment(spec):
    return validate_explicit_environment(spec)


def execution_input_descriptor(spec, asset_hashes, config_sha256, output_spec_fingerprint):
    """Content and deployed arguments, excluding physical source/snapshot paths."""
    result = {"schema_version": 1, "asset_hashes": asset_hashes,
            "command": spec["command"], "environment": explicit_environment(spec),
            "base_config_sha256": config_sha256,
            "output_spec_fingerprint": output_spec_fingerprint,
            "trial_environment_policy": trial_environment_descriptor(spec),
            "trial_environment_policy_sha256": digest(Path(__file__).with_name("trial_environment.py"))}
    capture = runtime_loader_policy(spec)
    if capture["enabled"]:
        result["runtime_loader_capture"] = capture
        result["runtime_loader_checker_sha256"] = digest(Path(__file__).with_name("runtime_loader_capture.py"))
    result["cache_execution_model"] = "functional-snapshot-cache-v3"
    return result


def runtime_loader_policy(spec):
    """Explicit owned-PID diagnostics; never feed loader chatter to ptxas."""
    policy = spec.get("runtime_loader_capture", {"enabled": False})
    if not isinstance(policy, dict) or type(policy.get("enabled")) is not bool:
        raise ValueError("runtime_loader_capture requires an explicit boolean enabled field")
    expected_keys = {"enabled", "expected_runtime"} if policy["enabled"] else {"enabled"}
    if set(policy) != expected_keys:
        raise ValueError("runtime_loader_capture has missing or unexpected fields")
    environment = explicit_environment(spec)
    if environment.get("LD_DEBUG_OUTPUT"):
        raise ValueError("loader debug-output must be the executor's private owned-PID path")
    if not policy["enabled"]:
        if environment.get("LD_DEBUG"):
            raise ValueError("LD_DEBUG requires explicit owned runtime_loader_capture")
        return {"enabled": False}
    if environment.get("LD_DEBUG") not in (None, "", "libs"):
        raise ValueError("only reviewed libs loader diagnostics are supported")
    expected = policy["expected_runtime"]
    if (not isinstance(expected, dict) or set(expected) != {"libcudart_realpath", "libcudart_sha256"}
            or not isinstance(expected.get("libcudart_realpath"), str)
            or "\0" in expected["libcudart_realpath"]
            or not Path(expected["libcudart_realpath"]).is_absolute()
            or not isinstance(expected.get("libcudart_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected["libcudart_sha256"])):
        raise ValueError("runtime_loader_capture requires exact absolute runtime path and SHA256")
    return {"enabled": True, "expected_runtime": dict(expected)}


def retain_correctness_work(spec):
    """Keep actual run assets only for explicit correctness evidence checks."""
    value = spec.get("retain_work", False)
    if type(value) is not bool or (value and spec.get("purpose") != "correctness"):
        raise ValueError("retain_work must be boolean and may be true only for correctness runs")
    return value


def run_trial(trial, spec, inputs, campaign_dir, golden, output_spec):
    retain_work = retain_correctness_work(spec)
    def save_attempt(record):
        if spec.get("record_trial_costs", True) is False:
            # Monitoring enforces timeout/OOM/accounting, without turning point
            # validation into a per-trial performance study.
            for key in ("process_metrics", "wall_seconds", "attempt_wall_seconds"):
                record.pop(key, None)
        if not spec.get("defer_evidence", False):
            atomic_json(attempt / "attempt.json", record)
    loader_policy = runtime_loader_policy(spec)
    trial_id = safe_id(trial["trial_id"])
    attempt = campaign_dir / "runs" / trial_id / datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    attempt.mkdir(parents=True)
    work = attempt / "work"
    work.mkdir()
    for destination, source in inputs.items():
        target = work / relative_name(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        if spec.get("reuse_readonly_assets", False):
            try:
                os.link(source, target)
            except OSError:
                shutil.copy2(source, target)
        else:
            shutil.copy2(source, target)
    parameters = dict(trial["hook_params"])
    contract = trial.get("valid_resident_contract")
    if contract is not None:
        # This small native input is necessary execution setup, not result sealing.
        import json
        (work / "valid-resident.json").write_text(json.dumps(contract, sort_keys=True) + "\n")
        parameters["-fi_valid_resident_contract"] = "valid-resident.json"
    (work / "gpgpusim.config").write_text(configured_text(spec["base_config_text"], parameters))
    started = time.monotonic()
    log = attempt / "run.log"
    record = {"started_utc": now(), "site_id": trial["site_id"],
              "attempt": str(attempt.relative_to(campaign_dir)), "process_metrics": None,
              "oom_guard": {"measurement": "cgroup_v2_memory.events",
                            "scope": "whole_shared_container_conservative", "verified": False}}
    if STOP.is_set() or not POLICY.dispatch_allowed():
        record.update(status="interrupted", interruption_reason=stop_reason() if STOP.is_set() else "dispatch_window_end")
        save_attempt(record)
        return trial_id, record
    try:
        environment = trial_environment(spec, os.environ)
        record["trial_environment"] = environment_evidence(spec, os.environ, environment)
        if not record["trial_environment"]["private_runtime_preserved"] or not record["trial_environment"]["execution_metadata_preserved"]:
            raise ValueError("private worker runtime/execution environment changed")
        if loader_policy["enabled"]:
            from script.execution.runtime_loader_capture import prepare_loader_capture
            environment, prefix = prepare_loader_capture(environment, work)
            record["loader_capture_environment"] = {"LD_DEBUG": "libs", "LD_DEBUG_OUTPUT": str(prefix)}
        elif environment.get("LD_DEBUG") or environment.get("LD_DEBUG_OUTPUT"):
            raise ValueError("inherited loader diagnostics require an explicit owned capture policy")
    except (OSError, ValueError) as error:
        record.update(status="infrastructure_error", reason="loader_capture_setup_failed: " + str(error))
        save_attempt(record)
        return trial_id, record
    process = None
    interrupted = None
    timed_out = False
    execution_error = None
    try:
        record["oom_guard"]["before"] = oom_snapshot()
        verify_oom_snapshots(record["oom_guard"]["before"])
    except (OSError, ValueError) as error:
        record["oom_guard"]["failure_reason"] = str(error)
        record.update(status="infrastructure_error", reason="OOM accounting failed: " + str(error))
        save_attempt(record)
        return trial_id, record
    with log.open("w") as stream:
        try:
            process = MeasuredChild(spec["command"], cwd=work, env=environment,
                                    stdout=stream, stderr=subprocess.STDOUT)
            try:
                while process.poll() is None:
                    if STOP.is_set() or POLICY.seconds_remaining() <= 2:
                        interrupted = stop_reason() if STOP.is_set() else "night_window_end"
                        break
                    if time.monotonic() - started >= spec["timeout_seconds"]:
                        timed_out = True
                        break
                    time.sleep(0.05)
            finally:
                stop_process(process)
        except (OSError, ReapOwnershipError, TimeoutError, ValueError) as error:
            execution_error = "%s: %s" % (type(error).__name__, error)
    metrics = process.metrics() if process is not None else None
    if not measured_process_valid(metrics):
        execution_error = execution_error or "missing or invalid per-child resource accounting"
    try:
        record["oom_guard"]["after"] = oom_snapshot()
        verify_oom_snapshots(record["oom_guard"]["before"], record["oom_guard"]["after"])
        record["oom_guard"]["verified"] = True
    except (OSError, ValueError) as error:
        record["oom_guard"]["failure_reason"] = str(error)
        execution_error = execution_error or "OOM accounting failed: " + str(error)
    measured_wall = metrics.get("wall_seconds") if isinstance(metrics, dict) else None
    if (isinstance(measured_wall, bool) or not isinstance(measured_wall, (int, float))
            or not math.isfinite(measured_wall) or measured_wall < 0):
        measured_wall = time.monotonic() - started
    record.update(finished_utc=now(), process_metrics=metrics,
                  wall_seconds=measured_wall,
                  attempt_wall_seconds=time.monotonic() - started, timed_out=timed_out,
                  exit_status=124 if timed_out else (process.returncode if process is not None else None),
                  log_sha256=None if spec.get("defer_evidence", False) else digest(log))
    if STOP.is_set() or not POLICY.contains():
        interrupted = stop_reason() if STOP.is_set() else "night_window_end"
    if timed_out:
        # The campaign's finite administrative budget is not evidence that
        # the modeled application detected a fault. Preserve the draw for
        # explicit retry rather than manufacturing a DUE outcome.
        interrupted = "administrative_process_timeout_not_DUE"
    if interrupted:
        record.update(status="interrupted", interruption_reason=interrupted)
        save_attempt(record)
        return trial_id, record
    if execution_error:
        record.update(status="infrastructure_error", reason="process_execution_or_measurement_failed: " + execution_error)
        save_attempt(record)
        return trial_id, record
    try:
        if loader_policy["enabled"]:
            from script.execution.runtime_loader_capture import bind_loader_capture
            receipt = bind_loader_capture(work, metrics, loader_policy["expected_runtime"])
            retained_loader = attempt / "runtime-loader.log"
            shutil.copy2(receipt["loader_path"], retained_loader)
            if digest(retained_loader) != receipt["loader_sha256"]:
                raise ValueError("owned loader evidence changed during retention")
            receipt["retained_loader_path"] = str(retained_loader.relative_to(campaign_dir))
            record["runtime_loader_capture"] = receipt
        # Configuration failures remain unfinished, even beside an earlier ACK.
        text = log.read_text(errors="replace")
        if any(line.strip() == "GPUFI_INVALID_CONFIGURATION" or
               line.strip().startswith("GPUFI_INVALID_CONFIGURATION ")
               for line in text.splitlines()):
            raise ValueError("invalid_simulator_configuration")
        evidence = fault_records(log, text=text)
        ack = validate_acknowledgement(trial, evidence, log_text=text)
        if contract is not None:
            from script.execution.cache_valid_resident import validate_native_witness
            record["valid_resident_witness"] = validate_native_witness(contract, text)
        approximations = []
        for line in text.splitlines():
            if line.startswith("GPUFI_CACHE_APPROX "):
                fields = dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)
                if fields.get("model") != "functional-snapshot-cache-v3":
                    raise ValueError("unexpected cache compatibility model")
                if fields not in approximations:
                    approximations.append(fields)
        if ack["status"] == "unmapped":
            raise ValueError("selected physical injection did not execute; incomplete draw")
        result = classify_fi_logs(golden_log=golden, run_log=log, output_spec=output_spec,
                                  exit_status=record["exit_status"], output_mode="raw",
                                  require_fault_evidence=True,
                                  typed_output_contract=spec.get("typed_output_contract"),
                                  golden_summary=spec.get("_golden_summary"),
                                  run_summary=_load_log_summary(log, text=text))
        if result["detail"].get("error_kind"):
            raise ValueError(result["detail"]["error_kind"])
        outcome = {"masked": "Masked", "sdc": "SDC", "due": "DUE"}[result["classification"]]
        monitor = spec.get("simulation_cycle_watchdog")
        if monitor is not None:
            limit = monitor.get("cycle_limit")
            if type(limit) is not int or limit <= monitor.get("golden_cycles", limit):
                raise ValueError("invalid frozen execution-cycle watchdog")
            actual = [int(value) for value in re.findall(r"gpu_tot_sim_cycle\s*=\s*(\d+)", text)]
            if actual and max(actual) >= limit:
                outcome = "DUE"
                result = dict(result, classification="due",
                    detail=dict(result["detail"], reason="declared_simulation_cycle_watchdog",
                                cycle_limit=limit, observed_cycles=max(actual)))
        record.update(status="complete", outcome=outcome, oracle=result,
                      cache_execution_model="functional-snapshot-cache-v3",
                      cache_compatibility={"used": bool(approximations), "reasons": approximations},
                      fault_acknowledgement=ack, fault_evidence=evidence)
    except (OSError, ValueError, KeyError) as error:
        record.update(status="infrastructure_error", reason=str(error))
    save_attempt(record)
    # Performance runs keep the normal scratch cleanup. Explicit correctness
    # runs can retain the actual binary and loader outputs for independent QA.
    if not retain_work and not spec.get("defer_evidence", False):
        shutil.rmtree(work)
    return trial_id, record
