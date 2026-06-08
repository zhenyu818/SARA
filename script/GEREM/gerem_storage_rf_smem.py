#!/usr/bin/env python3
"""GEREM predictors for register file and shared memory."""

from __future__ import annotations

import argparse
import bisect
import builtins as _builtins
import random
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

try:
    from .gerem_storage_common import (
        access_size_bytes_for_raw_event,
        build_component_payload,
        canonical_mem_space,
        campaign_runs_env,
        component_domain,
        component_denominator,
        cycle_domain_bounds,
        int_value,
        load_json,
        load_cycle_rows,
        write_json,
    )
except ImportError:
    from gerem_storage_common import (
        access_size_bytes_for_raw_event,
        build_component_payload,
        canonical_mem_space,
        campaign_runs_env,
        component_domain,
        component_denominator,
        cycle_domain_bounds,
        int_value,
        load_json,
        load_cycle_rows,
        write_json,
    )


MASKING_OPCODE_PREFIXES = ("max", "min")
MASKING_EVENT_KINDS = {"branch", "loop_branch"}
GEREM_STORAGE_CAMPAIGN_RUNS = campaign_runs_env("GEREM_STORAGE_CAMPAIGN_RUNS", 1000)
EXPERIMENT_RANDOM_SEED = 2026
_BUILTIN_INT = _builtins.int
_INT_VALUE = int_value


def _stable_campaign_seed(*_parts: Any) -> int:
    """Return the fixed GEREM campaign seed required for reproducible runs."""
    return _BUILTIN_INT(EXPERIMENT_RANDOM_SEED)


def _build_cycle_sampler(cycle_rows: Iterable[Tuple[int, int]]) -> Tuple[List[int], List[int], int]:
    cycles: List[int] = []
    cumulative: List[int] = []
    total = 0
    for cycle, multiplicity in cycle_rows:
        mult = max(0, _BUILTIN_INT(multiplicity))
        if mult <= 0:
            continue
        total += mult
        cycles.append(_BUILTIN_INT(cycle))
        cumulative.append(_BUILTIN_INT(total))
    if not cycles:
        cycles = [0]
        cumulative = [1]
        total = 1
    return cycles, cumulative, _BUILTIN_INT(total)



def _sample_cycle(rng: random.Random, cycles: List[int], cumulative: List[int], total: int) -> int:
    pick = rng.randrange(max(1, _BUILTIN_INT(total)))
    return _BUILTIN_INT(cycles[bisect.bisect_right(cumulative, pick)])


def _component_name(raw_component: str) -> str:
    component = str(raw_component).strip().lower()
    if component == "smem":
        return "smem_rf"
    if component in {"rf", "smem_rf"}:
        return component
    raise ValueError(f"unsupported component: {raw_component}")


def _event_is_masking(record: Mapping[str, Any]) -> bool:
    kind = str(record.get("kind", "")).strip().lower()
    if kind in MASKING_EVENT_KINDS:
        return True
    opcode = str(record.get("opcode", "")).strip().lower()
    return opcode.startswith(MASKING_OPCODE_PREFIXES)


def _canonical_pc(value: Any) -> Optional[str]:
    if value is None:
        return None
    try:
        return "0x{:x}".format(_INT_VALUE(value, 0))
    except Exception:
        text = str(value).strip().lower()
        return text or None


def _cfg_successors(inst: Mapping[str, Any]) -> List[str]:
    kind = str(inst.get("kind", "")).strip().lower()
    out: List[str] = []
    if kind == "branch":
        taken = _canonical_pc(inst.get("taken_target_pc"))
        fallthrough = _canonical_pc(inst.get("fallthrough_pc"))
        if taken is not None:
            out.append(taken)
        if fallthrough is not None and fallthrough not in out:
            out.append(fallthrough)
        return out
    if kind in {"inst", "load", "store"}:
        next_pc = _canonical_pc(inst.get("next_pc"))
        if next_pc is not None:
            out.append(next_pc)
    return out


def _normalize_trace_instruction(raw: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    pc = _canonical_pc(raw.get("pc"))
    if pc is None:
        return None
    kind = str(raw.get("kind", "inst")).strip().lower()
    if kind not in {"inst", "load", "store", "branch", "ret"}:
        return None
    inst = {
        "pc": pc,
        "kind": kind,
        "opcode": str(raw.get("opcode", "")).strip().lower(),
    }
    next_pc = _canonical_pc(raw.get("next_pc"))
    if next_pc is not None:
        inst["next_pc"] = next_pc
    if kind == "branch":
        taken = _canonical_pc(raw.get("taken_target_pc") or raw.get("branch_target_pc"))
        fallthrough = _canonical_pc(raw.get("fallthrough_pc") or raw.get("next_pc"))
        if taken is not None:
            inst["taken_target_pc"] = taken
        if fallthrough is not None:
            inst["fallthrough_pc"] = fallthrough
    return inst


def _merge_trace_instruction(existing: Mapping[str, Any], incoming: Mapping[str, Any]) -> Dict[str, Any]:
    merged = dict(existing)
    current_kind = str(merged.get("kind", "inst")).strip().lower()
    new_kind = str(incoming.get("kind", "inst")).strip().lower()
    if current_kind == "inst" and new_kind in {"load", "store", "branch", "ret"}:
        merged["kind"] = new_kind
    if not str(merged.get("opcode", "")).strip() and str(incoming.get("opcode", "")).strip():
        merged["opcode"] = str(incoming.get("opcode", "")).strip().lower()
    for key in ("next_pc", "taken_target_pc", "fallthrough_pc"):
        if key not in merged and key in incoming:
            merged[key] = incoming[key]
    return merged


def _prepare_trace_programs(trace_template: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    events = _trace_events(trace_template)
    trace_max_steps = _INT_VALUE(trace_template.get("max_steps"), 0)
    instructions_by_pc: Dict[str, Dict[str, Any]] = {}
    ordered_pcs: List[str] = []

    for raw in events:
        inst = _normalize_trace_instruction(raw)
        if inst is None:
            continue
        pc = str(inst["pc"])
        if pc not in instructions_by_pc:
            instructions_by_pc[pc] = inst
            ordered_pcs.append(pc)
        else:
            instructions_by_pc[pc] = _merge_trace_instruction(instructions_by_pc[pc], inst)

    if not instructions_by_pc:
        raise ValueError("GEREM storage predictor requires trace instructions with pc metadata")

    for idx, pc in enumerate(ordered_pcs):
        inst = instructions_by_pc[pc]
        if inst.get("kind") in {"inst", "load", "store"} and inst.get("next_pc") is None and idx + 1 < len(ordered_pcs):
            inst["next_pc"] = ordered_pcs[idx + 1]

    undirected_adj: Dict[str, set[str]] = {pc: set() for pc in ordered_pcs}
    for pc in ordered_pcs:
        inst = instructions_by_pc[pc]
        for succ in _cfg_successors(inst):
            if succ not in instructions_by_pc:
                continue
            undirected_adj[pc].add(succ)
            undirected_adj.setdefault(succ, set()).add(pc)

    visited: set[str] = set()
    programs: Dict[str, Dict[str, Any]] = {}
    for start_pc in ordered_pcs:
        if start_pc in visited:
            continue
        stack = [start_pc]
        members: List[str] = []
        while stack:
            pc = stack.pop()
            if pc in visited:
                continue
            visited.add(pc)
            members.append(pc)
            stack.extend(sorted(undirected_adj.get(pc, set()) - visited))
        member_set = set(members)
        instructions = {pc: instructions_by_pc[pc] for pc in members}
        entry_pc = next((pc for pc in ordered_pcs if pc in member_set), members[0])
        max_steps = trace_max_steps if trace_max_steps > 0 else max(256, len(instructions) + 32)
        programs[entry_pc] = {
            "entry_pc": entry_pc,
            "instructions": instructions,
            "max_steps": _BUILTIN_INT(max_steps),
        }
    return programs


def _resolve_program_for_pc(
    programs: Mapping[str, Mapping[str, Any]],
    pc: str,
) -> Mapping[str, Any]:
    matches = [
        program
        for program in programs.values()
        if isinstance(program.get("instructions"), Mapping)
        and pc in program.get("instructions", {})
    ]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise ValueError("no replay_program contains pc {}".format(pc))
    raise ValueError("pc {} is ambiguous across replay_programs".format(pc))


def _program_sic_values(
    program: Mapping[str, Any],
    max_steps: int,
) -> Dict[str, float]:
    instructions = program.get("instructions", {})
    if not isinstance(instructions, Mapping):
        raise ValueError("replay_program instructions must be an object")

    pcs = [str(pc) for pc in instructions.keys()]
    if not pcs:
        return {}
    steps = max(0, _BUILTIN_INT(max_steps) - 1)
    if steps <= 0:
        return {pc: 1.0 for pc in pcs}

    index_by_pc = {pc: idx for idx, pc in enumerate(pcs)}
    size = len(pcs) + 1
    matrix: List[List[float]] = [[0.0] * size for _ in range(size)]
    const_index = size - 1

    for pc, idx in index_by_pc.items():
        inst = instructions.get(pc)
        if not isinstance(inst, Mapping):
            matrix[idx][const_index] = 1.0
            continue
        factor = 0.5 if _event_is_masking(inst) else 1.0
        kind = str(inst.get("kind", "")).strip().lower()
        succs = [succ for succ in _cfg_successors(inst) if succ in index_by_pc]
        if kind == "ret" or not succs:
            matrix[idx][const_index] = float(factor)
            continue
        edge_weight = float(factor) / float(len(succs))
        for succ in succs:
            matrix[idx][index_by_pc[succ]] += edge_weight

    matrix[const_index][const_index] = 1.0
    vector = [1.0] * size

    def mat_vec_mul(mat: List[List[float]], vec: List[float]) -> List[float]:
        out = [0.0] * len(mat)
        for row_index, row in enumerate(mat):
            total = 0.0
            for col_index, value in enumerate(row):
                if value == 0.0:
                    continue
                total += value * vec[col_index]
            out[row_index] = total
        return out

    def mat_mul(left: List[List[float]], right: List[List[float]]) -> List[List[float]]:
        out = [[0.0] * len(right[0]) for _ in range(len(left))]
        for row_index, row in enumerate(left):
            out_row = out[row_index]
            for mid_index, left_value in enumerate(row):
                if left_value == 0.0:
                    continue
                right_row = right[mid_index]
                for col_index, right_value in enumerate(right_row):
                    if right_value == 0.0:
                        continue
                    out_row[col_index] += left_value * right_value
        return out

    power = steps
    transform = matrix
    while power > 0:
        if power & 1:
            vector = mat_vec_mul(transform, vector)
        power >>= 1
        if power > 0:
            transform = mat_mul(transform, transform)

    return {pc: float(vector[index_by_pc[pc]]) for pc in pcs}


def _site_sic_probability(
    site: Mapping[str, Any],
    program: Mapping[str, Any],
    values: Mapping[str, float],
) -> float:
    pc = _canonical_pc(site.get("pc"))
    if pc is None:
        raise ValueError("smem DCR site missing pc for SIC computation")
    instructions = program.get("instructions", {})
    if not isinstance(instructions, Mapping):
        raise ValueError("replay_program instructions must be an object")
    inst = instructions.get(pc)
    if not isinstance(inst, Mapping):
        raise ValueError("replay_program missing load pc {}".format(pc))
    succs = [succ for succ in _cfg_successors(inst) if succ in instructions]
    if not succs:
        return 1.0

    probability = sum(float(values[succ]) for succ in succs) / float(len(succs))
    return max(0.0, min(1.0, float(probability)))


def compute_smem_sic(
    trace_template: Mapping[str, Any],
    dcr_sites: Iterable[Tuple[Mapping[str, Any], int]],
) -> float:
    programs = _prepare_trace_programs(trace_template)
    total_weight = 0
    weighted_probability_sum = 0.0
    program_values_cache: Dict[Tuple[str, int], Dict[str, float]] = {}
    site_probability_cache: Dict[Tuple[str, str], float] = {}
    for site, weight in dcr_sites:
        weight_int = max(0, _BUILTIN_INT(weight))
        if weight_int <= 0:
            continue
        pc = _canonical_pc(site.get("pc"))
        if pc is None:
            raise ValueError("smem DCR site missing pc for SIC computation")
        program = _resolve_program_for_pc(programs, pc)
        max_steps = max(1, _INT_VALUE(program.get("max_steps", 256), 256))
        program_key = (str(program.get("entry_pc", "")), _BUILTIN_INT(max_steps))
        values = program_values_cache.get(program_key)
        if values is None:
            values = _program_sic_values(program, _BUILTIN_INT(max_steps))
            program_values_cache[program_key] = values
        site_key = (program_key[0], str(pc))
        probability = site_probability_cache.get(site_key)
        if probability is None:
            probability = _site_sic_probability(site, program, values)
            site_probability_cache[site_key] = float(probability)
        total_weight += weight_int
        weighted_probability_sum += float(weight_int) * float(probability)
    if total_weight <= 0:
        return 1.0
    return max(0.0, min(1.0, weighted_probability_sum / float(total_weight)))


def _trace_events(trace_template: Optional[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    if not isinstance(trace_template, Mapping):
        return []
    raw_events = trace_template.get("events", [])
    if not isinstance(raw_events, list):
        return []
    out: List[Dict[str, Any]] = []
    for event_index, record in enumerate(raw_events):
        if not isinstance(record, Mapping):
            continue
        row = dict(record)
        row.setdefault("event_index", _BUILTIN_INT(event_index))
        out.append(row)
    return out


def _event_cycle(record: Mapping[str, Any], fallback: int) -> int:
    return _INT_VALUE(record.get("cycle", fallback), fallback)


def _pred_true(record: Mapping[str, Any]) -> bool:
    pred = record.get("pred")
    if not isinstance(pred, Mapping):
        return True
    return _INT_VALUE(pred.get("val", 1), 1) != 0


def _register_identity(reg_name: Any, reg_uid: Any) -> Optional[Tuple[str, str]]:
    name = str(reg_name or "").strip()
    if not name.startswith("%"):
        return None
    uid = _INT_VALUE(reg_uid, -1)
    if uid >= 0:
        return ("uid", str(uid))
    if not name:
        return None
    return ("name", name)


def _datatype_bits(fi_sampling_space: Mapping[str, Any]) -> int:
    return max(1, _INT_VALUE(fi_sampling_space.get("datatype_bits"), 32))


def _component_row_required(fi_sampling_space: Mapping[str, Any], component: str) -> Dict[str, Any]:
    row = component_domain(dict(fi_sampling_space), component)
    if not row:
        raise ValueError("GEREM {} predictor requires fi_sampling_space.component_domains.{}".format(component, component))
    return dict(row)


def _load_register_rows(fi_sampling_space: Mapping[str, Any]) -> List[str]:
    raw_path = str(fi_sampling_space.get("register_domain_source", "") or "").strip()
    if not raw_path:
        raise ValueError("GEREM RF predictor requires fi_sampling_space.register_domain_source")
    path = Path(raw_path).expanduser()
    if not path.is_file():
        raise ValueError("GEREM RF predictor missing register_domain_source: {}".format(path))
    rows = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        raise ValueError("GEREM RF predictor requires a non-empty register_domain_source")
    return rows


def _build_rf_versions(
    trace_template: Optional[Mapping[str, Any]],
    *,
    fi_sampling_space: Mapping[str, Any],
) -> Tuple[List[Dict[str, Any]], int]:
    cycle_rows = load_cycle_rows(fi_sampling_space, trace_template)
    domain_start, domain_end = cycle_domain_bounds(cycle_rows)
    events = _trace_events(trace_template)
    active: Dict[Tuple[int, Tuple[str, str]], MutableMapping[str, Any]] = {}
    versions: List[Dict[str, Any]] = []

    def finalize(key: Tuple[int, Tuple[str, str]], end_cycle: int) -> None:
        current = active.pop(key, None)
        if current is None:
            return
        current["end_cycle"] = _BUILTIN_INT(end_cycle)
        versions.append(dict(current))

    for event_index, raw in enumerate(events):
        if not _pred_true(raw):
            continue
        cycle = _event_cycle(raw, event_index)
        tid = _INT_VALUE(raw.get("thread_id"), -1)
        if tid < 0:
            continue

        src_regs = raw.get("src_regs", [])
        src_uids = raw.get("src_reg_uids", [])
        if not isinstance(src_regs, list):
            src_regs = []
        if not isinstance(src_uids, list):
            src_uids = []
        for src_index, reg_name in enumerate(src_regs):
            ident = _register_identity(
                reg_name,
                src_uids[src_index] if src_index < len(src_uids) else -1,
            )
            if ident is None:
                continue
            key = (_BUILTIN_INT(tid), ident)
            current = active.get(key)
            if current is None:
                current = {
                    "thread_id": _BUILTIN_INT(tid),
                    "register": str(reg_name),
                    "identity": list(ident),
                    "start_cycle": _BUILTIN_INT(domain_start),
                    "read_cycles": [],
                }
                active[key] = current
            read_cycles = current.setdefault("read_cycles", [])
            if isinstance(read_cycles, list):
                read_cycles.append(_BUILTIN_INT(cycle))

        ident = _register_identity(raw.get("dst_reg"), raw.get("dst_reg_uid", -1))
        if ident is None:
            continue
        key = (_BUILTIN_INT(tid), ident)
        finalize(key, _BUILTIN_INT(cycle))
        active[key] = {
            "thread_id": _BUILTIN_INT(tid),
            "register": str(raw.get("dst_reg", "")),
            "identity": list(ident),
            "start_cycle": _BUILTIN_INT(cycle),
            "read_cycles": [],
        }

    for key in list(active.keys()):
        finalize(key, _BUILTIN_INT(domain_end))

    return versions, _BUILTIN_INT(domain_end)


def _build_smem_versions(
    trace_template: Optional[Mapping[str, Any]],
    *,
    fi_sampling_space: Mapping[str, Any],
) -> Tuple[List[Dict[str, Any]], int, List[Dict[str, Any]]]:
    cycle_rows = load_cycle_rows(fi_sampling_space, trace_template)
    _domain_start, domain_end = cycle_domain_bounds(cycle_rows)
    events = _trace_events(trace_template)
    active: Dict[Tuple[int, int, int], MutableMapping[str, Any]] = {}
    versions: List[Dict[str, Any]] = []
    load_sites: List[Dict[str, Any]] = []

    def finalize(key: Tuple[int, int, int], end_cycle: int) -> None:
        current = active.pop(key, None)
        if current is None:
            return
        current["end_cycle"] = _BUILTIN_INT(end_cycle)
        versions.append(dict(current))

    for event_index, raw in enumerate(events):
        if not _pred_true(raw):
            continue
        if canonical_mem_space(raw.get("mem_space") or raw.get("space")) != "shared":
            continue
        kind = str(raw.get("kind", "")).strip().lower()
        if kind not in {"load", "store"}:
            continue
        sm_id = _INT_VALUE(raw.get("sm_id"), -1)
        cta_id = _INT_VALUE(raw.get("cta_id"), -1)
        addr = raw.get("mem_addr", raw.get("base"))
        if sm_id < 0 or cta_id < 0 or addr is None:
            continue
        cycle = _event_cycle(raw, event_index)
        base_addr = _INT_VALUE(addr, 0)
        size_bytes = max(1, access_size_bytes_for_raw_event(raw))
        for byte_index in range(size_bytes):
            byte_addr = _BUILTIN_INT(base_addr + byte_index)
            key = (_BUILTIN_INT(sm_id), _BUILTIN_INT(cta_id), _BUILTIN_INT(byte_addr))
            if kind == "store":
                finalize(key, _BUILTIN_INT(cycle))
                active[key] = {
                    "sm_id": _BUILTIN_INT(sm_id),
                    "cta_id": _BUILTIN_INT(cta_id),
                    "addr": _BUILTIN_INT(byte_addr),
                    "start_cycle": _BUILTIN_INT(cycle),
                    "load_sites": [],
                }
                continue

            current = active.get(key)
            if current is None:
                continue
            site = {
                "sm_id": _BUILTIN_INT(sm_id),
                "cta_id": _BUILTIN_INT(cta_id),
                "thread_id": _INT_VALUE(raw.get("thread_id"), -1),
                "cycle": _BUILTIN_INT(cycle),
                "event_index": _BUILTIN_INT(event_index),
                "pc": raw.get("pc"),
                "kind": str(raw.get("kind", "")),
                "opcode": str(raw.get("opcode", "")),
                "addr": _BUILTIN_INT(byte_addr),
            }
            load_sites.append(site)
            cur_loads = current.setdefault("load_sites", [])
            if isinstance(cur_loads, list):
                cur_loads.append(site)

    for key in list(active.keys()):
        finalize(key, _BUILTIN_INT(domain_end))

    return versions, _BUILTIN_INT(domain_end), load_sites


def _smem_sample_sic_probability(
    programs: Mapping[str, Mapping[str, Any]],
    site: Mapping[str, Any],
) -> float:
    """Compute the GEREM shared-memory SIC probability for one sampled DCR.

    The sampled fault's trace/program context determines the masking
    instructions considered by the storage-EFM SIC rule.
    """
    pc = _canonical_pc(site.get("pc"))
    if pc is None:
        raise ValueError("smem DCR site missing pc for SIC computation")
    program = _resolve_program_for_pc(programs, pc)
    max_steps = max(1, _INT_VALUE(program.get("max_steps", 256), 256))
    values = _program_sic_values(program, _BUILTIN_INT(max_steps))
    return float(_site_sic_probability(site, program, values))


def _prepare_rf_campaign_state(
    *,
    fi_sampling_space: Mapping[str, Any],
    trace_template: Mapping[str, Any],
) -> Dict[str, Any]:
    row = _component_row_required(fi_sampling_space, "rf")
    cycle_rows = load_cycle_rows(fi_sampling_space, trace_template)
    versions, _domain_end = _build_rf_versions(trace_template, fi_sampling_space=fi_sampling_space)
    scan_versions: List[Dict[str, Any]] = []
    for version in versions:
        tid = _INT_VALUE(version.get("thread_id"), -1)
        reg_name = str(version.get("register", "")).strip()
        if tid < 0 or not reg_name:
            continue
        read_cycles = sorted(
            _INT_VALUE(raw_cycle, -1)
            for raw_cycle in version.get("read_cycles", [])
            if _INT_VALUE(raw_cycle, -1) >= 0
        )
        dcr_end = max(read_cycles) if read_cycles else _INT_VALUE(version.get("start_cycle"), 0)
        scan_versions.append(
            {
                "thread_id": _BUILTIN_INT(tid),
                "register": reg_name,
                "start_cycle": _INT_VALUE(version.get("start_cycle"), 0),
                "end_cycle": _INT_VALUE(version.get("end_cycle"), 0),
                "dcr_end_cycle": _BUILTIN_INT(dcr_end),
            }
        )
    register_rows = _load_register_rows(fi_sampling_space)
    return {
        "cycle_sampler": _build_cycle_sampler(cycle_rows),
        "register_rows": list(register_rows),
        "datatype_bits": _BUILTIN_INT(_datatype_bits(fi_sampling_space)),
        "seed_domain_size": max(1, _INT_VALUE(row.get("seed_domain_size"), _INT_VALUE(fi_sampling_space.get("thread_rand_max"), 1))),
        "domain_bits_per_seed": max(1, _INT_VALUE(row.get("domain_bits_per_seed"), len(register_rows) * _datatype_bits(fi_sampling_space))),
        "denominator": float(component_denominator(fi_sampling_space, "rf", fallback=0.0)),
        "version_count": len(versions),
        "versions": scan_versions,
    }


def _classify_rf_fault(
    state: Mapping[str, Any],
    *,
    cycle: int,
    thread_seed: int,
    bit_index: int,
) -> str:
    datatype_bits = max(1, _INT_VALUE(state.get("datatype_bits"), 32))
    reg_rows = state.get("register_rows", [])
    if not isinstance(reg_rows, list) or not reg_rows:
        return "benign"
    reg_slot = _BUILTIN_INT(bit_index) // _BUILTIN_INT(datatype_bits)
    if reg_slot < 0 or reg_slot >= len(reg_rows):
        return "benign"
    reg_name = str(reg_rows[reg_slot]).strip()
    versions = state.get("versions", [])
    if not isinstance(versions, list):
        return "benign"
    cycle_i = _BUILTIN_INT(cycle)
    for version in versions:
        if not isinstance(version, Mapping):
            continue
        if _INT_VALUE(version.get("thread_id"), -1) != _BUILTIN_INT(thread_seed):
            continue
        if str(version.get("register", "")).strip() != reg_name:
            continue
        start_cycle = _INT_VALUE(version.get("start_cycle"), 0)
        end_cycle = _INT_VALUE(version.get("end_cycle"), start_cycle)
        if start_cycle <= cycle_i < end_cycle:
            return "dcr" if cycle_i < _INT_VALUE(version.get("dcr_end_cycle"), -1) else "benign"
    return "benign"


def _run_rf_campaign(
    state: Mapping[str, Any],
    *,
    campaign_runs: int,
    rng_seed: int,
) -> Dict[str, float]:
    cycles, cumulative, total = state.get("cycle_sampler", ([0], [1], 1))
    rng = random.Random(_BUILTIN_INT(rng_seed))
    counts = {"benign": 0, "dcr": 0, "ebc": 0}
    seed_domain_size = max(1, _INT_VALUE(state.get("seed_domain_size"), 1))
    per_seed_bits = max(1, _INT_VALUE(state.get("domain_bits_per_seed"), 1))
    for _ in range(max(1, _BUILTIN_INT(campaign_runs))):
        cycle = _sample_cycle(rng, list(cycles), list(cumulative), _BUILTIN_INT(total))
        thread_seed = rng.randrange(seed_domain_size)
        bit_index = rng.randrange(per_seed_bits)
        counts[_classify_rf_fault(state, cycle=cycle, thread_seed=thread_seed, bit_index=bit_index)] += 1
    return {"counts": counts}


def _prepare_smem_campaign_state(
    *,
    fi_sampling_space: Mapping[str, Any],
    trace_template: Mapping[str, Any],
) -> Dict[str, Any]:
    row = _component_row_required(fi_sampling_space, "smem_rf")
    cycle_rows = load_cycle_rows(fi_sampling_space, trace_template)
    versions, _domain_end, trace_load_sites = _build_smem_versions(
        trace_template,
        fi_sampling_space=fi_sampling_space,
    )
    programs = _prepare_trace_programs(trace_template)
    scan_versions: List[Dict[str, Any]] = []
    for version in versions:
        cta_id = _INT_VALUE(version.get("cta_id"), -1)
        addr = _INT_VALUE(version.get("addr"), -1)
        if cta_id < 0 or addr < 0:
            continue
        load_sites = [
            dict(site)
            for site in version.get("load_sites", [])
            if isinstance(site, Mapping)
        ]
        load_sites.sort(
            key=lambda site: (
                _INT_VALUE(site.get("cycle"), 0),
                _INT_VALUE(site.get("event_index"), 0),
            )
        )
        scan_versions.append(
            {
                "cta_id": _BUILTIN_INT(cta_id),
                "addr": _BUILTIN_INT(addr),
                "start_cycle": _INT_VALUE(version.get("start_cycle"), 0),
                "end_cycle": _INT_VALUE(version.get("end_cycle"), 0),
                "load_sites": load_sites,
            }
        )
    return {
        "cycle_sampler": _build_cycle_sampler(cycle_rows),
        "seed_domain_size": max(1, _INT_VALUE(row.get("seed_domain_size"), _INT_VALUE(fi_sampling_space.get("block_rand_max"), 1))),
        "domain_bits_per_seed": max(1, _INT_VALUE(row.get("domain_bits_per_seed"), _INT_VALUE(fi_sampling_space.get("smem_size_bits"), 1))),
        "denominator": float(component_denominator(fi_sampling_space, "smem_rf", fallback=0.0)),
        "version_count": len(versions),
        "trace_load_site_count": len(trace_load_sites),
        "versions": scan_versions,
        "programs": programs,
    }


def _classify_smem_fault(
    state: Mapping[str, Any],
    *,
    cycle: int,
    block_seed: int,
    bit_index: int,
) -> Tuple[str, float]:
    byte_addr = _BUILTIN_INT(bit_index) // 8
    versions = state.get("versions", [])
    if not isinstance(versions, list):
        return ("benign", 1.0)
    cycle_i = _BUILTIN_INT(cycle)
    for version in versions:
        if not isinstance(version, Mapping):
            continue
        if _INT_VALUE(version.get("cta_id"), -1) != _BUILTIN_INT(block_seed):
            continue
        if _INT_VALUE(version.get("addr"), -1) != _BUILTIN_INT(byte_addr):
            continue
        start_cycle = _INT_VALUE(version.get("start_cycle"), 0)
        end_cycle = _INT_VALUE(version.get("end_cycle"), start_cycle)
        if not (start_cycle <= cycle_i < end_cycle):
            continue
        load_sites = version.get("load_sites", [])
        if not isinstance(load_sites, list):
            return ("benign", 1.0)
        for site in load_sites:
            if not isinstance(site, Mapping):
                continue
            load_cycle = _INT_VALUE(site.get("cycle"), start_cycle)
            if cycle_i < load_cycle:
                programs = state.get("programs", {})
                if not isinstance(programs, Mapping):
                    raise ValueError("smem SIC requires trace program context")
                return ("dcr", _smem_sample_sic_probability(programs, site))
        return ("benign", 1.0)
    return ("benign", 1.0)


def _run_smem_campaign(
    state: Mapping[str, Any],
    *,
    campaign_runs: int,
    rng_seed: int,
) -> Dict[str, Any]:
    cycles, cumulative, total = state.get("cycle_sampler", ([0], [1], 1))
    rng = random.Random(_BUILTIN_INT(rng_seed))
    counts = {"benign": 0, "dcr": 0, "ebc": 0}
    seed_domain_size = max(1, _INT_VALUE(state.get("seed_domain_size"), 1))
    per_seed_bits = max(1, _INT_VALUE(state.get("domain_bits_per_seed"), 1))
    sic_sum = 0.0
    for _ in range(max(1, _BUILTIN_INT(campaign_runs))):
        cycle = _sample_cycle(rng, list(cycles), list(cumulative), _BUILTIN_INT(total))
        block_seed = rng.randrange(seed_domain_size)
        bit_index = rng.randrange(per_seed_bits)
        category, sic = _classify_smem_fault(
            state,
            cycle=cycle,
            block_seed=block_seed,
            bit_index=bit_index,
        )
        counts[category] += 1
        if category == "dcr":
            sic_sum += float(sic)
    return {"counts": counts, "sic_sum": float(sic_sum)}


def predict_rf(
    *,
    benchmark: str,
    test_id: str,
    analyzer_output: Mapping[str, Any],
    fi_sampling_space: Optional[Mapping[str, Any]],
    trace_template: Optional[Mapping[str, Any]],
    analyzer_input: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    fi_space = dict(fi_sampling_space or {})
    if not isinstance(trace_template, Mapping):
        raise ValueError("GEREM RF predictor requires trace_template events")
    state = _prepare_rf_campaign_state(
        fi_sampling_space=fi_space,
        trace_template=trace_template,
    )
    campaign_seed = _stable_campaign_seed(benchmark, test_id, "rf")
    campaign = _run_rf_campaign(
        state,
        campaign_runs=_BUILTIN_INT(GEREM_STORAGE_CAMPAIGN_RUNS),
        rng_seed=campaign_seed,
    )
    campaign_runs = max(1, _BUILTIN_INT(GEREM_STORAGE_CAMPAIGN_RUNS))
    campaign_mode = "sample"
    counts = campaign["counts"]
    denominator = float(state["denominator"])
    efm_rates = {
        "benign": float(counts["benign"]) / float(campaign_runs),
        "dcr": float(counts["dcr"]) / float(campaign_runs),
        "ebc": 0.0,
    }
    final_rates = {
        "masked": efm_rates["benign"],
        "sdc": efm_rates["dcr"],
        "due": 0.0,
    }
    return build_component_payload(
        benchmark=benchmark,
        test_id=test_id,
        component="rf",
        den=denominator,
        efm_rates=efm_rates,
        final_rates=final_rates,
        meta={
            "trace_version_count": _BUILTIN_INT(state["version_count"]),
            "register_domain_size": len(state["register_rows"]),
            "datatype_bits": _BUILTIN_INT(state["datatype_bits"]),
            "campaign_runs": _BUILTIN_INT(campaign_runs),
            "campaign_mode": campaign_mode,
            "campaign_seed": _BUILTIN_INT(campaign_seed),
            "rule": "rf_random_sample_storage_efm_trace_scan",
        },
    )


def predict_smem(
    *,
    benchmark: str,
    test_id: str,
    analyzer_output: Mapping[str, Any],
    fi_sampling_space: Optional[Mapping[str, Any]],
    trace_template: Optional[Mapping[str, Any]],
    analyzer_input: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    fi_space = dict(fi_sampling_space or {})
    if not isinstance(trace_template, Mapping):
        raise ValueError("GEREM SMEM predictor requires trace_template events")
    state = _prepare_smem_campaign_state(
        fi_sampling_space=fi_space,
        trace_template=trace_template,
    )
    campaign_seed = _stable_campaign_seed(benchmark, test_id, "smem_rf")
    campaign = _run_smem_campaign(
        state,
        campaign_runs=_BUILTIN_INT(GEREM_STORAGE_CAMPAIGN_RUNS),
        rng_seed=campaign_seed,
    )
    campaign_runs = max(1, _BUILTIN_INT(GEREM_STORAGE_CAMPAIGN_RUNS))
    campaign_mode = "sample"
    counts = campaign["counts"]
    dcr_runs = _BUILTIN_INT(counts["dcr"])
    sic = 1.0 if dcr_runs <= 0 else float(campaign["sic_sum"]) / float(dcr_runs)
    denominator = float(state["denominator"])
    efm_rates = {
        "benign": float(counts["benign"]) / float(campaign_runs),
        "dcr": float(dcr_runs) / float(campaign_runs),
        "ebc": 0.0,
    }
    final_rates = {
        "masked": efm_rates["benign"] + (efm_rates["dcr"] * (1.0 - float(sic))),
        "sdc": efm_rates["dcr"] * float(sic),
        "due": 0.0,
    }
    return build_component_payload(
        benchmark=benchmark,
        test_id=test_id,
        component="smem_rf",
        den=denominator,
        efm_rates=efm_rates,
        final_rates=final_rates,
        meta={
            "trace_version_count": _BUILTIN_INT(state["version_count"]),
            "trace_load_site_count": _BUILTIN_INT(state["trace_load_site_count"]),
            "smem_sic": float(sic),
            "sic": float(sic),
            "campaign_runs": _BUILTIN_INT(campaign_runs),
            "campaign_mode": campaign_mode,
            "campaign_seed": _BUILTIN_INT(campaign_seed),
            "campaign_dcr_runs": _BUILTIN_INT(dcr_runs),
            "rule": "smem_random_sample_storage_efm_trace_scan_static_sic",
        },
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", choices=("rf", "smem", "smem_rf"), required=True)
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--test-id", required=True)
    parser.add_argument("--analyzer-output", type=Path, default=None)
    parser.add_argument("--fi-sampling-space", type=Path, default=None)
    parser.add_argument("--trace-template", type=Path, default=None)
    parser.add_argument("--analyzer-input", type=Path, default=None)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "predict":
        argv = argv[1:]
    args = build_arg_parser().parse_args(argv)
    analyzer_output = load_json(args.analyzer_output) if args.analyzer_output is not None else {}
    fi_sampling_space = load_json(args.fi_sampling_space) if args.fi_sampling_space is not None else {}
    analyzer_input = load_json(args.analyzer_input) if args.analyzer_input is not None else None
    trace_template = load_json(args.trace_template) if args.trace_template is not None else None

    component = _component_name(args.component)
    if component == "rf":
        payload = predict_rf(
            benchmark=args.benchmark,
            test_id=args.test_id,
            analyzer_output=analyzer_output,
            fi_sampling_space=fi_sampling_space,
            trace_template=trace_template,
            analyzer_input=analyzer_input,
        )
    else:
        payload = predict_smem(
            benchmark=args.benchmark,
            test_id=args.test_id,
            analyzer_output=analyzer_output,
            fi_sampling_space=fi_sampling_space,
            trace_template=trace_template,
            analyzer_input=analyzer_input,
        )
    write_json(args.output, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
