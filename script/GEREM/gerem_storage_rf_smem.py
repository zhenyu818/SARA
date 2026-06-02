#!/usr/bin/env python3
"""GEREM predictors for register file and shared memory."""

from __future__ import annotations

import argparse
import bisect
import hashlib
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
        cycle_weight_between,
        cycle_domain_bounds,
        int_value,
        is_all_campaign_runs,
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
        cycle_weight_between,
        cycle_domain_bounds,
        int_value,
        is_all_campaign_runs,
        load_json,
        load_cycle_rows,
        write_json,
    )


MASKING_OPCODE_PREFIXES = ("max", "min")
MASKING_EVENT_KINDS = {"branch", "loop_branch"}
GEREM_STORAGE_CAMPAIGN_RUNS = campaign_runs_env("GEREM_STORAGE_CAMPAIGN_RUNS", 1000)
_BUILTIN_INT = int


def _stable_campaign_seed(*parts: Any) -> int:
    digest = hashlib.blake2b(digest_size=8)
    for part in parts:
        digest.update(str(part).encode("utf-8", errors="replace"))
        digest.update(b"\0")
    return int.from_bytes(digest.digest(), byteorder="big", signed=False)


def _build_cycle_sampler(cycle_rows: Iterable[Tuple[int, int]]) -> Tuple[List[int], List[int], int]:
    cycles: List[int] = []
    cumulative: List[int] = []
    total = 0
    for cycle, multiplicity in cycle_rows:
        mult = max(0, int(multiplicity))
        if mult <= 0:
            continue
        total += mult
        cycles.append(int(cycle))
        cumulative.append(int(total))
    if not cycles:
        cycles = [0]
        cumulative = [1]
        total = 1
    return cycles, cumulative, int(total)


def _cycle_weight_from_sampler(
    sampler: Any,
    start_cycle: int,
    end_cycle: int,
    _to_int: Any = _BUILTIN_INT,
) -> int:
    cycles, cumulative, _total = sampler if isinstance(sampler, tuple) and len(sampler) == 3 else ([0], [1], 1)
    return cycle_weight_between(
        [_to_int(cycle) for cycle in cycles],
        [0] + [_to_int(value) for value in cumulative],
        _to_int(start_cycle),
        _to_int(end_cycle),
    )


def _effective_entries(index: Any) -> Iterable[Tuple[Mapping[str, Any], int]]:
    if not isinstance(index, Mapping):
        return []
    entries = index.get("entries", [])
    if not isinstance(entries, list):
        return []
    out: List[Tuple[Mapping[str, Any], int]] = []
    for idx, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            continue
        end_cycle = int_value(entry.get("end_cycle"), -1)
        if idx + 1 < len(entries) and isinstance(entries[idx + 1], Mapping):
            end_cycle = min(end_cycle, int_value(entries[idx + 1].get("start_cycle"), end_cycle))
        out.append((entry, int(end_cycle)))
    return out


def _valid_bits_for_byte(byte_addr: int, total_bits: int) -> int:
    bit_start = int(byte_addr) * 8
    return max(0, min(8, int(total_bits) - bit_start))


def _sample_cycle(rng: random.Random, cycles: List[int], cumulative: List[int], total: int) -> int:
    pick = rng.randrange(max(1, int(total)))
    return int(cycles[bisect.bisect_right(cumulative, pick)])


def _lookup_interval(index: Optional[Mapping[str, Any]], cycle: int) -> Optional[Mapping[str, Any]]:
    if not isinstance(index, Mapping):
        return None
    starts = index.get("starts", [])
    entries = index.get("entries", [])
    if not isinstance(starts, list) or not isinstance(entries, list) or not starts:
        return None
    idx = bisect.bisect_right(starts, int(cycle)) - 1
    if idx < 0 or idx >= len(entries):
        return None
    entry = entries[idx]
    if not isinstance(entry, Mapping):
        return None
    if int(cycle) < int_value(entry.get("end_cycle"), -1):
        return entry
    return None


def _build_interval_index(entries: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    ordered = sorted(
        (dict(entry) for entry in entries if isinstance(entry, Mapping)),
        key=lambda entry: (
            int_value(entry.get("start_cycle"), 0),
            int_value(entry.get("end_cycle"), 0),
        ),
    )
    return {
        "starts": [int_value(entry.get("start_cycle"), 0) for entry in ordered],
        "entries": ordered,
    }


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
        return "0x{:x}".format(int_value(value, 0))
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
    trace_max_steps = int_value(trace_template.get("max_steps"), 0)
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
            "max_steps": int(max_steps),
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
    steps = max(0, int(max_steps) - 1)
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
        weight_int = max(0, int(weight))
        if weight_int <= 0:
            continue
        pc = _canonical_pc(site.get("pc"))
        if pc is None:
            raise ValueError("smem DCR site missing pc for SIC computation")
        program = _resolve_program_for_pc(programs, pc)
        max_steps = max(1, int_value(program.get("max_steps", 256), 256))
        program_key = (str(program.get("entry_pc", "")), int(max_steps))
        values = program_values_cache.get(program_key)
        if values is None:
            values = _program_sic_values(program, int(max_steps))
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
        row.setdefault("event_index", int(event_index))
        out.append(row)
    return out


def _event_cycle(record: Mapping[str, Any], fallback: int) -> int:
    return int_value(record.get("cycle", fallback), fallback)


def _pred_true(record: Mapping[str, Any]) -> bool:
    pred = record.get("pred")
    if not isinstance(pred, Mapping):
        return True
    return int_value(pred.get("val", 1), 1) != 0


def _register_identity(reg_name: Any, reg_uid: Any) -> Optional[Tuple[str, str]]:
    name = str(reg_name or "").strip()
    if not name.startswith("%"):
        return None
    uid = int_value(reg_uid, -1)
    if uid >= 0:
        return ("uid", str(uid))
    if not name:
        return None
    return ("name", name)


def _datatype_bits(fi_sampling_space: Mapping[str, Any]) -> int:
    return max(1, int_value(fi_sampling_space.get("datatype_bits"), 32))


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
        current["end_cycle"] = int(end_cycle)
        versions.append(dict(current))

    for event_index, raw in enumerate(events):
        if not _pred_true(raw):
            continue
        cycle = _event_cycle(raw, event_index)
        tid = int_value(raw.get("thread_id"), -1)
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
            key = (int(tid), ident)
            current = active.get(key)
            if current is None:
                current = {
                    "thread_id": int(tid),
                    "register": str(reg_name),
                    "identity": list(ident),
                    "start_cycle": int(domain_start),
                    "read_cycles": [],
                }
                active[key] = current
            read_cycles = current.setdefault("read_cycles", [])
            if isinstance(read_cycles, list):
                read_cycles.append(int(cycle))

        ident = _register_identity(raw.get("dst_reg"), raw.get("dst_reg_uid", -1))
        if ident is None:
            continue
        key = (int(tid), ident)
        finalize(key, int(cycle))
        active[key] = {
            "thread_id": int(tid),
            "register": str(raw.get("dst_reg", "")),
            "identity": list(ident),
            "start_cycle": int(cycle),
            "read_cycles": [],
        }

    for key in list(active.keys()):
        finalize(key, int(domain_end))

    return versions, int(domain_end)


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
        current["end_cycle"] = int(end_cycle)
        versions.append(dict(current))

    for event_index, raw in enumerate(events):
        if not _pred_true(raw):
            continue
        if canonical_mem_space(raw.get("mem_space") or raw.get("space")) != "shared":
            continue
        kind = str(raw.get("kind", "")).strip().lower()
        if kind not in {"load", "store"}:
            continue
        sm_id = int_value(raw.get("sm_id"), -1)
        cta_id = int_value(raw.get("cta_id"), -1)
        addr = raw.get("mem_addr", raw.get("base"))
        if sm_id < 0 or cta_id < 0 or addr is None:
            continue
        cycle = _event_cycle(raw, event_index)
        base_addr = int_value(addr, 0)
        size_bytes = max(1, access_size_bytes_for_raw_event(raw))
        for byte_index in range(size_bytes):
            byte_addr = int(base_addr + byte_index)
            key = (int(sm_id), int(cta_id), int(byte_addr))
            if kind == "store":
                finalize(key, int(cycle))
                active[key] = {
                    "sm_id": int(sm_id),
                    "cta_id": int(cta_id),
                    "addr": int(byte_addr),
                    "start_cycle": int(cycle),
                    "load_sites": [],
                }
                continue

            current = active.get(key)
            if current is None:
                continue
            site = {
                "sm_id": int(sm_id),
                "cta_id": int(cta_id),
                "thread_id": int_value(raw.get("thread_id"), -1),
                "cycle": int(cycle),
                "event_index": int(event_index),
                "pc": raw.get("pc"),
                "kind": str(raw.get("kind", "")),
                "opcode": str(raw.get("opcode", "")),
                "addr": int(byte_addr),
            }
            load_sites.append(site)
            cur_loads = current.setdefault("load_sites", [])
            if isinstance(cur_loads, list):
                cur_loads.append(site)

    for key in list(active.keys()):
        finalize(key, int(domain_end))

    return versions, int(domain_end), load_sites


def _smem_site_probability_lookup(trace_template: Mapping[str, Any], sites: Iterable[Mapping[str, Any]]) -> Dict[str, float]:
    programs = _prepare_trace_programs(trace_template)
    program_values_cache: Dict[Tuple[str, int], Dict[str, float]] = {}
    probability_by_pc: Dict[str, float] = {}
    for site in sites:
        if not isinstance(site, Mapping):
            continue
        pc = _canonical_pc(site.get("pc"))
        if pc is None or pc in probability_by_pc:
            continue
        program = _resolve_program_for_pc(programs, pc)
        max_steps = max(1, int_value(program.get("max_steps", 256), 256))
        program_key = (str(program.get("entry_pc", "")), int(max_steps))
        values = program_values_cache.get(program_key)
        if values is None:
            values = _program_sic_values(program, int(max_steps))
            program_values_cache[program_key] = values
        probability_by_pc[pc] = float(_site_sic_probability(site, program, values))
    return probability_by_pc


def _prepare_rf_campaign_state(
    *,
    fi_sampling_space: Mapping[str, Any],
    trace_template: Mapping[str, Any],
) -> Dict[str, Any]:
    row = _component_row_required(fi_sampling_space, "rf")
    cycle_rows = load_cycle_rows(fi_sampling_space, trace_template)
    versions, _domain_end = _build_rf_versions(trace_template, fi_sampling_space=fi_sampling_space)
    versions_by_key: Dict[Tuple[int, str], List[Dict[str, Any]]] = {}
    for version in versions:
        tid = int_value(version.get("thread_id"), -1)
        reg_name = str(version.get("register", "")).strip()
        if tid < 0 or not reg_name:
            continue
        read_cycles = sorted(
            int_value(raw_cycle, -1)
            for raw_cycle in version.get("read_cycles", [])
            if int_value(raw_cycle, -1) >= 0
        )
        dcr_end = max(read_cycles) if read_cycles else int_value(version.get("start_cycle"), 0)
        versions_by_key.setdefault((int(tid), reg_name), []).append(
            {
                "start_cycle": int_value(version.get("start_cycle"), 0),
                "end_cycle": int_value(version.get("end_cycle"), 0),
                "dcr_end_cycle": int(dcr_end),
            }
        )
    register_rows = _load_register_rows(fi_sampling_space)
    return {
        "cycle_sampler": _build_cycle_sampler(cycle_rows),
        "register_rows": list(register_rows),
        "datatype_bits": int(_datatype_bits(fi_sampling_space)),
        "seed_domain_size": max(1, int_value(row.get("seed_domain_size"), int_value(fi_sampling_space.get("thread_rand_max"), 1))),
        "domain_bits_per_seed": max(1, int_value(row.get("domain_bits_per_seed"), len(register_rows) * _datatype_bits(fi_sampling_space))),
        "denominator": float(component_denominator(fi_sampling_space, "rf", fallback=0.0)),
        "version_count": len(versions),
        "lookup": {
            key: _build_interval_index(entries)
            for key, entries in versions_by_key.items()
        },
    }


def _classify_rf_fault(
    state: Mapping[str, Any],
    *,
    cycle: int,
    thread_seed: int,
    bit_index: int,
) -> str:
    datatype_bits = max(1, int_value(state.get("datatype_bits"), 32))
    reg_rows = state.get("register_rows", [])
    if not isinstance(reg_rows, list) or not reg_rows:
        return "benign"
    reg_slot = int(bit_index) // int(datatype_bits)
    if reg_slot < 0 or reg_slot >= len(reg_rows):
        return "benign"
    reg_name = str(reg_rows[reg_slot]).strip()
    interval = _lookup_interval(state.get("lookup", {}).get((int(thread_seed), reg_name)), int(cycle))
    if interval is None:
        return "benign"
    return "dcr" if int(cycle) < int_value(interval.get("dcr_end_cycle"), -1) else "benign"


def _run_rf_campaign(
    state: Mapping[str, Any],
    *,
    campaign_runs: int,
    rng_seed: int,
) -> Dict[str, float]:
    cycles, cumulative, total = state.get("cycle_sampler", ([0], [1], 1))
    rng = random.Random(int(rng_seed))
    counts = {"benign": 0, "dcr": 0, "ebc": 0}
    seed_domain_size = max(1, int_value(state.get("seed_domain_size"), 1))
    per_seed_bits = max(1, int_value(state.get("domain_bits_per_seed"), 1))
    for _ in range(max(1, int(campaign_runs))):
        cycle = _sample_cycle(rng, list(cycles), list(cumulative), int(total))
        thread_seed = rng.randrange(seed_domain_size)
        bit_index = rng.randrange(per_seed_bits)
        counts[_classify_rf_fault(state, cycle=cycle, thread_seed=thread_seed, bit_index=bit_index)] += 1
    return {"counts": counts}


def _run_rf_all_fault_points(state: Mapping[str, Any]) -> Dict[str, Any]:
    _cycles, _cumulative, cycle_total = state.get("cycle_sampler", ([0], [1], 1))
    seed_domain_size = max(1, int_value(state.get("seed_domain_size"), 1))
    per_seed_bits = max(1, int_value(state.get("domain_bits_per_seed"), 1))
    domain_points = int(cycle_total) * int(seed_domain_size) * int(per_seed_bits)
    datatype_bits = max(1, int_value(state.get("datatype_bits"), 32))
    register_rows = {str(row).strip() for row in state.get("register_rows", []) if str(row).strip()}

    dcr_bits = 0
    lookup = state.get("lookup", {})
    if isinstance(lookup, Mapping):
        for key, index in lookup.items():
            if not isinstance(key, tuple) or len(key) != 2:
                continue
            reg_name = str(key[1]).strip()
            if reg_name not in register_rows:
                continue
            for interval, effective_end in _effective_entries(index):
                start_cycle = int_value(interval.get("start_cycle"), 0)
                dcr_end = min(int_value(interval.get("dcr_end_cycle"), start_cycle), int(effective_end))
                if dcr_end <= start_cycle:
                    continue
                dcr_bits += _cycle_weight_from_sampler(state.get("cycle_sampler"), start_cycle, dcr_end) * datatype_bits

    dcr_bits = min(max(0, int(dcr_bits)), int(domain_points))
    return {
        "counts": {"benign": int(domain_points - dcr_bits), "dcr": int(dcr_bits), "ebc": 0},
        "domain_points": int(domain_points),
    }


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
    site_sic_by_pc = _smem_site_probability_lookup(trace_template, trace_load_sites)
    versions_by_key: Dict[Tuple[int, int], List[Dict[str, Any]]] = {}
    for version in versions:
        cta_id = int_value(version.get("cta_id"), -1)
        addr = int_value(version.get("addr"), -1)
        if cta_id < 0 or addr < 0:
            continue
        load_sites = [
            dict(site)
            for site in version.get("load_sites", [])
            if isinstance(site, Mapping)
        ]
        load_sites.sort(
            key=lambda site: (
                int_value(site.get("cycle"), 0),
                int_value(site.get("event_index"), 0),
            )
        )
        segments: List[Dict[str, Any]] = []
        segment_start = int_value(version.get("start_cycle"), 0)
        for site in load_sites:
            load_cycle = int_value(site.get("cycle"), segment_start)
            if load_cycle > segment_start:
                pc = _canonical_pc(site.get("pc"))
                if pc is None or pc not in site_sic_by_pc:
                    raise ValueError("smem DCR site missing trace pc for SIC computation")
                segments.append(
                    {
                        "start_cycle": int(segment_start),
                        "end_cycle": int(load_cycle),
                        "sic": float(site_sic_by_pc[pc]),
                    }
                )
            segment_start = int(load_cycle)
        versions_by_key.setdefault((int(cta_id), int(addr)), []).append(
            {
                "start_cycle": int_value(version.get("start_cycle"), 0),
                "end_cycle": int_value(version.get("end_cycle"), 0),
                "segments": segments,
                "segment_index": _build_interval_index(segments),
            }
        )
    return {
        "cycle_sampler": _build_cycle_sampler(cycle_rows),
        "seed_domain_size": max(1, int_value(row.get("seed_domain_size"), int_value(fi_sampling_space.get("block_rand_max"), 1))),
        "domain_bits_per_seed": max(1, int_value(row.get("domain_bits_per_seed"), int_value(fi_sampling_space.get("smem_size_bits"), 1))),
        "denominator": float(component_denominator(fi_sampling_space, "smem_rf", fallback=0.0)),
        "version_count": len(versions),
        "trace_load_site_count": len(trace_load_sites),
        "lookup": {
            key: _build_interval_index(entries)
            for key, entries in versions_by_key.items()
        },
    }


def _classify_smem_fault(
    state: Mapping[str, Any],
    *,
    cycle: int,
    block_seed: int,
    bit_index: int,
) -> Tuple[str, float]:
    byte_addr = int(bit_index) // 8
    interval = _lookup_interval(state.get("lookup", {}).get((int(block_seed), int(byte_addr))), int(cycle))
    if interval is None:
        return ("benign", 1.0)
    segment = _lookup_interval(interval.get("segment_index"), int(cycle))
    if segment is None:
        return ("benign", 1.0)
    return ("dcr", float(segment.get("sic", 1.0)))


def _run_smem_campaign(
    state: Mapping[str, Any],
    *,
    campaign_runs: int,
    rng_seed: int,
) -> Dict[str, Any]:
    cycles, cumulative, total = state.get("cycle_sampler", ([0], [1], 1))
    rng = random.Random(int(rng_seed))
    counts = {"benign": 0, "dcr": 0, "ebc": 0}
    seed_domain_size = max(1, int_value(state.get("seed_domain_size"), 1))
    per_seed_bits = max(1, int_value(state.get("domain_bits_per_seed"), 1))
    sic_sum = 0.0
    for _ in range(max(1, int(campaign_runs))):
        cycle = _sample_cycle(rng, list(cycles), list(cumulative), int(total))
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


def _run_smem_all_fault_points(state: Mapping[str, Any]) -> Dict[str, Any]:
    _cycles, _cumulative, cycle_total = state.get("cycle_sampler", ([0], [1], 1))
    seed_domain_size = max(1, int_value(state.get("seed_domain_size"), 1))
    per_seed_bits = max(1, int_value(state.get("domain_bits_per_seed"), 1))
    domain_points = int(cycle_total) * int(seed_domain_size) * int(per_seed_bits)

    dcr_bits = 0
    sic_sum = 0.0
    lookup = state.get("lookup", {})
    if isinstance(lookup, Mapping):
        for key, index in lookup.items():
            if not isinstance(key, tuple) or len(key) != 2:
                continue
            byte_addr = int_value(key[1], -1)
            bits_in_byte = _valid_bits_for_byte(byte_addr, per_seed_bits)
            if bits_in_byte <= 0:
                continue
            for interval, version_end in _effective_entries(index):
                for segment, segment_end in _effective_entries(interval.get("segment_index")):
                    start_cycle = max(
                        int_value(interval.get("start_cycle"), 0),
                        int_value(segment.get("start_cycle"), 0),
                    )
                    end_cycle = min(int(version_end), int(segment_end))
                    if end_cycle <= start_cycle:
                        continue
                    bit_weight = _cycle_weight_from_sampler(state.get("cycle_sampler"), start_cycle, end_cycle) * bits_in_byte
                    if bit_weight <= 0:
                        continue
                    dcr_bits += int(bit_weight)
                    sic_sum += float(bit_weight) * float(segment.get("sic", 1.0))

    dcr_bits = min(max(0, int(dcr_bits)), int(domain_points))
    return {
        "counts": {"benign": int(domain_points - dcr_bits), "dcr": int(dcr_bits), "ebc": 0},
        "sic_sum": float(sic_sum),
        "domain_points": int(domain_points),
    }
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
    if is_all_campaign_runs(GEREM_STORAGE_CAMPAIGN_RUNS):
        campaign = _run_rf_all_fault_points(state)
        campaign_runs = int(campaign["domain_points"])
        campaign_mode = "all"
    else:
        campaign = _run_rf_campaign(
            state,
            campaign_runs=int(GEREM_STORAGE_CAMPAIGN_RUNS),
            rng_seed=campaign_seed,
        )
        campaign_runs = max(1, int(GEREM_STORAGE_CAMPAIGN_RUNS))
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
            "trace_version_count": int(state["version_count"]),
            "register_domain_size": len(state["register_rows"]),
            "datatype_bits": int(state["datatype_bits"]),
            "campaign_runs": int(campaign_runs),
            "campaign_mode": campaign_mode,
            "campaign_seed": int(campaign_seed),
            "rule": "rf_per_run_trace_efm_direct",
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
    if is_all_campaign_runs(GEREM_STORAGE_CAMPAIGN_RUNS):
        campaign = _run_smem_all_fault_points(state)
        campaign_runs = int(campaign["domain_points"])
        campaign_mode = "all"
    else:
        campaign = _run_smem_campaign(
            state,
            campaign_runs=int(GEREM_STORAGE_CAMPAIGN_RUNS),
            rng_seed=campaign_seed,
        )
        campaign_runs = max(1, int(GEREM_STORAGE_CAMPAIGN_RUNS))
        campaign_mode = "sample"
    counts = campaign["counts"]
    dcr_runs = int(counts["dcr"])
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
            "trace_version_count": int(state["version_count"]),
            "trace_load_site_count": int(state["trace_load_site_count"]),
            "smem_sic": float(sic),
            "sic": float(sic),
            "campaign_runs": int(campaign_runs),
            "campaign_mode": campaign_mode,
            "campaign_seed": int(campaign_seed),
            "campaign_dcr_runs": int(dcr_runs),
            "rule": "smem_per_run_trace_static_sic",
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
