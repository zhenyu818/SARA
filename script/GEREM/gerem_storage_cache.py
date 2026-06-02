#!/usr/bin/env python3
"""GEREM predictors for L1D and L2 cache."""

from __future__ import annotations

import argparse
import bisect
import hashlib
import random
from collections.abc import MutableMapping
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    from .gerem_storage_common import (
        access_size_bytes_for_raw_event,
        build_component_payload,
        canonical_mem_space,
        campaign_runs_env,
        cycle_weight_between,
        cycle_domain_bounds,
        int_value,
        is_all_campaign_runs,
        load_cycle_rows,
        load_json,
        write_json,
    )
except ImportError:
    from gerem_storage_common import (
        access_size_bytes_for_raw_event,
        build_component_payload,
        canonical_mem_space,
        campaign_runs_env,
        cycle_weight_between,
        cycle_domain_bounds,
        int_value,
        is_all_campaign_runs,
        load_cycle_rows,
        load_json,
        write_json,
    )


MASK_FIELD_CANDIDATES: Tuple[str, ...] = (
    "observed_mask_this_site",
    "due_mask_this_site",
    "trace_expanding_mask_this_site",
    "replay_sdc_mask_this_site",
    "replay_due_mask_this_site",
)

INVALID_HINTS: Tuple[str, ...] = ("invalid", "not_present", "evicted")
TAG_HINTS: Tuple[str, ...] = ("tag", "index", "set")
DATA_HINTS: Tuple[str, ...] = ("data", "payload", "byte")
NOT_REUSED_HINTS: Tuple[str, ...] = ("never_reused", "not_used", "unused", "dead")
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


def _valid_bits_for_byte(byte_offset: int, data_bits_per_line: int) -> int:
    bit_start = int(byte_offset) * 8
    return max(0, min(8, int(data_bits_per_line) - bit_start))


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


def _float_value(value: Any, default: float = 0.0) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and value.strip():
        return float(value)
    return default


def _bool_field(record: Mapping[str, Any], key: str) -> Optional[bool]:
    if key not in record:
        return None
    value = record.get(key)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"1", "true", "yes", "y", "valid", "used"}:
            return True
        if text in {"0", "false", "no", "n", "invalid", "unused", "not_used"}:
            return False
    return None


def _mask_union(record: Mapping[str, Any]) -> int:
    mask = 0
    for field in MASK_FIELD_CANDIDATES:
        mask |= int_value(record.get(field, 0), 0)
    return mask


def _bit_count(value: int) -> int:
    value_i = int(value)
    try:
        return value_i.bit_count()
    except AttributeError:
        return bin(value_i & ((1 << max(1, value_i.bit_length())) - 1)).count("1")


def _selected_bits(record: Mapping[str, Any]) -> int:
    for key in ("selected_bits", "bit_count", "fault_bits", "num_bits"):
        bits = int_value(record.get(key), -1)
        if bits > 0:
            return bits
    live_mask = _mask_union(record)
    if live_mask:
        return _bit_count(live_mask)
    width_bits = int_value(record.get("width_bits"), 0)
    if width_bits > 0:
        return width_bits
    return 1


def _component_domain(fi_sampling_space: Mapping[str, Any], component: str) -> Dict[str, Any]:
    domains = fi_sampling_space.get("component_domains", {})
    if not isinstance(domains, Mapping):
        raise ValueError("fi_sampling_space.component_domains: expected object")
    row = domains.get(component, {})
    if not isinstance(row, Mapping) or not row:
        raise ValueError(f"missing component domain for {component}")
    return dict(row)


def _site_list(analyzer_output: Mapping[str, Any], component: str) -> List[Dict[str, Any]]:
    key = "l1d_fault_sites" if component == "l1d" else "l2_fault_sites"
    raw = analyzer_output.get(key, [])
    if not isinstance(raw, list):
        raise ValueError(f"{key}: expected list")
    return [dict(record) for record in raw if isinstance(record, Mapping)]


def _text_hints(record: Mapping[str, Any]) -> str:
    fields = (
        "site_kind",
        "fault_kind",
        "bit_kind",
        "bit_class",
        "field_kind",
        "cache_field",
        "line_state",
        "entry_state",
        "status",
    )
    tokens: List[str] = []
    for key in fields:
        value = record.get(key)
        if value is None:
            continue
        tokens.append(str(value).strip().lower())
    return " ".join(tokens)


def _is_invalid(record: Mapping[str, Any]) -> bool:
    for key in (
        "valid",
        "is_valid",
        "line_valid",
        "entry_valid",
        "valid_line",
        "valid_entry",
        "cache_valid",
        "is_line_valid",
        "is_entry_valid",
    ):
        value = _bool_field(record, key)
        if value is False:
            return True
    hints = _text_hints(record)
    return any(token in hints for token in INVALID_HINTS)


def _is_never_reused(record: Mapping[str, Any]) -> bool:
    for key in (
        "used_later",
        "used_again",
        "reused",
        "reused_later",
        "consumed_later",
        "used_by_load",
        "used_by_writeback",
        "writeback_consumed",
        "load_consumed",
    ):
        value = _bool_field(record, key)
        if value is False:
            return True
    hints = _text_hints(record)
    return any(token in hints for token in NOT_REUSED_HINTS)


def _is_tag_site(record: Mapping[str, Any], data_bits_per_line: int) -> bool:
    hints = _text_hints(record)
    if any(token in hints for token in TAG_HINTS):
        return True
    if any(token in hints for token in DATA_HINTS):
        return False
    for key in ("line_bit_index", "bit_index_in_line", "bit_offset_in_line", "bit_offset"):
        if key not in record:
            continue
        bit_offset = int_value(record.get(key), -1)
        if bit_offset >= 0:
            return bit_offset >= data_bits_per_line
    return False


def _classify_site_fallback(record: Mapping[str, Any], data_bits_per_line: int) -> str:
    if _is_invalid(record) or _is_never_reused(record):
        return "benign"
    if _is_tag_site(record, data_bits_per_line):
        return "ebc"
    return "dcr"


def _clamp_counts(den: float, benign: float, dcr: float, ebc: float) -> Tuple[float, float, float]:
    overflow = max(0.0, benign + dcr + ebc - den)
    if overflow <= 0.0:
        return benign, dcr, ebc
    benign = max(0.0, benign - overflow)
    overflow = max(0.0, benign + dcr + ebc - den)
    if overflow <= 0.0:
        return benign, dcr, ebc
    ebc = max(0.0, ebc - overflow)
    overflow = max(0.0, benign + dcr + ebc - den)
    if overflow <= 0.0:
        return benign, dcr, ebc
    dcr = max(0.0, dcr - overflow)
    return benign, dcr, ebc


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


def _line_chunks(raw: Mapping[str, Any], line_size_bytes: int) -> List[Tuple[int, Tuple[int, ...]]]:
    addr = raw.get("mem_addr", raw.get("base"))
    if addr is None:
        return []
    base_addr = int_value(addr, 0)
    size_bytes = max(1, access_size_bytes_for_raw_event(raw))
    out: List[Tuple[int, Tuple[int, ...]]] = []
    cur_addr = int(base_addr)
    remaining = int(size_bytes)
    while remaining > 0:
        line_addr = int(cur_addr // int(line_size_bytes))
        line_offset = int(cur_addr % int(line_size_bytes))
        chunk = min(int(remaining), int(line_size_bytes) - int(line_offset))
        offsets = tuple(range(int(line_offset), int(line_offset + chunk)))
        out.append((int(line_addr), offsets))
        cur_addr += int(chunk)
        remaining -= int(chunk)
    return out


def _resolve_l1d_seed(sm_id: int, allowed_seeds: Sequence[int]) -> Optional[int]:
    if sm_id >= 0:
        if not allowed_seeds or sm_id in allowed_seeds:
            return int(sm_id)
        return None
    if len(allowed_seeds) == 1:
        return int(allowed_seeds[0])
    return None


def _shader_seeds(component_row: Mapping[str, Any], events: Sequence[Mapping[str, Any]]) -> List[int]:
    shaders = component_row.get("shaders", [])
    if isinstance(shaders, list) and shaders:
        return sorted({int_value(v, -1) for v in shaders if int_value(v, -1) >= 0})
    shader_count = int_value(component_row.get("shader_count"), 0)
    if shader_count > 0:
        return list(range(shader_count))
    inferred = {
        int_value(raw.get("sm_id"), -1)
        for raw in events
        if canonical_mem_space(raw.get("mem_space") or raw.get("space")) in {"global", "local"}
        and int_value(raw.get("sm_id"), -1) >= 0
    }
    return sorted(inferred)


def _simulate_cache_episodes(
    *,
    component: str,
    trace_template: Mapping[str, Any],
    component_row: Mapping[str, Any],
    domain_end: int,
) -> List[Dict[str, Any]]:
    events = _trace_events(trace_template)
    line_size_bytes = max(1, int_value(component_row.get("line_size_bytes"), 128))
    nset = max(1, int_value(component_row.get("nset"), 1))
    assoc = max(1, int_value(component_row.get("assoc"), 1))
    write_allocate = int_value(component_row.get("write_allocate"), 1) != 0
    allowed_seeds = _shader_seeds(component_row, events) if component == "l1d" else [0]

    episodes: List[MutableMapping[str, Any]] = []
    active: Dict[Tuple[int, Tuple[Any, ...]], MutableMapping[str, Any]] = {}
    cache_sets: Dict[int, Dict[int, MutableMapping[str, Any]]] = {}

    def finalize_version(
        version: MutableMapping[str, Any],
        *,
        end_cycle: int,
        end_reason: str,
    ) -> None:
        if version.get("end_cycle") is not None:
            return
        version["end_cycle"] = int(end_cycle)
        version["end_reason"] = str(end_reason)

    def finalize_episode(
        episode: MutableMapping[str, Any],
        *,
        end_cycle: int,
        end_reason: str,
    ) -> None:
        if episode.get("end_cycle") is None:
            episode["end_cycle"] = int(end_cycle)
        active_versions = episode.get("active_versions_by_offset", {})
        if not isinstance(active_versions, MutableMapping):
            return
        for version in active_versions.values():
            if isinstance(version, MutableMapping):
                finalize_version(version, end_cycle=int(end_cycle), end_reason=end_reason)

    def make_clean_version(start_cycle: int) -> Dict[str, Any]:
        return {
            "start_cycle": int(start_cycle),
            "end_cycle": None,
            "end_reason": None,
            "dirty": False,
            "last_load_cycle": None,
        }

    def make_dirty_version(start_cycle: int) -> Dict[str, Any]:
        return {
            "start_cycle": int(start_cycle),
            "end_cycle": None,
            "end_reason": None,
            "dirty": True,
            "last_load_cycle": None,
        }

    def create_episode(
        *,
        seed: int,
        mem_space: str,
        line_key: Tuple[Any, ...],
        line_addr: int,
        set_idx: int,
        way_idx: int,
        cycle: int,
    ) -> MutableMapping[str, Any]:
        byte_versions: Dict[int, List[Dict[str, Any]]] = {}
        active_versions_by_offset: Dict[int, Dict[str, Any]] = {}
        for offset in range(line_size_bytes):
            version = make_clean_version(int(cycle))
            byte_versions[int(offset)] = [version]
            active_versions_by_offset[int(offset)] = version
        episode: MutableMapping[str, Any] = {
            "seed": int(seed),
            "mem_space": str(mem_space),
            "line_key": list(line_key),
            "line_addr": int(line_addr),
            "set_idx": int(set_idx),
            "way_idx": int(way_idx),
            "start_cycle": int(cycle),
            "end_cycle": None,
            "byte_versions": byte_versions,
            "active_versions_by_offset": active_versions_by_offset,
        }
        episodes.append(episode)
        active[(int(seed), line_key)] = episode
        return episode

    def set_state(seed: int, set_idx: int) -> MutableMapping[str, Any]:
        per_seed_sets = cache_sets.setdefault(int(seed), {})
        state = per_seed_sets.get(int(set_idx))
        if isinstance(state, MutableMapping):
            return state
        state = {
            "slots": [None for _ in range(assoc)],
            "lru": list(range(assoc)),
        }
        per_seed_sets[int(set_idx)] = state
        return state

    def touch_lru(state: MutableMapping[str, Any], way_idx: int) -> None:
        lru = state.get("lru", [])
        if not isinstance(lru, list):
            lru = []
            state["lru"] = lru
        if int(way_idx) in lru:
            lru.remove(int(way_idx))
        lru.insert(0, int(way_idx))

    for event_index, raw in enumerate(events):
        if not _pred_true(raw):
            continue
        kind = str(raw.get("kind", "")).strip().lower()
        if kind not in {"load", "store"}:
            continue
        mem_space = canonical_mem_space(raw.get("mem_space") or raw.get("space"))
        if mem_space not in {"global", "local"}:
            continue
        cycle = _event_cycle(raw, event_index)
        chunks = _line_chunks(raw, line_size_bytes)
        if not chunks:
            continue

        if component == "l1d":
            sm_id = int_value(raw.get("sm_id"), -1)
            seed = _resolve_l1d_seed(sm_id, allowed_seeds)
            if seed is None:
                continue
        else:
            seed = 0

        thread_id = int_value(raw.get("thread_id"), -1)
        should_allocate = kind == "load" or component == "l2" or write_allocate

        for line_addr, offsets in chunks:
            set_idx = int(line_addr % int(nset))
            state = set_state(int(seed), int(set_idx))
            slots = state.get("slots", [])
            if not isinstance(slots, list):
                slots = [None for _ in range(assoc)]
                state["slots"] = slots
            if mem_space == "local":
                if thread_id < 0:
                    continue
                line_key = (str(mem_space), int(thread_id), int(line_addr))
            else:
                line_key = (str(mem_space), int(line_addr))

            active_key = (int(seed), line_key)
            episode = active.get(active_key)

            if episode is None and not should_allocate:
                continue

            way_idx = -1
            if episode is not None:
                way_idx = int_value(episode.get("way_idx"), -1)
                if way_idx < 0:
                    for idx, slot_key in enumerate(slots):
                        if slot_key == line_key:
                            way_idx = int(idx)
                            break
                if way_idx >= 0:
                    touch_lru(state, int(way_idx))
            else:
                for idx, slot_key in enumerate(slots):
                    if slot_key is None:
                        way_idx = int(idx)
                        break
                if way_idx < 0:
                    lru = state.get("lru", [])
                    if not isinstance(lru, list) or not lru:
                        lru = list(range(assoc))
                        state["lru"] = lru
                    way_idx = int(lru[-1])
                    victim_key = slots[way_idx]
                    if victim_key is not None:
                        victim = active.pop((int(seed), victim_key), None)
                        if victim is not None:
                            finalize_episode(victim, end_cycle=int(cycle), end_reason="evict")
                    slots[way_idx] = None
                episode = create_episode(
                    seed=int(seed),
                    mem_space=str(mem_space),
                    line_key=line_key,
                    line_addr=int(line_addr),
                    set_idx=int(set_idx),
                    way_idx=int(way_idx),
                    cycle=int(cycle),
                )
                slots[way_idx] = line_key
                touch_lru(state, int(way_idx))

            byte_versions = episode.setdefault("byte_versions", {})
            if not isinstance(byte_versions, MutableMapping):
                byte_versions = {}
                episode["byte_versions"] = byte_versions
            active_versions = episode.setdefault("active_versions_by_offset", {})
            if not isinstance(active_versions, MutableMapping):
                active_versions = {}
                episode["active_versions_by_offset"] = active_versions

            if kind == "load":
                for offset in offsets:
                    current = active_versions.get(int(offset))
                    if isinstance(current, MutableMapping):
                        current["last_load_cycle"] = int(cycle)
                continue

            for offset in offsets:
                offset_i = int(offset)
                current = active_versions.get(offset_i)
                if isinstance(current, MutableMapping):
                    finalize_version(current, end_cycle=int(cycle), end_reason="overwrite")
                new_version = make_dirty_version(int(cycle))
                version_list = byte_versions.setdefault(offset_i, [])
                if not isinstance(version_list, list):
                    version_list = []
                    byte_versions[offset_i] = version_list
                version_list.append(new_version)
                active_versions[offset_i] = new_version

    for episode in active.values():
        finalize_episode(episode, end_cycle=int(domain_end), end_reason="evict")
    return [dict(episode) for episode in episodes]


def _prepare_cache_campaign_state(
    *,
    analyzer_output: Mapping[str, Any],
    fi_sampling_space: Mapping[str, Any],
    trace_template: Mapping[str, Any],
    component: str,
) -> Dict[str, Any]:
    row = _component_domain(fi_sampling_space, component)
    den = max(0.0, _float_value(row.get("domain_total_bits"), 0.0))
    if den <= 0.0:
        raise ValueError("missing component domain for {}".format(component))
    tag_bits = max(0, int_value(row.get("tag_bits"), 0))
    include_tag_bits = int_value(row.get("include_tag_bits"), 1) != 0
    line_size_bytes = max(1, int_value(row.get("line_size_bytes"), 128))
    cycle_rows = load_cycle_rows(fi_sampling_space, trace_template)
    episodes = _simulate_cache_episodes(
        component=component,
        trace_template=trace_template,
        component_row=row,
        domain_end=cycle_domain_bounds(cycle_rows)[1],
    )
    episodes_by_slot: Dict[Tuple[int, int, int], List[Dict[str, Any]]] = {}
    touched_data_offsets = 0
    for episode in episodes:
        slot_key = (
            int_value(episode.get("seed"), -1),
            int_value(episode.get("set_idx"), -1),
            int_value(episode.get("way_idx"), -1),
        )
        episodes_by_slot.setdefault(slot_key, []).append(dict(episode))
        byte_versions = episode.get("byte_versions", {})
        if isinstance(byte_versions, Mapping):
            touched_data_offsets += sum(1 for _offset in byte_versions.keys())
    slot_lookup = {
        key: _build_interval_index(entries)
        for key, entries in episodes_by_slot.items()
    }
    for episode_index in slot_lookup.values():
        for episode in episode_index.get("entries", []):
            if not isinstance(episode, MutableMapping):
                continue
            byte_versions = episode.get("byte_versions", {})
            if not isinstance(byte_versions, Mapping):
                episode["byte_versions"] = {}
                continue
            version_lookup: Dict[int, Dict[str, Any]] = {}
            for offset, version_list in byte_versions.items():
                if not isinstance(version_list, list):
                    continue
                version_lookup[int_value(offset, -1)] = _build_interval_index(version_list)
            episode["byte_version_index"] = version_lookup
    seed_choices = _shader_seeds(row, _trace_events(trace_template)) if component == "l1d" else [0]
    return {
        "denominator": float(den),
        "cycle_sampler": _build_cycle_sampler(cycle_rows),
        "seed_choices": list(seed_choices or [0]),
        "domain_bits_per_seed": max(1, int_value(row.get("domain_bits_per_seed"), 1)),
        "line_size_bytes": int(line_size_bytes),
        "data_bits_per_line": int(line_size_bytes * 8),
        "tag_bits_per_line": int(tag_bits if include_tag_bits else 0),
        "nset": max(1, int_value(row.get("nset"), 1)),
        "assoc": max(1, int_value(row.get("assoc"), 1)),
        "slot_lookup": slot_lookup,
        "episode_count": len(episodes),
        "touched_data_offsets": int(touched_data_offsets),
        "observed_site_count": len(_site_list(analyzer_output, component)),
    }


def _classify_cache_fault(
    state: Mapping[str, Any],
    *,
    cycle: int,
    seed: int,
    bit_index: int,
) -> str:
    data_bits = max(1, int_value(state.get("data_bits_per_line"), 8))
    tag_bits = max(0, int_value(state.get("tag_bits_per_line"), 0))
    line_bits = int(data_bits + tag_bits)
    if line_bits <= 0:
        return "benign"
    slot_index = int(bit_index) // int(line_bits)
    set_idx = slot_index // max(1, int_value(state.get("assoc"), 1))
    way_idx = slot_index % max(1, int_value(state.get("assoc"), 1))
    if set_idx < 0 or set_idx >= max(1, int_value(state.get("nset"), 1)):
        return "benign"
    episode = _lookup_interval(state.get("slot_lookup", {}).get((int(seed), int(set_idx), int(way_idx))), int(cycle))
    if episode is None:
        return "benign"
    bit_in_line = int(bit_index) % int(line_bits)
    if tag_bits > 0 and bit_in_line >= data_bits:
        return "ebc"
    byte_offset = bit_in_line // 8
    version_index = episode.get("byte_version_index", {})
    if not isinstance(version_index, Mapping):
        return "benign"
    version = _lookup_interval(version_index.get(int(byte_offset)), int(cycle))
    if version is None:
        return "benign"
    version_start = int_value(version.get("start_cycle"), 0)
    is_dirty = int_value(version.get("dirty"), 0) != 0
    end_reason = str(version.get("end_reason", "")).strip().lower()
    if is_dirty and end_reason == "evict":
        dcr_end = int_value(version.get("end_cycle"), version_start)
    else:
        dcr_end = int_value(version.get("last_load_cycle"), -1)
    return "dcr" if int(cycle) < int(dcr_end) and int(cycle) >= int(version_start) else "benign"


def _run_cache_campaign(
    state: Mapping[str, Any],
    *,
    campaign_runs: int,
    rng_seed: int,
) -> Dict[str, Any]:
    cycles, cumulative, total = state.get("cycle_sampler", ([0], [1], 1))
    rng = random.Random(int(rng_seed))
    counts = {"benign": 0, "dcr": 0, "ebc": 0}
    seed_choices = state.get("seed_choices", [0])
    if not isinstance(seed_choices, list) or not seed_choices:
        seed_choices = [0]
    per_seed_bits = max(1, int_value(state.get("domain_bits_per_seed"), 1))
    for _ in range(max(1, int(campaign_runs))):
        cycle = _sample_cycle(rng, list(cycles), list(cumulative), int(total))
        seed = int(seed_choices[rng.randrange(len(seed_choices))])
        bit_index = rng.randrange(per_seed_bits)
        counts[_classify_cache_fault(state, cycle=cycle, seed=seed, bit_index=bit_index)] += 1
    return {"counts": counts}


def _run_cache_all_fault_points(state: Mapping[str, Any]) -> Dict[str, Any]:
    _cycles, _cumulative, cycle_total = state.get("cycle_sampler", ([0], [1], 1))
    seed_choices = state.get("seed_choices", [0])
    if not isinstance(seed_choices, list) or not seed_choices:
        seed_choices = [0]
    per_seed_bits = max(1, int_value(state.get("domain_bits_per_seed"), 1))
    domain_points = int(cycle_total) * len(seed_choices) * int(per_seed_bits)
    data_bits = max(1, int_value(state.get("data_bits_per_line"), 8))
    tag_bits = max(0, int_value(state.get("tag_bits_per_line"), 0))

    dcr_bits = 0
    ebc_bits = 0
    slot_lookup = state.get("slot_lookup", {})
    if isinstance(slot_lookup, Mapping):
        for episode_index in slot_lookup.values():
            for episode, episode_end in _effective_entries(episode_index):
                episode_start = int_value(episode.get("start_cycle"), 0)
                if tag_bits > 0 and episode_end > episode_start:
                    ebc_bits += _cycle_weight_from_sampler(state.get("cycle_sampler"), episode_start, episode_end) * tag_bits
                version_lookup = episode.get("byte_version_index", {})
                if not isinstance(version_lookup, Mapping):
                    continue
                for byte_offset, version_index in version_lookup.items():
                    bits_in_byte = _valid_bits_for_byte(int_value(byte_offset, -1), data_bits)
                    if bits_in_byte <= 0:
                        continue
                    for version, version_end in _effective_entries(version_index):
                        version_start = int_value(version.get("start_cycle"), 0)
                        is_dirty = int_value(version.get("dirty"), 0) != 0
                        end_reason = str(version.get("end_reason", "")).strip().lower()
                        if is_dirty and end_reason == "evict":
                            dcr_end = int_value(version.get("end_cycle"), version_start)
                        else:
                            dcr_end = int_value(version.get("last_load_cycle"), -1)
                        start_cycle = max(version_start, episode_start)
                        end_cycle = min(int(version_end), int(episode_end), int(dcr_end))
                        if end_cycle <= start_cycle:
                            continue
                        dcr_bits += _cycle_weight_from_sampler(state.get("cycle_sampler"), start_cycle, end_cycle) * bits_in_byte

    dcr_bits = min(max(0, int(dcr_bits)), int(domain_points))
    ebc_bits = min(max(0, int(ebc_bits)), int(domain_points - dcr_bits))
    return {
        "counts": {
            "benign": int(domain_points - dcr_bits - ebc_bits),
            "dcr": int(dcr_bits),
            "ebc": int(ebc_bits),
        },
        "domain_points": int(domain_points),
    }


def _predict_cache_from_trace(
    *,
    analyzer_output: Mapping[str, Any],
    fi_sampling_space: Mapping[str, Any],
    trace_template: Mapping[str, Any],
    benchmark: str,
    test_id: str,
    component: str,
) -> Dict[str, Any]:
    state = _prepare_cache_campaign_state(
        analyzer_output=analyzer_output,
        fi_sampling_space=fi_sampling_space,
        trace_template=trace_template,
        component=component,
    )
    campaign_seed = _stable_campaign_seed(benchmark, test_id, component)
    if is_all_campaign_runs(GEREM_STORAGE_CAMPAIGN_RUNS):
        campaign = _run_cache_all_fault_points(state)
        campaign_runs = int(campaign["domain_points"])
        campaign_mode = "all"
    else:
        campaign = _run_cache_campaign(
            state,
            campaign_runs=int(GEREM_STORAGE_CAMPAIGN_RUNS),
            rng_seed=campaign_seed,
        )
        campaign_runs = max(1, int(GEREM_STORAGE_CAMPAIGN_RUNS))
        campaign_mode = "sample"
    counts = campaign["counts"]
    efm_rates = {
        "benign": float(counts["benign"]) / float(campaign_runs),
        "dcr": float(counts["dcr"]) / float(campaign_runs),
        "ebc": float(counts["ebc"]) / float(campaign_runs),
    }
    final_rates = {
        "masked": efm_rates["benign"] + efm_rates["ebc"],
        "sdc": efm_rates["dcr"],
        "due": 0.0,
    }
    return build_component_payload(
        benchmark=benchmark,
        test_id=test_id,
        component=component,
        den=float(state["denominator"]),
        efm_rates=efm_rates,
        final_rates=final_rates,
        meta={
            "observed_site_count": int(state["observed_site_count"]),
            "episode_count": int(state["episode_count"]),
            "touched_data_offsets": int(state["touched_data_offsets"]),
            "line_size_bytes": int(state["line_size_bytes"]),
            "tag_bits_per_line": int(state["tag_bits_per_line"]),
            "campaign_runs": int(campaign_runs),
            "campaign_mode": campaign_mode,
            "campaign_seed": int(campaign_seed),
            "rule": "cache_per_run_trace_efm_direct",
            "crash_policy": "due_forced_zero",
        },
    )


def _predict_cache_fallback(
    *,
    analyzer_output: Mapping[str, Any],
    fi_sampling_space: Mapping[str, Any],
    benchmark: str,
    test_id: str,
    component: str,
) -> Dict[str, Any]:
    row = _component_domain(fi_sampling_space, component)
    den = max(0.0, _float_value(row.get("domain_total_bits"), 0.0))
    tag_bits = max(0, int_value(row.get("tag_bits"), 0))
    line_size_bytes = max(1, int_value(row.get("line_size_bytes"), 128))
    data_bits_per_line = line_size_bytes * 8
    sites = _site_list(analyzer_output, component)

    observed_benign = 0.0
    observed_dcr = 0.0
    observed_ebc = 0.0
    class_counts = {"benign": 0, "dcr": 0, "ebc": 0}
    for record in sites:
        bits = float(_selected_bits(record))
        category = _classify_site_fallback(record, data_bits_per_line)
        class_counts[category] += 1
        if category == "benign":
            observed_benign += bits
        elif category == "ebc":
            observed_ebc += bits
        else:
            observed_dcr += bits

    observed_total = observed_benign + observed_dcr + observed_ebc
    benign = observed_benign + max(0.0, den - observed_total)
    benign, dcr, ebc = _clamp_counts(den, benign, observed_dcr, observed_ebc)
    return build_component_payload(
        benchmark=benchmark,
        test_id=test_id,
        component=component,
        den=den,
        efm_counts={"benign": benign, "dcr": dcr, "ebc": ebc},
        final_counts={"masked": benign + ebc, "sdc": dcr, "due": 0.0},
        meta={
            "observed_site_count": len(sites),
            "observed_bits_total": observed_total,
            "observed_class_sites": class_counts,
            "line_size_bytes": line_size_bytes,
            "tag_bits_per_line": tag_bits,
            "data_bits_per_line": data_bits_per_line,
            "rule": "cache_site_fallback",
            "crash_policy": "due_forced_zero",
        },
    )


def predict_cache(
    *,
    analyzer_output: Mapping[str, Any],
    fi_sampling_space: Mapping[str, Any],
    benchmark: str,
    test_id: str,
    component: str,
    trace_template: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    if not isinstance(trace_template, Mapping):
        raise ValueError("GEREM cache predictor requires trace_template events")
    return _predict_cache_from_trace(
        analyzer_output=analyzer_output,
        fi_sampling_space=fi_sampling_space,
        trace_template=trace_template,
        benchmark=benchmark,
        test_id=test_id,
        component=component,
    )


def _payload(
    analyzer_output: Mapping[str, Any],
    fi_sampling_space: Mapping[str, Any],
    benchmark: str,
    test_id: str,
    component: str,
    trace_template: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    return predict_cache(
        analyzer_output=analyzer_output,
        fi_sampling_space=fi_sampling_space,
        benchmark=benchmark,
        test_id=test_id,
        component=component,
        trace_template=trace_template,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", choices=("l1d", "l2"), required=True)
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--test-id", required=True)
    parser.add_argument("--analyzer-output", type=Path, default=None)
    parser.add_argument("--fi-sampling-space", type=Path, required=True)
    parser.add_argument("--trace-template", type=Path, default=None)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = build_arg_parser().parse_args(list(argv) if argv is not None else None)
    analyzer_output = load_json(args.analyzer_output) if args.analyzer_output is not None else {}
    fi_sampling_space = load_json(args.fi_sampling_space)
    trace_template = load_json(args.trace_template) if args.trace_template is not None else None
    payload = predict_cache(
        analyzer_output=analyzer_output,
        fi_sampling_space=fi_sampling_space,
        trace_template=trace_template,
        benchmark=args.benchmark,
        test_id=args.test_id,
        component=args.component,
    )
    write_json(args.output, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
