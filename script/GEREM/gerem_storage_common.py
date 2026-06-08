#!/usr/bin/env python3
"""Shared helpers for GEREM storage prediction/reporting."""

from __future__ import annotations

import bisect
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


MASK_FIELD_CANDIDATES: Tuple[str, ...] = (
    "observed_mask_this_read",
    "observed_mask_this_site",
    "due_mask_this_read",
    "due_mask_this_site",
    "trace_expanding_mask_this_read",
    "trace_expanding_mask_this_site",
    "replay_masked_mask_this_read",
    "replay_masked_mask_this_site",
    "replay_sdc_mask_this_read",
    "replay_sdc_mask_this_site",
    "replay_due_mask_this_read",
    "replay_due_mask_this_site",
)


def load_json(path: Union[str, Path]) -> Dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as f:
        raw = json.load(f)
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: expected top-level JSON object")
    return raw


def write_json(path: Union[str, Path], payload: Dict[str, Any]) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_suffix(out_path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")
    tmp_path.replace(out_path)


def int_mask(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return 0
        return int(text, 0)
    return 0


def int_value(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return int(default)
        return int(text, 0)
    return int(default)


def positive_int_env(name: str, default: int) -> int:
    """Return a positive integer from an environment variable.

    GEREM fixed-campaign validation is layered in ``campaign_runs_env`` below;
    this helper remains generic for other positive integer environment values.
    """
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return int(default)
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer, got {raw!r}") from exc
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer, got {raw!r}")
    return value


GEREM_ALLOWED_CAMPAIGN_RUNS: Tuple[int, ...] = (1000, 5000, 10000)


def campaign_runs_env(name: str, default: int) -> int:
    """Return the GEREM storage-EFM random-sampling campaign count.

    The public GEREM path intentionally supports only fixed random sample
    counts used for storage-component EFM replication. Exhaustive ``all`` mode
    and ad-hoc counts are rejected so the result metadata always describes a
    sampled GEREM-1000/5000/10000 campaign.
    """
    default_value = int(default)
    if default_value not in GEREM_ALLOWED_CAMPAIGN_RUNS:
        default_value = GEREM_ALLOWED_CAMPAIGN_RUNS[0]
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default_value
    if raw.strip().lower() in {"all", "exhaustive", "full"}:
        raise ValueError(f"{name} no longer supports exhaustive/all mode; choose one of {GEREM_ALLOWED_CAMPAIGN_RUNS}")
    value = positive_int_env(name, default_value)
    if value not in GEREM_ALLOWED_CAMPAIGN_RUNS:
        allowed = ", ".join(str(item) for item in GEREM_ALLOWED_CAMPAIGN_RUNS)
        raise ValueError(f"{name} must be one of {allowed}, got {raw!r}")
    return int(value)


def bit_count(value: int) -> int:
    value_i = int(value)
    try:
        return value_i.bit_count()
    except AttributeError:
        return bin(value_i & ((1 << max(1, value_i.bit_length())) - 1)).count("1")


def classify_bit_masks(record: Dict[str, Any], width_bits: int) -> Tuple[int, int]:
    """Return (dcr_bits, benign_bits) for a record based on analyzer masks."""
    if width_bits <= 0:
        return (0, 0)
    width_bits = min(int(width_bits), 64)
    live_mask = 0
    for field in MASK_FIELD_CANDIDATES:
        live_mask |= int_mask(record.get(field, 0))
    if width_bits < 64:
        live_mask &= (1 << width_bits) - 1
    dcr_bits = bit_count(live_mask)
    benign_bits = max(0, width_bits - dcr_bits)
    return dcr_bits, benign_bits


def canonical_mem_space(raw: Any) -> Optional[str]:
    text = str(raw or "").strip().lower()
    if not text:
        return None
    if text in {"global", "gmem"} or "global" in text:
        return "global"
    if text in {"local", "lmem"} or "local" in text:
        return "local"
    if text in {"shared", "smem", "lds"} or "shared" in text or "smem" in text:
        return "shared"
    if text in {"const", "constant"} or "const" in text:
        return "const"
    if text == "param":
        return "param"
    return text


def access_size_bytes_for_raw_event(raw: Mapping[str, Any]) -> int:
    for key in ("mem_access_size_bytes", "store_size_bytes", "size_bytes", "size"):
        if key in raw:
            size = int_value(raw.get(key), 0)
            if size > 0:
                return size
    width_bits = int_value(raw.get("width_bits"), 0)
    if width_bits > 0:
        return max(1, (width_bits + 7) // 8)
    return 1


def load_cycle_rows(
    fi_sampling_space: Mapping[str, Any],
    trace_template: Optional[Mapping[str, Any]] = None,
) -> List[Tuple[int, int]]:
    def _from_json_list(raw: Any) -> List[Tuple[int, int]]:
        rows: List[Tuple[int, int]] = []
        items = raw.get("cycles") if isinstance(raw, dict) and "cycles" in raw else raw
        if not isinstance(items, list):
            return rows
        for item in items:
            if isinstance(item, dict):
                if "cycle" not in item:
                    continue
                cycle = int_value(item.get("cycle"), 0)
                multiplicity = int_value(item.get("multiplicity"), 1)
            elif isinstance(item, list) and item:
                cycle = int_value(item[0], 0)
                multiplicity = int_value(item[2], 1) if len(item) >= 3 else 1
            else:
                continue
            if multiplicity <= 0:
                continue
            rows.append((int(cycle), int(multiplicity)))
        return rows

    cycle_rows: List[Tuple[int, int]] = []
    cycles_file = str(fi_sampling_space.get("cycles_file", "") or "").strip()
    if cycles_file:
        path = Path(cycles_file).expanduser()
        if path.is_file():
            if path.suffix.lower() == ".json":
                raw = json.loads(path.read_text(encoding="utf-8"))
                cycle_rows = _from_json_list(raw)
            else:
                per_cycle: Dict[int, int] = {}
                for line in path.read_text(encoding="utf-8").splitlines():
                    text = line.strip()
                    if not text or text.startswith("#"):
                        continue
                    cycle = int_value(text.split()[0], 0)
                    per_cycle[cycle] = int(per_cycle.get(cycle, 0)) + 1
                cycle_rows = sorted((int(cycle), int(mult)) for cycle, mult in per_cycle.items())

    if not cycle_rows and isinstance(trace_template, Mapping):
        events = trace_template.get("events", [])
        per_cycle: Dict[int, int] = {}
        if isinstance(events, list):
            for index, raw in enumerate(events):
                if not isinstance(raw, Mapping):
                    continue
                cycle = int_value(raw.get("cycle", index), index)
                per_cycle[cycle] = max(1, int(per_cycle.get(cycle, 0)))
        cycle_rows = sorted((int(cycle), int(mult)) for cycle, mult in per_cycle.items())

    if not cycle_rows:
        total = int_value(fi_sampling_space.get("cycle_total_multiplicity"), 0)
        unique = int_value(fi_sampling_space.get("cycle_unique_count"), total)
        if total > 0 and unique > 0:
            cycle_rows = [(idx, 1) for idx in range(min(total, unique))]
            remainder = total - len(cycle_rows)
            if remainder > 0 and cycle_rows:
                last_cycle, last_mult = cycle_rows[-1]
                cycle_rows[-1] = (int(last_cycle), int(last_mult + remainder))

    if not cycle_rows:
        return [(0, 1)]
    merged: Dict[int, int] = {}
    for cycle, mult in cycle_rows:
        merged[int(cycle)] = int(merged.get(int(cycle), 0)) + max(0, int(mult))
    return sorted((int(cycle), int(mult)) for cycle, mult in merged.items() if int(mult) > 0)


def build_cycle_prefix(cycle_rows: Sequence[Tuple[int, int]]) -> Tuple[List[int], List[int], int]:
    cycles = [int(cycle) for cycle, _mult in cycle_rows]
    prefix = [0]
    total = 0
    for _cycle, multiplicity in cycle_rows:
        total += max(0, int(multiplicity))
        prefix.append(total)
    return cycles, prefix, int(total)


def cycle_weight_between(
    cycles: Sequence[int],
    prefix: Sequence[int],
    start_cycle: int,
    end_cycle: int,
) -> int:
    if end_cycle <= start_cycle or not cycles:
        return 0
    lo = bisect.bisect_left(cycles, int(start_cycle))
    hi = bisect.bisect_left(cycles, int(end_cycle))
    return int(prefix[hi] - prefix[lo])


def cycle_domain_bounds(cycle_rows: Sequence[Tuple[int, int]]) -> Tuple[int, int]:
    if not cycle_rows:
        return (0, 1)
    start = int(cycle_rows[0][0])
    end = int(cycle_rows[-1][0]) + 1
    return (start, end)


def normalize_rates(counts: Dict[str, int], total_key: str = "total") -> Dict[str, float]:
    total = int(counts.get(total_key, 0))
    if total <= 0:
        return {k: 0.0 for k in counts if k != total_key}
    return {
        key: (float(value) / float(total))
        for key, value in counts.items()
        if key != total_key
    }


def _normalize_numeric_map(
    raw: Optional[Mapping[str, Any]],
    ordered_keys: Iterable[str],
) -> Dict[str, float]:
    keys = list(ordered_keys)
    out: Dict[str, float] = {key: 0.0 for key in keys}
    if not isinstance(raw, Mapping):
        return out
    for key in keys:
        value = raw.get(key, 0.0)
        if isinstance(value, (int, float)):
            out[key] = float(value)
        elif isinstance(value, str) and value.strip():
            out[key] = float(value)
    return out


def rates_from_counts(counts: Mapping[str, Any], denominator: float) -> Dict[str, float]:
    den = float(denominator)
    if den <= 0.0:
        return {str(key): 0.0 for key in counts.keys()}
    return {
        str(key): float(value) / den
        for key, value in counts.items()
    }


def build_component_payload(
    *,
    benchmark: str,
    test_id: str,
    component: str,
    den: Optional[float] = None,
    denominator: Optional[float] = None,
    efm_counts: Optional[Mapping[str, Any]] = None,
    efm_rates: Optional[Mapping[str, Any]] = None,
    final_counts: Optional[Mapping[str, Any]] = None,
    final_rates: Optional[Mapping[str, Any]] = None,
    meta: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    den_value = float(den if den is not None else (denominator if denominator is not None else 0.0))
    den_value = max(0.0, den_value)
    efm_keys = ("benign", "dcr", "ebc")
    final_keys = ("masked", "sdc", "due")

    efm_counts_norm = _normalize_numeric_map(efm_counts, efm_keys)
    final_counts_norm = _normalize_numeric_map(final_counts, final_keys)

    if not any(efm_counts_norm.values()) and isinstance(efm_rates, Mapping):
        efm_rates_norm = _normalize_numeric_map(efm_rates, efm_keys)
        efm_counts_norm = {key: den_value * efm_rates_norm[key] for key in efm_keys}
    if not any(final_counts_norm.values()) and isinstance(final_rates, Mapping):
        final_rates_norm = _normalize_numeric_map(final_rates, final_keys)
        final_counts_norm = {key: den_value * final_rates_norm[key] for key in final_keys}

    payload = {
        "benchmark": str(benchmark),
        "test_id": str(test_id),
        "component": str(component),
        "den": den_value,
        "efm_counts": efm_counts_norm,
        "efm_rates": rates_from_counts(efm_counts_norm, den_value),
        "final_counts": final_counts_norm,
        "final_rates": rates_from_counts(final_counts_norm, den_value),
        "meta": dict(meta or {}),
    }
    return payload


def component_domain(fi_sampling_space: Dict[str, Any], component: str) -> Dict[str, Any]:
    domains = fi_sampling_space.get("component_domains", {})
    if not isinstance(domains, dict):
        return {}
    row = domains.get(component, {})
    return row if isinstance(row, dict) else {}


def component_denominator(fi_sampling_space: Mapping[str, Any], component: str, fallback: float = 0.0) -> float:
    row = component_domain(dict(fi_sampling_space), component)
    raw = row.get("domain_total_bits", fallback)
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str) and raw.strip():
        return float(raw)
    return float(fallback)
