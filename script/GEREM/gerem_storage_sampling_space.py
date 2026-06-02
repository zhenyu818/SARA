#!/usr/bin/env python3
"""Build GEREM storage sampling-space metadata without exact-path helpers."""

from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: expected JSON object")
    return raw


def _load_app_info(path: Optional[Path]) -> Dict[str, str]:
    if path is None or not path.is_file():
        return {}
    out: Dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        out[key.strip()] = value.strip()
    return out


def _int_value(value: Any, default: int = 0) -> int:
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


def _read_register_count(path: Optional[Path]) -> int:
    if path is None or not path.is_file():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def _parse_trace_events(trace_template: Mapping[str, Any]) -> List[Dict[str, Any]]:
    raw_events = trace_template.get("events", [])
    if not isinstance(raw_events, list):
        return []
    out: List[Dict[str, Any]] = []
    for index, raw in enumerate(raw_events):
        if not isinstance(raw, Mapping):
            continue
        row = dict(raw)
        row.setdefault("event_index", int(index))
        out.append(row)
    return out


def _canonical_mem_space(raw: Any) -> Optional[str]:
    text = str(raw or "").strip().lower()
    if not text:
        return None
    if text in {"global", "gmem"} or "global" in text:
        return "global"
    if text in {"local", "lmem"} or "local" in text:
        return "local"
    if text in {"shared", "smem"} or "shared" in text or "smem" in text:
        return "shared"
    return text


def _parse_gpu_cycles(trace_log: Optional[Path], events: Sequence[Mapping[str, Any]]) -> int:
    if trace_log is not None and trace_log.is_file():
        pattern = re.compile(r"^gpu_(?:tot_)?sim_cycle\s*=\s*([0-9]+)")
        for raw in trace_log.read_text(encoding="utf-8", errors="replace").splitlines():
            match = pattern.search(raw.strip())
            if match:
                return max(1, int(match.group(1)))
    max_cycle = -1
    for index, raw in enumerate(events):
        cycle = _int_value(raw.get("cycle", index), index)
        if cycle > max_cycle:
            max_cycle = cycle
    return max(1, max_cycle + 1)


def _infer_trace_metrics(events: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    max_thread = -1
    max_warp = -1
    max_block = -1
    shared_seen = False
    l1d_shaders: List[int] = []
    seen_shader = set()
    unique_cycles = set()

    for index, raw in enumerate(events):
        cycle = _int_value(raw.get("cycle", index), index)
        unique_cycles.add(int(cycle))

        tid = _int_value(raw.get("thread_id"), -1)
        if tid > max_thread:
            max_thread = tid
        warp = _int_value(raw.get("warp_id"), -1)
        if warp > max_warp:
            max_warp = warp
        cta = _int_value(raw.get("cta_id"), -1)
        if cta > max_block:
            max_block = cta

        mem_space = _canonical_mem_space(raw.get("mem_space") or raw.get("space"))
        if mem_space == "shared":
            shared_seen = True
        if mem_space in {"global", "local"}:
            sm_id = _int_value(raw.get("sm_id"), -1)
            if sm_id >= 0 and sm_id not in seen_shader:
                seen_shader.add(sm_id)
                l1d_shaders.append(sm_id)

    l1d_shaders.sort()
    return {
        "thread_rand_max": max(1, max_thread + 1),
        "warp_rand_max": max(1, max_warp + 1),
        "block_rand_max": max(1, max_block + 1),
        "shared_seen": bool(shared_seen),
        "l1d_shaders": l1d_shaders,
        "l1d_shader_count": len(l1d_shaders),
        "cycle_unique_count": len(unique_cycles),
    }


def _get_app_int(app_info: Mapping[str, str], key: str) -> int:
    raw = str(app_info.get(key, "")).strip()
    return _int_value(raw, 0)


def _normalize_shader_spec(raw: str) -> List[int]:
    out: List[int] = []
    seen = set()
    normalized = raw.replace(",", " ").replace(":", " ")
    for token in normalized.split():
        try:
            value = int(token, 0)
        except Exception:
            continue
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    out.sort()
    return out


def _config_line(config_text: str, opt: str) -> str:
    for raw in config_text.splitlines():
        parts = raw.split()
        if len(parts) >= 2 and parts[0] == opt:
            return raw.strip()
    return ""


def _config_numeric(config_text: str, opt: str, default: int = 0) -> int:
    line = _config_line(config_text, opt)
    parts = line.split()
    if len(parts) >= 2:
        return _int_value(parts[1], default)
    return int(default)


def _parse_cache_geom(config_text: str, opt: str) -> Tuple[int, int, int]:
    line = _config_line(config_text, opt)
    match = re.search(r"[SN]:(\d+):(\d+):(\d+)", line)
    if not match:
        return (0, 0, 0)
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def _derive_tag_bits(nset: int, line_size_bytes: int, addr_bits: int = 64) -> int:
    if nset <= 0 or line_size_bytes <= 0:
        return 0
    offset_bits = int(math.log2(line_size_bytes)) if line_size_bytes > 0 else 0
    index_bits = int(math.log2(nset)) if nset > 0 else 0
    return max(0, int(addr_bits) - offset_bits - index_bits)


def _cache_bits(nset: int, line_size_bytes: int, assoc: int, tag_bits: int) -> int:
    if nset <= 0 or line_size_bytes <= 0 or assoc <= 0 or tag_bits < 0:
        return 0
    per_line_bits = line_size_bytes * 8 + tag_bits
    return max(0, nset * assoc * per_line_bits)


def _l2_total_bits(config_text: str, tag_bits: int) -> int:
    nset, line_size, assoc = _parse_cache_geom(config_text, "-gpgpu_cache:dl2")
    n_mem = _config_numeric(config_text, "-gpgpu_n_mem", 1)
    n_sub = _config_numeric(config_text, "-gpgpu_n_sub_partition_per_mchannel", 1)
    per_bank_bits = _cache_bits(nset, line_size, assoc, tag_bits)
    return max(0, per_bank_bits * max(1, n_mem) * max(1, n_sub))


def _detect_l1d_write_allocate(config_text: str) -> int:
    line = _config_line(config_text, "-gpgpu_cache:dl1")
    match = re.search(r",[A-Z]:[A-Z]:[a-zA-Z]:([A-Z]):[A-Z]", line)
    if not match:
        return 0
    return 0 if match.group(1) == "N" else 1


def _l2_global_prefill(config_text: str) -> int:
    return 1 if _config_numeric(config_text, "-gpgpu_perf_sim_memcpy", 0) > 0 else 0


def _write_cycles_file(path: Path, total_cycles: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if total_cycles <= 0:
        total_cycles = 1
    with path.open("w", encoding="utf-8") as handle:
        for cycle in range(total_cycles):
            handle.write(f"{cycle}\n")


def build_sampling_space(
    *,
    trace_template: Mapping[str, Any],
    trace_log: Optional[Path],
    config_path: Path,
    app_info_path: Optional[Path],
    register_domain_source: Path,
    cycles_file: Path,
) -> Dict[str, Any]:
    config_text = config_path.read_text(encoding="utf-8", errors="replace") if config_path.is_file() else ""
    app_info = _load_app_info(app_info_path)
    events = _parse_trace_events(trace_template)
    trace_metrics = _infer_trace_metrics(events)
    cycle_total = _parse_gpu_cycles(trace_log, events)
    _write_cycles_file(cycles_file, cycle_total)

    datatype_bits = _get_app_int(app_info, "DATATYPE_SIZE") or 32
    register_count = _read_register_count(register_domain_source)
    thread_rand_max = trace_metrics["thread_rand_max"]
    warp_rand_max = trace_metrics["warp_rand_max"]
    block_rand_max = trace_metrics["block_rand_max"]

    shared_seen = trace_metrics["shared_seen"]
    smem_size_bits = _get_app_int(app_info, "SMEM_SIZE_BITS")
    if not shared_seen:
        smem_size_bits = 0
    if shared_seen and smem_size_bits <= 0:
        smem_size_bits = 1

    campaign_l1d_bits = _get_app_int(app_info, "L1D_SIZE_BITS")
    campaign_l2_bits = _get_app_int(app_info, "L2_SIZE_BITS")
    campaign_cache_tag_bits = _get_app_int(app_info, "CACHE_TAG_ARRAY_BITS")
    campaign_l1d_line = _get_app_int(app_info, "L1D_LINE_SIZE_BYTES")
    campaign_l2_line = _get_app_int(app_info, "L2_LINE_SIZE_BYTES")

    l1d_nset, l1d_line_size, l1d_assoc = _parse_cache_geom(config_text, "-gpgpu_cache:dl1")
    l2_nset, l2_line_size, l2_assoc = _parse_cache_geom(config_text, "-gpgpu_cache:dl2")
    l1d_line_size = campaign_l1d_line or l1d_line_size or 128
    l2_line_size = campaign_l2_line or l2_line_size or 128
    cache_tag_bits = campaign_cache_tag_bits or _derive_tag_bits(l1d_nset, l1d_line_size)
    l1d_size_bits = campaign_l1d_bits or _cache_bits(l1d_nset, l1d_line_size, l1d_assoc, cache_tag_bits)
    l2_size_bits = campaign_l2_bits or _l2_total_bits(config_text, cache_tag_bits)

    shader_spec = _normalize_shader_spec(app_info.get("SHADER_USED", ""))
    l1d_shaders = shader_spec or trace_metrics["l1d_shaders"]
    l1d_shader_count = len(l1d_shaders)

    rf_domain_per_seed_bits = register_count * datatype_bits
    smem_domain_per_seed_bits = smem_size_bits
    l1d_domain_per_seed_bits = l1d_size_bits
    l2_domain_per_seed_bits = l2_size_bits

    return {
        "cycles_file": str(cycles_file.resolve()),
        "cycles_source_file": str(cycles_file.resolve()),
        "cycle_total_multiplicity": int(cycle_total),
        "cycle_unique_count": int(cycle_total),
        "thread_rand_max": int(thread_rand_max),
        "warp_rand_max": int(warp_rand_max),
        "block_rand_max": int(block_rand_max),
        "datatype_bits": int(datatype_bits),
        "register_domain_source": str(register_domain_source.resolve()),
        "register_count": int(register_count),
        "smem_size_bits": int(smem_size_bits),
        "l1d_size_bits": int(l1d_size_bits),
        "l2_size_bits": int(l2_size_bits),
        "l1d_line_size_bytes": int(l1d_line_size),
        "l2_line_size_bytes": int(l2_line_size),
        "l2_global_prefill": int(_l2_global_prefill(config_text)),
        "l1d_write_allocate": int(_detect_l1d_write_allocate(config_text)),
        "l1d_nset": int(l1d_nset),
        "l1d_assoc": int(l1d_assoc),
        "l2_nset": int(l2_nset),
        "l2_assoc": int(l2_assoc),
        "cache_tag_bits": int(cache_tag_bits),
        "l1d_tag_bits": int(cache_tag_bits),
        "l2_tag_bits": int(cache_tag_bits),
        "l1d_include_tag_bits": 1,
        "l2_include_tag_bits": 1,
        "l1d_shaders": ":".join(str(value) for value in l1d_shaders),
        "l1d_shaders_mode": "trace_or_app_info",
        "l1d_shader_count": int(l1d_shader_count),
        "active_sm_count": int(l1d_shader_count),
        "rf_domain_total_bits": int(cycle_total * thread_rand_max * rf_domain_per_seed_bits),
        "smem_rf_domain_total_bits": int(cycle_total * block_rand_max * smem_domain_per_seed_bits),
        "l1d_domain_total_bits": int(cycle_total * max(1, l1d_shader_count) * l1d_domain_per_seed_bits),
        "l2_domain_total_bits": int(cycle_total * l2_domain_per_seed_bits),
        "inject_bit_flip_count": 1,
        "per_warp": 0,
        "component_domains": {
            "rf": {
                "domain_bits_per_seed": int(rf_domain_per_seed_bits),
                "domain_total_bits": int(cycle_total * thread_rand_max * rf_domain_per_seed_bits),
                "seed_domain_size": int(thread_rand_max),
            },
            "smem_rf": {
                "domain_bits_per_seed": int(smem_domain_per_seed_bits),
                "domain_total_bits": int(cycle_total * block_rand_max * smem_domain_per_seed_bits),
                "seed_domain_size": int(block_rand_max),
            },
            "l1d": {
                "domain_bits_per_seed": int(l1d_domain_per_seed_bits),
                "domain_total_bits": int(cycle_total * max(1, l1d_shader_count) * l1d_domain_per_seed_bits),
                "shader_count": int(l1d_shader_count),
                "shaders": list(l1d_shaders),
                "include_tag_bits": 1,
                "tag_bits": int(cache_tag_bits),
                "line_size_bytes": int(l1d_line_size),
                "nset": int(l1d_nset),
                "assoc": int(l1d_assoc),
                "write_allocate": int(_detect_l1d_write_allocate(config_text)),
            },
            "l2": {
                "domain_bits_per_seed": int(l2_domain_per_seed_bits),
                "domain_total_bits": int(cycle_total * l2_domain_per_seed_bits),
                "include_tag_bits": 1,
                "tag_bits": int(cache_tag_bits),
                "line_size_bytes": int(l2_line_size),
                "nset": int(l2_nset),
                "assoc": int(l2_assoc),
            },
        },
        "source_priority": {
            "cycles_file": "trace_capture_log",
            "thread_rand_max": "trace_template",
            "warp_rand_max": "trace_template",
            "block_rand_max": "trace_template",
            "datatype_bits": "app_info_or_default",
            "smem_size_bits": "app_info_with_trace_presence_guard",
            "cache_tag_bits": "app_info_or_config",
            "l1d_size_bits": "app_info_or_config",
            "l2_size_bits": "app_info_or_config",
            "l1d_line_size_bytes": "app_info_or_config",
            "l2_line_size_bytes": "app_info_or_config",
            "l1d_shaders": "app_info_or_trace",
        },
        "app_info_file": str(app_info_path.resolve()) if app_info_path is not None else "",
        "config_file": str(config_path.resolve()),
        "trace_log_file": str(trace_log.resolve()) if trace_log is not None else "",
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace-template", type=Path, required=True)
    parser.add_argument("--trace-log", type=Path, required=False, default=None)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--app-info", type=Path, required=False, default=None)
    parser.add_argument("--register-domain-source", type=Path, required=True)
    parser.add_argument("--cycles-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    trace_template = _load_json(args.trace_template)
    payload = build_sampling_space(
        trace_template=trace_template,
        trace_log=args.trace_log,
        config_path=args.config,
        app_info_path=args.app_info,
        register_domain_source=args.register_domain_source,
        cycles_file=args.cycles_file,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
