#!/usr/bin/env python3
"""Compose analyzer input JSON from trace template + gpuFI4 run artifacts."""

import argparse
import gzip
import json
import os
import pickle
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

U64_MASK = (1 << 64) - 1
_EVENT_INT_FIELDS = {
    "thread_id",
    "width_bits",
    "dst_reg_uid",
    "dst_val",
    "dst_old_val",
    "dst_write_mask",
    "mem_addr",
    "base",
    "mem_addr_effective_bits",
    "mem_addr_mask",
    "mem_access_size_bytes",
    "size",
    "store_size_bytes",
    "store_data_src_index",
    "store_data_byte_offset",
    "ea_const_offset",
    "ea_width_bits",
    "cycle",
    "sm_id",
    "cta_id",
    "warp_id",
    "control_const_offset",
}
_EVENT_KEEP_FIELDS = (
    "thread_id",
    "kind",
    "pc",
    "opcode",
    "width_bits",
    "src_regs",
    "src_vals",
    "src_width_bits",
    "src_reg_uids",
    "dst_reg",
    "dst_reg_uid",
    "dst_val",
    "dst_old_val",
    "dst_write_mask",
    "pred",
    "mem_space",
    "space",
    "mem_addr",
    "base",
    "mem_addr_effective_bits",
    "mem_addr_mask",
    "mem_access_size_bytes",
    "size",
    "store_size_bytes",
    "store_data_src_index",
    "store_data_byte_offset",
    "is_output_store",
    "ea_base_src_indices",
    "ea_const_offset",
    "ea_width_bits",
    "ea_expr",
    "address_observed",
    "cycle",
    "sm_id",
    "cta_id",
    "warp_id",
    "control_expr",
    "control_const_offset",
    "branch_taken",
    "next_pc",
    "observed_next_pc",
    "taken_target_pc",
    "fallthrough_pc",
    "branch_target_pc",
    "target_pc",
)


def _compact_int_value(value: Any) -> Any:
    try:
        return _parse_int(value)
    except Exception:
        return value


def _compact_int_list(value: Any) -> Any:
    if not isinstance(value, list):
        return value
    return [_compact_int_value(item) for item in value]


def _compact_pred(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    out: Dict[str, Any] = {}
    if value.get("reg") is not None:
        out["reg"] = str(value.get("reg"))
    if value.get("val") is not None:
        out["val"] = _compact_int_value(value.get("val"))
    if value.get("uid") is not None:
        out["uid"] = _compact_int_value(value.get("uid"))
    return out


def _compact_event_for_analyzer(event: Any) -> Any:
    """Drop trace fields unused by analyzer input without changing semantics."""

    if not isinstance(event, dict):
        return event

    out: Dict[str, Any] = {}
    for key in _EVENT_KEEP_FIELDS:
        if key not in event:
            continue
        value = event.get(key)
        if value is None:
            continue
        if key in _EVENT_INT_FIELDS:
            value = _compact_int_value(value)
        elif key in ("src_vals", "src_width_bits", "src_reg_uids", "ea_base_src_indices"):
            value = _compact_int_list(value)
        elif key == "pred":
            value = _compact_pred(value)
        out[key] = value
    return out


def _env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    token = str(raw).strip().lower()
    if token in ("1", "true", "yes", "on", "y"):
        return True
    if token in ("0", "false", "no", "off", "n"):
        return False
    return bool(default)


try:
    import orjson as _orjson  # type: ignore
except Exception:
    _orjson = None

try:
    import zstandard as _zstd  # type: ignore
except Exception:
    _zstd = None


def _json_load_path(path: Path) -> Any:
    raw = path.read_bytes()
    if len(raw) >= 2 and raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    elif len(raw) >= 4 and raw[:4] == b"\x28\xb5\x2f\xfd":
        if _zstd is None:
            raise RuntimeError(
                f"{path}: zstd-compressed JSON requires python package 'zstandard'"
            )
        raw = _zstd.ZstdDecompressor().decompress(raw)
    if _orjson is not None:
        return _orjson.loads(raw)
    return json.loads(raw.decode("utf-8"))


def _json_dump_path(path: Path, obj: Any) -> None:
    raw: bytes
    if _orjson is not None:
        flags = 0
        append_newline_opt = getattr(_orjson, "OPT_APPEND_NEWLINE", 0)
        if isinstance(append_newline_opt, int):
            flags |= append_newline_opt
        raw = _orjson.dumps(obj, option=flags)
    else:
        raw = (
            json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            + b"\n"
        )

    if path.suffix.lower() == ".gz":
        level = int(os.environ.get("EXACT_SDC_JSON_GZIP_LEVEL", "3"))
        raw = gzip.compress(raw, compresslevel=max(1, min(9, level)))
    elif path.suffix.lower() == ".zst":
        if _zstd is None:
            raise RuntimeError(
                f"{path}: zstd JSON output requires python package 'zstandard'"
            )
        level = int(os.environ.get("EXACT_SDC_JSON_ZSTD_LEVEL", "6"))
        raw = _zstd.ZstdCompressor(level=level).compress(raw)
    path.write_bytes(raw)


def _manifest_relpath(path: Path, *, base_dir: Path) -> str:
    try:
        return os.path.relpath(str(path.resolve()), str(base_dir.resolve()))
    except Exception:
        return str(path)


def _binary_analyzer_input_sidecar_path(output_path: Path) -> Path:
    return Path(str(output_path) + ".bin")


def _columnar_analyzer_input_sidecar_path(output_path: Path) -> Path:
    return Path(str(output_path) + ".events.col.pkl")


_COLUMNAR_ANALYZER_EVENT_KEYS = (
    "thread_id",
    "kind",
    "pc",
    "opcode",
    "width_bits",
    "src_regs",
    "src_vals",
    "src_width_bits",
    "src_reg_uids",
    "dst_reg",
    "dst_reg_uid",
    "dst_val",
    "dst_old_val",
    "dst_write_mask",
    "pred",
    "mem_addr",
    "base",
    "mem_space",
    "space",
    "mem_addr_effective_bits",
    "mem_addr_mask",
    "mem_access_size_bytes",
    "size",
    "store_size_bytes",
    "store_data_src_index",
    "store_data_byte_offset",
    "is_output_store",
    "ea_base_src_indices",
    "ea_const_offset",
    "ea_width_bits",
    "ea_expr",
    "control_expr",
    "control_const_offset",
    "branch_taken",
    "next_pc",
    "observed_next_pc",
    "taken_target_pc",
    "fallthrough_pc",
    "branch_target_pc",
    "target_pc",
    "address_observed",
    "cycle",
    "sm_id",
    "cta_id",
    "warp_id",
)


def _events_to_columnar_payload(events: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(events, list):
        return None
    rows = [raw if isinstance(raw, dict) else {} for raw in events]
    columns: Dict[str, List[Any]] = {}
    keys: List[str] = []
    for key in _COLUMNAR_ANALYZER_EVENT_KEYS:
        col = [row.get(key) for row in rows]
        # All-null columns are absent in legacy dict rows too. Omitting them keeps
        # the columnar trace genuinely sparse and avoids serializing placeholder values.
        if any(value is not None for value in col):
            columns[key] = col
            keys.append(key)
    return {
        "format": "exact_sdc_analyzer_events_columnar_v1",
        "count": int(len(events)),
        "keys": keys,
        "columns": columns,
    }


def _write_binary_analyzer_input(output_path: Path, payload: Dict[str, Any]) -> None:
    """Write analyzer input as a binary sidecar plus a tiny JSON manifest."""

    events = payload.get("events", [])
    memory_ranges = payload.get("memory_ranges", [])
    output_spec = payload.get("output_spec", [])
    manifest: Dict[str, Any] = {
        "manifest_kind": "exact_sdc_analyzer_input_binary_v1",
        "events_count": len(events) if isinstance(events, list) else None,
        "memory_ranges_count": (
            len(memory_ranges) if isinstance(memory_ranges, list) else None
        ),
        "memory_ranges": memory_ranges if isinstance(memory_ranges, list) else [],
        "output_spec": output_spec if isinstance(output_spec, list) else [],
    }
    compat_dict_enabled = (
        os.environ.get("ANALYZER_INPUT_COMPAT_PICKLE_DICT", "1").strip().lower()
        not in ("0", "false", "no", "off")
    )
    if compat_dict_enabled:
        sidecar_path = _binary_analyzer_input_sidecar_path(output_path)
        sidecar_path.write_bytes(pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL))
        manifest["binary_format"] = "pickle_dict_v1"
        manifest["binary_ref"] = _manifest_relpath(
            sidecar_path,
            base_dir=output_path.parent,
        )
    else:
        try:
            _binary_analyzer_input_sidecar_path(output_path).unlink()
        except FileNotFoundError:
            pass
    columnar_enabled = os.environ.get("ANALYZER_INPUT_COLUMNAR", "1").strip().lower()
    if columnar_enabled not in ("0", "false", "no", "off"):
        columnar_payload = _events_to_columnar_payload(events)
        if columnar_payload is not None:
            columnar_path = _columnar_analyzer_input_sidecar_path(output_path)
            columnar_path.write_bytes(
                pickle.dumps(columnar_payload, protocol=pickle.HIGHEST_PROTOCOL)
            )
            manifest["columnar_format"] = "pickle_events_columnar_v1"
            manifest["columnar_ref"] = _manifest_relpath(
                columnar_path,
                base_dir=output_path.parent,
            )
    else:
        try:
            _columnar_analyzer_input_sidecar_path(output_path).unlink()
        except FileNotFoundError:
            pass
    _json_dump_path(output_path, manifest)


def _load_json(path: Path) -> Any:
    try:
        return _json_load_path(path)
    except Exception:
        text = path.read_text(encoding="utf-8")
        rows: List[Any] = []
        for i, line in enumerate(text.splitlines()):
            s = line.strip()
            if not s:
                continue
            try:
                rows.append(json.loads(s))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{path}: invalid JSONL at line {i+1}: {exc}"
                ) from exc
        return rows


def _extract_memory_ranges(raw: Any, source: Path) -> List[Dict[str, Any]]:
    if isinstance(raw, list):
        return list(raw)
    if isinstance(raw, dict):
        ranges = raw.get("memory_ranges")
        if isinstance(ranges, list):
            return list(ranges)
        raise ValueError(f"{source}: object sidecar must contain list field 'memory_ranges'")
    raise ValueError(f"{source}: memory range sidecar must be a list or object")


def _load_sidecar_memory_ranges(trace_path: Path) -> Optional[List[Dict[str, Any]]]:
    sidecar = Path(str(trace_path) + ".memory_ranges.json")
    if not sidecar.exists():
        return None
    return _extract_memory_ranges(_load_json(sidecar), sidecar)


def _parse_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def _load_trace_template(path: Path) -> Dict[str, Any]:
    raw = _load_json(path)
    if isinstance(raw, list):
        out: Dict[str, Any] = {"events": raw}
        sidecar_ranges = _load_sidecar_memory_ranges(path)
        if sidecar_ranges is not None:
            out["memory_ranges"] = sidecar_ranges
        return out
    if isinstance(raw, dict):
        out: Dict[str, Any] = {}
        if "events" in raw:
            out["events"] = raw["events"]
        elif "trace" in raw:
            out["events"] = raw["trace"]
        else:
            raise ValueError(
                f"{path}: template object must contain 'events' or 'trace'"
            )
        if "memory_ranges" in raw and isinstance(raw["memory_ranges"], list):
            out["memory_ranges"] = list(raw["memory_ranges"])
        elif "memory_ranges" in raw:
            raise ValueError(f"{path}: 'memory_ranges' must be a list when present")
        if "memory_ranges" not in out:
            sidecar_ranges = _load_sidecar_memory_ranges(path)
            if sidecar_ranges is not None:
                out["memory_ranges"] = sidecar_ranges
        return out
    raise ValueError(f"{path}: unsupported JSON type {type(raw)}")


def _parse_output_ranges(path: Path) -> List[Dict[str, Any]]:
    raw = _load_json(path)
    if not isinstance(raw, list):
        raise ValueError(f"{path}: output spec must be a list")
    ranges: List[Dict[str, Any]] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"{path}: output spec entry #{i} is not an object")
        if "base" not in item or "bytes" not in item:
            raise ValueError(f"{path}: output spec entry #{i} missing base/bytes")
        base = item["base"]
        size = int(item["bytes"])
        base_int = int(base, 0) if isinstance(base, str) else int(base)
        if size <= 0:
            continue
        ranges.append(
            {
                "space": "global",
                "base": base_int,
                "size": size,
            }
        )
    return ranges


def _parse_output_spec_entries(path: Path) -> List[Dict[str, Any]]:
    raw = _load_json(path)
    if not isinstance(raw, list):
        raise ValueError(f"{path}: output spec must be a list")

    out: List[Dict[str, Any]] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"{path}: output spec entry #{i} is not an object")
        if "base" not in item or "bytes" not in item:
            raise ValueError(f"{path}: output spec entry #{i} missing base/bytes")

        size = int(item["bytes"])
        if size <= 0:
            continue
        base_int = int(item["base"], 0) if isinstance(item["base"], str) else int(item["base"])
        entry: Dict[str, Any] = {
            "space": "global",
            "base": f"0x{base_int:016x}",
            "bytes": int(size),
        }
        if item.get("name") is not None:
            entry["name"] = str(item["name"])
        out.append(entry)
    return out


def _canonical_space(space: Any) -> str:
    if space is None:
        return ""
    s = str(space).strip().lower()
    if s in ("global", "local", "shared"):
        return s
    if s in ("param", "param_local", "param_space_local"):
        return "local"
    if s == "param_kernel":
        return "global"
    if s == "const":
        return "const"
    return s


def _mark_output_stores(
    events: List[Dict[str, Any]],
    output_ranges: List[Dict[str, Any]],
) -> None:
    if not output_ranges:
        return
    ranges = []
    for r in output_ranges:
        if _canonical_space(r.get("space")) != "global":
            continue
        base = int(r["base"])
        size = int(r["size"])
        if size <= 0:
            continue
        ranges.append((base, base + size))
    if not ranges:
        return

    for ev in events:
        if not isinstance(ev, dict):
            continue
        if str(ev.get("kind", "")).lower() != "store":
            continue
        mem_space = _canonical_space(ev.get("mem_space") or ev.get("space"))
        if mem_space != "global":
            continue
        if "mem_addr" in ev:
            addr = int(ev["mem_addr"], 0) if isinstance(ev["mem_addr"], str) else int(ev["mem_addr"])
        elif "base" in ev:
            addr = int(ev["base"], 0) if isinstance(ev["base"], str) else int(ev["base"])
        else:
            continue
        size = int(
            ev.get(
                "store_size_bytes",
                ev.get("mem_access_size_bytes", ev.get("size", 0)),
            )
        )
        if size <= 0:
            continue
        end = addr + size
        for lo, hi in ranges:
            if addr < hi and end > lo:
                ev["is_output_store"] = True
                break


def _format_u64(value: int) -> str:
    return f"0x{(int(value) & U64_MASK):016x}"


def _width_mask(width_bits: int) -> int:
    w = int(width_bits)
    if w <= 0:
        return 0
    if w >= 64:
        return U64_MASK
    return (1 << w) - 1


def _canonical_pc(value: Any) -> str:
    if isinstance(value, int):
        return f"0x{value:x}"
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return "0x0"
        try:
            return f"0x{int(s, 0):x}"
        except ValueError:
            return s
    try:
        return f"0x{int(value):x}"
    except Exception:
        return "0x0"



def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Prepare reg_observed_analyzer input by combining trace template "
            "with output ranges"
        )
    )
    p.add_argument("--trace-template", type=Path, required=True)
    p.add_argument("--output-spec", type=Path, required=True)
    p.set_defaults(
        compact_events=_env_flag("EXACT_SDC_PREPARE_COMPACT_EVENTS", True),
    )
    p.add_argument(
        "--compact-events",
        dest="compact_events",
        action="store_true",
        help=(
            "Drop analyzer-unused event fields and canonicalize numeric encodings "
            "(default: on; disable via --no-compact-events)."
        ),
    )
    p.add_argument(
        "--no-compact-events",
        dest="compact_events",
        action="store_false",
        help="Keep original event fields (legacy compatibility).",
    )
    p.set_defaults(
        manifest_reference=_env_flag("EXACT_SDC_PREPARE_MANIFEST_REFERENCE", False),
        binary_analyzer_input=_env_flag(
            "EXACT_SDC_PREPARE_BINARY_ANALYZER_INPUT",
            False,
        ),
    )
    p.add_argument(
        "--manifest-reference",
        dest="manifest_reference",
        action="store_true",
        help=(
            "Write a small analyzer-input manifest that references the captured "
            "trace instead of materializing a second events array."
        ),
    )
    p.add_argument(
        "--no-manifest-reference",
        dest="manifest_reference",
        action="store_false",
        help="Materialize the analyzer input events array (legacy behavior).",
    )
    p.add_argument(
        "--binary-analyzer-input",
        dest="binary_analyzer_input",
        action="store_true",
        help=(
            "Write analyzer input as a tiny JSON manifest plus binary sidecar "
            "instead of materializing the full analyzer_input JSON."
        ),
    )
    p.add_argument(
        "--no-binary-analyzer-input",
        dest="binary_analyzer_input",
        action="store_false",
        help="Write analyzer input as legacy JSON.",
    )
    p.add_argument("-o", "--output", type=Path, required=True)
    return p


def main() -> int:
    args = build_arg_parser().parse_args()
    if bool(args.manifest_reference) and bool(args.binary_analyzer_input):
        raise ValueError(
            "--binary-analyzer-input and --manifest-reference are mutually exclusive"
        )
    if bool(args.manifest_reference):
        output_ranges = _parse_output_ranges(args.output_spec)
        output_spec_entries = _parse_output_spec_entries(args.output_spec)
        out_dir = args.output.parent
        sidecar_path = Path(str(args.trace_template) + ".memory_ranges.json")
        sidecar_ranges = _load_sidecar_memory_ranges(args.trace_template)
        manifest_ranges: List[Dict[str, Any]] = list(output_ranges)
        if sidecar_ranges is not None and not sidecar_path.exists():
            manifest_ranges = list(sidecar_ranges) + manifest_ranges
        manifest: Dict[str, Any] = {
            "manifest_kind": "exact_sdc_analyzer_input_ref",
            "trace_template_ref": _manifest_relpath(args.trace_template, base_dir=out_dir),
            "memory_ranges": manifest_ranges,
            "output_spec": output_spec_entries,
            "compact_events": bool(args.compact_events),
        }
        if sidecar_path.exists():
            manifest["memory_ranges_ref"] = _manifest_relpath(sidecar_path, base_dir=out_dir)
        _json_dump_path(args.output, manifest)
        return 0

    trace = _load_trace_template(args.trace_template)
    output_ranges = _parse_output_ranges(args.output_spec)
    output_spec_entries = _parse_output_spec_entries(args.output_spec)
    if isinstance(trace.get("events"), list):
        _mark_output_stores(trace["events"], output_ranges)

    merged_ranges = list(trace.get("memory_ranges", []))
    merged_ranges.extend(output_ranges)

    events_out: Any = trace.get("events")
    if isinstance(events_out, list):
        if args.compact_events:
            events_out = [_compact_event_for_analyzer(ev) for ev in events_out]

    out: Dict[str, Any] = {
        "events": events_out,
        "memory_ranges": merged_ranges,
        "output_spec": output_spec_entries,
    }
    if bool(args.binary_analyzer_input):
        _write_binary_analyzer_input(args.output, out)
    else:
        sidecar_path = _binary_analyzer_input_sidecar_path(args.output)
        columnar_path = _columnar_analyzer_input_sidecar_path(args.output)
        try:
            sidecar_path.unlink()
        except FileNotFoundError:
            pass
        try:
            columnar_path.unlink()
        except FileNotFoundError:
            pass
        _json_dump_path(args.output, out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
