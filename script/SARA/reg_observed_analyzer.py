#!/usr/bin/env python3
from __future__ import annotations
"""Offline backward analyzer for register-read observed-bit masks + exact DUE.

Input format:
1) Legacy (list of events):
   [ {event0}, {event1}, ... ]

2) Extended (object):
   {
     "events": [ ... ],
     "memory_ranges": [
       {
         "space": "global|local|shared",
         "base": "0x...",
         "size": 4096,
         "start_event_index": 0,        # optional inclusive
         "end_event_index": 1000,       # optional exclusive
         "thread_id": 7,                # optional filter
         "cta_id": 2,                   # optional filter
         "sm_id": 0                     # optional filter
       }
     ]
   }

Per memory load/store event, optional EA metadata for exact address-DUE:
- "mem_space": "global|local|shared"
- "mem_addr": "0x..." or int
- "ea_base_src_indices": [idx0, idx1, ...]          # source indices forming EA
- "ea_const_offset": 0                               # optional
- "ea_width_bits": 64                                # optional
- "ea_expr": {
    "op": "ADD|SUB|...|IDENTITY|ADDR_SUM",
    "src_indices": [idx0, idx1, ...],
    "width_bits": 64
  }

Address-level exactness model used here:
- Base-register bit-flip level.
- Mutated effective addresses are SDC when range evidence proves a valid
  different access that reads different output-relevant bytes, DUE when range
  evidence proves an invalid access, and Unknown when the required range or
  byte evidence is unavailable.
"""

import argparse
import bisect
import builtins as _builtins

_BUILTIN_DICT = _builtins.dict
_BUILTIN_HASH = _builtins.hash
_BUILTIN_INT = _builtins.int
_BUILTIN_ISINSTANCE = _builtins.isinstance
_BUILTIN_LEN = _builtins.len
_BUILTIN_LIST = _builtins.list
_BUILTIN_MAX = _builtins.max
_BUILTIN_MIN = _builtins.min
_BUILTIN_STR = _builtins.str
_BUILTIN_TUPLE = _builtins.tuple
EXPERIMENT_RANDOM_SEED = 2026

import cProfile
import gzip
import hashlib
import inspect
import io
import json
import math
import os
import pickle
import pstats
import re
import struct
import sys
import time
from collections import Counter, OrderedDict, defaultdict
from fractions import Fraction
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Sequence, Set, Tuple

import outcome_oracle as shared_output_oracle

try:
    import orjson as _orjson  # type: ignore
except Exception:
    _orjson = None

try:
    import zstandard as _zstd  # type: ignore
except Exception:
    _zstd = None


def _text(value: Any) -> str:
    """Return a plain built-in str even if callers pass string-like objects.

    Some analyzer paths store opcodes inside compact cache/manifest records and
    later replay those records after binary/pickle/json round trips.  Keep all
    opcode helpers insulated from objects whose attributes can shadow normal
    string methods (for example a non-builtin string-like value with a textual
    ``startswith`` attribute).
    """

    if value is None:
        return ""
    return _BUILTIN_STR(value)


def _text_startswith(value: Any, prefix: str) -> bool:
    """startswith for opcode strings without relying on a possibly shadowed method.

    Long SARA runs replay opcodes through several compact/binary/pickle paths.
    Keeping the hot opcode helpers on plain built-in conversions plus slicing
    prevents string-like payloads from exposing a non-callable ``startswith``
    attribute and makes the helper immune to accidental built-in name shadowing.
    """

    text = _text(value)
    prefix_text = _text(prefix)
    return text[: _BUILTIN_LEN(prefix_text)] == prefix_text


def _text_in(value: Any, names: Sequence[str]) -> bool:
    """Return whether value textually equals one of names without tuple ``in``.

    A few historical failures occurred while replaying compact opcode artifacts,
    where traceback line cache pointed at tuple
    membership even though the logical operation was just an opcode equality
    check.  Use an explicit equality loop so mixed string-like/tuple payloads
    cannot trigger ordering comparisons inside optimized membership paths.
    """

    text = _text(value)
    for name in names:
        if text == _text(name):
            return True
    return False


def _json_load_path(path: Path) -> Any:
    raw = path.read_bytes()
    # Auto-detect gzip/zstd by magic bytes to tolerate symlinked aliases.
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


def _binary_output_sidecar_path(output_path: Path) -> Path:
    return Path(str(output_path) + ".bin")


def _binary_sidecar_payload_summary(payload: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key in ("read_events", "smem_fault_sites", "l1d_fault_sites", "l2_fault_sites"):
        rows = payload.get(key, [])
        if isinstance(rows, list):
            out[f"{key}_count"] = int(len(rows))
    meta = payload.get("exact_meta", {})
    if isinstance(meta, dict):
        for key in ("fault_component",):
            if key in meta:
                out[key] = meta.get(key)
    return out


def _write_binary_output_manifest(output_path: Path, payload: Dict[str, Any]) -> None:
    """Persist analyzer output as a binary sidecar plus a small JSON manifest."""

    sidecar = _binary_output_sidecar_path(output_path)
    sidecar.write_bytes(pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL))
    manifest = {
        "manifest_kind": "exact_sdc_analyzer_output_binary_v1",
        "binary_format": "pickle_dict_v1",
        "binary_ref": _manifest_relpath(sidecar, base_dir=output_path.parent),
    }
    manifest.update(_binary_sidecar_payload_summary(payload))
    _json_dump_path(output_path, manifest)


try:
    from dataclasses import dataclass as _stdlib_dataclass, field as dataclass_field
    _DATACLASS_SUPPORTS_SLOTS = "slots" in inspect.signature(
        _stdlib_dataclass
    ).parameters

    def dataclass(_cls=None, **kwargs):
        def _apply(cls):
            local_kwargs = dict(kwargs)
            if _DATACLASS_SUPPORTS_SLOTS and "__slots__" not in cls.__dict__:
                local_kwargs.setdefault("slots", True)
            return _stdlib_dataclass(cls, **local_kwargs)

        if _cls is None:
            return _apply
        return _apply(_cls)
except ImportError:
    def dataclass_field(*_args, default=None, default_factory=None, **_kwargs):
        if default_factory is not None:
            return default_factory()
        return default

    def dataclass(_cls=None, **_kwargs):
        def wrap(cls):
            fields = list(getattr(cls, "__annotations__", {}).keys())
            defaults = {}
            for name in fields:
                if hasattr(cls, name):
                    defaults[name] = getattr(cls, name)

            def __init__(self, *args, **kwargs):
                if len(args) > len(fields):
                    raise TypeError(
                        "{} expected at most {} args, got {}".format(
                            cls.__name__, len(fields), len(args)
                        )
                    )
                for name, value in zip(fields, args):
                    setattr(self, name, value)
                for name in fields[len(args):]:
                    if name in kwargs:
                        setattr(self, name, kwargs.pop(name))
                    elif name in defaults:
                        setattr(self, name, defaults[name])
                    else:
                        raise TypeError(
                            "{} missing required argument: '{}'".format(
                                cls.__name__, name
                            )
                        )
                if kwargs:
                    raise TypeError(
                        "{} got unexpected argument(s): {}".format(
                            cls.__name__, ", ".join(sorted(kwargs.keys()))
                        )
                    )

            cls.__init__ = __init__
            if bool(_kwargs.get("slots", False)):
                cls.__slots__ = tuple(fields)  # type: ignore[attr-defined]
            if "__repr__" not in cls.__dict__:
                def __repr__(self):
                    vals = ", ".join(
                        "{}={!r}".format(name, getattr(self, name)) for name in fields
                    )
                    return "{}({})".format(cls.__name__, vals)

                cls.__repr__ = __repr__
            return cls

        if _cls is None:
            return wrap
        return wrap(_cls)

UINT64_MASK = (1 << 64) - 1
CANONICAL_ADDR_DUE_MODE = "range"
CANONICAL_ADDR_FAULT_POLICY = "bounds_due"
MASK_FORMATS = ("int", "hex")
ZERO_MASK_INT = 0
ZERO_MASK_STR = "0x0000000000000000"
_WIDTH_MASK_TABLE = tuple((1 << i) - 1 for i in range(65))
ADDR_STATIC_DUE_MASK_FIELD = "addr_static_due_mask_this_read"
SMEM_SHARED_STORE_ESCAPE_MASK_FIELD = "shared_store_escape_mask_this_site"
READ_MASK_FIELDS = (
    "observed_mask_this_read",
    "due_mask_this_read",
    "trace_expanding_mask_this_read",
    "reg_observed_mask_at_read",
    "reg_due_mask_at_read",
    ADDR_STATIC_DUE_MASK_FIELD,
)
READ_CLASS_MASK_FIELDS = (
    "observed_mask_this_read",
    "due_mask_this_read",
    "trace_expanding_mask_this_read",
    ADDR_STATIC_DUE_MASK_FIELD,
)
DETAIL_MAP_FIELDS = ("notes",)
DETAIL_SCALAR_FIELDS = ("pc", "opcode", "read_kind")
SMEM_SITE_MASK_FIELDS = (
    "observed_mask_this_site",
    "due_mask_this_site",
    "trace_expanding_mask_this_site",
    SMEM_SHARED_STORE_ESCAPE_MASK_FIELD,
)
L2_SITE_MASK_FIELDS = SMEM_SITE_MASK_FIELDS
L1D_SITE_MASK_FIELDS = SMEM_SITE_MASK_FIELDS
FAULT_COMPONENTS = ("rf", "smem_rf", "smem_lds", "l1d", "l2")
_TOGGLE_SETPCACHE_MAXSIZE = 200000
_TOGGLE_VALIDATE_SAMPLE_EVERY_DEFAULT = 2000
_TOGGLE_VALIDATE_BLACKLIST_MAX_ENTRIES = 4096
SUPPORTED_OPS = {
    "ADD",
    "ADD_F32",
    "DIV_F32",
    "SQRT_F32",
    "SUB",
    "SUB_F32",
    "NEG",
    "NEG_F32",
    "NOT",
    "NOT_PRED",
    "MUL_LO",
    "MUL_F32",
    "MUL_WIDE_U32",
    "MUL_WIDE_S32",
    "MAD",
    "FMA_F32",
    "ABS_F32",
    "EX2_APPROX_FTZ_F32",
    "RCP_APPROX_FTZ_F32",
    "MIN_F32",
    "MAX_F32",
    "AND",
    "OR",
    "XOR",
    "SHL",
    "SHR_U",
    "SHR_S",
    "MIN_U",
    "MIN_S",
    "MAX_U",
    "MAX_S",
    "CVT_U32_U64",
    "CVT_U64_U32",
    "CVT_S32_S64",
    "CVT_S64_S32",
    "CVT_SAT_F32_F32",
    "IDENTITY",
    "SETP_EQ",
    "SETP_NE",
    "SETP_LT_U",
    "SETP_LT_S",
    "SETP_LE_U",
    "SETP_LE_S",
    "SETP_GT_U",
    "SETP_GT_S",
    "SETP_GE_U",
    "SETP_GE_S",
    "SETP_EQ_F16",
    "SETP_NE_F16",
    "SETP_LT_F16",
    "SETP_LE_F16",
    "SETP_GT_F16",
    "SETP_GE_F16",
    "SETP_LTU_F16",
    "SETP_LEU_F16",
    "SETP_GTU_F16",
    "SETP_GEU_F16",
    "SETP_EQ_F32",
    "SETP_NE_F32",
    "SETP_LT_F32",
    "SETP_LE_F32",
    "SETP_GT_F32",
    "SETP_GE_F32",
    "SETP_LTU_F32",
    "SETP_LEU_F32",
    "SETP_GTU_F32",
    "SETP_GEU_F32",
    "SETP_EQ_F64",
    "SETP_NE_F64",
    "SETP_LT_F64",
    "SETP_LE_F64",
    "SETP_GT_F64",
    "SETP_GE_F64",
    "SETP_LTU_F64",
    "SETP_LEU_F64",
    "SETP_GTU_F64",
    "SETP_GEU_F64",
    "SELP",
    "POPC",
    "CLZ",
    "BREV",
    "BFE_U",
    "BFE_S",
    "LOP3",
}
SETP_COMPARATORS = {"eq", "ne", "lt", "le", "gt", "ge", "ltu", "leu", "gtu", "geu"}
_SETP_COMPARATOR_ORDER = ("ltu", "leu", "gtu", "geu", "eq", "ne", "lt", "le", "gt", "ge")
_DICT_MISSING = object()
_OPERAND_IMM = 0
_OPERAND_PRED = 1
_OPERAND_REG = 2
LITE_OUTPUT_PROFILES = ("compat", "compute")
LITE_READ_EVENT_KEYS_COMPAT = (
    "event_index",
    "thread_id",
    "cycle",
    "pc",
    "opcode",
    "read_kind",
    "src_index",
    "src_reg",
    "src_reg_uid",
    "src_width_bits",
    "observed_mask_this_read",
    "due_mask_this_read",
    ADDR_STATIC_DUE_MASK_FIELD,
    "trace_expanding_mask_this_read",
    "reg_observed_mask_at_read",
    "reg_due_mask_at_read",
)
LITE_READ_EVENT_KEYS_COMPUTE = (
    "event_index",
    "thread_id",
    "cycle",
    "read_kind",
    "src_index",
    "src_reg",
    "src_reg_uid",
    "src_width_bits",
    "observed_mask_this_read",
    "due_mask_this_read",
    ADDR_STATIC_DUE_MASK_FIELD,
    "trace_expanding_mask_this_read",
)
LITE_READ_EVENT_KEYS_BY_PROFILE = {
    "compat": LITE_READ_EVENT_KEYS_COMPAT,
    "compute": LITE_READ_EVENT_KEYS_COMPUTE,
}
# Backward-compat alias.
LITE_READ_EVENT_KEYS = LITE_READ_EVENT_KEYS_COMPAT
COMPACT_READ_EVENT_KEYS_COMPUTE = (
    "event_index",
    "thread_id",
    "cycle",
    "read_kind",
    "src_index",
    "src_reg",
    "src_reg_uid",
    "src_width_bits",
    "observed_mask_this_read",
    "due_mask_this_read",
    ADDR_STATIC_DUE_MASK_FIELD,
    "trace_expanding_mask_this_read",
)
COMPACT_READ_EVENT_KEYS_COMPUTE_INDEX = {
    key: idx for idx, key in enumerate(COMPACT_READ_EVENT_KEYS_COMPUTE)
}
COMPACT_SMEM_SITE_KEYS = (
    "site_kind",
    "thread_id",
    "sm_id",
    "cta_id",
    "addr",
    "cycle",
    "event_index",
    "observed_mask_this_site",
    "due_mask_this_site",
    "trace_expanding_mask_this_site",
    SMEM_SHARED_STORE_ESCAPE_MASK_FIELD,
)
COMPACT_CACHE_SITE_KEYS = (
    "site_kind",
    "mem_space",
    "thread_id",
    "sm_id",
    "cta_id",
    "addr",
    "cycle",
    "event_index",
    "observed_mask_this_site",
    "due_mask_this_site",
    "trace_expanding_mask_this_site",
)
COMPACT_SMEM_SITE_KEYS_INDEX = {
    key: idx for idx, key in enumerate(COMPACT_SMEM_SITE_KEYS)
}
COMPACT_CACHE_SITE_KEYS_INDEX = {
    key: idx for idx, key in enumerate(COMPACT_CACHE_SITE_KEYS)
}
META_DIAGNOSTIC_SAMPLE_FIELDS = (
    "output_oracle_spec_ranges",
)

def parse_int(
    value: Any,
    _to_int: Any = _builtins.int,
    _isinstance: Any = _builtins.isinstance,
    _int_type: Any = _builtins.int,
    _str_type: Any = _builtins.str,
) -> int:
    if _isinstance(value, _int_type):
        return value
    if _isinstance(value, _str_type):
        return _to_int(value, 0)
    raise ValueError(f"Unsupported integer value: {value!r}")


def _linux_mem_available_bytes() -> Optional[int]:
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return int(parts[1]) * 1024
    except Exception:
        return None
    return None


def deterministic_seeded_index(length: int, *parts: Any) -> int:
    if length <= 0:
        return 0
    digest = hashlib.blake2b(digest_size=8)
    digest.update(str(EXPERIMENT_RANDOM_SEED).encode("utf-8"))
    digest.update(b"\0")
    for part in parts:
        digest.update(str(part).encode("utf-8", errors="replace"))
        digest.update(b"\0")
    return int.from_bytes(digest.digest(), byteorder="big", signed=False) % int(length)


def coerce_width_bits(
    width_bits: Any,
    default: int = 64,
    _to_int: Any = _builtins.int,
    _max: Any = _builtins.max,
    _min: Any = _builtins.min,
) -> int:
    """Return a safe 0..64 width for trace/read-record bit masks.

    Older/stale analyzer artifacts can contain explicit ``None`` width fields.
    Treat those the same as a missing field instead of letting a late summary
    pass crash inside ``width_mask``.
    """

    try:
        fallback = _to_int(default)
    except Exception:
        fallback = 64
    if width_bits is None:
        w = fallback
    else:
        try:
            w = _to_int(width_bits)
        except (TypeError, ValueError, OverflowError):
            w = fallback
    return _max(0, _min(64, w))


def coerce_positive_width_bits(
    width_bits: Any,
    default: int = 32,
    _max: Any = _builtins.max,
) -> int:
    return _max(1, coerce_width_bits(width_bits, default=default))


def width_mask(width_bits: Any) -> int:
    if type(width_bits) is int:
        w = width_bits
        if w <= 0:
            return 0
        if w >= 64:
            return UINT64_MASK
        return _WIDTH_MASK_TABLE[w]
    w = coerce_width_bits(width_bits, default=64)
    if w <= 0:
        return 0
    if w >= 64:
        return UINT64_MASK
    return _WIDTH_MASK_TABLE[w]


def to_signed(value: int, width_bits: int) -> int:
    value &= width_mask(width_bits)
    if width_bits == 64:
        if value & (1 << 63):
            return value - (1 << 64)
        return value
    sign = 1 << (width_bits - 1)
    return (value ^ sign) - sign


_BYTE_POPCOUNT = tuple(bin(i).count("1") for i in range(256))


def popcount(x: int) -> int:
    v = int(x & UINT64_MASK)
    try:
        return v.bit_count()  # type: ignore[attr-defined]
    except AttributeError:  # pragma: no cover - Python < 3.8 compatibility
        return sum(_BYTE_POPCOUNT[byte] for byte in v.to_bytes(8, "little"))


def iter_set_bits(mask: int):
    m = int(mask) & UINT64_MASK
    while m:
        lsb = m & -m
        yield int(lsb.bit_length() - 1)
        m ^= lsb


def format_mask(mask: int) -> str:
    return f"0x{(mask & UINT64_MASK):016x}"


def parse_mask(mask: Any) -> int:
    return parse_int(mask) & UINT64_MASK


def mask_as_int(
    mask: Any,
    _to_int: Any = _builtins.int,
    _isinstance: Any = _builtins.isinstance,
    _int_type: Any = _builtins.int,
) -> int:
    if mask is None:
        return 0
    if _isinstance(mask, _int_type):
        return _to_int(mask) & UINT64_MASK
    return parse_mask(mask)


def env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    token = str(raw).strip().lower()
    if token in ("1", "true", "yes", "on", "y"):
        return True
    if token in ("0", "false", "no", "off", "n"):
        return False
    return bool(default)


def mask_to_output(mask: Any, mask_format: str) -> Any:
    m = mask_as_int(mask)
    if mask_format == "hex":
        return format_mask(m)
    return m


def apply_mask_format_to_record(rec: Dict[str, Any], mask_format: str) -> Dict[str, Any]:
    if _is_compact_compute_read_row(rec):
        rec = compact_compute_read_row_to_dict(rec)
    out = dict(rec)
    for field in READ_MASK_FIELDS:
        if field in out:
            out[field] = mask_to_output(out.get(field, 0), mask_format)
    return out


def apply_mask_format_to_smem_site(
    rec: Dict[str, Any], mask_format: str
) -> Dict[str, Any]:
    if _is_compact_smem_site_row(rec):
        rec = compact_smem_site_row_to_dict(rec)
    out = dict(rec)
    for field in SMEM_SITE_MASK_FIELDS:
        if field in out:
            out[field] = mask_to_output(out.get(field, 0), mask_format)
    return out


def apply_mask_format_to_l2_site(
    rec: Dict[str, Any], mask_format: str
) -> Dict[str, Any]:
    if _is_compact_cache_site_row(rec):
        rec = compact_cache_site_row_to_dict(rec)
    out = dict(rec)
    for field in L2_SITE_MASK_FIELDS:
        if field in out:
            out[field] = mask_to_output(out.get(field, 0), mask_format)
    return out


def apply_mask_format_to_l1d_site(
    rec: Dict[str, Any], mask_format: str
) -> Dict[str, Any]:
    if _is_compact_cache_site_row(rec):
        rec = compact_cache_site_row_to_dict(rec)
    out = dict(rec)
    for field in L1D_SITE_MASK_FIELDS:
        if field in out:
            out[field] = mask_to_output(out.get(field, 0), mask_format)
    return out


def build_lite_read_record(
    rec: Dict[str, Any],
    *,
    mask_format: str = "int",
    profile: str = "compat",
) -> Dict[str, Any]:
    prof = str(profile).strip().lower()
    if prof == "compute" and mask_format == "int" and _is_compact_compute_read_row(rec):
        return rec
    if _is_compact_compute_read_row(rec):
        rec = compact_compute_read_row_to_dict(rec)
    keys = LITE_READ_EVENT_KEYS_BY_PROFILE.get(prof)
    if keys is None:
        raise ValueError(
            "lite_output_profile must be one of {}; got {!r}".format(
                ", ".join(LITE_OUTPUT_PROFILES), profile
            )
        )
    mask_fields = READ_MASK_FIELDS if prof == "compat" else READ_CLASS_MASK_FIELDS
    out: Dict[str, Any] = {}
    for key in keys:
        if key not in rec:
            continue
        if key in READ_MASK_FIELDS:
            out[key] = mask_to_output(rec[key], mask_format)
        else:
            out[key] = rec[key]
    # Keep mask fields explicit for downstream parsing defaults.
    for key in mask_fields:
        if key not in out:
            out[key] = format_mask(0) if mask_format == "hex" else ZERO_MASK_INT
    return out


def build_internal_read_record(
    *,
    profile: str,
    event_index: int,
    thread_id: int,
    cycle: Optional[int],
    read_kind: str,
    src_index: int,
    src_reg: str,
    src_reg_uid: int,
    src_width_bits: int,
    observed_mask_this_read: int,
    due_mask_this_read: int,
    trace_expanding_mask_this_read: int = 0,
    addr_static_due_mask_this_read: int = 0,
    reg_observed_mask_at_read: int = 0,
    reg_due_mask_at_read: int = 0,
    sm_id: Optional[int] = None,
    cta_id: Optional[int] = None,
    warp_id: Optional[int] = None,
    pc: str = "",
    opcode: str = "",
    notes: Optional[Dict[str, Any]] = None,
    compact_compute: bool = False,
    _to_int: Any = _builtins.int,
) -> Any:
    prof = str(profile).strip().lower()
    cycle_i = None if cycle is None else _to_int(cycle)
    if compact_compute and prof == "compute":
        return (
            _to_int(event_index),
            _to_int(thread_id),
            cycle_i,
            str(read_kind),
            _to_int(src_index),
            str(src_reg),
            _to_int(src_reg_uid),
            coerce_width_bits(src_width_bits, default=64),
            _to_int(observed_mask_this_read) & UINT64_MASK,
            _to_int(due_mask_this_read) & UINT64_MASK,
            _to_int(addr_static_due_mask_this_read) & UINT64_MASK,
            _to_int(trace_expanding_mask_this_read) & UINT64_MASK
        )
    rec: Dict[str, Any] = {
        "event_index": _to_int(event_index),
        "thread_id": _to_int(thread_id),
        "cycle": cycle_i,
        "read_kind": str(read_kind),
        "src_index": _to_int(src_index),
        "src_reg": str(src_reg),
        "src_reg_uid": _to_int(src_reg_uid),
        "src_width_bits": coerce_width_bits(src_width_bits, default=64),
        "observed_mask_this_read": _to_int(observed_mask_this_read) & UINT64_MASK,
        "due_mask_this_read": _to_int(due_mask_this_read) & UINT64_MASK,
        ADDR_STATIC_DUE_MASK_FIELD: _to_int(addr_static_due_mask_this_read) & UINT64_MASK,
        "trace_expanding_mask_this_read": _to_int(trace_expanding_mask_this_read)
        & UINT64_MASK,
    }
    if prof == "compat":
        rec["sm_id"] = sm_id
        rec["cta_id"] = cta_id
        rec["warp_id"] = warp_id
        rec["pc"] = str(pc)
        rec["opcode"] = str(opcode)
        rec["reg_observed_mask_at_read"] = _to_int(reg_observed_mask_at_read) & UINT64_MASK
        rec["reg_due_mask_at_read"] = _to_int(reg_due_mask_at_read) & UINT64_MASK
        if notes:
            rec["notes"] = dict(notes)
    return rec


def build_internal_site_record(
    *,
    site_family: str,
    site_kind: str,
    mem_space: Optional[str],
    thread_id: int,
    sm_id: Optional[int],
    cta_id: Optional[int],
    addr: int,
    cycle: Optional[int],
    event_index: int,
    width_bits: int,
    writer_event_index: int,
    observed_mask_this_site: int,
    due_mask_this_site: int,
    trace_expanding_mask_this_site: int,
    shared_store_escape_mask_this_site: int = 0,
    compact: bool = False,
    _to_int: Any = _builtins.int,
) -> Any:
    family = str(site_family).strip().lower()
    cycle_i = None if cycle is None else _to_int(cycle)
    if compact:
        if family == "smem":
            return (
                str(site_kind),
                _to_int(thread_id),
                sm_id,
                cta_id,
                _to_int(addr),
                cycle_i,
                _to_int(event_index),
                _to_int(observed_mask_this_site) & 0xFF,
                _to_int(due_mask_this_site) & 0xFF,
                _to_int(trace_expanding_mask_this_site) & 0xFF,
                _to_int(shared_store_escape_mask_this_site) & 0xFF,
            )
        if family in ("l1d", "l2"):
            return (
                str(site_kind),
                str(mem_space or ""),
                _to_int(thread_id),
                sm_id,
                cta_id,
                _to_int(addr),
                cycle_i,
                _to_int(event_index),
                _to_int(observed_mask_this_site) & 0xFF,
                _to_int(due_mask_this_site) & 0xFF,
                _to_int(trace_expanding_mask_this_site) & 0xFF,
            )
        raise ValueError(f"unsupported site_family: {site_family!r}")

    rec: Dict[str, Any] = {
        "site_kind": str(site_kind),
        "thread_id": _to_int(thread_id),
        "sm_id": sm_id,
        "cta_id": cta_id,
        "addr": _to_int(addr),
        "cycle": cycle_i,
        "event_index": _to_int(event_index),
        "width_bits": _to_int(width_bits),
        "writer_event_index": _to_int(writer_event_index),
        "observed_mask_this_site": _to_int(observed_mask_this_site) & 0xFF,
        "due_mask_this_site": _to_int(due_mask_this_site) & 0xFF,
        "trace_expanding_mask_this_site": _to_int(trace_expanding_mask_this_site) & 0xFF,
    }
    if family == "smem":
        rec[SMEM_SHARED_STORE_ESCAPE_MASK_FIELD] = (
            _to_int(shared_store_escape_mask_this_site) & 0xFF
        )
    elif family in ("l1d", "l2"):
        rec["mem_space"] = str(mem_space or "")
    else:
        raise ValueError(f"unsupported site_family: {site_family!r}")
    return rec


def _compact_row_get(
    rec: Any,
    *,
    index_map: Mapping[str, int],
    key: str,
    default: Any = None,
) -> Any:
    if not _builtins.isinstance(rec, (_builtins.list, _builtins.tuple)):
        return default
    try:
        idx = index_map.get(str(key))
    except AttributeError:
        # Some compact decoding paths can receive a mapping-like object whose
        # ``get`` implementation is not the built-in dict method. Fall back to
        # the saved built-in dict lookup for plain dict-compatible maps.
        idx = _BUILTIN_DICT.get(index_map, str(key))
    if idx is None or idx < 0 or idx >= _builtins.len(rec):
        return default
    return rec[idx]


def _is_compact_compute_read_row(rec: Any) -> bool:
    return _builtins.isinstance(
        rec, (_builtins.list, _builtins.tuple)
    ) and _builtins.len(rec) == _builtins.len(
        COMPACT_READ_EVENT_KEYS_COMPUTE
    )


def _is_compact_smem_site_row(rec: Any) -> bool:
    return _builtins.isinstance(
        rec, (_builtins.list, _builtins.tuple)
    ) and _builtins.len(rec) == _builtins.len(COMPACT_SMEM_SITE_KEYS)


def _is_compact_cache_site_row(rec: Any) -> bool:
    return _builtins.isinstance(
        rec, (_builtins.list, _builtins.tuple)
    ) and _builtins.len(rec) == _builtins.len(COMPACT_CACHE_SITE_KEYS)


def compact_compute_read_row_to_dict(rec: Any) -> Dict[str, Any]:
    if not _is_compact_compute_read_row(rec):
        return _BUILTIN_DICT(rec)
    return {
        key: _compact_row_get(
            rec,
            index_map=COMPACT_READ_EVENT_KEYS_COMPUTE_INDEX,
            key=key
        )
        for key in COMPACT_READ_EVENT_KEYS_COMPUTE
    }


def compact_smem_site_row_to_dict(rec: Any) -> Dict[str, Any]:
    if not _is_compact_smem_site_row(rec):
        return _BUILTIN_DICT(rec)
    return {
        key: _compact_row_get(
            rec,
            index_map=COMPACT_SMEM_SITE_KEYS_INDEX,
            key=key
        )
        for key in COMPACT_SMEM_SITE_KEYS
    }


def compact_cache_site_row_to_dict(rec: Any) -> Dict[str, Any]:
    if not _is_compact_cache_site_row(rec):
        return _BUILTIN_DICT(rec)
    return {
        key: _compact_row_get(
            rec,
            index_map=COMPACT_CACHE_SITE_KEYS_INDEX,
            key=key
        )
        for key in COMPACT_CACHE_SITE_KEYS
    }


def _read_row_field(rec: Any, key: str, default: Any = None) -> Any:
    if _is_compact_compute_read_row(rec):
        return _compact_row_get(
            rec,
            index_map=COMPACT_READ_EVENT_KEYS_COMPUTE_INDEX,
            key=key,
            default=default
        )
    if _builtins.isinstance(rec, _builtins.dict):
        return rec.get(key, default)
    return default


def _site_row_field(
    rec: Any,
    *,
    family: str,
    key: str,
    default: Any = None,
) -> Any:
    fam = str(family).strip().lower()
    if fam == "smem" and _is_compact_smem_site_row(rec):
        return _compact_row_get(
            rec,
            index_map=COMPACT_SMEM_SITE_KEYS_INDEX,
            key=key,
            default=default
        )
    if fam in ("l1d", "l2", "cache") and _is_compact_cache_site_row(rec):
        return _compact_row_get(
            rec,
            index_map=COMPACT_CACHE_SITE_KEYS_INDEX,
            key=key,
            default=default
        )
    if _builtins.isinstance(rec, _builtins.dict):
        return rec.get(key, default)
    return default


def compact_lite_read_records_in_place(
    records: List[Any],
    *,
    profile: str,
) -> List[Any]:
    for idx, rec in enumerate(records):
        if str(profile).strip().lower() == "compute" and _is_compact_compute_read_row(rec):
            records[idx] = rec
            continue
        records[idx] = build_lite_read_record(
            rec,
            mask_format="int",
            profile=profile,
        )
    return records


def build_compact_site_record(
    rec: Any,
    *,
    site_family: str,
    mask_format: str = "int",
) -> Any:
    family = str(site_family).strip().lower()
    if mask_format == "int":
        if family == "smem" and _is_compact_smem_site_row(rec):
            return rec
        if family in ("l1d", "l2") and _is_compact_cache_site_row(rec):
            return rec
    if family == "smem" and _is_compact_smem_site_row(rec):
        rec = compact_smem_site_row_to_dict(rec)
    elif family in ("l1d", "l2") and _is_compact_cache_site_row(rec):
        rec = compact_cache_site_row_to_dict(rec)
    if family == "smem":
        keys = COMPACT_SMEM_SITE_KEYS
        mask_fields = SMEM_SITE_MASK_FIELDS
    elif family in ("l1d", "l2"):
        keys = COMPACT_CACHE_SITE_KEYS
        mask_fields = L1D_SITE_MASK_FIELDS if family == "l1d" else L2_SITE_MASK_FIELDS
    else:
        raise ValueError(f"unsupported site_family: {site_family!r}")
    out: Dict[str, Any] = {}
    for key in keys:
        if key not in rec:
            continue
        if key in mask_fields:
            out[key] = mask_to_output(rec.get(key, 0), mask_format)
        else:
            out[key] = rec[key]
    return out



def compact_site_records_in_place(
    records: List[Any],
    *,
    site_family: str,
    mask_format: str = "int",
) -> List[Any]:
    for idx, rec in enumerate(records):
        records[idx] = build_compact_site_record(
            rec,
            site_family=site_family,
            mask_format=mask_format,
        )
    return records


def aggregate_lite_read_records(
    records: List[Any],
    *,
    profile: str = "compat",
    mask_format: str = "int",
) -> List[Dict[str, Any]]:
    prof = str(profile).strip().lower()
    if prof not in LITE_OUTPUT_PROFILES:
        raise ValueError(
            "lite_output_profile must be one of {}; got {!r}".format(
                ", ".join(LITE_OUTPUT_PROFILES), profile
            )
        )

    mask_fields = READ_MASK_FIELDS if prof == "compat" else READ_CLASS_MASK_FIELDS
    keep_detail_maps = prof == "compat"
    keep_detail_scalars = prof == "compat"
    by_key: Dict[Tuple[int, Any, int, str], Dict[str, Any]] = {}
    order: List[Tuple[int, Any, int, str]] = []

    for rec in records:
        if _is_compact_compute_read_row(rec):
            rec = compact_compute_read_row_to_dict(rec)
        elif not isinstance(rec, dict):
            continue
        tid = int(rec.get("thread_id", -1))
        cycle_raw = rec.get("cycle")
        cycle_key: Any = None if cycle_raw is None else int(cycle_raw)
        src_reg = str(rec.get("src_reg", ""))
        src_uid = int(rec.get("src_reg_uid", -1))
        key = (tid, cycle_key, src_uid, src_reg)

        cur = by_key.get(key)
        incoming_event_index = int(rec.get("event_index", 1 << 30))
        incoming_width = coerce_width_bits(rec.get("src_width_bits", 64), default=64)
        if cur is None:
            cur = {
                "event_index": incoming_event_index,
                "thread_id": tid,
                "src_reg": src_reg,
                "src_reg_uid": src_uid,
                "src_width_bits": incoming_width,
            }
            if cycle_key is not None:
                cur["cycle"] = int(cycle_key)
            if prof == "compat":
                cur["pc"] = str(rec.get("pc", ""))
                cur["opcode"] = str(rec.get("opcode", ""))
                if "read_kind" in rec:
                    cur["read_kind"] = str(rec.get("read_kind", ""))
                if "src_index" in rec:
                    cur["src_index"] = int(rec.get("src_index", -1))
                for field in DETAIL_MAP_FIELDS:
                    raw_map = rec.get(field)
                    if isinstance(raw_map, dict) and raw_map:
                        cur[field] = dict(raw_map)
                for field in DETAIL_SCALAR_FIELDS:
                    text = str(rec.get(field, "") or "").strip()
                    if text:
                        cur[field] = text
            for field in mask_fields:
                cur[field] = mask_as_int(rec.get(field, 0))
            by_key[key] = cur
            order.append(key)
            continue

        cur_event_index = int(cur.get("event_index", 1 << 30))
        if incoming_event_index < cur_event_index:
            cur["event_index"] = incoming_event_index
            if prof == "compat":
                cur["pc"] = str(rec.get("pc", cur.get("pc", "")))
                cur["opcode"] = str(rec.get("opcode", cur.get("opcode", "")))

        cur["src_width_bits"] = max(
            coerce_width_bits(cur.get("src_width_bits", 0), default=0),
            incoming_width
        )
        for field in mask_fields:
            cur[field] = mask_as_int(cur.get(field, 0)) | mask_as_int(rec.get(field, 0))

        if prof == "compat":
            if "read_kind" in cur:
                incoming_kind = str(rec.get("read_kind", ""))
                if str(cur.get("read_kind", "")) != incoming_kind:
                    cur["read_kind"] = "merged"
            if "src_index" in cur:
                incoming_src_index = int(rec.get("src_index", -1))
                if int(cur.get("src_index", -1)) != incoming_src_index:
                    cur["src_index"] = -1
            if keep_detail_maps:
                for field in DETAIL_MAP_FIELDS:
                    raw_map = rec.get(field)
                    if isinstance(raw_map, dict) and raw_map:
                        merged_map = cur.get(field)
                        if not isinstance(merged_map, dict):
                            merged_map = {}
                            cur[field] = merged_map
                        merged_map.update(raw_map)
            if keep_detail_scalars:
                for field in DETAIL_SCALAR_FIELDS:
                    if str(cur.get(field, "") or "").strip():
                        continue
                    text = str(rec.get(field, "") or "").strip()
                    if text:
                        cur[field] = text

    out = [by_key[k] for k in order]
    if mask_format == "hex":
        out = [apply_mask_format_to_record(rec, "hex") for rec in out]
    return out


def truncate_reason_message(message: Any, limit: int = 120) -> str:
    text = str(message).strip()
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: (limit - 3)] + "..."


def is_predicate_register(reg: Optional[str]) -> bool:
    return isinstance(reg, str) and reg.strip().lower().startswith("%p")


def is_data_register(reg: Optional[str]) -> bool:
    if not isinstance(reg, str):
        return False
    r = reg.strip().lower()
    return r.startswith("%") and not r.startswith("%p")


@lru_cache(maxsize=16384)
def _normalize_opcode_cached(opcode: str) -> str:
    op = opcode.strip().lower()
    op = op.split()[0] if op else op
    if "," in op:
        op = op.split(",", 1)[0]
    if "%" in op:
        op = op.split("%", 1)[0]
    if ";" in op:
        op = op.split(";", 1)[0]
    return op


def normalize_opcode(opcode: str) -> str:
    return _normalize_opcode_cached(_text(opcode))


def canonical_space(space: Optional[str]) -> Optional[str]:
    if space is None:
        return None
    return _canonical_space_cached(str(space))


@lru_cache(maxsize=128)
def _canonical_space_cached(space: str) -> str:
    s = space.strip().lower()
    if s in ("global", "local", "shared"):
        return s
    if s in ("param", "param_local", "param_space_local"):
        return "local"
    if s in ("param_kernel", "const"):
        return "global"
    if s in ("sstarr",):
        return "shared"
    return s


def infer_space_from_opcode(opcode: str) -> Optional[str]:
    opcode = _text(opcode)
    op = opcode.strip().lower()
    if ".global" in op:
        return "global"
    if ".local" in op:
        return "local"
    if ".shared" in op:
        return "shared"
    return None


class PredInfo:
    __slots__ = ("reg", "val", "uid")

    reg: str
    val: int
    uid: Optional[int]

    def __init__(self, reg: str, val: int, uid: Optional[int] = None) -> None:
        self.reg = reg
        self.val = int(val)
        self.uid = uid


@dataclass
class EAExpr:
    __slots__ = ("op", "src_indices", "width_bits")

    op: str
    src_indices: List[int]
    width_bits: int


class MemoryRange:
    __slots__ = (
        "space",
        "base",
        "size",
        "start_event_index",
        "end_event_index",
        "start_cycle",
        "end_cycle",
        "thread_id",
        "cta_id",
        "sm_id",
    )

    space: str
    base: int
    size: int
    start_event_index: Optional[int]
    end_event_index: Optional[int]
    start_cycle: Optional[int]
    end_cycle: Optional[int]
    thread_id: Optional[int]
    cta_id: Optional[int]
    sm_id: Optional[int]

    def __init__(
        self,
        space: str,
        base: int,
        size: int,
        start_event_index: Optional[int] = None,
        end_event_index: Optional[int] = None,
        start_cycle: Optional[int] = None,
        end_cycle: Optional[int] = None,
        thread_id: Optional[int] = None,
        cta_id: Optional[int] = None,
        sm_id: Optional[int] = None,
    ) -> None:
        self.space = space
        self.base = int(base)
        self.size = int(size)
        self.start_event_index = start_event_index
        self.end_event_index = end_event_index
        self.start_cycle = start_cycle
        self.end_cycle = end_cycle
        self.thread_id = thread_id
        self.cta_id = cta_id
        self.sm_id = sm_id

    def contains(self, addr: int) -> bool:
        if self.size <= 0:
            return False
        lo = self.base
        hi = self.base + self.size
        return lo <= addr < hi

    def contains_access(self, addr: int, size_bytes: int) -> bool:
        if self.size <= 0 or size_bytes <= 0:
            return False
        lo = self.base
        hi = self.base + self.size
        end = addr + size_bytes
        return lo <= addr and end <= hi

    def active_for_event(self, ev: "TraceEvent") -> bool:
        if canonical_space(self.space) != canonical_space(ev.mem_space):
            return False
        if self.start_event_index is not None and ev.index < self.start_event_index:
            return False
        if self.end_event_index is not None and ev.index >= self.end_event_index:
            return False
        if self.start_cycle is not None:
            if ev.cycle is None or ev.cycle < self.start_cycle:
                return False
        if self.end_cycle is not None:
            if ev.cycle is None or ev.cycle >= self.end_cycle:
                return False
        if self.thread_id is not None and ev.thread_id != self.thread_id:
            return False
        if self.cta_id is not None and ev.cta_id != self.cta_id:
            return False
        if self.sm_id is not None and ev.sm_id != self.sm_id:
            return False
        return True


class OutputRangeSpec:
    __slots__ = ("space", "base", "size", "name")

    space: str
    base: int
    size: int
    name: Optional[str]

    def __init__(
        self,
        space: str,
        base: int,
        size: int,
        name: Optional[str] = None,
    ) -> None:
        self.space = space
        self.base = int(base)
        self.size = int(size)
        self.name = name


@dataclass
class TraceEvent:
    __slots__ = (
        "index",
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
        "mem_space",
        "mem_addr_effective_bits",
        "mem_addr_mask",
        "mem_access_size_bytes",
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
        "recorded_branch_taken",
        "next_pc",
        "taken_target_pc",
        "fallthrough_pc",
        "branch_target_pc",
        "address_observed",
        "cycle",
        "sm_id",
        "cta_id",
        "warp_id",
    )

    index: int
    thread_id: int
    kind: str
    pc: str
    opcode: str
    width_bits: int
    src_regs: List[str]
    src_vals: List[int]
    src_width_bits: List[int]
    src_reg_uids: List[int]
    dst_reg: Optional[str]
    dst_reg_uid: Optional[int]
    dst_val: Optional[int]
    dst_old_val: Optional[int]
    dst_write_mask: Optional[int]
    pred: Optional[PredInfo]
    mem_addr: Optional[int]
    mem_space: Optional[str]
    mem_addr_effective_bits: Optional[int]
    mem_addr_mask: Optional[int]
    mem_access_size_bytes: Optional[int]
    store_size_bytes: Optional[int]
    store_data_src_index: int
    store_data_byte_offset: int
    is_output_store: bool
    ea_base_src_indices: List[int]
    ea_const_offset: int
    ea_width_bits: int
    ea_expr: Optional[EAExpr]
    control_expr: Optional[EAExpr]
    control_const_offset: int
    recorded_branch_taken: Optional[bool]
    next_pc: Optional[str]
    taken_target_pc: Optional[str]
    fallthrough_pc: Optional[str]
    branch_target_pc: Optional[str]
    address_observed: Optional[bool]
    cycle: Optional[int]
    sm_id: Optional[int]
    cta_id: Optional[int]
    warp_id: Optional[int]


def _is_basic_block_transfer_event(ev: TraceEvent) -> bool:
    """True for events whose backward transfer is register-local and reorder-safe.

    These events do not read/write memory, do not alter control-flow state, and
    are not predicated.  A per-thread run of such events can be summarized as a
    basic-block transfer because interleaved events from other threads cannot
    observe or mutate this thread's register liveness state.
    """

    return (
        ev.kind not in ("store", "load", "branch", "loop_branch")
        and ev.dst_reg is not None
        and ev.pred is None
    )


def _build_basic_block_transfer_maps(
    events: Sequence[TraceEvent],
    *,
    min_len: int,
) -> Tuple[Dict[int, Tuple[TraceEvent, ...]], Dict[int, int]]:
    """Build per-thread pure-register block maps keyed by global event position.

    The analyzer walks ``events`` in reverse global order.  For each thread we
    group consecutive pure-register events in that thread's own dynamic stream,
    even if other threads are interleaved in the global stream.  This is exact
    because these blocks only touch the owning thread's register state.
    """

    min_len_i = max(2, int(min_len))
    open_blocks: Dict[int, List[int]] = {}
    block_end_to_events: Dict[int, Tuple[TraceEvent, ...]] = {}
    block_member_to_end: Dict[int, int] = {}

    def finish_thread_block(thread_id: int) -> None:
        positions = open_blocks.get(thread_id)
        if not positions:
            open_blocks[thread_id] = []
            return
        if len(positions) >= min_len_i:
            end_pos = int(positions[-1])
            block_end_to_events[end_pos] = tuple(events[pos] for pos in positions)
            for pos in positions:
                block_member_to_end[int(pos)] = end_pos
        open_blocks[thread_id] = []

    for pos, ev in enumerate(events):
        thread_id = int(ev.thread_id)
        if _is_basic_block_transfer_event(ev):
            open_blocks.setdefault(thread_id, []).append(int(pos))
        else:
            finish_thread_block(thread_id)

    for thread_id in list(open_blocks.keys()):
        finish_thread_block(int(thread_id))

    return block_end_to_events, block_member_to_end


@dataclass(frozen=True)
class EAAnalysis:
    expr: Optional[EAExpr]
    effective_mask: int
    expr_width_bits: int
    base_raw_ea: int
    base_effective_ea: int
    src_indices: Tuple[int, ...]
    src_width_bits: Tuple[int, ...]

@lru_cache(maxsize=4096)
def _canonical_op_cached(opcode: str) -> str:
    op = opcode.strip().lower()
    op = op.split()[0] if op else op
    if "," in op:
        op = op.split(",", 1)[0]
    if "%" in op:
        op = op.split("%", 1)[0]
    if ";" in op:
        op = op.split(";", 1)[0]

    exact = {
        "add": "ADD",
        "add_f32": "ADD_F32",
        "div_f32": "DIV_F32",
        "sqrt_f32": "SQRT_F32",
        "sub": "SUB",
        "sub_f32": "SUB_F32",
        "neg": "NEG",
        "neg_f32": "NEG_F32",
        "mul_lo": "MUL_LO",
        "mul_f32": "MUL_F32",
        "mul_wide_u32": "MUL_WIDE_U32",
        "mul_wide_s32": "MUL_WIDE_S32",
        "mad": "MAD",
        "fma_f32": "FMA_F32",
        "abs_f32": "ABS_F32",
        "ex2_approx_ftz_f32": "EX2_APPROX_FTZ_F32",
        "rcp_approx_ftz_f32": "RCP_APPROX_FTZ_F32",
        "min_f32": "MIN_F32",
        "max_f32": "MAX_F32",
        "and": "AND",
        "or": "OR",
        "xor": "XOR",
        "shl": "SHL",
        "shr_u": "SHR_U",
        "shr_s": "SHR_S",
        "min_u": "MIN_U",
        "min_s": "MIN_S",
        "max_u": "MAX_U",
        "max_s": "MAX_S",
        "cvt_u32_u64": "CVT_U32_U64",
        "cvt_u64_u32": "CVT_U64_U32",
        "cvt_s32_s64": "CVT_S32_S64",
        "cvt_s64_s32": "CVT_S64_S32",
        "cvt_sat_f32_f32": "CVT_SAT_F32_F32",
        "setp_eq": "SETP_EQ",
        "setp_ne": "SETP_NE",
        "setp_lt_u": "SETP_LT_U",
        "setp_lt_s": "SETP_LT_S",
        "setp_le_u": "SETP_LE_U",
        "setp_le_s": "SETP_LE_S",
        "setp_gt_u": "SETP_GT_U",
        "setp_gt_s": "SETP_GT_S",
        "setp_ge_u": "SETP_GE_U",
        "setp_ge_s": "SETP_GE_S",
        "setp_eq_f16": "SETP_EQ_F16",
        "setp_ne_f16": "SETP_NE_F16",
        "setp_lt_f16": "SETP_LT_F16",
        "setp_le_f16": "SETP_LE_F16",
        "setp_gt_f16": "SETP_GT_F16",
        "setp_ge_f16": "SETP_GE_F16",
        "setp_ltu_f16": "SETP_LTU_F16",
        "setp_leu_f16": "SETP_LEU_F16",
        "setp_gtu_f16": "SETP_GTU_F16",
        "setp_geu_f16": "SETP_GEU_F16",
        "setp_eq_f32": "SETP_EQ_F32",
        "setp_ne_f32": "SETP_NE_F32",
        "setp_lt_f32": "SETP_LT_F32",
        "setp_le_f32": "SETP_LE_F32",
        "setp_gt_f32": "SETP_GT_F32",
        "setp_ge_f32": "SETP_GE_F32",
        "setp_ltu_f32": "SETP_LTU_F32",
        "setp_leu_f32": "SETP_LEU_F32",
        "setp_gtu_f32": "SETP_GTU_F32",
        "setp_geu_f32": "SETP_GEU_F32",
        "setp_eq_f64": "SETP_EQ_F64",
        "setp_ne_f64": "SETP_NE_F64",
        "setp_lt_f64": "SETP_LT_F64",
        "setp_le_f64": "SETP_LE_F64",
        "setp_gt_f64": "SETP_GT_F64",
        "setp_ge_f64": "SETP_GE_F64",
        "setp_ltu_f64": "SETP_LTU_F64",
        "setp_leu_f64": "SETP_LEU_F64",
        "setp_gtu_f64": "SETP_GTU_F64",
        "setp_geu_f64": "SETP_GEU_F64",
        "selp": "SELP",
        "popc": "POPC",
        "clz": "CLZ",
        "brev": "BREV",
        "bfe_u": "BFE_U",
        "bfe_s": "BFE_S",
        "lop3": "LOP3",
        "identity": "IDENTITY",
        "addr_sum": "ADDR_SUM",
    }
    if op in exact:
        return exact[op]

    if op.startswith("mul.lo"):
        return "MUL_LO"
    if op.startswith("div") and ".f32" in op:
        return "DIV_F32"
    if op.startswith("sqrt") and ".f32" in op:
        return "SQRT_F32"
    if op.startswith("add") and ".f32" in op:
        return "ADD_F32"
    if op.startswith("sub") and ".f32" in op:
        return "SUB_F32"
    if op.startswith("neg") and ".f32" in op:
        return "NEG_F32"
    if op.startswith("mul") and ".f32" in op:
        return "MUL_F32"
    if op.startswith("mul.wide"):
        if ".s32" in op:
            return "MUL_WIDE_S32"
        return "MUL_WIDE_U32"
    if op.startswith("mov"):
        return "IDENTITY"
    if op.startswith("cvta"):
        return "IDENTITY"
    if op.startswith("mad"):
        return "MAD"
    if op.startswith("fma") and ".f32" in op:
        return "FMA_F32"
    if op.startswith("abs") and ".f32" in op:
        return "ABS_F32"
    if op.startswith("ex2") and ".f32" in op:
        return "EX2_APPROX_FTZ_F32"
    if op.startswith("rcp") and ".f32" in op:
        return "RCP_APPROX_FTZ_F32"
    if op.startswith("min") and ".f32" in op:
        return "MIN_F32"
    if op.startswith("max") and ".f32" in op:
        return "MAX_F32"
    if op.startswith("add"):
        return "ADD"
    if op.startswith("sub"):
        return "SUB"
    if op.startswith("neg"):
        return "NEG"
    if op.startswith("not"):
        if ".pred" in op:
            return "NOT_PRED"
        return "NOT"
    if op.startswith("and"):
        return "AND"
    if op.startswith("or"):
        return "OR"
    if op.startswith("xor"):
        return "XOR"
    if op.startswith("shl"):
        return "SHL"
    if op.startswith("shr"):
        if ".s" in op:
            return "SHR_S"
        return "SHR_U"
    if op.startswith("min"):
        if ".s" in op:
            return "MIN_S"
        return "MIN_U"
    if op.startswith("max"):
        if ".s" in op:
            return "MAX_S"
        return "MAX_U"
    if op.startswith("popc"):
        return "POPC"
    if op.startswith("clz"):
        return "CLZ"
    if op.startswith("brev"):
        return "BREV"
    if op.startswith("bfe"):
        if ".s" in op:
            return "BFE_S"
        return "BFE_U"
    if op.startswith("lop3"):
        return "LOP3"
    if op.startswith("setp"):
        tokens = [tok for tok in op.split(".") if tok]
        cmp_kind = None
        value_kind = "unsigned"
        value_width_bits: Optional[int] = None
        for tok in tokens[1:]:
            if cmp_kind is None and tok in SETP_COMPARATORS:
                cmp_kind = tok
                continue
            if len(tok) >= 2 and tok[0] in ("s", "u", "f", "b") and tok[1:].isdigit():
                value_width_bits = int(tok[1:])
                if tok[0] == "s":
                    value_kind = "signed"
                elif tok[0] == "f":
                    value_kind = "float"
                else:
                    value_kind = "unsigned"
        if cmp_kind is None:
            for candidate in _SETP_COMPARATOR_ORDER:
                if f".{candidate}" in op or f"_{candidate}_" in op:
                    cmp_kind = candidate
                    break
        if cmp_kind is not None:
            cmp_upper = cmp_kind.upper()
            if value_kind == "float":
                width = value_width_bits if value_width_bits in (16, 32, 64) else 32
                return f"SETP_{cmp_upper}_F{width}"
            if cmp_kind in ("eq", "ne"):
                return f"SETP_{cmp_upper}"
            if cmp_kind in ("ltu", "leu", "gtu", "geu"):
                return f"SETP_{cmp_upper[:-1]}_U"
            suffix = "S" if value_kind == "signed" else "U"
            return f"SETP_{cmp_upper}_{suffix}"
    if op.startswith("cvt"):
        if ".sat" in op and ".f32.f32" in op:
            return "CVT_SAT_F32_F32"
        if ".u64.u32" in op:
            return "CVT_U32_U64"
        if ".u32.u64" in op:
            return "CVT_U64_U32"
        if ".s64.s32" in op:
            return "CVT_S32_S64"
        if ".s32.s64" in op:
            return "CVT_S64_S32"
    if op.startswith("selp"):
        return "SELP"

    return opcode.strip().upper()


def canonical_op(opcode: str) -> str:
    return _canonical_op_cached(_text(opcode))


def expected_src_count(op: str) -> int:
    op = _text(op)
    if op == "IDENTITY":
        return 1
    if _text_in(op, ("NEG", "NEG_F32", "SQRT_F32")):
        return 1
    if _text_in(op, ("NOT", "NOT_PRED", "POPC", "CLZ", "BREV")):
        return 1
    if _text_in(op, ("MAD", "SELP", "FMA_F32", "BFE_U", "BFE_S")):
        return 3
    if op == "LOP3":
        return 4
    if _text_in(
        op,
        (
        "CVT_U32_U64",
        "CVT_U64_U32",
        "CVT_S32_S64",
        "CVT_S64_S32",
        "CVT_SAT_F32_F32",
        ),
    ):
        return 1
    if _text_in(op, ("ABS_F32", "EX2_APPROX_FTZ_F32", "RCP_APPROX_FTZ_F32")):
        return 1
    return 2


@lru_cache(maxsize=512)
def _dst_width_bits_cached(op: str, default_width: int) -> int:
    if op == "NOT_PRED":
        return 1
    if _text_startswith(op, "SETP_"):
        return 1
    if op == "POPC" or op == "CLZ":
        return 32
    if op == "CVT_U32_U64" or op == "CVT_S32_S64":
        return 64
    if op == "CVT_U64_U32" or op == "CVT_S64_S32":
        return 32
    if op == "MUL_WIDE_U32" or op == "MUL_WIDE_S32":
        return 64
    return default_width


def dst_width_bits(op: str, default_width: int) -> int:
    return _dst_width_bits_cached(_text(op), _BUILTIN_INT(default_width))


@lru_cache(maxsize=256)
def _default_src_width_bits_cached(op: str, default_width: int, src_index: int) -> int:
    op = _text(op)
    default_width = _BUILTIN_INT(default_width)
    src_index = _BUILTIN_INT(src_index)
    if op == "CVT_U32_U64" or op == "CVT_S32_S64":
        return 32
    if op == "CVT_U64_U32" or op == "CVT_S64_S32":
        return 64
    if op == "SELP" and src_index == 2:
        return 1
    if op == "LOP3" and src_index == 3:
        return 8
    if (op == "BFE_U" or op == "BFE_S") and (src_index == 1 or src_index == 2):
        return 32
    if op == "MUL_WIDE_U32" or op == "MUL_WIDE_S32":
        return 32
    return default_width


def default_src_width_bits(op: str, default_width: int, src_index: int) -> int:
    return _default_src_width_bits_cached(
        _text(op),
        _BUILTIN_INT(default_width),
        _BUILTIN_INT(src_index),
    )


@lru_cache(maxsize=1048576)
def _bits_to_f32_u32(value: int) -> float:
    return struct.unpack("<f", struct.pack("<I", int(value) & 0xFFFFFFFF))[0]


@lru_cache(maxsize=1048576)
def _f32_to_bits_u32(value: float) -> int:
    v = float(value)
    if math.isnan(v):
        return 0x7FC00000
    if math.isinf(v):
        return 0x7F800000 if v > 0.0 else 0xFF800000
    try:
        return struct.unpack("<I", struct.pack("<f", v))[0]
    except OverflowError:
        return 0x7F800000 if v > 0.0 else 0xFF800000


def _flush_subnormal_f32(value: float) -> float:
    if value == 0.0 or math.isnan(value) or math.isinf(value):
        return value
    if abs(value) < 2.0 ** -126:
        return math.copysign(0.0, value)
    return value


def _as_f32(value: float) -> float:
    return _bits_to_f32_u32(_f32_to_bits_u32(value))


def _fmin_f32(a: float, b: float) -> float:
    if math.isnan(a):
        return float(b)
    if math.isnan(b):
        return float(a)
    if a == b:
        if a == 0.0:
            if math.copysign(1.0, a) < 0.0 or math.copysign(1.0, b) < 0.0:
                return -0.0
            return 0.0
        return float(a)
    return float(a) if a < b else float(b)


def _fmax_f32(a: float, b: float) -> float:
    if math.isnan(a):
        return float(b)
    if math.isnan(b):
        return float(a)
    if a == b:
        if a == 0.0:
            if math.copysign(1.0, a) > 0.0 or math.copysign(1.0, b) > 0.0:
                return 0.0
            return -0.0
        return float(a)
    return float(a) if a > b else float(b)


def _eval_canonical_float_setp(op: str, src_vals: List[int]) -> Optional[int]:
    op = _text(op)
    match = re.fullmatch(
        r"SETP_(EQ|NE|LTU|LEU|GTU|GEU|LT|LE|GT|GE)_F(16|32|64)",
        op,
    )
    if match is None:
        return None
    if len(src_vals) != 2:
        raise KeyError(op)
    cmp_kind = match.group(1).lower()
    width_bits = int(match.group(2))
    mask = width_mask(width_bits)
    lhs = bits_to_float_value(int(src_vals[0]) & mask, width_bits)
    rhs = bits_to_float_value(int(src_vals[1]) & mask, width_bits)
    return 1 if _setp_compare_predicate(cmp_kind, lhs, rhs) else 0


def eval_op(op: str, src_vals: List[int], width_bits_default: int) -> int:
    if type(op) is not str:
        op = _text(op)
    w = width_bits_default if type(width_bits_default) is int else _BUILTIN_INT(width_bits_default)
    mask = width_mask(w)

    if op == "IDENTITY":
        if not src_vals:
            return 0
        return src_vals[0] & mask
    if op == "ADD":
        return (src_vals[0] + src_vals[1]) & mask
    if op == "ADD_F32":
        a = _bits_to_f32_u32(src_vals[0])
        b = _bits_to_f32_u32(src_vals[1])
        return _f32_to_bits_u32(a + b)
    if op == "DIV_F32":
        a = _bits_to_f32_u32(src_vals[0])
        b = _bits_to_f32_u32(src_vals[1])
        if math.isnan(a) or math.isnan(b):
            out = float("nan")
        elif a == 0.0 and b == 0.0:
            out = float("nan")
        elif math.isinf(a) and math.isinf(b):
            out = float("nan")
        elif b == 0.0:
            out = math.copysign(float("inf"), a * b)
        else:
            out = a / b
        return _f32_to_bits_u32(out)
    if op == "SQRT_F32":
        a = _bits_to_f32_u32(src_vals[0])
        if math.isnan(a) or a < 0.0:
            out = float("nan")
        else:
            out = math.sqrt(a)
        return _f32_to_bits_u32(out)
    if op == "SUB":
        return (src_vals[0] - src_vals[1]) & mask
    if op == "SUB_F32":
        a = _bits_to_f32_u32(src_vals[0])
        b = _bits_to_f32_u32(src_vals[1])
        return _f32_to_bits_u32(a - b)
    if op == "NEG":
        return (-src_vals[0]) & mask
    if op == "NEG_F32":
        a = _bits_to_f32_u32(src_vals[0])
        return _f32_to_bits_u32(-a)
    if op == "NOT":
        return (~src_vals[0]) & mask
    if op == "NOT_PRED":
        return 0 if (src_vals[0] & 1) else 1
    if op == "POPC":
        return popcount(src_vals[0] & mask) & width_mask(32)
    if op == "CLZ":
        value = src_vals[0] & mask
        if value == 0:
            return w & width_mask(32)
        return (w - int(value.bit_length())) & width_mask(32)
    if op == "BREV":
        value = src_vals[0] & mask
        out = 0
        for bit in range(w):
            if value & (1 << bit):
                out |= 1 << (w - 1 - bit)
        return out & mask
    if op == "BFE_U" or op == "BFE_S":
        value = src_vals[0] & mask
        start = _BUILTIN_INT(src_vals[1]) & 0xFF
        length = _BUILTIN_INT(src_vals[2]) & 0xFF
        if length <= 0 or start >= w:
            return 0
        length = _BUILTIN_MIN(length, w - start, w)
        field = (value >> start) & width_mask(length)
        if op == "BFE_S" and length > 0 and (field & (1 << (length - 1))):
            field |= mask ^ width_mask(length)
        return field & mask
    if op == "LOP3":
        imm = int(src_vals[3]) & 0xFF if len(src_vals) > 3 else 0
        a = int(src_vals[0]) & mask
        b = int(src_vals[1]) & mask
        c = int(src_vals[2]) & mask
        out = 0
        for bit in range(w):
            idx = (1 if (a >> bit) & 1 else 0)
            idx |= (2 if (b >> bit) & 1 else 0)
            idx |= (4 if (c >> bit) & 1 else 0)
            if (imm >> idx) & 1:
                out |= 1 << bit
        return out & mask
    if op == "MUL_LO":
        return (src_vals[0] * src_vals[1]) & mask
    if op == "MUL_F32":
        a = _bits_to_f32_u32(src_vals[0])
        b = _bits_to_f32_u32(src_vals[1])
        return _f32_to_bits_u32(a * b)
    if op == "MUL_WIDE_U32":
        return ((src_vals[0] & 0xFFFFFFFF) * (src_vals[1] & 0xFFFFFFFF)) & UINT64_MASK
    if op == "MUL_WIDE_S32":
        return (to_signed(src_vals[0], 32) * to_signed(src_vals[1], 32)) & UINT64_MASK
    if op == "MAD":
        return (src_vals[0] * src_vals[1] + src_vals[2]) & mask
    if op == "FMA_F32":
        a = _bits_to_f32_u32(src_vals[0])
        b = _bits_to_f32_u32(src_vals[1])
        c = _bits_to_f32_u32(src_vals[2])
        try:
            out = math.fma(a, b, c)
        except AttributeError:
            # Fallback on runtimes without math.fma.
            out = a * b + c
        return _f32_to_bits_u32(out)
    if op == "ABS_F32":
        a = _bits_to_f32_u32(src_vals[0])
        return _f32_to_bits_u32(abs(a))
    if op == "EX2_APPROX_FTZ_F32":
        a = _bits_to_f32_u32(src_vals[0])
        try:
            out = math.pow(2.0, float(a))
        except OverflowError:
            out = float("inf")
        return _f32_to_bits_u32(_flush_subnormal_f32(out))
    if op == "RCP_APPROX_FTZ_F32":
        a = _bits_to_f32_u32(src_vals[0])
        if a == 0.0:
            out = math.copysign(float("inf"), a)
        else:
            out = 1.0 / float(a)
        return _f32_to_bits_u32(_flush_subnormal_f32(out))
    if op == "MIN_F32":
        a = _bits_to_f32_u32(src_vals[0])
        b = _bits_to_f32_u32(src_vals[1])
        return _f32_to_bits_u32(_fmin_f32(a, b))
    if op == "MAX_F32":
        a = _bits_to_f32_u32(src_vals[0])
        b = _bits_to_f32_u32(src_vals[1])
        return _f32_to_bits_u32(_fmax_f32(a, b))
    if op == "AND":
        return (src_vals[0] & src_vals[1]) & mask
    if op == "OR":
        return (src_vals[0] | src_vals[1]) & mask
    if op == "XOR":
        return (src_vals[0] ^ src_vals[1]) & mask
    if op == "SHL":
        sh = src_vals[1] & (w - 1)
        return (src_vals[0] << sh) & mask
    if op == "SHR_U":
        sh = src_vals[1] & (w - 1)
        return (src_vals[0] & mask) >> sh
    if op == "SHR_S":
        sh = src_vals[1] & (w - 1)
        return to_signed(src_vals[0], w) >> sh & mask
    if op == "MIN_U":
        return min(src_vals[0] & mask, src_vals[1] & mask)
    if op == "MIN_S":
        return (
            to_signed(src_vals[0], w)
            if to_signed(src_vals[0], w) < to_signed(src_vals[1], w)
            else to_signed(src_vals[1], w)
        ) & mask
    if op == "MAX_U":
        return max(src_vals[0] & mask, src_vals[1] & mask)
    if op == "MAX_S":
        return (
            to_signed(src_vals[0], w)
            if to_signed(src_vals[0], w) > to_signed(src_vals[1], w)
            else to_signed(src_vals[1], w)
        ) & mask
    if op == "CVT_U32_U64":
        return src_vals[0] & 0xFFFFFFFF
    if op == "CVT_U64_U32":
        return src_vals[0] & 0xFFFFFFFF
    if op == "CVT_S32_S64":
        return to_signed(src_vals[0], 32) & UINT64_MASK
    if op == "CVT_S64_S32":
        return src_vals[0] & 0xFFFFFFFF
    if op == "CVT_SAT_F32_F32":
        a = _bits_to_f32_u32(src_vals[0])
        if math.isnan(a):
            return 0x7FFFFFFF
        if a < 0.0:
            a = 0.0
        elif a > 1.0:
            a = 1.0
        return _f32_to_bits_u32(a)
    float_setp = _eval_canonical_float_setp(op, src_vals)
    if float_setp is not None:
        return int(float_setp)
    if op == "SETP_EQ":
        return 1 if (src_vals[0] & mask) == (src_vals[1] & mask) else 0
    if op == "SETP_NE":
        return 1 if (src_vals[0] & mask) != (src_vals[1] & mask) else 0
    if op == "SETP_LT_U":
        return 1 if (src_vals[0] & mask) < (src_vals[1] & mask) else 0
    if op == "SETP_LT_S":
        return 1 if to_signed(src_vals[0], w) < to_signed(src_vals[1], w) else 0
    if op == "SETP_LE_U":
        return 1 if (src_vals[0] & mask) <= (src_vals[1] & mask) else 0
    if op == "SETP_LE_S":
        return 1 if to_signed(src_vals[0], w) <= to_signed(src_vals[1], w) else 0
    if op == "SETP_GT_U":
        return 1 if (src_vals[0] & mask) > (src_vals[1] & mask) else 0
    if op == "SETP_GT_S":
        return 1 if to_signed(src_vals[0], w) > to_signed(src_vals[1], w) else 0
    if op == "SETP_GE_U":
        return 1 if (src_vals[0] & mask) >= (src_vals[1] & mask) else 0
    if op == "SETP_GE_S":
        return 1 if to_signed(src_vals[0], w) >= to_signed(src_vals[1], w) else 0
    if op == "SELP":
        return (src_vals[0] if (src_vals[2] & 1) else src_vals[1]) & mask

    raise KeyError(op)


@lru_cache(maxsize=1048576)
def eval_op_cached(op: str, src_vals: Tuple[int, ...], width_bits_default: int) -> int:
    return eval_op(op, src_vals, int(width_bits_default))


@lru_cache(maxsize=4096)
def _parse_setp_signature_cached(opcode: str) -> Tuple[str, str, Optional[int]]:
    op = normalize_opcode(opcode)
    if not _text_startswith(op, "setp"):
        raise NotImplementedError(f"not a setp opcode: {opcode}")

    tokens = [tok for tok in op.split(".") if tok]
    cmp_kind: Optional[str] = None
    value_kind: Optional[str] = None
    value_width_bits: Optional[int] = None

    for tok in tokens[1:]:
        if cmp_kind is None and tok in SETP_COMPARATORS:
            cmp_kind = tok
            continue
        if len(tok) >= 2 and _text_in(tok[0], ("s", "u", "f", "b")) and tok[1:].isdigit():
            value_width_bits = int(tok[1:])
            if tok[0] == "s":
                value_kind = "signed"
            elif tok[0] == "f":
                value_kind = "float"
            else:
                value_kind = "unsigned"

    if cmp_kind is None:
        raise NotImplementedError(f"setp compare kind missing in opcode: {opcode}")

    if value_kind is None:
        canonical = canonical_op(opcode)
        if canonical.endswith("_S"):
            value_kind = "signed"
        elif canonical.endswith("_U"):
            value_kind = "unsigned"
        else:
            # For eq/ne without explicit type token, integer compare remains valid.
            value_kind = "unsigned"

    return cmp_kind, value_kind, value_width_bits


def parse_setp_signature(opcode: str) -> Tuple[str, str, Optional[int]]:
    return _parse_setp_signature_cached(_text(opcode))


def bits_to_float_value(value: int, width_bits: int) -> float:
    value = _BUILTIN_INT(value)
    width_bits = _BUILTIN_INT(width_bits)
    if width_bits == 16:
        try:
            return struct.unpack("<e", struct.pack("<H", value & 0xFFFF))[0]
        except struct.error as exc:
            raise NotImplementedError("setp float16 is not supported in this Python runtime") from exc
    if width_bits == 32:
        return struct.unpack("<f", struct.pack("<I", value & 0xFFFFFFFF))[0]
    if width_bits == 64:
        return struct.unpack("<d", struct.pack("<Q", value & UINT64_MASK))[0]
    raise NotImplementedError(f"unsupported float width_bits={width_bits}")


def eval_setp_predicate(
    opcode: str,
    src_vals: List[int],
    src_width_bits: List[int],
) -> int:
    cmp_kind, value_kind, parsed_width = parse_setp_signature(opcode)
    if len(src_vals) != 2:
        raise NotImplementedError(
            f"setp variants with src_count={len(src_vals)} are not supported for control-taint eval: opcode={opcode}"
        )

    width_bits = parsed_width
    if width_bits is None or width_bits <= 0:
        inferred = [
            coerce_width_bits(src_width_bits[i], default=0)
            for i in range(min(2, len(src_width_bits)))
            if coerce_width_bits(src_width_bits[i], default=0) > 0
        ]
        width_bits = max(inferred) if inferred else 32
    width_bits = coerce_positive_width_bits(width_bits, default=32)
    mask = width_mask(width_bits)

    lhs_raw = src_vals[0] & mask
    rhs_raw = src_vals[1] & mask

    if value_kind == "float":
        lhs = bits_to_float_value(lhs_raw, width_bits)
        rhs = bits_to_float_value(rhs_raw, width_bits)
    elif value_kind == "signed":
        lhs = to_signed(lhs_raw, width_bits)
        rhs = to_signed(rhs_raw, width_bits)
    else:
        lhs = lhs_raw
        rhs = rhs_raw

    if cmp_kind == "eq":
        pred = lhs == rhs
    elif cmp_kind == "ne":
        pred = lhs != rhs
    elif cmp_kind == "lt":
        pred = lhs < rhs
    elif cmp_kind == "ltu":
        pred = (lhs < rhs) or (math.isnan(lhs) or math.isnan(rhs))
    elif cmp_kind == "le":
        pred = lhs <= rhs
    elif cmp_kind == "leu":
        pred = (lhs <= rhs) or (math.isnan(lhs) or math.isnan(rhs))
    elif cmp_kind == "gt":
        pred = lhs > rhs
    elif cmp_kind == "gtu":
        pred = (lhs > rhs) or (math.isnan(lhs) or math.isnan(rhs))
    elif cmp_kind == "ge":
        pred = lhs >= rhs
    elif cmp_kind == "geu":
        pred = (lhs >= rhs) or (math.isnan(lhs) or math.isnan(rhs))
    else:
        raise NotImplementedError(
            f"unsupported setp compare kind '{cmp_kind}' for opcode={opcode}"
        )

    return 1 if pred else 0


def _resolve_setp_eval_shape(
    opcode: str,
    src_width_bits: List[int],
) -> Tuple[str, str, int]:
    cmp_kind, value_kind, parsed_width = parse_setp_signature(opcode)
    width_bits = parsed_width
    if width_bits is None or width_bits <= 0:
        inferred = [
            coerce_width_bits(src_width_bits[i], default=0)
            for i in range(min(2, len(src_width_bits)))
            if coerce_width_bits(src_width_bits[i], default=0) > 0
        ]
        width_bits = max(inferred) if inferred else 32
    width_bits = coerce_positive_width_bits(width_bits, default=32)
    return cmp_kind, value_kind, width_bits


def _setp_compare_predicate(cmp_kind: str, lhs: Any, rhs: Any) -> bool:
    if cmp_kind == "eq":
        return lhs == rhs
    if cmp_kind == "ne":
        return lhs != rhs
    if cmp_kind == "lt":
        return lhs < rhs
    if cmp_kind == "ltu":
        return (lhs < rhs) or (math.isnan(lhs) or math.isnan(rhs))
    if cmp_kind == "le":
        return lhs <= rhs
    if cmp_kind == "leu":
        return (lhs <= rhs) or (math.isnan(lhs) or math.isnan(rhs))
    if cmp_kind == "gt":
        return lhs > rhs
    if cmp_kind == "gtu":
        return (lhs > rhs) or (math.isnan(lhs) or math.isnan(rhs))
    if cmp_kind == "ge":
        return lhs >= rhs
    if cmp_kind == "geu":
        return (lhs >= rhs) or (math.isnan(lhs) or math.isnan(rhs))
    raise NotImplementedError(f"unsupported setp compare kind '{cmp_kind}'")


def _toggle_bit_with_wrap(raw: int, bit: int, mask: int) -> int:
    delta = 1 << bit
    if raw & delta:
        return (raw - delta) & mask
    return (raw + delta) & mask


def _setp_cast_operand(raw: int, width_bits: int, value_kind: str) -> Any:
    if value_kind == "float":
        return bits_to_float_value(raw, width_bits)
    if value_kind == "signed":
        return to_signed(raw, width_bits)
    return raw


def _setp_toggle_mask_bruteforce_fields(
    *,
    cmp_kind: str,
    value_kind: str,
    width_bits: int,
    lhs_raw: int,
    rhs_raw: int,
) -> Tuple[int, int]:
    mask = width_mask(width_bits)
    lhs_raw &= mask
    rhs_raw &= mask
    lhs_base = _setp_cast_operand(lhs_raw, width_bits, value_kind)
    rhs_base = _setp_cast_operand(rhs_raw, width_bits, value_kind)
    baseline = _setp_compare_predicate(cmp_kind, lhs_base, rhs_base)

    lhs_toggle_mask = 0
    rhs_toggle_mask = 0
    for bit in range(width_bits):
        bit_mask = 1 << bit

        lhs_prime_raw = _toggle_bit_with_wrap(lhs_raw, bit, mask)
        lhs_prime = _setp_cast_operand(lhs_prime_raw, width_bits, value_kind)
        if _setp_compare_predicate(cmp_kind, lhs_prime, rhs_base) != baseline:
            lhs_toggle_mask |= bit_mask

        rhs_prime_raw = _toggle_bit_with_wrap(rhs_raw, bit, mask)
        rhs_prime = _setp_cast_operand(rhs_prime_raw, width_bits, value_kind)
        if _setp_compare_predicate(cmp_kind, lhs_base, rhs_prime) != baseline:
            rhs_toggle_mask |= bit_mask

    return lhs_toggle_mask & mask, rhs_toggle_mask & mask


def _setp_toggle_mask_integer_fields(
    *,
    cmp_kind: str,
    value_kind: str,
    width_bits: int,
    lhs_raw: int,
    rhs_raw: int,
) -> Tuple[int, int]:
    mask = width_mask(width_bits)
    lhs_raw &= mask
    rhs_raw &= mask
    lhs_base = (
        to_signed(lhs_raw, width_bits) if value_kind == "signed" else lhs_raw
    )
    rhs_base = (
        to_signed(rhs_raw, width_bits) if value_kind == "signed" else rhs_raw
    )
    baseline = _setp_compare_predicate(cmp_kind, lhs_base, rhs_base)

    if cmp_kind in ("eq", "ne"):
        xor_bits = lhs_raw ^ rhs_raw
        single_bit_mask = xor_bits if popcount(xor_bits) == 1 else 0
        if cmp_kind == "eq":
            if baseline:
                return mask, mask
            return single_bit_mask & mask, single_bit_mask & mask
        if baseline:
            return single_bit_mask & mask, single_bit_mask & mask
        return mask, mask

    lhs_toggle_mask = 0
    rhs_toggle_mask = 0
    for bit in range(width_bits):
        bit_mask = 1 << bit

        lhs_prime_raw = _toggle_bit_with_wrap(lhs_raw, bit, mask)
        lhs_prime = (
            to_signed(lhs_prime_raw, width_bits)
            if value_kind == "signed"
            else lhs_prime_raw
        )
        if _setp_compare_predicate(cmp_kind, lhs_prime, rhs_base) != baseline:
            lhs_toggle_mask |= bit_mask

        rhs_prime_raw = _toggle_bit_with_wrap(rhs_raw, bit, mask)
        rhs_prime = (
            to_signed(rhs_prime_raw, width_bits)
            if value_kind == "signed"
            else rhs_prime_raw
        )
        if _setp_compare_predicate(cmp_kind, lhs_base, rhs_prime) != baseline:
            rhs_toggle_mask |= bit_mask

    return lhs_toggle_mask & mask, rhs_toggle_mask & mask


@lru_cache(maxsize=_TOGGLE_SETPCACHE_MAXSIZE)
def _cached_setp_toggle(
    opcode_norm: str,
    lhs_raw: int,
    rhs_raw: int,
    width_bits: int,
    value_kind: str,
    cmp_kind: str,
) -> Tuple[int, int]:
    mask = width_mask(width_bits)
    lhs = int(lhs_raw) & mask
    rhs = int(rhs_raw) & mask
    if value_kind in ("signed", "unsigned") and cmp_kind in (
        "eq",
        "ne",
        "lt",
        "le",
        "gt",
        "ge",
    ):
        return _setp_toggle_mask_integer_fields(
            cmp_kind=cmp_kind,
            value_kind=value_kind,
            width_bits=width_bits,
            lhs_raw=lhs,
            rhs_raw=rhs
        )
    return _setp_toggle_mask_bruteforce_fields(
        cmp_kind=cmp_kind,
        value_kind=value_kind,
        width_bits=width_bits,
        lhs_raw=lhs,
        rhs_raw=rhs,
    )


def setp_toggle_mask(
    opcode: str,
    src_vals: List[int],
    src_width_bits: List[int],
) -> Tuple[int, int]:
    if len(src_vals) != 2:
        raise NotImplementedError(
            f"setp variants with src_count={len(src_vals)} are not supported for toggle mask"
        )
    cmp_kind, value_kind, width_bits = _resolve_setp_eval_shape(opcode, src_width_bits)
    mask = width_mask(width_bits)
    lhs_raw = int(src_vals[0]) & mask
    rhs_raw = int(src_vals[1]) & mask
    opcode_norm = normalize_opcode(opcode)
    lhs_toggle, rhs_toggle = _cached_setp_toggle(
        opcode_norm,
        lhs_raw,
        rhs_raw,
        width_bits,
        value_kind,
        cmp_kind,
    )

    lhs_src_w = int(src_width_bits[0]) if len(src_width_bits) >= 1 else width_bits
    rhs_src_w = int(src_width_bits[1]) if len(src_width_bits) >= 2 else width_bits
    lhs_toggle &= width_mask(max(0, min(64, lhs_src_w)))
    rhs_toggle &= width_mask(max(0, min(64, rhs_src_w)))
    return lhs_toggle & UINT64_MASK, rhs_toggle & UINT64_MASK


def _setp_toggle_mask_legacy_bruteforce(
    opcode: str,
    src_vals: List[int],
    src_width_bits: List[int],
    *,
    baseline: Optional[int] = None,
) -> Tuple[int, int]:
    if len(src_vals) != 2:
        raise NotImplementedError(
            f"setp variants with src_count={len(src_vals)} are not supported for legacy toggle mask"
        )
    if baseline is None:
        baseline = eval_setp_predicate(opcode, src_vals, src_width_bits)

    mutated = [int(src_vals[0]), int(src_vals[1])]
    out = [0, 0]
    for src_i in range(2):
        if src_i >= len(src_width_bits):
            continue
        src_w = coerce_width_bits(src_width_bits[src_i], default=64)
        acc = 0
        for bit in range(src_w):
            mutated[src_i] = int(src_vals[src_i]) ^ (1 << bit)
            pred_prime = eval_setp_predicate(opcode, mutated, src_width_bits)
            if pred_prime != baseline:
                acc |= 1 << bit
        mutated[src_i] = int(src_vals[src_i])
        out[src_i] = acc & UINT64_MASK
    return out[0], out[1]


def _selp_toggle_masks_legacy_bruteforce(ev: TraceEvent) -> Dict[int, int]:
    if len(ev.src_vals) < 3:
        return {}
    width_bits_default = coerce_positive_width_bits(ev.width_bits, default=32)
    baseline = eval_op("SELP", ev.src_vals, width_bits_default) & 1
    mutated = list(ev.src_vals)
    out: Dict[int, int] = {}

    for src_i, src_reg in enumerate(ev.src_regs):
        if src_i >= len(ev.src_vals):
            break
        if src_i >= len(ev.src_width_bits):
            continue

        if is_predicate_register(src_reg):
            src_w = 1
        elif is_data_register(src_reg):
            src_w = coerce_width_bits(ev.src_width_bits[src_i], default=64)
        else:
            continue
        if src_w <= 0:
            continue

        toggle_mask = 0
        for bit in range(src_w):
            mutated[src_i] = int(ev.src_vals[src_i]) ^ (1 << bit)
            pred_prime = eval_op("SELP", mutated, width_bits_default) & 1
            if pred_prime != baseline:
                toggle_mask |= 1 << bit
        mutated[src_i] = int(ev.src_vals[src_i])

        if toggle_mask != 0:
            out[src_i] = toggle_mask & UINT64_MASK
    return out


def _toggle_validation_should_sample(
    counters: Dict[str, int],
    opcode_norm: str,
    sample_every: int,
) -> bool:
    count = int(counters.get(opcode_norm, 0)) + 1
    counters[opcode_norm] = count
    if sample_every <= 1:
        return True
    return count == 1 or (count % sample_every) == 0


def _bounded_add_opcode_blacklist(blacklist: Set[str], opcode_norm: str) -> None:
    if opcode_norm in blacklist:
        return
    if len(blacklist) >= _TOGGLE_VALIDATE_BLACKLIST_MAX_ENTRIES:
        try:
            oldest = next(iter(blacklist))
            blacklist.discard(oldest)
        except StopIteration:
            pass
    blacklist.add(opcode_norm)


def backward_influence(
    op: str,
    src_vals: List[int],
    dst_val: int,
    dst_observed_mask: int,
    width_bits_default: int,
    src_widths: List[int],
    *,
    thread_id: Optional[int] = None,
    pc: Optional[str] = None,
    opcode: Optional[str] = None,
    event_index: Optional[int] = None,
) -> List[int]:
    op = _text(op)
    src_count = len(src_vals)
    observed = dst_observed_mask & width_mask(dst_width_bits(op, width_bits_default))
    if observed == 0:
        return [0] * src_count

    ctx = (
        f"thread_id={thread_id}, pc={pc}, event_index={event_index}, "
        f"opcode={opcode}, canonical_op={op}"
    )
    dst_wmask = width_mask(dst_width_bits(op, width_bits_default))
    selp_swapped_src01 = False

    def eval_with_layout(vals: List[int]) -> int:
        if op == "SELP" and selp_swapped_src01 and len(vals) == 3:
            return eval_op_cached(
                op,
                (
                    int(vals[1]) & UINT64_MASK,
                    int(vals[0]) & UINT64_MASK,
                    int(vals[2]) & UINT64_MASK,
                ),
                int(width_bits_default),
            ) & dst_wmask
        return eval_op_cached(
            op,
            tuple(int(v) & UINT64_MASK for v in vals),
            int(width_bits_default),
        ) & dst_wmask

    src_vals_key = tuple(int(v) & UINT64_MASK for v in src_vals)

    try:
        base_dst = eval_with_layout(src_vals_key)
    except KeyError as exc:
        raise NotImplementedError(f"Unsupported opcode in backward_influence: {ctx}") from exc

    if dst_val is not None and base_dst != (dst_val & dst_wmask):
        if op == "SELP" and len(src_vals) == 3:
            selp_swapped_src01 = True
            base_dst = eval_with_layout(src_vals_key)
            if base_dst == (dst_val & dst_wmask):
                pass
            else:
                selp_swapped_src01 = False
                base_dst = dst_val & dst_wmask
        else:
            # Keep analysis running when trace encoding/eval semantics differ.
            base_dst = dst_val & dst_wmask

    src_masks: List[int] = []
    for src_i in range(src_count):
        src_w = src_widths[src_i] if src_i < len(src_widths) else width_bits_default
        src_w = coerce_width_bits(src_w, default=width_bits_default)
        src_masks.append(width_mask(src_w))

    out = [0] * src_count

    # Exact fast paths for common integer ops.
    if op == "IDENTITY" and src_count >= 1:
        out[0] = observed & src_masks[0]
        return [x & UINT64_MASK for x in out]

    if op == "AND" and src_count >= 2:
        out[0] = (observed & (src_vals[1] & dst_wmask)) & src_masks[0]
        out[1] = (observed & (src_vals[0] & dst_wmask)) & src_masks[1]
        return [x & UINT64_MASK for x in out]

    if op == "OR" and src_count >= 2:
        out[0] = (observed & (~src_vals[1] & dst_wmask)) & src_masks[0]
        out[1] = (observed & (~src_vals[0] & dst_wmask)) & src_masks[1]
        return [x & UINT64_MASK for x in out]

    if op == "XOR" and src_count >= 2:
        out[0] = observed & src_masks[0]
        out[1] = observed & src_masks[1]
        return [x & UINT64_MASK for x in out]

    if op == "SELP" and src_count >= 3:
        # Match eval_with_layout semantics (optional src0/src1 swap fallback).
        true_src_idx = 0
        false_src_idx = 1
        if selp_swapped_src01:
            true_src_idx = 1
            false_src_idx = 0
        pred_val = int(src_vals[2]) & 1
        if pred_val != 0:
            out[true_src_idx] = observed & src_masks[true_src_idx]
        else:
            out[false_src_idx] = observed & src_masks[false_src_idx]

        diff_mask = ((src_vals[true_src_idx] ^ src_vals[false_src_idx]) & observed) & dst_wmask
        out[2] = (1 if diff_mask != 0 else 0) & src_masks[2]
        return [x & UINT64_MASK for x in out]

    # Partial fast path for variable-shift ops: src0 can be solved directly.
    # src1 shift-amount influence still uses exact bit-flip fallback.
    if op in ("SHL", "SHR_U", "SHR_S") and src_count >= 2:
        w = coerce_positive_width_bits(width_bits_default, default=32)
        sh = int(src_vals[1]) & (w - 1)
        if op == "SHL":
            if sh < w:
                out[0] = ((observed >> sh) & width_mask(w - sh)) & src_masks[0]
        else:
            out[0] = ((observed << sh) & width_mask(w)) & src_masks[0]

        mutated = list(src_vals)
        src_i = 1
        bit_width = src_widths[src_i] if src_i < len(src_widths) else width_bits_default
        bit_width = coerce_width_bits(bit_width, default=width_bits_default)
        acc = 0
        for bit in range(bit_width):
            mutated[src_i] = src_vals[src_i] ^ (1 << bit)
            try:
                dst_prime = eval_with_layout(mutated)
            except KeyError as exc:
                raise NotImplementedError(f"Unsupported opcode in backward_influence: {ctx}") from exc
            if ((base_dst ^ dst_prime) & observed) != 0:
                acc |= 1 << bit
        mutated[src_i] = src_vals[src_i]
        out[1] = acc & src_masks[1]
        return [x & UINT64_MASK for x in out]

    mutated = list(src_vals)
    for src_i in range(src_count):
        bit_width = src_widths[src_i] if src_i < len(src_widths) else width_bits_default
        bit_width = coerce_width_bits(bit_width, default=width_bits_default)
        acc = 0
        for bit in range(bit_width):
            mutated[src_i] = src_vals[src_i] ^ (1 << bit)
            try:
                dst_prime = eval_with_layout(mutated)
            except KeyError as exc:
                raise NotImplementedError(f"Unsupported opcode in backward_influence: {ctx}") from exc
            if ((base_dst ^ dst_prime) & observed) != 0:
                acc |= 1 << bit
        mutated[src_i] = src_vals[src_i]
        out[src_i] = acc & src_masks[src_i]

    return [x & UINT64_MASK for x in out]


def _backward_influence_triplet_uncached(
    *,
    op: str,
    src_vals: List[int],
    dst_val: int,
    obs_mask: int,
    due_mask: int,
    trace_mask: int,
    width_bits_default: int,
    src_widths: List[int],
    thread_id: Optional[int] = None,
    pc: Optional[str] = None,
    opcode: Optional[str] = None,
    event_index: Optional[int] = None,
) -> Tuple[List[int], List[int], List[int]]:
    op = _text(op)
    src_count = len(src_vals)
    out_obs = [0] * src_count
    out_due = [0] * src_count
    out_trace = [0] * src_count
    if src_count <= 0:
        return out_obs, out_due, out_trace

    if int(obs_mask) != 0:
        out_obs = backward_influence(
            op=op,
            src_vals=src_vals,
            dst_val=dst_val,
            dst_observed_mask=obs_mask,
            width_bits_default=width_bits_default,
            src_widths=src_widths,
            thread_id=thread_id,
            pc=pc,
            opcode=opcode,
            event_index=event_index
        )
    if int(due_mask) != 0:
        out_due = backward_influence(
            op=op,
            src_vals=src_vals,
            dst_val=dst_val,
            dst_observed_mask=due_mask,
            width_bits_default=width_bits_default,
            src_widths=src_widths,
            thread_id=thread_id,
            pc=pc,
            opcode=opcode,
            event_index=event_index
        )
    if int(trace_mask) != 0:
        out_trace = backward_influence(
            op=op,
            src_vals=src_vals,
            dst_val=dst_val,
            dst_observed_mask=trace_mask,
            width_bits_default=width_bits_default,
            src_widths=src_widths,
            thread_id=thread_id,
            pc=pc,
            opcode=opcode,
            event_index=event_index
        )

    return out_obs, out_due, out_trace


@lru_cache(maxsize=524288)
def _backward_influence_triplet_cached_core(
    op: str,
    src_vals_key: Tuple[int, ...],
    dst_val_key: Optional[int],
    obs_mask: int,
    due_mask: int,
    trace_mask: int,
    width_bits_default: int,
    src_widths_key: Tuple[int, ...],
) -> Tuple[Tuple[int, ...], Tuple[int, ...], Tuple[int, ...]]:
    out_obs, out_due, out_trace = _backward_influence_triplet_uncached(
        op=op,
        src_vals=list(src_vals_key),
        dst_val=dst_val_key,
        obs_mask=int(obs_mask),
        due_mask=int(due_mask),
        trace_mask=int(trace_mask),
        width_bits_default=int(width_bits_default),
        src_widths=list(src_widths_key),
    )
    return (
        tuple(int(v) & UINT64_MASK for v in out_obs),
        tuple(int(v) & UINT64_MASK for v in out_due),
        tuple(int(v) & UINT64_MASK for v in out_trace),
    )


def backward_influence_triplet(
    *,
    op: str,
    src_vals: List[int],
    dst_val: int,
    obs_mask: int,
    due_mask: int,
    trace_mask: int,
    width_bits_default: int,
    src_widths: List[int],
    thread_id: Optional[int] = None,
    pc: Optional[str] = None,
    opcode: Optional[str] = None,
    event_index: Optional[int] = None,
) -> Tuple[List[int], List[int], List[int]]:
    op_text = _text(op)
    src_vals_key = tuple(int(v) & UINT64_MASK for v in src_vals)
    src_widths_key = tuple(
        coerce_width_bits(
            src_widths[i] if i < len(src_widths) else width_bits_default,
            default=width_bits_default,
        )
        for i in range(len(src_vals_key))
    )
    dst_val_key = None if dst_val is None else int(dst_val) & UINT64_MASK
    try:
        cached = _backward_influence_triplet_cached_core(
            op_text,
            src_vals_key,
            dst_val_key,
            int(obs_mask) & UINT64_MASK,
            int(due_mask) & UINT64_MASK,
            int(trace_mask) & UINT64_MASK,
            int(width_bits_default),
            src_widths_key,
        )
        return (list(cached[0]), list(cached[1]), list(cached[2]))
    except Exception:
        # Preserve the original diagnostic context on unusual malformed traces
        # or unsupported opcodes.  Successful cached calls are pure functions of
        # the key above and therefore exact across threads/warps.
        return _backward_influence_triplet_uncached(
            op=op_text,
            src_vals=list(src_vals_key),
            dst_val=dst_val_key,
            obs_mask=int(obs_mask),
            due_mask=int(due_mask),
            trace_mask=int(trace_mask),
            width_bits_default=int(width_bits_default),
            src_widths=list(src_widths_key),
            thread_id=thread_id,
            pc=pc,
            opcode=opcode,
            event_index=event_index,
        )

def bytes_to_mask(size_bytes: int, byte_offset: int) -> int:
    if size_bytes <= 0:
        return 0
    if byte_offset < 0:
        raise ValueError("store_data_byte_offset must be >= 0")
    bits = size_bytes * 8
    shift = byte_offset * 8
    if shift >= 64:
        return 0
    if bits >= 64:
        return UINT64_MASK << shift & UINT64_MASK
    return ((1 << bits) - 1) << shift & UINT64_MASK


def parse_generic_expr(
    raw: Any, idx: int, default_width_bits: int, field_name: str
) -> Optional[EAExpr]:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError(f"event[{idx}] {field_name} must be an object")
    op = canonical_op(str(raw.get("op", "IDENTITY")))
    src_indices_raw = raw.get("src_indices")
    if src_indices_raw is None:
        raise ValueError(f"event[{idx}] {field_name} missing src_indices")
    src_indices = [int(x) for x in src_indices_raw]
    width_bits = int(raw.get("width_bits", default_width_bits))
    if width_bits <= 0 or width_bits > 64:
        raise ValueError(f"event[{idx}] invalid {field_name}.width_bits={width_bits}")
    return EAExpr(op=op, src_indices=src_indices, width_bits=width_bits)


def parse_ea_expr(raw: Any, idx: int, default_width_bits: int) -> Optional[EAExpr]:
    return parse_generic_expr(raw, idx, default_width_bits, "ea_expr")


def eval_expr(expr: EAExpr, src_vals: List[int], const_offset: int = 0) -> int:
    vals = [src_vals[i] & UINT64_MASK for i in expr.src_indices]
    w = expr.width_bits
    m = width_mask(w)

    if expr.op == "IDENTITY":
        if len(vals) != 1:
            raise ValueError("IDENTITY expression expects 1 source")
        return (vals[0] + const_offset) & m

    if expr.op == "ADDR_SUM":
        acc = const_offset & m
        for v in vals:
            acc = (acc + v) & m
        return acc & m

    if expr.op not in SUPPORTED_OPS:
        raise NotImplementedError(f"Unsupported expression op={expr.op}")

    need = expected_src_count(expr.op)
    if len(vals) != need:
        raise ValueError(
            f"Expression op={expr.op} expects {need} srcs, got {len(vals)}"
        )
    return eval_op(expr.op, vals, w) & m


def parse_effective_address_bits(raw: Dict[str, Any], idx: int) -> Optional[int]:
    if "mem_addr_effective_bits" not in raw:
        return None
    bits = int(raw["mem_addr_effective_bits"])
    if bits <= 0 or bits > 64:
        raise ValueError(f"event[{idx}] invalid mem_addr_effective_bits={bits}")
    return bits


def parse_effective_address_mask(raw: Dict[str, Any], idx: int) -> Optional[int]:
    if "mem_addr_mask" not in raw:
        return None
    mask = parse_int(raw["mem_addr_mask"]) & UINT64_MASK
    if mask == 0:
        raise ValueError(f"event[{idx}] invalid mem_addr_mask=0")
    return mask


def parse_optional_bool(
    value: Any,
    *,
    idx: Optional[int] = None,
    field_name: str = "value",
) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return bool(value)
    if isinstance(value, int):
        return int(value) != 0
    if isinstance(value, str):
        token = value.strip().lower()
        if token in ("true", "t", "yes", "y", "on"):
            return True
        if token in ("false", "f", "no", "n", "off"):
            return False
        try:
            return parse_int(value) != 0
        except ValueError as exc:
            if idx is not None:
                raise ValueError(
                    f"event[{idx}] invalid {field_name} value: {value!r}"
                ) from exc
            raise ValueError(f"invalid {field_name} value: {value!r}") from exc
    if idx is not None:
        raise ValueError(
            f"event[{idx}] unsupported {field_name} type: {type(value).__name__}"
        )
    raise ValueError(f"unsupported {field_name} type: {type(value).__name__}")


def parse_optional_pc_value(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        return f"0x{int(value):x}"
    return str(value)


def first_optional_pc_value(raw: Dict[str, Any], *field_names: str) -> Optional[str]:
    for field_name in field_names:
        if field_name in raw and raw.get(field_name) is not None:
            return parse_optional_pc_value(raw.get(field_name))
    return None


def parse_event(raw: Dict[str, Any], idx: int) -> TraceEvent:
    thread_id_raw = raw["thread_id"]
    thread_id = int(thread_id_raw) if not isinstance(thread_id_raw, int) else thread_id_raw

    kind_raw = raw.get("kind", "inst")
    kind = kind_raw.lower() if isinstance(kind_raw, str) else str(kind_raw).lower()

    pc_raw = raw.get("pc", "")
    pc = pc_raw if isinstance(pc_raw, str) else str(pc_raw)

    opcode_raw = raw.get("opcode", "UNKNOWN")
    opcode = opcode_raw if isinstance(opcode_raw, str) else str(opcode_raw)

    width_bits_raw = raw.get("width_bits", 32)
    width_bits = coerce_positive_width_bits(width_bits_raw, default=32)
    if width_bits <= 0 or width_bits > 64:
        raise ValueError(f"event[{idx}] invalid width_bits={width_bits}")

    src_regs_raw = raw.get("src_regs", [])
    if isinstance(src_regs_raw, list):
        src_regs = src_regs_raw
    else:
        src_regs = [str(x) for x in src_regs_raw]

    src_vals_raw = raw.get("src_vals", [])
    try:
        src_vals = [int(x) & UINT64_MASK for x in src_vals_raw]
    except Exception:
        src_vals = [parse_int(x) & UINT64_MASK for x in src_vals_raw]

    src_width_bits_raw = raw.get("src_width_bits")
    if src_width_bits_raw is None:
        src_width_bits = [
            default_src_width_bits(canonical_op(opcode), width_bits, i)
            for i in range(len(src_regs))
        ]
    elif isinstance(src_width_bits_raw, list):
        src_width_bits = [
            coerce_width_bits(
                x,
                default=default_src_width_bits(canonical_op(opcode), width_bits, i),
            )
            for i, x in enumerate(src_width_bits_raw)
        ]
    else:
        src_width_bits = [
            coerce_width_bits(
                x,
                default=default_src_width_bits(canonical_op(opcode), width_bits, i),
            )
            for i, x in enumerate(src_width_bits_raw)
        ]

    if len(src_regs) != len(src_vals):
        raise ValueError(f"event[{idx}] src_regs/src_vals length mismatch")
    if len(src_width_bits) != len(src_regs):
        raise ValueError(f"event[{idx}] src_width_bits/src_regs length mismatch")

    src_reg_uids_raw = raw.get("src_reg_uids")
    if src_reg_uids_raw is None:
        src_reg_uids = [-1 for _ in src_regs]
    elif isinstance(src_reg_uids_raw, list):
        src_reg_uids = src_reg_uids_raw
    else:
        src_reg_uids = [int(x) for x in src_reg_uids_raw]
        if len(src_reg_uids) != len(src_regs):
            raise ValueError(f"event[{idx}] src_reg_uids/src_regs length mismatch")

    dst_reg = raw.get("dst_reg")
    dst_reg = (
        dst_reg
        if dst_reg is None or isinstance(dst_reg, str)
        else str(dst_reg)
    )
    if "dst_reg_uid" in raw:
        dst_reg_uid_raw = raw["dst_reg_uid"]
        dst_reg_uid = (
            dst_reg_uid_raw if isinstance(dst_reg_uid_raw, int) else int(dst_reg_uid_raw)
        )
    else:
        dst_reg_uid = None
    if "dst_val" in raw:
        dst_val_raw = raw["dst_val"]
        dst_val = (
            (int(dst_val_raw) & UINT64_MASK)
            if isinstance(dst_val_raw, int)
            else (parse_int(dst_val_raw) & UINT64_MASK)
        )
    else:
        dst_val = None
    if "dst_old_val" in raw:
        dst_old_val_raw = raw["dst_old_val"]
        dst_old_val = (
            (int(dst_old_val_raw) & UINT64_MASK)
            if isinstance(dst_old_val_raw, int)
            else (parse_int(dst_old_val_raw) & UINT64_MASK)
        )
    else:
        dst_old_val = None
    if "dst_write_mask" in raw:
        dst_write_mask_raw = raw["dst_write_mask"]
        dst_write_mask = (
            (int(dst_write_mask_raw) & UINT64_MASK)
            if isinstance(dst_write_mask_raw, int)
            else (parse_int(dst_write_mask_raw) & UINT64_MASK)
        )
    else:
        dst_write_mask = None

    pred = None
    if "pred" in raw and raw["pred"] is not None:
        pred_raw = raw["pred"]
        pred = PredInfo(
            reg=str(pred_raw["reg"]),
            val=int(pred_raw["val"]) & 1,
            uid=int(pred_raw["uid"]) if "uid" in pred_raw else None
        )

    if "mem_addr" in raw:
        mem_addr_raw = raw["mem_addr"]
        mem_addr = mem_addr_raw if isinstance(mem_addr_raw, int) else parse_int(mem_addr_raw)
    elif "base" in raw:
        base_raw = raw["base"]
        mem_addr = base_raw if isinstance(base_raw, int) else parse_int(base_raw)
    else:
        mem_addr = None

    mem_space_raw = raw.get("mem_space") or raw.get("space")
    mem_space = (
        canonical_space(mem_space_raw)
        if mem_space_raw is not None or kind in ("load", "store")
        else None
    )
    if mem_space is None and kind in ("load", "store"):
        mem_space = infer_space_from_opcode(opcode)
    mem_addr_effective_bits = parse_effective_address_bits(raw, idx)
    mem_addr_mask = parse_effective_address_mask(raw, idx)

    if "mem_access_size_bytes" in raw:
        mem_access_raw = raw["mem_access_size_bytes"]
        mem_access_size_bytes = (
            mem_access_raw if isinstance(mem_access_raw, int) else int(mem_access_raw)
        )
    elif "size" in raw:
        size_raw = raw["size"]
        mem_access_size_bytes = size_raw if isinstance(size_raw, int) else int(size_raw)
    else:
        mem_access_size_bytes = None
    if "store_size_bytes" in raw:
        store_size_raw = raw["store_size_bytes"]
        store_size_bytes = (
            store_size_raw if isinstance(store_size_raw, int) else int(store_size_raw)
        )
    else:
        store_size_bytes = None
    store_data_src_index_raw = raw.get("store_data_src_index", 0)
    store_data_src_index = (
        store_data_src_index_raw
        if isinstance(store_data_src_index_raw, int)
        else int(store_data_src_index_raw)
    )
    store_data_byte_offset_raw = raw.get("store_data_byte_offset", 0)
    store_data_byte_offset = (
        store_data_byte_offset_raw
        if isinstance(store_data_byte_offset_raw, int)
        else int(store_data_byte_offset_raw)
    )
    is_output_store = bool(raw.get("is_output_store", False))

    ea_base_src_indices_raw = raw.get("ea_base_src_indices", [])
    if isinstance(ea_base_src_indices_raw, list):
        ea_base_src_indices = ea_base_src_indices_raw
    else:
        ea_base_src_indices = [int(x) for x in ea_base_src_indices_raw]

    ea_const_offset_raw = raw.get("ea_const_offset", 0)
    ea_const_offset = (
        ea_const_offset_raw
        if isinstance(ea_const_offset_raw, int)
        else int(ea_const_offset_raw)
    )
    ea_width_bits_raw = raw.get("ea_width_bits", 64)
    ea_width_bits = ea_width_bits_raw if isinstance(ea_width_bits_raw, int) else int(
        ea_width_bits_raw
    )
    if ea_width_bits <= 0 or ea_width_bits > 64:
        raise ValueError(f"event[{idx}] invalid ea_width_bits={ea_width_bits}")
    ea_expr = parse_ea_expr(raw.get("ea_expr"), idx, ea_width_bits)
    control_expr = parse_generic_expr(
        raw.get("control_expr"),
        idx,
        max(1, min(64, width_bits)),
        "control_expr",
    )
    control_const_offset_raw = raw.get("control_const_offset", 0)
    control_const_offset = (
        control_const_offset_raw
        if isinstance(control_const_offset_raw, int)
        else int(control_const_offset_raw)
    )
    recorded_branch_taken = parse_optional_bool(
        raw.get("branch_taken"),
        idx=idx,
        field_name="branch_taken",
    )
    next_pc = first_optional_pc_value(raw, "next_pc", "observed_next_pc")
    branch_target_pc = first_optional_pc_value(raw, "branch_target_pc", "target_pc")
    taken_target_pc = first_optional_pc_value(raw, "taken_target_pc")
    if taken_target_pc is None:
        taken_target_pc = branch_target_pc
    fallthrough_pc = first_optional_pc_value(raw, "fallthrough_pc")
    address_observed = raw.get("address_observed")
    if address_observed is not None:
        address_observed = bool(address_observed)

    cycle_raw = raw.get("cycle")
    cycle = cycle_raw if isinstance(cycle_raw, int) else (int(cycle_raw) if cycle_raw is not None else None)
    sm_id_raw = raw.get("sm_id")
    sm_id = sm_id_raw if isinstance(sm_id_raw, int) else (int(sm_id_raw) if sm_id_raw is not None else None)
    cta_id_raw = raw.get("cta_id")
    cta_id = cta_id_raw if isinstance(cta_id_raw, int) else (int(cta_id_raw) if cta_id_raw is not None else None)
    warp_id_raw = raw.get("warp_id")
    warp_id = warp_id_raw if isinstance(warp_id_raw, int) else (int(warp_id_raw) if warp_id_raw is not None else None)

    return TraceEvent(
        index=idx,
        thread_id=thread_id,
        kind=kind,
        pc=pc,
        opcode=opcode,
        width_bits=width_bits,
        src_regs=src_regs,
        src_vals=src_vals,
        src_width_bits=src_width_bits,
        src_reg_uids=src_reg_uids,
        dst_reg=dst_reg,
        dst_reg_uid=dst_reg_uid,
        dst_val=dst_val,
        dst_old_val=dst_old_val,
        dst_write_mask=dst_write_mask,
        pred=pred,
        mem_addr=mem_addr,
        mem_space=mem_space,
        mem_addr_effective_bits=mem_addr_effective_bits,
        mem_addr_mask=mem_addr_mask,
        mem_access_size_bytes=mem_access_size_bytes,
        store_size_bytes=store_size_bytes,
        store_data_src_index=store_data_src_index,
        store_data_byte_offset=store_data_byte_offset,
        is_output_store=is_output_store,
        ea_base_src_indices=ea_base_src_indices,
        ea_const_offset=ea_const_offset,
        ea_width_bits=ea_width_bits,
        ea_expr=ea_expr,
        control_expr=control_expr,
        control_const_offset=control_const_offset,
        recorded_branch_taken=recorded_branch_taken,
        next_pc=next_pc,
        taken_target_pc=taken_target_pc,
        fallthrough_pc=fallthrough_pc,
        branch_target_pc=branch_target_pc,
        address_observed=address_observed,
        cycle=cycle,
        sm_id=sm_id,
        cta_id=cta_id,
        warp_id=warp_id,
    )


def _column_value(columns: Mapping[str, List[Any]], key: str, idx: int, default: Any = None) -> Any:
    col = columns.get(key)
    return _column_value_fast(col, idx, default)


def _column_value_fast(col: Any, idx: int, default: Any = None) -> Any:
    try:
        value = col[idx]
    except (TypeError, IndexError):
        return default
    return default if value is None else value


def _first_column_pc_value(idx: int, *cols: Any) -> Optional[str]:
    for col in cols:
        raw_pc = _column_value_fast(col, idx)
        if raw_pc is not None:
            return parse_optional_pc_value(raw_pc)
    return None


def parse_columnar_events(
    payload: Dict[str, Any],
) -> List[TraceEvent]:
    """Build TraceEvent rows from analyzer-input columnar binary data.

    This intentionally mirrors parse_event semantics for the normalized trace
    shape emitted by exact_sdc_prepare_input, but avoids hundreds of thousands
    of Python dict lookups in reg_observed_analyzer's hot startup path.
    """

    if str(payload.get("format", "")).strip() != "exact_sdc_analyzer_events_columnar_v1":
        raise ValueError("unsupported analyzer events columnar payload")
    columns_raw = payload.get("columns", {})
    if not isinstance(columns_raw, dict):
        raise ValueError("columnar analyzer input missing columns")
    columns: Mapping[str, List[Any]] = columns_raw  # type: ignore[assignment]
    count = int(payload.get("count", 0))
    def column(name: str) -> List[Any]:
        col = columns.get(name)
        return col if isinstance(col, list) else []

    thread_id_col = column("thread_id")
    kind_col = column("kind")
    pc_col = column("pc")
    opcode_col = column("opcode")
    width_bits_col = column("width_bits")
    src_regs_col = column("src_regs")
    src_vals_col = column("src_vals")
    src_width_bits_col = column("src_width_bits")
    src_reg_uids_col = column("src_reg_uids")
    dst_reg_col = column("dst_reg")
    dst_reg_uid_col = column("dst_reg_uid")
    dst_val_col = column("dst_val")
    dst_old_val_col = column("dst_old_val")
    dst_write_mask_col = column("dst_write_mask")
    pred_col = column("pred")
    mem_addr_col = column("mem_addr")
    base_col = column("base")
    mem_space_col = column("mem_space")
    space_col = column("space")
    mem_addr_effective_bits_col = column("mem_addr_effective_bits")
    mem_addr_mask_col = column("mem_addr_mask")
    mem_access_size_bytes_col = column("mem_access_size_bytes")
    size_col = column("size")
    store_size_bytes_col = column("store_size_bytes")
    store_data_src_index_col = column("store_data_src_index")
    store_data_byte_offset_col = column("store_data_byte_offset")
    is_output_store_col = column("is_output_store")
    ea_base_src_indices_col = column("ea_base_src_indices")
    ea_const_offset_col = column("ea_const_offset")
    ea_width_bits_col = column("ea_width_bits")
    ea_expr_col = column("ea_expr")
    control_expr_col = column("control_expr")
    control_const_offset_col = column("control_const_offset")
    branch_taken_col = column("branch_taken")
    next_pc_col = column("next_pc")
    observed_next_pc_col = column("observed_next_pc")
    taken_target_pc_col = column("taken_target_pc")
    fallthrough_pc_col = column("fallthrough_pc")
    branch_target_pc_col = column("branch_target_pc")
    target_pc_col = column("target_pc")
    address_observed_col = column("address_observed")
    cycle_col = column("cycle")
    sm_id_col = column("sm_id")
    cta_id_col = column("cta_id")
    warp_id_col = column("warp_id")

    out: List[TraceEvent] = []
    append = out.append
    for idx in range(count):
        thread_id_raw = _column_value_fast(thread_id_col, idx)
        if thread_id_raw is None:
            raise ValueError(f"event[{idx}] missing thread_id")
        thread_id = (
            int(thread_id_raw) if not isinstance(thread_id_raw, int) else thread_id_raw
        )

        kind_raw = _column_value_fast(kind_col, idx, "inst")
        kind = kind_raw.lower() if isinstance(kind_raw, str) else str(kind_raw).lower()
        pc_raw = _column_value_fast(pc_col, idx, "")
        pc = pc_raw if isinstance(pc_raw, str) else str(pc_raw)
        opcode_raw = _column_value_fast(opcode_col, idx, "UNKNOWN")
        opcode = opcode_raw if isinstance(opcode_raw, str) else str(opcode_raw)

        width_bits_raw = _column_value_fast(width_bits_col, idx, 32)
        width_bits = (
            width_bits_raw if isinstance(width_bits_raw, int) else int(width_bits_raw)
        )
        if width_bits <= 0 or width_bits > 64:
            raise ValueError(f"event[{idx}] invalid width_bits={width_bits}")

        src_regs_raw = _column_value_fast(src_regs_col, idx, [])
        src_regs = src_regs_raw if isinstance(src_regs_raw, list) else [str(x) for x in src_regs_raw]
        src_vals_raw = _column_value_fast(src_vals_col, idx, [])
        try:
            src_vals = [int(x) & UINT64_MASK for x in src_vals_raw]
        except Exception:
            src_vals = [parse_int(x) & UINT64_MASK for x in src_vals_raw]
        src_width_bits_raw = _column_value_fast(src_width_bits_col, idx)
        if src_width_bits_raw is None:
            src_width_bits = [
                default_src_width_bits(canonical_op(opcode), width_bits, src_i)
                for src_i in range(len(src_regs))
            ]
        elif isinstance(src_width_bits_raw, list):
            src_width_bits = src_width_bits_raw
        else:
            src_width_bits = [int(x) for x in src_width_bits_raw]
        if len(src_regs) != len(src_vals):
            raise ValueError(f"event[{idx}] src_regs/src_vals length mismatch")
        if len(src_width_bits) != len(src_regs):
            raise ValueError(f"event[{idx}] src_width_bits/src_regs length mismatch")

        src_reg_uids_raw = _column_value_fast(src_reg_uids_col, idx)
        if src_reg_uids_raw is None:
            src_reg_uids = [-1 for _ in src_regs]
        elif isinstance(src_reg_uids_raw, list):
            src_reg_uids = src_reg_uids_raw
        else:
            src_reg_uids = [int(x) for x in src_reg_uids_raw]
            if len(src_reg_uids) != len(src_regs):
                raise ValueError(f"event[{idx}] src_reg_uids/src_regs length mismatch")

        dst_reg_raw = _column_value_fast(dst_reg_col, idx)
        dst_reg = (
            dst_reg_raw
            if dst_reg_raw is None or isinstance(dst_reg_raw, str)
            else str(dst_reg_raw)
        )
        dst_reg_uid_raw = _column_value_fast(dst_reg_uid_col, idx)
        dst_reg_uid = (
            None
            if dst_reg_uid_raw is None
            else (dst_reg_uid_raw if isinstance(dst_reg_uid_raw, int) else int(dst_reg_uid_raw))
        )

        def opt_u64_col(col):
            raw_v = _column_value_fast(col, idx)
            if raw_v is None:
                return None
            return (
                (int(raw_v) & UINT64_MASK)
                if isinstance(raw_v, int)
                else (parse_int(raw_v) & UINT64_MASK)
            )

        dst_val = opt_u64_col(dst_val_col)
        dst_old_val = opt_u64_col(dst_old_val_col)
        dst_write_mask = opt_u64_col(dst_write_mask_col)

        pred = None
        pred_raw = _column_value_fast(pred_col, idx)
        if pred_raw is not None:
            pred = PredInfo(
                reg=str(pred_raw["reg"]),
                val=int(pred_raw["val"]) & 1,
                uid=int(pred_raw["uid"]) if "uid" in pred_raw else None,
            )

        mem_addr_raw = _column_value_fast(mem_addr_col, idx)
        if mem_addr_raw is None:
            mem_addr_raw = _column_value_fast(base_col, idx)
        mem_addr = (
            None
            if mem_addr_raw is None
            else (mem_addr_raw if isinstance(mem_addr_raw, int) else parse_int(mem_addr_raw))
        )

        mem_space_raw = _column_value_fast(mem_space_col, idx)
        if mem_space_raw is None:
            mem_space_raw = _column_value_fast(space_col, idx)
        mem_space = (
            canonical_space(mem_space_raw)
            if mem_space_raw is not None or kind in ("load", "store")
            else None
        )
        if mem_space is None and kind in ("load", "store"):
            mem_space = infer_space_from_opcode(opcode)

        mem_addr_effective_bits_raw = _column_value_fast(mem_addr_effective_bits_col, idx)
        mem_addr_effective_bits = (
            None
            if mem_addr_effective_bits_raw is None
            else int(mem_addr_effective_bits_raw)
        )
        if (
            mem_addr_effective_bits is not None
            and (mem_addr_effective_bits <= 0 or mem_addr_effective_bits > 64)
        ):
            raise ValueError(
                f"event[{idx}] invalid mem_addr_effective_bits={mem_addr_effective_bits}"
            )
        mem_addr_mask_raw = _column_value_fast(mem_addr_mask_col, idx)
        mem_addr_mask = (
            None
            if mem_addr_mask_raw is None
            else (parse_int(mem_addr_mask_raw) & UINT64_MASK)
        )
        if mem_addr_mask == 0:
            raise ValueError(f"event[{idx}] invalid mem_addr_mask=0")

        mem_access_raw = _column_value_fast(mem_access_size_bytes_col, idx)
        if mem_access_raw is None:
            mem_access_raw = _column_value_fast(size_col, idx)
        mem_access_size_bytes = (
            None
            if mem_access_raw is None
            else (mem_access_raw if isinstance(mem_access_raw, int) else int(mem_access_raw))
        )
        store_size_raw = _column_value_fast(store_size_bytes_col, idx)
        store_size_bytes = (
            None
            if store_size_raw is None
            else (store_size_raw if isinstance(store_size_raw, int) else int(store_size_raw))
        )
        store_data_src_index_raw = _column_value_fast(store_data_src_index_col, idx, 0)
        store_data_src_index = (
            store_data_src_index_raw
            if isinstance(store_data_src_index_raw, int)
            else int(store_data_src_index_raw)
        )
        store_data_byte_offset_raw = _column_value_fast(store_data_byte_offset_col, idx, 0)
        store_data_byte_offset = (
            store_data_byte_offset_raw
            if isinstance(store_data_byte_offset_raw, int)
            else int(store_data_byte_offset_raw)
        )
        is_output_store = bool(_column_value_fast(is_output_store_col, idx, False))

        ea_base_src_indices_raw = _column_value_fast(ea_base_src_indices_col, idx, [])
        ea_base_src_indices = (
            ea_base_src_indices_raw
            if isinstance(ea_base_src_indices_raw, list)
            else [int(x) for x in ea_base_src_indices_raw]
        )
        ea_const_offset_raw = _column_value_fast(ea_const_offset_col, idx, 0)
        ea_const_offset = (
            ea_const_offset_raw
            if isinstance(ea_const_offset_raw, int)
            else int(ea_const_offset_raw)
        )
        ea_width_bits_raw = _column_value_fast(ea_width_bits_col, idx, 64)
        ea_width_bits = (
            ea_width_bits_raw if isinstance(ea_width_bits_raw, int) else int(ea_width_bits_raw)
        )
        if ea_width_bits <= 0 or ea_width_bits > 64:
            raise ValueError(f"event[{idx}] invalid ea_width_bits={ea_width_bits}")
        ea_expr = parse_ea_expr(_column_value_fast(ea_expr_col, idx), idx, ea_width_bits)
        control_expr = parse_generic_expr(
            _column_value_fast(control_expr_col, idx),
            idx,
            max(1, min(64, width_bits)),
            "control_expr"
        )
        control_const_offset_raw = _column_value_fast(control_const_offset_col, idx, 0)
        control_const_offset = (
            control_const_offset_raw
            if isinstance(control_const_offset_raw, int)
            else int(control_const_offset_raw)
        )
        recorded_branch_taken = parse_optional_bool(
            _column_value_fast(branch_taken_col, idx),
            idx=idx,
            field_name="branch_taken"
        )
        next_pc = _first_column_pc_value(idx, next_pc_col, observed_next_pc_col)
        branch_target_pc = _first_column_pc_value(idx, branch_target_pc_col, target_pc_col)
        taken_target_pc = _first_column_pc_value(idx, taken_target_pc_col)
        if taken_target_pc is None:
            taken_target_pc = branch_target_pc
        fallthrough_pc = _first_column_pc_value(idx, fallthrough_pc_col)
        address_observed_raw = _column_value_fast(address_observed_col, idx)
        address_observed = (
            None if address_observed_raw is None else bool(address_observed_raw)
        )

        def opt_i_col(col):
            raw_v = _column_value_fast(col, idx)
            if raw_v is None:
                return None
            return raw_v if isinstance(raw_v, int) else int(raw_v)

        append(
            TraceEvent(
                index=idx,
                thread_id=thread_id,
                kind=kind,
                pc=pc,
                opcode=opcode,
                width_bits=width_bits,
                src_regs=src_regs,
                src_vals=src_vals,
                src_width_bits=src_width_bits,
                src_reg_uids=src_reg_uids,
                dst_reg=dst_reg,
                dst_reg_uid=dst_reg_uid,
                dst_val=dst_val,
                dst_old_val=dst_old_val,
                dst_write_mask=dst_write_mask,
                pred=pred,
                mem_addr=mem_addr,
                mem_space=mem_space,
                mem_addr_effective_bits=mem_addr_effective_bits,
                mem_addr_mask=mem_addr_mask,
                mem_access_size_bytes=mem_access_size_bytes,
                store_size_bytes=store_size_bytes,
                store_data_src_index=store_data_src_index,
                store_data_byte_offset=store_data_byte_offset,
                is_output_store=is_output_store,
                ea_base_src_indices=ea_base_src_indices,
                ea_const_offset=ea_const_offset,
                ea_width_bits=ea_width_bits,
                ea_expr=ea_expr,
                control_expr=control_expr,
                control_const_offset=control_const_offset,
                recorded_branch_taken=recorded_branch_taken,
                next_pc=next_pc,
                taken_target_pc=taken_target_pc,
                fallthrough_pc=fallthrough_pc,
                branch_target_pc=branch_target_pc,
                address_observed=address_observed,
                cycle=opt_i_col(cycle_col),
                sm_id=opt_i_col(sm_id_col),
                cta_id=opt_i_col(cta_id_col),
                warp_id=opt_i_col(warp_id_col),
            )
        )
    return out


def parse_memory_ranges(raw_ranges: Any) -> List[MemoryRange]:
    if raw_ranges is None:
        return []
    if not isinstance(raw_ranges, list):
        raise ValueError("memory_ranges must be a list")

    out: List[MemoryRange] = []
    for i, r in enumerate(raw_ranges):
        if not isinstance(r, dict):
            raise ValueError(f"memory_ranges[{i}] must be an object")
        if "space" not in r or "base" not in r or "size" not in r:
            raise ValueError(f"memory_ranges[{i}] must have space/base/size")
        out.append(
            MemoryRange(
                space=canonical_space(str(r["space"])) or str(r["space"]),
                base=parse_int(r["base"]),
                size=int(r["size"]),
                start_event_index=int(r["start_event_index"]) if "start_event_index" in r else None,
                end_event_index=int(r["end_event_index"]) if "end_event_index" in r else None,
                start_cycle=int(r["start_cycle"]) if "start_cycle" in r else None,
                end_cycle=int(r["end_cycle"]) if "end_cycle" in r else None,
                thread_id=int(r["thread_id"]) if "thread_id" in r else None,
                cta_id=int(r["cta_id"]) if "cta_id" in r else None,
                sm_id=int(r["sm_id"]) if "sm_id" in r else None,
            )
        )
    return out


def parse_output_ranges(raw_output_spec: Any) -> List[OutputRangeSpec]:
    if raw_output_spec is None:
        return []
    if not isinstance(raw_output_spec, list):
        raise ValueError("output_spec must be a list")

    out: List[OutputRangeSpec] = []
    for i, item in enumerate(raw_output_spec):
        if not isinstance(item, dict):
            raise ValueError(f"output_spec[{i}] must be an object")
        if "base" not in item or "bytes" not in item:
            raise ValueError(f"output_spec[{i}] must have base/bytes")

        size = int(item["bytes"])
        if size <= 0:
            continue
        space = canonical_space(item.get("space") or "global") or "global"
        if space not in ("global", "local", "shared"):
            raise ValueError(
                f"output_spec[{i}] invalid space={item.get('space')!r}"
            )
        out.append(
            OutputRangeSpec(
                space=space,
                base=parse_int(item["base"]),
                size=size,
                name=(
                    str(item["name"]).strip()
                    if item.get("name") is not None
                    else None
                ),
            )
        )
    return out


def normalize_output_oracle_policy(raw: Any) -> Dict[str, Any]:
    """Normalize every benchmark to the exact-output SDC oracle.

    Older SARA revisions carried app-specific floating-point tolerance metadata.
    The current experiment definition intentionally removes that tolerance for
    FI, SARA, and GEREM-all: any final output mismatch is SDC.  This normalizer
    therefore strips stale tolerance fields even if an old policy file is passed
    in from a previous result directory.
    """
    source = "exact_output_mismatch_oracle"
    if isinstance(raw, dict):
        source = str(raw.get("source", source) or source)
    return {
        "source": source,
        "compare_kind": "exact",
        "nan_equal": False,
        "inf_sign_must_match": True,
        "device_materialized": True,
    }


def _match_output_range_for_store(
    ev: TraceEvent,
    output_ranges: Optional[Sequence[OutputRangeSpec]],
) -> Optional[OutputRangeSpec]:
    if not output_ranges or ev.mem_addr is None:
        return None
    size_bytes = access_size_bytes_for_event(ev)
    if size_bytes <= 0:
        return None
    mem_space = canonical_space(ev.mem_space)
    addr = int(ev.mem_addr)
    for spec in output_ranges:
        if canonical_space(spec.space) != mem_space:
            continue
        base = int(spec.base)
        size = int(spec.size)
        if addr < base or addr + int(size_bytes) > base + size:
            continue
        return spec
    return None


def output_store_participates_in_comparison(
    ev: TraceEvent,
    oracle_policy: Optional[Dict[str, Any]],
    output_ranges: Optional[Sequence[OutputRangeSpec]] = None,
) -> bool:
    if output_ranges:
        output_spec = _match_output_range_for_store(ev, output_ranges)
        if output_spec is None:
            return False
        output_name = (
            str(output_spec.name)
            if output_spec is not None and output_spec.name is not None
            else None
        )
        return shared_output_oracle.output_is_device_materialized(
            oracle_policy,
            output_name=output_name
        )
    return bool(getattr(ev, "is_output_store", False))


def derive_memory_ranges_from_events(events: List[TraceEvent]) -> List[MemoryRange]:
    """Build range intervals from alloc/free events in the trace itself.

    Expected event kinds:
    - alloc: requires mem_space, mem_addr (as base), mem_access_size_bytes (as size)
    - free:  requires mem_space, mem_addr (base). size is optional.
    """
    open_ranges: Dict[Tuple[Any, ...], Tuple[int, int]] = {}
    out: List[MemoryRange] = []

    for ev in events:
        if ev.kind not in ("alloc", "free"):
            continue
        if ev.mem_space is None or ev.mem_addr is None:
            raise ValueError(
                f"event[{ev.index}] {ev.kind} requires mem_space and mem_addr/base"
            )

        key = (ev.mem_space, ev.mem_addr, ev.thread_id, ev.cta_id, ev.sm_id)

        if ev.kind == "alloc":
            if ev.mem_access_size_bytes is None or ev.mem_access_size_bytes <= 0:
                raise ValueError(
                    f"event[{ev.index}] alloc requires positive size/mem_access_size_bytes"
                )
            if key in open_ranges:
                raise ValueError(
                    f"event[{ev.index}] duplicate alloc without free for key={key}"
                )
            open_ranges[key] = (ev.index, ev.mem_access_size_bytes)
            continue

        # free
        if key not in open_ranges:
            # If exact size does not match key tuple, allow fallback by space/base only.
            fallback_key = None
            for k in open_ranges:
                if k[0] == ev.mem_space and k[1] == ev.mem_addr:
                    fallback_key = k
                    break
            if fallback_key is None:
                raise ValueError(
                    f"event[{ev.index}] free without matching alloc for space={ev.mem_space}, base=0x{ev.mem_addr:x}"
                )
            key = fallback_key

        start_idx, size = open_ranges.pop(key)
        out.append(
            MemoryRange(
                space=key[0],
                base=key[1],
                size=size,
                start_event_index=start_idx,
                end_event_index=ev.index,
                thread_id=key[2],
                cta_id=key[3],
                sm_id=key[4],
            )
        )

    # Unfreed allocations remain valid to end-of-trace.
    for key, (start_idx, size) in open_ranges.items():
        out.append(
            MemoryRange(
                space=key[0],
                base=key[1],
                size=size,
                start_event_index=start_idx,
                end_event_index=None,
                thread_id=key[2],
                cta_id=key[3],
                sm_id=key[4],
            )
        )

    return out


def build_default_ea_expr(ev: TraceEvent) -> Optional[EAExpr]:
    if ev.ea_expr is not None:
        return ev.ea_expr
    if ev.ea_base_src_indices:
        if len(ev.ea_base_src_indices) == 1:
            return EAExpr(op="IDENTITY", src_indices=list(ev.ea_base_src_indices), width_bits=ev.ea_width_bits)
        return EAExpr(op="ADDR_SUM", src_indices=list(ev.ea_base_src_indices), width_bits=ev.ea_width_bits)
    return None


def _build_ea_analysis(ev: TraceEvent) -> EAAnalysis:
    expr = build_default_ea_expr(ev)
    if expr is None:
        if ev.mem_addr is None:
            raise ValueError(
                f"event[{ev.index}] missing EA expression metadata (ea_expr or ea_base_src_indices)"
            )
        default_width = coerce_positive_width_bits(ev.ea_width_bits, default=64)
        effective_mask = event_effective_address_mask(ev, default_width)
        base_raw_ea = int(ev.mem_addr) & UINT64_MASK
        return EAAnalysis(
            expr=None,
            effective_mask=int(effective_mask) & UINT64_MASK,
            expr_width_bits=int(default_width),
            base_raw_ea=int(base_raw_ea) & UINT64_MASK,
            base_effective_ea=int(base_raw_ea & effective_mask) & UINT64_MASK,
            src_indices=tuple(),
            src_width_bits=tuple()
        )

    try:
        base_raw_ea = eval_expr(expr, ev.src_vals, const_offset=ev.ea_const_offset)
    except (IndexError, KeyError, NotImplementedError, ValueError) as exc:
        raise type(exc)(
            f"event[{ev.index}] invalid ea_expr evaluation: {exc}"
        ) from exc

    return EAAnalysis(
        expr=expr,
        effective_mask=int(event_effective_address_mask(ev, expr.width_bits)) & UINT64_MASK,
        expr_width_bits=int(expr.width_bits),
        base_raw_ea=int(base_raw_ea) & UINT64_MASK,
        base_effective_ea=int(base_raw_ea) & int(event_effective_address_mask(ev, expr.width_bits)),
        src_indices=tuple(int(src_i) for src_i in expr.src_indices),
        src_width_bits=tuple(
            max(
                0,
                min(
                    64,
                    int(ev.src_width_bits[src_i] if src_i < len(ev.src_width_bits) else expr.width_bits),
                ),
            )
            for src_i in expr.src_indices
        ),
    )


def _eval_ea_expr_from_analysis(
    ev: TraceEvent,
    ea_analysis: EAAnalysis,
    src_vals_override: Optional[List[int]] = None,
) -> int:
    if ea_analysis.expr is None:
        return int(ea_analysis.base_raw_ea) & UINT64_MASK

    src_vals = src_vals_override if src_vals_override is not None else ev.src_vals
    expr = ea_analysis.expr
    value_mask = width_mask(int(ea_analysis.expr_width_bits))
    if expr.op == "IDENTITY" and len(ea_analysis.src_indices) == 1:
        src_idx = int(ea_analysis.src_indices[0])
        if src_idx < 0 or src_idx >= len(src_vals):
            raise IndexError(f"event[{ev.index}] invalid ea_expr source index {src_idx}")
        return (int(src_vals[src_idx]) + int(ev.ea_const_offset)) & value_mask
    if expr.op == "ADDR_SUM":
        acc = int(ev.ea_const_offset) & value_mask
        for src_idx in ea_analysis.src_indices:
            if src_idx < 0 or src_idx >= len(src_vals):
                raise IndexError(f"event[{ev.index}] invalid ea_expr source index {src_idx}")
            acc = (int(acc) + (int(src_vals[src_idx]) & UINT64_MASK)) & value_mask
        return int(acc) & value_mask
    return eval_expr(expr, src_vals, const_offset=ev.ea_const_offset)


def eval_ea_expr(
    ev: TraceEvent,
    src_vals_override: Optional[List[int]] = None,
    *,
    ea_analysis: Optional[EAAnalysis] = None,
) -> int:
    analysis = ea_analysis or _build_ea_analysis(ev)
    if analysis.expr is None:
        if ev.mem_addr is not None:
            return ev.mem_addr & UINT64_MASK
        raise ValueError(
            f"event[{ev.index}] missing EA expression metadata (ea_expr or ea_base_src_indices)"
        )

    try:
        return _eval_ea_expr_from_analysis(
            ev,
            analysis,
            src_vals_override=src_vals_override
        )
    except (IndexError, KeyError, NotImplementedError, ValueError) as exc:
        raise type(exc)(
            f"event[{ev.index}] invalid ea_expr evaluation: {exc}"
        ) from exc


def event_effective_address_mask(ev: TraceEvent, default_width_bits: int) -> int:
    if ev.mem_addr_mask is not None:
        return ev.mem_addr_mask & UINT64_MASK
    if ev.mem_addr_effective_bits is not None:
        return width_mask(ev.mem_addr_effective_bits)
    cspace = canonical_space(ev.mem_space)
    if cspace in ("global", "local", "shared"):
        # GPGPU-Sim uses 32-bit address_type in this tree; default to that
        # memory-consumed width when explicit metadata is absent.
        return width_mask(min(default_width_bits, 32))
    return width_mask(default_width_bits)


def eval_effective_ea(
    ev: TraceEvent,
    src_vals_override: Optional[List[int]] = None,
    *,
    ea_analysis: Optional[EAAnalysis] = None,
) -> int:
    analysis = ea_analysis or _build_ea_analysis(ev)
    if src_vals_override is None:
        return int(analysis.base_effective_ea) & UINT64_MASK
    raw_ea = _eval_ea_expr_from_analysis(
        ev,
        analysis,
        src_vals_override=src_vals_override,
    )
    return int(raw_ea) & int(analysis.effective_mask)


def ea_source_influence_masks(
    ev: TraceEvent,
    ea_observed_mask: int,
    *,
    ea_analysis: Optional[EAAnalysis] = None,
) -> Dict[int, int]:
    analysis = ea_analysis or _build_ea_analysis(ev)
    expr = analysis.expr
    if expr is None:
        return {}

    idxs = list(analysis.src_indices)
    if not idxs:
        return {}

    observed = int(ea_observed_mask) & int(analysis.effective_mask)
    if observed == 0:
        return {i: 0 for i in idxs}

    if expr.op == "IDENTITY" and len(idxs) == 1:
        src_idx = int(idxs[0])
        src_width = int(analysis.src_width_bits[0]) if analysis.src_width_bits else int(
            coerce_width_bits(ev.src_width_bits[src_idx], default=64)
        )
        if int(ev.ea_const_offset) == 0:
            return {
                src_idx: int(observed) & width_mask(src_width),
            }
        exact_masks = backward_influence(
            op="ADD",
            src_vals=[
                int(ev.src_vals[src_idx]) & UINT64_MASK,
                int(ev.ea_const_offset) & width_mask(int(analysis.expr_width_bits)),
            ],
            dst_val=int(analysis.base_effective_ea),
            dst_observed_mask=int(observed),
            width_bits_default=int(analysis.expr_width_bits),
            src_widths=[int(src_width), int(analysis.expr_width_bits)],
            thread_id=ev.thread_id,
            pc=ev.pc,
            opcode=ev.opcode,
            event_index=ev.index
        )
        return {
            src_idx: int(exact_masks[0]) & width_mask(src_width),
        }

    if expr.op == "ADDR_SUM":
        value_mask = width_mask(int(analysis.expr_width_bits))
        out_exact: Dict[int, int] = {}
        for pos, src_idx in enumerate(idxs):
            other_sum = int(ev.ea_const_offset) & value_mask
            for other_idx in idxs:
                if int(other_idx) == int(src_idx):
                    continue
                other_sum = (int(other_sum) + (int(ev.src_vals[int(other_idx)]) & UINT64_MASK)) & value_mask
            src_width = int(analysis.src_width_bits[pos]) if pos < len(analysis.src_width_bits) else int(
                coerce_width_bits(ev.src_width_bits[int(src_idx)], default=64)
            )
            exact_masks = backward_influence(
                op="ADD",
                src_vals=[
                    int(ev.src_vals[int(src_idx)]) & UINT64_MASK,
                    int(other_sum) & value_mask,
                ],
                dst_val=int(analysis.base_effective_ea),
                dst_observed_mask=int(observed),
                width_bits_default=int(analysis.expr_width_bits),
                src_widths=[int(src_width), int(analysis.expr_width_bits)],
                thread_id=ev.thread_id,
                pc=ev.pc,
                opcode=ev.opcode,
                event_index=ev.index,
            )
            out_exact[int(src_idx)] = int(exact_masks[0]) & width_mask(src_width)
        return out_exact

    if expr.op in SUPPORTED_OPS and len(idxs) <= 3:
        src_vals_exact = [int(ev.src_vals[int(src_idx)]) & UINT64_MASK for src_idx in idxs]
        src_widths_exact = [
            int(analysis.src_width_bits[pos]) if pos < len(analysis.src_width_bits) else int(
                coerce_width_bits(ev.src_width_bits[int(src_idx)], default=64)
            )
            for pos, src_idx in enumerate(idxs)
        ]
        exact_masks = backward_influence(
            op=str(expr.op),
            src_vals=src_vals_exact,
            dst_val=int(analysis.base_effective_ea),
            dst_observed_mask=int(observed),
            width_bits_default=int(analysis.expr_width_bits),
            src_widths=src_widths_exact,
            thread_id=ev.thread_id,
            pc=ev.pc,
            opcode=ev.opcode,
            event_index=ev.index
        )
        return {
            int(src_idx): int(exact_masks[pos]) & width_mask(src_widths_exact[pos])
            for pos, src_idx in enumerate(idxs)
        }

    out: Dict[int, int] = {i: 0 for i in idxs}
    mutated = list(ev.src_vals)
    base_ea = int(analysis.base_effective_ea) & UINT64_MASK

    for pos, src_i in enumerate(idxs):
        if src_i < 0 or src_i >= len(ev.src_vals):
            raise ValueError(f"event[{ev.index}] invalid ea source index {src_i}")
        src_w = int(analysis.src_width_bits[pos]) if pos < len(analysis.src_width_bits) else int(
            coerce_width_bits(ev.src_width_bits[src_i], default=64)
        )
        for bit in range(src_w):
            mutated[src_i] = ev.src_vals[src_i] ^ (1 << bit)
            ea_prime = eval_effective_ea(
                ev,
                src_vals_override=mutated,
                ea_analysis=analysis,
            )
            if ((base_ea ^ ea_prime) & observed) != 0:
                out[src_i] |= 1 << bit
        mutated[src_i] = ev.src_vals[src_i]

    return out


def active_ranges_for_event(ev: TraceEvent, ranges: List[MemoryRange]) -> List[MemoryRange]:
    return [r for r in ranges if r.active_for_event(ev)]


def access_size_bytes_for_event(ev: TraceEvent) -> int:
    if ev.kind == "store":
        if ev.store_size_bytes is not None and ev.store_size_bytes > 0:
            return int(ev.store_size_bytes)
        if ev.mem_access_size_bytes is not None and ev.mem_access_size_bytes > 0:
            return int(ev.mem_access_size_bytes)
    elif ev.kind == "load":
        if ev.mem_access_size_bytes is not None and ev.mem_access_size_bytes > 0:
            return int(ev.mem_access_size_bytes)
    elif ev.mem_access_size_bytes is not None and ev.mem_access_size_bytes > 0:
        return int(ev.mem_access_size_bytes)

    if ev.width_bits > 0:
        return max(1, (int(ev.width_bits) + 7) // 8)
    return 1


class TraceMemoryOracle:
    def __init__(self, events: List[TraceEvent]) -> None:
        self._timelines: Dict[Tuple[Any, ...], Tuple[List[int], List[int]]] = {}
        self._build(events)

    def _scope_key_for_event(
        self, ev: TraceEvent, mem_space: str
    ) -> Optional[Tuple[Any, ...]]:
        cspace = canonical_space(mem_space)
        if cspace == "shared":
            return (cspace, ev.sm_id, ev.cta_id)
        if cspace == "local":
            return (cspace, ev.thread_id)
        if cspace == "global":
            return (cspace,)
        return None

    def _scope_key_for_branch_event(
        self, branch_event: TraceEvent, mem_space: str
    ) -> Optional[Tuple[Any, ...]]:
        cspace = canonical_space(mem_space)
        if cspace == "shared":
            return (cspace, branch_event.sm_id, branch_event.cta_id)
        if cspace == "local":
            return (cspace, branch_event.thread_id)
        if cspace == "global":
            return (cspace,)
        return None

    def _record_byte(self, key: Tuple[Any, ...], event_index: int, value: int) -> None:
        bucket = self._timelines.get(key)
        if bucket is None:
            bucket = ([], [])
            self._timelines[key] = bucket
        bucket[0].append(int(event_index))
        bucket[1].append(int(value) & 0xFF)

    def _build(self, events: List[TraceEvent]) -> None:
        for ev in events:
            if ev.kind not in ("load", "store"):
                continue
            if ev.pred is not None and ev.pred.val == 0:
                continue
            if ev.mem_addr is None:
                continue
            scope_key = self._scope_key_for_event(ev, ev.mem_space or "")
            if scope_key is None:
                continue

            size_bytes = access_size_bytes_for_event(ev)
            if size_bytes <= 0:
                continue

            value = 0
            if ev.kind == "store":
                src_i = int(ev.store_data_src_index)
                if src_i < 0 or src_i >= len(ev.src_vals):
                    continue
                byte_off = int(ev.store_data_byte_offset)
                if byte_off < 0:
                    continue
                value = (ev.src_vals[src_i] >> (8 * byte_off)) & width_mask(
                    size_bytes * 8
                )
            else:
                if ev.dst_val is None:
                    continue
                value = ev.dst_val & width_mask(size_bytes * 8)

            for byte_i in range(size_bytes):
                addr = int(ev.mem_addr) + byte_i
                bval = (value >> (8 * byte_i)) & 0xFF
                self._record_byte(scope_key + (addr,), ev.index, bval)

    def lookup_byte(
        self,
        branch_event: TraceEvent,
        mem_space: str,
        addr: int,
    ) -> Optional[int]:
        scope_key = self._scope_key_for_branch_event(branch_event, mem_space)
        if scope_key is None:
            return None
        bucket = self._timelines.get(scope_key + (int(addr),))
        if bucket is None:
            return None
        event_indices, values = bucket
        pos = bisect.bisect_right(event_indices, int(branch_event.index)) - 1
        if pos < 0:
            return None
        return int(values[pos]) & 0xFF

    def lookup_byte_before_event(
        self,
        branch_event: TraceEvent,
        mem_space: str,
        addr: int,
    ) -> Optional[int]:
        scope_key = self._scope_key_for_branch_event(branch_event, mem_space)
        if scope_key is None:
            return None
        bucket = self._timelines.get(scope_key + (int(addr),))
        if bucket is None:
            return None
        event_indices, values = bucket
        pos = bisect.bisect_left(event_indices, int(branch_event.index)) - 1
        if pos < 0:
            return None
        return int(values[pos]) & 0xFF


def load_address_alias_value_relation(
    ev: TraceEvent,
    ea_prime: int,
    memory_oracle: Optional[TraceMemoryOracle],
    live_observed_mask: Optional[int] = None,
    live_due_mask: int = 0,
    live_trace_mask: int = 0,
) -> str:
    if memory_oracle is None:
        return "unknown"
    if ev.kind != "load" or ev.dst_val is None or ev.mem_space is None:
        return "unknown"

    size_bytes = access_size_bytes_for_event(ev)
    if size_bytes <= 0 or size_bytes > 8:
        return "unknown"

    golden_value = int(ev.dst_val) & width_mask(size_bytes * 8)
    base_addr = int(ea_prime)
    alias_value = 0
    for byte_i in range(size_bytes):
        alias_byte = memory_oracle.lookup_byte(
            ev,
            str(ev.mem_space),
            base_addr + int(byte_i),
        )
        if alias_byte is None:
            return "unknown"
        alias_value |= (int(alias_byte) & 0xFF) << (8 * int(byte_i))
    diff = (int(golden_value) ^ int(alias_value)) & width_mask(size_bytes * 8)
    if diff == 0:
        return "same"
    if live_observed_mask is None:
        return "different"

    live_obs = int(live_observed_mask) & width_mask(size_bytes * 8)
    live_due = int(live_due_mask) & width_mask(size_bytes * 8)
    live_trace = int(live_trace_mask) & width_mask(size_bytes * 8)
    if (int(diff) & (live_obs | live_due | live_trace)) == 0:
        return "same"
    if (int(diff) & live_due) != 0:
        return "due"
    if (int(diff) & live_obs) != 0:
        return "different"
    if (int(diff) & live_trace) != 0:
        return "unknown"
    return "same"


def has_known_valid_ea(
    ev: TraceEvent,
    ea: int,
    ranges: List[MemoryRange],
) -> bool:
    access_size = access_size_bytes_for_event(ev)
    if ev.mem_space is None:
        return False
    act = active_ranges_for_event(ev, ranges)
    if not act:
        return False
    return any(r.contains_access(ea, access_size) for r in act)


def _store_data_byte_value(ev: TraceEvent, byte_i: int) -> Optional[int]:
    src_i = int(ev.store_data_src_index)
    if src_i < 0 or src_i >= len(ev.src_vals):
        return None
    src_byte_i = int(ev.store_data_byte_offset) + int(byte_i)
    if src_byte_i < 0 or src_byte_i >= 8:
        return None
    return (int(ev.src_vals[src_i]) >> (8 * src_byte_i)) & 0xFF


def store_data_mask_src_to_memory(ev: TraceEvent, src_mask: int) -> int:
    size_bytes = access_size_bytes_for_event(ev)
    if size_bytes <= 0:
        return 0
    byte_off = int(ev.store_data_byte_offset)
    if byte_off < 0:
        return 0
    out = 0
    for byte_i in range(min(int(size_bytes), 8)):
        src_shift = 8 * (byte_off + int(byte_i))
        if src_shift >= 64:
            continue
        out |= (((int(src_mask) >> src_shift) & 0xFF) << (8 * int(byte_i)))
    return out & UINT64_MASK


def trace_memory_load_value_at_event(
    ev: TraceEvent,
    memory_oracle: Optional[TraceMemoryOracle],
) -> Optional[int]:
    if memory_oracle is None:
        return None
    if ev.mem_addr is None or ev.mem_space is None:
        return None
    size_bytes = access_size_bytes_for_event(ev)
    if size_bytes <= 0 or size_bytes > 8:
        return None
    value = 0
    for byte_i in range(int(size_bytes)):
        bval = memory_oracle.lookup_byte(
            ev,
            str(ev.mem_space),
            int(ev.mem_addr) + int(byte_i),
        )
        if bval is None:
            return None
        value |= (int(bval) & 0xFF) << (8 * int(byte_i))
    return int(value) & width_mask(int(size_bytes) * 8)


def _predicate_value_change_masks(
    old_value: Optional[int],
    new_value: Optional[int],
    obs_mask: int,
    due_mask: int,
    trace_mask: int,
) -> Tuple[int, int, int]:
    live_mask = int(obs_mask) | int(due_mask) | int(trace_mask)
    if live_mask == 0:
        return 0, 0, 0
    if old_value is None or new_value is None:
        return 0, 0, 1
    diff = (int(old_value) ^ int(new_value)) & UINT64_MASK
    return (
        1 if (diff & int(obs_mask)) != 0 else 0,
        1 if (diff & int(due_mask)) != 0 else 0,
        1 if (diff & int(trace_mask)) != 0 else 0,
    )


def store_predicate_effect_masks(
    ev: TraceEvent,
    memory_oracle: Optional[TraceMemoryOracle],
    live_obs_memory_mask: int,
    live_due_memory_mask: int,
    live_trace_memory_mask: int,
    *,
    executed_in_trace: bool,
) -> Tuple[int, int, int]:
    live_mask = (
        int(live_obs_memory_mask)
        | int(live_due_memory_mask)
        | int(live_trace_memory_mask)
    ) & UINT64_MASK
    if live_mask == 0:
        return 0, 0, 0
    if memory_oracle is None or ev.mem_addr is None or ev.mem_space is None:
        return 0, 0, 1
    size_bytes = access_size_bytes_for_event(ev)
    if size_bytes <= 0 or size_bytes > 8:
        return 0, 0, 1

    pred_obs = 0
    pred_due = 0
    pred_trace = 0
    for byte_i in range(int(size_bytes)):
        shift = 8 * int(byte_i)
        byte_obs = (int(live_obs_memory_mask) >> shift) & 0xFF
        byte_due = (int(live_due_memory_mask) >> shift) & 0xFF
        byte_trace = (int(live_trace_memory_mask) >> shift) & 0xFF
        if (byte_obs | byte_due | byte_trace) == 0:
            continue
        store_byte = _store_data_byte_value(ev, byte_i)
        if executed_in_trace:
            base_byte = memory_oracle.lookup_byte_before_event(
                ev,
                str(ev.mem_space),
                int(ev.mem_addr) + int(byte_i),
            )
        else:
            base_byte = memory_oracle.lookup_byte(
                ev,
                str(ev.mem_space),
                int(ev.mem_addr) + int(byte_i),
            )
        if store_byte is None or base_byte is None:
            pred_trace = 1
            continue
        diff = (int(store_byte) ^ int(base_byte)) & 0xFF
        if (diff & byte_obs) != 0:
            pred_obs = 1
        if (diff & byte_due) != 0:
            pred_due = 1
        if (diff & byte_trace) != 0:
            pred_trace = 1
    return int(pred_obs), int(pred_due), int(pred_trace)


def _scope_words_live_mask_for_addr(scope_words: Optional[Dict[int, Any]], addr: int) -> int:
    if scope_words is None:
        return 0
    word_addr = int(addr) >> 3
    lane = int(addr) & 0x7
    state = scope_words.get(word_addr)
    if state is None:
        return 0
    shift = lane * 8
    live_mask = int(getattr(state, "byte_obs_masks", 0) >> shift) & 0xFF
    live_mask |= int(getattr(state, "byte_due_masks", 0) >> shift) & 0xFF
    live_mask |= int(getattr(state, "byte_trace_masks", 0) >> shift) & 0xFF
    return live_mask & 0xFF


def store_target_overlaps_output_ranges(
    ev: TraceEvent,
    target_addr: int,
    size_bytes: int,
    output_ranges: List[OutputRangeSpec],
) -> bool:
    if not output_ranges:
        return True
    cspace = canonical_space(ev.mem_space)
    if cspace is None:
        return True
    lo = int(target_addr)
    hi = lo + int(size_bytes)
    if hi <= lo:
        return True
    for out in output_ranges:
        out_space = canonical_space(out.space) or out.space
        if str(out_space) != str(cspace):
            continue
        out_lo = int(out.base)
        out_hi = out_lo + int(out.size)
        if max(lo, out_lo) < min(hi, out_hi):
            return True
    return False


def store_address_alias_is_proven_masked(
    ev: TraceEvent,
    ea_prime: int,
    memory_oracle: Optional[TraceMemoryOracle],
    future_scope_words: Optional[Dict[int, Any]],
    original_live_mask: int,
    memory_ranges: List[MemoryRange],
    output_ranges: List[OutputRangeSpec],
    output_byte_last_writer: Optional[Dict[Tuple[str, int], int]] = None,
) -> bool:
    if memory_oracle is None:
        return False
    if ev.kind != "store" or ev.mem_addr is None or ev.mem_space is None:
        return False

    size_bytes = access_size_bytes_for_event(ev)
    if size_bytes <= 0 or size_bytes > 8:
        return False
    if not has_known_valid_ea(ev, int(ea_prime), memory_ranges):
        return False

    base_addr = int(ev.mem_addr)
    target_addr = int(ea_prime)
    if max(base_addr, target_addr) < min(base_addr + size_bytes, target_addr + size_bytes):
        # Partial self-overlap needs per-byte ordering proof; keep the existing
        # conservative classification unless the ranges are disjoint.
        return False
    output_last_writer = output_byte_last_writer or {}
    if not output_last_writer and store_target_overlaps_output_ranges(
        ev, target_addr, size_bytes, output_ranges
    ):
        return False

    cspace = canonical_space(ev.mem_space)
    if cspace is None:
        return False

    for byte_i in range(size_bytes):
        store_byte = _store_data_byte_value(ev, byte_i)
        if store_byte is None:
            return False

        original_live_byte_mask = (int(original_live_mask) >> (8 * byte_i)) & 0xFF
        if original_live_byte_mask != 0:
            prev_byte = memory_oracle.lookup_byte_before_event(
                ev,
                str(ev.mem_space),
                base_addr + int(byte_i),
            )
            if (
                prev_byte is None
                or ((int(prev_byte) ^ int(store_byte)) & int(original_live_byte_mask))
                != 0
            ):
                return False

        target_live_mask = _scope_words_live_mask_for_addr(
            future_scope_words,
            target_addr + int(byte_i),
        )
        target_last_writer = output_last_writer.get((str(cspace), target_addr + int(byte_i)))
        if target_last_writer is not None and int(target_last_writer) <= int(ev.index):
            target_live_mask |= 0xFF
        if target_live_mask != 0:
            prev_target_byte = memory_oracle.lookup_byte_before_event(
                ev,
                str(ev.mem_space),
                target_addr + int(byte_i),
            )
            if (
                prev_target_byte is None
                or ((int(prev_target_byte) ^ int(store_byte)) & int(target_live_mask))
                != 0
            ):
                return False

    return True


def is_out_of_range_ea(
    ev: TraceEvent,
    ea: int,
    ranges: List[MemoryRange],
) -> bool:
    access_size = access_size_bytes_for_event(ev)
    if ev.mem_space is None:
        return False

    act = active_ranges_for_event(ev, ranges)
    if not act:
        return False

    for r in act:
        if r.contains_access(ea, access_size):
            return False
    return True


def has_address_metadata(ev: TraceEvent) -> bool:
    return build_default_ea_expr(ev) is not None or ev.mem_addr is not None


def build_output_last_writer_index(
    events: List[TraceEvent],
    output_ranges: List[OutputRangeSpec],
) -> Tuple[Set[int], int, int, float]:
    if not output_ranges:
        return set(), 0, 0, 0.0

    ranges_by_space: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
    for out in output_ranges:
        cspace = canonical_space(out.space) or out.space
        size = int(out.size)
        if size <= 0:
            continue
        lo = int(out.base)
        hi = lo + size
        if hi <= lo:
            continue
        ranges_by_space[str(cspace)].append((lo, hi))
    if not ranges_by_space:
        return set(), 0, 0, 0.0

    output_store_event_indices: Set[int] = set()
    output_byte_last_writer: Dict[Tuple[str, int], int] = {}

    for ev in events:
        if ev.kind != "store":
            continue
        if ev.pred is not None and ev.pred.val == 0:
            continue
        if ev.mem_addr is None:
            continue

        cspace = canonical_space(ev.mem_space)
        if cspace is None:
            continue
        ranges = ranges_by_space.get(cspace)
        if not ranges:
            continue

        size_bytes = access_size_bytes_for_event(ev)
        if size_bytes <= 0:
            continue

        store_lo = int(ev.mem_addr)
        store_hi = store_lo + int(size_bytes)
        if store_hi <= store_lo:
            continue

        touches_output = False
        for range_lo, range_hi in ranges:
            ov_lo = max(store_lo, int(range_lo))
            ov_hi = min(store_hi, int(range_hi))
            if ov_lo >= ov_hi:
                continue
            touches_output = True
            for addr in range(ov_lo, ov_hi):
                output_byte_last_writer[(cspace, int(addr))] = int(ev.index)
        if touches_output:
            output_store_event_indices.add(int(ev.index))

    last_writer_event_indices = {int(v) for v in output_byte_last_writer.values()}
    total_store_count = int(len(output_store_event_indices))
    last_writer_count = int(len(last_writer_event_indices))
    filtered_store_ratio = (
        float(total_store_count - last_writer_count) / float(total_store_count)
        if total_store_count > 0
        else 0.0
    )
    return (
        last_writer_event_indices,
        last_writer_count,
        total_store_count,
        filtered_store_ratio,
    )


def build_output_byte_last_writer_index(
    events: List[TraceEvent],
    output_ranges: List[OutputRangeSpec],
) -> Dict[Tuple[str, int], int]:
    if not output_ranges:
        return {}

    ranges_by_space: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
    for out in output_ranges:
        cspace = canonical_space(out.space) or out.space
        size = int(out.size)
        if size <= 0:
            continue
        lo = int(out.base)
        hi = lo + size
        if hi > lo:
            ranges_by_space[str(cspace)].append((lo, hi))
    if not ranges_by_space:
        return {}

    output_byte_last_writer: Dict[Tuple[str, int], int] = {}
    for ev in events:
        if ev.kind != "store":
            continue
        if ev.pred is not None and ev.pred.val == 0:
            continue
        if ev.mem_addr is None:
            continue
        cspace = canonical_space(ev.mem_space)
        if cspace is None:
            continue
        ranges = ranges_by_space.get(str(cspace))
        if not ranges:
            continue
        size_bytes = access_size_bytes_for_event(ev)
        if size_bytes <= 0:
            continue
        store_lo = int(ev.mem_addr)
        store_hi = store_lo + int(size_bytes)
        if store_hi <= store_lo:
            continue
        for range_lo, range_hi in ranges:
            ov_lo = max(store_lo, int(range_lo))
            ov_hi = min(store_hi, int(range_hi))
            if ov_lo >= ov_hi:
                continue
            for addr in range(ov_lo, ov_hi):
                output_byte_last_writer[(str(cspace), int(addr))] = int(ev.index)
    return output_byte_last_writer


def should_seed_observed_for_store(ev: TraceEvent, is_observed_output_store: bool) -> bool:
    if ev.address_observed is not None:
        return ev.address_observed
    return bool(is_observed_output_store)


def should_seed_observed_for_load(ev: TraceEvent, dst_live_obs: int) -> bool:
    if ev.address_observed is not None:
        return ev.address_observed
    return dst_live_obs != 0


def merge_observed_state(
    regs_obs: Dict[str, int],
    reg: str,
    observed_mask: int,
) -> None:
    observed = int(observed_mask) & UINT64_MASK
    if observed != 0:
        regs_obs[reg] = (regs_obs[reg] | observed) & UINT64_MASK


def seed_address_masks(
    ev: TraceEvent,
    tid: int,
    regs_obs: Dict[str, int],
    regs_due: Dict[str, int],
    read_records: List[Any],
    memory_ranges: List[MemoryRange],
    force_rf_addr_masking: bool,
    seed_observed: bool,
    seed_due: bool,
    trigger_note: str,
    record_profile: str,
    compact_compute: bool = False,
    memory_oracle: Optional[TraceMemoryOracle] = None,
    load_value_observed_mask: Optional[int] = None,
    load_value_due_mask: int = 0,
    load_value_trace_mask: int = 0,
    store_address_mask_proof: Optional[Callable[[TraceEvent, int], bool]] = None,
    diagnostics: Optional[Dict[str, int]] = None,
) -> int:
    if not seed_observed and not seed_due:
        return 0

    ea_analysis = _build_ea_analysis(ev)
    base_ea = int(ea_analysis.base_effective_ea) & UINT64_MASK
    expr = ea_analysis.expr
    if expr is None:
        # Constant-address events still carry a concrete effective address via
        # mem_addr, but there is no register-derived address operand to seed.
        return 0

    src_addr_masks = ea_source_influence_masks(
        ev,
        int(ea_analysis.effective_mask),
        ea_analysis=ea_analysis,
    )
    suppress_rf_address_obs = bool(force_rf_addr_masking)
    suppressed_observed_bits = 0

    for src_i in expr.src_indices:
        if src_i < 0 or src_i >= len(ev.src_regs):
            raise ValueError(f"event[{ev.index}] invalid ea source index {src_i}")

        src_reg = ev.src_regs[src_i]
        src_w = coerce_width_bits(ev.src_width_bits[src_i], default=64)
        src_addr = src_addr_masks.get(src_i, 0) & width_mask(src_w)
        use_load_alias_oracle = (
            seed_observed and memory_oracle is not None and ev.kind == "load"
        )
        use_store_alias_mask_proof = (
            seed_observed and store_address_mask_proof is not None and ev.kind == "store"
        )
        src_obs = 0 if use_load_alias_oracle else (src_addr if seed_observed else 0)
        src_trace = 0
        src_due = 0
        src_same_value_masked = 0

        if (
            src_addr != 0
            and (
                seed_due
                or (
                    seed_observed
                    and memory_oracle is not None
                    and ev.kind == "load"
                )
                or use_store_alias_mask_proof
            )
        ):
            mutated = list(ev.src_vals)
            for bit in iter_set_bits(src_addr & width_mask(src_w)):
                mutated[src_i] = ev.src_vals[src_i] ^ (1 << bit)
                ea_prime = eval_effective_ea(
                    ev,
                    src_vals_override=mutated,
                    ea_analysis=ea_analysis,
                )
                if seed_due and is_out_of_range_ea(ev, ea_prime, memory_ranges):
                    src_due |= 1 << bit
                    continue
                if use_load_alias_oracle:
                    alias_relation = load_address_alias_value_relation(
                        ev,
                        int(ea_prime),
                        memory_oracle,
                        load_value_observed_mask,
                        int(load_value_due_mask),
                        int(load_value_trace_mask),
                    )
                    if alias_relation == "same":
                        src_same_value_masked |= 1 << bit
                    elif alias_relation == "due":
                        src_due |= 1 << bit
                    elif alias_relation == "different":
                        src_obs |= 1 << bit
                    else:
                        src_trace |= 1 << bit
                elif (
                    use_store_alias_mask_proof
                    and store_address_mask_proof is not None
                    and store_address_mask_proof(ev, int(ea_prime))
                ):
                    src_same_value_masked |= 1 << bit
            mutated[src_i] = ev.src_vals[src_i]

        if src_same_value_masked != 0:
            src_obs &= (~int(src_same_value_masked)) & width_mask(src_w)
            if diagnostics is not None:
                diagnostics["addr_same_value_masked_bits"] = int(
                    diagnostics.get("addr_same_value_masked_bits", 0)
                ) + int(popcount(src_same_value_masked))
                diagnostics["addr_same_value_masked_events"] = int(
                    diagnostics.get("addr_same_value_masked_events", 0)
                ) + 1
                if use_store_alias_mask_proof:
                    diagnostics["store_addr_proven_masked_bits"] = int(
                        diagnostics.get("store_addr_proven_masked_bits", 0)
                    ) + int(popcount(src_same_value_masked))
                    diagnostics["store_addr_proven_masked_events"] = int(
                        diagnostics.get("store_addr_proven_masked_events", 0)
                    ) + 1
        if src_trace != 0 and diagnostics is not None:
            diagnostics["addr_alias_unknown_bits"] = int(
                diagnostics.get("addr_alias_unknown_bits", 0)
            ) + int(popcount(src_trace))
            diagnostics["addr_alias_unknown_events"] = int(
                diagnostics.get("addr_alias_unknown_events", 0)
            ) + 1

        # The memory-component analyzer suppresses RF address effects from the
        # live register state so memory storage sites are not polluted by RF
        # faults.  The read record still keeps the proof-derived address
        # classification for the RF component, so all-components mode can use a
        # single analyzer without losing RF address SDC/DUE evidence.
        record_src_obs = int(src_obs) & width_mask(src_w)
        state_src_obs = int(record_src_obs)
        if suppress_rf_address_obs and state_src_obs != 0:
            suppressed_observed_bits += popcount(state_src_obs)
            state_src_obs = 0

        if seed_observed:
            regs_obs[src_reg] = (regs_obs[src_reg] | state_src_obs) & UINT64_MASK

        read_records.append(
            build_internal_read_record(
                profile=record_profile,
                event_index=ev.index,
                thread_id=tid,
                cycle=ev.cycle,
                sm_id=ev.sm_id,
                cta_id=ev.cta_id,
                warp_id=ev.warp_id,
                pc=ev.pc,
                opcode=ev.opcode,
                read_kind="addr",
                src_index=src_i,
                src_reg=src_reg,
                src_reg_uid=(
                    ev.src_reg_uids[src_i]
                    if 0 <= src_i < len(ev.src_reg_uids)
                    else -1
                ),
                src_width_bits=src_w,
                observed_mask_this_read=int(record_src_obs) & UINT64_MASK,
                due_mask_this_read=int(src_due) & UINT64_MASK,
                trace_expanding_mask_this_read=int(src_trace) & UINT64_MASK,
                reg_observed_mask_at_read=int(regs_obs[src_reg]) & UINT64_MASK,
                reg_due_mask_at_read=int(regs_due[src_reg]) & UINT64_MASK,
                addr_static_due_mask_this_read=int(src_due) & UINT64_MASK,
                notes={
                    "trigger": trigger_note,
                    "mem_space": ev.mem_space,
                    "mem_addr": f"0x{base_ea:016x}",
                    "ea_expr_op": expr.op,
                    "ea_expr_width_bits": expr.width_bits,
                    "ea_effective_mask": int(ea_analysis.effective_mask) & UINT64_MASK,
                    "addr_same_value_masked_bits": int(
                        popcount(src_same_value_masked)
                    ),
                    "addr_alias_unknown_bits": int(popcount(src_trace)),
                    "store_addr_proven_masked_bits": (
                        int(popcount(src_same_value_masked))
                        if use_store_alias_mask_proof
                        else 0
                    ),
                },
                compact_compute=compact_compute,
            )
        )
    return int(suppressed_observed_bits)


def fraction_to_json(x: Fraction) -> Dict[str, Any]:
    return {
        "numerator": x.numerator,
        "denominator": x.denominator,
        "value": float(x),
    }


def canonical_pc_value(pc: Any) -> str:
    if isinstance(pc, int):
        return f"0x{pc:x}"
    if isinstance(pc, str):
        p = pc.strip()
        try:
            return f"0x{int(p, 0):x}"
        except ValueError:
            return p
    raise ValueError(f"Unsupported PC value: {pc!r}")


def build_control_expr(ev: TraceEvent) -> Optional[EAExpr]:
    expr = ev.control_expr
    if expr is not None:
        return expr
    if len(ev.src_regs) == 1:
        w = ev.src_width_bits[0] if ev.src_width_bits else 1
        return EAExpr(op="IDENTITY", src_indices=[0], width_bits=coerce_positive_width_bits(w, default=64))
    if len(ev.src_regs) == 0:
        return None
    raise ValueError(
        f"event[{ev.index}] branch/loop control with multiple src_regs requires control_expr metadata"
    )


def eval_control_expr(ev: TraceEvent, src_vals_override: Optional[List[int]] = None) -> int:
    expr = build_control_expr(ev)
    if expr is None:
        raise ValueError(f"event[{ev.index}] missing control expression")
    src_vals = src_vals_override if src_vals_override is not None else ev.src_vals
    try:
        return eval_expr(
            expr,
            src_vals,
            const_offset=int(ev.control_const_offset)
        )
    except (IndexError, KeyError, NotImplementedError, ValueError) as exc:
        raise type(exc)(
            f"event[{ev.index}] invalid control expression evaluation: {exc}"
        ) from exc


def branch_taken(ev: TraceEvent, src_vals_override: Optional[List[int]] = None) -> bool:
    return (eval_control_expr(ev, src_vals_override=src_vals_override) & 1) != 0


def predicated_branch_taken(
    ev: TraceEvent, src_vals_override: Optional[List[int]] = None
) -> Optional[bool]:
    pred = ev.pred
    if pred is None:
        return None
    pred_reg = str(pred.reg)
    if pred_reg not in ev.src_regs:
        return None

    try:
        src_i = ev.src_regs.index(pred_reg)
    except ValueError:
        return None
    src_vals = src_vals_override if src_vals_override is not None else ev.src_vals
    if src_i < 0 or src_i >= len(src_vals) or src_i >= len(ev.src_vals):
        return None

    # Trace pred.val is the effective predicate value after predicate inversion.
    base_src_lsb = ev.src_vals[src_i] & 1
    base_pred_taken = int(pred.val) & 1
    pred_invert = base_src_lsb ^ base_pred_taken
    return (((src_vals[src_i] & 1) ^ pred_invert) & 1) != 0


def parse_branch_taken(
    ev: TraceEvent,
    src_vals_override: Optional[List[int]] = None,
    *,
    prefer_recorded: bool = True,
) -> bool:
    if prefer_recorded and src_vals_override is None and ev.recorded_branch_taken is not None:
        return bool(ev.recorded_branch_taken)

    pred_taken = predicated_branch_taken(ev, src_vals_override=src_vals_override)
    if pred_taken is not None:
        return pred_taken
    return branch_taken(ev, src_vals_override=src_vals_override)


def _normalized_pc_or_none(pc: Optional[str]) -> Optional[str]:
    if pc is None:
        return None
    try:
        return canonical_pc_value(pc)
    except Exception:
        return str(pc)


def branch_next_pc_for_decision(
    ev: TraceEvent,
    decision_taken: bool,
    base_taken: bool,
) -> Optional[str]:
    if decision_taken:
        target_pc = _normalized_pc_or_none(ev.taken_target_pc or ev.branch_target_pc)
    else:
        target_pc = _normalized_pc_or_none(ev.fallthrough_pc)
    if target_pc is not None:
        return target_pc
    if bool(decision_taken) == bool(base_taken):
        return _normalized_pc_or_none(ev.next_pc)
    return None


def branch_decision_changes_path(
    ev: TraceEvent,
    base_taken: bool,
    taken_prime: bool,
) -> bool:
    if bool(taken_prime) == bool(base_taken):
        return False
    base_next_pc = branch_next_pc_for_decision(ev, base_taken, base_taken)
    prime_next_pc = branch_next_pc_for_decision(ev, taken_prime, base_taken)
    if base_next_pc is None or prime_next_pc is None:
        return True
    return base_next_pc != prime_next_pc


def control_source_toggle_masks(ev: TraceEvent) -> Tuple[Dict[int, int], bool]:
    expr = build_control_expr(ev)
    if expr is None:
        return {}, False
    base_taken = parse_branch_taken(ev)

    out: Dict[int, int] = {i: 0 for i in expr.src_indices}
    mutated = list(ev.src_vals)
    for src_i in expr.src_indices:
        if src_i < 0 or src_i >= len(ev.src_vals):
            raise ValueError(f"event[{ev.index}] invalid control source index {src_i}")
        src_w = coerce_width_bits(ev.src_width_bits[src_i], default=64)
        for bit in range(src_w):
            mutated[src_i] = ev.src_vals[src_i] ^ (1 << bit)
            taken_prime = parse_branch_taken(
                ev, src_vals_override=mutated, prefer_recorded=False
            )
            if branch_decision_changes_path(ev, base_taken, taken_prime):
                out[src_i] |= 1 << bit
        mutated[src_i] = ev.src_vals[src_i]
    return out, base_taken


def or_trace_expanding_mask(rec: Dict[str, Any], add_mask: int) -> bool:
    add = add_mask & UINT64_MASK
    if add == 0:
        return False
    prev = mask_as_int(rec.get("trace_expanding_mask_this_read", 0))
    merged = prev | add
    if merged == prev:
        return False
    rec["trace_expanding_mask_this_read"] = merged
    return True


def merge_control_target_mask(
    target_masks: Dict[Tuple[int, int, bool], Dict[Tuple[int, int, str, int], int]],
    targets: Set[Tuple[int, int, bool]],
    read_key: Tuple[int, int, str, int],
    add_mask: int,
) -> None:
    mask = add_mask & UINT64_MASK
    if mask == 0 or not targets:
        return
    for target in targets:
        per_target = target_masks.setdefault(target, {})
        per_target[read_key] = (int(per_target.get(read_key, 0)) | mask) & UINT64_MASK


def build_control_seed_rec_map(
    events: List[TraceEvent],
) -> Dict[Tuple[int, int, str, int], Dict[str, Any]]:
    rec_map: Dict[Tuple[int, int, str, int], Dict[str, Any]] = {}
    for ev in events:
        if ev.kind in ("branch", "loop_branch"):
            for src_i in range(len(ev.src_regs)):
                rec_key = (int(ev.thread_id), int(ev.index), "control_src", int(src_i))
                rec_map.setdefault(
                    rec_key,
                    {
                        "thread_id": int(ev.thread_id),
                        "event_index": int(ev.index),
                        "read_kind": "control_src",
                        "src_index": int(src_i),
                        "trace_expanding_mask_this_read": ZERO_MASK_INT,
                    },
                )
            continue

        src_limit = min(len(ev.src_regs), len(ev.src_vals), len(ev.src_width_bits))
        for src_i in range(src_limit):
            rec_key = (int(ev.thread_id), int(ev.index), "src", int(src_i))
            rec_map.setdefault(
                rec_key,
                {
                    "thread_id": int(ev.thread_id),
                    "event_index": int(ev.index),
                    "read_kind": "src",
                    "src_index": int(src_i),
                    "trace_expanding_mask_this_read": ZERO_MASK_INT,
                },
            )
    return rec_map


def build_trace_seed_map_from_target_masks(
    target_masks: Dict[Tuple[int, int, bool], Dict[Tuple[int, int, str, int], int]]
) -> Dict[Tuple[int, int, str, int], int]:
    out: Dict[Tuple[int, int, str, int], int] = {}
    for per_read in target_masks.values():
        for rec_key, raw_mask in per_read.items():
            mask = int(raw_mask) & UINT64_MASK
            if mask == 0:
                continue
            out[rec_key] = (int(out.get(rec_key, 0)) | mask) & UINT64_MASK
    return out


def _lookup_output_oracle_memory_byte(space_mem: Any, addr: int) -> Tuple[bool, int]:
    key = int(addr)
    try:
        if key in space_mem:
            return True, int(space_mem[key]) & 0xFF
    except Exception:
        return False, 0
    return False, 0


def build_output_oracle_signature(
    memory: Dict[str, Dict[int, int]],
    output_ranges: List[OutputRangeSpec],
    compiled_ranges: Optional[List[Tuple[str, int, int, bytes, Tuple[int, ...]]]] = None,
) -> Optional[Dict[str, Any]]:
    if not output_ranges:
        return None

    ranges = (
        compiled_ranges
        if compiled_ranges is not None
        else compile_output_oracle_ranges(output_ranges)
    )
    if not ranges:
        return None

    hasher = hashlib.sha256()
    hasher_update = hasher.update
    missing_bytes = 0
    total_bytes = int(sum(size for _, _, size, _, _ in ranges))

    for space, _base, size, prefix, addrs in ranges:
        space_mem = memory.get(space, {})
        hasher_update(prefix)
        packed = bytearray(size * 2)
        for idx, addr in enumerate(addrs):
            off = idx * 2
            found, bval = _lookup_output_oracle_memory_byte(space_mem, addr)
            if found:
                packed[off] = 1
                packed[off + 1] = int(bval) & 0xFF
            else:
                missing_bytes += 1
                packed[off] = 0
                packed[off + 1] = 0xFF
        hasher_update(packed)

    return {
        "sha256": hasher.hexdigest(),
        "missing_bytes": int(missing_bytes),
        "total_bytes": int(total_bytes),
    }


def compile_output_oracle_ranges(
    output_ranges: List[OutputRangeSpec],
) -> List[Tuple[str, int, int, bytes, Tuple[int, ...]]]:
    out: List[Tuple[str, int, int, bytes, Tuple[int, ...]]] = []
    for spec in output_ranges:
        space = canonical_space(spec.space) or spec.space
        base = int(spec.base)
        size = int(spec.size)
        if size <= 0:
            continue
        prefix = (
            space.encode("ascii", errors="ignore")
            + b"|"
            + base.to_bytes(8, "little", signed=False)
            + size.to_bytes(8, "little", signed=False)
        )
        out.append((space, base, size, prefix, tuple(range(base, base + size))))
    return out


_CONTROL_TAINT_ADDITIVE_STATS = (
    "control_predicate_seeds",
    "control_needed_setp_events",
    "control_needed_selp_events",
    "control_needed_pred_logic_events",
    "unsupported_setp_events",
    "unsupported_predicate_writer_events",
    "toggle_fastpath_setp_events",
    "toggle_fastpath_selp_events",
    "toggle_validate_samples",
    "toggle_validate_mismatches",
    "trace_marked_data_src_reads",
    "trace_marked_data_src_bits",
    "trace_marked_predicate_src_reads",
    "trace_marked_predicate_src_bits",
    "propagated_predicate_dependencies",
)


def _hash_update_text(hasher: "hashlib._Hash", text: Any) -> None:
    raw = str(text).encode("utf-8", errors="surrogatepass")
    hasher.update(struct.pack("<I", len(raw)))
    hasher.update(raw)


def _hash_update_i64(hasher: "hashlib._Hash", value: int) -> None:
    hasher.update(struct.pack("<q", int(value)))


def _hash_update_u64(hasher: "hashlib._Hash", value: int) -> None:
    hasher.update(struct.pack("<Q", int(value) & UINT64_MASK))


@lru_cache(maxsize=131072)
def _control_taint_text_blob_cached(text: str) -> bytes:
    raw = text.encode("utf-8", errors="surrogatepass")
    return struct.pack("<I", len(raw)) + raw


def _control_taint_text_blob(text: str) -> bytes:
    return _control_taint_text_blob_cached(_text(text))


def _control_taint_base_taken(ev: TraceEvent) -> bool:
    cached = getattr(ev, "_control_taint_base_taken", _DICT_MISSING)
    if cached is not _DICT_MISSING:
        return bool(cached)
    taken = bool(parse_branch_taken(ev))
    try:
        setattr(ev, "_control_taint_base_taken", taken)
    except Exception:
        pass
    return taken


def _control_taint_event_signature_blob(ev: TraceEvent) -> bytes:
    cached = getattr(ev, "_control_taint_signature_blob", None)
    if isinstance(cached, (bytes, bytearray)):
        return bytes(cached)

    blob = bytearray()
    blob.extend(_control_taint_text_blob(str(ev.kind)))
    blob.extend(_control_taint_text_blob(normalize_opcode(ev.opcode)))
    blob.extend(_control_taint_text_blob(ev.pc if ev.pc is not None else ""))
    blob.extend(_control_taint_text_blob(ev.dst_reg if ev.dst_reg is not None else ""))
    blob.extend(struct.pack("<q", int(ev.width_bits)))

    blob.extend(struct.pack("<q", len(ev.src_regs)))
    for reg in ev.src_regs:
        blob.extend(_control_taint_text_blob(str(reg)))

    blob.extend(struct.pack("<q", len(ev.src_width_bits)))
    for width in ev.src_width_bits:
        blob.extend(struct.pack("<q", int(width)))

    blob.extend(struct.pack("<q", len(ev.src_vals)))
    for val in ev.src_vals:
        blob.extend(struct.pack("<Q", int(val) & UINT64_MASK))

    if ev.kind in ("branch", "loop_branch"):
        blob.extend(b"B")
        blob.extend(b"\x01" if _control_taint_base_taken(ev) else b"\x00")
    else:
        blob.extend(b"N")

    out = bytes(blob)
    try:
        setattr(ev, "_control_taint_signature_blob", out)
    except Exception:
        pass
    return out


def _control_taint_thread_signature(thread_events: List[TraceEvent]) -> bytes:
    h = hashlib.blake2b(digest_size=20)
    _hash_update_i64(h, len(thread_events))
    for ev in thread_events:
        h.update(_control_taint_event_signature_blob(ev))
    return h.digest()


def _control_taint_hash_event(hasher: "hashlib._Hash", ev: TraceEvent) -> None:
    hasher.update(_control_taint_event_signature_blob(ev))


def _control_taint_thread_sketch(thread_events: List[TraceEvent]) -> bytes:
    # Fast pre-filter for dedup candidates. Strict equality still requires
    # _control_taint_thread_signature in candidate buckets.
    n = len(thread_events)
    h = hashlib.blake2b(digest_size=12)
    _hash_update_i64(h, n)
    if n <= 0:
        return h.digest()

    sample_count = min(24, n)
    sample_pos: Set[int] = {0, n - 1}
    if sample_count > 2 and n > 2:
        denom = sample_count - 1
        for i in range(1, sample_count - 1):
            pos = (i * (n - 1)) // denom
            sample_pos.add(int(pos))

    for pos in sorted(sample_pos):
        _hash_update_i64(h, int(pos))
        _control_taint_hash_event(h, thread_events[pos])
    return h.digest()


def _control_taint_should_use_direct_signature(
    thread_count: int,
    total_event_count: int,
) -> bool:
    if thread_count < 1024:
        return False
    avg_events = float(total_event_count) / float(max(1, thread_count))
    return avg_events <= 64.0


def _control_taint_text_id(
    text: Any,
    interner: Dict[str, int],
) -> int:
    key = str(text)
    existing = interner.get(key)
    if existing is not None:
        return int(existing)
    value = len(interner) + 1
    interner[key] = int(value)
    return int(value)


def _merge_target_masks_into(
    dst: Dict[Tuple[int, int, bool], Dict[Tuple[int, int, str, int], int]],
    src: Dict[Tuple[int, int, bool], Dict[Tuple[int, int, str, int], int]],
) -> None:
    for target, per_read in src.items():
        dst_per = dst.setdefault(target, {})
        for rec_key, mask in per_read.items():
            dst_per[rec_key] = (int(dst_per.get(rec_key, 0)) | int(mask)) & UINT64_MASK


def _filter_target_masks_by_rec_map(
    masks: Dict[Tuple[int, int, bool], Dict[Tuple[int, int, str, int], int]],
    rec_map: Dict[Tuple[int, int, str, int], Dict[str, Any]],
) -> Dict[Tuple[int, int, bool], Dict[Tuple[int, int, str, int], int]]:
    out: Dict[Tuple[int, int, bool], Dict[Tuple[int, int, str, int], int]] = {}
    for target, per_read in masks.items():
        dst_per: Dict[Tuple[int, int, str, int], int] = {}
        for rec_key, mask in per_read.items():
            if rec_key not in rec_map:
                continue
            dst_per[rec_key] = (int(dst_per.get(rec_key, 0)) | int(mask)) & UINT64_MASK
        if dst_per:
            out[target] = dst_per
    return out


def _apply_target_masks_to_rec_map(
    rec_map: Dict[Tuple[int, int, str, int], Dict[str, Any]],
    masks: Dict[Tuple[int, int, bool], Dict[Tuple[int, int, str, int], int]],
) -> None:
    for per_read in masks.values():
        for rec_key, mask in per_read.items():
            rec = rec_map.get(rec_key)
            if rec is None:
                continue
            prev = mask_as_int(rec.get("trace_expanding_mask_this_read", 0))
            rec["trace_expanding_mask_this_read"] = (prev | int(mask)) & UINT64_MASK


def _map_thread_target_masks(
    rep_target_masks: Dict[Tuple[int, int, bool], Dict[Tuple[int, int, str, int], int]],
    rep_tid: int,
    rep_pos_map: Dict[int, int],
    other_tid: int,
    other_event_index_by_pos: List[int],
) -> Dict[Tuple[int, int, bool], Dict[Tuple[int, int, str, int], int]]:
    out: Dict[Tuple[int, int, bool], Dict[Tuple[int, int, str, int], int]] = {}
    if not other_event_index_by_pos:
        return out

    for target, per_read in rep_target_masks.items():
        tgt_tid, tgt_idx, alt_taken = target
        if int(tgt_tid) != int(rep_tid):
            continue
        pos = rep_pos_map.get(int(tgt_idx))
        if pos is None or pos < 0 or pos >= len(other_event_index_by_pos):
            continue
        mapped_target = (int(other_tid), int(other_event_index_by_pos[pos]), bool(alt_taken))
        dst_per = out.setdefault(mapped_target, {})

        for rec_key, mask in per_read.items():
            rec_tid, rec_idx, rec_kind, src_i = rec_key
            if int(rec_tid) != int(rep_tid):
                continue
            pos2 = rep_pos_map.get(int(rec_idx))
            if pos2 is None or pos2 < 0 or pos2 >= len(other_event_index_by_pos):
                continue
            mapped_rec = (
                int(other_tid),
                int(other_event_index_by_pos[pos2]),
                str(rec_kind),
                int(src_i),
            )
            dst_per[mapped_rec] = (int(dst_per.get(mapped_rec, 0)) | int(mask)) & UINT64_MASK

    return out


def _build_thread_rec_map_snapshot(
    thread_events: List[TraceEvent],
    rec_map: Dict[Tuple[int, int, str, int], Dict[str, Any]],
) -> Dict[Tuple[int, int, str, int], Dict[str, Any]]:
    out: Dict[Tuple[int, int, str, int], Dict[str, Any]] = {}
    for ev in thread_events:
        src_limit = min(len(ev.src_regs), len(ev.src_vals), len(ev.src_width_bits))
        for src_i in range(src_limit):
            rec_key = (int(ev.thread_id), int(ev.index), "src", int(src_i))
            rec = rec_map.get(rec_key)
            if rec is None:
                continue
            out[rec_key] = dict(rec)
    return out


def _propagate_control_taint_single_thread(
    thread_events: List[TraceEvent],
    rec_map: Dict[Tuple[int, int, str, int], Dict[str, Any]],
    *,
    warned_unsupported_writers: Set[str],
    warned_unsupported_setp: Set[str],
    warned_toggle_blacklist: Set[str],
    toggle_fastpath_enabled: bool,
    toggle_validate_enabled: bool,
    toggle_validate_every: int,
    toggle_validate_counters: Dict[str, int],
    toggle_validate_blacklist: Set[str],
) -> Tuple[
    Dict[str, int],
    Counter,
    Counter,
    Dict[Tuple[int, int, bool], Dict[Tuple[int, int, str, int], int]],
]:
    marked_data_src_opcodes: Counter = Counter()
    unsupported_setp_opcodes: Counter = Counter()
    thread_target_masks: Dict[Tuple[int, int, bool], Dict[Tuple[int, int, str, int], int]] = {}

    stats: Dict[str, int] = {
        "control_predicate_seeds": 0,
        "control_needed_setp_events": 0,
        "control_needed_selp_events": 0,
        "control_needed_pred_logic_events": 0,
        "unsupported_setp_events": 0,
        "unsupported_predicate_writer_events": 0,
        "toggle_fastpath_setp_events": 0,
        "toggle_fastpath_selp_events": 0,
        "toggle_validate_samples": 0,
        "toggle_validate_mismatches": 0,
        "trace_marked_data_src_reads": 0,
        "trace_marked_data_src_bits": 0,
        "trace_marked_predicate_src_reads": 0,
        "trace_marked_predicate_src_bits": 0,
        "propagated_predicate_dependencies": 0,
        "max_live_control_predicates": 0,
    }

    control_needed_pred: Dict[str, Set[Tuple[int, int, bool]]] = {}

    for ev in reversed(thread_events):
        if ev.kind in ("branch", "loop_branch"):
            base_taken = parse_branch_taken(ev)
            target = (ev.thread_id, ev.index, not base_taken)
            for src_reg in ev.src_regs:
                if not is_predicate_register(src_reg):
                    continue
                if src_reg not in control_needed_pred or not control_needed_pred[src_reg]:
                    stats["control_predicate_seeds"] += 1
                deps = control_needed_pred.get(src_reg)
                if deps is None:
                    deps = set()
                    control_needed_pred[src_reg] = deps
                deps.add(target)
            if len(control_needed_pred) > stats["max_live_control_predicates"]:
                stats["max_live_control_predicates"] = len(control_needed_pred)
            continue

        dst_pred = ev.dst_reg if is_predicate_register(ev.dst_reg) else None
        if dst_pred is None:
            continue
        dst_targets = control_needed_pred.get(dst_pred)
        if not dst_targets:
            continue

        opcode_norm = normalize_opcode(ev.opcode)
        writer_supported = False

        if opcode_norm.startswith("setp"):
            writer_supported = True
            stats["control_needed_setp_events"] += 1
            try:
                baseline = eval_setp_predicate(ev.opcode, ev.src_vals, ev.src_width_bits)
            except NotImplementedError as exc:
                stats["unsupported_setp_events"] += 1
                unsupported_setp_opcodes[opcode_norm] += 1
                if opcode_norm not in warned_unsupported_setp:
                    warned_unsupported_setp.add(opcode_norm)
                    print(
                        "WARNING: control-taint setp evaluator unsupported "
                        f"opcode='{ev.opcode}' at event[{ev.index}] thread_id={ev.thread_id}: {exc}",
                        file=sys.stderr,
                    )
                baseline = None

            if baseline is not None:
                lhs_toggle_mask = 0
                rhs_toggle_mask = 0
                if (not toggle_fastpath_enabled) or (opcode_norm in toggle_validate_blacklist):
                    lhs_toggle_mask, rhs_toggle_mask = _setp_toggle_mask_legacy_bruteforce(
                        ev.opcode,
                        ev.src_vals,
                        ev.src_width_bits,
                        baseline=baseline,
                    )
                else:
                    try:
                        lhs_new, rhs_new = setp_toggle_mask(
                            ev.opcode,
                            ev.src_vals,
                            ev.src_width_bits,
                        )
                        lhs_toggle_mask, rhs_toggle_mask = lhs_new, rhs_new
                        stats["toggle_fastpath_setp_events"] += 1

                        if toggle_validate_enabled and _toggle_validation_should_sample(
                            toggle_validate_counters,
                            opcode_norm,
                            toggle_validate_every,
                        ):
                            stats["toggle_validate_samples"] += 1
                            lhs_old, rhs_old = _setp_toggle_mask_legacy_bruteforce(
                                ev.opcode,
                                ev.src_vals,
                                ev.src_width_bits,
                                baseline=baseline,
                            )
                            if lhs_old != lhs_new or rhs_old != rhs_new:
                                stats["toggle_validate_mismatches"] += 1
                                _bounded_add_opcode_blacklist(
                                    toggle_validate_blacklist, opcode_norm
                                )
                                lhs_toggle_mask, rhs_toggle_mask = lhs_old, rhs_old
                                if opcode_norm not in warned_toggle_blacklist:
                                    warned_toggle_blacklist.add(opcode_norm)
                                    print(
                                        "WARNING: control-taint toggle fast-path mismatch; "
                                        f"fallback to legacy for opcode='{opcode_norm}' "
                                        f"(event[{ev.index}] thread_id={ev.thread_id})",
                                        file=sys.stderr,
                                    )
                    except NotImplementedError:
                        lhs_toggle_mask, rhs_toggle_mask = _setp_toggle_mask_legacy_bruteforce(
                            ev.opcode,
                            ev.src_vals,
                            ev.src_width_bits,
                            baseline=baseline,
                        )

                for src_i, src_reg in enumerate(ev.src_regs):
                    if src_i >= len(ev.src_vals):
                        break
                    if src_i >= len(ev.src_width_bits):
                        continue

                    rec_key = (ev.thread_id, ev.index, "src", src_i)
                    if is_predicate_register(src_reg):
                        rec = rec_map.get(rec_key)
                        if rec is not None:
                            if or_trace_expanding_mask(rec, 1):
                                stats["trace_marked_predicate_src_reads"] += 1
                                stats["trace_marked_predicate_src_bits"] += 1
                            merge_control_target_mask(
                                thread_target_masks,
                                dst_targets,
                                rec_key,
                                1,
                            )

                        src_deps = control_needed_pred.get(src_reg)
                        if not src_deps:
                            stats["propagated_predicate_dependencies"] += 1
                            src_deps = set()
                            control_needed_pred[src_reg] = src_deps
                        src_deps.update(dst_targets)
                        continue

                    if not is_data_register(src_reg):
                        continue

                    src_w = coerce_width_bits(ev.src_width_bits[src_i], default=64)
                    if src_w == 0:
                        continue
                    if src_i == 0:
                        toggle_mask = lhs_toggle_mask & width_mask(src_w)
                    elif src_i == 1:
                        toggle_mask = rhs_toggle_mask & width_mask(src_w)
                    else:
                        toggle_mask = 0

                    if toggle_mask == 0:
                        continue
                    rec = rec_map.get(rec_key)
                    if rec is not None:
                        if or_trace_expanding_mask(rec, toggle_mask):
                            stats["trace_marked_data_src_reads"] += 1
                            stats["trace_marked_data_src_bits"] += popcount(toggle_mask)
                            marked_data_src_opcodes[opcode_norm] += 1
                        merge_control_target_mask(
                            thread_target_masks,
                            dst_targets,
                            rec_key,
                            toggle_mask,
                        )

        elif opcode_norm.startswith("selp") and is_predicate_register(ev.dst_reg):
            writer_supported = True
            stats["control_needed_selp_events"] += 1
            if len(ev.src_vals) >= 3:
                selp_toggle_masks: Dict[int, int] = {}
                use_legacy_selp = (not toggle_fastpath_enabled) or (
                    opcode_norm in toggle_validate_blacklist
                )
                if use_legacy_selp:
                    selp_toggle_masks = _selp_toggle_masks_legacy_bruteforce(ev)
                else:
                    try:
                        width_bits_default = coerce_positive_width_bits(ev.width_bits, default=32)
                        baseline_full_dst = eval_op("SELP", ev.src_vals, width_bits_default)
                        masks = backward_influence(
                            op="SELP",
                            src_vals=ev.src_vals,
                            dst_val=baseline_full_dst,
                            dst_observed_mask=1,
                            width_bits_default=width_bits_default,
                            src_widths=ev.src_width_bits,
                            thread_id=ev.thread_id,
                            pc=ev.pc,
                            opcode=ev.opcode,
                            event_index=ev.index,
                        )
                        for src_i, mask in enumerate(masks):
                            if int(mask) != 0:
                                selp_toggle_masks[src_i] = int(mask) & UINT64_MASK
                        stats["toggle_fastpath_selp_events"] += 1

                        if toggle_validate_enabled and _toggle_validation_should_sample(
                            toggle_validate_counters,
                            opcode_norm,
                            toggle_validate_every,
                        ):
                            stats["toggle_validate_samples"] += 1
                            legacy_masks = _selp_toggle_masks_legacy_bruteforce(ev)
                            mismatch = False
                            max_len = max(len(ev.src_regs), len(masks))
                            for src_i in range(max_len):
                                if (int(legacy_masks.get(src_i, 0)) & UINT64_MASK) != (
                                    int(selp_toggle_masks.get(src_i, 0)) & UINT64_MASK
                                ):
                                    mismatch = True
                                    break
                            if mismatch:
                                stats["toggle_validate_mismatches"] += 1
                                _bounded_add_opcode_blacklist(
                                    toggle_validate_blacklist, opcode_norm
                                )
                                selp_toggle_masks = legacy_masks
                                if opcode_norm not in warned_toggle_blacklist:
                                    warned_toggle_blacklist.add(opcode_norm)
                                    print(
                                        "WARNING: control-taint toggle fast-path mismatch; "
                                        f"fallback to legacy for opcode='{opcode_norm}' "
                                        f"(event[{ev.index}] thread_id={ev.thread_id})",
                                        file=sys.stderr,
                                    )
                    except NotImplementedError:
                        selp_toggle_masks = _selp_toggle_masks_legacy_bruteforce(ev)

                for src_i, src_reg in enumerate(ev.src_regs):
                    if src_i >= len(ev.src_vals):
                        break
                    if src_i >= len(ev.src_width_bits):
                        continue

                    rec_key = (ev.thread_id, ev.index, "src", src_i)
                    if is_predicate_register(src_reg):
                        src_w = 1
                    elif is_data_register(src_reg):
                        src_w = coerce_width_bits(ev.src_width_bits[src_i], default=64)
                    else:
                        continue
                    if src_w == 0:
                        continue

                    toggle_mask = int(selp_toggle_masks.get(src_i, 0)) & width_mask(src_w)

                    if toggle_mask == 0:
                        continue
                    rec = rec_map.get(rec_key)
                    if rec is not None:
                        if or_trace_expanding_mask(rec, toggle_mask):
                            if is_predicate_register(src_reg):
                                stats["trace_marked_predicate_src_reads"] += 1
                                stats["trace_marked_predicate_src_bits"] += popcount(toggle_mask)
                            else:
                                stats["trace_marked_data_src_reads"] += 1
                                stats["trace_marked_data_src_bits"] += popcount(toggle_mask)
                                marked_data_src_opcodes[opcode_norm] += 1
                        merge_control_target_mask(
                            thread_target_masks,
                            dst_targets,
                            rec_key,
                            toggle_mask,
                        )

                    if is_predicate_register(src_reg):
                        src_deps = control_needed_pred.get(src_reg)
                        if not src_deps:
                            stats["propagated_predicate_dependencies"] += 1
                            src_deps = set()
                            control_needed_pred[src_reg] = src_deps
                        src_deps.update(dst_targets)

        elif opcode_norm in ("and.pred", "or.pred", "not.pred"):
            writer_supported = True
            stats["control_needed_pred_logic_events"] += 1
            for src_i, src_reg in enumerate(ev.src_regs):
                if not is_predicate_register(src_reg):
                    continue
                rec_key = (ev.thread_id, ev.index, "src", src_i)
                rec = rec_map.get(rec_key)
                if rec is not None:
                    if or_trace_expanding_mask(rec, 1):
                        stats["trace_marked_predicate_src_reads"] += 1
                        stats["trace_marked_predicate_src_bits"] += 1
                    merge_control_target_mask(thread_target_masks, dst_targets, rec_key, 1)
                src_deps = control_needed_pred.get(src_reg)
                if not src_deps:
                    stats["propagated_predicate_dependencies"] += 1
                    src_deps = set()
                    control_needed_pred[src_reg] = src_deps
                src_deps.update(dst_targets)

        if not writer_supported:
            stats["unsupported_predicate_writer_events"] += 1
            if opcode_norm not in warned_unsupported_writers:
                warned_unsupported_writers.add(opcode_norm)
                print(
                    "WARNING: control-taint encountered unsupported predicate writer "
                    f"opcode='{ev.opcode}' at event[{ev.index}] thread_id={ev.thread_id}",
                    file=sys.stderr,
                )

        control_needed_pred.pop(dst_pred, None)
        if len(control_needed_pred) > stats["max_live_control_predicates"]:
            stats["max_live_control_predicates"] = len(control_needed_pred)

    return (
        stats,
        marked_data_src_opcodes,
        unsupported_setp_opcodes,
        thread_target_masks,
    )


def propagate_control_taint_backward(
    events: List[TraceEvent],
    rec_map: Dict[Tuple[int, int, str, int], Dict[str, Any]],
) -> Tuple[
    Dict[str, Any],
    Dict[Tuple[int, int, bool], Dict[Tuple[int, int, str, int], int]],
]:
    events_by_thread: Dict[int, List[TraceEvent]] = defaultdict(list)
    for ev in events:
        events_by_thread[ev.thread_id].append(ev)

    marked_data_src_opcodes: Counter = Counter()
    unsupported_setp_opcodes: Counter = Counter()
    target_masks: Dict[Tuple[int, int, bool], Dict[Tuple[int, int, str, int], int]] = {}

    stats: Dict[str, int] = {
        "threads": len(events_by_thread),
        "control_predicate_seeds": 0,
        "control_needed_setp_events": 0,
        "control_needed_selp_events": 0,
        "control_needed_pred_logic_events": 0,
        "unsupported_setp_events": 0,
        "unsupported_predicate_writer_events": 0,
        "toggle_fastpath_setp_events": 0,
        "toggle_fastpath_selp_events": 0,
        "toggle_validate_samples": 0,
        "toggle_validate_mismatches": 0,
        "trace_marked_data_src_reads": 0,
        "trace_marked_data_src_bits": 0,
        "trace_marked_predicate_src_reads": 0,
        "trace_marked_predicate_src_bits": 0,
        "propagated_predicate_dependencies": 0,
        "max_live_control_predicates": 0,
    }

    warned_unsupported_writers: Set[str] = set()
    warned_unsupported_setp: Set[str] = set()
    warned_toggle_blacklist: Set[str] = set()

    toggle_fastpath_enabled = env_flag("EXACT_TOGGLE_FASTPATH", True)
    toggle_validate_enabled = env_flag("EXACT_TOGGLE_VALIDATE", True)
    try:
        toggle_validate_every = max(
            1,
            int(
                os.environ.get(
                    "EXACT_TOGGLE_VALIDATE_EVERY",
                    str(_TOGGLE_VALIDATE_SAMPLE_EVERY_DEFAULT),
                )
            )
        )
    except Exception:
        toggle_validate_every = _TOGGLE_VALIDATE_SAMPLE_EVERY_DEFAULT

    toggle_validate_counters: Dict[str, int] = {}
    toggle_validate_blacklist: Set[str] = set()

    thread_dedup_enabled = env_flag("EXACT_THREAD_DEDUP", True)
    thread_dedup_validate = env_flag("EXACT_THREAD_DEDUP_VALIDATE", False)
    thread_dedup_blacklist: Set[bytes] = set()
    thread_dedup_groups_total = 0
    thread_dedup_groups_used = 0
    thread_dedup_threads_saved = 0
    thread_dedup_validate_checks = 0
    thread_dedup_validate_mismatches = 0
    thread_dedup_candidate_buckets = 0
    thread_dedup_strict_signature_threads = 0

    def accumulate_single_thread(
        local_stats: Dict[str, int],
        local_marked_ops: Counter,
        local_unsupported_setp: Counter,
        multiplier: int,
    ) -> None:
        mul = max(1, int(multiplier))
        for key in _CONTROL_TAINT_ADDITIVE_STATS:
            stats[key] += int(local_stats.get(key, 0)) * mul
        stats["max_live_control_predicates"] = max(
            int(stats.get("max_live_control_predicates", 0)),
            int(local_stats.get("max_live_control_predicates", 0))
        )
        if mul == 1:
            marked_data_src_opcodes.update(local_marked_ops)
            unsupported_setp_opcodes.update(local_unsupported_setp)
        else:
            for op, cnt in local_marked_ops.items():
                marked_data_src_opcodes[op] += int(cnt) * mul
            for op, cnt in local_unsupported_setp.items():
                unsupported_setp_opcodes[op] += int(cnt) * mul

    thread_order = list(events_by_thread.keys())
    thread_groups: List[Tuple[Optional[bytes], List[int]]] = []
    total_event_count = int(len(events))
    use_direct_signature_dedup = (
        thread_dedup_enabled
        and _control_taint_should_use_direct_signature(
            len(thread_order),
            total_event_count
        )
    )
    if use_direct_signature_dedup:
        sig_to_tids: "OrderedDict[bytes, List[int]]" = OrderedDict()
        for tid in thread_order:
            sig = _control_taint_thread_signature(events_by_thread[int(tid)])
            thread_dedup_strict_signature_threads += 1
            sig_to_tids.setdefault(sig, []).append(int(tid))
        thread_dedup_candidate_buckets = int(
            sum(1 for tids in sig_to_tids.values() if len(tids) >= 2)
        )
        for sig, tids in sig_to_tids.items():
            if len(tids) >= 2:
                thread_groups.append((sig, list(tids)))
            else:
                thread_groups.append((None, list(tids)))
    elif thread_dedup_enabled:
        tid_to_sketch: Dict[int, bytes] = {}
        sketch_to_tids: Dict[bytes, List[int]] = defaultdict(list)
        for tid in thread_order:
            sketch = _control_taint_thread_sketch(events_by_thread[tid])
            tid_to_sketch[tid] = sketch
            sketch_to_tids[sketch].append(tid)

        processed_tids: Set[int] = set()
        for tid in thread_order:
            if tid in processed_tids:
                continue
            sketch = tid_to_sketch[tid]
            sketch_bucket = sketch_to_tids.get(sketch, [tid])
            for t in sketch_bucket:
                processed_tids.add(int(t))

            if len(sketch_bucket) <= 1:
                thread_groups.append((None, [int(tid)]))
                continue

            thread_dedup_candidate_buckets += 1
            sig_to_tids: Dict[bytes, List[int]] = defaultdict(list)
            tid_to_sig: Dict[int, bytes] = {}
            for bt in sketch_bucket:
                sig = _control_taint_thread_signature(events_by_thread[int(bt)])
                thread_dedup_strict_signature_threads += 1
                tid_to_sig[int(bt)] = sig
                sig_to_tids[sig].append(int(bt))

            seen_sigs_in_bucket: Set[bytes] = set()
            for bt in sketch_bucket:
                sig = tid_to_sig[int(bt)]
                if sig in seen_sigs_in_bucket:
                    continue
                seen_sigs_in_bucket.add(sig)
                thread_groups.append((sig, list(sig_to_tids[sig])))
    else:
        thread_groups = [(None, [tid]) for tid in thread_order]

    for sig, group_tids in thread_groups:
        if not group_tids:
            continue

        use_dedup = (
            thread_dedup_enabled
            and sig is not None
            and len(group_tids) >= 2
            and sig not in thread_dedup_blacklist
        )

        if not use_dedup:
            for tid in group_tids:
                local_stats, local_marked, local_unsupported, local_masks = (
                    _propagate_control_taint_single_thread(
                        events_by_thread[tid],
                        rec_map,
                        warned_unsupported_writers=warned_unsupported_writers,
                        warned_unsupported_setp=warned_unsupported_setp,
                        warned_toggle_blacklist=warned_toggle_blacklist,
                        toggle_fastpath_enabled=toggle_fastpath_enabled,
                        toggle_validate_enabled=toggle_validate_enabled,
                        toggle_validate_every=toggle_validate_every,
                        toggle_validate_counters=toggle_validate_counters,
                        toggle_validate_blacklist=toggle_validate_blacklist,
                    )
                )
                accumulate_single_thread(
                    local_stats,
                    local_marked,
                    local_unsupported,
                    1,
                )
                _merge_target_masks_into(target_masks, local_masks)
            continue

        thread_dedup_groups_total += 1
        rep_tid = int(group_tids[0])
        rep_events = events_by_thread[rep_tid]
        rep_local_stats, rep_local_marked, rep_local_unsupported, rep_local_masks = (
            _propagate_control_taint_single_thread(
                rep_events,
                rec_map,
                warned_unsupported_writers=warned_unsupported_writers,
                warned_unsupported_setp=warned_unsupported_setp,
                warned_toggle_blacklist=warned_toggle_blacklist,
                toggle_fastpath_enabled=toggle_fastpath_enabled,
                toggle_validate_enabled=toggle_validate_enabled,
                toggle_validate_every=toggle_validate_every,
                toggle_validate_counters=toggle_validate_counters,
                toggle_validate_blacklist=toggle_validate_blacklist,
            )
        )

        rep_pos_map: Dict[int, int] = {
            int(ev.index): int(pos) for pos, ev in enumerate(rep_events)
        }
        mapped_masks_by_tid: Dict[int, Dict[Tuple[int, int, bool], Dict[Tuple[int, int, str, int], int]]] = {}
        for other_tid in group_tids[1:]:
            other_events = events_by_thread[int(other_tid)]
            other_idx_by_pos = [int(ev.index) for ev in other_events]
            mapped_masks = _map_thread_target_masks(
                rep_local_masks,
                rep_tid=rep_tid,
                rep_pos_map=rep_pos_map,
                other_tid=int(other_tid),
                other_event_index_by_pos=other_idx_by_pos,
            )
            mapped_masks_by_tid[int(other_tid)] = _filter_target_masks_by_rec_map(
                mapped_masks,
                rec_map,
            )

        dedup_valid = True
        if thread_dedup_validate and group_tids[1:]:
            thread_dedup_validate_checks += 1
            sampled_candidates = group_tids[1:]
            sampled_tid = int(
                sampled_candidates[
                    deterministic_seeded_index(
                        len(sampled_candidates),
                        "thread_dedup_validate",
                        thread_dedup_validate_checks,
                        tuple(group_tids),
                    )
                ]
            )
            sampled_events = events_by_thread[sampled_tid]
            sampled_snapshot = _build_thread_rec_map_snapshot(sampled_events, rec_map)
            (
                _sample_stats,
                _sample_marked,
                _sample_unsupported,
                sampled_local_masks,
            ) = _propagate_control_taint_single_thread(
                sampled_events,
                sampled_snapshot,
                warned_unsupported_writers=warned_unsupported_writers,
                warned_unsupported_setp=warned_unsupported_setp,
                warned_toggle_blacklist=warned_toggle_blacklist,
                toggle_fastpath_enabled=toggle_fastpath_enabled,
                toggle_validate_enabled=False,
                toggle_validate_every=toggle_validate_every,
                toggle_validate_counters={},
                toggle_validate_blacklist=toggle_validate_blacklist,
            )
            sampled_local_masks = _filter_target_masks_by_rec_map(
                sampled_local_masks,
                sampled_snapshot,
            )
            if sampled_local_masks != mapped_masks_by_tid.get(sampled_tid, {}):
                dedup_valid = False
                thread_dedup_validate_mismatches += 1
                thread_dedup_blacklist.add(sig)
                print(
                    "WARNING: thread-dedup validation mismatch; fallback to per-thread "
                    f"processing for signature={sig.hex()} sample_tid={sampled_tid}",
                    file=sys.stderr,
                )

        if not dedup_valid:
            accumulate_single_thread(
                rep_local_stats,
                rep_local_marked,
                rep_local_unsupported,
                1,
            )
            _merge_target_masks_into(target_masks, rep_local_masks)
            for other_tid in group_tids[1:]:
                local_stats, local_marked, local_unsupported, local_masks = (
                    _propagate_control_taint_single_thread(
                        events_by_thread[int(other_tid)],
                        rec_map,
                        warned_unsupported_writers=warned_unsupported_writers,
                        warned_unsupported_setp=warned_unsupported_setp,
                        warned_toggle_blacklist=warned_toggle_blacklist,
                        toggle_fastpath_enabled=toggle_fastpath_enabled,
                        toggle_validate_enabled=toggle_validate_enabled,
                        toggle_validate_every=toggle_validate_every,
                        toggle_validate_counters=toggle_validate_counters,
                        toggle_validate_blacklist=toggle_validate_blacklist,
                    )
                )
                accumulate_single_thread(
                    local_stats,
                    local_marked,
                    local_unsupported,
                    1,
                )
                _merge_target_masks_into(target_masks, local_masks)
            continue

        group_size = len(group_tids)
        thread_dedup_groups_used += 1
        thread_dedup_threads_saved += max(0, group_size - 1)

        accumulate_single_thread(
            rep_local_stats,
            rep_local_marked,
            rep_local_unsupported,
            group_size
        )
        _merge_target_masks_into(target_masks, rep_local_masks)
        for other_tid in group_tids[1:]:
            mapped_masks = mapped_masks_by_tid.get(int(other_tid), {})
            if not mapped_masks:
                continue
            _merge_target_masks_into(target_masks, mapped_masks)
            _apply_target_masks_to_rec_map(rec_map, mapped_masks)

    out = dict(stats)
    out["toggle_validate_blacklist_size"] = int(len(toggle_validate_blacklist))
    out["thread_dedup_groups_total"] = int(thread_dedup_groups_total)
    out["thread_dedup_groups_used"] = int(thread_dedup_groups_used)
    out["thread_dedup_threads_saved"] = int(thread_dedup_threads_saved)
    out["thread_dedup_validate_checks"] = int(thread_dedup_validate_checks)
    out["thread_dedup_validate_mismatches"] = int(thread_dedup_validate_mismatches)
    out["thread_dedup_blacklist_size"] = int(len(thread_dedup_blacklist))
    out["thread_dedup_candidate_buckets"] = int(thread_dedup_candidate_buckets)
    out["thread_dedup_strict_signature_threads"] = int(
        thread_dedup_strict_signature_threads
    )
    out["thread_dedup_direct_signature"] = int(use_direct_signature_dedup)
    out["marked_data_src_opcodes"] = {
        op: int(cnt) for op, cnt in sorted(marked_data_src_opcodes.items())
    }
    out["unsupported_setp_opcodes"] = {
        op: int(cnt) for op, cnt in sorted(unsupported_setp_opcodes.items())
    }
    return out, target_masks

class _LiveWordState:
    __slots__ = (
        "byte_obs_masks",
        "byte_due_masks",
        "byte_trace_masks",
        "byte_counts",
        "byte_origins",
    )

    def __init__(self) -> None:
        self.byte_obs_masks = 0
        self.byte_due_masks = 0
        self.byte_trace_masks = 0
        self.byte_counts = [0] * 8
        self.byte_origins: List[Optional[Dict[int, int]]] = [None] * 8




def _event_sort_key(ev: TraceEvent) -> Tuple[int, int]:
    return ((ev.cycle if ev.cycle is not None else ev.index), ev.index)


def _events_already_sorted(events: List[TraceEvent]) -> bool:
    if len(events) <= 1:
        return True
    prev_cycle = int(events[0].cycle) if events[0].cycle is not None else int(events[0].index)
    prev_index = int(events[0].index)
    for ev in events[1:]:
        cur_cycle = int(ev.cycle) if ev.cycle is not None else int(ev.index)
        cur_index = int(ev.index)
        if cur_cycle < prev_cycle:
            return False
        if cur_cycle == prev_cycle and cur_index < prev_index:
            return False
        prev_cycle = cur_cycle
        prev_index = cur_index
    return True


def analyze(
    events: List[TraceEvent],
    memory_ranges: Optional[List[MemoryRange]] = None,
    output_ranges: Optional[List[OutputRangeSpec]] = None,
    *,
    lite_output: bool = False,
    lite_output_profile: str = "compat",
    aggregate_read_events: bool = False,
    mask_format: str = "int",
    assume_sorted_events: bool = False,
    fault_component: str = "rf",
    emit_cache_sites: bool = True,
    output_oracle_policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if memory_ranges is None:
        memory_ranges = []
    output_oracle_policy = normalize_output_oracle_policy(output_oracle_policy)
    mask_format = str(mask_format).strip().lower()
    if mask_format not in MASK_FORMATS:
        raise ValueError(
            "mask_format must be one of {}; got {!r}".format(
                ", ".join(MASK_FORMATS), mask_format
            )
        )
    lite_output_profile = str(lite_output_profile).strip().lower()
    if lite_output_profile not in LITE_OUTPUT_PROFILES:
        raise ValueError(
            "lite_output_profile must be one of {}; got {!r}".format(
                ", ".join(LITE_OUTPUT_PROFILES), lite_output_profile
            )
        )
    if aggregate_read_events and not lite_output:
        raise ValueError("aggregate_read_events requires lite_output=True")
    if aggregate_read_events:
        print(
            "WARNING: aggregate_read_events merges per-read masks and may change "
            "classification_rates/exact_rates semantics.",
            file=sys.stderr
        )
    internal_read_record_profile = (
        "compute" if lite_output and lite_output_profile == "compute" else "compat"
    )
    use_compact_storage_rows = bool(
        internal_read_record_profile == "compute"
        and mask_format == "int"
        and (not aggregate_read_events)
    )

    fault_component = str(fault_component).strip().lower()
    if fault_component not in FAULT_COMPONENTS:
        raise ValueError(
            "fault_component must be one of {}; got {!r}".format(
                ", ".join(FAULT_COMPONENTS), fault_component
            )
        )
    emit_cache_sites = bool(emit_cache_sites)
    enable_smem_features = fault_component in ("smem_rf", "smem_lds")
    enable_memory_site_features = fault_component in ("smem_rf", "smem_lds", "l1d", "l2")
    trim_component_output = env_flag("REG_OBSERVED_COMPONENT_OUTPUT_TRIM", False)
    omit_top_level_diagnostics = env_flag(
        "REG_OBSERVED_OMIT_TOP_LEVEL_DIAGNOSTICS", False
    )
    compact_site_output = env_flag(
        "REG_OBSERVED_COMPACT_SITE_OUTPUT",
        trim_component_output,
    )
    shared_memory_component_output = env_flag(
        "REG_OBSERVED_SHARED_MEMORY_COMPONENT_OUTPUT",
        False,
    )
    share_cache_site_records = env_flag(
        "REG_OBSERVED_SHARE_CACHE_SITE_RECORDS",
        False,
    )
    force_rf_addr_masking = env_flag("REG_OBSERVED_FORCE_RF_ADDR_MASKING", False)
    omit_meta_diagnostic_samples = env_flag(
        "REG_OBSERVED_OMIT_META_DIAGNOSTIC_SAMPLES",
        trim_component_output,
    )
    omit_read_events_output = env_flag(
        "REG_OBSERVED_OMIT_READ_EVENTS_FOR_NON_RF",
        trim_component_output and (fault_component != "rf"),
    )
    if fault_component == "rf":
        omit_read_events_output = False
    collect_smem_fault_sites = bool(
        enable_smem_features
        or shared_memory_component_output
        or (not trim_component_output)
    )
    collect_l1d_fault_sites = bool(
        emit_cache_sites
        and (
            (fault_component == "l1d")
            or shared_memory_component_output
            or (not trim_component_output)
        )
    )
    enable_rf_address_fastpath = bool(
        str(fault_component).strip().lower() == "rf" or force_rf_addr_masking
    )
    collect_l2_fault_sites = bool(
        emit_cache_sites
        and (
            (fault_component == "l2")
            or shared_memory_component_output
            or (not trim_component_output)
        )
    )
    # L1D and L2 site records are byte-identical at this analyzer stage except
    # for the site-kind label; the cache-level interpretation happens later in
    # exact_sdc_compute.py.  In storage all-components mode, avoid building,
    # sorting, and serializing a duplicate L2 site list.  The compute stage
    # remaps the shared L1D list to L2 site kinds when it sees the alias marker.
    share_l1d_l2_site_records = bool(
        share_cache_site_records
        and collect_l1d_fault_sites
        and collect_l2_fault_sites
    )
    if share_l1d_l2_site_records:
        collect_l2_fault_sites = False

    output_ranges = output_ranges or []

    reg_observed_mask: Dict[int, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    reg_due_mask: Dict[int, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    reg_trace_mask: Dict[int, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    reg_smem_store_escape_mask: Dict[int, Dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    read_records: List[Any] = []
    zero_effect_read_records_elided = 0
    zero_effect_read_bits_elided = 0
    elide_zero_effect_read_records = bool(
        use_compact_storage_rows
        and env_flag("REG_OBSERVED_ELIDE_ZERO_READ_EVENTS_FOR_COMPUTE", True)
    )

    if elide_zero_effect_read_records:
        def append_read_record(rec: Any) -> None:
            nonlocal zero_effect_read_records_elided
            nonlocal zero_effect_read_bits_elided
            width_i = coerce_width_bits(_read_row_field(rec, "src_width_bits", 64), default=64)
            mask_i = width_mask(width_i)
            obs_i = mask_as_int(_read_row_field(rec, "observed_mask_this_read", 0)) & mask_i
            due_i = mask_as_int(_read_row_field(rec, "due_mask_this_read", 0)) & mask_i
            trace_i = mask_as_int(_read_row_field(rec, "trace_expanding_mask_this_read", 0)) & mask_i
            addr_due_i = mask_as_int(_read_row_field(rec, ADDR_STATIC_DUE_MASK_FIELD, 0)) & mask_i
            if (obs_i | due_i | trace_i | addr_due_i) == 0:
                zero_effect_read_records_elided += 1
                zero_effect_read_bits_elided += int(width_i)
                return
            read_records.append(rec)
    else:
        append_read_record = read_records.append

    def memory_scope_key(ev: TraceEvent) -> Optional[Tuple[Any, ...]]:
        space = canonical_space(ev.mem_space)
        if space is None:
            return None
        if space == "shared":
            return (space, ev.sm_id, ev.cta_id)
        if space == "local":
            return (space, ev.thread_id)
        return (space,)

    if assume_sorted_events:
        global_events = events
    elif _events_already_sorted(events):
        global_events = events
    else:
        global_events = sorted(events, key=_event_sort_key)

    rf_register_uid_map: Dict[str, Set[int]] = defaultdict(set)
    for uid_ev in global_events:
        for reg_name, uid_raw in zip(uid_ev.src_regs, uid_ev.src_reg_uids):
            try:
                uid_i = int(uid_raw)
            except Exception:
                uid_i = -1
            if uid_i >= 0:
                rf_register_uid_map[str(reg_name)].add(uid_i)
        if uid_ev.dst_reg is not None and uid_ev.dst_reg_uid is not None:
            try:
                dst_uid_i = int(uid_ev.dst_reg_uid)
            except Exception:
                dst_uid_i = -1
            if dst_uid_i >= 0:
                rf_register_uid_map[str(uid_ev.dst_reg)].add(dst_uid_i)
        if uid_ev.pred is not None and uid_ev.pred.uid is not None:
            try:
                pred_uid_i = int(uid_ev.pred.uid)
            except Exception:
                pred_uid_i = -1
            if pred_uid_i >= 0:
                rf_register_uid_map[str(uid_ev.pred.reg)].add(pred_uid_i)

    basic_block_transfer_enabled = env_flag(
        "REG_OBSERVED_BASIC_BLOCK_TRANSFER",
        True,
    )
    try:
        basic_block_transfer_min_len = int(
            os.environ.get("REG_OBSERVED_BASIC_BLOCK_TRANSFER_MIN_LEN", "2")
        )
    except Exception:
        basic_block_transfer_min_len = 2
    try:
        basic_block_transfer_cache_max_entries = int(
            os.environ.get("REG_OBSERVED_BASIC_BLOCK_TRANSFER_CACHE_MAX", "8192")
        )
    except Exception:
        basic_block_transfer_cache_max_entries = 8192
    if basic_block_transfer_cache_max_entries < 0:
        basic_block_transfer_cache_max_entries = 0
    if basic_block_transfer_enabled:
        (
            basic_block_transfer_end_to_events,
            basic_block_transfer_member_to_end,
        ) = _build_basic_block_transfer_maps(
            global_events,
            min_len=basic_block_transfer_min_len,
        )
    else:
        basic_block_transfer_end_to_events = {}
        basic_block_transfer_member_to_end = {}
    basic_block_transfer_cache: OrderedDict[Any, Any] = OrderedDict()
    basic_block_transfer_signature_cache: Dict[int, Tuple[Any, ...]] = {}
    basic_block_transfer_touched_cache: Dict[int, Tuple[str, ...]] = {}
    basic_block_transfer_raw_candidate_blocks = int(
        len(basic_block_transfer_end_to_events)
    )
    basic_block_transfer_raw_candidate_events = int(
        sum(len(block) for block in basic_block_transfer_end_to_events.values())
    )
    basic_block_transfer_candidate_blocks = 0
    basic_block_transfer_candidate_events = 0
    basic_block_transfer_blocks_applied = 0
    basic_block_transfer_events_applied = 0
    basic_block_transfer_cache_hits = 0
    basic_block_transfer_cache_misses = 0
    basic_block_transfer_skipped_member_events = 0

    trace_memory_oracle: Optional[TraceMemoryOracle] = None
    trace_memory_oracle_built = False

    def get_trace_memory_oracle() -> TraceMemoryOracle:
        nonlocal trace_memory_oracle
        nonlocal trace_memory_oracle_built
        if trace_memory_oracle is None:
            trace_memory_oracle = TraceMemoryOracle(global_events)
            trace_memory_oracle_built = True
        return trace_memory_oracle

    (
        output_last_writer_event_indices,
        output_last_writer_store_count,
        output_total_store_count,
        filtered_store_ratio,
    ) = build_output_last_writer_index(global_events, output_ranges)
    output_byte_last_writer = build_output_byte_last_writer_index(
        global_events,
        output_ranges,
    )
    if not output_ranges:
        fallback_output_stores = {
            int(ev.index)
            for ev in global_events
            if ev.kind == "store"
            and bool(ev.is_output_store)
            and (ev.pred is None or ev.pred.val == 1)
        }
        output_last_writer_event_indices = set(fallback_output_stores)
        output_byte_last_writer = {}
        output_last_writer_store_count = int(len(fallback_output_stores))
        output_total_store_count = int(len(fallback_output_stores))
        filtered_store_ratio = 0.0

    print(
        "DEBUG: output last-writer filtering "
        f"output_last_writer_store_count={output_last_writer_store_count} "
        f"output_total_store_count={output_total_store_count} "
        f"filtered_store_ratio={filtered_store_ratio:.6f}",
        file=sys.stderr,
    )

    control_taint_guard_enabled = env_flag(
        "EXACT_CONTROL_TAINT_RESOURCE_GUARD", True
    )
    try:
        control_taint_max_events = int(
            os.environ.get("EXACT_CONTROL_TAINT_MAX_EVENTS", "500000")
        )
    except Exception:
        control_taint_max_events = 500000
    control_taint_event_count = int(len(global_events))
    if (
        control_taint_guard_enabled
        and control_taint_max_events > 0
        and control_taint_event_count > control_taint_max_events
    ):
        raise RuntimeError(
            "control-taint propagation exceeds the configured event limit "
            f"(event_count={control_taint_event_count}, "
            f"max_events={control_taint_max_events}). "
            "Refusing to omit trace-expanding control seeds; rerun with a higher "
            "EXACT_CONTROL_TAINT_MAX_EVENTS value or set "
            "EXACT_CONTROL_TAINT_RESOURCE_GUARD=0 to perform full propagation."
        )
    else:
        control_seed_rec_map = build_control_seed_rec_map(global_events)
        (
            precomputed_control_taint_stats,
            precomputed_target_masks
        ) = propagate_control_taint_backward(global_events, control_seed_rec_map)
    trace_seed_by_read_key = build_trace_seed_map_from_target_masks(
        precomputed_target_masks
    )

    memory_live_words: Dict[Tuple[Any, ...], Dict[int, _LiveWordState]] = defaultdict(dict)
    smem_fault_sites: List[Any] = []
    l1d_fault_sites: List[Any] = []
    l2_fault_sites: List[Any] = []
    smem_fault_site_count_total = 0
    smem_rf_site_count_total = 0
    smem_lds_site_count_total = 0
    l1d_fault_site_count_total = 0
    l1d_load_site_count_total = 0
    l1d_store_site_count_total = 0
    l2_fault_site_count_total = 0
    l2_load_site_count_total = 0
    l2_store_site_count_total = 0
    zero_effect_cache_site_hist: Counter = Counter()
    zero_effect_cache_site_bits_elided = 0
    elide_zero_effect_cache_site_records = bool(
        use_compact_storage_rows and compact_site_output
    )

    def _record_site_count(site_kind: str) -> None:
        nonlocal smem_fault_site_count_total
        nonlocal smem_rf_site_count_total
        nonlocal smem_lds_site_count_total
        nonlocal l1d_fault_site_count_total
        nonlocal l1d_load_site_count_total
        nonlocal l1d_store_site_count_total
        nonlocal l2_fault_site_count_total
        nonlocal l2_load_site_count_total
        nonlocal l2_store_site_count_total

        kind = str(site_kind)
        if kind == "smem_rf":
            smem_fault_site_count_total += 1
            smem_rf_site_count_total += 1
        elif kind == "smem_lds":
            smem_fault_site_count_total += 1
            smem_lds_site_count_total += 1
        elif kind == "l1d_load":
            l1d_fault_site_count_total += 1
            l1d_load_site_count_total += 1
        elif kind == "l1d_store":
            l1d_fault_site_count_total += 1
            l1d_store_site_count_total += 1
        elif kind == "l2_load":
            l2_fault_site_count_total += 1
            l2_load_site_count_total += 1
        elif kind == "l2_store":
            l2_fault_site_count_total += 1
            l2_store_site_count_total += 1

    def _record_site_count_many(site_kind: str, count: int) -> None:
        n = int(count)
        if n <= 0:
            return
        for _ in range(n):
            _record_site_count(site_kind)

    def _record_zero_effect_cache_site(site_kind: str, width_bits: int = 8, count: int = 1) -> None:
        nonlocal zero_effect_cache_site_bits_elided
        n = int(count)
        if n <= 0:
            return
        kind = str(site_kind)
        zero_effect_cache_site_hist[kind] += n
        zero_effect_cache_site_bits_elided += n * max(0, int(width_bits))

    def _cache_site_is_zero_effect(
        observed_mask_this_site: int,
        due_mask_this_site: int,
        trace_expanding_mask_this_site: int,
    ) -> bool:
        return (
            (int(observed_mask_this_site) & 0xFF)
            | (int(due_mask_this_site) & 0xFF)
            | (int(trace_expanding_mask_this_site) & 0xFF)
        ) == 0

    def _append_cache_load_site_record(
        target: List[Any],
        *,
        site_family: str,
        site_kind: str,
        mem_space: str,
        thread_id: int,
        sm_id: int,
        cta_id: int,
        addr: int,
        cycle: int,
        event_index: int,
        width_bits: int,
        writer_event_index: int,
        observed_mask_this_site: int,
        due_mask_this_site: int,
        trace_expanding_mask_this_site: int,
    ) -> None:
        # Exact-output cache analysis treats an absent load byte history as
        # masked mass.  Therefore a cache-load byte whose observed/due/trace
        # masks are all zero can be represented by this exact histogram instead
        # of an explicit site row.  This is a deterministic live-byte slice, not
        # sampling or a tunable heuristic.
        if elide_zero_effect_cache_site_records and _cache_site_is_zero_effect(
            observed_mask_this_site,
            due_mask_this_site,
            trace_expanding_mask_this_site,
        ):
            _record_zero_effect_cache_site(site_kind, width_bits=width_bits)
            return
        target.append(
            build_internal_site_record(
                site_family=site_family,
                site_kind=site_kind,
                mem_space=mem_space,
                thread_id=thread_id,
                sm_id=sm_id,
                cta_id=cta_id,
                addr=addr,
                cycle=cycle,
                event_index=event_index,
                width_bits=width_bits,
                writer_event_index=writer_event_index,
                observed_mask_this_site=observed_mask_this_site,
                due_mask_this_site=due_mask_this_site,
                trace_expanding_mask_this_site=trace_expanding_mask_this_site,
                compact=use_compact_storage_rows,
            )
        )

    def _record_predicate_read(
        ev: TraceEvent,
        regs_obs: Dict[str, int],
        regs_due: Dict[str, int],
        regs_trace: Dict[str, int],
        pred_mask_obs: int,
        pred_mask_due: int,
        pred_mask_trace: int,
        notes: Optional[Dict[str, Any]] = None,
    ) -> None:
        if ev.pred is None:
            return
        pred_reg = ev.pred.reg
        if int(pred_mask_obs) != 0:
            merge_observed_state(regs_obs, pred_reg, 1)
        if int(pred_mask_due) != 0:
            regs_due[pred_reg] = (regs_due[pred_reg] | 1) & UINT64_MASK
        if int(pred_mask_trace) != 0:
            regs_trace[pred_reg] = (regs_trace[pred_reg] | 1) & UINT64_MASK

        pred_notes = {"pred_val": ev.pred.val}
        if notes:
            pred_notes.update(notes)
        append_read_record(
            build_internal_read_record(
                profile=internal_read_record_profile,
                event_index=ev.index,
                thread_id=ev.thread_id,
                cycle=ev.cycle,
                sm_id=ev.sm_id,
                cta_id=ev.cta_id,
                warp_id=ev.warp_id,
                pc=ev.pc,
                opcode=ev.opcode,
                read_kind="pred",
                src_index=0,
                src_reg=pred_reg,
                src_reg_uid=(ev.pred.uid if ev.pred.uid is not None else -1),
                src_width_bits=1,
                observed_mask_this_read=int(pred_mask_obs) & UINT64_MASK,
                due_mask_this_read=int(pred_mask_due) & UINT64_MASK,
                trace_expanding_mask_this_read=int(pred_mask_trace) & UINT64_MASK,
                reg_observed_mask_at_read=int(regs_obs[pred_reg]) & UINT64_MASK,
                reg_due_mask_at_read=int(regs_due[pred_reg]) & UINT64_MASK,
                notes=pred_notes,
                compact_compute=use_compact_storage_rows,
            )
        )

    def _basic_block_touched_regs(block_events: Tuple[TraceEvent, ...]) -> Tuple[str, ...]:
        regs: Set[str] = set()
        for block_ev in block_events:
            if block_ev.dst_reg is not None:
                regs.add(str(block_ev.dst_reg))
            for src_reg in block_ev.src_regs:
                regs.add(str(src_reg))
        return tuple(sorted(regs))

    def _basic_block_value_independent_event(block_ev: TraceEvent) -> bool:
        """Whether this event's exact backward transfer ignores runtime values.

        Keep this deliberately narrow.  ``IDENTITY`` covers mov/cvta-style
        register transfers: for observed/due/trace masks, each propagated bit is
        the same source bit regardless of the concrete register value.  Other
        operations may have value-dependent carries, comparisons, predicates, or
        floating-point behavior, so their dynamic values remain part of the
        cache signature.
        """

        return canonical_op(block_ev.opcode) == "IDENTITY"

    def _basic_block_signature(block_events: Tuple[TraceEvent, ...]) -> Tuple[Any, ...]:
        return tuple(
            (
                str(block_ev.pc),
                str(block_ev.opcode),
                canonical_op(block_ev.opcode),
                int(block_ev.width_bits),
                str(block_ev.dst_reg),
                (
                    None
                    if block_ev.dst_write_mask is None
                    else int(block_ev.dst_write_mask) & UINT64_MASK
                ),
                tuple(str(reg) for reg in block_ev.src_regs),
                tuple(int(w) for w in block_ev.src_width_bits),
                (
                    "value_independent"
                    if _basic_block_value_independent_event(block_ev)
                    else tuple(int(v) & UINT64_MASK for v in block_ev.src_vals)
                ),
                (
                    "value_independent"
                    if _basic_block_value_independent_event(block_ev)
                    else (
                        None
                        if block_ev.dst_val is None
                        else int(block_ev.dst_val) & UINT64_MASK
                    )
                ),
            )
            for block_ev in block_events
        )

    if basic_block_transfer_enabled and basic_block_transfer_end_to_events:
        # The transfer function is exact, but building/applying it is only worth
        # doing when a block has a structurally identical peer.  Unique dynamic
        # blocks cannot hit the memoized transfer cache, so keep them on the
        # existing per-event path.  This is a structural equivalence test, not a
        # result-tuned heuristic: the key is the full opcode/register/value
        # shape used by the transfer itself.
        block_signature_by_end: Dict[int, Tuple[Any, ...]] = {}
        signature_counts: Counter = Counter()
        for block_end_pos, block_events in basic_block_transfer_end_to_events.items():
            signature = _basic_block_signature(block_events)
            block_signature_by_end[int(block_end_pos)] = signature
            signature_counts[signature] += 1

        reusable_block_ends = {
            int(block_end_pos)
            for block_end_pos, signature in block_signature_by_end.items()
            if int(signature_counts.get(signature, 0)) > 1
        }
        if reusable_block_ends:
            basic_block_transfer_end_to_events = {
                int(block_end_pos): block_events
                for block_end_pos, block_events in basic_block_transfer_end_to_events.items()
                if int(block_end_pos) in reusable_block_ends
            }
            basic_block_transfer_member_to_end = {
                int(pos): int(block_end_pos)
                for pos, block_end_pos in basic_block_transfer_member_to_end.items()
                if int(block_end_pos) in reusable_block_ends
            }
            basic_block_transfer_signature_cache.update(
                {
                    int(block_end_pos): signature
                    for block_end_pos, signature in block_signature_by_end.items()
                    if int(block_end_pos) in reusable_block_ends
                }
            )
        else:
            basic_block_transfer_end_to_events = {}
            basic_block_transfer_member_to_end = {}

    basic_block_transfer_candidate_blocks = int(
        len(basic_block_transfer_end_to_events)
    )
    basic_block_transfer_candidate_events = int(
        sum(len(block) for block in basic_block_transfer_end_to_events.values())
    )

    def _basic_block_state_key(
        touched_regs: Tuple[str, ...],
        regs_obs: Dict[str, int],
        regs_due: Dict[str, int],
        regs_trace: Dict[str, int],
        regs_smem_escape: Dict[str, int],
    ) -> Tuple[Any, ...]:
        return tuple(
            (
                reg,
                int(regs_obs.get(reg, 0)) & UINT64_MASK,
                int(regs_due.get(reg, 0)) & UINT64_MASK,
                int(regs_trace.get(reg, 0)) & UINT64_MASK,
                int(regs_smem_escape.get(reg, 0)) & UINT64_MASK,
            )
            for reg in touched_regs
        )

    def _apply_basic_block_final_state(
        final_state: Tuple[Any, ...],
        regs_obs: Dict[str, int],
        regs_due: Dict[str, int],
        regs_trace: Dict[str, int],
        regs_smem_escape: Dict[str, int],
    ) -> None:
        for (
            reg,
            obs,
            due,
            trace,
            smem_escape,
        ) in final_state:
            regs_obs[reg] = int(obs) & UINT64_MASK
            regs_due[reg] = int(due) & UINT64_MASK
            regs_trace[reg] = int(trace) & UINT64_MASK
            regs_smem_escape[reg] = int(smem_escape) & UINT64_MASK

    def _emit_basic_block_read_records(
        block_events: Tuple[TraceEvent, ...],
        read_masks: Tuple[Tuple[int, int, int, int, int, int, int], ...],
    ) -> None:
        for (
            event_offset,
            src_i,
            src_obs,
            src_due,
            src_trace,
            reg_obs_at_read,
            reg_due_at_read,
        ) in read_masks:
            block_ev = block_events[int(event_offset)]
            src_index = int(src_i)
            src_reg = block_ev.src_regs[src_index]
            src_w = block_ev.src_width_bits[src_index]
            append_read_record(
                build_internal_read_record(
                    profile=internal_read_record_profile,
                    event_index=block_ev.index,
                    thread_id=block_ev.thread_id,
                    cycle=block_ev.cycle,
                    sm_id=block_ev.sm_id,
                    cta_id=block_ev.cta_id,
                    warp_id=block_ev.warp_id,
                    pc=block_ev.pc,
                    opcode=block_ev.opcode,
                    read_kind="src",
                    src_index=src_index,
                    src_reg=src_reg,
                    src_reg_uid=(
                        block_ev.src_reg_uids[src_index]
                        if 0 <= src_index < len(block_ev.src_reg_uids)
                        else -1
                    ),
                    src_width_bits=src_w,
                    observed_mask_this_read=int(src_obs) & UINT64_MASK,
                    due_mask_this_read=int(src_due) & UINT64_MASK,
                    trace_expanding_mask_this_read=int(src_trace) & UINT64_MASK,
                    reg_observed_mask_at_read=int(reg_obs_at_read) & UINT64_MASK,
                    reg_due_mask_at_read=int(reg_due_at_read) & UINT64_MASK,
                    compact_compute=use_compact_storage_rows,
                )
            )

    def _compute_basic_block_transfer(
        block_events: Tuple[TraceEvent, ...],
        touched_regs: Tuple[str, ...],
        regs_obs: Dict[str, int],
        regs_due: Dict[str, int],
        regs_trace: Dict[str, int],
        regs_smem_escape: Dict[str, int],
    ) -> Tuple[
        Tuple[Any, ...],
        Tuple[Tuple[int, int, int, int, int, int, int], ...],
        int,
        int,
    ]:
        local_obs: Dict[str, int] = {
            reg: int(regs_obs.get(reg, 0)) & UINT64_MASK for reg in touched_regs
        }
        local_due: Dict[str, int] = {
            reg: int(regs_due.get(reg, 0)) & UINT64_MASK for reg in touched_regs
        }
        local_trace: Dict[str, int] = {
            reg: int(regs_trace.get(reg, 0)) & UINT64_MASK for reg in touched_regs
        }
        local_smem_escape: Dict[str, int] = {
            reg: int(regs_smem_escape.get(reg, 0)) & UINT64_MASK
            for reg in touched_regs
        }
        read_masks: List[Tuple[int, int, int, int, int, int, int]] = []
        local_zero_effect_read_records_elided = 0
        local_zero_effect_read_bits_elided = 0
        event_offset_by_index = {
            int(block_ev.index): int(offset)
            for offset, block_ev in enumerate(block_events)
        }

        for block_ev in reversed(block_events):
            op = canonical_op(block_ev.opcode)
            write_mask = block_ev.dst_write_mask
            if write_mask is None:
                write_mask = width_mask(dst_width_bits(op, block_ev.width_bits))
            write_mask &= UINT64_MASK

            dst_reg = str(block_ev.dst_reg)
            dst_live_obs = local_obs.get(dst_reg, 0) & write_mask
            dst_live_due = local_due.get(dst_reg, 0) & write_mask
            dst_live_trace = (
                local_trace.get(dst_reg, 0) & write_mask
            ) if enable_memory_site_features else 0
            dst_live_smem_escape = (
                local_smem_escape.get(dst_reg, 0) & write_mask
            ) if enable_smem_features else 0

            src_masks_obs = [0] * len(block_ev.src_regs)
            src_masks_due = [0] * len(block_ev.src_regs)
            src_masks_trace = [0] * len(block_ev.src_regs)

            if (
                elide_zero_effect_read_records
                and (
                    int(dst_live_obs)
                    | int(dst_live_due)
                    | int(dst_live_trace)
                    | int(dst_live_smem_escape)
                )
                == 0
            ):
                zero_effect_event_bits = 0
                has_trace_seed = False
                for src_i, _src_reg in enumerate(block_ev.src_regs):
                    src_w = coerce_width_bits(
                        block_ev.src_width_bits[src_i]
                        if src_i < len(block_ev.src_width_bits)
                        else 64,
                        default=64,
                    )
                    zero_effect_event_bits += int(src_w)
                    if (
                        int(
                            trace_seed_by_read_key.get(
                                (
                                    int(block_ev.thread_id),
                                    int(block_ev.index),
                                    "src",
                                    int(src_i),
                                ),
                                0,
                            )
                        )
                        & width_mask(src_w)
                    ) != 0:
                        has_trace_seed = True
                        break
                if not has_trace_seed:
                    local_zero_effect_read_records_elided += int(len(block_ev.src_regs))
                    local_zero_effect_read_bits_elided += int(zero_effect_event_bits)
                    continue

            if (
                dst_live_obs != 0
                or dst_live_due != 0
                or dst_live_trace != 0
                or dst_live_smem_escape != 0
            ):
                if op not in SUPPORTED_OPS:
                    raise NotImplementedError(
                        "Unsupported opcode with observed/due/trace destination bits: "
                        f"thread_id={block_ev.thread_id}, pc={block_ev.pc}, "
                        f"event_index={block_ev.index}, opcode={block_ev.opcode}, "
                        f"canonical_op={op}"
                    )

                if op == "IDENTITY":
                    if len(block_ev.src_vals) not in (0, 1):
                        raise ValueError(
                            f"event[{block_ev.index}] opcode {block_ev.opcode} "
                            f"expects 0 or 1 srcs, got {len(block_ev.src_vals)}"
                        )
                else:
                    need = expected_src_count(op)
                    if len(block_ev.src_vals) != need:
                        raise ValueError(
                            f"event[{block_ev.index}] opcode {block_ev.opcode} "
                            f"expects {need} srcs, got {len(block_ev.src_vals)}"
                        )

                if block_ev.dst_val is None:
                    try:
                        dst_val = eval_op(op, block_ev.src_vals, block_ev.width_bits)
                    except KeyError as exc:
                        raise NotImplementedError(
                            "Unsupported opcode while computing dst_val: "
                            f"thread_id={block_ev.thread_id}, pc={block_ev.pc}, "
                            f"event_index={block_ev.index}, opcode={block_ev.opcode}, "
                            f"canonical_op={op}"
                        ) from exc
                else:
                    dst_val = block_ev.dst_val

                obs_mask_for_exact = int(dst_live_obs) & UINT64_MASK

                if len(block_ev.src_vals) > 0:
                    (
                        src_masks_obs,
                        src_masks_due,
                        src_masks_trace,
                    ) = backward_influence_triplet(
                        op=op,
                        src_vals=block_ev.src_vals,
                        dst_val=dst_val,
                        obs_mask=obs_mask_for_exact,
                        due_mask=dst_live_due,
                        trace_mask=dst_live_trace,
                        width_bits_default=block_ev.width_bits,
                        src_widths=block_ev.src_width_bits,
                        thread_id=block_ev.thread_id,
                        pc=block_ev.pc,
                        opcode=block_ev.opcode,
                        event_index=block_ev.index,
                    )

                for src_i, src_reg_raw in enumerate(block_ev.src_regs):
                    src_reg = str(src_reg_raw)
                    merge_observed_state(local_obs, src_reg, int(src_masks_obs[src_i]))
                    local_due[src_reg] = (
                        local_due.get(src_reg, 0) | src_masks_due[src_i]
                    ) & UINT64_MASK
                    local_trace[src_reg] = (
                        local_trace.get(src_reg, 0) | src_masks_trace[src_i]
                    ) & UINT64_MASK

                local_obs[dst_reg] = local_obs.get(dst_reg, 0) & (
                    ~write_mask
                ) & UINT64_MASK
                local_due[dst_reg] = local_due.get(dst_reg, 0) & (
                    ~write_mask
                ) & UINT64_MASK
                local_trace[dst_reg] = local_trace.get(dst_reg, 0) & (
                    ~write_mask
                ) & UINT64_MASK
                local_smem_escape[dst_reg] = local_smem_escape.get(dst_reg, 0) & (
                    ~write_mask
                ) & UINT64_MASK

            for src_i, src_reg_raw in enumerate(block_ev.src_regs):
                src_reg = str(src_reg_raw)
                src_w = max(
                    0,
                    min(
                        64,
                        int(block_ev.src_width_bits[src_i])
                        if src_i < len(block_ev.src_width_bits)
                        else 64,
                    ),
                )
                trace_seed_mask = (
                    int(
                        trace_seed_by_read_key.get(
                            (
                                int(block_ev.thread_id),
                                int(block_ev.index),
                                "src",
                                int(src_i),
                            ),
                            0,
                        )
                    )
                    & width_mask(src_w)
                )
                if trace_seed_mask != 0:
                    src_masks_trace[src_i] = (
                        int(src_masks_trace[src_i]) | trace_seed_mask
                    ) & UINT64_MASK
                    local_trace[src_reg] = (
                        local_trace.get(src_reg, 0) | trace_seed_mask
                    ) & UINT64_MASK
                src_obs_i = int(src_masks_obs[src_i]) & UINT64_MASK
                src_due_i = int(src_masks_due[src_i]) & UINT64_MASK
                src_trace_i = int(src_masks_trace[src_i]) & UINT64_MASK
                if (
                    elide_zero_effect_read_records
                    and ((src_obs_i | src_due_i | src_trace_i) & width_mask(src_w)) == 0
                ):
                    # Exact zero-read elision inside cached basic-block transfers.
                    # This mirrors append_read_record's compute-profile behavior,
                    # but stores only the accounting in the transfer result so
                    # cache hits do not replay semantically masked read tuples.
                    local_zero_effect_read_records_elided += 1
                    local_zero_effect_read_bits_elided += int(src_w)
                    continue
                read_masks.append(
                    (
                        int(event_offset_by_index[int(block_ev.index)]),
                        int(src_i),
                        int(src_obs_i) & UINT64_MASK,
                        int(src_due_i) & UINT64_MASK,
                        int(src_trace_i) & UINT64_MASK,
                        int(local_obs.get(src_reg, 0)) & UINT64_MASK,
                        int(local_due.get(src_reg, 0)) & UINT64_MASK,
                    )
                )

        final_state = _basic_block_state_key(
            touched_regs,
            local_obs,
            local_due,
            local_trace,
            local_smem_escape,
        )
        return (
            final_state,
            tuple(read_masks),
            int(local_zero_effect_read_records_elided),
            int(local_zero_effect_read_bits_elided),
        )

    def _apply_basic_block_transfer(
        block_end_pos: int,
        block_events: Tuple[TraceEvent, ...],
        regs_obs: Dict[str, int],
        regs_due: Dict[str, int],
        regs_trace: Dict[str, int],
        regs_smem_escape: Dict[str, int],
    ) -> Tuple[bool, int, int]:
        nonlocal zero_effect_read_records_elided
        nonlocal zero_effect_read_bits_elided

        touched_regs = basic_block_transfer_touched_cache.get(block_end_pos)
        if touched_regs is None:
            touched_regs = _basic_block_touched_regs(block_events)
            basic_block_transfer_touched_cache[block_end_pos] = touched_regs
        signature = basic_block_transfer_signature_cache.get(block_end_pos)
        if signature is None:
            signature = _basic_block_signature(block_events)
            basic_block_transfer_signature_cache[block_end_pos] = signature

        trace_seed_key = tuple(
            int(
                trace_seed_by_read_key.get(
                    (int(block_ev.thread_id), int(block_ev.index), "src", int(src_i)),
                    0,
                )
            )
            & UINT64_MASK
            for block_ev in block_events
            for src_i, _src_reg in enumerate(block_ev.src_regs)
        )
        state_key = _basic_block_state_key(
            touched_regs,
            regs_obs,
            regs_due,
            regs_trace,
            regs_smem_escape,
        )
        cache_key = (
            signature,
            trace_seed_key,
            bool(enable_memory_site_features),
            bool(enable_smem_features),
            state_key,
        )
        cached = (
            basic_block_transfer_cache.get(cache_key)
            if basic_block_transfer_cache_max_entries != 0
            else None
        )
        cache_hit = cached is not None
        if cached is None:
            cached = _compute_basic_block_transfer(
                block_events,
                touched_regs,
                regs_obs,
                regs_due,
                regs_trace,
                regs_smem_escape,
            )
            if basic_block_transfer_cache_max_entries != 0:
                basic_block_transfer_cache[cache_key] = cached
                if (
                    basic_block_transfer_cache_max_entries > 0
                    and len(basic_block_transfer_cache)
                    > basic_block_transfer_cache_max_entries
                ):
                    basic_block_transfer_cache.popitem(last=False)
        else:
            basic_block_transfer_cache.move_to_end(cache_key)

        (
            final_state,
            read_masks,
            block_zero_records_elided,
            block_zero_bits_elided,
        ) = cached
        _apply_basic_block_final_state(
            final_state,
            regs_obs,
            regs_due,
            regs_trace,
            regs_smem_escape,
        )
        _emit_basic_block_read_records(block_events, read_masks)
        zero_effect_read_records_elided += int(block_zero_records_elided)
        zero_effect_read_bits_elided += int(block_zero_bits_elided)
        return (
            cache_hit,
            int(len(block_events)),
            int(len(read_masks)),
        )

    forwarded_load_bytes_total = 0
    forwarded_load_bytes_with_store = 0
    forwarded_cross_thread_count = 0
    stores_marked_observed_by_memory_flow = 0
    addr_observed_seed_suppressed_bits = 0
    addr_observed_seed_suppressed_events = 0
    addr_proof_diagnostics = {
        "addr_same_value_masked_bits": 0,
        "addr_same_value_masked_events": 0,
        "addr_alias_unknown_bits": 0,
        "addr_alias_unknown_events": 0,
        "store_addr_proven_masked_bits": 0,
        "store_addr_proven_masked_events": 0,
    }

    for _event_pos in range(len(global_events) - 1, -1, -1):
        ev = global_events[_event_pos]
        tid = ev.thread_id
        regs_obs = reg_observed_mask[tid]
        regs_due = reg_due_mask[tid]
        regs_trace = reg_trace_mask[tid]
        regs_smem_escape = reg_smem_store_escape_mask[tid]

        if basic_block_transfer_enabled:
            block_end_pos = basic_block_transfer_member_to_end.get(_event_pos)
            if block_end_pos is not None:
                if int(block_end_pos) != int(_event_pos):
                    basic_block_transfer_skipped_member_events += 1
                    continue
                block_events = basic_block_transfer_end_to_events.get(block_end_pos)
                if block_events:
                    (
                        cache_hit,
                        event_count,
                        _read_count,
                    ) = (
                        _apply_basic_block_transfer(
                            int(block_end_pos),
                            block_events,
                            regs_obs,
                            regs_due,
                            regs_trace,
                            regs_smem_escape,
                        )
                    )
                    basic_block_transfer_blocks_applied += 1
                    basic_block_transfer_events_applied += int(event_count)
                    if cache_hit:
                        basic_block_transfer_cache_hits += 1
                    else:
                        basic_block_transfer_cache_misses += 1
                    continue

        if ev.kind == "store":
            if ev.pred is not None and ev.pred.val == 0:
                pred_obs = 0
                pred_due = 0
                pred_trace = 0
                if ev.mem_addr is not None and is_out_of_range_ea(
                    ev,
                    int(ev.mem_addr),
                    memory_ranges,
                ):
                    pred_due = 1

                pred_live_obs = 0
                pred_live_due = 0
                pred_live_trace = 0
                scope_key = memory_scope_key(ev)
                size_bytes = access_size_bytes_for_event(ev)
                if (
                    scope_key is not None
                    and ev.mem_addr is not None
                    and size_bytes > 0
                ):
                    scope_words = memory_live_words.get(scope_key)
                    if scope_words is not None:
                        base_addr = int(ev.mem_addr)
                        for byte_i in range(min(int(size_bytes), 8)):
                            addr = base_addr + int(byte_i)
                            word_addr = int(addr >> 3)
                            lane = int(addr & 0x7)
                            state = scope_words.get(word_addr)
                            if state is None:
                                continue
                            shift = lane * 8
                            out_shift = 8 * int(byte_i)
                            pred_live_obs |= (
                                int((state.byte_obs_masks >> shift) & 0xFF)
                                << out_shift
                            )
                            if enable_memory_site_features:
                                pred_live_due |= (
                                    int((state.byte_due_masks >> shift) & 0xFF)
                                    << out_shift
                                )
                                pred_live_trace |= (
                                    int((state.byte_trace_masks >> shift) & 0xFF)
                                    << out_shift
                                )
                if (pred_live_obs | pred_live_due | pred_live_trace) != 0:
                    store_pred_obs, store_pred_due, store_pred_trace = (
                        store_predicate_effect_masks(
                            ev,
                            get_trace_memory_oracle(),
                            pred_live_obs,
                            pred_live_due,
                            pred_live_trace,
                            executed_in_trace=False,
                        )
                    )
                    pred_obs |= int(store_pred_obs)
                    pred_due |= int(store_pred_due)
                    pred_trace |= int(store_pred_trace)

                _record_predicate_read(
                    ev,
                    regs_obs,
                    regs_due,
                    regs_trace,
                    pred_obs,
                    pred_due,
                    pred_trace,
                    notes={
                        "predicate_gate": "store",
                        "predicate_effect": "enable_skipped_store",
                    },
                )
                continue

            memory_forward_live_mask = 0
            memory_forward_due_live_mask = 0
            memory_forward_trace_live_mask = 0
            memory_forward_src_obs_mask = 0
            memory_forward_src_due_mask = 0
            memory_forward_src_trace_mask = 0
            memory_forward_live_bytes = 0
            memory_forward_pending_bytes = 0

            scope_key = memory_scope_key(ev)
            if scope_key is not None and ev.mem_addr is not None:
                store_size_bytes = access_size_bytes_for_event(ev)
                if store_size_bytes > 0:
                    scope_words = memory_live_words.get(scope_key)
                    if scope_words is not None:
                        base_addr = int(ev.mem_addr)
                        for byte_i in range(store_size_bytes):
                            addr = base_addr + byte_i
                            word_addr = int(addr >> 3)
                            lane = int(addr & 0x7)
                            state = scope_words.get(word_addr)
                            shift = lane * 8
                            live_byte_obs_mask = 0
                            live_byte_due_mask = 0
                            live_byte_trace_mask = 0
                            pending = 0
                            origin_counts: Optional[Dict[int, int]] = None
                            if state is not None:
                                live_byte_obs_mask = int((state.byte_obs_masks >> shift) & 0xFF)
                                if enable_memory_site_features:
                                    live_byte_due_mask = int((state.byte_due_masks >> shift) & 0xFF)
                                    live_byte_trace_mask = int(
                                        (state.byte_trace_masks >> shift) & 0xFF
                                    )

                                if live_byte_obs_mask != 0:
                                    memory_forward_live_mask |= (
                                        live_byte_obs_mask << (8 * byte_i)
                                    ) & UINT64_MASK
                                    memory_forward_live_bytes += 1

                                    pending = int(state.byte_counts[lane])
                                    if pending <= 0:
                                        pending = 1
                                    memory_forward_pending_bytes += pending
                                    forwarded_load_bytes_with_store += pending

                                    origin_counts = state.byte_origins[lane]
                                    if origin_counts is not None:
                                        for origin_tid, origin_count in origin_counts.items():
                                            if int(origin_tid) != tid:
                                                forwarded_cross_thread_count += int(origin_count)

                                src_byte_i = ev.store_data_byte_offset + byte_i
                                if src_byte_i < 0:
                                    raise ValueError(
                                        f"event[{ev.index}] invalid negative store_data_byte_offset={ev.store_data_byte_offset}"
                                    )
                                if src_byte_i < 8:
                                    memory_forward_src_obs_mask |= (
                                        live_byte_obs_mask << (8 * src_byte_i)
                                    ) & UINT64_MASK
                                    if enable_memory_site_features:
                                        memory_forward_src_due_mask |= (
                                            live_byte_due_mask << (8 * src_byte_i)
                                        ) & UINT64_MASK
                                        memory_forward_src_trace_mask |= (
                                            live_byte_trace_mask << (8 * src_byte_i)
                                        ) & UINT64_MASK

                                if enable_memory_site_features:
                                    memory_forward_due_live_mask |= (
                                        live_byte_due_mask << (8 * byte_i)
                                    ) & UINT64_MASK
                                    memory_forward_trace_live_mask |= (
                                        live_byte_trace_mask << (8 * byte_i)
                                    ) & UINT64_MASK

                                state.byte_obs_masks &= (~(0xFF << shift)) & UINT64_MASK
                                if enable_memory_site_features:
                                    state.byte_due_masks &= (~(0xFF << shift)) & UINT64_MASK
                                    state.byte_trace_masks &= (~(0xFF << shift)) & UINT64_MASK
                                state.byte_counts[lane] = 0
                                lane_origins = state.byte_origins[lane]
                                if lane_origins is not None:
                                    lane_origins.clear()
                                state.byte_origins[lane] = None

                                if (
                                    state.byte_obs_masks == 0
                                    and (
                                        (state.byte_due_masks == 0 and state.byte_trace_masks == 0)
                                        or (not enable_memory_site_features)
                                    )
                                ):
                                    scope_words.pop(word_addr, None)

                            cspace = canonical_space(ev.mem_space)
                            if cspace == "shared":
                                _record_site_count("smem_rf")
                            if collect_smem_fault_sites and cspace == "shared":
                                smem_fault_sites.append(
                                    build_internal_site_record(
                                        site_family="smem",
                                        site_kind="smem_rf",
                                        mem_space="shared",
                                        thread_id=tid,
                                        sm_id=ev.sm_id,
                                        cta_id=ev.cta_id,
                                        addr=int(addr),
                                        cycle=ev.cycle,
                                        event_index=int(ev.index),
                                        width_bits=8,
                                        writer_event_index=int(ev.index),
                                        observed_mask_this_site=int(live_byte_obs_mask) & 0xFF,
                                        due_mask_this_site=int(live_byte_due_mask) & 0xFF,
                                        trace_expanding_mask_this_site=int(live_byte_trace_mask)
                                        & 0xFF,
                                        compact=use_compact_storage_rows,
                                    )
                                )
                            if emit_cache_sites and cspace in ("global", "local"):
                                _record_site_count("l1d_store")
                            if collect_l1d_fault_sites and cspace in ("global", "local"):
                                l1d_fault_sites.append(
                                    build_internal_site_record(
                                        site_family="l1d",
                                        site_kind="l1d_store",
                                        mem_space=str(cspace),
                                        thread_id=tid,
                                        sm_id=ev.sm_id,
                                        cta_id=ev.cta_id,
                                        addr=int(addr),
                                        cycle=ev.cycle,
                                        event_index=int(ev.index),
                                        width_bits=8,
                                        writer_event_index=int(ev.index),
                                        observed_mask_this_site=int(live_byte_obs_mask) & 0xFF,
                                        due_mask_this_site=int(live_byte_due_mask) & 0xFF,
                                        trace_expanding_mask_this_site=int(live_byte_trace_mask)
                                        & 0xFF,
                                        compact=use_compact_storage_rows,
                                    )
                                )
                            if emit_cache_sites and cspace in ("global", "local"):
                                _record_site_count("l2_store")
                            if collect_l2_fault_sites and cspace in ("global", "local"):
                                l2_fault_sites.append(
                                    build_internal_site_record(
                                        site_family="l2",
                                        site_kind="l2_store",
                                        mem_space=str(cspace),
                                        thread_id=tid,
                                        sm_id=ev.sm_id,
                                        cta_id=ev.cta_id,
                                        addr=int(addr),
                                        cycle=ev.cycle,
                                        event_index=int(ev.index),
                                        width_bits=8,
                                        writer_event_index=int(ev.index),
                                        observed_mask_this_site=int(live_byte_obs_mask) & 0xFF,
                                        due_mask_this_site=int(live_byte_due_mask) & 0xFF,
                                        trace_expanding_mask_this_site=int(live_byte_trace_mask)
                                        & 0xFF,
                                        compact=use_compact_storage_rows,
                                    )
                                )

                        if len(scope_words) == 0:
                            memory_live_words.pop(scope_key, None)

            observed_output_store = (
                int(ev.index) in output_last_writer_event_indices
                if output_ranges
                else bool(ev.is_output_store)
            )
            if observed_output_store:
                observed_output_store = output_store_participates_in_comparison(
                    ev,
                    output_oracle_policy,
                    output_ranges,
                )

            src_i = ev.store_data_src_index
            src_reg: Optional[str] = None
            src_w = 64
            if ev.src_regs:
                if src_i < 0 or src_i >= len(ev.src_regs):
                    raise ValueError(f"event[{ev.index}] invalid store_data_src_index")
                src_reg = ev.src_regs[src_i]
                if src_i < len(ev.src_width_bits):
                    src_w = coerce_width_bits(ev.src_width_bits[src_i], default=64)

            output_store_mask = 0
            if observed_output_store:
                if ev.store_size_bytes is None:
                    raise ValueError(f"event[{ev.index}] output store missing store_size_bytes")
                output_store_mask = bytes_to_mask(ev.store_size_bytes, ev.store_data_byte_offset)

            if src_reg is not None:
                src_mask_w = width_mask(src_w)
                output_store_mask &= src_mask_w
                memory_forward_src_obs_mask &= src_mask_w
                memory_forward_src_due_mask &= src_mask_w
                memory_forward_src_trace_mask &= src_mask_w
                store_data_obs_mask = (
                    output_store_mask | memory_forward_src_obs_mask
                ) & UINT64_MASK
                store_data_due_mask = (
                    memory_forward_src_due_mask & UINT64_MASK
                ) if enable_memory_site_features else 0
                store_data_trace_mask = (
                    memory_forward_src_trace_mask & UINT64_MASK
                ) if enable_memory_site_features else 0

                if (
                    store_data_obs_mask != 0
                    or store_data_due_mask != 0
                    or store_data_trace_mask != 0
                ):
                    merge_observed_state(
                        regs_obs,
                        src_reg,
                        int(store_data_obs_mask) & UINT64_MASK,
                    )
                    regs_due[src_reg] = (regs_due[src_reg] | store_data_due_mask) & UINT64_MASK
                    regs_trace[src_reg] = (
                        regs_trace[src_reg] | store_data_trace_mask
                    ) & UINT64_MASK
                    if (
                        canonical_space(ev.mem_space) == "shared"
                        and memory_forward_src_obs_mask != 0
                    ):
                        regs_smem_escape[src_reg] = (
                            regs_smem_escape[src_reg] | memory_forward_src_obs_mask
                        ) & UINT64_MASK
                if (
                    elide_zero_effect_read_records
                    and (
                        (int(store_data_obs_mask) | int(store_data_due_mask) | int(store_data_trace_mask))
                        & width_mask(src_w)
                    ) == 0
                ):
                    zero_effect_read_records_elided += 1
                    zero_effect_read_bits_elided += int(coerce_width_bits(src_w, default=64))
                    continue
                append_read_record(
                    build_internal_read_record(
                        profile=internal_read_record_profile,
                        event_index=ev.index,
                        thread_id=tid,
                        cycle=ev.cycle,
                        sm_id=ev.sm_id,
                        cta_id=ev.cta_id,
                        warp_id=ev.warp_id,
                        pc=ev.pc,
                        opcode=ev.opcode,
                        read_kind="store_data",
                        src_index=src_i,
                        src_reg=src_reg,
                        src_reg_uid=(
                            ev.src_reg_uids[src_i]
                            if 0 <= src_i < len(ev.src_reg_uids)
                            else -1
                        ),
                        src_width_bits=src_w,
                        observed_mask_this_read=int(store_data_obs_mask) & UINT64_MASK,
                        due_mask_this_read=int(store_data_due_mask) & UINT64_MASK,
                        trace_expanding_mask_this_read=int(store_data_trace_mask)
                        & UINT64_MASK,
                        reg_observed_mask_at_read=int(regs_obs[src_reg]) & UINT64_MASK,
                        reg_due_mask_at_read=int(regs_due[src_reg]) & UINT64_MASK,
                        notes={
                            "is_output_store": bool(ev.is_output_store),
                            "is_output_last_writer": bool(
                                int(ev.index) in output_last_writer_event_indices
                            ),
                            "output_store_observed_seed": bool(observed_output_store),
                            "store_size_bytes": ev.store_size_bytes,
                            "store_data_byte_offset": ev.store_data_byte_offset,
                            "memory_forwarded": bool(memory_forward_live_bytes > 0),
                            "memory_forwarded_live_mask": int(memory_forward_live_mask)
                            & UINT64_MASK,
                            "memory_forwarded_due_live_mask": int(
                                memory_forward_due_live_mask
                            )
                            & UINT64_MASK,
                            "memory_forwarded_trace_live_mask": int(
                                memory_forward_trace_live_mask
                            )
                            & UINT64_MASK,
                            "memory_forwarded_live_bytes": int(memory_forward_live_bytes),
                            "memory_forwarded_pending_load_bytes": int(
                                memory_forward_pending_bytes
                            ),
                        },
                        compact_compute=use_compact_storage_rows,
                    )
                )

            output_store_memory_mask = store_data_mask_src_to_memory(
                ev,
                int(output_store_mask),
            )
            force_store_address_observed = memory_forward_live_bytes > 0
            store_address_seed_observed = (
                force_store_address_observed
                or should_seed_observed_for_store(ev, observed_output_store)
            )
            if force_store_address_observed:
                stores_marked_observed_by_memory_flow += 1

            store_has_addr_meta = has_address_metadata(ev)
            if force_store_address_observed and not store_has_addr_meta:
                raise ValueError(
                    "event[{}] memory-forwarded store requires address metadata "
                    "(ea_expr or ea_base_src_indices)".format(ev.index)
                )
            if store_has_addr_meta:
                store_address_mask_proof = None
                proof_live_mask = (
                    int(memory_forward_live_mask)
                    | int(memory_forward_due_live_mask)
                    | int(memory_forward_trace_live_mask)
                    | int(output_store_memory_mask)
                ) & UINT64_MASK
                if (
                    store_address_seed_observed
                    and proof_live_mask != 0
                    and not force_rf_addr_masking
                    and scope_key is not None
                    and ev.mem_addr is not None
                ):
                    proof_scope_words = memory_live_words.get(scope_key)
                    proof_cache: Dict[int, bool] = {}
                    proof_memory_oracle = get_trace_memory_oracle()

                    def store_address_mask_proof(
                        candidate_ev: TraceEvent,
                        candidate_ea: int,
                    ) -> bool:
                        key = int(candidate_ea) & UINT64_MASK
                        cached = proof_cache.get(key)
                        if cached is not None:
                            return bool(cached)
                        proven = store_address_alias_is_proven_masked(
                            candidate_ev,
                            int(candidate_ea),
                            proof_memory_oracle,
                            proof_scope_words,
                            proof_live_mask,
                            memory_ranges,
                            output_ranges,
                            output_byte_last_writer,
                        )
                        proof_cache[key] = bool(proven)
                        return bool(proven)

                suppressed_bits = seed_address_masks(
                    ev,
                    tid,
                    regs_obs,
                    regs_due,
                    read_records,
                    memory_ranges,
                    force_rf_addr_masking,
                    seed_observed=(
                        store_address_seed_observed
                    ),
                    seed_due=True,
                    trigger_note="store_address",
                    record_profile=internal_read_record_profile,
                    compact_compute=use_compact_storage_rows,
                    store_address_mask_proof=store_address_mask_proof,
                    diagnostics=addr_proof_diagnostics,
                )
                if suppressed_bits > 0:
                    addr_observed_seed_suppressed_bits += int(suppressed_bits)
                    addr_observed_seed_suppressed_events += 1
            if ev.pred is not None:
                store_pred_obs, store_pred_due, store_pred_trace = (
                    store_predicate_effect_masks(
                        ev,
                        get_trace_memory_oracle(),
                        (int(memory_forward_live_mask) | int(output_store_memory_mask))
                        & UINT64_MASK,
                        int(memory_forward_due_live_mask) & UINT64_MASK,
                        int(memory_forward_trace_live_mask) & UINT64_MASK,
                        executed_in_trace=True,
                    )
                )
                _record_predicate_read(
                    ev,
                    regs_obs,
                    regs_due,
                    regs_trace,
                    store_pred_obs,
                    store_pred_due,
                    store_pred_trace,
                    notes={
                        "predicate_gate": "store",
                        "predicate_effect": "suppress_executed_store",
                    },
                )
            continue

        # Special handling for load events: address propagation and memory forwarding.
        if ev.kind == "load":
            write_mask = None
            dst_live_obs = 0
            dst_live_due = 0
            dst_live_trace = 0
            load_live_obs = 0
            load_live_due = 0
            load_live_trace = 0
            load_live_smem_escape = 0
            load_size_bytes = access_size_bytes_for_event(ev)
            if ev.dst_reg is not None:
                write_mask = ev.dst_write_mask
                if write_mask is None:
                    write_mask = width_mask(ev.width_bits)
                write_mask &= UINT64_MASK
                dst_live_obs = regs_obs[ev.dst_reg] & write_mask
                dst_live_due = (
                    regs_due[ev.dst_reg] & write_mask
                ) if enable_memory_site_features else 0
                dst_live_trace = (
                    regs_trace[ev.dst_reg] & write_mask
                ) if enable_memory_site_features else 0
                if load_size_bytes > 0:
                    load_live_obs = dst_live_obs & bytes_to_mask(load_size_bytes, 0)
                    load_live_due = (
                        dst_live_due & bytes_to_mask(load_size_bytes, 0)
                    ) if enable_memory_site_features else 0
                    load_live_trace = (
                        dst_live_trace & bytes_to_mask(load_size_bytes, 0)
                    ) if enable_memory_site_features else 0
                    load_live_smem_escape = (
                        regs_smem_escape[ev.dst_reg] & bytes_to_mask(load_size_bytes, 0)
                    ) if enable_smem_features else 0

            if ev.pred is not None:
                pred_obs = 0
                pred_due = 0
                pred_trace = 0
                pred_obs_mask = int(dst_live_obs) & UINT64_MASK

                if ev.pred.val == 1:
                    old_value = ev.dst_old_val
                    new_value = ev.dst_val
                    pred_obs, pred_due, pred_trace = _predicate_value_change_masks(
                        old_value,
                        new_value,
                        pred_obs_mask,
                        int(dst_live_due) & UINT64_MASK,
                        int(dst_live_trace) & UINT64_MASK,
                    )
                else:
                    if ev.mem_addr is not None and is_out_of_range_ea(
                        ev,
                        int(ev.mem_addr),
                        memory_ranges,
                    ):
                        pred_due = 1
                    elif (
                        (
                            int(pred_obs_mask)
                            | int(dst_live_due)
                            | int(dst_live_trace)
                        )
                        != 0
                    ):
                        loaded_value = trace_memory_load_value_at_event(
                            ev,
                            get_trace_memory_oracle(),
                        )
                        pred_obs, value_pred_due, pred_trace = _predicate_value_change_masks(
                            ev.dst_old_val,
                            loaded_value,
                            pred_obs_mask,
                            int(dst_live_due) & UINT64_MASK,
                            int(dst_live_trace) & UINT64_MASK,
                        )
                        pred_due |= int(value_pred_due)

                _record_predicate_read(
                    ev,
                    regs_obs,
                    regs_due,
                    regs_trace,
                    pred_obs,
                    pred_due,
                    pred_trace,
                    notes={
                        "predicate_gate": "load",
                        "predicate_effect": (
                            "suppress_executed_load"
                            if ev.pred.val == 1
                            else "enable_skipped_load"
                        ),
                    },
                )

                # Predicated-off loads do not read an address, touch memory, or
                # write the destination in the golden execution.  A predicate
                # flip is accounted for above; other single-bit source faults
                # cannot make this skipped load execute.
                if ev.pred.val == 0:
                    continue

            if has_address_metadata(ev):
                load_address_seed_observed = should_seed_observed_for_load(
                    ev,
                    dst_live_obs,
                )
                load_address_memory_oracle = (
                    get_trace_memory_oracle()
                    if load_address_seed_observed and not force_rf_addr_masking
                    else None
                )
                suppressed_bits = seed_address_masks(
                    ev,
                    tid,
                    regs_obs,
                    regs_due,
                    read_records,
                    memory_ranges,
                    force_rf_addr_masking,
                    seed_observed=load_address_seed_observed,
                    seed_due=True,
                    trigger_note="load_address",
                    record_profile=internal_read_record_profile,
                    compact_compute=use_compact_storage_rows,
                    memory_oracle=load_address_memory_oracle,
                    load_value_observed_mask=int(load_live_obs) & UINT64_MASK,
                    load_value_due_mask=int(load_live_due) & UINT64_MASK,
                    load_value_trace_mask=int(load_live_trace) & UINT64_MASK,
                    diagnostics=addr_proof_diagnostics,
                )
                if suppressed_bits > 0:
                    addr_observed_seed_suppressed_bits += int(suppressed_bits)
                    addr_observed_seed_suppressed_events += 1

            scope_key = memory_scope_key(ev)
            if (
                scope_key is not None
                and ev.mem_addr is not None
                and load_size_bytes > 0
                and (
                    load_live_obs != 0
                    or load_live_due != 0
                    or load_live_trace != 0
                )
            ):
                scope_words = memory_live_words[scope_key]
                base_addr = int(ev.mem_addr)
                for byte_i in range(min(load_size_bytes, 8)):
                    live_byte_obs_mask = (load_live_obs >> (8 * byte_i)) & 0xFF
                    live_byte_due_mask = (load_live_due >> (8 * byte_i)) & 0xFF
                    live_byte_trace_mask = (load_live_trace >> (8 * byte_i)) & 0xFF
                    if (
                        live_byte_obs_mask == 0
                        and live_byte_due_mask == 0
                        and live_byte_trace_mask == 0
                    ):
                        continue
                    addr = base_addr + byte_i
                    word_addr = int(addr >> 3)
                    lane = int(addr & 0x7)
                    state = scope_words.get(word_addr)
                    if state is None:
                        state = _LiveWordState()
                        scope_words[word_addr] = state
                    shift = lane * 8
                    prev_obs = int((state.byte_obs_masks >> shift) & 0xFF)
                    prev_due = int((state.byte_due_masks >> shift) & 0xFF)
                    prev_trace = int((state.byte_trace_masks >> shift) & 0xFF)
                    merged_obs = (prev_obs | int(live_byte_obs_mask)) & 0xFF
                    merged_due = (prev_due | int(live_byte_due_mask)) & 0xFF
                    merged_trace = (prev_trace | int(live_byte_trace_mask)) & 0xFF
                    if merged_obs != prev_obs:
                        state.byte_obs_masks = (
                            state.byte_obs_masks & (~(0xFF << shift) & UINT64_MASK)
                        ) | (merged_obs << shift)
                    if merged_due != prev_due:
                        state.byte_due_masks = (
                            state.byte_due_masks & (~(0xFF << shift) & UINT64_MASK)
                        ) | (merged_due << shift)
                    if merged_trace != prev_trace:
                        state.byte_trace_masks = (
                            state.byte_trace_masks & (~(0xFF << shift) & UINT64_MASK)
                        ) | (merged_trace << shift)
                    if live_byte_obs_mask != 0:
                        state.byte_counts[lane] = int(state.byte_counts[lane]) + 1
                        origin_counts = state.byte_origins[lane]
                        if origin_counts is None:
                            origin_counts = {int(tid): 1}
                            state.byte_origins[lane] = origin_counts
                        else:
                            origin_counts[int(tid)] = (
                                int(origin_counts.get(int(tid), 0)) + 1
                            )
                        forwarded_load_bytes_total += 1

            cspace = canonical_space(ev.mem_space)
            has_mem_addr = ev.mem_addr is not None
            byte_count = max(0, min(load_size_bytes, 8))
            is_shared_load = cspace == "shared" and has_mem_addr
            is_cache_load = cspace in ("global", "local") and has_mem_addr
            if byte_count > 0 and (is_shared_load or is_cache_load):
                base_addr = int(ev.mem_addr) if has_mem_addr else 0
                cache_space = str(cspace) if is_cache_load else ""
                cache_load_is_zero_live = bool(
                    is_cache_load
                    and (
                        (int(load_live_obs) & UINT64_MASK)
                        | (int(load_live_due) & UINT64_MASK)
                        | (int(load_live_trace) & UINT64_MASK)
                    )
                    == 0
                )
                if cache_load_is_zero_live:
                    if emit_cache_sites:
                        _record_site_count_many("l1d_load", byte_count)
                        _record_site_count_many("l2_load", byte_count)
                    if collect_l1d_fault_sites:
                        _record_zero_effect_cache_site("l1d_load", width_bits=8, count=byte_count)
                    if collect_l2_fault_sites:
                        _record_zero_effect_cache_site("l2_load", width_bits=8, count=byte_count)
                else:
                    for byte_i in range(byte_count):
                        shift = 8 * byte_i
                        byte_trace_mask = int((load_live_trace >> shift) & 0xFF)
                        byte_obs_mask = int((load_live_obs >> shift) & 0xFF)
                        byte_due_mask = int((load_live_due >> shift) & 0xFF)
                        addr_i = int(base_addr + byte_i)
                        if is_shared_load:
                            _record_site_count("smem_lds")
                            if collect_smem_fault_sites:
                                smem_fault_sites.append(
                                    build_internal_site_record(
                                        site_family="smem",
                                        site_kind="smem_lds",
                                        mem_space="shared",
                                        thread_id=tid,
                                        sm_id=ev.sm_id,
                                        cta_id=ev.cta_id,
                                        addr=addr_i,
                                        cycle=ev.cycle,
                                        event_index=int(ev.index),
                                        width_bits=8,
                                        writer_event_index=int(ev.index),
                                        observed_mask_this_site=byte_obs_mask,
                                        due_mask_this_site=byte_due_mask,
                                        trace_expanding_mask_this_site=byte_trace_mask,
                                        shared_store_escape_mask_this_site=int(
                                            (load_live_smem_escape >> shift) & 0xFF
                                        ),
                                        compact=use_compact_storage_rows,
                                    )
                                )
                        if is_cache_load:
                            if emit_cache_sites:
                                _record_site_count("l1d_load")
                                _record_site_count("l2_load")
                            if collect_l1d_fault_sites:
                                _append_cache_load_site_record(
                                    l1d_fault_sites,
                                    site_family="l1d",
                                    site_kind="l1d_load",
                                    mem_space=cache_space,
                                    thread_id=tid,
                                    sm_id=ev.sm_id,
                                    cta_id=ev.cta_id,
                                    addr=addr_i,
                                    cycle=ev.cycle,
                                    event_index=int(ev.index),
                                    width_bits=8,
                                    writer_event_index=int(ev.index),
                                    observed_mask_this_site=byte_obs_mask,
                                    due_mask_this_site=byte_due_mask,
                                    trace_expanding_mask_this_site=byte_trace_mask,
                                )
                            if collect_l2_fault_sites:
                                _append_cache_load_site_record(
                                    l2_fault_sites,
                                    site_family="l2",
                                    site_kind="l2_load",
                                    mem_space=cache_space,
                                    thread_id=tid,
                                    sm_id=ev.sm_id,
                                    cta_id=ev.cta_id,
                                    addr=addr_i,
                                    cycle=ev.cycle,
                                    event_index=int(ev.index),
                                    width_bits=8,
                                    writer_event_index=int(ev.index),
                                    observed_mask_this_site=byte_obs_mask,
                                    due_mask_this_site=byte_due_mask,
                                    trace_expanding_mask_this_site=byte_trace_mask,
                                )

            # Load writes dst; kill the written version after transfer.
            if ev.dst_reg is not None:
                regs_obs[ev.dst_reg] &= (~write_mask) & UINT64_MASK
                regs_due[ev.dst_reg] &= (~write_mask) & UINT64_MASK
                regs_trace[ev.dst_reg] &= (~write_mask) & UINT64_MASK
                regs_smem_escape[ev.dst_reg] &= (~write_mask) & UINT64_MASK
            continue

        # Control-flow event reads are explicit equivalence classes.
        if ev.kind in ("branch", "loop_branch"):
            direct_control_sdc_masks, _base_taken = control_source_toggle_masks(ev)
            for src_i, src_reg in enumerate(ev.src_regs):
                src_w = coerce_width_bits(ev.src_width_bits[src_i], default=64)
                direct_sdc_mask = (
                    int(direct_control_sdc_masks.get(int(src_i), 0)) & width_mask(src_w)
                )
                trace_seed_mask = (
                    int(
                        trace_seed_by_read_key.get(
                            (int(tid), int(ev.index), "control_src", int(src_i)),
                            0,
                        )
                    )
                    & width_mask(src_w)
                )
                if direct_sdc_mask != 0:
                    merge_observed_state(
                        regs_obs,
                        src_reg,
                        int(direct_sdc_mask) & UINT64_MASK,
                    )
                if trace_seed_mask != 0:
                    regs_trace[src_reg] = (
                        regs_trace[src_reg] | trace_seed_mask
                    ) & UINT64_MASK
                append_read_record(
                    build_internal_read_record(
                        profile=internal_read_record_profile,
                        event_index=ev.index,
                        thread_id=tid,
                        cycle=ev.cycle,
                        sm_id=ev.sm_id,
                        cta_id=ev.cta_id,
                        warp_id=ev.warp_id,
                        pc=ev.pc,
                        opcode=ev.opcode,
                        read_kind="control_src",
                        src_index=src_i,
                        src_reg=src_reg,
                        src_reg_uid=(
                            ev.src_reg_uids[src_i]
                            if 0 <= src_i < len(ev.src_reg_uids)
                            else -1
                        ),
                        src_width_bits=src_w,
                        observed_mask_this_read=int(direct_sdc_mask) & UINT64_MASK,
                        due_mask_this_read=0,
                        trace_expanding_mask_this_read=int(trace_seed_mask)
                        & UINT64_MASK,
                        reg_observed_mask_at_read=int(regs_obs[src_reg]) & UINT64_MASK,
                        reg_due_mask_at_read=int(regs_due[src_reg]) & UINT64_MASK,
                        notes={
                            "control_event_kind": ev.kind,
                            "branch_taken": (
                                parse_branch_taken(ev)
                                if ev.recorded_branch_taken is not None
                                else False
                            ),
                        },
                        compact_compute=use_compact_storage_rows,
                    )
                )
            continue

        if ev.dst_reg is None:
            continue

        op = canonical_op(ev.opcode)
        write_mask = ev.dst_write_mask
        if write_mask is None:
            write_mask = width_mask(dst_width_bits(op, ev.width_bits))
        write_mask &= UINT64_MASK

        dst_live_obs = regs_obs[ev.dst_reg] & write_mask
        dst_live_due = regs_due[ev.dst_reg] & write_mask
        dst_live_trace = (
            regs_trace[ev.dst_reg] & write_mask
        ) if enable_memory_site_features else 0
        dst_live_smem_escape = (
            regs_smem_escape[ev.dst_reg] & write_mask
        ) if enable_smem_features else 0

        if (
            elide_zero_effect_read_records
            and (
                int(dst_live_obs)
                | int(dst_live_due)
                | int(dst_live_trace)
                | int(dst_live_smem_escape)
            )
            == 0
        ):
            # Exact whole-event zero-effect pruning.
            #
            # If the destination is not live in any SARA state and no
            # precomputed control-taint seed targets a source operand, this
            # dynamic instruction can only contribute all-masked source/predicate
            # read records.  Those records are already represented by
            # zero_effect_read_bits_elided in compute-profile output, and the
            # persistent RF exact path prunes zero-effect read cycles explicitly.
            # Skipping the whole event avoids per-source list/mask bookkeeping
            # without changing the public rates or exact component counts.
            zero_effect_event_bits = 1 if ev.pred is not None else 0
            has_trace_seed = False
            for src_i, _src_reg in enumerate(ev.src_regs):
                src_w = coerce_width_bits(
                    ev.src_width_bits[src_i] if src_i < len(ev.src_width_bits) else 64,
                    default=64,
                )
                zero_effect_event_bits += int(src_w)
                if (
                    int(
                        trace_seed_by_read_key.get(
                            (int(tid), int(ev.index), "src", int(src_i)),
                            0,
                        )
                    )
                    & width_mask(src_w)
                ) != 0:
                    has_trace_seed = True
                    break

            if not has_trace_seed:
                zero_effect_read_records_elided += int(len(ev.src_regs)) + (
                    1 if ev.pred is not None else 0
                )
                zero_effect_read_bits_elided += int(zero_effect_event_bits)
                continue

        src_masks_obs = [0] * len(ev.src_regs)
        src_masks_due = [0] * len(ev.src_regs)
        src_masks_trace = [0] * len(ev.src_regs)
        pred_mask_obs = 0
        pred_mask_due = 0
        pred_mask_trace = 0

        if (
            dst_live_obs != 0
            or dst_live_due != 0
            or dst_live_trace != 0
            or dst_live_smem_escape != 0
        ):
            if op not in SUPPORTED_OPS:
                raise NotImplementedError(
                    "Unsupported opcode with observed/due/trace destination bits: "
                    f"thread_id={tid}, pc={ev.pc}, event_index={ev.index}, "
                    f"opcode={ev.opcode}, canonical_op={op}"
                )

            if op == "IDENTITY":
                if len(ev.src_vals) not in (0, 1):
                    raise ValueError(
                        f"event[{ev.index}] opcode {ev.opcode} expects 0 or 1 srcs, got {len(ev.src_vals)}"
                    )
            else:
                need = expected_src_count(op)
                if len(ev.src_vals) != need:
                    raise ValueError(
                        f"event[{ev.index}] opcode {ev.opcode} expects {need} srcs, got {len(ev.src_vals)}"
                    )

            if ev.dst_val is None:
                try:
                    dst_val = eval_op(op, ev.src_vals, ev.width_bits)
                except KeyError as exc:
                    raise NotImplementedError(
                        "Unsupported opcode while computing dst_val: "
                        f"thread_id={tid}, pc={ev.pc}, event_index={ev.index}, "
                        f"opcode={ev.opcode}, canonical_op={op}"
                    ) from exc
            else:
                dst_val = ev.dst_val

            obs_mask_for_exact = int(dst_live_obs) & UINT64_MASK

            if ev.pred is not None:
                if ev.dst_old_val is None:
                    raise ValueError(
                        f"event[{ev.index}] predicated instruction missing dst_old_val"
                    )

                old_dst_val = ev.dst_old_val & UINT64_MASK

                if ev.pred.val == 1:
                    predicate_write_val = dst_val
                else:
                    try:
                        predicate_write_val = eval_op(op, ev.src_vals, ev.width_bits)
                    except KeyError as exc:
                        raise NotImplementedError(
                            "Unsupported opcode while computing predicated-off dst_val: "
                            f"thread_id={tid}, pc={ev.pc}, event_index={ev.index}, "
                            f"opcode={ev.opcode}, canonical_op={op}"
                        ) from exc

                pred_mask_obs, pred_mask_due, pred_mask_trace = _predicate_value_change_masks(
                    old_dst_val,
                    int(predicate_write_val) & UINT64_MASK,
                    obs_mask_for_exact,
                    int(dst_live_due) & UINT64_MASK,
                    int(dst_live_trace) & UINT64_MASK,
                )

                if pred_mask_obs != 0:
                    pred_mask_obs = 1
                    merge_observed_state(
                        regs_obs,
                        ev.pred.reg,
                        1,
                    )
                if pred_mask_due != 0:
                    pred_mask_due = 1
                    regs_due[ev.pred.reg] = (regs_due[ev.pred.reg] | 1) & UINT64_MASK
                if pred_mask_trace != 0:
                    pred_mask_trace = 1
                    regs_trace[ev.pred.reg] = (regs_trace[ev.pred.reg] | 1) & UINT64_MASK

                if ev.pred.val == 1:
                    if len(ev.src_vals) > 0:
                        (
                            src_masks_obs,
                            src_masks_due,
                            src_masks_trace,
                        ) = backward_influence_triplet(
                            op=op,
                            src_vals=ev.src_vals,
                            dst_val=dst_val,
                            obs_mask=obs_mask_for_exact,
                            due_mask=dst_live_due,
                            trace_mask=dst_live_trace,
                            width_bits_default=ev.width_bits,
                            src_widths=ev.src_width_bits,
                            thread_id=tid,
                            pc=ev.pc,
                            opcode=ev.opcode,
                            event_index=ev.index,
                        )
                    for src_i, src_reg in enumerate(ev.src_regs):
                        merge_observed_state(regs_obs, src_reg, int(src_masks_obs[src_i]))
                        regs_due[src_reg] = (regs_due[src_reg] | src_masks_due[src_i]) & UINT64_MASK
                        regs_trace[src_reg] = (
                            regs_trace[src_reg] | src_masks_trace[src_i]
                        ) & UINT64_MASK

                    regs_obs[ev.dst_reg] &= (~write_mask) & UINT64_MASK
                    regs_due[ev.dst_reg] &= (~write_mask) & UINT64_MASK
                    regs_trace[ev.dst_reg] &= (~write_mask) & UINT64_MASK
                    regs_smem_escape[ev.dst_reg] &= (~write_mask) & UINT64_MASK
                else:
                    # pred==0: no write to dst; old dst version remains live.
                    pass
            else:
                if len(ev.src_vals) > 0:
                    (
                        src_masks_obs,
                        src_masks_due,
                        src_masks_trace,
                    ) = backward_influence_triplet(
                        op=op,
                        src_vals=ev.src_vals,
                        dst_val=dst_val,
                        obs_mask=obs_mask_for_exact,
                        due_mask=dst_live_due,
                        trace_mask=dst_live_trace,
                        width_bits_default=ev.width_bits,
                        src_widths=ev.src_width_bits,
                        thread_id=tid,
                        pc=ev.pc,
                        opcode=ev.opcode,
                        event_index=ev.index,
                    )
                for src_i, src_reg in enumerate(ev.src_regs):
                    merge_observed_state(regs_obs, src_reg, int(src_masks_obs[src_i]))
                    regs_due[src_reg] = (regs_due[src_reg] | src_masks_due[src_i]) & UINT64_MASK
                    regs_trace[src_reg] = (
                        regs_trace[src_reg] | src_masks_trace[src_i]
                    ) & UINT64_MASK

                regs_obs[ev.dst_reg] &= (~write_mask) & UINT64_MASK
                regs_due[ev.dst_reg] &= (~write_mask) & UINT64_MASK
                regs_trace[ev.dst_reg] &= (~write_mask) & UINT64_MASK
                regs_smem_escape[ev.dst_reg] &= (~write_mask) & UINT64_MASK

        for src_i, src_reg in enumerate(ev.src_regs):
            src_w = max(
                0,
                min(
                    64,
                    int(ev.src_width_bits[src_i]) if src_i < len(ev.src_width_bits) else 64,
                ),
            )
            trace_seed_mask = (
                int(
                    trace_seed_by_read_key.get(
                        (int(tid), int(ev.index), "src", int(src_i)),
                        0,
                    )
                )
                & width_mask(src_w)
            )
            if trace_seed_mask != 0:
                src_masks_trace[src_i] = (
                    int(src_masks_trace[src_i]) | trace_seed_mask
                ) & UINT64_MASK
                regs_trace[src_reg] = (regs_trace[src_reg] | trace_seed_mask) & UINT64_MASK

        # Emit one record per source-register read at this dynamic instruction.
        for src_i, src_reg in enumerate(ev.src_regs):
            src_width_i = ev.src_width_bits[src_i]
            src_wmask_i = width_mask(src_width_i)
            src_obs_i = int(src_masks_obs[src_i]) & src_wmask_i
            src_due_i = int(src_masks_due[src_i]) & src_wmask_i
            src_trace_i = int(src_masks_trace[src_i]) & src_wmask_i
            if elide_zero_effect_read_records and (src_obs_i | src_due_i | src_trace_i) == 0:
                zero_effect_read_records_elided += 1
                zero_effect_read_bits_elided += int(coerce_width_bits(src_width_i, default=64))
                continue
            append_read_record(
                build_internal_read_record(
                    profile=internal_read_record_profile,
                    event_index=ev.index,
                    thread_id=tid,
                    cycle=ev.cycle,
                    sm_id=ev.sm_id,
                    cta_id=ev.cta_id,
                    warp_id=ev.warp_id,
                    pc=ev.pc,
                    opcode=ev.opcode,
                    read_kind="src",
                    src_index=src_i,
                    src_reg=src_reg,
                    src_reg_uid=(
                        ev.src_reg_uids[src_i]
                        if 0 <= src_i < len(ev.src_reg_uids)
                        else -1
                    ),
                    src_width_bits=ev.src_width_bits[src_i],
                    observed_mask_this_read=int(src_obs_i) & UINT64_MASK,
                    due_mask_this_read=int(src_due_i) & UINT64_MASK,
                    trace_expanding_mask_this_read=int(src_trace_i) & UINT64_MASK,
                    reg_observed_mask_at_read=int(regs_obs[src_reg]) & UINT64_MASK,
                    reg_due_mask_at_read=int(regs_due[src_reg]) & UINT64_MASK,
                    compact_compute=use_compact_storage_rows,
                )
            )

        if ev.pred is not None:
            if (
                elide_zero_effect_read_records
                and (int(pred_mask_obs) | int(pred_mask_due) | int(pred_mask_trace)) == 0
            ):
                zero_effect_read_records_elided += 1
                zero_effect_read_bits_elided += 1
            else:
                append_read_record(
                    build_internal_read_record(
                    profile=internal_read_record_profile,
                    event_index=ev.index,
                    thread_id=tid,
                    cycle=ev.cycle,
                    sm_id=ev.sm_id,
                    cta_id=ev.cta_id,
                    warp_id=ev.warp_id,
                    pc=ev.pc,
                    opcode=ev.opcode,
                    read_kind="pred",
                    src_index=0,
                    src_reg=ev.pred.reg,
                    src_reg_uid=(ev.pred.uid if ev.pred.uid is not None else -1),
                    src_width_bits=1,
                    observed_mask_this_read=int(pred_mask_obs) & UINT64_MASK,
                    due_mask_this_read=int(pred_mask_due) & UINT64_MASK,
                    trace_expanding_mask_this_read=int(pred_mask_trace) & UINT64_MASK,
                    reg_observed_mask_at_read=int(regs_obs[ev.pred.reg]) & UINT64_MASK,
                    reg_due_mask_at_read=int(regs_due[ev.pred.reg]) & UINT64_MASK,
                    notes={"pred_val": ev.pred.val},
                    compact_compute=use_compact_storage_rows,
                )
            )

    missed_input_bytes = 0
    for scope_words in memory_live_words.values():
        for state in scope_words.values():
            for pending in state.byte_counts:
                if pending > 0:
                    missed_input_bytes += int(pending)

    skip_sorted_output_for_compute = bool(
        lite_output
        and str(lite_output_profile).strip().lower() == "compute"
        and env_flag("REG_OBSERVED_SKIP_SORT_FOR_COMPUTE", True)
    )
    # Return records in forward execution order, stable by source index.
    if not skip_sorted_output_for_compute:
        read_records.sort(
            key=lambda r: (
                int(_read_row_field(r, "thread_id", -1)),
                int(_read_row_field(r, "event_index", -1)),
                str(_read_row_field(r, "read_kind", "")),
                int(_read_row_field(r, "src_index", -1)),
            )
        )

    final_obs_masks: Dict[str, Dict[str, Any]] = {}
    final_due_masks: Dict[str, Dict[str, Any]] = {}
    if not omit_top_level_diagnostics:
        for tid, regs in reg_observed_mask.items():
            final_obs_masks[str(tid)] = {
                reg: mask_to_output(mask, mask_format)
                for reg, mask in sorted(regs.items())
                if (mask & UINT64_MASK) != 0
            }

        for tid, regs in reg_due_mask.items():
            final_due_masks[str(tid)] = {
                reg: mask_to_output(mask, mask_format)
                for reg, mask in sorted(regs.items())
                if (mask & UINT64_MASK) != 0
            }

    control_taint_stats = dict(precomputed_control_taint_stats)

    # Analyzer-level fault classification is intentionally not computed here.
    # exact_sdc_compute.py recomputes final RF/SMEM/L1D/L2 counts over the real
    # sampling domains; scanning read_records here would only duplicate work in
    # the current exact-output experiment path.
    due_from_static_checks = 0

    output_spec_entry_count = int(len(output_ranges))
    output_spec_total_bytes = int(sum(int(out.size) for out in output_ranges))
    output_spec_ranges = [
        {
            "space": str(out.space),
            "base": f"0x{int(out.base):016x}",
            "bytes": int(out.size),
            "name": str(out.name) if out.name is not None else "",
        }
        for out in output_ranges
    ]

    analyzer_exact_meta = {
        "fault_component": str(fault_component),
        "addr_fault_policy": CANONICAL_ADDR_FAULT_POLICY,
        "addr_due_mode": CANONICAL_ADDR_DUE_MODE,
        "analyzer_mask_format": str(mask_format),
        "emit_cache_sites": bool(emit_cache_sites),
        "addr_observed_seed_suppressed_bits": int(addr_observed_seed_suppressed_bits),
        "addr_observed_seed_suppressed_events": int(addr_observed_seed_suppressed_events),
        "addr_same_value_masked_bits": int(
            addr_proof_diagnostics.get("addr_same_value_masked_bits", 0)
        ),
        "addr_same_value_masked_events": int(
            addr_proof_diagnostics.get("addr_same_value_masked_events", 0)
        ),
        "addr_alias_unknown_bits": int(
            addr_proof_diagnostics.get("addr_alias_unknown_bits", 0)
        ),
        "addr_alias_unknown_events": int(
            addr_proof_diagnostics.get("addr_alias_unknown_events", 0)
        ),
        "store_addr_proven_masked_bits": int(
            addr_proof_diagnostics.get("store_addr_proven_masked_bits", 0)
        ),
        "store_addr_proven_masked_events": int(
            addr_proof_diagnostics.get("store_addr_proven_masked_events", 0)
        ),
        "trace_memory_oracle_built": bool(trace_memory_oracle_built),
        "basic_block_transfer_enabled": bool(basic_block_transfer_enabled),
        "basic_block_transfer_raw_candidate_blocks": int(
            basic_block_transfer_raw_candidate_blocks
        ),
        "basic_block_transfer_raw_candidate_events": int(
            basic_block_transfer_raw_candidate_events
        ),
        "basic_block_transfer_candidate_blocks": int(
            basic_block_transfer_candidate_blocks
        ),
        "basic_block_transfer_candidate_events": int(
            basic_block_transfer_candidate_events
        ),
        "basic_block_transfer_blocks_applied": int(
            basic_block_transfer_blocks_applied
        ),
        "basic_block_transfer_events_applied": int(
            basic_block_transfer_events_applied
        ),
        "basic_block_transfer_skipped_member_events": int(
            basic_block_transfer_skipped_member_events
        ),
        "basic_block_transfer_cache_entries": int(len(basic_block_transfer_cache)),
        "basic_block_transfer_cache_hits": int(basic_block_transfer_cache_hits),
        "basic_block_transfer_cache_misses": int(basic_block_transfer_cache_misses),
        "output_oracle_type": (
            "signature-based" if output_spec_entry_count > 0 else "log-based"
        ),
        "output_oracle_has_output_spec": bool(output_spec_entry_count > 0),
        "output_oracle_spec_entry_count": int(output_spec_entry_count),
        "output_oracle_spec_total_bytes": int(output_spec_total_bytes),
        "output_oracle_spec_ranges": output_spec_ranges,
        "output_last_writer_store_count": int(output_last_writer_store_count),
        "output_total_store_count": int(output_total_store_count),
        "filtered_store_ratio": float(filtered_store_ratio),
        "compact_storage_read_rows": bool(use_compact_storage_rows),
        "zero_effect_read_events_elided": bool(elide_zero_effect_read_records),
        "zero_effect_read_event_count_elided": int(zero_effect_read_records_elided),
        "zero_effect_read_bits_elided": int(zero_effect_read_bits_elided),
        "zero_effect_cache_site_records_elided": int(
            sum(int(v) for v in zero_effect_cache_site_hist.values())
        ),
        "zero_effect_cache_site_bits_elided": int(zero_effect_cache_site_bits_elided),
        "zero_effect_cache_site_histogram": {
            str(k): int(v) for k, v in sorted(zero_effect_cache_site_hist.items())
        },
        "memory_live_byte_slice_cache_zero_load_sites_elided": int(
            zero_effect_cache_site_hist.get("l1d_load", 0)
            + zero_effect_cache_site_hist.get("l2_load", 0)
        ),
        "rf_register_uid_map": {
            str(reg): [int(uid) for uid in sorted(uids)]
            for reg, uids in sorted(rf_register_uid_map.items())
            if uids
        },
        "compact_storage_site_rows": bool(use_compact_storage_rows and compact_site_output),
        "compact_read_events_schema": (
            "compute_v1" if bool(use_compact_storage_rows) else ""
        ),
        "compact_smem_fault_sites_schema": (
            "smem_v1"
            if bool(use_compact_storage_rows and compact_site_output)
            else ""
        ),
        "compact_l1d_fault_sites_schema": (
            "cache_v1"
            if bool(use_compact_storage_rows and compact_site_output)
            else ""
        ),
        "compact_l2_fault_sites_schema": (
            "cache_v1"
            if bool(use_compact_storage_rows and compact_site_output)
            else ""
        ),
        "l2_fault_sites_alias": (
            "l1d_fault_sites" if bool(share_l1d_l2_site_records) else ""
        ),
        "smem_fault_site_count": int(smem_fault_site_count_total),
        "smem_rf_site_count": int(smem_rf_site_count_total),
        "smem_lds_site_count": int(smem_lds_site_count_total),
        "l2_fault_site_count": int(l2_fault_site_count_total),
        "l2_load_site_count": int(l2_load_site_count_total),
        "l2_store_site_count": int(l2_store_site_count_total),
        "l1d_fault_site_count": int(l1d_fault_site_count_total),
        "l1d_load_site_count": int(l1d_load_site_count_total),
        "l1d_store_site_count": int(l1d_store_site_count_total),
    }

    read_events_out: List[Dict[str, Any]]
    if omit_read_events_output:
        read_events_out = []
        read_events_for_trace_stats = read_records
    elif lite_output:
        include_extra_fields = False
        read_events_int = compact_lite_read_records_in_place(
            read_records,
            profile=lite_output_profile,
            
        )
        if aggregate_read_events:
            read_events_out = aggregate_lite_read_records(
                read_events_int,
                profile=lite_output_profile,
                mask_format=mask_format,
            )
        elif mask_format == "hex":
            read_events_out = [
                apply_mask_format_to_record(rec, "hex") for rec in read_events_int
            ]
        else:
            read_events_out = read_events_int
        read_events_for_trace_stats = read_events_out
    else:
        if mask_format == "int":
            read_events_out = read_records
        else:
            read_events_out = [
                apply_mask_format_to_record(rec, mask_format) for rec in read_records
            ]
        read_events_for_trace_stats = read_events_out

    if not skip_sorted_output_for_compute:
        smem_fault_sites.sort(
            key=lambda r: (
                int(r.get("sm_id", -1)) if r.get("sm_id") is not None else -1,
                int(r.get("cta_id", -1)) if r.get("cta_id") is not None else -1,
                int(r.get("addr", 0)),
                int(r.get("event_index", -1)),
                str(r.get("site_kind", "")),
                int(r.get("thread_id", -1)),
            )
        )
    if compact_site_output:
        if use_compact_storage_rows and mask_format == "int":
            smem_fault_sites_out = smem_fault_sites
        else:
            smem_fault_sites_out = compact_site_records_in_place(
                smem_fault_sites,
                site_family="smem",
                mask_format=mask_format,
                        )
    elif mask_format == "hex":
        smem_fault_sites_out = [
            apply_mask_format_to_smem_site(rec, "hex") for rec in smem_fault_sites
        ]
    else:
        smem_fault_sites_out = smem_fault_sites

    if not share_l1d_l2_site_records and not skip_sorted_output_for_compute:
        l2_fault_sites.sort(
            key=lambda r: (
                str(r.get("mem_space", "")),
                int(r.get("thread_id", -1)),
                int(r.get("addr", 0)),
                int(r.get("event_index", -1)),
                str(r.get("site_kind", "")),
            )
        )
    if share_l1d_l2_site_records:
        l2_fault_sites_out = []
    elif compact_site_output:
        if use_compact_storage_rows and mask_format == "int":
            l2_fault_sites_out = l2_fault_sites
        else:
            l2_fault_sites_out = compact_site_records_in_place(
                l2_fault_sites,
                site_family="l2",
                mask_format=mask_format,
                        )
    elif mask_format == "hex":
        l2_fault_sites_out = [
            apply_mask_format_to_l2_site(rec, "hex") for rec in l2_fault_sites
        ]
    else:
        l2_fault_sites_out = l2_fault_sites

    if not skip_sorted_output_for_compute:
        l1d_fault_sites.sort(
            key=lambda r: (
                str(r.get("mem_space", "")),
                int(r.get("sm_id", -1)) if r.get("sm_id") is not None else -1,
                int(r.get("thread_id", -1)),
                int(r.get("addr", 0)),
                int(r.get("event_index", -1)),
                str(r.get("site_kind", "")),
            )
        )
    if compact_site_output:
        if use_compact_storage_rows and mask_format == "int":
            l1d_fault_sites_out = l1d_fault_sites
        else:
            l1d_fault_sites_out = compact_site_records_in_place(
                l1d_fault_sites,
                site_family="l1d",
                mask_format=mask_format,
                        )
    elif mask_format == "hex":
        l1d_fault_sites_out = [
            apply_mask_format_to_l1d_site(rec, "hex") for rec in l1d_fault_sites
        ]
    else:
        l1d_fault_sites_out = l1d_fault_sites

    if omit_meta_diagnostic_samples:
        for key in META_DIAGNOSTIC_SAMPLE_FIELDS:
            analyzer_exact_meta.pop(key, None)

    out = {
        "read_events": read_events_out,
        "smem_fault_sites": smem_fault_sites_out,
        "l1d_fault_sites": l1d_fault_sites_out,
        "l2_fault_sites": l2_fault_sites_out,
        "exact_meta": analyzer_exact_meta,
    }

    if not omit_top_level_diagnostics:
        out.update(
            {
                "due_from_static_checks": int(due_from_static_checks),
                "control_taint_stats": control_taint_stats,
                "forwarded_load_bytes_total": int(forwarded_load_bytes_total),
                "forwarded_load_bytes_with_store": int(forwarded_load_bytes_with_store),
                "forwarded_cross_thread_count": int(forwarded_cross_thread_count),
                "stores_marked_observed_by_memory_flow": int(
                    stores_marked_observed_by_memory_flow
                ),
                "addr_observed_seed_suppressed_bits": int(
                    addr_observed_seed_suppressed_bits
                ),
                "addr_observed_seed_suppressed_events": int(
                    addr_observed_seed_suppressed_events
                ),
                "addr_same_value_masked_bits": int(
                    addr_proof_diagnostics.get("addr_same_value_masked_bits", 0)
                ),
                "addr_same_value_masked_events": int(
                    addr_proof_diagnostics.get("addr_same_value_masked_events", 0)
                ),
                "addr_alias_unknown_bits": int(
                    addr_proof_diagnostics.get("addr_alias_unknown_bits", 0)
                ),
                "addr_alias_unknown_events": int(
                    addr_proof_diagnostics.get("addr_alias_unknown_events", 0)
                ),
                "store_addr_proven_masked_bits": int(
                    addr_proof_diagnostics.get("store_addr_proven_masked_bits", 0)
                ),
                "store_addr_proven_masked_events": int(
                    addr_proof_diagnostics.get("store_addr_proven_masked_events", 0)
                ),
                "output_last_writer_store_count": int(output_last_writer_store_count),
                "output_total_store_count": int(output_total_store_count),
                "filtered_store_ratio": float(filtered_store_ratio),
                "missed_input_bytes": int(missed_input_bytes),
                "final_reg_observed_mask_per_thread": final_obs_masks,
                "final_reg_due_mask_per_thread": final_due_masks,
            }
        )

    return out


def load_trace(
    path: Path,
    *,
    include_metadata: bool = False,
) -> Any:
    raw = _json_load_path(path)
    output_ranges: List[OutputRangeSpec] = []
    ranges: List[MemoryRange] = []

    def resolve_ref(ref_raw: Any) -> Path:
        ref = Path(str(ref_raw))
        if ref.is_absolute():
            return ref
        return path.parent / ref

    def load_binary_manifest_payload(manifest: Dict[str, Any]) -> Tuple[Any, Path]:
        fmt = str(manifest.get("binary_format", "")).strip().lower()
        if fmt != "pickle_dict_v1":
            raise ValueError(
                f"{path}: unsupported analyzer input binary_format={fmt!r}"
            )
        ref_raw = manifest.get("binary_ref")
        if ref_raw is None:
            raise ValueError(f"{path}: binary analyzer input manifest missing binary_ref")
        ref_path = resolve_ref(ref_raw)
        with ref_path.open("rb") as fh:
            payload = pickle.load(fh)
        return payload, ref_path

    def load_columnar_manifest_payload(manifest: Dict[str, Any]) -> Tuple[Dict[str, Any], Path]:
        fmt = str(manifest.get("columnar_format", "")).strip().lower()
        if fmt != "pickle_events_columnar_v1":
            raise ValueError(
                f"{path}: unsupported analyzer input columnar_format={fmt!r}"
            )
        ref_raw = manifest.get("columnar_ref")
        if ref_raw is None:
            raise ValueError(f"{path}: columnar analyzer input manifest missing columnar_ref")
        ref_path = resolve_ref(ref_raw)
        with ref_path.open("rb") as fh:
            payload = pickle.load(fh)
        if not isinstance(payload, dict):
            raise ValueError(f"{ref_path}: columnar analyzer payload must be an object")
        return payload, ref_path

    def extract_events_and_ranges(raw_obj: Any, *, source_path: Path) -> Tuple[Any, List[MemoryRange]]:
        if isinstance(raw_obj, list):
            return raw_obj, []
        if not isinstance(raw_obj, dict):
            raise ValueError("Input JSON must be a list of events or an object")
        if "events" in raw_obj:
            events_obj = raw_obj["events"]
        elif "trace" in raw_obj:
            events_obj = raw_obj["trace"]
        else:
            raise ValueError(f"{source_path}: input object must contain 'events' or 'trace'")
        return events_obj, parse_memory_ranges(raw_obj.get("memory_ranges", []))

    def load_ranges_ref(ref_raw: Any) -> List[MemoryRange]:
        ref_path = resolve_ref(ref_raw)
        ranges_raw = _json_load_path(ref_path)
        if isinstance(ranges_raw, dict):
            if isinstance(ranges_raw.get("memory_ranges"), list):
                ranges_raw = ranges_raw.get("memory_ranges", [])
            elif isinstance(ranges_raw.get("ranges"), list):
                ranges_raw = ranges_raw.get("ranges", [])
        return parse_memory_ranges(ranges_raw)

    events: Optional[List[TraceEvent]] = None
    events_raw: Any = []
    if (
        isinstance(raw, dict)
        and raw.get("manifest_kind") == "exact_sdc_analyzer_input_binary_v1"
    ):
        if raw.get("columnar_ref") is not None:
            try:
                columnar_payload, _columnar_path = load_columnar_manifest_payload(raw)
                events = parse_columnar_events(columnar_payload)
                ranges = parse_memory_ranges(raw.get("memory_ranges", []))
                output_ranges = parse_output_ranges(raw.get("output_spec", []))
            except Exception as exc:
                if not env_flag("REG_OBSERVED_COLUMNAR_INPUT_FALLBACK", True):
                    raise
                print(
                    f"[reg_observed_analyzer] columnar analyzer input fallback: {exc}",
                    file=sys.stderr,
                )
                payload, payload_path = load_binary_manifest_payload(raw)
                events_raw, ranges = extract_events_and_ranges(
                    payload,
                    source_path=payload_path,
                )
                if isinstance(payload, dict):
                    output_ranges = parse_output_ranges(payload.get("output_spec", []))
        else:
            payload, payload_path = load_binary_manifest_payload(raw)
            events_raw, ranges = extract_events_and_ranges(
                payload,
                source_path=payload_path,
            )
            if isinstance(payload, dict):
                output_ranges = parse_output_ranges(payload.get("output_spec", []))
    elif isinstance(raw, dict) and (
        raw.get("manifest_kind") == "exact_sdc_analyzer_input_ref"
        or raw.get("trace_template_ref") is not None
        or raw.get("events_ref") is not None
    ):
        ref_raw_value = raw.get("trace_template_ref", raw.get("events_ref"))
        if ref_raw_value is None:
            raise ValueError("analyzer input manifest missing trace_template_ref")
        ref_path = resolve_ref(ref_raw_value)
        ref_obj = _json_load_path(ref_path)
        events_raw, ranges = extract_events_and_ranges(
            ref_obj,
            source_path=ref_path,
        )
        if raw.get("memory_ranges_ref") is not None:
            ranges.extend(load_ranges_ref(raw.get("memory_ranges_ref")))
        ranges.extend(parse_memory_ranges(raw.get("memory_ranges", [])))
        output_ranges = parse_output_ranges(raw.get("output_spec", []))
    else:
        events_raw, ranges = extract_events_and_ranges(
            raw,
            source_path=path,
        )
        if isinstance(raw, dict):
            output_ranges = parse_output_ranges(raw.get("output_spec", []))

    if events is None:
        if not isinstance(events_raw, list):
            raise ValueError("events must be a list")
        events = [parse_event(ev, i) for i, ev in enumerate(events_raw)]
    events_raw = []
    raw = None
    derived_ranges = derive_memory_ranges_from_events(events)
    ranges.extend(derived_ranges)
    if include_metadata:
        return events, ranges, output_ranges
    return events, ranges


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Backward-pass analyzer for register observed/due masks with exact "
            "address-corruption DUE classification"
        )
    )
    parser.add_argument("trace", type=Path, help="JSON trace file")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("read_observed_masks.json"),
        help="Output JSON file path",
    )
    parser.add_argument(
        "--lite-output",
        action="store_true",
        help=(
            "Write compact read_events records that keep only fields required by "
            "exact_sdc_compute."
        ),
    )
    parser.add_argument(
        "--lite-output-profile",
        choices=LITE_OUTPUT_PROFILES,
        default=os.environ.get("REG_OBSERVED_LITE_OUTPUT_PROFILE", "compat"),
        help=(
            "Lite output schema profile: 'compat' keeps debug/reason fields, "
            "'compute' keeps only exact_sdc_compute-critical fields."
        ),
    )
    parser.set_defaults(
        aggregate_read_events=env_flag("REG_OBSERVED_AGGREGATE_READ_EVENTS", False)
    )
    parser.add_argument(
        "--aggregate-read-events",
        dest="aggregate_read_events",
        action="store_true",
        help=(
            "In --lite-output mode, merge records by (thread_id,cycle,src_reg_uid/src_reg) "
            "and OR masks to shrink read_events size (may change per-read rate semantics)."
        ),
    )
    parser.add_argument(
        "--no-aggregate-read-events",
        dest="aggregate_read_events",
        action="store_false",
        help="Disable lite read_events aggregation.",
    )
    parser.add_argument(
        "--mask-format",
        choices=MASK_FORMATS,
        default=os.environ.get("REG_OBSERVED_MASK_FORMAT", "int"),
        help=(
            "Mask representation in output JSON: 'int' (fast, default) or "
            "'hex' (legacy-compatible string masks)."
        ),
    )
    parser.add_argument(
        "--assume-sorted-events",
        action="store_true",
        help=(
            "Skip event order verification and sorting; use when trace events "
            "are guaranteed already ordered by (cycle/index, index)."
        ),
    )
    parser.add_argument(
        "--fault-component",
        choices=FAULT_COMPONENTS,
        default=os.environ.get("FAULT_COMPONENT", "rf").strip().lower(),
        help=(
            "Fault component mode for exact analysis output: "
            "'rf' keeps RF-focused behavior, "
            "'smem_rf'/'smem_lds' emit shared-memory fault sites, "
            "'l1d' and 'l2' emit cache-oriented global/local memory fault sites."
        ),
    )
    parser.set_defaults(
        emit_cache_sites=env_flag("REG_OBSERVED_EMIT_CACHE_SITES", True)
    )
    parser.add_argument(
        "--emit-cache-sites",
        dest="emit_cache_sites",
        action="store_true",
        help=(
            "Emit l1d_fault_sites/l2_fault_sites for global/local memory accesses "
            "independent of fault-component mode (default: on)."
        ),
    )
    parser.add_argument(
        "--no-emit-cache-sites",
        dest="emit_cache_sites",
        action="store_false",
        help="Disable emission of cache fault-site lists.",
    )
    parser.add_argument(
        "--profile-out",
        type=Path,
        default=None,
        help="Optional cProfile text report output path.",
    )
    parser.add_argument(
        "--meta-out",
        type=Path,
        default=None,
        help="Optional exact_meta sidecar JSON output path.",
    )
    parser.add_argument(
        "--output-oracle-policy",
        type=Path,
        default=None,
        help=(
            "Optional JSON policy that records the explicit application output "
            "oracle used by the benchmark. The policy is part of canonical SARA "
            "semantics and is not a fitted tolerance override."
        ),
    )
    parser.add_argument(
        "--output-oracle-policy-json",
        type=str,
        default="{}",
        help=argparse.SUPPRESS,
    )
    parser.set_defaults(
        binary_output=env_flag("REG_OBSERVED_BINARY_OUTPUT", False),
    )
    parser.add_argument(
        "--binary-output",
        dest="binary_output",
        action="store_true",
        help=(
            "Write analyzer output as a compact JSON manifest plus binary sidecar. "
            "This avoids the largest analyzer_output JSON materialization for "
            "exact_sdc_compute while preserving the legacy JSON CLI contract."
        ),
    )
    parser.add_argument(
        "--no-binary-output",
        dest="binary_output",
        action="store_false",
        help="Write analyzer output as legacy JSON.",
    )
    args = parser.parse_args()

    output_oracle_policy: Dict[str, Any] = {}
    if args.output_oracle_policy is not None:
        try:
            loaded_policy = json.loads(args.output_oracle_policy.read_text())
        except Exception as exc:
            raise ValueError(
                f"failed to read output oracle policy {args.output_oracle_policy}: {exc}"
            )
        if not isinstance(loaded_policy, dict):
            raise ValueError(
                f"output oracle policy must be a JSON object: {args.output_oracle_policy}"
            )
        output_oracle_policy = normalize_output_oracle_policy(loaded_policy)
    elif str(args.output_oracle_policy_json or "").strip() not in ("", "{}"):
        try:
            loaded_policy = json.loads(str(args.output_oracle_policy_json))
        except Exception as exc:
            raise ValueError(f"failed to parse --output-oracle-policy-json: {exc}")
        if not isinstance(loaded_policy, dict):
            raise ValueError("--output-oracle-policy-json must decode to a JSON object")
        output_oracle_policy = normalize_output_oracle_policy(loaded_policy)

    events, ranges, output_ranges = load_trace(
        args.trace,
        include_metadata=True,
    )
    prof: Optional[cProfile.Profile] = None
    if args.profile_out is not None:
        prof = cProfile.Profile()
        prof.enable()
    try:
        result = analyze(
            events,
            ranges,
            output_ranges=output_ranges,
            lite_output=bool(args.lite_output),
            lite_output_profile=str(args.lite_output_profile),
            aggregate_read_events=bool(args.aggregate_read_events),
            mask_format=str(args.mask_format),
            assume_sorted_events=bool(args.assume_sorted_events),
            fault_component=str(args.fault_component),
            emit_cache_sites=bool(args.emit_cache_sites),
            output_oracle_policy=output_oracle_policy,
        )
    finally:
        if prof is not None:
            prof.disable()
            args.profile_out.parent.mkdir(parents=True, exist_ok=True)
            stream = io.StringIO()
            stats = pstats.Stats(prof, stream=stream).sort_stats("cumulative")
            stats.print_stats(200)
            args.profile_out.write_text(stream.getvalue(), encoding="utf-8")

    if args.meta_out is not None:
        args.meta_out.parent.mkdir(parents=True, exist_ok=True)
        _json_dump_path(
            args.meta_out,
            result.get("exact_meta", {}) if isinstance(result, dict) else {},
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    if bool(args.binary_output):
        _write_binary_output_manifest(args.output, result)
    else:
        _json_dump_path(args.output, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
