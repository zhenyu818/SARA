#!/usr/bin/env python3
"""Exact SDC/DUE/masked computation from analyzer output + regfile trace."""

import argparse
import bisect
import concurrent.futures
import gzip
import hashlib
import json
import math
import multiprocessing as mp
import os
import pickle
import struct
import re
import sys
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

import exact_cpp_backend as exact_cpp_backend

try:
    import orjson as _orjson  # type: ignore
except Exception:
    _orjson = None

try:
    import zstandard as _zstd  # type: ignore
except Exception:
    _zstd = None

try:
    from dataclasses import dataclass
except ImportError:
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

MAGIC_RFTR = 0x52544652
WRITE_BIT = 0x80000000
HEADER_STRUCT = struct.Struct("<IHHII")
EVENT_STRUCT = struct.Struct("<QII")
ADDR_STATIC_DUE_MASK_FIELD = "addr_static_due_mask_this_read"
MASK_FIELDS = (
    "observed_mask_this_read",
    "due_mask_this_read",
    "trace_expanding_mask_this_read",
)
DETAIL_MAP_FIELDS = ("notes",)
DETAIL_SCALAR_FIELDS = ("pc", "opcode", "read_kind")
MASK64 = (1 << 64) - 1
ANALYZER_OUTPUT_ALIAS_FILENAMES = frozenset(
    (
        "analyzer_output_rf.json",
        "analyzer_output_smem_rf.json",
        "analyzer_output_l1d.json",
        "analyzer_output_l2.json",
    )
)
ADDR_BITS_MODES = ("auto", "all", "explicit")
STORAGE_GROUP_MODES = ("legacy", "grouped")
FAULT_COMPONENTS = ("rf", "smem_rf", "smem_lds", "l1d", "l2", "gmem")
SMEM_SITE_MASK_FIELDS = (
    "observed_mask_this_site",
    "due_mask_this_site",
    "trace_expanding_mask_this_site",
)
_CPP_MASK_CLASSIFIER_ENABLED = False
_CPP_MASK_CLASSIFIER_FAILED = False
_CPP_THREAD_CYCLE_MODE = str(
    os.environ.get("EXACT_SDC_USE_CPP_THREAD_CYCLE", "0")
).strip().lower()
_CPP_THREAD_CYCLE_FORCE = _CPP_THREAD_CYCLE_MODE in ("force", "forced")
_CPP_THREAD_CYCLE_ENABLED = _CPP_THREAD_CYCLE_FORCE or (
    _CPP_THREAD_CYCLE_MODE not in ("", "0", "false", "no", "off")
)
_CPP_THREAD_CYCLE_FAILED = False
_CPP_THREAD_CYCLE_AUTO_MAX_RECORDS = 256
_CPP_THREAD_CYCLE_AUTO_MAX_TOTAL_ACTIVE_THREADS = 4096
_CPP_RF_INTERVAL_ACCUM_ENABLED = (
    os.environ.get("EXACT_SDC_USE_CPP_RF_INTERVAL_ACCUM", "1") != "0"
)
_CPP_RF_INTERVAL_ACCUM_FAILED = False
_CPP_RF_INTERVAL_ACCUM_BATCH_SIZE = int(
    os.environ.get("EXACT_SDC_RF_INTERVAL_ACCUM_BATCH_SIZE", "65536")
)
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
    "shared_store_escape_mask_this_site",
)
COMPACT_SMEM_SITE_KEYS_INDEX = {
    key: idx for idx, key in enumerate(COMPACT_SMEM_SITE_KEYS)
}
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
COMPACT_CACHE_SITE_KEYS_INDEX = {
    key: idx for idx, key in enumerate(COMPACT_CACHE_SITE_KEYS)
}
EXACT_SEMANTICS_PROFILE = "canonical_proof_exact_v3"
CANONICAL_CONSUMER_COMPARE = "gt"
CANONICAL_RF_FAULT_MODEL = "persistent"
CANONICAL_TRACE_EXPANDING_POLICY = "masked"
CANONICAL_TRACE_EXPANDING_RESOLUTION_MODE = "legacy"
CANONICAL_TRACE_UNCOVERED_MODE = "legacy_unknown"
CANONICAL_MISSING_ACTIVE_THREADS_POLICY = "empty"
CANONICAL_TRACE_DIVERGENCE_POLICY = "unknown"
CANONICAL_ADDR_FAULT_POLICY = "bounds_due"
CANONICAL_ADDR_DUE_MODE = "range"
CANONICAL_ADDR_BITS = "auto"
CANONICAL_CACHE_TAG_CLASS_POLICY = "unknown"
CANONICAL_METADATA_FAULT_POLICY = "unknown"
CANONICAL_SMEM_DOMAIN_POLICY = "sampling_space"
CANONICAL_RF_DOMAIN_POLICY = "sampling_space"
CANONICAL_SMEM_ERROR_PROPAGATION_MODEL = "byte_defuse"
CANONICAL_SMEM_ADDR_EXCEPTION_POLICY = "unknown"
CANONICAL_RF_ADDR_REG_POLICY = "addr_regs_only"
SMEM_MEMORY_BLOCK_BYTES = 16 * 1024
CANONICAL_USE_SAMPLING_SPACE_DOMAIN = 1
REMOVED_SEMANTIC_ENV_VARS = (
    "STRICT_EXACT",
    "STRICT_REPLACEMENT",
    "STRICT_REPLACEMENT_HARD",
    "UNKNOWN_POLICY",
    "TRACE_EXPANDING_POLICY",
    "TRACE_UNCOVERED_MODE",
    "TRACE_DIVERGENCE_POLICY",
    "ADDR_FAULT_POLICY",
    "ADDR_DUE_MODE",
    "ADDR_BITS",
    "CACHE_TAG_CLASS_POLICY",
    "METADATA_FAULT_POLICY",
    "SMEM_DOMAIN_POLICY",
    "RF_DOMAIN_POLICY",
    "SMEM_ERROR_PROPAGATION_MODEL",
    "SMEM_ADDR_EXCEPTION_POLICY",
    "RF_ADDR_REG_POLICY",
    "USE_SAMPLING_SPACE_DOMAIN",
    "USE_SAMPLING_SPACE_DOMAIN_RF",
    "USE_SAMPLING_SPACE_DOMAIN_SMEM",
    "CONSUMER_COMPARE",
    "SAME_CYCLE_EFFECT_PROB",
    "RF_FAULT_MODEL",
    "MISSING_ACTIVE_THREADS_POLICY",
)
REMOVED_SEMANTIC_OPTIONS: Tuple[str, ...] = ()
L1D_TAG_ARRAY_BITS_DEFAULT = 57
L1D_LINE_SIZE_BYTES_DEFAULT = 128
L2_TAG_ARRAY_BITS_DEFAULT = 57
L2_LINE_SIZE_BYTES_DEFAULT = 128
FastMaskRecord = Tuple[int, int, int, int]
RF_READ_KIND_UNKNOWN = 0
RF_READ_KIND_ADDR = 1
RF_READ_KIND_SRC = 2
RF_READ_KIND_STORE_DATA = 3
RF_READ_KIND_PRED = 4
RF_READ_KIND_CONTROL_SRC = 5
RFConsumerRecord = Tuple[int, int, int, int, int, int, int, int]
RF_SDC_PROOF_SOURCE_KEYS = (
    "rf_arithmetic_transfer",
    "rf_bitwise_shift_transfer",
    "rf_move_convert_transfer",
    "rf_predicate_control_transfer",
    "rf_store_commit_transfer",
    "rf_multi_mechanism_transfer",
    "rf_other_exact_transfer",
)


def _ptx_opcode_base(opcode: Any) -> str:
    raw = str(opcode or "").strip().lower()
    if not raw:
        return ""
    # The trace normally stores only the opcode, but tolerate predicated PTX
    # text such as "@%p1 add.s32" if it appears in older traces.
    if raw.startswith("@"):
        parts = raw.split(None, 1)
        raw = parts[1] if len(parts) == 2 else ""
    raw = raw.rstrip(";")
    token = raw.split(None, 1)[0] if raw else ""
    return token.split(".", 1)[0]


def _rf_sdc_proof_source_from_event(
    event: Optional[Mapping[str, Any]],
    read_kind: int,
) -> str:
    """Classify an RF SDC proof by its semantic propagation mechanism.

    This taxonomy is for attribution only.  It does not alter Masked/SDC/DUE
    classification and does not introduce an application- or architecture-tuned
    outcome parameter.  The class is derived from the read-consumer kind and the
    recorded PTX opcode that supplied the exact backward-transfer proof.
    """

    if int(read_kind) in (RF_READ_KIND_PRED, RF_READ_KIND_CONTROL_SRC):
        return "rf_predicate_control_transfer"
    if int(read_kind) == RF_READ_KIND_STORE_DATA:
        return "rf_store_commit_transfer"

    raw = event if isinstance(event, Mapping) else {}
    opcode = str(raw.get("opcode", "")).strip().lower()
    base = _ptx_opcode_base(opcode)
    kind = str(raw.get("kind", "")).strip().lower()
    if kind == "store" or base == "st":
        return "rf_store_commit_transfer"
    if kind == "branch" or base in {"bra", "call", "ret", "exit"}:
        return "rf_predicate_control_transfer"
    if ".pred" in opcode or base in {"set", "setp", "selp", "slct", "testp"}:
        return "rf_predicate_control_transfer"
    if base in {"mov", "cvt", "cvta"}:
        return "rf_move_convert_transfer"
    if base in {
        "and",
        "or",
        "xor",
        "not",
        "shl",
        "shr",
        "bfe",
        "bfi",
        "brev",
        "popc",
        "clz",
        "lop3",
        "prmt",
    }:
        return "rf_bitwise_shift_transfer"
    if base in {
        "add",
        "sub",
        "mul",
        "mad",
        "fma",
        "div",
        "rem",
        "abs",
        "neg",
        "min",
        "max",
        "sqrt",
        "rsqrt",
        "rcp",
        "ex2",
        "lg2",
        "sin",
        "cos",
    }:
        return "rf_arithmetic_transfer"
    return "rf_other_exact_transfer"


def _disjoint_source_masks(
    source_masks: Mapping[str, int],
    *,
    multi_key: str = "rf_multi_mechanism_transfer",
    valid_keys: Sequence[str] = RF_SDC_PROOF_SOURCE_KEYS,
) -> Dict[str, int]:
    """Return non-overlapping masks and move cross-source overlap to multi_key."""

    valid = set(str(k) for k in valid_keys)
    raw: Dict[str, int] = {}
    for key, mask in source_masks.items():
        key_s = str(key)
        if key_s not in valid:
            key_s = "rf_other_exact_transfer"
        mask_i = int(mask) & MASK64
        if mask_i == 0:
            continue
        raw[key_s] = (int(raw.get(key_s, 0)) | mask_i) & MASK64
    seen = 0
    multi = int(raw.get(multi_key, 0)) & MASK64
    for key in valid_keys:
        if key == multi_key:
            continue
        mask_i = int(raw.get(key, 0)) & MASK64
        multi |= seen & mask_i
        seen |= mask_i
    out: Dict[str, int] = {}
    if multi:
        out[multi_key] = int(multi) & MASK64
    for key in valid_keys:
        if key == multi_key:
            continue
        mask_i = int(raw.get(key, 0)) & (~multi) & MASK64
        if mask_i:
            out[key] = int(mask_i)
    return out


def _rf_read_kind_code(raw: Any) -> int:
    kind = str(raw or "").strip().lower()
    if kind == "addr":
        return RF_READ_KIND_ADDR
    if kind == "src":
        return RF_READ_KIND_SRC
    if kind == "store_data":
        return RF_READ_KIND_STORE_DATA
    if kind == "pred":
        return RF_READ_KIND_PRED
    if kind == "control_src":
        return RF_READ_KIND_CONTROL_SRC
    return RF_READ_KIND_UNKNOWN


def _rf_consumer_record_fast_mask(rec: RFConsumerRecord) -> FastMaskRecord:
    return (int(rec[0]), int(rec[1]), int(rec[2]), int(rec[3]))


def _rf_consumer_record_addr_static_due_mask(rec: RFConsumerRecord) -> int:
    return int(rec[7]) & MASK64


def _rf_consumer_record_kind(rec: RFConsumerRecord) -> int:
    return int(rec[6])


def _rf_consumer_record_event_key(rec: RFConsumerRecord) -> Tuple[int, int, int]:
    return int(rec[4]), int(rec[5]), int(rec[6])


def _rf_consumer_record_event_index(rec: RFConsumerRecord) -> int:
    return int(rec[4])


def _rf_consumer_without_addr_observed(rec: RFConsumerRecord) -> FastMaskRecord:
    return (int(rec[0]), 0, 0, int(rec[3]))



def _json_load_path(path: Path) -> Any:
    return _json_load_path_cached(_path_cache_key(path))


def _path_cache_key(path: Any) -> str:
    try:
        return str(Path(path).resolve())
    except Exception:
        return str(path)


@lru_cache(maxsize=None)
def _file_head_signature(path_key: str, sample_bytes: int = 1 << 20) -> Tuple[int, str]:
    path = Path(path_key)
    stat = path.stat()
    h = hashlib.sha256()
    with path.open("rb") as handle:
        h.update(handle.read(int(sample_bytes)))
    return int(stat.st_size), str(h.hexdigest())


def _canonicalize_analyzer_output_path(path: Path) -> Path:
    try:
        resolved = Path(path).resolve()
    except Exception:
        resolved = Path(path)
    if resolved.name not in ANALYZER_OUTPUT_ALIAS_FILENAMES:
        return resolved
    canonical = resolved.with_name("analyzer_output.json")
    if not canonical.is_file():
        return resolved
    try:
        if _file_head_signature(_path_cache_key(resolved)) == _file_head_signature(
            _path_cache_key(canonical)
        ):
            return canonical
    except Exception:
        return resolved
    return resolved


@lru_cache(maxsize=None)
def _json_load_path_cached(path_key: str) -> Any:
    path = Path(path_key)
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


def _compact_row_get(
    rec: Any,
    *,
    index_map: Mapping[str, int],
    key: str,
    default: Any = None,
) -> Any:
    if not isinstance(rec, (list, tuple)):
        return default
    idx = index_map.get(str(key))
    if idx is None or idx < 0 or idx >= len(rec):
        return default
    return rec[idx]


def _read_event_row_field(rec: Any, key: str, default: Any = None) -> Any:
    if isinstance(rec, dict):
        return rec.get(key, default)
    if _is_compact_read_event_row(rec):
        return _compact_row_get(
            rec,
            index_map=COMPACT_READ_EVENT_KEYS_COMPUTE_INDEX,
            key=key,
            default=default,
        )
    return default


def _smem_site_row_field(rec: Any, key: str, default: Any = None) -> Any:
    if isinstance(rec, dict):
        return rec.get(key, default)
    if _is_compact_smem_site_row(rec):
        return _compact_row_get(
            rec,
            index_map=COMPACT_SMEM_SITE_KEYS_INDEX,
            key=key,
            default=default,
        )
    return default


def _cache_site_row_field(rec: Any, key: str, default: Any = None) -> Any:
    if isinstance(rec, dict):
        return rec.get(key, default)
    if _is_compact_cache_site_row(rec):
        return _compact_row_get(
            rec,
            index_map=COMPACT_CACHE_SITE_KEYS_INDEX,
            key=key,
            default=default,
        )
    return default


def _cache_site_record_with_kind(rec: Any, site_kind: str) -> Any:
    if isinstance(rec, dict):
        out = dict(rec)
        out["site_kind"] = str(site_kind)
        return out
    if _is_compact_cache_site_row(rec):
        out = list(rec)
        out[COMPACT_CACHE_SITE_KEYS_INDEX["site_kind"]] = str(site_kind)
        return tuple(out) if isinstance(rec, tuple) else out
    return rec


def _l1d_cache_site_record_as_l2(rec: Any) -> Any:
    site_kind = str(_cache_site_row_field(rec, "site_kind", ""))
    if site_kind == "l1d_load":
        return _cache_site_record_with_kind(rec, "l2_load")
    if site_kind == "l1d_store":
        return _cache_site_record_with_kind(rec, "l2_store")
    return rec


def _is_compact_read_event_row(rec: Any) -> bool:
    return isinstance(rec, (list, tuple)) and len(rec) == len(
        COMPACT_READ_EVENT_KEYS_COMPUTE
    )


def _is_compact_smem_site_row(rec: Any) -> bool:
    return isinstance(rec, (list, tuple)) and len(rec) == len(
        COMPACT_SMEM_SITE_KEYS
    )


def _is_compact_cache_site_row(rec: Any) -> bool:
    return isinstance(rec, (list, tuple)) and len(rec) == len(
        COMPACT_CACHE_SITE_KEYS
    )


def _expand_compact_read_event_row(rec: Any) -> Dict[str, Any]:
    return {
        key: _compact_row_get(
            rec,
            index_map=COMPACT_READ_EVENT_KEYS_COMPUTE_INDEX,
            key=key,
        )
        for key in COMPACT_READ_EVENT_KEYS_COMPUTE
    }


def _expand_compact_smem_site_row(rec: Any) -> Dict[str, Any]:
    return {
        key: _compact_row_get(
            rec,
            index_map=COMPACT_SMEM_SITE_KEYS_INDEX,
            key=key,
        )
        for key in COMPACT_SMEM_SITE_KEYS
    }


def _expand_compact_cache_site_row(rec: Any) -> Dict[str, Any]:
    return {
        key: _compact_row_get(
            rec,
            index_map=COMPACT_CACHE_SITE_KEYS_INDEX,
            key=key,
        )
        for key in COMPACT_CACHE_SITE_KEYS
    }


def _expand_compact_analyzer_rows_for_compute(analyzer_output: Any) -> Any:
    if not isinstance(analyzer_output, dict):
        return analyzer_output
    out = dict(analyzer_output)
    for key in ("read_events", "smem_fault_sites", "l1d_fault_sites", "l2_fault_sites"):
        raw_rows = out.get(key)
        if not isinstance(raw_rows, list) or not raw_rows:
            continue
        first = raw_rows[0]
        # Preserve compact rows for compute-side direct access. They are cheaper
        # to keep in tuple form than to eagerly inflate into per-row dicts.
        if key == "smem_fault_sites" and _is_compact_smem_site_row(first):
            out[key] = [_expand_compact_smem_site_row(rec) if _is_compact_smem_site_row(rec) else rec for rec in raw_rows]
    return out


def _load_analyzer_output_for_compute(
    path: Path,
    *,
    normalize_trace_coverage: bool = False,
) -> Dict[str, Any]:
    canonical_path = _canonicalize_analyzer_output_path(Path(path))
    analyzer = _load_analyzer_output_for_compute_cached(
        _path_cache_key(canonical_path),
        bool(normalize_trace_coverage),
    )
    if not isinstance(analyzer, dict):
        raise ValueError(f"{canonical_path}: analyzer output must be a JSON object")
    return analyzer


def _analyzer_output_cache_key(path: Path) -> str:
    return _path_cache_key(_canonicalize_analyzer_output_path(Path(path)))


def _analyzer_meta_sidecar_candidates(path: Path) -> List[Path]:
    parent = Path(path).parent
    name = Path(path).name
    candidates: List[Path] = []
    if name.startswith("analyzer_output_") and name.endswith(".json"):
        candidates.append(parent / ("analyzer_meta_" + name[len("analyzer_output_"):]))
    candidates.append(parent / "analyzer_meta.json")
    candidates.append(parent / (Path(path).stem + ".meta.json"))
    seen: Set[str] = set()
    unique: List[Path] = []
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


@lru_cache(maxsize=None)
def _load_analyzer_meta_sidecar_cached(path_key: str) -> Dict[str, Any]:
    analyzer_path = Path(path_key)
    for candidate in _analyzer_meta_sidecar_candidates(analyzer_path):
        if not candidate.is_file():
            continue
        try:
            meta = _json_load_path(candidate)
        except Exception:
            continue
        if isinstance(meta, dict):
            return dict(meta)
    return {}


@lru_cache(maxsize=None)
def _load_analyzer_output_for_compute_cached(
    path_key: str,
    normalize_trace_coverage: bool = False,
) -> Any:
    analyzer_path = Path(path_key)
    analyzer = _json_load_path(analyzer_path)
    if (
        isinstance(analyzer, dict)
        and analyzer.get("manifest_kind") == "exact_sdc_analyzer_output_binary_v1"
    ):
        fmt = str(analyzer.get("binary_format", "")).strip().lower()
        if fmt != "pickle_dict_v1":
            raise ValueError(
                f"{analyzer_path}: unsupported analyzer output binary_format={fmt!r}"
            )
        ref_raw = analyzer.get("binary_ref")
        if ref_raw is None:
            raise ValueError(
                f"{analyzer_path}: binary analyzer output manifest missing binary_ref"
            )
        ref_path = Path(str(ref_raw))
        if not ref_path.is_absolute():
            ref_path = analyzer_path.parent / ref_path
        with ref_path.open("rb") as fh:
            analyzer = pickle.load(fh)
    analyzer = _expand_compact_analyzer_rows_for_compute(analyzer)
    return analyzer


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


def parse_int(value: Any) -> int:
    if isinstance(value, int):
        return int(value)
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def parse_mask(value: Any) -> int:
    if isinstance(value, int):
        return value & MASK64
    if isinstance(value, str):
        return int(value, 0) & MASK64
    return 0


def parse_spec_list(spec: Optional[str]) -> Optional[List[int]]:
    if spec is None or spec == "":
        return None
    out: List[int] = []
    for tok in spec.replace(",", ":").split(":"):
        t = tok.strip()
        if not t:
            continue
        out.append(parse_int(t))
    return out


def _parse_addr_bits_spec(raw: Any) -> Tuple[str, Optional[List[int]]]:
    mode_raw = str(raw if raw is not None else "").strip()
    mode_lc = mode_raw.lower()
    if mode_lc in ("", "auto"):
        return "auto", None
    if mode_lc == "all":
        return "all", None
    vals = parse_spec_list(mode_raw)
    if vals is None:
        return "auto", None
    selected: List[int] = []
    for v in vals:
        iv = int(v)
        if iv <= 0:
            continue
        selected.append(int(iv))
    if not selected:
        raise ValueError(
            "addr-bits spec must include at least one positive bit index, "
            f"or use auto/all; got {raw!r}"
        )
    return "explicit", selected


def _effective_bits_from_mask(mask: int) -> int:
    m = int(mask) & MASK64
    if m <= 0:
        return 0
    return int(m.bit_length())


def _resolve_selected_addr_bits(
    *,
    effective_mask: int,
    addr_bits_mode: str,
    addr_bits_explicit: Optional[Sequence[int]],
) -> Tuple[int, int, int]:
    eff_mask = int(effective_mask) & MASK64
    eff_bits = _effective_bits_from_mask(eff_mask)
    if eff_bits <= 0:
        return 0, 0, 0

    mode = str(addr_bits_mode).strip().lower()
    if mode not in ADDR_BITS_MODES:
        mode = "auto"

    selected_mask = 0
    if mode in ("auto", "all"):
        selected_mask = width_mask(eff_bits)
    else:
        for bit_1based in list(addr_bits_explicit or []):
            b = int(bit_1based)
            if b <= 0 or b > int(eff_bits):
                continue
            selected_mask |= (1 << (int(b) - 1))
    selected_mask &= MASK64
    return int(selected_mask), int(popcount_u64(selected_mask)), int(eff_bits)


def _summarize_effective_bits(values: Set[int]) -> Any:
    cleaned = sorted({int(v) for v in values if int(v) > 0})
    if not cleaned:
        return 0
    if len(cleaned) == 1:
        return int(cleaned[0])
    return "varies"


def parse_shader_list(spec: Optional[str]) -> Optional[List[int]]:
    if spec is None:
        return None
    raw = str(spec).strip()
    if raw == "":
        return None
    toks = raw.replace(",", " ").replace(":", " ").split()
    out: List[int] = []
    for tok in toks:
        t = tok.strip()
        if not t:
            continue
        out.append(parse_int(t))
    if not out:
        return None
    return out


def _parse_shader_domain_value(raw: Any) -> Optional[List[int]]:
    if raw is None:
        return None
    if isinstance(raw, (list, tuple)):
        out: List[int] = []
        seen: Set[int] = set()
        for item in raw:
            try:
                val = int(item)
            except Exception:
                continue
            if val in seen:
                continue
            seen.add(val)
            out.append(int(val))
        return out or None
    return parse_shader_list(str(raw))


def parse_register_list(spec: str) -> List[str]:
    p = Path(spec)
    if p.exists() and p.is_file():
        vals = [line.strip() for line in p.read_text().splitlines() if line.strip()]
    else:
        vals = [tok.strip() for tok in spec.replace(",", ":").split(":") if tok.strip()]
    # Keep duplicates to mirror FI's line-sampling semantics:
    # `shuf -n 1 register_used.txt` samples rows, so duplicate rows carry weight.
    return list(vals)


def _normalize_trace_uncovered_mode(raw: Any) -> str:
    return CANONICAL_TRACE_UNCOVERED_MODE


def _normalize_trace_expanding_resolution_mode(raw: Any) -> str:
    return CANONICAL_TRACE_EXPANDING_RESOLUTION_MODE


def _normalize_cache_tag_class_policy(raw: Any) -> str:
    return CANONICAL_CACHE_TAG_CLASS_POLICY


def _normalize_missing_active_threads_policy(raw: Any) -> str:
    return CANONICAL_MISSING_ACTIVE_THREADS_POLICY


def _normalize_addr_fault_policy(raw: Any) -> str:
    return CANONICAL_ADDR_FAULT_POLICY


def _normalize_trace_divergence_policy(raw: Any) -> str:
    return CANONICAL_TRACE_DIVERGENCE_POLICY


def _normalize_metadata_fault_policy(raw: Any) -> str:
    return CANONICAL_METADATA_FAULT_POLICY


def _normalize_addr_due_mode(raw: Any) -> str:
    return CANONICAL_ADDR_DUE_MODE


def _normalize_smem_addr_exception_policy(raw: Any) -> str:
    return CANONICAL_SMEM_ADDR_EXCEPTION_POLICY


def _normalize_smem_domain_policy(raw: Any) -> str:
    return CANONICAL_SMEM_DOMAIN_POLICY


def _normalize_rf_domain_policy(raw: Any) -> str:
    return CANONICAL_RF_DOMAIN_POLICY


def _normalize_rf_addr_reg_policy(raw: Any) -> str:
    return CANONICAL_RF_ADDR_REG_POLICY


def _cache_tag_counts_from_data(
    *,
    tag_total: int,
    data_masked: int,
    data_sdc: int,
    data_due: int,
    data_unknown: int,
    policy: str,
) -> Dict[str, int]:
    tag_total_i = max(0, int(tag_total))
    if tag_total_i <= 0:
        return {"masked": 0, "sdc": 0, "due": 0, "unknown": 0}
    return {"masked": 0, "sdc": 0, "due": 0, "unknown": int(tag_total_i)}


@dataclass(frozen=True)
class CycleRecord:
    cycle: int
    multiplicity: int
    active_thread_ids: Sequence[int]


@dataclass(frozen=True)
class ThreadIdRanges:
    """Compact active-thread sequence represented as ordered [start, stop) runs.

    This keeps simulator-emitted ``active_thread_ranges`` columnar instead of
    expanding multi-run rows into large Python tuples.  It still behaves like a
    read-only integer sequence for legacy callers that index or iterate IDs.
    """

    ranges: Tuple[Tuple[int, int], ...]
    size: int

    def __len__(self) -> int:
        return int(self.size)

    def __iter__(self) -> Iterable[int]:
        for start, stop in self.ranges:
            yield from range(int(start), int(stop))

    def __getitem__(self, index: Any) -> Any:
        if isinstance(index, slice):
            return tuple(self)[index]
        idx = int(index)
        if idx < 0:
            idx += int(self.size)
        if idx < 0 or idx >= int(self.size):
            raise IndexError(idx)
        offset = 0
        for start, stop in self.ranges:
            count = int(stop) - int(start)
            if idx < offset + count:
                return int(start) + (idx - offset)
            offset += count
        raise IndexError(index)


class ThreadCycleWeightsDict(dict):
    __slots__ = ("_sorted_entries", "_thread_prefix")

    def __init__(self) -> None:
        super().__init__()
        self._sorted_entries: Optional[List[Tuple[int, int, int]]] = None
        self._thread_prefix: Optional[
            Dict[int, Tuple[List[int], List[int], int]]
        ] = None


def _intern_thread_id_sequence(
    ids: Sequence[int],
    intern: Dict[Tuple[Any, ...], Sequence[int]],
) -> Sequence[int]:
    if isinstance(ids, range):
        key: Tuple[Any, ...] = ("range", int(ids.start), int(ids.stop), int(ids.step))
        cached = intern.get(key)
        if cached is not None:
            return cached
        intern[key] = ids
        return ids
    if isinstance(ids, ThreadIdRanges):
        key = ("ranges",) + tuple(
            (int(start), int(stop)) for start, stop in ids.ranges
        )
        cached = intern.get(key)
        if cached is not None:
            return cached
        intern[key] = ids
        return ids
    key = ("tuple",) + tuple(int(v) for v in ids)
    cached = intern.get(key)
    if cached is not None:
        return cached
    seq = tuple(key[1:])
    intern[key] = seq
    return seq


def _normalize_thread_ids_for_cycle_record(ids: Sequence[int]) -> Sequence[int]:
    if isinstance(ids, (range, ThreadIdRanges)):
        return ids
    if isinstance(ids, tuple) and all(isinstance(v, int) for v in ids):
        return ids
    return tuple(int(x) for x in ids)


def _thread_id_sequence_cache_key(ids: Sequence[int]) -> Tuple[Any, ...]:
    if isinstance(ids, range):
        return ("range", int(ids.start), int(ids.stop), int(ids.step))
    if isinstance(ids, ThreadIdRanges):
        return ("ranges",) + tuple(
            (int(start), int(stop)) for start, stop in ids.ranges
        )
    return ("tuple",) + tuple(int(v) for v in ids)


def _iter_thread_ids_from_sequence(ids: Sequence[int]) -> Iterable[int]:
    if isinstance(ids, (range, ThreadIdRanges)):
        return ids
    return (int(v) for v in ids)


@dataclass(frozen=True)
class RFAddrTraceRecord:
    event_index: int
    src_index: int
    influence_mask: int


@dataclass(frozen=True)
class RFAddrEventEvalInfo:
    access_size_bytes: int
    active_intervals: Tuple[Tuple[int, int], ...]
    observed_intervals: Tuple[Tuple[int, int], ...]
    base_effective_ea: int
    base_raw_ea: Optional[int]
    expr_width_mask: int
    effective_mask: int
    expr_src_coeffs: Mapping[int, int]


RFAddrObservedIntervalKey = Tuple[str, Optional[int], Optional[int], Optional[int]]
RFAddrObservedIntervals = Dict[RFAddrObservedIntervalKey, Tuple[Tuple[int, int], ...]]


def _compact_thread_id_sequence(raw_ids: Sequence[Any]) -> Sequence[int]:
    if not raw_ids:
        return tuple()
    if isinstance(raw_ids, range):
        return raw_ids
    if isinstance(raw_ids, (list, tuple)) and raw_ids and all(
        isinstance(v, int) for v in raw_ids
    ):
        start = int(raw_ids[0])
        end = int(raw_ids[-1])
        count = int(len(raw_ids))
        if count == 1:
            return range(start, start + 1)
        if end >= start and (end - start + 1) == count:
            expected_sum = (start + end) * count // 2
            if int(sum(raw_ids)) == int(expected_sum):
                return range(start, end + 1)
        return tuple(int(x) for x in raw_ids)

    start: Optional[int] = None
    prev: Optional[int] = None
    contiguous = True
    values: List[int] = []
    for raw in raw_ids:
        value = int(raw)
        values.append(int(value))
        if start is None:
            start = value
            prev = value
            continue
        if contiguous and value != int(prev) + 1:
            contiguous = False
        prev = value
    if contiguous and start is not None and prev is not None:
        return range(int(start), int(prev) + 1)
    return tuple(values)


def _looks_like_jsonl_bytes(raw_bytes: bytes) -> bool:
    head = raw_bytes[:4096]
    return b"\n{" in head


def _parse_jsonl_int_field(line: bytes, field_name: bytes) -> Optional[int]:
    key = b'"' + field_name + b'":'
    pos = line.find(key)
    if pos < 0:
        return None
    pos += len(key)
    line_len = len(line)
    while pos < line_len and line[pos] in b" \t":
        pos += 1
    if pos >= line_len:
        return None
    sign = 1
    if line[pos] == ord("-"):
        sign = -1
        pos += 1
    if pos >= line_len or line[pos] < ord("0") or line[pos] > ord("9"):
        return None
    value = 0
    while pos < line_len and ord("0") <= line[pos] <= ord("9"):
        value = value * 10 + (line[pos] - ord("0"))
        pos += 1
    return int(sign * value)


def _parse_jsonl_int_array_compact(
    line: bytes,
    field_name: bytes,
    *,
    expected_size: Optional[int] = None,
) -> Optional[Sequence[int]]:
    key = b'"' + field_name + b'":['
    pos = line.find(key)
    if pos < 0:
        return None
    pos += len(key)
    line_len = len(line)
    while pos < line_len and line[pos] in b" \t\r\n":
        pos += 1
    if pos < line_len and line[pos] == ord("]"):
        if expected_size is not None and int(expected_size) != 0:
            return None
        return tuple()

    def _read_int_at(read_pos: int) -> Optional[Tuple[int, int]]:
        while read_pos < line_len and line[read_pos] in b" \t\r\n":
            read_pos += 1
        if read_pos >= line_len:
            return None
        sign = 1
        if line[read_pos] == ord("-"):
            sign = -1
            read_pos += 1
        if (
            read_pos >= line_len
            or line[read_pos] < ord("0")
            or line[read_pos] > ord("9")
        ):
            return None
        value = 0
        while read_pos < line_len and ord("0") <= line[read_pos] <= ord("9"):
            value = value * 10 + (line[read_pos] - ord("0"))
            read_pos += 1
        return int(sign * value), int(read_pos)

    # Simulator active-thread JSONL often emits very large dense ranges such as
    # [1,2,3,...,32768].  Fully materializing/parsing those rows dominates Exact
    # compute startup.  When the row itself declares the active size and the
    # endpoints match a dense +1 sequence, keep the compact range form and avoid
    # per-number Python work.  Irregular/small arrays still take the checked
    # scanner below.
    if expected_size is not None and int(expected_size) > 64:
        close = line.find(b"]", pos)
        if close > pos:
            first_read = _read_int_at(pos)
            last_comma = line.rfind(b",", pos, close)
            if first_read is not None and last_comma > pos:
                first_val, first_end = first_read
                comma_after_first = line.find(b",", first_end, close)
                second_read = (
                    _read_int_at(comma_after_first + 1)
                    if comma_after_first >= 0
                    else None
                )
                last_read = _read_int_at(last_comma + 1)
                if second_read is not None and last_read is not None:
                    second_val, _second_end = second_read
                    last_val, last_end = last_read
                    while last_end < close and line[last_end] in b" \t\r\n":
                        last_end += 1
                    if (
                        int(second_val) == int(first_val) + 1
                        and int(last_val) == int(first_val) + int(expected_size) - 1
                        and int(last_end) == int(close)
                    ):
                        return range(int(first_val), int(last_val) + 1)

    first: Optional[int] = None
    prev: Optional[int] = None
    count = 0
    contiguous = True
    values: Optional[List[int]] = None
    while pos < line_len:
        while pos < line_len and line[pos] in b" \t\r\n":
            pos += 1
        if pos >= line_len:
            return None
        sign = 1
        if line[pos] == ord("-"):
            sign = -1
            pos += 1
        if pos >= line_len or line[pos] < ord("0") or line[pos] > ord("9"):
            return None
        value = 0
        while pos < line_len and ord("0") <= line[pos] <= ord("9"):
            value = value * 10 + (line[pos] - ord("0"))
            pos += 1
        value *= sign
        if first is None:
            first = int(value)
            prev = int(value)
        else:
            if contiguous and int(value) == int(prev) + 1:
                prev = int(value)
            else:
                if contiguous:
                    values = list(range(int(first), int(prev) + 1))
                    contiguous = False
                assert values is not None
                values.append(int(value))
                prev = int(value)
        count += 1
        while pos < line_len and line[pos] in b" \t\r\n":
            pos += 1
        if pos >= line_len:
            return None
        if line[pos] == ord(","):
            pos += 1
            continue
        if line[pos] == ord("]"):
            break
        return None

    if expected_size is not None and int(count) != int(expected_size):
        return None
    if count == 0 or first is None or prev is None:
        return tuple()
    if contiguous:
        return range(int(first), int(prev) + 1)
    assert values is not None
    return tuple(values)


def _sequence_from_thread_ranges(
    raw_ranges: Any,
    *,
    expected_size: Optional[int] = None,
) -> Optional[Sequence[int]]:
    """Decode simulator [start, count] thread-id runs without losing order."""
    if not isinstance(raw_ranges, (list, tuple)):
        return None
    if not raw_ranges:
        if expected_size is not None and int(expected_size) != 0:
            return None
        return tuple()
    ranges: List[Tuple[int, int]] = []
    total = 0
    for item in raw_ranges:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            return None
        start = int(item[0])
        count = int(item[1])
        if count < 0:
            return None
        if count == 0:
            continue
        ranges.append((start, count))
        total += count
    if expected_size is not None and int(total) != int(expected_size):
        return None
    if not ranges:
        return tuple()
    if len(ranges) == 1:
        start, count = ranges[0]
        return range(start, start + count)
    return ThreadIdRanges(
        tuple((int(start), int(start) + int(count)) for start, count in ranges),
        int(total),
    )


def _parse_jsonl_int_ranges_compact(
    line: bytes,
    field_name: bytes,
    *,
    expected_size: Optional[int] = None,
) -> Optional[Sequence[int]]:
    key = b'"' + field_name + b'":['
    pos = line.find(key)
    if pos < 0:
        return None
    pos += len(key)
    line_len = len(line)

    def _skip_ws(read_pos: int) -> int:
        while read_pos < line_len and line[read_pos] in b" \t\r\n":
            read_pos += 1
        return read_pos

    def _read_int_at(read_pos: int) -> Optional[Tuple[int, int]]:
        read_pos = _skip_ws(read_pos)
        if read_pos >= line_len:
            return None
        sign = 1
        if line[read_pos] == ord("-"):
            sign = -1
            read_pos += 1
        if (
            read_pos >= line_len
            or line[read_pos] < ord("0")
            or line[read_pos] > ord("9")
        ):
            return None
        value = 0
        while read_pos < line_len and ord("0") <= line[read_pos] <= ord("9"):
            value = value * 10 + (line[read_pos] - ord("0"))
            read_pos += 1
        return int(sign * value), int(read_pos)

    pos = _skip_ws(pos)
    if pos < line_len and line[pos] == ord("]"):
        if expected_size is not None and int(expected_size) != 0:
            return None
        return tuple()

    ranges: List[Tuple[int, int]] = []
    total = 0
    while pos < line_len:
        pos = _skip_ws(pos)
        if pos >= line_len or line[pos] != ord("["):
            return None
        pos += 1
        start_read = _read_int_at(pos)
        if start_read is None:
            return None
        start, pos = start_read
        pos = _skip_ws(pos)
        if pos >= line_len or line[pos] != ord(","):
            return None
        count_read = _read_int_at(pos + 1)
        if count_read is None:
            return None
        count, pos = count_read
        if count < 0:
            return None
        pos = _skip_ws(pos)
        if pos >= line_len or line[pos] != ord("]"):
            return None
        pos += 1
        if count:
            ranges.append((int(start), int(count)))
            total += int(count)
        pos = _skip_ws(pos)
        if pos >= line_len:
            return None
        if line[pos] == ord(","):
            pos += 1
            continue
        if line[pos] == ord("]"):
            break
        return None

    if expected_size is not None and int(total) != int(expected_size):
        return None
    if not ranges:
        return tuple()
    if len(ranges) == 1:
        start, count = ranges[0]
        return range(start, start + count)
    return ThreadIdRanges(
        tuple((int(start), int(start) + int(count)) for start, count in ranges),
        int(total),
    )


def _parse_active_threads_jsonl_line_compact(
    line: bytes,
) -> Optional[Tuple[int, Sequence[int]]]:
    cycle = _parse_jsonl_int_field(line, b"cycle")
    if cycle is None:
        return None
    active_size = _parse_jsonl_int_field(line, b"active_threads_size")
    ids = _parse_jsonl_int_array_compact(
        line,
        b"active_thread_ids",
        expected_size=active_size,
    )
    if ids is None:
        ids = _parse_jsonl_int_ranges_compact(
            line,
            b"active_thread_ranges",
            expected_size=active_size,
        )
    if ids is None:
        return None
    return int(cycle), ids


def _load_cycle_counts_text(path: Path) -> Counter:
    counts: Counter = Counter()
    for line in path.read_bytes().splitlines():
        s = line.strip()
        if not s or s.startswith(b"#"):
            continue
        parts = s.replace(b",", b" ").split()
        if not parts:
            continue
        cycle = parse_int(parts[0])
        counts[cycle] += 1
    return counts


def _load_cycle_counts_json(path: Path) -> Tuple[Counter, Dict[int, Tuple[int, ...]]]:
    raw = _json_load_path(path)
    if isinstance(raw, dict):
        if "cycles" not in raw:
            raise ValueError(f"{path}: JSON object must contain 'cycles'")
        raw = raw["cycles"]
    if not isinstance(raw, list):
        raise ValueError(f"{path}: cycle JSON must be a list or {{'cycles': [...]}}")
    counts: Counter = Counter()
    ids_by_cycle: Dict[int, Tuple[int, ...]] = {}
    for i, item in enumerate(raw):
        if isinstance(item, dict):
            if "cycle" not in item:
                raise ValueError(f"{path}: cycles[{i}] missing cycle")
            cycle = int(item["cycle"])
            multiplicity = int(item.get("multiplicity", 1))
            if multiplicity <= 0:
                continue
            counts[cycle] += multiplicity
            ids = item.get("active_thread_ids")
            ids_seq: Optional[Sequence[int]] = None
            if ids is not None:
                ids_seq = tuple(int(x) for x in ids)
            elif "active_thread_ranges" in item:
                ids_seq = _sequence_from_thread_ranges(
                    item.get("active_thread_ranges"),
                    expected_size=item.get("active_threads_size"),
                )
            if ids_seq is not None:
                ids_tuple = tuple(int(x) for x in ids_seq)
                prev = ids_by_cycle.get(cycle)
                if prev is not None and prev != ids_tuple:
                    raise ValueError(
                        f"{path}: conflicting active thread ids for cycle {cycle}"
                    )
                ids_by_cycle[cycle] = ids_tuple
            continue
        if isinstance(item, list) and item:
            cycle = int(item[0])
            multiplicity = int(item[2]) if len(item) >= 3 else 1
            if multiplicity <= 0:
                continue
            counts[cycle] += multiplicity
            continue
        raise ValueError(f"{path}: unsupported cycles[{i}] item: {item!r}")
    return counts, ids_by_cycle


def load_active_threads_log(path: Path) -> Dict[int, Sequence[int]]:
    raw_bytes = path.read_bytes()
    raw_bytes = raw_bytes.strip()
    if not raw_bytes:
        return {}

    # JSON object/array mode.  The simulator active-thread log is JSONL and
    # commonly starts with "{", so avoid attempting a whole-file JSON parse for
    # that hot path.
    if raw_bytes[:1] in (b"{", b"[") and not _looks_like_jsonl_bytes(raw_bytes):
        try:
            raw = _json_load_path(path)
            rows: Iterable[Any]
            if isinstance(raw, dict) and "active_threads_by_cycle" in raw:
                rows = raw["active_threads_by_cycle"]
            elif isinstance(raw, list):
                rows = raw
            else:
                rows = []
            out: Dict[int, Sequence[int]] = {}
            intern: Dict[Tuple[Any, ...], Sequence[int]] = {}
            for row in rows:
                if not isinstance(row, dict):
                    continue
                if (
                    "cycle" not in row
                    or (
                        "active_thread_ids" not in row
                        and "active_thread_ranges" not in row
                    )
                ):
                    continue
                raw_ids = row.get("active_thread_ids")
                if isinstance(raw_ids, (list, tuple)):
                    ids = _compact_thread_id_sequence(raw_ids)
                else:
                    ids = _sequence_from_thread_ranges(
                        row.get("active_thread_ranges"),
                        expected_size=row.get("active_threads_size"),
                    )
                    if ids is None:
                        continue
                out[int(row["cycle"])] = _intern_thread_id_sequence(
                    ids,
                    intern,
                )
            if out:
                return out
        except Exception:
            pass

    # JSONL fallback
    out: Dict[int, Sequence[int]] = {}
    intern: Dict[Tuple[Any, ...], Sequence[int]] = {}
    for i, line in enumerate(raw_bytes.splitlines()):
        s = line.strip()
        if not s:
            continue
        fast_row = _parse_active_threads_jsonl_line_compact(s)
        if fast_row is not None:
            cycle, ids = fast_row
            out[int(cycle)] = _intern_thread_id_sequence(ids, intern)
            continue
        try:
            row = (
                _orjson.loads(s)
                if _orjson is not None
                else json.loads(s.decode("utf-8"))
            )
        except Exception as exc:
            raise ValueError(f"{path}: invalid JSONL at line {i+1}: {exc}") from exc
        if not isinstance(row, dict):
            continue
        if (
            "cycle" not in row
            or (
                "active_thread_ids" not in row
                and "active_thread_ranges" not in row
            )
        ):
            continue
        raw_ids = row.get("active_thread_ids")
        if isinstance(raw_ids, (list, tuple)):
            ids = _compact_thread_id_sequence(raw_ids)
        else:
            ids = _sequence_from_thread_ranges(
                row.get("active_thread_ranges"),
                expected_size=row.get("active_threads_size"),
            )
            if ids is None:
                continue
        out[int(row["cycle"])] = _intern_thread_id_sequence(
            ids,
            intern,
        )
    return out


def load_shared_scope_thread_ids_log(path: Path) -> Dict[int, Sequence[int]]:
    return _load_shared_scope_thread_ids_log_cached(_path_cache_key(path))


@lru_cache(maxsize=None)
def _load_shared_scope_thread_ids_log_cached(path_key: str) -> Dict[int, Sequence[int]]:
    path = Path(path_key)
    raw_bytes = path.read_bytes()
    raw_bytes = raw_bytes.strip()
    if not raw_bytes:
        return {}

    if raw_bytes[:1] not in (b"{", b"[") and b'"shared_scope_thread_ids"' in raw_bytes:
        has_nonempty_shared_scope = False
        for line in raw_bytes.splitlines():
            s = line.strip()
            if not s:
                continue
            ids = _parse_jsonl_int_array_compact(s, b"shared_scope_thread_ids")
            if ids is not None and len(ids) > 0:
                has_nonempty_shared_scope = True
                break
        if not has_nonempty_shared_scope:
            return {}

    def _normalize_rows(rows: Iterable[Any]) -> Dict[int, Sequence[int]]:
        out: Dict[int, Sequence[int]] = {}
        intern: Dict[Tuple[Any, ...], Sequence[int]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            if "cycle" not in row or "shared_scope_thread_ids" not in row:
                continue
            try:
                cycle = int(row["cycle"])
            except Exception:
                continue
            raw_ids = row.get("shared_scope_thread_ids")
            if not isinstance(raw_ids, (list, tuple)):
                continue
            out[cycle] = _intern_thread_id_sequence(
                _compact_thread_id_sequence(raw_ids),
                intern,
            )
        return out

    # JSON object/array mode
    if raw_bytes[:1] in (b"{", b"[") and not _looks_like_jsonl_bytes(raw_bytes):
        try:
            raw = _json_load_path(path)
            rows: Iterable[Any]
            if isinstance(raw, dict) and "active_threads_by_cycle" in raw:
                rows = raw["active_threads_by_cycle"]
            elif isinstance(raw, list):
                rows = raw
            else:
                rows = []
            out = _normalize_rows(rows)
            if out:
                return out
        except Exception:
            pass

    # JSONL fallback
    out: Dict[int, Sequence[int]] = {}
    intern: Dict[Tuple[Any, ...], Sequence[int]] = {}
    rows: List[Any] = []
    for i, line in enumerate(raw_bytes.splitlines()):
        s = line.strip()
        if not s:
            continue
        cycle = _parse_jsonl_int_field(s, b"cycle")
        ids = _parse_jsonl_int_array_compact(s, b"shared_scope_thread_ids")
        if cycle is not None and ids is not None:
            if len(ids) > 0:
                out[int(cycle)] = _intern_thread_id_sequence(ids, intern)
            continue
        try:
            rows.append(
                _orjson.loads(s)
                if _orjson is not None
                else json.loads(s.decode("utf-8"))
            )
        except Exception as exc:
            raise ValueError(f"{path}: invalid JSONL at line {i+1}: {exc}") from exc
    if out:
        return out
    return _normalize_rows(rows)


def load_cycle_records_with_meta(
    cycles_path: Path,
    active_log_path: Optional[Path],
    allow_missing_active_threads: bool = False,
    missing_active_threads_policy: str = "empty",
) -> Tuple[List[CycleRecord], Dict[str, Any]]:
    active_key = ""
    if active_log_path is not None:
        active_key = _path_cache_key(active_log_path)
    return _load_cycle_records_with_meta_cached(
        _path_cache_key(cycles_path),
        active_key,
        bool(allow_missing_active_threads),
        str(missing_active_threads_policy),
    )


@lru_cache(maxsize=None)
def _load_cycle_records_with_meta_cached(
    cycles_path_key: str,
    active_log_path_key: str,
    allow_missing_active_threads: bool,
    missing_active_threads_policy: str,
) -> Tuple[List[CycleRecord], Dict[str, Any]]:
    cycles_path = Path(cycles_path_key)
    active_log_path = Path(active_log_path_key) if active_log_path_key else None
    if cycles_path.suffix.lower() == ".json":
        counts, ids_from_cycles = _load_cycle_counts_json(cycles_path)
    else:
        counts = _load_cycle_counts_text(cycles_path)
        ids_from_cycles = {}

    if not counts:
        raise ValueError(f"{cycles_path}: empty cycle domain")

    ids_from_log: Dict[int, Tuple[int, ...]] = {}
    if active_log_path is not None:
        ids_from_log = load_active_threads_log(active_log_path)

    policy = _normalize_missing_active_threads_policy(missing_active_threads_policy)
    out: List[CycleRecord] = []
    missing_cycles = 0
    carried_forward_cycles = 0
    empty_fill_cycles = 0
    trailing_empty_extension_cycles = 0
    carry_forward_seed_missing_cycles = 0
    last_ids: Optional[Sequence[int]] = None
    max_logged_cycle = max(ids_from_log.keys()) if ids_from_log else None
    for cycle, multiplicity in sorted(counts.items()):
        ids = ids_from_cycles.get(cycle)
        if ids is None:
            ids = ids_from_log.get(cycle)
        if ids is None:
            if allow_missing_active_threads:
                trailing_empty_extension = (
                    max_logged_cycle is not None
                    and int(cycle) > int(max_logged_cycle)
                    and last_ids is not None
                    and len(last_ids) == 0
                )
                if trailing_empty_extension:
                    ids = tuple()
                    trailing_empty_extension_cycles += 1
                else:
                    missing_cycles += 1
                    if policy == "carry-forward" and last_ids is not None:
                        ids = last_ids
                        carried_forward_cycles += 1
                    else:
                        ids = tuple()
                        empty_fill_cycles += 1
                        if policy == "carry-forward":
                            carry_forward_seed_missing_cycles += 1
            else:
                raise ValueError(
                    f"Missing active threads for cycle {cycle}. "
                    "Provide --active-threads-log or embed active_thread_ids/"
                    "active_thread_ranges in cycles JSON."
                )
        last_ids = _normalize_thread_ids_for_cycle_record(ids)
        out.append(
            CycleRecord(
                cycle=cycle,
                multiplicity=int(multiplicity),
                active_thread_ids=last_ids,
            )
        )
    total_cycles = int(len(out))
    missing_ratio = (float(missing_cycles) / float(total_cycles)) if total_cycles > 0 else 0.0
    diag = {
        "missing_active_threads_policy": str(policy),
        "missing_active_thread_cycles": int(missing_cycles),
        "missing_active_thread_cycle_ratio": float(missing_ratio),
        "active_threads_carried_forward_cycles": int(carried_forward_cycles),
        "active_threads_empty_fill_cycles": int(empty_fill_cycles),
        "trailing_empty_active_thread_extension_cycles": int(
            trailing_empty_extension_cycles
        ),
        "carry_forward_seed_missing_cycles": int(carry_forward_seed_missing_cycles),
        "active_threads_cycle_total": int(total_cycles),
    }
    return out, diag


def load_cycle_records(
    cycles_path: Path,
    active_log_path: Optional[Path],
    allow_missing_active_threads: bool = False,
    missing_active_threads_policy: str = "empty",
) -> List[CycleRecord]:
    rows, _meta = load_cycle_records_with_meta(
        cycles_path=cycles_path,
        active_log_path=active_log_path,
        allow_missing_active_threads=allow_missing_active_threads,
        missing_active_threads_policy=missing_active_threads_policy,
    )
    return rows


def parse_regfile_accesses(
    path: Path,
) -> Tuple[Dict[int, Dict[int, List[int]]], Dict[int, Dict[int, List[int]]]]:
    return _parse_regfile_accesses_cached(_path_cache_key(path))


@lru_cache(maxsize=None)
def _parse_regfile_accesses_cached(
    path_key: str,
) -> Tuple[Dict[int, Dict[int, List[int]]], Dict[int, Dict[int, List[int]]]]:
    path = Path(path_key)
    data = path.read_bytes()
    if len(data) < HEADER_STRUCT.size:
        raise ValueError(f"{path}: too small")
    magic, _version, record_size, _flags, _reserved = HEADER_STRUCT.unpack_from(data, 0)
    if magic != MAGIC_RFTR:
        raise ValueError(f"{path}: invalid magic 0x{magic:08x}")
    if record_size < EVENT_STRUCT.size:
        raise ValueError(f"{path}: unsupported record_size={record_size}")
    payload = data[HEADER_STRUCT.size :]
    if len(payload) % record_size != 0:
        raise ValueError(f"{path}: payload not aligned to record_size")

    reads: Dict[int, Dict[int, List[int]]] = defaultdict(lambda: defaultdict(list))
    writes: Dict[int, Dict[int, List[int]]] = defaultdict(lambda: defaultdict(list))
    for off in range(0, len(payload), record_size):
        rec = payload[off : off + record_size]
        cycle, thread_uid, reg_uid_and_type = EVENT_STRUCT.unpack_from(rec, 0)
        reg_uid = reg_uid_and_type & ~WRITE_BIT
        if (reg_uid_and_type & WRITE_BIT) != 0:
            writes[int(thread_uid)][int(reg_uid)].append(int(cycle))
        else:
            reads[int(thread_uid)][int(reg_uid)].append(int(cycle))

    # Dedup within each (thread, reg), keeping sorted cycle list.
    for per_thread in reads.values():
        for reg_uid, cycles in list(per_thread.items()):
            per_thread[reg_uid] = sorted(set(cycles))
    for per_thread in writes.values():
        for reg_uid, cycles in list(per_thread.items()):
            per_thread[reg_uid] = sorted(set(cycles))
    return reads, writes


def parse_regfile_reads(path: Path) -> Dict[int, Dict[int, List[int]]]:
    reads, _writes = parse_regfile_accesses(path)
    return reads


def _merge_sorted_unique_cycles(
    lhs: Sequence[int],
    rhs: Sequence[int],
) -> List[int]:
    if not lhs:
        return [int(v) for v in rhs]
    if not rhs:
        return [int(v) for v in lhs]

    out: List[int] = []
    i = 0
    j = 0
    lhs_len = len(lhs)
    rhs_len = len(rhs)
    last: Optional[int] = None
    while i < lhs_len and j < rhs_len:
        lv = int(lhs[i])
        rv = int(rhs[j])
        if lv == rv:
            cur = lv
            i += 1
            j += 1
        elif lv < rv:
            cur = lv
            i += 1
        else:
            cur = rv
            j += 1
        if last != cur:
            out.append(cur)
            last = cur
    while i < lhs_len:
        cur = int(lhs[i])
        i += 1
        if last != cur:
            out.append(cur)
            last = cur
    while j < rhs_len:
        cur = int(rhs[j])
        j += 1
        if last != cur:
            out.append(cur)
            last = cur
    return out


def _invert_thread_reg_cycles(
    per_thread_cycles: Dict[int, Dict[int, List[int]]],
    valid_threads: Optional[Set[int]] = None,
) -> Dict[int, Dict[int, Sequence[int]]]:
    out: Dict[int, Dict[int, Sequence[int]]] = defaultdict(dict)
    for tid, per_reg in per_thread_cycles.items():
        tid_i = int(tid)
        if valid_threads is not None and tid_i not in valid_threads:
            continue
        for reg_uid, cycles in per_reg.items():
            if not cycles:
                continue
            out[int(reg_uid)][tid_i] = cycles
    return {int(uid): dict(per_tid) for uid, per_tid in out.items()}


def _collect_label_thread_cycles(
    uid_index: Mapping[int, Mapping[int, Sequence[int]]],
    uids: Sequence[int],
) -> Dict[int, List[int]]:
    out: Dict[int, List[int]] = {}
    for uid in uids:
        per_thread = uid_index.get(int(uid))
        if not per_thread:
            continue
        for tid, cycles in per_thread.items():
            tid_i = int(tid)
            prev = out.get(tid_i)
            if prev is None:
                out[tid_i] = [int(v) for v in cycles]
            else:
                out[tid_i] = _merge_sorted_unique_cycles(prev, cycles)
    return out


def _trace_policy_for_unresolved_bits(
    trace_mask: int,
    *,
    wmask: int,
    trace_expanding_policy: str,
    trace_uncovered_mode: str,
) -> Tuple[int, int, int]:
    unresolved = int(trace_mask) & int(wmask)
    return int(unresolved) & MASK64, 0, int(unresolved) & MASK64


def classify_bit_with_reason(
    rec: Dict[str, Any],
    bit: int,
    trace_expanding_policy: str,
    trace_uncovered_mode: str = "legacy_unknown",
    trace_expanding_resolution_mode: str = "legacy",
) -> Tuple[str, str]:
    if trace_expanding_policy != CANONICAL_TRACE_EXPANDING_POLICY:
        raise ValueError(f"invalid trace_expanding_policy={trace_expanding_policy!r}")
    bit0 = int(bit)
    obs = parse_mask(_read_event_row_field(rec, "observed_mask_this_read", 0))
    due = parse_mask(_read_event_row_field(rec, "due_mask_this_read", 0))
    trace = parse_mask(_read_event_row_field(rec, "trace_expanding_mask_this_read", 0))
    due_bit = ((due >> bit0) & 1) != 0
    obs_bit = ((obs >> bit0) & 1) != 0
    trace_bit = ((trace >> bit0) & 1) != 0
    if due_bit:
        return "due", "trace_proof" if trace_bit else "observed_path"
    if obs_bit:
        return "sdc", "trace_proof" if trace_bit else "observed_path"
    if trace_bit:
        return "unknown", "trace_policy_fallback_unknown"
    return "masked", "observed_path"


def classify_bit(
    rec: Dict[str, Any],
    bit: int,
    trace_expanding_policy: str,
    trace_uncovered_mode: str = "legacy_unknown",
    trace_expanding_resolution_mode: str = "legacy",
) -> str:
    cls, _reason = classify_bit_with_reason(
        rec, bit, trace_expanding_policy, trace_uncovered_mode, trace_expanding_resolution_mode
    )
    return cls


def bit_class_counts(
    rec: Dict[str, Any],
    trace_expanding_policy: str,
    trace_uncovered_mode: str = "legacy_unknown",
    trace_expanding_resolution_mode: str = "legacy",
) -> Tuple[Dict[str, int], Dict[str, int], int]:
    width = max(0, min(64, int(_read_event_row_field(rec, "src_width_bits", 64))))
    counts = {"masked": 0, "sdc": 0, "due": 0, "unknown": 0}
    reason_counts: Dict[str, int] = {}
    policy_added = 0
    for b in range(width):
        cls, reason = classify_bit_with_reason(
            rec, b, trace_expanding_policy, trace_uncovered_mode, trace_expanding_resolution_mode
        )
        counts[cls] = counts.get(cls, 0) + 1
        reason_counts[reason] = reason_counts.get(reason, 0) + 1
        if reason == "trace_policy_fallback_unknown":
            policy_added += 1
    return counts, reason_counts, policy_added


def width_mask(width_bits: Any) -> int:
    try:
        w = int(width_bits)
    except Exception:
        w = 64
    w = max(0, min(64, w))
    if w <= 0:
        return 0
    if w >= 64:
        return MASK64
    return (1 << w) - 1


def _cpp_classify_read_masks(**_kwargs: Any) -> Optional[Tuple[int, int, int, int, int, int, int]]:
    return None


def _cpp_classify_read_masks_many(
    records: Sequence[FastMaskRecord],
    *,
    trace_expanding_policy: str,
    trace_uncovered_mode: str,
    trace_expanding_resolution_mode: str = "legacy",
) -> Optional[List[Tuple[int, int, int, int, int, int, int]]]:
    return None


def _cpp_classify_site_masks(**_kwargs: Any) -> Optional[Tuple[int, int, int, int, int]]:
    return None


def _cpp_classify_site_masks_many(
    records: Sequence[Any],
    *,
    trace_expanding_policy: str,
    trace_uncovered_mode: str,
    trace_expanding_resolution_mode: str = "legacy",
) -> Optional[List[Tuple[int, int, int, int, int]]]:
    return None


def _final_due_sdc_masks_with_meta_fast_extended_many(
    records: Sequence[FastMaskRecord],
    *,
    trace_expanding_policy: str,
    trace_uncovered_mode: str,
    trace_expanding_resolution_mode: str = "legacy",
) -> List[Tuple[int, int, int, int, int, int, int]]:
    return [
        final_due_sdc_masks_with_meta_fast_extended(
            rec,
            trace_expanding_policy=trace_expanding_policy,
            trace_uncovered_mode=trace_uncovered_mode,
            trace_expanding_resolution_mode=trace_expanding_resolution_mode,
        )
        for rec in records
    ]


def final_due_sdc_masks_with_meta(
    rec: Dict[str, Any],
    trace_expanding_policy: str,
    trace_uncovered_mode: str = "legacy_unknown",
) -> Tuple[int, int, int, int, int, int, int]:
    return final_due_sdc_masks_with_meta_extended(
        rec=rec,
        trace_expanding_policy=trace_expanding_policy,
        trace_uncovered_mode=trace_uncovered_mode,
    )


def final_due_sdc_masks_with_meta_extended(
    rec: Any,
    trace_expanding_policy: str,
    trace_uncovered_mode: str = "legacy_unknown",
    trace_expanding_resolution_mode: str = "legacy",
) -> Tuple[int, int, int, int, int, int, int]:
    if trace_expanding_policy != CANONICAL_TRACE_EXPANDING_POLICY:
        raise ValueError(f"invalid trace_expanding_policy={trace_expanding_policy!r}")
    obs = parse_mask(_read_event_row_field(rec, "observed_mask_this_read", 0))
    due = parse_mask(_read_event_row_field(rec, "due_mask_this_read", 0))
    trace = parse_mask(_read_event_row_field(rec, "trace_expanding_mask_this_read", 0))
    wmask = width_mask(int(_read_event_row_field(rec, "src_width_bits", 64)))
    trace &= wmask
    obs &= wmask
    due &= wmask
    proof_due_trace = trace & due
    proof_sdc_trace = trace & obs & ((~proof_due_trace) & MASK64)
    trace_unresolved = trace & ((~proof_due_trace) & MASK64) & ((~proof_sdc_trace) & MASK64)
    policy_used_mask, policy_sdc_mask, policy_unknown_mask = _trace_policy_for_unresolved_bits(
        trace_unresolved,
        wmask=wmask,
        trace_expanding_policy=trace_expanding_policy,
        trace_uncovered_mode=trace_uncovered_mode,
    )
    inv_trace = (~trace) & wmask
    unknown_final = policy_unknown_mask
    due_final = proof_due_trace | (inv_trace & due)
    sdc_masked_baseline = proof_sdc_trace | (inv_trace & obs)
    sdc_final = sdc_masked_baseline | policy_sdc_mask
    due_final &= wmask
    sdc_final &= wmask
    unknown_final &= wmask
    due_final &= ~unknown_final
    sdc_final &= ~unknown_final
    sdc_final &= ~due_final
    sdc_masked_baseline &= wmask
    sdc_masked_baseline &= ~due_final
    sdc_masked_baseline &= ~unknown_final
    policy_added_sdc_mask = sdc_final & (~sdc_masked_baseline & MASK64)
    return (
        due_final & MASK64,
        sdc_final & MASK64,
        unknown_final & MASK64,
        policy_added_sdc_mask & MASK64,
        policy_used_mask & MASK64,
        trace & MASK64,
        0,
    )


def final_due_sdc_masks(
    rec: Dict[str, Any],
    trace_expanding_policy: str,
    trace_uncovered_mode: str = "legacy_unknown",
) -> Tuple[int, int, int]:
    due_mask, sdc_mask, _unknown_mask, policy_added_sdc_mask, *_rest = (
        final_due_sdc_masks_with_meta(rec, trace_expanding_policy, trace_uncovered_mode)
    )
    return due_mask, sdc_mask, policy_added_sdc_mask


def final_due_sdc_masks_with_meta_fast(
    rec: FastMaskRecord,
    trace_expanding_policy: str,
    trace_uncovered_mode: str = "legacy_unknown",
) -> Tuple[int, int, int, int, int, int, int]:
    return final_due_sdc_masks_with_meta_fast_extended(
        rec=rec,
        trace_expanding_policy=trace_expanding_policy,
        trace_uncovered_mode=trace_uncovered_mode,
    )


def final_due_sdc_masks_with_meta_fast_extended(
    rec: FastMaskRecord,
    trace_expanding_policy: str,
    trace_uncovered_mode: str = "legacy_unknown",
    trace_expanding_resolution_mode: str = "legacy",
) -> Tuple[int, int, int, int, int, int, int]:
    src_w, obs, due, trace = rec
    wmask = width_mask(int(src_w))
    trace &= wmask
    obs &= wmask
    due &= wmask
    proof_due_trace = trace & due
    proof_sdc_trace = trace & obs & ((~proof_due_trace) & MASK64)
    trace_unresolved = trace & ((~proof_due_trace) & MASK64) & ((~proof_sdc_trace) & MASK64)
    policy_used_mask, policy_sdc_mask, policy_unknown_mask = _trace_policy_for_unresolved_bits(
        trace_unresolved,
        wmask=wmask,
        trace_expanding_policy=trace_expanding_policy,
        trace_uncovered_mode=trace_uncovered_mode,
    )
    inv_trace = (~trace) & wmask
    unknown_final = policy_unknown_mask
    due_final = proof_due_trace | (inv_trace & due)
    sdc_masked_baseline = proof_sdc_trace | (inv_trace & obs)
    sdc_final = sdc_masked_baseline | policy_sdc_mask
    due_final &= wmask
    sdc_final &= wmask
    unknown_final &= wmask
    due_final &= ~unknown_final
    sdc_final &= ~unknown_final
    sdc_final &= ~due_final
    sdc_masked_baseline &= wmask
    sdc_masked_baseline &= ~due_final
    sdc_masked_baseline &= ~unknown_final
    policy_added_sdc_mask = sdc_final & (~sdc_masked_baseline & MASK64)
    return (
        due_final & MASK64,
        sdc_final & MASK64,
        unknown_final & MASK64,
        policy_added_sdc_mask & MASK64,
        policy_used_mask & MASK64,
        trace & MASK64,
        0,
    )


_BYTE_POPCOUNT = tuple(bin(i).count("1") for i in range(256))


def popcount_u64(x: int) -> int:
    v = int(x) & MASK64
    if hasattr(v, "bit_count"):
        return v.bit_count()  # type: ignore[attr-defined]
    return (
        _BYTE_POPCOUNT[v & 0xFF]
        + _BYTE_POPCOUNT[(v >> 8) & 0xFF]
        + _BYTE_POPCOUNT[(v >> 16) & 0xFF]
        + _BYTE_POPCOUNT[(v >> 24) & 0xFF]
        + _BYTE_POPCOUNT[(v >> 32) & 0xFF]
        + _BYTE_POPCOUNT[(v >> 40) & 0xFF]
        + _BYTE_POPCOUNT[(v >> 48) & 0xFF]
        + _BYTE_POPCOUNT[(v >> 56) & 0xFF]
    )


_RF_INTERVAL_ACCUM_FIELDS = (
    "masked_num",
    "sdc_num",
    "due_num",
    "unknown_num",
    "trace_due_mass",
    "addr_due_num",
    "addr_sdc_num",
    "addr_unknown_num",
    "addr_oob_due_mass",
    "trace_divergence_due_mass",
    "addr_alias_sdc_mass",
    "trace_divergence_sdc_mass",
    "trace_expanding_sdc_numerator",
    "trace_policy_used_bits",
    "trace_policy_used_mass",
    "trace_policy_override_bits",
    "trace_policy_override_mass",
    "trace_policy_override_sdc_bits",
    "trace_policy_override_due_bits",
    "trace_policy_override_unknown_bits",
    "trace_policy_override_masked_bits",
    "trace_uncovered_unknown_bits",
    "trace_uncovered_unknown_mass",
)


def _empty_rf_interval_accum() -> Dict[str, int]:
    out = {field: 0 for field in _RF_INTERVAL_ACCUM_FIELDS}
    out["saw_trace_selected_bits"] = 0
    return out


def _python_rf_interval_accumulate_many(
    requests: Sequence[Mapping[str, Any]],
) -> Dict[str, int]:
    out = _empty_rf_interval_accum()
    for req in requests:
        mass = int(req.get("mass", 0))
        if mass <= 0:
            continue
        bit_count = int(req.get("bit_count", 0))
        selected = int(req.get("selected_mask", 0)) & MASK64
        due_mask = int(req.get("due_mask", 0)) & MASK64
        sdc_mask = int(req.get("sdc_mask", 0)) & MASK64
        unknown_mask = int(req.get("unknown_mask", 0)) & MASK64
        trace_added_sdc_mask = (
            int(req.get("trace_added_sdc_mask", 0)) & int(sdc_mask) & MASK64
        )
        trace_policy_used_mask = int(req.get("trace_policy_used_mask", 0)) & MASK64
        trace_policy_override_mask = (
            int(req.get("trace_policy_override_mask", 0)) & MASK64
        )
        trace_mask = int(req.get("trace_mask", 0)) & MASK64
        semantic_due_mask = int(req.get("semantic_due_mask", 0)) & MASK64
        addr_due_mask = int(req.get("addr_due_mask", 0)) & MASK64
        addr_sdc_mask = int(req.get("addr_sdc_mask", 0)) & MASK64
        addr_unknown_mask = int(req.get("addr_unknown_mask", 0)) & MASK64
        addr_trace_div_mask = int(req.get("addr_trace_div_mask", 0)) & MASK64

        due_bits = popcount_u64(due_mask & selected)
        sdc_bits = popcount_u64(sdc_mask & selected)
        unknown_bits = popcount_u64(unknown_mask & selected)
        trace_added_sdc_bits = popcount_u64(trace_added_sdc_mask & selected)
        trace_policy_used_bits = popcount_u64(trace_policy_used_mask & selected)
        trace_policy_override_bits = popcount_u64(
            trace_policy_override_mask & selected
        )
        trace_policy_override_sdc_bits = popcount_u64(
            (trace_policy_override_mask & sdc_mask) & selected
        )
        trace_policy_override_due_bits = popcount_u64(
            (trace_policy_override_mask & due_mask) & selected
        )
        trace_policy_override_unknown_bits = popcount_u64(
            (trace_policy_override_mask & unknown_mask) & selected
        )
        trace_policy_override_masked_bits = max(
            0,
            int(trace_policy_override_bits)
            - int(trace_policy_override_sdc_bits)
            - int(trace_policy_override_due_bits)
            - int(trace_policy_override_unknown_bits),
        )
        trace_selected_bits = popcount_u64(trace_mask & selected)
        semantic_due_bits = popcount_u64(semantic_due_mask & selected)
        addr_trace_div_due_mask = addr_trace_div_mask & addr_due_mask & MASK64
        addr_trace_div_sdc_mask = addr_trace_div_mask & addr_sdc_mask & MASK64
        addr_oob_due_mask = addr_due_mask & (~addr_trace_div_due_mask) & MASK64
        addr_alias_sdc_mask = addr_sdc_mask & (~addr_trace_div_sdc_mask) & MASK64
        addr_due_bits = popcount_u64(addr_due_mask & selected)
        addr_sdc_bits = popcount_u64(addr_sdc_mask & selected)
        addr_unknown_bits = popcount_u64((addr_unknown_mask & unknown_mask) & selected)
        addr_oob_due_bits = popcount_u64(addr_oob_due_mask & selected)
        addr_trace_div_due_bits = popcount_u64(addr_trace_div_due_mask & selected)
        addr_alias_sdc_bits = popcount_u64(addr_alias_sdc_mask & selected)
        addr_trace_div_sdc_bits = popcount_u64(addr_trace_div_sdc_mask & selected)
        if trace_selected_bits > 0:
            out["saw_trace_selected_bits"] = 1

        masked_bits = int(bit_count) - due_bits - sdc_bits - unknown_bits
        out["masked_num"] += int(mass) * int(masked_bits)
        out["sdc_num"] += int(mass) * int(sdc_bits)
        out["due_num"] += int(mass) * int(due_bits)
        out["unknown_num"] += int(mass) * int(unknown_bits)
        out["trace_due_mass"] += int(mass) * int(semantic_due_bits)
        out["addr_due_num"] += int(mass) * int(addr_due_bits)
        out["addr_sdc_num"] += int(mass) * int(addr_sdc_bits)
        out["addr_unknown_num"] += int(mass) * int(addr_unknown_bits)
        out["addr_oob_due_mass"] += int(mass) * int(addr_oob_due_bits)
        out["trace_divergence_due_mass"] += int(mass) * int(
            addr_trace_div_due_bits
        )
        out["addr_alias_sdc_mass"] += int(mass) * int(addr_alias_sdc_bits)
        out["trace_divergence_sdc_mass"] += int(mass) * int(
            addr_trace_div_sdc_bits
        )
        out["trace_expanding_sdc_numerator"] += int(mass) * int(
            trace_added_sdc_bits
        )
        out["trace_policy_used_bits"] += int(trace_policy_used_bits)
        out["trace_policy_used_mass"] += int(mass) * int(trace_policy_used_bits)
        out["trace_policy_override_bits"] += int(trace_policy_override_bits)
        out["trace_policy_override_mass"] += int(mass) * int(
            trace_policy_override_bits
        )
        out["trace_policy_override_sdc_bits"] += int(trace_policy_override_sdc_bits)
        out["trace_policy_override_due_bits"] += int(trace_policy_override_due_bits)
        out["trace_policy_override_unknown_bits"] += int(
            trace_policy_override_unknown_bits
        )
        out["trace_policy_override_masked_bits"] += int(
            trace_policy_override_masked_bits
        )
        if bool(req.get("legacy_unknown_trace_uncovered", False)):
            out["trace_uncovered_unknown_bits"] += int(trace_policy_used_bits)
            out["trace_uncovered_unknown_mass"] += int(mass) * int(
                trace_policy_used_bits
            )
    return out


def _cpp_rf_interval_accumulate_many(
    requests: Sequence[Mapping[str, Any]],
) -> Optional[Dict[str, int]]:
    global _CPP_RF_INTERVAL_ACCUM_FAILED
    if (
        not requests
        or not _CPP_RF_INTERVAL_ACCUM_ENABLED
        or _CPP_RF_INTERVAL_ACCUM_FAILED
    ):
        return None
    try:
        accum = exact_cpp_backend.rf_interval_accumulate_many(  # type: ignore[attr-defined]
            list(dict(req) for req in requests)
        )
    except Exception:
        _CPP_RF_INTERVAL_ACCUM_FAILED = True
        return None
    if not isinstance(accum, dict):
        return None
    return {str(k): int(v) for k, v in accum.items()}


def final_due_sdc_masks_for_site(
    rec: Dict[str, Any],
    trace_expanding_policy: str,
    trace_uncovered_mode: str = "legacy_unknown",
) -> Tuple[int, int, int, int, int]:
    return final_due_sdc_masks_for_site_extended(
        rec=rec,
        trace_expanding_policy=trace_expanding_policy,
        trace_uncovered_mode=trace_uncovered_mode,
    )


def final_due_sdc_masks_for_site_extended(
    rec: Any,
    trace_expanding_policy: str,
    trace_uncovered_mode: str = "legacy_unknown",
    trace_expanding_resolution_mode: str = "legacy",
) -> Tuple[int, int, int, int, int]:
    if trace_expanding_policy != CANONICAL_TRACE_EXPANDING_POLICY:
        raise ValueError(f"invalid trace_expanding_policy={trace_expanding_policy!r}")
    width_bits = max(0, min(64, int(_cache_site_row_field(rec, "width_bits", 8))))
    wmask = width_mask(width_bits)
    obs = parse_mask(_cache_site_row_field(rec, "observed_mask_this_site", 0)) & wmask
    due = parse_mask(_cache_site_row_field(rec, "due_mask_this_site", 0)) & wmask
    trace = parse_mask(_cache_site_row_field(rec, "trace_expanding_mask_this_site", 0)) & wmask
    proof_due_trace = trace & due
    proof_sdc_trace = trace & obs & ((~proof_due_trace) & MASK64)
    trace_unresolved = trace & ((~proof_due_trace) & MASK64) & ((~proof_sdc_trace) & MASK64)
    policy_used_mask, policy_sdc_mask, policy_unknown_mask = _trace_policy_for_unresolved_bits(
        trace_unresolved,
        wmask=wmask,
        trace_expanding_policy=trace_expanding_policy,
        trace_uncovered_mode=trace_uncovered_mode,
    )
    inv_trace = (~trace) & wmask
    due_final = proof_due_trace | (inv_trace & due)
    sdc_final = proof_sdc_trace | (inv_trace & obs) | policy_sdc_mask
    unknown_final = policy_unknown_mask
    due_final &= wmask
    sdc_final &= wmask
    unknown_final &= wmask
    due_final &= ~unknown_final
    sdc_final &= ~unknown_final
    sdc_final &= ~due_final
    return (
        due_final & MASK64,
        sdc_final & MASK64,
        unknown_final & MASK64,
        policy_used_mask & MASK64,
        0,
    )


def merge_classification_record(
    existing: Optional[Dict[str, Any]],
    incoming: Dict[str, Any],
) -> Dict[str, Any]:
    if existing is None:
        out = dict(incoming)
        out["event_index"] = int(out.get("event_index", 1 << 30))
        out["src_width_bits"] = int(out.get("src_width_bits", 0))
        for f in MASK_FIELDS:
            out[f] = parse_mask(out.get(f, 0))
        for f in DETAIL_MAP_FIELDS:
            raw = out.get(f)
            out[f] = dict(raw) if isinstance(raw, dict) else {}
        for f in DETAIL_SCALAR_FIELDS:
            out[f] = str(out.get(f, "") or "")
        return out

    out = dict(existing)
    out["event_index"] = min(
        int(existing.get("event_index", 1 << 30)),
        int(incoming.get("event_index", 1 << 30)),
    )
    out["src_width_bits"] = max(
        int(existing.get("src_width_bits", 0)),
        int(incoming.get("src_width_bits", 0)),
    )
    for f in MASK_FIELDS:
        out[f] = parse_mask(existing.get(f, 0)) | parse_mask(incoming.get(f, 0))
    for f in DETAIL_MAP_FIELDS:
        merged_map: Dict[str, Any] = {}
        ex = existing.get(f)
        inc = incoming.get(f)
        if isinstance(ex, dict):
            merged_map.update(ex)
        if isinstance(inc, dict):
            merged_map.update(inc)
        out[f] = merged_map
    for f in DETAIL_SCALAR_FIELDS:
        ex_val = str(existing.get(f, "") or "").strip()
        inc_val = str(incoming.get(f, "") or "").strip()
        out[f] = ex_val if ex_val else inc_val
    return out


def build_analyzer_indexes(
    analyzer_output: Dict[str, Any],
) -> Tuple[
    Dict[Tuple[int, int, int], Dict[str, Any]],
    Dict[Tuple[int, int, str], Dict[str, Any]],
    Dict[str, Set[int]],
]:
    read_events = analyzer_output.get("read_events", [])
    if not isinstance(read_events, list):
        raise ValueError("analyzer output missing read_events list")

    by_uid: Dict[Tuple[int, int, int], Dict[str, Any]] = {}
    by_name: Dict[Tuple[int, int, str], Dict[str, Any]] = {}
    reg_to_uids: Dict[str, Set[int]] = defaultdict(set)

    for rec in read_events:
        if not isinstance(rec, dict):
            continue
        if "cycle" not in rec:
            continue
        tid = int(rec.get("thread_id", -1))
        cycle = int(rec.get("cycle"))
        reg = str(rec.get("src_reg", ""))
        uid = int(rec.get("src_reg_uid", -1))

        k_name = (tid, cycle, reg)
        by_name[k_name] = merge_classification_record(by_name.get(k_name), rec)

        if uid >= 0:
            reg_to_uids[reg].add(uid)
            k_uid = (tid, cycle, uid)
            by_uid[k_uid] = merge_classification_record(by_uid.get(k_uid), rec)

    return by_uid, by_name, reg_to_uids


def _analyzer_mask_format(analyzer_output: Dict[str, Any]) -> str:
    meta = analyzer_output.get("exact_meta", {})
    if isinstance(meta, dict):
        raw = str(meta.get("analyzer_mask_format", "")).strip().lower()
        if raw in ("int", "hex"):
            return raw
    return "hex"


def _parse_mask_with_format(value: Any, mask_format: str) -> int:
    if mask_format == "int":
        return int(value) & MASK64
    return parse_mask(value)


def _normalize_fast_record(raw: Dict[str, Any], *, mask_format: str) -> FastMaskRecord:
    src_w = int(_read_event_row_field(raw, "src_width_bits", 64))
    if src_w < 0:
        src_w = 0
    elif src_w > 64:
        src_w = 64
    return (
        src_w,
        _parse_mask_with_format(_read_event_row_field(raw, "observed_mask_this_read", 0), mask_format),
        _parse_mask_with_format(_read_event_row_field(raw, "due_mask_this_read", 0), mask_format),
        _parse_mask_with_format(
            _read_event_row_field(raw, "trace_expanding_mask_this_read", 0), mask_format
        ),
    )


def _normalize_rf_consumer_record(
    raw: Any,
    *,
    mask_format: str,
) -> RFConsumerRecord:
    src_w, obs, due, trace = _normalize_fast_record(raw, mask_format=mask_format)
    return (
        int(src_w),
        int(obs),
        int(due),
        int(trace),
        int(_read_event_row_field(raw, "event_index", -1)),
        int(_read_event_row_field(raw, "src_index", -1)),
        int(_rf_read_kind_code(_read_event_row_field(raw, "read_kind", ""))),
        int(
            _parse_mask_with_format(
                _read_event_row_field(raw, ADDR_STATIC_DUE_MASK_FIELD, 0),
                mask_format,
            )
        )
        & MASK64,
    )


def _decode_rf_read_event_for_indexes(
    raw: Any,
    *,
    mask_format: str,
) -> Optional[
    Tuple[int, int, str, int, FastMaskRecord, int, int, int, int]
]:
    if isinstance(raw, dict):
        cycle_raw = raw.get("cycle")
        if cycle_raw is None:
            return None
        tid = int(raw.get("thread_id", -1))
        cycle = int(cycle_raw)
        reg = str(raw.get("src_reg", ""))
        uid = int(raw.get("src_reg_uid", -1))
        packed = _normalize_fast_record(raw, mask_format=mask_format)
        event_index = int(raw.get("event_index", -1))
        src_index = int(raw.get("src_index", -1))
        read_kind_code = _rf_read_kind_code(raw.get("read_kind", ""))
        addr_due_mask = _parse_mask_with_format(
            raw.get(ADDR_STATIC_DUE_MASK_FIELD, 0),
            mask_format,
        )
        if addr_due_mask == 0 and read_kind_code == RF_READ_KIND_ADDR:
            addr_due_mask = int(packed[2]) & MASK64
        return (
            int(tid),
            int(cycle),
            str(reg),
            int(uid),
            packed,
            int(event_index),
            int(src_index),
            int(read_kind_code),
            int(addr_due_mask) & MASK64,
        )

    if not _is_compact_read_event_row(raw):
        return None

    try:
        cycle = int(raw[2])
    except Exception:
        return None
    try:
        src_w = int(raw[7])
    except Exception:
        src_w = 64
    if src_w < 0:
        src_w = 0
    elif src_w > 64:
        src_w = 64
    packed: FastMaskRecord = (
        int(src_w),
        _parse_mask_with_format(raw[8], mask_format),
        _parse_mask_with_format(raw[9], mask_format),
        _parse_mask_with_format(raw[11], mask_format),
    )
    read_kind_code = _rf_read_kind_code(raw[3])
    addr_due_mask = _parse_mask_with_format(raw[10], mask_format)
    if addr_due_mask == 0 and read_kind_code == RF_READ_KIND_ADDR:
        addr_due_mask = int(packed[2]) & MASK64
    return (
        int(raw[1]),
        int(cycle),
        str(raw[5]),
        int(raw[6]),
        packed,
        int(raw[0]),
        int(raw[4]),
        int(read_kind_code),
        int(addr_due_mask) & MASK64,
    )


def _merge_fast_record(
    existing: Optional[FastMaskRecord],
    incoming: FastMaskRecord,
) -> FastMaskRecord:
    if existing is None:
        return incoming
    return (
        max(int(existing[0]), int(incoming[0])),
        int(existing[1]) | int(incoming[1]),
        int(existing[2]) | int(incoming[2]),
        int(existing[3]) | int(incoming[3]),
    )


def build_fast_analyzer_indexes(
    analyzer_output: Dict[str, Any],
) -> Tuple[
    Dict[Tuple[int, int, int], FastMaskRecord],
    Dict[Tuple[int, int, str], FastMaskRecord],
    Dict[str, Set[int]],
]:
    by_uid, by_name, reg_to_uids, _addr_due_uid, _addr_due_name = (
        build_fast_rf_analyzer_indexes(analyzer_output)
    )
    return by_uid, by_name, reg_to_uids


def build_fast_rf_analyzer_indexes(
    analyzer_output: Dict[str, Any],
) -> Tuple[
    Dict[Tuple[int, int, int], FastMaskRecord],
    Dict[Tuple[int, int, str], FastMaskRecord],
    Dict[str, Set[int]],
    Dict[Tuple[int, int, int], int],
    Dict[Tuple[int, int, str], int],
]:
    (
        by_uid,
        by_name,
        reg_to_uids,
        addr_static_due_by_uid,
        addr_static_due_by_name,
        _consumer_by_uid,
        _consumer_by_name,
    ) = build_fast_rf_indexes(analyzer_output)
    return (
        by_uid,
        by_name,
        reg_to_uids,
        addr_static_due_by_uid,
        addr_static_due_by_name,
    )


def build_fast_rf_indexes(
    analyzer_output: Dict[str, Any],
) -> Tuple[
    Dict[Tuple[int, int, int], FastMaskRecord],
    Dict[Tuple[int, int, str], FastMaskRecord],
    Dict[str, Set[int]],
    Dict[Tuple[int, int, int], int],
    Dict[Tuple[int, int, str], int],
    Dict[Tuple[int, int, int], List[RFConsumerRecord]],
    Dict[Tuple[int, int, str], List[RFConsumerRecord]],
]:
    read_events = analyzer_output.get("read_events", [])
    if not isinstance(read_events, list):
        raise ValueError("analyzer output missing read_events list")

    mask_format = _analyzer_mask_format(analyzer_output)
    by_uid: Dict[Tuple[int, int, int], FastMaskRecord] = {}
    by_name: Dict[Tuple[int, int, str], FastMaskRecord] = {}
    reg_to_uids: Dict[str, Set[int]] = defaultdict(set)
    addr_static_due_by_uid: Dict[Tuple[int, int, int], int] = {}
    addr_static_due_by_name: Dict[Tuple[int, int, str], int] = {}
    consumer_by_uid: Dict[Tuple[int, int, int], List[RFConsumerRecord]] = defaultdict(list)
    consumer_by_name: Dict[Tuple[int, int, str], List[RFConsumerRecord]] = defaultdict(list)
    saw_kind = False

    for rec in read_events:
        decoded = _decode_rf_read_event_for_indexes(rec, mask_format=mask_format)
        if decoded is None:
            continue
        (
            tid,
            cycle,
            reg,
            uid,
            packed,
            event_index,
            src_index,
            read_kind_code,
            addr_due_mask,
        ) = decoded

        k_name = (tid, cycle, reg)
        by_name[k_name] = _merge_fast_record(by_name.get(k_name), packed)

        if addr_due_mask != 0:
            addr_static_due_by_name[k_name] = int(
                addr_static_due_by_name.get(k_name, 0)
            ) | int(addr_due_mask)

        consumer_rec: RFConsumerRecord = (
            int(packed[0]),
            int(packed[1]),
            int(packed[2]),
            int(packed[3]),
            int(event_index),
            int(src_index),
            int(read_kind_code),
            int(addr_due_mask) & MASK64,
        )
        saw_kind = saw_kind or int(read_kind_code) != RF_READ_KIND_UNKNOWN
        consumer_by_name[k_name].append(consumer_rec)

        if uid >= 0:
            reg_to_uids[reg].add(uid)
            k_uid = (tid, cycle, uid)
            by_uid[k_uid] = _merge_fast_record(by_uid.get(k_uid), packed)
            consumer_by_uid[k_uid].append(consumer_rec)
            if addr_due_mask != 0:
                addr_static_due_by_uid[k_uid] = int(
                    addr_static_due_by_uid.get(k_uid, 0)
                ) | int(addr_due_mask)
    return (
        by_uid,
        by_name,
        reg_to_uids,
        addr_static_due_by_uid,
        addr_static_due_by_name,
        dict(consumer_by_uid) if saw_kind else {},
        dict(consumer_by_name) if saw_kind else {},
    )


def build_fast_rf_consumer_indexes(
    analyzer_output: Dict[str, Any],
) -> Tuple[
    Dict[Tuple[int, int, int], List[RFConsumerRecord]],
    Dict[Tuple[int, int, str], List[RFConsumerRecord]],
]:
    (
        _by_uid,
        _by_name,
        _reg_to_uids,
        _addr_due_by_uid,
        _addr_due_by_name,
        consumer_by_uid,
        consumer_by_name,
    ) = build_fast_rf_indexes(analyzer_output)
    return consumer_by_uid, consumer_by_name


def build_rf_address_static_due_indexes(
    analyzer_output: Dict[str, Any],
) -> Tuple[
    Dict[Tuple[int, int, int], int],
    Dict[Tuple[int, int, str], int],
]:
    _by_uid, _by_name, _reg_to_uids, addr_due_by_uid, addr_due_by_name = (
        build_fast_rf_analyzer_indexes(analyzer_output)
    )
    return addr_due_by_uid, addr_due_by_name


@lru_cache(maxsize=None)
def _load_fast_rf_analyzer_indexes_cached(
    analyzer_path_key: str,
    normalize_trace_coverage: bool,
) -> Tuple[
    Dict[Tuple[int, int, int], FastMaskRecord],
    Dict[Tuple[int, int, str], FastMaskRecord],
    Dict[str, Set[int]],
    Dict[Tuple[int, int, int], int],
    Dict[Tuple[int, int, str], int],
]:
    (
        by_uid,
        by_name,
        reg_to_uids,
        addr_due_by_uid,
        addr_due_by_name,
        _consumer_by_uid,
        _consumer_by_name,
    ) = _load_fast_rf_indexes_cached(
        str(analyzer_path_key),
        bool(normalize_trace_coverage),
    )
    return by_uid, by_name, reg_to_uids, addr_due_by_uid, addr_due_by_name


@lru_cache(maxsize=None)
def _load_fast_rf_consumer_indexes_cached(
    analyzer_path_key: str,
    normalize_trace_coverage: bool,
) -> Tuple[
    Dict[Tuple[int, int, int], List[RFConsumerRecord]],
    Dict[Tuple[int, int, str], List[RFConsumerRecord]],
]:
    (
        _by_uid,
        _by_name,
        _reg_to_uids,
        _addr_due_by_uid,
        _addr_due_by_name,
        consumer_by_uid,
        consumer_by_name,
    ) = _load_fast_rf_indexes_cached(
        str(analyzer_path_key),
        bool(normalize_trace_coverage),
    )
    return consumer_by_uid, consumer_by_name


@lru_cache(maxsize=None)
def _load_fast_rf_indexes_cached(
    analyzer_path_key: str,
    normalize_trace_coverage: bool = False,
) -> Tuple[
    Dict[Tuple[int, int, int], FastMaskRecord],
    Dict[Tuple[int, int, str], FastMaskRecord],
    Dict[str, Set[int]],
    Dict[Tuple[int, int, int], int],
    Dict[Tuple[int, int, str], int],
    Dict[Tuple[int, int, int], List[RFConsumerRecord]],
    Dict[Tuple[int, int, str], List[RFConsumerRecord]],
]:
    analyzer_any = _load_analyzer_output_for_compute_cached(
        str(analyzer_path_key),
        bool(normalize_trace_coverage),
    )
    if not isinstance(analyzer_any, dict):
        raise ValueError("analyzer output must be a JSON object")
    return build_fast_rf_indexes(analyzer_any)


def build_thread_cycle_prefix(
    thread_cycle_weights: Dict[int, Dict[int, int]]
) -> Dict[int, Tuple[List[int], List[int], int]]:
    if isinstance(thread_cycle_weights, ThreadCycleWeightsDict):
        cached_prefix = getattr(thread_cycle_weights, "_thread_prefix", None)
        if cached_prefix is not None:
            return cached_prefix
        sorted_entries = getattr(thread_cycle_weights, "_sorted_entries", None)
        if sorted_entries:
            out: Dict[int, Tuple[List[int], List[int], int]] = {}
            current_tid: Optional[int] = None
            cycles: List[int] = []
            prefix: List[int] = [0]
            total = 0
            for tid, cycle, weight in sorted_entries:
                if current_tid is None:
                    current_tid = int(tid)
                if int(tid) != int(current_tid):
                    out[int(current_tid)] = (cycles, prefix, int(total))
                    current_tid = int(tid)
                    cycles = []
                    prefix = [0]
                    total = 0
                cycles.append(int(cycle))
                total += int(weight)
                prefix.append(int(total))
            if current_tid is not None:
                out[int(current_tid)] = (cycles, prefix, int(total))
            thread_cycle_weights._thread_prefix = out
            return out
    out: Dict[int, Tuple[List[int], List[int], int]] = {}
    for tid, per_cycle in thread_cycle_weights.items():
        items = sorted(per_cycle.items())
        cycles = [c for c, _w in items]
        prefix = [0]
        total = 0
        for _c, w in items:
            total += int(w)
            prefix.append(total)
        out[tid] = (cycles, prefix, total)
    if isinstance(thread_cycle_weights, ThreadCycleWeightsDict):
        thread_cycle_weights._thread_prefix = out
    return out


def range_sum(cycles: List[int], prefix: List[int], lo: int, hi: int) -> int:
    i = bisect.bisect_left(cycles, lo)
    j = bisect.bisect_left(cycles, hi)
    return prefix[j] - prefix[i]


def _active_thread_count_segments_for_prefix(
    ids: Sequence[int],
    domain_size: int,
    multiplicity: int,
) -> Optional[List[Tuple[int, int, int]]]:
    """Return sorted [tid_lo, tid_hi) segments with equal per-cycle seed mass.

    ``_thread_cycle_weights`` needs per-thread cycle prefix rows for RF exact
    accounting.  The old fallback expanded every active thread in every cycle.
    Simulator sidecars are already range-compressed, so preserve that columnar
    shape here: a cycle contributes at most one normal-count segment plus one
    modulo-bias segment per active run instead of one row per thread.
    """

    active_size = len(ids)
    if active_size <= 0:
        return []
    domain_size_i = int(domain_size)
    if domain_size_i <= 0:
        return None
    q, r = divmod(domain_size_i, int(active_size))

    ranges: List[Tuple[int, int]] = []
    if isinstance(ids, range) and int(ids.step) == 1:
        ranges = [(int(ids.start), int(ids.stop))]
    elif isinstance(ids, ThreadIdRanges):
        ranges = [(int(start), int(stop)) for start, stop in ids.ranges]
    else:
        # Fallback only for reasonably small legacy tuples/lists.  Large active
        # sets should arrive as range/ThreadIdRanges; expanding them here would
        # recreate the old hot path.
        if int(active_size) > 4096:
            return None
        start_tid: Optional[int] = None
        prev_tid: Optional[int] = None
        for tid_raw in ids:
            tid = int(tid_raw)
            if start_tid is None or prev_tid is None:
                start_tid = tid
                prev_tid = tid
            elif tid == int(prev_tid) + 1:
                prev_tid = tid
            else:
                ranges.append((int(start_tid), int(prev_tid) + 1))
                start_tid = tid
                prev_tid = tid
        if start_tid is not None and prev_tid is not None:
            ranges.append((int(start_tid), int(prev_tid) + 1))

    segments: List[Tuple[int, int, int]] = []
    slot_base = 0
    multiplicity_i = int(multiplicity)
    for start_raw, stop_raw in ranges:
        start = int(start_raw)
        stop = int(stop_raw)
        run_len = int(stop) - int(start)
        if run_len <= 0:
            continue

        # The first ``r`` active slots get q+1 seeds due to rand % active_size.
        biased_len = min(run_len, max(0, int(r) - int(slot_base)))
        if biased_len > 0 and q + 1 > 0:
            segments.append(
                (int(start), int(start) + int(biased_len), multiplicity_i * (int(q) + 1))
            )

        normal_start = max(0, int(r) - int(slot_base))
        if normal_start < run_len and q > 0:
            segments.append(
                (int(start) + int(normal_start), int(stop), multiplicity_i * int(q))
            )
        slot_base += int(run_len)

    if not segments:
        return []
    segments.sort(key=lambda row: (int(row[0]), int(row[1]), int(row[2])))
    merged: List[Tuple[int, int, int]] = []
    for lo_raw, hi_raw, weight_raw in segments:
        lo = int(lo_raw)
        hi = int(hi_raw)
        weight = int(weight_raw)
        if hi <= lo or weight <= 0:
            continue
        if merged and int(merged[-1][1]) == lo and int(merged[-1][2]) == weight:
            merged[-1] = (int(merged[-1][0]), hi, weight)
        else:
            merged.append((lo, hi, weight))
    return merged


def _thread_cycle_weights_range_refined_prefix(
    cycle_records: Sequence[CycleRecord],
    include_thread_ids: Set[int],
    thread_rand_max: Optional[int],
    total_cycle_lines: int,
) -> Optional[Tuple[ThreadCycleWeightsDict, int, int, int]]:
    """Build RF thread prefixes by refining tid intervals instead of expanding.

    For storage workloads the active-thread sidecar is mostly large contiguous
    ranges.  A per-cycle active range often covers tens of thousands of tids,
    but only creates a handful of count segments.  This routine incrementally
    refines contiguous tid partitions and attaches schedule nodes to whole
    intervals.  Identical schedules are materialized once and shared by all
    tids in the final partition.
    """

    if not include_thread_ids:
        return None
    if thread_rand_max is None or int(thread_rand_max) <= 0:
        return None
    min_tid = min(int(v) for v in include_thread_ids)
    max_tid = max(int(v) for v in include_thread_ids)
    if max_tid < min_tid:
        return None
    # The interval-refinement representation is most effective and simplest
    # when the RF read-thread domain is dense, which is the common FI setting.
    if len(include_thread_ids) != int(max_tid) - int(min_tid) + 1:
        return None

    domain_size = int(thread_rand_max)
    partitions: List[Tuple[int, int, int]] = [(int(min_tid), int(max_tid) + 1, 0)]
    # schedule node id -> (previous node id, cycle, weight)
    schedule_nodes: List[Optional[Tuple[int, int, int]]] = [None]
    extend_cache: Dict[Tuple[int, int, int], int] = {}
    inactive_base_mass = 0

    def extend_schedule(schedule_id: int, cycle: int, weight: int) -> int:
        key = (int(schedule_id), int(cycle), int(weight))
        cached = extend_cache.get(key)
        if cached is not None:
            return int(cached)
        schedule_nodes.append((int(schedule_id), int(cycle), int(weight)))
        new_id = len(schedule_nodes) - 1
        extend_cache[key] = int(new_id)
        return int(new_id)

    def append_partition(
        out: List[Tuple[int, int, int]],
        lo: int,
        hi: int,
        schedule_id: int,
    ) -> None:
        if int(hi) <= int(lo):
            return
        if out and int(out[-1][1]) == int(lo) and int(out[-1][2]) == int(schedule_id):
            out[-1] = (int(out[-1][0]), int(hi), int(schedule_id))
        else:
            out.append((int(lo), int(hi), int(schedule_id)))

    for rec in cycle_records:
        multiplicity = int(rec.multiplicity)
        active_ids = rec.active_thread_ids
        active_size = len(active_ids)
        if active_size <= 0:
            inactive_base_mass += int(multiplicity) * int(domain_size)
            continue
        segments = _active_thread_count_segments_for_prefix(
            active_ids,
            int(domain_size),
            int(multiplicity),
        )
        if segments is None:
            return None
        if not segments:
            continue

        new_partitions: List[Tuple[int, int, int]] = []
        seg_idx = 0
        cycle_i = int(rec.cycle)
        for part_lo, part_hi, schedule_id in partitions:
            cursor = int(part_lo)
            while seg_idx < len(segments) and int(segments[seg_idx][1]) <= int(part_lo):
                seg_idx += 1
            scan_idx = seg_idx
            while cursor < int(part_hi):
                if scan_idx >= len(segments) or int(segments[scan_idx][0]) >= int(part_hi):
                    append_partition(new_partitions, cursor, int(part_hi), int(schedule_id))
                    cursor = int(part_hi)
                    break

                seg_lo, seg_hi, weight = segments[scan_idx]
                seg_lo = int(seg_lo)
                seg_hi = int(seg_hi)
                weight = int(weight)
                if cursor < seg_lo:
                    gap_hi = min(int(part_hi), seg_lo)
                    append_partition(new_partitions, cursor, gap_hi, int(schedule_id))
                    cursor = int(gap_hi)
                    if cursor >= int(part_hi):
                        break
                if seg_hi <= cursor:
                    scan_idx += 1
                    continue

                overlap_hi = min(int(part_hi), seg_hi)
                append_partition(
                    new_partitions,
                    cursor,
                    overlap_hi,
                    extend_schedule(int(schedule_id), cycle_i, weight),
                )
                cursor = int(overlap_hi)
                if cursor >= seg_hi:
                    scan_idx += 1
        partitions = new_partitions

    row_cache: Dict[int, Tuple[List[int], List[int], int]] = {}

    def materialize_row(schedule_id: int) -> Tuple[List[int], List[int], int]:
        cached = row_cache.get(int(schedule_id))
        if cached is not None:
            return cached
        entries: List[Tuple[int, int]] = []
        cursor = int(schedule_id)
        while cursor:
            node = schedule_nodes[cursor]
            if node is None:
                break
            prev_id, cycle_i, weight_i = node
            entries.append((int(cycle_i), int(weight_i)))
            cursor = int(prev_id)
        entries.reverse()
        if entries:
            monotonic = True
            prev_cycle_check = int(entries[0][0])
            for cycle_i, _weight_i in entries[1:]:
                if int(cycle_i) < int(prev_cycle_check):
                    monotonic = False
                    break
                prev_cycle_check = int(cycle_i)
            if not monotonic:
                per_cycle: Dict[int, int] = {}
                for cycle_i, weight_i in entries:
                    per_cycle[int(cycle_i)] = int(per_cycle.get(int(cycle_i), 0)) + int(
                        weight_i
                    )
                entries = sorted(per_cycle.items())

        cycles: List[int] = []
        prefix: List[int] = [0]
        total = 0
        prev_cycle: Optional[int] = None
        accum = 0
        for cycle_i, weight_i in entries:
            if prev_cycle is None:
                prev_cycle = int(cycle_i)
                accum = int(weight_i)
            elif int(cycle_i) == int(prev_cycle):
                accum += int(weight_i)
            else:
                cycles.append(int(prev_cycle))
                total += int(accum)
                prefix.append(int(total))
                prev_cycle = int(cycle_i)
                accum = int(weight_i)
        if prev_cycle is not None:
            cycles.append(int(prev_cycle))
            total += int(accum)
            prefix.append(int(total))
        row = (cycles, prefix, int(total))
        row_cache[int(schedule_id)] = row
        return row

    thread_prefix: Dict[int, Tuple[List[int], List[int], int]] = {}
    for lo, hi, schedule_id in partitions:
        row = materialize_row(int(schedule_id))
        if int(row[2]) <= 0:
            continue
        for tid in range(int(lo), int(hi)):
            thread_prefix[int(tid)] = row

    result = ThreadCycleWeightsDict()
    result._thread_prefix = thread_prefix
    base_denominator = int(total_cycle_lines) * int(domain_size)
    active_base_mass = int(base_denominator) - int(inactive_base_mass)
    return (
        result,
        int(domain_size),
        int(inactive_base_mass),
        int(active_base_mass),
    )


def slot_counts_for_cycle(
    active_size: int,
    seed_values: Optional[List[int]],
    thread_rand_max: Optional[int],
) -> Tuple[Dict[int, int], int]:
    seed_values_key: Optional[Tuple[int, ...]] = None
    if seed_values is not None:
        seed_values_key = tuple(int(v) for v in seed_values)
    return _slot_counts_for_cycle_cached(
        int(active_size),
        seed_values_key,
        None if thread_rand_max is None else int(thread_rand_max),
    )


@lru_cache(maxsize=512)
def _slot_counts_for_cycle_cached(
    active_size: int,
    seed_values_key: Optional[Tuple[int, ...]],
    thread_rand_max: Optional[int],
) -> Tuple[Dict[int, int], int]:
    if active_size <= 0:
        if seed_values_key is not None:
            return {}, len(seed_values_key)
        if thread_rand_max is None or thread_rand_max <= 0:
            raise ValueError("thread_rand_max must be > 0 when --thread-rands is not set")
        return {}, int(thread_rand_max)

    if seed_values_key is not None:
        counts: Counter = Counter()
        for s in seed_values_key:
            counts[s % active_size] += 1
        return dict(counts), len(seed_values_key)

    if thread_rand_max is None or thread_rand_max <= 0:
        raise ValueError("thread_rand_max must be > 0 when --thread-rands is not set")
    # FI uses `rand % active_size`. When the random domain [0, rand_max-1]
    # is not divisible by `active_size`, modulo introduces a deterministic
    # bias: the first `r` slots get `q+1`, others get `q`, where
    # `q, r = divmod(rand_max, active_size)`.
    q, r = divmod(int(thread_rand_max), active_size)
    out = {slot: (q + (1 if slot < r else 0)) for slot in range(active_size)}
    return out, int(thread_rand_max)


def normalize_mem_space(space_raw: Any) -> Optional[str]:
    if space_raw is None:
        return None
    s = str(space_raw).strip().lower().replace("-", "_")
    if not s:
        return None
    if s in ("global", "gmem", "global_mem", "globalmem"):
        return "global"
    if s in ("local", "lmem", "local_mem", "localmem"):
        return "local"
    if s in (
        "shared",
        "smem",
        "lds",
        "shared_mem",
        "sharedmem",
        "shmem",
    ):
        return "shared"
    if s in ("const", "constant", "const_mem", "constant_mem"):
        return "const"
    if "global" in s:
        return "global"
    if "local" in s:
        return "local"
    if "shared" in s or "smem" in s or "lds" in s:
        return "shared"
    if "const" in s:
        return "const"
    return None


def canonical_space(space_raw: Any) -> Optional[str]:
    return normalize_mem_space(space_raw)


def canonical_raw_event_space(raw: Dict[str, Any]) -> Optional[str]:
    opcode = str(raw.get("opcode", "")).strip().lower()
    if ".param" in opcode or opcode.startswith("ld.param") or opcode.startswith("st.param"):
        return "param"
    mem_space_raw = raw.get("mem_space")
    if mem_space_raw is None:
        mem_space_raw = raw.get("space")
    return canonical_space(mem_space_raw)


def access_size_bytes_for_raw_event(ev: Dict[str, Any]) -> int:
    kind = str(ev.get("kind", "")).strip().lower()
    if kind == "store":
        if ev.get("store_size_bytes") is not None:
            return max(1, int(ev.get("store_size_bytes")))
        if ev.get("mem_access_size_bytes") is not None:
            return max(1, int(ev.get("mem_access_size_bytes")))
    elif kind == "load":
        if ev.get("mem_access_size_bytes") is not None:
            return max(1, int(ev.get("mem_access_size_bytes")))
    if ev.get("mem_access_size_bytes") is not None:
        return max(1, int(ev.get("mem_access_size_bytes")))
    if ev.get("width_bits") is not None:
        return max(1, (int(ev.get("width_bits")) + 7) // 8)
    return 1


def parse_trace_template(path: Path) -> Dict[str, Any]:
    return _parse_trace_template_cached(_path_cache_key(path))


def _template_ref_path(base_path: Path, ref_raw: Any) -> Path:
    ref = Path(str(ref_raw))
    if ref.is_absolute():
        return ref
    return base_path.parent / ref


def _load_binary_analyzer_input_manifest(base_path: Path, manifest: Dict[str, Any]) -> Any:
    fmt = str(manifest.get("binary_format", "")).strip().lower()
    if fmt != "pickle_dict_v1":
        raise ValueError(
            f"{base_path}: unsupported analyzer input binary_format={fmt!r}"
        )
    ref_raw = manifest.get("binary_ref")
    if ref_raw is None:
        raise ValueError(f"{base_path}: binary analyzer input manifest missing binary_ref")
    ref_path = _template_ref_path(base_path, ref_raw)
    with ref_path.open("rb") as fh:
        return pickle.load(fh)


def _load_columnar_analyzer_input_manifest(base_path: Path, manifest: Dict[str, Any]) -> Dict[str, Any]:
    fmt = str(manifest.get("columnar_format", "")).strip().lower()
    if fmt != "pickle_events_columnar_v1":
        raise ValueError(
            f"{base_path}: unsupported analyzer input columnar_format={fmt!r}"
        )
    ref_raw = manifest.get("columnar_ref")
    if ref_raw is None:
        raise ValueError(f"{base_path}: columnar analyzer input manifest missing columnar_ref")
    ref_path = _template_ref_path(base_path, ref_raw)
    with ref_path.open("rb") as fh:
        payload = pickle.load(fh)
    if not isinstance(payload, dict):
        raise ValueError(f"{ref_path}: columnar analyzer input must be an object")
    return payload


def _columnar_analyzer_input_to_event_dicts(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    if str(payload.get("format", "")).strip() != "exact_sdc_analyzer_events_columnar_v1":
        raise ValueError("unsupported analyzer input columnar payload")
    columns = payload.get("columns", {})
    if not isinstance(columns, dict):
        raise ValueError("columnar analyzer input missing columns")
    keys_raw = payload.get("keys")
    keys: List[str]
    if isinstance(keys_raw, list) and keys_raw:
        keys = [str(key) for key in keys_raw if str(key)]
    else:
        keys = [str(key) for key in columns.keys()]
    count = int(payload.get("count", 0))
    out: List[Dict[str, Any]] = []
    append = out.append
    column_items: List[Tuple[str, Any]] = [
        (key, columns.get(key))
        for key in keys
        if isinstance(columns.get(key), list)
    ]
    for idx in range(count):
        row: Dict[str, Any] = {}
        for key, col in column_items:
            if idx >= len(col):
                continue
            value = col[idx]
            if value is not None:
                row[key] = value
        append(row)
    return out


def _load_template_memory_ranges_ref(base_path: Path, ref_raw: Any) -> List[Dict[str, Any]]:
    ref_path = _template_ref_path(base_path, ref_raw)
    raw = _json_load_path(ref_path)
    if isinstance(raw, dict):
        if isinstance(raw.get("memory_ranges"), list):
            raw = raw.get("memory_ranges", [])
        elif isinstance(raw.get("ranges"), list):
            raw = raw.get("ranges", [])
    return list(raw) if isinstance(raw, list) else []


def _raw_event_memory_range_context(
    raw: Dict[str, Any],
    event_index: int,
) -> Optional[Tuple[str, int, int, Optional[int], Optional[int], Optional[int]]]:
    kind = str(raw.get("kind", "")).strip().lower()
    if kind not in ("load", "store"):
        return None
    cspace = canonical_space(raw.get("mem_space") or raw.get("space"))
    if cspace is None:
        return None
    addr_raw = raw.get("mem_addr", raw.get("base"))
    if addr_raw is None:
        return None
    try:
        addr = int(parse_int(addr_raw))
        size = int(access_size_bytes_for_raw_event(raw))
    except Exception:
        return None
    if size <= 0:
        return None

    def opt_int(name: str) -> Optional[int]:
        value = raw.get(name)
        if value is None:
            return None
        try:
            return int(value)
        except Exception:
            return None

    return (
        str(cspace),
        int(addr),
        int(size),
        opt_int("thread_id"),
        opt_int("cta_id"),
        opt_int("sm_id"),
    )



@lru_cache(maxsize=None)
def _parse_trace_template_cached(path_key: str) -> Dict[str, Any]:
    path = Path(path_key)
    raw = _json_load_path(path)
    output_spec_raw: Any = []
    if (
        isinstance(raw, dict)
        and raw.get("manifest_kind") == "exact_sdc_analyzer_input_binary_v1"
    ):
        manifest = raw
        memory_ranges_raw = list(manifest.get("memory_ranges", []) or [])
        output_spec_raw = manifest.get("output_spec", [])
        use_columnar = (
            str(os.environ.get("EXACT_SDC_TRACE_TEMPLATE_COLUMNAR", "1"))
            .strip()
            .lower()
            not in ("0", "false", "no", "off")
        )
        if use_columnar and manifest.get("columnar_ref") is not None:
            try:
                columnar_payload = _load_columnar_analyzer_input_manifest(path, manifest)
                raw = {
                    "events": _columnar_analyzer_input_to_event_dicts(columnar_payload),
                    "memory_ranges": memory_ranges_raw,
                    "output_spec": output_spec_raw,
                }
            except Exception as exc:
                if manifest.get("binary_ref") is None:
                    raise
                print(
                    f"[exact_sdc_compute] trace-template columnar fallback: {exc}",
                    file=sys.stderr,
                )
                raw = _load_binary_analyzer_input_manifest(path, manifest)
        else:
            raw = _load_binary_analyzer_input_manifest(path, manifest)
        if isinstance(raw, dict):
            output_spec_raw = output_spec_raw or raw.get("output_spec", [])
            if not memory_ranges_raw:
                memory_ranges_raw = raw.get("memory_ranges", [])
    elif isinstance(raw, dict) and (
        raw.get("manifest_kind") == "exact_sdc_analyzer_input_ref"
        or raw.get("trace_template_ref") is not None
        or raw.get("events_ref") is not None
    ):
        manifest = raw
        ref_raw = manifest.get("trace_template_ref", manifest.get("events_ref"))
        if ref_raw is None:
            raise ValueError(f"{path}: analyzer input manifest missing trace_template_ref")
        ref_path = _template_ref_path(path, ref_raw)
        raw = _json_load_path(ref_path)
        memory_ranges_raw: List[Any] = []
        if isinstance(raw, dict) and isinstance(raw.get("memory_ranges"), list):
            memory_ranges_raw.extend(list(raw.get("memory_ranges", [])))
        if manifest.get("memory_ranges_ref") is not None:
            memory_ranges_raw.extend(
                _load_template_memory_ranges_ref(path, manifest.get("memory_ranges_ref"))
            )
        if isinstance(manifest.get("memory_ranges"), list):
            memory_ranges_raw.extend(list(manifest.get("memory_ranges", [])))
        output_spec_raw = manifest.get("output_spec", [])
    else:
        memory_ranges_raw = []
        if isinstance(raw, dict):
            output_spec_raw = raw.get("output_spec", [])
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: trace template must be a JSON object")
    events_raw = raw.get("events")
    if not isinstance(events_raw, list):
        raise ValueError(f"{path}: trace template missing events list")
    if not memory_ranges_raw:
        memory_ranges_raw = raw.get("memory_ranges", [])
    if memory_ranges_raw is None:
        memory_ranges_raw = []
    if not isinstance(memory_ranges_raw, list):
        raise ValueError(f"{path}: memory_ranges must be a list")
    if output_spec_raw is None:
        output_spec_raw = []
    if not isinstance(output_spec_raw, list):
        output_spec_raw = []
    output_ranges_for_marking = _parse_output_spec_ranges({"output_spec": output_spec_raw})
    if output_ranges_for_marking:
        for raw_event in events_raw:
            if isinstance(raw_event, dict) and _raw_store_matches_output_ranges(
                raw_event,
                output_ranges_for_marking,
            ):
                raw_event["is_output_store"] = True
    return {
        "events": events_raw,
        "memory_ranges": memory_ranges_raw,
        "output_spec": output_spec_raw,
    }


def _safe_int(raw: Any, default: int = 0) -> int:
    try:
        if isinstance(raw, bool):
            return int(raw)
        if isinstance(raw, int):
            return int(raw)
        if isinstance(raw, float):
            return int(raw)
        if isinstance(raw, str):
            s = raw.strip()
            if not s:
                return int(default)
            return int(s, 0)
    except Exception:
        return int(default)
    return int(default)


def _deep_get(obj: Any, path: str) -> Any:
    cur = obj
    for part in str(path).split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur.get(part)
        else:
            return None
    return cur


def _sampling_first(fi_space: Dict[str, Any], paths: Sequence[str]) -> Any:
    for path in paths:
        val = _deep_get(fi_space, str(path))
        if val is not None:
            return val
    return None


def _load_fi_sampling_space(path: Optional[Path]) -> Dict[str, Any]:
    if path is None:
        return {}
    return _load_fi_sampling_space_cached(_path_cache_key(path))


@lru_cache(maxsize=None)
def _load_fi_sampling_space_cached(path_key: str) -> Dict[str, Any]:
    try:
        raw = _json_load_path(Path(path_key))
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}
    return dict(raw)


def _cycle_domain_stats(path: Optional[Path]) -> Dict[str, int]:
    if path is None:
        return {"unique_cycles": 0, "total_multiplicity": 0}
    p = Path(path)
    if not p.exists():
        return {"unique_cycles": 0, "total_multiplicity": 0}
    try:
        if p.suffix.lower() == ".json":
            counts, _ids = _load_cycle_counts_json(p)
        else:
            counts = _load_cycle_counts_text(p)
    except Exception:
        return {"unique_cycles": 0, "total_multiplicity": 0}
    return {
        "unique_cycles": int(len(counts)),
        "total_multiplicity": int(sum(int(v) for v in counts.values())),
    }


def _scope_cycle_prefix(
    cycle_weights: Dict[Tuple[int, int], Dict[int, int]]
) -> Dict[Tuple[int, int], Tuple[List[int], List[int], int]]:
    out: Dict[Tuple[int, int], Tuple[List[int], List[int], int]] = {}
    for scope, per_cycle in cycle_weights.items():
        items = sorted((int(c), int(w)) for c, w in per_cycle.items() if int(w) > 0)
        cycles = [c for c, _ in items]
        prefix = [0]
        total = 0
        for _cycle, w in items:
            total += int(w)
            prefix.append(total)
        out[scope] = (cycles, prefix, int(total))
    return out


def _thread_cycle_weights(
    cycle_records: List[CycleRecord],
    thread_rands: Optional[List[int]],
    thread_rand_max: Optional[int],
    *,
    include_thread_ids: Optional[Iterable[int]] = None,
    prefix_only: bool = False,
) -> Tuple[Dict[int, Dict[int, int]], int, int, int]:
    cycle_records_key = tuple(cycle_records)
    thread_rands_key = (
        None
        if thread_rands is None
        else tuple(int(v) for v in thread_rands)
    )
    include_thread_ids_key = (
        None
        if include_thread_ids is None
        else tuple(sorted({int(v) for v in include_thread_ids}))
    )
    thread_rand_max_key = (
        None if thread_rand_max is None else int(thread_rand_max)
    )
    return _thread_cycle_weights_cached(
        cycle_records_key,
        thread_rands_key,
        thread_rand_max_key,
        include_thread_ids_key,
        bool(prefix_only),
    )


def _should_use_cpp_thread_cycle(
    cycle_records: Sequence[CycleRecord],
) -> bool:
    if not _CPP_THREAD_CYCLE_ENABLED or _CPP_THREAD_CYCLE_FAILED:
        return False
    if _CPP_THREAD_CYCLE_FORCE:
        return True
    # The current C++ entrypoint requires eager Python marshalling of every
    # cycle + active-thread list. For the storage workloads in this repo, that
    # bridge cost dominates and is slower than the Python path once the cycle
    # domain is even moderately large, so auto-mode keeps C++ only for tiny
    # workloads unless the caller explicitly forces it.
    if len(cycle_records) > _CPP_THREAD_CYCLE_AUTO_MAX_RECORDS:
        return False
    total_active_threads = 0
    for rec in cycle_records:
        total_active_threads += len(rec.active_thread_ids)
        if total_active_threads > _CPP_THREAD_CYCLE_AUTO_MAX_TOTAL_ACTIVE_THREADS:
            return False
    return True


@lru_cache(maxsize=16)
def _thread_cycle_weights_cached(
    cycle_records: Tuple[CycleRecord, ...],
    thread_rands: Optional[Tuple[int, ...]],
    thread_rand_max: Optional[int],
    include_thread_ids: Optional[Tuple[int, ...]],
    prefix_only: bool,
) -> Tuple[Dict[int, Dict[int, int]], int, int, int]:
    return _thread_cycle_weights_uncached(
        list(cycle_records),
        None if thread_rands is None else list(thread_rands),
        thread_rand_max,
        None if include_thread_ids is None else set(int(v) for v in include_thread_ids),
        prefix_only=bool(prefix_only),
    )


def _thread_cycle_weights_uncached(
    cycle_records: List[CycleRecord],
    thread_rands: Optional[List[int]],
    thread_rand_max: Optional[int],
    include_thread_ids: Optional[Set[int]] = None,
    *,
    prefix_only: bool = False,
) -> Tuple[Dict[int, Dict[int, int]], int, int, int]:
    total_cycle_lines = sum(rec.multiplicity for rec in cycle_records)
    if total_cycle_lines <= 0:
        raise ValueError("cycle multiplicity total is zero")

    if prefix_only and include_thread_ids is not None:
        refined = _thread_cycle_weights_range_refined_prefix(
            cycle_records,
            include_thread_ids,
            thread_rand_max,
            total_cycle_lines,
        )
        if refined is not None:
            return refined

    return _thread_cycle_weights_expanded_uncached(
        cycle_records,
        thread_rands,
        thread_rand_max,
    )


def _should_use_cpp_thread_cycle(
    cycle_records: Sequence[CycleRecord],
) -> bool:
    if not _CPP_THREAD_CYCLE_ENABLED or _CPP_THREAD_CYCLE_FAILED:
        return False
    if _CPP_THREAD_CYCLE_FORCE:
        return True
    # The current C++ entrypoint requires eager Python marshalling of every
    # cycle + active-thread list. For the storage workloads in this repo, that
    # bridge cost dominates and is slower than the Python path once the cycle
    # domain is even moderately large, so auto-mode keeps C++ only for tiny
    # workloads unless the caller explicitly forces it.
    if len(cycle_records) > _CPP_THREAD_CYCLE_AUTO_MAX_RECORDS:
        return False
    total_active_threads = 0
    for rec in cycle_records:
        total_active_threads += len(rec.active_thread_ids)
        if total_active_threads > _CPP_THREAD_CYCLE_AUTO_MAX_TOTAL_ACTIVE_THREADS:
            return False
    return True


def _thread_cycle_weights_expanded_uncached(
    cycle_records: List[CycleRecord],
    thread_rands: Optional[List[int]],
    thread_rand_max: Optional[int],
) -> Tuple[Dict[int, Dict[int, int]], int, int, int]:
    global _CPP_THREAD_CYCLE_FAILED
    total_cycle_lines = sum(rec.multiplicity for rec in cycle_records)
    if total_cycle_lines <= 0:
        raise ValueError("cycle multiplicity total is zero")

    if _should_use_cpp_thread_cycle(cycle_records):
        try:
            cpp_result = exact_cpp_backend.thread_cycle_weights(
                cycles=[int(rec.cycle) for rec in cycle_records],
                multiplicities=[int(rec.multiplicity) for rec in cycle_records],
                active_thread_ids_by_record=[
                    [int(tid) for tid in rec.active_thread_ids] for rec in cycle_records
                ],
                seed_values=None if thread_rands is None else [int(v) for v in thread_rands],
                thread_rand_max=None if thread_rand_max is None else int(thread_rand_max),
            )
        except Exception:
            _CPP_THREAD_CYCLE_FAILED = True
            cpp_result = None
        if cpp_result is not None:
            sorted_entries, seed_domain_size, inactive_base_mass, active_base_mass = cpp_result
            thread_cycle_weights_cpp = ThreadCycleWeightsDict()
            thread_cycle_weights_cpp._sorted_entries = list(sorted_entries)
            for tid, cycle, weight in sorted_entries:
                per_cycle = thread_cycle_weights_cpp.get(int(tid))
                if per_cycle is None:
                    per_cycle = {}
                    thread_cycle_weights_cpp[int(tid)] = per_cycle
                per_cycle[int(cycle)] = int(weight)
            thread_cycle_weights_cpp._thread_prefix = build_thread_cycle_prefix(
                thread_cycle_weights_cpp
            )
            return (
                thread_cycle_weights_cpp,
                int(seed_domain_size),
                int(inactive_base_mass),
                int(active_base_mass),
            )

    inactive_base_mass = 0
    thread_cycle_weights = ThreadCycleWeightsDict()
    template_cache: Dict[
        Tuple[Any, ...],
        Tuple[Tuple[Tuple[int, int], ...], int],
    ] = {}
    seed_domain_size = None
    monotonic_cycles = True
    prev_cycle: Optional[int] = None
    weights_get = thread_cycle_weights.get
    for rec in cycle_records:
        cycle_i = int(rec.cycle)
        multiplicity_i = int(rec.multiplicity)
        if prev_cycle is not None and cycle_i < int(prev_cycle):
            monotonic_cycles = False
        prev_cycle = int(cycle_i)

        ids = rec.active_thread_ids
        ids_key = _thread_id_sequence_cache_key(ids)
        cached = template_cache.get(ids_key)
        if cached is None:
            slot_counts, domain_size = slot_counts_for_cycle(
                active_size=len(ids),
                seed_values=thread_rands,
                thread_rand_max=thread_rand_max,
            )
            tid_weights: Dict[int, int] = {}
            if len(ids) > 0:
                ids_values = tuple(_iter_thread_ids_from_sequence(ids))
                for slot, count in slot_counts.items():
                    count_i = int(count)
                    if count_i <= 0:
                        continue
                    tid = int(ids_values[int(slot)])
                    tid_weights[int(tid)] = int(tid_weights.get(int(tid), 0)) + int(count_i)
            cached = (
                tuple((int(tid), int(weight)) for tid, weight in tid_weights.items()),
                int(domain_size),
            )
            template_cache[ids_key] = cached
        tid_template, domain_size = cached
        if seed_domain_size is None:
            seed_domain_size = int(domain_size)
        elif int(seed_domain_size) != int(domain_size):
            raise AssertionError("internal: seed domain size mismatch")

        if len(ids) == 0:
            inactive_base_mass += multiplicity_i * int(domain_size)
            continue
        for tid, count in tid_template:
            per_cycle = weights_get(int(tid))
            if per_cycle is None:
                per_cycle = {}
                thread_cycle_weights[int(tid)] = per_cycle
            per_cycle[int(cycle_i)] = int(per_cycle.get(int(cycle_i), 0)) + (
                multiplicity_i * int(count)
            )

    assert seed_domain_size is not None
    base_denominator = int(total_cycle_lines) * int(seed_domain_size)
    active_base_mass = int(base_denominator - inactive_base_mass)
    sorted_entries: List[Tuple[int, int, int]] = []
    for tid in sorted(int(v) for v in thread_cycle_weights.keys()):
        per_cycle = thread_cycle_weights[int(tid)]
        items = (
            per_cycle.items()
            if monotonic_cycles
            else sorted((int(c), int(w)) for c, w in per_cycle.items())
        )
        for cycle, weight in items:
            sorted_entries.append((int(tid), int(cycle), int(weight)))
    thread_cycle_weights._sorted_entries = sorted_entries
    return thread_cycle_weights, int(seed_domain_size), int(inactive_base_mass), int(active_base_mass)


def _shared_scope_from_event(ev: Dict[str, Any]) -> Optional[Tuple[int, int]]:
    if canonical_space(ev.get("mem_space") or ev.get("space")) != "shared":
        return None
    sm_id = ev.get("sm_id")
    cta_id = ev.get("cta_id")
    if sm_id is None or cta_id is None:
        return None
    return (int(sm_id), int(cta_id))


def _build_shared_trace_indexes(
    trace_template: Dict[str, Any],
) -> Tuple[
    Dict[int, Tuple[int, int]],
    Dict[Tuple[int, int, int], List[int]],
    Dict[Tuple[int, int, int], List[int]],
]:
    events_raw = trace_template.get("events", [])
    thread_to_scope: Dict[int, Tuple[int, int]] = {}
    shared_write_cycles: Dict[Tuple[int, int, int], List[int]] = defaultdict(list)
    shared_read_cycles: Dict[Tuple[int, int, int], List[int]] = defaultdict(list)

    # Thread -> (sm, cta) mapping is needed for cycle/block sampling.  Collect
    # it while scanning shared-memory events so the prepared trace is not walked
    # twice for smem_rf.
    for idx, raw in enumerate(events_raw):
        if not isinstance(raw, dict):
            continue
        tid = raw.get("thread_id")
        sm_id = raw.get("sm_id")
        cta_id = raw.get("cta_id")
        if tid is not None and sm_id is not None and cta_id is not None:
            thread_to_scope[int(tid)] = (int(sm_id), int(cta_id))
        kind = str(raw.get("kind", "")).strip().lower()
        if kind not in ("store", "load"):
            continue
        pred_raw = raw.get("pred")
        if isinstance(pred_raw, dict) and int(pred_raw.get("val", 1)) == 0:
            continue
        scope = _shared_scope_from_event(raw)
        if scope is None:
            continue
        if raw.get("thread_id") is not None:
            thread_to_scope[int(raw.get("thread_id"))] = scope
        if raw.get("mem_addr") is None and raw.get("base") is None:
            continue
        try:
            addr = int(parse_int(raw.get("mem_addr", raw.get("base"))))
        except Exception:
            continue
        size_bytes = access_size_bytes_for_raw_event(raw)
        cycle = int(raw.get("cycle", idx))
        for byte_i in range(max(0, min(size_bytes, 8))):
            key = (int(scope[0]), int(scope[1]), int(addr + byte_i))
            if kind == "store":
                shared_write_cycles[key].append(cycle)
            else:
                shared_read_cycles[key].append(cycle)

    for key, rows in list(shared_write_cycles.items()):
        shared_write_cycles[key] = sorted(set(int(v) for v in rows))
    for key, rows in list(shared_read_cycles.items()):
        shared_read_cycles[key] = sorted(set(int(v) for v in rows))
    return thread_to_scope, shared_write_cycles, shared_read_cycles


def _extract_rf_addr_source_regs(
    trace_template: Optional[Dict[str, Any]],
) -> Tuple[Set[str], Set[int]]:
    if not isinstance(trace_template, dict):
        return set(), set()
    events_raw = trace_template.get("events", [])
    if not isinstance(events_raw, list):
        return set(), set()
    reg_names: Set[str] = set()
    reg_uids: Set[int] = set()
    for raw in events_raw:
        if not isinstance(raw, dict):
            continue
        kind = str(raw.get("kind", "")).strip().lower()
        if kind not in ("load", "store"):
            continue
        cspace = canonical_space(raw.get("mem_space") or raw.get("space"))
        if cspace not in ("global", "local", "shared", "const"):
            continue
        src_regs_raw = raw.get("src_regs", [])
        src_uids_raw = raw.get("src_reg_uids", [])
        if not isinstance(src_regs_raw, list):
            src_regs_raw = []
        if not isinstance(src_uids_raw, list):
            src_uids_raw = []
        ea_indices: List[int] = []
        base_indices_raw = raw.get("ea_base_src_indices", [])
        if isinstance(base_indices_raw, list):
            for idx_raw in base_indices_raw:
                try:
                    ea_indices.append(int(idx_raw))
                except Exception:
                    continue
        ea_expr_raw = raw.get("ea_expr")
        if isinstance(ea_expr_raw, dict):
            expr_indices = ea_expr_raw.get("src_indices", [])
            if isinstance(expr_indices, list):
                for idx_raw in expr_indices:
                    try:
                        ea_indices.append(int(idx_raw))
                    except Exception:
                        continue
        for src_i in ea_indices:
            if src_i < 0:
                continue
            if src_i < len(src_regs_raw):
                reg_name = str(src_regs_raw[src_i]).strip()
                if reg_name:
                    reg_names.add(reg_name)
            if src_i < len(src_uids_raw):
                try:
                    uid = int(src_uids_raw[src_i])
                except Exception:
                    uid = -1
                if uid >= 0:
                    reg_uids.add(int(uid))
    return reg_names, reg_uids


def _rf_addr_observed_scope_key(
    cspace: Optional[str],
    ev: Any,
) -> Optional[RFAddrObservedIntervalKey]:
    cspace_n = canonical_space(cspace)
    if cspace_n is None:
        return None
    if cspace_n == "global":
        return (str(cspace_n), None, None, None)
    if cspace_n == "local":
        return (
            str(cspace_n),
            int(getattr(ev, "thread_id", -1)),
            (
                int(getattr(ev, "cta_id"))
                if getattr(ev, "cta_id", None) is not None
                else None
            ),
            int(getattr(ev, "sm_id")) if getattr(ev, "sm_id", None) is not None else None,
        )
    if cspace_n == "shared":
        return (
            str(cspace_n),
            None,
            (
                int(getattr(ev, "cta_id"))
                if getattr(ev, "cta_id", None) is not None
                else None
            ),
            int(getattr(ev, "sm_id")) if getattr(ev, "sm_id", None) is not None else None,
        )
    return None



def _rf_addr_effective_ranges_for_event(
    analysis_mod: Any,
    ev: Any,
    ranges: Sequence[Any],
) -> List[Any]:
    return list(analysis_mod.active_ranges_for_event(ev, list(ranges)))


def _merge_half_open_intervals(
    intervals: Iterable[Tuple[int, int]],
) -> Tuple[Tuple[int, int], ...]:
    rows = sorted(
        (int(lo), int(hi))
        for lo, hi in intervals
        if int(hi) > int(lo)
    )
    if not rows:
        return ()
    out: List[Tuple[int, int]] = []
    cur_lo, cur_hi = rows[0]
    for lo, hi in rows[1:]:
        if int(lo) <= int(cur_hi):
            if int(hi) > int(cur_hi):
                cur_hi = int(hi)
            continue
        out.append((int(cur_lo), int(cur_hi)))
        cur_lo, cur_hi = int(lo), int(hi)
    out.append((int(cur_lo), int(cur_hi)))
    return tuple(out)


def _intervals_contain_access(
    intervals: Sequence[Tuple[int, int]],
    addr: int,
    size_bytes: int,
) -> bool:
    addr_i = int(addr)
    size_i = max(1, int(size_bytes))
    end_i = int(addr_i + size_i)
    if end_i <= addr_i:
        return False
    for lo, hi in intervals:
        if int(addr_i) < int(lo):
            return False
        if int(addr_i) >= int(lo) and int(end_i) <= int(hi):
            return True
    return False


def _rf_addr_ranges_to_intervals(ranges: Sequence[Any]) -> Tuple[Tuple[int, int], ...]:
    return _merge_half_open_intervals(
        (
            int(getattr(entry, "base", 0)),
            int(getattr(entry, "base", 0)) + int(getattr(entry, "size", 0)),
        )
        for entry in ranges
        if int(getattr(entry, "size", 0)) > 0
    )


def _build_rf_addr_event_eval_info(
    analysis_mod: Any,
    ev: Any,
    ranges: Sequence[Any],
    observed_intervals: Optional[RFAddrObservedIntervals],
) -> RFAddrEventEvalInfo:
    access_size = max(1, int(analysis_mod.access_size_bytes_for_event(ev)))
    scope_key = _rf_addr_observed_scope_key(getattr(ev, "mem_space", None), ev)
    observed = ()
    if observed_intervals and scope_key is not None:
        observed = tuple(observed_intervals.get(scope_key, ()))
    active_ranges = _rf_addr_effective_ranges_for_event(
        analysis_mod=analysis_mod,
        ev=ev,
        ranges=ranges,
    )
    active = _rf_addr_ranges_to_intervals(active_ranges)

    expr = analysis_mod.build_default_ea_expr(ev)
    base_effective_ea = int(analysis_mod.eval_effective_ea(ev))
    base_raw_ea: Optional[int] = None
    expr_width_mask = 0
    effective_mask = 0
    expr_src_coeffs: Dict[int, int] = {}
    if expr is not None:
        effective_mask = int(
            analysis_mod.event_effective_address_mask(ev, int(expr.width_bits))
        ) & MASK64
        expr_width_mask = int(analysis_mod.width_mask(int(expr.width_bits))) & MASK64
        if str(getattr(expr, "op", "")).strip().upper() in ("IDENTITY", "ADDR_SUM"):
            base_raw_ea = int(analysis_mod.eval_ea_expr(ev)) & int(expr_width_mask)
            for src_i in getattr(expr, "src_indices", []):
                src_i_int = int(src_i)
                if src_i_int < 0:
                    continue
                expr_src_coeffs[src_i_int] = int(expr_src_coeffs.get(src_i_int, 0)) + 1

    return RFAddrEventEvalInfo(
        access_size_bytes=int(access_size),
        active_intervals=tuple(active),
        observed_intervals=tuple(observed),
        base_effective_ea=int(base_effective_ea),
        base_raw_ea=(
            int(base_raw_ea) & MASK64 if base_raw_ea is not None else None
        ),
        expr_width_mask=int(expr_width_mask) & MASK64,
        effective_mask=int(effective_mask) & MASK64,
        expr_src_coeffs=dict(expr_src_coeffs),
    )


def _build_rf_addr_observed_intervals(
    analysis_mod: Any,
    events: Sequence[Any],
) -> RFAddrObservedIntervals:
    raw: Dict[RFAddrObservedIntervalKey, List[Tuple[int, int]]] = defaultdict(list)
    for ev in events:
        if str(getattr(ev, "kind", "")).strip().lower() not in ("load", "store"):
            continue
        pred = getattr(ev, "pred", None)
        if pred is not None and int(getattr(pred, "val", 1)) == 0:
            continue
        cspace = analysis_mod.canonical_space(getattr(ev, "mem_space", None))
        if cspace not in ("global", "local", "shared"):
            continue
        try:
            addr = int(analysis_mod.eval_effective_ea(ev))
        except Exception:
            continue
        size_bytes = int(analysis_mod.access_size_bytes_for_event(ev))
        if size_bytes <= 0:
            continue
        scope_key = _rf_addr_observed_scope_key(cspace, ev)
        if scope_key is None:
            continue
        raw[scope_key].append((int(addr), int(addr) + int(size_bytes)))
    return {
        scope_key: _merge_half_open_intervals(intervals)
        for scope_key, intervals in raw.items()
    }


def _load_rf_addr_trace_context(
    trace_template_path: Optional[str],
) -> Tuple[
    Optional[Any],
    Dict[int, Any],
    List[Any],
    Dict[Tuple[int, int, int], List[RFAddrTraceRecord]],
    Dict[Tuple[int, int, str], List[RFAddrTraceRecord]],
    RFAddrObservedIntervals,
]:
    if trace_template_path is None:
        return None, {}, [], {}, {}, {}
    return _load_rf_addr_trace_context_cached(_path_cache_key(trace_template_path))


@lru_cache(maxsize=None)
def _load_rf_addr_trace_context_cached(
    trace_template_path_key: str,
) -> Tuple[
    Optional[Any],
    Dict[int, Any],
    List[Any],
    Dict[Tuple[int, int, int], List[RFAddrTraceRecord]],
    Dict[Tuple[int, int, str], List[RFAddrTraceRecord]],
    RFAddrObservedIntervals,
]:
    try:
        import reg_observed_analyzer as analysis_mod

        loaded_trace = analysis_mod.load_trace(
            Path(trace_template_path_key),
            include_metadata=True,
        )
        # reg_observed_analyzer.load_trace(include_metadata=True) currently
        # returns (events, ranges, output_ranges).  Older in-tree revisions also
        # carried a semantic-program slot.  Accept both shapes so RF address
        # alias classification is not silently disabled when the loader shape
        # changes.
        if isinstance(loaded_trace, tuple) and len(loaded_trace) == 3:
            events, ranges, _output_ranges = loaded_trace
        elif isinstance(loaded_trace, tuple) and len(loaded_trace) == 4:
            events, ranges, _semantic_programs, _output_ranges = loaded_trace
        else:
            return None, {}, [], {}, {}, {}
    except Exception:
        return None, {}, [], {}, {}, {}

    event_by_index: Dict[int, Any] = {}
    by_uid: Dict[Tuple[int, int, int], List[RFAddrTraceRecord]] = defaultdict(list)
    by_name: Dict[Tuple[int, int, str], List[RFAddrTraceRecord]] = defaultdict(list)
    observed_intervals = _build_rf_addr_observed_intervals(analysis_mod, events)

    for ev in events:
        event_by_index[int(ev.index)] = ev
        if str(getattr(ev, "kind", "")).strip().lower() not in ("load", "store"):
            continue
        if getattr(ev, "cycle", None) is None:
            continue
        pred = getattr(ev, "pred", None)
        if pred is not None and int(getattr(pred, "val", 1)) == 0:
            continue
        expr = analysis_mod.build_default_ea_expr(ev)
        if expr is None:
            continue
        src_masks = analysis_mod.ea_source_influence_masks(
            ev,
            analysis_mod.width_mask(int(expr.width_bits)),
        )
        for src_i in expr.src_indices:
            if src_i < 0 or src_i >= len(ev.src_regs):
                continue
            src_w = min(64, int(ev.src_width_bits[src_i]))
            influence_mask = int(src_masks.get(src_i, 0)) & int(
                analysis_mod.width_mask(src_w)
            )
            if influence_mask == 0:
                continue
            rec = RFAddrTraceRecord(
                event_index=int(ev.index),
                src_index=int(src_i),
                influence_mask=int(influence_mask) & MASK64,
            )
            key_name = (int(ev.thread_id), int(ev.cycle), str(ev.src_regs[src_i]))
            by_name[key_name].append(rec)
            src_uid = (
                int(ev.src_reg_uids[src_i])
                if 0 <= src_i < len(ev.src_reg_uids)
                else -1
            )
            if src_uid >= 0:
                key_uid = (int(ev.thread_id), int(ev.cycle), int(src_uid))
                by_uid[key_uid].append(rec)

    return (
        analysis_mod,
        event_by_index,
        list(ranges),
        dict(by_uid),
        dict(by_name),
        dict(observed_intervals),
    )


def _analyzer_rf_requires_addr_trace_context(analyzer_output: Dict[str, Any]) -> bool:
    read_events = analyzer_output.get("read_events", [])
    if not isinstance(read_events, list):
        return False
    mask_format = _analyzer_mask_format(analyzer_output)
    for raw_rec in read_events:
        read_kind = str(_read_event_row_field(raw_rec, "read_kind", "")).strip().lower()
        if read_kind == "addr":
            return True
        for key in (
            ADDR_STATIC_DUE_MASK_FIELD,
            "addr_static_due_mask",
            "addr_due_mask_this_read",
        ):
            try:
                val = _parse_mask_with_format(
                    _read_event_row_field(raw_rec, key, 0),
                    mask_format,
                )
            except Exception:
                val = 0
            if int(val) != 0:
                return True
    return False


def _rf_addr_access_is_oob(
    analysis_mod: Any,
    ev: Any,
    mutated_addr: int,
    ranges: Sequence[Any],
    observed_intervals: Optional[RFAddrObservedIntervals] = None,
    event_info: Optional[RFAddrEventEvalInfo] = None,
) -> Optional[bool]:
    if event_info is not None:
        access_size = int(event_info.access_size_bytes)
        if event_info.observed_intervals and _intervals_contain_access(
            event_info.observed_intervals,
            int(mutated_addr),
            int(access_size),
        ):
            return False
        if event_info.active_intervals and _intervals_contain_access(
            event_info.active_intervals,
            int(mutated_addr),
            int(access_size),
        ):
            return False
        if event_info.active_intervals:
            return True
        return None

    cspace = analysis_mod.canonical_space(getattr(ev, "mem_space", None))
    access_size = int(analysis_mod.access_size_bytes_for_event(ev))
    if cspace is None:
        return None
    if observed_intervals:
        scope_key = _rf_addr_observed_scope_key(cspace, ev)
        if scope_key is not None:
            intervals = observed_intervals.get(scope_key, ())
            if intervals and _intervals_contain_access(
                intervals,
                int(mutated_addr),
                int(access_size),
            ):
                return False
    active_ranges = _rf_addr_effective_ranges_for_event(
        analysis_mod=analysis_mod,
        ev=ev,
        ranges=ranges,
    )
    for entry in active_ranges:
        if entry.contains_access(int(mutated_addr), int(access_size)):
            return False
    if active_ranges:
        return True
    return None


def _rf_addr_mutated_effective_ea(
    analysis_mod: Any,
    ev: Any,
    event_info: Optional[RFAddrEventEvalInfo],
    src_i: int,
    bit_idx: int,
) -> int:
    if event_info is not None and event_info.base_raw_ea is not None:
        coeff = int(event_info.expr_src_coeffs.get(int(src_i), 0))
        if coeff > 0:
            delta_unit = 1 << int(bit_idx)
            src_val = int(ev.src_vals[src_i]) & MASK64
            if ((int(src_val) >> int(bit_idx)) & 1) != 0:
                delta = -int(coeff) * int(delta_unit)
            else:
                delta = int(coeff) * int(delta_unit)
            raw_ea = (int(event_info.base_raw_ea) + int(delta)) & int(
                event_info.expr_width_mask
            )
            return int(raw_ea) & int(event_info.effective_mask)

    mutated_vals = list(ev.src_vals)
    mutated_vals[int(src_i)] = int(ev.src_vals[src_i]) ^ (1 << int(bit_idx))
    return int(analysis_mod.eval_effective_ea(ev, src_vals_override=mutated_vals))


def _classify_rf_addr_masks_from_trace(
    *,
    analysis_mod: Any,
    trace_events_by_index: Dict[int, Any],
    trace_ranges: Sequence[Any],
    trace_observed_intervals: Optional[RFAddrObservedIntervals],
    trace_event_eval_info_resolver: Optional[
        Callable[[int], Optional[RFAddrEventEvalInfo]]
    ],
    records: Sequence[RFAddrTraceRecord],
    addr_fault_policy: str,
    addr_due_mode: str,
    trace_mask: int,
    trace_divergence_policy: str,
) -> Tuple[int, int, int, int, Dict[str, int], int]:
    policy = _normalize_addr_fault_policy(addr_fault_policy)
    due_mode = _normalize_addr_due_mode(addr_due_mode)
    trace_target = _trace_divergence_target_class(trace_divergence_policy)
    bit_class: Dict[int, str] = {}
    bit_source: Dict[int, str] = {}
    precedence = {"masked": 0, "unknown": 1, "sdc": 2, "due": 3}
    seen: Set[Tuple[int, int]] = set()
    for rec in records:
        event_index = int(rec.event_index)
        ev = trace_events_by_index.get(int(event_index))
        if ev is None:
            continue
        event_info = (
            trace_event_eval_info_resolver(int(event_index))
            if trace_event_eval_info_resolver is not None
            else None
        )
        src_i = int(rec.src_index)
        if src_i < 0 or src_i >= len(ev.src_vals):
            continue
        src_w = min(64, int(ev.src_width_bits[src_i]))
        influence_mask = int(rec.influence_mask) & int(analysis_mod.width_mask(src_w))
        if influence_mask == 0:
            continue
        base_ea = (
            int(event_info.base_effective_ea)
            if event_info is not None
            else int(analysis_mod.eval_effective_ea(ev))
        )
        pending = int(influence_mask)
        while pending:
            one_bit = int(pending & -pending)
            bit_idx = int(one_bit.bit_length() - 1)
            pending ^= one_bit
            dedupe_key = (int(event_index), int(src_i) * 64 + int(bit_idx))
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            mutated_ea = _rf_addr_mutated_effective_ea(
                analysis_mod=analysis_mod,
                ev=ev,
                event_info=event_info,
                src_i=int(src_i),
                bit_idx=int(bit_idx),
            )
            cls = "masked"
            source = "rf_addr_masked"
            if mutated_ea == base_ea:
                cls = "masked"
                source = "rf_addr_masked"
            else:
                is_oob = _rf_addr_access_is_oob(
                    analysis_mod=analysis_mod,
                    ev=ev,
                    mutated_addr=int(mutated_ea),
                    ranges=trace_ranges,
                    observed_intervals=trace_observed_intervals,
                    event_info=event_info,
                )
                if is_oob is None:
                    cls = "unknown"
                    source = "rf_addr_unknown_range"
                elif is_oob:
                    cls = "due"
                    source = "rf_addr_oob_due"
                else:
                    cls = "sdc"
                    source = "addr_alias_sdc"

            if ((int(trace_mask) >> int(bit_idx)) & 1) != 0 and cls == "masked" and trace_target != "masked":
                cls = str(trace_target)
                if cls == "due":
                    source = "rf_trace_divergence_due"
                elif cls == "sdc":
                    source = "trace_divergence_sdc"
                else:
                    source = "trace_divergence_unknown"

            prev_cls = str(bit_class.get(int(bit_idx), "masked"))
            if int(precedence.get(str(cls), 0)) >= int(precedence.get(prev_cls, 0)):
                bit_class[int(bit_idx)] = str(cls)
                bit_source[int(bit_idx)] = str(source)

    due_mask = 0
    sdc_mask = 0
    unknown_mask = 0
    masked_mask = 0
    trace_div_bits = 0
    source_masks: Dict[str, int] = defaultdict(int)
    for bit_idx, cls in bit_class.items():
        one_bit = (1 << int(bit_idx)) & MASK64
        source = str(bit_source.get(int(bit_idx), "rf_addr_masked"))
        if cls == "due":
            due_mask |= int(one_bit)
        elif cls == "sdc":
            sdc_mask |= int(one_bit)
        elif cls == "unknown":
            unknown_mask |= int(one_bit)
        else:
            masked_mask |= int(one_bit)
        source_masks[str(source)] = int(source_masks.get(str(source), 0)) | int(one_bit)
        if str(source).startswith("trace_divergence_") or str(source) == "rf_trace_divergence_due":
            trace_div_bits |= int(one_bit)

    source_bits: Dict[str, int] = {}
    for source, mask in source_masks.items():
        source_bits[str(source)] = int(popcount_u64(int(mask) & MASK64))

    return (
        int(due_mask) & MASK64,
        int(sdc_mask) & MASK64,
        int(unknown_mask) & MASK64,
        int(masked_mask) & MASK64,
        source_bits,
        int(trace_div_bits) & MASK64,
    )


def _resolve_rf_domain_policy_info(
    *,
    args: argparse.Namespace,
    fi_space: Dict[str, Any],
    total_cycle_lines: int,
    seed_domain_size: int,
    register_count_used: int,
    bit_count: int,
) -> Dict[str, Any]:
    policy = _normalize_rf_domain_policy(getattr(args, "rf_domain_policy", "sampling_space"))
    used_regs = max(0, int(register_count_used))
    bits_per_reg = max(0, int(bit_count))
    used_per_seed = int(used_regs) * int(bits_per_reg)

    sampling_per_seed = _first_positive_int(
        (
            _sampling_first(
                fi_space,
                (
                    "component_domains.rf.domain_bits_per_seed",
                    "rf_domain_per_seed_bits",
                ),
            ),
        ),
        0,
    )
    sampling_total_bits = _first_positive_int(
        (
            _sampling_first(
                fi_space,
                (
                    "component_domains.rf.domain_total_bits",
                    "rf_domain_total_bits",
                ),
            ),
        ),
        0,
    )
    if (
        sampling_per_seed <= 0
        and sampling_total_bits > 0
        and int(total_cycle_lines) > 0
        and int(seed_domain_size) > 0
    ):
        sampling_per_seed = int(
            round(
                float(sampling_total_bits)
                / float(int(total_cycle_lines) * int(seed_domain_size))
            )
        )

    allocated_regs = _first_positive_int(
        (
            _sampling_first(
                fi_space,
                (
                    "component_domains.rf.allocated_register_count",
                    "component_domains.rf.registers_per_thread",
                    "component_domains.rf.regs_per_thread",
                    "allocated_register_count",
                    "registers_per_thread",
                    "regs_per_thread",
                ),
            ),
        ),
        0,
    )
    hw_regs = _first_positive_int(
        (
            os.environ.get("RF_HW_REGISTER_COUNT", ""),
            _sampling_first(
                fi_space,
                (
                    "component_domains.rf.hw_register_count",
                    "component_domains.rf.hw_full_register_count",
                    "rf_hw_register_count",
                    "hw_rf_register_count",
                    "gpgpu_shader_registers",
                ),
            ),
        ),
        0,
    )

    allocated_per_seed = int(allocated_regs) * int(bits_per_reg) if allocated_regs > 0 else 0
    hw_per_seed = int(hw_regs) * int(bits_per_reg) if hw_regs > 0 else 0

    final_per_seed = 0
    final_source = "used"
    if policy == "used_regs":
        final_per_seed = int(used_per_seed)
        final_source = "used"
    elif policy == "allocated_regs":
        if allocated_per_seed > 0:
            final_per_seed = int(allocated_per_seed)
            final_source = "allocated"
        elif sampling_per_seed > 0:
            final_per_seed = int(sampling_per_seed)
            final_source = "sampling_space"
        elif hw_per_seed > 0:
            final_per_seed = int(hw_per_seed)
            final_source = "hw"
        else:
            final_per_seed = int(used_per_seed)
            final_source = "used"
    elif policy == "hw_full":
        if hw_per_seed > 0:
            final_per_seed = int(hw_per_seed)
            final_source = "hw"
        elif sampling_per_seed > 0:
            final_per_seed = int(sampling_per_seed)
            final_source = "sampling_space"
        elif allocated_per_seed > 0:
            final_per_seed = int(allocated_per_seed)
            final_source = "allocated"
        else:
            final_per_seed = int(used_per_seed)
            final_source = "used"
    else:
        if sampling_per_seed > 0:
            final_per_seed = int(sampling_per_seed)
            final_source = "sampling_space"
        elif allocated_per_seed > 0:
            final_per_seed = int(allocated_per_seed)
            final_source = "allocated"
        elif hw_per_seed > 0:
            final_per_seed = int(hw_per_seed)
            final_source = "hw"
        else:
            final_per_seed = int(used_per_seed)
            final_source = "used"

    derived_total_bits = 0
    if int(total_cycle_lines) > 0 and int(seed_domain_size) > 0 and int(final_per_seed) > 0:
        derived_total_bits = int(total_cycle_lines) * int(seed_domain_size) * int(final_per_seed)
    final_total_bits = int(derived_total_bits)
    if policy == "sampling_space" and sampling_total_bits > 0:
        final_total_bits = int(sampling_total_bits)
        final_source = "sampling_space"
    elif final_total_bits <= 0 and sampling_total_bits > 0:
        final_total_bits = int(sampling_total_bits)
        final_source = "sampling_space"

    if final_per_seed <= 0:
        final_per_seed = int(max(1, used_per_seed))
    if final_total_bits <= 0 and int(total_cycle_lines) > 0 and int(seed_domain_size) > 0:
        final_total_bits = int(total_cycle_lines) * int(seed_domain_size) * int(final_per_seed)

    return {
        "rf_domain_policy": str(policy),
        "rf_domain_source": str(final_source),
        "rf_domain_bits_per_seed_final": int(max(0, final_per_seed)),
        "rf_domain_total_bits_final": int(max(0, final_total_bits)),
        "rf_domain_bits_per_seed_used_regs": int(max(0, used_per_seed)),
        "rf_domain_bits_per_seed_allocated_regs": int(max(0, allocated_per_seed)),
        "rf_domain_bits_per_seed_hw_full": int(max(0, hw_per_seed)),
        "rf_domain_bits_per_seed_sampling_space": int(max(0, sampling_per_seed)),
        "rf_domain_sampling_total_bits": int(max(0, sampling_total_bits)),
        "rf_domain_allocated_register_count": int(max(0, allocated_regs)),
        "rf_domain_hw_register_count": int(max(0, hw_regs)),
    }


def _ordered_scopes_for_cycle(
    active_thread_ids: Sequence[int],
    thread_to_scope: Dict[int, Tuple[int, int]],
    shared_scope_thread_ids: Optional[Sequence[int]] = None,
    scope_thread_runs: Optional[Sequence[Tuple[int, int, Tuple[int, int]]]] = None,
) -> List[Tuple[int, int]]:
    # shared_scope_thread_ids is a preferred ordering hint. Keep all active scopes
    # by appending any missing scopes inferred from active_thread_ids.
    out: List[Tuple[int, int]] = []
    seen: Set[Tuple[int, int]] = set()
    if shared_scope_thread_ids:
        for tid in shared_scope_thread_ids:
            scope = thread_to_scope.get(int(tid))
            if scope is None or scope in seen:
                continue
            seen.add(scope)
            out.append(scope)

    if (
        not shared_scope_thread_ids
        and scope_thread_runs
        and isinstance(active_thread_ids, range)
        and len(active_thread_ids) > 0
    ):
        active_start = int(active_thread_ids[0])
        active_end = int(active_thread_ids[-1])
        for run_start, run_end, scope in scope_thread_runs:
            if run_end < active_start:
                continue
            if run_start > active_end:
                break
            if scope in seen:
                continue
            seen.add(scope)
            out.append(scope)
        return out

    # Preserve active-thread order to mirror simulator walk order as closely as
    # possible while deduplicating CTA scopes.
    for tid in active_thread_ids:
        scope = thread_to_scope.get(int(tid))
        if scope is None or scope in seen:
            continue
        seen.add(scope)
        out.append(scope)
    return out


def _build_scope_thread_runs(
    thread_to_scope: Dict[int, Tuple[int, int]],
) -> List[Tuple[int, int, Tuple[int, int]]]:
    if not thread_to_scope:
        return []
    items = sorted((int(tid), scope) for tid, scope in thread_to_scope.items())
    out: List[Tuple[int, int, Tuple[int, int]]] = []
    run_start: Optional[int] = None
    run_end: Optional[int] = None
    run_scope: Optional[Tuple[int, int]] = None
    for tid, scope in items:
        if run_scope is None:
            run_start = tid
            run_end = tid
            run_scope = scope
            continue
        if scope == run_scope and tid == int(run_end) + 1:
            run_end = tid
            continue
        out.append((int(run_start), int(run_end), run_scope))
        run_start = tid
        run_end = tid
        run_scope = scope
    if run_scope is not None and run_start is not None and run_end is not None:
        out.append((int(run_start), int(run_end), run_scope))
    return out


def _scope_cycle_weights_from_block_sampling(
    cycle_records: List[CycleRecord],
    thread_to_scope: Dict[int, Tuple[int, int]],
    block_rands: Optional[List[int]],
    block_rand_max: Optional[int],
    shared_scope_thread_ids_by_cycle: Optional[Dict[int, Tuple[int, ...]]] = None,
) -> Tuple[Dict[Tuple[int, int], Dict[int, int]], int, Counter]:
    scope_cycle_weights: Dict[Tuple[int, int], Dict[int, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    scope_count_hist: Counter = Counter()
    block_seed_domain_size: Optional[int] = None
    scope_thread_runs = _build_scope_thread_runs(thread_to_scope)
    ordered_scope_cache: Dict[
        Tuple[Tuple[Any, ...], Optional[Tuple[Any, ...]]],
        Tuple[Tuple[int, int], ...],
    ] = {}
    scope_weight_template_cache: Dict[
        Tuple[Tuple[int, int], ...],
        Tuple[Tuple[Tuple[Tuple[int, int], int], ...], int],
    ] = {}
    for rec in cycle_records:
        shared_scope_thread_ids = None
        if shared_scope_thread_ids_by_cycle is not None:
            shared_scope_thread_ids = shared_scope_thread_ids_by_cycle.get(int(rec.cycle))
        scope_cache_key = (
            _thread_id_sequence_cache_key(rec.active_thread_ids),
            None
            if shared_scope_thread_ids is None
            else _thread_id_sequence_cache_key(shared_scope_thread_ids),
        )
        scopes = ordered_scope_cache.get(scope_cache_key)
        if scopes is None:
            scopes = tuple(
                _ordered_scopes_for_cycle(
                    rec.active_thread_ids,
                    thread_to_scope,
                    shared_scope_thread_ids=shared_scope_thread_ids,
                    scope_thread_runs=scope_thread_runs,
                )
            )
            ordered_scope_cache[scope_cache_key] = scopes
        scope_count_hist[int(len(scopes))] += 1
        cached_scope_template = scope_weight_template_cache.get(scopes)
        if cached_scope_template is None:
            slot_counts, domain_size = slot_counts_for_cycle(
                active_size=len(scopes),
                seed_values=block_rands,
                thread_rand_max=block_rand_max,
            )
            cached_scope_template = (
                tuple(
                    ((int(scopes[int(slot)][0]), int(scopes[int(slot)][1])), int(count))
                    for slot, count in slot_counts.items()
                    if int(count) > 0
                ),
                int(domain_size),
            )
            scope_weight_template_cache[scopes] = cached_scope_template
        scope_template, domain_size = cached_scope_template
        if block_seed_domain_size is None:
            block_seed_domain_size = int(domain_size)
        elif int(block_seed_domain_size) != int(domain_size):
            raise AssertionError("internal: block seed domain size mismatch")
        if len(scopes) == 0:
            continue
        cycle_i = int(rec.cycle)
        multiplicity_i = int(rec.multiplicity)
        for scope, count in scope_template:
            scope_cycle_weights[scope][cycle_i] += multiplicity_i * int(count)
    if block_seed_domain_size is None:
        raise ValueError("empty cycle domain for block sampling")
    return scope_cycle_weights, int(block_seed_domain_size), scope_count_hist


def _default_smem_size_bits_from_memory_ranges(memory_ranges: List[Dict[str, Any]]) -> int:
    # Fallback only: use the maximum shared-memory range size seen in template.
    max_bytes = 0
    for raw in memory_ranges:
        if not isinstance(raw, dict):
            continue
        if canonical_space(raw.get("space")) != "shared":
            continue
        size = int(raw.get("size", 0))
        if size > max_bytes:
            max_bytes = size
    return int(max_bytes * 8)


def _smem_touched_size_bits_from_trace_events(events_raw: Any) -> int:
    if not isinstance(events_raw, list):
        return 0
    max_end = 0
    for raw in events_raw:
        if not isinstance(raw, dict):
            continue
        kind = str(raw.get("kind", "")).strip().lower()
        if kind not in ("load", "store"):
            continue
        if canonical_space(raw.get("mem_space") or raw.get("space")) != "shared":
            continue
        if raw.get("mem_addr") is None and raw.get("base") is None:
            continue
        try:
            addr = int(parse_int(raw.get("mem_addr", raw.get("base"))))
        except Exception:
            continue
        if int(addr) < 0:
            continue
        size_bytes = access_size_bytes_for_raw_event(raw)
        if int(size_bytes) <= 0:
            continue
        end = int(addr) + int(size_bytes)
        if end > max_end:
            max_end = int(end)
    return int(max_end * 8)


def _resolve_smem_size_bits(
    *,
    fault_component: str,
    args: argparse.Namespace,
    fi_space: Dict[str, Any],
    trace_template: Dict[str, Any],
    memory_ranges: List[Dict[str, Any]],
) -> Dict[str, Any]:
    policy = _normalize_smem_domain_policy(getattr(args, "smem_domain_policy", "sampling_space"))
    fc = str(fault_component).strip().lower()
    sampling_bits = _first_positive_int(
        (
            _sampling_first(fi_space, (f"component_domains.{fc}.domain_bits_per_seed",)),
            _sampling_first(fi_space, ("component_domains.smem_rf.domain_bits_per_seed",)),
            _sampling_first(fi_space, ("component_domains.smem_lds.domain_bits_per_seed",)),
            _sampling_first(fi_space, (f"component_domains.{fc}.smem_size_bits",)),
            _sampling_first(fi_space, ("component_domains.smem_rf.smem_size_bits",)),
            _sampling_first(fi_space, ("component_domains.smem_lds.smem_size_bits",)),
            _sampling_first(fi_space, ("smem_size_bits",)),
        ),
        0,
    )
    sampling_total_bits = _first_positive_int(
        (
            _sampling_first(fi_space, (f"component_domains.{fc}.domain_total_bits",)),
            _sampling_first(fi_space, ("component_domains.smem_rf.domain_total_bits",)),
            _sampling_first(fi_space, ("component_domains.smem_lds.domain_total_bits",)),
        ),
        0,
    )
    allocated_bits = int(getattr(args, "smem_size_bits", 0))
    if allocated_bits <= 0:
        allocated_bits = _default_smem_size_bits_from_memory_ranges(memory_ranges)
    touched_bits = _smem_touched_size_bits_from_trace_events(trace_template.get("events", []))
    hw_bits = _first_positive_int(
        (
            os.environ.get("SMEM_HW_SIZE_BITS", ""),
            _sampling_first(fi_space, (f"component_domains.{fc}.hw_size_bits",)),
            _sampling_first(fi_space, ("component_domains.smem_rf.hw_size_bits",)),
            _sampling_first(fi_space, ("smem_hw_size_bits",)),
        ),
        0,
    )

    final_bits = 0
    source = "none"
    if policy == "sampling_space":
        if sampling_bits > 0:
            final_bits = int(sampling_bits)
            source = "sampling_space"
        elif hw_bits > 0:
            final_bits = int(hw_bits)
            source = "hw_full_fallback"
            print(
                "WARNING: SMEM_DOMAIN_POLICY=sampling_space but sampling-space "
                "domain_bits_per_seed is missing; falling back to hw_full bits.",
                file=sys.stderr,
            )
        elif allocated_bits > 0:
            final_bits = int(allocated_bits)
            source = "kernel_allocated_fallback"
            print(
                "WARNING: SMEM_DOMAIN_POLICY=sampling_space but sampling-space "
                "domain_bits_per_seed is missing; falling back to kernel_allocated bits.",
                file=sys.stderr,
            )
        elif touched_bits > 0:
            final_bits = int(touched_bits)
            source = "trace_touched_fallback"
            print(
                "WARNING: SMEM_DOMAIN_POLICY=sampling_space but sampling-space, "
                "hw_full and kernel_allocated bits are unavailable; using trace_touched bits.",
                file=sys.stderr,
            )
    elif policy == "hw_full":
        if hw_bits > 0:
            final_bits = int(hw_bits)
            source = "hw_full"
        elif sampling_bits > 0:
            final_bits = int(sampling_bits)
            source = "sampling_space_fallback"
        elif allocated_bits > 0:
            final_bits = int(allocated_bits)
            source = "kernel_allocated_fallback"
    elif policy == "kernel_allocated":
        if allocated_bits > 0:
            final_bits = int(allocated_bits)
            source = "kernel_allocated"
        elif sampling_bits > 0:
            final_bits = int(sampling_bits)
            source = "sampling_space_fallback"
        elif touched_bits > 0:
            final_bits = int(touched_bits)
            source = "trace_touched_fallback"
    else:
        if touched_bits > 0:
            final_bits = int(touched_bits)
            source = "trace_touched"
        elif allocated_bits > 0:
            final_bits = int(allocated_bits)
            source = "kernel_allocated_fallback"
        elif sampling_bits > 0:
            final_bits = int(sampling_bits)
            source = "sampling_space_fallback"

    if final_bits <= 0:
        final_bits = 1
        source = "default_1bit"

    return {
        "smem_domain_policy": str(policy),
        "smem_size_bits_source": str(source),
        "smem_size_bits_final": int(final_bits),
        "smem_domain_bits_per_seed_final": int(final_bits),
        "smem_domain_total_bits_final": int(max(0, sampling_total_bits)),
        "smem_domain_units": "bits",
        "smem_hw_size_bits": int(max(0, hw_bits)),
        "smem_allocated_bits": int(max(0, allocated_bits)),
        "smem_touched_bits": int(max(0, touched_bits)),
        "smem_sampling_space_bits": int(max(0, sampling_bits)),
        "smem_sampling_space_total_bits": int(max(0, sampling_total_bits)),
    }


def _load_smem_addr_valid_ranges(
    *,
    trace_memory_ranges: List[Dict[str, Any]],
    external_path: Optional[Path],
    smem_size_bits: int,
) -> Tuple[List[Dict[str, Any]], str]:
    def _shared_only(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out_rows: List[Dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            if canonical_space(row.get("space", row.get("mem_space"))) != "shared":
                continue
            out_rows.append(dict(row))
        return out_rows

    external_rows: List[Dict[str, Any]] = []
    if external_path is not None:
        external_rows = _shared_only(
            _load_addr_valid_ranges(trace_memory_ranges=[], external_path=external_path)
        )
        if external_rows:
            return external_rows, "external_path"

    trace_rows = _shared_only(
        _load_addr_valid_ranges(trace_memory_ranges=trace_memory_ranges, external_path=None)
    )
    if trace_rows:
        return trace_rows, "trace_template.memory_ranges"

    size_bytes = int((max(0, int(smem_size_bits)) + 7) // 8)
    if size_bytes > 0:
        return (
            [{"space": "shared", "base": 0, "size": int(size_bytes)}],
            "smem_size_bits_fallback",
        )
    return [], "none"


def _selected_bit_mask_for_smem_addr(
    addr: int,
    selected_bits_mask: int,
    domain_full_bytes: int,
    domain_tail_bits: int,
) -> int:
    """Return the realized byte-bit mask selected by shared-memory FI indices.

    The simulator samples shared-memory bit indices as one-based configured
    bits, then realizes each flip through a 64-bit word update:

        idx_64b = bit_in_block / 64
        bit_in_64b = bit_in_block - idx_64b * 64
        i_data[idx_64b] ^= 1UL << (bit_in_64b - 1)

    For ordinary indices this is the nominal byte bit. At every 64-bit word
    boundary, however, the configured high bit of byte 7/15/23/... is realized
    as the high bit of the following 64-bit word. This is a deterministic
    simulator-realization rule, not a fitted correction: SARA counts the same
    configured denominator as FI and maps those configured bits to the storage
    byte/bit that the simulator actually mutates.
    """

    actual_addr = int(addr)
    if actual_addr < 0:
        return 0

    selected = int(selected_bits_mask) & 0xFF
    domain_full = max(0, int(domain_full_bytes))
    tail_bits = max(0, int(domain_tail_bits))

    def configured_mask_for_byte(configured_addr: int) -> int:
        if configured_addr < 0:
            return 0
        if configured_addr < domain_full:
            return selected
        if tail_bits <= 0 or configured_addr != domain_full:
            return 0
        tail_mask = (1 << tail_bits) - 1
        return selected & tail_mask & 0xFF

    mask = 0

    # Bits 0..6 are realized on the nominal byte for all configured bytes.
    own_configured_mask = configured_mask_for_byte(actual_addr)
    mask |= int(own_configured_mask) & 0x7F

    # Configured bit 7 is nominal except at 64-bit word boundaries. At those
    # boundaries it is realized as bit 7 of the following 64-bit word.
    if (actual_addr % 8) != 7:
        mask |= int(own_configured_mask) & 0x80

    previous_word_boundary_addr = actual_addr - 8
    if previous_word_boundary_addr >= 0 and (previous_word_boundary_addr % 8) == 7:
        previous_configured_mask = configured_mask_for_byte(previous_word_boundary_addr)
        if int(previous_configured_mask) & 0x80:
            mask |= 0x80

    return int(mask) & 0xFF


def _selected_smem_domain_bit_count(
    selected_bits_mask: int,
    bit_count_full_byte: int,
    domain_full_bytes: int,
    domain_tail_bits: int,
) -> int:
    total = int(domain_full_bytes) * int(bit_count_full_byte)
    if int(domain_tail_bits) > 0:
        tail_mask = (1 << int(domain_tail_bits)) - 1
        total += popcount_u64(int(selected_bits_mask) & int(tail_mask))
    return int(total)


def _selected_tail_data_bits_count(
    selected_bits_mask: int,
    bit_count_full_byte: int,
    tail_data_bits: int,
) -> int:
    if int(tail_data_bits) <= 0:
        return 0
    full_bytes = int(tail_data_bits) // 8
    rem_bits = int(tail_data_bits) % 8
    total = int(full_bytes) * int(bit_count_full_byte)
    if rem_bits > 0:
        rem_mask = (1 << rem_bits) - 1
        total += popcount_u64(int(selected_bits_mask) & int(rem_mask))
    return int(total)


def _selected_l2_domain_bit_counts(
    l2_size_bits: int,
    line_size_bytes: int,
    tag_bits: int,
    selected_data_bits_mask: int,
    selected_data_bit_count_full_byte: int,
    include_tag_bits: bool,
) -> Tuple[int, int, int, int, int]:
    if int(line_size_bytes) <= 0:
        raise ValueError("l2 line size must be > 0")
    if int(tag_bits) < 0:
        raise ValueError("l2 tag bits must be >= 0")
    if int(l2_size_bits) <= 0:
        raise ValueError("l2 size bits must be > 0")

    line_bits = int(line_size_bytes) * 8 + int(tag_bits)
    if line_bits <= 0:
        raise ValueError("l2 line bit-domain is empty")

    full_lines = int(l2_size_bits) // int(line_bits)
    tail_bits = int(l2_size_bits) % int(line_bits)

    per_line_selected_data = int(line_size_bytes) * int(selected_data_bit_count_full_byte)
    per_line_selected_tag = int(tag_bits) if include_tag_bits else 0

    selected_data_bits_total = int(full_lines) * int(per_line_selected_data)
    selected_tag_bits_total = int(full_lines) * int(per_line_selected_tag)

    if tail_bits > 0:
        tail_tag_bits = min(int(tag_bits), int(tail_bits))
        tail_data_bits = max(0, int(tail_bits) - int(tag_bits))
        tail_selected_data = _selected_tail_data_bits_count(
            selected_bits_mask=int(selected_data_bits_mask),
            bit_count_full_byte=int(selected_data_bit_count_full_byte),
            tail_data_bits=int(tail_data_bits),
        )
        tail_selected_tag = int(tail_tag_bits) if include_tag_bits else 0
        selected_data_bits_total += int(tail_selected_data)
        selected_tag_bits_total += int(tail_selected_tag)

    selected_total = int(selected_data_bits_total) + int(selected_tag_bits_total)
    return (
        int(selected_total),
        int(selected_data_bits_total),
        int(selected_tag_bits_total),
        int(full_lines),
        int(tail_bits),
    )


def _cycle_prefix_from_records(
    cycle_records: Sequence[CycleRecord],
) -> Tuple[List[int], List[int], int]:
    per_cycle: Dict[int, int] = defaultdict(int)
    for rec in cycle_records:
        per_cycle[int(rec.cycle)] += int(rec.multiplicity)
    items = sorted((int(c), int(w)) for c, w in per_cycle.items() if int(w) > 0)
    cycles = [c for c, _w in items]
    prefix = [0]
    total = 0
    for _cycle, w in items:
        total += int(w)
        prefix.append(total)
    return cycles, prefix, int(total)


def _l2_line_key(mem_space: str, thread_id: int, line_addr: int) -> Tuple[str, int, int]:
    if str(mem_space) == "local":
        return ("local", int(thread_id), int(line_addr))
    return (str(mem_space), -1, int(line_addr))


def _l1d_line_key(
    mem_space: str,
    sm_id: int,
    thread_id: int,
    line_addr: int,
) -> Tuple[str, int, int, int]:
    if str(mem_space) == "local":
        return ("local", int(sm_id), int(thread_id), int(line_addr))
    return (str(mem_space), int(sm_id), -1, int(line_addr))


L1DByteCycleMasks = Tuple[
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
]
L1DByteHistorySignature = Tuple[Tuple[int, L1DByteCycleMasks], ...]
CacheDataSegmentMetricRow = Tuple[
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
]


def _normalize_l1d_byte_history_signature(
    per_cycle: Mapping[int, Sequence[int]],
) -> L1DByteHistorySignature:
    rows: List[Tuple[int, L1DByteCycleMasks]] = []
    for cycle, masks in sorted(per_cycle.items()):
        rows.append(
            (
                int(cycle),
                (
                    int(masks[0]) & 0xFF,
                    int(masks[1]) & 0xFF,
                    int(masks[2]) & 0xFF,
                    int(masks[3]) & 0xFF,
                    int(masks[4]) & 0xFF,
                    int(masks[5]) & 0xFF,
                    int(masks[6]) & 0xFF,
                    int(masks[7]) & MASK64,
                    int(masks[8]) & MASK64,
                    int(masks[9]) & MASK64,
                    int(masks[10]) & MASK64,
                    int(masks[11]) & MASK64,
                    int(masks[12]) & MASK64,
                    int(masks[13]) & MASK64,
                ),
            )
        )
    return tuple(rows)


def _normalize_storage_group_mode(value: Any) -> str:
    mode = str(value if value is not None else "legacy").strip().lower()
    if mode not in STORAGE_GROUP_MODES:
        raise ValueError(
            "storage_group_mode must be one of {}; got {!r}".format(
                ", ".join(STORAGE_GROUP_MODES),
                value,
            )
        )
    return mode


def _group_cache_byte_histories(
    byte_reads: Mapping[Tuple[Any, int], Mapping[int, Sequence[int]]],
) -> Dict[Any, List[Tuple[L1DByteHistorySignature, int]]]:
    grouped: Dict[Any, Dict[L1DByteHistorySignature, int]] = defaultdict(dict)
    for (line_key, _byte_off), per_cycle in byte_reads.items():
        signature = _normalize_l1d_byte_history_signature(per_cycle)
        if not signature:
            continue
        per_line = grouped[line_key]
        per_line[signature] = int(per_line.get(signature, 0)) + 1
    return {
        line_key: [(signature, int(mult)) for signature, mult in per_line.items()]
        for line_key, per_line in grouped.items()
    }


def _group_l1d_byte_histories(
    byte_reads: Mapping[
        Tuple[Tuple[str, int, int, int], int],
        Mapping[int, Sequence[int]],
    ],
) -> Dict[Tuple[str, int, int, int], List[Tuple[L1DByteHistorySignature, int]]]:
    return _group_cache_byte_histories(byte_reads)


def _group_l2_byte_histories(
    byte_reads: Mapping[
        Tuple[Tuple[str, int, int], int],
        Mapping[int, Sequence[int]],
    ],
) -> Dict[Tuple[str, int, int], List[Tuple[L1DByteHistorySignature, int]]]:
    return _group_cache_byte_histories(byte_reads)


def _cache_history_masks_key(
    seg_rows: Sequence[Tuple[int, L1DByteCycleMasks]],
) -> Tuple[L1DByteCycleMasks, ...]:
    return tuple(
        (
            int(masks[0]) & 0xFF,
            int(masks[1]) & 0xFF,
            int(masks[2]) & 0xFF,
            int(masks[3]) & 0xFF,
            int(masks[4]) & 0xFF,
            int(masks[5]) & 0xFF,
            int(masks[6]) & 0xFF,
            int(masks[7]) & MASK64,
            int(masks[8]) & MASK64,
            int(masks[9]) & MASK64,
            int(masks[10]) & MASK64,
            int(masks[11]) & MASK64,
            int(masks[12]) & MASK64,
            int(masks[13]) & MASK64,
        )
        for _cycle, masks in seg_rows
    )


def _build_cache_data_segment_metric_plan_from_masks(
    rows_masks: Tuple[L1DByteCycleMasks, ...],
    *,
    selected_data_bits_mask: int,
    addr_domain_enabled: bool,
    trace_divergence_policy: str,
) -> Tuple[CacheDataSegmentMetricRow, ...]:
    n = len(rows_masks)
    suffix_due = [0] * (n + 1)
    suffix_sdc = [0] * (n + 1)
    suffix_unknown = [0] * (n + 1)
    suffix_trace_uncovered = [0] * (n + 1)
    suffix_trace_policy_override = [0] * (n + 1)
    suffix_semantic_due = [0] * (n + 1)
    suffix_trace_div = [0] * (n + 1)
    if addr_domain_enabled:
        suffix_addr_due = [0] * (n + 1)
        suffix_addr_sdc = [0] * (n + 1)
        suffix_addr_unknown = [0] * (n + 1)
        suffix_addr_trace_div = [0] * (n + 1)
        suffix_addr_oob_due = [0] * (n + 1)
        suffix_addr_alias_sdc = [0] * (n + 1)
        suffix_addr_selected = [0] * (n + 1)
    for idx in range(n - 1, -1, -1):
        (
            due_mask,
            sdc_mask,
            unknown_mask,
            trace_uncovered_mask,
            trace_policy_override_mask,
            semantic_due_mask,
            trace_div_mask,
            addr_selected_mask,
            addr_due_mask,
            addr_sdc_mask,
            addr_unknown_mask,
            addr_trace_div_mask,
            addr_oob_due_mask,
            addr_alias_sdc_mask,
        ) = rows_masks[idx]
        suffix_due[idx] = int(suffix_due[idx + 1]) | (int(due_mask) & 0xFF)
        suffix_sdc[idx] = int(suffix_sdc[idx + 1]) | (int(sdc_mask) & 0xFF)
        suffix_unknown[idx] = int(suffix_unknown[idx + 1]) | (int(unknown_mask) & 0xFF)
        suffix_trace_uncovered[idx] = (
            int(suffix_trace_uncovered[idx + 1]) | (int(trace_uncovered_mask) & 0xFF)
        )
        suffix_trace_policy_override[idx] = (
            int(suffix_trace_policy_override[idx + 1])
            | (int(trace_policy_override_mask) & 0xFF)
        )
        suffix_semantic_due[idx] = (
            int(suffix_semantic_due[idx + 1]) | (int(semantic_due_mask) & 0xFF)
        )
        suffix_trace_div[idx] = (
            int(suffix_trace_div[idx + 1]) | (int(trace_div_mask) & 0xFF)
        )
        if addr_domain_enabled:
            suffix_addr_due[idx] = (
                int(suffix_addr_due[idx + 1]) | (int(addr_due_mask) & MASK64)
            )
            suffix_addr_sdc[idx] = (
                int(suffix_addr_sdc[idx + 1]) | (int(addr_sdc_mask) & MASK64)
            )
            suffix_addr_unknown[idx] = (
                int(suffix_addr_unknown[idx + 1]) | (int(addr_unknown_mask) & MASK64)
            )
            suffix_addr_trace_div[idx] = (
                int(suffix_addr_trace_div[idx + 1]) | (int(addr_trace_div_mask) & MASK64)
            )
            suffix_addr_oob_due[idx] = (
                int(suffix_addr_oob_due[idx + 1]) | (int(addr_oob_due_mask) & MASK64)
            )
            suffix_addr_alias_sdc[idx] = (
                int(suffix_addr_alias_sdc[idx + 1]) | (int(addr_alias_sdc_mask) & MASK64)
            )
            suffix_addr_selected[idx] = (
                int(suffix_addr_selected[idx + 1]) | (int(addr_selected_mask) & MASK64)
            )

    metrics: List[CacheDataSegmentMetricRow] = []
    for idx in range(n):
        due_agg = int(suffix_due[idx]) & 0xFF
        sdc_agg = int(suffix_sdc[idx]) & 0xFF
        unknown_agg = int(suffix_unknown[idx]) & 0xFF
        due_agg &= (~unknown_agg) & 0xFF
        sdc_agg &= (~unknown_agg) & 0xFF
        sdc_agg &= (~due_agg) & 0xFF
        due_bits = popcount_u64(due_agg & int(selected_data_bits_mask))
        sdc_bits = popcount_u64(sdc_agg & int(selected_data_bits_mask))
        unknown_bits = popcount_u64(unknown_agg & int(selected_data_bits_mask))
        trace_uncovered_agg = int(suffix_trace_uncovered[idx]) & 0xFF
        trace_uncovered_bits = popcount_u64(
            trace_uncovered_agg & int(selected_data_bits_mask)
        )
        trace_policy_override_agg = int(suffix_trace_policy_override[idx]) & 0xFF
        trace_policy_override_bits_here = popcount_u64(
            trace_policy_override_agg & int(selected_data_bits_mask)
        )
        trace_policy_override_sdc_bits_here = popcount_u64(
            (trace_policy_override_agg & int(sdc_agg)) & int(selected_data_bits_mask)
        )
        trace_policy_override_due_bits_here = popcount_u64(
            (trace_policy_override_agg & int(due_agg)) & int(selected_data_bits_mask)
        )
        trace_policy_override_unknown_bits_here = popcount_u64(
            (trace_policy_override_agg & int(unknown_agg))
            & int(selected_data_bits_mask)
        )
        trace_policy_override_masked_bits_here = max(
            0,
            int(trace_policy_override_bits_here)
            - int(trace_policy_override_sdc_bits_here)
            - int(trace_policy_override_due_bits_here)
            - int(trace_policy_override_unknown_bits_here),
        )
        semantic_due_agg = int(suffix_semantic_due[idx]) & 0xFF
        semantic_due_bits = popcount_u64(semantic_due_agg & int(selected_data_bits_mask))
        trace_div_agg = int(suffix_trace_div[idx]) & 0xFF
        trace_due_agg = (
            trace_div_agg
            if _trace_divergence_target_class(trace_divergence_policy) == "due"
            else 0
        )
        base_due_agg = int(due_agg) & ((~int(semantic_due_agg)) & 0xFF)
        base_due_agg &= (~int(trace_due_agg)) & 0xFF
        base_due_bits = popcount_u64(int(base_due_agg) & int(selected_data_bits_mask))
        trace_div_bits_here = popcount_u64(trace_div_agg & int(selected_data_bits_mask))
        addr_bits_count = 0
        addr_due_bits = 0
        addr_sdc_bits = 0
        addr_unknown_bits = 0
        addr_oob_due_bits = 0
        addr_alias_sdc_bits = 0
        addr_trace_div_bits = 0
        if addr_domain_enabled:
            addr_selected_agg = int(suffix_addr_selected[idx]) & MASK64
            addr_bits_count = int(popcount_u64(int(addr_selected_agg)))
            addr_due_agg = int(suffix_addr_due[idx]) & MASK64
            addr_sdc_agg = int(suffix_addr_sdc[idx]) & MASK64
            addr_unknown_agg = int(suffix_addr_unknown[idx]) & MASK64
            addr_due_agg &= (~addr_unknown_agg) & MASK64
            addr_sdc_agg &= (~addr_unknown_agg) & MASK64
            addr_sdc_agg &= (~addr_due_agg) & MASK64
            addr_due_bits = popcount_u64(addr_due_agg & int(addr_selected_agg))
            addr_sdc_bits = popcount_u64(addr_sdc_agg & int(addr_selected_agg))
            addr_unknown_bits = popcount_u64(addr_unknown_agg & int(addr_selected_agg))
            addr_oob_due_agg = int(suffix_addr_oob_due[idx]) & MASK64
            addr_alias_sdc_agg = int(suffix_addr_alias_sdc[idx]) & MASK64
            addr_oob_due_bits = popcount_u64(addr_oob_due_agg & int(addr_selected_agg))
            addr_alias_sdc_bits = popcount_u64(
                addr_alias_sdc_agg & int(addr_selected_agg)
            )
            addr_trace_div_agg = int(suffix_addr_trace_div[idx]) & MASK64
            addr_trace_div_bits = popcount_u64(
                addr_trace_div_agg & int(addr_selected_agg)
            )
        metrics.append(
            (
                int(due_bits),
                int(sdc_bits),
                int(unknown_bits),
                int(trace_uncovered_bits),
                int(trace_policy_override_bits_here),
                int(trace_policy_override_sdc_bits_here),
                int(trace_policy_override_due_bits_here),
                int(trace_policy_override_unknown_bits_here),
                int(trace_policy_override_masked_bits_here),
                int(semantic_due_bits),
                int(base_due_bits),
                int(trace_div_bits_here),
                int(addr_bits_count),
                int(addr_due_bits),
                int(addr_sdc_bits),
                int(addr_unknown_bits),
                int(addr_oob_due_bits),
                int(addr_alias_sdc_bits),
                int(addr_trace_div_bits),
            )
        )
    return tuple(metrics)


@lru_cache(maxsize=None)
def _build_cache_data_segment_metric_plan_cached(
    rows_masks: Tuple[L1DByteCycleMasks, ...],
    selected_data_bits_mask: int,
    addr_domain_enabled: bool,
    trace_divergence_policy: str,
) -> Tuple[CacheDataSegmentMetricRow, ...]:
    return _build_cache_data_segment_metric_plan_from_masks(
        rows_masks,
        selected_data_bits_mask=int(selected_data_bits_mask),
        addr_domain_enabled=bool(addr_domain_enabled),
        trace_divergence_policy=str(trace_divergence_policy),
    )


def _build_cache_data_segment_metric_plan(
    seg_rows: Sequence[Tuple[int, L1DByteCycleMasks]],
    *,
    selected_data_bits_mask: int,
    addr_domain_enabled: bool,
    trace_divergence_policy: str,
    use_cache: bool,
) -> Tuple[CacheDataSegmentMetricRow, ...]:
    rows_masks = _cache_history_masks_key(seg_rows)
    if use_cache:
        return _build_cache_data_segment_metric_plan_cached(
            rows_masks,
            int(selected_data_bits_mask),
            bool(addr_domain_enabled),
            str(trace_divergence_policy),
        )
    return _build_cache_data_segment_metric_plan_from_masks(
        rows_masks,
        selected_data_bits_mask=int(selected_data_bits_mask),
        addr_domain_enabled=bool(addr_domain_enabled),
        trace_divergence_policy=str(trace_divergence_policy),
    )


def _cache_actual_tag_bit_positions(sample_tag_bits: int) -> List[int]:
    bits = max(0, int(sample_tag_bits))
    return [63 - idx for idx in range(bits)]


def _sampling_component_int(
    fi_space: Optional[Dict[str, Any]],
    component: str,
    key: str,
    default: int = 0,
) -> int:
    if not isinstance(fi_space, dict):
        return int(default)
    comp = fi_space.get("component_domains", {})
    if isinstance(comp, dict):
        row = comp.get(str(component), {})
        if isinstance(row, dict) and key in row:
            try:
                return int(row.get(key, default))
            except Exception:
                return int(default)
    root_key = f"{component}_{key}"
    try:
        return int(fi_space.get(root_key, default))
    except Exception:
        return int(default)


def _build_global_readonly_line_state(
    trace_template: Dict[str, Any],
    line_size_bytes: int,
    *,
    scope_mode: str,
) -> Dict[Tuple[int, int], Dict[str, Any]]:
    events_raw = trace_template.get("events", [])
    out: Dict[Tuple[int, int], Dict[str, Any]] = {}
    if not isinstance(events_raw, list):
        return out
    for idx, raw in enumerate(events_raw):
        if not isinstance(raw, dict):
            continue
        kind = str(raw.get("kind", "")).strip().lower()
        if kind not in ("load", "store"):
            continue
        pred_raw = raw.get("pred")
        if isinstance(pred_raw, dict) and int(pred_raw.get("val", 1)) == 0:
            continue
        mem_space = canonical_raw_event_space(raw)
        if mem_space != "global":
            continue
        addr_raw = raw.get("mem_addr", raw.get("base"))
        if addr_raw is None:
            continue
        try:
            addr = int(parse_int(str(addr_raw)))
        except Exception:
            continue
        size_bytes = access_size_bytes_for_raw_event(raw)
        if size_bytes <= 0:
            continue
        cycle = int(raw.get("cycle", idx))
        sm_id = int(raw.get("sm_id", -1))
        scope = int(sm_id) if scope_mode == "l1d" else 0
        line_addr = int(addr // int(line_size_bytes))
        key = (int(scope), int(line_addr))
        state = out.get(key)
        if state is None:
            state = {
                "first_load_cycle": None,
                "first_load_event_index": None,
                "load_cycles": set(),
                "store_cycles": set(),
                "first_event_by_cycle": {},
                "event_indices_by_cycle": defaultdict(list),
                "thread_ids_by_cycle": defaultdict(set),
                "bytes_by_offset": {},
                "has_store": False,
            }
            out[key] = state
        if kind == "store":
            state["has_store"] = True
            state["store_cycles"].add(int(cycle))
            continue
        first_cycle = state.get("first_load_cycle")
        first_event = state.get("first_load_event_index")
        if (
            first_cycle is None
            or int(cycle) < int(first_cycle)
            or (int(cycle) == int(first_cycle) and int(idx) < int(first_event))
        ):
            state["first_load_cycle"] = int(cycle)
            state["first_load_event_index"] = int(idx)
        state["load_cycles"].add(int(cycle))
        cycle_events = state["first_event_by_cycle"]
        prev_event = cycle_events.get(int(cycle))
        if prev_event is None or int(idx) < int(prev_event):
            cycle_events[int(cycle)] = int(idx)
        state["event_indices_by_cycle"][int(cycle)].append(int(idx))
        state["thread_ids_by_cycle"][int(cycle)].add(int(raw.get("thread_id", -1)))
        if "dst_val" not in raw:
            continue
        try:
            dst_val = int(parse_int(str(raw.get("dst_val")))) & MASK64
        except Exception:
            continue
        width_bits = int(raw.get("width_bits", size_bytes * 8))
        if width_bits <= 0:
            width_bits = size_bytes * 8
        access_bytes = max(1, min(int(size_bytes), max(1, int(width_bits) // 8)))
        bytes_by_offset = state["bytes_by_offset"]
        for byte_i in range(access_bytes):
            off = int((addr + byte_i) % int(line_size_bytes))
            byte_v = int((dst_val >> (8 * byte_i)) & 0xFF)
            prev = bytes_by_offset.get(int(off))
            if prev is None:
                bytes_by_offset[int(off)] = int(byte_v)
    filtered: Dict[Tuple[int, int], Dict[str, Any]] = {}
    for key, state in out.items():
        if state.get("first_load_cycle") is None:
            # Pure store-only lines are not part of the readonly load domain.
            continue
        state["load_cycles"] = sorted(int(v) for v in state.get("load_cycles", set()))
        state["store_cycles"] = sorted(int(v) for v in state.get("store_cycles", set()))
        state["event_indices_by_cycle"] = {
            int(cycle): sorted(int(v) for v in values)
            for cycle, values in state.get("event_indices_by_cycle", {}).items()
        }
        state["thread_ids_by_cycle"] = {
            int(cycle): sorted(int(v) for v in values)
            for cycle, values in state.get("thread_ids_by_cycle", {}).items()
        }
        filtered[key] = state
    return filtered


def _filter_cache_fault_sites_by_trace_space(
    *,
    sites: Sequence[Any],
    event_by_index: Dict[int, Dict[str, Any]],
    allowed_spaces: Sequence[str],
) -> List[Any]:
    allowed = {str(v) for v in allowed_spaces}
    out: List[Any] = []
    for rec in sites:
        if isinstance(rec, dict):
            effective_space = canonical_space(rec.get("mem_space"))
            try:
                event_index = int(rec.get("event_index", -1))
            except Exception:
                event_index = -1
        elif _is_compact_cache_site_row(rec):
            effective_space = canonical_space(rec[1])
            try:
                event_index = int(rec[7])
            except Exception:
                event_index = -1
        else:
            continue
        raw = event_by_index.get(int(event_index))
        if isinstance(raw, dict):
            raw_space = canonical_raw_event_space(raw)
            if raw_space == "param":
                continue
            if raw_space is not None:
                effective_space = str(raw_space)
        if str(effective_space) not in allowed:
            continue
        out.append(rec)
    return out


@dataclass
class SharedCacheTraceViews:
    event_by_index: Dict[int, Dict[str, Any]]
    l1d_line_store_cycles_sorted: Dict[Tuple[str, int, int, int], Tuple[int, ...]]
    l1d_line_first_valid_cycle: Dict[Tuple[str, int, int, int], int]
    l2_line_store_cycles_sorted: Dict[Tuple[str, int, int], Tuple[int, ...]]
    l2_line_first_load_cycle: Dict[Tuple[str, int, int], int]


@lru_cache(maxsize=None)
def _trace_event_by_index_cached(trace_template_key: str) -> Dict[int, Dict[str, Any]]:
    trace_template = _parse_trace_template_cached(str(trace_template_key))
    trace_events_raw = trace_template.get("events", [])
    event_by_index: Dict[int, Dict[str, Any]] = {}
    if isinstance(trace_events_raw, list):
        for idx, raw in enumerate(trace_events_raw):
            if not isinstance(raw, dict):
                continue
            event_by_index[int(idx)] = raw
    return event_by_index


def _cache_fault_site_field_name(component: str) -> str:
    comp = str(component).strip().lower()
    if comp == "l1d":
        return "l1d_fault_sites"
    if comp == "l2":
        return "l2_fault_sites"
    raise ValueError(f"unsupported cache fault component for shared site view: {component!r}")


def _analyzer_l2_sites_alias_l1d(analyzer_any: Mapping[str, Any]) -> bool:
    meta = analyzer_any.get("exact_meta", {})
    if not isinstance(meta, Mapping):
        return False
    if meta.get("l2_fault_sites_alias") != "l1d_fault_sites":
        return False
    l2_sites = analyzer_any.get("l2_fault_sites", [])
    return not l2_sites


@lru_cache(maxsize=None)
def _load_filtered_cache_fault_sites_for_compute_cached(
    component: str,
    analyzer_path_key: str,
    trace_template_key: str,
    normalize_trace_coverage: bool = False,
) -> Tuple[Any, ...]:
    analyzer_any = _load_analyzer_output_for_compute_cached(
        str(analyzer_path_key),
        bool(normalize_trace_coverage),
    )
    if not isinstance(analyzer_any, dict):
        raise ValueError("analyzer output must be a JSON object")
    normalized_component = str(component).strip().lower()
    if normalized_component == "l2" and _analyzer_l2_sites_alias_l1d(analyzer_any):
        return tuple(
            _l1d_cache_site_record_as_l2(rec)
            for rec in _load_filtered_cache_fault_sites_for_compute_cached(
                "l1d",
                str(analyzer_path_key),
                str(trace_template_key),
                bool(normalize_trace_coverage),
            )
        )
    raw_field = _cache_fault_site_field_name(component)
    sites_raw = analyzer_any.get(raw_field, [])
    if not isinstance(sites_raw, list):
        raise ValueError(f"analyzer output missing {raw_field} list")
    candidate_sites = [
        rec
        for rec in sites_raw
        if isinstance(rec, dict) or _is_compact_cache_site_row(rec)
    ]
    filtered = _filter_cache_fault_sites_by_trace_space(
        sites=candidate_sites,
        event_by_index=_trace_event_by_index_cached(str(trace_template_key)),
        allowed_spaces=("global", "local"),
    )
    return tuple(filtered)


def _load_filtered_cache_fault_sites_for_compute(
    component: str,
    analyzer_output: Path,
    trace_template: Path,
    *,
    normalize_trace_coverage: bool = False,
) -> Tuple[Any, ...]:
    return _load_filtered_cache_fault_sites_for_compute_cached(
        str(component).strip().lower(),
        _analyzer_output_cache_key(Path(analyzer_output)),
        _path_cache_key(Path(trace_template)),
        bool(normalize_trace_coverage),
    )


@lru_cache(maxsize=None)
def _load_cache_site_masks_for_compute_cached(
    component: str,
    analyzer_path_key: str,
    trace_template_key: str,
    normalize_trace_coverage: bool,
    trace_expanding_policy: str,
    trace_uncovered_mode: str,
    trace_expanding_resolution_mode: str,
) -> Optional[Tuple[Tuple[int, int, int, int, int], ...]]:
    normalized_component = str(component).strip().lower()
    if normalized_component == "l2":
        analyzer_any = _load_analyzer_output_for_compute_cached(
            str(analyzer_path_key),
            bool(normalize_trace_coverage),
        )
        if not isinstance(analyzer_any, dict):
            raise ValueError("analyzer output must be a JSON object")
        if _analyzer_l2_sites_alias_l1d(analyzer_any):
            return _load_cache_site_masks_for_compute_cached(
                "l1d",
                str(analyzer_path_key),
                str(trace_template_key),
                bool(normalize_trace_coverage),
                str(trace_expanding_policy),
                str(trace_uncovered_mode),
                str(trace_expanding_resolution_mode),
            )
    sites = _load_filtered_cache_fault_sites_for_compute_cached(
        normalized_component,
        str(analyzer_path_key),
        str(trace_template_key),
        bool(normalize_trace_coverage),
    )
    masks = _cpp_classify_site_masks_many(
        sites,
        trace_expanding_policy=str(trace_expanding_policy),
        trace_uncovered_mode=str(trace_uncovered_mode),
        trace_expanding_resolution_mode=str(trace_expanding_resolution_mode),
    )
    if masks is None:
        return None
    return tuple(
        (
            int(row[0]),
            int(row[1]),
            int(row[2]),
            int(row[3]),
            int(row[4]),
        )
        for row in masks
    )


def _load_cache_site_masks_for_compute(
    component: str,
    analyzer_output: Path,
    trace_template: Path,
    *,
    normalize_trace_coverage: bool = False,
    trace_expanding_policy: str,
    trace_uncovered_mode: str,
    trace_expanding_resolution_mode: str,
) -> Optional[Tuple[Tuple[int, int, int, int, int], ...]]:
    return _load_cache_site_masks_for_compute_cached(
        str(component).strip().lower(),
        _analyzer_output_cache_key(Path(analyzer_output)),
        _path_cache_key(Path(trace_template)),
        bool(normalize_trace_coverage),
        str(trace_expanding_policy),
        str(trace_uncovered_mode),
        str(trace_expanding_resolution_mode),
    )


def _build_shared_cache_trace_views(
    trace_template_key: str,
    *,
    l1d_line_size_bytes: int,
    l1d_write_allocate: bool,
    l2_line_size_bytes: int,
    build_l1d: bool,
    build_l2: bool,
) -> SharedCacheTraceViews:
    if build_l1d and int(l1d_line_size_bytes) <= 0:
        raise ValueError("--l1d-line-size-bytes must be > 0")
    if build_l2 and int(l2_line_size_bytes) <= 0:
        raise ValueError("--l2-line-size-bytes must be > 0")

    trace_template = _parse_trace_template_cached(str(trace_template_key))
    trace_events_raw = trace_template.get("events", [])
    l1d_line_store_cycles: Dict[Tuple[str, int, int, int], Set[int]] = defaultdict(set)
    l1d_line_first_valid_cycle: Dict[Tuple[str, int, int, int], int] = {}
    l2_line_store_cycles: Dict[Tuple[str, int, int], Set[int]] = defaultdict(set)
    l2_line_first_load_cycle: Dict[Tuple[str, int, int], int] = {}

    if isinstance(trace_events_raw, list):
        for idx, raw in enumerate(trace_events_raw):
            if not isinstance(raw, dict):
                continue
            kind = str(raw.get("kind", "")).strip().lower()
            if kind not in ("load", "store"):
                continue
            pred_raw = raw.get("pred")
            if isinstance(pred_raw, dict) and int(pred_raw.get("val", 1)) == 0:
                continue
            mem_space = canonical_raw_event_space(raw)
            if mem_space not in ("global", "local"):
                continue
            if raw.get("mem_addr") is None and raw.get("base") is None:
                continue
            try:
                addr = int(parse_int(raw.get("mem_addr", raw.get("base"))))
            except Exception:
                continue
            size_bytes = access_size_bytes_for_raw_event(raw)
            if size_bytes <= 0:
                continue
            cycle = int(raw.get("cycle", idx))
            thread_id = int(raw.get("thread_id", -1))

            if build_l1d:
                sm_id_raw = raw.get("sm_id")
                if sm_id_raw is not None:
                    sm_id = int(sm_id_raw)
                    for byte_i in range(int(size_bytes)):
                        byte_addr = int(addr + byte_i)
                        line_addr = int(byte_addr // int(l1d_line_size_bytes))
                        line_key = _l1d_line_key(
                            mem_space=str(mem_space),
                            sm_id=int(sm_id),
                            thread_id=int(thread_id),
                            line_addr=int(line_addr),
                        )
                        if kind == "store":
                            l1d_line_store_cycles[line_key].add(int(cycle))
                        if kind == "load" or (kind == "store" and bool(l1d_write_allocate)):
                            prev = l1d_line_first_valid_cycle.get(line_key)
                            if prev is None or int(cycle) < int(prev):
                                l1d_line_first_valid_cycle[line_key] = int(cycle)

            if build_l2:
                for byte_i in range(int(size_bytes)):
                    byte_addr = int(addr + byte_i)
                    line_addr = int(byte_addr // int(l2_line_size_bytes))
                    line_key = _l2_line_key(
                        mem_space=str(mem_space),
                        thread_id=int(thread_id),
                        line_addr=int(line_addr),
                    )
                    if kind == "store":
                        l2_line_store_cycles[line_key].add(int(cycle))
                    else:
                        prev = l2_line_first_load_cycle.get(line_key)
                        if prev is None or int(cycle) < int(prev):
                            l2_line_first_load_cycle[line_key] = int(cycle)

    return SharedCacheTraceViews(
        event_by_index=_trace_event_by_index_cached(str(trace_template_key)),
        l1d_line_store_cycles_sorted={
            line_key: tuple(sorted(int(v) for v in rows))
            for line_key, rows in l1d_line_store_cycles.items()
        },
        l1d_line_first_valid_cycle=dict(l1d_line_first_valid_cycle),
        l2_line_store_cycles_sorted={
            line_key: tuple(sorted(int(v) for v in rows))
            for line_key, rows in l2_line_store_cycles.items()
        },
        l2_line_first_load_cycle=dict(l2_line_first_load_cycle),
    )


@lru_cache(maxsize=None)
def _load_shared_cache_trace_views_cached(
    trace_template_key: str,
    l1d_line_size_bytes: int,
    l1d_write_allocate: bool,
    l2_line_size_bytes: int,
    build_l1d: bool,
    build_l2: bool,
) -> SharedCacheTraceViews:
    return _build_shared_cache_trace_views(
        str(trace_template_key),
        l1d_line_size_bytes=int(l1d_line_size_bytes),
        l1d_write_allocate=bool(l1d_write_allocate),
        l2_line_size_bytes=int(l2_line_size_bytes),
        build_l1d=bool(build_l1d),
        build_l2=bool(build_l2),
    )


def _shared_cache_trace_view_targets_for_args(
    args: argparse.Namespace,
) -> Tuple[bool, bool]:
    active_raw = getattr(args, "_batch_active_components", None)
    active_components = {
        str(comp).strip().lower()
        for comp in (
            active_raw
            if isinstance(active_raw, (list, tuple, set, frozenset))
            else [getattr(args, "fault_component", "")]
        )
        if str(comp).strip()
    }
    if not active_components:
        active_components = {str(getattr(args, "fault_component", "")).strip().lower()}
    return ("l1d" in active_components), ("l2" in active_components)


def _load_shared_cache_trace_views_for_args(
    args: argparse.Namespace,
) -> SharedCacheTraceViews:
    trace_template_path = getattr(args, "trace_template", None)
    if trace_template_path is None:
        raise ValueError("--trace-template is required for cache trace views")
    build_l1d, build_l2 = _shared_cache_trace_view_targets_for_args(args)
    return _load_shared_cache_trace_views_cached(
        _path_cache_key(Path(trace_template_path)),
        int(getattr(args, "l1d_line_size_bytes", L1D_LINE_SIZE_BYTES_DEFAULT)),
        bool(int(getattr(args, "l1d_write_allocate", 0))),
        int(getattr(args, "l2_line_size_bytes", L2_LINE_SIZE_BYTES_DEFAULT)),
        bool(build_l1d),
        bool(build_l2),
    )


def _line_state_load_window_stable(state: Dict[str, Any]) -> bool:
    load_cycles_raw = state.get("load_cycles", [])
    if not isinstance(load_cycles_raw, list) or not load_cycles_raw:
        return False
    try:
        load_cycles = sorted(int(v) for v in load_cycles_raw)
    except Exception:
        return False
    store_cycles_raw = state.get("store_cycles", [])
    if not isinstance(store_cycles_raw, list):
        store_cycles_raw = []
    try:
        store_cycles = [int(v) for v in store_cycles_raw]
    except Exception:
        store_cycles = []
    first_load = int(load_cycles[0])
    last_load = int(load_cycles[-1])
    return not any(first_load <= int(cycle) <= last_load for cycle in store_cycles)


def _line_state_has_post_load_store(state: Dict[str, Any]) -> bool:
    load_cycles_raw = state.get("load_cycles", [])
    if not isinstance(load_cycles_raw, list) or not load_cycles_raw:
        return False
    try:
        last_load = max(int(v) for v in load_cycles_raw)
    except Exception:
        return False
    store_cycles_raw = state.get("store_cycles", [])
    if not isinstance(store_cycles_raw, list):
        return False
    for cycle in store_cycles_raw:
        try:
            if int(cycle) > int(last_load):
                return True
        except Exception:
            continue
    return False


def _merge_global_readonly_line_bytes(
    line_states: Dict[Tuple[int, int], Dict[str, Any]]
) -> Optional[Dict[int, Dict[int, int]]]:
    merged: Dict[int, Dict[int, int]] = {}
    for (_scope, line_addr), state in line_states.items():
        if not _line_state_load_window_stable(state):
            continue
        bytes_by_offset = state.get("bytes_by_offset", {})
        if not isinstance(bytes_by_offset, dict):
            continue
        dst = merged.setdefault(int(line_addr), {})
        for off_raw, byte_raw in bytes_by_offset.items():
            off = int(off_raw)
            byte_v = int(byte_raw) & 0xFF
            prev = dst.get(int(off))
            if prev is not None and int(prev) != int(byte_v):
                return None
            dst[int(off)] = int(byte_v)
    return merged


# Cache-tag accounting below treats tag bits as cache-line identity faults.
# Same-line tag misses and reachable wrong-line aliases are resolved by the
# identity-byte comparison in _exact_l1d_tag_counts_global_readonly_alias, so no
# separate cache-timing or trace-delta tag model is retained here.

def _parse_output_spec_ranges(
    trace_template: Dict[str, Any],
) -> List[Tuple[str, int, int]]:
    out: List[Tuple[str, int, int]] = []
    rows = trace_template.get("output_spec", [])
    if not isinstance(rows, list):
        return out
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        cspace = canonical_space(raw.get("space"))
        if cspace is None:
            continue
        try:
            base = int(parse_int(str(raw.get("base"))))
            size = int(parse_int(str(raw.get("bytes"))))
        except Exception:
            continue
        if size <= 0:
            continue
        out.append((str(cspace), int(base), int(size)))
    return out


def _raw_store_matches_output_ranges(
    raw: Dict[str, Any],
    output_ranges: Sequence[Tuple[str, int, int]],
) -> bool:
    if bool(raw.get("is_output_store", False)):
        return True
    if not output_ranges:
        return False
    if str(raw.get("kind", "")).strip().lower() != "store":
        return False
    cspace = canonical_space(raw.get("mem_space") or raw.get("space"))
    if cspace is None:
        return False
    addr_raw = raw.get("mem_addr", raw.get("base"))
    if addr_raw is None:
        return False
    try:
        addr = int(parse_int(addr_raw))
        size_bytes = int(access_size_bytes_for_raw_event(raw))
    except Exception:
        return False
    if size_bytes <= 0:
        return False
    end = int(addr) + int(size_bytes)
    for spec_space, base, size in output_ranges:
        if canonical_space(spec_space) != cspace:
            continue
        hi = int(base) + int(size)
        if int(addr) < int(hi) and int(end) > int(base):
            return True
    return False


# Cache-tag sites are now handled as cache-line identity faults by
# _cache_tag_output_relevant_lookup_masks and
# _exact_l1d_tag_counts_global_readonly_alias below.  The previous tag-local
# trace-delta replay path was intentionally removed because a wrong-line tag hit
# can change multiple data bits and therefore cannot be converted into an SDC
# proof by reusing per-bit output-relevance masks.

def _cache_tag_output_relevant_lookup_masks(
    *,
    cache_sites: Sequence[Dict[str, Any]],
    line_size_bytes: int,
    cache_component: str,
    scope_mode: str,
    trace_expanding_policy: str = CANONICAL_TRACE_EXPANDING_POLICY,
    trace_uncovered_mode: str = CANONICAL_TRACE_UNCOVERED_MODE,
    trace_expanding_resolution_mode: str = CANONICAL_TRACE_EXPANDING_RESOLUTION_MODE,
    trace_divergence_policy: str = CANONICAL_TRACE_DIVERGENCE_POLICY,
) -> Dict[Tuple[int, int, int], Dict[int, int]]:
    """Return output-relevant load-byte masks keyed by cache scope, line, and cycle.

    Cache-tag faults are cache-line identity faults.  A tag flip matters only
    when a later lookup that is already output-relevant for the golden value can
    be served by a different resident line.  This helper reuses only the
    single-byte output-relevance evidence of the golden lookup to decide whether
    a lookup must be considered; it does not use that mask to classify a
    multi-byte wrong-line value change as SDC.
    """

    component = str(cache_component).strip().lower() or "l1d"
    expected_kind = "l2_load" if component == "l2" else "l1d_load"
    scope_mode_n = str(scope_mode).strip().lower() or component
    out: Dict[Tuple[int, int, int], Dict[int, int]] = defaultdict(dict)
    for rec in cache_sites:
        if str(_cache_site_row_field(rec, "site_kind", "")) != expected_kind:
            continue
        mem_space = canonical_space(_cache_site_row_field(rec, "mem_space"))
        if mem_space != "global":
            continue
        try:
            addr = int(_cache_site_row_field(rec, "addr", 0))
            cycle = int(_cache_site_row_field(rec, "cycle", -1))
        except Exception:
            continue
        if cycle < 0:
            continue
        if int(line_size_bytes) <= 0:
            continue
        scope = (
            int(_cache_site_row_field(rec, "sm_id", -1))
            if scope_mode_n == "l1d"
            else 0
        )
        if scope_mode_n == "l1d" and scope < 0:
            continue
        line_addr = int(addr // int(line_size_bytes))
        byte_off = int(addr % int(line_size_bytes))
        try:
            (
                due_mask,
                sdc_mask,
                unknown_mask,
                _trace_uncovered_mask,
                _trace_policy_override_mask,
            ) = final_due_sdc_masks_for_site_extended(
                rec=rec,
                trace_expanding_policy=trace_expanding_policy,
                trace_uncovered_mode=trace_uncovered_mode,
                trace_expanding_resolution_mode=trace_expanding_resolution_mode,
            )
        except Exception:
            # If the golden lookup record cannot be interpreted, the lookup is
            # still a possible output-relevant use but the byte evidence is not
            # reliable enough for a Masked proof.
            relevant_mask = 0xFF
        else:
            trace_mask_this_site = (
                parse_mask(_cache_site_row_field(rec, "trace_expanding_mask_this_site", 0))
                & 0xFF
            )
            (
                due_mask,
                sdc_mask,
                unknown_mask,
                _trace_div_mask_this_site,
            ) = _apply_trace_divergence_policy_to_masks(
                due_mask=int(due_mask),
                sdc_mask=int(sdc_mask),
                unknown_mask=int(unknown_mask),
                trace_mask=int(trace_mask_this_site),
                width_bits=8,
                policy=trace_divergence_policy,
            )
            due_mask &= 0xFF
            unknown_mask &= 0xFF
            due_mask &= (~unknown_mask) & 0xFF
            sdc_mask &= (~due_mask) & 0xFF
            sdc_mask &= (~unknown_mask) & 0xFF
            # SDC bits are output-relevant by proof.  Unknown bits are also kept
            # as relevant because SARA cannot prove them harmless.  DUE bits do
            # not make a tag alias SDC; they are retained only through Unknown if
            # the output-relevance evidence is incomplete.
            relevant_mask = (int(sdc_mask) | int(unknown_mask)) & 0xFF
        if relevant_mask == 0:
            continue
        key = (int(scope), int(line_addr), int(cycle))
        prev = int(out[key].get(int(byte_off), 0))
        out[key][int(byte_off)] = (prev | int(relevant_mask)) & 0xFF
    return out


def _exact_l1d_tag_counts_global_readonly_alias(
    *,
    trace_template: Dict[str, Any],
    trace_path: Path,
    fi_space: Optional[Dict[str, Any]],
    l1d_sites: Sequence[Dict[str, Any]],
    shader_prefix: Dict[int, Tuple[List[int], List[int], int]],
    line_size_bytes: int,
    size_bits: int,
    sample_tag_bits: int,
    ge_mode: bool,
    addr_ranges: Optional[Sequence[Dict[str, Any]]] = None,
    cache_component: str = "l1d",
    scope_mode: str = "l1d",
    global_prefill: bool = False,
    trace_expanding_policy: str = CANONICAL_TRACE_EXPANDING_POLICY,
    trace_uncovered_mode: str = CANONICAL_TRACE_UNCOVERED_MODE,
    trace_expanding_resolution_mode: str = CANONICAL_TRACE_EXPANDING_RESOLUTION_MODE,
    trace_divergence_policy: str = CANONICAL_TRACE_DIVERGENCE_POLICY,
) -> Optional[Dict[str, Any]]:
    """Classify cache-tag bits as cache-line identity faults.

    A tag bit is Masked unless the corrupted tag can make a later
    output-relevant lookup select another resident line.  When such a lookup is
    present, SARA compares the aliased line bytes with the bytes returned by the
    golden lookup.  Equal bytes remain Masked; unequal or missing bytes are
    Unknown because a wrong-line hit can change multiple data bits and therefore
    cannot reuse the per-bit output-relevance mask as an SDC proof.
    """

    del trace_path, addr_ranges
    if any(
        canonical_space(_cache_site_row_field(rec, "mem_space")) != "global"
        for rec in l1d_sites
    ):
        return None
    cache_component = str(cache_component).strip().lower() or "l1d"
    scope_mode = str(scope_mode).strip().lower() or cache_component
    nset = _sampling_component_int(fi_space, cache_component, "nset", 0)
    if nset <= 0:
        return None
    per_line_bits = int(line_size_bytes) * 8 + int(sample_tag_bits)
    if per_line_bits <= 0:
        return None
    line_capacity = int(size_bits) // int(per_line_bits)
    if line_capacity <= 0:
        return None
    line_states = _build_global_readonly_line_state(
        trace_template,
        int(line_size_bytes),
        scope_mode=str(scope_mode),
    )
    if not line_states:
        return {
            "counts": {"masked": 0, "sdc": 0, "due": 0, "unknown": 0},
            "ordered_pairs": 0,
            "potential_ordered_pairs": 0,
            "replay_intervals": 0,
            "alias_intervals": 0,
            "fallback_reachable_intervals": 0,
            "fallback_reason": "no_global_cache_lookup",
            "self_miss_intervals": 0,
            "self_miss_sdc": 0,
            "self_miss_source_lines": 0,
            "self_miss_sampled_bits": 0,
            "multievent_cycles": 0,
            "multithread_cycles": 0,
            "multievent_examples": [],
            "self_miss_examples": [],
            "byte_match_intervals": 0,
            "byte_mismatch_intervals": 0,
            "missing_byte_intervals": 0,
            "examples": [],
            "mode": f"exact_{cache_component}_tag_identity_byte_compare",
        }

    sample_positions = _cache_actual_tag_bit_positions(int(sample_tag_bits))
    prefill_cycle = None
    if bool(global_prefill):
        events_raw_prefill = trace_template.get("events", [])
        if isinstance(events_raw_prefill, list) and events_raw_prefill:
            prefill_cycles = [
                int(raw.get("cycle", idx))
                for idx, raw in enumerate(events_raw_prefill)
                if isinstance(raw, dict)
            ]
            if prefill_cycles:
                prefill_cycle = min(prefill_cycles)

    stable_line_states = {
        key: state
        for key, state in line_states.items()
        if _line_state_load_window_stable(state)
    }
    global_line_bytes = _merge_global_readonly_line_bytes(stable_line_states)
    line_bytes_mergeable = global_line_bytes is not None
    if global_line_bytes is None:
        global_line_bytes = {}
    scope_line_counts: Counter = Counter(int(scope) for scope, _line in line_states.keys())
    line_capacity_exceeded = any(int(v) > int(line_capacity) for v in scope_line_counts.values())

    relevant_lookup_masks = _cache_tag_output_relevant_lookup_masks(
        cache_sites=l1d_sites,
        line_size_bytes=int(line_size_bytes),
        cache_component=str(cache_component),
        scope_mode=str(scope_mode),
        trace_expanding_policy=str(trace_expanding_policy),
        trace_uncovered_mode=str(trace_uncovered_mode),
        trace_expanding_resolution_mode=str(trace_expanding_resolution_mode),
        trace_divergence_policy=str(trace_divergence_policy),
    )

    counts = {"masked": 0, "sdc": 0, "due": 0, "unknown": 0}
    examples: List[Dict[str, Any]] = []
    ordered_pairs = 0
    alias_intervals = 0
    byte_match_intervals = 0
    missing_byte_intervals = 0
    byte_mismatch_intervals = 0

    nset_i = int(nset)
    for (scope_raw, source_line_raw), source_state in sorted(line_states.items()):
        scope = int(scope_raw)
        source_line = int(source_line_raw)
        source_first = source_state.get("first_load_cycle")
        if source_first is None:
            continue
        source_active_from = (
            int(prefill_cycle)
            if bool(global_prefill) and prefill_cycle is not None
            else int(source_first) + 1
        )
        shader_prefix_row = shader_prefix.get(scope)
        if shader_prefix_row is None:
            continue
        cycles_shader, prefix_shader, _shader_mass_total = shader_prefix_row
        source_tag = int(source_line) // nset_i
        set_idx = int(source_line) % nset_i
        source_stable = (scope, source_line) in stable_line_states
        source_line_bytes = global_line_bytes.get(int(source_line), {})

        for bitpos_raw in sample_positions:
            bitpos = int(bitpos_raw)
            target_tag = int(source_tag) ^ (1 << int(bitpos))
            target_line = int(set_idx) + nset_i * int(target_tag)
            target_state = line_states.get((scope, target_line))
            if target_state is None:
                continue
            target_cycles = [
                int(c)
                for c in target_state.get("load_cycles", [])
                if int(c) >= int(source_active_from)
                and (scope, int(target_line), int(c)) in relevant_lookup_masks
            ]
            if not target_cycles:
                continue
            ordered_pairs += 1
            target_stable = (scope, int(target_line)) in stable_line_states
            prev_boundary = int(source_active_from)
            for cyc in target_cycles:
                boundary = int(cyc) + 1 if ge_mode else int(cyc)
                if boundary <= prev_boundary:
                    continue
                mass = range_sum(cycles_shader, prefix_shader, int(prev_boundary), int(boundary))
                if mass <= 0:
                    prev_boundary = int(boundary)
                    continue
                alias_intervals += 1
                relevant_offsets = relevant_lookup_masks.get(
                    (scope, int(target_line), int(cyc)), {}
                )
                cls = "masked"
                reason = "tag_identity_bytes_match"
                if (
                    not line_bytes_mergeable
                    or line_capacity_exceeded
                    or not source_stable
                    or not target_stable
                ):
                    cls = "unknown"
                    reason = "tag_identity_line_byte_evidence_missing"
                else:
                    target_bytes = target_state.get("bytes_by_offset", {})
                    if not isinstance(target_bytes, dict):
                        target_bytes = {}
                    for off_raw in sorted(relevant_offsets):
                        off = int(off_raw)
                        if off not in source_line_bytes or off not in target_bytes:
                            cls = "unknown"
                            reason = "tag_identity_byte_evidence_missing"
                            break
                        src_byte = int(source_line_bytes.get(off, 0)) & 0xFF
                        tgt_byte = int(target_bytes.get(off, 0)) & 0xFF
                        if src_byte != tgt_byte:
                            cls = "unknown"
                            reason = "tag_identity_byte_mismatch"
                            break
                if cls == "unknown":
                    counts["unknown"] += int(mass)
                    if reason.endswith("missing"):
                        missing_byte_intervals += 1
                    else:
                        byte_mismatch_intervals += 1
                else:
                    byte_match_intervals += 1
                if len(examples) < 8:
                    examples.append(
                        {
                            "scope": int(scope),
                            "source_line": int(source_line),
                            "target_line": int(target_line),
                            "actual_tag_bit": int(bitpos),
                            "target_cycle": int(cyc),
                            "classification": str(cls),
                            "reason": str(reason),
                            "mass": int(mass),
                            "relevant_byte_count": int(len(relevant_offsets)),
                        }
                    )
                prev_boundary = int(boundary)

    return {
        "counts": {
            "masked": int(counts.get("masked", 0)),
            "sdc": 0,
            "due": 0,
            "unknown": int(counts.get("unknown", 0)),
        },
        "ordered_pairs": int(ordered_pairs),
        "potential_ordered_pairs": int(ordered_pairs),
        "replay_intervals": 0,
        "alias_intervals": int(alias_intervals),
        "fallback_reachable_intervals": 0,
        "fallback_reason": "",
        "self_miss_intervals": 0,
        "self_miss_sdc": 0,
        "self_miss_source_lines": 0,
        "self_miss_sampled_bits": 0,
        "multievent_cycles": 0,
        "multithread_cycles": 0,
        "multievent_examples": [],
        "self_miss_examples": [],
        "byte_match_intervals": int(byte_match_intervals),
        "byte_mismatch_intervals": int(byte_mismatch_intervals),
        "missing_byte_intervals": int(missing_byte_intervals),
        "examples": examples,
        "mode": f"exact_{cache_component}_tag_identity_byte_compare",
    }

def _exact_l2_tag_counts_global_readonly_no_alias(
    *,
    trace_template: Dict[str, Any],
    fi_space: Optional[Dict[str, Any]],
    l2_sites: Sequence[Dict[str, Any]],
    line_size_bytes: int,
    size_bits: int,
    sample_tag_bits: int,
    global_prefill: bool,
) -> Optional[Dict[str, Any]]:
    if any(
        canonical_space(_cache_site_row_field(rec, "mem_space")) != "global"
        for rec in l2_sites
    ):
        return None
    nset = _sampling_component_int(fi_space, "l2", "nset", 0)
    if nset <= 0:
        return None
    per_line_bits = int(line_size_bytes) * 8 + int(sample_tag_bits)
    if per_line_bits <= 0:
        return None
    line_capacity = int(size_bits) // int(per_line_bits)
    if line_capacity <= 0:
        return None
    line_states = _build_global_readonly_line_state(
        trace_template,
        int(line_size_bytes),
        scope_mode="l2",
    )
    if not line_states:
        return None
    if len(line_states) > int(line_capacity):
        return None
    sample_positions = _cache_actual_tag_bit_positions(int(sample_tag_bits))
    prefill_cycle = None
    events_raw = trace_template.get("events", [])
    if isinstance(events_raw, list) and events_raw:
        prefill_cycle = min(
            int(raw.get("cycle", idx))
            for idx, raw in enumerate(events_raw)
            if isinstance(raw, dict)
        )
    ordered_pairs = 0
    for (_scope, source_line), source_state in sorted(line_states.items()):
        first_load_cycle = source_state.get("first_load_cycle")
        if first_load_cycle is None:
            continue
        source_active_from = (
            int(prefill_cycle)
            if bool(global_prefill) and prefill_cycle is not None
            else int(first_load_cycle) + 1
        )
        source_tag = int(source_line) // int(nset)
        set_idx = int(source_line) % int(nset)
        for bitpos in sample_positions:
            target_tag = int(source_tag) ^ (1 << int(bitpos))
            target_line = int(set_idx) + int(nset) * int(target_tag)
            target_state = line_states.get((0, int(target_line)))
            if target_state is None:
                continue
            target_cycles = [
                int(c)
                for c in target_state.get("load_cycles", [])
                if int(c) >= int(source_active_from)
            ]
            if target_cycles:
                ordered_pairs += 1
    if ordered_pairs != 0:
        return None
    return {
        "counts": {
            "masked": 0,
            "sdc": 0,
            "due": 0,
            "unknown": 0,
        },
        "ordered_pairs": 0,
        "mode": "exact_masked_no_reachable_alias",
        "examples": [],
    }


def _infer_l1d_shaders_from_trace_and_sites(
    trace_template: Dict[str, Any],
    l1d_sites: Sequence[Any],
) -> List[int]:
    inferred_shaders: List[int] = []
    seen_shaders: Set[int] = set()
    events_raw_infer = trace_template.get("events", [])
    if isinstance(events_raw_infer, list):
        for raw in events_raw_infer:
            if not isinstance(raw, dict):
                continue
            kind = str(raw.get("kind", "")).strip().lower()
            if kind not in ("load", "store"):
                continue
            mem_space = canonical_space(raw.get("mem_space") or raw.get("space"))
            if mem_space not in ("global", "local"):
                continue
            sm_id_raw = raw.get("sm_id")
            if sm_id_raw is None:
                continue
            sm_id = int(sm_id_raw)
            if sm_id in seen_shaders:
                continue
            seen_shaders.add(sm_id)
            inferred_shaders.append(sm_id)
    if inferred_shaders:
        return inferred_shaders
    for rec in l1d_sites:
        sm_id_raw = _cache_site_row_field(rec, "sm_id")
        if sm_id_raw is None:
            continue
        sm_id = int(sm_id_raw)
        if sm_id in seen_shaders:
            continue
        seen_shaders.add(sm_id)
        inferred_shaders.append(sm_id)
    return inferred_shaders


def _resolve_l1d_shader_seed_list(
    *,
    raw_spec: Optional[str],
    fi_space: Dict[str, Any],
    trace_template: Dict[str, Any],
    l1d_sites: Sequence[Dict[str, Any]],
) -> Tuple[List[int], str, str]:
    mode_raw = "" if raw_spec is None else str(raw_spec).strip()
    mode_lc = mode_raw.lower()
    sampling_list = _parse_shader_domain_value(
        _sampling_first(
            fi_space,
            (
                "component_domains.l1d.shaders",
                "component_domains.l1d.shader_scope",
                "l1d_shaders",
            ),
        )
    )
    sampling_shader_count = _safe_int(
        _sampling_first(
            fi_space,
            (
                "component_domains.l1d.shader_count",
                "component_domains.l1d.active_sm_count",
                "l1d_shader_count",
                "active_sm_count",
                "sm_count",
            ),
        ),
        0,
    )
    sampling_source_priority = str(
        _sampling_first(fi_space, ("source_priority.l1d_shaders",))
    ).strip().lower()
    inferred = _infer_l1d_shaders_from_trace_and_sites(trace_template, l1d_sites)
    source = "arg"
    mode = "explicit"
    shader_seed_list: Optional[List[int]] = None

    if mode_lc in ("", "auto"):
        mode = "auto"
        if sampling_list:
            shader_seed_list = list(int(v) for v in sampling_list)
            source = "sampling_space"
        elif sampling_shader_count > 0:
            shader_seed_list = list(range(int(sampling_shader_count)))
            source = "sampling_space_count"
        else:
            shader_seed_list = list(int(v) for v in inferred)
            source = "trace_or_analyzer"
    elif mode_lc == "all":
        mode = "all"
        if sampling_shader_count > 0:
            shader_seed_list = list(range(int(sampling_shader_count)))
            source = "sampling_space_count"
        elif sampling_list:
            max_shader = max(int(v) for v in sampling_list)
            shader_seed_list = list(range(int(max_shader) + 1))
            source = "sampling_space_max"
        elif inferred:
            max_shader = max(int(v) for v in inferred)
            shader_seed_list = list(range(int(max_shader) + 1))
            source = "trace_or_analyzer_max"
        else:
            shader_seed_list = []
            source = "none"
    else:
        shader_seed_list = parse_shader_list(mode_raw)
        mode = "explicit"
        source = "arg"

    if shader_seed_list is None:
        shader_seed_list = []

    # Defensive FI-equivalence guard for auto mode. If fi_sampling_space
    # accidentally expanded to config_all while trace/site inference is narrow,
    # clamp to the inferred scope to avoid silently over-expanding denominator.
    if (
        mode == "auto"
        and source == "sampling_space"
        and sampling_list
        and inferred
    ):
        inferred_set = {int(v) for v in inferred}
        sampling_set = {int(v) for v in sampling_list}
        extra_count = int(len(sampling_set - inferred_set))
        threshold = int(max(1, len(inferred_set)))
        if extra_count >= threshold:
            print(
                "WARNING: l1d auto shader scope appears over-expanded versus inferred "
                f"trace scope: sampling={sorted(int(v) for v in sampling_set)} "
                f"inferred={sorted(int(v) for v in inferred_set)} "
                f"source_priority={sampling_source_priority or 'unknown'}",
                file=sys.stderr,
            )
            if sampling_source_priority in ("config_all", "config", "campaign"):
                intersection = [
                    int(v) for v in shader_seed_list if int(v) in inferred_set
                ]
                if intersection:
                    shader_seed_list = list(intersection)
                    source = "sampling_space_guard_intersection"
                else:
                    shader_seed_list = [int(v) for v in inferred]
                    source = "sampling_space_guard_inferred"

    # Stable dedup while preserving caller intent order.
    out: List[int] = []
    seen: Set[int] = set()
    for item in shader_seed_list:
        val = int(item)
        if val in seen:
            continue
        seen.add(val)
        out.append(val)
    return out, mode, source


def _cache_addr_domain_runtime_enabled(args: argparse.Namespace) -> bool:
    return not bool(int(getattr(args, "use_sampling_space_domain", 0)))


def _event_effective_address_mask_from_raw(ev: Dict[str, Any]) -> int:
    if "mem_addr_mask" in ev and ev.get("mem_addr_mask") is not None:
        mask = parse_mask(ev.get("mem_addr_mask", 0))
        if mask != 0:
            return int(mask) & MASK64
    if "mem_addr_effective_bits" in ev and ev.get("mem_addr_effective_bits") is not None:
        bits = max(1, min(64, int(ev.get("mem_addr_effective_bits", 64))))
        return width_mask(bits)
    default_width = max(1, min(64, int(ev.get("ea_width_bits", 64))))
    cspace = canonical_space(ev.get("mem_space") or ev.get("space"))
    if cspace in ("global", "local", "shared"):
        return width_mask(min(default_width, 32))
    return width_mask(default_width)


def _normalize_addr_range_entry(raw: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None
    cspace = canonical_space(raw.get("space", raw.get("mem_space")))
    if cspace not in ("global", "local", "shared", "const"):
        return None
    if raw.get("base") is None or raw.get("size") is None:
        return None
    base_raw = raw.get("base")
    try:
        if isinstance(base_raw, int):
            base = int(base_raw)
        else:
            base = parse_int(str(base_raw))
        size = int(raw.get("size"))
    except Exception:
        return None
    if size <= 0:
        return None
    out: Dict[str, Any] = {
        "space": str(cspace),
        "base": int(base),
        "size": int(size),
    }
    for key in (
        "start_event_index",
        "end_event_index",
        "start_cycle",
        "end_cycle",
        "thread_id",
        "cta_id",
        "sm_id",
    ):
        val = raw.get(key)
        if val is None:
            continue
        try:
            out[key] = int(val)
        except Exception:
            continue
    return out


def _load_addr_valid_ranges(
    *,
    trace_memory_ranges: List[Dict[str, Any]],
    external_path: Optional[Path],
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for raw in trace_memory_ranges:
        norm = _normalize_addr_range_entry(raw)
        if norm is not None:
            out.append(norm)

    if external_path is None:
        return out
    raw = _json_load_path(external_path)
    rows: List[Any] = []
    if isinstance(raw, list):
        rows = raw
    elif isinstance(raw, dict):
        if isinstance(raw.get("memory_ranges"), list):
            rows = list(raw.get("memory_ranges", []))
        elif isinstance(raw.get("ranges"), list):
            rows = list(raw.get("ranges", []))
    for item in rows:
        norm = _normalize_addr_range_entry(item)
        if norm is not None:
            out.append(norm)
    return out


def _addr_range_context_match(
    entry: Dict[str, Any],
    *,
    event_index: Optional[int],
    cycle: Optional[int],
    thread_id: Optional[int],
    cta_id: Optional[int],
    sm_id: Optional[int],
) -> bool:
    start_ev = entry.get("start_event_index")
    if start_ev is not None and event_index is not None and int(event_index) < int(start_ev):
        return False
    end_ev = entry.get("end_event_index")
    if end_ev is not None and event_index is not None and int(event_index) >= int(end_ev):
        return False
    start_cycle = entry.get("start_cycle")
    if start_cycle is not None and cycle is not None and int(cycle) < int(start_cycle):
        return False
    end_cycle = entry.get("end_cycle")
    if end_cycle is not None and cycle is not None and int(cycle) >= int(end_cycle):
        return False

    for key, cur in (
        ("thread_id", thread_id),
        ("cta_id", cta_id),
        ("sm_id", sm_id),
    ):
        val = entry.get(key)
        if val is None:
            continue
        if cur is None:
            return False
        if int(cur) != int(val):
            return False
    return True


def _addr_access_validity(
    *,
    ranges: Sequence[Dict[str, Any]],
    mem_space: Optional[str],
    addr: int,
    size_bytes: int,
    event_index: Optional[int],
    cycle: Optional[int],
    thread_id: Optional[int],
    cta_id: Optional[int],
    sm_id: Optional[int],
) -> Tuple[bool, bool]:
    cspace = canonical_space(mem_space)
    if cspace not in ("global", "local", "shared", "const"):
        return False, False
    addr_i = int(addr)
    size_i = max(1, int(size_bytes))
    has_context = False
    for entry in ranges:
        if str(entry.get("space", "")) != str(cspace):
            continue
        if not _addr_range_context_match(
            entry,
            event_index=event_index,
            cycle=cycle,
            thread_id=thread_id,
            cta_id=cta_id,
            sm_id=sm_id,
        ):
            continue
        has_context = True
        lo = int(entry.get("base", 0))
        hi = int(lo + int(entry.get("size", 0)))
        if addr_i >= lo and (addr_i + size_i) <= hi:
            return True, True
    return False, bool(has_context)


def _trace_divergence_target_class(policy: str) -> str:
    policy_n = _normalize_trace_divergence_policy(policy)
    if policy_n == "sdc":
        return "sdc"
    if policy_n == "due":
        return "due"
    if policy_n == "unknown":
        return "unknown"
    return "masked"


def _apply_trace_divergence_policy_to_masks(
    *,
    due_mask: int,
    sdc_mask: int,
    unknown_mask: int,
    trace_mask: int,
    width_bits: int,
    policy: str,
) -> Tuple[int, int, int, int]:
    wmask = width_mask(int(width_bits))
    due_m = int(due_mask) & int(wmask)
    sdc_m = int(sdc_mask) & int(wmask)
    unknown_m = int(unknown_mask) & int(wmask)
    trace_m = int(trace_mask) & int(wmask)

    due_m &= (~unknown_m) & int(wmask)
    sdc_m &= (~unknown_m) & int(wmask)
    sdc_m &= (~due_m) & int(wmask)

    target_cls = _trace_divergence_target_class(policy)
    if target_cls == "masked" or trace_m == 0:
        return due_m & MASK64, sdc_m & MASK64, unknown_m & MASK64, 0

    candidate = int(trace_m) & (~due_m) & (~sdc_m) & (~unknown_m) & int(wmask)
    if candidate == 0:
        return due_m & MASK64, sdc_m & MASK64, unknown_m & MASK64, 0

    if target_cls == "sdc":
        sdc_m |= int(candidate)
    elif target_cls == "due":
        due_m |= int(candidate)
    elif target_cls == "unknown":
        unknown_m |= int(candidate)

    due_m &= int(wmask)
    sdc_m &= int(wmask)
    unknown_m &= int(wmask)
    due_m &= (~unknown_m) & int(wmask)
    sdc_m &= (~unknown_m) & int(wmask)
    sdc_m &= (~due_m) & int(wmask)
    return due_m & MASK64, sdc_m & MASK64, unknown_m & MASK64, int(candidate) & MASK64


def _add_source_mass(acc: Dict[str, float], key: str, mass: float) -> None:
    if not math.isfinite(float(mass)):
        return
    if float(mass) == 0.0:
        return
    acc[str(key)] = float(acc.get(str(key), 0.0)) + float(mass)


def _normalize_mass_map(acc: Dict[str, float]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key in sorted(acc.keys()):
        out[str(key)] = _normalize_numeric(float(acc.get(key, 0.0)))
    return out


def _mass_map_to_bits_map(acc: Dict[str, float]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for key in sorted(acc.keys()):
        val = float(acc.get(key, 0.0))
        if val <= 0.0:
            out[str(key)] = 0
        else:
            out[str(key)] = int(round(val))
    return out


def _is_valid_smem_addr(addr: int, domain_full_bytes: int, domain_tail_bits: int) -> bool:
    addr_i = int(addr)
    if addr_i < 0:
        return False
    if addr_i < int(domain_full_bytes):
        return True
    if int(domain_tail_bits) <= 0:
        return False
    return addr_i == int(domain_full_bytes)


def _classify_smem_addr_masks(
    *,
    addr: int,
    selected_mask: int,
    effective_mask: int = MASK64,
    domain_full_bytes: int,
    domain_tail_bits: int,
    addr_fault_policy: str,
    addr_due_mode: str,
    trace_mask: int,
    trace_divergence_policy: str,
    oob_exception_policy: Optional[str] = None,
    source_prefix: str = "addr",
) -> Tuple[int, int, int, int, Dict[str, int], int]:
    policy = _normalize_addr_fault_policy(addr_fault_policy)
    due_mode = _normalize_addr_due_mode(addr_due_mode)
    trace_target = _trace_divergence_target_class(trace_divergence_policy)
    oob_policy = (
        _normalize_smem_addr_exception_policy(oob_exception_policy)
        if oob_exception_policy is not None
        else None
    )
    source_prefix_n = str(source_prefix).strip() or "addr"
    sel = int(selected_mask) & MASK64
    eff = int(effective_mask) & MASK64
    if eff == 0:
        eff = MASK64
    base_addr = int(addr) & int(eff)
    due_m = 0
    sdc_m = 0
    unknown_m = 0
    masked_m = 0
    trace_div_bits = 0
    source_bits: Counter = Counter()

    pending = int(sel)
    while pending:
        one_bit = int(pending & -pending)
        bit_idx = int(one_bit.bit_length() - 1)
        pending ^= one_bit

        cls = "masked"
        source = f"{source_prefix_n}_masked"
        if (int(eff) & int(one_bit)) == 0:
            cls = "masked"
            source = f"{source_prefix_n}_masked"
            mutated_addr = int(base_addr)
        else:
            mutated_addr = int((int(base_addr) ^ int(one_bit)) & int(eff))
        if mutated_addr == int(base_addr):
            cls = "masked"
            source = f"{source_prefix_n}_masked"
        else:
            valid = _is_valid_smem_addr(
                mutated_addr,
                domain_full_bytes=domain_full_bytes,
                domain_tail_bits=domain_tail_bits,
            )
            if valid:
                cls = "sdc"
                source = f"{source_prefix_n}_alias_sdc"
            elif oob_policy is not None:
                cls = str(oob_policy)
                source = f"{source_prefix_n}_oob_{cls}"
            else:
                cls = "due"
                source = f"{source_prefix_n}_oob_due"

        if ((int(trace_mask) >> bit_idx) & 1) != 0 and cls == "masked" and trace_target != "masked":
            cls = str(trace_target)
            source = f"trace_divergence_{cls}"
            trace_div_bits |= int(one_bit)

        if cls == "due":
            due_m |= int(one_bit)
        elif cls == "sdc":
            sdc_m |= int(one_bit)
        elif cls == "unknown":
            unknown_m |= int(one_bit)
        else:
            masked_m |= int(one_bit)
        source_bits[str(source)] += 1

    return (
        int(due_m) & MASK64,
        int(sdc_m) & MASK64,
        int(unknown_m) & MASK64,
        int(masked_m) & MASK64,
        {str(k): int(v) for k, v in sorted(source_bits.items())},
        int(trace_div_bits) & MASK64,
    )


def _classify_addr_masks_with_ranges(
    *,
    addr: int,
    selected_mask: int,
    effective_mask: int,
    mem_space: Optional[str],
    access_size: int,
    event_index: Optional[int],
    cycle: Optional[int],
    thread_id: Optional[int],
    cta_id: Optional[int],
    sm_id: Optional[int],
    addr_ranges: Sequence[Dict[str, Any]],
    addr_fault_policy: str,
    addr_due_mode: str,
    trace_mask: int,
    trace_divergence_policy: str,
    live_addr_set: Optional[Set[int]] = None,
    oob_exception_policy: Optional[str] = None,
    source_prefix: str = "addr",
) -> Tuple[int, int, int, int, Dict[str, int], int]:
    policy = _normalize_addr_fault_policy(addr_fault_policy)
    due_mode = _normalize_addr_due_mode(addr_due_mode)
    trace_target = _trace_divergence_target_class(trace_divergence_policy)
    oob_policy = (
        _normalize_smem_addr_exception_policy(oob_exception_policy)
        if oob_exception_policy is not None
        else None
    )
    source_prefix_n = str(source_prefix).strip() or "addr"
    cspace = canonical_space(mem_space)
    sel = int(selected_mask) & MASK64
    eff = int(effective_mask) & MASK64
    base_addr = int(addr) & int(eff if eff != 0 else MASK64)
    due_m = 0
    sdc_m = 0
    unknown_m = 0
    masked_m = 0
    trace_div_bits = 0
    source_bits: Counter = Counter()

    pending = int(sel)
    while pending:
        one_bit = int(pending & -pending)
        bit_idx = int(one_bit.bit_length() - 1)
        pending ^= one_bit

        cls = "masked"
        source = f"{source_prefix_n}_masked"
        if (int(eff) & int(one_bit)) == 0:
            cls = "masked"
            source = f"{source_prefix_n}_masked"
        else:
            mutated_addr = int((base_addr ^ int(one_bit)) & int(eff))
            if mutated_addr == int(base_addr):
                cls = "masked"
                source = f"{source_prefix_n}_masked"
            else:
                valid, has_context = _addr_access_validity(
                    ranges=addr_ranges,
                    mem_space=mem_space,
                    addr=mutated_addr,
                    size_bytes=int(access_size),
                    event_index=event_index,
                    cycle=cycle,
                    thread_id=thread_id,
                    cta_id=cta_id,
                    sm_id=sm_id,
                )
                if has_context:
                    if valid:
                        if cspace == "shared" and live_addr_set is not None:
                            cls = "unknown"
                            source = f"{source_prefix_n}_alias_unknown"
                        else:
                            cls = "sdc"
                            source = f"{source_prefix_n}_alias_sdc"
                    elif oob_policy is not None:
                        cls = str(oob_policy)
                        source = f"{source_prefix_n}_oob_{cls}"
                    else:
                        cls = "due"
                        source = f"{source_prefix_n}_oob_due"
                else:
                    if cspace == "shared" and live_addr_set is not None:
                        cls = "unknown"
                        source = f"{source_prefix_n}_alias_unknown"
                    else:
                        cls = "unknown"
                        source = f"{source_prefix_n}_unknown_unbounded"

        if ((int(trace_mask) >> bit_idx) & 1) != 0 and cls == "masked" and trace_target != "masked":
            cls = str(trace_target)
            source = f"trace_divergence_{cls}"
            trace_div_bits |= int(one_bit)

        if cls == "due":
            due_m |= int(one_bit)
        elif cls == "sdc":
            sdc_m |= int(one_bit)
        elif cls == "unknown":
            unknown_m |= int(one_bit)
        else:
            masked_m |= int(one_bit)
        source_bits[str(source)] += 1

    return (
        int(due_m) & MASK64,
        int(sdc_m) & MASK64,
        int(unknown_m) & MASK64,
        int(masked_m) & MASK64,
        {str(k): int(v) for k, v in sorted(source_bits.items())},
        int(trace_div_bits) & MASK64,
    )


def _build_shared_observed_addr_sets(
    smem_sites: Sequence[Dict[str, Any]],
) -> Dict[Tuple[int, int], Set[int]]:
    out: Dict[Tuple[int, int], Set[int]] = defaultdict(set)
    for rec in smem_sites:
        if not isinstance(rec, dict):
            continue
        if str(rec.get("site_kind", "")) not in ("smem_lds", "smem_rf"):
            continue
        observed_mask = int(parse_mask(rec.get("observed_mask_this_site", 0))) & 0xFF
        if observed_mask == 0:
            continue
        sm_id = int(rec.get("sm_id", -1))
        cta_id = int(rec.get("cta_id", -1))
        addr = int(rec.get("addr", -1))
        if sm_id < 0 or cta_id < 0 or addr < 0:
            continue
        out[(sm_id, cta_id)].add(int(addr))
    return out


def _build_shared_escape_addr_sets(
    smem_sites: Sequence[Dict[str, Any]],
) -> Dict[Tuple[int, int], Set[int]]:
    out: Dict[Tuple[int, int], Set[int]] = defaultdict(set)
    for rec in smem_sites:
        if not isinstance(rec, dict):
            continue
        if str(rec.get("site_kind", "")) not in ("smem_lds", "smem_rf"):
            continue
        shared_escape_mask = (
            int(parse_mask(rec.get("shared_store_escape_mask_this_site", 0))) & 0xFF
        )
        if shared_escape_mask == 0:
            continue
        sm_id = int(rec.get("sm_id", -1))
        cta_id = int(rec.get("cta_id", -1))
        addr = int(rec.get("addr", -1))
        if sm_id < 0 or cta_id < 0 or addr < 0:
            continue
        out[(sm_id, cta_id)].add(int(addr))
    return out


def _select_shared_live_target_sets(
    observed_sets: Dict[Tuple[int, int], Set[int]],
    escape_sets: Dict[Tuple[int, int], Set[int]],
) -> Dict[Tuple[int, int], Set[int]]:
    out: Dict[Tuple[int, int], Set[int]] = {}
    for key in set(observed_sets.keys()) | set(escape_sets.keys()):
        observed_values = observed_sets.get(key)
        escape_values = escape_sets.get(key)
        if observed_values:
            out[key] = set(int(v) for v in observed_values)
        elif escape_values:
            out[key] = set(int(v) for v in escape_values)
    return out


def _normalize_numeric(value: Any, *, tol: float = 1e-12) -> Any:
    fv = float(value)
    iv = int(round(fv))
    if abs(fv - float(iv)) <= float(tol):
        return int(iv)
    return fv


def fraction(n: float, d: int) -> Dict[str, Any]:
    return {
        "numerator": _normalize_numeric(n),
        "denominator": int(d),
        "value": (float(n) / float(d)) if d else 0.0,
    }


def _normalize_same_cycle_effect_prob(raw: Any) -> Optional[float]:
    if raw is None:
        return None
    try:
        p = float(raw)
    except Exception:
        raise ValueError(
            "same_cycle_effect_prob must be within [0,1] or unset; got {!r}".format(raw)
        )
    if not math.isfinite(p) or p < 0.0 or p > 1.0:
        raise ValueError(
            "same_cycle_effect_prob must be within [0,1]; got {!r}".format(raw)
        )
    return float(p)


def _boundary_affected_prob_for_output(
    *,
    consumer_compare: str,
    same_cycle_effect_prob: Optional[float],
) -> float:
    if same_cycle_effect_prob is not None:
        return float(same_cycle_effect_prob)
    return 1.0 if str(consumer_compare).strip().lower() == "ge" else 0.0


def _boundary_meta_fields(
    *,
    consumer_compare: str,
    same_cycle_effect_prob: Optional[float],
    boundary_events_count: int,
    boundary_events_mass: float,
    boundary_bits_mass_total: float,
) -> Dict[str, Any]:
    affected_prob = _boundary_affected_prob_for_output(
        consumer_compare=consumer_compare,
        same_cycle_effect_prob=same_cycle_effect_prob,
    )
    unaffected_prob = 1.0 - float(affected_prob)
    events_mass_f = float(boundary_events_mass)
    bits_mass_total_f = float(boundary_bits_mass_total)
    return {
        "same_cycle_effect_prob": (
            _normalize_numeric(float(same_cycle_effect_prob))
            if same_cycle_effect_prob is not None
            else None
        ),
        "boundary_events_count": int(boundary_events_count),
        "boundary_events_mass": _normalize_numeric(events_mass_f),
        "boundary_events_mass_affected": _normalize_numeric(
            events_mass_f * float(affected_prob)
        ),
        "boundary_events_mass_unaffected": _normalize_numeric(
            events_mass_f * float(unaffected_prob)
        ),
        "boundary_bits_mass_total": _normalize_numeric(bits_mass_total_f),
        "boundary_bits_mass_affected": _normalize_numeric(
            bits_mass_total_f * float(affected_prob)
        ),
        "boundary_bits_mass_unaffected": _normalize_numeric(
            bits_mass_total_f * float(unaffected_prob)
        ),
        "boundary_events_count_unit": "event_instances",
        "boundary_events_mass_unit": "weighted_injection_mass",
        "boundary_events_mass_note": (
            "boundary_events_count is the number of inject_cycle==read_cycle event "
            "instances; boundary_events_mass is the weighted injection mass of those "
            "instances before bit-width expansion."
        ),
    }


def _is_numeric_scalar(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    return isinstance(value, (int, float))


def _blend_numeric_struct(lhs: Any, rhs: Any, p: float) -> Any:
    if isinstance(lhs, dict) and isinstance(rhs, dict):
        out: Dict[str, Any] = {}
        keys = set(lhs.keys()) | set(rhs.keys())
        for key in keys:
            if key in lhs and key in rhs:
                out[key] = _blend_numeric_struct(lhs[key], rhs[key], p)
            elif key in lhs:
                out[key] = lhs[key]
            else:
                out[key] = rhs[key]
        return out
    if isinstance(lhs, list) and isinstance(rhs, list):
        return lhs if lhs == rhs else lhs
    if _is_numeric_scalar(lhs) and _is_numeric_scalar(rhs):
        return _normalize_numeric((1.0 - float(p)) * float(lhs) + float(p) * float(rhs))
    return lhs if lhs == rhs else lhs


def _clone_args_with(args: argparse.Namespace, **overrides: Any) -> argparse.Namespace:
    data = dict(vars(args))
    data.update(overrides)
    return argparse.Namespace(**data)


def _extract_counts_float(payload: Dict[str, Any]) -> Dict[str, float]:
    counts_raw = payload.get("classification_counts", {})
    if not isinstance(counts_raw, dict):
        counts_raw = {}
    return {
        "masked": _to_float_num(counts_raw.get("masked", 0.0)),
        "sdc": _to_float_num(counts_raw.get("sdc", 0.0)),
        "due": _to_float_num(counts_raw.get("due", 0.0)),
        "unknown": _to_float_num(counts_raw.get("unknown", 0.0)),
        "total": _to_float_num(counts_raw.get("total", 0.0)),
    }


def _counts_to_rate_map(counts: Dict[str, float]) -> Dict[str, float]:
    den = float(counts.get("total", 0.0))
    if den <= 0.0:
        return {"masked": 0.0, "sdc": 0.0, "due": 0.0, "unknown": 0.0}
    return {
        "masked": float(counts.get("masked", 0.0) / den),
        "sdc": float(counts.get("sdc", 0.0) / den),
        "due": float(counts.get("due", 0.0) / den),
        "unknown": float(counts.get("unknown", 0.0) / den),
    }


def _normalize_fault_component_sequence(raw: str) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    normalized = str(raw or "").replace(",", " ").replace(":", " ")
    for token in normalized.split():
        comp = str(token).strip().lower()
        if not comp:
            continue
        if comp not in FAULT_COMPONENTS:
            raise ValueError(
                "unsupported batch fault component {!r}; expected one of {}".format(
                    comp,
                    ", ".join(FAULT_COMPONENTS),
                )
            )
        if comp in seen:
            continue
        seen.add(comp)
        out.append(comp)
    if not out:
        raise ValueError("batch fault component list is empty")
    return out


def _parse_component_analyzer_mappings(entries: Sequence[str]) -> Dict[str, Path]:
    out: Dict[str, Path] = {}
    for raw in entries:
        text = str(raw or "").strip()
        if not text:
            continue
        comp_raw, sep, path_raw = text.partition("=")
        if sep != "=":
            raise ValueError(
                "invalid --component-analyzer entry {!r}; expected <component>=<path>".format(
                    text
                )
            )
        comp = str(comp_raw).strip().lower()
        if comp not in FAULT_COMPONENTS:
            raise ValueError(
                "invalid --component-analyzer component {!r}; expected one of {}".format(
                    comp,
                    ", ".join(FAULT_COMPONENTS),
                )
            )
        path_text = str(path_raw).strip()
        if not path_text:
            raise ValueError(
                "invalid --component-analyzer entry {!r}; missing path".format(text)
            )
        out[str(comp)] = Path(path_text)
    return out


def _resolve_batch_worker_count(requested_workers: Any, component_count: int) -> int:
    workers = int(requested_workers)
    if workers < 0:
        raise ValueError("batch_workers must be >= 0")
    if component_count <= 1:
        return 1
    if workers == 0:
        cpu_count = max(1, int(os.cpu_count() or 1))
        auto_cap = max(1, min(4, cpu_count // 4 if cpu_count >= 4 else 1))
        return max(1, min(component_count, auto_cap))
    return max(1, min(component_count, workers))


def _cap_batch_worker_count_for_risk(
    analyzer_paths: Sequence[Path],
    worker_count: int,
) -> int:
    resolved = int(max(1, worker_count))
    for path in analyzer_paths:
        meta = _load_analyzer_meta_sidecar_cached(_path_cache_key(Path(path)))
        if not meta:
            try:
                payload = _json_load_path(Path(path))
            except Exception:
                continue
            if not isinstance(payload, dict):
                continue
            meta = payload.get("exact_meta", {})
        if not isinstance(meta, dict):
            continue
        l1d_fault_site_count = int(meta.get("l1d_fault_site_count", 0) or 0)
        trace_expanding_bits_total = int(
            meta.get("trace_expanding_bits_total", 0) or 0
        )
        trace_expanding_mask_present_count = int(
            meta.get("trace_expanding_mask_present_count", 0) or 0
        )
        if trace_expanding_bits_total >= 4_000_000:
            return 1
        if (
            l1d_fault_site_count >= 500_000
            or trace_expanding_bits_total >= 3_000_000
            or trace_expanding_mask_present_count >= 2_000_000
        ):
            resolved = min(int(resolved), 2)
    return int(max(1, resolved))


def _prewarm_batch_component_inputs(
    args: argparse.Namespace,
    analyzer_paths: Sequence[Path],
    components: Sequence[str],
) -> None:
    seen_analyzers: Set[str] = set()
    component_set = {str(comp).strip().lower() for comp in components if str(comp).strip()}
    normalize_trace_coverage = bool(getattr(args, "normalize_trace_coverage", False))
    analyzer_payload_by_key: Dict[str, Dict[str, Any]] = {}
    for path in analyzer_paths:
        path_key = _path_cache_key(path)
        if path_key in seen_analyzers:
            continue
        seen_analyzers.add(path_key)
        _json_load_path(Path(path_key))
        analyzer_payload = _load_analyzer_output_for_compute_cached(
            path_key,
            normalize_trace_coverage,
        )
        if isinstance(analyzer_payload, dict):
            analyzer_payload_by_key[path_key] = analyzer_payload
        _trace_expanding_stats_for_analyzer_path(path_key, normalize_trace_coverage)

    if getattr(args, "trace_template", None) is not None:
        parse_trace_template(Path(args.trace_template))
    cycle_records: Optional[List[CycleRecord]] = None
    if getattr(args, "cycles", None) is not None:
        cycle_records, _cycle_records_meta = load_cycle_records_with_meta(
            Path(args.cycles),
            getattr(args, "active_threads_log", None),
            bool(getattr(args, "allow_missing_active_threads", False)),
            str(getattr(args, "missing_active_threads_policy", "empty")),
        )
    if getattr(args, "active_threads_log", None) is not None:
        load_shared_scope_thread_ids_log(Path(args.active_threads_log))
    if getattr(args, "fi_sampling_space_path", None) is not None:
        _load_fi_sampling_space(Path(args.fi_sampling_space_path))

    if "rf" in {str(comp).strip().lower() for comp in components}:
        if getattr(args, "regfile_trace", None) is not None:
            parse_regfile_accesses(Path(args.regfile_trace))
        if getattr(args, "registers", None) is not None:
            parse_register_list(str(args.registers))
        if getattr(args, "trace_template", None) is not None:
            trace_template_key = _path_cache_key(Path(args.trace_template))
            parse_trace_template(Path(trace_template_key))
            needs_addr_context = False
            for path in analyzer_paths:
                payload = analyzer_payload_by_key.get(_path_cache_key(path))
                if isinstance(payload, dict) and _analyzer_rf_requires_addr_trace_context(payload):
                    needs_addr_context = True
                    break
            if needs_addr_context:
                _load_rf_addr_trace_context_cached(trace_template_key)
            for path_key, payload in analyzer_payload_by_key.items():
                if not isinstance(payload.get("read_events"), list):
                    continue
                _load_fast_rf_analyzer_indexes_cached(
                    path_key,
                    normalize_trace_coverage,
                )
                _load_fast_rf_consumer_indexes_cached(
                    path_key,
                    normalize_trace_coverage,
                )
    if cycle_records is not None and (
        "rf" in component_set or "smem_rf" in component_set
    ):
        thread_rands = parse_spec_list(getattr(args, "thread_rands", None))
        if thread_rands is not None and len(thread_rands) == 0:
            thread_rands = None
        thread_rand_max = None
        if thread_rands is None:
            try:
                thread_rand_max = int(getattr(args, "thread_rand_max", 0))
            except Exception:
                thread_rand_max = 0
            if thread_rand_max <= 0:
                thread_rand_max = None
        _thread_cycle_weights(cycle_records, thread_rands, thread_rand_max)
    if getattr(args, "trace_template", None) is not None and (
        "l1d" in component_set or "l2" in component_set
    ):
        trace_template_key = _path_cache_key(Path(args.trace_template))
        _load_shared_cache_trace_views_cached(
            trace_template_key,
            int(getattr(args, "l1d_line_size_bytes", L1D_LINE_SIZE_BYTES_DEFAULT)),
            bool(int(getattr(args, "l1d_write_allocate", 0))),
            int(getattr(args, "l2_line_size_bytes", L2_LINE_SIZE_BYTES_DEFAULT)),
            bool("l1d" in component_set),
            bool("l2" in component_set),
        )
        trace_expanding_policy = str(getattr(args, "trace_expanding_policy", "masked"))
        trace_uncovered_mode = str(getattr(args, "trace_uncovered_mode", "legacy_unknown"))
        trace_expanding_resolution_mode = str(
            getattr(args, "trace_expanding_resolution_mode", "legacy")
        )
        for comp in ("l1d", "l2"):
            if comp not in component_set:
                continue
            field_name = _cache_fault_site_field_name(comp)
            for path_key, payload in analyzer_payload_by_key.items():
                if not isinstance(payload.get(field_name), list):
                    continue
                _load_filtered_cache_fault_sites_for_compute_cached(
                    comp,
                    path_key,
                    trace_template_key,
                    normalize_trace_coverage,
                )
                _load_cache_site_masks_for_compute_cached(
                    comp,
                    path_key,
                    trace_template_key,
                    normalize_trace_coverage,
                    trace_expanding_policy,
                    trace_uncovered_mode,
                    trace_expanding_resolution_mode,
                )


def _compute_exact_batch_component(
    comp_args: argparse.Namespace,
) -> Dict[str, Any]:
    out = compute_exact(comp_args)
    out = finalize_exact_result(out, comp_args)
    _json_dump_path(Path(comp_args.output), out)
    return {
        "fault_component": str(getattr(comp_args, "fault_component", "")),
        "analyzer_output": str(Path(getattr(comp_args, "analyzer_output"))),
        "output": str(Path(getattr(comp_args, "output"))),
        "strict_fail_report": str(Path(getattr(comp_args, "strict_fail_report"))),
        "strict_ok": True,
        "strict_failed": False,
        "classification_counts": dict(
            out.get("classification_counts", {})
            if isinstance(out.get("classification_counts", {}), dict)
            else {}
        ),
        "classification_rates": dict(
            out.get("classification_rates", {})
            if isinstance(out.get("classification_rates", {}), dict)
            else {}
        ),
    }


def compute_exact_batch(args: argparse.Namespace) -> Dict[str, Any]:
    components = _normalize_fault_component_sequence(getattr(args, "batch_components", ""))
    analyzer_map = _parse_component_analyzer_mappings(
        getattr(args, "component_analyzer", []) or []
    )
    default_analyzer = getattr(args, "analyzer_output", None)
    output_dir = getattr(args, "batch_output_dir", None)
    if output_dir is None:
        output_dir = Path(args.output).parent
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    component_payloads: Dict[str, Dict[str, Any]] = {}
    strict_failed_components: List[str] = []
    component_args: List[argparse.Namespace] = []
    analyzer_paths: List[Path] = []

    for comp in components:
        comp_analyzer = analyzer_map.get(str(comp), default_analyzer)
        if comp_analyzer is None:
            raise ValueError(
                "missing analyzer output for batch component {!r}; pass --analyzer-output "
                "or --component-analyzer {}=<path>".format(comp, comp)
            )
        comp_output = output_dir / f"exact_rates_{comp}.json"
        comp_report = output_dir / f"strict_fail_report_{comp}.json"
        comp_args = _clone_args_with(
            args,
            fault_component=str(comp),
            analyzer_output=Path(comp_analyzer),
            output=comp_output,
            strict_fail_report=comp_report,
            batch_components=None,
            batch_output_dir=None,
            component_analyzer=[],
            _batch_active_components=tuple(components),
        )
        component_args.append(comp_args)
        analyzer_paths.append(Path(comp_analyzer))

    batch_workers_requested = int(getattr(args, "batch_workers", 0))
    batch_workers_resolved = _resolve_batch_worker_count(
        batch_workers_requested,
        len(component_args),
    )
    if batch_workers_resolved > 1:
        batch_workers_resolved = _cap_batch_worker_count_for_risk(
            analyzer_paths,
            batch_workers_resolved,
        )

    results: List[Dict[str, Any]] = []
    if batch_workers_resolved > 1 and len(component_args) > 1:
        try:
            mp_ctx = mp.get_context("fork")
        except ValueError:
            mp_ctx = None
        if mp_ctx is None:
            batch_workers_resolved = 1
        else:
            _prewarm_batch_component_inputs(args, analyzer_paths, components)
            try:
                with concurrent.futures.ProcessPoolExecutor(
                    max_workers=batch_workers_resolved,
                    mp_context=mp_ctx,
                ) as executor:
                    for row in executor.map(_compute_exact_batch_component, component_args):
                        results.append(dict(row))
            except Exception as exc:
                print(
                    "WARNING: parallel batch exact compute failed; retrying sequentially "
                    "with 1 worker ({}: {})".format(type(exc).__name__, exc),
                    file=sys.stderr,
                )
                results = []
                batch_workers_resolved = 1

    if batch_workers_resolved <= 1 or len(results) != len(component_args):
        results = [
            _compute_exact_batch_component(comp_args)
            for comp_args in component_args
        ]

    for row in results:
        comp = str(row.get("fault_component", "")).strip().lower()
        if not comp:
            raise ValueError("batch component result missing fault_component")
        if bool(row.pop("strict_failed", False)):
            strict_failed_components.append(str(comp))
        component_payloads[str(comp)] = dict(row)

    return {
        "mode": "batch_exact_components",
        "components": component_payloads,
        "component_order": list(components),
        "output_dir": str(output_dir),
        "batch_workers_requested": int(batch_workers_requested),
        "batch_workers_resolved": int(batch_workers_resolved),
        "strict_failed_components": list(strict_failed_components),
    }


def compute_exact_rf(args: argparse.Namespace) -> Dict[str, Any]:
    if args.regfile_trace is None:
        raise ValueError("--regfile-trace is required for fault-component=rf")
    if args.registers is None:
        raise ValueError("--registers is required for fault-component=rf")

    storage_group_mode = _normalize_storage_group_mode(
        getattr(args, "storage_group_mode", "legacy")
    )
    use_grouped_mode = storage_group_mode == "grouped"
    normalize_trace_coverage = bool(getattr(args, "normalize_trace_coverage", False))
    analyzer_path_key = _analyzer_output_cache_key(Path(args.analyzer_output))
    analyzer = _load_analyzer_output_for_compute(
        args.analyzer_output,
        normalize_trace_coverage=normalize_trace_coverage,
    )
    (
        by_uid,
        by_name,
        reg_to_uids,
        addr_static_due_by_uid,
        addr_static_due_by_name,
    ) = _load_fast_rf_analyzer_indexes_cached(
        analyzer_path_key,
        normalize_trace_coverage,
    )
    (
        consumer_by_uid,
        consumer_by_name,
    ) = _load_fast_rf_consumer_indexes_cached(
        analyzer_path_key,
        normalize_trace_coverage,
    )
    reads, writes = parse_regfile_accesses(args.regfile_trace)
    rf_addr_reg_policy = _normalize_rf_addr_reg_policy(
        getattr(args, "rf_addr_reg_policy", "addr_regs_only")
    )
    rf_trace_template: Optional[Dict[str, Any]] = None
    rf_trace_analysis_mod: Optional[Any] = None
    rf_trace_events_by_index: Dict[int, Any] = {}
    rf_event_by_index: Dict[int, Dict[str, Any]] = {}
    rf_trace_ranges: List[Any] = []
    rf_addr_records_by_uid: Dict[Tuple[int, int, int], List[RFAddrTraceRecord]] = {}
    rf_addr_records_by_name: Dict[Tuple[int, int, str], List[RFAddrTraceRecord]] = {}
    rf_addr_observed_intervals: RFAddrObservedIntervals = {}
    needs_rf_addr_trace_context = _analyzer_rf_requires_addr_trace_context(analyzer)
    trace_template_key: Optional[str] = None
    if getattr(args, "trace_template", None) is not None:
        trace_template_key = _path_cache_key(Path(args.trace_template))
        try:
            rf_trace_template = parse_trace_template(Path(trace_template_key))
            rf_event_by_index = _trace_event_by_index_cached(trace_template_key)
        except Exception:
            rf_trace_template = None
            rf_event_by_index = {}
        if needs_rf_addr_trace_context:
            (
                rf_trace_analysis_mod,
                rf_trace_events_by_index,
                rf_trace_ranges,
                rf_addr_records_by_uid,
                rf_addr_records_by_name,
                rf_addr_observed_intervals,
            ) = _load_rf_addr_trace_context(getattr(args, "trace_template", None))
    rf_addr_source_reg_names, rf_addr_source_reg_uids = _extract_rf_addr_source_regs(
        rf_trace_template
    )
    rf_addr_reg_policy_effective = str(rf_addr_reg_policy)
    rf_addr_reg_policy_warning = ""
    if (
        rf_addr_reg_policy_effective == "addr_regs_only"
        and not rf_addr_source_reg_names
        and not rf_addr_source_reg_uids
    ):
        rf_addr_reg_policy_effective = "any_reg"
        rf_addr_reg_policy_warning = (
            "RF_ADDR_REG_POLICY=addr_regs_only but no address-source register mapping "
            "was found in trace_template events; falling back to any_reg."
        )

    def is_rf_addr_reg(label: str, uids: Sequence[int]) -> bool:
        if rf_addr_reg_policy_effective == "any_reg":
            return True
        if str(label) in rf_addr_source_reg_names:
            return True
        for uid in uids:
            if int(uid) in rf_addr_source_reg_uids:
                return True
        return False

    rf_addr_event_eval_info_cache: Dict[int, Optional[RFAddrEventEvalInfo]] = {}

    def resolve_rf_addr_event_eval_info(
        event_index: int,
    ) -> Optional[RFAddrEventEvalInfo]:
        event_index_i = int(event_index)
        if event_index_i in rf_addr_event_eval_info_cache:
            return rf_addr_event_eval_info_cache[event_index_i]
        if rf_trace_analysis_mod is None:
            rf_addr_event_eval_info_cache[event_index_i] = None
            return None
        ev = rf_trace_events_by_index.get(event_index_i)
        if ev is None:
            rf_addr_event_eval_info_cache[event_index_i] = None
            return None
        info = _build_rf_addr_event_eval_info(
            analysis_mod=rf_trace_analysis_mod,
            ev=ev,
            ranges=rf_trace_ranges,
            observed_intervals=rf_addr_observed_intervals,
        )
        rf_addr_event_eval_info_cache[event_index_i] = info
        return info

    analyzer_mask_format = _analyzer_mask_format(analyzer)
    rf_addr_due_observed_overlap_by_uid: Dict[Tuple[int, int, int], int] = {}
    rf_addr_due_observed_overlap_by_name: Dict[Tuple[int, int, str], int] = {}
    rf_addr_due_observed_overlap_bits = 0
    rf_addr_due_observed_overlap_records = 0
    read_events_raw = analyzer.get("read_events", [])
    if isinstance(read_events_raw, list) and rf_event_by_index:
        for raw_rec in read_events_raw:
            if _read_event_row_field(raw_rec, "cycle", None) is None:
                continue
            event_index = int(_read_event_row_field(raw_rec, "event_index", -1))
            raw_ev = rf_event_by_index.get(event_index, {})
            cspace = canonical_raw_event_space(raw_ev)
            if cspace not in ("global", "const"):
                continue
            addr_due_mask = _parse_mask_with_format(
                _read_event_row_field(raw_rec, ADDR_STATIC_DUE_MASK_FIELD, 0),
                analyzer_mask_format,
            )
            if addr_due_mask == 0 and str(_read_event_row_field(raw_rec, "read_kind", "")).strip().lower() == "addr":
                addr_due_mask = _parse_mask_with_format(
                    _read_event_row_field(raw_rec, "due_mask_this_read", 0),
                    analyzer_mask_format,
                )
            if addr_due_mask == 0:
                continue
            observed_sdc_mask = (
                _parse_mask_with_format(_read_event_row_field(raw_rec, "observed_mask_this_read", 0), analyzer_mask_format)
                | _parse_mask_with_format(_read_event_row_field(raw_rec, "semantic_sdc_mask_this_read", 0), analyzer_mask_format)
            ) & MASK64
            suppress_mask = int(addr_due_mask) & int(observed_sdc_mask)
            if suppress_mask == 0:
                continue
            tid = int(_read_event_row_field(raw_rec, "thread_id", -1))
            cycle = int(_read_event_row_field(raw_rec, "cycle", 0))
            reg = str(_read_event_row_field(raw_rec, "src_reg", ""))
            uid = int(_read_event_row_field(raw_rec, "src_reg_uid", -1))
            key_name = (tid, cycle, reg)
            rf_addr_due_observed_overlap_by_name[key_name] = (
                int(rf_addr_due_observed_overlap_by_name.get(key_name, 0))
                | int(suppress_mask)
            ) & MASK64
            if uid >= 0:
                key_uid = (tid, cycle, uid)
                rf_addr_due_observed_overlap_by_uid[key_uid] = (
                    int(rf_addr_due_observed_overlap_by_uid.get(key_uid, 0))
                    | int(suppress_mask)
                ) & MASK64
            rf_addr_due_observed_overlap_bits += int(popcount_u64(int(suppress_mask) & MASK64))
            rf_addr_due_observed_overlap_records += 1

    cycle_records, cycle_records_meta = load_cycle_records_with_meta(
        args.cycles,
        args.active_threads_log,
        bool(getattr(args, "allow_missing_active_threads", False)),
        str(getattr(args, "missing_active_threads_policy", "empty")),
    )

    register_labels = parse_register_list(args.registers)
    if not register_labels:
        raise ValueError("register domain is empty")

    datatype_bits = int(args.datatype_bits)
    if datatype_bits <= 0:
        raise ValueError("datatype_bits must be > 0")
    trace_expanding_policy = str(args.trace_expanding_policy).strip().lower()
    if trace_expanding_policy != CANONICAL_TRACE_EXPANDING_POLICY:
        raise ValueError(
            "trace_expanding_policy must be one of {}; got {!r}".format(
                CANONICAL_TRACE_EXPANDING_POLICY,
                trace_expanding_policy,
            )
        )
    trace_uncovered_mode = _normalize_trace_uncovered_mode(
        getattr(args, "trace_uncovered_mode", "legacy_unknown")
    )
    trace_expanding_resolution_mode = str(
        getattr(args, "trace_expanding_resolution_mode", "legacy")
    ).strip().lower()
    if trace_expanding_resolution_mode != CANONICAL_TRACE_EXPANDING_RESOLUTION_MODE:
        raise ValueError(
            "trace_expanding_resolution_mode must be one of {}; got {!r}".format(
                CANONICAL_TRACE_EXPANDING_RESOLUTION_MODE,
                trace_expanding_resolution_mode,
            )
        )
    same_cycle_effect_prob = _normalize_same_cycle_effect_prob(
        getattr(args, "same_cycle_effect_prob", None)
    )

    bits = parse_spec_list(args.bits)
    if bits is None:
        bits_1based = list(range(1, datatype_bits + 1))
    else:
        bits_1based = sorted({b for b in bits if 1 <= b <= datatype_bits})
        if not bits_1based:
            raise ValueError("bit domain is empty after filtering")
    bit_count = len(bits_1based)
    selected_bits_mask64 = 0
    for b in bits_1based:
        if 1 <= b <= 64:
            selected_bits_mask64 |= (1 << (b - 1))

    thread_rands = parse_spec_list(args.thread_rands)
    if thread_rands is not None and len(thread_rands) == 0:
        raise ValueError("--thread-rands provided but empty")
    thread_rand_max = None if thread_rands is not None else int(args.thread_rand_max)
    if thread_rands is None and thread_rand_max <= 0:
        raise ValueError("--thread-rand-max must be > 0 when --thread-rands is not set")

    # register label -> uid set; if multiple uids share one label, injection
    # flips all of them (matching gpuFI register_name semantics).
    label_to_uids: Dict[str, List[int]] = {}
    for label in register_labels:
        label_to_uids[label] = sorted(int(u) for u in reg_to_uids.get(label, set()))

    (
        thread_cycle_weights,
        seed_domain_size,
        inactive_base_mass,
        active_base_mass,
    ) = _thread_cycle_weights(
        cycle_records,
        thread_rands,
        thread_rand_max,
        include_thread_ids=reads.keys(),
        prefix_only=True,
    )
    thread_cycle_backend = (
        "cpp" if _should_use_cpp_thread_cycle(cycle_records) else "python"
    )
    thread_cycle_backend = (
        "cpp" if _should_use_cpp_thread_cycle(cycle_records) else "python"
    )
    total_cycle_lines = sum(rec.multiplicity for rec in cycle_records)
    if total_cycle_lines <= 0:
        raise ValueError("cycle multiplicity total is zero")
    base_denominator = int(total_cycle_lines) * int(seed_domain_size)

    thread_prefix = build_thread_cycle_prefix(thread_cycle_weights)

    reg_count = len(register_labels)
    fi_space = _load_fi_sampling_space(getattr(args, "fi_sampling_space_path", None))
    rf_domain_info = _resolve_rf_domain_policy_info(
        args=args,
        fi_space=fi_space,
        total_cycle_lines=int(total_cycle_lines),
        seed_domain_size=int(seed_domain_size),
        register_count_used=int(reg_count),
        bit_count=int(bit_count),
    )
    used_total_denominator = base_denominator * reg_count * bit_count
    target_total_denominator = int(
        max(
            0,
            int(rf_domain_info.get("rf_domain_total_bits_final", 0)),
        )
    )
    if target_total_denominator <= 0:
        target_total_denominator = int(used_total_denominator)
    total_denominator = int(target_total_denominator)

    masked_num = inactive_base_mass * reg_count * bit_count
    sdc_num = 0
    due_num = 0
    unknown_num = 0
    rf_trace_due_mass = 0.0
    rf_addr_oob_due_mass = 0.0
    rf_addr_alias_sdc_mass = 0.0
    rf_trace_divergence_due_mass = 0.0
    rf_trace_divergence_sdc_mass = 0.0
    rf_addr_due_num = 0.0
    rf_addr_sdc_num = 0.0
    rf_addr_unknown_num = 0.0
    rf_sdc_proof_source_mass: Dict[str, float] = defaultdict(float)

    missing_read_event_keys: List[Tuple[int, int, str, Tuple[int, ...]]] = []
    cache_final_masks: Dict[Tuple[int, int, str], Tuple[int, int, int, int, int, int, int]] = {}
    cache_final_masks_by_signature: Dict[
        Tuple[int, int, int, int, int, int, int, int, int],
        Tuple[int, int, int, int, int, int, int],
    ] = {}
    cache_resolved_records: Dict[Tuple[int, int, str], Optional[FastMaskRecord]] = {}
    cache_resolved_consumer_masks: Dict[
        Tuple[int, int, str],
        Optional[
            Tuple[
                int,
                int,
                int,
                int,
                int,
                int,
                int,
                int,
                int,
                int,
                Dict[str, int],
                Dict[str, int],
                int,
            ]
        ],
    ] = {}
    cache_resolved_consumers: Dict[Tuple[int, int, str], List[RFConsumerRecord]] = {}
    cache_consumer_base_masks_by_signature: Dict[
        Tuple[
            Tuple[Tuple[int, int, int, int, int, int, int, int, int], ...],
            str,
            str,
            str,
        ],
        Tuple[int, int, int, int, int, int, int],
    ] = {}
    cache_addr_class_masks: Dict[
        Tuple[int, int, str],
        Tuple[int, int, int, Dict[str, int], int],
    ] = {}
    cache_addr_static_due_masks_raw: Dict[Tuple[int, int, str], int] = {}
    write_killed_mass = 0
    trace_expanding_sdc_numerator = 0
    trace_policy_used_bits = 0
    trace_policy_used_mass = 0
    trace_policy_override_bits = 0
    trace_policy_override_mass = 0
    trace_policy_override_sdc_bits = 0
    trace_policy_override_due_bits = 0
    trace_policy_override_unknown_bits = 0
    trace_policy_override_masked_bits = 0
    trace_uncovered_unknown_bits = 0
    trace_uncovered_unknown_mass = 0
    boundary_events_count = 0
    boundary_events_mass = 0
    boundary_bits_mass_total = 0
    saw_trace_selected_bits = False
    rf_interval_accum_backend_used = "none"
    pending_rf_interval_reqs: List[Dict[str, Any]] = []
    rf_grouped_final_mask_requests = 0
    rf_grouped_final_mask_hits = 0
    rf_grouped_consumer_signature_requests = 0
    rf_grouped_consumer_signature_hits = 0

    def add_rf_sdc_proof_source_mass(
        mass: int,
        base_sdc_mask: int,
        source_masks: Mapping[str, int],
    ) -> None:
        selected_sdc = int(base_sdc_mask) & int(selected_bits_mask64) & MASK64
        if int(mass) <= 0 or selected_sdc == 0:
            return
        disjoint = _disjoint_source_masks(
            {
                str(key): int(mask) & selected_sdc
                for key, mask in source_masks.items()
                if int(mask) & selected_sdc
            }
        )
        covered = 0
        for source in RF_SDC_PROOF_SOURCE_KEYS:
            mask_i = int(disjoint.get(source, 0)) & selected_sdc & MASK64
            if mask_i == 0:
                continue
            covered |= mask_i
            rf_sdc_proof_source_mass[source] += float(int(mass) * popcount_u64(mask_i))
        residual = selected_sdc & (~covered) & MASK64
        if residual:
            rf_sdc_proof_source_mass["rf_other_exact_transfer"] += float(
                int(mass) * popcount_u64(residual)
            )

    def apply_rf_interval_accum(accum: Mapping[str, Any]) -> None:
        nonlocal masked_num
        nonlocal sdc_num
        nonlocal due_num
        nonlocal unknown_num
        nonlocal rf_trace_due_mass
        nonlocal rf_addr_due_num
        nonlocal rf_addr_sdc_num
        nonlocal rf_addr_unknown_num
        nonlocal rf_addr_oob_due_mass
        nonlocal rf_trace_divergence_due_mass
        nonlocal rf_addr_alias_sdc_mass
        nonlocal rf_trace_divergence_sdc_mass
        nonlocal trace_expanding_sdc_numerator
        nonlocal trace_policy_used_bits
        nonlocal trace_policy_used_mass
        nonlocal trace_policy_override_bits
        nonlocal trace_policy_override_mass
        nonlocal trace_policy_override_sdc_bits
        nonlocal trace_policy_override_due_bits
        nonlocal trace_policy_override_unknown_bits
        nonlocal trace_policy_override_masked_bits
        nonlocal trace_uncovered_unknown_bits
        nonlocal trace_uncovered_unknown_mass
        nonlocal saw_trace_selected_bits

        masked_num += int(accum.get("masked_num", 0))
        sdc_num += int(accum.get("sdc_num", 0))
        due_num += int(accum.get("due_num", 0))
        unknown_num += int(accum.get("unknown_num", 0))
        rf_trace_due_mass += float(int(accum.get("trace_due_mass", 0)))
        rf_addr_due_num += float(int(accum.get("addr_due_num", 0)))
        rf_addr_sdc_num += float(int(accum.get("addr_sdc_num", 0)))
        rf_addr_unknown_num += float(int(accum.get("addr_unknown_num", 0)))
        rf_addr_oob_due_mass += float(int(accum.get("addr_oob_due_mass", 0)))
        rf_trace_divergence_due_mass += float(
            int(accum.get("trace_divergence_due_mass", 0))
        )
        rf_addr_alias_sdc_mass += float(int(accum.get("addr_alias_sdc_mass", 0)))
        rf_trace_divergence_sdc_mass += float(
            int(accum.get("trace_divergence_sdc_mass", 0))
        )
        trace_expanding_sdc_numerator += int(
            accum.get("trace_expanding_sdc_numerator", 0)
        )
        trace_policy_used_bits += int(accum.get("trace_policy_used_bits", 0))
        trace_policy_used_mass += int(accum.get("trace_policy_used_mass", 0))
        trace_policy_override_bits += int(accum.get("trace_policy_override_bits", 0))
        trace_policy_override_mass += int(accum.get("trace_policy_override_mass", 0))
        trace_policy_override_sdc_bits += int(
            accum.get("trace_policy_override_sdc_bits", 0)
        )
        trace_policy_override_due_bits += int(
            accum.get("trace_policy_override_due_bits", 0)
        )
        trace_policy_override_unknown_bits += int(
            accum.get("trace_policy_override_unknown_bits", 0)
        )
        trace_policy_override_masked_bits += int(
            accum.get("trace_policy_override_masked_bits", 0)
        )
        trace_uncovered_unknown_bits += int(
            accum.get("trace_uncovered_unknown_bits", 0)
        )
        trace_uncovered_unknown_mass += int(
            accum.get("trace_uncovered_unknown_mass", 0)
        )
        if int(accum.get("saw_trace_selected_bits", 0)) != 0:
            saw_trace_selected_bits = True

    def flush_rf_interval_accum() -> None:
        nonlocal rf_interval_accum_backend_used
        if not pending_rf_interval_reqs:
            return
        pending = list(pending_rf_interval_reqs)
        pending_rf_interval_reqs.clear()
        accum = _cpp_rf_interval_accumulate_many(pending)
        if accum is not None:
            rf_interval_accum_backend_used = "cpp"
        else:
            accum = _python_rf_interval_accumulate_many(pending)
            if rf_interval_accum_backend_used == "none":
                rf_interval_accum_backend_used = "python"
        apply_rf_interval_accum(accum)

    def record_rf_interval(req: Dict[str, Any]) -> None:
        pending_rf_interval_reqs.append(req)
        if len(pending_rf_interval_reqs) >= int(_CPP_RF_INTERVAL_ACCUM_BATCH_SIZE):
            flush_rf_interval_accum()

    ge_mode = args.consumer_compare == "ge"
    persistent_rf_fault = args.rf_fault_model == "persistent"
    min_cycle = -10**30
    max_cycle = 10**30
    rf_thread_ids = set(int(tid) for tid in thread_prefix.keys())
    reads_by_uid = _invert_thread_reg_cycles(reads, valid_threads=rf_thread_ids)
    writes_by_uid = (
        _invert_thread_reg_cycles(writes, valid_threads=rf_thread_ids)
        if persistent_rf_fault
        else {}
    )

    def resolve_read_record(
        tid: int,
        rc: int,
        label: str,
        uids: Sequence[int],
    ) -> Optional[FastMaskRecord]:
        ckey = (tid, rc, label)
        if ckey in cache_resolved_records:
            return cache_resolved_records[ckey]

        rec = by_name.get((tid, rc, label))
        if rec is None:
            rec_merge: Optional[FastMaskRecord] = None
            for uid in uids:
                rec_uid = by_uid.get((tid, rc, uid))
                if rec_uid is not None:
                    rec_merge = _merge_fast_record(rec_merge, rec_uid)
            rec = rec_merge
        if rec is not None:
            static_addr_due_mask = resolve_addr_static_due_mask_raw(
                tid,
                rc,
                label,
                uids,
            )
            if static_addr_due_mask != 0:
                rec = (
                    int(rec[0]),
                    int(rec[1]),
                    int(rec[2]) & ((~int(static_addr_due_mask)) & MASK64),
                    int(rec[3]),
                )
        cache_resolved_records[ckey] = rec
        return rec

    def resolve_addr_static_due_mask_raw(
        tid: int,
        rc: int,
        label: str,
        uids: Sequence[int],
    ) -> int:
        ckey = (tid, rc, label)
        if ckey in cache_addr_static_due_masks_raw:
            return int(cache_addr_static_due_masks_raw[ckey])

        mask = int(addr_static_due_by_name.get(ckey, 0)) & MASK64
        if mask == 0:
            for uid in uids:
                mask |= int(addr_static_due_by_uid.get((tid, rc, int(uid)), 0)) & MASK64
        mask &= MASK64
        cache_addr_static_due_masks_raw[ckey] = int(mask)
        return int(mask)

    def resolve_addr_masks(
        tid: int,
        rc: int,
        label: str,
        uids: Sequence[int],
        trace_mask: int,
    ) -> Tuple[int, int, int, Dict[str, int], int]:
        ckey = (tid, rc, label)
        if ckey in cache_addr_class_masks:
            return cache_addr_class_masks[ckey]

        suppress_mask = int(rf_addr_due_observed_overlap_by_name.get(ckey, 0)) & MASK64
        if suppress_mask == 0:
            for uid in uids:
                suppress_mask |= int(
                    rf_addr_due_observed_overlap_by_uid.get((tid, rc, int(uid)), 0)
                ) & MASK64

        due_mask = 0
        sdc_mask = 0
        unknown_mask = 0
        source_bits: Dict[str, int] = {}
        trace_div_bits = 0
        used_dynamic_trace = False
        if rf_trace_analysis_mod is not None and rf_trace_events_by_index:
            records: List[RFAddrTraceRecord] = []
            seen_records: Set[RFAddrTraceRecord] = set()
            for rec in rf_addr_records_by_name.get((tid, rc, label), []):
                if rec in seen_records:
                    continue
                seen_records.add(rec)
                records.append(rec)
            for uid in uids:
                for rec in rf_addr_records_by_uid.get((tid, rc, int(uid)), []):
                    if rec in seen_records:
                        continue
                    seen_records.add(rec)
                    records.append(rec)
            if records and is_rf_addr_reg(label, uids):
                used_dynamic_trace = True
                (
                    due_mask,
                    sdc_mask,
                    unknown_mask,
                    _masked_mask,
                    source_bits,
                    trace_div_bits,
                ) = _classify_rf_addr_masks_from_trace(
                    analysis_mod=rf_trace_analysis_mod,
                    trace_events_by_index=rf_trace_events_by_index,
                    trace_ranges=rf_trace_ranges,
                    trace_observed_intervals=rf_addr_observed_intervals,
                    trace_event_eval_info_resolver=resolve_rf_addr_event_eval_info,
                    records=records,
                    addr_fault_policy=getattr(args, "addr_fault_policy", CANONICAL_ADDR_FAULT_POLICY),
                    addr_due_mode=getattr(args, "addr_due_mode", CANONICAL_ADDR_DUE_MODE),
                    trace_mask=int(trace_mask) & MASK64,
                    trace_divergence_policy=getattr(
                        args,
                        "trace_divergence_policy",
                        CANONICAL_TRACE_DIVERGENCE_POLICY,
                    ),
                )
        if not used_dynamic_trace:
            due_mask = resolve_addr_static_due_mask_raw(tid, rc, label, uids)
            if due_mask != 0:
                source_bits = {
                    "rf_addr_oob_due": int(popcount_u64(int(due_mask) & MASK64))
                }
        if suppress_mask != 0 and not used_dynamic_trace:
            due_mask &= (~int(suppress_mask)) & MASK64
        due_mask &= MASK64
        sdc_mask &= MASK64
        sdc_mask &= (~due_mask) & MASK64
        unknown_mask &= MASK64
        unknown_mask &= (~due_mask) & MASK64
        unknown_mask &= (~sdc_mask) & MASK64
        resolved = (
            int(due_mask),
            int(sdc_mask),
            int(unknown_mask),
            dict(source_bits),
            int(trace_div_bits) & MASK64,
        )
        cache_addr_class_masks[ckey] = resolved
        return resolved

    def resolve_read_consumers(
        tid: int,
        rc: int,
        label: str,
        uids: Sequence[int],
    ) -> List[RFConsumerRecord]:
        ckey = (tid, rc, label)
        cached = cache_resolved_consumers.get(ckey)
        if cached is not None:
            return cached
        if not consumer_by_name and not consumer_by_uid:
            cache_resolved_consumers[ckey] = []
            return []

        seen: Set[Tuple[int, int, int]] = set()
        out: List[RFConsumerRecord] = []
        for rec in consumer_by_name.get((tid, rc, label), []):
            rec_key = _rf_consumer_record_event_key(rec)
            if rec_key in seen:
                continue
            seen.add(rec_key)
            out.append(rec)
        for uid in uids:
            for rec in consumer_by_uid.get((tid, rc, int(uid)), []):
                rec_key = _rf_consumer_record_event_key(rec)
                if rec_key in seen:
                    continue
                seen.add(rec_key)
                out.append(rec)
        cache_resolved_consumers[ckey] = out
        return out

    def resolve_read_consumer_masks(
        tid: int,
        rc: int,
        label: str,
        uids: Sequence[int],
    ) -> Optional[
        Tuple[
            int,
            int,
            int,
            int,
            int,
            int,
            int,
            int,
            int,
            int,
            Dict[str, int],
            Dict[str, int],
            int,
        ]
    ]:
        nonlocal rf_grouped_consumer_signature_requests
        nonlocal rf_grouped_consumer_signature_hits
        ckey = (tid, rc, label)
        if ckey in cache_resolved_consumer_masks:
            return cache_resolved_consumer_masks[ckey]

        consumers = resolve_read_consumers(tid, rc, label, uids)
        if not consumers:
            cache_resolved_consumer_masks[ckey] = None
            return None

        base_due_union = 0
        base_sdc_union = 0
        base_unknown_union = 0
        trace_added_union = 0
        trace_policy_used_union = 0
        trace_union = 0
        trace_policy_override_union = 0
        addr_trace_mask = 0
        addr_consumer_present = False
        addr_record_due_union = 0
        addr_record_sdc_union = 0
        addr_record_unknown_union = 0
        non_addr_consumers: List[RFConsumerRecord] = []
        non_addr_fast_records: List[FastMaskRecord] = []

        for consumer in consumers:
            kind = _rf_consumer_record_kind(consumer)
            if kind == RF_READ_KIND_ADDR:
                addr_consumer_present = True
                fast_rec = _rf_consumer_record_fast_mask(consumer)
                addr_record_sdc_union |= int(fast_rec[1]) & MASK64
                addr_record_due_union |= (
                    int(fast_rec[2])
                    | int(_rf_consumer_record_addr_static_due_mask(consumer))
                ) & MASK64
                addr_record_unknown_union |= int(fast_rec[3]) & MASK64
                addr_trace_mask |= int(fast_rec[3]) & MASK64
            else:
                non_addr_consumers.append(consumer)
                non_addr_fast_records.append(_rf_consumer_record_fast_mask(consumer))

        rf_sdc_source_masks_raw: Dict[str, int] = {}
        if non_addr_fast_records:
            if use_grouped_mode:
                rf_grouped_consumer_signature_requests = (
                    rf_grouped_consumer_signature_requests + 1
                )
                consumer_sig = (
                    tuple(
                        sorted(
                            tuple(int(v) for v in rec_fast)
                            for rec_fast in non_addr_fast_records
                        )
                    ),
                    str(trace_expanding_policy),
                    str(trace_uncovered_mode),
                    str(trace_expanding_resolution_mode),
                )
                cached_consumer_base = cache_consumer_base_masks_by_signature.get(
                    consumer_sig
                )
            else:
                cached_consumer_base = None
            if cached_consumer_base is None:
                resolved_base_many = tuple(
                    _final_due_sdc_masks_with_meta_fast_extended_many(
                        non_addr_fast_records,
                        trace_expanding_policy=trace_expanding_policy,
                        trace_uncovered_mode=trace_uncovered_mode,
                        trace_expanding_resolution_mode=trace_expanding_resolution_mode,
                    )
                )
                if use_grouped_mode:
                    cache_consumer_base_masks_by_signature[consumer_sig] = tuple(
                        (
                            int(item[0]),
                            int(item[1]),
                            int(item[2]),
                            int(item[3]),
                            int(item[4]),
                            int(item[5]),
                            int(item[6]),
                        )
                        for item in resolved_base_many
                    )
            else:
                rf_grouped_consumer_signature_hits = (
                    rf_grouped_consumer_signature_hits + 1
                )
                resolved_base_many = cached_consumer_base
            for (
                due_mask_i,
                sdc_mask_i,
                unknown_mask_i,
                trace_added_i,
                trace_policy_used_i,
                trace_mask_i,
                trace_policy_override_i,
            ) in resolved_base_many:
                base_due_union |= int(due_mask_i)
                base_sdc_union |= int(sdc_mask_i)
                base_unknown_union |= int(unknown_mask_i)
                trace_added_union |= int(trace_added_i)
                trace_policy_used_union |= int(trace_policy_used_i)
                trace_union |= int(trace_mask_i)
                trace_policy_override_union |= int(trace_policy_override_i)
            for consumer, fast_rec in zip(non_addr_consumers, non_addr_fast_records):
                masks_i = final_due_sdc_masks_with_meta_fast_extended(
                    rec=fast_rec,
                    trace_expanding_policy=trace_expanding_policy,
                    trace_uncovered_mode=trace_uncovered_mode,
                    trace_expanding_resolution_mode=trace_expanding_resolution_mode,
                )
                sdc_mask_i = int(masks_i[1]) & MASK64
                if sdc_mask_i == 0:
                    continue
                event_index = _rf_consumer_record_event_index(consumer)
                raw_event = rf_event_by_index.get(int(event_index))
                source = _rf_sdc_proof_source_from_event(
                    raw_event,
                    _rf_consumer_record_kind(consumer),
                )
                rf_sdc_source_masks_raw[source] = (
                    int(rf_sdc_source_masks_raw.get(source, 0)) | int(sdc_mask_i)
                ) & MASK64
        rf_sdc_source_masks = _disjoint_source_masks(rf_sdc_source_masks_raw)


        addr_due_mask = 0
        addr_sdc_mask = 0
        addr_unknown_mask = 0
        addr_source_bits: Dict[str, int] = {}
        addr_trace_div_mask = 0
        if addr_consumer_present:
            # Address-read records are produced by the backward analyzer after
            # value-equality and liveness proofs have been applied:
            # - load aliases that read the same bytes are omitted (masked),
            # - load aliases that read different live bytes are observed (SDC),
            # - out-of-range addresses are DUE,
            # - aliases that cannot be proven either way remain trace/Unknown.
            #
            # Reclassifying the same RF address bits from only the active
            # address range would conservatively turn every in-range alias into
            # SDC and discard these proof results.  Use the analyzer's
            # trace-realized classification directly for current analyzer
            # outputs; the older dynamic resolver remains available through
            # resolve_addr_masks when no structured address consumer records
            # exist.
            addr_unknown_mask = int(addr_record_unknown_union) & MASK64
            addr_due_mask = int(addr_record_due_union) & (~addr_unknown_mask) & MASK64
            addr_sdc_mask = (
                int(addr_record_sdc_union)
                & (~addr_unknown_mask)
                & (~addr_due_mask)
                & MASK64
            )
            if addr_due_mask != 0:
                addr_source_bits["rf_addr_oob_due"] = int(popcount_u64(addr_due_mask))
            if addr_sdc_mask != 0:
                addr_source_bits["addr_alias_sdc"] = int(popcount_u64(addr_sdc_mask))
            trace_union |= int(addr_trace_mask)
        resolved = (
            int(base_due_union) & MASK64,
            int(base_sdc_union) & MASK64,
            int(base_unknown_union) & MASK64,
            int(trace_added_union) & MASK64,
            int(trace_policy_used_union) & MASK64,
            int(trace_union) & MASK64,
            int(trace_policy_override_union) & MASK64,
            int(addr_due_mask) & MASK64,
            int(addr_sdc_mask) & MASK64,
            int(addr_unknown_mask) & MASK64,
            dict(rf_sdc_source_masks),
            dict(addr_source_bits),
            int(addr_trace_div_mask) & MASK64,
        )
        cache_resolved_consumer_masks[ckey] = resolved
        return resolved

    for label in register_labels:
        uids = label_to_uids.get(label, [])
        if not uids:
            masked_num += active_base_mass * bit_count
            continue
        uid_tuple = tuple(uids)
        label_read_cycles_by_tid = _collect_label_thread_cycles(reads_by_uid, uids)
        if not label_read_cycles_by_tid:
            masked_num += active_base_mass * bit_count
            continue
        label_write_cycles_by_tid: Dict[int, List[int]] = {}
        if persistent_rf_fault:
            label_write_cycles_by_tid = _collect_label_thread_cycles(writes_by_uid, uids)

        label_thread_rows: List[Tuple[int, List[int], List[int], List[int], int]] = []
        label_touched_mass_total = 0
        for tid, read_cycles in label_read_cycles_by_tid.items():
            thread_row = thread_prefix.get(int(tid))
            if thread_row is None:
                continue
            cycles_sorted, prefix, thread_mass_total = thread_row
            if int(thread_mass_total) <= 0:
                continue
            label_touched_mass_total += int(thread_mass_total)
            label_thread_rows.append(
                (
                    int(tid),
                    read_cycles,
                    cycles_sorted,
                    prefix,
                    int(thread_mass_total),
                )
            )
        if not label_thread_rows:
            masked_num += active_base_mass * bit_count
            continue
        untouched_mass = int(active_base_mass) - int(label_touched_mass_total)
        if untouched_mass > 0:
            masked_num += untouched_mass * bit_count

        for tid, read_cycles, cycles_sorted, prefix, thread_mass_total in label_thread_rows:
            if persistent_rf_fault:
                write_cycles = label_write_cycles_by_tid.get(tid, [])

                prev_write = min_cycle
                for maybe_write in [*write_cycles, None]:
                    seg_lo = prev_write
                    seg_hi = max_cycle if maybe_write is None else int(maybe_write)
                    if seg_hi <= seg_lo:
                        prev_write = seg_hi
                        continue

                    seg_mass = range_sum(cycles_sorted, prefix, seg_lo, seg_hi)
                    if seg_mass <= 0:
                        prev_write = seg_hi
                        continue

                    read_lo = bisect.bisect_left(read_cycles, seg_lo)
                    if maybe_write is None:
                        read_hi = len(read_cycles)
                    else:
                        read_hi = bisect.bisect_right(read_cycles, seg_hi)
                    seg_reads = read_cycles[read_lo:read_hi]

                    if not seg_reads:
                        masked_num += seg_mass * bit_count
                        if maybe_write is not None:
                            write_killed_mass += seg_mass
                        prev_write = seg_hi
                        continue

                    n = len(seg_reads)
                    suffix_due = [0] * (n + 1)
                    suffix_addr_due = [0] * (n + 1)
                    suffix_sdc = [0] * (n + 1)
                    suffix_addr_sdc = [0] * (n + 1)
                    suffix_unknown = [0] * (n + 1)
                    suffix_addr_unknown = [0] * (n + 1)
                    suffix_trace_added_sdc = [0] * (n + 1)
                    suffix_trace_policy_used = [0] * (n + 1)
                    suffix_trace_policy_override = [0] * (n + 1)
                    suffix_trace_bits = [0] * (n + 1)
                    suffix_addr_trace_div = [0] * (n + 1)
                    suffix_rf_sdc_sources = {
                        source: [0] * (n + 1) for source in RF_SDC_PROOF_SOURCE_KEYS
                    }
                    for idx in range(n - 1, -1, -1):
                        rc = seg_reads[idx]
                        ckey = (tid, rc, label)
                        consumer_masks = resolve_read_consumer_masks(tid, rc, label, uids)
                        if consumer_masks is not None:
                            (
                                due_mask,
                                sdc_mask,
                                unknown_mask,
                                trace_added_sdc_mask,
                                trace_policy_used_mask,
                                trace_mask,
                                trace_policy_override_mask,
                                addr_due_mask,
                                addr_sdc_mask,
                                addr_unknown_mask,
                                rf_sdc_source_masks,
                                _addr_source_bits,
                                addr_trace_div_mask,
                            ) = consumer_masks
                        else:
                            rec = resolve_read_record(tid, rc, label, uids)
                            if rec is None:
                                missing_read_event_keys.append((tid, rc, label, uid_tuple))
                                due_mask = 0
                                sdc_mask = 0
                                unknown_mask = 0
                                trace_added_sdc_mask = 0
                                trace_policy_used_mask = 0
                                trace_mask = 0
                                trace_policy_override_mask = 0
                                addr_due_mask = 0
                                addr_sdc_mask = 0
                                addr_unknown_mask = 0
                                rf_sdc_source_masks = {}
                                addr_trace_div_mask = 0
                            else:
                                masks = cache_final_masks.get(ckey)
                                if masks is None:
                                    rec_sig = tuple(int(v) for v in rec)
                                    if use_grouped_mode:
                                        rf_grouped_final_mask_requests += 1
                                        masks = cache_final_masks_by_signature.get(rec_sig)
                                    else:
                                        masks = None
                                    if masks is None:
                                        masks = final_due_sdc_masks_with_meta_fast_extended(
                                            rec=rec,
                                            trace_expanding_policy=trace_expanding_policy,
                                            trace_uncovered_mode=trace_uncovered_mode,
                                            trace_expanding_resolution_mode=trace_expanding_resolution_mode,
                                        )
                                        if use_grouped_mode:
                                            cache_final_masks_by_signature[rec_sig] = masks
                                    else:
                                        rf_grouped_final_mask_hits += 1
                                    cache_final_masks[ckey] = masks
                                (
                                    due_mask,
                                    sdc_mask,
                                    unknown_mask,
                                    trace_added_sdc_mask,
                                    trace_policy_used_mask,
                                    trace_mask,
                                    trace_policy_override_mask,
                                ) = masks
                                (
                                    addr_due_mask,
                                    addr_sdc_mask,
                                    addr_unknown_mask,
                                    _addr_source_bits,
                                    addr_trace_div_mask,
                                ) = resolve_addr_masks(
                                    tid, rc, label, uids, trace_mask
                                )
                                rf_sdc_source_masks = {}
                        suffix_due[idx] = suffix_due[idx + 1] | due_mask
                        suffix_addr_due[idx] = (
                            suffix_addr_due[idx + 1] | addr_due_mask
                        )
                        suffix_sdc[idx] = suffix_sdc[idx + 1] | sdc_mask
                        suffix_addr_sdc[idx] = (
                            suffix_addr_sdc[idx + 1] | addr_sdc_mask
                        )
                        suffix_unknown[idx] = suffix_unknown[idx + 1] | unknown_mask
                        suffix_addr_unknown[idx] = (
                            suffix_addr_unknown[idx + 1] | addr_unknown_mask
                        )
                        suffix_trace_added_sdc[idx] = (
                            suffix_trace_added_sdc[idx + 1] | trace_added_sdc_mask
                        )
                        suffix_trace_policy_used[idx] = (
                            suffix_trace_policy_used[idx + 1] | trace_policy_used_mask
                        )
                        suffix_trace_policy_override[idx] = (
                            suffix_trace_policy_override[idx + 1] | trace_policy_override_mask
                        )
                        suffix_trace_bits[idx] = suffix_trace_bits[idx + 1] | trace_mask
                        suffix_addr_trace_div[idx] = (
                            suffix_addr_trace_div[idx + 1] | addr_trace_div_mask
                        )
                        for source, arr in suffix_rf_sdc_sources.items():
                            arr[idx] = (
                                int(arr[idx + 1])
                                | int(rf_sdc_source_masks.get(source, 0))
                            ) & MASK64

                    interval_lo = seg_lo
                    for idx, rc in enumerate(seg_reads):
                        boundary_mass_here = range_sum(cycles_sorted, prefix, int(rc), int(rc) + 1)
                        if boundary_mass_here > 0:
                            boundary_events_count += 1
                            boundary_events_mass += int(boundary_mass_here)
                            boundary_bits_mass_total += int(boundary_mass_here) * int(bit_count)
                        boundary = rc + 1 if ge_mode else rc
                        interval_hi = min(seg_hi, boundary)
                        if interval_hi > interval_lo:
                            mass = range_sum(cycles_sorted, prefix, interval_lo, interval_hi)
                            if mass > 0:
                                base_due_agg = suffix_due[idx] & MASK64
                                addr_due_agg = suffix_addr_due[idx] & MASK64
                                base_sdc_agg = suffix_sdc[idx] & MASK64
                                addr_sdc_agg = suffix_addr_sdc[idx] & MASK64
                                base_unknown_agg = suffix_unknown[idx] & MASK64
                                addr_unknown_agg = suffix_addr_unknown[idx] & MASK64
                                addr_trace_div_agg = suffix_addr_trace_div[idx] & MASK64
                                unknown_agg = (base_unknown_agg | addr_unknown_agg) & MASK64
                                due_agg = (base_due_agg | addr_due_agg) & MASK64
                                due_agg &= ~unknown_agg
                                semantic_due_agg = base_due_agg & due_agg & MASK64
                                addr_due_agg = addr_due_agg & due_agg & (~semantic_due_agg) & MASK64
                                sdc_agg = (base_sdc_agg | addr_sdc_agg) & MASK64
                                sdc_agg &= ~unknown_agg
                                sdc_agg &= ~due_agg
                                base_sdc_agg = base_sdc_agg & sdc_agg & MASK64
                                addr_sdc_agg = addr_sdc_agg & sdc_agg & (~base_sdc_agg) & MASK64
                                trace_added_sdc_agg = suffix_trace_added_sdc[idx] & MASK64
                                trace_added_sdc_agg &= sdc_agg
                                trace_policy_used_agg = suffix_trace_policy_used[idx] & MASK64
                                trace_policy_override_agg = (
                                    suffix_trace_policy_override[idx] & MASK64
                                )
                                trace_bits_agg = suffix_trace_bits[idx] & MASK64
                                rf_sdc_source_agg = {
                                    source: int(arr[idx]) & MASK64
                                    for source, arr in suffix_rf_sdc_sources.items()
                                    if int(arr[idx]) & MASK64
                                }
                                add_rf_sdc_proof_source_mass(
                                    int(mass),
                                    int(base_sdc_agg),
                                    rf_sdc_source_agg,
                                )
                                record_rf_interval(
                                    {
                                        "mass": int(mass),
                                        "bit_count": int(bit_count),
                                        "selected_mask": int(selected_bits_mask64),
                                        "due_mask": int(due_agg),
                                        "sdc_mask": int(sdc_agg),
                                        "unknown_mask": int(unknown_agg),
                                        "trace_added_sdc_mask": int(trace_added_sdc_agg),
                                        "trace_policy_used_mask": int(trace_policy_used_agg),
                                        "trace_policy_override_mask": int(
                                            trace_policy_override_agg
                                        ),
                                        "trace_mask": int(trace_bits_agg),
                                        "semantic_due_mask": int(semantic_due_agg),
                                        "addr_due_mask": int(addr_due_agg),
                                        "addr_sdc_mask": int(addr_sdc_agg),
                                        "addr_unknown_mask": int(addr_unknown_agg),
                                        "addr_trace_div_mask": int(addr_trace_div_agg),
                                        "legacy_unknown_trace_uncovered": bool(
                                            trace_uncovered_mode == "legacy_unknown"
                                        ),
                                    }
                                )
                            interval_lo = interval_hi
                        if interval_lo >= seg_hi:
                            break

                    if interval_lo < seg_hi:
                        tail_mass = range_sum(cycles_sorted, prefix, interval_lo, seg_hi)
                        if tail_mass > 0:
                            masked_num += tail_mass * bit_count
                            if maybe_write is not None:
                                write_killed_mass += tail_mass

                    prev_write = seg_hi
                continue

            # Transient RF model: classify by first consumer read only.
            prev_lo = min_cycle
            for rc in read_cycles:
                boundary_mass_here = range_sum(cycles_sorted, prefix, int(rc), int(rc) + 1)
                if boundary_mass_here > 0:
                    boundary_events_count += 1
                    boundary_events_mass += int(boundary_mass_here)
                    boundary_bits_mass_total += int(boundary_mass_here) * int(bit_count)
                hi = rc + 1 if ge_mode else rc
                if hi > prev_lo:
                    mass = range_sum(cycles_sorted, prefix, prev_lo, hi)
                    if mass > 0:
                        consumer_masks = resolve_read_consumer_masks(tid, rc, label, uids)
                        if consumer_masks is None:
                            rec = resolve_read_record(tid, rc, label, uids)
                            if rec is None:
                                missing_read_event_keys.append((tid, rc, label, uid_tuple))
                                prev_lo = rc + 1 if ge_mode else rc
                                continue
                            ckey = (tid, rc, label)
                            masks = cache_final_masks.get(ckey)
                            if masks is None:
                                rec_sig = tuple(int(v) for v in rec)
                                if use_grouped_mode:
                                    rf_grouped_final_mask_requests += 1
                                    masks = cache_final_masks_by_signature.get(rec_sig)
                                else:
                                    masks = None
                                if masks is None:
                                    masks = final_due_sdc_masks_with_meta_fast_extended(
                                        rec=rec,
                                        trace_expanding_policy=trace_expanding_policy,
                                        trace_uncovered_mode=trace_uncovered_mode,
                                        trace_expanding_resolution_mode=trace_expanding_resolution_mode,
                                    )
                                    if use_grouped_mode:
                                        cache_final_masks_by_signature[rec_sig] = masks
                                else:
                                    rf_grouped_final_mask_hits += 1
                                cache_final_masks[ckey] = masks
                            (
                                due_mask,
                                sdc_mask,
                                unknown_mask,
                                trace_added_sdc_mask,
                                trace_policy_used_mask,
                                trace_mask,
                                trace_policy_override_mask,
                            ) = masks
                            (
                                addr_due_mask,
                                addr_sdc_mask,
                                addr_unknown_mask,
                                _addr_source_bits,
                                addr_trace_div_mask,
                            ) = resolve_addr_masks(
                                tid, rc, label, uids, trace_mask
                            )
                            rf_sdc_source_masks = {}
                        else:
                            (
                                due_mask,
                                sdc_mask,
                                unknown_mask,
                                trace_added_sdc_mask,
                                trace_policy_used_mask,
                                trace_mask,
                                trace_policy_override_mask,
                                addr_due_mask,
                                addr_sdc_mask,
                                addr_unknown_mask,
                                rf_sdc_source_masks,
                                _addr_source_bits,
                                addr_trace_div_mask,
                            ) = consumer_masks
                        unknown_mask = (unknown_mask | addr_unknown_mask) & MASK64
                        due_mask &= ~unknown_mask
                        base_due_mask = due_mask & MASK64
                        addr_due_mask &= (~unknown_mask) & MASK64
                        due_mask = (base_due_mask | addr_due_mask) & MASK64
                        semantic_due_mask = base_due_mask & MASK64
                        addr_due_mask &= (~semantic_due_mask) & MASK64
                        sdc_mask &= ~unknown_mask
                        base_sdc_mask = sdc_mask & MASK64
                        addr_sdc_mask &= (~unknown_mask) & MASK64
                        sdc_mask = (base_sdc_mask | addr_sdc_mask) & MASK64
                        sdc_mask &= ~due_mask
                        base_sdc_mask &= sdc_mask
                        addr_sdc_mask &= sdc_mask
                        addr_sdc_mask &= (~base_sdc_mask) & MASK64
                        add_rf_sdc_proof_source_mass(
                            int(mass),
                            int(base_sdc_mask),
                            rf_sdc_source_masks if consumer_masks is not None else {},
                        )
                        record_rf_interval(
                            {
                                "mass": int(mass),
                                "bit_count": int(bit_count),
                                "selected_mask": int(selected_bits_mask64),
                                "due_mask": int(due_mask),
                                "sdc_mask": int(sdc_mask),
                                "unknown_mask": int(unknown_mask),
                                "trace_added_sdc_mask": int(trace_added_sdc_mask),
                                "trace_policy_used_mask": int(trace_policy_used_mask),
                                "trace_policy_override_mask": int(trace_policy_override_mask),
                                "trace_mask": int(trace_mask),
                                "semantic_due_mask": int(semantic_due_mask),
                                "addr_due_mask": int(addr_due_mask),
                                "addr_sdc_mask": int(addr_sdc_mask),
                                "addr_unknown_mask": int(addr_unknown_mask),
                                "addr_trace_div_mask": int(addr_trace_div_mask),
                                "legacy_unknown_trace_uncovered": bool(
                                    trace_uncovered_mode == "legacy_unknown"
                                ),
                            }
                        )
                prev_lo = rc + 1 if ge_mode else rc

            tail_mass = range_sum(cycles_sorted, prefix, prev_lo, max_cycle)
            if tail_mass > 0:
                masked_num += tail_mass * bit_count

    flush_rf_interval_accum()

    if missing_read_event_keys:
        uniq = sorted(set(missing_read_event_keys))
        sample = uniq[:20]
        raise ValueError(
            "Missing analyzer read_events for regfile read keys "
            "(thread_id, read_cycle, reg_name, reg_uid_set). Sample: "
            f"{sample}"
        )

    computed_total_denominator = int(masked_num + sdc_num + due_num + unknown_num)
    if int(total_denominator) > int(computed_total_denominator):
        masked_num += int(total_denominator - computed_total_denominator)
    elif int(total_denominator) < int(computed_total_denominator):
        raise ValueError(
            "Internal RF accounting exceeds the FI-aligned denominator; "
            "refusing proportional count scaling "
            f"(masked+sdc+due+unknown={computed_total_denominator}, "
            f"denominator={total_denominator})."
        )

    if masked_num + sdc_num + due_num + unknown_num != total_denominator:
        raise ValueError(
            "Internal accounting mismatch: "
            f"masked+sdc+due+unknown={masked_num + sdc_num + due_num + unknown_num} "
            f"!= denominator={total_denominator}"
        )

    rates = {
        "masked": (masked_num / total_denominator) if total_denominator else 0.0,
        "sdc": (sdc_num / total_denominator) if total_denominator else 0.0,
        "due": (due_num / total_denominator) if total_denominator else 0.0,
        "unknown": (unknown_num / total_denominator) if total_denominator else 0.0,
    }
    trace_policy_unused_reason = ""
    if trace_policy_used_mass == 0:
        if saw_trace_selected_bits:
            trace_policy_unused_reason = "all trace bits covered by semantic"
        else:
            trace_policy_unused_reason = "no trace bits in selected (reg,bit) domain"

    analyzer_exact_meta_raw = analyzer.get("exact_meta", {})
    analyzer_exact_meta = (
        analyzer_exact_meta_raw if isinstance(analyzer_exact_meta_raw, dict) else {}
    )
    rf_due_mass_by_source: Dict[str, float] = {
        "addr_alias_sdc": float(max(0.0, rf_addr_alias_sdc_mass)),
        "rf_semantic_due": float(max(0.0, rf_trace_due_mass)),
        "rf_addr_oob_due": float(max(0.0, rf_addr_oob_due_mass)),
        "rf_trace_divergence_due": float(max(0.0, rf_trace_divergence_due_mass)),
        "trace_divergence_sdc": float(max(0.0, rf_trace_divergence_sdc_mass)),
        "rf_unknown_fold_to_due": 0.0,
    }
    rf_due_bits_by_cause = {
        "rf_semantic_due_bits": int(round(float(rf_due_mass_by_source["rf_semantic_due"]))),
        "rf_addr_oob_due_bits": int(round(float(rf_due_mass_by_source["rf_addr_oob_due"]))),
        "rf_trace_divergence_due_bits": int(
            round(float(rf_due_mass_by_source["rf_trace_divergence_due"]))
        ),
        "rf_unknown_fold_to_due_bits": 0,
    }
    if rf_addr_reg_policy_warning:
        print(
            f"WARNING: {rf_addr_reg_policy_warning}",
            file=sys.stderr,
        )

    return {
        "classification_counts": {
            "masked": int(masked_num),
            "sdc": int(sdc_num),
            "due": int(due_num),
            "unknown": int(unknown_num),
            "total": int(total_denominator),
        },
        "classification_rates": rates,
        "weighted_classification_counts": {
            "masked": fraction(masked_num, total_denominator),
            "sdc": fraction(sdc_num, total_denominator),
            "due": fraction(due_num, total_denominator),
            "unknown": fraction(unknown_num, total_denominator),
            "total": fraction(total_denominator, total_denominator),
        },
        "weighted_classification_rates": {
            "masked": fraction(masked_num, total_denominator),
            "sdc": fraction(sdc_num, total_denominator),
            "due": fraction(due_num, total_denominator),
            "unknown": fraction(unknown_num, total_denominator),
        },
        "exact_meta": {
            "cycles_file": str(args.cycles),
            "active_threads_log": (
                str(args.active_threads_log) if args.active_threads_log is not None else None
            ),
            "thread_rand_max": thread_rand_max,
            "thread_rands": thread_rands if thread_rands is not None else "0..thread_rand_max-1",
            "thread_cycle_backend_requested": (
                "force"
                if _CPP_THREAD_CYCLE_FORCE
                else ("auto" if _CPP_THREAD_CYCLE_ENABLED else "disabled")
            ),
            "thread_cycle_backend_used": str(thread_cycle_backend),
            "register_count": reg_count,
            "rf_used_register_count": int(reg_count),
            "rf_domain_policy": str(rf_domain_info.get("rf_domain_policy", "sampling_space")),
            "rf_domain_source": str(rf_domain_info.get("rf_domain_source", "used")),
            "rf_domain_bits_per_seed_final": int(
                rf_domain_info.get("rf_domain_bits_per_seed_final", reg_count * bit_count)
            ),
            "rf_domain_total_bits_final": int(
                rf_domain_info.get("rf_domain_total_bits_final", total_denominator)
            ),
            "rf_domain_bits_per_seed_used_regs": int(
                rf_domain_info.get("rf_domain_bits_per_seed_used_regs", reg_count * bit_count)
            ),
            "rf_domain_bits_per_seed_allocated_regs": int(
                rf_domain_info.get("rf_domain_bits_per_seed_allocated_regs", 0)
            ),
            "rf_domain_bits_per_seed_hw_full": int(
                rf_domain_info.get("rf_domain_bits_per_seed_hw_full", 0)
            ),
            "rf_domain_bits_per_seed_sampling_space": int(
                rf_domain_info.get("rf_domain_bits_per_seed_sampling_space", 0)
            ),
            "rf_domain_sampling_total_bits": int(
                rf_domain_info.get("rf_domain_sampling_total_bits", 0)
            ),
            "rf_domain_allocated_register_count": int(
                rf_domain_info.get("rf_domain_allocated_register_count", 0)
            ),
            "rf_domain_hw_register_count": int(
                rf_domain_info.get("rf_domain_hw_register_count", 0)
            ),
            "rf_used_domain_total_bits": int(used_total_denominator),
            "bit_count": bit_count,
            "datatype_bits": datatype_bits,
            "consumer_compare": args.consumer_compare,
            "rf_fault_model": args.rf_fault_model,
            "rf_group_mode": str(storage_group_mode),
            "rf_interval_accum_backend_used": str(rf_interval_accum_backend_used),
            "rf_grouped_final_mask_requests": int(rf_grouped_final_mask_requests),
            "rf_grouped_final_mask_hits": int(rf_grouped_final_mask_hits),
            "rf_grouped_final_mask_entries": int(len(cache_final_masks_by_signature)),
            "rf_grouped_consumer_signature_requests": int(
                rf_grouped_consumer_signature_requests
            ),
            "rf_grouped_consumer_signature_hits": int(
                rf_grouped_consumer_signature_hits
            ),
            "rf_grouped_consumer_signature_entries": int(
                len(cache_consumer_base_masks_by_signature)
            ),
            "trace_expanding_policy": trace_expanding_policy,
            "trace_expanding_resolution_mode": str(trace_expanding_resolution_mode),
            "trace_uncovered_mode": str(trace_uncovered_mode),
            "trace_expanding_sdc_numerator": int(trace_expanding_sdc_numerator),
            "trace_policy_used_bits": int(trace_policy_used_bits),
            "trace_policy_used_mass": int(trace_policy_used_mass),
            "trace_policy_override_bits": int(trace_policy_override_bits),
            "trace_policy_override_mass": int(trace_policy_override_mass),
            "trace_policy_override_reason_breakdown": {
                "sdc": int(trace_policy_override_sdc_bits),
                "due": int(trace_policy_override_due_bits),
                "unknown": int(trace_policy_override_unknown_bits),
                "masked": int(trace_policy_override_masked_bits),
            },
            "trace_uncovered_unknown_bits": int(trace_uncovered_unknown_bits),
            "trace_uncovered_unknown_mass": int(trace_uncovered_unknown_mass),
            "trace_policy_unused_reason": trace_policy_unused_reason,
            "unknown_bits": int(unknown_num),
            "unknown_mass": int(unknown_num),
            "total_bits": int(total_denominator),
            "data_bits": int(total_denominator),
            "tag_bits": 0,
            "masked_bits_data": int(masked_num),
            "sdc_bits_data": int(sdc_num),
            "due_bits_data": int(due_num),
            "unknown_bits_data": int(unknown_num),
            "masked_bits_tag": 0,
            "sdc_bits_tag": 0,
            "due_bits_tag": 0,
            "unknown_bits_tag": 0,
            "addr_domain_bits": _normalize_numeric(
                float(rf_addr_due_num + rf_addr_sdc_num + rf_addr_unknown_num)
            ),
            "addr_sdc_bits": _normalize_numeric(float(rf_addr_sdc_num)),
            "addr_due_bits": _normalize_numeric(float(rf_addr_due_num)),
            "addr_unknown_bits": _normalize_numeric(float(rf_addr_unknown_num)),
            "rf_sdc_proof_source_mass": _normalize_mass_map(
                {
                    source: float(max(0.0, rf_sdc_proof_source_mass.get(source, 0.0)))
                    for source in RF_SDC_PROOF_SOURCE_KEYS
                    if float(rf_sdc_proof_source_mass.get(source, 0.0)) > 0.0
                }
            ),
            "rf_sdc_proof_source_bits": _mass_map_to_bits_map(
                {
                    source: float(max(0.0, rf_sdc_proof_source_mass.get(source, 0.0)))
                    for source in RF_SDC_PROOF_SOURCE_KEYS
                    if float(rf_sdc_proof_source_mass.get(source, 0.0)) > 0.0
                }
            ),
            "rf_sdc_proof_source_policy": (
                "exact_read_consumer_path; overlapping proof paths are reported "
                "as rf_multi_mechanism_transfer; no fitted outcome parameter"
            ),
            "due_source_bits": _mass_map_to_bits_map(rf_due_mass_by_source),
            "due_mass_by_source": _normalize_mass_map(rf_due_mass_by_source),
            "rf_due_bits_by_cause": dict(rf_due_bits_by_cause),
            "rf_addr_reg_policy": str(rf_addr_reg_policy),
            "rf_addr_reg_policy_effective": str(rf_addr_reg_policy_effective),
            "rf_addr_reg_policy_warning": str(rf_addr_reg_policy_warning),
            "rf_addr_source_register_count": int(len(rf_addr_source_reg_names)),
            "rf_addr_source_uid_count": int(len(rf_addr_source_reg_uids)),
            "rf_addr_due_observed_overlap_bits": int(rf_addr_due_observed_overlap_bits),
            "rf_addr_due_observed_overlap_records": int(rf_addr_due_observed_overlap_records),
            **_boundary_meta_fields(
                consumer_compare=str(args.consumer_compare),
                same_cycle_effect_prob=same_cycle_effect_prob,
                boundary_events_count=int(boundary_events_count),
                boundary_events_mass=float(boundary_events_mass),
                boundary_bits_mass_total=float(boundary_bits_mass_total),
            ),
            "missing_active_thread_cycles": int(
                cycle_records_meta.get("missing_active_thread_cycles", 0)
            ),
            "missing_active_thread_cycle_ratio": float(
                cycle_records_meta.get("missing_active_thread_cycle_ratio", 0.0)
            ),
            "active_threads_carried_forward_cycles": int(
                cycle_records_meta.get("active_threads_carried_forward_cycles", 0)
            ),
            "active_threads_empty_fill_cycles": int(
                cycle_records_meta.get("active_threads_empty_fill_cycles", 0)
            ),
            "missing_active_threads_policy": str(
                cycle_records_meta.get("missing_active_threads_policy", "empty")
            ),
            "semantic_error_reason_counts": dict(
                analyzer_exact_meta.get("semantic_error_reason_counts", {})
            ),
            "semantic_error_reasons_top20": list(
                analyzer_exact_meta.get("semantic_error_reasons_top20", [])
            ),
            "semantic_error_samples": list(
                analyzer_exact_meta.get("semantic_error_samples", [])
            ),
            "semantic_infra_error_count": int(
                analyzer_exact_meta.get("semantic_infra_error_count", 0)
            ),
            "semantic_infra_error_reason_counts": dict(
                analyzer_exact_meta.get("semantic_infra_error_reason_counts", {})
            ),
            "semantic_infra_error_reasons_top20": list(
                analyzer_exact_meta.get("semantic_infra_error_reasons_top20", [])
            ),
            "semantic_unknown_count": int(
                analyzer_exact_meta.get("semantic_unknown_count", 0)
            ),
            "semantic_unknown_reason_counts": dict(
                analyzer_exact_meta.get("semantic_unknown_reason_counts", {})
            ),
            "semantic_unknown_reasons_top20": list(
                analyzer_exact_meta.get("semantic_unknown_reasons_top20", [])
            ),
            "semantic_unknown_reason_details_top20": list(
                analyzer_exact_meta.get("semantic_unknown_reason_details_top20", [])
            ),
            "semantic_unknown_samples": list(
                analyzer_exact_meta.get("semantic_unknown_samples", [])
            ),
            "auto_range_created_count": int(
                analyzer_exact_meta.get("auto_range_created_count", 0)
            ),
            "auto_range_reason_counts": dict(
                analyzer_exact_meta.get("auto_range_reason_counts", {})
            ),
            "auto_range_samples_top20": list(
                analyzer_exact_meta.get("auto_range_samples_top20", [])
            ),
            "trace_load_init_event_count": int(
                analyzer_exact_meta.get("trace_load_init_event_count", 0)
            ),
            "trace_load_init_byte_count": int(
                analyzer_exact_meta.get("trace_load_init_byte_count", 0)
            ),
            "trace_load_init_samples_top20": list(
                analyzer_exact_meta.get("trace_load_init_samples_top20", [])
            ),
            "trace_bit_no_semantic_coverage_records": int(
                analyzer_exact_meta.get("trace_bit_no_semantic_coverage_records", 0)
            ),
            "trace_bit_no_semantic_coverage_bits": int(
                analyzer_exact_meta.get("trace_bit_no_semantic_coverage_bits", 0)
            ),
            "trace_bit_no_semantic_coverage_samples": list(
                analyzer_exact_meta.get("trace_bit_no_semantic_coverage_samples", [])
            ),
            "due_oracle_reason_counts": dict(
                analyzer_exact_meta.get("due_oracle_reason_counts", {})
            ),
            "due_oracle_reason_details_top20": list(
                analyzer_exact_meta.get("due_oracle_reason_details_top20", [])
            ),
            "output_oracle_type": str(
                analyzer_exact_meta.get("output_oracle_type", "")
            ),
            "output_oracle_has_output_spec": bool(
                analyzer_exact_meta.get("output_oracle_has_output_spec", False)
            ),
            "output_oracle_spec_entry_count": int(
                analyzer_exact_meta.get("output_oracle_spec_entry_count", 0)
            ),
            "output_oracle_spec_total_bytes": int(
                analyzer_exact_meta.get("output_oracle_spec_total_bytes", 0)
            ),
            "output_oracle_spec_ranges": list(
                analyzer_exact_meta.get("output_oracle_spec_ranges", [])
            ),
            "output_last_writer_store_count": int(
                analyzer_exact_meta.get("output_last_writer_store_count", 0)
            ),
            "output_total_store_count": int(
                analyzer_exact_meta.get("output_total_store_count", 0)
            ),
            "filtered_store_ratio": float(
                analyzer_exact_meta.get("filtered_store_ratio", 0.0)
            ),
            "addr_observed_seed_suppressed_bits": int(
                analyzer_exact_meta.get("addr_observed_seed_suppressed_bits", 0)
            ),
            "addr_observed_seed_suppressed_events": int(
                analyzer_exact_meta.get("addr_observed_seed_suppressed_events", 0)
            ),
            "tol_output_store_seed_count": int(
                analyzer_exact_meta.get("tol_output_store_seed_count", 0)
            ),
            "tol_float_backward_op_count": int(
                analyzer_exact_meta.get("tol_float_backward_op_count", 0)
            ),
            "tol_memory_forward_byte_count": int(
                analyzer_exact_meta.get("tol_memory_forward_byte_count", 0)
            ),
            "tol_fallback_count": int(
                analyzer_exact_meta.get("tol_fallback_count", 0)
            ),
            "inactive_base_mass": int(inactive_base_mass),
            "active_base_mass": int(active_base_mass),
            "write_killed_mass": int(write_killed_mass),
            "unmapped_registers": sorted(
                [label for label, uids in label_to_uids.items() if not uids]
            ),
            "multi_uid_registers": sorted(
                [label for label, uids in label_to_uids.items() if len(uids) > 1]
            ),
        },
    }


def compute_exact_smem(args: argparse.Namespace, fault_component: str) -> Dict[str, Any]:
    storage_group_mode = _normalize_storage_group_mode(
        getattr(args, "storage_group_mode", "legacy")
    )
    use_grouped_mode = storage_group_mode == "grouped"
    analyzer = _load_analyzer_output_for_compute(
        args.analyzer_output,
        normalize_trace_coverage=bool(getattr(args, "normalize_trace_coverage", False)),
    )
    analyzer_exact_meta_raw = analyzer.get("exact_meta", {})
    analyzer_exact_meta = (
        analyzer_exact_meta_raw if isinstance(analyzer_exact_meta_raw, dict) else {}
    )
    smem_sites_raw = analyzer.get("smem_fault_sites", [])
    if not isinstance(smem_sites_raw, list):
        raise ValueError("analyzer output missing smem_fault_sites list")
    smem_sites = [rec for rec in smem_sites_raw if isinstance(rec, dict)]

    if args.trace_template is None:
        raise ValueError(
            "--trace-template is required for fault-component smem_rf/smem_lds"
        )
    trace_template_key = _path_cache_key(Path(args.trace_template))
    trace_template = parse_trace_template(Path(trace_template_key))
    memory_ranges = list(trace_template.get("memory_ranges", []))
    event_by_index = _trace_event_by_index_cached(trace_template_key)
    (
        thread_to_scope,
        shared_write_cycles,
        shared_read_cycles,
    ) = _build_shared_trace_indexes(trace_template)
    shared_observed_addr_sets = _build_shared_observed_addr_sets(smem_sites)
    shared_escape_addr_sets = _build_shared_escape_addr_sets(smem_sites)
    shared_live_target_addr_sets = _select_shared_live_target_sets(
        shared_observed_addr_sets,
        shared_escape_addr_sets,
    )

    cycle_records, cycle_records_meta = load_cycle_records_with_meta(
        args.cycles,
        args.active_threads_log,
        bool(getattr(args, "allow_missing_active_threads", False)),
        str(getattr(args, "missing_active_threads_policy", "empty")),
    )
    shared_scope_thread_ids_by_cycle: Dict[int, Tuple[int, ...]] = {}
    if args.active_threads_log is not None:
        shared_scope_thread_ids_by_cycle = load_shared_scope_thread_ids_log(
            args.active_threads_log
        )
    trace_expanding_policy = str(args.trace_expanding_policy).strip().lower()
    if trace_expanding_policy != CANONICAL_TRACE_EXPANDING_POLICY:
        raise ValueError(
            "trace_expanding_policy must be one of {}; got {!r}".format(
                CANONICAL_TRACE_EXPANDING_POLICY,
                trace_expanding_policy,
            )
        )
    trace_uncovered_mode = _normalize_trace_uncovered_mode(
        getattr(args, "trace_uncovered_mode", "legacy_unknown")
    )
    trace_expanding_resolution_mode = str(
        getattr(args, "trace_expanding_resolution_mode", "legacy")
    ).strip().lower()
    if trace_expanding_resolution_mode != CANONICAL_TRACE_EXPANDING_RESOLUTION_MODE:
        raise ValueError(
            "trace_expanding_resolution_mode must be one of {}; got {!r}".format(
                CANONICAL_TRACE_EXPANDING_RESOLUTION_MODE,
                trace_expanding_resolution_mode,
            )
        )
    addr_fault_policy = _normalize_addr_fault_policy(
        getattr(args, "addr_fault_policy", CANONICAL_ADDR_FAULT_POLICY)
    )
    trace_divergence_policy = _normalize_trace_divergence_policy(
        getattr(args, "trace_divergence_policy", CANONICAL_TRACE_DIVERGENCE_POLICY)
    )
    addr_due_mode = _normalize_addr_due_mode(getattr(args, "addr_due_mode", CANONICAL_ADDR_DUE_MODE))
    cache_addr_domain_enabled = not bool(int(getattr(args, "use_sampling_space_domain", 0)))
    addr_domain_enabled = bool(cache_addr_domain_enabled)
    addr_bits_mode, addr_bits_explicit = _parse_addr_bits_spec(
        getattr(args, "addr_bits", "auto")
    )
    smem_addr_exception_policy = _normalize_smem_addr_exception_policy(
        getattr(args, "smem_addr_exception_policy", CANONICAL_SMEM_ADDR_EXCEPTION_POLICY)
    )
    smem_domain_policy = _normalize_smem_domain_policy(
        getattr(args, "smem_domain_policy", "sampling_space")
    )
    fi_space = _load_fi_sampling_space(getattr(args, "fi_sampling_space_path", None))
    ge_mode = str(args.consumer_compare).strip().lower() == "ge"
    same_cycle_effect_prob = _normalize_same_cycle_effect_prob(
        getattr(args, "same_cycle_effect_prob", None)
    )
    datatype_bits = int(args.datatype_bits)
    if datatype_bits <= 0:
        raise ValueError("datatype_bits must be > 0")
    max_component_bits = 8
    bits = parse_spec_list(args.bits)
    if bits is None:
        # FI memory/cache bitflip indices are sampled from the byte lane domain.
        bits_1based = list(range(1, max_component_bits + 1))
    else:
        bits_1based = sorted({b for b in bits if 1 <= b <= max_component_bits})
        if not bits_1based:
            raise ValueError("bit domain is empty after filtering for shared memory byte")
    bit_count = int(len(bits_1based))
    selected_bits_mask = 0
    for b in bits_1based:
        selected_bits_mask |= 1 << (int(b) - 1)

    # Shared-memory structural injection uses block_rand (not thread_rand).
    block_rands = parse_spec_list(args.block_rands)
    if block_rands is not None and len(block_rands) == 0:
        raise ValueError("--block-rands provided but empty")
    block_rand_max = None if block_rands is not None else int(args.block_rand_max)
    block_seed_domain_hint = None
    if fault_component == "smem_rf":
        if block_rands is None:
            if block_rand_max is None or int(block_rand_max) <= 0:
                raise ValueError("--block-rand-max must be > 0 when --block-rands is not set")
            block_seed_domain_hint = int(block_rand_max)

    thread_rands = parse_spec_list(args.thread_rands)
    if thread_rands is not None and len(thread_rands) == 0:
        raise ValueError("--thread-rands provided but empty")
    thread_rand_max = None if thread_rands is not None else int(args.thread_rand_max)
    if thread_rands is None and (thread_rand_max is None or thread_rand_max <= 0):
        raise ValueError("--thread-rand-max must be > 0 when --thread-rands is not set")

    (
        thread_cycle_weights,
        seed_domain_size,
        inactive_base_mass,
        active_base_mass,
    ) = _thread_cycle_weights(cycle_records, thread_rands, thread_rand_max)
    thread_cycle_backend = (
        "cpp" if _should_use_cpp_thread_cycle(cycle_records) else "python"
    )

    scope_cycle_weights: Dict[Tuple[int, int], Dict[int, int]] = {}
    scope_prefix: Dict[Tuple[int, int], Tuple[List[int], List[int], int]] = {}
    scope_count_hist: Counter = Counter()
    block_seed_domain_size = 0
    smem_domain_diag = _resolve_smem_size_bits(
        fault_component=fault_component,
        args=args,
        fi_space=fi_space,
        trace_template=trace_template,
        memory_ranges=memory_ranges,
    )
    smem_size_bits = int(max(0, smem_domain_diag.get("smem_size_bits_final", 0)))
    smem_domain_full_bytes = 0
    smem_domain_tail_bits = 0
    smem_selected_bit_domain_size = 0
    if smem_size_bits > 0:
        smem_domain_full_bytes = int(smem_size_bits) // 8
        smem_domain_tail_bits = int(smem_size_bits) % 8
        smem_selected_bit_domain_size = _selected_smem_domain_bit_count(
            selected_bits_mask=selected_bits_mask,
            bit_count_full_byte=bit_count,
            domain_full_bytes=smem_domain_full_bytes,
            domain_tail_bits=smem_domain_tail_bits,
        )

    denominator = 0
    if fault_component == "smem_rf":
        if smem_size_bits <= 0:
            raise ValueError(
                "smem_rf requires a positive shared-memory bit domain; "
                "pass --smem-size-bits or provide shared memory_ranges with size"
            )
        if smem_domain_full_bytes <= 0 and smem_domain_tail_bits <= 0:
            raise ValueError("shared-memory bit domain is empty")
        if smem_selected_bit_domain_size <= 0:
            raise ValueError("selected shared-memory bit domain is empty")

        (
            scope_cycle_weights,
            block_seed_domain_size,
            scope_count_hist,
        ) = _scope_cycle_weights_from_block_sampling(
            cycle_records=cycle_records,
            thread_to_scope=thread_to_scope,
            block_rands=block_rands,
            block_rand_max=block_seed_domain_hint,
            shared_scope_thread_ids_by_cycle=shared_scope_thread_ids_by_cycle,
        )
        scope_prefix = _scope_cycle_prefix(scope_cycle_weights)
        total_cycle_lines = sum(int(rec.multiplicity) for rec in cycle_records)
        denominator = (
            int(total_cycle_lines)
            * int(block_seed_domain_size)
            * int(smem_selected_bit_domain_size)
        )
        data_denominator = int(denominator)

    due_num = 0.0
    sdc_num = 0.0
    unknown_num = 0.0
    data_denominator = 0
    due_data_num = 0.0
    sdc_data_num = 0.0
    unknown_data_num = 0.0
    addr_denominator = 0
    due_addr_num = 0.0
    sdc_addr_num = 0.0
    unknown_addr_num = 0.0
    trace_policy_used_bits = 0
    trace_policy_used_mass = 0.0
    trace_policy_override_bits = 0
    trace_policy_override_mass = 0.0
    trace_policy_override_sdc_bits = 0
    trace_policy_override_due_bits = 0
    trace_policy_override_unknown_bits = 0
    trace_policy_override_masked_bits = 0
    trace_uncovered_unknown_bits = 0
    trace_uncovered_unknown_mass = 0.0
    trace_divergence_bits = 0
    trace_divergence_mass = 0.0
    smem_byte_defuse_sdc_bits = 0
    smem_byte_defuse_sdc_mass = 0.0
    due_source_mass: Dict[str, float] = defaultdict(float)
    boundary_events_count = 0
    boundary_events_mass = 0.0
    boundary_bits_mass_total = 0.0
    addr_effective_bits_seen: Set[int] = set()
    addr_bits_count_seen: Set[int] = set()
    smem_site_mask_signature_cache: Dict[
        Tuple[str, int, int, int, int, int, int, int, str, str, str],
        Tuple[int, int, int, int, int],
    ] = {}
    smem_site_mask_signature_requests = 0
    smem_site_mask_signature_hits = 0
    addr_ranges, smem_addr_ranges_source = _load_smem_addr_valid_ranges(
        trace_memory_ranges=memory_ranges,
        external_path=getattr(args, "addr_valid_ranges_path", None),
        smem_size_bits=int(smem_size_bits),
    )

    def resolve_smem_site_masks(
        rec: Mapping[str, Any],
    ) -> Tuple[int, int, int, int, int]:
        nonlocal smem_site_mask_signature_requests
        nonlocal smem_site_mask_signature_hits
        if not use_grouped_mode:
            return final_due_sdc_masks_for_site_extended(
                rec=rec,
                trace_expanding_policy=trace_expanding_policy,
                trace_uncovered_mode=trace_uncovered_mode,
                trace_expanding_resolution_mode=trace_expanding_resolution_mode,
            )
        smem_site_mask_signature_requests += 1
        sig = (
            str(rec.get("site_kind", "")),
            int(rec.get("width_bits", 0)),
            int(parse_mask(rec.get("observed_mask_this_site", 0))) & MASK64,
            int(parse_mask(rec.get("due_mask_this_site", 0))) & MASK64,
            int(parse_mask(rec.get("trace_expanding_mask_this_site", 0))) & MASK64,
            int(parse_mask(rec.get("semantic_masked_mask_this_site", 0))) & MASK64,
            int(parse_mask(rec.get("semantic_sdc_mask_this_site", 0))) & MASK64,
            int(parse_mask(rec.get("semantic_due_mask_this_site", 0))) & MASK64,
            str(trace_expanding_policy),
            str(trace_uncovered_mode),
            str(trace_expanding_resolution_mode),
        )
        cached_masks = smem_site_mask_signature_cache.get(sig)
        if cached_masks is not None:
            smem_site_mask_signature_hits += 1
            return cached_masks
        cached_masks = final_due_sdc_masks_for_site_extended(
            rec=rec,
            trace_expanding_policy=trace_expanding_policy,
            trace_uncovered_mode=trace_uncovered_mode,
            trace_expanding_resolution_mode=trace_expanding_resolution_mode,
        )
        smem_site_mask_signature_cache[sig] = cached_masks
        return cached_masks

    if fault_component == "smem_lds":
        for rec in smem_sites:
            if str(rec.get("site_kind", "")) != "smem_lds":
                continue
            tid = int(rec.get("thread_id", -1))
            cycle = int(rec.get("cycle", -1))
            mass = int(thread_cycle_weights.get(tid, {}).get(cycle, 0))
            if mass <= 0:
                continue
            (
                due_mask,
                sdc_mask,
                unknown_mask,
                trace_policy_used_mask,
                trace_policy_override_mask,
            ) = resolve_smem_site_masks(rec)
            trace_mask_this_site = parse_mask(rec.get("trace_expanding_mask_this_site", 0)) & 0xFF
            (
                due_mask,
                sdc_mask,
                unknown_mask,
                trace_div_mask_this_site,
            ) = _apply_trace_divergence_policy_to_masks(
                due_mask=int(due_mask),
                sdc_mask=int(sdc_mask),
                unknown_mask=int(unknown_mask),
                trace_mask=int(trace_mask_this_site),
                width_bits=8,
                policy=trace_divergence_policy,
            )
            due_mask &= ~unknown_mask
            sdc_mask &= ~unknown_mask
            sdc_mask &= ~due_mask
            due_bits = popcount_u64(due_mask & selected_bits_mask)
            sdc_bits = popcount_u64((sdc_mask & (~due_mask & MASK64)) & selected_bits_mask)
            unknown_bits = popcount_u64(unknown_mask & selected_bits_mask)
            trace_policy_used_bits_here = popcount_u64(trace_policy_used_mask & selected_bits_mask)
            trace_policy_override_bits_here = popcount_u64(
                int(trace_policy_override_mask) & int(selected_bits_mask)
            )
            trace_policy_override_sdc_bits_here = popcount_u64(
                (int(trace_policy_override_mask) & int(sdc_mask)) & int(selected_bits_mask)
            )
            trace_policy_override_due_bits_here = popcount_u64(
                (int(trace_policy_override_mask) & int(due_mask)) & int(selected_bits_mask)
            )
            trace_policy_override_unknown_bits_here = popcount_u64(
                (int(trace_policy_override_mask) & int(unknown_mask)) & int(selected_bits_mask)
            )
            trace_policy_override_masked_bits_here = max(
                0,
                int(trace_policy_override_bits_here)
                - int(trace_policy_override_sdc_bits_here)
                - int(trace_policy_override_due_bits_here)
                - int(trace_policy_override_unknown_bits_here),
            )
            trace_div_bits = popcount_u64(int(trace_div_mask_this_site) & selected_bits_mask)
            if trace_div_bits > 0:
                trace_divergence_bits += int(trace_div_bits)
                trace_divergence_mass += float(int(mass) * int(trace_div_bits))
                target_cls = _trace_divergence_target_class(trace_divergence_policy)
                _add_source_mass(
                    due_source_mass,
                    f"trace_divergence_{target_cls}",
                    float(int(mass) * int(trace_div_bits)),
                )
            due_mass = float(int(mass) * int(due_bits))
            sdc_mass = float(int(mass) * int(sdc_bits))
            unknown_mass = float(int(mass) * int(unknown_bits))
            due_data_num += float(due_mass)
            sdc_data_num += float(sdc_mass)
            unknown_data_num += float(unknown_mass)
            due_num += float(due_mass)
            sdc_num += float(sdc_mass)
            unknown_num += float(unknown_mass)
            _add_source_mass(due_source_mass, "semantic_due", float(due_mass))
            trace_policy_used_bits += int(trace_policy_used_bits_here)
            trace_policy_used_mass += float(int(mass) * int(trace_policy_used_bits_here))
            trace_policy_override_bits += int(trace_policy_override_bits_here)
            trace_policy_override_mass += float(int(mass) * int(trace_policy_override_bits_here))
            trace_policy_override_sdc_bits += int(trace_policy_override_sdc_bits_here)
            trace_policy_override_due_bits += int(trace_policy_override_due_bits_here)
            trace_policy_override_unknown_bits += int(trace_policy_override_unknown_bits_here)
            trace_policy_override_masked_bits += int(trace_policy_override_masked_bits_here)
            if trace_uncovered_mode == "legacy_unknown":
                trace_uncovered_unknown_bits += int(trace_policy_used_bits_here)
                trace_uncovered_unknown_mass += float(
                    int(mass) * int(trace_policy_used_bits_here)
                )
            if int(mass) > 0:
                boundary_events_count += 1
                boundary_events_mass += float(int(mass))
                boundary_bits_mass_total += float(int(mass) * int(bit_count))
            data_denominator += int(mass) * int(bit_count)

            if addr_domain_enabled:
                event_index = int(rec.get("event_index", -1))
                raw_ev = event_by_index.get(event_index, {})
                access_size = int(rec.get("width_bits", 8)) // 8
                if access_size <= 0:
                    access_size = 1
                if raw_ev:
                    effective_mask = _event_effective_address_mask_from_raw(raw_ev)
                else:
                    effective_mask = _event_effective_address_mask_from_raw(
                        {"mem_space": rec.get("mem_space", "shared")}
                    )
                (
                    selected_addr_bits_mask,
                    addr_bits_count,
                    addr_effective_bits,
                ) = _resolve_selected_addr_bits(
                    effective_mask=int(effective_mask),
                    addr_bits_mode=addr_bits_mode,
                    addr_bits_explicit=addr_bits_explicit,
                )
                if int(addr_effective_bits) > 0:
                    addr_effective_bits_seen.add(int(addr_effective_bits))
                addr_bits_count_seen.add(int(addr_bits_count))
                (
                    addr_due_mask,
                    addr_sdc_mask,
                    addr_unknown_mask,
                    _addr_masked_mask,
                    addr_source_bits,
                    addr_trace_div_mask,
                ) = _classify_addr_masks_with_ranges(
                    addr=int(rec.get("addr", 0)),
                    selected_mask=int(selected_addr_bits_mask),
                    effective_mask=int(effective_mask),
                    mem_space=str(
                        canonical_space(rec.get("mem_space", "shared")) or "shared"
                    ),
                    access_size=int(access_size),
                    event_index=event_index if event_index >= 0 else None,
                    cycle=int(rec.get("cycle", -1)) if int(rec.get("cycle", -1)) >= 0 else None,
                    thread_id=int(rec.get("thread_id", -1)) if int(rec.get("thread_id", -1)) >= 0 else None,
                    cta_id=int(rec.get("cta_id", -1)) if int(rec.get("cta_id", -1)) >= 0 else None,
                    sm_id=int(rec.get("sm_id", -1)) if int(rec.get("sm_id", -1)) >= 0 else None,
                    addr_ranges=addr_ranges,
                    addr_fault_policy=addr_fault_policy,
                    addr_due_mode=addr_due_mode,
                    trace_mask=int(trace_mask_this_site),
                    trace_divergence_policy=trace_divergence_policy,
                    live_addr_set=shared_live_target_addr_sets.get(
                        (
                            int(rec.get("sm_id", -1)),
                            int(rec.get("cta_id", -1)),
                        )
                    ),
                    oob_exception_policy=str(smem_addr_exception_policy),
                    source_prefix="smem_addr",
                )
                addr_due_bits = popcount_u64(int(addr_due_mask) & int(selected_addr_bits_mask))
                addr_sdc_bits = popcount_u64(int(addr_sdc_mask) & int(selected_addr_bits_mask))
                addr_unknown_bits = popcount_u64(
                    int(addr_unknown_mask) & int(selected_addr_bits_mask)
                )
                due_addr_num += float(int(mass) * int(addr_due_bits))
                sdc_addr_num += float(int(mass) * int(addr_sdc_bits))
                unknown_addr_num += float(int(mass) * int(addr_unknown_bits))
                for skey, sval in addr_source_bits.items():
                    _add_source_mass(
                        due_source_mass,
                        str(skey),
                        float(int(mass) * int(sval)),
                    )
                addr_trace_div_bits = popcount_u64(
                    int(addr_trace_div_mask) & int(selected_addr_bits_mask)
                )
                if addr_trace_div_bits > 0:
                    trace_divergence_bits += int(addr_trace_div_bits)
                    trace_divergence_mass += float(int(mass) * int(addr_trace_div_bits))
                addr_denominator += int(mass) * int(addr_bits_count)
    else:
        load_masks_by_scope_addr_cycle: Dict[
            Tuple[int, int, int, int], Dict[str, int]
        ] = {}
        store_semantic_by_scope_addr_cycle: Dict[
            Tuple[int, int, int, int], Dict[str, int]
        ] = {}

        for rec in smem_sites:
            site_kind = str(rec.get("site_kind", ""))
            if site_kind == "smem_rf":
                sm_id = rec.get("sm_id")
                cta_id = rec.get("cta_id")
                cycle = int(rec.get("cycle", -1))
                if sm_id is None or cta_id is None or cycle < 0:
                    continue
                key = (
                    int(sm_id),
                    int(cta_id),
                    int(rec.get("addr", 0)),
                    int(cycle),
                )
                semantic_masked_mask = (
                    parse_mask(rec.get("semantic_masked_mask_this_site", 0)) & 0xFF
                )
                semantic_sdc_mask = (
                    parse_mask(rec.get("semantic_sdc_mask_this_site", 0)) & 0xFF
                )
                semantic_due_mask = (
                    parse_mask(rec.get("semantic_due_mask_this_site", 0)) & 0xFF
                )
                semantic_unknown_mask = (
                    parse_mask(rec.get("semantic_unknown_mask_this_site", 0)) & 0xFF
                )
                if (
                    semantic_masked_mask != 0
                    or semantic_sdc_mask != 0
                    or semantic_due_mask != 0
                    or semantic_unknown_mask != 0
                ):
                    prev_store_masks = store_semantic_by_scope_addr_cycle.get(key)
                    if prev_store_masks is None:
                        store_semantic_by_scope_addr_cycle[key] = {
                            "semantic_masked": int(semantic_masked_mask) & 0xFF,
                            "semantic_sdc": int(semantic_sdc_mask) & 0xFF,
                            "semantic_due": int(semantic_due_mask) & 0xFF,
                            "semantic_unknown": int(semantic_unknown_mask) & 0xFF,
                        }
                    else:
                        store_semantic_by_scope_addr_cycle[key] = {
                            "semantic_masked": (
                                int(prev_store_masks.get("semantic_masked", 0))
                                | int(semantic_masked_mask)
                            ) & 0xFF,
                            "semantic_sdc": (
                                int(prev_store_masks.get("semantic_sdc", 0))
                                | int(semantic_sdc_mask)
                            ) & 0xFF,
                            "semantic_due": (
                                int(prev_store_masks.get("semantic_due", 0))
                                | int(semantic_due_mask)
                            ) & 0xFF,
                            "semantic_unknown": (
                                int(prev_store_masks.get("semantic_unknown", 0))
                                | int(semantic_unknown_mask)
                            ) & 0xFF,
                        }
                continue
            if site_kind != "smem_lds":
                continue
            sm_id = rec.get("sm_id")
            cta_id = rec.get("cta_id")
            if sm_id is None or cta_id is None:
                continue
            key = (
                int(sm_id),
                int(cta_id),
                int(rec.get("addr", 0)),
                int(rec.get("cycle", -1)),
            )
            (
                due_mask,
                sdc_mask,
                unknown_mask,
                trace_policy_used_mask,
                trace_policy_override_mask,
            ) = resolve_smem_site_masks(rec)
            trace_mask_this_site = parse_mask(rec.get("trace_expanding_mask_this_site", 0)) & 0xFF
            (
                due_mask,
                sdc_mask,
                unknown_mask,
                trace_div_mask_this_site,
            ) = _apply_trace_divergence_policy_to_masks(
                due_mask=int(due_mask),
                sdc_mask=int(sdc_mask),
                unknown_mask=int(unknown_mask),
                trace_mask=int(trace_mask_this_site),
                width_bits=8,
                policy=trace_divergence_policy,
            )
            due_mask &= ~unknown_mask
            sdc_mask &= ~unknown_mask
            sdc_mask &= ~due_mask
            semantic_due_mask = parse_mask(rec.get("semantic_due_mask_this_site", 0)) & 0xFF
            semantic_sdc_mask = parse_mask(rec.get("semantic_sdc_mask_this_site", 0)) & 0xFF
            semantic_sdc_mask &= (~semantic_due_mask) & 0xFF
            semantic_sdc_mask &= (~int(unknown_mask)) & 0xFF
            if _trace_divergence_target_class(trace_divergence_policy) == "sdc":
                semantic_sdc_mask |= int(trace_div_mask_this_site) & 0xFF
                semantic_sdc_mask &= (~semantic_due_mask) & 0xFF
                semantic_sdc_mask &= (~int(unknown_mask)) & 0xFF

            event_index = int(rec.get("event_index", -1))
            raw_ev_for_addr = event_by_index.get(event_index, {})
            if raw_ev_for_addr:
                effective_mask = _event_effective_address_mask_from_raw(raw_ev_for_addr)
            else:
                effective_mask = _event_effective_address_mask_from_raw(
                    {"mem_space": rec.get("mem_space", "shared")}
                )
            (
                selected_addr_bits_mask,
                addr_bits_count,
                addr_effective_bits,
            ) = _resolve_selected_addr_bits(
                effective_mask=int(effective_mask),
                addr_bits_mode=addr_bits_mode,
                addr_bits_explicit=addr_bits_explicit,
            )
            if int(addr_effective_bits) > 0:
                addr_effective_bits_seen.add(int(addr_effective_bits))
            addr_bits_count_seen.add(int(addr_bits_count))
            (
                addr_due_mask,
                addr_sdc_mask,
                addr_unknown_mask,
                _addr_masked_mask,
                addr_source_bits,
                addr_trace_div_mask,
            ) = _classify_addr_masks_with_ranges(
                addr=int(rec.get("addr", 0)),
                selected_mask=int(selected_addr_bits_mask),
                effective_mask=int(effective_mask),
                mem_space=str(
                    canonical_space(rec.get("mem_space", "shared")) or "shared"
                ),
                access_size=max(1, int(rec.get("width_bits", 8)) // 8),
                event_index=(
                    int(event_index) if int(event_index) >= 0 else None
                ),
                cycle=int(rec.get("cycle", -1)) if int(rec.get("cycle", -1)) >= 0 else None,
                thread_id=(
                    int(rec.get("thread_id", -1))
                    if int(rec.get("thread_id", -1)) >= 0
                    else None
                ),
                cta_id=(
                    int(rec.get("cta_id", -1)) if int(rec.get("cta_id", -1)) >= 0 else None
                ),
                sm_id=(
                    int(rec.get("sm_id", -1)) if int(rec.get("sm_id", -1)) >= 0 else None
                ),
                addr_ranges=addr_ranges,
                addr_fault_policy=addr_fault_policy,
                addr_due_mode=addr_due_mode,
                trace_mask=int(trace_mask_this_site),
                trace_divergence_policy=trace_divergence_policy,
                live_addr_set=shared_live_target_addr_sets.get(
                    (
                        int(rec.get("sm_id", -1)),
                        int(rec.get("cta_id", -1)),
                    )
                ),
                oob_exception_policy=str(smem_addr_exception_policy),
                source_prefix="smem_addr",
            )
            addr_oob_due_mask = (
                int(addr_due_mask)
                if int(addr_source_bits.get("smem_addr_oob_due", 0)) > 0
                else 0
            ) & MASK64
            addr_alias_sdc_mask = (
                int(addr_sdc_mask)
                if int(addr_source_bits.get("smem_addr_alias_sdc", 0)) > 0
                else 0
            ) & MASK64

            prev = load_masks_by_scope_addr_cycle.get(key)
            if prev is None:
                load_masks_by_scope_addr_cycle[key] = {
                    "due": int(due_mask) & 0xFF,
                    "sdc": int(sdc_mask) & 0xFF,
                    "unknown": int(unknown_mask) & 0xFF,
                    "semantic_sdc": int(semantic_sdc_mask) & 0xFF,
                    "semantic_due": int(semantic_due_mask) & 0xFF,
                    "trace_policy_used": int(trace_policy_used_mask) & 0xFF,
                    "trace_policy_override": int(trace_policy_override_mask) & 0xFF,
                    "trace_div": int(trace_div_mask_this_site) & 0xFF,
                    "addr_selected_mask": int(selected_addr_bits_mask) & MASK64,
                    "addr_due": int(addr_due_mask) & MASK64,
                    "addr_sdc": int(addr_sdc_mask) & MASK64,
                    "addr_unknown": int(addr_unknown_mask) & MASK64,
                    "addr_trace_div": int(addr_trace_div_mask) & MASK64,
                    "addr_oob_due": int(addr_oob_due_mask) & MASK64,
                    "addr_alias_sdc": int(addr_alias_sdc_mask) & MASK64,
                }
            else:
                load_masks_by_scope_addr_cycle[key] = {
                    "due": (int(prev.get("due", 0)) | int(due_mask)) & 0xFF,
                    "sdc": (int(prev.get("sdc", 0)) | int(sdc_mask)) & 0xFF,
                    "unknown": (int(prev.get("unknown", 0)) | int(unknown_mask)) & 0xFF,
                    "semantic_sdc": (
                        int(prev.get("semantic_sdc", 0)) | int(semantic_sdc_mask)
                    ) & 0xFF,
                    "semantic_due": (
                        int(prev.get("semantic_due", 0)) | int(semantic_due_mask)
                    ) & 0xFF,
                    "trace_policy_used": (
                        int(prev.get("trace_policy_used", 0)) | int(trace_policy_used_mask)
                    ) & 0xFF,
                    "trace_policy_override": (
                        int(prev.get("trace_policy_override", 0))
                        | int(trace_policy_override_mask)
                    ) & 0xFF,
                    "trace_div": (
                        int(prev.get("trace_div", 0)) | int(trace_div_mask_this_site)
                    ) & 0xFF,
                    "addr_selected_mask": (
                        int(prev.get("addr_selected_mask", 0))
                        | int(selected_addr_bits_mask)
                    ) & MASK64,
                    "addr_due": (int(prev.get("addr_due", 0)) | int(addr_due_mask)) & MASK64,
                    "addr_sdc": (int(prev.get("addr_sdc", 0)) | int(addr_sdc_mask)) & MASK64,
                    "addr_unknown": (
                        int(prev.get("addr_unknown", 0)) | int(addr_unknown_mask)
                    ) & MASK64,
                    "addr_trace_div": (
                        int(prev.get("addr_trace_div", 0)) | int(addr_trace_div_mask)
                    ) & MASK64,
                    "addr_oob_due": (
                        int(prev.get("addr_oob_due", 0)) | int(addr_oob_due_mask)
                    ) & MASK64,
                    "addr_alias_sdc": (
                        int(prev.get("addr_alias_sdc", 0)) | int(addr_alias_sdc_mask)
                    ) & MASK64,
                }

        # GPGPU-Sim shared memory is backed by memory_space_impl<16*1024>.
        # A storage bit flip mutates a block only after the simulator has
        # materialized that memory_data entry through a write; injections before
        # materialization cannot affect the absent zero-filled block.
        shared_block_materialized_cycle: Dict[Tuple[int, int, int], int] = {}
        for (wr_sm_id, wr_cta_id, wr_addr), wr_cycles in shared_write_cycles.items():
            if not wr_cycles:
                continue
            block_key = (
                int(wr_sm_id),
                int(wr_cta_id),
                int(wr_addr) // int(SMEM_MEMORY_BLOCK_BYTES),
            )
            first_cycle = int(min(int(c) for c in wr_cycles))
            prev_cycle = shared_block_materialized_cycle.get(block_key)
            if prev_cycle is None or first_cycle < int(prev_cycle):
                shared_block_materialized_cycle[block_key] = int(first_cycle)

        all_scope_addr_keys: Set[Tuple[int, int, int]] = set(shared_write_cycles.keys())
        all_scope_addr_keys.update(shared_read_cycles.keys())
        for sm_id, cta_id, addr, _cycle in load_masks_by_scope_addr_cycle.keys():
            all_scope_addr_keys.add((int(sm_id), int(cta_id), int(addr)))

        smem_unmaterialized_addr_keys = 0
        smem_materialized_addr_keys = 0
        smem_page_materialization_gated = True
        min_cycle = -10**30
        max_cycle = 10**30
        for key in sorted(all_scope_addr_keys):
            sm_id, cta_id, addr = int(key[0]), int(key[1]), int(key[2])
            scope = (sm_id, cta_id)
            if scope not in scope_prefix:
                continue
            data_selected_bits_mask = _selected_bit_mask_for_smem_addr(
                addr=addr,
                selected_bits_mask=selected_bits_mask,
                domain_full_bytes=smem_domain_full_bytes,
                domain_tail_bits=smem_domain_tail_bits,
            )
            if data_selected_bits_mask == 0:
                continue
            data_selected_bits_count = int(popcount_u64(int(data_selected_bits_mask)))

            cycles_sorted, prefix, scope_mass_total = scope_prefix[scope]
            if int(scope_mass_total) <= 0:
                continue

            read_cycles = sorted(
                set(int(x) for x in shared_read_cycles.get((sm_id, cta_id, addr), []))
            )
            write_cycles = sorted(
                set(int(x) for x in shared_write_cycles.get((sm_id, cta_id, addr), []))
            )
            if not read_cycles and not write_cycles:
                continue

            block_key = (
                int(sm_id),
                int(cta_id),
                int(addr) // int(SMEM_MEMORY_BLOCK_BYTES),
            )
            materialized_cycle = shared_block_materialized_cycle.get(block_key)
            if materialized_cycle is None:
                smem_unmaterialized_addr_keys += 1
                continue
            smem_materialized_addr_keys += 1
            materialized_lo = int(materialized_cycle)

            if write_cycles:
                segment_specs = []
                first_write = int(write_cycles[0])
                if any(int(read_cycle) < first_write for read_cycle in read_cycles):
                    segment_specs.append(
                        (
                            int(materialized_lo),
                            int(materialized_lo),
                            int(materialized_lo),
                            int(first_write),
                            None,
                        )
                    )
                segment_specs.extend(
                    (
                        int(write_cycle),
                        max(int(write_cycle), int(materialized_lo)),
                        max(int(write_cycle), int(materialized_lo)),
                        int(write_cycles[idx + 1]) if idx + 1 < len(write_cycles) else int(max_cycle),
                        store_semantic_by_scope_addr_cycle.get((sm_id, cta_id, addr, int(write_cycle))),
                    )
                    for idx, write_cycle in enumerate(write_cycles)
                )
            else:
                segment_specs = [
                    (
                        int(materialized_lo),
                        int(materialized_lo),
                        int(materialized_lo),
                        int(max_cycle),
                        None,
                    )
                ]

            segment_count = len(segment_specs)
            for seg_idx, (
                _producer_cycle,
                segment_interval_lo,
                segment_read_lo,
                seg_hi,
                segment_store_semantic,
            ) in enumerate(segment_specs):
                if int(seg_hi) <= int(segment_interval_lo):
                    continue

                read_lo = bisect.bisect_left(read_cycles, int(segment_read_lo))
                if int(seg_hi) >= int(max_cycle):
                    read_hi = len(read_cycles)
                else:
                    read_hi = bisect.bisect_right(read_cycles, int(seg_hi))
                seg_reads = read_cycles[read_lo:read_hi]

                if seg_reads:
                    n = len(seg_reads)
                    suffix_due = [0] * (n + 1)
                    suffix_sdc = [0] * (n + 1)
                    suffix_unknown = [0] * (n + 1)
                    suffix_semantic_sdc = [0] * (n + 1)
                    suffix_semantic_due = [0] * (n + 1)
                    suffix_trace_policy_used = [0] * (n + 1)
                    suffix_trace_policy_override = [0] * (n + 1)
                    suffix_trace_div = [0] * (n + 1)
                    suffix_addr_due = [0] * (n + 1)
                    suffix_addr_sdc = [0] * (n + 1)
                    suffix_addr_unknown = [0] * (n + 1)
                    suffix_addr_oob_due = [0] * (n + 1)
                    suffix_addr_alias_sdc = [0] * (n + 1)
                    suffix_addr_trace_div = [0] * (n + 1)
                    suffix_addr_selected = [0] * (n + 1)
                    for idx in range(n - 1, -1, -1):
                        rc = int(seg_reads[idx])
                        load_row = load_masks_by_scope_addr_cycle.get(
                            (sm_id, cta_id, addr, rc),
                            {},
                        )

                        load_due_mask = int(load_row.get("due", 0)) & 0xFF
                        load_sdc_mask = int(load_row.get("sdc", 0)) & 0xFF
                        load_unknown_mask = int(load_row.get("unknown", 0)) & 0xFF
                        load_semantic_sdc_mask = int(load_row.get("semantic_sdc", 0)) & 0xFF
                        load_semantic_due_mask = int(load_row.get("semantic_due", 0)) & 0xFF
                        event_due_mask = int(load_due_mask) & 0xFF
                        event_unknown_mask = int(load_unknown_mask) & 0xFF
                        event_semantic_due_mask = int(load_semantic_due_mask) & 0xFF
                        event_semantic_sdc_mask = int(load_semantic_sdc_mask) & 0xFF
                        # A load-side SDC mask is proof-derived by the same byte-level
                        # def-use chain used to build the shared-memory live byte set.
                        # Keep non-semantic byte-def/use SDC evidence instead of
                        # downgrading it to Unknown; unproven path/address cases remain
                        # in event_unknown_mask.
                        event_sdc_mask = int(load_sdc_mask) & 0xFF

                        # Paper-aligned priority: DUE > SDC > Unknown > Masked.
                        event_sdc_mask &= (~event_due_mask) & 0xFF
                        event_semantic_sdc_mask &= int(event_sdc_mask) & 0xFF
                        event_unknown_mask &= (~event_due_mask) & 0xFF
                        event_unknown_mask &= (~event_sdc_mask) & 0xFF
                        event_semantic_due_mask &= int(event_due_mask) & 0xFF

                        trace_policy_used_mask = (
                            int(load_row.get("trace_policy_used", 0)) & 0xFF
                        )
                        trace_policy_override_mask = int(
                            load_row.get("trace_policy_override", 0)
                        ) & 0xFF
                        trace_div_mask = int(load_row.get("trace_div", 0)) & 0xFF
                        addr_selected_mask = (
                            int(load_row.get("addr_selected_mask", 0)) & MASK64
                        )
                        addr_due_mask = int(load_row.get("addr_due", 0)) & MASK64
                        addr_sdc_mask = int(load_row.get("addr_sdc", 0)) & MASK64
                        addr_unknown_mask = (
                            int(load_row.get("addr_unknown", 0)) & MASK64
                        )
                        addr_oob_due_mask = (
                            int(load_row.get("addr_oob_due", 0)) & MASK64
                        )
                        addr_alias_sdc_mask = (
                            int(load_row.get("addr_alias_sdc", 0)) & MASK64
                        )
                        addr_trace_div_mask = (
                            int(load_row.get("addr_trace_div", 0)) & MASK64
                        )

                        suffix_due[idx] = int(suffix_due[idx + 1]) | int(event_due_mask)
                        suffix_sdc[idx] = int(suffix_sdc[idx + 1]) | int(event_sdc_mask)
                        suffix_unknown[idx] = (
                            int(suffix_unknown[idx + 1]) | int(event_unknown_mask)
                        )
                        suffix_semantic_sdc[idx] = (
                            int(suffix_semantic_sdc[idx + 1]) | int(event_semantic_sdc_mask)
                        ) & 0xFF
                        suffix_semantic_due[idx] = (
                            int(suffix_semantic_due[idx + 1]) | int(event_semantic_due_mask)
                        ) & 0xFF
                        suffix_trace_policy_used[idx] = (
                            int(suffix_trace_policy_used[idx + 1])
                            | int(trace_policy_used_mask)
                        ) & 0xFF
                        suffix_trace_policy_override[idx] = (
                            int(suffix_trace_policy_override[idx + 1])
                            | int(trace_policy_override_mask)
                        ) & 0xFF
                        suffix_trace_div[idx] = (
                            int(suffix_trace_div[idx + 1]) | int(trace_div_mask)
                        ) & 0xFF
                        suffix_addr_due[idx] = (
                            int(suffix_addr_due[idx + 1]) | int(addr_due_mask)
                        ) & MASK64
                        suffix_addr_sdc[idx] = (
                            int(suffix_addr_sdc[idx + 1]) | int(addr_sdc_mask)
                        ) & MASK64
                        suffix_addr_unknown[idx] = (
                            int(suffix_addr_unknown[idx + 1]) | int(addr_unknown_mask)
                        ) & MASK64
                        suffix_addr_oob_due[idx] = (
                            int(suffix_addr_oob_due[idx + 1]) | int(addr_oob_due_mask)
                        ) & MASK64
                        suffix_addr_alias_sdc[idx] = (
                            int(suffix_addr_alias_sdc[idx + 1]) | int(addr_alias_sdc_mask)
                        ) & MASK64
                        suffix_addr_trace_div[idx] = (
                            int(suffix_addr_trace_div[idx + 1]) | int(addr_trace_div_mask)
                        ) & MASK64
                        suffix_addr_selected[idx] = (
                            int(suffix_addr_selected[idx + 1]) | int(addr_selected_mask)
                        ) & MASK64

                    interval_lo = int(segment_interval_lo)
                    for idx, rc in enumerate(seg_reads):
                        boundary_mass_here = range_sum(
                            cycles_sorted, prefix, int(rc), int(rc) + 1
                        )
                        if boundary_mass_here > 0:
                            boundary_events_count += 1
                            boundary_events_mass += float(boundary_mass_here)
                            boundary_bits_mass_total += float(
                                float(boundary_mass_here) * float(data_selected_bits_count)
                            )
                        boundary = int(rc) + 1 if ge_mode else int(rc)
                        interval_hi = min(int(seg_hi), boundary)
                        if interval_hi > interval_lo:
                            mass = range_sum(cycles_sorted, prefix, interval_lo, interval_hi)
                            if mass > 0:
                                due_agg = int(suffix_due[idx]) & 0xFF
                                sdc_agg = int(suffix_sdc[idx]) & 0xFF
                                unknown_agg = int(suffix_unknown[idx]) & 0xFF
                                sdc_agg &= (~due_agg) & 0xFF
                                unknown_agg &= (~due_agg) & 0xFF
                                unknown_agg &= (~sdc_agg) & 0xFF

                                semantic_sdc_agg = int(suffix_semantic_sdc[idx]) & 0xFF
                                semantic_sdc_agg &= int(sdc_agg) & 0xFF
                                semantic_due_agg = int(suffix_semantic_due[idx]) & 0xFF
                                semantic_due_agg &= int(due_agg) & 0xFF
                                effective_sdc_agg = int(sdc_agg) & 0xFF
                                trace_div_agg = int(suffix_trace_div[idx]) & 0xFF
                                trace_due_agg = (
                                    trace_div_agg
                                    if _trace_divergence_target_class(
                                        trace_divergence_policy
                                    )
                                    == "due"
                                    else 0
                                )
                                base_due_agg = int(due_agg) & (
                                    (~int(semantic_due_agg)) & 0xFF
                                )
                                base_due_agg &= (~int(trace_due_agg)) & 0xFF
                                due_bits = popcount_u64(
                                    int(due_agg) & int(data_selected_bits_mask)
                                )
                                unknown_bits = popcount_u64(
                                    int(unknown_agg) & int(data_selected_bits_mask)
                                )
                                sdc_bits = popcount_u64(
                                    int(sdc_agg) & int(data_selected_bits_mask)
                                )
                                semantic_sdc_bits = popcount_u64(
                                    int(semantic_sdc_agg) & int(data_selected_bits_mask)
                                )
                                byte_defuse_sdc_bits = popcount_u64(
                                    (int(sdc_agg) & ((~int(semantic_sdc_agg)) & 0xFF))
                                    & int(data_selected_bits_mask)
                                )
                                semantic_due_bits = popcount_u64(
                                    int(semantic_due_agg) & int(data_selected_bits_mask)
                                )
                                base_due_bits = popcount_u64(
                                    int(base_due_agg) & int(data_selected_bits_mask)
                                )
                                trace_policy_used_agg = (
                                    int(suffix_trace_policy_used[idx]) & 0xFF
                                )
                                trace_policy_used_bits_here = popcount_u64(
                                    int(trace_policy_used_agg)
                                    & int(data_selected_bits_mask)
                                )
                                trace_policy_override_agg = (
                                    int(suffix_trace_policy_override[idx]) & 0xFF
                                )
                                trace_policy_override_bits_here = popcount_u64(
                                    int(trace_policy_override_agg)
                                    & int(data_selected_bits_mask)
                                )
                                trace_policy_override_sdc_bits_here = popcount_u64(
                                    (int(trace_policy_override_agg) & int(effective_sdc_agg))
                                    & int(data_selected_bits_mask)
                                )
                                trace_policy_override_due_bits_here = popcount_u64(
                                    (int(trace_policy_override_agg) & int(due_agg))
                                    & int(data_selected_bits_mask)
                                )
                                trace_policy_override_unknown_bits_here = popcount_u64(
                                    (int(trace_policy_override_agg) & int(unknown_agg))
                                    & int(data_selected_bits_mask)
                                )
                                trace_policy_override_masked_bits_here = max(
                                    0,
                                    int(trace_policy_override_bits_here)
                                    - int(trace_policy_override_sdc_bits_here)
                                    - int(trace_policy_override_due_bits_here)
                                    - int(trace_policy_override_unknown_bits_here),
                                )
                                trace_div_bits_here = popcount_u64(
                                    int(trace_div_agg) & int(data_selected_bits_mask)
                                )

                                due_mass_here = float(int(mass) * int(due_bits))
                                unknown_mass_here = float(int(mass) * int(unknown_bits))
                                sdc_mass_here = float(int(mass) * int(sdc_bits))
                                byte_defuse_sdc_mass_here = float(
                                    int(mass) * int(byte_defuse_sdc_bits)
                                )
                                due_data_num += float(due_mass_here)
                                sdc_data_num += float(sdc_mass_here)
                                unknown_data_num += float(unknown_mass_here)
                                due_num += float(due_mass_here)
                                unknown_num += float(unknown_mass_here)
                                sdc_num += float(sdc_mass_here)
                                smem_byte_defuse_sdc_bits += int(byte_defuse_sdc_bits)
                                smem_byte_defuse_sdc_mass += float(byte_defuse_sdc_mass_here)
                                _add_source_mass(
                                    due_source_mass,
                                    "semantic_due",
                                    float(int(mass) * int(semantic_due_bits)),
                                )
                                if trace_div_bits_here > 0:
                                    trace_divergence_bits += int(trace_div_bits_here)
                                    trace_divergence_mass += float(
                                        int(mass) * int(trace_div_bits_here)
                                    )
                                    target_cls = _trace_divergence_target_class(
                                        trace_divergence_policy
                                    )
                                    _add_source_mass(
                                        due_source_mass,
                                        f"trace_divergence_{target_cls}",
                                        float(int(mass) * int(trace_div_bits_here)),
                                    )
                                trace_policy_used_bits += int(trace_policy_used_bits_here)
                                trace_policy_used_mass += float(
                                    int(mass) * int(trace_policy_used_bits_here)
                                )
                                trace_policy_override_bits += int(
                                    trace_policy_override_bits_here
                                )
                                trace_policy_override_mass += float(
                                    int(mass) * int(trace_policy_override_bits_here)
                                )
                                trace_policy_override_sdc_bits += int(
                                    trace_policy_override_sdc_bits_here
                                )
                                trace_policy_override_due_bits += int(
                                    trace_policy_override_due_bits_here
                                )
                                trace_policy_override_unknown_bits += int(
                                    trace_policy_override_unknown_bits_here
                                )
                                trace_policy_override_masked_bits += int(
                                    trace_policy_override_masked_bits_here
                                )
                                if trace_uncovered_mode == "legacy_unknown":
                                    trace_uncovered_unknown_bits += int(
                                        trace_policy_used_bits_here
                                    )
                                    trace_uncovered_unknown_mass += float(
                                        int(mass) * int(trace_policy_used_bits_here)
                                    )

                                if addr_domain_enabled:
                                    addr_selected_agg = (
                                        int(suffix_addr_selected[idx]) & MASK64
                                    )
                                    addr_bits_count = int(
                                        popcount_u64(int(addr_selected_agg))
                                    )
                                    addr_due_agg = int(suffix_addr_due[idx]) & MASK64
                                    addr_sdc_agg = int(suffix_addr_sdc[idx]) & MASK64
                                    addr_unknown_agg = (
                                        int(suffix_addr_unknown[idx]) & MASK64
                                    )
                                    addr_due_agg &= (~addr_unknown_agg) & MASK64
                                    addr_sdc_agg &= (~addr_unknown_agg) & MASK64
                                    addr_sdc_agg &= (~addr_due_agg) & MASK64
                                    addr_due_bits = popcount_u64(
                                        addr_due_agg & addr_selected_agg
                                    )
                                    addr_sdc_bits = popcount_u64(
                                        addr_sdc_agg & addr_selected_agg
                                    )
                                    addr_unknown_bits = popcount_u64(
                                        addr_unknown_agg & addr_selected_agg
                                    )
                                    due_addr_num += float(int(mass) * int(addr_due_bits))
                                    sdc_addr_num += float(int(mass) * int(addr_sdc_bits))
                                    unknown_addr_num += float(
                                        int(mass) * int(addr_unknown_bits)
                                    )

                                    addr_oob_due_agg = (
                                        int(suffix_addr_oob_due[idx]) & MASK64
                                    )
                                    addr_alias_sdc_agg = (
                                        int(suffix_addr_alias_sdc[idx]) & MASK64
                                    )
                                    addr_trace_div_agg = (
                                        int(suffix_addr_trace_div[idx]) & MASK64
                                    )
                                    _add_source_mass(
                                        due_source_mass,
                                        "smem_addr_oob_due",
                                        float(
                                            int(mass)
                                            * popcount_u64(
                                                addr_oob_due_agg & addr_selected_agg
                                            )
                                        ),
                                    )
                                    _add_source_mass(
                                        due_source_mass,
                                        "smem_addr_alias_sdc",
                                        float(
                                            int(mass)
                                            * popcount_u64(
                                                addr_alias_sdc_agg & addr_selected_agg
                                            )
                                        ),
                                    )
                                    addr_trace_div_bits = popcount_u64(
                                        addr_trace_div_agg & addr_selected_agg
                                    )
                                    if addr_trace_div_bits > 0:
                                        trace_divergence_bits += int(addr_trace_div_bits)
                                        trace_divergence_mass += float(
                                            int(mass) * int(addr_trace_div_bits)
                                        )
                                    addr_denominator += int(mass) * int(addr_bits_count)
                        interval_lo = interval_hi

                else:
                    # No traced load consumes this byte before the next overwrite,
                    # so a persistent shared-memory storage fault in this interval
                    # has no output path and remains masked by denominator closure.
                    continue

    if fault_component == "smem_lds":
        denominator = int(data_denominator)
    if denominator <= 0 and data_denominator <= 0:
        raise ValueError("shared-memory denominator is zero")
    if data_denominator <= 0:
        data_denominator = int(denominator)

    if not addr_domain_enabled:
        addr_denominator = 0
        due_addr_num = 0.0
        sdc_addr_num = 0.0
        unknown_addr_num = 0.0
    total_denominator = int(data_denominator) + int(max(0, int(addr_denominator)))
    if total_denominator <= 0:
        raise ValueError("shared-memory total denominator is zero")

    if due_data_num + sdc_data_num + unknown_data_num > float(data_denominator) + 1e-9:
        raise ValueError(
            "Internal accounting mismatch for shared-memory data domain: "
            f"sdc+due+unknown={due_data_num + sdc_data_num + unknown_data_num} "
            f"> data_denominator={data_denominator}"
        )
    masked_data_num = (
        float(data_denominator)
        - float(due_data_num)
        - float(sdc_data_num)
        - float(unknown_data_num)
    )
    if masked_data_num < 0.0 and abs(masked_data_num) <= 1e-9:
        masked_data_num = 0.0
    if masked_data_num < 0.0:
        raise ValueError(
            "Internal accounting mismatch for shared-memory data domain masked mass: "
            f"{masked_data_num}"
        )

    if not addr_domain_enabled:
        masked_addr_num = 0.0
    else:
        if due_addr_num + sdc_addr_num + unknown_addr_num > float(addr_denominator) + 1e-9:
            raise ValueError(
                "Internal accounting mismatch for shared-memory addr domain: "
                f"sdc+due+unknown={due_addr_num + sdc_addr_num + unknown_addr_num} "
                f"> addr_denominator={addr_denominator}"
            )
        masked_addr_num = (
            float(addr_denominator)
            - float(due_addr_num)
            - float(sdc_addr_num)
            - float(unknown_addr_num)
        )
        if masked_addr_num < 0.0 and abs(masked_addr_num) <= 1e-9:
            masked_addr_num = 0.0
        if masked_addr_num < 0.0:
            raise ValueError(
                "Internal accounting mismatch for shared-memory addr masked mass: "
                f"{masked_addr_num}"
            )

    smem_error_propagation_model = str(
        getattr(args, "smem_error_propagation_model", CANONICAL_SMEM_ERROR_PROPAGATION_MODEL)
    )
    smem_sdc_mass_before = max(
        0.0,
        float(sdc_data_num) + float(sdc_addr_num) - float(smem_byte_defuse_sdc_mass),
    )
    smem_due_mass_before = float(due_data_num) + float(due_addr_num)

    due_num = float(due_data_num) + float(due_addr_num)
    sdc_num = float(sdc_data_num) + float(sdc_addr_num)
    unknown_num = float(unknown_data_num) + float(unknown_addr_num)
    masked_num = float(masked_data_num) + float(masked_addr_num)

    rates = {
        "masked": (float(masked_num) / float(total_denominator)),
        "sdc": (float(sdc_num) / float(total_denominator)),
        "due": (float(due_num) / float(total_denominator)),
        "unknown": (float(unknown_num) / float(total_denominator)),
    }
    masked_out = _normalize_numeric(masked_num)
    sdc_out = _normalize_numeric(sdc_num)
    due_out = _normalize_numeric(due_num)
    unknown_out = _normalize_numeric(unknown_num)
    smem_domain_total_bits_final = int(
        max(0, _safe_int(smem_domain_diag.get("smem_domain_total_bits_final", 0), 0))
    )
    if smem_domain_total_bits_final <= 0:
        smem_domain_total_bits_final = int(max(0, int(data_denominator)))
    addr_bits_count_value = int(max(addr_bits_count_seen)) if addr_bits_count_seen else 0
    addr_effective_bits_value = _summarize_effective_bits(addr_effective_bits_seen)
    shared_summary = {
        "masked": masked_out,
        "sdc": sdc_out,
        "due": due_out,
        "unknown": unknown_out,
        "den": int(total_denominator),
        "rate": dict(rates),
        "by_domain": {
            "data": {
                "masked": _normalize_numeric(masked_data_num),
                "sdc": _normalize_numeric(sdc_data_num),
                "due": _normalize_numeric(due_data_num),
                "unknown": _normalize_numeric(unknown_data_num),
                "den": int(data_denominator),
            },
            "addr": {
                "masked": _normalize_numeric(masked_addr_num),
                "sdc": _normalize_numeric(sdc_addr_num),
                "due": _normalize_numeric(due_addr_num),
                "unknown": _normalize_numeric(unknown_addr_num),
                "den": int(addr_denominator),
                "policy": str(addr_fault_policy),
                "addr_due_mode": str(addr_due_mode),
            },
        },
    }
    smem_scope_source = "shared+active_union" if fault_component == "smem_rf" else "none"
    smem_scope_count_hist_topk: List[Dict[str, int]] = []
    smem_scope_count_hist_total_cycles = 0
    smem_scope_count_hist_unique = 0
    if fault_component == "smem_rf" and scope_count_hist:
        smem_scope_count_hist_total_cycles = int(sum(int(v) for v in scope_count_hist.values()))
        smem_scope_count_hist_unique = int(len(scope_count_hist))
        for scope_count, cycle_count in sorted(
            ((int(k), int(v)) for k, v in scope_count_hist.items()),
            key=lambda item: (-int(item[1]), int(item[0])),
        )[:8]:
            smem_scope_count_hist_topk.append(
                {
                    "scope_count": int(scope_count),
                    "cycle_count": int(cycle_count),
                }
            )
    return {
        "classification_counts": {
            "masked": masked_out,
            "sdc": sdc_out,
            "due": due_out,
            "unknown": unknown_out,
            "total": int(total_denominator),
        },
        "classification_rates": rates,
        "weighted_classification_counts": {
            "masked": fraction(masked_num, total_denominator),
            "sdc": fraction(sdc_num, total_denominator),
            "due": fraction(due_num, total_denominator),
            "unknown": fraction(unknown_num, total_denominator),
            "total": fraction(total_denominator, total_denominator),
        },
        "weighted_classification_rates": {
            "masked": fraction(masked_num, total_denominator),
            "sdc": fraction(sdc_num, total_denominator),
            "due": fraction(due_num, total_denominator),
            "unknown": fraction(unknown_num, total_denominator),
        },
        "summary": {
            "shared_memory": {
                "smem_rf": shared_summary if fault_component == "smem_rf" else {
                    "masked": 0,
                    "sdc": 0,
                    "due": 0,
                    "unknown": 0,
                    "den": 0,
                    "rate": {"masked": 0.0, "sdc": 0.0, "due": 0.0, "unknown": 0.0},
                },
                "smem_lds": shared_summary if fault_component == "smem_lds" else {
                    "masked": 0,
                    "sdc": 0,
                    "due": 0,
                    "unknown": 0,
                    "den": 0,
                    "rate": {"masked": 0.0, "sdc": 0.0, "due": 0.0, "unknown": 0.0},
                },
            }
        },
        "exact_meta": {
            "fault_component": str(fault_component),
            "cycles_file": str(args.cycles),
            "active_threads_log": (
                str(args.active_threads_log) if args.active_threads_log is not None else None
            ),
            "trace_template": str(args.trace_template),
            "thread_rand_max": thread_rand_max,
            "thread_rands": thread_rands if thread_rands is not None else "0..thread_rand_max-1",
            "thread_cycle_backend_requested": (
                "force"
                if _CPP_THREAD_CYCLE_FORCE
                else ("auto" if _CPP_THREAD_CYCLE_ENABLED else "disabled")
            ),
            "thread_cycle_backend_used": str(thread_cycle_backend),
            "block_rand_max": int(block_rand_max) if block_rand_max is not None else None,
            "block_rands": block_rands if block_rands is not None else "0..block_rand_max-1",
            "block_seed_domain_size": int(block_seed_domain_size),
            "smem_size_bits": int(smem_size_bits),
            "smem_selected_bit_domain_size": int(smem_selected_bit_domain_size),
            "smem_domain_policy": str(smem_domain_policy),
            "smem_domain_bits_per_seed_final": int(
                smem_domain_diag.get("smem_domain_bits_per_seed_final", smem_size_bits)
            ),
            "smem_domain_total_bits_final": int(smem_domain_total_bits_final),
            "smem_domain_units": str(smem_domain_diag.get("smem_domain_units", "bits")),
            "smem_size_bits_source": str(smem_domain_diag.get("smem_size_bits_source", "")),
            "smem_size_bits_final": int(smem_domain_diag.get("smem_size_bits_final", smem_size_bits)),
            "smem_hw_size_bits": int(smem_domain_diag.get("smem_hw_size_bits", 0)),
            "smem_allocated_bits": int(smem_domain_diag.get("smem_allocated_bits", 0)),
            "smem_touched_bits": int(smem_domain_diag.get("smem_touched_bits", 0)),
            "smem_sampling_space_bits": int(
                smem_domain_diag.get("smem_sampling_space_bits", 0)
            ),
            "smem_sampling_space_total_bits": int(
                smem_domain_diag.get("smem_sampling_space_total_bits", 0)
            ),
            "smem_error_propagation_model": str(smem_error_propagation_model),
            "smem_memory_block_bytes": int(SMEM_MEMORY_BLOCK_BYTES),
            "smem_bit_index_realization": "gpgpusim_64bit_word_update",
            "smem_bit_index_boundary_aliasing": True,
            "smem_page_materialization_gated": bool(
                smem_page_materialization_gated
                if fault_component == "smem_rf"
                else False
            ),
            "smem_materialized_block_count": int(
                len(shared_block_materialized_cycle) if fault_component == "smem_rf" else 0
            ),
            "smem_materialized_addr_keys": int(
                smem_materialized_addr_keys if fault_component == "smem_rf" else 0
            ),
            "smem_unmaterialized_addr_keys": int(
                smem_unmaterialized_addr_keys if fault_component == "smem_rf" else 0
            ),
            "smem_byte_defuse_sdc_bits": int(smem_byte_defuse_sdc_bits),
            "smem_byte_defuse_sdc_mass": _normalize_numeric(
                smem_byte_defuse_sdc_mass
            ),
            "smem_sdc_mass_before_propagation": _normalize_numeric(
                smem_sdc_mass_before
            ),
            "smem_due_mass_before_propagation": _normalize_numeric(
                smem_due_mass_before
            ),
            "bit_count": int(bit_count),
            "datatype_bits": int(datatype_bits),
            "consumer_compare": str(args.consumer_compare),
            "smem_group_mode": str(storage_group_mode),
            "smem_site_mask_signature_requests": int(
                smem_site_mask_signature_requests
            ),
            "smem_site_mask_signature_hits": int(smem_site_mask_signature_hits),
            "smem_site_mask_signature_entries": int(
                len(smem_site_mask_signature_cache)
            ),
            "trace_expanding_policy": str(trace_expanding_policy),
            "trace_expanding_resolution_mode": str(trace_expanding_resolution_mode),
            "trace_uncovered_mode": str(trace_uncovered_mode),
            "trace_divergence_policy": str(trace_divergence_policy),
            "addr_fault_policy": str(addr_fault_policy),
            "addr_due_mode": str(addr_due_mode),
            "addr_bits_mode": str(addr_bits_mode),
            "addr_bits_count": int(addr_bits_count_value),
            "addr_effective_bits": addr_effective_bits_value,
            "addr_effective_bits_max": (
                int(max(addr_effective_bits_seen)) if addr_effective_bits_seen else 0
            ),
            "smem_addr_exception_policy": str(smem_addr_exception_policy),
            "trace_policy_used_bits": int(trace_policy_used_bits),
            "trace_policy_used_mass": _normalize_numeric(trace_policy_used_mass),
            "trace_policy_override_bits": int(trace_policy_override_bits),
            "trace_policy_override_mass": _normalize_numeric(trace_policy_override_mass),
            "trace_policy_override_reason_breakdown": {
                "sdc": int(trace_policy_override_sdc_bits),
                "due": int(trace_policy_override_due_bits),
                "unknown": int(trace_policy_override_unknown_bits),
                "masked": int(trace_policy_override_masked_bits),
            },
            "trace_uncovered_unknown_bits": int(trace_uncovered_unknown_bits),
            "trace_uncovered_unknown_mass": _normalize_numeric(trace_uncovered_unknown_mass),
            "unknown_bits": int(round(float(unknown_num))),
            "unknown_mass": int(round(float(unknown_num))),
            "trace_divergence_bits": int(trace_divergence_bits),
            "trace_divergence_mass": _normalize_numeric(trace_divergence_mass),
            "total_bits": int(total_denominator),
            "data_bits": int(data_denominator),
            "addr_domain_bits": int(addr_denominator),
            "tag_bits": 0,
            "masked_bits_data": _normalize_numeric(masked_data_num),
            "sdc_bits_data": _normalize_numeric(sdc_data_num),
            "due_bits_data": _normalize_numeric(due_data_num),
            "unknown_bits_data": _normalize_numeric(unknown_data_num),
            "addr_masked_bits": _normalize_numeric(masked_addr_num),
            "addr_sdc_bits": _normalize_numeric(sdc_addr_num),
            "addr_due_bits": _normalize_numeric(due_addr_num),
            "addr_unknown_bits": _normalize_numeric(unknown_addr_num),
            "smem_addr_domain_bits": int(addr_denominator),
            "smem_addr_masked_bits": _normalize_numeric(masked_addr_num),
            "smem_addr_sdc_bits": _normalize_numeric(sdc_addr_num),
            "smem_addr_due_bits": _normalize_numeric(due_addr_num),
            "smem_addr_unknown_bits": _normalize_numeric(unknown_addr_num),
            "masked_bits_tag": 0,
            "sdc_bits_tag": 0,
            "due_bits_tag": 0,
            "unknown_bits_tag": 0,
            "due_source_bits": _mass_map_to_bits_map(due_source_mass),
            "due_mass_by_source": _normalize_mass_map(due_source_mass),
            **_boundary_meta_fields(
                consumer_compare=str(args.consumer_compare),
                same_cycle_effect_prob=same_cycle_effect_prob,
                boundary_events_count=int(boundary_events_count),
                boundary_events_mass=float(boundary_events_mass),
                boundary_bits_mass_total=float(boundary_bits_mass_total),
            ),
            "missing_active_thread_cycles": int(
                cycle_records_meta.get("missing_active_thread_cycles", 0)
            ),
            "missing_active_thread_cycle_ratio": float(
                cycle_records_meta.get("missing_active_thread_cycle_ratio", 0.0)
            ),
            "active_threads_carried_forward_cycles": int(
                cycle_records_meta.get("active_threads_carried_forward_cycles", 0)
            ),
            "active_threads_empty_fill_cycles": int(
                cycle_records_meta.get("active_threads_empty_fill_cycles", 0)
            ),
            "missing_active_threads_policy": str(
                cycle_records_meta.get("missing_active_threads_policy", "empty")
            ),
            "addr_valid_ranges_path": (
                str(args.addr_valid_ranges_path)
                if getattr(args, "addr_valid_ranges_path", None) is not None
                else None
            ),
            "addr_valid_range_count": int(len(addr_ranges)),
            "smem_addr_range_source": str(smem_addr_ranges_source),
            "seed_domain_size": int(seed_domain_size),
            "inactive_base_mass": int(inactive_base_mass),
            "active_base_mass": int(active_base_mass),
            "semantic_error_reason_counts": dict(
                analyzer_exact_meta.get("semantic_error_reason_counts", {})
            ),
            "semantic_error_reasons_top20": list(
                analyzer_exact_meta.get("semantic_error_reasons_top20", [])
            ),
            "semantic_error_samples": list(
                analyzer_exact_meta.get("semantic_error_samples", [])
            ),
            "semantic_infra_error_count": int(
                analyzer_exact_meta.get("semantic_infra_error_count", 0)
            ),
            "semantic_infra_error_reason_counts": dict(
                analyzer_exact_meta.get("semantic_infra_error_reason_counts", {})
            ),
            "semantic_infra_error_reasons_top20": list(
                analyzer_exact_meta.get("semantic_infra_error_reasons_top20", [])
            ),
            "semantic_unknown_count": int(
                analyzer_exact_meta.get("semantic_unknown_count", 0)
            ),
            "semantic_unknown_reason_counts": dict(
                analyzer_exact_meta.get("semantic_unknown_reason_counts", {})
            ),
            "semantic_unknown_reasons_top20": list(
                analyzer_exact_meta.get("semantic_unknown_reasons_top20", [])
            ),
            "semantic_unknown_reason_details_top20": list(
                analyzer_exact_meta.get("semantic_unknown_reason_details_top20", [])
            ),
            "semantic_unknown_samples": list(
                analyzer_exact_meta.get("semantic_unknown_samples", [])
            ),
            "auto_range_created_count": int(
                analyzer_exact_meta.get("auto_range_created_count", 0)
            ),
            "auto_range_reason_counts": dict(
                analyzer_exact_meta.get("auto_range_reason_counts", {})
            ),
            "auto_range_samples_top20": list(
                analyzer_exact_meta.get("auto_range_samples_top20", [])
            ),
            "trace_load_init_event_count": int(
                analyzer_exact_meta.get("trace_load_init_event_count", 0)
            ),
            "trace_load_init_byte_count": int(
                analyzer_exact_meta.get("trace_load_init_byte_count", 0)
            ),
            "trace_load_init_samples_top20": list(
                analyzer_exact_meta.get("trace_load_init_samples_top20", [])
            ),
            "trace_bit_no_semantic_coverage_records": int(
                analyzer_exact_meta.get("trace_bit_no_semantic_coverage_records", 0)
            ),
            "trace_bit_no_semantic_coverage_bits": int(
                analyzer_exact_meta.get("trace_bit_no_semantic_coverage_bits", 0)
            ),
            "trace_bit_no_semantic_coverage_samples": list(
                analyzer_exact_meta.get("trace_bit_no_semantic_coverage_samples", [])
            ),
            "due_oracle_reason_counts": dict(
                analyzer_exact_meta.get("due_oracle_reason_counts", {})
            ),
            "due_oracle_reason_details_top20": list(
                analyzer_exact_meta.get("due_oracle_reason_details_top20", [])
            ),
            "output_oracle_type": str(
                analyzer_exact_meta.get("output_oracle_type", "")
            ),
            "output_oracle_has_output_spec": bool(
                analyzer_exact_meta.get("output_oracle_has_output_spec", False)
            ),
            "output_oracle_spec_entry_count": int(
                analyzer_exact_meta.get("output_oracle_spec_entry_count", 0)
            ),
            "output_oracle_spec_total_bytes": int(
                analyzer_exact_meta.get("output_oracle_spec_total_bytes", 0)
            ),
            "output_oracle_spec_ranges": list(
                analyzer_exact_meta.get("output_oracle_spec_ranges", [])
            ),
            "output_last_writer_store_count": int(
                analyzer_exact_meta.get("output_last_writer_store_count", 0)
            ),
            "output_total_store_count": int(
                analyzer_exact_meta.get("output_total_store_count", 0)
            ),
            "filtered_store_ratio": float(
                analyzer_exact_meta.get("filtered_store_ratio", 0.0)
            ),
            "addr_observed_seed_suppressed_bits": int(
                analyzer_exact_meta.get("addr_observed_seed_suppressed_bits", 0)
            ),
            "addr_observed_seed_suppressed_events": int(
                analyzer_exact_meta.get("addr_observed_seed_suppressed_events", 0)
            ),
            "tol_output_store_seed_count": int(
                analyzer_exact_meta.get("tol_output_store_seed_count", 0)
            ),
            "tol_float_backward_op_count": int(
                analyzer_exact_meta.get("tol_float_backward_op_count", 0)
            ),
            "tol_memory_forward_byte_count": int(
                analyzer_exact_meta.get("tol_memory_forward_byte_count", 0)
            ),
            "tol_fallback_count": int(
                analyzer_exact_meta.get("tol_fallback_count", 0)
            ),
            "shared_scope_count": int(len(scope_cycle_weights)),
            "smem_scope_source": str(smem_scope_source),
            "smem_scope_count_hist_topk": list(smem_scope_count_hist_topk),
            "smem_scope_count_hist_total_cycles": int(smem_scope_count_hist_total_cycles),
            "smem_scope_count_hist_unique": int(smem_scope_count_hist_unique),
            "smem_fault_site_count": int(len(smem_sites)),
            "smem_rf_site_count": int(
                sum(1 for rec in smem_sites if str(rec.get("site_kind", "")) == "smem_rf")
            ),
            "smem_lds_site_count": int(
                sum(1 for rec in smem_sites if str(rec.get("site_kind", "")) == "smem_lds")
            ),
        },
    }


def compute_exact_l1d(args: argparse.Namespace) -> Dict[str, Any]:
    normalize_trace_coverage = bool(getattr(args, "normalize_trace_coverage", False))
    storage_group_mode = _normalize_storage_group_mode(
        getattr(args, "storage_group_mode", "legacy")
    )
    use_grouped_segment_cache = storage_group_mode == "grouped"
    analyzer = _load_analyzer_output_for_compute(
        args.analyzer_output,
        normalize_trace_coverage=normalize_trace_coverage,
    )
    analyzer_exact_meta_raw = analyzer.get("exact_meta", {})
    analyzer_exact_meta = (
        analyzer_exact_meta_raw if isinstance(analyzer_exact_meta_raw, dict) else {}
    )

    if args.trace_template is None:
        raise ValueError("--trace-template is required for fault-component l1d")
    trace_template = parse_trace_template(args.trace_template)
    shared_cache_trace_views = _load_shared_cache_trace_views_for_args(args)
    event_by_index = shared_cache_trace_views.event_by_index
    l1d_sites = _load_filtered_cache_fault_sites_for_compute(
        "l1d",
        Path(args.analyzer_output),
        Path(args.trace_template),
        normalize_trace_coverage=normalize_trace_coverage,
    )

    cycle_records, cycle_records_meta = load_cycle_records_with_meta(
        args.cycles,
        args.active_threads_log,
        bool(getattr(args, "allow_missing_active_threads", False)),
        str(getattr(args, "missing_active_threads_policy", "empty")),
    )
    cycles_sorted, cycle_prefix, total_cycle_lines = _cycle_prefix_from_records(cycle_records)
    if total_cycle_lines <= 0:
        raise ValueError("cycle multiplicity total is zero")

    trace_expanding_policy = str(args.trace_expanding_policy).strip().lower()
    if trace_expanding_policy != CANONICAL_TRACE_EXPANDING_POLICY:
        raise ValueError(
            "trace_expanding_policy must be one of {}; got {!r}".format(
                CANONICAL_TRACE_EXPANDING_POLICY,
                trace_expanding_policy,
            )
        )
    trace_uncovered_mode = _normalize_trace_uncovered_mode(
        getattr(args, "trace_uncovered_mode", "legacy_unknown")
    )
    trace_expanding_resolution_mode = str(
        getattr(args, "trace_expanding_resolution_mode", "legacy")
    ).strip().lower()
    if trace_expanding_resolution_mode != CANONICAL_TRACE_EXPANDING_RESOLUTION_MODE:
        raise ValueError(
            "trace_expanding_resolution_mode must be one of {}; got {!r}".format(
                CANONICAL_TRACE_EXPANDING_RESOLUTION_MODE,
                trace_expanding_resolution_mode,
            )
        )
    l1d_site_masks_many = _load_cache_site_masks_for_compute(
        "l1d",
        Path(args.analyzer_output),
        Path(args.trace_template),
        normalize_trace_coverage=normalize_trace_coverage,
        trace_expanding_policy=trace_expanding_policy,
        trace_uncovered_mode=trace_uncovered_mode,
        trace_expanding_resolution_mode=trace_expanding_resolution_mode,
    )
    cache_tag_class_policy = _normalize_cache_tag_class_policy(
        getattr(args, "cache_tag_class_policy", CANONICAL_CACHE_TAG_CLASS_POLICY)
    )
    addr_fault_policy = _normalize_addr_fault_policy(
        getattr(args, "addr_fault_policy", CANONICAL_ADDR_FAULT_POLICY)
    )
    trace_divergence_policy = _normalize_trace_divergence_policy(
        getattr(args, "trace_divergence_policy", CANONICAL_TRACE_DIVERGENCE_POLICY)
    )
    addr_due_mode = _normalize_addr_due_mode(getattr(args, "addr_due_mode", CANONICAL_ADDR_DUE_MODE))
    cache_addr_domain_enabled = _cache_addr_domain_runtime_enabled(args)
    addr_domain_enabled = bool(cache_addr_domain_enabled)
    addr_bits_mode, addr_bits_explicit = _parse_addr_bits_spec(
        getattr(args, "addr_bits", "auto")
    )
    ge_mode = str(args.consumer_compare).strip().lower() == "ge"
    same_cycle_effect_prob = _normalize_same_cycle_effect_prob(
        getattr(args, "same_cycle_effect_prob", None)
    )
    if cache_addr_domain_enabled:
        addr_ranges = _load_addr_valid_ranges(
            trace_memory_ranges=list(trace_template.get("memory_ranges", [])),
            external_path=getattr(args, "addr_valid_ranges_path", None),
        )
    else:
        addr_ranges = []

    l1d_size_bits = int(args.l1d_size_bits)
    if l1d_size_bits <= 0:
        raise ValueError(
            "l1d requires positive --l1d-size-bits (use campaign/config derived L1D_SIZE_BITS)"
        )
    l1d_line_size_bytes = int(args.l1d_line_size_bytes)
    if l1d_line_size_bytes <= 0:
        raise ValueError("--l1d-line-size-bytes must be > 0")
    l1d_tag_bits = int(args.l1d_tag_bits)
    if l1d_tag_bits < 0:
        raise ValueError("--l1d-tag-bits must be >= 0")
    l1d_include_tag_bits = int(args.l1d_include_tag_bits)
    if l1d_include_tag_bits not in (0, 1):
        raise ValueError("--l1d-include-tag-bits must be 0 or 1")
    include_tag_bits = bool(l1d_include_tag_bits)

    datatype_bits = int(args.datatype_bits)
    if datatype_bits <= 0:
        raise ValueError("datatype_bits must be > 0")
    bits = parse_spec_list(args.bits)
    if bits is None:
        bits_1based = list(range(1, 9))
    else:
        bits_1based = sorted({b for b in bits if 1 <= b <= 8})
        if not bits_1based:
            raise ValueError("bit domain is empty after filtering for L1D byte lanes")
    bit_count = int(len(bits_1based))
    selected_data_bits_mask = 0
    for b in bits_1based:
        selected_data_bits_mask |= 1 << (int(b) - 1)
    selected_data_bits_count = int(popcount_u64(int(selected_data_bits_mask)))
    addr_effective_bits_seen: Set[int] = set()
    addr_bits_count_seen: Set[int] = set()

    (
        selected_l1d_bit_domain_size,
        selected_l1d_data_bit_domain_size,
        selected_l1d_tag_bit_domain_size,
        l1d_full_line_count,
        l1d_tail_bits,
    ) = _selected_l2_domain_bit_counts(
        l2_size_bits=int(l1d_size_bits),
        line_size_bytes=int(l1d_line_size_bytes),
        tag_bits=int(l1d_tag_bits),
        selected_data_bits_mask=int(selected_data_bits_mask),
        selected_data_bit_count_full_byte=int(bit_count),
        include_tag_bits=bool(include_tag_bits),
    )
    if selected_l1d_bit_domain_size <= 0:
        raise ValueError("selected L1D bit domain is empty")

    fi_space = _load_fi_sampling_space(getattr(args, "fi_sampling_space_path", None))
    (
        shader_seed_list,
        shader_scope_mode,
        shader_scope_source,
    ) = _resolve_l1d_shader_seed_list(
        raw_spec=getattr(args, "l1d_shaders", None),
        fi_space=fi_space,
        trace_template=trace_template,
        l1d_sites=l1d_sites,
    )
    if not shader_seed_list:
        raise ValueError(
            "l1d shader sampling domain is empty; pass --l1d-shaders (e.g. 0:1)"
        )
    shader_seed_counts: Counter = Counter(int(v) for v in shader_seed_list)
    shader_seed_domain_size = int(len(shader_seed_list))
    if shader_seed_domain_size <= 0:
        raise ValueError("l1d shader sampling domain is empty")
    l1d_write_allocate = int(getattr(args, "l1d_write_allocate", 0))
    if l1d_write_allocate not in (0, 1):
        raise ValueError("--l1d-write-allocate must be 0 or 1")
    line_store_allocates = bool(l1d_write_allocate)

    shader_cycle_weights: Dict[int, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    for rec in cycle_records:
        cycle = int(rec.cycle)
        mult = int(rec.multiplicity)
        if mult <= 0:
            continue
        for sm_id, count in shader_seed_counts.items():
            if int(count) <= 0:
                continue
            shader_cycle_weights[int(sm_id)][int(cycle)] += int(mult) * int(count)
    shader_prefix = build_thread_cycle_prefix(shader_cycle_weights)

    line_store_cycles_sorted = shared_cache_trace_views.l1d_line_store_cycles_sorted
    line_first_valid_cycle: Dict[Tuple[str, int, int, int], int] = dict(
        shared_cache_trace_views.l1d_line_first_valid_cycle
    )

    byte_cycle_masks: Dict[
        Tuple[Tuple[str, int, int, int], int, int],
        Tuple[int, int, int, int, int, int, int, int, int, int, int, int, int, int],
    ] = {}
    for rec_idx, rec in enumerate(l1d_sites):
        if str(_cache_site_row_field(rec, "site_kind", "")) != "l1d_load":
            continue
        mem_space = canonical_space(_cache_site_row_field(rec, "mem_space"))
        if mem_space not in ("global", "local"):
            continue
        sm_id_raw = _cache_site_row_field(rec, "sm_id")
        if sm_id_raw is None:
            continue
        addr = int(_cache_site_row_field(rec, "addr", 0))
        cycle = int(_cache_site_row_field(rec, "cycle", -1))
        thread_id = int(_cache_site_row_field(rec, "thread_id", -1))
        sm_id = int(sm_id_raw)
        line_addr = int(addr // int(l1d_line_size_bytes))
        byte_off = int(addr % int(l1d_line_size_bytes))
        line_key = _l1d_line_key(
            mem_space=str(mem_space),
            sm_id=int(sm_id),
            thread_id=int(thread_id),
            line_addr=int(line_addr),
        )
        if l1d_site_masks_many is not None:
            (
                due_mask,
                sdc_mask,
                unknown_mask,
                trace_uncovered_mask,
                trace_policy_override_mask,
            ) = l1d_site_masks_many[rec_idx]
        else:
            (
                due_mask,
                sdc_mask,
                unknown_mask,
                trace_uncovered_mask,
                trace_policy_override_mask,
            ) = final_due_sdc_masks_for_site_extended(
                rec=rec,
                trace_expanding_policy=trace_expanding_policy,
                trace_uncovered_mode=trace_uncovered_mode,
                trace_expanding_resolution_mode=trace_expanding_resolution_mode,
            )
        trace_mask_this_site = (
            parse_mask(_cache_site_row_field(rec, "trace_expanding_mask_this_site", 0))
            & 0xFF
        )
        (
            due_mask,
            sdc_mask,
            unknown_mask,
            trace_div_mask_this_site,
        ) = _apply_trace_divergence_policy_to_masks(
            due_mask=int(due_mask),
            sdc_mask=int(sdc_mask),
            unknown_mask=int(unknown_mask),
            trace_mask=int(trace_mask_this_site),
            width_bits=8,
            policy=trace_divergence_policy,
        )
        due_mask &= 0xFF
        unknown_mask &= 0xFF
        due_mask &= (~unknown_mask) & 0xFF
        sdc_mask &= (~due_mask) & 0xFF
        sdc_mask &= (~unknown_mask) & 0xFF
        trace_uncovered_mask &= 0xFF
        trace_policy_override_mask &= 0xFF
        semantic_due_mask = (
            parse_mask(_cache_site_row_field(rec, "semantic_due_mask_this_site", 0))
            & 0xFF
        )

        event_index = int(_cache_site_row_field(rec, "event_index", -1))
        raw_ev = event_by_index.get(event_index, {})
        access_size = int(_cache_site_row_field(rec, "width_bits", 8)) // 8
        if access_size <= 0:
            access_size = 1
        if raw_ev:
            effective_mask = _event_effective_address_mask_from_raw(raw_ev)
        else:
            effective_mask = _event_effective_address_mask_from_raw(
                {"mem_space": mem_space}
            )
        if addr_domain_enabled:
            (
                selected_addr_bits_mask,
                addr_bits_count,
                addr_effective_bits,
            ) = _resolve_selected_addr_bits(
                effective_mask=int(effective_mask),
                addr_bits_mode=addr_bits_mode,
                addr_bits_explicit=addr_bits_explicit,
            )
            if int(addr_effective_bits) > 0:
                addr_effective_bits_seen.add(int(addr_effective_bits))
            addr_bits_count_seen.add(int(addr_bits_count))
            (
                addr_due_mask,
                addr_sdc_mask,
                addr_unknown_mask,
                _addr_masked_mask,
                addr_source_bits,
                addr_trace_div_mask,
            ) = _classify_addr_masks_with_ranges(
                addr=int(_cache_site_row_field(rec, "addr", 0)),
                selected_mask=int(selected_addr_bits_mask),
                effective_mask=int(effective_mask),
                mem_space=str(mem_space),
                access_size=int(access_size),
                event_index=event_index if event_index >= 0 else None,
                cycle=int(_cache_site_row_field(rec, "cycle", -1))
                if int(_cache_site_row_field(rec, "cycle", -1)) >= 0
                else None,
                thread_id=int(_cache_site_row_field(rec, "thread_id", -1))
                if int(_cache_site_row_field(rec, "thread_id", -1)) >= 0
                else None,
                cta_id=int(_cache_site_row_field(rec, "cta_id", -1))
                if int(_cache_site_row_field(rec, "cta_id", -1)) >= 0
                else None,
                sm_id=int(_cache_site_row_field(rec, "sm_id", -1))
                if int(_cache_site_row_field(rec, "sm_id", -1)) >= 0
                else None,
                addr_ranges=addr_ranges,
                addr_fault_policy=addr_fault_policy,
                addr_due_mode=addr_due_mode,
                trace_mask=int(trace_mask_this_site),
                trace_divergence_policy=trace_divergence_policy,
            )
        else:
            selected_addr_bits_mask = 0
            addr_due_mask = 0
            addr_sdc_mask = 0
            addr_unknown_mask = 0
            addr_source_bits = {}
            addr_trace_div_mask = 0
        addr_oob_due_mask = (
            int(addr_due_mask) if int(addr_source_bits.get("addr_oob_due", 0)) > 0 else 0
        ) & MASK64
        addr_alias_sdc_mask = (
            int(addr_sdc_mask) if int(addr_source_bits.get("addr_alias_sdc", 0)) > 0 else 0
        ) & MASK64
        key = (line_key, int(byte_off), int(cycle))
        prev = byte_cycle_masks.get(key)
        if prev is None:
            byte_cycle_masks[key] = (
                int(due_mask),
                int(sdc_mask),
                int(unknown_mask),
                int(trace_uncovered_mask),
                int(trace_policy_override_mask),
                int(semantic_due_mask),
                int(trace_div_mask_this_site) & 0xFF,
                int(selected_addr_bits_mask) & MASK64,
                int(addr_due_mask) & MASK64,
                int(addr_sdc_mask) & MASK64,
                int(addr_unknown_mask) & MASK64,
                int(addr_trace_div_mask) & MASK64,
                int(addr_oob_due_mask) & MASK64,
                int(addr_alias_sdc_mask) & MASK64,
            )
        else:
            byte_cycle_masks[key] = (
                (int(prev[0]) | int(due_mask)) & 0xFF,
                (int(prev[1]) | int(sdc_mask)) & 0xFF,
                (int(prev[2]) | int(unknown_mask)) & 0xFF,
                (int(prev[3]) | int(trace_uncovered_mask)) & 0xFF,
                (int(prev[4]) | int(trace_policy_override_mask)) & 0xFF,
                (int(prev[5]) | int(semantic_due_mask)) & 0xFF,
                (int(prev[6]) | int(trace_div_mask_this_site)) & 0xFF,
                (int(prev[7]) | int(selected_addr_bits_mask)) & MASK64,
                (int(prev[8]) | int(addr_due_mask)) & MASK64,
                (int(prev[9]) | int(addr_sdc_mask)) & MASK64,
                (int(prev[10]) | int(addr_unknown_mask)) & MASK64,
                (int(prev[11]) | int(addr_trace_div_mask)) & MASK64,
                (int(prev[12]) | int(addr_oob_due_mask)) & MASK64,
                (int(prev[13]) | int(addr_alias_sdc_mask)) & MASK64,
            )
        prev_first = line_first_valid_cycle.get(line_key)
        if prev_first is None or int(cycle) < int(prev_first):
            line_first_valid_cycle[line_key] = int(cycle)

    byte_reads: Dict[
        Tuple[Tuple[str, int, int, int], int],
        Dict[int, Tuple[int, int, int, int, int, int, int, int, int, int, int, int, int, int]],
    ] = defaultdict(dict)
    for (line_key, byte_off, cycle), masks in byte_cycle_masks.items():
        per_cycle = byte_reads[(line_key, int(byte_off))]
        prev = per_cycle.get(int(cycle))
        if prev is None:
            per_cycle[int(cycle)] = (
                int(masks[0]) & 0xFF,
                int(masks[1]) & 0xFF,
                int(masks[2]) & 0xFF,
                int(masks[3]) & 0xFF,
                int(masks[4]) & 0xFF,
                int(masks[5]) & 0xFF,
                int(masks[6]) & 0xFF,
                int(masks[7]) & MASK64,
                int(masks[8]) & MASK64,
                int(masks[9]) & MASK64,
                int(masks[10]) & MASK64,
                int(masks[11]) & MASK64,
                int(masks[12]) & MASK64,
                int(masks[13]) & MASK64,
            )
        else:
            per_cycle[int(cycle)] = (
                (int(prev[0]) | int(masks[0])) & 0xFF,
                (int(prev[1]) | int(masks[1])) & 0xFF,
                (int(prev[2]) | int(masks[2])) & 0xFF,
                (int(prev[3]) | int(masks[3])) & 0xFF,
                (int(prev[4]) | int(masks[4])) & 0xFF,
                (int(prev[5]) | int(masks[5])) & 0xFF,
                (int(prev[6]) | int(masks[6])) & 0xFF,
                (int(prev[7]) | int(masks[7])) & MASK64,
                (int(prev[8]) | int(masks[8])) & MASK64,
                (int(prev[9]) | int(masks[9])) & MASK64,
                (int(prev[10]) | int(masks[10])) & MASK64,
                (int(prev[11]) | int(masks[11])) & MASK64,
                (int(prev[12]) | int(masks[12])) & MASK64,
                (int(prev[13]) | int(masks[13])) & MASK64,
            )

    grouped_byte_histories = _group_l1d_byte_histories(byte_reads)
    l1d_byte_key_count = int(len(byte_reads))
    l1d_byte_history_group_count = int(
        sum(len(rows) for rows in grouped_byte_histories.values())
    )
    l1d_byte_history_group_reduction = (
        float(l1d_byte_key_count) / float(l1d_byte_history_group_count)
        if l1d_byte_history_group_count > 0
        else 1.0
    )
    del byte_reads

    data_denominator = (
        int(total_cycle_lines)
        * int(shader_seed_domain_size)
        * int(selected_l1d_data_bit_domain_size)
    )
    tag_denominator = (
        int(total_cycle_lines)
        * int(shader_seed_domain_size)
        * int(selected_l1d_tag_bit_domain_size)
    )
    denominator = (
        int(total_cycle_lines)
        * int(shader_seed_domain_size)
        * int(selected_l1d_bit_domain_size)
    )
    if denominator <= 0:
        raise ValueError("l1d denominator is zero")
    addr_domain_enabled = bool(cache_addr_domain_enabled)

    due_data_num = 0
    sdc_data_num = 0
    unknown_data_num = 0
    addr_denominator = 0
    due_addr_num = 0
    sdc_addr_num = 0
    unknown_addr_num = 0
    trace_policy_used_bits = 0
    trace_policy_used_mass = 0
    trace_policy_override_bits = 0
    trace_policy_override_mass = 0
    trace_policy_override_sdc_bits = 0
    trace_policy_override_due_bits = 0
    trace_policy_override_unknown_bits = 0
    trace_policy_override_masked_bits = 0
    trace_uncovered_unknown_bits = 0
    trace_uncovered_unknown_mass = 0
    trace_divergence_bits = 0
    trace_divergence_mass = 0
    due_source_mass: Dict[str, float] = defaultdict(float)
    boundary_events_count = 0
    boundary_events_mass = 0
    boundary_bits_mass_total = 0
    l1d_segment_plan_cache: Dict[
        Tuple[Tuple[L1DByteCycleMasks, ...], int, bool, str],
        Tuple[CacheDataSegmentMetricRow, ...],
    ] = {}
    l1d_segment_plan_requests = 0
    l1d_segment_plan_hits = 0

    min_cycle = -10**30
    max_cycle = 10**30

    for line_key, history_groups in grouped_byte_histories.items():
        if not history_groups:
            continue
        first_valid_cycle = line_first_valid_cycle.get(line_key)
        if first_valid_cycle is None:
            continue

        sm_id = int(line_key[1])
        shader_prefix_row = shader_prefix.get(sm_id)
        if shader_prefix_row is None:
            continue
        cycles_shader, prefix_shader, shader_mass_total = shader_prefix_row
        if int(shader_mass_total) <= 0:
            continue

        store_cycles = line_store_cycles_sorted.get(line_key, [])
        for history_signature, byte_multiplicity in history_groups:
            read_cycles = [int(rc) for rc, _masks in history_signature]
            if not read_cycles:
                continue
            group_multiplier = int(byte_multiplicity)

            prev_store = max(int(min_cycle), int(first_valid_cycle))
            for maybe_store in [*store_cycles, None]:
                seg_lo = int(prev_store)
                seg_hi = int(max_cycle if maybe_store is None else int(maybe_store))
                if seg_hi <= seg_lo:
                    prev_store = seg_lo
                    continue

                read_lo = bisect.bisect_left(read_cycles, seg_lo)
                if maybe_store is None:
                    read_hi = len(read_cycles)
                else:
                    read_hi = bisect.bisect_right(read_cycles, seg_hi)
                seg_rows = history_signature[read_lo:read_hi]
                if not seg_rows:
                    prev_store = seg_hi
                    continue

                if use_grouped_segment_cache:
                    l1d_segment_plan_requests += 1
                    seg_plan_key = (
                        _cache_history_masks_key(seg_rows),
                        int(selected_data_bits_mask),
                        bool(addr_domain_enabled),
                        str(trace_divergence_policy),
                    )
                    seg_metrics = l1d_segment_plan_cache.get(seg_plan_key)
                    if seg_metrics is None:
                        seg_metrics = _build_cache_data_segment_metric_plan_from_masks(
                            seg_plan_key[0],
                            selected_data_bits_mask=int(selected_data_bits_mask),
                            addr_domain_enabled=bool(addr_domain_enabled),
                            trace_divergence_policy=str(trace_divergence_policy),
                        )
                        l1d_segment_plan_cache[seg_plan_key] = seg_metrics
                    else:
                        l1d_segment_plan_hits += 1
                else:
                    seg_metrics = _build_cache_data_segment_metric_plan(
                        seg_rows,
                        selected_data_bits_mask=int(selected_data_bits_mask),
                        addr_domain_enabled=bool(addr_domain_enabled),
                        trace_divergence_policy=str(trace_divergence_policy),
                        use_cache=False,
                    )

                interval_lo = seg_lo
                for idx, row in enumerate(seg_rows):
                    rc = int(row[0])
                    boundary_mass_here = range_sum(
                        cycles_shader,
                        prefix_shader,
                        int(rc),
                        int(rc) + 1,
                    )
                    if boundary_mass_here > 0:
                        boundary_events_count += int(group_multiplier)
                        boundary_events_mass += int(boundary_mass_here) * int(group_multiplier)
                        boundary_bits_mass_total += (
                            int(boundary_mass_here)
                            * int(selected_data_bits_count)
                            * int(group_multiplier)
                        )
                    boundary = int(rc) + 1 if ge_mode else int(rc)
                    interval_hi = min(seg_hi, boundary)
                    if interval_hi > interval_lo:
                        mass = range_sum(cycles_shader, prefix_shader, interval_lo, interval_hi)
                        if mass > 0:
                            weighted_mass = int(mass) * int(group_multiplier)
                            (
                                due_bits,
                                sdc_bits,
                                unknown_bits,
                                trace_uncovered_bits,
                                trace_policy_override_bits_here,
                                trace_policy_override_sdc_bits_here,
                                trace_policy_override_due_bits_here,
                                trace_policy_override_unknown_bits_here,
                                trace_policy_override_masked_bits_here,
                                semantic_due_bits,
                                base_due_bits,
                                trace_div_bits_here,
                                addr_bits_count,
                                addr_due_bits,
                                addr_sdc_bits,
                                addr_unknown_bits,
                                addr_oob_due_bits,
                                addr_alias_sdc_bits,
                                addr_trace_div_bits,
                            ) = seg_metrics[idx]
                            due_data_num += int(weighted_mass) * int(due_bits)
                            sdc_data_num += int(weighted_mass) * int(sdc_bits)
                            unknown_data_num += int(weighted_mass) * int(unknown_bits)
                            _add_source_mass(
                                due_source_mass,
                                "semantic_due",
                                float(int(weighted_mass) * int(semantic_due_bits)),
                            )
                            _add_source_mass(
                                due_source_mass,
                                "l1d_base_due",
                                float(int(weighted_mass) * int(base_due_bits)),
                            )
                            if trace_div_bits_here > 0:
                                trace_divergence_bits += int(trace_div_bits_here) * int(
                                    group_multiplier
                                )
                                trace_divergence_mass += int(weighted_mass) * int(
                                    trace_div_bits_here
                                )
                                target_cls = _trace_divergence_target_class(
                                    trace_divergence_policy
                                )
                                _add_source_mass(
                                    due_source_mass,
                                    f"trace_divergence_{target_cls}",
                                    float(int(weighted_mass) * int(trace_div_bits_here)),
                                )
                            trace_policy_used_bits += int(trace_uncovered_bits) * int(
                                group_multiplier
                            )
                            trace_policy_used_mass += int(weighted_mass) * int(
                                trace_uncovered_bits
                            )
                            trace_policy_override_bits += int(
                                trace_policy_override_bits_here
                            ) * int(group_multiplier)
                            trace_policy_override_mass += int(weighted_mass) * int(
                                trace_policy_override_bits_here
                            )
                            trace_policy_override_sdc_bits += int(
                                trace_policy_override_sdc_bits_here
                            ) * int(group_multiplier)
                            trace_policy_override_due_bits += int(
                                trace_policy_override_due_bits_here
                            ) * int(group_multiplier)
                            trace_policy_override_unknown_bits += int(
                                trace_policy_override_unknown_bits_here
                            ) * int(group_multiplier)
                            trace_policy_override_masked_bits += int(
                                trace_policy_override_masked_bits_here
                            ) * int(group_multiplier)
                            if trace_uncovered_mode == "legacy_unknown":
                                trace_uncovered_unknown_bits += int(trace_uncovered_bits) * int(
                                    group_multiplier
                                )
                                trace_uncovered_unknown_mass += int(weighted_mass) * int(
                                    trace_uncovered_bits
                                )

                            if addr_domain_enabled:
                                due_addr_num += int(weighted_mass) * int(addr_due_bits)
                                sdc_addr_num += int(weighted_mass) * int(addr_sdc_bits)
                                unknown_addr_num += int(weighted_mass) * int(addr_unknown_bits)
                                _add_source_mass(
                                    due_source_mass,
                                    "addr_oob_due",
                                    float(
                                        int(weighted_mass)
                                        * int(addr_oob_due_bits)
                                    ),
                                )
                                _add_source_mass(
                                    due_source_mass,
                                    "addr_alias_sdc",
                                    float(
                                        int(weighted_mass)
                                        * int(addr_alias_sdc_bits)
                                    ),
                                )
                                if addr_trace_div_bits > 0:
                                    trace_divergence_bits += int(addr_trace_div_bits) * int(
                                        group_multiplier
                                    )
                                    trace_divergence_mass += int(weighted_mass) * int(
                                        addr_trace_div_bits
                                    )
                                addr_denominator += int(weighted_mass) * int(addr_bits_count)
                    interval_lo = interval_hi
                    if interval_lo >= seg_hi:
                        break
                prev_store = seg_hi

    if due_data_num + sdc_data_num + unknown_data_num > data_denominator:
        raise ValueError(
            "Internal accounting mismatch for l1d data domain: "
            f"sdc+due+unknown={due_data_num + sdc_data_num + unknown_data_num} "
            f"> data_denominator={data_denominator}"
        )

    masked_data_num = (
        int(data_denominator)
        - int(due_data_num)
        - int(sdc_data_num)
        - int(unknown_data_num)
    )
    tag_exact_info = _exact_l1d_tag_counts_global_readonly_alias(
        trace_template=trace_template,
        trace_path=Path(args.trace_template),
        fi_space=fi_space,
        l1d_sites=l1d_sites,
        shader_prefix=shader_prefix,
        line_size_bytes=int(l1d_line_size_bytes),
        size_bits=int(l1d_size_bits),
        sample_tag_bits=int(l1d_tag_bits),
        ge_mode=bool(ge_mode),
        addr_ranges=addr_ranges,
        trace_expanding_policy=trace_expanding_policy,
        trace_uncovered_mode=trace_uncovered_mode,
        trace_expanding_resolution_mode=trace_expanding_resolution_mode,
        trace_divergence_policy=trace_divergence_policy,
    )
    if tag_exact_info is not None:
        tag_counts = {
            "masked": int(tag_denominator)
            - int(tag_exact_info["counts"].get("sdc", 0))
            - int(tag_exact_info["counts"].get("due", 0))
            - int(tag_exact_info["counts"].get("unknown", 0)),
            "sdc": int(tag_exact_info["counts"].get("sdc", 0)),
            "due": int(tag_exact_info["counts"].get("due", 0)),
            "unknown": int(tag_exact_info["counts"].get("unknown", 0)),
        }
    else:
        tag_counts = _cache_tag_counts_from_data(
            tag_total=int(tag_denominator),
            data_masked=int(masked_data_num),
            data_sdc=int(sdc_data_num),
            data_due=int(due_data_num),
            data_unknown=int(unknown_data_num),
            policy=cache_tag_class_policy,
        )
    masked_tag_num = int(tag_counts.get("masked", 0))
    sdc_tag_num = int(tag_counts.get("sdc", 0))
    due_tag_num = int(tag_counts.get("due", 0))
    unknown_tag_num = int(tag_counts.get("unknown", 0))
    if (
        masked_tag_num + sdc_tag_num + due_tag_num + unknown_tag_num
        != int(tag_denominator)
    ):
        raise ValueError(
            "Internal accounting mismatch for l1d tag domain: "
            f"masked+sdc+due+unknown="
            f"{masked_tag_num + sdc_tag_num + due_tag_num + unknown_tag_num} "
            f"!= tag_denominator={tag_denominator}"
        )

    if not addr_domain_enabled:
        addr_denominator = 0
        due_addr_num = 0
        sdc_addr_num = 0
        unknown_addr_num = 0
    if (
        int(due_addr_num) + int(sdc_addr_num) + int(unknown_addr_num)
        > int(addr_denominator)
    ):
        raise ValueError(
            "Internal accounting mismatch for l1d addr domain: "
            f"sdc+due+unknown={int(due_addr_num) + int(sdc_addr_num) + int(unknown_addr_num)} "
            f"> addr_denominator={addr_denominator}"
        )
    masked_addr_num = (
        int(addr_denominator)
        - int(due_addr_num)
        - int(sdc_addr_num)
        - int(unknown_addr_num)
    )
    addr_bits_count_value = int(max(addr_bits_count_seen)) if addr_bits_count_seen else 0
    addr_effective_bits_value = _summarize_effective_bits(addr_effective_bits_seen)

    denominator_total = int(denominator) + int(addr_denominator)
    due_num = int(due_data_num) + int(due_tag_num) + int(due_addr_num)
    sdc_num = int(sdc_data_num) + int(sdc_tag_num) + int(sdc_addr_num)
    unknown_num = int(unknown_data_num) + int(unknown_tag_num) + int(unknown_addr_num)
    if due_num + sdc_num + unknown_num > denominator_total:
        raise ValueError(
            "Internal accounting mismatch for l1d total domain: "
            f"sdc+due+unknown={due_num + sdc_num + unknown_num} > denominator={denominator_total}"
        )
    masked_num = int(denominator_total) - int(due_num) - int(sdc_num) - int(unknown_num)
    rates = {
        "masked": (float(masked_num) / float(denominator_total)),
        "sdc": (float(sdc_num) / float(denominator_total)),
        "due": (float(due_num) / float(denominator_total)),
        "unknown": (float(unknown_num) / float(denominator_total)),
    }
    l1d_summary = {
        "masked": int(masked_num),
        "sdc": int(sdc_num),
        "due": int(due_num),
        "unknown": int(unknown_num),
        "den": int(denominator_total),
        "rate": dict(rates),
        "by_domain": {
            "data": {
                "masked": int(masked_data_num),
                "sdc": int(sdc_data_num),
                "due": int(due_data_num),
                "unknown": int(unknown_data_num),
                "den": int(data_denominator),
            },
            "tag": {
                "masked": int(masked_tag_num),
                "sdc": int(sdc_tag_num),
                "due": int(due_tag_num),
                "unknown": int(unknown_tag_num),
                "den": int(tag_denominator),
                "policy": str(cache_tag_class_policy),
                "exact_mode": (
                    str(tag_exact_info.get("mode", ""))
                    if isinstance(tag_exact_info, dict)
                    else "policy_only"
                ),
            },
            "addr": {
                "masked": int(masked_addr_num),
                "sdc": int(sdc_addr_num),
                "due": int(due_addr_num),
                "unknown": int(unknown_addr_num),
                "den": int(addr_denominator),
                "policy": str(addr_fault_policy),
                "addr_due_mode": str(addr_due_mode),
            },
        },
    }

    return {
        "classification_counts": {
            "masked": int(masked_num),
            "sdc": int(sdc_num),
            "due": int(due_num),
            "unknown": int(unknown_num),
            "total": int(denominator_total),
        },
        "classification_rates": rates,
        "weighted_classification_counts": {
            "masked": fraction(masked_num, denominator_total),
            "sdc": fraction(sdc_num, denominator_total),
            "due": fraction(due_num, denominator_total),
            "unknown": fraction(unknown_num, denominator_total),
            "total": fraction(denominator_total, denominator_total),
        },
        "weighted_classification_rates": {
            "masked": fraction(masked_num, denominator_total),
            "sdc": fraction(sdc_num, denominator_total),
            "due": fraction(due_num, denominator_total),
            "unknown": fraction(unknown_num, denominator_total),
        },
        "summary": {
            "l1d_cache": l1d_summary,
        },
        "exact_meta": {
            "fault_component": "l1d",
            "cycles_file": str(args.cycles),
            "active_threads_log": (
                str(args.active_threads_log) if args.active_threads_log is not None else None
            ),
            "trace_template": str(args.trace_template),
            "l1d_size_bits": int(l1d_size_bits),
            "l1d_line_size_bytes": int(l1d_line_size_bytes),
            "l1d_tag_bits": int(l1d_tag_bits),
            "l1d_include_tag_bits": bool(include_tag_bits),
            "l1d_full_line_count": int(l1d_full_line_count),
            "l1d_tail_bits": int(l1d_tail_bits),
            "l1d_selected_bit_domain_size": int(selected_l1d_bit_domain_size),
            "l1d_selected_data_bit_domain_size": int(selected_l1d_data_bit_domain_size),
            "l1d_selected_tag_bit_domain_size": int(selected_l1d_tag_bit_domain_size),
            "l1d_shaders": [int(v) for v in shader_seed_list],
            "l1d_shader_seed_domain_size": int(shader_seed_domain_size),
            "shader_scope_mode": str(shader_scope_mode),
            "shader_scope_source": str(shader_scope_source),
            "shader_scope_count": int(shader_seed_domain_size),
            "bit_count": int(bit_count),
            "datatype_bits": int(datatype_bits),
            "consumer_compare": str(args.consumer_compare),
            "trace_expanding_policy": str(trace_expanding_policy),
            "trace_expanding_resolution_mode": str(trace_expanding_resolution_mode),
            "trace_uncovered_mode": str(trace_uncovered_mode),
            "trace_divergence_policy": str(trace_divergence_policy),
            "addr_fault_policy": str(addr_fault_policy),
            "addr_due_mode": str(addr_due_mode),
            "addr_bits_mode": str(addr_bits_mode),
            "addr_bits_count": int(addr_bits_count_value),
            "addr_effective_bits": addr_effective_bits_value,
            "addr_effective_bits_max": (
                int(max(addr_effective_bits_seen)) if addr_effective_bits_seen else 0
            ),
            "cache_tag_class_policy": str(cache_tag_class_policy),
            "cache_tag_exact_mode": (
                str(tag_exact_info.get("mode", ""))
                if isinstance(tag_exact_info, dict)
                else "policy_only"
            ),
            "cache_tag_alias_ordered_pairs": (
                int(tag_exact_info.get("ordered_pairs", 0))
                if isinstance(tag_exact_info, dict)
                else 0
            ),
            "cache_tag_alias_intervals": (
                int(tag_exact_info.get("alias_intervals", tag_exact_info.get("replay_intervals", 0)))
                if isinstance(tag_exact_info, dict)
                else 0
            ),
            "cache_tag_fallback_reachable_intervals": (
                int(tag_exact_info.get("fallback_reachable_intervals", 0))
                if isinstance(tag_exact_info, dict)
                else 0
            ),
            "cache_tag_fallback_reason": (
                str(tag_exact_info.get("fallback_reason", ""))
                if isinstance(tag_exact_info, dict)
                else ""
            ),
            "cache_tag_self_miss_intervals": (
                int(tag_exact_info.get("self_miss_intervals", 0))
                if isinstance(tag_exact_info, dict)
                else 0
            ),
            "cache_tag_self_miss_sdc_bits": (
                int(tag_exact_info.get("self_miss_sdc", 0))
                if isinstance(tag_exact_info, dict)
                else 0
            ),
            "cache_tag_multievent_cycles": (
                int(tag_exact_info.get("multievent_cycles", 0))
                if isinstance(tag_exact_info, dict)
                else 0
            ),
            "cache_tag_multithread_cycles": (
                int(tag_exact_info.get("multithread_cycles", 0))
                if isinstance(tag_exact_info, dict)
                else 0
            ),
            "cache_tag_multievent_examples": (
                list(tag_exact_info.get("multievent_examples", []))
                if isinstance(tag_exact_info, dict)
                else []
            ),
            "cache_tag_examples": (
                list(tag_exact_info.get("examples", []))
                if isinstance(tag_exact_info, dict)
                else []
            ),
            "cache_tag_self_miss_examples": (
                list(tag_exact_info.get("self_miss_examples", []))
                if isinstance(tag_exact_info, dict)
                else []
            ),
            "trace_policy_used_bits": int(trace_policy_used_bits),
            "trace_policy_used_mass": int(trace_policy_used_mass),
            "trace_policy_override_bits": int(trace_policy_override_bits),
            "trace_policy_override_mass": int(trace_policy_override_mass),
            "trace_policy_override_reason_breakdown": {
                "sdc": int(trace_policy_override_sdc_bits),
                "due": int(trace_policy_override_due_bits),
                "unknown": int(trace_policy_override_unknown_bits),
                "masked": int(trace_policy_override_masked_bits),
            },
            "trace_uncovered_unknown_bits": int(trace_uncovered_unknown_bits),
            "trace_uncovered_unknown_mass": int(trace_uncovered_unknown_mass),
            "trace_divergence_bits": int(trace_divergence_bits),
            "trace_divergence_mass": int(trace_divergence_mass),
            "unknown_bits": int(unknown_num),
            "unknown_mass": int(unknown_num),
            "total_bits": int(denominator_total),
            "data_bits": int(data_denominator),
            "addr_domain_bits": int(addr_denominator),
            "tag_bits": int(tag_denominator),
            "masked_bits_data": int(masked_data_num),
            "sdc_bits_data": int(sdc_data_num),
            "due_bits_data": int(due_data_num),
            "unknown_bits_data": int(unknown_data_num),
            "addr_masked_bits": int(masked_addr_num),
            "addr_sdc_bits": int(sdc_addr_num),
            "addr_due_bits": int(due_addr_num),
            "addr_unknown_bits": int(unknown_addr_num),
            "masked_bits_tag": int(masked_tag_num),
            "sdc_bits_tag": int(sdc_tag_num),
            "due_bits_tag": int(due_tag_num),
            "unknown_bits_tag": int(unknown_tag_num),
            "due_source_bits": _mass_map_to_bits_map(due_source_mass),
            "due_mass_by_source": _normalize_mass_map(due_source_mass),
            **_boundary_meta_fields(
                consumer_compare=str(args.consumer_compare),
                same_cycle_effect_prob=same_cycle_effect_prob,
                boundary_events_count=int(boundary_events_count),
                boundary_events_mass=float(boundary_events_mass),
                boundary_bits_mass_total=float(boundary_bits_mass_total),
            ),
            "missing_active_thread_cycles": int(
                cycle_records_meta.get("missing_active_thread_cycles", 0)
            ),
            "missing_active_thread_cycle_ratio": float(
                cycle_records_meta.get("missing_active_thread_cycle_ratio", 0.0)
            ),
            "active_threads_carried_forward_cycles": int(
                cycle_records_meta.get("active_threads_carried_forward_cycles", 0)
            ),
            "active_threads_empty_fill_cycles": int(
                cycle_records_meta.get("active_threads_empty_fill_cycles", 0)
            ),
            "missing_active_threads_policy": str(
                cycle_records_meta.get("missing_active_threads_policy", "empty")
            ),
            "addr_valid_ranges_path": (
                str(args.addr_valid_ranges_path)
                if getattr(args, "addr_valid_ranges_path", None) is not None
                else None
            ),
            "addr_valid_range_count": int(len(addr_ranges)),
            "observed_l1d_line_count": int(len(line_first_valid_cycle)),
            "l1d_byte_key_count": int(l1d_byte_key_count),
            "l1d_byte_history_group_count": int(l1d_byte_history_group_count),
            "l1d_byte_history_group_reduction": float(
                l1d_byte_history_group_reduction
            ),
            "l1d_segment_group_mode": str(storage_group_mode),
            "l1d_segment_plan_requests": int(l1d_segment_plan_requests),
            "l1d_segment_plan_hits": int(l1d_segment_plan_hits),
            "l1d_segment_plan_entries": int(len(l1d_segment_plan_cache)),
            "l1d_write_allocate": bool(line_store_allocates),
            "l1d_fault_site_count": int(len(l1d_sites)),
            "l1d_load_site_count": int(
                sum(
                    1
                    for rec in l1d_sites
                    if str(_cache_site_row_field(rec, "site_kind", "")) == "l1d_load"
                )
            ),
            "l1d_store_site_count": int(
                sum(
                    1
                    for rec in l1d_sites
                    if str(_cache_site_row_field(rec, "site_kind", "")) == "l1d_store"
                )
            ),
            "semantic_error_reason_counts": dict(
                analyzer_exact_meta.get("semantic_error_reason_counts", {})
            ),
            "semantic_error_reasons_top20": list(
                analyzer_exact_meta.get("semantic_error_reasons_top20", [])
            ),
            "semantic_error_samples": list(
                analyzer_exact_meta.get("semantic_error_samples", [])
            ),
            "semantic_infra_error_count": int(
                analyzer_exact_meta.get("semantic_infra_error_count", 0)
            ),
            "semantic_infra_error_reason_counts": dict(
                analyzer_exact_meta.get("semantic_infra_error_reason_counts", {})
            ),
            "semantic_infra_error_reasons_top20": list(
                analyzer_exact_meta.get("semantic_infra_error_reasons_top20", [])
            ),
            "semantic_unknown_count": int(
                analyzer_exact_meta.get("semantic_unknown_count", 0)
            ),
            "semantic_unknown_reason_counts": dict(
                analyzer_exact_meta.get("semantic_unknown_reason_counts", {})
            ),
            "semantic_unknown_reasons_top20": list(
                analyzer_exact_meta.get("semantic_unknown_reasons_top20", [])
            ),
            "semantic_unknown_reason_details_top20": list(
                analyzer_exact_meta.get("semantic_unknown_reason_details_top20", [])
            ),
            "semantic_unknown_samples": list(
                analyzer_exact_meta.get("semantic_unknown_samples", [])
            ),
            "auto_range_created_count": int(
                analyzer_exact_meta.get("auto_range_created_count", 0)
            ),
            "auto_range_reason_counts": dict(
                analyzer_exact_meta.get("auto_range_reason_counts", {})
            ),
            "auto_range_samples_top20": list(
                analyzer_exact_meta.get("auto_range_samples_top20", [])
            ),
            "trace_load_init_event_count": int(
                analyzer_exact_meta.get("trace_load_init_event_count", 0)
            ),
            "trace_load_init_byte_count": int(
                analyzer_exact_meta.get("trace_load_init_byte_count", 0)
            ),
            "trace_load_init_samples_top20": list(
                analyzer_exact_meta.get("trace_load_init_samples_top20", [])
            ),
            "trace_bit_no_semantic_coverage_records": int(
                analyzer_exact_meta.get("trace_bit_no_semantic_coverage_records", 0)
            ),
            "trace_bit_no_semantic_coverage_bits": int(
                analyzer_exact_meta.get("trace_bit_no_semantic_coverage_bits", 0)
            ),
            "trace_bit_no_semantic_coverage_samples": list(
                analyzer_exact_meta.get("trace_bit_no_semantic_coverage_samples", [])
            ),
            "due_oracle_reason_counts": dict(
                analyzer_exact_meta.get("due_oracle_reason_counts", {})
            ),
            "due_oracle_reason_details_top20": list(
                analyzer_exact_meta.get("due_oracle_reason_details_top20", [])
            ),
            "output_oracle_type": str(
                analyzer_exact_meta.get("output_oracle_type", "")
            ),
            "output_oracle_has_output_spec": bool(
                analyzer_exact_meta.get("output_oracle_has_output_spec", False)
            ),
            "output_oracle_spec_entry_count": int(
                analyzer_exact_meta.get("output_oracle_spec_entry_count", 0)
            ),
            "output_oracle_spec_total_bytes": int(
                analyzer_exact_meta.get("output_oracle_spec_total_bytes", 0)
            ),
            "output_oracle_spec_ranges": list(
                analyzer_exact_meta.get("output_oracle_spec_ranges", [])
            ),
            "output_last_writer_store_count": int(
                analyzer_exact_meta.get("output_last_writer_store_count", 0)
            ),
            "output_total_store_count": int(
                analyzer_exact_meta.get("output_total_store_count", 0)
            ),
            "filtered_store_ratio": float(
                analyzer_exact_meta.get("filtered_store_ratio", 0.0)
            ),
            "addr_observed_seed_suppressed_bits": int(
                analyzer_exact_meta.get("addr_observed_seed_suppressed_bits", 0)
            ),
            "addr_observed_seed_suppressed_events": int(
                analyzer_exact_meta.get("addr_observed_seed_suppressed_events", 0)
            ),
            "tol_output_store_seed_count": int(
                analyzer_exact_meta.get("tol_output_store_seed_count", 0)
            ),
            "tol_float_backward_op_count": int(
                analyzer_exact_meta.get("tol_float_backward_op_count", 0)
            ),
            "tol_memory_forward_byte_count": int(
                analyzer_exact_meta.get("tol_memory_forward_byte_count", 0)
            ),
            "tol_fallback_count": int(
                analyzer_exact_meta.get("tol_fallback_count", 0)
            ),
        },
    }


def compute_exact_l2(args: argparse.Namespace) -> Dict[str, Any]:
    normalize_trace_coverage = bool(getattr(args, "normalize_trace_coverage", False))
    storage_group_mode = _normalize_storage_group_mode(
        getattr(args, "storage_group_mode", "legacy")
    )
    use_grouped_history_mode = storage_group_mode == "grouped"
    analyzer = _load_analyzer_output_for_compute(
        args.analyzer_output,
        normalize_trace_coverage=normalize_trace_coverage,
    )
    analyzer_exact_meta_raw = analyzer.get("exact_meta", {})
    analyzer_exact_meta = (
        analyzer_exact_meta_raw if isinstance(analyzer_exact_meta_raw, dict) else {}
    )
    fi_space = _load_fi_sampling_space(getattr(args, "fi_sampling_space_path", None))

    if args.trace_template is None:
        raise ValueError("--trace-template is required for fault-component l2")
    trace_template = parse_trace_template(args.trace_template)
    shared_cache_trace_views = _load_shared_cache_trace_views_for_args(args)
    event_by_index = shared_cache_trace_views.event_by_index
    l2_sites = _load_filtered_cache_fault_sites_for_compute(
        "l2",
        Path(args.analyzer_output),
        Path(args.trace_template),
        normalize_trace_coverage=normalize_trace_coverage,
    )

    cycle_records, cycle_records_meta = load_cycle_records_with_meta(
        args.cycles,
        args.active_threads_log,
        bool(getattr(args, "allow_missing_active_threads", False)),
        str(getattr(args, "missing_active_threads_policy", "empty")),
    )
    cycles_sorted, cycle_prefix, total_cycle_lines = _cycle_prefix_from_records(cycle_records)
    if total_cycle_lines <= 0:
        raise ValueError("cycle multiplicity total is zero")

    trace_expanding_policy = str(args.trace_expanding_policy).strip().lower()
    if trace_expanding_policy != CANONICAL_TRACE_EXPANDING_POLICY:
        raise ValueError(
            "trace_expanding_policy must be one of {}; got {!r}".format(
                CANONICAL_TRACE_EXPANDING_POLICY,
                trace_expanding_policy,
            )
        )
    trace_uncovered_mode = _normalize_trace_uncovered_mode(
        getattr(args, "trace_uncovered_mode", "legacy_unknown")
    )
    trace_expanding_resolution_mode = str(
        getattr(args, "trace_expanding_resolution_mode", "legacy")
    ).strip().lower()
    if trace_expanding_resolution_mode != CANONICAL_TRACE_EXPANDING_RESOLUTION_MODE:
        raise ValueError(
            "trace_expanding_resolution_mode must be one of {}; got {!r}".format(
                CANONICAL_TRACE_EXPANDING_RESOLUTION_MODE,
                trace_expanding_resolution_mode,
            )
        )
    l2_site_masks_many = _load_cache_site_masks_for_compute(
        "l2",
        Path(args.analyzer_output),
        Path(args.trace_template),
        normalize_trace_coverage=normalize_trace_coverage,
        trace_expanding_policy=trace_expanding_policy,
        trace_uncovered_mode=trace_uncovered_mode,
        trace_expanding_resolution_mode=trace_expanding_resolution_mode,
    )
    cache_tag_class_policy = _normalize_cache_tag_class_policy(
        getattr(args, "cache_tag_class_policy", CANONICAL_CACHE_TAG_CLASS_POLICY)
    )
    addr_fault_policy = _normalize_addr_fault_policy(
        getattr(args, "addr_fault_policy", CANONICAL_ADDR_FAULT_POLICY)
    )
    trace_divergence_policy = _normalize_trace_divergence_policy(
        getattr(args, "trace_divergence_policy", CANONICAL_TRACE_DIVERGENCE_POLICY)
    )
    addr_due_mode = _normalize_addr_due_mode(getattr(args, "addr_due_mode", CANONICAL_ADDR_DUE_MODE))
    cache_addr_domain_enabled = _cache_addr_domain_runtime_enabled(args)
    addr_domain_enabled = bool(cache_addr_domain_enabled)
    addr_bits_mode, addr_bits_explicit = _parse_addr_bits_spec(
        getattr(args, "addr_bits", "auto")
    )
    ge_mode = str(args.consumer_compare).strip().lower() == "ge"
    same_cycle_effect_prob = _normalize_same_cycle_effect_prob(
        getattr(args, "same_cycle_effect_prob", None)
    )
    if cache_addr_domain_enabled:
        addr_ranges = _load_addr_valid_ranges(
            trace_memory_ranges=list(trace_template.get("memory_ranges", [])),
            external_path=getattr(args, "addr_valid_ranges_path", None),
        )
    else:
        addr_ranges = []

    l2_size_bits = int(args.l2_size_bits)
    if l2_size_bits <= 0:
        raise ValueError(
            "l2 requires positive --l2-size-bits (use campaign/config derived L2_SIZE_BITS)"
        )
    l2_line_size_bytes = int(args.l2_line_size_bytes)
    if l2_line_size_bytes <= 0:
        raise ValueError("--l2-line-size-bytes must be > 0")
    l2_tag_bits = int(args.l2_tag_bits)
    if l2_tag_bits < 0:
        raise ValueError("--l2-tag-bits must be >= 0")
    l2_include_tag_bits = int(args.l2_include_tag_bits)
    if l2_include_tag_bits not in (0, 1):
        raise ValueError("--l2-include-tag-bits must be 0 or 1")
    include_tag_bits = bool(l2_include_tag_bits)
    l2_global_prefill = int(args.l2_global_prefill)
    if l2_global_prefill not in (0, 1):
        raise ValueError("--l2-global-prefill must be 0 or 1")
    global_prefill = bool(l2_global_prefill)

    datatype_bits = int(args.datatype_bits)
    if datatype_bits <= 0:
        raise ValueError("datatype_bits must be > 0")
    bits = parse_spec_list(args.bits)
    if bits is None:
        bits_1based = list(range(1, 9))
    else:
        bits_1based = sorted({b for b in bits if 1 <= b <= 8})
        if not bits_1based:
            raise ValueError("bit domain is empty after filtering for L2 byte lanes")
    bit_count = int(len(bits_1based))
    selected_data_bits_mask = 0
    for b in bits_1based:
        selected_data_bits_mask |= 1 << (int(b) - 1)
    selected_data_bits_count = int(popcount_u64(int(selected_data_bits_mask)))
    addr_effective_bits_seen: Set[int] = set()
    addr_bits_count_seen: Set[int] = set()

    (
        selected_l2_bit_domain_size,
        selected_l2_data_bit_domain_size,
        selected_l2_tag_bit_domain_size,
        l2_full_line_count,
        l2_tail_bits,
    ) = _selected_l2_domain_bit_counts(
        l2_size_bits=int(l2_size_bits),
        line_size_bytes=int(l2_line_size_bytes),
        tag_bits=int(l2_tag_bits),
        selected_data_bits_mask=int(selected_data_bits_mask),
        selected_data_bit_count_full_byte=int(bit_count),
        include_tag_bits=bool(include_tag_bits),
    )
    if selected_l2_bit_domain_size <= 0:
        raise ValueError("selected L2 bit domain is empty")
    addr_domain_enabled = bool(cache_addr_domain_enabled)

    line_store_cycles_sorted = shared_cache_trace_views.l2_line_store_cycles_sorted
    line_first_load_cycle: Dict[Tuple[str, int, int], int] = dict(
        shared_cache_trace_views.l2_line_first_load_cycle
    )

    byte_cycle_masks: Dict[
        Tuple[Tuple[str, int, int], int, int],
        Tuple[int, int, int, int, int, int, int, int, int, int, int, int, int, int],
    ] = {}
    for rec_idx, rec in enumerate(l2_sites):
        if str(_cache_site_row_field(rec, "site_kind", "")) != "l2_load":
            continue
        mem_space = canonical_space(_cache_site_row_field(rec, "mem_space"))
        if mem_space not in ("global", "local"):
            continue
        addr = int(_cache_site_row_field(rec, "addr", 0))
        cycle = int(_cache_site_row_field(rec, "cycle", -1))
        thread_id = int(_cache_site_row_field(rec, "thread_id", -1))
        line_addr = int(addr // int(l2_line_size_bytes))
        byte_off = int(addr % int(l2_line_size_bytes))
        line_key = _l2_line_key(
            mem_space=str(mem_space),
            thread_id=int(thread_id),
            line_addr=int(line_addr),
        )
        if l2_site_masks_many is not None:
            (
                due_mask,
                sdc_mask,
                unknown_mask,
                trace_uncovered_mask,
                trace_policy_override_mask,
            ) = l2_site_masks_many[rec_idx]
        else:
            (
                due_mask,
                sdc_mask,
                unknown_mask,
                trace_uncovered_mask,
                trace_policy_override_mask,
            ) = final_due_sdc_masks_for_site_extended(
                rec=rec,
                trace_expanding_policy=trace_expanding_policy,
                trace_uncovered_mode=trace_uncovered_mode,
                trace_expanding_resolution_mode=trace_expanding_resolution_mode,
            )
        trace_mask_this_site = (
            parse_mask(_cache_site_row_field(rec, "trace_expanding_mask_this_site", 0))
            & 0xFF
        )
        (
            due_mask,
            sdc_mask,
            unknown_mask,
            trace_div_mask_this_site,
        ) = _apply_trace_divergence_policy_to_masks(
            due_mask=int(due_mask),
            sdc_mask=int(sdc_mask),
            unknown_mask=int(unknown_mask),
            trace_mask=int(trace_mask_this_site),
            width_bits=8,
            policy=trace_divergence_policy,
        )
        due_mask &= 0xFF
        unknown_mask &= 0xFF
        due_mask &= (~unknown_mask) & 0xFF
        sdc_mask &= (~due_mask) & 0xFF
        sdc_mask &= (~unknown_mask) & 0xFF
        trace_uncovered_mask &= 0xFF
        trace_policy_override_mask &= 0xFF
        semantic_due_mask = (
            parse_mask(_cache_site_row_field(rec, "semantic_due_mask_this_site", 0))
            & 0xFF
        )
        event_index = int(_cache_site_row_field(rec, "event_index", -1))
        raw_ev = event_by_index.get(event_index, {})
        access_size = int(_cache_site_row_field(rec, "width_bits", 8)) // 8
        if access_size <= 0:
            access_size = 1
        if raw_ev:
            effective_mask = _event_effective_address_mask_from_raw(raw_ev)
        else:
            effective_mask = _event_effective_address_mask_from_raw(
                {"mem_space": mem_space}
            )
        if addr_domain_enabled:
            (
                selected_addr_bits_mask,
                addr_bits_count,
                addr_effective_bits,
            ) = _resolve_selected_addr_bits(
                effective_mask=int(effective_mask),
                addr_bits_mode=addr_bits_mode,
                addr_bits_explicit=addr_bits_explicit,
            )
            if int(addr_effective_bits) > 0:
                addr_effective_bits_seen.add(int(addr_effective_bits))
            addr_bits_count_seen.add(int(addr_bits_count))
            (
                addr_due_mask,
                addr_sdc_mask,
                addr_unknown_mask,
                _addr_masked_mask,
                addr_source_bits,
                addr_trace_div_mask,
            ) = _classify_addr_masks_with_ranges(
                addr=int(_cache_site_row_field(rec, "addr", 0)),
                selected_mask=int(selected_addr_bits_mask),
                effective_mask=int(effective_mask),
                mem_space=str(mem_space),
                access_size=int(access_size),
                event_index=event_index if event_index >= 0 else None,
                cycle=int(_cache_site_row_field(rec, "cycle", -1))
                if int(_cache_site_row_field(rec, "cycle", -1)) >= 0
                else None,
                thread_id=int(_cache_site_row_field(rec, "thread_id", -1))
                if int(_cache_site_row_field(rec, "thread_id", -1)) >= 0
                else None,
                cta_id=int(_cache_site_row_field(rec, "cta_id", -1))
                if int(_cache_site_row_field(rec, "cta_id", -1)) >= 0
                else None,
                sm_id=int(_cache_site_row_field(rec, "sm_id", -1))
                if int(_cache_site_row_field(rec, "sm_id", -1)) >= 0
                else None,
                addr_ranges=addr_ranges,
                addr_fault_policy=addr_fault_policy,
                addr_due_mode=addr_due_mode,
                trace_mask=int(trace_mask_this_site),
                trace_divergence_policy=trace_divergence_policy,
            )
        else:
            selected_addr_bits_mask = 0
            addr_due_mask = 0
            addr_sdc_mask = 0
            addr_unknown_mask = 0
            addr_source_bits = {}
            addr_trace_div_mask = 0
        addr_oob_due_mask = (
            int(addr_due_mask) if int(addr_source_bits.get("addr_oob_due", 0)) > 0 else 0
        ) & MASK64
        addr_alias_sdc_mask = (
            int(addr_sdc_mask) if int(addr_source_bits.get("addr_alias_sdc", 0)) > 0 else 0
        ) & MASK64
        key = (line_key, int(byte_off), int(cycle))
        prev = byte_cycle_masks.get(key)
        if prev is None:
            byte_cycle_masks[key] = (
                int(due_mask),
                int(sdc_mask),
                int(unknown_mask),
                int(trace_uncovered_mask),
                int(trace_policy_override_mask),
                int(semantic_due_mask),
                int(trace_div_mask_this_site) & 0xFF,
                int(selected_addr_bits_mask) & MASK64,
                int(addr_due_mask) & MASK64,
                int(addr_sdc_mask) & MASK64,
                int(addr_unknown_mask) & MASK64,
                int(addr_trace_div_mask) & MASK64,
                int(addr_oob_due_mask) & MASK64,
                int(addr_alias_sdc_mask) & MASK64,
            )
        else:
            byte_cycle_masks[key] = (
                (int(prev[0]) | int(due_mask)) & 0xFF,
                (int(prev[1]) | int(sdc_mask)) & 0xFF,
                (int(prev[2]) | int(unknown_mask)) & 0xFF,
                (int(prev[3]) | int(trace_uncovered_mask)) & 0xFF,
                (int(prev[4]) | int(trace_policy_override_mask)) & 0xFF,
                (int(prev[5]) | int(semantic_due_mask)) & 0xFF,
                (int(prev[6]) | int(trace_div_mask_this_site)) & 0xFF,
                (int(prev[7]) | int(selected_addr_bits_mask)) & MASK64,
                (int(prev[8]) | int(addr_due_mask)) & MASK64,
                (int(prev[9]) | int(addr_sdc_mask)) & MASK64,
                (int(prev[10]) | int(addr_unknown_mask)) & MASK64,
                (int(prev[11]) | int(addr_trace_div_mask)) & MASK64,
                (int(prev[12]) | int(addr_oob_due_mask)) & MASK64,
                (int(prev[13]) | int(addr_alias_sdc_mask)) & MASK64,
            )
        prev_first = line_first_load_cycle.get(line_key)
        if prev_first is None or int(cycle) < int(prev_first):
            line_first_load_cycle[line_key] = int(cycle)

    # FI campaign uses gpgpu_perf_sim_memcpy=1 by default, which preloads many global
    # lines into L2 before the first kernel instruction executes. When enabled, treat
    # global lines as valid from the earliest sampled cycle instead of first in-kernel load.
    if global_prefill and cycles_sorted:
        prefill_cycle = int(cycles_sorted[0])
        for line_key in list(line_first_load_cycle.keys()):
            if isinstance(line_key, tuple) and len(line_key) >= 1 and str(line_key[0]) == "global":
                if int(line_first_load_cycle.get(line_key, prefill_cycle)) > int(prefill_cycle):
                    line_first_load_cycle[line_key] = int(prefill_cycle)

    byte_reads: Dict[
        Tuple[Tuple[str, int, int], int],
        Dict[int, Tuple[int, int, int, int, int, int, int, int, int, int, int, int, int, int]],
    ] = defaultdict(dict)
    for (line_key, byte_off, cycle), masks in byte_cycle_masks.items():
        per_cycle = byte_reads[(line_key, int(byte_off))]
        prev = per_cycle.get(int(cycle))
        if prev is None:
            per_cycle[int(cycle)] = (
                int(masks[0]) & 0xFF,
                int(masks[1]) & 0xFF,
                int(masks[2]) & 0xFF,
                int(masks[3]) & 0xFF,
                int(masks[4]) & 0xFF,
                int(masks[5]) & 0xFF,
                int(masks[6]) & 0xFF,
                int(masks[7]) & MASK64,
                int(masks[8]) & MASK64,
                int(masks[9]) & MASK64,
                int(masks[10]) & MASK64,
                int(masks[11]) & MASK64,
                int(masks[12]) & MASK64,
                int(masks[13]) & MASK64,
            )
        else:
            per_cycle[int(cycle)] = (
                (int(prev[0]) | int(masks[0])) & 0xFF,
                (int(prev[1]) | int(masks[1])) & 0xFF,
                (int(prev[2]) | int(masks[2])) & 0xFF,
                (int(prev[3]) | int(masks[3])) & 0xFF,
                (int(prev[4]) | int(masks[4])) & 0xFF,
                (int(prev[5]) | int(masks[5])) & 0xFF,
                (int(prev[6]) | int(masks[6])) & 0xFF,
                (int(prev[7]) | int(masks[7])) & MASK64,
                (int(prev[8]) | int(masks[8])) & MASK64,
                (int(prev[9]) | int(masks[9])) & MASK64,
                (int(prev[10]) | int(masks[10])) & MASK64,
                (int(prev[11]) | int(masks[11])) & MASK64,
                (int(prev[12]) | int(masks[12])) & MASK64,
                (int(prev[13]) | int(masks[13])) & MASK64,
            )

    l2_byte_key_count = int(len(byte_reads))
    if use_grouped_history_mode:
        grouped_byte_histories = _group_l2_byte_histories(byte_reads)
    else:
        grouped_byte_histories: Dict[
            Tuple[str, int, int],
            List[Tuple[L1DByteHistorySignature, int]],
        ] = defaultdict(list)
        for (line_key, _byte_off), per_cycle in byte_reads.items():
            signature = _normalize_l1d_byte_history_signature(per_cycle)
            if not signature:
                continue
            grouped_byte_histories[line_key].append((signature, 1))
    l2_byte_history_group_count = int(
        sum(len(rows) for rows in grouped_byte_histories.values())
    )
    l2_byte_history_group_reduction = (
        float(l2_byte_key_count) / float(l2_byte_history_group_count)
        if l2_byte_history_group_count > 0
        else 1.0
    )
    del byte_reads

    data_denominator = int(total_cycle_lines) * int(selected_l2_data_bit_domain_size)
    tag_denominator = int(total_cycle_lines) * int(selected_l2_tag_bit_domain_size)
    denominator = int(total_cycle_lines) * int(selected_l2_bit_domain_size)
    if denominator <= 0:
        raise ValueError("l2 denominator is zero")

    due_data_num = 0
    sdc_data_num = 0
    unknown_data_num = 0
    addr_denominator = 0
    due_addr_num = 0
    sdc_addr_num = 0
    unknown_addr_num = 0
    trace_policy_used_bits = 0
    trace_policy_used_mass = 0
    trace_policy_override_bits = 0
    trace_policy_override_mass = 0
    trace_policy_override_sdc_bits = 0
    trace_policy_override_due_bits = 0
    trace_policy_override_unknown_bits = 0
    trace_policy_override_masked_bits = 0
    trace_uncovered_unknown_bits = 0
    trace_uncovered_unknown_mass = 0
    trace_divergence_bits = 0
    trace_divergence_mass = 0
    due_source_mass: Dict[str, float] = defaultdict(float)
    boundary_events_count = 0
    boundary_events_mass = 0
    boundary_bits_mass_total = 0
    l2_segment_plan_cache: Dict[
        Tuple[Tuple[L1DByteCycleMasks, ...], int, bool, str],
        Tuple[CacheDataSegmentMetricRow, ...],
    ] = {}
    l2_segment_plan_requests = 0
    l2_segment_plan_hits = 0

    min_cycle = -10**30
    max_cycle = 10**30

    for line_key, history_groups in grouped_byte_histories.items():
        if not history_groups:
            continue
        first_valid_cycle = line_first_load_cycle.get(line_key)
        if first_valid_cycle is None:
            continue
        store_cycles = line_store_cycles_sorted.get(line_key, [])
        for history_signature, byte_multiplicity in history_groups:
            read_cycles = [int(rc) for rc, _masks in history_signature]
            if not read_cycles:
                continue
            group_multiplier = int(byte_multiplicity)

            prev_store = max(int(min_cycle), int(first_valid_cycle))
            for maybe_store in [*store_cycles, None]:
                seg_lo = int(prev_store)
                seg_hi = int(max_cycle if maybe_store is None else int(maybe_store))
                if seg_hi <= seg_lo:
                    prev_store = seg_hi
                    continue

                read_lo = bisect.bisect_left(read_cycles, seg_lo)
                if maybe_store is None:
                    read_hi = len(read_cycles)
                else:
                    read_hi = bisect.bisect_right(read_cycles, seg_hi)
                seg_rows = history_signature[read_lo:read_hi]
                if not seg_rows:
                    prev_store = seg_hi
                    continue

                if use_grouped_history_mode:
                    l2_segment_plan_requests += 1
                    seg_plan_key = (
                        _cache_history_masks_key(seg_rows),
                        int(selected_data_bits_mask),
                        bool(addr_domain_enabled),
                        str(trace_divergence_policy),
                    )
                    seg_metrics = l2_segment_plan_cache.get(seg_plan_key)
                    if seg_metrics is None:
                        seg_metrics = _build_cache_data_segment_metric_plan_from_masks(
                            seg_plan_key[0],
                            selected_data_bits_mask=int(selected_data_bits_mask),
                            addr_domain_enabled=bool(addr_domain_enabled),
                            trace_divergence_policy=str(trace_divergence_policy),
                        )
                        l2_segment_plan_cache[seg_plan_key] = seg_metrics
                    else:
                        l2_segment_plan_hits += 1
                else:
                    seg_metrics = _build_cache_data_segment_metric_plan(
                        seg_rows,
                        selected_data_bits_mask=int(selected_data_bits_mask),
                        addr_domain_enabled=bool(addr_domain_enabled),
                        trace_divergence_policy=str(trace_divergence_policy),
                        use_cache=False,
                    )

                interval_lo = seg_lo
                for idx, row in enumerate(seg_rows):
                    rc = int(row[0])
                    boundary_mass_here = range_sum(
                        cycles_sorted, cycle_prefix, int(rc), int(rc) + 1
                    )
                    if boundary_mass_here > 0:
                        boundary_events_count += int(group_multiplier)
                        boundary_events_mass += int(boundary_mass_here) * int(group_multiplier)
                        boundary_bits_mass_total += (
                            int(boundary_mass_here)
                            * int(selected_data_bits_count)
                            * int(group_multiplier)
                        )
                    boundary = int(rc) + 1 if ge_mode else int(rc)
                    interval_hi = min(seg_hi, boundary)
                    if interval_hi > interval_lo:
                        mass = range_sum(cycles_sorted, cycle_prefix, interval_lo, interval_hi)
                        if mass > 0:
                            weighted_mass = int(mass) * int(group_multiplier)
                            (
                                due_bits,
                                sdc_bits,
                                unknown_bits,
                                trace_uncovered_bits,
                                trace_policy_override_bits_here,
                                trace_policy_override_sdc_bits_here,
                                trace_policy_override_due_bits_here,
                                trace_policy_override_unknown_bits_here,
                                trace_policy_override_masked_bits_here,
                                semantic_due_bits,
                                base_due_bits,
                                trace_div_bits_here,
                                addr_bits_count,
                                addr_due_bits,
                                addr_sdc_bits,
                                addr_unknown_bits,
                                addr_oob_due_bits,
                                addr_alias_sdc_bits,
                                addr_trace_div_bits,
                            ) = seg_metrics[idx]
                            due_data_num += int(weighted_mass) * int(due_bits)
                            sdc_data_num += int(weighted_mass) * int(sdc_bits)
                            unknown_data_num += int(weighted_mass) * int(unknown_bits)
                            _add_source_mass(
                                due_source_mass,
                                "semantic_due",
                                float(int(weighted_mass) * int(semantic_due_bits)),
                            )
                            _add_source_mass(
                                due_source_mass,
                                "l2_base_due",
                                float(int(weighted_mass) * int(base_due_bits)),
                            )
                            if trace_div_bits_here > 0:
                                trace_divergence_bits += int(trace_div_bits_here) * int(
                                    group_multiplier
                                )
                                trace_divergence_mass += int(weighted_mass) * int(
                                    trace_div_bits_here
                                )
                                target_cls = _trace_divergence_target_class(
                                    trace_divergence_policy
                                )
                                _add_source_mass(
                                    due_source_mass,
                                    f"trace_divergence_{target_cls}",
                                    float(int(weighted_mass) * int(trace_div_bits_here)),
                                )
                            trace_policy_used_bits += int(trace_uncovered_bits) * int(
                                group_multiplier
                            )
                            trace_policy_used_mass += int(weighted_mass) * int(
                                trace_uncovered_bits
                            )
                            trace_policy_override_bits += int(
                                trace_policy_override_bits_here
                            ) * int(group_multiplier)
                            trace_policy_override_mass += int(weighted_mass) * int(
                                trace_policy_override_bits_here
                            )
                            trace_policy_override_sdc_bits += int(
                                trace_policy_override_sdc_bits_here
                            ) * int(group_multiplier)
                            trace_policy_override_due_bits += int(
                                trace_policy_override_due_bits_here
                            ) * int(group_multiplier)
                            trace_policy_override_unknown_bits += int(
                                trace_policy_override_unknown_bits_here
                            ) * int(group_multiplier)
                            trace_policy_override_masked_bits += int(
                                trace_policy_override_masked_bits_here
                            ) * int(group_multiplier)
                            if trace_uncovered_mode == "legacy_unknown":
                                trace_uncovered_unknown_bits += int(trace_uncovered_bits) * int(
                                    group_multiplier
                                )
                                trace_uncovered_unknown_mass += int(weighted_mass) * int(
                                    trace_uncovered_bits
                                )

                            if addr_domain_enabled:
                                due_addr_num += int(weighted_mass) * int(addr_due_bits)
                                sdc_addr_num += int(weighted_mass) * int(addr_sdc_bits)
                                unknown_addr_num += int(weighted_mass) * int(addr_unknown_bits)
                                _add_source_mass(
                                    due_source_mass,
                                    "addr_oob_due",
                                    float(int(weighted_mass) * int(addr_oob_due_bits)),
                                )
                                _add_source_mass(
                                    due_source_mass,
                                    "addr_alias_sdc",
                                    float(int(weighted_mass) * int(addr_alias_sdc_bits)),
                                )
                                if addr_trace_div_bits > 0:
                                    trace_divergence_bits += int(addr_trace_div_bits) * int(
                                        group_multiplier
                                    )
                                    trace_divergence_mass += int(weighted_mass) * int(
                                        addr_trace_div_bits
                                    )
                                addr_denominator += int(weighted_mass) * int(addr_bits_count)
                    interval_lo = interval_hi
                    if interval_lo >= seg_hi:
                        break
                prev_store = seg_hi

    if due_data_num + sdc_data_num + unknown_data_num > data_denominator:
        raise ValueError(
            "Internal accounting mismatch for l2 data domain: "
            f"sdc+due+unknown={due_data_num + sdc_data_num + unknown_data_num} "
            f"> data_denominator={data_denominator}"
        )

    masked_data_num = (
        int(data_denominator)
        - int(due_data_num)
        - int(sdc_data_num)
        - int(unknown_data_num)
    )
    tag_exact_info = _exact_l1d_tag_counts_global_readonly_alias(
        trace_template=trace_template,
        trace_path=Path(args.trace_template),
        fi_space=fi_space,
        l1d_sites=l2_sites,
        shader_prefix={0: (cycles_sorted, cycle_prefix, int(total_cycle_lines))},
        line_size_bytes=int(l2_line_size_bytes),
        size_bits=int(l2_size_bits),
        sample_tag_bits=int(l2_tag_bits),
        ge_mode=bool(ge_mode),
        addr_ranges=(addr_ranges if addr_ranges else None),
        cache_component="l2",
        scope_mode="l2",
        global_prefill=bool(global_prefill),
        trace_expanding_policy=trace_expanding_policy,
        trace_uncovered_mode=trace_uncovered_mode,
        trace_expanding_resolution_mode=trace_expanding_resolution_mode,
        trace_divergence_policy=trace_divergence_policy,
    )
    if tag_exact_info is not None:
        tag_counts = {
            "masked": int(tag_denominator)
            - int(tag_exact_info["counts"].get("sdc", 0))
            - int(tag_exact_info["counts"].get("due", 0))
            - int(tag_exact_info["counts"].get("unknown", 0)),
            "sdc": int(tag_exact_info["counts"].get("sdc", 0)),
            "due": int(tag_exact_info["counts"].get("due", 0)),
            "unknown": int(tag_exact_info["counts"].get("unknown", 0)),
        }
    else:
        tag_counts = _cache_tag_counts_from_data(
            tag_total=int(tag_denominator),
            data_masked=int(masked_data_num),
            data_sdc=int(sdc_data_num),
            data_due=int(due_data_num),
            data_unknown=int(unknown_data_num),
            policy=cache_tag_class_policy,
        )
    masked_tag_num = int(tag_counts.get("masked", 0))
    sdc_tag_num = int(tag_counts.get("sdc", 0))
    due_tag_num = int(tag_counts.get("due", 0))
    unknown_tag_num = int(tag_counts.get("unknown", 0))
    if (
        masked_tag_num + sdc_tag_num + due_tag_num + unknown_tag_num
        != int(tag_denominator)
    ):
        raise ValueError(
            "Internal accounting mismatch for l2 tag domain: "
            f"masked+sdc+due+unknown="
            f"{masked_tag_num + sdc_tag_num + due_tag_num + unknown_tag_num} "
            f"!= tag_denominator={tag_denominator}"
        )

    if not addr_domain_enabled:
        addr_denominator = 0
        due_addr_num = 0
        sdc_addr_num = 0
        unknown_addr_num = 0
    if (
        int(due_addr_num) + int(sdc_addr_num) + int(unknown_addr_num)
        > int(addr_denominator)
    ):
        raise ValueError(
            "Internal accounting mismatch for l2 addr domain: "
            f"sdc+due+unknown={int(due_addr_num) + int(sdc_addr_num) + int(unknown_addr_num)} "
            f"> addr_denominator={addr_denominator}"
        )
    masked_addr_num = (
        int(addr_denominator)
        - int(due_addr_num)
        - int(sdc_addr_num)
        - int(unknown_addr_num)
    )
    addr_bits_count_value = int(max(addr_bits_count_seen)) if addr_bits_count_seen else 0
    addr_effective_bits_value = _summarize_effective_bits(addr_effective_bits_seen)

    denominator_total = int(denominator) + int(addr_denominator)
    due_num = int(due_data_num) + int(due_tag_num) + int(due_addr_num)
    sdc_num = int(sdc_data_num) + int(sdc_tag_num) + int(sdc_addr_num)
    unknown_num = int(unknown_data_num) + int(unknown_tag_num) + int(unknown_addr_num)
    if due_num + sdc_num + unknown_num > denominator_total:
        raise ValueError(
            "Internal accounting mismatch for l2 total domain: "
            f"sdc+due+unknown={due_num + sdc_num + unknown_num} > denominator={denominator_total}"
        )
    masked_num = int(denominator_total) - int(due_num) - int(sdc_num) - int(unknown_num)
    rates = {
        "masked": (float(masked_num) / float(denominator_total)),
        "sdc": (float(sdc_num) / float(denominator_total)),
        "due": (float(due_num) / float(denominator_total)),
        "unknown": (float(unknown_num) / float(denominator_total)),
    }
    l2_summary = {
        "masked": int(masked_num),
        "sdc": int(sdc_num),
        "due": int(due_num),
        "unknown": int(unknown_num),
        "den": int(denominator_total),
        "rate": dict(rates),
        "by_domain": {
            "data": {
                "masked": int(masked_data_num),
                "sdc": int(sdc_data_num),
                "due": int(due_data_num),
                "unknown": int(unknown_data_num),
                "den": int(data_denominator),
            },
            "tag": {
                "masked": int(masked_tag_num),
                "sdc": int(sdc_tag_num),
                "due": int(due_tag_num),
                "unknown": int(unknown_tag_num),
                "den": int(tag_denominator),
                "policy": str(cache_tag_class_policy),
                "exact_mode": (
                    str(tag_exact_info.get("mode", ""))
                    if isinstance(tag_exact_info, dict)
                    else "policy_only"
                ),
            },
            "addr": {
                "masked": int(masked_addr_num),
                "sdc": int(sdc_addr_num),
                "due": int(due_addr_num),
                "unknown": int(unknown_addr_num),
                "den": int(addr_denominator),
                "policy": str(addr_fault_policy),
                "addr_due_mode": str(addr_due_mode),
            },
        },
    }

    return {
        "classification_counts": {
            "masked": int(masked_num),
            "sdc": int(sdc_num),
            "due": int(due_num),
            "unknown": int(unknown_num),
            "total": int(denominator_total),
        },
        "classification_rates": rates,
        "weighted_classification_counts": {
            "masked": fraction(masked_num, denominator_total),
            "sdc": fraction(sdc_num, denominator_total),
            "due": fraction(due_num, denominator_total),
            "unknown": fraction(unknown_num, denominator_total),
            "total": fraction(denominator_total, denominator_total),
        },
        "weighted_classification_rates": {
            "masked": fraction(masked_num, denominator_total),
            "sdc": fraction(sdc_num, denominator_total),
            "due": fraction(due_num, denominator_total),
            "unknown": fraction(unknown_num, denominator_total),
        },
        "summary": {
            "l2_cache": l2_summary,
        },
        "exact_meta": {
            "fault_component": "l2",
            "cycles_file": str(args.cycles),
            "active_threads_log": (
                str(args.active_threads_log) if args.active_threads_log is not None else None
            ),
            "trace_template": str(args.trace_template),
            "l2_size_bits": int(l2_size_bits),
            "l2_line_size_bytes": int(l2_line_size_bytes),
            "l2_tag_bits": int(l2_tag_bits),
            "l2_include_tag_bits": bool(include_tag_bits),
            "l2_global_prefill": bool(global_prefill),
            "l2_full_line_count": int(l2_full_line_count),
            "l2_tail_bits": int(l2_tail_bits),
            "l2_selected_bit_domain_size": int(selected_l2_bit_domain_size),
            "l2_selected_data_bit_domain_size": int(selected_l2_data_bit_domain_size),
            "l2_selected_tag_bit_domain_size": int(selected_l2_tag_bit_domain_size),
            "bit_count": int(bit_count),
            "datatype_bits": int(datatype_bits),
            "consumer_compare": str(args.consumer_compare),
            "trace_expanding_policy": str(trace_expanding_policy),
            "trace_expanding_resolution_mode": str(trace_expanding_resolution_mode),
            "trace_uncovered_mode": str(trace_uncovered_mode),
            "trace_divergence_policy": str(trace_divergence_policy),
            "addr_fault_policy": str(addr_fault_policy),
            "addr_due_mode": str(addr_due_mode),
            "addr_bits_mode": str(addr_bits_mode),
            "addr_bits_count": int(addr_bits_count_value),
            "addr_effective_bits": addr_effective_bits_value,
            "addr_effective_bits_max": (
                int(max(addr_effective_bits_seen)) if addr_effective_bits_seen else 0
            ),
            "cache_tag_class_policy": str(cache_tag_class_policy),
            "cache_tag_exact_mode": (
                str(tag_exact_info.get("mode", ""))
                if isinstance(tag_exact_info, dict)
                else "policy_only"
            ),
            "cache_tag_alias_ordered_pairs": (
                int(tag_exact_info.get("ordered_pairs", 0))
                if isinstance(tag_exact_info, dict)
                else 0
            ),
            "cache_tag_alias_intervals": (
                int(tag_exact_info.get("alias_intervals", tag_exact_info.get("replay_intervals", 0)))
                if isinstance(tag_exact_info, dict)
                else 0
            ),
            "cache_tag_fallback_reachable_intervals": (
                int(tag_exact_info.get("fallback_reachable_intervals", 0))
                if isinstance(tag_exact_info, dict)
                else 0
            ),
            "cache_tag_fallback_reason": (
                str(tag_exact_info.get("fallback_reason", ""))
                if isinstance(tag_exact_info, dict)
                else ""
            ),
            "cache_tag_self_miss_intervals": (
                int(tag_exact_info.get("self_miss_intervals", 0))
                if isinstance(tag_exact_info, dict)
                else 0
            ),
            "cache_tag_self_miss_sdc_bits": (
                int(tag_exact_info.get("self_miss_sdc", 0))
                if isinstance(tag_exact_info, dict)
                else 0
            ),
            "cache_tag_multievent_cycles": (
                int(tag_exact_info.get("multievent_cycles", 0))
                if isinstance(tag_exact_info, dict)
                else 0
            ),
            "cache_tag_multithread_cycles": (
                int(tag_exact_info.get("multithread_cycles", 0))
                if isinstance(tag_exact_info, dict)
                else 0
            ),
            "cache_tag_multievent_examples": (
                list(tag_exact_info.get("multievent_examples", []))
                if isinstance(tag_exact_info, dict)
                else []
            ),
            "cache_tag_examples": (
                list(tag_exact_info.get("examples", []))
                if isinstance(tag_exact_info, dict)
                else []
            ),
            "cache_tag_self_miss_examples": (
                list(tag_exact_info.get("self_miss_examples", []))
                if isinstance(tag_exact_info, dict)
                else []
            ),
            "trace_policy_used_bits": int(trace_policy_used_bits),
            "trace_policy_used_mass": int(trace_policy_used_mass),
            "trace_policy_override_bits": int(trace_policy_override_bits),
            "trace_policy_override_mass": int(trace_policy_override_mass),
            "trace_policy_override_reason_breakdown": {
                "sdc": int(trace_policy_override_sdc_bits),
                "due": int(trace_policy_override_due_bits),
                "unknown": int(trace_policy_override_unknown_bits),
                "masked": int(trace_policy_override_masked_bits),
            },
            "trace_uncovered_unknown_bits": int(trace_uncovered_unknown_bits),
            "trace_uncovered_unknown_mass": int(trace_uncovered_unknown_mass),
            "trace_divergence_bits": int(trace_divergence_bits),
            "trace_divergence_mass": int(trace_divergence_mass),
            "unknown_bits": int(unknown_num),
            "unknown_mass": int(unknown_num),
            "total_bits": int(denominator_total),
            "data_bits": int(data_denominator),
            "addr_domain_bits": int(addr_denominator),
            "tag_bits": int(tag_denominator),
            "masked_bits_data": int(masked_data_num),
            "sdc_bits_data": int(sdc_data_num),
            "due_bits_data": int(due_data_num),
            "unknown_bits_data": int(unknown_data_num),
            "addr_masked_bits": int(masked_addr_num),
            "addr_sdc_bits": int(sdc_addr_num),
            "addr_due_bits": int(due_addr_num),
            "addr_unknown_bits": int(unknown_addr_num),
            "masked_bits_tag": int(masked_tag_num),
            "sdc_bits_tag": int(sdc_tag_num),
            "due_bits_tag": int(due_tag_num),
            "unknown_bits_tag": int(unknown_tag_num),
            "due_source_bits": _mass_map_to_bits_map(due_source_mass),
            "due_mass_by_source": _normalize_mass_map(due_source_mass),
            **_boundary_meta_fields(
                consumer_compare=str(args.consumer_compare),
                same_cycle_effect_prob=same_cycle_effect_prob,
                boundary_events_count=int(boundary_events_count),
                boundary_events_mass=float(boundary_events_mass),
                boundary_bits_mass_total=float(boundary_bits_mass_total),
            ),
            "missing_active_thread_cycles": int(
                cycle_records_meta.get("missing_active_thread_cycles", 0)
            ),
            "missing_active_thread_cycle_ratio": float(
                cycle_records_meta.get("missing_active_thread_cycle_ratio", 0.0)
            ),
            "active_threads_carried_forward_cycles": int(
                cycle_records_meta.get("active_threads_carried_forward_cycles", 0)
            ),
            "active_threads_empty_fill_cycles": int(
                cycle_records_meta.get("active_threads_empty_fill_cycles", 0)
            ),
            "missing_active_threads_policy": str(
                cycle_records_meta.get("missing_active_threads_policy", "empty")
            ),
            "addr_valid_ranges_path": (
                str(args.addr_valid_ranges_path)
                if getattr(args, "addr_valid_ranges_path", None) is not None
                else None
            ),
            "addr_valid_range_count": int(len(addr_ranges)),
            "observed_l2_line_count": int(len(line_first_load_cycle)),
            "l2_byte_key_count": int(l2_byte_key_count),
            "l2_byte_history_group_count": int(l2_byte_history_group_count),
            "l2_byte_history_group_reduction": float(
                l2_byte_history_group_reduction
            ),
            "l2_group_mode": str(storage_group_mode),
            "l2_segment_plan_requests": int(l2_segment_plan_requests),
            "l2_segment_plan_hits": int(l2_segment_plan_hits),
            "l2_segment_plan_entries": int(len(l2_segment_plan_cache)),
            "l2_fault_site_count": int(len(l2_sites)),
            "l2_load_site_count": int(
                sum(
                    1
                    for rec in l2_sites
                    if str(_cache_site_row_field(rec, "site_kind", "")) == "l2_load"
                )
            ),
            "l2_store_site_count": int(
                sum(
                    1
                    for rec in l2_sites
                    if str(_cache_site_row_field(rec, "site_kind", "")) == "l2_store"
                )
            ),
            "semantic_error_reason_counts": dict(
                analyzer_exact_meta.get("semantic_error_reason_counts", {})
            ),
            "semantic_error_reasons_top20": list(
                analyzer_exact_meta.get("semantic_error_reasons_top20", [])
            ),
            "semantic_error_samples": list(
                analyzer_exact_meta.get("semantic_error_samples", [])
            ),
            "semantic_infra_error_count": int(
                analyzer_exact_meta.get("semantic_infra_error_count", 0)
            ),
            "semantic_infra_error_reason_counts": dict(
                analyzer_exact_meta.get("semantic_infra_error_reason_counts", {})
            ),
            "semantic_infra_error_reasons_top20": list(
                analyzer_exact_meta.get("semantic_infra_error_reasons_top20", [])
            ),
            "semantic_unknown_count": int(
                analyzer_exact_meta.get("semantic_unknown_count", 0)
            ),
            "semantic_unknown_reason_counts": dict(
                analyzer_exact_meta.get("semantic_unknown_reason_counts", {})
            ),
            "semantic_unknown_reasons_top20": list(
                analyzer_exact_meta.get("semantic_unknown_reasons_top20", [])
            ),
            "semantic_unknown_reason_details_top20": list(
                analyzer_exact_meta.get("semantic_unknown_reason_details_top20", [])
            ),
            "semantic_unknown_samples": list(
                analyzer_exact_meta.get("semantic_unknown_samples", [])
            ),
            "auto_range_created_count": int(
                analyzer_exact_meta.get("auto_range_created_count", 0)
            ),
            "auto_range_reason_counts": dict(
                analyzer_exact_meta.get("auto_range_reason_counts", {})
            ),
            "auto_range_samples_top20": list(
                analyzer_exact_meta.get("auto_range_samples_top20", [])
            ),
            "trace_load_init_event_count": int(
                analyzer_exact_meta.get("trace_load_init_event_count", 0)
            ),
            "trace_load_init_byte_count": int(
                analyzer_exact_meta.get("trace_load_init_byte_count", 0)
            ),
            "trace_load_init_samples_top20": list(
                analyzer_exact_meta.get("trace_load_init_samples_top20", [])
            ),
            "trace_bit_no_semantic_coverage_records": int(
                analyzer_exact_meta.get("trace_bit_no_semantic_coverage_records", 0)
            ),
            "trace_bit_no_semantic_coverage_bits": int(
                analyzer_exact_meta.get("trace_bit_no_semantic_coverage_bits", 0)
            ),
            "trace_bit_no_semantic_coverage_samples": list(
                analyzer_exact_meta.get("trace_bit_no_semantic_coverage_samples", [])
            ),
            "due_oracle_reason_counts": dict(
                analyzer_exact_meta.get("due_oracle_reason_counts", {})
            ),
            "due_oracle_reason_details_top20": list(
                analyzer_exact_meta.get("due_oracle_reason_details_top20", [])
            ),
            "output_oracle_type": str(
                analyzer_exact_meta.get("output_oracle_type", "")
            ),
            "output_oracle_has_output_spec": bool(
                analyzer_exact_meta.get("output_oracle_has_output_spec", False)
            ),
            "output_oracle_spec_entry_count": int(
                analyzer_exact_meta.get("output_oracle_spec_entry_count", 0)
            ),
            "output_oracle_spec_total_bytes": int(
                analyzer_exact_meta.get("output_oracle_spec_total_bytes", 0)
            ),
            "output_oracle_spec_ranges": list(
                analyzer_exact_meta.get("output_oracle_spec_ranges", [])
            ),
            "output_last_writer_store_count": int(
                analyzer_exact_meta.get("output_last_writer_store_count", 0)
            ),
            "output_total_store_count": int(
                analyzer_exact_meta.get("output_total_store_count", 0)
            ),
            "filtered_store_ratio": float(
                analyzer_exact_meta.get("filtered_store_ratio", 0.0)
            ),
            "addr_observed_seed_suppressed_bits": int(
                analyzer_exact_meta.get("addr_observed_seed_suppressed_bits", 0)
            ),
            "addr_observed_seed_suppressed_events": int(
                analyzer_exact_meta.get("addr_observed_seed_suppressed_events", 0)
            ),
            "tol_output_store_seed_count": int(
                analyzer_exact_meta.get("tol_output_store_seed_count", 0)
            ),
            "tol_float_backward_op_count": int(
                analyzer_exact_meta.get("tol_float_backward_op_count", 0)
            ),
            "tol_memory_forward_byte_count": int(
                analyzer_exact_meta.get("tol_memory_forward_byte_count", 0)
            ),
            "tol_fallback_count": int(
                analyzer_exact_meta.get("tol_fallback_count", 0)
            ),
        },
    }


def compute_exact_gmem(args: argparse.Namespace) -> Dict[str, Any]:
    normalize_trace_coverage = bool(getattr(args, "normalize_trace_coverage", False))
    storage_group_mode = _normalize_storage_group_mode(
        getattr(args, "storage_group_mode", "legacy")
    )
    use_grouped_history_mode = storage_group_mode == "grouped"
    analyzer = _load_analyzer_output_for_compute(
        args.analyzer_output,
        normalize_trace_coverage=normalize_trace_coverage,
    )
    analyzer_exact_meta_raw = analyzer.get("exact_meta", {})
    analyzer_exact_meta = (
        analyzer_exact_meta_raw if isinstance(analyzer_exact_meta_raw, dict) else {}
    )
    if args.trace_template is None:
        raise ValueError("--trace-template is required for fault-component gmem")
    trace_template = parse_trace_template(args.trace_template)
    l1d_sites = _load_filtered_cache_fault_sites_for_compute(
        "l1d",
        Path(args.analyzer_output),
        Path(args.trace_template),
        normalize_trace_coverage=normalize_trace_coverage,
    )

    cycle_records, cycle_records_meta = load_cycle_records_with_meta(
        args.cycles,
        args.active_threads_log,
        True,
        str(getattr(args, "missing_active_threads_policy", "empty")),
    )
    cycles_sorted, cycle_prefix, _total_cycle_lines = _cycle_prefix_from_records(cycle_records)
    if not cycles_sorted:
        raise ValueError("cycle multiplicity total is zero")

    trace_expanding_policy = str(args.trace_expanding_policy).strip().lower()
    if trace_expanding_policy != CANONICAL_TRACE_EXPANDING_POLICY:
        raise ValueError(
            "trace_expanding_policy must be one of {}; got {!r}".format(
                CANONICAL_TRACE_EXPANDING_POLICY,
                trace_expanding_policy,
            )
        )
    trace_uncovered_mode = _normalize_trace_uncovered_mode(
        getattr(args, "trace_uncovered_mode", "legacy_unknown")
    )
    trace_expanding_resolution_mode = str(
        getattr(args, "trace_expanding_resolution_mode", "legacy")
    ).strip().lower()
    if trace_expanding_resolution_mode != CANONICAL_TRACE_EXPANDING_RESOLUTION_MODE:
        raise ValueError(
            "trace_expanding_resolution_mode must be one of {}; got {!r}".format(
                CANONICAL_TRACE_EXPANDING_RESOLUTION_MODE,
                trace_expanding_resolution_mode,
            )
        )
    trace_divergence_policy = _normalize_trace_divergence_policy(
        getattr(args, "trace_divergence_policy", CANONICAL_TRACE_DIVERGENCE_POLICY)
    )
    ge_mode = str(args.consumer_compare).strip().lower() == "ge"
    same_cycle_effect_prob = _normalize_same_cycle_effect_prob(
        getattr(args, "same_cycle_effect_prob", None)
    )
    selected_data_bits_mask, selected_data_bits_count = _selected_byte_domain(
        getattr(args, "bits", None),
        8,
    )

    gmem_sites = [
        rec
        for rec in l1d_sites
        if canonical_space(_cache_site_row_field(rec, "mem_space")) == "global"
        and str(_cache_site_row_field(rec, "site_kind", "")) in ("l1d_load", "l1d_store")
    ]
    if not gmem_sites:
        raise ValueError("gmem requires global load/store fault sites in analyzer output")

    first_domain_cycle = int(cycles_sorted[0])
    max_cycle = int(cycles_sorted[-1]) + 1
    byte_store_cycles: Dict[int, Set[int]] = defaultdict(set)
    byte_first_load_cycle: Dict[int, int] = {}
    byte_first_store_cycle: Dict[int, int] = {}
    byte_cycle_masks: Dict[
        Tuple[int, int],
        Tuple[int, int, int, int, int, int, int, int, int, int, int, int, int, int],
    ] = {}

    for rec in gmem_sites:
        addr = int(_cache_site_row_field(rec, "addr", 0))
        cycle = int(_cache_site_row_field(rec, "cycle", -1))
        site_kind = str(_cache_site_row_field(rec, "site_kind", ""))
        if site_kind == "l1d_store":
            byte_store_cycles[int(addr)].add(int(cycle))
            prev_store = byte_first_store_cycle.get(int(addr))
            if prev_store is None or int(cycle) < int(prev_store):
                byte_first_store_cycle[int(addr)] = int(cycle)
        else:
            prev_load = byte_first_load_cycle.get(int(addr))
            if prev_load is None or int(cycle) < int(prev_load):
                byte_first_load_cycle[int(addr)] = int(cycle)

        (
            due_mask,
            sdc_mask,
            unknown_mask,
            trace_uncovered_mask,
            trace_policy_override_mask,
        ) = final_due_sdc_masks_for_site_extended(
            rec=rec,
            trace_expanding_policy=trace_expanding_policy,
            trace_uncovered_mode=trace_uncovered_mode,
            trace_expanding_resolution_mode=trace_expanding_resolution_mode,
        )
        trace_mask_this_site = (
            parse_mask(_cache_site_row_field(rec, "trace_expanding_mask_this_site", 0))
            & 0xFF
        )
        (
            due_mask,
            sdc_mask,
            unknown_mask,
            trace_div_mask_this_site,
        ) = _apply_trace_divergence_policy_to_masks(
            due_mask=int(due_mask),
            sdc_mask=int(sdc_mask),
            unknown_mask=int(unknown_mask),
            trace_mask=int(trace_mask_this_site),
            width_bits=8,
            policy=trace_divergence_policy,
        )
        due_mask &= 0xFF
        unknown_mask &= 0xFF
        due_mask &= (~unknown_mask) & 0xFF
        sdc_mask &= (~due_mask) & 0xFF
        sdc_mask &= (~unknown_mask) & 0xFF
        trace_uncovered_mask &= 0xFF
        trace_policy_override_mask &= 0xFF
        semantic_due_mask = (
            parse_mask(_cache_site_row_field(rec, "semantic_due_mask_this_site", 0)) & 0xFF
        )
        key = (int(addr), int(cycle))
        prev = byte_cycle_masks.get(key)
        if prev is None:
            byte_cycle_masks[key] = (
                int(due_mask),
                int(sdc_mask),
                int(unknown_mask),
                int(trace_uncovered_mask),
                int(trace_policy_override_mask),
                int(semantic_due_mask),
                int(trace_div_mask_this_site) & 0xFF,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            )
        else:
            byte_cycle_masks[key] = (
                (int(prev[0]) | int(due_mask)) & 0xFF,
                (int(prev[1]) | int(sdc_mask)) & 0xFF,
                (int(prev[2]) | int(unknown_mask)) & 0xFF,
                (int(prev[3]) | int(trace_uncovered_mask)) & 0xFF,
                (int(prev[4]) | int(trace_policy_override_mask)) & 0xFF,
                (int(prev[5]) | int(semantic_due_mask)) & 0xFF,
                (int(prev[6]) | int(trace_div_mask_this_site)) & 0xFF,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            )

    byte_histories: Dict[int, Dict[int, L1DByteCycleMasks]] = defaultdict(dict)
    for (addr, cycle), masks in byte_cycle_masks.items():
        per_cycle = byte_histories[int(addr)]
        prev = per_cycle.get(int(cycle))
        if prev is None:
            per_cycle[int(cycle)] = masks
        else:
            per_cycle[int(cycle)] = tuple(
                ((int(prev[idx]) | int(masks[idx])) & (0xFF if idx <= 6 else MASK64))
                for idx in range(len(masks))
            )  # type: ignore[assignment]

    grouped_histories: Dict[
        Tuple[int, Tuple[int, ...], L1DByteHistorySignature],
        int,
    ] = defaultdict(int)
    for addr, per_cycle in byte_histories.items():
        signature = _normalize_l1d_byte_history_signature(per_cycle)
        first_load = byte_first_load_cycle.get(int(addr))
        first_store = byte_first_store_cycle.get(int(addr))
        if first_store is None and first_load is None:
            continue
        if first_load is not None and (first_store is None or int(first_load) <= int(first_store)):
            first_valid_cycle = int(first_domain_cycle)
        else:
            first_valid_cycle = int(first_store)
        grouped_histories[
            (
                int(first_valid_cycle),
                tuple(sorted(int(v) for v in byte_store_cycles.get(int(addr), set()))),
                signature,
            )
        ] += 1

    if not grouped_histories:
        raise ValueError("gmem denominator is zero")

    denominator = 0
    due_data_num = 0
    sdc_data_num = 0
    unknown_data_num = 0
    trace_policy_used_bits = 0
    trace_policy_used_mass = 0
    trace_policy_override_bits = 0
    trace_policy_override_mass = 0
    trace_policy_override_sdc_bits = 0
    trace_policy_override_due_bits = 0
    trace_policy_override_unknown_bits = 0
    trace_policy_override_masked_bits = 0
    trace_uncovered_unknown_bits = 0
    trace_uncovered_unknown_mass = 0
    trace_divergence_bits = 0
    trace_divergence_mass = 0
    boundary_events_count = 0
    boundary_events_mass = 0
    boundary_bits_mass_total = 0
    due_source_mass: Dict[str, float] = defaultdict(float)

    gmem_segment_plan_cache: Dict[
        Tuple[Tuple[L1DByteCycleMasks, ...], int, bool, str],
        Tuple[CacheDataSegmentMetricRow, ...],
    ] = {}
    gmem_segment_plan_requests = 0
    gmem_segment_plan_hits = 0

    for (first_valid_cycle, store_cycles, history_signature), group_multiplier in grouped_histories.items():
        read_cycles = [int(rc) for rc, _masks in history_signature]
        prev_store = int(first_valid_cycle)
        for maybe_store in [*store_cycles, None]:
            seg_lo = int(prev_store)
            seg_hi = int(max_cycle if maybe_store is None else int(maybe_store))
            if seg_hi <= seg_lo:
                prev_store = seg_hi
                continue

            read_lo = bisect.bisect_left(read_cycles, seg_lo)
            if maybe_store is None:
                read_hi = len(read_cycles)
            else:
                read_hi = bisect.bisect_right(read_cycles, seg_hi)
            seg_rows = history_signature[read_lo:read_hi]
            seg_mass_total = range_sum(cycles_sorted, cycle_prefix, seg_lo, seg_hi)
            if seg_mass_total <= 0:
                prev_store = seg_hi
                continue
            denominator += int(seg_mass_total) * int(selected_data_bits_count) * int(group_multiplier)
            if not seg_rows:
                prev_store = seg_hi
                continue

            if use_grouped_history_mode:
                gmem_segment_plan_requests += 1
                seg_plan_key = (
                    _cache_history_masks_key(seg_rows),
                    int(selected_data_bits_mask),
                    False,
                    str(trace_divergence_policy),
                )
                seg_metrics = gmem_segment_plan_cache.get(seg_plan_key)
                if seg_metrics is None:
                    seg_metrics = _build_cache_data_segment_metric_plan_from_masks(
                        seg_plan_key[0],
                        selected_data_bits_mask=int(selected_data_bits_mask),
                        addr_domain_enabled=False,
                        trace_divergence_policy=str(trace_divergence_policy),
                    )
                    gmem_segment_plan_cache[seg_plan_key] = seg_metrics
                else:
                    gmem_segment_plan_hits += 1
            else:
                seg_metrics = _build_cache_data_segment_metric_plan(
                    seg_rows,
                    selected_data_bits_mask=int(selected_data_bits_mask),
                    addr_domain_enabled=False,
                    trace_divergence_policy=str(trace_divergence_policy),
                    use_cache=False,
                )

            interval_lo = seg_lo
            for idx, row in enumerate(seg_rows):
                rc = int(row[0])
                boundary_mass_here = range_sum(cycles_sorted, cycle_prefix, int(rc), int(rc) + 1)
                if boundary_mass_here > 0:
                    boundary_events_count += int(group_multiplier)
                    boundary_events_mass += int(boundary_mass_here) * int(group_multiplier)
                    boundary_bits_mass_total += (
                        int(boundary_mass_here)
                        * int(selected_data_bits_count)
                        * int(group_multiplier)
                    )
                boundary = int(rc) + 1 if ge_mode else int(rc)
                interval_hi = min(seg_hi, boundary)
                if interval_hi > interval_lo:
                    mass = range_sum(cycles_sorted, cycle_prefix, interval_lo, interval_hi)
                    if mass > 0:
                        weighted_mass = int(mass) * int(group_multiplier)
                        (
                            due_bits,
                            sdc_bits,
                            unknown_bits,
                            trace_uncovered_bits,
                            trace_policy_override_bits_here,
                            trace_policy_override_sdc_bits_here,
                            trace_policy_override_due_bits_here,
                            trace_policy_override_unknown_bits_here,
                            trace_policy_override_masked_bits_here,
                            semantic_due_bits,
                            base_due_bits,
                            trace_div_bits_here,
                            _addr_bits_count,
                            _addr_due_bits,
                            _addr_sdc_bits,
                            _addr_unknown_bits,
                            _addr_oob_due_bits,
                            _addr_alias_sdc_bits,
                            _addr_trace_div_bits,
                        ) = seg_metrics[idx]
                        due_data_num += int(weighted_mass) * int(due_bits)
                        sdc_data_num += int(weighted_mass) * int(sdc_bits)
                        unknown_data_num += int(weighted_mass) * int(unknown_bits)
                        _add_source_mass(
                            due_source_mass,
                            "semantic_due",
                            float(int(weighted_mass) * int(semantic_due_bits)),
                        )
                        _add_source_mass(
                            due_source_mass,
                            "l2_base_due",
                            float(int(weighted_mass) * int(base_due_bits)),
                        )
                        if trace_div_bits_here > 0:
                            trace_divergence_bits += int(trace_div_bits_here) * int(group_multiplier)
                            trace_divergence_mass += int(weighted_mass) * int(trace_div_bits_here)
                            target_cls = _trace_divergence_target_class(trace_divergence_policy)
                            _add_source_mass(
                                due_source_mass,
                                f"trace_divergence_{target_cls}",
                                float(int(weighted_mass) * int(trace_div_bits_here)),
                            )
                        trace_policy_used_bits += int(trace_uncovered_bits) * int(group_multiplier)
                        trace_policy_used_mass += int(weighted_mass) * int(trace_uncovered_bits)
                        trace_policy_override_bits += int(trace_policy_override_bits_here) * int(group_multiplier)
                        trace_policy_override_mass += int(weighted_mass) * int(trace_policy_override_bits_here)
                        trace_policy_override_sdc_bits += int(trace_policy_override_sdc_bits_here) * int(group_multiplier)
                        trace_policy_override_due_bits += int(trace_policy_override_due_bits_here) * int(group_multiplier)
                        trace_policy_override_unknown_bits += int(trace_policy_override_unknown_bits_here) * int(group_multiplier)
                        trace_policy_override_masked_bits += int(trace_policy_override_masked_bits_here) * int(group_multiplier)
                        if trace_uncovered_mode == "legacy_unknown":
                            trace_uncovered_unknown_bits += int(trace_uncovered_bits) * int(group_multiplier)
                            trace_uncovered_unknown_mass += int(weighted_mass) * int(trace_uncovered_bits)
                interval_lo = interval_hi
                if interval_lo >= seg_hi:
                    break
            prev_store = seg_hi

    if due_data_num + sdc_data_num + unknown_data_num > denominator:
        raise ValueError(
            "Internal accounting mismatch for gmem data domain: "
            f"sdc+due+unknown={due_data_num + sdc_data_num + unknown_data_num} > denominator={denominator}"
        )

    masked_num = int(denominator) - int(due_data_num) - int(sdc_data_num) - int(unknown_data_num)
    rates = {
        "masked": (float(masked_num) / float(denominator)),
        "sdc": (float(sdc_data_num) / float(denominator)),
        "due": (float(due_data_num) / float(denominator)),
        "unknown": (float(unknown_data_num) / float(denominator)),
    }
    gmem_summary = {
        "masked": int(masked_num),
        "sdc": int(sdc_data_num),
        "due": int(due_data_num),
        "unknown": int(unknown_data_num),
        "den": int(denominator),
        "rate": dict(rates),
    }

    output_ranges = _parse_output_spec_ranges(trace_template)
    output_spec_rows = trace_template.get("output_spec", [])
    output_spec_entry_count = len(output_spec_rows) if isinstance(output_spec_rows, list) else 0
    output_spec_total_bytes = int(
        sum(int(r.get("size", 0)) for r in output_ranges if isinstance(r, dict))
    )

    return {
        "classification_counts": {
            "masked": int(masked_num),
            "sdc": int(sdc_data_num),
            "due": int(due_data_num),
            "unknown": int(unknown_data_num),
            "total": int(denominator),
        },
        "classification_rates": rates,
        "weighted_classification_counts": {
            "masked": fraction(masked_num, denominator),
            "sdc": fraction(sdc_data_num, denominator),
            "due": fraction(due_data_num, denominator),
            "unknown": fraction(unknown_data_num, denominator),
            "total": fraction(denominator, denominator),
        },
        "weighted_classification_rates": {
            "masked": fraction(masked_num, denominator),
            "sdc": fraction(sdc_data_num, denominator),
            "due": fraction(due_data_num, denominator),
            "unknown": fraction(unknown_data_num, denominator),
        },
        "summary": {
            "gmem": gmem_summary,
        },
        "exact_meta": {
            "fault_component": "gmem",
            "cycles_file": str(args.cycles),
            "active_threads_log": (
                str(args.active_threads_log) if args.active_threads_log is not None else None
            ),
            "trace_template": str(args.trace_template),
            "bit_count": int(selected_data_bits_count),
            "datatype_bits": int(args.datatype_bits),
            "consumer_compare": str(args.consumer_compare),
            "trace_expanding_policy": str(trace_expanding_policy),
            "trace_expanding_resolution_mode": str(trace_expanding_resolution_mode),
            "trace_uncovered_mode": str(trace_uncovered_mode),
            "trace_divergence_policy": str(trace_divergence_policy),
            "addr_fault_policy": "not_applicable",
            "addr_due_mode": "not_applicable",
            "addr_bits_mode": "not_applicable",
            "addr_bits_count": 0,
            "addr_effective_bits": 0,
            "addr_effective_bits_max": 0,
            "trace_policy_used_bits": int(trace_policy_used_bits),
            "trace_policy_used_mass": int(trace_policy_used_mass),
            "trace_policy_override_bits": int(trace_policy_override_bits),
            "trace_policy_override_mass": int(trace_policy_override_mass),
            "trace_policy_override_reason_breakdown": {
                "sdc": int(trace_policy_override_sdc_bits),
                "due": int(trace_policy_override_due_bits),
                "unknown": int(trace_policy_override_unknown_bits),
                "masked": int(trace_policy_override_masked_bits),
            },
            "trace_uncovered_unknown_bits": int(trace_uncovered_unknown_bits),
            "trace_uncovered_unknown_mass": int(trace_uncovered_unknown_mass),
            "trace_divergence_bits": int(trace_divergence_bits),
            "trace_divergence_mass": int(trace_divergence_mass),
            "unknown_bits": int(unknown_data_num),
            "unknown_mass": int(unknown_data_num),
            "total_bits": int(denominator),
            "data_bits": int(denominator),
            "addr_domain_bits": 0,
            "tag_bits": 0,
            "masked_bits_data": int(masked_num),
            "sdc_bits_data": int(sdc_data_num),
            "due_bits_data": int(due_data_num),
            "unknown_bits_data": int(unknown_data_num),
            "masked_bits_tag": 0,
            "sdc_bits_tag": 0,
            "due_bits_tag": 0,
            "unknown_bits_tag": 0,
            "due_source_bits": _mass_map_to_bits_map(due_source_mass),
            "due_mass_by_source": _normalize_mass_map(due_source_mass),
            **_boundary_meta_fields(
                consumer_compare=str(args.consumer_compare),
                same_cycle_effect_prob=same_cycle_effect_prob,
                boundary_events_count=int(boundary_events_count),
                boundary_events_mass=float(boundary_events_mass),
                boundary_bits_mass_total=float(boundary_bits_mass_total),
            ),
            "missing_active_thread_cycles": int(
                cycle_records_meta.get("missing_active_thread_cycles", 0)
            ),
            "missing_active_thread_cycle_ratio": float(
                cycle_records_meta.get("missing_active_thread_cycle_ratio", 0.0)
            ),
            "active_threads_carried_forward_cycles": int(
                cycle_records_meta.get("active_threads_carried_forward_cycles", 0)
            ),
            "active_threads_empty_fill_cycles": int(
                cycle_records_meta.get("active_threads_empty_fill_cycles", 0)
            ),
            "missing_active_threads_policy": str(
                cycle_records_meta.get("missing_active_threads_policy", "empty")
            ),
            "gmem_byte_count": int(len(byte_histories)),
            "gmem_version_group_count": int(len(grouped_histories)),
            "gmem_group_mode": str(storage_group_mode),
            "gmem_segment_plan_requests": int(gmem_segment_plan_requests),
            "gmem_segment_plan_hits": int(gmem_segment_plan_hits),
            "gmem_segment_plan_entries": int(len(gmem_segment_plan_cache)),
            "gmem_fault_site_count": int(len(gmem_sites)),
            "gmem_load_site_count": int(
                sum(
                    1
                    for rec in gmem_sites
                    if str(_cache_site_row_field(rec, "site_kind", "")) == "l1d_load"
                )
            ),
            "gmem_store_site_count": int(
                sum(
                    1
                    for rec in gmem_sites
                    if str(_cache_site_row_field(rec, "site_kind", "")) == "l1d_store"
                )
            ),
            "output_oracle_type": str(analyzer_exact_meta.get("output_oracle_type", "")),
            "output_oracle_has_output_spec": bool(output_spec_entry_count > 0),
            "output_oracle_spec_entry_count": int(output_spec_entry_count),
            "output_oracle_spec_total_bytes": int(output_spec_total_bytes),
            "output_oracle_spec_ranges": list(output_ranges),
            "output_last_writer_store_count": int(
                analyzer_exact_meta.get("output_last_writer_store_count", 0)
            ),
            "output_total_store_count": int(
                analyzer_exact_meta.get("output_total_store_count", 0)
            ),
        },
    }


def _compute_exact_single(args: argparse.Namespace) -> Dict[str, Any]:
    fault_component = str(args.fault_component).strip().lower()
    if fault_component not in FAULT_COMPONENTS:
        raise ValueError(
            "fault_component must be one of {}; got {!r}".format(
                ", ".join(FAULT_COMPONENTS), fault_component
            )
        )
    if fault_component == "rf":
        return compute_exact_rf(args)
    if fault_component == "l1d":
        return compute_exact_l1d(args)
    if fault_component == "l2":
        return compute_exact_l2(args)
    if fault_component == "gmem":
        return compute_exact_gmem(args)
    return compute_exact_smem(args, fault_component)


def compute_exact(args: argparse.Namespace) -> Dict[str, Any]:
    _auto_enable_sampling_space_domain_switches(args)
    args.storage_group_mode = _normalize_storage_group_mode(
        getattr(args, "storage_group_mode", "legacy")
    )
    same_cycle_effect_prob = _normalize_same_cycle_effect_prob(
        getattr(args, "same_cycle_effect_prob", None)
    )
    if same_cycle_effect_prob is None:
        return _compute_exact_single(args)

    gt_args = _clone_args_with(
        args,
        consumer_compare="gt",
        same_cycle_effect_prob=None,
    )
    ge_args = _clone_args_with(
        args,
        consumer_compare="ge",
        same_cycle_effect_prob=None,
    )
    out_gt = _compute_exact_single(gt_args)
    out_ge = _compute_exact_single(ge_args)

    counts_gt = _extract_counts_float(out_gt)
    counts_ge = _extract_counts_float(out_ge)
    den_gt = float(counts_gt.get("total", 0.0))
    den_ge = float(counts_ge.get("total", 0.0))
    if abs(den_gt - den_ge) > 1e-9:
        raise ValueError(
            "same-cycle blending requires gt/ge denominator match; "
            f"got gt={den_gt}, ge={den_ge}"
        )

    blended_counts: Dict[str, float] = {}
    for key in ("masked", "sdc", "due", "unknown"):
        blended_counts[key] = (
            (1.0 - float(same_cycle_effect_prob)) * float(counts_gt.get(key, 0.0))
            + float(same_cycle_effect_prob) * float(counts_ge.get(key, 0.0))
        )
    blended_counts["total"] = float(den_gt)

    blended_rates = _counts_to_rate_map(blended_counts)

    denominator_int = int(round(float(blended_counts["total"])))
    if denominator_int < 0:
        denominator_int = 0
    den_for_fraction = denominator_int if denominator_int > 0 else 1

    meta_gt_raw = out_gt.get("exact_meta", {})
    meta_gt = meta_gt_raw if isinstance(meta_gt_raw, dict) else {}
    meta_ge_raw = out_ge.get("exact_meta", {})
    meta_ge = meta_ge_raw if isinstance(meta_ge_raw, dict) else {}
    meta_blended_raw = _blend_numeric_struct(meta_gt, meta_ge, float(same_cycle_effect_prob))
    meta_blended = meta_blended_raw if isinstance(meta_blended_raw, dict) else {}

    boundary_events_count = int(
        meta_gt.get("boundary_events_count", meta_ge.get("boundary_events_count", 0))
    )
    boundary_events_mass = _to_float_num(
        meta_gt.get("boundary_events_mass", meta_ge.get("boundary_events_mass", 0.0))
    )
    boundary_bits_mass_total = _to_float_num(
        meta_gt.get("boundary_bits_mass_total", meta_ge.get("boundary_bits_mass_total", 0.0))
    )
    if boundary_bits_mass_total <= 0.0 and boundary_events_mass > 0.0:
        bit_count_hint = _to_float_num(meta_gt.get("bit_count", meta_ge.get("bit_count", 0.0)))
        if bit_count_hint > 0.0:
            boundary_bits_mass_total = float(boundary_events_mass) * float(bit_count_hint)

    if not isinstance(meta_blended.get("fault_component"), str):
        meta_blended["fault_component"] = str(getattr(args, "fault_component", ""))
    meta_blended["consumer_compare"] = str(args.consumer_compare)
    meta_blended["same_cycle_effect_prob"] = _normalize_numeric(float(same_cycle_effect_prob))
    meta_blended["same_cycle_effect_prob_mode"] = "blended_gt_ge"
    meta_blended["classification_counts_gt"] = {
        "masked": _normalize_count_num(float(counts_gt["masked"])),
        "sdc": _normalize_count_num(float(counts_gt["sdc"])),
        "due": _normalize_count_num(float(counts_gt["due"])),
        "unknown": _normalize_count_num(float(counts_gt["unknown"])),
        "total": _normalize_count_num(float(counts_gt["total"])),
    }
    meta_blended["classification_counts_ge"] = {
        "masked": _normalize_count_num(float(counts_ge["masked"])),
        "sdc": _normalize_count_num(float(counts_ge["sdc"])),
        "due": _normalize_count_num(float(counts_ge["due"])),
        "unknown": _normalize_count_num(float(counts_ge["unknown"])),
        "total": _normalize_count_num(float(counts_ge["total"])),
    }
    meta_blended["classification_counts_blended_raw"] = {
        "masked": _normalize_count_num(float(blended_counts["masked"])),
        "sdc": _normalize_count_num(float(blended_counts["sdc"])),
        "due": _normalize_count_num(float(blended_counts["due"])),
        "unknown": _normalize_count_num(float(blended_counts["unknown"])),
        "total": _normalize_count_num(float(blended_counts["total"])),
    }
    meta_blended["rate_gt"] = _counts_to_rate_map(counts_gt)
    meta_blended["rate_ge"] = _counts_to_rate_map(counts_ge)
    meta_blended["rate_blended"] = dict(blended_rates)
    meta_blended["boundary_events_count"] = int(boundary_events_count)
    meta_blended["boundary_events_mass"] = _normalize_numeric(float(boundary_events_mass))
    meta_blended["boundary_events_mass_affected"] = _normalize_numeric(
        float(boundary_events_mass) * float(same_cycle_effect_prob)
    )
    meta_blended["boundary_events_mass_unaffected"] = _normalize_numeric(
        float(boundary_events_mass) * (1.0 - float(same_cycle_effect_prob))
    )
    meta_blended["boundary_bits_mass_total"] = _normalize_numeric(
        float(boundary_bits_mass_total)
    )
    meta_blended["boundary_bits_mass_affected"] = _normalize_numeric(
        float(boundary_bits_mass_total) * float(same_cycle_effect_prob)
    )
    meta_blended["boundary_bits_mass_unaffected"] = _normalize_numeric(
        float(boundary_bits_mass_total) * (1.0 - float(same_cycle_effect_prob))
    )
    meta_blended.setdefault("boundary_events_count_unit", "event_instances")
    meta_blended.setdefault("boundary_events_mass_unit", "weighted_injection_mass")
    meta_blended.setdefault(
        "boundary_events_mass_note",
        (
            "boundary_events_count is the number of inject_cycle==read_cycle event "
            "instances; boundary_events_mass is the weighted injection mass of those "
            "instances before bit-width expansion."
        ),
    )

    out_blended = dict(out_gt)
    out_blended["classification_counts"] = {
        "masked": _normalize_count_num(float(blended_counts["masked"])),
        "sdc": _normalize_count_num(float(blended_counts["sdc"])),
        "due": _normalize_count_num(float(blended_counts["due"])),
        "unknown": _normalize_count_num(float(blended_counts["unknown"])),
        "total": _normalize_count_num(float(blended_counts["total"])),
    }
    out_blended["classification_rates"] = dict(blended_rates)
    out_blended["weighted_classification_counts"] = {
        "masked": fraction(float(blended_counts["masked"]), den_for_fraction),
        "sdc": fraction(float(blended_counts["sdc"]), den_for_fraction),
        "due": fraction(float(blended_counts["due"]), den_for_fraction),
        "unknown": fraction(float(blended_counts["unknown"]), den_for_fraction),
        "total": fraction(float(blended_counts["total"]), den_for_fraction),
    }
    out_blended["weighted_classification_rates"] = {
        "masked": fraction(float(blended_counts["masked"]), den_for_fraction),
        "sdc": fraction(float(blended_counts["sdc"]), den_for_fraction),
        "due": fraction(float(blended_counts["due"]), den_for_fraction),
        "unknown": fraction(float(blended_counts["unknown"]), den_for_fraction),
    }
    summary_gt = out_gt.get("summary", {})
    summary_ge = out_ge.get("summary", {})
    if isinstance(summary_gt, dict) and isinstance(summary_ge, dict):
        out_blended["summary"] = _blend_numeric_struct(
            summary_gt,
            summary_ge,
            float(same_cycle_effect_prob),
        )
    elif isinstance(summary_gt, dict):
        out_blended["summary"] = dict(summary_gt)
    elif isinstance(summary_ge, dict):
        out_blended["summary"] = dict(summary_ge)
    out_blended["exact_meta"] = meta_blended
    return out_blended


def _to_float_num(value: Any) -> float:
    try:
        return float(value)
    except Exception:
        return 0.0


def _normalize_count_num(value: float) -> Any:
    if math.isfinite(value) and abs(value - round(value)) <= 1e-9:
        return int(round(value))
    return float(value)


def _safe_env_bool_01(name: str, default: int) -> int:
    raw = str(os.environ.get(name, str(default))).strip()
    if raw in ("0", "1"):
        return int(raw)
    return int(default)


def _safe_env_optional_float_01(name: str) -> Optional[float]:
    raw = str(os.environ.get(name, "")).strip()
    if raw == "":
        return None
    try:
        value = float(raw)
    except Exception:
        raise ValueError(
            "{} must be a float in [0,1] or empty; got {!r}".format(name, raw)
        )
    if not math.isfinite(value) or value < 0.0 or value > 1.0:
        raise ValueError(
            "{} must be in [0,1] or empty; got {!r}".format(name, raw)
        )
    return float(value)


def _safe_env_float_01(name: str, default: float) -> float:
    raw = str(os.environ.get(name, str(default))).strip()
    try:
        value = float(raw)
    except Exception:
        return float(default)
    if not math.isfinite(value) or value < 0.0 or value > 1.0:
        return float(default)
    return float(value)


def _cli_option_present(argv: Sequence[str], option: str) -> bool:
    for tok in argv:
        tok_s = str(tok).strip()
        if tok_s == str(option) or tok_s.startswith(str(option) + "="):
            return True
    return False


def reject_removed_exact_semantic_overrides(
    argv: Optional[Sequence[str]] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> None:
    argv_seq = list(sys.argv[1:] if argv is None else argv)
    env_map = dict(os.environ if environ is None else environ)
    used_options = [opt for opt in REMOVED_SEMANTIC_OPTIONS if _cli_option_present(argv_seq, opt)]
    used_env = [name for name in REMOVED_SEMANTIC_ENV_VARS if str(name) in env_map]
    if not used_options and not used_env:
        return
    lines = [
        "removed exact semantic overrides detected; unified exact semantics are now fixed.",
        f"exact_semantics_profile={EXACT_SEMANTICS_PROFILE}",
    ]
    if used_options:
        lines.append("deprecated CLI options: {}".format(", ".join(sorted(used_options))))
    if used_env:
        lines.append("deprecated environment vars: {}".format(", ".join(sorted(used_env))))
    lines.append(
        "Exact now preserves unresolved mass as unknown and no longer accepts policy/strict/folding switches."
    )
    raise SystemExit("\n".join(lines))


def apply_canonical_exact_semantics(args: argparse.Namespace) -> argparse.Namespace:
    args.allow_missing_active_threads = False
    args.missing_active_threads_policy = "empty"
    args.consumer_compare = CANONICAL_CONSUMER_COMPARE
    args.same_cycle_effect_prob = None
    args.rf_fault_model = CANONICAL_RF_FAULT_MODEL
    args.trace_expanding_policy = CANONICAL_TRACE_EXPANDING_POLICY
    args.trace_expanding_resolution_mode = (
        CANONICAL_TRACE_EXPANDING_RESOLUTION_MODE
    )
    args.trace_uncovered_mode = CANONICAL_TRACE_UNCOVERED_MODE
    args.trace_divergence_policy = CANONICAL_TRACE_DIVERGENCE_POLICY
    args.addr_fault_policy = CANONICAL_ADDR_FAULT_POLICY
    args.addr_due_mode = CANONICAL_ADDR_DUE_MODE
    args.addr_bits = CANONICAL_ADDR_BITS
    args.cache_tag_class_policy = CANONICAL_CACHE_TAG_CLASS_POLICY
    args.strict_replacement = 0
    args.strict_replacement_hard = 0
    args.unknown_policy = "preserve_unknown"
    args.use_sampling_space_domain = CANONICAL_USE_SAMPLING_SPACE_DOMAIN
    args.use_sampling_space_domain_rf = 0
    args.use_sampling_space_domain_smem = 0
    args.metadata_fault_policy = CANONICAL_METADATA_FAULT_POLICY
    args.smem_domain_policy = CANONICAL_SMEM_DOMAIN_POLICY
    args.rf_domain_policy = CANONICAL_RF_DOMAIN_POLICY
    args.smem_error_propagation_model = CANONICAL_SMEM_ERROR_PROPAGATION_MODEL
    args.smem_addr_exception_policy = CANONICAL_SMEM_ADDR_EXCEPTION_POLICY
    args.rf_addr_reg_policy = CANONICAL_RF_ADDR_REG_POLICY
    args.normalize_trace_coverage = True
    args.exact_semantics_profile = EXACT_SEMANTICS_PROFILE
    return args


def _auto_enable_sampling_space_domain_switches(args: argparse.Namespace) -> Dict[str, bool]:
    forced_rf = False
    forced_smem = False
    fault_component = str(getattr(args, "fault_component", "")).strip().lower()
    use_global = bool(int(getattr(args, "use_sampling_space_domain", 0)))

    rf_policy = _normalize_rf_domain_policy(
        getattr(args, "rf_domain_policy", "sampling_space")
    )
    if (
        fault_component == "rf"
        and
        rf_policy == "sampling_space"
        and not use_global
        and not bool(int(getattr(args, "use_sampling_space_domain_rf", 0)))
    ):
        setattr(args, "use_sampling_space_domain_rf", 1)
        forced_rf = True
        print(
            "WARNING: RF_DOMAIN_POLICY=sampling_space but "
            "USE_SAMPLING_SPACE_DOMAIN_RF=0; auto-enabling "
            "USE_SAMPLING_SPACE_DOMAIN_RF=1.",
            file=sys.stderr,
        )

    smem_policy = _normalize_smem_domain_policy(
        getattr(args, "smem_domain_policy", "sampling_space")
    )
    if (
        fault_component in ("smem_rf", "smem_lds")
        and
        smem_policy == "sampling_space"
        and not use_global
        and not bool(int(getattr(args, "use_sampling_space_domain_smem", 0)))
    ):
        setattr(args, "use_sampling_space_domain_smem", 1)
        forced_smem = True
        print(
            "WARNING: SMEM_DOMAIN_POLICY=sampling_space but "
            "USE_SAMPLING_SPACE_DOMAIN_SMEM=0; auto-enabling "
            "USE_SAMPLING_SPACE_DOMAIN_SMEM=1.",
            file=sys.stderr,
        )

    setattr(args, "_auto_enabled_sampling_space_domain_rf", bool(forced_rf))
    setattr(args, "_auto_enabled_sampling_space_domain_smem", bool(forced_smem))
    return {"rf": bool(forced_rf), "smem": bool(forced_smem)}


def _collect_unknown_reason_counts(meta: Dict[str, Any], unknown_raw: float) -> Dict[str, int]:
    if float(unknown_raw) <= 0.0:
        # Keep reason map empty when unknown classification mass is zero.
        return {}
    out: Counter = Counter()
    semantic_unknown = meta.get("semantic_unknown_reason_counts", {})
    if isinstance(semantic_unknown, dict):
        for k, v in semantic_unknown.items():
            key = str(k).strip() or "unknown"
            try:
                out[key] += int(v)
            except Exception:
                continue
    trace_policy_used_bits = int(meta.get("trace_policy_used_bits", 0))
    trace_mode = _normalize_trace_uncovered_mode(meta.get("trace_uncovered_mode", "legacy_unknown"))
    if trace_policy_used_bits > 0 and trace_mode == "legacy_unknown":
        out["trace_policy_fallback"] += int(trace_policy_used_bits)
    if not out and unknown_raw > 0:
        out["unknown"] += int(round(unknown_raw))
    return {k: int(v) for k, v in sorted(out.items())}


def _sum_int_dict(raw: Any) -> int:
    if not isinstance(raw, dict):
        return 0
    total = 0
    for v in raw.values():
        try:
            total += int(v)
        except Exception:
            continue
    return int(total)


def _unknown_source_breakdown(meta: Dict[str, Any], unknown_raw: float) -> Tuple[Dict[str, int], Dict[str, Any], str]:
    trace_mode = _normalize_trace_uncovered_mode(meta.get("trace_uncovered_mode", "legacy_unknown"))
    semantic_error_bits = int(_sum_int_dict(meta.get("semantic_error_reason_counts", {})))
    semantic_unknown_bits = int(meta.get("semantic_unknown_count", 0))
    infra_error_bits = int(meta.get("semantic_infra_error_count", 0))
    trace_uncovered_bits = int(meta.get("trace_uncovered_unknown_bits", 0))
    if trace_uncovered_bits <= 0 and trace_mode == "legacy_unknown":
        # Legacy behavior classified uncovered-trace bits as UNKNOWN.
        trace_uncovered_bits = int(meta.get("trace_policy_used_bits", 0))

    bits_map = {
        "semantic_error": max(0, int(semantic_error_bits)),
        "semantic_unknown": max(0, int(semantic_unknown_bits)),
        "infra_error": max(0, int(infra_error_bits)),
        "trace_uncovered": max(0, int(trace_uncovered_bits)),
    }
    total_bits = int(sum(bits_map.values()))
    if float(unknown_raw) <= 0.0:
        return bits_map, {k: 0 for k in bits_map.keys()}, "zero_unknown_mass"

    if total_bits <= 0:
        return bits_map, {
            "semantic_error": 0,
            "semantic_unknown": 0,
            "infra_error": 0,
            "trace_uncovered": 0,
            "other": _normalize_count_num(float(unknown_raw)),
        }, "fallback_other"

    mass_map: Dict[str, Any] = {}
    acc = 0.0
    keys = list(bits_map.keys())
    for k in keys[:-1]:
        frac = float(bits_map[k]) / float(total_bits)
        m = float(unknown_raw) * float(frac)
        mass_map[k] = _normalize_count_num(m)
        acc += float(mass_map[k]) if isinstance(mass_map[k], float) else float(int(mass_map[k]))
    last_k = keys[-1]
    rem = float(unknown_raw) - float(acc)
    if rem < 0 and abs(rem) <= 1e-9:
        rem = 0.0
    mass_map[last_k] = _normalize_count_num(rem)
    return bits_map, mass_map, "proportional_by_source_bits"


def _update_summary_unknown_policy(
    summary: Any,
    *,
    strict_enabled: bool,
    unknown_policy: str,
) -> None:
    if not isinstance(summary, dict):
        return

    if "den" in summary and "rate" in summary:
        total = float(summary.get("den", 0))
        masked_v = _to_float_num(summary.get("masked", 0))
        sdc_v = _to_float_num(summary.get("sdc", 0))
        due_v = _to_float_num(summary.get("due", 0))
        unknown_v = _to_float_num(summary.get("unknown", 0))
        summary["masked"] = _normalize_count_num(masked_v)
        summary["sdc"] = _normalize_count_num(sdc_v)
        summary["due"] = _normalize_count_num(due_v)
        summary["unknown"] = _normalize_count_num(unknown_v)
        if total > 0:
            summary["rate"] = {
                "masked": float(masked_v / total),
                "sdc": float(sdc_v / total),
                "due": float(due_v / total),
                "unknown": float(unknown_v / total),
            }
        else:
            summary["rate"] = {"masked": 0.0, "sdc": 0.0, "due": 0.0, "unknown": 0.0}
        return

    for v in summary.values():
        if isinstance(v, dict):
            _update_summary_unknown_policy(
                v,
                strict_enabled=strict_enabled,
                unknown_policy=unknown_policy,
            )


def _extract_missing_memory_samples(samples: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    patt = re.compile(
        r"space=([^,\s]+).*?addr=0x([0-9a-fA-F]+).*?pc=([^,\s]+).*?missing_addrs=\[([^\]]*)\]"
    )
    for row in samples:
        if not isinstance(row, dict):
            continue
        reason = str(row.get("reason", "")).strip().lower()
        etype = str(
            row.get("faulted_error_type")
            or row.get("golden_error_type")
            or row.get("error_type")
            or ""
        ).strip().lower()
        if reason not in ("missing_bytes", "uninitialized_load") and etype not in (
            "missingbytes",
            "uninitializedload",
        ):
            continue
        msg = str(
            row.get("message")
            or row.get("faulted_error")
            or row.get("golden_error")
            or ""
        )
        m = patt.search(msg)
        if m is None:
            continue
        missing_raw = [tok.strip() for tok in str(m.group(4)).split(",") if tok.strip()]
        out.append(
            {
                "space": str(m.group(1)),
                "addr": f"0x{int(m.group(2), 16):016x}",
                "pc": str(m.group(3)),
                "missing_addrs": missing_raw[:8],
            }
        )
        if len(out) >= 20:
            break
    return out


def _extract_unsupported_opcode_samples(samples: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for row in samples:
        if not isinstance(row, dict):
            continue
        msg = str(
            row.get("message")
            or row.get("faulted_error")
            or row.get("golden_error")
            or ""
        ).lower()
        etype = str(
            row.get("faulted_error_type")
            or row.get("golden_error_type")
            or row.get("error_type")
            or ""
        )
        if "unsupported opcode" not in msg and str(etype) != "NotImplementedError":
            continue
        out.append(
            {
                "event_index": row.get("event_index"),
                "thread_id": row.get("thread_id"),
                "pc": row.get("pc"),
                "opcode": row.get("opcode"),
                "error_type": etype,
                "message": row.get("message") or row.get("faulted_error") or row.get("golden_error"),
            }
        )
        if len(out) >= 20:
            break
    return out


def _summary_component_ref(summary: Any, fault_component: str) -> Optional[Dict[str, Any]]:
    if not isinstance(summary, dict):
        return None
    fc = str(fault_component).strip().lower()
    if fc == "l1d":
        row = summary.get("l1d_cache")
        return row if isinstance(row, dict) else None
    if fc == "l2":
        row = summary.get("l2_cache")
        return row if isinstance(row, dict) else None
    if fc in ("smem_rf", "smem_lds"):
        shared = summary.get("shared_memory")
        if not isinstance(shared, dict):
            return None
        row = shared.get(fc)
        return row if isinstance(row, dict) else None
    return None


def _write_counts_to_summary_row(
    row: Dict[str, Any],
    *,
    masked: float,
    sdc: float,
    due: float,
    unknown: float,
    den: int,
) -> None:
    den_i = int(max(0, den))
    row["masked"] = _normalize_count_num(float(masked))
    row["sdc"] = _normalize_count_num(float(sdc))
    row["due"] = _normalize_count_num(float(due))
    row["unknown"] = _normalize_count_num(float(unknown))
    row["den"] = int(den_i)
    if den_i > 0:
        row["rate"] = {
            "masked": float(masked) / float(den_i),
            "sdc": float(sdc) / float(den_i),
            "due": float(due) / float(den_i),
            "unknown": float(unknown) / float(den_i),
        }
    else:
        row["rate"] = {"masked": 0.0, "sdc": 0.0, "due": 0.0, "unknown": 0.0}


def _set_output_counts(
    out: Dict[str, Any],
    *,
    masked: float,
    sdc: float,
    due: float,
    unknown: float,
    total: int,
) -> None:
    total_i = int(max(0, total))
    if total_i <= 0:
        out["classification_counts"] = {
            "masked": 0,
            "sdc": 0,
            "due": 0,
            "unknown": 0,
            "total": 0,
        }
        out["classification_rates"] = {"masked": 0.0, "sdc": 0.0, "due": 0.0, "unknown": 0.0}
        out["weighted_classification_counts"] = {
            "masked": fraction(0.0, 1),
            "sdc": fraction(0.0, 1),
            "due": fraction(0.0, 1),
            "unknown": fraction(0.0, 1),
            "total": fraction(0.0, 1),
        }
        out["weighted_classification_rates"] = {
            "masked": fraction(0.0, 1),
            "sdc": fraction(0.0, 1),
            "due": fraction(0.0, 1),
            "unknown": fraction(0.0, 1),
        }
        return

    masked_f = float(masked)
    sdc_f = float(sdc)
    due_f = float(due)
    unknown_f = float(unknown)
    risk_mass = float(sdc_f + due_f + unknown_f)
    if risk_mass > float(total_i) + 1e-9:
        raise ValueError(
            "Cannot write classification counts: SDC+DUE+Unknown exceeds "
            "the FI-aligned denominator; refusing proportional count scaling "
            f"(risk_mass={risk_mass}, total={total_i})."
        )
    assigned = masked_f + sdc_f + due_f + unknown_f
    if abs(assigned - float(total_i)) > 1e-9:
        masked_f += float(total_i) - float(assigned)
    if masked_f < 0.0 and abs(masked_f) <= 1e-9:
        masked_f = 0.0

    out["classification_counts"] = {
        "masked": _normalize_count_num(masked_f),
        "sdc": _normalize_count_num(sdc_f),
        "due": _normalize_count_num(due_f),
        "unknown": _normalize_count_num(unknown_f),
        "total": int(total_i),
    }
    out["classification_rates"] = {
        "masked": float(masked_f) / float(total_i),
        "sdc": float(sdc_f) / float(total_i),
        "due": float(due_f) / float(total_i),
        "unknown": float(unknown_f) / float(total_i),
    }
    out["weighted_classification_counts"] = {
        "masked": fraction(masked_f, total_i),
        "sdc": fraction(sdc_f, total_i),
        "due": fraction(due_f, total_i),
        "unknown": fraction(unknown_f, total_i),
        "total": fraction(float(total_i), total_i),
    }
    out["weighted_classification_rates"] = {
        "masked": fraction(masked_f, total_i),
        "sdc": fraction(sdc_f, total_i),
        "due": fraction(due_f, total_i),
        "unknown": fraction(unknown_f, total_i),
    }


def _selected_byte_domain(
    bits_spec: Optional[str],
    default_max_bit: int = 8,
) -> Tuple[int, int]:
    bits = parse_spec_list(bits_spec)
    if bits is None:
        bits_1based = list(range(1, int(default_max_bit) + 1))
    else:
        bits_1based = sorted({int(b) for b in bits if 1 <= int(b) <= int(default_max_bit)})
        if not bits_1based:
            bits_1based = list(range(1, int(default_max_bit) + 1))
    mask = 0
    for b in bits_1based:
        mask |= 1 << (int(b) - 1)
    return int(mask), int(len(bits_1based))


def _metadata_policy_counts(metadata_bits: int, policy: str) -> Dict[str, int]:
    total = max(0, int(metadata_bits))
    pol = _normalize_metadata_fault_policy(policy)
    out = {"masked": 0, "sdc": 0, "due": 0, "unknown": 0}
    if total <= 0:
        return out
    if pol == "sdc":
        out["sdc"] = int(total)
    elif pol == "due":
        out["due"] = int(total)
    elif pol == "unknown":
        out["unknown"] = int(total)
    else:
        out["masked"] = int(total)
    return out


def _first_positive_int(values: Sequence[Any], default: int = 0) -> int:
    for raw in values:
        v = _safe_int(raw, 0)
        if v > 0:
            return int(v)
    return int(default)


def _safe_component_token(value: Any) -> str:
    token = str(value or "component").strip().lower()
    cleaned = "".join(ch if ch.isalnum() or ch in ("_", "-", ".") else "_" for ch in token)
    return cleaned or "component"


def _domain_reconciliation_failure_report_path(
    args: argparse.Namespace,
    fault_component: str,
) -> Path:
    output_path = getattr(args, "output", None)
    if output_path is not None:
        base = Path(output_path)
        parent = base.parent
    else:
        parent = Path.cwd()
    return parent / (
        "domain_reconciliation_failure_{}.json".format(
            _safe_component_token(fault_component)
        )
    )


def _write_domain_reconciliation_failure_report(
    *,
    args: argparse.Namespace,
    meta: Dict[str, Any],
    reason: str,
    details: Dict[str, Any],
) -> str:
    fault_component = str(
        meta.get("fault_component", getattr(args, "fault_component", ""))
    ).strip().lower()
    report_path = _domain_reconciliation_failure_report_path(args, fault_component)
    payload = {
        "status": "failed",
        "reason": str(reason),
        "details": dict(details),
        "fault_component": str(fault_component),
        "fi_sampling_space_path": str(getattr(args, "fi_sampling_space_path", "") or ""),
        "cycles_domain_path": str(getattr(args, "cycles_domain_path", "") or ""),
        "output": str(getattr(args, "output", "") or ""),
        "exact_meta": dict(meta),
    }
    try:
        _json_dump_path(report_path, payload)
    except Exception as exc:
        return "unwritten:{}:{}".format(type(exc).__name__, exc)
    return str(report_path)


def _fail_domain_reconciliation(
    *,
    args: argparse.Namespace,
    meta: Dict[str, Any],
    reason: str,
    details: Dict[str, Any],
) -> None:
    meta["domain_reconciliation_method"] = "failed_{}".format(str(reason))
    meta["domain_reconciliation_failure_reason"] = str(reason)
    meta["domain_reconciliation_unexplained_bits"] = int(
        _safe_int(details.get("unexplained_bits", details.get("mismatch_bits", 0)), 0)
    )
    report_path = _write_domain_reconciliation_failure_report(
        args=args,
        meta=meta,
        reason=str(reason),
        details=dict(details),
    )
    meta["domain_reconciliation_failure_report_path"] = str(report_path)
    fault_component = str(
        meta.get("fault_component", getattr(args, "fault_component", ""))
    ).strip().lower()
    raise ValueError(
        "FI-aligned denominator reconciliation failed for component {}: {}; "
        "details={}; report={}".format(
            fault_component,
            str(reason),
            json.dumps(details, sort_keys=True),
            report_path,
        )
    )


def _addr_domain_counts_for_reconciliation(meta: Dict[str, Any]) -> Dict[str, float]:
    generic = {
        "masked": _to_float_num(meta.get("addr_masked_bits", 0.0)),
        "sdc": _to_float_num(meta.get("addr_sdc_bits", 0.0)),
        "due": _to_float_num(meta.get("addr_due_bits", 0.0)),
        "unknown": _to_float_num(meta.get("addr_unknown_bits", 0.0)),
    }
    smem = {
        "masked": _to_float_num(meta.get("smem_addr_masked_bits", 0.0)),
        "sdc": _to_float_num(meta.get("smem_addr_sdc_bits", 0.0)),
        "due": _to_float_num(meta.get("smem_addr_due_bits", 0.0)),
        "unknown": _to_float_num(meta.get("smem_addr_unknown_bits", 0.0)),
    }
    generic_sum = sum(float(v) for v in generic.values())
    smem_sum = sum(float(v) for v in smem.values())
    counts = smem if smem_sum > generic_sum else generic
    domain_bits = max(
        _to_float_num(meta.get("addr_domain_bits", 0.0)),
        _to_float_num(meta.get("smem_addr_domain_bits", 0.0)),
        sum(float(v) for v in counts.values()),
    )
    assigned = sum(float(v) for v in counts.values())
    if domain_bits > assigned:
        counts = dict(counts)
        counts["masked"] = float(counts.get("masked", 0.0)) + float(domain_bits - assigned)
    return counts


def _record_summary_domain(
    summary_row: Optional[Dict[str, Any]],
    domain_name: str,
    *,
    masked: float,
    sdc: float,
    due: float,
    unknown: float,
    den: int,
    mode: str,
    policy: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    if summary_row is None:
        return
    by_domain_raw = summary_row.get("by_domain")
    if not isinstance(by_domain_raw, dict):
        by_domain_raw = {}
        summary_row["by_domain"] = by_domain_raw
    payload: Dict[str, Any] = {
        "masked": _normalize_count_num(masked),
        "sdc": _normalize_count_num(sdc),
        "due": _normalize_count_num(due),
        "unknown": _normalize_count_num(unknown),
        "den": int(max(0, int(den))),
        "mode": str(mode),
    }
    if policy is not None:
        payload["policy"] = str(policy)
    if isinstance(extra, dict):
        payload.update(dict(extra))
    by_domain_raw[str(domain_name)] = payload


def _sampling_component_domain_info(
    *,
    fi_space: Dict[str, Any],
    fault_component: str,
    meta: Dict[str, Any],
    args: argparse.Namespace,
) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "domain_total_bits": 0,
        "domain_per_seed_bits": 0,
        "cycle_total_multiplicity": 0,
        "cycle_unique_count": 0,
        "shader_scope_count": 0,
        "shader_scope": [],
        "include_tag_bits": None,
        "tag_bits": None,
        "line_size_bytes": None,
        "addr_fault_policy": _sampling_first(
            fi_space,
            (
                f"component_domains.{fault_component}.addr_fault_policy",
                "addr_fault_policy",
            ),
        ),
        "addr_domain_bits": _safe_int(
            _sampling_first(
                fi_space,
                (
                    f"component_domains.{fault_component}.addr_domain_bits",
                    f"{fault_component}_addr_domain_bits",
                    "addr_domain_bits",
                ),
            ),
            0,
        ),
        "domain_source": "none",
    }
    if not fi_space:
        return info

    sampling_cycles_file = _sampling_first(fi_space, ("cycles_file",))
    sampling_cycle_total_explicit = _safe_int(
        _sampling_first(
            fi_space,
            (
                "cycle_total_multiplicity",
                f"component_domains.{fault_component}.cycle_total_multiplicity",
            ),
        ),
        0,
    )
    sampling_cycle_unique_explicit = _safe_int(
        _sampling_first(
            fi_space,
            (
                "cycle_unique_count",
                f"component_domains.{fault_component}.cycle_unique_count",
            ),
        ),
        0,
    )
    sampling_cycle_stats = _cycle_domain_stats(
        Path(str(sampling_cycles_file))
        if isinstance(sampling_cycles_file, (str, Path)) and str(sampling_cycles_file).strip()
        else None
    )
    info["cycle_total_multiplicity"] = int(
        sampling_cycle_total_explicit
        if sampling_cycle_total_explicit > 0
        else sampling_cycle_stats.get("total_multiplicity", 0)
    )
    info["cycle_unique_count"] = int(
        sampling_cycle_unique_explicit
        if sampling_cycle_unique_explicit > 0
        else sampling_cycle_stats.get("unique_cycles", 0)
    )

    explicit_total = _first_positive_int(
        (
            _sampling_first(fi_space, (f"component_domains.{fault_component}.domain_total_bits",)),
            _sampling_first(fi_space, (f"{fault_component}_domain_total_bits",)),
            _sampling_first(fi_space, (f"{fault_component}_total_bits",)),
        ),
        0,
    )
    if explicit_total > 0:
        info["domain_total_bits"] = int(explicit_total)
        info["domain_source"] = "sampling_space_explicit"

    fc = str(fault_component).strip().lower()
    selected_mask, selected_bit_count = _selected_byte_domain(getattr(args, "bits", None))

    if fc == "rf":
        thread_rand_max = _first_positive_int(
            (
                _sampling_first(fi_space, ("component_domains.rf.thread_rand_max",)),
                _sampling_first(fi_space, ("thread_rand_max",)),
            ),
            _safe_int(meta.get("thread_rand_max", 0), 0),
        )
        explicit_per_seed = _first_positive_int(
            (
                _sampling_first(
                    fi_space,
                    ("component_domains.rf.domain_bits_per_seed", "rf_domain_per_seed_bits"),
                ),
            ),
            0,
        )
        reg_count = _first_positive_int(
            (
                _sampling_first(fi_space, ("component_domains.rf.register_count",)),
                _sampling_first(fi_space, ("register_count",)),
            ),
            _safe_int(meta.get("register_count", 0), 0),
        )
        bit_count = _first_positive_int((_safe_int(meta.get("bit_count", 0), 0),), 0)
        per_seed = int(max(0, explicit_per_seed))
        if per_seed <= 0:
            per_seed = int(max(0, reg_count * bit_count))
        info["domain_per_seed_bits"] = int(per_seed)
        if info["domain_total_bits"] <= 0:
            cycle_mass = int(info.get("cycle_total_multiplicity", 0))
            if cycle_mass > 0 and thread_rand_max > 0 and per_seed > 0:
                info["domain_total_bits"] = int(cycle_mass * thread_rand_max * per_seed)
                info["domain_source"] = "sampling_space_derived"
        return info

    if fc in ("smem_rf", "smem_lds"):
        block_rand_max = _first_positive_int(
            (
                _sampling_first(fi_space, (f"component_domains.{fc}.block_rand_max",)),
                _sampling_first(fi_space, ("block_rand_max",)),
            ),
            _safe_int(meta.get("block_seed_domain_size", 0), 0),
        )
        explicit_per_seed = _first_positive_int(
            (
                _sampling_first(
                    fi_space,
                    (
                        f"component_domains.{fc}.domain_bits_per_seed",
                        "component_domains.smem_rf.domain_bits_per_seed",
                        "component_domains.smem_lds.domain_bits_per_seed",
                    ),
                ),
            ),
            0,
        )
        smem_size_bits = _first_positive_int(
            (
                _sampling_first(fi_space, (f"component_domains.{fc}.smem_size_bits",)),
                _sampling_first(fi_space, ("smem_size_bits",)),
            ),
            _safe_int(meta.get("smem_size_bits", 0), 0),
        )
        per_seed = int(max(0, explicit_per_seed))
        if per_seed <= 0:
            per_seed = int(
                _selected_smem_domain_bit_count(
                    selected_bits_mask=int(selected_mask),
                    bit_count_full_byte=int(selected_bit_count),
                    domain_full_bytes=max(0, int(smem_size_bits) // 8),
                    domain_tail_bits=max(0, int(smem_size_bits) % 8),
                )
            )
        info["domain_per_seed_bits"] = int(max(0, per_seed))
        if info["domain_total_bits"] <= 0:
            cycle_mass = int(info.get("cycle_total_multiplicity", 0))
            if cycle_mass > 0 and block_rand_max > 0 and per_seed > 0:
                info["domain_total_bits"] = int(cycle_mass * block_rand_max * per_seed)
                info["domain_source"] = "sampling_space_derived"
        return info

    if fc in ("l1d", "l2"):
        prefix = "l1d" if fc == "l1d" else "l2"
        guard_source = str(meta.get("shader_scope_source", "")).strip()
        sampling_scope_guarded = bool(
            fc == "l1d"
            and guard_source
            in ("sampling_space_guard_intersection", "sampling_space_guard_inferred")
        )
        include_tag = _safe_int(
            _sampling_first(
                fi_space,
                (
                    f"component_domains.{fc}.include_tag_bits",
                    f"{prefix}_include_tag_bits",
                ),
            ),
            _safe_int(meta.get(f"{prefix}_include_tag_bits", 1), 1),
        )
        tag_bits = _safe_int(
            _sampling_first(
                fi_space,
                (
                    f"component_domains.{fc}.tag_bits",
                    f"{prefix}_tag_bits",
                    "cache_tag_bits",
                ),
            ),
            _safe_int(meta.get(f"{prefix}_tag_bits", 0), 0),
        )
        size_bits = _safe_int(
            _sampling_first(
                fi_space,
                (
                    f"component_domains.{fc}.size_bits",
                    f"{prefix}_size_bits",
                ),
            ),
            _safe_int(meta.get(f"{prefix}_size_bits", 0), 0),
        )
        line_size_bytes = _safe_int(
            _sampling_first(
                fi_space,
                (
                    f"component_domains.{fc}.line_size_bytes",
                    f"{prefix}_line_size_bytes",
                ),
            ),
            _safe_int(meta.get(f"{prefix}_line_size_bytes", 0), 0),
        )
        info["include_tag_bits"] = bool(include_tag)
        info["tag_bits"] = int(tag_bits)
        info["line_size_bytes"] = int(line_size_bytes)
        shader_scope: List[int] = []
        shader_scope_count = 1
        if fc == "l1d":
            shader_scope = _parse_shader_domain_value(
                _sampling_first(
                    fi_space,
                    (
                        "component_domains.l1d.shaders",
                        "component_domains.l1d.shader_scope",
                        "l1d_shaders",
                    ),
                )
            ) or []
            shader_scope_count = _first_positive_int(
                (
                    _sampling_first(
                        fi_space,
                        (
                            "component_domains.l1d.shader_count",
                            "component_domains.l1d.active_sm_count",
                            "l1d_shader_count",
                            "active_sm_count",
                            "sm_count",
                        ),
                    ),
                ),
                len(shader_scope),
            )
            if shader_scope and shader_scope_count <= 0:
                shader_scope_count = int(len(shader_scope))
            if shader_scope_count <= 0:
                shader_scope_count = _safe_int(meta.get("l1d_shader_seed_domain_size", 1), 1)
            if sampling_scope_guarded:
                guarded_scope = _parse_shader_domain_value(meta.get("l1d_shaders")) or []
                if guarded_scope:
                    shader_scope = [int(v) for v in guarded_scope]
                    shader_scope_count = int(len(shader_scope))
                else:
                    shader_scope_count = _safe_int(
                        meta.get("l1d_shader_seed_domain_size", shader_scope_count),
                        shader_scope_count,
                    )
        info["shader_scope"] = [int(v) for v in shader_scope]
        info["shader_scope_count"] = int(max(1, shader_scope_count))

        per_seed_total = _safe_int(
            _sampling_first(
                fi_space,
                (
                    f"component_domains.{fc}.domain_bits_per_seed",
                    f"{prefix}_domain_bits_per_seed",
                ),
            ),
            0,
        )
        per_seed_data = 0
        per_seed_tag = 0
        if size_bits > 0 and line_size_bytes > 0:
            (
                per_seed_total_sel,
                per_seed_data_sel,
                per_seed_tag_sel,
                _full_lines,
                _tail_bits,
            ) = _selected_l2_domain_bit_counts(
                l2_size_bits=int(size_bits),
                line_size_bytes=int(line_size_bytes),
                tag_bits=int(max(0, tag_bits)),
                selected_data_bits_mask=int(selected_mask),
                selected_data_bit_count_full_byte=int(selected_bit_count),
                include_tag_bits=bool(include_tag),
            )
            if per_seed_total <= 0:
                per_seed_total = int(per_seed_total_sel)
                per_seed_data = int(per_seed_data_sel)
                per_seed_tag = int(per_seed_tag_sel)
            elif int(per_seed_total) == int(per_seed_total_sel):
                # fi_sampling_space records an explicit total for cache components.
                # Preserve the data/tag split derived from the same cache geometry so
                # denominator alignment can distinguish real metadata gaps from the
                # ordinary data+tag FI domain.  This split is diagnostic only when the
                # explicit total is already aligned.
                per_seed_data = int(per_seed_data_sel)
                per_seed_tag = int(per_seed_tag_sel)
        info["domain_per_seed_bits"] = int(max(0, per_seed_total))
        info["data_bits_per_seed"] = int(max(0, per_seed_data))
        info["tag_bits_per_seed"] = int(max(0, per_seed_tag))

        if sampling_scope_guarded:
            cycle_mass = int(info.get("cycle_total_multiplicity", 0))
            if cycle_mass > 0 and per_seed_total > 0:
                info["domain_total_bits"] = int(
                    cycle_mass * int(info["shader_scope_count"]) * per_seed_total
                )
                info["domain_source"] = f"{guard_source}_derived"
        elif info["domain_total_bits"] <= 0:
            cycle_mass = int(info.get("cycle_total_multiplicity", 0))
            if cycle_mass > 0 and per_seed_total > 0:
                info["domain_total_bits"] = int(
                    cycle_mass * int(info["shader_scope_count"]) * per_seed_total
                )
                info["domain_source"] = "sampling_space_derived"
        return info

    return info


def _trace_expanding_stats_from_analyzer_payload(analyzer: Dict[str, Any]) -> Dict[str, int]:
    read_present = 0
    read_bits = 0
    site_present = 0
    site_bits = 0

    read_events = analyzer.get("read_events", [])
    if isinstance(read_events, list):
        for rec in read_events:
            trace_field = _read_event_row_field(rec, "trace_expanding_mask_this_read", None)
            if trace_field is not None:
                read_present += 1
            width = max(
                0,
                min(64, _safe_int(_read_event_row_field(rec, "src_width_bits", 64), 64)),
            )
            read_bits += int(
                popcount_u64(parse_mask(0 if trace_field is None else trace_field) & width_mask(width))
            )

    for key in ("smem_fault_sites", "l1d_fault_sites", "l2_fault_sites"):
        rows = analyzer.get(key, [])
        if not isinstance(rows, list):
            continue
        for rec in rows:
            if key == "smem_fault_sites":
                trace_field = _smem_site_row_field(rec, "trace_expanding_mask_this_site", None)
                width_raw = _smem_site_row_field(rec, "width_bits", 8)
            else:
                trace_field = _cache_site_row_field(rec, "trace_expanding_mask_this_site", None)
                width_raw = _cache_site_row_field(rec, "width_bits", 8)
            if trace_field is not None:
                site_present += 1
            width = max(0, min(64, _safe_int(width_raw, 8)))
            site_bits += int(
                popcount_u64(parse_mask(0 if trace_field is None else trace_field) & width_mask(width))
            )

    return {
        "trace_expanding_read_mask_present_count": int(read_present),
        "trace_expanding_read_bits_total": int(read_bits),
        "trace_expanding_site_mask_present_count": int(site_present),
        "trace_expanding_site_bits_total": int(site_bits),
        "trace_expanding_mask_present_count": int(read_present + site_present),
        "trace_expanding_bits_total": int(read_bits + site_bits),
    }


@lru_cache(maxsize=None)
def _trace_expanding_stats_for_analyzer_path(
    path_key: str,
    normalize_trace_coverage: bool,
) -> Dict[str, int]:
    required = (
        "trace_expanding_read_mask_present_count",
        "trace_expanding_read_bits_total",
        "trace_expanding_site_mask_present_count",
        "trace_expanding_site_bits_total",
        "trace_expanding_mask_present_count",
        "trace_expanding_bits_total",
    )
    sidecar_meta = _load_analyzer_meta_sidecar_cached(str(path_key))
    if all(key in sidecar_meta for key in required):
        return {key: int(_safe_int(sidecar_meta.get(key, 0), 0)) for key in required}

    analyzer_any = _load_analyzer_output_for_compute_cached(
        str(path_key),
        bool(normalize_trace_coverage),
    )
    if not isinstance(analyzer_any, dict):
        return {
            "trace_expanding_read_mask_present_count": 0,
            "trace_expanding_read_bits_total": 0,
            "trace_expanding_site_mask_present_count": 0,
            "trace_expanding_site_bits_total": 0,
            "trace_expanding_mask_present_count": 0,
            "trace_expanding_bits_total": 0,
        }
    analyzer_meta_raw = analyzer_any.get("exact_meta", {})
    analyzer_meta = analyzer_meta_raw if isinstance(analyzer_meta_raw, dict) else {}
    if all(key in analyzer_meta for key in required):
        return {key: int(_safe_int(analyzer_meta.get(key, 0), 0)) for key in required}
    return _trace_expanding_stats_from_analyzer_payload(analyzer_any)


def _apply_sampling_space_domain_reconciliation(
    out: Dict[str, Any],
    meta: Dict[str, Any],
    args: argparse.Namespace,
) -> None:
    fault_component = str(
        meta.get("fault_component", getattr(args, "fault_component", ""))
    ).strip().lower()
    use_sampling_space_domain_global = bool(
        int(getattr(args, "use_sampling_space_domain", 0))
    )
    use_sampling_space_domain_rf = bool(
        int(getattr(args, "use_sampling_space_domain_rf", 0))
    )
    use_sampling_space_domain_smem = bool(
        int(getattr(args, "use_sampling_space_domain_smem", 0))
    )
    use_sampling_space_domain = bool(use_sampling_space_domain_global)
    if fault_component == "rf":
        use_sampling_space_domain = bool(
            use_sampling_space_domain_global or use_sampling_space_domain_rf
        )
    elif fault_component in ("smem_rf", "smem_lds"):
        use_sampling_space_domain = bool(
            use_sampling_space_domain_global or use_sampling_space_domain_smem
        )

    metadata_fault_policy = _normalize_metadata_fault_policy(
        getattr(args, "metadata_fault_policy", CANONICAL_METADATA_FAULT_POLICY)
    )
    fi_space = _load_fi_sampling_space(getattr(args, "fi_sampling_space_path", None))
    sampling_info = _sampling_component_domain_info(
        fi_space=fi_space,
        fault_component=fault_component,
        meta=meta,
        args=args,
    )

    # The FI-aligned denominator is authoritative.  If SARA's derived evidence
    # contains address-domain sites that are not represented by fi_sampling_space,
    # those sites are excluded later from the common comparison domain rather than
    # being inferred into the FI denominator.
    sampling_total_raw = _safe_int(sampling_info.get("domain_total_bits", 0), 0)
    sampling_addr_domain_bits = _safe_int(sampling_info.get("addr_domain_bits", 0), 0)
    addr_fault_policy = _normalize_addr_fault_policy(
        meta.get("addr_fault_policy", getattr(args, "addr_fault_policy", CANONICAL_ADDR_FAULT_POLICY))
    )
    sampling_total_effective = int(max(0, sampling_total_raw))
    sampling_addr_domain_inferred_bits = 0
    meta["sampling_space_domain_total_bits_raw"] = int(max(0, sampling_total_raw))
    meta["sampling_space_domain_total_bits_effective"] = int(max(0, sampling_total_effective))
    meta["sampling_space_addr_domain_bits_raw"] = int(max(0, sampling_addr_domain_bits))
    meta["sampling_space_addr_domain_bits_inferred"] = int(
        max(0, sampling_addr_domain_inferred_bits)
    )
    meta["sampling_space_addr_domain_policy"] = str(addr_fault_policy)

    derived_total = _safe_int(
        meta.get("total_bits", 0),
        _safe_int(out.get("classification_counts", {}).get("total", 0), 0),
    )
    sampling_total = _safe_int(sampling_info.get("domain_total_bits", 0), 0)
    domain_mismatch = int(sampling_total - derived_total) if sampling_total > 0 else 0

    cycle_actual = _cycle_domain_stats(getattr(args, "cycles", None))
    cycle_derived_mass = int(cycle_actual.get("total_multiplicity", 0))
    cycle_sampling_mass = _safe_int(sampling_info.get("cycle_total_multiplicity", 0), 0)
    if cycle_sampling_mass <= 0:
        cycle_sampling_mass = int(cycle_derived_mass)

    cycle_mismatch_bits = 0
    thread_rand_mismatch_bits = 0
    block_rand_mismatch_bits = 0
    per_seed_mismatch_bits = 0
    shader_mismatch_bits = 0
    tag_mismatch_bits = 0
    metadata_domain_bits = 0

    if fault_component == "l1d":
        derived_shader = max(1, _safe_int(meta.get("l1d_shader_seed_domain_size", 1), 1))
        sampling_shader = max(
            1, _safe_int(sampling_info.get("shader_scope_count", 0), derived_shader)
        )
        derived_per_seed = max(0, _safe_int(meta.get("l1d_selected_bit_domain_size", 0), 0))
        sampling_per_seed = max(
            0, _safe_int(sampling_info.get("domain_per_seed_bits", 0), derived_per_seed)
        )
        cycle_mismatch_bits = (
            int(cycle_sampling_mass - cycle_derived_mass)
            * int(derived_shader)
            * int(derived_per_seed)
        )
        shader_mismatch_bits = (
            int(cycle_sampling_mass)
            * int(sampling_shader - derived_shader)
            * int(derived_per_seed)
        )
        per_seed_mismatch_bits = (
            int(cycle_sampling_mass)
            * int(sampling_shader)
            * int(sampling_per_seed - derived_per_seed)
        )
        sampling_tag_bits = int(cycle_sampling_mass) * int(sampling_shader) * int(
            _safe_int(sampling_info.get("tag_bits_per_seed", 0), 0)
        )
        tag_mismatch_bits = int(sampling_tag_bits - _safe_int(meta.get("tag_bits", 0), 0))
        sampling_data_tag_total = int(cycle_sampling_mass) * int(sampling_shader) * int(
            _safe_int(sampling_info.get("data_bits_per_seed", 0), 0)
            + _safe_int(sampling_info.get("tag_bits_per_seed", 0), 0)
        )
        if sampling_total > 0 and sampling_data_tag_total > 0:
            metadata_domain_bits = max(0, int(sampling_total - sampling_data_tag_total))
    elif fault_component == "l2":
        derived_per_seed = max(0, _safe_int(meta.get("l2_selected_bit_domain_size", 0), 0))
        sampling_per_seed = max(
            0, _safe_int(sampling_info.get("domain_per_seed_bits", 0), derived_per_seed)
        )
        cycle_mismatch_bits = int(cycle_sampling_mass - cycle_derived_mass) * int(derived_per_seed)
        per_seed_mismatch_bits = int(cycle_sampling_mass) * int(
            sampling_per_seed - derived_per_seed
        )
        sampling_tag_bits = int(cycle_sampling_mass) * int(
            _safe_int(sampling_info.get("tag_bits_per_seed", 0), 0)
        )
        tag_mismatch_bits = int(sampling_tag_bits - _safe_int(meta.get("tag_bits", 0), 0))
        sampling_data_tag_total = int(cycle_sampling_mass) * int(
            _safe_int(sampling_info.get("data_bits_per_seed", 0), 0)
            + _safe_int(sampling_info.get("tag_bits_per_seed", 0), 0)
        )
        if sampling_total > 0 and sampling_data_tag_total > 0:
            metadata_domain_bits = max(0, int(sampling_total - sampling_data_tag_total))
    elif fault_component == "rf":
        derived_thread_seed = max(
            1, _safe_int(meta.get("thread_rand_max", meta.get("seed_domain_size", 1)), 1)
        )
        sampling_thread_seed = max(
            1,
            _first_positive_int(
                (
                    _sampling_first(
                        fi_space,
                        ("component_domains.rf.thread_rand_max", "thread_rand_max"),
                    ),
                ),
                derived_thread_seed,
            ),
        )
        derived_per_seed = max(
            0,
            _safe_int(meta.get("rf_domain_bits_per_seed_final", 0), 0),
        )
        if derived_per_seed <= 0:
            derived_per_seed = max(
                0,
                _safe_int(meta.get("register_count", 0), 0)
                * _safe_int(meta.get("bit_count", 0), 0),
            )
        if derived_per_seed <= 0:
            derived_per_seed = max(
                0,
                _safe_int(sampling_info.get("domain_per_seed_bits", 0), 0),
            )
        sampling_per_seed = max(
            0, _safe_int(sampling_info.get("domain_per_seed_bits", 0), derived_per_seed)
        )
        cycle_mismatch_bits = (
            int(cycle_sampling_mass - cycle_derived_mass)
            * int(derived_thread_seed)
            * int(derived_per_seed)
        )
        thread_rand_mismatch_bits = (
            int(cycle_sampling_mass)
            * int(sampling_thread_seed - derived_thread_seed)
            * int(derived_per_seed)
        )
        per_seed_mismatch_bits = (
            int(cycle_sampling_mass)
            * int(sampling_thread_seed)
            * int(sampling_per_seed - derived_per_seed)
        )
    elif fault_component in ("smem_rf", "smem_lds"):
        derived_block_seed = max(
            1,
            _safe_int(meta.get("block_seed_domain_size", meta.get("block_rand_max", 1)), 1),
        )
        sampling_block_seed = max(
            1,
            _first_positive_int(
                (
                    _sampling_first(
                        fi_space,
                        (
                            f"component_domains.{fault_component}.block_rand_max",
                            "component_domains.smem_rf.block_rand_max",
                            "block_rand_max",
                        ),
                    ),
                ),
                derived_block_seed,
            ),
        )
        derived_per_seed = max(0, _safe_int(meta.get("smem_selected_bit_domain_size", 0), 0))
        if derived_per_seed <= 0:
            derived_per_seed = max(0, _safe_int(meta.get("smem_size_bits", 0), 0))
        sampling_per_seed = max(
            0, _safe_int(sampling_info.get("domain_per_seed_bits", 0), derived_per_seed)
        )
        cycle_mismatch_bits = (
            int(cycle_sampling_mass - cycle_derived_mass)
            * int(derived_block_seed)
            * int(derived_per_seed)
        )
        block_rand_mismatch_bits = (
            int(cycle_sampling_mass)
            * int(sampling_block_seed - derived_block_seed)
            * int(derived_per_seed)
        )
        per_seed_mismatch_bits = (
            int(cycle_sampling_mass)
            * int(sampling_block_seed)
            * int(sampling_per_seed - derived_per_seed)
        )

    metadata_policy_counts = _metadata_policy_counts(metadata_domain_bits, metadata_fault_policy)
    known_mismatch = int(
        cycle_mismatch_bits
        + thread_rand_mismatch_bits
        + block_rand_mismatch_bits
        + per_seed_mismatch_bits
        + shader_mismatch_bits
        + tag_mismatch_bits
        + metadata_domain_bits
    )
    other_mismatch_bits = int(domain_mismatch - known_mismatch) if sampling_total > 0 else 0

    meta["domain_sampling_space_total_bits"] = int(sampling_total)
    meta["domain_derived_total_bits"] = int(derived_total)
    meta["domain_mismatch_bits"] = int(domain_mismatch)
    meta["mismatch_breakdown"] = {
        "cycles": int(cycle_mismatch_bits),
        "thread_rand_max": int(thread_rand_mismatch_bits),
        "block_rand_max": int(block_rand_mismatch_bits),
        "per_seed_bits": int(per_seed_mismatch_bits),
        "tag": int(tag_mismatch_bits),
        "metadata": int(metadata_domain_bits),
        "shader_scope": int(shader_mismatch_bits),
        "cycle_domain": int(cycle_mismatch_bits),
        "other": int(other_mismatch_bits),
    }
    if fault_component == "rf":
        meta["rf_domain_sampling_bits"] = int(sampling_total)
        meta["rf_domain_derived_bits"] = int(derived_total)
        meta["rf_domain_mismatch"] = int(domain_mismatch)
    elif fault_component in ("smem_rf", "smem_lds"):
        meta["smem_domain_sampling_bits"] = int(sampling_total)
        meta["smem_domain_derived_bits"] = int(derived_total)
        meta["smem_domain_mismatch"] = int(domain_mismatch)

    meta["use_sampling_space_domain_global"] = bool(use_sampling_space_domain_global)
    meta["use_sampling_space_domain_rf"] = bool(use_sampling_space_domain_rf)
    meta["use_sampling_space_domain_smem"] = bool(use_sampling_space_domain_smem)
    meta["use_sampling_space_domain"] = bool(use_sampling_space_domain)
    meta["metadata_fault_policy"] = str(metadata_fault_policy)
    meta["metadata_domain_bits"] = int(metadata_domain_bits)
    meta["metadata_masked_bits"] = int(metadata_policy_counts.get("masked", 0))
    meta["metadata_sdc_bits"] = int(metadata_policy_counts.get("sdc", 0))
    meta["metadata_due_bits"] = int(metadata_policy_counts.get("due", 0))
    meta["metadata_unknown_bits"] = int(metadata_policy_counts.get("unknown", 0))
    meta["sampling_space_include_tag_bits"] = sampling_info.get("include_tag_bits")
    meta["sampling_space_tag_bits"] = sampling_info.get("tag_bits")
    meta["sampling_space_line_size_bytes"] = sampling_info.get("line_size_bytes")
    meta["sampling_space_shader_scope"] = list(sampling_info.get("shader_scope", []))
    meta["sampling_space_shader_scope_count"] = int(
        _safe_int(sampling_info.get("shader_scope_count", 0), 0)
    )
    meta["sampling_space_addr_fault_policy"] = sampling_info.get("addr_fault_policy")
    meta["sampling_space_addr_domain_bits"] = int(
        _safe_int(sampling_info.get("addr_domain_bits", 0), 0)
    )
    meta["sampling_space_domain_per_seed_bits"] = int(
        _safe_int(sampling_info.get("domain_per_seed_bits", 0), 0)
    )
    meta["sampling_space_domain_source"] = str(sampling_info.get("domain_source", "none"))

    metadata_applied_bits = 0
    metadata_applied_counts = {"masked": 0, "sdc": 0, "due": 0, "unknown": 0}
    non_live_masked_topup_bits = 0
    addr_domain_excluded_bits = 0
    addr_domain_excluded_counts = {"masked": 0.0, "sdc": 0.0, "due": 0.0, "unknown": 0.0}
    unexplained_mismatch_bits = 0
    reconciliation_method = "diagnostic_only"
    # Canonical FI-aligned mode no longer applies a common normalization factor.
    # Counts are either kept, explicitly topped up, explicitly excluded, or the
    # component fails with a denominator reconciliation report.
    target_total = int(max(0, sampling_total))
    current_total = float(
        _to_float_num(out.get("classification_counts", {}).get("total", 0.0))
    )
    fi_aligned_components = ("rf", "smem_rf", "smem_lds", "l1d", "l2")
    if (
        use_sampling_space_domain
        and sampling_total <= 0
        and fault_component in fi_aligned_components
    ):
        _fail_domain_reconciliation(
            args=args,
            meta=meta,
            reason="sampling_space_unavailable",
            details={
                "mismatch_bits": int(domain_mismatch),
                "sampling_total_bits": int(sampling_total),
                "derived_total_bits": int(derived_total),
                "fault_component": str(fault_component),
            },
        )

    if use_sampling_space_domain and sampling_total > 0:
        counts_raw = out.get("classification_counts", {})
        counts = {
            "masked": _to_float_num(counts_raw.get("masked", 0.0)),
            "sdc": _to_float_num(counts_raw.get("sdc", 0.0)),
            "due": _to_float_num(counts_raw.get("due", 0.0)),
            "unknown": _to_float_num(counts_raw.get("unknown", 0.0)),
            "total": _to_float_num(counts_raw.get("total", 0.0)),
        }
        current_total = float(counts["total"])
        current_total_i = int(round(current_total))
        if abs(float(current_total_i) - float(current_total)) > 1e-6:
            _fail_domain_reconciliation(
                args=args,
                meta=meta,
                reason="non_integral_current_total",
                details={
                    "current_total_bits": float(current_total),
                    "target_total_bits": int(target_total),
                    "unexplained_bits": int(abs(float(current_total) - float(current_total_i))),
                },
            )

        if target_total < current_total_i:
            drop_required = int(current_total_i - target_total)
            addr_domain_excluded_counts = _addr_domain_counts_for_reconciliation(meta)
            addr_drop_total = float(sum(float(v) for v in addr_domain_excluded_counts.values()))
            expected_without_addr = float(current_total) - float(addr_drop_total)
            if addr_drop_total > 0.0 and abs(expected_without_addr - float(target_total)) <= 1e-6:
                for cls in ("masked", "sdc", "due", "unknown"):
                    drop_v = float(addr_domain_excluded_counts.get(cls, 0.0))
                    if drop_v > float(counts.get(cls, 0.0)) + 1e-6:
                        _fail_domain_reconciliation(
                            args=args,
                            meta=meta,
                            reason="addr_domain_exclusion_exceeds_class_count",
                            details={
                                "class": str(cls),
                                "drop_bits": _normalize_numeric(drop_v),
                                "class_count_bits": _normalize_numeric(counts.get(cls, 0.0)),
                                "target_total_bits": int(target_total),
                                "current_total_bits": int(current_total_i),
                                "unexplained_bits": int(drop_required),
                            },
                        )
                    counts[cls] = max(0.0, float(counts.get(cls, 0.0)) - drop_v)
                addr_domain_excluded_bits = int(drop_required)
                reconciliation_method = "exclude_addr_domain_from_fi_aligned_space"
                meta["sampling_space_addr_domain_dropped_bits"] = _normalize_numeric(
                    float(addr_domain_excluded_bits)
                )
            else:
                unexplained_mismatch_bits = int(drop_required)
                _fail_domain_reconciliation(
                    args=args,
                    meta=meta,
                    reason="target_smaller_than_classified_domain",
                    details={
                        "target_total_bits": int(target_total),
                        "current_total_bits": int(current_total_i),
                        "drop_required_bits": int(drop_required),
                        "addr_domain_bits_available": _normalize_numeric(addr_drop_total),
                        "expected_total_without_addr": _normalize_numeric(expected_without_addr),
                        "unexplained_bits": int(unexplained_mismatch_bits),
                        "mismatch_breakdown": dict(meta.get("mismatch_breakdown", {})),
                    },
                )
        elif target_total > current_total_i:
            extra = int(target_total - current_total_i)
            extra_remaining = int(extra)
            if fault_component in ("l1d", "l2") and metadata_domain_bits > 0:
                metadata_applied_bits = int(min(extra_remaining, int(metadata_domain_bits)))
                metadata_applied_counts = _metadata_policy_counts(
                    metadata_applied_bits, metadata_fault_policy
                )
                counts["masked"] += float(metadata_applied_counts.get("masked", 0))
                counts["sdc"] += float(metadata_applied_counts.get("sdc", 0))
                counts["due"] += float(metadata_applied_counts.get("due", 0))
                counts["unknown"] += float(metadata_applied_counts.get("unknown", 0))
                extra_remaining = int(extra_remaining - metadata_applied_bits)
            if extra_remaining > 0:
                # These FI-domain sites have no represented live value in the
                # derivation evidence.  They are therefore non-live modeled sites
                # in the FI-aligned domain and are counted as Masked, not scaled.
                counts["masked"] += float(extra_remaining)
                non_live_masked_topup_bits = int(extra_remaining)
            if metadata_applied_bits > 0 and non_live_masked_topup_bits > 0:
                reconciliation_method = "metadata_and_non_live_topup_to_fi_sampling_space"
            elif metadata_applied_bits > 0:
                reconciliation_method = "metadata_topup_to_fi_sampling_space"
            else:
                reconciliation_method = "non_live_masked_topup_to_fi_sampling_space"
        else:
            reconciliation_method = "already_aligned"

        adjusted_total = float(
            counts["masked"] + counts["sdc"] + counts["due"] + counts["unknown"]
        )
        residual = float(target_total) - float(adjusted_total)
        if abs(residual) > 1e-6:
            _fail_domain_reconciliation(
                args=args,
                meta=meta,
                reason="post_alignment_total_mismatch",
                details={
                    "target_total_bits": int(target_total),
                    "adjusted_total_bits": _normalize_numeric(adjusted_total),
                    "residual_bits": _normalize_numeric(residual),
                    "unexplained_bits": int(abs(round(residual))),
                    "reconciliation_method": str(reconciliation_method),
                },
            )

        _set_output_counts(
            out,
            masked=float(counts["masked"]),
            sdc=float(counts["sdc"]),
            due=float(counts["due"]),
            unknown=float(counts["unknown"]),
            total=int(target_total),
        )
        summary_row = _summary_component_ref(out.get("summary"), fault_component)
        if summary_row is not None:
            out_counts = out.get("classification_counts", {})
            _write_counts_to_summary_row(
                summary_row,
                masked=_to_float_num(out_counts.get("masked", 0.0)),
                sdc=_to_float_num(out_counts.get("sdc", 0.0)),
                due=_to_float_num(out_counts.get("due", 0.0)),
                unknown=_to_float_num(out_counts.get("unknown", 0.0)),
                den=_safe_int(out_counts.get("total", 0), 0),
            )
            if addr_domain_excluded_bits > 0:
                _record_summary_domain(
                    summary_row,
                    "addr",
                    masked=0.0,
                    sdc=0.0,
                    due=0.0,
                    unknown=0.0,
                    den=0,
                    mode="excluded_from_fi_aligned_domain",
                    policy=str(addr_fault_policy),
                    extra={
                        "excluded_bits": int(addr_domain_excluded_bits),
                        "excluded_counts": {
                            "masked": _normalize_count_num(
                                addr_domain_excluded_counts.get("masked", 0.0)
                            ),
                            "sdc": _normalize_count_num(
                                addr_domain_excluded_counts.get("sdc", 0.0)
                            ),
                            "due": _normalize_count_num(
                                addr_domain_excluded_counts.get("due", 0.0)
                            ),
                            "unknown": _normalize_count_num(
                                addr_domain_excluded_counts.get("unknown", 0.0)
                            ),
                        },
                    },
                )
            if non_live_masked_topup_bits > 0:
                _record_summary_domain(
                    summary_row,
                    "non_live",
                    masked=float(non_live_masked_topup_bits),
                    sdc=0.0,
                    due=0.0,
                    unknown=0.0,
                    den=int(non_live_masked_topup_bits),
                    mode="masked_topup_to_fi_aligned_domain",
                )
            if fault_component in ("l1d", "l2"):
                _record_summary_domain(
                    summary_row,
                    "metadata",
                    masked=float(metadata_applied_counts.get("masked", 0)),
                    sdc=float(metadata_applied_counts.get("sdc", 0)),
                    due=float(metadata_applied_counts.get("due", 0)),
                    unknown=float(metadata_applied_counts.get("unknown", 0)),
                    den=int(metadata_applied_bits),
                    policy=str(metadata_fault_policy),
                    mode="fi_aligned_metadata_rule",
                )

        out_total = _safe_int(
            out.get("classification_counts", {}).get("total", 0), target_total
        )
        meta["total_bits"] = int(out_total)
    elif use_sampling_space_domain and sampling_total <= 0:
        reconciliation_method = "sampling_space_unavailable"
    else:
        reconciliation_method = "disabled"

    meta["domain_reconciliation_method"] = str(reconciliation_method)
    meta["domain_reconciliation_unexplained_bits"] = int(unexplained_mismatch_bits)
    meta["domain_reconciliation_non_live_masked_topup_bits"] = int(
        non_live_masked_topup_bits
    )
    meta["domain_reconciliation_addr_domain_excluded_bits"] = int(
        addr_domain_excluded_bits
    )
    meta["domain_reconciliation_failure_report_path"] = str(
        meta.get("domain_reconciliation_failure_report_path", "")
    )
    meta["domain_reconciliation_target_total_bits"] = int(target_total)
    meta["domain_reconciliation_current_total_bits"] = _normalize_numeric(
        float(current_total)
    )
    meta["metadata_applied_bits"] = int(metadata_applied_bits)
    meta["metadata_applied_masked_bits"] = int(metadata_applied_counts.get("masked", 0))
    meta["metadata_applied_sdc_bits"] = int(metadata_applied_counts.get("sdc", 0))
    meta["metadata_applied_due_bits"] = int(metadata_applied_counts.get("due", 0))
    meta["metadata_applied_unknown_bits"] = int(metadata_applied_counts.get("unknown", 0))


def _apply_trace_divergence_zero_diagnostics(
    meta: Dict[str, Any],
    args: argparse.Namespace,
) -> None:
    analyzer_stats_present = _safe_int(meta.get("trace_expanding_mask_present_count", -1), -1)
    analyzer_stats_bits = _safe_int(meta.get("trace_expanding_bits_total", -1), -1)
    if analyzer_stats_present < 0 or analyzer_stats_bits < 0:
        analyzer_path = getattr(args, "analyzer_output", None)
        if analyzer_path is not None:
            try:
                stats = _trace_expanding_stats_for_analyzer_path(
                    _path_cache_key(Path(analyzer_path)),
                    bool(getattr(args, "normalize_trace_coverage", False)),
                )
            except Exception:
                stats = {}
            for k, v in stats.items():
                meta[k] = int(v)
    meta.setdefault("trace_expanding_mask_present_count", 0)
    meta.setdefault("trace_expanding_bits_total", 0)
    meta.setdefault("trace_expanding_read_mask_present_count", 0)
    meta.setdefault("trace_expanding_read_bits_total", 0)
    meta.setdefault("trace_expanding_site_mask_present_count", 0)
    meta.setdefault("trace_expanding_site_bits_total", 0)

    policy = _normalize_trace_divergence_policy(meta.get("trace_divergence_policy", CANONICAL_TRACE_DIVERGENCE_POLICY))
    trace_div_bits = _safe_int(meta.get("trace_divergence_bits", 0), 0)
    if policy == CANONICAL_TRACE_DIVERGENCE_POLICY and trace_div_bits == 0:
        warning = (
            "trace_divergence_policy={} but trace_divergence_bits=0; "
            "trace_expanding_mask_present_count={} trace_expanding_bits_total={}"
        ).format(
            policy,
            int(meta.get("trace_expanding_mask_present_count", 0)),
            int(meta.get("trace_expanding_bits_total", 0)),
        )
        meta["trace_divergence_zero_warning"] = str(warning)


def finalize_exact_result(
    out: Dict[str, Any],
    args: argparse.Namespace,
) -> Dict[str, Any]:
    counts_raw = out.get("classification_counts", {})
    if not isinstance(counts_raw, dict):
        counts_raw = {}
    total = _to_float_num(counts_raw.get("total", 0))
    masked_raw = _to_float_num(counts_raw.get("masked", 0))
    sdc_raw = _to_float_num(counts_raw.get("sdc", 0))
    due_raw = _to_float_num(counts_raw.get("due", 0))
    unknown_raw = _to_float_num(counts_raw.get("unknown", 0))
    raw_total = masked_raw + sdc_raw + due_raw + unknown_raw
    if abs(raw_total - total) > 1e-6:
        raise ValueError(
            "classification count conservation failed before unknown folding: "
            f"masked+sdc+due+unknown={raw_total} total={total}"
        )

    masked_eff = masked_raw
    sdc_eff = sdc_raw
    due_eff = due_raw
    unknown_eff = unknown_raw
    canonical_promotions: Dict[str, Any] = {}
    fault_component = str(getattr(args, "fault_component", "")).strip().lower()
    meta_pre = out.get("exact_meta", {})
    meta_pre = dict(meta_pre) if isinstance(meta_pre, dict) else {}
    if float(unknown_eff) > 0.0:
        # Canonical proof-exact semantics must not silently convert unresolved
        # mass into one of the three FI outcomes.  Earlier revisions folded the
        # remaining unknown mass into Masked (and, for missing storage address
        # ranges, sometimes DUE), which made DUE/Unknown diagnostics appear
        # artificially clean even when trace/address evidence was incomplete.
        # Keep it explicit so downstream comparison/reporting can either handle
        # Unknown separately or choose a documented evaluation policy.
        canonical_promotions["unknown_preserved"] = _normalize_count_num(
            float(unknown_eff)
        )
    eff_total = masked_eff + sdc_eff + due_eff + unknown_eff
    if abs(eff_total - total) > 1e-6:
        raise ValueError(
            "classification count conservation failed after canonical exact finalization: "
            f"masked+sdc+due+unknown={eff_total} total={total}"
        )

    out["classification_counts"] = {
        "masked": _normalize_count_num(masked_eff),
        "sdc": _normalize_count_num(sdc_eff),
        "due": _normalize_count_num(due_eff),
        "unknown": _normalize_count_num(unknown_eff),
        "total": _normalize_count_num(total),
    }
    if total > 0:
        out["classification_rates"] = {
            "masked": float(masked_eff / total),
            "sdc": float(sdc_eff / total),
            "due": float(due_eff / total),
            "unknown": float(unknown_eff / total),
        }
    else:
        out["classification_rates"] = {
            "masked": 0.0,
            "sdc": 0.0,
            "due": 0.0,
            "unknown": 0.0,
        }
    out["weighted_classification_counts"] = {
        "masked": fraction(masked_eff, total if total > 0 else 1),
        "sdc": fraction(sdc_eff, total if total > 0 else 1),
        "due": fraction(due_eff, total if total > 0 else 1),
        "unknown": fraction(unknown_eff, total if total > 0 else 1),
        "total": fraction(total, total if total > 0 else 1),
    }
    out["weighted_classification_rates"] = {
        "masked": fraction(masked_eff, total if total > 0 else 1),
        "sdc": fraction(sdc_eff, total if total > 0 else 1),
        "due": fraction(due_eff, total if total > 0 else 1),
        "unknown": fraction(unknown_eff, total if total > 0 else 1),
    }

    summary = out.get("summary")
    _update_summary_unknown_policy(
        summary,
        strict_enabled=False,
        unknown_policy="preserve_unknown",
    )

    meta_raw = out.get("exact_meta", {})
    meta = dict(meta_raw) if isinstance(meta_raw, dict) else {}
    if canonical_promotions:
        meta["canonical_promotions"] = dict(canonical_promotions)
    meta.setdefault(
        "trace_expanding_resolution_mode",
        _normalize_trace_expanding_resolution_mode(
            getattr(args, "trace_expanding_resolution_mode", "legacy")
        ),
    )
    meta.setdefault("trace_policy_override_bits", 0)
    meta.setdefault("trace_policy_override_mass", 0)
    override_breakdown_raw = meta.get("trace_policy_override_reason_breakdown", {})
    if isinstance(override_breakdown_raw, dict):
        override_breakdown = dict(override_breakdown_raw)
    else:
        override_breakdown = {}
    meta["trace_policy_override_reason_breakdown"] = {
        "sdc": int(override_breakdown.get("sdc", 0)),
        "due": int(override_breakdown.get("due", 0)),
        "unknown": int(override_breakdown.get("unknown", 0)),
        "masked": int(override_breakdown.get("masked", 0)),
    }
    meta["raw_classification_counts"] = {
        "masked": _normalize_count_num(masked_raw),
        "sdc": _normalize_count_num(sdc_raw),
        "due": _normalize_count_num(due_raw),
        "unknown": _normalize_count_num(unknown_raw),
        "total": _normalize_count_num(total),
    }
    meta["raw_unknown_mass"] = _normalize_count_num(unknown_raw)
    meta["exact_semantics_profile"] = str(
        getattr(args, "exact_semantics_profile", EXACT_SEMANTICS_PROFILE)
    )
    strict_replacement_enabled = bool(_safe_int(getattr(args, "strict_replacement", 0), 0))
    strict_replacement_hard = bool(_safe_int(getattr(args, "strict_replacement_hard", 0), 0))
    meta["strict_replacement_enabled"] = bool(strict_replacement_enabled)
    meta["strict_replacement_hard"] = bool(strict_replacement_hard)
    meta["unknown_policy"] = "preserve_unknown"
    meta["unknown_policy_applied"] = "preserve_unknown"
    meta["sampling_space_domain_rf_auto_enabled"] = bool(
        getattr(args, "_auto_enabled_sampling_space_domain_rf", False)
    )
    meta["sampling_space_domain_smem_auto_enabled"] = bool(
        getattr(args, "_auto_enabled_sampling_space_domain_smem", False)
    )
    meta["unknown_fold_target"] = "none"
    meta["unknown_fold_mass"] = 0
    meta["unknown_fold_bits"] = 0
    # Strict-replacement invariant:
    # unknown_bits and unknown_mass must share the same decision domain.
    # unknown_mass is weighted by injection distribution; unknown_bits is an
    # unweighted flag/count proxy for the same classified unknown set.
    unknown_bits = 0
    if float(unknown_raw) > 0.0:
        unknown_bits = int(math.ceil(float(unknown_raw)))
        if unknown_bits <= 0:
            unknown_bits = 1
    meta["unknown_bits"] = int(unknown_bits)
    meta["unknown_mass"] = _normalize_count_num(unknown_raw)
    if "total_bits" not in meta:
        meta["total_bits"] = _normalize_count_num(total)
    if "data_bits" not in meta:
        if "l1d_selected_data_bit_domain_size" in meta:
            meta["data_bits"] = int(meta.get("l1d_selected_data_bit_domain_size", 0))
        elif "l2_selected_data_bit_domain_size" in meta:
            meta["data_bits"] = int(meta.get("l2_selected_data_bit_domain_size", 0))
        else:
            meta["data_bits"] = _normalize_count_num(total)
    if "tag_bits" not in meta:
        if "l1d_selected_tag_bit_domain_size" in meta:
            meta["tag_bits"] = int(meta.get("l1d_selected_tag_bit_domain_size", 0))
        elif "l2_selected_tag_bit_domain_size" in meta:
            meta["tag_bits"] = int(meta.get("l2_selected_tag_bit_domain_size", 0))
        else:
            meta["tag_bits"] = 0
    if "total_injection_bit_domain_size" not in meta:
        if "l1d_selected_bit_domain_size" in meta:
            meta["total_injection_bit_domain_size"] = int(
                meta.get("l1d_selected_bit_domain_size", 0)
            )
        elif "l2_selected_bit_domain_size" in meta:
            meta["total_injection_bit_domain_size"] = int(
                meta.get("l2_selected_bit_domain_size", 0)
            )
        else:
            meta["total_injection_bit_domain_size"] = int(
                max(0, int(meta.get("total_bits", 0)))
            )
    if "masked_bits_data" not in meta:
        meta["masked_bits_data"] = _normalize_count_num(masked_raw)
    if "sdc_bits_data" not in meta:
        meta["sdc_bits_data"] = _normalize_count_num(sdc_raw)
    if "due_bits_data" not in meta:
        meta["due_bits_data"] = _normalize_count_num(due_raw)
    if "unknown_bits_data" not in meta:
        meta["unknown_bits_data"] = _normalize_count_num(unknown_raw)
    if "masked_bits_tag" not in meta:
        meta["masked_bits_tag"] = 0
    if "sdc_bits_tag" not in meta:
        meta["sdc_bits_tag"] = 0
    if "due_bits_tag" not in meta:
        meta["due_bits_tag"] = 0
    if "unknown_bits_tag" not in meta:
        meta["unknown_bits_tag"] = 0
    if "addr_domain_bits" not in meta:
        meta["addr_domain_bits"] = 0
    if "addr_bits_mode" not in meta:
        try:
            mode_default, _vals = _parse_addr_bits_spec(getattr(args, "addr_bits", "auto"))
        except Exception:
            mode_default = "auto"
        meta["addr_bits_mode"] = str(mode_default)
    if "addr_bits_count" not in meta:
        meta["addr_bits_count"] = 0
    if "addr_effective_bits" not in meta:
        meta["addr_effective_bits"] = 0
    if "addr_effective_bits_max" not in meta:
        meta["addr_effective_bits_max"] = 0
    if "addr_masked_bits" not in meta:
        meta["addr_masked_bits"] = 0
    if "addr_sdc_bits" not in meta:
        meta["addr_sdc_bits"] = 0
    if "addr_due_bits" not in meta:
        meta["addr_due_bits"] = 0
    if "addr_unknown_bits" not in meta:
        meta["addr_unknown_bits"] = 0
    if "trace_divergence_bits" not in meta:
        meta["trace_divergence_bits"] = 0
    if "trace_divergence_mass" not in meta:
        meta["trace_divergence_mass"] = 0
    if "addr_fault_policy" not in meta:
        meta["addr_fault_policy"] = _normalize_addr_fault_policy(
            getattr(args, "addr_fault_policy", CANONICAL_ADDR_FAULT_POLICY)
        )
    if "trace_divergence_policy" not in meta:
        meta["trace_divergence_policy"] = _normalize_trace_divergence_policy(
            getattr(args, "trace_divergence_policy", CANONICAL_TRACE_DIVERGENCE_POLICY)
        )
    if "addr_due_mode" not in meta:
        meta["addr_due_mode"] = _normalize_addr_due_mode(
            getattr(args, "addr_due_mode", CANONICAL_ADDR_DUE_MODE)
        )

    due_source_mass_raw = meta.get("due_mass_by_source", {})
    due_source_mass: Dict[str, float] = {}
    if isinstance(due_source_mass_raw, dict):
        for k, v in due_source_mass_raw.items():
            due_source_mass[str(k)] = float(_to_float_num(v))
    required_due_keys = (
        "semantic_due",
        "addr_oob_due",
        "addr_alias_sdc",
        "smem_addr_oob_due",
        "smem_addr_alias_sdc",
        "rf_semantic_due",
        "rf_addr_oob_due",
        "rf_trace_divergence_due",
        "rf_unknown_fold_to_due",
        "l1d_base_due",
        "l2_base_due",
        "trace_divergence_sdc",
        "unknown_fold_to_due",
    )
    for key in required_due_keys:
        due_source_mass.setdefault(str(key), 0.0)
    fault_component_for_fold = str(
        meta.get("fault_component", getattr(args, "fault_component", ""))
    ).strip().lower()
    meta["due_mass_by_source"] = _normalize_mass_map(due_source_mass)
    meta["due_source_bits"] = _mass_map_to_bits_map(due_source_mass)
    rf_due_bits_by_cause_raw = meta.get("rf_due_bits_by_cause", {})
    if fault_component_for_fold == "rf" or isinstance(rf_due_bits_by_cause_raw, dict):
        rf_due_bits_by_cause = (
            dict(rf_due_bits_by_cause_raw)
            if isinstance(rf_due_bits_by_cause_raw, dict)
            else {}
        )
        rf_due_bits_by_cause["rf_semantic_due_bits"] = int(
            round(float(due_source_mass.get("rf_semantic_due", 0.0)))
        )
        rf_due_bits_by_cause["rf_addr_oob_due_bits"] = int(
            round(float(due_source_mass.get("rf_addr_oob_due", 0.0)))
        )
        rf_due_bits_by_cause["rf_trace_divergence_due_bits"] = int(
            round(float(due_source_mass.get("rf_trace_divergence_due", 0.0)))
        )
        rf_due_bits_by_cause["rf_unknown_fold_to_due_bits"] = int(
            round(float(due_source_mass.get("rf_unknown_fold_to_due", 0.0)))
        )
        meta["rf_due_bits_by_cause"] = rf_due_bits_by_cause
    unknown_source_bits, unknown_source_mass, unknown_source_method = _unknown_source_breakdown(
        meta,
        unknown_raw,
    )
    meta["unknown_source_bits"] = dict(unknown_source_bits)
    meta["unknown_mass_by_source"] = dict(unknown_source_mass)
    meta["unknown_source_mass_method"] = str(unknown_source_method)
    unknown_reason_counts = _collect_unknown_reason_counts(meta, unknown_raw)
    meta["unknown_reason_counts"] = dict(unknown_reason_counts)
    fi_sampling_space_path = getattr(args, "fi_sampling_space_path", None)
    if fi_sampling_space_path is not None:
        meta["fi_sampling_space_path"] = str(fi_sampling_space_path)
    cycles_domain_path = getattr(args, "cycles_domain_path", None)
    if cycles_domain_path is None:
        cycles_domain_path = getattr(args, "cycles", None)
    if cycles_domain_path is not None:
        meta["cycles_domain_path"] = str(cycles_domain_path)
    meta["storage_group_mode"] = _normalize_storage_group_mode(
        meta.get("storage_group_mode", getattr(args, "storage_group_mode", "legacy"))
    )
    meta["sampling_equivalence_mode"] = True

    same_cycle_effect_prob = _normalize_same_cycle_effect_prob(
        meta.get("same_cycle_effect_prob", getattr(args, "same_cycle_effect_prob", None))
    )
    meta["same_cycle_effect_prob"] = (
        _normalize_numeric(float(same_cycle_effect_prob))
        if same_cycle_effect_prob is not None
        else None
    )
    if "boundary_events_count_unit" not in meta:
        meta["boundary_events_count_unit"] = "event_instances"
    if "boundary_events_mass_unit" not in meta:
        meta["boundary_events_mass_unit"] = "weighted_injection_mass"
    if "boundary_events_mass_note" not in meta:
        meta["boundary_events_mass_note"] = (
            "boundary_events_count is the number of inject_cycle==read_cycle event "
            "instances; boundary_events_mass is the weighted injection mass of those "
            "instances before bit-width expansion."
        )
    boundary_bits_mass_total = _to_float_num(meta.get("boundary_bits_mass_total", 0.0))
    if boundary_bits_mass_total <= 0.0:
        boundary_events_mass_f = _to_float_num(meta.get("boundary_events_mass", 0.0))
        bit_count_hint = _to_float_num(meta.get("bit_count", 0.0))
        if boundary_events_mass_f > 0.0 and bit_count_hint > 0.0:
            boundary_bits_mass_total = float(boundary_events_mass_f) * float(bit_count_hint)
            meta["boundary_bits_mass_total"] = _normalize_count_num(boundary_bits_mass_total)
    if "boundary_bits_mass_total" in meta:
        affected_prob = _boundary_affected_prob_for_output(
            consumer_compare=str(meta.get("consumer_compare", getattr(args, "consumer_compare", "gt"))),
            same_cycle_effect_prob=same_cycle_effect_prob,
        )
        unaffected_prob = 1.0 - float(affected_prob)
        bits_total_f = _to_float_num(meta.get("boundary_bits_mass_total", 0.0))
        events_mass_f = _to_float_num(meta.get("boundary_events_mass", 0.0))
        if "boundary_bits_mass_affected" not in meta:
            meta["boundary_bits_mass_affected"] = _normalize_count_num(
                bits_total_f * float(affected_prob)
            )
        if "boundary_bits_mass_unaffected" not in meta:
            meta["boundary_bits_mass_unaffected"] = _normalize_count_num(
                bits_total_f * float(unaffected_prob)
            )
        if "boundary_events_mass_affected" not in meta:
            meta["boundary_events_mass_affected"] = _normalize_count_num(
                events_mass_f * float(affected_prob)
            )
        if "boundary_events_mass_unaffected" not in meta:
            meta["boundary_events_mass_unaffected"] = _normalize_count_num(
                events_mass_f * float(unaffected_prob)
            )

    def _effective_counts_with_policy(raw_counts: Any) -> Optional[Dict[str, float]]:
        if not isinstance(raw_counts, dict):
            return None
        total_v = _to_float_num(raw_counts.get("total", 0.0))
        masked_v = _to_float_num(raw_counts.get("masked", 0.0))
        sdc_v = _to_float_num(raw_counts.get("sdc", 0.0))
        due_v = _to_float_num(raw_counts.get("due", 0.0))
        unknown_v = _to_float_num(raw_counts.get("unknown", 0.0))
        return {
            "masked": float(masked_v),
            "sdc": float(sdc_v),
            "due": float(due_v),
            "unknown": float(unknown_v),
            "total": float(total_v),
        }

    def _rate_from_counts(raw_counts: Any) -> Optional[Dict[str, Any]]:
        eff = _effective_counts_with_policy(raw_counts)
        if eff is None:
            return None
        den = float(eff.get("total", 0.0))
        if den <= 0.0:
            return {"masked": 0.0, "sdc": 0.0, "due": 0.0, "unknown": 0.0}
        return {
            "masked": float(eff.get("masked", 0.0) / den),
            "sdc": float(eff.get("sdc", 0.0) / den),
            "due": float(eff.get("due", 0.0) / den),
            "unknown": float(eff.get("unknown", 0.0) / den),
        }

    unavailable_rate = {"masked": None, "sdc": None, "due": None, "unknown": None}
    blended_rate = out.get("classification_rates", {})
    if isinstance(blended_rate, dict):
        meta["rate_blended"] = {
            "masked": float(blended_rate.get("masked", 0.0)),
            "sdc": float(blended_rate.get("sdc", 0.0)),
            "due": float(blended_rate.get("due", 0.0)),
            "unknown": float(blended_rate.get("unknown", 0.0)),
        }
    else:
        meta["rate_blended"] = {"masked": 0.0, "sdc": 0.0, "due": 0.0, "unknown": 0.0}
    rate_gt = _rate_from_counts(meta.get("classification_counts_gt"))
    rate_ge = _rate_from_counts(meta.get("classification_counts_ge"))
    consumer_compare = str(meta.get("consumer_compare", getattr(args, "consumer_compare", "gt"))).strip().lower()
    if rate_gt is None:
        if consumer_compare == "gt":
            rate_gt = dict(meta.get("rate_blended", {}))
        else:
            rate_gt = dict(unavailable_rate)
    if rate_ge is None:
        if consumer_compare == "ge":
            rate_ge = dict(meta.get("rate_blended", {}))
        else:
            rate_ge = dict(unavailable_rate)
    meta["rate_gt"] = dict(rate_gt)
    meta["rate_ge"] = dict(rate_ge)

    _apply_sampling_space_domain_reconciliation(out, meta, args)
    _apply_trace_divergence_zero_diagnostics(meta, args)

    trace_policy_used_bits_total = int(meta.get("trace_policy_used_bits", 0))
    trace_policy_override_bits_total = int(meta.get("trace_policy_override_bits", 0))
    trace_policy_fallback_bits = max(
        0,
        int(trace_policy_used_bits_total) - int(trace_policy_override_bits_total),
    )
    trace_policy_used_mass_total = _to_float_num(meta.get("trace_policy_used_mass", 0))
    trace_policy_override_mass_total = _to_float_num(meta.get("trace_policy_override_mass", 0))
    trace_policy_fallback_mass = max(
        0.0,
        float(trace_policy_used_mass_total) - float(trace_policy_override_mass_total),
    )
    meta["trace_policy_fallback_bits"] = int(trace_policy_fallback_bits)
    meta["trace_policy_fallback_mass"] = _normalize_count_num(trace_policy_fallback_mass)
    meta["strict_ok"] = True
    meta["strict_fail_reasons"] = []
    meta["strict_fail_reason_counts"] = {}
    meta["strict_fail_report_path"] = ""
    meta["status"] = "ok"
    meta["status_reason"] = ""
    if bool(strict_replacement_enabled):
        strict_reasons: List[str] = []
        if _to_float_num(meta.get("unknown_mass", 0.0)) > 0.0:
            strict_reasons.append("unknown_classification_present")
        if (
            str(meta.get("cache_tag_exact_mode", "")).strip().lower()
            == "exact_global_readonly_alias_semantic"
            and int(_safe_int(meta.get("cache_tag_multievent_cycles", 0), 0)) > 0
            and int(_safe_int(meta.get("cache_tag_alias_intervals", 0), 0)) <= 0
        ):
            strict_reasons.append("cache_tag_multievent_cycle_unsupported")
        if strict_reasons:
            reason_counts = Counter(str(reason) for reason in strict_reasons)
            meta["strict_ok"] = False
            meta["strict_fail_reasons"] = sorted(reason_counts)
            meta["strict_fail_reason_counts"] = dict(reason_counts)
            meta["status"] = "strict_failed" if bool(strict_replacement_hard) else "ok"
            meta["status_reason"] = ",".join(sorted(reason_counts))
            report_path = getattr(args, "strict_fail_report", None)
            if report_path is not None:
                report = {
                    "strict_ok": False,
                    "strict_fail_reasons": list(meta["strict_fail_reasons"]),
                    "strict_fail_reason_counts": dict(reason_counts),
                    "fault_component": str(meta.get("fault_component", "")),
                    "cache_tag_exact_mode": str(meta.get("cache_tag_exact_mode", "")),
                    "cache_tag_multievent_cycles": int(
                        _safe_int(meta.get("cache_tag_multievent_cycles", 0), 0)
                    ),
                    "cache_tag_alias_intervals": int(
                        _safe_int(meta.get("cache_tag_alias_intervals", 0), 0)
                    ),
                    "unknown_mass": _normalize_count_num(
                        _to_float_num(meta.get("unknown_mass", 0.0))
                    ),
                }
                report_dst = Path(report_path)
                report_dst.parent.mkdir(parents=True, exist_ok=True)
                _json_dump_path(report_dst, report)
                meta["strict_fail_report_path"] = str(report_dst)

    final_counts = out.get("classification_counts", {})
    if isinstance(final_counts, dict):
        meta["total_bits"] = _safe_int(final_counts.get("total", meta.get("total_bits", 0)), 0)
        meta["unknown_mass"] = _normalize_count_num(
            _to_float_num(final_counts.get("unknown", meta.get("unknown_mass", 0)))
        )
        meta["unknown_bits"] = int(
            max(
                0,
                round(_to_float_num(final_counts.get("unknown", meta.get("unknown_bits", 0)))),
            )
        )
    if _to_float_num(out.get("classification_counts", {}).get("unknown", 0.0)) <= 0.0:
        meta["unknown_reason_counts"] = {}
        meta["unknown_source_bits"] = {}
        meta["unknown_mass_by_source"] = {}
        meta["unknown_source_mass_method"] = "zero_unknown_mass"

    out["exact_meta"] = meta
    return out


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Compute exact weighted masked/SDC/DUE rates using cycle/thread "
            "distribution, regfile first-consumer cycles, and analyzer bit classes"
        )
    )
    p.add_argument(
        "--analyzer-output",
        type=Path,
        default=None,
        help=(
            "Analyzer output JSON for single-component mode, or the default analyzer "
            "output for batch components that do not override via --component-analyzer."
        ),
    )
    p.add_argument(
        "--batch-components",
        type=str,
        default=None,
        help=(
            "Optional batch component list (colon/comma separated). When set, this "
            "script computes multiple exact components in one process and writes "
            "exact_rates_<component>.json files into --batch-output-dir."
        ),
    )
    p.add_argument(
        "--component-analyzer",
        action="append",
        default=[],
        help=(
            "Optional per-component analyzer override in the form "
            "<component>=<path>. May be repeated in --batch-components mode."
        ),
    )
    p.add_argument(
        "--batch-output-dir",
        type=Path,
        default=None,
        help=(
            "Output directory for per-component exact_rates_<component>.json files "
            "in --batch-components mode. Defaults to the directory of --output."
        ),
    )
    p.add_argument(
        "--batch-workers",
        type=int,
        default=0,
        help=(
            "Batch exact worker count. 0 auto-selects up to one worker per "
            "requested component in --batch-components mode."
        ),
    )
    p.add_argument(
        "--regfile-trace",
        type=Path,
        default=None,
        help="RF trace binary (required when --fault-component=rf)",
    )
    p.add_argument(
        "--trace-template",
        type=Path,
        default=None,
        help=(
            "Prepared trace template JSON (required when "
            "--fault-component=smem_rf/smem_lds/l1d/l2)"
        ),
    )
    p.add_argument("--cycles", type=Path, required=True)
    p.add_argument(
        "--active-threads-log",
        type=Path,
        default=None,
        help=(
            "JSONL/JSON active-thread log keyed by cycle. Required unless cycles JSON "
            "already embeds active_thread_ids/active_thread_ranges."
        ),
    )
    p.add_argument(
        "--thread-rand-max",
        type=int,
        default=0,
        help="Thread seed domain size [0..thread_rand_max-1] when --thread-rands is not set",
    )
    p.add_argument(
        "--thread-rands",
        type=str,
        default=None,
        help="Explicit thread seed values (colon/comma list), e.g. 0:1:2",
    )
    p.add_argument(
        "--block-rand-max",
        type=int,
        default=0,
        help=(
            "Shared-memory block seed domain size where seeds are drawn from "
            "[0..block_rand_max-1]. Used by smem_rf when --block-rands is not set."
        ),
    )
    p.add_argument(
        "--block-rands",
        type=str,
        default=None,
        help=(
            "Explicit shared-memory block seed values (colon/comma list). "
            "Used by smem_rf to mirror campaign block_rand samples."
        ),
    )
    p.add_argument(
        "--smem-size-bits",
        type=int,
        default=0,
        help=(
            "Shared-memory injection bit-domain size (SMEM_SIZE_BITS). "
            "Required for exact smem_rf campaign alignment; <=0 falls back to "
            "shared memory_ranges size."
        ),
    )
    p.add_argument(
        "--l1d-size-bits",
        type=int,
        default=0,
        help=(
            "L1D injection bit-domain size (L1D_SIZE_BITS from campaign/config). "
            "Required when --fault-component=l1d."
        ),
    )
    p.add_argument(
        "--l1d-line-size-bytes",
        type=int,
        default=L1D_LINE_SIZE_BYTES_DEFAULT,
        help=(
            "L1D cache line size in bytes. Used for l1d exact derivation "
            "(default: 128)."
        ),
    )
    p.add_argument(
        "--l1d-tag-bits",
        type=int,
        default=L1D_TAG_ARRAY_BITS_DEFAULT,
        help=(
            "Tag bits per L1D line in campaign bit-domain mapping "
            "(default: 57)."
        ),
    )
    p.add_argument(
        "--l1d-include-tag-bits",
        type=int,
        choices=(0, 1),
        default=1,
        help=(
            "Whether to include L1D tag-array bits in l1d denominator "
            "(1: include, 0: data-array only)."
        ),
    )
    p.add_argument(
        "--l1d-shaders",
        type=str,
        default=os.environ.get("L1D_SHADERS", "auto"),
        help=(
            "L1D shader seed domain: explicit list (e.g. 0:1), "
            "'auto' (prefer fi_sampling_space scope), or 'all' "
            "(expand to full [0..N-1] scope when N is known)."
        ),
    )
    p.add_argument(
        "--l1d-write-allocate",
        type=int,
        choices=(0, 1),
        default=0,
        help=(
            "Whether L1D stores can allocate cache lines for exact-validity windows "
            "(1: stores may start a line's vulnerable interval, 0: only loads do)."
        ),
    )
    p.add_argument(
        "--l2-size-bits",
        type=int,
        default=0,
        help=(
            "L2 injection bit-domain size (L2_SIZE_BITS from campaign/config). "
            "Required when --fault-component=l2."
        ),
    )
    p.add_argument(
        "--l2-line-size-bytes",
        type=int,
        default=L2_LINE_SIZE_BYTES_DEFAULT,
        help=(
            "L2 cache line size in bytes. Used for l2 exact derivation "
            "(default: 128)."
        ),
    )
    p.add_argument(
        "--l2-tag-bits",
        type=int,
        default=L2_TAG_ARRAY_BITS_DEFAULT,
        help=(
            "Tag bits per L2 line in campaign bit-domain mapping "
            "(default: 57)."
        ),
    )
    p.add_argument(
        "--l2-include-tag-bits",
        type=int,
        choices=(0, 1),
        default=1,
        help=(
            "Whether to include L2 tag-array bits in l2 denominator "
            "(1: include, 0: data-array only)."
        ),
    )
    p.add_argument(
        "--l2-global-prefill",
        type=int,
        choices=(0, 1),
        default=1,
        help=(
            "Whether to treat global L2 lines as prefilled from the earliest sampled cycle "
            "(1: enabled, 0: first in-kernel load cycle only)."
        ),
    )
    p.add_argument(
        "--registers",
        type=str,
        default=None,
        help=(
            "Register domain file (one label per line) or colon/comma list "
            "(required when --fault-component=rf)"
        ),
    )
    p.add_argument("--datatype-bits", type=int, required=True)
    p.add_argument(
        "--bits",
        type=str,
        default=None,
        help="Optional 1-based bit subset, colon/comma list",
    )
    p.add_argument(
        "--fault-component",
        choices=FAULT_COMPONENTS,
        default=os.environ.get("FAULT_COMPONENT", "rf").strip().lower(),
        help=(
            "Fault component model: "
            "rf (default), smem_rf (shared-memory persistent), "
            "smem_lds (ld.shared transient), "
            "l1d (L1D cache data/tag domain with shader sampling), "
            "l2 (L2 cache data/tag domain), "
            "gmem (program-visible global-memory byte versions)."
        ),
    )
    p.add_argument(
        "--addr-valid-ranges-path",
        type=Path,
        default=None,
        help=(
            "Optional JSON file containing memory ranges for address validity checks "
            "(list or object with memory_ranges/ranges)."
        ),
    )
    p.add_argument(
        "--strict-fail-report",
        type=Path,
        default=None,
        help=(
            "Path for strict diagnostics JSON when strict mode fails "
            "(default: <output_dir>/strict_fail_report.json)."
        ),
    )
    p.add_argument(
        "--fi-sampling-space-path",
        type=Path,
        default=None,
        help="Path to fi_sampling_space.json used to parameterize this run.",
    )
    p.add_argument(
        "--cycles-domain-path",
        type=Path,
        default=None,
        help="Path to the canonical FI cycles domain file consumed by this run.",
    )
    p.add_argument(
        "--disable-semantic-coverage",
        action="store_true",
        help=(
            "Ignore semantic coverage fields from analyzer output and derive semantic-disabled "
            "exact semantics directly from semantic-enabled analyzer payloads. "
            "Used by exact semantic-off reuse mode."
        ),
    )
    p.add_argument(
        "--storage-group-mode",
        type=str,
        default=os.environ.get("EXACT_STORAGE_GROUP_MODE", "legacy"),
        help=(
            "Storage exact grouping mode: 'legacy' keeps the original per-site/per-byte "
            "evaluation path, while 'grouped' enables similarity grouping/caching for "
            "RF/SMEM/L1D/L2 storage components."
        ),
    )
    p.add_argument("-o", "--output", type=Path, required=True)
    return p


def main() -> int:
    reject_removed_exact_semantic_overrides()
    args = build_arg_parser().parse_args()
    args = apply_canonical_exact_semantics(args)
    if getattr(args, "batch_components", None):
        out = compute_exact_batch(args)
        _json_dump_path(args.output, out)
        return 0
    if getattr(args, "analyzer_output", None) is None:
        raise ValueError("--analyzer-output is required unless --batch-components is used")
    out = compute_exact(args)
    out = finalize_exact_result(out, args)
    _json_dump_path(args.output, out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
