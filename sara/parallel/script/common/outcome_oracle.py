#!/usr/bin/env python3
"""Shared output oracle used by FI campaign parsing and semantic classification."""

import argparse
import csv
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

SUCCESS_SENTINEL = "Fault Injection Test Success!"
FAILED_SENTINEL = "Fault Injection Test Failed!"
GPUFI_OUTPUT_RE = re.compile(
    r"^GPUFI_OUTPUT\s+base=(0x[0-9a-fA-F]+)\s+bytes=([0-9]+)\s+name=([^\s]+)\s*$"
)
RAW_OUTPUT_RE = re.compile(
    r"^GPUFI_RAW_OUTPUT\s+(\S+)\s+(\S+)\s+([0-9]+)\s+([0-9a-fA-F]+)\s*$"
)
RAW_DTYPE_BYTES = {"f32": 4, "i32": 4, "u32": 4, "u8": 1}
CYCLE_RE = re.compile(r"^gpu_tot_sim_cycle\s*=\s*([0-9]+)\s*$")
DEFAULT_TIMEOUT_EXIT_STATUSES = {124, 137}
OUTPUT_VALUE_KEY_RE = re.compile(r"^(?P<space>[^:]+):0x(?P<addr>[0-9a-fA-F]+):(?P<size>[0-9]+)$")


def _to_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def _parse_timeout_statuses(spec: Optional[str]) -> Set[int]:
    if spec is None:
        return set(DEFAULT_TIMEOUT_EXIT_STATUSES)
    out: Set[int] = set()
    for tok in str(spec).replace(",", ":").split(":"):
        t = tok.strip()
        if not t:
            continue
        try:
            out.add(int(t, 0))
        except ValueError:
            continue
    if not out:
        out.update(DEFAULT_TIMEOUT_EXIT_STATUSES)
    return out


def _load_output_spec(raw: Any) -> List[Dict[str, Any]]:
    if raw is None:
        return []
    if isinstance(raw, (str, Path)):
        p = Path(raw)
        if not p.exists():
            return []
        try:
            raw = json.loads(p.read_text())
        except json.JSONDecodeError:
            return []
    if not isinstance(raw, list):
        return []
    out: List[Dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        if "base" not in item or "bytes" not in item:
            continue
        try:
            base = _to_int(item["base"])
            size = int(item["bytes"])
        except Exception:
            continue
        if size <= 0:
            continue
        ent = {
            "base": base,
            "bytes": size,
        }
        if item.get("name") is not None:
            ent["name"] = str(item["name"])
        for key in ("dtype", "count"):
            if key in item:
                ent[key] = item[key]
        out.append(ent)
    return out


def _expected_output_entries(output_spec: Sequence[Dict[str, Any]]) -> List[Tuple[int, int, str]]:
    out: List[Tuple[int, int, str]] = []
    for ent in output_spec:
        base = _to_int(ent.get("base", 0))
        size = int(ent.get("bytes", 0))
        if size <= 0:
            continue
        name = str(ent.get("name", "")).strip()
        out.append((base, size, name))
    return out


def _materialized_output_spec(
    output_spec: Optional[Sequence[Dict[str, Any]]],
    tol_policy: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    _ = tol_policy
    return _load_output_spec(output_spec)


def _load_log_summary(path: Path, *, text: Optional[str] = None) -> Dict[str, Any]:
    if not path.exists():
        return {
            "exists": False,
            "size_bytes": 0,
            "success": False,
            "failed": False,
            "cycles": None,
            "outputs": [],
            "output_set": set(),
        }

    if text is None:
        text = path.read_text(errors="replace")
    outputs: List[Dict[str, Any]] = []
    raw_outputs: Dict[str, Dict[str, Any]] = {}
    raw_errors: List[str] = []
    faults: List[Dict[str, str]] = []
    unsupported_semantics: List[str] = []
    unsupported_cache_model: List[str] = []
    invalid_configuration: List[str] = []
    cycles_val: Optional[int] = None
    success = False
    failed = False

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if SUCCESS_SENTINEL in line:
            success = True
        if FAILED_SENTINEL in line:
            failed = True
        if line.startswith("GPUFI_FAULT "):
            faults.append(dict(token.split("=", 1) for token in line.split()[1:] if "=" in token))
        for marker, evidence in (("GPUFI_UNSUPPORTED_SEMANTICS", unsupported_semantics),
                                 ("GPUFI_UNSUPPORTED_CACHE_MODEL", unsupported_cache_model),
                                 ("GPUFI_INVALID_CONFIGURATION", invalid_configuration)):
            if line == marker or line.startswith(marker + " "):
                evidence.append(line)

        m_cycle = CYCLE_RE.match(line)
        if m_cycle:
            try:
                cycles_val = int(m_cycle.group(1), 10)
            except ValueError:
                cycles_val = None

        m_out = GPUFI_OUTPUT_RE.match(line)
        if m_out:
            base = int(m_out.group(1), 0)
            size = int(m_out.group(2), 10)
            name = str(m_out.group(3))
            outputs.append({"base": base, "bytes": size, "name": name})
        elif line.startswith("GPUFI_OUTPUT"):
            raw_errors.append("malformed_output_declaration")
        if line.startswith("GPUFI_RAW_OUTPUT"):
            match = RAW_OUTPUT_RE.fullmatch(line)
            if match is None:
                raw_errors.append("malformed_raw_output")
                continue
            name, dtype, count_text, hexbytes = match.groups()
            count = int(count_text)
            width = RAW_DTYPE_BYTES.get(dtype)
            if name in raw_outputs:
                raw_errors.append("duplicate_raw_output:" + name)
                continue
            if width is None or count <= 0 or len(hexbytes) != count * (width or 0) * 2:
                raw_errors.append("invalid_raw_shape:" + name)
                continue
            raw_outputs[name] = {
                "dtype": dtype, "count": count, "bytes": count * width,
                "hexbytes": hexbytes.lower(),
            }

    output_set: Set[Tuple[int, int, str]] = {
        (int(item["base"]), int(item["bytes"]), str(item["name"])) for item in outputs
    }
    return {
        "exists": True,
        "size_bytes": path.stat().st_size,
        "success": success,
        "failed": failed,
        "cycles": cycles_val,
        "outputs": outputs,
        "output_set": output_set,
        "raw_outputs": raw_outputs,
        "raw_errors": raw_errors,
        "fault_evidence": faults,
        "unsupported_semantics": unsupported_semantics,
        "unsupported_cache_model": unsupported_cache_model,
        "invalid_configuration": invalid_configuration,
    }


def _validate_raw_summary(
    summary: Dict[str, Any], output_spec: Optional[Sequence[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Require one complete raw tensor for each declared final output."""
    if summary.get("invalid_configuration"):
        return {"valid": False, "reason": "invalid_simulator_configuration"}
    if summary.get("unsupported_semantics") or summary.get("unsupported_cache_model"):
        return {"valid": False, "reason": "unsupported_simulator_model"}
    if not summary.get("exists") or not summary.get("size_bytes"):
        return {"valid": False, "reason": "missing_log"}
    if summary.get("raw_errors"):
        return {"valid": False, "reason": summary["raw_errors"][0]}
    raw = summary.get("raw_outputs", {})
    if not raw:
        return {"valid": False, "reason": "missing_raw_outputs"}
    entries = list(summary.get("outputs", []))
    names = [str(item.get("name", "")) for item in entries]
    if not names or len(names) != len(set(names)) or any(not name for name in names):
        return {"valid": False, "reason": "invalid_output_declarations"}
    if set(names) != set(raw):
        return {"valid": False, "reason": "incomplete_raw_outputs"}
    for entry in entries:
        name = str(entry["name"])
        if int(entry["bytes"]) != raw[name]["bytes"]:
            return {"valid": False, "reason": "raw_declaration_size_mismatch:" + name}
    if output_spec is not None:
        if not isinstance(output_spec, list) or not output_spec:
            return {"valid": False, "reason": "invalid_output_spec"}
        for entry in output_spec:
            if not isinstance(entry, dict) or not all(k in entry for k in ("base", "bytes", "name")):
                return {"valid": False, "reason": "invalid_output_spec"}
            if (not isinstance(entry["name"], str) or not entry["name"] or
                    entry["name"].strip() != entry["name"] or
                    any(c.isspace() for c in entry["name"]) or
                    isinstance(entry["base"], bool) or isinstance(entry["bytes"], bool)):
                return {"valid": False, "reason": "invalid_output_spec"}
        try:
            expected = _expected_output_entries(output_spec)
        except (TypeError, ValueError):
            return {"valid": False, "reason": "invalid_output_spec"}
        if len(expected) != len(output_spec) or len(expected) != len(set(expected)):
            return {"valid": False, "reason": "invalid_output_spec"}
        if set(expected) != set(summary.get("output_set", set())):
            return {"valid": False, "reason": "missing_expected_output"}
        for entry in output_spec:
            tensor = raw[str(entry["name"])]
            if (("dtype" in entry and entry["dtype"] != tensor["dtype"]) or
                    ("count" in entry and entry["count"] != tensor["count"])):
                return {"valid": False, "reason": "raw_output_schema_mismatch"}
    declarations = {str(entry["name"]): entry for entry in entries}
    return {"valid": True, "reason": "complete_raw_outputs", "output_count": len(raw),
            "outputs": [{"name": name, "base": int(declarations[name]["base"]),
                         "dtype": tensor["dtype"], "count": tensor["count"],
                         "bytes": tensor["bytes"]}
                        for name, tensor in sorted(raw.items())]}


def _typed_summary(summary, output_spec, typed_output_contract):
    """Ignore ASLR only for explicitly declared host-derived outputs.

    Raw bytes, dtype, count and names remain part of the full-output checker.
    Device allocations keep the original strict address contract.
    """
    if typed_output_contract is None:
        return summary, output_spec
    doc = typed_output_contract
    if not isinstance(doc, dict) or doc.get("schema") != "sara-typed-output-contract-v1":
        raise ValueError("invalid typed output contract")
    rows = doc.get("outputs")
    if not isinstance(rows, list) or not rows:
        raise ValueError("typed output contract needs complete outputs")
    names = set()
    host = set()
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get("name"), str)
                or not row["name"] or row["name"] in names
                or row.get("dtype") not in RAW_DTYPE_BYTES
                or type(row.get("count")) is not int or row["count"] <= 0
                or row.get("bytes") != RAW_DTYPE_BYTES[row["dtype"]] * row["count"]
                or row.get("address_kind") not in {"device_global", "host_derived"}):
            raise ValueError("invalid typed output row")
        names.add(row["name"])
        if row["address_kind"] == "host_derived":
            host.add(row["name"])
    raw = summary.get("raw_outputs", {})
    mismatch = raw and (set(raw) != names or any(
            row["name"] in raw and
            (raw[row["name"]]["dtype"], raw[row["name"]]["count"], raw[row["name"]]["bytes"])
            != (row["dtype"], row["count"], row["bytes"]) for row in rows))
    normalized = dict(summary)
    if mismatch:
        normalized["raw_errors"] = list(summary.get("raw_errors", [])) + ["typed_raw_output_schema_mismatch"]
    normalized["outputs"] = [dict(row, base=0 if row["name"] in host else row["base"])
                             for row in summary.get("outputs", [])]
    normalized["output_set"] = {(row["base"], row["bytes"], row["name"])
                                for row in normalized["outputs"]}
    if output_spec is not None:
        if {row.get("name") for row in output_spec} != names:
            raise ValueError("typed output spec is incomplete")
        output_spec = [dict(row, base=0 if row["name"] in host else row["base"])
                       for row in output_spec]
    return normalized, output_spec


def validate_raw_outputs(
    log: Path, output_spec: Optional[Sequence[Dict[str, Any]]] = None,
    *, typed_output_contract=None,
) -> Dict[str, Any]:
    """Validate a golden/run log without trusting legacy Success strings.

    A tensor is declared with GPUFI_OUTPUT and materialized with
    GPUFI_RAW_OUTPUT <name> <dtype> <count> <hexbytes>. Bytes are little-endian.
    """
    summary, output_spec = _typed_summary(_load_log_summary(Path(log)), output_spec,
                                          typed_output_contract)
    return _validate_raw_summary(summary, output_spec)


def _empty_log_summary() -> Dict[str, Any]:
    return {
        "exists": False,
        "size_bytes": 0,
        "success": False,
        "failed": False,
        "cycles": None,
        "outputs": [],
        "output_set": set(),
    }


def _opt_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    return bool(value)


def _detail(
    *,
    reason: str,
    golden_summary: Dict[str, Any],
    run_summary: Dict[str, Any],
    expected_outputs: Sequence[Tuple[int, int, str]],
    exit_status: Optional[int],
) -> Dict[str, Any]:
    missing_expected: List[Tuple[int, int, str]] = []
    if expected_outputs:
        run_set = set(run_summary.get("output_set", set()))
        for ent in expected_outputs:
            if ent[2]:
                if ent not in run_set:
                    missing_expected.append(ent)
            else:
                if not any((rbase == ent[0] and rbytes == ent[1]) for rbase, rbytes, _n in run_set):
                    missing_expected.append(ent)

    g_exists = _opt_bool(golden_summary.get("exists"))
    r_exists = _opt_bool(run_summary.get("exists"))
    g_success = _opt_bool(golden_summary.get("success"))
    g_failed = _opt_bool(golden_summary.get("failed"))
    r_success = _opt_bool(run_summary.get("success"))
    r_failed = _opt_bool(run_summary.get("failed"))

    out: Dict[str, Any] = {
        "reason": reason,
        "exit_status": exit_status,
        "golden_log_exists": g_exists,
        "run_log_exists": r_exists,
        "golden_success_sentinel": g_success,
        "golden_failed_sentinel": g_failed,
        "run_success_sentinel": r_success,
        "run_failed_sentinel": r_failed,
        # Backward-compatible aliases.
        "golden_success": g_success,
        "golden_failed": g_failed,
        "run_success": r_success,
        "run_failed": r_failed,
        "golden_cycles": golden_summary.get("cycles"),
        "run_cycles": run_summary.get("cycles"),
        "cycles_match": (
            golden_summary.get("cycles") == run_summary.get("cycles")
            if golden_summary.get("cycles") is not None and run_summary.get("cycles") is not None
            else None
        ),
        # Keep the exact compared words in the atomic FI result, so a public
        # result can be checked without keeping simulator progress logs. These
        # are parsed observations, not a new outcome or completeness rule.
        "raw_output_witness": {
            "schema": "sara-observed-raw-output-bytes-v1",
            "golden": {key: golden_summary.get(key, {} if key == "raw_outputs" else [])
                       for key in ("outputs", "raw_outputs", "raw_errors")},
            "run": {key: run_summary.get(key, {} if key == "raw_outputs" else [])
                    for key in ("outputs", "raw_outputs", "raw_errors")},
        },
        "golden_output_count": len(golden_summary.get("outputs", [])),
        "run_output_count": len(run_summary.get("outputs", [])),
        "missing_expected_outputs": [
            {"base": f"0x{base:016x}", "bytes": int(size), "name": name}
            for base, size, name in missing_expected
        ],
    }
    faults = list(run_summary.get("fault_evidence", []))
    statuses = {item.get("status") for item in faults}
    fault_status = ("unsupported" if "unsupported" in statuses else
                    "rejected" if "rejected" in statuses else
                    "applied" if "applied" in statuses or "propagated" in statuses else
                    "armed" if "armed" in statuses else
                    "unmapped" if "unmapped" in statuses else "not_observed")
    out["fault_status"] = fault_status
    out["fault_evidence"] = faults
    semantic_evidence = {"golden": list(golden_summary.get("unsupported_semantics", [])),
                         "run": list(run_summary.get("unsupported_semantics", []))}
    cache_evidence = {"golden": list(golden_summary.get("unsupported_cache_model", [])),
                      "run": list(run_summary.get("unsupported_cache_model", []))}
    configuration_evidence = {"golden": list(golden_summary.get("invalid_configuration", [])),
                              "run": list(run_summary.get("invalid_configuration", []))}
    if any(configuration_evidence.values()):
        out["error_kind"] = "invalid_simulator_configuration"
        out["invalid_configuration"] = configuration_evidence
    elif any(semantic_evidence.values()):
        out["error_kind"] = "instruction_semantics_unsupported"
        out["unsupported_semantics"] = semantic_evidence
    elif any(cache_evidence.values()) or fault_status == "unsupported":
        out["error_kind"] = "cache_model_unsupported"
        out["unsupported_cache_model"] = cache_evidence
    elif fault_status == "rejected":
        out["error_kind"] = "fault_configuration"
    elif reason == "fault_not_observed":
        out["error_kind"] = "instrumentation"
    if out.get("error_kind"):
        out["scientific_outcome_usable"] = False
    return out


def _detail_minimal_due(
    *,
    reason: str,
    output_spec: Optional[Sequence[Dict[str, Any]]],
    run_output_set: Optional[Set[Tuple[int, int, str]]] = None,
    exit_status: Optional[int] = None,
    golden_reference_available: Optional[bool] = None,
    run_reference_available: Optional[bool] = None,
) -> Dict[str, Any]:
    gsum = _empty_log_summary()
    rsum = _empty_log_summary()
    if golden_reference_available is not None:
        gsum["exists"] = bool(golden_reference_available)
    if run_reference_available is not None:
        rsum["exists"] = bool(run_reference_available)
    if run_output_set is not None:
        rsum["output_set"] = set(run_output_set)
    return _detail(
        reason=reason,
        golden_summary=gsum,
        run_summary=rsum,
        expected_outputs=_expected_output_entries(output_spec or []),
        exit_status=exit_status,
    )


def _normalize_text(value: Any, tol_policy: Optional[Dict[str, Any]]) -> str:
    s = str(value)
    policy = tol_policy or {}
    if bool(policy.get("text_trim", True)):
        s = s.strip()
    if bool(policy.get("collapse_whitespace", False)):
        s = " ".join(s.split())
    return s


def _as_float(value: Any) -> Optional[float]:
    try:
        return float(str(value).strip())
    except Exception:
        return None


def _normalize_scalar_kind(kind: Any) -> str:
    return str(kind or "").strip().lower()


def _exact_output_policy() -> Dict[str, Any]:
    """Return the repository-wide exact-output SDC policy.

    FI/SARA/GEREM-all experiments now classify any final output mismatch as
    SDC for every application, including floating-point applications.  Shared
    oracle callers may still pass legacy tolerance-policy JSON; normalize it
    away here so stale result directories or environment values cannot
    re-enable tolerance during run_experiment.sh campaigns.
    """
    return {
        "compare_kind": "exact",
        "nan_equal": False,
        "inf_sign_must_match": True,
        "scalar_kind": "",
        "print_format": "",
        "print_precision": None,
        "text_trim": True,
        "collapse_whitespace": False,
        "device_materialized": True,
        "materialized_via": "",
    }


def resolve_output_policy(
    tol_policy: Optional[Dict[str, Any]],
    *,
    output_name: Optional[str] = None,
    output_index: Optional[int] = None,
) -> Dict[str, Any]:
    _ = (tol_policy, output_name, output_index)
    return _exact_output_policy()


def output_is_device_materialized(
    tol_policy: Optional[Dict[str, Any]],
    *,
    output_name: Optional[str] = None,
    output_index: Optional[int] = None,
) -> bool:
    _ = (tol_policy, output_name, output_index)
    return True


def _parse_output_value_key(key: str) -> Optional[Tuple[str, int, int]]:
    match = OUTPUT_VALUE_KEY_RE.match(str(key).strip())
    if match is None:
        return None
    return (
        str(match.group("space")),
        int(match.group("addr"), 16),
        int(match.group("size"), 10),
    )


def _int_from_raw(value: Any) -> Optional[int]:
    if isinstance(value, int):
        return int(value)
    try:
        s = str(value).strip()
    except Exception:
        return None
    if not s:
        return None
    try:
        return int(s, 0)
    except ValueError:
        return None


def _sign_extend(value: int, bits: int) -> int:
    if bits <= 0:
        return 0
    mask = (1 << bits) - 1
    value &= mask
    sign = 1 << (bits - 1)
    return value - (1 << bits) if (value & sign) != 0 else value


def _coerce_scalar_value(
    value: Any,
    scalar_kind: Any,
    *,
    size_bytes: Optional[int] = None,
) -> Any:
    kind = _normalize_scalar_kind(scalar_kind)
    if kind in ("float32", "float64", "float"):
        return _as_float(value)

    raw_int = _int_from_raw(value)
    if raw_int is None:
        return value

    if kind == "int8":
        return _sign_extend(raw_int, 8)
    if kind == "uint8":
        return raw_int & 0xFF
    if kind == "int16":
        return _sign_extend(raw_int, 16)
    if kind == "uint16":
        return raw_int & 0xFFFF
    if kind == "int32":
        return _sign_extend(raw_int, 32)
    if kind == "uint32":
        return raw_int & 0xFFFFFFFF
    if kind == "int64":
        return _sign_extend(raw_int, 64)
    if kind == "uint64":
        return raw_int & 0xFFFFFFFFFFFFFFFF

    if size_bytes is not None:
        bits = int(size_bytes) * 8
        if bits in (8, 16, 32, 64):
            return _sign_extend(raw_int, bits)
    return raw_int


def _format_serialized_scalar(value: Any, policy: Dict[str, Any]) -> str:
    kind = _normalize_scalar_kind(policy.get("scalar_kind"))
    fmt = str(policy.get("print_format", "") or "").strip()
    precision = policy.get("print_precision")
    if kind.startswith("float"):
        fv = _as_float(value)
        if fv is None:
            return str(value)
        if precision is None:
            precision = 6
        return format(float(fv), f".{int(precision)}f")
    iv = _int_from_raw(value)
    if iv is None:
        return str(value)
    if fmt.endswith(("x", "X")):
        return format(int(iv), "x" if fmt.endswith("x") else "X")
    return str(int(iv))


def serialized_reference_value(
    raw_value: Any,
    tol_policy: Optional[Dict[str, Any]],
    *,
    output_name: Optional[str] = None,
    output_index: Optional[int] = None,
    size_bytes: Optional[int] = None,
) -> Any:
    policy = resolve_output_policy(
        tol_policy,
        output_name=output_name,
        output_index=output_index,
    )
    return _coerce_scalar_value(raw_value, policy.get("scalar_kind"), size_bytes=size_bytes)


def _value_equal(a: Any, b: Any, tol_policy: Optional[Dict[str, Any]]) -> bool:
    _ = tol_policy
    policy = _exact_output_policy()
    scalar_kind = _normalize_scalar_kind(policy.get("scalar_kind"))
    if scalar_kind:
        a = _coerce_scalar_value(a, scalar_kind)
        b = _coerce_scalar_value(b, scalar_kind)
    fa = _as_float(a)
    fb = _as_float(b)
    if fa is not None and fb is not None:
        if math.isnan(fa) or math.isnan(fb):
            return False
        if math.isinf(fa) or math.isinf(fb):
            return math.isinf(fa) and math.isinf(fb) and math.copysign(1.0, fa) == math.copysign(1.0, fb)
    return a == b


def compare_observations(
    golden: Dict[str, Any],
    run: Dict[str, Any],
    output_spec: Optional[Sequence[Dict[str, Any]]] = None,
    tol_policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    run_failed = bool(run.get("run_failed", False))
    run_missing_output = bool(run.get("missing_output", False))
    if run_failed:
        return {
            "classification": "due",
            "detail": _detail_minimal_due(
                reason="run_failed",
                output_spec=output_spec,
            ),
        }
    if run_missing_output:
        return {
            "classification": "due",
            "detail": _detail_minimal_due(
                reason="missing_expected_output",
                output_spec=output_spec,
            ),
        }

    gout = golden.get("outputs")
    rout = run.get("outputs")
    effective_output_spec = _materialized_output_spec(output_spec, tol_policy)
    gsig = golden.get("output_signature")
    rsig = run.get("output_signature")
    if gsig is not None and rsig is not None:
        return {
            "classification": "masked" if gsig == rsig else "sdc",
            "detail": {"reason": "signature_compare"},
        }

    if isinstance(gout, dict) and isinstance(rout, dict):
        if set(gout.keys()) != set(rout.keys()):
            return {
                "classification": "sdc",
                "detail": {"reason": "output_map_compare"},
            }
        same = True
        for key in sorted(gout.keys()):
            if not _value_equal(gout.get(key), rout.get(key), tol_policy):
                same = False
                break
        return {
            "classification": "masked" if same else "sdc",
            "detail": {"reason": "output_map_compare"},
        }

    spec_entries = _expected_output_entries(effective_output_spec)
    gset = set(golden.get("output_set", set()))
    rset = set(run.get("output_set", set()))
    if spec_entries:
        missing = False
        for base, size, name in spec_entries:
            if name:
                if (base, size, name) not in rset:
                    missing = True
                    break
            else:
                if not any((rb == base and rs == size) for rb, rs, _rn in rset):
                    missing = True
                    break
        if missing:
            return {
                "classification": "due",
                "detail": _detail_minimal_due(
                    reason="missing_expected_output",
                    output_spec=output_spec,
                    run_output_set=rset,
                ),
            }

    if gset or rset:
        return {
            "classification": "masked" if gset == rset else "sdc",
            "detail": {"reason": "output_entry_compare"},
        }

    return {
        "classification": "due",
        "detail": _detail_minimal_due(
            reason="no_comparable_outputs",
            output_spec=output_spec,
        ),
    }


def classify_fi_logs(
    *,
    golden_log: Path,
    run_log: Path,
    output_spec: Optional[Sequence[Dict[str, Any]]] = None,
    tol_policy: Optional[Dict[str, Any]] = None,
    exit_status: Optional[int] = None,
    timeout_exit_statuses: Optional[Iterable[int]] = None,
    output_mode: str = "raw",
    require_fault_evidence: bool = False,
    typed_output_contract=None,
    golden_summary=None,
    run_summary=None,
) -> Dict[str, Any]:
    if output_mode not in {"raw", "legacy"}:
        raise ValueError("output_mode must be raw or explicit legacy")
    timeout_set = (
        set(int(x) for x in timeout_exit_statuses)
        if timeout_exit_statuses is not None
        else set(DEFAULT_TIMEOUT_EXIT_STATUSES)
    )
    gsum = golden_summary if golden_summary is not None else _load_log_summary(golden_log)
    rsum = run_summary if run_summary is not None else _load_log_summary(run_log)
    gsum, output_spec = _typed_summary(gsum, output_spec, typed_output_contract)
    rsum, _ = _typed_summary(rsum, output_spec, typed_output_contract)
    effective_output_spec = _materialized_output_spec(output_spec, tol_policy)
    spec_entries = _expected_output_entries(effective_output_spec)

    if any(summary.get("invalid_configuration") for summary in (gsum, rsum)):
        return {"classification": "due",  # legacy internal vocabulary only
                "detail": _detail(reason="invalid_simulator_configuration", golden_summary=gsum,
                                  run_summary=rsum, expected_outputs=spec_entries,
                                  exit_status=exit_status)}

    if any(summary.get(key) for summary in (gsum, rsum)
           for key in ("unsupported_semantics", "unsupported_cache_model")):
        # Keep the legacy classification vocabulary, but explicitly mark this
        # row ineligible as a fault outcome. Campaign executors reject error_kind.
        return {"classification": "due",
                "detail": _detail(reason="unsupported_simulator_model", golden_summary=gsum,
                                  run_summary=rsum, expected_outputs=spec_entries,
                                  exit_status=exit_status)}

    if not bool(gsum.get("exists", False)) or int(gsum.get("size_bytes", 0)) <= 0:
        return {
            "classification": "due",
            "detail": _detail(
                reason="invalid_path",
                golden_summary=gsum,
                run_summary=rsum,
                expected_outputs=spec_entries,
                exit_status=exit_status,
            ),
        }

    if exit_status is not None and int(exit_status) in timeout_set:
        return {
            "classification": "due",
            "detail": _detail(
                reason="timeout_exit_status",
                golden_summary=gsum,
                run_summary=rsum,
                expected_outputs=spec_entries,
                exit_status=int(exit_status),
            ),
        }

    if not bool(rsum.get("exists", False)) or int(rsum.get("size_bytes", 0)) <= 0:
        return {
            "classification": "due",
            "detail": _detail(
                reason="missing_log",
                golden_summary=gsum,
                run_summary=rsum,
                expected_outputs=spec_entries,
                exit_status=exit_status,
            ),
        }

    if exit_status is not None and int(exit_status) != 0:
        return {
            "classification": "due",
            "detail": _detail(
                reason="abnormal_exit_status",
                golden_summary=gsum,
                run_summary=rsum,
                expected_outputs=spec_entries,
                exit_status=int(exit_status),
            ),
        }

    faults = rsum.get("fault_evidence", [])
    rejected = any(item.get("status") == "rejected" for item in faults)
    if rejected or (require_fault_evidence and not faults):
        return {
            "classification": "due",
            "detail": _detail(reason="rejected_fault_configuration" if rejected else "fault_not_observed",
                              golden_summary=gsum, run_summary=rsum,
                              expected_outputs=spec_entries, exit_status=exit_status),
        }

    if output_mode == "raw":
        golden_check = _validate_raw_summary(gsum, output_spec)
        run_check = _validate_raw_summary(rsum, output_spec if output_spec is not None else gsum.get("outputs"))
        if not golden_check["valid"] or not run_check["valid"]:
            reason = ("invalid_golden_raw:" + golden_check["reason"]
                      if not golden_check["valid"] else run_check["reason"])
            return {
                "classification": "due",
                "detail": _detail(reason=reason, golden_summary=gsum,
                                  run_summary=rsum, expected_outputs=spec_entries,
                                  exit_status=exit_status),
            }
        golden_raw = gsum["raw_outputs"]
        run_raw = rsum["raw_outputs"]
        shape_equal = set(golden_raw) == set(run_raw) and all(
            (golden_raw[name]["dtype"], golden_raw[name]["count"]) ==
            (run_raw[name]["dtype"], run_raw[name]["count"])
            for name in golden_raw
        )
        if not shape_equal:
            classification, reason = "due", "raw_output_schema_mismatch"
        else:
            same = all(golden_raw[name]["hexbytes"] == run_raw[name]["hexbytes"]
                       for name in golden_raw)
            classification, reason = ("masked" if same else "sdc"), "raw_bytes_compare"
        return {
            "classification": classification,
            "detail": _detail(reason=reason, golden_summary=gsum,
                              run_summary=rsum, expected_outputs=spec_entries,
                              exit_status=exit_status),
        }

    obs_g = {
        "run_failed": False,
        "missing_output": False,
        "output_set": gsum.get("output_set", set()),
    }
    obs_r = {
        "run_failed": False,
        "missing_output": False,
        "output_set": rsum.get("output_set", set()),
    }

    if spec_entries:
        run_set = set(rsum.get("output_set", set()))
        missing_expected = False
        for base, size, name in spec_entries:
            if name:
                if (base, size, name) not in run_set:
                    missing_expected = True
                    break
            else:
                if not any((rb == base and rs == size) for rb, rs, _rn in run_set):
                    missing_expected = True
                    break
        if missing_expected:
            return {
                "classification": "due",
                "detail": _detail(
                    reason="missing_expected_output",
                    golden_summary=gsum,
                    run_summary=rsum,
                    expected_outputs=spec_entries,
                    exit_status=exit_status,
                ),
            }

    if bool(rsum.get("success", False)) and not bool(rsum.get("failed", False)):
        cls = "masked"
        reason = "success_sentinel"
    elif bool(rsum.get("failed", False)) and not bool(rsum.get("success", False)):
        cls = "sdc"
        reason = "failure_sentinel"
    elif not bool(rsum.get("success", False)) and not bool(rsum.get("failed", False)):
        cls = "due"
        reason = "non_success_sentinel"
    else:
        oracle_result = compare_observations(
            obs_g,
            obs_r,
            output_spec=effective_output_spec,
            tol_policy=tol_policy,
        )
        cls = str(oracle_result.get("classification", "masked")).lower()
        reason = str(oracle_result.get("detail", {}).get("reason", "entry_compare"))

    return {
        "classification": cls,
        "detail": _detail(
            reason=reason,
            golden_summary=gsum,
            run_summary=rsum,
            expected_outputs=spec_entries,
            exit_status=exit_status,
        ),
    }


def _resolve_log_like(path_like: Any, default_names: Sequence[str]) -> Optional[Path]:
    if path_like is None:
        return None
    p = Path(path_like)
    if p.is_file():
        return p
    if p.is_dir():
        for name in default_names:
            cand = p / name
            if cand.is_file():
                return cand
    return p


def compare_outputs(
    golden_dir: Any,
    run_dir: Any,
    output_spec: Any,
    tol_policy: Any,
    *, output_mode: str = "raw",
) -> Dict[str, Any]:
    """Compare run outputs against golden outputs using unified oracle semantics."""
    if output_mode == "raw" and isinstance(output_spec, (str, Path)):
        spec = json.loads(Path(output_spec).read_text())
    else:
        spec = output_spec if output_mode == "raw" else _load_output_spec(output_spec)
    policy = tol_policy if isinstance(tol_policy, dict) else {}
    golden_log = _resolve_log_like(golden_dir, ("golden.log", "run.log", "tmp.out"))
    run_log = _resolve_log_like(run_dir, ("run.log", "tmp.out", "golden.log"))
    if golden_log is None or run_log is None:
        return {
            "classification": "due",
            "detail": _detail(
                reason="invalid_path",
                golden_summary=_empty_log_summary(),
                run_summary=_empty_log_summary(),
                expected_outputs=_expected_output_entries(spec or []),
                exit_status=None,
            ),
        }
    return classify_fi_logs(
        golden_log=golden_log,
        run_log=run_log,
        output_spec=spec,
        tol_policy=policy,
        output_mode=output_mode,
    )


def compare_semantic_outputs(
    *,
    golden_signature: Optional[Dict[str, Any]],
    run_signature: Optional[Dict[str, Any]],
    golden_outputs: Optional[Dict[str, Any]] = None,
    run_outputs: Optional[Dict[str, Any]] = None,
    run_failed: bool = False,
    run_missing_output: bool = False,
    run_error_kind: Optional[str] = None,
    run_error_type: Optional[str] = None,
    golden_error_kind: Optional[str] = None,
    golden_error_type: Optional[str] = None,
    output_spec: Optional[Sequence[Dict[str, Any]]] = None,
    tol_policy: Optional[Dict[str, Any]] = None,
    golden_reference_available: Optional[bool] = None,
) -> Dict[str, Any]:
    golden_has_reference = (
        bool(golden_reference_available)
        if golden_reference_available is not None
        else (
            (golden_signature is not None)
            or (isinstance(golden_outputs, dict) and len(golden_outputs) > 0)
        )
    )
    run_has_reference = (
        (run_signature is not None)
        or (isinstance(run_outputs, dict) and len(run_outputs) > 0)
    )

    run_err_kind_s = str(run_error_kind or "").strip()
    run_err_type_s = str(run_error_type or "").strip()
    golden_err_kind_s = str(golden_error_kind or "").strip()
    golden_err_type_s = str(golden_error_type or "").strip()
    run_err_type_lc = run_err_type_s.lower()

    def _augment_detail(detail: Dict[str, Any]) -> Dict[str, Any]:
        out = dict(detail)
        if run_err_kind_s:
            out["run_error_kind"] = run_err_kind_s
        if run_err_type_s:
            out["run_error_type"] = run_err_type_s
        if golden_err_kind_s:
            out["golden_error_kind"] = golden_err_kind_s
        if golden_err_type_s:
            out["golden_error_type"] = golden_err_type_s
        return out

    if bool(run_failed):
        reason = "run_failed"
        classification = "due"
        if run_err_type_lc == "outofrangememoryaccess":
            reason = "out_of_range_memory_access"
        elif run_err_type_lc == "maxstepsexceeded":
            reason = "max_steps_exceeded"
        elif run_err_type_lc == "uninitializedload":
            reason = "uninitialized_load"
        elif run_err_type_lc == "missingbytes":
            reason = "missing_bytes"
        elif not golden_has_reference:
            reason = "invalid_path"

        detail = _detail_minimal_due(
            reason=reason,
            output_spec=output_spec,
            exit_status=None,
            golden_reference_available=golden_has_reference,
            run_reference_available=run_has_reference,
        )
        detail = _augment_detail(detail)
        return {
            "classification": classification,
            "detail": detail,
        }
    if bool(run_missing_output):
        return {
            "classification": "due",
            "detail": _augment_detail(_detail_minimal_due(
                reason="missing_expected_output",
                output_spec=output_spec,
                exit_status=None,
                golden_reference_available=golden_has_reference,
                run_reference_available=run_has_reference,
            )),
        }

    golden_obs: Dict[str, Any] = {
        "run_failed": False,
        "missing_output": False,
    }
    run_obs: Dict[str, Any] = {
        "run_failed": bool(run_failed),
        "missing_output": bool(run_missing_output),
    }
    if golden_signature is not None:
        golden_obs["output_signature"] = golden_signature
    if run_signature is not None:
        run_obs["output_signature"] = run_signature
    if golden_outputs is not None:
        golden_obs["outputs"] = dict(golden_outputs)
    if run_outputs is not None:
        run_obs["outputs"] = dict(run_outputs)
    return compare_observations(
        golden_obs,
        run_obs,
        output_spec=output_spec,
        tol_policy=tol_policy,
    )


def _coerce_int_optional(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        s = str(value).strip()
    except Exception:
        return None
    if not s:
        return None
    try:
        return int(s, 0)
    except ValueError:
        return None


def _normalize_run_id(value: Any, fallback: int) -> str:
    if value is None:
        return str(int(fallback))
    s = str(value).strip()
    return s if s else str(int(fallback))


def _batch_sort_key(run_id: str) -> Tuple[int, Any]:
    try:
        return (0, int(run_id, 0))
    except Exception:
        return (1, str(run_id))


def _resolve_batch_run_log(
    entry: Dict[str, Any],
    *,
    batch_dir: Optional[Path],
    run_log_name: str,
) -> Path:
    run_log_raw = entry.get("run_log", entry.get("run_log_path"))
    if run_log_raw is not None:
        p = Path(str(run_log_raw))
        if p.is_file():
            return p
        if p.is_dir():
            cand = p / run_log_name
            if cand.is_file():
                return cand
        return p

    tmp_file = str(entry.get("tmp_file", "")).strip() or run_log_name
    run_batch = _coerce_int_optional(entry.get("run_batch"))
    run_id = _normalize_run_id(entry.get("run_id", entry.get("trial")), 0)

    candidates: List[Path] = []
    if batch_dir is not None:
        root = Path(batch_dir)
        if run_batch is not None:
            candidates.append(root / f"run_{int(run_batch)}" / tmp_file)
            candidates.append(root / str(int(run_batch)) / tmp_file)
            candidates.append(root / f"logs{int(run_batch)}" / tmp_file)
        try:
            run_id_i = int(run_id, 0)
            candidates.append(root / f"run_{run_id_i}" / tmp_file)
        except Exception:
            pass
        candidates.append(root / tmp_file)

    for cand in candidates:
        if cand.is_file():
            return cand
    if candidates:
        return candidates[0]
    return Path(tmp_file)


def _load_batch_entries_from_json(path: Path) -> List[Dict[str, Any]]:
    raw = json.loads(path.read_text())
    if isinstance(raw, dict):
        rows = raw.get("entries")
    else:
        rows = raw
    if not isinstance(rows, list):
        raise ValueError(f"{path}: batch JSON must be a list or {{'entries':[...]}}")
    out: List[Dict[str, Any]] = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"{path}: entries[{i}] must be an object")
        out.append(dict(row))
    return out


def _load_batch_entries_from_csv(path: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            out.append(dict(row))
    return out


def _load_batch_entries_from_text(path: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = [tok.strip() for tok in re.split(r"[,\t ]+", s) if tok.strip()]
        if len(parts) < 2:
            continue
        row: Dict[str, Any] = {
            "run_id": parts[0],
            "run_log": parts[1],
        }
        if len(parts) >= 3:
            row["exit_status"] = parts[2]
        out.append(row)
    return out


def _load_batch_entries(path: Path) -> List[Dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return _load_batch_entries_from_json(path)
    if suffix in (".csv", ".tsv"):
        return _load_batch_entries_from_csv(path)
    # Try CSV header first; fallback to loose text mode.
    try:
        rows = _load_batch_entries_from_csv(path)
        if rows:
            return rows
    except Exception:
        pass
    return _load_batch_entries_from_text(path)


def _discover_batch_entries_from_dir(batch_dir: Path, run_log_name: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not batch_dir.exists():
        return out

    for sub in sorted(batch_dir.iterdir(), key=lambda p: p.name):
        if not sub.is_dir():
            continue
        name = sub.name
        run_batch: Optional[int] = None
        if name.startswith("run_"):
            run_batch = _coerce_int_optional(name[len("run_"):])
        elif name.startswith("logs"):
            run_batch = _coerce_int_optional(name[len("logs"):])
        elif name.isdigit():
            run_batch = _coerce_int_optional(name)
        if run_batch is None:
            continue

        log_path = sub / run_log_name
        if not log_path.is_file():
            continue
        exit_status_path = sub / "exit_status1"
        trial_id_path = sub / "trial_id1"
        row: Dict[str, Any] = {
            "run_id": str(int(run_batch)),
            "run_batch": str(int(run_batch)),
            "run_log": str(log_path),
            "tmp_file": run_log_name,
        }
        if trial_id_path.is_file():
            row["run_id"] = trial_id_path.read_text().strip() or row["run_id"]
        if exit_status_path.is_file():
            row["exit_status"] = exit_status_path.read_text().strip()
        out.append(row)
    return out


def _classify_batch_entry(task: Dict[str, Any]) -> Dict[str, Any]:
    run_id = str(task.get("run_id", ""))
    run_log = Path(str(task.get("run_log", "")))
    exit_status = task.get("exit_status")
    timeout_statuses = set(int(x) for x in task.get("timeout_exit_statuses", []))
    output_spec = task.get("output_spec")
    tol_policy = task.get("tol_policy")
    if not isinstance(tol_policy, dict):
        tol_policy = {}

    result = classify_fi_logs(
        golden_log=Path(str(task["golden_log"])),
        run_log=run_log,
        output_spec=output_spec,
        tol_policy=tol_policy,
        exit_status=exit_status,
        timeout_exit_statuses=timeout_statuses,
        output_mode=str(task.get("output_mode", "raw")),
        require_fault_evidence=bool(task.get("require_fault_evidence", False)),
    )
    cls = str(result.get("classification", "")).strip().lower()
    if cls == "sdc":
        outcome = "SDC"
    elif cls == "due":
        outcome = "DUE"
    else:
        outcome = "Masked"
    detail = result.get("detail", {})
    if detail.get("error_kind"):
        outcome = "Unknown"
    reason = str(detail.get("reason", "")).strip()
    return {
        "run_id": run_id,
        "classification": cls,
        "outcome": outcome,
        "due_reason": reason if cls == "due" else "",
        "exit_status": exit_status,
        "run_log": str(run_log),
        "run_batch": task.get("run_batch"),
        "tmp_file": task.get("tmp_file"),
        "detail": detail,
        "scientific_outcome_usable": not bool(detail.get("error_kind")),
    }


def classify_fi_logs_batch(
    *,
    golden_log: Path,
    entries: Sequence[Dict[str, Any]],
    output_spec: Optional[Sequence[Dict[str, Any]]] = None,
    tol_policy: Optional[Dict[str, Any]] = None,
    timeout_exit_statuses: Optional[Iterable[int]] = None,
    batch_dir: Optional[Path] = None,
    run_log_name: str = "tmp.out",
    output_mode: str = "raw",
    require_fault_evidence: bool = False,
) -> Dict[str, Any]:
    timeout_set = (
        set(int(x) for x in timeout_exit_statuses)
        if timeout_exit_statuses is not None
        else set(DEFAULT_TIMEOUT_EXIT_STATUSES)
    )
    spec = output_spec
    policy = dict(tol_policy or {})

    normalized: List[Dict[str, Any]] = []
    for idx, raw in enumerate(entries):
        row = dict(raw or {})
        run_id = _normalize_run_id(row.get("run_id", row.get("trial")), idx)
        run_log = _resolve_batch_run_log(
            row,
            batch_dir=batch_dir,
            run_log_name=run_log_name,
        )
        normalized.append(
            {
                "run_id": run_id,
                "run_log": str(run_log),
                "exit_status": _coerce_int_optional(row.get("exit_status")),
                "run_batch": row.get("run_batch"),
                "tmp_file": row.get("tmp_file"),
            }
        )

    normalized.sort(key=lambda row: _batch_sort_key(str(row.get("run_id", ""))))
    tasks: List[Dict[str, Any]] = []
    for row in normalized:
        tasks.append(
            {
                "golden_log": str(golden_log),
                "run_id": row.get("run_id"),
                "run_log": row.get("run_log"),
                "exit_status": row.get("exit_status"),
                "run_batch": row.get("run_batch"),
                "tmp_file": row.get("tmp_file"),
                "timeout_exit_statuses": sorted(timeout_set),
                "output_spec": spec,
                "tol_policy": policy,
                "output_mode": output_mode,
                "require_fault_evidence": require_fault_evidence,
            }
        )

    results = [_classify_batch_entry(task) for task in tasks]

    class_counts = Counter(str(row.get("classification", "")).lower() for row in results)
    usable_counts = Counter(str(row.get("classification", "")).lower() for row in results
                            if not row.get("detail", {}).get("error_kind"))
    return {
        "results": results,
        "meta": {
            "total": len(results),
            "class_counts": {name: int(usable_counts.get(name, 0)) for name in ("masked", "sdc", "due")},
            "diagnostic_class_counts": {name: int(class_counts.get(name, 0)) for name in ("masked", "sdc", "due")},
            "usable_class_counts": {name: int(usable_counts.get(name, 0)) for name in ("masked", "sdc", "due")},
            "infrastructure_error_count": sum(bool(row.get("detail", {}).get("error_kind")) for row in results),
            "golden_log": str(golden_log),
            "run_log_name": str(run_log_name),
        },
    }


def write_fi_batch_csv(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
    fieldnames = [
        "run_id",
        "outcome",
        "classification",
        "due_reason",
        "exit_status",
        "run_batch",
        "tmp_file",
        "run_log",
        "detail_reason",
        "detail_json",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            detail = row.get("detail", {})
            detail_reason = ""
            if isinstance(detail, dict):
                detail_reason = str(detail.get("reason", ""))
            out_row = {
                "run_id": row.get("run_id", ""),
                "outcome": row.get("outcome", ""),
                "classification": row.get("classification", ""),
                "due_reason": row.get("due_reason", ""),
                "exit_status": row.get("exit_status", ""),
                "run_batch": row.get("run_batch", ""),
                "tmp_file": row.get("tmp_file", ""),
                "run_log": row.get("run_log", ""),
                "detail_reason": detail_reason,
                "detail_json": json.dumps(detail, sort_keys=True),
            }
            writer.writerow(out_row)


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Unified output oracle")
    sub = p.add_subparsers(dest="cmd")

    p_fi = sub.add_parser("fi-logs", help="Compare FI run log against golden log")
    p_fi.add_argument("--golden-log", type=Path, required=True)
    p_fi.add_argument("--run-log", type=Path, required=True)
    p_fi.add_argument("--output-spec", type=Path, default=None)
    p_fi.add_argument("--exit-status", type=int, default=None)
    p_fi.add_argument("--output-mode", choices=("raw", "legacy"), default="raw")
    p_fi.add_argument("--require-fault-evidence", action="store_true")
    p_fi.add_argument(
        "--timeout-exit-statuses",
        type=str,
        default="124:137",
        help="colon/comma list of timeout-like exit statuses",
    )
    p_fi.add_argument(
        "--tol-policy-json",
        type=str,
        default="{}",
        help="Legacy JSON policy argument; experiments use exact output comparison",
    )

    p_cmp = sub.add_parser("compare", help="Generic compare_outputs wrapper")
    p_cmp.add_argument("--golden-dir", type=Path, required=True)
    p_cmp.add_argument("--run-dir", type=Path, required=True)
    p_cmp.add_argument("--output-spec", type=Path, default=None)
    p_cmp.add_argument("--tol-policy-json", type=str, default="{}")
    p_cmp.add_argument("--output-mode", choices=("raw", "legacy"), default="raw")

    p_validate = sub.add_parser("validate-raw", help="Validate complete golden raw outputs")
    p_validate.add_argument("--log", type=Path, required=True)
    p_validate.add_argument("--output-spec", type=Path, default=None)

    p_batch = sub.add_parser(
        "fi-batch",
        help="Batch compare many FI run logs against one golden log",
    )
    p_batch.add_argument("--golden-log", type=Path, required=True)
    p_batch.add_argument("--output-spec", type=Path, default=None)
    p_batch.add_argument("--batch-file", type=Path, default=None)
    p_batch.add_argument("--batch-dir", type=Path, default=None)
    p_batch.add_argument(
        "--run-log-name",
        type=str,
        default="tmp.out",
        help="Default per-run log filename when resolving via --batch-dir",
    )
    p_batch.add_argument(
        "--timeout-exit-statuses",
        type=str,
        default="124:137",
        help="colon/comma list of timeout-like exit statuses",
    )
    p_batch.add_argument(
        "--tol-policy-json",
        type=str,
        default="{}",
        help="Legacy JSON policy argument; experiments use exact output comparison",
    )
    p_batch.add_argument("--output-json", type=Path, default=None)
    p_batch.add_argument("--output-csv", type=Path, default=None)
    p_batch.add_argument("--output-mode", choices=("raw", "legacy"), default="raw")
    p_batch.add_argument("--require-fault-evidence", action="store_true")

    return p


def main() -> int:
    parser = _build_arg_parser()
    args = parser.parse_args()
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 2
    if args.cmd == "validate-raw":
        try:
            spec = json.loads(args.output_spec.read_text()) if args.output_spec is not None else None
        except (OSError, ValueError):
            print(json.dumps({"valid": False, "reason": "invalid_output_spec"}))
            return 1
        if args.output_spec is not None and not spec:
            result = {"valid": False, "reason": "invalid_output_spec"}
        else:
            result = validate_raw_outputs(args.log, spec)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["valid"] else 1
    try:
        tol_policy = json.loads(args.tol_policy_json) if args.tol_policy_json else {}
    except json.JSONDecodeError:
        tol_policy = {}

    if args.cmd == "fi-logs":
        spec = (json.loads(args.output_spec.read_text()) if args.output_mode == "raw"
                else _load_output_spec(args.output_spec)) if args.output_spec is not None else None
        res = classify_fi_logs(
            golden_log=args.golden_log,
            run_log=args.run_log,
            output_spec=spec,
            tol_policy=tol_policy,
            exit_status=args.exit_status,
            timeout_exit_statuses=_parse_timeout_statuses(args.timeout_exit_statuses),
            output_mode=args.output_mode,
            require_fault_evidence=args.require_fault_evidence,
        )
    elif args.cmd == "compare":
        spec = (json.loads(args.output_spec.read_text()) if args.output_mode == "raw"
                else _load_output_spec(args.output_spec)) if args.output_spec is not None else None
        res = compare_outputs(
            args.golden_dir,
            args.run_dir,
            spec,
            tol_policy,
            output_mode=args.output_mode,
        )
    elif args.cmd == "fi-batch":
        spec = (json.loads(args.output_spec.read_text()) if args.output_mode == "raw"
                else _load_output_spec(args.output_spec)) if args.output_spec is not None else None
        entries: List[Dict[str, Any]] = []
        if args.batch_file is not None:
            entries.extend(_load_batch_entries(args.batch_file))
        elif args.batch_dir is not None:
            entries.extend(_discover_batch_entries_from_dir(args.batch_dir, args.run_log_name))
        if not entries:
            raise ValueError("fi-batch requires --batch-file and/or --batch-dir with entries")

        res = classify_fi_logs_batch(
            golden_log=args.golden_log,
            entries=entries,
            output_spec=spec,
            tol_policy=tol_policy,
            timeout_exit_statuses=_parse_timeout_statuses(args.timeout_exit_statuses),
            batch_dir=args.batch_dir,
            run_log_name=args.run_log_name,
            output_mode=args.output_mode,
            require_fault_evidence=args.require_fault_evidence,
        )
        if args.output_json is not None:
            args.output_json.parent.mkdir(parents=True, exist_ok=True)
            args.output_json.write_text(json.dumps(res, indent=2, sort_keys=True) + "\n")
        if args.output_csv is not None:
            write_fi_batch_csv(args.output_csv, res.get("results", []))
    else:
        raise ValueError(f"unknown subcommand: {args.cmd}")

    print(json.dumps(res, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
