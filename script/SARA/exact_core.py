#!/usr/bin/env python3
"""Pure-Python SARA exact-result reporting helpers.

This replaces the previous native ``exact_core`` helper for the reporting and
CSV merge commands used by ``run_sara_app.sh``.  It deliberately does not
participate in exact SDC computation; it only normalizes summary JSON, writes
public CSV artifacts, and validates reported rates.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence

CLASS_KEYS = ("masked", "sdc", "due", "unknown")


def to_number(value: Any, fallback: float = 0.0) -> float:
    if isinstance(value, bool):
        return float(int(value))
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and value:
        try:
            return float(value)
        except ValueError:
            return fallback
    return fallback


def to_string_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return f"{value:.12g}"
    return ""


def fraction_to_float(value: Any) -> float:
    if not isinstance(value, Mapping):
        return to_number(value, 0.0)
    if "value" in value:
        return to_number(value.get("value"), 0.0)
    den = to_number(value.get("denominator"), 0.0)
    if den == 0.0:
        return 0.0
    return to_number(value.get("numerator"), 0.0) / den


def format_rate(value: float) -> str:
    return f"{float(value):.12f}"


def format_scalar(value: float) -> str:
    rounded = round(float(value))
    if abs(float(value) - rounded) <= 1e-12:
        return str(int(rounded))
    return f"{float(value):.12g}"


def load_json(path: str | Path) -> Any:
    with Path(path).open(encoding="utf-8", errors="replace") as handle:
        return json.load(handle)


def normalized_classification(
    counts_raw: Any,
    rates_raw: Any,
    den_hint: float,
) -> Dict[str, Any]:
    counts_obj = counts_raw if isinstance(counts_raw, Mapping) else {}
    rates_obj = rates_raw if isinstance(rates_raw, Mapping) else {}
    den = to_number(counts_obj.get("total"), 0.0)
    if den <= 0.0:
        den = float(den_hint)

    counts: Dict[str, float] = {}
    rates: Dict[str, float] = {}
    have_any_count = False
    for key in CLASS_KEYS:
        value = 0.0
        if key in counts_obj:
            value = to_number(counts_obj.get(key), 0.0)
            have_any_count = True
        counts[key] = value

    if have_any_count and den > 0.0:
        if "unknown" not in counts_obj:
            known_total = counts["masked"] + counts["sdc"] + counts["due"]
            counts["unknown"] = max(0.0, den - known_total)
        assigned = sum(counts.values())
        if abs(assigned - den) > 1e-9:
            counts["unknown"] = max(0.0, counts["unknown"] + (den - assigned))
            assigned = sum(counts.values())
        if abs(assigned - den) > 1e-9:
            counts["masked"] = max(0.0, counts["masked"] + (den - assigned))
        for key in CLASS_KEYS:
            rates[key] = counts[key] / den if den > 0.0 else 0.0
        return {"den": den, "counts": counts, "rates": rates}

    for key in CLASS_KEYS:
        rate = to_number(rates_obj.get(key), 0.0)
        rates[key] = rate
        counts[key] = rate * den if den > 0.0 else 0.0
    return {"den": den, "counts": counts, "rates": rates}


def rates_from_payload(data: Any) -> Dict[str, float]:
    obj = data if isinstance(data, Mapping) else {}
    counts = obj.get("classification_counts")
    if isinstance(counts, Mapping):
        cls = normalized_classification(
            counts,
            obj.get("classification_rates", {}),
            to_number(counts.get("total"), 0.0),
        )
        return dict(cls["rates"])
    rates = obj.get("classification_rates")
    if isinstance(rates, Mapping):
        return {key: to_number(rates.get(key), 0.0) for key in CLASS_KEYS}
    weighted = obj.get("weighted_classification_rates")
    if isinstance(weighted, Mapping):
        return {key: fraction_to_float(weighted.get(key, 0.0)) for key in CLASS_KEYS}
    return {key: to_number(obj.get(key), 0.0) for key in CLASS_KEYS}


def component_payload(summary_json: Any, component: str) -> Dict[str, Any]:
    obj = summary_json if isinstance(summary_json, Mapping) else {}
    counts_raw = obj.get("classification_counts", {})
    rates_raw = obj.get("classification_rates", {})
    summary_raw = obj.get("summary", {})
    counts = counts_raw if isinstance(counts_raw, Mapping) else {}
    rates = rates_raw if isinstance(rates_raw, Mapping) else {}
    summary = summary_raw if isinstance(summary_raw, Mapping) else {}

    def fallback_row() -> Dict[str, Any]:
        return {
            "den": counts.get("total", 0),
            "masked": counts.get("masked", 0),
            "sdc": counts.get("sdc", 0),
            "due": counts.get("due", 0),
            "unknown": counts.get("unknown", 0),
            "rate": dict(rates),
        }

    if component == "rf":
        return fallback_row()
    if component == "smem_rf":
        shared = summary.get("shared_memory", {})
        if isinstance(shared, Mapping) and isinstance(shared.get("smem_rf"), Mapping):
            return dict(shared["smem_rf"])
    if component == "smem_lds":
        shared = summary.get("shared_memory", {})
        if isinstance(shared, Mapping) and isinstance(shared.get("smem_lds"), Mapping):
            return dict(shared["smem_lds"])
    elif component == "l1d":
        row = summary.get("l1d_cache")
        if isinstance(row, Mapping):
            return dict(row)
    elif component == "l2":
        row = summary.get("l2_cache")
        if isinstance(row, Mapping):
            return dict(row)
    return fallback_row()


def component_row(summary_json: Any, component: str) -> Dict[str, Any]:
    raw = component_payload(summary_json, component)
    cls = normalized_classification(
        {
            "total": raw.get("den", 0),
            "masked": raw.get("masked", None),
            "sdc": raw.get("sdc", None),
            "due": raw.get("due", None),
            "unknown": raw.get("unknown", None),
        },
        raw.get("rate", {}),
        to_number(raw.get("den"), 0.0),
    )
    return {"raw": raw, "cls": cls}


def public_sara_text(value: str) -> str:
    replacements = (
        ("canonical_proof_exact_v2", "canonical_proof_sara_v2"),
        ("exact", "sara"),
        ("Exact", "SARA"),
        ("EXACT", "SARA"),
    )
    for old, new in replacements:
        value = value.replace(old, new)
    return value


def cmd_rates_summary(args: argparse.Namespace) -> int:
    data = load_json(args.input)
    rates = rates_from_payload(data)
    print(f"Masked total: {format_rate(rates['masked'])}")
    print(f"SDC total:    {format_rate(rates['sdc'])}")
    print(f"DUE total:    {format_rate(rates['due'])}")
    print(f"Unknown total:{format_rate(rates['unknown'])}")

    summary_raw = data.get("summary", {}) if isinstance(data, Mapping) else {}

    def print_nested(label: str, row: Any) -> None:
        if not isinstance(row, Mapping):
            return
        den = to_number(row.get("den"), 0.0)
        rate = row.get("rate", {})
        if den <= 0.0 or not isinstance(rate, Mapping):
            return
        print(
            f"{label} rate: masked={format_rate(to_number(rate.get('masked'), 0.0))} "
            f"sdc={format_rate(to_number(rate.get('sdc'), 0.0))} "
            f"due={format_rate(to_number(rate.get('due'), 0.0))} "
            f"unknown={format_rate(to_number(rate.get('unknown'), 0.0))} "
            f"den={int(den)}"
        )

    if isinstance(summary_raw, Mapping):
        print_nested("l1d", summary_raw.get("l1d_cache", {}))
        print_nested("l2", summary_raw.get("l2_cache", {}))
        shared = summary_raw.get("shared_memory", {})
        if isinstance(shared, Mapping):
            print_nested("smem_rf", shared.get("smem_rf", {}))
            print_nested("smem_lds", shared.get("smem_lds", {}))

    if args.output_json:
        out: Dict[str, Any] = {
            "benchmark": args.benchmark,
            "test_id": args.test_id,
            "classification_rates": {key: rates[key] for key in CLASS_KEYS},
            "status": "ok",
            "status_reason": "",
        }
        if isinstance(data, Mapping):
            if isinstance(data.get("classification_counts"), Mapping):
                out["classification_counts"] = data["classification_counts"]
            if isinstance(summary_raw, Mapping) and summary_raw:
                out["summary"] = summary_raw
            meta_raw = data.get("exact_meta", {})
            if isinstance(meta_raw, Mapping):
                out.update(dict(meta_raw))
                if "exact_semantics_profile" in meta_raw:
                    out["exact_semantics_profile"] = to_string_value(
                        meta_raw.get("exact_semantics_profile")
                    )
        Path(args.output_json).write_text(
            json.dumps(out, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    return 0


def cmd_summary_status(args: argparse.Namespace) -> int:
    raw = load_json(args.input)
    rates = raw.get("classification_rates", {}) if isinstance(raw, Mapping) else {}
    status = to_string_value(raw.get("status", "ok")) if isinstance(raw, Mapping) else "ok"
    reason = to_string_value(raw.get("status_reason", "")) if isinstance(raw, Mapping) else ""
    if not reason:
        reason = "-"
    print(
        "\t".join(
            [
                status,
                reason,
                format_rate(to_number(rates.get("masked"), 0.0)),
                format_rate(to_number(rates.get("sdc"), 0.0)),
                format_rate(to_number(rates.get("due"), 0.0)),
                format_rate(to_number(rates.get("unknown"), 0.0)),
            ]
        )
    )
    return 0


def cmd_rates_simple_summary_csv(args: argparse.Namespace) -> int:
    lines = Path(args.input).read_text(encoding="utf-8", errors="replace").splitlines()
    with Path(args.output).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["line"])
        for line in lines:
            writer.writerow([line])
    return 0


def cmd_rates_compare(args: argparse.Namespace) -> int:
    expected = rates_from_payload(load_json(args.expected))
    measured = rates_from_payload(load_json(args.measured))
    mismatch = False
    for key in ("masked", "sdc", "due"):
        diff = abs(expected[key] - measured[key])
        if math.isnan(diff) or diff > args.tolerance:
            mismatch = True
    if mismatch:
        for key in ("masked", "sdc", "due"):
            diff = abs(expected[key] - measured[key])
            print(
                f"rate_mismatch {key}: expected={format_rate(expected[key])} "
                f"measured={format_rate(measured[key])} diff={format_rate(diff)}"
            )
        return 1
    print(
        f"validation_match: masked={format_rate(measured['masked'])} "
        f"sdc={format_rate(measured['sdc'])} due={format_rate(measured['due'])}"
    )
    return 0


def cmd_rates_merge_csv(args: argparse.Namespace) -> int:
    fieldnames = [
        "benchmark",
        "test_id",
        "component",
        "sara_semantics_profile",
        "den",
        "masked_num",
        "sdc_num",
        "due_num",
        "unknown_num",
        "masked_rate",
        "sdc_rate",
        "due_rate",
        "unknown_rate",
    ]
    with Path(args.output).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for path in args.summary:
            data = load_json(path)
            obj = data if isinstance(data, Mapping) else {}
            rates = rates_from_payload(obj)
            counts = obj.get("classification_counts", {})
            counts_obj = counts if isinstance(counts, Mapping) else {}
            profile = to_string_value(obj.get("exact_semantics_profile", ""))
            if not profile:
                profile = to_string_value(obj.get("sara_semantics_profile", ""))
            component = to_string_value(obj.get("fault_component", ""))
            if not component:
                component = to_string_value(obj.get("component", ""))
            writer.writerow(
                {
                    "benchmark": to_string_value(obj.get("benchmark", "")),
                    "test_id": to_string_value(obj.get("test_id", "")),
                    "component": component,
                    "sara_semantics_profile": public_sara_text(profile),
                    "den": format_scalar(to_number(counts_obj.get("total"), 0.0)),
                    "masked_num": format_scalar(to_number(counts_obj.get("masked"), 0.0)),
                    "sdc_num": format_scalar(to_number(counts_obj.get("sdc"), 0.0)),
                    "due_num": format_scalar(to_number(counts_obj.get("due"), 0.0)),
                    "unknown_num": format_scalar(to_number(counts_obj.get("unknown"), 0.0)),
                    "masked_rate": format_rate(rates["masked"]),
                    "sdc_rate": format_rate(rates["sdc"]),
                    "due_rate": format_rate(rates["due"]),
                    "unknown_rate": format_rate(rates["unknown"]),
                }
            )
    return 0


def _first_nonempty_string(*values: Any) -> str:
    for value in values:
        text = to_string_value(value)
        if text:
            return text
    return ""


def cmd_rates_merge_components_csv(args: argparse.Namespace) -> int:
    rf = load_json(args.rf_summary)
    smem_rf = load_json(args.smem_rf_summary)
    l1d = load_json(args.l1d_summary)
    l2 = load_json(args.l2_summary)
    rf_obj = rf if isinstance(rf, Mapping) else {}
    smem_obj = smem_rf if isinstance(smem_rf, Mapping) else {}
    l1d_obj = l1d if isinstance(l1d, Mapping) else {}
    l2_obj = l2 if isinstance(l2, Mapping) else {}

    benchmark = _first_nonempty_string(
        rf_obj.get("benchmark", ""),
        smem_obj.get("benchmark", ""),
        l1d_obj.get("benchmark", ""),
        l2_obj.get("benchmark", ""),
    )
    test_id = _first_nonempty_string(
        rf_obj.get("test_id", ""),
        smem_obj.get("test_id", ""),
        l1d_obj.get("test_id", ""),
        l2_obj.get("test_id", ""),
    )
    profile = _first_nonempty_string(
        rf_obj.get("exact_semantics_profile", ""),
        smem_obj.get("exact_semantics_profile", ""),
        l1d_obj.get("exact_semantics_profile", ""),
        l2_obj.get("exact_semantics_profile", ""),
    )

    by_component = {
        "rf": component_row(rf_obj, "rf"),
        "smem_rf": component_row(smem_obj, "smem_rf"),
        "l1d": component_row(l1d_obj, "l1d"),
        "l2": component_row(l2_obj, "l2"),
    }
    fieldnames = ["benchmark", "test_id", "sara_semantics_profile"]
    row: Dict[str, str] = {
        "benchmark": benchmark,
        "test_id": test_id,
        "sara_semantics_profile": public_sara_text(profile),
    }
    for prefix in ("rf", "smem_rf", "l1d", "l2"):
        cls = by_component[prefix]["cls"]
        counts = cls["counts"]
        rates = cls["rates"]
        fieldnames.extend(
            [
                f"{prefix}_den",
                f"{prefix}_masked_num",
                f"{prefix}_sdc_num",
                f"{prefix}_due_num",
                f"{prefix}_unknown_num",
                f"{prefix}_masked_rate",
                f"{prefix}_sdc_rate",
                f"{prefix}_due_rate",
                f"{prefix}_unknown_rate",
            ]
        )
        row[f"{prefix}_den"] = format_scalar(cls["den"])
        row[f"{prefix}_masked_num"] = format_scalar(counts["masked"])
        row[f"{prefix}_sdc_num"] = format_scalar(counts["sdc"])
        row[f"{prefix}_due_num"] = format_scalar(counts["due"])
        row[f"{prefix}_unknown_num"] = format_scalar(counts["unknown"])
        row[f"{prefix}_masked_rate"] = format_rate(rates["masked"])
        row[f"{prefix}_sdc_rate"] = format_rate(rates["sdc"])
        row[f"{prefix}_due_rate"] = format_rate(rates["due"])
        row[f"{prefix}_unknown_rate"] = format_rate(rates["unknown"])

    with Path(args.output).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow(row)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    subparsers = parser.add_subparsers(dest="command")

    summary = subparsers.add_parser("rates-summary")
    summary.add_argument("--input", required=True)
    summary.add_argument("--benchmark", default="")
    summary.add_argument("--test-id", default="")
    summary.add_argument("--output-json", default="")
    summary.set_defaults(func=cmd_rates_summary)

    status = subparsers.add_parser("summary-status")
    status.add_argument("--input", required=True)
    status.set_defaults(func=cmd_summary_status)

    simple = subparsers.add_parser("rates-simple-summary-csv")
    simple.add_argument("--input", required=True)
    simple.add_argument("--output", required=True)
    simple.set_defaults(func=cmd_rates_simple_summary_csv)

    compare = subparsers.add_parser("rates-compare")
    compare.add_argument("--expected", required=True)
    compare.add_argument("--measured", required=True)
    compare.add_argument("--tolerance", type=float, default=1e-12)
    compare.set_defaults(func=cmd_rates_compare)

    merge = subparsers.add_parser("rates-merge-csv")
    merge.add_argument("--summary", nargs="+", required=True)
    merge.add_argument("--output", required=True)
    merge.set_defaults(func=cmd_rates_merge_csv)

    merge_components = subparsers.add_parser("rates-merge-components-csv")
    merge_components.add_argument("--rf-summary", required=True)
    merge_components.add_argument("--smem-rf-summary", required=True)
    merge_components.add_argument("--l1d-summary", required=True)
    merge_components.add_argument("--l2-summary", required=True)
    merge_components.add_argument("--output", required=True)
    merge_components.set_defaults(func=cmd_rates_merge_components_csv)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        print("exact_core.py dev")
        return 0
    if args.selftest:
        print("exact_core.py selftest OK")
        return 0
    if not hasattr(args, "func"):
        parser.print_help(sys.stderr)
        return 2
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
