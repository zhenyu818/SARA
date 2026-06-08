#!/usr/bin/env python3
"""Merge GEREM component JSON files into repo-style CSV outputs."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from gerem_storage_common import load_json


COMPONENT_ORDER: Sequence[Tuple[str, str]] = (
    ("rf", "Register File"),
    ("smem_rf", "Shared Memory"),
    ("l1d", "L1 D Cache"),
    ("l2", "L2 Cache"),
)
REQUIRED_COMPONENT_FIELDS = (
    "benchmark",
    "test_id",
    "component",
    "den",
    "efm_counts",
    "efm_rates",
    "final_counts",
    "final_rates",
    "meta",
)


def _float_value(value: Any, default: float = 0.0) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and value.strip():
        return float(value)
    return default


def _validate_numeric_map(name: str, raw: Any, keys: Iterable[str]) -> Dict[str, float]:
    if not isinstance(raw, Mapping):
        raise ValueError(f"{name}: expected object")
    return {key: _float_value(raw.get(key), 0.0) for key in keys}


def _load_component(path: Path, expected_component: str) -> Dict[str, Any]:
    data = load_json(path)
    missing = [key for key in REQUIRED_COMPONENT_FIELDS if key not in data]
    if missing:
        raise ValueError(f"{path}: missing required fields: {', '.join(missing)}")
    component = str(data.get("component", "")).strip().lower()
    if component != expected_component:
        raise ValueError(f"{path}: expected component '{expected_component}', got '{component}'")
    if not isinstance(data.get("meta"), dict):
        raise ValueError(f"{path}: meta must be an object")
    data["efm_counts"] = _validate_numeric_map(
        f"{path}:efm_counts",
        data.get("efm_counts"),
        ("benign", "dcr", "ebc"),
    )
    data["efm_rates"] = _validate_numeric_map(
        f"{path}:efm_rates",
        data.get("efm_rates"),
        ("benign", "dcr", "ebc"),
    )
    data["final_counts"] = _validate_numeric_map(
        f"{path}:final_counts",
        data.get("final_counts"),
        ("masked", "sdc", "due"),
    )
    data["final_rates"] = _validate_numeric_map(
        f"{path}:final_rates",
        data.get("final_rates"),
        ("masked", "sdc", "due"),
    )
    data["den"] = _float_value(data.get("den"), 0.0)
    return data


def _step_times_from_tsv(path: Optional[Path]) -> List[Tuple[str, float]]:
    if path is None or not path.is_file():
        return []
    ordered: List[str] = []
    totals: Dict[str, float] = {}
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.strip()
            if not line:
                continue
            parts = line.split("\t")
            label = None
            seconds = None
            if len(parts) >= 3 and parts[0] == "timestamp_iso":
                continue
            if len(parts) >= 3:
                label = parts[1].strip()
                try:
                    seconds = float(parts[2])
                except ValueError:
                    seconds = None
            elif len(parts) >= 2 and parts[0].lower() != "label":
                label = parts[0].strip()
                try:
                    seconds = float(parts[1])
                except ValueError:
                    seconds = None
            if not label or seconds is None:
                continue
            if label not in totals:
                ordered.append(label)
                totals[label] = 0.0
            totals[label] += seconds
    return [(label, totals[label]) for label in ordered]


def _component_row(data: Mapping[str, Any], prefix: str) -> Dict[str, float]:
    efm_counts = _validate_numeric_map(f"{prefix}:efm_counts", data.get("efm_counts"), ("benign", "dcr", "ebc"))
    efm_rates = _validate_numeric_map(f"{prefix}:efm_rates", data.get("efm_rates"), ("benign", "dcr", "ebc"))
    final_counts = _validate_numeric_map(
        f"{prefix}:final_counts",
        data.get("final_counts"),
        ("masked", "sdc", "due"),
    )
    final_rates = _validate_numeric_map(
        f"{prefix}:final_rates",
        data.get("final_rates"),
        ("masked", "sdc", "due"),
    )
    return {
        f"{prefix}_den": _float_value(data.get("den"), 0.0),
        f"{prefix}_efm_benign_num": efm_counts["benign"],
        f"{prefix}_efm_dcr_num": efm_counts["dcr"],
        f"{prefix}_efm_ebc_num": efm_counts["ebc"],
        f"{prefix}_efm_benign_rate": efm_rates["benign"],
        f"{prefix}_efm_dcr_rate": efm_rates["dcr"],
        f"{prefix}_efm_ebc_rate": efm_rates["ebc"],
        f"{prefix}_masked_num": final_counts["masked"],
        f"{prefix}_sdc_num": final_counts["sdc"],
        f"{prefix}_due_num": final_counts["due"],
        f"{prefix}_masked_rate": final_rates["masked"],
        f"{prefix}_sdc_rate": final_rates["sdc"],
        f"{prefix}_due_rate": final_rates["due"],
    }


def merge_components_row(components: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
    rf = components["rf"]
    row: Dict[str, Any] = {
        "benchmark": str(rf.get("benchmark", "")),
        "test_id": str(rf.get("test_id", "")),
    }
    for component, _label in COMPONENT_ORDER:
        row.update(_component_row(components[component], component))
    smem_meta = components["smem_rf"].get("meta", {})
    smem_sic = 0.0
    if isinstance(smem_meta, Mapping):
        smem_sic = _float_value(smem_meta.get("smem_sic", smem_meta.get("sic", 0.0)), 0.0)
    row["smem_sic"] = smem_sic
    for component, _label in COMPONENT_ORDER:
        meta = components[component].get("meta", {})
        if not isinstance(meta, Mapping):
            continue
        prefix = component
        for key in ("campaign_mode", "campaign_runs", "campaign_seed"):
            if key in meta:
                row[f"{prefix}_{key}"] = meta[key]
    return row


def _write_csv_row(path: Path, row: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(row.keys()))
        writer.writeheader()
        writer.writerow(row)


def write_merge_csv(components: Mapping[str, Mapping[str, Any]], output: Path) -> None:
    _write_csv_row(output, merge_components_row(components))


def _component_summary_line(label: str, payload: Mapping[str, Any]) -> str:
    meta = payload.get("meta", {})
    if isinstance(meta, Mapping) and meta.get("not_used"):
        return f"{label}: not used"
    efm_rates = _validate_numeric_map(f"{label}:efm_rates", payload.get("efm_rates"), ("benign", "dcr", "ebc"))
    final_rates = _validate_numeric_map(
        f"{label}:final_rates",
        payload.get("final_rates"),
        ("masked", "sdc", "due"),
    )
    extra = ""
    if label == "Shared Memory" and isinstance(meta, Mapping):
        sic = _float_value(meta.get("smem_sic", meta.get("sic", 0.0)), 0.0)
        extra = f" smem_sic={sic:.12f}"
    return (
        f"{label}: "
        f"Masked={final_rates['masked']:.12f} "
        f"SDC={final_rates['sdc']:.12f} "
        f"DUE={final_rates['due']:.12f} "
        f"EFM[benign={efm_rates['benign']:.12f} dcr={efm_rates['dcr']:.12f} ebc={efm_rates['ebc']:.12f}]"
        f"{extra}"
    )


def simple_summary_lines(
    *,
    components: Mapping[str, Mapping[str, Any]],
    app: str,
    test_id: str,
    input_line: str,
    step_times: Sequence[Tuple[str, float]],
) -> List[str]:
    total_time = sum(seconds for _label, seconds in step_times)
    lines = [
        f"Application Name: {app}",
        f"Test ID: {test_id}",
        f"Input: {input_line}",
        "Timing Scope: non-compilation end-to-end (excludes compile/prebuild only; includes method-owned result generation/trace/sampling/prediction/reporting)",
    ]
    campaign_modes: List[str] = []
    campaign_runs: List[str] = []
    for component, _label in COMPONENT_ORDER:
        meta = components[component].get("meta", {})
        if not isinstance(meta, Mapping):
            continue
        mode = str(meta.get("campaign_mode", "")).strip()
        runs = meta.get("campaign_runs")
        if mode:
            campaign_modes.append(mode)
        if runs is not None:
            campaign_runs.append(f"{component}={runs}")
    if campaign_modes:
        unique_modes = sorted(set(campaign_modes))
        lines.append(f"GEREM Campaign Mode: {unique_modes[0] if len(unique_modes) == 1 else ','.join(unique_modes)}")
    if campaign_runs:
        lines.append(f"GEREM Campaign Runs: {' '.join(campaign_runs)}")
    for component, label in COMPONENT_ORDER:
        lines.append(_component_summary_line(label, components[component]))
    lines.append("Step Times (s):")
    if step_times:
        lines.extend(f"{label}: {seconds:.6f}" for label, seconds in step_times)
    else:
        lines.append("none")
    lines.append(f"Total Time (s): {total_time:.6f}")
    return lines


def write_simple_summary(
    *,
    components: Mapping[str, Mapping[str, Any]],
    app: str,
    test_id: str,
    input_line: str,
    step_times: Sequence[Tuple[str, float]],
    output: Path,
) -> None:
    lines = simple_summary_lines(
        components=components,
        app=app,
        test_id=test_id,
        input_line=input_line,
        step_times=step_times,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["line"])
        writer.writeheader()
        for line in lines:
            writer.writerow({"line": line})


def _component_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--rf", type=Path, required=True)
    parser.add_argument("--smem-rf", type=Path, required=True, dest="smem_rf")
    parser.add_argument("--l1d", type=Path, required=True)
    parser.add_argument("--l2", type=Path, required=True)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    merge = subparsers.add_parser("merge-components")
    _component_args(merge)
    merge.add_argument("--output", type=Path, required=True)

    simple = subparsers.add_parser("simple-summary")
    _component_args(simple)
    simple.add_argument("--app", required=True)
    simple.add_argument("--test-id", required=True, dest="test_id")
    simple.add_argument("--input-line", required=True)
    simple.add_argument("--step-times", type=Path, default=None, dest="step_times")
    simple.add_argument("--output", type=Path, required=True)
    return parser


def _legacy_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rf-json", type=Path, required=True, dest="rf")
    parser.add_argument("--smem-json", type=Path, required=True, dest="smem_rf")
    parser.add_argument("--l1d-json", type=Path, required=True, dest="l1d")
    parser.add_argument("--l2-json", type=Path, required=True, dest="l2")
    parser.add_argument("--output-csv", type=Path, required=True, dest="output_csv")
    parser.add_argument("--output-simple", type=Path, required=True, dest="output_simple")
    parser.add_argument("--benchmark", required=True, dest="app")
    parser.add_argument("--test-id", required=True, dest="test_id")
    parser.add_argument("--input-line", required=True, dest="input_line")
    parser.add_argument("--timing-log", type=Path, required=False, default=None, dest="step_times")
    parser.add_argument("--total-time-seconds", type=float, required=False, default=None)
    return parser


def _load_components_from_args(args: argparse.Namespace) -> Dict[str, Dict[str, Any]]:
    return {
        "rf": _load_component(args.rf, "rf"),
        "smem_rf": _load_component(args.smem_rf, "smem_rf"),
        "l1d": _load_component(args.l1d, "l1d"),
        "l2": _load_component(args.l2, "l2"),
    }


def main(argv: Optional[Iterable[str]] = None) -> int:
    argv_list = list(argv) if argv is not None else sys.argv[1:]
    if argv_list and not argv_list[0].startswith("-"):
        args = build_arg_parser().parse_args(argv_list)
        components = _load_components_from_args(args)
        if args.command == "merge-components":
            write_merge_csv(components, args.output)
            return 0
        step_times = _step_times_from_tsv(args.step_times)
        write_simple_summary(
            components=components,
            app=args.app,
            test_id=args.test_id,
            input_line=args.input_line,
            step_times=step_times,
            output=args.output,
        )
        return 0

    args = _legacy_arg_parser().parse_args(argv_list)
    components = _load_components_from_args(args)
    write_merge_csv(components, args.output_csv)
    step_times = _step_times_from_tsv(args.step_times)
    if args.total_time_seconds is not None and not step_times:
        step_times = [("total", float(args.total_time_seconds))]
    write_simple_summary(
        components=components,
        app=args.app,
        test_id=args.test_id,
        input_line=args.input_line,
        step_times=step_times,
        output=args.output_simple,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
