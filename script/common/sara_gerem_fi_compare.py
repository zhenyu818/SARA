#!/usr/bin/env python3
"""Build public SARA / GEREM-all / FI comparison reports from test_result/."""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

STORAGE_COMPONENTS: List[Tuple[str, int, str]] = [
    ("rf", 0, "Register"),
    ("smem_rf", 2, "Shared Memory"),
    ("l1d", 3, "L1 D Cache"),
    ("l2", 6, "L2 Cache"),
]
GEREM_CAMPAIGN_COMPONENTS = ("rf", "smem_rf", "l1d", "l2")
OUTCOME_KEYS: Tuple[str, ...] = ("masked", "sdc", "due")
OUTCOME_LABELS: Dict[str, str] = {
    "masked": "Masked",
    "sdc": "SDC",
    "due": "DUE",
}




def _write_text_replace(path: Path, text: str) -> None:
    try:
        path.write_text(text, encoding="utf-8")
    except PermissionError:
        # Some previous container runs left root-owned compare files inside a
        # user-writable compare directory. Replace the file atomically enough
        # for this generated report instead of failing the whole experiment.
        path.unlink()
        path.write_text(text, encoding="utf-8")

def _read_csv_row(path: Path) -> Dict[str, str]:
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        return next(csv.DictReader(handle))


def _optional_read_csv_row(path: Path) -> Optional[Dict[str, str]]:
    if not path.exists():
        return None
    try:
        return _read_csv_row(path)
    except StopIteration:
        return None


def _first_existing(paths: Iterable[Path]) -> Optional[Path]:
    for path in paths:
        if path.exists():
            return path
    return None


def _parse_total_time_from_simple(path: Optional[Path]) -> Optional[float]:
    if path is None or not path.exists():
        return None
    pattern = re.compile(r"Total Time \(s\):\s*([0-9.eE+-]+)")
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = pattern.search(raw)
        if match:
            return float(match.group(1))
    return None


def _parse_gerem_campaign_mode_from_simple(path: Optional[Path]) -> Optional[str]:
    if path is None or not path.exists():
        return None
    prefix = "GEREM Campaign Mode:"
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line.startswith(prefix):
            return line[len(prefix) :].strip().lower() or None
    return None


def _gerem_campaign_status(row: Optional[Dict[str, str]], simple_path: Optional[Path]) -> str:
    """Return all/sample/mixed/unknown for a GEREM result's campaign metadata."""
    if row is None and (simple_path is None or not simple_path.exists()):
        return "-"
    modes = []
    if row:
        for component in GEREM_CAMPAIGN_COMPONENTS:
            raw = row.get(f"{component}_campaign_mode")
            if raw is not None and raw.strip():
                modes.append(raw.strip().lower())
    if not modes:
        simple_mode = _parse_gerem_campaign_mode_from_simple(simple_path)
        if simple_mode:
            modes.append(simple_mode)
    if not modes:
        return "unknown"
    unique = sorted(set(modes))
    if len(unique) == 1:
        return unique[0]
    return "mixed:" + ",".join(unique)


def _parse_fi_component(path: Path) -> Dict[str, float]:
    row = _read_csv_row(path)
    masked = float(row.get("Masked", 0) or 0)
    sdc = float(row.get("SDC", 0) or 0)
    due = float(row.get("DUE", 0) or 0)
    total = masked + sdc + due
    return {
        "masked": masked,
        "sdc": sdc,
        "due": due,
        "total": total,
        "masked_rate": (masked / total) if total > 0 else 0.0,
        "sdc_rate": (sdc / total) if total > 0 else 0.0,
        "due_rate": (due / total) if total > 0 else 0.0,
        "time_seconds": float(row.get("Injection Time (s)", 0) or 0),
    }


def _optional_parse_fi_component(path: Path) -> Optional[Dict[str, float]]:
    if not path.exists():
        return None
    try:
        return _parse_fi_component(path)
    except (StopIteration, ValueError, KeyError):
        return None


def _safe_float(row: Optional[Dict[str, str]], key: str) -> float:
    if row is None:
        return 0.0
    return float(row.get(key, 0) or 0)


def _method_outcome_rates(row: Optional[Dict[str, str]], component: str) -> Optional[Dict[str, float]]:
    if row is None or _safe_float(row, f"{component}_den") <= 0:
        return None
    return {
        outcome: _safe_float(row, f"{component}_{outcome}_rate")
        for outcome in OUTCOME_KEYS
    }


def _fi_outcome_rates(fi: Optional[Dict[str, float]]) -> Optional[Dict[str, float]]:
    if fi is None or fi.get("total", 0.0) <= 0:
        return None
    return {
        outcome: float(fi.get(f"{outcome}_rate", 0.0))
        for outcome in OUTCOME_KEYS
    }


def _outcome_total_error(
    method_rates: Optional[Dict[str, float]],
    fi_rates: Optional[Dict[str, float]],
) -> Optional[float]:
    if method_rates is None or fi_rates is None:
        return None
    return sum(abs(method_rates[outcome] - fi_rates[outcome]) for outcome in OUTCOME_KEYS) / float(len(OUTCOME_KEYS))


def _fmt_rate(value: Optional[float]) -> str:
    if value is None:
        return "-"
    return f"{value:.12f}"


def _fmt_speedup(value: Optional[float]) -> str:
    if value is None:
        return "-"
    return f"{value:.6f}x"


def _fmt_outcome_rates(rates: Optional[Dict[str, float]]) -> str:
    if rates is None:
        return "-"
    return " ".join(
        f"{OUTCOME_LABELS[outcome]}={rates[outcome]:.12f}"
        for outcome in OUTCOME_KEYS
    )


def _fmt_table(rows: List[List[str]], headers: List[str]) -> str:
    table = [headers] + rows
    widths = [max(len(str(row[i])) for row in table) for i in range(len(headers))]

    def _fmt_row(row: List[str]) -> str:
        return "  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)).rstrip()

    sep = "  ".join("-" * width for width in widths)
    return "\n".join([_fmt_row(headers), sep] + [_fmt_row(row) for row in rows])


def _discover_apps(sara_root: Path, gerem_root: Path, fi_root: Path, explicit: Optional[str]) -> List[str]:
    if explicit:
        return [part.strip() for part in explicit.replace(",", " ").split() if part.strip()]
    names = set()
    for root in (sara_root, gerem_root, fi_root):
        if root.exists():
            names.update(path.name for path in root.iterdir() if path.is_dir())
    return sorted(names)


def _sara_result_path(sara_app: Path, app: str) -> Optional[Path]:
    return _first_existing(
        [
            sara_app / f"sara_result_{app}_0-0.csv",
            sara_app / f"exact_result_{app}_0-0.csv",  # legacy compatibility only
        ]
    )


def _sara_simple_path(sara_app: Path, app: str) -> Optional[Path]:
    return _first_existing(
        [
            sara_app / f"sara_result_simple_{app}_0-0.csv",
            sara_app / f"exact_result_simple_{app}_0-0.csv",  # legacy compatibility only
        ]
    )


def build_report(
    arch_label: str,
    sara_root: Path,
    gerem_root: Path,
    fi_root: Path,
    output: Path,
    apps_arg: Optional[str],
    sara_label: str = "SARA",
) -> None:
    apps = _discover_apps(sara_root, gerem_root, fi_root, apps_arg)
    output.parent.mkdir(parents=True, exist_ok=True)

    detail_rows: List[List[str]] = []
    avg_sara_fi: Dict[str, List[float]] = {comp: [] for comp, _, _ in STORAGE_COMPONENTS}
    avg_gerem_fi: Dict[str, List[float]] = {comp: [] for comp, _, _ in STORAGE_COMPONENTS}
    overall_sara_fi: List[float] = []
    overall_gerem_fi: List[float] = []
    sara_total_times: List[float] = []
    gerem_total_times: List[float] = []
    fi_total_times: List[float] = []
    sara_speedup_method_time = 0.0
    sara_speedup_fi_time = 0.0
    gerem_speedup_method_time = 0.0
    gerem_speedup_fi_time = 0.0
    gerem_campaign_rows: List[List[str]] = []
    gerem_campaign_warnings: List[str] = []

    for app in apps:
        sara_app = sara_root / app
        gerem_app = gerem_root / app
        fi_app = fi_root / app
        sara_row = _optional_read_csv_row(_sara_result_path(sara_app, app) or Path("/nonexistent"))
        gerem_row = _optional_read_csv_row(gerem_app / f"gerem_result_{app}_0-0.csv")
        sara_time = _parse_total_time_from_simple(_sara_simple_path(sara_app, app))
        gerem_simple_path = gerem_app / f"gerem_result_simple_{app}_0-0.csv"
        gerem_time = _parse_total_time_from_simple(gerem_simple_path)
        gerem_campaign_status = _gerem_campaign_status(gerem_row, gerem_simple_path)
        gerem_campaign_rows.append([app, gerem_campaign_status])
        if gerem_time is not None and gerem_campaign_status != "all":
            gerem_campaign_warnings.append(f"{app}={gerem_campaign_status}")
        fi_storage_total = 0.0

        for comp, comp_id, label in STORAGE_COMPONENTS:
            sara_rates = _method_outcome_rates(sara_row, comp)
            gerem_rates = _method_outcome_rates(gerem_row, comp)

            fi_path = fi_app / f"test_result_{app}_0-0_{comp_id}_1.csv"
            fi = _optional_parse_fi_component(fi_path)
            fi_rates = _fi_outcome_rates(fi)
            if fi is not None:
                fi_storage_total += fi["time_seconds"]

            sara_fi_err = _outcome_total_error(sara_rates, fi_rates)
            gerem_fi_err = _outcome_total_error(gerem_rates, fi_rates)
            if sara_fi_err is not None:
                avg_sara_fi[comp].append(sara_fi_err)
                overall_sara_fi.append(sara_fi_err)
            if gerem_fi_err is not None:
                avg_gerem_fi[comp].append(gerem_fi_err)
                overall_gerem_fi.append(gerem_fi_err)

            detail_rows.append(
                [
                    app,
                    label,
                    _fmt_outcome_rates(sara_rates),
                    _fmt_outcome_rates(gerem_rates),
                    _fmt_outcome_rates(fi_rates),
                    _fmt_rate(sara_fi_err),
                    _fmt_rate(gerem_fi_err),
                ]
            )

        if sara_time is not None:
            sara_total_times.append(sara_time)
        if gerem_time is not None:
            gerem_total_times.append(gerem_time)
        if fi_storage_total > 0:
            fi_total_times.append(fi_storage_total)
        if sara_time is not None and sara_time > 0 and fi_storage_total > 0:
            sara_speedup_method_time += sara_time
            sara_speedup_fi_time += fi_storage_total
        if gerem_time is not None and gerem_time > 0 and fi_storage_total > 0:
            gerem_speedup_method_time += gerem_time
            gerem_speedup_fi_time += fi_storage_total

    avg_rows: List[List[str]] = []
    for comp, _comp_id, label in STORAGE_COMPONENTS:
        sara_vals = avg_sara_fi.get(comp, [])
        gerem_vals = avg_gerem_fi.get(comp, [])
        avg_rows.append(
            [
                label,
                _fmt_rate(sum(sara_vals) / len(sara_vals) if sara_vals else None),
                _fmt_rate(sum(gerem_vals) / len(gerem_vals) if gerem_vals else None),
            ]
        )

    total_sara_speedup = (
        sara_speedup_fi_time / sara_speedup_method_time
        if sara_speedup_method_time > 0.0 and sara_speedup_fi_time > 0.0
        else None
    )
    total_gerem_speedup = (
        gerem_speedup_fi_time / gerem_speedup_method_time
        if gerem_speedup_method_time > 0.0 and gerem_speedup_fi_time > 0.0
        else None
    )

    lines = [
        f"compare: {arch_label} storage-component total error and total speed for {sara_label} / GEREM-all versus FI",
        "",
        "Notes:",
        "- Scope: Register / Shared Memory / L1 D Cache / L2 Cache.",
        f"- {sara_label}, GEREM-all, and FI are read from public test_result directories; intermediate trace/profile directories are not used.",
        f"- {sara_label} result directory: `{sara_root}`.",
        "- GEREM-all must include `GEREM Campaign Mode: all` or `*_campaign_mode=all` metadata; migrated historical results without metadata are treated as unverified.",
        "- `-` means the corresponding application/component result is missing or the result file is empty.",
        "- Total error follows the GEREM paper accuracy-evaluation convention: average the absolute rate differences for Masked / SDC / DUE; it is not an SDC-only comparison.",
        f"- Per-component average total error is computed over applications where both {sara_label} (or GEREM-all) and FI are present.",
        "- Total speedup is computed over applications with results for the same method: sum(FI storage injection time) / sum(method total time); it is not the arithmetic mean of per-application speedups.",
        "",
        "GEREM-all campaign validation:",
        _fmt_table(gerem_campaign_rows, ["Application", "GEREM campaign status"]),
        "",
        *(
            [
                "WARNING: The current GEREM-all directory contains results that cannot be verified as exhaustive/all.",
                "The following GEREM-all values should not be used as strict GEREM-all paper results until rerun with `./run_experiment.sh --method gerem-all --gerem-runs all --force`:",
                ", ".join(gerem_campaign_warnings),
                "",
            ]
            if gerem_campaign_warnings
            else []
        ),
        "1. Per-application storage-component outcome-distribution total error",
        _fmt_table(
            detail_rows,
            [
                "Application",
                "Component",
                f"{sara_label} outcome rates",
                "GEREM-all outcome rates",
                "FI outcome rates",
                f"{sara_label} total error",
                "GEREM-all total error",
            ],
        ),
        "",
        "2. Average total error by storage component across applications",
        _fmt_table(avg_rows, ["Component", f"Avg total |{sara_label}-FI|", "Avg total |GEREM-all-FI|"]),
        "",
        "3. Overall total error",
        f"- {sara_label} outcome total error: {_fmt_rate(sum(overall_sara_fi) / len(overall_sara_fi) if overall_sara_fi else None)}",
        f"- GEREM-all outcome total error: {_fmt_rate(sum(overall_gerem_fi) / len(overall_gerem_fi) if overall_gerem_fi else None)}",
        "",
        "4. Total speedup",
        f"- {sara_label} total speedup over FI storage components: {_fmt_speedup(total_sara_speedup)}",
        f"- GEREM-all total speedup over FI storage components: {_fmt_speedup(total_gerem_speedup)}",
        "",
        "5. Public result total time (seconds)",
        f"- {sara_label} total time: {_fmt_rate(sum(sara_total_times) if sara_total_times else None)}",
        f"- GEREM-all total time: {_fmt_rate(sum(gerem_total_times) if gerem_total_times else None)}",
        f"- FI storage total injection time: {_fmt_rate(sum(fi_total_times) if fi_total_times else None)}",
        f"- GEREM-all / {sara_label} total-time ratio: {_fmt_speedup((sum(gerem_total_times) / sum(sara_total_times)) if gerem_total_times and sara_total_times and sum(sara_total_times) > 0 else None)}",
    ]
    _write_text_replace(output, "\n".join(lines) + "\n")
    print(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch-label", required=True)
    parser.add_argument("--result-root", default="test_result", type=Path)
    parser.add_argument("--sara-root", type=Path)
    parser.add_argument("--gerem-root", type=Path)
    parser.add_argument("--fi-root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--sara-label", default="SARA")
    parser.add_argument("--apps", help="space/comma separated app list; default discovers from result roots")
    args = parser.parse_args()

    arch_root = args.result_root / args.arch_label
    if args.sara_root is not None:
        sara_root = args.sara_root
    else:
        sara_root = arch_root / "SARA"
    gerem_root = args.gerem_root or (arch_root / "GEREM-all")
    fi_root = args.fi_root or (arch_root / "FI")
    output = args.output or (arch_root / "compare" / "sara_geremall_vs_fi.txt")
    build_report(args.arch_label, sara_root, gerem_root, fi_root, output, args.apps, args.sara_label)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
