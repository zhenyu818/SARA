#!/usr/bin/env python3
"""Generate paper Fig. 6 from SARA intermediate SDC proof-source summaries.

This tracked copy lives outside ``paper/``.  It intentionally reads SARA
intermediate ``summary_*.json`` files, because the public aggregate CSV files do
not retain the propagation source for each SDC site.  If those summaries are
missing, the caller should warn the user to rerun SARA with ``--keep-intermediate``.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Tuple

import matplotlib.pyplot as plt
from matplotlib import font_manager


ROOT = Path(__file__).resolve().parents[2]

ARCHES: Tuple[str, ...] = ("Turing-RTX2060", "Ampere-RTX3070")
COMPONENT_FILES: Tuple[Tuple[str, str, str], ...] = (
    ("rf", "summary_rf.json", "RF"),
    ("smem_rf", "summary_smem_rf.json", "SMEM"),
    ("l1d", "summary_l1d.json", "L1D"),
    ("l2", "summary_l2.json", "L2"),
)
SOURCE_ORDER: Tuple[Tuple[str, str, str], ...] = (
    ("memory_data_propagation", "Memory-data propagation", "#6F56B8"),
    ("scalar_computation_transfer", "Scalar-computation transfer", "#2F6BBA"),
    ("copy_forwarding_transfer", "Copy-forwarding transfer", "#56B4E9"),
    ("predicate_mediated_selection", "Predicate-mediated selection", "#D67A2C"),
    ("valid_address_substitution", "Valid address substitution", "#4C9A2A"),
)
SOURCE_ABBREVIATIONS: Mapping[str, str] = {
    "memory_data_propagation": "MDP",
    "scalar_computation_transfer": "SCT",
    "copy_forwarding_transfer": "CFT",
    "predicate_mediated_selection": "PMS",
    "valid_address_substitution": "VAS",
}
RF_INTERNAL_SOURCE_KEYS: Tuple[str, ...] = (
    "rf_arithmetic_transfer",
    "rf_bitwise_shift_transfer",
    "rf_move_convert_transfer",
    "rf_predicate_control_transfer",
    "rf_store_commit_transfer",
    "rf_multi_mechanism_transfer",
    "rf_other_exact_transfer",
)
RF_SOURCE_TO_PROOF_CLASS: Mapping[str, str] = {
    "rf_arithmetic_transfer": "scalar_computation_transfer",
    "rf_bitwise_shift_transfer": "scalar_computation_transfer",
    "rf_multi_mechanism_transfer": "scalar_computation_transfer",
    "rf_other_exact_transfer": "scalar_computation_transfer",
    "rf_move_convert_transfer": "copy_forwarding_transfer",
    "rf_predicate_control_transfer": "predicate_mediated_selection",
    "rf_store_commit_transfer": "copy_forwarding_transfer",
}


def _configure_fonts() -> None:
    preferred = ["Arial", "Liberation Sans", "DejaVu Sans"]
    available = {f.name for f in font_manager.fontManager.ttflist}
    chosen = next((name for name in preferred if name in available), preferred[-1])
    plt.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.sans-serif": preferred,
            "font.size": 8.5,
            "axes.labelsize": 9.0,
            "axes.titlesize": 9.0,
            "xtick.labelsize": 8.0,
            "ytick.labelsize": 8.0,
            "legend.fontsize": 7.8,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "axes.linewidth": 0.8,
            "figure.dpi": 200,
            "savefig.dpi": 300,
        }
    )
    if chosen != "Arial":
        print(
            f"Warning: Arial is not installed; using {chosen} fallback while keeping Arial first.",
            file=sys.stderr,
        )


def _num(value: Any) -> float:
    if isinstance(value, Mapping):
        for key in ("value", "num", "numerator"):
            if key in value:
                return _num(value[key])
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _exact_meta(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    meta = payload.get("exact_meta")
    return meta if isinstance(meta, Mapping) else payload


def _classification_sdc(payload: Mapping[str, Any]) -> float:
    counts = payload.get("classification_counts")
    if isinstance(counts, Mapping):
        return _num(counts.get("sdc", 0.0))
    meta = _exact_meta(payload)
    return _num(meta.get("sdc_bits_data", 0.0)) + _num(meta.get("sdc_bits_tag", 0.0))


def _source_split(payload: Mapping[str, Any], component: str) -> Dict[str, float]:
    meta = _exact_meta(payload)
    total = max(0.0, _classification_sdc(payload))
    stale_cache_tag = max(0.0, _num(meta.get("sdc_bits_tag", 0.0)))
    address_alias = max(
        0.0,
        _num(meta.get("addr_sdc_bits", 0.0)) + _num(meta.get("smem_addr_sdc_bits", 0.0)),
    )

    stale_cache_tag = min(stale_cache_tag, total)
    address_alias = min(address_alias, max(0.0, total - stale_cache_tag))
    data_value = max(0.0, total - stale_cache_tag - address_alias)

    out = {source: 0.0 for source, _label, _color in SOURCE_ORDER}
    out["valid_address_substitution"] += address_alias

    if component == "rf":
        source_mass = meta.get("rf_sdc_proof_source_mass", {})
        remaining = float(data_value)
        if isinstance(source_mass, Mapping) and source_mass:
            for source in RF_INTERNAL_SOURCE_KEYS:
                value = max(0.0, _num(source_mass.get(source, 0.0)))
                if value <= 0.0 or remaining <= 0.0:
                    continue
                taken = min(value, remaining)
                out[RF_SOURCE_TO_PROOF_CLASS.get(source, "scalar_computation_transfer")] += taken
                remaining -= taken
        if remaining > 0.0:
            out["scalar_computation_transfer"] += remaining
    elif component in {"smem_rf", "l1d", "l2"}:
        out["memory_data_propagation"] += data_value
    else:
        out["scalar_computation_transfer"] += data_value

    return out


def _latest_sara_runs(work_root: Path, arch: str) -> Path:
    arch_root = work_root / arch
    candidates = sorted(
        arch_root.glob("*/*/sara_runs"),
        key=lambda path: (path.parent.name, path.stat().st_mtime),
    )
    if not candidates:
        raise FileNotFoundError(f"no SARA intermediate summaries found under {arch_root}")
    return candidates[-1]


def _iter_component_summaries(work_root: Path, arches: Iterable[str]) -> Iterable[Tuple[str, str, str, Path]]:
    for arch in arches:
        sara_runs = _latest_sara_runs(work_root, arch)
        for app_dir in sorted(path for path in sara_runs.iterdir() if path.is_dir()):
            if app_dir.name == "method_results":
                continue
            run_dir = app_dir / "0-0"
            if not run_dir.is_dir():
                continue
            for component, filename, _label in COMPONENT_FILES:
                path = run_dir / filename
                if path.exists():
                    yield arch, app_dir.name, component, path


def _write_csv(output: Path, rows: List[Dict[str, Any]], source_totals: Mapping[str, float], total_sdc: float) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["level", "arch", "app", "source_type", "sdc_site_mass", "share_of_all_sdc_percent"])
        for row in rows:
            writer.writerow(
                [
                    "detail",
                    row["arch"],
                    row["app"],
                    row["source_type"],
                    f"{row['sdc_site_mass']:.6f}",
                    f"{(100.0 * row['sdc_site_mass'] / total_sdc) if total_sdc else 0.0:.6f}",
                ]
            )
        for source, _label, _color in SOURCE_ORDER:
            value = source_totals.get(source, 0.0)
            writer.writerow(
                [
                    "source_total",
                    "",
                    "",
                    source,
                    f"{value:.6f}",
                    f"{(100.0 * value / total_sdc) if total_sdc else 0.0:.6f}",
                ]
            )


def build_breakdown(work_root: Path, arches: Iterable[str]) -> Tuple[List[Dict[str, Any]], MutableMapping[str, float]]:
    detail_totals: MutableMapping[Tuple[str, str, str], float] = defaultdict(float)
    source_totals: MutableMapping[str, float] = defaultdict(float)

    for arch, app, component, path in _iter_component_summaries(work_root, arches):
        payload = json.loads(path.read_text(encoding="utf-8"))
        split = _source_split(payload, component)
        for source, value in split.items():
            if value <= 0.0:
                continue
            detail_totals[(arch, app, source)] += value
            source_totals[source] += value

    rows: List[Dict[str, Any]] = []
    for arch, app, source in sorted(detail_totals):
        rows.append(
            {
                "arch": arch,
                "app": app,
                "source_type": source,
                "sdc_site_mass": detail_totals[(arch, app, source)],
            }
        )
    return rows, source_totals


def plot_breakdown(source_totals: Mapping[str, float], total_sdc: float, output: Path) -> None:
    _configure_fonts()
    output.parent.mkdir(parents=True, exist_ok=True)
    visible_sources = [entry for entry in SOURCE_ORDER if source_totals.get(entry[0], 0.0) > 0.0]
    labels = [SOURCE_ABBREVIATIONS[source] for source, _label, _color in visible_sources]
    values = [(100.0 * source_totals.get(source, 0.0) / total_sdc) if total_sdc else 0.0 for source, _label, _color in visible_sources]
    colors = [color for _source, _label, color in visible_sources]

    fig, ax = plt.subplots(figsize=(3.5, 2.85))
    x = list(range(len(labels)))
    bars = ax.bar(x, values, color=colors, edgecolor="#263238", linewidth=0.35, width=0.68)
    ymax = max(values) if values else 1.0
    ax.set_ylim(0.0, ymax * 1.18)
    ax.set_ylabel("SDC site-mass share (%)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.grid(axis="y", linestyle="--", linewidth=0.45, alpha=0.45)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    for bar, value in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2.0,
            value + ymax * 0.025,
            f"{value:.2f}",
            ha="center",
            va="bottom",
            fontsize=7.8,
            color="#263238",
        )
    fig.subplots_adjust(left=0.16, right=0.99, top=0.84, bottom=0.16)
    fig.savefig(output, bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description="Plot SARA SDC semantic proof-source attribution.")
    parser.add_argument("--work-root", type=Path, default=ROOT / ".work")
    parser.add_argument("--arches", default=",".join(ARCHES), help="Comma-separated architecture labels to include.")
    parser.add_argument("--output", type=Path, default=ROOT / "sara-results" / "paper-results" / "sdc_source_breakdown.pdf")
    parser.add_argument("--csv", type=Path, default=ROOT / "sara-results" / "paper-results" / "sdc_source_breakdown.csv")
    args = parser.parse_args()

    work_root = args.work_root.resolve()
    arches = [part.strip() for part in str(args.arches).split(",") if part.strip()]
    if not arches:
        raise SystemExit("no architecture labels selected")

    rows, source_totals = build_breakdown(work_root, arches)
    total_sdc = sum(source_totals.values())
    if total_sdc <= 0.0:
        raise SystemExit("no SDC source mass found; run SARA with --keep-intermediate first")

    plot_breakdown(source_totals, total_sdc, args.output)
    _write_csv(args.csv, rows, source_totals, total_sdc)

    print(f"Total SARA SDC site mass: {total_sdc:.0f}")
    print("Semantic proof-source shares:")
    for source, label, _color in SOURCE_ORDER:
        value = source_totals.get(source, 0.0)
        print(f"  {label}: {100.0 * value / total_sdc:.3f}%")
    print(f"Wrote {args.output}")
    print(f"Wrote {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
