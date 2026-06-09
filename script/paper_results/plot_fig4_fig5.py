#!/usr/bin/env python3
"""Generate paper Fig. 4 and Fig. 5 from public SARA result directories.

This copy lives outside ``paper/`` so it is tracked by git.  It reads the
public results under a configurable result root and writes the figure PDFs to a
caller-selected directory (normally ``sara-results/paper-results``).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import matplotlib.pyplot as plt
from matplotlib import font_manager

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from script.common import sara_gerem_fi_compare as cmp  # noqa: E402


ARCHES: List[Tuple[str, str]] = [
    ("Turing-RTX2060", "SM75 / RTX 2060 (Turing)"),
    ("Ampere-RTX3070", "SM86 / RTX 3070 (Ampere)"),
]

APPS: List[str] = [
    "AdamW",
    "Attention",
    "Convolution1D",
    "Dijkstra",
    "GESpmm",
    "Gelu",
    "Gemm",
    "LayerNorm",
    "MatrixFactorization",
    "MatrixMultiplication",
    "Pathfinder",
    "Render",
    "Softmax",
    "Stencil1D",
]

APP_LABELS: Dict[str, str] = {
    "AdamW": "AW",
    "Attention": "At",
    "Convolution1D": "Conv",
    "Dijkstra": "Dij",
    "GESpmm": "GS",
    "Gelu": "Gl",
    "Gemm": "GE",
    "LayerNorm": "LN",
    "MatrixFactorization": "MF",
    "MatrixMultiplication": "MM",
    "Pathfinder": "Pf",
    "Render": "Rn",
    "Softmax": "Sm",
    "Stencil1D": "St",
}

METHODS: List[Tuple[str, str, str]] = [
    ("SARA", "SARA", "#2F6BBA"),
    ("GEREM-1000", "GEREM-1000", "#D67A2C"),
    ("GEREM-5000", "GEREM-5000", "#4C9A2A"),
    ("GEREM-10000", "GEREM-10000", "#6F56B8"),
]

EDGE = "#263238"


def _configure_fonts() -> None:
    preferred = ["Arial", "Liberation Sans", "DejaVu Sans"]
    available = {f.name for f in font_manager.fontManager.ttflist}
    chosen = next((name for name in preferred if name in available), preferred[-1])

    plt.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.sans-serif": preferred,
            "font.size": 7.4,
            "axes.labelsize": 7.8,
            "axes.titlesize": 7.8,
            "xtick.labelsize": 6.8,
            "ytick.labelsize": 7.0,
            "legend.fontsize": 7.2,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "axes.linewidth": 0.50,
            "xtick.major.width": 0.55,
            "ytick.major.width": 0.55,
            "xtick.major.size": 2.2,
            "ytick.major.size": 2.2,
            "figure.dpi": 200,
            "savefig.dpi": 300,
        }
    )

    if chosen != "Arial":
        print(
            f"Warning: Arial is not installed; using {chosen} fallback while keeping Arial first in the font list.",
            file=sys.stderr,
        )


def _row(path: Path):
    return cmp._optional_read_csv_row(path)


def _per_app_accuracy(result_root: Path, arch: str) -> Dict[str, Dict[str, float]]:
    root = result_root / arch
    out: Dict[str, Dict[str, float]] = {}

    for app in APPS:
        rows = {
            "SARA": _row(root / "SARA" / app / f"sara_result_{app}_0-0.csv"),
        }
        rows.update(
            {
                method: _row(root / method / app / f"gerem_result_{app}_0-0.csv")
                for method, _label, _color in METHODS
                if method != "SARA"
            }
        )

        errors: Dict[str, List[float]] = {method: [] for method, _label, _color in METHODS}

        for component, component_id, _label in cmp.STORAGE_COMPONENTS:
            fi = cmp._optional_parse_fi_component(
                root / "FI" / app / f"test_result_{app}_0-0_{component_id}_1.csv"
            )
            fi_rates = cmp._fi_outcome_rates(fi)

            for method, _label, _color in METHODS:
                rates = cmp._method_outcome_rates(rows[method], component)
                error = cmp._outcome_total_error(rates, fi_rates)
                if error is not None:
                    errors[method].append(error)

        missing = [method for method, _label, _color in METHODS if not errors[method]]
        if missing:
            raise RuntimeError(f"missing accuracy inputs for {arch}/{app}: {', '.join(missing)}")

        out[app] = {
            method: 100.0 * sum(errors[method]) / len(errors[method])
            for method, _label, _color in METHODS
        }

    return out


def _per_app_speedup(result_root: Path, arch: str) -> Dict[str, Dict[str, float]]:
    root = result_root / arch
    out: Dict[str, Dict[str, float]] = {}

    for app in APPS:
        fi_total = 0.0
        fi_components = 0

        for _component, component_id, _label in cmp.STORAGE_COMPONENTS:
            fi = cmp._optional_parse_fi_component(
                root / "FI" / app / f"test_result_{app}_0-0_{component_id}_1.csv"
            )
            if fi is not None and fi.get("has_e2e_time"):
                fi_total += float(fi["time_seconds"])
                fi_components += 1

        sara_time = cmp._parse_total_time_from_simple(
            root / "SARA" / app / f"sara_result_simple_{app}_0-0.csv"
        )

        method_times = {"SARA": sara_time}
        method_times.update(
            {
                method: cmp._parse_total_time_from_simple(
                    root / method / app / f"gerem_result_simple_{app}_0-0.csv"
                )
                for method, _label, _color in METHODS
                if method != "SARA"
            }
        )

        if fi_total <= 0 or fi_components <= 0 or any(
            not method_times[method] for method, _label, _color in METHODS
        ):
            raise RuntimeError(f"missing speed inputs for {arch}/{app}")

        out[app] = {
            method: fi_total / float(method_times[method])
            for method, _label, _color in METHODS
        }

    return out


def _with_avg(values: Dict[str, Dict[str, float]]) -> Tuple[List[str], Dict[str, List[float]]]:
    labels = [APP_LABELS[app] for app in APPS] + ["Avg"]
    series: Dict[str, List[float]] = {}

    for method, _label, _color in METHODS:
        method_values = [values[app][method] for app in APPS]
        method_values.append(sum(method_values) / len(method_values))
        series[method] = method_values

    return labels, series


def _average_arch_metrics(
    metric_by_arch: Dict[str, Dict[str, Dict[str, float]]]
) -> Dict[str, Dict[str, float]]:
    averaged: Dict[str, Dict[str, float]] = {}

    for app in APPS:
        averaged[app] = {}
        for method, _label, _color in METHODS:
            values = [metric_by_arch[arch][app][method] for arch, _title in ARCHES]
            averaged[app][method] = sum(values) / len(values)

    return averaged


def _plot_single_panel(
    metric_by_arch: Dict[str, Dict[str, Dict[str, float]]],
    ylabel: str,
    output: Path,
    y_pad_fraction: float,
) -> None:
    averaged = _average_arch_metrics(metric_by_arch)
    labels, series = _with_avg(averaged)

    x = list(range(len(labels)))
    avg_idx = len(labels) - 1
    width = 0.22
    ymax = max(max(series[method]) for method, _label, _color in METHODS)
    ymax = ymax if ymax > 0 else 1.0

    fig, ax = plt.subplots(1, 1, figsize=(7.10, 2.58))
    ax.axvspan(
        len(APPS) - 0.52,
        len(APPS) + 0.52,
        color="#F2F5F7",
        zorder=0,
        linewidth=0,
    )

    handles = []
    legend_labels = []
    for method_idx, (method, label, color) in enumerate(METHODS):
        offset = (method_idx - (len(METHODS) - 1) / 2.0) * width
        bars = ax.bar(
            [i + offset for i in x],
            series[method],
            width,
            label=label,
            color=color,
            edgecolor=EDGE,
            linewidth=0.16,
            zorder=3,
        )
        handles.append(bars[0])
        legend_labels.append(label)

    ax.set_xlim(-0.55, avg_idx + 0.60)
    ax.set_ylim(0, ymax * (1.0 + y_pad_fraction))
    ax.set_ylabel(ylabel)
    ax.grid(axis="y", linestyle="--", linewidth=0.30, alpha=0.38, zorder=0)
    ax.locator_params(axis="y", nbins=5)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_linewidth(0.50)
    ax.spines["bottom"].set_linewidth(0.50)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=0, ha="center")
    ax.tick_params(axis="x", width=0.55, length=0, pad=2)
    ax.tick_params(axis="y", width=0.55, length=2.2, pad=2)

    fig.legend(
        handles,
        legend_labels,
        loc="lower center",
        ncols=4,
        bbox_to_anchor=(0.5, 0.035),
        frameon=False,
        handlelength=1.2,
        columnspacing=1.35,
        handletextpad=0.35,
        borderaxespad=0.0,
    )
    fig.subplots_adjust(left=0.075, right=0.995, bottom=0.205, top=0.965)

    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, bbox_inches="tight", pad_inches=0.015)
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-root", type=Path, default=ROOT / "sara-results")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "sara-results" / "paper-results")
    parser.add_argument("--accuracy-output", default="perapp_accuracy_bars.pdf")
    parser.add_argument("--speedup-output", default="perapp_speedup_bars.pdf")
    args = parser.parse_args()

    _configure_fonts()
    result_root = args.result_root.resolve()
    output_dir = args.output_dir.resolve()

    accuracy = {arch: _per_app_accuracy(result_root, arch) for arch, _title in ARCHES}
    speedup = {arch: _per_app_speedup(result_root, arch) for arch, _title in ARCHES}

    accuracy_out = output_dir / args.accuracy_output
    speedup_out = output_dir / args.speedup_output
    _plot_single_panel(
        accuracy,
        ylabel="Avg. outcome error (%)",
        output=accuracy_out,
        y_pad_fraction=0.22,
    )
    _plot_single_panel(
        speedup,
        ylabel="Speedup over FI (×)",
        output=speedup_out,
        y_pad_fraction=0.22,
    )

    print(accuracy_out)
    print(speedup_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
