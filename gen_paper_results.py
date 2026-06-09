#!/usr/bin/env python3
"""Generate paper-ready result tables and figures from ``sara-results``.

The script reads only public result directories for accuracy/speed tables and
Fig. 4/5.  Fig. 6 additionally requires SARA intermediate ``summary_*.json``
files because proof-source attribution is not retained in aggregate CSVs.
Generated artifacts are written to ``<result-root>/paper-results``.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from script.common import sara_gerem_fi_compare as cmp  # noqa: E402

ARCHES: Tuple[Tuple[str, str], ...] = (
    ("Turing-RTX2060", "SM75"),
    ("Ampere-RTX3070", "SM86"),
)
METHODS: Tuple[str, ...] = ("SARA", "GEREM-1000", "GEREM-5000", "GEREM-10000")
GEREM_RUNS: Tuple[int, ...] = (1000, 5000, 10000)
OUTCOMES: Tuple[str, ...] = cmp.OUTCOME_KEYS
OUTCOME_TITLES: Mapping[str, str] = {
    "masked": "Masked",
    "sdc": "SDC",
    "due": "DUE",
}
COMPONENT_LABELS: Mapping[str, str] = {
    "rf": "Register",
    "smem_rf": "Shared Memory",
    "l1d": "L1D Cache",
    "l2": "L2 Cache",
}
PLOT_DIR = ROOT / "script" / "paper_results"


def _discover_apps(result_root: Path, explicit: Optional[str]) -> List[str]:
    if explicit:
        return [part.strip() for part in explicit.replace(",", " ").split() if part.strip()]
    test_apps = ROOT / "test_apps"
    if test_apps.is_dir():
        return sorted(path.name for path in test_apps.iterdir() if path.is_dir())
    names = set()
    for arch, _label in ARCHES:
        for method in METHODS:
            root = result_root / arch / method
            if root.is_dir():
                names.update(path.name for path in root.iterdir() if path.is_dir())
        fi_root = result_root / arch / "FI"
        if fi_root.is_dir():
            names.update(path.name for path in fi_root.iterdir() if path.is_dir())
    return sorted(names)


def _method_row(result_root: Path, arch: str, method: str, app: str) -> Optional[Dict[str, str]]:
    if method == "SARA":
        return cmp._optional_read_csv_row(result_root / arch / "SARA" / app / f"sara_result_{app}_0-0.csv")
    return cmp._optional_read_csv_row(result_root / arch / method / app / f"gerem_result_{app}_0-0.csv")


def _method_time(result_root: Path, arch: str, method: str, app: str) -> Optional[float]:
    if method == "SARA":
        return cmp._parse_total_time_from_simple(result_root / arch / "SARA" / app / f"sara_result_simple_{app}_0-0.csv")
    return cmp._parse_total_time_from_simple(result_root / arch / method / app / f"gerem_result_simple_{app}_0-0.csv")


def _fi_rates_and_time(result_root: Path, arch: str, app: str, component_id: int) -> Tuple[Optional[Dict[str, float]], Optional[float]]:
    fi = cmp._optional_parse_fi_component(
        result_root / arch / "FI" / app / f"test_result_{app}_0-0_{component_id}_1.csv"
    )
    rates = cmp._fi_outcome_rates(fi)
    if fi is not None and fi.get("has_e2e_time"):
        return rates, float(fi["time_seconds"])
    return rates, None


def _mean(values: Iterable[Optional[float]]) -> Optional[float]:
    vals = [float(value) for value in values if value is not None]
    if not vals:
        return None
    return sum(vals) / len(vals)


def _pct(value: Optional[float], digits: int = 3) -> str:
    if value is None:
        return "-"
    return f"{100.0 * value:.{digits}f}"


def _plain(value: Optional[float], digits: int = 3, comma: bool = False) -> str:
    if value is None:
        return "-"
    spec = f",.{digits}f" if comma else f".{digits}f"
    return format(value, spec)


def _speed(value: Optional[float]) -> str:
    if value is None:
        return "-"
    return f"{value:.2f}×"


def _md_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(lines) + "\n"


def _write_md(path: Path, title: str, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"# {title}\n\n{body.rstrip()}\n", encoding="utf-8")


class PaperData:
    def __init__(self, result_root: Path, apps: List[str]) -> None:
        self.result_root = result_root
        self.apps = apps
        self.rows: Dict[Tuple[str, str, str, str], Dict[str, object]] = {}
        self.times: Dict[Tuple[str, str, str], Optional[float]] = {}
        self.fi_app_times: Dict[Tuple[str, str], float] = {}
        self.warnings: List[str] = []
        self._load()

    def _load(self) -> None:
        for arch, _target in ARCHES:
            for app in self.apps:
                fi_app_time = 0.0
                for component, component_id, _component_label in cmp.STORAGE_COMPONENTS:
                    fi_rates, fi_time = _fi_rates_and_time(self.result_root, arch, app, component_id)
                    if fi_time is not None:
                        fi_app_time += fi_time
                    method_rows = {method: _method_row(self.result_root, arch, method, app) for method in METHODS}
                    any_method_component = any(
                        cmp._method_outcome_rates(method_rows[method], component) is not None
                        for method in METHODS
                    )
                    if fi_rates is None and any_method_component:
                        self.warnings.append(f"missing FI rates for {arch}/{app}/{component}")
                    for method in METHODS:
                        method_rates = cmp._method_outcome_rates(method_rows[method], component)
                        error = cmp._outcome_total_error(method_rates, fi_rates)
                        self.rows[(arch, app, component, method)] = {
                            "method_rates": method_rates,
                            "fi_rates": fi_rates,
                            "error": error,
                            "category_error": {
                                outcome: (abs(method_rates[outcome] - fi_rates[outcome]) if method_rates is not None and fi_rates is not None else None)
                                for outcome in OUTCOMES
                            },
                        }
                        if fi_rates is not None and method_rates is None:
                            self.warnings.append(f"missing {method} rates for {arch}/{app}/{component}")
                self.fi_app_times[(arch, app)] = fi_app_time
                for method in METHODS:
                    self.times[(arch, app, method)] = _method_time(self.result_root, arch, method, app)
                    if self.times[(arch, app, method)] is None:
                        self.warnings.append(f"missing {method} total time for {arch}/{app}")

    def errors(self, arch: str, method: str, component: Optional[str] = None) -> List[float]:
        values: List[float] = []
        for app in self.apps:
            for comp, _cid, _label in cmp.STORAGE_COMPONENTS:
                if component is not None and comp != component:
                    continue
                err = self.rows[(arch, app, comp, method)]["error"]
                if err is not None:
                    values.append(float(err))
        return values

    def category_errors(self, arch: str, method: str, outcome: str) -> List[float]:
        values: List[float] = []
        for app in self.apps:
            for comp, _cid, _label in cmp.STORAGE_COMPONENTS:
                err = self.rows[(arch, app, comp, method)]["category_error"][outcome]  # type: ignore[index]
                if err is not None:
                    values.append(float(err))
        return values

    def component_method_rates(self, arch: str, component: str, method: str, outcome: str) -> List[float]:
        values: List[float] = []
        for app in self.apps:
            entry = self.rows[(arch, app, component, method)]
            rates = entry["method_rates"]
            # Keep the rate average comparable to FI by requiring a valid FI row too.
            if rates is not None and entry["fi_rates"] is not None:
                values.append(float(rates[outcome]))  # type: ignore[index]
        return values

    def component_fi_rates(self, arch: str, component: str, outcome: str) -> List[float]:
        values: List[float] = []
        for app in self.apps:
            # Any method is equivalent here; SARA is used only to reach the shared row.
            entry = self.rows[(arch, app, component, "SARA")]
            rates = entry["fi_rates"]
            if rates is not None:
                values.append(float(rates[outcome]))  # type: ignore[index]
        return values

    def arch_method_time(self, arch: str, method: str) -> Optional[float]:
        vals = [self.times[(arch, app, method)] for app in self.apps]
        return sum(float(v) for v in vals if v is not None) if any(v is not None for v in vals) else None

    def arch_fi_time(self, arch: str) -> Optional[float]:
        vals = [self.fi_app_times[(arch, app)] for app in self.apps if self.fi_app_times[(arch, app)] > 0]
        return sum(vals) if vals else None


def _target_metric_by_method(
    per_arch_values: Mapping[Tuple[str, str], Optional[float]],
    arch: str,
    method: str,
) -> Optional[float]:
    return per_arch_values.get((arch, method))


def write_accuracy_overall(data: PaperData, output_dir: Path) -> MutableMapping[Tuple[str, str], Optional[float]]:
    values: MutableMapping[Tuple[str, str], Optional[float]] = {}
    rows: List[List[str]] = []
    for arch, target in ARCHES:
        for method in METHODS:
            value = _mean(data.errors(arch, method))
            values[(arch, method)] = value
            rows.append([target, f"**{method}**" if method == "SARA" else method, f"**{_pct(value)}**" if method == "SARA" else _pct(value)])
    for method in METHODS:
        combined = _mean(values[(arch, method)] for arch, _target in ARCHES)
        values[("Combined", method)] = combined
        rows.append(["Combined", f"**{method}**" if method == "SARA" else method, f"**{_pct(combined)}**" if method == "SARA" else _pct(combined)])
    body = _md_table(["Target", "Method", "Avg. Err. (%)"], rows)
    _write_md(output_dir / "table_iii_accuracy_overall.md", "Table III: Overall difference from FI", body)
    return values


def write_category_error(data: PaperData, output_dir: Path) -> MutableMapping[Tuple[str, str, str], Optional[float]]:
    values: MutableMapping[Tuple[str, str, str], Optional[float]] = {}
    rows: List[List[str]] = []
    for arch, target in ARCHES:
        for method in METHODS:
            row = [target, f"**{method}**" if method == "SARA" else method]
            for outcome in OUTCOMES:
                value = _mean(data.category_errors(arch, method, outcome))
                values[(arch, method, outcome)] = value
                cell = _pct(value)
                row.append(f"**{cell}**" if method == "SARA" else cell)
            rows.append(row)
    for method in METHODS:
        row = ["Combined", f"**{method}**" if method == "SARA" else method]
        for outcome in OUTCOMES:
            combined = _mean(values[(arch, method, outcome)] for arch, _target in ARCHES)
            values[("Combined", method, outcome)] = combined
            cell = _pct(combined)
            row.append(f"**{cell}**" if method == "SARA" else cell)
        rows.append(row)
    body = _md_table(["Target", "Method", "Masked (%)", "SDC (%)", "DUE (%)"], rows)
    _write_md(output_dir / "table_iv_category_error.md", "Table IV: Category-specific rate differences from FI", body)
    return values


def write_component_breakdown(data: PaperData, output_dir: Path) -> None:
    # Store percentages (not fractions) so combined rows are exactly target-row averages.
    err_values: MutableMapping[Tuple[str, str, str], Optional[float]] = {}
    rate_values: MutableMapping[Tuple[str, str, str, str], Optional[float]] = {}
    fi_rate_values: MutableMapping[Tuple[str, str, str], Optional[float]] = {}

    def _store_arch(arch: str) -> None:
        for component, _cid, _label in cmp.STORAGE_COMPONENTS:
            for method in METHODS:
                err_values[(arch, component, method)] = _mean(data.errors(arch, method, component))
                for outcome in OUTCOMES:
                    rate_values[(arch, component, method, outcome)] = _mean(data.component_method_rates(arch, component, method, outcome))
            for outcome in OUTCOMES:
                fi_rate_values[(arch, component, outcome)] = _mean(data.component_fi_rates(arch, component, outcome))

    for arch, _target in ARCHES:
        _store_arch(arch)

    for component, _cid, _label in cmp.STORAGE_COMPONENTS:
        for method in METHODS:
            err_values[("Combined", component, method)] = _mean(err_values[(arch, component, method)] for arch, _target in ARCHES)
            for outcome in OUTCOMES:
                rate_values[("Combined", component, method, outcome)] = _mean(rate_values[(arch, component, method, outcome)] for arch, _target in ARCHES)
        for outcome in OUTCOMES:
            fi_rate_values[("Combined", component, outcome)] = _mean(fi_rate_values[(arch, component, outcome)] for arch, _target in ARCHES)

    rows: List[List[str]] = []
    for arch, target in (*ARCHES, ("Combined", "Combined")):
        for component, _cid, _label in cmp.STORAGE_COMPONENTS:
            comp_label = COMPONENT_LABELS[component]
            row: List[str] = [target, comp_label]
            # Err.
            for method in METHODS:
                cell = _pct(err_values[(arch, component, method)], 3)
                row.append(f"**{cell}**" if method == "SARA" else cell)
            # Masked/SDC/DUE groups: FI then method rates.
            for outcome in OUTCOMES:
                row.append(_pct(fi_rate_values[(arch, component, outcome)], 2))
                for method in METHODS:
                    cell = _pct(rate_values[(arch, component, method, outcome)], 2)
                    row.append(f"**{cell}**" if method == "SARA" else cell)
            rows.append(row)

    headers = [
        "Target",
        "Component",
        "SARA Err.",
        "G-1k Err.",
        "G-5k Err.",
        "G-10k Err.",
        "FI Masked",
        "SARA Masked",
        "G-1k Masked",
        "G-5k Masked",
        "G-10k Masked",
        "FI SDC",
        "SARA SDC",
        "G-1k SDC",
        "G-5k SDC",
        "G-10k SDC",
        "FI DUE",
        "SARA DUE",
        "G-1k DUE",
        "G-5k DUE",
        "G-10k DUE",
    ]
    note = (
        "All numeric entries are percentages. Err. columns report average outcome error from FI; "
        "G-1k/G-5k/G-10k denote GEREM-1000/5000/10000.\n\n"
    )
    _write_md(output_dir / "table_vi_component_breakdown.md", "Table VI: Per-component differences and outcome rates", note + _md_table(headers, rows))


def write_speed_overall(data: PaperData, output_dir: Path) -> None:
    rows: List[List[str]] = []
    method_times: MutableMapping[Tuple[str, str], Optional[float]] = {}
    fi_times: MutableMapping[str, Optional[float]] = {}
    for arch, target in ARCHES:
        fi_time = data.arch_fi_time(arch)
        fi_times[arch] = fi_time
        for method in METHODS:
            method_time = data.arch_method_time(arch, method)
            method_times[(arch, method)] = method_time
            speedup = (fi_time / method_time) if fi_time and method_time and method_time > 0 else None
            rows.append([
                target,
                f"**{method}**" if method == "SARA" else method,
                f"**{_plain(method_time, comma=True)}**" if method == "SARA" else _plain(method_time, comma=True),
                f"**{_speed(speedup)}**" if method == "SARA" else _speed(speedup),
            ])

    combined_fi = sum(float(v) for v in fi_times.values() if v is not None)
    for method in METHODS:
        combined_time = sum(float(method_times[(arch, method)]) for arch, _target in ARCHES if method_times[(arch, method)] is not None)
        speedup = (combined_fi / combined_time) if combined_fi > 0 and combined_time > 0 else None
        rows.append([
            "Combined",
            f"**{method}**" if method == "SARA" else method,
            f"**{_plain(combined_time if combined_time > 0 else None, comma=True)}**" if method == "SARA" else _plain(combined_time if combined_time > 0 else None, comma=True),
            f"**{_speed(speedup)}**" if method == "SARA" else _speed(speedup),
        ])
    body = _md_table(["Target", "Method", "Time (s)", "FI speedup"], rows)
    _write_md(output_dir / "table_v_speed_overall.md", "Table V: Overall evaluation speed", body)


def write_unknown_summary(data: PaperData, output_dir: Path) -> None:
    rows: List[List[str]] = []
    for arch, target in (*ARCHES, ("Combined", "Combined")):
        for component, _cid, _label in cmp.STORAGE_COMPONENTS:
            values: List[float] = []
            arches = [a for a, _t in ARCHES] if arch == "Combined" else [arch]
            for actual_arch in arches:
                for app in data.apps:
                    entry = data.rows[(actual_arch, app, component, "SARA")]
                    rates = entry["method_rates"]
                    if rates is None or entry["fi_rates"] is None:
                        continue
                    known = sum(float(rates[outcome]) for outcome in OUTCOMES)  # type: ignore[index]
                    values.append(max(0.0, 1.0 - known))
            rows.append([target, COMPONENT_LABELS[component], _pct(_mean(values), 3)])
    _write_md(output_dir / "unknown_summary.md", "SARA Unknown share summary", _md_table(["Target", "Component", "Unknown (%)"], rows))


def _run_plot(label: str, cmd: List[str], warnings: List[str]) -> bool:
    print(f"[paper-results] generating {label}: {' '.join(cmd)}")
    proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
    if proc.stdout:
        print(proc.stdout.rstrip())
    if proc.returncode != 0:
        detail_lines = [
            line.strip()
            for line in (proc.stderr + "\n" + proc.stdout).splitlines()
            if line.strip()
            and not line.startswith("Traceback")
            and not line.startswith("File ")
            and not line.startswith("raise SystemExit")
            and not line.startswith("^^^^^^^^")
        ]
        detail = detail_lines[-1] if detail_lines else f"exit {proc.returncode}"
        if "No module named 'matplotlib'" in detail:
            detail += "; rebuild the Docker image or install matplotlib in the current Python environment"
        message = f"{label} was not generated ({detail})."
        warnings.append(message)
        print(f"WARNING: {message}", file=sys.stderr)
        return False
    if proc.stderr:
        print(proc.stderr.rstrip(), file=sys.stderr)
    return True


def write_manifest(output_dir: Path, result_root: Path, apps: List[str], warnings: List[str], generated: List[str]) -> None:
    manifest = {
        "result_root": str(result_root),
        "output_dir": str(output_dir),
        "apps": apps,
        "generated": sorted(generated),
        "warnings": warnings,
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    warning_text = "\n".join(f"- {warning}" for warning in warnings) if warnings else "- none"
    generated_text = "\n".join(f"- `{name}`" for name in sorted(generated)) if generated else "- none"
    _write_md(
        output_dir / "summary.md",
        "Generated paper results",
        f"Result root: `{result_root}`\n\nGenerated artifacts:\n{generated_text}\n\nWarnings:\n{warning_text}\n",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-root", type=Path, default=ROOT / "sara-results")
    parser.add_argument("--output-dir", type=Path, help="Default: <result-root>/paper-results")
    parser.add_argument("--work-root", type=Path, default=ROOT / ".work")
    parser.add_argument("--apps", help="Optional comma/space-separated app list; default reads test_apps/.")
    parser.add_argument("--strict", action="store_true", help="Return nonzero if any result artifact cannot be generated.")
    args = parser.parse_args()

    result_root = args.result_root.resolve()
    output_dir = (args.output_dir.resolve() if args.output_dir else result_root / "paper-results")
    output_dir.mkdir(parents=True, exist_ok=True)
    apps = _discover_apps(result_root, args.apps)
    warnings: List[str] = []
    generated: List[str] = []

    if not result_root.is_dir():
        print(f"WARNING: result root does not exist: {result_root}", file=sys.stderr)
        return 1 if args.strict else 0
    if not apps:
        print("WARNING: no applications found; no paper results generated", file=sys.stderr)
        return 1 if args.strict else 0

    data = PaperData(result_root, apps)
    warnings.extend(sorted(set(data.warnings)))

    table_writers = [
        ("table_iii_accuracy_overall.md", lambda: write_accuracy_overall(data, output_dir)),
        ("table_iv_category_error.md", lambda: write_category_error(data, output_dir)),
        ("table_vi_component_breakdown.md", lambda: write_component_breakdown(data, output_dir)),
        ("table_v_speed_overall.md", lambda: write_speed_overall(data, output_dir)),
        ("unknown_summary.md", lambda: write_unknown_summary(data, output_dir)),
    ]
    for artifact_name, writer in table_writers:
        try:
            writer()
            generated.append(artifact_name)
        except Exception as exc:  # keep run_experiment from failing solely due paper artifact generation
            warnings.append(f"{artifact_name} was not generated: {exc}")

    fig45_ok = _run_plot(
        "Fig. 4 / Fig. 5",
        [
            sys.executable,
            str(PLOT_DIR / "plot_fig4_fig5.py"),
            "--result-root",
            str(result_root),
            "--output-dir",
            str(output_dir),
        ],
        warnings,
    )
    if fig45_ok:
        generated.extend(["perapp_accuracy_bars.pdf", "perapp_speedup_bars.pdf"])

    fig6_ok = _run_plot(
        "Fig. 6",
        [
            sys.executable,
            str(PLOT_DIR / "plot_sdc_source_breakdown.py"),
            "--work-root",
            str(args.work_root.resolve()),
            "--output",
            str(output_dir / "sdc_source_breakdown.pdf"),
            "--csv",
            str(output_dir / "sdc_source_breakdown.csv"),
        ],
        warnings,
    )
    if fig6_ok:
        generated.extend(["sdc_source_breakdown.pdf", "sdc_source_breakdown.csv"])
    else:
        warnings.append("Fig. 6 requires SARA intermediate summary_*.json files; rerun SARA with --keep-intermediate if it is needed.")

    # Remove duplicate warning strings while preserving order.
    deduped_warnings: List[str] = []
    seen = set()
    for warning in warnings:
        if warning not in seen:
            deduped_warnings.append(warning)
            seen.add(warning)
    warnings = deduped_warnings

    generated_with_manifest = generated + ["manifest.json", "summary.md"]
    write_manifest(output_dir, result_root, apps, warnings, generated_with_manifest)

    print(f"[paper-results] output directory: {output_dir}")
    if warnings:
        print("WARNING: paper result generation completed with missing or incomplete artifacts:", file=sys.stderr)
        max_console_warnings = 30
        for warning in warnings[:max_console_warnings]:
            print(f"  - {warning}", file=sys.stderr)
        if len(warnings) > max_console_warnings:
            print(
                f"  - ... {len(warnings) - max_console_warnings} more; see {output_dir / 'summary.md'}",
                file=sys.stderr,
            )
    else:
        print("[paper-results] all requested paper result artifacts generated")

    return 1 if args.strict and warnings else 0


if __name__ == "__main__":
    raise SystemExit(main())
