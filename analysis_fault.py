#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import os
import re
import sys
from collections import defaultdict, Counter
from copy import deepcopy

# -----------------------------
# Core parsers and utilities (kept)
# -----------------------------


def normalize_result(s: str) -> str:
    """Normalize result category to Masked / SDC / DUE / Others"""
    x = s.strip().lower()
    if "sdc" in x:
        return "SDC"
    if "due" in x:
        return "DUE"
    if "masked" in x:
        return "Masked"
    return "Others"


def parse_log(log_path: str):
    """Parse log entries (supports inline Effects+WRITER/READER and segmented modes)."""
    re_effects_start = re.compile(
        r"^\[Run\s+(\d+)\]\s+Effects from\s+(?:.+/)?(tmp\.out\d+):\s*$"
    )
    re_effects_inline = re.compile(
        r"^\[Run\s+(\d+)\]\s+Effects from\s+(?:.+/)?(tmp\.out\d+):\s*(.*\S.*)$"
    )
    re_writer = re.compile(
        r"^\[(?P<src>[-A-Za-z0-9_]+)_FI_WRITER\].*?->\s*(\S+)\s+PC=.*\(([^:()]+):(\d+)\)\s*(.*)$"
    )
    re_reader = re.compile(
        r"^\[(?P<src>[-A-Za-z0-9_]+)_FI_READER\].*?->\s*(\S+)\s+PC=.*\(([^:()]+):(\d+)\)\s*(.*)$"
    )
    re_result = re.compile(r"^\[Run\s+(\d+)\]\s+(tmp\.out\d+):\s*(.*?)\s*$")
    re_params = re.compile(r"^\[INJ_PARAMS\]\s+\[Run\s+(\d+)\]\s+(tmp\.out\d+)\s+(.*)$")

    latest_effects_by_pair = {}
    params_by_pair = {}
    cur_key = None
    cur_writers, cur_readers = [], []

    occ_counter = defaultdict(int)
    effects_occ, results_occ = {}, {}

    def _merge_unique(writers, readers):
        seen = set()
        merged = []
        for rec in writers + readers:
            key = (
                rec.get("src"),
                rec.get("kernel"),
                rec.get("inst_line"),
                rec.get("inst_text"),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(deepcopy(rec))
        if not merged:
            merged = [
                {
                    "kernel": "invalid_summary",
                    "inst_line": -1,
                    "inst_text": "",
                    "src": "invalid",
                }
            ]
        return merged

    def _merge_records(existing, add):
        if not existing:
            return _merge_unique(add, [])
        if not add:
            return _merge_unique(existing, [])
        return _merge_unique(existing + add, [])

    def flush_current_effects():
        nonlocal cur_key, cur_writers, cur_readers
        if cur_key is not None:
            new_pack = _merge_unique(cur_writers, cur_readers)
            existed = latest_effects_by_pair.get(cur_key, [])
            latest_effects_by_pair[cur_key] = _merge_records(existed, new_pack)
            cur_key = None
            cur_writers, cur_readers = [], []

    if not os.path.exists(log_path):
        print(f"Warning: log file not found: {log_path}", file=sys.stderr)
        return {}, {}, {}

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.rstrip("\n")

            m = re_effects_inline.match(line)
            if m:
                run_id = int(m.group(1))
                name = m.group(2)
                rest = m.group(3).strip()
                new_key = (run_id, name)

                if cur_key != new_key:
                    flush_current_effects()
                    cur_key = new_key
                    cur_writers, cur_readers = [], []

                mw = re_writer.match(rest)
                if mw:
                    cur_writers.append(
                        {
                            "kernel": mw.group(2),
                            "inst_line": int(mw.group(4)),
                            "inst_text": mw.group(5).strip(),
                            "src": mw.group("src"),
                        }
                    )
                    continue
                mr = re_reader.match(rest)
                if mr:
                    cur_readers.append(
                        {
                            "kernel": mr.group(2),
                            "inst_line": int(mr.group(4)),
                            "inst_text": mr.group(5).strip(),
                            "src": mr.group("src"),
                        }
                    )
                    continue
                continue

            m = re_effects_start.match(line)
            if m:
                flush_current_effects()
                run_id = int(m.group(1))
                name = m.group(2)
                cur_key = (run_id, name)
                cur_writers, cur_readers = [], []
                continue

            if cur_key is not None:
                m = re_writer.match(line)
                if m:
                    cur_writers.append(
                        {
                            "kernel": m.group(2),
                            "inst_line": int(m.group(4)),
                            "inst_text": m.group(5).strip(),
                            "src": m.group("src"),
                        }
                    )
                    continue
                m = re_reader.match(line)
                if m:
                    cur_readers.append(
                        {
                            "kernel": m.group(2),
                            "inst_line": int(m.group(4)),
                            "inst_text": m.group(5).strip(),
                            "src": m.group("src"),
                        }
                    )
                    continue

            m = re_params.match(line)
            if m:
                run_id = int(m.group(1))
                name = m.group(2)
                params_by_pair[(run_id, name)] = m.group(3).strip()
                continue

            m = re_result.match(line)
            if m:
                run_id = int(m.group(1))
                name = m.group(2)
                res = normalize_result(m.group(3))
                pair = (run_id, name)

                occ_counter[pair] += 1
                idx = occ_counter[pair]
                inj_key = (run_id, name, idx)

                if cur_key == pair:
                    current_pack = _merge_unique(cur_writers, cur_readers)
                    existed = latest_effects_by_pair.get(pair, [])
                    recs = _merge_records(existed, current_pack)
                    latest_effects_by_pair[pair] = deepcopy(recs)
                else:
                    recs = latest_effects_by_pair.get(
                        pair,
                        [
                            {
                                "kernel": "invalid_summary",
                                "inst_line": -1,
                                "inst_text": "",
                                "src": "invalid",
                            }
                        ],
                    )

                effects_occ[inj_key] = deepcopy(recs)
                results_occ[inj_key] = res
                continue

    flush_current_effects()
    return effects_occ, results_occ, params_by_pair


# -----------------------------
# Output: ONLY Masked/SDC/DUE totals (CSV + stdout)
# -----------------------------


def write_summary_csv(
    app: str,
    test: str,
    components: str,
    bitflip: str,
    results_occ,
    injection_time_seconds=None,
    output_root=None,
):
    root = output_root or os.environ.get("TEST_RESULT_ROOT") or "test_result"
    out_dir = os.path.join(root, app)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(
        out_dir, f"test_result_{app}_{test}_{components}_{bitflip}.csv"
    )

    c = Counter(results_occ.values())
    row = {
        "Masked": int(c.get("Masked", 0)),
        "SDC": int(c.get("SDC", 0)),
        "DUE": int(c.get("DUE", 0)),
        "Injection Time (s)": (
            f"{float(injection_time_seconds):.6f}"
            if injection_time_seconds is not None
            else ""
        ),
    }

    fieldnames = ["Masked", "SDC", "DUE", "Injection Time (s)"]
    out_path_tmp = out_path + ".tmp"
    with open(out_path_tmp, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow(row)

    os.replace(out_path_tmp, out_path)
    return out_path, row


def validate_expected_trials(results_occ, expected_trials):
    if expected_trials is None:
        return
    observed = len(results_occ)
    if observed != expected_trials:
        raise ValueError(
            f"incomplete FI campaign: observed {observed} parsed trials, "
            f"expected {expected_trials}; refusing to write final CSV"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Parse inst_exec.log and output ONLY total counts of Masked/SDC/DUE."
    )
    parser.add_argument("--app", "-a", required=True, help="Application name")
    parser.add_argument("--test", "-t", required=True, help="Test identifier", type=str)
    parser.add_argument("--component", "-c", required=True, help="Component set")
    parser.add_argument("--bitflip", "-b", required=True, help="Number of bit flips to inject")
    parser.add_argument(
        "--injection-time-seconds",
        type=float,
        default=None,
        help="Measured wall-clock fault injection time in seconds",
    )
    parser.add_argument(
        "--output-root",
        default=os.environ.get("TEST_RESULT_ROOT", "test_result"),
        help=(
            "Directory where per-application FI result CSVs are written "
            "(default: TEST_RESULT_ROOT env or ./test_result)."
        ),
    )
    parser.add_argument(
        "--expected-trials",
        type=int,
        default=(
            int(os.environ["RUN_PER_EPOCH"])
            if os.environ.get("RUN_PER_EPOCH", "").isdigit()
            else None
        ),
        help=(
            "Require exactly this many parsed FI trials before writing the final CSV "
            "(default: RUN_PER_EPOCH env when set)."
        ),
    )
    parser.add_argument(
        "--log-path",
        default=None,
        help="Path to inst_exec.log (default: repository-root inst_exec.log).",
    )
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = args.log_path or os.path.join(base_dir, "inst_exec.log")

    _, results_occ, _ = parse_log(log_path)
    try:
        validate_expected_trials(
            results_occ,
            args.expected_trials,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    out_path, row = write_summary_csv(
        args.app,
        args.test,
        args.component,
        args.bitflip,
        results_occ,
        injection_time_seconds=args.injection_time_seconds,
        output_root=args.output_root,
    )

    # 终端打印统计结果；注入耗时由 fault_inject_exp.sh 输出
    print(f"Masked total: {row['Masked']}")
    print(f"SDC total:    {row['SDC']}")
    print(f"DUE total:    {row['DUE']}")
    print(f"Wrote CSV: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
