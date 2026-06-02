#!/usr/bin/env python3
"""Update or append the `Total Time (s)` line in a simple-summary file."""

from __future__ import annotations

import argparse
from pathlib import Path


def update_total_time_lines(lines: list[str], total_seconds: float) -> list[str]:
    target = f"Total Time (s): {total_seconds:.6f}"
    updated: list[str] = []
    replaced = False
    for line in lines:
        if line.startswith("Total Time (s):"):
            updated.append(target)
            replaced = True
        else:
            updated.append(line)
    if not replaced:
        updated.append(target)
    return updated


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--total-seconds", type=float, required=True, dest="total_seconds")
    args = parser.parse_args()

    lines = args.summary.read_text(encoding="utf-8").splitlines()
    updated = update_total_time_lines(lines, args.total_seconds)
    args.summary.write_text("\n".join(updated) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
