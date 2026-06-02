#!/usr/bin/env python3
"""Parse GPUFI_OUTPUT lines from a combined stdout/stderr log."""

import argparse
import json
import re
from pathlib import Path

REGEX = r"^GPUFI_OUTPUT\s+base=(0x[0-9a-fA-F]+)\s+bytes=([0-9]+)\s+name=([^\s]+)\s*$"
PATTERN = re.compile(REGEX)


def parse_lines(text: str):
    outputs = []
    for line in text.splitlines():
        match = PATTERN.match(line.strip())
        if not match:
            continue
        base, bytes_str, name = match.groups()
        outputs.append(
            {
                "base": base,
                "bytes": int(bytes_str),
                "name": name,
            }
        )
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract GPUFI_OUTPUT lines to outputs.json")
    parser.add_argument("logfile", type=Path, help="Path to combined stdout/stderr log")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("outputs.json"),
        help="Output JSON file path (default: outputs.json)",
    )
    args = parser.parse_args()

    text = args.logfile.read_text(errors="replace")
    outputs = parse_lines(text)
    args.output.write_text(json.dumps(outputs, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
