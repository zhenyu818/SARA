#!/usr/bin/env python3
"""Emit canonical output-oracle policies for SARA/FI/GEREM experiments.

The current experiment definition is exact-output SDC: for every benchmark,
including floating-point benchmarks, any final output mismatch is classified as
SDC. No absolute or relative tolerance is part of the oracle.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict


def policy_for_app(app: str) -> Dict[str, Any]:
    _ = str(app).strip()
    return {
        "source": "exact_output_mismatch_oracle",
        "compare_kind": "exact",
        "nan_equal": False,
        "inf_sign_must_match": True,
        "device_materialized": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Write the canonical exact-output oracle policy for one benchmark."
    )
    parser.add_argument("--app", required=True)
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()

    policy = policy_for_app(args.app)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
