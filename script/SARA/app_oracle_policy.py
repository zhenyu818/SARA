#!/usr/bin/env python3
"""Emit canonical SARA output-oracle policies from explicit benchmark code."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict


FLOAT32_ABS_1E5_APPS = {
    "AdamW",
    "Attention",
    "Dijkstra",
    "Gelu",
    "Gemm",
    "GESpmm",
    "LayerNorm",
    "MatrixFactorization",
    "MatrixMultiplication",
    "Render",
    "Softmax",
}


def _float_policy(abs_tol: float) -> Dict[str, Any]:
    return {
        "source": "explicit_application_oracle",
        "compare_kind": "float_abs_tol",
        "scalar_kind": "float32",
        "float_abs_tol": float(abs_tol),
        "float_rel_tol": 0.0,
        "nan_equal": True,
        "inf_sign_must_match": True,
        "device_materialized": True,
    }


def policy_for_app(app: str) -> Dict[str, Any]:
    name = str(app).strip()
    if name in FLOAT32_ABS_1E5_APPS:
        return _float_policy(1.0e-5)
    return {
        "source": "explicit_application_oracle",
        "compare_kind": "exact",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Write the canonical SARA output-oracle policy for one benchmark."
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
