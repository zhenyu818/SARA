#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export RUN_ALL_STORAGE_FAIR_SKIP_SARA=1
export RUN_ALL_STORAGE_FAIR_SKIP_COMPARE="${RUN_ALL_STORAGE_FAIR_SKIP_COMPARE:-1}"
exec bash "${ROOT_DIR}/script/common/run_storage_campaign.sh" "$@"
