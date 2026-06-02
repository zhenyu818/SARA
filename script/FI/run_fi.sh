#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUNS_PER_COMPONENT="${RUN_PER_EPOCH:-1000}"
RUN_ROOT="${RUN_ROOT:-${ROOT_DIR}/fi_storage_runs_all}"
COMPARE_INPUT_ROOT="${FI_COMPARE_INPUT_ROOT:-${ROOT_DIR}/exact_sdc_runs_all}"
TEST_RESULT_ROOT="${TEST_RESULT_ROOT:-${ROOT_DIR}/test_result}"
APPS_OVERRIDE="${APPS_OVERRIDE:-}"

COMPONENT_IDS=(0 2 3 6)
COMPONENT_NAMES=(rf smem_rf l1d l2)

if [[ -n "${APPS_OVERRIDE}" ]]; then
  read -r -a APPS <<< "${APPS_OVERRIDE//,/ }"
else
  mapfile -t APPS < <(find "${ROOT_DIR}/test_apps" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)
fi

if [[ ${#APPS[@]} -eq 0 ]]; then
  echo "Error: no application directories were found under test_apps." >&2
  exit 1
fi

cd "${ROOT_DIR}"

app_total="${#APPS[@]}"
component_total="${#COMPONENT_IDS[@]}"

for app_idx in "${!APPS[@]}"; do
  app="${APPS[$app_idx]}"
  app_num=$((app_idx + 1))
  echo "==== [${app_num}/${app_total}] Storage FI for ${app} ===="
  for idx in "${!COMPONENT_IDS[@]}"; do
    comp="${COMPONENT_IDS[$idx]}"
    comp_name="${COMPONENT_NAMES[$idx]}"
    comp_num=$((idx + 1))
    result_csv="${TEST_RESULT_ROOT}/${app}/test_result_${app}_0-0_${comp}_1.csv"
    if [[ -f "${result_csv}" ]]; then
      echo "=== Skip existing result: ${result_csv} ==="
      continue
    fi
    rm -rf "${RUN_ROOT}/${comp_name}/${app}"
    echo "==== [${comp_num}/${component_total}] ${app} / ${comp_name} / runs=${RUNS_PER_COMPONENT} ===="
    TEST_APP_NAME="${app}" \
    COMPONENT_SET="${comp}" \
    RUN_PER_EPOCH="${RUNS_PER_COMPONENT}" \
    DO_BUILD=0 \
    DO_RESULT_GEN=0 \
    FI_LOG_ROOT="${RUN_ROOT}/${comp_name}" \
    FI_COMPARE_INPUT_ROOT="${COMPARE_INPUT_ROOT}" \
    TEST_RESULT_ROOT="${TEST_RESULT_ROOT}" \
    FI_PROGRESS_APP="${app}" \
    FI_PROGRESS_APP_INDEX="${app_num}" \
    FI_PROGRESS_APP_TOTAL="${app_total}" \
    FI_PROGRESS_COMPONENT="${comp_name}" \
    FI_PROGRESS_COMPONENT_INDEX="${comp_num}" \
    FI_PROGRESS_COMPONENT_TOTAL="${component_total}" \
    bash "${SCRIPT_DIR}/run_fi_app.sh"
  done
done

echo "=== Storage FI resume run finished ==="
