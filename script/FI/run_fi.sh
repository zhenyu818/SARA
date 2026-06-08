#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUNS_PER_COMPONENT="${RUN_PER_EPOCH:-1000}"
FI_PARALLEL_JOBS="${FI_PARALLEL_JOBS:-8}"
RUN_ROOT="${RUN_ROOT:-${ROOT_DIR}/fi_storage_runs_all}"
TEST_RESULT_ROOT="${TEST_RESULT_ROOT:-${ROOT_DIR}/test_result}"
APPS_OVERRIDE="${APPS_OVERRIDE:-}"
RESULT_BASENAME="${RESULT_BASENAME:-0-0}"
PREBUILD_SCRIPT="${FI_PREBUILD_SCRIPT:-${ROOT_DIR}/script/common/storage_app_prebuild.sh}"
FI_PREBUILD_CACHE_ROOT="${FI_PREBUILD_CACHE_ROOT:-${RUN_ROOT}/storage_prebuilds}"
FI_METHOD_RESULT_ROOT="${FI_METHOD_RESULT_ROOT:-${RUN_ROOT}/method_results}"
GPU_ARCH="${GPU_ARCH:-auto}"
FI_SKIP_COMMON_BUILD="${FI_SKIP_COMMON_BUILD:-0}"
FI_BUILD_JOBS="${FI_BUILD_JOBS:-$(nproc 2>/dev/null || echo 4)}"

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

if ! [[ "${FI_PARALLEL_JOBS}" =~ ^[0-9]+$ ]] || (( FI_PARALLEL_JOBS <= 0 )); then
  FI_PARALLEL_JOBS=8
fi

cd "${ROOT_DIR}"

resolve_cuda_install_path() {
  if [[ -n "${CUDA_INSTALL_PATH:-}" && -d "${CUDA_INSTALL_PATH}" && -x "${CUDA_INSTALL_PATH}/bin/nvcc" ]]; then
    return 0
  fi
  local -a candidates=()
  local nvcc_path=""
  if nvcc_path="$(command -v nvcc 2>/dev/null)"; then
    candidates+=("$(cd "$(dirname "${nvcc_path}")/.." && pwd)")
  fi
  candidates+=("/usr/local/cuda")
  local d
  for d in /usr/local/cuda-*; do
    [[ -d "${d}" ]] || continue
    candidates+=("${d}")
  done
  local candidate
  for candidate in "${candidates[@]}"; do
    [[ -d "${candidate}" ]] || continue
    if [[ -x "${candidate}/bin/nvcc" ]]; then
      export CUDA_INSTALL_PATH="${candidate}"
      return 0
    fi
  done
  return 1
}

setup_gpgpusim_environment() {
  if ! resolve_cuda_install_path; then
    echo "=== Error: could not find a valid CUDA toolkit path with nvcc. ===" >&2
    return 1
  fi
  set +u
  source setup_environment || true
  set -u
  if [[ "${DISABLE_GPGPUSIM_POWER_MODEL:-0}" == "1" ]]; then
    unset GPGPUSIM_POWER_MODEL || true
  fi
  if [[ "${GPGPUSIM_SETUP_ENVIRONMENT_WAS_RUN:-}" != "1" ]]; then
    echo "=== Error: setup_environment did not complete successfully. ===" >&2
    return 1
  fi
}

run_common_build() {
  if [[ "${FI_SKIP_COMMON_BUILD}" == "1" ]]; then
    echo "==== Skipping FI common simulator build (FI_SKIP_COMMON_BUILD=1) ===="
    setup_gpgpusim_environment
    return 0
  fi
  setup_gpgpusim_environment
  if ! [[ "${FI_BUILD_JOBS}" =~ ^[0-9]+$ ]] || (( FI_BUILD_JOBS <= 0 )); then
    FI_BUILD_JOBS=4
  fi
  if (( FI_BUILD_JOBS > 8 )); then
    FI_BUILD_JOBS=8
  fi
  echo "==== Running FI common simulator build (excluded from noncompile-E2E timing) ===="
  make clean >/dev/null 2>&1 || true
  make -j"${FI_BUILD_JOBS}"
}

prebuild_app() {
  local app="$1"
  rm -rf "${FI_PREBUILD_CACHE_ROOT}/${app}" "${FI_METHOD_RESULT_ROOT}/${app}"
  TEST_APP_NAME="${app}" \
  RESULT_BASENAME="${RESULT_BASENAME}" \
  TEST_APPS_ROOT="${ROOT_DIR}/test_apps" \
  STORAGE_PREBUILD_CACHE_ROOT="${FI_PREBUILD_CACHE_ROOT}" \
  GPU_ARCH="${GPU_ARCH}" \
  bash "${PREBUILD_SCRIPT}"
}

csv_has_e2e_time() {
  local csv_path="$1"
  [[ -f "${csv_path}" ]] || return 1
  python3 - "${csv_path}" <<'PY'
import csv, sys
with open(sys.argv[1], newline='', encoding='utf-8', errors='replace') as f:
    row = next(csv.DictReader(f), {})
val = str(row.get('End-to-End Time (s)', '')).strip()
raise SystemExit(0 if val else 1)
PY
}

app_total="${#APPS[@]}"
component_total="${#COMPONENT_IDS[@]}"

run_common_build

for app_idx in "${!APPS[@]}"; do
  app="${APPS[$app_idx]}"
  app_num=$((app_idx + 1))
  echo "==== [${app_num}/${app_total}] Storage FI for ${app} ===="
  prebuild_app "${app}"
  for idx in "${!COMPONENT_IDS[@]}"; do
    comp="${COMPONENT_IDS[$idx]}"
    comp_name="${COMPONENT_NAMES[$idx]}"
    comp_num=$((idx + 1))
    result_csv="${TEST_RESULT_ROOT}/${app}/test_result_${app}_${RESULT_BASENAME}_${comp}_1.csv"
    if csv_has_e2e_time "${result_csv}"; then
      echo "=== Skip existing noncompile-E2E result: ${result_csv} ==="
      continue
    fi
    rm -rf "${RUN_ROOT}/${comp_name}/${app}"
    echo "==== [${comp_num}/${component_total}] ${app} / ${comp_name} / runs=${RUNS_PER_COMPONENT} ===="
    TEST_APP_NAME="${app}" \
    COMPONENT_SET="${comp}" \
    RUN_PER_EPOCH="${RUNS_PER_COMPONENT}" \
    FI_PARALLEL_JOBS="${FI_PARALLEL_JOBS}" \
    RESULT_BASENAME="${RESULT_BASENAME}" \
    DO_BUILD=0 \
    DO_RESULT_GEN=1 \
    FI_NONCOMPILE_E2E=1 \
    FI_LOG_ROOT="${RUN_ROOT}/${comp_name}" \
    STORAGE_PREBUILD_CACHE_ROOT="${FI_PREBUILD_CACHE_ROOT}" \
    STORAGE_METHOD_RESULT_ROOT="${FI_METHOD_RESULT_ROOT}/${comp_name}" \
    TEST_RESULT_ROOT="${TEST_RESULT_ROOT}" \
    FI_PROGRESS_APP="${app}" \
    FI_PROGRESS_APP_INDEX="${app_num}" \
    FI_PROGRESS_APP_TOTAL="${app_total}" \
    FI_PROGRESS_COMPONENT="${comp_name}" \
    FI_PROGRESS_COMPONENT_INDEX="${comp_num}" \
    FI_PROGRESS_COMPONENT_TOTAL="${component_total}" \
    GPU_ARCH="${GPU_ARCH}" \
    bash "${SCRIPT_DIR}/run_fi_app.sh"
  done
done

echo "=== Storage FI noncompile-E2E run finished ==="
