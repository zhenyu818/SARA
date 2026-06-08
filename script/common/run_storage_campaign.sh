#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${ROOT_DIR}"

TEST_APPS_DIR="${RUN_ALL_STORAGE_FAIR_TEST_APPS_DIR:-${ROOT_DIR}/test_apps}"
TEST_RESULT_DIR="${RUN_ALL_STORAGE_FAIR_TEST_RESULT_DIR:-${ROOT_DIR}/test_result}"
RESULT_BASENAME="${RUN_ALL_STORAGE_FAIR_RESULT_BASENAME:-0-0}"
ONLY_APP="${RUN_ALL_STORAGE_FAIR_ONLY_APP:-}"
SKIP_COMMON_BUILD="${RUN_ALL_STORAGE_FAIR_SKIP_COMMON_BUILD:-0}"
COMMON_BUILD_SCRIPT="${RUN_ALL_STORAGE_FAIR_COMMON_BUILD_SCRIPT:-}"
BUILD_JOBS="${RUN_ALL_STORAGE_FAIR_BUILD_JOBS:-$(nproc 2>/dev/null || echo 4)}"
NICE_LEVEL="${RUN_ALL_STORAGE_FAIR_NICE:-0}"
SARA_SCRIPT="${RUN_ALL_STORAGE_FAIR_SARA_SCRIPT:-${ROOT_DIR}/script/SARA/run_sara_app.sh}"
GEREM_SCRIPT="${RUN_ALL_STORAGE_FAIR_GEREM_SCRIPT:-${ROOT_DIR}/script/GEREM/run_gerem_app.sh}"
PREBUILD_SCRIPT="${RUN_ALL_STORAGE_FAIR_PREBUILD_SCRIPT:-${ROOT_DIR}/script/common/storage_app_prebuild.sh}"
COMPARE_SCRIPT="${RUN_ALL_STORAGE_FAIR_COMPARE_SCRIPT:-${ROOT_DIR}/script/common/storage_only_sara_gerem_fi_compare.py}"
COMPARE_OUTPUT="${RUN_ALL_STORAGE_FAIR_COMPARE_OUTPUT:-${ROOT_DIR}/compare/storage_only_sara_vs_gerem_vs_fi.txt}"
SARA_WORK_ROOT="${RUN_ALL_STORAGE_FAIR_SARA_WORK_ROOT:-${ROOT_DIR}/sara_runs_all_fair}"
GEREM_WORK_ROOT="${RUN_ALL_STORAGE_FAIR_GEREM_WORK_ROOT:-${ROOT_DIR}/GEREM_runs_all_fair}"
STORAGE_PREBUILD_CACHE_ROOT="${RUN_ALL_STORAGE_FAIR_STORAGE_PREBUILD_CACHE_ROOT:-${ROOT_DIR}/storage_app_prebuilds_fair}"
SKIP_SARA="${RUN_ALL_STORAGE_FAIR_SKIP_SARA:-0}"
SKIP_GEREM="${RUN_ALL_STORAGE_FAIR_SKIP_GEREM:-0}"
SKIP_COMPARE="${RUN_ALL_STORAGE_FAIR_SKIP_COMPARE:-0}"
SARA_STORAGE_GROUP_MODE="${SARA_STORAGE_GROUP_MODE:-grouped}"
SARA_ANALYZER_SHARE_CACHE_SITE_RECORDS="${RUN_ALL_STORAGE_FAIR_SARA_ANALYZER_SHARE_CACHE_SITE_RECORDS:-1}"

run_script() {
    local script_path="$1"
    shift
    if [[ "${script_path}" == *.py ]]; then
        python3 "${script_path}" "$@"
    else
        bash "${script_path}" "$@"
    fi
}

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
    if [[ "${SKIP_COMMON_BUILD}" == "1" ]]; then
        echo "==== Skipping common simulator build (RUN_ALL_STORAGE_FAIR_SKIP_COMMON_BUILD=1) ===="
        return 0
    fi
    if [[ -n "${COMMON_BUILD_SCRIPT}" ]]; then
        echo "==== Running common build hook: ${COMMON_BUILD_SCRIPT} ===="
        run_script "${COMMON_BUILD_SCRIPT}"
        return 0
    fi
    setup_gpgpusim_environment
    if ! [[ "${BUILD_JOBS}" =~ ^[0-9]+$ ]] || (( BUILD_JOBS <= 0 )); then
        BUILD_JOBS=4
    fi
    if (( BUILD_JOBS > 8 )); then
        BUILD_JOBS=8
    fi
    echo "==== Running common simulator build (excluded from fair timing) ===="
    make clean >/dev/null 2>&1 || true
    make -j"${BUILD_JOBS}"
}

cleanup_app_state() {
    local app_name="$1"
    if [[ "${SKIP_SARA}" != "1" ]]; then
        rm -rf "${SARA_WORK_ROOT}/${app_name}"
        rm -f "${TEST_RESULT_DIR}/${app_name}/sara_result_${app_name}_${RESULT_BASENAME}.csv"
        rm -f "${TEST_RESULT_DIR}/${app_name}/sara_result_simple_${app_name}_${RESULT_BASENAME}.csv"
    fi
    rm -rf "${STORAGE_PREBUILD_CACHE_ROOT}/${app_name}"
    rm -rf "${TEST_APPS_DIR}/${app_name}/result"
    if [[ "${SKIP_GEREM}" != "1" ]]; then
        rm -rf "${GEREM_WORK_ROOT}/${app_name}"
        rm -f "${TEST_RESULT_DIR}/${app_name}/gerem_result_${app_name}_${RESULT_BASENAME}.csv"
        rm -f "${TEST_RESULT_DIR}/${app_name}/gerem_result_simple_${app_name}_${RESULT_BASENAME}.csv"
    fi
}


run_sara_for_app() {
    local app_name="$1"
    local rc
    set +e
    env \
        DO_BUILD=0 \
        DO_RESULT_GEN=1 \
        FAIR_TIMING=1 \
        FRESH_RUN=1 \
        PREBUILD_ONLY=0 \
        RESULT_BASENAME="${RESULT_BASENAME}" \
        TEST_APP_NAME="${app_name}" \
        TEST_APPS_ROOT="${TEST_APPS_DIR}" \
        TEST_RESULT_ROOT="${TEST_RESULT_DIR}" \
        EXACT_WORK_ROOT="${SARA_WORK_ROOT}" \
        STORAGE_PREBUILD_CACHE_ROOT="${STORAGE_PREBUILD_CACHE_ROOT}" \
        STORAGE_METHOD_RESULT_ROOT="${SARA_WORK_ROOT}/method_results" \
        EXACT_STORAGE_ONLY_OUTPUT=1 \
        EXACT_STORAGE_GROUP_MODE="${SARA_STORAGE_GROUP_MODE}" \
        ANALYZER_SHARE_CACHE_SITE_RECORDS="${SARA_ANALYZER_SHARE_CACHE_SITE_RECORDS}" \
        EXACT_TOGGLE_VALIDATE="${EXACT_TOGGLE_VALIDATE:-0}" \
        STORAGE_APP_PREBUILD_HELPER="${PREBUILD_SCRIPT}" \
        UPDATE_SIMPLE_SUMMARY_TOTAL_TIME_TOOL="${ROOT_DIR}/script/common/update_simple_summary_total_time.py" \
        nice -n "${NICE_LEVEL}" bash "${SARA_SCRIPT}" all_components
    rc=$?
    set -e
    return "${rc}"
}

run_gerem_for_app() {
    local app_name="$1"
    env \
        DO_BUILD=0 \
        DO_RESULT_GEN=1 \
        FAIR_TIMING=1 \
        FRESH_RUN=1 \
        PREBUILD_ONLY=0 \
        RESULT_BASENAME="${RESULT_BASENAME}" \
        TEST_APP_NAME="${app_name}" \
        TEST_RESULT_ROOT="${TEST_RESULT_DIR}" \
        GEREM_WORK_ROOT="${GEREM_WORK_ROOT}" \
        STORAGE_PREBUILD_CACHE_ROOT="${STORAGE_PREBUILD_CACHE_ROOT}" \
        STORAGE_METHOD_RESULT_ROOT="${GEREM_WORK_ROOT}/method_results" \
        GEREM_STORAGE_CAMPAIGN_RUNS="${GEREM_STORAGE_CAMPAIGN_RUNS:-1000}" \
        STORAGE_APP_PREBUILD_HELPER="${PREBUILD_SCRIPT}" \
        UPDATE_SIMPLE_SUMMARY_TOTAL_TIME_TOOL="${ROOT_DIR}/script/common/update_simple_summary_total_time.py" \
        nice -n "${NICE_LEVEL}" bash "${GEREM_SCRIPT}"
}

run_prebuild_for_app() {
    local app_name="$1"
    env \
        RESULT_BASENAME="${RESULT_BASENAME}" \
        TEST_APP_NAME="${app_name}" \
        TEST_APPS_ROOT="${TEST_APPS_DIR}" \
        STORAGE_PREBUILD_CACHE_ROOT="${STORAGE_PREBUILD_CACHE_ROOT}" \
        bash "${PREBUILD_SCRIPT}"
}

main() {
    [[ -d "${TEST_APPS_DIR}" ]] || { echo "=== Error: test apps dir missing: ${TEST_APPS_DIR} ===" >&2; exit 1; }
    mkdir -p "${TEST_RESULT_DIR}"
    [[ -f "${SARA_SCRIPT}" ]] || { echo "=== Error: SARA script missing: ${SARA_SCRIPT} ===" >&2; exit 1; }
    [[ -f "${GEREM_SCRIPT}" ]] || { echo "=== Error: GEREM script missing: ${GEREM_SCRIPT} ===" >&2; exit 1; }
    [[ -f "${PREBUILD_SCRIPT}" ]] || { echo "=== Error: prebuild script missing: ${PREBUILD_SCRIPT} ===" >&2; exit 1; }
    [[ -f "${COMPARE_SCRIPT}" ]] || { echo "=== Error: compare script missing: ${COMPARE_SCRIPT} ===" >&2; exit 1; }
    [[ "${SKIP_COMMON_BUILD}" =~ ^[01]$ ]] || { echo "=== Error: RUN_ALL_STORAGE_FAIR_SKIP_COMMON_BUILD must be 0 or 1 ===" >&2; exit 1; }
    [[ "${SKIP_SARA}" =~ ^[01]$ ]] || { echo "=== Error: RUN_ALL_STORAGE_FAIR_SKIP_SARA must be 0 or 1 ===" >&2; exit 1; }
    [[ "${SKIP_GEREM}" =~ ^[01]$ ]] || { echo "=== Error: RUN_ALL_STORAGE_FAIR_SKIP_GEREM must be 0 or 1 ===" >&2; exit 1; }
    [[ "${SKIP_COMPARE}" =~ ^[01]$ ]] || { echo "=== Error: RUN_ALL_STORAGE_FAIR_SKIP_COMPARE must be 0 or 1 ===" >&2; exit 1; }
    if [[ "${SKIP_SARA}" == "1" && "${SKIP_GEREM}" == "1" ]]; then
        echo "=== Error: cannot skip both SARA and GEREM ===" >&2
        exit 1
    fi

    local -a apps=()
    local app_dir app_name
    while IFS= read -r app_dir; do
        app_name="$(basename "${app_dir}")"
        if [[ -n "${ONLY_APP}" && "${ONLY_APP}" != "${app_name}" ]]; then
            continue
        fi
        apps+=("${app_name}")
    done < <(find "${TEST_APPS_DIR}" -mindepth 1 -maxdepth 1 -type d | sort)

    if (( ${#apps[@]} == 0 )); then
        echo "=== Error: no applications matched RUN_ALL_STORAGE_FAIR_ONLY_APP='${ONLY_APP}' ===" >&2
        exit 1
    fi

    mkdir -p "${SARA_WORK_ROOT}" "${GEREM_WORK_ROOT}" "${STORAGE_PREBUILD_CACHE_ROOT}"
    run_common_build

    local total_apps="${#apps[@]}"
    local index=0
    for app_name in "${apps[@]}"; do
        index=$((index + 1))
        echo "==== [${index}/${total_apps}] Fair storage rerun for ${app_name} ===="
        cleanup_app_state "${app_name}"
        run_prebuild_for_app "${app_name}"
        if [[ "${SKIP_SARA}" != "1" ]]; then
            run_sara_for_app "${app_name}"
        fi
        if [[ "${SKIP_GEREM}" != "1" ]]; then
            run_gerem_for_app "${app_name}"
        fi
    done

    if [[ "${SKIP_COMPARE}" != "1" ]]; then
        STORAGE_ONLY_COMPARE_OUTPUT_PATH="${COMPARE_OUTPUT}" \
            STORAGE_ONLY_COMPARE_TEST_RESULT_DIR="${TEST_RESULT_DIR}" \
            STORAGE_ONLY_COMPARE_EXACT_WORK_ROOT="${SARA_WORK_ROOT}" \
            STORAGE_ONLY_COMPARE_GEREM_WORK_ROOT="${GEREM_WORK_ROOT}" \
            run_script "${COMPARE_SCRIPT}" >/dev/null
    fi
    if [[ "${SKIP_COMPARE}" == "1" ]]; then
        echo "==== Skipped compare generation (RUN_ALL_STORAGE_FAIR_SKIP_COMPARE=1) ===="
    elif [[ "${SKIP_GEREM}" == "1" ]]; then
        echo "==== Updated ${COMPARE_OUTPUT} with SARA-only fair cold-start storage results ===="
    elif [[ "${SKIP_SARA}" == "1" ]]; then
        echo "==== Updated ${COMPARE_OUTPUT} with GEREM-only fair cold-start storage results ===="
    else
        echo "==== Updated ${COMPARE_OUTPUT} with SARA/GEREM fair cold-start storage results ===="
    fi
}

main "$@"
