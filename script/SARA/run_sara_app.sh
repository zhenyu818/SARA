#!/bin/bash

set -euo pipefail

SARA_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SARA_ROOT_DIR="$(cd "${SARA_SCRIPT_DIR}/../.." && pwd)"
SARA_COMMON_DIR="${SARA_ROOT_DIR}/script/common"
export PYTHONPATH="${SARA_COMMON_DIR}:${SARA_SCRIPT_DIR}:${PYTHONPATH:-}"
cd "${SARA_ROOT_DIR}"

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    MODE="${1:-run}"
    shift || true
else
    MODE="${MODE:-run}"
fi

EXACT_SEMANTICS_PROFILE="canonical_proof_exact_v3"
SARA_SEMANTICS_PROFILE="canonical_proof_sara_v3"
EXACT_REMOVED_SEMANTIC_ENV_VARS=(
    STRICT_EXACT
    STRICT_REPLACEMENT
    STRICT_REPLACEMENT_HARD
    UNKNOWN_POLICY
    TRACE_EXPANDING_POLICY
    TRACE_UNCOVERED_MODE
    TRACE_DIVERGENCE_POLICY
    ADDR_FAULT_POLICY
    ADDR_DUE_MODE
    ADDR_BITS
    CACHE_TAG_CLASS_POLICY
    METADATA_FAULT_POLICY
    SMEM_DOMAIN_POLICY
    RF_DOMAIN_POLICY
    SMEM_ERROR_PROPAGATION_MODEL
    SMEM_ADDR_EXCEPTION_POLICY
    RF_ADDR_REG_POLICY
    USE_SAMPLING_SPACE_DOMAIN
    USE_SAMPLING_SPACE_DOMAIN_RF
    USE_SAMPLING_SPACE_DOMAIN_SMEM
    CONSUMER_COMPARE
    SAME_CYCLE_EFFECT_PROB
    RF_FAULT_MODEL
    MISSING_ACTIVE_THREADS_POLICY
    OUTPUT_ORACLE_TOL_POLICY
    FI_OUTPUT_ORACLE_TOL_POLICY
    ANALYZER_PREPARE_DERIVE_MISSING_MEMORY_RANGES
)
declare -a exact_removed_semantic_env_overrides=()
for exact_removed_name in "${EXACT_REMOVED_SEMANTIC_ENV_VARS[@]}"; do
    if [[ -v ${exact_removed_name} ]]; then
        exact_removed_semantic_env_overrides+=("${exact_removed_name}")
    fi
done
if (( ${#exact_removed_semantic_env_overrides[@]} > 0 )); then
    echo "=== Error: removed SARA semantic overrides detected: ${exact_removed_semantic_env_overrides[*]} ===" >&2
    echo "=== sara_semantics_profile=${SARA_SEMANTICS_PROFILE} ===" >&2
    echo "=== SARA uses fixed canonical semantics and preserves unresolved mass as unknown. ===" >&2
    exit 2
fi

TEST_APP_NAME="${TEST_APP_NAME:-Pathfinder}"
TEST_APPS_ROOT="${TEST_APPS_ROOT:-test_apps}"
TEST_RESULT_ROOT="${TEST_RESULT_ROOT:-test_result}"
COMPONENT_SET="${COMPONENT_SET:-0}" # kept for convention parity with fault_inject_exp.sh
INJECT_BIT_FLIP_COUNT="${INJECT_BIT_FLIP_COUNT:-1}" # kept for convention parity
RUN_PER_EPOCH="${RUN_PER_EPOCH:-100}" # kept for convention parity
GPU_ARCH="${GPU_ARCH:-auto}"

DO_BUILD="${DO_BUILD:-1}"
DO_RESULT_GEN="${DO_RESULT_GEN:-1}"
FAIR_TIMING="${FAIR_TIMING:-0}"
FRESH_RUN="${FRESH_RUN:-0}"
PREBUILD_ONLY="${PREBUILD_ONLY:-0}"

TRACE_TEMPLATE="${TRACE_TEMPLATE:-}"
ACTIVE_THREADS_LOG="${ACTIVE_THREADS_LOG:-}"
RESULT_BASENAME="${RESULT_BASENAME:-}" # e.g. 0-0.txt
TIMEOUT_VAL="${TIMEOUT_VAL:-400s}"

EXACT_WORK_ROOT="${EXACT_WORK_ROOT:-exact_sdc_runs}"
CSV_OUTPUT="${CSV_OUTPUT:-${TEST_RESULT_ROOT}/exact_sdc_summary.csv}"
BENCH_LIST_FILE="${BENCH_LIST_FILE:-}"
EXACT_STORAGE_ONLY_OUTPUT="${EXACT_STORAGE_ONLY_OUTPUT:-1}"
STORAGE_APP_PREBUILD_HELPER="${STORAGE_APP_PREBUILD_HELPER:-${SARA_COMMON_DIR}/storage_app_prebuild.sh}"
UPDATE_SIMPLE_SUMMARY_TOTAL_TIME_TOOL="${UPDATE_SIMPLE_SUMMARY_TOTAL_TIME_TOOL:-script/common/update_simple_summary_total_time.py}"

if [[ "${FAIR_TIMING}" == "1" && "${EXACT_STORAGE_ONLY_OUTPUT}" == "1" && ! -v EXACT_TOGGLE_VALIDATE ]]; then
    export EXACT_TOGGLE_VALIDATE=0
fi

# Sampling-domain controls for exact weighting.
# Leave empty to auto-resolve from campaign_profile tmp.out / campaign settings.
WEIGHT_THREAD_RAND_MAX="${WEIGHT_THREAD_RAND_MAX:-}" # >0; auto: profile-tmp/campaign/default(512)
WEIGHT_BLOCK_RAND_MAX="${WEIGHT_BLOCK_RAND_MAX:-}" # >=0; auto: profile-tmp/campaign/default(2)
WEIGHT_SMEM_SIZE_BITS="${WEIGHT_SMEM_SIZE_BITS:-}" # >0; auto: profile-tmp/campaign/golden-log
WEIGHT_L1D_SIZE_BITS="${WEIGHT_L1D_SIZE_BITS:-}" # >0; auto: config/campaign
WEIGHT_L1D_TAG_BITS="${WEIGHT_L1D_TAG_BITS:-auto}" # auto|>=0; keep aligned with campaign tag-domain bits
WEIGHT_L1D_LINE_SIZE_BYTES="${WEIGHT_L1D_LINE_SIZE_BYTES:-}" # >0; auto: config/default(128)
WEIGHT_L1D_SHADERS="${WEIGHT_L1D_SHADERS:-}" # shader domain list (e.g. 0:1); auto: campaign SHADER_USED
L1D_SHADERS="${L1D_SHADERS:-${WEIGHT_L1D_SHADERS:-auto}}" # auto|all|0:K list
WEIGHT_L2_SIZE_BITS="${WEIGHT_L2_SIZE_BITS:-}" # >0; auto: config/campaign
WEIGHT_L2_TAG_BITS="${WEIGHT_L2_TAG_BITS:-auto}" # auto|>=0; keep aligned with campaign tag-domain bits
WEIGHT_L2_LINE_SIZE_BYTES="${WEIGHT_L2_LINE_SIZE_BYTES:-}" # >0; auto: config/default(128)
WEIGHT_L2_GLOBAL_PREFILL="${WEIGHT_L2_GLOBAL_PREFILL:-auto}" # auto|0|1; 1 mirrors gpgpu_perf_sim_memcpy prefill
PROFILE_TMP_OUT="${PROFILE_TMP_OUT:-auto}" # auto|<path>; parse program-dependent domains from campaign_profile tmp.out
EXACT_TRACE_JSONL="${EXACT_TRACE_JSONL:-0}"
EXACT_CYCLES_FILE_OVERRIDE="${EXACT_CYCLES_FILE_OVERRIDE:-}" # optional explicit cycles-domain file for exact FI-space snapshot
ADDR_VALID_RANGES_PATH="${ADDR_VALID_RANGES_PATH:-}" # optional JSON ranges for address validity checks
FAULT_COMPONENT="${FAULT_COMPONENT:-rf}" # rf|smem_rf|smem_lds|l1d|l2|gmem
EXACT_STORAGE_GROUP_MODE="${EXACT_STORAGE_GROUP_MODE:-legacy}"

VALIDATE_MAX_CYCLES="${VALIDATE_MAX_CYCLES:-2}"
VALIDATE_MAX_THREADS="${VALIDATE_MAX_THREADS:-2}"
VALIDATE_MAX_REGS="${VALIDATE_MAX_REGS:-2}"
VALIDATE_BITS="${VALIDATE_BITS:-1:2}"
VALIDATE_TOL="${VALIDATE_TOL:-1e-12}"

OUTPUT_ORACLE_TIMEOUT_EXIT_STATUSES="${OUTPUT_ORACLE_TIMEOUT_EXIT_STATUSES:-124:137}"

CONFIG_FILE="./gpgpusim.config"
SUCCESS_MSG="Fault Injection Test Success!"
FAILED_MSG="Fault Injection Test Failed!"
CYCLES_MSG="gpu_tot_sim_cycle ="
FAULT_INJECTION_OCCURRED="Fault injection"
EXACT_CORE_BIN="${EXACT_CORE_BIN:-script/SARA/native/exact_core}"
EXACT_CORE_BUILD_TARGET="${EXACT_CORE_BUILD_TARGET:-exact_core}"
EXACT_STORAGE_BACKEND_SO="${EXACT_STORAGE_BACKEND_SO:-script/SARA/native/libexact_storage_backend.so}"
EXACT_STORAGE_BACKEND_BUILD_TARGET="${EXACT_STORAGE_BACKEND_BUILD_TARGET:-exact_storage_backend}"

CURRENT_RESULT_FILE=""
CURRENT_TEST_ID=""
CURRENT_SIZE_LINE=""
CURRENT_CU_FILE=""
CURRENT_RUN_DIR=""
CURRENT_GOLDEN_CYCLES=""
CURRENT_MEAN_ACTIVE_THREADS=""
CURRENT_DATATYPE_BITS=""
CURRENT_SMEM_SIZE_BITS=""
CURRENT_L1D_SIZE_BITS=""
CURRENT_L1D_TAG_BITS=""
CURRENT_L1D_LINE_SIZE_BYTES=""
CURRENT_L1D_SHADERS=""
CURRENT_L1D_WRITE_ALLOCATE=""
CURRENT_L2_SIZE_BITS=""
CURRENT_L2_TAG_BITS=""
CURRENT_L2_LINE_SIZE_BYTES=""
CURRENT_L2_GLOBAL_PREFILL=""
CURRENT_THREAD_RAND_MAX=""
CURRENT_BLOCK_RAND_MAX=""
CURRENT_APP_USES_SHARED_MEMORY=""
LAST_SUMMARY_JSON=""
CURRENT_TRACE_FILE=""
CURRENT_ACTIVE_THREADS_LOG=""
CURRENT_ANALYZER_INPUT_FILE=""
CURRENT_ANALYZER_OUTPUT_FILE=""
CURRENT_EXACT_RATES_FILE=""
CURRENT_FI_SAMPLING_SPACE_JSON=""
CURRENT_CYCLES_DOMAIN_FILE=""
CURRENT_REGISTER_DOMAIN_FILE=""
RUN_ANALYZER_WRITE_SINGLE_CSV=1
RUN_ANALYZER_FORCE_KEEP_READ_EVENTS=0
RUN_ANALYZER_FORCE_RF_ADDR_MASKING=0
PROFILE_METRICS_READY=0
PROFILE_METRICS_SOURCE=""
PROFILE_THREAD_RAND_MAX=""
PROFILE_WARP_RAND_MAX=""
PROFILE_BLOCK_RAND_MAX=""
PROFILE_DATATYPE_BITS=""
PROFILE_SMEM_SIZE_BITS=""
FAIR_TIMING_START_NS=""

ANALYZER_LITE_OUTPUT="${ANALYZER_LITE_OUTPUT:-1}"
ANALYZER_MASK_FORMAT="${ANALYZER_MASK_FORMAT:-int}"
ANALYZER_ASSUME_SORTED_EVENTS="${ANALYZER_ASSUME_SORTED_EVENTS:-1}"
ANALYZER_EMIT_CACHE_SITES="${ANALYZER_EMIT_CACHE_SITES:-1}"
ANALYZER_LITE_OUTPUT_PROFILE="${ANALYZER_LITE_OUTPUT_PROFILE:-compute}"
ANALYZER_AGGREGATE_READ_EVENTS="${ANALYZER_AGGREGATE_READ_EVENTS:-0}"
ANALYZER_TRIM_COMPONENT_OUTPUT="${ANALYZER_TRIM_COMPONENT_OUTPUT:-1}"
ANALYZER_OMIT_TOPLEVEL_DIAGNOSTICS="${ANALYZER_OMIT_TOPLEVEL_DIAGNOSTICS:-1}"
ANALYZER_COMPACT_SITE_OUTPUT="${ANALYZER_COMPACT_SITE_OUTPUT:-1}"
ANALYZER_OMIT_META_DIAGNOSTIC_SAMPLES="${ANALYZER_OMIT_META_DIAGNOSTIC_SAMPLES:-1}"
ANALYZER_OMIT_UNUSED_READ_EVENTS="${ANALYZER_OMIT_UNUSED_READ_EVENTS:-1}"
ANALYZER_SHARE_CACHE_SITE_RECORDS="${ANALYZER_SHARE_CACHE_SITE_RECORDS:-1}"
ANALYZER_PREPARE_COMPACT_EVENTS="${ANALYZER_PREPARE_COMPACT_EVENTS:-1}"
ANALYZER_INPUT_MANIFEST="${ANALYZER_INPUT_MANIFEST:-0}"
ANALYZER_INPUT_BINARY="${ANALYZER_INPUT_BINARY:-1}"
ANALYZER_INPUT_COLUMNAR="${ANALYZER_INPUT_COLUMNAR:-1}"
ANALYZER_INPUT_COMPAT_PICKLE_DICT="${ANALYZER_INPUT_COMPAT_PICKLE_DICT:-0}"
ANALYZER_OUTPUT_BINARY="${ANALYZER_OUTPUT_BINARY:-1}"
ANALYZER_JSON_CODEC="${ANALYZER_JSON_CODEC:-none}" # none|gz|zst
ANALYZER_PROFILE_OUT="${ANALYZER_PROFILE_OUT:-}"
ANALYZER_CACHE_ENABLE="${ANALYZER_CACHE_ENABLE:-1}"
ANALYZER_CACHE_FORCE_REBUILD="${ANALYZER_CACHE_FORCE_REBUILD:-0}"
ANALYZER_CACHE_META_BASENAME="${ANALYZER_CACHE_META_BASENAME:-cache_meta.json}"
ANALYZER_CACHE_SHA256_SMALL_MAX_BYTES="${ANALYZER_CACHE_SHA256_SMALL_MAX_BYTES:-16777216}"
ANALYZER_CACHE_SHA256_LARGE_FILES="${ANALYZER_CACHE_SHA256_LARGE_FILES:-0}"
ANALYZER_CACHE_LARGE_SAMPLE_BYTES="${ANALYZER_CACHE_LARGE_SAMPLE_BYTES:-1048576}"
# Large analyzer/compute sources can exceed the full-hash threshold and fall back
# to sampled hashing. Include mtime in cache signatures by default so mid-file
# derivation edits still invalidate cached exact/analyzer artifacts.
ANALYZER_CACHE_INCLUDE_MTIME_NS="${ANALYZER_CACHE_INCLUDE_MTIME_NS:-1}"
EXACT_GLOBAL_CACHE="${EXACT_GLOBAL_CACHE:-1}"
ANALYZER_GLOBAL_CACHE="${ANALYZER_GLOBAL_CACHE:-${EXACT_GLOBAL_CACHE}}"
ANALYZER_GLOBAL_CACHE_DIR="${ANALYZER_GLOBAL_CACHE_DIR:-${EXACT_WORK_ROOT}/.cache_exact_sdc}"
ANALYZER_GLOBAL_CACHE_LINK_MODE="${ANALYZER_GLOBAL_CACHE_LINK_MODE:-copy}"
ALL_COMPONENTS="${ALL_COMPONENTS:-rf:smem_rf:l1d:l2}" # components for mode=all_components
ALL_COMPONENTS_TABLE_BASENAME="${ALL_COMPONENTS_TABLE_BASENAME:-all_components_rates.tsv}"
ALL_COMPONENTS_COMPACT_OUTPUT="${ALL_COMPONENTS_COMPACT_OUTPUT:-1}" # 1 => print concise all-components report
ALL_COMPONENTS_ALLOW_PARTIAL="${ALL_COMPONENTS_ALLOW_PARTIAL:-0}" # 1 => return success even if some components are unavailable
RESULT_DIR="${RESULT_DIR:-}"
EXACT_RESULT_VARIANT="${EXACT_RESULT_VARIANT:-}"
if [[ -z "${EXACT_RESULT_VARIANT}" && "${FAULT_COMPONENT}" == "gmem" ]]; then
    EXACT_RESULT_VARIANT="gmem"
fi
TIMING_ENABLED=0
TIMINGS_FILE_BASENAME="${TIMINGS_FILE_BASENAME:-timings.tsv}"
TIMINGS_SUMMARY_FILE_BASENAME="${TIMINGS_SUMMARY_FILE_BASENAME:-timing_summary.txt}"
TIME_BIN_PATH="${TIME_BIN_PATH:-}"
TIME_BIN_WARNED=0
TIMING_LOG_START_LINE=-1
TIMING_CONTEXT_LABEL=""
QUIET_CONSOLE_OUTPUT=0
QUIET_LOG_FILE=""

# Keep analyzer backward propagation on the reference Python semantics by
# default.  The native tolerance-path evaluator is semantics-preserving and
# only accelerates replay of the already-built symbolic tolerance paths.
export REG_OBSERVED_USE_CPP_BACKWARD_INFLUENCE="${REG_OBSERVED_USE_CPP_BACKWARD_INFLUENCE:-0}"
export REG_OBSERVED_USE_CPP_TOLERANCE_PATH_EVAL="${REG_OBSERVED_USE_CPP_TOLERANCE_PATH_EVAL:-1}"
export REG_OBSERVED_USE_CPP_CONTROL_TAINT_HASH="${REG_OBSERVED_USE_CPP_CONTROL_TAINT_HASH:-0}"
export EXACT_SDC_USE_CPP_MASK_CLASSIFIER="${EXACT_SDC_USE_CPP_MASK_CLASSIFIER:-1}"
export EXACT_SDC_USE_CPP_THREAD_CYCLE="${EXACT_SDC_USE_CPP_THREAD_CYCLE:-1}"

declare -a CURRENT_SIZE_ARGS=()

CONFIG_BACKUP="$(mktemp)"
cp "${CONFIG_FILE}" "${CONFIG_BACKUP}"

restore_config() {
    if [[ -f "${CONFIG_BACKUP}" ]]; then
        cp "${CONFIG_BACKUP}" "${CONFIG_FILE}"
        rm -f "${CONFIG_BACKUP}"
    fi
}
trap restore_config EXIT

sanitize_tsv_field() {
    local value="${1:-}"
    value="${value//$'\t'/ }"
    value="${value//$'\n'/ }"
    value="${value//$'\r'/ }"
    echo "${value}"
}

run_with_optional_quiet() {
    if (( $# < 2 )); then
        echo "=== Error: run_with_optional_quiet requires <log_file> <command...> ===" >&2
        exit 1
    fi
    local log_file="$1"
    local rc=0
    local had_errexit=0
    shift
    case "$-" in
        *e*) had_errexit=1 ;;
    esac
    set +e
    if [[ "${QUIET_CONSOLE_OUTPUT}" == "1" ]]; then
        if [[ -z "${log_file}" ]]; then
            echo "=== Error: quiet output requested but log file path is empty ===" >&2
            exit 1
        fi
        mkdir -p "$(dirname "${log_file}")" >/dev/null 2>&1 || true
        "$@" >> "${log_file}" 2>&1
        rc=$?
    else
        "$@"
        rc=$?
    fi
    if [[ "${had_errexit}" -eq 1 ]]; then
        set -e
    else
        set +e
    fi
    return "${rc}"
}

ensure_quiet_log_file() {
    local candidate=""
    candidate="$(mktemp "/tmp/all_components_verbose_${TEST_APP_NAME}_XXXXXX.log")"
    echo "${candidate}"
}

report_quiet_failure() {
    local log_file="${1:-}"
    local context="${2:-command}"
    local preserved_log=""

    if [[ -n "${log_file}" ]]; then
        echo "=== Error: ${context} failed. See ${log_file} ===" >&2
    else
        echo "=== Error: ${context} failed ===" >&2
    fi

    if [[ -n "${log_file}" && -f "${log_file}" ]]; then
        if [[ -n "${CURRENT_RUN_DIR:-}" && -d "${CURRENT_RUN_DIR}" && -w "${CURRENT_RUN_DIR}" ]]; then
            preserved_log="${CURRENT_RUN_DIR}/$(basename "${log_file}")"
            if cp -f "${log_file}" "${preserved_log}" 2>/dev/null; then
                echo "=== Preserved verbose log: ${preserved_log} ===" >&2
            fi
        fi
        echo "=== Last 80 lines from ${log_file} ===" >&2
        tail -n 80 "${log_file}" >&2 || true
        echo "=== End verbose log excerpt ===" >&2
    fi
}

get_test_result_app_dir() {
    local app_name="${1:-${TEST_APP_NAME}}"
    echo "${TEST_RESULT_ROOT}/${app_name}"
}

ensure_test_result_app_dir() {
    local dir=""
    dir="$(get_test_result_app_dir "${1:-${TEST_APP_NAME}}")"
    mkdir -p "${dir}"
    echo "${dir}"
}

resolve_test_result_csv_path() {
    local filename="${1:?filename is required}"
    local app_name="${2:-${TEST_APP_NAME}}"
    local dir=""
    dir="$(ensure_test_result_app_dir "${app_name}")"
    echo "${dir}/${filename}"
}

normalize_exact_result_variant() {
    local raw="${1:-${EXACT_RESULT_VARIANT:-}}"
    raw="$(printf '%s' "${raw}" | sed -E 's/[^A-Za-z0-9_]+/_/g; s/^_+//; s/_+$//')"
    printf '%s' "${raw}"
}

build_exact_result_csv_filename() {
    local prefix="${1:?prefix is required}"
    local app_name="${2:-${TEST_APP_NAME}}"
    local test_id="${3:-${CURRENT_TEST_ID}}"
    local variant=""
    variant="$(normalize_exact_result_variant)"
    if [[ -n "${variant}" ]]; then
        printf '%s_%s_%s_%s.csv' "${prefix}" "${variant}" "${app_name}" "${test_id}"
    else
        printf '%s_%s_%s.csv' "${prefix}" "${app_name}" "${test_id}"
    fi
}

resolve_current_register_domain_file() {
    if [[ -n "${CURRENT_RUN_DIR:-}" ]]; then
        echo "${CURRENT_RUN_DIR}/register_used.txt"
        return 0
    fi
    echo "register_used.txt"
}

persist_current_register_domain_file() {
    local src="${1:?register domain source is required}"
    local dst=""
    if [[ ! -f "${src}" || ! -s "${src}" ]]; then
        echo "=== Error: register domain source missing or empty: ${src} ===" >&2
        return 1
    fi
    dst="${CURRENT_REGISTER_DOMAIN_FILE:-$(resolve_current_register_domain_file)}"
    CURRENT_REGISTER_DOMAIN_FILE="${dst}"
    cp "${src}" "${dst}"
}

ensure_current_register_domain_file() {
    CURRENT_REGISTER_DOMAIN_FILE="${CURRENT_REGISTER_DOMAIN_FILE:-$(resolve_current_register_domain_file)}"
    if [[ -f "${CURRENT_REGISTER_DOMAIN_FILE}" && -s "${CURRENT_REGISTER_DOMAIN_FILE}" ]]; then
        return 0
    fi
    echo "=== Error: exact register domain file is unavailable: ${CURRENT_REGISTER_DOMAIN_FILE} ===" >&2
    return 1
}

regenerate_current_register_domain_from_ptx() {
    local canonical_ptx="./${TEST_APP_NAME}.ptx"
    if [[ ! -f "${canonical_ptx}" || ! -s "${canonical_ptx}" ]]; then
        return 1
    fi
    python3 extract_registers.py "${TEST_APP_NAME}"
    persist_current_register_domain_file "register_used.txt"
}

print_progress_hint() {
    local step="${1:-0}"
    local total="${2:-0}"
    local message="${3:-}"
    local width=24
    local pct=0
    local fill=0
    local empty=0
    local bar_fill=""
    local bar_empty=""
    if ! [[ "${step}" =~ ^[0-9]+$ ]]; then
        step=0
    fi
    if ! [[ "${total}" =~ ^[0-9]+$ ]]; then
        total=0
    fi
    if (( total <= 0 )); then
        echo "[Progress] ${message}"
        return 0
    fi
    if (( step > total )); then
        step="${total}"
    fi
    pct=$(( step * 100 / total ))
    fill=$(( step * width / total ))
    if (( fill < 0 )); then
        fill=0
    fi
    if (( fill > width )); then
        fill="${width}"
    fi
    empty=$(( width - fill ))
    bar_fill="$(printf '%*s' "${fill}" '' | tr ' ' '#')"
    bar_empty="$(printf '%*s' "${empty}" '' | tr ' ' '-')"
    printf '[Progress] [%d/%d] [%s%s] %d%% - %s\n' "${step}" "${total}" "${bar_fill}" "${bar_empty}" "${pct}" "${message}"
}

ns_to_seconds() {
    local ns="${1:-0}"
    awk -v ns="${ns}" 'BEGIN { printf "%.6f", ns / 1000000000 }'
}

current_time_ns() {
    date +%s%N
}

start_fair_timing_now() {
    if [[ "${FAIR_TIMING}" == "1" ]]; then
        FAIR_TIMING_START_NS="$(current_time_ns)"
    else
        FAIR_TIMING_START_NS=""
    fi
}

reported_total_time_seconds() {
    if [[ "${FAIR_TIMING}" == "1" && -n "${FAIR_TIMING_START_NS}" ]]; then
        local end_ns elapsed_ns
        end_ns="$(current_time_ns)"
        elapsed_ns=$(( end_ns - FAIR_TIMING_START_NS ))
        ns_to_seconds "${elapsed_ns}"
        return 0
    fi
    sum_step_timing_seconds_since_start
}

rewrite_simple_summary_total_time() {
    local summary_txt="${1:-}"
    local summary_csv="${2:-}"
    local total_s
    if [[ -z "${summary_txt}" || ! -f "${summary_txt}" ]]; then
        return 0
    fi
    total_s="$(reported_total_time_seconds)"
    python3 "${UPDATE_SIMPLE_SUMMARY_TOTAL_TIME_TOOL}" \
        --summary "${summary_txt}" \
        --total-seconds "${total_s}"
    if [[ -n "${summary_csv}" ]]; then
        "${EXACT_CORE_BIN}" rates-simple-summary-csv \
            --input "${summary_txt}" \
            --output "${summary_csv}" >/dev/null
    fi
}

collect_step_timing_lines_since_start() {
    local log_path start_line
    log_path="$(resolve_timing_log_path)"
    start_line="${TIMING_LOG_START_LINE:-0}"
    if [[ ! -f "${log_path}" ]]; then
        return 0
    fi
    python3 - "${log_path}" "${start_line}" <<'PY'
import sys
from collections import OrderedDict

log_path = sys.argv[1]
try:
    start_line = int(sys.argv[2])
except Exception:
    start_line = 0

stats = OrderedDict()
with open(log_path, "r", encoding="utf-8", errors="replace") as f:
    for lineno, raw in enumerate(f, start=1):
        if lineno <= start_line:
            continue
        line = raw.rstrip("\n")
        if not line or line.startswith("timestamp_iso\t"):
            continue
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        label = parts[1]
        try:
            wall_s = float(parts[2])
        except Exception:
            continue
        total, count = stats.get(label, (0.0, 0))
        stats[label] = (total + wall_s, count + 1)

for label, (total, count) in stats.items():
    if count > 1:
        print(f"{label} (x{count})\t{total:.6f}")
    else:
        print(f"{label}\t{total:.6f}")
PY
}

sum_step_timing_seconds_since_start() {
    local log_path start_line
    log_path="$(resolve_timing_log_path)"
    start_line="${TIMING_LOG_START_LINE:-0}"
    if [[ ! -f "${log_path}" ]]; then
        echo "0.000000"
        return 0
    fi
    python3 - "${log_path}" "${start_line}" <<'PY'
import sys
from collections import OrderedDict

log_path = sys.argv[1]
try:
    start_line = int(sys.argv[2])
except Exception:
    start_line = 0

stats = OrderedDict()
with open(log_path, "r", encoding="utf-8", errors="replace") as f:
    for lineno, raw in enumerate(f, start=1):
        if lineno <= start_line:
            continue
        line = raw.rstrip("\n")
        if not line or line.startswith("timestamp_iso\t"):
            continue
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        label = parts[1]
        try:
            wall_s = float(parts[2])
        except Exception:
            continue
        total, count = stats.get(label, (0.0, 0))
        stats[label] = (total + wall_s, count + 1)

overall = sum(round(total, 6) for total, _count in stats.values())
print(f"{overall:.6f}")
PY
}

resolve_timing_log_path() {
    local dir candidate
    local -a dirs=()
    if [[ -n "${RESULT_DIR:-}" ]]; then
        dirs+=("${RESULT_DIR}")
    fi
    if [[ -n "${CURRENT_RUN_DIR:-}" ]]; then
        dirs+=("${CURRENT_RUN_DIR}")
    fi
    if [[ -n "${EXACT_WORK_ROOT:-}" ]]; then
        dirs+=("${EXACT_WORK_ROOT}/.timing")
    fi
    dirs+=(".")

    for dir in "${dirs[@]}"; do
        [[ -n "${dir}" ]] || continue
        mkdir -p "${dir}" 2>/dev/null || true
        candidate="${dir}/${TIMINGS_FILE_BASENAME}"
        if [[ ( -e "${candidate}" && -w "${candidate}" ) || ( ! -e "${candidate}" && -w "${dir}" ) ]]; then
            echo "${candidate}"
            return 0
        fi
    done

    dir="${TMPDIR:-/tmp}/sdc_compute_once_timing/${TEST_APP_NAME:-unknown}/${RESULT_BASENAME:-run}"
    mkdir -p "${dir}" 2>/dev/null || true
    echo "${dir}/${TIMINGS_FILE_BASENAME}"
}

resolve_timing_summary_path() {
    local dir candidate
    local -a dirs=()
    if [[ -n "${RESULT_DIR:-}" ]]; then
        dirs+=("${RESULT_DIR}")
    fi
    if [[ -n "${CURRENT_RUN_DIR:-}" ]]; then
        dirs+=("${CURRENT_RUN_DIR}")
    fi
    if [[ -n "${EXACT_WORK_ROOT:-}" ]]; then
        dirs+=("${EXACT_WORK_ROOT}/.timing")
    fi
    dirs+=(".")

    for dir in "${dirs[@]}"; do
        [[ -n "${dir}" ]] || continue
        mkdir -p "${dir}" 2>/dev/null || true
        candidate="${dir}/${TIMINGS_SUMMARY_FILE_BASENAME}"
        if [[ ( -e "${candidate}" && -w "${candidate}" ) || ( ! -e "${candidate}" && -w "${dir}" ) ]]; then
            echo "${candidate}"
            return 0
        fi
    done

    dir="${TMPDIR:-/tmp}/sdc_compute_once_timing/${TEST_APP_NAME:-unknown}/${RESULT_BASENAME:-run}"
    mkdir -p "${dir}" 2>/dev/null || true
    echo "${dir}/${TIMINGS_SUMMARY_FILE_BASENAME}"
}

timing_log_path_is_writable() {
    local path="${1:-}"
    local dir
    [[ -n "${path}" ]] || return 1
    dir="$(dirname "${path}")"
    [[ -d "${dir}" ]] || return 1
    if [[ -e "${path}" ]]; then
        [[ -w "${path}" ]]
    else
        [[ -w "${dir}" ]]
    fi
}

resolve_time_bin_path() {
    if [[ -n "${TIME_BIN_PATH}" && -x "${TIME_BIN_PATH}" ]]; then
        echo "${TIME_BIN_PATH}"
        return 0
    fi
    if [[ -x "/usr/bin/time" ]]; then
        TIME_BIN_PATH="/usr/bin/time"
        echo "${TIME_BIN_PATH}"
        return 0
    fi
    if [[ -x "/bin/time" ]]; then
        TIME_BIN_PATH="/bin/time"
        echo "${TIME_BIN_PATH}"
        return 0
    fi

    local time_bin=""
    time_bin="$(type -P time 2>/dev/null || true)"
    if [[ -n "${time_bin}" && -x "${time_bin}" ]]; then
        TIME_BIN_PATH="${time_bin}"
        echo "${TIME_BIN_PATH}"
        return 0
    fi
    return 1
}

start_timing_session() {
    local context_label="${1:-${MODE}}"
    TIMING_ENABLED=1
    TIMING_LOG_START_LINE=-1
    TIMING_CONTEXT_LABEL="${context_label}"
}

ensure_timing_session_start_line() {
    if [[ "${TIMING_ENABLED}" != "1" ]]; then
        return
    fi
    if [[ "${TIMING_LOG_START_LINE}" != "-1" ]]; then
        return
    fi

    local timing_log_path
    timing_log_path="$(resolve_timing_log_path)"
    if [[ -f "${timing_log_path}" ]]; then
        TIMING_LOG_START_LINE="$(wc -l < "${timing_log_path}")"
    else
        TIMING_LOG_START_LINE=0
    fi
}

run_timed() {
    if (( $# < 2 )); then
        echo "=== Error: run_timed requires <step_label> <command...> ===" >&2
        exit 1
    fi

    local step_label="$1"
    shift

    if [[ "${TIMING_ENABLED}" != "1" ]]; then
        "$@"
        return $?
    fi

    local start_ns end_ns wall_ns wall_s
    local timestamp_iso
    local time_tmp user_s sys_s maxrss_kb
    local exit_code
    local command_str log_path
    local had_errexit=0
    local time_bin=""

    ensure_timing_session_start_line

    start_ns="$(date +%s%N)"
    timestamp_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    command_str="$(printf '%q ' "$@")"
    command_str="${command_str% }"
    time_tmp="$(mktemp)"
    if resolve_time_bin_path >/dev/null; then
        time_bin="${TIME_BIN_PATH}"
    fi

    case "$-" in
        *e*) had_errexit=1 ;;
    esac
    set +e
    if [[ -n "${time_bin}" ]]; then
        "${time_bin}" -f "%U\t%S\t%M" -o "${time_tmp}" "$@"
        exit_code=$?
    else
        "$@"
        exit_code=$?
        if [[ "${TIME_BIN_WARNED}" -eq 0 ]]; then
            echo "=== Warning: external 'time' command not found; user/sys/maxrss fields will be 0 ===" >&2
            TIME_BIN_WARNED=1
        fi
    fi
    if [[ "${had_errexit}" -eq 1 ]]; then
        set -e
    else
        set +e
    fi

    end_ns="$(date +%s%N)"
    wall_ns=$((end_ns - start_ns))
    wall_s="$(awk -v ns="${wall_ns}" 'BEGIN { printf "%.9f", ns / 1000000000 }')"

    user_s="0"
    sys_s="0"
    maxrss_kb="0"
    if [[ -s "${time_tmp}" ]]; then
        IFS=$'\t' read -r user_s sys_s maxrss_kb < "${time_tmp}" || true
    fi
    rm -f "${time_tmp}"

    log_path="$(resolve_timing_log_path)"
    if timing_log_path_is_writable "${log_path}"; then
        if [[ ! -f "${log_path}" ]]; then
            printf 'timestamp_iso\tstep_label\twall_s\tuser_s\tsys_s\tmaxrss_kb\texit_code\tcommand\n' >> "${log_path}" 2>/dev/null || true
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "${timestamp_iso}" \
            "$(sanitize_tsv_field "${step_label}")" \
            "${wall_s}" \
            "${user_s}" \
            "${sys_s}" \
            "${maxrss_kb}" \
            "${exit_code}" \
            "$(sanitize_tsv_field "${command_str}")" \
            >> "${log_path}" 2>/dev/null || true
    fi

    printf '[timing] step=%s wall=%ss user=%ss sys=%ss maxrss=%sKB exit=%s\n' \
        "${step_label}" \
        "${wall_s}" \
        "${user_s}" \
        "${sys_s}" \
        "${maxrss_kb}" \
        "${exit_code}" \
        >&2

    return "${exit_code}"
}

run_timed_shell() {
    if (( $# < 2 )); then
        echo "=== Error: run_timed_shell requires <step_label> <command...> ===" >&2
        exit 1
    fi

    local step_label="$1"
    shift

    if [[ "${TIMING_ENABLED}" != "1" ]]; then
        "$@"
        return $?
    fi

    local start_ns end_ns wall_ns wall_s
    local timestamp_iso
    local exit_code
    local command_str log_path
    local had_errexit=0

    ensure_timing_session_start_line

    start_ns="$(date +%s%N)"
    timestamp_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    command_str="$(printf '%q ' "$@")"
    command_str="${command_str% }"

    case "$-" in
        *e*) had_errexit=1 ;;
    esac
    set +e
    "$@"
    exit_code=$?
    if [[ "${had_errexit}" -eq 1 ]]; then
        set -e
    else
        set +e
    fi

    end_ns="$(date +%s%N)"
    wall_ns=$((end_ns - start_ns))
    wall_s="$(awk -v ns="${wall_ns}" 'BEGIN { printf "%.9f", ns / 1000000000 }')"

    log_path="$(resolve_timing_log_path)"
    if timing_log_path_is_writable "${log_path}"; then
        if [[ ! -f "${log_path}" ]]; then
            printf 'timestamp_iso\tstep_label\twall_s\tuser_s\tsys_s\tmaxrss_kb\texit_code\tcommand\n' >> "${log_path}" 2>/dev/null || true
        fi
        printf '%s\t%s\t%s\t0\t0\t0\t%s\t%s\n' \
            "${timestamp_iso}" \
            "$(sanitize_tsv_field "${step_label}")" \
            "${wall_s}" \
            "${exit_code}" \
            "$(sanitize_tsv_field "${command_str}")" \
            >> "${log_path}" 2>/dev/null || true
    fi

    printf '[timing] step=%s wall=%ss user=%ss sys=%ss maxrss=%sKB exit=%s\n' \
        "${step_label}" \
        "${wall_s}" \
        "0" \
        "0" \
        "0" \
        "${exit_code}" \
        >&2

    return "${exit_code}"
}

cache_meta_path_for_dir() {
    local run_dir="$1"
    echo "${run_dir}/${ANALYZER_CACHE_META_BASENAME}"
}

cache_compute_signature() {
    if (( $# < 4 )); then
        echo "=== Error: cache_compute_signature requires step params_json payload_out files... ===" >&2
        exit 1
    fi
    local step="$1"
    local params_json="$2"
    local payload_out="$3"
    shift 3
    python3 - "${step}" "${params_json}" "${payload_out}" "${ANALYZER_CACHE_SHA256_SMALL_MAX_BYTES}" "${ANALYZER_CACHE_SHA256_LARGE_FILES}" "${ANALYZER_CACHE_LARGE_SAMPLE_BYTES}" "${ANALYZER_CACHE_INCLUDE_MTIME_NS}" "$@" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

step = sys.argv[1]
params_raw = sys.argv[2]
payload_out = Path(sys.argv[3])
small_max = int(sys.argv[4])
hash_large = str(sys.argv[5]).strip() == "1"
sample_bytes = max(1, int(sys.argv[6]))
include_mtime = str(sys.argv[7]).strip() == "1"
paths = [Path(p) for p in sys.argv[8:]]

try:
    params = json.loads(params_raw)
except Exception:
    params = {"_raw": str(params_raw)}


def file_meta(path: Path):
    rec = {"name": path.name}
    if not path.exists():
        rec["exists"] = False
        return rec
    rec["exists"] = True
    rec["is_file"] = path.is_file()
    st = path.stat()
    rec["size"] = int(st.st_size)
    if include_mtime:
        rec["mtime_ns"] = int(st.st_mtime_ns)
    if not path.is_file():
        return rec
    should_hash = hash_large or int(st.st_size) <= int(small_max)
    if should_hash:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        rec["sha256"] = h.hexdigest()
        rec["hash_mode"] = "full"
        return rec

    h = hashlib.sha256()
    size = int(st.st_size)
    with path.open("rb") as f:
        head = f.read(sample_bytes)
        if size > sample_bytes:
            if size > (sample_bytes * 2):
                f.seek(max(0, size - sample_bytes))
                tail = f.read(sample_bytes)
            else:
                tail = f.read()
        else:
            tail = b""
    h.update(str(size).encode("ascii", errors="ignore"))
    h.update(b"|")
    h.update(head)
    h.update(b"|")
    h.update(tail)
    rec["sha256_sampled"] = h.hexdigest()
    rec["sample_bytes"] = int(sample_bytes)
    rec["hash_mode"] = "sampled"
    return rec


inputs = [file_meta(p) for p in paths]
payload = {
    "schema": 2,
    "step": step,
    "params": params,
    "inputs": inputs,
}
canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
signature = hashlib.sha256(canonical).hexdigest()
payload_out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(signature)
PY
}

cache_step_hit() {
    if (( $# < 3 )); then
        echo "0"
        return 0
    fi
    local cache_meta_file="$1"
    local step="$2"
    local signature="$3"
    shift 3
    python3 - "${cache_meta_file}" "${step}" "${signature}" "$@" <<'PY'
import json
import sys
from pathlib import Path

meta_path = Path(sys.argv[1])
step = sys.argv[2]
sig = sys.argv[3]
outputs = [Path(p) for p in sys.argv[4:]]

for out in outputs:
    if not out.exists():
        print("0")
        raise SystemExit(0)

if not meta_path.is_file():
    print("0")
    raise SystemExit(0)

try:
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
except Exception:
    print("0")
    raise SystemExit(0)

entry = None
if isinstance(meta, dict):
    steps = meta.get("steps", {})
    if isinstance(steps, dict):
        entry = steps.get(step)

if not isinstance(entry, dict):
    print("0")
    raise SystemExit(0)

print("1" if str(entry.get("signature", "")) == str(sig) else "0")
PY
}

cache_step_update() {
    if (( $# < 4 )); then
        echo "=== Error: cache_step_update requires meta step signature payload outputs... ===" >&2
        exit 1
    fi
    local cache_meta_file="$1"
    local step="$2"
    local signature="$3"
    local payload_file="$4"
    shift 4
    if ! python3 - "${cache_meta_file}" "${step}" "${signature}" "${payload_file}" "$@" <<'PY'
import json
import time
from pathlib import Path
import sys

meta_path = Path(sys.argv[1])
step = sys.argv[2]
signature = sys.argv[3]
payload_path = Path(sys.argv[4])
outputs = [str(Path(p)) for p in sys.argv[5:]]

meta = {"version": 1, "steps": {}}
if meta_path.is_file():
    try:
        raw = json.loads(meta_path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            meta = raw
    except Exception:
        pass
if "steps" not in meta or not isinstance(meta.get("steps"), dict):
    meta["steps"] = {}

payload = {}
if payload_path.is_file():
    try:
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
    except Exception:
        payload = {}

entry = {
    "signature": str(signature),
    "updated_at_epoch": int(time.time()),
    "updated_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "params": payload.get("params", {}),
    "inputs": payload.get("inputs", []),
    "outputs": outputs,
}
meta["steps"][step] = entry
meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
    then
        return 0
    fi
}

is_global_cache_enabled() {
    if [[ "${ANALYZER_GLOBAL_CACHE}" == "1" || "${EXACT_GLOBAL_CACHE}" == "1" ]]; then
        echo "1"
    else
        echo "0"
    fi
}

global_cache_step_dir() {
    local step="$1"
    local signature="$2"
    echo "${ANALYZER_GLOBAL_CACHE_DIR%/}/${step}/${signature}"
}

global_cache_try_restore() {
    if (( $# < 3 )); then
        echo "0"
        return 0
    fi
    local step="$1"
    local signature="$2"
    shift 2
    local cache_dir
    cache_dir="$(global_cache_step_dir "${step}" "${signature}")"
    if [[ ! -d "${cache_dir}" ]]; then
        echo "0"
        return 0
    fi

    local out src
    for out in "$@"; do
        src="${cache_dir}/$(basename "${out}")"
        if [[ ! -f "${src}" ]]; then
            echo "0"
            return 0
        fi
    done

    for out in "$@"; do
        src="${cache_dir}/$(basename "${out}")"
        if ! mkdir -p "$(dirname "${out}")" 2>/dev/null; then
            echo "0"
            return 0
        fi
        if [[ "${ANALYZER_GLOBAL_CACHE_LINK_MODE}" == "symlink" ]]; then
            if ! ln -sfn "${src}" "${out}" 2>/dev/null; then
                echo "0"
                return 0
            fi
        else
            local tmp_out
            tmp_out="${out}.tmp.$$"
            if ! cp -f "${src}" "${tmp_out}" 2>/dev/null; then
                rm -f "${tmp_out}" 2>/dev/null || true
                echo "0"
                return 0
            fi
            if ! mv -f "${tmp_out}" "${out}" 2>/dev/null; then
                rm -f "${tmp_out}" 2>/dev/null || true
                echo "0"
                return 0
            fi
        fi
    done
    echo "1"
    return 0
}

link_or_copy_file() {
    if (( $# != 2 )); then
        return 1
    fi
    local src="$1"
    local dst="$2"
    mkdir -p "$(dirname "${dst}")"
    rm -f "${dst}"
    if cp -f --reflink=always --preserve=all "${src}" "${dst}" 2>/dev/null; then
        return 0
    fi
    if cp -f --reflink=auto --preserve=all "${src}" "${dst}" 2>/dev/null; then
        return 0
    fi
    cp -f "${src}" "${dst}"
}

link_or_symlink_file() {
    if (( $# != 2 )); then
        return 1
    fi
    local src="$1"
    local dst="$2"
    mkdir -p "$(dirname "${dst}")"
    rm -f "${dst}"
    if [[ "$(dirname "${src}")" == "$(dirname "${dst}")" ]]; then
        if ln -sfn "$(basename "${src}")" "${dst}" 2>/dev/null; then
            return 0
        fi
    fi
    link_or_copy_file "${src}" "${dst}"
}

copy_manifest_binary_ref_if_present() {
    if (( $# != 2 )); then
        return 1
    fi
    local manifest_src="$1"
    local target_dir="$2"
    local binary_ref binary_src binary_dst
    if [[ ! -f "${manifest_src}" ]]; then
        return 0
    fi
    binary_ref="$(python3 - "${manifest_src}" <<'PY' 2>/dev/null || true
import gzip
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    raw = path.read_bytes()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    elif raw[:4] == b"\x28\xb5\x2f\xfd":
        import zstandard as zstd  # type: ignore

        raw = zstd.ZstdDecompressor().decompress(raw)
    obj = json.loads(raw.decode("utf-8"))
except Exception:
    raise SystemExit(0)
if isinstance(obj, dict) and obj.get("manifest_kind") == "exact_sdc_analyzer_output_binary_v1":
    ref = obj.get("binary_ref")
    if isinstance(ref, str) and ref:
        print(ref)
PY
)"
    if [[ -z "${binary_ref}" ]]; then
        return 0
    fi
    binary_src="${binary_ref}"
    if [[ "${binary_src}" != /* ]]; then
        binary_src="$(dirname "${manifest_src}")/${binary_src}"
    fi
    if [[ ! -f "${binary_src}" ]]; then
        echo "=== Error: analyzer output binary sidecar missing for manifest ${manifest_src}: ${binary_src} ===" >&2
        return 1
    fi
    mkdir -p "${target_dir}"
    binary_dst="${target_dir}/$(basename "${binary_src}")"
    if [[ "${binary_src}" != "${binary_dst}" ]]; then
        link_or_copy_file "${binary_src}" "${binary_dst}"
    fi
}

copy_analyzer_manifest_with_sidecar() {
    if (( $# != 2 )); then
        return 1
    fi
    local manifest_src="$1"
    local manifest_dst="$2"
    if [[ ! -f "${manifest_src}" ]]; then
        echo "=== Error: analyzer manifest missing: ${manifest_src} ===" >&2
        return 1
    fi
    mkdir -p "$(dirname "${manifest_dst}")"
    python3 - "${manifest_src}" "${manifest_dst}" <<'PY'
import gzip
import json
import shutil
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])


def read_json(path: Path):
    raw = path.read_bytes()
    codec = "none"
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
        codec = "gzip"
    elif raw[:4] == b"\x28\xb5\x2f\xfd":
        try:
            import zstandard as zstd  # type: ignore
        except Exception as exc:  # pragma: no cover - optional runtime dependency
            raise RuntimeError(f"cannot read zstd analyzer manifest {path}: {exc}") from exc
        raw = zstd.ZstdDecompressor().decompress(raw)
        codec = "zstd"
    return json.loads(raw.decode("utf-8")), codec


try:
    obj, codec = read_json(src)
except Exception:
    shutil.copy2(src, dst)
    raise SystemExit(0)

if not (
    isinstance(obj, dict)
    and obj.get("manifest_kind") == "exact_sdc_analyzer_output_binary_v1"
    and isinstance(obj.get("binary_ref"), str)
    and obj.get("binary_ref")
):
    shutil.copy2(src, dst)
    raise SystemExit(0)

binary_ref = Path(str(obj["binary_ref"]))
binary_src = binary_ref if binary_ref.is_absolute() else src.parent / binary_ref
if not binary_src.is_file():
    raise FileNotFoundError(f"analyzer output binary sidecar missing for {src}: {binary_src}")

binary_dst = dst.with_name(dst.name + ".bin")
if binary_src.resolve() != binary_dst.resolve():
    shutil.copy2(binary_src, binary_dst)
obj["binary_ref"] = binary_dst.name

payload = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
if dst.name.endswith(".gz") or codec == "gzip" and dst.suffix == ".gz":
    dst.write_bytes(gzip.compress(payload))
elif dst.name.endswith(".zst") or dst.name.endswith(".zstd"):
    try:
        import zstandard as zstd  # type: ignore
    except Exception as exc:  # pragma: no cover - optional runtime dependency
        raise RuntimeError(f"cannot write zstd analyzer manifest {dst}: {exc}") from exc
    dst.write_bytes(zstd.ZstdCompressor().compress(payload))
else:
    dst.write_bytes(payload)
PY
}

prepare_reused_analyzer_outputs_from_run_dir() {
    if (( $# < 4 )); then
        echo "=== Error: prepare_reused_analyzer_outputs_from_run_dir requires <source_run_dir> <target_run_dir> <shared_component> <component...> ===" >&2
        return 1
    fi

    local source_run_dir="$1"
    local target_run_dir="$2"
    local shared_component="$3"
    shift 3

    local codec_ext shared_src shared_dst analyzer_output_dst analyzer_input_dst analyzer_meta_src analyzer_meta_dst comp comp_dst
    codec_ext="$(json_codec_suffix "${ANALYZER_JSON_CODEC:-none}")"
    shared_src="${source_run_dir}/analyzer_output_${shared_component}.json${codec_ext}"
    if [[ ! -f "${shared_src}" && -f "${source_run_dir}/analyzer_output_${shared_component}.json" ]]; then
        shared_src="${source_run_dir}/analyzer_output_${shared_component}.json"
    fi
    if [[ ! -f "${shared_src}" ]]; then
        echo "=== Error: shared analyzer artifact missing for reuse: ${shared_src} ===" >&2
        return 1
    fi

    mkdir -p "${target_run_dir}"
    shared_dst="${target_run_dir}/analyzer_output_${shared_component}.json${codec_ext}"
    if ! copy_analyzer_manifest_with_sidecar "${shared_src}" "${shared_dst}"; then
        return 1
    fi
    for comp in "$@"; do
        comp_dst="${target_run_dir}/analyzer_output_${comp}.json${codec_ext}"
        if [[ "${comp_dst}" != "${shared_dst}" ]]; then
            link_or_symlink_file "${shared_dst}" "${comp_dst}"
        fi
    done

    analyzer_output_dst="${target_run_dir}/analyzer_output.json${codec_ext}"
    if [[ "${analyzer_output_dst}" != "${shared_dst}" ]]; then
        if ! copy_analyzer_manifest_with_sidecar "${shared_dst}" "${analyzer_output_dst}"; then
            return 1
        fi
    fi
    if [[ "${analyzer_output_dst}" != "${target_run_dir}/analyzer_output.json" ]]; then
        ln -sfn "$(basename "${analyzer_output_dst}")" "${target_run_dir}/analyzer_output.json"
    fi

    analyzer_meta_src="${source_run_dir}/analyzer_meta.json"
    analyzer_meta_dst="${target_run_dir}/analyzer_meta.json"
    if [[ -f "${analyzer_meta_src}" ]]; then
        link_or_copy_file "${analyzer_meta_src}" "${analyzer_meta_dst}"
    fi

    analyzer_input_dst="${target_run_dir}/analyzer_input.json${codec_ext}"
    if [[ -f "${analyzer_input_dst}" ]]; then
        CURRENT_ANALYZER_INPUT_FILE="${analyzer_input_dst}"
    elif [[ -f "${target_run_dir}/analyzer_input.json" ]]; then
        CURRENT_ANALYZER_INPUT_FILE="${target_run_dir}/analyzer_input.json"
    fi
    CURRENT_ANALYZER_OUTPUT_FILE="${analyzer_output_dst}"
    CURRENT_EXACT_RATES_FILE="${target_run_dir}/exact_rates.json"
}

dir_has_entries() {
    if (( $# != 1 )); then
        return 1
    fi
    local dir="$1"
    [[ -d "${dir}" ]] || return 1
    find "${dir}" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null | grep -q .
}

replace_dir_contents() {
    if (( $# != 2 )); then
        return 1
    fi
    local src="$1"
    local dst="$2"
    mkdir -p "${dst}"
    find "${dst}" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true
    if dir_has_entries "${src}"; then
        cp -a "${src}/." "${dst}/"
    fi
}

global_cache_store() {
    if (( $# < 4 )); then
        return 0
    fi
    local step="$1"
    local signature="$2"
    local payload_file="$3"
    shift 3
    local step_root final_dir tmp_dir
    step_root="${ANALYZER_GLOBAL_CACHE_DIR%/}/${step}"
    final_dir="${step_root}/${signature}"
    if ! mkdir -p "${step_root}" 2>/dev/null; then
        return 0
    fi
    if [[ -d "${final_dir}" ]]; then
        return 0
    fi

    tmp_dir="$(mktemp -d "${step_root}/.tmp.${signature}.XXXXXX" 2>/dev/null)" || return 0
    if [[ -f "${payload_file}" ]]; then
        if ! cp -f "${payload_file}" "${tmp_dir}/signature_payload.json" 2>/dev/null; then
            rm -rf "${tmp_dir}" 2>/dev/null || true
            return 0
        fi
    fi

    local out base
    for out in "$@"; do
        if [[ ! -f "${out}" ]]; then
            rm -rf "${tmp_dir}"
            return 0
        fi
        base="$(basename "${out}")"
        if ! cp -f "${out}" "${tmp_dir}/${base}" 2>/dev/null; then
            rm -rf "${tmp_dir}" 2>/dev/null || true
            return 0
        fi
    done

    if mv "${tmp_dir}" "${final_dir}" 2>/dev/null; then
        return 0
    fi
    rm -rf "${tmp_dir}" 2>/dev/null || true
    return 0
}

json_codec_suffix() {
    local codec="${1:-none}"
    case "${codec}" in
        gz) echo ".gz" ;;
        zst) echo ".zst" ;;
        *) echo "" ;;
    esac
}

emit_timing_summary() {
    local context_label
    local log_path summary_path start_line
    context_label="${1:-${TIMING_CONTEXT_LABEL:-${MODE}}}"
    log_path="$(resolve_timing_log_path)"
    summary_path="$(resolve_timing_summary_path)"
    start_line="${TIMING_LOG_START_LINE:-0}"

    if [[ ! -f "${log_path}" ]]; then
        echo "=== timing summary: no timing log found ==="
        return
    fi

    if ! python3 - "${log_path}" "${start_line}" "${summary_path}" "${context_label}" <<'PY'
import os
import re
import shlex
import sys
from collections import defaultdict


def shorten(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3] + "..."


def parse_target(command: str) -> str:
    try:
        tokens = shlex.split(command)
    except Exception:
        tokens = command.split()
    if not tokens:
        return "unknown"
    exe = os.path.basename(tokens[0])
    if exe.startswith("python") and len(tokens) >= 2:
        if tokens[1] == "-":
            return "inline_python"
        return os.path.basename(tokens[1])
    return exe


def safe_stdout_write(text: str) -> None:
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:
        enc = sys.stdout.encoding or "ascii"
        sys.stdout.buffer.write(text.encode(enc, errors="replace"))


log_path = sys.argv[1]
start_line = int(sys.argv[2])
summary_path = sys.argv[3]
context_label = sys.argv[4] if len(sys.argv) > 4 else "session"

rows = []
with open(log_path, "r", encoding="utf-8", errors="replace") as f:
    for lineno, raw in enumerate(f, start=1):
        if lineno <= start_line:
            continue
        line = raw.rstrip("\n")
        if not line or line.startswith("timestamp_iso\t"):
            continue
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        ts, label, wall_s, user_s, sys_s, rss_kb, exit_code, command = parts[:8]
        try:
            wall = float(wall_s)
        except ValueError:
            continue
        try:
            exit_i = int(exit_code)
        except ValueError:
            exit_i = 1
        norm_label = re.sub(r"timed_run_[0-9]+_", "timed_run_*_", label)
        rows.append(
            {
                "label": label,
                "norm_label": norm_label,
                "wall": wall,
                "exit_code": exit_i,
                "command": command,
                "target": parse_target(command),
            }
        )

if not rows:
    content = "=== timing summary: no new timing records for this run ===\n"
    with open(summary_path, "w", encoding="utf-8") as out:
        out.write(content)
    safe_stdout_write(content)
    raise SystemExit(0)

step_stats = defaultdict(lambda: {"count": 0, "total": 0.0, "max": 0.0, "fail": 0})
target_stats = defaultdict(lambda: {"count": 0, "total": 0.0, "max": 0.0, "fail": 0})

for r in rows:
    s = step_stats[r["norm_label"]]
    s["count"] += 1
    s["total"] += r["wall"]
    s["max"] = max(s["max"], r["wall"])
    if r["exit_code"] != 0:
        s["fail"] += 1

    t = target_stats[r["target"]]
    t["count"] += 1
    t["total"] += r["wall"]
    t["max"] = max(t["max"], r["wall"])
    if r["exit_code"] != 0:
        t["fail"] += 1

step_rank = sorted(step_stats.items(), key=lambda kv: kv[1]["total"], reverse=True)
target_rank = sorted(target_stats.items(), key=lambda kv: kv[1]["total"], reverse=True)
slowest_rows = sorted(rows, key=lambda r: r["wall"], reverse=True)[:20]

lines = []
lines.append(f"=== Timing Summary (Readable, mode={context_label}) ===")
lines.append(f"records: {len(rows)}")
lines.append("")
lines.append("1) Step Summary (sorted by total time desc)")
lines.append(f"{'Rank':>4}  {'Step':<42} {'Count':>5} {'Total(s)':>10} {'Avg(s)':>10} {'Max(s)':>10} {'Fail':>6}")
for i, (name, st) in enumerate(step_rank, start=1):
    avg = st["total"] / st["count"] if st["count"] else 0.0
    lines.append(
        f"{i:>4}  {shorten(name, 42):<42} {st['count']:>5} {st['total']:>10.3f} {avg:>10.3f} {st['max']:>10.3f} {st['fail']:>6}"
    )

lines.append("")
lines.append("2) Target Summary (sorted by total time desc)")
lines.append(f"{'Rank':>4}  {'Target':<28} {'Count':>5} {'Total(s)':>10} {'Avg(s)':>10} {'Max(s)':>10} {'Fail':>6}")
for i, (name, st) in enumerate(target_rank, start=1):
    avg = st["total"] / st["count"] if st["count"] else 0.0
    lines.append(
        f"{i:>4}  {shorten(name, 28):<28} {st['count']:>5} {st['total']:>10.3f} {avg:>10.3f} {st['max']:>10.3f} {st['fail']:>6}"
    )

lines.append("")
lines.append("3) Slowest Single Steps Top 20")
lines.append(f"{'Rank':>4}  {'Wall(s)':>10} {'Step':<42} {'Target':<24} {'Exit':>4}")
for i, r in enumerate(slowest_rows, start=1):
    lines.append(
        f"{i:>4}  {r['wall']:>10.3f} {shorten(r['label'], 42):<42} {shorten(r['target'], 24):<24} {r['exit_code']:>4}"
    )

content = "\n".join(lines) + "\n"
with open(summary_path, "w", encoding="utf-8") as out:
    out.write(content)
safe_stdout_write(content)
PY
    then
        echo "=== Warning: failed to generate readable timing summary ===" >&2
        return
    fi

    echo "Wrote readable timing summary: ${summary_path}"
}

join_colon() {
    local IFS=":"
    echo "$*"
}

is_nonneg_int() {
    local v="${1:-}"
    [[ "${v}" =~ ^[0-9]+$ ]]
}

is_pos_int() {
    local v="${1:-}"
    [[ "${v}" =~ ^[0-9]+$ ]] && [[ "${v}" -gt 0 ]]
}

ilog2_pow2() {
    local v="${1:-}"
    local out=0
    if ! [[ "${v}" =~ ^[0-9]+$ ]] || (( v <= 0 )); then
        return 1
    fi
    if (( (v & (v - 1)) != 0 )); then
        return 1
    fi
    while (( v > 1 )); do
        v=$((v >> 1))
        out=$((out + 1))
    done
    echo "${out}"
}

derive_cache_tag_bits() {
    local nset="${1:-0}"
    local line_bytes="${2:-0}"
    local addr_bits="${3:-64}"
    if ! is_pos_int "${addr_bits}"; then
        echo ""
        return
    fi
    local lg_nset lg_line
    if ! lg_nset="$(ilog2_pow2 "${nset}")"; then
        echo ""
        return
    fi
    if ! lg_line="$(ilog2_pow2 "${line_bytes}")"; then
        echo ""
        return
    fi
    local tag_bits=$(( addr_bits - lg_nset - lg_line ))
    if (( tag_bits < 0 )); then
        echo ""
        return
    fi
    echo "${tag_bits}"
}

is_valid_l2_size_bits() {
    local v="${1:-}"
    # campaign_exec.sh keeps L2_SIZE_BITS=1 as a bootstrapping placeholder.
    # Treat <=1 as unresolved so we do not undercount the L2 denominator.
    [[ "${v}" =~ ^[0-9]+$ ]] && [[ "${v}" -gt 1 ]]
}

is_valid_l1d_size_bits() {
    local v="${1:-}"
    # campaign_exec.sh keeps L1D_SIZE_BITS=1 as a bootstrapping placeholder.
    # Treat <=1 as unresolved so we do not undercount the L1D denominator.
    [[ "${v}" =~ ^[0-9]+$ ]] && [[ "${v}" -gt 1 ]]
}

is_valid_smem_size_bits() {
    local v="${1:-}"
    # campaign_exec.sh keeps SMEM_SIZE_BITS=1 as a bootstrapping placeholder.
    # Real non-zero shared-memory allocations are byte-granular, so a genuine
    # bit-domain is always >= 8.
    [[ "${v}" =~ ^[0-9]+$ ]] && [[ "${v}" -gt 1 ]]
}

resolve_first_valid_source_value() {
    local validator="${1:-is_pos_int}"
    local source value
    shift || true
    while (( $# >= 2 )); do
        source="$1"
        value="$2"
        shift 2
        if "${validator}" "${value}"; then
            printf '%s\t%s\n' "${value}" "${source}"
            return 0
        fi
    done
    printf '\t\n'
    return 1
}

is_nonneg_number() {
    local v="${1:-}"
    [[ "${v}" =~ ^[0-9]+([.][0-9]+)?$ ]] || [[ "${v}" =~ ^[.][0-9]+$ ]]
}

is_bool_01() {
    local v="${1:-}"
    [[ "${v}" == "0" || "${v}" == "1" ]]
}

exact_core_needs_rebuild() {
    local bin="${EXACT_CORE_BIN}"
    local src
    if [[ ! -x "${bin}" ]]; then
        return 0
    fi
    if ! "${bin}" --version >/dev/null 2>&1; then
        return 0
    fi
    for src in \
        "src/analysis/exact_core_main.cc" \
        "src/analysis/ptx_influence.cc" \
        "src/analysis/ptx_influence.h" \
        "src/analysis/ptx_influence_capi.cc" \
        "src/analysis/ptx_influence_capi.h" \
        "src/CMakeLists.txt" \
        "Makefile" \
        "third_party/nlohmann/json.hpp"
    do
        if [[ -e "${src}" && "${src}" -nt "${bin}" ]]; then
            return 0
        fi
    done
    return 1
}

ensure_exact_core_binary() {
    local build_log=""
    if exact_core_needs_rebuild; then
        build_log="$(mktemp "${TMPDIR:-/tmp}/exact_core_build.XXXXXX.log")"
        echo "=== Rebuilding ${EXACT_CORE_BIN} in current runtime ==="
        if ! make "${EXACT_CORE_BUILD_TARGET}" >"${build_log}" 2>&1; then
            echo "=== Error: failed to build ${EXACT_CORE_BIN} in current runtime ===" >&2
            cat "${build_log}" >&2
            rm -f "${build_log}"
            return 1
        fi
        rm -f "${build_log}"
    fi
    if ! "${EXACT_CORE_BIN}" --version >/dev/null 2>&1; then
        echo "=== Error: ${EXACT_CORE_BIN} is unavailable in current runtime ===" >&2
        return 1
    fi
    return 0
}

exact_storage_backend_needs_rebuild() {
    local so="${EXACT_STORAGE_BACKEND_SO}"
    local src
    if [[ ! -f "${so}" ]]; then
        return 0
    fi
    if ! python3 - "${so}" <<'PY' >/dev/null 2>&1
import ctypes
import sys
ctypes.CDLL(sys.argv[1])
PY
    then
        return 0
    fi
    for src in \
        "src/analysis/ptx_influence.cc" \
        "src/analysis/ptx_influence.h" \
        "src/analysis/ptx_influence_capi.cc" \
        "src/analysis/ptx_influence_capi.h" \
        "src/CMakeLists.txt" \
        "Makefile"
    do
        if [[ -e "${src}" && "${src}" -nt "${so}" ]]; then
            return 0
        fi
    done
    return 1
}

ensure_exact_storage_backend_binary() {
    local build_log=""
    if exact_storage_backend_needs_rebuild; then
        build_log="$(mktemp "${TMPDIR:-/tmp}/exact_storage_backend_build.XXXXXX.log")"
        echo "=== Rebuilding ${EXACT_STORAGE_BACKEND_SO} in current runtime ==="
        if ! make "${EXACT_STORAGE_BACKEND_BUILD_TARGET}" >"${build_log}" 2>&1; then
            echo "=== Error: failed to build ${EXACT_STORAGE_BACKEND_SO} in current runtime ===" >&2
            cat "${build_log}" >&2
            rm -f "${build_log}"
            return 1
        fi
        rm -f "${build_log}"
    fi
    if ! python3 - "${EXACT_STORAGE_BACKEND_SO}" <<'PY' >/dev/null 2>&1
import ctypes
import sys
ctypes.CDLL(sys.argv[1])
PY
    then
        echo "=== Error: ${EXACT_STORAGE_BACKEND_SO} is unavailable in current runtime ===" >&2
        return 1
    fi
    return 0
}

fault_component_to_campaign_component() {
    local comp="${1:-rf}"
    case "${comp}" in
        rf)
            echo "0"
            ;;
        smem_rf|smem_lds)
            echo "2"
            ;;
        l1d)
            echo "3"
            ;;
        l2)
            echo "6"
            ;;
        gmem)
            echo "11"
            ;;
        *)
            echo ""
            ;;
    esac
}

normalize_component_list() {
    local raw="${1:-}"
    local normalized token
    local -A seen=()
    local -a out=()
    normalized="${raw//,/ }"
    normalized="${normalized//:/ }"
    for token in ${normalized}; do
        case "${token}" in
            rf|smem_rf|smem_lds|l1d|l2)
                if [[ -n "${seen[${token}]:-}" ]]; then
                    continue
                fi
                seen["${token}"]=1
                out+=("${token}")
                ;;
            *)
                echo "=== Error: unsupported component '${token}' in ALL_COMPONENTS ===" >&2
                return 1
                ;;
        esac
    done
    if (( ${#out[@]} == 0 )); then
        echo "=== Error: ALL_COMPONENTS resolved to empty set ===" >&2
        return 1
    fi
    local IFS=":"
    echo "${out[*]}"
}

component_display_name() {
    local comp="${1:-}"
    case "${comp}" in
        rf)
            echo "register"
            ;;
        smem_rf)
            echo "shared_memory"
            ;;
        smem_lds)
            echo "shared_memory_lds"
            ;;
        l1d)
            echo "l1d_cache"
            ;;
        l2)
            echo "l2_cache"
            ;;
        gmem)
            echo "gmem"
            ;;
        *)
            echo "${comp}"
            ;;
    esac
}

component_summary_label() {
    local comp="${1:-}"
    case "${comp}" in
        rf)
            echo "Register"
            ;;
        smem_rf|smem_lds)
            echo "Shared Memory"
            ;;
        l1d)
            echo "L1 D Cache"
            ;;
        l2)
            echo "L2 Cache"
            ;;
        gmem)
            echo "GMEM"
            ;;
        *)
            echo "${comp}"
            ;;
    esac
}

is_memory_component_for_shared_analyzer() {
    local comp="${1:-}"
    [[ "${comp}" == "smem_rf" || "${comp}" == "smem_lds" || "${comp}" == "l1d" || "${comp}" == "l2" || "${comp}" == "gmem" ]]
}

resolve_analyzer_fault_component() {
    local comp="${1:-}"
    if [[ "${comp}" == "gmem" ]]; then
        echo "l1d"
        return 0
    fi
    if [[ "${MODE}" == "all_components" || "${MODE}" == "all" ]]; then
        if is_memory_component_for_shared_analyzer "${comp}"; then
            # In all_components mode, memory components share one analyzer output.
            # Choose the shared analyzer strictly from runtime-observed traffic.
            if [[ "$(resolve_current_app_shared_memory_usage)" == "1" ]]; then
                echo "smem_rf"
            else
                echo "l1d"
            fi
            return 0
        fi
    fi
    echo "${comp}"
}

write_gmem_exact_outputs() {
    local summary_json_path="${CURRENT_RUN_DIR}/summary.json"
    local summary_txt_path="${CURRENT_RUN_DIR}/summary.txt"
    local result_csv=""
    local simple_csv=""
    result_csv="$(resolve_test_result_csv_path "$(build_exact_result_csv_filename "exact_result")")"
    python3 - "${summary_json_path}" "${result_csv}" <<'PY' || return $?
import csv
import json
import sys
from pathlib import Path

summary_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])
summary = json.loads(summary_path.read_text(encoding="utf-8"))
counts = summary.get("classification_counts", {})
rates = summary.get("classification_rates", {})
row = {
    "benchmark": str(summary.get("benchmark", "")),
    "test_id": str(summary.get("test_id", "")),
    "sara_semantics_profile": str(
        summary.get("sara_semantics_profile")
        or str(summary.get("exact_semantics_profile", "")).replace(
            "canonical_proof_exact_v3", "canonical_proof_sara_v3"
        )
    ),
    "gmem_den": int(counts.get("total", 0) or 0),
    "gmem_masked_num": counts.get("masked", 0),
    "gmem_sdc_num": counts.get("sdc", 0),
    "gmem_due_num": counts.get("due", 0),
    "gmem_unknown_num": counts.get("unknown", 0),
    "gmem_masked_rate": float(rates.get("masked", 0.0) or 0.0),
    "gmem_sdc_rate": float(rates.get("sdc", 0.0) or 0.0),
    "gmem_due_rate": float(rates.get("due", 0.0) or 0.0),
    "gmem_unknown_rate": float(rates.get("unknown", 0.0) or 0.0),
}
output_path.parent.mkdir(parents=True, exist_ok=True)
with output_path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=list(row.keys()))
    writer.writeheader()
    writer.writerow(row)
PY
    echo "Wrote GMEM CSV: ${result_csv}"
    simple_csv="$(resolve_test_result_csv_path "$(build_exact_result_csv_filename "exact_result_simple")")"
    run_timed "analyzer_gmem_simple_summary_csv_cpp" "${EXACT_CORE_BIN}" rates-simple-summary-csv \
        --input "${summary_txt_path}" \
        --output "${simple_csv}" || return $?
    if [[ "${FAIR_TIMING}" == "1" ]]; then
        rewrite_simple_summary_total_time "${summary_txt_path}" "${simple_csv}"
    fi
    echo "Wrote GMEM simple summary CSV: ${simple_csv}"
}

resolve_profile_tmp_out_path() {
    local mode="${PROFILE_TMP_OUT:-auto}"
    local mode_lc="${mode,,}"
    local -a candidates=()
    local chosen=""

    if [[ -n "${mode}" && "${mode_lc}" != "auto" ]]; then
        if [[ -f "${mode}" ]]; then
            echo "${mode}"
        else
            echo ""
        fi
        return
    fi

    if [[ -f "./logs1/tmp.out1" ]]; then
        echo "./logs1/tmp.out1"
        return
    fi

    while IFS= read -r p; do
        [[ -z "${p}" ]] && continue
        candidates+=("${p}")
    done < <(find . -maxdepth 4 -type f -path "./logs*/tmp.out*" 2>/dev/null | sort -u)

    if (( ${#candidates[@]} == 0 )); then
        echo ""
        return
    fi

    chosen="$(ls -1t -- "${candidates[@]}" 2>/dev/null | head -n 1)"
    echo "${chosen}"
}


get_smem_size_bits_from_profile_log() {
    local log_file="$1"
    local eff_smem=0
    local kname ksmem line bxyz bx by bz v bytes maxb tline suf
    local dyn_bytes static_bytes block_elems elem_bytes chosen
    declare -A k_static_smem_bytes
    declare -A k_block_elems
    declare -A k_shared_elem_bytes

    while IFS= read -r line; do
        kname="$(echo "${line}" | sed -E "s/.*Kernel '([^']+)'.*/\1/")"
        ksmem="$(echo "${line}" | sed -E 's/.*smem=([0-9]+).*/\1/')"
        if [[ -z "${kname}" || ! "${ksmem}" =~ ^[0-9]+$ ]]; then
            continue
        fi
        if [[ -z "${k_static_smem_bytes[$kname]:-}" || ${k_static_smem_bytes[$kname]} -lt ${ksmem} ]]; then
            k_static_smem_bytes["${kname}"]="${ksmem}"
        fi
    done < <(grep -aE "GPGPU-Sim PTX: Kernel '.*' : regs=[0-9]+, lmem=[0-9]+, smem=[0-9]+" "${log_file}")

    while IFS= read -r line; do
        kname="$(echo "${line}" | sed -E "s/.*(pushing|launching) kernel '([^']+)'.*/\2/")"
        bxyz="$(echo "${line}" | sed -E "s/.*blockDim[[:space:]]*=[[:space:]]*\\(\\s*([0-9]+)\\s*,\\s*([0-9]+)\\s*,\\s*([0-9]+)\\s*\\).*/\\1 \\2 \\3/")"
        bx="$(echo "${bxyz}" | awk '{print $1}')"
        by="$(echo "${bxyz}" | awk '{print $2}')"
        bz="$(echo "${bxyz}" | awk '{print $3}')"
        if [[ -n "${kname}" && "${bx}" =~ ^[0-9]+$ && "${by}" =~ ^[0-9]+$ && "${bz}" =~ ^[0-9]+$ ]]; then
            v=$(( bx * by * bz ))
            if [[ -z "${k_block_elems[$kname]:-}" || ${k_block_elems[$kname]} -lt ${v} ]]; then
                k_block_elems["${kname}"]="${v}"
            fi
        fi
    done < <(grep -aE "(pushing|launching) kernel '.*'.*blockDim[[:space:]]*=" "${log_file}")

    while IFS= read -r kname; do
        [[ -n "${kname}" ]] || continue
        maxb=0
        while IFS= read -r tline; do
            suf="$(echo "${tline}" | sed -nE 's/.*(ld|st)\.shared\.([a-z0-9]+).*/\2/p')"
            case "${suf}" in
                *64) bytes=8 ;;
                *32) bytes=4 ;;
                *16) bytes=2 ;;
                *8) bytes=1 ;;
                *) bytes=0 ;;
            esac
            (( bytes > maxb )) && maxb="${bytes}"
        done < <(grep -aF "kernel=\"${kname}\"" "${log_file}" | grep -aE "\[PTX_INST_SUM\].*(ld\.shared|st\.shared)\.")
        if (( maxb > 0 )); then
            k_shared_elem_bytes["${kname}"]="${maxb}"
        fi
    done < <(printf '%s\n' "${!k_static_smem_bytes[@]}" | sort -u)

    for kname in "${!k_static_smem_bytes[@]}"; do
        static_bytes="${k_static_smem_bytes[$kname]:-0}"
        block_elems="${k_block_elems[$kname]:-0}"
        elem_bytes="${k_shared_elem_bytes[$kname]:-0}"
        dyn_bytes=0
        if (( block_elems > 0 && elem_bytes > 0 )); then
            dyn_bytes=$(( block_elems * elem_bytes ))
        fi
        if (( dyn_bytes > static_bytes )); then
            chosen="${dyn_bytes}"
        else
            chosen="${static_bytes}"
        fi
        (( chosen > eff_smem )) && eff_smem="${chosen}"
    done

    if (( eff_smem <= 0 )); then
        echo "0"
        return
    fi
    echo "$(( eff_smem * 8 ))"
}

get_thread_warp_block_max_from_profile_log() {
    local log_file="$1"
    local max_threads=0
    local max_warps=0
    local max_blocks=0
    local line kname gxyz bxyz gx gy gz bx by bz bcnt tcnt wcnt

    while IFS= read -r line; do
        kname="$(echo "${line}" | sed -E "s/.*(pushing|launching) kernel '([^']+)'.*/\2/")"
        [[ -n "${kname}" ]] || continue
        gxyz="$(echo "${line}" | sed -E "s/.*gridDim[[:space:]]*=[[:space:]]*\\(\\s*([0-9]+)\\s*,\\s*([0-9]+)\\s*,\\s*([0-9]+)\\s*\\).*/\\1 \\2 \\3/")"
        bxyz="$(echo "${line}" | sed -E "s/.*blockDim[[:space:]]*=[[:space:]]*\\(\\s*([0-9]+)\\s*,\\s*([0-9]+)\\s*,\\s*([0-9]+)\\s*\\).*/\\1 \\2 \\3/")"
        gx="$(echo "${gxyz}" | awk '{print $1}')"
        gy="$(echo "${gxyz}" | awk '{print $2}')"
        gz="$(echo "${gxyz}" | awk '{print $3}')"
        bx="$(echo "${bxyz}" | awk '{print $1}')"
        by="$(echo "${bxyz}" | awk '{print $2}')"
        bz="$(echo "${bxyz}" | awk '{print $3}')"
        if [[ "${gx}" =~ ^[0-9]+$ && "${gy}" =~ ^[0-9]+$ && "${gz}" =~ ^[0-9]+$ ]]; then
            bcnt=$(( gx * gy * gz ))
            (( bcnt > max_blocks )) && max_blocks="${bcnt}"
        fi
        if [[ "${gx}" =~ ^[0-9]+$ && "${gy}" =~ ^[0-9]+$ && "${gz}" =~ ^[0-9]+$ && "${bx}" =~ ^[0-9]+$ && "${by}" =~ ^[0-9]+$ && "${bz}" =~ ^[0-9]+$ ]]; then
            tcnt=$(( gx * gy * gz * bx * by * bz ))
            wcnt=$(( (tcnt + 31) / 32 ))
            (( tcnt > max_threads )) && max_threads="${tcnt}"
            (( wcnt > max_warps )) && max_warps="${wcnt}"
        fi
    done < <(grep -aE "(pushing|launching) kernel '.*'.*gridDim[[:space:]]*=.*blockDim[[:space:]]*=" "${log_file}")

    echo "${max_threads} ${max_warps} ${max_blocks}"
}

load_profile_metrics_from_tmp() {
    if [[ "${PROFILE_METRICS_READY}" -eq 1 ]]; then
        return
    fi
    PROFILE_METRICS_READY=1

    PROFILE_METRICS_SOURCE="$(resolve_profile_tmp_out_path)"
    if [[ -z "${PROFILE_METRICS_SOURCE}" || ! -f "${PROFILE_METRICS_SOURCE}" ]]; then
        PROFILE_METRICS_SOURCE=""
        PROFILE_THREAD_RAND_MAX=""
        PROFILE_WARP_RAND_MAX=""
        PROFILE_BLOCK_RAND_MAX=""
        PROFILE_DATATYPE_BITS=""
        PROFILE_SMEM_SIZE_BITS=""
        return
    fi

    read -r PROFILE_THREAD_RAND_MAX PROFILE_WARP_RAND_MAX PROFILE_BLOCK_RAND_MAX <<< "$(get_thread_warp_block_max_from_profile_log "${PROFILE_METRICS_SOURCE}")"
    PROFILE_DATATYPE_BITS="$(get_datatype_bits_from_log "${PROFILE_METRICS_SOURCE}")"
    PROFILE_SMEM_SIZE_BITS="$(get_smem_size_bits_from_profile_log "${PROFILE_METRICS_SOURCE}")"
}

get_campaign_var_from_script() {
    local var_name="$1"
    local script_file="${2:-${SARA_COMMON_DIR}/campaign_exec.sh}"
    local line value
    if [[ ! -f "${script_file}" ]]; then
        echo ""
        return
    fi
    line="$(grep -E "^[[:space:]]*${var_name}[[:space:]]*=" "${script_file}" | tail -n 1 || true)"
    if [[ -z "${line}" ]]; then
        echo ""
        return
    fi
    value="${line#*=}"
    value="${value%%#*}"
    value="$(echo "${value}" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
    if [[ "${value}" =~ ^\"(.*)\"$ ]]; then
        value="${BASH_REMATCH[1]}"
    fi
    if [[ "${value}" =~ ^\$\{[A-Za-z_][A-Za-z0-9_]*:-([^}]*)\}$ ]]; then
        value="${BASH_REMATCH[1]}"
    elif [[ "${value}" =~ ^\$\{[A-Za-z_][A-Za-z0-9_]*-([^}]*)\}$ ]]; then
        value="${BASH_REMATCH[1]}"
    fi
    if [[ "${value}" =~ ^\"(.*)\"$ ]]; then
        value="${BASH_REMATCH[1]}"
    fi
    echo "${value}"
}

get_app_info_var() {
    local key="$1"
    local app_info_file="${TEST_APPS_ROOT}/${TEST_APP_NAME}/app_info.txt"
    if [[ ! -f "${app_info_file}" ]]; then
        echo ""
        return
    fi
    awk -F':' -v key="${key}" '
        $1 ~ ("^" key "$") {
            v = $2
            sub(/^[[:space:]]+/, "", v)
            sub(/[[:space:]]+$/, "", v)
            print v
            exit
        }
    ' "${app_info_file}"
}

get_config_numeric_opt() {
    local opt="$1"
    local val
    val="$(awk -v opt="${opt}" '$1 == opt {print $2; exit}' "${CONFIG_FILE}" 2>/dev/null)"
    echo "${val}"
}

get_json_field() {
    local json_file="$1"
    local field_path="$2"
    local default_value="${3:-}"
    python3 - "${json_file}" "${field_path}" "${default_value}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
field_path = sys.argv[2]
default_value = sys.argv[3]
if not path.is_file():
    print(default_value)
    raise SystemExit(0)
try:
    raw = json.loads(path.read_text())
except Exception:
    print(default_value)
    raise SystemExit(0)
cur = raw
for part in field_path.split("."):
    if isinstance(cur, dict) and part in cur:
        cur = cur[part]
    else:
        print(default_value)
        raise SystemExit(0)
if cur is None:
    print(default_value)
elif isinstance(cur, bool):
    print("1" if cur else "0")
else:
    print(cur)
PY
}

normalize_shader_domain_spec() {
    local raw="${1:-}"
    local normalized token dec
    local -A seen=()
    local -a out=()

    normalized="${raw//,/ }"
    normalized="${normalized//:/ }"
    for token in ${normalized}; do
        if ! [[ "${token}" =~ ^(0[xX][0-9a-fA-F]+|[0-9]+)$ ]]; then
            continue
        fi
        dec=$((token))
        if [[ -n "${seen[${dec}]:-}" ]]; then
            continue
        fi
        seen["${dec}"]=1
        out+=("${dec}")
    done

    if (( ${#out[@]} == 0 )); then
        echo ""
        return
    fi
    local IFS=":"
    echo "${out[*]}"
}

shader_domain_all_from_count() {
    local count="${1:-0}"
    if ! is_pos_int "${count}" || (( count <= 0 )); then
        echo ""
        return
    fi
    local -a out=()
    local i
    for ((i = 0; i < count; i++)); do
        out+=("${i}")
    done
    local IFS=":"
    echo "${out[*]}"
}

shader_domain_all_from_spec() {
    local spec normalized token max_seen
    spec="${1:-}"
    normalized="$(normalize_shader_domain_spec "${spec}")"
    if [[ -z "${normalized}" ]]; then
        echo ""
        return
    fi
    max_seen=-1
    IFS=':' read -r -a _tokens <<< "${normalized}"
    for token in "${_tokens[@]}"; do
        if ! [[ "${token}" =~ ^[0-9]+$ ]]; then
            continue
        fi
        if (( token > max_seen )); then
            max_seen="${token}"
        fi
    done
    if (( max_seen < 0 )); then
        echo ""
        return
    fi
    shader_domain_all_from_count "$((max_seen + 1))"
}

resolve_l1d_sampling_domain() {
    local mode_raw="${1:-auto}"
    local campaign_raw="${2:-}"
    local app_raw="${3:-}"
    local config_shader_count="${4:-0}"
    local mode_lc campaign_shaders app_shaders
    local l1d_shaders source_shaders source_active_sm

    mode_lc="${mode_raw,,}"
    campaign_shaders="$(normalize_shader_domain_spec "${campaign_raw}")"
    app_shaders="$(normalize_shader_domain_spec "${app_raw}")"
    if ! is_nonneg_int "${config_shader_count}"; then
        config_shader_count="0"
    fi

    if [[ -z "${mode_lc}" || "${mode_lc}" == "auto" ]]; then
        # Prefer the current app/profile-derived shader scope over
        # campaign_exec.sh.  The campaign script is a mutable FI launcher and may
        # still carry bootstrapping defaults (for example the full 0..45 shader
        # list from a previous/default app) when public SARA runs prepare their
        # FI-equivalent sampling snapshot.
        if [[ -n "${app_shaders}" ]]; then
            l1d_shaders="${app_shaders}"
            source_shaders="app_info"
            source_active_sm="app_shaders_len"
        elif [[ -n "${campaign_shaders}" ]]; then
            l1d_shaders="${campaign_shaders}"
            source_shaders="campaign"
            source_active_sm="campaign_shaders_len"
        elif is_pos_int "${config_shader_count}" && (( config_shader_count > 0 )); then
            l1d_shaders="$(shader_domain_all_from_count "${config_shader_count}")"
            source_shaders="config_all"
            source_active_sm="config_all_count"
        else
            l1d_shaders=""
            source_shaders="default"
            source_active_sm="resolved_l1d_shaders_len"
        fi
    elif [[ "${mode_lc}" == "all" ]]; then
        if is_pos_int "${config_shader_count}" && (( config_shader_count > 0 )); then
            l1d_shaders="$(shader_domain_all_from_count "${config_shader_count}")"
            source_shaders="config_all"
            source_active_sm="config_all_count"
        elif [[ -n "${app_shaders}" ]]; then
            l1d_shaders="$(shader_domain_all_from_spec "${app_shaders}")"
            source_shaders="app_info_all"
            source_active_sm="app_info_all_count"
        elif [[ -n "${campaign_shaders}" ]]; then
            l1d_shaders="$(shader_domain_all_from_spec "${campaign_shaders}")"
            source_shaders="campaign_all"
            source_active_sm="campaign_all_count"
        else
            l1d_shaders=""
            source_shaders="default"
            source_active_sm="resolved_l1d_shaders_len"
        fi
    else
        l1d_shaders="$(normalize_shader_domain_spec "${mode_raw}")"
        source_shaders="env_l1d_shaders"
        source_active_sm="resolved_l1d_shaders_len"
    fi

    printf '%s\t%s\t%s\n' "${l1d_shaders}" "${source_shaders}" "${source_active_sm}"
}

get_shader_count_from_config() {
    local cfg="${1:-${CONFIG_FILE}}"
    local val
    if [[ ! -f "${cfg}" ]]; then
        echo "0"
        return
    fi
    val="$(awk '$1 == "-gpgpu_n_shader" {print $2; exit} $1 == "-gpgpu_n_clusters" {print $2; exit}' "${cfg}" 2>/dev/null)"
    if is_pos_int "${val}"; then
        echo "${val}"
    else
        echo "0"
    fi
}

get_l1d_line_size_from_config() {
    local cfg="${1:-${CONFIG_FILE}}"
    if [[ ! -f "${cfg}" ]]; then
        echo "0"
        return
    fi
    local geom line_sz
    geom="$(awk '$1 == "-gpgpu_cache:dl1" {print; exit}' "${cfg}" \
        | sed -nE 's/^[[:space:]]*[^[:space:]]+[[:space:]]+[SN]:([0-9]+):([0-9]+):([0-9]+).*/\1 \2 \3/p')"
    line_sz="$(echo "${geom}" | awk '{print $2}')"
    if ! [[ "${line_sz}" =~ ^[0-9]+$ ]] || (( line_sz <= 0 )); then
        echo "0"
        return
    fi
    echo "${line_sz}"
}

get_l1d_nset_from_config() {
    local cfg="${1:-${CONFIG_FILE}}"
    if [[ ! -f "${cfg}" ]]; then
        echo "0"
        return
    fi
    local geom nset
    geom="$(awk '$1 == "-gpgpu_cache:dl1" {print; exit}' "${cfg}" \
        | sed -nE 's/^[[:space:]]*[^[:space:]]+[[:space:]]+[SN]:([0-9]+):([0-9]+):([0-9]+).*/\1 \2 \3/p')"
    nset="$(echo "${geom}" | awk '{print $1}')"
    if ! [[ "${nset}" =~ ^[0-9]+$ ]] || (( nset <= 0 )); then
        echo "0"
        return
    fi
    echo "${nset}"
}

get_l1d_assoc_from_config() {
    local cfg="${1:-${CONFIG_FILE}}"
    if [[ ! -f "${cfg}" ]]; then
        echo "0"
        return
    fi
    local geom assoc
    geom="$(awk '$1 == "-gpgpu_cache:dl1" {print; exit}' "${cfg}" \
        | sed -nE 's/^[[:space:]]*[^[:space:]]+[[:space:]]+[SN]:([0-9]+):([0-9]+):([0-9]+).*/\1 \2 \3/p')"
    assoc="$(echo "${geom}" | awk '{print $3}')"
    if ! [[ "${assoc}" =~ ^[0-9]+$ ]] || (( assoc <= 0 )); then
        echo "0"
        return
    fi
    echo "${assoc}"
}

get_l1d_tag_bits_from_config() {
    local cfg="${1:-${CONFIG_FILE}}"
    local addr_bits="${2:-64}"
    if [[ ! -f "${cfg}" ]]; then
        echo ""
        return
    fi
    local geom nset line_sz _assoc
    geom="$(awk '$1 == "-gpgpu_cache:dl1" {print; exit}' "${cfg}" \
        | sed -nE 's/^[[:space:]]*[^[:space:]]+[[:space:]]+[SN]:([0-9]+):([0-9]+):([0-9]+).*/\1 \2 \3/p')"
    nset="$(echo "${geom}" | awk '{print $1}')"
    line_sz="$(echo "${geom}" | awk '{print $2}')"
    _assoc="$(echo "${geom}" | awk '{print $3}')"
    derive_cache_tag_bits "${nset}" "${line_sz}" "${addr_bits}"
}

get_l1d_size_bits_from_config() {
    local cfg="${1:-${CONFIG_FILE}}"
    local tag_bits="${2:-57}"
    if [[ ! -f "${cfg}" ]]; then
        echo "0"
        return
    fi

    local nset line_sz assoc
    local geom
    geom="$(awk '$1 == "-gpgpu_cache:dl1" {print; exit}' "${cfg}" \
        | sed -nE 's/^[[:space:]]*[^[:space:]]+[[:space:]]+[SN]:([0-9]+):([0-9]+):([0-9]+).*/\1 \2 \3/p')"
    nset="$(echo "${geom}" | awk '{print $1}')"
    line_sz="$(echo "${geom}" | awk '{print $2}')"
    assoc="$(echo "${geom}" | awk '{print $3}')"

    if ! [[ "${nset}" =~ ^[0-9]+$ && "${line_sz}" =~ ^[0-9]+$ && "${assoc}" =~ ^[0-9]+$ ]]; then
        echo "0"
        return
    fi
    if ! [[ "${tag_bits}" =~ ^[0-9]+$ ]] || [[ "${tag_bits}" -lt 0 ]]; then
        echo "0"
        return
    fi

    local per_line_bits total_bits
    per_line_bits=$(( line_sz * 8 + tag_bits ))
    total_bits=$(( nset * assoc * per_line_bits ))
    if (( total_bits <= 0 )); then
        echo "0"
        return
    fi
    echo "${total_bits}"
}

get_l2_line_size_from_config() {
    local cfg="${1:-${CONFIG_FILE}}"
    if [[ ! -f "${cfg}" ]]; then
        echo "0"
        return
    fi
    local geom line_sz
    geom="$(awk '$1 == "-gpgpu_cache:dl2" {print; exit}' "${cfg}" \
        | sed -nE 's/^[[:space:]]*[^[:space:]]+[[:space:]]+[SN]:([0-9]+):([0-9]+):([0-9]+).*/\1 \2 \3/p')"
    line_sz="$(echo "${geom}" | awk '{print $2}')"
    if ! [[ "${line_sz}" =~ ^[0-9]+$ ]] || (( line_sz <= 0 )); then
        echo "0"
        return
    fi
    echo "${line_sz}"
}

get_l2_nset_from_config() {
    local cfg="${1:-${CONFIG_FILE}}"
    if [[ ! -f "${cfg}" ]]; then
        echo "0"
        return
    fi
    local geom nset
    geom="$(awk '$1 == "-gpgpu_cache:dl2" {print; exit}' "${cfg}" \
        | sed -nE 's/^[[:space:]]*[^[:space:]]+[[:space:]]+[SN]:([0-9]+):([0-9]+):([0-9]+).*/\1 \2 \3/p')"
    nset="$(echo "${geom}" | awk '{print $1}')"
    if ! [[ "${nset}" =~ ^[0-9]+$ ]] || (( nset <= 0 )); then
        echo "0"
        return
    fi
    echo "${nset}"
}

get_l2_assoc_from_config() {
    local cfg="${1:-${CONFIG_FILE}}"
    if [[ ! -f "${cfg}" ]]; then
        echo "0"
        return
    fi
    local geom assoc
    geom="$(awk '$1 == "-gpgpu_cache:dl2" {print; exit}' "${cfg}" \
        | sed -nE 's/^[[:space:]]*[^[:space:]]+[[:space:]]+[SN]:([0-9]+):([0-9]+):([0-9]+).*/\1 \2 \3/p')"
    assoc="$(echo "${geom}" | awk '{print $3}')"
    if ! [[ "${assoc}" =~ ^[0-9]+$ ]] || (( assoc <= 0 )); then
        echo "0"
        return
    fi
    echo "${assoc}"
}

get_l2_tag_bits_from_config() {
    local cfg="${1:-${CONFIG_FILE}}"
    local addr_bits="${2:-64}"
    if [[ ! -f "${cfg}" ]]; then
        echo ""
        return
    fi
    local geom nset line_sz _assoc
    geom="$(awk '$1 == "-gpgpu_cache:dl2" {print; exit}' "${cfg}" \
        | sed -nE 's/^[[:space:]]*[^[:space:]]+[[:space:]]+[SN]:([0-9]+):([0-9]+):([0-9]+).*/\1 \2 \3/p')"
    nset="$(echo "${geom}" | awk '{print $1}')"
    line_sz="$(echo "${geom}" | awk '{print $2}')"
    _assoc="$(echo "${geom}" | awk '{print $3}')"
    derive_cache_tag_bits "${nset}" "${line_sz}" "${addr_bits}"
}

get_l2_global_prefill_from_config() {
    local cfg="${1:-${CONFIG_FILE}}"
    if [[ ! -f "${cfg}" ]]; then
        echo "1"
        return
    fi
    local memcpy_fill
    memcpy_fill="$(awk '$1 == "-gpgpu_perf_sim_memcpy" {print $2; exit}' "${cfg}")"
    if [[ "${memcpy_fill}" =~ ^[0-9]+$ ]] && (( memcpy_fill > 0 )); then
        echo "1"
    else
        echo "0"
    fi
}

get_l1d_write_allocate_from_config() {
    local cfg="${1:-${CONFIG_FILE}}"
    if [[ ! -f "${cfg}" ]]; then
        echo "0"
        return
    fi
    local wap
    wap="$(awk '$1 == "-gpgpu_cache:dl1" {print $2; exit}' "${cfg}" \
        | sed -nE 's/^[SN]:[0-9]+:[0-9]+:[0-9]+,[A-Z]:[A-Z]:[a-zA-Z]:([A-Z]):[A-Z].*/\1/p')"
    case "${wap}" in
        N)
            echo "0"
            ;;
        W|F|L)
            echo "1"
            ;;
        *)
            echo "0"
            ;;
    esac
}

detect_gpu_arch_from_config() {
    local cfg="${1:-${CONFIG_FILE}}"
    local cap major minor
    if [[ ! -f "${cfg}" ]]; then
        echo ""
        return
    fi
    cap="$(awk '$1 == "-gpgpu_ptx_force_max_capability" {print $2; exit}' "${cfg}")"
    if [[ "${cap}" =~ ^[0-9]+$ ]]; then
        printf "sm_%s" "${cap}"
        return
    fi
    major="$(awk '$1 == "-gpgpu_compute_capability_major" {print $2; exit}' "${cfg}")"
    minor="$(awk '$1 == "-gpgpu_compute_capability_minor" {print $2; exit}' "${cfg}")"
    if [[ "${major}" =~ ^[0-9]+$ && "${minor}" =~ ^[0-9]+$ ]]; then
        printf "sm_%s%s" "${major}" "${minor}"
        return
    fi
    echo ""
}

resolve_gpu_arch_auto() {
    if [[ "${GPU_ARCH}" =~ ^sm_[0-9]+$ ]]; then
        return
    fi
    local detected
    detected="$(detect_gpu_arch_from_config "${CONFIG_FILE}")"
    if [[ "${detected}" =~ ^sm_[0-9]+$ ]]; then
        GPU_ARCH="${detected}"
    else
        GPU_ARCH="sm_75"
    fi
    echo "=== Resolved GPU_ARCH=${GPU_ARCH} from ${CONFIG_FILE} ==="
}

update_config_line() {
    local key="$1"
    local value="$2"
    if grep -qE "^${key}[[:space:]]+" "${CONFIG_FILE}"; then
        sed -i -E "s|^${key}[[:space:]].*$|${key} ${value}|" "${CONFIG_FILE}"
    else
        echo "${key} ${value}" >> "${CONFIG_FILE}"
    fi
}

get_datatype_bits_from_log() {
    local log_file="$1"
    local bits=0
    if grep -qE '(%rd[0-9]+|\.(u|s|f|b)64\b)' "${log_file}"; then
        bits=64
    fi
    if (( bits < 32 )) && grep -qE '\.(u|s|f|b)32\b' "${log_file}"; then
        bits=32
    fi
    if (( bits < 16 )) && grep -qE '\.(u|s|f|b)16\b' "${log_file}"; then
        bits=16
    fi
    if (( bits < 8 )) && grep -qE '\.(u|s|f|b)8\b' "${log_file}"; then
        bits=8
    fi
    if (( bits == 0 )); then
        bits=32
    fi
    echo "${bits}"
}

cycles_file_matches_current_run() {
    local cycles_file="$1"
    local expected_cycles="$2"
    local stats count min_cycle max_cycle
    [[ -f "${cycles_file}" && -s "${cycles_file}" ]] || return 1
    [[ "${expected_cycles}" =~ ^[0-9]+$ && "${expected_cycles}" -gt 0 ]] || return 1
    stats="$(
        awk '
            NF {
                v = $1 + 0
                n += 1
                if (n == 1 || v < min_v) min_v = v
                if (n == 1 || v > max_v) max_v = v
            }
            END {
                if (n <= 0) exit 1
                printf "%d\t%d\t%d", n, min_v, max_v
            }
        ' "${cycles_file}" 2>/dev/null
    )" || return 1
    IFS=$'\t' read -r count min_cycle max_cycle <<< "${stats}"
    [[ "${count}" =~ ^[0-9]+$ ]] || return 1
    [[ "${min_cycle}" =~ ^-?[0-9]+$ ]] || return 1
    [[ "${max_cycle}" =~ ^-?[0-9]+$ ]] || return 1
    if (( min_cycle < 0 )); then
        return 1
    fi
    if (( count < expected_cycles - 1 || count > expected_cycles + 1 )); then
        return 1
    fi
    if (( max_cycle < expected_cycles - 1 || max_cycle > expected_cycles )); then
        return 1
    fi
    return 0
}

cycles_file_embeds_active_thread_ids() {
    local cycles_file="$1"
    [[ -f "${cycles_file}" && -s "${cycles_file}" ]] || return 1
    grep -Eq 'active_thread_ids|active_thread_ranges' "${cycles_file}" 2>/dev/null
}

get_smem_size_bits_from_log() {
    local log_file="$1"
    local max_smem_bytes
    max_smem_bytes="$(
        grep -E "GPGPU-Sim PTX: Kernel '.*' : regs=[0-9]+, lmem=[0-9]+, smem=[0-9]+" "${log_file}" \
            | sed -E 's/.*smem=([0-9]+).*/\1/' \
            | awk 'BEGIN{m=0} {v=$1+0; if(v>m)m=v} END{print m}'
    )"
    if [[ -z "${max_smem_bytes}" ]]; then
        max_smem_bytes=0
    fi
    if [[ "${max_smem_bytes}" -le 0 ]]; then
        echo "0"
        return
    fi
    echo "$((max_smem_bytes * 8))"
}

detect_current_app_shared_memory_usage() {
    local golden_log=""
    local trace_log=""
    local profile_log=""
    local trace_json=""
    golden_log="${CURRENT_RUN_DIR}/golden.log"
    trace_log="${CURRENT_RUN_DIR}/trace_capture.log"
    profile_log="${PROFILE_METRICS_SOURCE:-${CURRENT_RUN_DIR}/profile2.log}"
    trace_json="${CURRENT_RUN_DIR}/inst_trace.json"

    if [[ -f "${profile_log}" ]] && grep -aEq "smem=[1-9][0-9]*|\\[PTX_INST_SUM\\].*(ld\\.shared|st\\.shared)\\." "${profile_log}"; then
        echo "1"
        return
    fi

    if [[ -f "${golden_log}" ]] && grep -aEq "smem=[1-9][0-9]*|\\[PTX_INST_SUM\\].*(ld\\.shared|st\\.shared)\\." "${golden_log}"; then
        echo "1"
        return
    fi

    if [[ -f "${trace_log}" ]] && grep -aEq "\\[PTX_INST_SUM\\].*(ld\\.shared|st\\.shared)\\." "${trace_log}"; then
        echo "1"
        return
    fi

    if [[ -f "${trace_json}" ]] && grep -aEq '"mem_space"[[:space:]]*:[[:space:]]*"shared"|"space"[[:space:]]*:[[:space:]]*"shared"' "${trace_json}"; then
        echo "1"
        return
    fi

    echo "0"
}

resolve_current_app_shared_memory_usage() {
    if [[ "${CURRENT_APP_USES_SHARED_MEMORY}" == "0" || "${CURRENT_APP_USES_SHARED_MEMORY}" == "1" ]]; then
        echo "${CURRENT_APP_USES_SHARED_MEMORY}"
        return
    fi
    CURRENT_APP_USES_SHARED_MEMORY="$(detect_current_app_shared_memory_usage)"
    if [[ "${CURRENT_APP_USES_SHARED_MEMORY}" != "0" && "${CURRENT_APP_USES_SHARED_MEMORY}" != "1" ]]; then
        CURRENT_APP_USES_SHARED_MEMORY="0"
    fi
    echo "${CURRENT_APP_USES_SHARED_MEMORY}"
}

write_skipped_component_artifacts() {
    local comp="$1"
    local note="${2:-skipped}"
    local summary_json_path="$3"
    local summary_txt_path="$4"
    local exact_rates_json_path="$5"
    local analyzer_output_json_path="$6"

    python3 - \
        "${TEST_APP_NAME}" \
        "${CURRENT_TEST_ID}" \
        "${comp}" \
        "${note}" \
        "${summary_json_path}" \
        "${summary_txt_path}" \
        "${exact_rates_json_path}" \
        "${analyzer_output_json_path}" <<'PY'
import json
import sys
from pathlib import Path

benchmark, test_id, component, note, summary_json_path, summary_txt_path, exact_rates_json_path, analyzer_output_json_path = sys.argv[1:]

rate_payload = {
    "den": 0,
    "masked": 0,
    "sdc": 0,
    "due": 0,
    "unknown": 0,
    "rate": {
        "masked": 0.0,
        "sdc": 0.0,
        "due": 0.0,
        "unknown": 0.0,
    },
}

summary_payload = {
    "benchmark": benchmark,
    "test_id": test_id,
    "status": "skip",
    "status_reason": note,
    "strict_ok": True,
    "classification_counts": {
        "total": 0,
        "masked": 0,
        "sdc": 0,
        "due": 0,
        "unknown": 0,
    },
    "classification_rates": {
        "masked": 0.0,
        "sdc": 0.0,
        "due": 0.0,
        "unknown": 0.0,
    },
    "summary": {
        "shared_memory": {
            "smem_rf": dict(rate_payload),
            "smem_lds": dict(rate_payload),
        },
        "l1d_cache": dict(rate_payload),
        "l2_cache": dict(rate_payload),
    },
    "smem_size_bits_source": "detected_no_shared_use",
    "smem_size_bits_final": 0,
    "smem_domain_policy": "",
    "smem_domain_bits_per_seed_final": 0,
    "smem_domain_total_bits_final": 0,
    "smem_domain_units": "bits",
    "smem_domain_sampling_bits": 0,
    "smem_domain_derived_bits": 0,
    "smem_domain_mismatch": 0,
    "domain_sampling_space_total_bits": 0,
    "domain_derived_total_bits": 0,
    "domain_mismatch_bits": 0,
    "domain_reconciliation_method": "skipped",
    "domain_reconciliation_unexplained_bits": 0,
    "domain_reconciliation_non_live_masked_topup_bits": 0,
    "domain_reconciliation_addr_domain_excluded_bits": 0,
    "domain_reconciliation_failure_report_path": "",
    "use_sampling_space_domain": False,
    "use_sampling_space_domain_rf": False,
    "use_sampling_space_domain_smem": False,
}

analyzer_payload = {
    "status": "skip",
    "status_reason": note,
    "fault_component": component,
    "smem_fault_sites": [],
    "l1d_fault_sites": [],
    "l2_fault_sites": [],
}

for path_str, payload in (
    (summary_json_path, summary_payload),
    (exact_rates_json_path, summary_payload),
    (analyzer_output_json_path, analyzer_payload),
):
    path = Path(path_str)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

Path(summary_txt_path).write_text(
    f"status=skip\ncomponent={component}\nreason={note}\n",
    encoding="utf-8",
)
PY
}

get_l2_size_bits_from_config() {
    local cfg="${1:-${CONFIG_FILE}}"
    local tag_bits="${2:-57}"
    if [[ ! -f "${cfg}" ]]; then
        echo "0"
        return
    fi

    local nset line_sz assoc n_mem n_subparts
    local geom
    geom="$(awk '$1 == "-gpgpu_cache:dl2" {print; exit}' "${cfg}" \
        | sed -nE 's/^[[:space:]]*[^[:space:]]+[[:space:]]+[SN]:([0-9]+):([0-9]+):([0-9]+).*/\1 \2 \3/p')"
    nset="$(echo "${geom}" | awk '{print $1}')"
    line_sz="$(echo "${geom}" | awk '{print $2}')"
    assoc="$(echo "${geom}" | awk '{print $3}')"
    n_mem="$(awk '$1 == "-gpgpu_n_mem" {print $2; exit}' "${cfg}")"
    n_subparts="$(awk '$1 == "-gpgpu_n_sub_partition_per_mchannel" {print $2; exit}' "${cfg}")"

    if ! [[ "${nset}" =~ ^[0-9]+$ && "${line_sz}" =~ ^[0-9]+$ && "${assoc}" =~ ^[0-9]+$ ]]; then
        echo "0"
        return
    fi
    if ! [[ "${tag_bits}" =~ ^[0-9]+$ ]] || [[ "${tag_bits}" -lt 0 ]]; then
        echo "0"
        return
    fi
    if ! [[ "${n_mem}" =~ ^[0-9]+$ ]] || [[ "${n_mem}" -le 0 ]]; then
        n_mem=1
    fi
    if ! [[ "${n_subparts}" =~ ^[0-9]+$ ]] || [[ "${n_subparts}" -le 0 ]]; then
        n_subparts=1
    fi

    local per_line_bits per_bank_bits total_bits
    per_line_bits=$(( line_sz * 8 + tag_bits ))
    per_bank_bits=$(( nset * assoc * per_line_bits ))
    total_bits=$(( per_bank_bits * n_mem * n_subparts ))
    if (( total_bits <= 0 )); then
        echo "0"
        return
    fi
    echo "${total_bits}"
}

build_project_if_needed() {
    local build_jobs default_build_jobs
    if [[ "${DO_BUILD}" -ne 1 ]]; then
        echo "=== Build skipped ==="
        return
    fi
    default_build_jobs="$(nproc)"
    if [[ -z "${BUILD_JOBS:-}" ]]; then
        build_jobs="${default_build_jobs}"
        if (( build_jobs > 8 )); then
            build_jobs=8
        fi
    else
        build_jobs="${BUILD_JOBS}"
    fi
    if ! [[ "${build_jobs}" =~ ^[0-9]+$ ]] || (( build_jobs <= 0 )); then
        echo "=== Error: BUILD_JOBS must be a positive integer (got ${build_jobs}) ===" >&2
        exit 1
    fi
    echo "=== Start compiling ==="
    echo "=== Using BUILD_JOBS=${build_jobs} ==="
    make clean >/dev/null 2>&1 || true
    if make -j"${build_jobs}" > build.log 2>&1; then
        echo "=== Make success ==="
    else
        echo "=== Build failed, showing errors ==="
        grep -i "error" build.log || true
        exit 1
    fi
}

resolve_cuda_install_path() {
    # Keep user-provided CUDA_INSTALL_PATH when valid.
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

    local c
    for c in "${candidates[@]}"; do
        [[ -d "${c}" ]] || continue
        if [[ -x "${c}/bin/nvcc" ]]; then
            export CUDA_INSTALL_PATH="${c}"
            return 0
        fi
    done
    return 1
}

setup_gpgpusim_environment() {
    if ! resolve_cuda_install_path; then
        echo "=== Error: could not find a valid CUDA toolkit path with nvcc. Set CUDA_INSTALL_PATH explicitly. ===" >&2
        return 1
    fi

    set +u
    source setup_environment || true
    set -u

    if [[ "${DISABLE_GPGPUSIM_POWER_MODEL:-0}" == "1" ]]; then
        unset GPGPUSIM_POWER_MODEL || true
    fi

    if [[ "${GPGPUSIM_SETUP_ENVIRONMENT_WAS_RUN:-}" != "1" ]]; then
        echo "=== Error: setup_environment did not complete successfully. CUDA_INSTALL_PATH=${CUDA_INSTALL_PATH:-<unset>} ===" >&2
        return 1
    fi
}

native_cuda_ld_library_path() {
    local -a paths=()
    if [[ -n "${CUDA_INSTALL_PATH:-}" && -d "${CUDA_INSTALL_PATH}/lib64" ]]; then
        paths+=("${CUDA_INSTALL_PATH}/lib64")
    fi
    if [[ -n "${CUDA_INSTALL_PATH:-}" && -d "${CUDA_INSTALL_PATH}/targets/x86_64-linux/lib" ]]; then
        paths+=("${CUDA_INSTALL_PATH}/targets/x86_64-linux/lib")
    fi
    local joined=""
    local path_entry
    for path_entry in "${paths[@]}"; do
        if [[ -z "${joined}" ]]; then
            joined="${path_entry}"
        else
            joined="${joined}:${path_entry}"
        fi
    done
    echo "${joined}"
}

run_with_native_cuda_env() {
    local native_ld
    native_ld="$(native_cuda_ld_library_path)"
    if [[ -n "${native_ld}" ]]; then
        env LD_LIBRARY_PATH="${native_ld}" "$@"
    else
        env -u LD_LIBRARY_PATH "$@"
    fi
}

generate_results_if_needed() {
    if [[ "${DO_RESULT_GEN}" -ne 1 ]]; then
        echo "=== Result generation skipped ==="
        return
    fi

    local app_dir="${TEST_APPS_ROOT}/${TEST_APP_NAME}"
    local size_list_file="${app_dir}/size_list.txt"
    if [[ ! -f "${size_list_file}" ]]; then
        echo "=== Error: size_list missing: ${size_list_file} ===" >&2
        exit 1
    fi

    local result_dir
    result_dir="${app_dir}/result"
    if [[ "${FRESH_RUN}" == "1" ]]; then
        echo "=== Fresh-run mode: regenerating application inputs from scratch ==="
    elif result_generation_outputs_current "${app_dir}" "${size_list_file}" "${result_dir}"; then
        echo "=== Result generation skipped: existing outputs are up to date ==="
        return 0
    fi

    echo "=== Start result generation for ${TEST_APP_NAME} ==="
    # Result generation must run with fault injection fully disabled.
    # Otherwise stale config values (for example from prior FI runs) can
    # corrupt the golden reference outputs and break later golden checks.
    update_config_line "-profile" "0"
    update_config_line "-components_to_flip" "0"
    update_config_line "-total_cycle_rand" "-1"
    update_config_line "-exact_trace" "0"
    update_config_line "-regfile_trace" "0"
    # Some test apps do not commit a pre-created result/ directory.
    # Create it here so result generation does not depend on repo layout.
    local staging_dir backup_dir
    local idx=0
    local rc=0
    local generated_any=0
    result_dir="${app_dir}/result"
    mkdir -p "${result_dir}"
    staging_dir="$(mktemp -d "${app_dir}/result.staging.XXXXXX")"
    backup_dir="$(mktemp -d "${app_dir}/result.backup.XXXXXX")"
    if dir_has_entries "${result_dir}"; then
        cp -a "${result_dir}/." "${backup_dir}/"
    fi

    while IFS= read -r line || [[ -n "${line}" ]]; do
        for cu_file in "${app_dir}/result_gen/${TEST_APP_NAME}_"*.cu; do
            [[ -f "${cu_file}" ]] || continue
            local filename x_val
            filename="$(basename "${cu_file}")"
            x_val="$(echo "${filename}" | sed -n "s/^${TEST_APP_NAME}_\([0-9]\+\)\.cu$/\1/p")"
            [[ -n "${x_val}" ]] || continue

            cp "${cu_file}" "${cu_file}.bak"
            if run_with_native_cuda_env nvcc "${cu_file}" -o "./gen" -g -lcudart -arch="${GPU_ARCH}" -arch="${GPU_ARCH}"; then
                # Execute generated CUDA input producers under the current
                # GPGPU-Sim runtime environment.  Forcing the native CUDA
                # toolkit libraries here requires a real host NVIDIA driver,
                # while the public run_experiment flow is expected to work in
                # simulator-only containers.
                if ./gen ${line} > "${staging_dir}/${idx}-${x_val}.txt"; then
                    :
                else
                    rc=$?
                fi
            else
                rc=$?
            fi

            local tmpfile gpgpu_lines start_line end_line
            if [[ "${rc}" -eq 0 ]]; then
                tmpfile="${staging_dir}/${idx}-${x_val}.txt.tmp"
                mapfile -t gpgpu_lines < <(grep -n "GPGPU-Sim" "${staging_dir}/${idx}-${x_val}.txt" | cut -d: -f1)
                if (( ${#gpgpu_lines[@]} >= 2 )); then
                    start_line=$(( gpgpu_lines[${#gpgpu_lines[@]}-2] + 1 ))
                    end_line=$(( gpgpu_lines[${#gpgpu_lines[@]}-1] - 1 ))
                    if (( start_line <= end_line )); then
                        sed -n "${start_line},${end_line}p" "${staging_dir}/${idx}-${x_val}.txt" > "${tmpfile}"
                        mv "${tmpfile}" "${staging_dir}/${idx}-${x_val}.txt"
                    else
                        : > "${staging_dir}/${idx}-${x_val}.txt"
                    fi
                fi
                generated_any=1
            fi

            rm -f ./gen "./gen.1.${GPU_ARCH}.ptxas"
            mv "${cu_file}.bak" "${cu_file}"
            rm -f "${TEST_APP_NAME}.cu" "${TEST_APP_NAME}.ptx"
            if [[ "${rc}" -ne 0 ]]; then
                break 2
            fi
        done
        idx=$((idx + 1))
    done < "${size_list_file}"

    if [[ "${rc}" -eq 0 && "${generated_any}" -eq 0 ]]; then
        rc=1
        echo "=== Error: result generation produced no outputs for ${TEST_APP_NAME} ===" >&2
    fi
    if [[ "${rc}" -ne 0 ]]; then
        replace_dir_contents "${backup_dir}" "${result_dir}"
        rm -rf "${staging_dir}" "${backup_dir}"
        if dir_has_entries "${result_dir}"; then
            echo "=== Error: result generation failed for ${TEST_APP_NAME}; restored previous results ===" >&2
        else
            echo "=== Error: result generation failed for ${TEST_APP_NAME}; no previous results were available ===" >&2
        fi
        return "${rc}"
    fi

    replace_dir_contents "${staging_dir}" "${result_dir}"
    rm -rf "${staging_dir}" "${backup_dir}"
    echo "=== Result generation finished ==="
}

result_generation_outputs_current() {
    if (( $# != 3 )); then
        return 1
    fi
    local app_dir="$1"
    local size_list_file="$2"
    local result_dir="$3"
    local -a result_gen_files=()
    local -a size_lines=()
    local newest_prereq=0
    local prereq_mtime=0
    local idx=0

    [[ -d "${result_dir}" ]] || return 1
    mapfile -t result_gen_files < <(find "${app_dir}/result_gen" -maxdepth 1 -type f -name "${TEST_APP_NAME}_*.cu" | sort)
    (( ${#result_gen_files[@]} > 0 )) || return 1
    mapfile -t size_lines < "${size_list_file}"
    (( ${#size_lines[@]} > 0 )) || return 1

    newest_prereq="$(stat -c %Y "${size_list_file}" 2>/dev/null || echo 0)"
    for cu_file in "${result_gen_files[@]}"; do
        prereq_mtime="$(stat -c %Y "${cu_file}" 2>/dev/null || echo 0)"
        if (( prereq_mtime > newest_prereq )); then
            newest_prereq="${prereq_mtime}"
        fi
    done

    for idx in "${!size_lines[@]}"; do
        local cu_file filename x_val out_path out_mtime
        for cu_file in "${result_gen_files[@]}"; do
            filename="$(basename "${cu_file}")"
            x_val="$(echo "${filename}" | sed -n "s/^${TEST_APP_NAME}_\\([0-9]\\+\\)\\.cu$/\\1/p")"
            [[ -n "${x_val}" ]] || return 1
            out_path="${result_dir}/${idx}-${x_val}.txt"
            [[ -f "${out_path}" ]] || return 1
            out_mtime="$(stat -c %Y "${out_path}" 2>/dev/null || echo 0)"
            if (( out_mtime < newest_prereq )); then
                return 1
            fi
        done
    done
    return 0
}

select_result_file() {
    local app_dir="${TEST_APPS_ROOT}/${TEST_APP_NAME}"
    local result_dir="${app_dir}/result"
    if [[ ! -d "${result_dir}" ]]; then
        echo "=== Error: result dir missing: ${result_dir} ===" >&2
        exit 1
    fi

    if [[ -n "${RESULT_BASENAME}" ]]; then
        local candidate="${RESULT_BASENAME}"
        local requested="${candidate}"
        local alias_candidate=""

        if [[ "${candidate}" != *.txt ]]; then
            candidate="${candidate}.txt"
        fi

        # Backward-friendly alias: RESULT_BASENAME=valN -> N-0.txt
        if [[ "${requested}" =~ ^val([0-9]+)$ || "${requested}" =~ ^val([0-9]+)\.txt$ ]]; then
            alias_candidate="${BASH_REMATCH[1]}-0.txt"
        fi

        if [[ -f "${result_dir}/${candidate}" ]]; then
            CURRENT_RESULT_FILE="${result_dir}/${candidate}"
            return
        fi
        if [[ -n "${alias_candidate}" && -f "${result_dir}/${alias_candidate}" ]]; then
            CURRENT_RESULT_FILE="${result_dir}/${alias_candidate}"
            echo "=== Warning: RESULT_BASENAME=${RESULT_BASENAME} mapped to ${alias_candidate} ==="
            return
        fi

        # If there is exactly one candidate, use it instead of failing early.
        local -a available=()
        mapfile -t available < <(find "${result_dir}" -maxdepth 1 -type f -name '*.txt' | sort)
        if (( ${#available[@]} == 1 )); then
            CURRENT_RESULT_FILE="${available[0]}"
            echo "=== Warning: requested result '${RESULT_BASENAME}' not found; using only available file: $(basename "${CURRENT_RESULT_FILE}") ==="
            return
        fi

        echo "=== Error: requested result file not found: ${result_dir}/${candidate} ===" >&2
        if [[ -n "${alias_candidate}" ]]; then
            echo "=== Tried alias: ${result_dir}/${alias_candidate} ===" >&2
        fi
        if (( ${#available[@]} > 0 )); then
            echo "=== Available result files under ${result_dir}: ===" >&2
            printf '  - %s\n' "${available[@]##*/}" >&2
        fi
        exit 1
        return
    fi

    CURRENT_RESULT_FILE="$(find "${result_dir}" -maxdepth 1 -type f -name '*.txt' | sort | head -n1 || true)"
    if [[ -z "${CURRENT_RESULT_FILE}" ]]; then
        echo "=== Error: no result files found under ${result_dir} ===" >&2
        exit 1
    fi
}

prepare_case_files() {
    select_result_file

    local filename a b_with_ext b size_list_file
    filename="$(basename "${CURRENT_RESULT_FILE}")"
    a="$(echo "${filename}" | cut -d'-' -f1)"
    b_with_ext="$(echo "${filename}" | cut -d'-' -f2)"
    b="$(echo "${b_with_ext}" | cut -d'.' -f1)"
    CURRENT_TEST_ID="${a}-${b}"

    CURRENT_CU_FILE="${TEST_APPS_ROOT}/${TEST_APP_NAME}/inject_app/${TEST_APP_NAME}_${b}.cu"
    if [[ ! -f "${CURRENT_CU_FILE}" ]]; then
        echo "=== Error: inject source not found: ${CURRENT_CU_FILE} ===" >&2
        exit 1
    fi

    size_list_file="${TEST_APPS_ROOT}/${TEST_APP_NAME}/size_list.txt"
    CURRENT_SIZE_LINE="$(awk "NR==$((a+1))" "${size_list_file}")"
    if [[ -z "${CURRENT_SIZE_LINE}" ]]; then
        echo "=== Error: unable to read input args from ${size_list_file} line $((a+1)) ===" >&2
        exit 1
    fi
    read -r -a CURRENT_SIZE_ARGS <<< "${CURRENT_SIZE_LINE}"

    CURRENT_RUN_DIR="${EXACT_WORK_ROOT}/${TEST_APP_NAME}/${CURRENT_TEST_ID}"
    if [[ "${FRESH_RUN}" == "1" && -d "${CURRENT_RUN_DIR}" ]]; then
        local preserved_timing_log=""
        local timing_log_path=""
        timing_log_path="$(resolve_timing_log_path)"
        if [[ -n "${timing_log_path}" ]]; then
            preserved_timing_log="$(mktemp)"
            if [[ -f "${timing_log_path}" ]]; then
                cp "${timing_log_path}" "${preserved_timing_log}"
            fi
        fi
        rm -rf "${CURRENT_RUN_DIR}"
        mkdir -p "${CURRENT_RUN_DIR}"
        if [[ -n "${preserved_timing_log}" ]]; then
            mv -f "${preserved_timing_log}" "${timing_log_path}"
        fi
    else
        mkdir -p "${CURRENT_RUN_DIR}"
    fi
    CURRENT_REGISTER_DOMAIN_FILE="$(resolve_current_register_domain_file)"
    CURRENT_APP_USES_SHARED_MEMORY=""
        if [[ -z "${RESULT_DIR:-}" ]]; then
        RESULT_DIR="${CURRENT_RUN_DIR}"
    fi


    cp "${CURRENT_RESULT_FILE}" ./result.txt
    if [[ "${FRESH_RUN}" != "1" && "${DO_BUILD}" -ne 1 ]] && [[ -x "./${TEST_APP_NAME}" ]] && \
       [[ -f "${CURRENT_REGISTER_DOMAIN_FILE}" && -s "${CURRENT_REGISTER_DOMAIN_FILE}" ]]; then
        echo "=== Reusing existing ${TEST_APP_NAME} binary/register list from ${CURRENT_REGISTER_DOMAIN_FILE} (DO_BUILD=0) ==="
        ensure_current_register_domain_file
    elif [[ "${DO_BUILD}" -ne 1 ]] && [[ -x "./${TEST_APP_NAME}" ]] && regenerate_current_register_domain_from_ptx; then
        echo "=== Reusing existing ${TEST_APP_NAME} binary/PTX and regenerating app-specific register list (DO_BUILD=0) ==="
    else
        cp "${CURRENT_CU_FILE}" "./${TEST_APP_NAME}.cu"
        run_with_native_cuda_env nvcc "./${TEST_APP_NAME}.cu" -o "./${TEST_APP_NAME}" -g -lcudart -arch="${GPU_ARCH}"
        run_with_native_cuda_env nvcc -arch="${GPU_ARCH}" -ptx -g -lineinfo "./${TEST_APP_NAME}.cu" -o "./${TEST_APP_NAME}.ptx"
        python3 extract_registers.py "${TEST_APP_NAME}"
        persist_current_register_domain_file "register_used.txt"
    fi
}

run_golden_and_collect() {
    if [[ "${FRESH_RUN}" != "1" && "${DO_BUILD}" -ne 1 && "${DO_RESULT_GEN}" -ne 1 ]]; then
        local reused_cycles=""
        if [[ -f "${CURRENT_RUN_DIR}/golden.log" && -f "${CURRENT_RUN_DIR}/regfile_trace.bin" ]]; then
            reused_cycles="$(grep -aE "^gpu_tot_sim_cycle[[:space:]]*=[[:space:]]*[0-9]+" "${CURRENT_RUN_DIR}/golden.log" | tail -n1 | sed -E 's/.*=[[:space:]]*([0-9]+).*/\1/')"
            if [[ -z "${reused_cycles}" ]]; then
                reused_cycles="$(grep -aE "^gpu_sim_cycle[[:space:]]*=[[:space:]]*[0-9]+" "${CURRENT_RUN_DIR}/golden.log" | tail -n1 | sed -E 's/.*=[[:space:]]*([0-9]+).*/\1/')"
            fi
            if [[ -z "${reused_cycles}" && -f "${CURRENT_RUN_DIR}/cycles_all.txt" ]]; then
                reused_cycles="$(wc -l < "${CURRENT_RUN_DIR}/cycles_all.txt" | tr -d '[:space:]')"
            fi
            if [[ -n "${reused_cycles}" && "${reused_cycles}" =~ ^[0-9]+$ && "${reused_cycles}" -gt 0 ]]; then
                CURRENT_GOLDEN_CYCLES="${reused_cycles}"
                if [[ ! -f "${CURRENT_RUN_DIR}/cycles_all.txt" ]]; then
                    seq 0 "$((CURRENT_GOLDEN_CYCLES - 1))" > "${CURRENT_RUN_DIR}/cycles_all.txt"
                fi
                if [[ ! -f "${CURRENT_RUN_DIR}/output_spec.json" ]]; then
                    python3 script/common/parse_outputs.py "${CURRENT_RUN_DIR}/golden.log" -o "${CURRENT_RUN_DIR}/output_spec.json"
                fi
                if [[ -f "${CURRENT_RUN_DIR}/output_spec.json" ]]; then
                    echo "=== Reusing existing golden/profile artifacts from ${CURRENT_RUN_DIR} (DO_BUILD=0, DO_RESULT_GEN=0) ==="
                    return 0
                fi
            fi
        fi
    fi

    echo "=== Running golden profiling execution (no injection) ==="
    update_config_line "-profile" "3"
    update_config_line "-components_to_flip" "0"
    update_config_line "-total_cycle_rand" "-1"
    update_config_line "-exact_trace" "0"
    update_config_line "-regfile_trace" "1"
    update_config_line "-regfile_trace_file" "${CURRENT_RUN_DIR}/regfile_trace.bin"
    update_config_line "-regfile_trace_buffer_kb" "4096"

    timeout "${TIMEOUT_VAL}" "./${TEST_APP_NAME}" "${CURRENT_SIZE_ARGS[@]}" > "${CURRENT_RUN_DIR}/golden.log" 2>&1

    if ! grep -a -iq "${SUCCESS_MSG}" "${CURRENT_RUN_DIR}/golden.log"; then
        echo "=== Error: golden run did not report success ===" >&2
        return 1
    fi

    CURRENT_GOLDEN_CYCLES="$(grep -aE "^gpu_tot_sim_cycle[[:space:]]*=[[:space:]]*[0-9]+" "${CURRENT_RUN_DIR}/golden.log" | tail -n1 | sed -E 's/.*=[[:space:]]*([0-9]+).*/\1/')"
    if [[ -z "${CURRENT_GOLDEN_CYCLES}" ]]; then
        CURRENT_GOLDEN_CYCLES="$(grep -aE "^gpu_sim_cycle[[:space:]]*=[[:space:]]*[0-9]+" "${CURRENT_RUN_DIR}/golden.log" | tail -n1 | sed -E 's/.*=[[:space:]]*([0-9]+).*/\1/')"
    fi
    if [[ -z "${CURRENT_GOLDEN_CYCLES}" || ! "${CURRENT_GOLDEN_CYCLES}" =~ ^[0-9]+$ ]]; then
        local app_info_cycles=""
        app_info_cycles="$(get_app_info_var "CYCLES")"
        if [[ -n "${app_info_cycles}" && "${app_info_cycles}" =~ ^[0-9]+$ && "${app_info_cycles}" -gt 0 ]]; then
            CURRENT_GOLDEN_CYCLES="${app_info_cycles}"
            echo "=== Warning: golden log did not contain a simulator cycle count; using app_info CYCLES=${CURRENT_GOLDEN_CYCLES} ===" >&2
        fi
    fi
    if [[ -z "${CURRENT_GOLDEN_CYCLES}" || ! "${CURRENT_GOLDEN_CYCLES}" =~ ^[0-9]+$ ]]; then
        echo "=== Error: unable to parse golden cycle count (value='${CURRENT_GOLDEN_CYCLES:-<empty>}') ===" >&2
        return 1
    fi
    if [[ "${CURRENT_GOLDEN_CYCLES}" -le 0 ]]; then
        echo "=== Error: invalid golden cycle count: ${CURRENT_GOLDEN_CYCLES} ===" >&2
        return 1
    fi

    seq 0 "$((CURRENT_GOLDEN_CYCLES - 1))" > "${CURRENT_RUN_DIR}/cycles_all.txt"
    python3 script/common/parse_outputs.py "${CURRENT_RUN_DIR}/golden.log" -o "${CURRENT_RUN_DIR}/output_spec.json"

    if [[ ! -f "${CURRENT_RUN_DIR}/regfile_trace.bin" ]]; then
        echo "=== Error: regfile trace missing: ${CURRENT_RUN_DIR}/regfile_trace.bin ===" >&2
        return 1
    fi
}

run_profile2_mean_active_threads() {
    if [[ "${EXACT_STORAGE_ONLY_OUTPUT:-0}" == "1" ]]; then
        CURRENT_MEAN_ACTIVE_THREADS="1"
        cat > "${CURRENT_RUN_DIR}/profile2.log" <<EOF
profile=2 skipped in storage-only canonical exact path
Mean active threads = ${CURRENT_MEAN_ACTIVE_THREADS}
EOF
        echo "=== Skipping profile=2 active-thread estimate in storage-only canonical exact mode ==="
        return 0
    fi

    if [[ "${FRESH_RUN}" != "1" && "${DO_BUILD}" -ne 1 && "${DO_RESULT_GEN}" -ne 1 && -f "${CURRENT_RUN_DIR}/profile2.log" ]]; then
        CURRENT_MEAN_ACTIVE_THREADS="$(grep -E "Mean active threads = [0-9]+" "${CURRENT_RUN_DIR}/profile2.log" | tail -n1 | sed -E 's/.*= ([0-9]+).*/\1/')"
        if [[ -z "${CURRENT_MEAN_ACTIVE_THREADS}" ]]; then
            CURRENT_MEAN_ACTIVE_THREADS="1"
        fi
        echo "=== Reusing existing profile=2 active-thread estimate from ${CURRENT_RUN_DIR}/profile2.log ==="
        return 0
    fi

    echo "=== Running profile=2 to estimate active thread count ==="
    local saved_cycles_tmp=""
    local had_cycles_txt="0"
    if [[ -f "./cycles.txt" ]]; then
        had_cycles_txt="1"
        saved_cycles_tmp="$(mktemp)"
        cp "./cycles.txt" "${saved_cycles_tmp}"
    fi
    cp "${CURRENT_RUN_DIR}/cycles_all.txt" ./cycles.txt

    update_config_line "-profile" "2"
    update_config_line "-components_to_flip" "0"
    update_config_line "-last_cycle" "${CURRENT_GOLDEN_CYCLES}"
    update_config_line "-total_cycle_rand" "-1"
    update_config_line "-regfile_trace" "0"
    update_config_line "-exact_trace" "0"

    timeout "${TIMEOUT_VAL}" "./${TEST_APP_NAME}" "${CURRENT_SIZE_ARGS[@]}" > "${CURRENT_RUN_DIR}/profile2.log" 2>&1

    CURRENT_MEAN_ACTIVE_THREADS="$(grep -E "Mean active threads = [0-9]+" "${CURRENT_RUN_DIR}/profile2.log" | tail -n1 | sed -E 's/.*= ([0-9]+).*/\1/')"
    if [[ -z "${CURRENT_MEAN_ACTIVE_THREADS}" ]]; then
        CURRENT_MEAN_ACTIVE_THREADS="1"
    fi

    if [[ "${had_cycles_txt}" == "1" && -n "${saved_cycles_tmp}" && -f "${saved_cycles_tmp}" ]]; then
        mv -f "${saved_cycles_tmp}" "./cycles.txt"
    else
        rm -f "./cycles.txt"
    fi
}

prepare_fi_sampling_space_snapshot() {
    local app_info_file campaign_per_warp config_per_warp
    local cycles_source cycles_source_name cycles_domain_path
    local app_thread app_warp app_block app_dtype app_smem app_shaders app_cache_tag app_l1d_bits app_l2_bits app_bit_flip app_per_warp app_l1d_line app_l2_line
    local campaign_thread campaign_warp campaign_block campaign_dtype campaign_smem campaign_shaders campaign_cache_tag campaign_l1d_bits campaign_l2_bits campaign_bit_flip campaign_l1d_line campaign_l2_line
    local golden_thread golden_warp golden_block golden_dtype golden_smem
    local resolved_value resolved_source
    local thread_rand_max warp_rand_max block_rand_max datatype_bits smem_size_bits
    local cache_tag_bits l1d_tag_bits l2_tag_bits l1d_size_bits l2_size_bits
    local l1d_nset l1d_assoc l2_nset l2_assoc
    local l1d_line_size_bytes l2_line_size_bytes l2_global_prefill l1d_shaders l1d_write_allocate
    local l1d_shaders_mode l1d_shaders_mode_lc config_shader_count
    local inject_bit_flip_count per_warp
    local source_thread source_warp source_block source_dtype source_smem source_shaders
    local source_cache_tag source_l1d_bits source_l2_bits source_inject_bit_flip source_per_warp source_cycles source_l1d_line source_l2_line
    local source_active_sm source_l1d_shader_count normalized_l1d_shaders normalized_campaign_shaders

    app_info_file="${TEST_APPS_ROOT}/${TEST_APP_NAME}/app_info.txt"
    app_thread="$(get_app_info_var "THREAD_RAND_MAX")"
    app_warp="$(get_app_info_var "WARP_RAND_MAX")"
    app_block="$(get_app_info_var "BLOCK_RAND_MAX")"
    app_dtype="$(get_app_info_var "DATATYPE_SIZE")"
    app_smem="$(get_app_info_var "SMEM_SIZE_BITS")"
    app_shaders="$(normalize_shader_domain_spec "$(get_app_info_var "SHADER_USED")")"
    app_cache_tag="$(get_app_info_var "CACHE_TAG_ARRAY_BITS")"
    app_l1d_bits="$(get_app_info_var "L1D_SIZE_BITS")"
    app_l2_bits="$(get_app_info_var "L2_SIZE_BITS")"
    app_bit_flip="$(get_app_info_var "INJECT_BIT_FLIP_COUNT")"
    app_per_warp="$(get_app_info_var "PER_WARP")"
    app_l1d_line="$(get_app_info_var "L1D_LINE_SIZE_BYTES")"
    app_l2_line="$(get_app_info_var "L2_LINE_SIZE_BYTES")"

    campaign_thread="$(get_campaign_var_from_script "THREAD_RAND_MAX")"
    campaign_warp="$(get_campaign_var_from_script "WARP_RAND_MAX")"
    campaign_block="$(get_campaign_var_from_script "BLOCK_RAND_MAX")"
    campaign_dtype="$(get_campaign_var_from_script "DATATYPE_SIZE")"
    campaign_smem="$(get_campaign_var_from_script "SMEM_SIZE_BITS")"
    campaign_shaders="$(normalize_shader_domain_spec "$(get_campaign_var_from_script "SHADER_USED")")"
    campaign_cache_tag="$(get_campaign_var_from_script "CACHE_TAG_ARRAY_BITS")"
    campaign_l1d_bits="$(get_campaign_var_from_script "L1D_SIZE_BITS")"
    campaign_l2_bits="$(get_campaign_var_from_script "L2_SIZE_BITS")"
    campaign_bit_flip="$(get_campaign_var_from_script "INJECT_BIT_FLIP_COUNT")"
    campaign_per_warp="$(get_campaign_var_from_script "per_warp")"
    campaign_l1d_line="$(get_campaign_var_from_script "L1D_LINE_SIZE_BYTES")"
    campaign_l2_line="$(get_campaign_var_from_script "L2_LINE_SIZE_BYTES")"
    config_per_warp="$(get_config_numeric_opt "-per_warp")"

    load_profile_metrics_from_tmp

    read -r golden_thread golden_warp golden_block <<< "$(get_thread_warp_block_max_from_profile_log "${CURRENT_RUN_DIR}/golden.log")"
    golden_dtype="$(get_datatype_bits_from_log "${CURRENT_RUN_DIR}/golden.log")"
    golden_smem="$(get_smem_size_bits_from_log "${CURRENT_RUN_DIR}/golden.log")"

    if [[ -n "${EXACT_CYCLES_FILE_OVERRIDE}" ]]; then
        if [[ ! -f "${EXACT_CYCLES_FILE_OVERRIDE}" || ! -s "${EXACT_CYCLES_FILE_OVERRIDE}" ]]; then
            echo "=== Error: EXACT_CYCLES_FILE_OVERRIDE is not a readable non-empty file: ${EXACT_CYCLES_FILE_OVERRIDE} ===" >&2
            return 1
        fi
        cycles_source="${EXACT_CYCLES_FILE_OVERRIDE}"
        cycles_source_name="exact_cycles_override"
    elif [[ -f "./cycles.txt" && -s "./cycles.txt" ]] \
        && cycles_file_matches_current_run "./cycles.txt" "${CURRENT_GOLDEN_CYCLES}" \
        && cycles_file_embeds_active_thread_ids "./cycles.txt"; then
        cycles_source="./cycles.txt"
        cycles_source_name="workspace_cycles_txt"
        echo "=== Info: using workspace cycles.txt for exact FI-space snapshot to mirror campaign_exec cycle sampling ==="
    elif [[ -f "./cycles.txt" && -s "./cycles.txt" ]] \
        && cycles_file_matches_current_run "./cycles.txt" "${CURRENT_GOLDEN_CYCLES}"; then
        echo "=== Info: workspace cycles.txt matches current run but lacks active_thread_ids; falling back to exact-run cycle domain ==="
        cycles_source="${CURRENT_RUN_DIR}/cycles_all.txt"
        cycles_source_name="cycles_all_exact_run"
    elif [[ -f "./cycles.txt" && -s "./cycles.txt" ]]; then
        echo "=== Info: workspace cycles.txt exists but is incompatible with current run (golden_cycles=${CURRENT_GOLDEN_CYCLES}); falling back to exact-run cycle domain ==="
        cycles_source="${CURRENT_RUN_DIR}/cycles_all.txt"
        cycles_source_name="cycles_all_exact_run"
    else
        cycles_source="${CURRENT_RUN_DIR}/cycles_all.txt"
        cycles_source_name="cycles_all_exact_run"
        echo "=== Info: workspace cycles.txt not present; falling back to cycles_all exact run domain ==="
    fi
    cycles_domain_path="${CURRENT_RUN_DIR}/cycles_fi_domain.txt"
    cp "${cycles_source}" "${cycles_domain_path}"
    CURRENT_CYCLES_DOMAIN_FILE="${cycles_domain_path}"
    source_cycles="${cycles_source_name}"

    # Runtime-derived FI-space metrics should prefer the current observed run.
    # campaign_exec.sh often carries bootstrapping defaults that are valid shell
    # values but not representative of this benchmark's actual execution.
    IFS=$'\t' read -r resolved_value resolved_source <<< "$(resolve_first_valid_source_value \
        is_pos_int \
        "golden" "${golden_thread}" \
        "profile" "${PROFILE_THREAD_RAND_MAX}" \
        "app_info" "${app_thread}" \
        "campaign" "${campaign_thread}")"
    if [[ -n "${resolved_value}" ]]; then
        thread_rand_max="${resolved_value}"
        source_thread="${resolved_source}"
    else
        thread_rand_max="512"
        source_thread="default"
    fi

    IFS=$'\t' read -r resolved_value resolved_source <<< "$(resolve_first_valid_source_value \
        is_pos_int \
        "golden" "${golden_warp}" \
        "profile" "${PROFILE_WARP_RAND_MAX}" \
        "app_info" "${app_warp}" \
        "campaign" "${campaign_warp}")"
    if [[ -n "${resolved_value}" ]]; then
        warp_rand_max="${resolved_value}"
        source_warp="${resolved_source}"
    else
        warp_rand_max="16"
        source_warp="default"
    fi

    IFS=$'\t' read -r resolved_value resolved_source <<< "$(resolve_first_valid_source_value \
        is_pos_int \
        "golden" "${golden_block}" \
        "profile" "${PROFILE_BLOCK_RAND_MAX}" \
        "app_info" "${app_block}" \
        "campaign" "${campaign_block}")"
    if [[ -n "${resolved_value}" ]]; then
        block_rand_max="${resolved_value}"
        source_block="${resolved_source}"
    else
        block_rand_max="2"
        source_block="default"
    fi

    # RF campaign bit sampling is parameterized by the benchmark-level
    # DATATYPE_SIZE snapshot (app_info/campaign), not by whatever width happens
    # to be recoverable from the current exact golden/profile logs.
    IFS=$'\t' read -r resolved_value resolved_source <<< "$(resolve_first_valid_source_value \
        is_pos_int \
        "app_info" "${app_dtype}" \
        "campaign" "${campaign_dtype}" \
        "golden" "${golden_dtype}" \
        "profile" "${PROFILE_DATATYPE_BITS}")"
    if [[ -n "${resolved_value}" ]]; then
        datatype_bits="${resolved_value}"
        source_dtype="${resolved_source}"
    else
        datatype_bits="32"
        source_dtype="default"
    fi

    if [[ "$(resolve_current_app_shared_memory_usage)" == "0" ]]; then
        smem_size_bits="0"
        source_smem="detected_no_shared_use"
    else
        IFS=$'\t' read -r resolved_value resolved_source <<< "$(resolve_first_valid_source_value \
            is_valid_smem_size_bits \
            "golden" "${golden_smem}" \
            "profile" "${PROFILE_SMEM_SIZE_BITS}" \
            "app_info" "${app_smem}" \
            "campaign" "${campaign_smem}")"
        if [[ -n "${resolved_value}" ]]; then
            smem_size_bits="${resolved_value}"
            source_smem="${resolved_source}"
        else
            smem_size_bits="1"
            source_smem="default"
        fi
    fi

    if is_nonneg_int "${campaign_cache_tag}"; then
        cache_tag_bits="${campaign_cache_tag}"
        source_cache_tag="campaign"
    elif is_nonneg_int "${app_cache_tag}"; then
        cache_tag_bits="${app_cache_tag}"
        source_cache_tag="app_info"
    else
        cache_tag_bits="$(get_l1d_tag_bits_from_config "${CONFIG_FILE}" "64")"
        if is_nonneg_int "${cache_tag_bits}"; then
            source_cache_tag="config"
        else
            cache_tag_bits="57"
            source_cache_tag="default"
        fi
    fi
    l1d_tag_bits="${cache_tag_bits}"
    l2_tag_bits="${cache_tag_bits}"

    if is_pos_int "${campaign_l1d_line}"; then
        l1d_line_size_bytes="${campaign_l1d_line}"
        source_l1d_line="campaign"
    elif is_pos_int "${app_l1d_line}"; then
        l1d_line_size_bytes="${app_l1d_line}"
        source_l1d_line="app_info"
    else
        l1d_line_size_bytes="$(get_l1d_line_size_from_config "${CONFIG_FILE}")"
        if ! is_pos_int "${l1d_line_size_bytes}"; then
            l1d_line_size_bytes="128"
            source_l1d_line="default"
        else
            source_l1d_line="config"
        fi
    fi
    if is_pos_int "${campaign_l2_line}"; then
        l2_line_size_bytes="${campaign_l2_line}"
        source_l2_line="campaign"
    elif is_pos_int "${app_l2_line}"; then
        l2_line_size_bytes="${app_l2_line}"
        source_l2_line="app_info"
    else
        l2_line_size_bytes="$(get_l2_line_size_from_config "${CONFIG_FILE}")"
        if ! is_pos_int "${l2_line_size_bytes}"; then
            l2_line_size_bytes="128"
            source_l2_line="default"
        else
            source_l2_line="config"
        fi
    fi

    if is_valid_l1d_size_bits "${campaign_l1d_bits}"; then
        l1d_size_bits="${campaign_l1d_bits}"
        source_l1d_bits="campaign"
    elif is_valid_l1d_size_bits "${app_l1d_bits}"; then
        l1d_size_bits="${app_l1d_bits}"
        source_l1d_bits="app_info"
    else
        l1d_size_bits="$(get_l1d_size_bits_from_config "${CONFIG_FILE}" "${l1d_tag_bits}")"
        if is_valid_l1d_size_bits "${l1d_size_bits}"; then
            source_l1d_bits="config"
        else
            l1d_size_bits="1"
            source_l1d_bits="default"
        fi
    fi

    if is_valid_l2_size_bits "${campaign_l2_bits}"; then
        l2_size_bits="${campaign_l2_bits}"
        source_l2_bits="campaign"
    elif is_valid_l2_size_bits "${app_l2_bits}"; then
        l2_size_bits="${app_l2_bits}"
        source_l2_bits="app_info"
    else
        l2_size_bits="$(get_l2_size_bits_from_config "${CONFIG_FILE}" "${l2_tag_bits}")"
        if is_valid_l2_size_bits "${l2_size_bits}"; then
            source_l2_bits="config"
        else
            l2_size_bits="1"
            source_l2_bits="default"
        fi
    fi

    l1d_shaders_mode="${L1D_SHADERS:-auto}"
    l1d_shaders_mode_lc="${l1d_shaders_mode,,}"
    config_shader_count="$(get_shader_count_from_config "${CONFIG_FILE}")"
    if ! is_nonneg_int "${config_shader_count}"; then
        config_shader_count="0"
    fi
    IFS=$'\t' read -r l1d_shaders source_shaders source_active_sm <<< "$(
        resolve_l1d_sampling_domain \
            "${l1d_shaders_mode_lc}" \
            "${campaign_shaders}" \
            "${app_shaders}" \
            "${config_shader_count}"
    )"
    source_l1d_shader_count="l1d_shaders_len"

    if [[ -z "${l1d_shaders_mode_lc}" || "${l1d_shaders_mode_lc}" == "auto" ]]; then
        if [[ -n "${campaign_shaders}" ]]; then
            normalized_l1d_shaders="$(normalize_shader_domain_spec "${l1d_shaders}")"
            normalized_campaign_shaders="$(normalize_shader_domain_spec "${campaign_shaders}")"
            if [[ "${source_shaders}" == "campaign" && "${normalized_l1d_shaders}" != "${normalized_campaign_shaders}" ]]; then
                echo "=== Error: L1D_SHADERS=auto must match campaign SHADER_USED for FI-equivalent domain ===" >&2
                echo "=== campaign_shaders=${normalized_campaign_shaders} ===" >&2
                echo "=== resolved_l1d_shaders=${normalized_l1d_shaders} (source=${source_shaders}) ===" >&2
                exit 1
            fi
        fi
    fi

    if is_pos_int "${campaign_bit_flip}"; then
        inject_bit_flip_count="${campaign_bit_flip}"
        source_inject_bit_flip="campaign"
    elif is_pos_int "${app_bit_flip}"; then
        inject_bit_flip_count="${app_bit_flip}"
        source_inject_bit_flip="app_info"
    elif is_pos_int "${INJECT_BIT_FLIP_COUNT}"; then
        inject_bit_flip_count="${INJECT_BIT_FLIP_COUNT}"
        source_inject_bit_flip="env"
    else
        inject_bit_flip_count="1"
        source_inject_bit_flip="default"
    fi

    if is_nonneg_int "${campaign_per_warp}"; then
        per_warp="${campaign_per_warp}"
        source_per_warp="campaign"
    elif is_nonneg_int "${app_per_warp}"; then
        per_warp="${app_per_warp}"
        source_per_warp="app_info"
    elif is_nonneg_int "${config_per_warp}"; then
        per_warp="${config_per_warp}"
        source_per_warp="config"
    else
        per_warp="0"
        source_per_warp="default"
    fi

    if [[ "${inject_bit_flip_count}" != "1" ]]; then
        echo "=== Error: exact FI-equivalent mode requires inject_bit_flip_count=1 (resolved ${inject_bit_flip_count}, source=${source_inject_bit_flip}) ===" >&2
        exit 1
    fi
    if [[ "${per_warp}" != "0" ]]; then
        echo "=== Error: exact FI-equivalent mode requires per_warp=0 (resolved ${per_warp}, source=${source_per_warp}) ===" >&2
        exit 1
    fi

    CURRENT_DATATYPE_BITS="${datatype_bits}"
    CURRENT_THREAD_RAND_MAX="${thread_rand_max}"
    CURRENT_BLOCK_RAND_MAX="${block_rand_max}"
    CURRENT_SMEM_SIZE_BITS="${smem_size_bits}"
    CURRENT_L1D_SIZE_BITS="${l1d_size_bits}"
    CURRENT_L1D_TAG_BITS="${l1d_tag_bits}"
    CURRENT_L1D_LINE_SIZE_BYTES="${l1d_line_size_bytes}"
    CURRENT_L1D_SHADERS="${l1d_shaders}"
    l1d_write_allocate="$(get_l1d_write_allocate_from_config "${CONFIG_FILE}")"
    if [[ "${l1d_write_allocate}" != "0" && "${l1d_write_allocate}" != "1" ]]; then
        l1d_write_allocate="0"
    fi
    CURRENT_L1D_WRITE_ALLOCATE="${l1d_write_allocate}"
    l1d_nset="$(get_l1d_nset_from_config "${CONFIG_FILE}")"
    l1d_assoc="$(get_l1d_assoc_from_config "${CONFIG_FILE}")"
    if ! is_pos_int "${l1d_nset}"; then
        l1d_nset="0"
    fi
    if ! is_pos_int "${l1d_assoc}"; then
        l1d_assoc="0"
    fi
    CURRENT_L2_SIZE_BITS="${l2_size_bits}"
    CURRENT_L2_TAG_BITS="${l2_tag_bits}"
    CURRENT_L2_LINE_SIZE_BYTES="${l2_line_size_bytes}"
    l2_nset="$(get_l2_nset_from_config "${CONFIG_FILE}")"
    l2_assoc="$(get_l2_assoc_from_config "${CONFIG_FILE}")"
    if ! is_pos_int "${l2_nset}"; then
        l2_nset="0"
    fi
    if ! is_pos_int "${l2_assoc}"; then
        l2_assoc="0"
    fi
    l2_global_prefill="$(get_l2_global_prefill_from_config "${CONFIG_FILE}")"
    if [[ "${l2_global_prefill}" != "0" && "${l2_global_prefill}" != "1" ]]; then
        l2_global_prefill="1"
    fi
    CURRENT_L2_GLOBAL_PREFILL="${l2_global_prefill}"

    ensure_current_register_domain_file
    CURRENT_FI_SAMPLING_SPACE_JSON="${CURRENT_RUN_DIR}/fi_sampling_space.json"
    if ! python3 - \
        "${CURRENT_FI_SAMPLING_SPACE_JSON}" \
        "${cycles_source}" \
        "${cycles_domain_path}" \
        "${thread_rand_max}" "${warp_rand_max}" "${block_rand_max}" \
        "${datatype_bits}" \
        "${CURRENT_REGISTER_DOMAIN_FILE}" \
        "${smem_size_bits}" \
        "${l1d_size_bits}" "${l2_size_bits}" \
        "${l1d_line_size_bytes}" "${l2_line_size_bytes}" "${l2_global_prefill}" "${l1d_write_allocate}" \
        "${l1d_nset}" "${l1d_assoc}" "${l2_nset}" "${l2_assoc}" \
        "${cache_tag_bits}" \
        "${l1d_shaders}" \
        "${l1d_shaders_mode_lc}" \
        "${inject_bit_flip_count}" \
        "${per_warp}" \
        "${source_cycles}" \
        "${source_thread}" "${source_warp}" "${source_block}" \
        "${source_dtype}" "${source_smem}" \
        "${source_cache_tag}" "${source_l1d_bits}" "${source_l2_bits}" \
        "${source_l1d_line}" "${source_l2_line}" \
        "${source_shaders}" \
        "${source_active_sm}" "${source_l1d_shader_count}" \
        "${source_inject_bit_flip}" "${source_per_warp}" \
        "${app_info_file}" <<'PY'
import json
import sys
from pathlib import Path

(
    out_path,
    cycles_file_raw,
    cycles_domain_path,
    thread_rand_max,
    warp_rand_max,
    block_rand_max,
    datatype_bits,
    register_domain_source,
    smem_size_bits,
    l1d_size_bits,
    l2_size_bits,
    l1d_line_size_bytes,
    l2_line_size_bytes,
    l2_global_prefill,
    l1d_write_allocate,
    l1d_nset,
    l1d_assoc,
    l2_nset,
    l2_assoc,
    cache_tag_bits,
    l1d_shaders,
    l1d_shaders_mode,
    inject_bit_flip_count,
    per_warp,
    source_cycles,
    source_thread,
    source_warp,
    source_block,
    source_dtype,
    source_smem,
    source_cache_tag,
    source_l1d_bits,
    source_l2_bits,
    source_l1d_line,
    source_l2_line,
    source_shaders,
    source_active_sm,
    source_l1d_shader_count,
    source_inject_bit_flip,
    source_per_warp,
    app_info_file,
) = sys.argv[1:]

def parse_shader_list(spec):
    out = []
    seen = set()
    for tok in str(spec).replace(",", " ").replace(":", " ").split():
        try:
            val = int(tok, 0)
        except Exception:
            continue
        if val in seen:
            continue
        seen.add(val)
        out.append(int(val))
    return out


def count_cycles(path):
    if not path.is_file():
        return 0, 0
    try:
        raw = path.read_text(encoding="utf-8")
    except Exception:
        return 0, 0
    text = raw.strip()
    if not text:
        return 0, 0
    # JSON cycles format.
    if text[:1] in ("{", "["):
        try:
            obj = json.loads(text)
            rows = obj.get("cycles", []) if isinstance(obj, dict) else obj
            if isinstance(rows, list):
                total = 0
                uniq = 0
                for row in rows:
                    if isinstance(row, dict):
                        uniq += 1
                        total += int(row.get("multiplicity", 1))
                    elif isinstance(row, list) and row:
                        uniq += 1
                        total += int(row[2]) if len(row) >= 3 else 1
                return max(0, int(total)), max(0, int(uniq))
        except Exception:
            pass
    # Text cycles format (one cycle per line).
    total = 0
    uniq = 0
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        total += 1
        uniq += 1
    return max(0, int(total)), max(0, int(uniq))


register_count = 0
reg_src = Path(register_domain_source)
if reg_src.is_file():
    register_count = sum(1 for ln in reg_src.read_text(encoding="utf-8").splitlines() if ln.strip())
cycle_total, cycle_unique = count_cycles(Path(cycles_domain_path))
l1d_shader_list = parse_shader_list(l1d_shaders)
l1d_shader_count = len(l1d_shader_list)

rf_domain_per_seed_bits = int(register_count) * int(datatype_bits)
rf_domain_total_bits = int(cycle_total) * int(thread_rand_max) * int(rf_domain_per_seed_bits)
smem_rf_domain_per_seed_bits = int(smem_size_bits)
smem_rf_domain_total_bits = int(cycle_total) * int(block_rand_max) * int(smem_rf_domain_per_seed_bits)
l1d_domain_per_seed_bits = int(l1d_size_bits)
l1d_domain_total_bits = int(cycle_total) * int(l1d_shader_count) * int(l1d_domain_per_seed_bits)
l2_domain_per_seed_bits = int(l2_size_bits)
l2_domain_total_bits = int(cycle_total) * int(l2_domain_per_seed_bits)

obj = {
    "cycles_file": str(Path(cycles_domain_path).resolve()),
    "cycles_source_file": str(Path(cycles_file_raw).resolve()),
    "cycle_total_multiplicity": int(cycle_total),
    "cycle_unique_count": int(cycle_unique),
    "thread_rand_max": int(thread_rand_max),
    "warp_rand_max": int(warp_rand_max),
    "block_rand_max": int(block_rand_max),
    "datatype_bits": int(datatype_bits),
    "register_domain_source": str(Path(register_domain_source).resolve()),
    "register_count": int(register_count),
    "smem_size_bits": int(smem_size_bits),
    "l1d_size_bits": int(l1d_size_bits),
    "l2_size_bits": int(l2_size_bits),
    "l1d_line_size_bytes": int(l1d_line_size_bytes),
    "l2_line_size_bytes": int(l2_line_size_bytes),
    "l2_global_prefill": int(l2_global_prefill),
    "l1d_write_allocate": int(l1d_write_allocate),
    "l1d_nset": int(l1d_nset),
    "l1d_assoc": int(l1d_assoc),
    "l2_nset": int(l2_nset),
    "l2_assoc": int(l2_assoc),
    "cache_tag_bits": int(cache_tag_bits),
    "l1d_tag_bits": int(cache_tag_bits),
    "l2_tag_bits": int(cache_tag_bits),
    "l1d_include_tag_bits": 1,
    "l2_include_tag_bits": 1,
    "l1d_shaders": str(l1d_shaders),
    "l1d_shaders_mode": str(l1d_shaders_mode),
    "l1d_shader_count": int(l1d_shader_count),
    "active_sm_count": int(l1d_shader_count),
    "rf_domain_total_bits": int(rf_domain_total_bits),
    "smem_rf_domain_total_bits": int(smem_rf_domain_total_bits),
    "l1d_domain_total_bits": int(l1d_domain_total_bits),
    "l2_domain_total_bits": int(l2_domain_total_bits),
    "inject_bit_flip_count": int(inject_bit_flip_count),
    "per_warp": int(per_warp),
    "component_domains": {
        "rf": {
            "domain_bits_per_seed": int(rf_domain_per_seed_bits),
            "domain_total_bits": int(rf_domain_total_bits),
            "seed_domain_size": int(thread_rand_max),
        },
        "smem_rf": {
            "domain_bits_per_seed": int(smem_rf_domain_per_seed_bits),
            "domain_total_bits": int(smem_rf_domain_total_bits),
            "seed_domain_size": int(block_rand_max),
        },
        "l1d": {
            "domain_bits_per_seed": int(l1d_domain_per_seed_bits),
            "domain_total_bits": int(l1d_domain_total_bits),
            "shader_count": int(l1d_shader_count),
            "shaders": list(l1d_shader_list),
            "include_tag_bits": 1,
            "tag_bits": int(cache_tag_bits),
            "line_size_bytes": int(l1d_line_size_bytes),
            "nset": int(l1d_nset),
            "assoc": int(l1d_assoc),
            "write_allocate": int(l1d_write_allocate),
        },
        "l2": {
            "domain_bits_per_seed": int(l2_domain_per_seed_bits),
            "domain_total_bits": int(l2_domain_total_bits),
            "include_tag_bits": 1,
            "tag_bits": int(cache_tag_bits),
            "line_size_bytes": int(l2_line_size_bytes),
            "nset": int(l2_nset),
            "assoc": int(l2_assoc),
        },
    },
    "source_priority": {
        "cycles_file": str(source_cycles),
        "thread_rand_max": str(source_thread),
        "warp_rand_max": str(source_warp),
        "block_rand_max": str(source_block),
        "datatype_bits": str(source_dtype),
        "smem_size_bits": str(source_smem),
        "cache_tag_bits": str(source_cache_tag),
        "l1d_size_bits": str(source_l1d_bits),
        "l2_size_bits": str(source_l2_bits),
        "l1d_line_size_bytes": str(source_l1d_line),
        "l2_line_size_bytes": str(source_l2_line),
        "l1d_shaders": str(source_shaders),
        "active_sm_count": str(source_active_sm),
        "l1d_shader_count": str(source_l1d_shader_count),
        "inject_bit_flip_count": str(source_inject_bit_flip),
        "per_warp": str(source_per_warp),
    },
    "app_info_file": str(Path(app_info_file).resolve()),
}
Path(out_path).write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
PY
    then
        echo "=== Error: failed to build FI sampling-space snapshot (${CURRENT_FI_SAMPLING_SPACE_JSON}) ===" >&2
        return 1
    fi
    if [[ ! -f "${CURRENT_FI_SAMPLING_SPACE_JSON}" ]]; then
        echo "=== Error: FI sampling-space snapshot missing after generation: ${CURRENT_FI_SAMPLING_SPACE_JSON} ===" >&2
        return 1
    fi

    echo "=== Wrote FI sampling-space snapshot: ${CURRENT_FI_SAMPLING_SPACE_JSON} ==="
}

run_exact_trace_capture() {
    local trace_path active_path ranges_path
    trace_path="${CURRENT_RUN_DIR}/inst_trace.json"
    active_path="${trace_path}.active_threads.jsonl"
    ranges_path="${trace_path}.memory_ranges.json"

    if [[ "${FRESH_RUN}" != "1" && "${DO_BUILD}" -ne 1 && "${DO_RESULT_GEN}" -ne 1 && -f "${trace_path}" && -f "${active_path}" && -f "${ranges_path}" ]]; then
        echo "=== Reusing existing exact trace artifacts from ${CURRENT_RUN_DIR} (DO_BUILD=0, DO_RESULT_GEN=0) ==="
        CURRENT_TRACE_FILE="${trace_path}"
        CURRENT_ACTIVE_THREADS_LOG="${active_path}"
        return 0
    fi

    rm -f "${trace_path}" "${active_path}" "${ranges_path}"

    echo "=== Running exact trace capture execution ==="
    update_config_line "-profile" "0"
    update_config_line "-components_to_flip" "0"
    update_config_line "-total_cycle_rand" "-1"
    update_config_line "-regfile_trace" "0"
    update_config_line "-exact_trace" "1"
    update_config_line "-exact_trace_file" "${trace_path}"
    update_config_line "-exact_trace_jsonl" "${EXACT_TRACE_JSONL}"

    timeout "${TIMEOUT_VAL}" "./${TEST_APP_NAME}" "${CURRENT_SIZE_ARGS[@]}" > "${CURRENT_RUN_DIR}/trace_capture.log" 2>&1

    if ! grep -a -iq "${SUCCESS_MSG}" "${CURRENT_RUN_DIR}/trace_capture.log"; then
        echo "=== Error: exact trace run did not report success ===" >&2
        exit 1
    fi
    if [[ ! -f "${trace_path}" ]]; then
        echo "=== Error: exact trace file missing: ${trace_path} ===" >&2
        exit 1
    fi
    if [[ ! -f "${active_path}" ]]; then
        echo "=== Error: active-thread trace missing: ${active_path} ===" >&2
        exit 1
    fi
    if [[ ! -f "${ranges_path}" ]]; then
        echo "=== Error: exact trace memory-range sidecar missing: ${ranges_path} ===" >&2
        exit 1
    fi

    CURRENT_TRACE_FILE="${trace_path}"
    CURRENT_ACTIVE_THREADS_LOG="${active_path}"
}

run_analyzer_pipeline() {
    local trace_input active_log_input
    local cache_meta_file cache_enabled cache_force global_cache_enabled
    local analyzer_input_file analyzer_input_binary_file analyzer_input_columnar_file analyzer_output_file analyzer_output_binary_file analyzer_meta_file exact_rates_file
    local codec_ext
    local analyzer_fault_component
    local omit_unused_read_events_effective analyzer_force_rf_addr_masking
    local -a prepare_sig_inputs=()

    cache_meta_file="$(cache_meta_path_for_dir "${CURRENT_RUN_DIR}")"
    cache_enabled="${ANALYZER_CACHE_ENABLE}"
    cache_force="${ANALYZER_CACHE_FORCE_REBUILD}"
    global_cache_enabled="$(is_global_cache_enabled)"
    codec_ext="$(json_codec_suffix "${ANALYZER_JSON_CODEC:-none}")"
    analyzer_input_file="${CURRENT_RUN_DIR}/analyzer_input.json${codec_ext}"
    analyzer_input_binary_file="${analyzer_input_file}.bin"
    analyzer_input_columnar_file="${analyzer_input_file}.events.col.pkl"
    analyzer_output_file="${CURRENT_RUN_DIR}/analyzer_output.json${codec_ext}"
    analyzer_output_binary_file="${analyzer_output_file}.bin"
    analyzer_meta_file="${CURRENT_RUN_DIR}/analyzer_meta.json"
    exact_rates_file="${CURRENT_RUN_DIR}/exact_rates.json"
    CURRENT_ANALYZER_INPUT_FILE="${analyzer_input_file}"
    CURRENT_ANALYZER_OUTPUT_FILE="${analyzer_output_file}"
    CURRENT_EXACT_RATES_FILE="${exact_rates_file}"
    analyzer_fault_component="$(resolve_analyzer_fault_component "${FAULT_COMPONENT}")"

    local fi_sampling_space_file
    local thread_rand_max block_rand_max smem_size_bits
    local l1d_size_bits l1d_tag_bits l1d_line_size_bytes l1d_shaders l1d_shaders_arg l1d_include_tag_bits l1d_write_allocate
    local l2_size_bits l2_tag_bits l2_line_size_bytes l2_global_prefill l2_include_tag_bits
    local l1d_tag_bits_source l2_tag_bits_source

    fi_sampling_space_file="${CURRENT_FI_SAMPLING_SPACE_JSON:-${CURRENT_RUN_DIR}/fi_sampling_space.json}"
    if [[ ! -f "${fi_sampling_space_file}" ]]; then
        echo "=== Error: missing FI sampling-space snapshot: ${fi_sampling_space_file} ===" >&2
        exit 1
    fi
    CURRENT_FI_SAMPLING_SPACE_JSON="${fi_sampling_space_file}"

    CURRENT_CYCLES_DOMAIN_FILE="$(get_json_field "${fi_sampling_space_file}" "cycles_file" "${CURRENT_RUN_DIR}/cycles_all.txt")"
    if [[ ! -f "${CURRENT_CYCLES_DOMAIN_FILE}" ]]; then
        echo "=== Error: FI cycles domain file missing: ${CURRENT_CYCLES_DOMAIN_FILE} ===" >&2
        exit 1
    fi

    CURRENT_DATATYPE_BITS="$(get_json_field "${fi_sampling_space_file}" "datatype_bits" "32")"
    thread_rand_max="$(get_json_field "${fi_sampling_space_file}" "thread_rand_max" "512")"
    block_rand_max="$(get_json_field "${fi_sampling_space_file}" "block_rand_max" "2")"
    smem_size_bits="$(get_json_field "${fi_sampling_space_file}" "smem_size_bits" "1")"
    l1d_size_bits="$(get_json_field "${fi_sampling_space_file}" "l1d_size_bits" "1")"
    l2_size_bits="$(get_json_field "${fi_sampling_space_file}" "l2_size_bits" "1")"
    l1d_tag_bits="$(get_json_field "${fi_sampling_space_file}" "l1d_tag_bits" "57")"
    l2_tag_bits="$(get_json_field "${fi_sampling_space_file}" "l2_tag_bits" "57")"
    l1d_include_tag_bits="$(get_json_field "${fi_sampling_space_file}" "l1d_include_tag_bits" "1")"
    l2_include_tag_bits="$(get_json_field "${fi_sampling_space_file}" "l2_include_tag_bits" "1")"
    l1d_shaders="$(normalize_shader_domain_spec "$(get_json_field "${fi_sampling_space_file}" "l1d_shaders" "")")"
    l1d_line_size_bytes="$(get_json_field "${fi_sampling_space_file}" "l1d_line_size_bytes" "128")"
    l2_line_size_bytes="$(get_json_field "${fi_sampling_space_file}" "l2_line_size_bytes" "128")"
    l2_global_prefill="$(get_json_field "${fi_sampling_space_file}" "l2_global_prefill" "1")"
    l1d_write_allocate="$(get_json_field "${fi_sampling_space_file}" "l1d_write_allocate" "0")"
    if ! is_pos_int "${l1d_line_size_bytes}"; then
        l1d_line_size_bytes="128"
    fi
    if ! is_pos_int "${l2_line_size_bytes}"; then
        l2_line_size_bytes="128"
    fi
    if [[ "${l2_global_prefill}" != "0" && "${l2_global_prefill}" != "1" ]]; then
        l2_global_prefill="1"
    fi
    if [[ "${l1d_write_allocate}" != "0" && "${l1d_write_allocate}" != "1" ]]; then
        l1d_write_allocate="0"
    fi
    l1d_tag_bits_source="$(get_json_field "${fi_sampling_space_file}" "source_priority.cache_tag_bits" "default")"
    l2_tag_bits_source="${l1d_tag_bits_source}"

    if ! is_pos_int "${CURRENT_DATATYPE_BITS}"; then
        echo "=== Error: invalid datatype_bits in ${fi_sampling_space_file}: ${CURRENT_DATATYPE_BITS} ===" >&2
        exit 1
    fi
    if ! is_pos_int "${thread_rand_max}"; then
        echo "=== Error: invalid thread_rand_max in ${fi_sampling_space_file}: ${thread_rand_max} ===" >&2
        exit 1
    fi
    if ! is_nonneg_int "${block_rand_max}"; then
        echo "=== Error: invalid block_rand_max in ${fi_sampling_space_file}: ${block_rand_max} ===" >&2
        exit 1
    fi
    if ! is_nonneg_int "${smem_size_bits}"; then
        echo "=== Error: invalid smem_size_bits in ${fi_sampling_space_file}: ${smem_size_bits} ===" >&2
        exit 1
    fi
    if ! is_valid_l1d_size_bits "${l1d_size_bits}"; then
        l1d_size_bits="1"
    fi
    if ! is_valid_l2_size_bits "${l2_size_bits}"; then
        l2_size_bits="1"
    fi
    if ! is_nonneg_int "${l1d_tag_bits}"; then
        l1d_tag_bits="57"
    fi
    if ! is_nonneg_int "${l2_tag_bits}"; then
        l2_tag_bits="57"
    fi
    if [[ "${l1d_include_tag_bits}" != "0" && "${l1d_include_tag_bits}" != "1" ]]; then
        l1d_include_tag_bits="1"
    fi
    if [[ "${l2_include_tag_bits}" != "0" && "${l2_include_tag_bits}" != "1" ]]; then
        l2_include_tag_bits="1"
    fi

    CURRENT_THREAD_RAND_MAX="${thread_rand_max}"
    CURRENT_BLOCK_RAND_MAX="${block_rand_max}"
    CURRENT_SMEM_SIZE_BITS="${smem_size_bits}"
    CURRENT_L1D_SIZE_BITS="${l1d_size_bits}"
    CURRENT_L1D_TAG_BITS="${l1d_tag_bits}"
    CURRENT_L1D_LINE_SIZE_BYTES="${l1d_line_size_bytes}"
    CURRENT_L1D_SHADERS="${l1d_shaders}"
    CURRENT_L1D_WRITE_ALLOCATE="${l1d_write_allocate}"
    CURRENT_L2_SIZE_BITS="${l2_size_bits}"
    CURRENT_L2_TAG_BITS="${l2_tag_bits}"
    CURRENT_L2_LINE_SIZE_BYTES="${l2_line_size_bytes}"
    CURRENT_L2_GLOBAL_PREFILL="${l2_global_prefill}"
    l1d_shaders_arg="${L1D_SHADERS:-auto}"
    if [[ -z "${l1d_shaders_arg}" || "${l1d_shaders_arg,,}" == "auto" ]]; then
        l1d_shaders_arg="auto"
    elif [[ "${l1d_shaders_arg,,}" == "all" ]]; then
        l1d_shaders_arg="all"
    else
        l1d_shaders_arg="$(normalize_shader_domain_spec "${l1d_shaders_arg}")"
        if [[ -z "${l1d_shaders_arg}" ]]; then
            echo "=== Error: invalid L1D_SHADERS='${L1D_SHADERS}' (expected auto|all|shader list) ===" >&2
            exit 1
        fi
    fi

    trace_input="${TRACE_TEMPLATE}"
    if [[ -z "${trace_input}" ]]; then
        trace_input="${CURRENT_TRACE_FILE}"
    fi
    if [[ ! -f "${trace_input}" ]]; then
        echo "=== Error: trace template missing: ${trace_input} ===" >&2
        exit 1
    fi

    active_log_input="${ACTIVE_THREADS_LOG:-}"
    if [[ -z "${active_log_input}" ]]; then
        active_log_input="${CURRENT_ACTIVE_THREADS_LOG}"
    fi
    if [[ ! -f "${active_log_input}" ]]; then
        echo "=== Error: active-thread trace missing: ${active_log_input} ===" >&2
        exit 1
    fi

    local prepare_payload_tmp prepare_sig prepare_hit prepare_params_json
    prepare_payload_tmp="$(mktemp)"
    prepare_params_json="$(printf '{"compact_events":%s,"input_manifest":%s,"input_binary":%s,"input_columnar":%s,"input_compat_pickle_dict":%s}' \
        "${ANALYZER_PREPARE_COMPACT_EVENTS}" "${ANALYZER_INPUT_MANIFEST}" "${ANALYZER_INPUT_BINARY}" "${ANALYZER_INPUT_COLUMNAR}" "${ANALYZER_INPUT_COMPAT_PICKLE_DICT}")"
    prepare_sig_inputs=(
        "${trace_input}"
        "${trace_input}.memory_ranges.json"
        "${CURRENT_RUN_DIR}/output_spec.json"
        "script/SARA/exact_sdc_prepare_input.py"
    )
    local -a prepare_cache_outputs=("${analyzer_input_file}")
    if [[ "${ANALYZER_INPUT_BINARY}" == "1" && "${ANALYZER_INPUT_MANIFEST}" != "1" ]]; then
        if [[ "${ANALYZER_INPUT_COLUMNAR}" == "1" ]]; then
            prepare_cache_outputs+=("${analyzer_input_columnar_file}")
        fi
        if [[ "${ANALYZER_INPUT_COMPAT_PICKLE_DICT}" == "1" ]]; then
            prepare_cache_outputs+=("${analyzer_input_binary_file}")
        fi
    fi
    prepare_sig="$(cache_compute_signature "analyzer_prepare_input" "${prepare_params_json}" "${prepare_payload_tmp}" \
        "${prepare_sig_inputs[@]}")"
    prepare_hit="0"
    if [[ "${cache_enabled}" == "1" && "${cache_force}" != "1" ]]; then
        prepare_hit="$(cache_step_hit "${cache_meta_file}" "analyzer_prepare_input" "${prepare_sig}" \
            "${prepare_cache_outputs[@]}")"
    fi
    if [[ "${prepare_hit}" != "1" && "${global_cache_enabled}" == "1" && "${cache_force}" != "1" ]]; then
        prepare_hit="$(global_cache_try_restore "analyzer_prepare_input" "${prepare_sig}" \
            "${prepare_cache_outputs[@]}")"
        if [[ "${prepare_hit}" == "1" ]]; then
            echo "=== Global cache hit: analyzer_prepare_input ==="
            if [[ "${cache_enabled}" == "1" ]]; then
                cache_step_update "${cache_meta_file}" "analyzer_prepare_input" "${prepare_sig}" "${prepare_payload_tmp}" \
                    "${prepare_cache_outputs[@]}"
            fi
        fi
    fi
    if [[ "${prepare_hit}" == "1" ]]; then
        echo "=== Cache hit: analyzer_prepare_input ($(basename "${analyzer_input_file}")) ==="
    else
        local -a prepare_cmd=(
            env
            "ANALYZER_INPUT_COLUMNAR=${ANALYZER_INPUT_COLUMNAR}"
            "ANALYZER_INPUT_COMPAT_PICKLE_DICT=${ANALYZER_INPUT_COMPAT_PICKLE_DICT}"
            python3
            script/SARA/exact_sdc_prepare_input.py
            --trace-template "${trace_input}"
            --output-spec "${CURRENT_RUN_DIR}/output_spec.json"
        )
        if [[ "${ANALYZER_INPUT_MANIFEST}" == "1" ]]; then
            prepare_cmd+=(--manifest-reference)
        else
            prepare_cmd+=(--no-manifest-reference)
        fi
        if [[ "${ANALYZER_INPUT_BINARY}" == "1" && "${ANALYZER_INPUT_MANIFEST}" != "1" ]]; then
            prepare_cmd+=(--binary-analyzer-input)
        else
            prepare_cmd+=(--no-binary-analyzer-input)
        fi
        if [[ "${ANALYZER_PREPARE_COMPACT_EVENTS}" == "1" ]]; then
            prepare_cmd+=(--compact-events)
        else
            prepare_cmd+=(--no-compact-events)
        fi
        prepare_cmd+=(-o "${analyzer_input_file}")
        run_timed "analyzer_prepare_input_py" "${prepare_cmd[@]}" || return $?
        if [[ "${cache_enabled}" == "1" ]]; then
            cache_step_update "${cache_meta_file}" "analyzer_prepare_input" "${prepare_sig}" "${prepare_payload_tmp}" \
                "${prepare_cache_outputs[@]}"
        fi
        if [[ "${global_cache_enabled}" == "1" ]]; then
            global_cache_store "analyzer_prepare_input" "${prepare_sig}" "${prepare_payload_tmp}" \
                "${prepare_cache_outputs[@]}"
        fi
    fi
    rm -f "${prepare_payload_tmp}"

    local analyzer_shared_memory_output=0
    local output_oracle_policy_file
    local analyzer_force_shared_component_output
    output_oracle_policy_file="${CURRENT_RUN_DIR}/output_oracle_policy.json"
    run_timed "sara_output_oracle_policy_py" python3 script/SARA/app_oracle_policy.py \
        --app "${TEST_APP_NAME}" \
        -o "${output_oracle_policy_file}"

    omit_unused_read_events_effective="${ANALYZER_OMIT_UNUSED_READ_EVENTS}"
    if [[ "${RUN_ANALYZER_FORCE_KEEP_READ_EVENTS:-0}" == "1" ]]; then
        omit_unused_read_events_effective="0"
    fi
    analyzer_force_rf_addr_masking="${RUN_ANALYZER_FORCE_RF_ADDR_MASKING:-0}"
    if ! is_bool_01 "${omit_unused_read_events_effective}"; then
        echo "=== Error: effective analyzer omit-unused-read-events flag must be 0 or 1 (got ${omit_unused_read_events_effective}) ===" >&2
        exit 1
    fi
    if ! is_bool_01 "${analyzer_force_rf_addr_masking}"; then
        echo "=== Error: effective analyzer force-rf-addr-masking flag must be 0 or 1 (got ${analyzer_force_rf_addr_masking}) ===" >&2
        exit 1
    fi
    analyzer_force_shared_component_output="${RUN_ANALYZER_FORCE_SHARED_COMPONENT_OUTPUT:-0}"
    if ! is_bool_01 "${analyzer_force_shared_component_output}"; then
        echo "=== Error: effective analyzer force-shared-component-output flag must be 0 or 1 (got ${analyzer_force_shared_component_output}) ===" >&2
        exit 1
    fi
    if [[ "${MODE}" == "all_components" || "${MODE}" == "all" ]] && {
        is_memory_component_for_shared_analyzer "${FAULT_COMPONENT}" || [[ "${analyzer_force_shared_component_output}" == "1" ]]
    }; then
        analyzer_shared_memory_output=1
    fi

    local -a analyzer_cmd=(
        env
        "REG_OBSERVED_COMPONENT_OUTPUT_TRIM=${ANALYZER_TRIM_COMPONENT_OUTPUT}"
        "REG_OBSERVED_OMIT_TOP_LEVEL_DIAGNOSTICS=${ANALYZER_OMIT_TOPLEVEL_DIAGNOSTICS}"
        "REG_OBSERVED_COMPACT_SITE_OUTPUT=${ANALYZER_COMPACT_SITE_OUTPUT}"
        "REG_OBSERVED_SKIP_SORT_FOR_COMPUTE=1"
        "REG_OBSERVED_SHARED_MEMORY_COMPONENT_OUTPUT=${analyzer_shared_memory_output}"
        "REG_OBSERVED_SHARE_CACHE_SITE_RECORDS=${ANALYZER_SHARE_CACHE_SITE_RECORDS}"
        "REG_OBSERVED_FORCE_RF_ADDR_MASKING=${analyzer_force_rf_addr_masking}"
        "REG_OBSERVED_OMIT_META_DIAGNOSTIC_SAMPLES=${ANALYZER_OMIT_META_DIAGNOSTIC_SAMPLES}"
        "REG_OBSERVED_OMIT_READ_EVENTS_FOR_NON_RF=${omit_unused_read_events_effective}"
        python3
        script/SARA/reg_observed_analyzer.py
        "${analyzer_input_file}"
        --fault-component "${analyzer_fault_component}"
        --output-oracle-policy "${output_oracle_policy_file}"
        --mask-format "${ANALYZER_MASK_FORMAT}"
        --lite-output-profile "${ANALYZER_LITE_OUTPUT_PROFILE}"
    )
    if [[ "${ANALYZER_ASSUME_SORTED_EVENTS}" == "1" ]]; then
        analyzer_cmd+=(--assume-sorted-events)
    fi
    if [[ "${ANALYZER_LITE_OUTPUT}" == "1" ]]; then
        analyzer_cmd+=(--lite-output)
        if [[ "${ANALYZER_AGGREGATE_READ_EVENTS}" == "1" ]]; then
            analyzer_cmd+=(--aggregate-read-events)
        else
            analyzer_cmd+=(--no-aggregate-read-events)
        fi
    else
        analyzer_cmd+=(--no-aggregate-read-events)
    fi
    if [[ -n "${ANALYZER_PROFILE_OUT}" ]]; then
        local profile_out_path
        profile_out_path="${ANALYZER_PROFILE_OUT}"
        if [[ "${profile_out_path}" == "1" ]]; then
            profile_out_path="${CURRENT_RUN_DIR}/reg_observed_profile.txt"
        fi
        analyzer_cmd+=(--profile-out "${profile_out_path}")
    fi
    if [[ "${ANALYZER_EMIT_CACHE_SITES}" == "1" ]]; then
        analyzer_cmd+=(--emit-cache-sites)
    else
        analyzer_cmd+=(--no-emit-cache-sites)
    fi
    if [[ "${ANALYZER_OUTPUT_BINARY}" == "1" ]]; then
        analyzer_cmd+=(--binary-output)
    else
        analyzer_cmd+=(--no-binary-output)
    fi
    analyzer_cmd+=(
        --meta-out
        "${analyzer_meta_file}"
        -o
        "${analyzer_output_file}"
    )
    local analyzer_payload_tmp analyzer_sig analyzer_hit analyzer_params_json
    local -a analyzer_cache_outputs=("${analyzer_output_file}" "${analyzer_meta_file}")
    if [[ "${ANALYZER_OUTPUT_BINARY}" == "1" ]]; then
        analyzer_cache_outputs+=("${analyzer_output_binary_file}")
    fi
    analyzer_payload_tmp="$(mktemp)"
    analyzer_params_json="$(printf '{"fault_component":"%s","lite_output":%s,"lite_output_profile":"%s","aggregate_read_events":%s,"mask_format":"%s","assume_sorted_events":%s,"emit_cache_sites":%s,"output_binary":%s,"trim_component_output":%s,"omit_toplevel_diagnostics":%s,"compact_site_output":%s,"shared_memory_component_output":%s,"share_cache_site_records":%s,"force_rf_addr_masking":%s,"omit_meta_diagnostic_samples":%s,"omit_unused_read_events":%s}' \
        "${analyzer_fault_component}" "${ANALYZER_LITE_OUTPUT}" "${ANALYZER_LITE_OUTPUT_PROFILE}" "${ANALYZER_AGGREGATE_READ_EVENTS}" "${ANALYZER_MASK_FORMAT}" "${ANALYZER_ASSUME_SORTED_EVENTS}" "${ANALYZER_EMIT_CACHE_SITES}" "${ANALYZER_OUTPUT_BINARY}" "${ANALYZER_TRIM_COMPONENT_OUTPUT}" "${ANALYZER_OMIT_TOPLEVEL_DIAGNOSTICS}" "${ANALYZER_COMPACT_SITE_OUTPUT}" "${analyzer_shared_memory_output}" "${ANALYZER_SHARE_CACHE_SITE_RECORDS}" "${analyzer_force_rf_addr_masking}" "${ANALYZER_OMIT_META_DIAGNOSTIC_SAMPLES}" "${omit_unused_read_events_effective}")"
    analyzer_sig="$(cache_compute_signature "analyzer_reg_observed" "${analyzer_params_json}" "${analyzer_payload_tmp}" \
        "${analyzer_input_file}" \
        "${trace_input}" \
        "${trace_input}.memory_ranges.json" \
        "script/SARA/reg_observed_analyzer.py" \
        "script/common/outcome_oracle.py" \
        "${output_oracle_policy_file}")"
    analyzer_hit="0"
    if [[ "${cache_enabled}" == "1" && "${cache_force}" != "1" ]]; then
        analyzer_hit="$(cache_step_hit "${cache_meta_file}" "analyzer_reg_observed" "${analyzer_sig}" \
            "${analyzer_cache_outputs[@]}")"
    fi
    if [[ "${analyzer_hit}" != "1" && "${global_cache_enabled}" == "1" && "${cache_force}" != "1" ]]; then
        analyzer_hit="$(global_cache_try_restore "analyzer_reg_observed" "${analyzer_sig}" \
            "${analyzer_cache_outputs[@]}")"
        if [[ "${analyzer_hit}" == "1" ]]; then
            echo "=== Global cache hit: analyzer_reg_observed ==="
            if [[ "${cache_enabled}" == "1" ]]; then
                cache_step_update "${cache_meta_file}" "analyzer_reg_observed" "${analyzer_sig}" "${analyzer_payload_tmp}" \
                    "${analyzer_cache_outputs[@]}"
            fi
        fi
    fi
    if [[ "${analyzer_hit}" == "1" ]]; then
        echo "=== Cache hit: analyzer_reg_observed ($(basename "${analyzer_output_file}")) ==="
    else
        run_timed "analyzer_reg_observed_py" "${analyzer_cmd[@]}" || return $?
        if [[ "${cache_enabled}" == "1" ]]; then
            cache_step_update "${cache_meta_file}" "analyzer_reg_observed" "${analyzer_sig}" "${analyzer_payload_tmp}" \
                "${analyzer_cache_outputs[@]}"
        fi
        if [[ "${global_cache_enabled}" == "1" ]]; then
            global_cache_store "analyzer_reg_observed" "${analyzer_sig}" "${analyzer_payload_tmp}" \
                "${analyzer_cache_outputs[@]}"
        fi
    fi
    if [[ ! -f "${analyzer_meta_file}" && -f "${analyzer_output_file}" ]]; then
        python3 - "${analyzer_output_file}" "${analyzer_meta_file}" <<'PY'
import gzip
import json
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
raw_bytes = src.read_bytes()
if raw_bytes[:2] == b"\x1f\x8b":
    raw_bytes = gzip.decompress(raw_bytes)
elif raw_bytes[:4] == b"\x28\xb5\x2f\xfd":
    import zstandard as zstd  # type: ignore

    raw_bytes = zstd.ZstdDecompressor().decompress(raw_bytes)
raw = json.loads(raw_bytes.decode("utf-8"))
meta = raw.get("exact_meta", {}) if isinstance(raw, dict) else {}
dst.write_text(json.dumps(meta, separators=(",", ":"), ensure_ascii=True) + "\n", encoding="utf-8")
PY
    fi
    rm -f "${analyzer_payload_tmp}"

    if [[ "${RUN_ANALYZER_SKIP_EXACT_COMPUTE:-0}" == "1" ]]; then
        if [[ "${analyzer_input_file}" != "${CURRENT_RUN_DIR}/analyzer_input.json" ]]; then
            ln -sfn "$(basename "${analyzer_input_file}")" "${CURRENT_RUN_DIR}/analyzer_input.json"
        fi
        if [[ "${analyzer_output_file}" != "${CURRENT_RUN_DIR}/analyzer_output.json" ]]; then
            ln -sfn "$(basename "${analyzer_output_file}")" "${CURRENT_RUN_DIR}/analyzer_output.json"
        fi
        LAST_SUMMARY_JSON=""
        return 0
    fi

    local compute_payload_tmp compute_sig compute_hit compute_params_json
    compute_payload_tmp="$(mktemp)"
    local -a compute_sig_inputs=("${analyzer_output_file}")
    if [[ "${ANALYZER_OUTPUT_BINARY}" == "1" ]]; then
        compute_sig_inputs+=("${analyzer_output_binary_file}")
    fi
    compute_params_json="$(printf '{"exact_semantics_profile":"%s","fault_component":"%s","thread_rand_max":%s,"block_rand_max":%s,"smem_size_bits":%s,"l1d_size_bits":%s,"l1d_tag_bits":%s,"l1d_include_tag_bits":%s,"l1d_line_size_bytes":%s,"l1d_shaders":"%s","l1d_shaders_arg":"%s","l1d_write_allocate":%s,"l2_size_bits":%s,"l2_tag_bits":%s,"l2_include_tag_bits":%s,"l2_line_size_bytes":%s,"l2_global_prefill":%s,"datatype_bits":%s,"addr_valid_ranges_path":"%s","fi_sampling_space":"%s","cycles_domain_file":"%s"}' \
        "${EXACT_SEMANTICS_PROFILE}" "${FAULT_COMPONENT}" "${thread_rand_max}" "${block_rand_max}" "${smem_size_bits}" "${l1d_size_bits}" "${l1d_tag_bits}" "${l1d_include_tag_bits}" "${l1d_line_size_bytes}" "${l1d_shaders}" "${l1d_shaders_arg}" "${l1d_write_allocate}" "${l2_size_bits}" "${l2_tag_bits}" "${l2_include_tag_bits}" "${l2_line_size_bytes}" "${l2_global_prefill}" "${CURRENT_DATATYPE_BITS}" "${ADDR_VALID_RANGES_PATH}" "${CURRENT_FI_SAMPLING_SPACE_JSON}" "${CURRENT_CYCLES_DOMAIN_FILE}")"
    compute_sig="$(cache_compute_signature "analyzer_exact_compute" "${compute_params_json}" "${compute_payload_tmp}" \
        "${compute_sig_inputs[@]}" \
        "${analyzer_input_file}" \
        "${trace_input}" \
        "${trace_input}.memory_ranges.json" \
        "${CURRENT_RUN_DIR}/regfile_trace.bin" \
        "${CURRENT_CYCLES_DOMAIN_FILE}" \
        "${active_log_input}" \
        "${CURRENT_REGISTER_DOMAIN_FILE}" \
        "${CURRENT_FI_SAMPLING_SPACE_JSON}" \
        "script/SARA/exact_sdc_compute.py")"
    compute_hit="0"
    if [[ "${cache_enabled}" == "1" && "${cache_force}" != "1" ]]; then
        compute_hit="$(cache_step_hit "${cache_meta_file}" "analyzer_exact_compute" "${compute_sig}" \
            "${exact_rates_file}")"
    fi
    if [[ "${compute_hit}" != "1" && "${global_cache_enabled}" == "1" && "${cache_force}" != "1" ]]; then
        compute_hit="$(global_cache_try_restore "analyzer_exact_compute" "${compute_sig}" \
            "${exact_rates_file}")"
        if [[ "${compute_hit}" == "1" ]]; then
            echo "=== Global cache hit: analyzer_exact_compute ==="
            if [[ "${cache_enabled}" == "1" ]]; then
                cache_step_update "${cache_meta_file}" "analyzer_exact_compute" "${compute_sig}" "${compute_payload_tmp}" \
                    "${exact_rates_file}"
            fi
        fi
    fi
    if [[ "${compute_hit}" == "1" ]]; then
        echo "=== Cache hit: analyzer_exact_compute (exact_rates.json) ==="
    else
        run_timed "analyzer_exact_compute_py" python3 script/SARA/exact_sdc_compute.py \
            --analyzer-output "${analyzer_output_file}" \
            --regfile-trace "${CURRENT_RUN_DIR}/regfile_trace.bin" \
            --trace-template "${analyzer_input_file}" \
            --cycles "${CURRENT_CYCLES_DOMAIN_FILE}" \
            --active-threads-log "${active_log_input}" \
            --thread-rand-max "${thread_rand_max}" \
            --block-rand-max "${block_rand_max}" \
            --smem-size-bits "${smem_size_bits}" \
            --l1d-size-bits "${l1d_size_bits}" \
            --l1d-line-size-bytes "${l1d_line_size_bytes}" \
            --l1d-tag-bits "${l1d_tag_bits}" \
            --l1d-include-tag-bits "${l1d_include_tag_bits}" \
            --l1d-shaders "${l1d_shaders_arg}" \
            --l1d-write-allocate "${l1d_write_allocate}" \
            --l2-size-bits "${l2_size_bits}" \
            --l2-tag-bits "${l2_tag_bits}" \
            --l2-include-tag-bits "${l2_include_tag_bits}" \
            --l2-line-size-bytes "${l2_line_size_bytes}" \
            --l2-global-prefill "${l2_global_prefill}" \
            --registers "${CURRENT_REGISTER_DOMAIN_FILE}" \
            --datatype-bits "${CURRENT_DATATYPE_BITS}" \
            --fault-component "${FAULT_COMPONENT}" \
            --storage-group-mode "${EXACT_STORAGE_GROUP_MODE}" \
            ${ADDR_VALID_RANGES_PATH:+--addr-valid-ranges-path} \
            ${ADDR_VALID_RANGES_PATH:+${ADDR_VALID_RANGES_PATH}} \
            --fi-sampling-space-path "${CURRENT_FI_SAMPLING_SPACE_JSON}" \
            --cycles-domain-path "${CURRENT_CYCLES_DOMAIN_FILE}" \
            -o "${exact_rates_file}" || return $?
        if [[ "${cache_enabled}" == "1" ]]; then
            cache_step_update "${cache_meta_file}" "analyzer_exact_compute" "${compute_sig}" "${compute_payload_tmp}" \
                "${exact_rates_file}"
        fi
        if [[ "${global_cache_enabled}" == "1" ]]; then
            global_cache_store "analyzer_exact_compute" "${compute_sig}" "${compute_payload_tmp}" \
                "${exact_rates_file}"
        fi
    fi
    rm -f "${compute_payload_tmp}"

    run_timed "analyzer_rates_summary_cpp" "${EXACT_CORE_BIN}" rates-summary \
        --input "${exact_rates_file}" \
        --benchmark "${TEST_APP_NAME}" \
        --test-id "${CURRENT_TEST_ID}" \
        --output-json "${CURRENT_RUN_DIR}/summary.json" \
        | tee "${CURRENT_RUN_DIR}/summary.txt" || return $?
    echo "sara_semantics_profile=${SARA_SEMANTICS_PROFILE}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "analyzer_lite_output=${ANALYZER_LITE_OUTPUT}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "analyzer_lite_output_profile=${ANALYZER_LITE_OUTPUT_PROFILE}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "analyzer_aggregate_read_events=${ANALYZER_AGGREGATE_READ_EVENTS}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "analyzer_compact_site_output=${ANALYZER_COMPACT_SITE_OUTPUT}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "analyzer_omit_meta_diagnostic_samples=${ANALYZER_OMIT_META_DIAGNOSTIC_SAMPLES}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "analyzer_omit_unused_read_events=${ANALYZER_OMIT_UNUSED_READ_EVENTS}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "analyzer_mask_format=${ANALYZER_MASK_FORMAT}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "analyzer_assume_sorted_events=${ANALYZER_ASSUME_SORTED_EVENTS}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "analyzer_emit_cache_sites=${ANALYZER_EMIT_CACHE_SITES}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "analyzer_prepare_compact_events=${ANALYZER_PREPARE_COMPACT_EVENTS}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "analyzer_input_manifest=${ANALYZER_INPUT_MANIFEST}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "analyzer_input_binary=${ANALYZER_INPUT_BINARY}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "analyzer_input_columnar=${ANALYZER_INPUT_COLUMNAR}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "analyzer_input_compat_pickle_dict=${ANALYZER_INPUT_COMPAT_PICKLE_DICT}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "analyzer_output_binary=${ANALYZER_OUTPUT_BINARY}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "analyzer_cache_enable=${ANALYZER_CACHE_ENABLE}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "analyzer_global_cache=${ANALYZER_GLOBAL_CACHE}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "analyzer_global_cache_dir=${ANALYZER_GLOBAL_CACHE_DIR}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "analyzer_json_codec=${ANALYZER_JSON_CODEC:-none}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "fault_component=${FAULT_COMPONENT}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "weight_thread_rand_max=${thread_rand_max}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "weight_block_rand_max=${block_rand_max}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "weight_smem_size_bits=${smem_size_bits}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "weight_l1d_size_bits=${l1d_size_bits}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "weight_l1d_tag_bits=${l1d_tag_bits}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "weight_l1d_include_tag_bits=${l1d_include_tag_bits}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "weight_l1d_tag_bits_source=${l1d_tag_bits_source}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "weight_l1d_line_size_bytes=${l1d_line_size_bytes}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "weight_l1d_shaders=${l1d_shaders}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "weight_l1d_shaders_arg=${l1d_shaders_arg}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "weight_l1d_write_allocate=${l1d_write_allocate}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "weight_l2_size_bits=${l2_size_bits}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "weight_l2_tag_bits=${l2_tag_bits}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "weight_l2_include_tag_bits=${l2_include_tag_bits}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "weight_l2_tag_bits_source=${l2_tag_bits_source}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "weight_l2_line_size_bytes=${l2_line_size_bytes}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "weight_l2_global_prefill=${l2_global_prefill}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "fi_sampling_space_json=${CURRENT_FI_SAMPLING_SPACE_JSON}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "cycles_domain_file=${CURRENT_CYCLES_DOMAIN_FILE}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "sara_semantics_profile=${SARA_SEMANTICS_PROFILE}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    echo "addr_valid_ranges_path=${ADDR_VALID_RANGES_PATH:-unset}" | tee -a "${CURRENT_RUN_DIR}/summary.txt"
    run_timed "analyzer_meta_summary_py" python3 - "${exact_rates_file}" <<'PY' | tee -a "${CURRENT_RUN_DIR}/summary.txt" || return $?
import json
import sys

path = sys.argv[1]
raw = json.loads(open(path).read())
meta = raw.get("exact_meta", {})
print(
    "trace-expanding bits contributed sdc numerator = {}".format(
        int(meta.get("trace_expanding_sdc_numerator", 0))
    )
)
print("trace_policy_used_bits={}".format(int(meta.get("trace_policy_used_bits", 0))))
print("trace_policy_used_mass={}".format(int(meta.get("trace_policy_used_mass", 0))))
print("trace_policy_override_bits={}".format(int(meta.get("trace_policy_override_bits", 0))))
print("trace_policy_override_mass={}".format(int(meta.get("trace_policy_override_mass", 0))))
trace_policy_override_reason_breakdown = meta.get("trace_policy_override_reason_breakdown", {})
if isinstance(trace_policy_override_reason_breakdown, dict):
    print("trace_policy_override_reason_breakdown=" + json.dumps(trace_policy_override_reason_breakdown, sort_keys=True))
print("trace_uncovered_mode={}".format(str(meta.get("trace_uncovered_mode", ""))))
print("trace_divergence_policy={}".format(str(meta.get("trace_divergence_policy", ""))))
print("trace_divergence_bits={}".format(meta.get("trace_divergence_bits", 0)))
print("trace_divergence_mass={}".format(meta.get("trace_divergence_mass", 0)))
print("trace_divergence_zero_warning={}".format(str(meta.get("trace_divergence_zero_warning", ""))))
print("trace_expanding_mask_present_count={}".format(int(meta.get("trace_expanding_mask_present_count", 0))))
print("trace_expanding_bits_total={}".format(int(meta.get("trace_expanding_bits_total", 0))))
print("cache_tag_class_policy={}".format(str(meta.get("cache_tag_class_policy", ""))))
print("addr_fault_policy={}".format(str(meta.get("addr_fault_policy", ""))))
print("addr_due_mode={}".format(str(meta.get("addr_due_mode", ""))))
print("addr_bits_mode={}".format(str(meta.get("addr_bits_mode", ""))))
print("addr_bits_count={}".format(meta.get("addr_bits_count", 0)))
print("addr_effective_bits={}".format(meta.get("addr_effective_bits", "")))
print("addr_domain_bits={}".format(meta.get("addr_domain_bits", 0)))
print("addr_due_bits={}".format(meta.get("addr_due_bits", 0)))
print("addr_sdc_bits={}".format(meta.get("addr_sdc_bits", 0)))
print("addr_masked_bits={}".format(meta.get("addr_masked_bits", 0)))
print("addr_unknown_bits={}".format(meta.get("addr_unknown_bits", 0)))
print("domain_sampling_space_total_bits={}".format(int(meta.get("domain_sampling_space_total_bits", 0))))
print("domain_derived_total_bits={}".format(int(meta.get("domain_derived_total_bits", 0))))
print("domain_mismatch_bits={}".format(int(meta.get("domain_mismatch_bits", 0))))
mismatch_breakdown = meta.get("mismatch_breakdown", {})
if isinstance(mismatch_breakdown, dict) and mismatch_breakdown:
    print("mismatch_breakdown=" + json.dumps(mismatch_breakdown, sort_keys=True))
print("domain_reconciliation_method={}".format(str(meta.get("domain_reconciliation_method", ""))))
print("domain_reconciliation_unexplained_bits={}".format(int(meta.get("domain_reconciliation_unexplained_bits", 0))))
print("domain_reconciliation_non_live_masked_topup_bits={}".format(int(meta.get("domain_reconciliation_non_live_masked_topup_bits", 0))))
print("domain_reconciliation_addr_domain_excluded_bits={}".format(int(meta.get("domain_reconciliation_addr_domain_excluded_bits", 0))))
print("domain_reconciliation_failure_report_path={}".format(str(meta.get("domain_reconciliation_failure_report_path", ""))))
print("use_sampling_space_domain={}".format(int(bool(meta.get("use_sampling_space_domain", False)))))
print("use_sampling_space_domain_rf={}".format(int(bool(meta.get("use_sampling_space_domain_rf", False)))))
print("use_sampling_space_domain_smem={}".format(int(bool(meta.get("use_sampling_space_domain_smem", False)))))
print("rf_domain_sampling_bits={}".format(int(meta.get("rf_domain_sampling_bits", 0))))
print("rf_domain_derived_bits={}".format(int(meta.get("rf_domain_derived_bits", 0))))
print("rf_domain_mismatch={}".format(int(meta.get("rf_domain_mismatch", 0))))
print("smem_domain_sampling_bits={}".format(int(meta.get("smem_domain_sampling_bits", 0))))
print("smem_domain_derived_bits={}".format(int(meta.get("smem_domain_derived_bits", 0))))
print("smem_domain_mismatch={}".format(int(meta.get("smem_domain_mismatch", 0))))
print("smem_domain_policy={}".format(str(meta.get("smem_domain_policy", ""))))
print("smem_size_bits_source={}".format(str(meta.get("smem_size_bits_source", ""))))
print("smem_size_bits_final={}".format(int(meta.get("smem_size_bits_final", 0))))
print("smem_hw_size_bits={}".format(int(meta.get("smem_hw_size_bits", 0))))
print("smem_allocated_bits={}".format(int(meta.get("smem_allocated_bits", 0))))
print("smem_touched_bits={}".format(int(meta.get("smem_touched_bits", 0))))
print("smem_sampling_space_bits={}".format(int(meta.get("smem_sampling_space_bits", 0))))
print("smem_addr_exception_policy={}".format(str(meta.get("smem_addr_exception_policy", ""))))
print("smem_addr_domain_bits={}".format(int(meta.get("smem_addr_domain_bits", 0))))
print("smem_addr_due_bits={}".format(meta.get("smem_addr_due_bits", 0)))
print("smem_addr_sdc_bits={}".format(meta.get("smem_addr_sdc_bits", 0)))
print("smem_addr_masked_bits={}".format(meta.get("smem_addr_masked_bits", 0)))
print("smem_addr_unknown_bits={}".format(meta.get("smem_addr_unknown_bits", 0)))
print("smem_addr_range_source={}".format(str(meta.get("smem_addr_range_source", ""))))
print("rf_addr_reg_policy={}".format(str(meta.get("rf_addr_reg_policy", ""))))
print("rf_addr_reg_policy_effective={}".format(str(meta.get("rf_addr_reg_policy_effective", ""))))
print("rf_due_bits_by_cause={}".format(json.dumps(meta.get("rf_due_bits_by_cause", {}), sort_keys=True)))
rf_sdc_proof_source_mass = meta.get("rf_sdc_proof_source_mass", {})
if isinstance(rf_sdc_proof_source_mass, dict) and rf_sdc_proof_source_mass:
    print("rf_sdc_proof_source_mass=" + json.dumps(rf_sdc_proof_source_mass, sort_keys=True))
rf_sdc_proof_source_policy = str(meta.get("rf_sdc_proof_source_policy", "")).strip()
if rf_sdc_proof_source_policy:
    print("rf_sdc_proof_source_policy={}".format(rf_sdc_proof_source_policy))
print("metadata_fault_policy={}".format(str(meta.get("metadata_fault_policy", ""))))
print("metadata_domain_bits={}".format(int(meta.get("metadata_domain_bits", 0))))
print("metadata_masked_bits={}".format(int(meta.get("metadata_masked_bits", 0))))
print("metadata_sdc_bits={}".format(int(meta.get("metadata_sdc_bits", 0))))
print("metadata_due_bits={}".format(int(meta.get("metadata_due_bits", 0))))
print("metadata_unknown_bits={}".format(int(meta.get("metadata_unknown_bits", 0))))
print("metadata_applied_bits={}".format(int(meta.get("metadata_applied_bits", 0))))
print("shader_scope_mode={}".format(str(meta.get("shader_scope_mode", ""))))
print("shader_scope_count={}".format(int(meta.get("shader_scope_count", 0))))
print("shader_scope_source={}".format(str(meta.get("shader_scope_source", ""))))
print("smem_scope_source={}".format(str(meta.get("smem_scope_source", ""))))
print("smem_scope_count_hist_total_cycles={}".format(int(meta.get("smem_scope_count_hist_total_cycles", 0))))
print("smem_scope_count_hist_unique={}".format(int(meta.get("smem_scope_count_hist_unique", 0))))
smem_scope_count_hist_topk = meta.get("smem_scope_count_hist_topk", [])
if isinstance(smem_scope_count_hist_topk, list) and smem_scope_count_hist_topk:
    print("smem_scope_count_hist_topk=" + json.dumps(smem_scope_count_hist_topk, sort_keys=True))
print("unknown_bits={}".format(meta.get("unknown_bits", 0)))
print("unknown_mass={}".format(meta.get("unknown_mass", 0)))
print("unknown_fold_target={}".format(str(meta.get("unknown_fold_target", ""))))
print("unknown_fold_mass={}".format(meta.get("unknown_fold_mass", 0)))
print("boundary_events_count={}".format(int(meta.get("boundary_events_count", 0))))
print("boundary_events_mass={}".format(meta.get("boundary_events_mass", 0))
)
print("missing_active_thread_cycles={}".format(int(meta.get("missing_active_thread_cycles", 0))))
print(
    "missing_active_thread_cycle_ratio={:.6f}".format(
        float(meta.get("missing_active_thread_cycle_ratio", 0.0))
    )
)
print(
    "active_threads_carried_forward_cycles={}".format(
        int(meta.get("active_threads_carried_forward_cycles", 0))
    )
)
print(
    "active_threads_empty_fill_cycles={}".format(
        int(meta.get("active_threads_empty_fill_cycles", 0))
    )
)
print("missing_active_threads_policy={}".format(str(meta.get("missing_active_threads_policy", ""))))
unknown_reasons = meta.get("unknown_reason_counts", {})
if isinstance(unknown_reasons, dict) and unknown_reasons:
    print("unknown_reason_counts=" + json.dumps(unknown_reasons, sort_keys=True))
unknown_source_bits = meta.get("unknown_source_bits", {})
if isinstance(unknown_source_bits, dict) and unknown_source_bits:
    print("unknown_source_bits=" + json.dumps(unknown_source_bits, sort_keys=True))
unknown_mass_by_source = meta.get("unknown_mass_by_source", {})
if isinstance(unknown_mass_by_source, dict) and unknown_mass_by_source:
    print("unknown_mass_by_source=" + json.dumps(unknown_mass_by_source, sort_keys=True))
unknown_source_method = str(meta.get("unknown_source_mass_method", "")).strip()
if unknown_source_method:
    print("unknown_source_mass_method={}".format(unknown_source_method))
due_source_bits = meta.get("due_source_bits", {})
if isinstance(due_source_bits, dict):
    print("due_source_bits=" + json.dumps(due_source_bits, sort_keys=True))
due_mass_by_source = meta.get("due_mass_by_source", {})
if isinstance(due_mass_by_source, dict):
    print("due_mass_by_source=" + json.dumps(due_mass_by_source, sort_keys=True))
profile = str(meta.get("exact_semantics_profile", "")).replace(
    "canonical_proof_exact_v3", "canonical_proof_sara_v3"
)
print("sara_semantics_profile={}".format(profile))
due_oracle_counts = meta.get("due_oracle_reason_counts", {})
if isinstance(due_oracle_counts, dict) and due_oracle_counts:
    print("due_oracle_reason_counts=" + json.dumps(due_oracle_counts, sort_keys=True))
due_oracle_details = meta.get("due_oracle_reason_details_top20", [])
if isinstance(due_oracle_details, list) and due_oracle_details:
    print(
        "due_oracle_reason_details_top20="
        + json.dumps(due_oracle_details[:20], sort_keys=True)
    )
print("output_oracle_type={}".format(str(meta.get("output_oracle_type", ""))))
print(
    "output_oracle_has_output_spec={}".format(
        str(bool(meta.get("output_oracle_has_output_spec", False))).lower()
    )
)
print("output_oracle_spec_entry_count={}".format(int(meta.get("output_oracle_spec_entry_count", 0))))
print("output_oracle_spec_total_bytes={}".format(int(meta.get("output_oracle_spec_total_bytes", 0))))
print("addr_observed_seed_suppressed_bits={}".format(int(meta.get("addr_observed_seed_suppressed_bits", 0))))
print("addr_observed_seed_suppressed_events={}".format(int(meta.get("addr_observed_seed_suppressed_events", 0))))
print("tol_output_store_seed_count={}".format(int(meta.get("tol_output_store_seed_count", 0))))
print("tol_float_backward_op_count={}".format(int(meta.get("tol_float_backward_op_count", 0))))
print("tol_memory_forward_byte_count={}".format(int(meta.get("tol_memory_forward_byte_count", 0))))
print("tol_exact_conversion_count={}".format(int(meta.get("tol_exact_conversion_count", 0))))
data_bits = meta.get("data_bits", None)
tag_bits = meta.get("tag_bits", None)
total_bits = meta.get("total_bits", None)
if data_bits is not None or tag_bits is not None or total_bits is not None:
    print(
        "cache_domain_bits(data/tag/total)={}/{}/{}".format(
            int(data_bits or 0), int(tag_bits or 0), int(total_bits or 0)
        )
    )
seed_data_bits = meta.get("l1d_selected_data_bit_domain_size", meta.get("l2_selected_data_bit_domain_size", None))
seed_tag_bits = meta.get("l1d_selected_tag_bit_domain_size", meta.get("l2_selected_tag_bit_domain_size", None))
seed_total_bits = meta.get("total_injection_bit_domain_size", None)
if seed_data_bits is not None or seed_tag_bits is not None or seed_total_bits is not None:
    print(
        "cache_domain_bits_per_seed(data/tag/total)={}/{}/{}".format(
            int(seed_data_bits or 0), int(seed_tag_bits or 0), int(seed_total_bits or 0)
        )
    )
print(
    "classification_bits_data(masked/sdc/due/unknown)={}/{}/{}/{}".format(
        int(meta.get("masked_bits_data", 0)),
        int(meta.get("sdc_bits_data", 0)),
        int(meta.get("due_bits_data", 0)),
        int(meta.get("unknown_bits_data", 0)),
    )
)
print(
    "classification_bits_tag(masked/sdc/due/unknown)={}/{}/{}/{}".format(
        int(meta.get("masked_bits_tag", 0)),
        int(meta.get("sdc_bits_tag", 0)),
        int(meta.get("due_bits_tag", 0)),
        int(meta.get("unknown_bits_tag", 0)),
    )
)
print(
    "classification_bits_addr(masked/sdc/due/unknown)={}/{}/{}/{}".format(
        int(meta.get("addr_masked_bits", 0)),
        int(meta.get("addr_sdc_bits", 0)),
        int(meta.get("addr_due_bits", 0)),
        int(meta.get("addr_unknown_bits", 0)),
    )
)
print(
    "output_last_writer_store_count={}".format(
        int(meta.get("output_last_writer_store_count", 0))
    )
)
print(
    "output_total_store_count={}".format(
        int(meta.get("output_total_store_count", 0))
    )
)
print("filtered_store_ratio={:.6f}".format(float(meta.get("filtered_store_ratio", 0.0))))
reason = str(meta.get("trace_policy_unused_reason", "")).strip()
if reason:
    print("trace_policy_unused_reason={}".format(reason))
PY
    run_timed "analyzer_summary_metadata_annotate_py" python3 - "${CURRENT_RUN_DIR}/summary.json" "${exact_rates_file}" "${EXACT_SEMANTICS_PROFILE}" <<'PY' || return $?
import json
import sys

summary_path = sys.argv[1]
exact_path = sys.argv[2]
exact_semantics_profile = str(sys.argv[3])

summary = json.loads(open(summary_path).read())
exact = json.loads(open(exact_path).read())
meta = exact.get("exact_meta", {}) if isinstance(exact, dict) else {}

summary["exact_semantics_profile"] = str(exact_semantics_profile)
summary["sara_semantics_profile"] = str(exact_semantics_profile).replace(
    "canonical_proof_exact_v3", "canonical_proof_sara_v3"
)
summary["status"] = "ok"
summary["status_reason"] = ""
summary["unknown_bits"] = meta.get("unknown_bits", 0)
summary["unknown_mass"] = meta.get("unknown_mass", 0)
summary["total_bits"] = meta.get("total_bits", 0)
summary["data_bits"] = meta.get("data_bits", 0)
summary["tag_bits"] = meta.get("tag_bits", 0)
summary["masked_bits_data"] = meta.get("masked_bits_data", 0)
summary["sdc_bits_data"] = meta.get("sdc_bits_data", 0)
summary["due_bits_data"] = meta.get("due_bits_data", 0)
summary["unknown_bits_data"] = meta.get("unknown_bits_data", 0)
summary["masked_bits_tag"] = meta.get("masked_bits_tag", 0)
summary["sdc_bits_tag"] = meta.get("sdc_bits_tag", 0)
summary["due_bits_tag"] = meta.get("due_bits_tag", 0)
summary["unknown_bits_tag"] = meta.get("unknown_bits_tag", 0)
summary["trace_policy_used_mass"] = int(meta.get("trace_policy_used_mass", 0))
summary["trace_policy_used_bits"] = int(meta.get("trace_policy_used_bits", 0))
summary["trace_policy_override_bits"] = int(meta.get("trace_policy_override_bits", 0))
summary["trace_policy_override_mass"] = int(meta.get("trace_policy_override_mass", 0))
summary["trace_policy_override_reason_breakdown"] = dict(meta.get("trace_policy_override_reason_breakdown", {})) if isinstance(meta.get("trace_policy_override_reason_breakdown", {}), dict) else {}
summary["trace_uncovered_mode"] = str(meta.get("trace_uncovered_mode", ""))
summary["trace_divergence_policy"] = str(meta.get("trace_divergence_policy", ""))
summary["trace_divergence_bits"] = meta.get("trace_divergence_bits", 0)
summary["trace_divergence_mass"] = meta.get("trace_divergence_mass", 0)
summary["addr_fault_policy"] = str(meta.get("addr_fault_policy", ""))
summary["addr_due_mode"] = str(meta.get("addr_due_mode", ""))
summary["addr_bits_mode"] = str(meta.get("addr_bits_mode", ""))
summary["addr_bits_count"] = meta.get("addr_bits_count", 0)
summary["addr_effective_bits"] = meta.get("addr_effective_bits", "")
summary["addr_domain_bits"] = meta.get("addr_domain_bits", 0)
summary["addr_due_bits"] = meta.get("addr_due_bits", 0)
summary["addr_sdc_bits"] = meta.get("addr_sdc_bits", 0)
summary["addr_masked_bits"] = meta.get("addr_masked_bits", 0)
summary["addr_unknown_bits"] = meta.get("addr_unknown_bits", 0)
summary["smem_addr_exception_policy"] = str(meta.get("smem_addr_exception_policy", ""))
summary["smem_addr_domain_bits"] = meta.get("smem_addr_domain_bits", 0)
summary["smem_addr_due_bits"] = meta.get("smem_addr_due_bits", 0)
summary["smem_addr_sdc_bits"] = meta.get("smem_addr_sdc_bits", 0)
summary["smem_addr_masked_bits"] = meta.get("smem_addr_masked_bits", 0)
summary["smem_addr_unknown_bits"] = meta.get("smem_addr_unknown_bits", 0)
summary["smem_addr_range_source"] = str(meta.get("smem_addr_range_source", ""))
summary["smem_domain_policy"] = str(meta.get("smem_domain_policy", ""))
summary["smem_size_bits_source"] = str(meta.get("smem_size_bits_source", ""))
summary["smem_size_bits_final"] = int(meta.get("smem_size_bits_final", 0))
summary["smem_hw_size_bits"] = int(meta.get("smem_hw_size_bits", 0))
summary["smem_allocated_bits"] = int(meta.get("smem_allocated_bits", 0))
summary["smem_touched_bits"] = int(meta.get("smem_touched_bits", 0))
summary["smem_sampling_space_bits"] = int(meta.get("smem_sampling_space_bits", 0))
summary["rf_addr_reg_policy"] = str(meta.get("rf_addr_reg_policy", ""))
summary["rf_addr_reg_policy_effective"] = str(meta.get("rf_addr_reg_policy_effective", ""))
summary["rf_due_bits_by_cause"] = dict(meta.get("rf_due_bits_by_cause", {})) if isinstance(meta.get("rf_due_bits_by_cause", {}), dict) else {}
rf_sdc_proof_source_mass = meta.get("rf_sdc_proof_source_mass", {})
summary["rf_sdc_proof_source_mass"] = dict(rf_sdc_proof_source_mass) if isinstance(rf_sdc_proof_source_mass, dict) else {}
rf_sdc_proof_source_bits = meta.get("rf_sdc_proof_source_bits", {})
summary["rf_sdc_proof_source_bits"] = dict(rf_sdc_proof_source_bits) if isinstance(rf_sdc_proof_source_bits, dict) else {}
summary["rf_sdc_proof_source_policy"] = str(meta.get("rf_sdc_proof_source_policy", ""))
summary["rf_domain_sampling_bits"] = int(meta.get("rf_domain_sampling_bits", 0))
summary["rf_domain_derived_bits"] = int(meta.get("rf_domain_derived_bits", 0))
summary["rf_domain_mismatch"] = int(meta.get("rf_domain_mismatch", 0))
summary["smem_domain_sampling_bits"] = int(meta.get("smem_domain_sampling_bits", 0))
summary["smem_domain_derived_bits"] = int(meta.get("smem_domain_derived_bits", 0))
summary["smem_domain_mismatch"] = int(meta.get("smem_domain_mismatch", 0))
summary["domain_sampling_space_total_bits"] = int(meta.get("domain_sampling_space_total_bits", 0))
summary["domain_derived_total_bits"] = int(meta.get("domain_derived_total_bits", 0))
summary["domain_mismatch_bits"] = int(meta.get("domain_mismatch_bits", 0))
summary["mismatch_breakdown"] = dict(meta.get("mismatch_breakdown", {})) if isinstance(meta.get("mismatch_breakdown", {}), dict) else {}
summary["domain_reconciliation_method"] = str(meta.get("domain_reconciliation_method", ""))
summary["domain_reconciliation_unexplained_bits"] = int(meta.get("domain_reconciliation_unexplained_bits", 0))
summary["domain_reconciliation_non_live_masked_topup_bits"] = int(meta.get("domain_reconciliation_non_live_masked_topup_bits", 0))
summary["domain_reconciliation_addr_domain_excluded_bits"] = int(meta.get("domain_reconciliation_addr_domain_excluded_bits", 0))
summary["domain_reconciliation_failure_report_path"] = str(meta.get("domain_reconciliation_failure_report_path", ""))
summary["use_sampling_space_domain"] = bool(meta.get("use_sampling_space_domain", False))
summary["use_sampling_space_domain_rf"] = bool(meta.get("use_sampling_space_domain_rf", False))
summary["use_sampling_space_domain_smem"] = bool(meta.get("use_sampling_space_domain_smem", False))
summary["cache_tag_class_policy"] = str(meta.get("cache_tag_class_policy", ""))
summary["boundary_events_count"] = int(meta.get("boundary_events_count", 0))
summary["boundary_events_mass"] = meta.get("boundary_events_mass", 0)
summary["missing_active_thread_cycles"] = int(meta.get("missing_active_thread_cycles", 0))
summary["missing_active_thread_cycle_ratio"] = float(meta.get("missing_active_thread_cycle_ratio", 0.0))
summary["active_threads_carried_forward_cycles"] = int(meta.get("active_threads_carried_forward_cycles", 0))
summary["active_threads_empty_fill_cycles"] = int(meta.get("active_threads_empty_fill_cycles", 0))
summary["missing_active_threads_policy"] = str(meta.get("missing_active_threads_policy", ""))
unknown_source_bits = meta.get("unknown_source_bits", {})
summary["unknown_source_bits"] = dict(unknown_source_bits) if isinstance(unknown_source_bits, dict) else {}
unknown_mass_by_source = meta.get("unknown_mass_by_source", {})
summary["unknown_mass_by_source"] = dict(unknown_mass_by_source) if isinstance(unknown_mass_by_source, dict) else {}
summary["unknown_source_mass_method"] = str(meta.get("unknown_source_mass_method", ""))
due_source_bits = meta.get("due_source_bits", {})
summary["due_source_bits"] = dict(due_source_bits) if isinstance(due_source_bits, dict) else {}
due_mass_by_source = meta.get("due_mass_by_source", {})
summary["due_mass_by_source"] = dict(due_mass_by_source) if isinstance(due_mass_by_source, dict) else {}
summary["unknown_fold_target"] = str(meta.get("unknown_fold_target", ""))
summary["unknown_fold_mass"] = meta.get("unknown_fold_mass", 0)
summary["output_oracle_type"] = str(meta.get("output_oracle_type", ""))
summary["output_oracle_has_output_spec"] = bool(meta.get("output_oracle_has_output_spec", False))
summary["addr_observed_seed_suppressed_bits"] = int(meta.get("addr_observed_seed_suppressed_bits", 0))
summary["addr_observed_seed_suppressed_events"] = int(meta.get("addr_observed_seed_suppressed_events", 0))
summary["tol_output_store_seed_count"] = int(meta.get("tol_output_store_seed_count", 0))
summary["tol_float_backward_op_count"] = int(meta.get("tol_float_backward_op_count", 0))
summary["tol_memory_forward_byte_count"] = int(meta.get("tol_memory_forward_byte_count", 0))
summary["tol_exact_conversion_count"] = int(meta.get("tol_exact_conversion_count", 0))

with open(summary_path, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, sort_keys=False)
    f.write("\n")
PY

    if [[ "${FAULT_COMPONENT}" == "gmem" ]]; then
        write_gmem_exact_outputs || return $?
    elif [[ "${RUN_ANALYZER_WRITE_SINGLE_CSV}" == "1" ]]; then
        local single_csv=""
        single_csv="$(resolve_test_result_csv_path "$(build_exact_result_csv_filename "exact_result")")"
        run_timed "analyzer_merge_csv_cpp" "${EXACT_CORE_BIN}" rates-merge-csv \
            --summary "${CURRENT_RUN_DIR}/summary.json" \
            --output "${single_csv}" || return $?
        echo "Wrote CSV: ${single_csv}"
    fi

    if [[ "${analyzer_input_file}" != "${CURRENT_RUN_DIR}/analyzer_input.json" ]]; then
        ln -sfn "$(basename "${analyzer_input_file}")" "${CURRENT_RUN_DIR}/analyzer_input.json"
    fi
    if [[ "${analyzer_output_file}" != "${CURRENT_RUN_DIR}/analyzer_output.json" ]]; then
        ln -sfn "$(basename "${analyzer_output_file}")" "${CURRENT_RUN_DIR}/analyzer_output.json"
    fi
    if [[ "${exact_rates_file}" != "${CURRENT_RUN_DIR}/exact_rates.json" ]]; then
        ln -sfn "$(basename "${exact_rates_file}")" "${CURRENT_RUN_DIR}/exact_rates.json"
    fi

    LAST_SUMMARY_JSON="${CURRENT_RUN_DIR}/summary.json"
    return 0
}

run_common_capture_pipeline() {
    PROFILE_METRICS_READY=0
    PROFILE_METRICS_SOURCE=""
    PROFILE_THREAD_RAND_MAX=""
    PROFILE_WARP_RAND_MAX=""
    PROFILE_BLOCK_RAND_MAX=""
    PROFILE_DATATYPE_BITS=""
    PROFILE_SMEM_SIZE_BITS=""
    resolve_gpu_arch_auto
    build_project_if_needed
    start_fair_timing_now
    run_timed_shell "generate_results_if_needed" generate_results_if_needed || return $?
    run_timed_shell "prepare_case_files" prepare_case_files || return $?
    run_timed_shell "run_golden_and_collect" run_golden_and_collect || return $?
    run_timed_shell "run_exact_trace_capture" run_exact_trace_capture || return $?
    run_timed_shell "run_profile2_mean_active_threads" run_profile2_mean_active_threads || return $?
    run_timed_shell "prepare_fi_sampling_space_snapshot" prepare_fi_sampling_space_snapshot || return $?
}

run_pipeline() {
    run_common_capture_pipeline
    run_analyzer_pipeline
    echo "=== SARA artifacts saved in ${CURRENT_RUN_DIR} ==="
}

run_all_components_mode_core() {
    local saved_fault_component normalized_components
    local table_path comp status note display_name
    local comp_summary_json comp_summary_txt comp_exact_rates_json comp_analyzer_output_json
    local masked_rate sdc_rate due_rate unknown_rate
    local compact_mode
    local overall_total_s
    local has_step_times step_label step_seconds
    local progress_step progress_total
    local simple_summary_txt simple_summary_csv summary_line
    local overall_failed=0
    local component_status component_reason
    local active_log_input batch_manifest batch_output_dir
    local default_batch_analyzer batch_components_csv batch_l1d_shaders_arg
    local reuse_analyzer_dir=""
    local shared_analyzer_component=""
    local shared_analyzer_output_json=""
    local shared_analyzer_keep_read_events=0
    local shared_analyzer_force_rf_addr_masking=0
    local has_active_rf=0
    local has_active_memory=0
    local last_generated_comp=""
    local -a components=()
    local -a ordered_components=("rf" "smem_rf" "l1d" "l2")
    local -a active_components=()
    local -a batch_component_analyzer_args=()
    local -a simple_summary_lines=()
    declare -A comp_status_map=()
    declare -A comp_note_map=()
    declare -A comp_masked_map=()
    declare -A comp_sdc_map=()
    declare -A comp_due_map=()
    declare -A comp_unknown_map=()
    declare -A comp_summary_json_map=()

    saved_fault_component="${FAULT_COMPONENT}"
    compact_mode="${ALL_COMPONENTS_COMPACT_OUTPUT}"
    simple_summary_txt=""
    simple_summary_csv=""
    if ! is_bool_01 "${compact_mode}"; then
        echo "=== Error: ALL_COMPONENTS_COMPACT_OUTPUT must be 0 or 1 (got ${compact_mode}) ===" >&2
        exit 1
    fi
    if [[ "${compact_mode}" == "1" && -z "${QUIET_LOG_FILE}" ]]; then
        QUIET_LOG_FILE="$(ensure_quiet_log_file "${EXACT_WORK_ROOT}")"
    fi

    normalized_components="$(normalize_component_list "${ALL_COMPONENTS}")"
    IFS=':' read -r -a components <<< "${normalized_components}"
    if (( ${#components[@]} == 0 )); then
        echo "=== Error: no components to run in all_components mode ===" >&2
        exit 1
    fi

    progress_step=0
    progress_total=$(( (${#components[@]} * 2) + 3 ))
    if [[ "${compact_mode}" == "1" ]]; then
        progress_step=$((progress_step + 1))
        if [[ "${RUN_ALL_COMPONENTS_SKIP_COMMON_CAPTURE:-0}" == "1" ]]; then
            print_progress_hint "${progress_step}" "${progress_total}" "Reusing shared artifacts (trace/profile/fi-space)"
        else
            print_progress_hint "${progress_step}" "${progress_total}" "Preparing shared artifacts (build/result/golden/trace/profile)"
        fi
    fi
    if [[ "${RUN_ALL_COMPONENTS_SKIP_COMMON_CAPTURE:-0}" != "1" ]]; then
        if ! run_with_optional_quiet "${QUIET_LOG_FILE}" run_common_capture_pipeline; then
            if [[ "${compact_mode}" == "1" ]]; then
                report_quiet_failure "${QUIET_LOG_FILE}" "common pipeline"
            else
                echo "=== Error: common pipeline failed ===" >&2
            fi
            exit 1
        fi
    elif [[ -z "${CURRENT_RUN_DIR:-}" || ! -d "${CURRENT_RUN_DIR}" ]]; then
        echo "=== Error: all_components reuse mode requires prepared CURRENT_RUN_DIR ===" >&2
        exit 1
    fi

    table_path="${CURRENT_RUN_DIR}/${ALL_COMPONENTS_TABLE_BASENAME}"
    printf "component\tstatus\tmasked_rate\tsdc_rate\tdue_rate\tunknown_rate\tnote\n" > "${table_path}"

    if [[ "${compact_mode}" != "1" ]]; then
        echo "=== all_components summary ==="
        printf "%-18s %-8s %-14s %-14s %-14s %-14s %s\n" "component" "status" "masked_rate" "sdc_rate" "due_rate" "unknown_rate" "note"
    fi

    for comp in "${components[@]}"; do
        display_name="$(component_display_name "${comp}")"
        if [[ "${compact_mode}" == "1" ]]; then
            progress_step=$((progress_step + 1))
            print_progress_hint "${progress_step}" "${progress_total}" "Preparing analyzer for $(component_summary_label "${comp}")"
        fi

        if [[ "${comp}" == "smem_rf" || "${comp}" == "smem_lds" ]]; then
            if ! is_pos_int "${CURRENT_SMEM_SIZE_BITS}" || (( CURRENT_SMEM_SIZE_BITS <= 0 )); then
                comp_summary_json="${CURRENT_RUN_DIR}/summary_${comp}.json"
                comp_summary_txt="${CURRENT_RUN_DIR}/summary_${comp}.txt"
                comp_exact_rates_json="${CURRENT_RUN_DIR}/exact_rates_${comp}.json"
                comp_analyzer_output_json="${CURRENT_RUN_DIR}/analyzer_output_${comp}.json"
                write_skipped_component_artifacts \
                    "${comp}" \
                    "no_shared_memory_used" \
                    "${comp_summary_json}" \
                    "${comp_summary_txt}" \
                    "${comp_exact_rates_json}" \
                    "${comp_analyzer_output_json}"
                comp_status_map["${comp}"]="skip"
                comp_note_map["${comp}"]="no_shared_memory_used"
                comp_masked_map["${comp}"]="NA"
                comp_sdc_map["${comp}"]="NA"
                comp_due_map["${comp}"]="NA"
                comp_unknown_map["${comp}"]="NA"
                comp_summary_json_map["${comp}"]="${comp_summary_json}"
                continue
            fi
        fi

        active_components+=("${comp}")
        comp_status_map["${comp}"]="pending"
        comp_note_map["${comp}"]=""
        if [[ "${comp}" == "rf" ]]; then
            has_active_rf=1
        else
            has_active_memory=1
        fi
    done

    if (( ${#active_components[@]} > 0 )); then
        reuse_analyzer_dir="${RUN_ALL_COMPONENTS_REUSE_ANALYZER_FROM_DIR:-}"
        if [[ "${FRESH_RUN}" == "1" ]]; then
            reuse_analyzer_dir=""
        fi
        if [[ "${has_active_rf}" == "1" ]]; then
            shared_analyzer_component="rf"
        elif [[ "${has_active_memory}" == "1" ]]; then
            if [[ "$(resolve_current_app_shared_memory_usage)" == "1" ]]; then
                shared_analyzer_component="smem_rf"
            else
                shared_analyzer_component="l1d"
            fi
        else
            shared_analyzer_component="rf"
        fi
        if [[ "${has_active_rf}" == "1" && "${shared_analyzer_component}" != "rf" ]]; then
            shared_analyzer_keep_read_events=1
            shared_analyzer_force_rf_addr_masking=1
        fi

        if [[ -n "${reuse_analyzer_dir}" ]]; then
            if ! prepare_reused_analyzer_outputs_from_run_dir \
                "${reuse_analyzer_dir}" \
                "${CURRENT_RUN_DIR}" \
                "${shared_analyzer_component}" \
                "${active_components[@]}"; then
                overall_failed=1
                for comp in "${active_components[@]}"; do
                    comp_status_map["${comp}"]="error"
                    comp_note_map["${comp}"]="pipeline_failed"
                done
            else
                shared_analyzer_output_json="${CURRENT_RUN_DIR}/analyzer_output_${shared_analyzer_component}.json"
                for comp in "${active_components[@]}"; do
                    comp_analyzer_output_json="${CURRENT_RUN_DIR}/analyzer_output_${comp}.json"
                    batch_component_analyzer_args+=(--component-analyzer "${comp}=${shared_analyzer_output_json}")
                done
            fi
        else
            FAULT_COMPONENT="${shared_analyzer_component}"
            if ! RUN_ANALYZER_SKIP_EXACT_COMPUTE=1 \
                RUN_ANALYZER_WRITE_SINGLE_CSV=0 \
                RUN_ANALYZER_FORCE_KEEP_READ_EVENTS="${shared_analyzer_keep_read_events}" \
                RUN_ANALYZER_FORCE_RF_ADDR_MASKING="${shared_analyzer_force_rf_addr_masking}" \
                RUN_ANALYZER_FORCE_SHARED_COMPONENT_OUTPUT="${has_active_memory}" \
                run_with_optional_quiet "${QUIET_LOG_FILE}" run_analyzer_pipeline; then
                if [[ "${compact_mode}" == "1" ]]; then
                    report_quiet_failure "${QUIET_LOG_FILE}" "shared analyzer pipeline"
                fi
                overall_failed=1
                for comp in "${active_components[@]}"; do
                    comp_status_map["${comp}"]="error"
                    comp_note_map["${comp}"]="pipeline_failed"
                done
            else
                shared_analyzer_output_json="${CURRENT_RUN_DIR}/analyzer_output_${shared_analyzer_component}.json"
                if ! copy_analyzer_manifest_with_sidecar "${CURRENT_RUN_DIR}/analyzer_output.json" "${shared_analyzer_output_json}"; then
                    overall_failed=1
                    for comp in "${active_components[@]}"; do
                        comp_status_map["${comp}"]="error"
                        comp_note_map["${comp}"]="pipeline_failed"
                    done
                fi
                for comp in "${active_components[@]}"; do
                    comp_analyzer_output_json="${CURRENT_RUN_DIR}/analyzer_output_${comp}.json"
                    if [[ "${comp_analyzer_output_json}" != "${shared_analyzer_output_json}" ]]; then
                        link_or_symlink_file "${shared_analyzer_output_json}" "${comp_analyzer_output_json}"
                    fi
                    batch_component_analyzer_args+=(--component-analyzer "${comp}=${shared_analyzer_output_json}")
                done
            fi
        fi
    fi

    FAULT_COMPONENT="${saved_fault_component}"

    if (( ${#active_components[@]} > 0 )) && [[ -n "${shared_analyzer_output_json}" ]] && [[ "${overall_failed}" != "1" ]]; then
        active_log_input="${ACTIVE_THREADS_LOG:-}"
        if [[ -z "${active_log_input}" ]]; then
            active_log_input="${CURRENT_ACTIVE_THREADS_LOG}"
        fi
        batch_l1d_shaders_arg="${L1D_SHADERS:-auto}"
        if [[ -z "${batch_l1d_shaders_arg}" || "${batch_l1d_shaders_arg,,}" == "auto" ]]; then
            batch_l1d_shaders_arg="auto"
        elif [[ "${batch_l1d_shaders_arg,,}" == "all" ]]; then
            batch_l1d_shaders_arg="all"
        else
            batch_l1d_shaders_arg="$(normalize_shader_domain_spec "${batch_l1d_shaders_arg}")"
            if [[ -z "${batch_l1d_shaders_arg}" ]]; then
                echo "=== Error: invalid L1D_SHADERS='${L1D_SHADERS}' (expected auto|all|shader list) ===" >&2
                return 2
            fi
        fi
        batch_manifest="${CURRENT_RUN_DIR}/exact_rates_batch_manifest.json"
        batch_output_dir="${CURRENT_RUN_DIR}"
        default_batch_analyzer="${shared_analyzer_output_json}"
        batch_components_csv="$(IFS=,; echo "${active_components[*]}")"
        if [[ "${compact_mode}" == "1" ]]; then
            progress_step=$((progress_step + 1))
            print_progress_hint "${progress_step}" "${progress_total}" "Running shared exact compute"
        fi
        local -a batch_exact_compute_cmd=(
            python3
            script/SARA/exact_sdc_compute.py
            --analyzer-output "${default_batch_analyzer}"
            "${batch_component_analyzer_args[@]}"
            --batch-components "${batch_components_csv}"
            --batch-output-dir "${batch_output_dir}"
            --regfile-trace "${CURRENT_RUN_DIR}/regfile_trace.bin"
            --trace-template "${CURRENT_RUN_DIR}/analyzer_input.json"
            --cycles "${CURRENT_CYCLES_DOMAIN_FILE}"
            --active-threads-log "${active_log_input}"
            --thread-rand-max "${CURRENT_THREAD_RAND_MAX}"
            --block-rand-max "${CURRENT_BLOCK_RAND_MAX}"
            --smem-size-bits "${CURRENT_SMEM_SIZE_BITS}"
            --l1d-size-bits "${CURRENT_L1D_SIZE_BITS}"
            --l1d-line-size-bytes "${CURRENT_L1D_LINE_SIZE_BYTES}"
            --l1d-tag-bits "${CURRENT_L1D_TAG_BITS}"
            --l1d-include-tag-bits "$(get_json_field "${CURRENT_FI_SAMPLING_SPACE_JSON}" "l1d_include_tag_bits" "1")"
            --l1d-shaders "${batch_l1d_shaders_arg}"
            --l1d-write-allocate "${CURRENT_L1D_WRITE_ALLOCATE}"
            --l2-size-bits "${CURRENT_L2_SIZE_BITS}"
            --l2-tag-bits "${CURRENT_L2_TAG_BITS}"
            --l2-include-tag-bits "$(get_json_field "${CURRENT_FI_SAMPLING_SPACE_JSON}" "l2_include_tag_bits" "1")"
            --l2-line-size-bytes "${CURRENT_L2_LINE_SIZE_BYTES}"
            --l2-global-prefill "${CURRENT_L2_GLOBAL_PREFILL}"
            --registers "${CURRENT_REGISTER_DOMAIN_FILE}"
            --datatype-bits "${CURRENT_DATATYPE_BITS}"
            --storage-group-mode "${EXACT_STORAGE_GROUP_MODE}"
        )
        if [[ -n "${ADDR_VALID_RANGES_PATH:-}" ]]; then
            batch_exact_compute_cmd+=(--addr-valid-ranges-path "${ADDR_VALID_RANGES_PATH}")
        fi
        batch_exact_compute_cmd+=(
            --fi-sampling-space-path "${CURRENT_FI_SAMPLING_SPACE_JSON}"
            --cycles-domain-path "${CURRENT_CYCLES_DOMAIN_FILE}"
        )
        batch_exact_compute_cmd+=(-o "${batch_manifest}")
        local batch_cache_meta_file batch_cache_enabled batch_cache_force batch_global_cache_enabled
        local batch_compute_payload_tmp batch_compute_sig batch_compute_hit batch_compute_params_json
        local -a batch_compute_outputs=()
        local -a batch_compute_sig_inputs=()
        batch_cache_meta_file="$(cache_meta_path_for_dir "${CURRENT_RUN_DIR}")"
        batch_cache_enabled="${ANALYZER_CACHE_ENABLE}"
        batch_cache_force="${ANALYZER_CACHE_FORCE_REBUILD}"
        batch_global_cache_enabled="$(is_global_cache_enabled)"
        batch_compute_payload_tmp="$(mktemp)"
        batch_compute_outputs=("${batch_manifest}")
        batch_compute_sig_inputs=()
        for comp in "${active_components[@]}"; do
            comp_analyzer_output_json="${CURRENT_RUN_DIR}/analyzer_output_${comp}.json"
            if [[ -f "${comp_analyzer_output_json}" || -L "${comp_analyzer_output_json}" ]]; then
                batch_compute_sig_inputs+=("${comp_analyzer_output_json}")
                if [[ -f "${comp_analyzer_output_json}.bin" || -L "${comp_analyzer_output_json}.bin" ]]; then
                    batch_compute_sig_inputs+=("${comp_analyzer_output_json}.bin")
                fi
            fi
        done
        if (( ${#batch_compute_sig_inputs[@]} == 0 )); then
            batch_compute_sig_inputs=("${shared_analyzer_output_json}")
            if [[ -f "${shared_analyzer_output_json}.bin" || -L "${shared_analyzer_output_json}.bin" ]]; then
                batch_compute_sig_inputs+=("${shared_analyzer_output_json}.bin")
            fi
        fi
        for comp in "${active_components[@]}"; do
            batch_compute_outputs+=("${CURRENT_RUN_DIR}/exact_rates_${comp}.json")
        done
        batch_compute_params_json="$(printf '{"exact_semantics_profile":"%s","components":"%s","thread_rand_max":%s,"block_rand_max":%s,"smem_size_bits":%s,"l1d_size_bits":%s,"l1d_tag_bits":%s,"l1d_include_tag_bits":%s,"l1d_line_size_bytes":%s,"l1d_shaders":"%s","l1d_shaders_arg":"%s","l1d_write_allocate":%s,"l2_size_bits":%s,"l2_tag_bits":%s,"l2_include_tag_bits":%s,"l2_line_size_bytes":%s,"l2_global_prefill":%s,"datatype_bits":%s,"addr_valid_ranges_path":"%s","rf_domain_total_bits":%s,"smem_rf_domain_total_bits":%s,"l1d_domain_total_bits":%s,"l2_domain_total_bits":%s,"storage_group_mode":"%s"}' \
            "${EXACT_SEMANTICS_PROFILE}" "${batch_components_csv}" "${CURRENT_THREAD_RAND_MAX}" "${CURRENT_BLOCK_RAND_MAX}" "${CURRENT_SMEM_SIZE_BITS}" "${CURRENT_L1D_SIZE_BITS}" "${CURRENT_L1D_TAG_BITS}" "$(get_json_field "${CURRENT_FI_SAMPLING_SPACE_JSON}" "l1d_include_tag_bits" "1")" "${CURRENT_L1D_LINE_SIZE_BYTES}" "${CURRENT_L1D_SHADERS}" "${batch_l1d_shaders_arg}" "${CURRENT_L1D_WRITE_ALLOCATE}" "${CURRENT_L2_SIZE_BITS}" "${CURRENT_L2_TAG_BITS}" "$(get_json_field "${CURRENT_FI_SAMPLING_SPACE_JSON}" "l2_include_tag_bits" "1")" "${CURRENT_L2_LINE_SIZE_BYTES}" "${CURRENT_L2_GLOBAL_PREFILL}" "${CURRENT_DATATYPE_BITS}" "${ADDR_VALID_RANGES_PATH:-}" "$(get_json_field "${CURRENT_FI_SAMPLING_SPACE_JSON}" "rf_domain_total_bits" "0")" "$(get_json_field "${CURRENT_FI_SAMPLING_SPACE_JSON}" "smem_rf_domain_total_bits" "0")" "$(get_json_field "${CURRENT_FI_SAMPLING_SPACE_JSON}" "l1d_domain_total_bits" "0")" "$(get_json_field "${CURRENT_FI_SAMPLING_SPACE_JSON}" "l2_domain_total_bits" "0")" "${EXACT_STORAGE_GROUP_MODE}")"
        batch_compute_sig="$(cache_compute_signature "analyzer_exact_compute_batch" "${batch_compute_params_json}" "${batch_compute_payload_tmp}" \
            "${batch_compute_sig_inputs[@]}" \
            "${CURRENT_RUN_DIR}/analyzer_input.json" \
            "${CURRENT_TRACE_FILE}" \
            "${CURRENT_TRACE_FILE}.memory_ranges.json" \
            "${CURRENT_RUN_DIR}/regfile_trace.bin" \
            "${CURRENT_CYCLES_DOMAIN_FILE}" \
            "${active_log_input}" \
            "${CURRENT_REGISTER_DOMAIN_FILE}" \
            "script/SARA/exact_sdc_compute.py")"
        batch_compute_hit="0"
        if [[ "${batch_cache_enabled}" == "1" && "${batch_cache_force}" != "1" ]]; then
            batch_compute_hit="$(cache_step_hit "${batch_cache_meta_file}" "analyzer_exact_compute_batch" "${batch_compute_sig}" \
                "${batch_compute_outputs[@]}")"
        fi
        if [[ "${batch_compute_hit}" != "1" && "${batch_global_cache_enabled}" == "1" && "${batch_cache_force}" != "1" ]]; then
            batch_compute_hit="$(global_cache_try_restore "analyzer_exact_compute_batch" "${batch_compute_sig}" \
                "${batch_compute_outputs[@]}")"
            if [[ "${batch_compute_hit}" == "1" ]]; then
                echo "=== Global cache hit: analyzer_exact_compute_batch ==="
                if [[ "${batch_cache_enabled}" == "1" ]]; then
                    cache_step_update "${batch_cache_meta_file}" "analyzer_exact_compute_batch" "${batch_compute_sig}" "${batch_compute_payload_tmp}" \
                        "${batch_compute_outputs[@]}"
                fi
            fi
        fi
        if [[ "${batch_compute_hit}" == "1" ]]; then
            echo "=== Cache hit: analyzer_exact_compute_batch ==="
        elif ! run_timed "analyzer_exact_compute_py" "${batch_exact_compute_cmd[@]}"; then
            if [[ "${compact_mode}" == "1" ]]; then
                report_quiet_failure "${QUIET_LOG_FILE}" "shared exact compute"
            fi
            overall_failed=1
            for comp in "${active_components[@]}"; do
                if [[ "${comp_status_map[${comp}]:-pending}" == "pending" ]]; then
                    comp_status_map["${comp}"]="error"
                    comp_note_map["${comp}"]="pipeline_failed"
                fi
            done
        else
            if [[ "${batch_cache_enabled}" == "1" ]]; then
                cache_step_update "${batch_cache_meta_file}" "analyzer_exact_compute_batch" "${batch_compute_sig}" "${batch_compute_payload_tmp}" \
                    "${batch_compute_outputs[@]}"
            fi
            if [[ "${batch_global_cache_enabled}" == "1" ]]; then
                global_cache_store "analyzer_exact_compute_batch" "${batch_compute_sig}" "${batch_compute_payload_tmp}" \
                    "${batch_compute_outputs[@]}"
            fi
        fi
        rm -f "${batch_compute_payload_tmp}"
    fi

    for comp in "${components[@]}"; do
        display_name="$(component_display_name "${comp}")"
        status="${comp_status_map[${comp}]:-not_run}"
        note="${comp_note_map[${comp}]:-}"
        masked_rate="NA"
        sdc_rate="NA"
        due_rate="NA"
        unknown_rate="NA"

        if [[ "${status}" == "skip" ]]; then
            if [[ "${compact_mode}" != "1" ]]; then
                echo "=== ${display_name}: no shared-memory access detected; skipping ==="
                printf "%-18s %-8s %-14s %-14s %-14s %-14s %s\n" "${display_name}" "${status}" "${masked_rate}" "${sdc_rate}" "${due_rate}" "${unknown_rate}" "${note}"
            fi
            printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "${display_name}" "${status}" "${masked_rate}" "${sdc_rate}" "${due_rate}" "${unknown_rate}" "${note}" >> "${table_path}"
            continue
        fi

        if [[ "${compact_mode}" == "1" ]]; then
            progress_step=$((progress_step + 1))
            print_progress_hint "${progress_step}" "${progress_total}" "Summarizing $(component_summary_label "${comp}")"
        fi

        if [[ "${status}" == "error" && "${note}" == "pipeline_failed" ]]; then
            if [[ "${compact_mode}" != "1" ]]; then
                printf "%-18s %-8s %-14s %-14s %-14s %-14s %s\n" "${display_name}" "${status}" "${masked_rate}" "${sdc_rate}" "${due_rate}" "${unknown_rate}" "${note}"
            fi
            printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "${display_name}" "${status}" "${masked_rate}" "${sdc_rate}" "${due_rate}" "${unknown_rate}" "${note}" >> "${table_path}"
            comp_masked_map["${comp}"]="${masked_rate}"
            comp_sdc_map["${comp}"]="${sdc_rate}"
            comp_due_map["${comp}"]="${due_rate}"
            comp_unknown_map["${comp}"]="${unknown_rate}"
            continue
        fi

        comp_exact_rates_json="${CURRENT_RUN_DIR}/exact_rates_${comp}.json"
        comp_summary_json="${CURRENT_RUN_DIR}/summary_${comp}.json"
        comp_summary_txt="${CURRENT_RUN_DIR}/summary_${comp}.txt"
        if [[ ! -f "${comp_exact_rates_json}" ]]; then
            status="error"
            note="missing_exact_rates"
            overall_failed=1
        elif ! run_timed "analyzer_rates_summary_cpp" "${EXACT_CORE_BIN}" rates-summary \
            --input "${comp_exact_rates_json}" \
            --benchmark "${TEST_APP_NAME}" \
            --test-id "${CURRENT_TEST_ID}" \
            --output-json "${comp_summary_json}" \
            | tee "${comp_summary_txt}" >/dev/null; then
            status="error"
            note="summary_failed"
            overall_failed=1
        else
            comp_summary_json_map["${comp}"]="${comp_summary_json}"
            last_generated_comp="${comp}"
            IFS=$'\t' read -r component_status component_reason masked_rate sdc_rate due_rate unknown_rate < <(
                "${EXACT_CORE_BIN}" summary-status --input "${comp_summary_json}"
            )
            if [[ "${component_status}" != "ok" ]]; then
                status="error"
                note="${component_reason:-summary_error}"
                masked_rate="NA"
                sdc_rate="NA"
                due_rate="NA"
                unknown_rate="NA"
                overall_failed=1
            else
                status="ok"
                note=""
            fi
        fi

        if [[ "${compact_mode}" != "1" ]]; then
            printf "%-18s %-8s %-14s %-14s %-14s %-14s %s\n" "${display_name}" "${status}" "${masked_rate}" "${sdc_rate}" "${due_rate}" "${unknown_rate}" "${note}"
        fi
        printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "${display_name}" "${status}" "${masked_rate}" "${sdc_rate}" "${due_rate}" "${unknown_rate}" "${note}" >> "${table_path}"
        comp_status_map["${comp}"]="${status}"
        comp_note_map["${comp}"]="${note}"
        comp_masked_map["${comp}"]="${masked_rate}"
        comp_sdc_map["${comp}"]="${sdc_rate}"
        comp_due_map["${comp}"]="${due_rate}"
        comp_unknown_map["${comp}"]="${unknown_rate}"
    done

    if [[ -n "${last_generated_comp}" ]]; then
        ln -sfn "summary_${last_generated_comp}.json" "${CURRENT_RUN_DIR}/summary.json"
        ln -sfn "summary_${last_generated_comp}.txt" "${CURRENT_RUN_DIR}/summary.txt"
        ln -sfn "exact_rates_${last_generated_comp}.json" "${CURRENT_RUN_DIR}/exact_rates.json"
    fi

    if [[ "${compact_mode}" == "1" ]]; then
        progress_step="${progress_total}"
        print_progress_hint "${progress_step}" "${progress_total}" "Finalizing summary"
    fi

    FAULT_COMPONENT="${saved_fault_component}"
    if [[ "${compact_mode}" == "1" ]]; then
        simple_summary_txt="${CURRENT_RUN_DIR}/all_components_console_summary.txt"
        simple_summary_lines=()
        simple_summary_lines+=("Application Name: ${TEST_APP_NAME}")
        if [[ -n "${CURRENT_SIZE_LINE}" ]]; then
            simple_summary_lines+=("Input: ${CURRENT_SIZE_LINE}")
        else
            simple_summary_lines+=("Input: unavailable")
        fi
        simple_summary_lines+=("Inference Mode: canonical_proof")

        for comp in "${ordered_components[@]}"; do
            local summary_label status_v note_v masked_v sdc_v due_v unknown_v
            summary_label="$(component_summary_label "${comp}")"
            status_v="${comp_status_map[${comp}]:-not_run}"
            note_v="${comp_note_map[${comp}]:-}"
            masked_v="${comp_masked_map[${comp}]:-NA}"
            sdc_v="${comp_sdc_map[${comp}]:-NA}"
            due_v="${comp_due_map[${comp}]:-NA}"
            unknown_v="${comp_unknown_map[${comp}]:-NA}"

            if [[ "${comp}" == "smem_rf" || "${comp}" == "smem_lds" ]]; then
                if [[ "${status_v}" == "skip" && "${note_v}" == "no_shared_memory_used" ]]; then
                    simple_summary_lines+=("${summary_label}: not used")
                    continue
                fi
            fi
            if [[ "${status_v}" != "ok" ]]; then
                if [[ -n "${note_v}" ]]; then
                    simple_summary_lines+=("${summary_label}: unavailable (${note_v})")
                else
                    simple_summary_lines+=("${summary_label}: unavailable")
                fi
                continue
            fi
            simple_summary_lines+=("${summary_label}: Masked Rate=${masked_v} SDC Rate=${sdc_v} DUE Rate=${due_v} Unknown Rate=${unknown_v}")
        done

        simple_summary_lines+=("Step Times (s):")
        has_step_times=0
        while IFS=$'\t' read -r step_label step_seconds; do
            [[ -n "${step_label}" ]] || continue
            simple_summary_lines+=("${step_label}: ${step_seconds}")
            has_step_times=1
        done < <(collect_step_timing_lines_since_start)
        if [[ "${has_step_times}" != "1" ]]; then
            simple_summary_lines+=("none")
        fi
        overall_total_s="$(sum_step_timing_seconds_since_start)"
        simple_summary_lines+=("Total Time (s): ${overall_total_s}")

        printf '%s\n' "${simple_summary_lines[@]}" > "${simple_summary_txt}"

        echo "------------------------------------------------------------"
        for summary_line in "${simple_summary_lines[@]}"; do
            echo "${summary_line}"
        done
    else
        echo "=== Wrote all-components table: ${table_path} ==="
    fi
    if [[ -n "${simple_summary_txt}" && -f "${simple_summary_txt}" ]]; then
        simple_summary_csv="$(resolve_test_result_csv_path "$(build_exact_result_csv_filename "exact_result_simple")")"
        run_timed "analyzer_simple_summary_csv_cpp" "${EXACT_CORE_BIN}" rates-simple-summary-csv \
            --input "${simple_summary_txt}" \
            --output "${simple_summary_csv}" || overall_failed=1
        if [[ "${overall_failed}" != "1" ]]; then
            echo "=== Wrote simplified all-components CSV: ${simple_summary_csv} ==="
        fi
    fi
    if [[ "${overall_failed}" != "1" ]]; then
        local merged_csv required_comp
        merged_csv="$(resolve_test_result_csv_path "$(build_exact_result_csv_filename "exact_result")")"
        for required_comp in rf smem_rf l1d l2; do
            if [[ -z "${comp_summary_json_map[${required_comp}]:-}" || ! -f "${comp_summary_json_map[${required_comp}]}" ]]; then
                overall_failed=1
                echo "=== Error: missing summary for component ${required_comp}; cannot build merged CSV ===" >&2
                break
            fi
        done
        if [[ "${overall_failed}" != "1" ]]; then
            run_timed "analyzer_merge_components_csv_cpp" "${EXACT_CORE_BIN}" rates-merge-components-csv \
                --rf-summary "${comp_summary_json_map[rf]}" \
                --smem-rf-summary "${comp_summary_json_map[smem_rf]}" \
                --l1d-summary "${comp_summary_json_map[l1d]}" \
                --l2-summary "${comp_summary_json_map[l2]}" \
                --output "${merged_csv}" || overall_failed=1
            if [[ "${overall_failed}" != "1" ]]; then
                echo "=== Wrote merged all-components CSV: ${merged_csv} ==="
                echo "=== Storage-only SARA mode: pipeline component outputs removed ==="
            fi
            if [[ "${overall_failed}" != "1" ]]; then
                run_timed "analyzer_domain_reconciliation_report_py" \
                    python3 - "${CURRENT_RUN_DIR}/domain_reconciliation.json" \
                    "${comp_summary_json_map[rf]}" \
                    "${comp_summary_json_map[smem_rf]}" \
                    "${comp_summary_json_map[l1d]}" \
                    "${comp_summary_json_map[l2]}" <<'PY' || overall_failed=1
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
paths = {
    "rf": Path(sys.argv[2]),
    "smem_rf": Path(sys.argv[3]),
    "l1d": Path(sys.argv[4]),
    "l2": Path(sys.argv[5]),
}

def load(path: Path) -> dict:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return raw if isinstance(raw, dict) else {}

rows = {k: load(v) for k, v in paths.items()}
benchmark = ""
test_id = ""
for key in ("rf", "smem_rf", "l1d", "l2"):
    row = rows.get(key, {})
    if not benchmark:
        benchmark = str(row.get("benchmark", "")).strip()
    if not test_id:
        test_id = str(row.get("test_id", "")).strip()

components = {}
for comp in ("rf", "smem_rf", "l1d", "l2"):
    row = rows.get(comp, {})
    components[comp] = {
        "status": str(row.get("status", "unknown")),
        "strict_ok": bool(row.get("strict_ok", False)),
        "use_sampling_space_domain": bool(row.get("use_sampling_space_domain", False)),
        "use_sampling_space_domain_rf": bool(row.get("use_sampling_space_domain_rf", False)),
        "use_sampling_space_domain_smem": bool(row.get("use_sampling_space_domain_smem", False)),
        "domain_sampling_space_total_bits": int(row.get("domain_sampling_space_total_bits", 0) or 0),
        "domain_derived_total_bits": int(row.get("domain_derived_total_bits", 0) or 0),
        "domain_mismatch_bits": int(row.get("domain_mismatch_bits", 0) or 0),
        "rf_domain_sampling_bits": int(row.get("rf_domain_sampling_bits", 0) or 0),
        "rf_domain_derived_bits": int(row.get("rf_domain_derived_bits", 0) or 0),
        "rf_domain_mismatch": int(row.get("rf_domain_mismatch", 0) or 0),
        "smem_domain_sampling_bits": int(row.get("smem_domain_sampling_bits", 0) or 0),
        "smem_domain_derived_bits": int(row.get("smem_domain_derived_bits", 0) or 0),
        "smem_domain_mismatch": int(row.get("smem_domain_mismatch", 0) or 0),
        "mismatch_breakdown": (
            dict(row.get("mismatch_breakdown", {}))
            if isinstance(row.get("mismatch_breakdown", {}), dict)
            else {}
        ),
        "domain_reconciliation_method": str(row.get("domain_reconciliation_method", "")),
        "domain_reconciliation_unexplained_bits": int(row.get("domain_reconciliation_unexplained_bits", 0) or 0),
        "domain_reconciliation_non_live_masked_topup_bits": int(row.get("domain_reconciliation_non_live_masked_topup_bits", 0) or 0),
        "domain_reconciliation_addr_domain_excluded_bits": int(row.get("domain_reconciliation_addr_domain_excluded_bits", 0) or 0),
        "domain_reconciliation_failure_report_path": str(row.get("domain_reconciliation_failure_report_path", "")),
        "metadata_fault_policy": str(row.get("metadata_fault_policy", "")),
        "metadata_domain_bits": int(row.get("metadata_domain_bits", 0) or 0),
        "metadata_masked_bits": int(row.get("metadata_masked_bits", 0) or 0),
        "metadata_sdc_bits": int(row.get("metadata_sdc_bits", 0) or 0),
        "metadata_due_bits": int(row.get("metadata_due_bits", 0) or 0),
        "metadata_unknown_bits": int(row.get("metadata_unknown_bits", 0) or 0),
        "shader_scope_mode": str(row.get("shader_scope_mode", "")),
        "shader_scope_count": int(row.get("shader_scope_count", 0) or 0),
        "shader_scope_source": str(row.get("shader_scope_source", "")),
    }

payload = {
    "benchmark": benchmark,
    "test_id": test_id,
    "components": components,
}
out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(str(out_path))
PY
                if [[ "${overall_failed}" != "1" ]]; then
                    echo "=== Wrote domain reconciliation report: ${CURRENT_RUN_DIR}/domain_reconciliation.json ==="
                fi
            fi
        fi
    fi
    if [[ "${overall_failed}" != "1" && "${FAIR_TIMING}" == "1" && -n "${simple_summary_txt}" && -n "${simple_summary_csv}" ]]; then
        rewrite_simple_summary_total_time "${simple_summary_txt}" "${simple_summary_csv}"
    fi
    if [[ "${overall_failed}" == "1" ]]; then
        if [[ "${ALL_COMPONENTS_ALLOW_PARTIAL}" == "1" ]]; then
            echo "=== Warning: one or more components failed in all_components mode; returning partial summary (see ${table_path}) ===" >&2
            return 0
        fi
        echo "=== Error: one or more components failed in all_components mode (see ${table_path}) ===" >&2
        return 2
    fi
    return 0
}

run_all_components_mode() {
    RUN_ALL_COMPONENTS_SKIP_COMMON_CAPTURE=0 run_all_components_mode_core
}

run_validation_mode() {
    if [[ "${FAULT_COMPONENT}" != "rf" ]]; then
        echo "=== Error: validate mode is RF-only; got FAULT_COMPONENT=${FAULT_COMPONENT} ===" >&2
        exit 1
    fi
    run_pipeline

    echo "=== Validation mode: exhaustive restricted injection campaign ==="
    local cycles_spec threads_spec bits_spec regs_subset_file cycles_subset_file
    local -a cycles_subset=()
    local -a threads_subset=()
    local -a regs_subset=()
    local -a bits_subset=()

    mapfile -t cycles_subset < <(head -n "${VALIDATE_MAX_CYCLES}" "${CURRENT_RUN_DIR}/cycles_all.txt")
    if (( ${#cycles_subset[@]} == 0 )); then
        echo "=== Error: validation cycles subset is empty ===" >&2
        exit 1
    fi

    local t
    for ((t = 0; t < VALIDATE_MAX_THREADS; t++)); do
        threads_subset+=("${t}")
    done
    if (( ${#threads_subset[@]} == 0 )); then
        echo "=== Error: validation thread subset is empty ===" >&2
        exit 1
    fi

    ensure_current_register_domain_file
    mapfile -t regs_subset < <(head -n "${VALIDATE_MAX_REGS}" "${CURRENT_REGISTER_DOMAIN_FILE}")
    if (( ${#regs_subset[@]} == 0 )); then
        echo "=== Error: validation register subset is empty ===" >&2
        exit 1
    fi

    IFS=':,' read -r -a bits_subset <<< "${VALIDATE_BITS}"
    if (( ${#bits_subset[@]} == 0 )); then
        bits_subset=(1)
    fi

    cycles_spec="$(join_colon "${cycles_subset[@]}")"
    threads_spec="$(join_colon "${threads_subset[@]}")"
    bits_spec="$(join_colon "${bits_subset[@]}")"
    regs_subset_file="${CURRENT_RUN_DIR}/validation_registers.txt"
    cycles_subset_file="${CURRENT_RUN_DIR}/validation_cycles.txt"
    printf "%s\n" "${regs_subset[@]}" > "${regs_subset_file}"
    printf "%s\n" "${cycles_subset[@]}" > "${cycles_subset_file}"

    python3 script/SARA/exact_sdc_compute.py \
        --analyzer-output "${CURRENT_ANALYZER_OUTPUT_FILE:-${CURRENT_RUN_DIR}/analyzer_output.json}" \
        --regfile-trace "${CURRENT_RUN_DIR}/regfile_trace.bin" \
        --trace-template "${CURRENT_ANALYZER_INPUT_FILE:-${CURRENT_RUN_DIR}/analyzer_input.json}" \
        --cycles "${cycles_subset_file}" \
        --active-threads-log "${CURRENT_ACTIVE_THREADS_LOG}" \
        --thread-rands "${threads_spec}" \
        --l1d-size-bits "${CURRENT_L1D_SIZE_BITS:-0}" \
        --l1d-line-size-bytes "${CURRENT_L1D_LINE_SIZE_BYTES:-128}" \
        --l1d-tag-bits "${CURRENT_L1D_TAG_BITS:-57}" \
        --l1d-shaders "${CURRENT_L1D_SHADERS:-}" \
        --l1d-write-allocate "${CURRENT_L1D_WRITE_ALLOCATE:-0}" \
        --l2-size-bits "${CURRENT_L2_SIZE_BITS:-0}" \
        --l2-tag-bits "${CURRENT_L2_TAG_BITS:-57}" \
        --l2-line-size-bytes "${CURRENT_L2_LINE_SIZE_BYTES:-128}" \
        --l2-global-prefill "${CURRENT_L2_GLOBAL_PREFILL:-1}" \
        --registers "${regs_subset_file}" \
        --datatype-bits "${CURRENT_DATATYPE_BITS}" \
        --bits "${bits_spec}" \
        --fault-component "${FAULT_COMPONENT}" \
        ${ADDR_VALID_RANGES_PATH:+--addr-valid-ranges-path} \
        ${ADDR_VALID_RANGES_PATH:+${ADDR_VALID_RANGES_PATH}} \
        --fi-sampling-space-path "${CURRENT_FI_SAMPLING_SPACE_JSON}" \
        --cycles-domain-path "${CURRENT_CYCLES_DOMAIN_FILE}" \
        -o "${CURRENT_RUN_DIR}/expected_validation.json"

    update_config_line "-profile" "0"
    update_config_line "-components_to_flip" "0"
    update_config_line "-per_warp" "0"
    update_config_line "-kernel_n" "0"
    update_config_line "-register_rand_n" "1"
    update_config_line "-regfile_trace" "0"
    update_config_line "-exact_trace" "0"

    local val_dir="${CURRENT_RUN_DIR}/validation_logs"
    mkdir -p "${val_dir}"

    local masked=0
    local sdc=0
    local due=0
    local total=0
    local run_idx=0
    local cycle thread reg bit
    for cycle in "${cycles_subset[@]}"; do
        for thread in "${threads_subset[@]}"; do
            for reg in "${regs_subset[@]}"; do
                for bit in "${bits_subset[@]}"; do
                    run_idx=$((run_idx + 1))
                    total=$((total + 1))
                    local vlog="${val_dir}/run_${run_idx}_c${cycle}_t${thread}_r$(echo "${reg}" | tr '%' '_')_b${bit}.log"

                    update_config_line "-thread_rand" "${thread}"
                    update_config_line "-warp_rand" "0"
                    update_config_line "-total_cycle_rand" "${cycle}"
                    update_config_line "-register_name" "${reg}"
                    update_config_line "-reg_bitflip_rand_n" "${bit}"
                    timeout "${TIMEOUT_VAL}" "./${TEST_APP_NAME}" "${CURRENT_SIZE_ARGS[@]}" > "${vlog}" 2>&1 || true

                    local success_msg_grep cycles_grep failed_msg_grep result_key
                    if grep -a -iq "${SUCCESS_MSG}" "${vlog}"; then success_msg_grep=0; else success_msg_grep=1; fi
                    if grep -a -i "${CYCLES_MSG}" "${vlog}" | tail -1 | grep -a -q "${CURRENT_GOLDEN_CYCLES}"; then cycles_grep=0; else cycles_grep=1; fi
                    if grep -a -iq "${FAILED_MSG}" "${vlog}"; then failed_msg_grep=0; else failed_msg_grep=1; fi
                    result_key="${success_msg_grep}${cycles_grep}${failed_msg_grep}"

                    case "${result_key}" in
                        "001"|"011")
                            masked=$((masked + 1))
                            ;;
                        "100"|"110")
                            sdc=$((sdc + 1))
                            ;;
                        *)
                            if grep -a -iq "${FAULT_INJECTION_OCCURRED}" "${vlog}"; then
                                due=$((due + 1))
                            else
                                # Treat unknown outcomes as DUE in validation mode.
                                due=$((due + 1))
                            fi
                            ;;
                    esac
                done
            done
        done
    done

    local masked_rate sdc_rate due_rate
    masked_rate="$(awk -v a="${masked}" -v t="${total}" 'BEGIN{if(t==0)print 0; else printf "%.12f", a/t}')"
    sdc_rate="$(awk -v a="${sdc}" -v t="${total}" 'BEGIN{if(t==0)print 0; else printf "%.12f", a/t}')"
    due_rate="$(awk -v a="${due}" -v t="${total}" 'BEGIN{if(t==0)print 0; else printf "%.12f", a/t}')"

    cat > "${CURRENT_RUN_DIR}/measured_validation.json" <<EOF
{
  "classification_counts": {
    "masked": ${masked},
    "sdc": ${sdc},
    "due": ${due},
    "total": ${total}
  },
  "classification_rates": {
    "masked": ${masked_rate},
    "sdc": ${sdc_rate},
    "due": ${due_rate}
  }
}
EOF

    echo "=== Measured validation rates ==="
    "${EXACT_CORE_BIN}" rates-summary --input "${CURRENT_RUN_DIR}/measured_validation.json"

    echo "=== Comparing measured vs exact expected rates ==="
    "${EXACT_CORE_BIN}" rates-compare \
        --expected "${CURRENT_RUN_DIR}/expected_validation.json" \
        --measured "${CURRENT_RUN_DIR}/measured_validation.json" \
        --tolerance "${VALIDATE_TOL}"
}

collect_csv_entries_from_file() {
    local file="$1"
    while IFS= read -r line || [[ -n "${line}" ]]; do
        line="${line%%#*}"
        line="$(echo "${line}" | xargs)"
        [[ -n "${line}" ]] || continue
        echo "${line}"
    done < "${file}"
}

run_csv_mode() {
    local -a entries=()
    local -a summaries=()
    local entry app trace saved_app saved_trace
    saved_app="${TEST_APP_NAME}"
    saved_trace="${TRACE_TEMPLATE}"

    if (( $# > 0 )); then
        entries=("$@")
    elif [[ -n "${BENCH_LIST_FILE}" && -f "${BENCH_LIST_FILE}" ]]; then
        mapfile -t entries < <(collect_csv_entries_from_file "${BENCH_LIST_FILE}")
    else
        echo "=== Error: csv mode requires benchmark entries as args or BENCH_LIST_FILE ===" >&2
        exit 1
    fi

    local first=1
    for entry in "${entries[@]}"; do
        app="${entry}"
        trace="${saved_trace}"
        if [[ "${entry}" == *","* ]]; then
            app="${entry%%,*}"
            trace="${entry#*,}"
        elif [[ "${entry}" == *"="* ]]; then
            app="${entry%%=*}"
            trace="${entry#*=}"
        fi

        TEST_APP_NAME="$(echo "${app}" | xargs)"
        TRACE_TEMPLATE="$(echo "${trace}" | xargs)"
        if (( first == 0 )); then
            DO_BUILD=0
        fi
        run_pipeline
        summaries+=("${LAST_SUMMARY_JSON}")
        first=0
    done

    "${EXACT_CORE_BIN}" rates-merge-csv \
        --summary "${summaries[@]}" \
        --output "${CSV_OUTPUT}"

    TEST_APP_NAME="${saved_app}"
    TRACE_TEMPLATE="${saved_trace}"
    echo "=== Wrote SARA CSV: ${CSV_OUTPUT} ==="
}

main() {
    if ! is_bool_01 "${FAIR_TIMING}"; then
        echo "=== Error: FAIR_TIMING must be 0 or 1 (got ${FAIR_TIMING}) ===" >&2
        exit 1
    fi
    if ! is_bool_01 "${FRESH_RUN}"; then
        echo "=== Error: FRESH_RUN must be 0 or 1 (got ${FRESH_RUN}) ===" >&2
        exit 1
    fi
    if ! is_bool_01 "${PREBUILD_ONLY}"; then
        echo "=== Error: PREBUILD_ONLY must be 0 or 1 (got ${PREBUILD_ONLY}) ===" >&2
        exit 1
    fi
    if [[ "${PREBUILD_ONLY}" == "1" ]]; then
        exec bash "${STORAGE_APP_PREBUILD_HELPER}" "$@"
    fi
    if ! is_bool_01 "${ALL_COMPONENTS_COMPACT_OUTPUT}"; then
        echo "=== Error: ALL_COMPONENTS_COMPACT_OUTPUT must be 0 or 1 (got ${ALL_COMPONENTS_COMPACT_OUTPUT}) ===" >&2
        exit 1
    fi
    if ! is_bool_01 "${ANALYZER_INPUT_MANIFEST}"; then
        echo "=== Error: ANALYZER_INPUT_MANIFEST must be 0 or 1 (got ${ANALYZER_INPUT_MANIFEST}) ===" >&2
        exit 1
    fi
    if ! is_bool_01 "${ANALYZER_INPUT_BINARY}"; then
        echo "=== Error: ANALYZER_INPUT_BINARY must be 0 or 1 (got ${ANALYZER_INPUT_BINARY}) ===" >&2
        exit 1
    fi
    if ! is_bool_01 "${ANALYZER_INPUT_COLUMNAR}"; then
        echo "=== Error: ANALYZER_INPUT_COLUMNAR must be 0 or 1 (got ${ANALYZER_INPUT_COLUMNAR}) ===" >&2
        exit 1
    fi
    if ! is_bool_01 "${ANALYZER_INPUT_COMPAT_PICKLE_DICT}"; then
        echo "=== Error: ANALYZER_INPUT_COMPAT_PICKLE_DICT must be 0 or 1 (got ${ANALYZER_INPUT_COMPAT_PICKLE_DICT}) ===" >&2
        exit 1
    fi
    if ! is_bool_01 "${ANALYZER_OUTPUT_BINARY}"; then
        echo "=== Error: ANALYZER_OUTPUT_BINARY must be 0 or 1 (got ${ANALYZER_OUTPUT_BINARY}) ===" >&2
        exit 1
    fi
    if [[ "${ANALYZER_INPUT_BINARY}" == "1" && "${ANALYZER_INPUT_COLUMNAR}" != "1" && "${ANALYZER_INPUT_COMPAT_PICKLE_DICT}" != "1" ]]; then
        echo "=== Error: ANALYZER_INPUT_BINARY=1 requires ANALYZER_INPUT_COLUMNAR=1 or ANALYZER_INPUT_COMPAT_PICKLE_DICT=1 ===" >&2
        exit 1
    fi
    if [[ "${ANALYZER_INPUT_MANIFEST}" == "1" && "${ANALYZER_INPUT_BINARY}" == "1" ]]; then
        echo "=== Error: ANALYZER_INPUT_BINARY=1 is mutually exclusive with ANALYZER_INPUT_MANIFEST=1 ===" >&2
        exit 1
    fi
    if ! ensure_exact_storage_backend_binary; then
        exit 1
    fi
    if ! ensure_exact_core_binary; then
        exit 1
    fi
    if [[ -n "${EXACT_RESULT_VARIANT:-}" && ! ( "${FAULT_COMPONENT}" == "gmem" || "${MODE}" == "gmem" ) ]]; then
        echo "=== Error: EXACT_RESULT_VARIANT is deprecated for canonical exact; alternate exact outputs are no longer generated ===" >&2
        exit 1
    fi
    if ! is_bool_01 "${ALL_COMPONENTS_ALLOW_PARTIAL}"; then
        echo "=== Error: ALL_COMPONENTS_ALLOW_PARTIAL must be 0 or 1 (got ${ALL_COMPONENTS_ALLOW_PARTIAL}) ===" >&2
        exit 1
    fi
    if [[ "${MODE}" == "all_components" || "${MODE}" == "all" ]]; then
        if [[ "${ALL_COMPONENTS_COMPACT_OUTPUT}" == "1" ]]; then
            QUIET_CONSOLE_OUTPUT=1
            QUIET_LOG_FILE="$(ensure_quiet_log_file "${EXACT_WORK_ROOT}")"
            echo "[Progress] Verbose log: ${QUIET_LOG_FILE}"
        fi
    fi

    if [[ "${MODE}" == "run" ]]; then
        start_timing_session "run"
    elif [[ "${MODE}" == "all_components" || "${MODE}" == "all" ]]; then
        if [[ "${ALL_COMPONENTS_COMPACT_OUTPUT}" == "1" ]]; then
            start_timing_session "all_components"
        fi
    fi

    if [[ -z "${RESULT_DIR:-}" ]]; then
        RESULT_DIR="${EXACT_WORK_ROOT}/${TEST_APP_NAME}/${RESULT_BASENAME}"
        mkdir -p "${RESULT_DIR}"
    fi

    if [[ "${QUIET_CONSOLE_OUTPUT}" == "1" ]]; then
        echo "[Progress] Initializing simulator environment..."
        if ! run_timed_shell "setup_gpgpusim_environment" run_with_optional_quiet "${QUIET_LOG_FILE}" setup_gpgpusim_environment; then
            report_quiet_failure "${QUIET_LOG_FILE}" "environment setup"
            exit 1
        fi
        echo "[Progress] Environment setup completed."
    else
        if ! run_timed_shell "setup_gpgpusim_environment" setup_gpgpusim_environment; then
            exit 1
        fi
    fi
    if ! is_bool_01 "${ANALYZER_EMIT_CACHE_SITES}"; then
        echo "=== Error: ANALYZER_EMIT_CACHE_SITES must be 0 or 1 (got ${ANALYZER_EMIT_CACHE_SITES}) ===" >&2
        exit 1
    fi
    if [[ "${QUIET_CONSOLE_OUTPUT}" != "1" ]]; then
        echo "=== Running SARA mode=${MODE} app=${TEST_APP_NAME} ==="
        echo "=== Component mapping: 0=RF, 1=local_mem, 2=shared_mem, 3=L1D_cache, 4=L1C_cache, 5=L1T_cache, 6=L2_cache, 11=GMEM ==="
        echo "=== Injection bit flip count (convention): ${INJECT_BIT_FLIP_COUNT} ==="
        echo "=== sara_semantics_profile=${SARA_SEMANTICS_PROFILE} ==="
        echo "=== L1D shader scope mode: ${L1D_SHADERS} ==="
    fi

    case "${MODE}" in
        run)
            run_pipeline
            emit_timing_summary "run"
            ;;
        gmem)
            if [[ -z "${EXACT_RESULT_VARIANT}" ]]; then
                EXACT_RESULT_VARIANT="gmem"
            fi
            FAULT_COMPONENT="gmem"
            RUN_ANALYZER_WRITE_SINGLE_CSV=0
            run_pipeline
            emit_timing_summary "run"
            ;;
        validate)
            run_validation_mode
            ;;
        all_components|all)
            run_all_components_mode
            ;;
        csv)
            run_csv_mode "$@"
            ;;
        *)
            echo "Usage: $0 [run|gmem|validate|all_components|all|csv] [csv_entries...]" >&2
            echo "CSV entry format: BENCH,TRACE_TEMPLATE or BENCH=TRACE_TEMPLATE or BENCH" >&2
            exit 1
            ;;
    esac
}

if [[ "${EXACT_SDC_EXP_LIB_ONLY:-0}" == "1" ]]; then
    if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
        return 0
    fi
    exit 0
fi

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
