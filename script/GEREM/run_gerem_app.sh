#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMMON_DIR="${ROOT_DIR}/script/common"
cd "${ROOT_DIR}"

CONFIG_FILE="${CONFIG_FILE:-${ROOT_DIR}/gpgpusim.config}"
TEST_APP_NAME="${TEST_APP_NAME:-Pathfinder}"
RESULT_BASENAME="${RESULT_BASENAME:-0-0}"
GPU_ARCH="${GPU_ARCH:-auto}"
DO_BUILD="${DO_BUILD:-1}"
DO_RESULT_GEN="${DO_RESULT_GEN:-1}"
FAIR_TIMING="${FAIR_TIMING:-0}"
FRESH_RUN="${FRESH_RUN:-0}"
PREBUILD_ONLY="${PREBUILD_ONLY:-0}"
GEREM_WORK_ROOT="${GEREM_WORK_ROOT:-GEREM_runs_all}"
GEREM_RF_SMEM_TOOL="${GEREM_RF_SMEM_TOOL:-script/GEREM/gerem_storage_rf_smem.py}"
GEREM_CACHE_TOOL="${GEREM_CACHE_TOOL:-script/GEREM/gerem_storage_cache.py}"
GEREM_REPORT_TOOL="${GEREM_REPORT_TOOL:-script/GEREM/gerem_storage_report.py}"
GEREM_SAMPLING_SPACE_TOOL="${GEREM_SAMPLING_SPACE_TOOL:-script/GEREM/gerem_storage_sampling_space.py}"
GEREM_TIMING_FILE_BASENAME="${GEREM_TIMING_FILE_BASENAME:-timings_gerem.tsv}"
TIMEOUT_VAL="${TIMEOUT_VAL:-400s}"
EXACT_TRACE_JSONL="${EXACT_TRACE_JSONL:-0}"
STORAGE_APP_PREBUILD_HELPER="${STORAGE_APP_PREBUILD_HELPER:-${COMMON_DIR}/storage_app_prebuild.sh}"
UPDATE_SIMPLE_SUMMARY_TOTAL_TIME_TOOL="${UPDATE_SIMPLE_SUMMARY_TOTAL_TIME_TOOL:-script/common/update_simple_summary_total_time.py}"

CURRENT_RESULT_FILE=""
CURRENT_RUN_DIR="${GEREM_WORK_ROOT}/${TEST_APP_NAME}/${RESULT_BASENAME}"
CURRENT_TEST_ID="${RESULT_BASENAME}"
CURRENT_CU_FILE=""
CURRENT_SIZE_LINE=""
CURRENT_TRACE_FILE=""
CURRENT_TRACE_LOG=""
CURRENT_SIZE_ARGS=()
CURRENT_REGISTER_DOMAIN_FILE=""
CURRENT_FI_SAMPLING_SPACE_JSON=""
CURRENT_TRACE_TOTAL_CYCLES=0
CURRENT_TIMING_LOG_PATH=""
CURRENT_SIMPLE_SUMMARY_CSV=""
FAIR_TIMING_START_NS=""

resolve_test_result_csv_path() {
    local filename="$1"
    mkdir -p "${TEST_RESULT_ROOT:-test_result}/${TEST_APP_NAME}"
    echo "${TEST_RESULT_ROOT:-test_result}/${TEST_APP_NAME}/${filename}"
}

sanitize_tsv_field() {
    printf '%s' "${1//$'\t'/ }" | tr '\n' ' '
}

resolve_timing_log_path() {
    echo "${CURRENT_RUN_DIR}/${GEREM_TIMING_FILE_BASENAME}"
}

start_timing_session() {
    local _label="${1:-gerem_storage}"
    CURRENT_TIMING_LOG_PATH="$(resolve_timing_log_path)"
    mkdir -p "$(dirname "${CURRENT_TIMING_LOG_PATH}")"
    printf 'timestamp_iso\tstep_label\twall_s\tuser_s\tsys_s\tmaxrss_kb\texit_code\tcommand\n' > "${CURRENT_TIMING_LOG_PATH}"
}

ns_to_seconds() {
    local ns="${1:-0}"
    awk -v ns="${ns}" 'BEGIN { printf "%.9f", ns / 1000000000 }'
}

current_time_ns() {
    date +%s%N
}

sum_timing_log_seconds() {
    if [[ -z "${CURRENT_TIMING_LOG_PATH}" || ! -f "${CURRENT_TIMING_LOG_PATH}" ]]; then
        echo "0.000000"
        return 0
    fi
    python3 - "${CURRENT_TIMING_LOG_PATH}" <<'PY'
import csv
import sys

path = sys.argv[1]
total = 0.0
with open(path, newline="", encoding="utf-8", errors="replace") as handle:
    reader = csv.DictReader(handle, delimiter="\t")
    for row in reader:
        try:
            total += float(row.get("wall_s", 0) or 0.0)
        except Exception:
            pass
print(f"{total:.6f}")
PY
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
    sum_timing_log_seconds
}

rewrite_simple_summary_total_time() {
    local summary_path="${1:-}"
    local total_s
    if [[ -z "${summary_path}" || ! -f "${summary_path}" ]]; then
        return 0
    fi
    total_s="$(reported_total_time_seconds)"
    python3 "${UPDATE_SIMPLE_SUMMARY_TOTAL_TIME_TOOL}" \
        --summary "${summary_path}" \
        --total-seconds "${total_s}"
}

run_timed() {
    if (( $# < 2 )); then
        echo "run_timed requires <label> <command...>" >&2
        return 1
    fi
    local label="$1"
    shift
    local start_ns end_ns wall_ns wall_s timestamp rc
    start_ns="$(date +%s%N)"
    if "$@"; then
        rc=0
    else
        rc=$?
    fi
    end_ns="$(date +%s%N)"
    wall_ns=$((end_ns - start_ns))
    wall_s="$(ns_to_seconds "${wall_ns}")"
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '%s\t%s\t%s\t0\t0\t0\t%s\t%s\n' \
        "${timestamp}" \
        "$(sanitize_tsv_field "${label}")" \
        "${wall_s}" \
        "${rc}" \
        "$(sanitize_tsv_field "$*")" >> "${CURRENT_TIMING_LOG_PATH}"
    return "${rc}"
}

run_timed_shell() {
    if (( $# < 2 )); then
        echo "run_timed_shell requires <label> <function...>" >&2
        return 1
    fi
    local label="$1"
    shift
    run_timed "${label}" "$@"
}

is_pos_int() {
    [[ "${1:-}" =~ ^[0-9]+$ ]] && (( $1 > 0 ))
}

dir_has_entries() {
    local dir_path="$1"
    [[ -d "${dir_path}" ]] || return 1
    find "${dir_path}" -mindepth 1 -print -quit | grep -q .
}

replace_dir_contents() {
    local src_dir="$1"
    local dst_dir="$2"
    mkdir -p "${dst_dir}"
    find "${dst_dir}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    if dir_has_entries "${src_dir}"; then
        cp -a "${src_dir}/." "${dst_dir}/"
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

detect_gpu_arch_from_config() {
    local cfg="${1:-${CONFIG_FILE}}"
    local cap major minor
    [[ -f "${cfg}" ]] || { echo ""; return; }
    cap="$(awk '$1 == "-gpgpu_ptx_force_max_capability" {print $2; exit}' "${cfg}")"
    if [[ "${cap}" =~ ^[0-9]+$ ]]; then
        printf 'sm_%s' "${cap}"
        return
    fi
    major="$(awk '$1 == "-gpgpu_compute_capability_major" {print $2; exit}' "${cfg}")"
    minor="$(awk '$1 == "-gpgpu_compute_capability_minor" {print $2; exit}' "${cfg}")"
    if [[ "${major}" =~ ^[0-9]+$ && "${minor}" =~ ^[0-9]+$ ]]; then
        printf 'sm_%s%s' "${major}" "${minor}"
        return
    fi
    echo ""
}

resolve_gpu_arch_auto() {
    if [[ "${GPU_ARCH}" =~ ^sm_[0-9]+$ ]]; then
        return
    fi
    GPU_ARCH="$(detect_gpu_arch_from_config "${CONFIG_FILE}")"
    if [[ ! "${GPU_ARCH}" =~ ^sm_[0-9]+$ ]]; then
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

build_project_if_needed() {
    if [[ "${DO_BUILD}" -ne 1 ]]; then
        echo "=== Build skipped ==="
        return 0
    fi
    local build_jobs="${BUILD_JOBS:-$(nproc)}"
    if ! [[ "${build_jobs}" =~ ^[0-9]+$ ]] || (( build_jobs <= 0 )); then
        build_jobs=4
    fi
    if (( build_jobs > 8 )); then
        build_jobs=8
    fi
    echo "=== Start compiling ==="
    make clean >/dev/null 2>&1 || true
    make -j"${build_jobs}" > build.log 2>&1 || {
        echo "=== Build failed, showing errors ===" >&2
        grep -i "error" build.log >&2 || true
        return 1
    }
    echo "=== Make success ==="
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
    local newest_prereq=0 prereq_mtime=0 idx=0

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
            x_val="$(echo "${filename}" | sed -n "s/^${TEST_APP_NAME}_\([0-9]\+\)\.cu$/\1/p")"
            [[ -n "${x_val}" ]] || return 1
            out_path="${result_dir}/${idx}-${x_val}.txt"
            [[ -f "${out_path}" ]] || return 1
            out_mtime="$(stat -c %Y "${out_path}" 2>/dev/null || echo 0)"
            (( out_mtime >= newest_prereq )) || return 1
        done
    done
    return 0
}

generate_results_if_needed() {
    if [[ "${DO_RESULT_GEN}" -ne 1 ]]; then
        echo "=== Result generation skipped ==="
        return 0
    fi
    local app_dir="test_apps/${TEST_APP_NAME}"
    local size_list_file="${app_dir}/size_list.txt"
    local result_dir="${app_dir}/result"
    [[ -f "${size_list_file}" ]] || { echo "=== Error: size_list missing: ${size_list_file} ===" >&2; return 1; }

    if [[ "${FRESH_RUN}" == "1" ]]; then
        echo "=== Fresh-run mode: regenerating application inputs from scratch ==="
    elif result_generation_outputs_current "${app_dir}" "${size_list_file}" "${result_dir}"; then
        echo "=== Result generation skipped: existing outputs are up to date ==="
        return 0
    fi

    # Golden input generation must run with fault injection and tracing disabled.
    # This matches the SARA runner and avoids stale simulator options from a
    # previous campaign making ./gen require a native CUDA driver.
    update_config_line "-profile" "0"
    update_config_line "-components_to_flip" "0"
    update_config_line "-total_cycle_rand" "-1"
    update_config_line "-exact_trace" "0"
    update_config_line "-regfile_trace" "0"

    local staging_dir backup_dir idx=0 rc=0 generated_any=0
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
                # Execute generated CUDA input producers under GPGPU-Sim.
                # Using native CUDA libraries here incorrectly requires a real
                # GPU/driver and breaks simulator-only runs.
                if ./gen ${line} > "${staging_dir}/${idx}-${x_val}.txt"; then
                    :
                else
                    rc=$?
                fi
            else
                rc=$?
            fi
            if [[ "${rc}" -eq 0 ]]; then
                local tmpfile gpgpu_lines start_line end_line
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
    fi
    if [[ "${rc}" -ne 0 ]]; then
        replace_dir_contents "${backup_dir}" "${result_dir}"
        rm -rf "${staging_dir}" "${backup_dir}"
        echo "=== Error: result generation failed for ${TEST_APP_NAME} ===" >&2
        return "${rc}"
    fi
    replace_dir_contents "${staging_dir}" "${result_dir}"
    rm -rf "${staging_dir}" "${backup_dir}"
    echo "=== Result generation finished ==="
}

persist_current_register_domain_file() {
    local src_path="$1"
    mkdir -p "$(dirname "${CURRENT_REGISTER_DOMAIN_FILE}")"
    cp "${src_path}" "${CURRENT_REGISTER_DOMAIN_FILE}"
}

select_result_file() {
    local result_dir="test_apps/${TEST_APP_NAME}/result"
    [[ -d "${result_dir}" ]] || { echo "=== Error: result dir missing: ${result_dir} ===" >&2; return 1; }
    local candidate="${RESULT_BASENAME}"
    if [[ "${candidate}" != *.txt ]]; then
        candidate="${candidate}.txt"
    fi
    if [[ -f "${result_dir}/${candidate}" ]]; then
        CURRENT_RESULT_FILE="${result_dir}/${candidate}"
        return 0
    fi
    CURRENT_RESULT_FILE="$(find "${result_dir}" -maxdepth 1 -type f -name '*.txt' | sort | head -n1 || true)"
    [[ -n "${CURRENT_RESULT_FILE}" ]] || { echo "=== Error: no result files found under ${result_dir} ===" >&2; return 1; }
    echo "=== Warning: requested result not found; using $(basename "${CURRENT_RESULT_FILE}") ==="
}

prepare_case_files() {
    select_result_file
    local filename a b_with_ext b size_list_file
    filename="$(basename "${CURRENT_RESULT_FILE}")"
    a="$(echo "${filename}" | cut -d'-' -f1)"
    b_with_ext="$(echo "${filename}" | cut -d'-' -f2)"
    b="$(echo "${b_with_ext}" | cut -d'.' -f1)"
    CURRENT_TEST_ID="${a}-${b}"
    CURRENT_CU_FILE="test_apps/${TEST_APP_NAME}/inject_app/${TEST_APP_NAME}_${b}.cu"
    [[ -f "${CURRENT_CU_FILE}" ]] || { echo "=== Error: inject source not found: ${CURRENT_CU_FILE} ===" >&2; return 1; }

    size_list_file="test_apps/${TEST_APP_NAME}/size_list.txt"
    CURRENT_SIZE_LINE="$(awk "NR==$((a+1))" "${size_list_file}")"
    [[ -n "${CURRENT_SIZE_LINE}" ]] || { echo "=== Error: unable to read input args from ${size_list_file} ===" >&2; return 1; }
    read -r -a CURRENT_SIZE_ARGS <<< "${CURRENT_SIZE_LINE}"

    CURRENT_RUN_DIR="${GEREM_WORK_ROOT}/${TEST_APP_NAME}/${CURRENT_TEST_ID}"
    if [[ "${FRESH_RUN}" == "1" && -d "${CURRENT_RUN_DIR}" ]]; then
        local preserved_timing_log=""
        if [[ -n "${CURRENT_TIMING_LOG_PATH:-}" ]]; then
            preserved_timing_log="$(mktemp)"
            if [[ -f "${CURRENT_TIMING_LOG_PATH}" ]]; then
                cp "${CURRENT_TIMING_LOG_PATH}" "${preserved_timing_log}"
            fi
        fi
        rm -rf "${CURRENT_RUN_DIR}"
        mkdir -p "${CURRENT_RUN_DIR}"
        if [[ -n "${preserved_timing_log}" ]]; then
            mv -f "${preserved_timing_log}" "${CURRENT_TIMING_LOG_PATH}"
        fi
    else
        mkdir -p "${CURRENT_RUN_DIR}"
    fi
    CURRENT_REGISTER_DOMAIN_FILE="${CURRENT_RUN_DIR}/register_used.txt"

    cp "${CURRENT_RESULT_FILE}" ./result.txt
    if [[ "${FRESH_RUN}" != "1" && "${DO_BUILD}" -ne 1 && -x "./${TEST_APP_NAME}" && -f "${CURRENT_REGISTER_DOMAIN_FILE}" && -s "${CURRENT_REGISTER_DOMAIN_FILE}" ]]; then
        echo "=== Reusing existing ${TEST_APP_NAME} binary/register list from ${CURRENT_REGISTER_DOMAIN_FILE} (DO_BUILD=0) ==="
        return 0
    fi
    if [[ "${DO_BUILD}" -ne 1 && -x "./${TEST_APP_NAME}" && -f "./register_used.txt" && -s "./register_used.txt" ]]; then
        echo "=== Reusing existing ${TEST_APP_NAME} binary/root register list (DO_BUILD=0) ==="
        persist_current_register_domain_file "./register_used.txt"
        return 0
    fi
    if [[ "${DO_BUILD}" -ne 1 && -x "./${TEST_APP_NAME}" && -f "./${TEST_APP_NAME}.ptx" && -s "./${TEST_APP_NAME}.ptx" ]]; then
        echo "=== Reusing existing ${TEST_APP_NAME} binary/PTX and regenerating register list (DO_BUILD=0) ==="
        python3 extract_registers.py "${TEST_APP_NAME}"
        persist_current_register_domain_file "register_used.txt"
        return 0
    fi

    cp "${CURRENT_CU_FILE}" "./${TEST_APP_NAME}.cu"
    run_with_native_cuda_env nvcc "./${TEST_APP_NAME}.cu" -o "./${TEST_APP_NAME}" -g -lcudart -arch="${GPU_ARCH}"
    run_with_native_cuda_env nvcc -arch="${GPU_ARCH}" -ptx -g -lineinfo "./${TEST_APP_NAME}.cu" -o "./${TEST_APP_NAME}.ptx"
    python3 extract_registers.py "${TEST_APP_NAME}"
    persist_current_register_domain_file "register_used.txt"
}

run_trace_capture() {
    local trace_path active_path ranges_path cycles_all_path
    trace_path="${CURRENT_RUN_DIR}/inst_trace.json"
    active_path="${trace_path}.active_threads.jsonl"
    ranges_path="${trace_path}.memory_ranges.json"
    cycles_all_path="${CURRENT_RUN_DIR}/cycles_all.txt"
    CURRENT_TRACE_LOG="${CURRENT_RUN_DIR}/trace_capture.log"

    rm -f "${trace_path}" "${active_path}" "${ranges_path}" "${cycles_all_path}"

    echo "=== Running GEREM trace capture execution ==="
    update_config_line "-profile" "0"
    update_config_line "-components_to_flip" "0"
    update_config_line "-total_cycle_rand" "-1"
    update_config_line "-regfile_trace" "0"
    update_config_line "-exact_trace" "1"
    update_config_line "-exact_trace_file" "${trace_path}"
    update_config_line "-exact_trace_jsonl" "${EXACT_TRACE_JSONL}"

    timeout "${TIMEOUT_VAL}" "./${TEST_APP_NAME}" "${CURRENT_SIZE_ARGS[@]}" > "${CURRENT_TRACE_LOG}" 2>&1
    grep -a -iq "Fault Injection Test Success!" "${CURRENT_TRACE_LOG}" || {
        echo "=== Error: GEREM trace run did not report success ===" >&2
        return 1
    }
    [[ -f "${trace_path}" ]] || { echo "=== Error: trace file missing: ${trace_path} ===" >&2; return 1; }
    [[ -f "${active_path}" ]] || { echo "=== Error: active-thread trace missing: ${active_path} ===" >&2; return 1; }
    [[ -f "${ranges_path}" ]] || { echo "=== Error: memory-range sidecar missing: ${ranges_path} ===" >&2; return 1; }

    CURRENT_TRACE_TOTAL_CYCLES="$(grep -aE "^gpu_tot_sim_cycle[[:space:]]*=[[:space:]]*[0-9]+" "${CURRENT_TRACE_LOG}" | tail -n1 | sed -E 's/.*=[[:space:]]*([0-9]+).*/\1/')"
    if [[ -z "${CURRENT_TRACE_TOTAL_CYCLES}" ]]; then
        CURRENT_TRACE_TOTAL_CYCLES="$(grep -aE "^gpu_sim_cycle[[:space:]]*=[[:space:]]*[0-9]+" "${CURRENT_TRACE_LOG}" | tail -n1 | sed -E 's/.*=[[:space:]]*([0-9]+).*/\1/')"
    fi
    if [[ -z "${CURRENT_TRACE_TOTAL_CYCLES}" || ! "${CURRENT_TRACE_TOTAL_CYCLES}" =~ ^[0-9]+$ || "${CURRENT_TRACE_TOTAL_CYCLES}" -le 0 ]]; then
        CURRENT_TRACE_TOTAL_CYCLES="$(python3 - "${trace_path}" <<'PY'
import json, sys
raw = json.load(open(sys.argv[1], "r", encoding="utf-8"))
events = raw.get("events", []) if isinstance(raw, dict) else []
max_cycle = -1
for index, row in enumerate(events):
    if not isinstance(row, dict):
        continue
    cycle = row.get("cycle", index)
    try:
        cycle = int(cycle)
    except Exception:
        cycle = index
    if cycle > max_cycle:
        max_cycle = cycle
print(max(1, max_cycle + 1))
PY
)"
    fi
    seq 0 "$((CURRENT_TRACE_TOTAL_CYCLES - 1))" > "${cycles_all_path}"
    CURRENT_TRACE_FILE="${trace_path}"
}

build_sampling_space() {
    local app_info_file cycles_file
    app_info_file="test_apps/${TEST_APP_NAME}/app_info.txt"
    cycles_file="${CURRENT_RUN_DIR}/cycles_all.txt"
    CURRENT_FI_SAMPLING_SPACE_JSON="${CURRENT_RUN_DIR}/fi_sampling_space.json"
    python3 "${GEREM_SAMPLING_SPACE_TOOL}" \
        --trace-template "${CURRENT_TRACE_FILE}" \
        --trace-log "${CURRENT_TRACE_LOG}" \
        --config "${CONFIG_FILE}" \
        --app-info "${app_info_file}" \
        --register-domain-source "${CURRENT_REGISTER_DOMAIN_FILE}" \
        --cycles-file "${cycles_file}" \
        --output "${CURRENT_FI_SAMPLING_SPACE_JSON}"
    echo "=== Wrote GEREM sampling-space snapshot: ${CURRENT_FI_SAMPLING_SPACE_JSON} ==="
}

run_component_predictors() {
    local rf_json smem_json l1d_json l2_json
    rf_json="${CURRENT_RUN_DIR}/gerem_rf_component.json"
    smem_json="${CURRENT_RUN_DIR}/gerem_smem_component.json"
    l1d_json="${CURRENT_RUN_DIR}/gerem_l1d_component.json"
    l2_json="${CURRENT_RUN_DIR}/gerem_l2_component.json"

    run_timed "gerem_rf_predict_py" \
        python3 "${GEREM_RF_SMEM_TOOL}" \
        --component rf \
        --benchmark "${TEST_APP_NAME}" \
        --test-id "${CURRENT_TEST_ID}" \
        --trace-template "${CURRENT_TRACE_FILE}" \
        --fi-sampling-space "${CURRENT_FI_SAMPLING_SPACE_JSON}" \
        --output "${rf_json}"

    run_timed "gerem_smem_predict_py" \
        python3 "${GEREM_RF_SMEM_TOOL}" \
        --component smem_rf \
        --benchmark "${TEST_APP_NAME}" \
        --test-id "${CURRENT_TEST_ID}" \
        --trace-template "${CURRENT_TRACE_FILE}" \
        --fi-sampling-space "${CURRENT_FI_SAMPLING_SPACE_JSON}" \
        --output "${smem_json}"

    run_timed "gerem_l1d_predict_py" \
        python3 "${GEREM_CACHE_TOOL}" \
        --component l1d \
        --benchmark "${TEST_APP_NAME}" \
        --test-id "${CURRENT_TEST_ID}" \
        --trace-template "${CURRENT_TRACE_FILE}" \
        --fi-sampling-space "${CURRENT_FI_SAMPLING_SPACE_JSON}" \
        --output "${l1d_json}"

    run_timed "gerem_l2_predict_py" \
        python3 "${GEREM_CACHE_TOOL}" \
        --component l2 \
        --benchmark "${TEST_APP_NAME}" \
        --test-id "${CURRENT_TEST_ID}" \
        --trace-template "${CURRENT_TRACE_FILE}" \
        --fi-sampling-space "${CURRENT_FI_SAMPLING_SPACE_JSON}" \
        --output "${l2_json}"
}

write_final_reports() {
    local rf_json smem_json l1d_json l2_json result_csv simple_csv
    rf_json="${CURRENT_RUN_DIR}/gerem_rf_component.json"
    smem_json="${CURRENT_RUN_DIR}/gerem_smem_component.json"
    l1d_json="${CURRENT_RUN_DIR}/gerem_l1d_component.json"
    l2_json="${CURRENT_RUN_DIR}/gerem_l2_component.json"
    result_csv="$(resolve_test_result_csv_path "gerem_result_${TEST_APP_NAME}_${CURRENT_TEST_ID}.csv")"
    simple_csv="$(resolve_test_result_csv_path "gerem_result_simple_${TEST_APP_NAME}_${CURRENT_TEST_ID}.csv")"

    run_timed "gerem_report_merge_py" \
        python3 "${GEREM_REPORT_TOOL}" merge-components \
        --rf "${rf_json}" \
        --smem-rf "${smem_json}" \
        --l1d "${l1d_json}" \
        --l2 "${l2_json}" \
        --output "${result_csv}"

    run_timed "gerem_report_simple_py" \
        python3 "${GEREM_REPORT_TOOL}" simple-summary \
        --rf "${rf_json}" \
        --smem-rf "${smem_json}" \
        --l1d "${l1d_json}" \
        --l2 "${l2_json}" \
        --app "${TEST_APP_NAME}" \
        --test-id "${CURRENT_TEST_ID}" \
        --input-line "${CURRENT_SIZE_LINE}" \
        --parallel-workers 0 \
        --step-times "${CURRENT_TIMING_LOG_PATH}" \
        --output "${simple_csv}"
    CURRENT_SIMPLE_SUMMARY_CSV="${simple_csv}"

    echo "=== GEREM artifacts saved in ${CURRENT_RUN_DIR} ==="
    echo "=== Wrote GEREM CSV: ${result_csv} ==="
    echo "=== Wrote GEREM simple summary CSV: ${simple_csv} ==="
}

main() {
    [[ "${FAIR_TIMING}" =~ ^[01]$ ]] || { echo "=== Error: FAIR_TIMING must be 0 or 1 (got ${FAIR_TIMING}) ===" >&2; exit 1; }
    [[ "${FRESH_RUN}" =~ ^[01]$ ]] || { echo "=== Error: FRESH_RUN must be 0 or 1 (got ${FRESH_RUN}) ===" >&2; exit 1; }
    [[ "${PREBUILD_ONLY}" =~ ^[01]$ ]] || { echo "=== Error: PREBUILD_ONLY must be 0 or 1 (got ${PREBUILD_ONLY}) ===" >&2; exit 1; }
    if [[ "${PREBUILD_ONLY}" == "1" ]]; then
        exec bash "${STORAGE_APP_PREBUILD_HELPER}" "$@"
    fi
    [[ -f "${GEREM_RF_SMEM_TOOL}" ]] || { echo "=== Error: missing GEREM RF/SMEM tool: ${GEREM_RF_SMEM_TOOL} ===" >&2; exit 1; }
    [[ -f "${GEREM_CACHE_TOOL}" ]] || { echo "=== Error: missing GEREM cache tool: ${GEREM_CACHE_TOOL} ===" >&2; exit 1; }
    [[ -f "${GEREM_REPORT_TOOL}" ]] || { echo "=== Error: missing GEREM report tool: ${GEREM_REPORT_TOOL} ===" >&2; exit 1; }
    [[ -f "${GEREM_SAMPLING_SPACE_TOOL}" ]] || { echo "=== Error: missing GEREM sampling-space tool: ${GEREM_SAMPLING_SPACE_TOOL} ===" >&2; exit 1; }

    mkdir -p "${CURRENT_RUN_DIR}"
    start_timing_session "gerem_storage"
    run_timed_shell "setup_gpgpusim_environment" setup_gpgpusim_environment
    resolve_gpu_arch_auto
    run_timed_shell "build_project_if_needed" build_project_if_needed
    start_fair_timing_now
    run_timed_shell "generate_results_if_needed" generate_results_if_needed
    run_timed_shell "prepare_case_files" prepare_case_files
    run_timed_shell "run_trace_capture" run_trace_capture
    run_timed_shell "build_sampling_space" build_sampling_space
    run_component_predictors
    write_final_reports
    if [[ "${FAIR_TIMING}" == "1" && -n "${CURRENT_SIMPLE_SUMMARY_CSV}" ]]; then
        rewrite_simple_summary_total_time "${CURRENT_SIMPLE_SUMMARY_CSV}"
    fi
}

main "$@"
