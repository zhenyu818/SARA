#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${ROOT_DIR}"

CONFIG_FILE="${CONFIG_FILE:-${ROOT_DIR}/gpgpusim.config}"
TEST_APP_NAME="${TEST_APP_NAME:-Pathfinder}"
TEST_APPS_ROOT="${TEST_APPS_ROOT:-test_apps}"
RESULT_BASENAME="${RESULT_BASENAME:-0-0}"
GPU_ARCH="${GPU_ARCH:-auto}"
STORAGE_PREBUILD_CACHE_ROOT="${STORAGE_PREBUILD_CACHE_ROOT:-${ROOT_DIR}/storage_app_prebuilds}"

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
        return 0
    fi
    GPU_ARCH="$(detect_gpu_arch_from_config "${CONFIG_FILE}")"
    if [[ ! "${GPU_ARCH}" =~ ^sm_[0-9]+$ ]]; then
        GPU_ARCH="sm_75"
    fi
    echo "=== Resolved GPU_ARCH=${GPU_ARCH} from ${CONFIG_FILE} ==="
}

resolve_variant_suffix() {
    local candidate="${RESULT_BASENAME}"
    if [[ "${candidate}" == *.txt ]]; then
        candidate="${candidate%.txt}"
    fi
    if [[ "${candidate}" =~ ^val([0-9]+)$ ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
        return 0
    fi
    if [[ "${candidate}" =~ ^[0-9]+-([0-9]+)$ ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
        return 0
    fi
    echo "=== Error: unable to derive inject variant from RESULT_BASENAME=${RESULT_BASENAME} ===" >&2
    return 1
}

main() {
    setup_gpgpusim_environment
    resolve_gpu_arch_auto

    local variant_suffix current_cu cache_dir
    variant_suffix="$(resolve_variant_suffix)"
    current_cu="${TEST_APPS_ROOT}/${TEST_APP_NAME}/inject_app/${TEST_APP_NAME}_${variant_suffix}.cu"
    [[ -f "${current_cu}" ]] || { echo "=== Error: inject source not found: ${current_cu} ===" >&2; return 1; }

    cp "${current_cu}" "./${TEST_APP_NAME}.cu"
    run_with_native_cuda_env nvcc "./${TEST_APP_NAME}.cu" -o "./${TEST_APP_NAME}" -g -lcudart -arch="${GPU_ARCH}"
    run_with_native_cuda_env nvcc -arch="${GPU_ARCH}" -ptx -g -lineinfo "./${TEST_APP_NAME}.cu" -o "./${TEST_APP_NAME}.ptx"
    python3 extract_registers.py "${TEST_APP_NAME}"

    cache_dir="${STORAGE_PREBUILD_CACHE_ROOT}/${TEST_APP_NAME}/${RESULT_BASENAME}"
    mkdir -p "${cache_dir}"
    cp "./${TEST_APP_NAME}" "${cache_dir}/${TEST_APP_NAME}"
    cp "./${TEST_APP_NAME}.ptx" "${cache_dir}/${TEST_APP_NAME}.ptx"
    cp "./register_used.txt" "${cache_dir}/register_used.txt"

    local generator_cache_dir result_gen_cu filename x_val
    generator_cache_dir="${cache_dir}/result_generators"
    mkdir -p "${generator_cache_dir}"
    for result_gen_cu in "${TEST_APPS_ROOT}/${TEST_APP_NAME}/result_gen/${TEST_APP_NAME}_"*.cu; do
        [[ -f "${result_gen_cu}" ]] || continue
        filename="$(basename "${result_gen_cu}")"
        x_val="$(echo "${filename}" | sed -n "s/^${TEST_APP_NAME}_\([0-9]\+\)\.cu$/\1/p")"
        [[ -n "${x_val}" ]] || continue
        run_with_native_cuda_env nvcc "${result_gen_cu}" -o "${generator_cache_dir}/gen_${x_val}" -g -lcudart -arch="${GPU_ARCH}"
    done

    echo "=== Prebuilt ${TEST_APP_NAME} for RESULT_BASENAME=${RESULT_BASENAME} ==="
    echo "=== Cached prebuild artifacts in ${cache_dir} ==="
}

main "$@"
