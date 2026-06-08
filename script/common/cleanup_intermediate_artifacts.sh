#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRATCH_DIR=""
ALL_KNOWN=0
KEEP_BUILD=1
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: script/common/cleanup_intermediate_artifacts.sh [options]

Remove generated intermediate artifacts while preserving source code, configs,
test_apps, and final public results under test_result/.

Options:
  --scratch DIR    Remove one experiment scratch directory (must be under .work/).
  --all-known      Also remove known historical run/cache/artifact directories.
  --drop-build     Remove build/ and lib/ outputs as well.
  --dry-run        Print removals without deleting.
  -h, --help       Show this help.
EOF
}

log_rm() {
  local target="$1"
  if [[ ! -e "${target}" && ! -L "${target}" ]]; then
    return 0
  fi
  if [[ "${DRY_RUN}" == "1" ]]; then
    echo "would remove ${target}"
  else
    rm -rf -- "${target}"
  fi
}

safe_remove_dir() {
  local target="$1"
  [[ -n "${target}" ]] || return 0
  local abs
  if [[ "${target}" = /* ]]; then
    abs="${target}"
  else
    abs="${ROOT_DIR}/${target}"
  fi
  case "${abs}" in
    "${ROOT_DIR}/.work"/*|"${ROOT_DIR}/.omx/tmp"/*|"${ROOT_DIR}/exact_sdc_runs"*|"${ROOT_DIR}/sara_sdc_runs"*|"${ROOT_DIR}/GEREM_runs"*|"${ROOT_DIR}/fi_storage_runs"*|"${ROOT_DIR}/storage_app_prebuilds"*|"${ROOT_DIR}/compare/raw_speed_artifacts"|"${ROOT_DIR}/tmp"|"${ROOT_DIR}/cache_logs"|"${ROOT_DIR}/checkpoint_files"|"${ROOT_DIR}/\$PROF")
      log_rm "${abs}"
      ;;
    *)
      echo "Refusing to remove unsafe directory: ${target}" >&2
      return 2
      ;;
  esac
}

prune_empty_work_parents() {
  local target="$1"
  [[ "${DRY_RUN}" != "1" ]] || return 0
  [[ -n "${target}" ]] || return 0
  local abs parent
  if [[ "${target}" = /* ]]; then
    abs="${target}"
  else
    abs="${ROOT_DIR}/${target}"
  fi
  case "${abs}" in
    "${ROOT_DIR}/.work"/*|"${ROOT_DIR}/.omx/tmp"/*)
      parent="$(dirname "${abs}")"
      while { [[ "${parent}" == "${ROOT_DIR}/.work"* ]] || [[ "${parent}" == "${ROOT_DIR}/.omx/tmp"* ]]; } && [[ "${parent}" != "${ROOT_DIR}" ]]; do
        rmdir "${parent}" 2>/dev/null || break
        [[ "${parent}" == "${ROOT_DIR}/.work" || "${parent}" == "${ROOT_DIR}/.omx/tmp" ]] && break
        parent="$(dirname "${parent}")"
      done
      ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scratch)
      SCRATCH_DIR="${2:-}"
      [[ -n "${SCRATCH_DIR}" ]] || { echo "--scratch requires a directory" >&2; exit 2; }
      shift 2
      ;;
    --all-known)
      ALL_KNOWN=1
      shift
      ;;
    --drop-build)
      KEEP_BUILD=0
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

cd "${ROOT_DIR}"

if [[ -n "${SCRATCH_DIR}" ]]; then
  safe_remove_dir "${SCRATCH_DIR}"
  prune_empty_work_parents "${SCRATCH_DIR}"
fi

# Root-level CUDA/app build products and simulator run byproducts.
find . -maxdepth 1 -type f \( \
  -name '_ptx*' -o \
  -name '_cuobjdump_*' -o \
  -name '_app_cuda*' -o \
  -name 'f_tempfile_ptx' -o \
  -name '*.ptx' -o \
  -name '*.ptxas' -o \
  -name '*.ptxas.rootbak' -o \
  -name '*.ptx.rootbak' -o \
  -name '*.rootbak' -o \
  -name '*.log' -o \
  -name '*_rerun.log' -o \
  -name 'cycles.txt' -o \
  -name 'inst_exec.log' -o \
  -name 'gpgpu_inst_stats.txt' -o \
  -name 'result.txt' -o \
  -name 'tmp.out' -o \
  -name 'register_used.txt' -o \
  -name '_app_cuda_version_*' -o \
  -name '_cuobjdump_list_ptx_*' \
\) -print0 | while IFS= read -r -d '' path; do log_rm "${path}"; done

# Root-level benchmark executables created during GPGPU-Sim runs.
if [[ -d test_apps ]]; then
  find test_apps -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | while IFS= read -r app; do
    [[ -n "${app}" ]] || continue
    if [[ -f "${ROOT_DIR}/${app}" && -x "${ROOT_DIR}/${app}" ]]; then
      log_rm "${ROOT_DIR}/${app}"
    fi
    log_rm "${ROOT_DIR}/${app}.cu"
    log_rm "${ROOT_DIR}/${app}.ptx"
    find "${ROOT_DIR}/test_apps/${app}" -mindepth 1 -maxdepth 1 -type d \( \
      -name 'result' -o \
      -name 'result.staging.*' -o \
      -name 'result.backup.*' \
    \) -print0 | while IFS= read -r -d '' path; do log_rm "${path}"; done
    log_rm "${ROOT_DIR}/test_apps/${app}/result"
  done
fi

# Root-level generated helper executable and simulator log/cache directories.
log_rm "${ROOT_DIR}/gen"
find . -maxdepth 1 -type d \( -name 'logs*' -o -name 'cache_logs' \) -print0 | while IFS= read -r -d '' path; do log_rm "${path}"; done

# Python and temporary caches.
find . -path './.git' -prune -o -type d -name '__pycache__' -print0 | while IFS= read -r -d '' path; do log_rm "${path}"; done
find . -path './.git' -prune -o -type f -name '*.pyc' -print0 | while IFS= read -r -d '' path; do log_rm "${path}"; done

if [[ "${ALL_KNOWN}" == "1" ]]; then
  for dir in \
    exact_sdc_runs exact_sdc_runs_all_fair exact_sdc_runs_gmem_all exact_sdc_runs_gmem_smoke exact_sdc_runs_renamed_test \
    GEREM_runs_all_fair storage_app_prebuilds_fair fi_storage_runs_all cache_logs tmp checkpoint_files \
    compare/raw_speed_artifacts '$PROF'; do
    [[ -e "${dir}" || -L "${dir}" ]] || continue
    safe_remove_dir "${dir}"
  done
fi

if [[ "${KEEP_BUILD}" == "0" ]]; then
  log_rm "${ROOT_DIR}/build"
  log_rm "${ROOT_DIR}/lib"
fi

if [[ "${DRY_RUN}" == "1" ]]; then
  echo "dry-run complete"
else
  echo "intermediate cleanup complete"
fi
