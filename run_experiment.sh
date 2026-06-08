#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_DIR="${ROOT_DIR}/script"
cd "${ROOT_DIR}"

RESULT_ROOT="${RESULT_ROOT:-${ROOT_DIR}/sara-results}"
WORK_ROOT="${WORK_ROOT:-${ROOT_DIR}/.work}"
EXPERIMENT_RANDOM_SEED=2026
export EXPERIMENT_RANDOM_SEED
export PYTHONHASHSEED="${PYTHONHASHSEED:-2026}"
ARCH=""
METHOD=""
APP=""
RUNS="${RUN_PER_EPOCH:-1000}"
FI_PARALLEL_JOBS="${FI_PARALLEL_JOBS:-8}"
GEREM_RUNS="${GEREM_STORAGE_CAMPAIGN_RUNS:-1000}"
RUNS_SET=0
GEREM_RUNS_SET=0
KEEP_INTERMEDIATE=0
KEEP_INTERMEDIATE_SET=0
KEEP_BUILD=0
SKIP_COMMON_BUILD="${SKIP_COMMON_BUILD:-0}"
FORCE=0
FORCE_SET=0
LOG_FILE="${RUN_EXPERIMENT_LOG_FILE:-}"
LOG_WRITE_WARNED=0
ORIGINAL_ARGS=("$@")
PROGRESS_TOTAL_STAGES=1
PROGRESS_DONE_STAGES=0
PROGRESS_STAGE_ACTIVE=0
PROGRESS_STATUS=""
PROGRESS_TTY=0
PROGRESS_RENDERED=0
PROGRESS_PANEL_LINES=0
PROGRESS_CURRENT_ARCH_LABEL=""
PROGRESS_CURRENT_EXPERIMENT=""
PROGRESS_CURRENT_APP=""
PROGRESS_CURRENT_DETAIL=""
PROGRESS_CURRENT_TASK_KEY=""
PROGRESS_CURRENT_COMMAND=""
PROGRESS_CHILD_PHASE=""
PROGRESS_FI_DETAIL=""
PLAN_SYSTEM_UNITS_PER_ARCH=2
PLAN_ARCH_LABELS=()
PLAN_APPS=()
PLAN_EXPERIMENTS=()
PLAN_TASK_KEYS=()
PLAN_TASK_LABELS=()
declare -A PLAN_TASK_DONE=()

usage() {
  cat <<'EOF'
Usage: ./run_experiment.sh [options]

Unified public runner for SARA, FI, and GEREM storage-EFM sampling. Results are written under:
  sara-results/<Turing-RTX2060|Ampere-RTX3070>/<SARA|FI|GEREM-1000|GEREM-5000|GEREM-10000>/

Options:
  --arch turing|ampere|both  Target architecture/config.
  --method sara|sara-gerem-all|fi|gerem-all|all
                              Experiment family to run.
  --app NAME|all             One application or all test_apps (default: all).
                              This selects what to rerun; compare reports are
                              always refreshed for the full benchmark suite
                              from the current RESULT_ROOT data.
  --runs N                   FI runs per component (default: 1000).
                              FI trials inside one app/component run in parallel
                              with FI_PARALLEL_JOBS jobs (default: 8); apps and
                              storage components remain strictly serial.
  --gerem-runs 1000|5000|10000
                              GEREM storage-EFM random-sampling campaign count.
  --skip-build               Skip common simulator build.
  --keep-intermediate        Keep this run's .work scratch directories after completion.
  --discard-intermediate     Delete this run's .work scratch directories after completion.
  --keep-build               Keep generated build artifacts after completion.
  --force                    Remove existing selected final app results first.
  --smoke                    Convenience: --app AdamW --runs 1 --gerem-runs 1000.
  -h, --help                 Show this help.

Interactive mode:
  Run without --arch/--method to use an arrow-key menu. Use ↑/↓ or k/j to move,
  Enter to select. The menu selects architecture, method, app, overwrite
  behavior, FI run count when needed, and intermediate cleanup behavior.

Examples:
  ./run_experiment.sh --arch turing --method sara --app AdamW --smoke
  ./run_experiment.sh --arch ampere --method fi --runs 1000
  ./run_experiment.sh --arch turing --method gerem-all --gerem-runs 5000
  ./run_experiment.sh --arch both --method sara --app AdamW --smoke
EOF
}

option_value() {
  local item="$1"
  printf '%s' "${item%%::*}"
}

option_label() {
  local item="$1"
  if [[ "${item}" == *"::"* ]]; then
    printf '%s' "${item#*::}"
  else
    printf '%s' "${item}"
  fi
}

require_option_value() {
  local opt="$1"
  local value="${2:-}"
  if [[ -z "${value}" || "${value}" == --* ]]; then
    echo "Missing value for ${opt}" >&2
    usage >&2
    exit 2
  fi
  printf '%s' "${value}"
}

arrow_select() {
  local var_name="$1"
  local prompt="$2"
  local selected="${3:-0}"
  shift 3
  local options=("$@")
  local count="${#options[@]}"
  local key rest i label

  if (( count == 0 )); then
    echo "No options available for ${prompt}" >&2
    exit 2
  fi
  if (( selected < 0 || selected >= count )); then
    selected=0
  fi
  if [[ ! -t 0 ]]; then
    printf -v "${var_name}" '%s' "$(option_value "${options[${selected}]}")"
    return 0
  fi

  echo "${prompt}" >&2
  for ((i = 0; i < count; i++)); do
    label="$(option_label "${options[${i}]}")"
    if (( i == selected )); then
      printf >&2 '\033[7m> %s\033[0m\n' "${label}"
    else
      printf >&2 '  %s\n' "${label}"
    fi
  done

  while true; do
    IFS= read -rsn1 key
    case "${key}" in
      "")
        break
        ;;
      $'\x1b')
        IFS= read -rsn2 -t 0.1 rest || rest=""
        case "${rest}" in
          "[A") selected=$(( (selected + count - 1) % count )) ;;
          "[B") selected=$(( (selected + 1) % count )) ;;
        esac
        ;;
      k|K)
        selected=$(( (selected + count - 1) % count ))
        ;;
      j|J)
        selected=$(( (selected + 1) % count ))
        ;;
    esac

    printf >&2 '\033[%dA' "${count}"
    for ((i = 0; i < count; i++)); do
      label="$(option_label "${options[${i}]}")"
      printf >&2 '\r\033[K'
      if (( i == selected )); then
        printf >&2 '\033[7m> %s\033[0m\n' "${label}"
      else
        printf >&2 '  %s\n' "${label}"
      fi
    done
  done

  label="$(option_label "${options[${selected}]}")"
  printf >&2 'Selected: %s\n\n' "${label}"
  printf -v "${var_name}" '%s' "$(option_value "${options[${selected}]}")"
}

choose_if_empty() {
  local var_name="$1"
  local prompt="$2"
  shift 2
  local options=("$@")
  local current="${!var_name}"
  if [[ -n "${current}" ]]; then
    return 0
  fi
  if [[ ! -t 0 ]]; then
    echo "Missing required --${var_name,,}; valid values: ${options[*]}" >&2
    exit 2
  fi
  arrow_select "${var_name}" "${prompt}" 0 "${options[@]}"
}

choose_app_if_empty() {
  if [[ -n "${APP}" ]]; then
    return 0
  fi
  if [[ ! -t 0 ]]; then
    APP="all"
    return 0
  fi
  local app_names=()
  local app_options=("all::All applications")
  local app
  mapfile -t app_names < <(find "${ROOT_DIR}/test_apps" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)
  for app in "${app_names[@]}"; do
    app_options+=("${app}::${app}")
  done
  arrow_select APP "Select application:" 0 "${app_options[@]}"
}

method_runs_sara() {
  [[ "${METHOD}" == "sara" || "${METHOD}" == "sara-gerem-all" || "${METHOD}" == "all" ]]
}

method_runs_gerem() {
  [[ "${METHOD}" == "gerem-all" || "${METHOD}" == "sara-gerem-all" || "${METHOD}" == "all" ]]
}

method_runs_fi() {
  [[ "${METHOD}" == "fi" || "${METHOD}" == "all" ]]
}

log_line() {
  if [[ -n "${LOG_FILE:-}" ]]; then
    local log_dir
    log_dir="$(dirname "${LOG_FILE}")"
    mkdir -p "${log_dir}" 2>/dev/null || true
    if ! printf '%s\n' "$*" >> "${LOG_FILE}" 2>/dev/null; then
      if [[ "${LOG_WRITE_WARNED}" != "1" ]]; then
        printf '%s\n' "=== Warning: cannot append to run log ${LOG_FILE}; continuing without file log until it becomes writable. ===" >&2
        LOG_WRITE_WARNED=1
      fi
    fi
  fi
}

notice_line() {
  log_line "$*"
  printf '%s\n' "$*" >&2
}

init_run_log() {
  if [[ -z "${LOG_FILE:-}" ]]; then
    local log_root
    log_root="${RUN_EXPERIMENT_LOG_ROOT:-${RESULT_ROOT}/logs}"
    LOG_FILE="${log_root}/run_experiment_${METHOD}_${TIMESTAMP}.log"
  fi

  local requested_log_file="${LOG_FILE}"
  local requested_log_dir
  requested_log_dir="$(dirname "${requested_log_file}")"
  if ! mkdir -p "${requested_log_dir}" 2>/dev/null || ! : > "${requested_log_file}" 2>/dev/null; then
    local fallback_root fallback_file
    fallback_root="${RUN_EXPERIMENT_FALLBACK_LOG_ROOT:-${WORK_ROOT}/logs}"
    fallback_file="${fallback_root}/run_experiment_${METHOD}_${TIMESTAMP}.log"
    if ! mkdir -p "${fallback_root}" 2>/dev/null || ! : > "${fallback_file}" 2>/dev/null; then
      fallback_root="${TMPDIR:-/tmp}/sdc_compute_once_logs"
      fallback_file="${fallback_root}/run_experiment_${METHOD}_${TIMESTAMP}.log"
      mkdir -p "${fallback_root}"
      : > "${fallback_file}"
    fi
    LOG_FILE="${fallback_file}"
    printf '%s\n' "=== Warning: requested log file is not writable; using ${LOG_FILE} instead of ${requested_log_file} ===" >&2
  fi
  log_line "=== run_experiment.sh started at $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
  log_line "command=$0 $*"
}

arch_label_for_value() {
  case "$1" in
    turing) echo "Turing-RTX2060" ;;
    ampere) echo "Ampere-RTX3070" ;;
    *) echo "$1" ;;
  esac
}

selected_app_list() {
  if [[ "${APP}" != "all" ]]; then
    printf '%s\n' "${APP}"
    return 0
  fi
  all_app_list
}

all_app_list() {
  find "${ROOT_DIR}/test_apps" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort
}

gerem_result_dir_name() {
  echo "GEREM-${GEREM_RUNS}"
}

gerem_compare_slug() {
  echo "gerem${GEREM_RUNS}"
}

sara_result_dir_name() {
  echo "SARA"
}

sara_compare_output_name() {
  echo "sara_$(gerem_compare_slug)_vs_fi.txt"
}

sara_compare_label() {
  echo "SARA"
}

selected_experiment_list() {
  if method_runs_sara; then
    sara_result_dir_name
  fi
  if method_runs_gerem; then
    gerem_result_dir_name
  fi
  if method_runs_fi; then
    echo "FI-storage"
  fi
}

join_with_commas_limited() {
  local max_count="$1"
  shift
  local total="$#" shown=0 item out=""
  for item in "$@"; do
    (( shown < max_count )) || break
    if [[ -n "${out}" ]]; then
      out+=", "
    fi
    out+="${item}"
    shown=$((shown + 1))
  done
  if (( total > shown )); then
    if [[ -n "${out}" ]]; then
      out+=", "
    fi
    out+="...(+ $((total - shown)))"
  fi
  printf '%s' "${out}"
}

ellipsize() {
  local text="$1" max_len="${2:-100}"
  if (( ${#text} > max_len )); then
    printf '%s...' "${text:0:$((max_len - 3))}"
  else
    printf '%s' "${text}"
  fi
}

progress_bar() {
  local current="$1" total="$2" width="${3:-34}"
  local filled empty
  if (( total <= 0 )); then
    total=1
  fi
  if (( current < 0 )); then
    current=0
  fi
  if (( current > total )); then
    current="${total}"
  fi
  filled=$(( current * width / total ))
  empty=$(( width - filled ))
  printf '%*s' "${filled}" '' | tr ' ' '#'
  printf '%*s' "${empty}" '' | tr ' ' '-'
}

make_task_key() {
  printf '%s|%s|%s' "$1" "$2" "$3"
}

make_task_label() {
  printf '%s › %s › %s' "$1" "$2" "$3"
}

mark_task_done_by_key() {
  local key="$1"
  if [[ -z "${key}" || "${PLAN_TASK_DONE[${key}]:-0}" == "1" ]]; then
    return 0
  fi
  PLAN_TASK_DONE["${key}"]=1
  PROGRESS_DONE_STAGES=$((PROGRESS_DONE_STAGES + 1))
}

mark_task_done() {
  local arch_label="$1" experiment="$2" app_name="$3"
  local key
  key="$(make_task_key "${arch_label}" "${experiment}" "${app_name}")"
  mark_task_done_by_key "${key}"
}

mark_current_task_done() {
  if [[ -n "${PROGRESS_CURRENT_TASK_KEY}" ]]; then
    mark_task_done_by_key "${PROGRESS_CURRENT_TASK_KEY}"
  elif [[ -n "${PROGRESS_CURRENT_ARCH_LABEL}" && -n "${PROGRESS_CURRENT_EXPERIMENT}" && -n "${PROGRESS_CURRENT_APP}" ]]; then
    mark_task_done "${PROGRESS_CURRENT_ARCH_LABEL}" "${PROGRESS_CURRENT_EXPERIMENT}" "${PROGRESS_CURRENT_APP}"
  fi
}

mark_all_experiment_tasks_done() {
  local arch_label="$1" experiment="$2" app_name
  [[ -n "${arch_label}" && -n "${experiment}" ]] || return 0
  for app_name in "${PLAN_APPS[@]}"; do
    mark_task_done "${arch_label}" "${experiment}" "${app_name}"
  done
}

progress_system_unit_done() {
  PROGRESS_DONE_STAGES=$((PROGRESS_DONE_STAGES + 1))
  if (( PROGRESS_DONE_STAGES > PROGRESS_TOTAL_STAGES )); then
    PROGRESS_DONE_STAGES="${PROGRESS_TOTAL_STAGES}"
  fi
}

progress_child_app_start() {
  local app_index="$1" app_total="$2" app_name="$3"
  if [[ -n "${PROGRESS_CURRENT_EXPERIMENT}" && -n "${PROGRESS_CURRENT_APP}" && "${PROGRESS_CURRENT_APP}" != "${app_name}" ]]; then
    mark_current_task_done
  fi
  PROGRESS_CURRENT_APP="${app_name}"
  if [[ -n "${PROGRESS_CURRENT_ARCH_LABEL}" && -n "${PROGRESS_CURRENT_EXPERIMENT}" ]]; then
    PROGRESS_CURRENT_TASK_KEY="$(make_task_key "${PROGRESS_CURRENT_ARCH_LABEL}" "${PROGRESS_CURRENT_EXPERIMENT}" "${app_name}")"
  fi
  PROGRESS_CURRENT_DETAIL="app ${app_index}/${app_total} ${app_name}"
  PROGRESS_CHILD_PHASE="prebuild"
}

progress_arch_position() {
  local idx
  for idx in "${!PLAN_ARCH_LABELS[@]}"; do
    if [[ "${PLAN_ARCH_LABELS[${idx}]}" == "${PROGRESS_CURRENT_ARCH_LABEL}" ]]; then
      printf '%s/%s' "$((idx + 1))" "${#PLAN_ARCH_LABELS[@]}"
      return 0
    fi
  done
  printf -- '-/%s' "${#PLAN_ARCH_LABELS[@]}"
}

progress_pending_preview() {
  local max_count="${1:-4}" shown=0 idx key label out=""
  for idx in "${!PLAN_TASK_KEYS[@]}"; do
    key="${PLAN_TASK_KEYS[${idx}]}"
    [[ "${PLAN_TASK_DONE[${key}]:-0}" != "1" ]] || continue
    [[ "${key}" != "${PROGRESS_CURRENT_TASK_KEY}" ]] || continue
    label="${PLAN_TASK_LABELS[${idx}]}"
    if [[ -n "${out}" ]]; then
      out+="; "
    fi
    out+="${label}"
    shown=$((shown + 1))
    (( shown >= max_count )) && break
  done
  if [[ -z "${out}" ]]; then
    out="none"
  fi
  printf '%s' "${out}"
}

progress_clear_line() {
  local i
  if (( PROGRESS_TTY == 1 && PROGRESS_RENDERED == 1 && PROGRESS_PANEL_LINES > 0 )); then
    printf '\033[%dA' "${PROGRESS_PANEL_LINES}" >&2
    for ((i = 0; i < PROGRESS_PANEL_LINES; i++)); do
      printf '\r\033[K\n' >&2
    done
    PROGRESS_RENDERED=0
    PROGRESS_PANEL_LINES=0
  elif (( PROGRESS_TTY == 1 && PROGRESS_RENDERED == 1 )); then
    printf '\r\033[K' >&2
    PROGRESS_RENDERED=0
  fi
}

box_rule() {
  local left="$1" fill="$2" right="$3" width="${4:-116}"
  local i line=""
  for ((i = 0; i < width - 2; i++)); do
    line+="${fill}"
  done
  printf '%s' "${left}"
  printf '%s' "${line}"
  printf '%s' "${right}"
}

box_line() {
  local text="$1" width="${2:-116}"
  local inner=$((width - 4)) pad
  text="$(ellipsize "${text}" "${inner}")"
  pad=$((inner - ${#text}))
  (( pad < 0 )) && pad=0
  printf '│ %s%*s │' "${text}" "${pad}" ''
}

category_progress_counts() {
  local experiment="$1"
  local key arch_label category app_name done=0 total=0
  for key in "${PLAN_TASK_KEYS[@]}"; do
    IFS='|' read -r arch_label category app_name <<< "${key}"
    [[ "${category}" == "${experiment}" ]] || continue
    total=$((total + 1))
    if [[ "${PLAN_TASK_DONE[${key}]:-0}" == "1" ]]; then
      done=$((done + 1))
    fi
  done
  printf '%s %s' "${done}" "${total}"
}

category_status_word() {
  local done="$1" total="$2" experiment="$3"
  if (( total > 0 && done >= total )); then
    printf 'done'
  elif [[ "${PROGRESS_CURRENT_EXPERIMENT}" == "${experiment}" ]]; then
    printf 'running'
  else
    printf 'queued'
  fi
}

category_progress_line() {
  local experiment="$1" counts done total percent bar marker status
  counts="$(category_progress_counts "${experiment}")"
  read -r done total <<< "${counts}"
  (( total <= 0 )) && total=1
  percent=$(( done * 100 / total ))
  bar="$(progress_bar "${done}" "${total}" 26)"
  marker=" "
  if [[ "${PROGRESS_CURRENT_EXPERIMENT}" == "${experiment}" ]]; then
    marker="*"
  fi
  status="$(category_status_word "${done}" "${total}" "${experiment}")"
  printf '%s %-28s [%s] %3d%%  %d/%d  %s' \
    "${marker}" "${experiment}" "${bar}" "${percent}" "${done}" "${total}" "${status}"
}

progress_render_status() {
  local status="$1"
  local done total percent current_slot bar current_line log_line_text arch_pos
  local experiment line
  local -a panel_lines=()
  done="${PROGRESS_DONE_STAGES}"
  total="${PROGRESS_TOTAL_STAGES}"
  (( total <= 0 )) && total=1
  (( done > total )) && done="${total}"
  percent=$(( done * 100 / total ))
  current_slot="${done}"
  if (( done < total )); then
    current_slot=$((done + 1))
  fi
  bar="$(progress_bar "${done}" "${total}" 42)"
  arch_pos="$(progress_arch_position)"
  current_line="${PROGRESS_CURRENT_ARCH_LABEL:-not started}"
  if [[ -n "${PROGRESS_CURRENT_EXPERIMENT}" ]]; then
    current_line+=" › ${PROGRESS_CURRENT_EXPERIMENT}"
  fi
  if [[ -n "${PROGRESS_CURRENT_APP}" ]]; then
    current_line+=" › ${PROGRESS_CURRENT_APP}"
  fi
  if [[ -n "${PROGRESS_CURRENT_DETAIL}" ]]; then
    current_line+=" — ${PROGRESS_CURRENT_DETAIL}"
  elif [[ -n "${status}" ]]; then
    current_line+=" — ${status}"
  fi
  log_line_text="Log: ${LOG_FILE:-not initialized}"

	  if (( PROGRESS_TTY == 1 )); then
	    progress_clear_line
	    panel_lines+=("$(box_rule '╭' '─' '╮')")
	    panel_lines+=("$(box_line "SDC Compute Once experiment progress  |  architecture ${arch_pos}  |  item ${current_slot}/${total}")")
	    panel_lines+=("$(box_line "Overall       [${bar}] ${percent}%  ${done}/${total}")")
	    if (( ${#PLAN_EXPERIMENTS[@]} > 0 )); then
	      panel_lines+=("$(box_line "Experiment categories:")")
	      for experiment in "${PLAN_EXPERIMENTS[@]}"; do
	        line="$(category_progress_line "${experiment}")"
	        panel_lines+=("$(box_line "${line}")")
	      done
	    fi
	    panel_lines+=("$(box_line "Current: $(ellipsize "${current_line}" 103)")")
	    if [[ -n "${PROGRESS_FI_DETAIL}" ]]; then
	      panel_lines+=("$(box_line "$(ellipsize "${PROGRESS_FI_DETAIL}" 103)")")
	    fi
	    panel_lines+=("$(box_line "Plan: architectures=${#PLAN_ARCH_LABELS[@]}, applications=${#PLAN_APPS[@]}, experiments=${#PLAN_EXPERIMENTS[@]}")")
	    panel_lines+=("$(box_line "$(ellipsize "${log_line_text}" 104)")")
    panel_lines+=("$(box_rule '╰' '─' '╯')")
    printf '%s\n' "${panel_lines[@]}" >&2
    PROGRESS_PANEL_LINES="${#panel_lines[@]}"
    PROGRESS_RENDERED=1
  else
    printf '[overall %3d%%] [%s] %d/%d | %s\n' \
      "${percent}" "${bar}" "${done}" "${total}" "$(ellipsize "${current_line}" 140)" >&2
	    if [[ -n "${PROGRESS_CURRENT_EXPERIMENT}" ]]; then
	      line="$(category_progress_line "${PROGRESS_CURRENT_EXPERIMENT}")"
	      printf '[category] %s\n' "${line}" >&2
	    fi
	    if [[ -n "${PROGRESS_FI_DETAIL}" ]]; then
	      printf '[fi] %s\n' "$(ellipsize "${PROGRESS_FI_DETAIL}" 140)" >&2
	    fi
  fi
}

progress_set_status() {
  PROGRESS_STATUS="$*"
  PROGRESS_CURRENT_DETAIL="$*"
  progress_render_status "${PROGRESS_STATUS}"
}

init_progress() {
  local arch_value arch_label experiment app_name key label
  mapfile -t PLAN_APPS < <(selected_app_list)
  mapfile -t PLAN_EXPERIMENTS < <(selected_experiment_list)
  PLAN_ARCH_LABELS=()
  PLAN_TASK_KEYS=()
  PLAN_TASK_LABELS=()
  PLAN_TASK_DONE=()
  for arch_value in "${ARCHES_TO_RUN[@]}"; do
    arch_label="$(arch_label_for_value "${arch_value}")"
    PLAN_ARCH_LABELS+=("${arch_label}")
    for experiment in "${PLAN_EXPERIMENTS[@]}"; do
      for app_name in "${PLAN_APPS[@]}"; do
        key="$(make_task_key "${arch_label}" "${experiment}" "${app_name}")"
        label="$(make_task_label "${arch_label}" "${experiment}" "${app_name}")"
        PLAN_TASK_KEYS+=("${key}")
        PLAN_TASK_LABELS+=("${label}")
        PLAN_TASK_DONE["${key}"]=0
      done
    done
  done
  PLAN_SYSTEM_UNITS_PER_ARCH=2 # compare + cleanup
  if method_runs_fi; then
    PLAN_SYSTEM_UNITS_PER_ARCH=$((PLAN_SYSTEM_UNITS_PER_ARCH + 1)) # common simulator build
  fi
  PROGRESS_TOTAL_STAGES=$(( ${#PLAN_TASK_KEYS[@]} + (${#ARCHES_TO_RUN[@]} * PLAN_SYSTEM_UNITS_PER_ARCH) ))
  if (( PROGRESS_TOTAL_STAGES <= 0 )); then
    PROGRESS_TOTAL_STAGES=1
  fi
  PROGRESS_DONE_STAGES=0
  PROGRESS_STAGE_ACTIVE=0
  PROGRESS_CURRENT_ARCH_LABEL=""
  PROGRESS_CURRENT_EXPERIMENT=""
  PROGRESS_CURRENT_APP=""
  PROGRESS_CURRENT_DETAIL=""
  PROGRESS_CURRENT_TASK_KEY=""
  PROGRESS_CURRENT_COMMAND=""
  PROGRESS_CHILD_PHASE=""
  PROGRESS_FI_DETAIL=""
  if [[ -t 2 && "${RUN_EXPERIMENT_PROGRESS:-1}" != "0" && "${RUN_EXPERIMENT_PROGRESS:-1}" != "false" ]]; then
    PROGRESS_TTY=1
  else
    PROGRESS_TTY=0
  fi
}

print_progress_plan_summary() {
  notice_line "=== Planned work: ${PROGRESS_TOTAL_STAGES} tracked units ==="
  notice_line "Architectures(${#PLAN_ARCH_LABELS[@]}): $(join_with_commas_limited 12 "${PLAN_ARCH_LABELS[@]}")"
  notice_line "Applications(${#PLAN_APPS[@]}): $(join_with_commas_limited 20 "${PLAN_APPS[@]}")"
  notice_line "Experiments(${#PLAN_EXPERIMENTS[@]}): $(join_with_commas_limited 12 "${PLAN_EXPERIMENTS[@]}")"
}

progress_stage_start() {
  local status="$1" experiment="${2:-}"
  PROGRESS_STAGE_ACTIVE=1
  PROGRESS_CURRENT_COMMAND="${status}"
  PROGRESS_CURRENT_DETAIL="${status}"
  PROGRESS_CHILD_PHASE=""
  PROGRESS_FI_DETAIL=""
  if [[ -n "${experiment}" ]]; then
    PROGRESS_CURRENT_EXPERIMENT="${experiment}"
    PROGRESS_CURRENT_APP=""
    PROGRESS_CURRENT_TASK_KEY=""
  else
    PROGRESS_CURRENT_EXPERIMENT=""
    PROGRESS_CURRENT_APP=""
    PROGRESS_CURRENT_TASK_KEY=""
  fi
  progress_render_status "${status}"
  log_line "--- STAGE START: ${status}"
}

progress_stage_done() {
  local status="$*"
  if [[ -n "${PROGRESS_CURRENT_EXPERIMENT}" ]]; then
    mark_current_task_done
    mark_all_experiment_tasks_done "${PROGRESS_CURRENT_ARCH_LABEL}" "${PROGRESS_CURRENT_EXPERIMENT}"
  else
    progress_system_unit_done
  fi
  PROGRESS_STAGE_ACTIVE=0
  if [[ -n "${status}" ]]; then
    PROGRESS_STATUS="${status}"
    PROGRESS_CURRENT_DETAIL="${status}"
  fi
  PROGRESS_CURRENT_EXPERIMENT=""
  PROGRESS_CURRENT_APP=""
  PROGRESS_CURRENT_TASK_KEY=""
  PROGRESS_FI_DETAIL=""
  progress_render_status "${PROGRESS_STATUS}"
  log_line "--- STAGE DONE: ${PROGRESS_STATUS}"
}

progress_finish_line() {
  if (( PROGRESS_TTY == 1 && PROGRESS_RENDERED == 1 )); then
    progress_clear_line
  fi
}

output_is_compile_warning() {
  local line="$1" line_lower="${1,,}"
  [[ ( "${PROGRESS_CHILD_PHASE:-}" == "prebuild" || "${PROGRESS_CURRENT_COMMAND,,}" == *"build"* ) && "${line_lower}" == *"warning"* ]] && return 0
  [[ "${line}" == warning:* ||
     "${line_lower}" == *"nvcc warning"* ||
     "${line_lower}" == *"ptxas warning"* ||
     "${line_lower}" == *"warning #"* ||
     "${line_lower}" == *"warning: #"* ||
     "${line}" =~ ^[^[:space:]]+:[0-9]+(:[0-9]+)?:[[:space:]]+warning: ||
     "${line_lower}" == make*": warning:"* ||
     "${line_lower}" == *"deprecated-declarations"* ||
     "${line_lower}" == *"declared but never referenced"* ]]
}

output_is_alert() {
  local line_lower="${1,,}"
  [[ "${line_lower}" == warning* ||
     "${line_lower}" == *"=== warning"* ||
     "${line_lower}" == error* ||
     "${line_lower}" == *"error:"* ||
     "${line_lower}" == *"=== error"* ||
     "${line_lower}" == *" failed"* ||
     "${line_lower}" == "failed"* ||
     "${line_lower}" == *"traceback "* ||
     "${line_lower}" == traceback* ||
     "${line_lower}" == *"exception"* ]]
}

console_alert_line() {
  local line="$1"
  progress_clear_line
  printf '%s\n' "${line}" >&2
  if [[ -n "${PROGRESS_STATUS:-}" ]]; then
    progress_render_status "${PROGRESS_STATUS}"
  fi
}

maybe_update_progress_from_log_line() {
  local label="$1" line="$2"
  if [[ "${line}" =~ ^====[[:space:]]+\[([0-9]+)/([0-9]+)\][[:space:]]+Fair[[:space:]]+storage[[:space:]]+rerun[[:space:]]+for[[:space:]]+(.+)[[:space:]]+====$ ]]; then
    progress_child_app_start "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
    progress_render_status "${label}: ${PROGRESS_CURRENT_DETAIL}"
    return 0
  fi
  if [[ "${line}" =~ ^====[[:space:]]+\[([0-9]+)/([0-9]+)\][[:space:]]+Storage[[:space:]]+FI[[:space:]]+for[[:space:]]+(.+)[[:space:]]+====$ ]]; then
    progress_child_app_start "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
    PROGRESS_CHILD_PHASE="fi"
    PROGRESS_CURRENT_DETAIL="app ${BASH_REMATCH[1]}/${BASH_REMATCH[2]} ${BASH_REMATCH[3]}; FI preparing"
    PROGRESS_FI_DETAIL="FI progress: waiting for component start"
    progress_render_status "${label}: ${PROGRESS_CURRENT_DETAIL}"
    return 0
  fi
  if [[ "${line}" =~ ^====[[:space:]]+\[([0-9]+)/([0-9]+)\][[:space:]]+([^[:space:]]+)[[:space:]]+/[[:space:]]+([^[:space:]]+)[[:space:]]+/[[:space:]]+runs=([0-9]+)[[:space:]]+====$ ]]; then
    PROGRESS_CHILD_PHASE="fi"
    PROGRESS_CURRENT_APP="${BASH_REMATCH[3]}"
    if [[ -n "${PROGRESS_CURRENT_ARCH_LABEL}" && -n "${PROGRESS_CURRENT_EXPERIMENT}" ]]; then
      PROGRESS_CURRENT_TASK_KEY="$(make_task_key "${PROGRESS_CURRENT_ARCH_LABEL}" "${PROGRESS_CURRENT_EXPERIMENT}" "${PROGRESS_CURRENT_APP}")"
    fi
    PROGRESS_CURRENT_DETAIL="${PROGRESS_CURRENT_APP}; component ${BASH_REMATCH[1]}/${BASH_REMATCH[2]} ${BASH_REMATCH[4]}; FI trials 0/${BASH_REMATCH[5]}"
    PROGRESS_FI_DETAIL="FI trials [$(progress_bar 0 "${BASH_REMATCH[5]}" 26)] 0%  0/${BASH_REMATCH[5]}  component ${BASH_REMATCH[1]}/${BASH_REMATCH[2]} ${BASH_REMATCH[4]}"
    progress_render_status "${label}: ${PROGRESS_CURRENT_DETAIL}"
    return 0
  fi
  if [[ "${line}" =~ ^\[FI_PROGRESS\][[:space:]]+app=([^[:space:]]+)[[:space:]]+app_index=([0-9]+)[[:space:]]+app_total=([0-9]+)[[:space:]]+component=([^[:space:]]+)[[:space:]]+component_index=([0-9]+)[[:space:]]+component_total=([0-9]+)[[:space:]]+completed=([0-9]+)[[:space:]]+total=([0-9]+)[[:space:]]+percent=([0-9]+)[[:space:]]+final=([0-9]+)$ ]]; then
    PROGRESS_CHILD_PHASE="fi"
    PROGRESS_CURRENT_APP="${BASH_REMATCH[1]}"
    if [[ -n "${PROGRESS_CURRENT_ARCH_LABEL}" && -n "${PROGRESS_CURRENT_EXPERIMENT}" ]]; then
      PROGRESS_CURRENT_TASK_KEY="$(make_task_key "${PROGRESS_CURRENT_ARCH_LABEL}" "${PROGRESS_CURRENT_EXPERIMENT}" "${PROGRESS_CURRENT_APP}")"
    fi
    PROGRESS_CURRENT_DETAIL="app ${BASH_REMATCH[2]}/${BASH_REMATCH[3]} ${BASH_REMATCH[1]}; component ${BASH_REMATCH[5]}/${BASH_REMATCH[6]} ${BASH_REMATCH[4]}; FI trials ${BASH_REMATCH[7]}/${BASH_REMATCH[8]} (${BASH_REMATCH[9]}%)"
    PROGRESS_FI_DETAIL="FI trials [$(progress_bar "${BASH_REMATCH[7]}" "${BASH_REMATCH[8]}" 26)] ${BASH_REMATCH[9]}%  ${BASH_REMATCH[7]}/${BASH_REMATCH[8]}  component ${BASH_REMATCH[5]}/${BASH_REMATCH[6]} ${BASH_REMATCH[4]}"
    progress_render_status "${label}: ${PROGRESS_CURRENT_DETAIL}"
    return 0
  fi
  if [[ "${line}" =~ ^\[Progress\][[:space:]]+\[([0-9]+)/([0-9]+)\].*-[[:space:]]*(.+)$ ]]; then
    PROGRESS_CHILD_PHASE="experiment"
    PROGRESS_CURRENT_DETAIL="${label}: ${BASH_REMATCH[1]}/${BASH_REMATCH[2]} ${BASH_REMATCH[3]}"
    if [[ "${BASH_REMATCH[1]}" == "${BASH_REMATCH[2]}" ]]; then
      mark_current_task_done
    fi
    progress_render_status "${PROGRESS_CURRENT_DETAIL}"
    return 0
  fi
  if [[ "${line}" =~ ^\[Progress\][[:space:]]+(.+)$ ]]; then
    PROGRESS_CHILD_PHASE="experiment"
    PROGRESS_CURRENT_DETAIL="${label}: ${BASH_REMATCH[1]}"
    progress_render_status "${PROGRESS_CURRENT_DETAIL}"
    return 0
  fi
  return 1
}

filter_logged_output() {
  local label="$1"
  local line
  while IFS= read -r line; do
    log_line "${line}"
    maybe_update_progress_from_log_line "${label}" "${line}" || true
    if output_is_compile_warning "${line}"; then
      continue
    fi
    if output_is_alert "${line}"; then
      console_alert_line "${line}"
    fi
  done
}

run_logged() {
  local label="$1"
  shift
  local rc=0
  log_line ""
  log_line "--- COMMAND START: ${label}"
  log_line "cwd=${ROOT_DIR}"
  log_line "cmd=$*"
  set +e
  "$@" 2>&1 | filter_logged_output "${label}"
  rc=${PIPESTATUS[0]}
  set -e
  log_line "--- COMMAND EXIT: ${label} rc=${rc}"
  if (( rc != 0 )); then
    console_alert_line "ERROR: ${label} failed with exit code ${rc}; full log: ${LOG_FILE}"
  fi
  return "${rc}"
}

choose_run_counts_if_needed() {
  if [[ ! -t 0 ]]; then
    return 0
  fi
  if [[ "${RUNS_SET}" != "1" ]] && method_runs_fi; then
    arrow_select RUNS "Select FI runs per storage component:" 2 \
      "1::1 (smoke)" \
      "100::100" \
      "1000::1000 (default)" \
      "10000::10000"
  fi
  if [[ "${GEREM_RUNS_SET}" != "1" ]] && method_runs_gerem; then
    arrow_select GEREM_RUNS "Select GEREM storage-EFM random samples:" 0 \
      "1000::GEREM-1000 (1000 random samples)" \
      "5000::GEREM-5000 (5000 random samples)" \
      "10000::GEREM-10000 (10000 random samples)"
  fi
}

choose_keep_intermediate_if_needed() {
  if [[ "${KEEP_INTERMEDIATE_SET}" == "1" || ! -t 0 ]]; then
    return 0
  fi
  local keep_choice="no"
  arrow_select keep_choice "Keep this run's intermediate .work files after completion?" 1 \
    "yes::Yes, keep current .work for inspection" \
    "no::No, delete current .work after the run"
  if [[ "${keep_choice}" == "yes" ]]; then
    KEEP_INTERMEDIATE=1
    KEEP_BUILD=1
  else
    KEEP_INTERMEDIATE=0
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

source_gpgpusim_environment() {
  if ! resolve_cuda_install_path; then
    echo "=== Error: could not find a valid CUDA toolkit path with nvcc. ===" >&2
    return 1
  fi
  local had_nounset=0
  case "$-" in
    *u*) had_nounset=1 ;;
  esac
  set +u
  source "${ROOT_DIR}/setup_environment" || true
  if [[ "${had_nounset}" == "1" ]]; then
    set -u
  else
    set +u
  fi
  if [[ "${DISABLE_GPGPUSIM_POWER_MODEL:-0}" == "1" ]]; then
    unset GPGPUSIM_POWER_MODEL || true
  fi
  if [[ "${GPGPUSIM_SETUP_ENVIRONMENT_WAS_RUN:-}" != "1" ]]; then
    echo "=== Error: setup_environment did not complete successfully. ===" >&2
    return 1
  fi
}

simulator_runtime_available() {
  source_gpgpusim_environment >/dev/null 2>&1 || return 1
  [[ -n "${GPGPUSIM_CONFIG:-}" ]] || return 1
  [[ -f "${ROOT_DIR}/lib/${GPGPUSIM_CONFIG}/libcudart.so" ]]
}

validate_skip_build_if_needed() {
  if [[ "${SKIP_COMMON_BUILD}" != "1" ]]; then
    return 0
  fi
  if simulator_runtime_available; then
    return 0
  fi
  echo "=== Error: --skip-build was requested, but the GPGPU-Sim CUDA runtime library is missing. ===" >&2
  echo "Run again without --skip-build, or use --keep-build on earlier runs that should preserve build artifacts." >&2
  exit 2
}

reset_work_root_at_start() {
  local abs_work
  abs_work="$(realpath -m "${WORK_ROOT}")"
  case "${abs_work}" in
    "${ROOT_DIR}/.work"|"${ROOT_DIR}/.work"/*|"${ROOT_DIR}/.omx/tmp"/*)
      rm -rf -- "${abs_work}"
      mkdir -p "${abs_work}"
      WORK_ROOT="${abs_work}"
      ;;
    *)
      echo "Unsafe WORK_ROOT for automatic cleanup: ${WORK_ROOT}" >&2
      echo "Use the default .work directory or a path under .omx/tmp for isolated validation." >&2
      exit 2
      ;;
  esac
}

choose_force_if_needed() {
  if [[ "${FORCE_SET}" == "1" || ! -t 0 ]]; then
    return 0
  fi
  local force_choice="no"
  arrow_select force_choice "Overwrite existing selected final timing results?" 0 \
    "no::No, keep existing results" \
    "yes::Yes, remove selected results first"
  if [[ "${force_choice}" == "yes" ]]; then
    FORCE=1
  else
    FORCE=0
  fi
}

normalize_arch() {
  case "${ARCH,,}" in
    turing|sm75|rtx2060|turing-rtx2060) ARCH="turing" ;;
    ampere|sm86|rtx3070|ampere-rtx3070) ARCH="ampere" ;;
    both|all-arch|all-architectures|turing+ampere|ampere+turing|turing_ampere|ampere_turing|turing-ampere|ampere-turing) ARCH="both" ;;
    *) echo "Invalid --arch: ${ARCH}" >&2; exit 2 ;;
  esac
}

normalize_method() {
  case "${METHOD,,}" in
    sara) METHOD="sara" ;;
    fi|fault-injection|fault_injection) METHOD="fi" ;;
    gerem|gerem-all|gerem_all) METHOD="gerem-all" ;;
    sara-gerem|sara_gerem|sara-gerem-all|sara_gerem_all|sara-geremall|sara+gerem|sara+gerem-all|sara_and_gerem|sara-and-gerem) METHOD="sara-gerem-all" ;;
    all) METHOD="all" ;;
    *) echo "Invalid --method: ${METHOD}" >&2; exit 2 ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch) ARCH="$(require_option_value "$1" "${2:-}")"; shift 2 ;;
    --method) METHOD="$(require_option_value "$1" "${2:-}")"; shift 2 ;;
    --app) APP="$(require_option_value "$1" "${2:-}")"; shift 2 ;;
    --runs) RUNS="$(require_option_value "$1" "${2:-}")"; RUNS_SET=1; shift 2 ;;
    --gerem-runs) GEREM_RUNS="$(require_option_value "$1" "${2:-}")"; GEREM_RUNS_SET=1; shift 2 ;;
    --skip-build) SKIP_COMMON_BUILD=1; shift ;;
    --keep-intermediate) KEEP_INTERMEDIATE=1; KEEP_INTERMEDIATE_SET=1; KEEP_BUILD=1; shift ;;
    --discard-intermediate) KEEP_INTERMEDIATE=0; KEEP_INTERMEDIATE_SET=1; shift ;;
    --keep-build) KEEP_BUILD=1; shift ;;
    --force) FORCE=1; FORCE_SET=1; shift ;;
    --smoke) APP="AdamW"; RUNS=1; GEREM_RUNS=1000; RUNS_SET=1; GEREM_RUNS_SET=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

choose_if_empty ARCH "Select architecture:" \
  "turing::Turing / RTX2060" \
  "ampere::Ampere / RTX3070" \
  "both::Turing + Ampere"
choose_if_empty METHOD "Select experiment method:" \
  "sara::SARA" \
  "sara-gerem-all::SARA + GEREM storage EFM" \
  "gerem-all::GEREM storage EFM" \
  "fi::FI" \
  "all::SARA + GEREM storage EFM + FI"
normalize_arch
normalize_method

[[ -d "${ROOT_DIR}/test_apps" ]] || { echo "Missing test_apps/" >&2; exit 1; }
choose_app_if_empty
choose_force_if_needed
choose_run_counts_if_needed
choose_keep_intermediate_if_needed

if ! [[ "${RUNS}" =~ ^[0-9]+$ ]] || (( RUNS <= 0 )); then
  echo "--runs must be a positive integer" >&2
  exit 2
fi
if method_runs_gerem; then
  if ! [[ "${GEREM_RUNS}" =~ ^[0-9]+$ ]]; then
    echo "--gerem-runs must be one of 1000, 5000, 10000" >&2
    exit 2
  fi
  case "${GEREM_RUNS}" in
    1000|5000|10000) ;;
    *) echo "--gerem-runs must be one of 1000, 5000, 10000" >&2; exit 2 ;;
  esac
fi
validate_skip_build_if_needed
python3 "${ROOT_DIR}/script/common/sara_result_layout.py" --result-root "${RESULT_ROOT}" --init >/dev/null

app_env_args=()
if [[ "${APP}" != "all" ]]; then
  [[ -d "${ROOT_DIR}/test_apps/${APP}" ]] || { echo "Unknown app: ${APP}" >&2; exit 2; }
  app_env_args+=(RUN_ALL_STORAGE_FAIR_ONLY_APP="${APP}")
  APPS_OVERRIDE_VALUE="${APP}"
else
  APPS_OVERRIDE_VALUE=""
fi

if [[ "${ARCH}" == "both" ]]; then
  ARCHES_TO_RUN=("turing" "ampere")
else
  ARCHES_TO_RUN=("${ARCH}")
fi

reset_work_root_at_start
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCH_LABEL=""
CONFIG_SOURCE=""
GPU_ARCH_VALUE=""
SCRATCH_ROOT=""
CONFIG_BACKUP=""
SCRATCH_CLEANED=1

init_run_log "${ORIGINAL_ARGS[@]}"
init_progress
notice_line "=== run_experiment console shows progress, runtime warnings/errors, and final reminders; compile warnings are log-only: ${LOG_FILE} ==="
print_progress_plan_summary

set_arch_context() {
  local selected_arch="$1"
  ARCH="${selected_arch}"
  case "${ARCH}" in
    turing)
      ARCH_LABEL="Turing-RTX2060"
      CONFIG_SOURCE="${ROOT_DIR}/configs/tested-cfgs/SM75_RTX2060_S/gpgpusim.config"
      GPU_ARCH_VALUE="sm_75"
      ;;
    ampere)
      ARCH_LABEL="Ampere-RTX3070"
      CONFIG_SOURCE="${ROOT_DIR}/configs/tested-cfgs/SM86_RTX3070/gpgpusim.config"
      GPU_ARCH_VALUE="sm_86"
      ;;
    *) echo "Internal error: unsupported architecture context ${ARCH}" >&2; exit 2 ;;
  esac

  [[ -f "${CONFIG_SOURCE}" ]] || { echo "Missing config: ${CONFIG_SOURCE}" >&2; exit 1; }

  SCRATCH_ROOT="${WORK_ROOT}/${ARCH_LABEL}/${METHOD}/${TIMESTAMP}"
  CONFIG_BACKUP="${SCRATCH_ROOT}/gpgpusim.config.before"
  SCRATCH_CLEANED=0
  mkdir -p "${SCRATCH_ROOT}"

  cp "${ROOT_DIR}/gpgpusim.config" "${CONFIG_BACKUP}" 2>/dev/null || true
  cp "${CONFIG_SOURCE}" "${ROOT_DIR}/gpgpusim.config"
  cmp -s "${CONFIG_SOURCE}" "${ROOT_DIR}/gpgpusim.config" || { echo "Failed to install strict config" >&2; exit 1; }

  log_line "=== Architecture: ${ARCH_LABEL} (${CONFIG_SOURCE}) ==="
  log_line "=== Method: ${METHOD}; App: ${APP}; FI runs: ${RUNS}; GEREM runs: ${GEREM_RUNS} ==="
  log_line "=== Final result root: ${RESULT_ROOT}/${ARCH_LABEL} ==="
  log_line "=== Scratch root: ${SCRATCH_ROOT} ==="
  PROGRESS_CURRENT_ARCH_LABEL="${ARCH_LABEL}"
  progress_set_status "${ARCH_LABEL}: method=${METHOD}, app=${APP}"
}

restore_config() {
  if [[ -n "${CONFIG_BACKUP}" && -f "${CONFIG_BACKUP}" ]]; then
    cp "${CONFIG_BACKUP}" "${ROOT_DIR}/gpgpusim.config"
  fi
}

cleanup_current_scratch() {
  local build_cleanup_mode="${1:-drop-build}"
  if [[ -z "${SCRATCH_ROOT}" || "${SCRATCH_CLEANED}" == "1" ]]; then
    return 0
  fi
  if [[ "${KEEP_INTERMEDIATE}" != "1" ]]; then
    local cleanup_args=(--scratch "${SCRATCH_ROOT}")
    if [[ "${KEEP_BUILD}" != "1" && "${build_cleanup_mode}" != "keep-build" ]]; then
      cleanup_args+=(--drop-build)
    fi
    if ! run_logged "cleanup intermediate artifacts" bash "${SCRIPT_DIR}/common/cleanup_intermediate_artifacts.sh" "${cleanup_args[@]}"; then
      console_alert_line "=== Error: intermediate cleanup failed for ${SCRATCH_ROOT} ==="
      return 1
    fi
  fi
  SCRATCH_CLEANED=1
}

cleanup_on_exit() {
  local rc=$?
  trap - EXIT
  if ! restore_config; then
    console_alert_line "=== Error: failed to restore original gpgpusim.config ==="
    rc=1
  fi
  if ! cleanup_current_scratch; then
    rc=1
  fi
  exit "${rc}"
}
trap cleanup_on_exit EXIT

remove_selected_results() {
  local method_dir="$1"
  if [[ "${FORCE}" != "1" ]]; then
    return 0
  fi
  if [[ "${APP}" == "all" ]]; then
    log_line "=== Removing selected results: ${RESULT_ROOT}/${ARCH_LABEL}/${method_dir} (all applications for this method) ==="
    rm -rf "${RESULT_ROOT}/${ARCH_LABEL}/${method_dir}"
    mkdir -p "${RESULT_ROOT}/${ARCH_LABEL}/${method_dir}"
  else
    log_line "=== Removing selected result only: ${RESULT_ROOT}/${ARCH_LABEL}/${method_dir}/${APP}; other applications and methods are preserved ==="
    rm -rf "${RESULT_ROOT}/${ARCH_LABEL}/${method_dir}/${APP}"
  fi
}

run_common_build_once() {
  progress_stage_start "${ARCH_LABEL} / common simulator build"
  if [[ "${SKIP_COMMON_BUILD}" == "1" ]]; then
    log_line "=== Skipping common build (--skip-build) ==="
    progress_stage_done "${ARCH_LABEL} / common simulator build skipped"
    return 0
  fi
  log_line "=== Building simulator once for ${ARCH_LABEL} ==="
  if ! source_gpgpusim_environment >> "${LOG_FILE}" 2>&1; then
    console_alert_line "=== Error: failed to source setup_environment; full log: ${LOG_FILE} ==="
    return 1
  fi
  local jobs="${BUILD_JOBS:-$(nproc 2>/dev/null || echo 4)}"
  if ! [[ "${jobs}" =~ ^[0-9]+$ ]] || (( jobs <= 0 )); then
    jobs=4
  fi
  if (( jobs > 8 )); then
    jobs=8
  fi
  run_logged "${ARCH_LABEL} common simulator build" make -j"${jobs}"
  SKIP_COMMON_BUILD=1
  progress_stage_done "${ARCH_LABEL} / common simulator build complete"
}

run_sara() {
  local method_dir="SARA"
  local final_dir="${RESULT_ROOT}/${ARCH_LABEL}/${method_dir}"
  local normalize_root
  local work_dir="${SCRATCH_ROOT}/sara_runs"
  local prebuild_dir="${SCRATCH_ROOT}/storage_prebuilds"
  progress_stage_start "${ARCH_LABEL} / ${method_dir}" "${method_dir}"
  remove_selected_results "${method_dir}"
  run_logged "${method_dir}" env \
    RUN_ALL_STORAGE_FAIR_TEST_RESULT_DIR="${final_dir}" \
    RUN_ALL_STORAGE_FAIR_SARA_WORK_ROOT="${work_dir}" \
    RUN_ALL_STORAGE_FAIR_GEREM_WORK_ROOT="${SCRATCH_ROOT}/unused_gerem_runs" \
    RUN_ALL_STORAGE_FAIR_STORAGE_PREBUILD_CACHE_ROOT="${prebuild_dir}" \
    RUN_ALL_STORAGE_FAIR_SKIP_GEREM=1 \
    RUN_ALL_STORAGE_FAIR_SKIP_COMPARE=1 \
    RUN_ALL_STORAGE_FAIR_SKIP_COMMON_BUILD="${SKIP_COMMON_BUILD}" \
    GPU_ARCH="${GPU_ARCH_VALUE}" \
    "${app_env_args[@]}" \
    bash "${SCRIPT_DIR}/SARA/run_sara.sh"
  normalize_root="${final_dir}"
  if [[ "${APP}" != "all" ]]; then
    normalize_root="${final_dir}/${APP}"
  fi
  run_logged "${method_dir} result layout normalize" \
    python3 "${ROOT_DIR}/script/common/sara_result_layout.py" --normalize-sara-root "${normalize_root}"
  SKIP_COMMON_BUILD=1
  progress_stage_done "${ARCH_LABEL} / ${method_dir} complete"
}


run_gerem_all() {
  local method_dir
  method_dir="$(gerem_result_dir_name)"
  local final_dir="${RESULT_ROOT}/${ARCH_LABEL}/${method_dir}"
  local work_dir="${SCRATCH_ROOT}/$(gerem_compare_slug)_runs"
  local prebuild_dir="${SCRATCH_ROOT}/storage_prebuilds"
  progress_stage_start "${ARCH_LABEL} / ${method_dir}" "${method_dir}"
  remove_selected_results "${method_dir}"
  run_logged "${method_dir}" env \
    RUN_ALL_STORAGE_FAIR_TEST_RESULT_DIR="${final_dir}" \
    RUN_ALL_STORAGE_FAIR_SARA_WORK_ROOT="${SCRATCH_ROOT}/unused_sara_runs" \
    RUN_ALL_STORAGE_FAIR_GEREM_WORK_ROOT="${work_dir}" \
    RUN_ALL_STORAGE_FAIR_STORAGE_PREBUILD_CACHE_ROOT="${prebuild_dir}" \
    RUN_ALL_STORAGE_FAIR_SKIP_SARA=1 \
    RUN_ALL_STORAGE_FAIR_SKIP_COMPARE=1 \
    RUN_ALL_STORAGE_FAIR_SKIP_COMMON_BUILD="${SKIP_COMMON_BUILD}" \
    GEREM_STORAGE_CAMPAIGN_RUNS="${GEREM_RUNS}" \
    GPU_ARCH="${GPU_ARCH_VALUE}" \
    "${app_env_args[@]}" \
    bash "${SCRIPT_DIR}/GEREM/run_gerem_all.sh"
  SKIP_COMMON_BUILD=1
  progress_stage_done "${ARCH_LABEL} / ${method_dir} complete"
}


run_fi() {
  local final_dir="${RESULT_ROOT}/${ARCH_LABEL}/FI"
  local fi_run_root="${SCRATCH_ROOT}/fi_runs"
  local fi_prebuild_dir="${SCRATCH_ROOT}/fi_storage_prebuilds"
  local fi_method_result_root="${SCRATCH_ROOT}/fi_method_results"
  progress_stage_start "${ARCH_LABEL} / FI-storage" "FI-storage"
  remove_selected_results "FI"
  if [[ -n "${APPS_OVERRIDE_VALUE}" ]]; then
    run_logged "FI-storage" env \
      RUN_PER_EPOCH="${RUNS}" \
      FI_PARALLEL_JOBS="${FI_PARALLEL_JOBS}" \
      FI_SKIP_COMMON_BUILD=1 \
      RUN_ROOT="${fi_run_root}" \
      FI_PREBUILD_CACHE_ROOT="${fi_prebuild_dir}" \
      FI_METHOD_RESULT_ROOT="${fi_method_result_root}" \
      TEST_RESULT_ROOT="${final_dir}" \
      FI_PROGRESS_EVENTS=1 \
      APPS_OVERRIDE="${APPS_OVERRIDE_VALUE}" \
      GPU_ARCH="${GPU_ARCH_VALUE}" \
      bash "${SCRIPT_DIR}/FI/run_fi.sh"
  else
    run_logged "FI-storage" env \
      RUN_PER_EPOCH="${RUNS}" \
      FI_PARALLEL_JOBS="${FI_PARALLEL_JOBS}" \
      FI_SKIP_COMMON_BUILD=1 \
      RUN_ROOT="${fi_run_root}" \
      FI_PREBUILD_CACHE_ROOT="${fi_prebuild_dir}" \
      FI_METHOD_RESULT_ROOT="${fi_method_result_root}" \
      TEST_RESULT_ROOT="${final_dir}" \
      FI_PROGRESS_EVENTS=1 \
      GPU_ARCH="${GPU_ARCH_VALUE}" \
      bash "${SCRIPT_DIR}/FI/run_fi.sh"
  fi
  progress_stage_done "${ARCH_LABEL} / FI-storage complete"
}


sara_app_result_exists() {
  local app_name="$1"
  local app_dir="${RESULT_ROOT}/${ARCH_LABEL}/$(sara_result_dir_name)/${app_name}"
  [[ -f "${app_dir}/sara_result_${app_name}_0-0.csv" || -f "${app_dir}/exact_result_${app_name}_0-0.csv" ]]
}

gerem_app_result_exists() {
  local app_name="$1"
  local app_dir="${RESULT_ROOT}/${ARCH_LABEL}/$(gerem_result_dir_name)/${app_name}"
  [[ -f "${app_dir}/gerem_result_${app_name}_0-0.csv" ]]
}

fi_app_result_exists() {
  local app_name="$1"
  local app_dir="${RESULT_ROOT}/${ARCH_LABEL}/FI/${app_name}"
  local comp_id
  for comp_id in 0 2 3 6; do
    [[ -f "${app_dir}/test_result_${app_name}_0-0_${comp_id}_1.csv" ]] || return 1
  done
  return 0
}

print_missing_experiment_reminder() {
  local -a apps=()
  local -a missing_lines=()
  local app_name line max_lines shown
  mapfile -t apps < <(all_app_list)

  for app_name in "${apps[@]}"; do
    if ! sara_app_result_exists "${app_name}"; then
      missing_lines+=("$(sara_result_dir_name)/${app_name}")
    fi
    if ! gerem_app_result_exists "${app_name}"; then
      missing_lines+=("$(gerem_result_dir_name)/${app_name}")
    fi
    if ! fi_app_result_exists "${app_name}"; then
      missing_lines+=("FI-storage/${app_name}")
    fi
  done

  progress_finish_line
  notice_line ""
  notice_line "======================================================================"
  notice_line "=== Missing experiment data reminder: ${ARCH_LABEL} ==="
  notice_line "======================================================================"
  if (( ${#missing_lines[@]} == 0 )); then
    notice_line "All public results for all applications are present for $(sara_result_dir_name), $(gerem_result_dir_name), and FI-storage."
  else
    notice_line "!!! The following public experiment results are still missing; compare files were updated and missing entries are shown as '-':"
    max_lines=160
    shown=0
    for line in "${missing_lines[@]}"; do
      (( shown < max_lines )) || { notice_line "... ($((${#missing_lines[@]} - shown)) more missing entries)"; break; }
      notice_line "  - ${line}"
      shown=$((shown + 1))
    done
  fi
  notice_line "======================================================================"
  notice_line ""
}

write_compare() {
  local compare_dir="${RESULT_ROOT}/${ARCH_LABEL}/compare"
  progress_stage_start "${ARCH_LABEL} / write compare files"
  mkdir -p "${compare_dir}"

  local sara_root="${RESULT_ROOT}/${ARCH_LABEL}/$(sara_result_dir_name)"
  local gerem_dir="$(gerem_result_dir_name)"
  local gerem_root="${RESULT_ROOT}/${ARCH_LABEL}/${gerem_dir}"
  local output="${compare_dir}/$(sara_compare_output_name)"
  local legacy_allapps_output="${compare_dir}/sara_geremall_vs_fi_allapps.txt"
  local sara_label="$(sara_compare_label)"
  local -a compare_apps=()
  local -a compare_app_args=()
  mapfile -t compare_apps < <(all_app_list)
  if (( ${#compare_apps[@]} > 0 )); then
    compare_app_args=(--apps "${compare_apps[*]}")
  fi
  log_line "=== Refreshing full-suite compare for ${ARCH_LABEL} / ${gerem_dir} using current public results (${#compare_apps[@]} applications) ==="
  run_logged "compare ${sara_label} ${gerem_dir}" python3 "${ROOT_DIR}/script/common/sara_gerem_fi_compare.py" \
    --arch-label "${ARCH_LABEL}" \
    --result-root "${RESULT_ROOT}" \
    --sara-root "${sara_root}" \
    --gerem-root "${gerem_root}" \
    --sara-label "${sara_label}" \
    --gerem-label "${gerem_dir}" \
    --expected-gerem-runs "${GEREM_RUNS}" \
    "${compare_app_args[@]}" \
    --output "${output}"
  if [[ "${GEREM_RUNS}" == "1000" && "${legacy_allapps_output}" != "${output}" ]]; then
    run_logged "compare ${sara_label} legacy allapps alias" python3 - "${output}" "${legacy_allapps_output}" <<'PY'
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
text = src.read_text(encoding="utf-8", errors="replace")
dst.parent.mkdir(parents=True, exist_ok=True)
try:
    dst.write_text(text, encoding="utf-8")
except PermissionError:
    dst.unlink()
    dst.write_text(text, encoding="utf-8")
PY
  fi
  progress_stage_done "${ARCH_LABEL} / compare files complete"
}


run_selected_method() {
  case "${METHOD}" in
    sara)
      run_sara
      ;;
    gerem-all)
      run_gerem_all
      ;;
    sara-gerem-all)
      run_sara
      run_gerem_all
      ;;
    fi)
      run_common_build_once
      run_fi
      ;;
    all)
      run_sara
      run_gerem_all
      run_common_build_once
      run_fi
      ;;
  esac
}

total_arches="${#ARCHES_TO_RUN[@]}"
for arch_index in "${!ARCHES_TO_RUN[@]}"; do
  selected_arch="${ARCHES_TO_RUN[${arch_index}]}"
  set_arch_context "${selected_arch}"
  run_selected_method
  write_compare
  print_missing_experiment_reminder
  restore_config
  progress_stage_start "${ARCH_LABEL} / cleanup"
  if (( arch_index + 1 < total_arches )); then
    cleanup_current_scratch keep-build
  else
    cleanup_current_scratch drop-build
  fi
  progress_stage_done "${ARCH_LABEL} / cleanup complete"
  progress_finish_line
  notice_line "=== Done. Final results are under ${RESULT_ROOT}/${ARCH_LABEL}; full log: ${LOG_FILE} ==="
done
