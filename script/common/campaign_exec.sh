#!/bin/bash

CAMPAIGN_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAMPAIGN_COMMON_DIR="${CAMPAIGN_COMMON_DIR_OVERRIDE:-${CAMPAIGN_SCRIPT_DIR}}"
CAMPAIGN_ROOT_DIR="${CAMPAIGN_ROOT_DIR_OVERRIDE:-$(cd "${CAMPAIGN_COMMON_DIR}/../.." && pwd)}"

# ---------------------------------------------- START ONE-TIME PARAMETERS ----------------------------------------------
# needed by gpgpu-sim for real register usage on PTXPlus mode
export PTXAS_CUDA_INSTALL_PATH=/usr/local/cuda
CONFIG_FILE=./gpgpusim.config
TMP_DIR="${TMP_DIR:-./logs}"
CACHE_LOGS_DIR="${CACHE_LOGS_DIR:-./cache_logs}"
TMP_FILE=tmp.out
# persistent list of invalid parameter combinations to skip
INVALID_COMBOS_FILE=./invalid_param_combos.txt
RUNS=1
FI_PARALLEL_JOBS="${FI_PARALLEL_JOBS:-8}"
COMPONENT_SET="6"
SIM_NICE="${SIM_NICE:-10}"
DELETE_LOGS="${DELETE_LOGS:-1}" # if 1 then all logs will be deleted at the end of the script
INJECT_BIT_FLIP_COUNT=1
THREAD_RAND_MAX=512
WARP_RAND_MAX=16
BLOCK_RAND_MAX=1

# Optional: specify PTX virtual register name(s) to inject (overrides index-based selection)
# Examples: %f1, %r36, %rd7, %p2; multiple names can be colon-delimited like "%f1:%r36".

# Default register name; overridden per-injection if register_used.txt exists
REGISTER_NAME="%r90"

# ---------------------------------------------- END ONE-TIME PARAMETERS ------------------------------------------------

# ---------------------------------------------- START PER GPGPU CARD PARAMETERS ----------------------------------------------
# Cache bit ranges are auto-detected from gpgpusim.config at runtime.
# Fallback defaults keep campaign execution safe if parsing fails.
CACHE_TAG_ARRAY_BITS="${CACHE_TAG_ARRAY_BITS:-57}"
L1D_SIZE_BITS=1
L1C_SIZE_BITS=1
L1T_SIZE_BITS=1
L2_SIZE_BITS=1
# ---------------------------------------------- END PER GPGPU CARD PARAMETERS ------------------------------------------------

# ---------------------------------------------- START PER KERNEL/APPLICATION PARAMETERS (+profile=1) ----------------------------------------------
CUDA_UUT="./AdamW 128 4"
# total cycles for all kernels
CYCLES=6436
# Get the exact cycles, max registers and SIMT cores used for each kernel with profile=1
# fix cycles.txt with kernel execution cycles
# (e.g. seq 1 10 >> cycles.txt, or multiple seq commands if a kernel has multiple executions)
# use the following command from profiling execution for easier creation of cycles.txt file
# e.g. grep "_Z12lud_diagonalPfii" cycles.in | awk  '{ system("seq " $12 " " $18 ">> cycles.txt")}'
CYCLES_FILE=./cycles.txt
MAX_REGISTERS_USED=17
SHADER_USED="0"
SUCCESS_MSG='Fault Injection Test Success!'
FAILED_MSG='Fault Injection Test Failed!'
TIMEOUT_VAL=20s
DATATYPE_SIZE=32
# lmem and smem values are taken from gpgpu-sim ptx output per kernel
# e.g. GPGPU-Sim PTX: Kernel '_Z9vectorAddPKdS0_Pdi' : regs=8, lmem=0, smem=0, cmem=380
# if 0 put a random value > 0
LMEM_SIZE_BITS=1
SMEM_SIZE_BITS=224
# ---------------------------------------------- END PER KERNEL/APPLICATION PARAMETERS (+profile=1) ------------------------------------------------

FAULT_INJECTION_OCCURRED="Fault injection"
CYCLES_MSG="gpu_tot_sim_cycle ="

masked=0
performance=0
SDC=0
crashes=0

# ---------------------------------------------- START PER INJECTION CAMPAIGN PARAMETERS (profile=0) ----------------------------------------------
# 0: perform injection campaign, 1: get cycles of each kernel, 2: get mean value of active threads, during all cycles in CYCLES_FILE, per SM,
# 3: single fault-free execution
profile=0

# 1: per warp bit flip, 0: per thread bit flip
per_warp=0
# in which kernels to inject the fault. e.g. 0: for all running kernels, 1: for kernel 1, 1:2 for kernel 1 & 2
kernel_n=0
# in how many blocks (smems) to inject the bit flip
blocks=1

if [[ -n "${CAMPAIGN_RUNS_OVERRIDE:-}" ]]; then RUNS="${CAMPAIGN_RUNS_OVERRIDE}"; fi
if [[ -n "${CAMPAIGN_COMPONENT_SET_OVERRIDE:-}" ]]; then COMPONENT_SET="${CAMPAIGN_COMPONENT_SET_OVERRIDE}"; fi
if [[ -n "${CAMPAIGN_CUDA_UUT_OVERRIDE:-}" ]]; then CUDA_UUT="${CAMPAIGN_CUDA_UUT_OVERRIDE}"; fi
if [[ -n "${CAMPAIGN_CYCLES_OVERRIDE:-}" ]]; then CYCLES="${CAMPAIGN_CYCLES_OVERRIDE}"; fi
if [[ -n "${CAMPAIGN_CYCLES_FILE_OVERRIDE:-}" ]]; then CYCLES_FILE="${CAMPAIGN_CYCLES_FILE_OVERRIDE}"; fi
if [[ -n "${CAMPAIGN_TIMEOUT_VAL_OVERRIDE:-}" ]]; then TIMEOUT_VAL="${CAMPAIGN_TIMEOUT_VAL_OVERRIDE}"; fi
if [[ -n "${CAMPAIGN_DATATYPE_SIZE_OVERRIDE:-}" ]]; then DATATYPE_SIZE="${CAMPAIGN_DATATYPE_SIZE_OVERRIDE}"; fi
if [[ -n "${CAMPAIGN_THREAD_RAND_MAX_OVERRIDE:-}" ]]; then THREAD_RAND_MAX="${CAMPAIGN_THREAD_RAND_MAX_OVERRIDE}"; fi
if [[ -n "${CAMPAIGN_WARP_RAND_MAX_OVERRIDE:-}" ]]; then WARP_RAND_MAX="${CAMPAIGN_WARP_RAND_MAX_OVERRIDE}"; fi
if [[ -n "${CAMPAIGN_BLOCK_RAND_MAX_OVERRIDE:-}" ]]; then BLOCK_RAND_MAX="${CAMPAIGN_BLOCK_RAND_MAX_OVERRIDE}"; fi
if [[ -n "${CAMPAIGN_PROFILE_OVERRIDE:-}" ]]; then profile="${CAMPAIGN_PROFILE_OVERRIDE}"; fi

FI_INJECTION_POINTS_FILE="${FI_INJECTION_POINTS_FILE:-}"
FI_OUTCOMES_FILE="${FI_OUTCOMES_FILE:-}"
FI_ACTIVE_THREADS_LOG="${FI_ACTIVE_THREADS_LOG:-}"
FI_ANALYZER_OUTPUT="${FI_ANALYZER_OUTPUT:-}"
FI_RF_FAULT_MODEL="${FI_RF_FAULT_MODEL:-persistent}"
FI_ADDR_DUE_MODE="${FI_ADDR_DUE_MODE:-none}"
FI_TRACE_EXPANDING_POLICY="${FI_TRACE_EXPANDING_POLICY:-masked}"
# Public artifact reproducibility seed. Keep fixed: do not derive it from
# wall-clock time, shell random state, OS entropy, or user-provided environment.
EXPERIMENT_RANDOM_SEED=2026
FI_SEED_BASE=2026
FI_GOLDEN_LOG="${FI_GOLDEN_LOG:-}"
FI_OUTPUT_SPEC="${FI_OUTPUT_SPEC:-}"
FI_OUTPUT_ORACLE_TOL_POLICY="${FI_OUTPUT_ORACLE_TOL_POLICY:-{}}"
FI_OUTPUT_ORACLE_TIMEOUT_EXIT_STATUSES="${FI_OUTPUT_ORACLE_TIMEOUT_EXIT_STATUSES:-124:137}"
FI_OUTPUT_ORACLE_MODE="${FI_OUTPUT_ORACLE_MODE:-single}" # single|off

FI_TRIAL_COUNTER=0
CURRENT_TRIAL_ID=0
CURRENT_TRIAL_SEED=0
PRNG_STATE=${EXPERIMENT_RANDOM_SEED}
RAND_VALUE=""
FI_ACTIVE_THREADS_INDEX=""
FI_REG_UID_MAP_FILE=""

init_deterministic_prng() {
    local seed="${1:-2026}"
    local stream="${2:-0}"
    if ! [[ "${seed}" =~ ^-?[0-9]+$ ]]; then
        seed=2026
    fi
    if ! [[ "${stream}" =~ ^-?[0-9]+$ ]]; then
        stream=0
    fi
    PRNG_STATE=$(( (seed + stream * 1000003 + 0x9e3779b9) & 0x7fffffff ))
    if (( PRNG_STATE <= 0 )); then
        PRNG_STATE=2026
    fi
}

rand_next() {
    PRNG_STATE=$(( (1103515245 * PRNG_STATE + 12345) & 0x7fffffff ))
    if (( PRNG_STATE <= 0 )); then
        PRNG_STATE=2026
    fi
    RAND_VALUE="${PRNG_STATE}"
}

rand_range() {
    local min_v="$1"
    local max_v="$2"
    local span raw
    if ! [[ "${min_v}" =~ ^-?[0-9]+$ && "${max_v}" =~ ^-?[0-9]+$ ]]; then
        RAND_VALUE="0"
        return
    fi
    if (( max_v < min_v )); then
        RAND_VALUE="${min_v}"
        return
    fi
    span=$(( max_v - min_v + 1 ))
    rand_next
    raw="${RAND_VALUE}"
    RAND_VALUE=$(( min_v + (raw % span) ))
}

rand_unique_range_colon() {
    local min_v="$1"
    local max_v="$2"
    local count="$3"
    local span pick
    local -a out=()
    local -A seen=()
    if ! [[ "${count}" =~ ^[0-9]+$ ]] || (( count <= 0 )); then
        count=1
    fi
    if ! [[ "${min_v}" =~ ^-?[0-9]+$ && "${max_v}" =~ ^-?[0-9]+$ ]] || (( max_v < min_v )); then
        RAND_VALUE="${min_v}"
        return
    fi
    span=$(( max_v - min_v + 1 ))
    if (( count > span )); then
        count="${span}"
    fi
    while (( ${#out[@]} < count )); do
        rand_range "${min_v}" "${max_v}"
        pick="${RAND_VALUE}"
        if [[ -z "${seen[${pick}]+x}" ]]; then
            seen["${pick}"]=1
            out+=("${pick}")
        fi
    done
    local IFS=:
    RAND_VALUE="${out[*]}"
}

rand_choose_words() {
    local -a items=("$@")
    local idx
    if (( ${#items[@]} == 0 )); then
        RAND_VALUE=""
        return
    fi
    rand_range 0 $((${#items[@]} - 1))
    idx="${RAND_VALUE}"
    RAND_VALUE="${items[${idx}]}"
}

rand_nonempty_file_line() {
    local file="$1"
    local count target
    count="$(awk 'NF {n++} END {print n+0}' "${file}" 2>/dev/null)"
    if ! [[ "${count}" =~ ^[0-9]+$ ]] || (( count <= 0 )); then
        RAND_VALUE=""
        return
    fi
    rand_range 1 "${count}"
    target="${RAND_VALUE}"
    RAND_VALUE="$(awk -v target="${target}" 'NF {n++; if (n == target) {print; exit}}' "${file}" | tr -d '\r')"
}

set_config_opt() {
    local opt="$1"
    local value="$2"
    local tmp

    if [[ ! -f "${CONFIG_FILE}" ]]; then
        echo "Error: missing GPGPU-Sim config: ${CONFIG_FILE}" >&2
        return 1
    fi

    tmp="$(mktemp "${CONFIG_FILE}.XXXXXX")" || return 1
    if awk -v opt="${opt}" -v value="${value}" '
        BEGIN { written = 0 }
        $1 == opt {
            if (!written) {
                print opt " " value
                written = 1
            }
            next
        }
        { print }
        END {
            if (!written) {
                print opt " " value
            }
        }
    ' "${CONFIG_FILE}" > "${tmp}"; then
        if [[ -w "${CONFIG_FILE}" ]]; then
            cat "${tmp}" > "${CONFIG_FILE}" && rm -f "${tmp}"
        else
            mv "${tmp}" "${CONFIG_FILE}"
        fi
    else
        rm -f "${tmp}"
        return 1
    fi
}

choose_total_cycle_rand() {
    if [[ "$profile" -eq 1 ]] || [[ "$profile" -eq 2 ]] || [[ "$profile" -eq 3 ]]; then
        RAND_VALUE="-1"
        return 0
    fi
    if [[ -f "${CYCLES_FILE}" && -s "${CYCLES_FILE}" ]]; then
        rand_nonempty_file_line "${CYCLES_FILE}"
        return 0
    fi
    if [[ "${CYCLES}" =~ ^[0-9]+$ ]] && [[ "${CYCLES}" -gt 0 ]]; then
        rand_range 0 "${CYCLES}"
        return 0
    fi
    RAND_VALUE="0"
}

sanitize_run_settings() {
    if ! [[ "${SIM_NICE}" =~ ^-?[0-9]+$ ]]; then
        SIM_NICE=10
    fi
}

launch_uut_guarded() {
    local out_file="$1"
    local exit_file="$2"
    local rc=0
    if command -v nice >/dev/null 2>&1; then
        nice -n "${SIM_NICE}" timeout "${TIMEOUT_VAL}" $CUDA_UUT > "${out_file}" 2>&1
        rc=$?
    else
        timeout "${TIMEOUT_VAL}" $CUDA_UUT > "${out_file}" 2>&1
        rc=$?
    fi
    echo "${rc}" > "${exit_file}"
}

csv_escape() {
    local v="${1:-}"
    v="${v//\"/\"\"}"
    printf '"%s"' "${v}"
}

ensure_csv_header() {
    local path="$1"
    local header="$2"
    [[ -n "${path}" ]] || return
    mkdir -p "$(dirname "${path}")" 2>/dev/null || return 1
    if [[ ! -e "${path}" ]]; then
        : > "${path}" 2>/dev/null || return 1
    fi
    [[ -w "${path}" ]] || return 1
    if [[ ! -s "${path}" ]]; then
        echo "${header}" > "${path}" || return 1
    fi
    return 0
}

get_config_numeric_opt() {
    local opt="$1"
    local val
    val="$(awk -v opt="${opt}" '$1 == opt {print $2; exit}' "${CONFIG_FILE}" 2>/dev/null)"
    echo "${val}"
}

get_cache_geometry() {
    local opt="$1"
    local line geom
    line="$(awk -v opt="${opt}" '$1 == opt {print; exit}' "${CONFIG_FILE}" 2>/dev/null)"
    geom="$(echo "${line}" | sed -nE 's/^[[:space:]]*[^[:space:]]+[[:space:]]+[SN]:([0-9]+):([0-9]+):([0-9]+).*/\1 \2 \3/p')"
    echo "${geom}"
}

calc_cache_bits() {
    local nset="$1"
    local line_bytes="$2"
    local assoc="$3"
    if ! [[ "${nset}" =~ ^[0-9]+$ && "${line_bytes}" =~ ^[0-9]+$ && "${assoc}" =~ ^[0-9]+$ ]]; then
        echo 0
        return
    fi
    if (( nset <= 0 || line_bytes <= 0 || assoc <= 0 )); then
        echo 0
        return
    fi
    local lines=$(( nset * assoc ))
    echo $(( lines * (line_bytes * 8 + CACHE_TAG_ARRAY_BITS) ))
}

auto_detect_cache_size_bits() {
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        echo "Warning: cache size auto-detect skipped, missing ${CONFIG_FILE}" >&2
        return
    fi

    local nset line_sz assoc bits
    read -r nset line_sz assoc <<< "$(get_cache_geometry "-gpgpu_cache:dl1")"
    bits="$(calc_cache_bits "${nset}" "${line_sz}" "${assoc}")"
    if (( bits > 0 )); then L1D_SIZE_BITS="${bits}"; fi

    read -r nset line_sz assoc <<< "$(get_cache_geometry "-gpgpu_const_cache:l1")"
    bits="$(calc_cache_bits "${nset}" "${line_sz}" "${assoc}")"
    if (( bits > 0 )); then L1C_SIZE_BITS="${bits}"; fi

    read -r nset line_sz assoc <<< "$(get_cache_geometry "-gpgpu_tex_cache:l1")"
    bits="$(calc_cache_bits "${nset}" "${line_sz}" "${assoc}")"
    if (( bits > 0 )); then L1T_SIZE_BITS="${bits}"; fi

    local l2_per_partition_bits n_mem n_subparts
    read -r nset line_sz assoc <<< "$(get_cache_geometry "-gpgpu_cache:dl2")"
    l2_per_partition_bits="$(calc_cache_bits "${nset}" "${line_sz}" "${assoc}")"

    n_mem="$(get_config_numeric_opt "-gpgpu_n_mem")"
    n_subparts="$(get_config_numeric_opt "-gpgpu_n_sub_partition_per_mchannel")"
    if ! [[ "${n_mem}" =~ ^[0-9]+$ ]] || (( n_mem <= 0 )); then n_mem=1; fi
    if ! [[ "${n_subparts}" =~ ^[0-9]+$ ]] || (( n_subparts <= 0 )); then n_subparts=1; fi
    bits=$(( l2_per_partition_bits * n_mem * n_subparts ))
    if (( bits > 0 )); then L2_SIZE_BITS="${bits}"; fi

    echo "Auto-detected cache size bits: L1D=${L1D_SIZE_BITS}, L1C=${L1C_SIZE_BITS}, L1T=${L1T_SIZE_BITS}, L2=${L2_SIZE_BITS}"
}

build_active_threads_index() {
    [[ -n "${FI_ACTIVE_THREADS_LOG}" && -f "${FI_ACTIVE_THREADS_LOG}" ]] || return
    FI_ACTIVE_THREADS_INDEX="$(mktemp)"
    python3 - "${FI_ACTIVE_THREADS_LOG}" "${FI_ACTIVE_THREADS_INDEX}" <<'PY'
import json
import sys
from pathlib import Path

inp = Path(sys.argv[1])
outp = Path(sys.argv[2])

rows = {}
text = inp.read_text(encoding="utf-8", errors="ignore").strip()

def add_row(obj):
    if not isinstance(obj, dict):
        return
    if "cycle" not in obj:
        return
    ids = obj.get("active_thread_ids")
    if not isinstance(ids, list):
        ids = []
        ranges = obj.get("active_thread_ranges")
        if isinstance(ranges, list):
            expected = obj.get("active_threads_size")
            total = 0
            decoded = []
            ok = True
            for item in ranges:
                if not isinstance(item, list) or len(item) != 2:
                    ok = False
                    break
                start = int(item[0])
                count = int(item[1])
                if count < 0:
                    ok = False
                    break
                decoded.extend(range(start, start + count))
                total += count
            if ok and (expected is None or int(expected) == int(total)):
                ids = decoded
    rows[int(obj["cycle"])] = [int(x) for x in ids]

if text and text[0] in "{[":
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        raw = None
    if isinstance(raw, dict):
        seq = raw.get("active_threads_by_cycle", [])
        if isinstance(seq, list):
            for item in seq:
                add_row(item)
    elif isinstance(raw, list):
        for item in raw:
            add_row(item)

if not rows:
    with inp.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            try:
                add_row(json.loads(s))
            except json.JSONDecodeError:
                continue

with outp.open("w", encoding="utf-8") as f:
    for cycle in sorted(rows.keys()):
        ids = rows[cycle]
        csv_ids = ",".join(str(x) for x in ids)
        f.write(f"{cycle}\t{len(ids)}\t{csv_ids}\n")
PY
}

build_reg_uid_map() {
    [[ -n "${FI_ANALYZER_OUTPUT}" && -f "${FI_ANALYZER_OUTPUT}" ]] || return
    FI_REG_UID_MAP_FILE="$(mktemp)"
    python3 - "${FI_ANALYZER_OUTPUT}" "${FI_REG_UID_MAP_FILE}" <<'PY'
import json
import pickle
import sys
from collections import defaultdict
from pathlib import Path

inp = Path(sys.argv[1])
outp = Path(sys.argv[2])
raw = json.loads(inp.read_text())
if isinstance(raw, dict) and raw.get("manifest_kind") == "exact_sdc_analyzer_output_binary_v1":
    ref = raw.get("binary_ref")
    if ref:
        ref_path = Path(str(ref))
        if not ref_path.is_absolute():
            ref_path = inp.parent / ref_path
        with ref_path.open("rb") as fh:
            raw = pickle.load(fh)
events = raw.get("read_events", [])
reg_to_uids = defaultdict(set)
if isinstance(events, list):
    for rec in events:
        if isinstance(rec, dict):
            reg = rec.get("src_reg")
            uid = rec.get("src_reg_uid")
        elif isinstance(rec, (list, tuple)) and len(rec) >= 7:
            # compact compute_v1 read-event schema:
            # (..., src_reg, src_reg_uid, ...)
            reg = rec[5]
            uid = rec[6]
        else:
            continue
        if not isinstance(reg, str) or reg == "":
            continue
        try:
            iuid = int(uid)
        except Exception:
            continue
        if iuid >= 0:
            reg_to_uids[reg].add(iuid)

with outp.open("w", encoding="utf-8") as f:
    for reg in sorted(reg_to_uids.keys()):
        uids = sorted(reg_to_uids[reg])
        f.write(f"{reg}\t{':'.join(str(u) for u in uids)}\n")
PY
}

init_trial_logging() {
    if [[ -n "${FI_INJECTION_POINTS_FILE}" ]]; then
        if ! ensure_csv_header "${FI_INJECTION_POINTS_FILE}" "trial,cycle,active_threads_size,thread_rand,chosen_thread_uid,reg,reg_uid,bit,datatype_bits,rf_fault_model,addr_due_mode,trace_expanding_policy,seed,component,per_warp,kernel,warp_rand,block_rand,local_bits,shared_bits,l1d_shader,l1d_bits,l1c_shader,l1c_bits,l1t_shader,l1t_bits,l2_bits,gmem_byte_seed,gmem_target_addr"; then
            echo "Warning: cannot write FI injection points CSV: ${FI_INJECTION_POINTS_FILE}" >&2
            FI_INJECTION_POINTS_FILE=""
        fi
    fi
    if [[ -n "${FI_OUTCOMES_FILE}" ]]; then
        if ! ensure_csv_header "${FI_OUTCOMES_FILE}" "trial,outcome,due_reason,exit_status,run_batch,tmp_file"; then
            echo "Warning: cannot write FI outcomes CSV: ${FI_OUTCOMES_FILE}" >&2
            FI_OUTCOMES_FILE=""
        fi
    fi
    if [[ -n "${FI_INJECTION_POINTS_FILE}" ]]; then
        build_active_threads_index
        build_reg_uid_map
    fi
}

cleanup_trial_logging() {
    if [[ -n "${FI_ACTIVE_THREADS_INDEX}" && -f "${FI_ACTIVE_THREADS_INDEX}" ]]; then
        rm -f "${FI_ACTIVE_THREADS_INDEX}"
    fi
    if [[ -n "${FI_REG_UID_MAP_FILE}" && -f "${FI_REG_UID_MAP_FILE}" ]]; then
        rm -f "${FI_REG_UID_MAP_FILE}"
    fi
}

canonicalize_optional_file_var() {
    local name="$1"
    local value="${!name:-}"
    if [[ -n "${value}" && "${value}" != /* ]]; then
        printf -v "${name}" '%s/%s' "${CAMPAIGN_ORIGINAL_CWD:-$(pwd)}" "${value}"
    fi
}

normalize_parallel_jobs() {
    if ! [[ "${FI_PARALLEL_JOBS}" =~ ^[0-9]+$ ]] || (( FI_PARALLEL_JOBS <= 0 )); then
        FI_PARALLEL_JOBS=8
    fi
    if [[ "${profile}" -eq 1 ]] || [[ "${profile}" -eq 2 ]] || [[ "${profile}" -eq 3 ]]; then
        FI_PARALLEL_JOBS=1
    fi
}

append_line_locked() {
    local path="$1"
    local line="$2"
    [[ -n "${path}" ]] || return 0
    if command -v flock >/dev/null 2>&1; then
        {
            flock 9
            printf '%s\n' "${line}" >> "${path}"
        } 9>> "${path}.lock"
    else
        printf '%s\n' "${line}" >> "${path}"
    fi
}

lookup_active_entry() {
    local cycle="$1"
    if [[ -z "${FI_ACTIVE_THREADS_INDEX}" || ! -f "${FI_ACTIVE_THREADS_INDEX}" ]]; then
        echo "-1"
        return
    fi
    awk -F'\t' -v c="${cycle}" '
        $1 == c {print $2 "\t" $3; found=1; exit}
        END {if (!found) print "-1\t"}
    ' "${FI_ACTIVE_THREADS_INDEX}"
}

lookup_reg_uid_set() {
    local reg="$1"
    if [[ -z "${FI_REG_UID_MAP_FILE}" || ! -f "${FI_REG_UID_MAP_FILE}" ]]; then
        echo ""
        return
    fi
    awk -F'\t' -v r="${reg}" '$1 == r {print $2; exit}' "${FI_REG_UID_MAP_FILE}"
}

log_fi_injection_point() {
    [[ -n "${FI_INJECTION_POINTS_FILE}" ]] || return

    local active_entry active_size active_ids_csv chosen_thread_uid slot
    local bit_for_log reg_uid_for_log
    active_entry="$(lookup_active_entry "${total_cycle_rand}")"
    active_size="${active_entry%%$'\t'*}"
    active_ids_csv="${active_entry#*$'\t'}"
    chosen_thread_uid="-1"
    if [[ "${active_size}" =~ ^[0-9]+$ ]] && (( active_size > 0 )); then
        slot=$(( thread_rand % active_size ))
        IFS=',' read -r -a active_ids_arr <<< "${active_ids_csv}"
        if (( slot < ${#active_ids_arr[@]} )); then
            chosen_thread_uid="${active_ids_arr[$slot]}"
        fi
    fi

    bit_for_log="$(echo "${reg_bitflip_rand_n}" | cut -d':' -f1)"
    reg_uid_for_log="$(lookup_reg_uid_set "${REGISTER_NAME}")"

    local csv_line
    csv_line="$(printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s' \
        "$(csv_escape "${CURRENT_TRIAL_ID}")" \
        "$(csv_escape "${total_cycle_rand}")" \
        "$(csv_escape "${active_size}")" \
        "$(csv_escape "${thread_rand}")" \
        "$(csv_escape "${chosen_thread_uid}")" \
        "$(csv_escape "${REGISTER_NAME}")" \
        "$(csv_escape "${reg_uid_for_log}")" \
        "$(csv_escape "${bit_for_log}")" \
        "$(csv_escape "${DATATYPE_SIZE}")" \
        "$(csv_escape "${FI_RF_FAULT_MODEL}")" \
        "$(csv_escape "${FI_ADDR_DUE_MODE}")" \
        "$(csv_escape "${FI_TRACE_EXPANDING_POLICY}")" \
        "$(csv_escape "${CURRENT_TRIAL_SEED}")" \
        "$(csv_escape "${components_to_flip}")" \
        "$(csv_escape "${per_warp}")" \
        "$(csv_escape "${kernel_n}")" \
        "$(csv_escape "${warp_rand}")" \
        "$(csv_escape "${block_rand}")" \
        "$(csv_escape "${local_mem_bitflip_rand_n}")" \
        "$(csv_escape "${shared_mem_bitflip_rand_n}")" \
        "$(csv_escape "${l1d_shader_rand_n}")" \
        "$(csv_escape "${l1d_cache_bitflip_rand_n}")" \
        "$(csv_escape "${l1c_shader_rand_n}")" \
        "$(csv_escape "${l1c_cache_bitflip_rand_n}")" \
        "$(csv_escape "${l1t_shader_rand_n}")" \
        "$(csv_escape "${l1t_cache_bitflip_rand_n}")" \
        "$(csv_escape "${l2_cache_bitflip_rand_n}")" \
        "$(csv_escape "${gmem_byte_seed}")" \
        "$(csv_escape "${gmem_target_addr}")")"
    append_line_locked "${FI_INJECTION_POINTS_FILE}" "${csv_line}"
}

classify_due_reason() {
    local file="$1"
    local exit_status="${2:-}"

    if [[ "${exit_status}" =~ ^[0-9]+$ ]] && { [[ "${exit_status}" -eq 124 ]] || [[ "${exit_status}" -eq 137 ]]; }; then
        echo "timeout"
        return
    fi

    if [[ ! -f "${file}" || ! -s "${file}" ]]; then
        echo "missing_output"
        return
    fi

    if grep -a -iqE "assert|fatal|segmentation fault|core dumped|cuda error|gpgpu-sim.*error|aborted" "${file}"; then
        echo "simulator_error"
        return
    fi

    if [[ "${exit_status}" =~ ^[0-9]+$ ]] && [[ "${exit_status}" -ne 0 ]]; then
        echo "abnormal_exit"
        return
    fi

    echo "other"
}

classify_outcome_with_oracle() {
    local run_log="$1"
    local exit_status="${2:-}"

    if [[ "${FI_OUTPUT_ORACLE_MODE}" != "single" ]]; then
        return 1
    fi
    if [[ -z "${FI_GOLDEN_LOG}" || ! -f "${FI_GOLDEN_LOG}" ]]; then
        return 1
    fi
    if [[ ! -f "${run_log}" ]]; then
        return 1
    fi
    if [[ -n "${FI_OUTPUT_SPEC}" && ! -f "${FI_OUTPUT_SPEC}" ]]; then
        return 1
    fi

    local -a cmd
    cmd=(
        python3
        "${CAMPAIGN_COMMON_DIR}/outcome_oracle.py"
        fi-logs
        --golden-log "${FI_GOLDEN_LOG}"
        --run-log "${run_log}"
        --timeout-exit-statuses "${FI_OUTPUT_ORACLE_TIMEOUT_EXIT_STATUSES}"
        --tol-policy-json "${FI_OUTPUT_ORACLE_TOL_POLICY}"
    )
    if [[ -n "${FI_OUTPUT_SPEC}" ]]; then
        cmd+=(--output-spec "${FI_OUTPUT_SPEC}")
    fi
    if [[ -n "${exit_status}" ]]; then
        cmd+=(--exit-status "${exit_status}")
    fi

    local oracle_json
    if ! oracle_json="$("${cmd[@]}" 2>/dev/null)"; then
        return 1
    fi

    python3 - "${oracle_json}" <<'PY'
import json
import sys

try:
    raw = json.loads(sys.argv[1])
except Exception:
    raise SystemExit(1)

cls = str(raw.get("classification", "masked")).strip().lower()
reason = str(raw.get("detail", {}).get("reason", "")).strip()
if cls == "sdc":
    print("SDC")
    print("")
elif cls == "due":
    print("DUE")
    print(reason or "oracle_due")
elif cls == "masked":
    print("Masked")
    print("")
else:
    raise SystemExit(1)
PY
}

log_fi_outcome() {
    local trial="$1"
    local outcome="$2"
    local due_reason="$3"
    local exit_status="$4"
    local run_batch="$5"
    local tmp_name="$6"
    [[ -n "${FI_OUTCOMES_FILE}" ]] || return
    local csv_line
    csv_line="$(printf '%s,%s,%s,%s,%s,%s' \
        "$(csv_escape "${trial}")" \
        "$(csv_escape "${outcome}")" \
        "$(csv_escape "${due_reason}")" \
        "$(csv_escape "${exit_status}")" \
        "$(csv_escape "${run_batch}")" \
        "$(csv_escape "${tmp_name}")")"
    append_line_locked "${FI_OUTCOMES_FILE}" "${csv_line}"
}

build_combo_key_from_vars() {
    # Build a canonical key string from currently selected variables
    # Keep ordering stable for matching with analysis_fault.py
    # Exclude reg_bits/local_bits/shared_bits/l1*_shader,l1*_bits/l2_bits from the filter key
    echo -n "comp=${components_to_flip};per_warp=${per_warp};kernel=${kernel_n};"
    echo -n "thread=${thread_rand};warp=${warp_rand};block=${block_rand};cycle=${total_cycle_rand};"
    echo -n "reg_name=${REGISTER_NAME};reg_rand_n=${register_rand_n}"
}

component_bitflip_width() {
    local component="${1:-0}"
    case "${component}" in
        11)
            echo "8"
            ;;
        *)
            echo "${DATATYPE_SIZE}"
            ;;
    esac
}

initialize_config() {
    # 0:RF, 1:local_mem, 2:shared_mem, 3:L1D_cache, 4:L1C_cache, 5:L1T_cache, 6:L2_cache, 11:gmem
    # random component to flip from COMPONENT_SET
    while true; do
        rand_choose_words ${COMPONENT_SET}
        components_to_flip="${RAND_VALUE}"
        # random number for choosing a random thread after thread_rand % #threads operation in gpgpu-sim
        tmax=${THREAD_RAND_MAX}
        if (( tmax <= 0 )); then tmax=6000; fi
        tmax=$(( tmax > 0 ? tmax - 1 : 0 ))
        rand_range 0 "${tmax}"
        thread_rand="${RAND_VALUE}"
        # random number for choosing a random warp after warp_rand % #warp operation in gpgpu-sim
        wmax=${WARP_RAND_MAX}
        if (( wmax <= 0 )); then wmax=6000; fi
        wmax=$(( wmax > 0 ? wmax - 1 : 0 ))
        rand_range 0 "${wmax}"
        warp_rand="${RAND_VALUE}"
        # random cycle for fault injection
        choose_total_cycle_rand
        total_cycle_rand="${RAND_VALUE}"
        # Randomize REGISTER_NAME per injection if register list is available
        if [[ -f "register_used.txt" && -s "register_used.txt" ]]; then
            rand_nonempty_file_line register_used.txt
            REGISTER_NAME="${RAND_VALUE}"
        fi
        # in which registers to inject the bit flip
        # Register index is fixed when REGISTER_NAME is selected from register_used.txt.
        register_rand_n=1
        # example: if -i 1-32 -n 2 then the two commands below will create a value with 2 random numbers, between [1,32] like 3:21. Meaning it will flip 3 and 21 bits.
        bitflip_width="$(component_bitflip_width "${components_to_flip}")"
        if ! [[ "${bitflip_width}" =~ ^[0-9]+$ ]] || (( bitflip_width <= 0 )); then
            bitflip_width=32
        fi
        rand_unique_range_colon 1 "${bitflip_width}" "${INJECT_BIT_FLIP_COUNT}"
        reg_bitflip_rand_n="${RAND_VALUE}"
        # same format like reg_bitflip_rand_n but for local memory bit flips
        if (( LMEM_SIZE_BITS > 0 )); then
            rand_unique_range_colon 1 "${LMEM_SIZE_BITS}" "${INJECT_BIT_FLIP_COUNT}"
            local_mem_bitflip_rand_n="${RAND_VALUE}"
        else
            local_mem_bitflip_rand_n=1
        fi
        # random number for choosing a random block after block_rand % #smems operation in gpgpu-sim
        bmax=${BLOCK_RAND_MAX}
        if (( bmax <= 0 )); then bmax=6000; fi
        bmax=$(( bmax > 0 ? bmax - 1 : 0 ))
        rand_range 0 "${bmax}"
        block_rand="${RAND_VALUE}"
        # same format like reg_bitflip_rand_n but for shared memory bit flips
        if (( SMEM_SIZE_BITS > 0 )); then
            rand_unique_range_colon 1 "${SMEM_SIZE_BITS}" "${INJECT_BIT_FLIP_COUNT}"
            shared_mem_bitflip_rand_n="${RAND_VALUE}"
        else
            shared_mem_bitflip_rand_n=1
        fi
        # randomly select one or more shaders for L1 data cache fault injections
        rand_choose_words ${SHADER_USED}; l1d_shader_rand_n="${RAND_VALUE//$'\n'/:}"
        # same format like reg_bitflip_rand_n but for L1 data cache bit flips
        rand_unique_range_colon 1 "${L1D_SIZE_BITS}" 1; l1d_cache_bitflip_rand_n="${RAND_VALUE}"
        # randomly select one or more shaders for L1 constant cache fault injections
        rand_choose_words ${SHADER_USED}; l1c_shader_rand_n="${RAND_VALUE//$'\n'/:}"
        # same format like reg_bitflip_rand_n but for L1 constant cache bit flips
        rand_unique_range_colon 1 "${L1C_SIZE_BITS}" 1; l1c_cache_bitflip_rand_n="${RAND_VALUE}"
        # randomly select one or more shaders for L1 texture cache fault injections
        rand_choose_words ${SHADER_USED}; l1t_shader_rand_n="${RAND_VALUE//$'\n'/:}"
        # same format like reg_bitflip_rand_n but for L1 texture cache bit flips
        rand_unique_range_colon 1 "${L1T_SIZE_BITS}" 1; l1t_cache_bitflip_rand_n="${RAND_VALUE}"
        # same format like reg_bitflip_rand_n but for L2 cache bit flips
        rand_unique_range_colon 1 "${L2_SIZE_BITS}" 1; l2_cache_bitflip_rand_n="${RAND_VALUE}"
        rand_range 0 2147483646; gmem_byte_seed="${RAND_VALUE}"
        gmem_target_addr=18446744073709551615
        if [[ "${components_to_flip}" == "11" && -n "${FI_ANALYZER_OUTPUT}" && -f "${FI_ANALYZER_OUTPUT}" ]]; then
            gmem_target_addr="$(
                python3 - "${FI_ANALYZER_OUTPUT}" "${gmem_byte_seed}" <<'PY'
import json
import sys

path = sys.argv[1]
seed = int(sys.argv[2])
try:
    data = json.load(open(path, "r", encoding="utf-8"))
except Exception:
    print(18446744073709551615)
    raise SystemExit(0)
rows = data.get("l1d_fault_sites", [])
addrs = sorted(
    {
        (
            int(rec.get("addr", 0))
            if isinstance(rec, dict)
            else int(rec[5])
        )
        for rec in rows
        if (
            (
                isinstance(rec, dict)
                and str(rec.get("mem_space", "")).strip().lower() == "global"
                and str(rec.get("site_kind", "")).strip().lower() in ("l1d_load", "l1d_store")
            )
            or (
                isinstance(rec, (list, tuple))
                and len(rec) >= 6
                and str(rec[1]).strip().lower() == "global"
                and str(rec[0]).strip().lower() in ("l1d_load", "l1d_store")
            )
        )
    }
)
if not addrs:
    print(18446744073709551615)
else:
    print(addrs[seed % len(addrs)])
PY
            )"
        fi

        # Build combo key and check against invalid list
        combo_key=$(build_combo_key_from_vars)
        if [[ -f "${INVALID_COMBOS_FILE}" ]] && grep -Fxq "${combo_key}" "${INVALID_COMBOS_FILE}"; then
            # invalid combo previously observed; re-sample
            continue
        fi
        break
    done
    log_fi_injection_point
# ---------------------------------------------- END PER INJECTION CAMPAIGN PARAMETERS (profile=0) ------------------------------------------------

    set_config_opt "-components_to_flip" "${components_to_flip}"
    set_config_opt "-profile" "${profile}"
    set_config_opt "-last_cycle" "${CYCLES}"
    set_config_opt "-thread_rand" "${thread_rand}"
    set_config_opt "-warp_rand" "${warp_rand}"
    set_config_opt "-total_cycle_rand" "${total_cycle_rand}"
    set_config_opt "-register_rand_n" "${register_rand_n}"
    # If a specific register name is provided, override index-based selection; otherwise reset to empty
    if [[ -n "${REGISTER_NAME}" ]]; then
        set_config_opt "-register_name" "${REGISTER_NAME}"
    else
        set_config_opt "-register_name" '""'
    fi
    set_config_opt "-reg_bitflip_rand_n" "${reg_bitflip_rand_n}"
    set_config_opt "-per_warp" "${per_warp}"
    set_config_opt "-kernel_n" "${kernel_n}"
    set_config_opt "-local_mem_bitflip_rand_n" "${local_mem_bitflip_rand_n}"
    set_config_opt "-block_rand" "${block_rand}"
    set_config_opt "-block_n" "${blocks}"
    set_config_opt "-shared_mem_bitflip_rand_n" "${shared_mem_bitflip_rand_n}"
    set_config_opt "-l1d_shader_rand_n" "${l1d_shader_rand_n}"
    set_config_opt "-l1d_cache_bitflip_rand_n" "${l1d_cache_bitflip_rand_n}"
    set_config_opt "-l1c_shader_rand_n" "${l1c_shader_rand_n}"
    set_config_opt "-l1c_cache_bitflip_rand_n" "${l1c_cache_bitflip_rand_n}"
    set_config_opt "-l1t_shader_rand_n" "${l1t_shader_rand_n}"
    set_config_opt "-l1t_cache_bitflip_rand_n" "${l1t_cache_bitflip_rand_n}"
    set_config_opt "-l2_cache_bitflip_rand_n" "${l2_cache_bitflip_rand_n}"
    set_config_opt "-gmem_byte_seed" "${gmem_byte_seed}"
    set_config_opt "-gmem_target_addr" "${gmem_target_addr}"
}

gather_results() {
    for file in ${TMP_DIR}${1}/${TMP_FILE}*; do
        # Derive index for matching saved config
        idx=${file##*${TMP_FILE}}
        cfg_path="${TMP_DIR}${1}/${CONFIG_FILE}${idx}"
        trial_id="${idx}"
        trial_id_path="${TMP_DIR}${1}/trial_id${idx}"
        if [[ -f "${trial_id_path}" ]]; then
            trial_id="$(tr -d '[:space:]' < "${trial_id_path}")"
        fi
        exit_status=""
        exit_status_path="${TMP_DIR}${1}/exit_status${idx}"
        if [[ -f "${exit_status_path}" ]]; then
            exit_status="$(tr -d '[:space:]' < "${exit_status_path}")"
        fi
        if [[ -f "${cfg_path}" ]]; then
            # Extract parameters from saved config to emit a canonical key line
            # Helper to read value after a flag from the config
            get_val() { grep -E "^$1\b" "${cfg_path}" | awk '{print $2}' | tail -n1; }
            components_to_flip_cfg=$(get_val "-components_to_flip")
            thread_rand_cfg=$(get_val "-thread_rand")
            warp_rand_cfg=$(get_val "-warp_rand")
            total_cycle_rand_cfg=$(get_val "-total_cycle_rand")
            register_rand_n_cfg=$(get_val "-register_rand_n")
            register_name_cfg=$(get_val "-register_name")
            reg_bitflip_rand_n_cfg=$(get_val "-reg_bitflip_rand_n")
            local_mem_bitflip_rand_n_cfg=$(get_val "-local_mem_bitflip_rand_n")
            block_rand_cfg=$(get_val "-block_rand")
            shared_mem_bitflip_rand_n_cfg=$(get_val "-shared_mem_bitflip_rand_n")
            l1d_shader_rand_n_cfg=$(get_val "-l1d_shader_rand_n")
            l1d_cache_bitflip_rand_n_cfg=$(get_val "-l1d_cache_bitflip_rand_n")
            l1c_shader_rand_n_cfg=$(get_val "-l1c_shader_rand_n")
            l1c_cache_bitflip_rand_n_cfg=$(get_val "-l1c_cache_bitflip_rand_n")
            l1t_shader_rand_n_cfg=$(get_val "-l1t_shader_rand_n")
            l1t_cache_bitflip_rand_n_cfg=$(get_val "-l1t_cache_bitflip_rand_n")
            l2_cache_bitflip_rand_n_cfg=$(get_val "-l2_cache_bitflip_rand_n")
            kernel_n_cfg=$(get_val "-kernel_n")

            combo_line="comp=${components_to_flip_cfg};per_warp=${per_warp};kernel=${kernel_n_cfg};"
            combo_line+="thread=${thread_rand_cfg};warp=${warp_rand_cfg};block=${block_rand_cfg};cycle=${total_cycle_rand_cfg};"
            combo_line+="reg_name=${register_name_cfg};reg_rand_n=${register_rand_n_cfg};reg_bits=${reg_bitflip_rand_n_cfg};"
            combo_line+="local_bits=${local_mem_bitflip_rand_n_cfg};shared_bits=${shared_mem_bitflip_rand_n_cfg};"
            combo_line+="l1d_shader=${l1d_shader_rand_n_cfg};l1d_bits=${l1d_cache_bitflip_rand_n_cfg};"
            combo_line+="l1c_shader=${l1c_shader_rand_n_cfg};l1c_bits=${l1c_cache_bitflip_rand_n_cfg};"
            combo_line+="l1t_shader=${l1t_shader_rand_n_cfg};l1t_bits=${l1t_cache_bitflip_rand_n_cfg};"
            combo_line+="l2_bits=${l2_cache_bitflip_rand_n_cfg}"

            echo "[INJ_PARAMS] [Run ${1}] ${TMP_FILE}${idx} ${combo_line}"
        fi
        grep -a -iq "${SUCCESS_MSG}" "$file"; success_msg_grep=$(echo $?)
	grep -a -i "${CYCLES_MSG}" "$file" | tail -1 | grep -a -q "${CYCLES}"; cycles_grep=$(echo $?)
        grep -a -iq "${FAILED_MSG}" "$file"; failed_msg_grep=$(echo $?)
        if grep -a -qE "FI_WRITER|FI_READER" "$file"; then
            grep -a -hE "FI_WRITER|FI_READER" "$file" | while IFS= read -r line; do
            echo "[Run ${1}] Effects from ${file}: $line"
            done
        fi
        result=${success_msg_grep}${cycles_grep}${failed_msg_grep}

        # Get file name for display
        filename=$(basename "$file")
        outcome=""
        due_reason=""
        oracle_parse=""
        oracle_used=0

        if oracle_parse="$(classify_outcome_with_oracle "${file}" "${exit_status}" 2>/dev/null)"; then
            outcome="$(echo "${oracle_parse}" | sed -n '1p')"
            due_reason="$(echo "${oracle_parse}" | sed -n '2p')"
            oracle_used=1
        fi

        if [[ -z "${outcome}" ]]; then
            if [[ "${FI_OUTPUT_ORACLE_MODE}" == "single" ]]; then
                outcome="DUE"
                due_reason="output_oracle_unavailable"
            else
                case $result in
                "001" | "011")
                    outcome="Masked"
                    due_reason=""
                    ;;
                "100" | "110")
                    outcome="SDC"
                    due_reason=""
                    ;;
                *)
                    outcome="DUE"
                    due_reason="$(classify_due_reason "${file}" "${exit_status}")"
                    ;;
                esac
            fi
        fi

        let RUNS--
        case "${outcome}" in
        "Masked")
            let masked++
            if [[ "${cycles_grep}" -ne 0 ]]; then
                let performance++
                echo "[Run ${1}] ${filename}: Masked (with performance impact)"
            else
                echo "[Run ${1}] ${filename}: Masked (no performance impact)"
            fi
            ;;
        "SDC")
            let SDC++
            if [[ "${oracle_used}" -eq 1 ]]; then
                echo "[Run ${1}] ${filename}: SDC (oracle)"
            else
                echo "[Run ${1}] ${filename}: SDC"
            fi
            ;;
        *)
            let crashes++
            outcome="DUE"
            if [[ -z "${due_reason}" ]]; then
                due_reason="oracle_due"
            fi
            if grep -a -iq "${FAULT_INJECTION_OCCURRED}" "$file"; then
                echo "[Run ${1}] ${filename}: DUE (${due_reason})"
            else
                echo "[Run ${1}] ${filename}: DUE (${due_reason}; key=${result})"
            fi
            ;;
        esac
        log_fi_outcome "${trial_id}" "${outcome}" "${due_reason}" "${exit_status}" "${1}" "${filename}"
    done
}

serial_execution() {
    local run_index="$1"
    local local_index=1
    mkdir "${TMP_DIR}${run_index}" > /dev/null 2>&1
    if [[ -n "${FI_FORCE_TRIAL_ID:-}" ]]; then
        CURRENT_TRIAL_ID="${FI_FORCE_TRIAL_ID}"
    else
        CURRENT_TRIAL_ID=$((FI_TRIAL_COUNTER + 1))
        FI_TRIAL_COUNTER=${CURRENT_TRIAL_ID}
    fi
    CURRENT_TRIAL_SEED="${FI_SEED_BASE}"
    init_deterministic_prng "${CURRENT_TRIAL_SEED}" "${CURRENT_TRIAL_ID}"
    initialize_config
    set_config_opt "-run_uid" "t${CURRENT_TRIAL_ID}_r${run_index}"
    cp ${CONFIG_FILE} "${TMP_DIR}${run_index}/${CONFIG_FILE}${local_index}" # save state
    echo "${CURRENT_TRIAL_ID}" > "${TMP_DIR}${run_index}/trial_id${local_index}"
    launch_uut_guarded "${TMP_DIR}${run_index}/${TMP_FILE}${local_index}" "${TMP_DIR}${run_index}/exit_status${local_index}"
    gather_results "${run_index}"
    if [[ "$DELETE_LOGS" -eq 1 ]]; then
        rm _ptx* _cuobjdump_* _app_cuda* *.ptx f_tempfile_ptx gpgpu_inst_stats.txt > /dev/null 2>&1
        rm -r "${TMP_DIR}${run_index}" > /dev/null 2>&1 # comment out to debug output
    fi
    if [[ "$profile" -ne 1 ]]; then
        # clean intermediate logs anyway if profile != 1
        rm _ptx* _cuobjdump_* _app_cuda* *.ptx f_tempfile_ptx gpgpu_inst_stats.txt > /dev/null 2>&1
    fi
    return 0
}

prepare_parallel_trial_workspace() {
    local trial_dir="$1"
    local uut_exe uut_src uut_base

    if ! rm -rf "${trial_dir}"; then
        echo "=== Error: failed to remove stale FI trial workspace: ${trial_dir} ===" >&2
        return 1
    fi
    if ! mkdir -p "${trial_dir}"; then
        echo "=== Error: failed to create FI trial workspace: ${trial_dir} ===" >&2
        return 1
    fi

    if ! cp -f "${CONFIG_FILE}" "${trial_dir}/gpgpusim.config"; then
        echo "=== Error: failed to copy gpgpu-sim config into FI trial workspace: ${CONFIG_FILE} -> ${trial_dir}/gpgpusim.config ===" >&2
        return 1
    fi
    if [[ -f "${CYCLES_FILE}" ]]; then
        if ! cp -f "${CYCLES_FILE}" "${trial_dir}/cycles.txt"; then
            echo "=== Error: failed to copy FI cycles file into trial workspace: ${CYCLES_FILE} -> ${trial_dir}/cycles.txt ===" >&2
            return 1
        fi
    fi
    if [[ -f "${INVALID_COMBOS_FILE}" ]]; then
        if ! cp -f "${INVALID_COMBOS_FILE}" "${trial_dir}/invalid_param_combos.txt"; then
            echo "=== Error: failed to copy FI invalid-combos file into trial workspace: ${INVALID_COMBOS_FILE} -> ${trial_dir}/invalid_param_combos.txt ===" >&2
            return 1
        fi
    fi
    if [[ -f "result.txt" ]]; then
        if ! cp -f "result.txt" "${trial_dir}/result.txt"; then
            echo "=== Error: failed to copy FI golden result into trial workspace: result.txt -> ${trial_dir}/result.txt ===" >&2
            return 1
        fi
    fi
    if [[ -f "register_used.txt" ]]; then
        if ! cp -f "register_used.txt" "${trial_dir}/register_used.txt"; then
            echo "=== Error: failed to copy FI register list into trial workspace: register_used.txt -> ${trial_dir}/register_used.txt ===" >&2
            return 1
        fi
    fi

    uut_exe="${CUDA_UUT%% *}"
    if [[ "${uut_exe}" == ./* ]]; then
        uut_src="${uut_exe#./}"
        uut_base="$(basename "${uut_src}")"
        if ! cp -f "${uut_src}" "${trial_dir}/${uut_base}"; then
            echo "=== Error: failed to copy FI executable into trial workspace: ${uut_src} -> ${trial_dir}/${uut_base} ===" >&2
            return 1
        fi
        chmod +x "${trial_dir}/${uut_base}" 2>/dev/null || true
        if [[ -f "${uut_src}.ptx" ]]; then
            if ! cp -f "${uut_src}.ptx" "${trial_dir}/${uut_base}.ptx"; then
                echo "=== Error: failed to copy FI PTX into trial workspace: ${uut_src}.ptx -> ${trial_dir}/${uut_base}.ptx ===" >&2
                return 1
            fi
        fi
        if [[ -f "${uut_src}.1.${GPU_ARCH:-sm_75}.ptx" ]]; then
            if ! cp -f "${uut_src}.1.${GPU_ARCH:-sm_75}.ptx" "${trial_dir}/${uut_base}.1.${GPU_ARCH:-sm_75}.ptx"; then
                echo "=== Error: failed to copy FI architecture PTX into trial workspace: ${uut_src}.1.${GPU_ARCH:-sm_75}.ptx -> ${trial_dir}/${uut_base}.1.${GPU_ARCH:-sm_75}.ptx ===" >&2
                return 1
            fi
        fi
    fi
}

parallel_trial_execution() {
    local run_index="$1"
    local trial_dir="$2"

    if ! prepare_parallel_trial_workspace "${trial_dir}"; then
        echo "=== Error: failed to prepare FI parallel trial workspace for run ${run_index}: ${trial_dir} ===" >&2
        return 1
    fi
    (
        if ! cd "${trial_dir}"; then
            echo "=== Error: failed to enter FI parallel trial workspace for run ${run_index}: ${trial_dir} ===" >&2
            exit 1
        fi
        CONFIG_FILE="./gpgpusim.config"
        TMP_DIR="./logs"
        CACHE_LOGS_DIR="./cache_logs"
        INVALID_COMBOS_FILE="./invalid_param_combos.txt"
        if [[ -f "./cycles.txt" ]]; then
            CYCLES_FILE="./cycles.txt"
        fi
        FI_FORCE_TRIAL_ID="${run_index}"
        serial_execution "${run_index}"
    )
}

PARALLEL_CHILD_PIDS=()
PARALLEL_CHILD_LOGS=()
PARALLEL_CHILD_STATUS=()

terminate_parallel_jobs() {
    local pid
    for pid in "${PARALLEL_CHILD_PIDS[@]:-}"; do
        if [[ -n "${pid}" ]]; then
            kill "${pid}" 2>/dev/null || true
        fi
    done
    for pid in "${PARALLEL_CHILD_PIDS[@]:-}"; do
        if [[ -n "${pid}" ]]; then
            wait "${pid}" 2>/dev/null || true
        fi
    done
    PARALLEL_CHILD_PIDS=()
    PARALLEL_CHILD_LOGS=()
    PARALLEL_CHILD_STATUS=()
}

campaign_cleanup() {
    terminate_parallel_jobs
    cleanup_trial_logging
}

start_parallel_job() {
    local run_index="$1"
    local parallel_root="$2"
    local trial_dir="${parallel_root}/trial_${run_index}"
    local log_file="${parallel_root}/job_logs/run_${run_index}.log"
    local status_file="${parallel_root}/job_logs/run_${run_index}.status"

    (
        (
            parallel_trial_execution "${run_index}" "${trial_dir}"
        )
        rc=$?
        printf '%s\n' "${rc}" > "${status_file}"
        exit "${rc}"
    ) > "${log_file}" 2>&1 &

    PARALLEL_CHILD_PIDS+=("$!")
    PARALLEL_CHILD_LOGS+=("${log_file}")
    PARALLEL_CHILD_STATUS+=("${status_file}")
}

reap_completed_parallel_jobs() {
    local blocking="${1:-0}"
    local had_completion status pid log_file status_file i
    local -a next_pids=()
    local -a next_logs=()
    local -a next_status=()

    while true; do
        had_completion=0
        next_pids=()
        next_logs=()
        next_status=()
        for i in "${!PARALLEL_CHILD_PIDS[@]}"; do
            pid="${PARALLEL_CHILD_PIDS[$i]}"
            log_file="${PARALLEL_CHILD_LOGS[$i]}"
            status_file="${PARALLEL_CHILD_STATUS[$i]}"
            if [[ -f "${status_file}" ]]; then
                status="$(tr -d '[:space:]' < "${status_file}")"
                wait "${pid}" 2>/dev/null || true
                cat "${log_file}"
                had_completion=1
                if ! [[ "${status}" =~ ^[0-9]+$ ]] || (( status != 0 )); then
                    echo "=== Error: FI parallel trial failed: pid=${pid}, status=${status:-missing}, log=${log_file} ===" >&2
                    return 1
                fi
            elif ! kill -0 "${pid}" 2>/dev/null; then
                wait "${pid}" 2>/dev/null || true
                cat "${log_file}" 2>/dev/null || true
                had_completion=1
                echo "=== Error: FI parallel trial exited without a status file: pid=${pid}, status_file=${status_file}, log=${log_file} ===" >&2
                return 1
            else
                next_pids+=("${pid}")
                next_logs+=("${log_file}")
                next_status+=("${status_file}")
            fi
        done
        PARALLEL_CHILD_PIDS=("${next_pids[@]}")
        PARALLEL_CHILD_LOGS=("${next_logs[@]}")
        PARALLEL_CHILD_STATUS=("${next_status[@]}")

        if (( had_completion == 1 )); then
            return 0
        fi
        if (( blocking == 0 || ${#PARALLEL_CHILD_PIDS[@]} == 0 )); then
            return 0
        fi
        sleep 0.2
    done
}

print_parallel_summary_from_logs() {
    local log_dir="$1"
    awk '
        /^\[Run[[:space:]]+[0-9]+\][[:space:]]+tmp\.out[0-9]+:[[:space:]]+Masked/ {
            masked++
            if ($0 ~ /with performance impact/) performance++
            next
        }
        /^\[Run[[:space:]]+[0-9]+\][[:space:]]+tmp\.out[0-9]+:[[:space:]]+SDC/ {
            sdc++
            next
        }
        /^\[Run[[:space:]]+[0-9]+\][[:space:]]+tmp\.out[0-9]+:[[:space:]]+DUE/ {
            due++
            next
        }
        END {
            printf "Masked: %d (performance = %d)\n", masked + 0, performance + 0
            printf "SDCs: %d\n", sdc + 0
            printf "DUEs: %d\n", due + 0
        }
    ' "${log_dir}"/run_*.log 2>/dev/null
}

parallel_execution() {
    local total_runs="$1"
    local parallel_jobs="${FI_PARALLEL_JOBS}"
    local parallel_root="${TMP_DIR}.parallel.$$"
    local next_run=1

    if (( total_runs <= 0 )); then
        return 0
    fi
    if (( parallel_jobs > total_runs )); then
        parallel_jobs="${total_runs}"
    fi
    mkdir -p "${parallel_root}/job_logs"
    echo "=== Campaign exec guarded settings: app/component serial, trial parallel_jobs=${parallel_jobs} ==="

    while (( next_run <= total_runs )); do
        start_parallel_job "${next_run}" "${parallel_root}"
        next_run=$((next_run + 1))
        while (( ${#PARALLEL_CHILD_PIDS[@]} >= parallel_jobs )); do
            if ! reap_completed_parallel_jobs 1; then
                terminate_parallel_jobs
                return 1
            fi
        done
    done

    while (( ${#PARALLEL_CHILD_PIDS[@]} > 0 )); do
        if ! reap_completed_parallel_jobs 1; then
            terminate_parallel_jobs
            return 1
        fi
    done

    print_parallel_summary_from_logs "${parallel_root}/job_logs"
    RUNS=0
    if [[ "$DELETE_LOGS" -eq 1 ]]; then
        rm -rf "${parallel_root}" > /dev/null 2>&1 || true
    fi
    return 0
}

trap campaign_cleanup EXIT

main() {
    sanitize_run_settings
    CAMPAIGN_ORIGINAL_CWD="$(pwd)"
    canonicalize_optional_file_var FI_INJECTION_POINTS_FILE
    canonicalize_optional_file_var FI_OUTCOMES_FILE
    canonicalize_optional_file_var FI_ACTIVE_THREADS_LOG
    canonicalize_optional_file_var FI_ANALYZER_OUTPUT
    canonicalize_optional_file_var FI_GOLDEN_LOG
    canonicalize_optional_file_var FI_OUTPUT_SPEC
    canonicalize_optional_file_var CYCLES_FILE
    normalize_parallel_jobs
    echo "=== Campaign exec guarded settings: app/component serial, trial_parallel_jobs=${FI_PARALLEL_JOBS}, nice=${SIM_NICE} ==="
    auto_detect_cache_size_bits
    init_trial_logging
    # Normalize existing invalid combos to reduced keys (idempotent)
    if [[ -f "${INVALID_COMBOS_FILE}" ]]; then
        tmp_reduced=$(mktemp)
        awk -F';' '
        function getv(kv, k) { return (k in kv)?kv[k]:"" }
        {
            delete kv
            for (i=1; i<=NF; ++i) {
                split($i, a, "=")
                k=a[1]; sub(/^\s+|\s+$/,"",k)
                v=a[2]; sub(/^\s+|\s+$/,"",v)
                kv[k]=v
            }
            key = "comp=" getv(kv,"comp") ";per_warp=" getv(kv,"per_warp") ";kernel=" getv(kv,"kernel") ";"
            key = key "thread=" getv(kv,"thread") ";warp=" getv(kv,"warp") ";block=" getv(kv,"block") ";cycle=" getv(kv,"cycle") ";"
            key = key "reg_name=" getv(kv,"reg_name") ";reg_rand_n=" getv(kv,"reg_rand_n")
            if (!(key in seen)) { print key; seen[key]=1 }
        }' "${INVALID_COMBOS_FILE}" > "$tmp_reduced" 2>/dev/null || true
        if [[ -s "$tmp_reduced" ]]; then
            mv "$tmp_reduced" "${INVALID_COMBOS_FILE}"
        else
            rm -f "$tmp_reduced"
        fi
    fi
    # Remove only top-level transient simulator logs.  Do not recursively delete
    # archived evidence directories under compare/raw_speed_artifacts whose names
    # may also start with "logs".
    find . -maxdepth 1 -type d -name "logs*" -exec rm -rf {} + 2>/dev/null || true

    if [[ "$profile" -eq 1 ]] || [[ "$profile" -eq 2 ]] || [[ "$profile" -eq 3 ]]; then
        RUNS=1
    fi
    if (( FI_PARALLEL_JOBS > 1 )); then
        local total_parallel_runs
        total_parallel_runs="${RUNS}"
        if ! parallel_execution "${total_parallel_runs}"; then
            echo "Parallel FI campaign failed." >&2
            exit 1
        fi
        if [[ "$DELETE_LOGS" -eq 1 ]]; then
            rm -r ${CACHE_LOGS_DIR} > /dev/null 2>&1 # comment out to debug cache logs
        fi
        return 0
    fi
    # MAX_RETRIES to avoid flooding the system storage with logs infinitely if the user
    # has wrong configuration and only Unclassified errors are returned
    MAX_RETRIES=3
    LOOP=1
    mkdir ${CACHE_LOGS_DIR} > /dev/null 2>&1
    while [[ $RUNS -gt 0 ]] && [[ $MAX_RETRIES -gt 0 ]]
    do
        echo "runs left ${RUNS}" # DEBUG
        let MAX_RETRIES--
        RUNS_THIS_PASS=${RUNS}
        for i in $( seq 1 ${RUNS_THIS_PASS} ); do
            if [[ $RUNS -le 0 ]]; then
                break
            fi
            serial_execution "${LOOP}"
            let LOOP++
        done
    done

    if [[ $MAX_RETRIES -eq 0 ]]; then
        echo "Probably \"${CUDA_UUT}\" was not able to run! Please make sure the execution with GPGPU-Sim works!"
    else
        echo "Masked: ${masked} (performance = ${performance})"
        echo "SDCs: ${SDC}"
        echo "DUEs: ${crashes}"
    fi
    if [[ "$DELETE_LOGS" -eq 1 ]]; then
        rm -r ${CACHE_LOGS_DIR} > /dev/null 2>&1 # comment out to debug cache logs
    fi
}

main "$@"
exit 0
