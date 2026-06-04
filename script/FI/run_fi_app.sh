#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMMON_DIR="${ROOT_DIR}/script/common"
cd "${ROOT_DIR}"

reject_output_tolerance_override() {
    local name="$1"
    local value="${2:-}"
    local stripped="${value//$'\n'/}"
    stripped="${stripped//$'\r'/}"
    stripped="${stripped//$'\t'/}"
    stripped="${stripped// /}"
    if [[ -n "${stripped}" && "${stripped}" != "{}" ]]; then
        echo "=== Error: ${name} is not accepted by the public FI path. ===" >&2
        echo "=== FI uses explicit application oracles when available; otherwise it compares outputs exactly. ===" >&2
        exit 2
    fi
}

if [[ -v OUTPUT_ORACLE_TOL_POLICY ]]; then
    reject_output_tolerance_override "OUTPUT_ORACLE_TOL_POLICY" "${OUTPUT_ORACLE_TOL_POLICY}"
fi
if [[ -v FI_OUTPUT_ORACLE_TOL_POLICY ]]; then
    reject_output_tolerance_override "FI_OUTPUT_ORACLE_TOL_POLICY" "${FI_OUTPUT_ORACLE_TOL_POLICY}"
fi

TEST_APP_NAME="${TEST_APP_NAME:-MatrixFactorization}"
COMPONENT_SET="${COMPONENT_SET:-0}" # 0:RF, 1:local_mem, 2:shared_mem, 3:L1D_cache, 4:L1C_cache, 5:L1T_cache, 6:L2_cache, 11:GMEM
INJECT_BIT_FLIP_COUNT="${INJECT_BIT_FLIP_COUNT:-1}" # number of bits to flip per injection (e.g. 2 means flip 2 bits per injection)

RUN_PER_EPOCH="${RUN_PER_EPOCH:-384}"
GPU_ARCH="${GPU_ARCH:-auto}" # auto | sm_XX

RF_FAULT_MODEL="${RF_FAULT_MODEL:-persistent}"
ANALYZER_ADDR_DUE_MODE="${ANALYZER_ADDR_DUE_MODE:-none}"
TRACE_EXPANDING_POLICY="${TRACE_EXPANDING_POLICY:-masked}"
# Public artifact reproducibility seed. Keep fixed across run_experiment.sh runs.
FI_SEED_BASE=2026
FI_LOG_ROOT="${FI_LOG_ROOT:-exact_sdc_runs}"
FI_COMPARE_INPUT_ROOT="${FI_COMPARE_INPUT_ROOT:-exact_sdc_runs_all}"
CAMPAIGN_EXEC_TEMPLATE="${CAMPAIGN_EXEC_SCRIPT:-${COMMON_DIR}/campaign_exec.sh}"
OUTPUT_ORACLE_TOL_POLICY="${OUTPUT_ORACLE_TOL_POLICY:-{}}"
OUTPUT_ORACLE_TOL_POLICY_BASE="${OUTPUT_ORACLE_TOL_POLICY}"
OUTPUT_ORACLE_TIMEOUT_EXIT_STATUSES="${OUTPUT_ORACLE_TIMEOUT_EXIT_STATUSES:-124:137}"
OUTPUT_ORACLE_TOL_POLICY_SOURCE="${OUTPUT_ORACLE_TOL_POLICY_SOURCE:-default_exact}"
FI_PROGRESS_EVENTS="${FI_PROGRESS_EVENTS:-0}"
FI_PROGRESS_APP="${FI_PROGRESS_APP:-${TEST_APP_NAME}}"
FI_PROGRESS_APP_INDEX="${FI_PROGRESS_APP_INDEX:-0}"
FI_PROGRESS_APP_TOTAL="${FI_PROGRESS_APP_TOTAL:-0}"
FI_PROGRESS_COMPONENT="${FI_PROGRESS_COMPONENT:-${COMPONENT_SET}}"
FI_PROGRESS_COMPONENT_INDEX="${FI_PROGRESS_COMPONENT_INDEX:-0}"
FI_PROGRESS_COMPONENT_TOTAL="${FI_PROGRESS_COMPONENT_TOTAL:-0}"


DO_BUILD="${DO_BUILD:-1}" # 1: build before run, 0: skip build
DO_RESULT_GEN="${DO_RESULT_GEN:-1}" # 1: generate result files, 0: skip result generation



# set cuda installation path
export CUDA_INSTALL_PATH="${CUDA_INSTALL_PATH:-/usr/local/cuda}"
CONFIG_FILE=./gpgpusim.config

# -------- Global metrics storage (script-wide) --------
GLOBAL_CYCLES=""
GLOBAL_MAX_REGISTERS_USED=""
GLOBAL_SHADER_USED=""
GLOBAL_DATATYPE_SIZE=""
GLOBAL_LMEM_SIZE_BITS=""
GLOBAL_SMEM_SIZE_BITS=""
GLOBAL_EXEC_TIME=""
GLOBAL_THREAD_RAND_MAX=""
GLOBAL_WARP_RAND_MAX=""
GLOBAL_BLOCK_RAND_MAX=""
GLOBAL_COMPONENT_SET=""
CMD_PID=""
PROGRESS_MONITOR_PID=""

get_config_numeric_opt() {
    local opt="$1"
    local val
    val="$(awk -v opt="${opt}" '$1 == opt {print $2; exit}' "${CONFIG_FILE}" 2>/dev/null)"
    echo "${val}"
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

detect_gpu_arch() {
    local profile_log="${1:-}"
    local auto_arch="" cap major minor

    if [[ -n "${GPU_ARCH}" && "${GPU_ARCH}" != "auto" ]]; then
        echo "Using manually configured GPU_ARCH: ${GPU_ARCH}"
        return
    fi

    if [[ -f "${CONFIG_FILE}" ]]; then
        cap="$(get_config_numeric_opt "-gpgpu_ptx_force_max_capability")"
        if [[ "${cap}" =~ ^[0-9]+$ ]]; then
            auto_arch="sm_${cap}"
        else
            major="$(get_config_numeric_opt "-gpgpu_compute_capability_major")"
            minor="$(get_config_numeric_opt "-gpgpu_compute_capability_minor")"
            if [[ "${major}" =~ ^[0-9]+$ && "${minor}" =~ ^[0-9]+$ ]]; then
                auto_arch="sm_${major}${minor}"
            fi
        fi
    fi

    if [[ -z "${auto_arch}" && -n "${profile_log}" && -f "${profile_log}" ]]; then
        auto_arch="$(grep -m1 -oE 'sm_[0-9]+' "${profile_log}")"
    fi

    if [[ -z "${auto_arch}" ]]; then
        auto_arch="sm_75"
        echo "Warning: failed to auto-detect GPU_ARCH from ${CONFIG_FILE}/tmp.out, fallback to ${auto_arch}"
    fi

    GPU_ARCH="${auto_arch}"
    echo "Auto-detected GPU_ARCH: ${GPU_ARCH}"
}

cleanup() {
    echo -e "\nInterrupted. Killing campaign_exec.sh (PID=${CMD_PID:-})..."
    if [[ -n "${PROGRESS_MONITOR_PID:-}" ]]; then
        kill "${PROGRESS_MONITOR_PID}" 2>/dev/null || true
    fi
    if [[ -n "${CMD_PID:-}" ]]; then
        kill "${CMD_PID}" 2>/dev/null || true
        wait "${CMD_PID}" 2>/dev/null || true
    fi
    exit 1
}

ns_to_seconds() {
    local ns="${1:-0}"
    awk -v ns="${ns}" 'BEGIN { printf "%.6f", ns / 1000000000 }'
}

count_fi_completed_tasks() {
    local log_path="${1:-}"
    if [[ -z "${log_path}" || ! -f "${log_path}" ]]; then
        echo 0
        return 0
    fi
    awk '
        /^\[Run[[:space:]]+[0-9]+\][[:space:]].*: (Masked|SDC|DUE)([[:space:]\(]|$)/ { count++ }
        END { print count + 0 }
    ' "${log_path}"
}

print_fi_progress() {
    local completed="${1:-0}"
    local total="${2:-0}"
    local final="${3:-0}"
    local percent left bar_len filled bar empty

    if ! [[ "${total}" =~ ^[0-9]+$ ]] || (( total <= 0 )); then
        total=1
    fi
    if ! [[ "${completed}" =~ ^[0-9]+$ ]] || (( completed < 0 )); then
        completed=0
    fi
    if (( completed > total )); then
        completed="${total}"
    fi

    left=$(( total - completed ))
    percent=$(( completed * 100 / total ))
    if [[ "${FI_PROGRESS_EVENTS}" == "1" ]]; then
        printf '[FI_PROGRESS]\tapp=%s\tapp_index=%s\tapp_total=%s\tcomponent=%s\tcomponent_index=%s\tcomponent_total=%s\tcompleted=%d\ttotal=%d\tpercent=%d\tfinal=%s\n' \
            "${FI_PROGRESS_APP}" \
            "${FI_PROGRESS_APP_INDEX}" \
            "${FI_PROGRESS_APP_TOTAL}" \
            "${FI_PROGRESS_COMPONENT}" \
            "${FI_PROGRESS_COMPONENT_INDEX}" \
            "${FI_PROGRESS_COMPONENT_TOTAL}" \
            "${completed}" \
            "${total}" \
            "${percent}" \
            "${final}"
        return 0
    fi
    bar_len=50
    filled=$(( percent * bar_len / 100 ))
    bar=$(printf "%${filled}s" | tr " " "#")
    empty=$(printf "%$(( bar_len - filled ))s")

    printf "\rProgress: [%-50s] %3d%%  completed %d/%d  runs left %d\033[K" \
        "$bar$empty" "$percent" "$completed" "$total" "$left"
    if [[ "${final}" == "1" ]]; then
        echo
    fi
}

monitor_fi_progress() {
    local log_path="${1:?log path is required}"
    local total="${2:?total task count is required}"
    local target_pid="${3:?target pid is required}"
    local completed last_completed

    last_completed=-1
    while kill -0 "${target_pid}" 2>/dev/null; do
        completed="$(count_fi_completed_tasks "${log_path}")"
        if [[ "${completed}" != "${last_completed}" ]]; then
            print_fi_progress "${completed}" "${total}" 0
            last_completed="${completed}"
        fi
        sleep 1
    done
    completed="$(count_fi_completed_tasks "${log_path}")"
    print_fi_progress "${completed}" "${total}" 1
}

resolve_output_oracle_policy() {
    local requested_policy="${OUTPUT_ORACLE_TOL_POLICY_BASE:-${OUTPUT_ORACLE_TOL_POLICY}}"
    local stripped="${requested_policy//$'\n'/}"
    stripped="${stripped//$'\r'/}"
    stripped="${stripped//$'\t'/}"
    stripped="${stripped// /}"
    if [[ -z "${stripped}" || "${stripped}" == "{}" ]]; then
        OUTPUT_ORACLE_TOL_POLICY="{}"
        OUTPUT_ORACLE_TOL_POLICY_SOURCE="default_exact"
    else
        OUTPUT_ORACLE_TOL_POLICY="${requested_policy}"
        OUTPUT_ORACLE_TOL_POLICY_SOURCE="explicit"
    fi
}

resolve_output_oracle_policy_from_sara_input() {
    local fi_input_dir="$1"
    local policy_file="${fi_input_dir}/output_oracle_policy.json"

    if [[ -f "${policy_file}" ]]; then
        OUTPUT_ORACLE_TOL_POLICY="$(cat "${policy_file}")"
        OUTPUT_ORACLE_TOL_POLICY_SOURCE="sara_input_policy"
    else
        resolve_output_oracle_policy
    fi
}

# -------- CYCLES --------
get_cycles() {
    local v
    v=$(grep -E "^gpu_tot_sim_cycle\s*=\s*[0-9]+" "$FILE_PATH" | tail -n1 | sed -E 's/.*=\s*([0-9]+).*/\1/')
    if [ -z "$v" ]; then
        v=$(grep -E "^gpu_sim_cycle\s*=\s*[0-9]+" "$FILE_PATH" | tail -n1 | sed -E 's/.*=\s*([0-9]+).*/\1/')
    fi
    echo "${v:-0}"
}

# -------- regs/lmem/smem (bytes) --------
get_kernel_triplet() {
    local line regs lmem smem
    line=$(grep -m1 -E "regs=[0-9]+,\s*lmem=[0-9]+,\s*smem=[0-9]+" "$FILE_PATH")
    if [ -z "$line" ]; then
        echo "0 0 0"
        return
    fi
    regs=$(echo "$line" | sed -E 's/.*regs=([0-9]+).*/\1/')
    lmem=$(echo "$line" | sed -E 's/.*lmem=([0-9]+).*/\1/')
    smem=$(echo "$line" | sed -E 's/.*smem=([0-9]+).*/\1/')
    echo "$regs $lmem $smem"
}

# -------- MULTI-KERNEL: collect per-kernel info and global maxima --------
collect_kernels_info() {
    echo "=== Collecting kernel information ==="
    # Output two sections via stdout separated by a blank line:
    # 1) Per-kernel lines: KERNEL\t<idx>\t<name>\t<regs>\t<lmem_bytes>\t<smem_bytes>\t<shader_ids_space_separated>
    # 2) One summary line: SUMMARY\t<max_regs>\t<max_lmem_bytes>\t<max_smem_bytes>\t<all_shader_ids_union>
    declare -A REG_MAP LMEM_MAP SMEM_MAP KSHADERS SEEN_SHADER_K SEEN_SHADER_G
    declare -A KID_NAME KID_CYCLES KID_SHADERS SEEN_SHADER_KID
    declare -a SHADER_UNION=()
    kernels_order=()
    kids_order=()

    # kernel resource lines
    while IFS= read -r line; do
        kname=$(echo "$line" | sed -E "s/.*Kernel '([^']+)'.*/\1/")
        regs=$(echo "$line" | sed -E 's/.*regs=([0-9]+).*/\1/')
        lmem=$(echo "$line" | sed -E 's/.*lmem=([0-9]+).*/\1/')
        smem=$(echo "$line" | sed -E 's/.*smem=([0-9]+).*/\1/')
        if [[ -n "$kname" ]]; then
            if [[ -z ${REG_MAP[$kname]} || ${REG_MAP[$kname]} -lt $regs ]]; then REG_MAP[$kname]=$regs; fi
            if [[ -z ${LMEM_MAP[$kname]} || ${LMEM_MAP[$kname]} -lt $lmem ]]; then LMEM_MAP[$kname]=$lmem; fi
            if [[ -z ${SMEM_MAP[$kname]} || ${SMEM_MAP[$kname]} -lt $smem ]]; then SMEM_MAP[$kname]=$smem; fi
            # record order once
            if [[ ! " ${kernels_order[*]} " =~ " $kname " ]]; then kernels_order+=("$kname"); fi
        fi
    done < <(grep -E "GPGPU-Sim PTX: Kernel '.*' : regs=[0-9]+, lmem=[0-9]+, smem=[0-9]+" "$FILE_PATH")

    # shader binding lines, also map kernel id -> name
    while IFS= read -r line; do
        parsed=$(echo "$line" | sed -E "s/.*Shader ([0-9]+) bind to kernel ([0-9]+) '([^']+)'.*/\1\t\2\t\3/")
        sid=$(echo "$parsed" | cut -f1)
        kid=$(echo "$parsed" | cut -f2)
        kname=$(echo "$parsed" | cut -f3-)
        if [[ -n "$kname" ]]; then
            key="$kname|$sid"
            if [[ -z ${SEEN_SHADER_K[$key]} ]]; then
                if [[ -z ${KSHADERS[$kname]} ]]; then KSHADERS[$kname]="$sid"; else KSHADERS[$kname]="${KSHADERS[$kname]} $sid"; fi
                SEEN_SHADER_K[$key]=1
            fi
            # per-invocation shader list
            key_kid="$kid|$sid"
            if [[ -z ${SEEN_SHADER_KID[$key_kid]} ]]; then
                if [[ -z ${KID_SHADERS[$kid]} ]]; then KID_SHADERS[$kid]="$sid"; else KID_SHADERS[$kid]="${KID_SHADERS[$kid]} $sid"; fi
                SEEN_SHADER_KID[$key_kid]=1
            fi
            if [[ -z ${SEEN_SHADER_G[$sid]} ]]; then
                SHADER_UNION+=("$sid")
                SEEN_SHADER_G[$sid]=1
            fi
            if [[ -z ${KID_NAME[$kid]} ]]; then KID_NAME[$kid]="$kname"; kids_order+=("$kid"); fi
            if [[ ! " ${kernels_order[*]} " =~ " $kname " ]]; then kernels_order+=("$kname"); fi
        fi
    done < <(grep -E "GPGPU-Sim uArch: Shader [0-9]+ bind to kernel [0-9]+ '.*'" "$FILE_PATH")

    # per-invocation cycles: scan sequentially to associate the first gpu_sim_cycle after each kernel_launch_uid
    pending_kid=""
    while IFS= read -r line; do
        if [[ $line =~ ^kernel_launch_uid[[:space:]]*=[[:space:]]*([0-9]+) ]]; then
            pending_kid="${BASH_REMATCH[1]}"
            continue
        fi
        if [[ -n "$pending_kid" && $line =~ ^gpu_sim_cycle[[:space:]]*=[[:space:]]*([0-9]+) ]]; then
            # only set once per pending kid
            if [[ -z ${KID_CYCLES[$pending_kid]} ]]; then
                KID_CYCLES[$pending_kid]="${BASH_REMATCH[1]}"
            fi
            pending_kid=""
            continue
        fi
    done < "$FILE_PATH"

    # print per-kernel lines
    idx=0
    for k in "${kernels_order[@]}"; do
        [[ -z "$k" ]] && continue
        ((idx++))
        # cycles per kernel (sum of its kids)
        sumc=0
        for kid in "${kids_order[@]}"; do
            [[ -z "$kid" ]] && continue
            [[ "${KID_NAME[$kid]}" != "$k" ]] && continue
            (( sumc += ${KID_CYCLES[$kid]:-0} ))
        done
        printf "KERNEL\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n" \
            "$idx" "$k" "${REG_MAP[$k]:-0}" "${LMEM_MAP[$k]:-0}" "${SMEM_MAP[$k]:-0}" "${KSHADERS[$k]}" "$sumc"
    done

    # summary
    max_regs=0; max_lmem=0; max_smem=0
    for k in "${kernels_order[@]}"; do
        (( ${REG_MAP[$k]:-0} > max_regs )) && max_regs=${REG_MAP[$k]:-0}
        (( ${LMEM_MAP[$k]:-0} > max_lmem )) && max_lmem=${LMEM_MAP[$k]:-0}
        (( ${SMEM_MAP[$k]:-0} > max_smem )) && max_smem=${SMEM_MAP[$k]:-0}
    done
    # sort union shader ids numerically
    all_shaders=$(printf "%s\n" "${SHADER_UNION[@]}" | sort -n | uniq | paste -sd' ' -)
    printf "\nSUMMARY\t%s\t%s\t%s\t%s\n" "$max_regs" "$max_lmem" "$max_smem" "$all_shaders"

    # print per-invocation lines
    if ((${#kids_order[@]} > 0)); then
        printf "\nKERNEL_INVOCATIONS:\n"
        # sort kid order numerically
        sorted_kids=$(printf "%s\n" "${kids_order[@]}" | sort -n | uniq)
        while IFS= read -r kid; do
            [[ -z "$kid" ]] && continue
            kname="${KID_NAME[$kid]}"
            printf -- "- id=%s name=%s regs=%s lmem=%s smem=%s shader_used=%s cycles=%s\n" \
                "$kid" "${kname}" "${REG_MAP[$kname]:-0}" "${LMEM_MAP[$kname]:-0}" "${SMEM_MAP[$kname]:-0}" \
                "${KID_SHADERS[$kid]}" "${KID_CYCLES[$kid]:-0}"
        done <<< "$sorted_kids"
    fi
}

# -------- SHADER_USED (space-separated list of shader IDs) --------
get_shader_used_list() {
    grep -oP 'Shader\s+\K\d+' "$FILE_PATH" | sort -n | uniq | paste -sd' ' -
}

# -------- DATATYPE_SIZE (bits) --------
get_datatype_bits() {
    # Pick the maximum data width observed in the log to avoid underestimating bit width.
    local bits=0
    if grep -qE '(%rd[0-9]+|\.(u|s|f|b)64\b)' "$FILE_PATH"; then
        bits=64
    fi
    if (( bits < 32 )) && grep -qE '\.(u|s|f|b)32\b' "$FILE_PATH"; then
        bits=32
    fi
    if (( bits < 16 )) && grep -qE '\.(u|s|f|b)16\b' "$FILE_PATH"; then
        bits=16
    fi
    if (( bits < 8 )) && grep -qE '\.(u|s|f|b)8\b' "$FILE_PATH"; then
        bits=8
    fi
    if (( bits == 0 )); then
        bits=32
    fi
    echo "$bits"
}

get_metrics() {
    echo "=== Extracting metrics from logs ==="
    local cycles regs lmem smem lmem_bits smem_bits shader_used_list dtype_bits exec_time
    local max_regs max_lmem max_smem all_shaders
    local max_threads max_warps max_blocks

    # Maps for dynamic shared-memory inference (per kernel)
    declare -A K_STATIC_SMEM_BYTES  # from resource line smem= (static only)
    declare -A K_BLOCK_ELEMS        # blockDim.x*blockDim.y*blockDim.z
    declare -A K_GRID_BLOCKS       # gridDim.x*gridDim.y*gridDim.z
    declare -A K_SHARED_ELEM_BYTES  # inferred element width from ld/st.shared.* (bytes)
    declare -A K_EFFECTIVE_SMEM     # effective smem bytes per kernel (max(static, dynamic_est))
    declare -A K_TOTAL_THREADS      # max total threads per kernel invocation

    cycles=$(get_cycles)
    dtype_bits=$(get_datatype_bits)

    # Multi-kernel aware collection
    mapfile -t kernel_lines < <(collect_kernels_info)

    # Build per-kernel static smem map from resource lines
    while IFS= read -r line; do
        kname=$(echo "$line" | sed -E "s/.*Kernel '([^']+)'.*/\1/")
        ksmem=$(echo "$line" | sed -E 's/.*smem=([0-9]+).*/\1/')
        [[ -n "$kname" ]] && K_STATIC_SMEM_BYTES["$kname"]="$ksmem"
    done < <(grep -E "GPGPU-Sim PTX: Kernel '.*' : regs=[0-9]+, lmem=[0-9]+, smem=[0-9]+" "$FILE_PATH")

    # Parse blockDim/gridDim per kernel from push/launch lines
    while IFS= read -r line; do
        kname=$(echo "$line" | sed -E "s/.*(pushing|launching) kernel '([^']+)'.*/\2/")
        gxyz=$(echo "$line" | sed -E "s/.*gridDim[[:space:]]*=[[:space:]]*\\(\\s*([0-9]+)\\s*,\\s*([0-9]+)\\s*,\\s*([0-9]+)\\s*\\).*/\\1 \\2 \\3/")
        bxyz=$(echo "$line" | sed -E "s/.*blockDim[[:space:]]*=[[:space:]]*\\(\\s*([0-9]+)\\s*,\\s*([0-9]+)\\s*,\\s*([0-9]+)\\s*\\).*/\\1 \\2 \\3/")
        gx=$(echo "$gxyz" | awk '{print $1}')
        gy=$(echo "$gxyz" | awk '{print $2}')
        gz=$(echo "$gxyz" | awk '{print $3}')
        bx=$(echo "$bxyz" | awk '{print $1}')
        by=$(echo "$bxyz" | awk '{print $2}')
        bz=$(echo "$bxyz" | awk '{print $3}')
        if [[ -n "$kname" && "$bx" =~ ^[0-9]+$ && "$by" =~ ^[0-9]+$ && "$bz" =~ ^[0-9]+$ ]]; then
            val=$(( bx * by * bz ))
            if [[ -z ${K_BLOCK_ELEMS[$kname]} || ${K_BLOCK_ELEMS[$kname]} -lt $val ]]; then
                K_BLOCK_ELEMS["$kname"]=$val
            fi
        fi
        if [[ -n "$kname" && "$gx" =~ ^[0-9]+$ && "$gy" =~ ^[0-9]+$ && "$gz" =~ ^[0-9]+$ ]]; then
            val=$(( gx * gy * gz ))
            if [[ -z ${K_GRID_BLOCKS[$kname]} || ${K_GRID_BLOCKS[$kname]} -lt $val ]]; then
                K_GRID_BLOCKS["$kname"]=$val
            fi
        fi
        if [[ -n "$kname" && "$bx" =~ ^[0-9]+$ && "$by" =~ ^[0-9]+$ && "$bz" =~ ^[0-9]+$ && "$gx" =~ ^[0-9]+$ && "$gy" =~ ^[0-9]+$ && "$gz" =~ ^[0-9]+$ ]]; then
            tcnt=$(( bx * by * bz * gx * gy * gz ))
            if [[ -z ${K_TOTAL_THREADS[$kname]} || ${K_TOTAL_THREADS[$kname]} -lt $tcnt ]]; then
                K_TOTAL_THREADS["$kname"]=$tcnt
            fi
        fi
    done < <(grep -E "(pushing|launching) kernel '.*'.*blockDim[[:space:]]*=" "$FILE_PATH")

    # Infer shared element byte width from PTX_INST_SUM lines (ld/st.shared.<type>) per kernel
    while IFS= read -r kname; do
        [[ -z "$kname" ]] && continue
        maxb=0
        while IFS= read -r tline; do
            suf=$(echo "$tline" | sed -nE 's/.*(ld|st)\.shared\.([a-z0-9]+).*/\2/p')
            case "$suf" in
                *64) bytes=8 ;;
                *32) bytes=4 ;;
                *16) bytes=2 ;;
                *8)  bytes=1 ;;
                *)   bytes=0 ;;
            esac
            (( bytes > maxb )) && maxb=$bytes
        done < <(grep -F "kernel=\"$kname\"" "$FILE_PATH" | grep -E "\[PTX_INST_SUM\].*(ld\.shared|st\.shared)\.")
        if (( maxb > 0 )); then
            K_SHARED_ELEM_BYTES["$kname"]=$maxb
        fi
    done < <(grep -oE "kernel='[^']+'|kernel=\"[^\"]+\"" "$FILE_PATH" | sed -E "s/kernel=['\"]([^'\"]+)['\"]/\1/" | sort -u)

    exec_time=$(grep -E "^gpgpu_simulation_time" "$FILE_PATH" | tail -n1)

    if [[ -n "$exec_time" ]]; then
        days=$(echo "$exec_time" | sed -E 's/.*=\s*([0-9]+)\s+days.*/\1/')
        hrs=$(echo "$exec_time"  | sed -E 's/.*days,\s*([0-9]+)\s+hrs.*/\1/')
        mins=$(echo "$exec_time" | sed -E 's/.*hrs,\s*([0-9]+)\s+min.*/\1/')
        secs=$(echo "$exec_time" | sed -E 's/.*min,\s*([0-9]+)\s+sec.*/\1/')

        days=${days:-0}
        hrs=${hrs:-0}
        mins=${mins:-0}
        secs=${secs:-0}

        exec_time=$(( days*86400 + hrs*3600 + mins*60 + secs ))
    else
        exec_time=0
    fi


    # Defaults in case nothing is found
    max_regs=0; max_lmem=0; max_smem=0; all_shaders=""

    # Parse summary and print per-kernel details
    echo "KERNELS:"
    for line in "${kernel_lines[@]}"; do
        [[ -z "$line" ]] && continue
        if [[ "$line" == SUMMARY* ]]; then
            # SUMMARY\t<max_regs>\t<max_lmem>\t<max_smem>\t<all_shaders>
            IFS=$'\t' read -r _ max_regs max_lmem max_smem all_shaders <<< "$line"
        elif [[ "$line" == KERNEL* ]]; then
            # KERNEL\t<idx>\t<name>\t<regs>\t<lmem>\t<smem>\t<shader_list>\t<cycles_sum>
            IFS=$'\t' read -r _ kidx kname kregs klmem ksmem kshaders kcycles <<< "$line"
            [[ -z "$kname" ]] && continue
            echo "- name=${kname} regs=${kregs} lmem=${klmem} smem=${ksmem} shader_used=${kshaders} cycles=${kcycles}"
        fi
    done

    # Echo kernel invocation details if present
    for line in "${kernel_lines[@]}"; do
        if [[ "$line" == KERNEL_INVOCATIONS:* ]] || [[ "$line" == -\ id=* ]]; then
            echo "$line"
        fi
    done

    # Fallback to single-triplet if no kernels parsed
    if [[ $max_regs -eq 0 && $max_lmem -eq 0 && $max_smem -eq 0 ]]; then
        read -r regs lmem smem < <(get_kernel_triplet)
        max_regs=$regs; max_lmem=$lmem; max_smem=$smem
        all_shaders=$(get_shader_used_list)
    fi

    lmem_bits=$((max_lmem * 8))

    # Compute effective shared memory (consider dynamic + static) across kernels
    # Start with the static max as baseline
    eff_smem_bytes=${max_smem}
    # Build kernels_order copy from previously collected function by re-parsing names
    # and compute per-kernel effective smem
    while IFS= read -r kname; do
        [[ -z "$kname" ]] && continue
        bs_elems=${K_BLOCK_ELEMS[$kname]:-0}
        elem_bytes=${K_SHARED_ELEM_BYTES[$kname]:-0}
        dyn_bytes=0
        if (( bs_elems > 0 && elem_bytes > 0 )); then
            dyn_bytes=$(( bs_elems * elem_bytes ))
        fi
        static_bytes=${K_STATIC_SMEM_BYTES[$kname]:-0}
        # choose max to avoid double-counting
        (( dyn_bytes > static_bytes )) && chosen=$dyn_bytes || chosen=$static_bytes
        K_EFFECTIVE_SMEM["$kname"]=$chosen
        (( chosen > eff_smem_bytes )) && eff_smem_bytes=$chosen
    done < <(grep -E "GPGPU-Sim PTX: Kernel '.*' : regs=[0-9]+, lmem=[0-9]+, smem=[0-9]+" "$FILE_PATH" | sed -E "s/.*Kernel '([^']+)'.*/\1/" | sort -u)

    smem_bits=$((eff_smem_bytes * 8))

    # Compute max threads/warps/blocks for random range scaling
    max_threads=0
    max_warps=0
    max_blocks=0
    if ((${#K_TOTAL_THREADS[@]} > 0)); then
        for k in "${!K_TOTAL_THREADS[@]}"; do
            tcnt=${K_TOTAL_THREADS[$k]:-0}
            (( tcnt > max_threads )) && max_threads=$tcnt
            wcnt=$(( (tcnt + 31) / 32 ))
            (( wcnt > max_warps )) && max_warps=$wcnt
        done
    else
        for k in "${!K_BLOCK_ELEMS[@]}"; do
            b_elems=${K_BLOCK_ELEMS[$k]:-0}
            g_blocks=${K_GRID_BLOCKS[$k]:-0}
            if (( b_elems > 0 && g_blocks > 0 )); then
                tcnt=$(( b_elems * g_blocks ))
                (( tcnt > max_threads )) && max_threads=$tcnt
                wcnt=$(( (tcnt + 31) / 32 ))
                (( wcnt > max_warps )) && max_warps=$wcnt
            fi
        done
    fi
    for k in "${!K_GRID_BLOCKS[@]}"; do
        g_blocks=${K_GRID_BLOCKS[$k]:-0}
        (( g_blocks > max_blocks )) && max_blocks=$g_blocks
    done

    echo
    # Store into global variables (keep existing prints unchanged)
    GLOBAL_CYCLES="${cycles}"
    GLOBAL_MAX_REGISTERS_USED="${max_regs}"
    GLOBAL_SHADER_USED="${all_shaders}"
    GLOBAL_DATATYPE_SIZE="${dtype_bits}"
    GLOBAL_EXEC_TIME="${exec_time}"
    GLOBAL_THREAD_RAND_MAX="${max_threads}"
    GLOBAL_WARP_RAND_MAX="${max_warps}"
    GLOBAL_BLOCK_RAND_MAX="${max_blocks}"

    if [[ "${lmem_bits}" -eq 0 ]]; then
        GLOBAL_LMEM_SIZE_BITS="1"
    else
        GLOBAL_LMEM_SIZE_BITS="${lmem_bits}"
    fi
    if [[ "${smem_bits}" -eq 0 ]]; then
        GLOBAL_SMEM_SIZE_BITS="1"
    else
        GLOBAL_SMEM_SIZE_BITS="${smem_bits}"
    fi
    # Sanitize component set to avoid injecting into non-existent or removed
    # components. Storage experiments support RF/local/shared/cache/GMEM only;
    # removed pipeline component IDs 7-10 are skipped rather than relabeled.
    GLOBAL_SKIP_COMPONENT=0
    effective_components=()
    if [[ -z "$COMPONENT_SET" ]]; then
        COMPONENT_SET="0"
    fi
    IFS=': ' read -r -a comps <<< "$COMPONENT_SET"
    for c in "${comps[@]}"; do
        [[ -z "$c" ]] && continue
        case "$c" in
            0|1|2|3|4|5|6|11) ;;
            *) continue ;;
        esac
        if [[ "$c" == "1" && "${lmem_bits}" -eq 0 ]]; then
            continue
        fi
        if [[ "$c" == "2" && "${smem_bits}" -eq 0 ]]; then
            continue
        fi
        effective_components+=("$c")
    done
    if ((${#effective_components[@]} == 0)); then
        GLOBAL_COMPONENT_SET=""
        GLOBAL_SKIP_COMPONENT=1
    else
        GLOBAL_COMPONENT_SET="$(IFS=:; printf "%s" "${effective_components[*]}")"
    fi
    echo "CYCLES: ${cycles}"
    echo "MAX_REGISTERS_USED: ${max_regs}"
    echo "SHADER_USED: ${all_shaders}"
    echo "DATATYPE_SIZE: ${dtype_bits}"
    echo "LMEM_SIZE_BITS: ${lmem_bits}"
    echo "SMEM_SIZE_BITS: ${smem_bits}"
    echo "EXEC_TIME: ${exec_time}s"
    echo "THREAD_RAND_MAX: ${GLOBAL_THREAD_RAND_MAX}"
    echo "WARP_RAND_MAX: ${GLOBAL_WARP_RAND_MAX}"
    echo "BLOCK_RAND_MAX: ${GLOBAL_BLOCK_RAND_MAX}"
    echo "EFFECTIVE_COMPONENT_SET: ${GLOBAL_COMPONENT_SET}"
    if [[ "${GLOBAL_SKIP_COMPONENT}" -eq 1 ]]; then
        echo "SKIP_COMPONENT: requested COMPONENT_SET=${COMPONENT_SET} has no modeled bits for this app/test"
    fi

}

main() {
    # load environment variables
    source setup_environment
    # Keep power model disabled: custom FI build path is not wired to
    # the 4.2.x AccelWattch API surface.
    unset GPGPUSIM_POWER_MODEL || true
    detect_gpu_arch

    if [[ -z "$COMPONENT_SET" ]]; then
        COMPONENT_SET="0"
    fi
    # Ensure gpgpusim.config has a valid components_to_flip before any run
    if [[ -f "${CONFIG_FILE}" ]]; then
        set_config_opt "-components_to_flip" "${COMPONENT_SET}"
    fi

    if [[ $DO_BUILD -eq 1 ]]; then
        echo "=== Start compiling ==="

        # Run 'make clean' quietly
        make clean >/dev/null 2>&1

        # Build with make; capture output to log instead of printing
        if make -j"$(nproc)" >build.log 2>&1; then
            echo "=== Make success ==="
        else
            echo "=== Build failed, showing errors ==="
            # Show only lines containing 'error'
            grep -i "error" build.log
            exit 1
        fi
    else
        echo "=== Build skipped ==="
    fi


    if [[ $DO_RESULT_GEN -eq 1 ]]; then
        echo "=== Start result generation ==="

        # Remove old result files
        rm -rf test_apps/${TEST_APP_NAME}/result/*

        # Generate results
        idx=0
        while IFS= read -r line || [[ -n "$line" ]]; do
            echo "$idx: $line"
            for cu_file in test_apps/${TEST_APP_NAME}/result_gen/${TEST_APP_NAME}_*.cu; do

                filename=$(basename "$cu_file")
                x_val=$(echo "$filename" | sed -n "s/^${TEST_APP_NAME}_\([0-9]\+\)\.cu$/\1/p")
                if [[ -z "$x_val" ]]; then
                    continue
                fi
                cp "$cu_file" "${cu_file}.bak"
                nvcc "$cu_file" -o "./gen" -g -lcudart -arch=$GPU_ARCH
                ./gen $line > "test_apps/${TEST_APP_NAME}/result/${idx}-${x_val}.txt"
                # Keep only the content between the last two 'GPGPU-Sim' lines (excluding the markers)
                tmpfile="test_apps/${TEST_APP_NAME}/result/${idx}-${x_val}.txt.tmp"
                gpgpu_lines=($(grep -n "GPGPU-Sim" "test_apps/${TEST_APP_NAME}/result/${idx}-${x_val}.txt" | cut -d: -f1))
                if (( ${#gpgpu_lines[@]} >= 2 )); then
                    start_line=$(( ${gpgpu_lines[-2]} + 1 ))
                    end_line=$(( ${gpgpu_lines[-1]} - 1 ))
                    if (( start_line <= end_line )); then
                        sed -n "${start_line},${end_line}p" "test_apps/${TEST_APP_NAME}/result/${idx}-${x_val}.txt" > "$tmpfile"
                        mv "$tmpfile" "test_apps/${TEST_APP_NAME}/result/${idx}-${x_val}.txt"
                    else
                        # If the range is empty, truncate the file
                        > "test_apps/${TEST_APP_NAME}/result/${idx}-${x_val}.txt"
                    fi
                fi
                rm -f "./gen"
                rm -f "./gen.1.${GPU_ARCH}.ptxas"
                mv "${cu_file}.bak" "$cu_file"
                rm -f $TEST_APP_NAME.cu
                rm -f $TEST_APP_NAME.ptx
            done
            idx=$((idx+1))
        done < "test_apps/${TEST_APP_NAME}/size_list.txt"

        echo "=== Result generation finished ==="
    else
        echo "=== Result generation skipped ==="
    fi

    # register_used.txt will be consumed by campaign_exec.sh per-injection

    FILE_PATH="${1:-./logs1/tmp.out1}"

    for result_file in test_apps/${TEST_APP_NAME}/result/*; do
        rm -f invalid_param_combos.txt
        echo "=== Preparing injection for file: $result_file ==="
        filename=$(basename "$result_file")
        # Extract 'a' and 'b'
        a=$(echo "$filename" | cut -d'-' -f1)
        b_with_ext=$(echo "$filename" | cut -d'-' -f2)
        b=$(echo "$b_with_ext" | cut -d'.' -f1)

        echo "=== Copying result and source files ==="
        # Copy the result file to project root as result.txt
        cp "$result_file" ./result.txt

        # Find the corresponding .cu under inject_app by 'b' and copy to root as ${TEST_APP_NAME}.cu
        cu_file="test_apps/${TEST_APP_NAME}/inject_app/${TEST_APP_NAME}_${b}.cu"
        if [[ -f "$cu_file" ]]; then
            cp "$cu_file" "./${TEST_APP_NAME}.cu"
        fi

        echo "=== Compiling CUDA application for injection ==="
        nvcc ${TEST_APP_NAME}.cu -o ${TEST_APP_NAME} -g -lcudart -arch=$GPU_ARCH

        # Read the a-th line of size_list.txt (0-based)
        size_list_file="test_apps/${TEST_APP_NAME}/size_list.txt"
        if [[ ! -f "$size_list_file" ]]; then
            echo "=== Error: size_list.txt not found: $size_list_file ===" >&2
            exit 1
        fi

        # Variable 'a' was extracted above
        size_line=$(awk "NR==$((a+1))" "$size_list_file")

        echo "=== Updating campaign_profile.sh ==="
        FILE="${COMMON_DIR}/campaign_profile.sh"
        # Use sed to replace the line starting with CUDA_UUT
        sed -i "s|^CUDA_UUT.*|CUDA_UUT=\"./${TEST_APP_NAME} ${size_line}\"|" "$FILE"

        profile_max_retries="${FI_PROFILE_MAX_RETRIES:-3}"
        if ! [[ "${profile_max_retries}" =~ ^[1-9][0-9]*$ ]]; then
            profile_max_retries=3
        fi
        app_info_file="test_apps/${TEST_APP_NAME}/app_info.txt"
        profile_attempt=1
        while true; do
            echo "=== Running campaign_profile.sh (attempt ${profile_attempt}/${profile_max_retries}) ==="
            rm -rf logs* cache_logs
            if ! bash "${COMMON_DIR}/campaign_profile.sh"; then
                echo "=== campaign_profile.sh exited non-zero on attempt ${profile_attempt} ===" >&2
            fi

            if [ ! -f "$FILE_PATH" ]; then
                echo "=== Profile output missing on attempt ${profile_attempt}: $FILE_PATH ===" >&2
            else
                prev_gpu_arch="$GPU_ARCH"
                detect_gpu_arch "$FILE_PATH"
                if [[ "$GPU_ARCH" != "$prev_gpu_arch" ]]; then
                    echo "=== Recompiling ${TEST_APP_NAME} with updated GPU_ARCH=${GPU_ARCH} ==="
                    nvcc ${TEST_APP_NAME}.cu -o ${TEST_APP_NAME} -g -lcudart -arch=$GPU_ARCH
                fi

                echo "=== Collecting metrics ==="
                : > "$app_info_file"
                { get_metrics; } > >(tee "$app_info_file")

                if [[ "${GLOBAL_CYCLES}" =~ ^[1-9][0-9]*$ ]]; then
                    break
                fi
                echo "=== Invalid profile metrics on attempt ${profile_attempt}: CYCLES=${GLOBAL_CYCLES}; retrying if possible ===" >&2
            fi

            if (( profile_attempt >= profile_max_retries )); then
                echo "Error: campaign_profile.sh did not produce a positive cycle count after ${profile_max_retries} attempts." >&2
                exit 1
            fi
            profile_attempt=$((profile_attempt + 1))
        done

        if [[ "${GLOBAL_SKIP_COMPONENT:-0}" -eq 1 ]]; then
            echo "=== Skipping ${TEST_APP_NAME} ${filename}: requested COMPONENT_SET=${COMPONENT_SET} has no modeled bits under this profile ==="
            continue
        fi

        echo "=== Extracting register information ==="
        # Copy current cu file to project root as ${TEST_APP_NAME}.cu (for helper scripts expecting that filename)
        cp -f "$cu_file" "./${TEST_APP_NAME}.cu"
        nvcc -arch=$GPU_ARCH -ptx -g -lineinfo $TEST_APP_NAME.cu -o "$TEST_APP_NAME.ptx"
        python3 extract_registers.py $TEST_APP_NAME


        # Read campaign_exec.sh contents into a variable
        campaign_template="${CAMPAIGN_EXEC_TEMPLATE}"
        if [[ ! -f "$campaign_template" ]]; then
            echo "Error: campaign_exec.sh not found: $campaign_template" >&2
            exit 1
        fi
        campaign_file="${FI_LOG_ROOT}/${TEST_APP_NAME}/campaign_exec_${COMPONENT_SET}.sh"
        mkdir -p "$(dirname "${campaign_file}")"
        cp -f "${campaign_template}" "${campaign_file}"
        chmod +x "${campaign_file}"
        bash "${COMMON_DIR}/generate_cycles.sh" $GLOBAL_CYCLES $GLOBAL_CYCLES
        if [ $? -ne 0 ]; then
            echo "Error: generate_cycles.sh failed." >&2
            exit 1
        fi

        echo "=== Updating campaign_exec.sh with metrics ==="
        # Generate updated content
        awk -v test_app_name="$TEST_APP_NAME" -v size_line="$size_line" \
            -v global_cycles="$GLOBAL_CYCLES" \
            -v global_max_registers="$GLOBAL_MAX_REGISTERS_USED" \
            -v global_shader="$GLOBAL_SHADER_USED" \
            -v global_datatype_size="$GLOBAL_DATATYPE_SIZE" \
            -v global_lmem_size_bits="$GLOBAL_LMEM_SIZE_BITS" \
            -v global_smem_size_bits="$GLOBAL_SMEM_SIZE_BITS" \
            -v run_times="$RUN_PER_EPOCH" \
            -v exec_time="$GLOBAL_EXEC_TIME" \
            -v component_set="$GLOBAL_COMPONENT_SET" \
            -v thread_rand_max="$GLOBAL_THREAD_RAND_MAX" \
            -v warp_rand_max="$GLOBAL_WARP_RAND_MAX" \
            -v block_rand_max="$GLOBAL_BLOCK_RAND_MAX" \
            -v inject_bit_flip_count="$INJECT_BIT_FLIP_COUNT" '
        {
            # Replace CUDA_UUT
            if ($0 ~ /^CUDA_UUT=/) {
                print "CUDA_UUT=\"./" test_app_name " " size_line "\""
                next
            }
            # Replace CYCLES
            if ($0 ~ /^CYCLES=/) {
                print "CYCLES=" global_cycles
                next
            }
            # Replace MAX_REGISTERS_USED
            if ($0 ~ /^MAX_REGISTERS_USED=/) {
                print "MAX_REGISTERS_USED=" global_max_registers
                next
            }
            # Replace SHADER_USED (wrap in double quotes)
            if ($0 ~ /^SHADER_USED=/) {
                print "SHADER_USED=\"" global_shader "\""
                next
            }
            # Replace DATATYPE_SIZE
            if ($0 ~ /^DATATYPE_SIZE=/) {
                print "DATATYPE_SIZE=" global_datatype_size
                next
            }
            # Replace LMEM_SIZE_BITS
            if ($0 ~ /^LMEM_SIZE_BITS=/) {
                print "LMEM_SIZE_BITS=" global_lmem_size_bits
                next
            }
            # Replace SMEM_SIZE_BITS
            if ($0 ~ /^SMEM_SIZE_BITS=/) {
                print "SMEM_SIZE_BITS=" global_smem_size_bits
                next
            }
            # Replace RUNS
            if ($0 ~ /^RUNS=/) {
                print "RUNS=" run_times
                next
            }
            # Replace TIMEOUT_VAL
            if ($0 ~ /^TIMEOUT_VAL=/) {
                et = (exec_time * 20)
                print "TIMEOUT_VAL=" et "s"
                next
            }
            # Replace COMPONENT_SET
            if ($0 ~ /^COMPONENT_SET=/) {
                print "COMPONENT_SET=\"" component_set "\""
                next
            }
            # Replace THREAD_RAND_MAX
            if ($0 ~ /^THREAD_RAND_MAX=/) {
                print "THREAD_RAND_MAX=" thread_rand_max
                next
            }
            # Replace WARP_RAND_MAX
            if ($0 ~ /^WARP_RAND_MAX=/) {
                print "WARP_RAND_MAX=" warp_rand_max
                next
            }
            # Replace BLOCK_RAND_MAX
            if ($0 ~ /^BLOCK_RAND_MAX=/) {
                print "BLOCK_RAND_MAX=" block_rand_max
                next
            }
            # Replace INJECT_BIT_FLIP_COUNT
            if ($0 ~ /^INJECT_BIT_FLIP_COUNT=/) {
                print "INJECT_BIT_FLIP_COUNT=" inject_bit_flip_count
                next
            }
            # Keep other lines unchanged
            print $0
        }' "$campaign_file" > "${campaign_file}.tmp" && mv "${campaign_file}.tmp" "$campaign_file"

        echo "=== Starting fault injection experiment: ${TEST_APP_NAME}, file ${filename} ==="
        filename_no_ext="${filename%.txt}"
        fi_input_dir="${FI_COMPARE_INPUT_ROOT}/${TEST_APP_NAME}/${filename_no_ext}"
        resolve_output_oracle_policy_from_sara_input "${fi_input_dir}"

        export FI_RF_FAULT_MODEL="${RF_FAULT_MODEL}"
        export FI_ADDR_DUE_MODE="${ANALYZER_ADDR_DUE_MODE}"
        export FI_TRACE_EXPANDING_POLICY="${TRACE_EXPANDING_POLICY}"
        export FI_SEED_BASE="${FI_SEED_BASE}"
        export FI_OUTPUT_ORACLE_TOL_POLICY="${OUTPUT_ORACLE_TOL_POLICY}"
        export FI_OUTPUT_ORACLE_TIMEOUT_EXIT_STATUSES="${OUTPUT_ORACLE_TIMEOUT_EXIT_STATUSES}"

        fi_active_threads_log="${fi_input_dir}/inst_trace.json.active_threads.jsonl"
        fi_analyzer_output="${fi_input_dir}/analyzer_output.json"
        fi_golden_log="${fi_input_dir}/golden.log"
        fi_output_spec="${fi_input_dir}/output_spec.json"
        if [[ -f "${fi_active_threads_log}" ]]; then
            export FI_ACTIVE_THREADS_LOG="${fi_active_threads_log}"
        else
            unset FI_ACTIVE_THREADS_LOG
        fi
        if [[ -f "${fi_analyzer_output}" ]]; then
            export FI_ANALYZER_OUTPUT="${fi_analyzer_output}"
        else
            unset FI_ANALYZER_OUTPUT
        fi
        if [[ -f "${fi_golden_log}" ]]; then
            export FI_GOLDEN_LOG="${fi_golden_log}"
        else
            unset FI_GOLDEN_LOG
        fi
        if [[ -f "${fi_output_spec}" ]]; then
            export FI_OUTPUT_SPEC="${fi_output_spec}"
        else
            unset FI_OUTPUT_SPEC
        fi

        # Actual total number of tasks
        TOTAL_TASKS="$RUN_PER_EPOCH"   # Total tasks defined earlier by RUN_PER_EPOCH

        local injection_start_ns injection_end_ns injection_wall_ns injection_wall_s campaign_status

        # Run in background; do not print logs to console
        injection_start_ns="$(date +%s%N)"
        : > inst_exec.log
        bash "${campaign_file}" > inst_exec.log 2>&1 &
        CMD_PID=$!

        trap cleanup INT

        # Monitor real completed trials from campaign_exec output.  The [Run N]
        # prefix is a batch id, not a trial id, so estimating progress from N or
        # CPU count can reach 100% before the campaign actually finishes.
        monitor_fi_progress "inst_exec.log" "${TOTAL_TASKS}" "${CMD_PID}" &
        PROGRESS_MONITOR_PID=$!

        # Wait for the main process to finish
        wait "${CMD_PID}"
        campaign_status=$?
        wait "${PROGRESS_MONITOR_PID}" 2>/dev/null || true
        PROGRESS_MONITOR_PID=""
        CMD_PID=""
        if (( campaign_status != 0 )); then
            echo "=== Error: campaign_exec.sh exited with status ${campaign_status}; refusing to write partial FI result ===" >&2
            return "${campaign_status}"
        fi
        injection_end_ns="$(date +%s%N)"
        injection_wall_ns=$((injection_end_ns - injection_start_ns))
        injection_wall_s="$(ns_to_seconds "${injection_wall_ns}")"
        echo "=== Fault injection for ${filename} finished ==="
        echo "Injection Time (s): ${injection_wall_s}"
        python3 analysis_fault.py \
            -a "$TEST_APP_NAME" \
            -t "$filename_no_ext" \
            -c "$GLOBAL_COMPONENT_SET" \
            -b "$INJECT_BIT_FLIP_COUNT" \
            --injection-time-seconds "${injection_wall_s}" \
            --expected-trials "${RUN_PER_EPOCH}" \
            --log-path "inst_exec.log"
        ret=$?
        if [ $ret -eq 99 ]; then
            echo "=== Early stopping triggered. Exiting loop ==="
            break
        fi
        if [ $ret -ne 0 ]; then
            echo "=== Error: analysis_fault.py failed with status ${ret}; refusing to continue with partial FI result ===" >&2
            return "${ret}"
        fi
    done
    rm -f register_used.txt
    rm -f $TEST_APP_NAME.ptx
    rm -f $TEST_APP_NAME.1.$GPU_ARCH.ptx
    rm -f $TEST_APP_NAME.1.$GPU_ARCH.ptxas
    rm -f $TEST_APP_NAME.cu
    rm -f $TEST_APP_NAME
    rm -f result.txt

}
echo "=== Running main with COMPONENT_SET=${COMPONENT_SET} ==="
echo "=== Component mapping: 0=RF, 1=local_mem, 2=shared_mem, 3=L1D_cache, 4=L1C_cache, 5=L1T_cache, 6=L2_cache, 11=GMEM ==="
echo "=== Test application: ${TEST_APP_NAME} ==="
echo "=== Injection bit flip count: ${INJECT_BIT_FLIP_COUNT} ==="
main "$@"
