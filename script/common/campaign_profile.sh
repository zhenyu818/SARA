#!/bin/bash

# ---------------------------------------------- START ONE-TIME PARAMETERS ----------------------------------------------
# needed by gpgpu-sim for real register usage on PTXPlus mode
export PTXAS_CUDA_INSTALL_PATH=/usr/local/cuda
CONFIG_FILE=./gpgpusim.config
TMP_DIR=./logs
CACHE_LOGS_DIR=./cache_logs
TMP_FILE=tmp.out
RUNS=10
SIM_NICE="${SIM_NICE:-10}"
DELETE_LOGS=0 # if 1 then all logs will be deleted at the end of the script
EXPERIMENT_RANDOM_SEED=2026
PRNG_STATE=${EXPERIMENT_RANDOM_SEED}
RAND_VALUE=""
# ---------------------------------------------- END ONE-TIME PARAMETERS ------------------------------------------------

# ---------------------------------------------- START PER GPGPU CARD PARAMETERS ----------------------------------------------
# L1 cache size per SIMT core (30 SIMT cores on RTX 2060, 30 clusters with 1 core each)
L1D_SIZE_BITS=524345  # nsets=1, line_size=128 bytes + 57 bits, assoc=512 (64 KB per core)
L1C_SIZE_BITS=524345 # nsets=128, line_size=64 bytes + 57 bits, assoc=8 (64 KB per core)
L1T_SIZE_BITS=1048633 # nsets=4, line_size=128 bytes + 57 bits, assoc=256 (128 KB per core)
# L2 cache total size from all sub partitions (RTX 2060: 12 memory controllers × 2 sub partitions = 24 total)
L2_SIZE_BITS=24576057 # (nsets=64, line_size=128 bytes + 57 bits, assoc=16) x 24 sub partitions = 3 MB total
# ---------------------------------------------- END PER GPGPU CARD PARAMETERS ------------------------------------------------

# ---------------------------------------------- START PER KERNEL/APPLICATION PARAMETERS (+profile=1) ----------------------------------------------
CUDA_UUT="./AdamW 128 4"
# total cycles for all kernels
CYCLES=4040
# Get the exact cycles, max registers and SIMT cores used for each kernel with profile=1
# fix cycles.txt with kernel execution cycles
# (e.g. seq 1 10 >> cycles.txt, or multiple seq commands if a kernel has multiple executions)
# use the following command from profiling execution for easier creation of cycles.txt file
# e.g. grep "_Z12lud_diagonalPfii" cycles.in | awk  '{ system("seq " $12 " " $18 ">> cycles.txt")}'
CYCLES_FILE=./cycles.txt
MAX_REGISTERS_USED=15
SHADER_USED=0
SUCCESS_MSG='Fault Injection Test Success!'
FAILED_MSG='Fault Injection Test Failed!'
TIMEOUT_VAL=400s
DATATYPE_SIZE=32
# lmem and smem values are taken from gpgpu-sim ptx output per kernel
# e.g. GPGPU-Sim PTX: Kernel '_Z9vectorAddPKdS0_Pdi' : regs=8, lmem=0, smem=0, cmem=380
# if 0 put a random value > 0
LMEM_SIZE_BITS=1
SMEM_SIZE_BITS=16384
# ---------------------------------------------- END PER KERNEL/APPLICATION PARAMETERS (+profile=1) ------------------------------------------------

FAULT_INJECTION_OCCURRED="Fault injection"
CYCLES_MSG="gpu_tot_sim_cycle ="

masked=0
performance=0
SDC=0
crashes=0

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

# ---------------------------------------------- START PER INJECTION CAMPAIGN PARAMETERS (profile=0) ----------------------------------------------
# 0: perform injection campaign, 1: get cycles of each kernel, 2: get mean value of active threads, during all cycles in CYCLES_FILE, per SM,
# 3: single fault-free execution
profile=1
# 0:RF, 1:local_mem, 2:shared_mem, 3:L1D_cache, 4:L1C_cache, 5:L1T_cache, 6:L2_cache, 11:GMEM
# (e.g. components_to_flip=0:1 for both RF and local_mem)
components_to_flip=0
# 1: per warp bit flip, 0: per thread bit flip
per_warp=0
# in which kernels to inject the fault. e.g. 0: for all running kernels, 1: for kernel 1, 1:2 for kernel 1 & 2
kernel_n=0
# in how many blocks (smems) to inject the bit flip
blocks=1

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
    if command -v nice >/dev/null 2>&1; then
        nice -n "${SIM_NICE}" timeout "${TIMEOUT_VAL}" $CUDA_UUT > "${out_file}" 2>&1
    else
        timeout "${TIMEOUT_VAL}" $CUDA_UUT > "${out_file}" 2>&1
    fi
}

initialize_config() {
    # random number for choosing a random thread after thread_rand % #threads operation in gpgpu-sim
    rand_range 0 6000; thread_rand="${RAND_VALUE}"
    # random number for choosing a random warp after warp_rand % #warp operation in gpgpu-sim
    rand_range 0 6000; warp_rand="${RAND_VALUE}"
    # random cycle for fault injection
    choose_total_cycle_rand; total_cycle_rand="${RAND_VALUE}"
    # in which registers to inject the bit flip
    rand_unique_range_colon 1 "${MAX_REGISTERS_USED}" 1; register_rand_n="${RAND_VALUE}"
    # example: if -i 1-32 -n 2 then the two commands below will create a value with 2 random numbers, between [1,32] like 3:21. Meaning it will flip 3 and 21 bits.
    rand_unique_range_colon 1 "${DATATYPE_SIZE}" 1; reg_bitflip_rand_n="${RAND_VALUE}"
    # same format like reg_bitflip_rand_n but for local memory bit flips
    rand_unique_range_colon 1 "${LMEM_SIZE_BITS}" 3; local_mem_bitflip_rand_n="${RAND_VALUE}"
    # random number for choosing a random block after block_rand % #smems operation in gpgpu-sim
    rand_range 0 6000; block_rand="${RAND_VALUE}"
    # same format like reg_bitflip_rand_n but for shared memory bit flips
    rand_unique_range_colon 1 "${SMEM_SIZE_BITS}" 1; shared_mem_bitflip_rand_n="${RAND_VALUE}"
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
    # seed for dynamic program-visible global-memory-byte selection
    rand_range 0 2147483646; gmem_byte_seed="${RAND_VALUE}"
    gmem_target_addr=18446744073709551615
# ---------------------------------------------- END PER INJECTION CAMPAIGN PARAMETERS (profile=0) ------------------------------------------------

    set_config_opt "-components_to_flip" "${components_to_flip}"
    set_config_opt "-profile" "${profile}"
    set_config_opt "-last_cycle" "${CYCLES}"
    set_config_opt "-thread_rand" "${thread_rand}"
    set_config_opt "-warp_rand" "${warp_rand}"
    set_config_opt "-total_cycle_rand" "${total_cycle_rand}"
    set_config_opt "-register_rand_n" "${register_rand_n}"
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
        grep -iq "${SUCCESS_MSG}" $file; success_msg_grep=$(echo $?)
	grep -i "${CYCLES_MSG}" $file | tail -1 | grep -q "${CYCLES}"; cycles_grep=$(echo $?)
        grep -iq "${FAILED_MSG}" $file; failed_msg_grep=$(echo $?)
        if grep -q "FI_VALIDATION:" "$file"; then
            echo "[Run ${1}] Effects from ${file}:"
            grep -h "FI_VALIDATION:" "$file"
        fi
        result=${success_msg_grep}${cycles_grep}${failed_msg_grep}
        case $result in
        "001")
            let RUNS--
            let masked++ ;;
        "011")
            let RUNS--
            let masked++
            let performance++ ;;
        "100" | "110")
            let RUNS--
            let SDC++ ;;
        *)
            grep -iq "${FAULT_INJECTION_OCCURRED}" $file
            if [ $? -eq 0 ]; then
                let RUNS--
                let crashes++
                echo "Crash appeared in loop ${1}" # DEBUG
            else
                echo "Unclassified in loop ${1} ${result}" # DEBUG
            fi ;;
        esac
    done
}

serial_execution() {
    local run_index="$1"
    local local_index=1

    mkdir ${TMP_DIR}${run_index} > /dev/null 2>&1
    init_deterministic_prng "${EXPERIMENT_RANDOM_SEED}" "${run_index}"
    initialize_config
    set_config_opt "-run_uid" "r${run_index}"
    cp ${CONFIG_FILE} ${TMP_DIR}${run_index}/${CONFIG_FILE}${local_index} # save state
    launch_uut_guarded "${TMP_DIR}${run_index}/${TMP_FILE}${local_index}"
    gather_results ${run_index}
    if [[ "$DELETE_LOGS" -eq 1 ]]; then
        rm _ptx* _cuobjdump_* _app_cuda* *.ptx f_tempfile_ptx gpgpu_inst_stats.txt > /dev/null 2>&1
        rm -r ${TMP_DIR}${run_index} > /dev/null 2>&1 # comment out to debug output
    fi
    if [[ "$profile" -ne 1 ]]; then
        # clean intermediate logs anyway if profile != 1
        rm _ptx* _cuobjdump_* _app_cuda* *.ptx f_tempfile_ptx gpgpu_inst_stats.txt > /dev/null 2>&1
    fi
}

main() {
    # Remove all directories whose names start with 'logs'
    find . -type d -name "logs*" -exec rm -rf {} + 2>/dev/null || true
    sanitize_run_settings
    echo "=== Campaign profile guarded settings: serial, nice=${SIM_NICE} ==="

    if [[ "$profile" -eq 1 ]] || [[ "$profile" -eq 2 ]] || [[ "$profile" -eq 3 ]]; then
        RUNS=1
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
