#ifndef PTX_INFLUENCE_CAPI_H_
#define PTX_INFLUENCE_CAPI_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum ExactInfluenceOpCode {
  EXACT_OP_ADD = 0,
  EXACT_OP_ADD_F32 = 1,
  EXACT_OP_SUB = 2,
  EXACT_OP_SUB_F32 = 3,
  EXACT_OP_NEG = 4,
  EXACT_OP_NEG_F32 = 5,
  EXACT_OP_MUL_LO = 6,
  EXACT_OP_MUL_F32 = 7,
  EXACT_OP_MUL_WIDE_U32 = 8,
  EXACT_OP_MUL_WIDE_S32 = 9,
  EXACT_OP_MAD = 10,
  EXACT_OP_FMA_F32 = 11,
  EXACT_OP_DIV_F32 = 12,
  EXACT_OP_SQRT_F32 = 13,
  EXACT_OP_ABS_F32 = 14,
  EXACT_OP_EX2_APPROX_FTZ_F32 = 15,
  EXACT_OP_RCP_APPROX_FTZ_F32 = 16,
  EXACT_OP_MIN_F32 = 17,
  EXACT_OP_MAX_F32 = 18,
  EXACT_OP_IDENTITY = 19,
  EXACT_OP_NOT = 20,
  EXACT_OP_NOT_PRED = 21,
  EXACT_OP_AND = 22,
  EXACT_OP_OR = 23,
  EXACT_OP_XOR = 24,
  EXACT_OP_SHL = 25,
  EXACT_OP_SHR_U = 26,
  EXACT_OP_SHR_S = 27,
  EXACT_OP_MIN_U = 28,
  EXACT_OP_MIN_S = 29,
  EXACT_OP_MAX_U = 30,
  EXACT_OP_MAX_S = 31,
  EXACT_OP_CVT_U32_U64 = 32,
  EXACT_OP_CVT_U64_U32 = 33,
  EXACT_OP_CVT_S32_S64 = 34,
  EXACT_OP_CVT_S64_S32 = 35,
  EXACT_OP_CVT_SAT_F32_F32 = 36,
  EXACT_OP_SETP_EQ = 37,
  EXACT_OP_SETP_NE = 38,
  EXACT_OP_SETP_LT_U = 39,
  EXACT_OP_SETP_LT_S = 40,
  EXACT_OP_SETP_LE_U = 41,
  EXACT_OP_SETP_LE_S = 42,
  EXACT_OP_SETP_GT_U = 43,
  EXACT_OP_SETP_GT_S = 44,
  EXACT_OP_SETP_GE_U = 45,
  EXACT_OP_SETP_GE_S = 46,
  EXACT_OP_SELP = 47
};

struct ExactInfluenceRequest {
  int op_code;
  int width_bits;
  int signed_mode;
  int src_count;
  uint64_t src_vals[3];
  uint64_t dst_val;
  uint64_t dst_observed_mask;
};

struct ExactInfluenceResponse {
  int status;
  uint64_t src_masks[3];
};

enum ExactTracePolicyCode {
  EXACT_TRACE_POLICY_MASKED = 0,
  EXACT_TRACE_POLICY_SDC = 1
};

enum ExactTraceUncoveredModeCode {
  EXACT_TRACE_UNCOVERED_LEGACY_UNKNOWN = 0,
  EXACT_TRACE_UNCOVERED_POLICY = 1
};

enum ExactTraceSemanticMaskedModeCode {
  EXACT_TRACE_SEMANTIC_LEGACY_SEMANTIC_FIRST = 0,
  EXACT_TRACE_SEMANTIC_POLICY_OVERRIDES_MASKED = 1
};

struct ExactMaskClassifyRequest {
  int width_bits;
  int trace_policy_code;
  int trace_uncovered_mode_code;
  int trace_semantic_masked_mode_code;
  uint64_t observed_mask;
  uint64_t due_mask;
  uint64_t trace_mask;
  uint64_t semantic_masked_mask;
  uint64_t semantic_sdc_mask;
  uint64_t semantic_due_mask;
  uint64_t semantic_infra_mask;
  uint64_t semantic_unknown_mask;
};

struct ExactMaskClassifyResponse {
  int status;
  uint64_t due_mask;
  uint64_t sdc_mask;
  uint64_t unknown_mask;
  uint64_t policy_added_sdc_mask;
  uint64_t policy_used_mask;
  uint64_t trace_mask;
  uint64_t policy_override_mask;
};

struct ExactSiteMaskClassifyResponse {
  int status;
  uint64_t due_mask;
  uint64_t sdc_mask;
  uint64_t unknown_mask;
  uint64_t policy_used_mask;
  uint64_t policy_override_mask;
};

struct ExactControlTaintEventDesc {
  int64_t kind_id;
  int64_t opcode_id;
  int64_t pc_id;
  int64_t dst_reg_id;
  int64_t width_bits;
  uint32_t src_reg_offset;
  uint32_t src_reg_count;
  uint32_t src_width_offset;
  uint32_t src_width_count;
  uint32_t src_val_offset;
  uint32_t src_val_count;
  uint8_t branch_flag;
  uint8_t base_taken;
  uint16_t reserved;
};

struct ExactControlTaintDigest {
  uint64_t lo;
  uint64_t hi;
};

struct ExactControlTaintThreadBatchDesc {
  uint32_t event_offset;
  uint32_t event_count;
};

struct ExactThreadCycleWeightEntry {
  int64_t thread_id;
  int64_t cycle;
  int64_t weight;
};

struct ExactToleranceStepDesc {
  int op_code;
  int width_bits_default;
  int tracked_src_index;
  uint32_t src_val_offset;
  uint32_t src_val_count;
};

struct ExactTolerancePathDesc {
  int final_width_bits;
  uint32_t step_offset;
  uint32_t step_count;
};

struct ExactToleranceEvalRequest {
  uint32_t path_index;
  uint64_t current_value;
};

struct ExactToleranceEvalResponse {
  int status;
  uint64_t final_bits;
};

struct ExactRfIntervalRequest {
  int64_t mass;
  int32_t bit_count;
  uint8_t legacy_unknown_trace_uncovered;
  uint64_t selected_mask;
  uint64_t due_mask;
  uint64_t sdc_mask;
  uint64_t unknown_mask;
  uint64_t trace_added_sdc_mask;
  uint64_t trace_policy_used_mask;
  uint64_t trace_policy_override_mask;
  uint64_t trace_mask;
  uint64_t semantic_due_mask;
  uint64_t addr_due_mask;
  uint64_t addr_sdc_mask;
  uint64_t addr_unknown_mask;
  uint64_t addr_trace_div_mask;
};

struct ExactRfIntervalAccum {
  int64_t masked_num;
  int64_t sdc_num;
  int64_t due_num;
  int64_t unknown_num;
  int64_t semantic_due_mass;
  int64_t addr_due_num;
  int64_t addr_sdc_num;
  int64_t addr_unknown_num;
  int64_t addr_oob_due_mass;
  int64_t trace_divergence_due_mass;
  int64_t addr_alias_sdc_mass;
  int64_t trace_divergence_sdc_mass;
  int64_t trace_expanding_sdc_numerator;
  int64_t trace_policy_used_bits;
  int64_t trace_policy_used_mass;
  int64_t trace_policy_override_bits;
  int64_t trace_policy_override_mass;
  int64_t trace_policy_override_sdc_bits;
  int64_t trace_policy_override_due_bits;
  int64_t trace_policy_override_unknown_bits;
  int64_t trace_policy_override_masked_bits;
  int64_t trace_uncovered_unknown_bits;
  int64_t trace_uncovered_unknown_mass;
  uint8_t saw_trace_selected_bits;
};

int exact_backward_influence_one(const ExactInfluenceRequest *request,
                                 ExactInfluenceResponse *response);

size_t exact_backward_influence_many(const ExactInfluenceRequest *requests,
                                     size_t count,
                                     ExactInfluenceResponse *responses);

int exact_classify_read_masks_one(const ExactMaskClassifyRequest *request,
                                  ExactMaskClassifyResponse *response);

size_t exact_classify_read_masks_many(const ExactMaskClassifyRequest *requests,
                                      size_t count,
                                      ExactMaskClassifyResponse *responses);

int exact_classify_site_masks_one(const ExactMaskClassifyRequest *request,
                                  ExactSiteMaskClassifyResponse *response);

size_t exact_classify_site_masks_many(
    const ExactMaskClassifyRequest *requests,
    size_t count,
    ExactSiteMaskClassifyResponse *responses);

int exact_control_taint_thread_hashes(
    const ExactControlTaintEventDesc *events,
    size_t event_count,
    const int64_t *src_reg_ids,
    size_t src_reg_count,
    const int64_t *src_width_bits,
    size_t src_width_count,
    const uint64_t *src_vals,
    size_t src_val_count,
    ExactControlTaintDigest *signature_out,
    ExactControlTaintDigest *sketch_out);

size_t exact_control_taint_thread_hashes_many(
    const ExactControlTaintThreadBatchDesc *threads,
    size_t thread_count,
    const ExactControlTaintEventDesc *events,
    size_t event_count,
    const int64_t *src_reg_ids,
    size_t src_reg_count,
    const int64_t *src_width_bits,
    size_t src_width_count,
    const uint64_t *src_vals,
    size_t src_val_count,
    ExactControlTaintDigest *signature_out,
    ExactControlTaintDigest *sketch_out);

size_t exact_thread_cycle_weights(
    const int64_t *cycles,
    const int64_t *multiplicities,
    const uint32_t *active_offsets,
    const int64_t *active_thread_ids,
    size_t record_count,
    const int64_t *seed_values,
    size_t seed_count,
    int64_t thread_rand_max,
    ExactThreadCycleWeightEntry *out_entries,
    size_t out_capacity,
    int64_t *seed_domain_size_out,
    int64_t *inactive_base_mass_out,
    int64_t *active_base_mass_out);

size_t exact_evaluate_tolerance_paths_many(
    const ExactToleranceStepDesc *steps,
    size_t step_count,
    const uint64_t *src_vals,
    size_t src_val_count,
    const ExactTolerancePathDesc *paths,
    size_t path_count,
    const ExactToleranceEvalRequest *requests,
    size_t request_count,
    ExactToleranceEvalResponse *responses);

int exact_rf_interval_accumulate_many(const ExactRfIntervalRequest *requests,
                                      size_t request_count,
                                      ExactRfIntervalAccum *out);

#ifdef __cplusplus
}
#endif

#endif  // PTX_INFLUENCE_CAPI_H_
