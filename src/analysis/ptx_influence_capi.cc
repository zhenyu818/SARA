#include "analysis/ptx_influence_capi.h"

#include "analysis/ptx_influence.h"

#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <set>
#include <unordered_map>
#include <vector>

namespace {

bool decode_op(int op_code, Op *out) {
  if (out == nullptr) {
    return false;
  }
  switch (op_code) {
    case EXACT_OP_ADD:
      *out = Op::ADD;
      return true;
    case EXACT_OP_ADD_F32:
      *out = Op::ADD_F32;
      return true;
    case EXACT_OP_SUB:
      *out = Op::SUB;
      return true;
    case EXACT_OP_SUB_F32:
      *out = Op::SUB_F32;
      return true;
    case EXACT_OP_NEG:
      *out = Op::NEG;
      return true;
    case EXACT_OP_NEG_F32:
      *out = Op::NEG_F32;
      return true;
    case EXACT_OP_MUL_LO:
      *out = Op::MUL_LO;
      return true;
    case EXACT_OP_MUL_F32:
      *out = Op::MUL_F32;
      return true;
    case EXACT_OP_MUL_WIDE_U32:
      *out = Op::MUL_WIDE_U32;
      return true;
    case EXACT_OP_MUL_WIDE_S32:
      *out = Op::MUL_WIDE_S32;
      return true;
    case EXACT_OP_MAD:
      *out = Op::MAD;
      return true;
    case EXACT_OP_FMA_F32:
      *out = Op::FMA_F32;
      return true;
    case EXACT_OP_DIV_F32:
      *out = Op::DIV_F32;
      return true;
    case EXACT_OP_SQRT_F32:
      *out = Op::SQRT_F32;
      return true;
    case EXACT_OP_ABS_F32:
      *out = Op::ABS_F32;
      return true;
    case EXACT_OP_EX2_APPROX_FTZ_F32:
      *out = Op::EX2_APPROX_FTZ_F32;
      return true;
    case EXACT_OP_RCP_APPROX_FTZ_F32:
      *out = Op::RCP_APPROX_FTZ_F32;
      return true;
    case EXACT_OP_MIN_F32:
      *out = Op::MIN_F32;
      return true;
    case EXACT_OP_MAX_F32:
      *out = Op::MAX_F32;
      return true;
    case EXACT_OP_IDENTITY:
      *out = Op::IDENTITY;
      return true;
    case EXACT_OP_NOT:
      *out = Op::NOT;
      return true;
    case EXACT_OP_NOT_PRED:
      *out = Op::NOT_PRED;
      return true;
    case EXACT_OP_AND:
      *out = Op::AND;
      return true;
    case EXACT_OP_OR:
      *out = Op::OR;
      return true;
    case EXACT_OP_XOR:
      *out = Op::XOR;
      return true;
    case EXACT_OP_SHL:
      *out = Op::SHL;
      return true;
    case EXACT_OP_SHR_U:
      *out = Op::SHR_U;
      return true;
    case EXACT_OP_SHR_S:
      *out = Op::SHR_S;
      return true;
    case EXACT_OP_MIN_U:
      *out = Op::MIN_U;
      return true;
    case EXACT_OP_MIN_S:
      *out = Op::MIN_S;
      return true;
    case EXACT_OP_MAX_U:
      *out = Op::MAX_U;
      return true;
    case EXACT_OP_MAX_S:
      *out = Op::MAX_S;
      return true;
    case EXACT_OP_CVT_U32_U64:
      *out = Op::CVT_U32_U64;
      return true;
    case EXACT_OP_CVT_U64_U32:
      *out = Op::CVT_U64_U32;
      return true;
    case EXACT_OP_CVT_S32_S64:
      *out = Op::CVT_S32_S64;
      return true;
    case EXACT_OP_CVT_S64_S32:
      *out = Op::CVT_S64_S32;
      return true;
    case EXACT_OP_CVT_SAT_F32_F32:
      *out = Op::CVT_SAT_F32_F32;
      return true;
    case EXACT_OP_SETP_EQ:
      *out = Op::SETP_EQ;
      return true;
    case EXACT_OP_SETP_NE:
      *out = Op::SETP_NE;
      return true;
    case EXACT_OP_SETP_LT_U:
      *out = Op::SETP_LT_U;
      return true;
    case EXACT_OP_SETP_LT_S:
      *out = Op::SETP_LT_S;
      return true;
    case EXACT_OP_SETP_LE_U:
      *out = Op::SETP_LE_U;
      return true;
    case EXACT_OP_SETP_LE_S:
      *out = Op::SETP_LE_S;
      return true;
    case EXACT_OP_SETP_GT_U:
      *out = Op::SETP_GT_U;
      return true;
    case EXACT_OP_SETP_GT_S:
      *out = Op::SETP_GT_S;
      return true;
    case EXACT_OP_SETP_GE_U:
      *out = Op::SETP_GE_U;
      return true;
    case EXACT_OP_SETP_GE_S:
      *out = Op::SETP_GE_S;
      return true;
    case EXACT_OP_SELP:
      *out = Op::SELP;
      return true;
    default:
      return false;
  }
}

int expected_src_count(Op op) {
  switch (op) {
    case Op::FMA_F32:
    case Op::MAD:
    case Op::SELP:
      return 3;
    case Op::NEG:
    case Op::NEG_F32:
    case Op::SQRT_F32:
    case Op::ABS_F32:
    case Op::EX2_APPROX_FTZ_F32:
    case Op::RCP_APPROX_FTZ_F32:
    case Op::IDENTITY:
    case Op::NOT:
    case Op::NOT_PRED:
    case Op::CVT_U32_U64:
    case Op::CVT_U64_U32:
    case Op::CVT_S32_S64:
    case Op::CVT_S64_S32:
    case Op::CVT_SAT_F32_F32:
      return 1;
    default:
      return 2;
  }
}

void clear_response(ExactInfluenceResponse *response, int status) {
  if (response == nullptr) {
    return;
  }
  response->status = status;
  response->src_masks[0] = 0;
  response->src_masks[1] = 0;
  response->src_masks[2] = 0;
}

uint64_t width_mask(int width_bits) {
  if (width_bits <= 0) {
    return 0;
  }
  if (width_bits >= 64) {
    return UINT64_MAX;
  }
  return (uint64_t{1} << width_bits) - uint64_t{1};
}

bool decode_trace_policy(int code, bool *policy_sdc) {
  if (policy_sdc == nullptr) return false;
  switch (code) {
    case EXACT_TRACE_POLICY_MASKED:
      *policy_sdc = false;
      return true;
    case EXACT_TRACE_POLICY_SDC:
      *policy_sdc = true;
      return true;
    default:
      return false;
  }
}

bool decode_trace_uncovered_mode(int code, bool *policy_mode) {
  if (policy_mode == nullptr) return false;
  switch (code) {
    case EXACT_TRACE_UNCOVERED_LEGACY_UNKNOWN:
      *policy_mode = false;
      return true;
    case EXACT_TRACE_UNCOVERED_POLICY:
      *policy_mode = true;
      return true;
    default:
      return false;
  }
}

bool decode_trace_semantic_masked_mode(int code, bool *policy_overrides_masked) {
  if (policy_overrides_masked == nullptr) return false;
  switch (code) {
    case EXACT_TRACE_SEMANTIC_LEGACY_SEMANTIC_FIRST:
      *policy_overrides_masked = false;
      return true;
    case EXACT_TRACE_SEMANTIC_POLICY_OVERRIDES_MASKED:
      *policy_overrides_masked = true;
      return true;
    default:
      return false;
  }
}

void clear_read_mask_response(ExactMaskClassifyResponse *response, int status) {
  if (response == nullptr) return;
  response->status = status;
  response->due_mask = 0;
  response->sdc_mask = 0;
  response->unknown_mask = 0;
  response->policy_added_sdc_mask = 0;
  response->policy_used_mask = 0;
  response->trace_mask = 0;
  response->policy_override_mask = 0;
}

void clear_site_mask_response(ExactSiteMaskClassifyResponse *response, int status) {
  if (response == nullptr) return;
  response->status = status;
  response->due_mask = 0;
  response->sdc_mask = 0;
  response->unknown_mask = 0;
  response->policy_used_mask = 0;
  response->policy_override_mask = 0;
}

void clear_tolerance_eval_response(ExactToleranceEvalResponse *response,
                                   int status) {
  if (response == nullptr) return;
  response->status = status;
  response->final_bits = 0;
}

uint64_t mix64(uint64_t x) {
  x += 0x9e3779b97f4a7c15ULL;
  x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
  x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
  return x ^ (x >> 31);
}

struct ThreadCycleKey {
  int64_t tid;
  int64_t cycle;

  bool operator==(const ThreadCycleKey &other) const {
    return tid == other.tid && cycle == other.cycle;
  }
};

struct ThreadCycleKeyHash {
  size_t operator()(const ThreadCycleKey &key) const {
    const uint64_t a = mix64(static_cast<uint64_t>(key.tid));
    const uint64_t b = mix64(static_cast<uint64_t>(key.cycle));
    return static_cast<size_t>(a ^ (b + 0x9e3779b97f4a7c15ULL + (a << 6) + (a >> 2)));
  }
};

void digest_update(uint64_t *lo, uint64_t *hi, uint64_t value) {
  if (lo == nullptr || hi == nullptr) return;
  *lo = mix64((*lo) ^ (value + 0x243f6a8885a308d3ULL));
  *hi = mix64((*hi) + value + 0x13198a2e03707344ULL);
}

void digest_update_i64(uint64_t *lo, uint64_t *hi, int64_t value) {
  digest_update(lo, hi, static_cast<uint64_t>(value));
}

void digest_update_u64(uint64_t *lo, uint64_t *hi, uint64_t value) {
  digest_update(lo, hi, value);
}

void digest_event(
    const ExactControlTaintEventDesc &ev,
    const int64_t *src_reg_ids,
    size_t src_reg_count,
    const int64_t *src_width_bits,
    size_t src_width_count,
    const uint64_t *src_vals,
    size_t src_val_count,
    uint64_t *lo,
    uint64_t *hi) {
  digest_update_i64(lo, hi, ev.kind_id);
  digest_update_i64(lo, hi, ev.opcode_id);
  digest_update_i64(lo, hi, ev.pc_id);
  digest_update_i64(lo, hi, ev.dst_reg_id);
  digest_update_i64(lo, hi, ev.width_bits);
  digest_update_u64(lo, hi, static_cast<uint64_t>(ev.branch_flag));
  digest_update_u64(lo, hi, static_cast<uint64_t>(ev.base_taken));

  digest_update_u64(lo, hi, static_cast<uint64_t>(ev.src_reg_count));
  const size_t reg_begin = static_cast<size_t>(ev.src_reg_offset);
  const size_t reg_end = reg_begin + static_cast<size_t>(ev.src_reg_count);
  if (reg_end <= src_reg_count) {
    for (size_t i = reg_begin; i < reg_end; ++i) {
      digest_update_i64(lo, hi, src_reg_ids[i]);
    }
  }

  digest_update_u64(lo, hi, static_cast<uint64_t>(ev.src_width_count));
  const size_t width_begin = static_cast<size_t>(ev.src_width_offset);
  const size_t width_end = width_begin + static_cast<size_t>(ev.src_width_count);
  if (width_end <= src_width_count) {
    for (size_t i = width_begin; i < width_end; ++i) {
      digest_update_i64(lo, hi, src_width_bits[i]);
    }
  }

  digest_update_u64(lo, hi, static_cast<uint64_t>(ev.src_val_count));
  const size_t val_begin = static_cast<size_t>(ev.src_val_offset);
  const size_t val_end = val_begin + static_cast<size_t>(ev.src_val_count);
  if (val_end <= src_val_count) {
    for (size_t i = val_begin; i < val_end; ++i) {
      digest_update_u64(lo, hi, src_vals[i]);
    }
  }
}

void finalize_control_taint_hashes_for_thread(
    const ExactControlTaintEventDesc *events,
    size_t event_count,
    const int64_t *src_reg_ids,
    size_t src_reg_count,
    const int64_t *src_width_bits,
    size_t src_width_count,
    const uint64_t *src_vals,
    size_t src_val_count,
    ExactControlTaintDigest *signature_out,
    ExactControlTaintDigest *sketch_out) {
  if (signature_out == nullptr || sketch_out == nullptr) {
    return;
  }
  if (event_count == 0) {
    signature_out->lo = 0;
    signature_out->hi = 0;
    sketch_out->lo = 0;
    sketch_out->hi = 0;
    return;
  }

  uint64_t sig_lo = 0x6a09e667f3bcc909ULL;
  uint64_t sig_hi = 0xbb67ae8584caa73bULL;
  digest_update_u64(&sig_lo, &sig_hi, static_cast<uint64_t>(event_count));
  for (size_t i = 0; i < event_count; ++i) {
    digest_event(events[i], src_reg_ids, src_reg_count, src_width_bits,
                 src_width_count, src_vals, src_val_count, &sig_lo, &sig_hi);
  }
  signature_out->lo = sig_lo;
  signature_out->hi = sig_hi;

  uint64_t sketch_lo = 0x3c6ef372fe94f82bULL;
  uint64_t sketch_hi = 0xa54ff53a5f1d36f1ULL;
  digest_update_u64(&sketch_lo, &sketch_hi, static_cast<uint64_t>(event_count));
  const size_t sample_count = std::min<size_t>(24, event_count);
  std::set<size_t> sample_positions;
  sample_positions.insert(0);
  sample_positions.insert(event_count - 1);
  if (sample_count > 2 && event_count > 2) {
    const size_t denom = sample_count - 1;
    for (size_t i = 1; i + 1 < sample_count; ++i) {
      sample_positions.insert((i * (event_count - 1)) / denom);
    }
  }

  for (size_t pos : sample_positions) {
    digest_update_u64(&sketch_lo, &sketch_hi, static_cast<uint64_t>(pos));
    digest_event(events[pos], src_reg_ids, src_reg_count, src_width_bits,
                 src_width_count, src_vals, src_val_count, &sketch_lo,
                 &sketch_hi);
  }
  sketch_out->lo = sketch_lo;
  sketch_out->hi = sketch_hi;
}

void trace_policy_masks_for_trace_bits(
    uint64_t trace,
    uint64_t r_masked,
    uint64_t r_sdc,
    uint64_t r_due,
    uint64_t r_infra,
    uint64_t r_unknown,
    uint64_t wmask,
    bool trace_policy_sdc,
    bool uncovered_policy_mode,
    bool policy_overrides_masked,
    uint64_t *semantic_due,
    uint64_t *semantic_sdc,
    uint64_t *semantic_unknown,
    uint64_t *policy_used_mask,
    uint64_t *policy_sdc_mask,
    uint64_t *policy_unknown_mask,
    uint64_t *policy_override_mask) {
  const uint64_t trace_mask = trace & wmask;
  const uint64_t due = trace_mask & r_due & wmask;
  const uint64_t sdc = trace_mask & r_sdc & wmask;
  const uint64_t unknown = trace_mask & (r_infra | r_unknown) & wmask;
  const uint64_t masked = trace_mask & r_masked & wmask;

  uint64_t semantic_covered = 0;
  uint64_t override_mask = 0;
  if (policy_overrides_masked) {
    semantic_covered = due | sdc | unknown;
    override_mask = masked & (~semantic_covered & wmask);
  } else {
    semantic_covered = due | sdc | masked | unknown;
  }

  uint64_t used_mask = trace_mask & (~semantic_covered & wmask);
  uint64_t policy_sdc_bits = 0;
  uint64_t policy_unknown_bits = 0;
  if (uncovered_policy_mode) {
    if (trace_policy_sdc) {
      policy_sdc_bits = used_mask;
    }
  } else {
    policy_unknown_bits = used_mask;
  }

  *semantic_due = due & UINT64_MAX;
  *semantic_sdc = sdc & UINT64_MAX;
  *semantic_unknown = unknown & UINT64_MAX;
  *policy_used_mask = used_mask & UINT64_MAX;
  *policy_sdc_mask = policy_sdc_bits & UINT64_MAX;
  *policy_unknown_mask = policy_unknown_bits & UINT64_MAX;
  *policy_override_mask = override_mask & UINT64_MAX;
}

int classify_masks_common(
    const ExactMaskClassifyRequest *request,
    uint64_t *due_final,
    uint64_t *sdc_final,
    uint64_t *unknown_final,
    uint64_t *policy_added_sdc_mask,
    uint64_t *policy_used_mask,
    uint64_t *trace_mask_out,
    uint64_t *policy_override_mask,
    bool site_mode) {
  if (request == nullptr) return -1;

  bool trace_policy_sdc = false;
  bool uncovered_policy_mode = false;
  bool semantic_policy_overrides_masked = false;
  if (!decode_trace_policy(request->trace_policy_code, &trace_policy_sdc)) return -2;
  if (!decode_trace_uncovered_mode(request->trace_uncovered_mode_code, &uncovered_policy_mode)) return -3;
  if (!decode_trace_semantic_masked_mode(request->trace_semantic_masked_mode_code,
                                       &semantic_policy_overrides_masked)) return -4;

  const uint64_t wmask = width_mask(request->width_bits);
  uint64_t obs = request->observed_mask & wmask;
  uint64_t due = request->due_mask & wmask;
  uint64_t trace = request->trace_mask & wmask;
  uint64_t r_masked = request->semantic_masked_mask & wmask;
  uint64_t r_sdc = request->semantic_sdc_mask & wmask;
  uint64_t r_due = request->semantic_due_mask & wmask;
  uint64_t r_infra = request->semantic_infra_mask & wmask;
  uint64_t r_unknown = request->semantic_unknown_mask & wmask;

  const uint64_t proof_due_trace = trace & due;
  const uint64_t proof_sdc_trace = trace & obs & (~proof_due_trace & UINT64_MAX);
  const uint64_t trace_for_semantic =
      trace & (~proof_due_trace & UINT64_MAX) & (~proof_sdc_trace & UINT64_MAX);

  uint64_t trace_semantic_due = 0;
  uint64_t trace_semantic_sdc = 0;
  uint64_t trace_semantic_unknown = 0;
  uint64_t policy_used = 0;
  uint64_t policy_sdc_bits = 0;
  uint64_t policy_unknown_bits = 0;
  uint64_t policy_override = 0;
  trace_policy_masks_for_trace_bits(
      trace_for_semantic, r_masked, r_sdc, r_due, r_infra, r_unknown, wmask,
      trace_policy_sdc, uncovered_policy_mode, semantic_policy_overrides_masked,
      &trace_semantic_due, &trace_semantic_sdc, &trace_semantic_unknown, &policy_used,
      &policy_sdc_bits, &policy_unknown_bits, &policy_override);

  if (!site_mode) {
    const uint64_t inv_trace = (~trace) & wmask;
    uint64_t unknown = policy_unknown_bits | trace_semantic_unknown | (inv_trace & (r_infra | r_unknown));
    uint64_t due_mask_final = proof_due_trace | trace_semantic_due | (inv_trace & due);
    uint64_t sdc_baseline = proof_sdc_trace | trace_semantic_sdc | (inv_trace & obs);
    uint64_t sdc_mask_final = sdc_baseline | policy_sdc_bits;

    due_mask_final &= wmask;
    sdc_mask_final &= wmask;
    unknown &= wmask;
    due_mask_final &= ~unknown;
    sdc_mask_final &= ~unknown;
    sdc_mask_final &= ~due_mask_final;
    sdc_baseline &= wmask;
    sdc_baseline &= ~due_mask_final;
    sdc_baseline &= ~unknown;

    *due_final = due_mask_final & UINT64_MAX;
    *sdc_final = sdc_mask_final & UINT64_MAX;
    *unknown_final = unknown & UINT64_MAX;
    *policy_added_sdc_mask = (sdc_mask_final & (~sdc_baseline & UINT64_MAX)) & UINT64_MAX;
    *policy_used_mask = policy_used & wmask & UINT64_MAX;
    *trace_mask_out = trace & UINT64_MAX;
    *policy_override_mask = policy_override & wmask & UINT64_MAX;
    return 0;
  }

  const uint64_t inv_trace = (~trace) & wmask;
  const uint64_t due_base = proof_due_trace | trace_semantic_due | (inv_trace & due);
  const uint64_t sdc_baseline = proof_sdc_trace | trace_semantic_sdc | (inv_trace & obs);
  const uint64_t sdc_base = sdc_baseline | policy_sdc_bits;
  const uint64_t proof_resolved = proof_due_trace | proof_sdc_trace;
  const uint64_t semantic_due_any = r_due & (~proof_resolved & UINT64_MAX) & wmask;
  const uint64_t semantic_sdc_any =
      (r_sdc & (~proof_resolved & UINT64_MAX) & (~semantic_due_any & UINT64_MAX)) & wmask;
  const uint64_t semantic_masked_any =
      (r_masked & (~proof_resolved & UINT64_MAX) & (~semantic_due_any & UINT64_MAX) &
       (~semantic_sdc_any & UINT64_MAX)) &
      wmask;
  const uint64_t semantic_unknown_any =
      ((r_infra | r_unknown) & (~proof_resolved & UINT64_MAX)) & wmask;
  const uint64_t semantic_any =
      semantic_due_any | semantic_sdc_any | semantic_masked_any | semantic_unknown_any;

  uint64_t due_mask_final = proof_due_trace | semantic_due_any | (due_base & (~semantic_any & UINT64_MAX));
  uint64_t sdc_mask_final = proof_sdc_trace | semantic_sdc_any | (sdc_base & (~semantic_any & UINT64_MAX));
  uint64_t unknown = semantic_unknown_any | policy_unknown_bits;

  due_mask_final &= wmask;
  sdc_mask_final &= wmask;
  unknown &= wmask;
  due_mask_final &= ~unknown;
  sdc_mask_final &= ~unknown;
  sdc_mask_final &= ~due_mask_final;

  *due_final = due_mask_final & UINT64_MAX;
  *sdc_final = sdc_mask_final & UINT64_MAX;
  *unknown_final = unknown & UINT64_MAX;
  *policy_added_sdc_mask = 0;
  *policy_used_mask = policy_used & wmask & UINT64_MAX;
  *trace_mask_out = trace & UINT64_MAX;
  *policy_override_mask = policy_override & wmask & UINT64_MAX;
  return 0;
}

}  // namespace

extern "C" int exact_backward_influence_one(
    const ExactInfluenceRequest *request, ExactInfluenceResponse *response) {
  if (request == nullptr || response == nullptr) {
    clear_response(response, -1);
    return -1;
  }

  Op op;
  if (!decode_op(request->op_code, &op)) {
    clear_response(response, -2);
    return -2;
  }

  const int expected = expected_src_count(op);
  if (request->src_count != expected) {
    clear_response(response, -3);
    return -3;
  }

  std::vector<uint64_t> src_vals;
  src_vals.reserve(static_cast<size_t>(expected));
  for (int i = 0; i < expected; ++i) {
    src_vals.push_back(request->src_vals[i]);
  }

  OpMeta meta;
  meta.width_bits = request->width_bits;
  meta.signed_mode = (request->signed_mode != 0);

  const InfluenceResult result =
      backward_influence(op, src_vals, request->dst_val,
                         request->dst_observed_mask, meta);

  clear_response(response, 0);
  for (size_t i = 0; i < result.src_masks.size() && i < 3; ++i) {
    response->src_masks[i] = result.src_masks[i];
  }
  return 0;
}

extern "C" size_t exact_backward_influence_many(
    const ExactInfluenceRequest *requests, size_t count,
    ExactInfluenceResponse *responses) {
  if (requests == nullptr || responses == nullptr) {
    return 0;
  }
  size_t completed = 0;
  for (size_t i = 0; i < count; ++i) {
    exact_backward_influence_one(&requests[i], &responses[i]);
    ++completed;
  }
  return completed;
}

extern "C" int exact_classify_read_masks_one(
    const ExactMaskClassifyRequest *request,
    ExactMaskClassifyResponse *response) {
  if (request == nullptr || response == nullptr) {
    clear_read_mask_response(response, -1);
    return -1;
  }
  uint64_t due = 0;
  uint64_t sdc = 0;
  uint64_t unknown = 0;
  uint64_t policy_added = 0;
  uint64_t policy_used = 0;
  uint64_t trace = 0;
  uint64_t policy_override = 0;
  const int rc = classify_masks_common(
      request, &due, &sdc, &unknown, &policy_added, &policy_used, &trace,
      &policy_override, false);
  clear_read_mask_response(response, rc);
  if (rc != 0) return rc;
  response->due_mask = due;
  response->sdc_mask = sdc;
  response->unknown_mask = unknown;
  response->policy_added_sdc_mask = policy_added;
  response->policy_used_mask = policy_used;
  response->trace_mask = trace;
  response->policy_override_mask = policy_override;
  return 0;
}

extern "C" size_t exact_classify_read_masks_many(
    const ExactMaskClassifyRequest *requests, size_t count,
    ExactMaskClassifyResponse *responses) {
  if (requests == nullptr || responses == nullptr) {
    return 0;
  }
  size_t completed = 0;
  for (size_t i = 0; i < count; ++i) {
    exact_classify_read_masks_one(&requests[i], &responses[i]);
    ++completed;
  }
  return completed;
}

extern "C" int exact_classify_site_masks_one(
    const ExactMaskClassifyRequest *request,
    ExactSiteMaskClassifyResponse *response) {
  if (request == nullptr || response == nullptr) {
    clear_site_mask_response(response, -1);
    return -1;
  }
  uint64_t due = 0;
  uint64_t sdc = 0;
  uint64_t unknown = 0;
  uint64_t policy_added = 0;
  uint64_t policy_used = 0;
  uint64_t trace = 0;
  uint64_t policy_override = 0;
  const int rc = classify_masks_common(
      request, &due, &sdc, &unknown, &policy_added, &policy_used, &trace,
      &policy_override, true);
  clear_site_mask_response(response, rc);
  if (rc != 0) return rc;
  response->due_mask = due;
  response->sdc_mask = sdc;
  response->unknown_mask = unknown;
  response->policy_used_mask = policy_used;
  response->policy_override_mask = policy_override;
  return 0;
}

extern "C" size_t exact_classify_site_masks_many(
    const ExactMaskClassifyRequest *requests, size_t count,
    ExactSiteMaskClassifyResponse *responses) {
  if (requests == nullptr || responses == nullptr) {
    return 0;
  }
  size_t completed = 0;
  for (size_t i = 0; i < count; ++i) {
    exact_classify_site_masks_one(&requests[i], &responses[i]);
    ++completed;
  }
  return completed;
}

extern "C" int exact_control_taint_thread_hashes(
    const ExactControlTaintEventDesc *events,
    size_t event_count,
    const int64_t *src_reg_ids,
    size_t src_reg_count,
    const int64_t *src_width_bits,
    size_t src_width_count,
    const uint64_t *src_vals,
    size_t src_val_count,
    ExactControlTaintDigest *signature_out,
    ExactControlTaintDigest *sketch_out) {
  if (events == nullptr || signature_out == nullptr || sketch_out == nullptr) {
    return -1;
  }
  finalize_control_taint_hashes_for_thread(
      events, event_count, src_reg_ids, src_reg_count, src_width_bits,
      src_width_count, src_vals, src_val_count, signature_out, sketch_out);
  return 0;
}

extern "C" size_t exact_control_taint_thread_hashes_many(
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
    ExactControlTaintDigest *sketch_out) {
  if (threads == nullptr || signature_out == nullptr || sketch_out == nullptr) {
    return 0;
  }
  size_t completed = 0;
  for (size_t i = 0; i < thread_count; ++i) {
    const size_t begin = static_cast<size_t>(threads[i].event_offset);
    const size_t count = static_cast<size_t>(threads[i].event_count);
    if (begin > event_count || count > (event_count - begin)) {
      break;
    }
    finalize_control_taint_hashes_for_thread(
        events + begin, count, src_reg_ids, src_reg_count, src_width_bits,
        src_width_count, src_vals, src_val_count, &signature_out[i],
        &sketch_out[i]);
    ++completed;
  }
  return completed;
}

extern "C" size_t exact_thread_cycle_weights(
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
    int64_t *active_base_mass_out) {
  if (cycles == nullptr || multiplicities == nullptr || active_offsets == nullptr ||
      out_entries == nullptr || seed_domain_size_out == nullptr ||
      inactive_base_mass_out == nullptr || active_base_mass_out == nullptr) {
    return 0;
  }

  int64_t total_cycle_lines = 0;
  int64_t inactive_base_mass = 0;
  int64_t seed_domain_size = 0;
  std::unordered_map<ThreadCycleKey, int64_t, ThreadCycleKeyHash> weights;

  for (size_t i = 0; i < record_count; ++i) {
    const int64_t multiplicity = multiplicities[i];
    total_cycle_lines += multiplicity;
    const size_t begin = static_cast<size_t>(active_offsets[i]);
    const size_t end = static_cast<size_t>(active_offsets[i + 1]);
    if (end < begin) {
      return 0;
    }
    const size_t active_size = end - begin;

    const int64_t domain_size =
        seed_count > 0 ? static_cast<int64_t>(seed_count) : thread_rand_max;
    if (domain_size <= 0) {
      return 0;
    }
    if (seed_domain_size == 0) {
      seed_domain_size = domain_size;
    } else if (seed_domain_size != domain_size) {
      return 0;
    }

    if (active_size == 0) {
      inactive_base_mass += multiplicity * domain_size;
      continue;
    }

    if (seed_count > 0) {
      std::unordered_map<size_t, int64_t> slot_counts;
      slot_counts.reserve(std::min(seed_count, active_size));
      for (size_t s = 0; s < seed_count; ++s) {
        const size_t slot =
            static_cast<size_t>(seed_values[s] % static_cast<int64_t>(active_size));
        slot_counts[slot] += 1;
      }
      for (const auto &entry : slot_counts) {
        const size_t slot = entry.first;
        const int64_t count = entry.second;
        if (count <= 0) continue;
        const int64_t tid = active_thread_ids[begin + slot];
        weights[{tid, cycles[i]}] += multiplicity * count;
      }
      continue;
    }

    const int64_t q = thread_rand_max / static_cast<int64_t>(active_size);
    const int64_t r = thread_rand_max % static_cast<int64_t>(active_size);
    for (size_t slot = 0; slot < active_size; ++slot) {
      const int64_t count = q + (static_cast<int64_t>(slot) < r ? 1 : 0);
      if (count <= 0) continue;
      const int64_t tid = active_thread_ids[begin + slot];
      weights[{tid, cycles[i]}] += multiplicity * count;
    }
  }

  const int64_t active_base_mass = total_cycle_lines * seed_domain_size - inactive_base_mass;
  *seed_domain_size_out = seed_domain_size;
  *inactive_base_mass_out = inactive_base_mass;
  *active_base_mass_out = active_base_mass;

  if (weights.size() > out_capacity) {
    return 0;
  }
  std::vector<ExactThreadCycleWeightEntry> entries;
  entries.reserve(weights.size());
  for (const auto &entry : weights) {
    entries.push_back(
        ExactThreadCycleWeightEntry{entry.first.tid, entry.first.cycle, entry.second});
  }
  std::sort(entries.begin(), entries.end(),
            [](const ExactThreadCycleWeightEntry &a,
               const ExactThreadCycleWeightEntry &b) {
              if (a.thread_id != b.thread_id) return a.thread_id < b.thread_id;
              return a.cycle < b.cycle;
            });
  for (size_t i = 0; i < entries.size(); ++i) {
    out_entries[i] = entries[i];
  }
  return entries.size();
}

extern "C" size_t exact_evaluate_tolerance_paths_many(
    const ExactToleranceStepDesc *steps,
    size_t step_count,
    const uint64_t *src_vals,
    size_t src_val_count,
    const ExactTolerancePathDesc *paths,
    size_t path_count,
    const ExactToleranceEvalRequest *requests,
    size_t request_count,
    ExactToleranceEvalResponse *responses) {
  if (paths == nullptr || requests == nullptr || responses == nullptr) {
    return 0;
  }
  if ((step_count > 0 && steps == nullptr) ||
      (src_val_count > 0 && src_vals == nullptr)) {
    return 0;
  }

  size_t completed = 0;
  for (size_t req_i = 0; req_i < request_count; ++req_i) {
    ExactToleranceEvalResponse *response = &responses[req_i];
    clear_tolerance_eval_response(response, 0);

    const size_t path_index = static_cast<size_t>(requests[req_i].path_index);
    if (path_index >= path_count) {
      clear_tolerance_eval_response(response, -2);
      ++completed;
      continue;
    }

    const ExactTolerancePathDesc &path = paths[path_index];
    if (path.final_width_bits <= 0 || path.final_width_bits > 64) {
      clear_tolerance_eval_response(response, -3);
      ++completed;
      continue;
    }
    const size_t step_begin = static_cast<size_t>(path.step_offset);
    const size_t path_steps = static_cast<size_t>(path.step_count);
    if (step_begin > step_count || path_steps > (step_count - step_begin)) {
      clear_tolerance_eval_response(response, -4);
      ++completed;
      continue;
    }

    uint64_t value = requests[req_i].current_value;
    bool ok = true;
    for (size_t j = 0; j < path_steps; ++j) {
      const ExactToleranceStepDesc &step = steps[step_begin + j];
      Op op;
      if (!decode_op(step.op_code, &op)) {
        clear_tolerance_eval_response(response, -5);
        ok = false;
        break;
      }
      if (step.width_bits_default <= 0 || step.width_bits_default > 64) {
        clear_tolerance_eval_response(response, -6);
        ok = false;
        break;
      }
      const size_t vals_begin = static_cast<size_t>(step.src_val_offset);
      const size_t vals_count = static_cast<size_t>(step.src_val_count);
      if (vals_begin > src_val_count || vals_count > (src_val_count - vals_begin)) {
        clear_tolerance_eval_response(response, -7);
        ok = false;
        break;
      }
      if (static_cast<int>(vals_count) != expected_src_count(op)) {
        clear_tolerance_eval_response(response, -8);
        ok = false;
        break;
      }
      if (step.tracked_src_index < 0 ||
          static_cast<size_t>(step.tracked_src_index) >= vals_count) {
        clear_tolerance_eval_response(response, -9);
        ok = false;
        break;
      }

      std::vector<uint64_t> vals;
      vals.reserve(vals_count);
      for (size_t k = 0; k < vals_count; ++k) {
        vals.push_back(src_vals[vals_begin + k]);
      }
      vals[static_cast<size_t>(step.tracked_src_index)] = value;

      OpMeta meta;
      meta.width_bits = step.width_bits_default;
      meta.signed_mode = false;
      const int dst_width = evaluate_op_dst_width_bits(op, meta);
      value = evaluate_op(op, vals, meta) & width_mask(dst_width);
    }

    if (ok) {
      response->status = 0;
      response->final_bits = value & width_mask(path.final_width_bits);
    }
    ++completed;
  }
  return completed;
}

extern "C" int exact_rf_interval_accumulate_many(
    const ExactRfIntervalRequest *requests,
    size_t request_count,
    ExactRfIntervalAccum *out) {
  if (requests == nullptr || out == nullptr) {
    return -1;
  }

  *out = ExactRfIntervalAccum{};
  for (size_t i = 0; i < request_count; ++i) {
    const ExactRfIntervalRequest &req = requests[i];
    const int64_t mass = req.mass;
    if (mass <= 0) continue;
    const int64_t bit_count = req.bit_count;
    const uint64_t selected = req.selected_mask;

    const uint64_t due_mask = req.due_mask & UINT64_MAX;
    const uint64_t sdc_mask = req.sdc_mask & UINT64_MAX;
    const uint64_t unknown_mask = req.unknown_mask & UINT64_MAX;
    const uint64_t trace_added_sdc_mask =
        req.trace_added_sdc_mask & sdc_mask & UINT64_MAX;
    const uint64_t trace_policy_used_mask =
        req.trace_policy_used_mask & UINT64_MAX;
    const uint64_t trace_policy_override_mask =
        req.trace_policy_override_mask & UINT64_MAX;
    const uint64_t trace_mask = req.trace_mask & UINT64_MAX;
    const uint64_t semantic_due_mask = req.semantic_due_mask & UINT64_MAX;
    const uint64_t addr_due_mask = req.addr_due_mask & UINT64_MAX;
    const uint64_t addr_sdc_mask = req.addr_sdc_mask & UINT64_MAX;
    const uint64_t addr_unknown_mask = req.addr_unknown_mask & UINT64_MAX;
    const uint64_t addr_trace_div_mask = req.addr_trace_div_mask & UINT64_MAX;

    int64_t due_bits =
        static_cast<int64_t>(__builtin_popcountll(due_mask & selected));
    int64_t sdc_bits =
        static_cast<int64_t>(__builtin_popcountll(sdc_mask & selected));
    const int64_t unknown_bits =
        static_cast<int64_t>(__builtin_popcountll(unknown_mask & selected));
    const int64_t trace_added_sdc_bits = static_cast<int64_t>(
        __builtin_popcountll(trace_added_sdc_mask & selected));
    const int64_t trace_policy_used_bits = static_cast<int64_t>(
        __builtin_popcountll(trace_policy_used_mask & selected));
    const int64_t trace_policy_override_bits = static_cast<int64_t>(
        __builtin_popcountll(trace_policy_override_mask & selected));
    const int64_t trace_policy_override_sdc_bits = static_cast<int64_t>(
        __builtin_popcountll((trace_policy_override_mask & sdc_mask) & selected));
    const int64_t trace_policy_override_due_bits = static_cast<int64_t>(
        __builtin_popcountll((trace_policy_override_mask & due_mask) & selected));
    const int64_t trace_policy_override_unknown_bits = static_cast<int64_t>(
        __builtin_popcountll((trace_policy_override_mask & unknown_mask) &
                             selected));
    const int64_t trace_policy_override_masked_bits =
        std::max<int64_t>(0, trace_policy_override_bits -
                                 trace_policy_override_sdc_bits -
                                 trace_policy_override_due_bits -
                                 trace_policy_override_unknown_bits);
    const int64_t trace_selected_bits =
        static_cast<int64_t>(__builtin_popcountll(trace_mask & selected));
    const int64_t semantic_due_bits =
        static_cast<int64_t>(__builtin_popcountll(semantic_due_mask & selected));

    const uint64_t addr_trace_div_due_mask =
        addr_trace_div_mask & addr_due_mask & UINT64_MAX;
    const uint64_t addr_trace_div_sdc_mask =
        addr_trace_div_mask & addr_sdc_mask & UINT64_MAX;
    const uint64_t addr_oob_due_mask =
        addr_due_mask & (~addr_trace_div_due_mask) & UINT64_MAX;
    const uint64_t addr_alias_sdc_mask =
        addr_sdc_mask & (~addr_trace_div_sdc_mask) & UINT64_MAX;
    const int64_t addr_due_bits =
        static_cast<int64_t>(__builtin_popcountll(addr_due_mask & selected));
    const int64_t addr_sdc_bits =
        static_cast<int64_t>(__builtin_popcountll(addr_sdc_mask & selected));
    const int64_t addr_unknown_bits = static_cast<int64_t>(
        __builtin_popcountll((addr_unknown_mask & unknown_mask) & selected));
    const int64_t addr_oob_due_bits =
        static_cast<int64_t>(__builtin_popcountll(addr_oob_due_mask & selected));
    const int64_t addr_trace_div_due_bits = static_cast<int64_t>(
        __builtin_popcountll(addr_trace_div_due_mask & selected));
    const int64_t addr_alias_sdc_bits = static_cast<int64_t>(
        __builtin_popcountll(addr_alias_sdc_mask & selected));
    const int64_t addr_trace_div_sdc_bits = static_cast<int64_t>(
        __builtin_popcountll(addr_trace_div_sdc_mask & selected));

    int64_t masked_bits = bit_count - due_bits - sdc_bits - unknown_bits;


    out->masked_num += mass * masked_bits;
    out->sdc_num += mass * sdc_bits;
    out->due_num += mass * due_bits;
    out->unknown_num += mass * unknown_bits;
    out->semantic_due_mass += mass * semantic_due_bits;
    out->addr_due_num += mass * addr_due_bits;
    out->addr_sdc_num += mass * addr_sdc_bits;
    out->addr_unknown_num += mass * addr_unknown_bits;
    out->addr_oob_due_mass += mass * addr_oob_due_bits;
    out->trace_divergence_due_mass += mass * addr_trace_div_due_bits;
    out->addr_alias_sdc_mass += mass * addr_alias_sdc_bits;
    out->trace_divergence_sdc_mass += mass * addr_trace_div_sdc_bits;
    out->trace_expanding_sdc_numerator += mass * trace_added_sdc_bits;
    out->trace_policy_used_bits += trace_policy_used_bits;
    out->trace_policy_used_mass += mass * trace_policy_used_bits;
    out->trace_policy_override_bits += trace_policy_override_bits;
    out->trace_policy_override_mass += mass * trace_policy_override_bits;
    out->trace_policy_override_sdc_bits += trace_policy_override_sdc_bits;
    out->trace_policy_override_due_bits += trace_policy_override_due_bits;
    out->trace_policy_override_unknown_bits += trace_policy_override_unknown_bits;
    out->trace_policy_override_masked_bits += trace_policy_override_masked_bits;
    if (req.legacy_unknown_trace_uncovered != 0) {
      out->trace_uncovered_unknown_bits += trace_policy_used_bits;
      out->trace_uncovered_unknown_mass += mass * trace_policy_used_bits;
    }
    if (trace_selected_bits > 0) {
      out->saw_trace_selected_bits = 1;
    }
  }
  return 0;
}
