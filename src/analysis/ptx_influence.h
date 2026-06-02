#ifndef PTX_INFLUENCE_H_
#define PTX_INFLUENCE_H_

#include <cstdint>
#include <vector>

enum class Op {
  ADD,
  ADD_F32,
  SUB,
  SUB_F32,
  NEG,
  NEG_F32,
  MUL_LO,
  MUL_F32,
  MUL_WIDE_U32,
  MUL_WIDE_S32,
  MAD,
  FMA_F32,
  DIV_F32,
  SQRT_F32,
  ABS_F32,
  EX2_APPROX_FTZ_F32,
  RCP_APPROX_FTZ_F32,
  MIN_F32,
  MAX_F32,
  IDENTITY,
  NOT,
  NOT_PRED,
  AND,
  OR,
  XOR,
  SHL,
  SHR_U,
  SHR_S,
  MIN_U,
  MIN_S,
  MAX_U,
  MAX_S,
  CVT_U32_U64,
  CVT_U64_U32,
  CVT_S32_S64,
  CVT_S64_S32,
  CVT_SAT_F32_F32,
  SETP_EQ,
  SETP_NE,
  SETP_LT_U,
  SETP_LT_S,
  SETP_LE_U,
  SETP_LE_S,
  SETP_GT_U,
  SETP_GT_S,
  SETP_GE_U,
  SETP_GE_S,
  SELP
};

struct OpMeta {
  int width_bits;   // 32 or 64
  bool signed_mode; // for compares/shifts/min/max where needed
};

struct InfluenceResult {
  std::vector<uint64_t> src_masks; // one per src operand
};

InfluenceResult backward_influence(Op op, const std::vector<uint64_t> &src_vals,
                                   uint64_t dst_val,
                                   uint64_t dst_observed_mask,
                                   const OpMeta &meta);

uint64_t evaluate_op(Op op, const std::vector<uint64_t> &src_vals,
                     const OpMeta &meta);

int evaluate_op_dst_width_bits(Op op, const OpMeta &meta);

#endif  // PTX_INFLUENCE_H_
