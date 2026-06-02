#include "analysis/ptx_influence.h"

#include <cassert>
#include <cmath>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <limits>
#include <vector>

namespace {

uint64_t width_mask(int width_bits) {
  if (width_bits >= 64) {
    return ~0ULL;
  }
  return (1ULL << width_bits) - 1ULL;
}

uint64_t mask_value(uint64_t value, int width_bits) {
  return value & width_mask(width_bits);
}

float bits_to_f32_u32(uint64_t value) {
  const uint32_t bits = static_cast<uint32_t>(value & 0xFFFFFFFFULL);
  float out = 0.0f;
  std::memcpy(&out, &bits, sizeof(out));
  return out;
}

uint32_t f32_to_bits_u32(float value) {
  uint32_t bits = 0;
  std::memcpy(&bits, &value, sizeof(bits));
  return bits;
}

float as_f32(float value) {
  return bits_to_f32_u32(f32_to_bits_u32(value));
}

float flush_subnormal_f32(float value) {
  if (value == 0.0f || std::isnan(value) || std::isinf(value)) {
    return value;
  }
  if (std::fabs(value) < std::ldexp(1.0f, -126)) {
    return std::copysign(0.0f, value);
  }
  return value;
}

float fmin_f32(float a, float b) {
  if (std::isnan(a)) {
    return b;
  }
  if (std::isnan(b)) {
    return a;
  }
  if (a == b) {
    if (a == 0.0f) {
      if (std::signbit(a) || std::signbit(b)) {
        return -0.0f;
      }
      return 0.0f;
    }
    return a;
  }
  return (a < b) ? a : b;
}

float fmax_f32(float a, float b) {
  if (std::isnan(a)) {
    return b;
  }
  if (std::isnan(b)) {
    return a;
  }
  if (a == b) {
    if (a == 0.0f) {
      if (!std::signbit(a) || !std::signbit(b)) {
        return 0.0f;
      }
      return -0.0f;
    }
    return a;
  }
  return (a > b) ? a : b;
}

int64_t signed_value(uint64_t value, int width_bits) {
  if (width_bits >= 64) {
    return static_cast<int64_t>(value);
  }
  int32_t v32 = static_cast<int32_t>(value & 0xFFFFFFFFULL);
  return static_cast<int64_t>(v32);
}

size_t expected_src_count(Op op) {
  switch (op) {
    case Op::MAD:
    case Op::SELP:
    case Op::FMA_F32:
      return 3;
    case Op::CVT_U32_U64:
    case Op::CVT_U64_U32:
    case Op::CVT_S32_S64:
    case Op::CVT_S64_S32:
    case Op::CVT_SAT_F32_F32:
    case Op::NEG:
    case Op::NEG_F32:
    case Op::NOT:
    case Op::NOT_PRED:
    case Op::IDENTITY:
    case Op::SQRT_F32:
    case Op::ABS_F32:
    case Op::EX2_APPROX_FTZ_F32:
    case Op::RCP_APPROX_FTZ_F32:
      return 1;
    default:
      return 2;
  }
}

int dst_width_bits(Op op, const OpMeta &meta) {
  switch (op) {
    case Op::NOT_PRED:
    case Op::SETP_EQ:
    case Op::SETP_NE:
    case Op::SETP_LT_U:
    case Op::SETP_LT_S:
    case Op::SETP_LE_U:
    case Op::SETP_LE_S:
    case Op::SETP_GT_U:
    case Op::SETP_GT_S:
    case Op::SETP_GE_U:
    case Op::SETP_GE_S:
      return 1;
    case Op::CVT_U32_U64:
    case Op::CVT_S32_S64:
    case Op::MUL_WIDE_U32:
    case Op::MUL_WIDE_S32:
      return 64;
    case Op::CVT_U64_U32:
    case Op::CVT_S64_S32:
      return 32;
    case Op::CVT_SAT_F32_F32:
      return 32;
    default:
      return meta.width_bits;
  }
}

int src_width_bits(Op op, const OpMeta &meta, size_t index) {
  switch (op) {
    case Op::CVT_U32_U64:
    case Op::CVT_S32_S64:
    case Op::MUL_WIDE_U32:
    case Op::MUL_WIDE_S32:
      return 32;
    case Op::CVT_U64_U32:
    case Op::CVT_S64_S32:
      return 64;
    case Op::CVT_SAT_F32_F32:
      return 32;
    case Op::SELP:
      if (index == 2) {
        return 1;
      }
      return meta.width_bits;
    default:
      return meta.width_bits;
  }
}

uint64_t eval_op(Op op, const std::vector<uint64_t> &src_vals,
                 const OpMeta &meta) {
  switch (op) {
    case Op::ADD: {
      int width = meta.width_bits;
      uint64_t a = mask_value(src_vals[0], width);
      uint64_t b = mask_value(src_vals[1], width);
      return mask_value(a + b, width);
    }
    case Op::ADD_F32: {
      const float a = bits_to_f32_u32(src_vals[0]);
      const float b = bits_to_f32_u32(src_vals[1]);
      return static_cast<uint64_t>(f32_to_bits_u32(as_f32(a + b)));
    }
    case Op::SUB: {
      int width = meta.width_bits;
      uint64_t a = mask_value(src_vals[0], width);
      uint64_t b = mask_value(src_vals[1], width);
      return mask_value(a - b, width);
    }
    case Op::SUB_F32: {
      const float a = bits_to_f32_u32(src_vals[0]);
      const float b = bits_to_f32_u32(src_vals[1]);
      return static_cast<uint64_t>(f32_to_bits_u32(as_f32(a - b)));
    }
    case Op::NEG: {
      int width = meta.width_bits;
      return mask_value(static_cast<uint64_t>(-static_cast<int64_t>(mask_value(src_vals[0], width))), width);
    }
    case Op::NEG_F32: {
      const float a = bits_to_f32_u32(src_vals[0]);
      return static_cast<uint64_t>(f32_to_bits_u32(as_f32(-a)));
    }
    case Op::MUL_LO: {
      int width = meta.width_bits;
      uint64_t a = mask_value(src_vals[0], width);
      uint64_t b = mask_value(src_vals[1], width);
      unsigned __int128 prod = static_cast<unsigned __int128>(a) *
                               static_cast<unsigned __int128>(b);
      return mask_value(static_cast<uint64_t>(prod), width);
    }
    case Op::MUL_F32: {
      const float a = bits_to_f32_u32(src_vals[0]);
      const float b = bits_to_f32_u32(src_vals[1]);
      return static_cast<uint64_t>(f32_to_bits_u32(as_f32(a * b)));
    }
    case Op::MUL_WIDE_U32: {
      const uint64_t a = src_vals[0] & 0xFFFFFFFFULL;
      const uint64_t b = src_vals[1] & 0xFFFFFFFFULL;
      return static_cast<uint64_t>((a * b) & UINT64_C(0xFFFFFFFFFFFFFFFF));
    }
    case Op::MUL_WIDE_S32: {
      const int64_t a = static_cast<int64_t>(static_cast<int32_t>(src_vals[0] & 0xFFFFFFFFULL));
      const int64_t b = static_cast<int64_t>(static_cast<int32_t>(src_vals[1] & 0xFFFFFFFFULL));
      return static_cast<uint64_t>(a * b);
    }
    case Op::MAD: {
      int width = meta.width_bits;
      uint64_t a = mask_value(src_vals[0], width);
      uint64_t b = mask_value(src_vals[1], width);
      uint64_t c = mask_value(src_vals[2], width);
      unsigned __int128 prod = static_cast<unsigned __int128>(a) *
                               static_cast<unsigned __int128>(b);
      unsigned __int128 sum = prod + static_cast<unsigned __int128>(c);
      return mask_value(static_cast<uint64_t>(sum), width);
    }
    case Op::FMA_F32: {
      const float a = bits_to_f32_u32(src_vals[0]);
      const float b = bits_to_f32_u32(src_vals[1]);
      const float c = bits_to_f32_u32(src_vals[2]);
      return static_cast<uint64_t>(f32_to_bits_u32(as_f32(std::fma(a, b, c))));
    }
    case Op::DIV_F32: {
      const float a = bits_to_f32_u32(src_vals[0]);
      const float b = bits_to_f32_u32(src_vals[1]);
      float out = 0.0f;
      if (std::isnan(a) || std::isnan(b)) {
        out = std::numeric_limits<float>::quiet_NaN();
      } else if (a == 0.0f && b == 0.0f) {
        out = std::numeric_limits<float>::quiet_NaN();
      } else if (std::isinf(a) && std::isinf(b)) {
        out = std::numeric_limits<float>::quiet_NaN();
      } else if (b == 0.0f) {
        out = std::copysign(std::numeric_limits<float>::infinity(), a * b);
      } else {
        out = a / b;
      }
      return static_cast<uint64_t>(f32_to_bits_u32(as_f32(out)));
    }
    case Op::SQRT_F32: {
      const float a = bits_to_f32_u32(src_vals[0]);
      float out = 0.0f;
      if (std::isnan(a) || a < 0.0f) {
        out = std::numeric_limits<float>::quiet_NaN();
      } else {
        out = std::sqrt(a);
      }
      return static_cast<uint64_t>(f32_to_bits_u32(as_f32(out)));
    }
    case Op::ABS_F32: {
      const float a = bits_to_f32_u32(src_vals[0]);
      return static_cast<uint64_t>(f32_to_bits_u32(as_f32(std::fabs(a))));
    }
    case Op::EX2_APPROX_FTZ_F32: {
      const float a = bits_to_f32_u32(src_vals[0]);
      float out = 0.0f;
      try {
        out = std::pow(2.0f, a);
      } catch (...) {
        out = std::numeric_limits<float>::infinity();
      }
      return static_cast<uint64_t>(f32_to_bits_u32(as_f32(flush_subnormal_f32(out))));
    }
    case Op::RCP_APPROX_FTZ_F32: {
      const float a = bits_to_f32_u32(src_vals[0]);
      float out = 0.0f;
      if (a == 0.0f) {
        out = std::copysign(std::numeric_limits<float>::infinity(), a);
      } else {
        out = 1.0f / a;
      }
      return static_cast<uint64_t>(f32_to_bits_u32(as_f32(flush_subnormal_f32(out))));
    }
    case Op::MIN_F32: {
      const float a = bits_to_f32_u32(src_vals[0]);
      const float b = bits_to_f32_u32(src_vals[1]);
      return static_cast<uint64_t>(f32_to_bits_u32(as_f32(fmin_f32(a, b))));
    }
    case Op::MAX_F32: {
      const float a = bits_to_f32_u32(src_vals[0]);
      const float b = bits_to_f32_u32(src_vals[1]);
      return static_cast<uint64_t>(f32_to_bits_u32(as_f32(fmax_f32(a, b))));
    }
    case Op::IDENTITY: {
      int width = meta.width_bits;
      return mask_value(src_vals[0], width);
    }
    case Op::NOT: {
      int width = meta.width_bits;
      return mask_value(~src_vals[0], width);
    }
    case Op::NOT_PRED: {
      return (src_vals[0] & 1ULL) ? 0ULL : 1ULL;
    }
    case Op::AND: {
      int width = meta.width_bits;
      uint64_t a = mask_value(src_vals[0], width);
      uint64_t b = mask_value(src_vals[1], width);
      return mask_value(a & b, width);
    }
    case Op::OR: {
      int width = meta.width_bits;
      uint64_t a = mask_value(src_vals[0], width);
      uint64_t b = mask_value(src_vals[1], width);
      return mask_value(a | b, width);
    }
    case Op::XOR: {
      int width = meta.width_bits;
      uint64_t a = mask_value(src_vals[0], width);
      uint64_t b = mask_value(src_vals[1], width);
      return mask_value(a ^ b, width);
    }
    case Op::SHL: {
      int width = meta.width_bits;
      uint64_t a = mask_value(src_vals[0], width);
      uint64_t sh = mask_value(src_vals[1], width) & (width - 1);
      return mask_value(a << sh, width);
    }
    case Op::SHR_U: {
      int width = meta.width_bits;
      uint64_t a = mask_value(src_vals[0], width);
      uint64_t sh = mask_value(src_vals[1], width) & (width - 1);
      return mask_value(a >> sh, width);
    }
    case Op::SHR_S: {
      int width = meta.width_bits;
      uint64_t a = mask_value(src_vals[0], width);
      uint64_t sh = mask_value(src_vals[1], width) & (width - 1);
      if (width == 32) {
        int32_t sa = static_cast<int32_t>(a);
        uint32_t res = static_cast<uint32_t>(sa >> sh);
        return static_cast<uint64_t>(res);
      }
      int64_t sa = static_cast<int64_t>(a);
      uint64_t res = static_cast<uint64_t>(sa >> sh);
      return res;
    }
    case Op::MIN_U: {
      int width = meta.width_bits;
      uint64_t a = mask_value(src_vals[0], width);
      uint64_t b = mask_value(src_vals[1], width);
      return (a < b) ? a : b;
    }
    case Op::MIN_S: {
      int width = meta.width_bits;
      int64_t a = signed_value(src_vals[0], width);
      int64_t b = signed_value(src_vals[1], width);
      int64_t res = (a < b) ? a : b;
      return mask_value(static_cast<uint64_t>(res), width);
    }
    case Op::MAX_U: {
      int width = meta.width_bits;
      uint64_t a = mask_value(src_vals[0], width);
      uint64_t b = mask_value(src_vals[1], width);
      return (a > b) ? a : b;
    }
    case Op::MAX_S: {
      int width = meta.width_bits;
      int64_t a = signed_value(src_vals[0], width);
      int64_t b = signed_value(src_vals[1], width);
      int64_t res = (a > b) ? a : b;
      return mask_value(static_cast<uint64_t>(res), width);
    }
    case Op::CVT_U32_U64: {
      uint32_t x = static_cast<uint32_t>(src_vals[0] & 0xFFFFFFFFULL);
      return static_cast<uint64_t>(x);
    }
    case Op::CVT_U64_U32: {
      uint64_t x = src_vals[0];
      return static_cast<uint64_t>(static_cast<uint32_t>(x));
    }
    case Op::CVT_S32_S64: {
      int32_t x = static_cast<int32_t>(src_vals[0] & 0xFFFFFFFFULL);
      return static_cast<uint64_t>(static_cast<int64_t>(x));
    }
    case Op::CVT_S64_S32: {
      int64_t x = static_cast<int64_t>(src_vals[0]);
      return static_cast<uint64_t>(static_cast<uint32_t>(x));
    }
    case Op::CVT_SAT_F32_F32: {
      const float x = bits_to_f32_u32(src_vals[0]);
      if (std::isnan(x)) {
        return 0x7fffffffULL;
      }
      const float clamped = std::min(1.0f, std::max(0.0f, x));
      return static_cast<uint64_t>(f32_to_bits_u32(as_f32(clamped)));
    }
    case Op::SETP_EQ: {
      int width = meta.width_bits;
      uint64_t a = mask_value(src_vals[0], width);
      uint64_t b = mask_value(src_vals[1], width);
      return (a == b) ? 1ULL : 0ULL;
    }
    case Op::SETP_NE: {
      int width = meta.width_bits;
      uint64_t a = mask_value(src_vals[0], width);
      uint64_t b = mask_value(src_vals[1], width);
      return (a != b) ? 1ULL : 0ULL;
    }
    case Op::SETP_LT_U: {
      int width = meta.width_bits;
      uint64_t a = mask_value(src_vals[0], width);
      uint64_t b = mask_value(src_vals[1], width);
      return (a < b) ? 1ULL : 0ULL;
    }
    case Op::SETP_LT_S: {
      int width = meta.width_bits;
      int64_t a = signed_value(src_vals[0], width);
      int64_t b = signed_value(src_vals[1], width);
      return (a < b) ? 1ULL : 0ULL;
    }
    case Op::SETP_LE_U: {
      int width = meta.width_bits;
      uint64_t a = mask_value(src_vals[0], width);
      uint64_t b = mask_value(src_vals[1], width);
      return (a <= b) ? 1ULL : 0ULL;
    }
    case Op::SETP_LE_S: {
      int width = meta.width_bits;
      int64_t a = signed_value(src_vals[0], width);
      int64_t b = signed_value(src_vals[1], width);
      return (a <= b) ? 1ULL : 0ULL;
    }
    case Op::SETP_GT_U: {
      int width = meta.width_bits;
      uint64_t a = mask_value(src_vals[0], width);
      uint64_t b = mask_value(src_vals[1], width);
      return (a > b) ? 1ULL : 0ULL;
    }
    case Op::SETP_GT_S: {
      int width = meta.width_bits;
      int64_t a = signed_value(src_vals[0], width);
      int64_t b = signed_value(src_vals[1], width);
      return (a > b) ? 1ULL : 0ULL;
    }
    case Op::SETP_GE_U: {
      int width = meta.width_bits;
      uint64_t a = mask_value(src_vals[0], width);
      uint64_t b = mask_value(src_vals[1], width);
      return (a >= b) ? 1ULL : 0ULL;
    }
    case Op::SETP_GE_S: {
      int width = meta.width_bits;
      int64_t a = signed_value(src_vals[0], width);
      int64_t b = signed_value(src_vals[1], width);
      return (a >= b) ? 1ULL : 0ULL;
    }
    case Op::SELP: {
      int width = meta.width_bits;
      uint64_t a = mask_value(src_vals[0], width);
      uint64_t b = mask_value(src_vals[1], width);
      uint64_t pred = src_vals[2] & 1ULL;
      return pred ? a : b;
    }
    default:
      return 0ULL;
  }
}

}  // namespace

uint64_t evaluate_op(Op op, const std::vector<uint64_t> &src_vals,
                     const OpMeta &meta) {
  return eval_op(op, src_vals, meta);
}

int evaluate_op_dst_width_bits(Op op, const OpMeta &meta) {
  return dst_width_bits(op, meta);
}

InfluenceResult backward_influence(Op op, const std::vector<uint64_t> &src_vals,
                                   uint64_t dst_val,
                                   uint64_t dst_observed_mask,
                                   const OpMeta &meta) {
  const size_t expected = expected_src_count(op);
  assert(src_vals.size() == expected);

  InfluenceResult result;
  result.src_masks.assign(src_vals.size(), 0ULL);

  const int dst_width = dst_width_bits(op, meta);
  const uint64_t dst_mask = width_mask(dst_width);
  const uint64_t observed_mask = dst_observed_mask & dst_mask;
  const uint64_t base_dst = dst_val & dst_mask;

  if (observed_mask == 0ULL) {
    return result;
  }

  std::vector<uint64_t> mutated = src_vals;
  for (size_t k = 0; k < src_vals.size(); ++k) {
    const int swidth = src_width_bits(op, meta, k);
    for (int i = 0; i < swidth; ++i) {
      mutated[k] = src_vals[k] ^ (1ULL << i);
      uint64_t dst_prime = eval_op(op, mutated, meta) & dst_mask;
      if (((base_dst ^ dst_prime) & observed_mask) != 0ULL) {
        result.src_masks[k] |= (1ULL << i);
      }
    }
    mutated[k] = src_vals[k];
  }

  return result;
}
