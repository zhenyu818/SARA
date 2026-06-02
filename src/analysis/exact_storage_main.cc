#include "analysis/ptx_influence.h"

#include <stdint.h>

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

void print_usage(std::ostream &os) {
  os << "Usage:\n"
     << "  exact_storage_core --help\n"
     << "  exact_storage_core --version\n"
     << "  exact_storage_core --selftest\n"
     << "  exact_storage_core backward-influence --op <OP> --width <bits>"
        " --dst-val <value> --dst-mask <mask> --src <value> [--src <value> ...]\n";
}

bool parse_i64(const std::string &text, int64_t *out) {
  if (out == nullptr) {
    return false;
  }
  char *end = nullptr;
  const long long value = std::strtoll(text.c_str(), &end, 0);
  if (end == nullptr || *end != '\0') {
    return false;
  }
  *out = static_cast<int64_t>(value);
  return true;
}

bool parse_u64(const std::string &text, uint64_t *out) {
  if (out == nullptr) {
    return false;
  }
  char *end = nullptr;
  const unsigned long long value = std::strtoull(text.c_str(), &end, 0);
  if (end == nullptr || *end != '\0') {
    return false;
  }
  *out = static_cast<uint64_t>(value);
  return true;
}

bool decode_op(const std::string &name, Op *out) {
  if (out == nullptr) {
    return false;
  }
  if (name == "ADD") {
    *out = Op::ADD;
  } else if (name == "SUB") {
    *out = Op::SUB;
  } else if (name == "MUL_LO") {
    *out = Op::MUL_LO;
  } else if (name == "MAD") {
    *out = Op::MAD;
  } else if (name == "AND") {
    *out = Op::AND;
  } else if (name == "OR") {
    *out = Op::OR;
  } else if (name == "XOR") {
    *out = Op::XOR;
  } else if (name == "SHL") {
    *out = Op::SHL;
  } else if (name == "SHR_U") {
    *out = Op::SHR_U;
  } else if (name == "SHR_S") {
    *out = Op::SHR_S;
  } else if (name == "MIN_U") {
    *out = Op::MIN_U;
  } else if (name == "MIN_S") {
    *out = Op::MIN_S;
  } else if (name == "MAX_U") {
    *out = Op::MAX_U;
  } else if (name == "MAX_S") {
    *out = Op::MAX_S;
  } else if (name == "CVT_U32_U64") {
    *out = Op::CVT_U32_U64;
  } else if (name == "CVT_U64_U32") {
    *out = Op::CVT_U64_U32;
  } else if (name == "CVT_S32_S64") {
    *out = Op::CVT_S32_S64;
  } else if (name == "CVT_S64_S32") {
    *out = Op::CVT_S64_S32;
  } else if (name == "CVT_SAT_F32_F32") {
    *out = Op::CVT_SAT_F32_F32;
  } else if (name == "SETP_EQ") {
    *out = Op::SETP_EQ;
  } else if (name == "SETP_NE") {
    *out = Op::SETP_NE;
  } else if (name == "SETP_LT_U") {
    *out = Op::SETP_LT_U;
  } else if (name == "SETP_LT_S") {
    *out = Op::SETP_LT_S;
  } else if (name == "SETP_LE_U") {
    *out = Op::SETP_LE_U;
  } else if (name == "SETP_LE_S") {
    *out = Op::SETP_LE_S;
  } else if (name == "SELP") {
    *out = Op::SELP;
  } else {
    return false;
  }
  return true;
}

int expected_src_count(Op op) {
  switch (op) {
    case Op::MAD:
    case Op::SELP:
      return 3;
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

int run_selftest() {
  OpMeta meta;
  meta.width_bits = 32;
  meta.signed_mode = false;
  std::vector<uint64_t> src_vals;
  src_vals.push_back(7);
  src_vals.push_back(5);
  const InfluenceResult result = backward_influence(Op::ADD, src_vals, 12, 0x1, meta);
  if (result.src_masks.size() != 2) {
    std::cerr << "selftest failed: unexpected source count\n";
    return 1;
  }
  if (result.src_masks[0] == 0 || result.src_masks[1] == 0) {
    std::cerr << "selftest failed: ADD influence masks unexpectedly zero\n";
    return 1;
  }
  std::cout << "exact_storage_core selftest OK\n";
  return 0;
}

int run_backward_influence(int argc, char **argv) {
  std::string op_name;
  int width_bits = 0;
  uint64_t dst_val = 0;
  uint64_t dst_mask = 0;
  bool signed_mode = false;
  std::vector<uint64_t> src_vals;

  for (int i = 2; i < argc; ++i) {
    const std::string arg(argv[i]);
    if (arg == "--op" && i + 1 < argc) {
      op_name = argv[++i];
    } else if (arg == "--width" && i + 1 < argc) {
      int64_t parsed = 0;
      if (!parse_i64(argv[++i], &parsed)) {
        std::cerr << "invalid --width\n";
        return 2;
      }
      width_bits = static_cast<int>(parsed);
    } else if (arg == "--dst-val" && i + 1 < argc) {
      if (!parse_u64(argv[++i], &dst_val)) {
        std::cerr << "invalid --dst-val\n";
        return 2;
      }
    } else if (arg == "--dst-mask" && i + 1 < argc) {
      if (!parse_u64(argv[++i], &dst_mask)) {
        std::cerr << "invalid --dst-mask\n";
        return 2;
      }
    } else if (arg == "--src" && i + 1 < argc) {
      uint64_t value = 0;
      if (!parse_u64(argv[++i], &value)) {
        std::cerr << "invalid --src\n";
        return 2;
      }
      src_vals.push_back(value);
    } else if (arg == "--signed") {
      signed_mode = true;
    } else {
      std::cerr << "unknown argument: " << arg << "\n";
      return 2;
    }
  }

  Op op;
  if (!decode_op(op_name, &op)) {
    std::cerr << "unsupported --op value\n";
    return 2;
  }
  if (width_bits <= 0 || width_bits > 64) {
    std::cerr << "--width must be in [1, 64]\n";
    return 2;
  }
  if (static_cast<int>(src_vals.size()) != expected_src_count(op)) {
    std::cerr << "unexpected src count for op " << op_name << "\n";
    return 2;
  }

  OpMeta meta;
  meta.width_bits = width_bits;
  meta.signed_mode = signed_mode;
  const InfluenceResult result =
      backward_influence(op, src_vals, dst_val, dst_mask, meta);
  for (size_t i = 0; i < result.src_masks.size(); ++i) {
    std::cout << "src[" << i << "]=" << result.src_masks[i] << "\n";
  }
  return 0;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc <= 1) {
    print_usage(std::cerr);
    return 2;
  }

  const std::string cmd(argv[1]);
  if (cmd == "--help" || cmd == "help") {
    print_usage(std::cout);
    return 0;
  }
  if (cmd == "--version") {
    std::cout << "exact_storage_core dev\n";
    return 0;
  }
  if (cmd == "--selftest") {
    return run_selftest();
  }
  if (cmd == "backward-influence") {
    return run_backward_influence(argc, argv);
  }

  std::cerr << "unknown command: " << cmd << "\n";
  print_usage(std::cerr);
  return 2;
}
