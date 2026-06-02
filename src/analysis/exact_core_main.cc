#include "analysis/ptx_influence.h"

#include <stdint.h>

#include <cstdlib>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace {

using json = nlohmann::json;

constexpr const char *kClassKeys[] = {"masked", "sdc", "due", "unknown"};
constexpr const char *kStorageComponents[] = {"rf", "smem_rf", "l1d", "l2"};

struct Classification {
  double den = 0.0;
  std::map<std::string, double> counts;
  std::map<std::string, double> rates;
};

struct RowPayload {
  json raw;
  Classification cls;
};

std::string escape_csv(const std::string &value);

void print_usage(std::ostream &os) {
  os << "Usage:\n"
     << "  exact_core --help\n"
     << "  exact_core --version\n"
     << "  exact_core --selftest\n"
     << "  exact_core backward-influence --op <OP> --width <bits> --dst-val <value>"
        " --dst-mask <mask> --src <value> [--src <value> ...]\n"
     << "  exact_core rates-summary --input <json> [--benchmark <name>] [--test-id <id>]"
        " [--output-json <path>]\n"
     << "  exact_core summary-status --input <summary-json>\n"
     << "  exact_core rates-simple-summary-csv --input <txt> --output <csv>\n"
     << "  exact_core rates-compare --expected <json> --measured <json>"
        " [--tolerance <float>]\n"
     << "  exact_core rates-merge-csv --summary <json> [<json> ...] --output <csv> (SARA outcome CSV)\n"
     << "  exact_core rates-merge-components-csv --rf-summary <json>"
        " --smem-rf-summary <json> --l1d-summary <json> --l2-summary <json> --output <csv>\n";
}

std::string read_text(const std::string &path) {
  std::ifstream in(path.c_str(), std::ios::in | std::ios::binary);
  if (!in) {
    throw std::runtime_error("failed to open " + path);
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

json load_json(const std::string &path) {
  return json::parse(read_text(path));
}

void write_text(const std::string &path, const std::string &text) {
  std::ofstream out(path.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);
  if (!out) {
    throw std::runtime_error("failed to write " + path);
  }
  out << text;
}

double to_number(const json &value, double fallback = 0.0) {
  if (value.is_number()) {
    return value.get<double>();
  }
  if (value.is_string()) {
    const std::string s = value.get<std::string>();
    if (s.empty()) {
      return fallback;
    }
    char *end = nullptr;
    const double parsed = std::strtod(s.c_str(), &end);
    if (end != nullptr && *end == '\0') {
      return parsed;
    }
  }
  return fallback;
}

std::string to_string_value(const json &value) {
  if (value.is_string()) {
    return value.get<std::string>();
  }
  if (value.is_number_integer()) {
    return std::to_string(value.get<long long>());
  }
  if (value.is_number_unsigned()) {
    return std::to_string(value.get<unsigned long long>());
  }
  if (value.is_number_float()) {
    std::ostringstream oss;
    oss << std::setprecision(12) << value.get<double>();
    return oss.str();
  }
  if (value.is_boolean()) {
    return value.get<bool>() ? "1" : "0";
  }
  return "";
}

double fraction_to_float(const json &value) {
  if (!value.is_object()) {
    return to_number(value, 0.0);
  }
  if (value.contains("value")) {
    return to_number(value.at("value"), 0.0);
  }
  const double den = to_number(value.value("denominator", json(0)), 0.0);
  if (den == 0.0) {
    return 0.0;
  }
  return to_number(value.value("numerator", json(0)), 0.0) / den;
}

std::string format_rate(double value) {
  std::ostringstream oss;
  oss << std::fixed << std::setprecision(12) << value;
  return oss.str();
}

std::string format_scalar(double value) {
  const double rounded = std::llround(value);
  if (std::abs(value - rounded) <= 1e-12) {
    return std::to_string(static_cast<long long>(rounded));
  }
  std::ostringstream oss;
  oss << std::setprecision(12) << value;
  return oss.str();
}

Classification normalized_classification(const json &counts_raw,
                                         const json &rates_raw,
                                         double den_hint) {
  Classification out;
  out.den = 0.0;
  if (counts_raw.is_object()) {
    out.den = to_number(counts_raw.value("total", json(0)), 0.0);
  }
  if (out.den <= 0.0) {
    out.den = den_hint;
  }

  bool have_any_count = false;
  for (const char *key : kClassKeys) {
    double value = 0.0;
    if (counts_raw.is_object() && counts_raw.contains(key)) {
      value = to_number(counts_raw.at(key), 0.0);
      have_any_count = true;
    }
    out.counts[key] = value;
  }

  if (have_any_count && out.den > 0.0) {
    const bool raw_unknown_present = counts_raw.is_object() && counts_raw.contains("unknown");
    if (!raw_unknown_present) {
      const double known_total =
          out.counts["masked"] + out.counts["sdc"] + out.counts["due"];
      out.counts["unknown"] = std::max(0.0, out.den - known_total);
    }
    double assigned = 0.0;
    for (const char *key : kClassKeys) {
      assigned += out.counts[key];
    }
    if (std::abs(assigned - out.den) > 1e-9) {
      out.counts["unknown"] = std::max(0.0, out.counts["unknown"] + (out.den - assigned));
      assigned = 0.0;
      for (const char *key : kClassKeys) {
        assigned += out.counts[key];
      }
    }
    if (std::abs(assigned - out.den) > 1e-9) {
      out.counts["masked"] = std::max(0.0, out.counts["masked"] + (out.den - assigned));
    }
    for (const char *key : kClassKeys) {
      out.rates[key] = out.den > 0.0 ? out.counts[key] / out.den : 0.0;
    }
    return out;
  }

  for (const char *key : kClassKeys) {
    double rate = 0.0;
    if (rates_raw.is_object() && rates_raw.contains(key)) {
      rate = to_number(rates_raw.at(key), 0.0);
    }
    out.rates[key] = rate;
    out.counts[key] = out.den > 0.0 ? (rate * out.den) : 0.0;
  }
  return out;
}

std::map<std::string, double> rates_from_payload(const json &data) {
  if (data.is_object() && data.contains("classification_counts") &&
      data.at("classification_counts").is_object()) {
    Classification cls = normalized_classification(
        data.at("classification_counts"),
        data.value("classification_rates", json::object()),
        to_number(data.at("classification_counts").value("total", json(0)), 0.0));
    return cls.rates;
  }
  if (data.is_object() && data.contains("classification_rates") &&
      data.at("classification_rates").is_object()) {
    std::map<std::string, double> rates;
    for (const char *key : kClassKeys) {
      rates[key] = to_number(data.at("classification_rates").value(key, json(0)), 0.0);
    }
    return rates;
  }
  if (data.is_object() && data.contains("weighted_classification_rates") &&
      data.at("weighted_classification_rates").is_object()) {
    std::map<std::string, double> rates;
    for (const char *key : kClassKeys) {
      rates[key] = fraction_to_float(data.at("weighted_classification_rates").value(key, json(0)));
    }
    return rates;
  }
  std::map<std::string, double> rates;
  for (const char *key : kClassKeys) {
    rates[key] = data.is_object() ? to_number(data.value(key, json(0)), 0.0) : 0.0;
  }
  return rates;
}

json component_payload(const json &summary_json, const std::string &component) {
  const json counts_raw =
      summary_json.is_object() ? summary_json.value("classification_counts", json::object())
                               : json::object();
  const json rates_raw =
      summary_json.is_object() ? summary_json.value("classification_rates", json::object())
                               : json::object();
  const json summary_raw =
      summary_json.is_object() ? summary_json.value("summary", json::object()) : json::object();
  if (component == "rf") {
    return json{
        {"den", counts_raw.is_object() ? counts_raw.value("total", json(0)) : json(0)},
        {"masked", counts_raw.is_object() ? counts_raw.value("masked", json(0)) : json(0)},
        {"sdc", counts_raw.is_object() ? counts_raw.value("sdc", json(0)) : json(0)},
        {"due", counts_raw.is_object() ? counts_raw.value("due", json(0)) : json(0)},
        {"unknown", counts_raw.is_object() ? counts_raw.value("unknown", json(0)) : json(0)},
        {"rate", rates_raw.is_object() ? rates_raw : json::object()},
    };
  }
  if (!summary_raw.is_object()) {
    return json{
        {"den", counts_raw.is_object() ? counts_raw.value("total", json(0)) : json(0)},
        {"masked", counts_raw.is_object() ? counts_raw.value("masked", json(0)) : json(0)},
        {"sdc", counts_raw.is_object() ? counts_raw.value("sdc", json(0)) : json(0)},
        {"due", counts_raw.is_object() ? counts_raw.value("due", json(0)) : json(0)},
        {"unknown", counts_raw.is_object() ? counts_raw.value("unknown", json(0)) : json(0)},
        {"rate", rates_raw.is_object() ? rates_raw : json::object()},
    };
  }
  if (component == "smem_rf") {
    const json shared = summary_raw.value("shared_memory", json::object());
    if (shared.is_object()) {
      const json row = shared.value("smem_rf", json::object());
      if (row.is_object()) return row;
    }
  }
  if (component == "smem_lds") {
    const json shared = summary_raw.value("shared_memory", json::object());
    if (shared.is_object()) {
      const json row = shared.value("smem_lds", json::object());
      if (row.is_object()) return row;
    }
  } else if (component == "l1d") {
    const json row = summary_raw.value("l1d_cache", json::object());
    if (row.is_object()) return row;
  } else if (component == "l2") {
    const json row = summary_raw.value("l2_cache", json::object());
    if (row.is_object()) return row;
  }
  return json{
      {"den", counts_raw.is_object() ? counts_raw.value("total", json(0)) : json(0)},
      {"masked", counts_raw.is_object() ? counts_raw.value("masked", json(0)) : json(0)},
      {"sdc", counts_raw.is_object() ? counts_raw.value("sdc", json(0)) : json(0)},
      {"due", counts_raw.is_object() ? counts_raw.value("due", json(0)) : json(0)},
      {"unknown", counts_raw.is_object() ? counts_raw.value("unknown", json(0)) : json(0)},
      {"rate", rates_raw.is_object() ? rates_raw : json::object()},
  };
}

RowPayload component_row(const json &summary_json, const std::string &component) {
  RowPayload payload;
  payload.raw = component_payload(summary_json, component);
  payload.cls = normalized_classification(
      json{
          {"total", payload.raw.value("den", json(0))},
          {"masked", payload.raw.value("masked", json())},
          {"sdc", payload.raw.value("sdc", json())},
          {"due", payload.raw.value("due", json())},
          {"unknown", payload.raw.value("unknown", json())},
      },
      payload.raw.value("rate", json::object()),
      to_number(payload.raw.value("den", json(0)), 0.0));
  return payload;
}

void write_simple_lines_csv(const std::string &path, const std::vector<std::string> &lines) {
  std::ofstream out(path.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);
  if (!out) {
    throw std::runtime_error("failed to write " + path);
  }
  out << "line\n";
  for (const std::string &line : lines) {
    out << escape_csv(line) << "\n";
  }
}

std::string escape_csv(const std::string &value) {
  if (value.find_first_of(",\"\n\r") == std::string::npos) {
    return value;
  }
  std::string out = "\"";
  for (char c : value) {
    if (c == '"') out += "\"\"";
    else out.push_back(c);
  }
  out += "\"";
  return out;
}

void write_csv(const std::string &path,
               const std::vector<std::string> &fieldnames,
               const std::map<std::string, std::string> &row) {
  std::ofstream out(path.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);
  if (!out) {
    throw std::runtime_error("failed to write " + path);
  }
  for (size_t i = 0; i < fieldnames.size(); ++i) {
    if (i) out << ',';
    out << escape_csv(fieldnames[i]);
  }
  out << '\n';
  for (size_t i = 0; i < fieldnames.size(); ++i) {
    if (i) out << ',';
    auto it = row.find(fieldnames[i]);
    out << escape_csv(it == row.end() ? std::string() : it->second);
  }
  out << '\n';
}

bool parse_i64(const std::string &text, int64_t *out) {
  if (out == nullptr) return false;
  char *end = nullptr;
  const long long value = std::strtoll(text.c_str(), &end, 0);
  if (end == nullptr || *end != '\0') return false;
  *out = static_cast<int64_t>(value);
  return true;
}

bool parse_u64(const std::string &text, uint64_t *out) {
  if (out == nullptr) return false;
  char *end = nullptr;
  const unsigned long long value = std::strtoull(text.c_str(), &end, 0);
  if (end == nullptr || *end != '\0') return false;
  *out = static_cast<uint64_t>(value);
  return true;
}

bool decode_op(const std::string &name, Op *out) {
  if (out == nullptr) return false;
  if (name == "ADD") *out = Op::ADD;
  else if (name == "SUB") *out = Op::SUB;
  else if (name == "MUL_LO") *out = Op::MUL_LO;
  else if (name == "MAD") *out = Op::MAD;
  else if (name == "AND") *out = Op::AND;
  else if (name == "OR") *out = Op::OR;
  else if (name == "XOR") *out = Op::XOR;
  else if (name == "SHL") *out = Op::SHL;
  else if (name == "SHR_U") *out = Op::SHR_U;
  else if (name == "SHR_S") *out = Op::SHR_S;
  else if (name == "MIN_U") *out = Op::MIN_U;
  else if (name == "MIN_S") *out = Op::MIN_S;
  else if (name == "MAX_U") *out = Op::MAX_U;
  else if (name == "MAX_S") *out = Op::MAX_S;
  else if (name == "CVT_U32_U64") *out = Op::CVT_U32_U64;
  else if (name == "CVT_U64_U32") *out = Op::CVT_U64_U32;
  else if (name == "CVT_S32_S64") *out = Op::CVT_S32_S64;
  else if (name == "CVT_S64_S32") *out = Op::CVT_S64_S32;
  else if (name == "CVT_SAT_F32_F32") *out = Op::CVT_SAT_F32_F32;
  else if (name == "SETP_EQ") *out = Op::SETP_EQ;
  else if (name == "SETP_NE") *out = Op::SETP_NE;
  else if (name == "SETP_LT_U") *out = Op::SETP_LT_U;
  else if (name == "SETP_LT_S") *out = Op::SETP_LT_S;
  else if (name == "SETP_LE_U") *out = Op::SETP_LE_U;
  else if (name == "SETP_LE_S") *out = Op::SETP_LE_S;
  else if (name == "SELP") *out = Op::SELP;
  else return false;
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
  if (result.src_masks.size() != 2 || result.src_masks[0] == 0 || result.src_masks[1] == 0) {
    std::cerr << "selftest failed\n";
    return 1;
  }
  std::cout << "exact_core selftest OK\n";
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
    if (arg == "--op" && i + 1 < argc) op_name = argv[++i];
    else if (arg == "--width" && i + 1 < argc) {
      int64_t parsed = 0;
      if (!parse_i64(argv[++i], &parsed)) return 2;
      width_bits = static_cast<int>(parsed);
    } else if (arg == "--dst-val" && i + 1 < argc) {
      if (!parse_u64(argv[++i], &dst_val)) return 2;
    } else if (arg == "--dst-mask" && i + 1 < argc) {
      if (!parse_u64(argv[++i], &dst_mask)) return 2;
    } else if (arg == "--src" && i + 1 < argc) {
      uint64_t value = 0;
      if (!parse_u64(argv[++i], &value)) return 2;
      src_vals.push_back(value);
    } else if (arg == "--signed") {
      signed_mode = true;
    } else {
      std::cerr << "unknown argument: " << arg << "\n";
      return 2;
    }
  }
  Op op;
  if (!decode_op(op_name, &op)) return 2;
  if (width_bits <= 0 || width_bits > 64) return 2;
  if (static_cast<int>(src_vals.size()) != expected_src_count(op)) return 2;

  OpMeta meta;
  meta.width_bits = width_bits;
  meta.signed_mode = signed_mode;
  const InfluenceResult result = backward_influence(op, src_vals, dst_val, dst_mask, meta);
  for (size_t i = 0; i < result.src_masks.size(); ++i) {
    std::cout << "src[" << i << "]=" << result.src_masks[i] << "\n";
  }
  return 0;
}

std::string arg_value(int argc, char **argv, const std::string &name,
                      const std::string &fallback = std::string()) {
  for (int i = 2; i < argc; ++i) {
    if (std::string(argv[i]) == name && i + 1 < argc) {
      return std::string(argv[i + 1]);
    }
  }
  return fallback;
}

std::vector<std::string> arg_values(int argc, char **argv, const std::string &name) {
  std::vector<std::string> values;
  for (int i = 2; i < argc; ++i) {
    if (std::string(argv[i]) != name) {
      continue;
    }
    while (i + 1 < argc) {
      const std::string next(argv[i + 1]);
      if (!next.empty() && next[0] == '-') {
        break;
      }
      values.push_back(next);
      ++i;
    }
  }
  return values;
}

int run_rates_summary(int argc, char **argv) {
  const std::string input = arg_value(argc, argv, "--input");
  const std::string benchmark = arg_value(argc, argv, "--benchmark");
  const std::string test_id = arg_value(argc, argv, "--test-id");
  const std::string output_json = arg_value(argc, argv, "--output-json");
  if (input.empty()) {
    std::cerr << "missing --input\n";
    return 2;
  }
  const json data = load_json(input);
  const std::map<std::string, double> rates = rates_from_payload(data);

  std::cout << "Masked total: " << format_rate(rates.at("masked")) << "\n";
  std::cout << "SDC total:    " << format_rate(rates.at("sdc")) << "\n";
  std::cout << "DUE total:    " << format_rate(rates.at("due")) << "\n";
  std::cout << "Unknown total:" << format_rate(rates.at("unknown")) << "\n";

  const json summary_raw = data.value("summary", json::object());
  auto print_nested = [&](const std::string &label, const json &row) {
    if (!row.is_object()) return;
    const double den = to_number(row.value("den", json(0)), 0.0);
    const json rate = row.value("rate", json::object());
    if (den <= 0.0 || !rate.is_object()) return;
    std::cout << label
              << " rate: masked=" << format_rate(to_number(rate.value("masked", json(0)), 0.0))
              << " sdc=" << format_rate(to_number(rate.value("sdc", json(0)), 0.0))
              << " due=" << format_rate(to_number(rate.value("due", json(0)), 0.0))
              << " unknown=" << format_rate(to_number(rate.value("unknown", json(0)), 0.0))
              << " den=" << static_cast<long long>(den) << "\n";
  };
  if (summary_raw.is_object()) {
    print_nested("l1d", summary_raw.value("l1d_cache", json::object()));
    print_nested("l2", summary_raw.value("l2_cache", json::object()));
    const json shared = summary_raw.value("shared_memory", json::object());
    if (shared.is_object()) {
      print_nested("smem_rf", shared.value("smem_rf", json::object()));
      print_nested("smem_lds", shared.value("smem_lds", json::object()));
    }
  }

  if (!output_json.empty()) {
    json out;
    out["benchmark"] = benchmark;
    out["test_id"] = test_id;
    out["classification_rates"] = json::object();
    for (const char *key : kClassKeys) {
      out["classification_rates"][key] = rates.at(key);
    }
    if (data.contains("classification_counts") && data.at("classification_counts").is_object()) {
      out["classification_counts"] = data.at("classification_counts");
    }
    if (summary_raw.is_object() && !summary_raw.empty()) {
      out["summary"] = summary_raw;
    }
    out["status"] = "ok";
    out["status_reason"] = "";
    const json meta_raw = data.value("exact_meta", json::object());
    if (meta_raw.is_object()) {
      for (auto it = meta_raw.begin(); it != meta_raw.end(); ++it) {
        out[it.key()] = it.value();
      }
      if (meta_raw.contains("exact_semantics_profile")) {
        out["exact_semantics_profile"] = to_string_value(meta_raw.at("exact_semantics_profile"));
      }
    }
    write_text(output_json, out.dump(2) + "\n");
  }
  return 0;
}

int run_summary_status(int argc, char **argv) {
  const std::string input = arg_value(argc, argv, "--input");
  if (input.empty()) {
    std::cerr << "missing --input\n";
    return 2;
  }
  const json raw = load_json(input);
  const json rates_raw = raw.value("classification_rates", json::object());
  const std::string status = to_string_value(raw.value("status", json("ok")));
  std::string reason = to_string_value(raw.value("status_reason", json("")));
  if (reason.empty()) {
    reason = "-";
  }
  const double masked = to_number(rates_raw.value("masked", json(0)), 0.0);
  const double sdc = to_number(rates_raw.value("sdc", json(0)), 0.0);
  const double due = to_number(rates_raw.value("due", json(0)), 0.0);
  const double unknown = to_number(rates_raw.value("unknown", json(0)), 0.0);
  std::cout << status << "\t" << reason << "\t" << format_rate(masked) << "\t"
            << format_rate(sdc) << "\t" << format_rate(due) << "\t"
            << format_rate(unknown) << "\n";
  return 0;
}

int run_rates_simple_summary_csv(int argc, char **argv) {
  const std::string input = arg_value(argc, argv, "--input");
  const std::string output = arg_value(argc, argv, "--output");
  if (input.empty() || output.empty()) {
    std::cerr << "missing --input/--output\n";
    return 2;
  }
  std::istringstream iss(read_text(input));
  std::ofstream out(output.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);
  if (!out) return 2;
  out << "line\n";
  std::string line;
  while (std::getline(iss, line)) {
    out << escape_csv(line) << "\n";
  }
  return 0;
}

int run_rates_compare(int argc, char **argv) {
  const std::string expected_path = arg_value(argc, argv, "--expected");
  const std::string measured_path = arg_value(argc, argv, "--measured");
  const std::string tolerance_arg = arg_value(argc, argv, "--tolerance", "1e-12");
  if (expected_path.empty() || measured_path.empty()) {
    std::cerr << "missing --expected/--measured\n";
    return 2;
  }
  const double tolerance = std::strtod(tolerance_arg.c_str(), nullptr);
  const std::map<std::string, double> expected = rates_from_payload(load_json(expected_path));
  const std::map<std::string, double> measured = rates_from_payload(load_json(measured_path));
  bool mismatch = false;
  for (const char *key : {"masked", "sdc", "due"}) {
    const double diff = std::abs(expected.at(key) - measured.at(key));
    if (std::isnan(diff) || diff > tolerance) {
      mismatch = true;
    }
  }
  if (mismatch) {
    for (const char *key : {"masked", "sdc", "due"}) {
      const double diff = std::abs(expected.at(key) - measured.at(key));
      std::cout << "rate_mismatch " << key
                << ": expected=" << format_rate(expected.at(key))
                << " measured=" << format_rate(measured.at(key))
                << " diff=" << format_rate(diff) << "\n";
    }
    return 1;
  }
  std::cout << "validation_match: masked=" << format_rate(measured.at("masked"))
            << " sdc=" << format_rate(measured.at("sdc"))
            << " due=" << format_rate(measured.at("due")) << "\n";
  return 0;
}

std::string json_dump_if_object(const json &value) {
  return value.is_object() ? value.dump() : std::string();
}

std::string public_sara_text(std::string value) {
  const std::vector<std::pair<std::string, std::string>> replacements = {
      {"canonical_proof_exact_v2", "canonical_proof_sara_v2"},
      {"exact", "sara"},
      {"Exact", "SARA"},
      {"EXACT", "SARA"},
  };
  for (const auto &entry : replacements) {
    const std::string &from = entry.first;
    const std::string &to = entry.second;
    size_t pos = 0;
    while ((pos = value.find(from, pos)) != std::string::npos) {
      value.replace(pos, from.size(), to);
      pos += to.size();
    }
  }
  return value;
}

int run_rates_merge_csv(int argc, char **argv) {
  const std::vector<std::string> summaries = arg_values(argc, argv, "--summary");
  const std::string output = arg_value(argc, argv, "--output");
  if (summaries.empty() || output.empty()) {
    std::cerr << "missing --summary/--output\n";
    return 2;
  }

  const std::vector<std::string> fieldnames = {
      "benchmark",
      "test_id",
      "component",
      "sara_semantics_profile",
      "den",
      "masked_num",
      "sdc_num",
      "due_num",
      "unknown_num",
      "masked_rate",
      "sdc_rate",
      "due_rate",
      "unknown_rate",
  };

  std::ofstream out(output.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);
  if (!out) {
    throw std::runtime_error("failed to write " + output);
  }
  for (size_t i = 0; i < fieldnames.size(); ++i) {
    if (i) out << ',';
    out << escape_csv(fieldnames[i]);
  }
  out << '\n';

  for (const std::string &path : summaries) {
    const json data = load_json(path);
    const std::map<std::string, double> rates = rates_from_payload(data);
    const json counts = data.value("classification_counts", json::object());

    std::string profile = to_string_value(data.value("exact_semantics_profile", json("")));
    if (profile.empty()) {
      profile = to_string_value(data.value("sara_semantics_profile", json("")));
    }
    profile = public_sara_text(profile);

    std::string component = to_string_value(data.value("fault_component", json("")));
    if (component.empty()) {
      component = to_string_value(data.value("component", json("")));
    }

    std::map<std::string, std::string> row;
    row["benchmark"] = to_string_value(data.value("benchmark", json("")));
    row["test_id"] = to_string_value(data.value("test_id", json("")));
    row["component"] = component;
    row["sara_semantics_profile"] = profile;
    row["den"] = format_scalar(to_number(counts.value("total", json(0)), 0.0));
    row["masked_num"] = format_scalar(to_number(counts.value("masked", json(0)), 0.0));
    row["sdc_num"] = format_scalar(to_number(counts.value("sdc", json(0)), 0.0));
    row["due_num"] = format_scalar(to_number(counts.value("due", json(0)), 0.0));
    row["unknown_num"] = format_scalar(to_number(counts.value("unknown", json(0)), 0.0));
    row["masked_rate"] = format_rate(rates.at("masked"));
    row["sdc_rate"] = format_rate(rates.at("sdc"));
    row["due_rate"] = format_rate(rates.at("due"));
    row["unknown_rate"] = format_rate(rates.at("unknown"));

    for (size_t i = 0; i < fieldnames.size(); ++i) {
      if (i) out << ',';
      auto it = row.find(fieldnames[i]);
      out << escape_csv(it == row.end() ? std::string() : it->second);
    }
    out << '\n';
  }
  return 0;
}

int run_rates_merge_components_csv(int argc, char **argv) {
  const std::string rf_path = arg_value(argc, argv, "--rf-summary");
  const std::string smem_path = arg_value(argc, argv, "--smem-rf-summary");
  const std::string l1d_path = arg_value(argc, argv, "--l1d-summary");
  const std::string l2_path = arg_value(argc, argv, "--l2-summary");
  const std::string output = arg_value(argc, argv, "--output");
  if (rf_path.empty() || smem_path.empty() || l1d_path.empty() || l2_path.empty() || output.empty()) {
    std::cerr << "missing merge-components-csv args\n";
    return 2;
  }
  const json rf = load_json(rf_path);
  const json smem_rf = load_json(smem_path);
  const json l1d = load_json(l1d_path);
  const json l2 = load_json(l2_path);

  const std::string benchmark = !to_string_value(rf.value("benchmark", json(""))).empty()
                                    ? to_string_value(rf.value("benchmark", json("")))
                                    : (!to_string_value(smem_rf.value("benchmark", json(""))).empty()
                                           ? to_string_value(smem_rf.value("benchmark", json("")))
                                           : (!to_string_value(l1d.value("benchmark", json(""))).empty()
                                                  ? to_string_value(l1d.value("benchmark", json("")))
                                                  : to_string_value(l2.value("benchmark", json("")))));
  const std::string sara_semantics_profile = public_sara_text(
      !to_string_value(rf.value("exact_semantics_profile", json(""))).empty()
          ? to_string_value(rf.value("exact_semantics_profile", json("")))
          : (!to_string_value(smem_rf.value("exact_semantics_profile", json(""))).empty()
                 ? to_string_value(smem_rf.value("exact_semantics_profile", json("")))
                 : (!to_string_value(l1d.value("exact_semantics_profile", json(""))).empty()
                        ? to_string_value(l1d.value("exact_semantics_profile", json("")))
                        : to_string_value(l2.value("exact_semantics_profile", json(""))))));
  const std::string test_id = !to_string_value(rf.value("test_id", json(""))).empty()
                                  ? to_string_value(rf.value("test_id", json("")))
                                  : (!to_string_value(smem_rf.value("test_id", json(""))).empty()
                                         ? to_string_value(smem_rf.value("test_id", json("")))
                                         : (!to_string_value(l1d.value("test_id", json(""))).empty()
                                                ? to_string_value(l1d.value("test_id", json("")))
                                                : to_string_value(l2.value("test_id", json("")))));

  std::map<std::string, RowPayload> by_component = {
      {"rf", component_row(rf, "rf")},
      {"smem_rf", component_row(smem_rf, "smem_rf")},
      {"l1d", component_row(l1d, "l1d")},
      {"l2", component_row(l2, "l2")},
  };

  std::vector<std::string> fieldnames = {"benchmark", "test_id", "sara_semantics_profile"};
  std::map<std::string, std::string> row = {
      {"benchmark", benchmark},
      {"test_id", test_id},
      {"sara_semantics_profile", sara_semantics_profile},
  };
  const std::vector<std::string> prefixes = {"rf", "smem_rf", "l1d", "l2"};

  for (const std::string &prefix : prefixes) {
    fieldnames.push_back(prefix + "_den");
    fieldnames.push_back(prefix + "_masked_num");
    fieldnames.push_back(prefix + "_sdc_num");
    fieldnames.push_back(prefix + "_due_num");
    fieldnames.push_back(prefix + "_unknown_num");
    fieldnames.push_back(prefix + "_masked_rate");
    fieldnames.push_back(prefix + "_sdc_rate");
    fieldnames.push_back(prefix + "_due_rate");
    fieldnames.push_back(prefix + "_unknown_rate");
    const RowPayload &payload = by_component.at(prefix);
    row[prefix + "_den"] = format_scalar(payload.cls.den);
    row[prefix + "_masked_num"] = format_scalar(payload.cls.counts.at("masked"));
    row[prefix + "_sdc_num"] = format_scalar(payload.cls.counts.at("sdc"));
    row[prefix + "_due_num"] = format_scalar(payload.cls.counts.at("due"));
    row[prefix + "_unknown_num"] = format_scalar(payload.cls.counts.at("unknown"));
    row[prefix + "_masked_rate"] = format_rate(payload.cls.rates.at("masked"));
    row[prefix + "_sdc_rate"] = format_rate(payload.cls.rates.at("sdc"));
    row[prefix + "_due_rate"] = format_rate(payload.cls.rates.at("due"));
    row[prefix + "_unknown_rate"] = format_rate(payload.cls.rates.at("unknown"));
  }

  write_csv(output, fieldnames, row);
  return 0;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc <= 1) {
    print_usage(std::cerr);
    return 2;
  }
  const std::string cmd(argv[1]);
  try {
    if (cmd == "--help" || cmd == "help") {
      print_usage(std::cout);
      return 0;
    }
    if (cmd == "--version") {
      std::cout << "exact_core dev\n";
      return 0;
    }
    if (cmd == "--selftest") {
      return run_selftest();
    }
    if (cmd == "backward-influence") {
      return run_backward_influence(argc, argv);
    }
    if (cmd == "rates-summary") {
      return run_rates_summary(argc, argv);
    }
    if (cmd == "summary-status") {
      return run_summary_status(argc, argv);
    }
    if (cmd == "rates-simple-summary-csv") {
      return run_rates_simple_summary_csv(argc, argv);
    }
    if (cmd == "rates-compare") {
      return run_rates_compare(argc, argv);
    }
    if (cmd == "rates-merge-csv") {
      return run_rates_merge_csv(argc, argv);
    }
    if (cmd == "rates-merge-components-csv") {
      return run_rates_merge_components_csv(argc, argv);
    }
  } catch (const std::exception &ex) {
    std::cerr << "exact_core error: " << ex.what() << "\n";
    return 1;
  }

  std::cerr << "unknown command: " << cmd << "\n";
  print_usage(std::cerr);
  return 2;
}
