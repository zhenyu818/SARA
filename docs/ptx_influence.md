# PTX Influence Engine (Stage-3)

This module provides an exact bit-level backward influence engine for a small
PTX-like integer ISA subset. It is intended for offline SDC analysis where
exactness matters more than speed.

## API

Header: `src/analysis/ptx_influence.h`

```cpp
enum class Op { ADD, SUB, MUL_LO, MAD, AND, OR, XOR, SHL, SHR_U, SHR_S,
                MIN_U, MIN_S, MAX_U, MAX_S,
                CVT_U32_U64, CVT_U64_U32, CVT_S32_S64, CVT_S64_S32,
                SETP_EQ, SETP_NE, SETP_LT_U, SETP_LT_S, SETP_LE_U, SETP_LE_S,
                SELP };

struct OpMeta {
  int width_bits;   // 32 or 64
  bool signed_mode; // for compares/shifts/min/max where needed
};

struct InfluenceResult {
  std::vector<uint64_t> src_masks; // one per src operand
};

InfluenceResult backward_influence(Op op,
                                   const std::vector<uint64_t>& src_vals,
                                   uint64_t dst_val,
                                   uint64_t dst_observed_mask,
                                   const OpMeta& meta);
```

## Semantics

- Integer ops are modulo 2^width_bits.
- Shifts mask the shift amount with `(width_bits - 1)` like PTX.
- `MUL_LO` returns the low half of the product (32 or 64 bits).
- `MAD` is `(a * b + c)` modulo 2^width_bits.
- `CVT_*` performs truncation or sign/zero-extension per the op name.
- `CVT_U32_U64`: zero-extend 32-bit unsigned to 64-bit.
- `CVT_U64_U32`: truncate 64-bit unsigned to low 32 bits.
- `CVT_S32_S64`: sign-extend 32-bit signed to 64-bit.
- `CVT_S64_S32`: truncate 64-bit signed to low 32 bits.
- `SETP_*` returns a predicate (0/1). Only bit0 of `dst_val` and
  `dst_observed_mask` is meaningful for these ops.
- `SELP` selects `a` or `b` based on predicate `src_vals[2] & 1`.

## Usage Example

```cpp
#include "analysis/ptx_influence.h"

OpMeta meta{32, false};
uint64_t a = 0x12345678ULL;
uint64_t b = 0x0000FFFFULL;
uint64_t dst = (a + b) & 0xFFFFFFFFULL;
uint64_t observed = 0x0000FFFFULL; // observe low 16 bits

InfluenceResult res = backward_influence(Op::ADD, {a, b}, dst, observed, meta);
// res.src_masks[0] and res.src_masks[1] contain influential input bits
```

## Integration Notes

An offline analyzer should:

1. Parse an instruction and map it to `Op` + `OpMeta`.
2. Provide concrete source operand values and the concrete destination value.
3. Provide the destination observed bitmask from the backward slice.
4. Call `backward_influence` to get per-source influential bitmasks.

## Tests

Build and run the standalone tests:

```bash
make ptx_influence_test_run
```
