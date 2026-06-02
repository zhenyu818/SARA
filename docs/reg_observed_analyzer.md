# Register Observed/DUE Backward Analyzer

## File

- `script/SARA/reg_observed_analyzer.py`: offline analyzer used by the SARA path to compute exact backward masks and trace-local control-flow divergence evidence.

## What it computes

- Backward observed-bit masks per register read (`observed_mask_this_read`).
- Backward DUE-bit masks per register read (`due_mask_this_read`).
- Control-flow divergence masks per read (`trace_expanding_mask_this_read`).
- Exact class evidence over `(read_event, bit)` sites, preserving unresolved trace-local evidence as `Unknown` when a final outcome cannot be proven from the golden trace.

## Architecture

```text
Trace JSON ------> Parse events/ranges
                       |
                       v
                 Golden-trace backward masks
                       |
                       v
                 Divergence detector
                       |
                       v
                 Exact SARA classification evidence
```

## Exact DUE model for address corruption

For memory operations with effective-address metadata:

1. Build the effective address from the trace metadata.
2. Enumerate single-bit flips on the selected effective-address source bits.
3. Re-evaluate the effective address exactly.
4. Classify DUE when the mutated address is outside the valid address domain for that access.

Address-effective metadata:

- `mem_addr_effective_bits`: integer `[1, 64]` for the memory-subsystem-consumed address width.
- `mem_addr_mask`: explicit mask (`0x...`) for consumed address bits.

## Trace-divergent fault detection

For branch-like events:

1. Evaluate the control expression on golden source values.
2. Flip each selected source bit and re-evaluate the control decision.
3. Mark bits that toggle the decision as trace-divergent.
4. Preserve unresolved off-trace effects as `Unknown` unless DUE or SDC is proven by exact evidence.

The analyzer is an internal SARA component. Public experiment execution should use `run_experiment.sh` rather than invoking this module directly.
