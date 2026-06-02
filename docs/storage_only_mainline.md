# Storage-only mainline

The public experiment entry point is the repository-root `run_experiment.sh` script. It invokes the method-specific implementations under `script/SARA/`, `script/GEREM/`, and `script/FI/`, and writes final reports under `test_result/<arch>/` unless `RESULT_ROOT` is explicitly overridden.

## Comparison surface

- Primary compare helper: `script/common/sara_gerem_fi_compare.py`
- Storage-only compare helper: `script/common/storage_only_sara_gerem_fi_compare.py`
- Standard output location: `test_result/<arch>/compare/`
- Headline storage components: `RF`, `SMEM`, `L1D`, `L2`

The comparison helpers consume already generated result files and compare reported rates. They do not rewrite method outputs. SARA and FI outputs use the repository output-oracle utilities; GEREM-all outputs are produced by the relocated GEREM storage EFM implementation under `script/GEREM/`.

Public SARA result CSVs expose the same component outcome fields used by the paper: denominator, Masked/SDC/DUE/Unknown counts, and Masked/SDC/DUE/Unknown rates for RF, SMEM, L1D, and L2. Implementation diagnostics are kept in intermediate work directories instead of the public result CSV.

## Default entry point

```bash
./run_experiment.sh
```

For a non-destructive smoke run, isolate outputs outside the public result tree:

```bash
RESULT_ROOT="$PWD/.omx/tmp/smoke-test-result" \
WORK_ROOT="$PWD/.omx/tmp/smoke-work" \
./run_experiment.sh --arch turing --method sara --app AdamW --gerem-runs 1 --discard-intermediate
```

The runner deletes the selected work directory at the start of every run. Final outputs always go to `RESULT_ROOT`; intermediate files are retained only when the keep-intermediate option is selected.
