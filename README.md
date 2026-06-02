# SARA Artifact Runner

This repository contains the artifact code for running the SARA, GEREM-all, and FI storage-fault experiments. The public entry point is `run_experiment.sh`; experiment outputs are written under `test_result/`, and temporary per-run scratch data is written under `.work/`.

## Repository layout

- `run_experiment.sh` — interactive and non-interactive experiment runner.
- `script/SARA/` — SARA analysis path and SARA app runner.
- `script/GEREM/` — GEREM-all storage campaign path.
- `script/FI/` — fault-injection campaign path.
- `script/common/` — common result-layout and campaign helpers. Its output-oracle utilities are used by the SARA and FI paths. GEREM-all remains the relocated GEREM storage EFM baseline.
- `test_apps/` — CUDA benchmark applications used by the experiments.
- `configs/` — architecture configurations for Turing RTX2060 and Ampere RTX3070.
- `test_result/` — current experiment results and run logs.

## Outcome classification policy

SARA and FI use the same final outcome definitions:

1. If an application-specific oracle is present, use it first.
2. If no explicit oracle is present, compare recorded outputs exactly.
3. Automatic tolerance-policy creation is not used.
4. Timeout, runtime error, invalid execution, missing logs, or missing required outputs are `DUE`.
5. A normal run whose oracle or exact output comparison differs from the golden run is `SDC`.
6. A normal run whose oracle or exact output comparison matches the golden run is `Masked`.

SARA may keep internal `Unknown` records for diagnosis, but `Unknown` is not folded into `Masked`, `SDC`, or `DUE`. GEREM-all is preserved as the GEREM storage EFM baseline after relocation to `script/GEREM/`; its EFM-to-outcome mapping follows the GEREM model rather than the SARA internal evidence rules.

The public SARA CSV files report result-facing fields only: `benchmark`, `test_id`, `sara_semantics_profile`, and, for each component, denominator, Masked/SDC/DUE/Unknown counts, and Masked/SDC/DUE/Unknown rates. Detailed trace diagnostics remain in `.work/` when `--keep-intermediate` is selected.

## Quick start in the CUDA container

The repository provides a root-level `Dockerfile` for the experiment environment. It builds the same CUDA 11.8 development image expected by the runner examples below (`sdc-gerem:cuda11.8-dev`). If a prebuilt image has been published for your artifact package, pull it first:

```bash
docker pull sdc-gerem:cuda11.8-dev
```

If the pull command cannot find the image, build it locally from this repository instead:

```bash
docker build -t sdc-gerem:cuda11.8-dev .
```

Then start the interactive experiment runner from the repository root:

```bash
docker run --rm -it \
  --name "sara-run-$(date +%s)" \
  -v "$(pwd):$(pwd)" \
  -w "$(pwd)" \
  sdc-gerem:cuda11.8-dev \
  bash -lc 'bash ./run_experiment.sh'
```

The runner opens an interactive menu for architecture, method, application, overwrite behavior, GEREM campaign size, and whether to retain `.work` scratch data after the run.

For a non-interactive smoke run that does not overwrite the existing repository results, use an isolated result root inside the same container image:

```bash
docker run --rm -it \
  --name "sara-smoke-$(date +%s)" \
  -v "$(pwd):$(pwd)" \
  -w "$(pwd)" \
  -e RESULT_ROOT="$(pwd)/.omx/tmp/smoke-test-result" \
  -e WORK_ROOT="$(pwd)/.omx/tmp/smoke-work" \
  sdc-gerem:cuda11.8-dev \
  bash -lc 'bash ./run_experiment.sh --arch turing --method sara --app AdamW --smoke --discard-intermediate'
```

For a full experiment run inside the container:

```bash
docker run --rm -it \
  --name "sara-full-$(date +%s)" \
  -v "$(pwd):$(pwd)" \
  -w "$(pwd)" \
  sdc-gerem:cuda11.8-dev \
  bash -lc 'bash ./run_experiment.sh --arch both --method all --app all --runs 1000 --gerem-runs all --force'
```

## Useful runner options

```text
--arch turing|ampere|both
--method sara|sara-gerem-all|fi|gerem-all|all
--app NAME|all
--runs N
--gerem-runs N|all
--skip-build
--keep-intermediate
--discard-intermediate
--force
--smoke
```

Each invocation deletes `.work/` before starting so every run begins from a clean scratch directory. Final results are always written to `test_result/` unless `RESULT_ROOT` is explicitly set.

Use `--keep-intermediate` to keep the current run's `.work/` scratch files for inspection. Use `--discard-intermediate` to remove the scratch files after the run finishes.

Partial reruns are app-scoped. For example, `--app Attention --method sara --force` removes and recomputes only `test_result/<arch>/SARA/Attention`; other applications and other methods under `test_result/` are preserved. After every invocation, the runner refreshes the full-suite comparison report under `test_result/<arch>/compare/` from the current public result directories, so a small rerun updates the aggregate compare file while showing missing data as `-`.
