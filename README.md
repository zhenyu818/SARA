# SARA Artifact Runner

This repository contains the runnable artifact for **SARA: Semantic Backward Derivation for GPU Storage Resilience Assessment**. It provides one public entry point, `run_experiment.sh`, for running and comparing three storage-fault assessment paths:

- **SARA**: semantic backward derivation over modeled GPU storage fault sites.
- **GEREM-1000 / GEREM-5000 / GEREM-10000**: the GEREM storage Early Fault Manifestation baseline using fixed-seed random sampling. This artifact reproduces the storage-component EFM model only; it does not include GEREM pipeline-component modeling or machine-learning accuracy improvement.
- **FI**: storage fault injection used as the reference outcome source.

The evaluated storage components are the register file, shared memory, L1 data cache, and L2 cache. The runner supports the Turing RTX2060 and Ampere RTX3070 configurations and the benchmark applications under `test_apps/`.

## Repository layout

- `run_experiment.sh` — interactive and non-interactive experiment runner.
- `script/SARA/` — SARA analysis and application runner.
- `script/GEREM/` — GEREM storage-EFM campaign runner.
- `script/FI/` — storage fault-injection runner.
- `script/common/` — shared campaign and result-layout utilities.
- `script/paper_results/` — tracked plotting helpers for paper figures.
- `gen_paper_results.py` — regenerates paper-ready Markdown tables and figure PDFs from `sara-results/`.
- `test_apps/` — CUDA benchmark applications used by the experiments.
- `configs/` — GPU architecture configurations used by the runner.

## Quick start

The runnable experiment image is built from this repository's Dockerfile. Docker cannot pull a final image directly from a Dockerfile; it can only pull images that have already been published to a registry. The commands below first pull the CUDA base image used by the Dockerfile and then build the local SARA experiment image. By default, `run_experiment.sh` writes results to the repository-local `sara-results/` directory, which is already present in the artifact.

```bash
docker pull nvidia/cuda:11.8.0-devel-ubuntu20.04
docker build --pull -t sara:cuda11.8-dev .
```

If paper figure generation reports `ModuleNotFoundError: No module named 'matplotlib'`, rebuild the image with the command above so the plotting dependencies from the Dockerfile are installed.

If you later publish the SARA experiment image to Docker Hub or GHCR, replace `sara:cuda11.8-dev` with that registry-qualified tag and use `docker pull <registry-qualified-tag>` instead of the local build step.

Run SARA for all applications on both supported architectures:

```bash
docker run --rm -it \
  --name "sara-run-$(date +%s)" \
  -v "$PWD:$PWD" \
  -w "$PWD" \
  sara:cuda11.8-dev \
  bash -lc 'bash ./run_experiment.sh --arch both --method sara --app all --force --discard-intermediate'
```

Results are organized as:

```text
$PWD/sara-results/<architecture>/<method>/<application>/
$PWD/sara-results/paper-results/
```

For example, SARA results for AdamW on Turing are written under:

```text
$PWD/sara-results/Turing-RTX2060/SARA/AdamW/
```

## Running the full experiment families

Run FI for all applications on all supported architectures:

```bash
docker run --rm -it \
  --name "fi-run-$(date +%s)" \
  -v "$PWD:$PWD" \
  -w "$PWD" \
  sara:cuda11.8-dev \
  bash -lc 'bash ./run_experiment.sh --arch both --method fi --app all --runs 1000 --force --discard-intermediate'
```

Run GEREM storage EFM for all applications on all supported architectures:

```bash
docker run --rm -it \
  --name "gerem-run-$(date +%s)" \
  -v "$PWD:$PWD" \
  -w "$PWD" \
  sara:cuda11.8-dev \
  bash -lc 'bash ./run_experiment.sh --arch both --method gerem-all --app all --gerem-runs 1000 --force --discard-intermediate'
```

Use `--gerem-runs 5000` or `--gerem-runs 10000` for the larger GEREM-5000 / GEREM-10000 campaigns; their results are written to separate directories.

Run SARA, GEREM storage EFM, and FI in one command:

```bash
docker run --rm -it \
  --name "all-run-$(date +%s)" \
  -v "$PWD:$PWD" \
  -w "$PWD" \
  sara:cuda11.8-dev \
  bash -lc 'bash ./run_experiment.sh --arch both --method all --app all --runs 1000 --gerem-runs 1000 --force --discard-intermediate'
```

The full FI campaign and the fixed-sample GEREM baselines can take a long time. For a quick functional check, run one SARA smoke test:

```bash
docker run --rm -it \
  --name "sara-smoke-$(date +%s)" \
  -v "$PWD:$PWD" \
  -w "$PWD" \
  sara:cuda11.8-dev \
  bash -lc 'bash ./run_experiment.sh --arch turing --method sara --app AdamW --smoke --force --discard-intermediate'
```

## Runner options

`run_experiment.sh` can run either non-interactively with command-line options or interactively with an arrow-key menu.

| Option | Meaning |
| --- | --- |
| `--arch turing\|ampere\|both` | Selects the target GPU architecture configuration. `turing` uses the Turing RTX2060 configuration, `ampere` uses the Ampere RTX3070 configuration, and `both` runs the selected experiment family on both configurations. |
| `--method sara\|sara-gerem-all\|fi\|gerem-all\|all` | Selects the experiment family. `sara` runs SARA only; `gerem-all` runs the selected GEREM storage-EFM campaign only; `fi` runs fault injection only; `sara-gerem-all` runs SARA plus GEREM; `all` runs SARA, GEREM, and FI. |
| `--app NAME\|all` | Selects one benchmark application under `test_apps/` or all applications. If omitted in non-interactive mode, it defaults to `all`. Paper-ready result summaries are refreshed from the current result directory after each invocation. |
| `--runs N` | Sets the number of FI trials per storage component. The default is `1000`; `--smoke` changes it to `1`. |
| `--gerem-runs 1000\|5000\|10000` | Selects the GEREM storage-EFM random-sampling campaign size. Results are written under `GEREM-1000`, `GEREM-5000`, or `GEREM-10000`. Exhaustive `all` mode and ad-hoc GEREM sample counts are not supported. |
| `--skip-build` | Skips the common simulator build. Use only when the required GPGPU-Sim runtime library already exists from a previous preserved build. |
| `--keep-intermediate` | Keeps this invocation's `.work` scratch directories for inspection after completion. This also preserves generated build artifacts. |
| `--discard-intermediate` | Deletes this invocation's `.work` scratch directories after completion. This is the default behavior. |
| `--keep-build` | Preserves generated build artifacts after completion, while still allowing scratch-directory cleanup. |
| `--force` | Removes existing selected final results before rerunning. For `--app all`, it removes the selected method directory for that architecture; for one app, it removes only that app's selected method results. |
| `--smoke` | Convenience shortcut for a quick check: `--app AdamW --runs 1 --gerem-runs 1000`. |
| `-h`, `--help` | Prints the built-in option summary. |

Optional environment variables:

| Variable | Meaning |
| --- | --- |
| `RESULT_ROOT` | Optional final result root override. If omitted, results are saved to `$PWD/sara-results` inside the repository. |
| `WORK_ROOT` | Temporary scratch root for the current invocation. If omitted, the runner uses `.work/` under the repository and cleans it according to `--keep-intermediate` / `--discard-intermediate`. |

Reproducibility seed policy: all experiment randomness is fixed to the public
seed `2026`. This includes benchmark input generation, FI injection-point
selection, SARA analyzer validation sampling, and GEREM sample-campaign
selection. The seed is fixed in the artifact rather than selected per benchmark
or per method.

## Interactive mode

To use the interactive menu, run `run_experiment.sh` from an interactive terminal and omit `--arch` and `--method`:

```bash
docker run --rm -it \
  --name "sara-interactive-$(date +%s)" \
  -v "$PWD:$PWD" \
  -w "$PWD" \
  sara:cuda11.8-dev \
  bash -lc 'bash ./run_experiment.sh'
```

Inside the container or a local shell at the repository root, you can run the script directly; it defaults to `$PWD/sara-results`:

```bash
bash ./run_experiment.sh
```

Use `↑` / `↓` or `k` / `j` to move through each menu and press `Enter` to select. The interactive flow asks for:

1. Architecture: Turing / RTX2060, Ampere / RTX3070, or both.
2. Experiment method: SARA, SARA + GEREM storage EFM, GEREM storage EFM, FI, or all methods.
3. Application: all applications or one application discovered from `test_apps/`.
4. Whether to overwrite existing selected final results (`--force` behavior).
5. FI run count, only when the selected method includes FI.
6. GEREM campaign size, only when the selected method includes GEREM: GEREM-1000, GEREM-5000, or GEREM-10000.
7. Whether to keep or delete this run's `.work` intermediate files.

You may also pre-fill some values and let the menu ask only for the missing ones. For example:

```bash
bash ./run_experiment.sh --arch turing
```

In non-interactive contexts, pass at least `--arch` and `--method`; otherwise the runner cannot show the menu.

Run `bash ./run_experiment.sh --help` inside the container for the complete option summary.

## Output comparison policy

SARA, FI, GEREM, and the paper-ready summaries use the same exact-output policy: any final output mismatch is classified as SDC, regardless of whether the field is integer or floating-point. Runtime failures, timeouts, invalid executions, and missing required outputs are classified as Detected Unrecoverable Error outcomes.

After each invocation, the runner calls `gen_paper_results.py` to refresh paper-ready artifacts under `sara-results/paper-results/`. The generator writes one Markdown file per experimental table used by the paper and writes the generated figure PDFs/CSV in the same directory. Partial reruns update only the selected application and method while preserving other existing results in the same result root; if some SARA, GEREM, or FI data are missing, the generator prints a warning and records the missing inputs in `sara-results/paper-results/summary.md`.

You can also regenerate these artifacts manually:

```bash
python3 gen_paper_results.py --result-root sara-results
```

Figures 4 and 5 are generated from the public aggregate CSV files in `sara-results/`. Figure 6 reports SARA SDC proof-source attribution and therefore requires SARA intermediate `summary_*.json` files under `.work/`; rerun SARA with `--keep-intermediate` if Figure 6 must be regenerated from a clean checkout.
