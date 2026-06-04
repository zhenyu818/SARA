# SARA Artifact Runner

This repository contains the runnable artifact for **SARA: Semantic Backward Derivation for GPU Storage Resilience Assessment**. It provides one public entry point, `run_experiment.sh`, for running and comparing three storage-fault assessment paths:

- **SARA**: semantic backward derivation over modeled GPU storage fault sites.
- **GEREM-all**: the GEREM storage Early Fault Manifestation baseline over the full modeled campaign space.
- **FI**: storage fault injection used as the reference outcome source.

The evaluated storage components are the register file, shared memory, L1 data cache, and L2 cache. The runner supports the Turing RTX2060 and Ampere RTX3070 configurations and the benchmark applications under `test_apps/`.

## Repository layout

- `run_experiment.sh` — interactive and non-interactive experiment runner.
- `script/SARA/` — SARA analysis and application runner.
- `script/GEREM/` — GEREM-all storage campaign runner.
- `script/FI/` — storage fault-injection runner.
- `script/common/` — shared campaign, result-layout, and output-comparison utilities.
- `test_apps/` — CUDA benchmark applications used by the experiments.
- `configs/` — GPU architecture configurations used by the runner.

## Quick start

The runnable experiment image is built from this repository's Dockerfile. Docker cannot pull a final image directly from a Dockerfile; it can only pull images that have already been published to a registry. The commands below first pull the CUDA base image used by the Dockerfile and then build the local SARA experiment image. All runs below write results to the repository-local `sara-results/` directory, which is already present in the artifact.

```bash
docker pull nvidia/cuda:11.8.0-devel-ubuntu20.04
docker build --pull -t sara:cuda11.8-dev .
```

If you later publish the SARA experiment image to Docker Hub or GHCR, replace `sara:cuda11.8-dev` with that registry-qualified tag and use `docker pull <registry-qualified-tag>` instead of the local build step.

Run SARA for all applications on both supported architectures:

```bash
docker run --rm -it \
  --name "sara-run-$(date +%s)" \
  -v "$PWD:$PWD" \
  -w "$PWD" \
  -e RESULT_ROOT="$PWD/sara-results" \
  sara:cuda11.8-dev \
  bash -lc 'bash ./run_experiment.sh --arch both --method sara --app all --force --discard-intermediate'
```

Results are organized as:

```text
$PWD/sara-results/<architecture>/<method>/<application>/
$PWD/sara-results/<architecture>/compare/
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
  -e RESULT_ROOT="$PWD/sara-results" \
  sara:cuda11.8-dev \
  bash -lc 'bash ./run_experiment.sh --arch both --method fi --app all --runs 1000 --force --discard-intermediate'
```

Run GEREM-all for all applications on all supported architectures:

```bash
docker run --rm -it \
  --name "gerem-run-$(date +%s)" \
  -v "$PWD:$PWD" \
  -w "$PWD" \
  -e RESULT_ROOT="$PWD/sara-results" \
  sara:cuda11.8-dev \
  bash -lc 'bash ./run_experiment.sh --arch both --method gerem-all --app all --gerem-runs all --force --discard-intermediate'
```

Run SARA, GEREM-all, and FI in one command:

```bash
docker run --rm -it \
  --name "all-run-$(date +%s)" \
  -v "$PWD:$PWD" \
  -w "$PWD" \
  -e RESULT_ROOT="$PWD/sara-results" \
  sara:cuda11.8-dev \
  bash -lc 'bash ./run_experiment.sh --arch both --method all --app all --runs 1000 --gerem-runs all --force --discard-intermediate'
```

The full FI and GEREM-all campaigns can take a long time. For a quick functional check, run one SARA smoke test:

```bash
docker run --rm -it \
  --name "sara-smoke-$(date +%s)" \
  -v "$PWD:$PWD" \
  -w "$PWD" \
  -e RESULT_ROOT="$PWD/sara-results" \
  sara:cuda11.8-dev \
  bash -lc 'bash ./run_experiment.sh --arch turing --method sara --app AdamW --smoke --force --discard-intermediate'
```

## Runner options

`run_experiment.sh` can run either non-interactively with command-line options or interactively with an arrow-key menu.

| Option | Meaning |
| --- | --- |
| `--arch turing\|ampere\|both` | Selects the target GPU architecture configuration. `turing` uses the Turing RTX2060 configuration, `ampere` uses the Ampere RTX3070 configuration, and `both` runs the selected experiment family on both configurations. |
| `--method sara\|sara-gerem-all\|fi\|gerem-all\|all` | Selects the experiment family. `sara` runs SARA only; `gerem-all` runs the GEREM-all baseline only; `fi` runs fault injection only; `sara-gerem-all` runs SARA plus GEREM-all; `all` runs SARA, GEREM-all, and FI. |
| `--app NAME\|all` | Selects one benchmark application under `test_apps/` or all applications. If omitted in non-interactive mode, it defaults to `all`. Comparison reports are refreshed from the current result directory after each invocation. |
| `--runs N` | Sets the number of FI trials per storage component. The default is `1000`; `--smoke` changes it to `1`. |
| `--gerem-runs N\|all` | Sets the number of GEREM campaign runs. `all` runs the full GEREM-all campaign and is the default; `--smoke` changes it to `1`. |
| `--skip-build` | Skips the common simulator build. Use only when the required GPGPU-Sim runtime library already exists from a previous preserved build. |
| `--keep-intermediate` | Keeps this invocation's `.work` scratch directories for inspection after completion. This also preserves generated build/native binaries. |
| `--discard-intermediate` | Deletes this invocation's `.work` scratch directories after completion. This is the default behavior. |
| `--keep-build` | Preserves generated build and SARA native binaries after completion, while still allowing scratch-directory cleanup. |
| `--force` | Removes existing selected final results before rerunning. For `--app all`, it removes the selected method directory for that architecture; for one app, it removes only that app's selected method results. |
| `--smoke` | Convenience shortcut for a quick check: `--app AdamW --runs 1 --gerem-runs 1`. |
| `-h`, `--help` | Prints the built-in option summary. |

Environment variables used by the README examples:

| Variable | Meaning |
| --- | --- |
| `RESULT_ROOT` | Final result root. The README Docker commands set it to `$PWD/sara-results`, so results are saved inside the repository. |
| `WORK_ROOT` | Temporary scratch root for the current invocation. If omitted, the runner uses `.work/` under the repository and cleans it according to `--keep-intermediate` / `--discard-intermediate`. |

## Interactive mode

To use the interactive menu, run `run_experiment.sh` from an interactive terminal and omit `--arch` and `--method`:

```bash
docker run --rm -it \
  --name "sara-interactive-$(date +%s)" \
  -v "$PWD:$PWD" \
  -w "$PWD" \
  -e RESULT_ROOT="$PWD/sara-results" \
  sara:cuda11.8-dev \
  bash -lc 'bash ./run_experiment.sh'
```

Inside a container or shell where `RESULT_ROOT` is already set to `$PWD/sara-results`, you can run the script directly:

```bash
bash ./run_experiment.sh
```

Use `↑` / `↓` or `k` / `j` to move through each menu and press `Enter` to select. The interactive flow asks for:

1. Architecture: Turing / RTX2060, Ampere / RTX3070, or both.
2. Experiment method: SARA, SARA + GEREM-all, GEREM-all, FI, or all methods.
3. Application: all applications or one application discovered from `test_apps/`.
4. Whether to overwrite existing selected final results (`--force` behavior).
5. FI run count, only when the selected method includes FI.
6. GEREM campaign count, only when the selected method includes GEREM-all.
7. Whether to keep or delete this run's `.work` intermediate files.

You may also pre-fill some values and let the menu ask only for the missing ones. For example:

```bash
bash ./run_experiment.sh --arch turing
```

In non-interactive contexts, pass at least `--arch` and `--method`; otherwise the runner cannot show the menu.

Run `bash ./run_experiment.sh --help` inside the container for the complete option summary.

## Output comparison policy

SARA, FI, and the public comparison reports use the same application output-equivalence policy. Floating-point result fields use the fixed benchmark tolerance implemented by the repository utilities, and integer or fixed-width result fields use exact equality. Runtime failures, timeouts, invalid executions, and missing required outputs are classified as Detected Unrecoverable Error outcomes.

After each invocation, the runner refreshes comparison reports from the current result root. Partial reruns update only the selected application and method while preserving other existing results in the same result root.
