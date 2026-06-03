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

The runnable experiment image is built from this repository's Dockerfile. Docker cannot pull a final image directly from a Dockerfile; it can only pull images that have already been published to a registry. The commands below first pull the CUDA base image used by the Dockerfile and then build the local SARA experiment image.

```bash
BASE_IMAGE=nvidia/cuda:11.8.0-devel-ubuntu20.04
IMAGE=sdc-gerem:cuda11.8-dev
RESULT_ROOT="$PWD/../sara-results"

mkdir -p "$RESULT_ROOT"
docker pull "$BASE_IMAGE"
docker build --pull -t "$IMAGE" .
```

If you later publish the SARA experiment image to Docker Hub or GHCR, replace `IMAGE` with that registry-qualified tag and use `docker pull "$IMAGE"` instead of the local build step.

Run SARA for all applications on both supported architectures:

```bash
docker run --rm -it \
  --name "sara-run-$(date +%s)" \
  -v "$PWD:$PWD" \
  -w "$PWD" \
  -e RESULT_ROOT="$RESULT_ROOT" \
  "$IMAGE" \
  bash -lc 'bash ./run_experiment.sh --arch both --method sara --app all --force --discard-intermediate'
```

Results are organized as:

```text
$RESULT_ROOT/<architecture>/<method>/<application>/
$RESULT_ROOT/<architecture>/compare/
```

For example, SARA results for AdamW on Turing are written under:

```text
$RESULT_ROOT/Turing-RTX2060/SARA/AdamW/
```

## Running the full experiment families

Run FI for all applications on all supported architectures:

```bash
docker run --rm -it \
  --name "fi-run-$(date +%s)" \
  -v "$PWD:$PWD" \
  -w "$PWD" \
  -e RESULT_ROOT="$RESULT_ROOT" \
  "$IMAGE" \
  bash -lc 'bash ./run_experiment.sh --arch both --method fi --app all --runs 1000 --force --discard-intermediate'
```

Run GEREM-all for all applications on all supported architectures:

```bash
docker run --rm -it \
  --name "gerem-run-$(date +%s)" \
  -v "$PWD:$PWD" \
  -w "$PWD" \
  -e RESULT_ROOT="$RESULT_ROOT" \
  "$IMAGE" \
  bash -lc 'bash ./run_experiment.sh --arch both --method gerem-all --app all --gerem-runs all --force --discard-intermediate'
```

Run SARA, GEREM-all, and FI in one command:

```bash
docker run --rm -it \
  --name "all-run-$(date +%s)" \
  -v "$PWD:$PWD" \
  -w "$PWD" \
  -e RESULT_ROOT="$RESULT_ROOT" \
  "$IMAGE" \
  bash -lc 'bash ./run_experiment.sh --arch both --method all --app all --runs 1000 --gerem-runs all --force --discard-intermediate'
```

The full FI and GEREM-all campaigns can take a long time. For a quick functional check, run one SARA smoke test:

```bash
docker run --rm -it \
  --name "sara-smoke-$(date +%s)" \
  -v "$PWD:$PWD" \
  -w "$PWD" \
  -e RESULT_ROOT="$RESULT_ROOT" \
  "$IMAGE" \
  bash -lc 'bash ./run_experiment.sh --arch turing --method sara --app AdamW --smoke --force --discard-intermediate'
```

## Runner options

```text
--arch turing|ampere|both
--method sara|sara-gerem-all|fi|gerem-all|all
--app NAME|all
--runs N
--gerem-runs N|all
--skip-build
--keep-intermediate
--discard-intermediate
--keep-build
--force
--smoke
```

Run `bash ./run_experiment.sh --help` inside the container for the complete option summary.

## Output comparison policy

SARA, FI, and the public comparison reports use the same application output-equivalence policy. Floating-point result fields use the fixed benchmark tolerance implemented by the repository utilities, and integer or fixed-width result fields use exact equality. Runtime failures, timeouts, invalid executions, and missing required outputs are classified as Detected Unrecoverable Error outcomes.

After each invocation, the runner refreshes comparison reports from the current result root. Partial reruns update only the selected application and method while preserving other existing results in the same result root.
