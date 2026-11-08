# SARA

SARA assesses transient single-bit faults in simulated GPU storage structures. It records a fault-free PTX execution, propagates output relevance and execution-validity evidence backward through recorded value versions, and maps that evidence to physical register, shared-memory, and cache bit-cycle lifetimes. A whole-space run returns Masked, silent data corruption (SDC), detected unrecoverable error (DUE), and Unknown mass. A point query projects the same model onto explicitly identified sampled sites.

The repository includes serial SARA, a parallel input-processing implementation for a complete tiny language model, a GEREM storage baseline, and the gpuFI-4 injection port to GPGPU-Sim 4.2. GEREM preserves native error-flow modes and SDC probabilities. These implementations have separate Python namespaces so one method never uses another method's predictions.

Only the current result-producing implementation families are included. Earlier support layers that remain imported are implementation dependencies, not selectable historical releases. `provenance/source-identities.json` records original execution-file hashes and distributed-file hashes. Packaging changes normalize module names, paths, comments, and administrative resource admission. The predictor rules and numerical result values are retained. The serial core also includes the generic correction modules that were loaded from an external source directory during the recorded runs.

## Layout

```text
sara/serial/       serial model, trace inputs, mapping and aggregation
sara/parallel/     parallel parsing, common model rules and full-model entry
gerem/            EFM/SIC storage model and dependency-keyed serial reuse
fi/               pinned native patch, FI dependency routes and dispatchers
benchmarks/       fixed workloads, small fixtures and registry
configs/          SM75 and SM86 configurations
scripts/          build, collection, execution, pairing and summary tools
data/             selected numerical CSV datasets, with column definitions
tests/            small semantic regression checks
environment/      pinned container and dependencies
licenses/         original third-party license texts
provenance/       execution identities, source mapping and portability scope
```

## Environment and build

Use Linux with Docker Engine, the `runc` runtime, and cgroup v2. A GPU is neither required nor exposed. The build uses the pinned CUDA 11.8 development image on Ubuntu 20.04, GCC 9.4, Python 3.8, and GPGPU-Sim 4.2. Python dependencies are specified under `environment/`. A Linux filesystem is recommended for execution outputs.

```bash
git clone --recurse-submodules https://github.com/zhenyu818/SARA.git
cd SARA
docker build -t sara:local -f environment/Dockerfile .
python3 scripts/run_checks.py --image sara:local
python3 scripts/check_data.py
python3 scripts/verify_files.py
```

The container build materializes the fixed upstream simulator, applies the port, selects the recorded parser sources, and builds from source. Download and compilation can take several minutes and require several GiB. The original parser actions are used instead of generating a different parser with an arbitrary installed Bison version. No prebuilt simulator library is downloaded.

For a non-container source inspection or materialization:

```bash
python3 scripts/prepare_simulator.py --output work/simulator
```

`work/simulator` must not exist. Running predictions still requires a bounded CPU-only container.

## Quick start

Run the fixed small GEMM workload, collect RF and cache observations, prepare its inputs, and execute the current serial whole model across all three applicable components:

```bash
python3 scripts/run.py --method sara --application GEMM --architecture SM75 \
  --image sara:local --cpus 4 --memory-gib 8 --output work/gemm-sm75-sara
```

Compilation is outside the workflow clock. Collection and prediction use separate consecutive containers, with newly collected inputs mounted read-only for prediction. An existing output directory is never overwritten. Inspect `complete.json`, the per-stage execution receipts, and `consume/*-aggregate.json`; a started process or a partial directory is not completion. This small workflow takes roughly two minutes on the verification machine. It does not launch FI or GEREM.

The `--cpus` and `--memory-gib` flags set real Docker limits. Memory plus swap is fixed to the same value, giving zero additional swap; `NVIDIA_VISIBLE_DEVICES=void` and explicit `runc` are required. Reference measurements used 64 CPU cores and 448 GiB. Smaller profiles are for functional checks, not comparable performance measurements. Keep adequate disk reserve for newly generated traces and logs; the runner's minimum-space check is only a small-example admission check.

## Complete execution routes

`benchmarks/registry.json` fixes the 14 application inputs, both architectures, applicable components, deterministic fixture paths, and complete output checksums. Use its application names with `scripts/run.py`. All 28 application/architecture groups are represented. Shared memory is omitted only for workloads with no actual shared allocation.

### Canonical space and sampling

Generate the neutral storage populations before paired or probabilistic evaluation:

```bash
python3 scripts/run.py --method population --application GEMM --architecture SM75 \
  --image sara:local --cpus 64 --memory-gib 448 --output work/gemm-sm75-space
```

The result has a component directory containing the capture, `inventory.json`, and immutable `manifest.json`. `FaultPopulation` canonicalizes the physical coordinates and records the population fingerprint and complete mass. Sampling uses seed 2026, SHA-256 rejection sampling, independent draw identifiers, and replacement. It retains legal duplicate coordinates. Smaller budgets select the original prefix; they do not reset identifiers. Newly built binaries must be checked against the registry's output hashes. A changed binary or population fingerprint starts a different experiment and must not be silently joined to an older result.

The selected aggregate datasets do not contain historical per-draw manifests. Reconstructing a campaign requires generating its canonical inputs with the pinned executable and environment. Exact historical byte identities are distinct from a new source build's identities; inspect them before asserting identical sampled sites.

### FI

```bash
python3 scripts/run.py --method fi --application GEMM --architecture SM75 \
  --component rf --budget 10000 --masters work/gemm-sm75-space/result \
  --image sara:local --cpus 64 --memory-gib 448 --output work/gemm-sm75-fi-rf
```

Repeat for each actual component and required workload. `fi/materialize.py` assembles an explicitly admitted FI dependency route; `fi/route-map.json` records which retained route generated the existing conditions and append segments. The new-campaign runner uses its retained dispatch core. Original append adapters and their source bindings remain distinguishable. A new 200K FI campaign is not part of this workflow.

The native hook validates application and consumption receipts separately. The oracle compares all declared output bytes. The FI dispatcher uses as many workers as the declared CPU limit, matching the 64-worker reference when `--cpus 64` is selected. The simulation watchdog is ten times the measured fault-free cycles. An administrative wall timeout or network/storage failure leaves an unfinished task rather than manufacturing DUE. The supplied FI-10K timings are cumulative completed-prefix timings. Fresh FI runs can be expensive and generate large logs; launch them explicitly, with sufficient capacity. No FI campaign is started by building, testing imports, or checking the CSVs.

### SARA whole and point modes

The quick-start command is the full grouped serial whole route. Repeat it for each registry group, once per application and architecture. `script.method_group.sara_group.evaluate_own_inputs` owns common reverse analysis and each physical projection. The grouped driver keeps necessary preparation, aggregation, persistence, and cleanup inside the method boundary.

For explicit point queries, use the same current grouped evaluator with an additional classified-region export and exact projection onto the canonical sampled sites:

```bash
python3 scripts/query.py --prepared work/gemm-sm75-sara/prepared \
  --masters work/gemm-sm75-space/result --budget 10000 --image sara:local \
  --cpus 4 --memory-gib 8 --output work/gemm-sm75-points
```

This command reads the completed immutable model inputs, reruns the same generic grouped evaluator while retaining regions, and then queries those regions. The extra run and export are separate from the aggregate performance clock. It reads no FI labels. The projection checks complete population equivalence and preserves the original master, site, and draw identities. Do not substitute older classified regions after changing support rules or population identity.

### GEREM

```bash
python3 scripts/run.py --method gerem --application GEMM --architecture SM75 \
  --budget 10000 --masters work/gemm-sm75-space/result \
  --image sara:local --cpus 64 --memory-gib 448 --output work/gemm-sm75-gerem-10000
```

Use fresh independent outputs for 1K, 5K, 10K, and 200K budgets. Each run pays for its own collection and preparation. Group-local input decoding, storage-access indices, CFGs, and SIC solutions may be reused only when their full dependency identity agrees; construction time and memory remain included. No parallel GEREM analysis is used.

The storage model is a reimplementation, with explicit assumptions where the original method is underspecified. Its compatibility rule retains dirty-writeback facts but does not treat writeback alone as an independent data-corruption consumer. A subsequent read remains a consumer; overwritten errors are handled by their real lifetime. This differs from a model in which writeback itself is sufficient corruption evidence. The baseline does not use SARA numerical propagation or FI labels. Independent DUE is unavailable. Unsupported inputs and mappings remain separate from a normal EFM or probability.

The 200K sampler preserves the original first 10K draws and generates another 190K using the same rule and distinct draw identifiers. It does not cycle the original list. Its results concern execution cost; no 200K FI accuracy reference is supplied.

Export native GEREM point probabilities separately from its aggregate performance run:

```bash
python3 scripts/query.py --method gerem --prepared work/gemm-sm75-gerem-10000/prepared \
  --masters work/gemm-sm75-space/result --budget 10000 --image sara:local \
  --output work/gemm-sm75-gerem-points
```

### Tiny language model

The workload is the complete five-layer Stories260K model, batch one, fixed token `1`, and all 512 logits. Fetch the immutable checkpoint separately:

```bash
python3 scripts/fetch_model.py --output work/model/stories260K.bin
```

`sara/parallel/script/parallel_stream/` contains the model's actual parallel input context and evaluator. `sara/parallel/entry/run_model.py` retains the full-model entry and its input/qualification bindings. Prepared component descriptors, their closure proofs, the full-output qualification, and the checkpoint are explicit read-only request inputs. It uses eight parser processes; global reverse propagation remains serial. It requires substantially more memory than the small example. The retained complete peak is approximately 138 GiB. The completed active workflows are approximately five hours per architecture. These are separate from the 14-application serial comparisons.

### Pairing and summaries

`script.execution.campaign`, `sara_batch_campaign`, and `validation_records` preserve campaign, site, draw, and population identities when joining new results. Reject joins with different master hashes or coordinate definitions. `scripts/metrics.py` implements jointly known SARA comparisons, complete-population proportions, native GEREM probability scores, and equal-condition aggregation. Repeated draws remain repeated observations.

```bash
python3 scripts/compare.py --fi-root work/gemm-sm75-fi-rf/result/rf-10000 \
  --sara work/gemm-sm75-points/rf/index.json \
  --gerem work/gemm-sm75-gerem-points/rf/index.json \
  --whole work/gemm-sm75-sara/consume/rf-aggregate.json \
  --application GEMM --architecture SM75 --component rf \
  --output work/comparisons/gemm-sm75-rf.json
python3 scripts/summarize.py work/comparisons/*.json --output work/comparison-summary.csv
python3 scripts/check_data.py --output work/data-check.json
```

Install `environment/requirements.txt` in a separate Python environment if using the low-level import-dependent comparison tools outside the image. The build and bounded execution routes install these dependencies inside the image.

See [data/README.md](data/README.md) for every supplied CSV, denominator, unit, and aggregation rule. The download intentionally contains only the selected numerical datasets. Recomputing per-draw classifications requires freshly generated inputs and predictions.

## Scope and limitations

Supported local instruction semantics cover the operations encountered in the admitted workloads, with explicit operand widths, signed division, floating-point rounding, conversion, carry, selection, and supported shuffle behavior. A baseline local re-evaluation that cannot reproduce the recorded result is a support failure. Unsupported instructions are not silently treated as Masked.

Local sensitivity composition and control changes retain model approximations. Generic bounded correlated-value handling does not enumerate arbitrary altered executions. Changed-address values absent from the recorded memory image, unresolved alternate execution values, and some cache Tag cases can remain Unknown. No extrapolation from these short fixed inputs establishes long-context model scalability. Cache behavior is the retained functional-snapshot injection model; erroneous dirty writebacks are discarded as independent functional propagation in that model.

## Verification and licenses

```bash
python3 scripts/run_checks.py --image sara:local
python3 scripts/check_data.py
```

Run semantic checks inside the bounded image for the pinned runtime. The release verification records distinguish imports, compilation, the complete small grouped example, summary arithmetic, and unexecuted expensive campaigns. Regression agreement is not an FI accuracy guarantee.

See [THIRD_PARTY.md](THIRD_PARTY.md), [LICENSE](LICENSE), and the original texts under `licenses/`. External dependencies are pinned or obtained from their stated source; credentials and host-specific connection settings are never part of the interface.
