# Third-party components

The root MIT license covers the SARA-authored implementation and integration code. It does not replace any third-party terms. Original notices are retained in `licenses/` and in the applicable source headers.

| Component | Origin | Distribution and terms |
|---|---|---|
| GPGPU-Sim | [gpgpu-sim_distribution](https://github.com/gpgpu-sim/gpgpu-sim_distribution), v4.2.0, commit `0e39753a623978eb37bf044b21fde1a5909bff03` | Pinned submodule plus source patch. `licenses/gpgpusim.txt` and upstream copyright notices apply. |
| gpuFI-4 | [caldi-uoa/gpuFI-4](https://github.com/caldi-uoa/gpuFI-4) | Ported injection behavior in the simulator patch; original terms in `licenses/gpufi.txt`. |
| GE-SpMM | [hgyhungry/ge-spmm](https://github.com/hgyhungry/ge-spmm), `spmm_test0` | Adapted fixed workload, MIT, `licenses/GESpmm-cuda.txt`. |
| LayerNorm and AdamW | [karpathy/llm.c](https://github.com/karpathy/llm.c) CUDA kernels | Adapted complete workload wrappers, MIT, corresponding files in `licenses/`. |
| MatrixMultiplication | [NVIDIA/cuda-samples](https://github.com/NVIDIA/cuda-samples), matrix multiplication | Guarded edge tiles and explicit complete output, NVIDIA permissive terms in `licenses/MatrixMultiplication-cuda.txt`. |
| Pathfinder | [ivanradanov/rodinia](https://github.com/ivanradanov/rodinia) | Adapted multi-launch workload; original University of Virginia terms in `licenses/Pathfinder-cuda.txt`. |
| Render | [Manan1406/RayTracer-CUDA](https://github.com/Manan1406/RayTracer-CUDA) | Adapted compact ray-casting workload, MIT, `licenses/Render-cuda.txt`. |
| Tiny language-model CUDA computation | [rogerallen/llama2.cu](https://github.com/rogerallen/llama2.cu), commit `d347208fcd3d6f07b2a5b3182bf0dfc01ccf2dbf` | Full forward computation with explicit simulator-compatible adaptations; MIT in `licenses/LLM_TinyStories260K-cuda.txt`. |
| Tiny language-model CPU computation | [karpathy/llama2.c](https://github.com/karpathy/llama2.c) | MIT terms in `licenses/LLM_TinyStories260K-cpu.txt`. Retained notices do not imply that a CPU reference is used as a fault predictor. |
| Stories260K weights | [karpathy/tinyllamas](https://huggingface.co/karpathy/tinyllamas) | Obtained separately by `scripts/fetch_model.py`, which checks a fixed immutable identifier, size, and SHA-256. Weights are not redistributed here. Consult the source's current terms before use. |
| nlohmann JSON | [nlohmann/json](https://github.com/nlohmann/json), v3.11.3 | Fetched as a pinned header with checksum during materialization; its MIT notice remains in that header. |
| zlib compatibility headers | zlib 1.2.11 | Original embedded license retained in the distributed patch. Version-macro labels are made neutral without changing their numerical values. |
| Generated lexers and parsers | Flex and GNU Bison | Recorded C sources retain their original notices and Bison's parser exception. GNU GPL v3 is retained in `licenses/GPL-3.0.txt`. Debug-source paths, technical comments, and a lexer column macro name are normalized. Parser actions and tables are preserved. |

Attention, Convolution1D, Dijkstra, GELU, GEMM, MatrixFactorization, Softmax, Stencil1D, and the common workload harness are compact SARA-authored implementations. Their evaluated dimensions, arguments, fixtures, and observable outputs are fixed in `benchmarks/registry.json`; they should be identified by those definitions rather than assumed to be unmodified external suites.

No full upstream checkout, prebuilt simulator library, CUDA toolkit, model checkpoint, or unrelated sample collection is included in the owned source tree. The submodule resolves the original simulator separately. Original third-party licenses are reproduced verbatim, including their reference requirements.
