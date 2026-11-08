// Golden and injected execution deliberately compile the same implementation.
#if __has_include("../benchmark.cuh")
#include "../benchmark.cuh"
#elif __has_include("test_apps/LayerNorm/benchmark.cuh")
#include "test_apps/LayerNorm/benchmark.cuh"
#else
#error "Benchmark headers missing: retain test_apps/ in the experiment workspace"
#endif
