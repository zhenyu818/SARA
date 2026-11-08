#ifndef SARA_BENCHMARK_SUPPORT_CUH
#define SARA_BENCHMARK_SUPPORT_CUH

#include <cuda_runtime.h>
#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <vector>

namespace sara_bench {
// Leave room for guarded tile/halo index arithmetic in the final partial block.
static const int MAX_INDEX = std::numeric_limits<int>::max() - 1024;
inline void fail(const char *message) {
    std::fprintf(stderr, "BENCHMARK_ERROR %s\n", message);
    std::exit(2);
}
inline void cuda_check(cudaError_t error, const char *expression, int line) {
    if (error != cudaSuccess) {
        std::fprintf(stderr, "CUDA_ERROR line=%d expression=%s error=%s\n",
                     line, expression, cudaGetErrorString(error));
        std::exit(3);
    }
}
#define SARA_CUDA(expression) ::sara_bench::cuda_check((expression), #expression, __LINE__)
inline int integer(const char *text, bool allow_zero = false) {
    char *end = 0;
    errno = 0;
    long value = std::strtol(text, &end, 10);
    if (errno || !end || end == text || *end || value < (allow_zero ? 0 : 1) ||
        value > MAX_INDEX) fail("invalid integer argument");
    return static_cast<int>(value);
}
inline int product(int a, int b) {
    if (a < 0 || b < 0 || (b && a > MAX_INDEX / b))
        fail("dimension product exceeds supported signed-index range");
    return a * b;
}
inline int ceil_div(int value, int divisor) { return value / divisor + (value % divisor != 0); }
inline void finish_kernel() {
    SARA_CUDA(cudaGetLastError());
    SARA_CUDA(cudaDeviceSynchronize());
}
// Fully specified PRNG: independent of the host C/C++ standard-library distribution.
struct Rng {
    uint32_t state;
    explicit Rng(uint32_t seed = 2026u) : state(seed ? seed : 1u) {}
    uint32_t next() {
        uint32_t x = state;
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        state = x;
        return x;
    }
    float uniform() { return static_cast<float>(next() >> 8) * (1.0f / 16777216.0f); }
    float signed_uniform() { return 2.0f * uniform() - 1.0f; }
};
template <typename T> class DeviceBuffer {
    T *pointer_;
    size_t count_;
    DeviceBuffer(const DeviceBuffer &);
    DeviceBuffer &operator=(const DeviceBuffer &);
public:
    explicit DeviceBuffer(size_t count) : pointer_(0), count_(count) {
        if (count > std::numeric_limits<size_t>::max() / sizeof(T)) fail("allocation overflow");
        SARA_CUDA(cudaMalloc(reinterpret_cast<void **>(&pointer_), std::max<size_t>(count, 1) * sizeof(T)));
    }
    ~DeviceBuffer() { if (pointer_) cuda_check(cudaFree(pointer_), "cudaFree", __LINE__); }
    T *get() const { return pointer_; }
    size_t size() const { return count_; }
    void upload(const std::vector<T> &values) {
        if (values.size() != count_) fail("upload shape mismatch");
        if (count_) SARA_CUDA(cudaMemcpy(pointer_, values.data(), count_ * sizeof(T), cudaMemcpyHostToDevice));
    }
};
template <typename T>
inline std::vector<T> output(const char *name, const char *dtype, const T *device, size_t count) {
    const uint32_t endian_probe = 1;
    if (*reinterpret_cast<const unsigned char *>(&endian_probe) != 1)
        fail("raw output protocol requires a little-endian host");
    std::vector<T> values(count);
    if (count) SARA_CUDA(cudaMemcpy(values.data(), device, count * sizeof(T), cudaMemcpyDeviceToHost));
    // The simulator may still print statistics from another host thread.
    // Never hold these locks across a CUDA call: that thread can need stdout
    // before signalling completion. Keep each complete protocol record intact,
    // including outputs larger than stdio's buffer.
    ::flockfile(stdout);
    ::flockfile(stderr);
    std::fflush(stdout);
    std::fprintf(stderr, "\nGPUFI_OUTPUT base=%p bytes=%llu name=%s\n",
                 static_cast<const void *>(device), static_cast<unsigned long long>(count * sizeof(T)), name);
    std::fflush(stderr);
    std::printf("GPUFI_RAW_OUTPUT %s %s %llu ", name, dtype, static_cast<unsigned long long>(count));
    const unsigned char *bytes = reinterpret_cast<const unsigned char *>(values.data());
    for (size_t i = 0; i < count * sizeof(T); ++i) std::printf("%02x", static_cast<unsigned>(bytes[i]));
    std::printf("\n");
    std::fflush(stdout);
    ::funlockfile(stderr);
    ::funlockfile(stdout);
    return values;
}
inline bool validate_cpu() {
    const char *value = std::getenv("SARA_VALIDATE_CPU");
    return value && std::strcmp(value, "1") == 0;
}
template <typename T>
inline void verify_close(const char *name, const std::vector<T> &actual,
                         const std::vector<double> &expected, double atol = 2e-5, double rtol = 2e-5) {
    if (actual.size() != expected.size()) fail("CPU oracle shape mismatch");
    for (size_t i = 0; i < actual.size(); ++i) {
        double got = static_cast<double>(actual[i]), want = expected[i];
        if (!std::isfinite(got) || !std::isfinite(want) ||
            std::fabs(got - want) > atol + rtol * std::fabs(want)) {
            std::fprintf(stderr, "CPU_ORACLE_FAILURE name=%s index=%llu got=%.17g expected=%.17g\n",
                         name, static_cast<unsigned long long>(i), got, want);
            std::exit(4);
        }
    }
}
template <typename T>
inline void verify_equal(const char *name, const std::vector<T> &actual, const std::vector<T> &expected) {
    if (actual != expected) {
        std::fprintf(stderr, "CPU_ORACLE_FAILURE name=%s exact_integer_mismatch\n", name);
        std::exit(4);
    }
}
inline void validation_passed(const char *application) {
    std::fprintf(stderr, "CPU_ORACLE_PASS application=%s\n", application);
}
}  // namespace sara_bench
#endif
