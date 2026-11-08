// SARA reference: complete GPU single-query scaled dot-product attention.
#include "../common/benchmark_support.cuh"
#include <cfloat>
namespace sb = sara_bench;
__global__ void attention_logits(const float *key, const float *query, float *logits, int n, int d) {
    int row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= n) return;
    float sum = 0.0f;
    for (int c = 0; c < d; ++c) sum += key[row * d + c] * query[c];
    logits[row] = sum / sqrtf(static_cast<float>(d));
}
__global__ void attention_softmax(const float *logits, float *scores, int n) {
    __shared__ float reduction[256];
    int tid = threadIdx.x;
    float m = -FLT_MAX;
    for (int i = tid; i < n; i += 256) m = fmaxf(m, logits[i]);
    reduction[tid] = m;
    __syncthreads();
    for (int step = 128; step; step >>= 1) {
        if (tid < step) reduction[tid] = fmaxf(reduction[tid], reduction[tid + step]);
        __syncthreads();
    }
    const float maximum = reduction[0];
    __syncthreads();  // all warps must consume the maximum before scratch reuse
    float sum = 0.0f;
    for (int i = tid; i < n; i += 256) { float e = expf(logits[i] - maximum); scores[i] = e; sum += e; }
    reduction[tid] = sum;
    __syncthreads();
    for (int step = 128; step; step >>= 1) {
        if (tid < step) reduction[tid] += reduction[tid + step];
        __syncthreads();
    }
    const float denominator = reduction[0];
    for (int i = tid; i < n; i += 256) scores[i] /= denominator;
}
__global__ void attention_weighted_sum(const float *scores, const float *value, float *out, int n, int d) {
    int c = blockIdx.x * blockDim.x + threadIdx.x;
    if (c >= d) return;
    float sum = 0.0f;
    for (int i = 0; i < n; ++i) sum += scores[i] * value[i * d + c];
    out[c] = sum;
}
int main(int argc, char **argv) {
    {
    if (argc != 3) sb::fail("usage: Attention key_count embedding_width");
    int n = sb::integer(argv[1]), d = sb::integer(argv[2]), count = sb::product(n, d);
    sb::Rng rng;
    std::vector<float> key(count), value(count), query(d);
    for (float &v : key) v = rng.signed_uniform();
    for (float &v : value) v = rng.signed_uniform();
    for (float &v : query) v = 2.0f * rng.signed_uniform();
    sb::DeviceBuffer<float> dk(count), dv(count), dq(d), dl(n), ds(n), dout(d);
    dk.upload(key); dv.upload(value); dq.upload(query);
    attention_logits<<<sb::ceil_div(n, 256), 256>>>(dk.get(), dq.get(), dl.get(), n, d);
    SARA_CUDA(cudaGetLastError());
    attention_softmax<<<1, 256>>>(dl.get(), ds.get(), n);
    SARA_CUDA(cudaGetLastError());
    attention_weighted_sum<<<sb::ceil_div(d, 256), 256>>>(ds.get(), dv.get(), dout.get(), n, d);
    sb::finish_kernel();
    std::vector<float> out = sb::output("out", "f32", dout.get(), d);
    if (sb::validate_cpu()) {
        std::vector<double> score(n), ref(d, 0.0);
        for (int i = 0; i < n; ++i) {
            double dot = 0;
            for (int c = 0; c < d; ++c) dot += static_cast<double>(key[i * d + c]) * query[c];
            score[i] = dot / std::sqrt(static_cast<double>(d));
        }
        double maximum = *std::max_element(score.begin(), score.end()), denominator = 0;
        for (double &v : score) { v = std::exp(v - maximum); denominator += v; }
        for (int i = 0; i < n; ++i)
            for (int c = 0; c < d; ++c) ref[c] += (score[i] / denominator) * value[i * d + c];
        sb::verify_close("out", out, ref, 3e-5, 3e-5);
    }
    } // All DeviceBuffer destructors have completed their cudaFree calls.
    SARA_CUDA(cudaDeviceSynchronize());
    SARA_CUDA(cudaThreadExit());
    if (sb::validate_cpu()) sb::validation_passed("Attention");
    return 0;
}
