// Full GPU LayerNorm, adapted from karpathy/llm.c dev/cuda/layernorm_forward.cu.
// Origin and MIT terms are listed in THIRD_PARTY.md and licenses/.
#include "../common/benchmark_support.cuh"
namespace sb = sara_bench;

__global__ void layernorm_forward_kernel1(float *out, float *mean, float *rstd,
                                         const float *inp, const float *weight, const float *bias,
                                         int rows, int channels) {
    int row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= rows) return;
    const float *x = inp + row * channels;
    float m = 0.0f;
    for (int c = 0; c < channels; ++c) m += x[c];
    m /= channels;
    float variance = 0.0f;
    for (int c = 0; c < channels; ++c) { float d = x[c] - m; variance += d * d; }
    variance /= channels;
    float inverse_std = 1.0f / sqrtf(variance + 1e-5f);
    for (int c = 0; c < channels; ++c)
        out[row * channels + c] = ((x[c] - m) * inverse_std) * weight[c] + bias[c];
    mean[row] = m;
    rstd[row] = inverse_std;
}
int main(int argc, char **argv) {
    {
    if (argc != 4) sb::fail("usage: LayerNorm B T C");
    int B = sb::integer(argv[1]), T = sb::integer(argv[2]), C = sb::integer(argv[3]);
    int rows = sb::product(B, T), count = sb::product(rows, C);
    sb::Rng rng;
    std::vector<float> inp(count), weight(C), bias(C);
    for (float &v : inp) v = rng.signed_uniform();
    for (float &v : weight) v = rng.signed_uniform();
    for (float &v : bias) v = rng.signed_uniform();
    sb::DeviceBuffer<float> di(count), dw(C), db(C), dout(count), dm(rows), dr(rows);
    di.upload(inp); dw.upload(weight); db.upload(bias);
    layernorm_forward_kernel1<<<sb::ceil_div(rows, 128), 128>>>(
        dout.get(), dm.get(), dr.get(), di.get(), dw.get(), db.get(), rows, C);
    sb::finish_kernel();
    std::vector<float> out = sb::output("out", "f32", dout.get(), count);
    std::vector<float> mean = sb::output("mean", "f32", dm.get(), rows);
    std::vector<float> rstd = sb::output("rstd", "f32", dr.get(), rows);
    if (sb::validate_cpu()) {
        std::vector<double> ref(count), rm(rows), rr(rows);
        for (int row = 0; row < rows; ++row) {
            double m = 0, v = 0;
            for (int c = 0; c < C; ++c) m += inp[row * C + c];
            m /= C;
            for (int c = 0; c < C; ++c) { double d = inp[row * C + c] - m; v += d * d; }
            double inverse = 1.0 / std::sqrt(v / C + 1e-5);
            rm[row] = m; rr[row] = inverse;
            for (int c = 0; c < C; ++c) ref[row * C + c] =
                ((inp[row * C + c] - m) * inverse) * weight[c] + bias[c];
        }
        sb::verify_close("out", out, ref); sb::verify_close("mean", mean, rm);
        sb::verify_close("rstd", rstd, rr);
    }
    } // All DeviceBuffer destructors have completed their cudaFree calls.
    SARA_CUDA(cudaDeviceSynchronize());
    SARA_CUDA(cudaThreadExit());
    if (sb::validate_cpu()) sb::validation_passed("LayerNorm");
    return 0;
}
