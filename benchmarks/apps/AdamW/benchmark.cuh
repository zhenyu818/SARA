// Adapted llm.c adamw_kernel2. See THIRD_PARTY.md and licenses/ for origin and MIT terms.
#include "../common/benchmark_support.cuh"
namespace sb = sara_bench;
__device__ inline float adamw_lerp(float start, float end, float weight) {
    return fmaf(weight, end, fmaf(-weight, start, start));
}
__global__ void adamw_kernel2(float *params, const float *grads, float *m, float *v, int count,
                             float rate, float beta1, float beta2, float correction1,
                             float correction2, float eps, float decay) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= count) return;
    float grad = grads[i], first = adamw_lerp(grad, m[i], beta1);
    float second = adamw_lerp(grad * grad, v[i], beta2);
    m[i] = first; v[i] = second;
    params[i] -= rate * ((first / correction1) / (sqrtf(second / correction2) + eps) + decay * params[i]);
}
int main(int argc, char **argv) {
    {
    if (argc != 3) sb::fail("usage: AdamW parameter_count timestep");
    int n = sb::integer(argv[1]), step = sb::integer(argv[2]);
    sb::Rng rng; std::vector<float> p(n), g(n), m(n), v(n);
    for (float &x : p) x = rng.signed_uniform();
    for (float &x : g) x = rng.signed_uniform();
    for (float &x : m) x = 0.1f * rng.signed_uniform();
    for (float &x : v) x = 0.01f + 0.1f * rng.uniform();
    const float rate = 1e-3f, b1 = 0.9f, b2 = 0.999f, eps = 1e-8f, decay = 0.01f;
    float c1 = 1.0f - powf(b1, static_cast<float>(step)), c2 = 1.0f - powf(b2, static_cast<float>(step));
    sb::DeviceBuffer<float> dp(n), dg(n), dm(n), dv(n); dp.upload(p); dg.upload(g); dm.upload(m); dv.upload(v);
    adamw_kernel2<<<sb::ceil_div(n,256),256>>>(dp.get(),dg.get(),dm.get(),dv.get(),n,rate,b1,b2,c1,c2,eps,decay);
    sb::finish_kernel();
    std::vector<float> po=sb::output("params","f32",dp.get(),n), mo=sb::output("m","f32",dm.get(),n), vo=sb::output("v","f32",dv.get(),n);
    if(sb::validate_cpu()) {
        std::vector<double> rp(n),rm(n),rv(n);
        for(int i=0;i<n;++i) {
            rm[i]=static_cast<double>(b1)*m[i]+(1.0-static_cast<double>(b1))*g[i];
            rv[i]=static_cast<double>(b2)*v[i]+(1.0-static_cast<double>(b2))*static_cast<double>(g[i])*g[i];
            rp[i]=p[i]-static_cast<double>(rate)*((rm[i]/c1)/(std::sqrt(rv[i]/c2)+eps)+static_cast<double>(decay)*p[i]);
        }
        sb::verify_close("params",po,rp);sb::verify_close("m",mo,rm);sb::verify_close("v",vo,rv);
    }
    } // All DeviceBuffer destructors have completed their cudaFree calls.
    SARA_CUDA(cudaDeviceSynchronize());
    SARA_CUDA(cudaThreadExit());
    if (sb::validate_cpu()) sb::validation_passed("AdamW");
    return 0;
}
