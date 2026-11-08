// Self-contained reference implementation of tanh-approximate GELU plus bias.
#include "../common/benchmark_support.cuh"
namespace sb = sara_bench;
__global__ void gelu_bias_loop(float *values,const float *bias,int count,int channels) {
    int i=blockIdx.x*blockDim.x+threadIdx.x;
    if(i>=count)return;
    float x=values[i]+bias[i%channels];
    values[i]=0.5f*x*(1.0f+tanhf(0.7978845608028654f*(x+0.044715f*x*x*x)));
}
int main(int argc,char **argv) {
    {
    if(argc!=4) sb::fail("usage: Gelu batch sequence_length hidden_width");
    int batch=sb::integer(argv[1]),time=sb::integer(argv[2]),channels=sb::integer(argv[3]);
    int count=sb::product(sb::product(batch,time),channels);sb::Rng rng;
    std::vector<float> input(count),bias(channels);
    for(float &v:input)v=3.0f*rng.signed_uniform();for(float &v:bias)v=0.5f*rng.signed_uniform();
    sb::DeviceBuffer<float> di(count),db(channels);di.upload(input);db.upload(bias);
    gelu_bias_loop<<<sb::ceil_div(count,256),256>>>(di.get(),db.get(),count,channels);sb::finish_kernel();
    std::vector<float> out=sb::output("out","f32",di.get(),count);
    if(sb::validate_cpu()) {
        std::vector<double> ref(count);
        for(int i=0;i<count;++i) {double x=static_cast<double>(input[i])+bias[i%channels];ref[i]=0.5*x*(1+std::tanh(std::sqrt(2.0/3.14159265358979323846)*(x+0.044715*x*x*x)));}
        sb::verify_close("out",out,ref);
    }
    } // All DeviceBuffer destructors have completed their cudaFree calls.
    SARA_CUDA(cudaDeviceSynchronize());
    SARA_CUDA(cudaThreadExit());
    if (sb::validate_cpu()) sb::validation_passed("Gelu");
    return 0;
}
