// Stable full GPU row softmax reference; supports row lengths beyond one warp.
#include "../common/benchmark_support.cuh"
#include <cfloat>
namespace sb = sara_bench;
__global__ void softmax_kernel(const float *input,float *output,int rows,int columns) {
    __shared__ float scratch[256];
    int row=blockIdx.x,tid=threadIdx.x;if(row>=rows)return;
    float maximum=-FLT_MAX;
    for(int c=tid;c<columns;c+=256)maximum=fmaxf(maximum,input[row*columns+c]);
    scratch[tid]=maximum;__syncthreads();
    for(int step=128;step;step>>=1){if(tid<step)scratch[tid]=fmaxf(scratch[tid],scratch[tid+step]);__syncthreads();}
    maximum=scratch[0];__syncthreads();
    float sum=0;
    for(int c=tid;c<columns;c+=256){float e=expf(input[row*columns+c]-maximum);output[row*columns+c]=e;sum+=e;}
    scratch[tid]=sum;__syncthreads();
    for(int step=128;step;step>>=1){if(tid<step)scratch[tid]+=scratch[tid+step];__syncthreads();}
    float denominator=scratch[0];for(int c=tid;c<columns;c+=256)output[row*columns+c]/=denominator;
}
int main(int argc,char **argv) {
    {
    if(argc!=3 && argc!=4)sb::fail("usage: Softmax rows columns [correctness_profile=1]");
    int rows=sb::integer(argv[1]),cols=sb::integer(argv[2]),count=sb::product(rows,cols);
    int profile=argc==4?sb::integer(argv[3]):0;
    if(profile && (profile!=1 || !sb::validate_cpu() || rows<2 || cols<2))
        sb::fail("softmax profile 1 requires CPU correctness validation and at least two rows/columns");
    sb::Rng rng;std::vector<float>input(count);
    if(profile) {
        // Exact binary fractions around offsets that overflow/underflow an
        // unshifted FP32 exp. The normal campaign's RNG input is unchanged.
        for(int r=0;r<rows;++r)for(int c=0;c<cols;++c)
            input[r*cols+c]=(r%2? -120.0f:100.0f)+static_cast<float>(c%17-8)*0.125f;
        std::fprintf(stderr,"SOFTMAX_INPUT_PROFILE version=1 name=stability_offsets rows=%d columns=%d\n",rows,cols);
    } else {
        for(float &v:input)v=12.0f*rng.signed_uniform();
    }
    sb::DeviceBuffer<float>di(count),dout(count);di.upload(input);softmax_kernel<<<rows,256>>>(di.get(),dout.get(),rows,cols);sb::finish_kernel();
    std::vector<float>out=sb::output("out","f32",dout.get(),count);
    if(sb::validate_cpu()) {
        std::vector<double>ref(count);for(int r=0;r<rows;++r){double maximum=input[r*cols],sum=0;for(int c=1;c<cols;++c)maximum=std::max(maximum,static_cast<double>(input[r*cols+c]));for(int c=0;c<cols;++c){ref[r*cols+c]=std::exp(input[r*cols+c]-maximum);sum+=ref[r*cols+c];}for(int c=0;c<cols;++c)ref[r*cols+c]/=sum;}
        sb::verify_close("out",out,ref,2e-6,2e-5);
        for(int r=0;r<rows;++r) {
            double sum=0;for(int c=0;c<cols;++c){if(out[r*cols+c]<0)sb::fail("negative softmax probability");sum+=out[r*cols+c];}
            if(!std::isfinite(sum) || std::fabs(sum-1.0)>3e-6)sb::fail("softmax row does not normalize");
        }

    }
    } // All DeviceBuffer destructors have completed their cudaFree calls.
    SARA_CUDA(cudaDeviceSynchronize());
    SARA_CUDA(cudaThreadExit());
    if (sb::validate_cpu()) sb::validation_passed("Softmax");
    return 0;
}
