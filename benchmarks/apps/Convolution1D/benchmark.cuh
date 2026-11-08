// Textbook-inspired reference: int32 zero-padded convolution, odd masks <= 9.
#include "../common/benchmark_support.cuh"
namespace sb = sara_bench;
__constant__ int32_t convolution_mask[10];
__global__ void conv1d_tiled_caching(const int32_t *input, int32_t *output, int length, int mask_width) {
    __shared__ int32_t tile[256];
    int tid=threadIdx.x,i=blockIdx.x*256+tid;
    tile[tid]=i<length?input[i]:0;
    __syncthreads();
    if(i>=length) return;
    int sum=0,begin=blockIdx.x*256;
    for(int j=0;j<mask_width;++j) {
        int index=i+j-mask_width/2;
        if(index>=0&&index<length) {
            int value=index>=begin&&index<begin+256?tile[index-begin]:input[index];
            sum+=value*convolution_mask[mask_width-1-j];
        }
    }
    output[i]=sum;
}
int main(int argc,char **argv) {
    {
    if(argc!=3) sb::fail("usage: Convolution1D input_length odd_mask_width");
    int n=sb::integer(argv[1]),k=sb::integer(argv[2]);
    if(k>9||!(k&1)) sb::fail("mask width must be an odd integer in [1,9]");
    sb::Rng rng;std::vector<int32_t> input(n),mask(k);
    for(int32_t &v:input) v=static_cast<int32_t>(rng.next()%17)-8;
    for(int j=0;j<k;++j) mask[j]=static_cast<int32_t>((j*3+1)%7)-3;
    sb::DeviceBuffer<int32_t> di(n),dout(n);di.upload(input);
    SARA_CUDA(cudaMemcpyToSymbol(convolution_mask,mask.data(),k*sizeof(int32_t)));
    conv1d_tiled_caching<<<sb::ceil_div(n,256),256>>>(di.get(),dout.get(),n,k);sb::finish_kernel();
    std::vector<int32_t> out=sb::output("out","i32",dout.get(),n);
    if(sb::validate_cpu()) {
        std::vector<int32_t> ref(n,0);
        for(int i=0;i<n;++i) for(int j=0;j<k;++j) {
            int index=i+k/2-j;if(index>=0&&index<n) ref[i]+=mask[j]*input[index];
        }
        sb::verify_equal("out",out,ref);
    }
    } // All DeviceBuffer destructors have completed their cudaFree calls.
    SARA_CUDA(cudaDeviceSynchronize());
    SARA_CUDA(cudaThreadExit());
    if (sb::validate_cpu()) sb::validation_passed("Convolution1D");
    return 0;
}
