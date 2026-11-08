// NVIDIA tutorial stencil pattern, radius 7; zero boundaries and guarded partial blocks.
#include "../common/benchmark_support.cuh"
namespace sb = sara_bench;
__global__ void stencil_1d(const int32_t *input,int32_t *output,int length) {
    __shared__ int32_t tile[256+14];
    int tid=threadIdx.x,index=blockIdx.x*256+tid,local=tid+7;
    tile[local]=index<length?input[index]:0;
    if(tid<7){int left=index-7,right=index+256;tile[local-7]=left>=0&&left<length?input[left]:0;tile[local+256]=right<length?input[right]:0;}
    __syncthreads();
    if(index<length){int32_t sum=0;for(int offset=-7;offset<=7;++offset)sum+=tile[local+offset];output[index]=sum;}
}
int main(int argc,char **argv) {
    {
    if(argc!=2)sb::fail("usage: Stencil1D length");int n=sb::integer(argv[1]);sb::Rng rng;
    std::vector<int32_t>input(n);for(int32_t &v:input)v=static_cast<int32_t>(rng.next()%65)-32;
    sb::DeviceBuffer<int32_t>di(n),dout(n);di.upload(input);stencil_1d<<<sb::ceil_div(n,256),256>>>(di.get(),dout.get(),n);sb::finish_kernel();
    std::vector<int32_t>out=sb::output("out","i32",dout.get(),n);
    if(sb::validate_cpu()){std::vector<int32_t>ref(n,0);for(int i=0;i<n;++i)for(int j=std::max(0,i-7);j<std::min(n,i+8);++j)ref[i]+=input[j];sb::verify_equal("out",out,ref);}
    } // All DeviceBuffer destructors have completed their cudaFree calls.
    SARA_CUDA(cudaDeviceSynchronize());
    SARA_CUDA(cudaThreadExit());
    if (sb::validate_cpu()) sb::validation_passed("Stencil1D");
    return 0;
}
