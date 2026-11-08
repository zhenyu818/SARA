// SARA scalar FP32 GEMM reference, not a CUDA Tensor Core / WMMA sample.
#include "../common/benchmark_support.cuh"
namespace sb = sara_bench;
__global__ void simple_gemm(const float *a,const float *b,const float *c,float *d,int m,int n,int k,float alpha,float beta) {
    int col=blockIdx.x*blockDim.x+threadIdx.x,row=blockIdx.y*blockDim.y+threadIdx.y;
    if(row>=m||col>=n)return;
    float sum=0;for(int j=0;j<k;++j)sum+=a[row*k+j]*b[j*n+col];
    d[row*n+col]=alpha*sum+beta*c[row*n+col];
}
int main(int argc,char **argv) {
    {
    if(argc!=2&&argc!=4)sb::fail("usage: Gemm tile_multiple OR m_multiple n_multiple k_multiple (tile=16)");
    int mt=sb::integer(argv[1]),nt=argc==2?mt:sb::integer(argv[2]),kt=argc==2?mt:sb::integer(argv[3]);
    int m=sb::product(mt,16),n=sb::product(nt,16),k=sb::product(kt,16);
    int ac=sb::product(m,k),bc=sb::product(k,n),cc=sb::product(m,n);const float alpha=1.1f,beta=1.2f;
    sb::Rng rng;std::vector<float>a(ac),b(bc),c(cc);
    for(float &v:a)v=rng.signed_uniform();for(float &v:b)v=rng.signed_uniform();for(float &v:c)v=rng.signed_uniform();
    sb::DeviceBuffer<float>da(ac),db(bc),dc(cc),dd(cc);da.upload(a);db.upload(b);dc.upload(c);
    simple_gemm<<<dim3(sb::ceil_div(n,16),sb::ceil_div(m,16)),dim3(16,16)>>>(da.get(),db.get(),dc.get(),dd.get(),m,n,k,alpha,beta);sb::finish_kernel();
    std::vector<float>out=sb::output("D","f32",dd.get(),cc);
    if(sb::validate_cpu()) {
        std::vector<double>ref(cc);
        for(int r=0;r<m;++r)for(int col=0;col<n;++col) {double sum=0;for(int j=0;j<k;++j)sum+=static_cast<double>(a[r*k+j])*b[j*n+col];ref[r*n+col]=alpha*sum+static_cast<double>(beta)*c[r*n+col];}
        sb::verify_close("D",out,ref,5e-5,3e-5);
    }
    } // All DeviceBuffer destructors have completed their cudaFree calls.
    SARA_CUDA(cudaDeviceSynchronize());
    SARA_CUDA(cudaThreadExit());
    if (sb::validate_cpu()) sb::validation_passed("Gemm");
    return 0;
}
