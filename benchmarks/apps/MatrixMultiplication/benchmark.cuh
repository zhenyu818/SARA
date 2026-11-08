// Adapted NVIDIA MatrixMulCUDA: shared-memory tiled FP32, with guarded edge tiles.
#include "../common/benchmark_support.cuh"
namespace sb = sara_bench;
__global__ void MatrixMulCUDA(float *c,const float *a,const float *b,int rows,int inner,int cols) {
    __shared__ float As[16][16],Bs[16][16];
    int tx=threadIdx.x,ty=threadIdx.y,row=blockIdx.y*16+ty,col=blockIdx.x*16+tx;
    float sum=0;
    for(int tile=0;tile<inner/16+(inner%16!=0);++tile) {
        int ak=tile*16+tx,bk=tile*16+ty;
        As[ty][tx]=row<rows&&ak<inner?a[row*inner+ak]:0.0f;
        Bs[ty][tx]=bk<inner&&col<cols?b[bk*cols+col]:0.0f;
        __syncthreads();
        for(int k=0;k<16;++k)sum+=As[ty][k]*Bs[k][tx];
        __syncthreads();
    }
    if(row<rows&&col<cols)c[row*cols+col]=sum;
}
int main(int argc,char **argv) {
    {
    int wa=32,ha=16,wb=16,hb=32;
    if((argc-1)%2)sb::fail("usage: MatrixMultiplication wA N hA N wB N hB N");
    for(int i=1;i<argc;i+=2) {
        int value=sb::integer(argv[i+1]);
        if(!std::strcmp(argv[i],"wA"))wa=value;else if(!std::strcmp(argv[i],"hA"))ha=value;
        else if(!std::strcmp(argv[i],"wB"))wb=value;else if(!std::strcmp(argv[i],"hB"))hb=value;else sb::fail("unknown matrix dimension flag");
    }
    if(wa!=hb)sb::fail("matrix dimensions do not match");
    int ac=sb::product(ha,wa),bc=sb::product(hb,wb),cc=sb::product(ha,wb);
    sb::Rng rng;std::vector<float>a(ac),b(bc);for(float &v:a)v=rng.signed_uniform();for(float &v:b)v=rng.signed_uniform();
    sb::DeviceBuffer<float>da(ac),db(bc),dc(cc);da.upload(a);db.upload(b);
    MatrixMulCUDA<<<dim3(sb::ceil_div(wb,16),sb::ceil_div(ha,16)),dim3(16,16)>>>(dc.get(),da.get(),db.get(),ha,wa,wb);sb::finish_kernel();
    std::vector<float>out=sb::output("C","f32",dc.get(),cc);
    if(sb::validate_cpu()) {
        std::vector<double>ref(cc,0);for(int r=0;r<ha;++r)for(int c=0;c<wb;++c)for(int j=0;j<wa;++j)ref[r*wb+c]+=static_cast<double>(a[r*wa+j])*b[j*wb+c];
        sb::verify_close("C",out,ref,5e-5,3e-5);
    }
    } // All DeviceBuffer destructors have completed their cudaFree calls.
    SARA_CUDA(cudaDeviceSynchronize());
    SARA_CUDA(cudaThreadExit());
    if (sb::validate_cpu()) sb::validation_passed("MatrixMultiplication");
    return 0;
}
