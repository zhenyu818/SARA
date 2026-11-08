// Adapted from hgyhungry/ge-spmm spmm_test0; origin and license are listed in THIRD_PARTY.md.
#include "../common/benchmark_support.cuh"
#include <utility>
namespace sb = sara_bench;
__global__ void spmm_test0(int rows,int columns,const int *row_ptr,const int *col_ind,
                          const float *values,const float *dense,float *out) {
    int row=blockDim.y*blockIdx.x+threadIdx.y,col=blockIdx.y*32+threadIdx.x;
    if(row>=rows||col>=columns) return;
    float sum=0;
    for(int e=row_ptr[row];e<row_ptr[row+1];++e) sum+=values[e]*dense[col_ind[e]*columns+col];
    out[row*columns+col]=sum;
}
int main(int argc,char **argv) {
    {
    if(argc!=5) sb::fail("usage: GESpmm A_rows A_columns B_columns nnz");
    int rows=sb::integer(argv[1]),inner=sb::integer(argv[2]),cols=sb::integer(argv[3]),nnz=sb::integer(argv[4],true);
    int capacity=sb::product(rows,inner),dense_count=sb::product(inner,cols),out_count=sb::product(rows,cols);
    if(nnz>capacity) sb::fail("nnz exceeds sparse matrix capacity");
    sb::Rng rng;std::vector<int> positions(capacity);
    for(int i=0;i<capacity;++i) positions[i]=i;
    for(int i=0;i<nnz;++i) {int j=i+static_cast<int>(rng.next()%static_cast<uint32_t>(capacity-i));std::swap(positions[i],positions[j]);}
    positions.resize(nnz);std::sort(positions.begin(),positions.end());
    std::vector<int> rp(rows+1,0),ci(nnz);std::vector<float> values(nnz),dense(dense_count);
    for(int e=0;e<nnz;++e) {++rp[positions[e]/inner+1];ci[e]=positions[e]%inner;values[e]=rng.signed_uniform();if(values[e]==0)values[e]=0.5f;}
    for(int r=0;r<rows;++r) rp[r+1]+=rp[r];
    for(float &v:dense) v=rng.signed_uniform();
    sb::DeviceBuffer<int> dr(rp.size()),dc(ci.size());sb::DeviceBuffer<float> dv(nnz),db(dense_count),dout(out_count);
    dr.upload(rp);dc.upload(ci);dv.upload(values);db.upload(dense);
    dim3 block(std::min(cols,32),4),grid(sb::ceil_div(rows,4),sb::ceil_div(cols,32));
    spmm_test0<<<grid,block>>>(rows,cols,dr.get(),dc.get(),dv.get(),db.get(),dout.get());sb::finish_kernel();
    std::vector<float> out=sb::output("C","f32",dout.get(),out_count);
    if(sb::validate_cpu()) {
        std::vector<double> ref(out_count,0);
        for(int r=0;r<rows;++r)for(int e=rp[r];e<rp[r+1];++e)for(int c=0;c<cols;++c)
            ref[r*cols+c]+=static_cast<double>(values[e])*dense[ci[e]*cols+c];
        sb::verify_close("C",out,ref);
    }
    } // All DeviceBuffer destructors have completed their cudaFree calls.
    SARA_CUDA(cudaDeviceSynchronize());
    SARA_CUDA(cudaThreadExit());
    if (sb::validate_cpu()) sb::validation_passed("GESpmm");
    return 0;
}
