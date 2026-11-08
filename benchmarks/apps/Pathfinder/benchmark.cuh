// Adapted Rodinia Pathfinder kernel; origin and license are listed in THIRD_PARTY.md.
#include "../common/benchmark_support.cuh"
namespace sb = sara_bench;
#define BLOCK_SIZE 256
#define HALO 1
#define IN_RANGE(x, low, high) ((x) >= (low) && (x) <= (high))
#define MIN(a, b) ((a) <= (b) ? (a) : (b))
__global__ void dynproc_kernel(int iteration, int *gpuWall, int *gpuSrc, int *gpuResults, int cols, int rows,
                               int startStep, int border) {

    __shared__ int prev[BLOCK_SIZE];
    __shared__ int result[BLOCK_SIZE];

    int bx = blockIdx.x;
    int tx = threadIdx.x;

    // each block finally computes result for a small block
    // after N iterations.
    // it is the non-overlapping small blocks that cover
    // all the input data

    // calculate the small block size
    int small_block_cols = BLOCK_SIZE - iteration * HALO * 2;

    // calculate the boundary for the block according to
    // the boundary of its small block
    int blkX = small_block_cols * bx - border;
    int blkXmax = blkX + BLOCK_SIZE - 1;

    // calculate the global thread coordination
    int xidx = blkX + tx;

    // effective range within this block that falls within
    // the valid range of the input data
    // used to rule out computation outside the boundary.
    int validXmin = (blkX < 0) ? -blkX : 0;
    int validXmax = (blkXmax > cols - 1) ? BLOCK_SIZE - 1 - (blkXmax - cols + 1) : BLOCK_SIZE - 1;

    int W = tx - 1;
    int E = tx + 1;

    W = (W < validXmin) ? validXmin : W;
    E = (E > validXmax) ? validXmax : E;

    bool isValid = IN_RANGE(tx, validXmin, validXmax);

    if (IN_RANGE(xidx, 0, cols - 1)) {
        prev[tx] = gpuSrc[xidx];
    }
    __syncthreads(); // [Ronny] Added sync to avoid race on prev Aug. 14 2012
    bool computed;
    for (int i = 0; i < iteration; i++) {
        computed = false;
        if (IN_RANGE(tx, i + 1, BLOCK_SIZE - i - 2) && isValid) {
            computed = true;
            int left = prev[W];
            int up = prev[tx];
            int right = prev[E];
            int shortest = MIN(left, up);
            shortest = MIN(shortest, right);
            int index = cols * (startStep + i) + xidx;
            result[tx] = shortest + gpuWall[index];
        }
        __syncthreads();
        if (i == iteration - 1)
            break;
        if (computed) // Assign the computation range
            prev[tx] = result[tx];
        __syncthreads(); // [Ronny] Added sync to avoid race on prev Aug. 14 2012
    }

    // update the global memory
    // after the last iteration, only threads coordinated within the
    // small block perform the calculation and switch on ``computed''
    if (computed) {
        gpuResults[xidx] = result[tx];
    }
}
int main(int argc,char **argv) {
    {
    if(argc!=4)sb::fail("usage: Pathfinder columns rows pyramid_height");
    int cols=sb::integer(argv[1]),rows=sb::integer(argv[2]),pyramid=sb::integer(argv[3]);
    if(pyramid>=128||rows>std::numeric_limits<int>::max()/9)sb::fail("require pyramid_height < 128 and bounded path cost");
    int count=sb::product(rows,cols);
    sb::Rng rng;std::vector<int32_t>input(count);for(int32_t &v:input)v=static_cast<int32_t>(rng.next()%10);
    std::vector<int32_t>first(input.begin(),input.begin()+cols),wall(input.begin()+cols,input.end());
    sb::DeviceBuffer<int32_t>dw(wall.size()),r0(cols),r1(cols);dw.upload(wall);r0.upload(first);
    int *result[2]={r0.get(),r1.get()};int current=0;
    for(int t=0;t<rows-1;t+=pyramid) {
        int next=current^1,iteration=std::min(pyramid,rows-t-1);
        int blocks=sb::ceil_div(cols,256-2*iteration);
        dynproc_kernel<<<blocks,256>>>(iteration,dw.get(),result[current],result[next],cols,rows,t,iteration);
        SARA_CUDA(cudaGetLastError());current=next;
    }
    sb::finish_kernel();
    std::vector<int32_t>out=sb::output("last_row","i32",result[current],cols);
    if(sb::validate_cpu()) {
        std::vector<int32_t>previous=first,next(cols);
        for(int r=1;r<rows;++r) {
            for(int c=0;c<cols;++c) {
                int32_t best=previous[c];if(c)best=std::min(best,previous[c-1]);if(c+1<cols)best=std::min(best,previous[c+1]);
                next[c]=best+input[r*cols+c];
            }
            previous.swap(next);
        }
        sb::verify_equal("last_row",out,previous);
    }
    } // All DeviceBuffer destructors have completed their cudaFree calls.
    SARA_CUDA(cudaDeviceSynchronize());
    SARA_CUDA(cudaThreadExit());
    if (sb::validate_cpu()) sb::validation_passed("Pathfinder");
    return 0;
}
