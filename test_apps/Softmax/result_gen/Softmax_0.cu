#include <cuda_runtime.h>

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <vector>

#define BLOCK_SIZE 32
#define M_SEED 2026

#define CUDA_CHECK(call)                                                                                               \
    do {                                                                                                               \
        cudaError_t err__ = (call);                                                                                    \
        if (err__ != cudaSuccess) {                                                                                    \
            fprintf(stderr, "CUDA error at %s:%d code=%d(%s)\n", __FILE__, __LINE__, (int)err__,                     \
                    cudaGetErrorString(err__));                                                                        \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

__global__ void softmax_kernel(const float *input, float *output, int numSlice, int sliceSize) {
    __shared__ float tile[BLOCK_SIZE];

    const int slice = blockIdx.x;
    const int tid = threadIdx.x;
    if (slice >= numSlice || sliceSize > BLOCK_SIZE) {
        return;
    }

    const int offset = slice * sliceSize;
    float value = -3.402823466e+38F;
    if (tid < sliceSize) {
        value = input[offset + tid];
    }
    tile[tid] = value;
    __syncthreads();

    for (int stride = BLOCK_SIZE / 2; stride > 0; stride >>= 1) {
        if (tid < stride) {
            const float other = tile[tid + stride];
            if (other > tile[tid]) {
                tile[tid] = other;
            }
        }
        __syncthreads();
    }
    const float max_val = tile[0];

    float exp_value = 0.0f;
    if (tid < sliceSize) {
        exp_value = expf(value - max_val);
    }
    tile[tid] = exp_value;
    __syncthreads();

    for (int stride = BLOCK_SIZE / 2; stride > 0; stride >>= 1) {
        if (tid < stride) {
            tile[tid] += tile[tid + stride];
        }
        __syncthreads();
    }

    if (tid < sliceSize) {
        output[offset + tid] = exp_value / tile[0];
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <number of slices> <slice size>\n", argv[0]);
        return 1;
    }

    const int numSlice = atoi(argv[1]);
    const int sliceSize = atoi(argv[2]);
    if (numSlice <= 0 || sliceSize <= 0 || sliceSize > BLOCK_SIZE) {
        return 1;
    }

    const int numElem = numSlice * sliceSize;
    std::vector<float> input(numElem);
    std::vector<float> output(numElem);

    srand(M_SEED);
    for (int i = 0; i < numElem; ++i) {
        input[i] = (float)(rand() % 13);
    }

    float *d_input = nullptr;
    float *d_output = nullptr;
    CUDA_CHECK(cudaMalloc((void **)&d_input, sizeof(float) * (size_t)numElem));
    CUDA_CHECK(cudaMalloc((void **)&d_output, sizeof(float) * (size_t)numElem));
    CUDA_CHECK(cudaMemcpy(d_input, input.data(), sizeof(float) * (size_t)numElem, cudaMemcpyHostToDevice));

    dim3 block(BLOCK_SIZE);
    dim3 grid(numSlice);
    softmax_kernel<<<grid, block>>>(d_input, d_output, numSlice, sliceSize);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    fprintf(stderr, "GPUFI_OUTPUT base=%p bytes=%llu name=output_0\n", (void *)d_output,
            (unsigned long long)(sizeof(float) * (size_t)numElem));
    fflush(stderr);
    CUDA_CHECK(cudaMemcpy(output.data(), d_output, sizeof(float) * (size_t)numElem, cudaMemcpyDeviceToHost));

    std::cout << std::setprecision(9);
    for (int i = 0; i < numElem; ++i) {
        std::cout << output[i];
        if (i + 1 < numElem) {
            std::cout << ' ';
        }
    }
    std::cout << '\n';

    cudaFree(d_input);
    cudaFree(d_output);
    return 0;
}
