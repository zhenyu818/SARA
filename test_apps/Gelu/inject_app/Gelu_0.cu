#include <chrono>
#include <cuda.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int exact_equal_float(float a, float b) {
    uint32_t ai = 0;
    uint32_t bi = 0;
    memcpy(&ai, &a, sizeof(ai));
    memcpy(&bi, &b, sizeof(bi));
    return ai == bi;
}

#define M_SEED 2026
#define M_BLOCK_SIZE 1024

/*
 * Copyright (c) 2020-2021, NVIDIA CORPORATION.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// width is hidden_dim and height is seq_len
__global__ void gelu_bias_loop(float *src, const float *bias, int width, int height) {
    __shared__ int shared_width;
    if (threadIdx.x == 0) {
        shared_width = width;
    }
    __syncthreads();

    int batch = blockIdx.x;
    int x = blockIdx.y; // seq length
    int y = threadIdx.x;

    if (x < height) {
        int index = batch * width * height + x * width;

        for (; y < shared_width; y += blockDim.x) {
            float v_src = src[index + y];
            float v_bias = bias[y];
            float v = v_src + v_bias;

            // GELU近似公式
            float t = 0.5f * v * (1.0f + tanhf(0.79788456f * (v + 0.044715f * v * v * v)));

            src[index + y] = t;
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <batch> <sequence length> <hidden dimension> <repeat>\n", argv[0]);
        return 1;
    }

    const int batch_size = atoi(argv[1]);
    const int seq_len = atoi(argv[2]);
    const int hidden_dim = atoi(argv[3]);
    const int repeat = 1;

    const size_t src_size = (size_t)batch_size * seq_len * hidden_dim;

    const size_t src_size_bytes = src_size * sizeof(float);
    const int bias_size_bytes = hidden_dim * sizeof(float);

    srand(M_SEED);
    float *output = (float *)malloc(src_size_bytes);
    for (size_t i = 0; i < src_size; i++) {
        output[i] = rand() / (float)RAND_MAX;
    }

    float *bias = (float *)malloc(bias_size_bytes);
    for (int i = 0; i < hidden_dim; i++) {
        bias[i] = -6.0f + (rand() % 12);
    }

    float *d_output;
    cudaMalloc((void **)&d_output, src_size_bytes);
    cudaMemcpy(d_output, output, src_size_bytes, cudaMemcpyHostToDevice);

    float *d_bias;
    cudaMalloc((void **)&d_bias, bias_size_bytes);
    cudaMemcpy(d_bias, bias, bias_size_bytes, cudaMemcpyHostToDevice);

    dim3 block(1024, 1);
    dim3 grid(batch_size, seq_len);

    cudaDeviceSynchronize();
    for (int i = 0; i < repeat; i++) {
        gelu_bias_loop<<<grid, block>>>(d_output, d_bias, hidden_dim, seq_len);
    }
    cudaDeviceSynchronize();
    // gpuFI exact SDC output definition for the final device buffer.
    fprintf(stderr, "GPUFI_OUTPUT base=0x%llx bytes=%llu name=Gelu_output\n",
            (unsigned long long)(uintptr_t)d_output,
            (unsigned long long)src_size_bytes);
    fflush(stderr);

    cudaMemcpy(output, d_output, src_size_bytes, cudaMemcpyDeviceToHost);

    // ==== 从 result.txt 读取参考值 ====
    FILE *file = fopen("result.txt", "r");
    if (file == NULL) {
        printf("Fault Injection Test Failed!\n");
        cudaFree(d_output);
        cudaFree(d_bias);
        free(output);
        free(bias);
        return 1;
    }

    float *expected = (float *)malloc(sizeof(float) * src_size);
    int count = 0;
    while (fscanf(file, "%f", &expected[count]) == 1 && count < (int)src_size) {
        count++;
    }
    fclose(file);

    if (count != (int)src_size) {
        printf("Fault Injection Test Failed!\n");
        free(expected);
        cudaFree(d_output);
        cudaFree(d_bias);
        free(output);
        free(bias);
        return 1;
    }

    // Exact-output SDC oracle: any output-bit mismatch is SDC.
    bool match = true;
    for (size_t i = 0; i < src_size; i++) {
        if (!exact_equal_float(output[i], expected[i])) {
            match = false;
            break;
        }
    }

    if (match) {
        printf("Fault Injection Test Success!\n");
    } else {
        printf("Fault Injection Test Failed!\n");
    }

    free(expected);
    cudaFree(d_output);
    cudaFree(d_bias);
    free(output);
    free(bias);

    return 0;
}
