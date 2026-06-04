#include <chrono>
#include <cuda.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#define M_SEED 2026
#define BLOCK_SIZE 256

// kernel1: dot product
__global__ void kernel1(const float *__restrict__ key, const float *__restrict__ query,
                        float *__restrict__ dot_product, const int n, const int d) {
    __shared__ int shared_d;
    if (threadIdx.x == 0) {
        shared_d = d;
    }
    __syncthreads();

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) {
        float sum = 0.0f;
        for (int j = 0; j < shared_d; j++) {
            sum += key[i * d + j] * query[j];
        }
        dot_product[i] = sum;
    }
}

// kernel3: weighted sum
__global__ void kernel3(const float *__restrict__ score, const float *__restrict__ value, float *__restrict__ output,
                        const int n, const int d) {
    __shared__ int shared_n;
    if (threadIdx.x == 0) {
        shared_n = n;
    }
    __syncthreads();

    int j = blockIdx.x * blockDim.x + threadIdx.x;
    if (j < d) {
        float sum = 0.0f;
        for (int i = 0; i < shared_n; i++) {
            sum += score[i] * value[i * d + j];
        }
        output[j] = sum;
    }
}

// Keep the softmax on the host so the simulator never executes device expf,
// which lowers to PTX fma.rm.f32 that this GPGPU-Sim build does not support.
void compute_softmax_scores_host(const float *dot_product, float *score, const int n) {
    float exp_sum = 0.0f;
    for (int i = 0; i < n; i++) {
        exp_sum += expf(dot_product[i]);
    }

    if (exp_sum == 0.0f) {
        for (int i = 0; i < n; i++) {
            score[i] = 0.0f;
        }
        return;
    }

    for (int i = 0; i < n; i++) {
        float s = expf(dot_product[i]) / exp_sum;
        score[i] = s;
    }
}

// device function
float *attention_device(const float *key, const float *value, const float *query, const int n, const int d,
                        const int repeat) {
    // input
    float *d_key;
    cudaMalloc((void **)&d_key, n * d * sizeof(float));
    cudaMemcpy(d_key, key, n * d * sizeof(float), cudaMemcpyHostToDevice);

    float *d_value;
    cudaMalloc((void **)&d_value, n * d * sizeof(float));
    cudaMemcpy(d_value, value, n * d * sizeof(float), cudaMemcpyHostToDevice);

    float *d_query;
    cudaMalloc((void **)&d_query, d * sizeof(float));
    cudaMemcpy(d_query, query, d * sizeof(float), cudaMemcpyHostToDevice);

    // intermediate
    float *d_dot_product;
    cudaMalloc((void **)&d_dot_product, n * sizeof(float));

    float *d_score;
    cudaMalloc((void **)&d_score, n * sizeof(float));

    float *h_dot_product = (float *)malloc(n * sizeof(float));
    float *h_score = (float *)malloc(n * sizeof(float));

    // result
    float *output = (float *)malloc(d * sizeof(float));
    float *d_output;
    cudaMalloc((void **)&d_output, d * sizeof(float));

    dim3 n_grid((n + BLOCK_SIZE - 1) / BLOCK_SIZE);
    dim3 n_block(BLOCK_SIZE);
    dim3 d_grid((d + BLOCK_SIZE - 1) / BLOCK_SIZE);
    dim3 d_block(BLOCK_SIZE);

    cudaDeviceSynchronize();

    for (int k = 0; k < repeat; k++) {
        kernel1<<<n_grid, n_block>>>(d_key, d_query, d_dot_product, n, d);
        cudaMemcpy(h_dot_product, d_dot_product, n * sizeof(float), cudaMemcpyDeviceToHost);
        compute_softmax_scores_host(h_dot_product, h_score, n);
        cudaMemcpy(d_score, h_score, n * sizeof(float), cudaMemcpyHostToDevice);

        kernel3<<<d_grid, d_block>>>(d_score, d_value, d_output, n, d);
    }

    cudaDeviceSynchronize();

    fprintf(stderr, "GPUFI_OUTPUT base=%p bytes=%llu name=output_0\n",
            (void *)d_output,
            (unsigned long long)(d * sizeof(float)));
    fflush(stderr);
    cudaMemcpy(output, d_output, d * sizeof(float), cudaMemcpyDeviceToHost);
    cudaFree(d_score);
    cudaFree(d_value);
    cudaFree(d_output);
    cudaFree(d_key);
    cudaFree(d_dot_product);
    free(h_score);
    free(h_dot_product);
    return output;
}

float random_float(float min, float max) {
    float scale = rand() / (float)RAND_MAX; // [0, 1]
    return min + scale * (max - min);       // [min, max]
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <rows> <columns>\n", argv[0]);
        return 1;
    }
    const int n = atoi(argv[1]);
    const int d = atoi(argv[2]);
    const int r = 1;

    // input (host float buffers)
    float *key = (float *)malloc(n * d * sizeof(float));
    float *value = (float *)malloc(n * d * sizeof(float));
    float *query = (float *)malloc(d * sizeof(float));

    srand(M_SEED);
    for (int i = 0; i < n * d; i++) {
        key[i] = random_float(-1.0f, 1.0f);
        value[i] = random_float(-1.0f, 1.0f);
    }

    for (int i = 0; i < d; i++) {
        query[i] = random_float(-2.0f, 2.0f);
    }

    float *dout = attention_device(key, value, query, n, d, r);

    // ===== 从 result.txt 读取期望结果 =====
    FILE *file = fopen("result.txt", "r");
    if (file == NULL) {
        printf("Fault Injection Test Failed!\n");

        free(key);
        free(value);
        free(query);
        free(dout);
        return 0;
    }

    float *expected = (float *)malloc(sizeof(float) * d);
    int count = 0;
    while (fscanf(file, "%f", &expected[count]) == 1 && count < d) {
        count++;
    }
    fclose(file);

    if (count != d) {
        printf("Fault Injection Test Failed!\n");
        free(expected);

        free(key);
        free(value);
        free(query);
        free(dout);
        return 0;
    }

    // ===== 逐项比较结果，显式支持 NaN 和 Inf =====
    bool match = true;
    const float eps = 1e-5f;
    for (int i = 0; i < d; i++) {
        float actual = dout[i];
        float expected_val = expected[i];

        if (isnan(actual) && isnan(expected_val)) {
            continue; // 两个都是 NaN
        }
        if (isnan(actual) || isnan(expected_val)) {
            match = false;
            break;
        }

        if (isinf(actual) && isinf(expected_val)) {
            if (signbit(actual) != signbit(expected_val)) {
                match = false; // +Inf vs -Inf
                break;
            } else {
                continue; // 同号 Inf
            }
        }
        if (isinf(actual) || isinf(expected_val)) {
            match = false; // 一个 Inf，一个不是
            break;
        }

        if (fabs(actual - expected_val) > eps) {
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

    free(key);
    free(value);
    free(query);
    free(dout);
    return 0;
}
