#define SEED 4364

#include <cuda_runtime.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define CUDA_CHECK(call)                                                                                               \
    do {                                                                                                               \
        cudaError_t err__ = (call);                                                                                    \
        if (err__ != cudaSuccess) {                                                                                    \
            fprintf(stderr, "CUDA error at %s:%d code=%d(%s)\n", __FILE__, __LINE__, (int)err__,                     \
                    cudaGetErrorString(err__));                                                                        \
            exit(EXIT_FAILURE);                                                                                        \
        }                                                                                                              \
    } while (0)

static float *make_random_float(int size) {
    float *data = (float *)malloc(size * sizeof(float));
    for (int i = 0; i < size; ++i) {
        data[i] = 2.0f * (rand() / (float)RAND_MAX) - 1.0f;
    }
    return data;
}

static int ceil_div(int a, int b) {
    return (a + b - 1) / b;
}

static bool approx_equal(float a, float b) {
    if (isnan(a) || isnan(b)) {
        return isnan(a) && isnan(b);
    }
    if (isinf(a) || isinf(b)) {
        return isinf(a) && isinf(b) && ((a > 0.0f) == (b > 0.0f));
    }
    return fabsf(a - b) <= 1e-5f;
}

static void compute_layernorm_stats(float *mean, float *rstd, const float *inp, int bt_count, int c) {
    for (int bt = 0; bt < bt_count; ++bt) {
        const float *row = inp + bt * c;
        double sum = 0.0;
        for (int i = 0; i < c; ++i) {
            sum += row[i];
        }
        float m = (float)(sum / (double)c);
        double var_sum = 0.0;
        for (int i = 0; i < c; ++i) {
            double diff = (double)row[i] - (double)m;
            var_sum += diff * diff;
        }
        mean[bt] = m;
        rstd[bt] = 1.0f / sqrtf((float)(var_sum / (double)c) + 1e-5f);
    }
}

__global__ void layernorm_apply_kernel(float *out, const float *inp, const float *mean, const float *rstd,
                                       const float *weight, const float *bias, int bt_count, int c) {
    int bt = blockIdx.y;
    if (bt >= bt_count)
        return;

    __shared__ float shared_mean;
    __shared__ float shared_rstd;
    if (threadIdx.x == 0) {
        shared_mean = mean[bt];
        shared_rstd = rstd[bt];
    }
    __syncthreads();

    int col = blockIdx.x * blockDim.x + threadIdx.x;
    if (col >= c)
        return;

    int idx = bt * c + col;
    float norm = (inp[idx] - shared_mean) * shared_rstd;
    out[idx] = norm * weight[col] + bias[col];
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s B T C\n", argv[0]);
        return 1;
    }

    srand(SEED);

    int B = atoi(argv[1]);
    int T = atoi(argv[2]);
    int C = atoi(argv[3]);
    int bt_count = B * T;

    float *out = (float *)malloc(bt_count * C * sizeof(float));
    float *mean = (float *)malloc(bt_count * sizeof(float));
    float *rstd = (float *)malloc(bt_count * sizeof(float));
    float *inp = make_random_float(bt_count * C);
    float *weight = make_random_float(C);
    float *bias = make_random_float(C);

    compute_layernorm_stats(mean, rstd, inp, bt_count, C);

    float *d_out = nullptr;
    float *d_mean = nullptr;
    float *d_rstd = nullptr;
    float *d_inp = nullptr;
    float *d_weight = nullptr;
    float *d_bias = nullptr;

    CUDA_CHECK(cudaMalloc(&d_out, bt_count * C * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&d_mean, bt_count * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&d_rstd, bt_count * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&d_inp, bt_count * C * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&d_weight, C * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&d_bias, C * sizeof(float)));

    CUDA_CHECK(cudaMemcpy(d_mean, mean, bt_count * sizeof(float), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_rstd, rstd, bt_count * sizeof(float), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_inp, inp, bt_count * C * sizeof(float), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_weight, weight, C * sizeof(float), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_bias, bias, C * sizeof(float), cudaMemcpyHostToDevice));

    dim3 block(256);
    dim3 grid(ceil_div(C, block.x), bt_count);
    layernorm_apply_kernel<<<grid, block>>>(d_out, d_inp, d_mean, d_rstd, d_weight, d_bias, bt_count, C);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    fprintf(stderr, "GPUFI_OUTPUT base=%p bytes=%llu name=output_0\n", (void *)d_out,
            (unsigned long long)(bt_count * C * sizeof(float)));
    fflush(stderr);
    CUDA_CHECK(cudaMemcpy(out, d_out, bt_count * C * sizeof(float), cudaMemcpyDeviceToHost));
    fprintf(stderr, "GPUFI_OUTPUT base=%p bytes=%llu name=output_1\n", (void *)d_mean,
            (unsigned long long)(bt_count * sizeof(float)));
    fflush(stderr);
    fprintf(stderr, "GPUFI_OUTPUT base=%p bytes=%llu name=output_2\n", (void *)d_rstd,
            (unsigned long long)(bt_count * sizeof(float)));
    fflush(stderr);

    FILE *fp = fopen("result.txt", "r");
    if (!fp) {
        printf("Fault Injection Test Failed!\n");
        free(out);
        free(mean);
        free(rstd);
        free(inp);
        free(weight);
        free(bias);
        cudaFree(d_out);
        cudaFree(d_mean);
        cudaFree(d_rstd);
        cudaFree(d_inp);
        cudaFree(d_weight);
        cudaFree(d_bias);
        return 1;
    }

    float *ref_out = (float *)malloc(bt_count * C * sizeof(float));
    float *ref_mean = (float *)malloc(bt_count * sizeof(float));
    float *ref_rstd = (float *)malloc(bt_count * sizeof(float));

    bool read_ok = true;
    for (int i = 0; i < bt_count * C; ++i) {
        if (fscanf(fp, "%f", &ref_out[i]) != 1) {
            read_ok = false;
            break;
        }
    }
    if (read_ok) {
        for (int i = 0; i < bt_count; ++i) {
            if (fscanf(fp, "%f", &ref_mean[i]) != 1) {
                read_ok = false;
                break;
            }
        }
    }
    if (read_ok) {
        for (int i = 0; i < bt_count; ++i) {
            if (fscanf(fp, "%f", &ref_rstd[i]) != 1) {
                read_ok = false;
                break;
            }
        }
    }
    fclose(fp);

    bool success = read_ok;
    for (int i = 0; success && i < bt_count * C; ++i) {
        if (!approx_equal(out[i], ref_out[i])) {
            success = false;
        }
    }
    for (int i = 0; success && i < bt_count; ++i) {
        if (!approx_equal(mean[i], ref_mean[i]) || !approx_equal(rstd[i], ref_rstd[i])) {
            success = false;
        }
    }

    if (success) {
        printf("Fault Injection Test Success!\n");
    } else {
        printf("Fault Injection Test Failed!\n");
    }

    free(ref_out);
    free(ref_mean);
    free(ref_rstd);
    free(out);
    free(mean);
    free(rstd);
    free(inp);
    free(weight);
    free(bias);
    cudaFree(d_out);
    cudaFree(d_mean);
    cudaFree(d_rstd);
    cudaFree(d_inp);
    cudaFree(d_weight);
    cudaFree(d_bias);
    return 0;
}
