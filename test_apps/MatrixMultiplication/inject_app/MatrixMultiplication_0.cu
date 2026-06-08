#include <cuda_runtime.h>
#include <math.h>
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

#define CUDA_CHECK(call)                                                                                               \
    do {                                                                                                               \
        cudaError_t err__ = (call);                                                                                    \
        if (err__ != cudaSuccess) {                                                                                    \
            fprintf(stderr, "CUDA error at %s:%d code=%d(%s)\n", __FILE__, __LINE__, (int)err__,                     \
                    cudaGetErrorString(err__));                                                                        \
            exit(EXIT_FAILURE);                                                                                        \
        }                                                                                                              \
    } while (0)

static int check_cmd_line_flag(int argc, const char **argv, const char *flag) {
    for (int i = 0; i < argc; ++i) {
        if (!strcmp(argv[i], flag))
            return 1;
    }
    return 0;
}

static int get_cmd_line_argument_int(int argc, const char **argv, const char *arg_name) {
    for (int i = 0; i < argc - 1; ++i) {
        if (!strcmp(argv[i], arg_name)) {
            return atoi(argv[i + 1]);
        }
    }
    return 0;
}

static void random_init(float *data, int size) {
    srand(M_SEED);
    for (int i = 0; i < size; ++i) {
        data[i] = (float)rand() / (float)RAND_MAX;
    }
}

__global__ void matrix_mul_kernel(float *c, const float *a, const float *b, int hA, int wA, int wB) {
    int col = blockIdx.x * blockDim.x + threadIdx.x;
    int row = blockIdx.y * blockDim.y + threadIdx.y;
    if (row >= hA || col >= wB)
        return;

    float sum = 0.0f;
    for (int k = 0; k < wA; ++k) {
        sum += a[row * wA + k] * b[k * wB + col];
    }
    c[row * wB + col] = sum;
}

static int matrix_multiply(int wA, int hA, int wB, int hB) {
    int size_A = wA * hA;
    int size_B = wB * hB;
    int size_C = wB * hA;
    size_t mem_size_A = sizeof(float) * size_A;
    size_t mem_size_B = sizeof(float) * size_B;
    size_t mem_size_C = sizeof(float) * size_C;

    float *h_A = (float *)malloc(mem_size_A);
    float *h_B = (float *)malloc(mem_size_B);
    float *h_C = (float *)malloc(mem_size_C);

    random_init(h_A, size_A);
    random_init(h_B, size_B);

    float *d_A = nullptr;
    float *d_B = nullptr;
    float *d_C = nullptr;
    CUDA_CHECK(cudaMalloc(&d_A, mem_size_A));
    CUDA_CHECK(cudaMalloc(&d_B, mem_size_B));
    CUDA_CHECK(cudaMalloc(&d_C, mem_size_C));
    CUDA_CHECK(cudaMemcpy(d_A, h_A, mem_size_A, cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_B, h_B, mem_size_B, cudaMemcpyHostToDevice));

    dim3 block(16, 16);
    dim3 grid((wB + block.x - 1) / block.x, (hA + block.y - 1) / block.y);
    matrix_mul_kernel<<<grid, block>>>(d_C, d_A, d_B, hA, wA, wB);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    fprintf(stderr, "GPUFI_OUTPUT base=%p bytes=%llu name=output_0\n", (void *)d_C,
            (unsigned long long)mem_size_C);
    fflush(stderr);

    CUDA_CHECK(cudaMemcpy(h_C, d_C, mem_size_C, cudaMemcpyDeviceToHost));

    FILE *file = fopen("result.txt", "r");
    if (file == NULL) {
        printf("Fault Injection Test Failed!\n");
        return 0;
    }

    float *expected = (float *)malloc(mem_size_C);
    int count = 0;
    while (count < size_C && fscanf(file, "%f", &expected[count]) == 1) {
        count++;
    }
    fclose(file);

    bool match = (count == size_C);
    for (int i = 0; match && i < size_C; ++i) {
        if (!exact_equal_float(h_C[i], expected[i])) {
            match = false;
            break;
        }
    }

    if (match)
        printf("Fault Injection Test Success!\n");
    else
        printf("Fault Injection Test Failed!\n");

    free(expected);
    free(h_A);
    free(h_B);
    free(h_C);
    cudaFree(d_A);
    cudaFree(d_B);
    cudaFree(d_C);
    return 0;
}

int main(int argc, char **argv) {
    int wA = 160;
    int hA = 160;
    int wB = 320;
    int hB = 160;

    if (check_cmd_line_flag(argc, (const char **)argv, "wA")) {
        wA = get_cmd_line_argument_int(argc, (const char **)argv, "wA");
    }
    if (check_cmd_line_flag(argc, (const char **)argv, "hA")) {
        hA = get_cmd_line_argument_int(argc, (const char **)argv, "hA");
    }
    if (check_cmd_line_flag(argc, (const char **)argv, "wB")) {
        wB = get_cmd_line_argument_int(argc, (const char **)argv, "wB");
    }
    if (check_cmd_line_flag(argc, (const char **)argv, "hB")) {
        hB = get_cmd_line_argument_int(argc, (const char **)argv, "hB");
    }
    if (wA <= 0 || hA <= 0 || wB <= 0 || hB <= 0 || wA != hB) {
        fprintf(stderr, "Error: Matrix dimensions do not match for multiplication!\n");
        return EXIT_FAILURE;
    }
    return matrix_multiply(wA, hA, wB, hB);
}
