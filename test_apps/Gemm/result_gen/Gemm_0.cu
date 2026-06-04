#include <cuda_runtime.h>

#include <cstdio>
#include <cstdlib>

#define GEMM_SEED 2026

#define CUDA_CHECK(call)                                                                                               \
    do {                                                                                                               \
        cudaError_t err__ = (call);                                                                                    \
        if (err__ != cudaSuccess) {                                                                                    \
            fprintf(stderr, "CUDA error at %s:%d code=%d(%s)\n", __FILE__, __LINE__, (int)err__,                     \
                    cudaGetErrorString(err__));                                                                        \
            exit(EXIT_FAILURE);                                                                                        \
        }                                                                                                              \
    } while (0)

__global__ void simple_gemm(const float *a, const float *b, const float *c, float *d, int m, int n, int k,
                            float alpha, float beta) {
    int col = blockIdx.x * blockDim.x + threadIdx.x;
    int row = blockIdx.y * blockDim.y + threadIdx.y;
    if (row >= m || col >= n)
        return;

    float acc = 0.0f;
    for (int kk = 0; kk < k; ++kk) {
        acc += a[row * k + kk] * b[kk * n + col];
    }
    d[row * n + col] = alpha * acc + beta * c[row * n + col];
}

static void init_host_matrices(float *a, float *b, float *c, int m, int n, int k) {
    srand(GEMM_SEED);
    for (int i = 0; i < m * k; ++i) {
        a[i] = static_cast<float>(rand() % 3);
    }
    for (int i = 0; i < k * n; ++i) {
        b[i] = static_cast<float>(rand() % 3);
    }
    for (int i = 0; i < m * n; ++i) {
        c[i] = static_cast<float>(rand() % 3);
    }
}

int main(int argc, char **argv) {
    int mt = 2;
    int nt = 2;
    int kt = 2;
    if (argc == 2) {
        int s = atoi(argv[1]);
        if (s > 0)
            mt = nt = kt = s;
    } else if (argc >= 4) {
        int t1 = atoi(argv[1]);
        int t2 = atoi(argv[2]);
        int t3 = atoi(argv[3]);
        if (t1 > 0)
            mt = t1;
        if (t2 > 0)
            nt = t2;
        if (t3 > 0)
            kt = t3;
    }

    const int m = 16 * mt;
    const int n = 16 * nt;
    const int k = 16 * kt;
    const float alpha = 1.1f;
    const float beta = 1.2f;

    float *a_h = (float *)malloc(sizeof(float) * m * k);
    float *b_h = (float *)malloc(sizeof(float) * k * n);
    float *c_h = (float *)malloc(sizeof(float) * m * n);
    float *d_h = (float *)malloc(sizeof(float) * m * n);

    float *a_d = nullptr;
    float *b_d = nullptr;
    float *c_d = nullptr;
    float *d_d = nullptr;

    init_host_matrices(a_h, b_h, c_h, m, n, k);

    CUDA_CHECK(cudaMalloc(&a_d, sizeof(float) * m * k));
    CUDA_CHECK(cudaMalloc(&b_d, sizeof(float) * k * n));
    CUDA_CHECK(cudaMalloc(&c_d, sizeof(float) * m * n));
    CUDA_CHECK(cudaMalloc(&d_d, sizeof(float) * m * n));

    CUDA_CHECK(cudaMemcpy(a_d, a_h, sizeof(float) * m * k, cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(b_d, b_h, sizeof(float) * k * n, cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(c_d, c_h, sizeof(float) * m * n, cudaMemcpyHostToDevice));

    dim3 block(16, 16);
    dim3 grid((n + block.x - 1) / block.x, (m + block.y - 1) / block.y);
    simple_gemm<<<grid, block>>>(a_d, b_d, c_d, d_d, m, n, k, alpha, beta);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    fprintf(stderr, "GPUFI_OUTPUT base=%p bytes=%llu name=output_0\n", (void *)d_d,
            (unsigned long long)(sizeof(float) * m * n));
    fflush(stderr);

    CUDA_CHECK(cudaMemcpy(d_h, d_d, sizeof(float) * m * n, cudaMemcpyDeviceToHost));
    for (int i = 0; i < m * n; ++i) {
        printf("%.6f ", d_h[i]);
    }
    printf("\n");

    free(a_h);
    free(b_h);
    free(c_h);
    free(d_h);
    cudaFree(a_d);
    cudaFree(b_d);
    cudaFree(c_d);
    cudaFree(d_d);
    return 0;
}
