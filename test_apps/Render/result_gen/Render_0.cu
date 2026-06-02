#include <cuda_runtime.h>

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <random>
#include <vector>

#ifndef RNG_SEED
#define RNG_SEED 4837
#endif

#define CUDA_CHECK(call)                                                                                               \
    do {                                                                                                               \
        cudaError_t err__ = (call);                                                                                    \
        if (err__ != cudaSuccess) {                                                                                    \
            fprintf(stderr, "CUDA error at %s:%d code=%d(%s)\n", __FILE__, __LINE__, (int)err__,                     \
                    cudaGetErrorString(err__));                                                                        \
            exit(EXIT_FAILURE);                                                                                        \
        }                                                                                                              \
    } while (0)

__global__ void render_kernel(float *color_buffer, const float *base_u, const float *base_v, const float *rand_u,
                              const float *rand_v, int num_pixels, int samples, float inv_nx, float inv_ny,
                              float inv_samples) {
    int pixel = blockIdx.x * blockDim.x + threadIdx.x;
    if (pixel >= num_pixels)
        return;

    float accum_r = 0.0f;
    float accum_g = 0.0f;
    float accum_b = 0.0f;
    float baseU = base_u[pixel];
    float baseV = base_v[pixel];
    int sample_offset = pixel * samples;
    for (int s = 0; s < samples; ++s) {
        float u = baseU + rand_u[sample_offset + s] * inv_nx;
        float v = baseV + rand_v[sample_offset + s] * inv_ny;
        accum_r += u;
        accum_g += v;
        accum_b += 0.25f + 0.5f * u * v;
    }

    float r = fminf(fmaxf(accum_r * inv_samples, 0.0f), 0.999f);
    float g = fminf(fmaxf(accum_g * inv_samples, 0.0f), 0.999f);
    float b = fminf(fmaxf(accum_b * inv_samples, 0.0f), 0.999f);
    color_buffer[pixel * 3 + 0] = sqrtf(r);
    color_buffer[pixel * 3 + 1] = sqrtf(g);
    color_buffer[pixel * 3 + 2] = sqrtf(b);
}

int main(int argc, char **argv) {
    int nx = 8;
    int ny = 4;
    int samples = 8;
    if (argc > 1)
        nx = atoi(argv[1]);
    if (argc > 2)
        ny = atoi(argv[2]);
    if (argc > 3)
        samples = atoi(argv[3]);
    if (nx <= 0 || ny <= 0 || samples <= 0)
        return 1;

    const int num_pixels = nx * ny;
    const size_t jitter_count = (size_t)num_pixels * (size_t)samples;
    const size_t output_count = (size_t)num_pixels * 3;
    const float inv_nx = 1.0f / (float)nx;
    const float inv_ny = 1.0f / (float)ny;
    const float inv_samples = 1.0f / (float)samples;

    std::vector<float> h_base_u(num_pixels);
    std::vector<float> h_base_v(num_pixels);
    std::vector<float> h_rand_u(jitter_count);
    std::vector<float> h_rand_v(jitter_count);
    std::vector<float> h_color(output_count);

    for (int y = 0; y < ny; ++y) {
        for (int x = 0; x < nx; ++x) {
            int pixel = y * nx + x;
            h_base_u[pixel] = (float)x * inv_nx;
            h_base_v[pixel] = (float)y * inv_ny;
        }
    }

    std::mt19937 rng((unsigned int)RNG_SEED);
    std::uniform_real_distribution<float> dist(0.0f, 1.0f);
    for (size_t i = 0; i < jitter_count; ++i) {
        h_rand_u[i] = dist(rng);
        h_rand_v[i] = dist(rng);
    }

    float *d_color = nullptr;
    float *d_base_u = nullptr;
    float *d_base_v = nullptr;
    float *d_rand_u = nullptr;
    float *d_rand_v = nullptr;
    CUDA_CHECK(cudaMalloc(&d_color, output_count * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&d_base_u, num_pixels * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&d_base_v, num_pixels * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&d_rand_u, jitter_count * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&d_rand_v, jitter_count * sizeof(float)));

    CUDA_CHECK(cudaMemcpy(d_base_u, h_base_u.data(), num_pixels * sizeof(float), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_base_v, h_base_v.data(), num_pixels * sizeof(float), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_rand_u, h_rand_u.data(), jitter_count * sizeof(float), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_rand_v, h_rand_v.data(), jitter_count * sizeof(float), cudaMemcpyHostToDevice));

    dim3 block(256);
    dim3 grid((num_pixels + block.x - 1) / block.x);
    render_kernel<<<grid, block>>>(d_color, d_base_u, d_base_v, d_rand_u, d_rand_v, num_pixels, samples, inv_nx,
                                   inv_ny, inv_samples);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    fprintf(stderr, "GPUFI_OUTPUT base=%p bytes=%llu name=output_0\n", (void *)d_color,
            (unsigned long long)(output_count * sizeof(float)));
    fflush(stderr);
    CUDA_CHECK(cudaMemcpy(h_color.data(), d_color, output_count * sizeof(float), cudaMemcpyDeviceToHost));

    std::cout << std::fixed << std::setprecision(6);
    for (size_t i = 0; i < output_count; ++i) {
        std::cout << h_color[i];
        if (i + 1 < output_count)
            std::cout << ' ';
    }
    std::cout << '\n';

    cudaFree(d_color);
    cudaFree(d_base_u);
    cudaFree(d_base_v);
    cudaFree(d_rand_u);
    cudaFree(d_rand_v);
    return 0;
}
