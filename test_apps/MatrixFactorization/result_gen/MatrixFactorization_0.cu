#include <cuda_runtime.h>

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <vector>

#define HOST_RANDOM_SEED 2026
#define LATENT_FACTORS 8
#define BLOCK_SIZE 256

#define CUDA_CHECK(call)                                                                                               \
    do {                                                                                                               \
        cudaError_t err__ = (call);                                                                                    \
        if (err__ != cudaSuccess) {                                                                                    \
            fprintf(stderr, "CUDA error at %s:%d code=%d(%s)\n", __FILE__, __LINE__, (int)err__,                     \
                    cudaGetErrorString(err__));                                                                        \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

__device__ float mf_predict(const float *p, const float *q, const float *user_bias, const float *item_bias,
                            int user, int item, float global_bias) {
    float pred = global_bias + user_bias[user] + item_bias[item];
    for (int f = 0; f < LATENT_FACTORS; ++f) {
        pred += p[user * LATENT_FACTORS + f] * q[item * LATENT_FACTORS + f];
    }
    return pred;
}

__global__ void matrix_factorization_sgd_kernel(const float *p_in, const float *q_in, const float *user_bias_in,
                                                const float *item_bias_in, const int *chosen_item,
                                                const float *ratings, float *p_out, float *q_out,
                                                float *user_bias_out, float *item_bias_out,
                                                unsigned char *item_updated_out, int num_users, int num_items,
                                                float global_bias, float learning_rate, float lambda) {
    const int idx = blockIdx.x * blockDim.x + threadIdx.x;
    const int p_count = num_users * LATENT_FACTORS;
    const int q_count = num_items * LATENT_FACTORS;
    const int user_bias_base = p_count + q_count;
    const int item_bias_base = user_bias_base + num_users;
    const int total = item_bias_base + num_items;

    if (idx < p_count) {
        const int user = idx / LATENT_FACTORS;
        const int factor = idx - user * LATENT_FACTORS;
        const int item = chosen_item[user];
        const float pred = mf_predict(p_in, q_in, user_bias_in, item_bias_in, user, item, global_bias);
        const float error = ratings[user] - pred;
        const float p_old = p_in[idx];
        const float q_old = q_in[item * LATENT_FACTORS + factor];
        p_out[idx] = p_old + learning_rate * (error * q_old - lambda * p_old);
    } else if (idx < user_bias_base) {
        const int q_idx = idx - p_count;
        const int item = q_idx / LATENT_FACTORS;
        const int factor = q_idx - item * LATENT_FACTORS;
        float value = q_in[q_idx];
        if (item < num_users && chosen_item[item] == item) {
            const float pred = mf_predict(p_in, q_in, user_bias_in, item_bias_in, item, item, global_bias);
            const float error = ratings[item] - pred;
            const float p_old = p_in[item * LATENT_FACTORS + factor];
            value = value + learning_rate * (error * p_old - lambda * value);
        }
        q_out[q_idx] = value;
    } else if (idx < item_bias_base) {
        const int user = idx - user_bias_base;
        const int item = chosen_item[user];
        const float pred = mf_predict(p_in, q_in, user_bias_in, item_bias_in, user, item, global_bias);
        const float error = ratings[user] - pred;
        user_bias_out[user] = user_bias_in[user] + learning_rate * (error - lambda * user_bias_in[user]);
    } else if (idx < total) {
        const int item = idx - item_bias_base;
        float value = item_bias_in[item];
        unsigned char updated = 0u;
        if (item < num_users && chosen_item[item] == item) {
            const float pred = mf_predict(p_in, q_in, user_bias_in, item_bias_in, item, item, global_bias);
            const float error = ratings[item] - pred;
            value = value + learning_rate * (error - lambda * value);
            updated = 1u;
        }
        item_bias_out[item] = value;
        item_updated_out[item] = updated;
    }
}

static void build_inputs(int num_users, int num_items, int items_per_user, std::vector<float> &p,
                         std::vector<float> &q, std::vector<float> &user_bias, std::vector<float> &item_bias,
                         std::vector<int> &chosen_item, std::vector<float> &ratings, float &global_bias) {
    std::mt19937 rng(HOST_RANDOM_SEED);
    std::uniform_real_distribution<float> rating_dist(1.0f, 5.0f);
    std::uniform_real_distribution<float> factor_dist(-0.5f, 0.5f);

    p.resize(num_users * LATENT_FACTORS);
    q.resize(num_items * LATENT_FACTORS);
    user_bias.resize(num_users);
    item_bias.resize(num_items);
    chosen_item.resize(num_users);
    ratings.resize(num_users);

    for (float &v : p) {
        v = factor_dist(rng);
    }
    for (float &v : q) {
        v = factor_dist(rng);
    }
    for (float &v : user_bias) {
        v = factor_dist(rng);
    }
    for (float &v : item_bias) {
        v = factor_dist(rng);
    }
    for (int u = 0; u < num_users; ++u) {
        chosen_item[u] = u % num_items;
        ratings[u] = rating_dist(rng) + 0.001f * (float)(items_per_user);
    }
    global_bias = factor_dist(rng);
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <num_users> <num_items> <items_per_user>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const int num_users = atoi(argv[1]);
    const int num_items = atoi(argv[2]);
    const int items_per_user = atoi(argv[3]);
    if (num_users <= 0 || num_items <= 0 || items_per_user <= 0) {
        return EXIT_FAILURE;
    }

    std::vector<float> h_p;
    std::vector<float> h_q;
    std::vector<float> h_user_bias;
    std::vector<float> h_item_bias;
    std::vector<int> h_chosen_item;
    std::vector<float> h_ratings;
    float global_bias = 0.0f;
    build_inputs(num_users, num_items, items_per_user, h_p, h_q, h_user_bias, h_item_bias, h_chosen_item, h_ratings,
                 global_bias);

    std::vector<float> h_p_out(h_p.size());
    std::vector<float> h_q_out(h_q.size());
    std::vector<float> h_user_bias_out(h_user_bias.size());
    std::vector<float> h_item_bias_out(h_item_bias.size());
    std::vector<unsigned char> h_item_updated_out(num_items);

    float *d_p = nullptr;
    float *d_q = nullptr;
    float *d_user_bias = nullptr;
    float *d_item_bias = nullptr;
    int *d_chosen_item = nullptr;
    float *d_ratings = nullptr;
    float *d_p_out = nullptr;
    float *d_q_out = nullptr;
    float *d_user_bias_out = nullptr;
    float *d_item_bias_out = nullptr;
    unsigned char *d_item_updated_out = nullptr;

    CUDA_CHECK(cudaMalloc(&d_p, h_p.size() * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&d_q, h_q.size() * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&d_user_bias, h_user_bias.size() * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&d_item_bias, h_item_bias.size() * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&d_chosen_item, h_chosen_item.size() * sizeof(int)));
    CUDA_CHECK(cudaMalloc(&d_ratings, h_ratings.size() * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&d_p_out, h_p_out.size() * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&d_q_out, h_q_out.size() * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&d_user_bias_out, h_user_bias_out.size() * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&d_item_bias_out, h_item_bias_out.size() * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&d_item_updated_out, h_item_updated_out.size() * sizeof(unsigned char)));

    CUDA_CHECK(cudaMemcpy(d_p, h_p.data(), h_p.size() * sizeof(float), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_q, h_q.data(), h_q.size() * sizeof(float), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_user_bias, h_user_bias.data(), h_user_bias.size() * sizeof(float), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_item_bias, h_item_bias.data(), h_item_bias.size() * sizeof(float), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_chosen_item, h_chosen_item.data(), h_chosen_item.size() * sizeof(int), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_ratings, h_ratings.data(), h_ratings.size() * sizeof(float), cudaMemcpyHostToDevice));

    const int total_work = (num_users + num_items) * LATENT_FACTORS + num_users + num_items;
    dim3 block(BLOCK_SIZE);
    dim3 grid((total_work + block.x - 1) / block.x);
    matrix_factorization_sgd_kernel<<<grid, block>>>(d_p, d_q, d_user_bias, d_item_bias, d_chosen_item, d_ratings,
                                                     d_p_out, d_q_out, d_user_bias_out, d_item_bias_out,
                                                     d_item_updated_out, num_users, num_items, global_bias, 0.01f,
                                                     0.02f);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    fprintf(stderr, "GPUFI_OUTPUT base=%p bytes=%llu name=output_0\n", (void *)d_p_out,
            (unsigned long long)(h_p_out.size() * sizeof(float)));
    fflush(stderr);
    fprintf(stderr, "GPUFI_OUTPUT base=%p bytes=%llu name=output_1\n", (void *)d_q_out,
            (unsigned long long)(h_q_out.size() * sizeof(float)));
    fflush(stderr);
    fprintf(stderr, "GPUFI_OUTPUT base=%p bytes=%llu name=output_2\n", (void *)d_user_bias_out,
            (unsigned long long)(h_user_bias_out.size() * sizeof(float)));
    fflush(stderr);
    fprintf(stderr, "GPUFI_OUTPUT base=%p bytes=%llu name=output_3\n", (void *)d_item_bias_out,
            (unsigned long long)(h_item_bias_out.size() * sizeof(float)));
    fflush(stderr);
    fprintf(stderr, "GPUFI_OUTPUT base=%p bytes=%llu name=output_4\n", (void *)d_item_updated_out,
            (unsigned long long)(h_item_updated_out.size() * sizeof(unsigned char)));
    fflush(stderr);

    CUDA_CHECK(cudaMemcpy(h_p_out.data(), d_p_out, h_p_out.size() * sizeof(float), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(h_q_out.data(), d_q_out, h_q_out.size() * sizeof(float), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(h_user_bias_out.data(), d_user_bias_out, h_user_bias_out.size() * sizeof(float),
                          cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(h_item_bias_out.data(), d_item_bias_out, h_item_bias_out.size() * sizeof(float),
                          cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(h_item_updated_out.data(), d_item_updated_out,
                          h_item_updated_out.size() * sizeof(unsigned char), cudaMemcpyDeviceToHost));

    for (size_t i = 0; i < h_p_out.size(); ++i) {
        printf("%.9g ", h_p_out[i]);
    }
    for (size_t i = 0; i < h_q_out.size(); ++i) {
        printf("%.9g ", h_q_out[i]);
    }
    for (size_t i = 0; i < h_user_bias_out.size(); ++i) {
        printf("%.9g ", h_user_bias_out[i]);
    }
    for (size_t i = 0; i < h_item_bias_out.size(); ++i) {
        printf("%.9g ", h_item_bias_out[i]);
    }
    for (size_t i = 0; i < h_item_updated_out.size(); ++i) {
        printf("%d ", (int)h_item_updated_out[i]);
    }
    printf("\n");

    cudaFree(d_p);
    cudaFree(d_q);
    cudaFree(d_user_bias);
    cudaFree(d_item_bias);
    cudaFree(d_chosen_item);
    cudaFree(d_ratings);
    cudaFree(d_p_out);
    cudaFree(d_q_out);
    cudaFree(d_user_bias_out);
    cudaFree(d_item_bias_out);
    cudaFree(d_item_updated_out);
    return 0;
}
