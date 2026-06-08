// Standalone Dijkstra Kernel1 harness (result generator)
#include <cuda_runtime.h>
#include <float.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define D_SEED 2026
#define BLOCK_SIZE 256

#define CUDA_CHECK(call)                                                                                               \
    do {                                                                                                               \
        cudaError_t err__ = (call);                                                                                    \
        if (err__ != cudaSuccess) {                                                                                    \
            fprintf(stderr, "CUDA error at %s:%d code=%d(%s)\n", __FILE__, __LINE__, (int)err__,                       \
                    cudaGetErrorString(err__));                                                                        \
            exit(EXIT_FAILURE);                                                                                        \
        }                                                                                                              \
    } while (0)

static inline int iDivUp(int a, int b) { return (a + b - 1) / b; }

// Core Dijkstra relaxation kernel (kept exactly as source logic)
__global__ void Kernel1(const int *__restrict__ vertexArray, const int *__restrict__ edgeArray,
                        const float *__restrict__ weightArray, bool *__restrict__ finalizedVertices,
                        float *__restrict__ shortestDistances, float *__restrict__ updatingShortestDistances,
                        const int numVertices, const int numEdges) {
    __shared__ bool shared_finalized_source;
    __shared__ float shared_source_distance;
    if (threadIdx.x == 0) {
        shared_finalized_source = finalizedVertices[0];
        shared_source_distance = shortestDistances[0];
    }
    __syncthreads();

    int tid = blockIdx.x * blockDim.x + threadIdx.x;

    if (tid < numEdges && shared_finalized_source == true) {
        int nid = edgeArray[tid];
        float candidate = shared_source_distance + weightArray[tid];
        if (candidate < updatingShortestDistances[nid]) {
            updatingShortestDistances[nid] = candidate;
        }
    }
}

// Build one source frontier with unique outgoing neighbors.
static void generate_graph(int V, int deg, int *vertexArray, int *edgeArray) {
    for (int i = 0; i < V; ++i)
        vertexArray[i] = 0;
    for (int j = 0; j < deg; ++j) {
        int v;
        for (;;) {
            v = 1 + (rand() % (V - 1));
            bool dup = false;
            for (int k = 0; k < j; ++k) {
                if (edgeArray[k] == v) {
                    dup = true;
                    break;
                }
            }
            if (!dup)
                break;
        }
        edgeArray[j] = v;
    }
}

int main(int argc, char **argv) {
    int V = 64;     // number of vertices
    int DEG = 4;    // neighbors per vertex
    int src = 0;    // source vertex

    if (argc >= 3) {
        V = atoi(argv[1]);
        DEG = atoi(argv[2]);
        if (V <= 0 || DEG <= 0) return 0;
        if (DEG > V - 1) DEG = V - 1;
    }

    srand(D_SEED);

    const int E = DEG;

    int *h_vertexArray = (int *)malloc(sizeof(int) * V);
    int *h_edgeArray = (int *)malloc(sizeof(int) * E);
    float *h_weightArray = (float *)malloc(sizeof(float) * E);
    bool *h_finalizedVertices = (bool *)malloc(sizeof(bool) * V);
    float *h_shortestDistances = (float *)malloc(sizeof(float) * V);
    float *h_updatingShortestDistances = (float *)malloc(sizeof(float) * V);

    generate_graph(V, DEG, h_vertexArray, h_edgeArray);
    for (int i = 0; i < E; ++i) {
        h_weightArray[i] = (float)rand() / (float)RAND_MAX;
    }

    for (int i = 0; i < V; ++i) {
        h_finalizedVertices[i] = (i == src);
        h_shortestDistances[i] = (i == src) ? 0.0f : FLT_MAX;
        h_updatingShortestDistances[i] = h_shortestDistances[i];
    }

    int *d_vertexArray = nullptr, *d_edgeArray = nullptr;
    float *d_weightArray = nullptr, *d_shortestDistances = nullptr, *d_updatingShortestDistances = nullptr;
    bool *d_finalizedVertices = nullptr;

    CUDA_CHECK(cudaMalloc(&d_vertexArray, sizeof(int) * V));
    CUDA_CHECK(cudaMalloc(&d_edgeArray, sizeof(int) * E));
    CUDA_CHECK(cudaMalloc(&d_weightArray, sizeof(float) * E));
    CUDA_CHECK(cudaMalloc(&d_finalizedVertices, sizeof(bool) * V));
    CUDA_CHECK(cudaMalloc(&d_shortestDistances, sizeof(float) * V));
    CUDA_CHECK(cudaMalloc(&d_updatingShortestDistances, sizeof(float) * V));

    CUDA_CHECK(cudaMemcpy(d_vertexArray, h_vertexArray, sizeof(int) * V, cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_edgeArray, h_edgeArray, sizeof(int) * E, cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_weightArray, h_weightArray, sizeof(float) * E, cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_finalizedVertices, h_finalizedVertices, sizeof(bool) * V, cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_shortestDistances, h_shortestDistances, sizeof(float) * V, cudaMemcpyHostToDevice));
    CUDA_CHECK(
        cudaMemcpy(d_updatingShortestDistances, h_updatingShortestDistances, sizeof(float) * V, cudaMemcpyHostToDevice));

    dim3 block(BLOCK_SIZE);
    dim3 grid(iDivUp(V, BLOCK_SIZE));
    Kernel1<<<grid, block>>>(d_vertexArray, d_edgeArray, d_weightArray, d_finalizedVertices, d_shortestDistances,
                             d_updatingShortestDistances, V, E);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    fprintf(stderr, "GPUFI_OUTPUT base=%p bytes=%llu name=output_0\n",
            (void *)d_updatingShortestDistances,
            (unsigned long long)(sizeof(float) * V));
    fflush(stderr);
    CUDA_CHECK(
        cudaMemcpy(h_updatingShortestDistances, d_updatingShortestDistances, sizeof(float) * V, cudaMemcpyDeviceToHost));

    for (int i = 0; i < V; ++i) {
        printf("%.9g%c", h_updatingShortestDistances[i], (i == V - 1) ? '\n' : ' ');
    }

    free(h_vertexArray);
    free(h_edgeArray);
    free(h_weightArray);
    free(h_finalizedVertices);
    free(h_shortestDistances);
    free(h_updatingShortestDistances);

    cudaFree(d_vertexArray);
    cudaFree(d_edgeArray);
    cudaFree(d_weightArray);
    cudaFree(d_finalizedVertices);
    cudaFree(d_shortestDistances);
    cudaFree(d_updatingShortestDistances);
    return 0;
}
