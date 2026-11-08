// Deterministic complete GPU Dijkstra reference; no host relaxation or float atomics.
#include "../common/benchmark_support.cuh"
#include <functional>
#include <queue>
#include <fstream>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
namespace sb = sara_bench;
static const uint32_t DIJKSTRA_INF = 0xffffffffu;
__device__ inline bool dijkstra_less(uint32_t a, uint32_t ai, uint32_t b, uint32_t bi) {
    return a < b || (a == b && ai < bi);
}
__global__ void dijkstra_block_min(const uint32_t *distance, const unsigned char *done,
                                  uint32_t *block_distance, uint32_t *block_vertex, int vertices) {
    __shared__ uint32_t ds[256], vs[256];
    int tid = threadIdx.x, vertex = blockIdx.x * 256 + tid;
    ds[tid] = vertex < vertices && !done[vertex] ? distance[vertex] : 0xffffffffu;
    vs[tid] = vertex < vertices && !done[vertex] ? static_cast<uint32_t>(vertex) : 0xffffffffu;
    __syncthreads();
    for (int step = 128; step; step >>= 1) {
        if (tid < step && dijkstra_less(ds[tid + step], vs[tid + step], ds[tid], vs[tid])) {
            ds[tid] = ds[tid + step]; vs[tid] = vs[tid + step];
        }
        __syncthreads();
    }
    if (!tid) { block_distance[blockIdx.x] = ds[0]; block_vertex[blockIdx.x] = vs[0]; }
}
__global__ void dijkstra_select(const uint32_t *block_distance, const uint32_t *block_vertex,
                               unsigned char *done, uint32_t *selected, int blocks) {
    __shared__ uint32_t ds[256], vs[256];
    int tid = threadIdx.x;
    uint32_t best = 0xffffffffu, vertex = 0xffffffffu;
    for (int i = tid; i < blocks; i += 256)
        if (dijkstra_less(block_distance[i], block_vertex[i], best, vertex)) {
            best = block_distance[i]; vertex = block_vertex[i];
        }
    ds[tid] = best; vs[tid] = vertex;
    __syncthreads();
    for (int step = 128; step; step >>= 1) {
        if (tid < step && dijkstra_less(ds[tid + step], vs[tid + step], ds[tid], vs[tid])) {
            ds[tid] = ds[tid + step]; vs[tid] = vs[tid + step];
        }
        __syncthreads();
    }
    if (!tid) {
        selected[0] = ds[0] == 0xffffffffu ? 0xffffffffu : vs[0];
        if (selected[0] != 0xffffffffu) done[selected[0]] = 1;
    }
}
__global__ void dijkstra_relax(const int *row_ptr, const int *column, const uint32_t *weight,
                              uint32_t *distance, const unsigned char *done,
                              const uint32_t *selected, int max_degree) {
    uint32_t source = selected[0];
    int lane = blockIdx.x * blockDim.x + threadIdx.x;
    if (source == 0xffffffffu || lane >= max_degree) return;
    int edge = row_ptr[source] + lane;
    if (edge >= row_ptr[source + 1]) return;
    int destination = column[edge];
    if (!done[destination] && distance[source] <= 0xffffffffu - weight[edge]) {
        uint32_t candidate = distance[source] + weight[edge];
        if (candidate < distance[destination]) distance[destination] = candidate;
    }
}
int main(int argc, char **argv) {
    {
    if (argc != 3) sb::fail("usage: Dijkstra vertices out_degree");
    int vertices = sb::integer(argv[1]), degree = sb::integer(argv[2]);
    if (vertices < 2 || degree >= vertices || vertices > 1000000)
        sb::fail("require 2 <= vertices <= 1000000 and 1 <= out_degree < vertices");
    int edge_count = sb::product(vertices, degree), blocks = sb::ceil_div(vertices, 256);
    std::vector<int> row_ptr(vertices + 1), column(edge_count);
    std::vector<uint32_t> weight(edge_count), initial(vertices, DIJKSTRA_INF);
    std::vector<unsigned char> done(vertices, 0);
    sb::Rng rng;
    const char *graph_file = std::getenv("SARA_DIJKSTRA_GRAPH");
    if (graph_file) {
        std::ifstream file(graph_file);
        if (!file) sb::fail("cannot open SARA_DIJKSTRA_GRAPH");
        std::vector<std::tuple<int, int, uint32_t> > edges;
        std::string line;
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') continue;
            std::istringstream row(line); int source, destination, cost;
            if (!(row >> source >> destination >> cost) || source < 0 || source >= vertices ||
                destination < 0 || destination >= vertices || cost < 0 || cost > 16)
                sb::fail("invalid graph fixture: require 0-based vertices and weights in [0,16]");
            edges.push_back(std::make_tuple(source, destination, static_cast<uint32_t>(cost)));
        }
        std::sort(edges.begin(), edges.end());
        if (edges.size() > static_cast<size_t>(edge_count)) sb::fail("graph fixture exceeds degree bound");
        column.resize(edges.size()); weight.resize(edges.size());
        for (size_t e = 0; e < edges.size(); ++e) {
            int source = std::get<0>(edges[e]), destination = std::get<1>(edges[e]);
            if (e && source == std::get<0>(edges[e-1]) && destination == std::get<1>(edges[e-1]))
                sb::fail("duplicate outgoing destination would violate race-free relaxation");
            ++row_ptr[source+1]; column[e] = destination; weight[e] = std::get<2>(edges[e]);
        }
        for (int source = 0; source < vertices; ++source) {
            if (row_ptr[source+1] > degree) sb::fail("graph fixture exceeds out_degree bound");
            row_ptr[source+1] += row_ptr[source];
        }
        edge_count = static_cast<int>(edges.size());
    } else for (int u = 0; u < vertices; ++u) {
        row_ptr[u] = u * degree;
        std::vector<int> chosen;
        chosen.push_back((u + 1) % vertices);  // connectivity without reducing to a star
        while (static_cast<int>(chosen.size()) < degree) {
            int v = static_cast<int>(rng.next() % vertices);
            if (v != u && std::find(chosen.begin(), chosen.end(), v) == chosen.end()) chosen.push_back(v);
        }
        for (int j = 0; j < degree; ++j) {
            column[u * degree + j] = chosen[j]; weight[u * degree + j] = 1u + rng.next() % 16u;
        }
    }
    row_ptr[vertices] = edge_count; initial[0] = 0;
    sb::DeviceBuffer<int> dr(row_ptr.size()), dc(column.size());
    sb::DeviceBuffer<uint32_t> dw(weight.size()), dd(vertices), bd(blocks), bv(blocks), selected(1);
    sb::DeviceBuffer<unsigned char> finalized(vertices);
    dr.upload(row_ptr); dc.upload(column); dw.upload(weight); dd.upload(initial); finalized.upload(done);
    for (int iteration = 0; iteration < vertices; ++iteration) {
        dijkstra_block_min<<<blocks, 256>>>(dd.get(), finalized.get(), bd.get(), bv.get(), vertices);
        SARA_CUDA(cudaGetLastError());
        dijkstra_select<<<1, 256>>>(bd.get(), bv.get(), finalized.get(), selected.get(), blocks);
        SARA_CUDA(cudaGetLastError());
        dijkstra_relax<<<sb::ceil_div(degree, 256), 256>>>(dr.get(), dc.get(), dw.get(), dd.get(),
                                                       finalized.get(), selected.get(), degree);
        SARA_CUDA(cudaGetLastError());
    }
    sb::finish_kernel();
    std::vector<uint32_t> out = sb::output("distances", "u32", dd.get(), vertices);
    if (sb::validate_cpu()) {
        typedef std::pair<uint32_t, int> Entry;
        std::priority_queue<Entry, std::vector<Entry>, std::greater<Entry> > queue;
        std::vector<uint32_t> ref(vertices, DIJKSTRA_INF); ref[0] = 0; queue.push(Entry(0, 0));
        while (!queue.empty()) {
            Entry current = queue.top(); queue.pop();
            if (current.first != ref[current.second]) continue;
            for (int e = row_ptr[current.second]; e < row_ptr[current.second + 1]; ++e) {
                uint32_t candidate = current.first + weight[e];
                if (candidate < ref[column[e]]) { ref[column[e]] = candidate; queue.push(Entry(candidate, column[e])); }
            }
        }
        sb::verify_equal("distances", out, ref);
    }
    } // All DeviceBuffer destructors have completed their cudaFree calls.
    SARA_CUDA(cudaDeviceSynchronize());
    SARA_CUDA(cudaThreadExit());
    if (sb::validate_cpu()) sb::validation_passed("Dijkstra");
    return 0;
}
