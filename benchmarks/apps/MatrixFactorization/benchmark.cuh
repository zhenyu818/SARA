// Deterministic, race-free mini-batch SGD reference using actual CSR ratings.
// Algorithm adaptation and dataset preparation are documented in docs/benchmarks.md.
#include "../common/benchmark_support.cuh"
#include "../../src/cuda-sim/trace_integrity.h"
#include <fstream>
#include <sstream>
#include <string>
#include <tuple>
namespace sb = sara_bench;
static const int MF_RANK = 8;
// Correctness-only input identity. Hash the actual source vector passed to
// upload(), not an expected constant. No rating bytes enter public run logs.
template <typename T>
void mf_input_bytes(const char *name, const char *dtype,
                    const std::vector<T> &values, const T *destination = 0) {
    if (!sb::validate_cpu()) return;
    const uint32_t endian = 1;
    if (sizeof(T) != 4 || *reinterpret_cast<const unsigned char *>(&endian) != 1)
        sb::fail("MF input diagnostic requires little-endian 32-bit elements");
    sara_trace::sha256 hash;
    hash.update(values.data(), values.size() * sizeof(T));
    if (hash.overflow()) sb::fail("MF input diagnostic byte count overflow");
    const std::string checksum = hash.hex_digest();
    ::flockfile(stderr);
    std::fprintf(stderr, "MF_INPUT_BYTES version=1 name=%s dtype=%s byte_order=little count=%llu destination=",
                 name, dtype, static_cast<unsigned long long>(values.size()));
    if (destination)
        std::fprintf(stderr, "0x%llx", static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(destination)));
    else std::fprintf(stderr, "none");
    std::fprintf(stderr, " sha256=%s\n", checksum.c_str());
    std::fflush(stderr);
    ::funlockfile(stderr);
}
template <typename T>
void mf_upload(const char *name, const char *dtype, sb::DeviceBuffer<T> &device,
               const std::vector<T> &values) {
    mf_input_bytes(name, dtype, values, device.get());
    device.upload(values);
}
__device__ float mf_prediction(const float *p, const float *q, const float *ub, const float *ib,
                               int user, int item, float global_bias) {
    float prediction = global_bias + ub[user] + ib[item];
    for (int f = 0; f < MF_RANK; ++f) prediction += p[user * MF_RANK + f] * q[item * MF_RANK + f];
    return prediction;
}
__global__ void mf_snapshot_step(const float *p, const float *q, const float *ub, const float *ib,
                                 float *po, float *qo, float *ubo, float *ibo,
                                 const int *user_rating, const int *item_rating,
                                 const int *rating_user, const int *column, const float *ratings,
                                 int users, int items, int batch, float global_bias) {
    const float rate = 0.01f, regularization = 0.01f;
    int index = blockIdx.x * blockDim.x + threadIdx.x;
    int pc = users * MF_RANK, qc = items * MF_RANK;
    if (index < pc) {
        int user = index / MF_RANK, factor = index % MF_RANK;
        int rid = user_rating[batch * users + user];
        float result = p[index];
        if (rid >= 0) {
            int item = column[rid];
            float error = ratings[rid] - mf_prediction(p, q, ub, ib, user, item, global_bias);
            result += rate * (error * q[item * MF_RANK + factor] - regularization * p[index]);
        }
        po[index] = result;
    } else if (index < pc + qc) {
        int qi = index - pc, item = qi / MF_RANK, factor = qi % MF_RANK;
        int rid = item_rating[batch * items + item];
        float result = q[qi];
        if (rid >= 0) {
            int user = rating_user[rid];
            float error = ratings[rid] - mf_prediction(p, q, ub, ib, user, item, global_bias);
            result += rate * (error * p[user * MF_RANK + factor] - regularization * q[qi]);
        }
        qo[qi] = result;
    } else if (index < pc + qc + users) {
        int user = index - pc - qc, rid = user_rating[batch * users + user];
        float result = ub[user];
        if (rid >= 0) {
            int item = column[rid];
            float error = ratings[rid] - mf_prediction(p, q, ub, ib, user, item, global_bias);
            result += rate * (error - regularization * ub[user]);
        }
        ubo[user] = result;
    } else if (index < pc + qc + users + items) {
        int item = index - pc - qc - users, rid = item_rating[batch * items + item];
        float result = ib[item];
        if (rid >= 0) {
            int user = rating_user[rid];
            float error = ratings[rid] - mf_prediction(p, q, ub, ib, user, item, global_bias);
            result += rate * (error - regularization * ib[item]);
        }
        ibo[item] = result;
    }
}
int main(int argc, char **argv) {
    {
    if (argc != 4) sb::fail("usage: MatrixFactorization users items max_ratings_per_user");
    int users = sb::integer(argv[1]), items = sb::integer(argv[2]), cap = sb::integer(argv[3]);
    int pc = sb::product(users, MF_RANK), qc = sb::product(items, MF_RANK);
    if (pc > sb::MAX_INDEX - qc - users - items) sb::fail("parameter count overflow");
    const char *override_path = std::getenv("SARA_MF_RATINGS");
    std::string path = override_path ? override_path : "test_apps/MatrixFactorization/data/local/ml-100k/u.data";
    std::ifstream file(path.c_str());
    if (!file) sb::fail("ratings missing: run python3 test_apps/MatrixFactorization/prepare_data.py; or set SARA_MF_RATINGS");
    std::vector<std::tuple<int, int, float> > records;
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream row(line);
        int user, item; float rating;
        if (!(row >> user >> item >> rating) || user < 1 || item < 1 ||
            !std::isfinite(rating) || rating < 1 || rating > 5) sb::fail("malformed 1-based user item rating record");
        if (user <= users && item <= items) records.push_back(std::make_tuple(user - 1, item - 1, rating));
    }
    std::sort(records.begin(), records.end());
    std::vector<int> row_ptr(users + 1, 0), column, rating_user;
    std::vector<float> rating;
    int previous_user = -1, previous_item = -1, used = 0;
    for (size_t i = 0; i < records.size(); ++i) {
        int user = std::get<0>(records[i]), item = std::get<1>(records[i]);
        if (user == previous_user && item == previous_item) sb::fail("duplicate user-item rating");
        if (user != previous_user) used = 0;
        previous_user = user; previous_item = item;
        if (used++ >= cap) continue;
        rating_user.push_back(user); column.push_back(item); rating.push_back(std::get<2>(records[i]));
        ++row_ptr[user + 1];
    }
    if (rating.empty()) sb::fail("selected rating subset is empty");
    for (int user = 0; user < users; ++user) row_ptr[user + 1] += row_ptr[user];
    if (rating.size() > static_cast<size_t>(std::numeric_limits<int>::max())) sb::fail("too many ratings");
    // Stable greedy edge coloring: each mini-batch is a user/item matching.
    std::vector<int> pending, user_rating, item_rating;
    for (int user = 0; user < users; ++user)
        for (int rid = row_ptr[user]; rid < row_ptr[user+1]; ++rid) pending.push_back(rid);
    int batches = 0;
    while (!pending.empty()) {
        std::vector<int> ur(users, -1), ir(items, -1), remaining;
        for (int rid : pending) {
            int user = rating_user[rid], item = column[rid];
            if (ur[user] < 0 && ir[item] < 0) { ur[user] = rid; ir[item] = rid; }
            else remaining.push_back(rid);
        }
        user_rating.insert(user_rating.end(), ur.begin(), ur.end());
        item_rating.insert(item_rating.end(), ir.begin(), ir.end());
        pending.swap(remaining); ++batches;
    }
    sb::product(batches, users); sb::product(batches, items);
    mf_input_bytes("row_ptr", "i32", row_ptr);
    sb::Rng rng;
    std::vector<float> p(pc), q(qc), ub(users, 0.0f), ib(items, 0.0f);
    for (float &v : p) v = 0.1f * rng.signed_uniform();
    for (float &v : q) v = 0.1f * rng.signed_uniform();
    double rating_sum = 0; for (float value : rating) rating_sum += value;
    float global_bias = static_cast<float>(rating_sum / rating.size());
    sb::DeviceBuffer<float> p0(pc), p1(pc), q0(qc), q1(qc), ub0(users), ub1(users), ib0(items), ib1(items), dr(rating.size());
    sb::DeviceBuffer<int> dur(user_rating.size()), dir(item_rating.size()), dru(rating_user.size()), dc(column.size());
    p0.upload(p); q0.upload(q); ub0.upload(ub); ib0.upload(ib);
    mf_upload("rating", "f32", dr, rating);
    mf_upload("user_rating", "i32", dur, user_rating);
    mf_upload("item_rating", "i32", dir, item_rating);
    mf_upload("rating_user", "i32", dru, rating_user);
    mf_upload("column", "i32", dc, column);
    float *dp[2] = {p0.get(), p1.get()}, *dq[2] = {q0.get(), q1.get()};
    float *du[2] = {ub0.get(), ub1.get()}, *di[2] = {ib0.get(), ib1.get()};
    int current = 0, parameter_count = pc + qc + users + items;
    for (int batch = 0; batch < batches; ++batch) {
        int next = current ^ 1;
        mf_snapshot_step<<<sb::ceil_div(parameter_count, 256), 256>>>(
            dp[current], dq[current], du[current], di[current], dp[next], dq[next], du[next], di[next],
            dur.get(), dir.get(), dru.get(), dc.get(), dr.get(), users, items, batch, global_bias);
        SARA_CUDA(cudaGetLastError()); current = next;
    }
    sb::finish_kernel();
    std::vector<float> po = sb::output("P", "f32", dp[current], pc), qo = sb::output("Q", "f32", dq[current], qc);
    std::vector<float> ubo = sb::output("user_bias", "f32", du[current], users);
    std::vector<float> ibo = sb::output("item_bias", "f32", di[current], items);
    std::fprintf(stderr, "MF_INPUT ratings=%llu batches=%d rank=%d epochs=1\n",
                 static_cast<unsigned long long>(rating.size()), batches, MF_RANK);
    if (sb::validate_cpu()) {
        std::vector<double> rp(p.begin(), p.end()), rq(q.begin(), q.end()), ru(users, 0), ri(items, 0);
        const double rate = static_cast<double>(0.01f), reg = static_cast<double>(0.01f);
        for (int batch = 0; batch < batches; ++batch) {
            // Matching edges share no model parameters; serial in-place CPU updates
            // equal a snapshot mini-batch without reusing the GPU indexing scheme.
            for (int user = 0; user < users; ++user) {
                int rid = user_rating[batch * users + user]; if (rid < 0) continue;
                int item = column[rid];
                double prediction = global_bias + ru[user] + ri[item];
                for (int f = 0; f < MF_RANK; ++f) prediction += rp[user * MF_RANK + f] * rq[item * MF_RANK + f];
                double error = rating[rid] - prediction;
                for (int f = 0; f < MF_RANK; ++f) {
                    int pi = user * MF_RANK + f, qi = item * MF_RANK + f;
                    double old_p = rp[pi], old_q = rq[qi];
                    rp[pi] += rate * (error * old_q - reg * old_p);
                    rq[qi] += rate * (error * old_p - reg * old_q);
                }
                ru[user] += rate * (error - reg * ru[user]); ri[item] += rate * (error - reg * ri[item]);
            }
        }
        sb::verify_close("P", po, rp, 2e-4, 2e-4); sb::verify_close("Q", qo, rq, 2e-4, 2e-4);
        sb::verify_close("user_bias", ubo, ru, 2e-4, 2e-4); sb::verify_close("item_bias", ibo, ri, 2e-4, 2e-4);

    }
    } // All DeviceBuffer destructors have completed their cudaFree calls.
    SARA_CUDA(cudaDeviceSynchronize());
    SARA_CUDA(cudaThreadExit());
    if (sb::validate_cpu()) sb::validation_passed("MatrixFactorization");
    return 0;
}
