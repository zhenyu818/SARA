// Complete trained-model forward harness proposal; not a single-operator proxy.
// Upstream computation and its MIT license are retained alongside this file.
#define TESTING
#include "common/forward.cuh"
#include <stdint.h>
#include <time.h>

static void raw_output(const char *name, const char *dtype, const void *address,
                       const void *host_data, size_t count, size_t item_size) {
    const uint32_t endian = 1;
    if (*(const unsigned char *)&endian != 1) exit(3);
    flockfile(stdout);
    flockfile(stderr);
    fflush(stdout);
    fprintf(stderr, "\nGPUFI_OUTPUT base=%p bytes=%llu name=%s\n", address,
            (unsigned long long)(count * item_size), name);
    fflush(stderr);
    printf("GPUFI_RAW_OUTPUT %s %s %llu ", name, dtype,
           (unsigned long long)count);
    const unsigned char *bytes = (const unsigned char *)host_data;
    for (size_t i = 0; i < count * item_size; ++i) printf("%02x", (unsigned)bytes[i]);
    printf("\n");
    fflush(stdout);
    funlockfile(stderr);
    funlockfile(stdout);
}

static unsigned long long monotonic_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        perror("clock_gettime"); exit(3);
    }
    return (unsigned long long)value.tv_sec * 1000000000ULL +
           (unsigned long long)value.tv_nsec;
}

int main(int argc, char **argv) {
    const unsigned long long application_start_ns = monotonic_ns();
    if (argc != 2) { fprintf(stderr, "usage: %s stories260K.bin\n", argv[0]); return 2; }
    // These header values are inferred from the published training configuration,
    // defined binary layout and published byte length; admission verifies them.
    // The controller must additionally verify the official pinned full-file SHA.
    FILE *input = fopen(argv[1], "rb");
    int header[7];
    if (!input || sizeof(int) != 4 || fread(header, sizeof(int), 7, input) != 7) return 2;
    const int expected[7] = {64, 172, 5, 8, 4, 512, 512};
    for (int i = 0; i < 7; ++i) if (header[i] != expected[i]) { fclose(input); return 2; }
    if (fseek(input, 0, SEEK_END) || ftell(input) != 1056540L) { fclose(input); return 2; }
    fclose(input);
    Transformer model;
    memset(&model, 0, sizeof(model));
    build_transformer(&model, argv[1]);
    // Every decoder layer, GQA, RoPE, FFN, final norm and vocabulary projection
    // remain in upstream forward(). No sampled token is fed back to the GPU.
    // The sole input token1 is fixed before its complete forward.
    // Do not sample or feed any argmax back into the GPU.
#ifdef USE_CUDA
    CUCHK(cudaGetLastError());
    CUCHK(cudaDeviceSynchronize());
#endif
    const unsigned long long forward_start_ns = monotonic_ns();
    float *logits = forward(&model, 1, 0);
#ifdef USE_CUDA
    CUCHK(cudaGetLastError());
    CUCHK(cudaDeviceSynchronize());
    const void *logits_address = model.state.logits_gpu;
#else
    const void *logits_address = logits;
#endif
    const unsigned long long forward_end_ns = monotonic_ns();
    const int32_t greedy_next = (int32_t)sample_argmax(logits, model.config.vocab_size);
    printf("GPUFI_LLM_FORWARD version=1 model=Stories260K batch=1 tokens=1 input_tokens=1 positions=0 final_position=0 layers=5 expected_computational_launches=72 precision=fp32\n");
    raw_output("logits", "f32", logits_address, logits, 512, sizeof(float));
    // Host-only display: no GPUFI_OUTPUT/RAW_OUTPUT declaration for this word.
    printf("GPUFI_LLM_HOST_ARGMAX greedy_next=%d source=final_512_logits GPU_root=0\n", (int)greedy_next);
    fflush(stdout);
    free_transformer(&model);
#ifdef USE_CUDA
    CUCHK(cudaDeviceSynchronize());
    CUCHK(cudaThreadExit());
#endif
    printf("GPUFI_LLM_OUTPUT_SCOPE logits=device_forward_only greedy_next=host_display_only final_position=0 intermediate_logits_output=0 feedback_to_gpu=0\n");
    fflush(stdout);
    const unsigned long long application_end_ns = monotonic_ns();
    printf("GPUFI_LLM_WALLCLOCK clock=MONOTONIC forward_wall_ns=%llu application_body_wall_ns=%llu forward_scope=one_complete_forward_including_device_synchronization application_scope=main_entry_through_output_flush_and_cleanup final_timing_line_excluded=1\n",
           forward_end_ns - forward_start_ns, application_end_ns - application_start_ns);
    fflush(stdout);
    return 0;
}
