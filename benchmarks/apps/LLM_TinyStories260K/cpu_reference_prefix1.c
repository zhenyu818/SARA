// Harness only: the independent official CPU forward below is unmodified.
// MIT: upstream_cpu/LICENSE; karpathy/llama2.c@350e04fe35433e6d2941dce5a1f53308f87058eb.
#include <stdint.h>
#include <time.h>
#define TESTING
#include "upstream_cpu/run.c"

static unsigned long long monotonic_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        perror("clock_gettime"); exit(3);
    }
    return (unsigned long long)value.tv_sec * 1000000000ULL +
           (unsigned long long)value.tv_nsec;
}

static void emit_logits(const float *data) {
    fprintf(stderr, "\nGPUFI_OUTPUT base=%p bytes=2048 name=logits\n", (const void *)data);
    fflush(stderr);
    printf("GPUFI_RAW_OUTPUT logits f32 512 ");
    for (size_t i = 0; i < 512 * sizeof(float); ++i)
        printf("%02x", ((const unsigned char *)data)[i]);
    printf("\n"); fflush(stdout);
}

int main(int argc, char **argv) {
    const unsigned long long application_start_ns = monotonic_ns();
    const uint32_t endian = 1;
    if (argc != 2 || sizeof(int) != 4 || sizeof(float) != 4 || sizeof(Config) != 28
        || *(const unsigned char *)&endian != 1) return 2;
    FILE *input = fopen(argv[1], "rb"); int header[7];
    const int expected[7] = {64, 172, 5, 8, 4, 512, 512};
    if (!input || fread(header, 4, 7, input) != 7) return 2;
    for (int i = 0; i < 7; ++i) if (header[i] != expected[i]) { fclose(input); return 2; }
    if (fseek(input, 0, SEEK_END) || ftell(input) != 1056540L) { fclose(input); return 2; }
    fclose(input);
    Transformer model; memset(&model, 0, sizeof(model));
    build_transformer(&model, argv[1]);
    // Fixed legal token1; one complete official forward including its output
    // head. The volatile pointer preserves this independent CPU call.
    float *(*volatile complete_forward)(Transformer *, int, int) = forward;
    const unsigned long long forward_start_ns = monotonic_ns();
    float *logits = complete_forward(&model, 1, 0);
    const unsigned long long forward_end_ns = monotonic_ns();
    const int32_t next = sample_argmax(logits, 512);
    printf("GPUFI_LLM_CPU_FORWARD version=1 model=Stories260K batch=1 tokens=1 input_tokens=1 positions=0 final_position=0 layers=5 precision=fp32\n");
    emit_logits(logits);
    printf("GPUFI_LLM_HOST_ARGMAX greedy_next=%d source=final_512_logits GPU_root=0\n", (int)next);
    fflush(stdout);
    free_transformer(&model);
    const unsigned long long application_end_ns = monotonic_ns();
    printf("GPUFI_LLM_CPU_WALLCLOCK clock=MONOTONIC forward_wall_ns=%llu application_body_wall_ns=%llu forward_scope=one_complete_official_CPU_forward application_scope=main_entry_through_output_flush_and_cleanup final_timing_line_excluded=1\n",
           forward_end_ns - forward_start_ns, application_end_ns - application_start_ns);
    fflush(stdout);
    return 0;
}
