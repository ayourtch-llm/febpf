/* bpf-to-bpf call across the .text boundary (exercises R_BPF_64_32).
 *   clang -O2 -target bpf -c subprog.c -o subprog.o                */
#define SEC(n) __attribute__((section(n), used))

static __attribute__((noinline)) long triple(long x)
{
    return x + x + x;
}

SEC("socket")
int prog(void *ctx)
{
    return (int)triple(14);
}
