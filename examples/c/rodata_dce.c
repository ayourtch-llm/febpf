/* Frozen-.rodata dead-code elimination (docs/specs/rodata-dce.md).
 *
 * `const volatile` config flags with their compile-time defaults: clang
 * cannot fold them (volatile), so the object branches on values loaded from
 * the frozen `.rodata` map. The loader must resolve those loads to constants
 * and remove the code they prove dead — including the whole `slow_path`
 * subprogram stitched in from `.text` — exactly as libbpf does before the
 * kernel sees a program; otherwise the verifier rejects the unreachable code.
 *
 * Compile:
 *   clang -O2 -g -target bpf -c rodata_dce.c -o rodata_dce.o              */
#define SEC(n) __attribute__((section(n), used))

const volatile int use_slow_path = 0; /* .rodata, frozen; default off */
const volatile int scale = 4;         /* .rodata, read at runtime      */

static __attribute__((noinline)) long slow_path(long x)
{
    return x * 0xdead;
}

SEC("socket")
int select_path(void *ctx)
{
    long v = *(unsigned int *)ctx;
    if (use_slow_path)
        return slow_path(v);
    return v * scale;
}
