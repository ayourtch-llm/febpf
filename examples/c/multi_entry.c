/* Multiple global entries in one SEC() section, each calling a distinct
 * static .text subprogram. Exercises entry slicing plus SECTION-symbol
 * R_BPF_64_32 call addends.
 *
 *   clang -O2 -g -target bpf -c multi_entry.c -o multi_entry.o
 */
#define SEC(n) __attribute__((section(n), used))

static __attribute__((noinline)) int add_one(int x)
{
    return x + 1;
}

static __attribute__((noinline)) int add_seven(int x)
{
    return x + 7;
}

SEC("xdp")
int first_entry(void *ctx)
{
    return add_one(*(int *)ctx);
}

SEC("xdp")
int second_entry(void *ctx)
{
    return add_seven(*(int *)ctx);
}
