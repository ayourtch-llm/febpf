/* Target-BTF side of the undefined kfunc relocation fixture. */
#define SEC(name) __attribute__((section(name), used))

__attribute__((used, noinline))
int kernel_function(void)
{
    return 7;
}

SEC("xdp")
int target_entry(void *ctx)
{
    return ctx != 0;
}
