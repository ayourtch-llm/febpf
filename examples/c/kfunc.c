/* Undefined __ksym call relocation fixture. */
#define SEC(name) __attribute__((section(name), used))
#define __ksym __attribute__((section(".ksyms")))

extern int kernel_function(void) __ksym;

SEC("xdp")
int entry(void *ctx)
{
    return kernel_function() + (ctx != 0);
}
