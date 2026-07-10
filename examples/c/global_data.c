/* Global data sections: .bss, .data, .rodata (incl. string literals).
 * Compile:
 *   clang -O2 -g -target bpf -c global_data.c -o global_data.o           */
#define SEC(n) __attribute__((section(n), used))

static long (*bpf_trace_printk)(const char *fmt, unsigned int size, ...) = (void *)6;

static long bss_counter;                          /* .bss   */
static long data_scale = 3;                       /* .data  */
static const int ro_table[4] = {10, 20, 30, 40};  /* .rodata */

SEC("socket")
int use_globals(void *ctx)
{
    unsigned int idx = *(unsigned int *)ctx & 3;
    bss_counter += ro_table[idx];        /* read .rodata, write .bss */
    data_scale += 1;                     /* write .data              */
    bpf_trace_printk("count=%ld", 10, bss_counter); /* fmt in .rodata.str1.1 */
    return bss_counter + 100 * data_scale;
}
