/* Kconfig externs: LINUX_KERNEL_VERSION lives in the virtual `.kconfig`
 * section and is resolved by the loader (libbpf fills it from uname; febpf
 * from /proc/sys/kernel/osrelease). The ELF symbol is UNDefined; the BTF
 * carries the extern VAR in a `.kconfig` DATASEC.
 * Compile:
 *   clang -O2 -g -target bpf -c kconfig.c -o kconfig.o                    */
#define SEC(n) __attribute__((section(n), used))
#define __kconfig __attribute__((section(".kconfig")))

extern unsigned int LINUX_KERNEL_VERSION __kconfig;

SEC("socket")
int kver(void *ctx)
{
    /* 1 when running on a kernel >= 3.0.0 (i.e. the extern was filled). */
    return LINUX_KERNEL_VERSION >= ((3 << 16) | (0 << 8)) ? 1 : 0;
}
