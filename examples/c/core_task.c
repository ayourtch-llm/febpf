/* CO-RE fixture against the *running kernel*: a deliberately wrong local
 * definition of task_struct. __builtin_preserve_field_info(..., 0) emits a
 * FIELD_BYTE_OFFSET relocation on an ALU immediate; relocated against
 * /sys/kernel/btf/vmlinux the program returns the kernel's real pid offset
 * (tests compare it with `bpftool btf dump`).
 *
 * Compile: clang -O2 -g -target bpf -c core_task.c -o core_task.o
 */

struct task_struct {
    int pid; /* locally at offset 0; thousands of bytes in on a real kernel */
} __attribute__((preserve_access_index));

int probe(void *ctx)
{
    struct task_struct *t = ctx;
    return __builtin_preserve_field_info(t->pid, 0 /* byte offset */);
}
