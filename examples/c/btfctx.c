/* Self-contained tp_btf fixture: defines both the program AND the
 * target-side types (task_struct, the btf_trace_sched_switch typedef the
 * kernel synthesizes for the tracepoint), so tests can use the object's own
 * .BTF as --target-btf without depending on a running kernel. The shapes
 * mirror the real sched_switch signature: (void *__data, bool preempt,
 * task_struct *prev, task_struct *next).
 */
typedef unsigned long long u64;

struct task_struct {
    int pid;
    int prio;
    struct task_struct *parent;
    char comm[16];
};

typedef void (*btf_trace_sched_switch)(void *__data, _Bool preempt,
                                       struct task_struct *prev,
                                       struct task_struct *next);

/* Keep the typedef reachable in the emitted BTF. */
static volatile btf_trace_sched_switch __btf_trace_keep __attribute__((used));

__attribute__((section("tp_btf/sched_switch"), used))
int handle__sched_switch(u64 *ctx)
{
    struct task_struct *prev = (struct task_struct *)ctx[1];
    struct task_struct *next = (struct task_struct *)ctx[2];
    /* scalar field reads + a nested pointer chase (parent->pid) */
    return prev->prio + next->pid + prev->parent->pid;
}
