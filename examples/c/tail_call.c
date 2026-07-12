#define SEC(n) __attribute__((section(n), used))
#define __uint(name, val) int (*name)[val]
#define __array(name, val) typeof(val) *name[]

#define BPF_MAP_TYPE_PROG_ARRAY 3

static long (*bpf_tail_call)(void *ctx, void *map, unsigned int index) = (void *)12;

SEC("socket/target")
int target(void *ctx)
{
    (void)ctx;
    return 42;
}

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __array(values, int(void *));
} progs SEC(".maps") = {
    .values = { [0] = (void *)&target },
};

SEC("socket/entry")
int entry(void *ctx)
{
    bpf_tail_call(ctx, &progs, 0);
    return 7;
}

char LICENSE[] SEC("license") = "GPL";
