#define SEC(n) __attribute__((section(n), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

#define BPF_MAP_TYPE_PROG_ARRAY 3
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_ARRAY_OF_MAPS 12

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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, unsigned long);
} inner SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 2);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __array(values, typeof(inner));
} outer SEC(".maps") = {
    .values = { [1] = &inner },
};

SEC("socket/entry")
int entry(void *ctx)
{
    bpf_tail_call(ctx, &progs, 0);
    return 7;
}

char LICENSE[] SEC("license") = "GPL";
