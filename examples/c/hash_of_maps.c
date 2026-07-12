#define SEC(n) __attribute__((section(n), used))
#define __uint(name, val) int (*name)[val]
#define __array(name, val) typeof(val) *name[]

#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4
#define BPF_MAP_TYPE_HASH_OF_MAPS 13

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(key_size, sizeof(unsigned long long));
    __uint(value_size, sizeof(unsigned int));
    __uint(max_entries, 8);
    __array(values, struct {
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        __uint(key_size, sizeof(unsigned int));
        __uint(value_size, sizeof(unsigned int));
    });
} outputs SEC(".maps");

SEC("socket")
int lookup(void *ctx)
{
    (void)ctx;
    unsigned long long namespace = 7;
    void *inner = bpf_map_lookup_elem(&outputs, &namespace);
    if (!inner)
        return 0;
    unsigned int cpu = 0;
    return bpf_map_lookup_elem(inner, &cpu) != 0;
}

char LICENSE[] SEC("license") = "GPL";
