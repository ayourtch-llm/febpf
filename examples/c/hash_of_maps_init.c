#define SEC(n) __attribute__((section(n), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_HASH_OF_MAPS 13

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, unsigned long long);
} inner SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 2);
    __type(key, unsigned int);
    __array(values, typeof(inner));
} outer SEC(".maps") = {
    .values = { [1] = &inner },
};

SEC("socket")
int lookup(void *ctx)
{
    (void)ctx;
    unsigned int key = 1;
    void *nested = bpf_map_lookup_elem(&outer, &key);
    if (!nested)
        return 0;
    key = 0;
    return bpf_map_lookup_elem(nested, &key) != 0;
}

char LICENSE[] SEC("license") = "GPL";
