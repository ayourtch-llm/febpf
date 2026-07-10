/* Modern BTF-defined .maps. Compile:
 *   clang -O2 -g -target bpf -c btf_maps.c -o btf_maps.o            */
#define SEC(n) __attribute__((section(n), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define BPF_MAP_TYPE_ARRAY 2

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, unsigned int);
    __type(value, unsigned long long);
} scratch SEC(".maps");

SEC("xdp")
int accumulate(void *ctx)
{
    unsigned int k = 0;
    unsigned long long *v = bpf_map_lookup_elem(&scratch, &k);
    if (!v)
        return -1;
    *v += 5;
    return (int)*v;
}
