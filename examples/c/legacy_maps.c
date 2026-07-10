/* Legacy bpf_map_def maps section. Compile:
 *   clang -O2 -target bpf -c legacy_maps.c -o legacy_maps.o          */
struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};
#define SEC(n) __attribute__((section(n), used))

/* helper ids */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, unsigned long flags) = (void *)2;

struct bpf_map_def SEC("maps") counts = {
    .type = 1,          /* BPF_MAP_TYPE_HASH */
    .key_size = 4,
    .value_size = 8,
    .max_entries = 16,
};

SEC("socket")
int count_key7(void *ctx)
{
    unsigned int key = 7;
    unsigned long long *val = bpf_map_lookup_elem(&counts, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
        return (int)*val;
    }
    unsigned long long init = 100;
    bpf_map_update_elem(&counts, &key, &init, 0);
    return 100;
}
