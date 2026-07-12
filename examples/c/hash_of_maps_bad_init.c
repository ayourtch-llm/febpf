#define SEC(n) __attribute__((section(n), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_HASH_OF_MAPS 13

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, unsigned long long);
} inner SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 2);
    __type(key, unsigned long long);
    __array(values, typeof(inner));
} outer SEC(".maps") = {
    .values = { [1] = &inner },
};

SEC("socket")
int entry(void *ctx)
{
    (void)ctx;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
