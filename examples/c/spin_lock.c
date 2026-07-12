/* Self-contained BTF map-value spin-lock metadata fixture. */
typedef unsigned int u32;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name

struct bpf_spin_lock {
    u32 val;
};

struct locked_value {
    u32 prefix;
    struct bpf_spin_lock lock;
};

struct {
    __uint(type, 2); /* BPF_MAP_TYPE_ARRAY */
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct locked_value);
} locks SEC(".maps");

SEC("xdp")
int entry(void *ctx)
{
    return ctx != 0;
}
