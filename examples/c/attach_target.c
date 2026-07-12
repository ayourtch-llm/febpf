/* Self-contained application attach-target fixture. The ELF program uses a
 * deliberately absent dummy section target, while actual_target is retained
 * in the object's BTF as the real function selected by the loader tests. */
typedef unsigned long long u64;

struct payload {
    int value;
};

__attribute__((used, noinline))
int actual_target(struct payload *payload)
{
    return payload->value;
}

__attribute__((section("fentry/dummy_target"), used))
int probe(u64 *ctx)
{
    struct payload *payload = (struct payload *)ctx[0];
    return payload->value;
}

__attribute__((section("xdp"), used))
int ordinary(u64 *ctx)
{
    return (int)ctx[0];
}
