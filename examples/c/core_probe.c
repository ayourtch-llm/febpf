/* CO-RE fixture: field accesses recorded as relocations, not fixed offsets.
 *
 * __attribute__((preserve_access_index)) makes clang emit a bpf_core_relo
 * (FIELD_BYTE_OFFSET) for every member access instead of baking the local
 * struct layout into the load offsets. At load time febpf re-resolves each
 * access against the target BTF and patches the instruction offsets, so this
 * object runs correctly even when the target's `struct point` layout differs.
 *
 * Compile: clang -O2 -g -target bpf -c core_probe.c -o core_probe.o
 */

struct point {
    int x;     /* local offset 0 */
    int y;     /* local offset 4 */
    long z;    /* local offset 8 */
} __attribute__((preserve_access_index));

int probe(void *ctx)
{
    struct point *p = ctx;
    return p->x + p->y + (int)p->z;
}
