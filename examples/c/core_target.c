/* CO-RE target-BTF fixture: the same `struct point` as core_probe.c but with
 * a deliberately different layout (padding shifts every member). Compiling
 * this with -g produces a .BTF section that stands in for a "different
 * kernel": loading core_probe.o with this object's BTF as the CO-RE target
 * must retarget the field offsets to x=4, y=12, z=16 (locally 0, 4, 8).
 *
 * Compile: clang -O2 -g -target bpf -c core_target.c -o core_target.o
 */

struct point {
    int _pad0; /* pushes x to offset 4 */
    int x;
    int _pad1; /* pushes y to offset 12 */
    int y;
    long z;    /* offset 16 */
};

/* Referenced so clang emits the type into .BTF. */
struct point g;

long touch(void)
{
    return g.x + g.y + g.z;
}
