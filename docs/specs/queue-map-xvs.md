# Queue maps and the xvs production lane

The pinned `davidcoles/xvs` v0.2.10 XDP virtual-server dataplane adds one
dense production family to the corpus. Its release build uses two
`BPF_MAP_TYPE_QUEUE` maps and `bpf_map_push_elem` to transfer flow and ICMP
records to userspace. The corpus script compiles the unchanged pinned source
with the capacity defaults from its Makefile. Because the source includes
glibc networking headers, the BPF compile explicitly selects the installed
x86-64 stubs instead of requiring the optional 32-bit libc development
package.

febpf models a queue as an ordered, bounded collection of fixed-size values.
It has no keys or byte initializer. `bpf_map_push_elem` appends a copied value;
a full queue returns `-E2BIG`, except `BPF_EXIST` discards the oldest value and
appends the new one. Queue identity is additive replay-v1 map-kind tag 16 and
kernel differential translation uses map type 22.

The same production object requires `bpf_xdp_adjust_head` and
`bpf_xdp_adjust_tail`. Verification uses their exact XDP context signatures
and invalidates every prior packet/data-end alias after either call, regardless
of the runtime result. The slice adapter returns `-EOPNOTSUPP` and never
invents capacity. A provider-owned `XdpFrame` can explicitly authorize head
and/or tail adjustment; the shared invocation packet window then updates
bounds atomically without changing the helper contracts.

Clang also emits both 64-bit and MOV32-mediated `data_end - data` forms in this
dataplane. febpf retains packet provenance through a MOV32 only to recognize
that exact subtraction and produces an unknown zero-extended u32 for the
ALU32 form. Other truncated pointer arithmetic remains rejected.

After these features all six xvs entries load and reach ordinary verification.
Four verify strictly. The two large dataplane entries currently exhaust the
one-million processed-instruction verifier budget, exposing state pruning as
the next family-level blocker rather than an unsupported map or helper.
