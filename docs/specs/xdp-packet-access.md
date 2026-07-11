# XDP direct packet access

febpf models the XDP `data` / `data_end` contract without exposing host
addresses. Verification is enabled with `verifier::Config { xdp: true, .. }`;
execution uses `Vm::run_xdp(&mut packet)`. The CLI recognizes ELF entry
sections named `xdp` or `xdp/*` automatically; `--packet <file>` also selects
XDP semantics for assembler/raw programs and supplies raw packet bytes.

## Verifier model

With XDP enabled, `r1` points to a read-only `struct xdp_md`. A 32-bit load at
offset 0 yields `PtrKind::Packet`, and one at offset 4 yields
`PtrKind::PacketEnd`. Other context accesses are currently rejected. The end
pointer cannot be dereferenced or adjusted.

A packet pointer starts with an accessible range of zero. Unsigned relational
comparisons between a packet pointer and `data_end` refine the safe successor:

```text
r2 = *(u32 *)(r1 + 0)     # data
r3 = *(u32 *)(r1 + 4)     # data_end
r4 = r2
r4 += 14
if r4 > r3 goto short
r0 = *(u16 *)(r2 + 12)    # [0, 14) was proved accessible
```

The proven prefix is propagated to all aliases (register copies and stack
spills), mirroring the kernel verifier's packet-pointer range propagation.
Loads and stores must fit wholly within that prefix; merely having a runtime
packet long enough is not sufficient.

Both inclusive and strict forms, and both operand orders, are understood:
`data+n > end`, `data+n >= end`, `data+n < end`, `end >= data+n`, and their
complements refine the appropriate branch with the exact inclusive/exclusive
byte count.

## Runtime model

The packet is a dedicated bounds-checked virtual-address region. `run_xdp`
constructs the `xdp_md` internally; the interpreter synthesizes full febpf
virtual addresses when the ABI's 32-bit `data` fields are loaded. Packet
writes are copied back to the caller on exit or runtime error.

This slice covers verifier semantics, deterministic interpreter execution,
automatic ELF program-type selection, and raw packet-file CLI runs. JIT
execution, pcap/replay containers, and kernel `BPF_PROG_TEST_RUN` differential
validation are follow-up layers.
