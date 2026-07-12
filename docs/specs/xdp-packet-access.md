# XDP direct packet access

febpf models the XDP `data` / `data_end` contract without exposing host
addresses. Verification is enabled with `verifier::Config { xdp: true, .. }`;
execution uses `Vm::run_xdp(&mut packet)`. The ELF loader classifies the
executable section before choosing any source-level function symbol as the
program's display name. The CLI recognizes entries from sections named `xdp`
or `xdp/*` automatically; `--packet <file>` also selects
XDP semantics for assembler/raw programs and supplies raw packet bytes.
`--pcap <file>` runs every record in a classic libpcap capture through one VM
(maps persist between packets) and prints `ABORTED`/`DROP`/`PASS`/`TX`/
`REDIRECT` verdicts with packet indices and timestamps. Both byte orders and
microsecond/nanosecond pcap variants are accepted; pcapng is rejected clearly.
`record --pcap <file> --packet-index N -o packet.febpf` extracts a chosen
packet into the replay container, including its packet bytes and XDP mode, so
`replay packet.febpf` opens that invocation in the time-travel debugger.

## Verifier model

With XDP enabled, `r1` points to a read-only `struct xdp_md`. Exact 32-bit
loads have the following types:

| Offset | Field | Verifier result | Standalone value |
|---:|---|---|---:|
| 0 | `data` | `PtrKind::Packet` | VM packet start |
| 4 | `data_end` | `PtrKind::PacketEnd` | VM packet end |
| 12 | `ingress_ifindex` | scalar | 0 |
| 16 | `rx_queue_index` | scalar | 0 |
| 20 | `egress_ifindex` | scalar | 0 |

Offset 8 (`data_meta`) remains rejected: it is a packet-metadata pointer, not
a scalar, and febpf does not yet model an XDP metadata region. All other field,
width, partial, overlapping, and write accesses are rejected. The end pointer
cannot be dereferenced or adjusted.

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
constructs a zero-backed 24-byte `xdp_md` internally; the interpreter
synthesizes full febpf virtual addresses when the ABI's 32-bit `data` fields
are loaded. The three supported scalar metadata fields therefore read zero.
Packet writes are copied back to the caller on exit or runtime error. A typed
metadata input API is intentionally deferred until a workload needs nonzero
interface or queue identities.

## Byte-copy helpers

`xdp_load_bytes` (#189) and `xdp_store_bytes` (#190) require the original,
unmodified context pointer under the explicit XDP model, a scalar u32 packet
offset, a memory buffer, and a bounded u32 length. Load accepts writable,
previously uninitialized stack memory and marks the full destination range
initialized. Store requires every source byte to be initialized.

Both helpers operate on the same VM-owned packet region as direct packet
access. An offset or length above `0xffff` returns `-EFAULT`; an interval past
the packet end returns `-EINVAL`. Failures are atomic: load preserves the
destination and store preserves the packet. A successful store changes packet
contents but not its extent, so existing `data_end` range proofs remain valid.
Interpreter and hybrid JIT share this helper implementation, and packet writes
are copied back through the ordinary `run_xdp` contract.

This slice covers verifier semantics, deterministic interpreter execution,
automatic ELF program-type selection, raw packet-file CLI runs, a
pcap-in/verdict-out harness, selected-packet `.febpf` replay/debugging, and
kernel differential validation. `febpf conftest --packet frame.bin prog.bpf.o`
compares febpf and kernel verifier verdicts independently, then compares XDP
verdict and exact mutated output bytes through `BPF_PROG_TEST_RUN`. The kernel
is only an oracle: febpf verification, rejection explanations, and
`Vm::run_xdp` remain the userspace side of the comparison.

JIT execution uses the same checked runtime load path and has identical context
and packet behavior.
