# Packet-provider boundary

febpf separates packet transport from eBPF execution. The public boundary is
backend-neutral and allocator-only (`no_std` compatible); XDP is its first
program-family adapter. The opt-in Linux AF_XDP copy-mode module is the first
live backend, but no AF_XDP socket, ring, or host-pointer type appears in the
VM API.

## Ownership and batching

An `XdpProvider` transfers an owned `XdpFrame` from `receive` and reclaims the
same frame through `complete`. `Vm::run_xdp_provider(provider, budget)` receives
and completes at most `budget` frames, stops early on `None`, and preserves
provider order. The JIT has the identical
`Vm::run_xdp_provider_jit` boundary.

A VM runtime failure is a completed frame whose `result` is `Err(EbpfError)`;
it is not a transport error and never strands the allocation inside the VM.
Errors returned by `receive` and `complete` are distinguished by
`XdpProviderError`. If `complete` itself fails, ownership has already moved
back into that provider call and recovery is backend-specific.

This pull/complete interface deliberately processes one ownership transfer at
a time while the VM method supplies the bounded batch. An AF_XDP backend can
drain and replenish its rings internally without making ring lifetimes part of
febpf's public contract.

## Frame storage and context

`XdpFrame` owns one allocation and identifies an active half-open data window.
The bytes before and after it are explicit `headroom()` and `tailroom()`.
Providers can adopt an existing `Vec` without another copy through
`from_storage`, and recover the allocation and window through `into_storage`.
An opaque `u64` cookie survives execution unchanged for descriptor or queue
bookkeeping.

An invocation environment borrows the frame storage and its active bounds
directly; `Vm` does not stage or own them. The guest still sees virtual
`data`/`data_end` addresses, never the allocation's host address. Provider
`XdpMetadata` supplies `ingress_ifindex`, `rx_queue_index`,
and `egress_ifindex`; febpf writes those scalar values into the synthetic
`xdp_md`. `data_meta` remains unsupported and unexposed.

The legacy `run_xdp(&mut [u8])` and `run_xdp_jit(&mut [u8])` adapters construct
the same environment directly over the slice and preserve their return-value
and mutation contracts. `run_xdp_frame` returns both the raw `u64` value and an optional
recognized action (`ABORTED`, `DROP`, `PASS`, `TX`, or `REDIRECT`). Unknown raw
values remain visible and are not silently coerced.

A successful `redirect` helper records an interface index and raw flags. A
successful `redirect_map` records the stable loaded-map index, map kind, u32
key, and raw flags. This provider-neutral `XdpRedirect` is included in the
verdict only when the final action is `XDP_REDIRECT`; a helper result ignored
by a program cannot accidentally transmit a frame. A later failed redirect
helper clears an earlier selection. The selection is invocation state and is
included in debugger snapshots, so reverse execution reproduces it exactly.
The legacy integer-only adapter intentionally discards this richer completion
payload.

## Capacity contract

Headroom and tailroom become mutable only when an `XdpFrame` advertises the
corresponding `XdpCapabilities` bit. `xdp_adjust_head` moves the active start;
positive deltas consume packet bytes and negative deltas expose provider
headroom. `xdp_adjust_tail` moves the active end; positive deltas consume
tailroom and zero every newly exposed byte, while negative deltas shrink the
packet. Deltas use the helper's signed-32-bit interpretation.

An unsupported capability returns `-EOPNOTSUPP`. A move beyond the active
packet or available capacity returns `-EINVAL`. Every failure is atomic. The
slice adapter advertises no resize capability, preserving its standalone
behavior. The verifier invalidates all packet/data-end aliases across either
helper regardless of the runtime result; programs must reload them from
`xdp_md` and prove fresh bounds.

Redirect delivery in the core records intent only; it never transmits a frame.
The opt-in Linux AF_XDP provider decides whether a recorded destination is
owned and delivers or rejects it during completion. In particular, XSKMAP
resolution consults sparse socket ownership supplied by that backend. febpf
maps never fabricate a live socket or transmit a frame themselves. See
[`af-xdp-copy.md`](af-xdp-copy.md) for the live adapter's deliberately narrower
delivery rules.

## Replay

Provider execution, `.febpf` replay, and time travel use the same logical
environment snapshot; snapshots contain bytes and bounds, never host
addresses. The first boundary does not automatically
record every live frame. A live backend may explicitly record a selected
frame using the existing replay format; adding metadata/cookie capture requires
a versioned replay extension rather than changing existing files silently.

## Validation invariant

For the same program, packet bytes, zero metadata, maps, PRNG seed, and
execution engine, the slice and frame adapters must produce identical raw
return values and mutated active bytes. Tests also require spare capacity,
metadata, cookies, ordering, batch limits, runtime-error completion, redirect
destinations, and redirect snapshot replay to survive the boundary.
