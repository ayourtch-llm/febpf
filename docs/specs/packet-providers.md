# Packet-provider boundary

febpf separates packet transport from eBPF execution. The public boundary is
backend-neutral and allocator-only (`no_std` compatible); XDP is its first
program-family adapter. AF_XDP will be the first live backend, but no AF_XDP,
socket, ring, or host-pointer type appears in the VM API.

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

Only the active window is staged in febpf's existing virtual packet region.
The guest sees virtual `data`/`data_end` addresses, never the allocation's host
address. Provider `XdpMetadata` supplies `ingress_ifindex`, `rx_queue_index`,
and `egress_ifindex`; febpf writes those scalar values into the synthetic
`xdp_md`. `data_meta` remains unsupported and unexposed.

The legacy `run_xdp(&mut [u8])` and `run_xdp_jit(&mut [u8])` adapters now pass
through this frame path and preserve their return-value and write-back
contracts. `run_xdp_frame` returns both the raw `u64` value and an optional
recognized action (`ABORTED`, `DROP`, `PASS`, `TX`, or `REDIRECT`). Unknown raw
values remain visible and are not silently coerced.

## Capacity and redirect contract

Headroom and tailroom are descriptive in this first boundary version. The VM
does not yet have an active provider-capability callback, so
`xdp_adjust_head` and `xdp_adjust_tail` continue to return `-EOPNOTSUPP` and
leave the active window and spare capacity unchanged. The next resizing batch
must make capability opt-in explicit, update the virtual packet bounds
atomically, and preserve the existing standalone behavior when capability is
absent.

Likewise, `XDP_REDIRECT` is currently delivered as a verdict action, matching
the old standalone behavior; the selected interface or map entry is not yet a
completion payload. Before AF_XDP transport lands, the verdict will gain a
provider-neutral redirect destination. XSKMAP resolution will then consult
socket ownership supplied by that backend. febpf maps must never fabricate a
live socket or transmit a frame themselves.

## Replay

Provider execution stays on the same deterministic VM packet backing used by
`.febpf` replay and time travel. The first boundary does not automatically
record every live frame. A live backend may explicitly record a selected
frame using the existing replay format; adding metadata/cookie capture requires
a versioned replay extension rather than changing existing files silently.

## Validation invariant

For the same program, packet bytes, zero metadata, maps, PRNG seed, and
execution engine, the slice and frame adapters must produce identical raw
return values and mutated active bytes. Tests also require spare capacity,
metadata, cookies, ordering, batch limits, and runtime-error completion to
survive the boundary.
