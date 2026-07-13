# Linux AF_XDP copy-mode adapter

STATUS: implemented, privileged live validation environment-gated (2026-07-13)

The Cargo feature `af-xdp` exposes `febpf::af_xdp` on Linux. It is an adapter
over the existing `XdpProvider` and `ExecutionEnvironment` boundaries, not a VM
mode. `Vm` contains no socket, UMEM, ring, interface, or queue state. The
default build remains dependency-free and does not compile this module.

The implementation uses the Linux UAPI directly without a libc or libbpf crate.
It creates a nonblocking `AF_XDP` socket, registers a private page-backed UMEM,
configures RX/TX/fill/completion rings, requests `XDP_COPY` plus
`XDP_USE_NEED_WAKEUP`, maps the offsets returned by `XDP_MMAP_OFFSETS`, and
binds one interface queue. Ring counters use acquire/release atomic ordering
and preserve the UAPI's single-producer/single-consumer ownership rules. These
steps and the copy-mode flag follow the
[Linux AF_XDP documentation](https://docs.kernel.org/networking/af_xdp.html).

## Provider boundary

RX descriptors are copied from UMEM into ordinary owned `XdpFrame` storage.
The frame preserves its real active offset and full chunk headroom/tailroom,
receives interface/queue metadata, and advertises both resize capabilities.
The opaque cookie is a provider-generated completion token, not a UMEM address.
Completion resolves it through an internal token-to-chunk table, so descriptor
addresses remain private and changed or double-completed tokens are rejected.

Completion copies a changed active window back only when it must transmit.
`XDP_DROP`, `XDP_ABORTED`, unknown returns, runtime errors, and the default PASS
policy recycle the UMEM frame to the fill ring. `XDP_TX` publishes it on the TX
ring. PASS cannot resume the original kernel receive path after AF_XDP has
diverted the packet, so `PassDisposition` makes the only honest choices
explicit: recycle it or re-inject it through TX.

Direct redirect can transmit only to the provider's own interface. XSKMAP
redirect can transmit only when the provider has explicitly registered the
exact `(loaded map index, u32 key)` with `bind_xskmap_slot`. Any other redirect
is recycled and returned as `UnboundRedirect`; the adapter never invents a
socket. The real socket FD is available through `AsRawFd` so an embedding host
can install it in the kernel XSKMAP that feeds AF_XDP reception. Kernel program
attachment and kernel-map updates remain host responsibilities.

## Deliberate limits

- One socket owns one private UMEM and one interface queue. Shared UMEM and
  cross-socket/cross-interface completion routing are not implemented.
- This is copy mode. Zero-copy, driver ownership, DPDK, TX metadata, and
  multi-buffer `XDP_USE_SG` are outside this batch.
- `receive` is nonblocking and bounded execution remains
  `Vm::run_xdp_provider(provider, budget)`; the adapter is not an event loop.
- The socket requires an externally attached kernel XDP redirect program and a
  real XSKMAP entry before it can receive traffic.

## Validation

Feature-enabled strict Clippy and deterministic tests cover UAPI structure
sizes, configuration validation, interface lookup, ring full/wrap behavior,
PASS policy, same-interface delivery, and sparse XSKMAP ownership. The ignored
live test accepts `FEBPF_AF_XDP_IFACE` and optional `FEBPF_AF_XDP_QUEUE`.

On the current host, `CONFIG_XDP_SOCKETS=y`, but unprivileged BPF is disabled
and no noninteractive privilege escalation is available. Running the ignored
test on `lo` reached the real `AF_XDP` setup and failed with `EPERM`; creating a
veth, attaching the feeder XDP program, installing its XSKMAP socket, and
driving packets was therefore **not reproduced** here. This is an environment
gap, not a passing live-integration claim.
