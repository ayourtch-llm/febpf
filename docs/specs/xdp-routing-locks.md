# XDP routing, checksum, time, and map spin locks

STATUS: implemented (2026-07-13)

This batch was selected by expanding the pinned xdp-tools v1.6.3 corpus from
`xdp-bench` to its production `xdp-forward`, `xdp-monitor`, and
`xdp-trafficgen` sources. It implements four general kernel interfaces exposed
by those families.

## Helpers

- `bpf_fib_lookup` (#69) requires the original `xdp_md` context and an
  initialized, writable buffer sized by its constant length argument. The
  standalone VM has no host route/neighbour table, so execution validates the
  `MEM_RDWR` region and returns `BPF_FIB_LKUP_RET_NOT_FWDED` without mutating it
  or inventing network state.
- `bpf_ktime_get_coarse_ns` (#160) is a deterministic coarse monotonic clock.
  Each observation advances snapshotted logical time by one millisecond, so
  interpreter, JIT, replay, and reverse execution agree.
- `bpf_csum_diff` (#28) uses nullable zero-length input buffers, requires both
  sizes to be constant multiples of four, and implements Linux's
  `csum_partial`/`csum_sub` composition with an optional seed.
- `bpf_spin_lock`/`bpf_spin_unlock` (#93/#94) accept only the exact aligned,
  top-level `struct bpf_spin_lock` field recorded from a BTF array/hash map
  value. The verifier tracks the held `(map, offset)` in every abstract state,
  forbids nested locks, other helper/local calls and legacy packet loads while
  held, requires the matching unlock on every path, and rejects direct access
  overlapping the lock word. Standalone execution is single-invocation, so the
  runtime helpers validate the writable word and otherwise act as the ordering
  boundary proven by the verifier.

The map's `spin_lock_off` metadata is additive in replay v1 through the
optional `MAP_SPIN_LOCKS` section. It is absent for legacy/assembler maps and
for invalid BTF layouts (nested, unaligned, or multiple lock fields).
