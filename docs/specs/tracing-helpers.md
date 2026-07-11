# Tracing helpers: the probe_read family + current_task_under_cgroup

Corpus-driven batch 3 (after `docs/specs/map-types.md` and `map-types-2.md`).
The post-map-types-2 corpus scan showed zero map-type blockers and named these
as the top verify blockers:

```
==== HISTOGRAM 2: unknown HELPERS (top verify blockers) ==============
     18 programs blocked by helper #113  probe_read_kernel
      4 programs blocked by helper #37   current_task_under_cgroup
      1 programs blocked by helper #114  probe_read_user_str
      1 programs blocked by helper #112  probe_read_user
```

(That histogram was initially mislabelled — `scan-corpus.sh`'s id→name table
had #113 as "ringbuf_output". The script now reads the authoritative
`___BPF_FUNC_MAPPER` list from `/usr/include/linux/bpf.h`; trust the names
only after that fix.)

## probe_read family (#4, #45, #112, #113, #114, #115)

All six share one signature: `(dst, size, unsafe_ptr)` with `dst` a writable
region (`MemWrite { size_arg: 1 }`), `size` a bounded scalar, and `unsafe_ptr`
`ArgKind::Any` — in the kernel the source is `ARG_ANYTHING` (any scalar can be
a kernel address). febpf has no kernel memory, so the model leans on the
virtual-address memory model (HANDOFF §1):

- **Fixed-size variants** (`probe_read` #4, `probe_read_kernel` #113,
  `probe_read_user` #112): try to resolve the source through
  `resolve_slice`. A valid febpf pointer (stack, ctx, map value, …) copies
  normally and returns 0. Anything unresolvable — a wild address, the opaque
  `get_current_task` token — **zero-fills dst and returns -EFAULT**, which is
  exactly the kernel's fault behaviour and fully deterministic.
- **String variants** (`probe_read_str` #45, `probe_read_kernel_str` #115,
  `probe_read_user_str` #114): copy byte-by-byte up to `size`, stopping at
  NUL. Returns the copied length **including** the NUL. An unterminated
  source is truncated with a forced NUL at `dst[size-1]` and returns `size`
  (kernel semantics). dst is zeroed first, so the tail beyond the string is
  deterministically zero (the kernel leaves it undefined — zero is the safe
  deterministic choice). A fault on any source byte zero-fills the whole dst
  and returns -EFAULT.

No user/kernel address-space distinction exists in febpf, so the `_user` and
`_kernel` variants are aliases of each other by design. The runtime, not the
verifier, is what keeps a wild `unsafe_ptr` safe — same story as `--no-verify`.

Note the interplay with the verifier's `MemWrite`: dst stack bytes are marked
initialized at verification time even on the -EFAULT path; the runtime
zero-fill is what makes that assumption true in every outcome.

## current_task_under_cgroup (#37)

`(map, index)` where `map` must be a `cgroup_array` (enforced by the verifier's
per-helper map-kind check, same mechanism as `perf_event_output` /
`get_stackid`). febpf's single synthetic task belongs to no cgroup, so the
answer is the fixed constant **0** ("not under"), per the determinism note in
`map-types-2.md`. An index `>= max_entries` returns -EINVAL like the kernel.

## STATUS

All implemented, tested (`tests/integration.rs` probe_read/cgroup sections),
both feature configs green.
