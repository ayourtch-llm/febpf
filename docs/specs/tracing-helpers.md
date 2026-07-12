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

## get_stack (#67)

`(ctx, buf, size, flags)` → number of bytes written on success, negative on
error. The buffer-writing sibling of `get_stackid` (#27,
`docs/specs/map-types-2.md`), and the last helper blocker for
`bcc__biostacks.o` (whose 5 programs all verify now).

Same deterministic stack model as get_stackid: febpf's stand-in for a kernel
stack is `Machine::backtrace_pcs()` — the call stack's instruction indices,
innermost first — written into `buf` as little-endian u64s. The buffer is
zeroed first so the result is deterministic in every outcome; only whole
8-byte frames are written (min(stack bytes, size), so the return value is
always a multiple of 8 — a size of 4 writes nothing and returns 0, matching
the kernel's whole-`u64`-slots behaviour). Verifier signature: `buf` is
`MemWrite { size_arg: 2 }`, `size` is `Size`; `ctx`/`flags` are accepted
loosely (`Any`/`Scalar`) like get_stackid's. No map is involved — there is no
map-kind check.

## Corpus load-failure batch (same session)

The 4 remaining `LOAD-FAIL` corpus objects were diagnosed and fixed:

- **`biosnoop`/`bitesize`/`capable` (LOAD-FAIL:relocation)** — relocations
  against the UNDefined `LINUX_KERNEL_VERSION` kconfig extern. Fixed by
  modelling libbpf's virtual `.kconfig` map; full write-up in
  `docs/specs/elf-loading.md` ("Kconfig externs").
- **`cpudist` (LOAD-FAIL:other)** — BTF map def omitting `max_entries`
  (libbpf lets the app fill it before load). Fixed by defaulting; see
  `docs/specs/elf-loading.md` ("Tolerated omissions").
- **`cpudist` (follow-on VERIFY-REJECT)** — its `lookup-or-init` static
  subprogram returns a map-value pointer, which febpf's verifier rejected
  ("subprogram may not return a pointer"). The kernel *allows* a static
  subprogram to return a pointer: `prepare_func_exit()` copies the callee's
  r0 to the caller verbatim; febpf now does too. The one exception — mirrored
  exactly — is `PTR_TO_STACK`: the kernel rejects returning ANY stack pointer,
  even a still-live caller-frame one ("technically it's ok to return caller's
  stack pointer [...] but let's be conservative" → "cannot return stack
  pointer to the caller"). An earlier febpf iteration allowed caller-frame
  stack returns; that was memory-safe here but LAXER than the kernel, so it
  was tightened back for vfuzz verdict parity. Tests in
  `tests/integration.rs` ("subprogram pointer returns").

After this batch: **loads 100%, verifies 78.6%** (44/56). The 12 remaining
rejects are all `VERIFY-REJECT:other` in the two known classes (rodata-driven
dead-code elimination; BTF-typed `tp_btf` ctx pointers) — see HANDOFF.

## get_socket_cookie (#46) and get_func_ip (#173)

Batch 5 (2026-07-11, `feat/map-types-2` follow-up). `bcc__tcppktlat.o`'s last
blocker was helper #46; #173 fell out of the ksnoop investigation below.

- **get_socket_cookie (#46)**: kernel signature is `(ctx) -> u64 cookie`,
  with `(sk)` flavors for other program types, so the argument is accepted
  loosely (`ArgKind::Any`, same as perf_event_output's ctx). febpf has no
  sockets: it returns the fixed, nonzero, deterministic token
  **`0x0000_0000_c00c_1e01`** — same style as get_current_task's
  `0xffff_0000_0000_0001`. Nonzero matters: real programs treat cookie 0 as
  "no socket" and bail.
- **get_func_ip (#173)**: `(ctx) -> u64` address of the traced function.
  febpf has no attach point, so it returns the opaque, nonzero,
  non-dereferenceable token **`0xffff_0000_0000_0002`** (deref of it faults
  cleanly through the virtual-address model, and probe_read of it
  zero-fills + returns -EFAULT like any wild pointer).

## trace_vprintk (#177)

`(fmt, fmt_size, data, data_len)` extends `trace_printk` with an array of up to
12 little-endian u64 arguments. The format and nonempty argument array must be
initialized readable memory; `data` may be NULL exactly when `data_len` is
zero. A data length not divisible by eight or above 96 returns `-EINVAL`
without appending output.

The deterministic runtime reuses the bounded `%d`/`%u`/`%x`/`%s`/`%p`/`%c`
formatter and appends the rendered line to `Vm::printk`, so snapshots,
equivalence observations, interpreter, and JIT retain the same behavior as
ordinary `trace_printk`. This closes both libbpf-bootstrap ksyscall entries,
whose four- and five-argument `bpf_printk` expansions select vprintk.

## ktime_get_boot_ns (#125)

The all-entry Inspektor Gadget scan made `bpf_ktime_get_boot_ns` the largest
combined-corpus blocker: 210 entries in 14 first-blocked object families. In
Linux it returns nanoseconds elapsed since boot using the boot-time clock,
which, unlike the monotonic clock used by `bpf_ktime_get_ns`, includes time
spent suspended. Its verifier signature is `() -> scalar`: no argument
register is read and r0 receives an ordinary u64.

febpf deliberately does not consult a host clock for this helper. A Machine's
deterministic boot-time stand-in is a logical nanosecond counter that advances
once per `ktime_get_boot_ns` observation; the first call in a run returns 1
and later calls never go backwards. Each Machine invocation begins at logical
boot time zero. This preserves the ordering property production programs need
from timestamps without making a replay depend on scheduler latency, host
suspend history, browser clock
availability, or the wall clock of a different machine.

This differs intentionally from the older `ktime_get_ns` model, which uses a
host `Instant` under native `std` and is consequently counted as
non-deterministic by the debugger. `ktime_get_boot_ns` does not increment
`nondet_calls`: snapshots and race-explorer instance state carry the logical
clock, so restore/replay produces the identical timestamp. JIT helper calls
use the ordinary deferred-helper path and therefore advance the same clock as
the interpreter. The model is pure integer arithmetic and is identical under
`std`, wasm, and true `no_std + alloc`; it adds no platform clock or
synchronization dependency.

## The ksnoop rejection is correct: the kernel rejects it too (verdict parity)

`bcc__ksnoop.o` (from the corpus pin, bcc v0.31.0) fails verification at its
`perf_event_output` call: "map value access out of bounds: max offset 65535 >
size 16296". Investigated 2026-07-11; **this is NOT a febpf gap** — do not
loosen anything to make it pass.

Root cause, from the source (`ksnoop.bpf.c` `output_trace()`): `__u16
trace_len = sizeof(*trace) + trace->buf_len - MAX_TRACE_BUF;` then `if
(trace_len <= sizeof(*trace)) bpf_perf_event_output(..., trace, trace_len)`.
Because `trace_len` is u16, clang masks a *copy* for the compare but masks r5
separately for the call:

```
584: w5 += 4008          ; r5 = buf_len+4008, u=[4009,69543]
585: w1 = w5             ; copy
586: w1 &= 65535         ; the u16 view of the copy
587: if w1 > 16296 goto skip
588: r5 &= 65535         ; the call arg — refined copy's bound never reaches r5
595: call perf_event_output(..., r4=trace(16296), r5=[0,65535])
```

The branch refines r1 only; recovering r5's bound needs the relational fact
"r5&0xffff == r1", which the kernel does not track either: its linked-scalar
machinery (`sync_linked_regs`, formerly `find_equal_scalars`) links r1/r5 at
the mov, but `w1 &= 65535` clears r1's id (verifier.c: "Make sure ID is
cleared otherwise dst_reg min/max could be incorrectly propagated"), and
`check_mem_size_reg` then checks `reg_umax(size_reg)` = 65535 against the
16296-byte region. **Proof the kernel agrees**: upstream bcc commit `0ae562c`
("libbpf-tools: ksnoop: Fix two invalid access to map value", 2025-07-13)
changes `trace_len` to `__u64` specifically because the kernel verifier
rejected this codegen with the identical error, `invalid access to map value,
value_size=16296 off=0 size=65535`. febpf's verdict matches the kernel's;
the object stays VERIFY-REJECT until the corpus pin moves past that commit.

Validation against the upstream-fixed source (0ae562c applied, compiled with
the corpus flags): febpf gets past `output_trace` and past the (now allowed)
subprogram pointer returns, and the remaining rejection is the `stack_depth`
push region — `r7 = r6` copies of the same loaded byte where the
`stack_depth >= FUNC_MAX_STACK_DEPTH - 1` refinement lands on one copy and
the store indexes with the other. THAT one the kernel does accept, via
linked scalar ids (kernel commit 75748837b7e5 "bpf: Propagate scalar ranges
through register assignments" + today's `sync_linked_regs`): a plain
register mov gives src/dst the same id, and a conditional-jump refinement is
propagated to every same-id register and spilled slot. febpf has no scalar
ids yet — that is the named follow-up feature if/when the corpus pin
advances. Note for the implementer: state-pruning subsumption must then also
compare id *links* (kernel `check_scalar_ids` with an idmap; two regs linked
in the visited state must be linked in the new state, or the visited state's
refinements don't cover the new one) — do not bolt on sync without it.

## STATUS

All implemented, tested (`tests/integration.rs` probe_read/cgroup/get_stack/
subprog-pointer/get_socket_cookie sections, `tests/elf.rs::kconfig_extern_object`),
both feature configs green. ksnoop documented as a correct (kernel-parity)
rejection, with linked scalar ids as the named follow-up.
