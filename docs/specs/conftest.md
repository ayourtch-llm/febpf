# febpf kernel conformance mode & differential fuzzer specification

This document specifies `febpf conftest` and `febpf fuzz`: two tools that
validate febpf's interpreter and JIT against each other and, when privileges
allow, against the **real Linux kernel** via the `bpf(2)` syscall.

> Status: see the STATUS section at the bottom of this file.

The design constraint is the project's: **zero dependencies**. All kernel
interaction is done through raw `syscall(2)` via inline `asm!` (syscall number
`321` = `SYS_bpf` on x86-64), exactly like the JIT's `sys` module allocates
executable memory. No libc, no `libbpf`.

---

## 1. The `bpf(2)` ABI, byte-exact

```
long syscall(321 /*SYS_bpf*/, int cmd, union bpf_attr *attr, unsigned int size);
```

Return value: a non-negative fd (or 0 for verb-style commands), or `-errno`
(the raw kernel convention; the wrapper maps the `-4095..0` band to `Err`).

`union bpf_attr` is a union of per-command anonymous structs. We never model
the whole union. Instead we use a **zeroed fixed-size byte buffer** (128 bytes
— larger than the highest field offset any command below touches, and smaller
than the kernel's `sizeof(union bpf_attr)`), write the fields we need at their
exact C offsets, and pass `size = 128`. The kernel copies our 128 bytes,
zero-fills the remainder of its own `attr`, and `CHECK_ATTR` validates that the
tail is zero (it is — we zeroed it). This idiom is version-robust: new trailing
fields in the union do not affect us.

Commands used (`enum bpf_cmd` ordinals, stable UAPI):

| cmd | value | purpose |
|-----|-------|---------|
| `BPF_MAP_CREATE`    | 0  | create a kernel map matching a `MapDef` |
| `BPF_MAP_UPDATE_ELEM` | 2 | seed initial map contents (`.data`/`.rodata`) |
| `BPF_PROG_LOAD`     | 5  | load + verify a program |
| `BPF_PROG_TEST_RUN` | 10 | run the loaded program on supplied input |

Program type used: `BPF_PROG_TYPE_SOCKET_FILTER` (value `1`) — loadable and
`TEST_RUN`-able without attaching to anything, and its `TEST_RUN` returns the
program's `r0` (truncated to `u32`) which is exactly what we diff against.

### 1.1 `BPF_PROG_LOAD` field offsets (bytes, from start of the union)

```
 0  __u32 prog_type
 4  __u32 insn_cnt
 8  __u64 insns          (pointer to Vec<[u8;8]> encoded program)
16  __u64 license        (pointer to "GPL\0")
24  __u32 log_level      (0 = no verifier log; 1+ = capture)
28  __u32 log_size
32  __u64 log_buf        (pointer to a user buffer for the verifier log)
40  __u32 kern_version   (unused for SOCKET_FILTER; 0)
44  __u32 prog_flags
48  char  prog_name[16]
64  __u32 prog_ifindex
...
```

We set: prog_type, insn_cnt, insns, license, and (optionally) log_level/
log_size/log_buf to capture the kernel verifier's rejection reason.

### 1.2 `BPF_MAP_CREATE` field offsets

```
 0  __u32 map_type       (BPF_MAP_TYPE_ARRAY=2, BPF_MAP_TYPE_HASH=1)
 4  __u32 key_size
 8  __u32 value_size
12  __u32 max_entries
16  __u32 map_flags
...
28  char  map_name[16]
```

### 1.3 `BPF_MAP_UPDATE_ELEM` field offsets

```
 0  __u32 map_fd
 (pad to 8)
 8  __u64 key            (pointer to key bytes)
16  __u64 value          (pointer to value bytes)
24  __u64 flags          (BPF_ANY=0)
```

### 1.4 `BPF_PROG_TEST_RUN` field offsets (the `test` sub-struct)

```
 0  __u32 prog_fd
 4  __u32 retval         (OUTPUT: the program's r0 as u32)
 8  __u32 data_size_in
12  __u32 data_size_out
16  __u64 data_in        (pointer to input packet bytes)
24  __u64 data_out       (pointer to output buffer, or NULL)
32  __u32 repeat
36  __u32 duration       (OUTPUT)
40  __u32 ctx_size_in
44  __u32 ctx_size_out
48  __u64 ctx_in
56  __u64 ctx_out
64  __u32 flags
68  __u32 cpu
72  __u32 batch_size
```

For `SOCKET_FILTER`, `TEST_RUN` builds an `skb` from `data_in`; the kernel
requires `data_size_in >= ETH_HLEN` (14). We always pass at least 16 bytes of
input (zero-padded when the caller gives less).

---

## 2. Map handling (kernel side of `Vm::new`)

The interpreter's `Vm::new` patches map-reference `lddw` instructions from the
`(src=BPF_PSEUDO_MAP_{FD,VALUE}, imm=map_index)` pseudo-form into concrete
region addresses. The kernel does the analogous thing but expects **real map
file descriptors** in the `lddw` imm with `src_reg = BPF_PSEUDO_MAP_FD (1)`.

So the kernel path:

1. For each `MapDef`, `BPF_MAP_CREATE` a matching kernel map (array→type 2,
   hash→type 1; key/value/max_entries copied across). Seed `.data`/`.rodata`
   contents with `BPF_MAP_UPDATE_ELEM`. (`.rodata` freeze via `BPF_MAP_FREEZE`
   is intentionally skipped — freezing forbids the map-value writes our test
   programs never do, and unfrozen is strictly more permissive for load.)
2. Encode the program, then rewrite every map-reference `lddw`: set
   `src_reg = 1` (BPF_PSEUDO_MAP_FD) and `imm = kernel_fd`.
   `BPF_PSEUDO_MAP_VALUE` (direct global-data value pointer, a two-slot form
   carrying an offset in the second slot's imm) is rewritten the same way, with
   `src_reg = 3` and the offset in the second slot preserved.
3. `BPF_PROG_LOAD`; on success `BPF_PROG_TEST_RUN`.

The fuzzer generates **map-free** programs, so this path is exercised by
`conftest` on real objects, not by `fuzz`.

---

## 3. Capability probe & graceful degradation

`BPF_PROG_LOAD` requires root or `CAP_BPF` (and, when
`kernel.unprivileged_bpf_disabled` is `1`/`2`, root/`CAP_BPF` unconditionally).
Rather than parse capabilities, we **probe**: attempt to load a trivial 2-insn
program (`mov r0,0; exit`). If it succeeds we have privilege (the fd is closed
immediately); if it fails with `EPERM`/`EACCES` we don't.

- `conftest`: if the probe fails, print
  `kernel side unavailable (permission denied); run as root` and exit with a
  **distinct** code (2, vs 1 for an actual interp/JIT/kernel mismatch), after
  still running and reporting the interp-vs-JIT comparison.
- `fuzz`: kernel mode is opt-in via `--kernel`. Without it, fuzzing is
  interp-vs-JIT only and needs no privilege. With `--kernel` but no privilege,
  it prints the skip line and continues interp-vs-JIT.
- Tests: kernel-dependent behavior is never asserted; tests probe and print
  `skipped: no bpf privilege` instead of failing, so CI stays green
  unprivileged.

---

## 4. Differential fuzzer: program generation

Goal: generate random programs that **both** verifiers (febpf's and the
kernel's) accept, so any `r0` disagreement is a real engine bug. Strategy is
deliberately conservative:

- **Seeded PRNG** (SplitMix64). The seed is printed on every failure and
  accepted via `--seed` to reproduce bit-for-bit. Determinism is a hard
  requirement (matches the project's fixed-seed prandom philosophy).
- **Init every register** `r0..=r9` first with a `mov64 imm` of a random
  constant. The kernel verifier rejects reads of uninitialized registers; this
  sidesteps that entirely. `r1` (ctx) and `r10` (fp) are left untouched — no
  pointer arithmetic, no memory access, so the virtual-address safety model and
  the kernel's pointer tracking are both trivially satisfied.
- **Body**: a random sequence of ALU (reg/imm, 32/64-bit) and conditional
  branches. Ops: add sub mul or and xor mov neg, plus lsh/rsh/arsh with
  **imm** shift amounts in range. Branches are `if rX cc rY goto +N` /
  `if rX cc imm goto +N`, **forward-only** and bounded so the CFG is a DAG —
  no loops, guaranteed termination, and the kernel verifier's path budget is
  never a concern.
- **End**: `exit` (returns `r0`).

### 4.1 Divergence traps deliberately avoided or normalized

- **div / mod**: excluded from the generator. eBPF `÷0 ⇒ 0` and `%0 ⇒
  unchanged` are implemented by febpf, but guarding every generated divisor to
  match the kernel exactly (and the signed-overflow `INT_MIN / -1` corner) adds
  noise without adding coverage. Left as documented future work; if added, the
  generator must guard divisors `!= 0` with a branch, or the harness must
  special-case.
- **shifts**: shift amounts are masked identically by all three engines —
  Rust's `wrapping_shl/shr` masks by the type width (63/31), x86 `shl/shr` mask
  in hardware (63/31), and the kernel does `& 63`/`& 31`. So shifts agree; the
  generator still restricts imm shift counts to `0..width` for clarity.
- **byte swap (`END`) / movsx / variable-count shift**: allowed (JIT defers
  them to the interpreter, so interp-vs-JIT is trivially consistent) but kept
  out of the initial generator to minimize kernel-verifier surprises.
- **32-bit sub-register semantics**: a 32-bit ALU op zero-extends into the full
  64-bit register on all three engines; the generator freely mixes widths.

### 4.2 Result normalization

`TEST_RUN` returns `retval` as `u32`. febpf's `r0` is `u64`. The comparison is
on the **low 32 bits** for the kernel diff (the kernel truncates), and on the
full `u64` for interp-vs-JIT (both are exact). A mismatch dumps the failing
program via `disasm::disasm_program` so it is immediately replayable with
`febpf run`/`febpf conftest`.

---

## 5. Module layout

- `src/kbpf.rs` — raw `bpf(2)` wrapper (`sys_bpf`), the `attr` byte-buffer
  builder, capability probe, `map_create`/`map_update`/`prog_load`/`test_run`,
  and a `run_program` convenience that loads a `Program` (creating maps,
  rewriting lddw) and test-runs it. Guarded to x86-64 Linux; a stub elsewhere.
- `src/fuzz.rs` — SplitMix64 PRNG and the conservative program generator, plus
  the fuzz driver (`interp` vs `jit` vs optional `kernel`).
- `main.rs` — `conftest` and `fuzz` subcommands + CLI flags.

---

## 6. Staged plan

- (a) raw `bpf(2)` wrapper + capability probe
- (b) `conftest` single-program path (interp/jit/kernel diff, maps)
- (c) fuzzer interp-vs-JIT
- (d) fuzzer `--kernel` + CLI polish

---

## STATUS

**Done.** All four stages (a–d) are implemented, tested and green.

- `src/kbpf.rs` — raw `bpf(2)` wrapper, capability probe, `map_create` /
  `map_update` / `prog_load` / `test_run`, and `run_program`. The byte offsets
  encoded here were **verified field-by-field against the running kernel's
  `<linux/bpf.h>` via `offsetof`** (PROG_LOAD, MAP_CREATE, MAP_UPDATE_ELEM,
  TEST_RUN all match; `sizeof(union bpf_attr) = 168`, so the 128-byte buffer is
  safely smaller).
- `src/fuzz.rs` — SplitMix64 PRNG + conservative generator + `interp_vs_jit`.
- `src/conftest.rs` (bin) — `conftest`/`fuzz` commands with the exit-code
  contract above.
- `tests/conftest.rs` — probe/skip kernel tests + always-on interp-vs-JIT
  differential.

**Validated:** interp-vs-JIT agree over tens of thousands of generated
programs (fuzzer + unit test + integration test). The fuzzer already caught one
real bug — a generator off-by-one that emitted an out-of-bounds forward branch.

**Kernel side NOT run at runtime on this host:** it is unprivileged
(`kernel.unprivileged_bpf_disabled = 2`, no passwordless sudo), so
`BPF_PROG_LOAD` returns `EPERM`. The probe correctly reports "no privilege" and
both commands degrade as specified. The kernel path is structurally validated
(offset check above; the syscall reaches the kernel's permission check with a
valid attr, returning `EPERM` rather than `EINVAL`/`EFAULT`). The
privilege-gated tests (`kernel_roundtrip_if_privileged`,
`fuzz_kernel_differential_if_privileged`) will exercise the real round-trip and
differential automatically when run as root / with `CAP_BPF`.

**Remaining / next steps** (none blocking):

1. Run the suite once as root to exercise the kernel differential for real
   (`sudo cargo test --test conftest`); expected to pass given the offset
   validation.
2. Extend the generator with **guarded div/mod** (branch divisor `!= 0` before
   dividing) to cover the div-by-zero / `INT_MIN / -1` divergence surface.
3. Add memory ops (stack loads/stores) to the generator, and map-using
   programs to the kernel differential (the `conftest` map path already exists;
   the generator just doesn't emit maps yet).
</content>
