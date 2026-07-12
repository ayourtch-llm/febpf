# febpf verifier differential fuzzing specification

This document specifies `febpf vfuzz`: a differential fuzzer that compares
**verifier verdicts** — does febpf's verifier accept/reject the same programs
the Linux kernel verifier does? — rather than execution results.

It is the sibling of `febpf fuzz` (see `docs/specs/conftest.md`), which diffs
*execution results* (interp vs JIT vs kernel) over programs both verifiers are
known to accept. `vfuzz` deliberately steers toward the **verification
frontier**: programs near the edge of legality, chosen to provoke *verdict*
disagreements.

> Status: see the STATUS section at the bottom of this file.

The project constraint is unchanged: **zero dependencies**. The kernel is
reached through the existing raw `bpf(2)` layer in `src/kbpf.rs`
(`prog_load(insns, Option<&mut String>)` returns the kernel verdict and, on
rejection, captures the kernel verifier log). febpf's own verdict comes from
`Vm::verify` (`src/interp.rs` → `src/verifier.rs`).

---

## 1. Classification taxonomy

Each generated program yields a febpf verdict (accept/reject) and, with
`--kernel` and privilege, a kernel verdict (accept/reject). The pair classifies
into one of four cells:

| febpf \ kernel | kernel ACCEPT | kernel REJECT |
|----------------|---------------|---------------|
| febpf ACCEPT   | **BOTH-accept** (agree) | **FEBPF-LAX** — febpf too permissive |
| febpf REJECT   | **FEBPF-STRICT** — febpf too strict | **BOTH-reject** (agree) |

- **BOTH-accept / BOTH-reject** — agreement. No action.
- **FEBPF-LAX** (`FEBPF-accepts / KERNEL-rejects`) — **the high-value signal.**
  febpf's verifier is *unsound relative to the kernel*: it admitted a program
  the kernel considers unsafe. This is a potential soundness gap in febpf and
  is what the whole tool exists to surface. Reported first, loudest, with full
  disasm + both verdicts + the kernel verifier log so it is immediately
  triageable, and reproducible via the printed `--seed`.
- **FEBPF-STRICT** (`KERNEL-accepts / FEBPF-rejects`) — a completeness gap:
  febpf rejects something the kernel accepts. Useful, but **expected in bulk**
  (see the asymmetry section) and reported separately/summarised so it does not
  drown the soundness signal.

### 1.1 febpf self-consistency (kernel-free, always on)

Independent of the kernel, `vfuzz` enforces a local soundness invariant that
needs no privilege and runs in every mode:

> If febpf's verifier **accepts** a program, executing it under the interpreter
> must not raise a **verifier-caught safety error** (out-of-bounds memory
> access, unaligned access, invalid-register/jump/pc structural fault, or a
> bad map-pointer dereference).

If an accepted program hits such a runtime fault, febpf's verifier is unsound
*against its own runtime* — a soundness bug fully reproducible unprivileged.
Legitimate runtime outcomes (a defined div-by-zero, a normal `exit`, an
instruction-limit trip) are **not** safety errors and do not count.

The classifier in `fuzz.rs` (`is_safety_error`) matches the runtime error
message against the memory/structural fault set above; everything else is
treated as a benign runtime result.

---

## 2. Generator: steering to the verification frontier

`fuzz::gen_program` (the conservative, map/memory/pointer-free generator used by
`fuzz`) is kept intact. `vfuzz` adds `fuzz::gen_frontier_program`, which biases
toward constructs *both* verifiers reason about, so disagreements cluster on
genuine semantic questions rather than obvious garbage:

- **ctx pointer arithmetic** — `r1` (the context pointer) is kept live and
  offset/masked, then dereferenced, exercising pointer-range tracking.
- **bounded vs unbounded memory access** — loads/stores through the stack
  (`r10`) and through ctx at various offsets, some provably in bounds, some
  deliberately off the end or with an unbounded index.
- **uninitialized-register reads** — occasionally skip a register's
  initializer, then read it (the kernel rejects; febpf should too).
- **stack access at various offsets** — `*(u64 *)(r10 - k)` for k in and out of
  `[8, 512]`, aligned and misaligned.
- **backward branches (loops)** — emit a backward `goto`, sometimes with a
  bounded counter (kernel may accept small bounded loops on modern kernels;
  febpf proves termination within its budget) and sometimes unbounded.
- **helper calls with varied argument setups** — `call` to a small allow-list
  of SOCKET_FILTER-legal helpers (e.g. `get_prandom_u32`, `ktime_get_ns`,
  `map_lookup_elem`) with arguments set up correctly, partially, or not at all.

The generator remains **fully seeded/deterministic** (SplitMix64, same `Prng`),
and the per-iteration seed is printed on any disagreement so every finding
replays bit-for-bit with `--seed`. A `--frontier`/default toggle selects which
generator drives a run; frontier is the `vfuzz` default.

### 2.1 Program type note

Both `fuzz` and `vfuzz` load as `BPF_PROG_TYPE_SOCKET_FILTER` (unprivileged
TEST_RUN-able). The helper allow-list is restricted to helpers that program
type may call; helpers outside it are a legitimate source of kernel rejection
and are only emitted deliberately as frontier probes.

---

## 3. The soundness-vs-completeness asymmetry (read this)

The kernel verifier is vastly more exhaustive than febpf's: it tracks more
state, enforces many program-type/context rules febpf does not model, has
alignment and bounds rules tuned over a decade, and rejects a large class of
programs for reasons febpf simply does not check. **Therefore expect
FEBPF-STRICT to be common and FEBPF-LAX to be rare.** That asymmetry is by
design and is *not* a bug in either verifier:

- **FEBPF-STRICT is expected and mostly uninteresting.** febpf rejecting what
  the kernel accepts (or the kernel rejecting for a rule febpf never claimed to
  model) is a completeness gap, not a safety problem. These are summarised as a
  count and a handful of samples, never allowed to bury the signal.
- **FEBPF-LAX is the rare, valuable case.** Every FEBPF-LAX result is a place
  febpf's verifier is more permissive than the kernel — i.e. it may be admitting
  something unsafe. These are dumped in full and counted separately.

To keep the signal legible the generator is *conservative enough* that
FEBPF-STRICT does not explode: it biases toward constructs both verifiers model
(bounds, null-checks, alignment) rather than toward exotic program-type rules
febpf never claims to implement. Even so, the report **classifies and counts the
two directions separately** so the soundness direction always stands out
regardless of how many completeness gaps show up.

---

## 4. `vfuzz` command

```
febpf vfuzz [--iters N] [--seed S] [--kernel] [--frontier|--conservative]
```

- `--iters N` — number of programs (default 1000).
- `--seed S` — base PRNG seed (random if omitted; the per-program seed is
  printed on any disagreement).
- `--kernel` — also obtain the kernel verdict via `BPF_PROG_LOAD`. Requires
  root/`CAP_BPF`; probed first and skipped gracefully with a clear message when
  unprivileged (interp-only self-consistency still runs).
- `--frontier` (default) / `--conservative` — pick the generator.

### 4.1 Output

1. A running tally of the four cells (+ self-consistency failures).
2. Every **FEBPF-LAX** and every **self-consistency failure**, immediately, in
   full: seed, disasm, febpf verdict + reason, kernel verdict + verifier log.
3. A summary: the four counts, the self-consistency count, and a short sample of
   FEBPF-STRICT cases (bounded, so the soundness signal is never buried).

Exit codes (scriptable, consistent with `conftest.rs`):
`0` no soundness problem (agreement or only expected FEBPF-STRICT);
`1` a soundness problem found (FEBPF-LAX or a self-consistency failure);
`2` `--kernel` requested but no privilege (self-consistency still ran).

---

## 5. Module layout

- `src/fuzz.rs` — adds `gen_frontier_program`, `is_safety_error`, the febpf
  verdict helper (`febpf_verdict`), and a self-consistency checker.
- `src/kbpf.rs` — reused as-is: `prog_load(insns, Option<&mut String>)` already
  returns the kernel verdict and captures the verifier log. (`&mut` provenance
  to the syscall is preserved; any new command must keep it.)
- `src/conftest.rs` — adds `vfuzz(&Opts)`, the classification loop and report.
- `src/main.rs` — `vfuzz` subcommand + `--frontier`/`--conservative` flags.

---

## 6. Staged plan

- (a) verdict-classification harness over the **existing** generator: febpf
  verifier-only self-consistency (verify-accepted ⇒ runs without a
  verifier-caught safety error), over many seeds.
- (b) frontier generator (`gen_frontier_program`): ctx pointer arithmetic,
  bounded/unbounded memory, uninitialized reads, stack offsets, backward
  branches, helper calls.
- (c) `--kernel` verdict differential + four-cell classification + reporting
  (FEBPF-LAX loud and first; FEBPF-STRICT summarised).
- (d) CLI wiring + tests (unprivileged: generator produces both accepted and
  rejected programs; classification stable per seed; verify+run
  self-consistency over many seeds. Privileged: probe/skip).

---

## STATUS

**Done (harness).** All four stages (a–d) are implemented, tested and green in
**both** the default and std interpreter-only configurations, with
`cargo clippy --all-targets` at zero warnings in each.

- `src/fuzz.rs` — `febpf_verdict`, `is_safety_error`, `SelfConsistency` +
  `check_self_consistency` (ctx sized to the verifier's assumed `ctx_size` so
  in-bounds ctx accesses don't read as spurious faults), and
  `gen_frontier_program` (flavors: ctx pointer arithmetic + load, stack access
  at various offsets, uninitialized reads, bounded/unbounded loops, helper
  calls, mixed body).
- `src/kbpf.rs` — `verdict(insns, Option<&mut String>)` returns the kernel
  verifier's accept/reject and captures the log on rejection; it reuses
  `prog_load`, so the `bpf(2)` attr keeps **mutable provenance to the syscall**
  (no new command, no new miscompile surface).
- `src/conftest.rs` — `vfuzz()`: four-cell classification, always-on kernel-free
  self-consistency, FEBPF-LAX + self-consistency failures dumped in full,
  FEBPF-STRICT summarised. Exit 1 (soundness problem) / 2 (kernel requested but
  unprivileged) / 0 (clean).
- `src/main.rs` — `vfuzz` subcommand, `--frontier` (default) / `--conservative`.
- `tests/conftest.rs` — unprivileged: frontier generator exercises both
  verdicts; febpf verify+run self-consistency over 2000 seeds × both
  generators; classification stable per seed. Privileged: kernel verdict
  differential asserts zero FEBPF-LAX (probe/skip unprivileged).

**Validated unprivileged:** self-consistency holds over thousands of seeds
(no febpf soundness bug against its own runtime); the frontier generator splits
roughly half accept / half reject; `vfuzz --kernel` unprivileged degrades
gracefully (probe + skip, exit 2).

**Kernel side — the user's to run (needs root/`CAP_BPF`).** This environment
could not `sudo` non-interactively, so the real kernel differential was not
executed here. Run it on the privileged reference host with:

```
cargo build --release
sudo ./target/release/febpf vfuzz --kernel --iters 20000
# reproduce any dumped disagreement with:  --seed <printed> --iters 1
sudo cargo test --test conftest    # runs the privileged vfuzz differential too
```

Expect **many FEBPF-STRICT** (kernel far stricter — normal, not bugs) and,
ideally, **zero FEBPF-LAX**. Any FEBPF-LAX line is a real soundness gap in
febpf's verifier and is triage material (disasm + kernel log are printed, seed
reproduces it); it is not a blocker for landing the harness.
</content>
</invoke>
