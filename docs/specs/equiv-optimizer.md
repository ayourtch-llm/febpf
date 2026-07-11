# Equivalence checker & verifier-guided optimizer

STATUS: in progress (see bottom for the exact next step).

Two coupled deliverables:

1. `febpf equiv <a> <b> [--ctx ...] [--iters N] [--seed N]` — decide whether two
   programs have the same **observable behavior** for all inputs.
2. `febpf optimize <prog> [-o out] [--stats]` — apply only provably-sound
   rewrites, each gated on the abstract state the verifier computes at that PC,
   then **self-check** the result with `equiv` and refuse to emit if behavior
   was not preserved.

The optimizer depends on the checker, so the checker is built first.

## 1. Observable behavior

For a fixed input (context bytes + preloaded map contents + a fixed
`get_prandom_u32` seed), an execution of a program produces an **observation**:

```
Observation = {
    outcome : Exit(r0: u64) | Fault(kind: String),
    printk  : Vec<String>,          // ordered trace_printk lines
    maps    : Vec<(name, Vec<(key,value)>)>,  // final non-readonly map contents
}
```

Two programs are **observably equivalent** iff for *every* input they produce
equal observations. Notes:

- `r0` alone is **not** the observable — two programs that log different
  `trace_printk` lines, or leave a map in a different state, are NOT equivalent
  even when `r0` matches. The interpreter already records all three (`Vm::printk`,
  `Vm::maps` with `Map::iter_entries`, and the run's return value).
- Map contents are canonicalized (entries sorted by key) so hash-map iteration
  order is not itself observable. Read-only (`.rodata`) maps are inputs, not
  outputs, and are excluded from the output tuple.
- `Fault` outcomes compare a **normalized** message: the `runtime error at insn
  N:` PC prefix is stripped, because an optimizer legitimately renumbers PCs.
  Both programs are verified before running, so faults are rare in practice.

Determinism (fixed prandom seed, stable map storage — HANDOFF §7) is what makes
a single observation a pure function of the input, and thus makes differential
testing meaningful and reproducible.

## 2. Layered checker (cheapest first)

### (a) Abstract / structural — yields `PROVEN-EQUIVALENT (abstract)`

Sound facts discharged with the verifier's tnum+range domain, no execution:

- **Identical programs**: same instruction slots and same map defs ⇒ trivially
  equivalent (the reflexive case; also the optimizer's "already optimal" path).
- **Proven-constant, side-effect-free**: run the verifier on both, read the
  per-PC abstract register state (new hook, §4) at every `exit`. If in both
  programs `r0` is proven to be the *same* single constant at every exit, and
  neither program performs an externally-visible side effect (no
  `trace_printk`, `map_update_elem`, `map_delete_elem`, or user helper — i.e.
  the observable is exactly `Exit(c)` with empty printk and unchanged maps),
  then they are equivalent for all inputs.

These are *sufficient* conditions; when none applies we fall through to (b).

### (b) Differential falsification — yields `NOT-EQUIVALENT` or empirical `EQUIVALENT`

Run both under the deterministic interpreter over a shared battery of inputs:

- **Seeded random** contexts (reuse `fuzz::Prng`), `--iters N` of them.
- **Boundary** contexts: all-zeroes, all-ones, and per-byte patterns.

For each input, build a fresh `Vm` for each program (fresh map state from the
`MapDef`s), run, and compare observations. The first mismatch ⇒
`NOT-EQUIVALENT` with the witnessing input (its seed/description and hex) and a
diff of the two observations — fully reproducible. If no input separates them,
report `EQUIVALENT (N inputs, no counterexample found)` and state explicitly
that this is empirical, not a proof.

### Verdicts and exit codes

| verdict | meaning | exit code |
|---|---|---|
| `PROVEN-EQUIVALENT (abstract)` | discharged by (a) | 0 |
| `EQUIVALENT (empirical)` | (b) found no counterexample | 0 |
| `NOT-EQUIVALENT` | (b) found a witness | 1 |
| error (load/verify failed) | — | 2 |

Programs that fail their own verifier are still comparable (we can run
`--no-verify` internally under the memory-safe interpreter), but `equiv`
verifies by default and reports a load/verify error as exit 2.

## 3. Optimizer — provably-sound, verifier-gated rewrites

`optimize` verifies the input, obtains the per-PC abstract pre-state (§4), and
applies rewrites **only** where the abstract state proves them behavior-
preserving. Each rewrite class and its soundness gate:

- **Constant folding**: an ALU insn whose dst and (reg) src are both proven
  constant by the abstract state ⇒ replace with `movimm dst, foldedconst` when
  the result fits in imm32; skip otherwise. Sound because the operands are the
  same constants on every execution reaching that PC.
- **Dead-branch elimination**: a conditional jump whose condition the range/tnum
  state proves always-true (⇒ replace with `ja`) or always-false (⇒ drop). The
  verifier already computes whether both successors are reachable; we reuse the
  per-PC bounds to evaluate the predicate. Unreachable instructions revealed by
  this are then dropped (they have no abstract state — never visited).
- **Algebraic simplification / strength reduction** (input-independent, always
  sound): `x*2^k ⇒ x<<k`, `+0`/`-0`/`*1`/`|0`/`^0`/`>>0`/`<<0` ⇒ drop,
  `*0 ⇒ mov 0`, `& mask` where tnum proves dst already fits in mask ⇒ drop.
- **Redundant reload elimination** (gated): a load into a register that the
  abstract state proves already holds that exact value ⇒ drop. Conservative;
  only fired when provably safe.

Instruction removal renumbers PCs; all pc-relative targets (JMP/JMP32 `off`,
`gotol` `imm`, local-`call` `imm`) are relocated through an old→new index map.
`lddw` two-slot pairs move together.

**Self-check (hard gate)**: after producing the candidate, run the full §2
checker between input and output. If it does not return PROVEN- or (empirical)
EQUIVALENT, the optimizer **errors and emits nothing** (exit nonzero). It also
asserts the output re-verifies. `--stats` prints insns before/after and a count
per rewrite class. Output stays kernel-loadable (no constructs the kernel
verifier rejects — we only ever remove work or swap in a cheaper equivalent
opcode).

## 4. Verifier per-PC abstract-state hook

The verifier already records a human-readable `insn_state: Vec<Option<(String,
usize)>>` at first visit. That is lossy (string) and first-visit-only (unsound
to optimize on). We add a machine-readable, **join-over-all-visits** record:

- New `VerifyOk.pc_regs: Vec<Option<[RegState; NUM_REGS]>>`, one slot per insn.
- On every visit to a PC (before `step`), the current frame's register array is
  **joined** (least upper bound) into the slot. A fact true in the joined state
  is true on every path reaching that PC ⇒ sound to optimize on. Join uses
  `Tnum::union` and min/max of the range fields; `Uninit`/pointer/scalar
  mismatches widen to a conservative "unknown/top".
- Pruned states are safe to skip: a pruned state is subsumed by one already
  processed at that prune point, whose downstream states already dominate it
  (monotonicity of the transfer functions — the verifier's own soundness
  argument).

The join and the public accessor live in `verifier.rs`; recording is always on
(cheap) and does not touch the pruning machinery.

## Module layout

- `src/equiv.rs` — Observation capture, abstract layer (a), differential layer
  (b), `Verdict` enum, top-level `check()`.
- `src/optimize.rs` — rewrites, PC relocation, self-check, `--stats`.
- `verifier.rs` — `RegState`/`Scalar` join + `pc_regs` recording + accessors.
- `main.rs` — `equiv` and `optimize` CLI commands.

## Staged plan

1. Spec (this file). ✅
2. Verifier per-PC abstract-state hook (`pc_regs` + joins + public `RegState`
   accessors).
3. `equiv` core (Observation capture, layers a+b, verdict) + CLI + tests.
4. Optimizer rewrites one class at a time, each behind the equiv self-check +
   `optimize` CLI + `--stats` + verifier re-check + tests.
5. Final: update this STATUS.

## Testing bar (differential/behavioral)

- `equiv` returns NOT-EQUIVALENT (with witness) on a deliberately-different
  pair, empirical EQUIVALENT on a known hand-optimized pair, and PROVEN on a
  trivial abstract case.
- `optimize` shrinks a program with constant-folding/dead-branch opportunities,
  preserves r0+map+printk (checked via equiv AND a direct run), leaves an
  already-optimal program unchanged, and its output re-verifies.
- Both feature configs stay green: `cargo test` and
  `cargo test --no-default-features`; `cargo clippy --all-targets` 0 warnings in
  both.

## STATUS

**DONE.** All stages complete and green in both feature configs
(`cargo test`: 180 / `--no-default-features`: 173; `cargo clippy --all-targets`
0 warnings in both).

Implemented:
- Stage 2 — verifier per-PC join-over-all-visits abstract state
  (`Scalar::join`, `RegState::join`, `VerifyOk::pc_regs` + `regs_at`).
- Stage 3 — `src/equiv.rs`: observation capture (r0/fault + printk + final ctx
  bytes + writable-map contents), abstract layer (identical program;
  side-effect-free proven-constant r0), differential layer (fixed/boundary/
  seeded-random), `Verdict` + exit codes, `febpf equiv` CLI, unit +
  integration tests (incl. a printk-only and a map-only difference).
- Stage 4 — `src/optimize.rs`: strength reduction, algebraic identities,
  constant folding, dead-branch elimination (const + range/tnum), redundant-
  mask elimination; PC relocation with i16-overflow detection; fixpoint loop;
  re-verify; **equiv self-check gate** (refuses to emit otherwise); `febpf
  optimize` CLI with `--stats`. `examples/optimizable.s` exercises all classes
  (11 → 7 insns).

Design choices worth noting for a future extender:
- Fault outcomes compare the PC-stripped message; both sides are verified so
  faults are rare. Error strings that embed absolute targets could in principle
  differ spuriously — not observed in practice.
- Constant folding only emits when the value round-trips through i32 (single
  `mov` slot); wider constants are left alone rather than synthesized as
  `lddw`.
- Redundant-reload elimination from the spec was intentionally **not**
  implemented: proving a reload redundant needs alias/memory analysis beyond
  the current per-PC register domain. The self-check gate means adding it later
  cannot ship an unsound result — worst case it fails to emit.

Exact next step if extending: add redundant-reload elimination behind a simple
"no intervening write to the pointer's region or the register" check, or teach
the abstract layer a CFG-isomorphism proof for the empirical cases.
