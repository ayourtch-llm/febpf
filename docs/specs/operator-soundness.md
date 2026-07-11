# Operator soundness — exhaustive small-width checks

Item 1 of the formal-methods plan (`docs/ideas.md`): brute-force verification
of the verifier's abstract operators, the bug class where Agni found real
kernel verifier bugs. Harness: `src/soundness.rs` (`#[cfg(test)]`, zero deps).

## The obligation

The verifier's abstract domains map an abstract value `a` to its
concretization `γ(a)`, the set of runtime values it stands for:

- **Tnum** `(value, mask)`: `γ = { n : n & !mask == value }` (`tnum.rs`,
  kernel `kernel/bpf/tnum.c`).
- **Scalar** `(tnum, umin, umax, smin, smax)`: the intersection of the tnum
  set with the unsigned range and the signed range (`verifier.rs`, kernel
  `bpf_reg_state` bounds).

For an abstract operator `⊕'` approximating a concrete operator `⊕`:

```
∀ abstract a, b.  ∀ x ∈ γ(a), y ∈ γ(b).   (x ⊕ y) ∈ γ(a ⊕' b)
```

For branch analysis the obligation is dual-sided:

- if the analysis **decides** an outcome, every concrete pair must realize
  that outcome;
- if it declares an outcome **dead**, no concrete pair may realize it;
- the **refined** abstract values for an outcome must still contain every
  concrete pair that realizes it.

This is a ∀-property over 2^64 × 2^64 concrete inputs — fuzzing cannot
establish it, but small-width exhaustion can, and the operators are
bit-sliced/carry-uniform enough that small-width windows placed at the
interesting boundaries catch the real bug classes (all three bugs found so
far were boundary bugs; see below).

## Harness design

**No mirror.** The harness runs the PRODUCTION 64-bit operators directly —
there is no re-implementation-at-width-w that could drift out of sync.
Instead the *abstract inputs* are confined to windows of `2^w` consecutive
values, which makes `γ` exhaustively enumerable while carries, wrap-around,
sign extension and truncation execute exactly as deployed. Windows used:

| window | base | exercises |
|---|---|---|
| low | `0` | plain small values |
| top64 | `2^64 - 2^w` | u64 wrap, negative i64, arsh sign fill |
| straddle-i64 | `2^63 - 2^(w-1)` | i64 sign boundary (signed compares/bounds) |
| straddle-bit32 | shift 28..29 | carries across bit 32 (tnum ops) |
| top-u32 | `2^32 - 2^w` | negative i32 under JMP32/ALU32 |
| straddle-i32 | `2^31 - 2^(w-1)` | i32 sign boundary under JMP32 |
| straddle-u32 | `2^32 - 2^(w-1)` | values above u32::MAX → truncation wrap |

**Ground truth** is a mirror of `interp.rs`'s concrete ALU/JMP evaluation
(`conc_alu` / `conc_cmp`: wrapping ops, udiv/0 → 0, umod/0 → dst, sdiv in the
operand width, shift amounts masked) — so the harness checks the abstract
transfer functions against the engine's actual runtime semantics.

**Enumeration.**

- Tnums over a window: all `3^w` well-formed `(value, mask)` pairs;
  `γ` enumerated by mask-subset iteration (`2^popcount` values).
- Scalar states over a window: for aligned windows, ALL
  `(umin, umax, tnum)`-consistent triples (every window tnum × every
  u-range), each with signed bounds both underived (what `sync` computes) and
  exact; `full_signed` mode additionally enumerates every consistent
  `(smin, smax)` pair, making the state space complete over the window
  (used at w=3 in the `*_full_state_space_w3` tests). Unaligned (straddle)
  windows use the tnums the verifier itself builds (`range`/`const`/
  `unknown`). All states are `sync`ed and deduplicated, and empty-γ states
  dropped, before use.

**Production entry points exercised** (via minimal `pub(crate)` hooks):
`Tnum::{add,sub,mul,and,or,xor,lshift,rshift,arshift,cast,subreg,range,
intersect,union,is_subset_of}`, `alu_scalar` (ADD SUB MUL DIV/SDIV MOD/SMOD
AND OR XOR LSH RSH ARSH, 64- and 32-bit — this covers `scalar_add`,
`scalar_sub`, …, `scalar_shift` and the ALU32 truncate/zero-extend epilogue
as deployed), `scalar_movsx`, `scalar_endian`, `Scalar::{truncate32,
from_tnum, sync, is_subset_of, join}`, and `analyze_cond_jmp` — a function
extracted from the verifier's jump step (and called by it), so the branch
checks test the exact truncation → `branch_taken` decision → `refine` →
write-back composition, not the pieces in isolation.

**Consistency invariants** checked alongside:

- tnum well-formedness (`value & mask == 0`) preserved by every op;
- `sync` never removes a concrete value (γ_after ⊇ γ_before), reports a
  contradiction only when γ is empty, and is idempotent (γ *growth* is
  permitted on contradictory inputs: `tnum_intersect`'s kernel contract says
  the caller must know the operands overlap; widening a dead state loses
  precision, never soundness);
- `is_subset_of` implies γ-inclusion (what pruning relies on);
- `join` is an upper bound both by γ and by `is_subset_of`.

## Exhaustiveness levels

Default `cargo test` (debug, runs in ~1.5 s wall on 24 threads):

| check | width | windows |
|---|---|---|
| tnum add/sub/mul/and/or/xor | w=6 (3^6 × 3^6 pairs, ~17M concrete/op) | low, top, straddle-32; cross-window w=4 |
| tnum shifts (const 0..64), cast, subreg | w=8, every shift amount | low, top, straddle |
| tnum range | w=8 (all 2^8 choose 2 ranges × full γ) | 4 bases |
| tnum intersect/union/is_subset_of | w=6 | low, top |
| alu_scalar, all 13 op/sign variants × {64,32} | w=3 state pools | 3–4 windows each |
| ditto, complete state space (`full_signed`) | w=3 | low + straddles |
| analyze_cond_jmp, all 11 ops × {64,32} | w=3 pools | 3–4 windows each |
| signed jumps, complete state space | w=3 | sign straddles |
| truncate32 / movsx / endian / from_tnum | w=4 pools / w=6 tnums | all |
| sync γ/idempotence | w=4 (+w=3 full_signed) | 4 windows |
| Scalar is_subset_of / join | w=4 / w=3 pools | all |

`#[ignore]`d heavy sweeps — run `cargo test --release -- --ignored soundness`:

- `tnum_binops_sound_w8_exhaustive`: all six binary tnum ops at w=8, low and
  top windows (3^8 × 3^8 abstract pairs, ~4.3×10^9 concrete checks per op
  per window).
- `alu_all_sound_w4_exhaustive`, `jmp_all_sound_w4_exhaustive`: every ALU and
  JMP variant over w=4 state pools.

## Bugs found (2026-07-11, first run of the harness)

All three were real and fixed in the same change; each has a program-level
regression test in `tests/integration.rs` that the buggy verifier ACCEPTED:

1. **JMP32 signed compares decided/refined on zero-extended bounds.**
   `truncate32()` sets `smin/smax` to the zero-extended value, so
   `w0 = 0x80000000; if w0 s> 1` was decided always-taken (2^31 > 1) while
   concretely INT_MIN > 1 is false — the executed path was pruned unverified.
   Refinement had the mirror-image bug (`w1 s<= 5` clamped the range to
   [0,5], excluding surviving values ≥ 2^31). Fix: `Scalar::sext32_view()` —
   JMP32 signed decisions and refinement now run in the sign-extended-32
   domain and map back via `truncate32`. Kernel parity: the kernel keeps
   dedicated `s32_min_value/s32_max_value` bounds that `is_branch32_taken` /
   `reg_set_min_max` use (kernel/bpf/verifier.c); febpf derives the s32 view
   on demand (exact unless the range crosses the i32 sign boundary).
2. **ALU32 sdiv/smod constant folding interpreted operands as i64.**
   `1 s/ -1` in 32 bits folded to `1 / 4294967295 = 0`; concretely it is
   `-1`. Fix: fold in i32 when `is32` (matching `interp.rs` and BPF ISA
   sdiv32/smod32 semantics).
3. **`Scalar::sync()` was not idempotent** — tnum tightening was not fed back
   into the signed bounds, leaving non-canonical states that broke the
   `join`/`is_subset_of` upper-bound relation (precision/consistency, not a
   memory-safety hole). Fix: iterate the derivations to a fixpoint, mirroring
   the kernel's `reg_bounds_sync()` running `__update_reg_bounds` both before
   and after `__reg_bound_offset`.

## How to extend

- **New ALU op / transfer function**: add the op to the `conc_alu` mirror (or
  a new concrete function matching `interp.rs`), then a `check_*` call — the
  state pools are reusable as-is. If the op is width-sensitive, think about
  which straddle window stresses its boundary and add one if missing.
- **New abstract domain field** (e.g. dedicated 32-bit bounds): extend
  `contains_s` and the state generator; the checks themselves are
  γ-membership and need no change.
- **Wider exhaustion**: widths are constants (`ALU_W_*`, `JMP_W_*`, per-test
  `w` arguments); bump them in the `#[ignore]`d tests only — debug-mode
  `cargo test` must stay in seconds.
- **Item 2 hook (SMT-LIB emission)**: the obligation checked here is exactly
  the formula to emit per operator — `γ` membership is quantifier-free over
  bitvectors (`(x & ~mask) == value`, range comparisons), so an emitter can
  reuse this file's operator inventory one-to-one: for each `check_*` there
  is one `(assert (not (=> (and (in x a) (in y b)) (in (op x y) (absop a
  b)))))` per operator, `(check-sat)` expecting `unsat` at full 64-bit width,
  discharged by z3 if installed (same optional-oracle pattern as
  clang/bpftool). Keep the concrete-semantics mirrors (`conc_alu`,
  `conc_cmp`) as the single source of the op list.
