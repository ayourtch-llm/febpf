# Load-time dead-code elimination driven by frozen `.rodata`

## Why

Real-world BPF objects use the `const volatile` config idiom:

```c
const volatile bool targ_ms = false;   /* .rodata — set by the loader tool */
...
if (targ_ms) delta /= 1000000;
```

`volatile` stops clang from folding the flag, so the object branches on
values loaded from the frozen `.rodata` map. Real libbpf resolves those loads
to constants and eliminates the dead branches *before the kernel ever sees
the program*; the kernel additionally treats reads of frozen maps as known
scalars. febpf loaded objects as-is, and the dead code tripped the verifier's
`unreachable instruction` check (`check_structure` in `verifier.rs`).

The dominant corpus shape is indirect: febpf's `.text` stitching appends the
**entire** `.text` to any entry program that calls into it
(`docs/specs/elf-loading.md`), so an object with three tracepoint handlers in
`.text` gives each entry program two statically-unreachable subprograms. This
is exactly the code libbpf would not have included, and it rejected 6 of the
56-object corpus (`bcc__biolatency.o`, `hardirqs`, `javagc`, `llcstat`,
`memleak`, `tcppktlat`) plus a rodata-guarded bad path in `wakeuptime`.

## What

`src/dce.rs` — `eliminate_rodata_dead_code(&[Insn], &[MapDef]) -> Option<DceResult>`,
applied automatically at ELF load time (`elf::load_with_target_btf`, after
CO-RE relocation and map-index patching, i.e. on the same instruction stream
libbpf's own pass sees). Assembler-built programs are untouched — the pass is
only wired into the ELF path, and is exported for direct use in tests.

`DceResult` carries the rewritten instructions, the number of removed slots
and resolved branches, and `pc_map` (old→new index of the first surviving
slot at or after each old pc), which `elf.rs` uses to remap the program's
source-level line/func info (`DebugInfo::remap_insns`).

## Model

A small conditional-constant-propagation (SCCP-style) forward dataflow over
the flat instruction stream. Abstract value per register:

| value | meaning |
|-------|---------|
| `Const(u64)` | proven the same constant on every path reaching this pc |
| `Rodata{map,off}` | pointer into a **frozen** (`readonly`) array map's value at a known byte offset |
| `Unknown` | everything else (top) |

Join is pointwise: differing values widen to `Unknown`. The worklist starts
at pc 0 with all-`Unknown` and propagates along **feasible** edges only:

- `lddw` `pseudo::IMM64` → `Const`; `pseudo::MAP_VALUE` into a
  `readonly` `Array` map → `Rodata` (that is exactly what `.rodata*`
  sections load as — see `docs/specs/elf-loading.md`).
- `LDX` (MEM and sign-extending MEMSX) through a `Rodata` pointer at a known
  in-bounds offset → `Const` read from `MapDef::init` little-endian, with
  bytes past the initializer reading as zero (map storage zero-fills).
- `mov` (not movsx) copies/loads constants; 64-bit `add` on a `Rodata`
  pointer adjusts the offset; other ALU on two `Const`s folds through the
  same `eval_alu_const` the optimizer uses; anything else → `Unknown`.
- Helper calls clobber r0–r5. Local calls propagate the caller state into the
  callee (r0 clobbered — r1–r5 are the arguments) and clobber r0–r5 on the
  fall-through; r6–r9 survive because the runtime saves/restores them around
  bpf-to-bpf calls (`SavedFrame` in `interp.rs`).
- A frozen decision can leave a called clang subprogram with only private
  register/stack bookkeeping and `EXIT`. When a top-level caller immediately
  overwrites r0 and then immediately exits, the call is observationally empty
  and is removed together with the now-unreachable body. Requiring the exit
  also makes the call's r1-r5 clobbers unobservable; a caller that performs
  any intervening instruction keeps the call. This handles clang's optimization
  of a source-level `return 0`: it may omit the r0 write when every caller
  discards that return. The purity check rejects helpers, atomics, non-stack
  stores, nested calls, backward control flow, and control flow escaping the
  subprogram; the verifier's rule that a surviving subprogram must initialize
  r0 is not relaxed.
- Conditional jumps with both operands `Const` propagate along the single
  decided edge (`eval_pred_const`, shared with the optimizer); otherwise both.
- Atomics conservatively clobber r0 and the src register (FETCH/XCHG
  write-back, CMPXCHG's r0).

At the fixpoint: instructions that never received a state are dead and are
dropped; conditional branches decided by the **final** joined state are
rewritten (always-taken → `ja`, never-taken → dropped). `ja +0` fall-through
jumps left behind by resolution are collapsed (iterated — removing one can
shorten another to +0). All pc-relative targets are relocated through the
old→new map by `optimize::apply_actions` (shared with `febpf optimize`;
`lddw` pairs move together, `gotol` imm and local-call imm included).

## Soundness

- **Only frozen rodata is folded.** A load folds only when the map is
  `readonly` — and read-only is enforced three independent times (verifier
  store path, verifier helper check, runtime `resolve_slice`), so the folded
  load could never have observed anything but the load-time bytes.
- The dataflow is a monotone join-over-all-paths analysis: a `Const` fact
  holds on *every* execution reaching that pc, so a decided branch really is
  one-way and code unreached at the fixpoint really is unreachable.
- Deciding edges during propagation with in-flight (not yet final) states is
  the standard SCCP argument: values only descend (`Const → Unknown`), edges
  only become more feasible, and final decisions are re-derived from the
  fixpoint states.
- On anything malformed (truncated lddw, jump out of range / mid-lddw) the
  pass returns `None` and the loader keeps the original instructions — the
  verifier then reports the real error. Same when nothing changes: the pass
  is the identity on fully-reachable, rodata-free programs.
- Behavior preservation is additionally checked differentially:
  `tests/dce.rs` runs `febpf equiv` (observable equivalence: r0 + map state +
  helper effects) between original and DCE'd programs, and
  `jit_matches_interpreter_on_objects` covers the DCE'd `rodata_dce.o`
  fixture under both engines.

## Gotchas

- The pass must run **after** CO-RE relocation (constants patched by CO-RE
  guard poisoned `0xbad2310` calls) and after data-relocation lowering to
  `pseudo::MAP_VALUE`, and **before** verification. In `elf.rs` it runs last
  in `load_with_target_btf`, remapping each program's `DebugInfo` via
  `pc_map` (records collapsing onto one new pc keep the latest — it is the
  covering record; records past the surviving code are dropped).
- asm `ro` maps have an empty `init` (all-zero value). Tests that need a
  nonzero flag patch `MapDef::init` directly after assembling.
- Register-only domain: a flag spilled to the stack and reloaded is not
  tracked (join at the reload sees `Unknown`). Not needed for the corpus —
  clang at -O2 keeps config flags in registers between load and branch.
- The 32-bit subtleties are inherited from the shared evaluators: `Const` is
  always the full 64-bit value; ALU32 results are zero-extended by
  `eval_alu_const`, and 32-bit `mov` of a `Rodata` pointer truncates to
  `Unknown`.

## Testing

- Unit (`src/dce.rs`): zero/nonzero flags both directions, writable map never
  folded, joins widen, dead subprogram removal, rodata pointer through a
  local call, sign-extending loads, out-of-bounds rodata reads stay unknown.
- Integration (`tests/dce.rs`): `equiv` equivalence (zero and nonzero flag),
  runtime behavior across inputs, the corpus failure shape
  (unreachable-instruction rejection → verifies after DCE), rodata-guarded
  call to a dead subprogram.
- End-to-end (`tests/elf.rs::rodata_dce_object` + `examples/c/rodata_dce.c`):
  a real clang object with a `const volatile` flag guarding a `.text`
  subprogram — loads, verifies, runs the surviving path, dead body gone,
  line info remapped in-range; also in the JIT/interpreter differential list.

## STATUS

**DONE (2026-07-11).** Both configs green (`cargo test` 225 /
std interpreter-only 216; `cargo clippy --all-targets` 0 warnings in
both). Corpus (56 objects, `scripts/scan-corpus.sh`): verified OK
**38 → 44 (67.9% → 78.6%)** — fixed `biolatency`, `hardirqs`, `javagc`,
`llcstat`, `memleak`, `wakeuptime`; `tcppktlat` moved past the unreachable
check to its real next blocker (helper #46 `get_socket_cookie`). Remaining
rejections are the known out-of-scope classes: BTF-typed ctx pointer derefs
(`offcputime`, `runqlat`, `runqslower`), "subprogram may not return a
pointer" (`filetop`, `ksnoop`, `tcpsynbl`), helpers #67/#46, and 4 CO-RE
load failures.

Possible extensions, in usefulness order: track spilled flags (stack slots in
the domain); teach the *verifier* frozen-rodata constant reads (kernel
parity, would sharpen path pruning); fold `Rodata` loads into `mov` imms so
the surviving loads disappear too (pure size win — behavior already right).
