# Verifier rejection explainer

When the verifier rejects a program, print a **counterexample trace**: the
exact path the abstract interpreter walked from entry to the failing
instruction, rendered as annotated disassembly with the abstract register
state at each step, plus cause notes such as "the pointer in r0 comes from
map_lookup_elem at insn 3 and may be NULL on this path".

This addresses the #1 real-world eBPF pain: inscrutable verifier errors.
The DFS in `src/verifier.rs` already walks the failing path; the work is
retaining enough information to reconstruct it, cheaply, without disturbing
the pruning machinery (HANDOFF.md §3).

## Design: record decisions cheaply, replay on rejection

Retaining per-step state snapshots along every live path would multiply the
verifier's memory footprint and interact badly with pruning. Instead:

### 1. Always-on: a path arena of branch decisions

The DFS main loop (`Verifier::verify`) pops `(pc, VState)` work items and runs
a linear trail until `step()` returns multiple successors (conditional branch,
maybe-null fork). Only those multi-successor points are non-deterministic to a
replayer — everything between them is a pure function of the state.

We add a **path arena**: `Vec<PathNode>` on the `Verifier`, where

```rust
struct PathNode {
    parent: Option<u32>, // previous decision on this path
    pc: u32,             // pc of the branching instruction
    choice: u8,          // index into the successor Vec that this path took
}
```

Whenever `step()` yields N > 1 successors, N nodes are appended (one per
successor), each pointing at the current path's node as parent. Work items
become `(pc, VState, node: Option<u32>, tail: u32)` where `tail` counts steps
executed since the last decision node (needed to know where to stop a replay
that ends in a straight line or an unconditional loop, e.g. the
"program too complex" error).

Cost: ~9 bytes per explored branch-state, bounded by `states_explored` which
is bounded by `insn_budget` (1M) — worst case a few MB, and only for programs
that are about to be rejected for complexity anyway. Typical programs: tens of
nodes. **Pruning is untouched**: nodes of pruned paths simply stay unused in
the arena; the prune lists, ring buffer, and miss-streak backoff see no
change.

### 2. On rejection: replay the failing path

When the DFS raises a `VerifyError` (or hits the insn budget / falls off the
end), we know the current `(node, tail)`. Walking `parent` links and reversing
yields the exact decision list from entry. A **replay** then re-runs the
abstract interpreter from the initial state:

- pruning disabled (fresh `seen` is not consulted; the prune-point block is
  skipped) — the original path already proved these states reachable, and
  ring-buffer eviction means the original prune lists cannot be trusted to
  reproduce the walk;
- at each multi-successor point, the next recorded `choice` is consumed;
- after the last decision, exactly `tail` more steps are executed;
- the final step reproduces the error (asserted by pc; on mismatch — which
  would be a bug — the trace is dropped and only the plain error is printed).

Replay is deterministic because `step()` is a pure function of
`(pc, VState)` modulo `next_null_id`, which is freshly re-counted but only
compared internally, so the state evolution along a single path is identical.
Replay cost is O(path length) ≤ O(original verification), paid only on
rejection.

During replay a bounded trace is captured (memory stays O(1) even for
million-step complexity failures):

- the first `HEAD` (8) steps, and a ring buffer of the last `TAIL` (48) steps;
  a `truncated` count reports omitted middle steps;
- per step: `pc`, the rendered pre-state (`VState::render()`), and for
  conditional branches whether the branch was taken and to where;
- origin tracking: when a helper returns a `MapValueOrNull`, the replay
  records `id → pc`. The final pre-failure `VState` is kept whole so cause
  notes can inspect the actual register operands of the failing instruction.

### 3. Public surface

```rust
pub struct VerifyError {
    pub pc: usize,
    pub msg: String,
    pub trace: Option<Trace>,   // NEW; None for structural (pre-DFS) errors
}
pub struct Trace {
    pub steps: Vec<TraceStep>,  // head ++ tail windows, in program order
    pub truncated: usize,       // steps omitted between the windows
    pub notes: Vec<String>,     // cause hints ("r0 may be NULL because ...")
}
pub struct TraceStep {
    pub pc: usize,
    pub state: String,               // rendered abstract state BEFORE the insn
    pub branch: Option<(bool, usize)>, // conditional on the path: (taken, target)
}
```

`verifier::render_trace(insns: &[Insn], err: &VerifyError) -> String` renders
the annotated disassembly (reusing `disasm::disasm_insn`); it lives in
`verifier.rs` so `disasm` stays dependency-free.

Cause notes (derived from the failing insn + final state):

- **NULL map value**: failing memory access whose base register holds
  `MapValueOrNull{id}` → "rX may be NULL: it was returned by <helper> at insn
  N and this path reaches insn P without a null check" (uses the id→pc origin
  map; also fires for the "arithmetic on this pointer" variant).
- **Uninitialized register**: "rX is uninitialized: no instruction on this
  path writes it" (plus, for helper-arg errors, which arg it was).
- **Out-of-bounds stack/ctx/map-value**: the final state line already shows
  the pointer's offset; a note spells out the computed access range vs the
  region size where recoverable from the message.
- **Branch provenance**: every conditional on the printed path is annotated
  "taken" / "not taken", which is the "because the branch at insn 12 was
  taken" part.

### 4. Output format (concrete example)

Program: lookup a map value and store through it without a null check on one
path.

```
verification FAILED: at insn 9: map value pointer may be NULL; compare it against 0 first

counterexample path (entry -> insn 9, 8 steps):
     0: r1 = map[id:0]                        ; r10=fp0
     2: r2 = r10                              ; r1=map0 r10=fp0
     3: r2 += -4                              ; r1=map0 r2=fp0 r10=fp0 ...
     4: *(u32 *)(r10 - 4) = 0                 ; ...
     5: call map_lookup_elem                  ; r1=map0 r2=fp0-4 ...
     6: r1 = *(u64 *)(r10 - 4)                ; r0=map0_value_or_null ...
     7: if r1 > 7 goto +1 <9>      [taken]    ; r0=map0_value_or_null r1=scalar(...)
  -> 9: *(u64 *)(r0) = 1                      ; r0=map0_value_or_null r1=scalar(u=[8,...])
        ^ at insn 9: map value pointer may be NULL; compare it against 0 first

note: r0 may be NULL here: it was returned by map_lookup_elem at insn 5,
      and this path (branch at insn 7 taken) never compares it against 0.
```

### 5. CLI wiring

Shown **by default** on rejection — no flag. Rationale: the trace is the whole
point; a user who wants the terse form has the first line. Affected commands:
`verify` (replaces the current single-insn echo), `run` / `profile` / `bench` /
`debug` (rejection message includes the trace), `analyze` (FAILED section).
`--no-explain` suppresses it for scripting.

## Implementation stages

1. **Spec** (this file). *(commit 1)*
2. **Capture + replay + `Trace`**: path arena threaded through the DFS,
   `VerifyError.trace`, replay engine, origin tracking; unit-level tests in
   `tests/integration.rs` asserting trace pcs/branches for a rejected
   program. Pruning stats must be unchanged on existing tests. *(commit 2)*
3. **Rendering + CLI**: `render_trace`, cause notes, `--no-explain`, wire
   into `main.rs`, usage text. *(commit 3)*
4. **Tests + polish**: rejection tests for NULL map-value deref,
   out-of-bounds stack, uninitialized register, complexity budget; assert the
   explanation names the right instruction and cause. STATUS update.
   *(commit 4)*

## STATUS

**Complete.** All four stages done; `cargo test` 71 green, clippy 0 warnings.

- [x] Stage 1: spec written.
- [x] Stage 2: capture + replay (`VerifyError.trace`, path arena, replay).
- [x] Stage 3: rendering (`verifier::render_trace`) + cause notes + CLI
      (`--no-explain`; shown by default in verify/analyze/run/profile/bench/debug).
- [x] Stage 4: tests — trace structure tests (`trace_*` in
      `tests/integration.rs`) and rendered-explanation tests (`explain_*`)
      covering NULL map-value deref (origin + branch named), out-of-bounds
      stack, uninitialized register, long-path truncation, and the
      too-complex budget rejection.

Deviations from the plan above: none material. `PathNode` dropped its `pc`
field (not needed for replay). The truncation marker in rendering relies on
the head window being exactly 8 steps (`TRACE_HEAD`); if you change the
constant, keep `render_trace`'s `i == 8` in sync.

Possible follow-ups (not required): notes for pointer-leak and
helper-signature rejections; folding repeated loop iterations in the tail
window ("x N times"); a trace hook in the debugger to seed breakpoints from
the counterexample path.
