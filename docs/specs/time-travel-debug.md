# Time-travel debugging

Reverse execution (`rstep` / `rcontinue`) and data watchpoints for the febpf
debugger. Because execution is fully deterministic (fixed-seed prandom, stable
map storage — HANDOFF §7), we never record per-instruction state: we take
**periodic snapshots** and **replay forward** to reach any earlier instruction
count. "Step backward one instruction" = restore nearest snapshot ≤ target,
re-execute until `insn_count == target`.

## Snapshot representation

`interp::Snapshot` (public struct, private fields; `Clone + PartialEq + Debug`)
captures *everything* execution reads or writes:

| field | why |
|-------|-----|
| `regs: [u64; 11]`, `pc`, `insn_count` | machine core |
| `frames: Vec<SavedFrame>` | bpf-to-bpf call stack (ret pc + saved r6..r9) |
| `stack: Vec<u8>` | all `MAX_CALL_FRAMES` stacks (one flat buffer in `Vm`) |
| `ctx: Vec<u8>` | programs may write to the context |
| `regions: Vec<Region>` | **load-bearing**: map-value regions are created lazily in execution order (`Vm::value_addr`). If we didn't restore the region table, replay would re-allocate handles at different indices and guest-visible virtual addresses would diverge from the original run. |
| `maps: Vec<MapSnapshot>` | per-map storage clone + `region_handles` (same reason as above) |
| `prandom: u64` | xorshift state |
| `printk: Vec<String>` | replay re-executes `trace_printk`; restoring first keeps the log exactly consistent with the current position |
| `profile: Option<Vec<u64>>` | replay would otherwise inflate profiling counts |
| `nondet_calls: u64` | see "non-determinism" below |

`maps::MapSnapshot` = `{ storage: Storage (now Clone), region_handles }`, with
`Map::snapshot()` / `Map::restore()`. Snapshot cost is O(state size): ~4 KiB of
stacks + map contents; taken every `snapshot_interval` (default 10 000) steps,
which makes any reverse operation O(interval + |state|) instead of O(n).

`Machine` gains:

- `snapshot(&self) -> Snapshot`
- `restore(&mut self, &Snapshot)` — restores all of the above, including
  overwriting `ctx` contents and replacing `vm.regions` (truncating any
  regions created after the snapshot).
- `run_to_count(&mut self, target: u64)` — steps until `insn_count == target`
  (stops early on exit/error; used only for replay so echo-printk is
  suppressed by the caller).

`Instant start` is deliberately NOT snapshotted (can't restore wall clock).

## Replay mechanism

`debug::DebugSession` keeps:

- `base: Snapshot` taken at `insn_count == 0` (machine creation),
- `checkpoints: Vec<Snapshot>` — pushed after any step where
  `insn_count % interval == 0`, monotonically increasing counts.

`goto_count(target)`: pick the latest of {base, checkpoints…} with
`insn_count <= target`, `restore`, replay to `target` with printk echo and
watchpoint reporting suppressed. All forward stepping in the REPL goes through
one wrapper (`step_fwd`) that also maintains checkpoints and evaluates
watchpoints, so time travel and watchpoints see every executed instruction.

- `rstep [N]`: `goto_count(insn_count - N)` (saturating at 0).
- `rcontinue`: find the greatest `t < current` where a stop condition holds
  (pc ∈ breakpoints at count `t`, or a watchpoint's value differs between
  `t-1` and `t`). Scan snapshot intervals from the one containing `current`
  backwards; within each interval replay forward from its snapshot recording
  the *last* matching `t` (and the pc of the writing instruction for
  watchpoints). First interval with a match wins; otherwise land at count 0
  ("start of program"). This is GDB `reverse-continue` semantics.

The program **exiting does not end the REPL** anymore: the session records
`finished = Some(r0)`, forward stepping reports "program has exited", and
reverse commands still work (you can step backwards from the exit). `quit`
returns the recorded r0 so `main.rs` behavior is preserved when the program
ran to completion.

## Watchpoints

`watch` targets are evaluated after every forward step (and during replay
scans); a change stops execution and reports old → new bytes plus the pc of
the instruction that performed the write.

Two target kinds (`WatchTarget`):

- `Addr { addr, len }` — raw virtual address, for ctx/stack (fixed region
  handles). Read via `Machine::read_mem`.
- `MapVal { map, key, off, len }` — **logical** map watch: the key is looked
  up at every evaluation and the value bytes read straight from map storage
  (`Map::lookup` + `Map::value`). Never uses virtual addresses, so it is
  immune to region-handle churn across restore/replay, and it works before
  the program ever obtains a pointer to the value. A hash-map entry
  appearing/disappearing (insert/delete) counts as a change
  (`Option<Vec<u8>>` comparison).

REPL syntax:

```
w, watch <addr> [len]                 raw memory watch (default len 8)
watch map <name> <key> [off [len]]    map value watch (key = integer, encoded
                                      little-endian at the map's key size;
                                      default: whole value)
unwatch <id> | unwatch                delete one / all watchpoints
info                                  now also lists watchpoints
```

"Step back to the write that changed it" = set the watch, `rcontinue`: it
lands on the state immediately after the changing write and reports the
writer's pc.

## Non-determinism caveat

Replay assumes re-execution reproduces the original run. That holds for
everything built in **except** `ktime_get_ns` (wall clock), and cannot be
guaranteed for user-registered helpers (arbitrary closures). The machine
counts calls to these (`nondet_calls`); the first reverse command issued while
the count is nonzero prints a warning that reverse execution may be
inaccurate. This is documented, not prevented: deterministic user helpers
(the common case for tests/fixtures) work fine.

## REPL testability

`debug.rs` is refactored so the session is driveable without a TTY:

```rust
pub struct DebugSession<'a> { /* machine, breakpoints, watchpoints, checkpoints… */ }
impl<'a> DebugSession<'a> {
    pub fn new(vm: &'a mut Vm, ctx: &'a mut [u8], opts: &DebuggerOpts) -> Self;
    pub fn handle_command(&mut self, line: &str, out: &mut dyn io::Write)
        -> io::Result<Outcome>;   // Outcome::Continue | Outcome::Quit(Option<u64>)
    pub fn machine(&mut self) -> &mut Machine<'a>;
}
```

`repl()` becomes a thin stdin/stdout loop over `handle_command`. Tests feed
command strings and assert on machine state and captured output.

## Implementation stages

1. **Spec** (this file) — commit.
2. **Snapshot/restore core** — `maps.rs`: `Storage: Clone`, `MapSnapshot`,
   `Map::{snapshot,restore}`; `interp.rs`: `Snapshot`,
   `Machine::{snapshot,restore,run_to_count}`, `nondet_calls` counter.
   Tests: snapshot at k / replay to n ≡ straight run (full-state equality),
   including a program exercising maps, prandom, subprog calls and ctx writes.
3. **REPL refactor** — `DebugSession` + `handle_command` with existing
   commands only, output via `io::Write`; exit no longer terminates the
   session. Tests drive step/break/continue/regs through strings.
4. **Time travel + watchpoints** — checkpoints, `rstep`, `rcontinue`,
   `goto <count>`, `watch`/`unwatch`, nondet warning. Tests: rstep equals
   fresh k-step run; watchpoint triggers on a map write with correct pc;
   rcontinue returns to the write; reverse from program exit.
5. **STATUS** section appended here — final commit.

## STATUS

**Done — all four stages implemented and committed.**

- Stage 2 — snapshot/restore core (`maps.rs` `MapSnapshot`, `interp.rs`
  `Snapshot` / `Machine::{snapshot,restore,run_to_count}`, `nondet_calls`).
- Stage 3 — `DebugSession` + `handle_command(line, out)`; REPL is a thin
  stdin loop; program exit no longer ends the session.
- Stage 4 — checkpoints, `rstep` / `rcontinue` / `goto`, `watch` (raw addr +
  logical map targets), `unwatch`, nondet warning.
- Tests (tests/timetravel.rs, tests/debugger.rs): replay determinism with
  full-state equality against a straight run (maps, prandom, frames, ctx,
  regions), rstep ≡ fresh k-step run, reverse from program exit, rcontinue
  to previous breakpoint, watchpoint on a map write + rcontinue back to the
  write, raw-address watch, nondet warning. `cargo test` 74 green,
  `cargo clippy --all-targets` 0 warnings.

Small deviations from the plan above (all deliberate):

- `goto` past the recorded exit clamps to the exit count instead of
  re-executing the exit instruction.
- Watchpoint evaluation during `rcontinue` uses the same
  `eval_watch`/segment-scan described here; the "step back to the write"
  flow reports the writer's pc in the stop message rather than a separate
  command.
- One old REPL behavior changed: `step`/`continue` reaching exit used to
  return from the REPL immediately; now the session stays open (so you can
  `rstep` back from the exit) and `quit` returns the recorded r0.

Possible follow-ups (not required): a `tt-interval` command to tune the
checkpoint spacing at runtime; capping checkpoint memory for very long runs;
watch expressions over registers.
