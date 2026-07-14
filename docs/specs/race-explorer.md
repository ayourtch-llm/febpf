# Race explorer — deterministic concurrency race detection

`febpf race <prog> [--procs N] [--schedules M] [--seed S] [--schedule CSV] [--ctx ...] [--stats]`

STATUS: complete, including heterogeneous library exploration (2026-07-15).
`febpf race` ships with systematic + seeded
exploration, outcome-divergence and lost-update detection, `--schedule` replay,
`--stats`, and `examples/race_{rmw,atomic}.s`. Behavioral tests in
`tests/race.rs` cover both repeated and heterogeneous programs. The CLI remains
the convenient single-program surface; embedders use `explore_programs` and
`replay_programs`. Follow-ups if extended: model `BPF_EXIST`/`BPF_NOEXIST`
update flags explicitly, per-CPU maps, and full `.febpf` replay-file
integration (the choice vector is the current reproduction path).

## What it is

Real eBPF programs run concurrently on many CPUs against **shared maps**. The
classic bugs are:

- **lost update / stale read-modify-write** — `lookup(k)`, read the value,
  `value+1`, `update(k, value)`; two CPUs both read the old value and one
  update is lost;
- **check-then-act TOCTOU** — `lookup(k)` says "absent", both CPUs then
  `update(k, ..., BPF_NOEXIST)` (or unconditionally) and clobber each other;
- **non-atomic RMW of a map value** — plain `*(u64*)ptr += x` through a
  looked-up pointer instead of an atomic add.

febpf's interpreter is **fully deterministic and single-threaded-simulated**
(handoff §7). That lets us do something a real kernel can't: model `N`
concurrent invocations of one or several programs sharing one map set, drive a
**deterministic scheduler** that interleaves them, systematically explore
schedules, and flag when different schedules commit different map state — a
race — reproducibly.

## Concurrency model

- `N` logical **instances**. The CLI assigns the same program to all instances
  (default 2); the library's `RaceProgram` API can assign a different program
  and context to every instance. Each has its own
  registers, program counter, call frames, 512-B×frames stack, instruction
  counter and context buffer. **All instances share ONE set of maps**
  (`src/maps.rs`) — that shared, mutable map state is the only channel through
  which they interact, which mirrors real eBPF (per-CPU registers/stack, shared
  maps).
- CLI instances run with the **same input** (`--ctx`). Heterogeneous library
  instances may have different context bytes, but every instance's input is
  fixed across all explored schedules. The schedule is therefore still the
  only independent variable. Context lengths must be equal because instances
  are swapped through one machine memory layout.
- Reuses the existing `Machine`/`Vm` (handoff §1 virtual-address memory model
  is untouched, so every instance is still fully memory-safe). Only ONE instance
  is ever *actively* stepping at a time (cooperative), so a single `Machine`
  borrows the `Vm`; per-instance execution state is swapped in/out around each
  turn via a new opaque `interp::InstanceState`. The shared map state, region
  table and prandom stream live in the `Vm` and are **not** swapped.

### Heterogeneous program boundary

`explore_programs(&[RaceProgram { name, program, ctx }, ...], config)` installs
one executable image per logical instance. The first program constructs the
VM and map storage; every later program must declare an exactly identical map
set. Alternate roots are internal scheduler images, not entries in a program
array and not tail-call edges. Consequently this API explores interactions
between flat program roots sharing maps; it does not model a different
tail-call graph per root.

The explorer is behavioral evidence, not a verifier entry point. Callers must
verify every program under the intended execution environment first. Program
labels are retained in `RaceReport` and heterogeneous traces. A choice vector
is replayed with the same ordered `RaceProgram` set through `replay_programs`.
An empty set, unequal context lengths, or non-identical map definitions is
rejected before scheduling.

`explore_xdp_programs` applies the same scheduler to `RaceXdpProgram` entries.
Each entry owns a fixed `XdpFrame` snapshot. Instances share maps but retain
private context, complete packet storage, active data bounds, resize
capabilities, output sinks, and redirect state. Storage capacities must match
because snapshots are swapped through one provider environment; packet bytes,
active bounds, and metadata may differ. XDP programs are verified under the
XDP context model before scheduling, and `replay_xdp_programs` preserves the
same choice-vector contract.

## Scheduler granularity + rationale

Preemption happens only at **map-visible operations**. Between two map-visible
ops an instance runs sequentially (its purely instance-local work — ALU,
branches, stack/ctx loads and stores, bpf-to-bpf calls, non-map helpers — is
deterministic and invisible to the others, so its ordering cannot matter). A
map-visible op is any instruction that touches shared map state:

1. `map_lookup_elem` / `map_update_elem` / `map_delete_elem` helper calls;
2. a plain `LDX`/`STX` (load/store) whose resolved address lands in a
   **map-value region** (i.e. a dereference of a pointer returned by
   `map_lookup_elem`);
3. an **atomic** (`STX|ATOMIC`: `lock += `, `atomic_fetch_*`, `xchg`,
   `cmpxchg`) on a map-value region.

Including the map-value **load** (case 2) as a preemption point is what makes
the lost-update race observable: the staleness window in a
`lookup → load → +1 → update` sequence is *between the load and the update*. If
we preempted only at helper calls, that load-to-update span would run
atomically and no interleaving could expose the lost update. Loads/stores to
stack or ctx are **not** preemption points — that memory is instance-private.

At each preemption point the scheduler chooses which pending instance executes
its next single map-visible op; then that instance runs locally forward to its
following map-visible op (or to program exit). So a *schedule* is a sequence of
`(instance-id, map-op)` choices — the interleaving trace we report.

**Limitation (documented):** this granularity captures exactly the races that
flow through map state. It will not catch races on other shared state — but in
this model there is no other shared state (registers/stack/ctx are per-instance
by construction), so within the model it is complete for map races. It also
models each map-visible op as itself atomic (the kernel's per-op guarantees);
sub-op tearing is out of scope.

## Race definition + detection

Two independent detectors, both reported:

1. **Outcome divergence (general).** For fixed inputs, explore schedules and
record each schedule's *observable outcome* = (final committed state of every
map, canonicalised) + (per-instance `r0` / error) + (provider-visible context,
packet window, outputs, and redirect state). If two explored schedules
   yield **different** outcomes, the program is racy: the outcome depends on the
   interleaving. We report the two divergent outcomes and a witnessing
   interleaving for each.

2. **Lost-update anti-pattern (specific, named).** While executing a schedule
   we log per map-value **cell** (region) a stream of `(instance, access)`
   events where access ∈ {Read (value load), Write (value store / update /
   delete), AtomicRMW}. A **lost update** is flagged when, for some cell, an
   instance A does `Read`, another instance B does `Write`, and then A does
   `Write`, with no intervening `Read` by A and no `AtomicRMW` in A's span —
   i.e. A overwrote using a value it read before B's write. Atomic RMWs never
   produce this pattern (they are a single atomic event), so a correctly
   atomic counter is reported race-free.

A program is **RACE-FREE** when every explored schedule produces the identical
outcome and no lost-update pattern is seen.

## Schedule exploration

- **Systematic** (default, no `--seed`): DFS enumeration of all interleavings
  via a mixed-radix "odometer" over the per-decision fan-out. Each schedule is
  replayed from a freshly built `Vm` (cheap for the small programs this
  targets), so no state cloning is needed. Capped at `--schedules M` (default
  2000).
- **Seeded-random** (`--seed S`): `M` schedules, each driven by a
  deterministic xorshift seeded from `S` (mixed with the schedule index). For
  larger state spaces where full enumeration is intractable.
- **Single replay** (`--schedule CSV`): run exactly one interleaving given as a
  comma-separated choice vector, print its full trace and outcome. This is the
  reproducible "seed" we emit for a witnessed race.

## Reproducibility / replay

The whole run is a pure function of `(ordered programs, fixed per-instance
contexts, exploration choices)`. A witnessed racing interleaving is emitted as
its **choice vector**;
re-running `febpf race <prog> --procs N --schedule <vector>` replays that exact
interleaving bit-for-bit and prints the step-by-step trace. When `--seed` is
used, the report also prints the seed and the offending schedule's index so the
same command reproduces it. (Full `.febpf` replay-file integration is out of
scope for this feature; the choice-vector replay is the deterministic
reproduction path, and it points at the losing schedule reproducibly.)

For heterogeneous runs, preserve the ordered program set and call
`replay_programs` with the emitted vector. The single-file CLI cannot honestly
reconstruct several program images, so heterogeneous reports do not print a
misleading CLI reproduction command.

## Staged plan

- **(a)** Multi-instance harness sharing maps + single fixed-schedule runner
  (`interp::InstanceState`, `Machine::{activate,deactivate,run_to_mapop}`;
  `src/race.rs` executor for one given schedule).
- **(b)** Deterministic scheduler + interleaving exploration (systematic
  odometer + seeded-random).
- **(c)** Race detection: outcome-divergence + lost-update anti-pattern +
  divergence/trace reporting.
- **(d)** Reproducibility (`--schedule` replay, `--seed`) + CLI wiring +
  `--stats`, behavioral tests.

## Testing bar

- (i) a genuine lost-update RMW program (`lookup`, load, `+1`, `update`) run as
  2 instances is flagged **RACE** with a witnessing interleaving;
- (ii) the same counter done with an **atomic add** (`lock *(u64*)ptr += 1`) on
  the same key is **RACE-FREE** across all explored schedules;
- (iii) determinism: the same `--seed` (and the same `--schedule`) reproduces
  the identical racing interleaving bit-for-bit.
- (iv) distinct `+1` and `+10` workers expose a cross-program lost update,
  their atomic equivalents are race-free, and the heterogeneous choice vector
  replays exactly;
- (v) incompatible maps, unequal context lengths, and empty program sets are
  rejected.
- (vi) XDP frames remain instance-private while their packet bytes drive shared
  map races; packet mutations alone distinguish schedule outcomes even when
  maps and return values converge; incompatible frame capacities and invalid
  XDP programs are rejected.

Tests live in `tests/race.rs` and drive the library API (no TTY needed).
</content>
</invoke>
