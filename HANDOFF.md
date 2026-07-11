# febpf — handoff notes

_A note from past-me to future-me (or whoever picks this up). Read this before
diving in; it's the context that isn't obvious from the code._

## What this is

**febpf** is a from-scratch, **zero-dependency** userland eBPF engine in Rust.
It was built as a "fun challenge" for the user (ayourtch@gmail.com) starting
2026-07-10. It is not a wrapper around the kernel or any library — the ISA
decoder, verifier, interpreter, JIT, assembler, and ELF loader are all
hand-written. `Cargo.toml` has **no dependencies** and that is a deliberate,
load-bearing constraint. Don't add any without a very good reason and the
user's OK (raw Linux syscalls via `asm!` are used instead of libc — see the
JIT's `sys` module).

Everything works today: `cargo test` is 197 green (188 with
`--no-default-features`, i.e. no JIT), `cargo clippy --all-targets` is 0
warnings in both configs, release builds clean. **Keep BOTH configs green** —
the JIT is now behind `default = ["jit"]`, so always run `cargo test` AND
`cargo test --no-default-features` (and clippy in both) before calling
anything done.

**Nothing in flight.** `feat/map-types-2` (perf/cgroup/stack maps + core
tracing helpers) and `feat/probe-read-helpers` (probe_read family #4/#45/#112–115
+ current_task_under_cgroup #37, spec `docs/specs/tracing-helpers.md`) are both
finished and merged (2026-07-11). Corpus coverage after the two batches:
**loads 92.9%, verifies 67.9%** (38/56) — up from 30% / 5.4%. Zero map-type
blockers remain; the next work is named under "Known limitations" below.

## The big picture (data flow)

```
   source.s ──asm──┐                    ┌── disasm ──► pseudo-C text
                   ├─► Vec<Insn> ──┬─────┤── analysis ─► CFG/DOT/heatmap/annotated
 clang .o ──elf────┘  + Vec<MapDef>│     └── verifier ─► accept/reject + abstract state
                                   │
                                   ▼
                              Vm::new  (patches map lddw → region addrs into `exec`)
                                   │
                        ┌──────────┴───────────┐
                        ▼                      ▼
                   interpreter            JIT (x86-64)
                   Machine::step      native ALU/branch + trampoline
                        └──────────┬───────────┘   back to Machine::jit_step_at
                                   ▼                for memory/calls/exit
                             r0 / EbpfError
```

## Module map (src/)

| file | lines | what |
|------|-------|------|
| `insn.rs` | ISA v4 opcode constants, `Insn`, decode/encode, `wide_imm` |
| `asm.rs` | assembler for kernel "pseudo-C" syntax; `.map name kind key val entries` (kinds: hash/array/percpu_hash/percpu_array/lru_hash/ringbuf) |
| `disasm.rs` | disassembler (round-trips with asm) |
| `tnum.rs` | tracked-numbers (known-bits) abstract domain, mirrors kernel `tnum.c` |
| `verifier.rs` (2806) | the big one: path-sensitive abstract interpreter; rejection explainer; per-PC joined abstract state (`pc_regs`/`regs_at`) used by the optimizer |
| `maps.rs` (516) | hash/array + per-CPU array/hash + LRU hash + ringbuf; stable value storage (safety note #5); record capture for ringbuf |
| `helpers.rs` | helper id/name/signature registry + user-helper API |
| `interp.rs` (1455) | the VM: `Vm`, `Machine`, virtual-address memory model, snapshot/restore (time travel), multi-instance activate/deactivate (race), JIT glue |
| `jit/*` | arch-independent frontend + `JitBackend` trait + x86-64 encoder (aarch64 backend TODO) |
| `elf.rs` (1126) | ELF64 loader + BTF `.maps` + CO-RE relocation application; `map_kind`/`map_type_name` |
| `btf.rs` (1002) | full BTF type graph (all 19 kinds), scales to vmlinux; `.BTF.ext` |
| `relo.rs` (1401) | CO-RE relocation algorithm (libbpf candidate matching) |
| `debuginfo.rs` (356) | `.BTF.ext` line/func info → source-level debugging |
| `kbpf.rs` (382) | raw `bpf(2)` syscall layer (conftest/vfuzz); **attr MUST be `&mut`** |
| `fuzz.rs` (526) | seeded PRNG + program generators (conservative + verification-frontier) |
| `conftest.rs` (310) | `conftest`/`fuzz`/`vfuzz` CLI orchestration |
| `race.rs` (688) | deterministic concurrency race explorer (`febpf race`) |
| `equiv.rs` (463) | observable-equivalence checker (`febpf equiv`) |
| `optimize.rs` (648) | verifier-guided, equivalence-checked optimizer (`febpf optimize`) |
| `replay.rs` (534) | `.febpf` shareable replay-file container (record/replay) |
| `analysis.rs` | CFG, DOT export, stats, annotated listing, heatmap (source-aware) |
| `debug.rs` (1301) | debugger REPL: breakpoints, time travel (rstep/rcontinue/goto), watchpoints, dataflow queries (origin/when/who), source stepping |
| `playground.rs` (517) / `wasm.rs` (193) | pure-std playground API + hand-written WASM ABI (no wasm-bindgen) for `web/` |
| `main.rs` (850) | CLI |

Line counts are approximate (they drift); the point is the shape. Specs live
in `docs/specs/` — one per subsystem (jit-backend, elf-loading, core-relocations,
time-travel-debug, verifier-explainer, source-debug, conftest, verifier-diff,
wasm-playground, dataflow-queries, replay-files, equiv-optimizer, race-explorer,
map-types, corpus-tooling). **Read the relevant spec before extending a
subsystem** — they encode the contracts and gotchas.

## Load-bearing design decisions (the non-obvious stuff)

### 1. Virtual-address memory model — this is the whole safety story
eBPF pointers in the interpreter are **not host pointers**. They are
`region_handle << 32 | offset`. Every load/store goes through
`resolve_slice()` in `interp.rs`, which looks up the region (ctx / one stack
per frame / map object / map value) and does an O(1) bounds check. Result: even
`--no-verify` can't cause UB — a wild access is a clean `EbpfError`, never a
segfault. **Never** break this by putting a real pointer in a guest register.
The JIT preserves it by *deferring* all memory ops to the interpreter (see #4).

### 2. `Vm` keeps two instruction arrays: `insns` and `exec`
- `insns` = as loaded (map `lddw` pseudo-instructions intact). The **verifier**
  and disassembler see this.
- `exec` = map `lddw` patched to concrete region addresses. The **interpreter
  and JIT** run this.

Verifying the *patched* array silently breaks map-pointer typing. This bit me
during initial development; keep the split. (Same pattern: `user_helpers` and
`jit` are `Option`-taken out of `Vm` during a run to satisfy the borrow
checker — see `run_jit`.)

### 3. Verifier state pruning needs care or it blows up
DFS over branch states with subsumption pruning at join points
(`prune_points`). Two things that took debugging:
- `max_states_per_pc` default is **4096** (a ring buffer). A small cap breaks
  pruning under DFS and causes exponential blowup.
- There's a **miss-streak backoff**: after 256 consecutive non-pruning
  arrivals at a point, only scan every 64th. Without it, a loop that mints a
  fresh constant each iteration made the "program too complex" rejection take
  ~134s instead of ~2s. See `PruneList` in `verifier.rs`.

`MapValueOrNull` pointers carry a unique `id` so a null check refines **every**
copy of the pointer, including ones spilled to the stack.

### 4. The JIT is a hybrid, and that's what keeps it safe
Only **ALU + branches** are compiled to native code. Everything else — loads,
stores, atomics, `lddw`, helper calls, bpf-to-bpf calls, `exit` — is
**deferred**: the native code spills registers, calls `Machine::jit_step_at`
(the same interpreter, one instruction), and resumes at whatever pc it returns.
So the JIT cannot introduce memory-unsafety the interpreter doesn't already
prevent; it only removes dispatch overhead. ~45× on ALU-heavy loops.

The frontend (`jit/mod.rs`, `classify.rs`) is architecture-independent; the
backend (`x64.rs`) is a pure encoder implementing `JitBackend`. **To add
aarch64/riscv you implement that trait and nothing else** — the whole point of
the split, done at the user's request. `docs/specs/jit-backend.md` is the
step-by-step. Gotchas already written down there: instruction-cache flush on
ARM/RISC-V (x86 doesn't need it), literal pools for absolute addresses (no
`movabs`), and 16-byte stack alignment at call sites (this was the first JIT
segfault — I was pushing 6 callee-saved regs and misaligning; it's now 5).

### 5. `maps.rs` value storage is stable on purpose
Array maps use one flat allocation; hash maps use a slab of boxed values with a
free-list. Values are never moved while present, so a map-value pointer handed
to the program stays valid. Deleted hash entries are tombstoned/reused, never
freed — mirrors the kernel's RCU-grace-period semantics (a stale pointer reads
recycled memory, never unsafe).

### 6. Global data sections (added 2026-07-10, session 2)
`.data`/`.bss`/`.rodata*` sections load as **single-entry array maps**
(libbpf's internal-map model): `MapDef` gained `init: Vec<u8>` (section
contents, `.bss` zero-fills) and `readonly: bool` (`.rodata*` frozen).
Things that will bite you if you forget them:
- clang does NOT put everything in plain `.rodata`: const tables land in
  `.rodata.cst16` (SHF_MERGE) and string literals in `.rodata.str1.1`
  (SHF_MERGE|SHF_STRINGS). Match by `.rodata` **prefix**.
- Data relocations are section symbols (value 0) with the **addend stored in
  the lddw's imm field**; final value offset = `sym.value + imm`. Lowered to
  `pseudo::MAP_VALUE` (imm = map idx, second imm = offset) — the runtime
  patching for that already existed in `Vm::new`.
- read-only is enforced **three times deliberately**: verifier store path
  (`check_mem_access`), verifier helper check (update/delete on frozen map),
  and the runtime (`resolve_slice` takes `write: bool`). The runtime check is
  what keeps `--no-verify` and the JIT honest (JIT defers all memory ops).
- asm syntax grew `.map name kind key val entries [ro]` and
  `rX = map[name][0] + off` (direct value pointer) to make this testable
  without ELF fixtures.
- `Map::update/delete` on frozen maps return `-EPERM` (-1), like the kernel.

### 7. Determinism
`get_prandom_u32` is a fixed-seed xorshift; hash maps never move values. So a
buggy program replays identically under the debugger. Keep it that way.

## Toolchain notes for this environment
- `clang` (21.x) and `bpftool` **are installed**. `llvm-objdump` may not be on
  PATH (user installed it but it didn't show up last I checked — verify with
  `which llvm-objdump`).
- ELF tests (`tests/elf.rs`) recompile `examples/c/*.c` → `tests/*.o` when
  clang is present, else use the committed `.o` fixtures. If you change the C,
  regenerate: `clang -O2 -g -target bpf -c examples/c/X.c -o tests/X.o` (use
  `-O0` for `subprog.c` so the cross-`.text` call isn't inlined away).
- `Date.now()`/randomness are fine here (this is a normal shell, not a workflow
  sandbox). The scratchpad dir is session-specific — use whatever the current
  session's system prompt says.
- **Next session may be on the user's aarch64 Mac Mini** (they plan to check
  out the repo there for the arm64 JIT backend). Expect macOS: `mmap`/`mprotect`
  via raw syscalls differ (no `asm!` Linux syscall ABI — macOS needs libc or
  its own syscall numbers AND `MAP_JIT` + `pthread_jit_write_protect_np` for
  W^X), plus `sys_icache_invalidate` for i-cache flush. The `JitBackend` trait
  split means x64.rs stays untouched; budget real time for the exec-mem layer,
  not just the encoder.

## How to verify you haven't broken anything
```
cargo test                     # 62 tests
cargo clippy --all-targets     # must stay 0 warnings
cargo build --release
./target/release/febpf bench examples/sum_loop.s --iters 50000 --jit   # ~11 GIPS
./target/release/febpf run tests/../examples/... # etc
```
The **differential tests are the safety net**: `tests/jit.rs` and the
`jit_matches_interpreter_on_objects` test in `tests/elf.rs` run programs under
both interpreter and JIT and require identical results. If you touch codegen,
these catch encoding bugs. Add more programs to the `programs()` list in
`tests/jit.rs` when you add native opcodes.

## "Wow" feature shortlist (user asked for these — things people wish existed)

Ranked by wow-per-effort. Each builds on something we already have, which is
what makes them feasible here when they aren't elsewhere:

1. **Time-travel debugging** — **DONE 2026-07-11** (`docs/specs/time-travel-debug.md`):
   `rstep`/`rcontinue`/`goto` + data watchpoints (raw addr and logical map+key),
   10k-step checkpoints, snapshot must include region table + per-map region
   handles (lazy allocation order matters on replay). Warns once if
   non-deterministic helpers were called.
2. **Verifier rejection explainer** — **DONE 2026-07-11**
   (`docs/specs/verifier-explainer.md`): counterexample trace on rejection
   (annotated disasm of the failing path, per-step abstract state, cause notes
   like "r0 may be NULL: returned by map_lookup_elem at insn 6"). On by
   default, `--no-explain` to suppress. Path arena during DFS + replay on
   rejection; pruning machinery untouched.
3. **Source-level debugging** — **DONE 2026-07-11** (`docs/specs/source-debug.md`):
   `.BTF.ext` line/func info surfaced via `src/debuginfo.rs` (clang embeds the
   source text — no .c needed): debugger shows the C line, `list`,
   `steps`/`nexts`/`rsteps` (source-line stepping, incl. reverse), `bt`
   backtraces with function names, `print <global>` typed via the BTF graph;
   source interleaved into disasm/heatmap/analyze. Watch the `.text`-stitching
   offset (`text_base`) — same trap as CO-RE relocs.
4. **Kernel conformance mode** — **DONE 2026-07-11** (`docs/specs/conftest.md`):
   `febpf conftest` (interp+JIT+kernel via raw bpf(2), exit codes 0/1/2/3 =
   agree/mismatch/no-priv/kernel-reject) and `febpf fuzz [--seed N] [--kernel]`
   (seeded differential fuzzer; already caught a real generator bug).
   `src/kbpf.rs` attr offsets verified against kernel headers, and the full
   kernel differential validated as root on this host 2026-07-11 (10k fuzz
   programs + gated tests all agree — after fixing a real harness miscompile:
   the TEST_RUN retval write-back needs the attr passed as `&mut`, see
   `kbpf::call`).
5. **WASM playground** — **DONE 2026-07-11** (`docs/specs/wasm-playground.md`):
   JIT now behind `default = ["jit"]` feature (keep BOTH configs green:
   `cargo test` and `cargo test --no-default-features`). `src/playground.rs`
   (pure-std API) + `src/wasm.rs` (hand-written ABI, no wasm-bindgen) +
   `web/`: `cd web && make` → self-contained `web/dist/` for any static
   server. Verified without a browser via wasmi harness (`web/test/`).
6. **CO-RE relocations** — **DONE 2026-07-11** (`docs/specs/core-relocations.md`):
   full BTF type graph in `src/btf.rs` (all 19 kinds, validated byte-exact
   against `bpftool btf dump` on vmlinux, 168k types ~56ms), `.BTF.ext`
   parsing (core_relo semantic; func/line_info stored for future #3), the
   libbpf matching algorithm in `src/relo.rs` (13 relo kinds, flavors,
   ambiguity rules), load-time patching with libbpf-style `0xbad2310`
   poisoning of unresolved relos. CLI: `--target-btf <path>`, defaults to
   /sys/kernel/btf/vmlinux. Differentially validated against bpftool and the
   running kernel.

### Second wow tier (all DONE 2026-07-11) — built on the deterministic replay + kbpf

7. **Omniscient debugging (dataflow queries)** — `docs/specs/dataflow-queries.md`.
   Debugger commands `origin <reg>` (recursive def-use trail to where a value
   was born: constant/ctx/map-load/helper-return), `when <reg>`, `whenwrite
   <addr|reg>` (alias `ww`), `who <addr|reg>`. No eager recording: rebuilds a
   lightweight write-log on demand by restoring the nearest checkpoint and
   replaying to the cursor (`DebugSession::build_write_log` +
   `Machine::describe_addr`). Bounded to one replay interval — defs older than
   the nearest checkpoint report "not written in this interval" (next step:
   cross-interval `origin`). Atomic-STX destinations not yet followed.
8. **Shareable replay files** — `docs/specs/replay-files.md`. `febpf record
   <prog> [--stop-at N] -o bug.febpf` + `febpf replay bug.febpf` (opens the
   time-travel debugger at the cursor, or `--run` reproduces r0). Versioned
   hand-written container (`src/replay.rs`, magic `FEBPFRPL`, no serde);
   determinism guard records expected r0 and warns on divergence. `from_bytes`
   grows vecs per bounds-checked element — do NOT reintroduce
   `Vec::with_capacity(untrusted_count)` (that was a real multi-GB-alloc DoS
   the corruption fuzz test caught). Playground/WASM entry `febpf_dbg_replay`
   opens a `.febpf` in the browser.
9. **Verifier differential fuzzing** — `docs/specs/verifier-diff.md`. `febpf
   vfuzz [--frontier|--conservative] [--kernel]` diffs febpf-verifier vs
   kernel-verifier *verdicts* (not just execution). Four cells; the
   **FEBPF-LAX** cell (febpf accepts / kernel rejects = a soundness gap) is
   dumped loud + first with disasm + kernel log. FEBPF-STRICT (kernel stricter)
   is expected in bulk, reported separately. New bpf(2) surface `kbpf::verdict`
   keeps the `&mut` attr provenance. Root run against a live kernel
   (2026-07-11) initially found 2407/20000 FEBPF-LAX in two classes, both now
   FIXED (see below) — a re-run is 0 FEBPF-LAX / 0 FEBPF-STRICT, i.e. febpf's
   verifier verdict matches the kernel's on every one of 20k frontier
   programs. `vfuzz --kernel` is the regression check; keep it at 0 LAX.

### Verifier hardened to kernel conformance (2026-07-11, via #9)
`fix/verifier-conformance` closed the two gaps vfuzz found — both were febpf
being *more permissive* than the kernel (conformance gaps, not memory-unsafety,
since febpf's virtual-address model is safe regardless):
- **Modified ctx-ptr deref**: the kernel requires a `PTR_TO_CTX`'s own
  accumulated offset to be 0 at dereference — the access offset must come from
  the load/store instruction immediate, never from pointer arithmetic baked
  into the register. `check_mem_access` now rejects a ctx deref when the
  pointer's `p.off != 0` or `p.var` is non-zero/non-const (keying on the
  POINTER's offset, NOT the total access offset — that distinction is what
  keeps `*(u32*)(r1+8)` legal while rejecting `r2=r1; r2+=8; *(u32*)(r2+0)`).
- **Stack alignment**: the kernel *always* enforces natural alignment on
  `PTR_TO_STACK` accesses (size-N access must be N-aligned), independent of the
  `--strict-align` policy that governs ctx/map/packet. febpf now enforces stack
  alignment unconditionally; the helper-buffer path is exempted (helper args
  pass a byte length as `size` with no alignment constraint).

### Third wow tier (2026-07-11) — built on deterministic replay + the verifier

10. **Omniscient debugging (dataflow queries)** — `docs/specs/dataflow-queries.md`.
    Debugger `origin <reg>` (def-use trail to where a value was born), `when`,
    `whenwrite`/`ww`, `who <addr>`. Rebuilds a bounded write-log on demand from
    the nearest checkpoint (no eager recording). Limited to one replay interval.
11. **Shareable replay files** — `docs/specs/replay-files.md`. `febpf record ->
    bug.febpf`, `febpf replay` (opens the time-travel debugger at the cursor, or
    `--run`). See `src/replay.rs` DoS note above.
12. **Verifier differential fuzzing (vfuzz)** — see #9 / verifier-conformance.
13. **Deterministic race explorer** — `docs/specs/race-explorer.md`. `febpf race
    <prog> --procs N` runs N instances sharing one map set, enumerates
    interleavings at map-op granularity, flags lost-update / stale-RMW /
    outcome-divergence, and emits the losing interleaving as a replayable
    `--schedule` vector. Also in the web playground (`febpf_race`, its own panel).
14. **Verified performance optimizer** — `docs/specs/equiv-optimizer.md`. `febpf
    equiv <a> <b>` decides *observable* equivalence (r0 + final map state +
    ordered helper effects — NOT just r0), via the verifier's joined per-PC
    abstract state plus differential falsification. `febpf optimize` applies
    verifier-gated sound rewrites (const-fold, dead-branch, strength-reduction,
    algebraic identity, redundant-mask), then runs `equiv` on its own output and
    REFUSES to emit if it can't prove behavior was preserved.

### Production coverage — the corpus-driven loop (START HERE for "is it useful?")
`scripts/fetch-corpus.sh` (gentle, pinned, cached) builds ~56 real `.bpf.o`
from bcc libbpf-tools + libbpf-bootstrap using local clang + bpftool + kernel
BTF. `scripts/scan-corpus.sh` runs febpf over them and prints a ranked
histogram of the exact map types / helpers blocking the most real programs.
`corpus/` is gitignored. This is how we pick what to build next — MEASURE, don't
guess (it already corrected a wrong guess: ringbuf mattered less than
PERF_EVENT_ARRAY for this corpus). Coverage progression (loads / verifies):
- baseline (hash+array only): 23% / 3.6%
- + ringbuf/per-CPU/LRU (`docs/specs/map-types.md`): 30% / 5.4%
- + perf/cgroup/stack maps + tracing helpers (`map-types-2.md`): 92.9% / 30.4%
- + probe_read family + task_under_cgroup (`tracing-helpers.md`): 92.9% / **67.9%**
**Workflow: merge a coverage batch → `./scripts/scan-corpus.sh` → the histogram
names the next batch.** febpf is an analysis/test/CI/debug engine, NOT a datapath
runtime — "production useful" means verify/explain/differential-test/debug real
programs, not attach-and-run in the kernel.

Two gotchas learned running this loop (2026-07-11): the scan uses
`target/release/febpf`, so `cargo build --release` BEFORE scanning or you
measure the previous build; and helper names in the histogram come from the
uapi header now — the old hardcoded table had wrong ids (#113 was labelled
ringbuf_output; it is probe_read_kernel).

What blocks the remaining 18 objects (ranked by count, from the per-object
detail in `corpus/coverage-report.txt`):
1. **13 × VERIFY-REJECT:other, two root causes.** (a) "unreachable
   instruction": libbpf performs dead-code elimination using frozen `.rodata`
   config values before the kernel ever sees the program; febpf verifies the
   object as-is, so `if (cfg_flag)` branches over unloaded code trip the
   unreachable check. Fix = a load-time rodata-driven branch-elimination pass
   (mirror libbpf's). (b) scalar-deref like `r1 = *(u32*)(r6+2804)` where r6
   came from a `tp_btf` ctx load: real kernels type that as PTR_TO_BTF_ID and
   allow direct kernel-memory reads. Fix = model BTF-typed ctx pointers
   (bigger; verifier + a deterministic "kernel memory reads as zero" story).
2. **3 × LOAD-FAIL:relocation + 1 LOAD-FAIL:other** — CO-RE edge cases worth a
   look (`biosnoop`, `bitesize`, `capable`, `cpudist`).
3. **1 × helper #67 get_stack** (biostacks) — easy: same model as get_stackid
   but writes the stack into a caller buffer.

## Known limitations / where to go next (roughly prioritized)

1. **Real-world map/helper coverage** — the corpus loop above is the active
   thrust. After `feat/map-types-2`, the next histogram picks the batch. Still
   missing: PROG_ARRAY/tail-calls, maps-of-maps, SK/TASK/INODE_STORAGE, LPM_TRIE,
   sock/dev/xsk maps; the `probe_read` family and most of the ~200 helpers;
   program-type-specific ctx (esp. XDP/TC **direct packet access** with
   data/data_end — the biggest verifier-side gap).
2. **aarch64 JIT backend** — the trait is ready, spec is written. The user wants
   it; needs the macOS/arm64 exec-mem layer (see toolchain notes). Then riscv64.
3. **Verifier depth** — dynptr, spin locks, bpf_loop/iterators, packet bounds.
   `vfuzz --kernel` (keep at 0 FEBPF-LAX) is the conformance regression check.
4. **ELF gaps** — `R_BPF_64_ABS*`, static linking of multiple objects.
5. **kfuncs**, legacy packet-access (`ld_abs`/`ld_ind`) — deliberately
   unsupported; add only if a real program needs them.

## Working style the user likes
- They're hands-on and technical (wrote the "fun challenge" framing, asked for
  the aarch64-ready abstraction and the design docs proactively). Give real
  engineering, not hand-holding.
- They asked me to **commit as I go** and to write specs so a future model
  could extend cleanly. Keep doing both.
- Differential/behavioral testing over assertions-about-code. When I built the
  JIT I validated against the interpreter; when I built the ELF loader I
  validated against real clang + bpftool. Match that bar.

— past-me, 2026-07-10
