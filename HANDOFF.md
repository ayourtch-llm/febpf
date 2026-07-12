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

Everything works today: the full default-feature suite is **328 green + 4
intentional heavy soundness sweeps ignored**; `--no-default-features` is **314
green + the same 4 ignored** (2026-07-12, after map-in-map support).
`cargo clippy --all-targets -- -D warnings` is clean in both configs. **Keep
BOTH configs green** — the JIT is now behind `default = ["jit"]`, so always
run `cargo test` AND
`cargo test --no-default-features` (and clippy in both) before calling
anything done.

## LATEST (2026-07-12): the current pinned real-world corpus is 57/57

**START HERE.** The immediate goal is real-world breadth: support the eBPF code
people actually run before spending time on esoterica. The current gentle,
pinned corpus is **57/57 loaded and 57/57 verified**, including a static
tail-call graph and `ARRAY_OF_MAPS`. That is 100% of this corpus, **not a claim
that febpf supports 100% of all eBPF in the wild**. The next useful move is to
widen the pinned corpus with another representative production project or
feature lane, scan it, and implement the highest-impact measured blocker. Keep
program graphs visible as graphs in the report rather than flattening them
into misleading object counts.

**DONE (2026-07-12): real-world program graphs / tail calls.**
`docs/specs/tail-calls.md` is the contract. The userspace-populated path is
implemented: `MapKind::ProgArray`, helper #12 verifier rules, independently
verified targets sharing maps, interpreter hit/miss/cycle/33-chain semantics,
snapshot/debugger program identity, optional v1 replay bundle section, hybrid
JIT-to-JIT dispatch, and `kbpf::KernelProgram::link_tail_call` for real
program-fd population plus a privilege-gated differential. Static BTF `.maps`
`values[]` relocations now produce automatic multi-program ELF/CLI bundles;
interpreter, JIT, analyze, record/replay, and conftest consume them. The pinned
corpus includes Cilium v0.21.0's sparse program-array loader fixture and the
scanner reports program graphs separately. The static ELF regression passed
against the real kernel as root: the entry and target loaded, the program fd
populated the real program array, and `BPF_PROG_TEST_RUN` returned 42. The
complete upstream Cilium object also contains `ARRAY_OF_MAPS`; that next
measured blocker is now implemented too (see below).

**DONE (2026-07-12): `ARRAY_OF_MAPS`, selected by the corpus.**
`docs/specs/map-in-map.md` is the contract. Map definitions carry an explicit
inner-map template and sparse map identities; outer lookup produces a nullable
typed map pointer, and verifier null refinement turns it into the template map
type for nested helper calls. Static BTF `values[]` relocations, dependency-
ordered kernel creation with `inner_map_fd`, userspace population, snapshots,
replay v1 optional tag `0x0b`, interpreter, and JIT are covered. Root kernel
differentials passed both nested lookup and the combined static ELF fixture.
The unchanged pinned Cilium v0.21.0 `testdata/btf_map_init.c` now loads,
verifies, and returns 42 under interpreter and JIT; its focused corpus scan is
100% loaded/verified and reports one static tail-call graph.

**DONE (2026-07-12): scalar identity closes the refreshed corpus.**
`docs/specs/scalar-identity.md` records the soundness invariants. BCC `ksnoop`
copies a derived size, masks and bounds-checks one copy, then applies the same
mask to the original before `perf_event_output`. Register/spill equality ids
and interned deterministic expression ids now propagate that proof without
weakening helper bounds. A mismatched-mask regression remains rejected. The
refreshed cached corpus is **57/57 loaded and 57/57 verified (100%)**, with no
unsupported map types, unknown helpers, load failures, or verifier rejections.
The current host kernel rejects a minimal version of this safe pattern after
dropping the id at the first mask; febpf's acceptance is a deliberate,
soundly-tested precision extension, not kernel-verdict parity.
The complete root conformance suite remains green: 500 accepted-program
runtime differentials and 1,000 verifier-frontier verdicts agree with the
kernel, alongside the XDP, tail-call, and map-in-map differentials.

This is the current tip and the context a fresh agent is most likely to need.
The work is committed linearly on `main`:

```
2b4f739 verifier: track scalar expression identities
a63e66e maps: support static array-of-maps
8e8978e tests: cover tail-call graphs in JIT
5271ebd docs: record kernel tail-call validation
3f35b5a tailcall: load static ELF program graphs
b32fe13 tailcall: add verified program bundles
261e156 tests: make fixture regeneration explicit
3061e49 xdp: differential test-run against kernel
```

To choose the next production-coverage batch, first build the binary the scan
actually uses, then rescan the existing cache:

```
cargo build --release
./scripts/fetch-corpus.sh --offline
NO_BUILD=1 FEBPF=target/release/febpf ./scripts/scan-corpus.sh
```

When widening the corpus, pin tags/commits, keep fetching shallow and gentle,
and document the new lane and its blockers in `docs/specs/corpus-tooling.md`.
Do not add a dependency to solve corpus tooling or core-engine work without the
user's explicit OK.

The old Claude worktree `.claude/worktrees/agent-aee527c2832b79ec3` was
successfully rescued: its two commits were rebased onto `main`, validated, and
integrated. Its branch still points at `426ea87`; it is no longer ahead of
`main` and contains no unique work.

### Exhaustive verifier-operator soundness (DONE)

`src/soundness.rs` runs the production 64-bit tnum/scalar/branch operators on
exhaustively enumerable small windows placed at low, u64 top, i64/i32 sign,
and u32 truncation boundaries. The exact obligation and inventory are in
`docs/specs/operator-soundness.md`. Default tests stay fast; four larger w=8/
w=4 sweeps are ignored and run with:

```
cargo test --release -- --ignored soundness
```

The first run found and fixed three real bugs, each with program-level
regressions in `tests/integration.rs`: signed JMP32 decisions/refinement were
using zero-extended bounds, ALU32 signed div/mod constant folding used i64
semantics, and `Scalar::sync()` was not idempotent. `sync()` now reaches a
fixpoint; signed JMP32 uses a sign-extended view and maps refinement back.

### XDP verifier model (DONE, first useful slice)

Read `docs/specs/xdp-packet-access.md` before extending this. `Config::xdp`
turns `r1` into a read-only `struct xdp_md` context: u32 loads at offset 0/4
produce `PtrKind::Packet { range }` and `PtrKind::PacketEnd`. Packet pointers
start with range 0. Unsigned relational comparisons against data_end refine
the safe successor with the exact proven prefix; the proof propagates through
register aliases and stack spills. Loads/stores must fit entirely in that
prefix. Inclusive/strict forms and both operand orders are handled.

Runtime packet bytes live in a dedicated `Region::Packet` using the normal
`handle << 32 | offset` safety model. Never put host packet pointers in guest
registers. Because the kernel ABI exposes `xdp_md.data`/`data_end` as u32 but
febpf handles are 64-bit, verified XDP ctx loads synthesize the full virtual
addresses at the interpreter load boundary. `Vm::prepare_xdp()` installs a
packet for debugger/replay use; `Vm::run_xdp(&mut packet)` runs it and copies
packet writes back. Packet backing is included in `Snapshot`, so reverse
execution rewinds packet writes as well as ctx/maps/stack.

Known limitation: XDP execution is interpreter-only. The CLI rejects
`--jit` clearly; JIT support needs the XDP ctx-load synthesis represented in
the JIT path. This is a performance limitation, not a verifier/runtime gap.

### ELF, raw packet and pcap CLI (DONE)

`LoadedProgram::xdp` recognizes entry sections named exactly `xdp` or
`xdp/*`; the CLI automatically verifies them with XDP rules. `--packet` also
selects XDP for assembler/raw programs. Examples:

```
febpf verify program.bpf.o
febpf run --packet frame.bin program.bpf.o
febpf run --pcap traffic.pcap program.bpf.o
```

`src/pcap.rs` is a zero-dependency classic-pcap parser: both byte orders,
micro/nanosecond timestamp magics, strict truncation/snaplen checks, explicit
pcapng rejection. One VM is reused across capture records so maps persist.
The CLI prints packet index/timestamp/length and named XDP verdicts
ABORTED/DROP/PASS/TX/REDIRECT. The parser is pure slice code and therefore
WASM-friendly.

### Packet `.febpf` replay and time-travel debugging (DONE)

Replay format version stays **1**: the sectioned format already promises
unknown-tag skipping, so optional tag `0x09 PACKET` was added compatibly.
Presence selects XDP verification/execution; CTX remains the synthetic
24-byte xdp_md image. Existing v1 files without PACKET round-trip unchanged.
Native CLI and playground/WASM replay both reconstruct the packet region.

```
febpf record program.bpf.o --packet frame.bin --stop-at 20 -o packet.febpf
febpf record program.bpf.o --pcap traffic.pcap --packet-index 37 \
  --stop-at 20 -o packet.febpf
febpf replay packet.febpf --run   # reproduce verdict + determinism guard
febpf replay packet.febpf         # open at cursor in time-travel debugger
```

`Replay::record_xdp`, `Replay::build_vm`, `playground::Session::from_replay`,
and `Vm::prepare_xdp` are the load-bearing chain. Tests cover binary
round-trip, reproduced r0, native replay CLI manually, and browser/playground
debugger continuation on the recorded packet.

### Parked web direction: “Wireshark + eBPF”, possibly using oside

The user likes a browser packet workbench: upload XDP `.bpf.o` + pcap, table
of packets/verdicts, protocol tree + hex view, click a packet to time-travel
debug it, export `.febpf`. This is a strong next product/demo direction, but
was explicitly **parked for a second** after investigation.

Candidate decoder: https://github.com/ayourtch/oside (Apache-2.0, same
author), a Scapy-inspired Rust layer stack with Ethernet/VLAN/ARP/IPv4/IPv6/
TCP/UDP/ICMP/DNS/DHCP/GRE/VXLAN/Geneve/etc and Serde-friendly layer output.
Do **not** add current oside directly to febpf core: its Cargo.toml has many
unconditional dependencies (`serde`/`typetag`, `linkme`, rand, host MAC,
crypto/SNMP, tracing...), likely WASM friction, and would violate febpf's
zero-dependency load-bearing constraint. Preferred future shape: refactor
oside upstream into a small decode-only/WASM-friendly feature or crate, then
consume it only in a web companion layer. Especially valuable API addition:
decoded fields should carry byte ranges, enabling protocol-field ⇄ hex bytes
⇄ eBPF load/instruction/branch provenance. Keep febpf and oside separate at
the library boundary.

**DONE (2026-07-11, session 7): aarch64 Linux JIT + CI on all three
platforms.** `.github/workflows/ci.yml` runs the suite, both feature configs,
clippy `-D warnings`, and a **1M-program differential fuzz** (~5s) on
`ubuntu-latest`, `ubuntu-24.04-arm` and `macos-latest`. This matters more than
usual CI: the JIT is the only part of febpf that isn't portable Rust, and each
runner *executes machine code generated for that exact CPU* — a bad encoding
surfaces as a wrong answer, not a compile error. It also finally gives the
**x86-64 backend real execution coverage**, which sessions 5-6 could not (all
that work was done on an arm64 Mac).

- **aarch64 Linux** is now a JIT platform. The A64 encoder was already
  OS-independent, so this was purely an exec-memory layer: `mod.rs` now has one
  module per platform (`x86_linux` / `arm_linux` / `arm_macos`), each exposing
  `alloc_rw` / `seal_rx` / `free`. Watch out for two things — the aarch64
  syscall numbers are *not* x86-64's (mmap=222, mprotect=226, munmap=215), and
  Linux gives you no `sys_icache_invalidate`, so the i-cache flush is written
  out by hand (`DC CVAU` / `DSB ISH` / `IC IVAU` / `DSB ISH` / `ISB`, line
  sizes from `CTR_EL0`).
- **The repo is now clippy-clean under `-D warnings` on every target**, which
  it was not: `kbpf.rs`'s UAPI constants are used only by the x86-64-Linux
  syscall path and read as dead code everywhere else (now gated together in a
  `uapi` module), and the stub `Fd` had no `Drop`, so `drop(fd)` tripped a lint
  off-Linux. Without those fixes CI could not have enforced `-D warnings`, and
  a warning gate nobody can turn on is worthless.
- **CI checks the fixtures survive** (`git diff --diff-filter=D -- tests/`) —
  the regression that destroyed them in session 5 would now fail the build.
  Note Linux CI *explicitly regenerates* the `.o` files with
  `FEBPF_REGENERATE_FIXTURES=1` (its clang can target BPF) while macOS consumes
  them read-only, so only deletions are an error on Linux; on macOS nothing may
  change at all. Both paths get covered, which is why the matrix is worth having.
- No benchmark *gate* — CI runners are far too noisy for timing assertions, so
  `bench` runs informationally only.

**DONE (2026-07-11, session 6): shrank the JIT's trampoline tax ~60%** — the
work §4 flagged as highest-value. Memory-heavy programs went from **0.96×
(slower than the interpreter!) to 1.22×**, and the store+load loop from 1.29×
to 1.60×; pure-ALU is unchanged (~25×). Three parts:
1. **Spill/reload masks** (`classify::deferred_regs`): the glue now moves only
   the registers the interpreter reads/writes. Derived arm-by-arm from
   `Machine::step` — *the interpreter is the spec here*. Two traps the ISA doc
   won't tell you: a helper call **scrubs r1–r5 to zero** (so they must be
   reloaded even though it "only writes r0"), and **`cmpxchg` reads and writes
   r0 implicitly** though r0 is in neither operand field. Unenumerated forms
   fall back to all-registers, i.e. to the old behaviour.
2. **aarch64 register remap**, and this is the load-bearing bit: masks are
   worthless unless the eBPF registers sit in *callee-saved* physical
   registers, or the call destroys them anyway. Session 5's identity map
   (r0..r10 → x0..x10) was exactly wrong for this. Now r0..r9 → **x19..x28**;
   r10 is memory-backed (AAPCS64 has 10 callee-saved regs and eBPF has 11 —
   r10 is read-only, so it is the one to give up).
3. **Fall-through**: loads/stores/atomics/deferred-ALU can only resume at the
   next instruction, so the glue skips the pc→address table lookup and its
   indirect branch. Only CALL/EXIT/`gotol` still need it.

Also fixed, found while doing this: the pc→address table had `n` entries but
the interpreter can legitimately return `pc == n` (a program whose last
instruction is a store or helper call, runnable via `--no-verify --jit`) — the
glue indexed one past the end and branched to whatever it read. **That was a
memory-safety hole in the one component whose whole premise is memory safety.**
The table now has `n + 1` entries, the last pointing at the epilogue.

⚠️ **The x86-64 backend changes were compile-checked, not executed** — sessions
5-6 were done on an arm64 Mac with no x86 machine or container available. The
delta adds *no new byte encodings* (it only omits emissions), and the shared
masks — the genuinely risky part — were validated by 100k differential programs
on aarch64. **Session 7's CI closes this**: `ubuntu-latest` now runs the suite
and a 1M-program fuzz against the real x86-64 backend. If that job is green,
this caveat is discharged; if it is red, look here first.

Validation: `fuzz::gen_mem_program` is new and exists because **`gen_program`
is memory-free** — it emits no deferred instructions at all, so the old 100k-
program fuzz run could not have caught a bad mask. The new generator drives
loads/stores at every width, atomics (incl. `cmpxchg`), helper calls, deferred
ALU and the native `rX = r10` read; `febpf fuzz` alternates both. Note a
differential generator may only call helpers that are deterministic in both
engines — **not `ktime_get_ns`**, which reads the wall clock.

**DONE (2026-07-11, session 5): aarch64 JIT backend** (`src/jit/aarch64.rs`)
— the JIT now runs natively on Apple Silicon, not just x86-64 Linux. The
frontend was genuinely drop-in: the *only* changes outside the new file were a
`#[cfg] mod`, a `compile()` branch, and the `ExecMem` half. Read §5 of
`docs/specs/jit-backend.md` before touching it — it now records what was
actually done (and where the spec's original suggestions were wrong).

Three things worth knowing:
- **Apple Silicon is not "ARM Linux".** Strict W^X means the Linux
  mmap+mprotect dance does not work at all: code must be `MAP_JIT`, writes are
  gated *per-thread* by `pthread_jit_write_protect_np`, and the i-cache must be
  flushed (`sys_icache_invalidate`) or you execute stale bytes. These come from
  libSystem (`macsys` in `jit/mod.rs`) — Darwin has no stable syscall ABI, so
  raw `asm!` syscalls are NOT an option here. This does not break the
  zero-dependency rule: every macOS process links libSystem anyway.
- ~~**eBPF r0..r10 → x0..x10, identity.** The spec suggested callee-saved
  `x19..x29`; that was unnecessary.~~ **This was wrong — session 6 reversed
  it.** The reasoning ("the glue spills/reloads all 11 anyway, so nothing live
  crosses a call") was true but backwards: putting the eBPF registers in
  caller-saved regs is what *forces* the full spill/reload. r0..r9 now live in
  callee-saved x19..x28. The spec was right the first time.
- **`JitBackend::resolve_branches` now returns `Result`** (x64 updated too).
  A64's `B.cond` reaches only ±1MiB, so a program over ~1MiB of emitted code
  can't be encoded; it now fails compilation cleanly (caller falls back to the
  interpreter) instead of panicking or, worse, truncating a displacement into a
  silently-wrong branch. Branch islands would lift the limit — nothing in the
  corpus is remotely close, so it's not worth doing yet.

Validated by the `tests/jit.rs` differential suite plus `febpf fuzz` — **100k
random programs, interpreter and JIT agree on every one** (the generator covers
every native emitter in both widths, reg+imm, all 10 conditions and JSET, so
that is real coverage). Perf on M-series: **~26× on an ALU-heavy loop**
(`sum_loop`: 7.0µs → 0.27µs/run; 425 → 11100 M insn/s) — but see §4, the JIT
*loses* on deferred-heavy code, which is worth understanding before optimizing
anything.

**Two latent macOS bugs fell out of this and are fixed** (both were invisible
on Linux, and both would have bitten anyone who ran the suite on a Mac):
1. **`maybe_compile` in the fixture tests was destroying the repo.** It checked
   only that `clang --version` runs, then invoked `clang -target bpf -o
   tests/X.o`. Apple clang has no BPF backend, so it failed *after* truncating
   the output — silently deleting 10 committed `.o` fixtures on every
   `cargo test`, which then cascaded into ~30 failures that looked
   environmental. It now probes `--print-targets` for real BPF support and
   builds via a temp file that is renamed into place only on success, so a
   failing clang can never damage a fixture. Follow-up: ordinary tests no
   longer invoke it at all. The four copies were consolidated in
   `tests/common/mod.rs`, gated by `FEBPF_REGENERATE_FIXTURES=1`.
2. **`kbpf::has_privilege()` returned `Err` on any non-Linux host.** The stub
   `probe()` reports ENOSYS, and only EPERM/EACCES were mapped to `Ok(false)`
   — so the probe violated the "never panics, always a definite answer"
   contract that `probe_is_well_behaved` asserts. ENOSYS ("no `bpf(2)` on this
   platform at all") is now also a definite `Ok(false)`.

With those fixed, **macOS is at full parity: `cargo test` is 250 green / 240
with `--no-default-features`** — the same counts as the Linux box. Note clippy
on macOS shows 18 dead-code warnings in `kbpf.rs` (the Linux-only `imp` module
is `#[cfg]`'d out, so its constants look unused); that is a platform artifact,
not a regression — it is still 0 on Linux.

**DONE (2026-07-11, session 4): BTF-typed ctx pointers** (kernel
PTR_TO_BTF_ID for `tp_btf`/`fentry`/`fexit`/`fmod_ret` ctx args) — the last
fixable corpus class. `docs/specs/btf-ctx-pointers.md` is the contract; every
rule cites the kernel function it mirrors (`btf_ctx_access`,
`btf_struct_walk`, `check_ptr_to_btf_access`, `convert_ctx_accesses`'
BPF_PROBE_MEM rewrite → `VerifyOk::probe_mem` arms the VM). Runtime adds
`Region::KernelMem` (reads-as-zero, writes fault — virtual-address model
intact), ctx pointer slots prefilled with distinct deterministic addresses.
`Program` gained a `btf_ctx` field (literal constructions everywhere gained
`btf_ctx: None`). Corpus: **100% loads / 98.2% verified (55/56)** — and the
four unblocked tp_btf tools also EXECUTE under interp+JIT. The in-flight
agent from the last checkpoint had died leaving only the btf.rs foundation
uncommitted; it was salvaged, finished, reviewed and committed on main.
Known deliberate divergences + replay-file limitation are in the spec §1/§3.

**CURRENT NEXT OPTIONS:** exhaustive small-width operator soundness, the first
XDP packet-access/pcap/replay slices, and kernel `BPF_PROG_TEST_RUN`
differential validation are DONE (see LATEST above). The kernel is only an
oracle: `conftest --packet` compares both verifier verdicts, then the verdict
and exact output bytes. The user explicitly parked the oside-backed web packet
workbench for now. Good next technical continuations are: XDP JIT ctx-load
support; or another ranked item
from `docs/ideas.md` (extension-mechanism packaging, CI/LSP packaging,
`snapshot-kernel`). Do not silently start the oside integration until the user
unparks it. GPUs remain parked.

Merged earlier (sessions 1–3, all on main): map-types-2 (perf/cgroup/stack
maps, tracing helpers #14–16/#35, get_stackid #27), probe_read family
(#4/#45/#112–115) + task_under_cgroup #37, get_stack #67, kconfig externs,
max_entries default, subprog pointer returns (kernel-exact:
`prepare_func_exit`), rodata DCE (`src/dce.rs`), get_socket_cookie #46 +
get_func_ip #173, scan-corpus helper-name fix.

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
                   interpreter        JIT (x86-64 / aarch64)
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
| `verifier.rs` | the big one: path-sensitive abstract interpreter; rejection explainer; XDP packet/data_end range tracking; per-PC joined abstract state (`pc_regs`/`regs_at`) used by the optimizer |
| `maps.rs` (516) | hash/array + per-CPU array/hash + LRU hash + ringbuf; stable value storage (safety note #5); record capture for ringbuf |
| `helpers.rs` | helper id/name/signature registry + user-helper API |
| `interp.rs` | the VM: `Vm`, `Machine`, virtual-address memory model (including `Region::Packet`), snapshot/restore, multi-instance activate/deactivate, JIT glue |
| `jit/*` | arch-independent frontend + `JitBackend` trait + x86-64 and aarch64 encoders (riscv64 TODO) |
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
| `replay.rs` | `.febpf` shareable replay-file container, including optional XDP PACKET input |
| `pcap.rs` | zero-dependency classic-pcap parser used by the XDP verdict harness |
| `analysis.rs` | CFG, DOT export, stats, annotated listing, heatmap (source-aware) |
| `debug.rs` (1301) | debugger REPL: breakpoints, time travel (rstep/rcontinue/goto), watchpoints, dataflow queries (origin/when/who), source stepping |
| `playground.rs` (517) / `wasm.rs` (193) | pure-std playground API + hand-written WASM ABI (no wasm-bindgen) for `web/` |
| `main.rs` (850) | CLI |

Line counts are approximate (they drift); the point is the shape. Specs live
in `docs/specs/` — one per subsystem (jit-backend, elf-loading, core-relocations,
time-travel-debug, verifier-explainer, source-debug, conftest, verifier-diff,
wasm-playground, dataflow-queries, replay-files, equiv-optimizer, race-explorer,
map-types, corpus-tooling, btf-ctx-pointers). **Read the relevant spec before extending a
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
prevent; it only removes dispatch overhead.

**The hybrid still has a performance gradient — know it before you "optimize"
the JIT.** Every deferred instruction pays a trampoline round-trip, so the win
tracks the **fraction of executed instructions that are deferred** (M-series,
aarch64; x86-64 differs in magnitude, not in shape):

| executed instruction | cost under interp | cost under JIT |
|---|---|---|
| native (ALU/branch)  | ~2–4 ns | **~0.12 ns** |
| deferred (mem/call)  | ~4.3 ns | **~5.3 ns** (was ~6.7) |

- ~0% deferred (`sum_loop`): **~25× faster**
- ~40% deferred (store+load loop): **1.6×** (was 1.29×)
- ~67% deferred (memory-saturated): **1.22×** (was 0.96× — the JIT *lost*)

Session 6 cut the tax ~60% (details below), moving break-even from ~40-50%
deferred to **~80%**, so realistic map/packet-heavy programs now sit
comfortably in the winning region. It is no longer easy to construct a program
where `--jit` loses, but a pathological one (nearly all memory ops) would still
only break even — the trampoline cannot be cheaper than the interpreter's own
dispatch of the same instruction.

What made it faster, and what is left:
- **Spill/reload masks** (`classify::deferred_regs`): move only the registers
  the interpreter actually reads/writes, not all 11. This *only pays off if the
  eBPF registers live in callee-saved physical registers* — otherwise the call
  destroys them anyway. That is why aarch64 maps r0..r9 → x19..x28; x86-64 has
  too few callee-saved registers and must always carry r0..r5.
- **Fall-through**: a load/store/atomic/ALU can only continue at the next
  instruction, so the glue skips the pc→address table lookup and its indirect
  branch entirely. Only CALL/EXIT/`gotol` still need the table.
- **Still on the table**: the remaining ~1 ns tax is the call itself plus
  `Machine::step`'s re-decode of the instruction (it re-reads the opcode,
  re-checks `insn_count`, the profile hook, bounds). A specialized entry point
  that skips the re-decode could shave more. Compiling loads natively would be
  faster still but forfeits the memory-safety story (see above) — don't.

The frontend (`jit/mod.rs`, `classify.rs`) is architecture-independent; the
backends (`x64.rs`, `aarch64.rs`) are pure encoders implementing `JitBackend`.
**To add riscv you implement that trait and nothing else** — the whole point of
the split, done at the user's request, and adding aarch64 (session 5) confirmed
it holds: no eBPF logic moved. `docs/specs/jit-backend.md` is the step-by-step.
Gotchas written down there, each of which has already bitten once: 16-byte
stack alignment at call sites (the first x86 JIT segfault — 6 callee-saved
pushes misaligned it; it's now 5), instruction-cache flush + `MAP_JIT` write
gating on ARM (x86 needs neither), literal pools for absolute addresses (no
`movabs` outside x86), and short branch displacements (A64 `B.cond` is ±1MiB,
so `resolve_branches` returns `Result` — never truncate a displacement).

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
- ELF tests consume committed `.o` fixtures and never rewrite them by default.
  If you change the C, regenerate with
  `FEBPF_REGENERATE_FIXTURES=1 cargo test` using a BPF-capable clang. The shared
  helper preserves `-O0` for `subprog.c` so the cross-`.text` call is not
  inlined away.
- Do not run a repository-wide `cargo fmt` on this host: the installed
  rustfmt/toolchain combination reformats unrelated files. Format only files
  intentionally touched and inspect the diff.
- Root conformance was run through the user's TTTT `pty-3`. If that shell is
  still available, its root PATH does not include Cargo; use
  `CARGO_HOME=/home/ayourtch/.cargo RUSTUP_HOME=/home/ayourtch/.rustup
  CARGO_TARGET_DIR=/tmp/febpf-root-target /home/ayourtch/.cargo/bin/cargo ...`.
  Keep root-owned build artifacts out of the checkout.
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

## Agent-orchestration lessons (session 3 — these all actually bit me)

- The user likes the pattern: delegate well-scoped corpus batches to parallel
  worktree agents; SEQUENCE anything touching `verifier.rs` (two parallel
  batches once "fixed" the same subprog-return rule differently — the
  kernel-exact version won). Review every verifier diff personally before
  merging; the soundness bar is "cite the kernel rule you mirror".
- The Bash shell's `cd` into a worktree PERSISTS across commands: a `git
  merge` once silently ran inside the agent's worktree ("Already up to date")
  instead of main. Always `cd /home/ayourtch/rust/febpf` first or check
  `git worktree list` output paths.
- `tests/*.o` fixtures: clang `-g` embeds the compilation directory, so an
  explicit regeneration inside a worktree differs byte-wise from a main-checkout
  build. Commit fixture `.o` files ONLY from the main checkout; ordinary tests
  are read-only and should produce no fixture churn.
- After merging an agent branch: run both test configs + clippy FROM MAIN,
  `cargo build --release` (the corpus scan uses the release binary), rescan,
  then `git worktree remove --force <path>` + delete the branch.
- Historical note: the old pinned ksnoop object was a correct kernel-parity
  rejection. The refreshed object now verifies via febpf's deliberately more
  precise scalar-expression identity; preserve the distinction documented
  under Production coverage and in `scalar-identity.md`.
- Strategy/roadmap ponderings live in `docs/ideas.md` (user endorsed the
  ranking there); don't re-litigate direction, extend it.

## How to verify you haven't broken anything
```
cargo test --all-targets
cargo test --all-targets --no-default-features
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --no-default-features -- -D warnings
cargo build --release
./target/release/febpf bench examples/sum_loop.s --iters 50000 --jit   # ~11 GIPS
cargo test --release -- --ignored soundness     # optional heavy verifier sweep
```
Latest host result after tail calls, map-in-map, and scalar identity:
default **328 passed / 4 ignored**; no-default-features **314 passed / 4
ignored**; both strict clippy invocations are clean, as is the release build.
The complete privileged conformance suite is also green: 500 runtime
differentials, 1,000 verifier-frontier verdict comparisons, and the XDP,
tail-call, and map-in-map differentials. Ordinary tests do not regenerate
tracked `tests/*.o`; any fixture diff
without `FEBPF_REGENERATE_FIXTURES=1` is now a regression. Explicitly generated
objects can still differ by clang version and compilation path. Never delete or
blindly rewrite user changes.
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
   opens a `.febpf` in the browser. **Extended for XDP:** optional v1 PACKET
   section; raw frame or selected pcap record reopens with data/data_end and
   packet mutations intact in native and playground time-travel debuggers.
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
`scripts/fetch-corpus.sh` (gentle, pinned, cached) builds 57 real `.bpf.o`
from bcc libbpf-tools + libbpf-bootstrap using local clang + bpftool + kernel
BTF. `scripts/scan-corpus.sh` runs febpf over them and prints a ranked
histogram of the exact map types / helpers blocking the most real programs.
`corpus/` is gitignored. This is how we pick what to build next — MEASURE, don't
guess (it already corrected a wrong guess: ringbuf mattered less than
PERF_EVENT_ARRAY for this corpus). Coverage progression (loads / verifies):
- baseline (hash+array only): 23% / 3.6%
- + ringbuf/per-CPU/LRU (`docs/specs/map-types.md`): 30% / 5.4%
- + perf/cgroup/stack maps + tracing helpers (`map-types-2.md`): 92.9% / 30.4%
- + probe_read family + task_under_cgroup (`tracing-helpers.md`): 92.9% / 67.9%
- + get_stack (#67) + kconfig externs + missing-max_entries default + subprog
  pointer returns (batch appended to `tracing-helpers.md` / `elf-loading.md`):
  100% / 78.6%. Zero load failures remain.
- + load-time rodata DCE (`rodata-dce.md`), merged on top of the above:
  100% / 89.3% (50/56). The two parallel batches' fixes compounded
  (each measured 78.6% alone).
- + get_socket_cookie (#46) + get_func_ip (#173) + ksnoop verdict-parity
  investigation (appended to `tracing-helpers.md`): 100% / 91.1% (51/56).
  Also tightened subprog stack-pointer returns back to the exact kernel rule
  (reject ANY stack pointer, `prepare_func_exit()` conservatism) — the
  caller-frame allowance from the load-failure batch was laxer than the
  kernel and would have shown up as FEBPF-LAX in `vfuzz --kernel`.
- + BTF-typed ctx pointers (`btf-ctx-pointers.md`): **100% / 98.2%** (55/56).
  bitesize/offcputime/runqlat/runqslower unblocked AND running. The one
  remaining rejection in that historical corpus pin was ksnoop and matched
  the host kernel; the next refreshed-corpus entry explains what changed.
- + tail-call program graphs, static `ARRAY_OF_MAPS`, and sound scalar
  expression identity (`tail-calls.md`, `map-in-map.md`,
  `scalar-identity.md`): **100% / 100% (57/57)** on the refreshed corpus. The
  scanner reports one static tail-call graph separately.
**Workflow: merge a coverage batch → `./scripts/scan-corpus.sh` → the histogram
names the next batch.** febpf is an analysis/test/CI/debug engine, NOT a datapath
runtime — "production useful" means verify/explain/differential-test/debug real
programs, not attach-and-run in the kernel.

Two gotchas learned running this loop (2026-07-11): the scan uses
`target/release/febpf`, so `cargo build --release` BEFORE scanning or you
measure the previous build; and helper names in the histogram come from the
uapi header now — the old hardcoded table had wrong ids (#113 was labelled
ringbuf_output; it is probe_read_kernel).

The refreshed BCC `ksnoop` now verifies because febpf tracks copied and
recomputed scalar-expression identity. Important nuance: this is not kernel
verdict parity on the current host. That kernel drops the relevant identity at
the first mask and rejects even the minimized safe pattern; febpf retains the
proof under the deliberately narrow, regression-tested rules in
`scalar-identity.md`. Preserve the mismatched-mask rejection and the exhaustive
kernel-frontier checks when changing this logic.

## Known limitations / where to go next (roughly prioritized)

1. **Broaden production coverage** — add another pinned, representative corpus
   lane, then let its scan choose the next map/helper/ELF/verifier feature.
   Preserve reproducibility and report multi-program graphs explicitly. Do not
   mistake 57/57 in today's corpus for universal eBPF coverage.
2. **XDP web packet workbench** — parked by the user for now. When unparked,
   add pcap upload/verdict table/click-to-debug/export `.febpf`; see LATEST's
   oside notes. Do not make febpf core depend on current oside.
3. **XDP JIT execution** — interpreter is complete; `--jit` rejects XDP
   clearly. Teach the native/deferred path to synthesize full virtual packet
   addresses for u32 xdp_md data/data_end loads, then differential-test
   interpreter vs JIT across capture packets.
4. **Real-world map/helper coverage** — still missing SK/TASK/INODE_STORAGE,
   LPM_TRIE, sock/dev/xsk maps and many helpers. Implement them when a widened
   corpus makes them relevant, not from the list alone.
5. **Verifier depth** — dynptr, spin locks, bpf_loop/iterators, broader linked
   scalar relationships. Expression identity is implemented; `vfuzz --kernel`
   (keep at 0 FEBPF-LAX) remains the conformance check.
6. **ELF/kfunc/legacy gaps** — `R_BPF_64_ABS*`, static multi-object linking,
   kfuncs, and legacy `ld_abs`/`ld_ind`; add when real workloads demand them.

## Working style the user likes
- They're hands-on and technical (wrote the "fun challenge" framing, asked for
  the aarch64-ready abstraction and the design docs proactively). Give real
  engineering, not hand-holding.
- They asked me to **commit as I go** and to write specs so a future model
  could extend cleanly. Keep doing both.
- Differential/behavioral testing over assertions-about-code. When I built the
  JIT I validated against the interpreter; when I built the ELF loader I
  validated against real clang + bpftool. Match that bar.

— past-me, updated 2026-07-12
