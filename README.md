# febpf — fast userland eBPF engine

[![CI](https://github.com/ayourtch-llm/febpf/actions/workflows/ci.yml/badge.svg)](https://github.com/ayourtch-llm/febpf/actions/workflows/ci.yml)

A **zero-dependency** eBPF virtual machine in Rust with its own kernel-style
**verifier**, an **assembler/disassembler**, **program analysis** tooling and
an **interactive debugger**. Made for developing, debugging and understanding
eBPF programs entirely in userland.

> **Try it in your browser:** [febpf WebAssembly playground](https://stdio.be/febpf/)

```console
$ febpf run examples/fib.s --ctx 0b
r0 = 89 (0x59)   [interp, 1.9µs]

$ febpf bench examples/sum_loop.s --iters 50000
50000 iterations, 3003 insns/run [interp]  — 247 M insn/s
$ febpf bench examples/sum_loop.s --iters 50000 --jit
50000 iterations, 3003 insns/run [jit]     — 11018 M insn/s   # 45× faster
```

## Features

- **Modern ISA (v4)**: ALU32/64, JMP32, sign-extending moves & loads
  (`movsx`, `ldxs*`), signed div/mod, `bswap`/`le`/`be`, 32-bit `gotol`,
  atomics (`add/or/and/xor`, fetch variants, `xchg`, `cmpxchg`),
  bpf-to-bpf calls with up to 8 frames.
- **Real verifier** — a path-sensitive abstract interpreter modeled on the
  kernel's: tnums (known-bits tracking), signed + unsigned range analysis,
  branch-condition refinement, pointer typestate (stack/context/map value/
  maybe-NULL), byte-granular stack initialization tracking, pointer-spill
  restore, scalar copy/expression identities, helper signature checking,
  subsumption-based state pruning with
  miss-streak backoff, and a 1M-instruction complexity budget.
- **Memory-safe by construction**: guest pointers are virtual addresses
  (`region_handle << 32 | offset`) resolved through a region table with O(1)
  bounds checks. No host pointers ever enter guest registers — even with
  `--no-verify`, a wild program gets a clean runtime error, never UB. Bonus:
  pointers are *readable* in the debugger (`0x0000000200000200` = stack
  frame 0, offset 512).
- **Assembler & disassembler** for the kernel-documentation "pseudo-C"
  syntax (`r0 = 42`, `if r1 s> r2 goto out`, `*(u32 *)(r10 - 8) = r1`),
  with labels, map declarations, and `asm(disasm(p)) == p` round-tripping.
  Embedders can also construct instruction streams with the typed, fluent
  `builder::Builder` API.
- **Analysis**: basic-block CFG (Graphviz DOT export), instruction-mix
  stats, and a listing annotated with the verifier's abstract state at
  every instruction — watch ranges tighten as null checks and bounds
  checks refine them.
- **Interactive, source-aware debugger**: breakpoints, stepping, reverse
  stepping/continue, watchpoints, register/stack/memory inspection, map dumps,
  `trace_printk` capture, dataflow queries (`origin`/`when`/`who`), and C source
  lines and typed globals from BTF debug info.
- **Maps & helpers**: array/hash/per-CPU/LRU/ring/perf/stack/program maps,
  typed `ARRAY_OF_MAPS` nested lookup, and kernel-compatible helper ids
  (`map_lookup_elem`, `map_update_elem`, `map_delete_elem`,
  `ktime_get_ns`, `trace_printk`, `get_prandom_u32`, …), plus an API to
  register **custom helpers** with verifier-checked signatures.
- **Tail-call program graphs**: `PROG_ARRAY` maps and helper 12 across the
  verifier, interpreter, JIT, debugger/snapshots, replay, and kernel
  differential path. ELF `values[]` relocations are linked automatically, so
  a multi-section clang object can be verified and run directly with `--prog`.
- **JIT compiler** (x86-64 Linux, aarch64 Linux and macOS; zero-dependency):
  hand-rolled native codegen for the ALU + branch core (~45× on tight loops on
  x86-64, ~26× on aarch64), with memory ops, calls and atomics deferred to the
  interpreter — so the JIT keeps the interpreter's exact memory-safety
  guarantee, it just removes dispatch overhead. Each deferred instruction pays
  a trampoline round-trip, so the speedup scales with how much of a program is
  arithmetic: ~25× for a tight ALU loop, ~1.2–1.6× for memory-saturated code.
  The compiler is split into an
  architecture-independent frontend and a `JitBackend` trait; adding **riscv64**
  means implementing that one trait (see `docs/specs/jit-backend.md`).
  Differentially tested against the interpreter.
- **Portable interpreter**: the VM, assembler, verifier, maps, helpers and
  replay tooling target x86-64 Windows with the JIT disabled; native Windows
  CI builds, runs the test suite and enforces strict clippy.
- **Execution profiler**: `febpf profile` runs the program and prints a
  per-instruction heatmap (counts, %, log-scaled bar) plus hottest-block
  summary.
- **Deterministic replay and race exploration**: self-contained `.febpf`
  captures preserve program graphs, maps, context or packet input, and debugger
  position for exact reproduction and time-travel debugging. `febpf race`
  explores concurrent instances sharing maps and emits replayable schedules for
  lost updates and other map-level races.
- **Equivalence checking and optimization**: compare observable behavior
  (return value, context/map mutations, output records and `trace_printk`) and
  apply verifier-guided rewrites that are reverified and equivalence-checked.
- **ELF loader** for real `clang -target bpf` objects: sections/symbols,
  `R_BPF_64_64` map relocations and `R_BPF_64_32` bpf-to-bpf calls (with
  cross-`.text` subprogram stitching), legacy `maps` **and** BTF-defined
  `.maps`, plus global data sections (`.data`/`.bss`/`.rodata*`
  as initialized single-entry array maps, `.rodata` frozen — string literals,
  lookup tables and persistent globals just work). Tested against genuine
  clang output, including sparse static program-array and map-in-map initializers
  (`docs/specs/elf-loading.md`).
- **BTF, CO-RE and XDP tooling**: all 19 BTF kinds, `.BTF.ext` function/line
  info, source-level debugging, and CO-RE relocation against a supplied target
  or the running kernel's BTF. XDP programs get verifier-tracked
  `data`/`data_end` packet bounds and can run deterministically over a raw packet
  or every packet in a classic pcap, with failing packets exportable as replay
  files.

## CLI

```text
febpf asm      prog.s -o prog.bin    # assemble to raw bytecode
febpf disasm   prog.bin              # disassemble
febpf verify   prog.s                # run the verifier, report stats
febpf analyze  prog.s                # CFG + stats + annotated listing
febpf dot      prog.s | dot -Tsvg    # control-flow graph
febpf run      prog.s [--ctx <hex|@file>] [--no-verify] [--jit]
febpf debug    prog.s                # interactive debugger
febpf profile  prog.s                # per-instruction execution heatmap
febpf bench    prog.s --iters 30000 [--jit]   # throughput (interp or JIT)
febpf record   prog.s -o run.febpf   # capture input/state for deterministic replay
febpf replay   run.febpf             # time-travel debug a captured execution
febpf race     prog.s --procs 2      # explore shared-map interleavings
febpf equiv    before.s after.s      # check observable equivalence
febpf optimize prog.s -o smaller.bin # verifier-guided, checked optimization
febpf conftest prog.s                # diff interpreter, JIT and real kernel
febpf fuzz     --iters 1000          # differential interpreter/JIT fuzzer
febpf vfuzz    --iters 1000          # verifier-frontier differential fuzzer
```

ELF inputs can select a section with `--prog`; CO-RE accepts `--target-btf`.
For XDP, use `--packet <file>` or `--pcap <file>`. Kernel differential modes
require Linux privileges and otherwise report that they were skipped.

## Assembly syntax

```asm
; comments: ';' '#' '//'
.map counts hash 4 8 1024      ; name kind key_size value_size max_entries

        w1 = 7                 ; 32-bit ALU (wN registers)
        *(u32 *)(r10 - 4) = r1 ; stack store
        r1 = map[counts]       ; map pointer (lddw pseudo)
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 == 0 goto miss   ; null check — required by the verifier
        r1 = 1
        lock *(u64 *)(r0) += r1
        r0 = 0
        exit
miss:
        r0 = -1
        exit
```

## Library use

```rust
use febpf::{builder::Builder, verifier::Config, Program, Vm};

fn constant(value: i32) -> Program {
    Program {
        insns: Builder::new().mov64_imm(0, value).exit().build().unwrap(),
        maps: Vec::new(),
        btf_ctx: None,
    }
}

let mut vm = Vm::new(constant(42)).unwrap();
vm.verify(Config::default()).unwrap();      // kernel-style verification
assert_eq!(vm.run_no_data().unwrap(), 42);  // explicit empty-input adapter

vm.replace_program(constant(7)).unwrap();   // transactional on failure
vm.verify(Config::default()).unwrap();      // replacements start unverified
assert_eq!(vm.run_no_data().unwrap(), 7);
```

For mutable byte input, `vm.run_raw(&mut buffer)` exposes the buffer through
febpf's bounded guest-address region and copies program writes directly back;
it never places the buffer's host pointer in a guest register. A successful
`replace_program` resets program-derived state while preserving registered
helpers and execution configuration; if construction fails, the original
program and its live map state remain unchanged.

Custom helpers get bounds-checked memory access and a verifier signature:

```rust,ignore
use febpf::helpers::{id, ArgKind, HelperSig, MemBus, RetKind};

vm.user_helpers.register(
    id::FIRST_USER,
    HelperSig { name: "my_helper",
                args: [ArgKind::Scalar, ArgKind::None, ArgKind::None,
                       ArgKind::None, ArgKind::None],
                ret: RetKind::Scalar },
    Box::new(|args: [u64; 5], _mem: &mut dyn MemBus| Ok(args[0] * 2)),
);
```

The debugger is also available as a library (`febpf::debug::repl`), and the
single-stepping `Machine` API (`vm.machine(&mut ctx)`) lets you build your
own tooling: step, inspect `regs`/`pc`, read memory.

## What the verifier catches

`febpf analyze` shows the abstract state the verifier proves at each insn:

```text
   0: r6 = *(u8 *)(r1)
      ; r1=ctx r6=scalar(u=[0,255] t=(v=0x0 m=0xff))
   2: if r6 == 0 goto +7 <10>
      ; r6=scalar(u=[1,255] ...)          <- range refined by the branch
   4: r8 = r0  ; visited 255x             <- loop explored to a bounded end
```

Rejected (with kernel-style messages): uninitialized register/stack reads,
out-of-bounds stack/context/map-value accesses, dereferencing scalars or
maybe-NULL map values, pointer leaks to non-stack memory, unbounded loops
("program too complex"), unreachable code, missing `exit`/`r0`, bad helper
arguments, call-depth overflow, writes to `r10`.

## WASM playground

The interpreter, verifier, assembler, disassembler, analysis and a
replay-based time-travel debugger are pure-std, zero-dependency Rust, so they
compile to `wasm32-unknown-unknown` and run **entirely in the browser** — paste
assembler or drop a clang `.o`, then verify / run / disassemble / analyze /
step (and *un*-step). The x86-64 JIT is feature-gated off for this build
(`default = ["jit"]`), so nothing pulls `asm!` into wasm.

```sh
rustup target add wasm32-unknown-unknown
cd web && make            # → web/dist/  (index.html, febpf.js, febpf.wasm)
cd dist && python3 -m http.server 8000      # then open http://localhost:8000
```

`web/dist/` is fully self-contained — `rsync` it to any static host. Serving
needs a real server so the `.wasm` gets the `application/wasm` MIME type;
`file://` will not instantiate it. `make clean` removes `dist/`.

The ABI is hand-written (no `wasm-bindgen`): `extern "C"` exports
(`febpf_verify`, `febpf_run`, `febpf_analyze`, `febpf_dbg_cmd`, …) with an
allocator and linear-memory string passing, packed as `(ptr << 32) | len`
u64 returns; `web/febpf.js` is the matching glue. See
`docs/specs/wasm-playground.md`.

Smoke tests (no browser needed): `web/test/smoke.sh` runs the in-wasm
`febpf_selftest` under any `wasmtime` (set `WASMTIME=/path/to/wasmtime`), and
`web/test/abi-harness` (`cargo run`) drives the *full string ABI* through the
pure-Rust `wasmi` interpreter — the exact marshalling the browser does,
including time-travel `rstep`.

## Design notes

- **Interpreter**: direct threaded `match` dispatch over the fixed 8-byte
  instruction encoding, inlined into the run loop; ~265 M insn/s on a
  simple ALU loop (release build, one core).
- **Verifier exploration** is DFS with an explicit stack, like the kernel:
  branch states are pushed, joined states are pruned when subsumed by an
  already-verified state at the same instruction. `MapValueOrNull` carries
  an id so null checks refine every copy of the pointer, including spills.
- **Determinism**: `get_prandom_u32` is a fixed-seed xorshift and hash maps
  never move values, so buggy programs replay identically under the
  debugger.
- **JIT**: `docs/specs/jit-backend.md` — architecture-independent frontend +
  `JitBackend` trait; x86-64 and aarch64 done, riscv64 documented as drop-in.
- **CI**: `.github/workflows/ci.yml` runs the suite, clippy (`-D warnings`) and
  the differential fuzzer on all three JIT platforms — each runner executes
  machine code generated for that exact CPU.
- **ELF/BTF/CO-RE loading**: `docs/specs/elf-loading.md` and
  `docs/specs/core-relocations.md`.
- **Known gaps**: kfuncs, dynptrs, spin locks, `bpf_loop`/iterators,
  `R_BPF_64_ABS*` relocations, static multi-object linking, legacy
  `ld_abs`/`ld_ind`, and a riscv64 JIT backend. XDP execution currently uses
  the interpreter; `--jit` rejects it explicitly.

## Tests

The current suite has **344 passing tests** with default features and **330**
with `--no-default-features`, plus four intentionally ignored exhaustive
soundness sweeps in each configuration. Coverage includes ISA semantics,
verifier acceptance and rejection, abstract-operator soundness, maps/helpers,
tail-call graphs, XDP, assembler/disassembler round-tripping, time travel,
replay, race exploration, equivalence/optimization, **JIT-vs-interpreter
differentials**, and **ELF/BTF/CO-RE loading** against genuine clang output.
Privilege-gated tests additionally compare execution and verifier verdicts
with the live Linux kernel when available.

Run both supported configurations before submitting changes:

```sh
cargo test
cargo test --no-default-features
```

ELF tests consume committed `tests/*.o` fixtures without modifying them. To
explicitly rebuild fixtures with a BPF-capable clang, run
`FEBPF_REGENERATE_FIXTURES=1 cargo test`. The four larger soundness sweeps run
separately with `cargo test --release -- --ignored soundness`.
