# febpf — fast userland eBPF engine

A **zero-dependency** eBPF virtual machine in Rust with its own kernel-style
**verifier**, an **assembler/disassembler**, **program analysis** tooling and
an **interactive debugger**. Made for developing, debugging and understanding
eBPF programs entirely in userland.

```
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
  restore, helper signature checking, subsumption-based state pruning with
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
- **Analysis**: basic-block CFG (Graphviz DOT export), instruction-mix
  stats, and a listing annotated with the verifier's abstract state at
  every instruction — watch ranges tighten as null checks and bounds
  checks refine them.
- **Interactive debugger**: breakpoints, single-stepping, register/stack/
  memory inspection, map dumps, `trace_printk` capture, per-insn tracing.
- **Maps & helpers**: array + hash maps, kernel-compatible helper ids
  (`map_lookup_elem`, `map_update_elem`, `map_delete_elem`,
  `ktime_get_ns`, `trace_printk`, `get_prandom_u32`, …), plus an API to
  register **custom helpers** with verifier-checked signatures.
- **JIT compiler** (x86-64 Linux, zero-dependency): hand-rolled native
  codegen for the ALU + branch core (~45× on tight loops), with memory
  ops, calls and atomics deferred to the interpreter — so the JIT keeps the
  interpreter's exact memory-safety guarantee, it just removes dispatch
  overhead. The compiler is split into an architecture-independent frontend
  and a `JitBackend` trait; adding **aarch64/riscv64** means implementing
  that one trait (see `docs/specs/jit-backend.md`). Differentially tested
  against the interpreter.
- **Execution profiler**: `febpf profile` runs the program and prints a
  per-instruction heatmap (counts, %, log-scaled bar) plus hottest-block
  summary.

## CLI

```
febpf asm      prog.s -o prog.bin    # assemble to raw bytecode
febpf disasm   prog.bin              # disassemble
febpf verify   prog.s                # run the verifier, report stats
febpf analyze  prog.s                # CFG + stats + annotated listing
febpf dot      prog.s | dot -Tsvg    # control-flow graph
febpf run      prog.s [--ctx <hex|@file>] [--no-verify] [--jit]
febpf debug    prog.s                # interactive debugger
febpf profile  prog.s                # per-instruction execution heatmap
febpf bench    prog.s --iters 30000 [--jit]   # throughput (interp or JIT)
```

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
use febpf::{asm, Program, Vm, verifier::Config};

let a = asm::assemble("r0 = 42\n exit").unwrap();
let mut vm = Vm::new(Program { insns: a.insns, maps: a.maps }).unwrap();
vm.verify(Config::default()).unwrap();      // kernel-style verification
assert_eq!(vm.run(&mut []).unwrap(), 42);
```

Custom helpers get bounds-checked memory access and a verifier signature:

```rust
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

```
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
- **Not implemented (yet)**: ELF object loading (`clang -target bpf` `.o`),
  BTF, kfuncs, legacy packet-access instructions, JIT compilation.

## Tests

`cargo test` — 48 tests covering ISA semantics (including div/mod-by-zero,
sign extension, byte swaps, atomics), verifier accept/reject cases, map
round-trips, bpf-to-bpf calls, custom helpers, and assembler/disassembler
round-tripping.
