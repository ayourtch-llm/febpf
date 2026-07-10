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

Everything works today: `cargo test` is 56 green, `cargo clippy --all-targets`
is 0 warnings, release builds clean. Two commits in git.

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
| `insn.rs` | 224 | ISA v4 opcode constants, `Insn`, decode/encode, `wide_imm` |
| `asm.rs` | 952 | assembler for kernel "pseudo-C" syntax (tokenizer + recursive-descent) |
| `disasm.rs` | 228 | disassembler (round-trips with asm) |
| `tnum.rs` | 281 | tracked-numbers (known-bits) abstract domain, mirrors kernel `tnum.c` |
| `verifier.rs` | 2164 | the big one: path-sensitive abstract interpreter |
| `maps.rs` | 208 | array + hash maps with stable value storage (see safety note) |
| `helpers.rs` | 174 | helper id/name/signature registry + user-helper API |
| `interp.rs` | 907 | the VM: `Vm`, `Machine`, virtual-address memory model, JIT glue |
| `jit/mod.rs` | 347 | arch-independent JIT frontend + `JitBackend` trait + exec-mem |
| `jit/classify.rs` | 176 | native-vs-deferred lowering (pure eBPF logic) |
| `jit/x64.rs` | 440 | the only arch-specific file: x86-64 encoder |
| `jit/abi.rs` | 32 | the trampoline ABI constants/contract |
| `elf.rs` | 818 | ELF64 loader for `clang -target bpf` objects + BTF `.maps` |
| `analysis.rs` | 302 | CFG, DOT export, stats, annotated listing, heatmap |
| `debug.rs` | 248 | interactive debugger REPL |
| `main.rs` | 399 | CLI |

Specs for the two subsystems most likely to be extended:
`docs/specs/jit-backend.md` and `docs/specs/elf-loading.md`. **Read those**
before touching the JIT or ELF code — they encode the contracts.

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

### 6. Determinism
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
  sandbox).
- Scratch dir for throwaway files:
  `/tmp/claude-1000/-home-ayourtch-rust-febpf/8e539042-9e74-4a14-94b5-6b9012fb3ac1/scratchpad`

## How to verify you haven't broken anything
```
cargo test                     # 56 tests
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

## Known limitations / where to go next (roughly prioritized)

1. **aarch64 JIT backend** — the trait is ready, spec is written. Highest-value
   next step and the user explicitly wants it. Then riscv64.
2. **Richer map types** — per-CPU, LRU, ringbuf, maps-of-maps. `maps.rs` is
   where they go; `helpers.rs` for any new helpers; verifier needs to know
   their semantics.
3. **Fuller BTF** — CO-RE relocations, `.BTF.ext` (func/line info). Current
   BTF is the minimal `.maps` subset only.
4. **ELF gaps** — global data sections (`.bss`/`.data`/`.rodata`) as maps,
   `R_BPF_64_ABS*` relocations, static linking of multiple objects.
5. **Verifier depth** — it's solid but not exhaustive; e.g. more precise
   handling of variable-offset pointer arithmetic, dynptr, spin locks. Compare
   against kernel `verifier.c` behavior if extending.
6. **kfuncs**, legacy packet-access (`ld_abs`/`ld_ind`) — deliberately
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
