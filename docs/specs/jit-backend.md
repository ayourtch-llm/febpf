# febpf JIT backend specification

This document specifies the contract a new architecture backend must satisfy.
It is written so that an implementer (human or model) can add an **aarch64** or
**riscv64** backend by implementing one trait — `JitBackend` — without touching
any eBPF logic.

> Status: x86-64/Linux backend implemented (`src/jit/x64.rs`). aarch64 and
> riscv64 backends are **not yet written**; this spec is the blueprint.

---

## 1. Architecture: frontend vs backend

The JIT is split so that everything eBPF-specific is written once:

```
                 ┌─────────────────────── frontend (arch-independent) ──────────────────────┐
   eBPF insns ──►│ classify.rs: native vs deferred, backend-neutral op description           │
                 │ mod.rs: emit loop, pc→address table, exec-mem alloc, 2-phase finalization  │
                 └───────────────────────────────────┬──────────────────────────────────────┘
                                                     │ calls JitBackend methods
                 ┌───────────────────────────────────▼──────────────────────────────────────┐
                 │ backend (arch-specific): pure instruction encoder                          │
                 │ x64.rs  ·  aarch64.rs (todo)  ·  riscv64.rs (todo)                          │
                 └────────────────────────────────────────────────────────────────────────────┘
```

The frontend (`src/jit/mod.rs`, `src/jit/classify.rs`) never emits bytes. The
backend never inspects eBPF semantics — it is handed already-decoded,
architecture-neutral operations (`AluOp::Add`, `Cc::Sgt`, register **indices**
0–10) and emits machine code for them.

**To add an architecture you implement `JitBackend` and add two lines** (a
`#[cfg]` `mod` declaration and a branch in `compile()`). Nothing else changes.

---

## 2. What is compiled vs deferred

`classify::lower()` (shared, do not duplicate) partitions instructions:

- **Native** (backend must emit code): 64/32-bit `ADD SUB MUL OR AND XOR MOV
  NEG`, immediate-count `LSH RSH ARSH`, unconditional `JA`, all conditional
  jumps `JEQ JNE JGT JGE JLT JLE JSGT JSGE JSLT JSLE`, and `JSET`.
- **Deferred** (backend emits trampoline glue only): `DIV MOD` (incl. signed),
  byte-swaps (`END`), sign-extending `MOVSX`, **register-count** shifts, every
  load/store/atomic, `lddw`, helper calls, bpf-to-bpf calls, and `EXIT`.

A backend therefore needs to encode only ~20 simple ALU/branch forms plus one
trampoline-glue sequence. Deferred instructions run on the interpreter core, so
their correctness and memory-safety are already guaranteed.

A future backend *may* natively compile more (e.g. loads with inline bounds
checks) as an optimization, but is never required to.

---

## 3. The `JitBackend` trait

Defined in `src/jit/mod.rs`. Call order enforced by the frontend:

```
prologue()
for each real instruction slot (lddw tail slots skipped):
    mark_label(pc)
    <one native emitter>  OR  deferred(pc)
epilogue()
resolve_branches(label_off, epilogue_off)   // relative fixups
<frontend copies code into executable memory>
patch_absolutes(code, trampoline_addr, table_addr)   // absolute pointers
```

Register operands are **eBPF indices 0–10**. The backend owns the physical
mapping. Widths are `Width::W32` (32-bit, zero-extends result to 64) or
`Width::W64`.

### Native emitters
| method | semantics |
|--------|-----------|
| `alu_reg(op,w,dst,src)` | `dst = dst op src` |
| `alu_imm(op,w,dst,imm)` | `dst = dst op sext(imm)` (imm is i32) |
| `mov_reg(w,dst,src)` | `dst = src` (W32 zero-extends) |
| `mov_imm(w,dst,imm)` | `dst = sext(imm)` (W64) / `zext(imm)` (W32) |
| `neg(w,dst)` | `dst = -dst` |
| `shift_imm(op,w,dst,amount)` | `dst = dst <shift> amount` (amount pre-masked to 31/63) |
| `jump(target)` | unconditional branch |
| `cond_branch(cc,w,dst,rhs,target)` | branch if `dst cc rhs` (signed per `cc`) |
| `jset_branch(w,dst,rhs,target)` | branch if `(dst & rhs) != 0` |

`W32` semantics must match eBPF: operate on the low 32 bits and **zero-extend**
the 32-bit result into the full 64-bit register. (On x86-64 this is free; on
aarch64 use the `W`-register forms; on riscv use `*W` ops + explicit
zero-extension where needed, e.g. after `addw` the result is sign-extended, so a
`zext.w`/`slli;srli` is required to match eBPF.)

For comparisons, unsigned vs signed is dictated by `cc`. 32-bit compares must
compare only the low 32 bits.

### Finalization
- `resolve_branches(label_off, epilogue_off)`: patch every relative branch the
  backend recorded. `label_off[pc]` is the byte offset of pc's code, or
  `usize::MAX` for a slot with no code (branch it to `epilogue_off`).
- `epilogue_off()`: byte offset of the epilogue.
- `patch_absolutes(code, trampoline, table)`: write the two absolute 64-bit
  pointers into the code buffer (now at its final address). On architectures
  without a movabs-style immediate (aarch64, riscv), load these from a small
  **literal pool** you emit inside the code buffer and record offsets for here.

---

## 4. Trampoline ABI (`src/jit/abi.rs`) — identical on every architecture

### Compiled function entry
`extern "C" fn(regs_ptr: *mut u64, machine_ptr: *mut ())`

- `regs_ptr` → the eBPF register file `[u64; 11]` (r0..r10). The prologue loads
  it into physical registers; deferred glue spills to / reloads from it.
- `machine_ptr` → type-erased `*mut Machine`, passed unchanged to the
  trampoline.

The prologue must: save the platform's callee-saved registers that the backend
uses, stash `regs_ptr` and `machine_ptr` somewhere stable across calls
(native-stack slots), load the 11 eBPF registers, and fall through to pc 0.

The epilogue restores callee-saved registers and returns. On a clean program
exit, `r0` must already be in `regs[0]` in memory (the deferred `EXIT` glue
spills before calling the trampoline, so this holds automatically).

### Trampoline
`extern "C" fn(machine_ptr, pc: u64) -> u64` (frontend provides this;
`jit::trampoline`). Returns:
- the **next pc** to execute, or
- `abi::STOP` (high bit set — no valid pc has it) when the program exited or a
  deferred instruction faulted. Fault vs clean-exit is disambiguated by the
  Rust caller via `Machine::take_jit_fault`.

### Deferred glue (`deferred(pc)`) — the one non-trivial sequence
Emit, in order:
1. **Spill** all 11 eBPF registers to `[regs_ptr + 8*i]`.
2. Set up args: arg0 = `machine_ptr` (from its stack slot), arg1 = `pc`.
3. **Call** the trampoline (absolute pointer, patched in `patch_absolutes`).
4. Save the return value in a scratch register **not** used for an eBPF reg.
5. **Reload** all 11 eBPF registers from `regs_ptr`.
6. If the saved return has the STOP bit set → branch to the epilogue.
7. Else indirect-jump to `table[next_pc]`, where `table` is the `pc→address`
   array whose base is patched in `patch_absolutes`. On x86-64 this is
   `jmp [table + next_pc*8]`; on aarch64/riscv, load `table` from a literal,
   `ldr`/`ld` the target, and branch to register.

Because control returns through this table after every deferred instruction,
the backend never needs to know how calls/exits change frames — the interpreter
does it and reports the resulting pc.

---

## 5. Step-by-step: adding aarch64

1. `src/jit/aarch64.rs`: `pub struct Aarch64Backend { … }` implementing
   `JitBackend`.
2. Register map suggestion (AAPCS64): eBPF r0..r10 → `x19..x29` region (all
   callee-saved so nothing to preserve across trampoline calls except the ones
   the AAPCS says); scratch `x9..x15`; args in `x0,x1`. Keep `regs_ptr`/
   `machine_ptr` in two callee-saved regs or stack slots.
3. Encode the native forms (all are single A64 instructions): `ADD/SUB/ORR/
   AND/EOR/MUL` (reg and imm — note A64 imm forms are restricted, fall back to
   materialize-in-scratch-then-reg), `MOVZ/MOVK/MOVN` for `mov_imm`, `NEG`,
   `LSL/LSR/ASR` immediate, `B`/`B.cond`, and `CMP` (`SUBS xzr,…`) +
   `TBNZ`-style for `jset`. Use `W`-register forms for `Width::W32`.
4. Branches use imm26 (B) / imm19 (B.cond) — record fixups and patch in
   `resolve_branches`; if a target is out of range, widen via an island (rare
   for eBPF-sized programs; can start by asserting range).
5. Absolute pointers: emit a literal pool at the function end; `patch_absolutes`
   writes the two 64-bit values there; native code uses `LDR (literal)` /
   `ADR`.
6. Executable memory: `mod.rs`'s `ExecMem`/`sys` is x86-64-gated only for the
   syscall numbers — generalize `sys` for aarch64 Linux (mmap=222, mprotect=226)
   plus a `__clear_cache`/`ISB`+`DC CVAU`/`IC IVAU` **instruction-cache flush**
   after `mprotect` (mandatory on ARM; x86-64 does not need it).
7. Wire it: `#[cfg(target_arch="aarch64")] pub mod aarch64;` and a branch in
   `compile()`.
8. Validate: the `tests/jit.rs` differential suite must pass unchanged — it
   compares JIT output to the interpreter for every program. Add loop/branch/
   call-heavy cases if coverage gaps appear.

riscv64 is analogous (syscalls mmap=222/mprotect=226; `FENCE.I` for I-cache;
branch immediates are ±4KiB for `B*` so use a compare-then-`BEQ/BNE` + `J`
trampoline for far targets; no cheap large immediates — materialize with
`LUI/ADDIW` or a literal loaded via `AUIPC`).

---

## 6. Invariants a backend must preserve

- **Never** dereference an eBPF register value as a host pointer. eBPF pointers
  are virtual addresses (`region<<32 | offset`); all dereferences are deferred
  to the interpreter, which bounds-checks them. This is the whole memory-safety
  story — a native backend that "optimizes" a load by dereferencing directly
  must replicate the interpreter's region resolution and bounds checks, or it
  breaks the guarantee.
- **32-bit results zero-extend** to the full register.
- **Div/mod/shift-by-register stay deferred** unless you also implement eBPF's
  exact edge cases (div-by-zero ⇒ 0, mod-by-zero ⇒ unchanged, signed variants,
  shift-amount masking).
- After making code executable, **flush the instruction cache** on
  architectures that require it (ARM, RISC-V).
- The compiled function must be **re-entrant across runs** (the frontend calls
  `enter` once per program run; no writable global state in the code).
