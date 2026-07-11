# Dataflow queries ("omniscient debugging")

Causality queries layered on the existing deterministic time-travel replay
(`docs/specs/time-travel-debug.md`). They answer *where did this value come
from* and *who wrote this* by walking the execution history, without recording
every step eagerly: because replay is deterministic and cheap, we reconstruct a
lightweight **write-log** on demand for the current replay interval and scan it.

Commands (all TTY-free through `DebugSession::handle_command`):

| command | question |
|---------|----------|
| `origin <reg>` | data provenance: trace this register's current value back through the instructions that produced it, to where it was "born" (constant / ctx / map-load / helper return) |
| `when <reg>` | the most recent instruction (before now) that last wrote this register |
| `whenwrite <addr\|reg>` | the most recent instruction that last wrote this stack slot / map byte / ctx byte (address given raw, or as a register holding a pointer) |
| `who <addr\|reg> [len]` | who wrote the byte(s) at a memory location — writing pc + source line + bytes written |

## Write-log representation

A query first rebuilds the per-step write-log covering the **current replay
interval**: restore the nearest checkpoint `≤ insn_count` (base or a
`DebugSession` checkpoint) and single-step forward to the current position,
recording one `Step` per executed instruction. This ends exactly at the current
position (determinism guarantees identical state), so it does not disturb the
session — same mechanism as `goto_count`, but recording. Memory is bounded: the
log spans one interval (`snapshot_interval`, default 10 000 steps) at a time; a
def older than the nearest checkpoint is reported as "not found in this
interval".

```rust
struct MemRange { addr: u64, len: usize }

struct Step {
    count: u64,             // insn_count AFTER executing (1-based)
    pc: usize,              // instruction index
    def_reg: Option<u8>,    // register this insn defined (0..=10)
    def_val: u64,           // value written to def_reg (post-state)
    store: Option<MemRange>,// memory this insn wrote
    store_val: u64,         // value stored (STX src reg / ST imm)
    load: Option<MemRange>, // memory this insn read into def_reg (LDX)
}
```

Each `Step` is computed from the decoded instruction (`Vm::insns()[pc]`) plus
the register file **before** the step (to resolve effective addresses
`regs[base] + off`) and **after** (to capture `def_val`). The interpreter is
untouched; the recorder lives in `DebugSession`. Per instruction class:

- `ALU`/`ALU64`: `def_reg = dst`, `def_val = regs_after[dst]`.
- `LD` (wide `lddw`): `def_reg = dst` (constant / map pointer — a provenance leaf).
- `LDX`: `def_reg = dst`, `load = { regs_before[src] + off, size }`.
- `ST`: `store = { regs_before[dst] + off, size }`, `store_val = imm`.
- `STX` (plain): `store = { regs_before[dst] + off, size }`, `store_val = regs_before[src]`.
- `STX`/atomic: records the `store` range only (fetch/cmpxchg reg defs are not
  followed — documented limitation).
- `JMP`/`JMP32` `CALL` helper: `def_reg = 0` (a helper-return leaf); local call
  / exit / branches define nothing.

Region naming resolves through the virtual-address model: `addr >> 32` is a
region handle, `addr & 0xffff_ffff` the offset. `Machine::describe_addr` maps
the handle to `ctx`, `stack frame N` (with fp-relative offset when it is the
live frame), `map '<name>' value`, or `map object` — added to `interp.rs`
because the region table is private there.

## `origin` — def-use walk

`origin <reg>` recursively follows the def-use chain, printing an indented
trail. A `Source` is either a register or a memory range; we resolve it to the
last `Step` that produced it strictly before a cutoff count, print that link
(pc, disasm, source line if `DebugInfo` present, value), then recurse into that
step's inputs:

```
trace(Source, cutoff, depth):
  Register(r): step = last Step with def_reg==r and count < cutoff
     none      -> leaf "r{r} = 0x.. (initial/ctx value, not written in interval)"
     MOV r<-src(reg)     -> trace(Register(src), step.count)
     MOV r<-imm / lddw   -> leaf "born: constant/map pointer"
     ALU r = r op X      -> trace(Register(dst=r)); if src is a distinct reg, also trace(Register(src))
     unary (NEG/END)     -> trace(Register(dst))
     LDX r <- [addr]     -> print "loaded from <region>"; trace(Memory(load.addr, load.len))
     CALL helper         -> leaf "born: helper return"
  Memory(addr,len): step = last Step whose store overlaps [addr,addr+len) and count < cutoff
     none      -> leaf "<region> not written in interval"
     STX [addr] <- src   -> trace(Register(src), step.count)
     ST  [addr] <- imm   -> leaf "born: constant stored to <region>"
```

Cycle / runaway protection: a visited set of `(kind, key, cutoff)` plus a depth
cap (64). The walk terminates at leaves whose inputs are all constants, ctx,
unwritten memory, or helper returns — "where the value was born".

### Example

Program (value flows mov -> alu -> store -> load -> exit):

```
0: r1 = 5
1: r1 += 3
2: *(u64 *)(r10 - 8) = r1
3: r0 = *(u64 *)(r10 - 8)
4: exit
```

`origin r0` after running to the `exit`:

```
origin of r0 = 0x8 (8):
  #0  insn 3  r0 = *(u64 *)(r10 - 8)      loaded from stack frame 0 (fp-8)
  #1  insn 2  *(u64 *)(r10 - 8) = r1      stored from r1
  #2  insn 1  r1 += 3                     r1 = 0x8
  #3  insn 0  r1 = 5                      born: constant 0x5
```

`whenwrite r10 -8`-style: `who 0x2_00000200`-... resolved via a register:
`who r10` (with an offset the user computes) or `whenwrite <addr>` prints:

```
stack frame 0 (fp-8) last written by insn 2: *(u64 *)(r10 - 8) = r1  (= 0x8)
  at prog.c:4   *p = a;
```

## Command syntax

```
origin <reg>              provenance trail for a register's current value
when <reg>                pc of the most recent write to a register
whenwrite <addr|reg>      pc of the most recent write to a memory location
                          (reg = use the register's value as the address)
who <addr|reg> [len]      writer pc + source line + bytes (default len 8)
```

`<reg>` accepts `r0`..`r10`. `<addr>` accepts decimal / `0x` hex. A bare
register in `whenwrite`/`who` is dereferenced (its current value is the target
address).

## Staged plan

1. **Spec** (this file) — commit.
2. **Recorder + region naming** — `Machine::describe_addr` in `interp.rs`; the
   `Step`/write-log builder in `debug.rs`; `when`/`whenwrite`/`who` commands +
   help text. Tests: `whenwrite`/`who` on a stack slot and a map byte.
3. **`origin` def-use walk** — recursive trail with `DebugInfo` annotation.
   Test: mov->alu->store->load->exit names the originating insns in order.
4. **STATUS** — append results.

## STATUS

**Done — all four commands implemented, tested, and committed.**

- `Machine::describe_addr` (`src/interp.rs`) names a virtual address' region
  (ctx / stack frame N with fp-relative slot / map value / map object).
- `DebugSession::build_write_log` (`src/debug.rs`) rebuilds the per-step
  write-log by restoring the nearest checkpoint and replaying to the current
  position — undisturbed, echo suppressed.
- Commands: `origin <reg>` (recursive def-use trail, source-annotated),
  `when <reg>`, `whenwrite <addr|reg> [len]` (alias `ww`), `who <addr|reg>
  [len]`. Help text updated.
- Tests (`tests/dataflow.rs`, driven through `handle_command`): mov->alu->
  store->load->exit names the originating insns in order and terminates at the
  born-constant; `whenwrite`/`who` resolve a stack slot to the writing pc and
  value; `origin`/`who` reach a helper-updated map value. `cargo test` green
  in both `--features jit` and `--no-default-features`; `cargo clippy
  --all-targets` 0 warnings in both.

Deliberate limitations (documented, not blocking):

- The write-log covers **one replay interval** (`snapshot_interval`, default
  10 000 steps): a def older than the nearest checkpoint is reported "not
  written in this interval" rather than searched across the whole run. Raising
  the checkpoint density (or a future `origin --deep` that scans earlier
  intervals) would extend reach at a memory/time cost.
- Atomic `STX` records only its memory write; fetch/cmpxchg register
  destinations are not followed by `origin`.
- `origin` follows both operands of a register-register ALU op (accumulator
  first, then the second source), printing a DFS pre-order trail; it does not
  deduplicate a value reachable by two paths beyond the cycle guard.

Possible follow-ups: `origin` across interval boundaries; taint-style forward
"who reads this" queries; wiring the four commands into a one-shot CLI
(`febpf origin …`) in addition to the interactive REPL.
</content>
</invoke>
