# Source-level debugging

Surface the `.BTF.ext` **func_info** and **line_info** (already parsed
structurally by `btf::BtfExt`, see `docs/specs/core-relocations.md`) plus the
`.BTF` type graph so febpf can debug, disassemble and profile at the level of
**C source**, and read **global variables by name** with typed rendering.

This is wow-list item #3 in HANDOFF.md. Nothing new is parsed off disk — the
raw records already load; this work builds a lookup structure over them and
threads it into the debugger, disassembler and analysis output.

## What clang gives us (for free, with `-g`)

`bpf_line_info { insn_off, file_name_off, line_off, line_col }`:

- `insn_off` — **byte** offset of the annotated instruction *within its ELF
  section* (÷ `INSN_SIZE` = instruction index in that section).
- `file_name_off` — offset into the **`.BTF` string table** of the file path.
- `line_off` — offset into the `.BTF` string table of the **source line text
  itself** (clang embeds the actual C line — we do *not* need the `.c` file).
- `line_col` — `line << 10 | col` (`LineInfo::line()` / `::col()`).

`bpf_func_info { insn_off, type_id }`: `type_id` is a BTF `FUNC` whose name is
the subprogram name (e.g. `triple`, `use_globals`). Marks subprogram
boundaries.

`.BTF` `DATASEC` + `VAR` types: each data section (`.bss`/`.data`/`.rodata`)
lists its variables as `(VAR type_id, offset, size)`; the `VAR`'s inner type is
the variable's C type. This is how we resolve `print counter`.

## Instruction-index mapping (the one subtlety)

`.BTF.ext` records are grouped per **ELF section** and use per-section byte
offsets. A febpf *program* is one entry section at instruction 0, optionally
followed by a **stitched copy of `.text`** at `text_base` (see `elf.rs`
`build_program`). So the flat program instruction index of a record is:

```
section == entry section : idx = insn_off / INSN_SIZE
section == ".text"        : idx = text_base + insn_off / INSN_SIZE   (if stitched)
other section             : not part of this program — skip
```

This mirrors `apply_core_relocations` exactly; `build_debug_info` reuses the
same `(sec_name, text_base)` the loader already computes per program.

## Data structures (`src/debuginfo.rs`, new module)

```rust
pub struct SourceLine { pub insn: usize, pub file: String, pub line: u32,
                        pub col: u32, pub text: String }
pub struct FuncBound  { pub insn: usize, pub name: String }
pub struct GlobalVar  { pub name: String, pub map: usize, pub map_name: String,
                        pub offset: u32, pub type_id: u32 }

pub struct DebugInfo {                 // owns a clone of the local Btf
    btf: Btf,
    lines: Vec<SourceLine>,            // sorted by .insn (flat index)
    funcs: Vec<FuncBound>,             // sorted by .insn
    globals: Vec<GlobalVar>,
}
```

Lookups are `addr2line`-style: a record covers instructions from its `insn`
until the next record's `insn`.

- `line_at(insn) -> Option<&SourceLine>` — greatest record with `insn <= q`
  (`partition_point`), `None` before the first.
- `func_at(insn) -> Option<&FuncBound>` — same shape (subprogram containing q).
- `global(name) -> Option<&GlobalVar>`, `globals()`, `lines()`.
- `render_value(type_id, bytes) -> String` — typed rendering through the BTF
  graph (below).

`DebugInfo` is **static** for a run, so it is *not* part of `Snapshot`; it hangs
off the `Vm` (new `Vm::debug: Option<DebugInfo>`, default `None`, set via
`Vm::set_debug`). `Program` is left as `{insns, maps}` so no constructor call
site changes. The ELF loader attaches it: `LoadedProgram` gains
`debug: Option<DebugInfo>`; `main.rs::load_program` calls `vm.set_debug(..)`.

### Typed value rendering (`render_value`)

Resolve modifiers/typedefs, then, one level deep:

| kind | rendering |
|------|-----------|
| Int | signed/unsigned per encoding & size; `bool`→true/false; `char`→'c' |
| Ptr | `0x…` (8 bytes) |
| Enum | matching enumerator name, else the numeric value |
| Array | `[e0, e1, …]` — elements rendered; nested aggregate ⇒ `[…]` |
| Struct/Union | `{ field: val, … }` — nested aggregate ⇒ `{…}` |
| Float | 4/8-byte f32/f64 |
| other | raw hex bytes |

Depth is capped at one level of aggregate nesting (per the task): deeper
structs/arrays render as `{…}` / `[…]`.

## REPL additions (`DebugSession`, TTY-free)

All go through `handle_command(line, out)` so they stay testable.

- **Current source line** — the position banner printed after `step`/`continue`
  /`rstep`/etc. gains a source line when debug info is present:
  ```
  use_globals:15  bss_counter += ro_table[idx];        /* .bss   */
    12:  r1 = *(u64*)(r10 - 8)
  ```
  i.e. `func:line  <source text>` above the disassembled instruction.
- **`list` / `l`** — when debug info is present, show a window of **source
  lines** around the current C line (with `=>` on the current one) in addition
  to the instruction view.
- **`steps` / `nexts`** — source-level stepping.
  - `steps [N]` (step *into*): step instructions until the covering
    `(file,line)` changes (N times); descends into called subprograms.
  - `nexts [N]` (step *over*): like `steps` but ignores line changes while the
    call frame is deeper than the start frame (steps over bpf-to-bpf calls).
  Both stop at program exit/error. Built on the existing `step_once`.
- **`rsteps [N]`** (bonus, reverse source step): compose with time travel —
  from the current `insn_count`, `goto_count` backward until the covering
  source line differs (or count 0). Uses the deterministic replay already in
  place.
- **`print <name>` / `p <name>`** — read a global by name: resolve
  `GlobalVar` → its data-section map region → bytes at `offset` →
  `render_value`. Prints `name: type = value`. `print` with no arg lists all
  known globals.
- **`bt` / `backtrace`** — subprogram call stack with function names, using the
  new `Machine::backtrace_pcs()` (current pc + each saved frame's `ret_pc-1`)
  mapped through `func_at` and `line_at`.

## Disassembler / analysis integration

- `analysis::heatmap_listing` and `annotated_listing` gain an optional
  `debug: Option<&DebugInfo>`; when present they interleave a `; file:line:
  text` comment whenever the source line changes (addr2line-style), so the
  profile heatmap and verifier listing read against C.
- New `analysis::source_listing(insns, Option<&DebugInfo>)` — a plain
  source-interleaved disassembly (used by `febpf disasm` when the object has
  line info, and available to tools).
- `main.rs`: `disasm` interleaves source when available; `profile` passes the
  debug info to the heatmap; `debug` sets it on the Vm.

## Testing bar (differential, per HANDOFF)

clang 21 + committed `.o` fixtures.

1. **Line info at known insns** — compile `subprog.c` / `global_data.c` with
   `-g`; assert `line_at(idx)` yields the expected C text at specific
   instruction indices (cross-checked with `llvm-objdump -S`, whose interleaved
   source comes from the same `.BTF.ext`). Assert `.text` records land at
   `text_base`, not offset 0 (the stitching subtlety).
2. **Func boundaries** — `func_at` returns `use_globals` in the entry range and
   `triple`/subprogram names inside stitched `.text`.
3. **Globals by name** — a dedicated `examples/c/globals.c` with typed globals
   in `.data`/`.bss` (int, unsigned, array, struct). Drive `print` through
   `DebugSession::handle_command` and assert the rendered values after the
   program mutates them; a raw-hex cross-check via `x`.
4. **Source stepping** — `steps`/`nexts` land on the expected next C line;
   `nexts` steps over the `triple` call in `subprog.o` while `steps` enters it.
5. **Unit** — `DebugInfo` built from a hand-assembled `.BTF`+`.BTF.ext`
   (reusing `btf::tests::build_btf`) for line/func lookup and `render_value`
   edge cases, independent of clang.

## Staged plan (one commit per stage, tests+clippy green each)

1. **Spec** (this file) — commit.
2. **`debuginfo.rs` + ELF surfacing** — `DebugInfo`, lookup, `render_value`;
   `build_debug_info` in `elf.rs`; `LoadedProgram.debug`; `Vm::debug` +
   `set_debug`; `Machine::backtrace_pcs`; `main.rs` wiring. Unit tests
   (stage-5 items 1-3, 5).
3. **Debugger integration** — source in the position banner, `list`, `print`,
   `bt`, `steps`/`nexts`/`rsteps`. Tests drive `handle_command`.
4. **Disasm/analysis integration** — source interleaving in
   `heatmap_listing`/`annotated_listing`/`source_listing`; `main.rs` wiring.
5. **STATUS** — update this section (done / remaining / next step).

## STATUS

**Done — all stages implemented and committed.** `cargo test` 116 green,
`cargo clippy --all-targets` 0 warnings.

- Stage 2 — `src/debuginfo.rs` (`DebugInfo` with `line_at`/`func_at`/`global`
  lookups and `render_value` one aggregate level deep); `elf.rs`
  `build_debug_info` translating per-section `.BTF.ext` offsets to flat
  instruction indices (entry at 0, stitched `.text` at `text_base`);
  `LoadedProgram.debug`; `Vm::{set_debug,debug}` (not snapshotted);
  `Machine::backtrace_pcs`; `main.rs` wiring.
- Stage 3 — debugger: source line + function in the position banner, `list`
  source interleaving, `print`/`p <name>` typed globals (list with no arg),
  `bt`/`backtrace`, `steps`/`nexts` (into/over), and `rsteps` reverse source
  step composing with time travel.
- Stage 4 — `analysis::source_listing` plus optional `debug` arg on
  `heatmap_listing`/`annotated_listing`; `febpf disasm` interleaves source
  when the object has line info, `profile` and `analyze` show C against the
  heatmap / verifier listing.

Tests: `src/debuginfo.rs` unit tests (lookup + rendering, clang-independent)
and `tests/sourcedebug.rs` differential against `subprog.o` (line text, `.text`
stitching offset, func boundaries, steps-into vs nexts-over, two-level
backtrace, rsteps, analysis interleaving) and `global_data.o` (globals
metadata + typed `print` after a run).

Deviations / notes:

- `.rodata` globals: clang emits a single `.rodata` DATASEC but the ELF splits
  const data across `.rodata.cst16` / `.rodata.str1.1`; globals in merged
  rodata are matched best-effort to the first `.rodata*` map (offsets across
  multiple rodata sections could be ambiguous). `.bss`/`.data` globals match
  exactly. `ro_table` resolves to `.rodata.cst16` and renders correctly.
- `render_value` renders one aggregate level deep by design (per the task);
  nested structs/arrays show `{…}` / `[…]`. Bitfield members are skipped.
- `rsteps` (reverse source step) is implemented (was flagged as optional
  bonus); it decrements the instruction count via `goto_count` until the
  covering line changes, reusing the deterministic replay.

Possible follow-ups (not required): DWARF `.debug_line` fallback for objects
without embedded `.BTF.ext` line text; reading locals/args by name (needs
stack-slot debug info clang does not emit for BPF today); `list <func>` by
name; column-accurate source carets.
