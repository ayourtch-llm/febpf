# febpf ELF object loading

febpf loads relocatable ELF objects produced by `clang -target bpf` (`src/elf.rs`).
It is a zero-dependency ELF64 parser scoped to exactly what an eBPF loader
needs: programs, maps, and the two relocation kinds clang emits for them.

## Supported

| Feature | Detail |
|---------|--------|
| ELF64 | `ELFCLASS64`, both endians (`e_ident[EI_DATA]`); rejects non-`ET_REL`, non-`EM_BPF` (247) |
| Programs | executable `SHT_PROGBITS` sections (`SHF_EXECINSTR`) become named programs; a section containing multiple global `STT_FUNC` entries is exposed once per function; `.text` is stitched in as subprograms |
| `R_BPF_64_64` | map references in `ld_imm64` — resolved to a map index (`src=MAP_ID`) |
| `R_BPF_64_32` | bpf-to-bpf calls, incl. cross-section into `.text` (retargeted, see below) |
| Legacy maps | `struct bpf_map_def` array in a `maps` section, one symbol per map |
| BTF maps | minimal parse of BTF-defined `.maps` (the libbpf `__uint`/`__type` idiom) |
| Map types | `BPF_MAP_TYPE_HASH` (1), `BPF_MAP_TYPE_ARRAY` (2) |
| Global data | `.data`/`.data.*`, `.bss`/`.bss.*`, `.rodata*` (incl. `.rodata.str1.1`, `.rodata.cst16`) as single-entry array maps |

Multiple `SEC()` programs in one object are all exposed; the CLI selects with
`--prog <name>`. A section with one entry retains its section name (e.g.
`socket`, `xdp`; `.text` → `text`) for backward compatibility. When clang
places multiple global entry `STT_FUNC` symbols in one executable section,
each function is sliced at its symbol value/size and exposed by its symbol
name, in byte-offset then symbol-table order. The slice retains the containing
section's program type, CO-RE/BTF context classification, relocations and
debug records. Calls into `.text` still stitch that section after the slice.

## `.text` stitching (cross-section bpf-to-bpf calls)

clang places `static` helper functions in `.text` and emits an `R_BPF_64_32`
relocation on the caller's `call` instruction. Since febpf runs one flat
instruction stream per program, the loader:

1. detects that an entry section's relocations reference a `.text` symbol,
2. appends the **entire** `.text` after the entry program's instructions
   (dead subprograms are removed again by the load-time rodata DCE pass —
   see below — before the verifier's unreachable-instruction check sees them),
3. retargets the caller's `call` to the appended offset, and applies `.text`'s
   own relocations (its map references and internal calls) at that offset.

Intra-`.text` calls are PC-relative and unchanged by the shift, so a single
append handles transitive calls. Recursion and multi-level calls work; the
only bound is the runtime's 8-frame call depth.

`SHT_REL` has no explicit addend. For `R_BPF_64_32`, clang stores the addend
in the call instruction's immediate using call-displacement units. The callee
instruction offset within its defining section is therefore
`symbol.value / 8 + immediate + 1`. This matters for relocations against a
section symbol: `symbol.value` is zero and the immediate selects the actual
subprogram. For ordinary `STT_FUNC` relocations clang normally leaves `-1` in
the immediate, so the same formula selects `symbol.value / 8`.

## BTF `.maps` parsing (minimal)

febpf does **not** implement the full BTF type system — only enough to read map
definitions in the standard libbpf form:

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);   // int (*)[BPF_MAP_TYPE_ARRAY]
    __uint(max_entries, 4);             // int (*)[4]
    __type(key, u32);                   // u32 *
    __type(value, u64);                 // u64 *
} scratch SEC(".maps");
```

Parsing steps (`src/elf.rs::btf`):
1. Parse the `.BTF` section: `btf_header` (magic `0xEB9F`), then the type and
   string subsections (offsets are relative to the end of the header).
2. Walk every type, advancing correctly past each kind's trailing data
   (`STRUCT`/`UNION` members, `ARRAY`, `ENUM`/`ENUM64`, `FUNC_PROTO` params,
   `DATASEC` secinfo, `INT`/`VAR`/`DECL_TAG` words). Getting these sizes wrong
   desyncs all following types — this is the one fiddly part.
3. Find the `.maps` `DATASEC`; each entry points at a `VAR` whose type is the
   map's anonymous `STRUCT`.
4. For each struct member:
   - `type`, `max_entries`, `map_flags`, `key_size`, `value_size` are encoded as
     `PTR → ARRAY`; the value is the array's `nr_elems`.
   - `key`, `value` are `PTR → T`; the size is `sizeof(T)`.
5. Map symbols in `.symtab` (pointing into `.maps`) tie each `ld_imm64`
   relocation to a map, matched by the DATASEC var offset (with a name-based
   fallback).

Cross-checked against `bpftool btf dump file <obj>`.

## Global data sections

Each allocatable, non-executable `.data*`/`.bss*`/`.rodata*` section becomes a
single-entry array map (`key_size=4`, `value_size=` section size,
`max_entries=1`), matching libbpf's internal-map model:

- The section contents become the map's initial value (`MapDef::init`);
  `.bss` is `SHT_NOBITS` and is zero-filled.
- `.rodata*` maps are **frozen** (`MapDef::readonly`): the verifier rejects
  stores through their value pointers and `map_update/delete_elem` on them,
  and the runtime independently rejects writes (so `--no-verify` and the JIT
  are covered too). Runtime update/delete return `-EPERM`, as the kernel does
  for frozen maps.
- `R_BPF_64_64` relocations whose symbol lives in a data section (clang emits
  section symbols with the addend stored in the instruction's `imm`) are
  lowered to `BPF_PSEUDO_MAP_VALUE` lddw: `imm` = map index, second `imm` =
  `sym.value + addend` (byte offset into the value). `Vm::new` patches these
  to a virtual address pointing into the map's storage, and the verifier
  types them as `PTR_TO_MAP_VALUE` with that constant offset.

This is what makes ordinary clang-compiled C — string literals, lookup
tables, persistent counters in globals — load and run unmodified.

## Kconfig externs (`.kconfig`)

libbpf models `extern ... __kconfig` variables (`LINUX_KERNEL_VERSION`,
`CONFIG_*`) as a virtual read-only `.kconfig` internal map. In the object the
extern is an **UNDefined** ELF symbol (value 0, section UND) whose type lives
in a BTF `.kconfig` DATASEC — so `R_BPF_64_64` relocations against it cannot
be resolved by section index like data-section symbols. febpf mirrors libbpf
(`elf.rs::load_kconfig_map`):

- The `.kconfig` DATASEC's extern VARs are laid out sequentially with natural
  alignment (the object's DATASEC offsets are all 0 — libbpf assigns them at
  load time, and so do we) into a synthetic frozen single-entry array map
  named `.kconfig`.
- Relocations against UND symbols resolve **by name** to
  `BPF_PSEUDO_MAP_VALUE` pointers at the extern's assigned offset
  (`MapRef::Data { idx, base }` — `base` is 0 for ordinary data-section
  symbols).
- Values: `LINUX_KERNEL_VERSION` is filled with `KERNEL_VERSION(a,b,c)` of
  the running kernel (patch clamped to 255, like libbpf), read from
  `/proc/sys/kernel/osrelease` — host-dependent in exactly the way the
  default `--target-btf /sys/kernel/btf/vmlinux` already is; a fixed 6.1.0
  fallback applies when /proc is unavailable (non-Linux, wasm). Other
  `CONFIG_*` externs are zero-filled — febpf does not parse kernel configs,
  and 0 is what libbpf gives an unset *weak* kconfig extern. (A strong unset
  extern would fail libbpf's load; febpf's zero-fill is deliberately more
  tolerant, since it is an analysis engine.)

This was the root cause of the `LOAD-FAIL:relocation` corpus failures
(bcc `biosnoop`/`bitesize`/`capable`): "map relocation for unknown symbol
'LINUX_KERNEL_VERSION'". Fixture: `examples/c/kconfig.c` / `tests/kconfig.o`.

## Tolerated omissions in BTF map defs

A BTF map def may omit `max_entries` entirely (libbpf leaves it 0 and the
loader app sets it via `bpf_map__set_max_entries` before load — bcc's
`cpudist` does this). febpf defaults it to `DEFAULT_MAX_ENTRIES` (10240,
bcc's usual value) instead of rejecting the object. This was the
`LOAD-FAIL:other` corpus failure ("map 'start': missing max_entries").

## Load-time dead-code elimination (rodata DCE)

After CO-RE relocation, each program runs through the frozen-`.rodata`
dead-code-elimination pass (`src/dce.rs`, `docs/specs/rodata-dce.md`) —
febpf's equivalent of what libbpf does before handing a program to the
kernel. Branches decided by `const volatile` config values in frozen
`.rodata` are resolved and the code they prove dead is removed — including
subprograms stitched in from `.text` that the entry point never calls, which
would otherwise trip the verifier's unreachable-instruction check. Line/func
debug info is remapped through the pass's old→new pc map.

## CO-RE relocations

`elf::load_with_target_btf` applies `.BTF.ext` CO-RE relocations against a
target BTF; the CLI exposes `--target-btf` and defaults to
`/sys/kernel/btf/vmlinux`. Full BTF parsing lives in `src/btf.rs`, the
relocation algorithm in `src/relo.rs` — see `docs/specs/core-relocations.md`.
`func_info`/`line_info` are parsed and stored but not yet surfaced
(future source-level debugging).

## Not supported (yet)

- Map types beyond hash/array (per-CPU, LRU, ringbuf, maps-of-maps, …).
- `R_BPF_64_ABS64`/`ABS32`/`NODYLD32` relocations.
- Static linking of multiple objects.

## Fixtures & testing

`examples/c/*.c` are compiled to committed `tests/*.o` fixtures. Ordinary
tests are read-only and consume those objects as-is. Explicitly run
`FEBPF_REGENERATE_FIXTURES=1 cargo test` with a BPF-capable clang to rebuild
them; regeneration stages to unique temporary files and installs only complete
objects. The tests assert the loaded maps/programs and run each under both the
interpreter and the JIT, requiring identical results.
