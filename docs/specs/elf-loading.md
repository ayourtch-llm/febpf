# febpf ELF object loading

febpf loads relocatable ELF objects produced by `clang -target bpf` (`src/elf.rs`).
It is a zero-dependency ELF64 parser scoped to exactly what an eBPF loader
needs: programs, maps, and the two relocation kinds clang emits for them.

## Supported

| Feature | Detail |
|---------|--------|
| ELF64 | `ELFCLASS64`, both endians (`e_ident[EI_DATA]`); rejects non-`ET_REL`, non-`EM_BPF` (247) |
| Programs | every executable `SHT_PROGBITS` section (`SHF_EXECINSTR`) becomes a named program; `.text` is stitched in as subprograms |
| `R_BPF_64_64` | map references in `ld_imm64` — resolved to a map index (`src=MAP_ID`) |
| `R_BPF_64_32` | bpf-to-bpf calls, incl. cross-section into `.text` (retargeted, see below) |
| Legacy maps | `struct bpf_map_def` array in a `maps` section, one symbol per map |
| BTF maps | minimal parse of BTF-defined `.maps` (the libbpf `__uint`/`__type` idiom) |
| Map types | `BPF_MAP_TYPE_HASH` (1), `BPF_MAP_TYPE_ARRAY` (2) |

Multiple `SEC()` programs in one object are all exposed; the CLI selects with
`--prog <name>` (section name, e.g. `socket`, `xdp`; `.text` → `text`).

## `.text` stitching (cross-section bpf-to-bpf calls)

clang places `static` helper functions in `.text` and emits an `R_BPF_64_32`
relocation on the caller's `call` instruction. Since febpf runs one flat
instruction stream per program, the loader:

1. detects that an entry section's relocations reference a `.text` symbol,
2. appends the **entire** `.text` after the entry program's instructions
   (dead subprograms are harmless — the verifier only explores reachable code),
3. retargets the caller's `call` to the appended offset, and applies `.text`'s
   own relocations (its map references and internal calls) at that offset.

Intra-`.text` calls are PC-relative and unchanged by the shift, so a single
append handles transitive calls. Recursion and multi-level calls work; the
only bound is the runtime's 8-frame call depth.

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

## Not supported (yet)

- Full BTF (func/line info, CO-RE relocations, `.BTF.ext`).
- Map types beyond hash/array (per-CPU, LRU, ringbuf, maps-of-maps, …).
- Global data sections (`.bss`/`.data`/`.rodata`) as maps.
- `R_BPF_64_ABS64`/`ABS32`/`NODYLD32` relocations.
- Static linking of multiple objects.

## Fixtures & testing

`examples/c/*.c` are compiled to `tests/*.o` fixtures. `tests/elf.rs`
regenerates them with clang when available (otherwise uses the committed
`.o`), then asserts the loaded maps/programs and runs each under both the
interpreter and the JIT, requiring identical results.
