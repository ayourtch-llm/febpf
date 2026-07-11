# febpf CO-RE (Compile Once — Run Everywhere) relocations

This document specifies febpf's support for BTF-based CO-RE relocations: the
binary formats (`.BTF`, `.BTF.ext`), the libbpf-mirroring relocation algorithm,
and the staging plan. It is the authoritative reference for `src/btf.rs` and the
CO-RE paths in `src/elf.rs`.

CO-RE lets a single compiled BPF object load against many kernels whose structs
have different layouts. clang records, per accessed field, *what* was accessed
(a type + a symbolic access path) rather than a hard-coded byte offset. At load
time the loader re-resolves each access against the **running kernel's** BTF and
patches the instruction's offset/immediate. No source recompilation.

## 1. Binary formats

All multi-byte integers follow the object's ELF endianness (`e_ident[EI_DATA]`),
same as the rest of `src/elf.rs`. In practice BPF objects are little-endian.

### 1.1 `.BTF` section — the type graph

```
struct btf_header {          // 24 bytes
    u16 magic;               // 0xEB9F
    u8  version;             // 1
    u8  flags;
    u32 hdr_len;             // usually 24
    u32 type_off;            // byte offset of type section, relative to end of header
    u32 type_len;
    u32 str_off;             // byte offset of string section, relative to end of header
    u32 str_len;
};
```

Section data begins at `hdr_len`. Type section spans
`[hdr_len+type_off, hdr_len+type_off+type_len)`; string section likewise. All
`*_off` string references throughout `.BTF` **and** `.BTF.ext` index into this
one string section.

Types are a packed array; **type ids start at 1** (id 0 is the implicit `void`).
Each type is a 12-byte header optionally followed by kind-specific trailing data:

```
struct btf_type {            // 12 bytes
    u32 name_off;
    u32 info;                // vlen:16 | unused:8 | kind:5 | unused:2 | kind_flag:1
    union { u32 size; u32 type; };   // "size" for INT/STRUCT/UNION/ENUM/ENUM64/DATASEC/FLOAT
                                     // "type" (referenced id) for PTR/TYPEDEF/CONST/… /VAR/FUNC/…
};
```

`vlen = info & 0xffff`, `kind = (info >> 24) & 0x1f`, `kind_flag = (info >> 31) & 1`.

Trailing data by kind (sizes are what the parser must skip to stay in sync — the
one fiddly invariant; getting a size wrong desyncs every following type):

| kind | # | trailing |
|------|---|----------|
| INT | 1 | 1×u32 encoding word: `bits = w & 0xff`, `offset = (w>>16)&0xff`, `encoding = (w>>24)&0xf` (SIGNED=1, CHAR=2, BOOL=4) |
| PTR | 2 | none (`type` = pointee) |
| ARRAY | 3 | `struct btf_array { u32 type; u32 index_type; u32 nelems; }` (12B) |
| STRUCT | 4 | vlen × `btf_member { u32 name_off; u32 type; u32 offset; }` (12B). If `kind_flag`: `offset` packs a bitfield — `bit_offset = offset & 0xffffff`, `bitfield_size = offset >> 24`. Else `offset` is a plain bit offset. |
| UNION | 5 | same as STRUCT |
| ENUM | 6 | vlen × `btf_enum { u32 name_off; s32 val; }` (8B). `kind_flag` ⇒ signed. `size` is the byte width. |
| FWD | 7 | none. `kind_flag`: 0=struct, 1=union. |
| TYPEDEF | 8 | none (`type`) |
| VOLATILE | 9 | none (`type`) |
| CONST | 10 | none (`type`) |
| RESTRICT | 11 | none (`type`) |
| FUNC | 12 | none (`type` = func_proto). `vlen` = linkage. |
| FUNC_PROTO | 13 | vlen × `btf_param { u32 name_off; u32 type; }` (8B) |
| VAR | 14 | `struct btf_var { u32 linkage; }` (4B) |
| DATASEC | 15 | vlen × `btf_var_secinfo { u32 type; u32 offset; u32 size; }` (12B) |
| FLOAT | 16 | none (`size`) |
| DECL_TAG | 17 | `struct btf_decl_tag { s32 component_idx; }` (4B) |
| TYPE_TAG | 18 | none (`type`) |
| ENUM64 | 19 | vlen × `btf_enum64 { u32 name_off; u32 val_lo32; u32 val_hi32; }` (12B). `size` is byte width, `kind_flag` ⇒ signed. |

vmlinux BTF has ~150k types. The parser must be linear and index named types by
name for candidate lookup (see §2).

### 1.2 `.BTF.ext` section — per-instruction metadata

```
struct btf_ext_header {
    u16 magic;               // 0xEB9F
    u8  version;
    u8  flags;
    u32 hdr_len;             // 32 when core_relo fields are present (>= 24 otherwise)
    // all offsets below are byte offsets relative to the end of this header (hdr_len)
    u32 func_info_off;   u32 func_info_len;
    u32 line_info_off;   u32 line_info_len;
    u32 core_relo_off;   u32 core_relo_len;   // only if hdr_len > 24
};
```

Each of the three sub-sections has the same envelope:

```
u32 record_size;             // size of one record; may exceed the sizes below → skip the excess
repeat until section end:
    struct btf_ext_info_sec { u32 sec_name_off; u32 num_info; }   // sec_name_off → .BTF strings (e.g. ".text")
    num_info × <record of record_size bytes>
```

Record layouts:

```
bpf_func_info { u32 insn_off; u32 type_id; }                                  // 8B
bpf_line_info { u32 insn_off; u32 file_name_off; u32 line_off; u32 line_col; }// 16B
                     //  line_col packs: line = line_col >> 10, col = line_col & 0x3ff
bpf_core_relo { u32 insn_off; u32 type_id; u32 access_str_off; u32 kind; }    // 16B
```

`insn_off` is a **byte** offset into the named section's instruction stream
(divide by 8 for an instruction index). `type_id` indexes the local `.BTF`.
`access_str_off` → `.BTF` strings.

`enum bpf_core_relo_kind`:

| value | name | based on |
|-------|------|----------|
| 0 | FIELD_BYTE_OFFSET | field |
| 1 | FIELD_BYTE_SIZE | field |
| 2 | FIELD_EXISTS | field |
| 3 | FIELD_SIGNED | field |
| 4 | FIELD_LSHIFT_U64 | field (bitfield) |
| 5 | FIELD_RSHIFT_U64 | field (bitfield) |
| 6 | TYPE_ID_LOCAL | type |
| 7 | TYPE_ID_TARGET | type |
| 8 | TYPE_EXISTS | type |
| 9 | TYPE_SIZE | type |
| 10 | ENUMVAL_EXISTS | enumval |
| 11 | ENUMVAL_VALUE | enumval |
| 12 | TYPE_MATCHES | type |

Ground-truth example (`p->x + p->y + (int)p->z` over `struct point {int x,y; long z;}`):
three core relos, all `kind=0` (BYTE_OFFSET), `type_id`=point, access strings
`"0:0"`, `"0:1"`, `"0:2"`.

## 2. The relocation algorithm (mirrors libbpf)

For each `bpf_core_relo`:

1. **Access spec** = colon-separated indices from the access string, e.g.
   `"0:1:2"` → `[0,1,2]`. The leading index is an array index applied to the
   root type (almost always 0). For type-based relos the string is `"0"`; for
   enumval-based relos it is a single enumerator index.

2. **Local spec**: starting at the local `type_id` (skipping
   typedef/const/volatile/restrict/type_tag when resolving), apply `[0]` as an
   array index, then for each remaining index walk *by member index* into
   struct/union members (or array elements), accumulating the byte offset and
   tracking the final field's type/size. This yields the values the compiler
   baked in (`orig_val`).

3. **Candidate search** (only for relos that need the target BTF — everything
   except TYPE_ID_LOCAL): the root local type has an **essential name** = its
   name with any `___flavor` suffix stripped (`task_struct___v2` → `task_struct`).
   Candidates are all target-BTF types whose essential name equals the local
   root's essential name and whose kind is compatible. Index target types by
   essential name once for O(1) lookup (vmlinux scale).

4. **Target spec** per candidate: replay the access path by **name**, not by
   index. For each local member index, take the local member's name and find the
   member of that name in the target struct (recursing into anonymous
   struct/union members, as libbpf does). Accumulate the target byte offset /
   size / signedness. For enumval relos, match the enumerator by name and read
   its value. A candidate that cannot be matched is dropped.

5. **Compute the value** (`new_val`) from the target spec by relo kind:
   - FIELD_BYTE_OFFSET → target field byte offset
   - FIELD_BYTE_SIZE → target field byte size
   - FIELD_EXISTS → 1 if matched else 0
   - FIELD_SIGNED → 1 if signed field/enum else 0
   - FIELD_LSHIFT_U64 / FIELD_RSHIFT_U64 → bitfield shift amounts (little-endian
     load-normalized; see libbpf `bpf_core_calc_field_relo`)
   - TYPE_ID_LOCAL → local type id (no target)
   - TYPE_ID_TARGET → matched target type id
   - TYPE_EXISTS / TYPE_MATCHES → 1 if a candidate matched else 0
   - TYPE_SIZE → byte size of the (target for TARGET-based, else local) type
   - ENUMVAL_EXISTS → 1 if enumerator matched else 0
   - ENUMVAL_VALUE → matched enumerator value

6. **Ambiguity rule**: every candidate that matches must yield the *same*
   `new_val`; if they disagree, the relocation is ambiguous → error. If **no**
   candidate matches: EXISTS-family relos resolve to 0; the others mark the
   instruction for **poisoning** (like libbpf): the loader replaces it with a
   call to invalid helper `0xbad2310`, so the program still loads and only
   fails — with a dedicated verifier/runtime message naming the CO-RE poison —
   if the (presumably existence-guarded) path is actually reached.

## 3. Instruction patching

libbpf `bpf_core_patch_insn`. `orig_val` (from local spec) is validated against
what the compiler actually wrote; `new_val` (from target spec) is written in:

- **ALU / ALU64**, `BPF_K`: patch `imm`. (`mov r, <off>` etc.) Validate
  `imm == orig_val` first.
- **LDX / ST / STX** (memory ops): patch the 16-bit `off`. Validate
  `off == orig_val`; error if `new_val > i16::MAX`.
- **LD (ld_imm64)**: patch the 64-bit immediate across both slots
  (`imm` = low32, next `imm` = high32). Used by TYPE_SIZE/TYPE_ID/ENUMVAL that
  may exceed 32 bits.

Validation is skipped for cases libbpf marks non-validatable (e.g. failed
FIELD_EXISTS, some bitfield shifts). Patching happens on the loaded `Vec<Insn>`
in `src/elf.rs`, before `Vm::new` — same lifecycle stage as the existing map
`ld_imm64` lowering, so the downstream verifier/interpreter/JIT need no changes.

## 4. Target BTF source

- CLI `--target-btf <path>`: raw BTF blob (a `.o`'s `.BTF` payload, or a raw
  `vmlinux` BTF such as `/sys/kernel/btf/vmlinux`).
- Default: `/sys/kernel/btf/vmlinux` when it exists **and** the object carries
  core relos. Read as a plain file (no libbpf, no deps).
- A raw `vmlinux` BTF file is just a `.BTF` blob (same `btf_header`); the parser
  is shared with the `.BTF` ELF section.

## 5. Staging plan

1. **Full BTF type graph** — `src/btf.rs`: parse every kind into a queryable
   table, index named types by name. Port the existing `.maps` extraction onto
   it. (elf.rs keeps working.)
2. **`.BTF.ext` parsing** — header + core_relo (semantic) + func_info/line_info
   (stored structurally for future source-level debugging).
3. **Relocation algorithm** — spec parse, essential-name matching, candidate
   search, per-kind value computation, ambiguity rules. Unit-tested on synthetic
   BTF; differential-tested against clang + a hand-laid-out target BTF.
4. **Instruction patching + CLI** — rewrite imm/off during load; `--target-btf`
   flag defaulting to vmlinux.

## STATUS

- Stage 0 (this spec): **done**.
- Stage 1 (BTF type graph + `.maps` port): **done** — `src/btf.rs` parses all
  19 kinds into `Btf` (type table + string table + exact-name index), with
  `resolve()` (modifier/typedef skipping), `type_size()`, `datasec()`, and
  `essential_name()`. `elf.rs::btf_maps` re-implements `.maps` extraction on
  top of it. Validated against `bpftool btf dump` on `/sys/kernel/btf/vmlinux`
  (168,815 types; all (id, name) pairs and the full task_struct member layout
  agree; parse ~56ms) in `tests/btf.rs`, plus synthetic unit tests in
  `src/btf.rs`.
- Stage 2 (`.BTF.ext`): **done** — `BtfExt` in `src/btf.rs` parses the ext
  header (24- and 32-byte variants), `core_relo` records and, structurally,
  `func_info`/`line_info` (per-annotated-section `ExtSec<T>` groups; oversized
  `record_size` tolerated). `relo_kind` constants cover all 13 CO-RE kinds.
  `elf::read_section` extracts named section payloads for standalone use.
  Fixture `examples/c/core_probe.c` (`preserve_access_index`) → committed
  `tests/core_probe.o`; `tests/btf.rs::btf_ext_of_core_probe_object` verifies
  the 3 FIELD_BYTE_OFFSET relos ("0:0"/"0:1"/"0:2" on struct point in ".text"),
  func_info (FUNC 'probe' at insn 0) and line_info against clang 21 output.
- Stage 3 (relocation algorithm): **done** — `src/relo.rs`:
  `calc_relo(local, &CoreRelo, target, &CandidateIndex) -> ReloResult
  { new_val, orig_val, validate, matched }`. Implements all 13 relo kinds:
  access-spec parse, local spec walk by member index (anonymous members fold
  into the bit offset and produce no step, as libbpf), `CandidateIndex` keyed
  by essential name, target replay by member NAME with recursive descent into
  anonymous members + `fields_compat` checks, `types_compat` (TYPE_EXISTS) and
  `types_match` (TYPE_MATCHES), bitfield byte-offset/LSHIFT/RSHIFT (LE
  formulas), ambiguity rule (all candidates must agree on `new_val`),
  EXISTS-family → 0 on no match, others hard-error. Deviations from libbpf:
  none intended; candidate root name is the type's own name (typedef roots
  match target typedefs), anonymous roots error. 11 unit tests in `src/relo.rs`
  (shifted layouts, name-vs-index, anon nesting both directions, arrays,
  bitfields, flavors, ambiguity, missing field/type, enums incl. ENUM64,
  typedef roots) + a self-relocation differential in `tests/btf.rs` (fixture's
  own BTF as target must reproduce clang's baked-in offsets).
- Stage 4 (patching + CLI): **done** —
  `elf::load_with_target_btf(bytes, Option<&[u8]>)` applies every core_relo
  to the loaded programs (per-section relos mapped onto the flat instruction
  stream, `.text` relos re-applied at each program's `text_base`);
  `patch_core_insn` handles mem-class `off` (i16 range + validation), ALU-K
  `imm`, and `lddw` (both slots), and poisons unresolvable instructions with
  `call 0xbad2310` — the verifier and interpreter report reaching one as
  "unresolved CO-RE relocation". Target BTF endianness is auto-detected from
  its magic. `elf::has_core_relocations` lets callers decide whether a target
  is needed. CLI: `--target-btf <path>` (raw blob or ELF with a `.BTF`
  section); when omitted, defaults to `/sys/kernel/btf/vmlinux` if it exists
  and the object has core relos (with a stderr note). End-to-end tests in
  `tests/elf.rs`: `core_probe.o` against a clang-compiled shifted-layout
  target BTF (`examples/c/core_target.c`) under interpreter + JIT,
  self-relocation no-op, and a running-kernel differential
  (`examples/c/core_task.c`: FIELD_BYTE_OFFSET on an ALU imm relocated
  against vmlinux must equal `bpftool`'s task_struct.pid offset).

All four stages complete. Possible follow-ups (not planned here): use the
stored func_info/line_info for source-level debugging; `bpf_core_type_id`
kernel-vs-local id spaces if kfuncs ever land; TYPE_MATCHES strictness
corner-cases (libbpf's rules for FWD↔STRUCT matching are looser than ours).
