//! Loader for `clang -target bpf` relocatable objects (ELF64, `EM_BPF`).
//!
//! Zero-dependency ELF64 parser supporting the pieces febpf needs:
//! - section / symbol / string tables,
//! - executable `SHT_PROGBITS` sections as programs,
//! - `R_BPF_64_64` relocations (map references in `ld_imm64`) and
//!   `R_BPF_64_32` (cross-section bpf-to-bpf calls),
//! - map definitions from either the legacy `maps` section
//!   (`struct bpf_map_def`) or a minimal parse of BTF-defined `.maps`.
//!
//! BTF-defined maps are read through the full BTF type graph in
//! [`crate::btf`], using the standard libbpf `.maps` idiom (`__uint`/`__type`
//! members encoded as pointer-to-array and pointer-to-type).
//! See `docs/specs/elf-loading.md`.

use crate::insn::{self, Insn};
use crate::maps::{MapDef, MapKind};

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;
const ET_REL: u16 = 1;
const EM_BPF: u16 = 247;

const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_REL: u32 = 9;
const SHT_NOBITS: u32 = 8;

const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;

// BPF relocation types.
const R_BPF_64_64: u32 = 1;
const R_BPF_64_32: u32 = 10;

// Legacy BPF map types we support.
const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;

/// One program (executable section) from an object.
pub struct LoadedProgram {
    pub name: String,
    pub insns: Vec<Insn>,
}

/// The result of loading an object file.
pub struct Object {
    pub programs: Vec<LoadedProgram>,
    pub maps: Vec<MapDef>,
}

/// Little/big-endian aware byte reader over a borrowed buffer.
struct Reader<'a> {
    buf: &'a [u8],
    le: bool,
}

impl<'a> Reader<'a> {
    fn u16(&self, off: usize) -> Result<u16, String> {
        let b: [u8; 2] = self
            .buf
            .get(off..off + 2)
            .ok_or("truncated (u16)")?
            .try_into()
            .unwrap();
        Ok(if self.le {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    }
    fn u32(&self, off: usize) -> Result<u32, String> {
        let b: [u8; 4] = self
            .buf
            .get(off..off + 4)
            .ok_or("truncated (u32)")?
            .try_into()
            .unwrap();
        Ok(if self.le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }
    fn u64(&self, off: usize) -> Result<u64, String> {
        let b: [u8; 8] = self
            .buf
            .get(off..off + 8)
            .ok_or("truncated (u64)")?
            .try_into()
            .unwrap();
        Ok(if self.le {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        })
    }
}

#[derive(Clone)]
struct Section {
    name: String,
    kind: u32,
    flags: u64,
    offset: usize,
    size: usize,
    link: u32,
    info: u32,
    entsize: usize,
}

#[derive(Clone)]
struct Symbol {
    name: String,
    value: u64,
    shndx: u16,
    #[allow(dead_code)]
    size: u64,
}

struct Relocation {
    offset: u64,
    sym: u32,
    kind: u32,
}

/// Validate the ELF64/EM_BPF header and parse the section table.
fn parse_elf(bytes: &[u8]) -> Result<(Reader<'_>, Vec<Section>), String> {
    if bytes.len() < 64 || &bytes[0..4] != ELF_MAGIC {
        return Err("not an ELF file".into());
    }
    if bytes[4] != ELFCLASS64 {
        return Err("only ELF64 is supported".into());
    }
    let le = match bytes[5] {
        ELFDATA2LSB => true,
        ELFDATA2MSB => false,
        _ => return Err("invalid ELF endianness".into()),
    };
    let r = Reader { buf: bytes, le };

    if r.u16(16)? != ET_REL {
        return Err("expected a relocatable object (ET_REL)".into());
    }
    if r.u16(18)? != EM_BPF {
        return Err("not a BPF object (e_machine != EM_BPF)".into());
    }

    let shoff = r.u64(40)? as usize;
    let shentsize = r.u16(58)? as usize;
    let shnum = r.u16(60)? as usize;
    let shstrndx = r.u16(62)? as usize;

    if shentsize < 64 {
        return Err("unexpected section header size".into());
    }

    // section-header string table
    let shstr_off = r.u64(shoff + shstrndx * shentsize + 24)? as usize;
    let shstr_size = r.u64(shoff + shstrndx * shentsize + 32)? as usize;
    let shstrtab = bytes
        .get(shstr_off..shstr_off + shstr_size)
        .ok_or("bad section string table")?;

    let mut sections = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let base = shoff + i * shentsize;
        let name_off = r.u32(base)? as usize;
        sections.push(Section {
            name: cstr(shstrtab, name_off),
            kind: r.u32(base + 4)?,
            flags: r.u64(base + 8)?,
            offset: r.u64(base + 24)? as usize,
            size: r.u64(base + 32)? as usize,
            link: r.u32(base + 40)?,
            info: r.u32(base + 44)?,
            entsize: r.u64(base + 56)? as usize,
        });
    }
    Ok((r, sections))
}

/// Extract a named section's payload from a BPF ELF object (e.g. `.BTF`,
/// `.BTF.ext`). Returns `Ok(None)` if the section is absent. The second
/// element of the pair reports the object's endianness (little = true).
pub fn read_section(bytes: &[u8], name: &str) -> Result<Option<(Vec<u8>, bool)>, String> {
    let (r, sections) = parse_elf(bytes)?;
    match sections.iter().position(|s| s.name == name && s.size > 0) {
        Some(i) => Ok(Some((section_bytes(bytes, &sections, i)?.to_vec(), r.le))),
        None => Ok(None),
    }
}

/// Parse and relocate a BPF object file.
pub fn load(bytes: &[u8]) -> Result<Object, String> {
    let (r, sections) = parse_elf(bytes)?;
    let bytes = r.buf;

    // symbol table + its string table
    let symtab_idx = sections
        .iter()
        .position(|s| s.kind == SHT_SYMTAB)
        .ok_or("no symbol table")?;
    let symstr_idx = sections[symtab_idx].link as usize;
    let symstr = section_bytes(bytes, &sections, symstr_idx)?;
    let symbols = parse_symbols(&r, bytes, &sections[symtab_idx], symstr)?;

    // maps: prefer BTF-defined `.maps`, else the legacy `maps` section.
    let (mut maps, mut map_by_symval) = load_maps(&r, bytes, &sections, &symbols)?;

    // Global data sections become single-entry array maps; `ld_imm64`
    // relocations against their symbols resolve to value pointers.
    load_data_maps(bytes, &sections, &mut maps, &mut map_by_symval)?;

    // The `.text` section holds subprograms that entry sections call into via
    // `R_BPF_64_32` relocations. We stitch all of `.text` onto the end of any
    // program that references it and retarget the calls (see `build_program`).
    let text_idx = sections
        .iter()
        .position(|s| s.name == ".text" && s.kind == SHT_PROGBITS && s.size > 0);
    let text_insns = match text_idx {
        Some(i) => insn::decode_program(section_bytes(bytes, &sections, i)?)?,
        None => Vec::new(),
    };

    let entry_sections: Vec<usize> = sections
        .iter()
        .enumerate()
        .filter(|(_, s)| {
            s.kind == SHT_PROGBITS
                && s.flags & SHF_EXECINSTR != 0
                && s.size > 0
                && s.name != ".text"
        })
        .map(|(i, _)| i)
        .collect();

    let mut programs = Vec::new();
    for idx in &entry_sections {
        let sec = &sections[*idx];
        let insns = build_program(
            &r,
            bytes,
            &sections,
            *idx,
            text_idx,
            &text_insns,
            &symbols,
            &map_by_symval,
        )?;
        programs.push(LoadedProgram {
            name: sec.name.clone(),
            insns,
        });
    }

    // If there are no SEC()-annotated entry programs, expose `.text` itself.
    if programs.is_empty() {
        if let Some(ti) = text_idx {
            let insns = build_program(
                &r, bytes, &sections, ti, text_idx, &text_insns, &symbols, &map_by_symval,
            )?;
            programs.push(LoadedProgram {
                name: "text".into(),
                insns,
            });
        }
    }
    if programs.is_empty() {
        return Err("no executable program sections found".into());
    }

    Ok(Object { programs, maps })
}

/// Build one runnable program from entry section `idx`, appending `.text`
/// subprograms and fixing up call targets when the entry calls into `.text`.
#[allow(clippy::too_many_arguments)]
fn build_program(
    r: &Reader,
    bytes: &[u8],
    sections: &[Section],
    idx: usize,
    text_idx: Option<usize>,
    text_insns: &[Insn],
    symbols: &[Symbol],
    map_by_symval: &MapIndex,
) -> Result<Vec<Insn>, String> {
    let raw = section_bytes(bytes, sections, idx)?;
    let mut insns = insn::decode_program(raw)?;

    // Does this section call into `.text`? If so, append it once.
    let calls_text = match text_idx {
        Some(ti) => section_reloc_targets_section(r, sections, idx, symbols, ti)?,
        None => false,
    };
    let is_text_itself = Some(idx) == text_idx;
    let text_base = if calls_text && !is_text_itself {
        let base = insns.len();
        insns.extend_from_slice(text_insns);
        Some(base)
    } else if is_text_itself {
        Some(0)
    } else {
        None
    };

    // Relocations for the entry section (code at offset 0).
    apply_relocations(r, sections, idx, symbols, map_by_symval, text_idx, 0, text_base, &mut insns)?;
    // Relocations for the appended `.text` (code at offset `text_base`).
    if let (Some(ti), Some(base)) = (text_idx, text_base) {
        if !is_text_itself {
            apply_relocations(
                r, sections, ti, symbols, map_by_symval, text_idx, base, text_base, &mut insns,
            )?;
        }
    }
    Ok(insns)
}

/// Does section `sec_idx`'s relocation table reference any symbol defined in
/// section `wanted`? (Used to detect calls into `.text`.)
fn section_reloc_targets_section(
    r: &Reader,
    sections: &[Section],
    sec_idx: usize,
    symbols: &[Symbol],
    wanted: usize,
) -> Result<bool, String> {
    let Some(rel) = sections
        .iter()
        .find(|s| s.kind == SHT_REL && s.info as usize == sec_idx)
    else {
        return Ok(false);
    };
    let entsize = if rel.entsize == 0 { 16 } else { rel.entsize };
    for i in 0..rel.size / entsize {
        let base = rel.offset + i * entsize;
        let sym_idx = (r.u64(base + 8)? >> 32) as usize;
        if let Some(sym) = symbols.get(sym_idx) {
            if sym.shndx as usize == wanted {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn parse_symbols(
    r: &Reader,
    _bytes: &[u8],
    symtab: &Section,
    symstr: &[u8],
) -> Result<Vec<Symbol>, String> {
    let entsize = if symtab.entsize == 0 {
        24
    } else {
        symtab.entsize
    };
    let count = symtab.size / entsize;
    let mut syms = Vec::with_capacity(count);
    for i in 0..count {
        let base = symtab.offset + i * entsize;
        let name_off = r.u32(base)? as usize;
        syms.push(Symbol {
            name: cstr(symstr, name_off),
            shndx: r.u16(base + 6)?,
            value: r.u64(base + 8)?,
            size: r.u64(base + 16)?,
        });
    }
    Ok(syms)
}

/// Apply the relocation table for section `target_idx` onto `insns`, where
/// that section's code begins at instruction `code_base`. Cross-section calls
/// into `.text` are retargeted to `text_base` (the offset at which `.text` was
/// appended).
#[allow(clippy::too_many_arguments)]
fn apply_relocations(
    r: &Reader,
    sections: &[Section],
    target_idx: usize,
    symbols: &[Symbol],
    map_by_symval: &MapIndex,
    text_idx: Option<usize>,
    code_base: usize,
    text_base: Option<usize>,
    insns: &mut [Insn],
) -> Result<(), String> {
    let Some(rel) = sections
        .iter()
        .find(|s| s.kind == SHT_REL && s.info as usize == target_idx)
    else {
        return Ok(());
    };
    let entsize = if rel.entsize == 0 { 16 } else { rel.entsize };
    let count = rel.size / entsize;
    for i in 0..count {
        let base = rel.offset + i * entsize;
        let reloc = Relocation {
            offset: r.u64(base)?,
            sym: (r.u64(base + 8)? >> 32) as u32,
            kind: (r.u64(base + 8)? & 0xffff_ffff) as u32,
        };
        let sym = symbols
            .get(reloc.sym as usize)
            .ok_or("relocation references invalid symbol")?;
        let insn_idx = code_base + reloc.offset as usize / insn::INSN_SIZE;
        if insn_idx >= insns.len() {
            return Err(format!("relocation offset {} out of range", reloc.offset));
        }
        match reloc.kind {
            R_BPF_64_64 => {
                // ld_imm64 map or global-data reference.
                if insn_idx + 1 >= insns.len() {
                    return Err(format!("ld_imm64 relocation at {insn_idx} truncated"));
                }
                match map_by_symval.resolve(sym) {
                    Some(MapRef::Obj(map_idx)) => {
                        insns[insn_idx].src = insn::pseudo::MAP_ID;
                        insns[insn_idx].imm = map_idx as i32;
                        insns[insn_idx + 1].imm = 0;
                    }
                    Some(MapRef::Data(map_idx)) => {
                        // Pointer into the section's value: symbol offset plus
                        // the addend clang stored in the instruction's imm.
                        let off = (sym.value as u32).wrapping_add(insns[insn_idx].imm as u32);
                        insns[insn_idx].src = insn::pseudo::MAP_VALUE;
                        insns[insn_idx].imm = map_idx as i32;
                        insns[insn_idx + 1].imm = off as i32;
                    }
                    None => {
                        return Err(format!(
                            "map relocation for unknown symbol '{}'",
                            sym.name
                        ));
                    }
                }
            }
            R_BPF_64_32 => {
                // bpf-to-bpf call. The callee symbol lives in `.text` (or in
                // this same section); its value is a byte offset there.
                let callee_off = sym.value as usize / insn::INSN_SIZE;
                let target = if Some(sym.shndx as usize) == text_idx {
                    let tb = text_base.ok_or("call into .text but .text not stitched in")?;
                    tb + callee_off
                } else {
                    // same-section call
                    code_base + callee_off
                };
                let disp = target as i64 - insn_idx as i64 - 1;
                insns[insn_idx].imm = disp as i32;
                insns[insn_idx].src = insn::call_kind::LOCAL;
            }
            other => {
                return Err(format!(
                    "unsupported relocation type {other} at insn {insn_idx}"
                ));
            }
        }
    }
    Ok(())
}

/// What a `R_BPF_64_64` relocation symbol refers to.
enum MapRef {
    /// A map object (declared in `maps`/`.maps`): lddw a map pointer.
    Obj(usize),
    /// A global-data section mapped as a single-entry array map: lddw a
    /// pointer into its value (the symbol offset is added by the caller).
    Data(usize),
}

/// Maps a relocation symbol to a map reference.
struct MapIndex {
    /// (symbol value, section) → map index, for symbols in `maps`/`.maps`.
    by_offset: Vec<(u64, u16, usize)>,
    /// data section index → map index, for symbols in `.data`/`.rodata`/`.bss`.
    data_secs: Vec<(u16, usize)>,
}

impl MapIndex {
    fn resolve(&self, sym: &Symbol) -> Option<MapRef> {
        if let Some((_, _, idx)) = self
            .by_offset
            .iter()
            .find(|(val, shndx, _)| *val == sym.value && *shndx == sym.shndx)
        {
            return Some(MapRef::Obj(*idx));
        }
        self.data_secs
            .iter()
            .find(|(shndx, _)| *shndx == sym.shndx)
            .map(|(_, idx)| MapRef::Data(*idx))
    }
}

fn load_maps(
    r: &Reader,
    bytes: &[u8],
    sections: &[Section],
    symbols: &[Symbol],
) -> Result<(Vec<MapDef>, MapIndex), String> {
    // Prefer BTF `.maps`.
    if let Some(dotmaps_idx) = sections.iter().position(|s| s.name == ".maps") {
        if let Some(btf_idx) = sections.iter().position(|s| s.name == ".BTF") {
            let btf = section_bytes(bytes, sections, btf_idx)?;
            return btf_maps::load_btf_maps(r.le, btf, sections, symbols, dotmaps_idx);
        }
    }
    // Legacy `maps` section.
    if let Some(maps_idx) = sections.iter().position(|s| s.name == "maps") {
        return load_legacy_maps(r, bytes, sections, symbols, maps_idx);
    }
    Ok((
        Vec::new(),
        MapIndex {
            by_offset: Vec::new(),
            data_secs: Vec::new(),
        },
    ))
}

/// Is this a global data section we expose as a map?
fn is_data_section(s: &Section) -> bool {
    (s.kind == SHT_PROGBITS || s.kind == SHT_NOBITS)
        && s.flags & SHF_ALLOC != 0
        && s.flags & SHF_EXECINSTR == 0
        && s.size > 0
        && (s.name == ".data"
            || s.name.starts_with(".data.")
            || s.name == ".bss"
            || s.name.starts_with(".bss.")
            || s.name.starts_with(".rodata"))
}

/// Expose `.data`/`.rodata*`/`.bss` sections as single-entry array maps,
/// initialized with the section contents (`.bss` is zero-filled). `.rodata`
/// maps are frozen: the verifier and the runtime both reject writes.
fn load_data_maps(
    bytes: &[u8],
    sections: &[Section],
    maps: &mut Vec<MapDef>,
    index: &mut MapIndex,
) -> Result<(), String> {
    for (i, sec) in sections.iter().enumerate() {
        if !is_data_section(sec) {
            continue;
        }
        let init = if sec.kind == SHT_NOBITS {
            Vec::new() // .bss occupies no file space; storage is zero-filled
        } else {
            section_bytes(bytes, sections, i)?.to_vec()
        };
        index.data_secs.push((i as u16, maps.len()));
        maps.push(MapDef {
            name: sec.name.clone(),
            kind: MapKind::Array,
            key_size: 4,
            value_size: sec.size as u32,
            max_entries: 1,
            readonly: sec.name.starts_with(".rodata"),
            init,
        });
    }
    Ok(())
}

fn load_legacy_maps(
    r: &Reader,
    _bytes: &[u8],
    sections: &[Section],
    symbols: &[Symbol],
    maps_idx: usize,
) -> Result<(Vec<MapDef>, MapIndex), String> {
    let sec = &sections[maps_idx];
    // Collect map symbols in this section, ordered by offset.
    let mut entries: Vec<&Symbol> = symbols
        .iter()
        .filter(|s| s.shndx as usize == maps_idx && !s.name.is_empty())
        .collect();
    entries.sort_by_key(|s| s.value);

    let mut maps = Vec::new();
    let mut index = Vec::new();
    for (i, sym) in entries.iter().enumerate() {
        let off = sec.offset + sym.value as usize;
        // struct bpf_map_def { u32 type, key_size, value_size, max_entries, flags; }
        let ty = r.u32(off)?;
        let key_size = r.u32(off + 4)?;
        let value_size = r.u32(off + 8)?;
        let max_entries = r.u32(off + 12)?;
        maps.push(MapDef {
            name: sym.name.clone(),
            kind: map_kind(ty)?,
            key_size,
            value_size,
            max_entries,
            readonly: false,
            init: Vec::new(),
        });
        index.push((sym.value, sym.shndx, i));
    }
    Ok((
        maps,
        MapIndex {
            by_offset: index,
            data_secs: Vec::new(),
        },
    ))
}

fn map_kind(ty: u32) -> Result<MapKind, String> {
    match ty {
        BPF_MAP_TYPE_HASH => Ok(MapKind::Hash),
        BPF_MAP_TYPE_ARRAY => Ok(MapKind::Array),
        other => Err(format!("unsupported map type {other} (only hash/array)")),
    }
}

fn section_bytes<'a>(
    bytes: &'a [u8],
    sections: &[Section],
    idx: usize,
) -> Result<&'a [u8], String> {
    let s = sections.get(idx).ok_or("section index out of range")?;
    bytes
        .get(s.offset..s.offset + s.size)
        .ok_or_else(|| format!("section '{}' out of bounds", s.name))
}

fn cstr(strtab: &[u8], off: usize) -> String {
    let end = strtab[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| off + p)
        .unwrap_or(strtab.len());
    String::from_utf8_lossy(&strtab[off..end]).into_owned()
}

// ---------------------------------------------------------------------------
// BTF `.maps` parsing (on the full type graph in `crate::btf`)
// ---------------------------------------------------------------------------

mod btf_maps {
    use super::{map_kind, MapIndex, Section, Symbol};
    use crate::btf::{Btf, Kind};
    use crate::maps::MapDef;

    /// Read libbpf-style BTF map definitions out of the `.maps` DATASEC.
    ///
    /// Each DATASEC entry points at a `VAR` whose type is the map's anonymous
    /// struct; `__uint(name, VAL)` members are encoded as `int (*)[VAL]`
    /// (value = the array's nelems) and `__type(name, T)` as `T *`
    /// (size = sizeof(T)). See `docs/specs/elf-loading.md`.
    pub(super) fn load_btf_maps(
        le: bool,
        btf_bytes: &[u8],
        _sections: &[Section],
        symbols: &[Symbol],
        dotmaps_idx: usize,
    ) -> Result<(Vec<MapDef>, MapIndex), String> {
        let btf = Btf::parse(le, btf_bytes)?;

        let ptr_array_nelems = |id: u32| -> Result<u32, String> {
            let Kind::Ptr { type_id } = btf.ty(btf.resolve(id)?)?.kind else {
                return Err("expected pointer-encoded __uint member".into());
            };
            match btf.ty(btf.resolve(type_id)?)?.kind {
                Kind::Array { nelems, .. } => Ok(nelems),
                _ => Err("expected pointer-to-array __uint encoding".into()),
            }
        };
        let ptr_pointee_size = |id: u32| -> Result<u32, String> {
            let Kind::Ptr { type_id } = btf.ty(btf.resolve(id)?)?.kind else {
                return Err("expected pointer-encoded __type member".into());
            };
            btf.type_size(type_id)
        };

        let secinfo = btf.datasec(".maps").ok_or("no .maps DATASEC in BTF")?;
        let mut ordered: Vec<_> = secinfo.to_vec();
        ordered.sort_by_key(|si| si.offset);

        let mut maps = Vec::new();
        let mut index = Vec::new();
        // secinfo entries point at VARs; the DATASEC offset matches the map
        // variable's symbol value in the `.maps` section.
        for si in &ordered {
            let var = btf.ty(si.type_id)?;
            let Kind::Var { type_id, .. } = var.kind else {
                continue;
            };
            let map_name = btf.str_at(var.name_off).to_string();
            let st_id = btf.resolve(type_id)?;
            let Kind::Struct { members, .. } = &btf.ty(st_id)?.kind else {
                return Err(format!("map '{map_name}' is not a struct"));
            };
            let (mut kind, mut key_size, mut value_size, mut max_entries) =
                (None, None, None, None);
            for m in members {
                match btf.str_at(m.name_off) {
                    "type" => kind = Some(map_kind(ptr_array_nelems(m.type_id)?)?),
                    "max_entries" => max_entries = Some(ptr_array_nelems(m.type_id)?),
                    "map_flags" => {}
                    "key_size" => key_size = Some(ptr_array_nelems(m.type_id)?),
                    "value_size" => value_size = Some(ptr_array_nelems(m.type_id)?),
                    "key" => key_size = Some(ptr_pointee_size(m.type_id)?),
                    "value" => value_size = Some(ptr_pointee_size(m.type_id)?),
                    _ => {}
                }
            }
            maps.push(MapDef {
                name: map_name.clone(),
                kind: kind.ok_or_else(|| format!("map '{map_name}': missing type"))?,
                key_size: key_size
                    .ok_or_else(|| format!("map '{map_name}': missing key size"))?,
                value_size: value_size
                    .ok_or_else(|| format!("map '{map_name}': missing value size"))?,
                max_entries: max_entries
                    .ok_or_else(|| format!("map '{map_name}': missing max_entries"))?,
                readonly: false,
                init: Vec::new(),
            });
            index.push((si.offset as u64, dotmaps_idx as u16, maps.len() - 1));
        }
        // Map symbols may not be at DATASEC offsets in every toolchain; also
        // index by symbol order as a fallback.
        for sym in symbols.iter().filter(|s| s.shndx as usize == dotmaps_idx) {
            if !index
                .iter()
                .any(|(v, sh, _)| *v == sym.value && *sh == sym.shndx)
            {
                if let Some(pos) = maps.iter().position(|m| m.name == sym.name) {
                    index.push((sym.value, sym.shndx, pos));
                }
            }
        }
        Ok((
            maps,
            MapIndex {
                by_offset: index,
                data_secs: Vec::new(),
            },
        ))
    }
}
