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

use crate::btf::{Btf, BtfExt, Kind};
use crate::debuginfo::{DebugInfo, FuncBound, GlobalVar, SourceLine};
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

// BPF map types we support.
const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_MAP_TYPE_PERCPU_HASH: u32 = 5;
const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
const BPF_MAP_TYPE_LRU_HASH: u32 = 9;
const BPF_MAP_TYPE_RINGBUF: u32 = 27;

/// One program (executable section) from an object.
pub struct LoadedProgram {
    pub name: String,
    pub insns: Vec<Insn>,
    /// Source-level debug info from `.BTF`/`.BTF.ext`, if the object had any.
    pub debug: Option<DebugInfo>,
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

/// Parse and relocate a BPF object file (no CO-RE target: any CO-RE
/// relocations are left at the layout the compiler baked in).
pub fn load(bytes: &[u8]) -> Result<Object, String> {
    load_with_target_btf(bytes, None)
}

/// Parse and relocate a BPF object file, applying CO-RE relocations from
/// `.BTF.ext` against `target_btf` (a raw BTF blob: a `.BTF` section payload
/// or a kernel BTF file such as `/sys/kernel/btf/vmlinux`) when given.
pub fn load_with_target_btf(bytes: &[u8], target_btf: Option<&[u8]>) -> Result<Object, String> {
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

    // (program, its ELF section name, where `.text` was stitched in — needed
    // to map per-section CO-RE relocations onto the flat instruction stream)
    let mut programs: Vec<(LoadedProgram, String, Option<usize>)> = Vec::new();
    for idx in &entry_sections {
        let sec = &sections[*idx];
        let (insns, text_base) = build_program(
            &r,
            bytes,
            &sections,
            *idx,
            text_idx,
            &text_insns,
            &symbols,
            &map_by_symval,
        )?;
        programs.push((
            LoadedProgram {
                name: sec.name.clone(),
                insns,
                debug: None,
            },
            sec.name.clone(),
            text_base,
        ));
    }

    // If there are no SEC()-annotated entry programs, expose `.text` itself.
    if programs.is_empty() {
        if let Some(ti) = text_idx {
            let (insns, text_base) = build_program(
                &r, bytes, &sections, ti, text_idx, &text_insns, &symbols, &map_by_symval,
            )?;
            programs.push((
                LoadedProgram {
                    name: "text".into(),
                    insns,
                    debug: None,
                },
                ".text".into(),
                text_base,
            ));
        }
    }
    if programs.is_empty() {
        return Err("no executable program sections found".into());
    }

    if let Some(target) = target_btf {
        apply_core_relocations(r.le, bytes, &sections, &mut programs, target)?;
    }

    // Surface source-level debug info (line/func/globals) for each program.
    for (prog, sec_name, text_base) in programs.iter_mut() {
        prog.debug = build_debug_info(r.le, bytes, &sections, sec_name, *text_base, &maps)?;
    }

    Ok(Object {
        programs: programs.into_iter().map(|(p, _, _)| p).collect(),
        maps,
    })
}

/// Does this object carry CO-RE relocations (a `.BTF.ext` with a non-empty
/// core_relo sub-section)? Used by callers to decide whether a target BTF
/// (e.g. `/sys/kernel/btf/vmlinux`) should be supplied.
pub fn has_core_relocations(bytes: &[u8]) -> bool {
    let Ok(Some((ext_raw, le))) = read_section(bytes, ".BTF.ext") else {
        return false;
    };
    crate::btf::BtfExt::parse(le, &ext_raw)
        .map(|e| e.num_core_relos() > 0)
        .unwrap_or(false)
}

/// Resolve every CO-RE relocation against the target BTF and patch the
/// affected instructions in place (see `docs/specs/core-relocations.md` §3).
///
/// Relocations are grouped per ELF section; a program consists of its entry
/// section (at instruction 0) plus, possibly, a stitched copy of `.text` (at
/// `text_base`), so `.text` relocations are re-applied at that offset in
/// every program that embeds it.
fn apply_core_relocations(
    le: bool,
    bytes: &[u8],
    sections: &[Section],
    programs: &mut [(LoadedProgram, String, Option<usize>)],
    target_btf: &[u8],
) -> Result<(), String> {
    let Some(btf_idx) = sections.iter().position(|s| s.name == ".BTF" && s.size > 0) else {
        return Ok(()); // no local BTF, nothing to relocate
    };
    let Some(ext_idx) = sections
        .iter()
        .position(|s| s.name == ".BTF.ext" && s.size > 0)
    else {
        return Ok(());
    };
    let local = Btf::parse(le, section_bytes(bytes, sections, btf_idx)?)?;
    let ext = BtfExt::parse(le, section_bytes(bytes, sections, ext_idx)?)?;
    if ext.num_core_relos() == 0 {
        return Ok(());
    }

    // A raw BTF blob declares its own byte order via the magic.
    let target_le = match target_btf.first_chunk::<2>() {
        Some(&[0x9f, 0xeb]) => true,
        Some(&[0xeb, 0x9f]) => false,
        _ => return Err("target BTF: bad magic".into()),
    };
    let target = Btf::parse(target_le, target_btf)?;
    let index = crate::relo::CandidateIndex::new(&target);

    for (prog, sec_name, text_base) in programs.iter_mut() {
        for ext_sec in &ext.core_relos {
            let relo_sec = local.str_at(ext_sec.sec_name_off);
            // Where does this section's code live inside this program?
            let code_base = if relo_sec == sec_name {
                0
            } else if relo_sec == ".text" {
                match text_base {
                    Some(base) => *base,
                    None => continue, // program didn't stitch .text in
                }
            } else {
                continue; // relocations for some other program's section
            };
            for relo in &ext_sec.recs {
                let res = crate::relo::calc_relo(&local, relo, &target, &index)
                    .map_err(|e| format!("{}+{}: {e}", relo_sec, relo.insn_off))?;
                let idx = code_base + relo.insn_off as usize / insn::INSN_SIZE;
                patch_core_insn(&mut prog.insns, idx, &res).map_err(|e| {
                    format!(
                        "{}+{}: CO-RE {}: {e}",
                        relo_sec,
                        relo.insn_off,
                        crate::btf::relo_kind::name(relo.kind)
                    )
                })?;
            }
        }
    }
    Ok(())
}

/// Build source-level [`DebugInfo`] for one program from the object's `.BTF`
/// and `.BTF.ext`. `sec_name`/`text_base` describe where this program's code
/// came from (see [`build_program`]); `.BTF.ext` records are grouped per ELF
/// section and translated to flat instruction indices exactly as CO-RE
/// relocations are (see `docs/specs/source-debug.md`). Returns `None` when the
/// object carries no usable debug info.
fn build_debug_info(
    le: bool,
    bytes: &[u8],
    sections: &[Section],
    sec_name: &str,
    text_base: Option<usize>,
    maps: &[MapDef],
) -> Result<Option<DebugInfo>, String> {
    let Some(btf_idx) = sections.iter().position(|s| s.name == ".BTF" && s.size > 0) else {
        return Ok(None);
    };
    let btf = Btf::parse(le, section_bytes(bytes, sections, btf_idx)?)?;

    // Flat instruction index of a per-section byte offset, or None if the
    // record belongs to a section not part of this program.
    let flat_idx = |rec_sec: &str, insn_off: u32| -> Option<usize> {
        let base = if rec_sec == sec_name {
            0
        } else if rec_sec == ".text" {
            text_base?
        } else {
            return None;
        };
        Some(base + insn_off as usize / insn::INSN_SIZE)
    };

    let mut lines = Vec::new();
    let mut funcs = Vec::new();
    if let Some(ext_idx) = sections
        .iter()
        .position(|s| s.name == ".BTF.ext" && s.size > 0)
    {
        let ext = BtfExt::parse(le, section_bytes(bytes, sections, ext_idx)?)?;
        for es in &ext.line_info {
            let rec_sec = btf.str_at(es.sec_name_off).to_string();
            for r in &es.recs {
                if let Some(idx) = flat_idx(&rec_sec, r.insn_off) {
                    lines.push(SourceLine {
                        insn: idx,
                        file: btf.str_at(r.file_name_off).to_string(),
                        line: r.line(),
                        col: r.col(),
                        text: btf.str_at(r.line_off).trim_end().to_string(),
                    });
                }
            }
        }
        for es in &ext.func_info {
            let rec_sec = btf.str_at(es.sec_name_off).to_string();
            for r in &es.recs {
                if let Some(idx) = flat_idx(&rec_sec, r.insn_off) {
                    funcs.push(FuncBound {
                        insn: idx,
                        name: btf.type_name(r.type_id).to_string(),
                    });
                }
            }
        }
    }

    // Globals: every DATASEC var that maps to a data-section map.
    let mut globals = Vec::new();
    for (id, t) in btf.iter() {
        let Kind::Datasec { entries, .. } = &t.kind else {
            continue;
        };
        let sec = btf.type_name(id);
        let map = maps.iter().position(|m| m.name == sec).or_else(|| {
            // clang merges `.rodata.*` into one `.rodata` DATASEC; best-effort.
            sec.starts_with(".rodata")
                .then(|| maps.iter().position(|m| m.name.starts_with(".rodata")))
                .flatten()
        });
        let Some(map) = map else { continue };
        for e in entries {
            let Ok(var) = btf.ty(e.type_id) else { continue };
            let Kind::Var { type_id, .. } = var.kind else {
                continue;
            };
            globals.push(GlobalVar {
                name: btf.str_at(var.name_off).to_string(),
                map,
                map_name: maps[map].name.clone(),
                offset: e.offset,
                type_id,
            });
        }
    }

    let di = DebugInfo::new(btf, lines, funcs, globals);
    Ok((!di.is_empty()).then_some(di))
}

/// Patch one relocated instruction with the computed target value, mirroring
/// libbpf's `bpf_core_patch_insn`: memory-class instructions take the value
/// in `off`, immediate ALU ops in `imm`, and `lddw` across both `imm` slots.
fn patch_core_insn(
    insns: &mut [Insn],
    idx: usize,
    res: &crate::relo::ReloResult,
) -> Result<(), String> {
    use crate::insn::{class, jmp};
    let insn = *insns
        .get(idx)
        .ok_or_else(|| format!("relocated instruction {idx} out of range"))?;

    if res.poison {
        // Like libbpf: replace with a call to an invalid helper (0xbad2310)
        // so the program still loads and only fails verification if the
        // (presumably existence-guarded) path is actually reachable.
        insns[idx] = Insn {
            opcode: class::JMP | jmp::CALL,
            dst: 0,
            src: 0,
            off: 0,
            imm: 0xbad2310,
        };
        return Ok(());
    }

    match insn.class() {
        class::LDX | class::ST | class::STX => {
            if res.validate && insn.off as i64 != res.orig_val as i64 {
                return Err(format!(
                    "insn {idx} off {} does not match expected {}",
                    insn.off, res.orig_val
                ));
            }
            if res.new_val > i16::MAX as u64 {
                return Err(format!("new offset {} does not fit in i16", res.new_val));
            }
            insns[idx].off = res.new_val as i16;
        }
        class::ALU | class::ALU64 => {
            if insn.is_src_reg() {
                return Err(format!("insn {idx}: relocation on register-source ALU op"));
            }
            if res.validate && insn.imm as u32 as u64 != res.orig_val {
                return Err(format!(
                    "insn {idx} imm {} does not match expected {}",
                    insn.imm, res.orig_val
                ));
            }
            if res.new_val > u32::MAX as u64 {
                return Err(format!("new value {} does not fit in imm", res.new_val));
            }
            insns[idx].imm = res.new_val as u32 as i32;
        }
        class::LD if insn.is_wide() => {
            if idx + 1 >= insns.len() {
                return Err(format!("relocated lddw at {idx} truncated"));
            }
            if res.validate && insn::wide_imm(insns, idx) != res.orig_val {
                return Err(format!(
                    "insn {idx} lddw {} does not match expected {}",
                    insn::wide_imm(insns, idx),
                    res.orig_val
                ));
            }
            insns[idx].imm = res.new_val as u32 as i32;
            insns[idx + 1].imm = (res.new_val >> 32) as u32 as i32;
        }
        other => {
            return Err(format!(
                "insn {idx}: unsupported instruction class {other:#x} for relocation"
            ))
        }
    }
    Ok(())
}

/// Build one runnable program from entry section `idx`, appending `.text`
/// subprograms and fixing up call targets when the entry calls into `.text`.
/// Also returns the instruction offset at which `.text` was stitched in (if
/// it was), so CO-RE relocations on `.text` can be applied there.
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
) -> Result<(Vec<Insn>, Option<usize>), String> {
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
    Ok((insns, text_base))
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
        BPF_MAP_TYPE_PERCPU_HASH => Ok(MapKind::PerCpuHash),
        BPF_MAP_TYPE_PERCPU_ARRAY => Ok(MapKind::PerCpuArray),
        BPF_MAP_TYPE_LRU_HASH => Ok(MapKind::LruHash),
        BPF_MAP_TYPE_RINGBUF => Ok(MapKind::RingBuf),
        other => Err(format!(
            "unsupported map type {other} ({}); supported: \
             hash/array/percpu_hash/percpu_array/lru_hash/ringbuf",
            map_type_name(other)
        )),
    }
}

/// Symbolic name for a kernel `enum bpf_map_type` value, so an unsupported-map
/// error names the type (e.g. `PERF_EVENT_ARRAY`) and not just its number.
/// Keeps the corpus coverage histogram crisp (see `docs/specs/corpus-tooling.md`).
fn map_type_name(ty: u32) -> &'static str {
    match ty {
        0 => "UNSPEC",
        1 => "HASH",
        2 => "ARRAY",
        3 => "PROG_ARRAY",
        4 => "PERF_EVENT_ARRAY",
        5 => "PERCPU_HASH",
        6 => "PERCPU_ARRAY",
        7 => "STACK_TRACE",
        8 => "CGROUP_ARRAY",
        9 => "LRU_HASH",
        10 => "LRU_PERCPU_HASH",
        11 => "LPM_TRIE",
        12 => "ARRAY_OF_MAPS",
        13 => "HASH_OF_MAPS",
        14 => "DEVMAP",
        15 => "SOCKMAP",
        16 => "CPUMAP",
        17 => "XSKMAP",
        18 => "SOCKHASH",
        19 => "CGROUP_STORAGE",
        20 => "REUSEPORT_SOCKARRAY",
        21 => "PERCPU_CGROUP_STORAGE",
        22 => "QUEUE",
        23 => "STACK",
        24 => "SK_STORAGE",
        25 => "DEVMAP_HASH",
        26 => "STRUCT_OPS",
        27 => "RINGBUF",
        28 => "INODE_STORAGE",
        29 => "TASK_STORAGE",
        30 => "BLOOM_FILTER",
        31 => "USER_RINGBUF",
        32 => "CGRP_STORAGE",
        33 => "ARENA",
        _ => "unknown",
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
            let kind = kind.ok_or_else(|| format!("map '{map_name}': missing type"))?;
            // Ringbufs have no key/value; libbpf omits those members entirely.
            let no_kv = kind == crate::maps::MapKind::RingBuf;
            maps.push(MapDef {
                name: map_name.clone(),
                kind,
                key_size: key_size
                    .or(no_kv.then_some(0))
                    .ok_or_else(|| format!("map '{map_name}': missing key size"))?,
                value_size: value_size
                    .or(no_kv.then_some(0))
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

#[cfg(test)]
mod tests {
    use super::{map_kind, map_type_name};

    #[test]
    fn map_kind_names_unsupported_type() {
        // Supported types resolve; unsupported ones name the type crisply so
        // the corpus coverage histogram can bucket by name (RINGBUF, etc.).
        assert!(map_kind(1).is_ok());
        assert!(map_kind(2).is_ok());
        let e = map_kind(27).unwrap_err();
        assert!(e.contains("unsupported map type 27"), "{e}");
        assert!(e.contains("RINGBUF"), "{e}");
        assert_eq!(map_type_name(5), "PERCPU_HASH");
        assert_eq!(map_type_name(999), "unknown");
    }
}
