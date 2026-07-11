//! Source-level debug information: a lookup structure over the `.BTF.ext`
//! func_info / line_info records and the `.BTF` type graph.
//!
//! `clang -g -target bpf` embeds, in `.BTF.ext`, the source location of every
//! instruction (file, line, column *and* the source line text itself) and the
//! subprogram each instruction belongs to; the `.BTF` `DATASEC`/`VAR` types
//! describe every global by name, type and offset. This module turns those
//! raw records (parsed by [`crate::btf`]) into fast, program-relative lookups
//! and renders typed values through the BTF graph. See
//! `docs/specs/source-debug.md`.

use crate::btf::{int_enc, Btf, Kind};

/// The source location covering a range of instructions (addr2line-style: a
/// record covers instructions from `insn` up to the next record's `insn`).
#[derive(Debug, Clone)]
pub struct SourceLine {
    /// Flat program instruction index (after `.text` stitching).
    pub insn: usize,
    pub file: String,
    pub line: u32,
    pub col: u32,
    /// The source line text clang embedded (may be empty).
    pub text: String,
}

/// A subprogram boundary: `name` begins at instruction `insn`.
#[derive(Debug, Clone)]
pub struct FuncBound {
    pub insn: usize,
    pub name: String,
}

/// A global variable declared in a data section.
#[derive(Debug, Clone)]
pub struct GlobalVar {
    pub name: String,
    /// Index into the `Vm`'s map list (the data-section map holding it).
    pub map: usize,
    /// Name of that map / data section (e.g. `.bss`).
    pub map_name: String,
    /// Byte offset of the variable within the section.
    pub offset: u32,
    /// BTF type id of the variable.
    pub type_id: u32,
}

/// All source-level debug information for one loaded program.
#[derive(Clone)]
pub struct DebugInfo {
    btf: Btf,
    /// Sorted by `insn`.
    lines: Vec<SourceLine>,
    /// Sorted by `insn`.
    funcs: Vec<FuncBound>,
    globals: Vec<GlobalVar>,
}

impl DebugInfo {
    /// Assemble from already-collected records. `lines` and `funcs` are sorted
    /// here so callers may pass them in any order.
    pub fn new(
        btf: Btf,
        mut lines: Vec<SourceLine>,
        mut funcs: Vec<FuncBound>,
        globals: Vec<GlobalVar>,
    ) -> DebugInfo {
        lines.sort_by_key(|l| l.insn);
        funcs.sort_by_key(|f| f.insn);
        DebugInfo {
            btf,
            lines,
            funcs,
            globals,
        }
    }

    /// True when there is nothing useful to show.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty() && self.funcs.is_empty() && self.globals.is_empty()
    }

    /// The BTF type graph (for rendering / introspection).
    pub fn btf(&self) -> &Btf {
        &self.btf
    }

    /// Source line covering instruction `insn` (the greatest record at or
    /// before it), or `None` before the first record.
    pub fn line_at(&self, insn: usize) -> Option<&SourceLine> {
        let pos = self.lines.partition_point(|l| l.insn <= insn);
        (pos > 0).then(|| &self.lines[pos - 1])
    }

    /// Subprogram containing instruction `insn`.
    pub fn func_at(&self, insn: usize) -> Option<&FuncBound> {
        let pos = self.funcs.partition_point(|f| f.insn <= insn);
        (pos > 0).then(|| &self.funcs[pos - 1])
    }

    /// All source lines, sorted by instruction index.
    pub fn lines(&self) -> &[SourceLine] {
        &self.lines
    }

    /// All known globals.
    pub fn globals(&self) -> &[GlobalVar] {
        &self.globals
    }

    /// Look up a global by name.
    pub fn global(&self, name: &str) -> Option<&GlobalVar> {
        self.globals.iter().find(|g| g.name == name)
    }

    /// A short C-ish name for a BTF type id (for `print` output).
    pub fn type_name(&self, id: u32) -> String {
        let name = self.btf.type_name(id);
        if !name.is_empty() {
            return name.to_string();
        }
        // Anonymous: describe by structure.
        match self.btf.ty(id).map(|t| &t.kind) {
            Ok(Kind::Ptr { type_id }) => format!("{} *", self.type_name(*type_id)),
            Ok(Kind::Const { type_id })
            | Ok(Kind::Volatile { type_id })
            | Ok(Kind::Typedef { type_id })
            | Ok(Kind::Restrict { type_id }) => self.type_name(*type_id),
            Ok(Kind::Array {
                elem_type, nelems, ..
            }) => format!("{}[{}]", self.type_name(*elem_type), nelems),
            Ok(Kind::Struct { .. }) => "struct".to_string(),
            Ok(Kind::Union { .. }) => "union".to_string(),
            Ok(Kind::Enum { .. }) => "enum".to_string(),
            _ => "?".to_string(),
        }
    }

    /// Render `bytes` as a value of BTF type `type_id`, one aggregate level
    /// deep (nested structs/arrays render as `{…}` / `[…]`).
    pub fn render_value(&self, type_id: u32, bytes: &[u8]) -> String {
        self.render(type_id, bytes, 0)
    }

    fn render(&self, id: u32, bytes: &[u8], depth: usize) -> String {
        let id = self.btf.resolve(id).unwrap_or(id);
        let kind = match self.btf.ty(id) {
            Ok(t) => &t.kind,
            Err(_) => return hexbytes(bytes),
        };
        match kind {
            Kind::Int {
                size, encoding, ..
            } => render_int(bytes, *size, *encoding),
            Kind::Ptr { .. } => match read_uint(bytes, 8) {
                Some(v) => format!("{v:#x}"),
                None => hexbytes(bytes),
            },
            Kind::Enum {
                size, vals, signed, ..
            } => {
                let raw = read_uint(bytes, *size).unwrap_or(0);
                match vals.iter().find(|v| v.value == raw) {
                    Some(v) => self.btf.str_at(v.name_off).to_string(),
                    None if *signed => format!("{}", raw as i64),
                    None => format!("{raw}"),
                }
            }
            Kind::Float { size } => match size {
                4 => bytes
                    .first_chunk::<4>()
                    .map(|b| format!("{}", f32::from_le_bytes(*b)))
                    .unwrap_or_else(|| hexbytes(bytes)),
                8 => bytes
                    .first_chunk::<8>()
                    .map(|b| format!("{}", f64::from_le_bytes(*b)))
                    .unwrap_or_else(|| hexbytes(bytes)),
                _ => hexbytes(bytes),
            },
            Kind::Array {
                elem_type, nelems, ..
            } => {
                if depth >= 1 {
                    return "[…]".to_string();
                }
                let esize = self.btf.type_size(*elem_type).unwrap_or(0) as usize;
                if esize == 0 {
                    return "[…]".to_string();
                }
                let mut parts = Vec::new();
                for i in 0..*nelems as usize {
                    match bytes.get(i * esize..(i + 1) * esize) {
                        Some(slice) => parts.push(self.render(*elem_type, slice, depth + 1)),
                        None => break,
                    }
                }
                format!("[{}]", parts.join(", "))
            }
            Kind::Struct { members, .. } | Kind::Union { members, .. } => {
                if depth >= 1 {
                    return "{…}".to_string();
                }
                let mut parts = Vec::new();
                for m in members {
                    // Only whole-byte, non-bitfield members are rendered.
                    if m.bitfield_size != 0 || !m.bit_offset.is_multiple_of(8) {
                        continue;
                    }
                    let boff = (m.bit_offset / 8) as usize;
                    let msize = self.btf.type_size(m.type_id).unwrap_or(0) as usize;
                    let name = self.btf.str_at(m.name_off);
                    let val = match bytes.get(boff..boff + msize) {
                        Some(slice) if msize > 0 => self.render(m.type_id, slice, depth + 1),
                        _ => "?".to_string(),
                    };
                    parts.push(format!("{name}: {val}"));
                }
                format!("{{ {} }}", parts.join(", "))
            }
            _ => hexbytes(bytes),
        }
    }
}

fn hexbytes(b: &[u8]) -> String {
    let mut s = String::from("0x");
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Read up to 8 little-endian bytes as an unsigned integer.
fn read_uint(bytes: &[u8], size: u32) -> Option<u64> {
    let size = size as usize;
    if size == 0 || size > 8 {
        return None;
    }
    let slice = bytes.get(..size)?;
    let mut v = 0u64;
    for (i, b) in slice.iter().enumerate() {
        v |= (*b as u64) << (8 * i);
    }
    Some(v)
}

fn render_int(bytes: &[u8], size: u32, encoding: u8) -> String {
    let Some(raw) = read_uint(bytes, size) else {
        return hexbytes(bytes);
    };
    if encoding & int_enc::BOOL != 0 {
        return if raw != 0 { "true" } else { "false" }.to_string();
    }
    if encoding & int_enc::SIGNED != 0 {
        // Sign-extend from `size` bytes.
        let bits = size * 8;
        let signed = if bits < 64 {
            let sign = 1u64 << (bits - 1);
            ((raw ^ sign).wrapping_sub(sign)) as i64
        } else {
            raw as i64
        };
        if encoding & int_enc::CHAR != 0 && size == 1 {
            return format!("{signed}");
        }
        return format!("{signed}");
    }
    format!("{raw}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btf::kind;
    use crate::btf::tests::{build_btf, stroff};

    fn info(k: u32, vlen: u32, kflag: bool) -> u32 {
        (k << 24) | (vlen & 0xffff) | ((kflag as u32) << 31)
    }

    fn sample_btf() -> Btf {
        let strings = ["int", "uint", "point", "x", "y", "byte", "pair"];
        let s = |n| stroff(&strings, n);
        let blob = build_btf(
            &strings,
            &[
                // [1] int (signed 32)
                (s("int"), info(kind::INT, 0, false), 4, vec![(1u32 << 24) | 32]),
                // [2] unsigned int (32, no flags)
                (s("uint"), info(kind::INT, 0, false), 4, vec![32]),
                // [3] struct point { int x; int y; }
                (
                    s("point"),
                    info(kind::STRUCT, 2, false),
                    8,
                    vec![s("x"), 1, 0, s("y"), 1, 32],
                ),
                // [4] u8 (unsigned char) for arrays
                (s("byte"), info(kind::INT, 0, false), 1, vec![8]),
                // [5] array of 3 bytes
                (0, info(kind::ARRAY, 0, false), 0, vec![4, 1, 3]),
                // [6] array of 2 points (nested aggregate)
                (0, info(kind::ARRAY, 0, false), 0, vec![3, 1, 2]),
            ],
        );
        Btf::parse(true, &blob).unwrap()
    }

    #[test]
    fn line_and_func_lookup() {
        let di = DebugInfo::new(
            sample_btf(),
            vec![
                SourceLine { insn: 0, file: "a.c".into(), line: 10, col: 1, text: "{".into() },
                SourceLine { insn: 3, file: "a.c".into(), line: 12, col: 5, text: "return x;".into() },
            ],
            vec![
                FuncBound { insn: 0, name: "main".into() },
                FuncBound { insn: 6, name: "helper".into() },
            ],
            vec![],
        );
        assert!(di.line_at(0).is_some());
        assert_eq!(di.line_at(2).unwrap().line, 10);
        assert_eq!(di.line_at(3).unwrap().line, 12);
        assert_eq!(di.line_at(99).unwrap().text, "return x;");
        assert_eq!(di.func_at(0).unwrap().name, "main");
        assert_eq!(di.func_at(5).unwrap().name, "main");
        assert_eq!(di.func_at(6).unwrap().name, "helper");
    }

    #[test]
    fn render_scalars() {
        let di = DebugInfo::new(sample_btf(), vec![], vec![], vec![]);
        // signed int -1
        assert_eq!(di.render_value(1, &(-1i32).to_le_bytes()), "-1");
        // unsigned int 4000000000
        assert_eq!(di.render_value(2, &4_000_000_000u32.to_le_bytes()), "4000000000");
    }

    #[test]
    fn render_struct_and_array_one_level() {
        let di = DebugInfo::new(sample_btf(), vec![], vec![], vec![]);
        // struct point { x=7, y=-2 }
        let mut b = Vec::new();
        b.extend_from_slice(&7i32.to_le_bytes());
        b.extend_from_slice(&(-2i32).to_le_bytes());
        assert_eq!(di.render_value(3, &b), "{ x: 7, y: -2 }");
        // array of 3 bytes
        assert_eq!(di.render_value(5, &[1u8, 2, 3]), "[1, 2, 3]");
        // array of 2 points: nested aggregate collapses to {…}
        let mut arr = b.clone();
        arr.extend_from_slice(&b);
        assert_eq!(di.render_value(6, &arr), "[{…}, {…}]");
    }
}
