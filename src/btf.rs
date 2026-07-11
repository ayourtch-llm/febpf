//! BTF (BPF Type Format) parser: the full type graph.
//!
//! Parses a raw BTF blob — either the `.BTF` section of a `clang -target bpf`
//! object or a standalone kernel BTF file such as `/sys/kernel/btf/vmlinux` —
//! into a queryable type table. Every BTF kind is represented; named types are
//! indexed by name so candidate lookup stays O(1) at vmlinux scale
//! (~150k types). See `docs/specs/core-relocations.md` §1.1.

use std::collections::HashMap;

pub const BTF_MAGIC: u16 = 0xEB9F;

/// BTF kind discriminants (the `info` field's bits 24-28).
pub mod kind {
    pub const VOID: u32 = 0;
    pub const INT: u32 = 1;
    pub const PTR: u32 = 2;
    pub const ARRAY: u32 = 3;
    pub const STRUCT: u32 = 4;
    pub const UNION: u32 = 5;
    pub const ENUM: u32 = 6;
    pub const FWD: u32 = 7;
    pub const TYPEDEF: u32 = 8;
    pub const VOLATILE: u32 = 9;
    pub const CONST: u32 = 10;
    pub const RESTRICT: u32 = 11;
    pub const FUNC: u32 = 12;
    pub const FUNC_PROTO: u32 = 13;
    pub const VAR: u32 = 14;
    pub const DATASEC: u32 = 15;
    pub const FLOAT: u32 = 16;
    pub const DECL_TAG: u32 = 17;
    pub const TYPE_TAG: u32 = 18;
    pub const ENUM64: u32 = 19;
}

/// Integer encoding flags (INT's trailing word, bits 24-27).
pub mod int_enc {
    pub const SIGNED: u8 = 1 << 0;
    pub const CHAR: u8 = 1 << 1;
    pub const BOOL: u8 = 1 << 2;
}

/// A struct/union member.
#[derive(Debug, Clone)]
pub struct Member {
    pub name_off: u32,
    pub type_id: u32,
    /// Offset of the member in bits from the start of the struct.
    pub bit_offset: u32,
    /// 0 for a regular member; the width in bits for a bitfield member.
    pub bitfield_size: u8,
}

/// One enumerator (ENUM and ENUM64 are unified; values are sign- or
/// zero-extended to 64 bits according to the enum's signedness).
#[derive(Debug, Clone)]
pub struct EnumVal {
    pub name_off: u32,
    pub value: u64,
}

/// A DATASEC entry: a variable placed in the section.
#[derive(Debug, Clone)]
pub struct SecInfo {
    pub type_id: u32,
    pub offset: u32,
    pub size: u32,
}

/// A function prototype parameter.
#[derive(Debug, Clone)]
pub struct Param {
    pub name_off: u32,
    pub type_id: u32,
}

/// Kind-specific payload of a BTF type.
#[derive(Debug, Clone)]
pub enum Kind {
    /// Type id 0.
    Void,
    Int {
        size: u32,
        /// Width in bits (may be smaller than `size * 8`).
        bits: u8,
        encoding: u8,
    },
    Ptr {
        type_id: u32,
    },
    Array {
        elem_type: u32,
        index_type: u32,
        nelems: u32,
    },
    Struct {
        size: u32,
        members: Vec<Member>,
    },
    Union {
        size: u32,
        members: Vec<Member>,
    },
    Enum {
        size: u32,
        signed: bool,
        /// True when this came from ENUM64 on the wire.
        is64: bool,
        vals: Vec<EnumVal>,
    },
    Fwd {
        is_union: bool,
    },
    Typedef {
        type_id: u32,
    },
    Volatile {
        type_id: u32,
    },
    Const {
        type_id: u32,
    },
    Restrict {
        type_id: u32,
    },
    Func {
        proto_type: u32,
        linkage: u32,
    },
    FuncProto {
        ret_type: u32,
        params: Vec<Param>,
    },
    Var {
        type_id: u32,
        linkage: u32,
    },
    Datasec {
        size: u32,
        entries: Vec<SecInfo>,
    },
    Float {
        size: u32,
    },
    DeclTag {
        type_id: u32,
        component_idx: i32,
    },
    TypeTag {
        type_id: u32,
    },
}

impl Kind {
    /// The wire discriminant (see [`kind`]).
    pub fn discr(&self) -> u32 {
        match self {
            Kind::Void => kind::VOID,
            Kind::Int { .. } => kind::INT,
            Kind::Ptr { .. } => kind::PTR,
            Kind::Array { .. } => kind::ARRAY,
            Kind::Struct { .. } => kind::STRUCT,
            Kind::Union { .. } => kind::UNION,
            Kind::Enum { is64: false, .. } => kind::ENUM,
            Kind::Enum { is64: true, .. } => kind::ENUM64,
            Kind::Fwd { .. } => kind::FWD,
            Kind::Typedef { .. } => kind::TYPEDEF,
            Kind::Volatile { .. } => kind::VOLATILE,
            Kind::Const { .. } => kind::CONST,
            Kind::Restrict { .. } => kind::RESTRICT,
            Kind::Func { .. } => kind::FUNC,
            Kind::FuncProto { .. } => kind::FUNC_PROTO,
            Kind::Var { .. } => kind::VAR,
            Kind::Datasec { .. } => kind::DATASEC,
            Kind::Float { .. } => kind::FLOAT,
            Kind::DeclTag { .. } => kind::DECL_TAG,
            Kind::TypeTag { .. } => kind::TYPE_TAG,
        }
    }
}

/// One parsed BTF type.
#[derive(Debug, Clone)]
pub struct Type {
    pub name_off: u32,
    pub kind: Kind,
}

/// A parsed BTF blob: type table + string table + name index.
#[derive(Clone)]
pub struct Btf {
    types: Vec<Type>,
    strs: Vec<u8>,
    /// name → type ids bearing that exact name (all named kinds).
    by_name: HashMap<String, Vec<u32>>,
}

/// Little/big-endian u32 reader over the blob.
struct R<'a> {
    buf: &'a [u8],
    le: bool,
}

impl R<'_> {
    fn u16(&self, off: usize) -> Result<u16, String> {
        let b: [u8; 2] = self
            .buf
            .get(off..off + 2)
            .ok_or("truncated BTF")?
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
            .ok_or("truncated BTF")?
            .try_into()
            .unwrap();
        Ok(if self.le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }
}

impl Btf {
    /// Parse a raw BTF blob (a `.BTF` ELF section payload or a standalone
    /// kernel BTF file). `le` selects the byte order.
    pub fn parse(le: bool, data: &[u8]) -> Result<Btf, String> {
        let r = R { buf: data, le };
        if r.u16(0)? != BTF_MAGIC {
            return Err("bad BTF magic".into());
        }
        // btf_header: magic u16, version u8, flags u8, hdr_len u32,
        //             type_off u32, type_len u32, str_off u32, str_len u32
        let hdr_len = r.u32(4)? as usize;
        if hdr_len < 24 {
            return Err("BTF header too short".into());
        }
        let type_off = r.u32(8)? as usize;
        let type_len = r.u32(12)? as usize;
        let str_off = r.u32(16)? as usize;
        let str_len = r.u32(20)? as usize;
        let types_start = hdr_len + type_off;
        let types_end = types_start
            .checked_add(type_len)
            .filter(|&e| e <= data.len())
            .ok_or("BTF type section out of bounds")?;
        let strs = data
            .get(hdr_len + str_off..hdr_len + str_off + str_len)
            .ok_or("BTF string section out of bounds")?
            .to_vec();

        let mut types = vec![Type {
            name_off: 0,
            kind: Kind::Void,
        }];
        let mut off = types_start;
        while off < types_end {
            let name_off = r.u32(off)?;
            let info = r.u32(off + 4)?;
            let size_or_type = r.u32(off + 8)?;
            let vlen = (info & 0xffff) as usize;
            let k = (info >> 24) & 0x1f;
            let kflag = info >> 31 == 1;
            off += 12;
            let kind = match k {
                kind::INT => {
                    let w = r.u32(off)?;
                    off += 4;
                    Kind::Int {
                        size: size_or_type,
                        bits: (w & 0xff) as u8,
                        encoding: ((w >> 24) & 0xf) as u8,
                    }
                }
                kind::PTR => Kind::Ptr {
                    type_id: size_or_type,
                },
                kind::ARRAY => {
                    let a = Kind::Array {
                        elem_type: r.u32(off)?,
                        index_type: r.u32(off + 4)?,
                        nelems: r.u32(off + 8)?,
                    };
                    off += 12;
                    a
                }
                kind::STRUCT | kind::UNION => {
                    let mut members = Vec::with_capacity(vlen);
                    for _ in 0..vlen {
                        let m_off = r.u32(off + 8)?;
                        let (bit_offset, bitfield_size) = if kflag {
                            (m_off & 0x00ff_ffff, (m_off >> 24) as u8)
                        } else {
                            (m_off, 0)
                        };
                        members.push(Member {
                            name_off: r.u32(off)?,
                            type_id: r.u32(off + 4)?,
                            bit_offset,
                            bitfield_size,
                        });
                        off += 12;
                    }
                    if k == kind::STRUCT {
                        Kind::Struct {
                            size: size_or_type,
                            members,
                        }
                    } else {
                        Kind::Union {
                            size: size_or_type,
                            members,
                        }
                    }
                }
                kind::ENUM => {
                    let mut vals = Vec::with_capacity(vlen);
                    for _ in 0..vlen {
                        let v = r.u32(off + 4)? as i32;
                        vals.push(EnumVal {
                            name_off: r.u32(off)?,
                            // Sign-extend; unsigned 32-bit values still
                            // round-trip through the low word.
                            value: v as i64 as u64,
                        });
                        off += 8;
                    }
                    Kind::Enum {
                        size: size_or_type,
                        signed: kflag,
                        is64: false,
                        vals,
                    }
                }
                kind::ENUM64 => {
                    let mut vals = Vec::with_capacity(vlen);
                    for _ in 0..vlen {
                        let lo = r.u32(off + 4)? as u64;
                        let hi = r.u32(off + 8)? as u64;
                        vals.push(EnumVal {
                            name_off: r.u32(off)?,
                            value: lo | (hi << 32),
                        });
                        off += 12;
                    }
                    Kind::Enum {
                        size: size_or_type,
                        signed: kflag,
                        is64: true,
                        vals,
                    }
                }
                kind::FWD => Kind::Fwd { is_union: kflag },
                kind::TYPEDEF => Kind::Typedef {
                    type_id: size_or_type,
                },
                kind::VOLATILE => Kind::Volatile {
                    type_id: size_or_type,
                },
                kind::CONST => Kind::Const {
                    type_id: size_or_type,
                },
                kind::RESTRICT => Kind::Restrict {
                    type_id: size_or_type,
                },
                kind::FUNC => Kind::Func {
                    proto_type: size_or_type,
                    linkage: (info & 0xffff),
                },
                kind::FUNC_PROTO => {
                    let mut params = Vec::with_capacity(vlen);
                    for _ in 0..vlen {
                        params.push(Param {
                            name_off: r.u32(off)?,
                            type_id: r.u32(off + 4)?,
                        });
                        off += 8;
                    }
                    Kind::FuncProto {
                        ret_type: size_or_type,
                        params,
                    }
                }
                kind::VAR => {
                    let linkage = r.u32(off)?;
                    off += 4;
                    Kind::Var {
                        type_id: size_or_type,
                        linkage,
                    }
                }
                kind::DATASEC => {
                    let mut entries = Vec::with_capacity(vlen);
                    for _ in 0..vlen {
                        entries.push(SecInfo {
                            type_id: r.u32(off)?,
                            offset: r.u32(off + 4)?,
                            size: r.u32(off + 8)?,
                        });
                        off += 12;
                    }
                    Kind::Datasec {
                        size: size_or_type,
                        entries,
                    }
                }
                kind::FLOAT => Kind::Float { size: size_or_type },
                kind::DECL_TAG => {
                    let idx = r.u32(off)? as i32;
                    off += 4;
                    Kind::DeclTag {
                        type_id: size_or_type,
                        component_idx: idx,
                    }
                }
                kind::TYPE_TAG => Kind::TypeTag {
                    type_id: size_or_type,
                },
                other => return Err(format!("unknown BTF kind {other} at offset {off}")),
            };
            types.push(Type { name_off, kind });
        }
        if off != types_end {
            return Err("BTF type section desynchronized (trailing bytes)".into());
        }

        // Index named types for candidate lookup.
        let mut by_name: HashMap<String, Vec<u32>> = HashMap::new();
        for (id, t) in types.iter().enumerate().skip(1) {
            let name = str_at(&strs, t.name_off);
            if !name.is_empty() {
                by_name.entry(name.to_string()).or_default().push(id as u32);
            }
        }

        Ok(Btf {
            types,
            strs,
            by_name,
        })
    }

    /// Number of type ids (including the implicit `void` at id 0).
    pub fn len(&self) -> usize {
        self.types.len()
    }
    pub fn is_empty(&self) -> bool {
        self.types.len() <= 1
    }

    /// Look up a type by id.
    pub fn ty(&self, id: u32) -> Result<&Type, String> {
        self.types
            .get(id as usize)
            .ok_or_else(|| format!("BTF type id {id} out of range"))
    }

    /// Resolve a string-table offset.
    pub fn str_at(&self, off: u32) -> &str {
        str_at(&self.strs, off)
    }

    /// A type's name ("" for anonymous types).
    pub fn type_name(&self, id: u32) -> &str {
        match self.types.get(id as usize) {
            Some(t) => self.str_at(t.name_off),
            None => "",
        }
    }

    /// Ids of all types with exactly this name.
    pub fn ids_by_name(&self, name: &str) -> &[u32] {
        self.by_name.get(name).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Iterate `(id, type)` over all types (skipping void).
    pub fn iter(&self) -> impl Iterator<Item = (u32, &Type)> {
        self.types
            .iter()
            .enumerate()
            .skip(1)
            .map(|(i, t)| (i as u32, t))
    }

    /// Skip modifiers (const/volatile/restrict/type_tag) and typedefs,
    /// returning the underlying type id.
    pub fn resolve(&self, mut id: u32) -> Result<u32, String> {
        for _ in 0..64 {
            match &self.ty(id)?.kind {
                Kind::Typedef { type_id }
                | Kind::Volatile { type_id }
                | Kind::Const { type_id }
                | Kind::Restrict { type_id }
                | Kind::TypeTag { type_id } => id = *type_id,
                _ => return Ok(id),
            }
        }
        Err("BTF modifier/typedef chain too deep (cycle?)".into())
    }

    /// Byte size of a type (resolving modifiers/typedefs). Errors on types
    /// without a size (functions, void, forward declarations).
    pub fn type_size(&self, id: u32) -> Result<u32, String> {
        let id = self.resolve(id)?;
        match &self.ty(id)?.kind {
            Kind::Int { size, .. }
            | Kind::Struct { size, .. }
            | Kind::Union { size, .. }
            | Kind::Enum { size, .. }
            | Kind::Float { size }
            | Kind::Datasec { size, .. } => Ok(*size),
            Kind::Ptr { .. } => Ok(8),
            Kind::Array {
                elem_type, nelems, ..
            } => {
                let e = self.type_size(*elem_type)?;
                e.checked_mul(*nelems)
                    .ok_or_else(|| "BTF array size overflow".into())
            }
            Kind::Var { type_id, .. } => self.type_size(*type_id),
            other => Err(format!(
                "BTF type {} (kind {}) has no size",
                id,
                other.discr()
            )),
        }
    }

    /// Find the DATASEC with the given name, if any.
    pub fn datasec(&self, name: &str) -> Option<&[SecInfo]> {
        self.ids_by_name(name).iter().find_map(|&id| {
            match &self.types[id as usize].kind {
                Kind::Datasec { entries, .. } => Some(entries.as_slice()),
                _ => None,
            }
        })
    }

    /// What a `size`-byte read at byte offset `off` inside type `id` yields:
    /// `Some(pointee)` when the read covers exactly a pointer-to-struct/union
    /// member (8 bytes at the member's offset) — the resolved pointee type id —
    /// and `None` for anything else (the read is a plain scalar). Walks nested
    /// structs, unions and arrays like the kernel's `btf_struct_walk()`
    /// (kernel/bpf/btf.c), simplified: bounds against the type size are the
    /// caller's job, bitfield members never produce pointers, and reads that
    /// match no pointer member are scalars rather than errors (any read within
    /// the object is data). See docs/specs/btf-ctx-pointers.md.
    pub fn read_kind(&self, id: u32, off: u32, size: u32) -> Result<Option<u32>, String> {
        self.read_kind_rec(id, off, size, 0)
    }

    fn read_kind_rec(
        &self,
        id: u32,
        off: u32,
        size: u32,
        depth: u32,
    ) -> Result<Option<u32>, String> {
        if depth > 32 {
            return Ok(None); // pathological nesting: treat as data
        }
        let id = self.resolve(id)?;
        match &self.ty(id)?.kind {
            Kind::Ptr { type_id } if off == 0 && size == 8 => {
                let p = self.resolve(*type_id)?;
                match self.ty(p)?.kind {
                    // Only pointers to composite types become BTF pointers;
                    // pointers to scalars/void read as scalar data (stricter
                    // than the kernel, which types those too — see spec).
                    Kind::Struct { .. } | Kind::Union { .. } => Ok(Some(p)),
                    _ => Ok(None),
                }
            }
            Kind::Struct { members, .. } | Kind::Union { members, .. } => {
                for m in members {
                    if m.bitfield_size != 0 || !m.bit_offset.is_multiple_of(8) {
                        continue;
                    }
                    let moff = m.bit_offset / 8;
                    let msize = match self.type_size(m.type_id) {
                        Ok(s) => s,
                        Err(_) => continue, // unsized member (flex array tail)
                    };
                    if off < moff || off.saturating_add(size) > moff.saturating_add(msize) {
                        continue;
                    }
                    if let Some(p) = self.read_kind_rec(m.type_id, off - moff, size, depth + 1)? {
                        return Ok(Some(p));
                    }
                }
                Ok(None)
            }
            Kind::Array { elem_type, .. } => {
                let es = self.type_size(*elem_type).unwrap_or(0);
                if es == 0 {
                    return Ok(None);
                }
                let rel = off % es;
                if rel.saturating_add(size) > es {
                    return Ok(None); // straddles elements: data
                }
                self.read_kind_rec(*elem_type, rel, size, depth + 1)
            }
            _ => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// BTF-typed program context (tp_btf / fentry / fexit / fmod_ret)
// ---------------------------------------------------------------------------

/// What a load of one 8-byte context slot yields for a program whose ctx is an
/// array of BTF-typed u64 arguments (the kernel's `btf_ctx_access()` model).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtxSlot {
    /// An integer/enum/by-value argument (or a pointer to a non-composite
    /// type): loads read an unknown scalar.
    Scalar,
    /// A pointer to the (resolved) struct/union type `btf_id` in the target
    /// BTF: an 8-byte load yields a BTF-typed pointer.
    Ptr { btf_id: u32 },
}

/// BTF typing of a program's context: one [`CtxSlot`] per 8-byte argument,
/// plus the type graph the slots refer to. The graph is needed only for
/// *verification* (field walks); the runtime uses the slots alone, which is
/// why replay files can carry a `BtfCtx` with `btf: None`.
/// See docs/specs/btf-ctx-pointers.md.
#[derive(Clone)]
pub struct BtfCtx {
    pub args: Vec<CtxSlot>,
    pub btf: Option<std::sync::Arc<Btf>>,
}

impl std::fmt::Debug for BtfCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The type graph can be all of vmlinux; print the slots only.
        f.debug_struct("BtfCtx")
            .field("args", &self.args)
            .field("btf", &self.btf.as_ref().map(|_| ".."))
            .finish()
    }
}

/// Is this ELF section name a BTF-typed program type — one whose ctx is an
/// array of BTF-typed arguments that [`resolve_ctx_args`] can resolve?
pub fn is_btf_ctx_section(name: &str) -> bool {
    ["tp_btf/", "fentry/", "fexit/", "fmod_ret/"]
        .iter()
        .any(|p| name.starts_with(p))
}

/// Resolve an ELF section name to the BTF typing of the program's ctx
/// arguments, mirroring how the kernel types `tp_btf`/`fentry`/`fexit`
/// programs (`btf_ctx_access()` in kernel/bpf/btf.c):
///
/// - `tp_btf/NAME`: the `btf_trace_NAME` typedef's func_proto, with the first
///   `void *__data` parameter skipped (the kernel does the same for
///   `attach_btf_trace` programs).
/// - `fentry/NAME` / `fmod_ret/NAME`: the kernel function `NAME`'s proto.
/// - `fexit/NAME`: like fentry plus one extra trailing slot for the return
///   value (typed by the proto's return type).
///
/// Returns `Ok(None)` for section names that are not BTF-typed program types
/// (`raw_tp/`, `kprobe/`, `tracepoint/`, ...), and `Err` when the section IS
/// BTF-typed but the target cannot be found in `btf`.
pub fn resolve_ctx_args(btf: &Btf, section: &str) -> Result<Option<Vec<CtxSlot>>, String> {
    let (proto_id, skip_data_arg, ret_slot, what) =
        if let Some(name) = section.strip_prefix("tp_btf/") {
            let tname = format!("btf_trace_{name}");
            let td = btf
                .ids_by_name(&tname)
                .iter()
                .copied()
                .find(|&id| matches!(btf.ty(id).map(|t| &t.kind), Ok(Kind::Typedef { .. })))
                .ok_or_else(|| format!("no typedef '{tname}' in target BTF"))?;
            // typedef -> ptr -> func_proto
            let r = btf.resolve(td)?;
            let Kind::Ptr { type_id } = btf.ty(r)?.kind else {
                return Err(format!("'{tname}' does not resolve to a function pointer"));
            };
            (btf.resolve(type_id)?, true, false, tname)
        } else if let Some(name) = section
            .strip_prefix("fentry/")
            .or_else(|| section.strip_prefix("fmod_ret/"))
        {
            (func_proto_of(btf, name)?, false, false, name.to_string())
        } else if let Some(name) = section.strip_prefix("fexit/") {
            (func_proto_of(btf, name)?, false, true, name.to_string())
        } else {
            return Ok(None);
        };

    let Kind::FuncProto { params, ret_type } = &btf.ty(proto_id)?.kind else {
        return Err(format!("'{what}' does not resolve to a function prototype"));
    };
    let mut slots = Vec::new();
    for p in params.iter().skip(skip_data_arg as usize) {
        if p.type_id == 0 {
            break; // trailing void / vararg marker
        }
        slots.push(slot_of(btf, p.type_id)?);
    }
    if ret_slot {
        slots.push(if *ret_type == 0 {
            CtxSlot::Scalar
        } else {
            slot_of(btf, *ret_type)?
        });
    }
    Ok(Some(slots))
}

/// The func_proto type id of the named kernel function.
fn func_proto_of(btf: &Btf, name: &str) -> Result<u32, String> {
    let f = btf
        .ids_by_name(name)
        .iter()
        .copied()
        .find(|&id| matches!(btf.ty(id).map(|t| &t.kind), Ok(Kind::Func { .. })))
        .ok_or_else(|| format!("no function '{name}' in target BTF"))?;
    match btf.ty(f)?.kind {
        Kind::Func { proto_type, .. } => Ok(btf.resolve(proto_type)?),
        _ => unreachable!(),
    }
}

/// Slot typing of one argument: pointer-to-struct/union becomes a BTF pointer
/// slot (with the pointee resolved through modifiers/typedefs); everything
/// else — ints, enums, by-value structs, pointers to scalars — reads as a
/// scalar, matching (or, for scalar-pointees, tightening) `btf_ctx_access()`.
fn slot_of(btf: &Btf, type_id: u32) -> Result<CtxSlot, String> {
    let r = btf.resolve(type_id)?;
    if let Kind::Ptr { type_id: pointee } = btf.ty(r)?.kind {
        let p = btf.resolve(pointee)?;
        if matches!(btf.ty(p)?.kind, Kind::Struct { .. } | Kind::Union { .. }) {
            return Ok(CtxSlot::Ptr { btf_id: p });
        }
    }
    Ok(CtxSlot::Scalar)
}

fn str_at(strs: &[u8], off: u32) -> &str {
    let off = off as usize;
    if off >= strs.len() {
        return "";
    }
    let end = strs[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| off + p)
        .unwrap_or(strs.len());
    std::str::from_utf8(&strs[off..end]).unwrap_or("")
}

// ---------------------------------------------------------------------------
// .BTF.ext — per-instruction metadata (func_info / line_info / core_relo)
// ---------------------------------------------------------------------------

/// CO-RE relocation kinds (`enum bpf_core_relo_kind`).
pub mod relo_kind {
    pub const FIELD_BYTE_OFFSET: u32 = 0;
    pub const FIELD_BYTE_SIZE: u32 = 1;
    pub const FIELD_EXISTS: u32 = 2;
    pub const FIELD_SIGNED: u32 = 3;
    pub const FIELD_LSHIFT_U64: u32 = 4;
    pub const FIELD_RSHIFT_U64: u32 = 5;
    pub const TYPE_ID_LOCAL: u32 = 6;
    pub const TYPE_ID_TARGET: u32 = 7;
    pub const TYPE_EXISTS: u32 = 8;
    pub const TYPE_SIZE: u32 = 9;
    pub const ENUMVAL_EXISTS: u32 = 10;
    pub const ENUMVAL_VALUE: u32 = 11;
    pub const TYPE_MATCHES: u32 = 12;

    pub fn name(k: u32) -> &'static str {
        match k {
            FIELD_BYTE_OFFSET => "field_byte_offset",
            FIELD_BYTE_SIZE => "field_byte_size",
            FIELD_EXISTS => "field_exists",
            FIELD_SIGNED => "field_signed",
            FIELD_LSHIFT_U64 => "field_lshift_u64",
            FIELD_RSHIFT_U64 => "field_rshift_u64",
            TYPE_ID_LOCAL => "type_id_local",
            TYPE_ID_TARGET => "type_id_target",
            TYPE_EXISTS => "type_exists",
            TYPE_SIZE => "type_size",
            ENUMVAL_EXISTS => "enumval_exists",
            ENUMVAL_VALUE => "enumval_value",
            TYPE_MATCHES => "type_matches",
            _ => "unknown",
        }
    }
}

/// One `bpf_core_relo` record. String offsets index the companion `.BTF`
/// string section; `insn_off` is a byte offset into the section's code.
#[derive(Debug, Clone)]
pub struct CoreRelo {
    pub insn_off: u32,
    pub type_id: u32,
    pub access_str_off: u32,
    pub kind: u32,
}

/// One `bpf_func_info` record: the FUNC type at an instruction.
#[derive(Debug, Clone)]
pub struct FuncInfo {
    pub insn_off: u32,
    pub type_id: u32,
}

/// One `bpf_line_info` record: source location of an instruction.
#[derive(Debug, Clone)]
pub struct LineInfo {
    pub insn_off: u32,
    pub file_name_off: u32,
    pub line_off: u32,
    pub line_col: u32,
}

impl LineInfo {
    pub fn line(&self) -> u32 {
        self.line_col >> 10
    }
    pub fn col(&self) -> u32 {
        self.line_col & 0x3ff
    }
}

/// Records of one `.BTF.ext` sub-section, grouped by the ELF section they
/// annotate (e.g. ".text", "xdp").
#[derive(Debug, Clone)]
pub struct ExtSec<T> {
    /// ELF section name (resolved from the companion `.BTF` string table).
    pub sec_name_off: u32,
    pub recs: Vec<T>,
}

/// A parsed `.BTF.ext` section: CO-RE relocations (semantic) plus
/// func/line info (stored for future source-level debugging).
#[derive(Debug, Clone, Default)]
pub struct BtfExt {
    pub func_info: Vec<ExtSec<FuncInfo>>,
    pub line_info: Vec<ExtSec<LineInfo>>,
    pub core_relos: Vec<ExtSec<CoreRelo>>,
}

impl BtfExt {
    /// Parse a raw `.BTF.ext` section payload. All string offsets inside
    /// refer to the companion `.BTF` string table (resolve via [`Btf::str_at`]).
    pub fn parse(le: bool, data: &[u8]) -> Result<BtfExt, String> {
        let r = R { buf: data, le };
        if r.u16(0)? != BTF_MAGIC {
            return Err("bad .BTF.ext magic".into());
        }
        let hdr_len = r.u32(4)? as usize;
        if hdr_len < 24 {
            return Err(".BTF.ext header too short".into());
        }
        let func_off = r.u32(8)? as usize;
        let func_len = r.u32(12)? as usize;
        let line_off = r.u32(16)? as usize;
        let line_len = r.u32(20)? as usize;
        // core_relo fields exist only in the extended (hdr_len >= 32) header.
        let (core_off, core_len) = if hdr_len >= 32 {
            (r.u32(24)? as usize, r.u32(28)? as usize)
        } else {
            (0, 0)
        };

        Ok(BtfExt {
            func_info: parse_ext_info(&r, hdr_len, func_off, func_len, 8, |r, p| {
                Ok(FuncInfo {
                    insn_off: r.u32(p)?,
                    type_id: r.u32(p + 4)?,
                })
            })?,
            line_info: parse_ext_info(&r, hdr_len, line_off, line_len, 16, |r, p| {
                Ok(LineInfo {
                    insn_off: r.u32(p)?,
                    file_name_off: r.u32(p + 4)?,
                    line_off: r.u32(p + 8)?,
                    line_col: r.u32(p + 12)?,
                })
            })?,
            core_relos: parse_ext_info(&r, hdr_len, core_off, core_len, 16, |r, p| {
                Ok(CoreRelo {
                    insn_off: r.u32(p)?,
                    type_id: r.u32(p + 4)?,
                    access_str_off: r.u32(p + 8)?,
                    kind: r.u32(p + 12)?,
                })
            })?,
        })
    }

    /// Total number of CO-RE relocations across all sections.
    pub fn num_core_relos(&self) -> usize {
        self.core_relos.iter().map(|s| s.recs.len()).sum()
    }
}

/// Parse one `.BTF.ext` sub-section: `u32 record_size` followed by
/// `btf_ext_info_sec { sec_name_off, num_info }` groups. `record_size` may
/// exceed `min_rec` (newer toolchains append fields); the excess is skipped.
fn parse_ext_info<T>(
    r: &R,
    hdr_len: usize,
    off: usize,
    len: usize,
    min_rec: usize,
    read: impl Fn(&R, usize) -> Result<T, String>,
) -> Result<Vec<ExtSec<T>>, String> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let start = hdr_len + off;
    let end = start
        .checked_add(len)
        .filter(|&e| e <= r.buf.len())
        .ok_or(".BTF.ext: info section out of bounds")?;
    let rec_size = r.u32(start)? as usize;
    if rec_size < min_rec || !rec_size.is_multiple_of(4) {
        return Err(format!(".BTF.ext: bad record size {rec_size}"));
    }
    let mut out = Vec::new();
    let mut p = start + 4;
    while p < end {
        let sec_name_off = r.u32(p)?;
        let num = r.u32(p + 4)? as usize;
        p += 8;
        if p + num.saturating_mul(rec_size) > end {
            return Err(".BTF.ext: info section overruns its length".into());
        }
        let mut recs = Vec::with_capacity(num);
        for _ in 0..num {
            recs.push(read(r, p)?);
            p += rec_size;
        }
        out.push(ExtSec { sec_name_off, recs });
    }
    if p != end {
        return Err(".BTF.ext: info section desynchronized".into());
    }
    Ok(out)
}

/// The "essential name" of a type: the name with any `___flavor` suffix
/// stripped. CO-RE candidate matching compares essential names so that
/// `task_struct___v2` in the program matches `task_struct` in the kernel.
pub fn essential_name(name: &str) -> &str {
    match name.find("___") {
        Some(0) | None => name,
        Some(i) => &name[..i],
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Hand-assemble a BTF blob from (name, info, size_or_type, extra-words).
    pub(crate) fn build_btf(strings: &[&str], types: &[(u32, u32, u32, Vec<u32>)]) -> Vec<u8> {
        let mut strs = vec![0u8]; // offset 0 = ""
        let mut offs = vec![0u32];
        for s in strings {
            offs.push(strs.len() as u32);
            strs.extend_from_slice(s.as_bytes());
            strs.push(0);
        }
        let _ = offs;
        let mut tsec = Vec::new();
        for (name_off, info, sz, extra) in types {
            tsec.extend_from_slice(&name_off.to_le_bytes());
            tsec.extend_from_slice(&info.to_le_bytes());
            tsec.extend_from_slice(&sz.to_le_bytes());
            for w in extra {
                tsec.extend_from_slice(&w.to_le_bytes());
            }
        }
        let mut out = Vec::new();
        out.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        out.push(1); // version
        out.push(0); // flags
        out.extend_from_slice(&24u32.to_le_bytes()); // hdr_len
        out.extend_from_slice(&0u32.to_le_bytes()); // type_off
        out.extend_from_slice(&(tsec.len() as u32).to_le_bytes());
        out.extend_from_slice(&(tsec.len() as u32).to_le_bytes()); // str_off
        out.extend_from_slice(&(strs.len() as u32).to_le_bytes());
        out.extend(tsec);
        out.extend(strs);
        out
    }

    /// String offset helper matching `build_btf`'s layout.
    pub(crate) fn stroff(strings: &[&str], name: &str) -> u32 {
        let mut off = 1u32;
        for s in strings {
            if *s == name {
                return off;
            }
            off += s.len() as u32 + 1;
        }
        panic!("string {name} not in table");
    }

    fn info(kind: u32, vlen: u32, kflag: bool) -> u32 {
        (kind << 24) | (vlen & 0xffff) | ((kflag as u32) << 31)
    }

    #[test]
    fn parse_struct_graph() {
        let strings = ["int", "x", "y", "point", "flags"];
        let s = |n| stroff(&strings, n);
        let blob = build_btf(
            &strings,
            &[
                // [1] int, size 4, signed 32 bits
                (
                    s("int"),
                    info(kind::INT, 0, false),
                    4,
                    vec![(1u32 << 24) | 32],
                ),
                // [2] struct point { int x; int y; }
                (
                    s("point"),
                    info(kind::STRUCT, 2, false),
                    8,
                    vec![s("x"), 1, 0, s("y"), 1, 32],
                ),
                // [3] bitfield struct (kind_flag): flags:3 at bit 0
                (
                    0,
                    info(kind::STRUCT, 1, true),
                    4,
                    vec![s("flags"), 1, (3u32 << 24)],
                ),
                // [4] ptr -> point
                (0, info(kind::PTR, 0, false), 2, vec![]),
                // [5] array of 10 ints
                (0, info(kind::ARRAY, 0, false), 0, vec![1, 1, 10]),
            ],
        );
        let btf = Btf::parse(true, &blob).unwrap();
        assert_eq!(btf.len(), 6);
        assert_eq!(btf.type_name(2), "point");
        let Kind::Struct { size, members } = &btf.ty(2).unwrap().kind else {
            panic!("not a struct");
        };
        assert_eq!(*size, 8);
        assert_eq!(members.len(), 2);
        assert_eq!(btf.str_at(members[1].name_off), "y");
        assert_eq!(members[1].bit_offset, 32);
        assert_eq!(members[1].bitfield_size, 0);
        let Kind::Struct { members: bm, .. } = &btf.ty(3).unwrap().kind else {
            panic!()
        };
        assert_eq!((bm[0].bit_offset, bm[0].bitfield_size), (0, 3));
        assert_eq!(btf.type_size(4).unwrap(), 8); // pointer
        assert_eq!(btf.type_size(5).unwrap(), 40); // 10 * int
        assert_eq!(btf.ids_by_name("point"), &[2]);
    }

    #[test]
    fn resolve_skips_modifiers() {
        let strings = ["int", "myint"];
        let s = |n| stroff(&strings, n);
        let blob = build_btf(
            &strings,
            &[
                (
                    s("int"),
                    info(kind::INT, 0, false),
                    4,
                    vec![(1u32 << 24) | 32],
                ),
                (s("myint"), info(kind::TYPEDEF, 0, false), 1, vec![]),
                (0, info(kind::CONST, 0, false), 2, vec![]),
                (0, info(kind::VOLATILE, 0, false), 3, vec![]),
            ],
        );
        let btf = Btf::parse(true, &blob).unwrap();
        assert_eq!(btf.resolve(4).unwrap(), 1);
        assert_eq!(btf.type_size(4).unwrap(), 4);
    }

    #[test]
    fn enum_and_enum64() {
        let strings = ["A", "B", "big"];
        let s = |n| stroff(&strings, n);
        let blob = build_btf(
            &strings,
            &[
                // [1] enum { A = -1, B = 5 } (signed)
                (
                    0,
                    info(kind::ENUM, 2, true),
                    4,
                    vec![s("A"), (-1i32) as u32, s("B"), 5],
                ),
                // [2] enum64 { big = 0x1_0000_0001 }
                (
                    0,
                    info(kind::ENUM64, 1, false),
                    8,
                    vec![s("big"), 1, 1],
                ),
            ],
        );
        let btf = Btf::parse(true, &blob).unwrap();
        let Kind::Enum { vals, signed, is64, .. } = &btf.ty(1).unwrap().kind else {
            panic!()
        };
        assert!(*signed && !*is64);
        assert_eq!(vals[0].value as i64, -1);
        assert_eq!(vals[1].value, 5);
        let Kind::Enum { vals, is64, .. } = &btf.ty(2).unwrap().kind else {
            panic!()
        };
        assert!(*is64);
        assert_eq!(vals[0].value, 0x1_0000_0001);
    }

    #[test]
    fn desync_is_detected() {
        // A FUNC_PROTO whose vlen promises more params than the section holds.
        let blob = build_btf(&[], &[(0, 13 << 24 | 3, 0, vec![0, 0])]);
        assert!(Btf::parse(true, &blob).is_err());
    }

    #[test]
    fn btf_ext_roundtrip() {
        // Hand-build a .BTF.ext with an oversized core_relo record size (20
        // instead of 16) to check the skip-excess path, plus empty func/line.
        let mut b = Vec::new();
        b.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        b.push(1);
        b.push(0);
        b.extend_from_slice(&32u32.to_le_bytes()); // hdr_len
        let core: &[u32] = &[
            20, // record_size (16 + 4 bytes of future extension)
            7,  // sec_name_off
            2,  // num_info
            0, 5, 100, 0, 0xdead, // relo 1 (+pad)
            8, 5, 104, 2, 0xbeef, // relo 2 (+pad)
        ];
        let core_len = core.len() as u32 * 4;
        for (off, len) in [(0u32, 0u32), (0, 0), (0, core_len)] {
            b.extend_from_slice(&off.to_le_bytes());
            b.extend_from_slice(&len.to_le_bytes());
        }
        for w in core {
            b.extend_from_slice(&w.to_le_bytes());
        }
        let ext = BtfExt::parse(true, &b).unwrap();
        assert!(ext.func_info.is_empty() && ext.line_info.is_empty());
        assert_eq!(ext.num_core_relos(), 2);
        let sec = &ext.core_relos[0];
        assert_eq!(sec.sec_name_off, 7);
        assert_eq!(
            (sec.recs[0].insn_off, sec.recs[0].type_id, sec.recs[0].access_str_off, sec.recs[0].kind),
            (0, 5, 100, relo_kind::FIELD_BYTE_OFFSET)
        );
        assert_eq!(
            (sec.recs[1].insn_off, sec.recs[1].kind),
            (8, relo_kind::FIELD_EXISTS)
        );

        // A legacy 24-byte header (no core_relo words) parses with no relos.
        let mut old = Vec::new();
        old.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        old.push(1);
        old.push(0);
        old.extend_from_slice(&24u32.to_le_bytes());
        old.extend_from_slice(&[0u8; 16]); // func/line off+len = 0
        let ext = BtfExt::parse(true, &old).unwrap();
        assert_eq!(ext.num_core_relos(), 0);

        // Truncated info section is an error, not a desync.
        let mut bad = b.clone();
        bad.truncate(bad.len() - 4);
        assert!(BtfExt::parse(true, &bad).is_err());
    }

    #[test]
    fn essential_names() {
        assert_eq!(essential_name("task_struct"), "task_struct");
        assert_eq!(essential_name("task_struct___v2"), "task_struct");
        assert_eq!(essential_name("a___b___c"), "a");
        assert_eq!(essential_name("___weird"), "___weird");
        assert_eq!(essential_name(""), "");
    }
}
