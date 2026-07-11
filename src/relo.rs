//! CO-RE relocation resolution, mirroring libbpf's `relo_core.c`.
//!
//! Given a `bpf_core_relo` (local type id + access string + kind) from a
//! program's `.BTF.ext` and a *target* BTF (e.g. the running kernel's
//! `/sys/kernel/btf/vmlinux`), compute the value the relocated instruction
//! must carry on the target: field byte offsets/sizes, type sizes/ids, enum
//! values, existence flags. See `docs/specs/core-relocations.md` §2.
//!
//! The shape follows libbpf: parse the access spec against the local BTF
//! (by member *index*), find target candidates by essential name, replay the
//! spec against each candidate (by member *name*, descending into anonymous
//! members), and require all matching candidates to agree on the result.

use crate::btf::{essential_name, relo_kind, Btf, CoreRelo, Kind, Member};
use std::collections::HashMap;

const MAX_SPEC_LEN: usize = 64;
const MAX_TYPE_DEPTH: u32 = 32;

/// The outcome of resolving one relocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloResult {
    /// Value to patch into the instruction.
    pub new_val: u64,
    /// Value the compiler baked in (computed from the local BTF); used to
    /// validate the instruction before patching.
    pub orig_val: u64,
    /// Whether the instruction's current value must equal `orig_val`.
    pub validate: bool,
    /// Number of target candidates that matched (0 for EXISTS-style misses
    /// and for relos that need no target).
    pub matched: usize,
    /// A non-EXISTS relocation found no matching candidate: the instruction
    /// cannot be resolved and should be poisoned (libbpf-style), so that the
    /// program still loads and only fails if the path is actually taken.
    pub poison: bool,
}

/// Essential-name index over a target BTF, built once and reused for every
/// relocation (vmlinux has ~150k types; candidate lookup must be O(1)).
pub struct CandidateIndex {
    by_essential: HashMap<String, Vec<u32>>,
}

impl CandidateIndex {
    pub fn new(btf: &Btf) -> CandidateIndex {
        let mut by_essential: HashMap<String, Vec<u32>> = HashMap::new();
        for (id, t) in btf.iter() {
            // Only kinds that can be relocation roots.
            match t.kind {
                Kind::Struct { .. }
                | Kind::Union { .. }
                | Kind::Enum { .. }
                | Kind::Int { .. }
                | Kind::Float { .. }
                | Kind::Typedef { .. }
                | Kind::Fwd { .. } => {}
                _ => continue,
            }
            let name = btf.str_at(t.name_off);
            if name.is_empty() {
                continue;
            }
            by_essential
                .entry(essential_name(name).to_string())
                .or_default()
                .push(id);
        }
        CandidateIndex { by_essential }
    }

    fn candidates(&self, essential: &str) -> &[u32] {
        self.by_essential
            .get(essential)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

/// One step of an access spec, in the form used for target matching.
/// Anonymous-member hops contribute only to the bit offset and produce no
/// step (libbpf does the same), so a target match descends into anonymous
/// members by itself.
#[derive(Debug, Clone)]
enum Step {
    /// Array indexing; the first raw index is this with the root as element.
    Array { idx: u32 },
    /// Named member access.
    Member { name: String, local_type: u32 },
}

/// The local access spec, resolved against the program's own BTF.
#[derive(Debug)]
struct LocalSpec {
    steps: Vec<Step>,
    bit_offset: u64,
    /// Final accessed member, when the last step lands on one.
    last_member: Option<Member>,
    /// Type id of the final accessed entity (member/element/root).
    field_id: u32,
}

fn parse_access(s: &str) -> Result<Vec<u32>, String> {
    if s.is_empty() {
        return Err("empty CO-RE access string".into());
    }
    let parts: Vec<u32> = s
        .split(':')
        .map(|p| {
            p.parse::<u32>()
                .map_err(|_| format!("bad CO-RE access string '{s}'"))
        })
        .collect::<Result<_, _>>()?;
    if parts.len() > MAX_SPEC_LEN {
        return Err(format!("CO-RE access string too long ({} steps)", parts.len()));
    }
    Ok(parts)
}

fn is_field_kind(k: u32) -> bool {
    matches!(
        k,
        relo_kind::FIELD_BYTE_OFFSET
            | relo_kind::FIELD_BYTE_SIZE
            | relo_kind::FIELD_EXISTS
            | relo_kind::FIELD_SIGNED
            | relo_kind::FIELD_LSHIFT_U64
            | relo_kind::FIELD_RSHIFT_U64
    )
}

fn is_type_kind(k: u32) -> bool {
    matches!(
        k,
        relo_kind::TYPE_ID_LOCAL
            | relo_kind::TYPE_ID_TARGET
            | relo_kind::TYPE_EXISTS
            | relo_kind::TYPE_SIZE
            | relo_kind::TYPE_MATCHES
    )
}

fn is_enumval_kind(k: u32) -> bool {
    matches!(k, relo_kind::ENUMVAL_EXISTS | relo_kind::ENUMVAL_VALUE)
}

/// EXISTS-style relos resolve to 0 instead of erroring when nothing matches.
fn is_exists_kind(k: u32) -> bool {
    matches!(
        k,
        relo_kind::FIELD_EXISTS
            | relo_kind::TYPE_EXISTS
            | relo_kind::TYPE_MATCHES
            | relo_kind::ENUMVAL_EXISTS
    )
}

/// Parse and resolve the access spec against the local BTF (member access by
/// index — the compiler recorded indices into *its* type graph).
fn parse_local_spec(btf: &Btf, type_id: u32, raw: &[u32]) -> Result<LocalSpec, String> {
    let root_id = btf.resolve(type_id)?;
    let mut id = root_id;
    let mut bit_offset = raw[0] as u64 * btf.type_size(id)? as u64 * 8;
    let mut steps = vec![Step::Array { idx: raw[0] }];
    let mut last_member: Option<Member> = None;
    let mut field_id = root_id;

    for &idx in &raw[1..] {
        id = btf.resolve(id)?;
        match &btf.ty(id)?.kind {
            Kind::Struct { members, .. } | Kind::Union { members, .. } => {
                let m = members
                    .get(idx as usize)
                    .ok_or_else(|| format!("CO-RE spec member index {idx} out of range"))?;
                bit_offset += m.bit_offset as u64;
                let name = btf.str_at(m.name_off);
                if !name.is_empty() {
                    steps.push(Step::Member {
                        name: name.to_string(),
                        local_type: m.type_id,
                    });
                }
                last_member = Some(m.clone());
                field_id = m.type_id;
                id = m.type_id;
            }
            Kind::Array { elem_type, .. } => {
                let elem = *elem_type;
                bit_offset += idx as u64 * btf.type_size(elem)? as u64 * 8;
                steps.push(Step::Array { idx });
                last_member = None;
                field_id = elem;
                id = elem;
            }
            _ => {
                return Err(format!(
                    "CO-RE spec walks into non-composite type {} ('{}')",
                    id,
                    btf.type_name(id)
                ))
            }
        }
    }
    Ok(LocalSpec {
        steps,
        bit_offset,
        last_member,
        field_id,
    })
}

/// The result of replaying a spec against one target candidate.
struct TargetField {
    bit_offset: u64,
    last_member: Option<Member>,
    field_id: u32,
}

/// Find a member by name in a target struct/union, descending into anonymous
/// struct/union members (accumulating their offsets), as libbpf's
/// `bpf_core_match_member` does.
fn find_member(
    btf: &Btf,
    id: u32,
    name: &str,
    depth: u32,
) -> Result<Option<(u64, Member)>, String> {
    if depth == 0 {
        return Err("CO-RE member search too deep".into());
    }
    let id = btf.resolve(id)?;
    let members = match &btf.ty(id)?.kind {
        Kind::Struct { members, .. } | Kind::Union { members, .. } => members,
        _ => return Ok(None),
    };
    for m in members {
        let mname = btf.str_at(m.name_off);
        if mname == name {
            return Ok(Some((m.bit_offset as u64, m.clone())));
        }
        if mname.is_empty() {
            if let Some((off, inner)) = find_member(btf, m.type_id, name, depth - 1)? {
                return Ok(Some((m.bit_offset as u64 + off, inner)));
            }
        }
    }
    Ok(None)
}

/// libbpf `bpf_core_fields_are_compat`: shallow compatibility between the
/// local and target types of a matched field.
fn fields_compat(
    local: &Btf,
    l_id: u32,
    target: &Btf,
    t_id: u32,
    depth: u32,
) -> Result<bool, String> {
    if depth == 0 {
        return Ok(false);
    }
    let l = &local.ty(local.resolve(l_id)?)?.kind;
    let t = &target.ty(target.resolve(t_id)?)?.kind;
    Ok(match (l, t) {
        // Any two composites are shallow-compatible; their members are
        // checked when (and if) the spec walks into them.
        (Kind::Struct { .. } | Kind::Union { .. }, Kind::Struct { .. } | Kind::Union { .. }) => {
            true
        }
        (Kind::Ptr { .. }, Kind::Ptr { .. }) => true,
        (Kind::Float { .. }, Kind::Float { .. }) => true,
        // Integers of any size are compatible.
        (Kind::Int { .. }, Kind::Int { .. }) => true,
        // Enums (32/64-bit alike): essential names must agree, unless one
        // side is anonymous.
        (Kind::Enum { .. }, Kind::Enum { .. }) | (Kind::Fwd { .. }, Kind::Fwd { .. }) => {
            let ln = essential_name(local.type_name(local.resolve(l_id)?));
            let tn = essential_name(target.type_name(target.resolve(t_id)?));
            ln.is_empty() || tn.is_empty() || ln == tn
        }
        (
            Kind::Array {
                elem_type: le, ..
            },
            Kind::Array {
                elem_type: te, ..
            },
        ) => fields_compat(local, *le, target, *te, depth - 1)?,
        _ => false,
    })
}

/// Replay the local spec against one target candidate (by member name).
/// `Ok(None)` = candidate does not match.
fn match_target_spec(
    local: &Btf,
    spec: &LocalSpec,
    target: &Btf,
    cand: u32,
) -> Result<Option<TargetField>, String> {
    let mut id = target.resolve(cand)?;
    let mut bit_offset = 0u64;
    let mut last_member: Option<Member> = None;
    let mut field_id = id;

    for (i, step) in spec.steps.iter().enumerate() {
        id = target.resolve(id)?;
        match step {
            Step::Array { idx } => {
                let elem = if i == 0 {
                    id // leading index dereferences the root pointer
                } else {
                    match &target.ty(id)?.kind {
                        Kind::Array { elem_type, .. } => target.resolve(*elem_type)?,
                        _ => return Ok(None),
                    }
                };
                bit_offset += *idx as u64 * target.type_size(elem)? as u64 * 8;
                last_member = None;
                field_id = elem;
                id = elem;
            }
            Step::Member { name, local_type } => {
                let Some((off, m)) = find_member(target, id, name, MAX_TYPE_DEPTH)? else {
                    return Ok(None);
                };
                if !fields_compat(local, *local_type, target, m.type_id, MAX_TYPE_DEPTH)? {
                    return Ok(None);
                }
                bit_offset += off;
                field_id = m.type_id;
                id = m.type_id;
                last_member = Some(m);
            }
        }
    }
    Ok(Some(TargetField {
        bit_offset,
        last_member,
        field_id,
    }))
}

/// libbpf `bpf_core_types_are_compat` (used by TYPE_EXISTS): kinds must agree
/// recursively through pointers/arrays/func protos; names are not compared.
fn types_compat(local: &Btf, l_id: u32, target: &Btf, t_id: u32, depth: u32) -> Result<bool, String> {
    if depth == 0 {
        return Ok(false);
    }
    let l = &local.ty(local.resolve(l_id)?)?.kind;
    let t = &target.ty(target.resolve(t_id)?)?.kind;
    Ok(match (l, t) {
        (Kind::Void, Kind::Void) => true,
        (Kind::Struct { .. }, Kind::Struct { .. }) => true,
        (Kind::Union { .. }, Kind::Union { .. }) => true,
        (Kind::Enum { .. }, Kind::Enum { .. }) => true,
        (Kind::Fwd { .. }, Kind::Fwd { .. }) => true,
        (Kind::Int { .. }, Kind::Int { .. }) => true,
        (Kind::Float { .. }, Kind::Float { .. }) => true,
        (Kind::Ptr { type_id: lp }, Kind::Ptr { type_id: tp }) => {
            types_compat(local, *lp, target, *tp, depth - 1)?
        }
        (Kind::Array { elem_type: le, .. }, Kind::Array { elem_type: te, .. }) => {
            types_compat(local, *le, target, *te, depth - 1)?
        }
        (
            Kind::FuncProto {
                ret_type: lr,
                params: lp,
            },
            Kind::FuncProto {
                ret_type: tr,
                params: tp,
            },
        ) => {
            if lp.len() != tp.len() {
                return Ok(false);
            }
            for (a, b) in lp.iter().zip(tp) {
                if !types_compat(local, a.type_id, target, b.type_id, depth - 1)? {
                    return Ok(false);
                }
            }
            types_compat(local, *lr, target, *tr, depth - 1)?
        }
        _ => false,
    })
}

/// libbpf `bpf_core_types_match` (used by TYPE_MATCHES): like `types_compat`
/// but names must match (modulo flavors) and composites/enums must contain
/// every local member/enumerator with recursively matching types.
fn types_match(local: &Btf, l_id: u32, target: &Btf, t_id: u32, depth: u32) -> Result<bool, String> {
    if depth == 0 {
        return Ok(false);
    }
    let l_id = local.resolve(l_id)?;
    let t_id = target.resolve(t_id)?;
    let ln = essential_name(local.type_name(l_id));
    let tn = essential_name(target.type_name(t_id));
    if !ln.is_empty() && !tn.is_empty() && ln != tn {
        return Ok(false);
    }
    let l = &local.ty(l_id)?.kind;
    let t = &target.ty(t_id)?.kind;
    Ok(match (l, t) {
        (Kind::Void, Kind::Void) => true,
        (Kind::Fwd { is_union: a }, Kind::Fwd { is_union: b }) => a == b,
        (
            Kind::Int {
                size: ls,
                encoding: le,
                ..
            },
            Kind::Int {
                size: ts,
                encoding: te,
                ..
            },
        ) => ls == ts && le == te,
        (Kind::Float { size: ls }, Kind::Float { size: ts }) => ls == ts,
        (Kind::Ptr { type_id: lp }, Kind::Ptr { type_id: tp }) => {
            types_match(local, *lp, target, *tp, depth - 1)?
        }
        (
            Kind::Array {
                elem_type: le,
                nelems: lnel,
                ..
            },
            Kind::Array {
                elem_type: te,
                nelems: tnel,
                ..
            },
        ) => lnel == tnel && types_match(local, *le, target, *te, depth - 1)?,
        (Kind::Struct { members: lm, .. }, Kind::Struct { members: tm, .. })
        | (Kind::Union { members: lm, .. }, Kind::Union { members: tm, .. }) => {
            // every local member must exist in the target with a matching type
            for m in lm {
                let name = local.str_at(m.name_off);
                if name.is_empty() {
                    // anonymous member: require some anonymous target member
                    // with a matching type
                    let mut found = false;
                    for t_m in tm {
                        if target.str_at(t_m.name_off).is_empty()
                            && types_match(local, m.type_id, target, t_m.type_id, depth - 1)?
                        {
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        return Ok(false);
                    }
                    continue;
                }
                match find_member(target, t_id, name, MAX_TYPE_DEPTH)? {
                    Some((_, t_m)) => {
                        if !types_match(local, m.type_id, target, t_m.type_id, depth - 1)? {
                            return Ok(false);
                        }
                    }
                    None => return Ok(false),
                }
            }
            true
        }
        (Kind::Enum { vals: lv, .. }, Kind::Enum { vals: tv, .. }) => {
            // every local enumerator name must exist in the target
            lv.iter().all(|v| {
                let name = local.str_at(v.name_off);
                tv.iter().any(|t_v| target.str_at(t_v.name_off) == name)
            })
        }
        (
            Kind::FuncProto {
                ret_type: lr,
                params: lp,
            },
            Kind::FuncProto {
                ret_type: tr,
                params: tp,
            },
        ) => {
            if lp.len() != tp.len() {
                return Ok(false);
            }
            for (a, b) in lp.iter().zip(tp) {
                if !types_match(local, a.type_id, target, b.type_id, depth - 1)? {
                    return Ok(false);
                }
            }
            types_match(local, *lr, target, *tr, depth - 1)?
        }
        _ => false,
    })
}

/// Compute the value of a field-based relocation from a resolved field
/// (mirrors `bpf_core_calc_field_relo`). Returns `(value, validate)`.
fn field_value(
    btf: &Btf,
    relo: u32,
    bit_offset: u64,
    last_member: Option<&Member>,
    field_id: u32,
) -> Result<(u64, bool), String> {
    if relo == relo_kind::FIELD_EXISTS {
        return Ok((1, false));
    }
    let bitfield_bits = last_member.map(|m| m.bitfield_size as u64).unwrap_or(0);
    let is_bitfield = bitfield_bits > 0;

    let (byte_off, byte_sz, bit_sz) = if is_bitfield {
        // Find the smallest power-of-two load that covers the bitfield,
        // starting from the underlying int's size.
        let mut byte_sz = btf.type_size(field_id)? as u64;
        let mut byte_off = bit_offset / 8 / byte_sz * byte_sz;
        while bit_offset + bitfield_bits > (byte_off + byte_sz) * 8 {
            if byte_sz >= 8 {
                return Err(format!(
                    "CO-RE bitfield at bit {bit_offset} size {bitfield_bits} spans >8 bytes"
                ));
            }
            byte_sz *= 2;
            byte_off = bit_offset / 8 / byte_sz * byte_sz;
        }
        (byte_off, byte_sz, bitfield_bits)
    } else {
        let sz = btf.type_size(field_id)? as u64;
        (bit_offset / 8, sz, sz * 8)
    };

    Ok(match relo {
        relo_kind::FIELD_BYTE_OFFSET => (byte_off, !is_bitfield),
        relo_kind::FIELD_BYTE_SIZE => (byte_sz, !is_bitfield),
        relo_kind::FIELD_SIGNED => {
            let id = btf.resolve(field_id)?;
            let signed = match &btf.ty(id)?.kind {
                Kind::Int { encoding, .. } => encoding & crate::btf::int_enc::SIGNED != 0,
                Kind::Enum { signed, .. } => *signed,
                _ => false,
            };
            (signed as u64, true)
        }
        // Little-endian formulas (BPF objects and febpf's memory model are
        // little-endian).
        relo_kind::FIELD_LSHIFT_U64 => (64 - (bit_offset + bit_sz - byte_off * 8), false),
        relo_kind::FIELD_RSHIFT_U64 => (64 - bit_sz, false),
        other => return Err(format!("not a field relocation kind: {other}")),
    })
}

/// Resolve one CO-RE relocation against a target BTF. `index` must be
/// `CandidateIndex::new(target)` (built once, shared across relocations).
pub fn calc_relo(
    local: &Btf,
    relo: &CoreRelo,
    target: &Btf,
    index: &CandidateIndex,
) -> Result<ReloResult, String> {
    let access = local.str_at(relo.access_str_off).to_string();
    let raw = parse_access(&access)?;
    let kindname = relo_kind::name(relo.kind);

    // TYPE_ID_LOCAL needs no target at all.
    if relo.kind == relo_kind::TYPE_ID_LOCAL {
        return Ok(ReloResult {
            new_val: relo.type_id as u64,
            orig_val: relo.type_id as u64,
            validate: true,
            matched: 0,
            poison: false,
        });
    }

    // Root type name for candidate lookup. Like libbpf, the root's own name
    // is used (a typedef root matches target typedefs of the same name);
    // anonymous roots cannot be searched for.
    let root_name = local.type_name(relo.type_id);
    if root_name.is_empty() {
        return Err(format!("CO-RE {kindname}: anonymous root type {}", relo.type_id));
    }
    let essential = essential_name(root_name).to_string();
    let local_resolved = local.resolve(relo.type_id)?;
    let local_kind_discr = local.ty(local_resolved)?.kind.discr();

    // Local ("orig") value and, for field relos, the parsed spec.
    let field_spec = if is_field_kind(relo.kind) {
        Some(parse_local_spec(local, relo.type_id, &raw)?)
    } else {
        None
    };
    let orig_val = if let Some(spec) = &field_spec {
        field_value(
            local,
            relo.kind,
            spec.bit_offset,
            spec.last_member.as_ref(),
            spec.field_id,
        )?
        .0
    } else if is_type_kind(relo.kind) {
        match relo.kind {
            relo_kind::TYPE_EXISTS | relo_kind::TYPE_MATCHES => 1,
            relo_kind::TYPE_SIZE => local.type_size(relo.type_id)? as u64,
            relo_kind::TYPE_ID_TARGET => relo.type_id as u64,
            _ => unreachable!(),
        }
    } else if is_enumval_kind(relo.kind) {
        let Kind::Enum { vals, .. } = &local.ty(local_resolved)?.kind else {
            return Err(format!("CO-RE {kindname}: root is not an enum"));
        };
        let v = vals
            .get(raw[0] as usize)
            .ok_or_else(|| format!("CO-RE {kindname}: enumerator index {} out of range", raw[0]))?;
        match relo.kind {
            relo_kind::ENUMVAL_EXISTS => 1,
            _ => v.value,
        }
    } else {
        return Err(format!("unknown CO-RE relocation kind {}", relo.kind));
    };

    // Candidate search + per-candidate value computation.
    let mut result: Option<ReloResult> = None;
    for &cand in index.candidates(&essential) {
        // Kinds must agree. ENUM/ENUM64 are unified in our Kind::Enum but
        // carry distinct wire discriminants, so compare via a normalizer.
        let norm = |d: u32| {
            if d == crate::btf::kind::ENUM64 {
                crate::btf::kind::ENUM
            } else {
                d
            }
        };
        let cand_resolved = target.resolve(cand)?;
        if norm(target.ty(cand_resolved)?.kind.discr()) != norm(local_kind_discr) {
            continue;
        }

        let cand_val: Option<(u64, bool)> = if let Some(spec) = &field_spec {
            match match_target_spec(local, spec, target, cand)? {
                Some(tf) => Some(field_value(
                    target,
                    relo.kind,
                    tf.bit_offset,
                    tf.last_member.as_ref(),
                    tf.field_id,
                )?),
                None => None,
            }
        } else if is_type_kind(relo.kind) {
            let ok = match relo.kind {
                relo_kind::TYPE_MATCHES => {
                    types_match(local, relo.type_id, target, cand, MAX_TYPE_DEPTH)?
                }
                _ => types_compat(local, relo.type_id, target, cand, MAX_TYPE_DEPTH)?,
            };
            if !ok {
                None
            } else {
                match relo.kind {
                    relo_kind::TYPE_EXISTS | relo_kind::TYPE_MATCHES => Some((1, false)),
                    relo_kind::TYPE_SIZE => Some((target.type_size(cand)? as u64, false)),
                    relo_kind::TYPE_ID_TARGET => Some((cand as u64, false)),
                    _ => unreachable!(),
                }
            }
        } else {
            // enumval: find the local enumerator's name in the candidate.
            let Kind::Enum { vals: lv, .. } = &local.ty(local_resolved)?.kind else {
                unreachable!()
            };
            let want = local.str_at(lv[raw[0] as usize].name_off);
            let Kind::Enum { vals: tv, .. } = &target.ty(cand_resolved)?.kind else {
                continue;
            };
            tv.iter()
                .find(|v| target.str_at(v.name_off) == want)
                .map(|v| match relo.kind {
                    relo_kind::ENUMVAL_EXISTS => (1, false),
                    _ => (v.value, false),
                })
        };

        let Some((new_val, validate)) = cand_val else {
            continue;
        };
        match &result {
            Some(prev) => {
                if prev.new_val != new_val {
                    return Err(format!(
                        "CO-RE {kindname} '{root_name}' [{access}]: ambiguous — candidates \
                         disagree ({} vs {new_val})",
                        prev.new_val
                    ));
                }
                result = Some(ReloResult {
                    matched: prev.matched + 1,
                    ..prev.clone()
                });
            }
            None => {
                result = Some(ReloResult {
                    new_val,
                    orig_val,
                    validate,
                    matched: 1,
                    poison: false,
                })
            }
        }
    }

    match result {
        Some(r) => Ok(r),
        None if is_exists_kind(relo.kind) => Ok(ReloResult {
            new_val: 0,
            orig_val,
            validate: false,
            matched: 0,
            poison: false,
        }),
        // Nothing matched a non-EXISTS relocation: the instruction cannot be
        // resolved. Report it for poisoning (libbpf-style) rather than
        // failing the whole load — existence-guarded code never runs it.
        None => Ok(ReloResult {
            new_val: 0,
            orig_val,
            validate: false,
            matched: 0,
            poison: true,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btf::tests::{build_btf, stroff};
    use crate::btf::{kind, relo_kind};

    fn info(k: u32, vlen: u32, kflag: bool) -> u32 {
        (k << 24) | (vlen & 0xffff) | ((kflag as u32) << 31)
    }

    /// int + long + `struct point { int x; int y; long z; }` with the given
    /// member bit offsets and struct size, plus a set of access strings.
    fn point_btf(size: u32, x_bit: u32, y_bit: u32, z_bit: u32) -> Btf {
        let strings = ["int", "long", "x", "y", "z", "point", "0:0", "0:1", "0:2"];
        let s = |n| stroff(&strings, n);
        let blob = build_btf(
            &strings,
            &[
                (s("int"), info(kind::INT, 0, false), 4, vec![(1 << 24) | 32]),
                (s("long"), info(kind::INT, 0, false), 8, vec![(1 << 24) | 64]),
                (
                    s("point"),
                    info(kind::STRUCT, 3, false),
                    size,
                    vec![s("x"), 1, x_bit, s("y"), 1, y_bit, s("z"), 2, z_bit],
                ),
            ],
        );
        Btf::parse(true, &blob).unwrap()
    }

    fn relo(btf: &Btf, type_id: u32, access: &str, kind: u32) -> CoreRelo {
        // find the access string's offset by scanning: tests place access
        // strings into the same string table via build_btf's strings arg.
        let mut off = None;
        for i in 0..4096u32 {
            if btf.str_at(i) == access {
                off = Some(i);
                break;
            }
        }
        CoreRelo {
            insn_off: 0,
            type_id,
            access_str_off: off.expect("access string not in table"),
            kind,
        }
    }

    #[test]
    fn field_byte_offset_shifted_layout() {
        let local = point_btf(16, 0, 32, 64);
        let target = point_btf(24, 32, 64, 128); // everything shifted by 4/8B
        let idx = CandidateIndex::new(&target);
        for (access, orig, new) in [("0:0", 0, 4), ("0:1", 4, 8), ("0:2", 8, 16)] {
            let r = calc_relo(
                &local,
                &relo(&local, 3, access, relo_kind::FIELD_BYTE_OFFSET),
                &target,
                &idx,
            )
            .unwrap();
            assert_eq!((r.orig_val, r.new_val, r.matched), (orig, new, 1), "{access}");
            assert!(r.validate);
        }
        // field sizes are unchanged
        let r = calc_relo(
            &local,
            &relo(&local, 3, "0:2", relo_kind::FIELD_BYTE_SIZE),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!((r.orig_val, r.new_val), (8, 8));
        // signedness
        let r = calc_relo(
            &local,
            &relo(&local, 3, "0:0", relo_kind::FIELD_SIGNED),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!(r.new_val, 1);
    }

    #[test]
    fn members_matched_by_name_not_index() {
        let local = point_btf(16, 0, 32, 64);
        // Target declares y before x: index-based matching would swap them.
        let strings = ["int", "long", "x", "y", "z", "point"];
        let s = |n| stroff(&strings, n);
        let target = Btf::parse(
            true,
            &build_btf(
                &strings,
                &[
                    (s("int"), info(kind::INT, 0, false), 4, vec![(1 << 24) | 32]),
                    (s("long"), info(kind::INT, 0, false), 8, vec![(1 << 24) | 64]),
                    (
                        s("point"),
                        info(kind::STRUCT, 3, false),
                        16,
                        vec![s("y"), 1, 0, s("x"), 1, 32, s("z"), 2, 64],
                    ),
                ],
            ),
        )
        .unwrap();
        let idx = CandidateIndex::new(&target);
        let r = calc_relo(
            &local,
            &relo(&local, 3, "0:0", relo_kind::FIELD_BYTE_OFFSET),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!((r.orig_val, r.new_val), (0, 4)); // x moved to offset 4
    }

    #[test]
    fn anonymous_members_are_traversed() {
        // local: struct S { int a; }           (a at 0)
        // target: struct S { struct { int pad; int a; }; }  (a at 4, via anon)
        let ls = ["int", "a", "S", "0:0"];
        let l = |n| stroff(&ls, n);
        let local = Btf::parse(
            true,
            &build_btf(
                &ls,
                &[
                    (l("int"), info(kind::INT, 0, false), 4, vec![(1 << 24) | 32]),
                    (l("S"), info(kind::STRUCT, 1, false), 4, vec![l("a"), 1, 0]),
                ],
            ),
        )
        .unwrap();
        let ts = ["int", "pad", "a", "S"];
        let t = |n| stroff(&ts, n);
        let target = Btf::parse(
            true,
            &build_btf(
                &ts,
                &[
                    (t("int"), info(kind::INT, 0, false), 4, vec![(1 << 24) | 32]),
                    // [2] anon struct { int pad; int a; }
                    (
                        0,
                        info(kind::STRUCT, 2, false),
                        8,
                        vec![t("pad"), 1, 0, t("a"), 1, 32],
                    ),
                    // [3] struct S { <anon> at 0 }
                    (t("S"), info(kind::STRUCT, 1, false), 8, vec![0, 2, 0]),
                ],
            ),
        )
        .unwrap();
        let idx = CandidateIndex::new(&target);
        let r = calc_relo(
            &local,
            &relo(&local, 2, "0:0", relo_kind::FIELD_BYTE_OFFSET),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!((r.orig_val, r.new_val, r.matched), (0, 4, 1));
    }

    #[test]
    fn local_anonymous_member_folds_into_offset() {
        // local: struct S { int b; struct { int a; }; } — access "0:1:0" (a)
        // goes through the anonymous member: it contributes offset but no
        // name step, so the target lookup searches for "a" directly.
        let ls = ["int", "a", "b", "S", "0:1:0"];
        let l = |n| stroff(&ls, n);
        let local = Btf::parse(
            true,
            &build_btf(
                &ls,
                &[
                    (l("int"), info(kind::INT, 0, false), 4, vec![(1 << 24) | 32]),
                    // [2] anon struct { int a; }
                    (0, info(kind::STRUCT, 1, false), 4, vec![l("a"), 1, 0]),
                    // [3] struct S { int b; <anon> at 32 }
                    (
                        l("S"),
                        info(kind::STRUCT, 2, false),
                        8,
                        vec![l("b"), 1, 0, 0, 2, 32],
                    ),
                ],
            ),
        )
        .unwrap();
        // target: struct S { int a; int b; } — a is a plain member at 0.
        let ts = ["int", "a", "b", "S"];
        let t = |n| stroff(&ts, n);
        let target = Btf::parse(
            true,
            &build_btf(
                &ts,
                &[
                    (t("int"), info(kind::INT, 0, false), 4, vec![(1 << 24) | 32]),
                    (
                        t("S"),
                        info(kind::STRUCT, 2, false),
                        8,
                        vec![t("a"), 1, 0, t("b"), 1, 32],
                    ),
                ],
            ),
        )
        .unwrap();
        let idx = CandidateIndex::new(&target);
        let r = calc_relo(
            &local,
            &relo(&local, 3, "0:1:0", relo_kind::FIELD_BYTE_OFFSET),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!((r.orig_val, r.new_val), (4, 0));
    }

    #[test]
    fn array_element_access() {
        // struct A { int pre; long arr[8]; } — access "0:1:3" = arr[3]
        fn mk(pre_name: &str, arr_bit: u32, elem: u32) -> Btf {
            let ss = ["int", "long", "pre", "arr", "A", "0:1:3"];
            let s = |n| stroff(&ss, n);
            Btf::parse(
                true,
                &build_btf(
                    &ss,
                    &[
                        (s("int"), info(kind::INT, 0, false), 4, vec![(1 << 24) | 32]),
                        (s("long"), info(kind::INT, 0, false), 8, vec![(1 << 24) | 64]),
                        // [3] array of 8 elems
                        (0, info(kind::ARRAY, 0, false), 0, vec![elem, 1, 8]),
                        (
                            s("A"),
                            info(kind::STRUCT, 2, false),
                            72,
                            vec![s(pre_name), 1, 0, s("arr"), 3, arr_bit],
                        ),
                    ],
                ),
            )
            .unwrap()
        }
        let local = mk("pre", 64, 2); // arr: long[8] at byte 8 -> arr[3] at 8+24=32
        let target = mk("pre", 128, 2); // arr at byte 16 -> arr[3] at 16+24=40
        let idx = CandidateIndex::new(&target);
        let r = calc_relo(
            &local,
            &relo(&local, 4, "0:1:3", relo_kind::FIELD_BYTE_OFFSET),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!((r.orig_val, r.new_val), (32, 40));
    }

    #[test]
    fn bitfield_shifts() {
        // struct B { long base; unsigned flags:3; } with the bitfield at a
        // configurable bit offset; kind_flag packs (size << 24 | offset).
        fn mk(flags_bit: u32) -> Btf {
            let ss = ["int", "long", "base", "flags", "B", "0:1"];
            let s = |n| stroff(&ss, n);
            Btf::parse(
                true,
                &build_btf(
                    &ss,
                    &[
                        (s("int"), info(kind::INT, 0, false), 4, vec![32]),
                        (s("long"), info(kind::INT, 0, false), 8, vec![64]),
                        (
                            s("B"),
                            info(kind::STRUCT, 2, true), // kind_flag: bitfield encoding
                            16,
                            vec![s("base"), 2, 0, s("flags"), 1, (3 << 24) | flags_bit],
                        ),
                    ],
                ),
            )
            .unwrap()
        }
        let local = mk(64); // flags:3 at bit 64
        let target = mk(69); // flags:3 at bit 69 (same byte word, shifted)
        let idx = CandidateIndex::new(&target);

        let r = calc_relo(
            &local,
            &relo(&local, 3, "0:1", relo_kind::FIELD_BYTE_OFFSET),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!((r.orig_val, r.new_val), (8, 8));
        assert!(!r.validate, "bitfield byte offset is not validatable");

        // LSHIFT_U64 (LE): 64 - (bit_off + bits - byte_off*8)
        let r = calc_relo(
            &local,
            &relo(&local, 3, "0:1", relo_kind::FIELD_LSHIFT_U64),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!((r.orig_val, r.new_val), (64 - 3, 64 - 8));
        // RSHIFT_U64: 64 - bits
        let r = calc_relo(
            &local,
            &relo(&local, 3, "0:1", relo_kind::FIELD_RSHIFT_U64),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!((r.orig_val, r.new_val), (61, 61));
    }

    #[test]
    fn flavors_match_by_essential_name() {
        // local root "point___v2" must find target "point".
        let ls = ["int", "long", "x", "y", "z", "point___v2", "0:1"];
        let l = |n| stroff(&ls, n);
        let local = Btf::parse(
            true,
            &build_btf(
                &ls,
                &[
                    (l("int"), info(kind::INT, 0, false), 4, vec![(1 << 24) | 32]),
                    (l("long"), info(kind::INT, 0, false), 8, vec![(1 << 24) | 64]),
                    (
                        l("point___v2"),
                        info(kind::STRUCT, 3, false),
                        16,
                        vec![l("x"), 1, 0, l("y"), 1, 32, l("z"), 2, 64],
                    ),
                ],
            ),
        )
        .unwrap();
        let target = point_btf(24, 32, 96, 128);
        let idx = CandidateIndex::new(&target);
        let r = calc_relo(
            &local,
            &relo(&local, 3, "0:1", relo_kind::FIELD_BYTE_OFFSET),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!((r.orig_val, r.new_val), (4, 12));
    }

    #[test]
    fn ambiguous_candidates_are_rejected_but_agreeing_ones_pass() {
        let local = point_btf(16, 0, 32, 64);
        // Two target "point" structs with different x offsets -> ambiguous.
        let ss = ["int", "long", "x", "y", "z", "point", "point___a"];
        let s = |n| stroff(&ss, n);
        let two = |x2: u32| {
            Btf::parse(
                true,
                &build_btf(
                    &ss,
                    &[
                        (s("int"), info(kind::INT, 0, false), 4, vec![(1 << 24) | 32]),
                        (s("long"), info(kind::INT, 0, false), 8, vec![(1 << 24) | 64]),
                        (
                            s("point"),
                            info(kind::STRUCT, 3, false),
                            16,
                            vec![s("x"), 1, 0, s("y"), 1, 32, s("z"), 2, 64],
                        ),
                        (
                            s("point___a"),
                            info(kind::STRUCT, 3, false),
                            16,
                            vec![s("x"), 1, x2, s("y"), 1, 32, s("z"), 2, 64],
                        ),
                    ],
                ),
            )
            .unwrap()
        };
        let target = two(96); // disagreeing x offsets
        let idx = CandidateIndex::new(&target);
        let err = calc_relo(
            &local,
            &relo(&local, 3, "0:0", relo_kind::FIELD_BYTE_OFFSET),
            &target,
            &idx,
        )
        .unwrap_err();
        assert!(err.contains("ambiguous"), "{err}");

        let target = two(0); // agreeing
        let idx = CandidateIndex::new(&target);
        let r = calc_relo(
            &local,
            &relo(&local, 3, "0:0", relo_kind::FIELD_BYTE_OFFSET),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!((r.new_val, r.matched), (0, 2));
    }

    #[test]
    fn missing_field_and_type() {
        let local = point_btf(16, 0, 32, 64);
        // Target "point" lacks "y".
        let ss = ["int", "long", "x", "z", "point"];
        let s = |n| stroff(&ss, n);
        let target = Btf::parse(
            true,
            &build_btf(
                &ss,
                &[
                    (s("int"), info(kind::INT, 0, false), 4, vec![(1 << 24) | 32]),
                    (s("long"), info(kind::INT, 0, false), 8, vec![(1 << 24) | 64]),
                    (
                        s("point"),
                        info(kind::STRUCT, 2, false),
                        16,
                        vec![s("x"), 1, 0, s("z"), 2, 64],
                    ),
                ],
            ),
        )
        .unwrap();
        let idx = CandidateIndex::new(&target);
        // FIELD_EXISTS: y -> 0, x -> 1
        let r = calc_relo(
            &local,
            &relo(&local, 3, "0:1", relo_kind::FIELD_EXISTS),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!((r.new_val, r.matched, r.validate), (0, 0, false));
        let r = calc_relo(
            &local,
            &relo(&local, 3, "0:0", relo_kind::FIELD_EXISTS),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!((r.new_val, r.matched), (1, 1));
        // BYTE_OFFSET of a missing field marks the instruction for poisoning.
        let r = calc_relo(
            &local,
            &relo(&local, 3, "0:1", relo_kind::FIELD_BYTE_OFFSET),
            &target,
            &idx,
        )
        .unwrap();
        assert!(r.poison);
        assert_eq!(r.matched, 0);
        // TYPE_EXISTS of a type absent from the target -> 0.
        let ls2 = ["nosuch", "0"];
        let l2 = |n| stroff(&ls2, n);
        let local2 = Btf::parse(
            true,
            &build_btf(&ls2, &[(l2("nosuch"), info(kind::STRUCT, 0, false), 0, vec![])]),
        )
        .unwrap();
        let r = calc_relo(
            &local2,
            &relo(&local2, 1, "0", relo_kind::TYPE_EXISTS),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!(r.new_val, 0);
    }

    #[test]
    fn type_relocations() {
        let local = point_btf(16, 0, 32, 64);
        let target = point_btf(24, 32, 64, 128);
        let idx = CandidateIndex::new(&target);
        let r = calc_relo(
            &local,
            &relo(&local, 3, "0", relo_kind::TYPE_SIZE),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!((r.orig_val, r.new_val), (16, 24));
        let r = calc_relo(
            &local,
            &relo(&local, 3, "0", relo_kind::TYPE_ID_TARGET),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!(r.new_val, 3); // point's id in the target table
        let r = calc_relo(
            &local,
            &relo(&local, 3, "0", relo_kind::TYPE_ID_LOCAL),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!(r.new_val, 3);
        let r = calc_relo(
            &local,
            &relo(&local, 3, "0", relo_kind::TYPE_EXISTS),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!(r.new_val, 1);
        let r = calc_relo(
            &local,
            &relo(&local, 3, "0", relo_kind::TYPE_MATCHES),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!(r.new_val, 1);
    }

    #[test]
    fn enumval_relocations() {
        // local enum E { A = 1, B = 2 }; target enum E { B = 7, A = 3 }
        let ls = ["A", "B", "E", "1"];
        let l = |n| stroff(&ls, n);
        let local = Btf::parse(
            true,
            &build_btf(
                &ls,
                &[(
                    l("E"),
                    info(kind::ENUM, 2, false),
                    4,
                    vec![l("A"), 1, l("B"), 2],
                )],
            ),
        )
        .unwrap();
        let ts = ["B", "A", "E"];
        let t = |n| stroff(&ts, n);
        let target = Btf::parse(
            true,
            &build_btf(
                &ts,
                &[(
                    t("E"),
                    info(kind::ENUM, 2, false),
                    4,
                    vec![t("B"), 7, t("A"), 3],
                )],
            ),
        )
        .unwrap();
        let idx = CandidateIndex::new(&target);
        // access "1" = local enumerator index 1 = B
        let r = calc_relo(
            &local,
            &relo(&local, 1, "1", relo_kind::ENUMVAL_VALUE),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!((r.orig_val, r.new_val), (2, 7));
        let r = calc_relo(
            &local,
            &relo(&local, 1, "1", relo_kind::ENUMVAL_EXISTS),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!(r.new_val, 1);
        // ENUM64 target also matches (kind normalization).
        let ts64 = ["B", "A", "E"];
        let t64 = |n| stroff(&ts64, n);
        let target64 = Btf::parse(
            true,
            &build_btf(
                &ts64,
                &[(
                    t64("E"),
                    info(kind::ENUM64, 2, false),
                    8,
                    vec![t64("B"), 9, 1, t64("A"), 3, 0], // B = 0x1_0000_0009
                )],
            ),
        )
        .unwrap();
        let idx64 = CandidateIndex::new(&target64);
        let r = calc_relo(
            &local,
            &relo(&local, 1, "1", relo_kind::ENUMVAL_VALUE),
            &target64,
            &idx64,
        )
        .unwrap();
        assert_eq!(r.new_val, 0x1_0000_0009);
    }

    #[test]
    fn typedef_and_modifier_roots_resolve() {
        // local accesses through `const struct point *` typedef'd root.
        let ls = ["int", "long", "x", "y", "z", "point", "point_t", "0:2"];
        let l = |n| stroff(&ls, n);
        let local = Btf::parse(
            true,
            &build_btf(
                &ls,
                &[
                    (l("int"), info(kind::INT, 0, false), 4, vec![(1 << 24) | 32]),
                    (l("long"), info(kind::INT, 0, false), 8, vec![(1 << 24) | 64]),
                    (
                        l("point"),
                        info(kind::STRUCT, 3, false),
                        16,
                        vec![l("x"), 1, 0, l("y"), 1, 32, l("z"), 2, 64],
                    ),
                    (0, info(kind::CONST, 0, false), 3, vec![]),
                    (l("point_t"), info(kind::TYPEDEF, 0, false), 4, vec![]),
                ],
            ),
        )
        .unwrap();
        // Target: shifted struct point + `typedef struct point point_t`.
        // Candidate lookup goes by the root's own name ("point_t", as libbpf
        // does), and both sides resolve through their typedef/const chains.
        let ts = ["int", "long", "x", "y", "z", "point", "point_t"];
        let t = |n| stroff(&ts, n);
        let target = Btf::parse(
            true,
            &build_btf(
                &ts,
                &[
                    (t("int"), info(kind::INT, 0, false), 4, vec![(1 << 24) | 32]),
                    (t("long"), info(kind::INT, 0, false), 8, vec![(1 << 24) | 64]),
                    (
                        t("point"),
                        info(kind::STRUCT, 3, false),
                        24,
                        vec![t("x"), 1, 32, t("y"), 1, 64, t("z"), 2, 128],
                    ),
                    (t("point_t"), info(kind::TYPEDEF, 0, false), 3, vec![]),
                ],
            ),
        )
        .unwrap();
        let idx = CandidateIndex::new(&target);
        let r = calc_relo(
            &local,
            &relo(&local, 5, "0:2", relo_kind::FIELD_BYTE_OFFSET),
            &target,
            &idx,
        )
        .unwrap();
        assert_eq!((r.orig_val, r.new_val), (8, 16));
    }
}
