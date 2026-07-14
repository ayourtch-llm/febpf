//! Conservative effects on map state derived from successful verification.

use alloc::vec::Vec;

use crate::helpers;
use crate::insn::{call_kind, class, jmp, mode, Insn};
use crate::verifier::{PtrKind, RegState, VerifyOk};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapEffectKind {
    Lookup,
    Read,
    Write,
    Atomic,
    Delete,
    Lock,
    Unlock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRange {
    pub min: i64,
    pub max: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapEffect {
    pub pc: usize,
    pub map: u32,
    pub kind: MapEffectKind,
    /// Inclusive possible byte range for direct value-pointer accesses.
    /// Helper effects operate on a key or whole logical value and use None.
    pub bytes: Option<ByteRange>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapEffects {
    pub accesses: Vec<MapEffect>,
    /// False when verifier joins erased an exact map identity. Consumers must
    /// reject or conservatively treat every shared map as affected.
    pub complete: bool,
}

impl Default for MapEffects {
    fn default() -> Self {
        Self {
            accesses: Vec::new(),
            complete: true,
        }
    }
}

fn map_pointer(reg: RegState) -> Option<u32> {
    match reg {
        RegState::Ptr(pointer) => match pointer.kind {
            PtrKind::Map { map } | PtrKind::MapValue { map } => Some(map),
            _ => None,
        },
        _ => None,
    }
}

fn direct_effect(pc: usize, insn: Insn, regs: &[RegState]) -> Result<Option<MapEffect>, ()> {
    let (base, kind) = match insn.class() {
        class::LDX if matches!(insn.mem_mode(), mode::MEM | mode::MEMSX) => {
            (insn.src as usize, MapEffectKind::Read)
        }
        class::ST if insn.mem_mode() == mode::MEM => (insn.dst as usize, MapEffectKind::Write),
        class::STX if insn.mem_mode() == mode::MEM => (insn.dst as usize, MapEffectKind::Write),
        class::STX if insn.mem_mode() == mode::ATOMIC => (insn.dst as usize, MapEffectKind::Atomic),
        _ => return Ok(None),
    };
    let RegState::Ptr(pointer) = regs[base] else {
        return Err(());
    };
    let PtrKind::MapValue { map } = pointer.kind else {
        return Ok(None);
    };
    let start = pointer.off.checked_add(insn.off as i64).ok_or(())?;
    let min = start.checked_add(pointer.var.smin).ok_or(())?;
    let last = (insn.mem_size() as i64).checked_sub(1).ok_or(())?;
    let max = start
        .checked_add(pointer.var.smax)
        .and_then(|value| value.checked_add(last))
        .ok_or(())?;
    Ok(Some(MapEffect {
        pc,
        map,
        kind,
        bytes: Some(ByteRange { min, max }),
    }))
}

fn helper_effect(id: u32) -> Option<(usize, MapEffectKind)> {
    match id {
        helpers::id::MAP_LOOKUP_ELEM
        | helpers::id::REDIRECT_MAP
        | helpers::id::CURRENT_TASK_UNDER_CGROUP => Some((1, MapEffectKind::Lookup)),
        helpers::id::TAIL_CALL => Some((2, MapEffectKind::Lookup)),
        helpers::id::MAP_UPDATE_ELEM
        | helpers::id::MAP_PUSH_ELEM
        | helpers::id::RINGBUF_OUTPUT
        | helpers::id::RINGBUF_RESERVE => Some((1, MapEffectKind::Write)),
        helpers::id::GET_STACKID | helpers::id::PERF_EVENT_OUTPUT => {
            Some((2, MapEffectKind::Write))
        }
        helpers::id::MAP_DELETE_ELEM => Some((1, MapEffectKind::Delete)),
        helpers::id::SPIN_LOCK => Some((1, MapEffectKind::Lock)),
        helpers::id::SPIN_UNLOCK => Some((1, MapEffectKind::Unlock)),
        _ => None,
    }
}

/// Summarize reachable map effects after successful verification.
pub fn summarize(insns: &[Insn], verified: &VerifyOk) -> MapEffects {
    let mut accesses = Vec::new();
    let mut complete = true;
    for (pc, insn) in insns.iter().copied().enumerate() {
        let Some(regs) = verified.regs_at(pc) else {
            continue;
        };
        match direct_effect(pc, insn, regs) {
            Ok(Some(effect)) => {
                accesses.push(effect);
                continue;
            }
            Ok(None) => {}
            Err(()) => {
                complete = false;
                continue;
            }
        }
        if !matches!(insn.class(), class::JMP | class::JMP32)
            || insn.op() != jmp::CALL
            || insn.src == call_kind::LOCAL
            || insn.imm < 0
        {
            continue;
        }
        let Some((map_reg, kind)) = helper_effect(insn.imm as u32) else {
            continue;
        };
        let Some(map) = map_pointer(regs[map_reg]) else {
            complete = false;
            continue;
        };
        accesses.push(MapEffect {
            pc,
            map,
            kind,
            bytes: None,
        });
    }
    MapEffects { accesses, complete }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{asm, verifier};

    fn effects(source: &str) -> MapEffects {
        let program = asm::assemble(source).unwrap();
        let verified = verifier::verify(
            &program.insns,
            &program.maps,
            &[],
            verifier::Config::default(),
        )
        .unwrap();
        summarize(&program.insns, &verified)
    }

    #[test]
    fn distinguishes_racy_read_write_from_atomic_update() {
        let racy = effects(include_str!("../examples/race_rmw.s"));
        assert!(racy.complete);
        let racy_kinds: Vec<_> = racy.accesses.iter().map(|effect| effect.kind).collect();
        assert!(racy_kinds.contains(&MapEffectKind::Lookup));
        assert!(racy_kinds.contains(&MapEffectKind::Read));
        assert!(racy_kinds.contains(&MapEffectKind::Write));
        assert!(!racy_kinds.contains(&MapEffectKind::Atomic));

        let atomic = effects(include_str!("../examples/race_atomic.s"));
        assert!(atomic.complete);
        let atomic_kinds: Vec<_> = atomic.accesses.iter().map(|effect| effect.kind).collect();
        assert!(atomic_kinds.contains(&MapEffectKind::Lookup));
        assert!(atomic_kinds.contains(&MapEffectKind::Atomic));
        assert!(!atomic_kinds.contains(&MapEffectKind::Write));
    }

    #[test]
    fn reports_verified_direct_byte_ranges() {
        let summary = effects(include_str!("../examples/race_atomic.s"));
        let atomic = summary
            .accesses
            .iter()
            .find(|effect| effect.kind == MapEffectKind::Atomic)
            .unwrap();
        assert_eq!(atomic.map, 0);
        assert_eq!(atomic.bytes, Some(ByteRange { min: 0, max: 7 }));
    }

    #[test]
    fn marks_summary_incomplete_when_join_erases_map_identity() {
        let summary = effects(
            r#"
            .map a array 4 8 1
            .map b array 4 8 1
            r0 = 0
            *(u32 *)(r10 - 4) = r0
            call get_prandom_u32
            if r0 == 0 goto use_a
            r1 = map[b]
            goto lookup
        use_a:
            r1 = map[a]
        lookup:
            r2 = r10
            r2 += -4
            call map_lookup_elem
            if r0 == 0 goto out
            r1 = *(u64 *)(r0 + 0)
        out:
            r0 = 0
            exit
            "#,
        );
        assert!(!summary.complete);
    }
}
