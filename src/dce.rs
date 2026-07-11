//! Load-time dead-code elimination driven by frozen `.rodata` values.
//!
//! Real libbpf resolves loads from frozen read-only global-data maps (the
//! `const volatile` config-flag idiom) to constants before the kernel ever
//! sees the program, then eliminates the branches those constants decide and
//! the code behind them. febpf loads objects as-is, so without this pass a
//! real-world object trips the verifier's "unreachable instruction" check on
//! code that libbpf would have removed — most commonly a subprogram stitched
//! in from `.text` that this entry point only calls under a config flag that
//! is off (or never calls at all).
//!
//! This pass is a small conditional-constant-propagation (SCCP-style) forward
//! dataflow over the flat instruction stream, run at ELF load time after
//! CO-RE relocation and map-index patching (`src/elf.rs`). The abstract
//! domain tracks, per register:
//!
//!   - `Const(u64)`  — a value proven identical on every path,
//!   - `Rodata{map,off}` — a pointer into a *frozen* (`readonly`) array map's
//!     value, at a known byte offset,
//!   - `Unknown`     — anything else.
//!
//! A load through a `Rodata` pointer at a known offset yields the map's
//! initial bytes as a `Const` — sound because the map is frozen: the verifier
//! and the runtime both reject every write to it, so the load can only ever
//! observe the load-time contents. Conditional branches whose operands are
//! `Const` propagate along the single feasible edge; at the fixpoint,
//! never-visited instructions are dead and decided branches are rewritten
//! (always-taken → `ja`, never-taken → removed), with all pc-relative targets
//! relocated through the shared machinery in `crate::optimize`.
//!
//! See `docs/specs/rodata-dce.md` for the model and soundness argument.

use crate::insn::{alu, call_kind, class, jmp, mode, pseudo, Insn, NUM_REGS};
use crate::maps::{MapDef, MapKind};
use crate::optimize::{apply_actions, eval_alu_const, eval_pred_const, Action};

/// The abstract value a register holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Val {
    Unknown,
    /// Proven the same constant on every path reaching this point.
    Const(u64),
    /// Pointer into frozen array map `map`'s (single) value at byte `off`.
    Rodata { map: u32, off: i64 },
}

type State = [Val; NUM_REGS];

/// Join `b` into `a` (pointwise lattice meet towards `Unknown`). Returns true
/// if `a` changed.
fn join_into(a: &mut State, b: &State) -> bool {
    let mut changed = false;
    for (av, bv) in a.iter_mut().zip(b.iter()) {
        if *av != *bv && *av != Val::Unknown {
            *av = Val::Unknown;
            changed = true;
        }
    }
    changed
}

/// The output of a successful pass.
pub struct DceResult {
    /// The rewritten program (dead code removed, decided branches resolved).
    pub insns: Vec<Insn>,
    /// `pc_map[old]` = new index of the first surviving slot at or after
    /// `old`; length is `old_len + 1` and `pc_map[old_len]` is the new
    /// length. Used to remap side tables (line info) after the rewrite.
    pub pc_map: Vec<usize>,
    /// Instruction slots removed.
    pub removed: usize,
    /// Conditional branches resolved (either direction).
    pub branches_resolved: usize,
}

/// Is `maps[idx]` a frozen array whose entry-0 value bytes are fixed for the
/// program's whole lifetime? (`.rodata*` sections load as exactly this.)
fn frozen_array(maps: &[MapDef], idx: u32) -> bool {
    maps.get(idx as usize)
        .map(|m| m.readonly && m.kind == MapKind::Array)
        .unwrap_or(false)
}

/// Read `size` little-endian bytes at `off` of the map's initial value.
/// Bytes beyond `init` but inside `value_size` read as zero (map storage is
/// zero-filled past the initializer). `None` when out of bounds.
fn read_rodata(maps: &[MapDef], map: u32, off: i64, size: usize, sign: bool) -> Option<u64> {
    let def = maps.get(map as usize)?;
    if off < 0 || (off as u64).checked_add(size as u64)? > def.value_size as u64 {
        return None;
    }
    let off = off as usize;
    let mut v: u64 = 0;
    for i in (0..size).rev() {
        v = (v << 8) | def.init.get(off + i).copied().unwrap_or(0) as u64;
    }
    if sign {
        let shift = 64 - 8 * size as u32;
        v = ((v << shift) as i64 >> shift) as u64;
    }
    Some(v)
}

/// Compute the post-state of one (possibly wide) instruction, mutating
/// `st` in place. `next` is the second slot of a wide `lddw`, if any.
fn transfer(ins: Insn, next: Option<Insn>, maps: &[MapDef], st: &mut State) {
    let dst = ins.dst as usize;
    let cls = ins.class();
    match cls {
        class::LD => {
            let Some(_) = next else {
                // Legacy ld_abs/ld_ind (unsupported; clobbers several regs):
                // forget everything to stay sound if it ever gets this far.
                *st = [Val::Unknown; NUM_REGS];
                return;
            };
            st[dst] = match (ins.src, next) {
                (s, Some(hi)) if s == pseudo::IMM64 => {
                    Val::Const((ins.imm as u32 as u64) | ((hi.imm as u32 as u64) << 32))
                }
                (s, Some(hi)) if s == pseudo::MAP_VALUE && frozen_array(maps, ins.imm as u32) => {
                    Val::Rodata {
                        map: ins.imm as u32,
                        off: hi.imm as u32 as i64,
                    }
                }
                _ => Val::Unknown,
            };
        }
        class::LDX => {
            let m = ins.opcode & 0xe0;
            st[dst] = match (m, st[ins.src as usize]) {
                (mode::MEM | mode::MEMSX, Val::Rodata { map, off }) => {
                    match read_rodata(
                        maps,
                        map,
                        off + ins.off as i64,
                        ins.mem_size(),
                        m == mode::MEMSX,
                    ) {
                        Some(v) => Val::Const(v),
                        None => Val::Unknown,
                    }
                }
                _ => Val::Unknown,
            };
        }
        class::ST => {} // no register effect
        class::STX => {
            if ins.opcode & 0xe0 == mode::ATOMIC {
                // FETCH/XCHG write back into src; CMPXCHG writes r0.
                st[ins.src as usize] = Val::Unknown;
                st[0] = Val::Unknown;
            }
        }
        class::ALU | class::ALU64 => {
            let is32 = cls == class::ALU;
            let op = ins.op();
            // Operand: immediate, or the source register's value.
            let b: Option<u64> = if ins.is_src_reg() {
                match st[ins.src as usize] {
                    Val::Const(v) => Some(v),
                    _ => None,
                }
            } else {
                Some(ins.imm as i64 as u64)
            };
            st[dst] = match (op, st[dst]) {
                // mov (not movsx: off must be 0)
                (alu::MOV, _) if ins.off == 0 => {
                    if ins.is_src_reg() {
                        match (is32, st[ins.src as usize]) {
                            (false, v) => v, // 64-bit mov copies exactly
                            (true, Val::Const(v)) => Val::Const(v as u32 as u64),
                            (true, _) => Val::Unknown,
                        }
                    } else if is32 {
                        Val::Const(ins.imm as u32 as u64)
                    } else {
                        Val::Const(ins.imm as i64 as u64)
                    }
                }
                // 64-bit pointer arithmetic on a rodata pointer.
                (alu::ADD, Val::Rodata { map, off }) if !is32 => match b {
                    Some(k) => Val::Rodata {
                        map,
                        off: off.wrapping_add(k as i64),
                    },
                    None => Val::Unknown,
                },
                // Constant folding for binary ops on proven constants.
                (_, Val::Const(a)) if op != alu::NEG && op != alu::END => match b {
                    Some(bv) => match eval_alu_const(op, is32, ins.off, a, bv) {
                        Some(v) => Val::Const(v),
                        None => Val::Unknown,
                    },
                    None => Val::Unknown,
                },
                _ => Val::Unknown,
            };
        }
        _ => {} // JMP/JMP32 register effects are handled by the caller
    }
}

/// Decide a conditional jump from the state before it. `Some(true)` = always
/// taken, `Some(false)` = never taken, `None` = unknown.
fn decide_branch(ins: Insn, st: &State) -> Option<bool> {
    let a = match st[ins.dst as usize] {
        Val::Const(v) => v,
        _ => return None,
    };
    let b = if ins.is_src_reg() {
        match st[ins.src as usize] {
            Val::Const(v) => v,
            _ => return None,
        }
    } else {
        ins.imm as i64 as u64
    };
    eval_pred_const(ins.op(), ins.class() == class::JMP32, a, b)
}

/// Run the pass. Returns `None` when nothing changes (the program is fully
/// reachable and no branch is decided by frozen rodata) or when the stream is
/// malformed — the caller then keeps the original instructions and the
/// verifier reports the real error.
pub fn eliminate_rodata_dead_code(insns: &[Insn], maps: &[MapDef]) -> Option<DceResult> {
    let n = insns.len();
    if n == 0 {
        return None;
    }
    // Mark lddw second slots; bail on truncated pairs (verifier's problem).
    let mut is_second = vec![false; n];
    let mut i = 0;
    while i < n {
        if insns[i].is_wide() {
            if i + 1 >= n {
                return None;
            }
            is_second[i + 1] = true;
            i += 2;
        } else {
            i += 1;
        }
    }

    // ---- forward dataflow to a fixpoint ---------------------------------
    let mut states: Vec<Option<State>> = vec![None; n];
    states[0] = Some([Val::Unknown; NUM_REGS]);
    let mut work: Vec<usize> = vec![0];
    // Propagate `s` into pc `t`; enqueue on change. Returns false on a bad
    // target (out of range / mid-lddw) — the whole pass then aborts.
    while let Some(pc) = work.pop() {
        let st = states[pc]?; // in the worklist => has a state
        let ins = insns[pc];
        let width = if ins.is_wide() { 2 } else { 1 };
        let next = ins.is_wide().then(|| insns[pc + 1]);

        // (target, state) successors of this instruction.
        let mut succs: Vec<(i64, State)> = Vec::with_capacity(2);
        let cls = ins.class();
        if cls == class::JMP || cls == class::JMP32 {
            match ins.op() {
                jmp::EXIT => {}
                jmp::JA => {
                    let rel = if cls == class::JMP32 {
                        ins.imm as i64
                    } else {
                        ins.off as i64
                    };
                    succs.push((pc as i64 + 1 + rel, st));
                }
                jmp::CALL => {
                    if ins.src == call_kind::LOCAL {
                        // The callee starts with the caller's registers
                        // (r1-r5 are the arguments); r0 is treated as
                        // clobbered.
                        let mut callee = st;
                        callee[0] = Val::Unknown;
                        succs.push((pc as i64 + 1 + ins.imm as i64, callee));
                    }
                    // Fall through: calls clobber r0-r5; r6-r9 are saved and
                    // restored around local calls by the runtime.
                    let mut after = st;
                    for v in after.iter_mut().take(6) {
                        *v = Val::Unknown;
                    }
                    succs.push(((pc + width) as i64, after));
                }
                _ => {
                    let target = pc as i64 + 1 + ins.off as i64;
                    match decide_branch(ins, &st) {
                        Some(true) => succs.push((target, st)),
                        Some(false) => succs.push(((pc + width) as i64, st)),
                        None => {
                            succs.push((target, st));
                            succs.push(((pc + width) as i64, st));
                        }
                    }
                }
            }
        } else {
            let mut after = st;
            transfer(ins, next, maps, &mut after);
            succs.push(((pc + width) as i64, after));
        }

        for (t, s) in succs {
            if t < 0 || t as usize >= n || is_second[t as usize] {
                return None; // malformed; let the verifier explain it
            }
            let t = t as usize;
            match &mut states[t] {
                None => {
                    states[t] = Some(s);
                    work.push(t);
                }
                Some(old) => {
                    if join_into(old, &s) {
                        work.push(t);
                    }
                }
            }
        }
    }

    // ---- rewrite from the fixpoint ---------------------------------------
    let mut actions: Vec<Action> = Vec::with_capacity(n);
    let mut branches_resolved = 0usize;
    let mut pc = 0;
    while pc < n {
        let ins = insns[pc];
        let width = if ins.is_wide() { 2 } else { 1 };
        let Some(st) = states[pc] else {
            // Never visited on any feasible path: dead code.
            for _ in 0..width {
                actions.push(Action::Drop);
            }
            pc += width;
            continue;
        };
        let cls = ins.class();
        let is_cond = (cls == class::JMP || cls == class::JMP32)
            && ins.op() != jmp::JA
            && ins.op() != jmp::CALL
            && ins.op() != jmp::EXIT;
        if is_cond {
            match decide_branch(ins, &st) {
                Some(true) => {
                    branches_resolved += 1;
                    actions.push(Action::Keep(Insn {
                        opcode: class::JMP | jmp::JA,
                        dst: 0,
                        src: 0,
                        off: ins.off,
                        imm: 0,
                    }));
                    pc += 1;
                    continue;
                }
                Some(false) => {
                    branches_resolved += 1;
                    actions.push(Action::Drop);
                    pc += 1;
                    continue;
                }
                None => {}
            }
        }
        actions.push(Action::Keep(ins));
        if width == 2 {
            actions.push(Action::Keep(insns[pc + 1]));
        }
        pc += width;
    }

    let dropped = actions
        .iter()
        .filter(|a| matches!(a, Action::Drop))
        .count();
    if dropped == 0 && branches_resolved == 0 {
        return None; // nothing to do
    }
    let mut relocated = apply_actions(insns, actions).ok()?;

    // Cleanup: resolving an always-taken branch whose dead side was removed
    // leaves a `ja +0` (jump to the next instruction). Collapse those;
    // removing one can shorten another jump to +0, so iterate.
    let is_nop_ja = |i: &Insn| {
        (i.class() == class::JMP && i.op() == jmp::JA && i.off == 0)
            || (i.class() == class::JMP32 && i.op() == jmp::JA && i.imm == 0)
    };
    while relocated.insns.iter().any(is_nop_ja) {
        let acts: Vec<Action> = relocated
            .insns
            .iter()
            .map(|i| {
                if is_nop_ja(i) {
                    Action::Drop
                } else {
                    Action::Keep(*i)
                }
            })
            .collect();
        let next = apply_actions(&relocated.insns, acts).ok()?;
        // Compose the two old→new mappings.
        let pc_map = relocated
            .pc_map
            .iter()
            .map(|&mid| next.pc_map[mid])
            .collect();
        relocated = crate::optimize::Relocated {
            insns: next.insns,
            pc_map,
        };
    }

    Some(DceResult {
        removed: n - relocated.insns.len(),
        insns: relocated.insns,
        pc_map: relocated.pc_map,
        branches_resolved,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asm;

    fn prog(src: &str) -> (Vec<Insn>, Vec<MapDef>) {
        let a = asm::assemble(src).expect("assembly failed");
        (a.insns, a.maps)
    }

    #[test]
    fn untouched_when_nothing_provable() {
        let (insns, maps) = prog("r0 = *(u8 *)(r1 + 0)\nif r0 == 0 goto l\nr0 = 1\nl:\nexit\n");
        assert!(eliminate_rodata_dead_code(&insns, &maps).is_none());
    }

    #[test]
    fn rodata_zero_flag_folds_branch() {
        // cfg value is 0 (asm ro maps are zero-initialized), so the != 0
        // branch is never taken and the guarded block is removed.
        let (insns, maps) = prog(
            ".map cfg array 4 4 1 ro\n\
             r1 = map[cfg][0] + 0\n\
             r1 = *(u32 *)(r1 + 0)\n\
             if r1 != 0 goto on\n\
             r0 = 1\n\
             exit\n\
             on:\n\
             r0 = 2\n\
             exit\n",
        );
        let res = eliminate_rodata_dead_code(&insns, &maps).expect("should fire");
        assert_eq!(res.branches_resolved, 1);
        // Branch dropped (1) + dead block dropped (2).
        assert_eq!(res.removed, 3);
    }

    #[test]
    fn rodata_nonzero_flag_takes_branch() {
        let (insns, mut maps) = prog(
            ".map cfg array 4 4 1 ro\n\
             r1 = map[cfg][0] + 0\n\
             r1 = *(u32 *)(r1 + 0)\n\
             if r1 == 7 goto on\n\
             r0 = 1\n\
             exit\n\
             on:\n\
             r0 = 2\n\
             exit\n",
        );
        maps[0].init = 7u32.to_le_bytes().to_vec();
        let res = eliminate_rodata_dead_code(&insns, &maps).expect("should fire");
        assert_eq!(res.branches_resolved, 1);
        // The always-taken branch became a JA; the fall-through side is dead.
        assert!(res.removed >= 2);
        // And with the flag clear, the same program is resolved the other way.
        maps[0].init.clear();
        let res0 = eliminate_rodata_dead_code(&insns, &maps).expect("should fire");
        assert_ne!(res0.insns, res.insns);
    }

    #[test]
    fn writable_map_is_never_folded() {
        // Identical shape but the map is not readonly: no fold.
        let (insns, maps) = prog(
            ".map cfg array 4 4 1\n\
             r1 = map[cfg][0] + 0\n\
             r1 = *(u32 *)(r1 + 0)\n\
             if r1 != 0 goto on\n\
             r0 = 1\n\
             exit\n\
             on:\n\
             r0 = 2\n\
             exit\n",
        );
        assert!(eliminate_rodata_dead_code(&insns, &maps).is_none());
    }

    #[test]
    fn join_of_diverging_paths_widens() {
        // r2 is 0 on one path and 1 on the other; the join must not decide
        // the final branch.
        let (insns, maps) = prog(
            "r0 = *(u8 *)(r1 + 0)\n\
             r2 = 0\n\
             if r0 == 0 goto merged\n\
             r2 = 1\n\
             merged:\n\
             if r2 == 0 goto z\n\
             r0 = 10\n\
             exit\n\
             z:\n\
             r0 = 20\n\
             exit\n",
        );
        assert!(eliminate_rodata_dead_code(&insns, &maps).is_none());
    }

    #[test]
    fn dead_subprogram_is_removed() {
        // A local call target that is never called (mirrors an entry program
        // with an unrelated `.text` subprogram stitched in).
        let (insns, maps) = prog(
            "r0 = 0\n\
             exit\n\
             r0 = 99\n\
             exit\n",
        );
        let res = eliminate_rodata_dead_code(&insns, &maps).expect("should fire");
        assert_eq!(res.removed, 2);
        assert_eq!(res.insns.len(), 2);
    }

    #[test]
    fn rodata_pointer_survives_local_call() {
        // The flag is loaded inside a subprogram from a pointer passed in r1.
        let (insns, maps) = prog(
            ".map cfg array 4 4 1 ro\n\
             r1 = map[cfg][0] + 0\n\
             call sub\n\
             exit\n\
             sub:\n\
             r0 = *(u32 *)(r1 + 0)\n\
             if r0 != 0 goto bad\n\
             r0 = 5\n\
             exit\n\
             bad:\n\
             r0 = 6\n\
             exit\n",
        );
        let res = eliminate_rodata_dead_code(&insns, &maps).expect("should fire");
        assert_eq!(res.branches_resolved, 1);
    }

    #[test]
    fn sign_extending_load() {
        let (insns, mut maps) = prog(
            ".map cfg array 4 4 1 ro\n\
             r1 = map[cfg][0] + 0\n\
             r1 = *(s8 *)(r1 + 0)\n\
             if r1 == -1 goto neg\n\
             r0 = 0\n\
             exit\n\
             neg:\n\
             r0 = 1\n\
             exit\n",
        );
        maps[0].init = vec![0xff];
        let res = eliminate_rodata_dead_code(&insns, &maps).expect("should fire");
        assert_eq!(res.branches_resolved, 1);
        // Always-taken: the fall-through (r0 = 0; exit) is removed, and the
        // resulting `ja +0` is collapsed too.
        assert_eq!(res.removed, 3);
    }

    #[test]
    fn out_of_bounds_rodata_read_is_unknown() {
        let (insns, maps) = prog(
            ".map cfg array 4 4 1 ro\n\
             r1 = map[cfg][0] + 0\n\
             r1 = *(u64 *)(r1 + 0)\n\
             if r1 != 0 goto on\n\
             r0 = 1\n\
             exit\n\
             on:\n\
             r0 = 2\n\
             exit\n",
        );
        // 8-byte read of a 4-byte value: not folded (and the verifier will
        // reject the access itself).
        assert!(eliminate_rodata_dead_code(&insns, &maps).is_none());
    }
}
