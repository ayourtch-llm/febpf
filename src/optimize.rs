//! Verifier-guided, equivalence-checked optimizer.
//!
//! Applies only provably-sound rewrites, each gated on the abstract state the
//! verifier computes at that PC (`VerifyOk::pc_regs`, a join over every path
//! reaching the instruction — so a fact there holds on all executions). After
//! producing a candidate the optimizer **self-checks** it against the input
//! with the observable-equivalence checker (`crate::equiv`) and refuses to emit
//! anything it cannot prove behavior-preserving. See
//! `docs/specs/equiv-optimizer.md` §3.
//!
//! Rewrite classes:
//!   - strength reduction / algebraic identities (input-independent),
//!   - constant folding (both operands proven constant),
//!   - dead-branch elimination (predicate proven always-/never-taken),
//!   - redundant-mask elimination (tnum proves `x & mask == x`).

use crate::equiv::{self, Verdict};
use crate::insn::{alu, class, jmp, Insn};
use crate::interp::{Program, Vm};
use crate::verifier::{Config, RegState, Scalar, VerifyOk};

/// Per-class counts of rewrites that fired.
#[derive(Default, Clone, Debug)]
pub struct Stats {
    pub strength_reduction: usize,
    pub algebraic_identity: usize,
    pub constant_fold: usize,
    pub dead_branch: usize,
    pub redundant_mask: usize,
    pub insns_before: usize,
    pub insns_after: usize,
    pub rounds: usize,
}

impl Stats {
    pub fn total_rewrites(&self) -> usize {
        self.strength_reduction
            + self.algebraic_identity
            + self.constant_fold
            + self.dead_branch
            + self.redundant_mask
    }
}

/// Outcome of [`optimize`]: the new program plus statistics and the verdict of
/// the self-check that authorized it.
pub struct Optimized {
    pub program: Program,
    pub stats: Stats,
    pub self_check: Verdict,
}

/// What to do with one instruction slot during a rewrite round.
enum Action {
    /// Keep this slot, possibly with a rewritten instruction.
    Keep(Insn),
    /// Remove this slot (it was a proven no-op / dead branch).
    Drop,
}

/// The scalar an abstract register holds, if it is a scalar (else `None`).
fn as_scalar(r: &RegState) -> Option<Scalar> {
    match r {
        RegState::Scalar(s) => Some(*s),
        _ => None,
    }
}

/// Exact evaluation of a 64/32-bit conditional-jump predicate on two constants,
/// mirroring the interpreter (`interp.rs` `step`).
fn eval_pred_const(op: u8, is32: bool, a: u64, b: u64) -> Option<bool> {
    let r = if is32 {
        let (a, b) = (a as u32, b as u32);
        let (sa, sb) = (a as i32, b as i32);
        match op {
            jmp::JEQ => a == b,
            jmp::JGT => a > b,
            jmp::JGE => a >= b,
            jmp::JSET => a & b != 0,
            jmp::JNE => a != b,
            jmp::JSGT => sa > sb,
            jmp::JSGE => sa >= sb,
            jmp::JLT => a < b,
            jmp::JLE => a <= b,
            jmp::JSLT => sa < sb,
            jmp::JSLE => sa <= sb,
            _ => return None,
        }
    } else {
        let (sa, sb) = (a as i64, b as i64);
        match op {
            jmp::JEQ => a == b,
            jmp::JGT => a > b,
            jmp::JGE => a >= b,
            jmp::JSET => a & b != 0,
            jmp::JNE => a != b,
            jmp::JSGT => sa > sb,
            jmp::JSGE => sa >= sb,
            jmp::JLT => a < b,
            jmp::JLE => a <= b,
            jmp::JSLT => sa < sb,
            jmp::JSLE => sa <= sb,
            _ => return None,
        }
    };
    Some(r)
}

/// Decide a conditional branch from the abstract operand states. `Some(true)` =
/// proven always taken, `Some(false)` = proven never taken, `None` = unknown.
/// Constant operands give an exact answer; otherwise unsigned/signed range
/// reasoning is applied (64-bit only, to avoid 32-bit truncation subtleties).
fn eval_branch(op: u8, is32: bool, a: Scalar, b: Scalar) -> Option<bool> {
    if a.is_const() && b.is_const() {
        return eval_pred_const(op, is32, a.umin, b.umin);
    }
    if is32 {
        return None;
    }
    // Unsigned range reasoning.
    let (au, bu) = ((a.umin, a.umax), (b.umin, b.umax));
    let (as_, bs) = ((a.smin, a.smax), (b.smin, b.smax));
    match op {
        jmp::JGT => range_gt(au, bu),
        jmp::JGE => range_ge(au, bu),
        jmp::JLT => range_gt(bu, au), // a<b  <=>  b>a
        jmp::JLE => range_ge(bu, au), // a<=b <=>  b>=a
        jmp::JSGT => range_gt_s(as_, bs),
        jmp::JSGE => range_ge_s(as_, bs),
        jmp::JSLT => range_gt_s(bs, as_),
        jmp::JSLE => range_ge_s(bs, as_),
        jmp::JEQ => range_eq(au, bu),
        jmp::JNE => range_eq(au, bu).map(|t| !t),
        _ => None,
    }
}

// Range predicates: `Some(true)` = always, `Some(false)` = never, `None` = maybe.
fn range_gt(a: (u64, u64), b: (u64, u64)) -> Option<bool> {
    if a.0 > b.1 {
        Some(true)
    } else if a.1 <= b.0 {
        Some(false)
    } else {
        None
    }
}
fn range_ge(a: (u64, u64), b: (u64, u64)) -> Option<bool> {
    if a.0 >= b.1 {
        Some(true)
    } else if a.1 < b.0 {
        Some(false)
    } else {
        None
    }
}
fn range_gt_s(a: (i64, i64), b: (i64, i64)) -> Option<bool> {
    if a.0 > b.1 {
        Some(true)
    } else if a.1 <= b.0 {
        Some(false)
    } else {
        None
    }
}
fn range_ge_s(a: (i64, i64), b: (i64, i64)) -> Option<bool> {
    if a.0 >= b.1 {
        Some(true)
    } else if a.1 < b.0 {
        Some(false)
    } else {
        None
    }
}
/// `a == b`: never when the unsigned ranges are disjoint; otherwise unknown
/// (equality of overlapping ranges is not decidable from bounds alone unless
/// both are the same single constant — handled by the const fast-path).
fn range_eq(a: (u64, u64), b: (u64, u64)) -> Option<bool> {
    if a.1 < b.0 || b.1 < a.0 {
        Some(false)
    } else {
        None
    }
}

/// Exact ALU result of `a op b` for two constants, matching the interpreter.
/// `None` for ops we do not fold (e.g. byte-swap, or shifts out of range).
fn eval_alu_const(op: u8, is32: bool, off: i16, a: u64, b: u64) -> Option<u64> {
    if is32 {
        let a = a as u32;
        let b = b as u32;
        let r: u32 = match op {
            alu::ADD => a.wrapping_add(b),
            alu::SUB => a.wrapping_sub(b),
            alu::MUL => a.wrapping_mul(b),
            alu::OR => a | b,
            alu::AND => a & b,
            alu::XOR => a ^ b,
            alu::LSH if b < 32 => a.wrapping_shl(b),
            alu::RSH if b < 32 => a.wrapping_shr(b),
            alu::ARSH if b < 32 => (a as i32).wrapping_shr(b) as u32,
            alu::MOV if off == 0 => b,
            alu::DIV if off == 0 => a.checked_div(b).unwrap_or(0),
            alu::MOD if off == 0 => a.checked_rem(b).unwrap_or(a),
            _ => return None,
        };
        Some(r as u64)
    } else {
        let r: u64 = match op {
            alu::ADD => a.wrapping_add(b),
            alu::SUB => a.wrapping_sub(b),
            alu::MUL => a.wrapping_mul(b),
            alu::OR => a | b,
            alu::AND => a & b,
            alu::XOR => a ^ b,
            alu::LSH if b < 64 => a.wrapping_shl(b as u32),
            alu::RSH if b < 64 => a.wrapping_shr(b as u32),
            alu::ARSH if b < 64 => (a as i64).wrapping_shr(b as u32) as u64,
            alu::MOV if off == 0 => b,
            alu::DIV if off == 0 => a.checked_div(b).unwrap_or(0),
            alu::MOD if off == 0 => a.checked_rem(b).unwrap_or(a),
            _ => return None,
        };
        Some(r)
    }
}

/// A 64-bit `mov dst, imm` (0xb7) with a value that round-trips through i32.
fn mov_imm(dst: u8, val: u64) -> Option<Insn> {
    if val == (val as i32 as i64 as u64) {
        Some(Insn {
            opcode: class::ALU64 | alu::MOV,
            dst,
            src: 0,
            off: 0,
            imm: val as i32,
        })
    } else {
        None
    }
}

/// Decide the rewrite for one single-slot instruction at `pc`, using the
/// abstract state on entry (`regs`). Returns `None` to leave it unchanged.
/// `stats` is bumped for the class that fired.
fn rewrite_one(ins: Insn, regs: &[RegState; crate::insn::NUM_REGS], stats: &mut Stats) -> Option<Action> {
    let cls = ins.class();
    let is32 = cls == class::ALU;

    // --- ALU rewrites (ALU64 / ALU) ---
    if cls == class::ALU64 || cls == class::ALU {
        let op = ins.op();
        let dst_s = as_scalar(&regs[ins.dst as usize]);
        // Operand value: immediate, or the source register if it is a scalar.
        let b_val: Option<u64> = if ins.is_src_reg() {
            as_scalar(&regs[ins.src as usize]).filter(|s| s.is_const()).map(|s| s.umin)
        } else {
            Some(ins.imm as i64 as u64)
        };

        // (1) Constant folding: dst and operand both proven constant.
        if let (Some(a), Some(b)) = (dst_s.filter(|s| s.is_const()).map(|s| s.umin), b_val) {
            // Skip NEG/END here (unary / no operand); handled below or left.
            if op != alu::NEG && op != alu::END {
                if let Some(v) = eval_alu_const(op, is32, ins.off, a, b) {
                    if let Some(m) = mov_imm(ins.dst, v) {
                        // Only count as a fold if it actually changes the insn.
                        if m != ins {
                            stats.constant_fold += 1;
                            return Some(Action::Keep(m));
                        }
                    }
                }
            }
        }

        // (2) Immediate algebraic identities and strength reduction.
        if !ins.is_src_reg() {
            let imm = ins.imm as i64 as u64;
            // 64-bit identities that drop the instruction entirely.
            if cls == class::ALU64 {
                let is_identity = match op {
                    alu::ADD | alu::SUB | alu::OR | alu::XOR | alu::LSH | alu::RSH | alu::ARSH => {
                        imm == 0
                    }
                    alu::MUL => imm == 1,
                    alu::DIV if ins.off == 0 => imm == 1,
                    alu::AND => imm == u64::MAX, // imm sign-extends: -1 => all ones
                    _ => false,
                };
                if is_identity {
                    stats.algebraic_identity += 1;
                    return Some(Action::Drop);
                }
            }
            // MUL by a power of two -> left shift (both widths sound: same
            // truncation and zero-extension).
            if op == alu::MUL && imm >= 2 {
                let width = if is32 { 32 } else { 64 };
                if imm.is_power_of_two() {
                    let sh = imm.trailing_zeros();
                    if (sh as u64) < width {
                        stats.strength_reduction += 1;
                        return Some(Action::Keep(Insn {
                            opcode: cls | alu::LSH,
                            dst: ins.dst,
                            src: 0,
                            off: 0,
                            imm: sh as i32,
                        }));
                    }
                }
            }
            // (3) Redundant mask: `dst &= mask` where tnum proves dst already
            // fits in mask. For 32-bit ops we additionally need dst <= u32::MAX
            // so the zero-extension is a no-op too.
            if op == alu::AND {
                if let Some(s) = dst_s {
                    let mask = imm; // sign-extended
                    let fits = s.tnum.umax() & !mask == 0;
                    let width_ok = !is32 || s.umax <= u32::MAX as u64;
                    if fits && width_ok {
                        stats.redundant_mask += 1;
                        return Some(Action::Drop);
                    }
                }
            }
        }
        return None;
    }

    None
}

/// One optimization round: rewrite instructions in place / mark drops, then
/// relocate all pc-relative targets through the old→new index map. Returns the
/// new instruction vector and whether anything changed. Errors if a relocated
/// offset no longer fits its field (caller then keeps the previous program).
fn rewrite_round(insns: &[Insn], vres: &VerifyOk) -> Result<(Vec<Insn>, bool, Stats), String> {
    let n = insns.len();
    let mut stats = Stats::default();
    let mut actions: Vec<Action> = Vec::with_capacity(n);

    let mut pc = 0;
    while pc < n {
        let ins = insns[pc];
        if ins.is_wide() {
            // Two-slot lddw: never rewritten or dropped.
            actions.push(Action::Keep(ins));
            actions.push(Action::Keep(insns[pc + 1]));
            pc += 2;
            continue;
        }
        // Dead-branch elimination for conditional jumps.
        if (ins.class() == class::JMP || ins.class() == class::JMP32)
            && ins.op() != jmp::JA
            && ins.op() != jmp::CALL
            && ins.op() != jmp::EXIT
        {
            if let Some(regs) = vres.regs_at(pc) {
                let a = as_scalar(&regs[ins.dst as usize]);
                let b = if ins.is_src_reg() {
                    as_scalar(&regs[ins.src as usize])
                } else {
                    Some(Scalar::constant(ins.imm as i64 as u64))
                };
                if let (Some(a), Some(b)) = (a, b) {
                    let is32 = ins.class() == class::JMP32;
                    match eval_branch(ins.op(), is32, a, b) {
                        Some(true) => {
                            // Always taken -> unconditional JMP JA with the
                            // same (off) target.
                            stats.dead_branch += 1;
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
                            // Never taken -> fall through (drop the branch).
                            stats.dead_branch += 1;
                            actions.push(Action::Drop);
                            pc += 1;
                            continue;
                        }
                        None => {}
                    }
                }
            } else {
                // Unreachable instruction (dead code): drop it.
                actions.push(Action::Drop);
                pc += 1;
                continue;
            }
        }

        // ALU rewrites need the abstract state; unreachable => drop as dead.
        match vres.regs_at(pc) {
            Some(regs) => match rewrite_one(ins, regs, &mut stats) {
                Some(a) => actions.push(a),
                None => actions.push(Action::Keep(ins)),
            },
            None => actions.push(Action::Drop), // dead code
        }
        pc += 1;
    }

    // Build the kept vector and the old->new index map.
    let mut out: Vec<Insn> = Vec::new();
    let mut kept_new: Vec<Option<usize>> = vec![None; n];
    let mut old_of_new: Vec<usize> = Vec::new();
    for (pc, act) in actions.into_iter().enumerate() {
        if let Action::Keep(ins) = act {
            kept_new[pc] = Some(out.len());
            old_of_new.push(pc);
            out.push(ins);
        }
    }
    let new_len = out.len();
    // map[pc] = new index of the first kept slot at or after pc.
    let mut map = vec![new_len; n + 1];
    for pc in (0..n).rev() {
        map[pc] = kept_new[pc].unwrap_or(map[pc + 1]);
    }

    // Relocate pc-relative targets.
    for (new_pc, ins) in out.iter_mut().enumerate() {
        let old_pc = old_of_new[new_pc];
        let cls = ins.class();
        if cls != class::JMP && cls != class::JMP32 {
            continue;
        }
        let op = ins.op();
        if op == jmp::EXIT {
            continue;
        }
        if op == jmp::CALL {
            if ins.src == crate::insn::call_kind::LOCAL {
                let target = (old_pc as i64 + 1 + ins.imm as i64) as usize;
                let new_rel = map[target] as i64 - (new_pc as i64 + 1);
                ins.imm = new_rel as i32;
            }
            continue;
        }
        // JA (both classes) or a conditional. gotol (JMP32|JA) uses imm.
        let uses_imm = cls == class::JMP32 && op == jmp::JA;
        let rel = if uses_imm {
            ins.imm as i64
        } else {
            ins.off as i64
        };
        let target = (old_pc as i64 + 1 + rel) as usize;
        if target > n {
            return Err(format!("relocated jump target {target} out of range"));
        }
        let new_rel = map[target] as i64 - (new_pc as i64 + 1);
        if uses_imm {
            ins.imm = new_rel as i32;
        } else {
            if new_rel < i16::MIN as i64 || new_rel > i16::MAX as i64 {
                return Err(format!("relocated branch offset {new_rel} overflows i16"));
            }
            ins.off = new_rel as i16;
        }
    }

    let changed = new_len != n || stats.total_rewrites() > 0;
    Ok((out, changed, stats))
}

/// Optimize a program: apply sound, verifier-gated rewrites to a fixpoint, then
/// require the observable-equivalence checker to prove input≡output. Errors
/// (emitting nothing) if equivalence cannot be established or the result fails
/// to re-verify — an optimizer that cannot prove it preserved behavior must not
/// ship the result.
pub fn optimize(input: &Program, cfg: Config, equiv_opts: &equiv::Options) -> Result<Optimized, String> {
    // The input must verify — we optimize on its abstract state.
    Vm::new(input.clone())?
        .verify(cfg.clone())
        .map_err(|e| format!("input does not verify: {e}"))?;

    let mut current = input.clone();
    let mut total = Stats {
        insns_before: input.insns.len(),
        ..Default::default()
    };

    const MAX_ROUNDS: usize = 16;
    for _ in 0..MAX_ROUNDS {
        let vres = match Vm::new(current.clone()).and_then(|vm| {
            vm.verify(cfg.clone()).map_err(|e| e.to_string())
        }) {
            Ok(v) => v,
            Err(e) => return Err(format!("intermediate program failed to verify: {e}")),
        };
        let (new_insns, changed, round_stats) = rewrite_round(&current.insns, &vres)?;
        if !changed {
            break;
        }
        total.strength_reduction += round_stats.strength_reduction;
        total.algebraic_identity += round_stats.algebraic_identity;
        total.constant_fold += round_stats.constant_fold;
        total.dead_branch += round_stats.dead_branch;
        total.redundant_mask += round_stats.redundant_mask;
        total.rounds += 1;
        current = Program {
            insns: new_insns,
            maps: current.maps,
        };
    }
    total.insns_after = current.insns.len();

    // Re-verify the final program (must still be kernel-loadable).
    Vm::new(current.clone())?
        .verify(cfg)
        .map_err(|e| format!("optimized program failed to re-verify: {e}"))?;

    // Hard self-check gate: prove observable equivalence, else refuse to emit.
    let verdict = equiv::check(input, &current, equiv_opts)?;
    if !verdict.is_equivalent() {
        return Err(match verdict {
            Verdict::NotEquivalent(w) => format!(
                "self-check FAILED — refusing to emit; the rewrite changed observable \
                 behavior:\n{}",
                equiv::render_witness(&w)
            ),
            _ => "self-check failed".to_string(),
        });
    }

    Ok(Optimized {
        program: current,
        stats: total,
        self_check: verdict,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asm;
    use crate::equiv::Verdict;

    fn prog(src: &str) -> Program {
        let a = asm::assemble(src).unwrap();
        Program {
            insns: a.insns,
            maps: a.maps,
        }
    }

    fn opt(p: &Program) -> Optimized {
        optimize(p, Config::default(), &equiv::Options::default()).unwrap()
    }

    #[test]
    fn strength_reduction_mul_to_shift() {
        let p = prog("r0 = *(u8 *)(r1 + 0)\nr0 *= 8\nexit\n");
        let o = opt(&p);
        assert_eq!(o.stats.strength_reduction, 1);
        // The mul became a shift (same insn count, still equivalent).
        assert!(o.program.insns.iter().any(|i| i.opcode == (class::ALU64 | alu::LSH)));
        assert!(o.self_check.is_equivalent());
    }

    #[test]
    fn algebraic_identity_dropped() {
        let p = prog("r0 = *(u8 *)(r1 + 0)\nr0 += 0\nr0 *= 1\nexit\n");
        let o = opt(&p);
        assert_eq!(o.stats.algebraic_identity, 2);
        assert!(o.stats.insns_after < o.stats.insns_before);
    }

    #[test]
    fn constant_folding() {
        let p = prog("r0 = 2\nr0 += 3\nr0 *= 10\nexit\n");
        let o = opt(&p);
        assert!(o.stats.constant_fold >= 1);
        // Proven equivalent (side-effect-free constant r0 = 50).
        assert!(matches!(o.self_check, Verdict::ProvenEquivalent(_)));
    }

    #[test]
    fn dead_branch_never_taken_dropped() {
        // r0=0 then `if r0 != 0 goto +2` can never be taken.
        let p = prog("r0 = 0\nif r0 != 0 goto skip\nr0 = 7\nskip:\nexit\n");
        let o = opt(&p);
        assert!(o.stats.dead_branch >= 1);
        assert!(o.stats.insns_after < o.stats.insns_before);
    }

    #[test]
    fn dead_branch_always_taken_becomes_ja() {
        let p = prog("r0 = 5\nif r0 == 5 goto tgt\nr0 = 9\ntgt:\nr0 += 1\nexit\n");
        let o = opt(&p);
        assert!(o.stats.dead_branch >= 1);
        assert!(o.self_check.is_equivalent());
    }

    #[test]
    fn redundant_mask_dropped() {
        // Load a byte (proven 0..=255), masking with 0xff is a no-op.
        let p = prog("r0 = *(u8 *)(r1 + 0)\nr0 &= 0xff\nexit\n");
        let o = opt(&p);
        assert_eq!(o.stats.redundant_mask, 1);
        assert!(o.stats.insns_after < o.stats.insns_before);
    }

    #[test]
    fn already_optimal_unchanged() {
        let p = prog("r0 = *(u8 *)(r1 + 0)\nr0 <<= 1\nexit\n");
        let o = opt(&p);
        assert_eq!(o.stats.total_rewrites(), 0);
        assert_eq!(o.program.insns, p.insns);
    }

    #[test]
    fn preserves_printk_and_map_side_effects() {
        // A program that logs and writes a map must be preserved exactly; the
        // only rewrite available is the redundant mask, and equiv must still
        // hold across the observable tuple.
        let p = prog(
            ".map counts array 4 8 4\n\
             r1 = 65\n\
             *(u8 *)(r10 - 8) = r1\n\
             r1 = r10\n\
             r1 += -8\n\
             r2 = 1\n\
             r3 = 0\n\
             call 6\n\
             r0 = 0\n\
             exit\n",
        );
        let o = opt(&p);
        assert!(o.self_check.is_equivalent());
    }
}
