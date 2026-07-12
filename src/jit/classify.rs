//! Architecture-independent instruction lowering: decide whether an eBPF
//! instruction is compiled to native code or deferred to the interpreter,
//! and if native, describe it in backend-neutral terms.
//!
//! The native set is deliberately the hot arithmetic/branch core. Everything
//! with tricky encodings or memory/effect semantics (div/mod, byte swaps,
//! sign-extending moves, variable-count shifts, loads, stores, atomics,
//! calls, `lddw`, `exit`) is deferred — the interpreter already handles those
//! correctly and safely, and they are rarely the JIT's bottleneck.

use crate::insn::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Width {
    W32,
    W64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AluOp {
    Add,
    Sub,
    Mul,
    Or,
    And,
    Xor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShiftOp {
    Lsh,
    Rsh,
    Arsh,
}

/// Comparison condition for a conditional branch (`if dst CC rhs goto`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cc {
    Eq,
    Ne,
    Gt,  // unsigned >
    Ge,  // unsigned >=
    Lt,  // unsigned <
    Le,  // unsigned <=
    Sgt, // signed >
    Sge, // signed >=
    Slt, // signed <
    Sle, // signed <=
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegOrImm {
    Reg(u8),
    Imm(i32),
}

/// Backend-neutral description of one instruction slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lowering {
    /// Not compiled natively — run on the interpreter via the trampoline.
    Deferred,
    AluReg { op: AluOp, w: Width, dst: u8, src: u8 },
    AluImm { op: AluOp, w: Width, dst: u8, imm: i32 },
    MovReg { w: Width, dst: u8, src: u8 },
    MovImm { w: Width, dst: u8, imm: i32 },
    Neg { w: Width, dst: u8 },
    ShiftImm { op: ShiftOp, w: Width, dst: u8, amount: u8 },
    /// Unconditional branch by `target` (relative offset).
    Jump { target: i16 },
    CondBranch { cc: Cc, w: Width, dst: u8, rhs: RegOrImm, off: i16 },
    JsetBranch { w: Width, dst: u8, rhs: RegOrImm, off: i16 },
}

/// Bitmask of eBPF registers (bit *i* = r*i*).
pub type RegMask = u16;

/// Every register — the safe default.
pub const ALL_REGS: RegMask = (1 << NUM_REGS) - 1;

#[inline]
fn bit(r: u8) -> RegMask {
    1 << r
}

/// Which registers the trampoline glue for a deferred instruction must move
/// between physical registers and the in-memory register file.
///
/// - `spill`: registers the interpreter will **read**, so their live values
///   must be in `regs[]` before the call.
/// - `reload`: registers the interpreter may **write**, so the physical copies
///   must be refreshed after it.
///
/// Registers in neither set keep their physical values across the trampoline —
/// *provided the backend maps them to callee-saved physical registers*. A
/// backend whose mapping puts an eBPF register in a caller-saved register must
/// union that register into both sets, since the call destroys it regardless
/// (see `x64::CLOBBERED`).
///
/// Every entry below is derived from the matching arm of
/// [`Machine::step`](crate::interp::Machine::step) — the interpreter is the
/// specification here, not the eBPF ISA doc. The fallback is [`ALL_REGS`], so
/// an instruction form nobody enumerated behaves exactly as it did before this
/// optimization existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeferredRegs {
    pub spill: RegMask,
    pub reload: RegMask,
    /// True when the instruction's only outcomes are "continue at the next
    /// instruction" or "stop" — i.e. it never redirects control anywhere else.
    /// Loads, stores, atomics, `lddw` and deferred ALU all qualify: the
    /// interpreter simply advances pc.
    ///
    /// The backend can then skip the pc→address table entirely and *fall
    /// through* into the next instruction's code, which the frontend emits
    /// immediately after this one (`lddw`'s tail slot is skipped, so the next
    /// emitted code is pc+2 — exactly where the interpreter lands). That saves
    /// two dependent loads and an indirect branch on the hottest deferred
    /// instructions.
    ///
    /// `false` for CALL / EXIT / `gotol`, which move pc arbitrarily.
    pub falls_through: bool,
}

impl DeferredRegs {
    const fn all() -> Self {
        DeferredRegs {
            spill: ALL_REGS,
            reload: ALL_REGS,
            falls_through: false,
        }
    }
    const fn flow(spill: RegMask, reload: RegMask) -> Self {
        DeferredRegs { spill, reload, falls_through: true }
    }
}

pub fn deferred_regs(ins: Insn) -> DeferredRegs {
    let (dst, src) = (ins.dst, ins.src);
    match ins.class() {
        // Deferred ALU (div, mod, byte-swap, sign-extending mov, register
        // shifts): reads dst and — when the operand is a register — src;
        // writes dst.
        class::ALU | class::ALU64 => {
            let mut spill = bit(dst);
            if ins.is_src_reg() {
                spill |= bit(src);
            }
            DeferredRegs::flow(spill, bit(dst))
        }
        // `lddw` takes its value from the instruction stream.
        class::LD if ins.is_wide() => DeferredRegs::flow(0, bit(dst)),
        // Legacy packet loads read r6 implicitly and, for IND, the encoded
        // source register. They write r0 and clobber r1-r5.
        class::LD => {
            let mut spill = bit(6);
            if ins.mem_mode() == mode::IND {
                spill |= bit(src);
            }
            DeferredRegs::flow(spill, 0x3f)
        }
        // dst = *(src + off)
        class::LDX => DeferredRegs::flow(bit(src), bit(dst)),
        class::ST | class::STX => {
            if ins.mem_mode() == mode::ATOMIC {
                // Atomics read dst (address) and src (operand); cmpxchg also
                // reads r0. Fetch/xchg variants write back into src, cmpxchg
                // writes r0. Covering all variants at once is still far
                // cheaper than the full file.
                let m = bit(dst) | bit(src) | bit(0);
                DeferredRegs::flow(m, bit(src) | bit(0))
            } else if ins.class() == class::ST {
                // *(dst + off) = imm
                DeferredRegs::flow(bit(dst), 0)
            } else {
                // *(dst + off) = src
                DeferredRegs::flow(bit(dst) | bit(src), 0)
            }
        }
        // `gotol` (JMP32 | JA) moves pc arbitrarily: it needs the table.
        class::JMP32 if ins.op() == jmp::JA => DeferredRegs {
            spill: 0,
            reload: 0,
            falls_through: false,
        },
        // CALL and EXIT rearrange call frames and the whole register file
        // (helper calls scrub r1-r5; exit restores r6-r9 and r10 from the
        // frame). Keep the full spill/reload — they are rare next to memory
        // ops, and the frame bookkeeping is not worth encoding as a mask.
        _ => DeferredRegs::all(),
    }
}

fn alu_op(op: u8) -> Option<AluOp> {
    Some(match op {
        alu::ADD => AluOp::Add,
        alu::SUB => AluOp::Sub,
        alu::MUL => AluOp::Mul,
        alu::OR => AluOp::Or,
        alu::AND => AluOp::And,
        alu::XOR => AluOp::Xor,
        _ => return None,
    })
}

fn cond(op: u8) -> Option<Cc> {
    Some(match op {
        jmp::JEQ => Cc::Eq,
        jmp::JNE => Cc::Ne,
        jmp::JGT => Cc::Gt,
        jmp::JGE => Cc::Ge,
        jmp::JLT => Cc::Lt,
        jmp::JLE => Cc::Le,
        jmp::JSGT => Cc::Sgt,
        jmp::JSGE => Cc::Sge,
        jmp::JSLT => Cc::Slt,
        jmp::JSLE => Cc::Sle,
        _ => return None,
    })
}

pub fn lower(ins: Insn) -> Lowering {
    let cls = ins.class();
    match cls {
        // A native write to r10 is never emitted: the frame pointer is
        // read-only in eBPF (the verifier rejects writes), and backends are
        // allowed to keep it memory-backed — aarch64 does, because it is one
        // callee-saved register short of holding all 11. Deferring the write
        // keeps the interpreter authoritative for r10 even in an unverified
        // program, where such a store would otherwise diverge.
        class::ALU | class::ALU64 if ins.dst == REG_FP => Lowering::Deferred,
        class::ALU | class::ALU64 => {
            let w = if cls == class::ALU { Width::W32 } else { Width::W64 };
            let dst = ins.dst;
            let rhs = |ins: &Insn| {
                if ins.is_src_reg() {
                    RegOrImm::Reg(ins.src)
                } else {
                    RegOrImm::Imm(ins.imm)
                }
            };
            match ins.op() {
                alu::MOV if ins.off == 0 => match rhs(&ins) {
                    RegOrImm::Reg(src) => Lowering::MovReg { w, dst, src },
                    RegOrImm::Imm(imm) => Lowering::MovImm { w, dst, imm },
                },
                alu::NEG => Lowering::Neg { w, dst },
                alu::LSH | alu::RSH | alu::ARSH if !ins.is_src_reg() => {
                    let op = match ins.op() {
                        alu::LSH => ShiftOp::Lsh,
                        alu::RSH => ShiftOp::Rsh,
                        _ => ShiftOp::Arsh,
                    };
                    let max = if w == Width::W32 { 31 } else { 63 };
                    Lowering::ShiftImm {
                        op,
                        w,
                        dst,
                        amount: (ins.imm as u32 & max) as u8,
                    }
                }
                op => match alu_op(op) {
                    Some(a) => match rhs(&ins) {
                        RegOrImm::Reg(src) => Lowering::AluReg { op: a, w, dst, src },
                        RegOrImm::Imm(imm) => Lowering::AluImm { op: a, w, dst, imm },
                    },
                    None => Lowering::Deferred, // div, mod, movsx, end, var-shift
                },
            }
        }
        class::JMP | class::JMP32 => {
            let w = if cls == class::JMP32 { Width::W32 } else { Width::W64 };
            match ins.op() {
                jmp::JA if cls == class::JMP => Lowering::Jump { target: ins.off },
                jmp::JSET => Lowering::JsetBranch {
                    w,
                    dst: ins.dst,
                    rhs: if ins.is_src_reg() {
                        RegOrImm::Reg(ins.src)
                    } else {
                        RegOrImm::Imm(ins.imm)
                    },
                    off: ins.off,
                },
                op => match cond(op) {
                    Some(cc) => Lowering::CondBranch {
                        cc,
                        w,
                        dst: ins.dst,
                        rhs: if ins.is_src_reg() {
                            RegOrImm::Reg(ins.src)
                        } else {
                            RegOrImm::Imm(ins.imm)
                        },
                        off: ins.off,
                    },
                    None => Lowering::Deferred, // call, exit, gotol
                },
            }
        }
        _ => Lowering::Deferred, // ld/ldx/st/stx
    }
}
