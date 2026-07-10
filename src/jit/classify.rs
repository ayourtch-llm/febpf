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
