//! Fluent, typed construction of eBPF instruction streams.
//!
//! [`Builder`] is intentionally a thin layer over [`Insn`]. It validates
//! register numbers while Rust types make instruction offsets and immediates
//! explicit, then emits the same instruction slots accepted by [`crate::Vm`].

use crate::insn::{alu, call_kind, class, jmp, mode, pseudo, size, Insn, NUM_REGS};
use alloc::vec::Vec;
#[cfg(all(test, not(feature = "std")))]
use alloc::{string::ToString, vec};

/// An error found while constructing an instruction stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildError {
    register: u8,
}

impl BuildError {
    /// The invalid register number supplied to the builder.
    pub fn register(&self) -> u8 {
        self.register
    }
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "invalid eBPF register r{} (expected r0..r{})",
            self.register,
            NUM_REGS - 1
        )
    }
}

impl core::error::Error for BuildError {}

/// Width of a memory load or store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemSize {
    Byte,
    Half,
    Word,
    Double,
}

impl MemSize {
    fn opcode(self) -> u8 {
        match self {
            Self::Byte => size::B,
            Self::Half => size::H,
            Self::Word => size::W,
            Self::Double => size::DW,
        }
    }
}

/// Binary ALU operation for [`Builder::alu64_imm`] and related methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AluOp {
    Add,
    Sub,
    Mul,
    Div,
    Or,
    And,
    Lsh,
    Rsh,
    Mod,
    Xor,
    Arsh,
}

impl AluOp {
    fn opcode(self) -> u8 {
        match self {
            Self::Add => alu::ADD,
            Self::Sub => alu::SUB,
            Self::Mul => alu::MUL,
            Self::Div => alu::DIV,
            Self::Or => alu::OR,
            Self::And => alu::AND,
            Self::Lsh => alu::LSH,
            Self::Rsh => alu::RSH,
            Self::Mod => alu::MOD,
            Self::Xor => alu::XOR,
            Self::Arsh => alu::ARSH,
        }
    }
}

/// Conditional jump operation for [`Builder::jump_imm`] and
/// [`Builder::jump_reg`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JumpOp {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    Set,
    SignedGt,
    SignedGe,
    SignedLt,
    SignedLe,
}

impl JumpOp {
    fn opcode(self) -> u8 {
        match self {
            Self::Eq => jmp::JEQ,
            Self::Ne => jmp::JNE,
            Self::Gt => jmp::JGT,
            Self::Ge => jmp::JGE,
            Self::Lt => jmp::JLT,
            Self::Le => jmp::JLE,
            Self::Set => jmp::JSET,
            Self::SignedGt => jmp::JSGT,
            Self::SignedGe => jmp::JSGE,
            Self::SignedLt => jmp::JSLT,
            Self::SignedLe => jmp::JSLE,
        }
    }
}

/// A fluent eBPF instruction builder.
///
/// Methods consume and return the builder so programs can be written as a
/// chain. The first invalid register is retained and returned by [`build`](Self::build).
#[derive(Debug, Clone, Default)]
pub struct Builder {
    insns: Vec<Insn>,
    error: Option<BuildError>,
}

impl Builder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Finish construction and return instruction slots suitable for a
    /// [`crate::Program`].
    pub fn build(self) -> Result<Vec<Insn>, BuildError> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(self.insns),
        }
    }

    /// Number of instruction slots emitted so far. An `lddw` occupies two.
    pub fn len(&self) -> usize {
        self.insns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }

    fn registers(&mut self, registers: &[u8]) -> bool {
        if self.error.is_some() {
            return false;
        }
        if let Some(&register) = registers.iter().find(|&&r| r as usize >= NUM_REGS) {
            self.error = Some(BuildError { register });
            return false;
        }
        true
    }

    fn push(mut self, insn: Insn, registers: &[u8]) -> Self {
        if self.registers(registers) {
            self.insns.push(insn);
        }
        self
    }

    fn alu_imm(self, class: u8, op: AluOp, dst: u8, imm: i32) -> Self {
        self.push(
            Insn {
                opcode: class | op.opcode(),
                dst,
                src: 0,
                off: 0,
                imm,
            },
            &[dst],
        )
    }

    fn alu_reg(self, class: u8, op: AluOp, dst: u8, src_reg: u8) -> Self {
        self.push(
            Insn {
                opcode: class | op.opcode() | crate::insn::src::X,
                dst,
                src: src_reg,
                off: 0,
                imm: 0,
            },
            &[dst, src_reg],
        )
    }

    pub fn mov64_imm(self, dst: u8, imm: i32) -> Self {
        self.push(
            Insn {
                opcode: class::ALU64 | alu::MOV,
                dst,
                src: 0,
                off: 0,
                imm,
            },
            &[dst],
        )
    }

    pub fn mov64_reg(self, dst: u8, src_reg: u8) -> Self {
        self.push(
            Insn {
                opcode: class::ALU64 | alu::MOV | crate::insn::src::X,
                dst,
                src: src_reg,
                off: 0,
                imm: 0,
            },
            &[dst, src_reg],
        )
    }

    pub fn mov32_imm(self, dst: u8, imm: i32) -> Self {
        self.push(
            Insn {
                opcode: class::ALU | alu::MOV,
                dst,
                src: 0,
                off: 0,
                imm,
            },
            &[dst],
        )
    }

    pub fn mov32_reg(self, dst: u8, src_reg: u8) -> Self {
        self.push(
            Insn {
                opcode: class::ALU | alu::MOV | crate::insn::src::X,
                dst,
                src: src_reg,
                off: 0,
                imm: 0,
            },
            &[dst, src_reg],
        )
    }

    pub fn alu64_imm(self, op: AluOp, dst: u8, imm: i32) -> Self {
        self.alu_imm(class::ALU64, op, dst, imm)
    }

    pub fn alu64_reg(self, op: AluOp, dst: u8, src_reg: u8) -> Self {
        self.alu_reg(class::ALU64, op, dst, src_reg)
    }

    pub fn alu32_imm(self, op: AluOp, dst: u8, imm: i32) -> Self {
        self.alu_imm(class::ALU, op, dst, imm)
    }

    pub fn alu32_reg(self, op: AluOp, dst: u8, src_reg: u8) -> Self {
        self.alu_reg(class::ALU, op, dst, src_reg)
    }

    /// Load a plain 64-bit immediate. This emits two instruction slots.
    pub fn lddw(mut self, dst: u8, imm: u64) -> Self {
        if self.registers(&[dst]) {
            self.insns.push(Insn {
                opcode: class::LD | mode::IMM | size::DW,
                dst,
                src: pseudo::IMM64,
                off: 0,
                imm: imm as u32 as i32,
            });
            self.insns.push(Insn {
                opcode: 0,
                dst: 0,
                src: 0,
                off: 0,
                imm: (imm >> 32) as u32 as i32,
            });
        }
        self
    }

    pub fn load(self, size: MemSize, dst: u8, base: u8, off: i16) -> Self {
        self.push(
            Insn {
                opcode: class::LDX | mode::MEM | size.opcode(),
                dst,
                src: base,
                off,
                imm: 0,
            },
            &[dst, base],
        )
    }

    pub fn store_imm(self, size: MemSize, base: u8, off: i16, imm: i32) -> Self {
        self.push(
            Insn {
                opcode: class::ST | mode::MEM | size.opcode(),
                dst: base,
                src: 0,
                off,
                imm,
            },
            &[base],
        )
    }

    pub fn store_reg(self, size: MemSize, base: u8, off: i16, src_reg: u8) -> Self {
        self.push(
            Insn {
                opcode: class::STX | mode::MEM | size.opcode(),
                dst: base,
                src: src_reg,
                off,
                imm: 0,
            },
            &[base, src_reg],
        )
    }

    pub fn jump(self, off: i16) -> Self {
        self.push(
            Insn {
                opcode: class::JMP | jmp::JA,
                dst: 0,
                src: 0,
                off,
                imm: 0,
            },
            &[],
        )
    }

    pub fn jump_imm(self, op: JumpOp, dst: u8, imm: i32, off: i16) -> Self {
        self.push(
            Insn {
                opcode: class::JMP | op.opcode(),
                dst,
                src: 0,
                off,
                imm,
            },
            &[dst],
        )
    }

    pub fn jump_reg(self, op: JumpOp, dst: u8, src_reg: u8, off: i16) -> Self {
        self.push(
            Insn {
                opcode: class::JMP | op.opcode() | crate::insn::src::X,
                dst,
                src: src_reg,
                off,
                imm: 0,
            },
            &[dst, src_reg],
        )
    }

    pub fn call(self, helper_id: u32) -> Self {
        self.push(
            Insn {
                opcode: class::JMP | jmp::CALL,
                dst: 0,
                src: call_kind::HELPER,
                off: 0,
                imm: helper_id as i32,
            },
            &[],
        )
    }

    pub fn call_local(self, relative_target: i32) -> Self {
        self.push(
            Insn {
                opcode: class::JMP | jmp::CALL,
                dst: 0,
                src: call_kind::LOCAL,
                off: 0,
                imm: relative_target,
            },
            &[],
        )
    }

    pub fn exit(self) -> Self {
        self.push(
            Insn {
                opcode: class::JMP | jmp::EXIT,
                dst: 0,
                src: 0,
                off: 0,
                imm: 0,
            },
            &[],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Program, VerifierConfig, Vm};

    #[test]
    fn builds_and_executes_a_program() {
        let insns = Builder::new()
            .mov64_imm(0, 40)
            .mov64_imm(1, 2)
            .alu64_reg(AluOp::Add, 0, 1)
            .exit()
            .build()
            .unwrap();
        let mut vm = Vm::new(Program {
            insns,
            maps: vec![],
            btf_ctx: None,
        })
        .unwrap();
        vm.verify(VerifierConfig::default()).unwrap();
        assert_eq!(vm.run(&mut []).unwrap(), 42);
    }

    #[test]
    fn lddw_and_memory_encodings_are_exact() {
        let insns = Builder::new()
            .lddw(3, 0x1122_3344_89ab_cdef)
            .load(MemSize::Word, 1, 10, -8)
            .store_reg(MemSize::Double, 10, -16, 3)
            .build()
            .unwrap();
        assert_eq!(insns.len(), 4);
        assert_eq!(
            insns[0],
            Insn {
                opcode: 0x18,
                dst: 3,
                src: 0,
                off: 0,
                imm: 0x89ab_cdef_u32 as i32,
            }
        );
        assert_eq!(
            insns[1],
            Insn {
                opcode: 0,
                dst: 0,
                src: 0,
                off: 0,
                imm: 0x1122_3344,
            }
        );
        assert_eq!(
            insns[2],
            Insn {
                opcode: class::LDX | mode::MEM | size::W,
                dst: 1,
                src: 10,
                off: -8,
                imm: 0,
            }
        );
        assert_eq!(
            insns[3],
            Insn {
                opcode: class::STX | mode::MEM | size::DW,
                dst: 10,
                src: 3,
                off: -16,
                imm: 0,
            }
        );
    }

    #[test]
    fn rejects_invalid_register_and_stops_emitting() {
        let error = Builder::new()
            .mov64_imm(0, 1)
            .alu64_reg(AluOp::Add, 0, 11)
            .exit()
            .build()
            .unwrap_err();
        assert_eq!(error.register(), 11);
        assert_eq!(
            error.to_string(),
            "invalid eBPF register r11 (expected r0..r10)"
        );
    }

    #[test]
    fn encodes_jumps_and_calls() {
        let insns = Builder::new()
            .jump_imm(JumpOp::Eq, 2, -1, 7)
            .jump_reg(JumpOp::SignedLt, 3, 4, -2)
            .call(0xffff_fffe)
            .call_local(-4)
            .exit()
            .build()
            .unwrap();
        assert_eq!(insns[0].opcode, class::JMP | jmp::JEQ);
        assert_eq!(insns[0].off, 7);
        assert_eq!(
            insns[1].opcode,
            class::JMP | jmp::JSLT | crate::insn::src::X
        );
        assert_eq!(insns[2].src, call_kind::HELPER);
        assert_eq!(insns[2].imm, -2);
        assert_eq!(insns[3].src, call_kind::LOCAL);
        assert_eq!(insns[3].imm, -4);
        assert_eq!(insns[4].opcode, class::JMP | jmp::EXIT);
    }
}
