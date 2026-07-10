//! eBPF instruction encoding/decoding (ISA v4).
//!
//! Wire format: 8 bytes per instruction, little-endian:
//! ```text
//!   opcode:8  dst_reg:4  src_reg:4  offset:16  imm:32
//! ```
//! `lddw` (BPF_LD | BPF_IMM | BPF_DW) occupies two consecutive slots; the
//! second slot carries the upper 32 bits of the immediate in its `imm` field.

/// Instruction classes (low 3 bits of opcode).
pub mod class {
    pub const LD: u8 = 0x00;
    pub const LDX: u8 = 0x01;
    pub const ST: u8 = 0x02;
    pub const STX: u8 = 0x03;
    pub const ALU: u8 = 0x04;
    pub const JMP: u8 = 0x05;
    pub const JMP32: u8 = 0x06;
    pub const ALU64: u8 = 0x07;
}

/// ALU / ALU64 operation codes (high 4 bits).
pub mod alu {
    pub const ADD: u8 = 0x00;
    pub const SUB: u8 = 0x10;
    pub const MUL: u8 = 0x20;
    pub const DIV: u8 = 0x30; // offset==1: signed division (sdiv)
    pub const OR: u8 = 0x40;
    pub const AND: u8 = 0x50;
    pub const LSH: u8 = 0x60;
    pub const RSH: u8 = 0x70;
    pub const NEG: u8 = 0x80;
    pub const MOD: u8 = 0x90; // offset==1: signed modulo (smod)
    pub const XOR: u8 = 0xa0;
    pub const MOV: u8 = 0xb0; // offset==8|16|32: movsx
    pub const ARSH: u8 = 0xc0;
    pub const END: u8 = 0xd0; // byte swap
}

/// JMP / JMP32 operation codes (high 4 bits).
pub mod jmp {
    pub const JA: u8 = 0x00; // JMP32 class: `gotol` with 32-bit imm offset
    pub const JEQ: u8 = 0x10;
    pub const JGT: u8 = 0x20;
    pub const JGE: u8 = 0x30;
    pub const JSET: u8 = 0x40;
    pub const JNE: u8 = 0x50;
    pub const JSGT: u8 = 0x60;
    pub const JSGE: u8 = 0x70;
    pub const CALL: u8 = 0x80;
    pub const EXIT: u8 = 0x90;
    pub const JLT: u8 = 0xa0;
    pub const JLE: u8 = 0xb0;
    pub const JSLT: u8 = 0xc0;
    pub const JSLE: u8 = 0xd0;
}

/// Source operand bit for ALU/JMP classes.
pub mod src {
    pub const K: u8 = 0x00; // use 32-bit immediate
    pub const X: u8 = 0x08; // use source register
}

/// Memory access size (bits 3-4 of opcode for LD/LDX/ST/STX).
pub mod size {
    pub const W: u8 = 0x00; // 4 bytes
    pub const H: u8 = 0x08; // 2 bytes
    pub const B: u8 = 0x10; // 1 byte
    pub const DW: u8 = 0x18; // 8 bytes
}

/// Memory access mode (bits 5-7 of opcode for LD/LDX/ST/STX).
pub mod mode {
    pub const IMM: u8 = 0x00; // lddw
    pub const ABS: u8 = 0x20; // legacy packet access (unsupported)
    pub const IND: u8 = 0x40; // legacy packet access (unsupported)
    pub const MEM: u8 = 0x60; // regular load/store
    pub const MEMSX: u8 = 0x80; // sign-extending load
    pub const ATOMIC: u8 = 0xc0; // atomic operation
}

/// Atomic operation encodings (in `imm` of STX|ATOMIC insns).
pub mod atomic {
    pub const ADD: i32 = 0x00;
    pub const OR: i32 = 0x40;
    pub const AND: i32 = 0x50;
    pub const XOR: i32 = 0xa0;
    pub const FETCH: i32 = 0x01;
    pub const XCHG: i32 = 0xe1;
    pub const CMPXCHG: i32 = 0xf1;
}

/// `src_reg` pseudo values for `lddw`.
pub mod pseudo {
    /// Plain 64-bit immediate.
    pub const IMM64: u8 = 0;
    /// imm = map id; dst receives a map pointer.
    pub const MAP_ID: u8 = 1;
    /// imm = map id, next_imm = offset; dst receives ptr to map value.
    pub const MAP_VALUE: u8 = 2;
}

/// `src_reg` values for CALL.
pub mod call_kind {
    pub const HELPER: u8 = 0;
    pub const LOCAL: u8 = 1; // bpf-to-bpf call, imm = pc-relative target
    pub const KFUNC: u8 = 2; // unsupported in userland
}

pub const INSN_SIZE: usize = 8;
/// Frame pointer register (read-only).
pub const REG_FP: u8 = 10;
/// Number of addressable registers.
pub const NUM_REGS: usize = 11;
/// Per-frame stack size in bytes.
pub const STACK_SIZE: usize = 512;
/// Maximum bpf-to-bpf call depth (including the entry frame).
pub const MAX_CALL_FRAMES: usize = 8;

/// One decoded 8-byte instruction slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Insn {
    pub opcode: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i32,
}

impl Insn {
    #[inline]
    pub fn class(&self) -> u8 {
        self.opcode & 0x07
    }
    #[inline]
    pub fn op(&self) -> u8 {
        self.opcode & 0xf0
    }
    /// Source operand selector (ALU/JMP classes).
    #[inline]
    pub fn is_src_reg(&self) -> bool {
        self.opcode & 0x08 != 0
    }
    /// Memory access size in bytes (LD/LDX/ST/STX classes).
    #[inline]
    pub fn mem_size(&self) -> usize {
        match self.opcode & 0x18 {
            size::W => 4,
            size::H => 2,
            size::B => 1,
            _ => 8,
        }
    }
    #[inline]
    pub fn mem_mode(&self) -> u8 {
        self.opcode & 0xe0
    }
    /// Is this the first slot of a two-slot `lddw`?
    #[inline]
    pub fn is_wide(&self) -> bool {
        self.opcode == (class::LD | mode::IMM | size::DW)
    }

    pub fn encode(&self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0] = self.opcode;
        b[1] = (self.dst & 0x0f) | (self.src << 4);
        b[2..4].copy_from_slice(&self.off.to_le_bytes());
        b[4..8].copy_from_slice(&self.imm.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Insn {
        Insn {
            opcode: b[0],
            dst: b[1] & 0x0f,
            src: b[1] >> 4,
            off: i16::from_le_bytes([b[2], b[3]]),
            imm: i32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        }
    }
}

/// Decode raw bytecode into instruction slots.
///
/// Returns an error if the byte length is not a multiple of 8 or a trailing
/// `lddw` is truncated.
pub fn decode_program(bytes: &[u8]) -> Result<Vec<Insn>, String> {
    if !bytes.len().is_multiple_of(INSN_SIZE) {
        return Err(format!(
            "program length {} is not a multiple of {}",
            bytes.len(),
            INSN_SIZE
        ));
    }
    let insns: Vec<Insn> = bytes.chunks_exact(INSN_SIZE).map(Insn::decode).collect();
    let mut i = 0;
    while i < insns.len() {
        if insns[i].is_wide() {
            if i + 1 >= insns.len() {
                return Err(format!("truncated lddw at instruction {i}"));
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    Ok(insns)
}

/// Encode instruction slots back to raw bytecode.
pub fn encode_program(insns: &[Insn]) -> Vec<u8> {
    let mut out = Vec::with_capacity(insns.len() * INSN_SIZE);
    for i in insns {
        out.extend_from_slice(&i.encode());
    }
    out
}

/// Combined 64-bit immediate of a two-slot `lddw` starting at `pc`.
#[inline]
pub fn wide_imm(insns: &[Insn], pc: usize) -> u64 {
    (insns[pc].imm as u32 as u64) | ((insns[pc + 1].imm as u32 as u64) << 32)
}
