//! Disassembler producing kernel-documentation "pseudo-C" syntax,
//! e.g. `r0 = 42`, `r1 += r2`, `if r3 > 7 goto +5`, `*(u32 *)(r10 - 8) = r1`.

use crate::insn::*;

fn alu_op_str(op: u8) -> &'static str {
    match op {
        alu::ADD => "+=",
        alu::SUB => "-=",
        alu::MUL => "*=",
        alu::DIV => "/=",
        alu::OR => "|=",
        alu::AND => "&=",
        alu::LSH => "<<=",
        alu::RSH => ">>=",
        alu::MOD => "%=",
        alu::XOR => "^=",
        alu::MOV => "=",
        alu::ARSH => "s>>=",
        _ => "?=",
    }
}

fn jmp_cond_str(op: u8) -> &'static str {
    match op {
        jmp::JEQ => "==",
        jmp::JGT => ">",
        jmp::JGE => ">=",
        jmp::JSET => "&",
        jmp::JNE => "!=",
        jmp::JSGT => "s>",
        jmp::JSGE => "s>=",
        jmp::JLT => "<",
        jmp::JLE => "<=",
        jmp::JSLT => "s<",
        jmp::JSLE => "s<=",
        _ => "?",
    }
}

fn size_str(bytes: usize) -> &'static str {
    match bytes {
        1 => "u8",
        2 => "u16",
        4 => "u32",
        _ => "u64",
    }
}

fn mem_operand(base: u8, off: i16, bytes: usize, signed: bool) -> String {
    let ty = if signed {
        match bytes {
            1 => "s8",
            2 => "s16",
            _ => "s32",
        }
    } else {
        size_str(bytes)
    };
    if off == 0 {
        format!("*({ty} *)(r{base})")
    } else if off > 0 {
        format!("*({ty} *)(r{base} + {off})")
    } else {
        format!("*({ty} *)(r{base} - {})", -(off as i32))
    }
}

fn goto_str(pc: usize, rel: i64) -> String {
    let target = pc as i64 + 1 + rel;
    if rel >= 0 {
        format!("goto +{rel} <{target}>")
    } else {
        format!("goto {rel} <{target}>")
    }
}

/// Disassemble the instruction at `pc`. For a `lddw` this consumes two slots.
pub fn disasm_insn(insns: &[Insn], pc: usize) -> String {
    let ins = insns[pc];
    let (dst, src, off, imm) = (ins.dst, ins.src, ins.off, ins.imm);
    match ins.class() {
        class::ALU | class::ALU64 => {
            let is32 = ins.class() == class::ALU;
            let d = if is32 {
                format!("w{dst}")
            } else {
                format!("r{dst}")
            };
            let s = if ins.is_src_reg() {
                if is32 {
                    format!("w{src}")
                } else {
                    format!("r{src}")
                }
            } else {
                format!("{imm}")
            };
            match ins.op() {
                alu::NEG => format!("{d} = -{d}"),
                alu::END => {
                    let name = if ins.class() == class::ALU64 {
                        "bswap"
                    } else if ins.is_src_reg() {
                        "be"
                    } else {
                        "le"
                    };
                    format!("{d} = {name}{imm} {d}")
                }
                alu::DIV if off == 1 => format!("{d} s/= {s}"),
                alu::MOD if off == 1 => format!("{d} s%= {s}"),
                alu::MOV if off != 0 => {
                    // movsx: off = source width in bits
                    format!("{d} = (s{off}){s}")
                }
                op => format!("{d} {} {s}", alu_op_str(op)),
            }
        }
        class::JMP | class::JMP32 => {
            let is32 = ins.class() == class::JMP32;
            match ins.op() {
                jmp::JA => {
                    if is32 {
                        goto_str(pc, imm as i64)
                    } else {
                        goto_str(pc, off as i64)
                    }
                }
                jmp::CALL => match src {
                    call_kind::LOCAL => {
                        let target = pc as i64 + 1 + imm as i64;
                        format!("call pc{:+} <{target}>", imm)
                    }
                    call_kind::KFUNC => format!("call kfunc#{imm}"),
                    _ => format!("call {}", crate::helpers::helper_name(imm as u32)),
                },
                jmp::EXIT => "exit".to_string(),
                op => {
                    let d = if is32 {
                        format!("w{dst}")
                    } else {
                        format!("r{dst}")
                    };
                    let s = if ins.is_src_reg() {
                        if is32 {
                            format!("w{src}")
                        } else {
                            format!("r{src}")
                        }
                    } else {
                        format!("{imm}")
                    };
                    format!("if {d} {} {s} {}", jmp_cond_str(op), goto_str(pc, off as i64))
                }
            }
        }
        class::LD => {
            if ins.is_wide() {
                let v = wide_imm(insns, pc);
                match src {
                    pseudo::MAP_ID => format!("r{dst} = map[id:{imm}]"),
                    pseudo::MAP_VALUE => {
                        format!("r{dst} = map[id:{imm}][0] + {}", insns[pc + 1].imm)
                    }
                    _ => format!("r{dst} = {v} ll"),
                }
            } else {
                format!("<legacy ld 0x{:02x}>", ins.opcode)
            }
        }
        class::LDX => {
            let signed = ins.mem_mode() == mode::MEMSX;
            format!(
                "r{dst} = {}",
                mem_operand(src, off, ins.mem_size(), signed)
            )
        }
        class::ST => {
            format!("{} = {imm}", mem_operand(dst, off, ins.mem_size(), false))
        }
        class::STX => {
            if ins.mem_mode() == mode::ATOMIC {
                let sz = size_str(ins.mem_size());
                let m = mem_operand(dst, off, ins.mem_size(), false);
                match imm {
                    x if x == atomic::ADD => format!("lock {m} += r{src}"),
                    x if x == atomic::OR => format!("lock {m} |= r{src}"),
                    x if x == atomic::AND => format!("lock {m} &= r{src}"),
                    x if x == atomic::XOR => format!("lock {m} ^= r{src}"),
                    x if x == atomic::ADD | atomic::FETCH => {
                        format!("r{src} = atomic_fetch_add(({sz} *)(r{dst} {off:+}), r{src})")
                    }
                    x if x == atomic::OR | atomic::FETCH => {
                        format!("r{src} = atomic_fetch_or(({sz} *)(r{dst} {off:+}), r{src})")
                    }
                    x if x == atomic::AND | atomic::FETCH => {
                        format!("r{src} = atomic_fetch_and(({sz} *)(r{dst} {off:+}), r{src})")
                    }
                    x if x == atomic::XOR | atomic::FETCH => {
                        format!("r{src} = atomic_fetch_xor(({sz} *)(r{dst} {off:+}), r{src})")
                    }
                    x if x == atomic::XCHG => {
                        format!("r{src} = xchg(({sz} *)(r{dst} {off:+}), r{src})")
                    }
                    x if x == atomic::CMPXCHG => {
                        format!("r0 = cmpxchg(({sz} *)(r{dst} {off:+}), r0, r{src})")
                    }
                    _ => format!("<bad atomic 0x{imm:x}>"),
                }
            } else {
                format!("{} = r{src}", mem_operand(dst, off, ins.mem_size(), false))
            }
        }
        _ => unreachable!(),
    }
}

/// Disassemble a whole program, one line per instruction slot.
pub fn disasm_program(insns: &[Insn]) -> String {
    let mut out = String::new();
    let mut pc = 0;
    while pc < insns.len() {
        out.push_str(&format!("{pc:4}: {}\n", disasm_insn(insns, pc)));
        pc += if insns[pc].is_wide() { 2 } else { 1 };
    }
    out
}
