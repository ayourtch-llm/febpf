//! aarch64 (AAPCS64, macOS/Apple Silicon) backend for the JIT.
//!
//! This file is a pure A64 instruction encoder — it contains no eBPF
//! semantics. See `docs/specs/jit-backend.md` for the contract it satisfies.
//! The encoder itself is OS-independent; only the executable-memory glue in
//! `mod.rs` (`MAP_JIT` + per-thread write gate + i-cache flush) is macOS-
//! specific.
//!
//! ## Register mapping (eBPF → aarch64)
//!
//! eBPF r0..r10 map **identically** to `x0..x10`. All of those are
//! caller-saved, which is fine: native code makes exactly one kind of call
//! (the deferred-instruction trampoline), and that glue spills all 11 eBPF
//! registers to the register file before the call and reloads them after,
//! so nothing live crosses a call boundary in a scratch register.
//!
//! | purpose            | register | notes                                |
//! |--------------------|----------|--------------------------------------|
//! | eBPF r0..r10       | x0..x10  | identity map, caller-saved           |
//! | `regs_ptr`         | x19      | callee-saved, survives trampoline    |
//! | `machine_ptr`      | x20      | callee-saved, survives trampoline    |
//! | trampoline return  | x11      | next pc / STOP                       |
//! | table base/target  | x12      |                                      |
//! | immediates         | x15      | materialized rhs operands            |
//! | call target        | x16      | IP0, conventional intra-call scratch |
//!
//! `W`-register forms give eBPF's 32-bit zero-extension semantics for free.
//! Absolute pointers (trampoline, pc→address table) live in an 8-byte-aligned
//! literal pool after the epilogue, loaded with `LDR (literal)` and written
//! by `patch_absolutes` once the code has its final address.

use super::{AluOp, Cc, JitBackend, RegOrImm, ShiftOp, Target, Width};

/// eBPF register index → physical register number (identity, see above).
#[inline]
fn hreg(ebpf: u8) -> u32 {
    ebpf as u32
}

const REGS_PTR: u32 = 19; // x19
const MACHINE_PTR: u32 = 20; // x20
const RET_SAVE: u32 = 11; // x11: trampoline return (next pc / STOP)
const TBL: u32 = 12; // x12: table base, then jump target
const IMM: u32 = 15; // x15: materialized immediates
const CALL_TGT: u32 = 16; // x16 (IP0): trampoline address
const FP: u32 = 29;
const LR: u32 = 30;
const SP: u32 = 31; // also XZR in register-operand positions
const ZR: u32 = 31;

const NOP: u32 = 0xD503_201F;

/// A64 condition codes.
mod cond {
    pub const EQ: u32 = 0x0;
    pub const NE: u32 = 0x1;
    pub const HS: u32 = 0x2; // unsigned >=
    pub const LO: u32 = 0x3; // unsigned <
    pub const MI: u32 = 0x4; // negative (N set)
    pub const HI: u32 = 0x8; // unsigned >
    pub const LS: u32 = 0x9; // unsigned <=
    pub const GE: u32 = 0xA;
    pub const LT: u32 = 0xB;
    pub const GT: u32 = 0xC;
    pub const LE: u32 = 0xD;
}

/// eBPF condition → A64 condition code (for `B.cond` after `CMP`).
fn cc_code(cc: Cc) -> u32 {
    match cc {
        Cc::Eq => cond::EQ,
        Cc::Ne => cond::NE,
        Cc::Gt => cond::HI,
        Cc::Ge => cond::HS,
        Cc::Lt => cond::LO,
        Cc::Le => cond::LS,
        Cc::Sgt => cond::GT,
        Cc::Sge => cond::GE,
        Cc::Slt => cond::LT,
        Cc::Sle => cond::LE,
    }
}

/// Which relative field a fixup patches (both are scaled by 4).
enum Form {
    /// `B` — imm26 at bit 0.
    Imm26,
    /// `B.cond` / `LDR (literal)` — imm19 at bit 5.
    Imm19,
}

enum FixTarget {
    Pc(usize),
    Epilogue,
    /// Literal-pool slot holding the trampoline address.
    PoolTrampoline,
    /// Literal-pool slot holding the pc→address table base.
    PoolTable,
}

struct Fix {
    /// Byte offset of the instruction word (imm field emitted as zero).
    at: usize,
    form: Form,
    target: FixTarget,
}

pub struct Aarch64Backend {
    buf: Vec<u8>,
    fixups: Vec<Fix>,
    epilogue: usize,
    /// Byte offset of the literal pool (trampoline u64, then table u64).
    pool: usize,
}

impl Aarch64Backend {
    /// Emit one 32-bit instruction word.
    fn w(&mut self, insn: u32) {
        self.buf.extend_from_slice(&insn.to_le_bytes());
    }

    fn sf(w: Width) -> u32 {
        match w {
            Width::W64 => 1 << 31,
            Width::W32 => 0,
        }
    }

    /// Add/sub (shifted register): `rd = rn op rm`. `base` is the 32-bit
    /// opcode (`ADD` 0x0B.., `SUB` 0x4B.., `SUBS` 0x6B..); logical ops use
    /// [`logic_rrr`].
    fn addsub_rrr(&mut self, base: u32, w: Width, rd: u32, rn: u32, rm: u32) {
        self.w(base | Self::sf(w) | (rm << 16) | (rn << 5) | rd);
    }

    /// Logical (shifted register): AND 0x0A.., ORR 0x2A.., EOR 0x4A..,
    /// ANDS 0x6A.. — same field layout as add/sub.
    fn logic_rrr(&mut self, base: u32, w: Width, rd: u32, rn: u32, rm: u32) {
        self.w(base | Self::sf(w) | (rm << 16) | (rn << 5) | rd);
    }

    /// `MOV rd, rm` as `ORR rd, zr, rm` (W-form zero-extends).
    fn mov_rr(&mut self, w: Width, rd: u32, rm: u32) {
        self.logic_rrr(0x2A00_0000, w, rd, ZR, rm);
    }

    /// Materialize an arbitrary 64-bit constant with MOVZ/MOVN + MOVK.
    fn mov_u64(&mut self, rd: u32, v: u64) {
        let chunk = |i: u32| ((v >> (16 * i)) & 0xFFFF) as u32;
        let zeros = (0..4).filter(|&i| chunk(i) == 0).count();
        let ones = (0..4).filter(|&i| chunk(i) == 0xFFFF).count();
        if ones > zeros {
            // MOVN seeds every chunk with 0xFFFF; fix the rest with MOVK.
            let first = (0..4).find(|&i| chunk(i) != 0xFFFF).unwrap_or(0);
            self.w(0x9280_0000 | (first << 21) | ((!chunk(first) & 0xFFFF) << 5) | rd);
            for i in 0..4 {
                if i != first && chunk(i) != 0xFFFF {
                    self.w(0xF280_0000 | (i << 21) | (chunk(i) << 5) | rd);
                }
            }
        } else {
            let first = (0..4).find(|&i| chunk(i) != 0).unwrap_or(0);
            self.w(0xD280_0000 | (first << 21) | (chunk(first) << 5) | rd);
            for i in 0..4 {
                if i != first && chunk(i) != 0 {
                    self.w(0xF280_0000 | (i << 21) | (chunk(i) << 5) | rd);
                }
            }
        }
    }

    /// Materialize a sign-extended i32 rhs into the scratch register and
    /// return it. W-form consumers read only the low 32 bits, which equal
    /// the raw imm bits, so one materialization serves both widths.
    fn imm_to_scratch(&mut self, imm: i32) -> u32 {
        self.mov_u64(IMM, imm as i64 as u64);
        IMM
    }

    fn rhs_reg(&mut self, rhs: RegOrImm) -> u32 {
        match rhs {
            RegOrImm::Reg(s) => hreg(s),
            RegOrImm::Imm(v) => self.imm_to_scratch(v),
        }
    }

    /// `STR xt, [x19, #8*slot]` / `LDR xt, [x19, #8*slot]`.
    fn str_slot(&mut self, xt: u32, slot: u32) {
        self.w(0xF900_0000 | (slot << 10) | (REGS_PTR << 5) | xt);
    }
    fn ldr_slot(&mut self, xt: u32, slot: u32) {
        self.w(0xF940_0000 | (slot << 10) | (REGS_PTR << 5) | xt);
    }

    fn spill_all(&mut self) {
        for i in 0..super::abi::NUM_REGS as u32 {
            self.str_slot(i, i);
        }
    }
    fn reload_all(&mut self) {
        for i in 0..super::abi::NUM_REGS as u32 {
            self.ldr_slot(i, i);
        }
    }

    /// `CMP dst, rhs` (`SUBS zr, dst, rhs`) for a following B.cond.
    fn emit_cmp(&mut self, w: Width, dst: u8, rhs: RegOrImm) {
        let rm = self.rhs_reg(rhs);
        self.addsub_rrr(0x6B00_0000, w, ZR, hreg(dst), rm);
    }

    /// `B.cond` with a fixup.
    fn bcond(&mut self, cc: u32, target: Target) {
        self.record_fix(Form::Imm19, target);
        self.w(0x5400_0000 | cc);
    }

    fn record_fix(&mut self, form: Form, target: Target) {
        let target = match target {
            Target::Pc(pc) => FixTarget::Pc(pc),
            Target::Epilogue => FixTarget::Epilogue,
        };
        self.fixups.push(Fix { at: self.buf.len(), form, target });
    }

    /// `LDR xt, <literal>` with a pool fixup.
    fn ldr_lit(&mut self, xt: u32, pool: FixTarget) {
        self.fixups.push(Fix {
            at: self.buf.len(),
            form: Form::Imm19,
            target: pool,
        });
        self.w(0x5800_0000 | xt);
    }
}

impl JitBackend for Aarch64Backend {
    fn new(num_insns: usize) -> Self {
        Aarch64Backend {
            buf: Vec::with_capacity(num_insns * 16 + 128),
            fixups: Vec::new(),
            epilogue: 0,
            pool: 0,
        }
    }

    fn code(&self) -> &[u8] {
        &self.buf
    }

    fn mark_label(&mut self, _pc: usize) {}

    fn prologue(&mut self) {
        // stp x29, x30, [sp, #-32]!  (frame record + room for x19/x20)
        self.w(0xA980_0000 | (0x7C << 15) | (LR << 10) | (SP << 5) | FP);
        // stp x19, x20, [sp, #16]
        self.w(0xA900_0000 | (2 << 15) | (MACHINE_PTR << 10) | (SP << 5) | REGS_PTR);
        // mov x29, sp   (ADD x29, sp, #0)
        self.w(0x9100_0000 | (SP << 5) | FP);
        // x19 = regs_ptr (arg0), x20 = machine_ptr (arg1)
        self.mov_rr(Width::W64, REGS_PTR, 0);
        self.mov_rr(Width::W64, MACHINE_PTR, 1);
        // load the eBPF register file, then fall through into pc 0
        self.reload_all();
    }

    fn epilogue(&mut self) {
        self.epilogue = self.buf.len();
        // ldp x19, x20, [sp, #16]
        self.w(0xA940_0000 | (2 << 15) | (MACHINE_PTR << 10) | (SP << 5) | REGS_PTR);
        // ldp x29, x30, [sp], #32
        self.w(0xA8C0_0000 | (4 << 15) | (LR << 10) | (SP << 5) | FP);
        self.w(0xD65F_03C0); // ret
        // 8-byte-aligned literal pool: [trampoline u64][table u64]
        if !self.buf.len().is_multiple_of(8) {
            self.w(NOP);
        }
        self.pool = self.buf.len();
        self.buf.extend_from_slice(&[0u8; 16]);
    }

    fn alu_reg(&mut self, op: AluOp, w: Width, dst: u8, src: u8) {
        let (d, s) = (hreg(dst), hreg(src));
        match op {
            AluOp::Add => self.addsub_rrr(0x0B00_0000, w, d, d, s),
            AluOp::Sub => self.addsub_rrr(0x4B00_0000, w, d, d, s),
            AluOp::Or => self.logic_rrr(0x2A00_0000, w, d, d, s),
            AluOp::And => self.logic_rrr(0x0A00_0000, w, d, d, s),
            AluOp::Xor => self.logic_rrr(0x4A00_0000, w, d, d, s),
            // MUL = MADD rd, rn, rm, zr
            AluOp::Mul => self.w(0x1B00_7C00 | Self::sf(w) | (s << 16) | (d << 5) | d),
        }
    }

    fn alu_imm(&mut self, op: AluOp, w: Width, dst: u8, imm: i32) {
        // A64 immediate forms are restricted (12-bit add/sub, bitmask
        // logicals), so materialize and reuse the register path.
        let s = self.imm_to_scratch(imm);
        let d = hreg(dst);
        match op {
            AluOp::Add => self.addsub_rrr(0x0B00_0000, w, d, d, s),
            AluOp::Sub => self.addsub_rrr(0x4B00_0000, w, d, d, s),
            AluOp::Or => self.logic_rrr(0x2A00_0000, w, d, d, s),
            AluOp::And => self.logic_rrr(0x0A00_0000, w, d, d, s),
            AluOp::Xor => self.logic_rrr(0x4A00_0000, w, d, d, s),
            AluOp::Mul => self.w(0x1B00_7C00 | Self::sf(w) | (s << 16) | (hreg(dst) << 5) | hreg(dst)),
        }
    }

    fn mov_reg(&mut self, w: Width, dst: u8, src: u8) {
        let (d, s) = (hreg(dst), hreg(src));
        if d == s && w == Width::W64 {
            return; // no-op (W32 must still zero-extend)
        }
        self.mov_rr(w, d, s);
    }

    fn mov_imm(&mut self, w: Width, dst: u8, imm: i32) {
        let v = match w {
            Width::W64 => imm as i64 as u64,
            Width::W32 => imm as u32 as u64,
        };
        self.mov_u64(hreg(dst), v);
    }

    fn neg(&mut self, w: Width, dst: u8) {
        // NEG rd = SUB rd, zr, rd
        let d = hreg(dst);
        self.addsub_rrr(0x4B00_0000, w, d, ZR, d);
    }

    fn shift_imm(&mut self, op: ShiftOp, w: Width, dst: u8, amount: u8) {
        let d = hreg(dst);
        let sh = amount as u32;
        let (bits, top) = match w {
            Width::W64 => (64, 63),
            Width::W32 => (32, 31),
        };
        // UBFM (LSL/LSR) / SBFM (ASR) aliases; N matches sf.
        let (base, immr, imms) = match op {
            ShiftOp::Lsh => (0x5300_0000, (bits - sh) % bits, top - sh),
            ShiftOp::Rsh => (0x5300_0000, sh, top),
            ShiftOp::Arsh => (0x1300_0000, sh, top),
        };
        let n_sf = match w {
            Width::W64 => (1 << 31) | (1 << 22),
            Width::W32 => 0,
        };
        self.w(base | n_sf | (immr << 16) | (imms << 10) | (d << 5) | d);
    }

    fn jump(&mut self, target: Target) {
        self.record_fix(Form::Imm26, target);
        self.w(0x1400_0000); // b
    }

    fn cond_branch(&mut self, cc: Cc, w: Width, dst: u8, rhs: RegOrImm, target: Target) {
        self.emit_cmp(w, dst, rhs);
        self.bcond(cc_code(cc), target);
    }

    fn jset_branch(&mut self, w: Width, dst: u8, rhs: RegOrImm, target: Target) {
        // TST dst, rhs (ANDS zr, dst, rhs); taken when (dst & rhs) != 0.
        let rm = self.rhs_reg(rhs);
        self.logic_rrr(0x6A00_0000, w, ZR, hreg(dst), rm);
        self.bcond(cond::NE, target);
    }

    fn deferred(&mut self, pc: usize) {
        // Spill the eBPF register file.
        self.spill_all();
        // arg0 = machine_ptr, arg1 = pc
        self.mov_rr(Width::W64, 0, MACHINE_PTR);
        self.mov_u64(1, pc as u64);
        // Call the trampoline through the literal pool.
        self.ldr_lit(CALL_TGT, FixTarget::PoolTrampoline);
        self.w(0xD63F_0000 | (CALL_TGT << 5)); // blr x16
        // Save next-pc/STOP, reload the eBPF registers (loads leave flags
        // alone, but TST comes after the reload anyway).
        self.mov_rr(Width::W64, RET_SAVE, 0);
        self.reload_all();
        // STOP has bit 63 set: TST sets N, B.MI exits via the epilogue.
        self.logic_rrr(0x6A00_0000, Width::W64, ZR, RET_SAVE, RET_SAVE);
        self.bcond(cond::MI, Target::Epilogue);
        // Resume: br table[next_pc]
        self.ldr_lit(TBL, FixTarget::PoolTable);
        // ldr x12, [x12, x11, lsl #3]
        self.w(0xF860_7800 | (RET_SAVE << 16) | (TBL << 5) | TBL);
        self.w(0xD61F_0000 | (TBL << 5)); // br x12
    }

    fn resolve_branches(&mut self, label_off: &[usize], epilogue_off: usize) -> Result<(), String> {
        for f in &self.fixups {
            let target_off = match f.target {
                FixTarget::Epilogue => epilogue_off,
                FixTarget::PoolTrampoline => self.pool,
                FixTarget::PoolTable => self.pool + 8,
                FixTarget::Pc(pc) => {
                    let o = label_off.get(pc).copied().unwrap_or(usize::MAX);
                    if o == usize::MAX {
                        epilogue_off
                    } else {
                        o
                    }
                }
            };
            let delta = target_off as i64 - f.at as i64;
            debug_assert_eq!(delta % 4, 0);
            let imm = delta / 4;
            let (mask, shift, range) = match f.form {
                Form::Imm26 => (0x03FF_FFFFu32, 0, 1i64 << 25),
                Form::Imm19 => (0x0007_FFFFu32, 5, 1i64 << 18),
            };
            if !(-range..range).contains(&imm) {
                // Only reachable for programs emitting >1MiB of code (imm19).
                // Fixing this needs branch islands; until then the caller
                // falls back to the interpreter rather than mis-encoding.
                return Err(format!(
                    "aarch64 JIT: branch displacement {delta} bytes exceeds the \
                     encodable range; program too large to JIT"
                ));
            }
            let mut word = u32::from_le_bytes(self.buf[f.at..f.at + 4].try_into().unwrap());
            word |= ((imm as u32) & mask) << shift;
            self.buf[f.at..f.at + 4].copy_from_slice(&word.to_le_bytes());
        }
        Ok(())
    }

    fn epilogue_off(&self) -> usize {
        self.epilogue
    }

    fn patch_absolutes(&self, code: &mut [u8], trampoline: u64, table: u64) {
        code[self.pool..self.pool + 8].copy_from_slice(&trampoline.to_le_bytes());
        code[self.pool + 8..self.pool + 16].copy_from_slice(&table.to_le_bytes());
    }
}
