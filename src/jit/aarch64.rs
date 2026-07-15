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
//! eBPF r0..r9 live in `x19..x28`, which are **callee-saved**. That is the
//! whole point: the trampoline call preserves them, so a deferred instruction
//! only has to spill the registers the interpreter *reads* and reload the ones
//! it *writes* (see [`DeferredRegs`]). Mapping them to caller-saved registers
//! instead would force all 11 to be spilled and reloaded on every deferred
//! instruction, which is exactly the trampoline tax this mapping avoids.
//!
//! AAPCS64 offers ten callee-saved registers (`x19..x28`) and eBPF has eleven
//! registers, so one has to live somewhere else. That one is **r10**, the
//! frame pointer: it is read-only in eBPF (the verifier rejects writes, and
//! `classify::lower` defers any that slip through), and the interpreter
//! already rewrites `regs[10]` on every call/exit. So r10 is simply left in
//! the in-memory register file, which is always authoritative for it, and
//! loaded on demand in the rare native instruction that reads it.
//!
//! | purpose            | register  | notes                                 |
//! |--------------------|-----------|---------------------------------------|
//! | eBPF r0..r9        | x19..x28  | callee-saved: survive the trampoline  |
//! | eBPF r10           | `regs[10]`| memory-backed, read-only              |
//! | `regs_ptr`         | `[sp,#96]`| stack slot (frees a callee-saved reg) |
//! | `machine_ptr`      | `[sp,#104]`|                                      |
//! | regs_ptr scratch   | x9        | reloaded after each call (caller-saved)|
//! | trampoline return  | x11       | next pc / STOP                        |
//! | table base/target  | x12       |                                       |
//! | r10 materialization| x14       | left operand of a compare             |
//! | immediates / rhs   | x15       |                                       |
//! | call target        | x16       | IP0, conventional intra-call scratch  |
//!
//! `W`-register forms give eBPF's 32-bit zero-extension semantics for free.
//! Absolute pointers (trampoline, pc→address table) live in an 8-byte-aligned
//! literal pool after the epilogue, loaded with `LDR (literal)` and written by
//! `patch_absolutes` once the code has its final address.

use super::{
    AluOp, Cc, DeferredRegs, JitBackend, LoadHint, RegMask, RegOrImm, ShiftOp, Target, Width,
};
use crate::insn::Insn;
use crate::insn::REG_FP;

/// eBPF register index → physical register. Only valid for r0..r9; r10 is
/// memory-backed (see [`Aarch64Backend::read_reg`]).
#[inline]
fn hreg(ebpf: u8) -> u32 {
    debug_assert!(ebpf < REG_FP, "r10 has no physical register");
    19 + ebpf as u32
}

/// eBPF registers that have a physical register (r0..r9).
const IN_REGS: RegMask = 0x3FF;

const TMP: u32 = 9; // regs_ptr scratch (caller-saved: reloaded after calls)
const RET_SAVE: u32 = 11; // trampoline return (next pc / STOP)
const TBL: u32 = 12; // table base, then jump target
const DSTV: u32 = 14; // r10 materialized as a compare's left operand
const IMM: u32 = 15; // immediates / materialized rhs
const CALL_TGT: u32 = 16; // x16 (IP0)
const FP: u32 = 29;
const LR: u32 = 30;
const SP: u32 = 31; // also XZR in register-operand positions
const ZR: u32 = 31;

/// Frame layout: 16-byte frame record, x19..x28 (5 pairs), then the two
/// incoming pointers. 112 bytes keeps sp 16-byte aligned for the call.
const FRAME: u32 = 112;
/// Stack slots, in 8-byte units from sp.
const REGS_SLOT: u32 = 12; // [sp, #96]  — regs_ptr
const MACH_SLOT: u32 = 13; // [sp, #104] — machine_ptr

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

    /// Add/sub (shifted register): `rd = rn op rm`. `base` selects ADD
    /// (0x0B..), SUB (0x4B..) or SUBS (0x6B..).
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

    /// `STR xt, [xn, #8*slot]` / `LDR xt, [xn, #8*slot]` (unsigned offset).
    fn str_off(&mut self, xt: u32, xn: u32, slot: u32) {
        self.w(0xF900_0000 | (slot << 10) | (xn << 5) | xt);
    }
    fn ldr_off(&mut self, xt: u32, xn: u32, slot: u32) {
        self.w(0xF940_0000 | (slot << 10) | (xn << 5) | xt);
    }

    /// Load `regs_ptr` from its stack slot into [`TMP`]. Needed again after
    /// every call: x9 is caller-saved.
    fn load_regs_ptr(&mut self) {
        self.ldr_off(TMP, SP, REGS_SLOT);
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

    /// The physical register holding eBPF register `ebpf`, materializing r10
    /// from the register file into `scratch` when needed.
    fn read_reg(&mut self, ebpf: u8, scratch: u32) -> u32 {
        if ebpf < REG_FP {
            return hreg(ebpf);
        }
        self.load_regs_ptr();
        self.ldr_off(scratch, TMP, REG_FP as u32);
        scratch
    }

    /// Materialize a sign-extended i32 rhs into [`IMM`]. W-form consumers read
    /// only the low 32 bits, which equal the raw immediate bits, so one
    /// materialization serves both widths.
    fn imm_to_scratch(&mut self, imm: i32) -> u32 {
        self.mov_u64(IMM, imm as i64 as u64);
        IMM
    }

    fn rhs_reg(&mut self, rhs: RegOrImm) -> u32 {
        match rhs {
            RegOrImm::Reg(s) => self.read_reg(s, IMM),
            RegOrImm::Imm(v) => self.imm_to_scratch(v),
        }
    }

    /// `CMP dst, rhs` (`SUBS zr, dst, rhs`) for a following B.cond. `dst` is
    /// read-only here, so it may legitimately be r10.
    fn emit_cmp(&mut self, w: Width, dst: u8, rhs: RegOrImm) {
        let a = self.read_reg(dst, DSTV);
        let rm = self.rhs_reg(rhs);
        self.addsub_rrr(0x6B00_0000, w, ZR, a, rm);
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
        self.fixups.push(Fix {
            at: self.buf.len(),
            form,
            target,
        });
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
        // stp x29, x30, [sp, #-112]!   (imm7 = -112/8 = -14)
        self.w(0xA980_0000 | ((-14i32 as u32 & 0x7F) << 15) | (LR << 10) | (SP << 5) | FP);
        // stp x19..x28, [sp, #16..#80]
        for (i, pair) in [(19, 20), (21, 22), (23, 24), (25, 26), (27, 28)]
            .iter()
            .enumerate()
        {
            let off = 2 + 2 * i as u32; // in 8-byte units
            self.w(0xA900_0000 | (off << 15) | (pair.1 << 10) | (SP << 5) | pair.0);
        }
        // mov x29, sp   (ADD x29, sp, #0)
        self.w(0x9100_0000 | (SP << 5) | FP);
        // stash the incoming pointers: regs_ptr (x0), machine_ptr (x1)
        self.str_off(0, SP, REGS_SLOT);
        self.str_off(1, SP, MACH_SLOT);
        // load eBPF r0..r9 from the register file (r10 stays in memory)
        for i in 0..10u32 {
            self.ldr_off(19 + i, 0, i);
        }
        // fall through into pc 0
    }

    fn epilogue(&mut self) {
        self.epilogue = self.buf.len();
        // ldp x19..x28
        for (i, pair) in [(19, 20), (21, 22), (23, 24), (25, 26), (27, 28)]
            .iter()
            .enumerate()
        {
            let off = 2 + 2 * i as u32;
            self.w(0xA940_0000 | (off << 15) | (pair.1 << 10) | (SP << 5) | pair.0);
        }
        // ldp x29, x30, [sp], #112   (post-index, imm7 = 14)
        self.w(0xA8C0_0000 | (14 << 15) | (LR << 10) | (SP << 5) | FP);
        self.w(0xD65F_03C0); // ret
                             // 8-byte-aligned literal pool: [trampoline u64][table u64]
        if !self.buf.len().is_multiple_of(8) {
            self.w(NOP);
        }
        self.pool = self.buf.len();
        self.buf.extend_from_slice(&[0u8; 16]);
    }

    fn alu_reg(&mut self, op: AluOp, w: Width, dst: u8, src: u8) {
        let s = self.read_reg(src, IMM);
        let d = hreg(dst);
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
            AluOp::Mul => self.w(0x1B00_7C00 | Self::sf(w) | (s << 16) | (d << 5) | d),
        }
    }

    fn mov_reg(&mut self, w: Width, dst: u8, src: u8) {
        let s = self.read_reg(src, IMM);
        let d = hreg(dst);
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
        let a = self.read_reg(dst, DSTV);
        let rm = self.rhs_reg(rhs);
        self.logic_rrr(0x6A00_0000, w, ZR, a, rm);
        self.bcond(cond::NE, target);
    }

    fn exit(&mut self) {
        self.load_regs_ptr();
        self.str_off(19, TMP, 0);
        self.jump(Target::Epilogue);
    }

    fn verified_load(&mut self, pc: usize, ins: Insn, _hint: LoadHint) {
        self.deferred(
            pc,
            DeferredRegs {
                spill: 1 << ins.src,
                reload: 1 << ins.dst,
                falls_through: true,
            },
        );
    }

    fn deferred(&mut self, pc: usize, regs: DeferredRegs) {
        // r0..r9 are callee-saved, so only what the interpreter actually reads
        // has to reach the register file. r10 needs nothing: it has no
        // physical copy, and `regs[10]` is always authoritative.
        let spill = regs.spill & IN_REGS;
        let reload = regs.reload & IN_REGS;

        if spill != 0 {
            self.load_regs_ptr();
            for i in 0..10u32 {
                if spill & (1 << i) != 0 {
                    self.str_off(19 + i, TMP, i);
                }
            }
        }
        // arg0 = machine_ptr, arg1 = pc
        self.ldr_off(0, SP, MACH_SLOT);
        self.mov_u64(1, pc as u64);
        // Call the trampoline through the literal pool.
        self.ldr_lit(CALL_TGT, FixTarget::PoolTrampoline);
        self.w(0xD63F_0000 | (CALL_TGT << 5)); // blr x16
                                               // Save next-pc/STOP before touching x0.
        self.mov_rr(Width::W64, RET_SAVE, 0);
        if reload != 0 {
            self.load_regs_ptr(); // x9 was caller-saved: reload it
            for i in 0..10u32 {
                if reload & (1 << i) != 0 {
                    self.ldr_off(19 + i, TMP, i);
                }
            }
        }
        // STOP has bit 63 set: TST sets N, B.MI exits via the epilogue.
        self.logic_rrr(0x6A00_0000, Width::W64, ZR, RET_SAVE, RET_SAVE);
        self.bcond(cond::MI, Target::Epilogue);
        if regs.falls_through {
            // The interpreter can only have landed on the next instruction,
            // whose code the frontend emits right here — no table lookup and
            // no indirect branch.
            return;
        }
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

// The frame size is baked into the prologue/epilogue immediates above; keep
// the constant honest if anyone changes the layout.
const _: () = assert!(FRAME == 112 && REGS_SLOT * 8 == 96 && MACH_SLOT * 8 == 104);
