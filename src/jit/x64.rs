//! x86-64 (System V, Linux) backend for the JIT.
//!
//! This file is a pure instruction encoder — it contains no eBPF semantics.
//! To port febpf's JIT to another architecture, implement [`JitBackend`] the
//! same way for that ISA; see `docs/specs/jit-backend.md`.
//!
//! ## Register mapping (eBPF → x86-64)
//!
//! | eBPF | x86-64 | notes                    |
//! |------|--------|--------------------------|
//! | r0   | rax    | also idiv output (unused, div is deferred) |
//! | r1   | rdi    | arg0                     |
//! | r2   | rsi    | arg1                     |
//! | r3   | rdx    |                          |
//! | r4   | rcx    | shift count reg (var shifts deferred) |
//! | r5   | r8     |                          |
//! | r6   | rbx    | callee-saved             |
//! | r7   | r13    | callee-saved             |
//! | r8   | r14    | callee-saved             |
//! | r9   | r15    | callee-saved             |
//! | r10  | r12    | callee-saved, frame ptr (never dereferenced natively) |
//!
//! Scratch: `r9`, `r11`. Stack slots hold `regs_ptr` and `machine_ptr`.

use super::{AluOp, Cc, JitBackend, RegOrImm, ShiftOp, Target, Width};

// x86-64 register numbers.
const RAX: u8 = 0;
const RCX: u8 = 1;
const RDX: u8 = 2;
#[allow(dead_code)]
const RBX: u8 = 3;
const RSP: u8 = 4; // documented; RSP is implicit in stack-slot encodings
const RSI: u8 = 6;
const RDI: u8 = 7;
const R11: u8 = 11;

/// eBPF register index → x86-64 register number.
const MAP: [u8; 11] = [
    RAX, // r0
    RDI, // r1
    RSI, // r2
    RDX, // r3
    RCX, // r4
    8,   // r5  -> r8
    3,   // r6  -> rbx
    13,  // r7  -> r13
    14,  // r8  -> r14
    15,  // r9  -> r15
    12,  // r10 -> r12
];

/// Callee-saved registers we clobber, saved in the prologue (push order).
/// Five pushes: at entry `rsp ≡ 8 (mod 16)`, so after 5 pushes `rsp ≡ 0`, and
/// `sub rsp, 32` keeps it 16-byte aligned for `call`. (RBP is untouched, so
/// it need not be saved — and saving it would misalign the stack.)
const SAVED: [u8; 5] = [RBX_SAVE, 12, 13, 14, 15];
const RBX_SAVE: u8 = 3;

#[inline]
fn hreg(ebpf: u8) -> u8 {
    MAP[ebpf as usize]
}

enum FixKind {
    Pc(usize),
    Epilogue,
}

struct Fix {
    /// Offset of the rel32 field.
    at: usize,
    kind: FixKind,
}

enum AbsKind {
    Trampoline,
    Table,
}

struct Abs {
    /// Offset of the imm64 field.
    at: usize,
    kind: AbsKind,
}

pub struct X64Backend {
    buf: Vec<u8>,
    fixups: Vec<Fix>,
    absolutes: Vec<Abs>,
    epilogue: usize,
}

impl X64Backend {
    fn b(&mut self, byte: u8) {
        self.buf.push(byte);
    }
    fn bytes(&mut self, s: &[u8]) {
        self.buf.extend_from_slice(s);
    }
    fn imm32(&mut self, v: i32) {
        self.bytes(&v.to_le_bytes());
    }

    /// REX prefix; emitted only when needed (any of W / extended regs).
    fn rex(&mut self, w: bool, reg: u8, rm: u8) {
        let r = (reg >> 3) & 1;
        let b = (rm >> 3) & 1;
        if w || r == 1 || b == 1 {
            self.b(0x40 | ((w as u8) << 3) | (r << 2) | b);
        }
    }
    fn modrm(&mut self, md: u8, reg: u8, rm: u8) {
        self.b((md << 6) | ((reg & 7) << 3) | (rm & 7));
    }

    /// `op r/m, r` form (opcode operates with reg = src, rm = dst).
    fn emit_rr(&mut self, opcode: u8, w: bool, dst_rm: u8, src_reg: u8) {
        self.rex(w, src_reg, dst_rm);
        self.b(opcode);
        self.modrm(0b11, src_reg, dst_rm);
    }

    /// `op r/m, imm32` form with ModRM.reg = `ext` (opcode extension).
    fn emit_ri(&mut self, opcode: u8, ext: u8, w: bool, dst_rm: u8, imm: i32) {
        self.rex(w, 0, dst_rm);
        self.b(opcode);
        self.modrm(0b11, ext, dst_rm);
        self.imm32(imm);
    }

    fn width_w(w: Width) -> bool {
        w == Width::W64
    }

    /// Load `regs_ptr` (stack slot 0) into r11.
    fn load_regs_ptr_r11(&mut self) {
        // mov r11, [rsp+0]
        self.bytes(&[0x4C, 0x8B, 0x1C, 0x24]);
    }

    fn spill_all(&mut self) {
        self.load_regs_ptr_r11();
        for (i, &h) in MAP.iter().enumerate() {
            // mov [r11 + 8*i], h   (89 /r, mod=01 disp8)
            self.rex(true, h, R11);
            self.b(0x89);
            self.modrm(0b01, h, R11);
            self.b((8 * i) as u8);
        }
    }

    fn reload_all(&mut self) {
        self.load_regs_ptr_r11();
        for (i, &h) in MAP.iter().enumerate() {
            // mov h, [r11 + 8*i]   (8B /r, mod=01 disp8)
            self.rex(true, h, R11);
            self.b(0x8B);
            self.modrm(0b01, h, R11);
            self.b((8 * i) as u8);
        }
    }

    fn jcc(&mut self, cc: u8, target: Target) {
        self.b(0x0F);
        self.b(0x80 | cc);
        let at = self.buf.len();
        self.imm32(0);
        self.record_fix(at, target);
    }

    fn record_fix(&mut self, at: usize, target: Target) {
        let kind = match target {
            Target::Pc(pc) => FixKind::Pc(pc),
            Target::Epilogue => FixKind::Epilogue,
        };
        self.fixups.push(Fix { at, kind });
    }

    /// Emit `cmp dst, rhs` (64/32-bit) so a following jcc reads its flags.
    fn emit_cmp(&mut self, w: Width, dst: u8, rhs: RegOrImm) {
        let wb = Self::width_w(w);
        let d = hreg(dst);
        match rhs {
            RegOrImm::Reg(s) => self.emit_rr(0x39, wb, d, hreg(s)), // cmp r/m, r
            RegOrImm::Imm(v) => self.emit_ri(0x81, 7, wb, d, v),    // cmp r/m, imm32 (/7)
        }
    }
}

/// eBPF condition → x86 condition-code nibble.
fn cc_code(cc: Cc) -> u8 {
    match cc {
        Cc::Eq => 0x4,
        Cc::Ne => 0x5,
        Cc::Gt => 0x7,  // A  (unsigned above)
        Cc::Ge => 0x3,  // AE
        Cc::Lt => 0x2,  // B  (unsigned below)
        Cc::Le => 0x6,  // BE
        Cc::Sgt => 0xF, // G
        Cc::Sge => 0xD, // GE
        Cc::Slt => 0xC, // L
        Cc::Sle => 0xE, // LE
    }
}

impl JitBackend for X64Backend {
    fn new(num_insns: usize) -> Self {
        X64Backend {
            buf: Vec::with_capacity(num_insns * 16 + 128),
            fixups: Vec::new(),
            absolutes: Vec::new(),
            epilogue: 0,
        }
    }

    fn code(&self) -> &[u8] {
        &self.buf
    }

    fn mark_label(&mut self, _pc: usize) {}

    fn prologue(&mut self) {
        // push callee-saved
        for &r in &SAVED {
            if r >= 8 {
                self.b(0x41);
            }
            self.b(0x50 | (r & 7)); // push
        }
        // sub rsp, 32   (keep 16-byte alignment; slots for regs_ptr/machine_ptr)
        self.bytes(&[0x48, 0x83, 0xEC, 0x20]);
        // mov [rsp+0], rdi   (regs_ptr)
        self.bytes(&[0x48, 0x89, 0x7C, 0x24, 0x00]);
        // mov [rsp+8], rsi   (machine_ptr)
        self.bytes(&[0x48, 0x89, 0x74, 0x24, 0x08]);
        // load eBPF register file from regs_ptr into physical registers
        self.reload_all();
        // fall through into pc 0
    }

    fn epilogue(&mut self) {
        self.epilogue = self.buf.len();
        // add rsp, 32
        self.bytes(&[0x48, 0x83, 0xC4, 0x20]);
        // pop callee-saved (reverse order)
        for &r in SAVED.iter().rev() {
            if r >= 8 {
                self.b(0x41);
            }
            self.b(0x58 | (r & 7)); // pop
        }
        self.b(0xC3); // ret
    }

    fn alu_reg(&mut self, op: AluOp, w: Width, dst: u8, src: u8) {
        let wb = Self::width_w(w);
        let (d, s) = (hreg(dst), hreg(src));
        match op {
            AluOp::Add => self.emit_rr(0x01, wb, d, s),
            AluOp::Sub => self.emit_rr(0x29, wb, d, s),
            AluOp::Or => self.emit_rr(0x09, wb, d, s),
            AluOp::And => self.emit_rr(0x21, wb, d, s),
            AluOp::Xor => self.emit_rr(0x31, wb, d, s),
            AluOp::Mul => {
                // imul d, s   (0F AF /r; reg = dst, rm = src)
                self.rex(wb, d, s);
                self.b(0x0F);
                self.b(0xAF);
                self.modrm(0b11, d, s);
            }
        }
    }

    fn alu_imm(&mut self, op: AluOp, w: Width, dst: u8, imm: i32) {
        let wb = Self::width_w(w);
        let d = hreg(dst);
        match op {
            AluOp::Add => self.emit_ri(0x81, 0, wb, d, imm),
            AluOp::Or => self.emit_ri(0x81, 1, wb, d, imm),
            AluOp::And => self.emit_ri(0x81, 4, wb, d, imm),
            AluOp::Sub => self.emit_ri(0x81, 5, wb, d, imm),
            AluOp::Xor => self.emit_ri(0x81, 6, wb, d, imm),
            AluOp::Mul => {
                // imul d, d, imm32   (69 /r id)
                self.rex(wb, d, d);
                self.b(0x69);
                self.modrm(0b11, d, d);
                self.imm32(imm);
            }
        }
    }

    fn mov_reg(&mut self, w: Width, dst: u8, src: u8) {
        let d = hreg(dst);
        let s = hreg(src);
        if d == s && w == Width::W64 {
            return; // no-op
        }
        self.emit_rr(0x89, Self::width_w(w), d, s); // mov r/m, r
    }

    fn mov_imm(&mut self, w: Width, dst: u8, imm: i32) {
        let d = hreg(dst);
        match w {
            Width::W64 => self.emit_ri(0xC7, 0, true, d, imm), // sign-extends imm32→64
            Width::W32 => {
                // mov r32, imm32 (zero-extends): B8+rd id
                if d >= 8 {
                    self.b(0x41);
                }
                self.b(0xB8 | (d & 7));
                self.imm32(imm);
            }
        }
    }

    fn neg(&mut self, w: Width, dst: u8) {
        let d = hreg(dst);
        self.rex(Self::width_w(w), 0, d);
        self.b(0xF7);
        self.modrm(0b11, 3, d); // /3 = neg
    }

    fn shift_imm(&mut self, op: ShiftOp, w: Width, dst: u8, amount: u8) {
        let d = hreg(dst);
        let ext = match op {
            ShiftOp::Lsh => 4,  // shl
            ShiftOp::Rsh => 5,  // shr
            ShiftOp::Arsh => 7, // sar
        };
        self.rex(Self::width_w(w), 0, d);
        self.b(0xC1);
        self.modrm(0b11, ext, d);
        self.b(amount);
    }

    fn jump(&mut self, target: Target) {
        self.b(0xE9);
        let at = self.buf.len();
        self.imm32(0);
        self.record_fix(at, target);
    }

    fn cond_branch(&mut self, cc: Cc, w: Width, dst: u8, rhs: RegOrImm, target: Target) {
        self.emit_cmp(w, dst, rhs);
        self.jcc(cc_code(cc), target);
    }

    fn jset_branch(&mut self, w: Width, dst: u8, rhs: RegOrImm, target: Target) {
        let wb = Self::width_w(w);
        let d = hreg(dst);
        match rhs {
            RegOrImm::Reg(s) => self.emit_rr(0x85, wb, d, hreg(s)), // test r/m, r
            RegOrImm::Imm(v) => self.emit_ri(0xF7, 0, wb, d, v),    // test r/m, imm32 (/0)
        }
        self.jcc(0x5, target); // jnz — taken when (dst & rhs) != 0
    }

    fn deferred(&mut self, pc: usize) {
        // Spill eBPF registers to the register file.
        self.spill_all();
        // mov rdi, [rsp+8]   (machine_ptr = arg0)
        self.bytes(&[0x48, 0x8B, 0x7C, 0x24, 0x08]);
        // mov rsi, imm32(pc) (arg1)
        self.rex(true, 0, RSI);
        self.b(0xC7);
        self.modrm(0b11, 0, RSI);
        self.imm32(pc as i32);
        // movabs rax, trampoline; call rax
        self.rex(true, 0, RAX);
        self.b(0xB8 | (RAX & 7));
        let abs_at = self.buf.len();
        self.bytes(&[0; 8]);
        self.absolutes.push(Abs {
            at: abs_at,
            kind: AbsKind::Trampoline,
        });
        self.bytes(&[0xFF, 0xD0]); // call rax
        // save trampoline return in r9 (r9 is not eBPF-mapped): mov r9, rax
        self.bytes(&[0x49, 0x89, 0xC1]);
        // reload eBPF registers (r9 is untouched — not an eBPF-mapped reg)
        self.reload_all();
        // test r9, r9 ; js epilogue   (STOP has the high bit set)
        self.bytes(&[0x4D, 0x85, 0xC9]);
        self.b(0x0F);
        self.b(0x88); // js
        let at = self.buf.len();
        self.imm32(0);
        self.record_fix(at, Target::Epilogue);
        // movabs r11, table_base
        self.b(0x49);
        self.b(0xBB); // movabs r11
        let tbl_at = self.buf.len();
        self.bytes(&[0; 8]);
        self.absolutes.push(Abs {
            at: tbl_at,
            kind: AbsKind::Table,
        });
        // jmp [r11 + r9*8]
        self.bytes(&[0x43, 0xFF, 0x24, 0xCB]);
    }

    fn resolve_branches(&mut self, label_off: &[usize], epilogue_off: usize) -> Result<(), String> {
        for f in &self.fixups {
            let target_off = match f.kind {
                FixKind::Epilogue => epilogue_off,
                FixKind::Pc(pc) => {
                    let o = label_off.get(pc).copied().unwrap_or(usize::MAX);
                    if o == usize::MAX {
                        epilogue_off
                    } else {
                        o
                    }
                }
            };
            let site_end = f.at + 4;
            let rel = target_off as i64 - site_end as i64;
            let rel = rel as i32;
            self.buf[f.at..f.at + 4].copy_from_slice(&rel.to_le_bytes());
        }
        Ok(()) // rel32 spans ±2GiB: always in range for any emittable program
    }

    fn epilogue_off(&self) -> usize {
        self.epilogue
    }

    fn patch_absolutes(&self, code: &mut [u8], trampoline: u64, table: u64) {
        for a in &self.absolutes {
            let v = match a.kind {
                AbsKind::Trampoline => trampoline,
                AbsKind::Table => table,
            };
            code[a.at..a.at + 8].copy_from_slice(&v.to_le_bytes());
        }
    }
}

// Silence unused-const warnings for register names kept for documentation.
const _: (u8, u8) = (RSP, RCX);
