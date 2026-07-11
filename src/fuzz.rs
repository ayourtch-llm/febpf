//! Differential-fuzzer support: a seeded PRNG and a conservative random
//! program generator, plus a helper to run one program under the interpreter
//! and the JIT and compare `r0`.
//!
//! The generator is deliberately narrow: it emits only programs that **both**
//! febpf's verifier and the kernel's verifier accept, so any `r0` disagreement
//! between engines is a genuine bug rather than an artefact of an ill-formed
//! program. See `docs/specs/conftest.md` §4 for the strategy and the list of
//! divergence traps it avoids (div/mod, uninitialized registers, loops,
//! pointer arithmetic).

use crate::insn::*;

/// SplitMix64: a tiny, fast, fully deterministic PRNG. Seeded runs replay
/// bit-for-bit, which is what makes a fuzzer finding reproducible.
#[derive(Clone)]
pub struct Prng(u64);

impl Prng {
    pub fn new(seed: u64) -> Prng {
        Prng(seed)
    }
    pub fn next_u64(&mut self) -> u64 {
        // SplitMix64 (Steele et al.). Constants are the reference values.
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    pub fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    /// Uniform in `0..n` (n > 0).
    pub fn below(&mut self, n: u32) -> u32 {
        self.next_u32() % n
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len() as u32) as usize]
    }
}

/// A random 64-bit-safe seed for when the user didn't supply one.
pub fn random_seed() -> u64 {
    // Zero-dependency entropy: mix the wall clock with a stack address.
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x1234_5678);
    let x = 0u8;
    let addr = &x as *const u8 as u64;
    let mut p = Prng::new(t ^ addr.rotate_left(17));
    p.next_u64()
}

// Instruction-construction helpers (single-slot; no lddw is generated).
fn alu64(op: u8) -> u8 {
    class::ALU64 | op
}
fn alu32(op: u8) -> u8 {
    class::ALU | op
}
fn ins(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    Insn { opcode, dst, src, off, imm }
}

const ALU_OPS: &[u8] = &[
    alu::ADD, alu::SUB, alu::MUL, alu::OR, alu::AND, alu::XOR, alu::MOV,
];
const SHIFT_OPS: &[u8] = &[alu::LSH, alu::RSH, alu::ARSH];
const JMP_OPS: &[u8] = &[
    jmp::JEQ, jmp::JNE, jmp::JGT, jmp::JGE, jmp::JLT, jmp::JLE, jmp::JSGT,
    jmp::JSGE, jmp::JSLT, jmp::JSLE, jmp::JSET,
];

/// Generate one conservative, loop-free, memory-free program.
///
/// Layout: 10 `mov64 rX, imm` initializers (registers `r0..=r9`), then a body
/// of random ALU ops and forward-only conditional branches, then `exit`
/// (returning `r0`). `r1` is intentionally overwritten by an initializer so no
/// register holds a pointer during the body — pointer verification is thereby
/// sidestepped entirely on both engines.
pub fn gen_program(rng: &mut Prng) -> Vec<Insn> {
    let mut p: Vec<Insn> = Vec::new();

    // (1) Initialize r0..=r9 with random constants.
    for r in 0..10u8 {
        p.push(ins(0xb7 /* mov64 imm */, r, 0, 0, rng.next_u32() as i32));
    }

    // (2) Body. Choose a length; leave the last slot for `exit`.
    let body_len = 6 + rng.below(24) as usize; // 6..=29
    let exit_index = p.len() + body_len; // absolute index of the exit slot

    for _ in 0..body_len {
        let here = p.len();
        // Largest forward offset that still lands within the program (at worst
        // on `exit` at exit_index). Zero when `here` is the slot right before
        // `exit`, in which case no forward branch is possible.
        let maxoff = (exit_index - (here + 1)).min(6);
        // ~30% branches, ~70% ALU (branch only when there's somewhere to go).
        if maxoff >= 1 && rng.below(10) < 3 {
            // Forward-only conditional branch; target in `here+2 ..= exit_index`.
            let off = 1 + rng.below(maxoff as u32) as i16;
            let is32 = rng.below(2) == 1;
            let cls = if is32 { class::JMP32 } else { class::JMP };
            let op = *rng.pick(JMP_OPS);
            let dst = rng.below(10) as u8;
            if rng.below(2) == 0 {
                let s = rng.below(10) as u8;
                p.push(ins(cls | op | src::X, dst, s, off, 0));
            } else {
                p.push(ins(cls | op, dst, 0, off, rng.next_u32() as i32));
            }
        } else {
            let dst = rng.below(10) as u8;
            let is32 = rng.below(2) == 1;
            let kind = rng.below(10);
            if kind == 0 {
                // neg
                let op = if is32 { alu32(alu::NEG) } else { alu64(alu::NEG) };
                p.push(ins(op, dst, 0, 0, 0));
            } else if kind <= 2 {
                // shift by an in-range immediate (all engines mask identically,
                // but keeping it in range is clearest).
                let sop = *rng.pick(SHIFT_OPS);
                let op = if is32 { alu32(sop) } else { alu64(sop) };
                let max = if is32 { 31 } else { 63 };
                let amt = rng.below(max + 1) as i32;
                p.push(ins(op, dst, 0, 0, amt));
            } else {
                let aop = *rng.pick(ALU_OPS);
                let op = if is32 { alu32(aop) } else { alu64(aop) };
                if rng.below(2) == 0 {
                    let s = rng.below(10) as u8;
                    p.push(ins(op | src::X, dst, s, 0, 0));
                } else {
                    p.push(ins(op, dst, 0, 0, rng.next_u32() as i32));
                }
            }
        }
    }

    // (3) exit
    p.push(ins(0x95 /* exit */, 0, 0, 0, 0));
    debug_assert_eq!(p.len(), exit_index + 1);
    p
}

/// Run `insns` (no maps) under the interpreter and the JIT with a fresh 16-byte
/// zero context, returning `(interp_r0, jit_r0)`. Errors from either engine are
/// surfaced as `Err`.
pub fn interp_vs_jit(insns: &[Insn]) -> Result<(u64, u64), String> {
    let prog = crate::Program {
        insns: insns.to_vec(),
        maps: Vec::new(),
    };
    let mut ctx_i = vec![0u8; 16];
    let mut vm_i = crate::Vm::new(prog.clone())?;
    let r_interp = vm_i.run(&mut ctx_i).map_err(|e| e.to_string())?;

    let mut ctx_j = vec![0u8; 16];
    let mut vm_j = crate::Vm::new(prog)?;
    let r_jit = vm_j.run_jit(&mut ctx_j).map_err(|e| e.to_string())?;
    Ok((r_interp, r_jit))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The core invariant: over many seeds, the interpreter and the JIT agree
    /// on `r0` for every generated program. This is the differential test that
    /// makes the fuzzer meaningful.
    #[test]
    fn interp_and_jit_agree() {
        // Only meaningful where the JIT exists; elsewhere run_jit errors and
        // we simply skip (the interpreter is validated by other tests).
        if crate::jit::compile(&[Insn { opcode: 0x95, dst: 0, src: 0, off: 0, imm: 0 }]).is_err() {
            return;
        }
        for seed in 0..2000u64 {
            let mut rng = Prng::new(seed);
            let prog = gen_program(&mut rng);
            match interp_vs_jit(&prog) {
                Ok((i, j)) => assert_eq!(
                    i, j,
                    "interp/JIT mismatch on seed {seed}:\n{}",
                    crate::disasm::disasm_program(&prog)
                ),
                Err(e) => panic!("seed {seed}: engine error: {e}\n{}", crate::disasm::disasm_program(&prog)),
            }
        }
    }

    #[test]
    fn prng_is_deterministic() {
        let mut a = Prng::new(42);
        let mut b = Prng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }
}
