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
use crate::maps::MapDef;
use crate::verifier::Config;

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

// ---- frontier generator (see docs/specs/verifier-diff.md §2) --------------
//
// Where `gen_program` deliberately stays inside the region both verifiers
// accept, `gen_frontier_program` steers *toward the edge of legality*: ctx
// pointer arithmetic, bounded/unbounded memory access, uninitialized reads,
// stack access at various offsets, backward branches, and helper calls. The
// goal is to provoke verdict disagreements, so it emits a mix that both
// verifiers reason about — roughly half accepted, half rejected — while
// staying seeded and deterministic.

// Memory opcodes (class | mode::MEM | size).
fn ldx(sz: u8) -> u8 {
    class::LDX | mode::MEM | sz
}
fn stx(sz: u8) -> u8 {
    class::STX | mode::MEM | sz
}

/// No-argument, scalar-returning helpers legal for SOCKET_FILTER that *both*
/// verifiers accept with no setup — used to produce accepted helper-call cases.
const SAFE_HELPERS: &[i32] = &[
    5, // ktime_get_ns
    7, // get_prandom_u32
    8, // get_smp_processor_id
];

/// Generate one program near the verification frontier. Deterministic in `rng`.
pub fn gen_frontier_program(rng: &mut Prng) -> Vec<Insn> {
    let mut p: Vec<Insn> = Vec::new();
    // Pick a focused "flavor" so each program probes one frontier construct and
    // its verdict is easy to triage. Weighted toward the memory/pointer cases.
    match rng.below(6) {
        0 => gen_ctx_ptr(rng, &mut p),
        1 => gen_stack(rng, &mut p),
        2 => gen_uninit(rng, &mut p),
        3 => gen_loop(rng, &mut p),
        4 => gen_helper(rng, &mut p),
        _ => gen_mixed(rng, &mut p),
    }
    // Always terminate with exit (flavors leave r0 defined, or the verifier
    // will reject the read of an undefined r0 — itself a valid frontier case).
    p.push(ins(0x95, 0, 0, 0, 0));
    p
}

/// Initialize r0..=r9 with constants (r1..r5 excluded when `keep_ctx`, so the
/// ctx pointer in r1 survives for pointer-arithmetic flavors).
fn init_regs(rng: &mut Prng, p: &mut Vec<Insn>, keep_ctx: bool) {
    for r in 0..10u8 {
        if keep_ctx && r == 1 {
            continue; // leave r1 = ctx pointer
        }
        p.push(ins(0xb7, r, 0, 0, rng.next_u32() as i32));
    }
}

/// ctx pointer arithmetic then a load. In bounds when the final offset stays in
/// `[0, ctx_size)`; out of bounds (→ reject) when it runs off either end.
fn gen_ctx_ptr(rng: &mut Prng, p: &mut Vec<Insn>) {
    init_regs(rng, p, true);
    // r2 = r1 (ctx); r2 += delta.
    p.push(ins(alu64(alu::MOV) | src::X, 2, 1, 0, 0));
    // Offset: mostly small in-bounds, sometimes far out.
    let off: i32 = match rng.below(4) {
        0 => -8,                              // before ctx start → reject
        1 => (VFUZZ_CTX_SIZE as i32) + 16,    // past ctx end → reject
        _ => (rng.below(64) as i32) * 4,      // small, in bounds → accept
    };
    p.push(ins(alu64(alu::ADD), 2, 0, 0, off));
    // r0 = *(u32 *)(r2 + 0)
    let sz = *rng.pick(&[size::B, size::H, size::W]);
    p.push(ins(ldx(sz), 0, 2, 0, 0));
}

/// Stack access through r10 at various offsets. Aligned in-range store+load is
/// accepted; out-of-range offsets or reading never-written stack is rejected.
fn gen_stack(rng: &mut Prng, p: &mut Vec<Insn>) {
    init_regs(rng, p, false);
    // Slot offset (negative from fp). In range: [-512, -8], 8-aligned.
    let k: i16 = match rng.below(4) {
        0 => -(8 + 8 * (rng.below(63) as i16)), // -8..-512 aligned → accept path
        1 => 8,                                 // positive (above fp) → reject
        2 => -520,                              // below stack → reject
        _ => -((rng.below(512) as i16) + 1),    // arbitrary, maybe misaligned
    };
    // Store r0 to the slot, then load it back into r0 (dw).
    p.push(ins(stx(size::DW), 10, 0, k, 0));
    p.push(ins(ldx(size::DW), 0, 10, k, 0));
}

/// Read a register that was never initialized → the kernel and febpf both
/// reject. Occasionally initialize it after all (accepted control case).
fn gen_uninit(rng: &mut Prng, p: &mut Vec<Insn>) {
    // Choose a victim register in r2..=r9.
    let victim = 2 + rng.below(8) as u8;
    for r in 0..10u8 {
        if r == victim && rng.below(3) != 0 {
            continue; // usually skip its init → uninitialized read below
        }
        p.push(ins(0xb7, r, 0, 0, rng.next_u32() as i32));
    }
    // r0 += victim  (reads victim; uninitialized ⇒ reject)
    p.push(ins(alu64(alu::ADD) | src::X, 0, victim, 0, 0));
}

/// A backward branch (loop). Bounded with a decrementing counter (may be
/// accepted), or unbounded (rejected). Termination/complexity is the frontier.
fn gen_loop(rng: &mut Prng, p: &mut Vec<Insn>) {
    init_regs(rng, p, false);
    let bounded = rng.below(2) == 0;
    // r6 = counter
    let n = 1 + rng.below(64) as i32;
    p.push(ins(0xb7, 6, 0, 0, if bounded { n } else { 0 }));
    let loop_top = p.len();
    // r0 += 1
    p.push(ins(alu64(alu::ADD), 0, 0, 0, 1));
    if bounded {
        // r6 -= 1 ; if r6 != 0 goto loop_top
        p.push(ins(alu64(alu::SUB), 6, 0, 0, 1));
        let back = loop_top as i32 - (p.len() as i32 + 1);
        p.push(ins(class::JMP | jmp::JNE, 6, 0, back as i16, 0));
    } else {
        // unconditional backward goto → infinite loop → reject
        let back = loop_top as i32 - (p.len() as i32 + 1);
        p.push(ins(class::JMP | jmp::JA, 0, 0, back as i16, 0));
    }
}

/// Helper call with varied argument setup. `SAFE_HELPERS` with no args are
/// accepted; a pointer-taking helper (map_lookup_elem, id 1) with no map set up
/// is rejected. After a call r1..r5 are clobbered; we only read r0.
fn gen_helper(rng: &mut Prng, p: &mut Vec<Insn>) {
    init_regs(rng, p, false);
    if rng.below(3) == 0 {
        // map_lookup_elem with bogus args and no map in the program → reject.
        p.push(ins(class::JMP | jmp::CALL, 0, call_kind::HELPER, 0, 1));
    } else {
        let hid = *rng.pick(SAFE_HELPERS);
        p.push(ins(class::JMP | jmp::CALL, 0, call_kind::HELPER, 0, hid));
        // r0 holds the return; optionally fold it so r0 is clearly defined.
        p.push(ins(alu64(alu::AND), 0, 0, 0, 0xffff));
    }
}

/// The conservative body with one memory op spliced in — a mostly-legal program
/// that occasionally strays. Keeps the corpus from being all extremes.
fn gen_mixed(rng: &mut Prng, p: &mut Vec<Insn>) {
    init_regs(rng, p, false);
    let body = 3 + rng.below(8) as usize;
    for _ in 0..body {
        let dst = rng.below(10) as u8;
        match rng.below(5) {
            0 => {
                // aligned in-range stack round-trip
                let k = -(8 + 8 * (rng.below(60) as i16));
                p.push(ins(stx(size::DW), 10, dst, k, 0));
                p.push(ins(ldx(size::DW), dst, 10, k, 0));
            }
            _ => {
                let aop = *rng.pick(ALU_OPS);
                p.push(ins(alu64(aop), dst, 0, 0, rng.next_u32() as i32));
            }
        }
    }
}

/// Helpers whose return value is *identical* in the interpreter and the JIT,
/// so a differential test can call them. `get_prandom_u32` is a fixed-seed
/// xorshift (each `Vm` starts from the same seed), `get_smp_processor_id` is a
/// constant, and `ktime_get_boot_ns` is a snapshotted logical clock.
/// `ktime_get_ns` is deliberately absent: it reads the wall clock, and the
/// two engines would disagree.
const DETERMINISTIC_HELPERS: &[i32] = &[
    7, // get_prandom_u32
    8, // get_smp_processor_id
    125, // ktime_get_boot_ns (snapshotted logical clock)
];

/// Generate a **memory-heavy** program: stack loads/stores at every width,
/// atomics (including `cmpxchg`, which reads and writes r0 implicitly),
/// helper calls, deferred ALU (div/mod/byte-swap/sign-extend/register shifts)
/// and native reads of r10 — interleaved with native ALU.
///
/// This exists to exercise the JIT's *deferred* path, which [`gen_program`]
/// never touches: it is memory-free by construction, so it cannot catch a
/// wrong spill/reload mask (see `DeferredRegs`). Every access is an aligned,
/// in-bounds stack slot so both engines run clean to `exit` — a program that
/// faults would prove nothing about codegen.
pub fn gen_mem_program(rng: &mut Prng) -> Vec<Insn> {
    let mut p: Vec<Insn> = Vec::new();
    for r in 0..10u8 {
        p.push(ins(0xb7 /* mov64 imm */, r, 0, 0, rng.next_u32() as i32));
    }

    // Aligned, in-bounds stack slot: r10-8 .. r10-512.
    let slot = |rng: &mut Prng| -(8 + 8 * (rng.below(63) as i16));
    const SIZES: &[u8] = &[size::B, size::H, size::W, size::DW];
    const ATOMIC_OPS: &[i32] = &[
        atomic::ADD,
        atomic::OR,
        atomic::AND,
        atomic::XOR,
        atomic::ADD | atomic::FETCH,
        atomic::OR | atomic::FETCH,
        atomic::XCHG,
        atomic::CMPXCHG,
    ];

    let body = 8 + rng.below(20) as usize;
    for _ in 0..body {
        // Registers 1..=9: leave r0 free to be clobbered by helpers/cmpxchg.
        let d = 1 + rng.below(9) as u8;
        let s = 1 + rng.below(9) as u8;
        let k = slot(rng);
        match rng.below(9) {
            // store a register, then read it back at the same width
            0 => {
                let sz = *rng.pick(SIZES);
                p.push(ins(stx(sz), 10, s, k, 0));
                p.push(ins(ldx(sz), d, 10, k, 0));
            }
            // store an immediate, load it back
            1 => {
                let sz = *rng.pick(SIZES);
                p.push(ins(class::ST | mode::MEM | sz, 10, 0, k, rng.next_u32() as i32));
                p.push(ins(ldx(sz), d, 10, k, 0));
            }
            // sign-extending load (deferred; reads src, writes dst)
            2 => {
                let sz = *rng.pick(&[size::B, size::H, size::W]);
                p.push(ins(stx(size::DW), 10, s, k, 0));
                p.push(ins(class::LDX | mode::MEMSX | sz, d, 10, k, 0));
            }
            // atomic RMW on an 8-byte slot (cmpxchg touches r0 implicitly)
            3 => {
                let op = *rng.pick(ATOMIC_OPS);
                let sz = if rng.below(2) == 0 { size::DW } else { size::W };
                p.push(ins(stx(size::DW), 10, s, k, 0));
                p.push(ins(class::STX | mode::ATOMIC | sz, 10, s, k, op));
            }
            // copy the frame pointer and store through it: the one native
            // instruction that *reads* r10, which aarch64 keeps in memory
            4 => {
                p.push(ins(0xbf /* mov64 reg */, d, 10, 0, 0)); // rd = r10
                p.push(ins(alu64(alu::ADD), d, 0, 0, k as i32)); // rd += k
                p.push(ins(stx(size::DW), d, s, 0, 0)); // *(u64*)(rd) = rs
                p.push(ins(ldx(size::DW), d, d, 0, 0)); // rd = *(u64*)(rd)
            }
            // helper call: scrubs r1-r5, writes r0
            5 => {
                // NOT `SAFE_HELPERS`: that list includes ktime_get_ns, which
                // returns the wall clock. A differential test may only call
                // helpers whose result is identical in both engines.
                let h = *rng.pick(DETERMINISTIC_HELPERS);
                p.push(ins(class::JMP | jmp::CALL, 0, 0, 0, h));
            }
            // deferred ALU: div/mod (by a possibly-zero register), byte swap,
            // register-count shifts
            6 => {
                let op = *rng.pick(&[alu::DIV, alu::MOD]);
                let is32 = rng.below(2) == 1;
                let opc = if is32 { alu32(op) } else { alu64(op) };
                p.push(ins(opc | src::X, d, s, 0, 0));
            }
            7 => {
                let imm = *rng.pick(&[16i32, 32, 64]);
                p.push(ins(alu64(alu::END), d, 0, 0, imm));
            }
            _ => {
                let sop = *rng.pick(SHIFT_OPS);
                let is32 = rng.below(2) == 1;
                let opc = if is32 { alu32(sop) } else { alu64(sop) };
                p.push(ins(opc | src::X, d, s, 0, 0));
            }
        }
        // Keep some native ALU in the mix so the JIT is not purely trampolines.
        let aop = *rng.pick(ALU_OPS);
        p.push(ins(alu64(aop), rng.below(10) as u8, 0, 0, rng.next_u32() as i32));
    }

    p.push(ins(0xb7, 0, 0, 0, rng.next_u32() as i32)); // r0 = imm
    p.push(ins(class::JMP | jmp::EXIT, 0, 0, 0, 0));
    p
}

/// Run `insns` (no maps) under the interpreter and the JIT with a fresh 16-byte
/// zero context, returning `(interp_r0, jit_r0)`. Errors from either engine are
/// surfaced as `Err`.
pub fn interp_vs_jit(insns: &[Insn]) -> Result<(u64, u64), String> {
    let prog = crate::Program {
        insns: insns.to_vec(),
        maps: Vec::new(),
        btf_ctx: None,
    };
    let mut ctx_i = vec![0u8; 16];
    let mut vm_i = crate::Vm::new(prog.clone())?;
    let r_interp = vm_i.run(&mut ctx_i).map_err(|e| e.to_string())?;

    let mut ctx_j = vec![0u8; 16];
    let mut vm_j = crate::Vm::new(prog)?;
    // Without the jit feature this degrades to interp-vs-interp (still a
    // determinism check, but not a codegen differential).
    #[cfg(feature = "jit")]
    let r_jit = vm_j.run_jit(&mut ctx_j).map_err(|e| e.to_string())?;
    #[cfg(not(feature = "jit"))]
    let r_jit = vm_j.run(&mut ctx_j).map_err(|e| e.to_string())?;
    Ok((r_interp, r_jit))
}

// ===========================================================================
// Verifier differential fuzzing (see docs/specs/verifier-diff.md)
// ===========================================================================

/// The verifier context size febpf assumes for these programs. The runtime
/// context handed to the interpreter is sized to match, so a context access
/// the verifier proves in-bounds is genuinely in-bounds at run time (otherwise
/// a smaller runtime ctx would raise spurious out-of-bounds "safety faults").
pub const VFUZZ_CTX_SIZE: usize = 4096;

/// febpf's verifier verdict for a program: `Ok(())` = accepted,
/// `Err(reason)` = rejected (the rendered `VerifyError`).
pub fn febpf_verdict(insns: &[Insn], maps: &[MapDef]) -> Result<(), String> {
    let prog = crate::Program {
        insns: insns.to_vec(),
        maps: maps.to_vec(),
        btf_ctx: None,
    };
    // Vm::new can fail for a structurally-malformed program (e.g. a truncated
    // lddw); treat that as a rejection — the verifier would reject it too.
    let mut vm = crate::Vm::new(prog).map_err(|e| format!("malformed: {e}"))?;
    vm.verify(Config::default()).map(|_| ()).map_err(|e| e.to_string())
}

/// Is this interpreter runtime error a **verifier-caught safety fault** — i.e.
/// a memory or structural violation the verifier is supposed to prove absent?
///
/// If febpf's verifier *accepted* a program and the interpreter then raises one
/// of these, febpf's verifier is unsound against its own runtime. Legitimate
/// runtime outcomes (defined div-by-zero, normal exit, instruction-limit trip,
/// unknown-helper) are **not** safety faults.
pub fn is_safety_error(msg: &str) -> bool {
    msg.contains("out of bounds")       // memory / jump / pc out of bounds
        || msg.contains("unaligned")    // misaligned access
        || msg.contains("invalid register")
        || msg.contains("not a map pointer")
}

/// Result of the kernel-free self-consistency check for one program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfConsistency {
    /// febpf's verifier rejected the program — nothing to run.
    Rejected,
    /// Accepted, then ran under the interpreter with no verifier-caught fault
    /// (a normal exit, or only a benign runtime outcome).
    AcceptedClean,
    /// Accepted, but the interpreter raised a verifier-caught safety fault —
    /// a soundness bug in febpf's verifier (fully reproducible unprivileged).
    AcceptedSafetyFault(String),
}

/// Enforce febpf's local soundness invariant: a verify-*accepted* program must
/// run without a verifier-caught safety fault. Needs no privilege.
pub fn check_self_consistency(insns: &[Insn], maps: &[MapDef]) -> SelfConsistency {
    if febpf_verdict(insns, maps).is_err() {
        return SelfConsistency::Rejected;
    }
    let prog = crate::Program {
        insns: insns.to_vec(),
        maps: maps.to_vec(),
        btf_ctx: None,
    };
    // Size the runtime ctx to the verifier's assumed ctx size (see the const).
    let mut ctx = vec![0u8; VFUZZ_CTX_SIZE];
    let mut vm = match crate::Vm::new(prog) {
        Ok(vm) => vm,
        // Accepted by verify() above, so Vm::new should not fail here; if it
        // somehow does, that itself is an inconsistency worth surfacing.
        Err(e) => return SelfConsistency::AcceptedSafetyFault(format!("vm build failed after accept: {e}")),
    };
    match vm.run(&mut ctx) {
        Ok(_) => SelfConsistency::AcceptedClean,
        Err(e) if is_safety_error(&e.msg) => SelfConsistency::AcceptedSafetyFault(e.msg),
        Err(_) => SelfConsistency::AcceptedClean, // benign runtime outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The core invariant: over many seeds, the interpreter and the JIT agree
    /// on `r0` for every generated program. This is the differential test that
    /// makes the fuzzer meaningful.
    #[cfg(feature = "jit")]
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

    /// The same invariant over *memory-heavy* programs. [`gen_program`] is
    /// memory-free, so it exercises none of the JIT's deferred path: it cannot
    /// catch a wrong spill/reload mask, a clobbered scratch register, or a
    /// mis-encoded trampoline. This generator does.
    #[cfg(feature = "jit")]
    #[test]
    fn interp_and_jit_agree_on_memory() {
        if crate::jit::compile(&[Insn { opcode: 0x95, dst: 0, src: 0, off: 0, imm: 0 }]).is_err() {
            return;
        }
        for seed in 0..2000u64 {
            let mut rng = Prng::new(seed ^ 0xA5A5_0000_0000);
            let prog = gen_mem_program(&mut rng);
            match interp_vs_jit(&prog) {
                Ok((i, j)) => assert_eq!(
                    i, j,
                    "interp/JIT mismatch on memory seed {seed}:\n{}",
                    crate::disasm::disasm_program(&prog)
                ),
                Err(e) => panic!(
                    "memory seed {seed}: engine error: {e}\n{}",
                    crate::disasm::disasm_program(&prog)
                ),
            }
        }
    }

    /// Self-consistency over the conservative generator: every program febpf
    /// accepts must run without a verifier-caught safety fault. This generator
    /// is memory/pointer-free, so all programs are accepted and run clean — the
    /// check is the invariant that must hold before frontier programs stress it.
    #[test]
    fn conservative_generator_self_consistent() {
        for seed in 0..3000u64 {
            let mut rng = Prng::new(seed);
            let prog = gen_program(&mut rng);
            if let SelfConsistency::AcceptedSafetyFault(m) = check_self_consistency(&prog, &[]) {
                panic!(
                    "seed {seed}: verify accepted but runtime safety fault: {m}\n{}",
                    crate::disasm::disasm_program(&prog)
                );
            }
        }
    }

    /// The frontier generator must exercise *both* sides of the verdict — it is
    /// useless if everything is accepted or everything is rejected.
    #[test]
    fn frontier_generator_produces_both_verdicts() {
        let mut accepted = 0u32;
        let mut rejected = 0u32;
        for seed in 0..2000u64 {
            let mut rng = Prng::new(seed);
            let prog = gen_frontier_program(&mut rng);
            if febpf_verdict(&prog, &[]).is_ok() {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
        assert!(accepted > 100, "too few accepted: {accepted}");
        assert!(rejected > 100, "too few rejected: {rejected}");
    }

    /// Self-consistency must hold for the frontier generator too: any program
    /// febpf *accepts* must run without a verifier-caught safety fault. A
    /// failure here is a genuine soundness bug in febpf's verifier.
    #[test]
    fn frontier_generator_self_consistent() {
        for seed in 0..3000u64 {
            let mut rng = Prng::new(seed);
            let prog = gen_frontier_program(&mut rng);
            if let SelfConsistency::AcceptedSafetyFault(m) = check_self_consistency(&prog, &[]) {
                panic!(
                    "seed {seed}: verify accepted but runtime safety fault: {m}\n{}",
                    crate::disasm::disasm_program(&prog)
                );
            }
        }
    }

    /// Verdict classification is stable per seed (determinism prerequisite for
    /// reproducible `--seed` triage).
    #[test]
    fn febpf_verdict_is_stable_per_seed() {
        for seed in 0..500u64 {
            let mut a = Prng::new(seed);
            let mut b = Prng::new(seed);
            let pa = gen_program(&mut a);
            let pb = gen_program(&mut b);
            assert_eq!(pa, pb, "generator not deterministic at seed {seed}");
            assert_eq!(
                febpf_verdict(&pa, &[]).is_ok(),
                febpf_verdict(&pb, &[]).is_ok(),
                "verdict not stable at seed {seed}"
            );
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
