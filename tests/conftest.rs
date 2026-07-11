//! Tests for kernel conformance mode and the differential fuzzer.
//!
//! Everything that needs BPF load privilege **probes and skips** (printing
//! `skipped: no bpf privilege`) rather than failing, so the suite stays green
//! unprivileged. The interp-vs-JIT differential fuzzing needs no privilege and
//! is always exercised.

use febpf::fuzz::{
    check_self_consistency, febpf_verdict, gen_frontier_program, gen_program, interp_vs_jit, Prng,
    SelfConsistency,
};
use febpf::insn::Insn;
use febpf::kbpf;

/// The capability probe must never panic and must return a definite answer.
#[test]
fn probe_is_well_behaved() {
    match kbpf::has_privilege() {
        Ok(true) => eprintln!("bpf privilege: available"),
        Ok(false) => eprintln!("bpf privilege: none (unprivileged)"),
        Err(e) => panic!("probe returned an unexpected error: {e}"),
    }
}

/// Interp vs JIT must agree on a batch of generated programs. Determinism of
/// the PRNG makes this a fixed, reproducible corpus.
#[cfg(feature = "jit")]
#[test]
fn fuzz_interp_matches_jit() {
    // Skip where the JIT is unavailable (non-x86-64-Linux): run_jit errors.
    let exit = [Insn { opcode: 0x95, dst: 0, src: 0, off: 0, imm: 0 }];
    if febpf::jit::compile(&exit).is_err() {
        eprintln!("skipped: JIT unavailable on this target");
        return;
    }
    for seed in 0..1000u64 {
        let mut rng = Prng::new(seed);
        let prog = gen_program(&mut rng);
        let (i, j) = interp_vs_jit(&prog).unwrap_or_else(|e| {
            panic!(
                "seed {seed}: {e}\n{}",
                febpf::disasm::disasm_program(&prog)
            )
        });
        assert_eq!(
            i,
            j,
            "seed {seed} interp/JIT disagree\n{}",
            febpf::disasm::disasm_program(&prog)
        );
    }
}

/// End-to-end kernel round-trip: load a trivial program and TEST_RUN it,
/// checking the kernel's retval equals the program's r0. Skipped without
/// privilege.
#[test]
fn kernel_roundtrip_if_privileged() {
    if !matches!(kbpf::has_privilege(), Ok(true)) {
        eprintln!("skipped: no bpf privilege");
        return;
    }
    // mov r0, 42 ; exit
    let prog = [
        Insn { opcode: 0xb7, dst: 0, src: 0, off: 0, imm: 42 },
        Insn { opcode: 0x95, dst: 0, src: 0, off: 0, imm: 0 },
    ];
    let mut log = String::new();
    let retval = kbpf::run_program(&prog, &[], &[0u8; 16], Some(&mut log))
        .unwrap_or_else(|e| panic!("kernel run failed: {e}\nlog: {log}"));
    assert_eq!(retval, 42, "kernel retval mismatch");
}

/// Differential fuzz against the real kernel when privileged: interp, JIT and
/// kernel must agree (low 32 bits) on every program the kernel accepts.
#[test]
fn fuzz_kernel_differential_if_privileged() {
    if !matches!(kbpf::has_privilege(), Ok(true)) {
        eprintln!("skipped: no bpf privilege");
        return;
    }
    let mut checked = 0u32;
    for seed in 0..500u64 {
        let mut rng = Prng::new(seed);
        let prog = gen_program(&mut rng);
        let (r_interp, r_jit) = match interp_vs_jit(&prog) {
            Ok(v) => v,
            Err(_) => continue,
        };
        assert_eq!(r_interp, r_jit, "seed {seed}: interp/JIT disagree");
        if let Ok(retval) = kbpf::run_program(&prog, &[], &[0u8; 16], None) {
            assert_eq!(
                retval as u64,
                r_interp & 0xffff_ffff,
                "seed {seed}: kernel disagrees with febpf\n{}",
                febpf::disasm::disasm_program(&prog)
            );
            checked += 1;
        }
    }
    eprintln!("kernel differential: {checked} programs agreed");
}

// ---------------------------------------------------------------------------
// Verifier differential fuzzing (vfuzz) — see docs/specs/verifier-diff.md
// ---------------------------------------------------------------------------

/// The frontier generator must produce *both* accepted and rejected programs;
/// a generator that only ever hits one side cannot expose verdict disagreement.
#[test]
fn frontier_generator_exercises_both_verdicts() {
    let (mut acc, mut rej) = (0u32, 0u32);
    for seed in 0..1500u64 {
        let mut rng = Prng::new(seed);
        let prog = gen_frontier_program(&mut rng);
        if febpf_verdict(&prog, &[]).is_ok() {
            acc += 1;
        } else {
            rej += 1;
        }
    }
    assert!(acc > 50 && rej > 50, "unbalanced verdicts: {acc} accepted, {rej} rejected");
}

/// febpf verify+run self-consistency over many seeds and both generators: a
/// verify-accepted program must never raise a verifier-caught safety fault at
/// run time. This is the kernel-free soundness check and needs no privilege.
#[test]
fn febpf_verifier_is_self_consistent() {
    for seed in 0..2000u64 {
        let mut rc = Prng::new(seed);
        let mut rf = Prng::new(seed);
        for prog in [gen_program(&mut rc), gen_frontier_program(&mut rf)] {
            if let SelfConsistency::AcceptedSafetyFault(m) = check_self_consistency(&prog, &[]) {
                panic!(
                    "seed {seed}: febpf accepted but interpreter faulted: {m}\n{}",
                    febpf::disasm::disasm_program(&prog)
                );
            }
        }
    }
}

/// Classification is stable per seed: the same seed yields the same program and
/// the same febpf verdict every time (reproducible `--seed` triage).
#[test]
fn classification_is_stable_per_seed() {
    for seed in 0..500u64 {
        let mut a = Prng::new(seed);
        let mut b = Prng::new(seed);
        let pa = gen_frontier_program(&mut a);
        let pb = gen_frontier_program(&mut b);
        assert_eq!(pa, pb, "frontier generator not deterministic at seed {seed}");
        assert_eq!(
            febpf_verdict(&pa, &[]).is_ok(),
            febpf_verdict(&pb, &[]).is_ok(),
            "verdict not stable at seed {seed}"
        );
    }
}

/// Kernel-side verifier verdict differential: when privileged, classify frontier
/// programs into the four cells and assert febpf never accepts a program the
/// kernel rejects (FEBPF-LAX would be a soundness gap). Skipped unprivileged.
#[test]
fn vfuzz_kernel_verdict_differential_if_privileged() {
    if !matches!(kbpf::has_privilege(), Ok(true)) {
        eprintln!("skipped: no bpf privilege");
        return;
    }
    let (mut lax, mut strict, mut agree) = (0u32, 0u32, 0u32);
    for seed in 0..1000u64 {
        let mut rng = Prng::new(seed);
        let prog = gen_frontier_program(&mut rng);
        let febpf_ok = febpf_verdict(&prog, &[]).is_ok();
        let mut log = String::new();
        let kernel_ok = kbpf::verdict(&prog, Some(&mut log)).is_ok();
        match (febpf_ok, kernel_ok) {
            (true, false) => {
                lax += 1;
                eprintln!(
                    "FEBPF-LAX at seed {seed} (febpf accepts, kernel rejects):\n{}\nkernel log:\n{}",
                    febpf::disasm::disasm_program(&prog),
                    log.trim_end()
                );
            }
            (false, true) => strict += 1,
            _ => agree += 1,
        }
    }
    eprintln!("vfuzz kernel differential: {agree} agree, {strict} FEBPF-STRICT, {lax} FEBPF-LAX");
    assert_eq!(lax, 0, "{lax} FEBPF-LAX case(s) — febpf verifier unsound vs kernel");
}
