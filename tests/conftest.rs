//! Tests for kernel conformance mode and the differential fuzzer.
//!
//! Everything that needs BPF load privilege **probes and skips** (printing
//! `skipped: no bpf privilege`) rather than failing, so the suite stays green
//! unprivileged. The interp-vs-JIT differential fuzzing needs no privilege and
//! is always exercised.

use febpf::fuzz::{gen_program, interp_vs_jit, Prng};
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
