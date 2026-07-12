//! Tests for kernel conformance mode and the differential fuzzer.
//!
//! Everything that needs BPF load privilege **probes and skips** (printing
//! `skipped: no bpf privilege`) rather than failing, so the suite stays green
//! unprivileged. The interp-vs-JIT differential fuzzing needs no privilege and
//! is always exercised.

mod common;

use febpf::fuzz::{
    check_self_consistency, febpf_verdict, gen_frontier_program, gen_program, interp_vs_jit, Prng,
    SelfConsistency,
};
use febpf::insn::Insn;
use febpf::kbpf;
use febpf::{asm, verifier, Program, Vm};

fn xdp_byte_writer() -> Program {
    let assembled = asm::assemble(
        "
        r2 = *(u32 *)(r1 + 0)
        r3 = *(u32 *)(r1 + 4)
        r4 = r2
        r4 += 1
        if r4 > r3 goto out
        *(u8 *)(r2 + 0) = 0xaa
    out:
        r0 = 2
        exit",
    )
    .unwrap();
    Program {
        insns: assembled.insns,
        maps: assembled.maps,
        btf_ctx: None,
    }
}

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

/// The febpf half of the XDP differential remains an ordinary verifier-backed
/// execution and is always tested, even on hosts without kernel BPF access.
#[test]
fn xdp_febpf_verifier_and_packet_output() {
    let prog = xdp_byte_writer();
    let mut vm = Vm::new(prog).unwrap();
    vm.verify(verifier::Config {
        ctx_size: 24,
        ctx_writable: false,
        xdp: true,
        ..Default::default()
    })
    .expect("febpf XDP verifier rejected bounded packet write");
    let mut packet = vec![1, 2, 3, 4];
    assert_eq!(vm.run_xdp(&mut packet).unwrap(), 2);
    assert_eq!(packet, [0xaa, 2, 3, 4]);
}

/// End-to-end XDP oracle check: both verifiers accept, and TEST_RUN returns
/// the same verdict and mutated packet as febpf. Skipped without privilege.
#[test]
fn xdp_kernel_differential_if_privileged() {
    if !matches!(kbpf::has_privilege(), Ok(true)) {
        eprintln!("skipped: no bpf privilege");
        return;
    }
    let prog = xdp_byte_writer();
    let input = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];

    let mut vm = Vm::new(prog.clone()).unwrap();
    vm.verify(verifier::Config {
        ctx_size: 24,
        ctx_writable: false,
        xdp: true,
        ..Default::default()
    })
    .unwrap();
    let mut febpf_packet = input.clone();
    let febpf_retval = vm.run_xdp(&mut febpf_packet).unwrap() as u32;

    let mut log = String::new();
    let kernel = kbpf::run_xdp_program(&prog.insns, &prog.maps, &input, Some(&mut log))
        .unwrap_or_else(|e| panic!("kernel XDP run failed: {e}\nlog: {log}"));
    assert_eq!(kernel.retval, febpf_retval, "XDP verdict mismatch");
    assert_eq!(kernel.data_out, febpf_packet, "XDP output packet mismatch");
}

#[test]
fn tail_call_kernel_differential_if_privileged() {
    if !matches!(kbpf::has_privilege(), Ok(true)) {
        eprintln!("skipped: no bpf privilege");
        return;
    }
    let entry = asm::assemble(
        ".map progs prog_array 4 4 1
         r2 = map[progs]
         r3 = 0
         call tail_call
         r0 = 7
         exit",
    )
    .unwrap();
    let target = asm::assemble(
        ".map progs prog_array 4 4 1
         r0 = 42
         exit",
    )
    .unwrap();

    let entry_prog = Program {
        insns: entry.insns,
        maps: entry.maps,
        btf_ctx: None,
    };
    let target_prog = Program {
        insns: target.insns,
        maps: target.maps,
        btf_ctx: None,
    };
    let mut vm = Vm::new(entry_prog.clone()).unwrap();
    vm.verify(verifier::Config::default()).unwrap();
    vm.register_tail_call("progs", 0, target_prog.clone(), verifier::Config::default())
        .unwrap();
    let febpf_ret = vm.run(&mut [0u8; 16]).unwrap() as u32;

    let mut log = String::new();
    let mut kernel = kbpf::load_kernel_program(
        &entry_prog.insns,
        &entry_prog.maps,
        Some(&mut log),
    )
    .unwrap_or_else(|e| panic!("kernel entry load failed: {e}\n{log}"));
    log.clear();
    kernel
        .link_tail_call("progs", 0, &target_prog.insns, Some(&mut log))
        .unwrap_or_else(|e| panic!("kernel target link failed: {e}\n{log}"));
    let kernel_ret = kernel.test_run(&[0u8; 16]).unwrap().retval;
    assert_eq!(kernel_ret, febpf_ret);
    assert_eq!(kernel_ret, 42);
}

#[test]
fn static_elf_tail_call_kernel_differential_if_privileged() {
    common::maybe_compile("tail_call.c", "tail_call.o", "-O2");
    if !matches!(kbpf::has_privilege(), Ok(true)) {
        eprintln!("skipped: no bpf privilege");
        return;
    }
    let bytes = std::fs::read("tests/tail_call.o").unwrap();
    let obj = febpf::elf::load(&bytes).unwrap();
    let entry = obj
        .programs
        .iter()
        .find(|program| program.name == "socket/entry")
        .unwrap();
    let init = obj.prog_array_inits.first().unwrap();
    let target = obj
        .programs
        .iter()
        .find(|program| program.name == init.program)
        .unwrap();

    let mut log = String::new();
    let mut kernel = kbpf::load_kernel_program(&entry.insns, &obj.maps, Some(&mut log))
        .unwrap_or_else(|e| panic!("kernel entry load failed: {e}\n{log}"));
    log.clear();
    kernel
        .link_tail_call(
            &obj.maps[init.map_index].name,
            init.index,
            &target.insns,
            Some(&mut log),
        )
        .unwrap_or_else(|e| panic!("kernel target link failed: {e}\n{log}"));
    assert_eq!(kernel.test_run(&[0u8; 16]).unwrap().retval, 42);
}

#[test]
fn array_of_maps_kernel_differential_if_privileged() {
    let mut assembled = asm::assemble(
        ".map inner array 4 8 1
         .map outer array_of_maps 4 4 2 inner
         *(u32 *)(r10 - 4) = 1
         r1 = map[outer]
         r2 = r10
         r2 += -4
         call map_lookup_elem
         if r0 == 0 goto miss
         r1 = r0
         *(u32 *)(r10 - 4) = 0
         r2 = r10
         r2 += -4
         call map_lookup_elem
         if r0 == 0 goto miss
         r0 = *(u64 *)(r0 + 0)
         exit
       miss:
         r0 = 0
         exit",
    )
    .unwrap();
    assembled.maps[0].init = 42u64.to_ne_bytes().to_vec();
    assembled.maps[1].map_in_map_values = vec![(1, 0)];
    let prog = Program {
        insns: assembled.insns,
        maps: assembled.maps,
        btf_ctx: None,
    };

    let mut vm = Vm::new(prog.clone()).unwrap();
    vm.verify(verifier::Config::default()).unwrap();
    assert_eq!(vm.run(&mut []).unwrap(), 42);

    if !matches!(kbpf::has_privilege(), Ok(true)) {
        eprintln!("skipped kernel half: no bpf privilege");
        return;
    }
    let mut log = String::new();
    let kernel = kbpf::run_program(&prog.insns, &prog.maps, &[], Some(&mut log))
        .unwrap_or_else(|e| panic!("kernel map-in-map run failed: {e}\n{log}"));
    assert_eq!(kernel, 42);
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
