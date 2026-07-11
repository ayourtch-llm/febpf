//! CLI orchestration for `febpf conftest` and `febpf fuzz`.
//!
//! `conftest` runs one program under the interpreter, the JIT and — when
//! privileged — the real kernel (`bpf(2)` TEST_RUN), and diffs `r0`. `fuzz`
//! generates random conservative programs and requires the engines to agree.
//!
//! Exit-code contract (distinct so scripts can tell outcomes apart):
//!   0  all engines agree
//!   1  a real mismatch (interp vs JIT, or febpf vs kernel)
//!   2  kernel side unavailable (no privilege) — interp/JIT still compared
//!   3  kernel rejected the program (load/verify error), not a value mismatch

use crate::{make_ctx, Opts};
use febpf::{disasm, kbpf, Program, Vm};
use std::process::ExitCode;

/// Run interp and (best-effort) JIT for a loaded program with the given ctx.
/// Returns `(interp_r0, Option<jit_r0>)`; the JIT is `None` where unsupported.
fn run_febpf(prog: &Program, ctx: &[u8]) -> Result<(u64, Option<u64>), String> {
    let mut ctx_i = ctx.to_vec();
    let mut vm_i = Vm::new(prog.clone())?;
    let r_interp = vm_i.run(&mut ctx_i).map_err(|e| e.to_string())?;

    let mut ctx_j = ctx.to_vec();
    let mut vm_j = Vm::new(prog.clone())?;
    let r_jit = match vm_j.run_jit(&mut ctx_j) {
        Ok(r) => Some(r),
        Err(e) => {
            eprintln!("note: JIT unavailable ({e}); comparing interpreter only");
            None
        }
    };
    Ok((r_interp, r_jit))
}

pub fn conftest(o: &Opts, prog: Program) -> Result<ExitCode, String> {
    let ctx = make_ctx(o)?;

    // febpf side (always available, unprivileged).
    let (r_interp, r_jit) = run_febpf(&prog, &ctx)?;
    println!("interp : r0 = {r_interp} ({r_interp:#x})");
    if let Some(j) = r_jit {
        println!("jit    : r0 = {j} ({j:#x})");
        if j != r_interp {
            println!("MISMATCH: interpreter and JIT disagree");
            print!("{}", disasm::disasm_program(&prog.insns));
            return Ok(ExitCode::from(1));
        }
    }

    // Kernel side: probe privilege first.
    match kbpf::has_privilege() {
        Ok(false) => {
            println!("kernel : unavailable (permission denied); run as root");
            return Ok(ExitCode::from(2));
        }
        Err(e) => {
            println!("kernel : probe failed unexpectedly: {e}");
            return Ok(ExitCode::from(2));
        }
        Ok(true) => {}
    }

    let mut log = String::new();
    match kbpf::run_program(&prog.insns, &prog.maps, &ctx, Some(&mut log)) {
        Ok(retval) => {
            println!("kernel : retval = {retval} ({retval:#x})");
            // The kernel returns retval as u32; compare against r0's low 32 bits.
            if retval as u64 != (r_interp & 0xffff_ffff) {
                println!(
                    "MISMATCH: kernel retval {retval:#x} != febpf r0 low32 {:#x}",
                    r_interp & 0xffff_ffff
                );
                print!("{}", disasm::disasm_program(&prog.insns));
                return Ok(ExitCode::from(1));
            }
            println!("OK: all engines agree (r0 low32 = {:#x})", r_interp & 0xffff_ffff);
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            println!("kernel : load/run failed: {e}");
            if !log.trim().is_empty() {
                println!("--- kernel verifier log ---\n{}", log.trim_end());
            }
            Ok(ExitCode::from(3))
        }
    }
}

pub fn fuzz(o: &Opts) -> Result<ExitCode, String> {
    use febpf::fuzz::{gen_program, interp_vs_jit, random_seed, Prng};

    let base_seed = o.seed.unwrap_or_else(random_seed);
    let iters = o.iters;

    // Kernel mode is opt-in and degrades gracefully.
    let use_kernel = if o.kernel {
        match kbpf::has_privilege() {
            Ok(true) => true,
            Ok(false) => {
                eprintln!("skipped: no bpf privilege — kernel diff disabled, interp-vs-JIT only");
                false
            }
            Err(e) => {
                eprintln!("skipped: bpf probe error ({e}) — interp-vs-JIT only");
                false
            }
        }
    } else {
        false
    };

    println!(
        "fuzzing {iters} programs, base seed {base_seed:#x}{}",
        if use_kernel { ", +kernel" } else { "" }
    );

    let mut kernel_skipped = 0u64;
    for i in 0..iters {
        // Each program gets its own seed derived from the base, so a failure at
        // iteration i is reproducible with `--seed <printed>`.
        let seed = base_seed.wrapping_add(i);
        let mut rng = Prng::new(seed);
        let prog = gen_program(&mut rng);

        let (r_interp, r_jit) = match interp_vs_jit(&prog) {
            Ok(v) => v,
            Err(e) => return Ok(fail(seed, &prog, &format!("engine error: {e}"))),
        };
        if r_interp != r_jit {
            return Ok(fail(
                seed,
                &prog,
                &format!("interp r0 {r_interp:#x} != jit r0 {r_jit:#x}"),
            ));
        }

        if use_kernel {
            let mut log = String::new();
            match kbpf::run_program(&prog, &[], &[0u8; 16], Some(&mut log)) {
                Ok(retval) => {
                    if retval as u64 != (r_interp & 0xffff_ffff) {
                        return Ok(fail(
                            seed,
                            &prog,
                            &format!(
                                "kernel retval {retval:#x} != febpf r0 low32 {:#x}",
                                r_interp & 0xffff_ffff
                            ),
                        ));
                    }
                }
                Err(_) => kernel_skipped += 1, // kernel verifier declined; not a value bug
            }
        }
    }

    println!("OK: {iters} programs, all engines agree");
    if use_kernel && kernel_skipped > 0 {
        println!(
            "note: {kernel_skipped} program(s) were rejected by the kernel verifier and skipped"
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn fail(seed: u64, prog: &[febpf::insn::Insn], why: &str) -> ExitCode {
    println!("FAIL (seed {seed:#x} — reproduce with --seed {seed}): {why}");
    println!("--- program ---");
    print!("{}", disasm::disasm_program(prog));
    ExitCode::from(1)
}
