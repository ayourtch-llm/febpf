//! Integration tests for the load-time rodata dead-code elimination pass
//! (`src/dce.rs`, `docs/specs/rodata-dce.md`): behavior preservation is
//! checked with the observable-equivalence checker (`febpf::equiv`), and the
//! pass must turn the corpus failure shape (statically unreachable code the
//! verifier rejects) into a verifiable program.

use febpf::verifier::Config;
use febpf::{asm, dce, equiv, Program, Vm};

fn program(src: &str) -> Program {
    let a = asm::assemble(src).expect("assembly failed");
    Program {
        insns: a.insns,
        maps: a.maps,
        btf_ctx: None,
    }
}

fn dced(p: &Program) -> Program {
    let res = dce::eliminate_rodata_dead_code(&p.insns, &p.maps).expect("DCE should fire");
    Program {
        insns: res.insns,
        maps: p.maps.clone(),
        btf_ctx: None,
    }
}

fn run(p: &Program, ctx: &mut [u8]) -> u64 {
    let mut vm = Vm::new(p.clone()).unwrap();
    vm.verify(Config {
        ctx_size: ctx.len(),
        ..Default::default()
    })
    .expect("verification failed");
    vm.run(ctx).expect("run failed")
}

/// The `const volatile bool` config-flag idiom: the flag is 0 (asm `ro` maps
/// are zero-initialized), so the guarded side is dead. The original program
/// still verifies (both sides are CFG-reachable), which lets `febpf equiv`
/// prove the DCE'd program observably equivalent.
const FLAG_PROG: &str = "\
.map cfg array 4 4 1 ro
    r6 = *(u32 *)(r1 + 0)
    r2 = map[cfg][0] + 0
    r2 = *(u32 *)(r2 + 0)
    if r2 != 0 goto slow
    r0 = r6
    r0 <<= 1
    exit
slow:
    r0 = r6
    r0 *= 3
    exit
";

#[test]
fn dce_output_is_equivalent_to_original() {
    let orig = program(FLAG_PROG);
    let opt = dced(&orig);
    assert!(opt.insns.len() < orig.insns.len());

    let opts = equiv::Options {
        ctx_size: 8,
        ..Default::default()
    };
    let verdict = equiv::check(&orig, &opt, &opts).expect("equiv check errored");
    assert!(
        verdict.is_equivalent(),
        "DCE'd program must be observably equivalent, got: {verdict:?}"
    );
}

#[test]
fn dce_preserves_runtime_behavior() {
    let orig = program(FLAG_PROG);
    let opt = dced(&orig);
    for v in [0u32, 1, 7, 0xffff_ffff] {
        let mut a = [0u8; 8];
        a[..4].copy_from_slice(&v.to_le_bytes());
        let mut b = a;
        assert_eq!(run(&orig, &mut a), run(&opt, &mut b), "input {v}");
        assert_eq!(run(&opt, &mut b), (v as u64) << 1); // fast path selected
    }
}

#[test]
fn dce_respects_nonzero_rodata() {
    // Same program, flag patched to 1: the *fast* side is dead instead.
    let mut orig = program(FLAG_PROG);
    orig.maps[0].init = 1u32.to_le_bytes().to_vec();
    let opt = dced(&orig);

    let mut ctx = [0u8; 8];
    ctx[..4].copy_from_slice(&5u32.to_le_bytes());
    assert_eq!(run(&opt, &mut ctx.clone()), 15); // slow path: 5 * 3
    let verdict = equiv::check(
        &orig,
        &opt,
        &equiv::Options {
            ctx_size: 8,
            ..Default::default()
        },
    )
    .expect("equiv check errored");
    assert!(verdict.is_equivalent());
}

#[test]
fn dce_makes_unreachable_code_verifiable() {
    // The corpus failure shape: code that is statically unreachable (a
    // subprogram this entry point never calls, as stitched in from `.text`).
    // The verifier rejects the original; after DCE it passes.
    let src = "\
r0 = 0
exit
r0 = 99
exit
";
    let orig = program(src);
    let err = match Vm::new(orig.clone()).unwrap().verify(Config::default()) {
        Ok(_) => panic!("original must be rejected"),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("unreachable instruction"),
        "unexpected rejection: {err}"
    );

    let opt = dced(&orig);
    assert_eq!(opt.insns.len(), 2);
    assert_eq!(run(&opt, &mut []), 0);
}

#[test]
fn dce_removes_rodata_guarded_call_to_dead_subprog() {
    // A subprogram reachable only under a frozen flag that is 0: both the
    // branch and the whole callee must go, and the result must verify.
    let src = "\
.map cfg array 4 4 1 ro
    r2 = map[cfg][0] + 0
    r2 = *(u32 *)(r2 + 0)
    if r2 == 0 goto out
    call helper_fn
    exit
out:
    r0 = 42
    exit
helper_fn:
    r0 = 7
    exit
";
    let orig = program(src);
    let opt = dced(&orig);
    // Surviving: lddw (2 slots) + load + r0 = 42 + exit.
    assert_eq!(opt.insns.len(), 5);
    assert_eq!(run(&opt, &mut []), 42);
}
