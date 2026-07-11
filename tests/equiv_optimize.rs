//! End-to-end tests for the observable-equivalence checker (`febpf equiv`) and
//! the verifier-guided optimizer (`febpf optimize`), exercising the public
//! library API the CLI is built on. Behavioral/differential per HANDOFF.

use febpf::equiv::{self, Observation, Options, Outcome, Verdict};
use febpf::optimize::{self, optimize};
use febpf::verifier::Config;
use febpf::{asm, Program, Vm};

fn prog(src: &str) -> Program {
    let a = asm::assemble(src).expect("assemble");
    Program {
        insns: a.insns,
        maps: a.maps,
        btf_ctx: None,
    }
}

fn run_r0(p: &Program, ctx: &[u8]) -> u64 {
    let mut vm = Vm::new(p.clone()).unwrap();
    let mut c = ctx.to_vec();
    vm.run(&mut c).unwrap()
}

// --- equiv --------------------------------------------------------------

#[test]
fn equiv_proven_trivial_abstract() {
    let a = prog("r0 = 42\nexit\n");
    let b = prog("r0 = 40\nr0 += 2\nexit\n");
    let v = equiv::check(&a, &b, &Options::default()).unwrap();
    assert!(matches!(v, Verdict::ProvenEquivalent(_)), "{v:?}");
    assert_eq!(v.exit_code(), 0);
}

#[test]
fn equiv_empirical_on_hand_optimized_pair() {
    // Behaviorally identical, but ctx-dependent so not a proven constant.
    let a = prog("r0 = *(u32 *)(r1 + 0)\nr0 *= 4\nexit\n");
    let b = prog("r0 = *(u32 *)(r1 + 0)\nr0 <<= 2\nexit\n");
    let v = equiv::check(&a, &b, &Options::default()).unwrap();
    assert!(matches!(v, Verdict::Equivalent { .. }), "{v:?}");
    assert_eq!(v.exit_code(), 0);
}

#[test]
fn equiv_not_equivalent_with_reproducible_witness() {
    let a = prog("r0 = *(u32 *)(r1 + 0)\nexit\n");
    let b = prog("r0 = *(u32 *)(r1 + 0)\nr0 += 1\nexit\n");
    let v = equiv::check(&a, &b, &Options::default()).unwrap();
    let Verdict::NotEquivalent(w) = v else {
        panic!("expected NOT-EQUIVALENT, got {v:?}");
    };
    // The witness reproduces the divergence deterministically.
    let ctx: Vec<u8> = (0..w.ctx_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&w.ctx_hex[i..i + 2], 16).unwrap())
        .collect();
    let oa = equiv::observe(&a, &ctx, w.prandom_seed, 1_000_000).unwrap();
    let ob = equiv::observe(&b, &ctx, w.prandom_seed, 1_000_000).unwrap();
    assert_ne!(oa, ob);
}

#[test]
fn equiv_map_side_effect_is_observable() {
    // Same r0 (0), but B writes a different value into the map.
    let a = prog(
        ".map m array 4 8 4\n\
         r1 = map[m][0] + 0\n\
         r2 = 7\n\
         *(u64 *)(r1 + 0) = r2\n\
         r0 = 0\n\
         exit\n",
    );
    let b = prog(
        ".map m array 4 8 4\n\
         r1 = map[m][0] + 0\n\
         r2 = 9\n\
         *(u64 *)(r1 + 0) = r2\n\
         r0 = 0\n\
         exit\n",
    );
    let v = equiv::check(&a, &b, &Options::default()).unwrap();
    assert!(matches!(v, Verdict::NotEquivalent(_)), "{v:?}");
}

#[test]
fn observation_captures_ctx_mutation() {
    // A stores into the ctx; the final ctx bytes are part of the observable.
    let p = prog("r2 = 0x99\n*(u8 *)(r1 + 0) = r2\nr0 = 0\nexit\n");
    let o: Observation = equiv::observe(&p, &[0u8; 8], 1, 1_000_000).unwrap();
    assert_eq!(o.outcome, Outcome::Exit(0));
    assert_eq!(o.ctx_out[0], 0x99);
}

// --- optimize -----------------------------------------------------------

fn optimize_ok(p: &Program) -> optimize::Optimized {
    optimize(p, Config::default(), &Options::default()).expect("optimize")
}

#[test]
fn optimize_shrinks_and_preserves_behavior() {
    // Constant-foldable + dead branch + strength reduction.
    let p = prog(
        "r0 = *(u32 *)(r1 + 0)\n\
         r0 *= 16\n\
         r2 = 0\n\
         if r2 != 0 goto dead\n\
         r0 += 1\n\
         dead:\n\
         exit\n",
    );
    let o = optimize_ok(&p);
    assert!(o.stats.insns_after < o.stats.insns_before, "should shrink");
    assert!(o.self_check.is_equivalent());

    // Direct run: identical r0 on several inputs.
    for word in [0u32, 1, 255, 0x1234_5678, u32::MAX] {
        let ctx = word.to_le_bytes().to_vec();
        assert_eq!(run_r0(&p, &ctx), run_r0(&o.program, &ctx), "word {word:#x}");
    }

    // And equiv agrees, independently.
    let v = equiv::check(&p, &o.program, &Options::default()).unwrap();
    assert!(v.is_equivalent(), "{v:?}");
}

#[test]
fn optimize_output_reverifies() {
    let p = prog(
        "r0 = *(u32 *)(r1 + 0)\n\
         r0 *= 2\n\
         r0 += 0\n\
         r0 &= 0x7fffffff\n\
         exit\n",
    );
    let o = optimize_ok(&p);
    // The optimized program must still pass the verifier (kernel-loadable).
    let mut vm = Vm::new(o.program.clone()).unwrap();
    assert!(vm.verify(Config::default()).is_ok());
}

#[test]
fn optimize_leaves_optimal_program_unchanged() {
    let p = prog("r0 = *(u32 *)(r1 + 0)\nr0 <<= 2\nexit\n");
    let o = optimize_ok(&p);
    assert_eq!(o.stats.total_rewrites(), 0);
    assert_eq!(o.program.insns, p.insns);
}

#[test]
fn optimize_preserves_printk_lines() {
    // Logs a character; the optimizer must not perturb the printk stream.
    let p = prog(
        "r1 = 88\n\
         *(u8 *)(r10 - 8) = r1\n\
         r1 = r10\n\
         r1 += -8\n\
         r2 = 1\n\
         r3 = 0\n\
         call 6\n\
         r0 = 0\n\
         exit\n",
    );
    let o = optimize_ok(&p);
    let before = equiv::observe(&p, &[0u8; 16], 1, 1_000_000).unwrap();
    let after = equiv::observe(&o.program, &[0u8; 16], 1, 1_000_000).unwrap();
    assert_eq!(before.printk, after.printk);
    assert!(!before.printk.is_empty());
    assert!(o.self_check.is_equivalent());
}
