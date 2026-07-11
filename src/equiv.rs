//! Observable-behavior equivalence checking for two eBPF programs.
//!
//! Two programs are *observably equivalent* iff, for every input, they produce
//! the same observation: the return value `r0`, the ordered `trace_printk`
//! lines, the final context bytes, and the final contents of every writable
//! map. See `docs/specs/equiv-optimizer.md` for the full definition and the
//! soundness argument.
//!
//! The checker is layered, cheapest first:
//!   (a) abstract/structural proofs discharged with the verifier's tnum+range
//!       domain (identical programs; a proven-constant, side-effect-free `r0`);
//!   (b) deterministic differential falsification over seeded-random and
//!       boundary inputs — any observation mismatch is a witnessed
//!       counterexample; no mismatch over N inputs is reported as *empirical*
//!       equivalence, not a proof.

use crate::fuzz::Prng;
use crate::insn::{call_kind, class, jmp};
use crate::interp::{Program, Vm};
use crate::verifier::{Config, PtrKind, RegState};

/// One run's externally-visible result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Program exited returning this `r0`.
    Exit(u64),
    /// Runtime fault. The message has no PC prefix (the raw `EbpfError.msg`),
    /// so it is stable under the PC renumbering an optimizer performs.
    Fault(String),
}

/// A map's final contents: its name and sorted `(key, value)` entries.
pub type MapState = (String, Vec<(Vec<u8>, Vec<u8>)>);

/// Everything an execution makes externally visible for one input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub outcome: Outcome,
    pub printk: Vec<String>,
    /// Final context bytes (the caller-visible buffer r1 points at).
    pub ctx_out: Vec<u8>,
    /// Final contents of each writable map. Read-only maps are inputs, not
    /// outputs, and are excluded.
    pub maps: Vec<MapState>,
}

/// A separating input: run both programs on this and they diverge.
#[derive(Clone, Debug)]
pub struct Witness {
    pub desc: String,
    pub ctx_hex: String,
    pub prandom_seed: u64,
    pub a: Observation,
    pub b: Observation,
}

/// The checker's verdict.
#[derive(Clone, Debug)]
pub enum Verdict {
    /// Discharged by the abstract layer — holds for all inputs.
    ProvenEquivalent(String),
    /// No counterexample over `inputs` deterministic inputs. Empirical.
    Equivalent { inputs: usize },
    /// A witnessing input separates them.
    NotEquivalent(Box<Witness>),
}

impl Verdict {
    /// Distinct process exit code per verdict (see spec §2).
    pub fn exit_code(&self) -> u8 {
        match self {
            Verdict::ProvenEquivalent(_) | Verdict::Equivalent { .. } => 0,
            Verdict::NotEquivalent(_) => 1,
        }
    }
    pub fn is_equivalent(&self) -> bool {
        !matches!(self, Verdict::NotEquivalent(_))
    }
}

/// Options for [`check`].
#[derive(Clone)]
pub struct Options {
    /// Context size (bytes) for the differential inputs.
    pub ctx_size: usize,
    /// A fixed context (hex-decoded) to always test, in addition to the
    /// generated battery. `None` = only generated inputs.
    pub fixed_ctx: Option<Vec<u8>>,
    /// Number of seeded-random inputs.
    pub iters: usize,
    /// Base PRNG seed (reproducibility).
    pub seed: u64,
    /// Per-run instruction cap (both programs are verified to terminate, but a
    /// loop bounded by a context value can still be long).
    pub insn_limit: u64,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            ctx_size: 64,
            fixed_ctx: None,
            iters: 200,
            seed: 0x5eed_1234,
            insn_limit: 2_000_000,
        }
    }
}

/// Run one program on one input and capture its observation. The run is
/// deterministic in `(prog, ctx, prandom_seed)`.
pub fn observe(
    prog: &Program,
    ctx_in: &[u8],
    prandom_seed: u64,
    insn_limit: u64,
) -> Result<Observation, String> {
    let mut vm = Vm::new(prog.clone())?;
    vm.insn_limit = insn_limit;
    vm.set_prandom_seed(prandom_seed);
    let mut ctx = ctx_in.to_vec();
    let outcome = match vm.run(&mut ctx) {
        Ok(r0) => Outcome::Exit(r0),
        Err(e) => Outcome::Fault(e.msg),
    };
    let mut maps = Vec::new();
    for m in &vm.maps {
        if m.def.readonly {
            continue;
        }
        let mut entries = m.iter_entries();
        entries.sort();
        maps.push((m.def.name.clone(), entries));
    }
    Ok(Observation {
        outcome,
        printk: vm.printk.clone(),
        ctx_out: ctx,
        maps,
    })
}

// ---------------------------------------------------------------------------
// Layer (a): abstract / structural proofs
// ---------------------------------------------------------------------------

/// Does the program perform any externally-visible side effect? Conservatively
/// true unless we can prove otherwise: any helper call is a potential effect,
/// and any store whose destination is not provably the stack is a potential
/// effect (a write to ctx or a map value is observable). `pc_regs` supplies the
/// destination pointer kind. Uninitialized/unknown store targets ⇒ effectful.
fn side_effect_free(prog: &Program, vres: &crate::verifier::VerifyOk) -> bool {
    let mut pc = 0;
    while pc < prog.insns.len() {
        let ins = prog.insns[pc];
        if ins.is_wide() {
            pc += 2;
            continue;
        }
        match ins.class() {
            class::JMP | class::JMP32 => {
                if ins.op() == jmp::CALL && ins.src != call_kind::LOCAL {
                    // Any helper call may log, mutate a map, or be a user helper.
                    return false;
                }
            }
            class::ST | class::STX => {
                // Stores to the stack are private; anything else is observable.
                let Some(regs) = vres.regs_at(pc) else {
                    pc += 1;
                    continue; // dead code — never executed, no effect
                };
                match regs[ins.dst as usize] {
                    RegState::Ptr(p) if matches!(p.kind, PtrKind::Stack { .. }) => {}
                    _ => return false,
                }
            }
            _ => {}
        }
        pc += 1;
    }
    true
}

/// If every reachable `exit` proves `r0` equal to the *same* single constant,
/// return it. `None` if r0 is not a proven constant at some reachable exit, or
/// exits disagree, or there is no reachable exit.
fn proven_constant_r0(prog: &Program, vres: &crate::verifier::VerifyOk) -> Option<u64> {
    let mut found: Option<u64> = None;
    let mut any = false;
    let mut pc = 0;
    while pc < prog.insns.len() {
        let ins = prog.insns[pc];
        if ins.is_wide() {
            pc += 2;
            continue;
        }
        let is_exit = matches!(ins.class(), class::JMP)
            && ins.op() == jmp::EXIT;
        if is_exit {
            let regs = vres.regs_at(pc)?; // reachable exit with no state → give up
            match regs[0] {
                RegState::Scalar(s) if s.is_const() => {
                    any = true;
                    match found {
                        None => found = Some(s.umin),
                        Some(c) if c == s.umin => {}
                        Some(_) => return None, // exits disagree
                    }
                }
                _ => return None,
            }
        }
        pc += 1;
    }
    if any {
        found
    } else {
        None
    }
}

/// Try the abstract layer. Returns `Some(reason)` on a discharged proof.
fn try_abstract(a: &Program, b: &Program, cfg: Config) -> Option<String> {
    // Reflexive / identical-program proof (also the optimizer's "unchanged").
    if a.insns == b.insns && a.maps == b.maps {
        return Some("identical instruction sequence and map set".to_string());
    }
    let va = Vm::new(a.clone()).ok()?.verify(cfg.clone()).ok()?;
    let vb = Vm::new(b.clone()).ok()?.verify(cfg).ok()?;
    if side_effect_free(a, &va) && side_effect_free(b, &vb) {
        if let (Some(ca), Some(cb)) = (proven_constant_r0(a, &va), proven_constant_r0(b, &vb)) {
            if ca == cb {
                return Some(format!(
                    "both side-effect-free and prove r0 = {ca} ({ca:#x}) at every exit"
                ));
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Layer (b): differential falsification
// ---------------------------------------------------------------------------

/// The boundary inputs, as `(description, ctx bytes)`.
fn boundary_inputs(ctx_size: usize) -> Vec<(String, Vec<u8>)> {
    let mut v = vec![
        ("all-zero".to_string(), vec![0u8; ctx_size]),
        ("all-ones".to_string(), vec![0xffu8; ctx_size]),
        (
            "0xaa".to_string(),
            vec![0xaau8; ctx_size],
        ),
        (
            "0x55".to_string(),
            vec![0x55u8; ctx_size],
        ),
        (
            "index".to_string(),
            (0..ctx_size).map(|i| i as u8).collect(),
        ),
    ];
    // A couple of "one hot" low-byte patterns exercise sign/zero boundaries.
    if ctx_size >= 8 {
        let mut hi = vec![0u8; ctx_size];
        for b in hi.iter_mut().take(8) {
            *b = 0x80;
        }
        v.push(("sign-bytes".to_string(), hi));
    }
    v
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Compare `a` and `b` on one input; `Some(witness)` on divergence.
fn compare_on(
    a: &Program,
    b: &Program,
    desc: &str,
    ctx: &[u8],
    prandom_seed: u64,
    insn_limit: u64,
) -> Result<Option<Witness>, String> {
    let oa = observe(a, ctx, prandom_seed, insn_limit)?;
    let ob = observe(b, ctx, prandom_seed, insn_limit)?;
    if oa == ob {
        Ok(None)
    } else {
        Ok(Some(Witness {
            desc: desc.to_string(),
            ctx_hex: to_hex(ctx),
            prandom_seed,
            a: oa,
            b: ob,
        }))
    }
}

/// The full layered check.
pub fn check(a: &Program, b: &Program, opts: &Options) -> Result<Verdict, String> {
    // Layer (a): abstract proofs.
    let cfg = Config {
        ctx_size: opts.ctx_size,
        ..Default::default()
    };
    if let Some(reason) = try_abstract(a, b, cfg) {
        return Ok(Verdict::ProvenEquivalent(reason));
    }

    // Layer (b): differential falsification. Fixed ctx (if any) first, then
    // boundaries, then seeded-random.
    let mut count = 0usize;
    let prandom = crate::interp::DEFAULT_PRANDOM_SEED;

    if let Some(fixed) = &opts.fixed_ctx {
        count += 1;
        if let Some(w) = compare_on(a, b, "fixed --ctx", fixed, prandom, opts.insn_limit)? {
            return Ok(Verdict::NotEquivalent(Box::new(w)));
        }
    }

    for (desc, ctx) in boundary_inputs(opts.ctx_size) {
        count += 1;
        if let Some(w) = compare_on(a, b, &format!("boundary:{desc}"), &ctx, prandom, opts.insn_limit)? {
            return Ok(Verdict::NotEquivalent(Box::new(w)));
        }
    }

    let mut rng = Prng::new(opts.seed);
    for _ in 0..opts.iters {
        let mut ctx = vec![0u8; opts.ctx_size];
        for b in ctx.iter_mut() {
            *b = rng.next_u32() as u8;
        }
        // Vary the prandom stream per input too, so get_prandom_u32-dependent
        // behavior is exercised; both programs see the same seed.
        let pseed = rng.next_u64();
        count += 1;
        if let Some(w) = compare_on(a, b, "random", &ctx, pseed, opts.insn_limit)? {
            return Ok(Verdict::NotEquivalent(Box::new(w)));
        }
    }

    Ok(Verdict::Equivalent { inputs: count })
}

/// Render an observation difference for the CLI witness dump.
pub fn render_witness(w: &Witness) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "  input: {} (prandom seed {})", w.desc, w.prandom_seed);
    if w.ctx_hex.len() <= 128 {
        let _ = writeln!(s, "  ctx:   {}", w.ctx_hex);
    } else {
        let _ = writeln!(s, "  ctx:   {}… ({} bytes)", &w.ctx_hex[..128], w.ctx_hex.len() / 2);
    }
    let fo = |o: &Outcome| match o {
        Outcome::Exit(r0) => format!("r0 = {r0} ({r0:#x})"),
        Outcome::Fault(m) => format!("fault: {m}"),
    };
    if w.a.outcome != w.b.outcome {
        let _ = writeln!(s, "  outcome: A {} | B {}", fo(&w.a.outcome), fo(&w.b.outcome));
    }
    if w.a.printk != w.b.printk {
        let _ = writeln!(s, "  printk A: {:?}", w.a.printk);
        let _ = writeln!(s, "  printk B: {:?}", w.b.printk);
    }
    if w.a.ctx_out != w.b.ctx_out {
        let _ = writeln!(s, "  ctx-out A: {}", to_hex(&w.a.ctx_out));
        let _ = writeln!(s, "  ctx-out B: {}", to_hex(&w.b.ctx_out));
    }
    if w.a.maps != w.b.maps {
        let _ = writeln!(s, "  map state differs:");
        let _ = writeln!(s, "    A: {:?}", w.a.maps);
        let _ = writeln!(s, "    B: {:?}", w.b.maps);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asm;

    fn prog(src: &str) -> Program {
        let a = asm::assemble(src).unwrap();
        Program {
            insns: a.insns,
            maps: a.maps,
            btf_ctx: None,
        }
    }

    #[test]
    fn identical_is_proven() {
        let p = prog("r0 = 1\nexit\n");
        let v = check(&p, &p, &Options::default()).unwrap();
        assert!(matches!(v, Verdict::ProvenEquivalent(_)), "{v:?}");
    }

    #[test]
    fn constant_folding_pair_is_proven() {
        // Both prove r0 = 5, side-effect-free.
        let a = prog("r0 = 5\nexit\n");
        let b = prog("r0 = 2\nr0 += 3\nexit\n");
        let v = check(&a, &b, &Options::default()).unwrap();
        assert!(matches!(v, Verdict::ProvenEquivalent(_)), "{v:?}");
    }

    #[test]
    fn hand_optimized_pair_is_equivalent() {
        // r0 = ctx-dependent, so not a proven constant; must match empirically.
        // A: r0 = *(u8*)(r1+0); r0 *= 2 ; exit
        // B: r0 = *(u8*)(r1+0); r0 <<= 1 ; exit
        let a = prog("r0 = *(u8 *)(r1 + 0)\nr0 *= 2\nexit\n");
        let b = prog("r0 = *(u8 *)(r1 + 0)\nr0 <<= 1\nexit\n");
        let v = check(&a, &b, &Options::default()).unwrap();
        assert!(v.is_equivalent(), "{v:?}");
        assert!(matches!(v, Verdict::Equivalent { .. }), "{v:?}");
    }

    #[test]
    fn different_pair_is_not_equivalent_with_witness() {
        // r0 = ctx byte  vs  r0 = ctx byte + 1
        let a = prog("r0 = *(u8 *)(r1 + 0)\nexit\n");
        let b = prog("r0 = *(u8 *)(r1 + 0)\nr0 += 1\nexit\n");
        let v = check(&a, &b, &Options::default()).unwrap();
        match v {
            Verdict::NotEquivalent(w) => {
                // Reproduce the witness deterministically.
                let ctx: Vec<u8> = (0..w.ctx_hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&w.ctx_hex[i..i + 2], 16).unwrap())
                    .collect();
                let oa = observe(&a, &ctx, w.prandom_seed, Options::default().insn_limit).unwrap();
                let ob = observe(&b, &ctx, w.prandom_seed, Options::default().insn_limit).unwrap();
                assert_ne!(oa, ob, "witness did not reproduce");
            }
            other => panic!("expected NotEquivalent, got {other:?}"),
        }
    }

    #[test]
    fn printk_difference_is_observable() {
        // Same r0, different log line ⇒ NOT equivalent.
        let a = prog(
            "r1 = 65\n*(u8 *)(r10 - 8) = r1\nr1 = r10\nr1 += -8\nr2 = 1\nr3 = 0\ncall 6\nr0 = 0\nexit\n",
        );
        let b = prog(
            "r1 = 66\n*(u8 *)(r10 - 8) = r1\nr1 = r10\nr1 += -8\nr2 = 1\nr3 = 0\ncall 6\nr0 = 0\nexit\n",
        );
        let v = check(&a, &b, &Options::default()).unwrap();
        assert!(matches!(v, Verdict::NotEquivalent(_)), "{v:?}");
    }
}
