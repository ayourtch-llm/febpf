//! Exhaustive small-bit-width soundness checks for the verifier's abstract
//! operators (see `docs/specs/operator-soundness.md`).
//!
//! The obligation: for an abstract operator `⊕'` approximating a concrete
//! operator `⊕`, for ALL abstract values `a, b` and ALL concrete
//! `x ∈ γ(a), y ∈ γ(b)`:  `(x ⊕ y) ∈ γ(a ⊕' b)`.
//!
//! Everything here runs the PRODUCTION 64-bit operators directly — there is
//! no re-implementation-at-width-w mirror to drift out of sync. Instead the
//! abstract inputs are confined to small *windows* of the 64-bit domain
//! (`2^w` consecutive values placed at the low end, the top end, and across
//! the i64/i32/u32 sign/truncation boundaries), which makes the input space
//! exhaustively enumerable while still exercising carries, wrap-around,
//! sign extension and truncation exactly as deployed.
//!
//! The concrete semantics used as the ground truth mirror `interp.rs`'s ALU
//! and JMP evaluation (wrapping ops, div-by-zero → 0, mod-by-zero → dst,
//! shift amounts masked by the width).
//!
//! Widths are tuned so `cargo test` (debug) stays in seconds; the heaviest
//! sweeps are `#[ignore]`d — run them with
//! `cargo test --release -- --ignored soundness`.

use crate::insn::{alu, jmp};
use crate::tnum::Tnum;
use crate::verifier::{
    alu_scalar, analyze_cond_jmp, scalar_endian, scalar_movsx, CondOutcome, Scalar,
};
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Tnum enumeration and concretization
// ---------------------------------------------------------------------------

fn wf(t: Tnum) -> bool {
    t.value & t.mask == 0
}

/// All well-formed tnums whose value and mask are confined to the `w` low
/// bits, shifted left by `shift`. `3^w` entries.
fn tnums_at(w: u32, shift: u32) -> Vec<Tnum> {
    let mut out = Vec::new();
    for mask in 0..(1u64 << w) {
        let free = !mask & ((1u64 << w) - 1);
        // iterate all subsets of `free` (the known bits), including 0
        let mut v = 0u64;
        loop {
            out.push(Tnum {
                value: v << shift,
                mask: mask << shift,
            });
            v = v.wrapping_sub(free) & free;
            if v == 0 {
                break;
            }
        }
    }
    out
}

/// γ(t): every concrete value the tnum represents. `2^popcount(mask)` values.
fn gamma_t(t: Tnum) -> Vec<u64> {
    let mut out = Vec::with_capacity(1usize << t.mask.count_ones());
    let mut s = 0u64;
    loop {
        out.push(t.value | s);
        s = s.wrapping_sub(t.mask) & t.mask;
        if s == 0 {
            break;
        }
    }
    out
}

fn tnum_pool(w: u32, shift: u32) -> Vec<(Tnum, Vec<u64>)> {
    tnums_at(w, shift)
        .into_iter()
        .map(|t| (t, gamma_t(t)))
        .collect()
}

/// ∀ a, b in the pools, ∀ x∈γ(a), y∈γ(b): conc(x,y) ∈ γ(abs(a,b)).
fn check_tnum_binop(
    name: &str,
    ta: &[(Tnum, Vec<u64>)],
    tb: &[(Tnum, Vec<u64>)],
    abs: impl Fn(Tnum, Tnum) -> Tnum,
    conc: impl Fn(u64, u64) -> u64,
) {
    for (a, ga) in ta {
        for (b, gb) in tb {
            let r = abs(*a, *b);
            assert!(wf(r), "{name}: ill-formed result {r:?} from {a} x {b}");
            for &x in ga {
                for &y in gb {
                    let v = conc(x, y);
                    assert!(
                        r.contains(v),
                        "{name}: conc({x:#x},{y:#x}) = {v:#x} not in {r} = abs({a}, {b})"
                    );
                }
            }
        }
    }
}

fn tnum_binops_at(w: u32, shift: u32) {
    let p = tnum_pool(w, shift);
    check_tnum_binop("tnum add", &p, &p, |a, b| a.add(b), u64::wrapping_add);
    check_tnum_binop("tnum sub", &p, &p, |a, b| a.sub(b), u64::wrapping_sub);
    check_tnum_binop("tnum mul", &p, &p, |a, b| a.mul(b), u64::wrapping_mul);
    check_tnum_binop("tnum and", &p, &p, |a, b| a.and(b), |x, y| x & y);
    check_tnum_binop("tnum or", &p, &p, |a, b| a.or(b), |x, y| x | y);
    check_tnum_binop("tnum xor", &p, &p, |a, b| a.xor(b), |x, y| x ^ y);
}

#[test]
fn tnum_binops_sound_w6_low() {
    tnum_binops_at(6, 0);
}

#[test]
fn tnum_binops_sound_w6_top() {
    // top of u64: carries out of bit 63 wrap; sub borrows wrap the other way
    tnum_binops_at(6, 58);
}

#[test]
fn tnum_binops_sound_w6_straddle32() {
    // window straddling the 32-bit boundary: carries cross bit 32
    tnum_binops_at(6, 29);
}

/// Add/sub with operands in *different* windows: carry chains have to travel
/// through the known-zero gap between the windows.
#[test]
fn tnum_binops_sound_cross_window() {
    let lo = tnum_pool(4, 0);
    let hi = tnum_pool(4, 60);
    check_tnum_binop("tnum add x", &lo, &hi, |a, b| a.add(b), u64::wrapping_add);
    check_tnum_binop("tnum add x", &hi, &lo, |a, b| a.add(b), u64::wrapping_add);
    check_tnum_binop("tnum sub x", &lo, &hi, |a, b| a.sub(b), u64::wrapping_sub);
    check_tnum_binop("tnum sub x", &hi, &lo, |a, b| a.sub(b), u64::wrapping_sub);
    check_tnum_binop("tnum mul x", &lo, &hi, |a, b| a.mul(b), u64::wrapping_mul);
}

/// Full w=8 sweep of the binary tnum ops (3^8 x 3^8 abstract pairs,
/// ~4.3e9 concretization checks per op). Run with:
/// `cargo test --release -- --ignored soundness`
#[test]
#[ignore = "heavy: run with cargo test --release -- --ignored"]
fn tnum_binops_sound_w8_exhaustive() {
    tnum_binops_at(8, 0);
    tnum_binops_at(8, 56);
}

#[test]
fn tnum_shifts_sound_w8() {
    for shift in [0u32, 56, 28] {
        for (t, g) in tnum_pool(8, shift) {
            for sh in 0..64u8 {
                let l = t.lshift(sh);
                let r = t.rshift(sh);
                let a64 = t.arshift(sh, 64);
                assert!(wf(l) && wf(r) && wf(a64));
                for &x in &g {
                    assert!(l.contains(x << sh), "lshift {t} by {sh}: {x:#x}");
                    assert!(r.contains(x >> sh), "rshift {t} by {sh}: {x:#x}");
                    let v = ((x as i64) >> sh) as u64;
                    assert!(a64.contains(v), "arshift64 {t} by {sh}: {x:#x}");
                }
            }
            // 32-bit arshift truncates the input itself; concrete result is
            // the zero-extended 32-bit arithmetic shift (interp semantics)
            for sh in 0..32u8 {
                let a32 = t.arshift(sh, 32);
                assert!(wf(a32));
                for &x in &g {
                    let v = ((x as u32 as i32) >> sh) as u32 as u64;
                    assert!(a32.contains(v), "arshift32 {t} by {sh}: {x:#x}");
                }
            }
        }
    }
}

#[test]
fn tnum_cast_sound_w8() {
    for shift in [0u32, 28, 56] {
        for (t, g) in tnum_pool(8, shift) {
            for size in [1u8, 2, 4, 8] {
                let c = t.cast(size);
                assert!(wf(c));
                let keep = if size == 8 {
                    u64::MAX
                } else {
                    (1u64 << (size * 8)) - 1
                };
                for &x in &g {
                    assert!(c.contains(x & keep), "cast({size}) {t}: {x:#x}");
                }
            }
            let s = t.subreg();
            for &x in &g {
                assert!(s.contains(x & 0xffff_ffff));
            }
        }
    }
}

#[test]
fn tnum_range_sound_w8() {
    // range(min,max) must contain every value in [min,max]
    for base in [0u64, u64::MAX - 255, (1u64 << 63) - 128, (1u64 << 32) - 128] {
        for i in 0..=255u64 {
            for j in i..=255u64 {
                let (lo, hi) = (base + i, base + j);
                let t = Tnum::range(lo, hi);
                assert!(wf(t));
                for x in lo..=hi {
                    assert!(x < lo || t.contains(x), "range({lo:#x},{hi:#x}): {x:#x}");
                }
            }
        }
    }
}

#[test]
fn tnum_set_ops_sound_w6() {
    tnum_set_ops_at(6, 0);
    tnum_set_ops_at(6, 58);
}

#[test]
#[ignore = "heavy: run with cargo test --release -- --ignored"]
fn tnum_set_ops_sound_w8_exhaustive() {
    tnum_set_ops_at(8, 0);
    tnum_set_ops_at(8, 56);
}

fn tnum_set_ops_at(w: u32, shift: u32) {
    let p = tnum_pool(w, shift);
    for (a, ga) in &p {
        for (b, _) in &p {
            let i = a.intersect(*b);
            let u = a.union(*b);
            assert!(wf(u), "union {a} {b}");
            // intersect: x in γ(a) ∩ γ(b) => x in γ(a ∩ b).
            // (intersect may return an ill-formed tnum when the operands are
            // contradictory — the kernel documents that the caller must know
            // they overlap; Scalar::sync() then reports the contradiction.)
            for &x in ga {
                if b.contains(x) {
                    assert!(wf(i), "intersect {a} {b} overlaps at {x:#x} but ill-formed");
                    assert!(i.contains(x), "intersect {a} {b}: {x:#x}");
                }
                // union: γ(a) ∪ γ(b) ⊆ γ(a ∪ b); by symmetry checking γ(a)
                // against both orders covers γ(b) too
                assert!(u.contains(x), "union {a} {b}: {x:#x}");
                assert!(b.union(*a).contains(x), "union {b} {a}: {x:#x}");
            }
            // is_subset_of: claimed subset => γ inclusion
            if a.is_subset_of(b) {
                for &x in ga {
                    assert!(b.contains(x), "{a} claimed subset of {b} but {x:#x} escapes");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Scalar (tnum + u/s range) abstract states
// ---------------------------------------------------------------------------

fn contains_s(s: &Scalar, v: u64) -> bool {
    s.tnum.contains(v)
        && s.umin <= v
        && v <= s.umax
        && s.smin <= (v as i64)
        && (v as i64) <= s.smax
        && s.umin32 <= v as u32
        && (v as u32) <= s.umax32
        && s.smin32 <= v as u32 as i32
        && (v as u32 as i32) <= s.smax32
}

#[derive(Clone)]
struct AState {
    s: Scalar,
    g: Vec<u64>,
}

/// Raw (pre-`sync`) abstract-state candidates whose u-range lies inside the
/// window `[base, base + 2^w)`, together with the window's value list.
///
/// For 2^w-aligned bases this enumerates ALL `(umin, umax, tnum)`-consistent
/// states over the window (every window tnum x every u-range), each with the
/// signed bounds both untightened (i64 full range: what `sync` derives) and
/// exact (the tightest consistent signed range). With `full_signed`, every
/// consistent `(smin, smax)` pair over the window is enumerated as well. The
/// dedicated 32-bit fields start unconstrained here; independently tight
/// subregister states are covered by [`pool_mixed32`].
fn window_candidates(w: u32, base: u64, full_signed: bool) -> (Vec<u64>, Vec<Scalar>) {
    let n = 1u64 << w;
    assert!(base.checked_add(n - 1).is_some(), "window wraps u64");
    let vals: Vec<u64> = (0..n).map(|k| base + k).collect();
    let aligned = base & (n - 1) == 0;
    let all_tn: Vec<Tnum> = if aligned {
        tnums_at(w, 0)
            .into_iter()
            .map(|t| Tnum {
                value: base | t.value,
                mask: t.mask,
            })
            .collect()
    } else {
        Vec::new()
    };
    let mut out = Vec::new();
    for i in 0..vals.len() {
        for j in i..vals.len() {
            let (lo, hi) = (vals[i], vals[j]);
            let cands: Vec<Tnum> = if aligned {
                all_tn.clone()
            } else {
                // unaligned windows (sign/truncation straddles): no common
                // known-bit prefix, use the tnums the verifier itself builds
                vec![
                    Tnum::range(lo, hi),
                    Tnum::const_val(lo),
                    Tnum::const_val(hi),
                    Tnum::unknown(),
                ]
            };
            for t in cands {
                let mk = |smin: i64, smax: i64| Scalar {
                    tnum: t,
                    umin: lo,
                    umax: hi,
                    smin,
                    smax,
                    umin32: 0,
                    umax32: u32::MAX,
                    smin32: i32::MIN,
                    smax32: i32::MAX,
                };
                // signed bounds untightened: sync derives them
                out.push(mk(i64::MIN, i64::MAX));
                // exact signed bounds of the u-and-tnum-consistent values
                let (mut smin, mut smax) = (i64::MAX, i64::MIN);
                for &v in &vals[i..=j] {
                    if t.contains(v) {
                        smin = smin.min(v as i64);
                        smax = smax.max(v as i64);
                    }
                }
                if smin <= smax {
                    out.push(mk(smin, smax));
                }
                if full_signed {
                    for &p in &vals {
                        for &q in &vals {
                            if (p as i64) <= (q as i64) {
                                out.push(mk(p as i64, q as i64));
                            }
                        }
                    }
                }
            }
        }
    }
    (vals, out)
}

/// Synced, deduplicated, non-empty abstract states over the window.
fn window_states(w: u32, base: u64, full_signed: bool) -> Vec<AState> {
    let (vals, cands) = window_candidates(w, base, full_signed);
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for mut s in cands {
        if !s.sync() {
            continue;
        }
        let g: Vec<u64> = vals.iter().copied().filter(|&v| contains_s(&s, v)).collect();
        if g.is_empty() {
            continue;
        }
        if seen.insert((s.tnum.value, s.tnum.mask, s.umin, s.umax, s.smin, s.smax)) {
            out.push(AState { s, g });
        }
    }
    out
}

/// Windows for 64-bit ops: low end, top end (all-negative i64, wraps on
/// add), i64 sign straddle.
fn pool64(w: u32) -> Vec<AState> {
    let mut p = window_states(w, 0, false);
    p.extend(window_states(w, u64::MAX - (1u64 << w) + 1, false));
    p.extend(window_states(w, (1u64 << 63) - (1u64 << (w - 1)), false));
    p
}

/// Windows for 32-bit ops: low end, top of u32 (negative as i32), i32 sign
/// straddle, u32 truncation straddle (values above u32::MAX).
fn pool32(w: u32) -> Vec<AState> {
    let mut p = window_states(w, 0, false);
    p.extend(window_states(w, (1u64 << 32) - (1u64 << w), false));
    p.extend(window_states(w, (1u64 << 31) - (1u64 << (w - 1)), false));
    p.extend(window_states(w, (1u64 << 32) - (1u64 << (w - 1)), false));
    p
}

/// States with several unrelated upper halves but a tight low-32 interval.
/// This is the shape produced by a JMP32 refinement of a u64 load and cannot
/// be represented by a single contiguous 64-bit range alone.
fn pool_mixed32(w: u32) -> Vec<AState> {
    let n = 1u64 << w;
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for base in [0u64, (1u64 << 31) - n / 2, (1u64 << 32) - n] {
        let lows: Vec<u32> = (0..n).map(|v| (base + v) as u32).collect();
        for i in 0..lows.len() {
            for j in i..lows.len() {
                let mut g = Vec::new();
                for hi in [0u64, 1, u32::MAX as u64] {
                    for &lo in &lows[i..=j] {
                        g.push((hi << 32) | lo as u64);
                    }
                }
                let mut s = Scalar::unknown();
                s.umin = *g.iter().min().unwrap();
                s.umax = *g.iter().max().unwrap();
                s.umin32 = lows[i];
                s.umax32 = lows[j];
                let slo = lows[i] as i32;
                let shi = lows[j] as i32;
                if slo <= shi {
                    s.smin32 = slo;
                    s.smax32 = shi;
                }
                assert!(g.iter().all(|&v| contains_s(&s, v)));
                if !s.sync() {
                    continue;
                }
                for &v in &g {
                    assert!(
                        contains_s(&s, v),
                        "mixed sync removed {v:#x} from {s:?}"
                    );
                }
                let mut s2 = s;
                assert!(s2.sync(), "second mixed sync contradicted {s:?}");
                assert_eq!(s, s2, "mixed sync not idempotent");
                if !g.is_empty()
                    && seen.insert((
                        s.tnum.value,
                        s.tnum.mask,
                        s.umin,
                        s.umax,
                        s.smin,
                        s.smax,
                        s.umin32,
                        s.umax32,
                        s.smin32,
                        s.smax32,
                    ))
                {
                    out.push(AState { s, g });
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Concrete ALU / JMP semantics (ground truth; mirrors interp.rs)
// ---------------------------------------------------------------------------

fn conc_alu(op: u8, is32: bool, soff: bool, a: u64, b: u64) -> u64 {
    if is32 {
        let (a, b) = (a as u32, b as u32);
        (match op {
            alu::ADD => a.wrapping_add(b),
            alu::SUB => a.wrapping_sub(b),
            alu::MUL => a.wrapping_mul(b),
            alu::DIV => {
                if soff {
                    let (a, b) = (a as i32, b as i32);
                    if b == 0 { 0 } else { a.wrapping_div(b) as u32 }
                } else {
                    a.checked_div(b).unwrap_or(0)
                }
            }
            alu::MOD => {
                if soff {
                    let (a, b) = (a as i32, b as i32);
                    if b == 0 { a as u32 } else { a.wrapping_rem(b) as u32 }
                } else {
                    a.checked_rem(b).unwrap_or(a)
                }
            }
            alu::OR => a | b,
            alu::AND => a & b,
            alu::XOR => a ^ b,
            alu::LSH => a.wrapping_shl(b),
            alu::RSH => a.wrapping_shr(b),
            alu::ARSH => ((a as i32).wrapping_shr(b)) as u32,
            _ => unreachable!(),
        }) as u64
    } else {
        match op {
            alu::ADD => a.wrapping_add(b),
            alu::SUB => a.wrapping_sub(b),
            alu::MUL => a.wrapping_mul(b),
            alu::DIV => {
                if soff {
                    let (a, b) = (a as i64, b as i64);
                    if b == 0 { 0 } else { a.wrapping_div(b) as u64 }
                } else {
                    a.checked_div(b).unwrap_or(0)
                }
            }
            alu::MOD => {
                if soff {
                    let (a, b) = (a as i64, b as i64);
                    if b == 0 { a as u64 } else { a.wrapping_rem(b) as u64 }
                } else {
                    a.checked_rem(b).unwrap_or(a)
                }
            }
            alu::OR => a | b,
            alu::AND => a & b,
            alu::XOR => a ^ b,
            alu::LSH => a.wrapping_shl(b as u32),
            alu::RSH => a.wrapping_shr(b as u32),
            alu::ARSH => ((a as i64).wrapping_shr(b as u32)) as u64,
            _ => unreachable!(),
        }
    }
}

fn conc_cmp(op: u8, is32: bool, a: u64, b: u64) -> bool {
    if is32 {
        let (a, b) = (a as u32, b as u32);
        let (sa, sb) = (a as i32, b as i32);
        match op {
            jmp::JEQ => a == b,
            jmp::JNE => a != b,
            jmp::JGT => a > b,
            jmp::JGE => a >= b,
            jmp::JLT => a < b,
            jmp::JLE => a <= b,
            jmp::JSGT => sa > sb,
            jmp::JSGE => sa >= sb,
            jmp::JSLT => sa < sb,
            jmp::JSLE => sa <= sb,
            jmp::JSET => a & b != 0,
            _ => unreachable!(),
        }
    } else {
        let (sa, sb) = (a as i64, b as i64);
        match op {
            jmp::JEQ => a == b,
            jmp::JNE => a != b,
            jmp::JGT => a > b,
            jmp::JGE => a >= b,
            jmp::JLT => a < b,
            jmp::JLE => a <= b,
            jmp::JSGT => sa > sb,
            jmp::JSGE => sa >= sb,
            jmp::JSLT => sa < sb,
            jmp::JSLE => sa <= sb,
            jmp::JSET => a & b != 0,
            _ => unreachable!(),
        }
    }
}

// ---------------------------------------------------------------------------
// ALU transfer-function soundness (alu_scalar as deployed)
// ---------------------------------------------------------------------------

fn check_alu_op(op: u8, is32: bool, soff: bool, pool: &[AState]) {
    let shift_op = matches!(op, alu::LSH | alu::RSH | alu::ARSH);
    for a in pool {
        for b in pool {
            let r = match alu_scalar(op, is32, soff, a.s, b.s) {
                Ok(r) => r,
                Err(_) => {
                    // the verifier REJECTS the program here (a verdict, not a
                    // transfer); only const oversize shifts may do that
                    assert!(
                        shift_op,
                        "alu op {op:#x} rejected non-shift inputs {} {}",
                        a.s, b.s
                    );
                    continue;
                }
            };
            assert!(wf(r.tnum), "alu {op:#x}: ill-formed tnum from {} {}", a.s, b.s);
            for &x in &a.g {
                for &y in &b.g {
                    let v = conc_alu(op, is32, soff, x, y);
                    assert!(
                        contains_s(&r, v),
                        "alu op {op:#x} is32={is32} soff={soff}: \
                         conc({x:#x},{y:#x}) = {v:#x} escapes {r} = abs({}, {})",
                        a.s,
                        b.s
                    );
                }
            }
        }
    }
}

const ALU_W_DEBUG: u32 = 3;
const ALU_W_HEAVY: u32 = 4;

macro_rules! alu_test {
    ($name:ident, $op:expr, $soff:expr) => {
        #[test]
        fn $name() {
            check_alu_op($op, false, $soff, &pool64(ALU_W_DEBUG));
            check_alu_op($op, true, $soff, &pool32(ALU_W_DEBUG));
        }
    };
}

alu_test!(alu_add_sound, alu::ADD, false);
alu_test!(alu_sub_sound, alu::SUB, false);
alu_test!(alu_mul_sound, alu::MUL, false);
alu_test!(alu_div_sound, alu::DIV, false);
alu_test!(alu_sdiv_sound, alu::DIV, true);
alu_test!(alu_mod_sound, alu::MOD, false);
alu_test!(alu_smod_sound, alu::MOD, true);
alu_test!(alu_and_sound, alu::AND, false);
alu_test!(alu_or_sound, alu::OR, false);
alu_test!(alu_xor_sound, alu::XOR, false);
alu_test!(alu_lsh_sound, alu::LSH, false);
alu_test!(alu_rsh_sound, alu::RSH, false);
alu_test!(alu_arsh_sound, alu::ARSH, false);

#[test]
#[ignore = "heavy: run with cargo test --release -- --ignored"]
fn alu_all_sound_w4_exhaustive() {
    let p64 = pool64(ALU_W_HEAVY);
    let p32 = pool32(ALU_W_HEAVY);
    for (op, soff) in [
        (alu::ADD, false),
        (alu::SUB, false),
        (alu::MUL, false),
        (alu::DIV, false),
        (alu::DIV, true),
        (alu::MOD, false),
        (alu::MOD, true),
        (alu::AND, false),
        (alu::OR, false),
        (alu::XOR, false),
        (alu::LSH, false),
        (alu::RSH, false),
        (alu::ARSH, false),
    ] {
        check_alu_op(op, false, soff, &p64);
        check_alu_op(op, true, soff, &p32);
    }
}

/// The complete consistent-state space (independent signed bounds included)
/// at w=3, low window plus each straddle window.
#[test]
fn alu_full_state_space_w3() {
    let mut p64 = window_states(3, 0, true);
    p64.extend(window_states(3, (1u64 << 63) - 4, true));
    let mut p32 = window_states(3, 0, true);
    p32.extend(window_states(3, (1u64 << 31) - 4, true));
    p32.extend(window_states(3, (1u64 << 32) - 4, true));
    for (op, soff) in [(alu::ADD, false), (alu::SUB, false), (alu::AND, false)] {
        check_alu_op(op, false, soff, &p64);
        check_alu_op(op, true, soff, &p32);
    }
}

// ---------------------------------------------------------------------------
// Branch decision + refinement soundness (analyze_cond_jmp as deployed)
// ---------------------------------------------------------------------------

/// Obligations:
/// - `Decided(t)`: EVERY concrete pair must compare to `t`.
/// - `Both`: for every concrete pair, the outcome it realizes must not have
///   been declared dead, and the refined scalars must still contain it.
fn check_branch_op(op: u8, is32: bool, pool: &[AState]) {
    for a in pool {
        for b in pool {
            match analyze_cond_jmp(op, is32, a.s, b.s) {
                CondOutcome::Decided(t) => {
                    for &x in &a.g {
                        for &y in &b.g {
                            assert_eq!(
                                conc_cmp(op, is32, x, y),
                                t,
                                "jmp op {op:#x} is32={is32}: decided {t} but \
                                 x={x:#x} y={y:#x} disagrees (a={}, b={})",
                                a.s,
                                b.s
                            );
                        }
                    }
                }
                CondOutcome::Both(refined) => {
                    for &x in &a.g {
                        for &y in &b.g {
                            let taken = conc_cmp(op, is32, x, y);
                            let Some((ra, rb)) = refined[taken as usize] else {
                                panic!(
                                    "jmp op {op:#x} is32={is32}: outcome {taken} \
                                     declared dead but x={x:#x} y={y:#x} realizes \
                                     it (a={}, b={})",
                                    a.s, b.s
                                );
                            };
                            assert!(
                                contains_s(&ra, x) && contains_s(&rb, y),
                                "jmp op {op:#x} is32={is32} taken={taken}: \
                                 x={x:#x} y={y:#x} escapes refinement \
                                 ra={ra} rb={rb} (a={}, b={})",
                                a.s,
                                b.s
                            );
                        }
                    }
                }
            }
        }
    }
}

const JMP_W_DEBUG: u32 = 3;
const JMP_W_HEAVY: u32 = 4;

macro_rules! jmp_test {
    ($name:ident, $op:expr) => {
        #[test]
        fn $name() {
            check_branch_op($op, false, &pool64(JMP_W_DEBUG));
            check_branch_op($op, true, &pool32(JMP_W_DEBUG));
        }
    };
}

jmp_test!(jmp_jeq_sound, jmp::JEQ);
jmp_test!(jmp_jne_sound, jmp::JNE);
jmp_test!(jmp_jgt_sound, jmp::JGT);
jmp_test!(jmp_jge_sound, jmp::JGE);
jmp_test!(jmp_jlt_sound, jmp::JLT);
jmp_test!(jmp_jle_sound, jmp::JLE);
jmp_test!(jmp_jsgt_sound, jmp::JSGT);
jmp_test!(jmp_jsge_sound, jmp::JSGE);
jmp_test!(jmp_jslt_sound, jmp::JSLT);
jmp_test!(jmp_jsle_sound, jmp::JSLE);
jmp_test!(jmp_jset_sound, jmp::JSET);

#[test]
#[ignore = "heavy: run with cargo test --release -- --ignored"]
fn jmp_all_sound_w4_exhaustive() {
    let p64 = pool64(JMP_W_HEAVY);
    let p32 = pool32(JMP_W_HEAVY);
    for op in [
        jmp::JEQ,
        jmp::JNE,
        jmp::JGT,
        jmp::JGE,
        jmp::JLT,
        jmp::JLE,
        jmp::JSGT,
        jmp::JSGE,
        jmp::JSLT,
        jmp::JSLE,
        jmp::JSET,
    ] {
        check_branch_op(op, false, &p64);
        check_branch_op(op, true, &p32);
    }
}

/// Full consistent-state space (independent signed bounds) for the signed
/// comparisons, at the sign straddles where they are most fragile.
#[test]
fn jmp_signed_full_state_space_w3() {
    let mut p64 = window_states(3, 0, true);
    p64.extend(window_states(3, (1u64 << 63) - 4, true));
    p64.extend(window_states(3, u64::MAX - 7, true));
    let mut p32 = window_states(3, 0, true);
    p32.extend(window_states(3, (1u64 << 31) - 4, true));
    p32.extend(window_states(3, (1u64 << 32) - 8, true));
    for op in [jmp::JSGT, jmp::JSGE, jmp::JSLT, jmp::JSLE, jmp::JEQ, jmp::JNE] {
        check_branch_op(op, false, &p64);
        check_branch_op(op, true, &p32);
    }
}

#[test]
fn jmp_mixed_upper_halves_w3() {
    let p = pool_mixed32(3);
    for op in [
        jmp::JEQ,
        jmp::JNE,
        jmp::JGT,
        jmp::JGE,
        jmp::JLT,
        jmp::JLE,
        jmp::JSGT,
        jmp::JSGE,
        jmp::JSLT,
        jmp::JSLE,
        jmp::JSET,
    ] {
        check_branch_op(op, true, &p);
        check_branch_op(op, false, &p);
    }
}

#[test]
fn alu_low32_local_ops_mixed_upper_halves_w3() {
    let p = pool_mixed32(3);
    for op in [alu::ADD, alu::SUB, alu::MUL, alu::AND, alu::OR, alu::XOR] {
        check_alu_op(op, false, false, &p);
        check_alu_op(op, true, false, &p);
    }
}

#[test]
fn alu_nonlocal_ops_mixed_upper_halves_w3() {
    let p = pool_mixed32(3);
    for op in [alu::DIV, alu::MOD, alu::LSH, alu::RSH, alu::ARSH] {
        check_alu_op(op, false, false, &p);
        check_alu_op(op, true, false, &p);
    }
    for op in [alu::DIV, alu::MOD] {
        check_alu_op(op, false, true, &p);
        check_alu_op(op, true, true, &p);
    }
}

// ---------------------------------------------------------------------------
// Unary transfers: truncation, sign-extension, endianness
// ---------------------------------------------------------------------------

#[test]
fn truncate32_sound() {
    let mixed = pool_mixed32(3);
    for a in pool32(4).iter().chain(pool64(4).iter()).chain(&mixed) {
        let r = a.s.truncate32();
        assert!(wf(r.tnum));
        for &x in &a.g {
            let v = x as u32 as u64;
            assert!(contains_s(&r, v), "truncate32({}) misses {v:#x}", a.s);
        }
    }
}

#[test]
fn movsx_sound() {
    // 64-bit MOVSX: truncate to `bits`, then sign-extend to 64
    let sext = |x: u64, bits: u16| -> u64 {
        match bits {
            8 => x as u8 as i8 as i64 as u64,
            16 => x as u16 as i16 as i64 as u64,
            _ => x as u32 as i32 as i64 as u64,
        }
    };
    let mixed = pool_mixed32(3);
    for a in pool64(4).iter().chain(pool32(4).iter()).chain(&mixed) {
        for bits in [8u16, 16, 32] {
            let r = scalar_movsx(a.s, bits);
            assert!(wf(r.tnum));
            for &x in &a.g {
                let v = sext(x, bits);
                assert!(contains_s(&r, v), "movsx{bits}({}) misses {v:#x}", a.s);
            }
            // 32-bit MOVSX as deployed (verifier MOV32 with offset):
            // truncate32 . movsx . truncate32; concrete result zero-extended
            if bits < 32 {
                let r = scalar_movsx(a.s.truncate32(), bits).truncate32();
                for &x in &a.g {
                    let v = sext(x, bits) as u32 as u64;
                    assert!(contains_s(&r, v), "movsx32/{bits}({}) misses {v:#x}", a.s);
                }
            }
        }
    }
}

#[test]
fn endian_sound() {
    let mixed = pool_mixed32(3);
    for a in pool64(4).iter().chain(pool32(4).iter()).chain(&mixed) {
        for width in [16i32, 32, 64] {
            for is_swap in [false, true] {
                let mut r = scalar_endian(is_swap, width, a.s);
                r.sync();
                assert!(wf(r.tnum));
                for &x in &a.g {
                    let v = if is_swap {
                        match width {
                            16 => (x as u16).swap_bytes() as u64,
                            32 => (x as u32).swap_bytes() as u64,
                            _ => x.swap_bytes(),
                        }
                    } else {
                        match width {
                            16 => x as u16 as u64,
                            32 => x as u32 as u64,
                            _ => x,
                        }
                    };
                    assert!(
                        contains_s(&r, v),
                        "endian swap={is_swap} w={width} ({}) misses {v:#x}",
                        a.s
                    );
                }
            }
        }
    }
}

#[test]
fn from_tnum_sound() {
    for shift in [0u32, 56, 28] {
        for (t, g) in tnum_pool(6, shift) {
            let s = Scalar::from_tnum(t);
            for &x in &g {
                assert!(contains_s(&s, x), "from_tnum({t}) misses {x:#x}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Internal consistency invariants
// ---------------------------------------------------------------------------

/// `sync` must never REMOVE concrete values (γ_after ⊇ γ_before — dropping a
/// realizable value is unsound), must report a contradiction only when γ is
/// empty, and must be idempotent. Growth of γ is permitted: on contradictory
/// tnum/range inputs `tnum_intersect` may invent values (the kernel documents
/// that its caller must know the operands overlap), which widens a dead
/// state — a precision loss, never a soundness loss.
#[test]
fn sync_preserves_gamma_and_is_idempotent() {
    for (w, base, fs) in [
        (4u32, 0u64, false),
        (4, u64::MAX - 15, false),
        (4, (1u64 << 63) - 8, false),
        (4, (1u64 << 32) - 8, false),
        (3, 0, true),
        (3, (1u64 << 63) - 4, true),
    ] {
        let (vals, cands) = window_candidates(w, base, fs);
        for raw in cands {
            let g_raw: Vec<u64> = vals
                .iter()
                .copied()
                .filter(|&v| contains_s(&raw, v))
                .collect();
            let mut s = raw;
            let ok = s.sync();
            if !ok {
                assert!(
                    g_raw.is_empty(),
                    "sync reported contradiction but γ nonempty for {raw:?}"
                );
                continue;
            }
            assert!(wf(s.tnum), "sync produced ill-formed tnum for {raw:?}");
            for &v in &g_raw {
                assert!(
                    contains_s(&s, v),
                    "sync removed {v:#x} from γ of {raw:?} -> {s:?}"
                );
            }
            let mut s2 = s;
            assert!(s2.sync(), "second sync reported contradiction for {s:?}");
            assert_eq!(s, s2, "sync not idempotent for {raw:?}");
        }
    }
}

/// `a ⊆ b` (as claimed by is_subset_of) must imply γ(a) ⊆ γ(b); the verifier's
/// pruning is unsound without this.
#[test]
fn scalar_subset_sound() {
    for pool in [pool64(4), pool32(4), pool_mixed32(3)] {
        for a in &pool {
            for b in &pool {
                if a.s.is_subset_of(&b.s) {
                    for &x in &a.g {
                        assert!(
                            contains_s(&b.s, x),
                            "{} claimed subset of {} but {x:#x} escapes",
                            a.s,
                            b.s
                        );
                    }
                }
            }
        }
    }
}

/// join is an upper bound: γ(a) ∪ γ(b) ⊆ γ(a ⊔ b).
#[test]
fn scalar_join_sound() {
    for pool in [pool64(3), pool32(3), pool_mixed32(3)] {
        for a in &pool {
            for b in &pool {
                let j = a.s.join(&b.s);
                assert!(wf(j.tnum));
                for &x in a.g.iter().chain(b.g.iter()) {
                    assert!(
                        contains_s(&j, x),
                        "join({}, {}) = {j} misses {x:#x}",
                        a.s,
                        b.s
                    );
                }
                // join result must also be accepted as a superset by pruning
                assert!(
                    a.s.is_subset_of(&j) && b.s.is_subset_of(&j),
                    "join({}, {}) = {j} not a superset per is_subset_of",
                    a.s,
                    b.s
                );
            }
        }
    }
}
