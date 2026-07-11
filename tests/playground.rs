//! End-to-end tests for the playground back-end (the layer the WASM ABI wraps).
//! These run under both `cargo test` and `cargo test --no-default-features`.

use febpf::playground::{analyze_text, disasm_text, run_text, verify_text, Session};

const SUM_LOOP: &[u8] = b"r0 = 0\nr1 = 10\nloop:\nr0 += r1\nr1 -= 1\nif r1 != 0 goto loop\nexit\n";

#[test]
fn verify_accepts_good_program() {
    let out = verify_text(SUM_LOOP);
    assert!(out.contains("PASSED"), "{out}");
}

#[test]
fn verify_rejects_and_shows_counterexample() {
    // r0 is never initialised before exit -> rejected.
    let out = verify_text(b"exit\n");
    assert!(out.contains("FAILED"), "{out}");
    assert!(out.contains("counterexample"), "{out}");
    assert!(out.contains(">>"), "should point at the failing insn:\n{out}");
}

#[test]
fn run_reports_r0() {
    let out = run_text(SUM_LOOP, "");
    assert!(out.contains("r0 = 55"), "{out}");
}

#[test]
fn disasm_roundtrips_somewhat() {
    let out = disasm_text(SUM_LOOP);
    assert!(out.contains("exit"), "{out}");
    assert!(out.contains("goto"), "{out}");
}

#[test]
fn analyze_modes() {
    // annotated
    assert!(analyze_text(SUM_LOOP, 0).contains("basic blocks"));
    // DOT
    assert!(analyze_text(SUM_LOOP, 1).contains("digraph"));
    // heatmap (runs the program; the loop body is hot)
    let heat = analyze_text(SUM_LOOP, 2);
    assert!(!heat.is_empty(), "{heat}");
}

#[test]
fn debug_session_time_travel() {
    let mut s = Session::new(SUM_LOOP, "").unwrap();
    let a = s.command("step 5");
    assert!(a.contains("insn count 5") || a.contains("exited"), "{a}");
    // step forward, then rewind, and confirm the register file matches a fresh
    // replay to the same count (determinism / time travel).
    s.command("goto 4");
    let regs_at_4 = s.command("regs");
    s.command("step 3");
    s.command("rstep 3");
    let regs_back = s.command("regs");
    assert_eq!(regs_at_4, regs_back, "rstep must reproduce earlier state");
    assert!(regs_back.contains("insns executed = 4"), "{regs_back}");
}

#[test]
fn debug_session_reaches_exit() {
    let mut s = Session::new(SUM_LOOP, "").unwrap();
    let out = s.command("continue");
    assert!(out.contains("r0 = 55"), "{out}");
}

#[test]
fn debug_help_and_bad_command() {
    let mut s = Session::new(SUM_LOOP, "").unwrap();
    assert!(s.command("help").contains("time travel"));
    assert!(s.command("frobnicate").contains("unknown command"));
}
