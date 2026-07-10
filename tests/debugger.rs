//! Drives the debugger's command handling without a TTY.

use febpf::debug::{DebugSession, DebuggerOpts, Outcome};
use febpf::{asm, Program, Vm};

fn vm(src: &str) -> Vm {
    let a = asm::assemble(src).unwrap();
    Vm::new(Program {
        insns: a.insns,
        maps: a.maps,
    })
    .unwrap()
}

/// Run one command, returning its output and the outcome.
fn cmd(s: &mut DebugSession, line: &str) -> (String, Outcome) {
    let mut out = Vec::new();
    let outcome = s.handle_command(line, &mut out).unwrap();
    (String::from_utf8(out).unwrap(), outcome)
}

const LOOP_SRC: &str = "
    r0 = 0
    r2 = 10
loop:
    r0 += r2
    r2 -= 1
    if r2 != 0 goto loop
    exit";

#[test]
fn step_break_continue() {
    let mut v = vm(LOOP_SRC);
    let mut ctx = [];
    let mut s = DebugSession::new(&mut v, &mut ctx, &DebuggerOpts::default());

    let (o, _) = cmd(&mut s, "step 2");
    assert!(o.contains("2:"), "should sit at insn 2 after 2 steps: {o}");
    assert_eq!(s.machine().insn_count, 2);
    assert_eq!(s.machine().regs[2], 10);

    let (o, _) = cmd(&mut s, "b 3");
    assert!(o.contains("breakpoint set at 3"));

    let (o, _) = cmd(&mut s, "c");
    assert!(o.contains("breakpoint hit at 3"), "{o}");
    assert_eq!(s.machine().pc, 3);
    assert_eq!(s.machine().regs[0], 10); // first r0 += r2 done

    let (o, _) = cmd(&mut s, "delete 3");
    assert!(!o.contains("usage"));
    let (o, _) = cmd(&mut s, "continue");
    assert!(o.contains("program exited with r0 = 55"), "{o}");
    assert_eq!(s.finished(), Some(55));

    // Session survives program exit; forward stepping refuses politely.
    let (o, _) = cmd(&mut s, "step");
    assert!(o.contains("program has exited"), "{o}");

    match cmd(&mut s, "quit").1 {
        Outcome::Quit(r0) => assert_eq!(r0, Some(55)),
        _ => panic!("quit should quit"),
    }
}

#[test]
fn regs_and_info_output() {
    let mut v = vm(LOOP_SRC);
    let mut ctx = [];
    let mut s = DebugSession::new(&mut v, &mut ctx, &DebuggerOpts::default());
    cmd(&mut s, "s 2");
    let (o, _) = cmd(&mut s, "regs");
    assert!(o.contains("r2 = 0x000000000000000a") || o.contains("r2 = 0x0"), "{o}");
    assert!(o.contains("pc = 2"), "{o}");
    cmd(&mut s, "break 5");
    let (o, _) = cmd(&mut s, "info");
    assert!(o.contains("[5]"), "{o}");
    let (o, _) = cmd(&mut s, "bogus");
    assert!(o.contains("unknown command"), "{o}");
}

#[test]
fn runtime_error_is_reported_not_fatal() {
    // Wild pointer dereference: clean runtime error, session stays usable.
    let mut v = vm("r1 = 0\n r0 = *(u64 *)(r1 + 0)\n exit");
    let mut ctx = [];
    let mut s = DebugSession::new(&mut v, &mut ctx, &DebuggerOpts::default());
    let (o, _) = cmd(&mut s, "c");
    assert!(o.contains("runtime error"), "{o}");
    let (o, _) = cmd(&mut s, "regs");
    assert!(o.contains("pc = "), "{o}");
}
