//! Time-travel debugging: snapshot/replay determinism and the reverse
//! debugger commands built on it.

use febpf::debug::{DebugSession, DebuggerOpts};
use febpf::{asm, Program, Vm};

fn vm(src: &str) -> Vm {
    let a = asm::assemble(src).unwrap();
    Vm::new(Program {
        insns: a.insns,
        maps: a.maps,
    })
    .unwrap()
}

/// Exercises everything a snapshot must capture: array + hash map updates,
/// lazy map-value regions (lookup), prandom state, bpf-to-bpf call frames,
/// ctx writes, stack traffic and trace_printk.
const BUSY_SRC: &str = "
    .map arr array 4 8 4
    .map h hash 4 8 8
    r7 = r1             ; ctx pointer
    r6 = 10             ; loop counter
loop:
    r1 = r6
    r1 &= 3
    *(u32 *)(r10 - 4) = r1
    call get_prandom_u32
    *(u64 *)(r10 - 16) = r0
    r1 = map[arr]
    r2 = r10
    r2 += -4
    r3 = r10
    r3 += -16
    r4 = 0
    call map_update_elem
    r1 = map[h]
    r2 = r10
    r2 += -4
    r3 = r10
    r3 += -16
    r4 = 0
    call map_update_elem
    r1 = map[arr]
    r2 = r10
    r2 += -4
    call map_lookup_elem
    if r0 == 0 goto skip
    r1 = *(u64 *)(r0)
    r2 = r6
    call mix
    *(u64 *)(r7 + 0) = r0
skip:
    r6 -= 1
    if r6 != 0 goto loop
    r1 = r7
    r2 = 4
    call trace_printk
    r0 = *(u64 *)(r7 + 0)
    exit
mix:
    r0 = r1
    r0 ^= r2
    r0 *= 31
    exit";

#[test]
fn replay_from_snapshot_matches_straight_run() {
    // Reference run: snapshots at every step.
    let mut ref_vm = vm(BUSY_SRC);
    let mut ref_ctx = vec![0u8; 16];
    let mut m = ref_vm.machine(&mut ref_ctx);
    let mut states = vec![m.snapshot()];
    let ret = loop {
        match m.step().unwrap() {
            Some(r0) => {
                states.push(m.snapshot()); // post-exit state
                break r0;
            }
            None => states.push(m.snapshot()),
        }
    };
    let total = states.len() as u64 - 1; // counts after each step
    assert!(total > 50, "want a busy program, got {total} steps");

    // Second machine: snapshot at k, run on to n, then rewind to the snapshot
    // and replay — every intermediate state must match the reference run.
    let (k, n) = (total / 3, 2 * total / 3);
    let mut vm2 = vm(BUSY_SRC);
    let mut ctx2 = vec![0u8; 16];
    let mut m2 = vm2.machine(&mut ctx2);
    m2.run_to_count(k).unwrap();
    let snap_k = m2.snapshot();
    assert_eq!(snap_k, states[k as usize], "state at k differs across VMs");

    m2.run_to_count(n).unwrap();
    assert_eq!(m2.snapshot(), states[n as usize]);

    // Rewind and replay to n: identical state again.
    m2.restore(&snap_k);
    assert_eq!(m2.snapshot(), states[k as usize]);
    m2.run_to_count(n).unwrap();
    assert_eq!(m2.snapshot(), states[n as usize], "replay diverged");

    // Replay through to completion: same r0, same final state.
    let r0 = m2.run_to_count(u64::MAX).unwrap();
    assert_eq!(r0, Some(ret));
    assert_eq!(m2.snapshot(), *states.last().unwrap());
}

#[test]
fn restore_rewinds_map_and_ctx_side_effects() {
    let mut v = vm(BUSY_SRC);
    let mut ctx = vec![0u8; 16];
    let mut m = v.machine(&mut ctx);
    let base = m.snapshot();
    m.run_to_count(u64::MAX).unwrap();
    assert_ne!(m.snapshot(), base, "program should have side effects");
    m.restore(&base);
    assert_eq!(m.snapshot(), base);
    drop(m);
    // Maps and printk are visibly reset on the VM as well.
    assert!(v.printk.is_empty());
    assert!(v.maps[1].iter_entries().is_empty()); // hash map emptied
    assert_eq!(ctx, vec![0u8; 16]);
}

#[test]
fn nondet_helper_calls_are_counted() {
    let mut v = vm("call ktime_get_ns\n r0 = 0\n exit");
    let mut ctx = [];
    let mut m = v.machine(&mut ctx);
    assert_eq!(m.nondet_calls, 0);
    m.run_to_count(u64::MAX).unwrap();
    assert_eq!(m.nondet_calls, 1);
}

// ---------------------------------------------------------------- debugger

/// Run one command through the session, returning its output.
fn cmd(s: &mut DebugSession, line: &str) -> String {
    let mut out = Vec::new();
    s.handle_command(line, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

/// A tiny snapshot interval so short tests still exercise checkpointing.
fn opts() -> DebuggerOpts {
    DebuggerOpts {
        echo_printk: false,
        snapshot_interval: 3,
        ..Default::default()
    }
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
fn rstep_matches_fresh_run() {
    let mut v1 = vm(LOOP_SRC);
    let mut c1 = [];
    let mut s = DebugSession::new(&mut v1, &mut c1, &opts());
    cmd(&mut s, "step 11");
    assert_eq!(s.machine().insn_count, 11);
    let o = cmd(&mut s, "rstep 4");
    assert!(!o.contains("error"), "{o}");
    assert_eq!(s.machine().insn_count, 7);

    // A machine stepped 7 times from scratch must agree exactly.
    let mut v2 = vm(LOOP_SRC);
    let mut c2 = [];
    let mut m2 = v2.machine(&mut c2);
    m2.run_to_count(7).unwrap();
    assert_eq!(s.machine().snapshot(), m2.snapshot());

    // rstep 1 at a time down to 0.
    cmd(&mut s, "rstep 7");
    assert_eq!(s.machine().insn_count, 0);
    let o = cmd(&mut s, "rstep");
    assert!(o.contains("already at the start"), "{o}");
}

#[test]
fn reverse_from_program_exit() {
    let mut v = vm(LOOP_SRC);
    let mut c = [];
    let mut s = DebugSession::new(&mut v, &mut c, &opts());
    let o = cmd(&mut s, "continue");
    assert!(o.contains("exited with r0 = 55"), "{o}");
    assert_eq!(s.finished(), Some(55));
    let exit_count = s.machine().insn_count;

    // Step back before the exit: the session is live again.
    cmd(&mut s, "rstep 2");
    assert_eq!(s.finished(), None);
    assert_eq!(s.machine().insn_count, exit_count - 2);
    // And forward again to the same exit.
    let o = cmd(&mut s, "continue");
    assert!(o.contains("exited with r0 = 55"), "{o}");
    assert_eq!(s.machine().insn_count, exit_count);
    // goto past the end clamps to the exit.
    cmd(&mut s, "rstep 3");
    let o = cmd(&mut s, "goto 99999");
    assert!(o.contains("program ends after"), "{o}");
    assert_eq!(s.machine().insn_count, exit_count);
    assert_eq!(s.finished(), Some(55));
}

#[test]
fn rcontinue_returns_to_previous_breakpoint() {
    let mut v = vm(LOOP_SRC);
    let mut c = [];
    let mut s = DebugSession::new(&mut v, &mut c, &opts());
    cmd(&mut s, "break 2");
    cmd(&mut s, "continue"); // first hit: pc 2 at count 2
    assert_eq!(s.machine().insn_count, 2);
    cmd(&mut s, "continue"); // second hit: count 5
    assert_eq!(s.machine().insn_count, 5);
    cmd(&mut s, "continue"); // third hit: count 8
    assert_eq!(s.machine().insn_count, 8);

    let o = cmd(&mut s, "rcontinue");
    assert!(o.contains("breakpoint hit at 2"), "{o}");
    assert_eq!(s.machine().insn_count, 5);
    assert_eq!(s.machine().pc, 2);

    // No breakpoint earlier than count 2's hit besides itself: rcontinue
    // twice more lands at the start.
    cmd(&mut s, "rcontinue");
    assert_eq!(s.machine().insn_count, 2);
    let o = cmd(&mut s, "rcontinue");
    assert!(o.contains("start of the program"), "{o}");
    assert_eq!(s.machine().insn_count, 0);
}

const MAPWRITE_SRC: &str = "
    .map m array 4 8 1
    r6 = 3              ; a few quiet iterations first
warmup:
    r6 -= 1
    if r6 != 0 goto warmup
    r0 = 0
    *(u32 *)(r10 - 4) = r0
    r1 = 7
    *(u64 *)(r10 - 16) = r1
    r1 = map[m]
    r2 = r10
    r2 += -4
    r3 = r10
    r3 += -16
    r4 = 0
    call map_update_elem   ; <-- the write the watchpoint must catch
    r5 = 5
    r5 += 1
    r0 = r5
    exit";

#[test]
fn watchpoint_triggers_on_map_write_and_rcontinue_finds_it() {
    let mut v = vm(MAPWRITE_SRC);
    let mut c = [];
    let mut s = DebugSession::new(&mut v, &mut c, &opts());

    let o = cmd(&mut s, "watch map m 0");
    assert!(o.contains("watchpoint 1 set"), "{o}");

    let o = cmd(&mut s, "continue");
    assert!(o.contains("watchpoint 1"), "{o}");
    assert!(o.contains("changed by insn"), "{o}");
    assert!(o.contains("0000000000000000 -> 0700000000000000"), "{o}");
    let hit_count = s.machine().insn_count;

    // Run on to the end, then reverse-continue straight back to the write.
    let o = cmd(&mut s, "continue");
    assert!(o.contains("exited"), "{o}");
    let o = cmd(&mut s, "rcontinue");
    assert!(o.contains("watchpoint 1"), "{o}");
    assert!(o.contains("changed by insn"), "{o}");
    assert_eq!(s.machine().insn_count, hit_count, "rcontinue must land on the write");

    // Nothing changed the map before that: reverse again reaches the start.
    let o = cmd(&mut s, "rcontinue");
    assert!(o.contains("start of the program"), "{o}");
}

#[test]
fn watch_raw_stack_address() {
    // fp-16 is written by insn 6 (count 7). Watch it via raw address.
    let mut v = vm(MAPWRITE_SRC);
    let mut c = [];
    let mut s = DebugSession::new(&mut v, &mut c, &opts());
    let fp = s.machine().regs[10];
    let o = cmd(&mut s, &format!("watch {:#x} 8", fp - 16));
    assert!(o.contains("watchpoint 1 set"), "{o}");
    let o = cmd(&mut s, "c");
    assert!(o.contains("watchpoint 1"), "{o}");
    assert!(o.contains("-> 0700000000000000"), "{o}");
    // unwatch, and continue runs to completion.
    cmd(&mut s, "unwatch 1");
    let o = cmd(&mut s, "c");
    assert!(o.contains("exited"), "{o}");
}

#[test]
fn nondet_warning_on_reverse() {
    let mut v = vm("call ktime_get_ns\n r6 = r0\n r0 = 0\n exit");
    let mut c = [];
    let mut s = DebugSession::new(&mut v, &mut c, &opts());
    cmd(&mut s, "step 2");
    let o = cmd(&mut s, "rstep");
    assert!(o.contains("warning") && o.contains("non-deterministic"), "{o}");
    // warned only once
    cmd(&mut s, "step");
    let o = cmd(&mut s, "rstep");
    assert!(!o.contains("warning"), "{o}");
}
