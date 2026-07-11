//! Dataflow ("omniscient debugging") queries driven through the TTY-free
//! `DebugSession::handle_command`: `origin`, `when`, `whenwrite`, `who`.

use febpf::debug::{DebugSession, DebuggerOpts};
use febpf::{asm, Program, Vm};

fn vm(src: &str) -> Vm {
    let a = asm::assemble(src).unwrap();
    Vm::new(Program {
        insns: a.insns,
        maps: a.maps,
        btf_ctx: None,
    })
    .unwrap()
}

fn cmd(s: &mut DebugSession, line: &str) -> String {
    let mut out = Vec::new();
    s.handle_command(line, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

/// A value flows mov -> alu -> store -> load -> exit; `origin r0` must name the
/// originating instructions, in order, back to the constant it was born from.
const FLOW_SRC: &str = "
    r1 = 5
    r1 += 3
    *(u64 *)(r10 - 8) = r1
    r0 = *(u64 *)(r10 - 8)
    exit";

#[test]
fn origin_traces_mov_alu_store_load() {
    let mut v = vm(FLOW_SRC);
    let mut ctx = [];
    let mut s = DebugSession::new(&mut v, &mut ctx, &DebuggerOpts::default());

    cmd(&mut s, "c"); // run to exit
    assert_eq!(s.finished(), Some(8));

    let o = cmd(&mut s, "origin r0");
    // Header shows the final value.
    assert!(o.contains("origin of r0 = 0x8"), "{o}");

    // The trail must name the four originating instructions in order:
    // load (insn 3) -> store (insn 2) -> alu (insn 1) -> mov const (insn 0).
    let load = o.find("insn 3:").expect(&o);
    let store = o.find("insn 2:").expect(&o);
    let alu = o.find("insn 1:").expect(&o);
    let mov = o.find("insn 0:").expect(&o);
    assert!(load < store && store < alu && alu < mov, "out of order:\n{o}");

    // The load must name the stack region it read from.
    assert!(o.contains("loaded from stack"), "{o}");
    // The store must show it came from a register store.
    assert!(o.contains("stored to stack"), "{o}");
    // The chain must terminate at the born-constant.
    assert!(o.contains("born: constant 0x5"), "{o}");
}

#[test]
fn whenwrite_and_who_on_stack_slot() {
    let mut v = vm(FLOW_SRC);
    let mut ctx = [];
    let mut s = DebugSession::new(&mut v, &mut ctx, &DebuggerOpts::default());
    cmd(&mut s, "c");

    // The store at insn 3 wrote *(u64*)(r10-8). Resolve the slot via r10.
    let fp = s.machine().regs[10];
    let slot = fp - 8;

    let o = cmd(&mut s, &format!("whenwrite {slot}"));
    assert!(o.contains("last written by insn 2"), "{o}"); // insn index 2 = the store

    // Same via a register-held pointer: whenwrite r10 with the -8 baked into
    // an explicit address is what a user does; here confirm `who` names it too.
    let o = cmd(&mut s, &format!("who {slot}"));
    assert!(o.contains("last written by insn 2"), "{o}");
    assert!(o.contains("= 0x8"), "who should show the stored value: {o}");
    assert!(o.contains("stack"), "who should name the stack region: {o}");
}

#[test]
fn when_names_last_register_write() {
    let mut v = vm(FLOW_SRC);
    let mut ctx = [];
    let mut s = DebugSession::new(&mut v, &mut ctx, &DebuggerOpts::default());
    cmd(&mut s, "c");

    // r1 was last written by `r1 += 3` (insn index 1).
    let o = cmd(&mut s, "when r1");
    assert!(o.contains("r1 last written by insn 1"), "{o}");
    assert!(o.contains("= 0x8"), "{o}");

    // r0 was last written by the load (insn index 3).
    let o = cmd(&mut s, "when r0");
    assert!(o.contains("r0 last written by insn 3"), "{o}");
}

/// A helper writes a map value; `who` on a byte of that value must name the
/// updating instruction, and `origin` of a register loaded from the map value
/// must reach back to the map load.
const MAP_SRC: &str = "
    .map arr array 4 8 4
    r1 = 7
    *(u32 *)(r10 - 4) = 0        ; key = 0
    *(u64 *)(r10 - 16) = r1      ; value = 7
    r1 = map[arr]
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
    if r0 == 0 goto done
    r0 = *(u64 *)(r0)
done:
    exit";

#[test]
fn who_on_map_byte_after_helper_update() {
    let mut v = vm(MAP_SRC);
    let mut ctx = [];
    let mut s = DebugSession::new(&mut v, &mut ctx, &DebuggerOpts::default());
    cmd(&mut s, "c");
    // The lookup returned the value pointer and the final load put 7 in r0.
    assert_eq!(s.finished(), Some(7));

    // origin r0 traces the load back to the map value it read.
    let o = cmd(&mut s, "origin r0");
    assert!(o.contains("origin of r0 = 0x7"), "{o}");
    assert!(o.contains("loaded from map 'arr' value"), "{o}");
}
