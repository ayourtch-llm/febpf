//! Source-level debug info surfaced from `.BTF`/`.BTF.ext` of real
//! `clang -g -target bpf` objects. Normal tests use committed `.o` fixtures;
//! `FEBPF_REGENERATE_FIXTURES=1` rebuilds them explicitly.

mod common;

use febpf::debug::{DebugSession, DebuggerOpts, Outcome};
use febpf::debuginfo::DebugInfo;
use febpf::{elf, Program, Vm};

fn maybe_compile(src: &str, out: &str, opt: &str) {
    common::maybe_compile(src, out, opt);
}

fn debug_of<'a>(obj: &'a elf::Object, prog: &str) -> &'a DebugInfo {
    obj.programs
        .iter()
        .find(|p| p.name == prog)
        .unwrap_or_else(|| panic!("no program '{prog}'"))
        .debug
        .as_ref()
        .expect("no debug info (was the object compiled with -g?)")
}

fn load(path: &str) -> elf::Object {
    let bytes = std::fs::read(path).unwrap();
    elf::load(&bytes).unwrap()
}

/// Build a `Vm` from one program of an object, with its debug info attached.
fn vm_of(path: &str, prog: &str) -> Vm {
    let bytes = std::fs::read(path).unwrap();
    let mut obj = elf::load(&bytes).unwrap();
    let idx = obj.programs.iter().position(|p| p.name == prog).unwrap();
    let p = obj.programs.swap_remove(idx);
    let mut vm = Vm::new(Program {
        insns: p.insns,
        maps: obj.maps,
        btf_ctx: None,
    })
    .unwrap();
    if let Some(di) = p.debug {
        vm.set_debug(di);
    }
    vm
}

/// Run one debugger command, returning captured output.
fn cmd(s: &mut DebugSession, line: &str) -> String {
    let mut out = Vec::new();
    let outcome = s.handle_command(line, &mut out).unwrap();
    assert!(matches!(outcome, Outcome::Continue | Outcome::Quit(_)));
    String::from_utf8(out).unwrap()
}

#[test]
fn line_info_and_text_stitching() {
    // -O0 so the cross-.text call to `triple` survives (see HANDOFF).
    maybe_compile("subprog.c", "subprog.o", "-O0");
    let obj = load("tests/subprog.o");
    let di = debug_of(&obj, "socket");

    // Entry section (`prog`) maps at instruction 0.
    let l0 = di.line_at(0).expect("line for insn 0");
    assert!(l0.file.ends_with("subprog.c"), "file was {}", l0.file);
    assert!(
        l0.text.contains("int prog"),
        "insn 0 line text: {:?}",
        l0.text
    );

    // The `.text` subprogram `triple` is stitched after `prog`; its line
    // records must land at text_base (> 0), not at offset 0.
    let triple = di
        .func_at(9)
        .expect("func at a stitched-.text instruction");
    assert_eq!(triple.name, "triple");
    // `prog` is the entry function at 0.
    assert_eq!(di.func_at(0).unwrap().name, "prog");
    // Somewhere in triple's body we see `return x + x + x;`.
    let body: Vec<&str> = di
        .lines()
        .iter()
        .filter(|l| l.insn >= triple.insn)
        .map(|l| l.text.as_str())
        .collect();
    assert!(
        body.iter().any(|t| t.contains("x + x + x")),
        "triple body lines: {body:?}"
    );
}

#[test]
fn globals_metadata_and_rendering() {
    maybe_compile("global_data.c", "global_data.o", "-O2");
    let obj = load("tests/global_data.o");
    let di = debug_of(&obj, "socket");

    // Named globals from the DATASECs, mapped to their data-section maps.
    let bss = di.global("bss_counter").expect("bss_counter global");
    assert_eq!(bss.map_name, ".bss");
    assert_eq!(bss.offset, 0);
    let data = di.global("data_scale").expect("data_scale global");
    assert_eq!(data.map_name, ".data");

    // Typed rendering through the BTF graph: `long` renders as a signed int.
    assert_eq!(di.render_value(bss.type_id, &7i64.to_le_bytes()), "7");
    assert_eq!(di.render_value(data.type_id, &(-3i64).to_le_bytes()), "-3");

    // ro_table is a `const int[4]`: rendered one level deep.
    let ro = di.global("ro_table").expect("ro_table global");
    let mut bytes = Vec::new();
    for v in [10i32, 20, 30, 40] {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    assert_eq!(di.render_value(ro.type_id, &bytes), "[10, 20, 30, 40]");
}

#[test]
fn debugger_shows_source_and_steps() {
    maybe_compile("subprog.c", "subprog.o", "-O0");
    let mut v = vm_of("tests/subprog.o", "socket");
    let mut ctx = vec![0u8; 8];
    let mut s = DebugSession::new(&mut v, &mut ctx, &DebuggerOpts::default());

    // Position banner carries the C source line and function name.
    let mut out = Vec::new();
    s.print_position(&mut out).unwrap();
    let banner = String::from_utf8(out).unwrap();
    assert!(banner.contains("prog at"), "banner: {banner}");
    assert!(banner.contains("subprog.c:11"), "banner: {banner}");

    // `steps` from line 11 lands on the next distinct source line (13).
    let o = cmd(&mut s, "steps");
    assert!(o.contains("subprog.c:13"), "steps -> {o}");

    // `steps` again descends into `triple` (line 5 then 7).
    let o = cmd(&mut s, "steps");
    assert!(o.contains("triple"), "steps into triple -> {o}");

    // Backtrace now shows the two-level call stack.
    let o = cmd(&mut s, "bt");
    assert!(o.contains("#0  triple"), "bt: {o}");
    assert!(o.contains("#1  prog"), "bt: {o}");
}

#[test]
fn debugger_nexts_steps_over_call() {
    maybe_compile("subprog.c", "subprog.o", "-O0");
    let mut v = vm_of("tests/subprog.o", "socket");
    let mut ctx = vec![0u8; 8];
    let mut s = DebugSession::new(&mut v, &mut ctx, &DebuggerOpts::default());

    cmd(&mut s, "steps"); // to the call line (13)
    // `nexts` steps over triple; the program has nothing after the call but
    // the return, so it runs to exit without ever showing `triple`.
    let o = cmd(&mut s, "nexts");
    assert!(!o.contains("triple at"), "nexts entered triple: {o}");
    assert!(o.contains("exited") || o.contains("13"), "nexts: {o}");
    assert!(s.machine().current_frame() == 0);
}

#[test]
fn debugger_print_global_by_name() {
    maybe_compile("global_data.c", "global_data.o", "-O2");
    let mut v = vm_of("tests/global_data.o", "socket");
    let mut ctx = vec![5u8, 0, 0, 0]; // ctx word = 5 -> idx = 5 & 3 = 1
    let mut s = DebugSession::new(&mut v, &mut ctx, &DebuggerOpts::default());

    cmd(&mut s, "c"); // run to completion; globals now hold final values

    // ro_table[1] == 20 added to bss_counter.
    let o = cmd(&mut s, "print bss_counter");
    assert!(o.contains("bss_counter: long = 20"), "print bss: {o}");
    // data_scale started at 3, += 1.
    let o = cmd(&mut s, "print data_scale");
    assert!(o.contains("data_scale: long = 4"), "print data: {o}");
    // Typed array rendering, one level deep.
    let o = cmd(&mut s, "print ro_table");
    assert!(o.contains("[10, 20, 30, 40]"), "print ro_table: {o}");
    // Unknown name is reported, not a panic.
    let o = cmd(&mut s, "print nope");
    assert!(o.contains("no global named 'nope'"), "print nope: {o}");

    // Listing all globals with `print` (no arg).
    let o = cmd(&mut s, "print");
    assert!(o.contains("bss_counter") && o.contains("data_scale"), "list: {o}");
}

#[test]
fn debugger_reverse_source_step() {
    maybe_compile("subprog.c", "subprog.o", "-O0");
    let mut v = vm_of("tests/subprog.o", "socket");
    let mut ctx = vec![0u8; 8];
    let mut s = DebugSession::new(&mut v, &mut ctx, &DebuggerOpts::default());

    cmd(&mut s, "steps"); // line 13
    cmd(&mut s, "steps"); // into triple, line 5
    cmd(&mut s, "steps"); // line 7
    let o = cmd(&mut s, "rsteps"); // back to line 5
    assert!(o.contains("subprog.c:5"), "rsteps: {o}");
}

#[test]
fn analysis_source_interleaving() {
    maybe_compile("subprog.c", "subprog.o", "-O0");
    let obj = load("tests/subprog.o");
    let di = debug_of(&obj, "socket");
    let prog = obj.programs.iter().find(|p| p.name == "socket").unwrap();

    // Plain source-interleaved disassembly.
    let listing = febpf::analysis::source_listing(&prog.insns, di);
    assert!(listing.contains("; ---- prog ----"), "no func header:\n{listing}");
    assert!(listing.contains("; ---- triple ----"), "no triple header:\n{listing}");
    assert!(listing.contains("return x + x + x"), "no source text:\n{listing}");
    // Each distinct source line appears once (deduped), not per instruction.
    assert_eq!(listing.matches("return x + x + x").count(), 1);

    // Heatmap interleaves source too.
    let counts = vec![1u64; prog.insns.len()];
    let heat = febpf::analysis::heatmap_listing(&prog.insns, &counts, Some(di));
    assert!(heat.contains("subprog.c:13"), "heatmap missing source:\n{heat}");
}
