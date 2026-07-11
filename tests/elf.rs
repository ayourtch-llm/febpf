//! Tests for the ELF object loader, using real `clang -target bpf` output.
//!
//! The `.o` fixtures under `tests/` were produced by clang from the sources in
//! `examples/c/`. When clang is available the fixtures are regenerated first so
//! the tests always track the current toolchain; otherwise the committed
//! fixtures are used as-is.

use febpf::verifier::Config;
use febpf::{elf, Program, Vm};
use std::path::Path;
use std::process::Command;

fn maybe_compile(src: &str, out: &str) {
    if Command::new("clang").arg("--version").output().is_err() {
        return; // no clang; use the committed fixture
    }
    let src_path = format!("examples/c/{src}");
    if !Path::new(&src_path).exists() {
        return;
    }
    let opt = if src == "subprog.c" { "-O0" } else { "-O2" };
    let status = Command::new("clang")
        .args([opt, "-g", "-target", "bpf", "-c", &src_path, "-o"])
        .arg(format!("tests/{out}"))
        .status();
    assert!(
        status.map(|s| s.success()).unwrap_or(false),
        "clang failed to compile {src}"
    );
}

fn load(path: &str) -> elf::Object {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    elf::load(&bytes).unwrap_or_else(|e| panic!("load {path}: {e}"))
}

fn run_prog(obj: &elf::Object, prog_name: &str, ctx: &mut [u8]) -> u64 {
    let prog = obj
        .programs
        .iter()
        .find(|p| p.name == prog_name)
        .unwrap_or_else(|| panic!("no program '{prog_name}'"));
    let mut vm = Vm::new(Program {
        insns: prog.insns.clone(),
        maps: obj.maps.clone(),
    })
    .unwrap();
    vm.verify(Config {
        ctx_size: ctx.len(),
        ..Default::default()
    })
    .expect("verification failed");
    vm.run(ctx).unwrap()
}

#[test]
fn legacy_maps_object() {
    maybe_compile("legacy_maps.c", "legacy_maps.o");
    let obj = load("tests/legacy_maps.o");
    assert_eq!(obj.maps.len(), 1);
    let m = &obj.maps[0];
    assert_eq!(m.name, "counts");
    assert_eq!(m.kind, febpf::maps::MapKind::Hash);
    assert_eq!((m.key_size, m.value_size, m.max_entries), (4, 8, 16));
    // first call inserts 100
    assert_eq!(run_prog(&obj, "socket", &mut [0u8; 64]), 100);
}

#[test]
fn btf_maps_object() {
    maybe_compile("btf_maps.c", "btf_maps.o");
    let obj = load("tests/btf_maps.o");
    assert_eq!(obj.maps.len(), 1);
    let m = &obj.maps[0];
    assert_eq!(m.name, "scratch");
    assert_eq!(m.kind, febpf::maps::MapKind::Array);
    assert_eq!((m.key_size, m.value_size, m.max_entries), (4, 8, 4));
    // *v starts at 0, += 5 -> 5
    assert_eq!(run_prog(&obj, "xdp", &mut [0u8; 64]), 5);
}

#[test]
fn cross_text_bpf_to_bpf_call() {
    maybe_compile("subprog.c", "subprog.o");
    let obj = load("tests/subprog.o");
    // triple(14) = 42, via a call into a .text subprogram
    assert_eq!(run_prog(&obj, "socket", &mut [0u8; 8]), 42);
}

#[test]
fn global_data_object() {
    maybe_compile("global_data.c", "global_data.o");
    let obj = load("tests/global_data.o");

    // .rodata* (frozen, initialized), .data (initialized), .bss (zero).
    let ro = obj
        .maps
        .iter()
        .find(|m| m.name.starts_with(".rodata") && m.value_size == 16)
        .expect("no .rodata table map");
    assert!(ro.readonly);
    assert_eq!(ro.init.len(), 16);
    assert_eq!(ro.init[0..4], 10i32.to_le_bytes());
    let data = obj.maps.iter().find(|m| m.name == ".data").expect("no .data map");
    assert!(!data.readonly);
    assert_eq!(data.init, 3i64.to_le_bytes());
    let bss = obj.maps.iter().find(|m| m.name == ".bss").expect("no .bss map");
    assert!(!bss.readonly);
    assert!(bss.init.is_empty());
    assert_eq!(bss.value_size, 8);

    // Globals persist across runs of the same VM:
    // run 1 (idx 0): bss = 10, scale = 4  -> 10 + 400 = 410
    // run 2 (idx 0): bss = 20, scale = 5  -> 20 + 500 = 520
    let prog = obj.programs.iter().find(|p| p.name == "socket").unwrap();
    let mut vm = Vm::new(Program {
        insns: prog.insns.clone(),
        maps: obj.maps.clone(),
    })
    .unwrap();
    vm.verify(Config {
        ctx_size: 64,
        ..Default::default()
    })
    .expect("verification failed");
    assert_eq!(vm.run(&mut [0u8; 64]).unwrap(), 410);
    assert_eq!(vm.run(&mut [0u8; 64]).unwrap(), 520);
    // the printk format string lives in .rodata.str1.1
    assert_eq!(vm.printk, vec!["count=10".to_string(), "count=20".to_string()]);

    // ctx selects the table index: idx 3 -> bss = 40, scale = 4 -> 440
    let mut vm2 = Vm::new(Program {
        insns: prog.insns.clone(),
        maps: obj.maps.clone(),
    })
    .unwrap();
    vm2.verify(Config {
        ctx_size: 64,
        ..Default::default()
    })
    .unwrap();
    let mut ctx = [0u8; 64];
    ctx[0] = 3;
    assert_eq!(vm2.run(&mut ctx).unwrap(), 440);
}

#[cfg(feature = "jit")]
#[test]
fn jit_matches_interpreter_on_objects() {
    for (file, prog, ctx_len) in [
        ("tests/legacy_maps.o", "socket", 64),
        ("tests/btf_maps.o", "xdp", 64),
        ("tests/subprog.o", "socket", 8),
        ("tests/global_data.o", "socket", 64),
    ] {
        let obj = load(file);
        let mut i_ctx = vec![0u8; ctx_len];
        let interp = run_prog(&obj, prog, &mut i_ctx);

        let p = obj.programs.iter().find(|p| p.name == prog).unwrap();
        let mut vm = Vm::new(Program {
            insns: p.insns.clone(),
            maps: obj.maps.clone(),
        })
        .unwrap();
        vm.verify(Config {
            ctx_size: ctx_len,
            ..Default::default()
        })
        .unwrap();
        let mut j_ctx = vec![0u8; ctx_len];
        let jit = vm.run_jit(&mut j_ctx).unwrap();
        assert_eq!(interp, jit, "{file}: interp {interp} != jit {jit}");
    }
}
