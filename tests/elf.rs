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
fn jit_matches_interpreter_on_objects() {
    for (file, prog, ctx_len) in [
        ("tests/legacy_maps.o", "socket", 64),
        ("tests/btf_maps.o", "xdp", 64),
        ("tests/subprog.o", "socket", 8),
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
