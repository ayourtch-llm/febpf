//! Source-level debug info surfaced from `.BTF`/`.BTF.ext` of real
//! `clang -g -target bpf` objects. Regenerates fixtures when clang is present
//! (like tests/elf.rs), else uses the committed `.o`.

use febpf::debuginfo::DebugInfo;
use febpf::elf;
use std::path::Path;
use std::process::Command;

fn maybe_compile(src: &str, out: &str, opt: &str) {
    if Command::new("clang").arg("--version").output().is_err() {
        return;
    }
    let src_path = format!("examples/c/{src}");
    if !Path::new(&src_path).exists() {
        return;
    }
    let status = Command::new("clang")
        .args([opt, "-g", "-target", "bpf", "-c", &src_path, "-o"])
        .arg(format!("tests/{out}"))
        .status();
    assert!(
        status.map(|s| s.success()).unwrap_or(false),
        "clang failed to compile {src}"
    );
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
