#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn temp_dir(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "febpf-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn programs_lists_elf_entries_and_static_links_in_loader_order() {
    let output = Command::new(env!("CARGO_BIN_EXE_febpf"))
        .args(["programs", "tests/tail_call.o"])
        .output()
        .expect("run febpf programs");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "program\t0\tsocket\tsocket/target\n\
         program\t1\tsocket\tsocket/entry\n\
         link\tprogs\t0\tsocket/target\n"
    );
}

#[test]
fn scanner_counts_a_non_default_rejection_and_preserves_section_names() {
    let temp = temp_dir("corpus-scan");
    let mock = temp.join("febpf-mock");
    let object = temp.join("multi.o");
    let report = temp.join("report.txt");
    fs::write(&object, b"mock object").unwrap();
    fs::write(
        &mock,
        r#"#!/usr/bin/env bash
set -u
if [ "$1" = programs ]; then
    printf 'program\t0\tother\tfirst/name\n'
    printf 'program\t1\tother\tsecond:name\n'
    printf 'program\t2\tsocket\tsocket/legacy\n'
    exit 0
fi
prog=
legacy=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --prog) prog="$2"; shift 2 ;;
        --legacy-packet) legacy=1; shift 2 ;;
        *) shift ;;
    esac
done
case "$prog" in
    first/name) printf 'verification PASSED\n' ;;
    second:name) printf 'verification FAILED: at insn 0: call to unknown helper #999\n' ;;
    socket/legacy)
        if [ "$legacy" -eq 1 ]; then
            printf 'verification PASSED\n'
        else
            printf 'verification FAILED: at insn 0: legacy packet access (opcode 0x20) is not supported\n'
        fi
        ;;
    *) printf 'error: unexpected program %s\n' "$prog" >&2; exit 1 ;;
esac
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&mock).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&mock, permissions).unwrap();

    let output = Command::new("bash")
        .arg("scripts/scan-corpus.sh")
        .arg(&object)
        .env("NO_BUILD", "1")
        .env("FEBPF", &mock)
        .env("TARGET_BTF", temp.join("missing-btf"))
        .env("CORPUS_REPORT", &report)
        .output()
        .expect("run corpus scanner");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let report = fs::read_to_string(report).unwrap();
    assert!(report.contains("objects/families scanned  : 1"), "{report}");
    assert!(report.contains("objects fully compatible  : 0  (0.0%)"), "{report}");
    assert!(report.contains("entry programs scanned    : 3"), "{report}");
    assert!(report.contains("entries verified OK       : 2  (66.7%)"), "{report}");
    assert!(report.contains("second:name"), "{report}");
    assert!(report.contains("VERIFY-REJECT:unsupported-helper:#999"), "{report}");
    assert!(report.contains("socket/legacy"), "{report}");

    fs::remove_dir_all(temp).unwrap();
}
