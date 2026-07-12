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
fn programs_lists_each_global_entry_in_a_shared_section() {
    let output = Command::new(env!("CARGO_BIN_EXE_febpf"))
        .args(["programs", "tests/multi_entry.o"])
        .output()
        .expect("run febpf programs");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "program\t0\txdp\tfirst_entry\nprogram\t1\txdp\tsecond_entry\n"
    );

    for name in ["first_entry", "second_entry"] {
        let verify = Command::new(env!("CARGO_BIN_EXE_febpf"))
            .args(["verify", "tests/multi_entry.o", "--prog", name])
            .output()
            .expect("select shared-section entry");
        assert!(
            verify.status.success(),
            "{}",
            String::from_utf8_lossy(&verify.stderr)
        );
        assert!(String::from_utf8_lossy(&verify.stdout).contains("verification PASSED"));
    }
}

#[test]
fn scanner_counts_a_non_default_rejection_and_preserves_section_names() {
    let temp = temp_dir("corpus-scan");
    let mock = temp.join("febpf-mock");
    let object = temp.join("inspektor-gadget__audit_seccomp.o");
    let report = temp.join("report.txt");
    fs::write(&object, b"mock object").unwrap();
    fs::write(
        &mock,
        r#"#!/usr/bin/env bash
set -u
if [ "$1" = programs ]; then
    case " $* " in
        *" --map-max-entries ig_build_id=1024 "*) ;;
        *) printf 'error: missing Gadget map override\n' >&2; exit 1 ;;
    esac
    printf 'program\t0\tother\tfirst/name\n'
    printf 'program\t1\tother\tsecond:name\n'
    printf 'program\t2\tsocket\tsocket/legacy\n'
    exit 0
fi
prog=
legacy=0
map_override=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --prog) prog="$2"; shift 2 ;;
        --legacy-packet) legacy=1; shift 2 ;;
        --map-max-entries)
            [ "$2" = ig_build_id=1024 ] && map_override=1
            shift 2
            ;;
        *) shift ;;
    esac
done
[ "$map_override" -eq 1 ] || { printf 'error: missing Gadget map override\n' >&2; exit 1; }
case "$prog" in
    first/name) printf 'verification PASSED\n' ;;
    second:name) printf 'verification FAILED: at insn 0: call to unknown helper #999\n' ;;
    socket/legacy)
        if [ "$legacy" -eq 1 ]; then
            printf 'verification FAILED: at insn 7: call to unknown helper #26\n'
        else
            printf 'verification FAILED: at insn 0: legacy packet profile disabled for opcode 0x20\n'
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
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report = fs::read_to_string(report).unwrap();
    assert!(report.contains("objects/families scanned  : 1"), "{report}");
    assert!(report.contains("objects fully compatible  : 0  (0.0%)"), "{report}");
    assert!(report.contains("entry programs scanned    : 3"), "{report}");
    assert!(report.contains("entries verified OK       : 1  (33.3%)"), "{report}");
    assert!(report.contains("second:name"), "{report}");
    assert!(report.contains("VERIFY-REJECT:unsupported-helper:#999"), "{report}");
    assert!(report.contains("VERIFY-REJECT:unsupported-helper:#26"), "{report}");
    assert!(report.contains("socket/legacy"), "{report}");

    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn scanner_applies_attach_targets_to_listing_and_verification() {
    let temp = temp_dir("corpus-attach-target");
    let mock = temp.join("febpf-mock");
    let object = temp.join("bcc__cachestat.o");
    let target = temp.join("target.btf");
    let report = temp.join("report.txt");
    fs::write(&object, b"mock object").unwrap();
    fs::write(&target, b"mock BTF").unwrap();
    fs::write(
        &mock,
        r#"#!/usr/bin/env bash
set -u
attach=0
target=0
for arg in "$@"; do
    [ "$arg" = section:fentry/account_page_dirtied=folio_account_dirtied ] && attach=1
    [ "$arg" = "$TARGET_BTF" ] && target=1
done
[ "$attach" -eq 1 ] || { printf 'error: missing attach override\n' >&2; exit 1; }
[ "$target" -eq 1 ] || { printf 'error: missing target BTF\n' >&2; exit 1; }
if [ "$1" = programs ]; then
    if [ "${MOCK_MISSING_FUNCTION:-0}" -eq 1 ]; then
        printf "error: attach-target: no function 'folio_account_dirtied' in target BTF\n" >&2
        exit 1
    fi
    printf 'program\t0\tother\tfentry/account_page_dirtied\n'
else
    printf 'verification PASSED\n'
fi
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&mock).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&mock, permissions).unwrap();

    let scan = |missing_function: bool| {
        let mut command = Command::new("bash");
        command
            .arg("scripts/scan-corpus.sh")
            .arg(&object)
            .env("NO_BUILD", "1")
            .env("FEBPF", &mock)
            .env("TARGET_BTF", &target)
            .env("CORPUS_REPORT", &report);
        if missing_function {
            command.env("MOCK_MISSING_FUNCTION", "1");
        }
        command.output().expect("run corpus scanner")
    };

    let output = scan(false);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let successful = fs::read_to_string(&report).unwrap();
    assert!(successful.contains("objects fully compatible  : 1  (100.0%)"), "{successful}");
    assert!(successful.contains("entries verified OK       : 1  (100.0%)"), "{successful}");

    let output = scan(true);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let missing = fs::read_to_string(&report).unwrap();
    assert!(missing.contains("objects fully compatible  : 0  (0.0%)"), "{missing}");
    assert!(missing.contains("LOAD-FAIL:other"), "{missing}");
    assert!(!missing.contains("entries verified OK       : 1"), "{missing}");

    fs::remove_dir_all(temp).unwrap();
}
