//! Shared integration-test fixture support.
//!
//! Normal tests are read-only consumers of committed `.o` files. Regeneration
//! is deliberately opt-in because clang embeds toolchain- and path-dependent
//! bytes, so rewriting fixtures during `cargo test` dirties the checkout.

use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

pub const REGENERATE_ENV: &str = "FEBPF_REGENERATE_FIXTURES";

fn regeneration_requested() -> bool {
    std::env::var_os(REGENERATE_ENV).as_deref() == Some(OsStr::new("1"))
}

fn clang_targets_bpf() -> bool {
    Command::new("clang")
        .arg("--print-targets")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("bpf"))
        .unwrap_or(false)
}

/// Rebuild one committed fixture, but only under the explicit opt-in.
pub fn maybe_compile(src: &str, out: &str, opt: &str) {
    if !regeneration_requested() {
        return;
    }
    assert!(
        clang_targets_bpf(),
        "{REGENERATE_ENV}=1 requires clang with the BPF target"
    );
    let src_path = format!("examples/c/{src}");
    assert!(Path::new(&src_path).exists(), "missing fixture source {src_path}");

    // Test threads may request the same fixture concurrently. Compile to a
    // unique staging file and install only a complete, successful object.
    static TEMP_ID: AtomicU64 = AtomicU64::new(0);
    let tmp = format!(
        "tests/.{out}.{}.{}.tmp",
        std::process::id(),
        TEMP_ID.fetch_add(1, Ordering::Relaxed)
    );
    let status = Command::new("clang")
        .args([opt, "-g", "-target", "bpf", "-c", &src_path, "-o"])
        .arg(&tmp)
        .status();
    let ok = status.map(|s| s.success()).unwrap_or(false);
    if ok {
        std::fs::rename(&tmp, format!("tests/{out}")).expect("install fixture");
    } else {
        let _ = std::fs::remove_file(&tmp);
    }
    assert!(ok, "clang failed to compile {src}");
}
