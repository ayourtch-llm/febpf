//! Differential tests for the BTF parser against `bpftool btf dump`.
//!
//! These run only where the ground truth exists: kernel BTF at
//! `/sys/kernel/btf/vmlinux` and `bpftool` on PATH. The synthetic-BTF unit
//! tests live in `src/btf.rs`; this file checks the parser at vmlinux scale
//! (~150k types) against an independent implementation.

use febpf::btf::{Btf, Kind};
use std::process::Command;

const VMLINUX: &str = "/sys/kernel/btf/vmlinux";

fn bpftool_dump(path: &str) -> Option<String> {
    let out = Command::new("bpftool")
        .args(["btf", "dump", "file", path])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn vmlinux_matches_bpftool() {
    let Ok(data) = std::fs::read(VMLINUX) else {
        eprintln!("skipping: no {VMLINUX}");
        return;
    };
    let Some(dump) = bpftool_dump(VMLINUX) else {
        eprintln!("skipping: bpftool unavailable");
        return;
    };
    let btf = Btf::parse(true, &data).expect("parse vmlinux BTF");

    // Every top-level dump line is "[id] KIND 'name' ..." — compare id count
    // and names. A single skip-size bug anywhere desyncs all following ids,
    // so agreeing on all (id, name) pairs is a strong whole-file check.
    let mut top_level = 0usize;
    let mut max_id = 0u32;
    for line in dump.lines() {
        let Some(rest) = line.strip_prefix('[') else {
            continue; // member/param continuation lines
        };
        let Some((id_s, rest)) = rest.split_once("] ") else {
            continue;
        };
        let id: u32 = id_s.parse().expect("bad id in bpftool output");
        top_level += 1;
        max_id = max_id.max(id);
        // KIND 'name' — anonymous types print as '(anon)'.
        let name = rest
            .split_once('\'')
            .map(|(_, r)| r.split('\'').next().unwrap_or(""))
            .unwrap_or("");
        if name != "(anon)" && !name.is_empty() {
            assert_eq!(
                btf.type_name(id),
                name,
                "type {id}: name mismatch vs bpftool"
            );
        }
    }
    assert!(top_level > 100_000, "vmlinux dump suspiciously small");
    assert_eq!(btf.len() as u32, max_id + 1, "type count mismatch");

    // Spot-check a well-known struct: bpftool's "size=N vlen=M" for
    // task_struct must match our parse, member for member.
    let ids = btf.ids_by_name("task_struct");
    assert!(!ids.is_empty(), "no task_struct in vmlinux BTF");
    let ts = ids
        .iter()
        .find_map(|&id| match &btf.ty(id).unwrap().kind {
            Kind::Struct { size, members } => Some((id, *size, members)),
            _ => None,
        })
        .expect("task_struct is not a struct");
    let (id, size, members) = ts;
    let hdr = dump
        .lines()
        .find(|l| l.starts_with(&format!("[{id}] STRUCT 'task_struct'")))
        .expect("bpftool has no task_struct line");
    assert!(hdr.contains(&format!("size={size}")), "size mismatch: {hdr}");
    assert!(
        hdr.contains(&format!("vlen={}", members.len())),
        "vlen mismatch: {hdr}"
    );
    // Members: bpftool prints "\t'name' type_id=T bits_offset=O[ bitfield_size=S]"
    let mut lines = dump.lines().skip_while(|l| !l.starts_with(&format!("[{id}]")));
    lines.next();
    for m in members {
        let l = lines.next().expect("bpftool member lines exhausted");
        let name = btf.str_at(m.name_off);
        if !name.is_empty() {
            assert!(l.contains(&format!("'{name}'")), "member name: {l}");
        }
        assert!(
            l.contains(&format!("type_id={}", m.type_id)),
            "member type: {l}"
        );
        assert!(
            l.contains(&format!("bits_offset={}", m.bit_offset)),
            "member offset: {l}"
        );
        if m.bitfield_size != 0 {
            assert!(
                l.contains(&format!("bitfield_size={}", m.bitfield_size)),
                "bitfield size: {l}"
            );
        }
    }
}
