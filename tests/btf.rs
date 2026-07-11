//! Differential tests for the BTF parser against `bpftool btf dump`.
//!
//! These run only where the ground truth exists: kernel BTF at
//! `/sys/kernel/btf/vmlinux` and `bpftool` on PATH. The synthetic-BTF unit
//! tests live in `src/btf.rs`; this file checks the parser at vmlinux scale
//! (~150k types) against an independent implementation.

use febpf::btf::{relo_kind, Btf, BtfExt, Kind};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

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

/// Recompile a fixture when a BPF-capable clang is available (mirrors
/// tests/elf.rs). Apple clang has no BPF backend — running it would fail and
/// destroy the committed fixture, so probe first and build via a temp file.
fn maybe_compile(src: &str, out: &str) {
    let bpf_capable = Command::new("clang")
        .arg("--print-targets")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("bpf"))
        .unwrap_or(false);
    if !bpf_capable {
        return;
    }
    let src_path = format!("examples/c/{src}");
    if !Path::new(&src_path).exists() {
        return;
    }
    // Tests run concurrently, so a fixed temp name would let one invocation
    // rename another's output before it installs its own fixture.
    static TEMP_ID: AtomicU64 = AtomicU64::new(0);
    let tmp = format!(
        "tests/.{out}.{}.{}.tmp",
        std::process::id(),
        TEMP_ID.fetch_add(1, Ordering::Relaxed)
    );
    let status = Command::new("clang")
        .args(["-O2", "-g", "-target", "bpf", "-c", &src_path, "-o"])
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

#[test]
fn btf_ext_of_core_probe_object() {
    maybe_compile("core_probe.c", "core_probe.o");
    let bytes = std::fs::read("tests/core_probe.o").expect("fixture");
    let (btf_raw, le) = febpf::elf::read_section(&bytes, ".BTF")
        .unwrap()
        .expect("no .BTF");
    let (ext_raw, _) = febpf::elf::read_section(&bytes, ".BTF.ext")
        .unwrap()
        .expect("no .BTF.ext");
    let btf = Btf::parse(le, &btf_raw).unwrap();
    let ext = BtfExt::parse(le, &ext_raw).unwrap();

    // CO-RE relocations: `p->x + p->y + p->z` over preserve_access_index
    // yields three FIELD_BYTE_OFFSET relos in .text, one per member, with
    // access strings "0:0"/"0:1"/"0:2" rooted at struct point.
    assert_eq!(ext.core_relos.len(), 1);
    let sec = &ext.core_relos[0];
    assert_eq!(btf.str_at(sec.sec_name_off), ".text");
    let mut relos = sec.recs.clone();
    relos.sort_by_key(|r| r.insn_off);
    assert_eq!(relos.len(), 3);
    let mut accesses = Vec::new();
    for r in &relos {
        assert_eq!(r.kind, relo_kind::FIELD_BYTE_OFFSET);
        assert!(r.insn_off.is_multiple_of(8), "insn_off is a byte offset");
        assert_eq!(btf.type_name(btf.resolve(r.type_id).unwrap()), "point");
        accesses.push(btf.str_at(r.access_str_off).to_string());
    }
    assert_eq!(accesses, ["0:0", "0:1", "0:2"]);

    // func_info: one record, at insn 0, pointing at FUNC 'probe'.
    assert_eq!(ext.func_info.len(), 1);
    let fi = &ext.func_info[0];
    assert_eq!(btf.str_at(fi.sec_name_off), ".text");
    assert_eq!(fi.recs.len(), 1);
    assert_eq!(fi.recs[0].insn_off, 0);
    assert_eq!(btf.type_name(fi.recs[0].type_id), "probe");

    // line_info: at least one record per source statement, with a resolvable
    // file name and 1-based line numbers.
    assert_eq!(ext.line_info.len(), 1);
    let li = &ext.line_info[0];
    assert_eq!(btf.str_at(li.sec_name_off), ".text");
    assert!(!li.recs.is_empty());
    for rec in &li.recs {
        assert!(btf.str_at(rec.file_name_off).ends_with("core_probe.c"));
        assert!(rec.line() > 0 && rec.line() < 100);
    }
}

#[test]
fn core_relos_resolve_against_own_btf() {
    // Self-relocation: using the object's own BTF as the target must
    // reproduce exactly the offsets clang baked into the instructions.
    maybe_compile("core_probe.c", "core_probe.o");
    let bytes = std::fs::read("tests/core_probe.o").expect("fixture");
    let (btf_raw, le) = febpf::elf::read_section(&bytes, ".BTF")
        .unwrap()
        .expect("no .BTF");
    let (ext_raw, _) = febpf::elf::read_section(&bytes, ".BTF.ext")
        .unwrap()
        .expect("no .BTF.ext");
    let btf = Btf::parse(le, &btf_raw).unwrap();
    let ext = BtfExt::parse(le, &ext_raw).unwrap();
    let index = febpf::relo::CandidateIndex::new(&btf);

    let mut relos = ext.core_relos[0].recs.clone();
    relos.sort_by_key(|r| r.insn_off);
    let expected_offsets = [0u64, 4, 8]; // x, y, z in struct point
    for (r, want) in relos.iter().zip(expected_offsets) {
        let res = febpf::relo::calc_relo(&btf, r, &btf, &index).unwrap();
        assert_eq!(res.new_val, want, "insn_off {}", r.insn_off);
        assert_eq!(res.orig_val, want);
        assert_eq!(res.matched, 1);
        assert!(res.validate);
    }
}

#[test]
fn ctx_args_resolve_against_real_vmlinux() {
    // BTF-typed ctx resolution at vmlinux scale: the real sched_switch
    // tracepoint and vfs_read kernel function, checked against their known
    // kernel signatures.
    let Ok(data) = std::fs::read(VMLINUX) else {
        eprintln!("skipping: no {VMLINUX}");
        return;
    };
    let btf = Btf::parse(true, &data).expect("parse vmlinux BTF");
    use febpf::btf::{resolve_ctx_args, CtxSlot};

    // trace_sched_switch(preempt, prev, next[, prev_state]): bool + 2x
    // task_struct* (+ a scalar prev_state on kernels >= 5.16).
    let args = resolve_ctx_args(&btf, "tp_btf/sched_switch")
        .unwrap()
        .expect("BTF-typed section");
    assert!(args.len() == 3 || args.len() == 4, "{args:?}");
    assert_eq!(args[0], CtxSlot::Scalar);
    for a in &args[1..3] {
        let CtxSlot::Ptr { btf_id } = a else {
            panic!("expected task_struct pointers: {args:?}")
        };
        assert_eq!(btf.type_name(*btf_id), "task_struct");
    }

    // vfs_read(file*, buf, count, pos): fexit gets one extra slot for the
    // ssize_t return value (a scalar).
    let fentry = resolve_ctx_args(&btf, "fentry/vfs_read").unwrap().unwrap();
    let fexit = resolve_ctx_args(&btf, "fexit/vfs_read").unwrap().unwrap();
    assert_eq!(fentry.len(), 4, "{fentry:?}");
    assert_eq!(fexit.len(), 5, "{fexit:?}");
    assert!(matches!(fentry[0], CtxSlot::Ptr { btf_id }
        if btf.type_name(btf_id) == "file"));
    assert_eq!(fexit[4], CtxSlot::Scalar);
    assert_eq!(&fexit[..4], &fentry[..]);

    // Not present in any kernel: an error, not a panic.
    assert!(resolve_ctx_args(&btf, "fentry/definitely_not_a_kernel_fn").is_err());
}
