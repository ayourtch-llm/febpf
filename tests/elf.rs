//! Tests for the ELF object loader, using real `clang -target bpf` output.
//!
//! The `.o` fixtures under `tests/` were produced by clang from the sources in
//! `examples/c/`. Normal tests consume the committed fixtures without writing
//! them; set `FEBPF_REGENERATE_FIXTURES=1` to rebuild explicitly.

mod common;

use febpf::verifier::Config;
use febpf::{elf, Program, Vm};
use std::process::Command;

fn maybe_compile(src: &str, out: &str) {
    let opt = if src == "subprog.c" { "-O0" } else { "-O2" };
    common::maybe_compile(src, out, opt);
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
    #[cfg_attr(not(feature = "jit"), allow(unused_mut))]
    let mut vm = Vm::new(Program {
        insns: prog.insns.clone(),
        maps: obj.maps.clone(),
        btf_ctx: None,
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
fn shared_section_entries_and_section_symbol_call_addends() {
    maybe_compile("multi_entry.c", "multi_entry.o");
    let obj = load("tests/multi_entry.o");
    assert_eq!(
        obj.programs
            .iter()
            .map(|program| program.name.as_str())
            .collect::<Vec<_>>(),
        ["first_entry", "second_entry"]
    );

    // The second relocation is against the .text SECTION symbol with encoded
    // addend 2 and must select add_seven rather than silently selecting
    // add_one. Load-time subprogram DCE then removes the uncalled callee and
    // remaps both surviving calls to the same compact displacement.
    assert_eq!(obj.programs[0].insns[1].imm, 1);
    assert_eq!(obj.programs[1].insns[1].imm, 1);
    assert!(obj.programs[0].insns.iter().any(|insn| insn.imm == 1));
    assert!(obj.programs[1].insns.iter().any(|insn| insn.imm == 7));
    let mut ctx = [0u8; 8];
    ctx[..4].copy_from_slice(&11u32.to_le_bytes());
    assert_eq!(run_prog(&obj, "first_entry", &mut ctx), 12);
    assert_eq!(run_prog(&obj, "second_entry", &mut ctx), 18);
}

#[test]
fn cached_production_shared_entries_and_call_addend() {
    let xdp_path = "corpus/obj/xdp-tools__xdp_basic.o";
    let bio_path = "corpus/obj/bcc__biolatency.o";
    let (Ok(xdp_bytes), Ok(bio_bytes)) = (std::fs::read(xdp_path), std::fs::read(bio_path)) else {
        eprintln!("skipping: cached production corpus objects are absent");
        return;
    };

    let xdp = elf::load(&xdp_bytes).unwrap();
    let xdp_names: Vec<&str> = xdp
        .programs
        .iter()
        .map(|program| program.name.as_str())
        .collect();
    for expected in [
        "xdp_basic_prog",
        "xdp_read_data_prog",
        "xdp_read_data_load_bytes_prog",
        "xdp_swap_macs_prog",
        "xdp_swap_macs_load_bytes_prog",
        "xdp_parse_prog",
        "xdp_parse_load_bytes_prog",
    ] {
        assert!(
            xdp_names.contains(&expected),
            "missing xdp entry {expected}"
        );
    }
    assert!(!xdp_names.contains(&"xdp"));

    let bio = elf::load(&bio_bytes).unwrap();
    let complete = bio
        .programs
        .iter()
        .find(|program| program.name == "raw_tp/block_rq_complete")
        .unwrap();
    // The section-symbol addend selects handle_block_rq_complete. DCE removes
    // the two preceding uncalled .text functions and compacts this callee to
    // pc 4; the debug function boundary proves which body survived.
    assert_eq!(complete.insns[1].imm, 2);
    assert_eq!(
        complete.debug.as_ref().unwrap().func_at(4).unwrap().name,
        "handle_block_rq_complete"
    );
}

#[test]
fn static_prog_array_initializers_link_programs() {
    maybe_compile("tail_call.c", "tail_call.o");
    let obj = load("tests/tail_call.o");
    assert_eq!(obj.prog_array_inits.len(), 1);
    let init = &obj.prog_array_inits[0];
    assert_eq!(obj.maps[init.map_index].name, "progs");
    assert_eq!(
        (
            obj.maps[init.map_index].key_size,
            obj.maps[init.map_index].value_size,
        ),
        (4, 4)
    );
    assert_eq!(init.index, 0);
    assert_eq!(init.program, "socket/target");
    let outer = obj.maps.iter().position(|map| map.name == "outer").unwrap();
    let inner = obj.maps.iter().position(|map| map.name == "inner").unwrap();
    assert_eq!(obj.maps[outer].kind, febpf::maps::MapKind::ArrayOfMaps);
    assert_eq!(obj.maps[outer].inner_map_idx, Some(inner as u32));
    assert_eq!(obj.maps[outer].map_in_map_values, [(1, inner as u32)]);

    let entry = obj.programs.iter().find(|p| p.name == "socket/entry").unwrap();
    let target = obj
        .programs
        .iter()
        .find(|p| p.name == init.program)
        .unwrap();
    let linked_vm = || {
        let mut vm = Vm::new(Program {
            insns: entry.insns.clone(),
            maps: obj.maps.clone(),
            btf_ctx: None,
        })
        .unwrap();
        vm.verify(Config::default()).unwrap();
        vm.register_tail_call(
            "progs",
            0,
            Program {
                insns: target.insns.clone(),
                maps: obj.maps.clone(),
                btf_ctx: None,
            },
            Config::default(),
        )
        .unwrap();
        vm
    };
    assert_eq!(linked_vm().run(&mut [0u8; 16]).unwrap(), 42);
    #[cfg(feature = "jit")]
    assert_eq!(linked_vm().run_jit(&mut [0u8; 16]).unwrap(), 42);
}

#[test]
fn cross_text_bpf_to_bpf_call() {
    maybe_compile("subprog.c", "subprog.o");
    let obj = load("tests/subprog.o");
    // triple(14) = 42, via a call into a .text subprogram
    assert_eq!(run_prog(&obj, "socket", &mut [0u8; 8]), 42);
}

#[test]
fn kconfig_extern_object() {
    maybe_compile("kconfig.c", "kconfig.o");
    let obj = load("tests/kconfig.o");

    // The extern lands in a synthetic frozen `.kconfig` map, filled with the
    // running kernel's KERNEL_VERSION (or the documented fallback) — always
    // a plausible nonzero version.
    let kc = obj
        .maps
        .iter()
        .find(|m| m.name == ".kconfig")
        .expect("no .kconfig map");
    assert!(kc.readonly);
    assert_eq!(kc.value_size, 4);
    let kver = u32::from_le_bytes(kc.init[0..4].try_into().unwrap());
    assert!(kver >= (3 << 16), "implausible kernel version {kver:#x}");

    // The program compares LINUX_KERNEL_VERSION against 3.0.0: the UND
    // extern symbol relocated into the .kconfig value, read at runtime.
    assert_eq!(run_prog(&obj, "socket", &mut [0u8; 8]), 1);
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
    #[cfg_attr(not(feature = "jit"), allow(unused_mut))]
    let mut vm = Vm::new(Program {
        insns: prog.insns.clone(),
        maps: obj.maps.clone(),
        btf_ctx: None,
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
        btf_ctx: None,
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

/// Load-time rodata DCE (docs/specs/rodata-dce.md): a `const volatile` flag
/// left at its default 0 guards a call to a `.text` subprogram. Without the
/// pass the stitched-in dead subprogram trips the verifier's
/// unreachable-instruction check; with it the object loads, verifies, runs
/// the surviving path, and carries consistently remapped line info.
#[test]
fn rodata_dce_object() {
    maybe_compile("rodata_dce.c", "rodata_dce.o");
    let obj = load("tests/rodata_dce.o");
    let prog = &obj.programs[0];
    // The dead `slow_path` body (x * 0xdead) must be gone.
    assert!(
        !prog.insns.iter().any(|i| i.imm == 0xdead),
        "dead subprogram survived DCE"
    );
    // No local calls survive either (the only call was rodata-dead).
    assert!(!prog
        .insns
        .iter()
        .any(|i| i.class() == 0x05 && i.op() == 0x80));
    // Remapped debug info stays in range.
    if let Some(d) = &prog.debug {
        for l in d.lines() {
            assert!(l.insn < prog.insns.len());
        }
    }
    // v = 5 (u32 at ctx[0]), flag off: returns v * scale = 20.
    let mut ctx = [0u8; 64];
    ctx[..4].copy_from_slice(&5u32.to_le_bytes());
    assert_eq!(run_prog(&obj, "socket", &mut ctx), 20);
}

#[cfg(feature = "jit")]
#[test]
fn jit_matches_interpreter_on_objects() {
    for (file, prog, ctx_len) in [
        ("tests/legacy_maps.o", "socket", 64),
        ("tests/btf_maps.o", "xdp", 64),
        ("tests/subprog.o", "socket", 8),
        ("tests/global_data.o", "socket", 64),
        ("tests/rodata_dce.o", "socket", 64),
    ] {
        let obj = load(file);
        let mut i_ctx = vec![0u8; ctx_len];
        let interp = run_prog(&obj, prog, &mut i_ctx);

        let p = obj.programs.iter().find(|p| p.name == prog).unwrap();
        let mut vm = Vm::new(Program {
            insns: p.insns.clone(),
            maps: obj.maps.clone(),
            btf_ctx: None,
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

#[test]
fn core_relocations_against_shifted_target() {
    maybe_compile("core_probe.c", "core_probe.o");
    maybe_compile("core_target.c", "core_target.o");
    let probe = std::fs::read("tests/core_probe.o").unwrap();
    let target_obj = std::fs::read("tests/core_target.o").unwrap();
    let (target_btf, _) = elf::read_section(&target_obj, ".BTF")
        .unwrap()
        .expect("target fixture has no .BTF");

    assert!(elf::has_core_relocations(&probe));
    assert!(!elf::has_core_relocations(&std::fs::read("tests/btf_maps.o").unwrap()));

    // probe computes p->x + p->y + (int)p->z over `struct point`.
    // Unrelocated (compiler's local layout): x@0, y@4, z@8.
    let mut ctx = [0u8; 64];
    ctx[0..4].copy_from_slice(&11i32.to_le_bytes());
    ctx[4..8].copy_from_slice(&22i32.to_le_bytes());
    ctx[8..16].copy_from_slice(&33i64.to_le_bytes());
    let obj = elf::load(&probe).unwrap();
    assert_eq!(run_prog(&obj, "text", &mut ctx), 66);

    // Relocated against the shifted target layout: x@4, y@12, z@16.
    let mut ctx = [0u8; 64];
    ctx[4..8].copy_from_slice(&100i32.to_le_bytes());
    ctx[12..16].copy_from_slice(&20i32.to_le_bytes());
    ctx[16..24].copy_from_slice(&3i64.to_le_bytes());
    let obj = elf::load_with_target_btf(&probe, Some(&target_btf)).unwrap();
    assert_eq!(run_prog(&obj, "text", &mut ctx), 123);

    // Self-relocation (own BTF as target) must be a no-op.
    let (own_btf, _) = elf::read_section(&probe, ".BTF").unwrap().unwrap();
    let own = elf::load_with_target_btf(&probe, Some(&own_btf)).unwrap();
    let plain = elf::load(&probe).unwrap();
    assert_eq!(own.programs[0].insns, plain.programs[0].insns);

    // JIT/interpreter parity on the relocated program.
    let prog = &obj.programs[0];
    #[cfg_attr(not(feature = "jit"), allow(unused_mut))]
    let mut vm = Vm::new(Program {
        insns: prog.insns.clone(),
        maps: obj.maps.clone(),
        btf_ctx: None,
    })
    .unwrap();
    vm.verify(Config {
        ctx_size: 64,
        ..Default::default()
    })
    .unwrap();
    #[cfg(feature = "jit")]
    {
        let mut jit_ctx = [0u8; 64];
        jit_ctx[4..8].copy_from_slice(&100i32.to_le_bytes());
        jit_ctx[12..16].copy_from_slice(&20i32.to_le_bytes());
        jit_ctx[16..24].copy_from_slice(&3i64.to_le_bytes());
        assert_eq!(vm.run_jit(&mut jit_ctx).unwrap(), 123);
    }
}

/// Differential against the running kernel: relocate a FIELD_BYTE_OFFSET on
/// an ALU immediate against /sys/kernel/btf/vmlinux and compare the patched
/// value with what `bpftool btf dump` reports for task_struct.pid.
#[test]
fn core_alu_relocation_against_running_kernel() {
    maybe_compile("core_task.c", "core_task.o");
    let vmlinux = "/sys/kernel/btf/vmlinux";
    let Ok(target) = std::fs::read(vmlinux) else {
        eprintln!("skipping: no {vmlinux}");
        return;
    };
    let out = Command::new("bpftool")
        .args(["btf", "dump", "file", vmlinux])
        .output();
    let Ok(out) = out else {
        eprintln!("skipping: bpftool unavailable");
        return;
    };
    if !out.status.success() {
        eprintln!(
            "skipping: bpftool could not dump {vmlinux}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        return;
    }
    let dump = String::from_utf8_lossy(&out.stdout);
    // First 'pid' member inside STRUCT task_struct.
    let Some(expected) = dump
        .split("STRUCT 'task_struct' size")
        .nth(1)
        .and_then(|s| s.lines().find(|l| l.contains("'pid' type_id")))
        .and_then(|l| l.rsplit("bits_offset=").next())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|offset| offset / 8)
    else {
        eprintln!("skipping: bpftool output has no parseable task_struct.pid");
        return;
    };

    let probe = std::fs::read("tests/core_task.o").unwrap();
    let obj = elf::load_with_target_btf(&probe, Some(&target)).unwrap();
    assert_eq!(run_prog(&obj, "text", &mut [0u8; 8]), expected);
}
