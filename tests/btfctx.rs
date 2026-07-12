//! BTF-typed ctx pointers (kernel PTR_TO_BTF_ID) — end-to-end tests against
//! the self-contained `tests/btfctx.o` fixture (examples/c/btfctx.c), which
//! carries both a `tp_btf/sched_switch` program and the target-side types in
//! its own `.BTF`, so no running kernel is needed.
//! See docs/specs/btf-ctx-pointers.md.

mod common;

use febpf::btf::{resolve_ctx_args, Btf, BtfCtx, CtxSlot};
use febpf::verifier::Config;
use febpf::{asm, Program, Vm};
use std::sync::Arc;

fn fixture_bytes() -> Vec<u8> {
    // Compile at most once per test process — tests run in parallel, and a
    // concurrent clang rewrite would race the readers.
    static BYTES: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    BYTES
        .get_or_init(|| {
            common::maybe_compile("btfctx.c", "btfctx.o", "-O2");
            std::fs::read("tests/btfctx.o").expect("tests/btfctx.o fixture")
        })
        .clone()
}

/// The fixture's raw `.BTF` payload, usable as a target-BTF blob.
fn fixture_btf_raw(bytes: &[u8]) -> Vec<u8> {
    febpf::elf::read_section(bytes, ".BTF").unwrap().expect(".BTF").0
}

/// The fixture's own BTF, used as the "kernel" BTF throughout.
fn fixture_btf(bytes: &[u8]) -> Arc<Btf> {
    let (raw, le) = febpf::elf::read_section(bytes, ".BTF").unwrap().expect(".BTF");
    Arc::new(Btf::parse(le, &raw).unwrap())
}

/// BtfCtx for tp_btf/sched_switch as the loader would resolve it:
/// [Scalar (bool preempt), Ptr task_struct (prev), Ptr task_struct (next)].
fn sched_switch_ctx(btf: &Arc<Btf>) -> BtfCtx {
    let args = resolve_ctx_args(btf, "tp_btf/sched_switch").unwrap().unwrap();
    assert_eq!(args.len(), 3);
    assert_eq!(args[0], CtxSlot::Scalar);
    assert!(matches!(args[1], CtxSlot::Ptr { .. }));
    assert_eq!(args[1], args[2]);
    BtfCtx { args, btf: Some(btf.clone()) }
}

/// Assemble an asm body into a Program carrying the sched_switch BtfCtx.
fn btf_prog(src: &str) -> Program {
    let bytes = fixture_bytes();
    let btf = fixture_btf(&bytes);
    let a = asm::assemble(src).unwrap();
    Program {
        insns: a.insns,
        maps: a.maps,
        btf_ctx: Some(sched_switch_ctx(&btf)),
    }
}

fn verify_err(src: &str) -> String {
    let mut vm = Vm::new(btf_prog(src)).unwrap();
    match vm.verify(Config::default()) {
        Ok(_) => panic!("expected the verifier to reject:\n{src}"),
        Err(e) => e.to_string(),
    }
}

fn live_iterator_ctx(object: &str, program: &str) -> Option<BtfCtx> {
    let object = std::fs::read(object).ok()?;
    let target = std::fs::read("/sys/kernel/btf/vmlinux").ok()?;
    let loaded = febpf::elf::load_with_target_btf(&object, Some(&target)).ok()?;
    loaded
        .programs
        .into_iter()
        .find(|p| p.name == program)?
        .btf_ctx
}

fn iterator_prog(src: &str, ctx: BtfCtx) -> Program {
    let a = asm::assemble(src).unwrap();
    Program { insns: a.insns, maps: a.maps, btf_ctx: Some(ctx) }
}

// ---------------------------------------------------------------------------
// ELF loader end to end
// ---------------------------------------------------------------------------

#[test]
fn fixture_loads_verifies_and_runs() {
    let bytes = fixture_bytes();
    let target = fixture_btf_raw(&bytes);
    let obj = febpf::elf::load_with_target_btf(&bytes, Some(&target)).unwrap();
    assert!(obj.warnings.is_empty(), "{:?}", obj.warnings);
    let prog = obj
        .programs
        .into_iter()
        .find(|p| p.name == "tp_btf/sched_switch")
        .expect("tp_btf program");
    let bc = prog.btf_ctx.clone().expect("loader resolved BtfCtx");
    assert_eq!(bc.args.len(), 3);

    let mut vm = Vm::new(Program {
        insns: prog.insns,
        maps: obj.maps,
        btf_ctx: prog.btf_ctx,
    })
    .unwrap();
    let ok = vm.verify(Config::default()).expect("verifies");
    // The program derefs BTF pointers; at least one load must be a probe read.
    assert!(ok.probe_mem.iter().any(|&b| b));
    // prev->prio + next->pid + prev->parent->pid over all-zeroes kernel
    // memory (including the NULL parent chase) is 0.
    let mut ctx = vec![0u8; 4096];
    assert_eq!(vm.run(&mut ctx).unwrap(), 0);
}

#[test]
fn loader_without_target_btf_leaves_ctx_untyped() {
    let bytes = fixture_bytes();
    assert!(febpf::elf::needs_kernel_btf(&bytes));
    let obj = febpf::elf::load_with_target_btf(&bytes, None).unwrap();
    assert!(obj.programs.iter().all(|p| p.btf_ctx.is_none()));
}

#[test]
fn iterator_context_layout_is_exact_and_nullable() {
    if let Ok(bytes) = std::fs::read("corpus/obj/inspektor-gadget__snapshot_file.o") {
        assert!(febpf::elf::needs_kernel_btf(&bytes));
        let without_target = febpf::elf::load_with_target_btf(&bytes, None).unwrap();
        assert!(without_target.programs.iter().all(|p| p.btf_ctx.is_none()));
    }
    let Some(ctx) = live_iterator_ctx(
        "corpus/obj/inspektor-gadget__snapshot_file.o",
        "iter/task_file",
    ) else {
        eprintln!("skipping: live target BTF or cached iterator corpus is absent");
        return;
    };
    assert!(matches!(ctx.args[0], CtxSlot::Ptr { .. }));
    assert!(matches!(ctx.args[1], CtxSlot::PtrOrNull { .. }));
    assert_eq!(ctx.args[2], CtxSlot::ScalarSized { size: 4 });
    assert!(matches!(ctx.args[3], CtxSlot::PtrOrNull { .. }));

    let reject = |src: &str| {
        let mut vm = Vm::new(iterator_prog(src, ctx.clone())).unwrap();
        vm.verify(Config::default()).err().expect("must reject").to_string()
    };
    assert!(reject("r0 = *(u32 *)(r1 + 8)\nexit").contains("8-byte"));
    assert!(reject("r0 = *(u64 *)(r1 + 16)\nexit").contains("4-byte"));
    assert!(reject("r0 = *(u64 *)(r1 + 4)\nexit").contains("multiple of 8"));
    assert!(reject("r0 = 0\n*(u64 *)(r1 + 8) = r0\nexit").contains("read-only"));
    assert!(reject("r2 = *(u64 *)(r1 + 8)\nr0 = *(u32 *)(r2)\nexit").contains("may be NULL"));
}

#[test]
fn iterator_terminal_record_runs_without_host_pointers() {
    let Some(ctx) = live_iterator_ctx(
        "corpus/obj/inspektor-gadget__snapshot_process.o",
        "iter/task",
    ) else {
        eprintln!("skipping: live target BTF or cached iterator corpus is absent");
        return;
    };
    let src = "
        r2 = *(u64 *)(r1 + 0)
        r3 = *(u64 *)(r2 + 0)
        r4 = *(u64 *)(r1 + 8)
        if r4 == 0 goto terminal
        r0 = 1
        exit
    terminal:
        r0 = 0
        exit";
    let mut vm = Vm::new(iterator_prog(src, ctx)).unwrap();
    vm.verify(Config::default()).unwrap();
    let mut record = [0u8; 16];
    assert_eq!(vm.run(&mut record).unwrap(), 0);
    assert_ne!(u64::from_le_bytes(record[0..8].try_into().unwrap()), 0);
    assert_eq!(u64::from_le_bytes(record[8..16].try_into().unwrap()), 0);

    #[cfg(feature = "jit")]
    {
        record.fill(0);
        assert_eq!(vm.run_jit(&mut record).unwrap(), 0);
    }
}

#[test]
fn iterator_corpus_advances_past_context_typing() {
    let target = match std::fs::read("/sys/kernel/btf/vmlinux") {
        Ok(v) => v,
        Err(_) => return,
    };
    let cases = [
        ("corpus/obj/inspektor-gadget__snapshot_file.o", "iter/task_file", 127),
        ("corpus/obj/inspektor-gadget__snapshot_process.o", "iter/task", 127),
        ("corpus/obj/inspektor-gadget__snapshot_socket.o", "iter/tcp", 137),
        ("corpus/obj/inspektor-gadget__snapshot_socket.o", "iter/udp", 127),
        ("corpus/obj/libbpf-bootstrap__task_iter.o", "iter/task", 141),
    ];
    for (path, name, helper) in cases {
        let Ok(bytes) = std::fs::read(path) else {
            eprintln!("skipping: cached iterator corpus is absent");
            return;
        };
        let object = febpf::elf::load_with_target_btf(&bytes, Some(&target)).unwrap();
        let loaded = object.programs.into_iter().find(|p| p.name == name).unwrap();
        let mut vm = Vm::new(Program {
            insns: loaded.insns,
            maps: object.maps,
            btf_ctx: loaded.btf_ctx,
        })
        .unwrap();
        let error = vm
            .verify(Config::default())
            .err()
            .expect("next helper must reject")
            .to_string();
        assert!(
            error.contains(&format!("unknown helper #{helper}")),
            "{path}::{name}: {error}"
        );
        assert!(!error.contains("scalar; loads need a pointer"), "{path}::{name}: {error}");
    }
}

// ---------------------------------------------------------------------------
// Verifier: btf_ctx_access() rules for the ctx itself
// ---------------------------------------------------------------------------

#[test]
fn ctx_slot_loads_accept_and_type() {
    // Load prev (slot 1), deref pid (offset 0) — and a narrow scalar-slot read.
    let mut vm = Vm::new(btf_prog(
        "r6 = *(u64 *)(r1 + 8)
         r0 = *(u32 *)(r6 + 0)
         r7 = *(u32 *)(r1 + 0)
         exit",
    ))
    .unwrap();
    let ok = vm.verify(Config::default()).unwrap();
    // Only the BTF-pointer deref (insn 1) is a probe read; ctx loads are not.
    assert_eq!(&ok.probe_mem[..4], &[false, true, false, false]);
}

#[test]
fn ctx_rejects_kernel_rules() {
    // Not a multiple of 8 (btf_ctx_access).
    assert!(verify_err("r0 = *(u64 *)(r1 + 4)\nexit").contains("multiple of 8"));
    // Beyond the typed argument slots.
    assert!(verify_err("r0 = *(u64 *)(r1 + 24)\nexit").contains("beyond"));
    // BTF ctx is read-only for tracing programs.
    assert!(verify_err("r0 = 0\n*(u64 *)(r1 + 0) = r0\nexit").contains("read-only"));
    // A pointer slot must be read whole.
    assert!(verify_err("r0 = *(u32 *)(r1 + 8)\nexit").contains("8-byte"));
    // Modified ctx pointer (kernel PTR_TO_CTX off==0 rule still applies).
    assert!(
        verify_err("r2 = r1\nr2 += 8\nr0 = *(u64 *)(r2 + 0)\nexit").contains("modified ctx")
    );
}

// ---------------------------------------------------------------------------
// Verifier: check_ptr_to_btf_access() / btf_struct_access() rules
// ---------------------------------------------------------------------------

#[test]
fn btf_ptr_deref_rules() {
    // Nested pointer chase (parent @8 in the fixture's task_struct), plus
    // constant pointer arithmetic before the deref.
    let mut vm = Vm::new(btf_prog(
        "r6 = *(u64 *)(r1 + 8)
         r6 += 8
         r7 = *(u64 *)(r6 + 0)
         r0 = *(u32 *)(r7 + 0)
         exit",
    ))
    .unwrap();
    let ok = vm.verify(Config::default()).unwrap();
    assert_eq!(&ok.probe_mem[..5], &[false, false, true, true, false]);

    // Out of bounds of the BTF type (task_struct is 32 bytes).
    assert!(verify_err(
        "r6 = *(u64 *)(r1 + 8)\nr0 = *(u32 *)(r6 + 32)\nexit"
    )
    .contains("outside BTF type"));
    // Read-only.
    assert!(verify_err(
        "r6 = *(u64 *)(r1 + 8)\nr0 = 0\n*(u32 *)(r6 + 0) = r0\nexit"
    )
    .contains("BTF pointer"));
    // Variable offset is not allowed.
    assert!(verify_err(
        "r6 = *(u64 *)(r1 + 8)\nr7 = *(u64 *)(r1 + 0)\nr6 += r7\nr0 = *(u32 *)(r6 + 0)\nexit"
    )
    .contains("variable offset"));
}

#[test]
fn btf_ptr_as_helper_buffer() {
    // A BTF pointer is not a helper memory buffer (ARG_PTR_TO_MEM parity)…
    assert!(verify_err(
        "r6 = *(u64 *)(r1 + 8)
         r1 = r6
         r2 = 8
         r3 = r6
         call 113
         exit"
    )
    .contains("helper memory buffer"));
    // …but it IS a valid probe_read_kernel source (ARG_ANYTHING).
    let mut vm = Vm::new(btf_prog(
        "r6 = *(u64 *)(r1 + 8)
         r1 = r10
         r1 += -8
         r2 = 8
         r3 = r6
         call 113
         r0 = 0
         exit",
    ))
    .unwrap();
    vm.verify(Config::default()).expect("probe_read_kernel from a BTF ptr");
}

#[test]
fn mixed_pointer_classes_on_one_insn_reject() {
    // The same load insn reached with a BTF pointer on one path and a stack
    // pointer on the other — the kernel rewrites loads one way or the other,
    // so this must reject with its exact message.
    let e = verify_err(
        "r6 = *(u64 *)(r1 + 8)
         r7 = r10
         r7 += -8
         r0 = 0
         *(u64 *)(r7 + 0) = r0
         r8 = *(u64 *)(r1 + 0)
         if r8 == 0 goto stackside
         r9 = r6
         goto load
stackside:
         r9 = r7
load:
         r0 = *(u64 *)(r9 + 0)
         exit",
    );
    assert!(
        e.contains("same insn cannot be used with different pointers"),
        "{e}"
    );
}

// ---------------------------------------------------------------------------
// Runtime: kernel memory reads as zero, writes fault, NULL chases probe-read
// ---------------------------------------------------------------------------

#[test]
fn runtime_reads_zero_and_distinct_arg_pointers() {
    // Kernel memory reads as zero…
    let mut vm = Vm::new(btf_prog(
        "r6 = *(u64 *)(r1 + 8)\nr0 = *(u64 *)(r6 + 0)\nexit",
    ))
    .unwrap();
    vm.verify(Config::default()).unwrap();
    let mut ctx = vec![0u8; 64];
    assert_eq!(vm.run(&mut ctx).unwrap(), 0);
    // …and distinct pointer arguments compare unequal (prev != next), while
    // the pointers themselves are nonzero.
    let mut vm = Vm::new(btf_prog(
        "r6 = *(u64 *)(r1 + 8)
         r7 = *(u64 *)(r1 + 16)
         r0 = 1
         if r6 == r7 goto out
         if r6 == 0 goto out
         if r7 == 0 goto out
         r0 = 0
out:
         exit",
    ))
    .unwrap();
    vm.verify(Config::default()).unwrap();
    let mut ctx = vec![0u8; 64];
    assert_eq!(vm.run(&mut ctx).unwrap(), 0);
}

#[test]
fn runtime_null_chase_probes_to_zero_only_when_verified() {
    // parent (kernel memory) reads as 0 = NULL; the next deref goes through
    // address 0. Verified: the load is a probe read and yields 0 (kernel
    // BPF_PROBE_MEM parity). Unverified: it faults cleanly instead.
    let src = "r6 = *(u64 *)(r1 + 8)
               r6 = *(u64 *)(r6 + 8)
               r0 = *(u32 *)(r6 + 0)
               exit";
    let mut vm = Vm::new(btf_prog(src)).unwrap();
    vm.verify(Config::default()).unwrap();
    let mut ctx = vec![0u8; 64];
    assert_eq!(vm.run(&mut ctx).unwrap(), 0);

    let mut vm = Vm::new(btf_prog(src)).unwrap(); // no verify
    let mut ctx = vec![0u8; 64];
    let err = vm.run(&mut ctx).unwrap_err().to_string();
    assert!(err.contains("invalid pointer"), "{err}");
}

#[test]
fn runtime_kernel_memory_write_faults() {
    // Even unverified, the virtual-address model keeps kernel memory
    // write-protected (this is what keeps --no-verify and the JIT honest).
    let mut vm = Vm::new(btf_prog(
        "r6 = *(u64 *)(r1 + 8)\nr0 = 0\n*(u64 *)(r6 + 0) = r0\nexit",
    ))
    .unwrap();
    let mut ctx = vec![0u8; 64];
    let err = vm.run(&mut ctx).unwrap_err().to_string();
    assert!(err.contains("kernel memory"), "{err}");
}

#[cfg(feature = "jit")]
#[test]
fn jit_matches_interpreter_on_btf_fixture() {
    let bytes = fixture_bytes();
    let target = fixture_btf_raw(&bytes);
    let obj = febpf::elf::load_with_target_btf(&bytes, Some(&target)).unwrap();
    let prog = obj
        .programs
        .into_iter()
        .find(|p| p.name == "tp_btf/sched_switch")
        .unwrap();
    let program = Program {
        insns: prog.insns,
        maps: obj.maps,
        btf_ctx: prog.btf_ctx,
    };

    let mut vi = Vm::new(program.clone()).unwrap();
    vi.verify(Config::default()).unwrap();
    let mut ctx = vec![0u8; 4096];
    let interp = vi.run(&mut ctx).unwrap();

    let mut vj = Vm::new(program).unwrap();
    vj.verify(Config::default()).unwrap();
    let mut ctx = vec![0u8; 4096];
    let jit = vj.run_jit(&mut ctx).unwrap();
    assert_eq!(interp, jit);
}
