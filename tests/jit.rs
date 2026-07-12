//! Differential testing of the JIT against the interpreter: every program is
//! run both ways and the results (and map side effects) must match exactly.

#![cfg(all(
    feature = "jit",
    any(
        all(target_arch = "x86_64", target_os = "linux"),
        all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux"))
    )
))]

use febpf::verifier::Config;
use febpf::{asm, Program, Vm};

fn programs() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    // (name, source, ctx)
    vec![
        ("const", "r0 = 42\n exit", vec![]),
        ("add", "r0 = 20\n r1 = 22\n r0 += r1\n exit", vec![]),
        ("sub_imm", "r0 = 100\n r0 -= 58\n exit", vec![]),
        ("mul", "r0 = 6\n r1 = 7\n r0 *= r1\n exit", vec![]),
        ("mul_imm", "r0 = 7\n r0 *= 6\n exit", vec![]),
        ("bitops", "r0 = 0xf0\n r0 |= 0x0f\n r0 &= 0xfe\n r0 ^= 0x11\n exit", vec![]),
        ("neg", "r0 = 5\n r0 = -r0\n exit", vec![]),
        ("neg32", "w0 = 5\n w0 = -w0\n exit", vec![]),
        ("shifts", "r0 = 1\n r0 <<= 40\n r0 >>= 8\n exit", vec![]),
        ("arsh", "r0 = -16\n r0 s>>= 2\n exit", vec![]),
        ("alu32_zext", "r0 = -1\n w0 += 1\n exit", vec![]),
        ("mov32", "r1 = 0x1_00000005 ll\n w0 = w1\n exit", vec![]),
        (
            "cond_u",
            "r0 = 0\n r1 = 5\n if r1 > 4 goto big\n r0 = 1\n exit\n big:\n r0 = 2\n exit",
            vec![],
        ),
        (
            "cond_s",
            "r1 = -1\n r0 = 0\n if r1 s< 0 goto neg\n r0 = 1\n exit\n neg:\n r0 = 2\n exit",
            vec![],
        ),
        (
            "jmp32",
            "r1 = 0x1_00000000 ll\n r0 = 1\n if w1 == 0 goto y\n r0 = 2\n y:\n exit",
            vec![],
        ),
        (
            "jset",
            "r1 = 10\n r0 = 0\n if r1 & 2 goto s\n r0 = 9\n exit\n s:\n r0 = 7\n exit",
            vec![],
        ),
        (
            "sum_loop",
            "r0 = 0\n r2 = 1000\n l:\n r0 += r2\n r2 -= 1\n if r2 != 0 goto l\n exit",
            vec![],
        ),
        (
            "nested_branches",
            "r1 = 7\n r0 = 0\n if r1 s> 10 goto a\n if r1 s> 5 goto b\n r0 = 1\n exit\n a:\n r0 = 2\n exit\n b:\n r0 = 3\n exit",
            vec![],
        ),
        // memory + deferred instructions interleaved with native ALU
        (
            "stack_rmw",
            "r1 = 100\n *(u64 *)(r10 - 8) = r1\n r0 = *(u64 *)(r10 - 8)\n r0 += 5\n r0 *= 2\n exit",
            vec![],
        ),
        (
            "ctx_sum",
            "r2 = *(u8 *)(r1)\n r3 = *(u8 *)(r1 + 1)\n r0 = r2\n r0 += r3\n r0 <<= 1\n exit",
            vec![0x11, 0x22],
        ),
        (
            "bpf_call",
            "r1 = 20\n r2 = 22\n call add\n exit\n add:\n r0 = r1\n r0 += r2\n exit",
            vec![],
        ),
        (
            "loop_with_call",
            "r6 = 0\n r7 = 5\n l:\n r1 = r7\n call dbl\n r6 += r0\n r7 -= 1\n if r7 != 0 goto l\n r0 = r6\n exit\n dbl:\n r0 = r1\n r0 += r1\n exit",
            vec![],
        ),
    ]
}

fn interp_run(src: &str, ctx: &mut [u8]) -> u64 {
    let a = asm::assemble(src).unwrap();
    let mut vm = Vm::new(Program {
        insns: a.insns,
        maps: a.maps,
        btf_ctx: None,
    })
    .unwrap();
    vm.verify(Config {
        ctx_size: ctx.len(),
        ..Default::default()
    })
    .unwrap();
    vm.run(ctx).unwrap()
}

fn jit_run(src: &str, ctx: &mut [u8]) -> u64 {
    let a = asm::assemble(src).unwrap();
    let mut vm = Vm::new(Program {
        insns: a.insns,
        maps: a.maps,
        btf_ctx: None,
    })
    .unwrap();
    vm.verify(Config {
        ctx_size: ctx.len(),
        ..Default::default()
    })
    .unwrap();
    vm.run_jit(ctx).unwrap()
}

#[test]
fn jit_matches_interpreter() {
    for (name, src, ctx) in programs() {
        let mut c1 = ctx.clone();
        let mut c2 = ctx.clone();
        let interp = interp_run(src, &mut c1);
        let jit = jit_run(src, &mut c2);
        assert_eq!(interp, jit, "program '{name}': interp={interp} jit={jit}");
        assert_eq!(c1, c2, "program '{name}': ctx side effects diverged");
    }
}

#[test]
fn jit_map_side_effects() {
    let src = "
        .map counts array 4 8 4
        w1 = 1
        *(u32 *)(r10 - 4) = r1
        r1 = 777
        *(u64 *)(r10 - 16) = r1
        r1 = map[counts]
        r2 = r10
        r2 += -4
        r3 = r10
        r3 += -16
        r4 = 0
        call map_update_elem
        r1 = map[counts]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 == 0 goto miss
        r0 = *(u64 *)(r0)
        exit
    miss:
        r0 = 0
        exit";
    assert_eq!(jit_run(src, &mut []), 777);
}

#[test]
fn jit_hash_counter_loop() {
    // exercises loops, calls, atomics, maps — all under the JIT
    let src = "
        .map h hash 4 8 16
        w1 = 7
        *(u32 *)(r10 - 4) = r1
        r6 = 500
    loop:
        r1 = map[h]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 != 0 goto found
        r1 = 0
        *(u64 *)(r10 - 16) = r1
        r1 = map[h]
        r2 = r10
        r2 += -4
        r3 = r10
        r3 += -16
        r4 = 0
        call map_update_elem
        goto next
    found:
        r1 = 1
        lock *(u64 *)(r0) += r1
    next:
        r6 -= 1
        if r6 != 0 goto loop
        r1 = map[h]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 == 0 goto miss
        r0 = *(u64 *)(r0)
        exit
    miss:
        r0 = -1
        exit";
    assert_eq!(jit_run(src, &mut []), 499);
}

#[test]
fn jit_ringbuf_matches_interpreter() {
    // ringbuf reserve/write/submit through the (deferred) helper path under
    // both engines; the captured record must be identical.
    let src = "
        .map rb ringbuf 0 0 4096
        r1 = map[rb]
        r2 = 8
        r3 = 0
        call ringbuf_reserve
        if r0 == 0 goto out
        r6 = r0
        r1 = 0x1122334455667788 ll
        *(u64 *)(r6 + 0) = r1
        r1 = r6
        r2 = 0
        call ringbuf_submit
        r0 = 0
        exit
    out:
        r0 = 1
        exit";
    let records = |jit: bool| -> Vec<Vec<u8>> {
        let a = asm::assemble(src).unwrap();
        let mut vm = Vm::new(Program {
            insns: a.insns,
            maps: a.maps,
            btf_ctx: None,
        })
        .unwrap();
        vm.verify(Config::default()).unwrap();
        if jit {
            vm.run_jit(&mut []).unwrap();
        } else {
            vm.run(&mut []).unwrap();
        }
        vm.ringbuf_records("rb").unwrap().to_vec()
    };
    assert_eq!(records(false), records(true));
    assert_eq!(records(true), vec![0x1122334455667788u64.to_le_bytes().to_vec()]);
}

#[test]
fn jit_percpu_array_matches_interpreter() {
    let src = "
        .map pa percpu_array 4 8 4
        w1 = 2
        *(u32 *)(r10 - 4) = r1
        r1 = 555
        *(u64 *)(r10 - 16) = r1
        r1 = map[pa]
        r2 = r10
        r2 += -4
        r3 = r10
        r3 += -16
        r4 = 0
        call map_update_elem
        r1 = map[pa]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 == 0 goto miss
        r0 = *(u64 *)(r0)
        exit
    miss:
        r0 = 0
        exit";
    assert_eq!(interp_run(src, &mut []), jit_run(src, &mut []));
    assert_eq!(jit_run(src, &mut []), 555);
}

#[test]
fn jit_runtime_fault_is_caught() {
    // dividing is deferred, but an out-of-bounds stack access must fault
    // cleanly under the JIT (not corrupt memory or crash).
    let a = asm::assemble("r1 = 1\n r2 = r10\n r0 = *(u64 *)(r2 + 8)\n exit").unwrap();
    let mut vm = Vm::new(Program {
        insns: a.insns,
        maps: a.maps,
        btf_ctx: None,
    })
    .unwrap();
    // skip verification so the bad access reaches the runtime
    let err = vm.run_jit(&mut []).unwrap_err();
    assert!(err.to_string().contains("out of bounds") || err.to_string().contains("bad pointer"),
        "unexpected error: {err}");
}

#[test]
fn jit_tail_call_bundle_matches_interpreter() {
    fn linked_vm() -> Vm {
        let entry = asm::assemble(
            ".map progs prog_array 4 4 1
             r2 = map[progs]
             r3 = 0
             call tail_call
             r0 = 7
             exit",
        )
        .unwrap();
        let target = asm::assemble(
            ".map progs prog_array 4 4 1
             r0 = 42
             exit",
        )
        .unwrap();
        let mut vm = Vm::new(Program {
            insns: entry.insns,
            maps: entry.maps,
            btf_ctx: None,
        })
        .unwrap();
        vm.verify(Config::default()).unwrap();
        vm.register_tail_call(
            "progs",
            0,
            Program {
                insns: target.insns,
                maps: target.maps,
                btf_ctx: None,
            },
            Config::default(),
        )
        .unwrap();
        vm
    }
    assert_eq!(linked_vm().run(&mut []).unwrap(), 42);
    assert_eq!(linked_vm().run_jit(&mut []).unwrap(), 42);
}
