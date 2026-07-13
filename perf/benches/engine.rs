use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use febpf::{asm, elf, verifier, Program, VerifierConfig, Vm};

const SUM_LOOP: &str = include_str!("../../examples/sum_loop.s");
const CORE_PROBE: &[u8] = include_bytes!("../../tests/core_probe.o");
const CORE_TARGET: &[u8] = include_bytes!("../../tests/core_target.o");

fn sum_program() -> Program {
    let assembled = asm::assemble(SUM_LOOP).expect("committed sum_loop fixture must assemble");
    Program {
        insns: assembled.insns,
        maps: assembled.maps,
        btf_ctx: None,
    }
}

fn verified_sum_vm() -> Vm {
    let mut vm = Vm::new(sum_program()).expect("sum_loop VM must construct");
    vm.verify(VerifierConfig::default())
        .expect("sum_loop must verify");
    vm
}

fn sum_instruction_count() -> u64 {
    let mut vm = verified_sum_vm();
    let mut context = [];
    let mut machine = vm.machine(&mut context);
    while machine
        .step()
        .expect("sum_loop execution must succeed")
        .is_none()
    {}
    machine.insn_count
}

fn execution_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("execution/sum_loop");
    group.throughput(Throughput::Elements(sum_instruction_count()));

    let mut interpreter = verified_sum_vm();
    let mut interpreter_context = [];
    group.bench_function("interpreter", |b| {
        b.iter(|| {
            let result = interpreter
                .run(black_box(&mut interpreter_context))
                .expect("interpreter execution must succeed");
            black_box(result)
        });
    });

    let mut jit = verified_sum_vm();
    jit.compile().expect("host JIT must compile sum_loop");
    let mut jit_context = [];
    group.bench_function("jit_warm", |b| {
        b.iter(|| {
            let result = jit
                .run_jit(black_box(&mut jit_context))
                .expect("JIT execution must succeed");
            black_box(result)
        });
    });

    group.finish();
}

fn construction_benchmarks(c: &mut Criterion) {
    let program = sum_program();
    c.bench_function("verifier/sum_loop", |b| {
        b.iter(|| {
            let result = verifier::verify(
                black_box(&program.insns),
                black_box(&program.maps),
                &[],
                VerifierConfig::default(),
            )
            .expect("sum_loop must verify");
            black_box(result.stats.insns_processed)
        });
    });

    c.bench_function("jit/compile_sum_loop", |b| {
        b.iter_batched(
            verified_sum_vm,
            |mut vm| {
                vm.compile().expect("host JIT must compile sum_loop");
                black_box(vm.insns().len())
            },
            BatchSize::SmallInput,
        );
    });

    let target_btf = elf::read_section(CORE_TARGET, ".BTF")
        .expect("committed target ELF must parse")
        .expect("committed target ELF must contain BTF")
        .0;
    c.bench_function("elf/core_load_and_relocate", |b| {
        b.iter(|| {
            let object = elf::load_with_target_btf(
                black_box(CORE_PROBE),
                Some(black_box(target_btf.as_slice())),
            )
            .expect("committed CO-RE fixture must load");
            black_box(object.programs.len())
        });
    });
}

criterion_group!(benches, execution_benchmarks, construction_benchmarks);
criterion_main!(benches);
