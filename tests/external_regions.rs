use febpf::helpers::{id, ArgKind, HelperSig, MemBus, RetKind};
use febpf::interp::RegionAccess;
use febpf::verifier::Config;
use febpf::{asm, Program, Vm};

fn program(src: &str) -> Program {
    let assembled = asm::assemble(src).unwrap();
    Program {
        insns: assembled.insns,
        maps: assembled.maps,
        btf_ctx: None,
    }
}

fn register_pointer_helper(vm: &mut Vm, base: u64, size: u32, writable: bool) {
    vm.user_helpers.register(
        id::FIRST_USER,
        HelperSig {
            name: "owned_region",
            args: [ArgKind::None; 5],
            ret: RetKind::ExternalMemory { size, writable },
        },
        Box::new(
            move |_: [u64; 5], _: &mut dyn MemBus| -> Result<u64, String> { Ok(base) },
        ),
    );
}

#[test]
fn typed_helper_returns_read_write_owned_region() {
    let mut vm = Vm::new(program(
        "call 0x10000\n\
         r1 = *(u8 *)(r0 + 1)\n\
         *(u8 *)(r0 + 2) = 0x7f\n\
         r0 = r1\n\
         exit",
    ))
    .unwrap();
    let base = vm
        .register_owned_region(vec![10, 42, 0, 99], RegionAccess::ReadWrite)
        .unwrap();
    register_pointer_helper(&mut vm, base, 4, true);
    vm.verify(Config::default()).unwrap();

    assert_eq!(vm.run_no_data().unwrap(), 42);
    assert_eq!(vm.owned_region(base), Some(&[10, 42, 0x7f, 99][..]));
}

#[test]
fn typed_helper_reads_read_only_owned_region() {
    let mut vm = Vm::new(program(
        "call 0x10000\n r0 = *(u8 *)(r0 + 0)\n exit",
    ))
    .unwrap();
    let base = vm
        .register_owned_region(vec![42], RegionAccess::ReadOnly)
        .unwrap();
    register_pointer_helper(&mut vm, base, 1, false);
    vm.verify(Config::default()).unwrap();
    assert_eq!(vm.run_no_data().unwrap(), 42);
}

#[test]
fn verifier_checks_external_region_bounds_and_mutability() {
    let mut bounds = Vm::new(program(
        "call 0x10000\n r0 = *(u8 *)(r0 + 4)\n exit",
    ))
    .unwrap();
    let base = bounds
        .register_owned_region(vec![0; 4], RegionAccess::ReadWrite)
        .unwrap();
    register_pointer_helper(&mut bounds, base, 4, true);
    let error = match bounds.verify(Config::default()) {
        Ok(_) => panic!("out-of-bounds external access verified"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("external memory access out of bounds"), "{error}");

    let mut readonly = Vm::new(program(
        "call 0x10000\n *(u8 *)(r0 + 0) = 1\n exit",
    ))
    .unwrap();
    let base = readonly
        .register_owned_region(vec![0], RegionAccess::ReadOnly)
        .unwrap();
    register_pointer_helper(&mut readonly, base, 1, false);
    let error = match readonly.verify(Config::default()) {
        Ok(_) => panic!("read-only external write verified"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("read-only external memory"), "{error}");
}

#[test]
fn unchecked_execution_still_enforces_actual_region_bounds_and_mutability() {
    let mut bounds = Vm::new(program(
        "call 0x10000\n r0 = *(u8 *)(r0 + 4)\n exit",
    ))
    .unwrap();
    let base = bounds
        .register_owned_region(vec![0; 4], RegionAccess::ReadWrite)
        .unwrap();
    register_pointer_helper(&mut bounds, base, 100, true);
    let error = bounds.run_no_data().unwrap_err().to_string();
    assert!(error.contains("access out of bounds"), "{error}");

    let mut readonly = Vm::new(program(
        "call 0x10000\n *(u8 *)(r0 + 0) = 1\n exit",
    ))
    .unwrap();
    let base = readonly
        .register_owned_region(vec![0], RegionAccess::ReadOnly)
        .unwrap();
    // Deliberately lie in the helper signature and skip verification. The
    // runtime region permission remains authoritative.
    register_pointer_helper(&mut readonly, base, 1, true);
    let error = readonly.run_no_data().unwrap_err().to_string();
    assert!(error.contains("read-only owned region"), "{error}");
    assert_eq!(readonly.owned_region(base), Some(&[0][..]));
}

#[test]
fn snapshots_capture_and_restore_owned_region_bytes() {
    let mut vm = Vm::new(program(
        "call 0x10000\n *(u8 *)(r0 + 0) = 9\n r0 = 0\n exit",
    ))
    .unwrap();
    let base = vm
        .register_owned_region(vec![1], RegionAccess::ReadWrite)
        .unwrap();
    register_pointer_helper(&mut vm, base, 1, true);
    vm.verify(Config::default()).unwrap();

    let mut ctx = [];
    let mut machine = vm.machine(&mut ctx);
    assert_eq!(machine.step().unwrap(), None); // helper returns the base
    let snapshot = machine.snapshot();
    assert_eq!(machine.step().unwrap(), None); // store 9
    assert_eq!(machine.vm_ref().owned_region(base), Some(&[9][..]));
    machine.restore(&snapshot);
    assert_eq!(machine.vm_ref().owned_region(base), Some(&[1][..]));
    assert_eq!(machine.step().unwrap(), None);
    assert_eq!(machine.vm_ref().owned_region(base), Some(&[9][..]));
}

#[test]
fn program_replacement_drops_owned_regions() {
    let mut vm = Vm::new(program("r0 = 1\n exit")).unwrap();
    let base = vm
        .register_owned_region(vec![1, 2, 3], RegionAccess::ReadWrite)
        .unwrap();
    assert_eq!(vm.owned_region(base), Some(&[1, 2, 3][..]));

    vm.replace_program(program("r0 = 2\n exit")).unwrap();
    assert_eq!(vm.owned_region(base), None);
}

#[cfg(feature = "jit")]
#[test]
fn owned_region_behavior_agrees_between_interpreter_and_jit() {
    fn configured_vm() -> (Vm, u64) {
        let mut vm = Vm::new(program(
            "call 0x10000\n\
             r1 = *(u32 *)(r0 + 0)\n\
             r1 += 5\n\
             *(u32 *)(r0 + 0) = r1\n\
             r0 = r1\n\
             exit",
        ))
        .unwrap();
        let base = vm
            .register_owned_region(37u32.to_le_bytes().to_vec(), RegionAccess::ReadWrite)
            .unwrap();
        register_pointer_helper(&mut vm, base, 4, true);
        vm.verify(Config::default()).unwrap();
        (vm, base)
    }

    let (mut interpreted, interpreted_base) = configured_vm();
    let (mut jitted, jitted_base) = configured_vm();
    let interpreted_result = interpreted.run_no_data().unwrap();
    let jitted_result = jitted.run_jit(&mut []).unwrap();
    assert_eq!(interpreted_result, jitted_result);
    assert_eq!(
        interpreted.owned_region(interpreted_base),
        jitted.owned_region(jitted_base)
    );
}
