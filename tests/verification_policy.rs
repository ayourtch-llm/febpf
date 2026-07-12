use std::cell::Cell;

use febpf::helpers::{id, ArgKind, HelperSig, MemBus, RetKind};
use febpf::interp::RegionAccess;
use febpf::verifier::{Config, VerifyWithPolicyError};
use febpf::{asm, Program, Vm};

fn program(src: &str) -> Program {
    let assembled = asm::assemble(src).unwrap();
    Program {
        insns: assembled.insns,
        maps: assembled.maps,
        btf_ctx: None,
    }
}

#[test]
fn policy_can_inspect_program_maps_and_core_evidence() {
    let mut vm = Vm::new(program(".map values array 4 8 1\n r0 = 42\n exit")).unwrap();
    let ok = vm
        .verify_with_policy(Config::default(), |view| {
            assert_eq!(view.insns.len(), 2);
            assert_eq!(view.maps.len(), 1);
            assert_eq!(view.maps[0].name, "values");
            assert_eq!(view.evidence.pc_regs.len(), view.insns.len());
            assert!(view.evidence.stats.insns_processed > 0);
            Ok(())
        })
        .unwrap();

    assert_eq!(ok.pc_regs.len(), 2);
    assert_eq!(vm.run_no_data().unwrap(), 42);
}

#[test]
fn policy_rejection_has_a_distinct_public_error() {
    let mut vm = Vm::new(program("r0 = 1\n exit")).unwrap();
    let error = match vm.verify_with_policy(Config::default(), |_| {
            Err("entry return value is forbidden".into())
        }) {
        Ok(_) => panic!("policy rejection was ignored"),
        Err(error) => error,
    };

    match error {
        VerifyWithPolicyError::Policy(message) => {
            assert_eq!(message, "entry return value is forbidden")
        }
        VerifyWithPolicyError::Core(error) => panic!("unexpected core error: {error}"),
    }
}

#[test]
fn core_rejection_short_circuits_policy() {
    let mut vm = Vm::new(program("r0 = r2\n exit")).unwrap();
    let called = Cell::new(false);
    let error = match vm.verify_with_policy(Config::default(), |_| {
            called.set(true);
            Ok(())
        }) {
        Ok(_) => panic!("invalid program verified"),
        Err(error) => error,
    };

    assert!(!called.get());
    match error {
        VerifyWithPolicyError::Core(error) => assert!(error.msg.contains("uninitialized")),
        VerifyWithPolicyError::Policy(message) => panic!("unexpected policy error: {message}"),
    }
}

#[test]
fn policy_layer_preserves_external_pointer_verification() {
    let mut vm = Vm::new(program(
        "call 0x10000\n *(u8 *)(r0 + 1) = 9\n r0 = 7\n exit",
    ))
    .unwrap();
    let base = vm
        .register_owned_region(vec![1, 2], RegionAccess::ReadWrite)
        .unwrap();
    vm.user_helpers.register(
        id::FIRST_USER,
        HelperSig {
            name: "external",
            args: [ArgKind::None; 5],
            ret: RetKind::ExternalMemory {
                size: 2,
                writable: true,
            },
        },
        Box::new(
            move |_: [u64; 5], _: &mut dyn MemBus| -> Result<u64, String> { Ok(base) },
        ),
    );

    vm.verify_with_policy(Config::default(), |_| Ok(()))
        .unwrap();
    assert_eq!(vm.run_no_data().unwrap(), 7);
    assert_eq!(vm.owned_region(base), Some(&[1, 9][..]));
}
