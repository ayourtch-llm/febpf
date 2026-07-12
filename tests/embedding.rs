//! Behavioral coverage for febpf's public embedding surface.

use febpf::builder::{AluOp, Builder};
use febpf::helpers::{id, ArgKind, HelperSig, MemBus, RetKind};
use febpf::insn::{self, alu, class, jmp};
use febpf::verifier::Config;
use febpf::{asm, Program, Vm};

fn program(source: &str) -> Program {
    let assembled = asm::assemble(source).expect("assembly failed");
    Program {
        insns: assembled.insns,
        maps: assembled.maps,
        btf_ctx: None,
    }
}

fn instruction_program(insns: Vec<insn::Insn>) -> Program {
    Program {
        insns,
        maps: Vec::new(),
        btf_ctx: None,
    }
}

#[test]
fn no_data_adapter_executes_an_input_free_program() {
    let mut vm = Vm::new(program("r0 = 42\nexit")).unwrap();
    vm.verify(Config::default()).unwrap();

    assert_eq!(vm.run_no_data().unwrap(), 42);
}

#[test]
fn run_and_run_raw_accept_caller_owned_metadata() {
    let mut vm = Vm::new(program(
        "r0 = *(u32 *)(r1 + 0)\n\
         r2 = *(u16 *)(r1 + 8)\n\
         r0 += r2\n\
         *(u32 *)(r1 + 12) = r0\n\
         exit",
    ))
    .unwrap();
    vm.verify(Config {
        ctx_size: 16,
        ..Config::default()
    })
    .unwrap();

    let mut metadata = [0u8; 16];
    metadata[0..4].copy_from_slice(&40u32.to_le_bytes());
    metadata[8..10].copy_from_slice(&2u16.to_le_bytes());
    assert_eq!(vm.run(&mut metadata).unwrap(), 42);
    assert_eq!(&metadata[12..16], &42u32.to_le_bytes());

    metadata[0..4].copy_from_slice(&100u32.to_le_bytes());
    metadata[8..10].copy_from_slice(&23u16.to_le_bytes());
    assert_eq!(vm.run_raw(&mut metadata).unwrap(), 123);
    assert_eq!(&metadata[12..16], &123u32.to_le_bytes());
}

#[test]
fn run_xdp_synthesizes_metadata_and_copies_packet_writes_back() {
    let mut vm = Vm::new(program(
        "r2 = *(u32 *)(r1 + 0)\n\
         r3 = *(u32 *)(r1 + 4)\n\
         r4 = r2\n\
         r4 += 1\n\
         if r4 > r3 goto out\n\
         *(u8 *)(r2 + 0) = 0xaa\n\
         r0 = 1\n\
         exit\n\
         out:\n\
         r0 = 0\n\
         exit",
    ))
    .unwrap();
    vm.verify(Config {
        ctx_size: 24,
        ctx_writable: false,
        xdp: true,
        ..Config::default()
    })
    .unwrap();

    let mut packet = [1, 2, 3];
    assert_eq!(vm.run_xdp(&mut packet).unwrap(), 1);
    assert_eq!(packet, [0xaa, 2, 3]);

    let mut empty = [];
    assert_eq!(vm.run_xdp(&mut empty).unwrap(), 0);
}

#[test]
fn typed_builder_has_stable_encoding_and_executes() {
    let insns = Builder::new()
        .lddw(0, 0x1122_3344_0000_0028)
        .mov64_imm(1, 2)
        .alu64_reg(AluOp::Add, 0, 1)
        .exit()
        .build()
        .unwrap();

    assert_eq!(insns.len(), 5);
    assert_eq!(insns[0].opcode, 0x18);
    assert_eq!(insn::wide_imm(&insns, 0), 0x1122_3344_0000_0028);
    assert_eq!(insns[2].opcode, class::ALU64 | alu::MOV);
    assert_eq!(insns[3].opcode, class::ALU64 | alu::ADD | insn::src::X);
    assert_eq!(insns[4].opcode, class::JMP | jmp::EXIT);

    // Use a value that also proves the upper half emitted by lddw is retained.
    let mut vm = Vm::new(instruction_program(insns)).unwrap();
    vm.verify(Config::default()).unwrap();
    assert_eq!(vm.run_no_data().unwrap(), 0x1122_3344_0000_002a);
}

#[test]
fn failed_replacement_leaves_code_and_live_state_untouched() {
    let mut vm = Vm::new(program(
        ".map state array 4 8 1\n\
         r1 = map[state][0] + 0\n\
         r0 = *(u64 *)(r1 + 0)\n\
         r0 += 1\n\
         *(u64 *)(r1 + 0) = r0\n\
         exit",
    ))
    .unwrap();
    vm.verify(Config::default()).unwrap();
    assert_eq!(vm.run_no_data().unwrap(), 1);

    let mut invalid = program(".map missing array 4 8 1\nr0 = map[missing][0]\nexit");
    invalid.maps.clear();
    assert!(vm.replace_program(invalid).is_err());

    assert_eq!(vm.run_no_data().unwrap(), 2);
}

#[test]
fn successful_replacement_resets_program_state_and_preserves_helpers() {
    const ANSWER: u32 = id::FIRST_USER;

    let mut vm = Vm::new(program(
        ".map state array 4 8 1\n\
         r1 = map[state][0] + 0\n\
         *(u64 *)(r1 + 0) = 99\n\
         r0 = 0\n\
         exit",
    ))
    .unwrap();
    vm.user_helpers.register(
        ANSWER,
        HelperSig {
            name: "embedding_answer",
            args: [ArgKind::None; 5],
            ret: RetKind::Scalar,
        },
        Box::new(|_: [u64; 5], _: &mut dyn MemBus| -> Result<u64, String> { Ok(42) }),
    );
    vm.verify(Config::default()).unwrap();
    assert_eq!(vm.run_no_data().unwrap(), 0);

    vm.replace_program(program(
        ".map state array 4 8 1\n\
         call 0x10000\n\
         r1 = map[state][0] + 0\n\
         r1 = *(u64 *)(r1 + 0)\n\
         r0 += r1\n\
         exit",
    ))
    .unwrap();
    vm.verify(Config::default()).unwrap();

    // The callback remains registered, while the replacement map starts fresh.
    assert_eq!(vm.run_no_data().unwrap(), 42);
}
