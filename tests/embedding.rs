//! Behavioral coverage for febpf's public embedding surface.

use febpf::builder::{AluOp, Builder};
use febpf::helpers::{id, ArgKind, HelperSig, MemBus, RetKind};
use febpf::insn::{self, alu, class, jmp};
use febpf::verifier::Config;
use febpf::{asm, Program, Vm};
use febpf::{
    CompletedXdpFrame, XdpAction, XdpFrame, XdpMetadata, XdpProvider, XdpRedirect, XdpVerdict,
};
use std::collections::VecDeque;

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
fn xdp_frame_preserves_provider_capacity_and_matches_slice_adapter() {
    let source = "r2 = *(u32 *)(r1 + 0)\n\
                  r3 = *(u32 *)(r1 + 4)\n\
                  r4 = r2\n\
                  r4 += 1\n\
                  if r4 > r3 goto short\n\
                  *(u8 *)(r2 + 0) = 0xaa\n\
                  r0 = 2\n\
                  exit\n\
                  short:\n\
                  r0 = 1\n\
                  exit";
    let config = Config {
        ctx_size: 24,
        ctx_writable: false,
        xdp: true,
        ..Config::default()
    };
    let mut slice_vm = Vm::new(program(source)).unwrap();
    slice_vm.verify(config.clone()).unwrap();
    let mut frame_vm = Vm::new(program(source)).unwrap();
    frame_vm.verify(config).unwrap();

    let mut packet = [1, 2, 3];
    let slice_return = slice_vm.run_xdp(&mut packet).unwrap();
    let mut frame = XdpFrame::with_capacity(&[1, 2, 3], 17, 29).unwrap();
    let verdict = frame_vm.run_xdp_frame(&mut frame).unwrap();

    assert_eq!(verdict, XdpVerdict::new(slice_return));
    assert_eq!(verdict.action, Some(XdpAction::Pass));
    assert_eq!(frame.data(), packet);
    assert_eq!(frame.headroom(), 17);
    assert_eq!(frame.tailroom(), 29);
    assert_eq!(frame.capacity(), 49);

    #[cfg(feature = "jit")]
    {
        let mut jit_vm = Vm::new(program(source)).unwrap();
        jit_vm
            .verify(Config {
                ctx_size: 24,
                ctx_writable: false,
                xdp: true,
                ..Config::default()
            })
            .unwrap();
        let mut jit_frame = XdpFrame::with_capacity(&[1, 2, 3], 17, 29).unwrap();
        let jit_verdict = jit_vm.run_xdp_frame_jit(&mut jit_frame).unwrap();
        assert_eq!(jit_verdict, verdict);
        assert_eq!(jit_frame, frame);
    }
}

#[test]
fn xdp_frame_metadata_is_synthesized_without_exposing_provider_storage() {
    let mut vm = Vm::new(program(
        "r0 = *(u32 *)(r1 + 12)\n\
         r2 = *(u32 *)(r1 + 16)\n\
         r0 += r2\n\
         r2 = *(u32 *)(r1 + 20)\n\
         r0 += r2\n\
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
    let mut frame = XdpFrame::from_storage(vec![0, 0, 9, 8, 0], 2, 4).unwrap();
    frame.set_metadata(XdpMetadata {
        ingress_ifindex: 10,
        rx_queue_index: 20,
        egress_ifindex: 12,
    });
    frame.set_cookie(0xfeed_beef);

    assert_eq!(vm.run_xdp_frame(&mut frame).unwrap().return_value, 42);
    assert_eq!(frame.data(), [9, 8]);
    assert_eq!(frame.cookie(), 0xfeed_beef);
    let (storage, start, end) = frame.into_storage();
    assert_eq!(storage, [0, 0, 9, 8, 0]);
    assert_eq!((start, end), (2, 4));
}

#[derive(Default)]
struct MockXdpProvider {
    pending: VecDeque<XdpFrame>,
    completed: Vec<CompletedXdpFrame>,
}

impl XdpProvider for MockXdpProvider {
    type Error = &'static str;

    fn receive(&mut self) -> Result<Option<XdpFrame>, Self::Error> {
        Ok(self.pending.pop_front())
    }

    fn complete(&mut self, completed: CompletedXdpFrame) -> Result<(), Self::Error> {
        self.completed.push(completed);
        Ok(())
    }
}

#[test]
fn xdp_provider_processing_is_bounded_and_returns_frames_in_order() {
    let mut vm = Vm::new(program(
        "r2 = *(u32 *)(r1 + 0)\n\
                                  r3 = *(u32 *)(r1 + 4)\n\
                                  r4 = r2\n\
                                  r4 += 1\n\
                                  if r4 > r3 goto out\n\
                                  r0 = *(u8 *)(r2 + 0)\n\
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
    let mut provider = MockXdpProvider {
        pending: [[1u8], [2], [3]]
            .into_iter()
            .map(|packet| XdpFrame::new(&packet))
            .collect(),
        completed: Vec::new(),
    };

    let first = vm.run_xdp_provider(&mut provider, 2).unwrap();
    assert_eq!(first.received, 2);
    assert_eq!(first.completed, 2);
    assert_eq!(first.runtime_errors, 0);
    assert_eq!(provider.pending.len(), 1);
    assert_eq!(provider.completed[0].frame.data(), [1]);
    assert_eq!(
        provider.completed[0].result.as_ref().unwrap().return_value,
        1
    );
    assert_eq!(provider.completed[1].frame.data(), [2]);
    assert_eq!(
        provider.completed[1].result.as_ref().unwrap().return_value,
        2
    );

    let second = vm.run_xdp_provider(&mut provider, 8).unwrap();
    assert_eq!(second.received, 1);
    assert_eq!(second.completed, 1);
    assert_eq!(provider.completed[2].frame.data(), [3]);
}

#[test]
fn xdp_provider_receives_runtime_failures_as_completions() {
    let mut vm = Vm::new(program("r0 = 2\nexit")).unwrap();
    vm.verify(Config {
        ctx_size: 24,
        ctx_writable: false,
        xdp: true,
        ..Config::default()
    })
    .unwrap();
    vm.insn_limit = 0;
    let mut provider = MockXdpProvider {
        pending: [XdpFrame::new(&[7])].into_iter().collect(),
        completed: Vec::new(),
    };

    let stats = vm.run_xdp_provider(&mut provider, 1).unwrap();
    assert_eq!(stats.runtime_errors, 1);
    assert_eq!(stats.completed, 1);
    assert!(provider.completed[0].result.is_err());
    assert_eq!(provider.completed[0].frame.data(), [7]);
}

#[test]
fn xdp_verdict_delivers_direct_and_map_redirect_destinations() {
    let config = || Config {
        ctx_size: 24,
        ctx_writable: false,
        xdp: true,
        ..Config::default()
    };
    let mut direct = Vm::new(program("r1 = 17\nr2 = 0\ncall redirect\nexit")).unwrap();
    direct.verify(config()).unwrap();
    let mut frame = XdpFrame::new(&[1]);
    let verdict = direct.run_xdp_frame(&mut frame).unwrap();
    assert_eq!(verdict.action, Some(XdpAction::Redirect));
    assert_eq!(
        verdict.redirect,
        Some(XdpRedirect::Interface {
            ifindex: 17,
            flags: 0,
        })
    );

    let mut map = Vm::new(program(
        ".map targets xskmap 4 4 4\n\
         *(u32 *)(r10 - 4) = 2\n\
         *(u32 *)(r10 - 8) = 7\n\
         r1 = map[targets]\n\
         r2 = r10\n\
         r2 += -4\n\
         r3 = r10\n\
         r3 += -8\n\
         r4 = 0\n\
         call map_update_elem\n\
         r1 = map[targets]\n\
         r2 = 2\n\
         r3 = 0x100\n\
         call redirect_map\n\
         exit",
    ))
    .unwrap();
    map.verify(config()).unwrap();
    let verdict = map.run_xdp_frame(&mut frame).unwrap();
    let expected = Some(XdpRedirect::Map {
        map_index: 0,
        map_kind: febpf::maps::MapKind::XskMap,
        key: 2,
        flags: 0x100,
    });
    assert_eq!(verdict.redirect, expected);

    #[cfg(feature = "jit")]
    {
        let verdict = map.run_xdp_frame_jit(&mut frame).unwrap();
        assert_eq!(verdict.redirect, expected);
    }
}

#[test]
fn redirect_destination_requires_final_redirect_and_replays_with_snapshot() {
    let mut vm = Vm::new(program(
        "r1 = 17\n\
         r2 = 0\n\
         call redirect\n\
         r1 = 18\n\
         r2 = 1\n\
         call redirect\n\
         r0 = 4\n\
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
    let mut ctx = vm.prepare_xdp(&[1]).unwrap();
    let mut machine = vm.machine_prepared_xdp(&mut ctx).unwrap();
    for _ in 0..3 {
        assert_eq!(machine.step().unwrap(), None);
    }
    let selected = Some(XdpRedirect::Interface {
        ifindex: 17,
        flags: 0,
    });
    assert_eq!(machine.xdp_redirect(), selected);
    let snapshot = machine.snapshot();
    for _ in 0..3 {
        assert_eq!(machine.step().unwrap(), None);
    }
    assert_eq!(machine.xdp_redirect(), None);
    machine.restore(&snapshot);
    assert_eq!(machine.xdp_redirect(), selected);

    drop(machine);
    let mut no_redirect = Vm::new(program("r1 = 17\nr2 = 0\ncall redirect\nr0 = 2\nexit")).unwrap();
    no_redirect
        .verify(Config {
            ctx_size: 24,
            ctx_writable: false,
            xdp: true,
            ..Config::default()
        })
        .unwrap();
    let mut frame = XdpFrame::new(&[1]);
    assert_eq!(
        no_redirect.run_xdp_frame(&mut frame).unwrap().redirect,
        None
    );
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
