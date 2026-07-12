use febpf::insn::{class, mode, size, Insn};
use febpf::builder::{Builder, MemSize};
use febpf::verifier::{Config, LegacyPacketProfile};
use febpf::{asm, disasm, kbpf, MetadataLayout, Program, RegionAccess, Vm};

fn program(source: &str) -> Program {
    let assembled = asm::assemble(source).expect("assembly failed");
    Program {
        insns: assembled.insns,
        maps: assembled.maps,
        btf_ctx: None,
    }
}

fn packet_config() -> Config {
    Config {
        ctx_size: 24,
        ctx_writable: false,
        xdp: true,
        legacy_packet: LegacyPacketProfile::Linux,
        ..Default::default()
    }
}

fn run_packet(source: &str, packet: &[u8]) -> u64 {
    let mut vm = Vm::new(program(source)).unwrap();
    vm.verify(packet_config()).expect("packet verification failed");
    let mut packet = packet.to_vec();
    vm.run_xdp(&mut packet).expect("packet execution failed")
}

fn verify_error(source: &str, cfg: Config) -> String {
    let mut vm = Vm::new(program(source)).unwrap();
    match vm.verify(cfg) {
        Ok(_) => panic!("program unexpectedly verified"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn assembler_disassembler_round_trip_abs_and_ind() {
    let source = "\
r6 = r1
ldabsb 3
r2 = 1
ldindh r2, 4
ldindw r7, -2
exit
";
    let first = asm::assemble(source).unwrap();
    let text = (0..first.insns.len())
        .map(|pc| disasm::disasm_insn(&first.insns, pc))
        .collect::<Vec<_>>()
        .join("\n");
    let second = asm::assemble(&text).unwrap();
    assert_eq!(second.insns, first.insns, "{text}");
    assert_eq!(first.insns[1].opcode, class::LD | mode::ABS | size::B);
    assert_eq!(first.insns[3].opcode, class::LD | mode::IND | size::H);
    assert_eq!(first.insns[3].src, 2);
    assert_eq!(first.insns[3].imm, 4);
}

#[test]
fn typed_builder_emits_exact_legacy_encodings() {
    let insns = Builder::new()
        .legacy_packet_abs(MemSize::Byte, 14)
        .legacy_packet_ind(MemSize::Double, 3, -2)
        .build()
        .unwrap();
    assert_eq!(insns[0].encode(), [0x30, 0, 0, 0, 14, 0, 0, 0]);
    assert_eq!(insns[1].opcode, 0x58);
    assert_eq!(insns[1].src, 3);
    assert_eq!(insns[1].imm, -2);
}

#[test]
fn loads_use_network_byte_order_and_exact_end_boundary() {
    let packet = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab];
    assert_eq!(run_packet("r6 = r1\nldabsb 5\nexit", &packet), 0xab);
    assert_eq!(run_packet("r6 = r1\nldabsh 4\nexit", &packet), 0x89ab);
    assert_eq!(run_packet("r6 = r1\nldabsw 2\nexit", &packet), 0x4567_89ab);
    assert_eq!(
        run_packet("r6 = r1\nr2 = 2\nldindw r2, 0\nexit", &packet),
        0x4567_89ab
    );
}

#[test]
fn out_of_bounds_load_terminates_cleanly_with_zero() {
    let source = "\
r6 = r1
r0 = 99
ldabsw 1
r0 = 77
exit
";
    assert_eq!(run_packet(source, &[1, 2, 3, 4]), 0);
    assert_eq!(run_packet("r6 = r1\nr2 = 0\nldindb r2, -1\nexit", &[1]), 0);
}

#[test]
fn verifier_requires_packet_mode_r6_scalar_index_and_observes_clobbers() {
    let abs = "r6 = r1\nldabsb 0\nexit";
    assert!(verify_error(abs, Config { ctx_size: 24, ..Default::default() })
        .contains("profile disabled"));

    let missing_r6 = "ldabsb 0\nexit";
    assert!(verify_error(missing_r6, packet_config()).contains("uninitialized register r6"));

    let pointer_index = "r6 = r1\nldindb r6, 0\nexit";
    assert!(verify_error(pointer_index, packet_config()).contains("must be a scalar"));

    let modified_r6 = "\
r6 = r1
call get_prandom_u32
r2 = r0
r2 &= 1
r6 += r2
ldabsb 0
exit";
    let error = verify_error(modified_r6, packet_config());
    assert!(error.contains("r6 to hold the packet context"), "{error}");

    let clobber = "r6 = r1\nr2 = 0\nldindb r2, 0\nr0 = r2\nexit";
    assert!(verify_error(clobber, packet_config()).contains("uninitialized register r2"));
}

#[test]
fn verifier_rejects_dw_and_malformed_forms() {
    let make = |opcode, dst, src, off| Program {
        insns: vec![
            Insn { opcode: class::ALU64 | febpf::insn::alu::MOV | febpf::insn::src::X, dst: 6, src: 1, off: 0, imm: 0 },
            Insn { opcode, dst, src, off, imm: 0 },
            Insn { opcode: class::JMP | febpf::insn::jmp::EXIT, dst: 0, src: 0, off: 0, imm: 0 },
        ],
        maps: vec![],
        btf_ctx: None,
    };
    for (program, message) in [
        (make(class::LD | mode::ABS | size::DW, 0, 0, 0), "require the Rbpf041 profile"),
        (make(class::LD | mode::ABS | size::B, 1, 0, 0), "dst=0"),
        (make(class::LD | mode::ABS | size::B, 0, 0, 1), "off=0"),
        (make(class::LD | mode::ABS | size::B, 0, 2, 0), "src=0"),
        ({
            let mut p = make(class::LD | mode::ABS | size::B, 0, 0, 0);
            p.insns[1].imm = -1;
            p
        }, "must be nonnegative"),
        (make(class::LD | mode::IND | size::B, 0, 15, 0), "invalid src register"),
    ] {
        let mut vm = Vm::new(program).unwrap();
        let error = match vm.verify(packet_config()) {
            Ok(_) => panic!("program unexpectedly verified"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(message), "{error}");
    }
}

#[test]
fn rbpf_profile_supports_little_endian_dw_without_r6() {
    let source = "ldabsdw 1\nexit";
    let assembled = program(source);
    assert_eq!(assembled.insns[0].opcode, 0x38);
    assert_eq!(assembled.insns.len(), 2, "0x38 must remain a single-slot load");

    let mut vm = Vm::new(assembled).unwrap();
    vm.verify(Config {
        ctx_size: 9,
        legacy_packet: LegacyPacketProfile::Rbpf041,
        ..Default::default()
    })
    .unwrap();
    let mut packet = [0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    assert_eq!(vm.run_raw(&mut packet).unwrap(), 0x8877_6655_4433_2211);
}

#[test]
fn rbpf_041_public_raw_vectors_match_all_legacy_encodings() {
    let packet = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let cases = [
        ("ldabsb 3\nexit", 0x33),
        ("ldabsh 3\nexit", 0x4433),
        ("ldabsw 3\nexit", 0x6655_4433),
        ("ldabsdw 3\nexit", 0xaa99_8877_6655_4433),
        ("r1 = 5\nldindb r1, 3\nexit", 0x88),
        ("r1 = 5\nldindh r1, 3\nexit", 0x9988),
        ("r1 = 4\nldindw r1, 1\nexit", 0x8877_6655),
        ("r1 = 2\nldinddw r1, 3\nexit", 0xccbb_aa99_8877_6655),
    ];
    for (source, expected) in cases {
        let mut vm = Vm::new(program(source)).unwrap();
        vm.verify(Config {
            ctx_size: packet.len(),
            legacy_packet: LegacyPacketProfile::Rbpf041,
            ..Default::default()
        }).unwrap();
        assert_eq!(vm.run_raw(&mut packet.clone()).unwrap(), expected, "{source}");
    }
}

#[test]
fn rbpf_profile_preserves_r1_through_r5() {
    let source = "\
r1 = 1
r2 = 2
r3 = 3
r4 = 4
r5 = 5
ldabsb 0
r0 += r1
r0 += r2
r0 += r3
r0 += r4
r0 += r5
exit";
    let config = Config {
        ctx_size: 1,
        legacy_packet: LegacyPacketProfile::Rbpf041,
        ..Default::default()
    };
    let mut interpreted = Vm::new(program(source)).unwrap();
    interpreted.verify(config.clone()).unwrap();
    let mut packet = [7];
    assert_eq!(interpreted.run_raw(&mut packet).unwrap(), 22);

    #[cfg(feature = "jit")]
    {
        let mut jitted = Vm::new(program(source)).unwrap();
        jitted.verify(config).unwrap();
        assert_eq!(jitted.run_raw_jit(&mut packet).unwrap(), 22);
    }
}

#[test]
fn profiles_distinguish_oob_and_missing_backing() {
    let mut rbpf = Vm::new(program("ldabsw 1\nexit")).unwrap();
    rbpf.verify(Config {
        ctx_size: 2,
        legacy_packet: LegacyPacketProfile::Rbpf041,
        ..Default::default()
    })
    .unwrap();
    let mut short = [1, 2];
    let error = rbpf.run_raw(&mut short).unwrap_err();
    assert_eq!(error.pc, 0);
    assert!(error.to_string().contains("out of bounds"));

    let mut linux = Vm::new(program("r6 = r1\nldabsb 0\nexit")).unwrap();
    linux.verify(Config {
        ctx_size: 1,
        legacy_packet: LegacyPacketProfile::Linux,
        ..Default::default()
    })
    .unwrap();
    let error = linux.run(&mut [7]).unwrap_err();
    assert_eq!(error.pc, 0);
    assert!(error.to_string().contains("input unavailable"));

    let mut overflow = Vm::new(program("r2 = -1 ll\nldindb r2, 1\nexit")).unwrap();
    overflow.verify(Config {
        ctx_size: 1,
        legacy_packet: LegacyPacketProfile::Rbpf041,
        ..Default::default()
    })
    .unwrap();
    assert!(overflow
        .run_raw(&mut [7])
        .unwrap_err()
        .to_string()
        .contains("out of bounds"));
}

#[test]
fn metadata_adapters_bind_the_selected_owned_packet() {
    let layout = MetadataLayout::new(8, 24).unwrap();
    for fixed in [false, true] {
        let mut vm = Vm::new(program("ldabsh 1\nexit")).unwrap();
        let base = vm
            .register_owned_region(vec![0xff, 0x33, 0x44], RegionAccess::ReadWrite)
            .unwrap();
        vm.verify(Config {
            ctx_size: 32,
            metadata_layout: Some(layout),
            legacy_packet: LegacyPacketProfile::Rbpf041,
            ..Default::default()
        })
        .unwrap();
        let result = if fixed {
            vm.run_fixed_metadata(base).unwrap()
        } else {
            vm.run_metadata(&mut [0u8; 32], base).unwrap()
        };
        assert_eq!(result, 0x4433);
    }
}

#[cfg(feature = "jit")]
#[test]
fn hybrid_jit_matches_interpreter_for_packet_load_and_oob_exit() {
    for (source, packet) in [
        ("r6 = r1\nr2 = 1\nldindw r2, 1\nexit", &[0x99, 1, 2, 3, 4, 5][..]),
        ("r6 = r1\nldabsw 3\nr0 = 55\nexit", &[1, 2, 3, 4][..]),
    ] {
        let mut interpreted = Vm::new(program(source)).unwrap();
        interpreted.verify(packet_config()).unwrap();
        let mut interp_packet = packet.to_vec();
        let expected = interpreted.run_xdp(&mut interp_packet).unwrap();

        let mut jitted = Vm::new(program(source)).unwrap();
        jitted.verify(packet_config()).unwrap();
        let mut jit_packet = packet.to_vec();
        assert_eq!(jitted.run_xdp_jit(&mut jit_packet).unwrap(), expected);
    }

    let source = "ldabsdw 1\nexit";
    let config = Config {
        ctx_size: 9,
        legacy_packet: LegacyPacketProfile::Rbpf041,
        ..Default::default()
    };
    let mut interpreted = Vm::new(program(source)).unwrap();
    interpreted.verify(config.clone()).unwrap();
    let mut packet = [0xff, 1, 2, 3, 4, 5, 6, 7, 8];
    let expected = interpreted.run_raw(&mut packet).unwrap();
    let mut jitted = Vm::new(program(source)).unwrap();
    jitted.verify(config).unwrap();
    assert_eq!(jitted.run_raw_jit(&mut packet).unwrap(), expected);

    let oob = "ldabsdw 2\nexit";
    let mut jitted = Vm::new(program(oob)).unwrap();
    jitted
        .verify(Config {
            ctx_size: packet.len(),
            legacy_packet: LegacyPacketProfile::Rbpf041,
            ..Default::default()
        })
        .unwrap();
    let error = jitted.run_raw_jit(&mut packet).unwrap_err();
    assert_eq!(error.pc, 0);
    assert!(error.to_string().contains("out of bounds"));
}

/// Compare Linux-profile legacy packet loads with the real socket-filter
/// implementation. The febpf half always runs; only the raw `bpf(2)` oracle
/// is privilege- and kernel-support-gated.
#[test]
fn linux_legacy_packet_loads_match_kernel_if_available() {
    struct Case {
        name: &'static str,
        source: &'static str,
        expected: u64,
    }

    let packet = [
        0xff, 0x12, 0x34, 0x56, 0x78, 0xab, 0xcd, 0x80,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0xbe, 0xef,
    ];
    let cases = [
        Case {
            name: "ABS W network byte order",
            source: "r6 = r1\nldabsw 1\nexit",
            expected: 0x1234_5678,
        },
        Case {
            name: "IND H exact end",
            source: "r6 = r1\nr2 = 14\nldindh r2, 0\nexit",
            expected: 0xbeef,
        },
        Case {
            name: "IND B",
            source: "r6 = r1\nr2 = 5\nldindb r2, 2\nexit",
            expected: 0x80,
        },
        Case {
            name: "OOB implicit zero exit",
            source: "r6 = r1\nr0 = 99\nldabsw 13\nr0 = 77\nexit",
            expected: 0,
        },
    ];

    let programs = cases.iter().map(|case| {
        let program = program(case.source);
        let config = Config {
            ctx_size: packet.len(),
            ctx_writable: false,
            legacy_packet: LegacyPacketProfile::Linux,
            ..Default::default()
        };
        let mut interpreted = Vm::new(program.clone()).unwrap();
        interpreted.verify(config.clone()).unwrap();
        let mut input = packet;
        assert_eq!(interpreted.run_raw(&mut input).unwrap(), case.expected,
            "{}: interpreter", case.name);
        #[cfg(feature = "jit")]
        {
            let mut jitted = Vm::new(program.clone()).unwrap();
            jitted.verify(config).unwrap();
            let mut input = packet;
            assert_eq!(jitted.run_raw_jit(&mut input).unwrap(), case.expected,
                "{}: JIT", case.name);
        }
        program
    }).collect::<Vec<_>>();

    match kbpf::has_privilege() {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("skipped kernel half: no bpf privilege");
            return;
        }
        Err(error) if error.is_unsupported() || matches!(error.errno, 22 | 95) => {
            eprintln!("skipped kernel half: kernel BPF unavailable: {error}");
            return;
        }
        Err(error) => panic!("kernel privilege probe failed: {error}"),
    }

    for (index, (case, program)) in cases.iter().zip(programs).enumerate() {
        let mut log = String::new();
        match kbpf::run_program(&program.insns, &[], &packet, Some(&mut log)) {
            Ok(result) => assert_eq!(result as u64, case.expected, "{}: kernel", case.name),
            Err(error) if index == 0 && (error.is_permission()
                || error.is_unsupported() || matches!(error.errno, 22 | 95)) => {
                eprintln!("skipped kernel half: legacy socket-filter loads unavailable: {error}\n{}",
                    log.trim_end());
                return;
            }
            Err(error) => panic!("{}: kernel execution failed: {error}\n{}",
                case.name, log.trim_end()),
        }
    }
}
