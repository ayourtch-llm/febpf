use febpf::helpers::{id, ArgKind, HelperSig, MemBus, RetKind};
use febpf::verifier::Config;
use febpf::{asm, MetadataLayout, Program, RegionAccess, Vm};

fn program(source: &str) -> Program {
    let assembled = asm::assemble(source).unwrap();
    Program {
        insns: assembled.insns,
        maps: assembled.maps,
        btf_ctx: None,
    }
}

fn config(layout: MetadataLayout, size: usize) -> Config {
    Config {
        ctx_size: size,
        metadata_layout: Some(layout),
        ..Config::default()
    }
}

fn verify_error(vm: &mut Vm, config: Config) -> String {
    match vm.verify(config) {
        Ok(_) => panic!("verification unexpectedly succeeded"),
        Err(error) => error.to_string(),
    }
}

const READ_WRITE: &str = "
    r2 = *(u64 *)(r1 + 8)
    r3 = *(u64 *)(r1 + 24)
    r4 = r2
    r4 += 2
    if r4 > r3 goto short
    r0 = *(u8 *)(r2 + 0)
    r5 = *(u8 *)(r2 + 1)
    r0 += r5
    r4 = *(u8 *)(r2 + 0)
    r4 += 1
    *(u8 *)(r2 + 0) = r4
    exit
short:
    r0 = 0
    exit
";

#[test]
fn custom_offsets_preserve_metadata_and_packet_mutations_across_runs() {
    let layout = MetadataLayout::new(8, 24).unwrap();
    let mut vm = Vm::new(program(READ_WRITE)).unwrap();
    let base = vm
        .register_owned_region(vec![40, 2], RegionAccess::ReadWrite)
        .unwrap();
    vm.verify(config(layout, 40)).unwrap();

    let mut metadata = [0x5a; 40];
    assert_eq!(vm.run_metadata(&mut metadata, base).unwrap(), 42);
    assert_eq!(vm.owned_region(base), Some(&[41, 2][..]));
    assert_eq!(&metadata[0..8], &[0x5a; 8]);
    assert_eq!(&metadata[16..24], &[0x5a; 8]);
    assert_eq!(&metadata[32..40], &[0x5a; 8]);
    assert_eq!(
        u64::from_le_bytes(metadata[8..16].try_into().unwrap()),
        base
    );
    assert_eq!(
        u64::from_le_bytes(metadata[24..32].try_into().unwrap()),
        base + 2
    );

    assert_eq!(vm.run_metadata(&mut metadata, base).unwrap(), 43);
    assert_eq!(vm.owned_region(base), Some(&[42, 2][..]));
}

#[test]
fn fixed_metadata_is_zero_filled_and_uses_minimum_size() {
    let layout = MetadataLayout::new(16, 0).unwrap();
    let mut vm = Vm::new(program(
        "r2 = *(u64 *)(r1 + 16)\n\
         r3 = *(u64 *)(r1 + 0)\n\
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
    let base = vm
        .register_owned_region(vec![77], RegionAccess::ReadWrite)
        .unwrap();
    vm.verify(config(layout, layout.required_len())).unwrap();
    assert_eq!(layout.required_len(), 24);
    assert_eq!(vm.run_fixed_metadata(base).unwrap(), 77);
}

#[test]
fn invalid_layouts_configs_and_handles_fail_cleanly() {
    assert!(MetadataLayout::new(0, 7).is_err());
    assert!(MetadataLayout::new(usize::MAX, 0).is_err());

    let layout = MetadataLayout::new(0, 8).unwrap();
    let mut conflict = Vm::new(program("r0 = 0\nexit")).unwrap();
    let error = verify_error(
        &mut conflict,
        Config {
            metadata_layout: Some(layout),
            xdp: true,
            ..Config::default()
        },
    );
    assert!(error.contains("mutually exclusive"));

    let mut btf_conflict = Vm::new(program("r0 = 0\nexit")).unwrap();
    let error = verify_error(
        &mut btf_conflict,
        Config {
            metadata_layout: Some(layout),
            btf_ctx: Some(febpf::btf::BtfCtx { args: vec![], btf: None }),
            ..Config::default()
        },
    );
    assert!(error.contains("BTF and configurable metadata"));

    let mut short_config = Vm::new(program("r0 = 0\nexit")).unwrap();
    let error = verify_error(&mut short_config, config(layout, 15));
    assert!(error.contains("needs 16 context bytes"));

    let mut vm = Vm::new(program("r0 = 0\nexit")).unwrap();
    let writable = vm
        .register_owned_region(vec![1], RegionAccess::ReadWrite)
        .unwrap();
    let readonly = vm
        .register_owned_region(vec![1], RegionAccess::ReadOnly)
        .unwrap();
    vm.verify(config(layout, 16)).unwrap();
    let mut metadata = [0u8; 16];
    assert!(vm.run_metadata(&mut metadata[..15], writable).is_err());
    assert!(vm.run_metadata(&mut metadata, writable + 1).is_err());
    assert!(vm.run_metadata(&mut metadata, 1u64 << 32).is_err());
    let error = vm.run_metadata(&mut metadata, readonly).unwrap_err();
    assert!(error.to_string().contains("read-write"));
}

#[test]
fn empty_packet_branches_safely_and_oob_program_is_rejected() {
    let layout = MetadataLayout::new(0, 8).unwrap();
    let source = "
        r2 = *(u64 *)(r1 + 0)
        r3 = *(u64 *)(r1 + 8)
        r4 = r2
        r4 += 1
        if r4 > r3 goto short
        r0 = *(u8 *)(r2 + 0)
        exit
    short:
        r0 = 9
        exit";
    let mut vm = Vm::new(program(source)).unwrap();
    let base = vm
        .register_owned_region(Vec::new(), RegionAccess::ReadWrite)
        .unwrap();
    vm.verify(config(layout, 16)).unwrap();
    assert_eq!(vm.run_fixed_metadata(base).unwrap(), 9);

    let mut unsafe_vm =
        Vm::new(program("r2 = *(u64 *)(r1 + 0)\nr0 = *(u8 *)(r2 + 0)\nexit")).unwrap();
    let error = verify_error(&mut unsafe_vm, config(layout, 16));
    assert!(error.contains("packet access"));
}

#[test]
fn only_exact_u64_field_loads_produce_packet_pointers() {
    let layout = MetadataLayout::new(0, 8).unwrap();
    for source in [
        "r2 = *(u32 *)(r1 + 0)\nr0 = *(u8 *)(r2 + 0)\nexit",
        "r2 = *(u64 *)(r1 + 1)\nr0 = *(u8 *)(r2 + 0)\nexit",
    ] {
        let mut vm = Vm::new(program(source)).unwrap();
        let error = verify_error(&mut vm, config(layout, 16));
        assert!(error.contains("scalar"), "{error}");
    }
}

#[test]
fn strict_alignment_applies_to_metadata_pointer_fields() {
    let layout = MetadataLayout::new(1, 9).unwrap();
    let source = "
        r2 = *(u64 *)(r1 + 1)
        r3 = *(u64 *)(r1 + 9)
        r4 = r2
        if r4 >= r3 goto out
    out:
        r0 = 0
        exit";

    let mut relaxed = Vm::new(program(source)).unwrap();
    relaxed.verify(config(layout, 17)).unwrap();

    let mut strict = Vm::new(program(source)).unwrap();
    let error = verify_error(
        &mut strict,
        Config {
            strict_alignment: true,
            ..config(layout, 17)
        },
    );
    assert!(error.contains("misaligned metadata pointer"));
}

#[test]
fn replacement_resets_layout_and_invalidates_old_packet() {
    let layout = MetadataLayout::new(0, 8).unwrap();
    let mut vm = Vm::new(program("r0 = 1\nexit")).unwrap();
    let base = vm
        .register_owned_region(vec![1], RegionAccess::ReadWrite)
        .unwrap();
    vm.verify(config(layout, 16)).unwrap();

    let mut invalid = program(".map missing array 4 8 1\nr0 = map[missing][0]\nexit");
    invalid.maps.clear();
    assert!(vm.replace_program(invalid).is_err());
    let mut metadata = [0u8; 16];
    assert_eq!(vm.run_metadata(&mut metadata, base).unwrap(), 1);

    vm.replace_program(program("r0 = 2\nexit")).unwrap();
    assert!(vm.run_metadata(&mut metadata, base).is_err());
    vm.verify(config(layout, 16)).unwrap();
    assert!(vm.run_metadata(&mut metadata, base).is_err());
}

#[test]
fn helper_membus_and_metadata_pointer_share_the_owned_region() {
    let layout = MetadataLayout::new(0, 8).unwrap();
    let mut vm = Vm::new(program(
        "r2 = *(u64 *)(r1 + 8)\n\
         r1 = *(u64 *)(r1 + 0)\n\
         r3 = r1\n\
         r3 += 1\n\
         if r3 > r2 goto out\n\
         r2 = 1\n\
         call 0x10000\n\
         r0 = 0\n\
         exit\n\
         out:\n\
         r0 = 1\n\
         exit",
    ))
    .unwrap();
    vm.user_helpers.register(
        id::FIRST_USER,
        HelperSig {
            name: "write_packet",
            args: [
                ArgKind::MemWrite { size_arg: 1 },
                ArgKind::Size,
                ArgKind::None,
                ArgKind::None,
                ArgKind::None,
            ],
            ret: RetKind::Scalar,
        },
        Box::new(|args: [u64; 5], mem: &mut dyn MemBus| {
            mem.write(args[0], &[0x7f])?;
            Ok(0)
        }),
    );
    let base = vm
        .register_owned_region(vec![0], RegionAccess::ReadWrite)
        .unwrap();
    vm.verify(config(layout, 16)).unwrap();
    assert_eq!(vm.run_fixed_metadata(base).unwrap(), 0);
    assert_eq!(vm.owned_region(base), Some(&[0x7f][..]));
}

#[cfg(feature = "jit")]
#[test]
fn metadata_packet_behavior_agrees_with_jit() {
    fn configured() -> (Vm, u64) {
        let layout = MetadataLayout::new(8, 24).unwrap();
        let mut vm = Vm::new(program(READ_WRITE)).unwrap();
        let base = vm
            .register_owned_region(vec![40, 2], RegionAccess::ReadWrite)
            .unwrap();
        vm.verify(config(layout, 40)).unwrap();
        (vm, base)
    }

    let (mut interpreted, ibase) = configured();
    let (mut jitted, jbase) = configured();
    let mut imeta = [0u8; 40];
    assert_eq!(interpreted.run_metadata(&mut imeta, ibase).unwrap(), 42);

    let mut jmeta = [0u8; 40];
    assert_eq!(jitted.run_metadata_jit(&mut jmeta, jbase).unwrap(), 42);
    assert_eq!(interpreted.owned_region(ibase), jitted.owned_region(jbase));

    let (mut fixed, fbase) = configured();
    assert_eq!(fixed.run_fixed_metadata_jit(fbase).unwrap(), 42);
}
