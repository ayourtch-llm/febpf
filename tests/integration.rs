use febpf::verifier::Config;
use febpf::{asm, ExecutionEnvironment, Program, Vm};

fn program(src: &str) -> Program {
    let a = asm::assemble(src).expect("assembly failed");
    Program {
        insns: a.insns,
        maps: a.maps,
        btf_ctx: None,
    }
}

fn run_src(src: &str) -> u64 {
    run_ctx(src, &mut [])
}

fn run_ctx(src: &str, ctx: &mut [u8]) -> u64 {
    let mut vm = Vm::new(program(src)).unwrap();
    let cfg = Config {
        ctx_size: ctx.len(),
        ..Default::default()
    };
    vm.verify(cfg).expect("verification failed");
    vm.run(ctx).expect("run failed")
}

fn verify_err(src: &str) -> String {
    verify_err_ctx(src, 0)
}

fn verify_err_ctx(src: &str, ctx_size: usize) -> String {
    let mut vm = Vm::new(program(src)).unwrap();
    let cfg = Config {
        ctx_size,
        ..Default::default()
    };
    match vm.verify(cfg) {
        Ok(_) => panic!("expected verification to fail"),
        Err(e) => e.to_string(),
    }
}

fn xdp_config() -> Config {
    Config {
        ctx_size: 24,
        ctx_writable: false,
        xdp: true,
        ..Default::default()
    }
}

#[test]
fn xdp_alu32_data_end_minus_data_is_a_u32_scalar() {
    let mut vm = Vm::new(program(
        "r2 = *(u32 *)(r1 + 4)\n\
         r1 = *(u32 *)(r1 + 0)\n\
         w2 -= w1\n\
         r0 = r2\n\
         exit",
    ))
    .unwrap();
    vm.verify(xdp_config()).unwrap();

    let mut packet = [0u8; 37];
    assert_eq!(vm.run_xdp(&mut packet).unwrap(), 37);
    #[cfg(feature = "jit")]
    assert_eq!(vm.run_xdp_jit(&mut packet).unwrap(), 37);

    let mut vm = Vm::new(program(
        "r2 = *(u32 *)(r1 + 4)\n\
         w2 += 1\n\
         r0 = 0\n\
         exit",
    ))
    .unwrap();
    let error = match vm.verify(xdp_config()) {
        Ok(_) => panic!("ALU32 pointer addition verified"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("32-bit arithmetic on a pointer"), "{error}");

    for subtraction in [
        "r2 -= r1",
        "w3 = w2\nw3 -= w1\nr2 = r3",
        "w3 = w2\nw4 = w1\nw3 -= w4\nr2 = r3",
    ] {
        let mut vm = Vm::new(program(&format!(
            "r2 = *(u32 *)(r1 + 4)\n\
             r1 = *(u32 *)(r1 + 0)\n\
             {subtraction}\n\
             r0 = r2\n\
             exit"
        )))
        .unwrap();
        vm.verify(xdp_config()).unwrap();
        let mut packet = [0u8; 37];
        assert_eq!(vm.run_xdp(&mut packet).unwrap(), 37);
        #[cfg(feature = "jit")]
        assert_eq!(vm.run_xdp_jit(&mut packet).unwrap(), 37);
    }
}

#[test]
fn fib_lookup_requires_initialized_writable_input_and_has_no_route_standalone() {
    assert_eq!(febpf::helpers::helper_id("fib_lookup"), Some(69));
    let initialized = "
        r6 = r1
        r2 = r10
        r2 += -64
        r0 = 0
        *(u64 *)(r10 - 64) = r0
        *(u64 *)(r10 - 56) = r0
        *(u64 *)(r10 - 48) = r0
        *(u64 *)(r10 - 40) = r0
        *(u64 *)(r10 - 32) = r0
        *(u64 *)(r10 - 24) = r0
        *(u64 *)(r10 - 16) = r0
        *(u64 *)(r10 - 8) = r0
        r1 = r6
        r3 = 64
        r4 = 0
        call fib_lookup
        exit";
    let mut vm = Vm::new(program(initialized)).unwrap();
    vm.verify(xdp_config()).unwrap();
    let mut packet = [0u8; 1];
    assert_eq!(vm.run_xdp(&mut packet).unwrap(), 4);
    #[cfg(feature = "jit")]
    assert_eq!(vm.run_xdp_jit(&mut packet).unwrap(), 4);

    let uninitialized = initialized.replace("*(u64 *)(r10 - 64) = r0\n", "");
    let mut vm = Vm::new(program(&uninitialized)).unwrap();
    let error = match vm.verify(xdp_config()) {
        Ok(_) => panic!("uninitialized read-write buffer verified"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("uninitialized stack"), "{error}");
}

#[test]
fn xdp_byte_helpers_copy_owned_packet_and_mark_load_destination_initialized() {
    assert_eq!(febpf::helpers::helper_id("xdp_load_bytes"), Some(189));
    assert_eq!(febpf::helpers::helper_id("xdp_store_bytes"), Some(190));
    let mut vm = Vm::new(program(
        "r6 = r1\n\
         r1 = r6\n\
         r2 = 1\n\
         r3 = r10\n\
         r3 += -4\n\
         r4 = 4\n\
         call xdp_load_bytes\n\
         if r0 != 0 goto fail\n\
         r1 = r6\n\
         r2 = 0\n\
         r3 = r10\n\
         r3 += -4\n\
         r4 = 4\n\
         call xdp_store_bytes\n\
         if r0 != 0 goto fail\n\
         r0 = *(u32 *)(r10 - 4)\n\
         exit\n\
         fail:\n\
         exit",
    ))
    .unwrap();
    vm.verify(xdp_config()).unwrap();

    let original = [1, 2, 3, 4, 5];
    let mut packet = original;
    assert_eq!(vm.run_xdp(&mut packet).unwrap(), 0x0504_0302);
    assert_eq!(packet, [2, 3, 4, 5, 5]);
    #[cfg(feature = "jit")]
    {
        packet = original;
        assert_eq!(vm.run_xdp_jit(&mut packet).unwrap(), 0x0504_0302);
        assert_eq!(packet, [2, 3, 4, 5, 5]);
    }
}

#[test]
fn xdp_byte_helpers_fail_atomically_and_require_xdp_context() {
    let mut load = Vm::new(program(
        "*(u32 *)(r10 - 4) = 0x12345678\n\
         r6 = r1\n\
         r2 = 3\n\
         r3 = r10\n\
         r3 += -4\n\
         r4 = 2\n\
         call xdp_load_bytes\n\
         if r0 != -22 goto fail\n\
         r0 = *(u32 *)(r10 - 4)\n\
         exit\n\
         fail:\n\
         r0 = 0\n\
         exit",
    ))
    .unwrap();
    load.verify(xdp_config()).unwrap();
    let mut packet = [1, 2, 3, 4];
    assert_eq!(load.run_xdp(&mut packet).unwrap(), 0x1234_5678);

    let mut store = Vm::new(program(
        "*(u16 *)(r10 - 2) = 0xaaaa\n\
         r2 = 3\n\
         r3 = r10\n\
         r3 += -2\n\
         r4 = 2\n\
         call xdp_store_bytes\n\
         exit",
    ))
    .unwrap();
    store.verify(xdp_config()).unwrap();
    assert_eq!(store.run_xdp(&mut packet).unwrap(), (-22i64) as u64);
    assert_eq!(packet, [1, 2, 3, 4]);

    let mut too_large = Vm::new(program(
        "r2 = 65536\nr3 = r10\nr4 = 0\ncall xdp_load_bytes\nexit",
    ))
    .unwrap();
    too_large.verify(xdp_config()).unwrap();
    assert_eq!(too_large.run_xdp(&mut packet).unwrap(), (-14i64) as u64);

    let mut generic = Vm::new(program(
        "r2 = 0\nr3 = r10\nr4 = 0\ncall xdp_load_bytes\nexit",
    ))
    .unwrap();
    let error = generic
        .verify(Config::default())
        .err()
        .expect("XDP helper under a generic context must reject")
        .to_string();
    assert!(error.contains("expected xdp_md context pointer"), "{error}");

    let mut adjusted = Vm::new(program(
        "r1 += 4\nr2 = 0\nr3 = r10\nr4 = 0\ncall xdp_load_bytes\nexit",
    ))
    .unwrap();
    let error = adjusted
        .verify(xdp_config())
        .err()
        .expect("modified XDP context must reject")
        .to_string();
    assert!(error.contains("expected xdp_md context pointer"), "{error}");

    let mut uninitialized_store = Vm::new(program(
        "r2 = 0\nr3 = r10\nr3 += -1\nr4 = 1\ncall xdp_store_bytes\nexit",
    ))
    .unwrap();
    let error = uninitialized_store
        .verify(xdp_config())
        .err()
        .expect("XDP store source must be initialized")
        .to_string();
    assert!(error.contains("helper reads uninitialized stack byte"), "{error}");
}

#[test]
fn xdp_store_bytes_preserves_direct_packet_range_proofs() {
    let mut vm = Vm::new(program(
        "r6 = r1\n\
         r7 = *(u32 *)(r1 + 0)\n\
         r8 = *(u32 *)(r1 + 4)\n\
         r2 = r7\n\
         r2 += 1\n\
         if r2 > r8 goto short\n\
         *(u8 *)(r10 - 1) = 0xaa\n\
         r1 = r6\n\
         r2 = 0\n\
         r3 = r10\n\
         r3 += -1\n\
         r4 = 1\n\
         call xdp_store_bytes\n\
         if r0 != 0 goto short\n\
         r0 = *(u8 *)(r7 + 0)\n\
         exit\n\
         short:\n\
         r0 = 0\n\
         exit",
    ))
    .unwrap();
    vm.verify(xdp_config()).unwrap();
    let mut packet = [1];
    assert_eq!(vm.run_xdp(&mut packet).unwrap(), 0xaa);
    assert_eq!(packet, [0xaa]);
}

// -------------------------------------------------------- embedding adapters

#[test]
fn explicit_no_data_adapter_runs_with_empty_context() {
    let mut vm = Vm::new(program("r0 = 42\n exit")).unwrap();
    vm.verify(Config::default()).unwrap();
    assert_eq!(vm.run_no_data().unwrap(), 42);
}

#[test]
fn raw_buffer_adapter_uses_bounded_virtual_context_memory() {
    let mut vm = Vm::new(program(
        "r0 = *(u8 *)(r1 + 1)\n *(u8 *)(r1 + 2) = 0x7f\n exit",
    ))
    .unwrap();
    vm.verify(Config {
        ctx_size: 3,
        ..Default::default()
    })
    .unwrap();

    let mut input = [10, 42, 0];
    assert_eq!(vm.run_raw(&mut input).unwrap(), 42);
    assert_eq!(input, [10, 42, 0x7f]);
}

#[test]
fn skb_load_bytes_uses_explicit_owned_packet_adapter() {
    assert_eq!(febpf::helpers::helper_id("skb_load_bytes"), Some(26));
    let mut vm = Vm::new(program(
        "*(u32 *)(r10 - 4) = 0\n\
         r6 = r1\n\
         r2 = *(u32 *)(r6 + 0)\n\
         if r2 != 4 goto fail\n\
         r1 = r6\n\
         r2 = 1\n\
         r3 = r10\n\
         r3 += -4\n\
         r4 = 3\n\
         call skb_load_bytes\n\
         if r0 != 0 goto fail\n\
         r0 = *(u32 *)(r10 - 4)\n\
         exit\n\
         fail:\n\
         r0 = -1\n\
         exit",
    ))
    .unwrap();
    vm.verify(Config {
        ctx_size: 192,
        ctx_writable: false,
        skb: true,
        ..Default::default()
    })
    .unwrap();

    let mut packet = [0xaa, 0xbb, 0xcc, 0xdd];
    assert_eq!(vm.run_skb(&mut packet).unwrap(), 0x00dd_ccbb);
    assert_eq!(packet, [0xaa, 0xbb, 0xcc, 0xdd]);
    #[cfg(feature = "jit")]
    assert_eq!(vm.run_skb_jit(&mut packet).unwrap(), 0x00dd_ccbb);

    let mut ordinary = Vm::new(program(
        "r2 = 0\nr3 = r10\nr4 = 0\ncall skb_load_bytes\nexit",
    ))
    .unwrap();
    let error = ordinary
        .verify(Config::default())
        .err()
        .expect("skb helper without skb mode must reject")
        .to_string();
    assert!(error.contains("expected __sk_buff context pointer"), "{error}");
}

#[test]
fn skb_load_bytes_reports_out_of_bounds_without_partial_write() {
    let mut vm = Vm::new(program(
        "*(u32 *)(r10 - 4) = 0x12345678\n\
         r2 = 3\n\
         r3 = r10\n\
         r3 += -4\n\
         r4 = 2\n\
         call skb_load_bytes\n\
         r1 = *(u32 *)(r10 - 4)\n\
         if r1 != 0x12345678 goto changed\n\
         exit\n\
         changed:\n\
         r0 = 1\n\
         exit",
    ))
    .unwrap();
    vm.verify(Config {
        ctx_size: 192,
        ctx_writable: false,
        skb: true,
        ..Default::default()
    })
    .unwrap();
    let mut packet = [1, 2, 3, 4];
    assert_eq!(vm.run_skb(&mut packet).unwrap(), (-14i64) as u64);
}

#[test]
fn skb_protocol_and_direct_packet_fields_match_ethernet_input() {
    let source = "
        r2 = *(u32 *)(r1 + 16)
        if w2 != 8 goto miss
        r2 = *(u32 *)(r1 + 76)
        r3 = *(u32 *)(r1 + 80)
        r4 = r2
        r4 += 14
        if r4 > r3 goto miss
        r0 = *(u8 *)(r2 + 0)
        exit
      miss:
        r0 = 0
        exit";
    let config = Config {
        ctx_size: 192,
        ctx_writable: false,
        skb: true,
        ..Default::default()
    };
    let packet = [
        0xaa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00,
    ];
    let mut vm = Vm::new(program(source)).unwrap();
    vm.verify(config.clone()).unwrap();
    let mut frame = packet;
    assert_eq!(vm.run_skb(&mut frame).unwrap(), 0xaa);
    let mut non_ipv4 = packet;
    non_ipv4[12..14].copy_from_slice(&[0x86, 0xdd]);
    assert_eq!(vm.run_skb(&mut non_ipv4).unwrap(), 0);
    let mut short = [0xaau8; 13];
    assert_eq!(vm.run_skb(&mut short).unwrap(), 0);
    #[cfg(feature = "jit")]
    {
        let mut vm = Vm::new(program(source)).unwrap();
        vm.verify(config).unwrap();
        let mut frame = packet;
        assert_eq!(vm.run_skb_jit(&mut frame).unwrap(), 0xaa);
    }
}

#[test]
fn skb_pull_data_invalidates_old_packet_pointers_and_allows_reload() {
    assert_eq!(febpf::helpers::helper_id("skb_pull_data"), Some(39));
    let stale = "r6 = r1
        r7 = *(u32 *)(r1 + 76)
        r8 = *(u32 *)(r1 + 80)
        r2 = r7
        r2 += 1
        if r2 > r8 goto short
        r1 = r6
        r2 = 0
        call skb_pull_data
        r0 = *(u8 *)(r7 + 0)
        exit
      short:
        r0 = 0
        exit";
    let mut stale_vm = Vm::new(program(stale)).unwrap();
    let error = stale_vm
        .verify(Config {
            ctx_size: 192,
            ctx_writable: false,
            skb: true,
            ..Default::default()
        })
        .err()
        .expect("old packet pointer must be invalidated")
        .to_string();
    assert!(error.contains("loads need a pointer"), "{error}");

    let mut vm = Vm::new(program(
        "r6 = r1\n\
         r2 = 0\n\
         call skb_pull_data\n\
         if r0 != 0 goto short\n\
         r7 = *(u32 *)(r6 + 76)\n\
         r8 = *(u32 *)(r6 + 80)\n\
         r2 = r7\n\
         r2 += 1\n\
         if r2 > r8 goto short\n\
         r0 = *(u8 *)(r7 + 0)\n\
         exit\n\
         short:\n\
         r0 = 0\n\
         exit",
    ))
    .unwrap();
    vm.verify(Config {
        ctx_size: 192,
        ctx_writable: false,
        skb: true,
        ..Default::default()
    })
    .unwrap();
    let mut packet = [0xab];
    assert_eq!(vm.run_skb(&mut packet).unwrap(), 0xab);
    #[cfg(feature = "jit")]
    assert_eq!(vm.run_skb_jit(&mut packet).unwrap(), 0xab);
}

#[test]
fn skb_pull_data_reports_unavailable_length_without_mutation() {
    let mut vm = Vm::new(program("r2 = 5\ncall skb_pull_data\nexit")).unwrap();
    vm.verify(Config {
        ctx_size: 192,
        ctx_writable: false,
        skb: true,
        ..Default::default()
    })
    .unwrap();
    let mut packet = [1, 2, 3, 4];
    assert_eq!(vm.run_skb(&mut packet).unwrap(), (-12i64) as u64);
    assert_eq!(packet, [1, 2, 3, 4]);
}

#[test]
fn xdp_adjust_tail_invalidates_packet_aliases_and_is_honestly_unsupported() {
    assert_eq!(febpf::helpers::helper_id("xdp_adjust_tail"), Some(65));
    let stale = "r6 = r1
        r7 = *(u32 *)(r1 + 0)
        r8 = *(u32 *)(r1 + 4)
        r2 = r7
        r2 += 1
        if r2 > r8 goto short
        r1 = r6
        r2 = 0
        call xdp_adjust_tail
        r0 = *(u8 *)(r7 + 0)
        exit
      short:
        r0 = 0
        exit";
    let mut stale_vm = Vm::new(program(stale)).unwrap();
    let error = stale_vm
        .verify(xdp_config())
        .err()
        .expect("old packet pointer must be invalidated")
        .to_string();
    assert!(error.contains("loads need a pointer"), "{error}");

    let mut vm = Vm::new(program("r2 = 0\ncall xdp_adjust_tail\nexit")).unwrap();
    vm.verify(xdp_config()).unwrap();
    let mut packet = [1, 2, 3, 4];
    assert_eq!(vm.run_xdp(&mut packet).unwrap(), (-95i64) as u64);
    assert_eq!(packet, [1, 2, 3, 4]);
}

#[test]
fn replace_program_is_transactional_on_construction_failure() {
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

    let mut invalid = program(".map doomed array 4 8 1\n r0 = map[doomed][0]\n exit");
    invalid.maps.clear();
    assert!(vm.replace_program(invalid).is_err());

    // Both the old executable and its live map state survived the failure.
    assert_eq!(vm.run_no_data().unwrap(), 2);
}

#[test]
fn replace_program_preserves_embedding_configuration_and_resets_program_state() {
    use febpf::helpers::{id, ArgKind, HelperSig, RetKind};

    let mut vm = Vm::new(program(
        ".map state array 4 8 1\n\
         r1 = map[state][0] + 0\n\
         *(u64 *)(r1 + 0) = 99\n\
         r0 = 0\n\
         exit",
    ))
    .unwrap();
    vm.user_helpers.register(
        id::FIRST_USER,
        HelperSig {
            name: "answer",
            args: [ArgKind::None; 5],
            ret: RetKind::Scalar,
        },
        Box::new(
            |_: [u64; 5], _: &mut dyn febpf::helpers::MemBus| -> Result<u64, String> { Ok(42) },
        ),
    );
    vm.echo_printk = true;
    vm.insn_limit = 123;
    vm.set_prandom_seed(456);
    vm.enable_profiling();
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

    assert!(vm.echo_printk);
    assert_eq!(vm.insn_limit, 123);
    assert_eq!(vm.prandom_seed(), 456);
    let profile = vm.profile.as_ref().expect("profiling stays enabled");
    assert_eq!(profile.len(), vm.insns().len());
    assert!(profile.iter().all(|&count| count == 0));
    vm.verify(Config::default()).unwrap();
    // The helper survived, while the identically named replacement map is new.
    assert_eq!(vm.run_no_data().unwrap(), 42);
}

// ------------------------------------------------------------------ ALU

#[test]
fn alu_basics() {
    assert_eq!(run_src("r0 = 2\n r0 += 3\n exit"), 5);
    assert_eq!(run_src("r0 = 10\n r0 -= 3\n exit"), 7);
    assert_eq!(run_src("r0 = 6\n r0 *= 7\n exit"), 42);
    assert_eq!(run_src("r0 = 100\n r0 /= 7\n exit"), 14);
    assert_eq!(run_src("r0 = 100\n r0 %= 7\n exit"), 2);
    assert_eq!(run_src("r0 = 0xf0\n r0 |= 0x0f\n exit"), 0xff);
    assert_eq!(run_src("r0 = 0xff\n r0 &= 0x0f\n exit"), 0x0f);
    assert_eq!(run_src("r0 = 0xff\n r0 ^= 0xf0\n exit"), 0x0f);
    assert_eq!(run_src("r0 = 1\n r0 <<= 40\n r0 >>= 8\n exit"), 1u64 << 32);
    assert_eq!(run_src("r0 = 5\n r0 = -r0\n exit"), (-5i64) as u64);
}

#[test]
fn div_mod_by_zero_defined() {
    assert_eq!(run_src("r0 = 42\n r1 = 0\n r0 /= r1\n exit"), 0);
    assert_eq!(run_src("r0 = 42\n r1 = 0\n r0 %= r1\n exit"), 42);
    assert_eq!(run_src("r0 = -42\n r1 = 0\n r0 s/= r1\n exit"), 0);
}

#[test]
fn signed_div_mod() {
    assert_eq!(run_src("r0 = -100\n r1 = 7\n r0 s/= r1\n exit"), (-14i64) as u64);
    assert_eq!(run_src("r0 = -100\n r1 = 7\n r0 s%= r1\n exit"), (-2i64) as u64);
    // unsigned div of the same bit pattern is huge
    assert_eq!(
        run_src("r0 = -100\n r1 = 7\n r0 /= r1\n exit"),
        (u64::MAX - 99) / 7
    );
}

#[test]
fn alu32_truncates_and_zero_extends() {
    assert_eq!(run_src("r0 = -1\n w0 += 1\n exit"), 0);
    assert_eq!(
        run_src("r0 = 0x1_00000001 ll\n w0 += 0\n exit"),
        1,
        "32-bit op must zero the upper half"
    );
    assert_eq!(run_src("w0 = -1\n exit"), 0xffff_ffff);
}

#[test]
fn movsx_and_arsh() {
    assert_eq!(run_src("r1 = 0xff\n r0 = (s8)r1\n exit"), u64::MAX);
    assert_eq!(run_src("r1 = 0x7f\n r0 = (s8)r1\n exit"), 0x7f);
    assert_eq!(run_src("r1 = 0xffffffff ll\n r0 = (s32)r1\n exit"), u64::MAX);
    assert_eq!(run_src("r0 = -8\n r0 s>>= 1\n exit"), (-4i64) as u64);
    assert_eq!(run_src("w1 = 0x8000\n w0 = (s16)w1\n exit"), 0xffff_8000);
}

#[test]
fn byte_swaps() {
    assert_eq!(
        run_src("r0 = 0x1122334455667788 ll\n r0 = bswap64 r0\n exit"),
        0x8877665544332211
    );
    assert_eq!(run_src("r0 = 0x1234\n r0 = be16 r0\n exit"), 0x3412);
    assert_eq!(
        run_src("r0 = 0x1122334455667788 ll\n r0 = le32 r0\n exit"),
        0x55667788,
        "to-LE on LE host truncates"
    );
}

#[test]
fn lddw_imm64() {
    assert_eq!(
        run_src("r0 = 0xdeadbeefcafebabe ll\n exit"),
        0xdeadbeefcafebabe
    );
}

// ------------------------------------------------------------------ jumps

#[test]
fn conditional_jumps() {
    let src = "
        r0 = 0
        r1 = 5
        if r1 > 4 goto big
        r0 = 1
        exit
    big:
        r0 = 2
        exit";
    assert_eq!(run_src(src), 2);
}

#[test]
fn signed_vs_unsigned_compare() {
    // -1 unsigned-greater-than 1, but not signed-greater-than
    let src = "
        r1 = -1
        r0 = 0
        if r1 > 1 goto ugt
        goto out
    ugt:
        r0 += 1
        if r1 s> 1 goto sgt
        goto out
    sgt:
        r0 += 10
    out:
        exit";
    assert_eq!(run_src(src), 1);
}

#[test]
fn jmp32_compares_low_bits() {
    let src = "
        r1 = 0x1_00000000 ll  ; low 32 bits are zero
        r0 = 1
        if w1 == 0 goto yes
        r0 = 2
    yes:
        exit";
    assert_eq!(run_src(src), 1);
}

#[test]
fn bounded_loop_verifies_and_runs() {
    let src = "
        r0 = 0
        r2 = 100
    loop:
        r0 += r2
        r2 -= 1
        if r2 != 0 goto loop
        exit";
    assert_eq!(run_src(src), 5050);
}

#[test]
fn branch_free_tail_pruning_keeps_live_stack_initialization() {
    let error = verify_err_ctx(
        "r2 = *(u64 *)(r1 + 0)\n\
         if r2 == 0 goto init\n\
         goto join\n\
         init:\n\
         *(u64 *)(r10 - 8) = 1\n\
         join:\n\
         r0 = *(u64 *)(r10 - 8)\n\
         exit",
        8,
    );
    assert!(error.contains("uninitialized stack"), "{error}");
}

#[test]
fn branch_free_tail_pruning_ignores_only_overwritten_registers() {
    let mut vm = Vm::new(program(
        "r2 = *(u64 *)(r1 + 0)\n\
         if r2 == 0 goto pointer\n\
         r3 = 7\n\
         goto join\n\
         pointer:\n\
         r3 = r10\n\
         join:\n\
         r3 = 0\n\
         r0 = r3\n\
         exit",
    ))
    .unwrap();
    let ok = vm.verify(Config { ctx_size: 8, ..Default::default() }).unwrap();
    assert!(ok.stats.states_pruned > 0, "tail projection should prune a dead r3 variant");
}

#[test]
fn cfg_liveness_prunes_dead_pointer_across_branching_continuation() {
    let mut vm = Vm::new(program(
        "r2 = *(u64 *)(r1 + 0)
         if r2 == 0 goto pointer
         r3 = 7
         goto join
        pointer:
         r3 = r10
        join:
         r3 = 0
         if r2 == 1 goto one
         r0 = 0
         exit
        one:
         r0 = 1
         exit",
    ))
    .unwrap();
    let ok = vm
        .verify(Config {
            ctx_size: 8,
            ..Default::default()
        })
        .unwrap();
    assert!(
        ok.stats.states_pruned > 0,
        "whole-CFG liveness should prune the dead r3 variant"
    );
}

#[test]
fn cfg_liveness_keeps_pointer_used_after_branching_join() {
    let error = verify_err_ctx(
        "r2 = *(u64 *)(r1 + 0)
         *(u64 *)(r10 - 8) = 1
         if r2 == 0 goto pointer
         r3 = 7
         goto join
        pointer:
         r3 = r10
         r3 += -8
        join:
         if r2 == 42 goto out
         r0 = *(u64 *)(r3)
         exit
        out:
         r0 = 0
         exit",
        8,
    );
    assert!(
        error.contains("loads need a pointer"),
        "live pointer variant was pruned: {error}"
    );
}

#[test]
fn cfg_liveness_keeps_stack_initialization_across_branching_join() {
    let error = verify_err_ctx(
        "r2 = *(u64 *)(r1 + 0)
         if r2 == 0 goto init
         goto join
        init:
         *(u64 *)(r10 - 8) = 1
        join:
         if r2 == 42 goto out
         r0 = *(u64 *)(r10 - 8)
         exit
        out:
         r0 = 0
         exit",
        8,
    );
    assert!(
        error.contains("uninitialized stack"),
        "live stack variant was pruned: {error}"
    );
}

// ------------------------------------------------------------------ memory

#[test]
fn stack_load_store() {
    let src = "
        r1 = 0x1122334455667788 ll
        *(u64 *)(r10 - 8) = r1
        r0 = *(u32 *)(r10 - 8)
        exit";
    assert_eq!(run_src(src), 0x55667788);
}

#[test]
fn store_immediates_and_bytes() {
    let src = "
        *(u8 *)(r10 - 1) = 0xab
        *(u16 *)(r10 - 4) = 0x1234
        r0 = *(u8 *)(r10 - 1)
        r1 = *(u16 *)(r10 - 4)
        r0 += r1
        exit";
    assert_eq!(run_src(src), 0xab + 0x1234);
}

#[test]
fn sign_extending_load() {
    let src = "
        r1 = -1
        *(u8 *)(r10 - 8) = r1
        r0 = *(s8 *)(r10 - 8)
        exit";
    assert_eq!(run_src(src), u64::MAX);
}

#[test]
fn ctx_access() {
    let mut ctx = [0u8; 16];
    ctx[0] = 0x11;
    ctx[8] = 0x22;
    let src = "
        r3 = *(u8 *)(r1)
        r4 = *(u8 *)(r1 + 8)
        r0 = r3
        r0 += r4
        *(u8 *)(r1 + 15) = 0x7f
        exit";
    assert_eq!(run_ctx(src, &mut ctx), 0x33);
    assert_eq!(ctx[15], 0x7f);
}

#[test]
fn xdp_packet_access_after_data_end_check() {
    let src = "
        r2 = *(u32 *)(r1 + 0)
        r3 = *(u32 *)(r1 + 4)
        r4 = r2
        r4 += 14
        if r4 > r3 goto short
        r0 = *(u16 *)(r2 + 12)
        exit
    short:
        r0 = 0
        exit";
    let mut vm = Vm::new(program(src)).unwrap();
    vm.verify(xdp_config()).expect("bounded packet load verifies");

    let mut packet = (0u8..20).collect::<Vec<_>>();
    assert_eq!(vm.run_xdp(&mut packet).unwrap(), 0x0d0c);
    let mut short = vec![0u8; 13];
    assert_eq!(vm.run_xdp(&mut short).unwrap(), 0);
}

#[test]
fn xdp_scalar_metadata_fields_are_exact_and_zero_backed() {
    let src = "
        r0 = *(u32 *)(r1 + 12)
        r2 = *(u32 *)(r1 + 16)
        r0 |= r2
        r2 = *(u32 *)(r1 + 20)
        r0 |= r2
        exit";
    let mut vm = Vm::new(program(src)).unwrap();
    vm.verify(xdp_config()).expect("scalar xdp_md fields verify");
    let mut packet = [1u8, 2, 3];
    assert_eq!(vm.run_xdp(&mut packet).unwrap(), 0);
    #[cfg(feature = "jit")]
    assert_eq!(vm.run_xdp_jit(&mut packet).unwrap(), 0);
}

#[test]
fn xdp_context_rejects_unmodelled_metadata_and_non_exact_accesses() {
    for src in [
        "r0 = *(u32 *)(r1 + 8)\nexit",  // data_meta is a pointer, not a scalar
        "r0 = *(u16 *)(r1 + 12)\nexit", // partial scalar field
        "r0 = *(u64 *)(r1 + 12)\nexit", // overlapping scalar fields
        "*(u32 *)(r1 + 12) = 1\nr0 = 0\nexit", // read-only context
        "r0 = *(u32 *)(r1 + 24)\nexit", // outside xdp_md
    ] {
        let mut vm = Vm::new(program(src)).unwrap();
        let error = match vm.verify(xdp_config()) {
            Ok(_) => panic!("invalid XDP context access verified"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("invalid XDP context access")
                || error.contains("XDP context is read-only"),
            "{error}"
        );
    }
}

#[test]
fn xdp_packet_access_requires_sufficient_proof() {
    let unchecked = "
        r2 = *(u32 *)(r1 + 0)
        r0 = *(u8 *)(r2 + 0)
        exit";
    let mut vm = Vm::new(program(unchecked)).unwrap();
    let e = match vm.verify(xdp_config()) {
        Ok(_) => panic!("unchecked packet access verified"),
        Err(e) => e.to_string(),
    };
    assert!(e.contains("only 0 bytes proven"), "{e}");

    let underchecked = "
        r0 = 0
        r2 = *(u32 *)(r1 + 0)
        r3 = *(u32 *)(r1 + 4)
        r4 = r2
        r4 += 8
        if r4 > r3 goto out
        r0 = *(u8 *)(r2 + 8)
    out:
        exit";
    let mut vm = Vm::new(program(underchecked)).unwrap();
    let e = match vm.verify(xdp_config()) {
        Ok(_) => panic!("under-checked packet access verified"),
        Err(e) => e.to_string(),
    };
    assert!(e.contains("only 8 bytes proven"), "{e}");
}

#[test]
fn xdp_packet_writes_are_bounded_and_visible() {
    let src = "
        r2 = *(u32 *)(r1 + 0)
        r3 = *(u32 *)(r1 + 4)
        r4 = r2
        r4 += 1
        if r4 > r3 goto out
        *(u8 *)(r2 + 0) = 0xaa
    out:
        r0 = 2
        exit";
    let mut vm = Vm::new(program(src)).unwrap();
    vm.verify(xdp_config()).unwrap();
    let mut packet = vec![1, 2, 3];
    assert_eq!(vm.run_xdp(&mut packet).unwrap(), 2);
    assert_eq!(packet, [0xaa, 2, 3]);
}

#[test]
fn xdp_data_end_proof_propagates_to_spilled_aliases() {
    let src = "
        r2 = *(u32 *)(r1 + 0)
        r3 = *(u32 *)(r1 + 4)
        *(u64 *)(r10 - 8) = r2
        r2 = 0
        r4 = *(u64 *)(r10 - 8)
        r4 += 4
        if r3 >= r4 goto safe
        r0 = 0
        exit
    safe:
        r2 = *(u64 *)(r10 - 8)
        r0 = *(u32 *)(r2 + 0)
        exit";
    let mut vm = Vm::new(program(src)).unwrap();
    vm.verify(xdp_config()).expect("range reaches spilled alias");
    let mut packet = vec![0x78, 0x56, 0x34, 0x12];
    assert_eq!(vm.run_xdp(&mut packet).unwrap(), 0x1234_5678);
}

#[test]
fn atomics() {
    let src = "
        r1 = 10
        *(u64 *)(r10 - 8) = r1
        r2 = 5
        lock *(u64 *)(r10 - 8) += r2
        r3 = 3
        r3 = atomic_fetch_add((u64 *)(r10 - 8), r3)   ; r3 = 15, mem = 18
        r0 = *(u64 *)(r10 - 8)
        r0 += r3
        exit";
    assert_eq!(run_src(src), 33);
}

#[test]
fn atomic_cmpxchg() {
    let src = "
        r1 = 7
        *(u64 *)(r10 - 8) = r1
        r0 = 7           ; expected
        r2 = 99          ; new value
        r0 = cmpxchg((u64 *)(r10 - 8), r0, r2)
        r3 = *(u64 *)(r10 - 8)
        r0 += r3         ; 7 (old) + 99 (stored)
        exit";
    assert_eq!(run_src(src), 106);
}

#[test]
fn xchg() {
    let src = "
        r1 = 111
        *(u64 *)(r10 - 16) = r1
        r2 = 222
        r2 = xchg((u64 *)(r10 - 16), r2)
        r0 = *(u64 *)(r10 - 16)
        r0 += r2      ; 222 + 111
        exit";
    assert_eq!(run_src(src), 333);
}

// ------------------------------------------------------------------ maps

#[test]
fn array_map_roundtrip() {
    let src = "
        .map counts array 4 8 4
        ; key 2 at fp-4
        w1 = 2
        *(u32 *)(r10 - 4) = r1
        ; value 999 at fp-16
        r1 = 999
        *(u64 *)(r10 - 16) = r1
        r1 = map[counts]
        r2 = r10
        r2 += -4
        r3 = r10
        r3 += -16
        r4 = 0
        call map_update_elem
        ; look it back up
        r1 = map[counts]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 == 0 goto miss
        r0 = *(u64 *)(r0)
        exit
    miss:
        r0 = -1
        exit";
    assert_eq!(run_src(src), 999);
}

#[test]
fn hash_map_counter_loop() {
    // count 1000 increments of key 7 in a hash map
    let src = "
        .map h hash 4 8 16
        w1 = 7
        *(u32 *)(r10 - 4) = r1
        r6 = 1000
    loop:
        r1 = map[h]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 != 0 goto found
        ; insert initial value 0
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
        ; read final count
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
    assert_eq!(run_src(src), 999); // first iteration inserts 0, then 999 increments
}

// --------------------------------------------------------------- ringbuf

/// Verify + run a program, returning the whole Vm so the caller can inspect
/// captured ringbuf records.
fn build_run(src: &str) -> Vm {
    let mut vm = Vm::new(program(src)).unwrap();
    vm.verify(Config::default()).expect("verification failed");
    vm.run(&mut []).expect("run failed");
    vm
}

#[test]
fn ringbuf_reserve_submit_captures_record() {
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
    let vm = build_run(src);
    let recs = vm.ringbuf_records("rb").expect("ringbuf map");
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0], 0x1122334455667788u64.to_le_bytes());
}

#[test]
fn ringbuf_reserve_null_check_path() {
    // capacity 8 but request 16 -> reserve returns NULL at runtime; the
    // program takes the null branch and emits nothing.
    let src = "
        .map rb ringbuf 0 0 8
        r1 = map[rb]
        r2 = 16
        r3 = 0
        call ringbuf_reserve
        if r0 == 0 goto null
        r6 = r0
        r1 = r6
        r2 = 0
        call ringbuf_submit
        r0 = 1
        exit
    null:
        r0 = 200
        exit";
    let mut vm = Vm::new(program(src)).unwrap();
    vm.verify(Config::default()).expect("verification failed");
    let r = vm.run(&mut []).expect("run failed");
    assert_eq!(r, 200);
    assert_eq!(vm.ringbuf_records("rb").unwrap().len(), 0);
}

#[test]
fn ringbuf_use_after_submit_rejected() {
    let src = "
        .map rb ringbuf 0 0 64
        r1 = map[rb]
        r2 = 8
        r3 = 0
        call ringbuf_reserve
        if r0 == 0 goto out
        r6 = r0
        r1 = r6
        r2 = 0
        call ringbuf_submit
        r1 = *(u64 *)(r6 + 0)
        r0 = 0
        exit
    out:
        r0 = 1
        exit";
    let e = verify_err(src);
    assert!(
        e.contains("submitted/discarded"),
        "unexpected error: {e}"
    );
}

#[test]
fn ringbuf_reserve_without_nullcheck_rejected() {
    let src = "
        .map rb ringbuf 0 0 64
        r1 = map[rb]
        r2 = 8
        r3 = 0
        call ringbuf_reserve
        r1 = *(u64 *)(r0 + 0)
        r0 = 0
        exit";
    let e = verify_err(src);
    assert!(e.contains("may be NULL"), "unexpected error: {e}");
}

#[test]
fn ringbuf_output_captures_from_stack() {
    let src = "
        .map rb ringbuf 0 0 4096
        r1 = 0x11223344
        *(u32 *)(r10 - 8) = r1
        r1 = map[rb]
        r2 = r10
        r2 += -8
        r3 = 4
        r4 = 0
        call ringbuf_output
        r0 = 0
        exit";
    let vm = build_run(src);
    let recs = vm.ringbuf_records("rb").expect("ringbuf map");
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0], 0x11223344u32.to_le_bytes());
}

// ------------------------------------------------------- perf_event_array

#[test]
fn perf_event_output_emits_record() {
    // Build an 8-byte event on the stack and stream it to userspace via
    // bpf_perf_event_output(ctx, map, BPF_F_CURRENT_CPU, data, 8).
    let src = "
        .map ev perf_event_array 4 4 4
        r1 = 0x1122334455667788 ll
        *(u64 *)(r10 - 8) = r1
        r1 = 0
        r2 = map[ev]
        r3 = 0xffffffff ll
        r4 = r10
        r4 += -8
        r5 = 8
        call perf_event_output
        r0 = 0
        exit";
    let vm = build_run(src);
    let recs = vm.perf_records("ev").expect("perf map");
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0], 0x1122334455667788u64.to_le_bytes());
}

#[test]
fn perf_event_output_wrong_map_kind_rejected() {
    // A plain array is not a PERF_EVENT_ARRAY; the verifier must reject it.
    let src = "
        .map ev array 4 4 4
        r1 = 0
        *(u64 *)(r10 - 8) = r1
        r1 = 0
        r2 = map[ev]
        r3 = 0
        r4 = r10
        r4 += -8
        r5 = 8
        call perf_event_output
        r0 = 0
        exit";
    let e = verify_err(src);
    assert!(e.contains("requires a perf_event_array"), "unexpected error: {e}");
}

// -------------------------------------------------------------- per-CPU

#[test]
fn percpu_array_roundtrip_and_independent_slots() {
    let src = "
        .map pa percpu_array 4 8 4
        w1 = 1
        *(u32 *)(r10 - 4) = r1
        r1 = 777
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
        r0 = -1
        exit";
    let mut vm = Vm::new(program(src)).unwrap();
    vm.verify(Config::default()).expect("verification failed");
    let r = vm.run(&mut []).expect("run failed");
    // The in-program view (CPU 0) round-trips.
    assert_eq!(r, 777);
    // CPU 0 has 777; the other CPUs' slots stay independent (zero).
    let m = vm.maps.iter().find(|m| m.def.name == "pa").unwrap();
    let vref = m.lookup(&1u32.to_ne_bytes()).unwrap();
    assert_eq!(m.value_cpu(vref, 0), 777u64.to_le_bytes());
    for cpu in 1..febpf::maps::NR_CPUS {
        assert_eq!(m.value_cpu(vref, cpu), [0u8; 8], "cpu {cpu} must be independent");
    }
}

#[test]
fn percpu_hash_roundtrip() {
    let src = "
        .map ph percpu_hash 4 8 16
        w1 = 42
        *(u32 *)(r10 - 4) = r1
        r1 = 0xdead
        *(u64 *)(r10 - 16) = r1
        r1 = map[ph]
        r2 = r10
        r2 += -4
        r3 = r10
        r3 += -16
        r4 = 0
        call map_update_elem
        r1 = map[ph]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 == 0 goto miss
        r0 = *(u64 *)(r0)
        exit
    miss:
        r0 = -1
        exit";
    let mut vm = Vm::new(program(src)).unwrap();
    vm.verify(Config::default()).expect("verification failed");
    assert_eq!(vm.run(&mut []).expect("run failed"), 0xdead);
    let m = vm.maps.iter().find(|m| m.def.name == "ph").unwrap();
    let vref = m.lookup(&42u32.to_ne_bytes()).unwrap();
    assert_eq!(m.value_cpu(vref, 0), 0xdeadu64.to_le_bytes());
    assert_eq!(m.value_cpu(vref, 1), [0u8; 8]);
}

// ------------------------------------------------------------------ LRU

/// Insert k1,k2 (fills a capacity-2 LRU), touch k1 via a lookup, then insert
/// k3. The least-recently-used live entry (k2) must be the one evicted.
const LRU_PROG: &str = "
    .map lru lru_hash 4 8 2
    w1 = 1
    *(u32 *)(r10 - 4) = r1
    r1 = 10
    *(u64 *)(r10 - 16) = r1
    r1 = map[lru]
    r2 = r10
    r2 += -4
    r3 = r10
    r3 += -16
    r4 = 0
    call map_update_elem
    w1 = 2
    *(u32 *)(r10 - 4) = r1
    r1 = 20
    *(u64 *)(r10 - 16) = r1
    r1 = map[lru]
    r2 = r10
    r2 += -4
    r3 = r10
    r3 += -16
    r4 = 0
    call map_update_elem
    w1 = 1
    *(u32 *)(r10 - 4) = r1
    r1 = map[lru]
    r2 = r10
    r2 += -4
    call map_lookup_elem
    w1 = 3
    *(u32 *)(r10 - 4) = r1
    r1 = 30
    *(u64 *)(r10 - 16) = r1
    r1 = map[lru]
    r2 = r10
    r2 += -4
    r3 = r10
    r3 += -16
    r4 = 0
    call map_update_elem
    r0 = 0
    exit";

fn run_lru() -> Vec<(u32, u64)> {
    let mut vm = Vm::new(program(LRU_PROG)).unwrap();
    vm.verify(Config::default()).expect("verification failed");
    vm.run(&mut []).expect("run failed");
    let m = vm.maps.iter().find(|m| m.def.name == "lru").unwrap();
    let mut out: Vec<(u32, u64)> = m
        .iter_entries()
        .into_iter()
        .map(|(k, v)| {
            (
                u32::from_ne_bytes(k.try_into().unwrap()),
                u64::from_le_bytes(v.try_into().unwrap()),
            )
        })
        .collect();
    out.sort();
    out
}

#[test]
fn lru_evicts_least_recently_used_deterministically() {
    let entries = run_lru();
    // k2 was the LRU (k1 was touched after both inserts), so it is evicted;
    // k1 and k3 remain.
    assert_eq!(entries, vec![(1, 10), (3, 30)]);
    // Deterministic: a second identical run evicts exactly the same entry.
    assert_eq!(run_lru(), entries);
}

// --------------------------------------------------------- cgroup_array

/// A cgroup_array is modelled as a plain array (a lookup map). The point is
/// that it LOADS, verifies and its element is readable — the corpus blocker is
/// the map type at load time. Cgroup-membership helpers are out of scope.
#[test]
fn cgroup_array_loads_and_looks_up() {
    let src = "
        .map cg cgroup_array 4 4 8
        w1 = 0
        *(u32 *)(r10 - 4) = r1
        r1 = map[cg]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 == 0 goto miss
        r0 = *(u32 *)(r0 + 0)
        exit
    miss:
        r0 = 123
        exit";
    // Element 0 is zero-initialised, so the lookup hits and returns 0.
    assert_eq!(run_src(src), 0);
}

// ---------------------------------------------------------- XDP redirect maps

/// The redirect-map family is modelled with ordinary keyed storage for
/// userland execution. That is enough for map lookup/update and preserves the
/// verifier's typed map identity; actual device/CPU redirection is a kernel
/// attachment concern outside a standalone VM.
#[test]
fn xdp_redirect_map_families_load_and_roundtrip() {
    for (kind, value) in [("devmap", 17u32), ("cpumap", 23u32), ("xskmap", 29u32)] {
        let src = format!(
            ".map redirect {kind} 4 4 4
             w1 = 2
             *(u32 *)(r10 - 4) = r1
             r1 = {value}
             *(u32 *)(r10 - 8) = r1
             r1 = map[redirect]
             r2 = r10
             r2 += -4
             r3 = r10
             r3 += -8
             r4 = 0
             call map_update_elem
             r1 = map[redirect]
             r2 = r10
             r2 += -4
             call map_lookup_elem
             if r0 == 0 goto miss
             r0 = *(u32 *)(r0 + 0)
             exit
           miss:
             r0 = 0
             exit"
        );
        assert_eq!(run_src(&src), value as u64, "{kind} storage must round-trip");
    }

    let src = "
        .map redirect devmap_hash 4 8 4
        w1 = 2
        *(u32 *)(r10 - 4) = r1
        r1 = 0x1122334455667788 ll
        *(u64 *)(r10 - 16) = r1
        r1 = map[redirect]
        r2 = r10
        r2 += -4
        r3 = r10
        r3 += -16
        r4 = 0
        call map_update_elem
        r1 = map[redirect]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 == 0 goto miss
        r0 = *(u64 *)(r0 + 0)
        exit
      miss:
        r0 = 0
        exit";
    assert_eq!(run_src(src), 0x1122334455667788);
}

#[test]
fn redirect_map_requires_redirect_kind_and_returns_deterministic_verdict() {
    assert_eq!(febpf::helpers::helper_id("redirect_map"), Some(51));
    for kind in ["devmap", "cpumap", "devmap_hash", "xskmap"] {
        let src = format!(
            ".map targets {kind} 4 4 4
             *(u32 *)(r10 - 4) = 2
             *(u32 *)(r10 - 8) = 7
             r1 = map[targets]
             r2 = r10
             r2 += -4
             r3 = r10
             r3 += -8
             r4 = 0
             call map_update_elem
             r1 = map[targets]
             r2 = 2
             r3 = 1
             call redirect_map
             exit"
        );
        assert_eq!(run_src(&src), 4, "{kind}");
    }

    assert_eq!(
        run_src(
            ".map targets devmap 4 4 4\n\
             r1 = map[targets]\n\
             r2 = 9\n\
             r3 = 2\n\
             call redirect_map\n\
             exit"
        ),
        2
    );

    let error = verify_err(
        ".map wrong array 4 4 4\n\
         r1 = map[wrong]\n\
         r2 = 0\n\
         r3 = 0\n\
         call redirect_map\n\
         exit",
    );
    assert!(error.contains("requires a devmap"), "{error}");
}

#[test]
fn xskmap_slots_are_sparse_and_queue_bounded() {
    assert_eq!(
        run_src(
            ".map xs xskmap 4 4 4\n\
             *(u32 *)(r10 - 4) = 1\n\
             r1 = map[xs]\n\
             r2 = r10\n\
             r2 += -4\n\
             call map_lookup_elem\n\
             if r0 == 0 goto missing\n\
             r0 = 99\n\
             exit\n\
           missing:\n\
             r0 = 7\n\
             exit"
        ),
        7
    );

    let mut map = febpf::maps::Map::new(febpf::maps::MapDef {
        name: "xs".into(),
        kind: febpf::maps::MapKind::XskMap,
        key_size: 4,
        value_size: 4,
        max_entries: 4,
        readonly: false,
        init: Vec::new(),
        inner_map_idx: None,
        map_in_map_values: Vec::new(),
        spin_lock_off: None,
    })
    .unwrap();
    assert_eq!(map.update(&4u32.to_ne_bytes(), &9u32.to_ne_bytes()), Err(-7));
    assert!(map.lookup(&4u32.to_ne_bytes()).is_none());
}

#[test]
fn queue_map_pushes_fifo_and_overwrites_only_with_exist() {
    use febpf::maps::{Map, MapDef, MapKind};

    assert_eq!(febpf::helpers::helper_id("map_push_elem"), Some(87));
    let mut map = Map::new(MapDef {
        name: "events".into(),
        kind: MapKind::Queue,
        key_size: 0,
        value_size: 4,
        max_entries: 2,
        readonly: false,
        init: Vec::new(),
        inner_map_idx: None,
        map_in_map_values: Vec::new(),
        spin_lock_off: None,
    })
    .unwrap();
    map.push(&1u32.to_ne_bytes(), 0).unwrap();
    map.push(&2u32.to_ne_bytes(), 0).unwrap();
    assert_eq!(map.push(&3u32.to_ne_bytes(), 0), Err(-7));
    map.push(&3u32.to_ne_bytes(), 2).unwrap();
    assert_eq!(
        map.iter_entries()
            .into_iter()
            .map(|(_, value)| u32::from_ne_bytes(value.try_into().unwrap()))
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
}

#[test]
fn redirect_helper_uses_program_kind_verdicts() {
    assert_eq!(febpf::helpers::helper_id("redirect"), Some(23));

    let xdp = |flags: u64| {
        let mut vm = Vm::new(program(&format!(
            "r1 = 7\nr2 = {flags}\ncall redirect\nexit"
        )))
        .unwrap();
        vm.verify(xdp_config()).unwrap();
        let mut packet = [0u8; 1];
        vm.run_xdp(&mut packet).unwrap()
    };
    assert_eq!(xdp(0), 4);
    assert_eq!(xdp(1), 0);

    let skb = |flags: u64| {
        let mut vm = Vm::new(program(&format!(
            "r1 = 7\nr2 = {flags}\ncall redirect\nexit"
        )))
        .unwrap();
        vm.verify(Config {
            ctx_size: 192,
            ctx_writable: false,
            skb: true,
            ..Default::default()
        })
        .unwrap();
        let mut packet = [0u8; 1];
        vm.run_skb(&mut packet).unwrap()
    };
    assert_eq!(skb(0), 7);
    assert_eq!(skb(1), 7);
    assert_eq!(skb(2), 2);

    let mut generic = Vm::new(program("r1 = 7\nr2 = 0\ncall redirect\nexit")).unwrap();
    let error = generic
        .verify(Config::default())
        .err()
        .expect("redirect under generic context must reject")
        .to_string();
    assert!(error.contains("requires an XDP or __sk_buff"), "{error}");
}

// --------------------------------------------------------- stack_trace

/// get_stackid returns a deterministic 31-bit id and stores the captured
/// stack under it, so an immediate lookup with that id must hit.
#[test]
fn get_stackid_stores_retrievable_stack() {
    let src = "
        .map st stack_trace 4 16 8
        r1 = 0
        r2 = map[st]
        r3 = 0
        call get_stackid
        *(u32 *)(r10 - 4) = r0
        r1 = map[st]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 == 0 goto miss
        r0 = 1
        exit
    miss:
        r0 = 0
        exit";
    assert_eq!(run_src(src), 1);
}

/// Two different call sites have different stacks, hence different ids.
#[test]
fn get_stackid_distinguishes_call_sites() {
    let src = "
        .map st stack_trace 4 16 8
        r1 = 0
        r2 = map[st]
        r3 = 0
        call get_stackid
        r6 = r0
        r1 = 0
        r2 = map[st]
        r3 = 0
        call get_stackid
        if r0 == r6 goto same
        r0 = 1
        exit
    same:
        r0 = 0
        exit";
    assert_eq!(run_src(src), 1);
}

/// get_stack writes the deterministic call stack (instruction indices as LE
/// u64s) into the caller's buffer and returns the byte count. A top-level
/// program has one frame, so it writes exactly 8 bytes; the untouched tail
/// of the buffer is zeroed.
#[test]
fn get_stack_writes_stack_and_returns_bytes() {
    let src = "
        r1 = 0
        r2 = r10
        r2 += -16
        r3 = 16
        r4 = 0
        call get_stack
        if r0 != 8 goto bad
        r1 = *(u64 *)(r10 - 16)
        if r1 == 0 goto bad
        r1 = *(u64 *)(r10 - 8)
        if r1 != 0 goto bad
        r0 = 1
        exit
    bad:
        r0 = 0
        exit";
    assert_eq!(run_src(src), 1);
}

/// A buffer too small for even one frame gets zeroed and 0 bytes written
/// (the return is always a multiple of 8).
#[test]
fn get_stack_truncates_to_whole_frames() {
    let src = "
        *(u32 *)(r10 - 4) = 7
        r1 = 0
        r2 = r10
        r2 += -4
        r3 = 4
        r4 = 0
        call get_stack
        if r0 != 0 goto bad
        r1 = *(u32 *)(r10 - 4)
        if r1 != 0 goto bad
        r0 = 1
        exit
    bad:
        r0 = 0
        exit";
    assert_eq!(run_src(src), 1);
}

/// The first stack entry written by get_stack is the calling pc — the same
/// value get_stackid stores in its map, so the two helpers agree on the model.
#[test]
fn get_stack_is_deterministic_across_calls() {
    let src = "
        r1 = 0
        r2 = r10
        r2 += -8
        r3 = 8
        r4 = 0
        call get_stack
        r6 = *(u64 *)(r10 - 8)
        r1 = 0
        r2 = r10
        r2 += -8
        r3 = 8
        r4 = 0
        call get_stack
        r7 = *(u64 *)(r10 - 8)
        if r6 == r7 goto same
        r0 = 1
        exit
    same:
        r0 = 0
        exit";
    // Two different call sites -> different innermost pcs.
    assert_eq!(run_src(src), 1);
}

// ------------------------------------------- subprogram pointer returns

/// A static subprogram may return a pointer (kernel semantics: the caller's
/// r0 inherits the register state) — here a map-value-or-null from a lookup
/// wrapper, null-checked by the caller. Real programs (bcc cpudist) do this.
#[test]
fn subprog_may_return_map_value_pointer() {
    let src = "
        .map a array 4 8 1
        call get_val
        if r0 == 0 goto miss
        r1 = *(u64 *)(r0 + 0)
        r0 = 1
        exit
    miss:
        r0 = 0
        exit
    get_val:
        r1 = 0
        *(u32 *)(r10 - 4) = r1
        r1 = map[a]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        exit";
    // Array element 0 always exists, so the lookup hits.
    assert_eq!(run_src(src), 1);
}

/// The kernel rejects returning ANY stack pointer from a subprogram — even a
/// still-live caller-frame one. prepare_func_exit(): "technically it's ok to
/// return caller's stack pointer [...] but let's be conservative" and errors
/// with "cannot return stack pointer to the caller". Mirror it exactly so the
/// vfuzz verdict parity (0 FEBPF-LAX) holds.
#[test]
fn subprog_may_not_return_caller_stack_pointer() {
    let src = "
        r1 = 42
        *(u64 *)(r10 - 8) = r1
        r1 = r10
        r1 += -8
        call ident
        r0 = *(u64 *)(r0 + 0)
        exit
    ident:
        r0 = r1
        exit";
    let err = verify_err(src);
    assert!(err.contains("cannot return stack pointer"), "{err}");
}

/// A pointer into the exiting frame's own stack dies with the frame and is
/// likewise rejected (same kernel rule).
#[test]
fn subprog_may_not_return_own_stack_pointer() {
    let src = "
        call f
        r0 = 0
        exit
    f:
        r0 = r10
        r0 += -8
        exit";
    let err = verify_err(src);
    assert!(err.contains("cannot return stack pointer"), "{err}");
}

/// get_stackid rejects (at verification) a map that is not a stack_trace map.
#[test]
fn get_stackid_requires_stack_trace_map() {
    let src = "
        .map a array 4 8 4
        r1 = 0
        r2 = map[a]
        r3 = 0
        call get_stackid
        exit";
    let err = verify_err(src);
    assert!(err.contains("stack_trace"), "{err}");
}

// ------------------------------------------------- core tracing helpers

/// The tracing identity helpers return fixed, documented constants
/// (febpf has no processes): tgid=pid=1, uid=gid=0, task = opaque nonzero.
#[test]
fn tracing_identity_helpers_are_deterministic_constants() {
    let src = "
        call get_current_pid_tgid
        r6 = r0
        call get_current_uid_gid
        if r0 != 0 goto bad
        call get_current_task
        if r0 == 0 goto bad
        r0 = r6
        exit
    bad:
        r0 = 0
        exit";
    assert_eq!(run_src(src), 0x0000_0001_0000_0001);
}

#[test]
fn get_ns_current_pid_tgid_zeroes_uninitialized_output_without_host_namespace() {
    assert_eq!(febpf::helpers::helper_id("get_ns_current_pid_tgid"), Some(120));
    let mut vm = Vm::new(program(
        "r1 = 0\n\
         r2 = 0\n\
         r3 = r10\n\
         r3 += -8\n\
         r4 = 8\n\
         call get_ns_current_pid_tgid\n\
         r0 = *(u64 *)(r10 - 8)\n\
         exit",
    ))
    .unwrap();
    vm.verify(Config::default()).unwrap();
    assert_eq!(vm.run_no_data().unwrap(), 0);
    #[cfg(feature = "jit")]
    assert_eq!(vm.run_jit(&mut []).unwrap(), 0);

    let mut errno = Vm::new(program(
        "r1 = 0\n\
         r2 = 0\n\
         r3 = r10\n\
         r3 += -8\n\
         r4 = 8\n\
         call get_ns_current_pid_tgid\n\
         exit",
    ))
    .unwrap();
    errno.verify(Config::default()).unwrap();
    assert_eq!(errno.run_no_data().unwrap(), (-22i64) as u64);
}

/// get_socket_cookie returns the fixed, documented, nonzero token
/// 0x0000_0000_c00c_1e01 (febpf has no sockets); it is deterministic across
/// calls and accepts its argument loosely (ctx-like pointer OR scalar), the
/// same shape as the kernel's (ctx)/(sk) flavors.
#[test]
fn get_socket_cookie_is_fixed_nonzero_token() {
    let src = "
        r1 = r10
        call get_socket_cookie
        r6 = r0
        r1 = 0
        call get_socket_cookie
        if r0 != r6 goto bad
        r0 = r6
        exit
    bad:
        r0 = 0
        exit";
    assert_eq!(run_src(src), 0x0000_0000_c00c_1e01);
}

/// get_func_ip returns the fixed opaque token 0xffff_0000_0000_0002 (febpf
/// has no attach point); like get_current_task's token it must not be
/// dereferenced, and probe_read of it faults cleanly.
#[test]
fn get_func_ip_is_opaque_nonzero_token() {
    let src = "
        r1 = 0
        call get_func_ip
        r6 = r0
        ; probe_read(fp-8, 8, token) must -EFAULT and zero-fill
        r1 = r10
        r1 += -8
        r2 = 8
        r3 = r6
        call probe_read_kernel
        if r0 == 0 goto bad
        r1 = *(u64 *)(r10 - 8)
        if r1 != 0 goto bad
        r0 = r6
        exit
    bad:
        r0 = 0
        exit";
    assert_eq!(run_src(src), 0xffff_0000_0000_0002);
}

/// ktime_get_boot_ns has the kernel's no-argument/scalar signature, but its
/// standalone value is deterministic logical time: one nanosecond per
/// observation. Uninitialized r1-r5 prove that no argument is
/// accidentally required by the verifier.
#[test]
fn ktime_get_boot_ns_is_deterministic_logical_time() {
    assert_eq!(febpf::helpers::helper_id("ktime_get_boot_ns"), Some(125));
    assert_eq!(febpf::helpers::helper_name(125), "ktime_get_boot_ns");

    let src = "
        call ktime_get_boot_ns
        r6 = r0
        call ktime_get_boot_ns
        r0 -= r6
        exit";
    assert_eq!(run_src(src), 1);

    #[cfg(feature = "jit")]
    {
        let mut vm = Vm::new(program(src)).unwrap();
        vm.verify(Config::default()).unwrap();
        assert_eq!(vm.run_jit(&mut []).unwrap(), 1);
    }
}

#[test]
fn ktime_get_coarse_ns_is_deterministic_millisecond_time() {
    assert_eq!(febpf::helpers::helper_id("ktime_get_coarse_ns"), Some(160));
    assert_eq!(febpf::helpers::helper_name(160), "ktime_get_coarse_ns");
    let src = "
        call ktime_get_coarse_ns
        r6 = r0
        call ktime_get_coarse_ns
        r0 -= r6
        exit";
    assert_eq!(run_src(src), 1_000_000);
    #[cfg(feature = "jit")]
    {
        let mut vm = Vm::new(program(src)).unwrap();
        vm.verify(Config::default()).unwrap();
        assert_eq!(vm.run_jit(&mut []).unwrap(), 1_000_000);
    }
}

#[test]
fn csum_diff_has_kernel_buffer_rules_and_incremental_checksum_semantics() {
    assert_eq!(febpf::helpers::helper_id("csum_diff"), Some(28));
    let src = "
        *(u32 *)(r10 - 8) = 0x01020304
        *(u32 *)(r10 - 4) = 0x05060708
        r1 = r10
        r1 += -8
        r2 = 4
        r3 = r10
        r3 += -4
        r4 = 4
        r5 = 0
        call csum_diff
        exit";
    assert_eq!(run_src(src), 0x0808);
    #[cfg(feature = "jit")]
    {
        let mut vm = Vm::new(program(src)).unwrap();
        vm.verify(Config::default()).unwrap();
        assert_eq!(vm.run_jit(&mut []).unwrap(), 0x0808);
    }

    let bad_size = src.replace("r2 = 4", "r2 = 2");
    assert!(verify_err(&bad_size).contains("constant multiple of 4"));
    let uninit = src.replace("*(u32 *)(r10 - 8) = 0x01020304\n", "");
    assert!(verify_err(&uninit).contains("uninitialized stack"));
}

#[test]
fn spin_helpers_require_exact_btf_map_field_and_balanced_pairing() {
    assert_eq!(febpf::helpers::helper_id("spin_lock"), Some(93));
    assert_eq!(febpf::helpers::helper_id("spin_unlock"), Some(94));
    let body = "
        .map locks array 4 8 1
        *(u32 *)(r10 - 4) = 0
        r1 = map[locks]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 == 0 goto miss
        r6 = r0
        r1 = r6
        call spin_lock
        *(u32 *)(r6 + 4) = 7
        r1 = r6
        call spin_unlock
        r0 = *(u32 *)(r6 + 4)
        exit
    miss:
        r0 = 0
        exit";
    let mut prog = program(body);
    prog.maps[0].spin_lock_off = Some(0);
    let mut standalone_map = febpf::maps::Map::new(prog.maps[0].clone()).unwrap();
    standalone_map
        .update(&0u32.to_ne_bytes(), &[1, 2, 3, 4, 7, 0, 0, 0])
        .unwrap();
    let value = standalone_map.lookup(&0u32.to_ne_bytes()).unwrap();
    assert_eq!(standalone_map.value(value), &[0, 0, 0, 0, 7, 0, 0, 0]);

    let mut invalid = prog.clone();
    invalid.maps[0].spin_lock_off = Some(8);
    assert!(Vm::new(invalid).is_err());

    let mut vm = Vm::new(prog.clone()).unwrap();
    vm.verify(Config::default()).unwrap();
    assert_eq!(vm.run(&mut []).unwrap(), 7);
    #[cfg(feature = "jit")]
    assert_eq!(vm.run_jit(&mut []).unwrap(), 7);

    let mut missing_btf = prog.clone();
    missing_btf.maps[0].spin_lock_off = None;
    let mut vm = Vm::new(missing_btf).unwrap();
    assert!(vm.verify(Config::default()).is_err());

    let direct_lock_access = body.replace("*(u32 *)(r6 + 4) = 7", "*(u32 *)(r6 + 0) = 7");
    let mut prog = program(&direct_lock_access);
    prog.maps[0].spin_lock_off = Some(0);
    let mut vm = Vm::new(prog).unwrap();
    let error = match vm.verify(Config::default()) {
        Ok(_) => panic!("direct spin-lock access verified"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("overlaps spin-lock field"), "{error}");

    let unbalanced = body.replace("r1 = r6\n        call spin_unlock\n", "");
    let mut prog = program(&unbalanced);
    prog.maps[0].spin_lock_off = Some(0);
    let mut vm = Vm::new(prog).unwrap();
    let error = match vm.verify(Config::default()) {
        Ok(_) => panic!("unbalanced spin lock verified"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("holding a spin lock"), "{error}");
}

/// The caller must null-check a returned map_value_or_null before deref —
/// the pointer's typing survives the frame pop.
#[test]
fn subprog_returned_pointer_still_needs_null_check() {
    let src = "
        .map a array 4 8 1
        call lookup0
        r0 = *(u64 *)(r0 + 0)
        exit
    lookup0:
        w1 = 0
        *(u32 *)(r10 - 4) = r1
        r1 = map[a]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        exit";
    let err = verify_err(src);
    assert!(err.contains("NULL"), "{err}");
}

/// get_current_comm fills the buffer with \"febpf\" NUL-padded and marks the
/// stack initialized (the read-back below would fail verification otherwise).
#[test]
fn get_current_comm_writes_fixed_name() {
    let src = "
        r1 = r10
        r1 += -8
        r2 = 8
        call get_current_comm
        r0 = *(u64 *)(r10 - 8)
        exit";
    assert_eq!(run_src(src), 0x66_7062_6566); // \"febpf\\0\\0\\0\" little-endian
}

// ------------------------------------------------------ probe_read family

/// probe_read_kernel from a resolvable pointer (here: a map value) copies the
/// bytes and returns 0.
#[test]
fn probe_read_kernel_copies_from_valid_pointer() {
    let src = "
        .map a array 4 8 1
        ; store 777 into element 0
        w1 = 0
        *(u32 *)(r10 - 4) = r1
        r1 = 777
        *(u64 *)(r10 - 16) = r1
        r1 = map[a]
        r2 = r10
        r2 += -4
        r3 = r10
        r3 += -16
        r4 = 0
        call map_update_elem
        ; probe_read_kernel(fp-24, 8, &elem0)
        r7 = map[a][0]
        r1 = r10
        r1 += -24
        r2 = 8
        r3 = r7
        call probe_read_kernel
        if r0 != 0 goto fault
        r0 = *(u64 *)(r10 - 24)
        exit
    fault:
        r0 = 0
        exit";
    assert_eq!(run_src(src), 777);
}

/// probe_read_kernel from an unresolvable address (the opaque
/// get_current_task token) zero-fills dst and returns -EFAULT.
#[test]
fn probe_read_kernel_faults_cleanly_on_wild_pointer() {
    let src = "
        ; poison the buffer so the zero-fill is observable
        r1 = 0xdead
        *(u64 *)(r10 - 8) = r1
        call get_current_task
        r3 = r0
        r1 = r10
        r1 += -8
        r2 = 8
        call probe_read_kernel
        if r0 == -14 goto efault
        r0 = 0
        exit
    efault:
        r0 = *(u64 *)(r10 - 8)
        r0 += 1        ; zero-filled buffer + 1
        exit";
    assert_eq!(run_src(src), 1);
}

/// probe_read_kernel_str stops at the NUL and returns length including it;
/// the rest of the buffer is zeroed.
#[test]
fn probe_read_kernel_str_copies_nul_terminated() {
    let src = "
        ; build \"hi\\0\" + junk at fp-8
        r1 = 0x4141410000006968 ll ; bytes: 68 69 00 00 00 41 41 41
        *(u64 *)(r10 - 8) = r1
        r3 = r10
        r3 += -8
        r1 = r10
        r1 += -16
        r2 = 8
        call probe_read_kernel_str
        if r0 != 3 goto bad       ; 'h','i',NUL
        r0 = *(u64 *)(r10 - 16)   ; \"hi\\0\" then zeros, junk not copied
        exit
    bad:
        r0 = 0
        exit";
    assert_eq!(run_src(src), 0x6968);
}

/// An unterminated source is truncated to size with a forced NUL and the
/// returned length equals size.
#[test]
fn probe_read_kernel_str_truncates_with_nul() {
    let src = "
        r1 = 0x4242424242424242 ll
        *(u64 *)(r10 - 8) = r1
        r3 = r10
        r3 += -8
        r1 = r10
        r1 += -16
        r2 = 4
        call probe_read_kernel_str
        if r0 != 4 goto bad
        r0 = *(u32 *)(r10 - 16)   ; 42 42 42 00
        exit
    bad:
        r0 = 0
        exit";
    assert_eq!(run_src(src), 0x0042_4242);
}

/// current_task_under_cgroup: febpf's task is under no cgroup (fixed 0);
/// an out-of-range index is -EINVAL; a non-cgroup map fails verification.
#[test]
fn current_task_under_cgroup_deterministic() {
    let src = "
        .map cg cgroup_array 4 4 2
        r1 = map[cg]
        r2 = 1
        call current_task_under_cgroup
        if r0 != 0 goto bad
        r1 = map[cg]
        r2 = 5                    ; >= max_entries
        call current_task_under_cgroup
        if r0 != -22 goto bad
        r0 = 7
        exit
    bad:
        r0 = 0
        exit";
    assert_eq!(run_src(src), 7);

    let err = verify_err(
        "
        .map h hash 4 4 2
        r1 = map[h]
        r2 = 0
        call current_task_under_cgroup
        exit",
    );
    assert!(err.contains("cgroup_array"), "{err}");
}

// ------------------------------------------------------------------ calls

#[test]
fn bpf_to_bpf_call() {
    let src = "
        r1 = 20
        r2 = 22
        call add
        exit
    add:
        r0 = r1
        r0 += r2
        exit";
    assert_eq!(run_src(src), 42);
}

#[test]
fn callee_saved_regs_survive_call() {
    let src = "
        r6 = 111
        r1 = 0
        call clobber
        r0 = r6
        exit
    clobber:
        r6 = 999
        r0 = 0
        exit";
    assert_eq!(run_src(src), 111);
}

#[test]
fn caller_stack_pointer_arg() {
    // pass a pointer into the caller's stack; callee writes through it
    let src = "
        r1 = 0
        *(u64 *)(r10 - 8) = r1
        r1 = r10
        r1 += -8
        call write42
        r0 = *(u64 *)(r10 - 8)
        exit
    write42:
        r2 = 42
        *(u64 *)(r1) = r2
        r0 = 0
        exit";
    assert_eq!(run_src(src), 42);
}

#[test]
fn helper_trace_printk() {
    let src = r#"
        ; build "n=%d" style output: store format on the stack
        r1 = 0x0064253d6e ll   ; "n=%d\0" little-endian
        *(u64 *)(r10 - 8) = r1
        r1 = r10
        r1 += -8
        r2 = 5
        r3 = 42
        call trace_printk
        r0 = 0
        exit"#;
    let mut vm = Vm::new(program(src)).unwrap();
    vm.verify(Config {
        ctx_size: 0,
        ..Default::default()
    })
    .unwrap();
    vm.run(&mut []).unwrap();
    assert_eq!(vm.printk, vec!["n=42".to_string()]);

    vm.printk.clear();
    let mut external = Vec::new();
    let mut context = [];
    {
        let env = ExecutionEnvironment::plain(&mut context).with_printk(&mut external, false);
        let mut machine = vm.machine_environment(env).unwrap();
        let base = machine.snapshot();
        while machine.step().unwrap().is_none() {}
        let finished = machine.snapshot();
        machine.restore(&base);
        while machine.step().unwrap().is_none() {}
        assert_eq!(machine.snapshot(), finished);
    }
    assert_eq!(external, ["n=42"]);
    assert!(vm.printk.is_empty());

    #[cfg(feature = "jit")]
    {
        external.clear();
        let env = ExecutionEnvironment::plain(&mut context).with_printk(&mut external, false);
        assert_eq!(vm.run_environment_jit(env).unwrap().return_value, 0);
        assert_eq!(external, ["n=42"]);
        assert!(vm.printk.is_empty());
    }
}

#[test]
fn helper_trace_vprintk_formats_argument_array_and_accepts_null_for_zero() {
    assert_eq!(febpf::helpers::helper_id("trace_vprintk"), Some(177));
    let src = "r0 = 0x253d622064253d61 ll\n\
        *(u64 *)(r10 - 64) = r0\n\
        r0 = 0x642064253d632064 ll\n\
        *(u64 *)(r10 - 56) = r0\n\
        r0 = 0x64253d ll\n\
        *(u64 *)(r10 - 48) = r0\n\
        *(u64 *)(r10 - 32) = 1\n\
        *(u64 *)(r10 - 24) = 2\n\
        *(u64 *)(r10 - 16) = 3\n\
        *(u64 *)(r10 - 8) = 4\n\
        r1 = r10\n\
        r1 += -64\n\
        r2 = 24\n\
        r3 = r10\n\
        r3 += -32\n\
        r4 = 32\n\
        call trace_vprintk\n\
        exit";
    let mut vm = Vm::new(program(src)).unwrap();
    vm.verify(Config::default()).unwrap();
    assert_eq!(vm.run_no_data().unwrap(), 15);
    assert_eq!(vm.printk, ["a=1 b=2 c=3 d=4"]);
    #[cfg(feature = "jit")]
    {
        vm.printk.clear();
        assert_eq!(vm.run_jit(&mut []).unwrap(), 15);
        assert_eq!(vm.printk, ["a=1 b=2 c=3 d=4"]);
    }

    let mut no_args = Vm::new(program(
        "*(u32 *)(r10 - 4) = 0x000a6b6f\n\
         r1 = r10\n\
         r1 += -4\n\
         r2 = 4\n\
         r3 = 0\n\
         r4 = 0\n\
         call trace_vprintk\n\
         exit",
    ))
    .unwrap();
    no_args.verify(Config::default()).unwrap();
    assert_eq!(no_args.run_no_data().unwrap(), 3);
    assert_eq!(no_args.printk, ["ok\n"]);
}

#[test]
fn helper_trace_vprintk_rejects_malformed_data_length_atomically() {
    let mut vm = Vm::new(program(
        "*(u32 *)(r10 - 16) = 0x000a6b6f\n\
         *(u64 *)(r10 - 8) = 1\n\
         r1 = r10\n\
         r1 += -16\n\
         r2 = 4\n\
         r3 = r10\n\
         r3 += -8\n\
         r4 = 7\n\
         call trace_vprintk\n\
         exit",
    ))
    .unwrap();
    vm.verify(Config::default()).unwrap();
    assert_eq!(vm.run_no_data().unwrap(), (-22i64) as u64);
    assert!(vm.printk.is_empty());
}

// ------------------------------------------------------------------ verifier rejections

#[test]
fn reject_uninit_reg() {
    let e = verify_err("r0 = r3\n exit");
    assert!(e.contains("uninitialized"), "{e}");
}

#[test]
fn reject_missing_r0() {
    let e = verify_err("r1 = 1\n exit");
    assert!(e.contains("without setting r0"), "{e}");
}

#[test]
fn reject_write_to_r10() {
    let e = verify_err("r10 = 4\n r0 = 0\n exit");
    assert!(e.contains("read-only"), "{e}");
}

#[test]
fn reject_stack_oob() {
    let e = verify_err("r1 = 1\n *(u64 *)(r10 - 520) = r1\n r0 = 0\n exit");
    assert!(e.contains("out of bounds"), "{e}");
    let e = verify_err("r1 = 1\n *(u64 *)(r10 + 8) = r1\n r0 = 0\n exit");
    assert!(e.contains("out of bounds"), "{e}");
}

#[test]
fn reject_uninit_stack_read() {
    let e = verify_err("r0 = *(u64 *)(r10 - 8)\n exit");
    assert!(e.contains("uninitialized stack"), "{e}");
}

#[test]
fn privileged_policy_allows_zero_backed_direct_stack_reads() {
    let source = "
        *(u32 *)(r10 - 8) = 0x11223344
        r0 = *(u64 *)(r10 - 8)
        exit";
    let mut strict = Vm::new(program(source)).unwrap();
    assert!(strict.verify(Config::default()).is_err());

    let mut privileged = Vm::new(program(source)).unwrap();
    privileged
        .verify(Config {
            uninit_stack: febpf::verifier::UninitStackPolicy::Allow,
            ..Config::default()
        })
        .unwrap();
    assert_eq!(privileged.run(&mut []).unwrap(), 0x11223344);
}

#[test]
fn privileged_policy_allows_zero_backed_helper_input_but_not_uninit_registers() {
    let source = "
        .map values hash 4 8 1
        *(u32 *)(r10 - 12) = 7
        *(u32 *)(r10 - 8) = 0x55667788
        r1 = map[values]
        r2 = r10
        r2 += -12
        r3 = r10
        r3 += -8
        r4 = 0
        call map_update_elem
        r1 = map[values]
        r2 = r10
        r2 += -12
        call map_lookup_elem
        if r0 == 0 goto miss
        r0 = *(u64 *)(r0 + 0)
        exit
      miss:
        r0 = 0
        exit";
    let mut strict = Vm::new(program(source)).unwrap();
    let error = match strict.verify(Config::default()) {
        Ok(_) => panic!("strict policy accepted partially initialized helper input"),
        Err(error) => error,
    };
    assert!(error.msg.contains("helper reads uninitialized stack"), "{error}");

    let cfg = Config {
        uninit_stack: febpf::verifier::UninitStackPolicy::Allow,
        ..Config::default()
    };
    let mut privileged = Vm::new(program(source)).unwrap();
    privileged.verify(cfg.clone()).unwrap();
    assert_eq!(privileged.run(&mut []).unwrap(), 0x55667788);

    let mut bad_register = Vm::new(program("r0 = r2\nexit")).unwrap();
    assert!(bad_register.verify(cfg).is_err());
}

#[test]
fn privileged_policy_zeroes_reused_local_call_frames() {
    let source = "
        call write_byte
        call read_byte
        exit
      write_byte:
        *(u8 *)(r10 - 1) = 0xaa
        r0 = 0
        exit
      read_byte:
        r0 = *(u8 *)(r10 - 1)
        exit";
    let mut vm = Vm::new(program(source)).unwrap();
    vm.verify(Config {
        uninit_stack: febpf::verifier::UninitStackPolicy::Allow,
        ..Config::default()
    })
    .unwrap();
    assert_eq!(vm.run(&mut []).unwrap(), 0);
    #[cfg(feature = "jit")]
    {
        let mut vm = Vm::new(program(source)).unwrap();
        vm.verify(Config {
            uninit_stack: febpf::verifier::UninitStackPolicy::Allow,
            ..Config::default()
        })
        .unwrap();
        assert_eq!(vm.run_jit(&mut []).unwrap(), 0);
    }
}

#[test]
fn reject_unchecked_map_value() {
    let e = verify_err(
        "
        .map m array 4 8 1
        w1 = 0
        *(u32 *)(r10 - 4) = r1
        r1 = map[m]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        r0 = *(u64 *)(r0)   ; missing null check!
        exit",
    );
    assert!(e.contains("NULL"), "{e}");
}

#[test]
fn reject_infinite_loop() {
    let e = verify_err(
        "
    loop:
        r0 = 0
        goto loop
        exit",
    );
    // either unreachable exit or too complex, depending on structure checks
    assert!(
        e.contains("unreachable") || e.contains("too complex"),
        "{e}"
    );
}

#[test]
fn reject_unbounded_loop() {
    let e = verify_err(
        "
        r0 = 0
    loop:
        r0 += 1
        if r0 != 0 goto loop
        exit",
    );
    assert!(e.contains("too complex"), "{e}");
}

#[test]
fn tail_call_requires_prog_array() {
    let good = "
        .map progs prog_array 4 4 8
        r2 = map[progs]
        r3 = 0
        call tail_call
        r0 = 7
        exit";
    let mut vm = Vm::new(program(good)).unwrap();
    vm.verify(Config::default())
        .expect("tail_call with prog_array should verify");

    let bad = "
        .map values array 4 4 8
        r2 = map[values]
        r3 = 0
        call tail_call
        r0 = 7
        exit";
    let mut vm = Vm::new(program(bad)).unwrap();
    let err = match vm.verify(Config::default()) {
        Ok(_) => panic!("tail_call with an array map verified"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("requires a prog_array map"), "{err}");
}

#[test]
fn prog_array_slots_store_program_identities() {
    use febpf::maps::{Map, MapDef, MapKind};
    let mut map = Map::new(MapDef {
        name: "dispatch".into(),
        kind: MapKind::ProgArray,
        key_size: 4,
        value_size: 4,
        max_entries: 2,
        readonly: false,
        init: Vec::new(),
        inner_map_idx: None,
        map_in_map_values: Vec::new(),
        spin_lock_off: None,
    })
    .unwrap();
    assert_eq!(map.program_at(0), None);
    map.set_program(0, 42).unwrap();
    assert_eq!(map.program_at(0), Some(42));
    assert_eq!(map.set_program(2, 9), Err(-7));
}

fn nested_map_program(null_check: bool) -> Program {
    let check = if null_check {
        "if r0 == 0 goto miss"
    } else {
        ""
    };
    let mut prog = program(&format!(
        ".map inner array 4 8 1
         .map outer array_of_maps 4 4 2 inner
         *(u32 *)(r10 - 4) = 1
         r1 = map[outer]
         r2 = r10
         r2 += -4
         call map_lookup_elem
         {check}
         r1 = r0
         *(u32 *)(r10 - 4) = 0
         r2 = r10
         r2 += -4
         call map_lookup_elem
         if r0 == 0 goto miss
         r0 = *(u64 *)(r0 + 0)
         exit
       miss:
         r0 = 0
         exit"
    ));
    prog.maps[0].init = 42u64.to_ne_bytes().to_vec();
    prog.maps[1].map_in_map_values = vec![(1, 0)];
    prog
}

#[test]
fn array_of_maps_lookup_returns_typed_inner_map() {
    let prog = nested_map_program(true);
    let mut vm = Vm::new(prog).unwrap();
    vm.verify(Config::default()).unwrap();
    assert_eq!(vm.run(&mut []).unwrap(), 42);
}

#[test]
fn array_of_maps_lookup_requires_null_check() {
    let prog = nested_map_program(false);
    let mut vm = Vm::new(prog).unwrap();
    let err = match vm.verify(Config::default()) {
        Ok(_) => panic!("array_of_maps lookup without a null check verified"),
        Err(err) => err,
    };
    assert!(err.msg.contains("expected map pointer"), "{err}");
}

#[test]
fn hash_of_maps_lookup_returns_typed_inner_map() {
    let mut prog = program(
        ".map inner array 4 8 1
         .map outer hash_of_maps 8 4 2 inner
         *(u64 *)(r10 - 8) = 7
         r1 = map[outer]
         r2 = r10
         r2 += -8
         call map_lookup_elem
         if r0 == 0 goto miss
         r1 = r0
         *(u32 *)(r10 - 4) = 0
         r2 = r10
         r2 += -4
         call map_lookup_elem
         if r0 == 0 goto miss
         r0 = *(u64 *)(r0 + 0)
         exit
       miss:
         r0 = 0
         exit",
    );
    prog.maps[0].init = 42u64.to_ne_bytes().to_vec();
    let mut vm = Vm::new(prog).unwrap();
    vm.update_inner_map(
        1,
        &7u64.to_ne_bytes(),
        0,
        febpf::maps::MapUpdateMode::NoExist,
    )
    .unwrap();
    vm.verify(Config::default()).unwrap();
    assert_eq!(vm.run(&mut []).unwrap(), 42);
    assert_eq!(vm.maps[1].inner_map_by_key(&7u64.to_ne_bytes()), Some(0));
    assert_eq!(
        vm.update_inner_map(
            1,
            &7u64.to_ne_bytes(),
            0,
            febpf::maps::MapUpdateMode::NoExist,
        ),
        Err(-17)
    );
    vm.delete_inner_map(1, &7u64.to_ne_bytes()).unwrap();
    assert_eq!(vm.maps[1].inner_map_by_key(&7u64.to_ne_bytes()), None);
}

#[test]
fn map_in_map_userspace_update_rejects_incompatible_inner_map() {
    let prog = program(
        ".map template array 4 8 1
         .map incompatible hash 4 8 1
         .map outer hash_of_maps 8 4 2 template
         r0 = 0
         exit",
    );
    let mut vm = Vm::new(prog).unwrap();
    assert_eq!(
        vm.update_inner_map(
            2,
            &7u64.to_ne_bytes(),
            1,
            febpf::maps::MapUpdateMode::Any,
        ),
        Err(-22)
    );
    assert_eq!(
        vm.update_inner_map(
            2,
            &7u64.to_ne_bytes(),
            99,
            febpf::maps::MapUpdateMode::Any,
        ),
        Err(-2)
    );
}

fn copied_scalar_size_program(second_mask: u64) -> Program {
    program(&format!(
        ".map buf array 4 16296 1
         .map events perf_event_array 4 4 1
         r6 = r1
         r5 = *(u16 *)(r1 + 0)
         if r5 == 0 goto out
         w5 += 4008
         w1 = w5
         w1 &= 65535
         if w1 > 16296 goto out
         r5 &= {second_mask}
         r1 = r6
         r2 = map[events]
         r3 = -1
         r4 = map[buf][0] + 0
         call perf_event_output
       out:
         r0 = 0
         exit"
    ))
}

#[test]
fn copied_scalar_expression_propagates_bounds() {
    let mut vm = Vm::new(copied_scalar_size_program(65535)).unwrap();
    vm.verify(Config {
        ctx_size: 2,
        ..Default::default()
    })
    .unwrap();
}

#[test]
fn different_scalar_expression_does_not_inherit_bounds() {
    let mut vm = Vm::new(copied_scalar_size_program(32767)).unwrap();
    let err = match vm.verify(Config {
        ctx_size: 2,
        ..Default::default()
    }) {
        Ok(_) => panic!("different masked expression inherited an unrelated bound"),
        Err(err) => err,
    };
    assert!(err.msg.contains("out of bounds"), "{err}");
}

#[test]
fn copied_scalar_bounds_follow_aligned_spill() {
    let prog = program(
        ".map buf array 4 100 1
         .map events perf_event_array 4 4 1
         r6 = r1
         r5 = *(u16 *)(r1 + 0)
         r1 = r5
         *(u64 *)(r10 - 8) = r5
         if r1 > 100 goto out
         r5 = *(u64 *)(r10 - 8)
         r1 = r6
         r2 = map[events]
         r3 = -1
         r4 = map[buf][0] + 0
         call perf_event_output
       out:
         r0 = 0
         exit",
    );
    let mut vm = Vm::new(prog).unwrap();
    vm.verify(Config {
        ctx_size: 2,
        ..Default::default()
    })
    .unwrap();
}

#[test]
fn tail_call_dispatches_and_miss_falls_through() {
    let entry = program(
        ".map progs prog_array 4 4 2
         r2 = map[progs]
         r3 = 0
         call tail_call
         r0 = 7
         exit",
    );
    let target = program(
        ".map progs prog_array 4 4 2
         r0 = 42
         exit",
    );
    let mut vm = Vm::new(entry.clone()).unwrap();
    vm.verify(Config::default()).unwrap();
    vm.register_tail_call("progs", 0, target, Config::default())
        .unwrap();
    assert_eq!(vm.run(&mut []).unwrap(), 42);

    let mut miss = Vm::new(entry).unwrap();
    miss.verify(Config::default()).unwrap();
    assert_eq!(miss.run(&mut []).unwrap(), 7);
}

#[test]
fn tail_call_cycle_stops_at_kernel_chain_limit() {
    let src = ".map progs prog_array 4 4 1
               r2 = map[progs]
               r3 = 0
               call tail_call
               r0 = 99
               exit";
    let mut vm = Vm::new(program(src)).unwrap();
    vm.verify(Config::default()).unwrap();
    vm.register_tail_call("progs", 0, program(src), Config::default())
        .unwrap();
    assert_eq!(vm.run(&mut []).unwrap(), 99);
}

#[test]
fn tail_call_target_shares_maps_with_entry() {
    let maps = ".map progs prog_array 4 4 1\n.map state array 4 8 1\n";
    let entry = program(&format!(
        "{maps}
         r6 = r1
         *(u32 *)(r10 - 4) = 0
         *(u64 *)(r10 - 16) = 55
         r1 = map[state]
         r2 = r10
         r2 += -4
         r3 = r10
         r3 += -16
         r4 = 0
         call map_update_elem
         r1 = r6
         r2 = map[progs]
         r3 = 0
         call tail_call
         r0 = 7
         exit"
    ));
    let target = program(&format!(
        "{maps}
         *(u32 *)(r10 - 4) = 0
         r1 = map[state]
         r2 = r10
         r2 += -4
         call map_lookup_elem
         if r0 == 0 goto miss
         r0 = *(u64 *)(r0 + 0)
         exit
       miss:
         r0 = 0
         exit"
    ));
    let mut vm = Vm::new(entry).unwrap();
    vm.verify(Config::default()).unwrap();
    vm.register_tail_call("progs", 0, target, Config::default())
        .unwrap();
    assert_eq!(vm.run(&mut []).unwrap(), 55);
}

#[test]
fn tail_call_snapshot_restores_active_program() {
    let entry = program(
        ".map progs prog_array 4 4 1
         r2 = map[progs]
         r3 = 0
         call tail_call
         r0 = 7
         exit",
    );
    let target = program(
        ".map progs prog_array 4 4 1
         r0 = 42
         exit",
    );
    let mut vm = Vm::new(entry).unwrap();
    vm.verify(Config::default()).unwrap();
    vm.register_tail_call("progs", 0, target, Config::default())
        .unwrap();
    let mut ctx = [];
    let mut machine = vm.machine(&mut ctx);
    assert_eq!(machine.step().unwrap(), None); // map lddw
    assert_eq!(machine.step().unwrap(), None); // index
    assert_eq!(machine.step().unwrap(), None); // successful tail call
    let snap = machine.snapshot();
    assert_eq!(machine.step().unwrap(), None);
    assert_eq!(machine.step().unwrap(), Some(42));
    machine.restore(&snap);
    assert_eq!(machine.step().unwrap(), None);
    assert_eq!(machine.step().unwrap(), Some(42));
}

#[test]
fn reject_ctx_oob() {
    let e = verify_err_ctx("r0 = *(u64 *)(r1 + 12)\n exit", 16);
    assert!(e.contains("out of bounds"), "{e}");
}

#[test]
fn reject_modified_ctx_ptr_deref() {
    // The kernel requires a PTR_TO_CTX to have its own accumulated offset == 0
    // at dereference time; the access offset must come only from the load
    // instruction's immediate. Both of these bake an offset into the pointer
    // register and are rejected.

    // (a) VARIABLE offset: pointer arithmetic with an unknown value.
    let e = verify_err_ctx(
        "
        r2 = *(u8 *)(r1 + 0)
        r2 &= 4
        r1 += r2
        r0 = *(u8 *)(r1 + 0)
        exit",
        16,
    );
    assert!(e.contains("modified ctx ptr"), "{e}");

    // (b) CONSTANT offset baked into the pointer: r2 = r1; r2 += 4; *(r2+0).
    // Kernel shows R2=ctx(off=4) and rejects the deref.
    let e = verify_err_ctx(
        "
        r2 = r1
        r2 += 4
        r0 = *(u32 *)(r2 + 0)
        exit",
        16,
    );
    assert!(e.contains("modified ctx ptr"), "{e}");
}

#[test]
fn accept_fixed_offset_ctx_access() {
    // Offset in the LOAD INSTRUCTION's immediate — pointer's own offset is 0.
    // This must stay legal (not over-tightened into FEBPF-STRICT).
    let mut vm = Vm::new(program("r0 = *(u32 *)(r1 + 8)\n exit")).unwrap();
    vm.verify(Config {
        ctx_size: 16,
        ..Default::default()
    })
    .expect("fixed-offset ctx access must verify");
}

#[test]
fn reject_misaligned_stack_store() {
    // 8-byte store at a non-8-aligned stack offset: kernel always rejects,
    // regardless of the --strict-align policy (strict_alignment defaults off).
    let e = verify_err("r1 = 1\n *(u64 *)(r10 - 12) = r1\n r0 = 0\n exit");
    assert!(e.contains("misaligned stack access"), "{e}");
    // a 4-byte store at a 2-aligned-but-not-4 offset is also rejected
    let e = verify_err("r1 = 1\n *(u32 *)(r10 - 6) = r1\n r0 = 0\n exit");
    assert!(e.contains("misaligned stack access"), "{e}");
}

#[test]
fn accept_aligned_stack_access() {
    // Naturally aligned stack accesses must still verify (not over-tightened).
    let mut vm = Vm::new(program(
        "
        r1 = 1
        *(u64 *)(r10 - 8) = r1
        *(u32 *)(r10 - 12) = r1
        *(u16 *)(r10 - 14) = r1
        *(u8 *)(r10 - 15) = r1
        r0 = 0
        exit",
    ))
    .unwrap();
    vm.verify(Config::default())
        .expect("aligned stack accesses must verify");
}

#[test]
fn reject_scalar_deref() {
    let e = verify_err("r1 = 1000\n r0 = *(u64 *)(r1)\n exit");
    assert!(e.contains("scalar"), "{e}");
}

#[test]
fn reject_unreachable_code() {
    let e = verify_err(
        "
        r0 = 0
        exit
        r0 = 1
        exit",
    );
    assert!(e.contains("unreachable"), "{e}");
}

#[test]
fn reject_pointer_return() {
    let e = verify_err("r0 = r10\n exit");
    assert!(e.contains("pointer"), "{e}");
}

#[test]
fn reject_call_depth() {
    let src = "
        r1 = 0
        call f1
        exit
    f1:
        call f2
        exit
    f2:
        call f3
        exit
    f3:
        call f4
        exit
    f4:
        call f5
        exit
    f5:
        call f6
        exit
    f6:
        call f7
        exit
    f7:
        call f8
        exit
    f8:
        r0 = 0
        exit";
    let e = verify_err(src);
    assert!(e.contains("call depth"), "{e}");
}

#[test]
fn bounds_refinement_allows_var_offset_map_access() {
    // classic pattern: bound a scalar, use it as a map-value offset
    let src = "
        .map m array 4 16 1
        w1 = 0
        *(u32 *)(r10 - 4) = r1
        r1 = map[m]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 == 0 goto out
        r3 = *(u64 *)(r0)     ; untrusted scalar from the map
        r3 &= 7               ; bound it to [0,7]
        r0 += r3
        r0 = *(u8 *)(r0 + 8)  ; offset in [8,15] — inside the 16-byte value
        exit
    out:
        r0 = 0
        exit";
    assert_eq!(run_src(src), 0);
}

#[test]
fn reject_unbounded_map_offset() {
    let e = verify_err(
        "
        .map m array 4 16 1
        w1 = 0
        *(u32 *)(r10 - 4) = r1
        r1 = map[m]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 == 0 goto out
        r3 = *(u64 *)(r0)
        r0 += r3              ; unbounded offset
        r0 = *(u8 *)(r0)
        exit
    out:
        r0 = 0
        exit",
    );
    assert!(e.contains("unbounded") || e.contains("out of bounds"), "{e}");
}

#[test]
fn spilled_pointer_restored() {
    let src = "
        *(u64 *)(r10 - 8) = r10    ; spill fp
        r1 = *(u64 *)(r10 - 8)     ; restore as pointer
        r2 = 5
        *(u64 *)(r1 - 16) = r2     ; use it as a stack pointer
        r0 = *(u64 *)(r10 - 16)
        exit";
    assert_eq!(run_src(src), 5);
}

// ------------------------------------------------------------------ asm/disasm

#[test]
fn disasm_roundtrip() {
    let src = "
        r0 = 0
        r1 = 0x1122334455667788 ll
        w2 = 7
        r3 = (s16)r1
        r0 += r1
        if r0 s< 3 goto out
        r4 = *(u16 *)(r10 - 8)
    out:
        exit";
    let p = program(&format!(
        "r5 = 1\n *(u64 *)(r10 - 8) = r5\n{src}"
    ));
    let text = febpf::disasm::disasm_program(&p.insns);
    // strip the "N:" prefixes and reassemble
    let stripped: String = text
        .lines()
        .map(|l| l.split_once(": ").unwrap().1)
        .collect::<Vec<_>>()
        .join("\n");
    let p2 = asm::assemble(&stripped).expect("reassembly failed");
    assert_eq!(p.insns, p2.insns, "asm(disasm(p)) != p:\n{text}\n{stripped}");
}

// ------------------------------------------------------------------ user helpers

#[test]
fn user_registered_helper() {
    use febpf::helpers::{id, ArgKind, HelperSig, MemBus, RetKind};
    let src = "
        r1 = 6
        r2 = r10
        r2 += -8
        r5 = 1              ; size for the MemWrite arg
        call 0x10000        ; custom: r0 = r1 * 7, writes 0xEE to *r2
        r1 = *(u8 *)(r10 - 8)
        r0 += r1
        exit";
    let mut vm = Vm::new(program(src)).unwrap();
    vm.user_helpers.register(
        id::FIRST_USER,
        HelperSig {
            name: "mul7_poke",
            args: [
                ArgKind::Scalar,
                ArgKind::MemWrite { size_arg: 4 },
                ArgKind::None,
                ArgKind::None,
                ArgKind::Size,
            ],
            ret: RetKind::Scalar,
        },
        Box::new(|args: [u64; 5], mem: &mut dyn MemBus| {
            mem.write(args[1], &[0xEE])?;
            Ok(args[0] * 7)
        }),
    );
    vm.verify(Config {
        ctx_size: 0,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(vm.run(&mut []).unwrap(), 42 + 0xEE);
}

// ------------------------------------------------------------ read-only maps

#[test]
fn readonly_map_reads_ok() {
    // reads through a frozen map's value pointer are fine
    let src = "
        .map ro array 4 8 1 ro
        r1 = map[ro][0] + 0
        r0 = *(u64 *)(r1 + 0)
        exit";
    assert_eq!(run_src(src), 0);
}

#[test]
fn readonly_map_store_rejected_by_verifier() {
    let e = verify_err(
        "
        .map ro array 4 8 1 ro
        r1 = map[ro][0]
        r2 = 1
        *(u64 *)(r1 + 0) = r2
        r0 = 0
        exit",
    );
    assert!(e.contains("read-only"), "unexpected error: {e}");
}

#[test]
fn readonly_map_store_rejected_at_runtime() {
    // even unverified, the interpreter blocks the write
    let mut vm = Vm::new(program(
        "
        .map ro array 4 8 1 ro
        r1 = map[ro][0]
        r2 = 1
        *(u64 *)(r1 + 0) = r2
        r0 = 0
        exit",
    ))
    .unwrap();
    let err = vm.run(&mut []).expect_err("write should fault");
    assert!(err.to_string().contains("read-only"), "unexpected: {err}");
}

#[test]
fn readonly_map_update_helper_rejected() {
    let e = verify_err(
        "
        .map ro array 4 8 1 ro
        w1 = 0
        *(u32 *)(r10 - 4) = r1
        r1 = 7
        *(u64 *)(r10 - 16) = r1
        r1 = map[ro]
        r2 = r10
        r2 += -4
        r3 = r10
        r3 += -16
        r4 = 0
        call map_update_elem
        r0 = 0
        exit",
    );
    assert!(e.contains("read-only"), "unexpected error: {e}");
}

#[test]
fn map_value_lddw_with_offset() {
    // writable direct value access: store at +8, read it back at +8
    let src = "
        .map m array 4 16 1
        r1 = map[m][0] + 8
        r2 = 77
        *(u64 *)(r1 + 0) = r2
        r3 = map[m][0]
        r0 = *(u64 *)(r3 + 8)
        exit";
    assert_eq!(run_src(src), 77);
}

// -------------------------------------------------- rejection explainer

/// Like `verify_err` but returns the whole error (with counterexample trace).
fn verify_err_full(src: &str) -> febpf::VerifyError {
    let mut vm = Vm::new(program(src)).unwrap();
    match vm.verify(Config::default()) {
        Ok(_) => panic!("expected verification to fail"),
        Err(e) => e,
    }
}

#[test]
fn trace_covers_path_to_failure() {
    let e = verify_err_full(
        "
        r0 = 1
        r1 = 2
        r2 = r3      ; r3 uninitialized
        exit",
    );
    assert_eq!(e.pc, 2);
    let t = e.trace.expect("rejection should carry a trace");
    assert_eq!(t.truncated, 0);
    let pcs: Vec<usize> = t.steps.iter().map(|s| s.pc).collect();
    assert_eq!(pcs, vec![0, 1, 2], "trace must walk entry -> failing insn");
    // the failing step reflects the state before the instruction
    assert!(t.steps[2].state.contains("r0=1"), "{:?}", t.steps[2]);
    assert!(t.steps[2].state.contains("r1=2"), "{:?}", t.steps[2]);
}

#[test]
fn trace_records_branch_decisions() {
    // failure only on the branch-taken path (r1 too large for ctx read)
    let src = "
        r0 = *(u32 *)(r1 + 0)
        if r0 > 10 goto bad
        r0 = 0
        exit
    bad:
        r2 = *(u64 *)(r1 + 8000)
        exit";
    let mut vm = Vm::new(program(src)).unwrap();
    let e = match vm.verify(Config {
        ctx_size: 64,
        ..Default::default()
    }) {
        Ok(_) => panic!("expected verification to fail"),
        Err(e) => e,
    };
    assert_eq!(e.pc, 4);
    let t = e.trace.expect("trace");
    let branch_step = t
        .steps
        .iter()
        .find(|s| s.pc == 1)
        .expect("conditional at insn 1 on the path");
    assert_eq!(
        branch_step.branch,
        Some((true, 4)),
        "the counterexample takes the branch to insn 4"
    );
    // path must not include the not-taken side (insns 2/3)
    assert!(t.steps.iter().all(|s| s.pc != 2 && s.pc != 3));
}

#[test]
fn trace_null_path_reaches_deref() {
    let e = verify_err_full(
        "
        .map m array 4 8 1
        w1 = 0
        *(u32 *)(r10 - 4) = r1
        r1 = map[m]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        r0 = *(u64 *)(r0)
        exit",
    );
    assert!(e.msg.contains("NULL"), "{e}");
    let t = e.trace.expect("trace");
    let last = t.steps.last().unwrap();
    assert_eq!(last.pc, e.pc);
    assert!(
        last.state.contains("map0_value_or_null"),
        "failing state should show the maybe-null pointer: {}",
        last.state
    );
}

#[test]
fn trace_long_path_is_truncated() {
    // bounded loop long enough to overflow the head+tail windows
    let e = verify_err_full(
        "
        r0 = 0
    loop:
        r0 += 1
        if r0 < 200 goto loop
        r1 = r9      ; r9 uninitialized: fails after a long path
        exit",
    );
    assert!(e.msg.contains("uninitialized"), "{e}");
    let t = e.trace.expect("trace");
    assert!(t.truncated > 0, "long path should be truncated");
    assert_eq!(t.steps.first().unwrap().pc, 0);
    assert_eq!(t.steps.last().unwrap().pc, e.pc);
}

// Assemble, verify (expecting failure), and render the explanation.
fn explain_err(src: &str) -> (febpf::VerifyError, String) {
    let prog = program(src);
    let mut vm = Vm::new(prog.clone()).unwrap();
    let e = match vm.verify(Config::default()) {
        Ok(_) => panic!("expected verification to fail"),
        Err(e) => e,
    };
    let text = febpf::verifier::render_trace(&prog.insns, &e);
    (e, text)
}

/// The rendered explanation must name the failing instruction and the cause.
#[test]
fn explain_null_deref_names_origin_and_branch() {
    let (e, text) = explain_err(
        "
        .map m array 4 8 1
        w1 = 0
        *(u32 *)(r10 - 4) = r1
        r1 = map[m]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        r6 = r0
        call ktime_get_ns
        if r0 > 7 goto bad
        r0 = 0
        exit
    bad:
        r0 = *(u64 *)(r6)
        exit",
    );
    assert_eq!(e.pc, 12);
    assert!(text.contains("->  12: r0 = *(u64 *)(r6)"), "{text}");
    assert!(text.contains("[taken]"), "{text}");
    assert!(text.contains("^ map value pointer may be NULL"), "{text}");
    assert!(
        text.contains("r6 may be NULL here: it was returned by map_lookup_elem at insn 6"),
        "{text}"
    );
}

#[test]
fn precision_backtracking_keeps_scalar_control_of_nullable_deref() {
    let error = verify_err(
        ".map m array 4 8 1
         w1 = 0
         *(u32 *)(r10 - 4) = r1
         r1 = map[m]
         r2 = r10
         r2 += -4
         call map_lookup_elem
         r6 = r0
         call ktime_get_ns
         r7 = r0
         if r7 != 0 goto safe
         goto join
        safe:
         r0 = 0
        join:
         if r7 == 0 goto bad
         if r6 == 0 goto out
         r0 = *(u64 *)(r6)
        out:
         r0 = 0
         exit
        bad:
         r0 = *(u64 *)(r6)
         exit",
    );
    assert!(
        error.contains("may be NULL"),
        "scalar-controlled bad path was pruned: {error}"
    );
}

#[test]
fn explain_stack_oob_names_insn() {
    let (e, text) = explain_err(
        "
        r1 = 5
        *(u64 *)(r10 - 516) = r1
        r0 = 0
        exit",
    );
    assert_eq!(e.pc, 1);
    assert!(text.contains("->   1: *(u64 *)(r10 - 516) = r1"), "{text}");
    assert!(text.contains("^ stack access out of bounds"), "{text}");
}

#[test]
fn explain_uninit_register_names_register() {
    let (e, text) = explain_err("r0 = 1\n r2 = r3\n exit");
    assert_eq!(e.pc, 1);
    assert!(text.contains("->   1: r2 = r3"), "{text}");
    assert!(
        text.contains("r3 is uninitialized: no instruction on this path writes it"),
        "{text}"
    );
}

#[test]
fn explain_long_path_shows_omission_marker() {
    let (e, text) = explain_err(
        "
        r0 = 0
    loop:
        r0 += 1
        if r0 < 200 goto loop
        r1 = r9
        exit",
    );
    assert!(e.msg.contains("uninitialized"), "{e}");
    assert!(text.contains("steps omitted"), "{text}");
    assert!(text.contains("r9 is uninitialized"), "{text}");
}

#[test]
fn explain_too_complex_has_trace() {
    let prog = program(
        "
        r0 = 0
    loop:
        r0 += 1
        if r0 != 0 goto loop
        exit",
    );
    let mut vm = Vm::new(prog.clone()).unwrap();
    let e = match vm.verify(Config {
        insn_budget: 10_000,
        ..Default::default()
    }) {
        Ok(_) => panic!("expected too-complex rejection"),
        Err(e) => e,
    };
    assert!(e.msg.contains("too complex"), "{e}");
    let t = e.trace.as_ref().expect("complexity rejection carries a trace");
    assert!(t.truncated > 0);
    // the tail window shows the loop body repeating
    let text = febpf::verifier::render_trace(&prog.insns, &e);
    assert!(text.contains("if r0 != 0 goto"), "{text}");
}

// ------------------------------------- operator-soundness regressions
// Found by the exhaustive small-width soundness harness (src/soundness.rs,
// docs/specs/operator-soundness.md). Each program routes its concretely
// executed path through code the buggy verifier pruned as dead, so the
// (correct) verdict must be a rejection of the violation on that path.

#[test]
fn jmp32_signed_compare_uses_s32_bounds() {
    // w0 = 0x80000000 is INT_MIN as s32, so `w0 s> 1` is FALSE and the
    // fall-through (which reads uninitialized r2) executes. The unsound
    // verifier compared the zero-extended 32-bit values (2^31 > 1), decided
    // the branch always-taken, and pruned the executed path. Kernel parity:
    // is_branch32_taken uses dedicated s32 bounds (kernel/bpf/verifier.c).
    let e = verify_err(
        "w0 = -2147483648
         if w0 s> 1 goto ok
         r0 = r2
        ok:
         exit",
    );
    assert!(e.contains("uninitialized"), "expected uninit rejection: {e}");
    // same shape for the other three signed 32-bit compares
    for cmp in ["s>=", "s<", "s<="] {
        let (bad_val, rhs) = match cmp {
            "s>=" => ("-2147483648", "0"),  // INT_MIN >= 0 is false
            "s<" => ("0x7fffffff", "0"),   // INT_MAX < 0 is false
            _ => ("0x7fffffff", "-1"),     // INT_MAX <= -1 is false
        };
        let src = format!(
            "w0 = {bad_val}
             if w0 {cmp} {rhs} goto ok
             r0 = r2
            ok:
             exit"
        );
        let e = verify_err(&src);
        assert!(e.contains("uninitialized"), "{cmp}: {e}");
    }
}

#[test]
fn jmp32_signed_refinement_keeps_sign_range() {
    // r1 is unknown-32-bit; on the `w1 s<= 5` path values with the 32-bit
    // sign bit set (e.g. 0x80000000) survive. The unsound refinement clamped
    // the range to [0, 5], so `w1 == 0x80000000` afterwards was decided
    // always-false and its target pruned even though it concretely executes.
    let e = verify_err_ctx(
        "r1 = *(u32 *)(r1 + 0)
         if w1 s<= 5 goto le
         r0 = 0
         exit
        le:
         if w1 == -2147483648 goto bad
         r0 = 0
         exit
        bad:
         r0 = r2
         exit",
        8,
    );
    assert!(e.contains("uninitialized"), "expected uninit rejection: {e}");
}

#[test]
fn jmp32_refines_unknown_u64_low_half_through_mask_and_mov32() {
    // The guard constrains only low32(r1). A 64-bit mask removes the unknown
    // upper half, after which the verifier can use the non-power-of-two bound.
    let mut vm = Vm::new(program(
        "r1 = *(u64 *)(r1 + 0)
         if w1 > 499 goto out
         r1 &= 511
         if r1 > 499 goto bad
        out:
         r0 = 0
         exit
        bad:
         r0 = r2
         exit",
    ))
    .unwrap();
    vm.verify(Config {
        ctx_size: 8,
        ..Default::default()
    })
    .expect("JMP32 fallthrough bound should survive a low mask");

    // Taken refinement is consumed by an ALU32 move, which zero-extends.
    let mut vm = Vm::new(program(
        "r1 = *(u64 *)(r1 + 0)
         if w1 < 8192 goto small
         r0 = 0
         exit
        small:
         w2 = w1
         if r2 >= 8192 goto bad
         r0 = 0
         exit
        bad:
         r0 = r3
         exit",
    ))
    .unwrap();
    vm.verify(Config {
        ctx_size: 8,
        ..Default::default()
    })
    .expect("JMP32 taken bound should feed an ALU32 move");

    // Signed refinement of an unknown-u64 source remains available to a
    // later signed JMP32 comparison.
    let mut vm = Vm::new(program(
        "r1 = *(u64 *)(r1 + 0)
         if w1 s< 100 goto small
         r0 = 0
         exit
        small:
         if w1 s>= 100 goto bad
         r0 = 0
         exit
        bad:
         r0 = r2
         exit",
    ))
    .unwrap();
    vm.verify(Config {
        ctx_size: 8,
        ..Default::default()
    })
    .expect("signed JMP32 bounds should remain in the s32 domain");
}

#[test]
fn jmp32_low_half_refinement_propagates_to_equal_copies_and_spills() {
    let mut vm = Vm::new(program(
        "r1 = *(u64 *)(r1 + 0)
         r2 = r1
         *(u64 *)(r10 - 8) = r1
         if w2 > 499 goto out
         r3 = *(u64 *)(r10 - 8)
         r3 &= 511
         if r3 > 499 goto bad
        out:
         r0 = 0
         exit
        bad:
         r0 = r4
         exit",
    ))
    .unwrap();
    vm.verify(Config {
        ctx_size: 8,
        ..Default::default()
    })
    .expect("scalar ids should carry low-half facts to copies and aligned spills");
}

#[test]
fn jmp32_refinement_propagates_through_aligned_u32_stack_reload() {
    let mut vm = Vm::new(program(
        "r1 = *(u64 *)(r1 + 0)
         *(u32 *)(r10 - 8) = r1
         r2 = *(u32 *)(r10 - 8)
         if w2 != 6 goto out
         r3 = *(u32 *)(r10 - 8)
         if w3 != 6 goto bad
        out:
         r0 = 0
         exit
        bad:
         r0 = r4
         exit",
    ))
    .unwrap();
    vm.verify(Config {
        ctx_size: 8,
        ..Default::default()
    })
    .expect("aligned u32 stack scalars should retain branch refinement");

    let e = verify_err_ctx(
        "r1 = *(u64 *)(r1 + 0)
         *(u32 *)(r10 - 8) = r1
         *(u8 *)(r10 - 7) = 0
         r2 = *(u32 *)(r10 - 8)
         if w2 == 6 goto bad
         r0 = 0
         exit
        bad:
         r0 = r3
         exit",
        8,
    );
    assert!(e.contains("uninitialized"), "overlap retained stale scalar facts: {e}");
}

#[test]
fn jmp32_refinement_never_constrains_unknown_upper_half() {
    let e = verify_err_ctx(
        "r1 = *(u64 *)(r1 + 0)
         if w1 > 499 goto out
         if r1 > 499 goto bad
        out:
         r0 = 0
         exit
        bad:
         r0 = r2
         exit",
        8,
    );
    assert!(e.contains("uninitialized"), "upper half was unsoundly bounded: {e}");

    // Equality of low halves says nothing about equality of full registers.
    let e = verify_err_ctx(
        "r1 = *(u64 *)(r1 + 0)
         r2 = 0x1_00000000 ll
         if w1 != w2 goto out
         if r1 != r2 goto bad
        out:
         r0 = 0
         exit
        bad:
         r0 = r3
         exit",
        8,
    );
    assert!(e.contains("uninitialized"), "JMP32 equality leaked to u64: {e}");

    // Signed low-half refinement cannot be consumed as an unsigned bound.
    let e = verify_err_ctx(
        "r1 = *(u64 *)(r1 + 0)
         if w1 s>= 100 goto out
         if w1 > 99 goto bad
        out:
         r0 = 0
         exit
        bad:
         r0 = r2
         exit",
        8,
    );
    assert!(e.contains("uninitialized"), "signed bound leaked to unsigned: {e}");
}

#[test]
fn alu32_signed_div_mod_fold_as_i32() {
    // 1 s/ -1 in 32 bits is -1 (0xffffffff); the unsound fold computed
    // 1 / 4294967295 = 0, so the verifier believed `w0 == -1` impossible
    // and pruned the concretely executed branch. Same for s% (1 s% -1 = 0).
    let e = verify_err(
        "w0 = 1
         w1 = -1
         w0 s/= w1
         if w0 == -1 goto bad
         r0 = 0
         exit
        bad:
         r0 = r2
         exit",
    );
    assert!(e.contains("uninitialized"), "sdiv32: {e}");
    let e = verify_err(
        "w0 = 1
         w1 = -1
         w0 s%= w1
         if w0 == 0 goto bad
         r0 = 0
         exit
        bad:
         r0 = r2
         exit",
    );
    assert!(e.contains("uninitialized"), "smod32: {e}");
}
