//! Integration tests for shareable replay files: a program recorded to a
//! `.febpf` blob, round-tripped through bytes, and replayed must reproduce a
//! *direct* run exactly — same r0, same final register file, same map state.
//! Also covers the determinism guard, preload reproduction, and clean
//! rejection of corrupt/short/version-mismatched files (no panics).

use febpf::interp::DEFAULT_PRANDOM_SEED;
use febpf::maps::Map;
use febpf::replay::{MapPreload, Outcome, Replay, TailCallProgram};
use febpf::{asm, Program, Vm};

fn prog(src: &str) -> Program {
    let a = asm::assemble(src).unwrap();
    Program {
        insns: a.insns,
        maps: a.maps,
        btf_ctx: None,
    }
}

/// Sorted key/value dump of every map, one inner Vec per map.
type MapDumps = Vec<Vec<(Vec<u8>, Vec<u8>)>>;

/// Run a VM to completion, returning (r0, final registers, sorted map dumps).
fn run_capture(vm: &mut Vm, ctx: &[u8]) -> (Option<u64>, [u64; 11], MapDumps) {
    let mut c = ctx.to_vec();
    let mut m = vm.machine(&mut c);
    let mut r0 = None;
    loop {
        match m.step() {
            Ok(Some(v)) => {
                r0 = Some(v);
                break;
            }
            Ok(None) => {}
            Err(_) => break,
        }
    }
    let regs = m.regs;
    drop(m);
    let maps = vm
        .maps
        .iter()
        .map(|mp: &Map| {
            let mut e = mp.iter_entries();
            e.sort();
            e
        })
        .collect();
    (r0, regs, maps)
}

/// Exercises prandom + array + hash map traffic, so the captured state is a
/// meaningful fingerprint of the run.
const BUSY: &str = "
    .map arr array 4 8 4
    .map h hash 4 8 8
    r6 = 5
loop:
    r1 = r6
    r1 &= 3
    *(u32 *)(r10 - 4) = r1
    call get_prandom_u32
    *(u64 *)(r10 - 16) = r0
    r1 = map[arr]
    r2 = r10
    r2 += -4
    r3 = r10
    r3 += -16
    r4 = 0
    call map_update_elem
    r1 = map[h]
    r2 = r10
    r2 += -4
    r3 = r10
    r3 += -16
    r4 = 0
    call map_update_elem
    r6 -= 1
    if r6 != 0 goto loop
    r0 = 0
    exit
";

#[test]
fn replay_reproduces_direct_run_exactly() {
    let p = prog(BUSY);
    let ctx = vec![0u8; 32];

    // Direct run.
    let mut direct = Vm::new(p.clone()).unwrap();
    let (d_r0, d_regs, d_maps) = run_capture(&mut direct, &ctx);

    // Record -> bytes -> parse -> rebuild -> run.
    let rec = Replay::record(&p, ctx.clone(), DEFAULT_PRANDOM_SEED, None, Vec::new()).unwrap();
    assert_eq!(rec.outcome, Some(Outcome::Exit(d_r0.unwrap())));
    let bytes = rec.to_bytes();
    let parsed = Replay::from_bytes(&bytes).unwrap();
    let (mut vm, rctx) = parsed.build_vm().unwrap();
    let (r_r0, r_regs, r_maps) = run_capture(&mut vm, &rctx);

    assert_eq!(d_r0, r_r0, "r0 must match");
    assert_eq!(d_regs, r_regs, "final register file must match");
    assert_eq!(d_maps, r_maps, "final map state must match");
}

#[test]
fn replay_preserves_ctx_dependent_result() {
    // r0 = first 8 bytes of ctx: a run whose result depends on the ctx bytes,
    // so we know the recorded ctx actually round-trips.
    let p = prog("
        r0 = *(u64 *)(r1 + 0)
        exit
    ");
    let ctx = 0x1122334455667788u64.to_le_bytes().to_vec();
    let rec = Replay::record(&p, ctx, DEFAULT_PRANDOM_SEED, Some(1), Vec::new()).unwrap();
    let parsed = Replay::from_bytes(&rec.to_bytes()).unwrap();
    let (mut vm, rctx) = parsed.build_vm().unwrap();
    assert_eq!(run_capture(&mut vm, &rctx).0, Some(0x1122334455667788));
}

#[test]
fn xdp_packet_round_trips_and_replays() {
    let p = prog("
        r2 = *(u32 *)(r1 + 0)
        r3 = *(u32 *)(r1 + 4)
        r4 = r2
        r4 += 2
        if r4 > r3 goto short
        r0 = *(u16 *)(r2 + 0)
        exit
    short:
        r0 = 0
        exit
    ");
    let packet = vec![0x34, 0x12, 0xaa];
    let rec = Replay::record_xdp(
        &p,
        packet.clone(),
        DEFAULT_PRANDOM_SEED,
        Some(5),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(rec.packet, Some(packet));
    assert_eq!(rec.outcome, Some(Outcome::Exit(0x1234)));

    let parsed = Replay::from_bytes(&rec.to_bytes()).unwrap();
    assert_eq!(parsed, rec);
    let (mut vm, mut ctx) = parsed.build_vm().unwrap();
    assert_eq!(vm.run(&mut ctx).unwrap(), 0x1234);
}

#[test]
fn preload_round_trips_and_reproduces() {
    // Look up preloaded hash key 7 and return its value.
    let p = prog("
        .map h hash 4 8 8
        *(u32 *)(r10 - 4) = 7
        r1 = map[h]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 == 0 goto miss
        r0 = *(u64 *)(r0 + 0)
        exit
    miss:
        r0 = 0xdead
        exit
    ");
    let preload = vec![MapPreload {
        map_index: 0,
        entries: vec![(7u32.to_le_bytes().to_vec(), 0xcafef00du64.to_le_bytes().to_vec())],
    }];
    let rec = Replay::record(&p, vec![0u8; 8], DEFAULT_PRANDOM_SEED, None, preload).unwrap();
    assert_eq!(rec.outcome, Some(Outcome::Exit(0xcafef00d)));

    let parsed = Replay::from_bytes(&rec.to_bytes()).unwrap();
    assert_eq!(parsed.preload.len(), 1);
    let (mut vm, rctx) = parsed.build_vm().unwrap();
    assert_eq!(run_capture(&mut vm, &rctx).0, Some(0xcafef00d));
}

#[test]
fn corrupt_and_short_files_are_rejected_cleanly() {
    let rec = Replay::record(&prog(BUSY), vec![0u8; 8], DEFAULT_PRANDOM_SEED, None, Vec::new())
        .unwrap();
    let bytes = rec.to_bytes();

    // Random junk and short buffers: Err, never panic.
    assert!(Replay::from_bytes(b"").is_err());
    assert!(Replay::from_bytes(b"FEBPFRPL").is_err());
    assert!(Replay::from_bytes(b"garbage!!\x01\x00trailing").is_err());
    for cut in 0..bytes.len() {
        let _ = Replay::from_bytes(&bytes[..cut]); // must not panic
    }

    // A single flipped byte anywhere must not panic (may or may not error).
    for i in 10..bytes.len() {
        let mut b = bytes.clone();
        b[i] ^= 0xff;
        let _ = Replay::from_bytes(&b);
    }
}

#[test]
fn version_mismatch_is_reported() {
    let rec = Replay::record(&prog(BUSY), vec![], DEFAULT_PRANDOM_SEED, None, Vec::new()).unwrap();
    let mut bytes = rec.to_bytes();
    bytes[8] = 0xfe;
    bytes[9] = 0xca;
    let err = Replay::from_bytes(&bytes).unwrap_err();
    assert!(err.contains("unsupported replay format version"), "{err}");
}

#[test]
fn tail_call_bundle_round_trips_and_replays() {
    let entry = prog(
        ".map progs prog_array 4 4 1
         r2 = map[progs]
         r3 = 0
         call tail_call
         r0 = 7
         exit",
    );
    let target = prog(
        ".map progs prog_array 4 4 1
         r0 = 42
         exit",
    );
    let replay = Replay::record_tail_calls(
        &entry,
        vec![TailCallProgram {
            map_name: "progs".into(),
            index: 0,
            insns: target.insns,
        }],
        Vec::new(),
        DEFAULT_PRANDOM_SEED,
        Some(3),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(replay.outcome, Some(Outcome::Exit(42)));
    let parsed = Replay::from_bytes(&replay.to_bytes()).unwrap();
    assert_eq!(parsed, replay);
    let (mut vm, mut ctx) = parsed.build_vm().unwrap();
    assert_eq!(vm.run(&mut ctx).unwrap(), 42);
}
