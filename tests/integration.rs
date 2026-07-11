use febpf::verifier::Config;
use febpf::{asm, Program, Vm};

fn program(src: &str) -> Program {
    let a = asm::assemble(src).expect("assembly failed");
    Program {
        insns: a.insns,
        maps: a.maps,
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
    let vm = Vm::new(program(src)).unwrap();
    let cfg = Config {
        ctx_size,
        ..Default::default()
    };
    match vm.verify(cfg) {
        Ok(_) => panic!("expected verification to fail"),
        Err(e) => e.to_string(),
    }
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
    let vm = Vm::new(program("r0 = *(u32 *)(r1 + 8)\n exit")).unwrap();
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
    let vm = Vm::new(program(
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
    let vm = Vm::new(program(src)).unwrap();
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
    let vm = Vm::new(program(src)).unwrap();
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
    let vm = Vm::new(prog.clone()).unwrap();
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
        r1 = *(u32 *)(r10 - 4)
        if r1 > 7 goto bad
        r0 = 0
        exit
    bad:
        r0 = *(u64 *)(r0)
        exit",
    );
    assert_eq!(e.pc, 11);
    assert!(text.contains("->  11: r0 = *(u64 *)(r0)"), "{text}");
    assert!(text.contains("[taken]"), "{text}");
    assert!(text.contains("^ map value pointer may be NULL"), "{text}");
    assert!(
        text.contains("r0 may be NULL here: it was returned by map_lookup_elem at insn 6"),
        "{text}"
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
    let vm = Vm::new(prog.clone()).unwrap();
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
