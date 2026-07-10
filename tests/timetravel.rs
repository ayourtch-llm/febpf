//! Time-travel debugging: snapshot/replay determinism and the reverse
//! debugger commands built on it.

use febpf::{asm, Program, Vm};

fn vm(src: &str) -> Vm {
    let a = asm::assemble(src).unwrap();
    Vm::new(Program {
        insns: a.insns,
        maps: a.maps,
    })
    .unwrap()
}

/// Exercises everything a snapshot must capture: array + hash map updates,
/// lazy map-value regions (lookup), prandom state, bpf-to-bpf call frames,
/// ctx writes, stack traffic and trace_printk.
const BUSY_SRC: &str = "
    .map arr array 4 8 4
    .map h hash 4 8 8
    r7 = r1             ; ctx pointer
    r6 = 10             ; loop counter
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
    r1 = map[arr]
    r2 = r10
    r2 += -4
    call map_lookup_elem
    if r0 == 0 goto skip
    r1 = *(u64 *)(r0)
    r2 = r6
    call mix
    *(u64 *)(r7 + 0) = r0
skip:
    r6 -= 1
    if r6 != 0 goto loop
    r1 = r7
    r2 = 4
    call trace_printk
    r0 = *(u64 *)(r7 + 0)
    exit
mix:
    r0 = r1
    r0 ^= r2
    r0 *= 31
    exit";

#[test]
fn replay_from_snapshot_matches_straight_run() {
    // Reference run: snapshots at every step.
    let mut ref_vm = vm(BUSY_SRC);
    let mut ref_ctx = vec![0u8; 16];
    let mut m = ref_vm.machine(&mut ref_ctx);
    let mut states = vec![m.snapshot()];
    let ret = loop {
        match m.step().unwrap() {
            Some(r0) => {
                states.push(m.snapshot()); // post-exit state
                break r0;
            }
            None => states.push(m.snapshot()),
        }
    };
    let total = states.len() as u64 - 1; // counts after each step
    assert!(total > 50, "want a busy program, got {total} steps");

    // Second machine: snapshot at k, run on to n, then rewind to the snapshot
    // and replay — every intermediate state must match the reference run.
    let (k, n) = (total / 3, 2 * total / 3);
    let mut vm2 = vm(BUSY_SRC);
    let mut ctx2 = vec![0u8; 16];
    let mut m2 = vm2.machine(&mut ctx2);
    m2.run_to_count(k).unwrap();
    let snap_k = m2.snapshot();
    assert_eq!(snap_k, states[k as usize], "state at k differs across VMs");

    m2.run_to_count(n).unwrap();
    assert_eq!(m2.snapshot(), states[n as usize]);

    // Rewind and replay to n: identical state again.
    m2.restore(&snap_k);
    assert_eq!(m2.snapshot(), states[k as usize]);
    m2.run_to_count(n).unwrap();
    assert_eq!(m2.snapshot(), states[n as usize], "replay diverged");

    // Replay through to completion: same r0, same final state.
    let r0 = m2.run_to_count(u64::MAX).unwrap();
    assert_eq!(r0, Some(ret));
    assert_eq!(m2.snapshot(), *states.last().unwrap());
}

#[test]
fn restore_rewinds_map_and_ctx_side_effects() {
    let mut v = vm(BUSY_SRC);
    let mut ctx = vec![0u8; 16];
    let mut m = v.machine(&mut ctx);
    let base = m.snapshot();
    m.run_to_count(u64::MAX).unwrap();
    assert_ne!(m.snapshot(), base, "program should have side effects");
    m.restore(&base);
    assert_eq!(m.snapshot(), base);
    drop(m);
    // Maps and printk are visibly reset on the VM as well.
    assert!(v.printk.is_empty());
    assert!(v.maps[1].iter_entries().is_empty()); // hash map emptied
    assert_eq!(ctx, vec![0u8; 16]);
}

#[test]
fn nondet_helper_calls_are_counted() {
    let mut v = vm("call ktime_get_ns\n r0 = 0\n exit");
    let mut ctx = [];
    let mut m = v.machine(&mut ctx);
    assert_eq!(m.nondet_calls, 0);
    m.run_to_count(u64::MAX).unwrap();
    assert_eq!(m.nondet_calls, 1);
}
