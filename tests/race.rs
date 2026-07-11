//! Behavioral tests for the deterministic concurrency race explorer.
//!
//! (i)   a genuine lost-update RMW (lookup, load, +1, update) run as 2 instances
//!       is flagged as a RACE with a witnessing interleaving;
//! (ii)  the same counter done with an atomic add on the same key is RACE-FREE
//!       across all explored schedules;
//! (iii) determinism: the same --seed reproduces the identical racing
//!       interleaving bit-for-bit, and a --schedule choice vector replays it.

use febpf::race::{explore, replay_schedule, ExploreConfig, InstanceResult};
use febpf::{asm, Program};

fn prog(src: &str) -> Program {
    let a = asm::assemble(src).unwrap();
    Program {
        insns: a.insns,
        maps: a.maps,
        btf_ctx: None,
    }
}

/// Non-atomic read-modify-write of a shared array-map counter.
const RMW: &str = r#"
        .map counter array 4 8 1
        r0 = 0
        *(u32 *)(r10 - 4) = r0
        r1 = map[counter]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 == 0 goto out
        r6 = *(u64 *)(r0 + 0)
        r6 += 1
        *(u64 *)(r10 - 16) = r6
        r1 = map[counter]
        r2 = r10
        r2 += -4
        r3 = r10
        r3 += -16
        r4 = 0
        call map_update_elem
out:
        r0 = 0
        exit
"#;

/// Atomic increment of the same shared counter.
const ATOMIC: &str = r#"
        .map counter array 4 8 1
        r0 = 0
        *(u32 *)(r10 - 4) = r0
        r1 = map[counter]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 == 0 goto out
        r1 = 1
        lock *(u64 *)(r0 + 0) += r1
out:
        r0 = 0
        exit
"#;

fn counter_value(entries: &[(Vec<u8>, Vec<u8>)]) -> u64 {
    let v = &entries[0].1;
    u64::from_le_bytes(v[..8].try_into().unwrap())
}

#[test]
fn lost_update_is_flagged_as_race() {
    let p = prog(RMW);
    let cfg = ExploreConfig {
        procs: 2,
        schedules: 10_000,
        seed: None,
    };
    let rep = explore(&p, &[0u8; 16], &cfg).unwrap();

    assert!(rep.is_race(), "racy RMW must be flagged as a race");
    assert!(rep.exhausted, "small state space should enumerate fully");

    // Outcome divergence: some schedule commits 2 (correct), some commits 1
    // (lost update).
    let finals: Vec<u64> = rep
        .groups
        .iter()
        .map(|g| counter_value(&g.witness.outcome.maps[0].entries))
        .collect();
    assert!(finals.contains(&2), "a serial schedule reaches 2: {finals:?}");
    assert!(finals.contains(&1), "a racy schedule loses an update -> 1: {finals:?}");

    // The lost-update anti-pattern is named, with a witnessing interleaving.
    let lu = rep
        .lost_update_witness
        .expect("lost-update pattern must be witnessed");
    assert_eq!(lu.lost_updates.len(), 1);
    let occ = &lu.lost_updates[0];
    assert_ne!(occ.reader, occ.clobbered_by);
    // Ordering invariant: read < other's write < overwrite.
    assert!(occ.read_step < occ.other_write_step);
    assert!(occ.other_write_step < occ.overwrite_step);
    // The witnessing schedule really loses an update (final == 1).
    assert_eq!(counter_value(&lu.outcome.maps[0].entries), 1);
}

#[test]
fn atomic_counter_is_race_free() {
    let p = prog(ATOMIC);
    let cfg = ExploreConfig {
        procs: 2,
        schedules: 10_000,
        seed: None,
    };
    let rep = explore(&p, &[0u8; 16], &cfg).unwrap();

    assert!(!rep.is_race(), "an atomic counter must be race-free");
    assert!(rep.exhausted);
    assert_eq!(rep.groups.len(), 1, "every schedule commits the same state");
    assert!(rep.lost_update_witness.is_none());
    // Two atomic increments always land: final == 2 regardless of interleaving.
    assert_eq!(counter_value(&rep.groups[0].witness.outcome.maps[0].entries), 2);
}

#[test]
fn three_instances_still_race_free_with_atomics() {
    let p = prog(ATOMIC);
    let cfg = ExploreConfig {
        procs: 3,
        schedules: 100_000,
        seed: None,
    };
    let rep = explore(&p, &[0u8; 16], &cfg).unwrap();
    assert!(!rep.is_race());
    assert_eq!(counter_value(&rep.groups[0].witness.outcome.maps[0].entries), 3);
}

#[test]
fn seeded_random_is_deterministic() {
    let p = prog(RMW);
    let mk = || ExploreConfig {
        procs: 2,
        schedules: 50,
        seed: Some(1234),
    };
    let a = explore(&p, &[0u8; 16], &mk()).unwrap();
    let b = explore(&p, &[0u8; 16], &mk()).unwrap();

    assert!(a.is_race() && b.is_race());
    // Same seed -> identical witnessing interleavings, bit for bit.
    let choices = |r: &febpf::race::RaceReport| -> Vec<Vec<usize>> {
        r.groups.iter().map(|g| g.witness.choices.clone()).collect()
    };
    assert_eq!(choices(&a), choices(&b));
    let lu_choices = |r: &febpf::race::RaceReport| {
        r.lost_update_witness.as_ref().map(|w| w.choices.clone())
    };
    assert_eq!(lu_choices(&a), lu_choices(&b));
}

#[test]
fn schedule_replay_reproduces_the_losing_interleaving() {
    let p = prog(RMW);
    // Interleave both instances' read before either write: a guaranteed loss.
    // choices index into the runnable set at each map op:
    //  0: inst0 lookup, 0: inst0 load, 1: inst1 lookup, 1: inst1 load,
    //  0: inst0 update, 0: inst1 update
    let path = vec![0, 0, 1, 1, 0, 0];
    let run = replay_schedule(&p, &[0u8; 16], 2, path.clone()).unwrap();

    assert_eq!(run.choices, path, "the recipe is followed verbatim");
    assert_eq!(
        counter_value(&run.outcome.maps[0].entries),
        1,
        "this interleaving loses one update"
    );
    assert_eq!(run.lost_updates.len(), 1);
    for r in &run.outcome.results {
        assert_eq!(*r, InstanceResult::Exit(0));
    }

    // Replaying again yields an identical run.
    let again = replay_schedule(&p, &[0u8; 16], 2, path).unwrap();
    assert_eq!(again.trace, run.trace);
    assert_eq!(again.outcome, run.outcome);
}

#[test]
fn serial_schedule_reaches_two() {
    let p = prog(RMW);
    // inst0 runs fully (lookup, load, update) then inst1: no interleaving.
    let run = replay_schedule(&p, &[0u8; 16], 2, vec![0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(counter_value(&run.outcome.maps[0].entries), 2);
    assert!(run.lost_updates.is_empty());
}
