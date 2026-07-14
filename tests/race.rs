//! Behavioral tests for the deterministic concurrency race explorer.
//!
//! (i)   a genuine lost-update RMW (lookup, load, +1, update) run as 2 instances
//!       is flagged as a RACE with a witnessing interleaving;
//! (ii)  the same counter done with an atomic add on the same key is RACE-FREE
//!       across all explored schedules;
//! (iii) determinism: the same --seed reproduces the identical racing
//!       interleaving bit-for-bit, and a --schedule choice vector replays it.

use febpf::race::{
    explore, explore_programs, explore_xdp_programs, render_report, replay_programs,
    replay_schedule, replay_xdp_programs, ExploreConfig, ExploreProgramsConfig, InstanceResult,
    RaceProgram, RaceXdpProgram,
};
use febpf::{asm, Program, XdpFrame};

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

/// A distinct non-atomic worker that adds ten to the same shared counter.
const RMW_TEN: &str = r#"
        .map counter array 4 8 1
        r0 = 0
        *(u32 *)(r10 - 4) = r0
        r1 = map[counter]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 == 0 goto out
        r6 = *(u64 *)(r0 + 0)
        r6 += 10
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

/// A distinct atomic worker that adds ten to the same shared counter.
const ATOMIC_TEN: &str = r#"
        .map counter array 4 8 1
        r0 = 0
        *(u32 *)(r10 - 4) = r0
        r1 = map[counter]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 == 0 goto out
        r1 = 10
        lock *(u64 *)(r0 + 0) += r1
out:
        r0 = 0
        exit
"#;

const XDP_PACKET_RMW: &str = r#"
        .map counter array 4 8 1
        r7 = *(u32 *)(r1 + 0)
        r8 = *(u32 *)(r1 + 4)
        r9 = r7
        r9 += 1
        if r9 > r8 goto out
        r6 = *(u8 *)(r7 + 0)
        r0 = 0
        *(u32 *)(r10 - 4) = r0
        r1 = map[counter]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 == 0 goto out
        r8 = *(u64 *)(r0 + 0)
        r8 += r6
        *(u64 *)(r10 - 16) = r8
        r1 = map[counter]
        r2 = r10
        r2 += -4
        r3 = r10
        r3 += -16
        r4 = 0
        call map_update_elem
out:
        r0 = 2
        exit
"#;

const XDP_ATOMIC_OBSERVE: &str = r#"
        .map counter array 4 8 1
        r7 = *(u32 *)(r1 + 0)
        r8 = *(u32 *)(r1 + 4)
        r9 = r7
        r9 += 1
        if r9 > r8 goto out
        r0 = 0
        *(u32 *)(r10 - 4) = r0
        r1 = map[counter]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 == 0 goto out
        r1 = 1
        lock *(u64 *)(r0 + 0) += r1
        r6 = *(u64 *)(r0 + 0)
        *(u8 *)(r7 + 0) = r6
out:
        r0 = 2
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

#[test]
fn heterogeneous_workers_expose_a_cross_program_lost_update() {
    let add_one = prog(RMW);
    let add_ten = prog(RMW_TEN);
    let ctx = [0u8; 16];
    let programs = [
        RaceProgram {
            name: "add-one",
            program: &add_one,
            ctx: &ctx,
        },
        RaceProgram {
            name: "add-ten",
            program: &add_ten,
            ctx: &ctx,
        },
    ];
    let rep = explore_programs(
        &programs,
        &ExploreProgramsConfig {
            schedules: 10_000,
            seed: None,
        },
    )
    .unwrap();

    assert!(rep.is_race());
    assert!(rep.exhausted);
    assert_eq!(rep.programs, ["add-one", "add-ten"]);
    let finals: Vec<u64> = rep
        .groups
        .iter()
        .map(|g| counter_value(&g.witness.outcome.maps[0].entries))
        .collect();
    assert!(finals.contains(&11), "serial execution preserves both writes");
    assert!(
        finals.contains(&1) || finals.contains(&10),
        "an interleaving must lose one heterogeneous write: {finals:?}"
    );
    let witness = rep.lost_update_witness.as_ref().unwrap();
    assert!(witness.trace.iter().any(|step| step.program == 0));
    assert!(witness.trace.iter().any(|step| step.program == 1));

    let rendered = render_report(&rep, "not-a-single-program.s", false);
    assert!(rendered.contains("inst0[add-one]"));
    assert!(rendered.contains("inst1[add-ten]"));
    assert!(rendered.contains("replay with race::replay_programs"));
    assert!(!rendered.contains("febpf race not-a-single-program.s"));
}

#[test]
fn heterogeneous_atomic_workers_are_race_free() {
    let add_one = prog(ATOMIC);
    let add_ten = prog(ATOMIC_TEN);
    let ctx = [0u8; 16];
    let programs = [
        RaceProgram {
            name: "atomic-one",
            program: &add_one,
            ctx: &ctx,
        },
        RaceProgram {
            name: "atomic-ten",
            program: &add_ten,
            ctx: &ctx,
        },
    ];
    let rep = explore_programs(
        &programs,
        &ExploreProgramsConfig {
            schedules: 10_000,
            seed: None,
        },
    )
    .unwrap();

    assert!(!rep.is_race());
    assert!(rep.exhausted);
    assert_eq!(rep.groups.len(), 1);
    assert_eq!(counter_value(&rep.groups[0].witness.outcome.maps[0].entries), 11);
}

#[test]
fn heterogeneous_schedule_replay_is_exact() {
    let add_one = prog(RMW);
    let add_ten = prog(RMW_TEN);
    let ctx = [0u8; 16];
    let programs = [
        RaceProgram {
            name: "add-one",
            program: &add_one,
            ctx: &ctx,
        },
        RaceProgram {
            name: "add-ten",
            program: &add_ten,
            ctx: &ctx,
        },
    ];
    let path = vec![0, 0, 1, 1, 0, 0];
    let run = replay_programs(&programs, path.clone()).unwrap();
    let again = replay_programs(&programs, path.clone()).unwrap();

    assert_eq!(run.choices, path);
    assert_eq!(run.trace, again.trace);
    assert_eq!(run.outcome, again.outcome);
    assert_eq!(run.lost_updates, again.lost_updates);
    assert!(matches!(counter_value(&run.outcome.maps[0].entries), 1 | 10));
}

#[test]
fn heterogeneous_program_contract_is_strict() {
    let add_one = prog(RMW);
    let different_map = prog(&RMW_TEN.replace("array 4 8 1", "array 4 8 2"));
    let short_ctx = [0u8; 8];
    let long_ctx = [0u8; 16];

    let empty = explore_programs(
        &[],
        &ExploreProgramsConfig {
            schedules: 1,
            seed: None,
        },
    )
    .err()
    .expect("an empty program set must be rejected");
    assert!(empty.contains("empty"));

    let unequal_contexts = [
        RaceProgram {
            name: "short",
            program: &add_one,
            ctx: &short_ctx,
        },
        RaceProgram {
            name: "long",
            program: &add_one,
            ctx: &long_ctx,
        },
    ];
    let err = replay_programs(&unequal_contexts, vec![]).unwrap_err();
    assert!(err.contains("equal context lengths"));

    let incompatible_maps = [
        RaceProgram {
            name: "one-entry",
            program: &add_one,
            ctx: &long_ctx,
        },
        RaceProgram {
            name: "two-entries",
            program: &different_map,
            ctx: &long_ctx,
        },
    ];
    let err = replay_programs(&incompatible_maps, vec![]).unwrap_err();
    assert!(err.contains("identical map definitions"));
}

#[test]
fn xdp_frames_are_private_while_packet_driven_map_races_are_shared() {
    let program = prog(XDP_PACKET_RMW);
    let one = XdpFrame::new(&[1]);
    let ten = XdpFrame::new(&[10]);
    let programs = [
        RaceXdpProgram {
            name: "packet-one",
            program: &program,
            frame: &one,
        },
        RaceXdpProgram {
            name: "packet-ten",
            program: &program,
            frame: &ten,
        },
    ];
    let report = explore_xdp_programs(
        &programs,
        &ExploreProgramsConfig {
            schedules: 10_000,
            seed: None,
        },
    )
    .unwrap();

    assert!(report.is_race());
    assert!(report.exhausted);
    let finals: Vec<_> = report
        .groups
        .iter()
        .map(|group| counter_value(&group.witness.outcome.maps[0].entries))
        .collect();
    assert!(finals.contains(&11));
    assert!(finals.contains(&1) || finals.contains(&10));
    for group in &report.groups {
        assert_eq!(group.witness.outcome.invocations[0].packet.as_ref().unwrap().storage, [1]);
        assert_eq!(group.witness.outcome.invocations[1].packet.as_ref().unwrap().storage, [10]);
    }

    let path = report.groups[0].witness.choices.clone();
    let replay = replay_xdp_programs(&programs, path).unwrap();
    assert_eq!(replay.outcome, report.groups[0].witness.outcome);
}

#[test]
fn xdp_packet_outputs_are_part_of_schedule_outcomes() {
    let program = prog(XDP_ATOMIC_OBSERVE);
    let first = XdpFrame::new(&[0]);
    let second = XdpFrame::new(&[0]);
    let programs = [
        RaceXdpProgram {
            name: "observer-a",
            program: &program,
            frame: &first,
        },
        RaceXdpProgram {
            name: "observer-b",
            program: &program,
            frame: &second,
        },
    ];
    let report = explore_xdp_programs(
        &programs,
        &ExploreProgramsConfig {
            schedules: 10_000,
            seed: None,
        },
    )
    .unwrap();

    assert!(report.is_race());
    assert!(report.exhausted);
    assert!(report.lost_update_witness.is_none());
    assert!(report.groups.len() > 1);
    assert!(report.groups.iter().all(|group| {
        counter_value(&group.witness.outcome.maps[0].entries) == 2
            && group.witness.outcome.results == [InstanceResult::Exit(2), InstanceResult::Exit(2)]
    }));
    let packets: Vec<_> = report
        .groups
        .iter()
        .map(|group| {
            group
                .witness
                .outcome
                .invocations
                .iter()
                .map(|state| state.packet.as_ref().unwrap().storage[0])
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(packets.iter().any(|values| values == &[1, 2]));
    assert!(packets.iter().any(|values| values == &[2, 2]));
}

#[test]
fn xdp_race_contract_rejects_capacity_mismatch_and_bad_programs() {
    let valid = prog(XDP_PACKET_RMW);
    let invalid = prog("r0 = *(u8 *)(r1 + 0)\nexit");
    let short = XdpFrame::new(&[1]);
    let long = XdpFrame::new(&[1, 2]);

    let mismatch = [
        RaceXdpProgram {
            name: "short",
            program: &valid,
            frame: &short,
        },
        RaceXdpProgram {
            name: "long",
            program: &valid,
            frame: &long,
        },
    ];
    let error = replay_xdp_programs(&mismatch, vec![]).unwrap_err();
    assert!(error.contains("equal storage capacities"));

    let unverifiable = [RaceXdpProgram {
        name: "invalid",
        program: &invalid,
        frame: &short,
    }];
    let error = replay_xdp_programs(&unverifiable, vec![]).unwrap_err();
    assert!(error.contains("failed verification"));
}
