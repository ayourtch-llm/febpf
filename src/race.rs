//! Deterministic concurrency race explorer for eBPF programs that share maps.
//!
//! febpf's interpreter is fully deterministic and single-threaded-simulated, so
//! we can model concurrent invocations of one or more programs sharing one map set,
//! drive a deterministic scheduler that interleaves them at map-visible
//! operations, systematically (or seeded-randomly) explore schedules, and flag
//! when different schedules commit different map state — a race.
//!
//! See `docs/specs/race-explorer.md` for the model, granularity rationale and
//! race definition. The scheduler preempts only at *map-visible* operations
//! (map helper calls, atomics, and loads/stores through a looked-up pointer);
//! between them an instance's purely instance-local work runs sequentially.

use crate::execution::InvocationState;
use crate::interp::{InstanceState, Machine, MapOp, MapOpKind, MapStep, Vm};
use crate::{Program, XdpFrame};
use std::collections::HashMap;

/// Per-instance instruction cap for one schedule (guards against a program
/// that loops forever inside one instance).
const PER_INSTANCE_INSN_LIMIT: u64 = 5_000_000;

// -- outcome / trace types ---------------------------------------------------

/// How one instance's program ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstanceResult {
    Exit(u64),
    Error(String),
}

/// The observable outcome of a single schedule: the final committed state of
/// every map (canonicalised: entries sorted by key) plus each instance's
/// result. Two schedules with different `Outcome`s are a race.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub maps: Vec<MapState>,
    pub results: Vec<InstanceResult>,
    /// Final provider-visible context/packet/output state for each instance.
    pub invocations: Vec<InvocationState>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapState {
    pub name: String,
    /// (key, value) pairs, sorted by key.
    pub entries: Vec<(Vec<u8>, Vec<u8>)>,
}

/// One recorded step of an interleaving: which instance ran and the
/// map-visible op it performed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceStep {
    pub instance: usize,
    /// Index of the heterogeneous program assigned to this instance.
    pub program: usize,
    pub op: MapOpKind,
    pub pc: usize,
    /// The `(map, key)` cell touched, when known.
    pub cell: Option<(usize, Vec<u8>)>,
    pub detail: String,
}

/// One logical invocation in a heterogeneous race exploration.
///
/// Programs must have identical map definitions and equally sized contexts.
/// Context bytes may differ between instances. The explorer does not verify
/// programs; callers should verify each program under the intended execution
/// environment before treating exploration results as meaningful.
pub struct RaceProgram<'a> {
    pub name: &'a str,
    pub program: &'a Program,
    pub ctx: &'a [u8],
}

/// One verified XDP invocation in heterogeneous race exploration.
pub struct RaceXdpProgram<'a> {
    pub name: &'a str,
    pub program: &'a Program,
    pub frame: &'a XdpFrame,
}

/// A witnessed lost-update / stale read-modify-write: instance `reader` read a
/// value cell, `clobbered_by` wrote it, then `reader` overwrote it with a value
/// computed from its stale read — losing `clobbered_by`'s write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LostUpdate {
    pub map: usize,
    pub key: Vec<u8>,
    pub reader: usize,
    pub clobbered_by: usize,
    pub read_step: usize,
    pub other_write_step: usize,
    pub overwrite_step: usize,
}

/// The result of running one full schedule to completion.
#[derive(Clone, Debug)]
pub struct ScheduleRun {
    /// The scheduler's choice at each decision point (index into the runnable
    /// set). Replaying with this exact vector reproduces the interleaving.
    pub choices: Vec<usize>,
    pub trace: Vec<TraceStep>,
    pub outcome: Outcome,
    pub lost_updates: Vec<LostUpdate>,
}

// -- schedulers --------------------------------------------------------------

/// Decides which of the currently-runnable instances takes the next
/// map-visible op. Returns an index into `runnable`.
trait Chooser {
    fn choose(&mut self, runnable: &[usize]) -> usize;
}

/// Follows a fixed choice vector (used both for `--schedule` replay and, with a
/// recorded fan-out, for systematic DFS enumeration). Falls back to 0 once the
/// prefix is exhausted.
struct PathChooser {
    path: Vec<usize>,
    idx: usize,
    fanout: Vec<usize>,
}

impl PathChooser {
    fn new(path: Vec<usize>) -> PathChooser {
        PathChooser {
            path,
            idx: 0,
            fanout: Vec::new(),
        }
    }
}

impl Chooser for PathChooser {
    fn choose(&mut self, runnable: &[usize]) -> usize {
        let k = runnable.len();
        let pos = self.path.get(self.idx).copied().unwrap_or(0).min(k - 1);
        self.fanout.push(k);
        self.idx += 1;
        pos
    }
}

/// Seeded xorshift64* random scheduler.
struct RandomChooser {
    state: u64,
}

impl RandomChooser {
    fn new(seed: u64) -> RandomChooser {
        RandomChooser {
            // avoid the zero fixed point
            state: seed ^ 0x9e3779b97f4a7c15,
        }
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

impl Chooser for RandomChooser {
    fn choose(&mut self, runnable: &[usize]) -> usize {
        (self.next_u64() % runnable.len() as u64) as usize
    }
}

// -- lost-update detector ----------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    Write,
    Atomic,
}

#[derive(Default, Clone)]
struct CellState {
    /// Per instance: (step of its last unmatched Read, first foreign write
    /// since that read as (writer, step)).
    last_read: HashMap<usize, usize>,
    foreign: HashMap<usize, (usize, usize)>,
}

/// Tracks read/write/atomic events per `(map, key)` cell across a schedule and
/// flags lost-update patterns as they complete.
struct HazardLog {
    cells: HashMap<(usize, Vec<u8>), CellState>,
    found: Vec<LostUpdate>,
}

impl HazardLog {
    fn new() -> HazardLog {
        HazardLog {
            cells: HashMap::new(),
            found: Vec::new(),
        }
    }

    fn record(&mut self, inst: usize, cell: (usize, Vec<u8>), access: Access, step: usize) {
        let st = self.cells.entry(cell.clone()).or_default();
        match access {
            Access::Read => {
                st.last_read.insert(inst, step);
                st.foreign.remove(&inst);
            }
            Access::Write => {
                // Does this write complete a lost-update by `inst`?
                if let (Some(&rstep), Some(&(bwriter, bstep))) =
                    (st.last_read.get(&inst), st.foreign.get(&inst))
                {
                    self.found.push(LostUpdate {
                        map: cell.0,
                        key: cell.1.clone(),
                        reader: inst,
                        clobbered_by: bwriter,
                        read_step: rstep,
                        other_write_step: bstep,
                        overwrite_step: step,
                    });
                }
                st.last_read.remove(&inst);
                st.foreign.remove(&inst);
                Self::mark_foreign(st, inst, step);
            }
            Access::Atomic => {
                // An atomic RMW is safe for `inst` itself, but still a write
                // that other instances can lose against.
                st.last_read.remove(&inst);
                st.foreign.remove(&inst);
                Self::mark_foreign(st, inst, step);
            }
        }
    }

    /// A write by `writer` becomes the first foreign write for every other
    /// instance that currently holds an unmatched read.
    fn mark_foreign(st: &mut CellState, writer: usize, step: usize) {
        let readers: Vec<usize> = st.last_read.keys().copied().collect();
        for r in readers {
            if r != writer {
                st.foreign.entry(r).or_insert((writer, step));
            }
        }
    }
}

// -- single-schedule executor ------------------------------------------------

/// Run one full schedule of heterogeneous program instances, letting
/// `chooser` decide the interleaving at each map-visible op.
fn run_program_schedule(
    programs: &[RaceProgram<'_>],
    chooser: &mut dyn Chooser,
) -> Result<ScheduleRun, String> {
    let first = programs.first().ok_or("race program set is empty")?;
    let ctx_len = first.ctx.len();
    if programs.iter().any(|program| program.ctx.len() != ctx_len) {
        return Err("race programs must use equal context lengths".into());
    }
    let mut vm = Vm::new(first.program.clone())?;
    let mut program_ids = vec![0];
    for program in programs.iter().skip(1) {
        program_ids.push(vm.register_race_program(program.program, Vec::new())?);
    }
    vm.insn_limit = PER_INSTANCE_INSN_LIMIT;
    let instances: Vec<InstanceState> = programs
        .iter()
        .zip(program_ids)
        .map(|(program, id)| InstanceState::new_for_program(program.ctx, id))
        .collect();
    let mut scratch = first.ctx.to_vec();
    let machine = vm.machine(&mut scratch);
    execute_schedule(machine, instances, chooser)
}

fn run_xdp_program_schedule(
    programs: &[RaceXdpProgram<'_>],
    chooser: &mut dyn Chooser,
) -> Result<ScheduleRun, String> {
    let first = programs.first().ok_or("race program set is empty")?;
    let capacity = first.frame.capacity();
    if programs
        .iter()
        .any(|program| program.frame.capacity() != capacity)
    {
        return Err("race XDP frames must use equal storage capacities".into());
    }

    let config = crate::verifier::Config {
        ctx_size: 24,
        ctx_writable: false,
        xdp: true,
        ..crate::verifier::Config::default()
    };
    let mut vm = Vm::new(first.program.clone())?;
    vm.verify(config.clone()).map_err(|error| {
        format!(
            "race XDP program '{}' failed verification: {error}",
            first.name
        )
    })?;
    let mut program_ids = vec![0];
    for program in programs.iter().skip(1) {
        let verified = crate::verifier::verify(
            &program.program.insns,
            &program.program.maps,
            &[],
            config.clone(),
        )
        .map_err(|error| {
            format!(
                "race XDP program '{}' failed verification: {error}",
                program.name
            )
        })?;
        program_ids.push(
            vm.register_race_program(program.program, verified.probe_mem)
                .map_err(|error| format!("race XDP program '{}': {error}", program.name))?,
        );
    }
    vm.insn_limit = PER_INSTANCE_INSN_LIMIT;

    let mut instances = Vec::with_capacity(programs.len());
    for (program, id) in programs.iter().zip(program_ids) {
        let mut frame = program.frame.clone();
        let environment = crate::execution::ExecutionEnvironment::xdp(&mut frame)?;
        instances.push(InstanceState::new_for_environment(&environment, id));
    }

    let mut scratch = first.frame.clone();
    let machine = vm
        .machine_xdp(&mut scratch)
        .map_err(|error| error.to_string())?;
    execute_schedule(machine, instances, chooser)
}

fn execute_schedule(
    mut m: Machine<'_>,
    mut instances: Vec<InstanceState>,
    chooser: &mut dyn Chooser,
) -> Result<ScheduleRun, String> {
    let procs = instances.len();
    let map_names: Vec<String> = m
        .vm_ref()
        .maps
        .iter()
        .map(|map| map.def.name.clone())
        .collect();
    let mut pending: Vec<Option<MapOp>> = vec![None; procs];
    let mut results: Vec<Option<InstanceResult>> = vec![None; procs];

    let mut trace: Vec<TraceStep> = Vec::new();
    let mut choices: Vec<usize> = Vec::new();
    let mut hazards = HazardLog::new();

    // Bring every instance up to its first map-visible op (or completion).
    for i in 0..procs {
        m.activate(&instances[i]);
        match m.run_to_mapop() {
            Ok(MapStep::Pending(op)) => pending[i] = Some(op),
            Ok(MapStep::Exited(r0)) => results[i] = Some(InstanceResult::Exit(r0)),
            Err(e) => results[i] = Some(InstanceResult::Error(e.to_string())),
        }
        m.deactivate(&mut instances[i]);
    }

    // Interleave.
    loop {
        let runnable: Vec<usize> = (0..procs).filter(|&i| pending[i].is_some()).collect();
        if runnable.is_empty() {
            break;
        }
        let pos = chooser.choose(&runnable).min(runnable.len() - 1);
        choices.push(pos);
        let i = runnable[pos];
        let op = pending[i].take().unwrap();

        m.activate(&instances[i]);
        let step_idx = trace.len();
        let exec = m.step();

        // Attribute this op to a (map, key) cell.
        let cell = match op.kind {
            MapOpKind::Lookup | MapOpKind::Update | MapOpKind::Delete => match (op.map, &op.key) {
                (Some(mp), Some(k)) => Some((mp, k.clone())),
                _ => None,
            },
            MapOpKind::ValueLoad | MapOpKind::ValueStore | MapOpKind::Atomic => {
                op.region.and_then(|r| m.cell_of_region(r))
            }
        };

        let detail = describe(&m, op.kind, cell.as_ref());
        trace.push(TraceStep {
            instance: i,
            program: i,
            op: op.kind,
            pc: op.pc,
            cell: cell.clone(),
            detail,
        });

        // Feed the hazard detector.
        if let Some(c) = cell.clone() {
            let access = match op.kind {
                MapOpKind::ValueLoad => Some(Access::Read),
                MapOpKind::ValueStore | MapOpKind::Update | MapOpKind::Delete => {
                    Some(Access::Write)
                }
                MapOpKind::Atomic => Some(Access::Atomic),
                MapOpKind::Lookup => None, // fetches a pointer, not the value
            };
            if let Some(a) = access {
                hazards.record(i, c, a, step_idx);
            }
        }

        match exec {
            Ok(_) => match m.run_to_mapop() {
                Ok(MapStep::Pending(next)) => pending[i] = Some(next),
                Ok(MapStep::Exited(r0)) => results[i] = Some(InstanceResult::Exit(r0)),
                Err(e) => results[i] = Some(InstanceResult::Error(e.to_string())),
            },
            Err(e) => results[i] = Some(InstanceResult::Error(e.to_string())),
        }
        m.deactivate(&mut instances[i]);
    }

    // Snapshot final map state.
    let maps: Vec<MapState> = m
        .vm_ref()
        .maps
        .iter()
        .enumerate()
        .map(|(idx, mm)| {
            let mut entries = mm.iter_entries();
            entries.sort();
            MapState {
                name: map_names[idx].clone(),
                entries,
            }
        })
        .collect();

    let results = results
        .into_iter()
        .map(|r| r.unwrap_or(InstanceResult::Error("never scheduled".into())))
        .collect();
    let invocations = instances
        .iter()
        .map(InstanceState::invocation_state)
        .collect();

    Ok(ScheduleRun {
        choices,
        trace,
        outcome: Outcome {
            maps,
            results,
            invocations,
        },
        lost_updates: hazards.found,
    })
}

fn run_schedule(
    prog: &Program,
    ctx: &[u8],
    procs: usize,
    chooser: &mut dyn Chooser,
) -> Result<ScheduleRun, String> {
    let programs: Vec<_> = (0..procs)
        .map(|_| RaceProgram {
            name: "program",
            program: prog,
            ctx,
        })
        .collect();
    run_program_schedule(&programs, chooser)
}

/// Human-readable detail for a trace step (current cell value + r0).
fn describe(
    m: &crate::interp::Machine,
    kind: MapOpKind,
    cell: Option<&(usize, Vec<u8>)>,
) -> String {
    let cellval = cell.and_then(|(mp, k)| {
        let mm = m.vm_ref().maps.get(*mp)?;
        mm.lookup(k).map(|vr| mm.value(vr).to_vec())
    });
    match kind {
        MapOpKind::Lookup => {
            let r0 = m.regs[0];
            if r0 == 0 {
                "r0 = NULL".to_string()
            } else {
                format!("r0 = ptr {r0:#x}")
            }
        }
        MapOpKind::ValueLoad => match cellval {
            Some(v) => format!("read value = {}", hex(&v)),
            None => "read value".to_string(),
        },
        MapOpKind::ValueStore | MapOpKind::Update => match cellval {
            Some(v) => format!("wrote value = {}", hex(&v)),
            None => "wrote value".to_string(),
        },
        MapOpKind::Atomic => match cellval {
            Some(v) => format!("atomic -> value = {}", hex(&v)),
            None => "atomic".to_string(),
        },
        MapOpKind::Delete => "deleted".to_string(),
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// -- exploration -------------------------------------------------------------

pub struct ExploreConfig {
    pub procs: usize,
    pub schedules: usize,
    pub seed: Option<u64>,
}

/// Exploration controls for an explicit heterogeneous program set.
pub struct ExploreProgramsConfig {
    pub schedules: usize,
    pub seed: Option<u64>,
}

/// A distinct observed outcome plus a witnessing schedule and how many explored
/// schedules produced it.
pub struct OutcomeGroup {
    pub witness: ScheduleRun,
    pub count: usize,
}

pub struct RaceReport {
    pub procs: usize,
    /// Whether the report came from the explicit multi-program API.
    pub heterogeneous: bool,
    /// Program label for each instance, in instance order.
    pub programs: Vec<String>,
    pub ctx_len: usize,
    pub runs: usize,
    /// Distinct outcomes, in first-seen order.
    pub groups: Vec<OutcomeGroup>,
    /// First schedule witnessing a lost-update anti-pattern, if any.
    pub lost_update_witness: Option<ScheduleRun>,
    /// Whether systematic enumeration completed (vs. hit the `--schedules` cap
    /// or was random).
    pub exhausted: bool,
    pub seed: Option<u64>,
}

impl RaceReport {
    /// A race is present when schedules diverge, or a lost-update was witnessed.
    pub fn is_race(&self) -> bool {
        self.groups.len() > 1 || self.lost_update_witness.is_some()
    }
}

fn ingest(groups: &mut Vec<OutcomeGroup>, lost: &mut Option<ScheduleRun>, run: ScheduleRun) {
    if lost.is_none() && !run.lost_updates.is_empty() {
        *lost = Some(run.clone());
    }
    match groups.iter_mut().find(|g| g.witness.outcome == run.outcome) {
        Some(g) => g.count += 1,
        None => groups.push(OutcomeGroup {
            witness: run,
            count: 1,
        }),
    }
}

/// Odometer increment over the mixed-radix `fanout` of the choices just taken:
/// the next DFS schedule, or `None` when the tree is exhausted.
fn next_path(taken: &[usize], fanout: &[usize]) -> Option<Vec<usize>> {
    let mut p = taken.to_vec();
    for i in (0..p.len()).rev() {
        if p[i] + 1 < fanout[i] {
            p[i] += 1;
            p.truncate(i + 1);
            return Some(p);
        }
    }
    None
}

fn explore_runs(
    schedules: usize,
    seed: Option<u64>,
    mut execute: impl FnMut(&mut dyn Chooser) -> Result<ScheduleRun, String>,
) -> Result<(Vec<OutcomeGroup>, Option<ScheduleRun>, usize, bool), String> {
    let mut groups = Vec::new();
    let mut lost = None;
    let mut runs = 0usize;
    let exhausted;

    if let Some(seed) = seed {
        for s in 0..schedules {
            let mut chooser =
                RandomChooser::new(seed.wrapping_add((s as u64).wrapping_mul(0x9e3779b1)));
            let run = execute(&mut chooser)?;
            runs += 1;
            ingest(&mut groups, &mut lost, run);
        }
        exhausted = false;
    } else {
        let mut path = Vec::new();
        exhausted = loop {
            if runs >= schedules {
                break false;
            }
            let mut chooser = PathChooser::new(path.clone());
            let run = execute(&mut chooser)?;
            runs += 1;
            let taken = run.choices.clone();
            let fanout = chooser.fanout.clone();
            ingest(&mut groups, &mut lost, run);
            match next_path(&taken, &fanout) {
                Some(next) => path = next,
                None => break true,
            }
        };
    }
    Ok((groups, lost, runs, exhausted))
}

fn explore_program_set(
    programs: &[RaceProgram<'_>],
    schedules: usize,
    seed: Option<u64>,
    heterogeneous: bool,
) -> Result<RaceReport, String> {
    let first = programs.first().ok_or("race program set is empty")?;
    let (groups, lost, runs, exhausted) = explore_runs(schedules, seed, |chooser| {
        run_program_schedule(programs, chooser)
    })?;

    Ok(RaceReport {
        procs: programs.len(),
        heterogeneous,
        programs: programs.iter().map(|p| p.name.to_string()).collect(),
        ctx_len: first.ctx.len(),
        runs,
        groups,
        lost_update_witness: lost,
        exhausted,
        seed,
    })
}

fn explore_xdp_program_set(
    programs: &[RaceXdpProgram<'_>],
    schedules: usize,
    seed: Option<u64>,
) -> Result<RaceReport, String> {
    programs.first().ok_or("race program set is empty")?;
    let (groups, lost, runs, exhausted) = explore_runs(schedules, seed, |chooser| {
        run_xdp_program_schedule(programs, chooser)
    })?;
    Ok(RaceReport {
        procs: programs.len(),
        heterogeneous: true,
        programs: programs
            .iter()
            .map(|program| program.name.to_string())
            .collect(),
        ctx_len: 24,
        runs,
        groups,
        lost_update_witness: lost,
        exhausted,
        seed,
    })
}

/// Explore schedules for repeated invocations of one program.
pub fn explore(prog: &Program, ctx: &[u8], cfg: &ExploreConfig) -> Result<RaceReport, String> {
    let programs: Vec<_> = (0..cfg.procs.max(1))
        .map(|_| RaceProgram {
            name: "program",
            program: prog,
            ctx,
        })
        .collect();
    explore_program_set(&programs, cfg.schedules, cfg.seed, false)
}

/// Explore schedules across an explicit set of program instances sharing maps.
pub fn explore_programs(
    programs: &[RaceProgram<'_>],
    cfg: &ExploreProgramsConfig,
) -> Result<RaceReport, String> {
    explore_program_set(programs, cfg.schedules, cfg.seed, true)
}

/// Explore verified XDP invocations with private provider-owned frames and
/// shared maps. Frame storage capacities must match so one machine environment
/// can swap their complete invocation snapshots.
pub fn explore_xdp_programs(
    programs: &[RaceXdpProgram<'_>],
    cfg: &ExploreProgramsConfig,
) -> Result<RaceReport, String> {
    explore_xdp_program_set(programs, cfg.schedules, cfg.seed)
}

/// Replay exactly one interleaving given as a choice vector.
pub fn replay_schedule(
    prog: &Program,
    ctx: &[u8],
    procs: usize,
    path: Vec<usize>,
) -> Result<ScheduleRun, String> {
    let mut ch = PathChooser::new(path);
    run_schedule(prog, ctx, procs.max(1), &mut ch)
}

/// Replay one interleaving across an explicit heterogeneous program set.
pub fn replay_programs(
    programs: &[RaceProgram<'_>],
    path: Vec<usize>,
) -> Result<ScheduleRun, String> {
    let mut ch = PathChooser::new(path);
    run_program_schedule(programs, &mut ch)
}

/// Replay one interleaving across an explicit heterogeneous XDP program set.
pub fn replay_xdp_programs(
    programs: &[RaceXdpProgram<'_>],
    path: Vec<usize>,
) -> Result<ScheduleRun, String> {
    let mut chooser = PathChooser::new(path);
    run_xdp_program_schedule(programs, &mut chooser)
}

// -- reporting ---------------------------------------------------------------

fn render_result(r: &InstanceResult) -> String {
    match r {
        InstanceResult::Exit(v) => format!("r0={v} ({v:#x})"),
        InstanceResult::Error(e) => format!("error: {e}"),
    }
}

fn render_maps(maps: &[MapState]) -> String {
    let mut out = String::new();
    for m in maps {
        let entries: Vec<String> = m
            .entries
            .iter()
            .map(|(k, v)| format!("{}={}", hex(k), hex(v)))
            .collect();
        out.push_str(&format!("      map '{}': {}\n", m.name, entries.join(" ")));
    }
    out
}

fn hex_preview(bytes: &[u8]) -> String {
    const LIMIT: usize = 32;
    if bytes.len() <= LIMIT {
        hex(bytes)
    } else {
        format!("{}... ({}B)", hex(&bytes[..LIMIT]), bytes.len())
    }
}

fn render_invocations(states: &[InvocationState]) -> String {
    let mut out = String::new();
    for (instance, state) in states.iter().enumerate() {
        out.push_str(&format!(
            "      inst{instance} context={} ",
            hex_preview(&state.context)
        ));
        if let Some(packet) = &state.packet {
            out.push_str(&format!(
                "packet={}[{}..{}] ",
                hex_preview(&packet.storage),
                packet.data_start,
                packet.data_end
            ));
        }
        if let Some(redirect) = state.redirect {
            out.push_str(&format!("redirect={redirect:?} "));
        }
        if let Some(printk) = &state.printk {
            out.push_str(&format!("printk={printk:?} "));
        }
        if let Some(seq) = &state.seq_output {
            out.push_str(&format!("seq={} ", hex_preview(seq)));
        }
        out.push('\n');
    }
    out
}

fn render_trace(
    trace: &[TraceStep],
    programs: &[String],
    heterogeneous: bool,
    file: &str,
    procs: usize,
    choices: &[usize],
) -> String {
    let mut out = String::new();
    for (n, s) in trace.iter().enumerate() {
        let cell = match &s.cell {
            Some((mp, k)) => format!(" cell(map{mp},key={})", hex(k)),
            None => String::new(),
        };
        let label = programs
            .get(s.program)
            .filter(|_| heterogeneous)
            .map(|name| format!("[{}]", name))
            .unwrap_or_default();
        out.push_str(&format!(
            "      #{n:<2} inst{}{label}  {:<6}{}  {}\n",
            s.instance,
            s.op.as_str(),
            cell,
            s.detail
        ));
    }
    let csv: Vec<String> = choices.iter().map(|c| c.to_string()).collect();
    if heterogeneous {
        out.push_str(&format!(
            "      replay with race::replay_programs, choices {}\n",
            csv.join(",")
        ));
    } else {
        out.push_str(&format!(
            "      reproduce: febpf race {file} --procs {procs} --schedule {}\n",
            csv.join(",")
        ));
    }
    out
}

/// Render a full report for the CLI.
pub fn render_report(rep: &RaceReport, file: &str, stats: bool) -> String {
    let mut out = String::new();
    let how = if let Some(seed) = rep.seed {
        format!("{} random schedule(s), seed {seed}", rep.runs)
    } else if rep.exhausted {
        format!("{} schedule(s), exhaustive", rep.runs)
    } else {
        format!("{} schedule(s) (capped)", rep.runs)
    };
    out.push_str(&format!(
        "race: {} instances, ctx {}B, explored {how}\n",
        rep.procs, rep.ctx_len
    ));

    if rep.is_race() {
        out.push_str("RESULT: RACE\n");
    } else {
        out.push_str("RESULT: RACE-FREE\n");
    }

    if let Some(run) = &rep.lost_update_witness {
        out.push_str("\nlost update (stale read-modify-write):\n");
        for lu in &run.lost_updates {
            out.push_str(&format!(
                "  map {} key {}: inst{} read at step #{}, inst{} wrote at step #{}, \
                 then inst{} overwrote at step #{} (losing inst{}'s write)\n",
                lu.map,
                hex(&lu.key),
                lu.reader,
                lu.read_step,
                lu.clobbered_by,
                lu.other_write_step,
                lu.reader,
                lu.overwrite_step,
                lu.clobbered_by,
            ));
        }
        out.push_str("  witnessing interleaving:\n");
        out.push_str(&render_trace(
            &run.trace,
            &rep.programs,
            rep.heterogeneous,
            file,
            rep.procs,
            &run.choices,
        ));
    }

    if rep.groups.len() > 1 {
        let invocation_divergence = rep.groups.first().is_some_and(|first| {
            rep.groups
                .iter()
                .skip(1)
                .any(|group| group.witness.outcome.invocations != first.witness.outcome.invocations)
        });
        out.push_str(&format!(
            "\ndivergent outcomes: {} distinct committed states across schedules\n",
            rep.groups.len()
        ));
        for (n, g) in rep.groups.iter().enumerate().take(2) {
            out.push_str(&format!(
                "\n  outcome {} (seen in {} schedule(s)):\n",
                n + 1,
                g.count
            ));
            out.push_str(&render_maps(&g.witness.outcome.maps));
            if invocation_divergence {
                out.push_str("      invocation state:\n");
                out.push_str(&render_invocations(&g.witness.outcome.invocations));
            }
            let rs: Vec<String> = g
                .witness
                .outcome
                .results
                .iter()
                .enumerate()
                .map(|(i, r)| format!("inst{i} {}", render_result(r)))
                .collect();
            out.push_str(&format!("      results: {}\n", rs.join(", ")));
            out.push_str("      witnessing interleaving:\n");
            out.push_str(&render_trace(
                &g.witness.trace,
                &rep.programs,
                rep.heterogeneous,
                file,
                rep.procs,
                &g.witness.choices,
            ));
        }
        if rep.groups.len() > 2 {
            out.push_str(&format!(
                "\n  ... and {} more distinct outcome(s)\n",
                rep.groups.len() - 2
            ));
        }
    } else if !rep.is_race() {
        // Single outcome, no hazards: show the committed state once.
        if let Some(g) = rep.groups.first() {
            out.push_str("committed state (identical across all schedules):\n");
            out.push_str(&render_maps(&g.witness.outcome.maps));
        }
    }

    if stats {
        out.push_str("\nstats:\n");
        out.push_str(&format!("  schedules explored: {}\n", rep.runs));
        out.push_str(&format!("  distinct outcomes:  {}\n", rep.groups.len()));
        let total_steps: usize = rep.groups.iter().map(|g| g.witness.trace.len()).sum();
        out.push_str(&format!("  map ops in witness traces: {total_steps}\n"));
        out.push_str(&format!(
            "  lost-update witnessed: {}\n",
            rep.lost_update_witness.is_some()
        ));
    }

    out
}

/// Render a single replayed schedule (for `--schedule`).
pub fn render_single(run: &ScheduleRun, file: &str, procs: usize) -> String {
    let mut out = String::new();
    out.push_str(&format!("replayed schedule ({procs} instances):\n"));
    out.push_str(&render_trace(
        &run.trace,
        &[],
        false,
        file,
        procs,
        &run.choices,
    ));
    out.push_str("committed state:\n");
    out.push_str(&render_maps(&run.outcome.maps));
    let rs: Vec<String> = run
        .outcome
        .results
        .iter()
        .enumerate()
        .map(|(i, r)| format!("inst{i} {}", render_result(r)))
        .collect();
    out.push_str(&format!("results: {}\n", rs.join(", ")));
    if !run.lost_updates.is_empty() {
        out.push_str(&format!(
            "lost-update anti-pattern present in this interleaving ({} occurrence(s))\n",
            run.lost_updates.len()
        ));
    }
    out
}
