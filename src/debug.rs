//! Interactive debugger: breakpoints, single-stepping, register / stack /
//! memory / map inspection, execution tracing — and time travel.
//!
//! Execution is deterministic (fixed-seed prandom, stable map storage), so
//! reverse execution is snapshot + replay: the session keeps a base snapshot
//! plus periodic checkpoints (every [`DebuggerOpts::snapshot_interval`]
//! steps), and `rstep`/`rcontinue`/`goto` restore the nearest checkpoint and
//! re-execute forward. Data watchpoints stop execution when watched bytes
//! change; combined with `rcontinue` they step *back* to the write that
//! changed them. The one caveat: `ktime_get_ns` and user-registered helpers
//! are re-executed during replay, so programs whose control flow depends on
//! them may not replay faithfully (the debugger warns once when this risk
//! exists — see [`Machine::nondet_calls`]).
//!
//! The REPL is a thin stdin/stdout loop over [`DebugSession`], which is
//! driveable programmatically (and from tests) via
//! [`DebugSession::handle_command`].

use crate::disasm::disasm_insn;
use crate::insn::{call_kind, class, jmp, NUM_REGS};
use crate::interp::{Machine, Snapshot, Vm};
use std::collections::HashSet;
use std::io::{self, BufRead, Write};

pub struct DebuggerOpts {
    pub echo_printk: bool,
    /// Take a time-travel checkpoint every this many executed instructions.
    /// Reverse operations cost O(interval) replay steps.
    pub snapshot_interval: u64,
}

impl Default for DebuggerOpts {
    fn default() -> Self {
        DebuggerOpts {
            echo_printk: true,
            snapshot_interval: 10_000,
        }
    }
}

/// What the REPL should do after a command.
pub enum Outcome {
    /// Keep reading commands.
    Continue,
    /// Leave the debugger; carries r0 if the program ran to completion.
    Quit(Option<u64>),
}

/// Parse a register operand (`r0`..`r10`).
fn parse_reg(s: &str) -> Option<u8> {
    let n = s.trim().strip_prefix('r').or_else(|| s.trim().strip_prefix('R'))?;
    let v: u8 = n.parse().ok()?;
    (v < NUM_REGS as u8).then_some(v)
}

/// A contiguous span of guest memory (virtual address + length).
#[derive(Clone, Copy)]
struct MemRange {
    addr: u64,
    len: usize,
}

impl MemRange {
    /// Do the two spans share any byte?
    fn overlaps(&self, addr: u64, len: usize) -> bool {
        self.addr < addr.saturating_add(len as u64) && addr < self.addr.saturating_add(self.len as u64)
    }
}

/// One executed instruction's dataflow effect, recorded during an on-demand
/// replay of the current interval (see `docs/specs/dataflow-queries.md`).
struct Step {
    /// `insn_count` *after* executing (1-based).
    count: u64,
    pc: usize,
    /// Register this instruction defined, if any.
    def_reg: Option<u8>,
    /// Value written to `def_reg` (post-state).
    def_val: u64,
    /// Memory this instruction wrote, if any.
    store: Option<MemRange>,
    /// Value stored (STX source register / ST immediate).
    store_val: u64,
    /// Memory this instruction read into `def_reg` (LDX).
    load: Option<MemRange>,
}

fn parse_num(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn hexdump(out: &mut dyn Write, bytes: &[u8], base: u64) -> io::Result<()> {
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let mut hex = String::new();
        let mut ascii = String::new();
        for b in chunk {
            hex.push_str(&format!("{b:02x} "));
            ascii.push(if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            });
        }
        writeln!(out, "{:#010x}: {hex:<48} |{ascii}|", base + (i * 16) as u64)?;
    }
    Ok(())
}

fn hexbytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Final path component of a source file path.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn fmt_val(v: &Option<Vec<u8>>) -> String {
    match v {
        Some(b) => hexbytes(b),
        None => "<absent>".to_string(),
    }
}

/// What a watchpoint observes.
#[derive(Clone)]
enum WatchTarget {
    /// Raw virtual address (ctx / stack — regions with fixed handles).
    Addr { addr: u64, len: usize },
    /// A map value, addressed *logically* (looked up on every evaluation).
    /// This is deliberate: map-value region handles are allocated lazily in
    /// execution order and rewinding rewinds that allocation, so a virtual
    /// address captured now may mean something else after time travel. It
    /// also lets insert/delete of a hash entry register as a change.
    MapVal {
        map: usize,
        name: String,
        key: Vec<u8>,
        off: usize,
        len: usize,
    },
}

fn describe_target(t: &WatchTarget) -> String {
    match t {
        WatchTarget::Addr { addr, len } => format!("{addr:#x} len {len}"),
        WatchTarget::MapVal {
            name, key, off, len, ..
        } => format!("map {name}[{}]+{off} len {len}", hexbytes(key)),
    }
}

/// Current bytes of a watch target; `None` if unreadable / entry absent.
fn eval_watch(m: &mut Machine, t: &WatchTarget) -> Option<Vec<u8>> {
    match t {
        WatchTarget::Addr { addr, len } => m.read_mem(*addr, *len).ok(),
        WatchTarget::MapVal {
            map, key, off, len, ..
        } => {
            let mp = &m.vm_ref().maps[*map];
            let vref = mp.lookup(key)?;
            mp.value(vref).get(*off..*off + *len).map(|s| s.to_vec())
        }
    }
}

struct Watchpoint {
    id: u32,
    target: WatchTarget,
    /// Value as of the debugger's current position.
    last: Option<Vec<u8>>,
}

const HELP: &str = "\
commands:
  s, step [N]        execute N instructions (default 1)
  steps [N]          step N source lines, descending into calls
  n, nexts [N]       step N source lines, stepping over calls
  c, continue        run until breakpoint, watchpoint, exit or error
  rs, rstep [N]      step backward N instructions (time travel)
  rsteps [N]         step backward N source lines (time travel)
  rc, rcontinue      run backward to the previous breakpoint hit or
                     watchpoint change (e.g. back to the write that
                     changed a watched map value)
  goto <count>       jump to absolute executed-instruction count
  b, break <pc>      set breakpoint at instruction index
  d, delete <pc>     remove breakpoint (no arg: remove all)
  w, watch <addr> [len]               break when memory bytes change
  watch map <name> <key> [off [len]]  break when a map value changes
                     (key is an integer; default: the whole value)
  unwatch [id]       delete watchpoint (no arg: delete all)
  i, info            show breakpoints and watchpoints
  r, regs            show registers
  origin <reg>       trace a register's value back to where it was born
  when <reg>         pc of the most recent write to a register
  whenwrite <a|reg>  pc of the most recent write to a memory location
  who <a|reg> [len]  who wrote the bytes at a memory location (pc + source)
  p, print [name]    read a global variable by name (no arg: list globals)
  bt, backtrace      source-level call stack (subprogram names)
  l, list [pc]       disassemble around pc, interleaving C source
  x <addr> [len]     hex-dump memory at virtual address (default 64 bytes)
  stack              hex-dump the current stack frame
  maps               dump map contents
  printk             show trace_printk output so far
  t, trace           toggle per-instruction trace while stepping/running
  q, quit            leave the debugger
";

/// One interactive debugging session: a live [`Machine`] plus debugger state
/// (breakpoints, watchpoints and the time-travel checkpoints).
pub struct DebugSession<'a> {
    m: Machine<'a>,
    breakpoints: HashSet<usize>,
    watchpoints: Vec<Watchpoint>,
    next_watch_id: u32,
    trace: bool,
    /// r0 if the *current position* is past the program's exit.
    finished: Option<u64>,
    /// The exit ever observed: (instruction count, r0). Survives rewinding.
    exit_seen: Option<(u64, u64)>,
    /// State at instruction count 0.
    base: Snapshot,
    /// Periodic checkpoints, sorted by instruction count (all > 0). Kept
    /// after rewinding — determinism means they stay valid.
    checkpoints: Vec<Snapshot>,
    interval: u64,
    nondet_warned: bool,
}

impl<'a> DebugSession<'a> {
    pub fn new(vm: &'a mut Vm, ctx: &'a mut [u8], opts: &DebuggerOpts) -> Self {
        vm.echo_printk = opts.echo_printk;
        let m = vm.machine(ctx);
        let base = m.snapshot();
        DebugSession {
            m,
            breakpoints: HashSet::new(),
            watchpoints: Vec::new(),
            next_watch_id: 1,
            trace: false,
            finished: None,
            exit_seen: None,
            base,
            checkpoints: Vec::new(),
            interval: opts.snapshot_interval.max(1),
            nondet_warned: false,
        }
    }

    /// The underlying machine, for inspection in tests/tools.
    pub fn machine(&mut self) -> &mut Machine<'a> {
        &mut self.m
    }

    /// r0, if the current position is at or past the program's exit.
    pub fn finished(&self) -> Option<u64> {
        self.finished
    }

    fn print_insn(&self, out: &mut dyn Write, pc: usize) -> io::Result<()> {
        let insns = self.m.vm_ref().insns();
        if pc < insns.len() {
            writeln!(out, "{pc:4}: {}", disasm_insn(insns, pc))
        } else {
            writeln!(out, "{pc:4}: <out of bounds>")
        }
    }

    /// Print the current position (used by the REPL banner): the C source
    /// line, if known, followed by the disassembled instruction.
    pub fn print_position(&self, out: &mut dyn Write) -> io::Result<()> {
        self.print_loc(out, self.m.pc)
    }

    /// Source line + instruction at `pc`.
    fn print_loc(&self, out: &mut dyn Write, pc: usize) -> io::Result<()> {
        self.print_source_line(out, pc)?;
        self.print_insn(out, pc)
    }

    /// Print the C source line covering `pc` (as `func at file:line  text`),
    /// if debug info is available.
    fn print_source_line(&self, out: &mut dyn Write, pc: usize) -> io::Result<()> {
        let Some(di) = self.m.vm_ref().debug() else {
            return Ok(());
        };
        let func = di.func_at(pc).map(|f| f.name.as_str()).unwrap_or("?");
        if let Some(l) = di.line_at(pc) {
            if l.text.is_empty() {
                writeln!(out, "{func} at {}:{}", basename(&l.file), l.line)?;
            } else {
                writeln!(
                    out,
                    "{func} at {}:{}  {}",
                    basename(&l.file),
                    l.line,
                    l.text.trim()
                )?;
            }
        }
        Ok(())
    }

    /// The (file, line) covering `pc`, for source-level stepping.
    fn line_key(&self, pc: usize) -> Option<(String, u32)> {
        let di = self.m.vm_ref().debug()?;
        di.line_at(pc).map(|l| (l.file.clone(), l.line))
    }

    fn print_regs(&self, out: &mut dyn Write) -> io::Result<()> {
        for row in 0..3 {
            let mut line = String::new();
            for col in 0..4 {
                let r = row * 4 + col;
                if r > 10 {
                    break;
                }
                line.push_str(&format!("r{r:<2}= {:#018x}  ", self.m.regs[r]));
            }
            writeln!(out, "{}", line.trim_end())?;
        }
        writeln!(
            out,
            "pc = {}  frame = {}  insns executed = {}",
            self.m.pc,
            self.m.current_frame(),
            self.m.insn_count
        )
    }

    fn maybe_checkpoint(&mut self) {
        let c = self.m.insn_count;
        if c == 0 || !c.is_multiple_of(self.interval) {
            return;
        }
        let pos = self.checkpoints.partition_point(|s| s.insn_count() < c);
        if self.checkpoints.get(pos).map(Snapshot::insn_count) != Some(c) {
            self.checkpoints.insert(pos, self.m.snapshot());
        }
    }

    /// Execute one instruction; returns whether the caller may keep stepping.
    fn step_once(&mut self, out: &mut dyn Write) -> io::Result<bool> {
        if let Some(r0) = self.finished {
            writeln!(out, "program has exited (r0 = {r0}); rstep to go back, 'q' to leave")?;
            return Ok(false);
        }
        if self.trace {
            self.print_insn(out, self.m.pc)?;
        }
        let pre_pc = self.m.pc;
        match self.m.step() {
            Ok(Some(r0)) => {
                self.finished = Some(r0);
                self.exit_seen = Some((self.m.insn_count, r0));
                self.maybe_checkpoint();
                writeln!(out, "program exited with r0 = {r0} ({r0:#x})")?;
                Ok(false)
            }
            Ok(None) => {
                self.maybe_checkpoint();
                let mut stopped = false;
                for i in 0..self.watchpoints.len() {
                    let new = eval_watch(&mut self.m, &self.watchpoints[i].target);
                    if new != self.watchpoints[i].last {
                        let wp = &self.watchpoints[i];
                        writeln!(
                            out,
                            "watchpoint {} ({}) changed by insn {pre_pc}: {} -> {}",
                            wp.id,
                            describe_target(&wp.target),
                            fmt_val(&wp.last),
                            fmt_val(&new)
                        )?;
                        stopped = true;
                    }
                    self.watchpoints[i].last = new;
                }
                if stopped {
                    return Ok(false);
                }
                if self.breakpoints.contains(&self.m.pc) {
                    writeln!(out, "breakpoint hit at {}", self.m.pc)?;
                    Ok(false)
                } else {
                    Ok(true)
                }
            }
            Err(e) => {
                writeln!(out, "{e}")?;
                Ok(false)
            }
        }
    }

    /// Move to absolute instruction count `target`: restore the nearest
    /// snapshot at or before it and replay forward (silently).
    fn goto_count(&mut self, target: u64, out: &mut dyn Write) -> io::Result<()> {
        // Past the recorded exit there is nothing to execute.
        let target = match self.exit_seen {
            Some((c, _)) if target > c => c,
            _ => target,
        };
        if target < self.m.insn_count {
            let pos = self.checkpoints.partition_point(|s| s.insn_count() <= target);
            let snap = if pos == 0 { &self.base } else { &self.checkpoints[pos - 1] };
            self.m.restore(snap);
        } // else: target is ahead of us; just run forward from here
        let prev_echo = self.m.set_echo_printk(false);
        let res = self.m.run_to_count(target);
        self.m.set_echo_printk(prev_echo);
        if let Err(e) = res {
            writeln!(out, "replay error: {e}")?;
        }
        self.finished = match self.exit_seen {
            Some((c, r0)) if self.m.insn_count >= c => Some(r0),
            _ => None,
        };
        // Watch baselines now describe the new position.
        for i in 0..self.watchpoints.len() {
            self.watchpoints[i].last = eval_watch(&mut self.m, &self.watchpoints[i].target);
        }
        Ok(())
    }

    fn warn_nondet(&mut self, out: &mut dyn Write) -> io::Result<()> {
        if self.m.nondet_calls > 0 && !self.nondet_warned {
            self.nondet_warned = true;
            writeln!(
                out,
                "warning: {} call(s) to non-deterministic helpers so far \
                 (ktime_get_ns / user helpers); replay re-executes them, so \
                 reverse execution may not reproduce this run exactly",
                self.m.nondet_calls
            )?;
        }
        Ok(())
    }

    /// Run backward to the most recent state (strictly before the current
    /// one) where a breakpoint was hit or a watchpoint value changed.
    fn reverse_continue(&mut self, out: &mut dyn Write) -> io::Result<()> {
        let cur = self.m.insn_count;
        if cur == 0 {
            writeln!(out, "already at the start of the program")?;
            return Ok(());
        }
        self.warn_nondet(out)?;
        let targets: Vec<(u32, WatchTarget)> = self
            .watchpoints
            .iter()
            .map(|w| (w.id, w.target.clone()))
            .collect();
        // Segment starts strictly below `cur`: the base plus checkpoints.
        let n_starts = 1 + self.checkpoints.partition_point(|s| s.insn_count() < cur);
        let prev_echo = self.m.set_echo_printk(false);
        let mut found: Option<(u64, String)> = None;
        for i in (0..n_starts).rev() {
            let snap = if i == 0 { &self.base } else { &self.checkpoints[i - 1] };
            // States checked in this segment: (start, hi]; the last segment
            // must exclude `cur` itself, hence hi = cur - 1 there.
            let hi = if i + 1 < n_starts {
                self.checkpoints[i].insn_count()
            } else {
                cur - 1
            };
            self.m.restore(snap);
            let mut prev_vals: Vec<Option<Vec<u8>>> = targets
                .iter()
                .map(|(_, t)| eval_watch(&mut self.m, t))
                .collect();
            let mut hit: Option<(u64, String)> = None;
            while self.m.insn_count < hi {
                let pre_pc = self.m.pc;
                if self.m.step().is_err() {
                    break; // fault: no states beyond it in this run
                }
                let t = self.m.insn_count;
                for (j, (id, tgt)) in targets.iter().enumerate() {
                    let nv = eval_watch(&mut self.m, tgt);
                    if nv != prev_vals[j] {
                        hit = Some((
                            t,
                            format!(
                                "watchpoint {id} ({}) changed by insn {pre_pc}: {} -> {}",
                                describe_target(tgt),
                                fmt_val(&prev_vals[j]),
                                fmt_val(&nv)
                            ),
                        ));
                        prev_vals[j] = nv;
                    }
                }
                if self.breakpoints.contains(&self.m.pc) {
                    hit = Some((t, format!("breakpoint hit at {}", self.m.pc)));
                }
            }
            if hit.is_some() {
                found = hit;
                break;
            }
        }
        self.m.set_echo_printk(prev_echo);
        match found {
            Some((t, reason)) => {
                self.goto_count(t, out)?;
                writeln!(out, "{reason}")?;
            }
            None => {
                self.goto_count(0, out)?;
                writeln!(out, "no earlier breakpoint/watchpoint hit; at the start of the program")?;
            }
        }
        self.print_loc(out, self.m.pc)
    }

    /// Source-level step: execute until the covering C source line changes.
    /// With `step_over`, ignore line changes while inside a deeper call frame
    /// (steps over bpf-to-bpf calls); otherwise descend into them. Returns
    /// false when the program stops (exit / breakpoint / watchpoint / error).
    fn source_step(&mut self, step_over: bool, out: &mut dyn Write) -> io::Result<bool> {
        if self.m.vm_ref().debug().is_none() {
            // No line info: fall back to a single instruction step.
            return self.step_once(out);
        }
        let start_key = self.line_key(self.m.pc);
        let start_frame = self.m.current_frame();
        loop {
            if !self.step_once(out)? {
                return Ok(false);
            }
            let frame = self.m.current_frame();
            if step_over && frame > start_frame {
                continue; // inside a called subprogram; keep going
            }
            let changed = self.line_key(self.m.pc) != start_key;
            if changed || frame < start_frame {
                return Ok(true);
            }
        }
    }

    /// Reverse source step: time-travel backward to the previous distinct C
    /// source line.
    fn reverse_source_step(&mut self, n: u64, out: &mut dyn Write) -> io::Result<()> {
        if self.m.vm_ref().debug().is_none() {
            self.goto_count(self.m.insn_count.saturating_sub(n), out)?;
            return self.print_loc(out, self.m.pc);
        }
        self.warn_nondet(out)?;
        for _ in 0..n {
            let cur = self.m.insn_count;
            if cur == 0 {
                writeln!(out, "already at the start of the program")?;
                break;
            }
            let start_key = self.line_key(self.m.pc);
            let mut t = cur;
            loop {
                t -= 1;
                self.goto_count(t, out)?;
                if t == 0 || self.line_key(self.m.pc) != start_key {
                    break;
                }
            }
        }
        self.print_loc(out, self.m.pc)
    }

    /// Print a global variable by name (or list all globals), rendering the
    /// value through the BTF type graph.
    fn print_global(&self, name: Option<&str>, out: &mut dyn Write) -> io::Result<()> {
        let vm = self.m.vm_ref();
        let Some(di) = vm.debug() else {
            writeln!(out, "no debug info (load a program built with clang -g)")?;
            return Ok(());
        };
        let Some(name) = name else {
            if di.globals().is_empty() {
                writeln!(out, "no known globals")?;
            }
            for g in di.globals() {
                writeln!(out, "  {}: {}  (in {})", g.name, di.type_name(g.type_id), g.map_name)?;
            }
            return Ok(());
        };
        let Some(g) = di.global(name) else {
            writeln!(out, "no global named '{name}'")?;
            return Ok(());
        };
        let size = di.btf().type_size(g.type_id).unwrap_or(0) as usize;
        let map = &vm.maps[g.map];
        let key = 0u32.to_le_bytes();
        let bytes = map
            .lookup(&key)
            .map(|vref| map.value(vref))
            .and_then(|v| v.get(g.offset as usize..g.offset as usize + size));
        match bytes {
            Some(b) => writeln!(
                out,
                "{}: {} = {}",
                g.name,
                di.type_name(g.type_id),
                di.render_value(g.type_id, b)
            ),
            None => writeln!(out, "{}: <unreadable>", g.name),
        }
    }

    /// Print a source-level backtrace: the subprogram call stack, innermost
    /// first, with function names and source lines.
    fn print_backtrace(&self, out: &mut dyn Write) -> io::Result<()> {
        let pcs = self.m.backtrace_pcs();
        let di = self.m.vm_ref().debug();
        for (depth, pc) in pcs.iter().enumerate() {
            let func = di
                .and_then(|d| d.func_at(*pc))
                .map(|f| f.name.as_str())
                .unwrap_or("?");
            match di.and_then(|d| d.line_at(*pc)) {
                Some(l) => writeln!(
                    out,
                    "#{depth}  {func}  at {}:{}  (insn {pc})",
                    basename(&l.file),
                    l.line
                )?,
                None => writeln!(out, "#{depth}  {func}  (insn {pc})")?,
            }
        }
        Ok(())
    }

    fn add_watch(&mut self, args: &[&str], out: &mut dyn Write) -> io::Result<()> {
        let usage = "usage: watch <addr> [len]  |  watch map <name> <key> [off [len]]";
        let target = if args.first() == Some(&"map") {
            let (Some(name), Some(key)) = (args.get(1), args.get(2)) else {
                writeln!(out, "{usage}")?;
                return Ok(());
            };
            let maps = &self.m.vm_ref().maps;
            let Some(map) = maps.iter().position(|m| m.def.name == *name) else {
                writeln!(out, "no map named '{name}'")?;
                return Ok(());
            };
            let def = &maps[map].def;
            let (key_size, value_size) = (def.key_size as usize, def.value_size as usize);
            let Some(keyn) = parse_num(key) else {
                writeln!(out, "bad key '{key}' — {usage}")?;
                return Ok(());
            };
            if key_size > 8 {
                writeln!(out, "watch map: key size {key_size} > 8 not supported")?;
                return Ok(());
            }
            let key = keyn.to_le_bytes()[..key_size].to_vec();
            let off = args.get(3).and_then(|s| parse_num(s)).unwrap_or(0) as usize;
            let len = args
                .get(4)
                .and_then(|s| parse_num(s))
                .map(|v| v as usize)
                .unwrap_or(value_size.saturating_sub(off));
            if off + len > value_size || len == 0 {
                writeln!(out, "watch range {off}+{len} outside value size {value_size}")?;
                return Ok(());
            }
            WatchTarget::MapVal {
                map,
                name: name.to_string(),
                key,
                off,
                len,
            }
        } else {
            let Some(addr) = args.first().and_then(|s| parse_num(s)) else {
                writeln!(out, "{usage}")?;
                return Ok(());
            };
            let len = args.get(1).and_then(|s| parse_num(s)).unwrap_or(8) as usize;
            WatchTarget::Addr { addr, len }
        };
        let last = eval_watch(&mut self.m, &target);
        let id = self.next_watch_id;
        self.next_watch_id += 1;
        writeln!(
            out,
            "watchpoint {id} set: {} (current value {})",
            describe_target(&target),
            fmt_val(&last)
        )?;
        self.watchpoints.push(Watchpoint { id, target, last });
        Ok(())
    }

    // -- dataflow queries ----------------------------------------------------

    /// Rebuild the per-step write-log covering the current replay interval:
    /// restore the nearest checkpoint at or before the current position and
    /// single-step forward to it, recording each instruction's dataflow
    /// effect. Determinism means this ends exactly where we started, so the
    /// session is undisturbed (same mechanism as `goto_count`, but recording).
    fn build_write_log(&mut self) -> Vec<Step> {
        let target = self.m.insn_count;
        let pos = self.checkpoints.partition_point(|s| s.insn_count() <= target);
        let snap = if pos == 0 {
            self.base.clone()
        } else {
            self.checkpoints[pos - 1].clone()
        };
        self.m.restore(&snap);
        let prev_echo = self.m.set_echo_printk(false);
        let mut log = Vec::new();
        while self.m.insn_count < target {
            let pc = self.m.pc;
            let insn = self.m.vm_ref().insns()[pc];
            let regs = self.m.regs;
            let mut def_reg = None;
            let mut store = None;
            let mut load = None;
            let mut store_val = 0u64;
            match insn.class() {
                class::ALU | class::ALU64 => def_reg = Some(insn.dst),
                class::LD if insn.is_wide() => def_reg = Some(insn.dst),
                class::LDX => {
                    def_reg = Some(insn.dst);
                    let addr = regs[insn.src as usize].wrapping_add(insn.off as i64 as u64);
                    load = Some(MemRange { addr, len: insn.mem_size() });
                }
                class::ST => {
                    let addr = regs[insn.dst as usize].wrapping_add(insn.off as i64 as u64);
                    store = Some(MemRange { addr, len: insn.mem_size() });
                    store_val = insn.imm as i64 as u64;
                }
                class::STX => {
                    let addr = regs[insn.dst as usize].wrapping_add(insn.off as i64 as u64);
                    store = Some(MemRange { addr, len: insn.mem_size() });
                    store_val = regs[insn.src as usize];
                }
                class::JMP | class::JMP32
                    if insn.op() == jmp::CALL && insn.src == call_kind::HELPER =>
                {
                    def_reg = Some(0); // helper return in r0
                }
                _ => {}
            }
            if self.m.step().is_err() {
                break;
            }
            let def_val = def_reg.map_or(0, |r| self.m.regs[r as usize]);
            log.push(Step {
                count: self.m.insn_count,
                pc,
                def_reg,
                def_val,
                store,
                store_val,
                load,
            });
        }
        self.m.set_echo_printk(prev_echo);
        log
    }

    /// Print the source line covering `pc`, indented, when debug info exists.
    fn print_source_indent(&self, out: &mut dyn Write, pc: usize) -> io::Result<()> {
        let Some(di) = self.m.vm_ref().debug() else {
            return Ok(());
        };
        if let Some(l) = di.line_at(pc) {
            let func = di.func_at(pc).map(|f| f.name.as_str()).unwrap_or("?");
            if l.text.is_empty() {
                writeln!(out, "        at {} {}:{}", func, basename(&l.file), l.line)?;
            } else {
                writeln!(
                    out,
                    "        at {} {}:{}  {}",
                    func,
                    basename(&l.file),
                    l.line,
                    l.text.trim()
                )?;
            }
        }
        Ok(())
    }

    /// Resolve a `whenwrite`/`who` memory argument: a register name yields the
    /// register's current value (a pointer); otherwise parse a raw address.
    fn resolve_mem_arg(&self, arg: &str) -> Option<u64> {
        if let Some(r) = parse_reg(arg) {
            Some(self.m.regs[r as usize])
        } else {
            parse_num(arg)
        }
    }

    /// `when <reg>`: the most recent instruction (before now) that wrote `reg`.
    fn cmd_when(&mut self, arg: Option<&str>, out: &mut dyn Write) -> io::Result<()> {
        let Some(r) = arg.and_then(parse_reg) else {
            writeln!(out, "usage: when <reg>")?;
            return Ok(());
        };
        let cur = self.m.regs[r as usize];
        let log = self.build_write_log();
        match log.iter().rev().find(|s| s.def_reg == Some(r)) {
            Some(s) => {
                let insns = self.m.vm_ref().insns();
                writeln!(
                    out,
                    "r{r} last written by insn {} (count {}): {}  (= {:#x})",
                    s.pc,
                    s.count,
                    disasm_insn(insns, s.pc),
                    s.def_val
                )?;
                self.print_source_indent(out, s.pc)?;
            }
            None => writeln!(
                out,
                "r{r} not written in the current interval (value {cur:#x})"
            )?,
        }
        Ok(())
    }

    /// Shared body of `whenwrite` / `who`: locate the last write to
    /// `[addr, addr+len)` in the current interval and report it.
    fn report_mem_writer(
        &mut self,
        addr: u64,
        len: usize,
        show_value: bool,
        out: &mut dyn Write,
    ) -> io::Result<()> {
        let region = self.m.describe_addr(addr);
        let log = self.build_write_log();
        let found = log
            .iter()
            .rev()
            .find(|s| s.store.is_some_and(|m| m.overlaps(addr, len)));
        match found {
            Some(s) => {
                let insns = self.m.vm_ref().insns();
                if show_value {
                    writeln!(
                        out,
                        "{region} (len {len}) last written by insn {} (count {}): {}  (= {:#x})",
                        s.pc,
                        s.count,
                        disasm_insn(insns, s.pc),
                        s.store_val
                    )?;
                } else {
                    writeln!(
                        out,
                        "{region} (len {len}) last written by insn {} (count {}): {}",
                        s.pc,
                        s.count,
                        disasm_insn(insns, s.pc)
                    )?;
                }
                self.print_source_indent(out, s.pc)?;
            }
            None => {
                let cur = self.m.read_mem(addr, len).ok();
                match cur {
                    Some(b) => writeln!(
                        out,
                        "{region} (len {len}) not written in the current interval (now = {})",
                        hexbytes(&b)
                    )?,
                    None => writeln!(
                        out,
                        "{region} (len {len}) not written in the current interval"
                    )?,
                }
            }
        }
        Ok(())
    }

    /// `whenwrite <addr|reg> [len]`: pc of the last write to a memory location.
    fn cmd_whenwrite(&mut self, args: &[&str], out: &mut dyn Write) -> io::Result<()> {
        let Some(addr) = args.first().and_then(|a| self.resolve_mem_arg(a)) else {
            writeln!(out, "usage: whenwrite <addr|reg> [len]")?;
            return Ok(());
        };
        let len = args.get(1).and_then(|s| parse_num(s)).unwrap_or(8) as usize;
        self.report_mem_writer(addr, len, false, out)
    }

    /// `who <addr|reg> [len]`: who wrote these bytes — pc, source, value.
    fn cmd_who(&mut self, args: &[&str], out: &mut dyn Write) -> io::Result<()> {
        let Some(addr) = args.first().and_then(|a| self.resolve_mem_arg(a)) else {
            writeln!(out, "usage: who <addr|reg> [len]")?;
            return Ok(());
        };
        let len = args.get(1).and_then(|s| parse_num(s)).unwrap_or(8) as usize;
        self.report_mem_writer(addr, len, true, out)
    }

    /// Handle one debugger command line, writing output to `out`.
    pub fn handle_command(&mut self, line: &str, out: &mut dyn Write) -> io::Result<Outcome> {
        let mut it = line.split_whitespace();
        let cmd = it.next().unwrap_or("");
        let args: Vec<&str> = it.collect();
        let arg1 = args.first().copied();
        let arg2 = args.get(1).copied();

        match cmd {
            "" => {}
            "help" | "h" | "?" => write!(out, "{HELP}")?,
            "q" | "quit" | "exit" => return Ok(Outcome::Quit(self.finished)),
            "s" | "step" => {
                let n = arg1.and_then(parse_num).unwrap_or(1);
                for _ in 0..n {
                    if !self.step_once(out)? {
                        break;
                    }
                }
                if self.finished.is_none() {
                    self.print_loc(out, self.m.pc)?;
                }
            }
            "steps" => {
                let n = arg1.and_then(parse_num).unwrap_or(1);
                for _ in 0..n {
                    if !self.source_step(false, out)? {
                        break;
                    }
                }
                if self.finished.is_none() {
                    self.print_loc(out, self.m.pc)?;
                }
            }
            "nexts" | "n" => {
                let n = arg1.and_then(parse_num).unwrap_or(1);
                for _ in 0..n {
                    if !self.source_step(true, out)? {
                        break;
                    }
                }
                if self.finished.is_none() {
                    self.print_loc(out, self.m.pc)?;
                }
            }
            "c" | "continue" | "run" => {
                while self.step_once(out)? {}
                if self.finished.is_none() {
                    self.print_loc(out, self.m.pc)?;
                }
            }
            "rs" | "rstep" => {
                let n = arg1.and_then(parse_num).unwrap_or(1);
                let cur = self.m.insn_count;
                if cur == 0 {
                    writeln!(out, "already at the start of the program")?;
                } else {
                    self.warn_nondet(out)?;
                    self.goto_count(cur.saturating_sub(n), out)?;
                    self.print_loc(out, self.m.pc)?;
                }
            }
            "rsteps" => {
                let n = arg1.and_then(parse_num).unwrap_or(1);
                self.reverse_source_step(n, out)?;
            }
            "rc" | "rcontinue" | "rcont" => self.reverse_continue(out)?,
            "goto" => match arg1.and_then(parse_num) {
                Some(target) => {
                    if target < self.m.insn_count {
                        self.warn_nondet(out)?;
                    }
                    self.goto_count(target, out)?;
                    if self.m.insn_count != target {
                        writeln!(
                            out,
                            "(program ends after {} instructions)",
                            self.m.insn_count
                        )?;
                    }
                    self.print_loc(out, self.m.pc)?;
                }
                None => writeln!(out, "usage: goto <instruction count>")?,
            },
            "when" => self.cmd_when(arg1, out)?,
            "whenwrite" | "ww" => self.cmd_whenwrite(&args, out)?,
            "who" => self.cmd_who(&args, out)?,
            "p" | "print" => self.print_global(arg1, out)?,
            "bt" | "backtrace" | "where" => self.print_backtrace(out)?,
            "b" | "break" => match arg1.and_then(parse_num) {
                Some(pc) => {
                    self.breakpoints.insert(pc as usize);
                    writeln!(out, "breakpoint set at {pc}")?;
                }
                None => writeln!(out, "usage: break <pc>")?,
            },
            "d" | "delete" => match arg1.and_then(parse_num) {
                Some(pc) => {
                    self.breakpoints.remove(&(pc as usize));
                }
                None => {
                    self.breakpoints.clear();
                    writeln!(out, "all breakpoints removed")?;
                }
            },
            "w" | "watch" => self.add_watch(&args, out)?,
            "unwatch" => match arg1.and_then(parse_num) {
                Some(id) => {
                    let before = self.watchpoints.len();
                    self.watchpoints.retain(|w| w.id as u64 != id);
                    if self.watchpoints.len() == before {
                        writeln!(out, "no watchpoint {id}")?;
                    }
                }
                None => {
                    self.watchpoints.clear();
                    writeln!(out, "all watchpoints removed")?;
                }
            },
            "i" | "info" => {
                let mut bps: Vec<_> = self.breakpoints.iter().collect();
                bps.sort();
                writeln!(out, "breakpoints: {bps:?}")?;
                for w in &self.watchpoints {
                    writeln!(
                        out,
                        "watchpoint {}: {} = {}",
                        w.id,
                        describe_target(&w.target),
                        fmt_val(&w.last)
                    )?;
                }
            }
            "r" | "regs" => self.print_regs(out)?,
            "l" | "list" => {
                let center = arg1
                    .and_then(parse_num)
                    .map(|v| v as usize)
                    .unwrap_or(self.m.pc);
                let vm = self.m.vm_ref();
                let insns = vm.insns();
                let di = vm.debug();
                let lo = center.saturating_sub(5);
                let hi = (center + 6).min(insns.len().saturating_sub(1));
                let mut lines = Vec::new();
                let mut last_src: Option<(String, u32)> = None;
                let mut pc = lo;
                while pc <= hi {
                    // Interleave the covering C source line when it changes.
                    if let Some(di) = di {
                        if di.func_at(pc).map(|f| f.insn) == Some(pc) {
                            if let Some(f) = di.func_at(pc) {
                                lines.push(format!("; ---- {} ----", f.name));
                            }
                        }
                        if let Some(l) = di.line_at(pc) {
                            let key = (l.file.clone(), l.line);
                            if last_src.as_ref() != Some(&key) {
                                last_src = Some(key);
                                lines.push(format!(
                                    "; {}:{}  {}",
                                    basename(&l.file),
                                    l.line,
                                    l.text.trim()
                                ));
                            }
                        }
                    }
                    let marker = if pc == self.m.pc { "=>" } else { "  " };
                    let bp = if self.breakpoints.contains(&pc) { "*" } else { " " };
                    lines.push(format!("{marker}{bp}{pc:4}: {}", disasm_insn(insns, pc)));
                    pc += if insns[pc].is_wide() { 2 } else { 1 };
                }
                for l in lines {
                    writeln!(out, "{l}")?;
                }
            }
            "x" => match arg1.and_then(parse_num) {
                Some(addr) => {
                    let len = arg2.and_then(parse_num).unwrap_or(64) as usize;
                    match self.m.read_mem(addr, len) {
                        Ok(bytes) => hexdump(out, &bytes, addr)?,
                        Err(e) => writeln!(out, "{e}")?,
                    }
                }
                None => writeln!(out, "usage: x <addr> [len]")?,
            },
            "stack" => {
                let fp = self.m.regs[10];
                let base = fp - crate::insn::STACK_SIZE as u64;
                match self.m.read_mem(base, crate::insn::STACK_SIZE) {
                    Ok(bytes) => hexdump(out, &bytes, base)?,
                    Err(e) => writeln!(out, "{e}")?,
                }
            }
            "maps" => {
                for map in &self.m.vm_ref().maps {
                    writeln!(
                        out,
                        "map '{}' ({}, key={}B value={}B max={}):",
                        map.def.name, map.def.kind, map.def.key_size, map.def.value_size,
                        map.def.max_entries
                    )?;
                    for (k, v) in map.iter_entries() {
                        writeln!(out, "  [{}] = {}", hexbytes(&k), hexbytes(&v))?;
                    }
                }
            }
            "printk" => {
                for line in &self.m.vm_ref().printk {
                    writeln!(out, "{line}")?;
                }
            }
            "t" | "trace" => {
                self.trace = !self.trace;
                writeln!(out, "trace {}", if self.trace { "on" } else { "off" })?;
            }
            other => writeln!(out, "unknown command '{other}' — try 'help'")?,
        }
        Ok(Outcome::Continue)
    }
}

/// Run an interactive debugging session for `vm` with context `ctx`.
/// Returns the program's r0 if it ran to completion.
pub fn repl(vm: &mut Vm, ctx: &mut [u8], opts: DebuggerOpts) -> io::Result<Option<u64>> {
    let mut session = DebugSession::new(vm, ctx, &opts);
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    let mut out = io::stdout();

    writeln!(out, "febpf debugger — type 'help' for commands")?;
    session.print_position(&mut out)?;

    loop {
        write!(out, "(febpf) ")?;
        out.flush()?;
        let line = match lines.next() {
            Some(l) => l?,
            None => return Ok(session.finished()), // EOF
        };
        match session.handle_command(&line, &mut out)? {
            Outcome::Continue => {}
            Outcome::Quit(r0) => return Ok(r0),
        }
    }
}
