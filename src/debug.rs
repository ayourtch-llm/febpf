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
  c, continue        run until breakpoint, watchpoint, exit or error
  rs, rstep [N]      step backward N instructions (time travel)
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
  l, list [pc]       disassemble around pc (default: current)
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

    /// Print the current position (used by the REPL banner).
    pub fn print_position(&self, out: &mut dyn Write) -> io::Result<()> {
        self.print_insn(out, self.m.pc)
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
        self.print_insn(out, self.m.pc)
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
                    self.print_insn(out, self.m.pc)?;
                }
            }
            "c" | "continue" | "run" => {
                while self.step_once(out)? {}
                if self.finished.is_none() {
                    self.print_insn(out, self.m.pc)?;
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
                    self.print_insn(out, self.m.pc)?;
                }
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
                    self.print_insn(out, self.m.pc)?;
                }
                None => writeln!(out, "usage: goto <instruction count>")?,
            },
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
                let insns = self.m.vm_ref().insns();
                let lo = center.saturating_sub(5);
                let hi = (center + 6).min(insns.len().saturating_sub(1));
                let mut lines = Vec::new();
                let mut pc = lo;
                while pc <= hi {
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
