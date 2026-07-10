//! Interactive debugger: breakpoints, single-stepping, register / stack /
//! memory / map inspection, and execution tracing.
//!
//! The REPL is a thin stdin/stdout loop over [`DebugSession`], which is
//! driveable programmatically (and from tests) via
//! [`DebugSession::handle_command`].

use crate::disasm::disasm_insn;
use crate::interp::{Machine, Vm};
use std::collections::HashSet;
use std::io::{self, BufRead, Write};

pub struct DebuggerOpts {
    pub echo_printk: bool,
}

impl Default for DebuggerOpts {
    fn default() -> Self {
        DebuggerOpts { echo_printk: true }
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

const HELP: &str = "\
commands:
  s, step [N]        execute N instructions (default 1)
  c, continue        run until breakpoint, exit or error
  b, break <pc>      set breakpoint at instruction index
  d, delete <pc>     remove breakpoint (no arg: remove all)
  i, info            show breakpoints
  r, regs            show registers
  l, list [pc]       disassemble around pc (default: current)
  x <addr> [len]     hex-dump memory at virtual address (default 64 bytes)
  stack              hex-dump the current stack frame
  maps               dump map contents
  printk             show trace_printk output so far
  t, trace           toggle per-instruction trace while stepping/running
  q, quit            leave the debugger
";

/// One interactive debugging session: a live [`Machine`] plus debugger state.
pub struct DebugSession<'a> {
    m: Machine<'a>,
    breakpoints: HashSet<usize>,
    trace: bool,
    finished: Option<u64>,
}

impl<'a> DebugSession<'a> {
    pub fn new(vm: &'a mut Vm, ctx: &'a mut [u8], opts: &DebuggerOpts) -> Self {
        vm.echo_printk = opts.echo_printk;
        DebugSession {
            m: vm.machine(ctx),
            breakpoints: HashSet::new(),
            trace: false,
            finished: None,
        }
    }

    /// The underlying machine, for inspection in tests/tools.
    pub fn machine(&mut self) -> &mut Machine<'a> {
        &mut self.m
    }

    /// r0, if the program has run to completion.
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

    /// Execute one instruction; returns whether the caller may keep stepping.
    fn step_once(&mut self, out: &mut dyn Write) -> io::Result<bool> {
        if let Some(r0) = self.finished {
            writeln!(out, "program has exited (r0 = {r0}); 'q' to leave")?;
            return Ok(false);
        }
        if self.trace {
            self.print_insn(out, self.m.pc)?;
        }
        match self.m.step() {
            Ok(Some(r0)) => {
                self.finished = Some(r0);
                writeln!(out, "program exited with r0 = {r0} ({r0:#x})")?;
                Ok(false)
            }
            Ok(None) => {
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

    /// Handle one debugger command line, writing output to `out`.
    pub fn handle_command(&mut self, line: &str, out: &mut dyn Write) -> io::Result<Outcome> {
        let mut it = line.split_whitespace();
        let cmd = it.next().unwrap_or("");
        let arg1 = it.next();
        let arg2 = it.next();

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
            "i" | "info" => {
                let mut bps: Vec<_> = self.breakpoints.iter().collect();
                bps.sort();
                writeln!(out, "breakpoints: {bps:?}")?;
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
                        let hex =
                            |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
                        writeln!(out, "  [{}] = {}", hex(&k), hex(&v))?;
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
