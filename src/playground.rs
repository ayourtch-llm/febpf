//! Pure-std playground back-end shared by the CLI-independent web build.
//!
//! Every entry point takes program bytes (UTF-8 assembler source *or* a
//! `clang -target bpf` ELF object, distinguished by magic) and returns a
//! `String`. This module has **no** WASM/ABI concerns — those live in
//! [`crate::wasm`] and merely marshal linear-memory strings in and out of
//! these functions. It compiles on every target so the native test suite can
//! exercise it directly (`tests/playground.rs`).
//!
//! The debugger [`Session`] gets time-travel for free from the engine's
//! determinism (fixed-seed prandom, stable map storage): a fresh [`Vm`] is
//! rebuilt and replayed to the target instruction count on every query, so
//! `rstep`/`goto` are just "replay to an earlier N".

use crate::disasm::{disasm_insn, disasm_program};
use crate::insn::STACK_SIZE;
use crate::interp::{Machine, Program, Vm};
use crate::{analysis, asm, verifier};

/// Cap replay/execution so a runaway loop can't hang the browser tab.
const RUN_INSN_LIMIT: u64 = 1_000_000;

/// Load a program from assembler source or an ELF object (magic-sniffed).
pub fn load_program(bytes: &[u8]) -> Result<Program, String> {
    if bytes.len() >= 4 && &bytes[0..4] == b"\x7fELF" {
        let obj = crate::elf::load(bytes)?;
        let prog = obj
            .programs
            .into_iter()
            .next()
            .ok_or("ELF object contains no programs")?;
        Ok(Program {
            insns: prog.insns,
            maps: obj.maps,
            btf_ctx: None,
        })
    } else {
        let src = std::str::from_utf8(bytes)
            .map_err(|_| "input is neither an ELF object nor UTF-8 assembler source".to_string())?;
        let a = asm::assemble(src).map_err(|e| e.to_string())?;
        Ok(Program {
            insns: a.insns,
            maps: a.maps,
            btf_ctx: None,
        })
    }
}

/// Parse a hex context string (whitespace ignored). Empty ⇒ 4096 zero bytes.
fn parse_ctx(hex: &str) -> Result<Vec<u8>, String> {
    let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() {
        return Ok(vec![0u8; 4096]);
    }
    if !clean.len().is_multiple_of(2) {
        return Err("ctx hex string must have an even number of digits".into());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|e| format!("bad ctx hex: {e}"))
}

fn verifier_config(ctx_len: usize) -> verifier::Config {
    verifier::Config {
        ctx_size: ctx_len,
        ..Default::default()
    }
}

/// Verify a program; return the result text. On rejection this is the killer
/// demo: the failing instruction plus a disassembly window around it. The
/// message itself is whatever the verifier produces, so a richer explainer
/// (when it lands on `main`) surfaces here unchanged.
pub fn verify_text(bytes: &[u8]) -> String {
    let prog = match load_program(bytes) {
        Ok(p) => p,
        Err(e) => return format!("load error: {e}"),
    };
    let mut vm = match Vm::new(prog.clone()) {
        Ok(v) => v,
        Err(e) => return format!("load error: {e}"),
    };
    match vm.verify(verifier_config(4096)) {
        Ok(ok) => {
            let mut out = String::from("verification PASSED\n");
            let s = &ok.stats;
            out.push_str(&format!(
                "  {} insns processed, {} states explored, {} pruned, \
                 max call depth {}, stack usage {}B\n",
                s.insns_processed, s.states_explored, s.states_pruned, s.max_frames, s.stack_usage
            ));
            for w in &ok.warnings {
                out.push_str(&format!("  warning: {w}\n"));
            }
            out
        }
        Err(e) => {
            let mut out = format!("verification FAILED: {e}\n\n");
            out.push_str("counterexample — the failing instruction in context:\n");
            let pc = e.pc.min(prog.insns.len().saturating_sub(1));
            let lo = pc.saturating_sub(4);
            let hi = (pc + 4).min(prog.insns.len().saturating_sub(1));
            let mut i = lo;
            while i <= hi {
                let marker = if i == pc { ">>" } else { "  " };
                out.push_str(&format!("{marker}{i:4}: {}\n", disasm_insn(&prog.insns, i)));
                i += if prog.insns[i].is_wide() { 2 } else { 1 };
            }
            out
        }
    }
}

/// Verify then run; report `r0` and any `trace_printk` output.
pub fn run_text(bytes: &[u8], ctx_hex: &str) -> String {
    let prog = match load_program(bytes) {
        Ok(p) => p,
        Err(e) => return format!("load error: {e}"),
    };
    let mut ctx = match parse_ctx(ctx_hex) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let mut vm = match Vm::new(prog.clone()) {
        Ok(v) => v,
        Err(e) => return format!("load error: {e}"),
    };
    let mut out = String::new();
    match vm.verify(verifier_config(ctx.len())) {
        Ok(_) => out.push_str("verifier: PASSED\n"),
        Err(e) => out.push_str(&format!("verifier: FAILED: {e} (running anyway)\n")),
    }
    vm.insn_limit = RUN_INSN_LIMIT;
    match vm.run(&mut ctx) {
        Ok(r0) => out.push_str(&format!("r0 = {r0} ({r0:#x})\n")),
        Err(e) => out.push_str(&format!("runtime error: {e}\n")),
    }
    if !vm.printk.is_empty() {
        out.push_str("\ntrace_printk:\n");
        for line in &vm.printk {
            out.push_str(&format!("  {line}\n"));
        }
    }
    out
}

/// Disassemble a program to pseudo-C text.
pub fn disasm_text(bytes: &[u8]) -> String {
    match load_program(bytes) {
        Ok(p) => disasm_program(&p.insns),
        Err(e) => format!("load error: {e}"),
    }
}

/// Analysis output. `mode`: 0 = verifier-annotated listing, 1 = Graphviz DOT,
/// 2 = execution heatmap (runs the program).
pub fn analyze_text(bytes: &[u8], mode: u32) -> String {
    let prog = match load_program(bytes) {
        Ok(p) => p,
        Err(e) => return format!("load error: {e}"),
    };
    match mode {
        1 => {
            let cfg = analysis::build_cfg(&prog.insns);
            analysis::cfg_to_dot(&prog.insns, &cfg)
        }
        2 => {
            let mut ctx = vec![0u8; 4096];
            let mut vm = match Vm::new(prog.clone()) {
                Ok(v) => v,
                Err(e) => return format!("load error: {e}"),
            };
            vm.insn_limit = RUN_INSN_LIMIT;
            vm.enable_profiling();
            let mut out = String::new();
            if let Err(e) = vm.run(&mut ctx) {
                out.push_str(&format!("(program errored during profiling: {e})\n"));
            }
            let counts = vm.profile.take().unwrap_or_default();
            out.push_str(&analysis::heatmap_listing(&prog.insns, &counts, None));
            out
        }
        _ => {
            let mut vm = match Vm::new(prog.clone()) {
                Ok(v) => v,
                Err(e) => return format!("load error: {e}"),
            };
            match vm.verify(verifier_config(4096)) {
                Ok(ok) => {
                    let cfg = analysis::build_cfg(&prog.insns);
                    let st = analysis::stats(&prog.insns, &cfg);
                    let mut out = format!(
                        "{} instructions ({} slots), {} basic blocks, \
                         {} subprogram(s), {} back edge(s)\n\n",
                        st.insn_count, st.insn_slots, st.blocks, st.subprogs, st.back_edges
                    );
                    out.push_str(&analysis::annotated_listing(&prog.insns, &ok, None));
                    out
                }
                Err(e) => format!("cannot annotate: verification failed: {e}"),
            }
        }
    }
}

/// Deterministic concurrency race exploration. Runs `procs` instances of the
/// program sharing one map set across all interleavings (capped at
/// `schedules`), and renders the report — divergent outcomes / lost updates,
/// each with a replayable interleaving. `procs`/`schedules` of 0 fall back to
/// sensible defaults (2 instances, 2000 schedules).
pub fn race_text(bytes: &[u8], procs: u32, schedules: u32) -> String {
    let prog = match load_program(bytes) {
        Ok(p) => p,
        Err(e) => return format!("load error: {e}"),
    };
    let ctx = vec![0u8; 4096];
    let cfg = crate::race::ExploreConfig {
        procs: if procs == 0 { 2 } else { procs as usize },
        schedules: if schedules == 0 { 2000 } else { schedules as usize },
        seed: None,
    };
    match crate::race::explore(&prog, &ctx, &cfg) {
        Ok(rep) => crate::race::render_report(&rep, "program", true),
        Err(e) => format!("race error: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Debugger session (replay-based time travel)
// ---------------------------------------------------------------------------

/// A headless, string-driven debug session. Holds the program and a context
/// template plus a target instruction count; each command re-derives machine
/// state by replaying a fresh VM to that count.
pub struct Session {
    prog: Program,
    ctx_template: Vec<u8>,
    /// Target instruction count (the "current position" in time).
    steps: u64,
    /// PRNG seed to reproduce a recorded run (`None` ⇒ engine default).
    seed: Option<u64>,
    /// User-supplied map contents applied before each replay.
    preload: Vec<crate::replay::MapPreload>,
    /// XDP packet input for replay sessions.
    packet: Option<Vec<u8>>,
}

/// Load a replay file's bytes into a debugger [`Session`], positioned at its
/// recorded cursor. Lets the same `bug.febpf` open in the browser build.
pub fn replay_session(bytes: &[u8]) -> Result<Session, String> {
    Session::from_replay(bytes)
}

/// Where a replay ended relative to the requested target.
enum Status {
    Running,
    Exited(u64),
    Fault(String),
}

const DBG_HELP: &str = "\
commands:
  step [N] / s     advance N instructions (default 1)
  rstep [N] / rs   rewind N instructions (time travel)
  goto N / g       jump to instruction count N
  continue / c     run to exit, fault or the instruction cap
  reset            back to the start (count 0)
  regs / r         show registers, pc, frame, insn count
  stack            hex-dump the current stack frame
  list / l         disassemble around the current pc
  x <addr> [len]   hex-dump memory at a virtual address (default 64)
  maps             dump map contents at the current position
  printk           trace_printk output produced so far
  help             this text";

impl Session {
    pub fn new(bytes: &[u8], ctx_hex: &str) -> Result<Session, String> {
        let prog = load_program(bytes)?;
        // Validate that a VM can be built (map defs etc.) up front.
        Vm::new(prog.clone())?;
        let ctx_template = parse_ctx(ctx_hex)?;
        Ok(Session {
            prog,
            ctx_template,
            steps: 0,
            seed: None,
            preload: Vec::new(),
            packet: None,
        })
    }

    /// Build a session from a serialized replay file (see `crate::replay`),
    /// starting at the recorded cursor with the recorded seed and preload.
    pub fn from_replay(bytes: &[u8]) -> Result<Session, String> {
        let r = crate::replay::Replay::from_bytes(bytes)?;
        let prog = r.program();
        // Validate that a VM can be built (map defs etc.) up front.
        Vm::new(prog.clone())?;
        Ok(Session {
            prog,
            ctx_template: r.ctx,
            steps: r.stop_at.unwrap_or(0),
            seed: Some(r.seed),
            preload: r.preload,
            packet: r.packet,
        })
    }

    /// Build a fresh VM+ctx, replay to `self.steps`, and hand the machine and
    /// end-status to `f`. Rebuilding gives deterministic time travel.
    fn with_replay<R>(&self, f: impl FnOnce(&mut Machine, &Status) -> R) -> Result<R, String> {
        let mut vm = Vm::new(self.prog.clone())?;
        vm.insn_limit = RUN_INSN_LIMIT;
        if let Some(seed) = self.seed {
            vm.set_prandom_seed(seed);
        }
        crate::replay::apply_preload(&mut vm, &self.preload)?;
        let mut ctx = if let Some(packet) = &self.packet {
            vm.verify(crate::verifier::Config {
                ctx_size: 24,
                ctx_writable: false,
                xdp: true,
                ..Default::default()
            })
            .map_err(|e| format!("replayed XDP program no longer verifies: {e}"))?;
            vm.prepare_xdp(packet)?
        } else {
            self.ctx_template.clone()
        };
        let mut m = vm.machine(&mut ctx);
        let mut status = Status::Running;
        while m.insn_count < self.steps {
            match m.step() {
                Ok(Some(r0)) => {
                    status = Status::Exited(r0);
                    break;
                }
                Ok(None) => {}
                Err(e) => {
                    status = Status::Fault(e.to_string());
                    break;
                }
            }
        }
        Ok(f(&mut m, &status))
    }

    /// Move to `target` instructions, clamp to where execution actually
    /// reached, and report the new position.
    fn set_target(&mut self, target: u64) -> String {
        self.steps = target;
        match self.with_replay(|m, status| (m.insn_count, m.pc, status_line(m, status))) {
            Ok((actual, _pc, line)) => {
                self.steps = actual; // clamp so rstep works from the real count
                line
            }
            Err(e) => format!("error: {e}"),
        }
    }

    /// Execute one command line, returning the text to display.
    pub fn command(&mut self, line: &str) -> String {
        let mut it = line.split_whitespace();
        let cmd = it.next().unwrap_or("");
        let a1 = it.next();
        let a2 = it.next();
        let num = |s: Option<&str>, dflt: u64| -> u64 {
            s.and_then(|v| {
                v.strip_prefix("0x")
                    .and_then(|h| u64::from_str_radix(h, 16).ok())
                    .or_else(|| v.parse().ok())
            })
            .unwrap_or(dflt)
        };
        match cmd {
            "" => String::new(),
            "help" | "h" | "?" => DBG_HELP.to_string(),
            "step" | "s" => self.set_target(self.steps + num(a1, 1)),
            "rstep" | "rs" => self.set_target(self.steps.saturating_sub(num(a1, 1))),
            "goto" | "g" => self.set_target(num(a1, 0)),
            "continue" | "c" => self.set_target(u64::MAX),
            "reset" => self.set_target(0),
            "regs" | "r" => self
                .with_replay(|m, status| fmt_regs(m, status))
                .unwrap_or_else(|e| format!("error: {e}")),
            "stack" => self
                .with_replay(|m, _| fmt_stack(m))
                .unwrap_or_else(|e| format!("error: {e}")),
            "list" | "l" | "disasm" => self
                .with_replay(|m, _| fmt_list(m))
                .unwrap_or_else(|e| format!("error: {e}")),
            "x" => {
                let addr = num(a1, 0);
                let len = num(a2, 64).min(4096) as usize;
                self.with_replay(|m, _| match m.read_mem(addr, len) {
                    Ok(bytes) => hexdump(&bytes, addr),
                    Err(e) => format!("{e}"),
                })
                .unwrap_or_else(|e| format!("error: {e}"))
            }
            "maps" => self
                .with_replay(|m, _| fmt_maps(m))
                .unwrap_or_else(|e| format!("error: {e}")),
            "printk" => self
                .with_replay(|m, _| {
                    let lines = &m.vm_ref().printk;
                    if lines.is_empty() {
                        "(no trace_printk output yet)".to_string()
                    } else {
                        lines.join("\n")
                    }
                })
                .unwrap_or_else(|e| format!("error: {e}")),
            other => format!("unknown command '{other}' — try 'help'"),
        }
    }
}

fn status_line(m: &Machine, status: &Status) -> String {
    let head = match status {
        Status::Running => format!("stopped at pc {} (insn count {})", m.pc, m.insn_count),
        Status::Exited(r0) => format!("program exited: r0 = {r0} ({r0:#x})"),
        Status::Fault(msg) => format!("halted: {msg}"),
    };
    let insns = m.vm_ref().insns();
    if m.pc < insns.len() && !matches!(status, Status::Exited(_)) {
        format!("{head}\n{:4}: {}", m.pc, disasm_insn(insns, m.pc))
    } else {
        head
    }
}

fn fmt_regs(m: &Machine, status: &Status) -> String {
    let mut out = String::new();
    for row in 0..3 {
        let mut line = String::new();
        for col in 0..4 {
            let r = row * 4 + col;
            if r > 10 {
                break;
            }
            line.push_str(&format!("r{r:<2}= {:#018x}  ", m.regs[r]));
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out.push_str(&format!(
        "pc = {}  frame = {}  insns executed = {}\n",
        m.pc,
        m.current_frame(),
        m.insn_count
    ));
    if let Status::Exited(r0) = status {
        out.push_str(&format!("(program has exited: r0 = {r0})\n"));
    } else if let Status::Fault(msg) = status {
        out.push_str(&format!("(halted: {msg})\n"));
    }
    out
}

fn fmt_stack(m: &mut Machine) -> String {
    let fp = m.regs[10];
    if fp < STACK_SIZE as u64 {
        return "(no stack frame)".into();
    }
    let base = fp - STACK_SIZE as u64;
    match m.read_mem(base, STACK_SIZE) {
        Ok(bytes) => hexdump(&bytes, base),
        Err(e) => format!("{e}"),
    }
}

fn fmt_list(m: &Machine) -> String {
    let insns = m.vm_ref().insns();
    let center = m.pc;
    let lo = center.saturating_sub(5);
    let mut out = String::new();
    let mut pc = lo;
    while pc <= (center + 6).min(insns.len().saturating_sub(1)) {
        let marker = if pc == m.pc { "=>" } else { "  " };
        out.push_str(&format!("{marker}{pc:4}: {}\n", disasm_insn(insns, pc)));
        pc += if insns[pc].is_wide() { 2 } else { 1 };
    }
    out
}

fn fmt_maps(m: &Machine) -> String {
    let mut out = String::new();
    for map in &m.vm_ref().maps {
        out.push_str(&format!(
            "map '{}' ({}, key={}B value={}B max={}):\n",
            map.def.name, map.def.kind, map.def.key_size, map.def.value_size, map.def.max_entries
        ));
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let mut any = false;
        for (k, v) in map.iter_entries() {
            out.push_str(&format!("  [{}] = {}\n", hex(&k), hex(&v)));
            any = true;
        }
        if !any {
            out.push_str("  (empty)\n");
        }
    }
    if out.is_empty() {
        out.push_str("(no maps)");
    }
    out
}

fn hexdump(bytes: &[u8], base: u64) -> String {
    let mut out = String::new();
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
        out.push_str(&format!(
            "{:#010x}: {hex:<48} |{ascii}|\n",
            base + (i * 16) as u64
        ));
    }
    if out.is_empty() {
        out.push_str("(no bytes)\n");
    }
    out
}
