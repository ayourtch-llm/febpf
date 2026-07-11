//! Program analysis: control-flow graph extraction, DOT export, and
//! verifier-annotated listings.

use crate::debuginfo::DebugInfo;
use crate::disasm::disasm_insn;
use crate::insn::*;
use crate::verifier::VerifyOk;
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Tracks the last-emitted source line so a listing only prints a source
/// comment when the covering line changes (addr2line-style interleaving).
struct SourceInterleaver<'a> {
    debug: Option<&'a DebugInfo>,
    /// (file, line) last emitted, so identical consecutive lines collapse.
    last: Option<(String, u32)>,
}

impl<'a> SourceInterleaver<'a> {
    fn new(debug: Option<&'a DebugInfo>) -> Self {
        SourceInterleaver { debug, last: None }
    }

    /// Emit source context for instruction `pc` into `out` if the covering
    /// source line just changed. Also emits a subprogram header at a function
    /// boundary.
    fn emit(&mut self, out: &mut String, pc: usize) {
        let Some(di) = self.debug else { return };
        if let Some(f) = di.func_at(pc) {
            if f.insn == pc {
                let _ = writeln!(out, "; ---- {} ----", f.name);
            }
        }
        let Some(line) = di.line_at(pc) else { return };
        let key = (line.file.clone(), line.line);
        if self.last.as_ref() == Some(&key) {
            return;
        }
        self.last = Some(key);
        // Show just the file's basename to keep listings readable.
        let file = line.file.rsplit('/').next().unwrap_or(&line.file);
        if line.text.is_empty() {
            let _ = writeln!(out, "; {}:{}", file, line.line);
        } else {
            let _ = writeln!(out, "; {}:{}  {}", file, line.line, line.text.trim());
        }
    }
}

/// A basic block: a maximal straight-line instruction sequence.
#[derive(Debug)]
pub struct Block {
    pub start: usize,
    /// pc of the last instruction in the block.
    pub end: usize,
    pub succs: Vec<usize>, // successor block start pcs
    pub is_exit: bool,
}

pub struct Cfg {
    pub blocks: BTreeMap<usize, Block>,
    /// Entry points of bpf-to-bpf subprograms (including 0 for main).
    pub subprogs: Vec<usize>,
}

fn insn_targets(insns: &[Insn], pc: usize) -> (Vec<i64>, bool /*fallthrough*/, bool /*exit*/) {
    let ins = insns[pc];
    let cls = ins.class();
    if cls != class::JMP && cls != class::JMP32 {
        return (vec![], true, false);
    }
    match ins.op() {
        jmp::EXIT => (vec![], false, true),
        jmp::JA => {
            let rel = if cls == class::JMP32 {
                ins.imm as i64
            } else {
                ins.off as i64
            };
            (vec![pc as i64 + 1 + rel], false, false)
        }
        jmp::CALL => (vec![], true, false), // treat calls as straight-line
        _ => (vec![pc as i64 + 1 + ins.off as i64], true, false),
    }
}

pub fn build_cfg(insns: &[Insn]) -> Cfg {
    let n = insns.len();
    let mut leaders = vec![false; n];
    let mut subprogs = vec![0usize];
    if n > 0 {
        leaders[0] = true;
    }
    let mut pc = 0;
    while pc < n {
        let ins = insns[pc];
        let width = if ins.is_wide() { 2 } else { 1 };
        let (targets, fallthrough, is_exit) = insn_targets(insns, pc);
        let cls = ins.class();
        let is_jump = cls == class::JMP || cls == class::JMP32;
        if is_jump && ins.op() == jmp::CALL && ins.src == call_kind::LOCAL {
            let t = pc as i64 + 1 + ins.imm as i64;
            if t >= 0 && (t as usize) < n {
                leaders[t as usize] = true;
                if !subprogs.contains(&(t as usize)) {
                    subprogs.push(t as usize);
                }
            }
        }
        for t in &targets {
            if *t >= 0 && (*t as usize) < n {
                leaders[*t as usize] = true;
            }
        }
        if (!targets.is_empty() || is_exit || !fallthrough) && pc + width < n {
            leaders[pc + width] = true;
        }
        pc += width;
    }

    let mut blocks = BTreeMap::new();
    let mut pc = 0;
    while pc < n {
        let start = pc;
        let mut last;
        loop {
            let width = if insns[pc].is_wide() { 2 } else { 1 };
            last = pc;
            pc += width;
            if pc >= n || leaders[pc] {
                break;
            }
            let (t, ft, ex) = insn_targets(insns, last);
            if !t.is_empty() || ex || !ft {
                break;
            }
        }
        let (targets, fallthrough, is_exit) = insn_targets(insns, last);
        let mut succs: Vec<usize> = targets
            .into_iter()
            .filter(|t| *t >= 0 && (*t as usize) < n)
            .map(|t| t as usize)
            .collect();
        if fallthrough && pc < n && !is_exit {
            succs.push(pc);
        }
        blocks.insert(
            start,
            Block {
                start,
                end: last,
                succs,
                is_exit,
            },
        );
    }
    subprogs.sort_unstable();
    Cfg { blocks, subprogs }
}

/// Render the CFG in Graphviz DOT format.
pub fn cfg_to_dot(insns: &[Insn], cfg: &Cfg) -> String {
    let mut out = String::from("digraph ebpf {\n  node [shape=box fontname=\"monospace\"];\n");
    for (start, b) in &cfg.blocks {
        let mut label = String::new();
        let mut pc = *start;
        while pc <= b.end {
            let _ = write!(label, "{pc}: {}\\l", disasm_insn(insns, pc).replace('"', "'"));
            pc += if insns[pc].is_wide() { 2 } else { 1 };
        }
        let shape = if b.is_exit { " color=red" } else { "" };
        let _ = writeln!(out, "  b{start} [label=\"{label}\"{shape}];");
        for s in &b.succs {
            let style = if *s <= *start { " [color=blue]" } else { "" }; // back edge
            let _ = writeln!(out, "  b{start} -> b{s}{style};");
        }
    }
    out.push_str("}\n");
    out
}

/// Instruction-mix and structural statistics.
pub struct ProgStats {
    pub insn_slots: usize,
    pub insn_count: usize,
    pub blocks: usize,
    pub subprogs: usize,
    pub back_edges: usize,
    pub helpers: Vec<u32>,
    pub class_histogram: BTreeMap<&'static str, usize>,
}

pub fn stats(insns: &[Insn], cfg: &Cfg) -> ProgStats {
    let mut hist: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut helpers_used = Vec::new();
    let mut count = 0;
    let mut pc = 0;
    while pc < insns.len() {
        let ins = insns[pc];
        count += 1;
        let name = match ins.class() {
            class::ALU => "alu32",
            class::ALU64 => "alu64",
            class::JMP => match ins.op() {
                jmp::CALL => "call",
                jmp::EXIT => "exit",
                _ => "jmp",
            },
            class::JMP32 => "jmp32",
            class::LD => "lddw",
            class::LDX => "load",
            class::ST | class::STX => {
                if ins.mem_mode() == mode::ATOMIC {
                    "atomic"
                } else {
                    "store"
                }
            }
            _ => "other",
        };
        *hist.entry(name).or_default() += 1;
        if ins.class() == class::JMP && ins.op() == jmp::CALL && ins.src == call_kind::HELPER {
            let hid = ins.imm as u32;
            if !helpers_used.contains(&hid) {
                helpers_used.push(hid);
            }
        }
        pc += if ins.is_wide() { 2 } else { 1 };
    }
    let back_edges = cfg
        .blocks
        .values()
        .map(|b| b.succs.iter().filter(|s| **s <= b.start).count())
        .sum();
    ProgStats {
        insn_slots: insns.len(),
        insn_count: count,
        blocks: cfg.blocks.len(),
        subprogs: cfg.subprogs.len(),
        back_edges,
        helpers: helpers_used,
        class_histogram: hist,
    }
}

/// Plain disassembly interleaved with C source lines from `debug`.
pub fn source_listing(insns: &[Insn], debug: &DebugInfo) -> String {
    let mut out = String::new();
    let mut src = SourceInterleaver::new(Some(debug));
    let mut pc = 0;
    while pc < insns.len() {
        src.emit(&mut out, pc);
        let _ = writeln!(out, "{pc:4}: {}", disasm_insn(insns, pc));
        pc += if insns[pc].is_wide() { 2 } else { 1 };
    }
    out
}

/// Disassembly listing annotated with the verifier's abstract state before
/// each instruction (as seen on its first visit) and visit counts. When
/// `debug` is present, C source lines are interleaved.
pub fn annotated_listing(insns: &[Insn], vres: &VerifyOk, debug: Option<&DebugInfo>) -> String {
    let mut out = String::new();
    let mut src = SourceInterleaver::new(debug);
    let mut pc = 0;
    while pc < insns.len() {
        src.emit(&mut out, pc);
        match &vres.insn_state[pc] {
            Some((state, visits)) => {
                if !state.is_empty() {
                    let _ = writeln!(out, "      ; {state}");
                }
                let v = if *visits > 1 {
                    format!("  ; visited {visits}x")
                } else {
                    String::new()
                };
                let _ = writeln!(out, "{pc:4}: {}{v}", disasm_insn(insns, pc));
            }
            None => {
                let _ = writeln!(out, "{pc:4}: {}  ; DEAD", disasm_insn(insns, pc));
            }
        }
        pc += if insns[pc].is_wide() { 2 } else { 1 };
    }
    out
}

/// Execution heatmap: disassembly annotated with per-instruction execution
/// counts and a log-scaled intensity bar, plus a hottest-blocks summary.
pub fn heatmap_listing(insns: &[Insn], counts: &[u64], debug: Option<&DebugInfo>) -> String {
    let max = counts.iter().copied().max().unwrap_or(0);
    let total: u64 = counts.iter().sum();
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{total} instructions executed, hottest instruction ran {max}x\n"
    );
    let bar_for = |c: u64| -> String {
        if c == 0 || max == 0 {
            return String::new();
        }
        // log scale: 1..=8 blocks
        let lg = |v: u64| (v as f64).ln();
        let frac = if max == 1 { 1.0 } else { lg(c) / lg(max) };
        let blocks = 1 + (frac * 7.0).round() as usize;
        "█".repeat(blocks)
    };
    let mut src = SourceInterleaver::new(debug);
    let mut pc = 0;
    while pc < insns.len() {
        src.emit(&mut out, pc);
        let c = counts.get(pc).copied().unwrap_or(0);
        let pct = if total > 0 {
            100.0 * c as f64 / total as f64
        } else {
            0.0
        };
        if c == 0 {
            let _ = writeln!(out, "         .        {pc:4}: {}", disasm_insn(insns, pc));
        } else {
            let _ = writeln!(
                out,
                "{c:>9} {pct:5.1}% {:<8} {pc:4}: {}",
                bar_for(c),
                disasm_insn(insns, pc)
            );
        }
        pc += if insns[pc].is_wide() { 2 } else { 1 };
    }
    // hottest basic blocks
    let cfg = build_cfg(insns);
    let mut blocks: Vec<(u64, usize, usize)> = cfg
        .blocks
        .values()
        .map(|b| {
            let mut sum = 0u64;
            let mut pc = b.start;
            while pc <= b.end {
                sum += counts.get(pc).copied().unwrap_or(0);
                pc += if insns[pc].is_wide() { 2 } else { 1 };
            }
            (sum, b.start, b.end)
        })
        .collect();
    blocks.sort_unstable_by_key(|&(sum, _, _)| std::cmp::Reverse(sum));
    let _ = writeln!(out, "\nhottest blocks:");
    for (sum, start, end) in blocks.iter().take(5) {
        if *sum == 0 {
            break;
        }
        let pct = if total > 0 {
            100.0 * *sum as f64 / total as f64
        } else {
            0.0
        };
        let _ = writeln!(out, "  insns {start:>4}..={end:<4} {sum:>10} executions ({pct:.1}%)");
    }
    out
}
