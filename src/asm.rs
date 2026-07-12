//! Assembler for kernel-documentation "pseudo-C" eBPF syntax.
//!
//! ```text
//! ; comments start with ';', '#' or '//'
//! .map counters hash 4 8 1024        ; name kind key_size value_size max_entries
//!
//! entry:
//!     r1 = map[counters]             ; lddw map pointer
//!     r2 = 0x1122334455667788 ll     ; 64-bit immediate
//!     w3 = 7                         ; 32-bit alu
//!     r4 = (s16)r3                   ; sign-extending move
//!     r5 = *(u32 *)(r1 + 4)          ; load
//!     *(u64 *)(r10 - 8) = r5         ; store
//!     lock *(u64 *)(r1 + 0) += r2    ; atomic
//!     if r5 s> 3 goto out            ; conditional jump
//!     call map_lookup_elem           ; helper by name (or `call 1`)
//!     call subprog                   ; bpf-to-bpf call to a local label
//! out:
//!     exit
//! ```

use crate::insn::*;
use crate::maps::{MapDef, MapKind};
use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};

#[derive(Debug)]
pub struct AsmError {
    pub line: usize,
    pub msg: String,
}

impl core::fmt::Display for AsmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "line {}: {}", self.line, self.msg)
    }
}
impl core::error::Error for AsmError {}

/// Result of assembling a source file.
pub struct Assembled {
    pub insns: Vec<Insn>,
    pub maps: Vec<MapDef>,
    /// label -> instruction index
    pub labels: BTreeMap<String, usize>,
}

const OPERATORS: &[&str] = &[
    "s>>=", "<<=", ">>=", "s/=", "s%=", "s<=", "s>=", "+=", "-=", "*=", "/=", "|=", "&=", "%=",
    "^=", "==", "!=", "<=", ">=", "s<", "s>", "=", "<", ">", "&", "(", ")", "*", "+", "-", ":",
    ",", "[", "]",
];

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Num(i64),
    Op(&'static str),
}

fn strip_comment(line: &str) -> &str {
    let mut end = line.len();
    for pat in [";", "#", "//"] {
        if let Some(i) = line.find(pat) {
            end = end.min(i);
        }
    }
    &line[..end]
}

fn tokenize(line: &str) -> Result<Vec<Tok>, String> {
    let mut toks = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    'outer: while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' || c == '.' {
            let start = i;
            while i < bytes.len()
                && ((bytes[i] as char).is_ascii_alphanumeric()
                    || bytes[i] == b'_'
                    || bytes[i] == b'.')
            {
                i += 1;
            }
            let word = &line[start..i];
            // `s>` / `s<` style operators would have been consumed as idents
            // only if standalone `s` is followed by symbol - handled below by
            // checking operators first for 's'-prefixed ones.
            toks.push(Tok::Ident(word.to_string()));
            continue;
        }
        if c.is_ascii_digit() {
            let start = i;
            if c == '0' && i + 1 < bytes.len() && (bytes[i + 1] | 0x20) == b'x' {
                i += 2;
                while i < bytes.len()
                    && ((bytes[i] as char).is_ascii_hexdigit() || bytes[i] == b'_')
                {
                    i += 1;
                }
                let digits: String = line[start + 2..i].chars().filter(|c| *c != '_').collect();
                let v = u64::from_str_radix(&digits, 16)
                    .map_err(|e| format!("bad hex number: {e}"))?;
                toks.push(Tok::Num(v as i64));
            } else {
                while i < bytes.len()
                    && ((bytes[i] as char).is_ascii_digit() || bytes[i] == b'_')
                {
                    i += 1;
                }
                let digits: String = line[start..i].chars().filter(|c| *c != '_').collect();
                let v: i64 = digits
                    .parse()
                    .map_err(|e| format!("bad number: {e}"))?;
                toks.push(Tok::Num(v));
            }
            continue;
        }
        for op in OPERATORS {
            if line[i..].starts_with(op) {
                toks.push(Tok::Op(op));
                i += op.len();
                continue 'outer;
            }
        }
        // ignore disassembler annotations like `<12>`
        if c == '<' {
            if let Some(j) = line[i..].find('>') {
                i += j + 1;
                continue;
            }
        }
        return Err(format!("unexpected character '{c}'"));
    }
    // Merge Ident("s") + comparison ops back: tokenizer above already treats
    // "s>=" etc. as operators only when they start at a symbol boundary. An
    // identifier like `s` followed by `>` never occurs in valid input except
    // as a signed operator, and OPERATORS handles those before identifiers
    // only when the char isn't alphabetic. Fix up here:
    let mut merged: Vec<Tok> = Vec::with_capacity(toks.len());
    let mut it = toks.into_iter().peekable();
    while let Some(t) = it.next() {
        if let Tok::Ident(ref s) = t {
            if s == "s" {
                if let Some(Tok::Op(op)) = it.peek() {
                    let combined = match *op {
                        ">>=" => Some("s>>="),
                        "/=" => Some("s/="),
                        "%=" => Some("s%="),
                        "<=" => Some("s<="),
                        ">=" => Some("s>="),
                        "<" => Some("s<"),
                        ">" => Some("s>"),
                        _ => None,
                    };
                    if let Some(cop) = combined {
                        it.next();
                        merged.push(Tok::Op(cop));
                        continue;
                    }
                }
            }
        }
        merged.push(t);
    }
    Ok(merged)
}

/// Pending fixup for a label reference.
struct Fixup {
    insn_idx: usize,
    label: String,
    line: usize,
    /// true → patch `imm` (gotol/local call), false → patch `off`
    wide: bool,
}

struct Parser<'a> {
    toks: &'a [Tok],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn next(&mut self) -> Result<&Tok, String> {
        let t = self.toks.get(self.pos).ok_or("unexpected end of line")?;
        self.pos += 1;
        Ok(t)
    }
    fn expect_op(&mut self, op: &str) -> Result<(), String> {
        match self.next()? {
            Tok::Op(o) if *o == op => Ok(()),
            t => Err(format!("expected '{op}', got {t:?}")),
        }
    }
    fn expect_ident(&mut self) -> Result<String, String> {
        match self.next()? {
            Tok::Ident(s) => Ok(s.clone()),
            t => Err(format!("expected identifier, got {t:?}")),
        }
    }
    /// Parse a possibly-negated integer.
    fn number(&mut self) -> Result<i64, String> {
        match self.next()? {
            Tok::Num(n) => Ok(*n),
            Tok::Op("-") => match self.next()? {
                Tok::Num(n) => Ok(-*n),
                t => Err(format!("expected number after '-', got {t:?}")),
            },
            Tok::Op("+") => match self.next()? {
                Tok::Num(n) => Ok(*n),
                t => Err(format!("expected number after '+', got {t:?}")),
            },
            t => Err(format!("expected number, got {t:?}")),
        }
    }
}

/// Parse `rN`/`wN`; returns (reg, is32).
fn parse_reg_name(s: &str) -> Option<(u8, bool)> {
    let (is32, rest) = match s.strip_prefix('r') {
        Some(r) => (false, r),
        None => (true, s.strip_prefix('w')?),
    };
    let n: u8 = rest.parse().ok()?;
    (n < NUM_REGS as u8).then_some((n, is32))
}

fn mem_size_of(name: &str) -> Option<(u8, bool)> {
    match name {
        "u8" => Some((size::B, false)),
        "u16" => Some((size::H, false)),
        "u32" => Some((size::W, false)),
        "u64" => Some((size::DW, false)),
        "s8" => Some((size::B, true)),
        "s16" => Some((size::H, true)),
        "s32" => Some((size::W, true)),
        _ => None,
    }
}

/// Parse `*(SIZE *)(rN [± off])` returning (size_bits, signed, reg, off).
fn parse_mem_ref(p: &mut Parser) -> Result<(u8, bool, u8, i16), String> {
    p.expect_op("*")?;
    p.expect_op("(")?;
    let ty = p.expect_ident()?;
    let (sz, signed) = mem_size_of(&ty).ok_or(format!("bad memory size '{ty}'"))?;
    p.expect_op("*")?;
    p.expect_op(")")?;
    p.expect_op("(")?;
    let rname = p.expect_ident()?;
    let (reg, is32) = parse_reg_name(&rname).ok_or(format!("bad register '{rname}'"))?;
    if is32 {
        return Err("memory operands need 64-bit registers (rN)".into());
    }
    let off = match p.peek() {
        Some(Tok::Op(")")) => 0i64,
        _ => p.number()?,
    };
    p.expect_op(")")?;
    let off: i16 = off
        .try_into()
        .map_err(|_| format!("offset {off} out of i16 range"))?;
    Ok((sz, signed, reg, off))
}

fn cond_op(op: &str) -> Option<u8> {
    Some(match op {
        "==" => jmp::JEQ,
        "!=" => jmp::JNE,
        ">" => jmp::JGT,
        ">=" => jmp::JGE,
        "<" => jmp::JLT,
        "<=" => jmp::JLE,
        "s>" => jmp::JSGT,
        "s>=" => jmp::JSGE,
        "s<" => jmp::JSLT,
        "s<=" => jmp::JSLE,
        "&" => jmp::JSET,
        _ => return None,
    })
}

fn alu_op_of(op: &str) -> Option<(u8, i16)> {
    Some(match op {
        "+=" => (alu::ADD, 0),
        "-=" => (alu::SUB, 0),
        "*=" => (alu::MUL, 0),
        "/=" => (alu::DIV, 0),
        "s/=" => (alu::DIV, 1),
        "|=" => (alu::OR, 0),
        "&=" => (alu::AND, 0),
        "<<=" => (alu::LSH, 0),
        ">>=" => (alu::RSH, 0),
        "%=" => (alu::MOD, 0),
        "s%=" => (alu::MOD, 1),
        "^=" => (alu::XOR, 0),
        "s>>=" => (alu::ARSH, 0),
        _ => return None,
    })
}

pub fn assemble(source: &str) -> Result<Assembled, AsmError> {
    let mut insns: Vec<Insn> = Vec::new();
    let mut maps: Vec<MapDef> = Vec::new();
    let mut map_ids: BTreeMap<String, u32> = BTreeMap::new();
    let mut labels: BTreeMap<String, usize> = BTreeMap::new();
    let mut fixups: Vec<Fixup> = Vec::new();

    for (lineno, raw) in source.lines().enumerate() {
        let lineno = lineno + 1;
        let err = |msg: String| AsmError { line: lineno, msg };
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let toks = tokenize(line).map_err(err)?;
        let mut p = Parser {
            toks: &toks,
            pos: 0,
        };

        // label definition: `name:`
        if toks.len() == 2 {
            if let (Tok::Ident(name), Tok::Op(":")) = (&toks[0], &toks[1]) {
                if labels.insert(name.clone(), insns.len()).is_some() {
                    return Err(err(format!("duplicate label '{name}'")));
                }
                continue;
            }
        }

        let result: Result<(), String> = (|| {
            let first = p.next()?.clone();
            match first {
                Tok::Ident(w) if w == ".map" => {
                    // .map name kind key_size value_size max_entries [inner_map] [ro]
                    let name = p.expect_ident()?;
                    let kind_s = p.expect_ident()?;
                    let kind = match kind_s.as_str() {
                        "array" => MapKind::Array,
                        "hash" => MapKind::Hash,
                        "percpu_array" => MapKind::PerCpuArray,
                        "percpu_hash" => MapKind::PerCpuHash,
                        "lru_hash" => MapKind::LruHash,
                        "ringbuf" => MapKind::RingBuf,
                        "perf_event_array" => MapKind::PerfEventArray,
                        "cgroup_array" => MapKind::CgroupArray,
                        "stack_trace" => MapKind::StackTrace,
                        "prog_array" => MapKind::ProgArray,
                        "array_of_maps" => MapKind::ArrayOfMaps,
                        "devmap" => MapKind::DevMap,
                        "cpumap" => MapKind::CpuMap,
                        "devmap_hash" => MapKind::DevMapHash,
                        _ => return Err(format!("unknown map kind '{kind_s}'")),
                    };
                    let key_size = p.number()? as u32;
                    let value_size = p.number()? as u32;
                    let max_entries = p.number()? as u32;
                    let inner_map_idx = if kind == MapKind::ArrayOfMaps {
                        let inner = p.expect_ident()?;
                        Some(
                            *map_ids.get(&inner).ok_or_else(|| {
                                format!("array_of_maps '{name}' references unknown map '{inner}'")
                            })?,
                        )
                    } else {
                        None
                    };
                    let readonly = match p.peek() {
                        Some(Tok::Ident(f)) if f == "ro" => {
                            p.next()?;
                            true
                        }
                        _ => false,
                    };
                    if map_ids.contains_key(&name) {
                        return Err(format!("duplicate map '{name}'"));
                    }
                    map_ids.insert(name.clone(), maps.len() as u32);
                    maps.push(MapDef {
                        name,
                        kind,
                        key_size,
                        value_size,
                        max_entries,
                        readonly,
                        init: Vec::new(),
                        inner_map_idx,
                        map_in_map_values: Vec::new(),
                    });
                    Ok(())
                }
                Tok::Ident(w) if w == "goto" => {
                    let idx = insns.len();
                    insns.push(Insn {
                        opcode: class::JMP | jmp::JA,
                        dst: 0,
                        src: 0,
                        off: 0,
                        imm: 0,
                    });
                    parse_jump_target(&mut p, idx, lineno, &mut insns, &mut fixups)?;
                    Ok(())
                }
                Tok::Ident(w) if w == "if" => {
                    let rname = p.expect_ident()?;
                    let (dst, is32) =
                        parse_reg_name(&rname).ok_or(format!("bad register '{rname}'"))?;
                    let op_tok = match p.next()? {
                        Tok::Op(o) => *o,
                        t => return Err(format!("expected comparison, got {t:?}")),
                    };
                    let cond = cond_op(op_tok).ok_or(format!("bad comparison '{op_tok}'"))?;
                    let cls = if is32 { class::JMP32 } else { class::JMP };
                    let (opcode, src_reg, imm) = match p.peek() {
                        Some(Tok::Ident(s)) if parse_reg_name(s).is_some() => {
                            let (sr, s32) = parse_reg_name(s).unwrap();
                            if s32 != is32 {
                                return Err("mixed 32/64-bit comparison operands".into());
                            }
                            p.next()?;
                            (cls | cond | src::X, sr, 0)
                        }
                        _ => {
                            let v = p.number()?;
                            let v: i32 = v
                                .try_into()
                                .map_err(|_| format!("immediate {v} out of i32 range"))?;
                            (cls | cond | src::K, 0, v)
                        }
                    };
                    match p.next()? {
                        Tok::Ident(g) if g == "goto" => {}
                        t => return Err(format!("expected 'goto', got {t:?}")),
                    }
                    let idx = insns.len();
                    insns.push(Insn {
                        opcode,
                        dst,
                        src: src_reg,
                        off: 0,
                        imm,
                    });
                    parse_cond_target(&mut p, idx, lineno, &mut insns, &mut fixups)?;
                    Ok(())
                }
                Tok::Ident(w) if w == "call" => {
                    match p.next()? {
                        Tok::Num(n) => {
                            insns.push(Insn {
                                opcode: class::JMP | jmp::CALL,
                                dst: 0,
                                src: call_kind::HELPER,
                                off: 0,
                                imm: *n as i32,
                            });
                        }
                        Tok::Ident(name) if name == "pc" => {
                            // `call pc+N` (disassembler form of a local call)
                            let rel = p.number()?;
                            insns.push(Insn {
                                opcode: class::JMP | jmp::CALL,
                                dst: 0,
                                src: call_kind::LOCAL,
                                off: 0,
                                imm: rel
                                    .try_into()
                                    .map_err(|_| format!("call offset {rel} out of range"))?,
                            });
                        }
                        Tok::Ident(name) => {
                            if let Some(id) = crate::helpers::helper_id(name) {
                                insns.push(Insn {
                                    opcode: class::JMP | jmp::CALL,
                                    dst: 0,
                                    src: call_kind::HELPER,
                                    off: 0,
                                    imm: id as i32,
                                });
                            } else {
                                // local (bpf-to-bpf) call to a label
                                let idx = insns.len();
                                fixups.push(Fixup {
                                    insn_idx: idx,
                                    label: name.clone(),
                                    line: lineno,
                                    wide: true,
                                });
                                insns.push(Insn {
                                    opcode: class::JMP | jmp::CALL,
                                    dst: 0,
                                    src: call_kind::LOCAL,
                                    off: 0,
                                    imm: 0,
                                });
                            }
                        }
                        t => return Err(format!("expected helper or label, got {t:?}")),
                    }
                    Ok(())
                }
                Tok::Ident(w) if w.starts_with("ldabs") || w.starts_with("ldind") => {
                    let (m, suffix) = if let Some(suffix) = w.strip_prefix("ldabs") {
                        (mode::ABS, suffix)
                    } else {
                        (mode::IND, w.strip_prefix("ldind").unwrap())
                    };
                    let sz = match suffix {
                        "b" => size::B,
                        "h" => size::H,
                        "w" => size::W,
                        "dw" => size::DW,
                        _ => return Err(format!("bad legacy packet-load mnemonic '{w}'")),
                    };
                    let src_reg = if m == mode::IND {
                        let name = p.expect_ident()?;
                        let (reg, is32) = parse_reg_name(&name)
                            .ok_or(format!("bad packet index register '{name}'"))?;
                        if is32 {
                            return Err("packet index needs a 64-bit register (rN)".into());
                        }
                        p.expect_op(",")?;
                        reg
                    } else {
                        0
                    };
                    let offset = p.number()?;
                    let imm = i32::try_from(offset)
                        .map_err(|_| format!("packet offset {offset} out of i32 range"))?;
                    insns.push(Insn {
                        opcode: class::LD | m | sz,
                        dst: 0,
                        src: src_reg,
                        off: 0,
                        imm,
                    });
                    Ok(())
                }
                Tok::Ident(w) if w == "exit" => {
                    insns.push(Insn {
                        opcode: class::JMP | jmp::EXIT,
                        dst: 0,
                        src: 0,
                        off: 0,
                        imm: 0,
                    });
                    Ok(())
                }
                Tok::Ident(w) if w == "lock" => {
                    // lock *(uN *)(rD + off) OP= rS
                    let (sz, signed, dst, off) = parse_mem_ref(&mut p)?;
                    if signed || (sz != size::W && sz != size::DW) {
                        return Err("atomics require u32 or u64".into());
                    }
                    let op_tok = match p.next()? {
                        Tok::Op(o) => *o,
                        t => return Err(format!("expected atomic op, got {t:?}")),
                    };
                    let aop = match op_tok {
                        "+=" => atomic::ADD,
                        "|=" => atomic::OR,
                        "&=" => atomic::AND,
                        "^=" => atomic::XOR,
                        _ => return Err(format!("bad atomic op '{op_tok}'")),
                    };
                    let sname = p.expect_ident()?;
                    let (src_r, s32) =
                        parse_reg_name(&sname).ok_or(format!("bad register '{sname}'"))?;
                    if s32 {
                        return Err("atomics need 64-bit register names".into());
                    }
                    insns.push(Insn {
                        opcode: class::STX | mode::ATOMIC | sz,
                        dst,
                        src: src_r,
                        off,
                        imm: aop,
                    });
                    Ok(())
                }
                Tok::Op("*") => {
                    // store: *(uN *)(rD + off) = rS | imm
                    p.pos = 0;
                    let (sz, signed, dst, off) = parse_mem_ref(&mut p)?;
                    if signed {
                        return Err("stores cannot be sign-extending".into());
                    }
                    p.expect_op("=")?;
                    match p.peek() {
                        Some(Tok::Ident(s)) if parse_reg_name(s).is_some() => {
                            let (sr, _) = parse_reg_name(s).unwrap();
                            p.next()?;
                            insns.push(Insn {
                                opcode: class::STX | mode::MEM | sz,
                                dst,
                                src: sr,
                                off,
                                imm: 0,
                            });
                        }
                        _ => {
                            let v = p.number()?;
                            let v: i32 = v
                                .try_into()
                                .map_err(|_| format!("immediate {v} out of i32 range"))?;
                            insns.push(Insn {
                                opcode: class::ST | mode::MEM | sz,
                                dst,
                                src: 0,
                                off,
                                imm: v,
                            });
                        }
                    }
                    Ok(())
                }
                Tok::Ident(rname) if parse_reg_name(&rname).is_some() => {
                    let (dst, is32) = parse_reg_name(&rname).unwrap();
                    parse_reg_insn(&mut p, dst, is32, &map_ids, &mut insns)
                }
                t => Err(format!("cannot parse statement starting with {t:?}")),
            }
        })();
        result.map_err(|msg| AsmError { line: lineno, msg })?;
        // tolerate a trailing `<N>` target annotation (disassembler output)
        if p.toks.len() - p.pos == 3
            && p.toks[p.pos] == Tok::Op("<")
            && matches!(p.toks[p.pos + 1], Tok::Num(_))
            && p.toks[p.pos + 2] == Tok::Op(">")
        {
            p.pos += 3;
        }
        if let Some(t) = p.peek() {
            return Err(AsmError {
                line: lineno,
                msg: format!("trailing tokens after instruction, starting at {t:?}"),
            });
        }
    }

    // resolve label fixups
    for f in fixups {
        let target = *labels.get(&f.label).ok_or(AsmError {
            line: f.line,
            msg: format!("undefined label '{}'", f.label),
        })? as i64;
        let rel = target - f.insn_idx as i64 - 1;
        if f.wide {
            insns[f.insn_idx].imm = rel.try_into().map_err(|_| AsmError {
                line: f.line,
                msg: "jump target out of range".into(),
            })?;
        } else {
            insns[f.insn_idx].off = rel.try_into().map_err(|_| AsmError {
                line: f.line,
                msg: format!("jump to '{}' out of i16 range", f.label),
            })?;
        }
    }

    Ok(Assembled {
        insns,
        maps,
        labels,
    })
}

/// Target of an unconditional `goto`: label or ±N. Uses JMP|JA (16-bit off),
/// falling back to JMP32|JA (gotol) never needed at asm time since labels fit.
fn parse_jump_target(
    p: &mut Parser,
    idx: usize,
    line: usize,
    insns: &mut [Insn],
    fixups: &mut Vec<Fixup>,
) -> Result<(), String> {
    match p.peek() {
        Some(Tok::Ident(l)) => {
            let l = l.clone();
            p.next()?;
            fixups.push(Fixup {
                insn_idx: idx,
                label: l,
                line,
                wide: false,
            });
        }
        _ => {
            let rel = p.number()?;
            insns[idx].off = rel
                .try_into()
                .map_err(|_| format!("offset {rel} out of i16 range"))?;
        }
    }
    Ok(())
}

fn parse_cond_target(
    p: &mut Parser,
    idx: usize,
    line: usize,
    insns: &mut [Insn],
    fixups: &mut Vec<Fixup>,
) -> Result<(), String> {
    parse_jump_target(p, idx, line, insns, fixups)
}

/// Parse instructions of the form `rD ...` / `wD ...`.
fn parse_reg_insn(
    p: &mut Parser,
    dst: u8,
    is32: bool,
    map_ids: &BTreeMap<String, u32>,
    insns: &mut Vec<Insn>,
) -> Result<(), String> {
    let alu_cls = if is32 { class::ALU } else { class::ALU64 };
    let op_tok = match p.next()? {
        Tok::Op(o) => *o,
        t => return Err(format!("expected operator, got {t:?}")),
    };

    if op_tok == "=" {
        return parse_assignment(p, dst, is32, alu_cls, map_ids, insns);
    }
    let (aop, off) = alu_op_of(op_tok).ok_or(format!("bad ALU operator '{op_tok}'"))?;
    match p.peek() {
        Some(Tok::Ident(s)) if parse_reg_name(s).is_some() => {
            let (sr, s32) = parse_reg_name(s).unwrap();
            if s32 != is32 {
                return Err("mixed 32/64-bit ALU operands".into());
            }
            p.next()?;
            insns.push(Insn {
                opcode: alu_cls | aop | src::X,
                dst,
                src: sr,
                off,
                imm: 0,
            });
        }
        _ => {
            let v = p.number()?;
            let v: i32 = v
                .try_into()
                .map_err(|_| format!("immediate {v} out of i32 range"))?;
            insns.push(Insn {
                opcode: alu_cls | aop | src::K,
                dst,
                src: 0,
                off,
                imm: v,
            });
        }
    }
    Ok(())
}

fn parse_assignment(
    p: &mut Parser,
    dst: u8,
    is32: bool,
    alu_cls: u8,
    map_ids: &BTreeMap<String, u32>,
    insns: &mut Vec<Insn>,
) -> Result<(), String> {
    match p.peek().cloned() {
        // rD = -rD  (negate)
        Some(Tok::Op("-")) if matches!(p.toks.get(p.pos + 1), Some(Tok::Ident(s)) if parse_reg_name(s).is_some()) =>
        {
            p.next()?;
            let s = p.expect_ident()?;
            let (sr, _) = parse_reg_name(&s).unwrap();
            if sr != dst {
                return Err("negation must be of the destination register itself".into());
            }
            insns.push(Insn {
                opcode: alu_cls | alu::NEG,
                dst,
                src: 0,
                off: 0,
                imm: 0,
            });
            Ok(())
        }
        // rD = <num> [ll]
        Some(Tok::Op("-")) | Some(Tok::Op("+")) | Some(Tok::Num(_)) => {
            let v = p.number()?;
            let wide = matches!(p.peek(), Some(Tok::Ident(s)) if s == "ll");
            if wide {
                p.next()?;
                if is32 {
                    return Err("lddw needs a 64-bit register (rN)".into());
                }
                let v = v as u64;
                insns.push(Insn {
                    opcode: class::LD | mode::IMM | size::DW,
                    dst,
                    src: pseudo::IMM64,
                    off: 0,
                    imm: v as u32 as i32,
                });
                insns.push(Insn {
                    opcode: 0,
                    dst: 0,
                    src: 0,
                    off: 0,
                    imm: (v >> 32) as u32 as i32,
                });
            } else {
                let v: i32 = v
                    .try_into()
                    .map_err(|_| format!("immediate {v} out of i32 range (use `ll`)"))?;
                insns.push(Insn {
                    opcode: alu_cls | alu::MOV | src::K,
                    dst,
                    src: 0,
                    off: 0,
                    imm: v,
                });
            }
            Ok(())
        }
        // rD = *(uN *)(rS + off)  (load)
        Some(Tok::Op("*")) => {
            let (sz, signed, src_r, off) = parse_mem_ref(p)?;
            if is32 {
                return Err("loads write 64-bit registers (rN)".into());
            }
            let m = if signed { mode::MEMSX } else { mode::MEM };
            insns.push(Insn {
                opcode: class::LDX | m | sz,
                dst,
                src: src_r,
                off,
                imm: 0,
            });
            Ok(())
        }
        // rD = (sN)rS  (movsx)
        Some(Tok::Op("(")) => {
            p.next()?;
            let ty = p.expect_ident()?;
            let bits: i16 = match ty.as_str() {
                "s8" => 8,
                "s16" => 16,
                "s32" => 32,
                _ => return Err(format!("bad movsx type '({ty})'")),
            };
            p.expect_op(")")?;
            let s = p.expect_ident()?;
            let (sr, s32) = parse_reg_name(&s).ok_or(format!("bad register '{s}'"))?;
            if s32 != is32 {
                return Err("mixed 32/64-bit movsx operands".into());
            }
            if is32 && bits == 32 {
                return Err("(s32) movsx needs 64-bit destination".into());
            }
            insns.push(Insn {
                opcode: alu_cls | alu::MOV | src::X,
                dst,
                src: sr,
                off: bits,
                imm: 0,
            });
            Ok(())
        }
        Some(Tok::Ident(word)) => {
            // register move, byteswap, map ref, or atomic fetch call
            if let Some((sr, s32)) = parse_reg_name(&word) {
                if s32 != is32 {
                    return Err("mixed 32/64-bit move operands".into());
                }
                p.next()?;
                insns.push(Insn {
                    opcode: alu_cls | alu::MOV | src::X,
                    dst,
                    src: sr,
                    off: 0,
                    imm: 0,
                });
                return Ok(());
            }
            match word.as_str() {
                "map" => {
                    p.next()?;
                    p.expect_op("[")?;
                    let name = p.expect_ident()?;
                    p.expect_op("]")?;
                    let id = *map_ids
                        .get(&name)
                        .ok_or(format!("unknown map '{name}' (declare with .map)"))?;
                    if is32 {
                        return Err("map loads need a 64-bit register".into());
                    }
                    // `map[name]` = map object pointer;
                    // `map[name][0] + off` = pointer into the first value.
                    let (src_reg, value_off) = if matches!(p.peek(), Some(Tok::Op("["))) {
                        p.next()?;
                        let elem = p.number()?;
                        if elem != 0 {
                            return Err("direct value access only supports element 0".into());
                        }
                        p.expect_op("]")?;
                        let off = if matches!(p.peek(), Some(Tok::Op("+"))) {
                            p.next()?;
                            p.number()?
                        } else {
                            0
                        };
                        (pseudo::MAP_VALUE, off as i32)
                    } else {
                        (pseudo::MAP_ID, 0)
                    };
                    insns.push(Insn {
                        opcode: class::LD | mode::IMM | size::DW,
                        dst,
                        src: src_reg,
                        off: 0,
                        imm: id as i32,
                    });
                    insns.push(Insn {
                        opcode: 0,
                        dst: 0,
                        src: 0,
                        off: 0,
                        imm: value_off,
                    });
                    Ok(())
                }
                w if w.starts_with("bswap") || w.starts_with("be") || w.starts_with("le") => {
                    p.next()?;
                    let (kind, num) = if let Some(n) = w.strip_prefix("bswap") {
                        ("bswap", n)
                    } else if let Some(n) = w.strip_prefix("be") {
                        ("be", n)
                    } else {
                        ("le", w.strip_prefix("le").unwrap())
                    };
                    let bits: i32 = num.parse().map_err(|_| format!("bad swap width '{w}'"))?;
                    if !matches!(bits, 16 | 32 | 64) {
                        return Err(format!("bad swap width {bits}"));
                    }
                    let s = p.expect_ident()?;
                    let (sr, _) = parse_reg_name(&s).ok_or(format!("bad register '{s}'"))?;
                    if sr != dst {
                        return Err("byte swap operates on the destination register".into());
                    }
                    let opcode = match kind {
                        "bswap" => class::ALU64 | alu::END | src::X,
                        "be" => class::ALU | alu::END | src::X,
                        _ => class::ALU | alu::END | src::K,
                    };
                    insns.push(Insn {
                        opcode,
                        dst,
                        src: 0,
                        off: 0,
                        imm: bits,
                    });
                    Ok(())
                }
                w if w.starts_with("atomic_fetch_") || w == "xchg" || w == "cmpxchg" => {
                    p.next()?;
                    let aop = match w {
                        "atomic_fetch_add" => atomic::ADD | atomic::FETCH,
                        "atomic_fetch_or" => atomic::OR | atomic::FETCH,
                        "atomic_fetch_and" => atomic::AND | atomic::FETCH,
                        "atomic_fetch_xor" => atomic::XOR | atomic::FETCH,
                        "xchg" => atomic::XCHG,
                        "cmpxchg" => atomic::CMPXCHG,
                        _ => return Err(format!("unknown atomic '{w}'")),
                    };
                    // (uN *)(rB + off), [r0,] rS )
                    p.expect_op("(")?;
                    p.expect_op("(")?;
                    let ty = p.expect_ident()?;
                    let (sz, signed) = mem_size_of(&ty).ok_or(format!("bad size '{ty}'"))?;
                    if signed || (sz != size::W && sz != size::DW) {
                        return Err("atomics require u32 or u64".into());
                    }
                    p.expect_op("*")?;
                    p.expect_op(")")?;
                    p.expect_op("(")?;
                    let bname = p.expect_ident()?;
                    let (base, _) =
                        parse_reg_name(&bname).ok_or(format!("bad register '{bname}'"))?;
                    let off = match p.peek() {
                        Some(Tok::Op(")")) => 0i64,
                        _ => p.number()?,
                    };
                    p.expect_op(")")?;
                    p.expect_op(",")?;
                    let mut sname = p.expect_ident()?;
                    if aop == atomic::CMPXCHG {
                        // syntax: r0 = cmpxchg((uN *)(rB+off), r0, rS)
                        if sname != "r0" {
                            return Err("cmpxchg compare operand must be r0".into());
                        }
                        p.expect_op(",")?;
                        sname = p.expect_ident()?;
                    }
                    let (src_r, _) =
                        parse_reg_name(&sname).ok_or(format!("bad register '{sname}'"))?;
                    p.expect_op(")")?;
                    if aop == atomic::CMPXCHG {
                        if dst != 0 {
                            return Err("cmpxchg result goes to r0".into());
                        }
                    } else if src_r != dst {
                        return Err(format!(
                            "atomic result register must match source (r{src_r})"
                        ));
                    }
                    let off: i16 = off
                        .try_into()
                        .map_err(|_| format!("offset {off} out of i16 range"))?;
                    insns.push(Insn {
                        opcode: class::STX | mode::ATOMIC | sz,
                        dst: base,
                        src: src_r,
                        off,
                        imm: aop,
                    });
                    Ok(())
                }
                _ => Err(format!("cannot parse '{word}'")),
            }
        }
        t => Err(format!("cannot parse assignment source {t:?}")),
    }
}
