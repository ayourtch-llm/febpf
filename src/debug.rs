//! Interactive debugger: breakpoints, single-stepping, register / stack /
//! memory / map inspection, and execution tracing.

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

fn parse_num(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn print_insn(m: &Machine, pc: usize) {
    let insns = m.vm_ref().insns();
    if pc < insns.len() {
        println!("{pc:4}: {}", disasm_insn(insns, pc));
    } else {
        println!("{pc:4}: <out of bounds>");
    }
}

fn print_regs(m: &Machine) {
    for row in 0..3 {
        let mut line = String::new();
        for col in 0..4 {
            let r = row * 4 + col;
            if r > 10 {
                break;
            }
            line.push_str(&format!("r{r:<2}= {:#018x}  ", m.regs[r]));
        }
        println!("{}", line.trim_end());
    }
    println!(
        "pc = {}  frame = {}  insns executed = {}",
        m.pc,
        m.current_frame(),
        m.insn_count
    );
}

fn hexdump(bytes: &[u8], base: u64) {
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
        println!("{:#010x}: {hex:<48} |{ascii}|", base + (i * 16) as u64);
    }
}

const HELP: &str = "\
commands:
  s, step [N]        execute N instructions (default 1)
  c, continue        run until breakpoint, exit or error
  b, break <pc>      set breakpoint at instruction index
  d, delete <pc>     remove breakpoint
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

/// Run an interactive debugging session for `vm` with context `ctx`.
/// Returns the program's r0 if it ran to completion.
pub fn repl(vm: &mut Vm, ctx: &mut [u8], opts: DebuggerOpts) -> io::Result<Option<u64>> {
    vm.echo_printk = opts.echo_printk;
    let mut breakpoints: HashSet<usize> = HashSet::new();
    let mut trace = false;
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    let mut m = vm.machine(ctx);
    println!("febpf debugger — type 'help' for commands");
    print_insn(&m, m.pc);

    loop {
        print!("(febpf) ");
        io::stdout().flush()?;
        let line = match lines.next() {
            Some(l) => l?,
            None => return Ok(None), // EOF
        };
        let mut it = line.split_whitespace();
        let cmd = it.next().unwrap_or("");
        let arg1 = it.next();
        let arg2 = it.next();

        match cmd {
            "" => {}
            "help" | "h" | "?" => print!("{HELP}"),
            "q" | "quit" | "exit" => return Ok(None),
            "s" | "step" => {
                let n = arg1.and_then(parse_num).unwrap_or(1);
                for _ in 0..n {
                    if trace {
                        print_insn(&m, m.pc);
                    }
                    match m.step() {
                        Ok(Some(r0)) => {
                            println!("program exited with r0 = {r0} ({r0:#x})");
                            return Ok(Some(r0));
                        }
                        Ok(None) => {}
                        Err(e) => {
                            println!("{e}");
                            break;
                        }
                    }
                    if breakpoints.contains(&m.pc) {
                        println!("breakpoint hit at {}", m.pc);
                        break;
                    }
                }
                print_insn(&m, m.pc);
            }
            "c" | "continue" | "run" => loop {
                if trace {
                    print_insn(&m, m.pc);
                }
                match m.step() {
                    Ok(Some(r0)) => {
                        println!("program exited with r0 = {r0} ({r0:#x})");
                        return Ok(Some(r0));
                    }
                    Ok(None) => {}
                    Err(e) => {
                        println!("{e}");
                        print_insn(&m, m.pc);
                        break;
                    }
                }
                if breakpoints.contains(&m.pc) {
                    println!("breakpoint hit at {}", m.pc);
                    print_insn(&m, m.pc);
                    break;
                }
            },
            "b" | "break" => match arg1.and_then(parse_num) {
                Some(pc) => {
                    breakpoints.insert(pc as usize);
                    println!("breakpoint set at {pc}");
                }
                None => println!("usage: break <pc>"),
            },
            "d" | "delete" => match arg1.and_then(parse_num) {
                Some(pc) => {
                    breakpoints.remove(&(pc as usize));
                }
                None => {
                    breakpoints.clear();
                    println!("all breakpoints removed");
                }
            },
            "i" | "info" => {
                let mut bps: Vec<_> = breakpoints.iter().collect();
                bps.sort();
                println!("breakpoints: {bps:?}");
            }
            "r" | "regs" => print_regs(&m),
            "l" | "list" => {
                let insns = m.vm_ref().insns();
                let center = arg1
                    .and_then(parse_num)
                    .map(|v| v as usize)
                    .unwrap_or(m.pc);
                let lo = center.saturating_sub(5);
                let mut pc = lo;
                // align to instruction boundary from 0 if lddw slots interfere
                while pc <= (center + 6).min(insns.len().saturating_sub(1)) {
                    let marker = if pc == m.pc { "=>" } else { "  " };
                    let bp = if breakpoints.contains(&pc) { "*" } else { " " };
                    println!("{marker}{bp}{pc:4}: {}", disasm_insn(insns, pc));
                    pc += if insns[pc].is_wide() { 2 } else { 1 };
                }
            }
            "x" => match arg1.and_then(parse_num) {
                Some(addr) => {
                    let len = arg2.and_then(parse_num).unwrap_or(64) as usize;
                    match m.read_mem(addr, len) {
                        Ok(bytes) => hexdump(&bytes, addr),
                        Err(e) => println!("{e}"),
                    }
                }
                None => println!("usage: x <addr> [len]"),
            },
            "stack" => {
                let fp = m.regs[10];
                let base = fp - crate::insn::STACK_SIZE as u64;
                match m.read_mem(base, crate::insn::STACK_SIZE) {
                    Ok(bytes) => hexdump(&bytes, base),
                    Err(e) => println!("{e}"),
                }
            }
            "maps" => {
                for map in &m.vm_ref().maps {
                    println!(
                        "map '{}' ({}, key={}B value={}B max={}):",
                        map.def.name, map.def.kind, map.def.key_size, map.def.value_size,
                        map.def.max_entries
                    );
                    for (k, v) in map.iter_entries() {
                        let hex = |b: &[u8]| {
                            b.iter().map(|x| format!("{x:02x}")).collect::<String>()
                        };
                        println!("  [{}] = {}", hex(&k), hex(&v));
                    }
                }
            }
            "printk" => {
                for line in &m.vm_ref().printk {
                    println!("{line}");
                }
            }
            "t" | "trace" => {
                trace = !trace;
                println!("trace {}", if trace { "on" } else { "off" });
            }
            other => println!("unknown command '{other}' — try 'help'"),
        }
    }
}
