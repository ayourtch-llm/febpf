//! febpf command-line tool: assemble, disassemble, verify, analyze, run,
//! debug and benchmark eBPF programs.

use febpf::{analysis, asm, debug, disasm, insn, verifier, Program, Vm};
use std::process::ExitCode;
use std::time::Instant;

const USAGE: &str = "\
febpf — fast userland eBPF engine with verifier, debugger and analyzer

usage: febpf <command> [options] <file>

commands:
  asm <file.s> -o <out.bin>   assemble pseudo-C source to raw bytecode
  disasm <file>               disassemble a program
  verify <file>               run the verifier and report the result
  analyze <file>              CFG, stats, and verifier-annotated listing
  dot <file>                  print the control-flow graph in Graphviz DOT
  run <file>                  verify then execute
  debug <file>                interactive debugger (breakpoints, stepping)
  profile <file>              run and show a per-instruction heatmap
  bench <file>                measure interpreter throughput

options:
  --ctx <hex|@file>    context memory contents (hex string or file)
  --ctx-size <n>       context size in bytes (default 4096, or data length)
  --no-verify          run without verifying first (still memory-safe)
  --jit                compile to native code (run/bench; x86-64 Linux)
  --strict-align       verifier: require aligned memory accesses
  --readonly-ctx       verifier: forbid stores to the context
  --iters <n>          bench: iterations (default 1000)
  --prog <name>        select a program from a multi-program ELF object
  -o <file>            output file (asm)

input files ending in .s/.asm/.bpf are assembled; ELF objects from
`clang -target bpf` are loaded (maps + relocations); anything else is
treated as raw little-endian eBPF bytecode.
";

struct Opts {
    cmd: String,
    file: String,
    out: Option<String>,
    ctx_hex: Option<String>,
    ctx_size: Option<usize>,
    no_verify: bool,
    strict_align: bool,
    readonly_ctx: bool,
    iters: u64,
    jit: bool,
    prog: Option<String>,
}

fn parse_args() -> Result<Opts, String> {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().ok_or("missing command")?;
    let mut o = Opts {
        cmd,
        file: String::new(),
        out: None,
        ctx_hex: None,
        ctx_size: None,
        no_verify: false,
        strict_align: false,
        readonly_ctx: false,
        iters: 1000,
        jit: false,
        prog: None,
    };
    while let Some(a) = args.next() {
        match a.as_str() {
            "-o" => o.out = Some(args.next().ok_or("-o needs a value")?),
            "--ctx" => o.ctx_hex = Some(args.next().ok_or("--ctx needs a value")?),
            "--ctx-size" => {
                o.ctx_size = Some(
                    args.next()
                        .ok_or("--ctx-size needs a value")?
                        .parse()
                        .map_err(|e| format!("bad --ctx-size: {e}"))?,
                )
            }
            "--iters" => {
                o.iters = args
                    .next()
                    .ok_or("--iters needs a value")?
                    .parse()
                    .map_err(|e| format!("bad --iters: {e}"))?
            }
            "--no-verify" => o.no_verify = true,
            "--jit" => o.jit = true,
            "--prog" => o.prog = Some(args.next().ok_or("--prog needs a value")?),
            "--strict-align" => o.strict_align = true,
            "--readonly-ctx" => o.readonly_ctx = true,
            f if !f.starts_with('-') && o.file.is_empty() => o.file = f.to_string(),
            other => return Err(format!("unknown option '{other}'")),
        }
    }
    if o.file.is_empty() && o.cmd != "help" {
        return Err("missing input file".into());
    }
    Ok(o)
}

fn load_program(path: &str, prog: Option<&str>) -> Result<Program, String> {
    let is_source = [".s", ".asm", ".bpf"]
        .iter()
        .any(|ext| path.ends_with(ext));
    if is_source {
        let src =
            std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        let a = asm::assemble(&src).map_err(|e| format!("{path}: {e}"))?;
        return Ok(Program {
            insns: a.insns,
            maps: a.maps,
        });
    }
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    // ELF object (clang -target bpf) vs raw bytecode.
    if bytes.len() >= 4 && &bytes[0..4] == b"\x7fELF" {
        let obj = febpf::elf::load(&bytes).map_err(|e| format!("{path}: {e}"))?;
        let chosen = match prog {
            Some(name) => obj
                .programs
                .iter()
                .find(|p| p.name == name)
                .ok_or_else(|| {
                    let names: Vec<&str> = obj.programs.iter().map(|p| p.name.as_str()).collect();
                    format!("no program '{name}' in {path}; available: {}", names.join(", "))
                })?,
            None => &obj.programs[0],
        };
        if prog.is_none() && obj.programs.len() > 1 {
            let names: Vec<&str> = obj.programs.iter().map(|p| p.name.as_str()).collect();
            eprintln!(
                "note: {path} has {} programs ({}); using '{}' (--prog to choose)",
                obj.programs.len(),
                names.join(", "),
                chosen.name
            );
        }
        Ok(Program {
            insns: chosen.insns.clone(),
            maps: obj.maps,
        })
    } else {
        let insns = insn::decode_program(&bytes)?;
        Ok(Program {
            insns,
            maps: Vec::new(),
        })
    }
}

fn make_ctx(o: &Opts) -> Result<Vec<u8>, String> {
    let mut ctx = match &o.ctx_hex {
        Some(spec) => {
            if let Some(path) = spec.strip_prefix('@') {
                std::fs::read(path).map_err(|e| format!("cannot read ctx file: {e}"))?
            } else {
                let clean: String = spec.chars().filter(|c| !c.is_whitespace()).collect();
                if !clean.len().is_multiple_of(2) {
                    return Err("--ctx hex string must have even length".into());
                }
                (0..clean.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&clean[i..i + 2], 16))
                    .collect::<Result<Vec<u8>, _>>()
                    .map_err(|e| format!("bad --ctx hex: {e}"))?
            }
        }
        None => Vec::new(),
    };
    if let Some(sz) = o.ctx_size {
        ctx.resize(sz, 0);
    } else if ctx.is_empty() && o.ctx_hex.is_none() {
        ctx = vec![0u8; 4096];
    }
    Ok(ctx)
}

fn verifier_config(o: &Opts, ctx_len: usize) -> verifier::Config {
    verifier::Config {
        ctx_size: ctx_len,
        ctx_writable: !o.readonly_ctx,
        strict_alignment: o.strict_align,
        ..Default::default()
    }
}

fn run() -> Result<ExitCode, String> {
    let o = parse_args().map_err(|e| format!("{e}\n\n{USAGE}"))?;
    if o.cmd == "help" {
        print!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }
    let prog = load_program(&o.file, o.prog.as_deref())?;

    match o.cmd.as_str() {
        "asm" => {
            let out = o.out.as_deref().unwrap_or("out.bin");
            let bytes = insn::encode_program(&prog.insns);
            std::fs::write(out, &bytes).map_err(|e| format!("cannot write {out}: {e}"))?;
            println!(
                "wrote {} bytes ({} instruction slots) to {out}",
                bytes.len(),
                prog.insns.len()
            );
            if !prog.maps.is_empty() {
                println!(
                    "note: {} map definition(s) are not stored in raw bytecode",
                    prog.maps.len()
                );
            }
        }
        "disasm" => print!("{}", disasm::disasm_program(&prog.insns)),
        "verify" => {
            let ctx = make_ctx(&o)?;
            let vm = Vm::new(prog.clone())?;
            match vm.verify(verifier_config(&o, ctx.len())) {
                Ok(ok) => {
                    println!("verification PASSED");
                    print_verify_stats(&ok);
                }
                Err(e) => {
                    println!("verification FAILED: {e}");
                    let pc = e.pc.min(prog.insns.len().saturating_sub(1));
                    println!("  {pc:4}: {}", disasm::disasm_insn(&prog.insns, pc));
                    return Ok(ExitCode::FAILURE);
                }
            }
        }
        "analyze" => {
            let ctx = make_ctx(&o)?;
            let cfg = analysis::build_cfg(&prog.insns);
            let st = analysis::stats(&prog.insns, &cfg);
            println!("== program ==");
            println!(
                "  {} instructions ({} slots), {} basic blocks, {} subprogram(s), {} back edge(s)",
                st.insn_count, st.insn_slots, st.blocks, st.subprogs, st.back_edges
            );
            let mix: Vec<String> = st
                .class_histogram
                .iter()
                .map(|(k, v)| format!("{k}:{v}"))
                .collect();
            println!("  mix: {}", mix.join(" "));
            if !st.helpers.is_empty() {
                let names: Vec<String> = st
                    .helpers
                    .iter()
                    .map(|h| febpf::helpers::helper_name(*h))
                    .collect();
                println!("  helpers: {}", names.join(", "));
            }
            for m in &prog.maps {
                println!(
                    "  map '{}': {} key={}B value={}B max_entries={}",
                    m.name, m.kind, m.key_size, m.value_size, m.max_entries
                );
            }
            let vm = Vm::new(prog.clone())?;
            match vm.verify(verifier_config(&o, ctx.len())) {
                Ok(ok) => {
                    println!("\n== verifier ==");
                    println!("  PASSED");
                    print_verify_stats(&ok);
                    println!("\n== annotated listing (abstract state on first visit) ==");
                    print!("{}", analysis::annotated_listing(&prog.insns, &ok));
                }
                Err(e) => {
                    println!("\n== verifier ==");
                    println!("  FAILED: {e}");
                }
            }
        }
        "dot" => {
            let cfg = analysis::build_cfg(&prog.insns);
            print!("{}", analysis::cfg_to_dot(&prog.insns, &cfg));
        }
        "run" => {
            let mut ctx = make_ctx(&o)?;
            let mut vm = Vm::new(prog)?;
            vm.echo_printk = true;
            if o.no_verify {
                vm.insn_limit = 100_000_000;
            } else {
                vm.verify(verifier_config(&o, ctx.len())).map_err(|e| {
                    format!("verification failed: {e}\n(use --no-verify to run anyway)")
                })?;
            }
            if o.jit {
                vm.compile().map_err(|e| format!("JIT compile failed: {e}"))?;
            }
            let t0 = Instant::now();
            let r0 = if o.jit {
                vm.run_jit(&mut ctx)
            } else {
                vm.run(&mut ctx)
            }
            .map_err(|e| e.to_string())?;
            let dt = t0.elapsed();
            let how = if o.jit { "jit" } else { "interp" };
            println!("r0 = {r0} ({r0:#x})   [{how}, {dt:?}]");
        }
        "profile" => {
            let mut ctx = make_ctx(&o)?;
            let mut vm = Vm::new(prog.clone())?;
            vm.echo_printk = true;
            if !o.no_verify {
                vm.verify(verifier_config(&o, ctx.len()))
                    .map_err(|e| format!("verification failed: {e}"))?;
            } else {
                vm.insn_limit = 100_000_000;
            }
            vm.enable_profiling();
            let r0 = vm.run(&mut ctx).map_err(|e| e.to_string())?;
            let counts = vm.profile.take().unwrap();
            print!("{}", analysis::heatmap_listing(&prog.insns, &counts));
            println!("\nr0 = {r0} ({r0:#x})");
        }
        "debug" => {
            let mut ctx = make_ctx(&o)?;
            let mut vm = Vm::new(prog)?;
            if !o.no_verify {
                match vm.verify(verifier_config(&o, ctx.len())) {
                    Ok(_) => println!("verifier: PASSED"),
                    Err(e) => println!("verifier: FAILED: {e} (debugging anyway)"),
                }
            }
            debug::repl(&mut vm, &mut ctx, debug::DebuggerOpts::default())
                .map_err(|e| e.to_string())?;
        }
        "bench" => {
            let mut ctx = make_ctx(&o)?;
            let mut vm = Vm::new(prog)?;
            if !o.no_verify {
                vm.verify(verifier_config(&o, ctx.len()))
                    .map_err(|e| format!("verification failed: {e}"))?;
            }
            // warmup + count instructions once
            let mut m = vm.machine(&mut ctx);
            loop {
                if m.step().map_err(|e| e.to_string())?.is_some() {
                    break;
                }
            }
            let per_run = m.insn_count;
            drop(m);
            if o.jit {
                vm.compile().map_err(|e| format!("JIT compile failed: {e}"))?;
            }
            let t0 = Instant::now();
            for _ in 0..o.iters {
                if o.jit {
                    vm.run_jit(&mut ctx)
                } else {
                    vm.run(&mut ctx)
                }
                .map_err(|e| e.to_string())?;
            }
            let dt = t0.elapsed();
            let total_insns = per_run.saturating_mul(o.iters);
            let mips = total_insns as f64 / dt.as_secs_f64() / 1e6;
            let how = if o.jit { "jit" } else { "interp" };
            println!(
                "{} iterations, {} insns/run [{}], {:?} total ({:.1} ns/run) — {:.0} M insn/s",
                o.iters,
                per_run,
                how,
                dt,
                dt.as_nanos() as f64 / o.iters as f64,
                mips
            );
        }
        other => return Err(format!("unknown command '{other}'\n\n{USAGE}")),
    }
    Ok(ExitCode::SUCCESS)
}

fn print_verify_stats(ok: &verifier::VerifyOk) {
    let s = &ok.stats;
    println!(
        "  {} insns processed, {} states explored, {} pruned, max call depth {}, stack usage {}B",
        s.insns_processed, s.states_explored, s.states_pruned, s.max_frames, s.stack_usage
    );
    for w in &ok.warnings {
        println!("  warning: {w}");
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
