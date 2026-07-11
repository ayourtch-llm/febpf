//! febpf command-line tool: assemble, disassemble, verify, analyze, run,
//! debug and benchmark eBPF programs.

use febpf::debuginfo::DebugInfo;
use febpf::{analysis, asm, debug, disasm, insn, verifier, Program, Vm};
use std::process::ExitCode;
use std::time::Instant;

mod conftest;

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
  conftest <file>             run under interp, JIT and the real kernel; diff r0
  fuzz                        differential fuzzer: interp vs JIT (vs --kernel)
  vfuzz                       verifier differential: febpf vs kernel verdicts
  record <file> -o <out>      write a self-contained .febpf replay file
  replay <file.febpf>         load a replay file into the time-travel debugger
                              (or --run to just reproduce r0)
  race <file>                 explore interleavings of N instances sharing maps
                              and report concurrency races (lost updates, etc.)
  equiv <a> <b>               decide observable equivalence of two programs
  optimize <file> [-o out]    verifier-guided, equivalence-checked optimizer

options:
  --ctx <hex|@file>    context memory contents (hex string or file)
  --packet <file>      run an XDP program over raw packet bytes from file
  --ctx-size <n>       context size in bytes (default 4096, or data length)
  --no-verify          run without verifying first (still memory-safe)
  --no-explain         don't print the counterexample trace when rejected
  --jit                compile to native code (run/bench; x86-64 Linux, aarch64 macOS/Linux)
  --strict-align       verifier: require aligned memory accesses
  --readonly-ctx       verifier: forbid stores to the context
  --iters <n>          bench/fuzz: iterations (default 1000)
  --seed <n>           fuzz: PRNG seed (random if omitted; printed on failure)
  --kernel             conftest/fuzz/vfuzz: also diff against the real kernel (root)
  --frontier           vfuzz: use the verification-frontier generator (default)
  --conservative       vfuzz: use the conservative (fuzz) generator instead
  --stop-at <n>        record: store a debugger cursor at instruction count n
  --run                replay: reproduce r0 instead of opening the debugger
  --procs <n>          race: number of concurrent instances (default 2)
  --schedules <m>      race: cap on schedules explored (default 2000)
  --schedule <csv>     race: replay one interleaving (choice vector) verbatim
  --stats              race: print exploration statistics
  --prog <name>        select a program from a multi-program ELF object
  --target-btf <path>  CO-RE: relocate against this BTF (raw blob or ELF with
                       a .BTF section); defaults to /sys/kernel/btf/vmlinux
                       when present and the object has CO-RE relocations
  -o <file>            output file (asm)

input files ending in .s/.asm/.bpf are assembled; ELF objects from
`clang -target bpf` are loaded (maps + relocations); anything else is
treated as raw little-endian eBPF bytecode.
";

struct Opts {
    cmd: String,
    file: String,
    /// Second positional file (for `equiv <a> <b>`).
    file2: Option<String>,
    out: Option<String>,
    stats: bool,
    ctx_hex: Option<String>,
    packet: Option<String>,
    ctx_size: Option<usize>,
    no_verify: bool,
    no_explain: bool,
    strict_align: bool,
    readonly_ctx: bool,
    iters: u64,
    jit: bool,
    prog: Option<String>,
    target_btf: Option<String>,
    seed: Option<u64>,
    kernel: bool,
    conservative: bool,
    stop_at: Option<u64>,
    run: bool,
    procs: usize,
    schedules: usize,
    schedule: Option<String>,
}

fn parse_args() -> Result<Opts, String> {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().ok_or("missing command")?;
    let mut o = Opts {
        cmd,
        file: String::new(),
        file2: None,
        out: None,
        stats: false,
        ctx_hex: None,
        packet: None,
        ctx_size: None,
        no_verify: false,
        no_explain: false,
        strict_align: false,
        readonly_ctx: false,
        iters: 1000,
        jit: false,
        prog: None,
        target_btf: None,
        seed: None,
        kernel: false,
        conservative: false,
        stop_at: None,
        run: false,
        procs: 2,
        schedules: 2000,
        schedule: None,
    };
    while let Some(a) = args.next() {
        match a.as_str() {
            "-o" => o.out = Some(args.next().ok_or("-o needs a value")?),
            "--ctx" => o.ctx_hex = Some(args.next().ok_or("--ctx needs a value")?),
            "--packet" => o.packet = Some(args.next().ok_or("--packet needs a value")?),
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
            "--seed" => {
                o.seed = Some(
                    args.next()
                        .ok_or("--seed needs a value")?
                        .parse()
                        .map_err(|e| format!("bad --seed: {e}"))?,
                )
            }
            "--kernel" => o.kernel = true,
            "--frontier" => o.conservative = false,
            "--conservative" => o.conservative = true,
            "--stop-at" => {
                o.stop_at = Some(
                    args.next()
                        .ok_or("--stop-at needs a value")?
                        .parse()
                        .map_err(|e| format!("bad --stop-at: {e}"))?,
                )
            }
            "--run" => o.run = true,
            "--procs" => {
                o.procs = args
                    .next()
                    .ok_or("--procs needs a value")?
                    .parse()
                    .map_err(|e| format!("bad --procs: {e}"))?
            }
            "--schedules" => {
                o.schedules = args
                    .next()
                    .ok_or("--schedules needs a value")?
                    .parse()
                    .map_err(|e| format!("bad --schedules: {e}"))?
            }
            "--schedule" => o.schedule = Some(args.next().ok_or("--schedule needs a value")?),
            "--stats" => o.stats = true,
            "--no-verify" => o.no_verify = true,
            "--no-explain" => o.no_explain = true,
            "--jit" => o.jit = true,
            "--prog" => o.prog = Some(args.next().ok_or("--prog needs a value")?),
            "--target-btf" => {
                o.target_btf = Some(args.next().ok_or("--target-btf needs a value")?)
            }
            "--strict-align" => o.strict_align = true,
            "--readonly-ctx" => o.readonly_ctx = true,
            f if !f.starts_with('-') && o.file.is_empty() => o.file = f.to_string(),
            f if !f.starts_with('-') && o.file2.is_none() => o.file2 = Some(f.to_string()),
            other => return Err(format!("unknown option '{other}'")),
        }
    }
    if o.file.is_empty() && o.cmd != "help" && o.cmd != "fuzz" && o.cmd != "vfuzz" {
        return Err("missing input file".into());
    }
    Ok(o)
}

/// Compile the VM to native code, or report that this build has no JIT.
#[cfg(feature = "jit")]
fn jit_compile(vm: &mut Vm) -> Result<(), String> {
    vm.compile().map_err(|e| format!("JIT compile failed: {e}"))
}
#[cfg(not(feature = "jit"))]
fn jit_compile(_vm: &mut Vm) -> Result<(), String> {
    Err("this build has no JIT (rebuilt with --no-default-features)".into())
}

/// Run the VM, via the JIT when `jit` is set and this build supports it.
#[cfg(feature = "jit")]
fn run_maybe_jit(vm: &mut Vm, ctx: &mut [u8], jit: bool) -> Result<u64, febpf::EbpfError> {
    if jit {
        vm.run_jit(ctx)
    } else {
        vm.run(ctx)
    }
}
#[cfg(not(feature = "jit"))]
fn run_maybe_jit(vm: &mut Vm, ctx: &mut [u8], _jit: bool) -> Result<u64, febpf::EbpfError> {
    vm.run(ctx)
}

/// Read a target BTF for CO-RE: either a raw BTF blob (e.g.
/// /sys/kernel/btf/vmlinux) or an ELF object carrying a .BTF section.
fn read_target_btf(path: &str) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    if bytes.len() >= 4 && &bytes[0..4] == b"\x7fELF" {
        match febpf::elf::read_section(&bytes, ".BTF").map_err(|e| format!("{path}: {e}"))? {
            Some((btf, _)) => Ok(btf),
            None => Err(format!("{path}: no .BTF section")),
        }
    } else {
        Ok(bytes) // raw BTF blob; endianness is detected from its magic
    }
}

const VMLINUX_BTF: &str = "/sys/kernel/btf/vmlinux";

fn load_program(
    path: &str,
    prog: Option<&str>,
    target_btf: Option<&str>,
) -> Result<(Program, Option<DebugInfo>, bool), String> {
    let is_source = [".s", ".asm", ".bpf"]
        .iter()
        .any(|ext| path.ends_with(ext));
    if is_source {
        let src =
            std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        let a = asm::assemble(&src).map_err(|e| format!("{path}: {e}"))?;
        return Ok((
            Program {
                insns: a.insns,
                maps: a.maps,
                btf_ctx: None,
            },
            None,
            false,
        ));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    // ELF object (clang -target bpf) vs raw bytecode.
    if bytes.len() >= 4 && &bytes[0..4] == b"\x7fELF" {
        // An explicit --target-btf wins; otherwise default to the running
        // kernel's BTF when the object has CO-RE relocations or BTF-typed
        // (tp_btf/fentry/...) program sections.
        let target = match target_btf {
            Some(p) => Some(read_target_btf(p)?),
            None if febpf::elf::needs_kernel_btf(&bytes)
                && std::path::Path::new(VMLINUX_BTF).exists() =>
            {
                eprintln!("note: resolving CO-RE/BTF-typed sections against {VMLINUX_BTF} (--target-btf to override)");
                Some(read_target_btf(VMLINUX_BTF)?)
            }
            None => None,
        };
        let obj = febpf::elf::load_with_target_btf(&bytes, target.as_deref())
            .map_err(|e| format!("{path}: {e}"))?;
        for w in &obj.warnings {
            eprintln!("warning: {w}");
        }
        let idx = match prog {
            Some(name) => obj.programs.iter().position(|p| p.name == name).ok_or_else(|| {
                let names: Vec<&str> = obj.programs.iter().map(|p| p.name.as_str()).collect();
                format!("no program '{name}' in {path}; available: {}", names.join(", "))
            })?,
            None => 0,
        };
        if prog.is_none() && obj.programs.len() > 1 {
            let names: Vec<&str> = obj.programs.iter().map(|p| p.name.as_str()).collect();
            eprintln!(
                "note: {path} has {} programs ({}); using '{}' (--prog to choose)",
                obj.programs.len(),
                names.join(", "),
                obj.programs[idx].name
            );
        }
        let mut programs = obj.programs;
        let chosen = programs.swap_remove(idx);
        let xdp = chosen.xdp;
        Ok((
            Program {
                insns: chosen.insns,
                maps: obj.maps,
                btf_ctx: chosen.btf_ctx,
            },
            chosen.debug,
            xdp,
        ))
    } else {
        let insns = insn::decode_program(&bytes)?;
        Ok((
            Program {
                insns,
                maps: Vec::new(),
                btf_ctx: None,
            },
            None,
            false,
        ))
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

fn read_packet(o: &Opts) -> Result<Vec<u8>, String> {
    let path = o
        .packet
        .as_deref()
        .ok_or("XDP execution needs --packet <raw-packet-file>")?;
    std::fs::read(path).map_err(|e| format!("cannot read packet {path}: {e}"))
}

fn verifier_config(o: &Opts, ctx_len: usize, xdp: bool) -> verifier::Config {
    verifier::Config {
        ctx_size: ctx_len,
        ctx_writable: !o.readonly_ctx,
        strict_alignment: o.strict_align,
        xdp,
        ..Default::default()
    }
}

/// `febpf record <prog> [--ctx ...] [--stop-at N] -o out.febpf`
fn cmd_record(o: &Opts, prog: Program) -> Result<ExitCode, String> {
    let out = o
        .out
        .as_deref()
        .ok_or("record needs an output file: -o <out.febpf>")?;
    let ctx = make_ctx(o)?;
    let seed = febpf::interp::DEFAULT_PRANDOM_SEED;
    let replay = febpf::replay::Replay::record(&prog, ctx, seed, o.stop_at, Vec::new())?;
    let bytes = replay.to_bytes();
    std::fs::write(out, &bytes).map_err(|e| format!("cannot write {out}: {e}"))?;
    let outcome = match &replay.outcome {
        Some(febpf::replay::Outcome::Exit(r0)) => format!("r0 = {r0} ({r0:#x})"),
        Some(febpf::replay::Outcome::Error(msg)) => format!("error: {msg}"),
        None => "not captured".to_string(),
    };
    println!(
        "wrote {} bytes to {out} ({} insns, {} map(s), ctx {}B, {}) [{outcome}]",
        bytes.len(),
        replay.insns.len(),
        replay.maps.len(),
        replay.ctx.len(),
        match replay.stop_at {
            Some(n) => format!("cursor @ {n}"),
            None => "no cursor".to_string(),
        }
    );
    Ok(ExitCode::SUCCESS)
}

/// `febpf replay <file.febpf> [--run]`. Loads the replay, re-executes with the
/// recorded inputs, checks the determinism guard, and either prints r0
/// (`--run`) or drops into the time-travel debugger at the recorded cursor.
fn cmd_replay(o: &Opts) -> Result<ExitCode, String> {
    let bytes = std::fs::read(&o.file).map_err(|e| format!("cannot read {}: {e}", o.file))?;
    let replay = febpf::replay::Replay::from_bytes(&bytes)?;
    if replay.febpf_version != febpf::replay::febpf_version() {
        eprintln!(
            "note: replay recorded by febpf {} (this build is {})",
            replay.febpf_version,
            febpf::replay::febpf_version()
        );
    }
    let (mut vm, mut ctx) = replay.build_vm()?;

    if o.run {
        // Reproduce r0 and apply the determinism guard.
        vm.insn_limit = 100_000_000;
        let reproduced = vm.run(&mut ctx);
        let repro = match &reproduced {
            Ok(r0) => febpf::replay::Outcome::Exit(*r0),
            Err(e) => febpf::replay::Outcome::Error(e.to_string()),
        };
        match &reproduced {
            Ok(r0) => println!("r0 = {r0} ({r0:#x})   [replay]"),
            Err(e) => println!("runtime error: {e}   [replay]"),
        }
        check_determinism(replay.outcome.as_ref(), &repro);
        return Ok(ExitCode::SUCCESS);
    }

    // Drop into the debugger, positioned at the recorded cursor.
    let opts = debug::DebuggerOpts {
        start_at: replay.stop_at,
        ..Default::default()
    };
    debug::repl(&mut vm, &mut ctx, opts).map_err(|e| e.to_string())?;
    Ok(ExitCode::SUCCESS)
}

/// Warn loudly if a reproduced run disagrees with what the file recorded — a
/// determinism regression.
fn check_determinism(recorded: Option<&febpf::replay::Outcome>, reproduced: &febpf::replay::Outcome) {
    use febpf::replay::Outcome;
    let Some(recorded) = recorded else {
        return; // no guard stored
    };
    if recorded != reproduced {
        let fmt = |o: &Outcome| match o {
            Outcome::Exit(r0) => format!("r0 = {r0} ({r0:#x})"),
            Outcome::Error(m) => format!("error: {m}"),
        };
        eprintln!(
            "WARNING: determinism mismatch — recorded {}, reproduced {}",
            fmt(recorded),
            fmt(reproduced)
        );
        eprintln!(
            "         this replay is no longer reproducible on this build; a \
             determinism regression worth investigating."
        );
    }
}

/// `febpf race <prog> [--procs N] [--schedules M] [--seed S] [--schedule CSV]
/// [--ctx ...] [--stats]`. Explore interleavings of N instances sharing one map
/// set and report concurrency races. Exit code 1 when a race is found.
fn cmd_race(o: &Opts, prog: Program) -> Result<ExitCode, String> {
    use febpf::race;
    let ctx = make_ctx(o)?;

    // Verify once (a race is not a verifier error); require pass unless
    // --no-verify, mirroring `run`.
    if !o.no_verify {
        let mut vm = Vm::new(prog.clone())?;
        vm.verify(verifier_config(o, ctx.len(), false)).map_err(|e| {
            format!(
                "verification failed: {e}\n{}(use --no-verify to race anyway)",
                explain(vm.insns(), &e, o)
            )
        })?;
    }

    // `--schedule CSV`: replay exactly one interleaving.
    if let Some(csv) = &o.schedule {
        let path = csv
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().parse::<usize>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("bad --schedule choice vector: {e}"))?;
        let run = race::replay_schedule(&prog, &ctx, o.procs, path)?;
        print!("{}", race::render_single(&run, &o.file, o.procs.max(1)));
        return Ok(ExitCode::SUCCESS);
    }

    let cfg = race::ExploreConfig {
        procs: o.procs,
        schedules: o.schedules,
        seed: o.seed,
    };
    let rep = race::explore(&prog, &ctx, &cfg)?;
    print!("{}", race::render_report(&rep, &o.file, o.stats));
    Ok(if rep.is_race() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

/// Build equivalence-checker options from CLI flags. A `--ctx` value becomes a
/// fixed input always tested; `--ctx-size` (or the `--ctx` length, else 64)
/// sizes the generated inputs.
fn equiv_options(o: &Opts) -> Result<febpf::equiv::Options, String> {
    let fixed = if o.ctx_hex.is_some() {
        Some(make_ctx(o)?)
    } else {
        None
    };
    let ctx_size = o
        .ctx_size
        .or_else(|| fixed.as_ref().map(|c| c.len()))
        .unwrap_or(64);
    Ok(febpf::equiv::Options {
        ctx_size,
        fixed_ctx: fixed,
        iters: o.iters as usize,
        seed: o.seed.unwrap_or(0x5eed_1234),
        insn_limit: 2_000_000,
    })
}

/// `febpf equiv <a> <b> [--ctx ...] [--ctx-size n] [--iters N] [--seed N]`.
fn cmd_equiv(o: &Opts) -> Result<ExitCode, String> {
    use febpf::equiv::{self, Verdict};
    let file_b = o
        .file2
        .as_deref()
        .ok_or("equiv needs two programs: febpf equiv <a> <b>")?;
    let (pa, _, _) = load_program(&o.file, o.prog.as_deref(), o.target_btf.as_deref())?;
    let (pb, _, _) = load_program(file_b, o.prog.as_deref(), o.target_btf.as_deref())?;
    let opts = equiv_options(o)?;
    let verdict = equiv::check(&pa, &pb, &opts)?;
    match &verdict {
        Verdict::ProvenEquivalent(reason) => {
            println!("PROVEN-EQUIVALENT (abstract)");
            println!("  {reason}");
        }
        Verdict::Equivalent { inputs } => {
            println!("EQUIVALENT ({inputs} inputs, no counterexample found)");
            println!("  empirical: differential falsification found no separating input");
        }
        Verdict::NotEquivalent(w) => {
            println!("NOT-EQUIVALENT");
            print!("{}", equiv::render_witness(w));
        }
    }
    Ok(ExitCode::from(verdict.exit_code()))
}

/// `febpf optimize <file> [-o out.bin] [--stats] [--ctx ...] [--iters N]`.
/// Applies verifier-gated sound rewrites, self-checks equivalence, and only
/// then emits the result (raw bytecode). Refuses (nonzero exit) if it cannot
/// prove behavior was preserved or the output fails to re-verify.
fn cmd_optimize(o: &Opts, prog: Program) -> Result<ExitCode, String> {
    use febpf::equiv::Verdict;
    let ctx = make_ctx(o)?;
    let cfg = verifier_config(o, ctx.len(), false);
    let equiv_opts = equiv_options(o)?;
    let result = febpf::optimize::optimize(&prog, cfg, &equiv_opts)?;
    let s = &result.stats;

    match &result.self_check {
        Verdict::ProvenEquivalent(reason) => {
            println!("equivalence: PROVEN-EQUIVALENT (abstract) — {reason}");
        }
        Verdict::Equivalent { inputs } => {
            println!("equivalence: EQUIVALENT ({inputs} inputs, empirical)");
        }
        Verdict::NotEquivalent(_) => unreachable!("optimize would have errored"),
    }

    if o.stats {
        println!("== optimizer stats ==");
        println!(
            "  insns: {} -> {} ({:+})",
            s.insns_before,
            s.insns_after,
            s.insns_after as isize - s.insns_before as isize
        );
        println!("  rounds: {}", s.rounds);
        println!("  constant folding:    {}", s.constant_fold);
        println!("  dead-branch elim:    {}", s.dead_branch);
        println!("  strength reduction:  {}", s.strength_reduction);
        println!("  algebraic identity:  {}", s.algebraic_identity);
        println!("  redundant mask elim: {}", s.redundant_mask);
        println!("  total rewrites:      {}", s.total_rewrites());
    } else {
        println!(
            "optimized {} -> {} insns ({} rewrites)",
            s.insns_before,
            s.insns_after,
            s.total_rewrites()
        );
    }

    if let Some(out) = o.out.as_deref() {
        let bytes = insn::encode_program(&result.program.insns);
        std::fs::write(out, &bytes).map_err(|e| format!("cannot write {out}: {e}"))?;
        println!("wrote {} bytes to {out}", bytes.len());
        if !result.program.maps.is_empty() {
            println!(
                "note: {} map definition(s) are not stored in raw bytecode",
                result.program.maps.len()
            );
        }
    } else {
        print!("{}", disasm::disasm_program(&result.program.insns));
    }
    Ok(ExitCode::SUCCESS)
}

fn run() -> Result<ExitCode, String> {
    let o = parse_args().map_err(|e| format!("{e}\n\n{USAGE}"))?;
    if o.cmd == "help" {
        print!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }
    if o.cmd == "fuzz" {
        return conftest::fuzz(&o);
    }
    if o.cmd == "vfuzz" {
        return conftest::vfuzz(&o);
    }
    if o.cmd == "replay" {
        return cmd_replay(&o);
    }
    if o.cmd == "equiv" {
        return cmd_equiv(&o);
    }
    let (prog, debug, elf_xdp) =
        load_program(&o.file, o.prog.as_deref(), o.target_btf.as_deref())?;
    let xdp = elf_xdp || o.packet.is_some();
    if xdp
        && !matches!(
            o.cmd.as_str(),
            "asm" | "disasm" | "verify" | "analyze" | "dot" | "run" | "profile"
        )
    {
        return Err(format!(
            "{} does not support XDP packet context yet; use verify, analyze, run, or profile",
            o.cmd
        ));
    }
    if o.cmd == "record" {
        return cmd_record(&o, prog);
    }
    if o.cmd == "optimize" {
        return cmd_optimize(&o, prog);
    }
    if o.cmd == "conftest" {
        return conftest::conftest(&o, prog);
    }
    if o.cmd == "race" {
        return cmd_race(&o, prog);
    }

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
        "disasm" => match &debug {
            Some(di) => print!("{}", analysis::source_listing(&prog.insns, di)),
            None => print!("{}", disasm::disasm_program(&prog.insns)),
        },
        "verify" => {
            let ctx = make_ctx(&o)?;
            let mut vm = Vm::new(prog.clone())?;
            match vm.verify(verifier_config(&o, ctx.len(), xdp)) {
                Ok(ok) => {
                    println!("verification PASSED");
                    print_verify_stats(&ok);
                }
                Err(e) => {
                    println!("verification FAILED: {e}");
                    print!("{}", explain(&prog.insns, &e, &o));
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
            let mut vm = Vm::new(prog.clone())?;
            match vm.verify(verifier_config(&o, ctx.len(), xdp)) {
                Ok(ok) => {
                    println!("\n== verifier ==");
                    println!("  PASSED");
                    print_verify_stats(&ok);
                    println!("\n== annotated listing (abstract state on first visit) ==");
                    print!(
                        "{}",
                        analysis::annotated_listing(&prog.insns, &ok, debug.as_ref())
                    );
                }
                Err(e) => {
                    println!("\n== verifier ==");
                    println!("  FAILED: {e}");
                    print!("{}", explain(&prog.insns, &e, &o));
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
            if xdp && o.no_verify {
                return Err("XDP execution currently requires verification".into());
            }
            if o.no_verify {
                vm.insn_limit = 100_000_000;
            } else {
                vm.verify(verifier_config(&o, ctx.len(), xdp)).map_err(|e| {
                    format!(
                        "verification failed: {e}\n{}(use --no-verify to run anyway)",
                        explain(vm.insns(), &e, &o)
                    )
                })?;
            }
            if xdp && o.jit {
                return Err("XDP packet execution is interpreter-only for now (--jit unsupported)".into());
            }
            if o.jit {
                jit_compile(&mut vm)?;
            }
            let t0 = Instant::now();
            let r0 = if xdp {
                let mut packet = read_packet(&o)?;
                vm.run_xdp(&mut packet).map_err(|e| e.to_string())?
            } else {
                run_maybe_jit(&mut vm, &mut ctx, o.jit).map_err(|e| e.to_string())?
            };
            let dt = t0.elapsed();
            let how = if o.jit { "jit" } else { "interp" };
            println!("r0 = {r0} ({r0:#x})   [{how}, {dt:?}]");
        }
        "profile" => {
            let mut ctx = make_ctx(&o)?;
            let mut vm = Vm::new(prog.clone())?;
            vm.echo_printk = true;
            if !o.no_verify {
                vm.verify(verifier_config(&o, ctx.len(), xdp)).map_err(|e| {
                    format!("verification failed: {e}\n{}", explain(vm.insns(), &e, &o))
                })?;
            } else {
                vm.insn_limit = 100_000_000;
            }
            vm.enable_profiling();
            let r0 = if xdp {
                let mut packet = read_packet(&o)?;
                vm.run_xdp(&mut packet).map_err(|e| e.to_string())?
            } else {
                vm.run(&mut ctx).map_err(|e| e.to_string())?
            };
            let counts = vm.profile.take().unwrap();
            print!(
                "{}",
                analysis::heatmap_listing(&prog.insns, &counts, debug.as_ref())
            );
            println!("\nr0 = {r0} ({r0:#x})");
        }
        "debug" => {
            let mut ctx = make_ctx(&o)?;
            let mut vm = Vm::new(prog)?;
            if let Some(di) = debug {
                vm.set_debug(di);
            }
            if !o.no_verify {
                match vm.verify(verifier_config(&o, ctx.len(), xdp)) {
                    Ok(_) => println!("verifier: PASSED"),
                    Err(e) => {
                        println!("verifier: FAILED: {e} (debugging anyway)");
                        print!("{}", explain(vm.insns(), &e, &o));
                    }
                }
            }
            debug::repl(&mut vm, &mut ctx, debug::DebuggerOpts::default())
                .map_err(|e| e.to_string())?;
        }
        "bench" => {
            let mut ctx = make_ctx(&o)?;
            let mut vm = Vm::new(prog)?;
            if !o.no_verify {
                vm.verify(verifier_config(&o, ctx.len(), xdp)).map_err(|e| {
                    format!("verification failed: {e}\n{}", explain(vm.insns(), &e, &o))
                })?;
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
                jit_compile(&mut vm)?;
            }
            let t0 = Instant::now();
            for _ in 0..o.iters {
                run_maybe_jit(&mut vm, &mut ctx, o.jit).map_err(|e| e.to_string())?;
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

/// Render a rejection's counterexample trace, honoring --no-explain.
fn explain(insns: &[insn::Insn], e: &verifier::VerifyError, o: &Opts) -> String {
    if o.no_explain {
        return String::new();
    }
    verifier::render_trace(insns, e)
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
