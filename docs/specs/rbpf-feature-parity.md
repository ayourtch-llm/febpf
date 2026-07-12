# rbpf feature-parity audit

STATUS: audited against qmonnet/rbpf 0.4.1 on 2026-07-12. This is an
independent inventory of public behavior and metadata. No rbpf code is copied
into febpf.

## Scope and conclusion

The comparison has two different axes that must not be collapsed:

1. **Linux eBPF semantics and analysis tooling.** febpf is materially broader:
   it has a kernel-style verifier, maps and Linux helper semantics, program
   graphs and tail calls, direct clang ELF/BTF/BTF.ext/CO-RE loading, safe
   interpreter and hybrid-JIT runtime faults, and debugging, replay,
   conformance, race, equivalence, and optimization tools.
2. **Embedding conveniences and portability.** febpf already exposes a broad,
   safety-oriented embedding API. rbpf additionally provides four named input
   wrappers, a replaceable verifier callback, arbitrary allowed host-memory
   ranges, runtime program replacement, a fluent Rust instruction builder, a
   `no_std` interpreter/assembler build, and a Windows interpreter build.

Therefore **febpf must not yet claim to be a strict global feature superset of
rbpf 0.4.1**. It can accurately claim substantially broader Linux eBPF
semantics, safety analysis, object support, developer tooling, and an existing
typed embedding surface. The remaining gaps are pointed conveniences and
portability targets, tracked in `embedding-parity-roadmap.md`.

## Evidence baseline

Primary rbpf references:

- [rbpf 0.4.1 crate documentation](https://docs.rs/rbpf/0.4.1/rbpf/)
- [upstream README](https://github.com/qmonnet/rbpf/blob/main/README.md)
- [0.4.1 feature metadata](https://docs.rs/crate/rbpf/0.4.1/features)
- [0.4.1 Cargo metadata](https://docs.rs/crate/rbpf/0.4.1/source/Cargo.toml.orig)

Docs.rs records 0.4.1 as published on 2026-02-06. The crate has default
`std` and optional `cranelift` features. The latter activates five Cranelift
dependencies; its presence is recorded here, but backend coverage and safety
are not inferred merely from dependency metadata.

febpf evidence is the source and specs in this repository at commit
`48f253c` and later. In particular, see `README.md`, `docs/specs/`, the public
API in `src/interp.rs`, platform gates in `src/jit/mod.rs`, and the two
configuration test suites.

## Linux semantics and tooling matrix

| Capability | febpf | rbpf 0.4.1 | Assessment |
|---|---|---|---|
| Verifier | Path-sensitive abstract interpretation with pointer types, ranges, bounded loops, rejection traces, and kernel verdict differentials | Public docs call its verifier very short/simple and warn that it may accept unsafe programs; callback is replaceable | febpf broader semantically; rbpf more pluggable |
| Nontermination | Bounded loops are proved; unbounded loops reject; runtime instruction limit remains a backstop | Public docs warn that infinite loops are the caller's responsibility | febpf broader and safer |
| Interpreter memory safety | Virtual addresses resolve through typed, bounds-checked regions; wild accesses return `EbpfError` even with verification disabled | Interpreter validates packet/metadata and registered allowed-memory accesses and returns errors | Both provide checked interpreter faults; febpf avoids guest-visible host pointers |
| JIT memory safety | Hybrid JIT defers memory operations through the checked interpreter, so runtime faults remain errors | Public API marks JIT execution `unsafe`; docs warn unauthorized accesses can crash | febpf stronger |
| Built-in maps | Array/hash, per-CPU, LRU, ring/perf/stack/cgroup/program, map-in-map, and XDP redirect families | Public README lists user-space array/hash map support as future work | febpf broader |
| Linux helpers | Typed verifier registry plus a substantial tracing, map, ring, stack, XDP, and tail-call set; custom helpers supported | User helpers supported at arbitrary `u32` ids; only a few Linux helpers are built in | febpf broader for Linux semantics; both extensible |
| Tail calls/program graphs | Verified bundles, static ELF linking, replay, interpreter/JIT dispatch, and kernel linking | Public docs say tail calls are not implemented | febpf broader |
| Clang object loading | Direct ELF loader with relocations, global data, BTF `.maps`, BTF.ext, CO-RE, and static program/map initializers | README's object example uses the separate `elf` crate; improving direct clang support remains on its to-do list | febpf broader |
| BTF and CO-RE | Full BTF graph, source info, typed contexts, and 13 CO-RE relocation kinds | No public built-in BTF/CO-RE surface found | febpf broader |
| XDP packet model | Kernel-style `xdp_md` data/data_end verification, deterministic raw-packet/pcap execution, replay, and kernel differential; interpreter only | General raw-packet and metadata-buffer execution; not a kernel XDP verifier/model | Different abstraction; febpf broader for XDP semantics |
| Native JIT platforms | x86-64 Linux and AArch64 Linux/macOS | README documents a hand-written x86-64 JIT on non-Windows `std` builds | febpf has broader documented native architecture coverage |
| Optional Cranelift backend | None | Optional `cranelift` feature exists in 0.4.1 | rbpf-only option; exact platform/opcode coverage not claimed by this audit |
| Debug/analysis tools | CFG/analyze/profile, source debugger, reverse execution, dataflow queries, replay, race exploration, equivalence, optimizer, kernel conformance fuzzing | Assembler and disassembler; no comparable public integrated toolset found | febpf broader |
| ISA edge coverage | Modern JMP32, atomics, signed div/mod, sign-extending moves, subprograms, and long jumps are covered by tests | Public opcode surface is broad but README says a small number remain unimplemented | Do not claim strict ISA inclusion without a differential opcode audit |
| Legacy `ld_abs`/`ld_ind` | Not implemented | Public opcode inventory includes these forms, but this audit did not independently test execution | Explicit febpf gap; another reason not to claim strict ISA superset |

## Portable embedding matrix

| Capability | febpf | rbpf 0.4.1 | Assessment |
|---|---|---|---|
| Input models | Generic mutable context bytes via `Vm::run` already cover raw-buffer, caller-metadata, and empty/no-data execution; `run_xdp` synthesizes kernel-style XDP context and packet regions | Separate raw-packet, caller metadata-buffer, fixed synthesized metadata-buffer, and no-data VM types | Both cover the core modes; rbpf names them as distinct wrapper types, while febpf uses one safer virtual-region API |
| Raw packet pointer in `r1` | `Vm::run(&mut packet)` places a bounded virtual pointer to those bytes in `r1`, preserving program-visible direct-buffer semantics without exposing a host address | `EbpfVmRaw` places the host packet address in the first register | Capability present in both; febpf has the stronger runtime safety model |
| Arbitrary metadata layout | Caller may supply bytes, but embedded host pointers are not imported as guest regions; XDP synthesis uses its defined layout | Caller-controlled metadata or fixed buffer with configurable data/data_end offsets | rbpf broader |
| Replaceable verifier | Verification policy is configurable, and callers may skip verification, but cannot replace it with an arbitrary callback | `set_verifier` installs a function and immediately rechecks a loaded program | rbpf broader/pluggable |
| Allowed host-memory ranges | No public registration of host addresses; memory must become a VM-owned typed region | `register_allowed_memory` appends arbitrary address ranges for interpreter access | rbpf broader as an escape hatch; febpf's restriction is intentional safety architecture |
| Runtime program replacement | Construct a new `Vm`; tail-call bundle targets can be linked, but the entry program has no `set_program` API | `set_program` replaces and reverifies code on an existing VM | rbpf broader |
| Instruction construction | Public `Insn` encoding/decoding plus textual assembler | Textual assembler plus fluent `insn_builder::BpfCode` API | febpf lacks only the fluent convenience layer |
| Custom helper ABI | Boxed `UserHelper` with verifier-visible argument/return signatures and checked `MemBus` access | Plain five-`u64` function pointer registered at any `u32` id | Both extensible; febpf adds type/safety integration, rbpf is simpler |
| `no_std` | No; febpf uses `std`. `--no-default-features` disables JIT, not the standard library | Default `std` can be disabled; interpreter and reduced-diagnostic assembler remain, normal JIT does not | rbpf broader |
| Windows | No supported Windows execution target documented | README documents interpreter support on Windows and excludes JIT there | rbpf broader |
| Browser/WASM | Hand-written wasm ABI and self-contained playground; interpreter build is tested | No comparable public browser integration found; `no_std` alone is not treated as proof of WASM behavior | febpf broader |
| Dependency profile | Zero Cargo dependencies by design | Uses byteorder, combine, hashbrown, log; libc is optional with `std`; Cranelift dependencies are optional | Different tradeoff; febpf smaller, rbpf enables `no_std` despite dependencies |

## Claim language

Safe wording for project documentation:

> Compared with rbpf 0.4.1, febpf provides substantially broader Linux eBPF
> verification, maps/helpers, object loading, safe JIT fault handling, and
> analysis/debugging tooling, together with a typed embedding API. rbpf retains
> several additional portability and host-integration conveniences, including
> `no_std` and Windows interpreter support, verifier replacement, and allowed
> host-memory ranges.

Avoid:

> febpf is a strict superset of rbpf.

That statement is false under the audited public surfaces and remains
unproven at the opcode-behavior level.

## Follow-up policy

Do not weaken the virtual-address model to imitate `EbpfVmRaw` or arbitrary
host-memory ranges. If embedding parity becomes a real user need, preserve the
safety invariant by registering owned/borrowed slices as bounded VM regions
and exposing opaque guest handles. The most plausible low-risk additions are:

1. a convenience no-data constructor or runner;
2. a safe configurable metadata-layout adapter backed by VM regions;
3. a fluent instruction builder over febpf's existing `Insn` constructors;
4. entry-program replacement that rebuilds verifier/JIT/debug state
   transactionally.

`no_std` and Windows are architectural projects, not opportunistic parity
patches. Implement any of these only when an embedding user or measured corpus
requires it.
