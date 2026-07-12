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
2. **Embedding conveniences and portability.** febpf now covers rbpf's useful
   public embedding behaviors: named input adapters, configurable metadata,
   transactional program replacement, a fluent builder, post-core policy
   hooks, owned external regions, `no_std + alloc`, and Windows interpreter
   builds. It preserves these behaviors without putting host addresses in
   guest registers. rbpf still exposes live aliases to arbitrary host-memory
   ranges and permits a callback to replace verification entirely; febpf
   intentionally does neither through its verified API.

Therefore **febpf must not claim to be a strict global public-API superset of
rbpf 0.4.1**. It can accurately claim substantially broader Linux eBPF
semantics, safety analysis, object support, developer tooling, and a portable
typed embedding surface. Legacy opcode behavior and the optional Cranelift
backend have now been measured and closed as capability questions. The
remaining differences are live host-memory aliasing and exact unsafe API
shape, not missing ordinary embedding workflows.

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

febpf evidence is the source and specs in this repository through the legacy
packet/replay closure on 2026-07-12. In particular, see `tests/embedding.rs`,
`tests/external_regions.rs`, `tests/verification_policy.rs`,
`tests/metadata.rs`, the public APIs in `src/builder.rs` and `src/interp.rs`,
and the default, standard-library interpreter-only, true-`no_std`, Windows,
and wasm CI configurations.

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
| Optional Cranelift backend | No Cranelift dependency; safe hybrid native backend on the claimed JIT targets | Pinned suite measured 134 passed, 2 ignored on x86-64 Linux; atomics/tail calls/local calls have backend gaps | Alternative implementation strategy, not an observed febpf capability gap; additional host reach is unknown |
| Debug/analysis tools | CFG/analyze/profile, source debugger, reverse execution, dataflow queries, replay, race exploration, equivalence, optimizer, kernel conformance fuzzing | Assembler and disassembler; no comparable public integrated toolset found | febpf broader |
| ISA edge coverage | Modern JMP32, atomics, signed div/mod, sign-extending moves, subprograms, long jumps, and explicit legacy packet profiles are covered by tests | Public opcode surface is broad; pinned interpreter/Cranelift legacy vectors were measured | febpf covers the identified opcode gap; universal behavior across every raw encoding remains broader than this audit |
| Legacy `ld_abs`/`ld_ind` | Explicit Linux B/H/W and rbpf-compatible B/H/W/DW profiles across tools, verifier, interpreter, hybrid JIT, CLI, replay, and debugger | All eight ABS/IND width forms measured as little-endian; checked interpreter reports OOB errors | Covered without conflating rbpf's extension with Linux semantics |

## Portable embedding matrix

| Capability | febpf | rbpf 0.4.1 | Assessment |
|---|---|---|---|
| Input models | `run_no_data`, `run_raw`, ordinary `run`, `run_xdp`, `run_metadata`, and fixed-metadata adapters cover empty, raw, caller-metadata, kernel XDP, and synthesized-metadata execution | Separate raw-packet, caller metadata-buffer, fixed synthesized metadata-buffer, and no-data VM types | Behavioral parity; febpf uses one VM and explicit safe adapters rather than wrapper VM types |
| Raw packet pointer in `r1` | `Vm::run_raw` places a bounded virtual pointer to mutable packet bytes in `r1`, preserving direct-buffer semantics without exposing a host address | `EbpfVmRaw` places the host packet address in the first register | Behavioral parity; febpf has the stronger runtime safety model |
| Arbitrary metadata layout | `MetadataLayout` configures data/data_end offsets; caller or fixed buffers receive opaque virtual packet bounds, with interpreter/JIT execution and runtime validation | Caller-controlled metadata or fixed buffer with configurable data/data_end offsets | Behavioral parity; febpf never imports host pointers and additionally verifies the layout |
| Replaceable verifier | `verify_with_policy` runs application policy over instructions, maps, and `VerifyOk` only after core safety verification; callers may separately choose unchecked execution | `set_verifier` installs a function and immediately rechecks a loaded program | Practical policy-hook parity with stronger safety; arbitrary acceptance of core-invalid programs remains an intentional rbpf-only escape hatch |
| Allowed host-memory ranges | `register_owned_region` provides opaque bounded RO/RW guest regions, typed helper returns, snapshots, and checked interpreter/JIT access even when unverified | `register_allowed_memory` appends arbitrary live host-address ranges for interpreter access | Owned copy-in/inspection behavior is covered and safer; rbpf alone provides zero-copy live host aliasing, intentionally deferred |
| Runtime program replacement | `replace_program` transactionally rebuilds program-derived state, resets maps/tails/debug/verifier/JIT state, and preserves embedding configuration/helpers; verification is then explicit | `set_program` replaces and reverifies code on an existing VM | Behavioral parity; febpf has the clearer failure/state contract |
| Instruction construction | Public `Insn`, textual assembler, and fluent typed `builder::Builder` covering representative ALU32/64, memory, jumps, calls, `lddw`, and exit | Textual assembler plus fluent `insn_builder::BpfCode` API | Parity for the audited construction convenience; exact method-for-method identity is not claimed |
| Custom helper ABI | Boxed `UserHelper` with verifier-visible argument/return signatures and checked `MemBus` access | Plain five-`u64` function pointer registered at any `u32` id | Both extensible; febpf adds type/safety integration, rbpf is simpler |
| `no_std` | Default `std`/`jit` features are separable; `--no-default-features` builds the VM, verifier, maps/helpers, builder, and reduced-diagnostic assembler with `core + alloc`, checked on `thumbv7em-none-eabihf` | Default `std` can be disabled; interpreter and reduced-diagnostic assembler remain, normal JIT does not | Behavioral parity; febpf retains zero dependencies |
| Windows | Native Windows CI checks default compatibility and runs the interpreter/library/CLI tests and strict clippy with `std` but no JIT | README documents interpreter support on Windows and excludes JIT there | Interpreter-platform parity |
| Browser/WASM | Hand-written wasm ABI and self-contained playground; interpreter build is tested | No comparable public browser integration found; `no_std` alone is not treated as proof of WASM behavior | febpf broader |
| Dependency profile | Zero Cargo dependencies by design | Uses byteorder, combine, hashbrown, log; libc is optional with `std`; Cranelift dependencies are optional | Different tradeoff; febpf smaller, rbpf enables `no_std` despite dependencies |

## Claim language

Safe wording for project documentation:

> Compared with rbpf 0.4.1, febpf provides substantially broader Linux eBPF
> verification, maps/helpers, object loading, safe JIT fault handling, and
> analysis/debugging tooling, together with a portable typed embedding API
> covering rbpf's useful execution, construction, replacement, metadata, and
> policy workflows. rbpf retains unsafe escape hatches for replacing the
> verifier and live-aliasing arbitrary host addresses; febpf deliberately uses
> mandatory core verification for verified runs and owned virtual regions.

Avoid:

> febpf is a strict superset of rbpf.

That statement is false under the audited public surfaces and remains
unproven at the opcode-behavior level.

## Follow-up policy

Do not weaken the virtual-address model to imitate `EbpfVmRaw` or arbitrary
host-memory ranges. Owned regions cover deterministic copy-in/inspection and
snapshot behavior. Execution-scoped borrowed regions may be added later if a
real zero-copy user requires live host aliasing, but their lifetimes must not
outlive the run and replay must never serialize host addresses.

Likewise, a caller can apply its own callback before deliberately running
without `Vm::verify`; no verifier-shaped custom-only API is needed. Such a
path must never arm XDP/probe evidence or masquerade as core verification.
