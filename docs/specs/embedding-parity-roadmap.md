# Embedding parity roadmap

STATUS: active roadmap, agreed 2026-07-12. This closes the useful embedding
and portability gaps identified by the rbpf 0.4.1 audit without weakening
febpf's virtual-address safety model or zero-dependency constraint.

## Goal

febpf already has a substantial embedding API: `Program`, `Vm`, configurable
verification, caller-provided context memory, XDP packet execution, maps,
typed custom helpers, interpreter/JIT execution, stepping, debugging, replay,
and analysis are public library surfaces. The remaining work is targeted API
ergonomics, host integration, and portability—not creation of an embedding
API from scratch.

The desired end state is behavioral coverage of rbpf's useful public
embedding capabilities with stronger memory safety. This alone does not prove
a strict global feature superset; legacy opcode behavior and optional backend
coverage remain separate audit axes.

## Non-negotiable invariants

1. Guest registers never contain dereferenceable host pointers. Every pointer
   is a virtual `region_handle << 32 | offset` address resolved with bounds and
   mutability checks.
2. The normal verification path always runs febpf's structural and memory-
   safety verifier. Application policy hooks add constraints; they do not
   silently replace the safety proof.
3. Any explicitly unchecked/custom-only path is named as such and retains
   runtime virtual-memory checks.
4. Program replacement is transactional: on any construction or verification
   failure, the original VM remains usable and bit-for-bit equivalent in
   program-derived state.
5. The crate remains zero-dependency. `no_std` work may use `core` and `alloc`,
   not new Cargo dependencies.
6. Both current configurations remain green throughout:
   `cargo test --all-targets` and
   `cargo test --all-targets --no-default-features`, plus strict clippy for
   each.

## Wave 1 — embedding ergonomics and Windows baseline

### Typed instruction builder

Add a public fluent/typed builder over `Insn`, alongside rather than instead
of the textual assembler. It should:

- cover representative ALU32/64, moves, loads/stores, jumps, calls, `lddw`,
  and exit;
- reject invalid registers and immediate/displacement values at construction;
- emit ordinary `Vec<Insn>` accepted by `Program`, encoding, verification,
  interpreter, and JIT paths;
- prove behavior with execution tests, not only struct-field assertions.

### Input conveniences

Name the input modes already expressible through `Vm::run`:

- no-data execution (empty context);
- raw mutable bytes, where `r1` points to the bounded virtual context region;
- ordinary caller metadata bytes;
- kernel-style XDP metadata plus packet via `run_xdp`.

Prefer small adapters or an `ExecutionInput` abstraction over four duplicated
VM implementations. Configurable pointer-bearing metadata layouts belong to
Wave 2 because they require multiple safe regions.

### Transactional program replacement

Add an entry-program replacement operation with an explicit state contract.
The first version should preserve host configuration and registered helper
implementations, rebuild all program-derived state, reset maps/tail programs/
debug/verifier/JIT state, and install the new program only after complete
construction succeeds. Compatible map-state preservation can be a later,
explicit option; it must never happen heuristically.

### Windows interpreter baseline

Make the interpreter/library configuration compile and run on Windows while
cleanly stubbing Linux kernel integration and native JIT support. Add CI that
at minimum cross-checks an MSVC target; run interpreter tests natively when a
Windows runner is available. JIT support is not part of this milestone.

## Wave 2 — safe host integration and verifier policy

### External regions

Replace rbpf-style arbitrary allowed host-address ranges with safe virtual
regions:

- registration returns an opaque guest base address;
- every access is bounds- and mutability-checked by normal region resolution;
- helper signatures can return a typed nullable/non-null external-region
  pointer understood by the verifier;
- owned regions come first; execution-scoped borrowed regions follow with
  lifetimes that cannot outlive the run;
- snapshots and replay either capture owned bytes or explicitly identify an
  unavailable external input—never serialize host addresses.

Behavioral acceptance includes valid reads/writes, boundary failures,
read-only enforcement, helper-returned pointers, JIT/interpreter agreement,
snapshot restoration, and clean failure under `--no-verify`.

### Verification policy hooks

Add application-specific policy after the core verifier succeeds. The hook
receives the program and/or `VerifyOk` evidence and may reject with an
application error. If custom-only verification is needed, expose it as an
explicitly unsafe or conspicuously unchecked mode; ordinary `verify` must
never lose febpf's proof silently.

## Wave 3 — `no_std + alloc`

Introduce a default `std` feature distinct from `jit`, then split the crate:

- core VM, verifier, instruction encoding, maps, helpers, and a reduced-
  diagnostic assembler use `core`/`alloc`;
- CLI, filesystem, wall clocks, kernel conformance, native JIT allocation,
  and OS integrations require `std`;
- deterministic collection replacements preserve replay behavior;
- `--no-default-features` becomes the `no_std + alloc` core, while a separate
  `std` without `jit` configuration retains today's portable interpreter.

Required checks include a true no-std target, `std` interpreter-only, and the
default JIT build. This is an architectural batch and should follow the API
work so public boundaries are stable before modules are feature-gated.

## Wave 4 — behavioral parity evidence

Build tests from rbpf's public documentation and documented behavior only; do
not copy implementation code. Cover:

- no-data, raw buffer, caller metadata, and synthesized metadata modes;
- program replacement success/failure and state rules;
- policy-hook rejection and explicit unchecked behavior;
- external-region reads, writes, and invalid accesses;
- instruction-builder output and execution;
- Windows interpreter and `no_std + alloc` builds.

Update `docs/specs/rbpf-feature-parity.md` after each wave. Claim embedding
parity only when every row has behavioral evidence. A global strict-superset
claim additionally requires resolving or explicitly scoping legacy
`ld_abs`/`ld_ind` and completing an opcode/backend differential audit.

## Commit boundaries

Keep the work reviewable and bisectable:

1. docs: record embedding parity roadmap and correct the existing audit;
2. api: add typed instruction builder;
3. api: add input adapters and transactional replacement;
4. portability: support the Windows interpreter build;
5. vm/verifier: add safe external regions and policy hooks;
6. portability: split the `no_std + alloc` core;
7. tests/docs: finish behavioral parity evidence and claim update.

Every implementation commit carries its own behavioral tests and passes both
then-supported feature configurations before merge.
