# Embedding parity roadmap

STATUS: Waves 1-3 complete and Wave 4 evidence current as of 2026-07-12
(through `7e919d3`). The useful behavioral embedding and portability gaps in
the rbpf 0.4.1 audit are closed without weakening febpf's virtual-address
safety model or zero-dependency constraint. Borrowed zero-copy aliases and
external-region replay-file support are deferred follow-ups, not requirements
for the behavioral-parity claim.

## Goal

febpf exposes `Program`, `Vm`, configurable core verification, application
policy hooks, caller-provided and synthesized inputs, maps, typed helpers,
interpreter/JIT execution, stepping, debugging, replay, and analysis. The
completed work adds the remaining useful ergonomics, host integration, and
portability behavior identified from rbpf's public API.

Behavioral embedding parity does not prove a strict global feature superset.
Legacy opcode behavior and optional backend coverage remain separate audit
axes.

## Completion record

- **Wave 1 complete:** fluent typed builder, named input adapters,
  transactional program replacement, and native Windows interpreter CI.
- **Wave 2 complete:** owned RO/RW virtual regions with verifier-typed helper
  returns and snapshots; core-first application policy hooks with distinct
  core/policy errors; configurable caller/fixed metadata layouts backed by
  opaque packet-region addresses. Borrowed live aliases are intentionally
  deferred.
- **Wave 3 complete:** separate `std` and `jit` features; VM/verifier/maps/
  helpers/builder/reduced assembler on `no_std + alloc`; true no-std target,
  standard-library interpreter-only, default JIT, wasm, and Windows checks.
- **Wave 4 current:** public behavioral tests cover adapters, builder,
  replacement success/failure, owned regions and unchecked faults, policy
  ordering/rejection, metadata layouts, snapshots, and interpreter/JIT
  agreement where applicable.

## Non-negotiable invariants

1. Guest registers never contain dereferenceable host pointers. Every pointer
   is a virtual `region_handle << 32 | offset` address resolved with bounds and
   mutability checks.
2. The normal verification path always runs febpf's structural and memory-
   safety verifier. Application policy hooks add constraints; they do not
   silently replace the safety proof.
3. Deliberately unverified execution retains runtime virtual-memory checks and
   never masquerades as core verification or arms verifier-derived XDP/probe
   state.
4. Program replacement is transactional: construction failure leaves the
   original VM usable and unchanged in program-derived state.
5. The crate remains zero-dependency. The portable core uses only `core` and
   `alloc`.
6. All supported configurations remain green: default JIT
   (`cargo test --all-targets`), standard-library interpreter-only
   (`cargo test --all-targets --no-default-features --features std`), and the
   true no-std library target (`cargo check --lib --target
   thumbv7em-none-eabihf --no-default-features`), with strict clippy for each.

## Wave 1 — embedding ergonomics and Windows baseline (complete)

### Typed instruction builder

`builder::Builder` is a fluent typed layer over `Insn`, alongside the textual
assembler. It covers representative ALU32/64, moves, loads/stores, jumps,
calls, `lddw`, and exit; validates registers; and emits ordinary `Vec<Insn>`
accepted by encoding, verification, interpreter, and JIT paths. Tests cover
both exact encodings and execution.

### Input conveniences

One VM exposes explicit adapters for no-data, raw mutable bytes, ordinary
caller metadata, kernel-style XDP metadata/packet execution, and configurable
caller or fixed metadata layouts. The adapters reuse the virtual-region
runtime rather than duplicating VM implementations.

### Transactional program replacement

`Vm::replace_program` preserves embedding configuration and registered helper
implementations while rebuilding program-derived state and resetting maps,
tail programs, debug, verifier, and JIT state. A construction failure leaves
the old executable and live state untouched. Re-verification is explicit.

### Windows interpreter baseline

Windows CI checks default-feature compatibility and natively builds, tests,
and runs strict clippy for `std` interpreter-only mode. Native Windows JIT is
outside this milestone.

## Wave 2 — safe host integration and verifier policy (complete)

### External regions

Owned external regions return opaque guest bases and enforce bounds and RO/RW
permissions through ordinary region resolution, including unverified runs.
Typed helpers can return verifier-understood external pointers. Snapshots
capture owned bytes, program replacement resets them, and interpreter/JIT
behavior agrees.

Execution-scoped borrowed regions are deferred until a measured zero-copy
need justifies their lifetime API. Replay-file support for external regions is
also deferred. Neither follow-up may serialize or expose host addresses.

### Verification policy hooks

`Vm::verify_with_policy` invokes application policy only after the core
verifier succeeds. The policy can inspect instructions, map definitions, and
`VerifyOk` evidence; core and policy failures remain distinct. The VM receives
verifier-derived runtime state only after both stages accept.

A verifier-shaped custom-only API is unnecessary: callers can run their own
callback before deliberately executing without `Vm::verify`, while runtime
virtual-memory checks remain active. Such execution does not constitute core
verification.

### Configurable metadata

`MetadataLayout` safely places opaque packet start/end addresses at configured
offsets in caller-owned or fixed metadata buffers. Verification types those
loads as packet pointers; runtime validates layout, packet base, region
permissions, and bounds. Tests cover malformed layouts, unchecked failures,
replacement behavior, and interpreter/JIT execution.

## Wave 3 — `no_std + alloc` (complete)

The default `std` feature is distinct from `jit`. Core VM, verifier,
instruction encoding, maps, helpers, builder, and a reduced-diagnostic
assembler use `core + alloc`. CLI, filesystem, wall-clock/error integration,
kernel conformance, and native JIT require `std` as appropriate.

`--no-default-features` is the true `no_std + alloc` core. Standard-library
interpreter-only builds use `--no-default-features --features std`; default
builds retain JIT. CI checks a real no-std target as well as wasm and Windows.

## Wave 4 — behavioral parity evidence (current)

Tests were derived from rbpf's public documentation and documented behavior
only; no implementation code was copied. Evidence covers:

- no-data, raw buffer, caller metadata, fixed metadata, and synthesized XDP;
- program replacement success/failure and state rules;
- policy acceptance, rejection, core short-circuit, and unchecked runtime
  memory safety;
- external-region reads/writes, permissions, invalid accesses, snapshots, and
  interpreter/JIT agreement;
- instruction-builder encoding and execution;
- Windows interpreter, wasm, true `no_std + alloc`, standard-library
  interpreter-only, and default JIT builds.

The embedding matrix may claim behavioral parity with stronger memory safety.
A global strict-superset claim still requires resolving or explicitly scoping
legacy `ld_abs`/`ld_ind` and completing an opcode/backend differential audit,
including the significance of rbpf's optional Cranelift feature.

## Completed commit boundaries

1. `e60b901` — record the roadmap and correct the audit;
2. `ffdbee3` — typed instruction builder;
3. `4bc990b` and `19a2b46` — input/replacement APIs and public behavior;
4. `2a39d7d` — Windows interpreter CI;
5. `a90688b` and `190f186` — owned regions and policy hooks;
6. `beb9eeb` — `no_std + alloc` core split;
7. `7e919d3` — configurable metadata and remaining behavioral evidence.
