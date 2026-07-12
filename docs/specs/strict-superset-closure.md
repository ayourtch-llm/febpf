# Strict-superset closure: legacy packet ISA and backend audit

STATUS: complete, 2026-07-12. This plan closed the two technical axes left open
by `rbpf-feature-parity.md`: deprecated `LD_ABS`/`LD_IND` packet instructions
and rbpf 0.4.1's optional Cranelift execution backend.

The two axes must remain distinct. Instruction behavior is part of the guest
contract. Cranelift is an implementation technique unless it enables an
observable target, safety, or execution capability febpf lacks.

## Evidence rules

- Linux semantics come from RFC 9669 and current kernel documentation and are
  validated against `BPF_PROG_TEST_RUN` where the host supports the required
  program type.
- rbpf behavior comes from public 0.4.1 documentation, metadata, tests, and
  black-box execution. No rbpf implementation code is copied.
- Every comparison labels evidence as measured, documented, inferred, or
  unknown.
- febpf remains zero-dependency. Cranelift crates must not be added merely to
  match a backend name.

## Step 1 — specify legacy packet loads

Write `legacy-packet-loads.md` before accepting the implementation. It must
define:

1. the `LD | ABS/IND | B/H/W` encodings and reserved fields;
2. Linux implicit register behavior (`r6` input, `r0` output, `r1-r5`
   clobbered), packet-only applicability, network byte order, and implicit
   termination on failed packet access;
3. how those semantics map onto febpf's virtual packet/owned-region model for
   raw, XDP, and configurable metadata inputs;
4. verifier typing and liveness rules, including indirect scalar offsets;
5. interpreter and hybrid-JIT behavior, assembler/disassembler syntax,
   snapshots, replay, and debugging;
6. treatment of rbpf's `DW` extension, which is outside the standardized
   packet conformance group.

No host packet pointer may enter a guest register.

## Step 2 — implement the packet conformance group

Add the standard byte/half/word forms across instruction constants, textual
tools, verifier, interpreter, and hybrid JIT. Prefer one packet-access runtime
primitive shared by XDP/configurable metadata and legacy instructions.

The JIT remains safe: legacy loads are deferred to the checked interpreter
unless a future native implementation proves the same clean failure behavior.

Acceptance tests cover exact encodings, round trips, ABS and IND addressing,
all widths and endian behavior, exact-end access, underflow/overflow/OOB,
implicit clobbers, packet-mode restrictions, verifier rejection, snapshot/
debug behavior, and interpreter/JIT agreement.

## Step 3 — differential evidence

Use three independent oracles where applicable:

- RFC/kernel examples for standardized semantics;
- live-kernel socket-filter `BPF_PROG_TEST_RUN` for verdict, return value, and
  OOB behavior;
- rbpf 0.4.1 black-box programs for its supported standard forms and `DW`
  extension.

If rbpf and Linux differ (notably byte order or nonstandard `DW`), do not hide
the difference. Preserve kernel semantics by default and expose compatibility
only through an explicit, tested policy if it has real value.

## Step 4 — audit Cranelift behavior

Pin rbpf 0.4.1 and run its feature-gated Cranelift suite. Inventory:

- translated opcode/helper coverage and unsupported instructions;
- interpreter-versus-Cranelift behavioral tests;
- memory-region bounds checks, trap behavior, and whether faults return a
  recoverable error;
- relationship to rbpf's replaceable simple verifier;
- actual tested host architecture/OS matrix versus merely theoretical
  Cranelift support;
- compile latency, runtime role, dependencies, and `no_std` availability.

Then compare observable capability with febpf's safe hybrid x86-64 Linux and
AArch64 Linux/macOS backends plus its Windows, wasm, and no-std interpreter
profiles.

## Step 5 — backend decision

Use the audit outcome, not backend branding:

- If Cranelift adds no observed execution target or guest behavior, record it
  as an alternative implementation strategy rather than a febpf gap.
- If it provides a tested target febpf lacks, decide whether that target is in
  febpf's claim scope. Add a zero-dependency backend only when the target is
  valuable and testable in CI.
- Never add Cranelift dependencies to febpf without explicit user approval;
  doing so would break a load-bearing project constraint.

Likely native follow-up, if evidence justifies one, is a `JitBackend`
implementation for an uncovered architecture such as riscv64—not a second
compiler framework.

## Step 6 — claim update and final gates

Update `rbpf-feature-parity.md` and the active handoff with:

- the exact legacy packet conformance result and any explicit rbpf extension;
- the measured Cranelift suite/backend matrix;
- scoped strict-superset wording, or the remaining named counterexample.

Before committing the final claim, run default JIT and std interpreter-only
tests/clippy, true no-std check/clippy, relevant wasm/Windows cross-checks,
legacy kernel/rbpf differentials, and `git diff --check`.

## Result

- Steps 1-3 are implemented in `legacy-packet-loads.md`: explicit Linux and
  rbpf 0.4.1 profiles cover all eight measured rbpf forms while keeping the
  standardized Linux B/H/W, byte order, register effects, and OOB exit
  semantics distinct. The privilege-gated live-kernel differential passed as
  root on the Linux 7.0.0 host for ABS W, IND H/B, exact-end, byte order, and
  OOB implicit-zero behavior.
- Steps 4-5 are recorded in `rbpf-backend-parity.md`. The pinned Cranelift
  suite passed 134 tests with two ignored on x86-64 Linux. Cranelift adds no
  observed guest behavior or claimed target that requires a febpf dependency;
  its additional host reach remains unmeasured, while its backend omits
  atomics, tail calls, and correct local-call handling.
- Replay v1 remains backward compatible through an additive, address-free
  legacy-profile section. Native CLI and browser debugger replay select the
  recorded packet adapter.
- The final qualification is no longer legacy ISA or Cranelift. A strict
  global public-API superset claim remains inappropriate because rbpf exposes
  unsafe live host-memory aliases and total verifier replacement, which febpf
  deliberately does not reproduce in its verified API.
