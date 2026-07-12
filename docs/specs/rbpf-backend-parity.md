# rbpf 0.4.1 Cranelift/backend parity audit

Status: evidence and decision record, 2026-07-12. This audit is pinned to
rbpf `v0.4.1` (peeled commit `2b335775baf8ef15f7a73953025ce3e2d052c462`); it
does not treat rbpf `main` or a later Cranelift release as evidence for 0.4.1.
No rbpf implementation is copied into febpf.

## 1. Conclusion

Cranelift is primarily an **implementation choice**, not a user-visible feature
that febpf must reproduce. febpf already offers native execution on every
platform where its JIT is claimed: x86-64 Linux and aarch64 Linux/macOS. Its
hybrid design deliberately sends complicated operations through the checked
interpreter, so the JIT retains structured runtime errors instead of exposing
native traps.

rbpf's Cranelift backend does reveal one possible platform-coverage question:
its use of `cranelift_native::builder()` can potentially generate host-native
code on Cranelift-supported 64-bit hosts beyond febpf's three JIT targets. That
is **inferred potential**, not demonstrated rbpf support: rbpf's checked-in CI
only executes the all-feature/Cranelift build on x86-64 Linux, and this audit
measured only x86-64 Linux. No evidence currently justifies adding a febpf
backend.

Consequently:

- do not add Cranelift to febpf; doing so would abandon the zero-dependency
  property for no demonstrated semantic capability;
- do not claim that febpf has native JIT coverage on every host rbpf might
  support;
- if a concrete riscv64 or s390x user requirement appears, measure rbpf 0.4.1
  there first, then add the smallest justified zero-dependency febpf backend;
- legacy packet-load parity must be decided and tested on semantics, not on the
  fact that rbpf happens to lower those instructions with Cranelift.

## 2. Evidence labels and sources

This document uses four labels:

- **Measured**: reproduced by this audit on the host recorded below.
- **Documented**: stated in pinned source, tests, manifest, or CI.
- **Inferred**: follows from inspected code/dependency behavior but was not run
  on the relevant target.
- **Unknown**: neither tested nor promised by the pinned project.

Primary pinned sources:

- [rbpf 0.4.1 manifest](https://github.com/qmonnet/rbpf/blob/v0.4.1/Cargo.toml)
- [Cranelift implementation](https://github.com/qmonnet/rbpf/blob/v0.4.1/src/cranelift.rs)
- [Cranelift tests](https://github.com/qmonnet/rbpf/blob/v0.4.1/tests/cranelift.rs)
- [VM APIs](https://github.com/qmonnet/rbpf/blob/v0.4.1/src/lib.rs)
- [verifier](https://github.com/qmonnet/rbpf/blob/v0.4.1/src/verifier.rs)
- [CI workflow](https://github.com/qmonnet/rbpf/blob/v0.4.1/.github/workflows/test.yaml)
- [Windows CI](https://github.com/qmonnet/rbpf/blob/v0.4.1/.appveyor.yml)
- [README safety and platform statements](https://github.com/qmonnet/rbpf/blob/v0.4.1/README.md)

## 3. Reproduction

**Measured.** A shallow checkout of tag `v0.4.1` resolved to the pinned commit.
On this host:

```text
Linux 7.0.0-27-generic x86_64
rustc 1.96.1 (31fca3adb 2026-06-26)
cargo 1.96.1 (356927216 2026-06-26)
```

Command:

```sh
cargo test --features cranelift --test cranelift
```

Exact result:

```text
running 136 tests
test result: ok. 134 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out
```

The two ignored tests are materially different:

- `test_cranelift_err_stack_out_of_bound` says bounds checks exist but the trap
  is not caught and converted to an error/panic;
- `test_cranelift_string_stack` has no reason attached in the test declaration.

This run establishes x86-64 Linux behavior for the targeted suite only. It is
not a cross-architecture result, a full conformance run, a performance result,
or proof for untested opcodes.

## 4. What the rbpf Cranelift backend implements

### 4.1 Compilation and public API

**Documented.** Feature `cranelift` pulls in five optional Cranelift crates:
`cranelift-codegen`, `cranelift-frontend`, `cranelift-jit`,
`cranelift-native`, and `cranelift-module`, all at the `0.127` compatibility
line. `hashbrown` is also used by the crate. The resolved audit build used
Cranelift 0.127.4 and a substantial transitive graph including regalloc2,
target-lexicon, region, libc, anyhow, gimli, and multiple Cranelift support
crates. This contrasts with febpf's empty dependency list.

**Documented.** Each rbpf VM flavor exposes `cranelift_compile()` and a matching
`execute_program_cranelift(...)`: metadata-buffer, fixed-metadata, raw-packet,
and no-data execution. Compilation captures the helper registry, creates one
host-native function with a private four-argument ABI, finalizes it, and owns
the executable allocation until drop. There is no public Cranelift IR, object,
code buffer, relocation, cache, tiering, or backend-selection API.

**Documented.** Helpers are direct five-`u64`-argument host calls returning
`u64`. They must exist at compilation time. An unregistered helper is rejected
while compiling; the targeted suite measures that failure. Adding a helper
after compilation cannot make it callable without recompiling.

### 4.2 Opcode inventory

The following inventory describes the Cranelift translator, not rbpf's
interpreter or handwritten x86-64 JIT.

| Class | Cranelift status | Evidence |
|---|---|---|
| 32/64-bit ALU arithmetic and bitwise ops | implemented | documented; representative forms measured |
| immediate/register shifts, signed shifts | implemented | documented; measured |
| endian conversions (16/32/64) | implemented | documented; measured |
| `lddw` | implemented | documented; measured |
| ordinary byte/half/word/dword loads and stores | implemented with inline region checks | documented; measured |
| 64-bit and 32-bit conditional jumps, signed/unsigned, `jset`, `ja` | implemented | documented; measured |
| helper calls and `exit` | implemented | documented; measured |
| legacy `LD_ABS_{B,H,W,DW}` and `LD_IND_{B,H,W,DW}` | implemented | documented; all eight measured |
| atomic/XADD word and dword stores | `unimplemented!()` | documented; not tested |
| tail-call opcode | verifier rejects; translator also has `unimplemented!()` | documented; not tested |
| bpf-to-bpf pseudo-calls (`CALL src=1`) | verifier accepts, but Cranelift translates every `CALL` as a helper lookup | documented; no Cranelift test; inferred compile failure or wrong helper binding |
| any otherwise unmatched opcode | `unimplemented!()` | documented |

The suite is broad but not exhaustive by Cartesian product: it has 136 named
cases covering ALU, jump, endian, stack, packet, ordinary memory, helper, and
legacy-load behavior. It contains no Cranelift atomic, tail-call, bpf-to-bpf
call, allowed-memory, or trap-to-`Error` success case.

### 4.3 Legacy packet loads are not kernel-semantics evidence

**Measured and documented.** rbpf lowers ABS as `mem_start + zero_extended_imm`
and IND as that address plus the selected source register, then applies its
ordinary memory-region bounds check. All B/H/W/DW forms are present. Its tests
expect little-endian host loads (`[0x33, 0x44] -> 0x4433` and
`[0x33,0x44,0x55,0x66] -> 0x66554433`).

Therefore the passing rbpf tests prove rbpf's own legacy-load behavior, not
Linux packet-load parity. Standard Linux byte/half/word packet loads use their
special packet semantics, including network-byte-order conversion and special
register effects; rbpf's DW form is an extension. febpf's legacy-load work
must use its kernel differential suite as authority and should separately
document whether to accept the DW extension.

### 4.4 Memory checking and runtime failures

**Documented.** Every Cranelift ordinary load/store checks the full access
against one of three host-address intervals: the current 512-byte stack,
packet memory, or metadata buffer. It also checks end-address wraparound.
Failure emits a Cranelift `HEAP_OUT_OF_BOUNDS` trap.

**Documented.** `register_allowed_memory` does not extend those Cranelift
checks. rbpf's own README says allowed-memory validation is interpreter-only,
and the compiler carries no allowed-region collection. Thus helper-returned
pointers into registered external host memory are not a working Cranelift
capability.

**Measured/documented.** Runtime trap conversion is incomplete: the stack-OOB
test is ignored for precisely that reason. `execute_program_cranelift` returns
`Result<u64, Error>`, but after successful compilation its native function
returns only `u64`; there is no trap-to-`Error` channel in the wrapper. Exact
process behavior for each OS is **unknown** and should not be described as a
recoverable rbpf error.

The compiler uses host pointers directly. It bounds-checks generated ordinary
loads/stores, but a registered helper is arbitrary host code and receives raw
register values. This is a different trust boundary from febpf's typed helpers
and virtual-address memory bus.

### 4.5 Relationship to verification

**Documented.** Programs pass the VM's selected verifier when loaded or
replaced, before any backend is compiled. rbpf's default verifier checks basic
encoding, registers, branches, exits, instruction count, and call shape, but
does not prove register initialization, pointer types, or general memory
safety. Applications may replace it with an arbitrary callback.

The Cranelift compiler adds selected runtime and late checks: ordinary memory
bounds, helper presence, and its own CFG construction. It is not a second
semantic verifier. Because local calls accepted by the verifier are not
implemented correctly in this backend, verifier acceptance does not imply
Cranelift support. Conversely, atomics and tail calls fail before or during
translation rather than degrading to rbpf's interpreter.

## 5. Platform matrix

| Platform/profile | rbpf 0.4.1 Cranelift | febpf |
|---|---|---|
| x86-64 Linux native | **measured**: targeted suite 134/0/2 | native safe-hybrid JIT; CI interpreter/JIT differential coverage |
| aarch64 Linux native | **unknown** for rbpf; potentially available through Cranelift | native safe-hybrid JIT, executed in CI |
| aarch64 macOS native | **unknown** for rbpf; potentially available through Cranelift | native safe-hybrid JIT, executed in CI with macOS W^X handling |
| x86-64 macOS native | **unknown** for rbpf 0.4.1 Cranelift | interpreter; no claimed febpf JIT |
| x86-64 Windows native | all-features Windows CI is documented, but no isolated Cranelift result was reproduced here; rbpf README's “JIT does not work with Windows” is ambiguous because it predates/distinguishes the handwritten JIT | interpreter profile and unsupported-JIT stub tested; no native JIT claim |
| riscv64 Linux native | **inferred potential**, not rbpf-tested/documented as a supported matrix entry | interpreter; JIT backend specified but not implemented |
| s390x native | **inferred potential**, not rbpf-tested/documented as a supported matrix entry | interpreter where Rust/alloc profile builds; no JIT claim |
| WASM | Cranelift JIT unavailable as an in-process wasm host-native JIT; rbpf status otherwise not established here | std interpreter/WASM artifact tested |
| `no_std + alloc` | rbpf Cranelift unavailable because it requires std/JIT dependencies | core interpreter/verifier/assembler profile tested |

Why “potential” rather than “supported”: rbpf asks `cranelift_native` for the
host ISA and does not itself restrict the architecture, while its internal ABI
uses 64-bit addresses and lengths. Cranelift 0.127's host architecture feature
can select x86-64, aarch64, riscv64, or s390x code generation, but successful
dependency compilation does not prove rbpf's ABI, helper calls, traps, memory
protection, or tests work on each OS/ISA combination.

## 6. Behavioral comparison with febpf

| Concern | rbpf Cranelift | febpf JIT |
|---|---|---|
| Backend strategy | translates most supported instructions to Cranelift IR | native arithmetic/branch core plus checked-interpreter trampoline |
| Runtime memory errors | inline trap; trap-to-`Error` incomplete | deferred to the same virtual-address memory bus as interpreter; structured `EbpfError` retained |
| Atomics | not implemented | executed safely through interpreter trampoline, including fetch, xchg, cmpxchg forms |
| Tail-call program graphs | not implemented in rbpf | executed through the shared VM machinery |
| bpf-to-bpf calls | Cranelift-specific gap | executed through shared machinery |
| Helpers | raw host function ABI, captured at compile | typed/custom and built-in helper machinery with verifier signatures and checked memory access |
| External memory | registered raw host ranges are interpreter-only | owned RO/RW guest virtual regions work through the shared memory model |
| Verification | replaceable simple verifier plus local compiler checks | mandatory core verifier for verified runs plus application policy |
| Native targets actually exercised | x86-64 Linux in pinned upstream CI and this audit | x86-64 Linux, aarch64 Linux, aarch64 macOS |
| Portable profiles | interpreter supports std/no_std configurations; no Cranelift in no_std | Windows, WASM/std, and genuine `no_std + alloc` interpreter profiles |
| Dependency posture | large optional Cranelift dependency graph | zero dependencies, including JIT encoders |

febpf's “hybrid” label is not a capability concession. Memory, calls, atomics,
`lddw`, and exits execute in the authoritative interpreter one instruction at a
time, while native code removes dispatch from the hot arithmetic/branch path.
This is why febpf can preserve the interpreter's checked errors and broad VM
features under JIT execution without duplicating them in each ISA backend.

## 7. Decision and exact claim language

Recommended project language:

> febpf provides a zero-dependency native JIT on x86-64 Linux and aarch64
> Linux/macOS. Its hybrid backends preserve the interpreter's checked memory,
> helper, call, atomic, and tail-call semantics. rbpf 0.4.1 also offers an
> optional Cranelift backend; that is an alternative implementation strategy,
> not a missing febpf API on febpf's supported JIT targets. rbpf may have
> unmeasured host-native reach through Cranelift on additional 64-bit targets,
> so febpf does not claim universal native-backend platform dominance.

Avoid these claims:

- “febpf supports every native target rbpf supports” — the rbpf target matrix
  is not measured sufficiently to prove or disprove it;
- “rbpf Cranelift has recoverable memory errors” — its OOB trap conversion test
  is ignored;
- “rbpf Cranelift fully supports eBPF” — atomics, tail calls, and local calls
  are concrete backend gaps;
- “passing rbpf legacy-load tests proves Linux compatibility” — the tested
  multi-byte values are little-endian and include a non-standard DW form;
- “febpf needs Cranelift for parity” — no user-visible capability missing on
  febpf's claimed JIT platforms has been demonstrated.

## 8. Trigger for future backend work

Do not schedule a speculative backend. Open a backend implementation batch
only when all of the following are true:

1. a named OS/architecture matters to an actual febpf use case;
2. rbpf 0.4.1 or the chosen comparison version successfully runs its Cranelift
   suite there, including a separately added runtime-fault probe;
3. febpf's interpreter is insufficient for that use case;
4. expected performance or deployment value justifies CI capacity and ongoing
   encoder maintenance.

For riscv64, the existing `JitBackend` specification is the appropriate
zero-dependency route. Before implementation, add a runner/emulator experiment
that checks executable-memory setup, trampoline ABI, instruction-cache flush,
branch range, interpreter/JIT differential behavior, and structured faults.
For x86-64 macOS or Windows, first decide whether extending febpf's x86 encoder
and W^X allocation layer is smaller and safer than introducing a new backend.

Legacy packet loads are independent work and should proceed first. Once their
kernel-defined B/H/W forms are green in interpreter, both febpf native JITs can
inherit them safely through deferred execution without backend-specific opcode
lowering.
