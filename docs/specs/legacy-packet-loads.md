# Legacy eBPF packet loads

STATUS: specification; implementation pending

## Goal and scope

Implement the deprecated `LD_ABS` and `LD_IND` packet-load families without
weakening febpf's verifier or virtual-memory model. The Linux-standard
`BPF_LD | BPF_ABS/IND | BPF_B/H/W` instructions form the normative feature.
An explicit compatibility profile additionally reproduces rbpf 0.4.1's
publicly documented `DW` extension and little-endian load results.

This is packet-input support, not generic memory access. No instruction in
this family may expose a host address, bypass a region bound, or turn an
ordinary context/map/stack address into a packet.

Normative references and comparison evidence:

- [RFC 9669, section 5.5](https://www.rfc-editor.org/rfc/rfc9669.html#section-5.5)
  defines the historical packet conformance group, its encodings, and only
  the `B`, `H`, and `W` sizes.
- [Linux implementation notes](https://docs.kernel.org/bpf/linux-notes.html#legacy-bpf-packet-access-instructions)
  define packet-only applicability, the seven implicit register operands,
  network byte order, and implicit termination on an invalid access.
- rbpf 0.4.1's public assembler/disassembler and public interpreter,
  handwritten-JIT, and Cranelift tests expose all eight `ABS/IND × B/H/W/DW`
  encodings. Its test vectors expect little-endian numeric results (for
  example bytes `33 44` produce `0x4433`), which intentionally differs from
  Linux's network-order semantics. Those tests are behavioral evidence only;
  no rbpf implementation code is to be copied.

The instructions are deprecated. febpf accepts existing binaries and makes
their behavior inspectable; documentation and the builder must not recommend
them for new portable programs.

## Profiles and configuration

Legacy packet access is disabled by default. Add this verifier configuration:

```text
legacy_packet: LegacyPacketProfile

LegacyPacketProfile::Disabled             // default
LegacyPacketProfile::Linux
LegacyPacketProfile::Rbpf041
```

The selected profile is part of successful-verification state stored in the
VM, is cleared by `Vm::replace_program`, and must agree across an entry
program and every tail-call target.

`Linux` means:

- accept `B`, `H`, and `W`; reject `DW`;
- interpret multi-byte fields in network (big-endian) byte order;
- require the program to establish `r6` from the entry packet context as
  described below;
- terminate the invocation with return value zero on an invalid packet load.

`Rbpf041` is a named, non-kernel compatibility mode:

- accept `B`, `H`, `W`, and `DW`;
- interpret multi-byte fields as little-endian, matching rbpf 0.4.1's public
  test vectors deterministically on every host;
- obtain the packet from febpf's explicit input adapter, so no meaningful
  `r6` value is required (matching rbpf's raw/fixed-metadata public behavior);
- report invalid packet loads as an `EbpfError`, matching rbpf's checked
  interpreter behavior rather than Linux's implicit zero-return exit.

The profile split is deliberate. A single ambiguous mode would either call
rbpf's `DW` and little-endian behavior "Linux", or make faithful execution of
one of the two observable contracts impossible.

## Encoding and validation

All instructions occupy one 8-byte slot. `dst_reg` and `offset` are reserved
and must be zero. `ABS` also requires `src_reg == 0`. `IND.src_reg` is its
explicit scalar index register. `imm` is the signed 32-bit displacement.

| Instruction | Opcode | Effective packet offset |
|---|---:|---|
| `LD_ABS_W` | `0x20` | `imm` |
| `LD_ABS_H` | `0x28` | `imm` |
| `LD_ABS_B` | `0x30` | `imm` |
| `LD_ABS_DW` | `0x38` | `imm` (rbpf profile only) |
| `LD_IND_W` | `0x40` | `u64(src) + imm` |
| `LD_IND_H` | `0x48` | `u64(src) + imm` |
| `LD_IND_B` | `0x50` | `u64(src) + imm` |
| `LD_IND_DW` | `0x58` | `u64(src) + imm` (rbpf profile only) |

Structural validation rejects nonzero reserved fields, an invalid register,
an unsupported size/mode/class combination, and `DW` outside `Rbpf041`.
`ABS` with a negative immediate is rejected statically. For `IND`, compute the
effective offset in a widened mathematical domain: `u64(src) + i64(imm)` must
be representable as a nonnegative `u64`, and `offset + size` must not overflow.
Never use wrapping address arithmetic to turn underflow into a valid access.

The normal instruction decoder and raw-byte loader preserve these opcodes.
An `LD_ABS/IND` instruction is never wide: opcode `0x38` is one rbpf-extension
slot and must not consume the following instruction as an `lddw` tail.

## Register semantics

The Linux form has seven implicit operands:

- `r6` is an input packet-context capability;
- `IND.src_reg` is an additional explicit input (`ABS.src_reg` is reserved);
- `r0` is the zero-extended output;
- `r1` through `r5` are clobbered outputs.

febpf represents the packet capability abstractly; it never constructs a
userspace `struct sk_buff` or places its address in `r6`. In the `Linux`
profile, the verifier requires `r6` to contain an unmodified alias of the
entry context (`r6 = r1`, possibly through register/stack copies). Arithmetic,
pointer casts, a helper call, a subprogram call that does not preserve it, or
overwriting the alias makes it invalid. The runtime still selects bytes from
the active packet adapter, not by dereferencing `r6`.

In `Rbpf041`, `r6` remains an implicit compatibility operand in disassembly
and liveness documentation but is not required or dereferenced. This permits
rbpf's public raw-buffer examples, which execute `LD_ABS` without first
initializing `r6`.

On every successful load, write the unsigned result to all 64 bits of `r0`
and set `r1..r5` to zero. Linux only promises that these registers are
clobbered; deterministic zeroing follows febpf's existing helper/tail-call
scrubbing convention. `IND` reads its source before scrubbing, including when
the source is one of `r1..r5`. `r6..r10` otherwise remain unchanged. Verifier
state after the instruction is `r0 = known scalar of the selected width`,
`r1..r5 = unreadable/clobbered`, and preserved state for `r6..r10`.

## Data and byte-order semantics

Given a packet byte slice `P`, effective offset `i`, and width `n`, a load is
valid iff `0 <= i` and `i + n <= P.len()`. Unaligned packet loads are valid;
`strict_alignment` does not apply to this family.

For the `Linux` profile:

```text
B:  r0 = P[i]
H:  r0 = u16::from_be_bytes(P[i..i+2])
W:  r0 = u32::from_be_bytes(P[i..i+4])
```

This is host-independent network-byte-order behavior. For `Rbpf041`, use
`from_le_bytes` for `H`, `W`, and `DW`; `B` is identical. The `DW` behavior is
an rbpf compatibility extension and is not part of RFC 9669's `packet`
conformance group. Kernel-oriented tools must diagnose it as non-portable.

Legacy loads are read-only even when the selected packet backing is mutable.
Packet writes continue to require ordinary verified packet-pointer stores.

## Verifier rules

The verifier handles this family in two layers.

Structural validation:

1. Reject when `legacy_packet == Disabled` with a diagnostic that names the
   opcode and the required profile.
2. Enforce the reserved fields, source register, size, and `DW` rules above.
3. Reject a negative `ABS.imm` and an invalid `IND.src_reg`.
4. Treat the instruction as a single slot for CFG targets and complexity.

Abstract execution:

1. Require an armed packet input contract. The profile alone authorizes the
   opcode; the execution adapter supplies the per-run bytes.
2. In `Linux`, require `r6` to be the unmodified entry-context capability.
3. In `IND`, require the source register to be an initialized scalar. Pointer
   values, unreadable/clobbered values, and uninitialized values are rejected.
4. Constant/range facts may prove an access impossible (negative/overflowing)
   and should then reject it. A runtime packet length is generally unknown, so
   lack of a static length proof does not reject an otherwise valid legacy
   load; the instruction's specified implicit-exit check is the safety guard.
5. Apply the register effects above. The instruction does not refine or grant
   ordinary `PtrKind::Packet` ranges and therefore cannot replace a
   `data_end` check for direct packet access.

Tail-called programs receive the same active packet input and profile. Local
subprograms may use legacy loads only under the same verifier rules. The
verifier must include the implicit `r0..r6` effects in state equality,
pruning, liveness, diagnostics, and counterexample paths.

## Runtime input integration

No general `Vm::run` invocation silently guesses which region is a packet.
If a verified program contains a legacy load and the selected runner has no
packet backing, execution fails before instruction zero with
`legacy packet input unavailable for this execution adapter`.

The adapters bind packet bytes as follows:

| Adapter | Legacy packet backing | Notes |
|---|---|---|
| `run_raw` / `run_raw_jit` | the caller's mutable raw buffer | Context accesses through `r1` and legacy reads alias the same bytes. |
| `run_xdp` / XDP JIT counterpart | the dedicated `Vm::packet` region | This userspace composition is useful but is not a claim that Linux accepts legacy loads for XDP program type. |
| `run_metadata` / `run_metadata_jit` | the registered RW owned region named by the prepared `data` field | Validate the base, handle, permissions, and exact active region before entry. |
| `run_fixed_metadata` and JIT counterpart | same owned region as configurable metadata | The zero-filled metadata buffer does not become the packet. |
| `run`, `run_no_data`, ordinary `run_jit` | none | Reject before execution if the program uses legacy loads. |

For backward compatibility, `run_raw` remains equivalent to `run` for
programs without legacy loads. A dedicated internal packet-view enum should
make the binding explicit; do not alias two mutable Rust slices or copy raw
input merely to simplify borrowing. Legacy reads only need a shared view,
while ordinary context stores retain the caller's mutable view.

`run_xdp` continues to copy packet mutations back on clean exit and runtime
error. Metadata execution continues to mutate the owned region. A legacy load
never changes either backing.

## Invalid access and termination

Invalid means no packet backing, negative/overflowing effective offset, or a
range outside the selected packet.

- Missing backing is an embedding misuse and always returns `EbpfError` before
  instruction zero.
- In `Linux`, an invalid in-program packet range performs an implicit program
  exit with `r0 = 0`. It is a clean `Ok(0)`, not an `EbpfError`; no following
  instruction or caller frame executes. This models the networking filter's
  abort/drop result.
- In `Rbpf041`, an invalid in-program range returns a bounds `EbpfError` at the
  legacy instruction PC, matching rbpf's checked interpreter contract.

Both outcomes count the faulting/terminating instruction once, preserve prior
packet/context mutations, and remain deterministic. A debugger stops after
the instruction with a distinct `LegacyPacketExit` reason in Linux mode or
the ordinary runtime error in rbpf mode. Profiling attributes the event to
the legacy instruction.

Unchecked execution retains every runtime check above. Verification may
reject malformed encodings and invalid register types, but skipping
verification must never permit an unchecked host read.

## Interpreter and hybrid JIT

Implement one shared interpreter primitive that resolves the active packet,
checks widened arithmetic and bounds, decodes byte order, applies register
clobbers, and reports `Continue`, `ImplicitExit(0)`, or `Fault`. `Machine::step`
uses it directly.

Initially classify every legacy load as deferred. The backend spill mask must
include `r6` in `Linux`, the `IND` source in both profiles, and any other live
register the trampoline needs. The reload mask includes `r0..r5`; control
does not resume on implicit exit or fault. This gives x86-64 and AArch64 the
same checked behavior without new native encodings. `run_jit` must surface
the same `Ok(0)` versus `EbpfError { pc, ... }` distinction as the interpreter.

Native lowering is an optional later optimization and may land only with the
same arithmetic, bounds, byte order, register scrubbing, STOP/fault reporting,
and differential tests. JIT compilation failure must continue to fall back
cleanly to interpretation.

## Assembly, disassembly, builder, and diagnostics

Use stable rbpf-compatible mnemonics because they are concise and already
identify the implicit destination:

```text
ldabsb 14
ldabsh 12
ldabsw 26
ldindb r2, 1
ldindh r3, -2
ldindw r4, 8
ldabsdw 3        ; accepted only with the rbpf profile at verification
ldinddw r1, 3    ; accepted only with the rbpf profile at verification
```

Assembler output sets all reserved fields to zero. Immediates must fit `i32`.
`ABS` syntax has one immediate; `IND` has a 64-bit `rN` scalar and an
immediate. The disassembler emits these exact forms, never the current
`<legacy ld ...>` placeholder, so assemble-disassemble-assemble round trips
all eight encodings. For malformed reserved fields, disassembly appends an
explicit `<invalid ...>` annotation rather than normalizing away evidence.

The typed builder may expose deprecated methods under a clearly named
`legacy_packet` group. Documentation must point callers to direct packet
access for new programs. CLI verification errors must distinguish "legacy
packet profile disabled", "DW requires Rbpf041", "r6 is not packet context",
"IND index is not a scalar", and runtime "legacy packet access out of bounds".

## Snapshot, debugger, race, and replay

`Snapshot` already captures registers, context, `Vm::packet`, owned regions,
PC, and counters. Add the active packet-view identity and profile if they are
not VM-stable fields. Restoration must select the same backing without storing
a Rust reference or host address. Stepping backward across a successful load
restores `r0..r5`; stepping backward across implicit exit reopens the machine
at the legacy instruction.

Race-explorer instances must carry their own raw context image while sharing
only the resources already designated shared. A legacy raw packet therefore
tracks the active instance's context, not another instance's slice.

Replay needs an optional `LEGACY_PACKET` section containing only the profile
tag (`Linux` or `Rbpf041`). Presence arms legacy verification and execution:

- with `PACKET`, replay binds the recorded XDP packet;
- without `PACKET`, replay treats `CTX` as the raw packet and uses the raw
  adapter;
- configurable-metadata replay remains rejected with a precise diagnostic
  until replay files support external owned regions and their selected base.

The section contains no address. Old files without it retain current
behavior. A reader that understands the tag rejects unknown profile values;
the normal unknown-section rule remains unchanged. Recording includes the
section only when the verified program uses legacy loads. The outcome guard
then covers implicit zero exits and rbpf-profile errors normally.

## Test and differential strategy

### Encoding and tools

- Exact instruction bytes and round trips for all eight encodings.
- Reserved-field, bad-register, out-of-range-immediate, disabled-profile, and
  Linux-`DW` rejection tests.
- Confirm `0x38` consumes one slot and a following instruction executes.

### Semantic table

Use the fixed packet
`00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff` and cover every
`ABS/IND × size` combination, unaligned offsets, zero offset, last valid byte,
empty packets, negative `IND.imm`, large scalar indices, addition overflow,
and each one-byte OOB boundary. Assert:

- Linux big-endian B/H/W results;
- rbpf little-endian B/H/W/DW results matching its public vectors;
- `IND` reads its source before `r1..r5` are zeroed;
- `r0` zero-extension, `r1..r5 == 0`, and preservation of `r6..r10`;
- Linux implicit `Ok(0)` versus rbpf-profile `EbpfError`;
- interpreter/JIT/debugger/snapshot agreement.

Run the same legal cases through raw, XDP, caller metadata, and fixed metadata
adapters. Verify aliasing after ordinary writes, owned-region selection,
replacement reset, tail-call inheritance, and missing-backing rejection.

### Linux kernel differential

Generate raw socket-filter-compatible eBPF objects for B/H/W ABS and IND.
Load them as a networking `sk_buff` program type and compare verifier verdict,
return value, and boundary behavior using `BPF_PROG_TEST_RUN`. Include both
constant and scalar indices, unaligned loads, minimum packet lengths, negative
offset attempts, and programs that preserve values in `r1..r5` across the
instruction (kernel rejection or clobber behavior is evidence, not an
assumption).

Do not use XDP as the kernel oracle for this deprecated skb-context family.
The febpf XDP-adapter tests prove internal composition only. Submit `DW` to the
kernel as a negative/non-standard case and never count its rejection against
Linux-profile parity. Kernel tests must skip clearly when privileges or the
required program type are unavailable.

### rbpf behavioral comparison

Derive black-box cases from rbpf 0.4.1's public API/tests:

- assembler/disassembler spellings for all eight encodings;
- raw-buffer and fixed-metadata B/H/W/DW result vectors;
- ABS and IND offset calculation;
- no-data and OOB checked-interpreter errors;
- interpreter, handwritten JIT, and Cranelift result agreement where rbpf's
  public tests claim it.

The febpf `Rbpf041` profile must match deterministic successful results and
checked-interpreter errors. Record separately that rbpf's public handwritten
JIT tests state bounds checks are absent; febpf must not reproduce that safety
gap. No test or implementation may copy rbpf source code.

### Configuration matrix

Run default JIT tests, `std` interpreter-only tests, strict clippy in both,
and the true `no_std + alloc` library check. Legacy packet support belongs in
the portable core and adds no dependency. Windows and wasm interpreter tests
must cover at least one successful and one OOB case; native JIT cases run on
the existing supported architecture CI.

## Delivery order

1. Constants/decoding, profile type, structural verifier rules, assembler,
   disassembler, builder methods, and exact encoding tests.
2. Packet-view binding for raw, XDP, and metadata adapters; interpreter
   semantics and verifier register effects.
3. Hybrid-JIT deferred masks/control outcomes and interpreter/JIT tests.
4. Snapshot/debugger/race/replay integration.
5. Linux kernel differential and rbpf black-box behavior matrix.
6. Capability documentation and parity-audit update only after all acceptance
   criteria pass.

Each step is a separate reviewable commit and leaves all supported build
profiles green.

## Acceptance criteria

The work is complete only when:

1. All six RFC/Linux encodings execute with network byte order and Linux
   implicit-exit behavior under an explicit `Linux` profile.
2. The two `DW` encodings are rejected as non-standard in `Linux` and execute,
   together with B/H/W, with rbpf 0.4.1's public little-endian behavior under
   explicit `Rbpf041`.
3. Reserved fields, profile applicability, `r6`, IND scalar input, register
   clobbers, arithmetic overflow, and packet bounds are verified and have
   stable diagnostics.
4. Interpreter and hybrid JIT agree on return values, full registers, packet
   bytes, errors/PCs, implicit exits, and instruction counts.
5. Raw, XDP, caller-metadata, and fixed-metadata adapters select exactly the
   intended packet; generic/no-data execution cannot guess or escape memory.
6. Snapshots/time travel and supported replay forms reproduce both profiles
   without serializing host addresses.
7. Linux B/H/W differential tests and rbpf 0.4.1 black-box tests pass, with
   intentional differences (`DW`, byte order profile, and febpf JIT bounds
   safety) explicitly reported.
8. Default JIT, `std` interpreter-only, no-std, wasm, Windows, and strict
   clippy checks remain green with zero dependencies.
9. Capability/parity documentation claims the RFC `packet` conformance group
   only for the Linux profile and labels `Rbpf041` as a compatibility
   extension.
