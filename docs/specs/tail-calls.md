# Program arrays and tail calls

Status: userspace-populated and static ELF program bundles are implemented
across verifier, interpreter, JIT, snapshots/debugger, replay, CLI, and kernel
conformance APIs. The pinned corpus now includes Cilium's sparse static
program-array loader fixture; loading that complete object is currently
blocked by its separate `ARRAY_OF_MAPS` declaration. Privileged execution of
the static ELF graph remains before this item is fully closed.

## Goal

Support real multi-program eBPF objects that dispatch through
`BPF_MAP_TYPE_PROG_ARRAY` and helper `bpf_tail_call` (id 12), while preserving
febpf's verifier-first safety, deterministic replay, and kernel differential
testing. A tail call is a program-graph edge, not a bpf-to-bpf subprogram call.

## Kernel-visible semantics

- A program array has u32 keys and u32 program-fd values in the kernel ABI.
  febpf stores stable program identities instead of host/kernel descriptors.
- `bpf_tail_call(ctx, map, index)` succeeds only when `map` is a program array,
  `index < max_entries`, the slot is populated with a compatible program, and
  the chain limit has not been exhausted.
- Success starts the target at instruction zero and never returns. The target
  receives the original context in r1, fresh/uninitialized r2-r9, r10 at a
  fresh stack top, and shares the bundle's maps. The old program's registers,
  local-call frames, and stack values are inaccessible.
- Failure has no observable helper return value: execution falls through to
  the instruction after the call. This includes an empty/out-of-range slot and
  chain-limit exhaustion.
- The chain counter follows the kernel `MAX_TAIL_CALL_CNT` boundary (33
  successful dispatch attempts in the UAPI documentation used by this repo).

## Bundle and linking model

A `ProgramBundle` owns named programs plus shared map definitions. Its entry
program is selected exactly as ELF loading selects one today. Program-array
slots contain bundle program ids. Two population paths are required:

1. An embedding API equivalent to userspace writing a loaded program fd into
   a `PROG_ARRAY` slot (the common BCC/control-plane model).
2. ELF map-initializer relocations naming program sections (libbpf's static
   initialization model).

Every target is verified independently with the same program/context type.
Registration refuses an unverified or incompatible target. Map pseudo-lddw
instructions in every program resolve against the bundle's one shared map set.

## Runtime, JIT, and debugging

The interpreter tracks `(program_id, pc, tail_call_count)`. A successful helper
dispatch replaces `program_id`, resets execution-local state, and continues at
pc 0. Snapshots and replay files must include all three fields and the bundle;
debugger locations render as `program:pc` once more than one program exists.

The hybrid JIT defers helper 12 and resumes through a bundle-level dispatcher;
it never resumes the caller's compiled stream after success.
Interpreter/JIT/kernel differential tests cover hits, misses, cycles, and the
exact chain boundary.

## Coverage obligations

- ELF loader recognizes map type 3 instead of reporting a load blocker.
- Verifier requires `(Any ctx, ConstMapPtr prog_array, Scalar index)` and
  rejects helper 12 with any other map kind.
- Runtime tests cover shared-map state across programs and inaccessible caller
  stack/register state.
- Kernel tests populate a real program array with program fds and compare
  return values at missing, successful, cyclic, and limit-boundary cases.
- The corpus gains at least one userspace-populated and one ELF-initialized
  real-world program graph; coverage claims report program graphs separately
  from standalone objects.

## Implemented ELF form

The BTF `.maps` parser records the byte offset of a `values` flexible-array
member. `R_BPF_64_ABS64` relocations inside that map's exact slot range become
`ProgArrayInit` edges from `(map, index)` to an executable ELF section. Sparse
slots are preserved, duplicate and misaligned initializers are rejected, and
each target is independently verified when the CLI constructs the VM. The
same links are installed as real program fds for kernel conformance runs and
serialized into optional replay bundle sections.
