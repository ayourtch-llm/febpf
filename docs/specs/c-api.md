# Native C embedding API

STATUS: v1 implemented (2026-07-13)

The opt-in Cargo feature `c-api` exposes a hand-written, versioned native ABI
declared by `include/febpf.h`. It adds no dependencies. Artifact choice stays
explicit so normal `rlib` and true no-std builds are unchanged:

```sh
cargo rustc --lib --release --features c-api -- --crate-type=cdylib
cargo rustc --lib --release --features c-api -- --crate-type=staticlib
```

`scripts/test-c-api.sh` builds the shared library, compiles the zero-dependency
C example, and runs it against that library.

## Stable v1 surface

- `febpf_c_abi_version` reports ABI version 1.
- `febpf_vm_create_assembly` and `febpf_vm_create_bytecode` copy their inputs
  into an opaque VM handle. Raw bytecode is the ordinary little-endian sequence
  of eight-byte eBPF instruction slots.
- `febpf_vm_create_elf` loads a relocatable eBPF object, selects an exact
  program name, and accepts target BTF as either a raw blob or an ELF object
  containing `.BTF`. Objects that need kernel BTF must receive it; multi-entry
  objects require an explicit selector. Section kind constrains later
  verification to XDP, skb, or Flat semantics as appropriate.
- `febpf_vm_create_elf_v2` adds exact-name, nonzero map-capacity overrides
  before storage is instantiated. The original constructor remains unchanged.
- `febpf_vm_verify` always runs febpf's verifier and selects Flat, XDP, or skb
  context semantics. Writable flat context, strict alignment, privileged
  uninitialized-stack policy, verifier budget, and runtime instruction limit
  are explicit options.
- `febpf_vm_run` borrows one versioned invocation descriptor. Flat invocations
  supply mutable context; XDP/skb invocations supply a mutable packet and use a
  synthesized context. Interpreter execution is default and JIT is an explicit
  invocation flag when the library was built with `jit`; otherwise that flag
  returns `FEBPF_STATUS_UNSUPPORTED`.
- An optional output callback receives invocation-local printk lines and binary
  sequence output, including output produced before a later runtime failure.
  Callback bytes are borrowed only until it returns.
- `febpf_vm_map_info`, `febpf_vm_map_lookup`, `febpf_vm_map_update`, and
  `febpf_vm_map_delete` provide copied, exact-name runtime map control. They
  expose CPU 0 values for per-CPU maps and never expose internal pointers.
- `febpf_vm_define_helper` installs a scalar-returning verifier signature before
  verification. `febpf_vm_run_v2` binds its callback and user token for one
  invocation. Scalar arguments cross by value; memory arguments cross as
  bounded copies, with successful writable views copied back in argument order.
- `febpf_vm_destroy` consumes the opaque handle. `febpf_last_error` copies the
  calling thread's diagnostic with a length-query contract.

Every descriptor begins with `struct_size`. V1 rejects truncated structs and
unknown flags, but accepts a larger size so fields can be appended compatibly.
Statuses are fixed-width `uint32_t` constants rather than C enums whose ABI can
vary by compiler.

### ELF construction

`febpf_elf_options_v1` keeps loading separate from verification and execution;
`febpf_elf_options_v2` adds only pre-instantiation map-capacity configuration.
All object, selector, and target-BTF bytes are consumed during construction;
the handle retains only the relocated program, maps, BTF-derived verifier
metadata, and section-derived context constraint. A target may be a raw BTF
blob such as `/sys/kernel/btf/vmlinux` or a complete ELF carrying `.BTF`.

An omitted selector is accepted only for a single-entry object. An object with
CO-RE relocations or a BTF-typed context is rejected without target BTF rather
than running against compiler-local layout. XDP and skb-family ELF sections
must subsequently be verified under their matching context model. V1 also
fails closed on loader warnings and static tail-call initializers, because it
has neither a warning sink nor a verification-time bundle-link descriptor.

### Custom helper add-on

Custom helpers deliberately split program configuration from per-run host
resources. `febpf_helper_signature_v1` is durable verifier input and accepts
only the safe initial subset: unused/scalar arguments, size arguments, and
read, write, or read-write memory whose length is named by a size argument.
Helper ids begin at 65536 and the v1 return is scalar. Map pointers, context
pointers, BTF pointers, external-memory returns, and host pointers are not
smuggled through scalar fields.

`febpf_invocation_v2` composes an array of exact-stride helper bindings with
the existing context, packet, output, and JIT resources. The callback and user
token are borrowed only until `febpf_vm_run_v2` returns. Each memory argument
is copied into a bounded callback view; its guest virtual address is not
exposed. A successful callback copies writable views back in argument order.
A non-OK callback status becomes a deterministic runtime failure and performs
no writeback. Returning an application error to eBPF remains possible by
returning `FEBPF_STATUS_OK` and placing the desired scalar (including a
two's-complement negative errno) in `result`.

Bindings are restored to unavailable placeholders after every run, including
Rust panic unwinding caught by the outer ABI boundary. Interpreter and JIT use
the same runtime dispatch. Callbacks must not retain borrowed pointers, throw a
C++ exception across C, or re-enter the same exclusively borrowed VM handle.

## Architectural boundary

The C layer stores only durable `Vm` state (including custom-helper verifier
signatures), the last successfully verified context model, and an ELF
section's optional context-model constraint. Every run translates caller
buffers, output callbacks, and helper bindings into fresh invocation
resources; no caller pointer, object/BTF bytes, callback, packet, context,
user token, or sink is retained after the function returns. XDP packet bytes
are borrowed directly through `ExecutionEnvironment::xdp_slice`, not staged
in `Vm`.

Guest-visible pointers remain febpf virtual addresses. A C pointer is never
placed in an eBPF register. The host must still obey ordinary FFI ownership:
buffers must be live for the call, mutable buffers must be uniquely borrowed,
a VM may not be used concurrently, and each non-null handle is destroyed once.
Rust panics in exported VM operations are caught before crossing the ABI boundary
and reported as `FEBPF_STATUS_PANIC`.

## Deliberate v1 limits

Typed ring/perf/queue consumption, program/map-in-map linking, nonzero per-CPU
lane access, pointer-returning custom helpers, snapshots/replay,
application-supplied attach targets, provider-owned resizable frames, and rich
redirect completion are not silently squeezed into generic byte-map
operations. Static `PROG_ARRAY` initializers are rejected until
verification-time bundle linking has a versioned contract. Loader warnings are
errors because v1 has no warning sink. These gaps need separately versioned
descriptors or handles. The Rust embedding API remains the complete surface in
the meantime.

## Validation record

- Default all-target tests: **477 passed + 4 ignored**; std-only:
  **459 passed + 4 ignored**.
- Default/JIT `c-api` all-target tests: **487 passed + 4 ignored**.
- Std interpreter-only `c-api` all-target tests: **469 passed + 4 ignored**.
- Strict Clippy passes for both C API feature profiles; the ordinary default,
  std-only, and true thumb no-std profiles remain green.
- Both explicit cdylib and staticlib builds succeed. The C11 hosts compile with
  `-Wall -Wextra -Werror`, dynamically link the fifteen exported v1 symbols,
  and exercise assembly, streaming Flat-context filtering, and ELF/CO-RE. The
  ELF host drops its input buffers immediately after construction and prints
  `core-result=123` after relocating against a target-BTF ELF. The map host
  prints `map-state: first=410 second=820 counter=20 scale=8` after proving
  construction-time capacity and runtime durability. The helper host prints
  `helper-state: interp=123/42 jit=123/100 calls=3` after proving failed-call
  isolation, copied memory writeback, and interpreter/JIT parity.
- The complete pinned corpus remains unchanged at 137 families, 135 objects
  loaded, 126 fully compatible families, 835/835 entries loaded, and 822/835
  verified (673 strict + 149 privileged-uninitialized). The remaining six
  attach-target, seven poisoned-relocation, and two missing-kfunc gaps retain
  their honest classifications; blocker histograms remain empty.
