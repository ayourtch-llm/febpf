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
- `febpf_vm_destroy` consumes the opaque handle. `febpf_last_error` copies the
  calling thread's diagnostic with a length-query contract.

Every descriptor begins with `struct_size`. V1 rejects truncated structs and
unknown flags, but accepts a larger size so fields can be appended compatibly.
Statuses are fixed-width `uint32_t` constants rather than C enums whose ABI can
vary by compiler.

## Architectural boundary

The C layer stores only durable `Vm` state plus the last successfully verified
context model. Every run translates caller buffers and output callbacks into a
fresh `ExecutionEnvironment`; no caller pointer, callback, packet, context, or
sink is retained after the function returns. XDP packet bytes are borrowed
directly through `ExecutionEnvironment::xdp_slice`, not staged in `Vm`.

Guest-visible pointers remain febpf virtual addresses. A C pointer is never
placed in an eBPF register. The host must still obey ordinary FFI ownership:
buffers must be live for the call, mutable buffers must be uniquely borrowed,
a VM may not be used concurrently, and each non-null handle is destroyed once.
Rust panics in exported VM operations are caught before crossing the ABI boundary
and reported as `FEBPF_STATUS_PANIC`.

## Deliberate v1 limits

ELF entry selection/CO-RE target BTF, map administration, custom C helper
callbacks, snapshots/replay, metadata/BTF contexts, provider-owned resizable
frames, and rich redirect completion are not silently squeezed into v1. They
need separately versioned descriptors or handles. The Rust embedding API
remains the complete surface in the meantime.

## Validation record

- Default/JIT `c-api` all-target tests: **480 passed + 4 ignored**.
- Std interpreter-only `c-api` all-target tests: **462 passed + 4 ignored**.
- Strict Clippy passes for both C API feature profiles; the ordinary default,
  std-only, and true thumb no-std profiles remain green.
- Both explicit cdylib and staticlib builds succeed. The C11 host compiles with
  `-Wall -Wextra -Werror`, dynamically links the seven exported v1 symbols,
  and prints `printk: n=42` plus `result=9 context=[9,7]` before exiting zero.
- The complete pinned corpus remains unchanged at 137 families, 835/835 entries
  loaded, and 822/835 verified (673 strict + 149 privileged-uninitialized).
