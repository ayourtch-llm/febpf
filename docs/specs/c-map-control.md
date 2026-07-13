# Native C map configuration and control

STATUS: v1 runtime control implemented (2026-07-13)

The native ABI separates map operations by lifetime. ELF capacity overrides
are construction inputs; lookup/update/delete operate on maps already owned by
an opaque VM. Neither surface exposes a Rust `Map`, value pointer, storage
address, or guest virtual address.

## Pre-construction configuration

`febpf_vm_create_elf_v2` accepts an array of
`febpf_map_max_entries_v1` descriptors. Each descriptor names one map exactly
and supplies a nonzero `max_entries`. Names must be unique within the request.
Overrides are applied to the loaded `elf::Object` before `Vm::new`, which is
the only point where storage capacity can be changed without invalidating map
regions and verifier assumptions.

The v2 array has the fixed stride `sizeof(febpf_map_max_entries_v1)`, so each
element must report exactly that `struct_size`. A future larger element will
use a new container descriptor with an explicit stride rather than making an
old array walker guess where its next element begins.

This mirrors `Object::set_map_max_entries` and unlocks objects whose BTF map
definition deliberately encodes zero for application-side sizing. Unknown map
names, duplicate overrides, zero capacities, incompatible map-in-map results,
and allocation/construction failures are reported instead of silently ignored.
The original v1 ELF constructor remains source- and binary-compatible.

## Runtime operations

The runtime functions address a map by exact UTF-8 name on an exclusively
borrowed VM handle:

- `febpf_vm_map_info` copies kind, flags, key/value sizes, capacity, and logical
  CPU count into a versioned output structure.
- `febpf_vm_map_lookup` copies one value into an exactly sized caller buffer.
- `febpf_vm_map_update` copies one key/value pair with ANY, NOEXIST, or EXIST
  semantics.
- `febpf_vm_map_delete` deletes one hash-family key.

Unknown maps and absent keys return `FEBPF_STATUS_NOT_FOUND`. Invalid caller
buffer sizes return `FEBPF_STATUS_INVALID_ARGUMENT`. Map-semantic failures—
frozen values, array deletion, capacity exhaustion, incompatible kinds, and
update-mode conflicts—return `FEBPF_STATUS_MAP` with the underlying errno in
the thread-local diagnostic. Output buffers are written only on success.

Array/hash, per-CPU array/hash, LRU hash, stack-trace, cgroup array, devmap,
cpumap, devmap-hash, and XSKMAP storage use the byte-value path. Ring/perf
output, queues, program arrays, and maps-of-maps require typed operations and
are rejected by these generic byte functions rather than misrepresented.

## Per-CPU and concurrency contract

febpf execution has one deterministic logical CPU, CPU 0. Runtime map lookup
and update therefore access CPU 0's `value_size` bytes, matching what guest
helpers observe. `FEBPF_MAP_PER_CPU` plus `cpu_count` reports that other lanes
exist; v1 does not pretend the caller supplied the kernel syscall ABI's packed
all-CPU blob. Explicit lane access can be added independently if a real host
needs it.

Like run/verify, map operations require exclusive use of the VM handle. This
makes update-mode existence checks and mutations atomic with respect to other
ABI calls. An LRU lookup updates recency exactly as a guest lookup does. Map
state is durable across invocations and remains part of snapshots/replay on the
Rust surface.

## Validation host

`examples/c-map-host` proves both lifetimes against committed clang fixtures.
It reduces `legacy_maps.o::counts` from 16 entries to 1, inserts one key, and
observes `E2BIG` on a second. It then runs `global_data.o`, observes result 410,
sets `.data` to 7, runs again, and reads result 820, `.bss` 20, and `.data` 8.
An attempted `.rodata.cst16` update returns `EPERM`. The host compiles as C11
with `-Wall -Wextra -Werror` in `scripts/test-c-api.sh`.

The complete validation matrix is **477 + 4 ignored** default, **459 + 4**
std-only, **486 + 4** C API/JIT, and **468 + 4** C API/interpreter-only. Strict
Clippy passes in all four profiles, true thumb no-std remains green, and both
native library forms build. The pinned corpus is unchanged at 137 families,
835/835 entries loaded, and 822/835 verified; all environment and poisoned
application outcomes retain their prior classifications.
