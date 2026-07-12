# Array-of-maps support

Status: implemented for `BPF_MAP_TYPE_ARRAY_OF_MAPS`, including BTF static
initializers, verifier typing, interpreter/JIT execution, replay, and kernel
differential validation.

## Coverage motivation

Cilium/ebpf v0.21.0's `testdata/btf_map_init.c` is a real ELF-loader fixture
containing both a sparse static `PROG_ARRAY` and a sparse static
`ARRAY_OF_MAPS`. Tail-call support made the former loadable; map type 12 was
then the next measured blocker preventing the complete upstream object from
loading. The pinned corpus compiles and scans that object unchanged.

## Model

An outer map definition records:

- the map index used as its inner-map template;
- sparse `(outer slot, concrete inner map index)` initializers.

The template and every concrete inner map must agree on kind, key size, value
size, and maximum entries. Outer keys and kernel ABI values are u32. Runtime
slots hold stable map identities rather than host pointers or file
descriptors.

`map_lookup_elem(outer, key)` returns either NULL or a map-object pointer typed
as the template map. The verifier requires a null check before that pointer can
be passed as the map argument to another helper. It is never a dereferenceable
map-value pointer. BPF-side update/delete of an outer map is rejected; outer
map population is a loader/userspace operation.

## ELF and kernel loading

The BTF parser recognizes map type 12 and obtains its template from the
`values` flexible-array element type. `R_BPF_64_ABS64` relocations within that
map's exact `values[]` byte range populate sparse slots. ELF symbol values,
not DATASEC offsets, are authoritative map bases because real loader fixtures
can carry zero or otherwise non-distinct DATASEC offsets.

Kernel maps are created in dependency order. `BPF_MAP_CREATE` receives the
template's fd in `inner_map_fd`; after all maps exist, outer slots are updated
with concrete inner-map fds. Replay format v1 carries the template and sparse
links in optional section `0x0b`, preserving compatibility with older files.

## Evidence

- verifier/runtime tests cover typed nested lookup and missing-null-check
  rejection;
- interpreter and JIT return the same nested inner value;
- replay round-trips the template, sparse links, and result;
- the combined clang fixture covers coexisting program-array and map-in-map
  relocations;
- privileged differentials cover nested lookup and the combined static ELF
  object against the real kernel;
- the unchanged pinned Cilium fixture loads, verifies, and runs through both
  interpreter and JIT, returning 42.
