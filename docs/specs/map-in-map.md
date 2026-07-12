# Map-in-map support

Status: implemented for `BPF_MAP_TYPE_ARRAY_OF_MAPS` and
`BPF_MAP_TYPE_HASH_OF_MAPS`, including BTF inner templates, verifier typing,
interpreter/JIT execution, replay, and kernel loading. Array static
initializers and kernel differential validation are also covered.

## Coverage motivation

Cilium/ebpf v0.21.0's `testdata/btf_map_init.c` is a real ELF-loader fixture
containing both a sparse static `PROG_ARRAY` and a sparse static
`ARRAY_OF_MAPS`. Tail-call support made the former loadable; map type 12 was
then the next measured blocker preventing the complete upstream object from
loading. The pinned corpus compiles and scans that object unchanged.

Inspektor Gadget's `traceloop` uses a `HASH_OF_MAPS`, keyed by mount namespace
ID, whose BTF `values` member points to an anonymous `PERF_EVENT_ARRAY`
template. Supporting that actual type and anonymous template closes its ELF
load failure without coercing hash semantics into an array model.

## Model

An outer map definition records:

- the map index used as its inner-map template;
- for array outers, sparse `(outer slot, concrete inner map index)`
  initializers.

The template and every concrete inner map must agree on kind, key size, value
size, and maximum entries. Array outer keys and kernel ABI values are u32;
hash outers preserve their declared key width. Runtime entries hold stable map
identities rather than host pointers or file descriptors. Userspace can
populate either outer kind through `Vm::update_inner_map`; that API validates
the concrete inner map against the verifier's template and implements
`Any`/`NoExist`/`Exist` modes. `Vm::delete_inner_map` removes hash entries.

`map_lookup_elem(outer, key)` returns either NULL or a map-object pointer typed
as the template map. The verifier requires a null check before that pointer can
be passed as the map argument to another helper. It is never a dereferenceable
map-value pointer. BPF-side update/delete of an outer map is rejected; outer
map population is a loader/userspace operation.

## ELF and kernel loading

The BTF parser recognizes map types 12 and 13 and obtains their template from
the `values` flexible-array element type. If that type is not a declared map,
the loader materializes a private `<outer>.inner` template definition. Nested
map-in-map templates remain rejected. `R_BPF_64_ABS64` relocations within an
array outer's exact `values[]` byte range populate sparse slots. ELF symbol
values, not DATASEC offsets, are authoritative map bases because real loader
fixtures can carry zero or otherwise non-distinct DATASEC offsets.
Hash static initializers use their u32 slot indices as keys and are accepted
only when the declared key size is four bytes.

Kernel maps are created in dependency order. `BPF_MAP_CREATE` receives the
template's fd in `inner_map_fd`; after all maps exist, outer slots are updated
with concrete inner-map fds. Kernel loading applies the VM's tolerant dynamic
map defaults before `BPF_MAP_CREATE`, so anonymous templates with an omitted
capacity do not become invalid zero-sized kernel maps. Replay format v1 carries
the template and sparse links in optional section `0x0b`, preserving
compatibility with older files. Runtime userspace mutations are execution
state and are not added to a replay unless represented by static links.

## Evidence

- verifier/runtime tests cover typed nested lookup and missing-null-check
  rejection;
- interpreter and JIT return the same nested inner value;
- replay round-trips the template, sparse links, and result;
- a clang `HASH_OF_MAPS` fixture covers an eight-byte key and anonymous
  `PERF_EVENT_ARRAY` template, while a runtime test covers keyed nested lookup;
- the combined clang fixture covers coexisting program-array and map-in-map
  relocations;
- privileged differentials cover nested lookup and the combined static ELF
  object against the real kernel;
- the unchanged pinned Cilium fixture loads, verifies, and runs through both
  interpreter and JIT, returning 42.
