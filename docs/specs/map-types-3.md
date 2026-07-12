# Map types, round 3 — XDP redirect maps

This round is driven by the pinned `xdp-project/xdp-tools` v1.6.3 corpus lane.
Its five `xdp-bench/*.bpf.c` objects compile successfully; the first scan
verified the two ordinary XDP objects and blocked the three redirect objects
only because their map declarations used types febpf did not yet recognize:

```
1  DEVMAP
1  CPUMAP
1  DEVMAP_HASH
```

The goal is load-time and standalone-VM support for the map family. It does
not pretend that a userland VM can attach a program to a network device, queue,
or CPU redirect path.

## Kernel type mapping

`src/elf.rs` recognizes the UAPI values `14` (`DEVMAP`), `16` (`CPUMAP`), and
`25` (`DEVMAP_HASH`) and maps them to distinct `MapKind` values. `kbpf::map_create`
uses the same values for kernel differentials. The assembler accepts
`devmap`, `cpumap`, and `devmap_hash` in `.map` declarations.

## Userland model

The VM models the ordinary keyed map operations faithfully enough for
standalone execution:

- `DEVMAP` and `CPUMAP` use bounded u32-key array storage.
- `DEVMAP_HASH` uses the existing stable hash/slab storage.
- `map_lookup_elem`, `map_update_elem`, `map_delete_elem`, snapshots, replay
  preloads, and JIT/interpreter map-value accesses therefore behave like their
  storage family.

The map kind remains distinct in `MapDef`. `redirect_map` (#51) accepts only
these three kinds and rejects ordinary arrays/hashes. It returns
`XDP_REDIRECT` when the selected entry exists and contains a nonzero target;
an absent, out-of-range, or zero entry returns the fallback action encoded in
the low two flag bits. Device/CPU transmission is not invented in the
standalone VM; it requires an XDP attachment environment.

Replay format v1 assigns map-kind codes 11–13 to these three kinds. Existing
v1 files contain only the earlier codes and remain unchanged; readers that
understand this revision can round-trip all three new kinds.

## Validation

- `src/elf.rs` unit tests cover all three UAPI type numbers.
- Integration tests exercise update/lookup round trips through the VM for both
  array-family maps and the hash-family map, plus redirect verdict/fallback and
  wrong-map rejection for helper #51.
- Replay tests verify that all three map identities survive a v1 round trip.
- The unchanged xdp-tools objects are rescanned after implementation; the
  corpus histogram, rather than a synthetic object count, is the acceptance
  criterion.
