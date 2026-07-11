# Map types — semantics, userland model, and staged plan

febpf started with only two BPF map types: `HASH` and `ARRAY` (`src/maps.rs`,
`MapKind`). This spec covers the expansion toward real-world eBPF coverage:
**ringbuf**, **per-CPU array/hash**, and **LRU hash**. It records the userland
modelling choices (which necessarily differ from a real kernel) so a future
reader — or the coordinator running a `.bpf.o` corpus through febpf — knows
exactly what is and isn't faithful.

The touched modules are: `maps.rs` (the map objects + storage), `helpers.rs`
(new helper ids/signatures + arg/return kinds), `interp.rs` (helper dispatch +
the virtual-address region model), `verifier.rs` (helper typing + the
reserved-pointer type and its null-check/consume refinement), `elf.rs` (map
type integers → `MapKind`), and the assembler `.map` keywords in `asm.rs`.

## Background: the two things every map type must plug into

1. **Stable value storage** (HANDOFF §5). A pointer handed to the program must
   stay valid: array maps use one flat allocation, hash maps a slab with a
   free-list; values are never moved while present. Every new type preserves
   this.
2. **The virtual-address memory model** (HANDOFF §1). Guest pointers are
   `region_handle << 32 | offset`; `resolve_slice()` bounds-checks every
   access. A map value becomes a `Region::MapValue{map,vref}` minted lazily on
   first use. New pointer-producing helpers (ringbuf reserve) mint new region
   kinds the same way.

## Determinism (HANDOFF §7)

Everything here is deterministic: a run is a pure function of (program, ctx,
prandom seed, map preload). Concretely:
- ringbuf reservation succeeds/fails purely on the requested size vs capacity;
- per-CPU "current CPU" is fixed (see below), so which slot is touched is
  deterministic;
- LRU eviction order is driven by a monotonic per-map access tick, so the
  victim is a pure function of the access history — replay reproduces it.

---

## STAGE 1 — RINGBUF (`BPF_MAP_TYPE_RINGBUF`, type 27)

The dominant userspace-delivery mechanism in modern observability programs.

**Definition shape.** `max_entries` is a **byte capacity** (kernel requires a
power of two ≥ page size; we require only `> 0` and *document* the power-of-two
expectation — we don't reject, so odd corpus objects still load). `key_size`
and `value_size` are 0 (there is no key/value).

**Helpers.**
- `bpf_ringbuf_reserve` (id **131**): `(map, size, flags)` → a writable pointer
  to exactly `size` bytes, **or NULL**. Verifier: the result is
  `PTR_TO_MEM`-or-NULL and must be null-checked before use; the region is
  exactly `size` bytes and writable. `size` must be a known constant (kernel
  requires this too). Userland: mints a fresh reservation region (like a map
  value) of `size` zeroed bytes. Returns NULL when `size == 0` or
  `size > capacity`.
- `bpf_ringbuf_submit` (id **132**) and `bpf_ringbuf_discard` (id **133**):
  `(data, flags)` — consume the reserved pointer. Submit appends the reserved
  bytes to the ringbuf's captured record list; discard drops them. Both mark
  the reservation consumed; the verifier rejects any later use of that pointer
  (deref, arithmetic, or a second submit/discard) — this is the "reserve then
  reuse after submit is rejected" rule.
- `bpf_ringbuf_output` (id **130**): `(map, data, size, flags)` — copies `size`
  bytes from a stack/map buffer straight into the captured record list (the
  reserve-free path). Returns 0 on success.

**Userland capture model.** Submitted / output records are stored on the
ringbuf **Map** itself (`Storage::RingBuf::emitted`), so they are snapshotted by
the existing `MapSnapshot` machinery (time travel just works) and inspectable
via `Map::ringbuf_records()` / `Vm::ringbuf_output(name)`. This mirrors how
`trace_printk` captures into `Vm::printk`, but per-map instead of global.

**Reserved-region bookkeeping.** A reservation is
`Storage::RingBuf::reserved[i] = Reservation { data, handle, live }`. Reserve
mints a `Region::RingReserved{map,res}` and records its handle; `resolve_slice`
resolves it to the reservation's bytes (writable) and errors if not `live`
(i.e. already submitted/discarded — reserve-without-consume is caught by the
verifier, use-after-consume by both verifier and runtime).

**Verifier types.** `PtrKind::RingbufMemOrNull{id,size}` (from reserve, must be
null-checked), refines on a `== 0` / `!= 0` test to `RingbufMem{id,size}`
(writable, `[0,size)` bounds) or to a null scalar — reusing the exact
`MapValueOrNull` id mechanism. Submit/discard take a `RingbufMem` at offset 0
and mark every copy of that `id` `RingbufConsumed`; deref/arith/consume of a
`RingbufConsumed` (or a still-maybe-null `RingbufMemOrNull`) is rejected. A
reservation that is never consumed is *not* yet flagged at program exit (the
kernel's "unreleased reference" check) — a documented known limitation; the
runtime simply drops the un-submitted bytes.

---

## STAGE 2 — PER-CPU maps (`PERCPU_ARRAY` type 6, `PERCPU_HASH` type 5)

Pervasive in tracing/perf: each logical CPU gets its own value copy, so
increments need no atomics.

**nr_cpus choice.** We model **`NR_CPUS = 4`** logical CPUs (a small, fixed,
documented number — `maps::NR_CPUS`). `get_smp_processor_id` already returns 0,
so the **current CPU is always 0**; the in-program helpers
(`lookup`/`update`/`delete`) therefore operate on **CPU 0's copy**, matching the
kernel semantics for the per-program view. The other CPUs' slots exist in
storage (so the model is faithful and testable) but are only reachable through
the test/inspection API `Map::value_cpu()` — a real program on this VM can't
observe CPU ≠ 0 because the VM has one logical execution CPU.

**Storage layout.** Per-CPU maps store `NR_CPUS` value cells per entry. Array:
one flat allocation of `max_entries * NR_CPUS * value_size`, entry `k`'s CPU `c`
at cell `k*NR_CPUS + c`. Hash: slab entries are `NR_CPUS * value_size` wide.
`lookup`/`value`/`value_mut` return **CPU 0's** `value_size`-byte slice, so the
region bounds a program sees are exactly one value (independence preserved).
Values stay stable (HANDOFF §5).

**Verifier.** Typed exactly like their non-per-CPU counterparts (same
`key_size`/`value_size` typing); no new pointer kinds needed.

---

## STAGE 3 — LRU_HASH (`BPF_MAP_TYPE_LRU_HASH`, type 9)

Like `HASH` but **bounded**: inserting past capacity evicts the
least-recently-used live entry instead of failing with `-E2BIG`.

**LRU order (deterministic).** Each live entry carries a `last_used` value from
a per-map monotonic tick counter. The tick is bumped on every `update` of an
entry and on every successful `lookup` (the interpreter calls `Map::touch`
after a hit for LRU maps — `lookup` stays `&self`). On an insert that would
exceed `max_entries`, the victim is the live entry with the smallest
`last_used`; ticks are unique so there are no ties. The victim's slab slot is
reused for the new entry — the evicted entry is gone, so its recycled slot
matches kernel LRU+RCU semantics; **live** entries never move.

**Verifier.** Typed exactly like `HASH`.

---

## Assembler `.map` keywords

`asm.rs` `.map name kind key val entries [ro]` gains kinds: `ringbuf`,
`percpu_array`, `percpu_hash`, `lru_hash` (in addition to `array`, `hash`). For
ringbuf, key/val are written as 0 and `entries` is the byte capacity, e.g.
`.map rb ringbuf 0 0 4096`.

## ELF loader

`map_kind()` maps the type integers 5/6/9/27 to the new `MapKind`s. BTF `.maps`
parsing tolerates ringbuf's missing `key`/`value`/`key_size`/`value_size`
members (defaulting them to 0) so ringbuf objects load. Unknown/unsupported map
types still error *per map*, not for the whole object, so a corpus object that
merely *mentions* an unsupported type in one map can still be inspected.

## STATUS

- Spec + plan: **done**.
- Stage 1 (ringbuf): **done** — helpers 130-133, `Region::RingReserved`, verifier
  reserved-pointer type + null-check/consume refinement, ELF/BTF type 27,
  `.map ... ringbuf`, 5 integration tests.
- Stage 2 (per-CPU): **done** — `PerCpuArray`/`PerCpuHash` (types 6/5), NR_CPUS=4
  storage, CPU-0 in-program view, `Map::value_cpu` for inspection, ELF/BTF +
  `.map` keywords, 2 integration tests (round-trip + slot independence).
- Stage 3 (LRU hash): _pending_.
