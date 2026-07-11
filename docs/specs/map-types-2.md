# Map types, round 2 — corpus-driven next batch

This continues `docs/specs/map-types.md`. That round added ringbuf, per-CPU and
LRU maps. A real-world corpus scan (`scripts/scan-corpus.sh`, 56 bcc /
libbpf-bootstrap programs) then ranked the remaining blockers; this round
implements the top ones. As before it records the **userland modelling choices**
(which necessarily differ from a real kernel) so a future reader — or the
coordinator re-running the corpus scan — knows exactly what is and isn't
faithful.

The corpus histogram that drove this work:

```
==== HISTOGRAM 1: unsupported MAP TYPES (top load blockers) ====
     18 programs blocked by map type  PERF_EVENT_ARRAY   <- Stage 1
     13 programs blocked by map type  CGROUP_ARRAY        <- Stage 2
      6 programs blocked by map type  STACK_TRACE         <- Stage 3
==== HISTOGRAM 2: unknown HELPERS (top verify blockers) ====
      5 programs blocked by helper #14   get_current_pid_tgid  <- Stage 4
```

The overriding goal is **LOAD-time support**: making these map types load (and
their signature helpers verify) is what moves the coverage numbers, because a
program that can't load never reaches the verifier. The ELF loader is kept
tolerant (missing/zero `key_size`/`value_size`/`max_entries` are defaulted
rather than rejected — libbpf fills these from `nr_cpus` at load, so real
objects frequently omit them).

Touched modules mirror round 1: `maps.rs` (map kinds + storage + capture),
`helpers.rs` (ids/names/signatures), `interp.rs` (helper dispatch + capture),
`verifier.rs` (helper arg typing + map-kind enforcement), `elf.rs`
(type integers → `MapKind`), `asm.rs` (`.map` keywords).

## Determinism (HANDOFF §7)

Everything added here is a pure function of (program, ctx, prandom seed, map
preload):
- `perf_event_output` captures records into the map exactly like ringbuf
  submit; which CPU lane is selected is a pure function of the `flags` arg.
- `get_stackid` returns a deterministic id: the FNV-1a hash of the current call
  stack's instruction indices (`Machine::backtrace_pcs`), masked to 31 bits. The
  captured stack (the frame pcs as u64s) is stored in the map under that id, so
  the same call site always yields the same id and the same stored stack.
- `get_current_pid_tgid` / `_uid_gid` / `_comm` / `_task` return fixed,
  documented constants (febpf has no processes).

---

## STAGE 1 — PERF_EVENT_ARRAY (`BPF_MAP_TYPE_PERF_EVENT_ARRAY`, type 4)

The classic pre-ringbuf way to stream events to userspace, and the single top
load blocker (18 programs).

**Definition shape.** A per-CPU array of "perf event" output slots. `key_size`
and `value_size` are 4 (a CPU index → a perf-event fd, in the kernel);
`max_entries` is the number of CPUs. libbpf fills all of these at load, so the
ELF often omits them — we default `key_size`/`value_size` to 4 and
`max_entries` to `NR_CPUS` when zero.

**Storage / capture model.** `Storage::PerfEvent { emitted: Vec<Vec<u8>> }`. It
does not use the flat array storage: the "values" are conceptual perf buffers,
not readable map values. Submitted records are captured on the **Map** (like
ringbuf's `emitted`), so `MapSnapshot` time-travel just works and they are
inspectable via `Map::perf_records()` / `Vm::perf_records(name)`. All CPUs'
records land in one capture list (febpf has one logical execution CPU, so
central capture is faithful to what a single-CPU run can observe); the selected
CPU index is validated but not partitioned in storage.

**Helper — `bpf_perf_event_output` (id 25).** `(ctx, map, flags, data, size)`.
Copies `size` bytes from the `data` pointer and appends them to the map's
capture list. The low 32 bits of `flags` select a CPU index;
`BPF_F_CURRENT_CPU` (`0xffffffff`) means the current CPU, which is CPU 0 in our
model (matching `get_smp_processor_id` → 0). A selected index ≥ `NR_CPUS` is
rejected with `-EINVAL`, like the kernel.

**Verifier.** `data` is a readable memory region of `size` bytes (stack or map
value — the existing `MemRead { size_arg }` typing). The `map` arg must be a
`PERF_EVENT_ARRAY` (enforced by a new per-helper map-kind check); `ctx` and
`flags` are accepted loosely (`Any`/`Scalar`) to keep corpus objects loading.

---

## STAGE 2 — CGROUP_ARRAY (`BPF_MAP_TYPE_CGROUP_ARRAY`, type 8)

13 programs. A simple array holding cgroup fd/id values (`value_size` 4). It is
almost always a *lookup* map consulted by helpers like
`bpf_current_task_under_cgroup` / `bpf_skb_under_cgroup`; we do **not** need
those helpers' full cgroup semantics to unblock loading — the corpus blocker is
the map type at load time.

**Model.** A plain array (`is_arraylike`), backed by `Storage::Array`, keyed by
a u32 index with `value_size` 4 (defaulted if the ELF omits it). Lookups /
updates behave exactly like an `ARRAY`. Any cgroup-membership *helper* is out of
scope here and — being unimplemented — will simply surface as a **helper**
blocker in the next corpus scan (that is the intended next signal, not a
regression). Documented determinism: because febpf has no cgroup hierarchy, if a
membership helper is later added it should return a fixed deterministic answer.

---

## STAGE 3 — STACK_TRACE (`BPF_MAP_TYPE_STACK_TRACE`, type 7) + `bpf_get_stackid`

6 programs. A map from a u32 stack-id to a captured stack (an array of u64
addresses). `key_size` is 4; `value_size` is `depth * 8` (defaulted to
`PERF_MAX_STACK_DEPTH(127) * 8` if the ELF omits it); `max_entries` is the
number of distinct stacks retained.

**Model.** Backed by the existing hash (slab) storage (`is_hashlike`): a u32
stack-id key → the captured stack bytes. This reuses stable value storage and
snapshotting for free.

**Helper — `bpf_get_stackid` (id 27).** `(ctx, map, flags)` → a stack id
(non-negative), or negative on error. febpf has call frames but not real kernel
stacks, so the model is: the id is the FNV-1a hash of the current call stack's
instruction indices (`Machine::backtrace_pcs`, innermost first), masked to 31
bits; the captured "stack" stored under that id is those pcs as little-endian
u64s (truncated/zero-padded to `value_size`). Deterministic: the same call site
always produces the same id and stored stack. Insertion into a full map is
ignored (the id is still returned) — the kernel likewise returns the id and may
drop the store.

---

## STAGE 4 — core tracing helpers (deterministic constants)

Now that more programs load, these are the next verify blockers. All return
fixed, documented values (febpf has no processes/tasks):

| id | name | model |
|----|------|-------|
| 14 | `get_current_pid_tgid` | returns `(tgid << 32) \| pid` with `tgid = pid = 1` → `0x0000_0001_0000_0001` |
| 15 | `get_current_uid_gid`  | returns `(gid << 32) \| uid` with `uid = gid = 0` (root) → `0` |
| 16 | `get_current_comm`     | writes the fixed comm `"febpf"` (NUL-padded) into the caller's buffer; verifier: buffer is a **writable** mem region of the given size (`MemWrite { size_arg: 1 }`); returns 0 |
| 35 | `get_current_task`     | returns a deterministic nonzero token `0xffff_0000_0000_0001` (an opaque task pointer; not dereferenceable in our memory model) |

---

## Assembler `.map` keywords

`asm.rs` `.map name kind key val entries [ro]` gains kinds `perf_event_array`,
`cgroup_array`, `stack_trace` (in addition to the round-1 set). Perf event
arrays are written e.g. `.map ev perf_event_array 4 4 4`.

## ELF loader

`map_kind()` maps type integers 4/8/7 to the new `MapKind`s. Tolerant loading
(see intro): the BTF `.maps` parser already defaults missing key/value for
`no_kv` types; `Map::new` additionally defaults missing/zero
`key_size`/`value_size`/`max_entries` for these three kinds so objects that rely
on libbpf to fill them still load. Unknown/unsupported map types still error
*per map*, not for the whole object.

## STATUS

- Spec + plan: **done**.
- Stage 1 (PERF_EVENT_ARRAY + helper 25): _pending_.
- Stage 2 (CGROUP_ARRAY): _pending_.
- Stage 3 (STACK_TRACE + helper 27): _pending_.
- Stage 4 (helpers 14/15/16/35): _pending_.
</content>
</invoke>
