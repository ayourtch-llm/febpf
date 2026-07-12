# Shareable replay files (`.febpf`)

STATUS: complete (2026-07-11)

A **replay file** is a small, self-contained, versioned binary blob that captures
everything needed to *deterministically* reproduce one run of an eBPF program and
re-open it in the time-travel debugger at a point of interest. It is the "attach a
repro to the bug report" primitive: one file, no external `.o`, no BTF, no notes.

## Why this is possible (and small)

febpf execution is **fully deterministic** (HANDOFF §7): `get_prandom_u32` is a
fixed-seed xorshift and map storage is stable, so a run is a pure function of

```
run  =  f(program, ctx, prandom_seed, map_preload)
```

A replay file therefore does **not** store a state trace — only those inputs, plus
an optional cursor ("stop at instruction count N") and a determinism guard (the
febpf version + the r0 the recorder observed). Replay rebuilds a fresh `Vm`, feeds
it the same inputs, and re-executes; the debugger's time travel then comes for free
because it is itself replay-based (`src/debug.rs`, `src/playground.rs`).

## Container layout

All integers are **little-endian**. `bytes(x)` denotes a `u32` length prefix
followed by that many raw bytes. `str(x)` is `bytes(x)` holding UTF-8.

```
offset  size  field
------  ----  -----------------------------------------------------------
0       8     magic          = b"FEBPFRPL"
8       2     format_version = 1  (u16)
10      ...   one or more sections, packed to EOF
```

Each **section** is length-prefixed and self-describing, so unknown sections are
skipped forward-compatibly:

```
size  field
----  ----------------------------------------------------------------
1     tag            (u8, see table)
4     payload_len    (u32)
N     payload        (payload_len bytes; parsed per-tag below)
```

### Section tags

| tag  | name    | required | payload |
|------|---------|----------|---------|
| 0x01 | META    | yes      | `str(febpf_version)` — the recorder's `CARGO_PKG_VERSION` |
| 0x02 | INSNS   | yes      | `u32 count`, then `count*8` bytes of encoded instruction slots (same wire format as raw bytecode / `insn::encode_program`; map-`lddw` pseudo `src` values are preserved) |
| 0x03 | MAPS    | yes      | `u32 nmaps`, then per map: `str(name)`, `u8 kind` (0=array, 1=hash, 2=percpu-array, 3=percpu-hash, 4=LRU-hash, 5=ringbuf, 6=perf-event-array, 7=cgroup-array, 8=stack-trace, 9=prog-array, 10=array-of-maps), `u32 key_size`, `u32 value_size`, `u32 max_entries`, `u8 readonly`, `bytes(init)` |
| 0x04 | CTX     | yes      | raw context bytes (length = `payload_len`) |
| 0x05 | SEED    | yes      | `u64` prandom seed |
| 0x06 | CURSOR  | no       | `u64` stop-at instruction count (absent ⇒ no cursor) |
| 0x07 | PRELOAD | no       | `u32 nentries`, then per entry: `u32 map_index`, `bytes(key)`, `bytes(value)` (user-supplied map contents applied *after* map init, *before* the run) |
| 0x08 | OUTCOME | no       | determinism guard: `u8 kind` (0=exit,1=error); if 0 then `u64 r0`, if 1 then `str(message)` |
| 0x09 | PACKET  | no       | original XDP packet bytes; presence selects XDP verification/execution and makes CTX the synthetic 24-byte `xdp_md` image |
| 0x0a | TAIL_CALLS | no    | `u32 count`, then per static link: `str(map_name)`, `u32 slot`, `u32 insn_count`, encoded target instructions |
| 0x0b | MAP_IN_MAP | no    | `u32 outer_count`, then per outer map: `u32 outer_index`, `u32 template_index`, `u32 value_count`, followed by `(u32 slot, u32 inner_index)` pairs |
| 0x0c | LEGACY_PACKET | no | one `u8 profile` (`1` = Linux, `2` = Rbpf041); selects deprecated packet-load verification and execution semantics, and never contains a guest or host address |

Round-trip is exact: `from_bytes(to_bytes(r)) == r` for every field.

### Rejection / robustness contract

`Replay::from_bytes` never panics. It returns `Err(String)` on:
- too-short input or bad magic (`not a febpf replay file`),
- a `format_version` it does not understand (`unsupported replay format version N`),
- a section whose `payload_len` runs past EOF, or a truncated field inside a payload,
- a missing required section (INSNS/MAPS/CTX/SEED).

Unknown section tags are skipped (forward compatibility). A `.o`/random file is
rejected cleanly by the magic check. Element counts (maps, preload entries) are
**never** used to pre-allocate — vectors grow as each bounds-checked element is
read — so a corrupted count fails fast instead of attempting a huge allocation.

An absent LEGACY_PACKET section preserves the pre-extension v1 behavior and
serialization exactly. Unknown profile values and trailing bytes in its payload
are corrupt-file errors. With PACKET, legacy reads use the recorded XDP packet;
without PACKET, CTX is both context and raw packet. Configurable-metadata legacy
replays are rejected until owned external regions and their selected bases have
an address-free replay representation.

## Determinism contract

On `replay`, febpf rebuilds the `Vm`, applies SEED and PRELOAD, and re-executes.
If the file carries an OUTCOME section and the reproduced result differs from the
recorded one, febpf prints a **loud warning** to stderr:

```
WARNING: determinism mismatch — recorded r0 = <X>, reproduced r0 = <Y>
         this replay file was produced by a different/perturbed febpf; the run
         is no longer reproducible (this is a determinism regression worth
         investigating).
```

A version skew (META vs the running `CARGO_PKG_VERSION`) is noted but not fatal;
the r0 comparison is the real signal.

## CLI

```
febpf record <prog> [--ctx <hex|@file>] [--ctx-size N] [--stop-at N] -o bug.febpf
febpf record <xdp-prog> --packet frame.bin [--stop-at N] -o packet.febpf
febpf record <xdp-prog> --pcap capture.pcap --packet-index N -o packet.febpf
febpf replay <bug.febpf> [--run]
```

- `record` loads `<prog>` (`.s`/`.asm`/`.bpf` source, a `clang -target bpf` ELF
  object, or raw bytecode — same loader as every other command), builds the ctx,
  runs it once to capture the determinism-guard OUTCOME, and writes the replay
  file. `--stop-at N` stores a CURSOR at instruction count N.
- For XDP, `--packet` stores one raw frame. `--pcap` plus the 1-based
  `--packet-index` extracts one capture record. The PACKET section preserves
  the original bytes, and replay rebuilds the packet virtual region before
  opening the debugger, so data/data_end pointers and packet mutations remain
  time-travel reproducible.
- `replay bug.febpf` loads the file and drops into the **time-travel debugger**,
  positioned at the CURSOR if one is present (otherwise at count 0).
- `replay bug.febpf --run` instead runs to completion and prints r0, applying the
  determinism guard.

## Playground / WASM entry (bonus)

`playground::replay_session(bytes) -> Result<Session, String>` loads a replay
file's bytes and returns a debugger `Session` positioned at the cursor, so the
same `bug.febpf` opens in the browser build. The WASM ABI stub and a note in
`web/` document how the host would hand the file's bytes across the boundary.

## Module layout

- `src/replay.rs` — the container: `Replay` struct, hand-written `to_bytes` /
  `from_bytes`, `record(...)` (build + run + capture), `apply_preload(...)`,
  and `into_program()`. Zero dependencies, no serde.
- `src/interp.rs` — `DEFAULT_PRANDOM_SEED` constant + `set_prandom_seed` /
  `prandom_seed` so the seed is recordable and settable.
- `src/main.rs` — `record` / `replay` subcommands.
- `src/debug.rs` — `DebuggerOpts::start_at` so `replay` can drop in at the cursor.
- `src/playground.rs` — `replay_session`.

## Staged plan

1. Spec (this file) + `interp` seed accessors. **done**
2. `src/replay.rs`: format + `to_bytes`/`from_bytes` round-trip + `record`. Unit
   tests for round-trip, corruption/short-file rejection, version mismatch. **done**
3. CLI `record`/`replay` wired into `main.rs`; `DebuggerOpts::start_at`. **done**
4. Playground `replay_session` + WASM/web `dbgReplay` stub. **done**
5. Integration test (`tests/replay.rs`): record→file→replay reproduces identical
   r0 + final register/map state vs a direct run; preload reproduction; corrupt/
   short/flipped-byte fuzz rejects with no panic. Spec STATUS: complete. **done**
```
