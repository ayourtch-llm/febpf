# Corpus tooling — real-world coverage measurement

STATUS: complete. Both scripts are checked in and were exercised end-to-end on
this host (clang 21, bpftool, live vmlinux BTF, network): a real fetch built 56
objects from libbpf-bootstrap + bcc and the scanner produced the histogram
below. The coordinator can re-run `fetch` + `scan` to refresh the numbers on
their kernel. See "Sample run" at the end.

## Why

febpf can load, verify, run and JIT hand-written and small clang-compiled
programs. The open question is **how production-ready is it against real,
in-the-wild eBPF?** This tooling answers that with a number and a ranked
worklist instead of a guess:

1. `scripts/fetch-corpus.sh` — gently assembles a reproducible corpus of real
   `*.bpf.c` programs from a small, pinned set of upstream repos and compiles
   them to `*.o` with the locally-installed clang + bpftool.
2. `scripts/scan-corpus.sh` — runs `febpf verify` over every object and
   produces a coverage report: % that load, % that verify, the number of
   static tail-call program graphs, and a **histogram
   ranked by the specific unsupported map types / helper ids that block the
   most programs**. That histogram is the whole point — it is the worklist.

The corpus itself (downloads + built objects) is **not** checked in; only the
two scripts are. `corpus/` is git-ignored.

## Prerequisites

- `git`, `clang` (tested with clang 21), `bpftool`, and a readable
  `/sys/kernel/btf/vmlinux` for `scan-corpus.sh`'s `--target-btf`.
- Network access for `fetch-corpus.sh` (unless `--offline`).
- Shell scripts are exempt from febpf's zero-dependency rule; they may use
  git/clang/bpftool/curl freely.

## Gentle-fetch policy (hard requirement)

`fetch-corpus.sh` is deliberately polite so it can be re-run without hammering
anyone:

- **Shallow, single-branch, pinned.** Every repo is cloned with
  `git clone --depth 1 --single-branch --branch <PIN>` where `<PIN>` is a
  tag or commit recorded in the `REPOS` array at the top of the script.
  Pinning makes the corpus reproducible; shallow keeps it small.
- **One repo at a time,** with a configurable `SLEEP` (default 2s) between
  network operations. Never parallel, never a firehose.
- **Cache + skip.** Everything lands in `corpus/cache/<repo>`. If a repo is
  already present it is *not* re-downloaded. Delete the cache dir to refresh.
- **Offline mode.** `--offline` builds only from whatever is already in
  `corpus/cache/` and never touches the network. If a needed repo is missing
  it is skipped with a logged warning rather than failing the run.
- **Mirror override.** `CORPUS_MIRROR=<base-url>` swaps the clone base
  (default `https://github.com`) so an internal mirror can be used.

## What the fetch produces

```
corpus/
  cache/                 shallow clones (git-ignored, reused across runs)
    libbpf/              pinned libbpf — source of the libbpf headers
    libbpf-bootstrap/    examples/c/*.bpf.c
    bcc/                 libbpf-tools/*.bpf.c
    cilium-ebpf/         testdata/btf_map_init.c (ELF loader fixture)
  include/
    vmlinux.h            generated locally: bpftool btf dump file
                         /sys/kernel/btf/vmlinux format c
    (libbpf headers copied here: bpf_helpers.h, bpf_core_read.h,
     bpf_tracing.h, bpf_endian.h, and the rest of libbpf/src/*.h)
  obj/
    <repo>__<name>.o     one compiled object per discovered *.bpf.c
  build.log              per-file clang stdout/stderr; compile failures logged
                         here and skipped, never aborting the whole run
```

Each `*.bpf.c` is compiled with:

```
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
      -I corpus/include -I corpus/cache/libbpf/src \
      -c <file> -o corpus/obj/<repo>__<name>.o
```

Compile failures are **expected** for a fraction of programs (missing arch
macros, per-repo private headers, kfunc decls, etc.). They are logged to
`corpus/build.log` and skipped. The script prints a summary: N repos
processed, M `*.bpf.c` discovered, K objects built, and where they are.

### Extending the repo list

Add a line to the `REPOS` array at the top of `scripts/fetch-corpus.sh`:

```
# name|relative-github-path|pinned-tag-or-commit|glob-of-bpf-sources
REPOS="
libbpf-bootstrap|libbpf/libbpf-bootstrap|<tag>|examples/c/*.bpf.c
bcc|iovisor/bcc|<tag>|libbpf-tools/*.bpf.c
cilium-ebpf|cilium/ebpf|<tag>|testdata/btf_map_init.c
"
```

Keep the set small, self-contained (tracing/networking programs that don't
need a repo-specific build system), and always pinned.

## Categorization taxonomy (`scan-corpus.sh`)

For each `corpus/obj/*.o`, the scanner runs:

```
febpf verify <obj> --target-btf /sys/kernel/btf/vmlinux
```

and captures **combined stdout+stderr**. Classification keys off the output
text, which febpf makes unambiguous (see below), not exit codes:

| bucket | trigger | meaning |
|--------|---------|---------|
| `OK` | stdout `verification PASSED` | loaded, relocated and verified |
| `LOAD-FAIL:unsupported-map-type:<NAME>` | stderr `error: … unsupported map type <n> (<NAME>)` | ELF loader hit a map type febpf doesn't implement |
| `LOAD-FAIL:relocation` | stderr `error: …` with `relocation`/`CO-RE`/`unknown symbol` | reloc or CO-RE resolution failed at load |
| `LOAD-FAIL:other` | any other stderr `error: …` | load failed for another reason (printed verbatim) |
| `VERIFY-REJECT:unsupported-helper:#<id>` | stdout `verification FAILED: … unknown helper #<id>` | program calls a helper febpf hasn't implemented |
| `VERIFY-REJECT:poisoned-relocation` | stdout `verification FAILED: … unresolved CO-RE relocation` | a CO-RE relo found no match in the target BTF and its (guarded) path is reachable |
| `VERIFY-REJECT:other` | any other stdout `verification FAILED:` | genuine verifier rejection (printed verbatim) |

Note on **helpers**: in febpf an unknown helper is caught by the *verifier*
(the ELF loader doesn't inspect `call` targets), so it lands under
`VERIFY-REJECT` rather than `LOAD-FAIL`. The scanner still tallies it into the
helper histogram — the bucket name is about where febpf detects it, the
histogram is about what feature is missing.

### The report

`scan-corpus.sh` writes a human-readable report to stdout and to
`corpus/coverage-report.txt`:

- totals: objects scanned, # and % that load, # and % that verify, and # and
  % containing a successfully loaded static tail-call graph;
- a bucket breakdown (count per bucket above);
- **HISTOGRAM 1 — unsupported map types**, ranked by how many programs each
  blocks, each line naming the map type (e.g. `RINGBUF`, `PERCPU_HASH`);
- **HISTOGRAM 2 — unknown helpers**, ranked by frequency; the raw kernel
  helper id is shown, and a best-effort symbolic name is looked up from a
  static kernel-helper table embedded in the script (id → name), so the
  worklist reads e.g. `helper #131 ringbuf_reserve — blocks 9 programs`.

The two histograms are the deliverable: they turn "how production-ready are
we?" into a ranked list of exactly which map types and helpers to implement
next for the most real-world coverage.

## febpf error-string requirement

For the map-type histogram to be crisp the loader must **name** the
unsupported type, not just its number. `src/elf.rs`'s `map_kind` was updated to
emit `unsupported map type 27 (RINGBUF)` (symbolic name from the kernel
`bpf_map_type` enum) instead of the previous `unsupported map type 27 (only
hash/array)`. Unknown-helper errors already name the id crisply
(`call to unknown helper #131` in `src/verifier.rs`), so no change was needed
there; the scanner maps the id to a name from its own embedded table.

## How to run

Fetch (needs network + clang + bpftool), then scan:

```
./scripts/fetch-corpus.sh                 # gentle, pinned, cached
./scripts/scan-corpus.sh                  # builds febpf --release, scans corpus/obj
cat corpus/coverage-report.txt
```

Rebuild the corpus from cache only (no network):

```
./scripts/fetch-corpus.sh --offline
```

Smoke-test the scanner without a full corpus (uses febpf's own real
clang-compiled fixtures):

```
./scripts/scan-corpus.sh tests/*.o
```

## Files

- `scripts/fetch-corpus.sh` — gentle, pinned, cached corpus builder.
- `scripts/scan-corpus.sh` — runs febpf over the corpus and emits the report.
- `docs/specs/corpus-tooling.md` — this file.
- `corpus/` — git-ignored working area (downloads + built objects + report).
</content>
</invoke>

## Sample run (this host, 2026-07-11)

`./scripts/fetch-corpus.sh` cloned libbpf @ v1.4.7, libbpf-bootstrap @ v1.4 and
bcc @ v0.31.0 (shallow, pinned) and compiled **56** `*.bpf.c` objects.
`./scripts/scan-corpus.sh` then reported:

```
objects scanned : 56
loaded (reached verifier) : 13  (23.2%)
verified OK               : 2  (3.6%)
load failures             : 43  (76.8%)
verify rejections         : 11  (19.6%)

==== HISTOGRAM 1: unsupported MAP TYPES (top load blockers) ===========
     18 programs blocked by map type  PERF_EVENT_ARRAY
     13 programs blocked by map type  CGROUP_ARRAY
      6 programs blocked by map type  STACK_TRACE
      4 programs blocked by map type  PERCPU_ARRAY
      1 programs blocked by map type  PERCPU_HASH

==== HISTOGRAM 2: unknown HELPERS (top verify blockers) ==============
      5 programs blocked by helper #14   get_current_pid_tgid
      5 programs blocked by helper #113  ringbuf_output
```

Read as a worklist: implementing **PERF_EVENT_ARRAY** and **CGROUP_ARRAY** map
types would unblock the *loading* of ~31 of these 56 real programs; the next
verify wall is the **get_current_pid_tgid** and **ringbuf_output** helpers.
(Numbers will shift with the pinned repo set and the running kernel's BTF; this
is illustrative of the signal the tooling produces, not a fixed score.)

## What the coordinator should run

```
./scripts/fetch-corpus.sh      # network + clang + bpftool; ~1 min, gentle
./scripts/scan-corpus.sh       # builds febpf --release, scans corpus/obj
cat corpus/coverage-report.txt # the ranked worklist
```

Optionally widen coverage by adding pinned repos to the `REPOS` array at the
top of `scripts/fetch-corpus.sh`, then re-running both scripts (cached repos
are not re-downloaded).
