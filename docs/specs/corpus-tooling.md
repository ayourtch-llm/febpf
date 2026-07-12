# Corpus tooling — real-world coverage measurement

STATUS: complete. Both scripts are checked in and were exercised end-to-end on
this host (clang 21, bpftool, live vmlinux BTF, network): a real fetch built 56
objects from libbpf-bootstrap + bcc and the scanner produced the histogram
below. The coordinator can re-run `fetch` + `scan` to refresh the numbers on
their kernel. See "Sample run" at the end.

The Cilium v0.21.0 loader fixture added on 2026-07-12 contains sparse static
program-array and array-of-maps initializers. After implementing both, a
focused scan of the unchanged object reports 100% load/verify success and one
static tail-call graph. This is the intended workflow: each newly exposed
blocker becomes the next implementation item, then the same upstream object
proves that the blocker is gone.

The xdp-tools v1.6.3 lane added on 2026-07-12 is intentionally shallow:
`xdp-bench/*.bpf.c` only. It contributes five production networking objects
covering direct XDP packet parsing and writes, the XDP load/store-bytes helpers,
DEVMAP/DEVMAP_HASH/CPUMAP redirect paths, and multi-program XDP sections. Its
source headers are included from the pinned checkout's `headers/` directory;
the fetch script also supplies the host multiarch include directory required by
the distro's `asm/types.h` include and advertises the pinned libbpf helper API.

The Inspektor Gadget lane pins v0.54.0 at the immutable commit
`0c733324b97dbbbe8d85b64ae93622a86fe7bf45`. Its explicit
`gadgets/*/program.bpf.c` selection contains exactly 39 top-level production
gadgets; nested `gadgets/ci/` fixtures and `testdata/` are excluded. All 39
sources compile directly with clang and the checkout's
`include/gadget/amd64` and `include` trees, without Go, Docker, `ig`, or the
upstream builder image. Their object names use the gadget directory
(`inspektor-gadget__trace_exec.o`, for example), since every source basename
is `program.bpf.c`.

The repository is Apache-2.0 overall, while the selected BPF sources retain
their more specific SPDX declarations: 24 GPL-2.0, 10
`(LGPL-2.1 OR BSD-2-Clause)`, three GPL-2.0 with the Linux syscall note, one
BSD-2-Clause, and one Apache-2.0. Corpus downloads and compiled objects remain
git-ignored; users redistributing them must preserve and evaluate the upstream
license terms rather than treating febpf's repository license as a substitute.

The first combined scan exposed two loader/enumerator defects that were fixed
before recording the baseline below:

1. `R_BPF_64_32` calls against a `.text` section symbol can lose their
   relocation addend. BCC `biolatency`'s `raw_tp/block_rq_complete` has an
   addend/encoded call target of `0x147`; mislinking it to the first subprogram
   can reject that entry and can also let a sibling entry verify the wrong
   body.
2. Multiple global `STT_FUNC` entry symbols sharing one executable section are
   currently collapsed into one loader entry. The xdp-tools `xdp_basic`
   object, for example, has several functions in `SEC("xdp")`, so the program
   count is a known undercount.

The Gadget lane also carries six objects whose shared `ig_build_id` map
explicitly declares `max_entries=0` and is resized by the Gadget userspace
loader. The scanner models that application configuration explicitly: only
`audit_seccomp`, `profile_cpu`, `profile_cuda`, `trace_capabilities`,
`trace_malloc`, and `trace_open` receive
`--map-max-entries ig_build_id=1024`. No other Inspektor Gadget object and no
other corpus lane receives a silent default. An omitted `max_entries` member
continues to use febpf's documented tolerant loader default; an explicit zero
without a named override remains a crisp load failure.

After those fixes, the authoritative combined scan observed 114 object
families and 785 entry programs. 113 families enumerate, 71 are fully
compatible, and 486/785 entries verify (61.9%); 42 entries fail during loading
and 257 reach the verifier but reject. Helper #125 `ktime_get_boot_ns` is the
largest blocker by both families and entries (14 first-blocked families / 210
entries), though one 147-hook LSM family amplifies the entry count. The next
groups are other verifier/context failures (11 families / 19 entries), other
load failures (six / 42), helper #51 `redirect_map` (three / 13), helper #26
`skb_load_bytes` (three / three), helper #189 `xdp_load_bytes` (four entries),
helpers #39 `skb_pull_data` and #177 `trace_vprintk` (two entries each), and one
`HASH_OF_MAPS` load blocker. Family count, entry count, and graph shape remain
separate signals; no single large generated hook family is treated as hundreds
of independent production workloads.

Program-kind records are derived from each executable ELF section and retained
independently of the exposed FUNC-symbol name. Multiple named functions sharing
one `xdp` section all report `xdp`, while Gadget's
`classifier/ingress/main` and `classifier/egress/main` entries report `tc`
instead of the old catch-all `other`. The scanner consumes these stable records
without guessing a program family from its display name.

The old `libbpf-bootstrap v1.4` clone ref did not exist upstream and therefore
never populated a fresh cache. This revision pins the repository directly at
`fac4e8ddf011aead8e14962bf8db74542331264b`; 13 of its current example objects
compile on this host (two target-specific examples do not). This accounts for
the increase from 62 previously cached families to 114 combined families once
the 39 Gadget objects are added.

A previous full cached scan built/scanned 57 objects: all 57 loaded and all 57
verified (100%), with no unsupported map types/helpers, load failures, or
verifier rejections. The final rejection, BCC `ksnoop`, was resolved with
scalar copy/expression identity propagation while retaining the helper
memory-bounds check. The host kernel rejects a minimal version of the same
safe relation, so this 100% figure measures febpf coverage rather than kernel
verdict parity.

The earlier default-entry-only scan after adding `xdp-tools` and implementing
its measured redirect-map blockers built/scanned 62 objects: each object's
first selected entry loaded and verified. That historical 62/62 result is not
an all-entry claim; the enumeration audit above supersedes that measurement
method.

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

- `git`, `clang` (tested with clang 21), `sha256sum`, `bpftool`, and a readable
  `/sys/kernel/btf/vmlinux` for `scan-corpus.sh`'s `--target-btf`.
- Network access for `fetch-corpus.sh` (unless `--offline`).
- Shell scripts are exempt from febpf's zero-dependency rule; they may use
  git/clang/bpftool/curl freely.

## Gentle-fetch policy (hard requirement)

`fetch-corpus.sh` is deliberately polite so it can be re-run without hammering
anyone:

- **Shallow and pinned.** Tags are cloned with
  `git clone --depth 1 --single-branch --branch <tag>`. Exact commit pins use a
  one-commit `git fetch --depth 1` followed by a detached checkout. Every
  resolved `HEAD` must equal the separately recorded immutable commit.
  Pinning makes the corpus reproducible; shallow keeps it small.
- **One repo at a time,** with a configurable `SLEEP` (default 2s) between
  network operations. Never parallel, never a firehose.
- **Cache + skip.** Everything lands in `corpus/cache/<repo>`. If a repo is
  already present it is *not* re-downloaded. Before reuse, its exact `HEAD` is
  compared with the immutable expected commit recorded beside the clone ref.
  A non-git cache or mismatch is a hard error with the expected/found commits
  and a request to remove that one cache directory; the script never silently
  scans a moving or locally switched checkout.
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
    xdp-tools/           xdp-bench/*.bpf.c (XDP networking lane)
    inspektor-gadget/    gadgets/*/program.bpf.c (39 production gadgets)
  include/
    vmlinux.h            generated locally: bpftool btf dump file
                         /sys/kernel/btf/vmlinux format c
    (libbpf headers copied here: bpf_helpers.h, bpf_core_read.h,
     bpf_tracing.h, bpf_endian.h, and the rest of libbpf/src/*.h)
  obj/
    <repo>__<name>.o     one compiled object per discovered *.bpf.c
  build.log              per-file clang stdout/stderr; compile failures logged
                         here and skipped, never aborting the whole run
  inspektor-gadget-manifest.sha256
                         pin/toolchain plus stable source and object SHA-256s
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

The Inspektor Gadget lane is stricter: the pinned glob must resolve to exactly
39 sources. Before rebuilding, only `inspektor-gadget__*.o` is removed, so a
stale object cannot survive a renamed/deleted gadget and no other lane is
touched. The timestamp-free manifest records the exact commit, first clang
version line, 39 source hashes, and 39 object hashes. On this host two complete
offline rebuilds produced the identical manifest SHA-256
`cc4b5fdff7392995183181692f328dbb063356d8004bd88b5fdb96b9847bb62d`.

### Extending the repo list

Add a line to the `REPOS` array at the top of `scripts/fetch-corpus.sh`:

```
# name|relative-github-path|clone-ref|expected-commit|glob-of-bpf-sources
REPOS="
libbpf-bootstrap|libbpf/libbpf-bootstrap|<ref>|<40-hex-commit>|examples/c/*.bpf.c
bcc|iovisor/bcc|<tag>|<40-hex-commit>|libbpf-tools/*.bpf.c
cilium-ebpf|cilium/ebpf|<tag>|<40-hex-commit>|testdata/btf_map_init.c
xdp-tools|xdp-project/xdp-tools|v1.6.3|8fbad9f0af621a22aa87ff2520b3735915b1f0fd|xdp-bench/*.bpf.c
inspektor-gadget|inspektor-gadget/inspektor-gadget|v0.54.0|0c733324b97dbbbe8d85b64ae93622a86fe7bf45|gadgets/*/program.bpf.c
"
```

Keep the set small, self-contained (tracing/networking programs that don't
need a repo-specific build system), and always pinned.

## Categorization taxonomy (`scan-corpus.sh`)

### Program enumeration and aggregation contract

Corpus measurement is per ELF entry program, not merely per object. Before
verification the scanner runs:

```
febpf programs <object> [--target-btf <path>]
```

`programs` is a stable, machine-readable interface. It writes one
tab-delimited record per line, in executable-section order. A section with a
single entry keeps its section name; a section containing multiple global
entry `STT_FUNC` symbols contributes one record per function, ordered by byte
offset and then symbol-table order and named by the function symbol:

```
program<TAB><zero-based-index><TAB><kind><TAB><section-name>
link<TAB><map-name><TAB><map-slot><TAB><target-section-name>
```

`kind` is `xdp`, `socket`, or `other`. Names are copied verbatim from the
loaded object; `/` and `:` are ordinary name bytes and are never separators.
The loader already requires UTF-8 names. Tabs and newlines are rejected for
this line-oriented interface rather than escaped ambiguously. Diagnostics and
non-fatal loader warnings go to stderr, so successful stdout contains records
only. A load failure is a non-zero exit and produces no partial records.

The scanner invokes `verify --prog <exact-name>` once for every `program`
record, using a tab-aware `read` loop rather than shell word splitting. A
socket entry rejected specifically because legacy packet loads are disabled is
retried with the Linux legacy profile and an empty, armed packet input. The
retry predicate is the verifier's complete structured diagnostic —
`verification FAILED: at insn N: legacy packet profile disabled for opcode
0xNN` — rather than a broad `legacy packet` substring that could hide a real
fault. No other entry or rejection is retried with a compatibility profile.
For the pinned Gadget `trace_dns::socket1` entry this retry advances to its
actual first blocker, helper #26 (`skb_load_bytes`).

Reports retain two levels of aggregation:

- an **entry program** is the verification unit and contributes one outcome;
- an **object/family** is fully compatible only when enumeration succeeds and
  every entry program, including the targets needed by its static links,
  verifies.

`link` records are graph edges, not additional entry programs. The report
counts objects containing static graphs and link edges separately. A broken or
unverifiable link makes the containing object incompatible, but never inflates
the entry-program denominator. This prevents a large multi-hook object from
being flattened into a misleading object success and prevents graph edges
from being advertised as independent workloads.

For each entry returned from a successfully enumerated
`corpus/obj/*.o`, the scanner runs:

```
febpf verify <obj> --prog <exact-section-name> \
    --target-btf /sys/kernel/btf/vmlinux
```

Lane-specific loader arguments are appended to both `programs` and `verify`.
At present the only such configuration is the six-object Gadget
`ig_build_id=1024` list above; keeping it as an exact basename list makes a
new explicit-zero object fail visibly until its real loader policy is audited.

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
