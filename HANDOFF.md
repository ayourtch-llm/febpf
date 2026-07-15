# febpf — handoff notes

_A note from past-me to future-me (or whoever picks this up). Read this before
diving in; it's the context that isn't obvious from the code._

## CONTEXT REFRESH PROTOCOL (use this autonomously)

When the working context becomes long, stale, or difficult to navigate, do not
wait for the user to request a refresh. Perform this exact protocol yourself:

1. Finish or stop at a coherent boundary. Do not leave an edit half-applied or
   a destructive command in flight. Check `git status --short`, active test or
   build processes, and any active subagents/terminal collaborators.
2. Rewrite the newest `ACTIVE RESUME CHECKPOINT` at the top of this file. It
   must record the current commit and worktree state, what was actually
   completed, exact validation/measurement results, decisions and invariants
   that must survive the reset, unfinished investigation findings, and a
   concrete ordered resume list. Preserve older checkpoints as history unless
   they are actively misleading; clearly say which checkpoint is authoritative.
3. If work is intentionally uncommitted, list every modified file and describe
   the partial state precisely. Never call a dirty tree clean. Record whether
   any subagent or external terminal session is still active and what it owns.
4. Invoke the tttt MCP tool `tttt_clear_and_read_handoff_md` with
   `filename: "HANDOFF.md"`. Do not substitute a shell reread: this MCP tool is
   the operation that schedules `/clear` and then injects the instruction to
   reread this file and continue.
5. Return control and allow tttt's two-stage refresh to happen. After the
   injected resume prompt arrives, reread this file from the beginning, verify
   the recorded repository state against reality, and continue from only the
   newest active checkpoint. Do not redo completed work or trust superseded
   measurements from older sections.

## ACTIVE RESUME CHECKPOINT (2026-07-15 masked AVX2 packet lanes; authoritative)

febpf is committed through `414cc33` (`perf: execute forward XDP lanes with
AVX2 masks`). The existing branchless SSE2/AVX2 lowering is joined by
`X86Avx2Masked` for verified forward-only quad plans of at most 64 operations.
It accepts data/data_end, constant packet loads, branches, exit, and the
existing ALU64 subset. A fixed pending mask per PC tracks divergent lanes;
register results are blended only into active lanes. Packet bytes are
scalar-materialized only after an independent active-lane bounds check, then
loaded into AVX2 registers, so inactive truncated lanes cannot be touched.
Two- and one-packet remainders use the scalar reference executor.

Branch operands are currently extracted and compared scalarly to construct
masks. The honest claim is safe masked packet execution with AVX2 register
operations, not fully vectorized predicates. Helpers, maps, stores, stacks,
calls, loops, plans longer than 64 operations, AVX-512, and NEON retain normal
fallback. `LanePlanKey` remains feature/backend-sensitive and the graph loader
differentially validates the selected backend against scalar XDP over 79
deterministic boundary and randomized frames.

The graph consumer is committed through `c3af391` (`perf: activate masked AVX2
packet nodes`). The real Ethernet classifier now selects masked AVX2 on this
Ryzen 9 3900X; non-AVX2 hosts keep pinned scalar JIT. Isolated batch-256,
10,000-sample p50 TSC reference ticks: classifier 130.18 masked versus 159.87
scalar JIT and 206.18 scalar lanes; mixed 150.37 versus 223.55 scalar JIT;
classifier-to-PASS 163.28 versus 336.66 scalar JIT and 269.56 scalar lanes.
The final automatic 5,000-sample matrix is PASS 61.16, classifier 133.00,
classifier-to-PASS 173.52, mixed 158.38, native scheduler 52.84. These are TSC
reference ticks, not PMU core cycles. Release objdump confirms `vpblendvb`
alongside AVX2 broadcast/arithmetic instructions.

Validation passes: febpf default all-targets **491 passed + 4 ignored**,
interpreter-only std **472 + 4**, strict default/interpreter/aarch64/thumb;
graph runtime 14/14, memif 9/9, ConnectX default 4/4 and rdma 6 + one hardware
ignore, strict runtime/adapters/locked perf, pinned Rust-to-eBPF builds/target
Clippy, scripts, and exact demo. The graph host now permits thread-local
userspace PMU events at `perf_event_paranoid=2`: automatic classifier, chain,
and mixed p50s are 148.56, 196.19, and 174.39 hardware cycles versus scalar
JIT 180.87, 337.68, and 264.67. Graph commit `8356d89` adds the documented
`perf/pmu-access` helper. Provisioned mlx5 execution remains the honest
hardware gap.

The production classifier family is now profitable and saturated for this
slice. Do not keep widening SIMD opportunistically. Next design and implement
the generic graph packet-provider boundary, then an AF_XDP provider; preserve
the current scalar fallback and translation validation. Scalar-to-vector
branch predicates are a later profile-driven micro-optimization. DPDK remains
optional after AF_XDP.

The branchless x86 SIMD checkpoint below is historical and superseded.

## ACTIVE RESUME CHECKPOINT (2026-07-15 validated XDP lanes; superseded)

febpf is committed through `4cc5b6e` (`feat: lower pure XDP programs into
validated lanes`). The new std `lanes` module lowers a verified, map-free,
forward-only XDP subset into architecture-independent operations. It accepts
ALU32/64, forward branches, exact verifier-proven XDP data/data_end and packet
loads, and root exit. Helpers, maps, stores/atomics, stacks, generic loads,
calls, and backward edges reject normally to the scalar path. Quad execution
uses exact 4/2/1 groups, so double lanes and the scalar remainder are explicit.

Each lane owns registers, PC, packet, and result. Divergence is modeled with
independent PCs. `XdpLaneProgram::validate` compares lane verdicts and complete
frames against the ordinary scalar VM over a supplied corpus. This is empirical
translation validation plus a conservative static soundness argument, **not**
a formal equivalence proof. `docs/specs/xdp-lanes.md` records the boundary.

The graph consumer is committed through `6bab76f` (`perf: execute tiny graph
nodes in validated lanes`). Node loading preserves an explicit
`LaneSelection`: unsupported with reason, validated but scalar-session, or
validated scalar-interleaved. The loader corpus has 15 empty, truncated,
minimum, patterned, IPv4/non-IPv4, 64/256/1514-byte frames. Any accepted-plan
mismatch rejects loading. A static cost policy activates scalar lanes only for
at most four reachable branchless operations with no context/packet loads;
the 11-op divergent Ethernet plan is retained for future SIMD but uses its
scalar JIT, while PASS/DROP use lanes.

Final batch-256/5,000-sample forced scalar-session versus automatic p50 TSC
ticks were PASS 151.26/75.55, classifier 159.72/157.64 (same scalar path),
classifier-to-PASS 293.16/214.49, mixed 231.86/191.63, native control
51.36/49.88. Mixed improves 17.4%. The 256-PASS-node chain at 2,000 samples
fell from 36,253.04 to 16,959.28 ticks/packet, 53.2%. A forced lane Ethernet
run was worse (214.05 versus 158.98), proving why validation and selection are
separate. These are scalar host lanes, not SSE/AVX results.

Validation passes: febpf default all-targets **490 passed + 4 ignored**,
interpreter-only std **471 + 4**, strict default/interpreter/aarch64/thumb
legs; graph runtime 14/14, memif 9/9, ConnectX default 4/4 and rdma 6 + one
hardware ignore, strict runtime/adapters/perf, pinned Rust-to-eBPF builds and
target Clippy, scripts, and exact demo. PMU and mlx5 hardware remain honest
environment gaps.

Next coherent batch: add an x86 lane backend without changing lane semantics.
Start with explicit runtime CPU-feature capture and a feature-sensitive
compiled-plan/cache identity, then SSE2 double and AVX2 quad lowering for the
branchless ALU subset. Divergent Ethernet requires masked control flow and
packet-load materialization; do not enable it from feature detection alone.
Benchmark every backend against scalar-interleaved lanes and scalar JIT, and
select only measured wins. Aarch64 keeps the reference scalar lowering until a
separate NEON backend is justified.

The VPP-shaped node-frame checkpoint below is historical and superseded.

## ACTIVE RESUME CHECKPOINT (2026-07-15 VPP-shaped node frames; superseded)

febpf is committed through `b0958b9` (`perf: pin JIT images across XDP node
frames`). `Vm::xdp_jit_session` returns a public `XdpJitSession` that compiles
once, pins the entry and tail-call-bundle images, executes independent XDP
frames without per-packet JIT ownership transfer, and restores every image on
drop. The embedding test executes two different frames through one session and
then proves the ordinary JIT API still owns usable code. A pre-existing
interpreter-only unused local is now correctly JIT-gated.

The real consumer `/home/ayourtch/rust/febpf-graph` is committed through
`5c1b558` (`perf: dispatch VPP-shaped pending node frames`). Inspection of
`~/vpp/vpp/src/vlib/node.h`, `main.c`, and `punt_node.c` established the model:
node-major dispatch, worker-local node runtime, per-next-node pending work, and
bounded 256-packet frames. The graph drains contiguous per-node queues in
bounded 256-packet views while one node JIT session is pinned. It remains an
honest scalar XDP invocation per packet inside that view.

An eBPF scheduler tail-called between nodes was rejected: only `r1` survives,
the stack is reset, and node/scheduler alternation exhausts the 33-call limit
after roughly 16 nodes. The graph stress workload now constructs 256 nodes.
The stable 256-packet/5,000-sample matrix compared legacy versus pinned p50 TSC
reference ticks: PASS 158.38/150.07, classifier 169.66/160.91,
classifier-to-PASS 316.02/304.00, and mixed 264.07/242.25 (3.8-8.3% lower).
The native scheduler control was 49.88/48.69 noise. The 256-image chain was
not stable enough to claim a win: repeated unpinned p50s were 38,706-40,596
pinned and 40,150-40,423 legacy, with run order affecting the result.

Full validation passes: febpf default all-targets is **488 passed + 4
ignored**, interpreter-only std is **469 + 4**, and strict default,
interpreter-only, aarch64, and true thumb no-std Clippy/check legs pass. Graph
runtime is 12/12; memif 9/9; ConnectX default 4/4 and rdma 6 + one honest
hardware ignore. Strict host/aarch64 runtime, adapters, locked perf, all three
pinned Rust-to-eBPF builds/target Clippy, shell syntax, and exact demo pass.
Hardware PMU access and provisioned mlx5 execution remain configuration gaps.

Next execution slice belongs primarily in febpf-graph: define a vector node
ABI for at most 256 packet descriptors, then lower one verified scalar loop to
2x/4x architecture-neutral lane IR plus a scalar remainder. Today's verifier
proves safety, not semantic equivalence; widening needs translation validation
covering packet results/mutations, ordering, aliasing, and map/helper effects,
with scalar differential execution as another guard. febpf should provide only
generic multi-window/effect/JIT primitives. The x86 backend can subsequently
lower the same lane IR to SSE2/AVX2/AVX-512 according to runtime features and a
feature-sensitive JIT cache key; scalar interleaving remains the portable
lowering and unsafe/divergent operations are scalarization points.

The packet-aware checkpoint immediately below is historical and superseded.

## ACTIVE RESUME CHECKPOINT (2026-07-15 packet-aware race exploration; superseded)

The heterogeneous race explorer now swaps complete private invocation
environments rather than only context bytes. `InstanceState` retains an
`EnvironmentSnapshot`; activation/restoration therefore includes context,
packet storage and active bounds, resize capabilities, output sinks, and
redirect state while maps and the map-region table remain shared. Observable
race outcomes now include a public `InvocationState`/`PacketState` per
instance, so schedule-dependent provider output is not hidden by convergent
maps and return values.

`RaceXdpProgram`, `explore_xdp_programs`, and `replay_xdp_programs` are the
first packet-provider adapter. Every program is verified under the XDP model
before execution. Frames may have different bytes, windows, metadata, and
capabilities but require equal backing capacities so snapshots fit one live
environment topology. Flat context APIs remain source-compatible wrappers.
Program images still do not imply tail-call edges.

Three new behavioral tests prove: packet bytes can drive a shared-map lost
update while frames remain private; packet mutations alone create distinct
outcomes even when maps and return values converge; replay, incompatible
capacities, and XDP verification failures remain exact. `tests/race.rs` is now
13/13. Complete default all-target validation is **487 passed + 4 ignored**;
std interpreter-only is **469 + 4**. Strict hosted JIT/interpreter-only and
true thumb no-std Clippy pass, as does the release all-target build. Current
rustfmt still proposes pre-existing test/interpreter reflow; `src/race.rs` was
formatted source-specifically and no unrelated whole-repository rewrite was
accepted.

The sibling graph consumer adds `ConcurrentXdpExecutable`, retains each loaded
node's verified `Program`, and exposes `Node::concurrent_xdp` plus
`validate_concurrent_xdp_executables`. Its test demonstrates dynamic rejection
of schedule-dependent frame mutations after the shared-atomic static gate
passes.

The user selected a real ConnectX adapter as the next production target and
pointed to `~/vpp/vpp`. Initial audit found VPP's Apache-2.0 `plugins/rdma`
driver uses rdma-core/libibverbs for control-plane object creation and mlx5
direct-verbs ring access for the datapath: raw-packet QPs, registered packet
memory, 64-byte CQEs/WQEs, owner-bit CQ polling, big-endian doorbell records,
and optional striding RQ/compressed CQEs. This host has libibverbs/libmlx5 and
headers but no Mellanox PCI or infiniband device, so hardware execution remains
an honest provisioned-host gap. The graph project, not febpf, owns this driver.

The heterogeneous-only checkpoint below is historical and superseded.

## ACTIVE RESUME CHECKPOINT (2026-07-15 heterogeneous race exploration; superseded)

Heterogeneous deterministic race exploration is implemented and ready to
commit. `race::explore_programs` accepts an ordered set of `RaceProgram`
instances, each with its own label, program, and fixed context. All instances
retain private registers, PC, frames, stack, and context while sharing one VM's
map storage. Map definitions must be exactly identical and context lengths
must match; empty sets are rejected. `replay_programs` consumes the same
ordered set and a recorded choice vector. Existing `explore` and
`replay_schedule` remain source-compatible single-program wrappers.

The VM's private `tail_programs` container was generalized to
`program_images`: program-array edges and scheduler-selected roots are now
separate ways to select a shared-map executable image, rather than pretending
heterogeneous roots are tail calls. Alternate race roots do not create program
array entries or tail-call edges. The current API deliberately models flat
program roots and map-visible concurrency only; callers must verify every
program under their intended execution environment before relying on the
behavioral evidence. Per-instance program labels survive into reports/traces,
and heterogeneous reports point to `replay_programs` rather than emitting an
invalid single-file CLI reproduction command.

Behavioral coverage uses distinct non-atomic `+1` and `+10` workers: exhaustive
exploration finds serial 11 and a stale-write outcome of 1 or 10. Equivalent
atomic workers always commit 11. Exact replay, labels, honest rendering, empty
sets, unequal contexts, and incompatible maps are tested. `tests/race.rs` is
now 10/10. Complete default all-target validation is **484 passed + 4
ignored**; std interpreter-only is **466 + 4**. Strict Clippy passes both
hosted profiles, AF_XDP all-targets, C-API all-targets, and true thumb no-std.
Focused AF_XDP is 5 passed + 1 provisioned-host ignore; focused C API is 11
passed. Release all-target build and `git diff --check` pass. Current rustfmt
still proposes the previously documented unrelated repository reflow, so it
was not applied.

No corpus compatibility claim changed: this is a generic concurrency primitive
for the real graph consumer, not an ELF/verifier parity change. The next
production step is to integrate the heterogeneous API into
`/home/ayourtch/rust/febpf-graph` as an explicit pre-publication shared-map
validation tool, while retaining its conservative static policy as the gate.
Key partitions or critical-section reasoning still require concrete evidence;
AF_XDP follows deterministic lifecycle and concurrency semantics.

The verified-map-effects checkpoint immediately below is historical and
superseded by this one.

## ACTIVE RESUME CHECKPOINT (2026-07-14 verified map effects; superseded)

The production consumer is the separate sibling project
`/home/ayourtch/rust/febpf-graph`, committed through `c49883d` (`feat: enforce
shared-map capabilities`). The graph measurements are 49.632–50.586 us to
prepare one two-node worker and 98.822–100.42 us for two,
starting from already-read ELF bytes. This is near-linear but not yet enough to
justify a febpf code/state split solely for reload latency.

The first generic shared-state primitive is complete. `effects::summarize`
turns a successful `VerifyOk` into reachable
per-map lookup, direct read/write, atomic, delete, lock, and unlock effects.
Direct accesses retain verifier-proven inclusive byte ranges. Known map helpers
are attributed using their exact argument register. When the verifier's
cross-path join erases one exact map identity, `MapEffects::complete` is false;
consumers must reject or conservatively treat all shared maps as affected.
`docs/specs/map-effects.md` records scope and honest limitations. The sibling
now retains `MapEffects` on every loaded node and implements the first policy
for worker-local, shared-read-only, and shared-atomic bindings. It rejects
incomplete summaries, ordinary writes/deletes on shared regions, and
inconsistent capabilities. Its racy counter is rejected while the atomic
counter is accepted. Shared storage remains disabled.

The recurring tttt job remains deleted. No build,
benchmark, scanner, subagent, or external terminal collaborator is active.

This corrects the prior C-parity momentum: do not continue versioning C
constructors merely because a Rust capability exists. febpf remains the
general zero-dependency loader/verifier/VM/JIT. The sibling project owns graph
scheduling, workers, node lifecycle, hot reload, packet adapters, control-plane
policy, and their dependencies. Upstream only generic primitives proven useful
by that real consumer. C static-tail-call construction is deferred until an
actual C host measures the need.

Rust node compilation was proven rather than designed speculatively. A pinned
nightly-2026-07-13 `bpfel-unknown-none` build using `aya-ebpf` 0.2.1 and
`bpf-linker` 0.10.3 emits an ordinary relocatable eBPF ELF. The sibling
`./demo` loads it through febpf, requires warning-free loading, verifies it as
XDP, JIT-compiles it, and executes owned frames.
`bpf-script` was rejected as the primary node language because it is a small
Rust-like runtime DSL/compiler, not Rust-to-eBPF, and still documents control
flow/testing gaps. The current rustc CO-RE emission limitation does not block
packet nodes using stable packet and graph-metadata ABIs. The sibling now runs
Rust Ethernet, PASS, and DROP nodes through an immutable validated DAG plan.
Prepared generations contain worker-local mutable VMs; the demo proves a
transactional PASS-to-DROP replacement at a single-worker batch boundary and
returns the retired generation. Its separately locked Criterion harness
measures both generic scalar execution and prepared-generation publication.
Runtime and unrouted-result failures are now per-frame completion states, so
every input frame is returned in exactly one terminal or failure bucket while
independent frames continue. A deterministic worker group now validates exact
artifacts/plans, exposes partial publication explicitly, and withholds retired
generations until all workers acknowledge the new ID. Two-worker coordinated
publication measured 1.8525–1.8571 us excluding preparation.

Immediate work remains in `febpf-graph`:

1. Extend deterministic race exploration to heterogeneous programs and
   preserve replayable schedules.
2. Add key partitions or paired critical-section reasoning only with concrete
   static/dynamic evidence; ordinary shared writes remain rejected by default.
3. Connect AF_XDP after deterministic lifecycle and concurrency semantics hold.

Read the sibling project's `HANDOFF.md` before continuing this direction.

The Criterion checkpoint immediately below is historical and superseded by
this one.

## ACTIVE RESUME CHECKPOINT (2026-07-13 Criterion performance harness; superseded)

Reproducible performance infrastructure is committed as `c14aed0` (`perf: add
reproducible Criterion harness`). At checkpoint writing HEAD is `c14aed0`; only
this HANDOFF update is intentionally uncommitted. The recurring tttt job
remains deleted. No build, benchmark, scanner, subagent, or external terminal
collaborator is active.

Criterion 0.8.2 lives entirely in the separately locked, unpublished `perf/`
crate; the root febpf package retains zero dependencies and the true no-std
graph is unchanged. `./perf/run` is the supported one-command entry point and
accepts Criterion filters and saved-baseline arguments. The committed harness
uses only febpf's public API and committed fixtures. It measures warm
interpreter and precompiled-JIT execution separately from JIT compilation,
verification, and ELF/BTF/CO-RE loading. Its bench profile matches febpf's LTO
and single-codegen-unit release settings.

The complete isolated run on this AMD Ryzen 9 3900X/rustc 1.96.1 host produced
95% intervals recorded in README: interpreter **12.035–12.134 us**
(247.49–249.52 M insn/s), warm JIT **289.02–292.36 ns**
(10.272–10.390 G insn/s), JIT compile **8.134–8.328 us**, verifier
**1.459–1.463 ms**, and CO-RE load **8.408–8.453 us**. These are explicitly
host observations, not portable promises. The previous ad-hoc README speedup
claims were removed.

Validation: `./perf/run`, locked performance-crate check, strict performance
Clippy, runner syntax, root default/std all-target tests and strict Clippy, true
thumb no-std check/Clippy, and `git diff --check` pass. CI compiles the locked
harness on x86-64 and aarch64 Linux without using hosted timing as a merge
gate. All Criterion transitive packages declare permissive licenses; the root
normal dependency tree contains only febpf.

Immediate resume order remains production-driven:

1. Expose verification-time static tail-call bundle linking for the one
   measured production graph. Audit `prog_array_inits`, bundle verification,
   exact program/map selection, durable graph identity, and interpreter/JIT
   dispatch. Do not model program identity as an invocation-local callback.
2. Add Criterion cases only when a coherent implementation batch creates a
   meaningful boundary or suspected regression; do not turn the harness into
   another synthetic feature backlog.
3. Preserve honest corpus/environment gaps and the composable add-on boundary.
   AF_XDP live-veth remains provisioned-host work; zero-copy and DPDK remain
   optional later adapters.

The C attach-target checkpoint immediately below is historical and superseded
by this one.

## ACTIVE RESUME CHECKPOINT (2026-07-13 C attach targets landed; superseded)

Exact application-side BTF attach retargeting is committed as `91f7b91`
(`ffi: configure BTF attach targets from C`). At checkpoint writing HEAD is
`91f7b91`; only this HANDOFF update is intentionally uncommitted. The recurring
tttt job remains deleted. No build, scanner, subagent, or external terminal
collaborator is active.

`febpf_vm_create_elf_v3` composes V2 map-capacity overrides with an exact-stride
array of attach-target descriptors. Each descriptor selects either one exact
loaded program name or one exact ELF section and supplies a real target-BTF
function name. The shared ELF loader rejects duplicate, unmatched,
non-BTF-section, overlapping, and unsupported iterator/tp_btf selectors. V1
and V2 remain unchanged. The constructor never fabricates BTF, changes CO-RE's
target, or suppresses unrelated loader warnings; an override without target
BTF or a target absent from that BTF remains an honest construction failure.

`examples/c-attach-host` first requires the unretargeted V2 construction to
fail, then proves V3 through the installed header and shared library. The
committed fixture verifies `fentry/dummy_target -> actual_target`; on this
provisioned host the same binary also proves pinned BCC cachestat's real
application mapping `account_page_dirtied -> folio_account_dirtied` against
live kernel BTF. The native library exports exactly sixteen `febpf_*` symbols.

The aarch64 Linux CI linker failure was also closed in this batch. Explicit
command-line cdylib/staticlib artifacts now use isolated Cargo target
directories and `CARGO_PROFILE_RELEASE_LTO=false`; this prevents GNU linkers
which cannot consume LLVM-bitcode objects from receiving profile-LTO inputs.
Ordinary release builds retain manifest LTO. The exact focused CI sequence and
all six C11 hosts pass locally.

Exact validation for `91f7b91`: default all-target remains **477 passed + 4
ignored**; std-only remains **459 + 4**; default/JIT C API is **488 + 4**; std
interpreter-only C API is **470 + 4**. Strict Clippy passed all four profiles.
True thumb no-std check/Clippy, release build, staticlib, cdylib, C-API
doctests, `bash -n`, `git diff --check`, the C hosts, and the sixteen-symbol
audit passed. The current rustfmt 1.9.0/rustc 1.96.1 toolchain still proposes a
repository-wide pre-existing reflow, so no unrelated formatter rewrite was
mixed into this batch.

The complete release corpus was freshly remeasured and remains **137
families**, 135 loaded, **126 fully compatible**, **835/835 entries loaded**,
and **822/835 verified (98.4%)**: 673 strict + 149
privileged-uninitialized. The same six missing attach targets, seven poisoned
relocations, and two object-level missing kfuncs remain; unsupported-map and
unknown-helper histograms are empty. The C override closes an embedding parity
gap but correctly does not relabel unprovisioned kernel targets as compatible.

Immediate resume order:

1. Expose verification-time static tail-call bundle linking for the one
   measured production graph. Audit `prog_array_inits`, bundle verification,
   exact program/map selection, durable graph identity, and interpreter/JIT
   dispatch. Do not model program identity as an invocation-local callback.
2. Prove the smallest versioned C construction contract with the committed
   tail-call fixture and, where provisioned, the pinned real production graph.
   Preserve the existing V1/V2/V3 rejection of unresolved static initializers.
3. Keep typed ring/perf/queue consumption, runtime map-in-map linking, `.febpf`
   capture/snapshot handles, provider-owned resize/redirect completion, and
   pointer-returning helpers independent until a host measures them. AF_XDP
   live-veth remains a provisioned-host gap; zero-copy and DPDK remain optional
   later adapters.

The map-control checkpoint immediately below is historical and superseded by
this one; the helper milestone remains represented in commit history.

## ACTIVE RESUME CHECKPOINT (2026-07-13 C map control landed; superseded)

Versioned native map configuration and runtime control are committed as
`4ea5d74` (`ffi: configure and control maps from C`), following the ELF/CO-RE
constructor milestone. Apache-2.0 licensing and removal of the stray tracked
`x` fuzzer note are committed as `4f3e219` (`docs: license project under
Apache-2.0`). At checkpoint writing HEAD is `4f3e219`; only this HANDOFF update
is intentionally uncommitted. The recurring tttt job remains deleted. No
build, scanner, subagent, or external terminal collaborator is active.

The license audit found one contributor under two email identities and no
Cargo dependencies. The four locally authored C fixtures containing
`SEC("license") = "GPL"` use the Linux BPF loader declaration; they do not
carry GPL SPDX or copyright notices. The pinned real-world GPL/LGPL sources and
their compiled objects remain under the git-ignored `corpus/` tree and retain
their upstream terms. The README and corpus specification state both
boundaries explicitly. The packaged crate contains `LICENSE` and Apache-2.0
Cargo metadata and excludes `x`; the default all-target suite remains 477
passed plus four ignored. One toolchain drift is recorded honestly: current
rustfmt 1.9.0 (rustc 1.96.1, 2026-06-26) wants to reflow many pre-existing Rust
files, although the map checkpoint's formatter validation passed. No unrelated
formatter rewrite was made for the license-only batch.

The ABI now separates two map lifetimes. `febpf_vm_create_elf_v2` adds a
fixed-stride array of exact-name, nonzero `febpf_map_max_entries_v1` overrides.
They are applied to `elf::Object` before `Vm::new`, so storage allocation,
map-in-map validation, verifier definitions, and virtual region identity all
see the final capacity. V1 construction remains unchanged. Array element sizes
must be exact; a future enlarged element needs an explicit stride rather than
an unsafe guessed layout.

Runtime map operations address maps by exact UTF-8 name and copy all bytes:
`febpf_vm_map_info`, `lookup`, `update`, and `delete`. Info reports stable
kernel-aligned kind numbers, readonly/per-CPU flags, key/value sizes, capacity,
and logical CPU count. Lookup/update expose only CPU 0 for per-CPU maps because
that is febpf's deterministic execution CPU; the flag/count make the omitted
lanes honest. ANY/NOEXIST/EXIST semantics, LRU recency, frozen-map EPERM,
capacity E2BIG, array-delete EINVAL, and absent-key ENOENT are preserved.
Unknown maps/keys return `FEBPF_STATUS_NOT_FOUND`; semantic map failures return
`FEBPF_STATUS_MAP`; bad caller buffer sizes remain invalid arguments. No `Map`,
value pointer, guest address, or storage layout crosses the ABI.

Generic byte operations intentionally reject ringbuf/perf output, queues,
program arrays, and maps-of-maps, which need typed ownership contracts. Map
calls require exclusive VM use, so update-mode checks and mutation are atomic
with respect to other ABI calls. Durable map state remains VM state and is
visible to subsequent invocations.

`examples/c-map-host` proves both lifetimes. It changes the real
`legacy_maps.o::counts` capacity from 16 to 1, inserts one hash key, and gets
E2BIG on a second. It then runs `global_data.o` twice around a C-side `.data`
update and reads exact output `map-state: first=410 second=820 counter=20
scale=8`; frozen `.rodata.cst16` returns EPERM. The shared library exports
exactly thirteen `febpf_*` symbols.

Exact validation and measurement for `4ea5d74`:

- Default all-target: **477 passed + 4 ignored**; std-only: **459 passed + 4
  ignored**.
- Default/JIT C API: **486 passed + 4 ignored**; std interpreter-only C API:
  **468 passed + 4 ignored**.
- Strict all-target Clippy passed for default, std-only, default/JIT C API, and
  std-only C API. True `thumbv7em-none-eabihf` no-std check and strict Clippy,
  release build, and C-API doctests passed.
- Explicit cdylib and staticlib builds passed. All four C11 hosts compile with
  `-Wall -Wextra -Werror`; assembly, log filtering, CO-RE, capacity override,
  durable map state, and frozen-map rejection all pass.
- Complete rebuilt-release corpus remains **137 families**, 135 loaded,
  **126 fully compatible**, **835/835 entries loaded**, and **822/835 verified
  (98.4%)**: 673 strict + 149 privileged-uninitialized. The same six missing
  attach targets, seven poisoned relocations, and two object-level missing
  kfuncs remain; unsupported-map and unknown-helper histograms are empty.
- `rustfmt --check`, `git diff --check`, and the thirteen-symbol audit passed.

Historical resume order at that checkpoint:

1. The next independent embedding gap is custom C helpers. Audit
   `UserHelpers`, verifier signatures, callback mutability/panic behavior,
   guest virtual memory translation, JIT dispatch, snapshots, and whether the
   callback/user token belongs in durable VM host services or a per-invocation
   `ExecutionEnvironment` add-on. Do not assume the current Rust placement is
   the correct C ownership model.
2. Design a typed, versioned helper descriptor. Never hand C a guest or host
   pointer masquerading as the other. Prefer scalar arguments plus explicit
   bounded copied/borrowed memory views derived from verifier signatures. Make
   callback failure a deterministic guest return or runtime error, and prove
   interpreter/JIT parity with a real C host service.
3. Keep typed ring/perf/queue/map-in-map operations, static tail-call linking,
   attach-target overrides, and `.febpf` capture handles independent until a
   host measures them. AF_XDP live traffic remains a provisioned-host gap;
   zero-copy and DPDK remain optional later adapters.

The checkpoint immediately below is historical and superseded by this one.

## ACTIVE RESUME CHECKPOINT (2026-07-13 C ELF/CO-RE loading landed; superseded)

Native production-plugin distribution is committed as `608224d` (`ffi: load
ELF and CO-RE programs from C`), on top of the C ABI and application-host
milestones. At checkpoint writing HEAD is `608224d`; only this HANDOFF update
is intentionally uncommitted. The recurring tttt job remains deleted. No
build, corpus scanner, subagent, or external terminal collaborator is active.

The additive ABI-v1 function `febpf_vm_create_elf` takes copied object bytes
and a versioned `febpf_elf_options_v1`. It selects an exact loaded-program name
and accepts target BTF either as a raw blob or as a complete ELF containing a
`.BTF` section. Multi-entry objects require an explicit selector. Objects with
CO-RE relocations or BTF-typed contexts require target BTF rather than silently
using compiler-local layout. Loader warnings fail closed because v1 has no
warning sink, and static `PROG_ARRAY` initializers return unsupported because
they require verification-time bundle linking. Application attach-target
overrides remain deliberately outside this descriptor.

The handle retains no object, selector, or target-BTF pointer/bytes. It owns the
relocated `Vm`, the last verified model, and only the ELF section's derived
context-model constraint. XDP entries must verify as XDP and skb-family entries
as skb; raw/assembly constructors remain unconstrained. This prevents a caller
from reinterpreting section-specific ctx accesses through an unrelated Flat
ABI without introducing an ELF execution mode in `Vm`.

`examples/c-elf-host` loads `core_probe.o`, passes the complete
`core_target.o` as target BTF, frees both C input buffers immediately after
construction, verifies a Flat context, and produces `core-result=123` from the
relocated offsets. Rust boundary tests additionally cover ambiguous selector
rejection, missing required target BTF, XDP model enforcement, durable ELF map
state, and honest static-tail-call rejection. The shared library exports
exactly eight `febpf_*` symbols.

Exact validation and measurement for `608224d`:

- Default all-target: **477 passed + 4 ignored**; std-only: **459 passed + 4
  ignored**.
- Default/JIT C API: **484 passed + 4 ignored**; std interpreter-only C API:
  **466 passed + 4 ignored**.
- Strict all-target Clippy passed for default, std-only, default/JIT C API, and
  std-only C API. True `thumbv7em-none-eabihf` no-std check and strict Clippy
  passed. Release build and C-API doctests passed.
- Explicit cdylib and staticlib builds passed. All three C11 hosts compiled
  with `-Wall -Wextra -Werror`; assembly output, log filtering, and exact CO-RE
  result 123 passed.
- Complete rebuilt-release corpus scan remains **137 families**, 135 loaded,
  **126 fully compatible**, **835/835 entries loaded**, and **822/835 verified
  (98.4%)**: 673 strict + 149 privileged-uninitialized. The remaining six
  missing-attach-target entries, seven poisoned relocations, and two
  object-level missing-kfunc families are unchanged; unsupported-map and
  unknown-helper histograms remain empty.
- `rustfmt --check`, `git diff --check`, and the eight-symbol `nm` audit passed.

Immediate resume order:

1. The next measured embedding gap is map configuration/control, not another
   execution mode. Audit `Object::set_map_max_entries`, `Vm` map ownership,
   preload/update/lookup APIs, frozen maps, per-CPU selection, and map-in-map
   invariants. Separate pre-construction ELF configuration from post-construction
   runtime map access; they have different lifetimes.
2. Land the smallest versioned surface that unlocks a real host. Likely start
   with exact-name ELF max-entry overrides for explicit-zero maps, then opaque
   or index-stable runtime map access with copied keys/values and precise errno
   diagnostics. Prove it with a C host configuring and reading durable state.
   Do not expose `Map` layout or host pointers and do not combine this with
   custom helper callbacks.
3. Rank custom C helpers only after map control is exercised. Static tail-call
   linking and attach-target overrides remain independently versioned future
   surfaces. AF_XDP live traffic remains an honest provisioned-host gap;
   zero-copy and DPDK remain optional later adapters.

The checkpoint immediately below is historical and superseded by this one.

## ACTIVE RESUME CHECKPOINT (2026-07-13 C log-filter host landed; superseded)

The first production-shaped application of the native ABI is committed as
`7d26ad2` (`examples: add C log-filter host`), on top of the ABI baseline
`a73d983` and its checkpoint `99b4faf`. At checkpoint writing HEAD is
`7d26ad2`; only this HANDOFF update is intentionally uncommitted. The recurring
tttt job remains deleted. No build, scanner, subagent, or external terminal
collaborator is active.

`examples/c-log-filter` is a zero-dependency C11 streaming host. It loads and
verifies one assembly plugin, then supplies each input line through a versioned
4104-byte Flat context: two u32 fields followed by a 4096-byte inline record.
The plugin returns accept/drop and may redact within the record. There are no
embedded host pointers. The entire context is zeroed before every read because
the verified guest may legally inspect fixed-capacity bytes beyond the logical
length; this prevents stale C stack disclosure. After execution the host
revalidates the guest-writable length and action before emitting anything.
Oversized records, runtime failures, and unknown actions fail closed.

This is the intended architectural result: a genuinely different non-packet
application needed no new `Vm` mode, provider trait, or runtime state. The
existing Flat model plus a fresh per-run `ExecutionEnvironment` expressed it.
`scripts/test-c-api.sh` now compiles both C hosts under C11 with
`-Wall -Wextra -Werror`, dynamically links the shared library, and checks exact
log-filter output: `INFO ready` and `TOKEN=*ecret` survive, while `DEBUG noisy`
is dropped. All five focused Rust C-boundary tests and strict C-API all-target
Clippy pass. No Rust execution/loading/verifier source changed, so the complete
corpus was not redundantly rescanned; the unchanged `a73d983` measurement below
remains authoritative.

The example measured the next blocker cleanly: production plugin distribution
still requires assembly text or raw bytecode, while the real corpus is ELF and
often needs a selected program/section and CO-RE target BTF. Continue with an
additive, separately versioned ELF construction descriptor rather than adding
ELF state to invocation descriptors or `Vm`. First audit the existing Rust ELF
selection/target-BTF ownership, then expose the smallest copied-input C
constructor and rejection diagnostics. Do not bundle custom helper callbacks
or map administration into that constructor; those are separate ownership
surfaces and must be ranked after the ELF host is real.

The checkpoint immediately below is historical and superseded by this one.

## ACTIVE RESUME CHECKPOINT (2026-07-13 native C embedding API landed; superseded)

The application-extension packaging baseline requested by the user is
committed as `a73d983` (`ffi: add versioned native C embedding API`). The
architecture redirection remains in `22ab9db` (`runtime: compose invocation
add-ons`) and `08e6b5b` (`runtime: extract invocation host services`), with
the generic packet boundary and AF_XDP copy-mode backend completed through
`445a159` and `6e15d26`. At checkpoint writing HEAD is `a73d983`; only this
HANDOFF update is intentionally uncommitted. The recurring tttt job `cron-1`
was deleted at the user's request. No scanner, build, subagent, or external
terminal collaborator started by this batch remains active.

The new opt-in `c-api` feature exposes a hand-written ABI v1 through
`include/febpf.h`. It has seven exported functions: ABI version, thread-local
last-error copying, assembly and raw-bytecode constructors, destroy, verify,
and run. VM handles are opaque. Versioned input structs begin with
`struct_size`, reject truncation and unknown flags, and accept larger structs
for additive evolution. Status values and model/output identifiers use fixed
`uint32_t` values. Exported VM operations catch Rust panics before the ABI
boundary. Both cdylib and staticlib selection remain explicit through
`cargo rustc -- --crate-type=...`, so the manifest stays rlib-only and true
no-std consumers do not acquire a native allocator or panic-runtime burden.

The load-bearing invariant survives the C surface: a C handle retains only
durable `Vm` state plus the last verified context model. Each run snapshots the
descriptor and creates a fresh `ExecutionEnvironment` containing caller-owned
context or packet bytes and invocation-local printk/sequence callbacks. No C
buffer, callback, or user token is retained. XDP directly borrows the packet
slice through `ExecutionEnvironment::xdp_slice`; it is not staged in `Vm`, and
host pointers are never exposed as guest pointers. Interpreter execution is
the default; requesting JIT from a library built without `jit` returns an
honest unsupported status. Output produced before a later runtime failure is
still delivered, while the result slot is written only on success.

The zero-dependency C11 host in `examples/c-host` is compiled and run by
`scripts/test-c-api.sh`. It constructs an assembly plugin, verifies a writable
Flat context, receives `trace_printk` through its callback, mutates the caller's
context, and returns r0. CI exercises the Rust ABI tests, strict Clippy, the
static library artifact, the shared library, and the compiled C host. The
deliberate v1 omissions are recorded in `docs/specs/c-api.md`: ELF/CO-RE entry
selection, map administration, C helper callbacks, capture/replay handles,
metadata/BTF contexts, provider-owned resizable frames, and rich redirect
completion must earn separately versioned descriptors or handles rather than
be packed into durable VM modes.

Exact validation and measurement for `a73d983`:

- Default all-target tests remain **475 passed + 4 ignored**; std-only remain
  **457 passed + 4 ignored**.
- Default/JIT `c-api` all-target tests: **480 passed + 4 ignored**. Std
  interpreter-only `c-api` all-target tests: **462 passed + 4 ignored**.
- Strict Clippy passed for default, std-only, default/JIT C API, and std-only C
  API profiles. True `thumbv7em-none-eabihf` no-std check and strict Clippy
  passed. Release build and C-API doctests passed.
- Explicit cdylib and staticlib builds passed. The C host compiled as C11 with
  `-Wall -Wextra -Werror`, linked the shared library, printed `printk: n=42`
  and `result=9 context=[9,7]`, and exited zero.
- The complete release corpus scan is unchanged: **137 families**, 135
  instantiate, **835/835 entries load**, **126/137 families fully compatible**,
  and **822/835 entries verify (98.4%)**: 673 strict + 149
  privileged-uninitialized-stack. The remaining outcomes are still six honest
  missing-attach-target environment gaps, seven poisoned application CO-RE
  relocations, and two object-level flowtable missing-kfunc families.
  Unsupported-map and unknown-helper histograms remain empty.
- `rustfmt --check` and `git diff --check` passed.

Immediate resume order:

1. Build one compelling, still zero-dependency application host: prefer an
   eBPF-scriptable streaming log filter over an HTTP server because it can be
   production-shaped without importing a networking stack. Define a small
   versioned Flat context ABI, load the plugin from a file, process bounded
   input records, expose accept/drop and safe in-place redaction, and cover it
   through both Rust integration tests and the compiled C host path.
2. Treat that host as an abstraction test. Record every place it cannot be
   expressed through the existing per-run `ExecutionEnvironment`. Add only
   measured, composable capabilities; do not turn log processing, XDP, ELF,
   maps, or callbacks into modes stored in `Vm` and do not grow C ABI v1 merely
   for convenience.
3. If the example proves a real need, rank ELF entry selection, C helper
   callbacks, and map control independently and give each a separately
   versioned descriptor/handle. AF_XDP live validation remains an honest
   privilege/configuration gap for a provisioned host. Zero-copy and DPDK stay
   optional later adapters.

The checkpoint immediately below is historical and superseded by this one.

## ACTIVE RESUME CHECKPOINT (2026-07-13 AF_XDP copy adapter landed; superseded)

The architecture redirection requested by the user is committed as `22ab9db`
(`runtime: compose invocation add-ons`), with the non-packet proof follow-up in
`08e6b5b` (`runtime: extract invocation host services`) and provider resize
support in `445a159` (`xdp: resize provider packet windows`). The first live
backend is committed as `6e15d26` (`af-xdp: add copy-mode packet provider`). At
checkpoint writing HEAD is `6e15d26`; only this HANDOFF update is intentionally
uncommitted. The recurring tttt job `cron-1` was deleted at the user's request.
No scanner or build started by this batch remains active. Several sleeping
cargo test processes in the pre-existing `pty-2`/`pty-3`/`pty-4` terminal
sessions predate this refactor; they were not used or killed, and own none of
the changed files. No subagent was used.

The key correction is architectural rather than another XDP feature. `Vm` no
longer owns or stages packet bytes, XDP/SKB booleans, or metadata-layout run
state. Verification selects one durable `ContextModel`; each `Machine` borrows
an `ExecutionEnvironment` containing context bytes, an optional packet window,
legacy packet-source identity, optional sequence-output sink, and redirect
completion. `ExecutionOutcome`, `Vm::run_environment`, and
`Vm::machine_environment` make this boundary public. Convenience methods for
XDP slices/frames/providers, skb, raw packet, metadata-owned packet, replay,
debugger, playground, and JIT are thin adapters over it. The old
`prepare_xdp`/`machine_prepared_xdp` staging protocol is gone.

This is deliberately proven by more than XDP: skb and raw inputs use the same
packet resolver, metadata selects an owned packet through the environment,
and BTF iterator execution can compose an independently borrowed `seq_write`
sink. External sink state participates in snapshot/restore and interpreter/JIT
agreement. A verified XDP/SKB model without a packet-window add-on rejects
before instruction zero. Default VM-owned sequence/printk buffers remain
compatibility sinks when an environment does not override them. Explicit
environments do not route through those buffers; removing the public fallbacks
later is API cleanup rather than a prerequisite for the execution boundary.

Provider frames can now opt independently into `adjust_head` and `adjust_tail`
through `XdpCapabilities`. The helpers resize the active packet window owned by
`ExecutionEnvironment`: positive head deltas consume data, negative head deltas
expose provider headroom, positive tail deltas grow into tailroom and zero the
new bytes, and negative tail deltas shrink data. Capacity failures return
`-EINVAL` atomically, absent capability returns `-EOPNOTSUPP`, and a missing
packet returns `-EFAULT`. The slice adapter deliberately advertises neither
capability and therefore keeps its historical unsupported result. Provider
completion observes changed bounds even after a later runtime error, while
snapshot/restore captures and restores the logical window. The verifier's
existing rule still invalidates all packet/data-end aliases after either helper
regardless of the helper's runtime result.

The follow-up audit removed deterministic BTF kernel-memory scratch from `Vm`
and made it environment-owned. It also added an independently borrowed printk
sink (including echo configuration), snapshot/restore, and interpreter/JIT
tests under a Flat context. Together with the BTF sequence sink this proves two
non-packet consumers across distinct context families. The audit classified
maps, PRNG progression, profiling counters, and map-backed perf records as
intentionally durable/cross-invocation state rather than blindly moving every
mutable field. Default VM-owned printk/sequence vectors remain compatibility
sinks only when an explicit environment does not override them.

The opt-in Cargo feature `af-xdp` now exposes a Linux raw-UAPI copy-mode
`AfXdpProvider`. All socket, private UMEM, ring, interface, queue, and
descriptor state stays inside `src/af_xdp.rs`; `Vm` was not modified. RX copies
one UMEM chunk into an ordinary `XdpFrame`, preserves real active bounds,
installs metadata and resize capabilities, and uses an opaque token-to-chunk
table for completion. Rings use the kernel-returned offsets and acquire/release
SPSC ownership. TX completion supports `XDP_TX`, explicit PASS recycle/TX
policy, same-interface redirect, and only exact sparse XSKMAP slots registered
by the provider. Unowned redirects fail honestly after reclaiming the frame.
The real socket FD is exposed with `AsRawFd` for an embedding host to install
in its kernel XSKMAP; program attachment and kernel-map updates remain outside
febpf.

Live validation is an environment gap. This host has `CONFIG_XDP_SOCKETS=y`,
but unprivileged BPF is disabled, noninteractive sudo is unavailable, and the
ignored live test on `lo` reached socket setup then failed with `EPERM`.
Therefore no veth was created, no feeder XDP/XSKMAP was installed, and no live
packet-flow success is claimed. Deterministic UAPI layout, ring wrap/full,
configuration, interface lookup, PASS, same-interface, and sparse-slot policy
tests do pass. Zero-copy, shared UMEM, multi-buffer operation, and cross-socket
or cross-interface completion routing remain deliberately unimplemented.

Exact validation and measurement through `6e15d26`:

- Default all-target tests: **475 passed + 4 ignored**.
- Std interpreter-only all-target tests: **457 passed + 4 ignored**.
- AF_XDP-feature all-target tests: **480 passed + 5 ignored**; the extra ignored
  test is the explicitly provisioned live socket test.
- Strict Clippy passed for default/all-targets, std-only/all-targets, and
  AF_XDP-feature/all-targets.
- True `thumbv7em-none-eabihf` no-std check and strict Clippy passed.
- Release build and complete corpus scan: **137 families**, 135 instantiate,
  **835/835 entries load**, **126/137 families fully compatible**, and
  **822/835 entries verify (98.4%)**: 673 strict + 149 privileged-uninitialized
  stack. The only entry gaps remain six missing attach targets and seven
  poisoned CO-RE relocations; two object-level flowtable families remain
  missing-kfunc. Unsupported-map and unknown-helper histograms remain empty.
- `git diff --check` passed.

Immediate resume order:

1. Do not spin on privileged AF_XDP validation in this environment. When a
   provisioned host is available, create a veth, attach a minimal feeder XDP
   program, install `provider.as_raw_fd()` in its real XSKMAP, run PASS/TX/DROP
   and resize traffic, and record the first mismatch as `.febpf`.
2. Corpus saturation and the two ranked boundary milestones (generic provider
   plus AF_XDP copy mode) are complete. The next unprivileged coherent project
   should be the ranked application-extension packaging audit: stabilize the
   embedding surface, then add a zero-dependency C ABI/header and one small
   example host. Keep invocation resources composed through
   `ExecutionEnvironment`; do not reintroduce modes in `Vm`.
3. DPDK and AF_XDP zero-copy remain optional later adapters, not the default
   next step and never VM features.

The checkpoint immediately below is historical and superseded by this one.

## ACTIVE RESUME CHECKPOINT (2026-07-13 redirect delivery landed; resize capability next; superseded)

The provider-neutral redirect batch is committed as `fb73fc7` (`xdp: deliver
provider redirect destinations`). At checkpoint writing HEAD is `fb73fc7`;
only this HANDOFF update is intentionally uncommitted. No test, build, scanner,
subagent, or external terminal collaborator is active.

`XdpVerdict` now carries an optional `XdpRedirect`. Successful direct redirects
record interface index/flags; redirect-map helpers record loaded-map index,
map kind, u32 key, and raw flags. The destination is exposed only when the
final action is `XDP_REDIRECT`; a later failed helper clears an earlier choice.
This is delivery intent only: febpf still never transmits or fabricates socket
ownership. Interpreter/JIT agree, the legacy integer adapter remains unchanged,
and `Machine` snapshots capture/restore the per-invocation redirect selection.

Exact validation and measurement for `fb73fc7`:

- Default all-target tests: **472 passed + 4 ignored**.
- Std interpreter-only all-target tests: **454 passed + 4 ignored**.
- Strict Clippy passed for default/all-targets and std-only/all-targets.
- True `thumbv7em-none-eabihf` no-std check and strict Clippy passed.
- Release build and complete corpus scan: **137 families**, 135 instantiate,
  **835/835 entries load**, **126/137 families fully compatible**, and
  **822/835 entries verify (98.4%)**: 673 strict + 149 privileged-uninitialized
  stack. The only entry gaps remain six missing attach targets and seven
  poisoned CO-RE relocations; two object-level flowtable families remain
  missing-kfunc. Unsupported-map and unknown-helper histograms are empty.

Immediate resume order:

1. Add explicit resize capability to provider-owned frames. Refactor the VM
   packet backing so adjust-head/tail can atomically move the active window,
   update virtual `data`/`data_end`, and copy the resulting window back only
   when the frame opts in and capacity suffices. Standalone `run_xdp` must
   continue returning `-EOPNOTSUPP`; failed resize must not mutate anything.
   Cover positive/negative deltas, headroom/tailroom exhaustion, direct access
   after reloading invalidated pointers, interpreter/JIT, and snapshots/replay.
2. Implement Linux AF_XDP copy mode behind target/feature gating with raw
   syscalls and zero new dependencies. Validate on veth, bind provider-owned
   sparse XSKMAP sockets during completion, and record the first mismatch as
   `.febpf`. Zero-copy and DPDK remain later work.

Older checkpoint text below remains useful history, but its resume lists are
superseded by the two steps above.

The first post-saturation packet-provider batch is committed as `6a6010e`
(`xdp: add packet provider boundary`). At checkpoint writing, HEAD is
`6a6010e`; only this HANDOFF update is intentionally uncommitted. No test,
build, scanner, subagent, or external terminal collaborator is active.

The new allocator-only `src/packet.rs` boundary remains compatible with true
`no_std` builds. `XdpFrame` owns storage plus an explicit active data window,
headroom/tailroom, typed scalar `xdp_md` metadata, and an opaque provider
cookie. `XdpProvider` transfers one owned frame at a time and reclaims every
frame through completion; `Vm::run_xdp_provider(..., budget)` makes that a
bounded batch. Runtime VM failures are completion data rather than transport
failures, so frame ownership is not silently lost. Interpreter and JIT expose
matching frame and provider adapters. Legacy `run_xdp(&mut [u8])` behavior is
preserved through the same frame execution path.

Focused differential tests prove slice/frame interpreter/JIT equality,
active-byte mutation, preservation of spare capacity and opaque cookies,
provider metadata synthesis, bounded ordered completion, and runtime-error
completion. The contract and honest gaps are documented in
`docs/specs/packet-providers.md`; `xdp_adjust_head`/`xdp_adjust_tail` still
return `-EOPNOTSUPP`, and redirect currently delivers only the action rather
than fabricating a destination.

Exact validation for `6a6010e`:

- Default all-target tests: **470 passed + 4 ignored**.
- Std interpreter-only all-target tests: **452 passed + 4 ignored**.
- Strict Clippy passed for default/all-targets and std-only/all-targets.
- True `thumbv7em-none-eabihf` no-std check and strict Clippy passed.
- `git diff --check` passed. The production corpus was not rescanned because
  this runtime-only boundary does not alter loading or verification; the
  saturated `b78bbea` measurements below remain authoritative.

Immediate resume order:

1. Complete provider-neutral redirect delivery. Record the selected direct
   interface or redirect-map index/key/flags during helper execution, include
   it only when the final action is `XDP_REDIRECT`, snapshot/restore it for
   deterministic stepping, and return it in `XdpVerdict`. Keep standalone
   helpers verdict-only in effect: recording a destination must not transmit.
2. Add explicit per-frame/provider resize capability and make adjust-head/tail
   update the active window and virtual packet bounds atomically only when
   capacity permits. Preserve standalone `run_xdp` as `-EOPNOTSUPP`; cover
   interpreter/JIT, stale-alias verifier rules, failure atomicity, and replay.
3. Implement Linux AF_XDP copy mode behind target/feature gating with raw
   syscalls and zero new dependencies. Validate on veth, preserve backend-owned
   sparse XSKMAP sockets, and record the first mismatch as `.febpf`. Zero-copy
   and DPDK remain later work.

Everything below this insertion is historical corpus/verifier context. The
corpus-saturation measurements remain valid, but older "Immediate resume"
lists are superseded by the one above.

The corpus-first continuation is active. The prior checkpoint documentation
was committed as `21047c5`, and the complete xvs production-lane batch was
committed as `3f9bb65` (`xdp: cover xvs queue dataplane`). A tttt recurring
job named `cron-1` injects the continuation plan every 30 minutes with
`if_busy=wait`. The fully validated diagnostic/ALU32 continuation batch below
is committed as `34877b9` (`verifier: diagnose xvs complexity frontier`). At
checkpoint writing the incremental branch-free-tail pruning batch is committed
as `11a034e` (`verifier: prune branch-free exit tails`), HEAD is `11a034e`, and
the worktree is clean. No test/build/scanner process or subagent is active.

Refresh update: the checkpoint follow-up documentation is committed as
`912963a`, and the rejected packet-range ordering experiment is documented in
`e5a7db2`. The checkpoint commit is `cfa72f9`; at refresh scheduling HEAD is
`cfa72f9` and only this exact HEAD-correction in `HANDOFF.md` is intentionally
uncommitted. No test, build, scanner, subagent, or external terminal
collaborator is active.
The newest authoritative resume action remains explicit relational precision/
partition tracking for conditional joins. Do not redo the three removed global
join/liveness prototypes or independent packet-range ordering.

Continuation update: a prune-scan backoff experiment was also rejected and
removed. Scanning every arrival after the miss-streak threshold made
`xdp_request_func` consume enough memory that the verifier process was killed.
Scanning every eighth arrival still exhausted one million instructions and
increased remembered states at the conditional joins (pc 3422 from 529 to
2247, pc 3424 from 1149 to 2732, and pc 3426 from 511 to 2682). The original
one-in-64 backoff is restored. The xvs frontier is not caused by skipped
subsumption scans; more frequent scans mostly retain additional incomparable
states. Current-source release baseline remains request failure at pc 3472,
with hottest joins pc 4787 28469/3, pc 3468 18656/1, pc 3422 16010/529,
pc 3424 15966/1149, and pc 3426 15906/511. Forward remains a complexity
failure as well. Continue with relational precision/partitioning, not backoff
tuning.

Precision-design update: inspection of the current upstream Linux verifier
(`kernel/bpf/states.c` and `kernel/bpf/backtrack.c`) confirms that its useful
state compression is not ordinary backward liveness. `regsafe()` treats an
old imprecise scalar as covering any current scalar, but every scalar used for
a branch, pointer offset, or memory proof triggers `bpf_mark_chain_precision()`.
That routine walks recorded instruction history and checkpoint-parent states,
marks the contributing registers/stack slots precise transitively, and mutates
already checkpointed ancestors before they can be used for pruning. This is
the missing invariant behind the failed febpf prototypes.

Implement the febpf version as one coherent semantic change:

1. Give remembered states stable checkpoint identities instead of storing
   only replaceable `VState` clones in `PruneList`; running paths must retain a
   parent checkpoint and the instruction/branch history since it.
2. Add per-register and per-spill scalar precision marks. State subsumption
   may ignore only an old scalar explicitly known imprecise; pointers,
   initialization, nullability, locks, packet ranges, and equality classes
   keep their existing strict contracts.
3. On every conditional scalar refinement and every scalar use in pointer or
   memory bounds, backtrack MOV/ALU/load/spill dependencies through the local
   history and checkpoint parents. Unsupported transfers conservatively mark
   all scalar registers/spills in the affected frames precise.
4. A prune is valid only after required precision has been propagated into
   the old checkpoint chain. Ring replacement must not invalidate parent
   identities; use an arena/tombstone or generation-safe references.
5. First land adversarial tests proving retroactive precision for dead/live
   register copies, spills, equality-linked values, null branches, and packet
   range/control correlation. Only then measure xvs. Do not approximate this
   with global location masks or branch-history hashes: both lose the
   transitive data dependencies the kernel algorithm preserves.

Implementation update: stable checkpoint ancestry (`75e82fb`), scalar
precision representation (`32bf4a8`), and register/ALU/aligned-spill
backtracking (`98d9662`) are committed. The next incremental layer adds
direct-child branch reference counts and bottom-up propagation of accumulated
precision requirements when checkpoints finalize. Its initial activation was
deliberately rejected: applying the accumulated masks made xvs request reach
the known false packet rejection at pc 494 (62-byte proof before an offset-70
access). Marking every scalar register and spill precise at packet-bound
branches still produced the same counterexample, proving a transitive relation
is lost elsewhere. The committed-safe form must keep finalized checkpoint
comparison fully precise while retaining the finalization/requirement
infrastructure; do not enable imprecise masks until that missing relation is
identified. A live-uninitialized-stack adversarial test also caught and fixed
an independent comparison rule: imprecision may ignore ranges only when both
old and current locations are initialized scalar spills/registers, never the
initialization/type distinction. With compression disabled, release xvs
request exactly reproduces the honest pc-3472 complexity baseline and hottest
joins. Bounded and unbounded loop regressions pass; branch accounting is
direct-child and propagates upward only on a zero transition to avoid the
rejected O(depth^2) implementation.

Aligned-u32 continuation update: `7d89d96` finalized the safe checkpoint
ancestry infrastructure, and `d32f7ea` (`verifier: preserve aligned u32 stack
scalars`) is the newest semantic batch. The pc-494 packet counterexample was
not itself evidence that checkpoint compression was invalid: xvs stores its
parsed protocol as an aligned 32-bit stack value at offset -288, reloads it
after helper clobbers, and needs that value's scalar identity to keep the UDP
62-byte proof separate from the TCP offset-70 access. The verifier previously
reduced that reload to an unrelated unknown scalar. It now preserves exact
aligned u32 scalar ranges and equality identity, propagates JMP32 refinement
through such reloads, and degrades provenance conservatively on other writes
while retaining byte initialization. Prune comparison explicitly preserves
the initialization mask; a fully initialized remembered slot cannot cover a
partially initialized arrival.

The initial pre-Scalar32 activation appeared to prune a nullable-map-value
failure and was therefore kept disabled. Repeating that experiment after the
aligned-u32 model and adapting the trace fixture to use a genuinely unknown
scalar no longer reproduces the failure. `d741e76` (`verifier: activate scalar
precision checkpoints`) now applies accumulated register/spill masks when a
single-frame checkpoint finalizes; multi-frame/local-call checkpoints remain
fully precise. A new adversarial diamond proves the important transitive case:
a scalar decides whether a nullable pointer is checked before dereference. If
conditional precision propagation is removed, the test is incorrectly
accepted because the bad path prunes; with the production implementation it
rejects at the nullable dereference. Keep that regression when extending
history transfer rules.

Exact activated measurements from the rebuilt release binary under the
unchanged one-million instruction budget:

- `xdp_request_func` fails for complexity at insn 2744; hottest joins are pc
  3416 17393/3423, pc 4787 14964/1, pc 3422 14958/491, pc 3424 14883/490, and
  pc 3426 14877/485.
- `xdp_forward_func` fails for complexity at insn 5800; hottest joins are pc
  150 14232/4096, pc 215 10362/3737, pc 244 7330/23, pc 192 6716/1945, and pc
  3194 6044/2059.
- Default all-target tests: **462 passed + 4 ignored**. Std-only all-target
  tests: **444 passed + 4 ignored**. Strict Clippy passes for default/all-
  features and std-only. True `thumbv7em-none-eabihf` no-std check and strict
  Clippy pass.
- The definitive rebuilt-release scan remains **137 families**, 135
  instantiate, **835/835 entries load**, **125/137 compatible families**, and
  **820/835 entries verify (98.2%)**: 671 strict + 149 privileged-uninitialized-
  stack. Honest remaining outcomes are six missing-attach-target entries,
  seven poisoned CO-RE entries, and the two xvs complexity rejections; two
  flowtable families remain missing-kfunc. Unsupported-map and unknown-helper
  histograms remain empty.

Packet-proof/helper continuation: `6459284` (`xdp: order packet proofs and add
adjust tail`) is the newest production batch. Temporary component diagnostics
showed that request pc 3416 had no precise scalar registers, while its packet
pointer in r1 and spilled alias at stack -256 differed in 3415/3423 remembered
states because paths accumulated different packet-range proofs. The earlier
one-way packet-range experiment had predated Scalar32 and exposed pc 494 by
losing the protocol/control relation. Retesting after exact u32 stack identity
and activated precision no longer reproduces that false rejection. State
subsumption now permits only the safe direction: a current packet pointer with
an equal-or-stronger proof may be covered by an otherwise identical remembered
pointer with a weaker proof. A focused unit test locks the direction.
Resetting new active checkpoints to imprecise and mutating their masks
immediately was also prototyped; both xvs entries produced byte-for-byte
identical failure PCs and join counts, so timing of mask application is not the
current blocker and that no-effect prototype was removed.

That ordering immediately exposed xvs forward helper #65,
`bpf_xdp_adjust_tail`. It now has the exact XDP ctx/scalar signature and, like
`xdp_adjust_head`, invalidates all packet/data-end aliases regardless of return
value. Standalone execution honestly returns `-EOPNOTSUPP` and leaves packet
bytes unchanged because no packet provider owns resizing yet. A focused test
covers helper-name/id lookup, stale-alias rejection, return value, and packet
non-mutation. The generic packet-provider/AF_XDP work remains deferred until
the corpus is saturated; do not pretend this standalone helper resizes.

Exact final release measurements under the unchanged budget:

- Request advances from insn 2744 to complexity at insn 4468; hottest joins
  are pc 4787 9801/1, pc 3416 9346/3142, pc 4725 8185/2147, pc 4723 8001/377,
  and pc 4481 7890/1808.
- Forward passes the new helper and advances to complexity at insn 4615;
  hottest joins are pc 150 16152/3569, pc 4624 7269/2421, pc 3194 6044/2059,
  pc 3195 5778/2032, and pc 3253 5749/641.
- Default all-target tests: **464 passed + 4 ignored**. Std-only all-target
  tests: **446 passed + 4 ignored**. Both strict Clippy profiles and the true
  thumb no-std check/strict Clippy pass.
- The complete rebuilt-release scan remains exactly 137 families, 835/835
  loaded entries, 125 compatible families, and 820/835 verified (671 strict +
  149 privileged). The same six attach-target gaps, seven poisoned CO-RE
  entries, two xvs complexity rejections, and two flowtable missing-kfunc
  families remain classified honestly; both blocker histograms are empty.

Corpus-saturation update: `b78bbea` (`verifier: prune with whole-cfg
liveness`) closes both xvs complexity rejections under the unchanged
one-million instruction budget. Temporary component diagnostics showed that
the remaining large partitions were dominated by dead packet/map/stack
pointer variants rather than scalar precision. The verifier now computes a
conservative backward may-liveness fixed point over both successors of every
branch and projects dead registers/stack slots from prune comparison. Exact
helper signatures determine register uses; any helper memory/`Any` argument
keeps all stack slots live. Only aligned full-slot stores kill a stack slot.
Programs containing local BPF calls deliberately fall back to the older exact
branch-free-tail projection because inter-frame liveness is not modeled.

This does not recreate the rejected pre-precision liveness prototype. The
previous pc-494 failure lost protocol/control correlation before aligned-u32
stack identity, activated scalar precision backtracking, and one-way packet-
proof ordering existed. With those invariants now composed, request and
forward both verify and pc 494 remains unreachable. Focused branching-CFG
tests prove dead pointer variants prune, live pointer/scalar distinctions do
not, live stack initialization does not, and local calls take the conservative
fallback. The existing discriminating nullable/control, packet-range,
bounded/unbounded-loop, equality, and aligned-u32 tests remain green.

Exact final measurements:

- `xdp_request_func`: **verification PASSED**, 502771 processed instructions,
  100230 states explored, 50115 pruned, call depth 1, 456-byte stack.
- `xdp_forward_func`: **verification PASSED**, 386134 processed instructions,
  81278 states explored, 40639 pruned, call depth 1, 480-byte stack.
- Default all-target tests: **468 passed + 4 ignored**. Std-only all-target
  tests: **450 passed + 4 ignored**. Strict Clippy passes in both profiles;
  true `thumbv7em-none-eabihf` no-std check and strict Clippy pass.
- Definitive rebuilt-release scan: **137 families**, 135 instantiate,
  **835/835 entries load**, **126/137 families fully compatible**, and
  **822/835 entries verify (98.4%)**: 673 strict + 149 privileged-uninitialized-
  stack. There are **zero ordinary verifier rejections**. The only remaining
  entry outcomes are six honest missing-attach-target environment gaps and
  seven poisoned application CO-RE relocations; two object-level flowtable
  families remain missing-kfunc on this host. Both blocker histograms are
  empty.

This is genuine saturation of the pinned executable corpus. Preserve the
environment/configuration classifications; do not manufacture attach targets,
kfuncs, target types, or improved denominators. The active work now moves to
the agreed ranked idea: a generic packet-provider/batch boundary, then an
AF_XDP copy-mode backend with zero new dependencies. DPDK remains optional and
later.

Completed and committed in `3f9bb65`:

- Added immutable production upstream `davidcoles/xvs` v0.2.10 at commit
  `6b6011b2c9a7176de5490a8b1c6d829de26724d6`; its unchanged `bpf/layer3.c`
  builds offline with upstream Makefile capacity defaults and explicit host
  x86-64 glibc-header selection.
- Added `BPF_MAP_TYPE_QUEUE`, FIFO/overwrite-on-`BPF_EXIST` semantics,
  `bpf_map_push_elem` #87, assembler, additive replay-v1 kind 16, and kernel
  translation. Added `xdp_adjust_head` #44 with exact XDP ctx signature,
  unconditional verifier packet-alias invalidation, and honest standalone
  `-EOPNOTSUPP` because no packet provider owns headroom yet.
- Accepted exact 64-bit XDP `data_end - packet` and MOV32-mediated ALU32
  differences while preserving rejection of all other truncated pointer
  arithmetic. Packet provenance uses reserved scalar identity markers rather
  than keeping a MOV32 result typed as a pointer; this preserved the existing
  multi-entry fixture that legitimately truncates a packet pointer to scalar.
- Documented the contracts in `docs/specs/queue-map-xvs.md`.

Exact committed-batch validation and measurement:

- Default all-target tests: **454 passed + 4 ignored**.
- Std interpreter-only all-target tests: **436 passed + 4 ignored**.
- Strict Clippy passes in default and std-only profiles.
- True `thumbv7em-none-eabihf` no-std check and strict Clippy pass.
- Offline corpus rebuild: **137 object families**.
- Full scan: 135/137 instantiate on this host; **835/835 enumerable entries
  load**; **125/137 families compatible** and **820/835 entries verify
  (98.2%)**: 671 strict plus 149 privileged-uninitialized-stack. Remaining
  entries are six missing-attach-target, seven poisoned CO-RE, and the two xvs
  complexity-limit rejections. Two flowtable objects remain missing-kfunc.
  Unsupported-map and unknown-helper histograms are empty.

In-progress investigation after `3f9bb65` (not committed):

- `src/verifier.rs` adds useful hottest-join diagnostics to the one-million
  processed-instruction error. Keep this unless a cleaner equivalent replaces
  it; it materially improves the rejection explainer.
- It also closes one newly exposed mixed ALU32 form: truncated `data_end`
  scalar marker minus an untruncated packet pointer. This is the same exact
  XDP difference contract and must receive a focused test before commit.
- With diagnostics, `xdp_forward_func` exhausts the budget with hottest joins
  `pc 150: 15178 arrivals/3965 states`, `pc 3253: 8789/2705`, `pc 3195:
  8789/389`, `pc 3194: 8785/389`, `pc 215: 7599/3717`.
- After the mixed subtraction fix, `xdp_request_func` advances to the same
  complexity class: hottest joins include `pc 4787: 39028/947`, `pc 3468:
  16185/4096`, and pcs 3422/3424/3426 around 14k arrivals/~500 states.
- Source/disassembly inspection shows major joins are shared post-parse and
  metrics/counter blocks, not loops. This is acyclic path explosion.
- A first structural-join prototype was tested and deliberately backed out.
  Immediate joining made the existing 100-iteration bounded-loop regression
  widen one step at a time until the instruction budget; delaying joins and
  disabling them across static backward-edge regions fixed that part. However,
  `xdp_request_func` then converged to a false rejection at pc 494: a widened
  path retained only a 62-byte packet proof before a branch-specific access at
  offset 70 size 2. The merge had erased the correlation between protocol
  branches and packet-range proofs. Therefore dropping all equality/correlation
  facts is too imprecise for xvs even though conservative. The prototype is no
  longer in the worktree; do not recreate it unchanged. A viable design must
  partition such states or retain the control facts that justify packet range.
- A second, much narrower prototype merged only numerically identical states
  while forgetting equality IDs. It preserved all 144 integration outcomes but
  slowed that test binary to 37.77s and left `xdp_request_func`'s complexity
  failure and hottest-join histogram exactly unchanged. It too was backed out.
  Equality-ID duplication alone is not the source. The next promising direction
  is conservative backward liveness/precision: ignore only register and stack
  facts provably dead on every continuation, while keeping live branch and
  packet-range correlations partitioned.
- A third prototype added conservative backward register and stack-slot
  liveness to prune comparisons (local-call programs disabled; helpers first
  treated as using r1-r5/all stack, then used exact non-None signature args;
  only aligned full-slot stores killed stack facts). Register-only liveness did
  not converge. Slot liveness collapsed pc 4787 from 947 remembered states to
  3, while pc 3468 remained capped at 4096. Signature-aware helper uses then
  exposed the same false rejection at pc 494 (62-byte proof before offset-70
  access). All 144 integration tests and strict default Clippy passed, but the
  xvs counterexample proves plain syntactic liveness is insufficiently precise.
  The prototype was backed out. Do not ignore a state component merely because
  its register/slot is syntactically dead: verifier precision/equality
  dependencies require Linux-style precision backtracking or an equivalent
  relational partition before such pruning is safe enough for this corpus.
- A promising narrower next step was identified after the third prototype:
  pc 3468 is the start of a deterministic acyclic tail (`map load`, fixed
  stack load, unconditional jump, `redirect_map`, exit), and pc 4787 is the
  exit itself. Implement state projection only at prune points whose entire
  continuation is a branch-free acyclic tail, with live operands computed
  exactly backward through that tail and helper uses taken from `HelperSig`.
  Treat memory/unknown helper arguments and local calls conservatively, and
  fall back to full-state comparison everywhere else. This should capture the
  observed 4096-state/terminal explosion without touching the earlier packet
  parser where global liveness caused the pc-494 false rejection.
- The branch-free-tail projection is now implemented and validated in the
  worktree. It follows only a unique acyclic path to EXIT; conditional branches,
  local calls, unknown helpers, legacy loads, or ambiguous targets disable it.
  Exact helper signatures identify used registers; possible memory arguments
  conservatively keep all stack slots live. Equality IDs use the same projection.
  Focused tests prove a live uninitialized stack slot still rejects while an
  overwritten scalar/pointer register difference prunes safely.
- Exact xvs effect under the unchanged one-million budget: request pc 3468
  falls from 4096 remembered states to 1 and pc 4787 to 3. The entry still
  rejects on earlier conditional joins (pcs 3422-3426); forward remains
  effectively unchanged. This is a bounded improvement, not claimed xvs
  compatibility.
- Final validation for this incremental batch: default **456 passed + 4
  ignored**, std-only **438 passed + 4 ignored**, both strict Clippy profiles,
  and true thumb no-std check/strict Clippy pass. Full scan remains exactly 137
  families, 835/835 loaded entries, 125 compatible families, and 820/835
  verified (671 strict + 149 privileged); the honest remaining classifications
  are unchanged.
- A subsequent packet-range subsumption experiment was rejected and removed.
  Treating an otherwise identical pointer with a stronger proven packet range
  as covered by a weaker-proof state is valid pointwise, and reduced forward's
  hottest pc 150 from 3965 to 2033 states, but it again made request falsely
  reject at pc 494 (62-byte proof before offset-70 access). Packet proof and
  branch partition are relational; never order ranges independently in prune
  comparisons without preserving the control correlation.

Immediate resume order:

1. Define the generic packet-provider/batch contract in a focused spec and in
   `docs/ideas.md`: packet ownership, mutable frame extent/headroom/tailroom,
   metadata/context synthesis, verdict/redirect delivery, batching, and replay
   capture. Keep verifier packet semantics independent of provider choice.
2. Refactor the current owned-packet XDP path behind that boundary with a mock
   provider and differential tests proving unchanged interpreter/JIT/replay
   behavior. Make `xdp_adjust_head`/`xdp_adjust_tail` delegate resizing only
   when the provider explicitly owns capacity; standalone remains honest
   `-EOPNOTSUPP`.
3. Add AF_XDP copy mode first using raw Linux syscalls and feature/target
   gating, tested on veth before mlx5. Preserve XSKMAP sparse socket ownership
   and save the first kernel/febpf mismatch as `.febpf`. Consider zero-copy
   only after copy mode; keep DPDK a separate optional workspace adapter.

Continuation batch completed after this checkpoint was written:

- Added and validated the focused mixed MOV32 `data_end` minus untruncated
  packet-pointer regression. Preserved the existing shared-section multi-entry
  fixture and the bounded-loop regression.
- Kept hottest-join diagnostics on the one-million-instruction error and
  documented two rejected pruning prototypes above. No unsound or materially
  imprecise join remains in the tree.
- Final default all-target matrix: **454 passed + 4 ignored**. Std-only:
  **436 passed + 4 ignored**. Strict Clippy passed in default/all-features and
  std-only profiles. True `thumbv7em-none-eabihf` check and strict Clippy passed.
- Final release rebuild and complete scan reproduced the committed frontier:
  **137 families**, 135 instantiate, **835/835 entries load**, **125/137
  compatible families**, and **820/835 entries verify (98.2%)**: 671 strict +
  149 privileged-uninitialized-stack. Remaining outcomes are the same six
  attach-target gaps, seven poisoned CO-RE entries, and two xvs complexity
  rejections; two object-level flowtable families remain missing-kfunc.

## ACTIVE RESUME CHECKPOINT (2026-07-13 AF_XDP corpus frontier; superseded by checkpoint above)

The real-world coverage moonshot remains active. Two complete, measured
xdp-tools batches landed after the prior checkpoint: `d19da69` (`xdp: cover
dump and filter production programs`) and `f33f92d` (`xdp: support AF_XDP
socket maps`). At checkpoint writing HEAD is `f33f92d` and the worktree is
clean except for this intentional HANDOFF update. No test/build/scanner
process, Codex subagent, or external terminal collaborator is active.

Completed:

- The pinned xdp-tools v1.6.3 lane now includes xdp-dump's two BPF translation
  units, all ten xdp-filter variants, three lib/util BPF probes, and both
  libxdp default AF_XDP programs. The offline build produces 136 total object
  families. Explicit globs cover upstream's generated-style `.c` filenames;
  libbpf feature declarations match the pinned headers.
- ALU32 `data_end - data` is accepted only for XDP packet-end minus packet
  pointers and yields an unknown zero-extended u32 scalar. All other ALU32
  pointer arithmetic remains rejected. Interpreter and JIT execute the
  ordinary subtraction and a 37-byte focused test agrees exactly.
- `BPF_MAP_TYPE_XSKMAP` is supported across ELF, maps, verifier, interpreter/
  JIT redirect behavior, assembler, replay v1 (additive kind 15), and kernel
  map translation. It has exact four-byte key/value shape, sparse slots, and
  bounded queue indices; absent slots return the redirect fallback. Standalone
  execution never fabricates an AF_XDP socket or transmission.
- xdp-dump's placeholder fentry/fexit target remains an honest
  `ENVIRONMENT:missing-attach-target`. The two flowtable objects remain
  `ENVIRONMENT:missing-kfunc` on this host. Application CO-RE poison remains
  explicit rather than being weakened or reclassified.

Exact final validation and measurement:

- Default all-target tests: **453 passed + 4 ignored**.
- Std interpreter-only all-target tests: **435 passed + 4 ignored**.
- Strict Clippy passes in default and `--no-default-features --features std`.
- True `thumbv7em-none-eabihf` no-std check and strict Clippy pass.
- `cargo build --release`, focused XSKMAP/ALU32 tests, offline corpus rebuild,
  and `git diff --check` pass.
- Full `NO_BUILD=1 ./scripts/scan-corpus.sh`: **136 families**, 134 instantiate
  on this host, and **829 enumerable entries all load**. **125/136 families**
  are compatible and **816/829 entries verify (98.4%)**: 667 strict plus 149
  explicitly privileged uninitialized-stack entries.
- Remaining entry outcomes are exactly six missing-attach-target environment
  gaps and seven poisoned application-supplied CO-RE entries. The two
  object-level missing-kfunc families do not add enumerable entry outcomes.
  Unsupported-map, unknown-helper, and ordinary verifier histograms are empty.

Decisions and invariants:

- Continue maximizing honest real-world coverage before new ideas. Rank by
  distinct production family first, entry count second; never improve the
  percentage by inventing prototypes, sockets, routes, disabled lanes, or
  denominators.
- XSKMAP is deliberately sparse even though queue keys are bounded like an
  array. A missing socket is not a present zero value. AF_XDP socket ownership
  belongs to the future packet-provider backend, not the helper/map model.
- The agreed post-saturation architecture remains a generic packet-provider/
  batch boundary, AF_XDP as the zero-dependency first backend, and DPDK only as
  a separate optional workspace adapter/sidecar. Preserve mlx5 kernel
  ownership; direct PCI/VFIO mlx5 ownership is a separate driver project.

Immediate resume order:

1. Commit this HANDOFF update if it remains the only modification after the
   tttt refresh.
2. Add the next small immutable production upstream (or another clearly
   production pinned source lane), rebuild offline/reproducibly, and rank the
   newly exposed blockers by distinct family. The ordinary xdp-tools source
   frontier is now exhausted except generated dispatcher templates and tests.
3. Continue one full-matrix, measured, documented, clean commit at a time. At
   genuine real-world saturation, record and implement the generic packet
   provider/AF_XDP design before any DPDK-specific adapter.

## ACTIVE RESUME CHECKPOINT (2026-07-13 xdp-tools expansion complete; superseded by checkpoint above)

The production-corpus moonshot remains active. The xdp-tools production
expansion and its general functionality are committed at `814ced9` (`xdp:
support routing and locked flow state`). The prior explicit attach-target batch
is committed at `143e1ed`, with its documentation at `3253a07`. At checkpoint
writing, the implementation tree was clean and only this `HANDOFF.md` edit was
uncommitted. No build/test/scanner process, Codex subagent, or external terminal
collaborator is active.

Completed in `814ced9`:

- The pinned xdp-tools v1.6.3 lane expanded from xdp-bench to five additional
  production families: xdp-forward flowtable, flowtable-sample, ordinary
  forwarding, monitor, and trafficgen. Offline rebuilding now produces 119
  total objects.
- `bpf_fib_lookup` (#69) uses an exact XDP ctx plus initialized writable
  `MEM_RDWR` buffer. Standalone execution validates the region and returns the
  kernel's NOT_FWDED outcome without inventing host route/neighbour state.
- `bpf_ktime_get_coarse_ns` (#160) advances snapshotted deterministic logical
  time by one millisecond. `bpf_csum_diff` (#28) implements the kernel
  nullable/multiple-of-four buffer contract and checksum composition; its
  privileged kernel oracle test skipped locally because BPF privilege was
  unavailable rather than claiming a differential result.
- `bpf_spin_lock`/`unlock` (#93/#94) preserve the exact aligned top-level BTF
  lock offset in `MapDef` and replay v1. Verification tracks the held map/offset
  per path; rejects wrong/non-BTF fields, nested locks, mismatched/unbalanced
  unlocks, helper/local calls and legacy packet loads while held, invalid map
  kinds, and direct access overlapping the lock. Map updates preserve an
  existing lock word or zero it on insertion. Interpreter/JIT validate the
  actual writable word and use single-invocation no-op locking.
- Undefined `__ksym` call relocations now resolve only to non-extern FUNCs in
  supplied target BTF and encode a KFUNC call. Missing target functions are
  explicit `ENVIRONMENT:missing-kfunc`, not generic relocation failures. Full
  typed kfunc verification/execution is deliberately not fabricated.
- Self-contained spin-lock, kfunc-object, and kfunc-target fixtures cover BTF
  metadata and strict relocation behavior. `docs/specs/xdp-routing-locks.md`
  and additive replay tag `MAP_SPIN_LOCKS` document the contracts.

Exact validation and measurement:

- Default all-target tests: **451 passed + 4 ignored**.
- Std interpreter-only all-target tests: **433 passed + 4 ignored**.
- Strict Clippy passes in default and
  `--no-default-features --features std` profiles.
- True thumb no-std check and strict Clippy both pass.
- `cargo build --release` passes. The final tiny spin-map invariant then passed
  its focused test and both strict Clippy profiles.
- Full `NO_BUILD=1 ./scripts/scan-corpus.sh`: **119 families**, 117 instantiate
  on this target, and **811 enumerable entries all load**. **109/119 families**
  are compatible and **800/811 entries verify (98.6%)**: 651 strict plus 149
  explicitly privileged uninitialized-stack entries.
- Remaining entry outcomes are exactly four honest attach-target environment
  gaps and seven poisoned application-supplied CO-RE entries. The two
  xdp-flowtable families are object-level `ENVIRONMENT:missing-kfunc` because
  `/sys/kernel/btf/vmlinux` lacks `bpf_xdp_flow_lookup`. Unsupported-map and
  unknown-helper histograms are empty; there is no ordinary verifier rejection.

Decisions and unfinished findings that must survive refresh:

- Do not count the two flowtable families compatible on this host and do not
  synthesize a flowtable pointer. A worthwhile future layer is typed kfunc
  verification plus an explicit user-registered kfunc implementation returning
  VM-owned BTF-shaped data; default absence remains an environment gap.
- The user proposed a ConnectX-7/DPDK userland XDP subject. The agreed likely
  architecture is a generic packet-provider/batch boundary, with AF_XDP as the
  zero-dependency first backend and DPDK as a separate optional workspace
  adapter/sidecar. Keep mlx5/kernel ownership; direct PCI/VFIO mlx5 ownership is
  a separate driver project. This is a high-value post-saturation `ideas.md`
  item: veth copy mode first, kernel differential, then mlx5 zero-copy, saving
  the first mismatch as `.febpf` replay.
- Preserve application/autoload, missing-target, missing-kfunc, and poisoned
  CO-RE cases as explicit environment/configuration outcomes. Never improve a
  percentage by inventing prototypes, network state, disabled lanes, or corpus
  denominators.

Immediate resume order after tttt refresh:

1. Verify HEAD/worktree against this checkpoint and commit this HANDOFF update
   if it is still the only modification.
2. Continue corpus expansion from reproducible production sources. Audit the
   remaining pinned xdp-tools xdp-dump/xdp-filter generated source layout or add
   the next small pinned upstream; rank blockers by distinct family first.
3. If a target BTF with `bpf_xdp_flow_lookup` becomes available, measure the
   already-resolved KFUNC path honestly before designing typed kfunc execution.
4. Continue one full-matrix, measured, committed batch at a time. At genuine
   real-world saturation, add the generic packet-provider/AF_XDP design to
   `docs/ideas.md` and implement it before any DPDK-specific adapter.

## ACTIVE RESUME CHECKPOINT (2026-07-12 22:50 UTC, read this first)

The production-corpus moonshot is active. The portable CI closure remains
fully green at `932060e`; implementation has advanced through `5415b76`.
Do not resume from older 62/62 object-level or 600/785 entry-level claims:
measurement is per ELF entry function and preserves static graph grouping.

The worktree is clean. No Codex subagent is active. Claude is intentionally
offline to conserve memory. A lightweight Codex subagent adversarially audited
the recent map, privileged-stack, and final ordinary-verifier batches. Its
capacity normalization, template invariant, frame-reuse, replay provenance,
and scanner-classification findings were fixed before their commits. Continue
with one evidence-selected batch at a time and commit before widening scope.

Completed and committed since the prior refresh:

```
5415b76 skb: model protocol context field
feedac1 verifier: add privileged stack policy
84b1970 maps: support hash-of-maps templates
d7c1bb7 verifier: track 32-bit conditional bounds
188e641 tracing: add deterministic pid namespace helper
58bdecf tracing: implement variadic printk helper
3b47d42 skb: implement pull data invalidation
079456f network: implement direct redirect helper
593a726 xdp: add packet byte copy helpers
eb9aac3 xdp: implement redirect map helper
01e59f1 skb: add safe packet load adapter
f60e2f6 helpers: type iterator socket conversions
```

Current measured corpus:

- 114 pinned object families and 787 enumerable entry programs: BCC/libbpf-tools,
  libbpf-bootstrap, xdp-tools, Cilium fixture, and 39/39 production Inspektor
  Gadget v0.54.0 sources.
- Latest stable full scan: **102/114 compatible families** and **755/787
  verified entries (95.9%)** under explicit per-object policy. The strict
  baseline is **99/114 families and 606/787 entries (77.0%)**; exactly
  three audited Gadget families / 149 entries are separately reported as
  `OK-PRIVILEGED-UNINIT`. All 787 entries load and all 114 families instantiate.
- The unsupported-map and unknown-helper histograms are now empty. Remaining
  buckets are seven application-retargeting families / 25 entries labeled
  `ENVIRONMENT:missing-attach-target`, plus five poisoned-CO-RE families /
  seven entries. No ordinary verifier rejection remains.
- The Gadget lane remains reproducible at manifest digest
  `cc4b5fdff7392995183181692f328dbb063356d8004bd88b5fdb96b9847bb62d`.
- Default tests: **438 passed + 4 ignored**. Std interpreter-only: **420 passed
  + 4 ignored**. Both strict Clippy profiles and true thumb no-std check/Clippy
  are green. The last full GitHub portable matrix remains run `29207495214`;
  no new remote CI run has been claimed for the post-checkpoint commits.

Important correctness and breadth now landed:

- The skb context models `protocol` at offset 16 and derives its host-visible
  `__be16` value from Ethernet packet input. This closes libbpf-bootstrap `tc`
  across verifier, interpreter, and JIT. Exact selected-program warning
  matching now separates every deliberate dummy fentry target from genuine
  verifier outcomes instead of counting untyped fallback success as kernel
  compatibility.
- `UninitStackPolicy` is strict by default and has one explicit privileged
  `Allow` mode matching Linux `allow_uninit_stack` for direct and helper stack
  reads. The CLI never infers it from uid or `--kernel`. VM stack holes are
  deterministic zeroes, including reused local-call frames; verifier loads
  remain unknown scalars. Replay v1 preserves the policy additively. The
  scanner retries only exact diagnostics for `snapshot_file`, `top_blockio`,
  and `trace_lsm`, labeling their 149 entries separately instead of hiding
  them as ordinary strict success.
- `HASH_OF_MAPS` preserves arbitrary hash key widths and typed nullable inner
  lookups across verifier, interpreter/JIT, replay, assembler, and kernel map
  creation. BTF-only anonymous inner templates are materialized explicitly;
  Gadget `traceloop`'s anonymous `PERF_EVENT_ARRAY` template receives the same
  dynamic defaults in VM and kernel paths. Safe userspace update/delete APIs
  enforce template compatibility and kernel update modes. Static `values[]`
  initializers work for four-byte keys and reject wider keys explicitly.
- Iterator conversions #137-#139 require exact `sock_common` target-BTF input
  and return nullable exact TCP target types; standalone execution returns
  null rather than fabricating host or synthetic sockets.
- Explicit `__sk_buff` mode supplies a VM-owned packet and exact scalar/data
  context fields. #26 copies packet bytes safely; #39 invalidates every stale
  packet/data-end register alias and spill even though the VM packet is already
  linear. Reload plus a fresh bounds check is required.
- Redirect helpers #23/#51 distinguish XDP versus TC verdicts and enforce
  redirect map kinds without inventing device transmission.
- XDP #189/#190 use original-context typing, initialized buffer rules, atomic
  kernel-style errors, VM-owned packet mutation, and preserve range proofs
  because store does not change packet extent.
- #177 supports up to 12 u64 format arguments, nullable zero-length data, and
  deterministic snapshotted output. #120 zeroes output and returns `-EINVAL`
  because febpf imports no host PID namespace identity.
- Scalars now carry canonical u32/s32 subregister bounds. JMP32 refinement
  preserves unknown upper halves, propagates through equality-linked copies
  and aligned spills, and feeds only low-32-local operations. Exhaustive mixed
  upper-half tests cover signed/unsigned taken and fallthrough paths, joins,
  pruning, shifts, and adversarial 64-bit/equality leaks. This made Gadget
  `advise_seccomp` and `ttysnoop` fully compatible.
- The earlier relocation, ELF-entry slicing, map-capacity, deterministic boot
  clock, XDP metadata, DCE hardening, typed iterator contexts, #127 sequence
  output, and #141 task-stack fixes remain authoritative below.

Immediate resume order:

1. Add an explicit application attach-target override (section/program to real
   target-BTF function) and configure the seven BCC dummy-target families with
   their actual filesystem/kernel functions. Never fabricate dummy prototypes.
2. After the retargeted lane is measured, expand the pinned source corpus with
   the next reproducible production families and rank new blockers by distinct
   family first, entry count second.
3. Keep application-supplied/missing CO-RE targets (Gadget DNS/SNI/tcpdump,
   tcpdrop/tcpretrans, missing fentry targets/socket BTF) classified as
   environment/configuration artifacts, not reasons to loosen verification.

CI failures were identified from the `27a3404` logs and fixed at `2fcc237`.
Linux's JIT pass regenerated toolchain-specific committed objects, then the
no-JIT pass consumed them; CI now checks for fixture deletion and restores the
committed objects between passes. On aarch64, deferred rbpf-profile packet
loads reloaded stale in-memory r1-r5 values without first spilling the live
callee-saved registers; the classifier now spills r1-r6 before the trampoline.
The next run proved x86-64 and aarch64 Linux fully green. Its remaining macOS
failure was Bash 3.2 treating empty array expansion as unbound under `set -u`;
the scanner now uses positional parameters for optional arguments and also
replaces unavailable `mapfile` in the default object-discovery path. The
absent-BTF and ordinary scanner tests are green locally. GitHub run
`29207495214` then passed every Linux, macOS, Windows, wasm, and true no-std
job: the portable CI closure is complete.

Privileged-kernel oracle result that changes the earlier audit:

- On Linux 7.0.0-27 as root, the real `top_blockio` object loaded all three
  programs, and 13 representative `trace_lsm` hooks verified despite partially
  initialized stack bytes passed to `map_update_elem`/`ringbuf_output`.
  febpf's 148 rejections are therefore false negatives, not source defects.
- Primary kernel verifier source explains the policy: `env->allow_uninit_stack`
  accepts `STACK_INVALID` reads for privileged programs. febpf now mirrors it
  only through the explicit strict-default policy described above; runtime
  zero backing and frame reuse are regression-tested.
- Full `trace_lsm` kernel load eventually stopped at disabled hook
  `bpf_lsm_vm_enough_memory` before instruction verification; that one stop is
  an attach-environment artifact and does not invalidate the representative
  verifier results.

Workflow remains: implement one evidence-selected batch, commit immediately,
`cargo build --release`, run `NO_BUILD=1 ./scripts/scan-corpus.sh`, and rank by
distinct families first, entries second. Keep generated 147-hook LSM counts
from masquerading as 147 independent workloads.

## PRIOR CHECKPOINT (embedding and legacy/backend closure)

Embedding parity and the legacy-opcode/Cranelift closure are complete through
`b30a42a`. Commit the current documentation checkpoint separately.

Completed linear batches:

```
b30a42a replay: preserve legacy packet profiles
01ae4c0 docs: record rbpf legacy behavior
72b9d93 tests: differential legacy packet behavior
fc37249 packet: support legacy ABS and IND loads
ac4137d docs: specify legacy packet and backend parity
83f3687 docs: plan strict superset closure
7e919d3 api: add configurable packet metadata
beb9eeb portability: add no_std alloc core
190f186 verifier: add embedding policy hooks
a90688b vm: add safe owned external regions
19a2b46 tests: cover public embedding behavior
4bc990b api: add embedding execution adapters
ffdbee3 api: add typed instruction builder
2a39d7d ci: cover Windows interpreter builds
e60b901 docs: plan embedding parity work
d4f7224 docs: audit rbpf feature parity
```

Current capability checkpoint:

- Explicit no-data/raw/caller-metadata/XDP input adapters, configurable
  caller/fixed packet metadata, transactional program replacement, and the
  typed fluent instruction builder are complete.
- Owned RO/RW external regions use opaque virtual guest addresses, have typed
  verifier helper returns, retain runtime bounds/permission checks when
  unverified, participate in snapshots, and agree across interpreter/JIT.
- `verify_with_policy` runs application policy only after core verification
  and keeps `Core` versus `Policy` rejection distinct.
- `std` and `jit` are separate features. `--no-default-features` is the true
  `no_std + alloc` core; portable interpreter-only builds use
  `--no-default-features --features std`.
- Native Windows interpreter CI, wasm `std` interpreter checks, and a true
  `thumbv7em-none-eabihf` no-std target are configured.
- The pinned production corpus remains 62/62 loaded and verified, with no
  measured map/helper/load/verifier blockers.
- Deprecated packet loads are explicit profiles, disabled by default: Linux
  B/H/W semantics and rbpf 0.4.1 B/H/W/DW compatibility are implemented across
  assembler/disassembler, verifier, interpreter, hybrid JIT, CLI, replay, and
  native/browser debugging. Replay stores only an address-free profile tag and
  packet bytes.
- The pinned rbpf Cranelift audit is complete. Its x86-64 Linux suite measured
  134 passed and 2 ignored. It is an alternative backend, not an observed
  febpf capability gap; additional host reach is unknown, and the audited
  backend has atomics, tail-call, and local-call gaps.

Validation at this tip:

- Default JIT: `cargo test --all-targets` — **382 passed + 4 ignored**.
- `std` interpreter-only:
  `cargo test --all-targets --no-default-features --features std` —
  **365 passed + 4 ignored**.
- Strict clippy is green with
  `cargo clippy --all-targets -- -D warnings` and
  `cargo clippy --all-targets --no-default-features --features std -- -D warnings`.
- True no-std checks are green:
  `cargo check --lib --target thumbv7em-none-eabihf --no-default-features` and
  `cargo clippy --lib --target thumbv7em-none-eabihf --no-default-features -- -D warnings`.
- CI also builds/clippies wasm with `--no-default-features --features std` and
  builds/tests/clippies the same interpreter-only configuration on Windows.

Honest remaining differences and follow-ups:

- Owned external regions do not provide rbpf-style live, zero-copy aliases to
  arbitrary host memory. Borrowed execution-scoped regions are deferred until
  a real use case justifies their lifetime API.
- Replay files do not serialize external regions. Any future support must
  capture explicit bytes or report unavailable input, never host addresses.
- The legacy live-kernel socket-filter differential passed as root on this
  Linux 7.0.0 host: ABS W, IND H/B, exact-end, network byte order, and OOB
  implicit-zero behavior agree with the interpreter and hybrid JIT. Preserve
  its 14-byte Ethernet-header prefix: TEST_RUN consumes it before invoking the
  socket filter.
- Universal native-target dominance is not claimed: rbpf Cranelift reach
  beyond its measured x86-64 Linux suite remains unknown.
- Arbitrary custom-only verifier replacement is intentionally not presented
  as verification. Callers may apply their own callback before deliberately
  running unverified; runtime virtual-memory checks still apply.

Immediate resume action after this docs-only commit: pause for user direction.
Preserve the qualified claim language in `docs/specs/rbpf-feature-parity.md`.
Historical sections below predate the `std`/`jit` split; use the feature
commands in this active checkpoint rather than their old command examples.

## What this is

**febpf** is a from-scratch, **zero-dependency** userland eBPF engine in Rust.
It was built as a "fun challenge" for the user (ayourtch@gmail.com) starting
2026-07-10. It is not a wrapper around the kernel or any library — the ISA
decoder, verifier, interpreter, JIT, assembler, and ELF loader are all
hand-written. `Cargo.toml` has **no dependencies** and that is a deliberate,
load-bearing constraint. Don't add any without a very good reason and the
user's OK (raw Linux syscalls via `asm!` are used instead of libc — see the
JIT's `sys` module).

Everything works today: the full default-feature suite is **330 green + 4
intentional heavy soundness sweeps ignored**; `--no-default-features` is **316
green + the same 4 ignored** (2026-07-12, after map-in-map support).
`cargo clippy --all-targets -- -D warnings` is clean in both configs. **Keep
BOTH configs green** — the JIT is now behind `default = ["jit"]`, so always
run `cargo test` AND
`cargo test --no-default-features` (and clippy in both) before calling
anything done.

## LATEST (2026-07-12): the current pinned real-world corpus is 57/57

**START HERE.** The immediate goal is real-world breadth: support the eBPF code
people actually run before spending time on esoterica. The current gentle,
pinned corpus is **57/57 loaded and 57/57 verified**, including a static
tail-call graph and `ARRAY_OF_MAPS`. That is 100% of this corpus, **not a claim
that febpf supports 100% of all eBPF in the wild**. The next useful move is to
widen the pinned corpus with another representative production project or
feature lane, scan it, and implement the highest-impact measured blocker. Keep
program graphs visible as graphs in the report rather than flattening them
into misleading object counts.

**DONE (2026-07-12): real-world program graphs / tail calls.**
`docs/specs/tail-calls.md` is the contract. The userspace-populated path is
implemented: `MapKind::ProgArray`, helper #12 verifier rules, independently
verified targets sharing maps, interpreter hit/miss/cycle/33-chain semantics,
snapshot/debugger program identity, optional v1 replay bundle section, hybrid
JIT-to-JIT dispatch, and `kbpf::KernelProgram::link_tail_call` for real
program-fd population plus a privilege-gated differential. Static BTF `.maps`
`values[]` relocations now produce automatic multi-program ELF/CLI bundles;
interpreter, JIT, analyze, record/replay, and conftest consume them. The pinned
corpus includes Cilium v0.21.0's sparse program-array loader fixture and the
scanner reports program graphs separately. The static ELF regression passed
against the real kernel as root: the entry and target loaded, the program fd
populated the real program array, and `BPF_PROG_TEST_RUN` returned 42. The
complete upstream Cilium object also contains `ARRAY_OF_MAPS`; that next
measured blocker is now implemented too (see below).

**DONE (2026-07-12): `ARRAY_OF_MAPS`, selected by the corpus.**
`docs/specs/map-in-map.md` is the contract. Map definitions carry an explicit
inner-map template and sparse map identities; outer lookup produces a nullable
typed map pointer, and verifier null refinement turns it into the template map
type for nested helper calls. Static BTF `values[]` relocations, dependency-
ordered kernel creation with `inner_map_fd`, userspace population, snapshots,
replay v1 optional tag `0x0b`, interpreter, and JIT are covered. Root kernel
differentials passed both nested lookup and the combined static ELF fixture.
The unchanged pinned Cilium v0.21.0 `testdata/btf_map_init.c` now loads,
verifies, and returns 42 under interpreter and JIT; its focused corpus scan is
100% loaded/verified and reports one static tail-call graph.

**DONE (2026-07-12): scalar identity closes the refreshed corpus.**
`docs/specs/scalar-identity.md` records the soundness invariants. BCC `ksnoop`
copies a derived size, masks and bounds-checks one copy, then applies the same
mask to the original before `perf_event_output`. Register/spill equality ids
and interned deterministic expression ids now propagate that proof without
weakening helper bounds. A mismatched-mask regression remains rejected. The
refreshed cached corpus is **57/57 loaded and 57/57 verified (100%)**, with no
unsupported map types, unknown helpers, load failures, or verifier rejections.
The current host kernel rejects a minimal version of this safe pattern after
dropping the id at the first mask; febpf's acceptance is a deliberate,
soundly-tested precision extension, not kernel-verdict parity.
The complete root conformance suite remains green: 500 accepted-program
runtime differentials and 1,000 verifier-frontier verdicts agree with the
kernel, alongside the XDP, tail-call, and map-in-map differentials.

This is the current tip and the context a fresh agent is most likely to need.
The work is committed linearly on `main`:

```
2b4f739 verifier: track scalar expression identities
a63e66e maps: support static array-of-maps
8e8978e tests: cover tail-call graphs in JIT
5271ebd docs: record kernel tail-call validation
3f35b5a tailcall: load static ELF program graphs
b32fe13 tailcall: add verified program bundles
261e156 tests: make fixture regeneration explicit
3061e49 xdp: differential test-run against kernel
```

To choose the next production-coverage batch, first build the binary the scan
actually uses, then rescan the existing cache:

```
cargo build --release
./scripts/fetch-corpus.sh --offline
NO_BUILD=1 FEBPF=target/release/febpf ./scripts/scan-corpus.sh
```

When widening the corpus, pin tags/commits, keep fetching shallow and gentle,
and document the new lane and its blockers in `docs/specs/corpus-tooling.md`.
Do not add a dependency to solve corpus tooling or core-engine work without the
user's explicit OK.

The old Claude worktree `.claude/worktrees/agent-aee527c2832b79ec3` was
successfully rescued: its two commits were rebased onto `main`, validated, and
integrated. Its branch still points at `426ea87`; it is no longer ahead of
`main` and contains no unique work.

### Exhaustive verifier-operator soundness (DONE)

`src/soundness.rs` runs the production 64-bit tnum/scalar/branch operators on
exhaustively enumerable small windows placed at low, u64 top, i64/i32 sign,
and u32 truncation boundaries. The exact obligation and inventory are in
`docs/specs/operator-soundness.md`. Default tests stay fast; four larger w=8/
w=4 sweeps are ignored and run with:

```
cargo test --release -- --ignored soundness
```

The first run found and fixed three real bugs, each with program-level
regressions in `tests/integration.rs`: signed JMP32 decisions/refinement were
using zero-extended bounds, ALU32 signed div/mod constant folding used i64
semantics, and `Scalar::sync()` was not idempotent. `sync()` now reaches a
fixpoint; signed JMP32 uses a sign-extended view and maps refinement back.

### XDP verifier model (DONE, first useful slice)

Read `docs/specs/xdp-packet-access.md` before extending this. `Config::xdp`
turns `r1` into a read-only `struct xdp_md` context: u32 loads at offset 0/4
produce `PtrKind::Packet { range }` and `PtrKind::PacketEnd`. Packet pointers
start with range 0. Unsigned relational comparisons against data_end refine
the safe successor with the exact proven prefix; the proof propagates through
register aliases and stack spills. Loads/stores must fit entirely in that
prefix. Inclusive/strict forms and both operand orders are handled.

Runtime packet bytes live in a dedicated `Region::Packet` using the normal
`handle << 32 | offset` safety model. Never put host packet pointers in guest
registers. Because the kernel ABI exposes `xdp_md.data`/`data_end` as u32 but
febpf handles are 64-bit, verified XDP ctx loads synthesize the full virtual
addresses at the interpreter load boundary. `Vm::prepare_xdp()` installs a
packet for debugger/replay use; `Vm::run_xdp(&mut packet)` runs it and copies
packet writes back. Packet backing is included in `Snapshot`, so reverse
execution rewinds packet writes as well as ctx/maps/stack.

Known limitation: XDP execution is interpreter-only. The CLI rejects
`--jit` clearly; JIT support needs the XDP ctx-load synthesis represented in
the JIT path. This is a performance limitation, not a verifier/runtime gap.

### ELF, raw packet and pcap CLI (DONE)

`LoadedProgram::xdp` recognizes entry sections named exactly `xdp` or
`xdp/*`; the CLI automatically verifies them with XDP rules. `--packet` also
selects XDP for assembler/raw programs. Examples:

```
febpf verify program.bpf.o
febpf run --packet frame.bin program.bpf.o
febpf run --pcap traffic.pcap program.bpf.o
```

`src/pcap.rs` is a zero-dependency classic-pcap parser: both byte orders,
micro/nanosecond timestamp magics, strict truncation/snaplen checks, explicit
pcapng rejection. One VM is reused across capture records so maps persist.
The CLI prints packet index/timestamp/length and named XDP verdicts
ABORTED/DROP/PASS/TX/REDIRECT. The parser is pure slice code and therefore
WASM-friendly.

### Packet `.febpf` replay and time-travel debugging (DONE)

Replay format version stays **1**: the sectioned format already promises
unknown-tag skipping, so optional tag `0x09 PACKET` was added compatibly.
Presence selects XDP verification/execution; CTX remains the synthetic
24-byte xdp_md image. Existing v1 files without PACKET round-trip unchanged.
Native CLI and playground/WASM replay both reconstruct the packet region.

```
febpf record program.bpf.o --packet frame.bin --stop-at 20 -o packet.febpf
febpf record program.bpf.o --pcap traffic.pcap --packet-index 37 \
  --stop-at 20 -o packet.febpf
febpf replay packet.febpf --run   # reproduce verdict + determinism guard
febpf replay packet.febpf         # open at cursor in time-travel debugger
```

`Replay::record_xdp`, `Replay::build_vm`, `playground::Session::from_replay`,
and `Vm::prepare_xdp` are the load-bearing chain. Tests cover binary
round-trip, reproduced r0, native replay CLI manually, and browser/playground
debugger continuation on the recorded packet.

### Parked web direction: “Wireshark + eBPF”, possibly using oside

The user likes a browser packet workbench: upload XDP `.bpf.o` + pcap, table
of packets/verdicts, protocol tree + hex view, click a packet to time-travel
debug it, export `.febpf`. This is a strong next product/demo direction, but
was explicitly **parked for a second** after investigation.

Candidate decoder: https://github.com/ayourtch/oside (Apache-2.0, same
author), a Scapy-inspired Rust layer stack with Ethernet/VLAN/ARP/IPv4/IPv6/
TCP/UDP/ICMP/DNS/DHCP/GRE/VXLAN/Geneve/etc and Serde-friendly layer output.
Do **not** add current oside directly to febpf core: its Cargo.toml has many
unconditional dependencies (`serde`/`typetag`, `linkme`, rand, host MAC,
crypto/SNMP, tracing...), likely WASM friction, and would violate febpf's
zero-dependency load-bearing constraint. Preferred future shape: refactor
oside upstream into a small decode-only/WASM-friendly feature or crate, then
consume it only in a web companion layer. Especially valuable API addition:
decoded fields should carry byte ranges, enabling protocol-field ⇄ hex bytes
⇄ eBPF load/instruction/branch provenance. Keep febpf and oside separate at
the library boundary.

**DONE (2026-07-11, session 7): aarch64 Linux JIT + CI on all three
platforms.** `.github/workflows/ci.yml` runs the suite, both feature configs,
clippy `-D warnings`, and a **1M-program differential fuzz** (~5s) on
`ubuntu-latest`, `ubuntu-24.04-arm` and `macos-latest`. This matters more than
usual CI: the JIT is the only part of febpf that isn't portable Rust, and each
runner *executes machine code generated for that exact CPU* — a bad encoding
surfaces as a wrong answer, not a compile error. It also finally gives the
**x86-64 backend real execution coverage**, which sessions 5-6 could not (all
that work was done on an arm64 Mac).

- **aarch64 Linux** is now a JIT platform. The A64 encoder was already
  OS-independent, so this was purely an exec-memory layer: `mod.rs` now has one
  module per platform (`x86_linux` / `arm_linux` / `arm_macos`), each exposing
  `alloc_rw` / `seal_rx` / `free`. Watch out for two things — the aarch64
  syscall numbers are *not* x86-64's (mmap=222, mprotect=226, munmap=215), and
  Linux gives you no `sys_icache_invalidate`, so the i-cache flush is written
  out by hand (`DC CVAU` / `DSB ISH` / `IC IVAU` / `DSB ISH` / `ISB`, line
  sizes from `CTR_EL0`).
- **The repo is now clippy-clean under `-D warnings` on every target**, which
  it was not: `kbpf.rs`'s UAPI constants are used only by the x86-64-Linux
  syscall path and read as dead code everywhere else (now gated together in a
  `uapi` module), and the stub `Fd` had no `Drop`, so `drop(fd)` tripped a lint
  off-Linux. Without those fixes CI could not have enforced `-D warnings`, and
  a warning gate nobody can turn on is worthless.
- **CI checks the fixtures survive** (`git diff --diff-filter=D -- tests/`) —
  the regression that destroyed them in session 5 would now fail the build.
  Note Linux CI *explicitly regenerates* the `.o` files with
  `FEBPF_REGENERATE_FIXTURES=1` (its clang can target BPF) while macOS consumes
  them read-only, so only deletions are an error on Linux; on macOS nothing may
  change at all. Both paths get covered, which is why the matrix is worth having.
- No benchmark *gate* — CI runners are far too noisy for timing assertions, so
  `bench` runs informationally only.

**DONE (2026-07-11, session 6): shrank the JIT's trampoline tax ~60%** — the
work §4 flagged as highest-value. Memory-heavy programs went from **0.96×
(slower than the interpreter!) to 1.22×**, and the store+load loop from 1.29×
to 1.60×; pure-ALU is unchanged (~25×). Three parts:
1. **Spill/reload masks** (`classify::deferred_regs`): the glue now moves only
   the registers the interpreter reads/writes. Derived arm-by-arm from
   `Machine::step` — *the interpreter is the spec here*. Two traps the ISA doc
   won't tell you: a helper call **scrubs r1–r5 to zero** (so they must be
   reloaded even though it "only writes r0"), and **`cmpxchg` reads and writes
   r0 implicitly** though r0 is in neither operand field. Unenumerated forms
   fall back to all-registers, i.e. to the old behaviour.
2. **aarch64 register remap**, and this is the load-bearing bit: masks are
   worthless unless the eBPF registers sit in *callee-saved* physical
   registers, or the call destroys them anyway. Session 5's identity map
   (r0..r10 → x0..x10) was exactly wrong for this. Now r0..r9 → **x19..x28**;
   r10 is memory-backed (AAPCS64 has 10 callee-saved regs and eBPF has 11 —
   r10 is read-only, so it is the one to give up).
3. **Fall-through**: loads/stores/atomics/deferred-ALU can only resume at the
   next instruction, so the glue skips the pc→address table lookup and its
   indirect branch. Only CALL/EXIT/`gotol` still need it.

Also fixed, found while doing this: the pc→address table had `n` entries but
the interpreter can legitimately return `pc == n` (a program whose last
instruction is a store or helper call, runnable via `--no-verify --jit`) — the
glue indexed one past the end and branched to whatever it read. **That was a
memory-safety hole in the one component whose whole premise is memory safety.**
The table now has `n + 1` entries, the last pointing at the epilogue.

⚠️ **The x86-64 backend changes were compile-checked, not executed** — sessions
5-6 were done on an arm64 Mac with no x86 machine or container available. The
delta adds *no new byte encodings* (it only omits emissions), and the shared
masks — the genuinely risky part — were validated by 100k differential programs
on aarch64. **Session 7's CI closes this**: `ubuntu-latest` now runs the suite
and a 1M-program fuzz against the real x86-64 backend. If that job is green,
this caveat is discharged; if it is red, look here first.

Validation: `fuzz::gen_mem_program` is new and exists because **`gen_program`
is memory-free** — it emits no deferred instructions at all, so the old 100k-
program fuzz run could not have caught a bad mask. The new generator drives
loads/stores at every width, atomics (incl. `cmpxchg`), helper calls, deferred
ALU and the native `rX = r10` read; `febpf fuzz` alternates both. Note a
differential generator may only call helpers that are deterministic in both
engines — **not `ktime_get_ns`**, which reads the wall clock.

**DONE (2026-07-11, session 5): aarch64 JIT backend** (`src/jit/aarch64.rs`)
— the JIT now runs natively on Apple Silicon, not just x86-64 Linux. The
frontend was genuinely drop-in: the *only* changes outside the new file were a
`#[cfg] mod`, a `compile()` branch, and the `ExecMem` half. Read §5 of
`docs/specs/jit-backend.md` before touching it — it now records what was
actually done (and where the spec's original suggestions were wrong).

Three things worth knowing:
- **Apple Silicon is not "ARM Linux".** Strict W^X means the Linux
  mmap+mprotect dance does not work at all: code must be `MAP_JIT`, writes are
  gated *per-thread* by `pthread_jit_write_protect_np`, and the i-cache must be
  flushed (`sys_icache_invalidate`) or you execute stale bytes. These come from
  libSystem (`macsys` in `jit/mod.rs`) — Darwin has no stable syscall ABI, so
  raw `asm!` syscalls are NOT an option here. This does not break the
  zero-dependency rule: every macOS process links libSystem anyway.
- ~~**eBPF r0..r10 → x0..x10, identity.** The spec suggested callee-saved
  `x19..x29`; that was unnecessary.~~ **This was wrong — session 6 reversed
  it.** The reasoning ("the glue spills/reloads all 11 anyway, so nothing live
  crosses a call") was true but backwards: putting the eBPF registers in
  caller-saved regs is what *forces* the full spill/reload. r0..r9 now live in
  callee-saved x19..x28. The spec was right the first time.
- **`JitBackend::resolve_branches` now returns `Result`** (x64 updated too).
  A64's `B.cond` reaches only ±1MiB, so a program over ~1MiB of emitted code
  can't be encoded; it now fails compilation cleanly (caller falls back to the
  interpreter) instead of panicking or, worse, truncating a displacement into a
  silently-wrong branch. Branch islands would lift the limit — nothing in the
  corpus is remotely close, so it's not worth doing yet.

Validated by the `tests/jit.rs` differential suite plus `febpf fuzz` — **100k
random programs, interpreter and JIT agree on every one** (the generator covers
every native emitter in both widths, reg+imm, all 10 conditions and JSET, so
that is real coverage). Perf on M-series: **~26× on an ALU-heavy loop**
(`sum_loop`: 7.0µs → 0.27µs/run; 425 → 11100 M insn/s) — but see §4, the JIT
*loses* on deferred-heavy code, which is worth understanding before optimizing
anything.

**Two latent macOS bugs fell out of this and are fixed** (both were invisible
on Linux, and both would have bitten anyone who ran the suite on a Mac):
1. **`maybe_compile` in the fixture tests was destroying the repo.** It checked
   only that `clang --version` runs, then invoked `clang -target bpf -o
   tests/X.o`. Apple clang has no BPF backend, so it failed *after* truncating
   the output — silently deleting 10 committed `.o` fixtures on every
   `cargo test`, which then cascaded into ~30 failures that looked
   environmental. It now probes `--print-targets` for real BPF support and
   builds via a temp file that is renamed into place only on success, so a
   failing clang can never damage a fixture. Follow-up: ordinary tests no
   longer invoke it at all. The four copies were consolidated in
   `tests/common/mod.rs`, gated by `FEBPF_REGENERATE_FIXTURES=1`.
2. **`kbpf::has_privilege()` returned `Err` on any non-Linux host.** The stub
   `probe()` reports ENOSYS, and only EPERM/EACCES were mapped to `Ok(false)`
   — so the probe violated the "never panics, always a definite answer"
   contract that `probe_is_well_behaved` asserts. ENOSYS ("no `bpf(2)` on this
   platform at all") is now also a definite `Ok(false)`.

With those fixed, **macOS is at full parity: `cargo test` is 250 green / 240
with `--no-default-features`** — the same counts as the Linux box. Note clippy
on macOS shows 18 dead-code warnings in `kbpf.rs` (the Linux-only `imp` module
is `#[cfg]`'d out, so its constants look unused); that is a platform artifact,
not a regression — it is still 0 on Linux.

**DONE (2026-07-11, session 4): BTF-typed ctx pointers** (kernel
PTR_TO_BTF_ID for `tp_btf`/`fentry`/`fexit`/`fmod_ret` ctx args) — the last
fixable corpus class. `docs/specs/btf-ctx-pointers.md` is the contract; every
rule cites the kernel function it mirrors (`btf_ctx_access`,
`btf_struct_walk`, `check_ptr_to_btf_access`, `convert_ctx_accesses`'
BPF_PROBE_MEM rewrite → `VerifyOk::probe_mem` arms the VM). Runtime adds
`Region::KernelMem` (reads-as-zero, writes fault — virtual-address model
intact), ctx pointer slots prefilled with distinct deterministic addresses.
`Program` gained a `btf_ctx` field (literal constructions everywhere gained
`btf_ctx: None`). Corpus: **100% loads / 98.2% verified (55/56)** — and the
four unblocked tp_btf tools also EXECUTE under interp+JIT. The in-flight
agent from the last checkpoint had died leaving only the btf.rs foundation
uncommitted; it was salvaged, finished, reviewed and committed on main.
Known deliberate divergences + replay-file limitation are in the spec §1/§3.

**CURRENT NEXT OPTIONS:** exhaustive small-width operator soundness, the first
XDP packet-access/pcap/replay slices, and kernel `BPF_PROG_TEST_RUN`
differential validation are DONE (see LATEST above). The kernel is only an
oracle: `conftest --packet` compares both verifier verdicts, then the verdict
and exact output bytes. The user explicitly parked the oside-backed web packet
workbench for now. Good next technical continuations are: XDP JIT ctx-load
support; or another ranked item
from `docs/ideas.md` (extension-mechanism packaging, CI/LSP packaging,
`snapshot-kernel`). Do not silently start the oside integration until the user
unparks it. GPUs remain parked.

Merged earlier (sessions 1–3, all on main): map-types-2 (perf/cgroup/stack
maps, tracing helpers #14–16/#35, get_stackid #27), probe_read family
(#4/#45/#112–115) + task_under_cgroup #37, get_stack #67, kconfig externs,
max_entries default, subprog pointer returns (kernel-exact:
`prepare_func_exit`), rodata DCE (`src/dce.rs`), get_socket_cookie #46 +
get_func_ip #173, scan-corpus helper-name fix.

## The big picture (data flow)

```
   source.s ──asm──┐                    ┌── disasm ──► pseudo-C text
                   ├─► Vec<Insn> ──┬─────┤── analysis ─► CFG/DOT/heatmap/annotated
 clang .o ──elf────┘  + Vec<MapDef>│     └── verifier ─► accept/reject + abstract state
                                   │
                                   ▼
                              Vm::new  (patches map lddw → region addrs into `exec`)
                                   │
                        ┌──────────┴───────────┐
                        ▼                      ▼
                   interpreter        JIT (x86-64 / aarch64)
                   Machine::step      native ALU/branch + trampoline
                        └──────────┬───────────┘   back to Machine::jit_step_at
                                   ▼                for memory/calls/exit
                             r0 / EbpfError
```

## Module map (src/)

| file | lines | what |
|------|-------|------|
| `insn.rs` | ISA v4 opcode constants, `Insn`, decode/encode, `wide_imm` |
| `asm.rs` | assembler for kernel "pseudo-C" syntax; `.map name kind key val entries` (kinds: hash/array/percpu_hash/percpu_array/lru_hash/ringbuf) |
| `disasm.rs` | disassembler (round-trips with asm) |
| `tnum.rs` | tracked-numbers (known-bits) abstract domain, mirrors kernel `tnum.c` |
| `verifier.rs` | the big one: path-sensitive abstract interpreter; rejection explainer; XDP packet/data_end range tracking; per-PC joined abstract state (`pc_regs`/`regs_at`) used by the optimizer |
| `maps.rs` (516) | hash/array + per-CPU array/hash + LRU hash + ringbuf; stable value storage (safety note #5); record capture for ringbuf |
| `helpers.rs` | helper id/name/signature registry + user-helper API |
| `interp.rs` | the VM: `Vm`, `Machine`, virtual-address memory model (including `Region::Packet`), snapshot/restore, multi-instance activate/deactivate, JIT glue |
| `jit/*` | arch-independent frontend + `JitBackend` trait + x86-64 and aarch64 encoders (riscv64 TODO) |
| `elf.rs` (1126) | ELF64 loader + BTF `.maps` + CO-RE relocation application; `map_kind`/`map_type_name` |
| `btf.rs` (1002) | full BTF type graph (all 19 kinds), scales to vmlinux; `.BTF.ext` |
| `relo.rs` (1401) | CO-RE relocation algorithm (libbpf candidate matching) |
| `debuginfo.rs` (356) | `.BTF.ext` line/func info → source-level debugging |
| `kbpf.rs` (382) | raw `bpf(2)` syscall layer (conftest/vfuzz); **attr MUST be `&mut`** |
| `fuzz.rs` (526) | seeded PRNG + program generators (conservative + verification-frontier) |
| `conftest.rs` (310) | `conftest`/`fuzz`/`vfuzz` CLI orchestration |
| `race.rs` (688) | deterministic concurrency race explorer (`febpf race`) |
| `equiv.rs` (463) | observable-equivalence checker (`febpf equiv`) |
| `optimize.rs` (648) | verifier-guided, equivalence-checked optimizer (`febpf optimize`) |
| `replay.rs` | `.febpf` shareable replay-file container, including optional XDP PACKET input |
| `pcap.rs` | zero-dependency classic-pcap parser used by the XDP verdict harness |
| `analysis.rs` | CFG, DOT export, stats, annotated listing, heatmap (source-aware) |
| `debug.rs` (1301) | debugger REPL: breakpoints, time travel (rstep/rcontinue/goto), watchpoints, dataflow queries (origin/when/who), source stepping |
| `playground.rs` (517) / `wasm.rs` (193) | pure-std playground API + hand-written WASM ABI (no wasm-bindgen) for `web/` |
| `main.rs` (850) | CLI |

Line counts are approximate (they drift); the point is the shape. Specs live
in `docs/specs/` — one per subsystem (jit-backend, elf-loading, core-relocations,
time-travel-debug, verifier-explainer, source-debug, conftest, verifier-diff,
wasm-playground, dataflow-queries, replay-files, equiv-optimizer, race-explorer,
map-types, corpus-tooling, btf-ctx-pointers). **Read the relevant spec before extending a
subsystem** — they encode the contracts and gotchas.

## Load-bearing design decisions (the non-obvious stuff)

### 1. Virtual-address memory model — this is the whole safety story
eBPF pointers in the interpreter are **not host pointers**. They are
`region_handle << 32 | offset`. Every load/store goes through
`resolve_slice()` in `interp.rs`, which looks up the region (ctx / one stack
per frame / map object / map value) and does an O(1) bounds check. Result: even
`--no-verify` can't cause UB — a wild access is a clean `EbpfError`, never a
segfault. **Never** break this by putting a real pointer in a guest register.
The JIT preserves it by *deferring* all memory ops to the interpreter (see #4).

### 2. `Vm` keeps two instruction arrays: `insns` and `exec`
- `insns` = as loaded (map `lddw` pseudo-instructions intact). The **verifier**
  and disassembler see this.
- `exec` = map `lddw` patched to concrete region addresses. The **interpreter
  and JIT** run this.

Verifying the *patched* array silently breaks map-pointer typing. This bit me
during initial development; keep the split. (Same pattern: `user_helpers` and
`jit` are `Option`-taken out of `Vm` during a run to satisfy the borrow
checker — see `run_jit`.)

### 3. Verifier state pruning needs care or it blows up
DFS over branch states with subsumption pruning at join points
(`prune_points`). Two things that took debugging:
- `max_states_per_pc` default is **4096** (a ring buffer). A small cap breaks
  pruning under DFS and causes exponential blowup.
- There's a **miss-streak backoff**: after 256 consecutive non-pruning
  arrivals at a point, only scan every 64th. Without it, a loop that mints a
  fresh constant each iteration made the "program too complex" rejection take
  ~134s instead of ~2s. See `PruneList` in `verifier.rs`.

`MapValueOrNull` pointers carry a unique `id` so a null check refines **every**
copy of the pointer, including ones spilled to the stack.

### 4. The JIT is a hybrid, and that's what keeps it safe
Only **ALU + branches** are compiled to native code. Everything else — loads,
stores, atomics, `lddw`, helper calls, bpf-to-bpf calls, `exit` — is
**deferred**: the native code spills registers, calls `Machine::jit_step_at`
(the same interpreter, one instruction), and resumes at whatever pc it returns.
So the JIT cannot introduce memory-unsafety the interpreter doesn't already
prevent; it only removes dispatch overhead.

**The hybrid still has a performance gradient — know it before you "optimize"
the JIT.** Every deferred instruction pays a trampoline round-trip, so the win
tracks the **fraction of executed instructions that are deferred** (M-series,
aarch64; x86-64 differs in magnitude, not in shape):

| executed instruction | cost under interp | cost under JIT |
|---|---|---|
| native (ALU/branch)  | ~2–4 ns | **~0.12 ns** |
| deferred (mem/call)  | ~4.3 ns | **~5.3 ns** (was ~6.7) |

- ~0% deferred (`sum_loop`): **~25× faster**
- ~40% deferred (store+load loop): **1.6×** (was 1.29×)
- ~67% deferred (memory-saturated): **1.22×** (was 0.96× — the JIT *lost*)

Session 6 cut the tax ~60% (details below), moving break-even from ~40-50%
deferred to **~80%**, so realistic map/packet-heavy programs now sit
comfortably in the winning region. It is no longer easy to construct a program
where `--jit` loses, but a pathological one (nearly all memory ops) would still
only break even — the trampoline cannot be cheaper than the interpreter's own
dispatch of the same instruction.

What made it faster, and what is left:
- **Spill/reload masks** (`classify::deferred_regs`): move only the registers
  the interpreter actually reads/writes, not all 11. This *only pays off if the
  eBPF registers live in callee-saved physical registers* — otherwise the call
  destroys them anyway. That is why aarch64 maps r0..r9 → x19..x28; x86-64 has
  too few callee-saved registers and must always carry r0..r5.
- **Fall-through**: a load/store/atomic/ALU can only continue at the next
  instruction, so the glue skips the pc→address table lookup and its indirect
  branch entirely. Only CALL/EXIT/`gotol` still need the table.
- **Still on the table**: the remaining ~1 ns tax is the call itself plus
  `Machine::step`'s re-decode of the instruction (it re-reads the opcode,
  re-checks `insn_count`, the profile hook, bounds). A specialized entry point
  that skips the re-decode could shave more. Compiling loads natively would be
  faster still but forfeits the memory-safety story (see above) — don't.

The frontend (`jit/mod.rs`, `classify.rs`) is architecture-independent; the
backends (`x64.rs`, `aarch64.rs`) are pure encoders implementing `JitBackend`.
**To add riscv you implement that trait and nothing else** — the whole point of
the split, done at the user's request, and adding aarch64 (session 5) confirmed
it holds: no eBPF logic moved. `docs/specs/jit-backend.md` is the step-by-step.
Gotchas written down there, each of which has already bitten once: 16-byte
stack alignment at call sites (the first x86 JIT segfault — 6 callee-saved
pushes misaligned it; it's now 5), instruction-cache flush + `MAP_JIT` write
gating on ARM (x86 needs neither), literal pools for absolute addresses (no
`movabs` outside x86), and short branch displacements (A64 `B.cond` is ±1MiB,
so `resolve_branches` returns `Result` — never truncate a displacement).

### 5. `maps.rs` value storage is stable on purpose
Array maps use one flat allocation; hash maps use a slab of boxed values with a
free-list. Values are never moved while present, so a map-value pointer handed
to the program stays valid. Deleted hash entries are tombstoned/reused, never
freed — mirrors the kernel's RCU-grace-period semantics (a stale pointer reads
recycled memory, never unsafe).

### 6. Global data sections (added 2026-07-10, session 2)
`.data`/`.bss`/`.rodata*` sections load as **single-entry array maps**
(libbpf's internal-map model): `MapDef` gained `init: Vec<u8>` (section
contents, `.bss` zero-fills) and `readonly: bool` (`.rodata*` frozen).
Things that will bite you if you forget them:
- clang does NOT put everything in plain `.rodata`: const tables land in
  `.rodata.cst16` (SHF_MERGE) and string literals in `.rodata.str1.1`
  (SHF_MERGE|SHF_STRINGS). Match by `.rodata` **prefix**.
- Data relocations are section symbols (value 0) with the **addend stored in
  the lddw's imm field**; final value offset = `sym.value + imm`. Lowered to
  `pseudo::MAP_VALUE` (imm = map idx, second imm = offset) — the runtime
  patching for that already existed in `Vm::new`.
- read-only is enforced **three times deliberately**: verifier store path
  (`check_mem_access`), verifier helper check (update/delete on frozen map),
  and the runtime (`resolve_slice` takes `write: bool`). The runtime check is
  what keeps `--no-verify` and the JIT honest (JIT defers all memory ops).
- asm syntax grew `.map name kind key val entries [ro]` and
  `rX = map[name][0] + off` (direct value pointer) to make this testable
  without ELF fixtures.
- `Map::update/delete` on frozen maps return `-EPERM` (-1), like the kernel.

### 7. Determinism
`get_prandom_u32` is a fixed-seed xorshift; hash maps never move values. So a
buggy program replays identically under the debugger. Keep it that way.

## Toolchain notes for this environment
- `clang` (21.x) and `bpftool` **are installed**. `llvm-objdump` may not be on
  PATH (user installed it but it didn't show up last I checked — verify with
  `which llvm-objdump`).
- ELF tests consume committed `.o` fixtures and never rewrite them by default.
  If you change the C, regenerate with
  `FEBPF_REGENERATE_FIXTURES=1 cargo test` using a BPF-capable clang. The shared
  helper preserves `-O0` for `subprog.c` so the cross-`.text` call is not
  inlined away.
- Do not run a repository-wide `cargo fmt` on this host: the installed
  rustfmt/toolchain combination reformats unrelated files. Format only files
  intentionally touched and inspect the diff.
- Root conformance was run through the user's TTTT `pty-3`. If that shell is
  still available, its root PATH does not include Cargo; use
  `CARGO_HOME=/home/ayourtch/.cargo RUSTUP_HOME=/home/ayourtch/.rustup
  CARGO_TARGET_DIR=/tmp/febpf-root-target /home/ayourtch/.cargo/bin/cargo ...`.
  Keep root-owned build artifacts out of the checkout.
- `Date.now()`/randomness are fine here (this is a normal shell, not a workflow
  sandbox). The scratchpad dir is session-specific — use whatever the current
  session's system prompt says.
- **Next session may be on the user's aarch64 Mac Mini** (they plan to check
  out the repo there for the arm64 JIT backend). Expect macOS: `mmap`/`mprotect`
  via raw syscalls differ (no `asm!` Linux syscall ABI — macOS needs libc or
  its own syscall numbers AND `MAP_JIT` + `pthread_jit_write_protect_np` for
  W^X), plus `sys_icache_invalidate` for i-cache flush. The `JitBackend` trait
  split means x64.rs stays untouched; budget real time for the exec-mem layer,
  not just the encoder.

## Agent-orchestration lessons (session 3 — these all actually bit me)

- The user likes the pattern: delegate well-scoped corpus batches to parallel
  worktree agents; SEQUENCE anything touching `verifier.rs` (two parallel
  batches once "fixed" the same subprog-return rule differently — the
  kernel-exact version won). Review every verifier diff personally before
  merging; the soundness bar is "cite the kernel rule you mirror".
- The Bash shell's `cd` into a worktree PERSISTS across commands: a `git
  merge` once silently ran inside the agent's worktree ("Already up to date")
  instead of main. Always `cd /home/ayourtch/rust/febpf` first or check
  `git worktree list` output paths.
- `tests/*.o` fixtures: clang `-g` embeds the compilation directory, so an
  explicit regeneration inside a worktree differs byte-wise from a main-checkout
  build. Commit fixture `.o` files ONLY from the main checkout; ordinary tests
  are read-only and should produce no fixture churn.
- After merging an agent branch: run both test configs + clippy FROM MAIN,
  `cargo build --release` (the corpus scan uses the release binary), rescan,
  then `git worktree remove --force <path>` + delete the branch.
- Historical note: the old pinned ksnoop object was a correct kernel-parity
  rejection. The refreshed object now verifies via febpf's deliberately more
  precise scalar-expression identity; preserve the distinction documented
  under Production coverage and in `scalar-identity.md`.
- Strategy/roadmap ponderings live in `docs/ideas.md` (user endorsed the
  ranking there); don't re-litigate direction, extend it.

## How to verify you haven't broken anything
```
cargo test --all-targets
cargo test --all-targets --no-default-features
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --no-default-features -- -D warnings
cargo build --release
./target/release/febpf bench examples/sum_loop.s --iters 50000 --jit   # ~11 GIPS
cargo test --release -- --ignored soundness     # optional heavy verifier sweep
```
Latest host result after tail calls, map-in-map, and scalar identity:
default **328 passed / 4 ignored**; no-default-features **314 passed / 4
ignored**; both strict clippy invocations are clean, as is the release build.
The complete privileged conformance suite is also green: 500 runtime
differentials, 1,000 verifier-frontier verdict comparisons, and the XDP,
tail-call, and map-in-map differentials. Ordinary tests do not regenerate
tracked `tests/*.o`; any fixture diff
without `FEBPF_REGENERATE_FIXTURES=1` is now a regression. Explicitly generated
objects can still differ by clang version and compilation path. Never delete or
blindly rewrite user changes.
The **differential tests are the safety net**: `tests/jit.rs` and the
`jit_matches_interpreter_on_objects` test in `tests/elf.rs` run programs under
both interpreter and JIT and require identical results. If you touch codegen,
these catch encoding bugs. Add more programs to the `programs()` list in
`tests/jit.rs` when you add native opcodes.

## "Wow" feature shortlist (user asked for these — things people wish existed)

Ranked by wow-per-effort. Each builds on something we already have, which is
what makes them feasible here when they aren't elsewhere:

1. **Time-travel debugging** — **DONE 2026-07-11** (`docs/specs/time-travel-debug.md`):
   `rstep`/`rcontinue`/`goto` + data watchpoints (raw addr and logical map+key),
   10k-step checkpoints, snapshot must include region table + per-map region
   handles (lazy allocation order matters on replay). Warns once if
   non-deterministic helpers were called.
2. **Verifier rejection explainer** — **DONE 2026-07-11**
   (`docs/specs/verifier-explainer.md`): counterexample trace on rejection
   (annotated disasm of the failing path, per-step abstract state, cause notes
   like "r0 may be NULL: returned by map_lookup_elem at insn 6"). On by
   default, `--no-explain` to suppress. Path arena during DFS + replay on
   rejection; pruning machinery untouched.
3. **Source-level debugging** — **DONE 2026-07-11** (`docs/specs/source-debug.md`):
   `.BTF.ext` line/func info surfaced via `src/debuginfo.rs` (clang embeds the
   source text — no .c needed): debugger shows the C line, `list`,
   `steps`/`nexts`/`rsteps` (source-line stepping, incl. reverse), `bt`
   backtraces with function names, `print <global>` typed via the BTF graph;
   source interleaved into disasm/heatmap/analyze. Watch the `.text`-stitching
   offset (`text_base`) — same trap as CO-RE relocs.
4. **Kernel conformance mode** — **DONE 2026-07-11** (`docs/specs/conftest.md`):
   `febpf conftest` (interp+JIT+kernel via raw bpf(2), exit codes 0/1/2/3 =
   agree/mismatch/no-priv/kernel-reject) and `febpf fuzz [--seed N] [--kernel]`
   (seeded differential fuzzer; already caught a real generator bug).
   `src/kbpf.rs` attr offsets verified against kernel headers, and the full
   kernel differential validated as root on this host 2026-07-11 (10k fuzz
   programs + gated tests all agree — after fixing a real harness miscompile:
   the TEST_RUN retval write-back needs the attr passed as `&mut`, see
   `kbpf::call`).
5. **WASM playground** — **DONE 2026-07-11** (`docs/specs/wasm-playground.md`):
   JIT now behind `default = ["jit"]` feature (keep BOTH configs green:
   `cargo test` and `cargo test --no-default-features`). `src/playground.rs`
   (pure-std API) + `src/wasm.rs` (hand-written ABI, no wasm-bindgen) +
   `web/`: `cd web && make` → self-contained `web/dist/` for any static
   server. Verified without a browser via wasmi harness (`web/test/`).
6. **CO-RE relocations** — **DONE 2026-07-11** (`docs/specs/core-relocations.md`):
   full BTF type graph in `src/btf.rs` (all 19 kinds, validated byte-exact
   against `bpftool btf dump` on vmlinux, 168k types ~56ms), `.BTF.ext`
   parsing (core_relo semantic; func/line_info stored for future #3), the
   libbpf matching algorithm in `src/relo.rs` (13 relo kinds, flavors,
   ambiguity rules), load-time patching with libbpf-style `0xbad2310`
   poisoning of unresolved relos. CLI: `--target-btf <path>`, defaults to
   /sys/kernel/btf/vmlinux. Differentially validated against bpftool and the
   running kernel.

### Second wow tier (all DONE 2026-07-11) — built on the deterministic replay + kbpf

7. **Omniscient debugging (dataflow queries)** — `docs/specs/dataflow-queries.md`.
   Debugger commands `origin <reg>` (recursive def-use trail to where a value
   was born: constant/ctx/map-load/helper-return), `when <reg>`, `whenwrite
   <addr|reg>` (alias `ww`), `who <addr|reg>`. No eager recording: rebuilds a
   lightweight write-log on demand by restoring the nearest checkpoint and
   replaying to the cursor (`DebugSession::build_write_log` +
   `Machine::describe_addr`). Bounded to one replay interval — defs older than
   the nearest checkpoint report "not written in this interval" (next step:
   cross-interval `origin`). Atomic-STX destinations not yet followed.
8. **Shareable replay files** — `docs/specs/replay-files.md`. `febpf record
   <prog> [--stop-at N] -o bug.febpf` + `febpf replay bug.febpf` (opens the
   time-travel debugger at the cursor, or `--run` reproduces r0). Versioned
   hand-written container (`src/replay.rs`, magic `FEBPFRPL`, no serde);
   determinism guard records expected r0 and warns on divergence. `from_bytes`
   grows vecs per bounds-checked element — do NOT reintroduce
   `Vec::with_capacity(untrusted_count)` (that was a real multi-GB-alloc DoS
   the corruption fuzz test caught). Playground/WASM entry `febpf_dbg_replay`
   opens a `.febpf` in the browser. **Extended for XDP:** optional v1 PACKET
   section; raw frame or selected pcap record reopens with data/data_end and
   packet mutations intact in native and playground time-travel debuggers.
9. **Verifier differential fuzzing** — `docs/specs/verifier-diff.md`. `febpf
   vfuzz [--frontier|--conservative] [--kernel]` diffs febpf-verifier vs
   kernel-verifier *verdicts* (not just execution). Four cells; the
   **FEBPF-LAX** cell (febpf accepts / kernel rejects = a soundness gap) is
   dumped loud + first with disasm + kernel log. FEBPF-STRICT (kernel stricter)
   is expected in bulk, reported separately. New bpf(2) surface `kbpf::verdict`
   keeps the `&mut` attr provenance. Root run against a live kernel
   (2026-07-11) initially found 2407/20000 FEBPF-LAX in two classes, both now
   FIXED (see below) — a re-run is 0 FEBPF-LAX / 0 FEBPF-STRICT, i.e. febpf's
   verifier verdict matches the kernel's on every one of 20k frontier
   programs. `vfuzz --kernel` is the regression check; keep it at 0 LAX.

### Verifier hardened to kernel conformance (2026-07-11, via #9)
`fix/verifier-conformance` closed the two gaps vfuzz found — both were febpf
being *more permissive* than the kernel (conformance gaps, not memory-unsafety,
since febpf's virtual-address model is safe regardless):
- **Modified ctx-ptr deref**: the kernel requires a `PTR_TO_CTX`'s own
  accumulated offset to be 0 at dereference — the access offset must come from
  the load/store instruction immediate, never from pointer arithmetic baked
  into the register. `check_mem_access` now rejects a ctx deref when the
  pointer's `p.off != 0` or `p.var` is non-zero/non-const (keying on the
  POINTER's offset, NOT the total access offset — that distinction is what
  keeps `*(u32*)(r1+8)` legal while rejecting `r2=r1; r2+=8; *(u32*)(r2+0)`).
- **Stack alignment**: the kernel *always* enforces natural alignment on
  `PTR_TO_STACK` accesses (size-N access must be N-aligned), independent of the
  `--strict-align` policy that governs ctx/map/packet. febpf now enforces stack
  alignment unconditionally; the helper-buffer path is exempted (helper args
  pass a byte length as `size` with no alignment constraint).

### Third wow tier (2026-07-11) — built on deterministic replay + the verifier

10. **Omniscient debugging (dataflow queries)** — `docs/specs/dataflow-queries.md`.
    Debugger `origin <reg>` (def-use trail to where a value was born), `when`,
    `whenwrite`/`ww`, `who <addr>`. Rebuilds a bounded write-log on demand from
    the nearest checkpoint (no eager recording). Limited to one replay interval.
11. **Shareable replay files** — `docs/specs/replay-files.md`. `febpf record ->
    bug.febpf`, `febpf replay` (opens the time-travel debugger at the cursor, or
    `--run`). See `src/replay.rs` DoS note above.
12. **Verifier differential fuzzing (vfuzz)** — see #9 / verifier-conformance.
13. **Deterministic race explorer** — `docs/specs/race-explorer.md`. `febpf race
    <prog> --procs N` runs N instances sharing one map set, enumerates
    interleavings at map-op granularity, flags lost-update / stale-RMW /
    outcome-divergence, and emits the losing interleaving as a replayable
    `--schedule` vector. Also in the web playground (`febpf_race`, its own panel).
14. **Verified performance optimizer** — `docs/specs/equiv-optimizer.md`. `febpf
    equiv <a> <b>` decides *observable* equivalence (r0 + final map state +
    ordered helper effects — NOT just r0), via the verifier's joined per-PC
    abstract state plus differential falsification. `febpf optimize` applies
    verifier-gated sound rewrites (const-fold, dead-branch, strength-reduction,
    algebraic identity, redundant-mask), then runs `equiv` on its own output and
    REFUSES to emit if it can't prove behavior was preserved.

### Production coverage — the corpus-driven loop (START HERE for "is it useful?")
`scripts/fetch-corpus.sh` (gentle, pinned, cached) builds 57 real `.bpf.o`
from bcc libbpf-tools + libbpf-bootstrap using local clang + bpftool + kernel
BTF. `scripts/scan-corpus.sh` runs febpf over them and prints a ranked
histogram of the exact map types / helpers blocking the most real programs.
`corpus/` is gitignored. This is how we pick what to build next — MEASURE, don't
guess (it already corrected a wrong guess: ringbuf mattered less than
PERF_EVENT_ARRAY for this corpus). Coverage progression (loads / verifies):
- baseline (hash+array only): 23% / 3.6%
- + ringbuf/per-CPU/LRU (`docs/specs/map-types.md`): 30% / 5.4%
- + perf/cgroup/stack maps + tracing helpers (`map-types-2.md`): 92.9% / 30.4%
- + probe_read family + task_under_cgroup (`tracing-helpers.md`): 92.9% / 67.9%
- + get_stack (#67) + kconfig externs + missing-max_entries default + subprog
  pointer returns (batch appended to `tracing-helpers.md` / `elf-loading.md`):
  100% / 78.6%. Zero load failures remain.
- + load-time rodata DCE (`rodata-dce.md`), merged on top of the above:
  100% / 89.3% (50/56). The two parallel batches' fixes compounded
  (each measured 78.6% alone).
- + get_socket_cookie (#46) + get_func_ip (#173) + ksnoop verdict-parity
  investigation (appended to `tracing-helpers.md`): 100% / 91.1% (51/56).
  Also tightened subprog stack-pointer returns back to the exact kernel rule
  (reject ANY stack pointer, `prepare_func_exit()` conservatism) — the
  caller-frame allowance from the load-failure batch was laxer than the
  kernel and would have shown up as FEBPF-LAX in `vfuzz --kernel`.
- + BTF-typed ctx pointers (`btf-ctx-pointers.md`): **100% / 98.2%** (55/56).
  bitesize/offcputime/runqlat/runqslower unblocked AND running. The one
  remaining rejection in that historical corpus pin was ksnoop and matched
  the host kernel; the next refreshed-corpus entry explains what changed.
- + tail-call program graphs, static `ARRAY_OF_MAPS`, and sound scalar
  expression identity (`tail-calls.md`, `map-in-map.md`,
  `scalar-identity.md`): **100% / 100% (57/57)** on the refreshed corpus. The
  scanner reports one static tail-call graph separately.
**Workflow: merge a coverage batch → `./scripts/scan-corpus.sh` → the histogram
names the next batch.** febpf is an analysis/test/CI/debug engine, NOT a datapath
runtime — "production useful" means verify/explain/differential-test/debug real
programs, not attach-and-run in the kernel.

Two gotchas learned running this loop (2026-07-11): the scan uses
`target/release/febpf`, so `cargo build --release` BEFORE scanning or you
measure the previous build; and helper names in the histogram come from the
uapi header now — the old hardcoded table had wrong ids (#113 was labelled
ringbuf_output; it is probe_read_kernel).

The refreshed BCC `ksnoop` now verifies because febpf tracks copied and
recomputed scalar-expression identity. Important nuance: this is not kernel
verdict parity on the current host. That kernel drops the relevant identity at
the first mask and rejects even the minimized safe pattern; febpf retains the
proof under the deliberately narrow, regression-tested rules in
`scalar-identity.md`. Preserve the mismatched-mask rejection and the exhaustive
kernel-frontier checks when changing this logic.

## Known limitations / where to go next (roughly prioritized)

1. **Broaden production coverage** — add another pinned, representative corpus
   lane, then let its scan choose the next map/helper/ELF/verifier feature.
   Preserve reproducibility and report multi-program graphs explicitly. Do not
   mistake 57/57 in today's corpus for universal eBPF coverage.
2. **XDP web packet workbench** — parked by the user for now. When unparked,
   add pcap upload/verdict table/click-to-debug/export `.febpf`; see LATEST's
   oside notes. Do not make febpf core depend on current oside.
3. **XDP JIT execution** — interpreter is complete; `--jit` rejects XDP
   clearly. Teach the native/deferred path to synthesize full virtual packet
   addresses for u32 xdp_md data/data_end loads, then differential-test
   interpreter vs JIT across capture packets.
4. **Real-world map/helper coverage** — still missing SK/TASK/INODE_STORAGE,
   LPM_TRIE, sock/dev/xsk maps and many helpers. Implement them when a widened
   corpus makes them relevant, not from the list alone.
5. **Verifier depth** — dynptr, spin locks, bpf_loop/iterators, broader linked
   scalar relationships. Expression identity is implemented; `vfuzz --kernel`
   (keep at 0 FEBPF-LAX) remains the conformance check.
6. **ELF/kfunc gaps** — `R_BPF_64_ABS*`, static multi-object linking, and
   kfuncs; add when real workloads demand them.

## Working style the user likes
- They're hands-on and technical (wrote the "fun challenge" framing, asked for
  the aarch64-ready abstraction and the design docs proactively). Give real
  engineering, not hand-holding.
- They asked me to **commit as I go** and to write specs so a future model
  could extend cleanly. Keep doing both.
- Differential/behavioral testing over assertions-about-code. When I built the
  JIT I validated against the interpreter; when I built the ELF loader I
  validated against real clang + bpftool. Match that bar.

— past-me, updated 2026-07-12
