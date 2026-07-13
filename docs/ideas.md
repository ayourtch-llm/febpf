# Ideas parking lot — where febpf could go next

_Strategy ponderings from the 2026-07-11 session, so they survive context
resets. These are ranked assessments, not commitments. The corpus loop
(HANDOFF "Production coverage") remains the active thrust._

## Active after corpus saturation: composable execution add-ons

The pinned production corpus reached zero ordinary verifier rejections on
2026-07-13. Packet-provider work exposed a more general boundary: XDP is one
invocation add-on, not a mode that should absorb the VM. `ExecutionEnvironment`
now owns the compositional boundary described in
`specs/execution-addons.md`; XDP, skb, raw packet, metadata packet selection,
and an independently borrowed sequence-output sink exercise it. AF_XDP remains
the first intended live backend, while DPDK stays a later optional workspace
adapter rather than a febpf core dependency.

The provider owns packet storage and transport; an invocation environment
borrows live resources; the VM owns durable program semantics.
The boundary must describe:

- the mutable frame window plus explicit headroom/tailroom capacity;
- synthesis of the program-specific context (`xdp_md` first) without exposing
  host pointers to eBPF;
- bounded batches in and verdicts out, including PASS/DROP/TX and redirect
  delivery rather than only an integer return value;
- sparse XSKMAP socket ownership supplied by the backend, never fabricated by
  the map implementation;
- optional capture of the selected input, metadata, maps, nondeterminism, and
  result into the existing `.febpf` replay format;
- provider capability negotiation for resizing. `xdp_adjust_head` and
  `xdp_adjust_tail` may mutate a frame only when the provider explicitly owns
  sufficient capacity; the standalone owned-packet path continues returning
  `-EOPNOTSUPP` instead of inventing headroom or tailroom.

Revised implementation order:

1. Continue factoring invocation-only services that still live in `Vm`.
   Synthetic BTF kernel-memory scratch and borrowed sequence/printk sinks have
   moved; next audit deterministic clock/random streams, profiling, and perf
   output, distinguishing intentionally cross-invocation state from resources.
   Keep typed slots and measure multiple consumers before generalizing a
   builder or hook interface.
2. Provider resize capabilities are active through the shared packet window;
   plain slices preserve `-EOPNOTSUPP`.
3. Linux AF_XDP copy mode is now an opt-in raw-UAPI `XdpProvider` adapter. Its
   deterministic ABI/ring/routing tests are complete; privileged veth and
   XSKMAP validation remains environment-gated and must not be reported as
   reproduced where `CAP_NET_RAW`/BPF setup is unavailable.
4. Add mlx5 zero-copy only after copy mode is stable and the environment
   supports it. Preserve normal kernel driver ownership.
5. If still valuable, expose the same boundary to a separate optional DPDK
   adapter/sidecar. Direct PCI/VFIO mlx5 ownership is a different driver
   project and is not implied by this plan.

## Ranked: what makes people go "wow" next

febpf's differentiators to build on: zero-dep, deterministic replay,
safe-by-construction runtime (virtual-address model), a real verifier with an
explainer, differential testing against the live kernel (kbpf), time-travel
debugging, the race explorer, full BTF + CO-RE.

### 1. eBPF as an application extension mechanism (packaging, not research)

The infrastructure half-exists: `UserHelpers` registry, ctx passing, the
memory model where a hostile plugin cannot corrupt the host even with
`--no-verify`. Differentiators vs WASM plugins (and vs ubpf/rbpf, which have
no real verifier): static termination/memory-safety guarantees BEFORE the
plugin runs, the rejection explainer for plugin authors, misbehaving plugins
shipped as `.febpf` replay files the host vendor can time-travel debug, and
the race explorer for concurrent plugin instances sharing maps.

The packaging baseline now exists: the opt-in versioned C ABI has an opaque VM,
explicit verifier/run descriptors, composable invocation output sinks, a
hand-written header, cdylib/staticlib builds, and compiled C hosts while
remaining zero-dependency. The streaming log-filter host proves a non-packet
application needs no new VM mode: a versioned inline Flat context supports
bounded accept/drop and safe in-place redaction. ELF/CO-RE construction now has
its own versioned descriptor and section-derived verification constraint. Next
additions remain independently measured: C helper callbacks, map control, and
`.febpf` capture handles should not become one miscellaneous adapter.

### 2. The XDP story (packet access) — already on the roadmap's critical path

Real NIC hardware offload: no (needs hardware). But direct packet access
(`data`/`data_end` bounds tracking) is already the #1 named verifier gap, and
once it exists:
- pcap-in, verdict-out deterministic harness: time-travel debug THE packet
  that broke the program; `origin r3` on the bogus offset.
- Differential validation via the existing kbpf layer — `BPF_PROG_TEST_RUN`
  supports XDP, so every verdict can be checked against the live kernel.
- Stretch demo: AF_XDP / raw-socket loop with raw syscalls (zero-dep) to run
  an XDP program on live veth traffic in userspace. Demo-tier, not
  datapath-tier (HANDOFF rule: febpf is an analysis engine, not a runtime).

### 3. CI / IDE packaging (cheap, do opportunistically)

At ~90% real-world verification, febpf is a credible CI gate: a GitHub Action
verifying `.bpf.o` files, posting the explainer as PR annotations mapped to C
source lines via `.BTF.ext` — no root, no matching kernel. Same trick as an
LSP/VS Code diagnostics mode. Near-zero new engineering.

### 4. GPUs — a different project; park it

Fights the architecture instead of building on it: the JIT's safety story is
deferral of memory ops to the interpreter (a GPU can't call back into a host
interpreter per memory op), execution needs CUDA/Vulkan (zero-dep dies), and
GPU scheduling kills determinism. Only zero-dep-compatible angle: emitting
PTX/SPIR-V text as an experiment — but it can't be differentially validated
without drivers, which is against the project's religion.

## Migration of eBPF workloads and their state

The naive version exists (`bpftool map dump` → restore) and is mostly wrong
in ways that map exactly onto febpf's assets. The thesis: **eBPF migration is
a semantics problem, and the semantics live in BTF**, which we fully parse.

Why naive dump/restore lies:
- map values embed `ktime_get_ns()` timestamps (monotonic clock is
  per-host), kernel addresses (stack traces, kptrs), per-CPU layouts
  (nr_cpus differs). BTF value types let a migrator introspect every field
  and rebase clocks / translate addresses (kallsyms diff) / re-layout
  per-CPU lanes: BTF-guided semantic state translation — novel, nobody does it.
- the program isn't portable either: same `.bpf.o` needs different CO-RE
  relocations on the target kernel — febpf already does full retargeting via
  `--target-btf`.
- quiesce granularity: eBPF invocations are transactional microseconds, so
  migration happens BETWEEN invocations (detach → drain → transfer → reload →
  re-attach). No CRIU-style mid-execution checkpoint needed; the hard part is
  the cutover window (lost events, atomicity).

Phasing:
- **Phase 1 (this repo, high wow-per-effort): `febpf snapshot-kernel`** —
  drain a live program's pinned maps via kbpf, pair with its `.bpf.o`, emit a
  `.febpf` → time-travel debug production eBPF state on a laptop. Pure
  composition of existing pieces (kbpf, ELF+BTF, MapSnapshot, replay
  container, debugger). Also proves the capture half of migration.
- **Phase 2 (separate project, febpf as its library): the migrator** —
  "CRIU for eBPF": semantic value translation, CO-RE re-specialization for
  the destination kernel, attach-point re-establishment, and a febpf-unique
  verification step: load translated state into febpf on both sides and
  differentially check invariants before committing the cutover. Headline
  demo: upgrade the kernel under a stateful XDP load balancer without losing
  its session table.

Known-hard corners (documentable limitations, not fatal): prog_array /
tail-call contents are FDs (re-link by name), stack_trace ids are hashes of
kernel addresses (stale across kernels; translatable only with both hosts'
kallsyms), ringbuf in-flight records at quiesce time.

## Formal methods (2026-07-11 pondering)

TLA+ verdict: wrong tool for the ISA (big 64-bit state, no temporal structure
— TLC explodes; Sail/K/Lean/SMT are the right shapes there, and the ISA is
already RFC 9669 + CertrBPF academically). Right tool for exactly one slice:
**the race explorer's map-op interleaving semantics** — N instances, shared
maps, lost-update/stale-RMW properties. A TLA+ model in docs/formal/ +
TLC-vs-`febpf race` verdict cross-validation on small configs is a genuine,
modest project (differential testing applied to formal methods).

The high-value target is **verifier abstract-operator soundness** (where Agni
found real kernel bugs; the tnum paper proved the kernel's ops sound). The
bugs live in abstract arithmetic — our `tnum.rs` + range logic — and
soundness is a ∀-property fuzzing can't establish. Feasible in-repo,
zero-dep, ranked:
1. **Exhaustive small-width soundness checks** (do first; single-agent batch):
   parameterize tnum/interval ops over bit width, brute-force the soundness
   obligation (∀x∈γ(a),y∈γ(b): x⊕y ∈ γ(a⊕'b)) at w=8 over ALL abstract pairs
   in a test module. Seconds to run, lives in CI, catches the Agni bug class.
2. **SMT-LIB emission**: hand-written emitter (SMT-LIB2 is text) dumping each
   operator's 64-bit soundness obligation to .smt2, discharged by z3 IF
   installed — same optional-oracle pattern as clang/bpftool/root-kernel.
3. The TLA+ race-model cross-check above.

A fully verified verifier (Lean/Coq) is a different project; febpf would be a
good substrate (deterministic, no libc, interpreter = executable semantics)
but CertrBPF/Agni occupy that research ground.
