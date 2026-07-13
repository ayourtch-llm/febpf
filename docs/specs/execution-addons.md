# Composable execution add-ons

## Problem

`Vm` historically accumulated both durable program state and whichever host
model the newest program family required. XDP is the clearest symptom: packet
bytes, context synthesis, redirect intent, helper behavior, replay state, and
eventual transport capacity all started converging on `Vm`. The same pattern
already exists in smaller forms for skb packets, typed BTF kernel memory,
iterator `seq_file` output, and caller-owned metadata regions.

That shape does not scale. A reusable VM must not become the owner of every
possible invocation resource, and a transport adapter must not be wired into
the interpreter or JIT.

## Four layers

febpf execution is split into four layers:

1. **Program** (`Vm`): instructions, maps, linked tail programs, compiled code,
   verifier evidence, debug information, and embedding configuration that
   persists across invocations.
2. **Verified context model**: exactly one ABI interpretation selected during
   verification (`Flat`, `Btf`, `Xdp`, `Skb`, or pointer-bearing `Metadata`).
   This is program semantics, not live host state.
3. **Invocation environment**: borrowed resources and completion state for one
   `Machine`—context bytes, an optional packet window, optional output sinks,
   synthetic host-memory services, and program-family completion data.
4. **Backend adapter**: owns transport/storage and constructs an invocation
   environment. Slice, replay, pcap, debugger, mock-provider, and AF_XDP are
   peers at this layer.

The core rule is: **a `Machine` borrows invocation resources; `Vm` never stages
or owns them merely because an add-on needs them.**

## Environment and add-ons

The environment is data-oriented rather than a chain of per-instruction trait
objects. Hot paths consult typed optional resource slots:

- `ContextResource`: caller-borrowed or adapter-owned context bytes;
- `PacketWindow`: borrowed storage, mutable half-open data bounds, and explicit
  head/tail capabilities;
- `PacketSource`: selects that window, the context itself, or an owned region
  for deprecated absolute/indirect packet loads;
- `OutputSinks`: optional sequence output today, with perf/diagnostic sinks as
  candidates for the same boundary;
- `Completion`: redirect intent and future program-family results.

An add-on constructs a compatible typed environment. The environment has only
one context model and packet slot by construction; execution rejects a model
incompatible with the program verified into the VM. A fluent builder can be
added when there are enough genuinely independent slots to justify it. The
initial constructors/add-ons are:

- `Xdp`: XDP context scalar metadata + packet window + reserved resize capabilities +
  redirect completion;
- `Skb`: safe scalar `__sk_buff` context + the same packet-window resource;
- `RawPacket`: flat context also selected as the legacy packet source;
- `OwnedPacketMetadata`: caller context whose pointer fields name a registered
  owned region;
- `SeqOutput`: a borrowed output sink, independently composable with any
  compatible context/packet add-on.

The public convenience methods are deliberately thin constructors over this
same environment. There is no privileged VM-owned packet adapter and no
`prepare_*`/`finish_*` staging pair.

## Packet window

A packet window borrows storage and its mutable `data_start`/`data_end` fields.
Direct guest accesses use virtual packet offsets relative to the current
window. Helper byte copies, legacy loads, interpreter deferred accesses, user
helper `MemBus`, and JIT callbacks all resolve through this single resource.

The window carries explicit head/tail capability bits, but this refactor does
not yet activate them. `xdp_adjust_head` and `xdp_adjust_tail` therefore remain
honestly `-EOPNOTSUPP` for every adapter. The next resize batch may mutate the
borrowed bounds only when the installed window advertises the corresponding
capability; bounds failures must be atomic and tail growth must zero newly
exposed bytes. A slice adapter installs no resize capability.

## Hooks and completion

The verified context model handles context-field loads and determines which
program-family helpers are meaningful. Helpers obtain resources from the
environment; they do not reach into `Vm` for packet or backend state.
Redirect helpers write provider-neutral intent into invocation completion.
The backend receives that completion after the machine exits but decides
whether and how to transmit.

Both interpreter and JIT operate on the same `Machine` and therefore the same
environment hooks. A backend-specific pointer is never embedded in guest
registers or native code.

## Snapshots and replay

A snapshot copies the logical contents of installed invocation slots and their
mutable cursors/bounds, not their host addresses. Restore requires the same
environment topology and compatible capacities, then copies logical state back
into the borrowed resources. This makes direct provider execution, debugger
time travel, and replay use one mechanism.

The `.febpf` container remains an owned serialization adapter: it reconstructs
ordinary environment resources when opened. Live ring descriptors, provider
cookies, and socket ownership are not serialized unless a versioned section
defines their stable meaning.

## Migration test

The abstraction is not considered established merely because XDP works. The
first implementation must migrate multiple independent consumers:

1. slice and provider-frame XDP under interpreter and JIT;
2. skb and raw packet inputs through the same packet resolver;
3. metadata-owned packets without a VM staging copy;
4. one non-packet resource (`SeqOutput`) to demonstrate actual composition;
5. snapshots/replay across installed resources.

Only after that matrix is green should AF_XDP or further XDP capability work
resume. The initial implementation retains the existing VM-owned sequence
buffer as the default convenience sink for API compatibility, while an
explicit environment can override it with an independently borrowed sink.
