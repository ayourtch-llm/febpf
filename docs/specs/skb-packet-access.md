# Safe SKB packet contexts

Status: the explicit `struct __sk_buff` adapter and read-only helper
`skb_load_bytes` (#26) are implemented. Direct packet pointers and skb-mutating
helpers remain separate work.

## Selection and context

ELF section kinds `socket`, `classifier`/`tc`, `cgroup_skb`, `sk_skb`,
`flow_dissector`, and `lwt_*` select `verifier::Config::skb`. Raw/assembler
programs must opt into that configuration explicitly. It is mutually exclusive
with XDP, BTF-typed, and configurable metadata context models.

The current verifier exposes the production-corpus scalar subset of
`struct __sk_buff` as exact read-only 32-bit fields: `len` at offset 0,
`pkt_type` at 4, `protocol` at 16, `ifindex` at 40, and `cb[0..5]` at offsets
48 through 64.
Modified context pointers, other widths/offsets, and context writes reject.
Exact 32-bit loads of `data` and `data_end` at offsets 76 and 80 yield the
same bounded VM packet-pointer classes as XDP. Direct access therefore needs a
fresh end comparison proving the accessed prefix.

`Vm::run_skb` and `Vm::run_skb_jit` copy caller packet bytes into the existing
bounds-checked VM packet region and construct a zero-filled 192-byte context.
`len` is the packet length. For an Ethernet-sized packet, `protocol` is derived
from its outer EtherType in the host representation of the kernel's `__be16`;
the other modeled metadata fields default to zero.
No host skb or host packet address enters a guest register. Ordinary `Vm::run`
does not guess that an arbitrary context has packet backing.

`redirect` (#23) is also selected by the explicit skb model. Flags may be zero
or `BPF_F_INGRESS`; those cases return `TC_ACT_REDIRECT`. Other flag bits
return `TC_ACT_SHOT`. The standalone VM reports only this action and does not
invent a network device or transmission side effect.

## `skb_load_bytes`

The helper prototype is `(struct __sk_buff *skb, u32 offset, void *to,
u32 len) -> scalar`. Argument one must be the original context pointer under
the explicit skb verifier mode. The destination must be writable for the
bounded length, including zero. Offset and length use their kernel u32
interpretation.

With the skb adapter, an in-range call copies exact packet bytes and returns
zero. A missing packet backing, arithmetic overflow, or out-of-range interval
returns `-EFAULT` without partially changing the destination. Interpreter and
hybrid JIT use the same helper dispatcher and packet region.

## `skb_pull_data`

`skb_pull_data` (#39) requires the original skb context and a scalar u32
length. The VM-owned packet is already linear and writable, so zero or an
available length succeeds without changing bytes; a requested length beyond
the packet returns `-ENOMEM`.

The verifier nevertheless follows the kernel relocation rule: every packet
and data-end pointer derived before the call, including register aliases and
aligned spills, is invalidated regardless of the runtime result. Programs
must reload `data` and `data_end` from the preserved context and repeat their
bounds check. This keeps the standalone optimization from weakening the
portable verifier contract.

## Acceptance

- Inspektor Gadget `advise_networkpolicy` and libbpf-bootstrap `sockfilter`
  become fully compatible; Gadget DNS/SNI advance beyond helper #26 and remain
  classified by their target/environment CO-RE relocation outcomes.
- Tests cover exact packet copies, synthesized `len`, generic-context
  rejection, atomic out-of-range failure, and interpreter/JIT agreement.
- The full corpus contains no remaining helper #26 blocker.
- Both Gadget tcpdump entries advance beyond helper #39 and remain classified
  by their target/environment CO-RE relocation outcome; #39 is absent from the
  helper histogram.
