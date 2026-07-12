# Typed BPF iterator contexts

Status: specified for `iter/task`, `iter/task_file`, `iter/tcp`, and
`iter/udp`. These are verification/execution records, not a host-kernel
enumeration API.

## Target-BTF contract

Iterator section names select an exact context structure in the target BTF.
The loader does not infer pointer meaning from arbitrary section names or flat
context offsets.

| section | target type | members (x86-64 host BTF; byte offsets) |
|---|---|---|
| `iter/task` | `struct bpf_iter__task` | `meta` 0: `bpf_iter_meta *`; `task` 8: nullable `task_struct *` |
| `iter/task_file` | `struct bpf_iter__task_file` | `meta` 0; nullable `task` 8; `fd` 16: `u32`; nullable `file` 24: `file *` |
| `iter/tcp` | `struct bpf_iter__tcp` | `meta` 0; nullable `sk_common` 8: `sock_common *`; `uid` 16: 32-bit scalar |
| `iter/udp` | `struct bpf_iter__udp` | `meta` 0; nullable `udp_sk` 8: `udp_sock *`; `uid` 16: 32-bit scalar; `bucket` 24: 32-bit scalar |

The named fields may appear through anonymous unions in vmlinux BTF. Their
resolved pointee types, rather than host Rust layouts or numeric BTF ids, are
authoritative. `bpf_iter_meta` contains a `seq_file *` at offset 0 followed by
64-bit `session_id` and `seq_num` scalars. The iterator element is nullable:
the kernel invokes iterator programs once with a null element to mark end of
iteration. `meta` is the invocation record and is non-null.

## Verification

Iterator context memory is read-only. Accesses must start at an exact member
offset and use that member's declared width: eight bytes for pointer members
and four bytes for the scalar members above. Misaligned, partial, straddling,
out-of-range, and write accesses reject. Loads of `meta` and `meta->seq` yield
read-only BTF pointers. Element loads yield a maybe-null BTF pointer and must
be compared with zero before dereference; copies and aligned spills retain the
same null identity. A successful non-null refinement yields the exact target
BTF pointee, so later field reads use the existing bounded, constant-offset,
fault-tolerant BTF access rules. Arbitrary flat contexts and missing target BTF
remain untyped.

The section-to-type mapping is closed. `iter/foo`, a raw program, or a generic
context with bytes at the same offsets does not acquire iterator pointer
types. Missing or structurally incompatible named context types produce the
same non-fatal loader warning/untyped verification behavior as a missing
fentry attach target.

## Standalone execution

febpf does not enumerate host tasks, files, or sockets and never embeds host
pointers in the context. Its deterministic standalone record uses opaque
virtual kernel addresses for the non-null `meta` slot and leaves nullable
element slots zero. Consequently an ordinary production iterator executes its
end-of-iteration path safely. The virtual kernel-memory region reads as zero,
so `meta->seq` is an opaque zero stand-in unless a future explicit iterator
record adapter supplies richer VM-owned state.

Meaningful enumeration is deferred: it would require a safe caller-supplied
typed record/collection adapter, not fabricated kernel structs or arbitrary
address aliases. The representation and verifier are allocation-only and
remain identical under native `std`, wasm, and `no_std + alloc`.

## Acceptance

- The five pinned entries in Gadget snapshot-file/process/socket and
  libbpf-bootstrap task-iter verify against the running target BTF.
- Tests cover exact positive member typing, required null checks, malformed
  offsets and widths, read-only enforcement, closed section matching, and
  deterministic interpreter/JIT agreement on the null-element path.
- Generic flat-context and missing-attach behavior do not change.
