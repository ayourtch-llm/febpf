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

## Iterator output and task stacks

`seq_write` (#127) has the kernel prototype `(struct seq_file *seq, const
void *data, u32 len) -> scalar`. The first argument must be an unmodified,
non-null pointer to the exact target-BTF `seq_file` type; an arbitrary scalar,
another BTF pointer, a nullable pointer, or an adjusted pointer rejects. The
data argument is readable initialized memory for the bounded `len`, including
the kernel's valid zero-length case.

Standalone execution appends successful writes to the VM-owned
`Vm::seq_output` byte vector. The synthetic sequence has a deterministic 1 MiB
capacity. A write which would cross it is atomic, preserves earlier bytes,
and returns `-EOVERFLOW`; otherwise it returns zero. The output is part of
machine snapshots, so restore and debugger replay neither lose nor duplicate
iterator bytes.

`get_task_stack` (#141) likewise requires an unmodified, non-null target-BTF
`task_struct *`, followed by writable memory, a bounded size which may be
zero, and kernel-style unrestricted flags. febpf has no host task stack. Its
deterministic synthetic task writes the same innermost-first sequence of BPF
instruction indices used by `get_stack`, as whole little-endian u64 frames,
zero-fills the rest of the requested buffer, and returns the number of bytes
written. This uses only VM call-frame state and therefore agrees across the
interpreter, hybrid JIT, snapshots, and portable builds.

## Socket conversions

`skc_to_tcp_sock` (#137), `skc_to_tcp_timewait_sock` (#138), and
`skc_to_tcp_request_sock` (#139) require an unmodified, non-null pointer to
the exact target-BTF `sock_common` type. Their results are nullable pointers
to the exact target-BTF `tcp_sock`, `tcp_timewait_sock`, and
`tcp_request_sock` types respectively. A result must be checked against zero
before it can be dereferenced, and its fields retain the existing bounded,
fault-tolerant BTF access rules.

febpf does not expose host sockets or manufacture synthetic kernel socket
layouts. Standalone conversion therefore returns null deterministically. The
ordinary terminal iterator record does not reach these calls, while an
explicit future typed socket-record adapter can add meaningful conversion
semantics without weakening pointer verification.

## Acceptance

- The five pinned entries in Gadget snapshot-file/process/socket and
  libbpf-bootstrap task-iter advance through helpers #127, #137--#139, and
  #141 against the running target BTF.
- Tests cover exact positive member typing, required null checks, malformed
  offsets and widths, read-only enforcement, closed section matching, and
  deterministic interpreter/JIT agreement on the null-element path, sequence
  output/snapshot behavior, and deterministic task-stack bytes.
- Generic flat-context and missing-attach behavior do not change.
