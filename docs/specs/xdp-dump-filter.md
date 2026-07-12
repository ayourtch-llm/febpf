# XDP dump/filter production expansion

STATUS: implemented (2026-07-13)

The pinned xdp-tools v1.6.3 corpus lane now includes the two checked-in
xdp-dump BPF translation units and all ten xdp-filter allow/deny variants.
These sources deliberately use generated-style `.c` names rather than the
repository's more common `*.bpf.c` suffix, so the fetch manifest names them
explicitly. They compile directly from the immutable checkout with its
`headers/` tree; no generated userspace feature header or upstream build is
needed for the BPF objects.

The expansion exposed one shared verifier gap. XDP's `data` and `data_end`
context fields are 32-bit packet addresses, and clang emits an ALU32
`data_end - data` operation when calculating packet length. febpf now accepts
only that packet-end minus packet-pointer form and produces an unknown,
zero-extended u32 scalar. Other ALU32 operations involving pointers remain
rejected, including pointer addition. Interpreter and JIT execute the ordinary
ALU32 subtraction unchanged after verification.

The xdp-dump fentry/fexit object retains its two deliberate `func` attach
placeholders. Without the application's selected XDP target function they are
reported as `ENVIRONMENT:missing-attach-target`; febpf does not fabricate a
prototype. The ordinary xdp-dump XDP program and all ten xdp-filter variants
verify strictly.

The resulting full cached scan covers 131 object families and 824 enumerable
entries. All 824 entries load; 811 verify (98.4%): 662 strictly and 149 under
the three explicit privileged uninitialized-stack policies. The remaining
outcomes are six attach-target environment gaps and seven poisoned
application-supplied CO-RE entries. At family level, 120/131 are compatible:
117 strict plus three privileged. The two flowtable objects remain honest
`ENVIRONMENT:missing-kfunc` outcomes on this host. Unsupported-map,
unknown-helper, and ordinary-verifier-rejection histograms are empty.
