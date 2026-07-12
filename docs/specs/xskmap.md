# AF_XDP socket maps

STATUS: implemented (2026-07-13)

The pinned xdp-tools v1.6.3 lane includes its production utility probes and
libxdp socket programs: `xdp_load_bytes`, `xdp_sample`, the shared-UMEM
`xdpsock` redirector, and both current and Linux-5.3-compatible default AF_XDP
programs. The fetch script supplies the same libbpf feature declarations used
by the pinned upstream build, avoiding duplicate fallback helper declarations.

`BPF_MAP_TYPE_XSKMAP` is a sparse, queue-indexed redirect map with exact
four-byte keys and values. Missing slots stay absent rather than behaving like
zero-filled array elements; queue indices outside `max_entries` cannot be
looked up or inserted. The verifier accepts XSKMAP for `bpf_redirect_map` and
retains the existing rule that ordinary maps are rejected. Interpreter and JIT
use the same deterministic standalone contract as other redirect maps: a
populated slot returns `XDP_REDIRECT`, while an absent slot returns the helper's
fallback action. febpf does not fabricate an AF_XDP socket or transmit data.

The kind is available through the assembler, ELF loader, kernel-map adapter,
and additive replay-v1 map-kind tag. All five added upstream programs load and
verify against the host target BTF. The resulting full scan covers 136 object
families and 829 entries; all entries load and 816 verify (98.4%): 667 strict
plus 149 under the three explicit privileged uninitialized-stack policies.
There is no ordinary verifier rejection.
