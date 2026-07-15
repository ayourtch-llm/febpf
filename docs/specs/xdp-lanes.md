# XDP lane plans

`lanes::XdpLaneProgram` is an architecture-independent execution plan for
running one verified scalar XDP program over independent packet lanes. It is
the semantic input for scalar interleaving today and optional SIMD JIT lowering
later; it is not a new Linux eBPF program type.

## Accepted subset

The first implementation accepts map-free, forward-only programs containing:

- scalar ALU32 and ALU64 operations;
- forward unconditional and conditional branches;
- verifier-proven `xdp_md.data`, `data_end`, and constant-offset packet loads;
- root exit.

It rejects helpers, maps, stores and atomics, stack access, generic loads,
local and tail calls, and backward control flow. Rejection is a normal scalar
fallback, not a load failure. These restrictions make lanes independent and
remove observable execution order from the first model.

## Execution

`LaneWidth::Four` executes four states in lockstep. A final group of two is the
automatic double-lane form and a final single packet is the scalar remainder.
Branches advance each lane's program counter independently, so divergent lanes
remain correct but can be slower when lowered to ordinary scalar Rust.

The graph runtime therefore activates scalar-interleaved lanes only for tiny
branchless plans. More complex accepted plans are retained and validated but
continue through the scalar JIT until a profitable backend exists.

## Translation validation

Compilation consumes the verifier's all-path register states. Packet loads are
accepted only when the source is a packet pointer with one constant effective
offset inside its proven range. Context loads are limited to the XDP data and
data-end fields. Each lane has a private register file, packet, program counter,
and result.

`XdpLaneProgram::validate` differentially executes a caller-supplied frame
corpus through the ordinary scalar VM and the lane plan. It compares verdicts
and the complete frame. A successful `LaneValidation` is empirical evidence,
not a universal formal proof. The conservative static subset is the soundness
argument; a mechanized equivalence proof does not exist yet.

The graph loader validates accepted plans over empty, truncated, minimum,
ordinary, 256-byte, and 1514-byte packets, including IPv4, non-IPv4, and
patterned data. Any mismatch is an internal translation error and rejects node
loading rather than silently selecting scalar execution.

## SIMD lowering

The x86 backend may lower the same lane operations to SSE2, AVX2, or AVX-512
after runtime feature detection. CPU features must participate in the compiled
image cache key. Divergent branches require masks; helpers and observable
effects remain scalarization boundaries when later subsets admit them. Every
backend must retain scalar-interleaved lowering as the reference implementation.
