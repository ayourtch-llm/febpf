# Privileged uninitialized-stack policy

Status: implemented as an explicit, strict-default verifier policy.

## Motivation and boundary

Linux permits reads from `STACK_INVALID` bytes when the verifier environment's
`allow_uninit_stack` capability is enabled. Current kernel source derives that
permission from `CAP_PERFMON` (including delegated BPF-token capability), and
applies it to both direct stack loads and helper-readable stack buffers. This
is verifier policy, not a property febpf can infer from the host uid.

febpf therefore exposes `UninitStackPolicy::{Strict, Allow}` in
`verifier::Config` and the explicit CLI option `--allow-uninit-stack`. The
default remains `Strict`; `--kernel`, root execution, and ordinary unchecked
execution never enable it implicitly.

## Semantics

Under `Allow`, bounds, alignment, pointer provenance, helper argument typing,
initialized registers, and atomic rules remain unchanged. Only missing stack
initialization bits cease to reject a direct load or a helper read. A direct
load produces an unknown verifier scalar rather than a known zero.

febpf's VM backing stack is deterministically zeroed. Local-call entry clears
the selected 512-byte frame even when an earlier callee used the same depth,
so an accepted never-written byte cannot expose stale VM data. Helpers and
direct loads consequently observe zero for holes in standalone execution.
That deterministic runtime choice is stronger than the verifier claim and is
not presented as a claim about kernel runtime byte values.

## Persistence and corpus policy

Replay format v1 uses optional section `0x0d` to preserve the policy; absence
means `Strict`, retaining byte-compatible strict replay files. Browser/debugger
replay carries the same provenance.

The corpus scanner always tries strict verification first. It retries only the
exact uninitialized-stack diagnostic for the audited Gadget families
`snapshot_file`, `top_blockio`, and `trace_lsm`, and records successful retries
as `OK-PRIVILEGED-UNINIT` rather than plain `OK`. Other verifier failures are
never hidden by this policy.

## Evidence

- direct and helper-buffer tests reject by default, accept only under the
  explicit policy, and verify exact zero padding at runtime;
- uninitialized registers remain rejected;
- a local-call frame-reuse regression covers interpreter and JIT execution;
- replay round-trips the additive policy tag, with absent-tag strict fallback;
- the production scanner keeps strict and privileged acceptance separately
  measurable.

Primary kernel reference: [`kernel/bpf/verifier.c`](https://github.com/torvalds/linux/blob/master/kernel/bpf/verifier.c)
(`check_stack_read_fixed_off`, stack-range initialization, and
`env->allow_uninit_stack`).
