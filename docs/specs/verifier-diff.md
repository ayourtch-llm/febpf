# verifier differential fuzzing (`vfuzz --kernel`)

`febpf vfuzz --kernel` generates frontier programs and compares febpf's verifier
verdict against the real kernel's `BPF_PROG_LOAD` verdict, classifying each
disagreement as:

- **FEBPF-LAX** — febpf ACCEPTS a program the kernel REJECTS (conformance gap;
  febpf too permissive).
- **FEBPF-STRICT** — febpf REJECTS a program the kernel ACCEPTS (over-tightening;
  false rejection).

## STATUS

First real run (as root, against a live kernel) found **2 gaps**, both
FEBPF-LAX (~12% of frontier programs), fixed on branch
`fix/verifier-conformance`:

1. **Modified ctx-pointer dereference.** The kernel forbids dereferencing a
   `PTR_TO_CTX` pointer once it has a *variable* (non-constant) offset — i.e.
   after pointer arithmetic with a register/unknown operand. Fixed
   *constant*-offset ctx field access (e.g. `*(u32*)(r1 + 8)`) stays legal.
   Fixed in `src/verifier.rs` `check_mem_access`, `PtrKind::Ctx` arm: reject
   with `dereference of modified ctx ptr off=... disallowed` when
   `!p.var.is_const()`.

2. **Unconditional stack alignment.** The kernel ALWAYS enforces natural
   alignment on `PTR_TO_STACK` accesses (size-N access must be N-byte aligned),
   independently of the general `--strict-align` policy. febpf previously only
   checked stack alignment under `--strict-align`. Fixed in `src/verifier.rs`
   `check_mem_access`, `PtrKind::Stack` arm: enforce `off % size == 0` always
   for real load/store/atomic accesses (a new `align` flag distinguishes these
   from helper-argument buffer checks, which carry no alignment constraint).
   ctx/map/packet alignment continues to follow the existing `--strict-align`
   policy — only the stack rule became always-on.

Tests added (`tests/integration.rs`): `reject_modified_ctx_ptr_deref`,
`accept_fixed_offset_ctx_access`, `reject_misaligned_stack_store`,
`accept_aligned_stack_access`. Both feature configs green.
