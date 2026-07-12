# Scalar identity and expression refinement

Status: implemented and selected by the real-world corpus. This closes the
last verifier rejection in the pinned 57-object corpus (BCC `ksnoop`).

## Problem

Sound verification can track relationships between scalar expressions, not
only independent ranges. `ksnoop` uses this clang pattern for a helper buffer
size:

1. derive a scalar size;
2. copy it to another register;
3. mask and bound-check the copy;
4. apply the equivalent mask to the original;
5. pass the original as `perf_event_output`'s size.

Independent ranges cannot connect steps 3 and 4, so febpf retained a maximum
of 65,535 and rejected access to a 16,296-byte map value. Removing the helper
bounds check would be unsound; the missing feature was relational precision.

The current host kernel also rejects a minimal reproduction after losing the
copy id at the first mask. febpf deliberately proves this safe expression
relation beyond current kernel precision; this is not a kernel-verdict parity
claim. The negative-expression tests below are therefore load-bearing.

## Model and invariants

Verifier frames carry scalar equality ids for registers and aligned 8-byte
spills. A plain move preserves the id only when the destination's full value
is semantically identical (an ALU32 move therefore needs a source already
proven zero-extended). Arithmetic never keeps the parent id directly.

Instead, deterministic operations with a constant operand derive an interned
expression id from `(parent identity, operation, width, operand, signed-mode)`.
Applying the same expression later to another copy recovers that id and meets
its bounds with every live register/spill carrying the expression. ALU32 and
ALU64 AND/OR/XOR expressions unify only when both operands are already proven
within u32, which makes their concrete results identical.

Branch refinement propagates to every live location with the same expression
id. Writes, partial spills, helpers, and non-equivalent operations clear the
affected relation. Local-call arguments and scalar returns preserve it.

Pruning compares equality *patterns*, not numeric ids: a remembered state can
cover a new state only when every equality assumption the old state may use is
also present in the new state. Extra equality in the new state is narrower and
therefore safe.

## Evidence

- the exact mixed-width copied/masked size pattern verifies;
- a different second mask remains rejected as out-of-bounds;
- branch bounds propagate through an aligned scalar spill/reload;
- all existing scalar/operator soundness and program tests remain green;
- BCC `ksnoop` now verifies (57,771 instructions processed);
- the refreshed pinned corpus is 57/57 loaded and 57/57 verified.
