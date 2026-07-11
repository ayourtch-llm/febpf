# BTF-typed ctx pointers (kernel `PTR_TO_BTF_ID`)

Programs in `tp_btf/…`, `fentry/…`, `fexit/…` and `fmod_ret/…` sections do not
get a flat byte-buffer ctx: the kernel types their ctx as an **array of 8-byte
BTF-typed arguments**, and pointer arguments are direct kernel pointers whose
fields the program may read without `probe_read`. This spec describes how
febpf mirrors that — the last verifier feature needed for full corpus
coverage (55/56; ksnoop's rejection is kernel verdict parity, see
`tracing-helpers.md`).

Every rule below cites the kernel function it mirrors. Files:
`src/btf.rs` (typing), `src/verifier.rs` (`PtrKind::BtfId`), `src/interp.rs`
(`Region::KernelMem`, probe reads), `src/elf.rs` (section resolution).
Tests: `tests/btfctx.rs` (self-contained fixture `examples/c/btfctx.c` —
carries its *own* target-side types so no kernel is needed), unit tests in
`src/btf.rs`, vmlinux-gated parity in `tests/btf.rs`.

## 1. Resolving the ctx typing (`btf.rs`)

`resolve_ctx_args(btf, section)` mirrors how the kernel picks the prototype
that types the ctx (`btf_ctx_access()` in kernel/bpf/btf.c):

- `tp_btf/NAME` → the `btf_trace_NAME` typedef's func_proto, with the first
  `void *__data` parameter skipped (kernel: `attach_btf_trace` handling).
- `fentry/NAME`, `fmod_ret/NAME` → kernel function `NAME`'s proto.
- `fexit/NAME` → like fentry plus one trailing slot typed by the return value.

Each parameter becomes a `CtxSlot`: `Ptr { btf_id }` when it is a pointer to
a struct/union (pointee resolved through modifiers/typedefs), else `Scalar`.
**Divergence (stricter):** the kernel also types pointers to scalars/void as
`PTR_TO_BTF_ID`; febpf reads them as scalars — a program that derefs one is
rejected here but accepted by the kernel. No corpus program does this.

`Btf::read_kind(id, off, size)` mirrors `btf_struct_walk()`: what does a
`size`-byte read at `off` inside type `id` yield? `Some(pointee)` iff the
read covers exactly an 8-byte pointer-to-struct/union member (walking nested
structs, unions and arrays; bitfield members never produce pointers);
`None` = plain data. Reads that match no pointer member are data, not errors.

The result travels as `BtfCtx { args: Vec<CtxSlot>, btf: Option<Arc<Btf>> }`
on `Program`/`LoadedProgram` and `verifier::Config`. The `btf` graph is only
needed for verification; the runtime uses the slots alone.

## 2. Verifier (`verifier.rs`)

New pointer kind: `PtrKind::BtfId { btf_id }`.

**Ctx accesses** (when `Config::btf_ctx` is set) mirror `btf_ctx_access()`:
- the register's own offset must be 0 (shared `PTR_TO_CTX` rule, kernel
  `check_ctx_reg()`), the access offset a multiple of 8, and within
  `args.len()` slots;
- all writes reject (tracing programs' ctx is read-only);
- a `Ptr` slot must be loaded with a full 8-byte read → yields
  `Ptr(BtfId)`; scalar slots may be read narrow (yield unknown scalars).

**BTF pointer derefs** mirror `check_ptr_to_btf_access()` +
`btf_struct_access()`:
- reads only ("only read is supported"), constant offset only, `off >= 0`,
  `off + size <= type_size(btf_id)`;
- the loaded value is typed by `read_kind`: pointer members chase to a
  nested `Ptr(BtfId { pointee })`, everything else is an unknown scalar;
- natural alignment is enforced only under `--strict-align` (like ctx/map);
- a BTF pointer is rejected as any helper memory buffer
  (`check_helper_mem`) — the kernel's `ARG_PTR_TO_MEM` family never accepts
  `PTR_TO_BTF_ID`. It IS fine as `ARG_ANYTHING` (e.g. `probe_read_kernel`'s
  source).

**Probe-read marking.** The kernel rewrites every load through a BTF pointer
to `BPF_PROBE_MEM` in `convert_ctx_accesses()` — fault-tolerant, bad address
reads as zero. febpf records the same fact per insn (`VerifyOk::probe_mem`)
and `Vm::verify` arms the VM with it on success. Because the rewrite is
per-instruction, one LDX reached with a BTF pointer on one path and ordinary
memory on another is rejected with the kernel's exact message ("same insn
cannot be used with different pointers", `do_check()`), tracked in
`Verifier::note_ldx_class`.

**Pruning/join soundness.** `PtrKind` equality is derived, so `BtfId` joins
and subsumes only against the identical type id + offset; any mismatch widens
to an unknown scalar (sound in the virtual-address model — a pointer IS a
u64 — and a deref through the widened value then rejects). A typed pointer
never *survives* a join it shouldn't; nothing ever widens INTO a pointer.

## 3. Runtime (`interp.rs`) — deterministic stand-in for kernel memory

`Region::KernelMem` (handle `KMEM_HANDLE`, always present): **every read
returns zeroes, every write faults**, at any offset/length. `resolve_slice`
serves reads from a re-zeroed scratch buffer, so this stays inside the
virtual-address model — `--no-verify` and the JIT (which defers all memory
ops) cannot scribble on it.

On each run, `Machine::new` prefills every `Ptr` ctx slot with a distinct
deterministic kernel-region address (slot i → offset `(i+1) << 20`, 1 MiB
apart) so distinct pointer arguments compare unequal and are non-NULL, like
real kernel pointers. Scalar slots keep whatever ctx bytes the user supplied.

Loads marked probe-mem read 0 on *any* resolution failure — exactly
`BPF_PROBE_MEM`'s fault path. The canonical case: a pointer member read from
zeroed kernel memory is 0 (NULL); chasing it faults internally and yields 0,
as it would in the kernel. Unverified runs have no probe-mem bitmap, so the
same chase faults cleanly instead (still memory-safe; semantics differ from
the kernel only in that error path — documented, deliberate).

Determinism: the region is all-zeroes, addresses are fixed → a run is still
a pure function of (program, ctx, seed, map preload). Replay/time-travel
work unchanged. **Limitation:** `.febpf` replay files (v1 container) do not
carry `BtfCtx`/probe-mem yet, so a replayed BTF program runs unarmed — the
determinism guard will warn if that changes r0. Add container fields when it
matters (slots + bitmap are enough; that is why `BtfCtx.btf` is optional).

## 4. ELF/CLI (`elf.rs`, `main.rs`)

The target BTF is parsed once in `load_with_target_btf` and shared (Arc) by
CO-RE relocation and ctx resolution. `--target-btf` defaults to
`/sys/kernel/btf/vmlinux` whenever `elf::needs_kernel_btf()` — CO-RE relos
*or* BTF-typed exec sections (`btf::is_btf_ctx_section`).

A BTF-typed section whose attach target is missing from the target BTF is
**not** a load error: real tools carry `fentry/dummy_*` placeholders
retargeted at runtime (`bpf_program__set_attach_target`) and names that only
exist on some kernel versions (`account_page_dirtied`, …). Matching
`bpf_object__open` (which also succeeds), the program falls back to the
untyped flat-ctx model and the loader records a warning in
`Object::warnings` (printed by the CLI). The kernel would reject actually
loading that program against that target — the warning says so.

## 5. What this unblocked, and where next

Corpus went 51/56 → **55/56** (bitesize, offcputime, runqlat, runqslower —
all `tp_btf` scalar-derefs of typed ctx pointers); the four also *execute*
under interp and JIT (kernel memory as zeroes → r0 = 0 paths). ksnoop
remains rejected by design (see `tracing-helpers.md`; needs linked scalar
ids once the corpus pin advances past bcc 0ae562c).

Natural extensions:
- **Real kernel images:** `febpf snapshot-kernel` (docs/ideas.md, migration
  phase 1) could back `Region::KernelMem` with captured struct contents
  instead of zeroes — the region/probe-mem mechanics already support any
  backing that keeps reads deterministic and writes faulting.
- **kfuncs / `bpf_rdonly_cast`** would reuse `PtrKind::BtfId` unchanged.
- Pointer-to-scalar ctx args (divergence in §1) if a real program needs them.
