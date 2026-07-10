//! The trampoline ABI — the contract shared by the frontend, every backend,
//! and the interpreter trampoline. Architecture-independent.
//!
//! ## Compiled-function entry
//!
//! `extern "C" fn(regs_ptr: *mut u64, machine_ptr: *mut ())`
//! - `regs_ptr` points at the eBPF register file `[u64; 11]` (r0..r10). The
//!   prologue loads it into physical registers; deferred glue spills to and
//!   reloads from it.
//! - `machine_ptr` is a type-erased `*mut Machine`, passed unchanged to the
//!   trampoline.
//!
//! ## Trampoline
//!
//! `extern "C" fn(machine_ptr: *mut (), pc: u64) -> u64`
//! - Executes exactly the instruction at `pc` on the interpreter core.
//! - Returns the next `pc` to run, **or** [`STOP`] when the program has
//!   exited or a deferred instruction faulted. The caller distinguishes exit
//!   from fault by checking `Machine::take_jit_fault` afterwards; on a clean
//!   exit the return value `r0` is already in `regs[0]`.
//!
//! Because a real pc is always a small in-range index, [`STOP`] is encoded
//! with the high bit set, which no valid pc can have. Backends test that one
//! bit to decide "resume" vs "leave via epilogue".

/// Returned by the trampoline to mean "stop executing" (program exit or
/// fault). The high bit is set so a simple sign test distinguishes it from a
/// genuine next-pc.
pub const STOP: u64 = 1 << 63;

/// Number of eBPF registers spilled/reloaded across a trampoline call.
pub const NUM_REGS: usize = crate::insn::NUM_REGS;
