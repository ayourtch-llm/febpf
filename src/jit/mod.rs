//! Architecture-independent JIT frontend.
//!
//! The JIT is split into a **frontend** (this module) and per-architecture
//! **backends** (x86-64 Linux in `x64`, arm64 macOS in `aarch64`). The
//! frontend does everything that is pure eBPF logic and identical on every
//! CPU:
//!
//! - classify each instruction as *native* (compiled to machine code) or
//!   *deferred* (executed by the interpreter core via a trampoline),
//! - drive the emit loop, calling abstract [`JitBackend`] methods,
//! - own the `pc → native address` table and executable-memory allocation,
//! - coordinate two-phase finalization (relative branch fixups, then
//!   absolute-pointer patches once the code has a final address).
//!
//! A backend is a mechanical instruction encoder: it never reasons about
//! eBPF semantics, only about how to emit "add these two registers" or
//! "branch if equal" for its ISA. Adding a new architecture (aarch64,
//! riscv64, …) means implementing [`JitBackend`] and nothing else — see
//! `docs/specs/jit-backend.md`.
//!
//! # Safety model
//!
//! Only ALU and branch instructions are compiled to native code. Every
//! memory access, helper call, `lddw`, bpf-to-bpf call and `exit` is
//! *deferred*: the native code spills the register file, calls back into
//! [`crate::interp::Machine::jit_step_at`] (the same interpreter that runs
//! un-JITed code, with the same bounds-checked memory model), and resumes at
//! whatever pc the interpreter reports. The JIT therefore cannot introduce
//! memory-unsafety that the interpreter doesn't already prevent — it only
//! removes dispatch overhead from the arithmetic/control-flow core.

use crate::insn::*;

pub mod abi;
mod classify;

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub mod x64;

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
pub mod aarch64;

pub use classify::{AluOp, Cc, Lowering, RegOrImm, ShiftOp, Width};

/// Symbolic branch target used while emitting, resolved during finalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The native code for eBPF instruction `pc`.
    Pc(usize),
    /// The shared function epilogue (used on program stop / fault).
    Epilogue,
}

/// The porting surface. A backend emits machine code for one architecture.
///
/// The frontend calls these in a fixed order:
/// 1. [`prologue`](JitBackend::prologue)
/// 2. for each instruction slot: [`mark_label`](JitBackend::mark_label),
///    then either the matching native emitter or
///    [`deferred`](JitBackend::deferred)
/// 3. [`epilogue`](JitBackend::epilogue)
/// 4. [`resolve_branches`](JitBackend::resolve_branches) (relative fixups)
/// 5. code is copied into executable memory, then
///    [`patch_absolutes`](JitBackend::patch_absolutes)
///
/// Registers are referred to by eBPF index (`0..=10`); the backend owns the
/// mapping to physical registers. See the trait contract in
/// `docs/specs/jit-backend.md`.
pub trait JitBackend {
    fn new(num_insns: usize) -> Self
    where
        Self: Sized;

    /// The machine code emitted so far.
    fn code(&self) -> &[u8];

    /// Record that instruction `pc`'s native code starts at the current
    /// offset. Called once per real instruction (never for `lddw` tail
    /// slots).
    fn mark_label(&mut self, pc: usize);

    /// Function entry: save callee-saved registers, stash the two incoming
    /// arguments (`regs_ptr`, `machine_ptr`), and load the eBPF register file
    /// into physical registers. Control then falls through into pc 0.
    fn prologue(&mut self);

    /// Function exit: restore callee-saved registers and return. The backend
    /// records the epilogue's offset internally for [`Target::Epilogue`].
    fn epilogue(&mut self);

    // ---- native ALU (operands are eBPF register indices) ----
    fn alu_reg(&mut self, op: AluOp, w: Width, dst: u8, src: u8);
    fn alu_imm(&mut self, op: AluOp, w: Width, dst: u8, imm: i32);
    fn mov_reg(&mut self, w: Width, dst: u8, src: u8);
    fn mov_imm(&mut self, w: Width, dst: u8, imm: i32);
    fn neg(&mut self, w: Width, dst: u8);
    fn shift_imm(&mut self, op: ShiftOp, w: Width, dst: u8, amount: u8);

    // ---- native control flow ----
    fn jump(&mut self, target: Target);
    /// Branch to `target` when `dst CC rhs` holds (signed/unsigned per `cc`).
    fn cond_branch(&mut self, cc: Cc, w: Width, dst: u8, rhs: RegOrImm, target: Target);
    /// Branch to `target` when `(dst & rhs) != 0` (the `JSET` instruction).
    fn jset_branch(&mut self, w: Width, dst: u8, rhs: RegOrImm, target: Target);

    // ---- deferred instructions ----
    /// Emit the trampoline glue for the instruction at `pc`: spill the eBPF
    /// registers, call the trampoline, and either jump to the epilogue (stop
    /// bit set) or reload and indirect-jump through the pc→address table.
    fn deferred(&mut self, pc: usize);

    // ---- finalization ----
    /// Patch relative branch fixups now that every label offset is known.
    /// `label_off[pc] == usize::MAX` marks a slot with no code (jump such
    /// targets to `epilogue_off`).
    ///
    /// Returns `Err` if a fixup cannot be encoded — on ISAs with short branch
    /// displacements (aarch64's ±1MiB `B.cond`) a huge program can exceed the
    /// range. Compilation then fails cleanly and the caller falls back to the
    /// interpreter, rather than the backend emitting a wrong branch.
    fn resolve_branches(&mut self, label_off: &[usize], epilogue_off: usize) -> Result<(), String>;

    /// The byte offset of the epilogue within [`code`](JitBackend::code).
    fn epilogue_off(&self) -> usize;

    /// After the code is at its final address, patch absolute pointers: the
    /// trampoline function address and the pc→address table base.
    fn patch_absolutes(&self, code: &mut [u8], trampoline: u64, table: u64);
}

/// A finished, executable native program.
pub struct JitProgram {
    mem: ExecMem,
    /// `pc → absolute native address`; kept alive because the code indexes it.
    _table: Vec<u64>,
    entry: usize,
}

impl JitProgram {
    /// Enter the compiled program. Runs until the program exits or a deferred
    /// instruction faults (both recorded in the [`Machine`](crate::interp::Machine)).
    ///
    /// # Safety
    /// Executes JIT-generated machine code. The code only mutates `m`'s
    /// register file and calls back through the trampoline; the caller must
    /// keep `m` valid for the duration.
    pub unsafe fn enter(&self, m: &mut crate::interp::Machine) {
        let regs_ptr = m.regs_ptr();
        let machine_ptr = m as *mut crate::interp::Machine as *mut ();
        let f: EnterFn = std::mem::transmute(self.mem.ptr.add(self.entry));
        f(regs_ptr, machine_ptr);
    }
}

/// ABI of the compiled function: `(regs_ptr, machine_ptr)`.
type EnterFn = unsafe extern "C" fn(*mut u64, *mut ());

/// The C trampoline invoked by deferred glue. `machine` is a type-erased
/// `*mut Machine`; the pointer is valid for the call's duration.
pub(crate) extern "C" fn trampoline(machine: *mut (), pc: u64) -> u64 {
    // Safety: `machine` is the pointer handed to `enter`, live for this call.
    // The lifetime parameter of `Machine` does not affect layout, so erasing
    // and restoring it through `*mut ()` is sound for the call.
    let m = unsafe { &mut *(machine as *mut crate::interp::Machine<'static>) };
    m.jit_step_at(pc as usize)
}

/// Compile `insns` for the host architecture.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub fn compile(insns: &[Insn]) -> Result<JitProgram, String> {
    compile_with::<x64::X64Backend>(insns)
}

/// Compile `insns` for the host architecture.
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
pub fn compile(insns: &[Insn]) -> Result<JitProgram, String> {
    compile_with::<aarch64::Aarch64Backend>(insns)
}

#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "linux"),
    all(target_arch = "aarch64", target_os = "macos")
)))]
pub fn compile(_insns: &[Insn]) -> Result<JitProgram, String> {
    Err("JIT is only implemented for x86-64 Linux and arm64 macOS (see \
         docs/specs/jit-backend.md to add another architecture)"
        .into())
}

/// The architecture-independent compile pipeline, generic over the backend.
pub fn compile_with<B: JitBackend>(insns: &[Insn]) -> Result<JitProgram, String> {
    let n = insns.len();
    let mut b = B::new(n);
    let mut label_off = vec![usize::MAX; n];

    b.prologue();

    let mut pc = 0;
    while pc < n {
        b.mark_label(pc);
        label_off[pc] = b.code().len();
        let width = if insns[pc].is_wide() { 2 } else { 1 };
        match classify::lower(insns[pc]) {
            Lowering::Deferred => b.deferred(pc),
            Lowering::AluReg { op, w, dst, src } => b.alu_reg(op, w, dst, src),
            Lowering::AluImm { op, w, dst, imm } => b.alu_imm(op, w, dst, imm),
            Lowering::MovReg { w, dst, src } => b.mov_reg(w, dst, src),
            Lowering::MovImm { w, dst, imm } => b.mov_imm(w, dst, imm),
            Lowering::Neg { w, dst } => b.neg(w, dst),
            Lowering::ShiftImm { op, w, dst, amount } => b.shift_imm(op, w, dst, amount),
            Lowering::Jump { target } => b.jump(rel_target(pc, target)),
            Lowering::CondBranch { cc, w, dst, rhs, off } => {
                b.cond_branch(cc, w, dst, rhs, rel_target(pc, off))
            }
            Lowering::JsetBranch { w, dst, rhs, off } => {
                b.jset_branch(w, dst, rhs, rel_target(pc, off))
            }
        }
        pc += width;
    }

    b.epilogue();
    let epi = b.epilogue_off();
    b.resolve_branches(&label_off, epi)?;

    // Move the code into executable memory.
    let code = b.code().to_vec();
    let mut mem = ExecMem::new(code.len())?;
    // Safety: `mem` is a fresh RW mapping of exactly `code.len()` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(code.as_ptr(), mem.ptr, code.len());
    }

    // Build the pc→address table now that we know the base address.
    let base = mem.ptr as u64;
    let epilogue_addr = base + b.epilogue_off() as u64;
    let table: Vec<u64> = (0..n)
        .map(|pc| {
            if label_off[pc] == usize::MAX {
                epilogue_addr
            } else {
                base + label_off[pc] as u64
            }
        })
        .collect();

    // Patch absolute pointers into the copied code, then seal it.
    let code_slice = unsafe { std::slice::from_raw_parts_mut(mem.ptr, mem.len) };
    b.patch_absolutes(code_slice, trampoline as *const () as u64, table.as_ptr() as u64);
    mem.make_executable()?;

    Ok(JitProgram {
        mem,
        _table: table,
        entry: 0,
    })
}

fn rel_target(pc: usize, off: i16) -> Target {
    Target::Pc((pc as i64 + 1 + off as i64) as usize)
}

// ---------------------------------------------------------------------------
// Executable memory (Linux, no libc)
// ---------------------------------------------------------------------------

struct ExecMem {
    ptr: *mut u8,
    len: usize,
}

// The pointer is only used to run code we own; it is not shared across
// threads by febpf itself.
unsafe impl Send for ExecMem {}

impl ExecMem {
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fn new(len: usize) -> Result<ExecMem, String> {
        let len = len.max(1);
        let ptr = unsafe { sys::mmap_rw(len) }?;
        Ok(ExecMem { ptr, len })
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fn make_executable(&mut self) -> Result<(), String> {
        unsafe { sys::mprotect_rx(self.ptr, self.len) }
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    fn new(len: usize) -> Result<ExecMem, String> {
        let len = len.max(1);
        let ptr = unsafe { macsys::mmap_jit(len) }?;
        Ok(ExecMem { ptr, len })
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    fn make_executable(&mut self) -> Result<(), String> {
        unsafe { macsys::seal_and_flush(self.ptr, self.len) };
        Ok(())
    }

    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "linux"),
        all(target_arch = "aarch64", target_os = "macos")
    )))]
    fn new(_len: usize) -> Result<ExecMem, String> {
        Err("executable memory allocation unsupported on this platform".into())
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "linux"),
        all(target_arch = "aarch64", target_os = "macos")
    )))]
    fn make_executable(&mut self) -> Result<(), String> {
        Ok(())
    }
}

impl Drop for ExecMem {
    fn drop(&mut self) {
        #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
        unsafe {
            sys::munmap(self.ptr, self.len);
        }
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        unsafe {
            macsys::unmap(self.ptr, self.len);
        }
    }
}

/// W^X JIT memory on macOS/Apple Silicon, via libSystem — which every macOS
/// process links anyway, so this adds no crate dependency (raw syscalls are
/// not a stable ABI on Darwin).
///
/// Apple Silicon enforces strict W^X: JIT code must live in a `MAP_JIT`
/// mapping, writes are gated per-thread by `pthread_jit_write_protect_np`,
/// and the instruction cache must be flushed before execution. `mmap_jit`
/// leaves the calling thread's write gate open; `compile_with` performs all
/// writes on that same thread before `seal_and_flush` closes the gate.
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
mod macsys {
    use core::ffi::c_void;

    extern "C" {
        fn mmap(addr: *mut c_void, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut c_void;
        fn munmap(addr: *mut c_void, len: usize) -> i32;
        fn pthread_jit_write_protect_np(enabled: i32);
        fn sys_icache_invalidate(start: *mut c_void, len: usize);
        fn __error() -> *mut i32;
    }

    const PROT_READ: i32 = 0x1;
    const PROT_WRITE: i32 = 0x2;
    const PROT_EXEC: i32 = 0x4;
    const MAP_PRIVATE: i32 = 0x0002;
    const MAP_ANON: i32 = 0x1000;
    const MAP_JIT: i32 = 0x0800;

    pub unsafe fn mmap_jit(len: usize) -> Result<*mut u8, String> {
        let p = mmap(
            core::ptr::null_mut(),
            len,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANON | MAP_JIT,
            -1,
            0,
        );
        if p as isize == -1 {
            return Err(format!("mmap(MAP_JIT) failed (errno {})", *__error()));
        }
        // Open this thread's write gate so the frontend can copy and patch.
        pthread_jit_write_protect_np(0);
        Ok(p as *mut u8)
    }

    pub unsafe fn seal_and_flush(ptr: *mut u8, len: usize) {
        pthread_jit_write_protect_np(1);
        sys_icache_invalidate(ptr as *mut c_void, len);
    }

    pub unsafe fn unmap(ptr: *mut u8, len: usize) {
        munmap(ptr as *mut c_void, len);
    }
}

/// Raw Linux syscalls for W^X code memory — keeps the crate dependency-free.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod sys {
    use std::arch::asm;

    const PROT_READ: usize = 0x1;
    const PROT_WRITE: usize = 0x2;
    const PROT_EXEC: usize = 0x4;
    const MAP_PRIVATE: usize = 0x2;
    const MAP_ANONYMOUS: usize = 0x20;

    pub unsafe fn mmap_rw(len: usize) -> Result<*mut u8, String> {
        let ret: isize;
        asm!(
            "syscall",
            inlateout("rax") 9isize => ret, // SYS_mmap
            in("rdi") 0usize,               // addr = NULL
            in("rsi") len,
            in("rdx") PROT_READ | PROT_WRITE,
            in("r10") MAP_PRIVATE | MAP_ANONYMOUS,
            in("r8") -1isize,               // fd
            in("r9") 0usize,                // offset
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
        if (-4095..0).contains(&ret) {
            return Err(format!("mmap failed (errno {})", -ret));
        }
        Ok(ret as *mut u8)
    }

    pub unsafe fn mprotect_rx(ptr: *mut u8, len: usize) -> Result<(), String> {
        let ret: isize;
        asm!(
            "syscall",
            inlateout("rax") 10isize => ret, // SYS_mprotect
            in("rdi") ptr,
            in("rsi") len,
            in("rdx") PROT_READ | PROT_EXEC,
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
        if ret != 0 {
            return Err(format!("mprotect failed (errno {})", -ret));
        }
        Ok(())
    }

    pub unsafe fn munmap(ptr: *mut u8, len: usize) {
        asm!(
            "syscall",
            inlateout("rax") 11isize => _, // SYS_munmap
            in("rdi") ptr,
            in("rsi") len,
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
    }
}
