//! Hand-written WebAssembly ABI (no wasm-bindgen).
//!
//! Strings cross the boundary through linear memory. Inputs are `(ptr, len)`
//! pairs the host writes into a buffer obtained from [`febpf_alloc`]. Results
//! are returned packed into a single `u64`: `(ptr as u64) << 32 | len as u64`
//! (wasm32 pointers are 32-bit). The host reads both halves, copies the UTF-8
//! out, then releases the buffer with [`febpf_free`].
//!
//! Buffers are owned as boxed slices so allocation and deallocation always
//! agree on capacity. Everything here is a thin marshalling layer over
//! [`crate::playground`], which holds the actual logic and is unit-tested
//! natively.

use crate::playground::{self, Session};
use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    static SESSIONS: RefCell<HashMap<u32, Session>> = RefCell::new(HashMap::new());
}

/// Allocate `len` bytes of linear memory and return a pointer to them.
#[no_mangle]
pub extern "C" fn febpf_alloc(len: usize) -> *mut u8 {
    let buf = vec![0u8; len].into_boxed_slice();
    Box::into_raw(buf) as *mut u8
}

/// Free a buffer previously returned by [`febpf_alloc`] or as a result buffer.
///
/// # Safety
/// `ptr`/`len` must exactly match a prior allocation.
#[no_mangle]
pub unsafe extern "C" fn febpf_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    let slice = std::slice::from_raw_parts_mut(ptr, len);
    drop(Box::from_raw(slice as *mut [u8]));
}

/// Pack an owned string into a leaked linear-memory buffer, returning
/// `(ptr << 32) | len`. The host frees it with [`febpf_free`].
fn ret(s: String) -> u64 {
    let boxed = s.into_bytes().into_boxed_slice();
    let len = boxed.len() as u64;
    let ptr = Box::into_raw(boxed) as *mut u8 as u64;
    (ptr << 32) | len
}

/// Borrow a `(ptr, len)` region as bytes for the duration of the call.
///
/// # Safety
/// Must describe a live buffer of at least `len` bytes.
unsafe fn slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, len)
    }
}

unsafe fn text<'a>(ptr: *const u8, len: usize) -> &'a str {
    std::str::from_utf8(slice(ptr, len)).unwrap_or("")
}

/// # Safety: `src` must describe a live buffer of `src_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn febpf_verify(src: *const u8, src_len: usize) -> u64 {
    ret(playground::verify_text(slice(src, src_len)))
}

/// # Safety: both `(src,*)` and `(ctx,*)` must describe live buffers.
#[no_mangle]
pub unsafe extern "C" fn febpf_run(
    src: *const u8,
    src_len: usize,
    ctx: *const u8,
    ctx_len: usize,
) -> u64 {
    ret(playground::run_text(slice(src, src_len), text(ctx, ctx_len)))
}

/// # Safety: `src` must describe a live buffer of `src_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn febpf_disasm(src: *const u8, src_len: usize) -> u64 {
    ret(playground::disasm_text(slice(src, src_len)))
}

/// # Safety: `src` must describe a live buffer of `src_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn febpf_analyze(src: *const u8, src_len: usize, mode: u32) -> u64 {
    ret(playground::analyze_text(slice(src, src_len), mode))
}

/// Create a debug session under a host-chosen `handle`. Returns "OK" or an
/// error string.
///
/// # Safety: both `(src,*)` and `(ctx,*)` must describe live buffers.
#[no_mangle]
pub unsafe extern "C" fn febpf_dbg_new(
    handle: u32,
    src: *const u8,
    src_len: usize,
    ctx: *const u8,
    ctx_len: usize,
) -> u64 {
    match Session::new(slice(src, src_len), text(ctx, ctx_len)) {
        Ok(s) => {
            SESSIONS.with(|m| m.borrow_mut().insert(handle, s));
            ret("OK".to_string())
        }
        Err(e) => ret(format!("ERR {e}")),
    }
}

/// Run one debugger command against `handle`.
///
/// # Safety: `cmd` must describe a live buffer of `cmd_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn febpf_dbg_cmd(handle: u32, cmd: *const u8, cmd_len: usize) -> u64 {
    let line = text(cmd, cmd_len).to_string();
    let out = SESSIONS.with(|m| match m.borrow_mut().get_mut(&handle) {
        Some(s) => s.command(&line),
        None => format!("no session {handle}"),
    });
    ret(out)
}

/// Destroy a debug session.
#[no_mangle]
pub extern "C" fn febpf_dbg_free(handle: u32) {
    SESSIONS.with(|m| m.borrow_mut().remove(&handle));
}

/// Self-test: exercise the whole engine in-wasm with no memory marshalling, so
/// the compiled binary can be smoke-tested with a single integer-returning
/// call (`wasmtime --invoke febpf_selftest`). Returns a bitmask; 15 = all four
/// checks passed.
#[no_mangle]
pub extern "C" fn febpf_selftest() -> i64 {
    let good = b"r0 = 0\nr1 = 10\nloop:\nr0 += r1\nr1 -= 1\nif r1 != 0 goto loop\nexit\n";
    let bad = b"exit\n"; // r0 never initialised -> verifier rejects

    let mut bits = 0i64;
    if playground::verify_text(good).contains("PASSED") {
        bits |= 1;
    }
    if playground::run_text(good, "").contains("r0 = 55") {
        bits |= 2;
    }
    if playground::verify_text(bad).contains("FAILED") {
        bits |= 4;
    }
    if let Ok(mut s) = Session::new(good, "") {
        let _ = s.command("step 3");
        if s.command("regs").contains("insns executed = 3") {
            bits |= 8;
        }
    }
    bits
}
