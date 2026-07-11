//! Raw `bpf(2)` syscall layer for kernel conformance testing.
//!
//! Zero-dependency: the kernel is reached through inline `asm!` on
//! `syscall` number `321` (`SYS_bpf` on x86-64 Linux), the same technique the
//! JIT's `sys` module uses for `mmap`/`mprotect`. No libc, no libbpf.
//!
//! `union bpf_attr` is not modelled as a Rust type. Instead each command
//! writes its fields at their exact C byte offsets into a zeroed 128-byte
//! buffer and passes `size = 128`; the kernel copies those bytes and
//! zero-fills the rest of its own `attr`. See `docs/specs/conftest.md` for the
//! offset tables this file encodes.
//!
//! Everything here is gated to x86-64 Linux; on other targets the public API
//! degrades to "kernel unavailable" so the rest of the crate still builds.

use crate::insn::{encode_program, Insn};
use crate::maps::{MapDef, MapKind};

/// Outcome of a `bpf(2)` operation: an fd/return value, or a raw `-errno`.
pub type KResult<T> = Result<T, KError>;

/// A `bpf(2)` failure, carrying the errno and a human label.
#[derive(Debug, Clone)]
pub struct KError {
    pub errno: i32,
    pub what: String,
}

impl std::fmt::Display for KError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed (errno {}: {})", self.what, self.errno, errno_str(self.errno))
    }
}
impl std::error::Error for KError {}

impl KError {
    /// True when the failure is a privilege problem (EPERM/EACCES).
    pub fn is_permission(&self) -> bool {
        self.errno == 1 || self.errno == 13 // EPERM / EACCES
    }
}

fn errno_str(e: i32) -> &'static str {
    match e {
        1 => "EPERM",
        2 => "ENOENT",
        7 => "E2BIG",
        13 => "EACCES",
        14 => "EFAULT",
        22 => "EINVAL",
        28 => "ENOSPC",
        _ => "?",
    }
}

// ---- bpf_cmd ordinals (stable UAPI) --------------------------------------
const BPF_MAP_CREATE: i32 = 0;
const BPF_MAP_UPDATE_ELEM: i32 = 2;
const BPF_PROG_LOAD: i32 = 5;
const BPF_PROG_TEST_RUN: i32 = 10;

// ---- program & map types --------------------------------------------------
/// `BPF_PROG_TYPE_SOCKET_FILTER`: loadable and TEST_RUN-able unprivileged of
/// attachment, and its TEST_RUN returns the program's `r0` as `retval`.
const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;

// ---- lddw pseudo src_reg values the kernel understands --------------------
const BPF_PSEUDO_MAP_FD: u8 = 1;
const BPF_PSEUDO_MAP_VALUE: u8 = 3;

/// The eBPF ISA `lddw` opcode (`BPF_LD | BPF_IMM | BPF_DW`).
const LDDW_OPCODE: u8 = 0x18;

/// Fixed attr buffer size: covers every field offset used below and is well
/// under the kernel's `sizeof(union bpf_attr)`.
const ATTR_SIZE: usize = 128;

// ===========================================================================
// x86-64 Linux implementation
// ===========================================================================
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod imp {
    use super::*;
    use std::arch::asm;

    /// Raw `bpf(2)`: `syscall(321, cmd, attr, size)`. Returns the kernel's
    /// signed result (fd/return value >= 0, or `-errno`). The pointer must be
    /// `*mut`: some commands (TEST_RUN) write results back into the attr.
    unsafe fn sys_bpf(cmd: i32, attr: *mut u8, size: usize) -> isize {
        let ret: isize;
        asm!(
            "syscall",
            inlateout("rax") 321isize => ret, // SYS_bpf
            in("rdi") cmd as usize,
            in("rsi") attr,
            in("rdx") size,
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
        ret
    }

    fn call(cmd: i32, attr: &mut [u8; ATTR_SIZE], what: &str) -> KResult<i32> {
        // Safety: `attr` is a valid, fully-initialized 128-byte buffer; the
        // kernel reads `size` bytes and never retains the pointer. It must be
        // a mutable borrow: TEST_RUN writes `retval` (offset 4) back into it,
        // and through a shared reference the compiler is free to assume the
        // buffer unchanged and fold the read-back to its old value (this
        // exact miscompile shipped: kernel retval always read as 0 in
        // release builds).
        let ret = unsafe { sys_bpf(cmd, attr.as_mut_ptr(), ATTR_SIZE) };
        if (-4095..0).contains(&ret) {
            Err(KError {
                errno: (-ret) as i32,
                what: what.to_string(),
            })
        } else {
            Ok(ret as i32)
        }
    }

    fn close(fd: i32) {
        // Safety: plain close(2); ignore the result.
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") 3isize => _, // SYS_close
                in("rdi") fd as usize,
                lateout("rcx") _, lateout("r11") _,
                options(nostack),
            );
        }
    }

    // -- little helpers to write fields at exact offsets --------------------
    fn put_u32(b: &mut [u8; ATTR_SIZE], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u64(b: &mut [u8; ATTR_SIZE], off: usize, v: u64) {
        b[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn ptr(v: &[u8]) -> u64 {
        v.as_ptr() as u64
    }

    /// An owned kernel fd, closed on drop.
    pub struct Fd(pub i32);
    impl Drop for Fd {
        fn drop(&mut self) {
            close(self.0);
        }
    }

    /// Attempt to load a trivial `mov r0,0; exit` program. `Ok(())` means we
    /// have the privilege to load BPF programs; a permission error means we
    /// don't. Any other error is surfaced (unexpected environment problem).
    pub fn probe() -> KResult<()> {
        let insns = [
            Insn { opcode: 0xb7, dst: 0, src: 0, off: 0, imm: 0 }, // mov64 r0, 0
            Insn { opcode: 0x95, dst: 0, src: 0, off: 0, imm: 0 }, // exit
        ];
        let fd = prog_load(&insns, None)?;
        drop(fd);
        Ok(())
    }

    /// `BPF_PROG_LOAD` a SOCKET_FILTER program. On rejection, if `log` is
    /// `Some`, the kernel verifier's message is captured into it.
    pub fn prog_load(insns: &[Insn], log: Option<&mut String>) -> KResult<Fd> {
        let code = encode_program(insns);
        let license = b"GPL\0";
        // Optional verifier-log buffer.
        let logbuf = vec![0u8; if log.is_some() { 16 * 1024 } else { 0 }];

        let mut a = [0u8; ATTR_SIZE];
        put_u32(&mut a, 0, BPF_PROG_TYPE_SOCKET_FILTER);
        put_u32(&mut a, 4, insns.len() as u32);
        put_u64(&mut a, 8, ptr(&code));
        put_u64(&mut a, 16, ptr(license));
        if !logbuf.is_empty() {
            put_u32(&mut a, 24, 1); // log_level = 1
            put_u32(&mut a, 28, logbuf.len() as u32);
            put_u64(&mut a, 32, ptr(&logbuf));
        }

        let r = call(BPF_PROG_LOAD, &mut a, "BPF_PROG_LOAD");
        if let Some(dst) = log {
            let end = logbuf.iter().position(|&b| b == 0).unwrap_or(logbuf.len());
            *dst = String::from_utf8_lossy(&logbuf[..end]).into_owned();
        }
        r.map(Fd)
    }

    /// `BPF_MAP_CREATE` a map matching `def`. Returns the new map fd.
    pub fn map_create(def: &MapDef) -> KResult<Fd> {
        let map_type = match def.kind {
            MapKind::Array => BPF_MAP_TYPE_ARRAY,
            MapKind::Hash => BPF_MAP_TYPE_HASH,
        };
        let mut a = [0u8; ATTR_SIZE];
        put_u32(&mut a, 0, map_type);
        put_u32(&mut a, 4, def.key_size);
        put_u32(&mut a, 8, def.value_size);
        put_u32(&mut a, 12, def.max_entries);
        // map_name[16] at offset 28 (best-effort, truncated).
        let name = def.name.as_bytes();
        let n = name.len().min(15);
        a[28..28 + n].copy_from_slice(&name[..n]);
        call(BPF_MAP_CREATE, &mut a, "BPF_MAP_CREATE").map(Fd)
    }

    /// `BPF_MAP_UPDATE_ELEM` with `BPF_ANY`.
    pub fn map_update(fd: i32, key: &[u8], value: &[u8]) -> KResult<()> {
        let mut a = [0u8; ATTR_SIZE];
        put_u32(&mut a, 0, fd as u32);
        put_u64(&mut a, 8, ptr(key));
        put_u64(&mut a, 16, ptr(value));
        put_u64(&mut a, 24, 0); // BPF_ANY
        call(BPF_MAP_UPDATE_ELEM, &mut a, "BPF_MAP_UPDATE_ELEM").map(|_| ())
    }

    /// `BPF_PROG_TEST_RUN`. Returns the program's `retval` (its `r0` as u32).
    pub fn test_run(prog_fd: i32, data_in: &[u8]) -> KResult<u32> {
        // SOCKET_FILTER TEST_RUN needs at least ETH_HLEN (14) input bytes.
        let mut input = data_in.to_vec();
        if input.len() < 16 {
            input.resize(16, 0);
        }
        let out = vec![0u8; input.len()];
        let mut a = [0u8; ATTR_SIZE];
        put_u32(&mut a, 0, prog_fd as u32);
        put_u32(&mut a, 8, input.len() as u32); // data_size_in
        put_u32(&mut a, 12, out.len() as u32); // data_size_out
        put_u64(&mut a, 16, ptr(&input)); // data_in
        put_u64(&mut a, 24, ptr(&out)); // data_out
        put_u32(&mut a, 32, 1); // repeat
        call(BPF_PROG_TEST_RUN, &mut a, "BPF_PROG_TEST_RUN")?;
        // retval is written back into the attr buffer at offset 4.
        Ok(u32::from_le_bytes([a[4], a[5], a[6], a[7]]))
    }
}

// ===========================================================================
// Non-x86-64-Linux stub
// ===========================================================================
#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
mod imp {
    use super::*;

    pub struct Fd(pub i32);

    fn unsupported(what: &str) -> KError {
        KError {
            errno: 38, // ENOSYS
            what: what.to_string(),
        }
    }

    pub fn probe() -> KResult<()> {
        Err(unsupported("bpf(2)"))
    }
    pub fn prog_load(_insns: &[Insn], _log: Option<&mut String>) -> KResult<Fd> {
        Err(unsupported("BPF_PROG_LOAD"))
    }
    pub fn map_create(_def: &MapDef) -> KResult<Fd> {
        Err(unsupported("BPF_MAP_CREATE"))
    }
    pub fn map_update(_fd: i32, _key: &[u8], _value: &[u8]) -> KResult<()> {
        Err(unsupported("BPF_MAP_UPDATE_ELEM"))
    }
    pub fn test_run(_prog_fd: i32, _data_in: &[u8]) -> KResult<u32> {
        Err(unsupported("BPF_PROG_TEST_RUN"))
    }
}

pub use imp::Fd;

/// Does this process have the privilege to load BPF programs? Probes by
/// loading a trivial program. Returns `Ok(true)` if yes, `Ok(false)` on a
/// permission error, and `Err` on any other (unexpected) failure.
pub fn has_privilege() -> KResult<bool> {
    match imp::probe() {
        Ok(()) => Ok(true),
        Err(e) if e.is_permission() => Ok(false),
        Err(e) => Err(e),
    }
}

/// The kernel verifier's *verdict* for a map-free program: `Ok(())` = the
/// kernel accepted (loaded) it, `Err(KError)` = it rejected the program (a
/// load/verify error). On rejection, if `log` is `Some`, the kernel verifier's
/// message is captured into it for triage.
///
/// This reuses [`imp::prog_load`], so the `bpf(2)` attr keeps mutable
/// provenance all the way to the syscall (the kernel writes back into it — a
/// shared reference miscompiles in release builds). On acceptance the returned
/// fd is dropped immediately, closing the loaded program.
pub fn verdict(insns: &[Insn], log: Option<&mut String>) -> KResult<()> {
    imp::prog_load(insns, log).map(|_fd| ())
}

/// Load a program (creating its maps and rewriting map-reference `lddw`
/// instructions to kernel fds), TEST_RUN it on `data_in`, and return the
/// kernel `retval`. The created fds live until the returned value drops — but
/// since we only need `retval`, everything is closed before returning.
pub fn run_program(
    insns: &[Insn],
    maps: &[MapDef],
    data_in: &[u8],
    log: Option<&mut String>,
) -> KResult<u32> {
    // Create kernel maps and remember their fds by original map index.
    let mut map_fds: Vec<Fd> = Vec::with_capacity(maps.len());
    for def in maps {
        let fd = imp::map_create(def)?;
        // Seed initial contents for global-data maps (single array element 0).
        if !def.init.is_empty() && def.kind == MapKind::Array {
            let key = 0u32.to_ne_bytes();
            let mut val = vec![0u8; def.value_size as usize];
            let n = def.init.len().min(val.len());
            val[..n].copy_from_slice(&def.init[..n]);
            imp::map_update(fd.0, &key, &val)?;
        }
        map_fds.push(fd);
    }

    // Rewrite map-reference lddw instructions to carry kernel fds.
    let mut prog: Vec<Insn> = insns.to_vec();
    let mut pc = 0;
    while pc < prog.len() {
        let ins = prog[pc];
        let wide = ins.opcode == LDDW_OPCODE;
        if wide {
            let m = ins.imm as usize;
            match ins.src {
                // src=1 (MAP_ID/MAP_FD): dst gets a map object pointer.
                1 => {
                    let fd = map_fds
                        .get(m)
                        .ok_or_else(|| KError {
                            errno: 22,
                            what: format!("lddw references unknown map {m}"),
                        })?;
                    prog[pc].src = BPF_PSEUDO_MAP_FD;
                    prog[pc].imm = fd.0;
                }
                // src=2 (MAP_VALUE): dst gets a pointer to a map value; the
                // second slot's imm carries the byte offset (kept as-is).
                2 => {
                    let fd = map_fds
                        .get(m)
                        .ok_or_else(|| KError {
                            errno: 22,
                            what: format!("lddw references unknown map {m}"),
                        })?;
                    prog[pc].src = BPF_PSEUDO_MAP_VALUE;
                    prog[pc].imm = fd.0;
                }
                _ => {}
            }
            pc += 2;
        } else {
            pc += 1;
        }
    }

    let prog_fd = imp::prog_load(&prog, log)?;
    let retval = imp::test_run(prog_fd.0, data_in)?;
    drop(prog_fd);
    drop(map_fds);
    Ok(retval)
}
