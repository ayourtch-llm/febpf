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

use crate::insn::Insn;
use crate::maps::{Map, MapDef, MapKind};

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

    /// True when `bpf(2)` does not exist on this platform at all — the
    /// non-Linux stub reports ENOSYS. Distinct from the kernel *refusing* the
    /// call: there is no kernel BPF here to refuse it.
    pub fn is_unsupported(&self) -> bool {
        self.errno == 38 // ENOSYS
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
        38 => "ENOSYS",
        75 => "EOVERFLOW",
        _ => "?",
    }
}

/// The `bpf(2)` UAPI constants. Only the x86-64-Linux `imp` below issues the
/// syscall — everywhere else it is a stub — so gate them as a unit rather than
/// letting them read as dead code on macOS and aarch64 (`imp` picks them up
/// through its `use super::*`).
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
use uapi::*;

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod uapi {
    // ---- bpf_cmd ordinals (stable UAPI) ----------------------------------
    pub const BPF_MAP_CREATE: i32 = 0;
    pub const BPF_MAP_UPDATE_ELEM: i32 = 2;
    pub const BPF_PROG_LOAD: i32 = 5;
    pub const BPF_PROG_TEST_RUN: i32 = 10;

    // ---- program & map types ---------------------------------------------
    /// `BPF_PROG_TYPE_SOCKET_FILTER`: loadable and TEST_RUN-able unprivileged
    /// of attachment, and its TEST_RUN returns the program's `r0` as `retval`.
    pub const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
    /// `BPF_PROG_TYPE_XDP`: direct packet access through `xdp_md.data` /
    /// `data_end`, and TEST_RUN copies the possibly-mutated packet back.
    pub const BPF_PROG_TYPE_XDP: u32 = 6;
    pub const BPF_MAP_TYPE_HASH: u32 = 1;
    pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
    pub const BPF_MAP_TYPE_PROG_ARRAY: u32 = 3;
    pub const BPF_MAP_TYPE_PERF_EVENT_ARRAY: u32 = 4;
    pub const BPF_MAP_TYPE_PERCPU_HASH: u32 = 5;
    pub const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
    pub const BPF_MAP_TYPE_STACK_TRACE: u32 = 7;
    pub const BPF_MAP_TYPE_CGROUP_ARRAY: u32 = 8;
    pub const BPF_MAP_TYPE_LRU_HASH: u32 = 9;
    pub const BPF_MAP_TYPE_DEVMAP: u32 = 14;
    pub const BPF_MAP_TYPE_CPUMAP: u32 = 16;
    pub const BPF_MAP_TYPE_XSKMAP: u32 = 17;
    pub const BPF_MAP_TYPE_DEVMAP_HASH: u32 = 25;
    pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;

    /// Fixed attr buffer size: covers every field offset used below and is
    /// well under the kernel's `sizeof(union bpf_attr)`.
    pub const ATTR_SIZE: usize = 128;
}

// These three are used by the map-`lddw` rewriting, which is plain data
// munging compiled on every platform — so they are not part of `uapi`.
// ---- lddw pseudo src_reg values the kernel understands --------------------
const BPF_PSEUDO_MAP_FD: u8 = 1;
const BPF_PSEUDO_MAP_VALUE: u8 = 3;

/// The eBPF ISA `lddw` opcode (`BPF_LD | BPF_IMM | BPF_DW`).
const LDDW_OPCODE: u8 = 0x18;

// ===========================================================================
// x86-64 Linux implementation
// ===========================================================================
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod imp {
    use super::*;
    use crate::insn::encode_program;
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
    fn mut_ptr(v: &mut [u8]) -> u64 {
        v.as_mut_ptr() as u64
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

    /// `BPF_PROG_LOAD` with the selected program type. On rejection, if
    /// `log` is `Some`, the kernel verifier's message is captured into it.
    fn prog_load_type(
        insns: &[Insn],
        prog_type: u32,
        log: Option<&mut String>,
    ) -> KResult<Fd> {
        let code = encode_program(insns);
        let license = b"GPL\0";
        // Optional verifier-log buffer.
        let logbuf = vec![0u8; if log.is_some() { 16 * 1024 } else { 0 }];

        let mut a = [0u8; ATTR_SIZE];
        put_u32(&mut a, 0, prog_type);
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

    pub fn prog_load(insns: &[Insn], log: Option<&mut String>) -> KResult<Fd> {
        prog_load_type(insns, BPF_PROG_TYPE_SOCKET_FILTER, log)
    }

    pub fn prog_load_xdp(insns: &[Insn], log: Option<&mut String>) -> KResult<Fd> {
        prog_load_type(insns, BPF_PROG_TYPE_XDP, log)
    }

    /// `BPF_MAP_CREATE` a map matching `def`. Returns the new map fd.
    pub fn map_create(def: &MapDef, inner_map_fd: Option<i32>) -> KResult<Fd> {
        let map_type = match def.kind {
            MapKind::Array => BPF_MAP_TYPE_ARRAY,
            MapKind::ProgArray => BPF_MAP_TYPE_PROG_ARRAY,
            MapKind::ArrayOfMaps => 12,
            MapKind::HashOfMaps => 13,
            MapKind::Hash => BPF_MAP_TYPE_HASH,
            MapKind::PerCpuArray => BPF_MAP_TYPE_PERCPU_ARRAY,
            MapKind::PerCpuHash => BPF_MAP_TYPE_PERCPU_HASH,
            MapKind::LruHash => BPF_MAP_TYPE_LRU_HASH,
            MapKind::RingBuf => BPF_MAP_TYPE_RINGBUF,
            MapKind::PerfEventArray => BPF_MAP_TYPE_PERF_EVENT_ARRAY,
            MapKind::CgroupArray => BPF_MAP_TYPE_CGROUP_ARRAY,
            MapKind::StackTrace => BPF_MAP_TYPE_STACK_TRACE,
            MapKind::DevMap => BPF_MAP_TYPE_DEVMAP,
            MapKind::CpuMap => BPF_MAP_TYPE_CPUMAP,
            MapKind::DevMapHash => BPF_MAP_TYPE_DEVMAP_HASH,
            MapKind::XskMap => BPF_MAP_TYPE_XSKMAP,
        };
        let mut a = [0u8; ATTR_SIZE];
        put_u32(&mut a, 0, map_type);
        put_u32(&mut a, 4, def.key_size);
        put_u32(&mut a, 8, def.value_size);
        put_u32(&mut a, 12, def.max_entries);
        if let Some(fd) = inner_map_fd {
            put_u32(&mut a, 20, fd as u32);
        }
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

    /// `BPF_PROG_TEST_RUN`. Returns `retval` and the exact output packet.
    pub fn test_run(prog_fd: i32, data_in: &[u8], pad_socket_input: bool) -> KResult<TestRun> {
        if data_in.len() > u32::MAX as usize {
            return Err(KError {
                errno: 7, // E2BIG
                what: "BPF_PROG_TEST_RUN data_size_in".into(),
            });
        }
        let mut input = data_in.to_vec();
        // SOCKET_FILTER TEST_RUN needs at least ETH_HLEN (14) input bytes.
        // XDP must see the caller's exact packet, including short packets.
        if pad_socket_input && input.len() < 16 {
            input.resize(16, 0);
        }
        let mut out = vec![0u8; input.len()];
        let mut a = [0u8; ATTR_SIZE];
        put_u32(&mut a, 0, prog_fd as u32);
        put_u32(&mut a, 8, input.len() as u32); // data_size_in
        put_u32(&mut a, 12, out.len() as u32); // data_size_out
        put_u64(&mut a, 16, ptr(&input)); // data_in
        // The kernel writes through data_out. Preserve mutable provenance all
        // the way to the syscall, just as `call` does for the attr itself.
        put_u64(&mut a, 24, mut_ptr(&mut out)); // data_out
        put_u32(&mut a, 32, 1); // repeat
        call(BPF_PROG_TEST_RUN, &mut a, "BPF_PROG_TEST_RUN")?;
        // retval and data_size_out are written back into the attr buffer.
        let retval = u32::from_le_bytes([a[4], a[5], a[6], a[7]]);
        let out_len = u32::from_le_bytes([a[12], a[13], a[14], a[15]]) as usize;
        if out_len > out.len() {
            return Err(KError {
                errno: 75, // EOVERFLOW: successful syscall returned impossible size
                what: "BPF_PROG_TEST_RUN data_size_out".into(),
            });
        }
        out.truncate(out_len);
        Ok(TestRun { retval, data_out: out })
    }
}

// ===========================================================================
// Non-x86-64-Linux stub
// ===========================================================================
#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
mod imp {
    use super::*;

    pub struct Fd(pub i32);

    /// No descriptor is ever opened here (every call returns ENOSYS), but the
    /// type must still be droppable the same way as the real one so shared
    /// callers can `drop(fd)` without a `#[cfg]`.
    impl Drop for Fd {
        fn drop(&mut self) {}
    }

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
    pub fn prog_load_xdp(_insns: &[Insn], _log: Option<&mut String>) -> KResult<Fd> {
        Err(unsupported("BPF_PROG_LOAD"))
    }
    pub fn map_create(_def: &MapDef, _inner_map_fd: Option<i32>) -> KResult<Fd> {
        Err(unsupported("BPF_MAP_CREATE"))
    }
    pub fn map_update(_fd: i32, _key: &[u8], _value: &[u8]) -> KResult<()> {
        Err(unsupported("BPF_MAP_UPDATE_ELEM"))
    }
    pub fn test_run(
        _prog_fd: i32,
        _data_in: &[u8],
        _pad_socket_input: bool,
    ) -> KResult<TestRun> {
        Err(unsupported("BPF_PROG_TEST_RUN"))
    }
}

pub use imp::Fd;

/// Result fields written back by `BPF_PROG_TEST_RUN`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestRun {
    pub retval: u32,
    pub data_out: Vec<u8>,
}

/// A loaded kernel program and the map fds its rewritten instructions refer
/// to. Field order is intentional: the program closes before its maps.
pub struct KernelProgram {
    prog_fd: Fd,
    _map_fds: Vec<Fd>,
    map_names: Vec<String>,
    tail_fds: Vec<Fd>,
    xdp: bool,
}

impl KernelProgram {
    /// Execute once through `BPF_PROG_TEST_RUN`.
    pub fn test_run(&self, data_in: &[u8]) -> KResult<TestRun> {
        imp::test_run(self.prog_fd.0, data_in, !self.xdp)
    }

    /// Load a target against this program's map fds and install it into a
    /// named `PROG_ARRAY` slot, exactly as a userspace control plane does.
    pub fn link_tail_call(
        &mut self,
        map_name: &str,
        index: u32,
        insns: &[Insn],
        log: Option<&mut String>,
    ) -> KResult<()> {
        let prog = rewrite_map_refs(insns, &self._map_fds)?;
        let fd = if self.xdp {
            imp::prog_load_xdp(&prog, log)?
        } else {
            imp::prog_load(&prog, log)?
        };
        let map = self
            .map_names
            .iter()
            .position(|name| name == map_name)
            .ok_or_else(|| KError {
                errno: 2,
                what: format!("unknown map '{map_name}'"),
            })?;
        imp::map_update(
            self._map_fds[map].0,
            &index.to_ne_bytes(),
            &fd.0.to_ne_bytes(),
        )?;
        self.tail_fds.push(fd);
        Ok(())
    }
}

/// Does this process have the privilege to load BPF programs? Probes by
/// loading a trivial program. Returns `Ok(true)` if yes, `Ok(false)` on a
/// permission error, and `Err` on any other (unexpected) failure.
pub fn has_privilege() -> KResult<bool> {
    match imp::probe() {
        Ok(()) => Ok(true),
        // Unprivileged, or a platform with no bpf(2) whatsoever (macOS): both
        // are definite "no", which is what callers need in order to skip.
        Err(e) if e.is_permission() || e.is_unsupported() => Ok(false),
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

/// The kernel XDP verifier's verdict for a map-free program.
pub fn xdp_verdict(insns: &[Insn], log: Option<&mut String>) -> KResult<()> {
    imp::prog_load_xdp(insns, log).map(|_fd| ())
}

fn load_program_type(
    insns: &[Insn],
    maps: &[MapDef],
    xdp: bool,
    log: Option<&mut String>,
) -> KResult<KernelProgram> {
    // Apply the same tolerant defaults used by the standalone VM before
    // issuing BPF_MAP_CREATE. BTF templates commonly omit dynamic capacities
    // (notably PERF_EVENT_ARRAY inside HASH_OF_MAPS); zero is not a valid
    // kernel capacity.
    let maps: Vec<MapDef> = maps
        .iter()
        .map(|def| {
            Map::new(def.clone()).map(|map| map.def).map_err(|what| KError {
                errno: 22,
                what,
            })
        })
        .collect::<KResult<_>>()?;
    // Create kernel maps and remember their fds by original map index.
    let mut pending: Vec<usize> = (0..maps.len()).collect();
    let mut created: Vec<Option<Fd>> = (0..maps.len()).map(|_| None).collect();
    while !pending.is_empty() {
        let before = pending.len();
        let mut next = Vec::new();
        for i in pending {
            let def = &maps[i];
            if !def.kind.is_map_of_maps()
                && (def.inner_map_idx.is_some() || !def.map_in_map_values.is_empty())
            {
                return Err(KError {
                    errno: 22,
                    what: format!(
                        "map '{}' has map-in-map metadata but is a {} map",
                        def.name, def.kind
                    ),
                });
            }
            let inner_fd = match (def.kind.is_map_of_maps(), def.inner_map_idx) {
                (true, Some(inner)) => {
                    match created.get(inner as usize).and_then(Option::as_ref) {
                        Some(fd) => Some(fd.0),
                        None => {
                            next.push(i);
                            continue;
                        }
                    }
                }
                (true, None) | (false, _) => None,
            };
            if def.kind.is_map_of_maps() && inner_fd.is_none() {
                return Err(KError {
                    errno: 22,
                    what: format!("map-in-map '{}' has no inner-map template", def.name),
                });
            }
            let fd = imp::map_create(def, inner_fd)?;
            created[i] = Some(fd);
        }
        if next.len() == before {
            return Err(KError {
                errno: 22,
                what: "cyclic or invalid map-in-map template graph".into(),
            });
        }
        pending = next;
    }
    let map_fds: Vec<Fd> = created
        .into_iter()
        .map(|fd| fd.expect("all map dependencies were created"))
        .collect();
    for (i, def) in maps.iter().enumerate() {
        // Seed initial contents for global-data maps (single array element 0).
        if !def.init.is_empty() && def.kind == MapKind::Array {
            let key = 0u32.to_ne_bytes();
            let mut val = vec![0u8; def.value_size as usize];
            let n = def.init.len().min(val.len());
            val[..n].copy_from_slice(&def.init[..n]);
            imp::map_update(map_fds[i].0, &key, &val)?;
        }
        for &(slot, inner) in &def.map_in_map_values {
            let inner_fd = map_fds.get(inner as usize).ok_or_else(|| KError {
                errno: 22,
                what: format!("map '{}' references unknown inner map {inner}", def.name),
            })?;
            imp::map_update(
                map_fds[i].0,
                &slot.to_ne_bytes(),
                &inner_fd.0.to_ne_bytes(),
            )?;
        }
    }

    let prog = rewrite_map_refs(insns, &map_fds)?;

    let prog_fd = if xdp {
        imp::prog_load_xdp(&prog, log)?
    } else {
        imp::prog_load(&prog, log)?
    };
    Ok(KernelProgram {
        prog_fd,
        map_names: maps.iter().map(|m| m.name.clone()).collect(),
        _map_fds: map_fds,
        tail_fds: Vec::new(),
        xdp,
    })
}

fn rewrite_map_refs(insns: &[Insn], map_fds: &[Fd]) -> KResult<Vec<Insn>> {
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
                    let fd = map_fds.get(m).ok_or_else(|| KError {
                        errno: 22,
                        what: format!("lddw references unknown map {m}"),
                    })?;
                    prog[pc].src = BPF_PSEUDO_MAP_FD;
                    prog[pc].imm = fd.0;
                }
                // src=2 (MAP_VALUE): dst gets a pointer to a map value; the
                // second slot's imm carries the byte offset (kept as-is).
                2 => {
                    let fd = map_fds.get(m).ok_or_else(|| KError {
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

    Ok(prog)
}

/// Load an XDP program into the kernel, retaining all referenced map fds.
pub fn load_xdp_program(
    insns: &[Insn],
    maps: &[MapDef],
    log: Option<&mut String>,
) -> KResult<KernelProgram> {
    load_program_type(insns, maps, true, log)
}

/// Load a socket-filter program while retaining maps for tail-call linking.
pub fn load_kernel_program(
    insns: &[Insn],
    maps: &[MapDef],
    log: Option<&mut String>,
) -> KResult<KernelProgram> {
    load_program_type(insns, maps, false, log)
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
    let prog = load_program_type(insns, maps, false, log)?;
    prog.test_run(data_in).map(|run| run.retval)
}

/// Load and test-run an XDP program, returning its verdict and output packet.
pub fn run_xdp_program(
    insns: &[Insn],
    maps: &[MapDef],
    packet: &[u8],
    log: Option<&mut String>,
) -> KResult<TestRun> {
    let prog = load_xdp_program(insns, maps, log)?;
    prog.test_run(packet)
}
