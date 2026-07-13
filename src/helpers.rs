//! Helper function registry: kernel-compatible ids, names, and the type
//! signatures the verifier uses to check calls.

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};

/// Kernel-compatible helper ids implemented by the runtime.
pub mod id {
    pub const MAP_LOOKUP_ELEM: u32 = 1;
    pub const MAP_UPDATE_ELEM: u32 = 2;
    pub const MAP_DELETE_ELEM: u32 = 3;
    pub const PROBE_READ: u32 = 4;
    pub const KTIME_GET_NS: u32 = 5;
    pub const TRACE_PRINTK: u32 = 6;
    pub const GET_PRANDOM_U32: u32 = 7;
    pub const GET_SMP_PROCESSOR_ID: u32 = 8;
    pub const TAIL_CALL: u32 = 12;
    pub const GET_CURRENT_PID_TGID: u32 = 14;
    pub const GET_CURRENT_UID_GID: u32 = 15;
    pub const GET_CURRENT_COMM: u32 = 16;
    pub const REDIRECT: u32 = 23;
    pub const PERF_EVENT_OUTPUT: u32 = 25;
    pub const SKB_LOAD_BYTES: u32 = 26;
    pub const GET_STACKID: u32 = 27;
    pub const CSUM_DIFF: u32 = 28;
    pub const GET_CURRENT_TASK: u32 = 35;
    pub const CURRENT_TASK_UNDER_CGROUP: u32 = 37;
    pub const SKB_PULL_DATA: u32 = 39;
    pub const XDP_ADJUST_HEAD: u32 = 44;
    pub const PROBE_READ_STR: u32 = 45;
    pub const GET_SOCKET_COOKIE: u32 = 46;
    pub const REDIRECT_MAP: u32 = 51;
    pub const XDP_ADJUST_TAIL: u32 = 65;
    pub const GET_STACK: u32 = 67;
    pub const FIB_LOOKUP: u32 = 69;
    pub const MAP_PUSH_ELEM: u32 = 87;
    pub const SPIN_LOCK: u32 = 93;
    pub const SPIN_UNLOCK: u32 = 94;
    pub const PROBE_READ_USER: u32 = 112;
    pub const PROBE_READ_KERNEL: u32 = 113;
    pub const PROBE_READ_USER_STR: u32 = 114;
    pub const PROBE_READ_KERNEL_STR: u32 = 115;
    pub const GET_NS_CURRENT_PID_TGID: u32 = 120;
    pub const KTIME_GET_BOOT_NS: u32 = 125;
    pub const SEQ_WRITE: u32 = 127;
    pub const RINGBUF_OUTPUT: u32 = 130;
    pub const RINGBUF_RESERVE: u32 = 131;
    pub const RINGBUF_SUBMIT: u32 = 132;
    pub const RINGBUF_DISCARD: u32 = 133;
    pub const SKC_TO_TCP_SOCK: u32 = 137;
    pub const SKC_TO_TCP_TIMEWAIT_SOCK: u32 = 138;
    pub const SKC_TO_TCP_REQUEST_SOCK: u32 = 139;
    pub const GET_TASK_STACK: u32 = 141;
    pub const KTIME_GET_COARSE_NS: u32 = 160;
    pub const GET_FUNC_IP: u32 = 173;
    pub const TRACE_VPRINTK: u32 = 177;
    pub const XDP_LOAD_BYTES: u32 = 189;
    pub const XDP_STORE_BYTES: u32 = 190;
    /// First id available for user-registered helpers.
    pub const FIRST_USER: u32 = 0x1_0000;
}

/// What the verifier requires of each argument register (r1..r5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    /// Unused argument; contents ignored (may be uninitialized).
    None,
    /// Any initialized scalar value.
    Scalar,
    /// A map pointer produced by `lddw rN = map[...]`.
    ConstMapPtr,
    /// The original program context pointer (`ARG_PTR_TO_CTX`).
    CtxPtr,
    /// The original context pointer under the explicit `__sk_buff` model.
    SkbCtxPtr,
    /// The original context pointer under the explicit `xdp_md` model.
    XdpCtxPtr,
    /// Readable memory of exactly the map's key size (map from arg 1).
    MapKey,
    /// Readable memory of exactly the map's value size (map from arg 1).
    MapValue,
    /// Readable memory whose length is given by the argument at `size_arg`
    /// (0-based index into args).
    MemRead { size_arg: u8 },
    /// Readable memory sized by another argument, or scalar NULL when that
    /// size is exactly zero (`ARG_PTR_TO_MEM | PTR_MAYBE_NULL`).
    MemReadOrNull { size_arg: u8 },
    /// Writable memory whose length is given by the argument at `size_arg`.
    MemWrite { size_arg: u8 },
    /// Initialized, writable memory whose length is given by another argument.
    /// Kernel helpers with `MEM_RDWR` consume and may update the same buffer.
    MemReadWrite { size_arg: u8 },
    /// A scalar used as a memory size; the paired memory argument constrains
    /// its upper bound. Zero is accepted for kernel `*_SIZE_OR_ZERO` forms.
    Size,
    /// An unmodified pointer to the exact named struct/union in target BTF.
    /// This models helpers whose kernel prototype uses `ARG_PTR_TO_BTF_ID`.
    BtfPtr { type_name: &'static str },
    /// Exact BTF-declared `struct bpf_spin_lock` field in a map value.
    SpinLock,
    /// Anything, including uninitialized (kernel ARG_ANYTHING for varargs).
    Any,
    /// A pointer to a ringbuf-reserved record (from `ringbuf_reserve`, after a
    /// null check), at offset 0. Consumed by `ringbuf_submit`/`_discard`.
    RingbufReserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetKind {
    /// Unknown scalar.
    Scalar,
    /// Pointer to the map's value, or NULL — must be null-checked before use.
    MapValueOrNull,
    /// Pointer to a writable ringbuf record of `size_arg` bytes, or NULL —
    /// must be null-checked before use (from `ringbuf_reserve`).
    RingbufMemOrNull { size_arg: u8 },
    /// Nullable pointer to the exact named struct/union in target BTF. This
    /// models helpers whose kernel prototype returns `PTR_TO_BTF_ID_OR_NULL`.
    BtfPtrOrNull { type_name: &'static str },
    /// Non-null pointer to a VM-owned external memory region. The helper
    /// signature declares the byte extent visible to the program and whether
    /// stores are permitted; runtime region resolution independently enforces
    /// the actual registered region's bounds and access mode.
    ExternalMemory { size: u32, writable: bool },
}

#[derive(Debug, Clone)]
pub struct HelperSig {
    pub name: &'static str,
    pub args: [ArgKind; 5],
    pub ret: RetKind,
}

/// Signature of a built-in helper, if `id` names one.
pub fn builtin_sig(hid: u32) -> Option<HelperSig> {
    use ArgKind::*;
    let sig = match hid {
        id::MAP_LOOKUP_ELEM => HelperSig {
            name: "map_lookup_elem",
            args: [ConstMapPtr, MapKey, None, None, None],
            ret: RetKind::MapValueOrNull,
        },
        id::MAP_UPDATE_ELEM => HelperSig {
            name: "map_update_elem",
            args: [ConstMapPtr, MapKey, MapValue, Scalar, None],
            ret: RetKind::Scalar,
        },
        id::MAP_DELETE_ELEM => HelperSig {
            name: "map_delete_elem",
            args: [ConstMapPtr, MapKey, None, None, None],
            ret: RetKind::Scalar,
        },
        id::MAP_PUSH_ELEM => HelperSig {
            name: "map_push_elem",
            args: [ConstMapPtr, MapValue, Scalar, None, None],
            ret: RetKind::Scalar,
        },
        id::KTIME_GET_NS => HelperSig {
            name: "ktime_get_ns",
            args: [None, None, None, None, None],
            ret: RetKind::Scalar,
        },
        id::TRACE_PRINTK => HelperSig {
            name: "trace_printk",
            args: [MemRead { size_arg: 1 }, Size, Any, Any, Any],
            ret: RetKind::Scalar,
        },
        id::GET_PRANDOM_U32 => HelperSig {
            name: "get_prandom_u32",
            args: [None, None, None, None, None],
            ret: RetKind::Scalar,
        },
        id::GET_SMP_PROCESSOR_ID => HelperSig {
            name: "get_smp_processor_id",
            args: [None, None, None, None, None],
            ret: RetKind::Scalar,
        },
        id::TAIL_CALL => HelperSig {
            name: "tail_call",
            args: [CtxPtr, ConstMapPtr, Scalar, None, None],
            ret: RetKind::Scalar,
        },
        id::GET_CURRENT_PID_TGID => HelperSig {
            name: "get_current_pid_tgid",
            args: [None, None, None, None, None],
            ret: RetKind::Scalar,
        },
        id::GET_CURRENT_UID_GID => HelperSig {
            name: "get_current_uid_gid",
            args: [None, None, None, None, None],
            ret: RetKind::Scalar,
        },
        id::GET_CURRENT_COMM => HelperSig {
            name: "get_current_comm",
            // (buf, size); buf must be writable for `size` bytes.
            args: [MemWrite { size_arg: 1 }, Size, None, None, None],
            ret: RetKind::Scalar,
        },
        id::REDIRECT => HelperSig {
            name: "redirect",
            args: [Scalar, Scalar, None, None, None],
            ret: RetKind::Scalar,
        },
        id::SKB_LOAD_BYTES => HelperSig {
            name: "skb_load_bytes",
            args: [SkbCtxPtr, Scalar, MemWrite { size_arg: 3 }, Size, None],
            ret: RetKind::Scalar,
        },
        id::GET_CURRENT_TASK => HelperSig {
            name: "get_current_task",
            args: [None, None, None, None, None],
            ret: RetKind::Scalar,
        },
        id::GET_STACKID => HelperSig {
            name: "get_stackid",
            // (ctx, map, flags); ctx accepted loosely like perf_event_output.
            args: [Any, ConstMapPtr, Scalar, None, None],
            ret: RetKind::Scalar,
        },
        id::CSUM_DIFF => HelperSig {
            name: "csum_diff",
            args: [
                MemReadOrNull { size_arg: 1 },
                Size,
                MemReadOrNull { size_arg: 3 },
                Size,
                Scalar,
            ],
            ret: RetKind::Scalar,
        },
        id::GET_STACK => HelperSig {
            name: "get_stack",
            // (ctx, buf, size, flags); buf must be writable for `size` bytes.
            // ctx/flags accepted loosely like get_stackid. No map involved.
            args: [Any, MemWrite { size_arg: 2 }, Size, Scalar, None],
            ret: RetKind::Scalar,
        },
        id::FIB_LOOKUP => HelperSig {
            name: "fib_lookup",
            args: [
                XdpCtxPtr,
                MemReadWrite { size_arg: 2 },
                Size,
                Scalar,
                None,
            ],
            ret: RetKind::Scalar,
        },
        id::SPIN_LOCK => HelperSig {
            name: "spin_lock",
            args: [SpinLock, None, None, None, None],
            ret: RetKind::Scalar,
        },
        id::SPIN_UNLOCK => HelperSig {
            name: "spin_unlock",
            args: [SpinLock, None, None, None, None],
            ret: RetKind::Scalar,
        },
        // probe_read family: (dst, size, unsafe_ptr). The source is
        // ARG_ANYTHING in the kernel (any scalar/pointer); febpf resolves it
        // through the virtual-address model at runtime and faults cleanly.
        id::PROBE_READ => HelperSig {
            name: "probe_read",
            args: [MemWrite { size_arg: 1 }, Size, Any, None, None],
            ret: RetKind::Scalar,
        },
        id::PROBE_READ_KERNEL => HelperSig {
            name: "probe_read_kernel",
            args: [MemWrite { size_arg: 1 }, Size, Any, None, None],
            ret: RetKind::Scalar,
        },
        id::PROBE_READ_USER => HelperSig {
            name: "probe_read_user",
            args: [MemWrite { size_arg: 1 }, Size, Any, None, None],
            ret: RetKind::Scalar,
        },
        id::PROBE_READ_STR => HelperSig {
            name: "probe_read_str",
            args: [MemWrite { size_arg: 1 }, Size, Any, None, None],
            ret: RetKind::Scalar,
        },
        id::PROBE_READ_KERNEL_STR => HelperSig {
            name: "probe_read_kernel_str",
            args: [MemWrite { size_arg: 1 }, Size, Any, None, None],
            ret: RetKind::Scalar,
        },
        id::PROBE_READ_USER_STR => HelperSig {
            name: "probe_read_user_str",
            args: [MemWrite { size_arg: 1 }, Size, Any, None, None],
            ret: RetKind::Scalar,
        },
        id::GET_NS_CURRENT_PID_TGID => HelperSig {
            name: "get_ns_current_pid_tgid",
            args: [Scalar, Scalar, MemWrite { size_arg: 3 }, Size, None],
            ret: RetKind::Scalar,
        },
        id::KTIME_GET_BOOT_NS => HelperSig {
            name: "ktime_get_boot_ns",
            args: [None, None, None, None, None],
            ret: RetKind::Scalar,
        },
        id::SEQ_WRITE => HelperSig {
            name: "seq_write",
            args: [
                BtfPtr { type_name: "seq_file" },
                MemRead { size_arg: 2 },
                Size,
                None,
                None,
            ],
            ret: RetKind::Scalar,
        },
        id::GET_SOCKET_COOKIE => HelperSig {
            // (ctx) -> u64 cookie; the kernel also has (sk) flavors, so the
            // argument is accepted loosely like perf_event_output's ctx.
            name: "get_socket_cookie",
            args: [Any, None, None, None, None],
            ret: RetKind::Scalar,
        },
        id::REDIRECT_MAP => HelperSig {
            name: "redirect_map",
            args: [ConstMapPtr, Scalar, Scalar, None, None],
            ret: RetKind::Scalar,
        },
        id::CURRENT_TASK_UNDER_CGROUP => HelperSig {
            name: "current_task_under_cgroup",
            // (map, index); map must be a cgroup_array.
            args: [ConstMapPtr, Scalar, None, None, None],
            ret: RetKind::Scalar,
        },
        id::SKB_PULL_DATA => HelperSig {
            name: "skb_pull_data",
            args: [SkbCtxPtr, Scalar, None, None, None],
            ret: RetKind::Scalar,
        },
        id::XDP_ADJUST_HEAD => HelperSig {
            name: "xdp_adjust_head",
            args: [XdpCtxPtr, Scalar, None, None, None],
            ret: RetKind::Scalar,
        },
        id::XDP_ADJUST_TAIL => HelperSig {
            name: "xdp_adjust_tail",
            args: [XdpCtxPtr, Scalar, None, None, None],
            ret: RetKind::Scalar,
        },
        id::PERF_EVENT_OUTPUT => HelperSig {
            name: "perf_event_output",
            // (ctx, map, flags, data, size); data is a readable region of `size`
            // bytes. ctx/flags accepted loosely to keep corpus objects loading.
            args: [Any, ConstMapPtr, Scalar, MemRead { size_arg: 4 }, Size],
            ret: RetKind::Scalar,
        },
        id::GET_FUNC_IP => HelperSig {
            // (ctx) -> u64 address of the traced function.
            name: "get_func_ip",
            args: [Any, None, None, None, None],
            ret: RetKind::Scalar,
        },
        id::TRACE_VPRINTK => HelperSig {
            name: "trace_vprintk",
            args: [
                MemRead { size_arg: 1 },
                Size,
                MemReadOrNull { size_arg: 3 },
                Size,
                None,
            ],
            ret: RetKind::Scalar,
        },
        id::XDP_LOAD_BYTES => HelperSig {
            name: "xdp_load_bytes",
            args: [XdpCtxPtr, Scalar, MemWrite { size_arg: 3 }, Size, None],
            ret: RetKind::Scalar,
        },
        id::XDP_STORE_BYTES => HelperSig {
            name: "xdp_store_bytes",
            args: [XdpCtxPtr, Scalar, MemRead { size_arg: 3 }, Size, None],
            ret: RetKind::Scalar,
        },
        id::RINGBUF_OUTPUT => HelperSig {
            name: "ringbuf_output",
            // (map, data, size, flags)
            args: [ConstMapPtr, MemRead { size_arg: 2 }, Size, Any, None],
            ret: RetKind::Scalar,
        },
        id::RINGBUF_RESERVE => HelperSig {
            name: "ringbuf_reserve",
            // (map, size, flags) -> PTR_TO_MEM-or-NULL of `size` bytes
            args: [ConstMapPtr, Size, Any, None, None],
            ret: RetKind::RingbufMemOrNull { size_arg: 1 },
        },
        id::RINGBUF_SUBMIT => HelperSig {
            name: "ringbuf_submit",
            args: [RingbufReserved, Any, None, None, None],
            ret: RetKind::Scalar,
        },
        id::RINGBUF_DISCARD => HelperSig {
            name: "ringbuf_discard",
            args: [RingbufReserved, Any, None, None, None],
            ret: RetKind::Scalar,
        },
        id::SKC_TO_TCP_SOCK => HelperSig {
            name: "skc_to_tcp_sock",
            args: [BtfPtr { type_name: "sock_common" }, None, None, None, None],
            ret: RetKind::BtfPtrOrNull { type_name: "tcp_sock" },
        },
        id::SKC_TO_TCP_TIMEWAIT_SOCK => HelperSig {
            name: "skc_to_tcp_timewait_sock",
            args: [BtfPtr { type_name: "sock_common" }, None, None, None, None],
            ret: RetKind::BtfPtrOrNull { type_name: "tcp_timewait_sock" },
        },
        id::SKC_TO_TCP_REQUEST_SOCK => HelperSig {
            name: "skc_to_tcp_request_sock",
            args: [BtfPtr { type_name: "sock_common" }, None, None, None, None],
            ret: RetKind::BtfPtrOrNull { type_name: "tcp_request_sock" },
        },
        id::GET_TASK_STACK => HelperSig {
            name: "get_task_stack",
            args: [
                BtfPtr { type_name: "task_struct" },
                MemWrite { size_arg: 2 },
                Size,
                Any,
                None,
            ],
            ret: RetKind::Scalar,
        },
        id::KTIME_GET_COARSE_NS => HelperSig {
            name: "ktime_get_coarse_ns",
            args: [None, None, None, None, None],
            ret: RetKind::Scalar,
        },
        _ => return Option::None,
    };
    Some(sig)
}

pub fn helper_name(hid: u32) -> String {
    match builtin_sig(hid) {
        Some(s) => s.name.to_string(),
        None => format!("helper#{hid}"),
    }
}

pub fn helper_id(name: &str) -> Option<u32> {
    [
        id::MAP_LOOKUP_ELEM,
        id::MAP_UPDATE_ELEM,
        id::MAP_DELETE_ELEM,
        id::KTIME_GET_NS,
        id::TRACE_PRINTK,
        id::GET_PRANDOM_U32,
        id::GET_SMP_PROCESSOR_ID,
        id::TAIL_CALL,
        id::GET_CURRENT_PID_TGID,
        id::GET_CURRENT_UID_GID,
        id::GET_CURRENT_COMM,
        id::REDIRECT,
        id::SKB_LOAD_BYTES,
        id::GET_CURRENT_TASK,
        id::GET_STACKID,
        id::CSUM_DIFF,
        id::GET_STACK,
        id::FIB_LOOKUP,
        id::MAP_PUSH_ELEM,
        id::SPIN_LOCK,
        id::SPIN_UNLOCK,
        id::PROBE_READ,
        id::PROBE_READ_STR,
        id::GET_SOCKET_COOKIE,
        id::REDIRECT_MAP,
        id::PROBE_READ_KERNEL,
        id::PROBE_READ_USER,
        id::PROBE_READ_KERNEL_STR,
        id::PROBE_READ_USER_STR,
        id::GET_NS_CURRENT_PID_TGID,
        id::KTIME_GET_BOOT_NS,
        id::SEQ_WRITE,
        id::CURRENT_TASK_UNDER_CGROUP,
        id::SKB_PULL_DATA,
        id::XDP_ADJUST_HEAD,
        id::XDP_ADJUST_TAIL,
        id::PERF_EVENT_OUTPUT,
        id::GET_FUNC_IP,
        id::TRACE_VPRINTK,
        id::XDP_LOAD_BYTES,
        id::XDP_STORE_BYTES,
        id::RINGBUF_OUTPUT,
        id::RINGBUF_RESERVE,
        id::RINGBUF_SUBMIT,
        id::RINGBUF_DISCARD,
        id::SKC_TO_TCP_SOCK,
        id::SKC_TO_TCP_TIMEWAIT_SOCK,
        id::SKC_TO_TCP_REQUEST_SOCK,
        id::GET_TASK_STACK,
        id::KTIME_GET_COARSE_NS,
    ].into_iter().find(|&hid| builtin_sig(hid).unwrap().name == name)
}

/// Memory access interface handed to user-registered helpers so they can
/// dereference pointer arguments safely (bounds-checked by the VM).
pub trait MemBus {
    fn read(&mut self, addr: u64, buf: &mut [u8]) -> Result<(), String>;
    fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), String>;
}

/// A user-registered helper implementation.
pub trait UserHelper {
    fn call(&mut self, args: [u64; 5], mem: &mut dyn MemBus) -> Result<u64, String>;
}

impl<F> UserHelper for F
where
    F: FnMut([u64; 5], &mut dyn MemBus) -> Result<u64, String>,
{
    fn call(&mut self, args: [u64; 5], mem: &mut dyn MemBus) -> Result<u64, String> {
        self(args, mem)
    }
}

/// Registry of user helpers, keyed by helper id.
#[derive(Default)]
pub struct UserHelpers {
    sigs: Vec<(u32, HelperSig)>,
    impls: Vec<(u32, Option<Box<dyn UserHelper>>)>,
}

impl UserHelpers {
    pub fn new() -> Self {
        UserHelpers::default()
    }
    pub fn register(&mut self, hid: u32, sig: HelperSig, imp: Box<dyn UserHelper>) {
        self.sigs.retain(|(i, _)| *i != hid);
        self.impls.retain(|(i, _)| *i != hid);
        self.sigs.push((hid, sig));
        self.impls.push((hid, Some(imp)));
    }
    /// Signatures for the verifier.
    pub fn sigs(&self) -> &[(u32, HelperSig)] {
        &self.sigs
    }
    /// Temporarily remove an implementation so it can be called while the VM
    /// state is mutably borrowed; return it with [`UserHelpers::put_back`].
    pub fn take(&mut self, hid: u32) -> Option<Box<dyn UserHelper>> {
        self.impls
            .iter_mut()
            .find(|(i, _)| *i == hid)
            .and_then(|(_, f)| f.take())
    }
    pub fn put_back(&mut self, hid: u32, imp: Box<dyn UserHelper>) {
        if let Some((_, slot)) = self.impls.iter_mut().find(|(i, _)| *i == hid) {
            *slot = Some(imp);
        }
    }
}
