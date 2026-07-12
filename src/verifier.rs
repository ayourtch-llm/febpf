//! The eBPF verifier: path-sensitive abstract interpretation over the
//! program, modeled on the Linux kernel verifier.
//!
//! It proves, before execution, that:
//! - every instruction is well-formed and reachable,
//! - no register is read uninitialized, r10 is never written,
//! - all memory accesses (stack, context, map values) are in bounds,
//! - map-value pointers are null-checked before use,
//! - helper calls match their signatures,
//! - bpf-to-bpf calls respect the frame limit and return a value,
//! - the program provably terminates within the instruction budget.
//!
//! Value tracking uses tnums ([`crate::tnum::Tnum`], known bits) plus
//! signed/unsigned 64-bit ranges, with branch-condition refinement and
//! subset-based state pruning at join points.

// div/mod arms encode eBPF defined-by-zero semantics; `checked_div` hides them.
#![allow(clippy::manual_checked_ops)]
use crate::disasm;
use crate::helpers::{builtin_sig, ArgKind, HelperSig, RetKind};
use crate::insn::*;
use crate::maps::MapDef;
use crate::tnum::Tnum;
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as LookupMap;
use alloc::collections::VecDeque;
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
#[cfg(feature = "std")]
use std::collections::HashMap as LookupMap;
use core::fmt::Write as _;

/// Semantics selected for deprecated `LD_ABS`/`LD_IND` packet loads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LegacyPacketProfile {
    /// Reject every legacy packet-load instruction.
    #[default]
    Disabled,
    /// Linux B/H/W semantics: network byte order and implicit zero exit.
    Linux,
    /// rbpf 0.4.1 compatibility, including little-endian DW loads.
    Rbpf041,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Size of the memory region r1 points to on entry (0 = no context).
    pub ctx_size: usize,
    /// Whether stores through the context pointer are allowed.
    pub ctx_writable: bool,
    /// Require naturally aligned memory accesses.
    pub strict_alignment: bool,
    /// Abstract instructions processed before "program too complex".
    pub insn_budget: usize,
    /// Bound on remembered states per prune point.
    pub max_states_per_pc: usize,
    /// BTF typing of the context, for `tp_btf`/`fentry`-style programs whose
    /// ctx is an array of typed u64 arguments (the kernel's `btf_ctx_access()`
    /// model). When set, ctx loads follow the kernel's BTF rules instead of
    /// the flat `ctx_size` byte-buffer model: 8-byte-slot reads only, pointer
    /// slots yield [`PtrKind::BtfId`] pointers, and writes are rejected.
    pub btf_ctx: Option<crate::btf::BtfCtx>,
    /// Treat the context as `struct xdp_md`: 32-bit loads at offsets 0 and 4
    /// yield packet start/end pointers; offsets 12, 16, and 20 yield scalar
    /// interface/queue metadata. Packet memory may only be accessed after a
    /// comparison against `data_end` proves the range safe.
    pub xdp: bool,
    /// Treat exact 64-bit loads at caller-selected context offsets as packet
    /// start/end virtual pointers.
    pub metadata_layout: Option<crate::interp::MetadataLayout>,
    /// Explicit semantics for deprecated legacy packet loads.
    pub legacy_packet: LegacyPacketProfile,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            ctx_size: 4096,
            ctx_writable: true,
            strict_alignment: false,
            insn_budget: 1_000_000,
            max_states_per_pc: 4096,
            btf_ctx: None,
            xdp: false,
            metadata_layout: None,
            legacy_packet: LegacyPacketProfile::Disabled,
        }
    }
}

#[derive(Debug)]
pub struct VerifyError {
    pub pc: usize,
    pub msg: String,
    /// Counterexample: the exact path the verifier walked from entry to the
    /// failing instruction. `None` for structural (pre-DFS) errors or if the
    /// path could not be reconstructed.
    pub trace: Option<Trace>,
}

/// A replayed counterexample path ending at the failing instruction.
#[derive(Debug)]
pub struct Trace {
    /// Steps in program order. When the path is long, this holds a window of
    /// the first few and last few steps; `truncated` counts the omitted
    /// middle. The final entry is the failing instruction itself (not
    /// executed).
    pub steps: Vec<TraceStep>,
    /// Number of steps omitted between the head and tail windows.
    pub truncated: usize,
    /// Cause hints, e.g. where a maybe-NULL pointer came from.
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TraceStep {
    pub pc: usize,
    /// Rendered abstract state *before* executing the instruction.
    pub state: String,
    /// For a conditional jump on the path: (taken, jump target).
    pub branch: Option<(bool, usize)>,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "at insn {}: {}", self.pc, self.msg)
    }
}
impl core::error::Error for VerifyError {}

/// Immutable input supplied to an application verification policy after the
/// core memory-safety verifier has accepted a program.
pub struct PolicyView<'a> {
    pub insns: &'a [Insn],
    pub maps: &'a [MapDef],
    pub evidence: &'a VerifyOk,
}

/// Failure from [`crate::interp::Vm::verify_with_policy`]. Core verifier
/// failures and application policy rejections remain distinguishable.
#[derive(Debug)]
pub enum VerifyWithPolicyError {
    Core(VerifyError),
    Policy(String),
}

impl core::fmt::Display for VerifyWithPolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyWithPolicyError::Core(error) => write!(f, "core verification failed: {error}"),
            VerifyWithPolicyError::Policy(message) => {
                write!(f, "verification policy rejected program: {message}")
            }
        }
    }
}

impl core::error::Error for VerifyWithPolicyError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            VerifyWithPolicyError::Core(error) => Some(error),
            VerifyWithPolicyError::Policy(_) => None,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Stats {
    /// Abstract instructions processed.
    pub insns_processed: usize,
    /// Branch states pushed for later exploration.
    pub states_explored: usize,
    /// Paths cut short because a subsuming state was already verified.
    pub states_pruned: usize,
    /// Deepest call-frame chain observed.
    pub max_frames: usize,
    /// Deepest stack byte written in any frame (positive number of bytes).
    pub stack_usage: usize,
    /// Number of distinct prune points.
    pub prune_points: usize,
}

pub struct VerifyOk {
    pub stats: Stats,
    pub warnings: Vec<String>,
    /// Human-readable register state at first visit of each insn (for the
    /// analyzer), plus visit count.
    pub insn_state: Vec<Option<(String, usize)>>,
    /// Machine-readable **join over all visits** of the current frame's
    /// register states on entry to each insn. `None` = never reached (dead
    /// code). A fact true here holds on every path reaching that PC, so it is
    /// sound to optimize on (see `docs/specs/equiv-optimizer.md` §4). Indexed
    /// by instruction slot; the second slot of a `lddw` is `None`.
    pub pc_regs: Vec<Option<[RegState; NUM_REGS]>>,
    /// Per-insn: `true` for loads that go through a BTF-typed kernel pointer.
    /// The kernel rewrites these to `BPF_PROBE_MEM` (fault-tolerant, a bad
    /// address reads as zero) in convert_ctx_accesses(); febpf's runtime does
    /// the same when the VM is armed with this bitmap (`Vm::verify` arms it
    /// automatically). Indexed by instruction slot.
    pub probe_mem: Vec<bool>,
}

impl VerifyOk {
    /// Abstract register state joined across every path reaching `pc`, or
    /// `None` if `pc` is unreachable (dead code) or out of range.
    pub fn regs_at(&self, pc: usize) -> Option<&[RegState; NUM_REGS]> {
        self.pc_regs.get(pc).and_then(|s| s.as_ref())
    }
}

// ---------------------------------------------------------------------------
// Abstract values
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scalar {
    pub tnum: Tnum,
    pub umin: u64,
    pub umax: u64,
    pub smin: i64,
    pub smax: i64,
}

impl Scalar {
    pub fn unknown() -> Scalar {
        Scalar {
            tnum: Tnum::unknown(),
            umin: 0,
            umax: u64::MAX,
            smin: i64::MIN,
            smax: i64::MAX,
        }
    }
    pub fn constant(v: u64) -> Scalar {
        Scalar {
            tnum: Tnum::const_val(v),
            umin: v,
            umax: v,
            smin: v as i64,
            smax: v as i64,
        }
    }
    pub fn is_const(&self) -> bool {
        self.umin == self.umax
    }

    /// Reconcile tnum and range information; false if contradictory
    /// (the state is unreachable).
    ///
    /// The derivations run to a fixpoint: tightening the tnum from the
    /// u-range can re-tighten u, which can re-tighten s (and vice versa) —
    /// a single pass is not idempotent, which broke canonical-form
    /// assumptions downstream (join/is_subset_of interplay; found by the
    /// operator-soundness harness). The kernel's reg_bounds_sync()
    /// (kernel/bpf/verifier.c) likewise runs __update_reg_bounds both
    /// before and after __reg_bound_offset. Every step only tightens, so
    /// the loop terminates.
    pub fn sync(&mut self) -> bool {
        loop {
            let before = *self;
            // bounds from tnum
            self.umin = self.umin.max(self.tnum.umin());
            self.umax = self.umax.min(self.tnum.umax());
            // signed from unsigned when the range doesn't cross the sign boundary
            if (self.umin as i64) <= (self.umax as i64) {
                self.smin = self.smin.max(self.umin as i64);
                self.smax = self.smax.min(self.umax as i64);
            }
            // unsigned from signed when the range doesn't cross zero
            // when the signed range doesn't cross zero, its u64 view is ordered
            if self.smin >= 0 || self.smax < 0 {
                self.umin = self.umin.max(self.smin as u64);
                self.umax = self.umax.min(self.smax as u64);
            }
            // tnum from unsigned range
            self.tnum = self.tnum.intersect(Tnum::range(self.umin, self.umax));
            self.umin = self.umin.max(self.tnum.umin());
            self.umax = self.umax.min(self.tnum.umax());
            if self.umin > self.umax || self.smin > self.smax {
                return false;
            }
            if *self == before {
                return true;
            }
        }
    }

    pub(crate) fn from_tnum(t: Tnum) -> Scalar {
        let mut s = Scalar {
            tnum: t,
            umin: t.umin(),
            umax: t.umax(),
            smin: i64::MIN,
            smax: i64::MAX,
        };
        s.sync();
        s
    }

    /// Zero-extended 32-bit view. Result ranges lie within [0, u32::MAX].
    pub(crate) fn truncate32(&self) -> Scalar {
        if self.umax <= u32::MAX as u64 {
            let mut s = *self;
            s.tnum = s.tnum.cast(4);
            s.smin = s.umin as i64;
            s.smax = s.umax as i64;
            s.sync();
            s
        } else {
            Scalar::from_tnum(self.tnum.cast(4))
        }
    }

    /// The signed-32 view of a scalar already truncated to 32 bits
    /// (γ ⊆ [0, u32::MAX], zero-extended): a scalar containing
    /// `{ sign_extend_32(x) : x ∈ γ(self) }`.
    ///
    /// The kernel keeps dedicated 32-bit bounds (`s32_min_value` /
    /// `s32_max_value`, kernel/bpf/verifier.c) that JMP32 signed decisions
    /// and refinement use directly (`is_branch32_taken`, `reg_set_min_max`).
    /// febpf tracks only 64-bit bounds, so the s32 view is derived on
    /// demand: exact when the 32-bit range does not cross the i32 sign
    /// boundary, conservative (`[i32::MIN, i32::MAX]`) when it does.
    fn sext32_view(&self) -> Scalar {
        let t = self.tnum.cast(4);
        let tnum = if t.mask & 0x8000_0000 != 0 {
            // sign bit unknown: all high bits unknown
            Tnum {
                value: t.value,
                mask: t.mask | 0xffff_ffff_0000_0000,
            }
        } else if t.value & 0x8000_0000 != 0 {
            // sign bit known set: high bits known one
            Tnum {
                value: t.value | 0xffff_ffff_0000_0000,
                mask: t.mask,
            }
        } else {
            t
        };
        let (umin, umax, smin, smax) = if self.umax <= i32::MAX as u64 {
            // non-negative as i32: sign-extension is the identity
            (self.umin, self.umax, self.umin as i64, self.umax as i64)
        } else if self.umin >= 1 << 31 {
            // negative as i32: sign-extension is monotone on [2^31, 2^32)
            let lo = self.umin as u32 as i32 as i64;
            let hi = self.umax as u32 as i32 as i64;
            (lo as u64, hi as u64, lo, hi)
        } else {
            // range crosses the i32 sign boundary: only the sign-extended
            // magnitude is known
            (0, u64::MAX, i32::MIN as i64, i32::MAX as i64)
        };
        let mut r = Scalar {
            tnum,
            umin,
            umax,
            smin,
            smax,
        };
        if !r.sync() {
            // cannot happen for a consistent truncated input; never return
            // an empty (unsound) state
            return Scalar {
                tnum: Tnum::unknown(),
                umin: 0,
                umax: u64::MAX,
                smin: i32::MIN as i64,
                smax: i32::MAX as i64,
            };
        }
        r
    }

    pub fn is_subset_of(&self, o: &Scalar) -> bool {
        self.umin >= o.umin
            && self.umax <= o.umax
            && self.smin >= o.smin
            && self.smax <= o.smax
            && self.tnum.is_subset_of(&o.tnum)
    }

    /// Least upper bound: the tightest scalar containing every value either
    /// operand could hold. Used to join abstract states across paths reaching
    /// the same PC (see [`VerifyOk::pc_regs`]).
    pub fn join(&self, o: &Scalar) -> Scalar {
        let mut r = Scalar {
            tnum: self.tnum.union(o.tnum),
            umin: self.umin.min(o.umin),
            umax: self.umax.max(o.umax),
            smin: self.smin.min(o.smin),
            smax: self.smax.max(o.smax),
        };
        // `sync` only tightens; a union of two valid scalars stays non-empty.
        // Guard defensively: if reconciliation somehow contradicts, widen to
        // the safe top element rather than keep an empty (unsound) state.
        if !r.sync() {
            return Scalar::unknown();
        }
        r
    }
}

impl core::fmt::Display for Scalar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_const() {
            return write!(f, "{}", self.umin as i64);
        }
        if *self == Scalar::unknown() {
            return write!(f, "scalar");
        }
        write!(f, "scalar(")?;
        let mut first = true;
        if self.umin != 0 || self.umax != u64::MAX {
            write!(f, "u=[{},{}]", self.umin, self.umax)?;
            first = false;
        }
        if self.smin != i64::MIN || self.smax != i64::MAX {
            if !first {
                write!(f, " ")?;
            }
            write!(f, "s=[{},{}]", self.smin, self.smax)?;
            first = false;
        }
        if self.tnum != Tnum::unknown() {
            if !first {
                write!(f, " ")?;
            }
            write!(f, "t={}", self.tnum)?;
        }
        write!(f, ")")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtrKind {
    /// Pointer into the stack of frame `frame`.
    Stack { frame: usize },
    /// Pointer into the context region.
    Ctx,
    /// Direct packet pointer loaded from `xdp_md.data`. `range` is the number
    /// of bytes from packet start proven accessible by a data_end comparison.
    Packet { range: u32 },
    /// Sentinel pointer loaded from `xdp_md.data_end`; never dereferenceable.
    PacketEnd,
    /// A map object pointer (not dereferenceable).
    Map { map: u32 },
    /// Pointer into a map value.
    MapValue { map: u32 },
    /// Result of map_lookup_elem before the null check.
    MapValueOrNull { map: u32, id: u32 },
    /// Result of looking up an `ARRAY_OF_MAPS`; becomes a map pointer after a
    /// null check. `map` is the verifier's inner-map template index.
    MapOrNull { map: u32, id: u32 },
    /// Writable ringbuf record of `size` bytes (from ringbuf_reserve, after the
    /// null check). `id` ties every copy together for consume-tracking.
    RingbufMem { id: u32, size: u32 },
    /// Result of ringbuf_reserve before the null check.
    RingbufMemOrNull { id: u32, size: u32 },
    /// A ringbuf record already submitted/discarded; any further use is an
    /// error (use-after-consume).
    RingbufConsumed { id: u32 },
    /// Pointer into a VM-owned external region returned by a typed helper.
    ExternalMemory { size: u32, writable: bool },
    /// A BTF-typed kernel pointer (the kernel's `PTR_TO_BTF_ID`): points at a
    /// struct/union of BTF type id `btf_id` in the target BTF (`Config::
    /// btf_ctx`). Read-only; loads are typed by `Btf::read_kind` (pointer
    /// members chase to another `BtfId`, everything else is a scalar) and are
    /// executed as fault-tolerant probe reads (kernel `BPF_PROBE_MEM`).
    BtfId { btf_id: u32 },
    /// Nullable iterator-element BTF pointer. It becomes `BtfId` after an
    /// equality/inequality comparison against zero.
    BtfIdOrNull { btf_id: u32, id: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ptr {
    pub kind: PtrKind,
    /// Known constant part of the offset.
    pub off: i64,
    /// Variable part of the offset (const 0 when none).
    pub var: Scalar,
}

impl Ptr {
    fn new(kind: PtrKind) -> Ptr {
        Ptr {
            kind,
            off: 0,
            var: Scalar::constant(0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegState {
    Uninit,
    Scalar(Scalar),
    Ptr(Ptr),
}

impl RegState {
    /// Least upper bound of two register states for the same PC reached along
    /// different paths. A scalar joins with a scalar; a pointer with an
    /// identical-kind/-offset pointer joins its variable part; anything else
    /// (including one side `Uninit` that the other read as a value) widens to
    /// the top scalar. Sound over-approximation: a fact true in the join holds
    /// on every joined path.
    pub fn join(&self, o: &RegState) -> RegState {
        match (self, o) {
            (RegState::Uninit, RegState::Uninit) => RegState::Uninit,
            (RegState::Scalar(a), RegState::Scalar(b)) => RegState::Scalar(a.join(b)),
            (RegState::Ptr(a), RegState::Ptr(b))
                if a.kind == b.kind && a.off == b.off =>
            {
                RegState::Ptr(Ptr {
                    kind: a.kind,
                    off: a.off,
                    var: a.var.join(&b.var),
                })
            }
            _ => RegState::Scalar(Scalar::unknown()),
        }
    }

    fn subsumed_by(&self, old: &RegState) -> bool {
        match (old, self) {
            (RegState::Uninit, _) => true, // old never read this reg
            (RegState::Scalar(o), RegState::Scalar(n)) => n.is_subset_of(o),
            (RegState::Ptr(o), RegState::Ptr(n)) => {
                o.kind == n.kind && o.off == n.off && n.var.is_subset_of(&o.var)
            }
            _ => false,
        }
    }
}

impl core::fmt::Display for RegState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RegState::Uninit => write!(f, "?"),
            RegState::Scalar(s) => write!(f, "{s}"),
            RegState::Ptr(p) => {
                match p.kind {
                    PtrKind::Stack { frame } => write!(f, "fp{frame}")?,
                    PtrKind::Ctx => write!(f, "ctx")?,
                    PtrKind::Packet { range } => write!(f, "packet[r={range}]")?,
                    PtrKind::PacketEnd => write!(f, "packet_end")?,
                    PtrKind::Map { map } => write!(f, "map{map}")?,
                    PtrKind::MapValue { map } => write!(f, "map{map}_value")?,
                    PtrKind::MapValueOrNull { map, .. } => write!(f, "map{map}_value_or_null")?,
                    PtrKind::MapOrNull { map, .. } => write!(f, "map{map}_or_null")?,
                    PtrKind::RingbufMem { size, .. } => write!(f, "ringbuf_mem[{size}]")?,
                    PtrKind::RingbufMemOrNull { size, .. } => {
                        write!(f, "ringbuf_mem_or_null[{size}]")?
                    }
                    PtrKind::BtfIdOrNull { btf_id, .. } => {
                        write!(f, "kptr_or_null(btf{btf_id})")?
                    }
                    PtrKind::RingbufConsumed { .. } => write!(f, "ringbuf_consumed")?,
                    PtrKind::ExternalMemory { size, writable } => write!(
                        f,
                        "external_mem[{size},{}]",
                        if writable { "rw" } else { "ro" }
                    )?,
                    PtrKind::BtfId { btf_id } => write!(f, "kptr(btf{btf_id})")?,
                }
                if p.off != 0 {
                    write!(f, "{:+}", p.off)?;
                }
                if !p.var.is_const() || p.var.umin != 0 {
                    write!(f, "+var{}", p.var)?;
                }
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Stack modeling
// ---------------------------------------------------------------------------

const SLOTS: usize = STACK_SIZE / 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotState {
    /// Full 8-byte spill of a register (via aligned 8-byte store).
    Spill(RegState),
    /// Byte-granular data; bit i set = byte i initialized.
    Bytes(u8),
}

impl SlotState {
    const EMPTY: SlotState = SlotState::Bytes(0);

    fn init_mask(&self) -> u8 {
        match self {
            SlotState::Spill(_) => 0xff,
            SlotState::Bytes(m) => *m,
        }
    }
    fn subsumed_by(&self, old: &SlotState) -> bool {
        match (old, self) {
            (SlotState::Spill(o), SlotState::Spill(n)) => n.subsumed_by(o),
            (SlotState::Spill(_), _) => false,
            (SlotState::Bytes(om), n) => {
                // old byte pattern must be covered: every byte old had
                // initialized must be initialized in new
                om & !n.init_mask() == 0
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Frame {
    regs: [RegState; NUM_REGS],
    /// Equality class for scalar registers (0 = no tracked equality).
    scalar_ids: [u32; NUM_REGS],
    stack: [SlotState; SLOTS],
    /// Scalar equality class for aligned 8-byte spills.
    spill_ids: [u32; SLOTS],
    /// Where execution resumes in the caller (frames > 0).
    ret_pc: usize,
}

impl Frame {
    fn new(ret_pc: usize) -> Frame {
        Frame {
            regs: [RegState::Uninit; NUM_REGS],
            scalar_ids: [0; NUM_REGS],
            stack: [SlotState::EMPTY; SLOTS],
            spill_ids: [0; SLOTS],
            ret_pc,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct VState {
    frames: Vec<Frame>,
}

/// States remembered at one prune point, with a miss-streak backoff so that
/// points which never yield prunes (e.g. a loop counting a fresh constant
/// every iteration) stop paying the subsumption-scan cost.
#[derive(Default)]
struct PruneList {
    states: Vec<VState>,
    cursor: usize,
    miss_streak: u32,
    arrivals: u32,
}

const MISS_STREAK_LIMIT: u32 = 256;
const BACKOFF_SCAN_EVERY: u32 = 64;

impl VState {
    fn cur(&self) -> &Frame {
        self.frames.last().unwrap()
    }
    fn cur_mut(&mut self) -> &mut Frame {
        self.frames.last_mut().unwrap()
    }

    fn subsumed_by(&self, old: &VState) -> bool {
        if self.frames.len() != old.frames.len() {
            return false;
        }
        for (nf, of) in self.frames.iter().zip(&old.frames) {
            if nf.ret_pc != of.ret_pc {
                return false;
            }
            for r in 0..NUM_REGS {
                if !nf.regs[r].subsumed_by(&of.regs[r]) {
                    return false;
                }
            }
            for s in 0..SLOTS {
                if !nf.stack[s].subsumed_by(&of.stack[s]) {
                    return false;
                }
            }
        }
        // An old equality relation is an assumption its future branch
        // refinement may use, so the new state is covered only if it carries
        // at least the same relation. Numeric ids are path-local; compare the
        // induced equivalence pattern, not the numbers themselves.
        let ids = |state: &VState| {
            let mut out = Vec::new();
            for frame in &state.frames {
                out.extend_from_slice(&frame.scalar_ids);
                out.extend_from_slice(&frame.spill_ids);
            }
            out
        };
        let new_ids = ids(self);
        let old_ids = ids(old);
        let mut classes = LookupMap::new();
        for (&old_id, &new_id) in old_ids.iter().zip(&new_ids) {
            if old_id == 0 {
                continue;
            }
            if let Some(&first_new) = classes.get(&old_id) {
                if first_new == 0 || new_id == 0 || first_new != new_id {
                    return false;
                }
            } else {
                classes.insert(old_id, new_id);
            }
        }
        true
    }

    fn render(&self) -> String {
        let mut out = String::new();
        let f = self.cur();
        if self.frames.len() > 1 {
            let _ = write!(out, "frame{} ", self.frames.len() - 1);
        }
        for (i, r) in f.regs.iter().enumerate().take(10) {
            if !matches!(r, RegState::Uninit) {
                let _ = write!(out, "r{i}={r} ");
            }
        }
        let used: Vec<usize> = (0..SLOTS)
            .filter(|&s| f.stack[s] != SlotState::EMPTY)
            .collect();
        if !used.is_empty() {
            let _ = write!(out, "stack:");
            for s in used {
                let off = (s as i64) * 8 - STACK_SIZE as i64;
                match &f.stack[s] {
                    SlotState::Spill(r) => {
                        let _ = write!(out, " [{off}]={r}");
                    }
                    SlotState::Bytes(m) => {
                        let _ = write!(out, " [{off}]=mm({m:08b})");
                    }
                }
            }
        }
        out.trim_end().to_string()
    }
}

// ---------------------------------------------------------------------------
// Scalar ALU transfer functions
// ---------------------------------------------------------------------------

pub(crate) fn scalar_add(a: Scalar, b: Scalar) -> Scalar {
    let mut r = Scalar {
        tnum: a.tnum.add(b.tnum),
        ..Scalar::unknown()
    };
    let (lo, o1) = a.umin.overflowing_add(b.umin);
    let (hi, o2) = a.umax.overflowing_add(b.umax);
    if !o1 && !o2 {
        r.umin = lo;
        r.umax = hi;
    }
    if let (Some(lo), Some(hi)) = (a.smin.checked_add(b.smin), a.smax.checked_add(b.smax)) {
        r.smin = lo;
        r.smax = hi;
    }
    r.sync();
    r
}

pub(crate) fn scalar_sub(a: Scalar, b: Scalar) -> Scalar {
    let mut r = Scalar {
        tnum: a.tnum.sub(b.tnum),
        ..Scalar::unknown()
    };
    if a.umin >= b.umax {
        r.umin = a.umin - b.umax;
        r.umax = a.umax - b.umin; // a.umax >= a.umin >= b.umax >= b.umin
    }
    if let (Some(lo), Some(hi)) = (a.smin.checked_sub(b.smax), a.smax.checked_sub(b.smin)) {
        r.smin = lo;
        r.smax = hi;
    }
    r.sync();
    r
}

pub(crate) fn scalar_mul(a: Scalar, b: Scalar) -> Scalar {
    let mut r = Scalar {
        tnum: a.tnum.mul(b.tnum),
        ..Scalar::unknown()
    };
    if let (Some(lo), Some(hi)) = (a.umin.checked_mul(b.umin), a.umax.checked_mul(b.umax)) {
        r.umin = lo;
        r.umax = hi;
        if a.smin >= 0 && b.smin >= 0 && hi <= i64::MAX as u64 {
            r.smin = lo as i64;
            r.smax = hi as i64;
        }
    }
    r.sync();
    r
}

/// Unsigned division; division by zero yields 0 (ISA-defined).
pub(crate) fn scalar_div(a: Scalar, b: Scalar) -> Scalar {
    if a.is_const() && b.is_const() {
        let v = if b.umin == 0 { 0 } else { a.umin / b.umin };
        return Scalar::constant(v);
    }
    let mut r = Scalar::unknown();
    r.umin = 0;
    r.umax = a.umax; // result never exceeds the dividend (or 0 on div-by-0)
    r.sync();
    r
}

/// Unsigned modulo; x % 0 leaves dst unchanged (ISA-defined).
pub(crate) fn scalar_mod(a: Scalar, b: Scalar) -> Scalar {
    if a.is_const() && b.is_const() {
        let v = if b.umin == 0 { a.umin } else { a.umin % b.umin };
        return Scalar::constant(v);
    }
    let mut r = Scalar::unknown();
    r.umin = 0;
    r.umax = if b.umin >= 1 {
        a.umax.min(b.umax - 1)
    } else {
        // divisor may be 0 (result = dividend) or up to umax-1 otherwise
        a.umax.max(b.umax.saturating_sub(1))
    };
    r.sync();
    r
}

pub(crate) fn scalar_bitop(op: u8, a: Scalar, b: Scalar) -> Scalar {
    let t = match op {
        alu::AND => a.tnum.and(b.tnum),
        alu::OR => a.tnum.or(b.tnum),
        _ => a.tnum.xor(b.tnum),
    };
    let mut r = Scalar::from_tnum(t);
    match op {
        alu::AND => r.umax = r.umax.min(a.umax.min(b.umax)),
        alu::OR => r.umin = r.umin.max(a.umin.max(b.umin)),
        _ => {}
    }
    r.sync();
    r
}

pub(crate) fn scalar_shift(op: u8, is32: bool, a: Scalar, b: Scalar) -> Result<Scalar, String> {
    let width: u64 = if is32 { 32 } else { 64 };
    if b.is_const() {
        let sh = b.umin;
        if sh >= width {
            return Err(format!("invalid shift by {sh} (width {width})"));
        }
        let sh = sh as u8;
        let r = match op {
            alu::LSH => {
                let mut r = Scalar::from_tnum(a.tnum.lshift(sh));
                if a.umax.leading_zeros() as u64 >= sh as u64 {
                    r.umin = r.umin.max(a.umin << sh);
                    r.umax = r.umax.min(a.umax << sh);
                }
                r.sync();
                r
            }
            alu::RSH => {
                let mut r = Scalar::from_tnum(a.tnum.rshift(sh));
                r.umin = r.umin.max(a.umin >> sh);
                r.umax = r.umax.min(a.umax >> sh);
                r.sync();
                r
            }
            _ => {
                // ARSH
                let mut r = Scalar::from_tnum(a.tnum.arshift(sh, if is32 { 32 } else { 64 }));
                if !is32 {
                    r.smin = r.smin.max(a.smin >> sh);
                    r.smax = r.smax.min(a.smax >> sh);
                }
                r.sync();
                r
            }
        };
        Ok(r)
    } else {
        // variable shift: runtime masks the amount; result largely unknown
        let mut r = Scalar::unknown();
        if op == alu::RSH {
            r.umax = a.umax;
            r.umin = 0;
        }
        r.sync();
        Ok(r)
    }
}

pub(crate) fn scalar_endian(is_swap: bool, width_bits: i32, a: Scalar) -> Scalar {
    let bytes = (width_bits / 8) as u8;
    if a.is_const() {
        let v = a.umin;
        let out = if is_swap {
            match width_bits {
                16 => (v as u16).swap_bytes() as u64,
                32 => (v as u32).swap_bytes() as u64,
                _ => v.swap_bytes(),
            }
        } else {
            // to-LE on a little-endian host: plain truncation
            match width_bits {
                16 => v as u16 as u64,
                32 => v as u32 as u64,
                _ => v,
            }
        };
        return Scalar::constant(out);
    }
    if is_swap {
        Scalar::from_tnum(Tnum::unknown().cast(bytes))
    } else {
        Scalar::from_tnum(a.tnum.cast(bytes))
    }
}

/// Sign-extend a scalar known to hold a value representable in `bits`.
pub(crate) fn scalar_movsx(b: Scalar, bits: u16) -> Scalar {
    let half = 1u64 << (bits - 1);
    if b.umax < half {
        // non-negative in the narrow type: sext == zext == identity
        let mut r = b;
        r.tnum = r.tnum.cast((bits / 8) as u8);
        r.sync();
        return r;
    }
    if b.is_const() {
        let v = b.umin;
        let sext = match bits {
            8 => v as u8 as i8 as i64 as u64,
            16 => v as u16 as i16 as i64 as u64,
            _ => v as u32 as i32 as i64 as u64,
        };
        return Scalar::constant(sext);
    }
    let mut r = Scalar::unknown();
    // result confined to the sign-extended range of the narrow type
    r.smin = -(half as i64);
    r.smax = half as i64 - 1;
    r.sync();
    r
}

pub(crate) fn alu_scalar(
    op: u8,
    is32: bool,
    signed_off: bool,
    a: Scalar,
    b: Scalar,
) -> Result<Scalar, String> {
    let (a, b) = if is32 {
        (a.truncate32(), b.truncate32())
    } else {
        (a, b)
    };
    let mut r = match op {
        alu::ADD => scalar_add(a, b),
        alu::SUB => scalar_sub(a, b),
        alu::MUL => scalar_mul(a, b),
        alu::DIV => {
            if signed_off {
                if a.is_const() && b.is_const() {
                    // signed division is width-sensitive: fold ALU32 in i32
                    // (interpreting the truncated operands as i64 was
                    // unsound, e.g. 1 s/ -1 folded to 0 instead of -1;
                    // found by the operator-soundness harness)
                    let v = if is32 {
                        let (av, bv) = (a.umin as u32 as i32, b.umin as u32 as i32);
                        (if bv == 0 { 0 } else { av.wrapping_div(bv) }) as u32 as u64
                    } else {
                        let (av, bv) = (a.umin as i64, b.umin as i64);
                        if bv == 0 { 0 } else { av.wrapping_div(bv) as u64 }
                    };
                    Scalar::constant(v)
                } else {
                    Scalar::unknown()
                }
            } else {
                scalar_div(a, b)
            }
        }
        alu::MOD => {
            if signed_off {
                if a.is_const() && b.is_const() {
                    // width-sensitive like DIV above; x s% 0 leaves dst
                    let v = if is32 {
                        let (av, bv) = (a.umin as u32 as i32, b.umin as u32 as i32);
                        (if bv == 0 { av } else { av.wrapping_rem(bv) }) as u32 as u64
                    } else {
                        let (av, bv) = (a.umin as i64, b.umin as i64);
                        if bv == 0 {
                            a.umin
                        } else {
                            av.wrapping_rem(bv) as u64
                        }
                    };
                    Scalar::constant(v)
                } else {
                    Scalar::unknown()
                }
            } else {
                scalar_mod(a, b)
            }
        }
        alu::AND | alu::OR | alu::XOR => scalar_bitop(op, a, b),
        alu::LSH | alu::RSH | alu::ARSH => scalar_shift(op, is32, a, b)?,
        _ => return Err(format!("unhandled ALU op {op:#x}")),
    };
    if is32 {
        // zero-extend the 32-bit result
        r.tnum = r.tnum.cast(4);
        if r.umax > u32::MAX as u64 {
            r = Scalar::from_tnum(r.tnum);
        }
        r.umin = r.umin.min(u32::MAX as u64);
        r.umax = r.umax.min(u32::MAX as u64);
        r.smin = r.umin as i64;
        r.smax = r.umax as i64;
        r.sync();
    }
    Ok(r)
}

// ---------------------------------------------------------------------------
// Branch analysis
// ---------------------------------------------------------------------------

/// For a conditional jump, report whether the step from `pc` to `npc` took
/// the branch and where the branch target is. `None` for non-conditionals.
fn cond_branch_info(ins: Insn, pc: usize, npc: usize) -> Option<(bool, usize)> {
    let cls = ins.class();
    if cls != class::JMP && cls != class::JMP32 {
        return None;
    }
    match ins.op() {
        jmp::JA | jmp::EXIT | jmp::CALL => None,
        _ => {
            let target = (pc as i64 + 1 + ins.off as i64) as usize;
            Some((npc == target, target))
        }
    }
}

/// Decide a comparison if the ranges force it. `None` = could go either way.
pub(crate) fn branch_taken(op: u8, a: &Scalar, b: &Scalar) -> Option<bool> {
    match op {
        jmp::JEQ => {
            if a.is_const() && b.is_const() {
                Some(a.umin == b.umin)
            } else if a.umax < b.umin || a.umin > b.umax || a.smax < b.smin || a.smin > b.smax {
                Some(false)
            } else {
                None
            }
        }
        jmp::JNE => branch_taken(jmp::JEQ, a, b).map(|t| !t),
        jmp::JGT => {
            if a.umin > b.umax {
                Some(true)
            } else if a.umax <= b.umin {
                Some(false)
            } else {
                None
            }
        }
        jmp::JGE => {
            if a.umin >= b.umax {
                Some(true)
            } else if a.umax < b.umin {
                Some(false)
            } else {
                None
            }
        }
        jmp::JLT => branch_taken(jmp::JGE, a, b).map(|t| !t),
        jmp::JLE => branch_taken(jmp::JGT, a, b).map(|t| !t),
        jmp::JSGT => {
            if a.smin > b.smax {
                Some(true)
            } else if a.smax <= b.smin {
                Some(false)
            } else {
                None
            }
        }
        jmp::JSGE => {
            if a.smin >= b.smax {
                Some(true)
            } else if a.smax < b.smin {
                Some(false)
            } else {
                None
            }
        }
        jmp::JSLT => branch_taken(jmp::JSGE, a, b).map(|t| !t),
        jmp::JSLE => branch_taken(jmp::JSGT, a, b).map(|t| !t),
        jmp::JSET => {
            if b.is_const() {
                if a.tnum.value & b.umin != 0 {
                    return Some(true); // some known bit overlaps
                }
                if (a.tnum.value | a.tnum.mask) & b.umin == 0 {
                    return Some(false); // no possible bit overlaps
                }
            }
            None
        }
        _ => None,
    }
}

/// Refine `a` and `b` under the assumption `a OP b` is `taken`.
/// Returns false if the assumption is contradictory (dead path).
pub(crate) fn refine(op: u8, taken: bool, a: &mut Scalar, b: &mut Scalar) -> bool {
    // Reduce "not taken" to the inverse op where cleanly possible.
    let (op, taken) = match (op, taken) {
        (jmp::JEQ, false) => (jmp::JNE, true),
        (jmp::JNE, false) => (jmp::JEQ, true),
        (jmp::JGT, false) => (jmp::JLE, true),
        (jmp::JGE, false) => (jmp::JLT, true),
        (jmp::JLT, false) => (jmp::JGE, true),
        (jmp::JLE, false) => (jmp::JGT, true),
        (jmp::JSGT, false) => (jmp::JSLE, true),
        (jmp::JSGE, false) => (jmp::JSLT, true),
        (jmp::JSLT, false) => (jmp::JSGE, true),
        (jmp::JSLE, false) => (jmp::JSGT, true),
        (o, t) => (o, t),
    };
    match (op, taken) {
        (jmp::JEQ, true) => {
            // both take the intersection
            let umin = a.umin.max(b.umin);
            let umax = a.umax.min(b.umax);
            let smin = a.smin.max(b.smin);
            let smax = a.smax.min(b.smax);
            let t = a.tnum.intersect(b.tnum);
            for r in [&mut *a, &mut *b] {
                r.umin = umin;
                r.umax = umax;
                r.smin = smin;
                r.smax = smax;
                r.tnum = t;
            }
        }
        (jmp::JNE, true) => {
            // only useful when one side is const at a range boundary
            fn nudge(x: &mut Scalar, y: &Scalar) {
                if y.is_const() {
                    let c = y.umin;
                    if x.umin == c {
                        x.umin = x.umin.saturating_add(1);
                    }
                    if x.umax == c {
                        x.umax = x.umax.saturating_sub(1);
                    }
                    if x.smin == c as i64 {
                        x.smin = x.smin.saturating_add(1);
                    }
                    if x.smax == c as i64 {
                        x.smax = x.smax.saturating_sub(1);
                    }
                }
            }
            nudge(a, b);
            nudge(b, a);
        }
        (jmp::JGT, true) => {
            // a > b
            if b.umin == u64::MAX {
                return false;
            }
            a.umin = a.umin.max(b.umin + 1);
            b.umax = b.umax.min(a.umax.saturating_sub(1));
        }
        (jmp::JGE, true) => {
            a.umin = a.umin.max(b.umin);
            b.umax = b.umax.min(a.umax);
        }
        (jmp::JLT, true) => {
            if b.umax == 0 {
                return false;
            }
            a.umax = a.umax.min(b.umax - 1);
            b.umin = b.umin.max(a.umin.saturating_add(1));
        }
        (jmp::JLE, true) => {
            a.umax = a.umax.min(b.umax);
            b.umin = b.umin.max(a.umin);
        }
        (jmp::JSGT, true) => {
            if b.smin == i64::MAX {
                return false;
            }
            a.smin = a.smin.max(b.smin + 1);
            b.smax = b.smax.min(a.smax.saturating_sub(1));
        }
        (jmp::JSGE, true) => {
            a.smin = a.smin.max(b.smin);
            b.smax = b.smax.min(a.smax);
        }
        (jmp::JSLT, true) => {
            if b.smax == i64::MIN {
                return false;
            }
            a.smax = a.smax.min(b.smax - 1);
            b.smin = b.smin.max(a.smin.saturating_add(1));
        }
        (jmp::JSLE, true) => {
            a.smax = a.smax.min(b.smax);
            b.smin = b.smin.max(a.smin);
        }
        (jmp::JSET, false)
            // a & b == 0: known-set bits of b are known-zero in a
            if b.is_const() => {
                a.tnum = a.tnum.and(Tnum::const_val(!b.umin));
            }
        _ => {}
    }
    a.sync() && b.sync()
}

/// Outcome of analyzing a conditional jump over two scalars.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::large_enum_variant)] // Copy on the hot path beats boxing
pub(crate) enum CondOutcome {
    /// The ranges force the comparison: only this outcome is possible.
    Decided(bool),
    /// Both outcomes possible. Per outcome (`[not-taken, taken]`): `None` if
    /// refinement proved the outcome contradictory (dead path), else the
    /// refined `(dst, src)` scalars to continue with.
    Both([Option<(Scalar, Scalar)>; 2]),
}

/// Analyze `dst OP src` for a conditional jump: decide it if the abstract
/// values force it, otherwise refine the scalars under each outcome. This is
/// the single entry point used by the verifier's jump step (and the soundness
/// harness), so the truncation/refinement composition is tested as deployed.
pub(crate) fn analyze_cond_jmp(op: u8, is32: bool, sa: Scalar, sb: Scalar) -> CondOutcome {
    let signed_op = matches!(op, jmp::JSGT | jmp::JSGE | jmp::JSLT | jmp::JSLE);
    // 32-bit compares refine only when values fit in 32 bits
    let refinable = !is32 || (sa.umax <= u32::MAX as u64 && sb.umax <= u32::MAX as u64);
    let (ca, cb) = if is32 {
        let (ta, tb) = (sa.truncate32(), sb.truncate32());
        if signed_op {
            // JMP32 signed compares are decided over the s32 view. Deciding
            // them on the zero-extended truncation was unsound (a 32-bit
            // value with the sign bit set looked like a large positive):
            // found by the operator-soundness harness. Kernel:
            // is_branch32_taken / reg_set_min_max use dedicated s32 bounds.
            (ta.sext32_view(), tb.sext32_view())
        } else {
            (ta, tb)
        }
    } else {
        (sa, sb)
    };

    if let Some(taken) = branch_taken(op, &ca, &cb) {
        return CondOutcome::Decided(taken);
    }

    let mut out: [Option<(Scalar, Scalar)>; 2] = [Some((sa, sb)), Some((sa, sb))];
    if refinable {
        for (slot, taken) in [(0usize, false), (1usize, true)] {
            let (mut ra, mut rb) = (ca, cb);
            if refine(op, taken, &mut ra, &mut rb) {
                // refinement of a 32-bit signed compare happened in the
                // sign-extended domain; map back to the zero-extended values
                // the register holds
                if is32 && signed_op {
                    ra = ra.truncate32();
                    rb = rb.truncate32();
                }
                out[slot] = Some((ra, rb));
            } else {
                out[slot] = None; // contradictory: path is dead
            }
        }
    }
    CondOutcome::Both(out)
}

// ---------------------------------------------------------------------------
// The verifier proper
// ---------------------------------------------------------------------------

pub struct Verifier<'a> {
    insns: &'a [Insn],
    maps: &'a [MapDef],
    user_sigs: &'a [(u32, HelperSig)],
    cfg: Config,
    stats: Stats,
    warnings: Vec<String>,
    /// Remembered states per prune point.
    seen: LookupMap<usize, PruneList>,
    prune_points: Vec<bool>,
    insn_state: Vec<Option<(String, usize)>>,
    /// Join-over-all-visits of the current frame's registers per insn (see
    /// [`VerifyOk::pc_regs`]).
    pc_regs: Vec<Option<[RegState; NUM_REGS]>>,
    next_null_id: u32,
    next_scalar_id: u32,
    /// Intern deterministic scalar expressions so applying the same operation
    /// later to another copy recovers the same equality class.
    scalar_expr_ids: LookupMap<(u32, u8, bool, u64, i16), u32>,
    /// Per-insn: loads that go through a BTF pointer and must execute as
    /// fault-tolerant probe reads (kernel `BPF_PROBE_MEM`). See
    /// [`VerifyOk::probe_mem`].
    probe_mem: Vec<bool>,
    /// Per-insn pointer class of LDX instructions (0 = unseen, 1 = BTF
    /// probe read, 2 = ordinary memory) — see [`Verifier::note_ldx_class`].
    mem_class: Vec<u8>,
    /// Path arena: one node per successor of every multi-successor step,
    /// forming a tree of branch decisions rooted at program entry. Used to
    /// replay the failing path when verification is rejected.
    path_nodes: Vec<PathNode>,
    /// During trace replay: map from maybe-null pointer id to the pc and
    /// helper name that created it.
    replay_null_origin: Option<LookupMap<u32, (usize, String)>>,
}

/// One branch decision on a verification path (see `Verifier::path_nodes`).
struct PathNode {
    /// Previous decision on this path.
    parent: Option<u32>,
    /// Index into the successor list that this path followed.
    choice: u8,
}

enum StepOutcome {
    /// Continue at these successor states.
    Next(Vec<(usize, VState)>),
    /// Path finished (program exit).
    Done,
}

impl<'a> Verifier<'a> {
    pub fn new(
        insns: &'a [Insn],
        maps: &'a [MapDef],
        user_sigs: &'a [(u32, HelperSig)],
        cfg: Config,
    ) -> Verifier<'a> {
        Verifier {
            insns,
            maps,
            user_sigs,
            cfg,
            stats: Stats::default(),
            warnings: Vec::new(),
            seen: LookupMap::new(),
            prune_points: Vec::new(),
            insn_state: Vec::new(),
            pc_regs: Vec::new(),
            next_null_id: 1,
            next_scalar_id: 1,
            scalar_expr_ids: LookupMap::new(),
            probe_mem: Vec::new(),
            mem_class: Vec::new(),
            path_nodes: Vec::new(),
            replay_null_origin: None,
        }
    }

    fn err(&self, pc: usize, msg: impl Into<String>) -> VerifyError {
        VerifyError {
            pc,
            msg: msg.into(),
            trace: None,
        }
    }

    fn sig_for(&self, hid: u32) -> Option<HelperSig> {
        builtin_sig(hid).or_else(|| {
            self.user_sigs
                .iter()
                .find(|(i, _)| *i == hid)
                .map(|(_, s)| s.clone())
        })
    }

    pub fn verify(mut self) -> Result<VerifyOk, VerifyError> {
        if self.insns.is_empty() {
            return Err(self.err(0, "empty program"));
        }
        self.check_structure()?;
        self.compute_prune_points();
        self.insn_state = vec![None; self.insns.len()];
        self.pc_regs = vec![None; self.insns.len()];
        self.probe_mem = vec![false; self.insns.len()];
        self.mem_class = vec![0u8; self.insns.len()];

        // work items: (pc, state, last path node, steps taken from entry)
        let mut pending: Vec<(usize, VState, Option<u32>, u32)> =
            vec![(0, self.initial_state(), None, 0)];
        while let Some((pc, state, node, len)) = pending.pop() {
            let mut pc = pc;
            let mut state = state;
            let mut node = node;
            let mut len = len;
            loop {
                if self.stats.insns_processed >= self.cfg.insn_budget {
                    let e = self.err(
                        pc,
                        format!(
                            "program too complex: exceeded {} processed instructions \
                             (unbounded loop?)",
                            self.cfg.insn_budget
                        ),
                    );
                    return Err(self.attach_trace(e, node, len));
                }
                if pc >= self.insns.len() {
                    let e = self.err(pc, "fell off the end of the program");
                    return Err(self.attach_trace(e, node, len));
                }
                // prune / remember
                if self.prune_points[pc] {
                    let cap = self.cfg.max_states_per_pc;
                    let pl = self.seen.entry(pc).or_default();
                    pl.arrivals = pl.arrivals.wrapping_add(1);
                    let backoff = pl.miss_streak >= MISS_STREAK_LIMIT
                        && !pl.arrivals.is_multiple_of(BACKOFF_SCAN_EVERY);
                    if !backoff {
                        if pl.states.iter().any(|old| state.subsumed_by(old)) {
                            self.stats.states_pruned += 1;
                            pl.miss_streak = 0;
                            break;
                        }
                        pl.miss_streak = pl.miss_streak.saturating_add(1);
                        // ring buffer: keep the most recent states so
                        // convergent forks of a loop iteration still prune
                        if pl.states.len() < cap {
                            pl.states.push(state.clone());
                        } else {
                            pl.states[pl.cursor % cap] = state.clone();
                            pl.cursor = pl.cursor.wrapping_add(1);
                        }
                    }
                }
                self.stats.insns_processed += 1;
                self.stats.max_frames = self.stats.max_frames.max(state.frames.len());
                match &mut self.insn_state[pc] {
                    Some((_, n)) => *n += 1,
                    slot @ None => *slot = Some((state.render(), 1)),
                }
                // Join this visit's current-frame registers into the per-PC
                // abstract state used by the optimizer (sound across paths).
                {
                    let regs = &state.cur().regs;
                    match &mut self.pc_regs[pc] {
                        Some(acc) => {
                            for r in 0..NUM_REGS {
                                acc[r] = acc[r].join(&regs[r]);
                            }
                        }
                        slot @ None => *slot = Some(*regs),
                    }
                }

                match self.step(pc, state) {
                    Err(e) => return Err(self.attach_trace(e, node, len)),
                    Ok(StepOutcome::Done) => break,
                    Ok(StepOutcome::Next(mut succs)) => {
                        if succs.is_empty() {
                            break; // all successors dead
                        }
                        if succs.len() > 1 {
                            // record one decision node per successor
                            let first_id = self.path_nodes.len() as u32;
                            for i in 0..succs.len() {
                                self.path_nodes.push(PathNode {
                                    parent: node,
                                    choice: i as u8,
                                });
                            }
                            let cont = succs.len() - 1; // we continue on the last
                            let (npc, nstate) = succs.pop().unwrap();
                            for (i, (opc, ostate)) in succs.into_iter().enumerate() {
                                self.stats.states_explored += 1;
                                pending.push((opc, ostate, Some(first_id + i as u32), len + 1));
                            }
                            node = Some(first_id + cont as u32);
                            len += 1;
                            pc = npc;
                            state = nstate;
                        } else {
                            let (npc, nstate) = succs.pop().unwrap();
                            len += 1;
                            pc = npc;
                            state = nstate;
                        }
                    }
                }
            }
        }

        self.stats.prune_points = self.prune_points.iter().filter(|p| **p).count();
        Ok(VerifyOk {
            stats: self.stats,
            warnings: self.warnings,
            insn_state: self.insn_state,
            pc_regs: self.pc_regs,
            probe_mem: self.probe_mem,
        })
    }

    // -- counterexample trace (rejection explainer) --------------------------

    /// Initial abstract state: r1 = ctx (if any), r10 = fp.
    fn initial_state(&self) -> VState {
        let mut frame = Frame::new(0);
        if self.cfg.ctx_size > 0 || self.cfg.btf_ctx.is_some() {
            frame.regs[1] = RegState::Ptr(Ptr::new(PtrKind::Ctx));
        }
        frame.regs[REG_FP as usize] = RegState::Ptr(Ptr::new(PtrKind::Stack { frame: 0 }));
        VState {
            frames: vec![frame],
        }
    }

    /// Attach a counterexample trace to `e` by replaying the failing path.
    /// `node` is the last branch decision on the path, `len` the number of
    /// instructions executed from entry (the failing one not included).
    fn attach_trace(&mut self, mut e: VerifyError, node: Option<u32>, len: u32) -> VerifyError {
        e.trace = self.build_trace(e.pc, node, len);
        e
    }

    fn build_trace(&mut self, err_pc: usize, node: Option<u32>, len: u32) -> Option<Trace> {
        // Reconstruct the branch-decision list from entry.
        let mut decisions: Vec<u8> = Vec::new();
        let mut n = node;
        while let Some(i) = n {
            let nd = &self.path_nodes[i as usize];
            decisions.push(nd.choice);
            n = nd.parent;
        }
        decisions.reverse();
        self.replay_null_origin = Some(LookupMap::new());
        self.replay(err_pc, &decisions, len)
    }

    /// Re-run the abstract interpreter along one recorded path (pruning
    /// disabled), capturing a bounded window of per-step states. `step()` is
    /// deterministic in `(pc, state)`, so following the recorded choices at
    /// every multi-successor point reproduces the exact failing path.
    fn replay(&mut self, err_pc: usize, decisions: &[u8], len: u32) -> Option<Trace> {
        const TRACE_HEAD: usize = 8;
        const TRACE_TAIL: usize = 48;
        fn push_step(
            head: &mut Vec<TraceStep>,
            tail: &mut VecDeque<TraceStep>,
            total: &mut usize,
            s: TraceStep,
        ) {
            if head.len() < TRACE_HEAD {
                head.push(s.clone());
            }
            if tail.len() == TRACE_TAIL {
                tail.pop_front();
            }
            tail.push_back(s);
            *total += 1;
        }

        let mut state = self.initial_state();
        let mut pc = 0usize;
        let mut di = 0usize;
        let mut head: Vec<TraceStep> = Vec::new();
        let mut tail: VecDeque<TraceStep> = VecDeque::new();
        let mut total = 0usize;
        let final_state;

        loop {
            if total as u32 == len {
                // Arrived at the failing instruction; do not execute it.
                if pc != err_pc {
                    return None; // replay diverged (should not happen)
                }
                if pc < self.insns.len() {
                    let s = TraceStep {
                        pc,
                        state: state.render(),
                        branch: None,
                    };
                    push_step(&mut head, &mut tail, &mut total, s);
                }
                final_state = state;
                break;
            }
            if pc >= self.insns.len() {
                return None;
            }
            let pre = state.render();
            let ins = self.insns[pc];
            let cur_pc = pc;
            let succs = match self.step(pc, state) {
                Ok(StepOutcome::Next(s)) => s,
                _ => return None, // exit or error before the recorded point
            };
            let choice = if succs.len() > 1 {
                let c = *decisions.get(di)? as usize;
                di += 1;
                c
            } else {
                0
            };
            let (npc, nstate) = succs.into_iter().nth(choice)?;
            let branch = cond_branch_info(ins, cur_pc, npc);
            push_step(
                &mut head,
                &mut tail,
                &mut total,
                TraceStep {
                    pc: cur_pc,
                    state: pre,
                    branch,
                },
            );
            pc = npc;
            state = nstate;
        }

        // Assemble head + tail windows without duplicating overlap.
        let cut = head.len();
        let ring_start = total - tail.len();
        let mut steps = head;
        for (j, s) in tail.iter().enumerate() {
            if ring_start + j >= cut {
                steps.push(s.clone());
            }
        }
        let notes = self.trace_notes(err_pc, &final_state);
        Some(Trace {
            steps,
            truncated: ring_start.saturating_sub(cut),
            notes,
        })
    }

    /// Registers the instruction at `pc` reads (used for cause hints).
    fn regs_read_at(&self, pc: usize) -> Vec<u8> {
        let ins = self.insns[pc];
        let mut v: Vec<u8> = Vec::new();
        match ins.class() {
            class::ALU | class::ALU64 => {
                if ins.op() != alu::MOV {
                    v.push(ins.dst);
                }
                if ins.is_src_reg() && ins.op() != alu::NEG && ins.op() != alu::END {
                    v.push(ins.src);
                }
            }
            class::LD if !ins.is_wide() => {
                v.push(6);
                if ins.mem_mode() == mode::IND {
                    v.push(ins.src);
                }
            }
            class::LD => {}
            class::LDX => v.push(ins.src),
            class::ST => v.push(ins.dst),
            class::STX => {
                v.push(ins.dst);
                v.push(ins.src);
            }
            class::JMP | class::JMP32 => match ins.op() {
                jmp::EXIT => v.push(0),
                jmp::JA => {}
                jmp::CALL => {
                    if ins.src != call_kind::LOCAL {
                        v.extend(1..=5u8);
                    }
                }
                _ => {
                    v.push(ins.dst);
                    if ins.is_src_reg() {
                        v.push(ins.src);
                    }
                }
            },
            _ => {} // LD (lddw): no register reads
        }
        v.dedup();
        v
    }

    /// Cause hints derived from the failing instruction and the abstract
    /// state right before it.
    fn trace_notes(&self, err_pc: usize, pre: &VState) -> Vec<String> {
        let mut notes = Vec::new();
        if err_pc >= self.insns.len() {
            return notes;
        }
        let f = pre.cur();
        for r in self.regs_read_at(err_pc) {
            match f.regs[r as usize] {
                RegState::Uninit => notes.push(format!(
                    "r{r} is uninitialized: no instruction on this path writes it \
                     before insn {err_pc}"
                )),
                RegState::Ptr(p) => {
                    if let PtrKind::MapValueOrNull { map, id } | PtrKind::MapOrNull { map, id } =
                        p.kind
                    {
                        let name = &self.maps[map as usize].name;
                        match self.replay_null_origin.as_ref().and_then(|m| m.get(&id)) {
                            Some((opc, helper)) => notes.push(format!(
                                "r{r} may be NULL here: it was returned by {helper} at \
                                 insn {opc} (map '{name}'), and this path never compares \
                                 it against 0"
                            )),
                            None => notes.push(format!(
                                "r{r} may be NULL here and is not null-checked on this path"
                            )),
                        }
                    }
                }
                _ => {}
            }
        }
        notes
    }

    // -- structural pre-pass ------------------------------------------------

    /// Validate opcodes, jump targets and lddw pairing; reject unreachable
    /// instructions and missing exit paths.
    fn check_structure(&mut self) -> Result<(), VerifyError> {
        let n = self.insns.len();
        // mark lddw second slots
        let mut is_second = vec![false; n];
        let mut i = 0;
        while i < n {
            let ins = self.insns[i];
            if ins.is_wide() {
                if i + 1 >= n {
                    return Err(self.err(i, "truncated lddw"));
                }
                if self.insns[i + 1].opcode != 0 {
                    return Err(self.err(i + 1, "invalid lddw second slot (opcode must be 0)"));
                }
                is_second[i + 1] = true;
                i += 2;
            } else {
                if ins.opcode == 0 {
                    return Err(self.err(i, "invalid opcode 0"));
                }
                i += 1;
            }
        }
        // per-insn validity + collect edges
        let mut edges: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut i = 0;
        while i < n {
            let ins = self.insns[i];
            let width = if ins.is_wide() { 2 } else { 1 };
            self.check_insn_form(i, ins)?;
            let add_edge = |targets: &mut Vec<usize>, t: i64| -> Result<(), VerifyError> {
                if t < 0 || t as usize >= n {
                    return Err(VerifyError {
                        pc: i,
                        msg: format!("jump target {t} out of range"),
                        trace: None,
                    });
                }
                if is_second[t as usize] {
                    return Err(VerifyError {
                        pc: i,
                        msg: format!("jump target {t} lands in the middle of lddw"),
                        trace: None,
                    });
                }
                targets.push(t as usize);
                Ok(())
            };
            let cls = ins.class();
            if cls == class::JMP || cls == class::JMP32 {
                match ins.op() {
                    jmp::EXIT => {}
                    jmp::JA => {
                        let rel = if cls == class::JMP32 {
                            ins.imm as i64
                        } else {
                            ins.off as i64
                        };
                        add_edge(&mut edges[i], i as i64 + 1 + rel)?;
                    }
                    jmp::CALL => {
                        if ins.src == call_kind::LOCAL {
                            add_edge(&mut edges[i], i as i64 + 1 + ins.imm as i64)?;
                        }
                        add_edge(&mut edges[i], (i + width) as i64)?;
                    }
                    _ => {
                        add_edge(&mut edges[i], i as i64 + 1 + ins.off as i64)?;
                        add_edge(&mut edges[i], (i + width) as i64)?;
                    }
                }
            } else {
                if i + width > n {
                    return Err(self.err(i, "program does not end with exit"));
                }
                if i + width < n {
                    add_edge(&mut edges[i], (i + width) as i64)?;
                } else {
                    return Err(self.err(i, "last instruction must be exit or jump"));
                }
            }
            i += width;
        }
        // reachability
        let mut reach = vec![false; n];
        let mut stack = vec![0usize];
        while let Some(p) = stack.pop() {
            if reach[p] {
                continue;
            }
            reach[p] = true;
            for &t in &edges[p] {
                if !reach[t] {
                    stack.push(t);
                }
            }
        }
        let mut i = 0;
        while i < n {
            if !reach[i] && !is_second[i] {
                return Err(self.err(i, "unreachable instruction"));
            }
            i += if self.insns[i].is_wide() { 2 } else { 1 };
        }
        Ok(())
    }

    /// Reject malformed single instructions (bad opcodes, bad field use).
    fn check_insn_form(&mut self, pc: usize, ins: Insn) -> Result<(), VerifyError> {
        let bad = |msg: String| VerifyError {
            pc,
            msg,
            trace: None,
        };
        if ins.dst >= NUM_REGS as u8 {
            return Err(bad(format!("invalid dst register r{}", ins.dst)));
        }
        if ins.src >= NUM_REGS as u8
            && !(ins.class() == class::LD && ins.mem_mode() != mode::IND)
        {
            return Err(bad(format!("invalid src register r{}", ins.src)));
        }
        match ins.class() {
            class::ALU | class::ALU64 => match ins.op() {
                alu::ADD | alu::SUB | alu::MUL | alu::OR | alu::AND | alu::LSH | alu::RSH
                | alu::XOR | alu::ARSH => Ok(()),
                alu::DIV | alu::MOD => {
                    if ins.off != 0 && ins.off != 1 {
                        Err(bad(format!("invalid offset {} for div/mod", ins.off)))
                    } else {
                        Ok(())
                    }
                }
                alu::MOV => match ins.off {
                    0 | 8 | 16 | 32 => Ok(()),
                    o => Err(bad(format!("invalid offset {o} for mov"))),
                },
                alu::NEG => Ok(()),
                alu::END => match ins.imm {
                    16 | 32 | 64 => Ok(()),
                    w => Err(bad(format!("invalid byte swap width {w}"))),
                },
                op => Err(bad(format!("unknown ALU op {op:#x}"))),
            },
            class::JMP | class::JMP32 => match ins.op() {
                jmp::JA | jmp::EXIT => Ok(()),
                jmp::CALL => {
                    if ins.class() == class::JMP32 {
                        Err(bad("call must use the JMP class".into()))
                    } else if ins.src == call_kind::KFUNC {
                        Err(bad("kfunc calls are not supported".into()))
                    } else {
                        Ok(())
                    }
                }
                jmp::JEQ | jmp::JGT | jmp::JGE | jmp::JSET | jmp::JNE | jmp::JSGT | jmp::JSGE
                | jmp::JLT | jmp::JLE | jmp::JSLT | jmp::JSLE => Ok(()),
                op => Err(bad(format!("unknown JMP op {op:#x}"))),
            },
            class::LD => {
                if ins.is_wide() {
                    match ins.src {
                        pseudo::IMM64 => Ok(()),
                        pseudo::MAP_ID | pseudo::MAP_VALUE => {
                            if (ins.imm as usize) < self.maps.len() {
                                Ok(())
                            } else {
                                Err(bad(format!("lddw references unknown map {}", ins.imm)))
                            }
                        }
                        s => Err(bad(format!("unsupported lddw pseudo src {s}"))),
                    }
                } else if self.cfg.legacy_packet == LegacyPacketProfile::Disabled {
                    Err(bad(format!(
                        "legacy packet profile disabled for opcode {:#04x}", ins.opcode
                    )))
                } else if !matches!(ins.mem_mode(), mode::ABS | mode::IND) {
                    Err(bad(format!("invalid LD mode {:#x}", ins.mem_mode())))
                } else if ins.mem_size() == 8
                    && self.cfg.legacy_packet != LegacyPacketProfile::Rbpf041
                {
                    Err(bad("legacy packet DW loads require the Rbpf041 profile".into()))
                } else if ins.dst != 0 || ins.off != 0 {
                    Err(bad("legacy packet loads require dst=0 and off=0".into()))
                } else if ins.mem_mode() == mode::ABS && ins.src != 0 {
                    Err(bad("LD_ABS requires src=0".into()))
                } else if ins.mem_mode() == mode::ABS && ins.imm < 0 {
                    Err(bad("LD_ABS packet offset must be nonnegative".into()))
                } else {
                    Ok(())
                }
            }
            class::LDX => match ins.mem_mode() {
                mode::MEM => Ok(()),
                mode::MEMSX => {
                    if ins.mem_size() == 8 {
                        Err(bad("sign-extending 8-byte load is meaningless".into()))
                    } else {
                        Ok(())
                    }
                }
                m => Err(bad(format!("invalid LDX mode {m:#x}"))),
            },
            class::ST => {
                if ins.mem_mode() == mode::MEM {
                    Ok(())
                } else {
                    Err(bad(format!("invalid ST mode {:#x}", ins.mem_mode())))
                }
            }
            class::STX => match ins.mem_mode() {
                mode::MEM => Ok(()),
                mode::ATOMIC => {
                    let sz = ins.mem_size();
                    if sz != 4 && sz != 8 {
                        return Err(bad("atomic operations require u32 or u64".into()));
                    }
                    use crate::insn::atomic as a;
                    match ins.imm {
                        x if [
                            a::ADD,
                            a::OR,
                            a::AND,
                            a::XOR,
                            a::ADD | a::FETCH,
                            a::OR | a::FETCH,
                            a::AND | a::FETCH,
                            a::XOR | a::FETCH,
                            a::XCHG,
                            a::CMPXCHG,
                        ]
                        .contains(&x) =>
                        {
                            Ok(())
                        }
                        x => Err(bad(format!("unknown atomic operation {x:#x}"))),
                    }
                }
                m => Err(bad(format!("invalid STX mode {m:#x}"))),
            },
            _ => unreachable!(),
        }
    }

    fn compute_prune_points(&mut self) {
        let n = self.insns.len();
        let mut pts = vec![false; n];
        let mut i = 0;
        while i < n {
            let ins = self.insns[i];
            let cls = ins.class();
            if cls == class::JMP || cls == class::JMP32 {
                match ins.op() {
                    jmp::EXIT => {}
                    jmp::JA => {
                        let rel = if cls == class::JMP32 {
                            ins.imm as i64
                        } else {
                            ins.off as i64
                        };
                        let t = i as i64 + 1 + rel;
                        if t >= 0 && (t as usize) < n {
                            pts[t as usize] = true;
                        }
                    }
                    jmp::CALL => {
                        if ins.src == call_kind::LOCAL {
                            let t = i as i64 + 1 + ins.imm as i64;
                            if t >= 0 && (t as usize) < n {
                                pts[t as usize] = true;
                            }
                        }
                    }
                    _ => {
                        let t = i as i64 + 1 + ins.off as i64;
                        if t >= 0 && (t as usize) < n {
                            pts[t as usize] = true;
                        }
                        if i + 1 < n {
                            pts[i + 1] = true;
                        }
                    }
                }
            }
            i += if ins.is_wide() { 2 } else { 1 };
        }
        self.prune_points = pts;
    }

    // -- reading/writing registers -----------------------------------------

    fn read_reg(&self, state: &VState, pc: usize, r: u8) -> Result<RegState, VerifyError> {
        let v = state.cur().regs[r as usize];
        if matches!(v, RegState::Uninit) {
            return Err(self.err(pc, format!("read of uninitialized register r{r}")));
        }
        Ok(v)
    }

    fn write_reg(
        &self,
        state: &mut VState,
        pc: usize,
        r: u8,
        v: RegState,
    ) -> Result<(), VerifyError> {
        if r == REG_FP {
            return Err(self.err(pc, "r10 (frame pointer) is read-only"));
        }
        let frame = state.cur_mut();
        frame.regs[r as usize] = v;
        frame.scalar_ids[r as usize] = 0;
        Ok(())
    }

    fn fresh_scalar_id(&mut self) -> u32 {
        let id = self.next_scalar_id;
        self.next_scalar_id = self.next_scalar_id.wrapping_add(1).max(1);
        id
    }

    fn scalar_expr_id(
        &mut self,
        parent: u32,
        op: u8,
        is32: bool,
        rhs: u64,
        off: i16,
    ) -> u32 {
        let key = (parent, op, is32, rhs, off);
        if let Some(&id) = self.scalar_expr_ids.get(&key) {
            id
        } else {
            let id = self.fresh_scalar_id();
            self.scalar_expr_ids.insert(key, id);
            id
        }
    }

    fn scalar_meet(a: Scalar, b: Scalar) -> Option<Scalar> {
        let mut value = Scalar {
            tnum: a.tnum.intersect(b.tnum),
            umin: a.umin.max(b.umin),
            umax: a.umax.min(b.umax),
            smin: a.smin.max(b.smin),
            smax: a.smax.min(b.smax),
        };
        value.sync().then_some(value)
    }

    /// Assign a scalar expression id to `reg` and reconcile its bounds with
    /// every live register/spill carrying the same expression. If two paths
    /// have contradictory facts the current path is infeasible; dropping the
    /// new relation is the conservative fallback.
    fn set_scalar_id(state: &mut VState, reg: u8, id: u32, value: Scalar) {
        let mut common = value;
        for frame in &state.frames {
            for (slot, &scalar_id) in frame.regs.iter().zip(&frame.scalar_ids) {
                if scalar_id == id {
                    if let RegState::Scalar(other) = slot {
                        let Some(meet) = Self::scalar_meet(common, *other) else {
                            return;
                        };
                        common = meet;
                    }
                }
            }
            for (slot, &scalar_id) in frame.stack.iter().zip(&frame.spill_ids) {
                if scalar_id == id {
                    if let SlotState::Spill(RegState::Scalar(other)) = slot {
                        let Some(meet) = Self::scalar_meet(common, *other) else {
                            return;
                        };
                        common = meet;
                    }
                }
            }
        }
        state.cur_mut().scalar_ids[reg as usize] = id;
        Self::mark_scalar_id(state, id, common);
    }

    // -- memory access checking ---------------------------------------------

    /// Check an access of `size` bytes through pointer `p`, at additional
    /// constant displacement `disp`. Returns the resolved constant stack
    /// offset when the target is the stack.
    #[allow(clippy::too_many_arguments)]
    fn check_mem_access(
        &mut self,
        state: &VState,
        pc: usize,
        p: &Ptr,
        disp: i64,
        size: u64,
        write: bool,
        // True for a real BPF_LDX/STX/ST/atomic access (natural alignment is
        // required); false for a helper argument buffer whose `size` is just
        // the byte length and carries no alignment constraint.
        align: bool,
    ) -> Result<Option<(usize, i64)>, VerifyError> {
        let (region_size, what): (u64, &str) = match p.kind {
            PtrKind::Stack { frame } => {
                if !p.var.is_const() || p.var.umin != 0 {
                    return Err(self.err(pc, "variable-offset stack access is not allowed"));
                }
                let off = p.off + disp;
                if off < -(STACK_SIZE as i64) || off + size as i64 > 0 {
                    return Err(self.err(
                        pc,
                        format!(
                            "stack access out of bounds: off {off} size {size} \
                             (valid: [-{STACK_SIZE}, 0))"
                        ),
                    ));
                }
                // The kernel ALWAYS enforces natural alignment on stack
                // (PTR_TO_STACK) accesses — a size-N access must be N-byte
                // aligned — independent of the general --strict-align policy.
                if align && size > 1 && (off.rem_euclid(size as i64)) != 0 {
                    return Err(self.err(
                        pc,
                        format!("misaligned stack access off {off} size {size}"),
                    ));
                }
                let depth = (-off) as usize;
                // depth relative to that frame; global max is fine for stats
                if frame + 1 == state.frames.len() {
                    self.stats.stack_usage = self.stats.stack_usage.max(depth);
                }
                return Ok(Some((frame, off)));
            }
            PtrKind::Ctx => {
                // The kernel requires a PTR_TO_CTX to have its OWN accumulated
                // offset == 0 at dereference time — the access offset must come
                // only from the load instruction's immediate (`disp`), never
                // from arithmetic folded into the pointer register. So
                // `*(u32*)(r1 + 8)` (pointer off 0, immediate 8) stays legal,
                // but `r2 = r1; r2 += 8; *(u32*)(r2 + 0)` (pointer off 8) is
                // rejected, as is any variable/unknown pointer offset.
                if p.off != 0 || !p.var.is_const() || p.var.umin != 0 {
                    return Err(self.err(
                        pc,
                        format!(
                            "dereference of modified ctx ptr off={}{} disallowed",
                            p.off,
                            if p.var.is_const() && p.var.umin == 0 {
                                String::new()
                            } else {
                                format!("+{}", p.var)
                            }
                        ),
                    ));
                }
                if self.cfg.xdp {
                    if write {
                        return Err(self.err(pc, "XDP context is read-only"));
                    }
                    if !matches!((disp, size), (0 | 4 | 12 | 16 | 20, 4)) {
                        return Err(self.err(
                            pc,
                            format!("invalid XDP context access at offset {disp} size {size}"),
                        ));
                    }
                    return Ok(None);
                }
                if let Some(layout) = self.cfg.metadata_layout {
                    let overlaps = |field: usize| {
                        let start = disp as i128;
                        let end = start + size as i128;
                        let field = field as i128;
                        start < field + 8 && field < end
                    };
                    if write && (overlaps(layout.data_offset()) || overlaps(layout.data_end_offset())) {
                        return Err(self.err(pc, "cannot write metadata packet-pointer fields"));
                    }
                    let exact_pointer = size == 8 && (disp == layout.data_offset() as i64
                        || disp == layout.data_end_offset() as i64);
                    if exact_pointer && align && self.cfg.strict_alignment && disp % 8 != 0 {
                        return Err(self.err(pc,
                            format!("misaligned metadata pointer access off {disp} size 8")));
                    }
                }
                if let Some(bc) = &self.cfg.btf_ctx {
                    // BTF-typed ctx: an array of 8-byte typed arguments. The
                    // kernel's btf_ctx_access() (kernel/bpf/btf.c) requires
                    // the offset to be a multiple of 8, within the argument
                    // count, and rejects all writes for tracing programs.
                    if write {
                        return Err(self.err(pc, "BTF-typed context is read-only"));
                    }
                    if disp % 8 != 0 {
                        return Err(self.err(
                            pc,
                            format!("BTF ctx access at offset {disp} is not a multiple of 8"),
                        ));
                    }
                    let arg = disp / 8;
                    if arg < 0 || arg as usize >= bc.args.len() {
                        return Err(self.err(
                            pc,
                            format!(
                                "BTF ctx access at offset {disp} is beyond the {} typed \
                                 argument slots",
                                bc.args.len()
                            ),
                        ));
                    }
                    match bc.args[arg as usize] {
                        crate::btf::CtxSlot::Ptr { .. }
                        | crate::btf::CtxSlot::PtrOrNull { .. }
                            if size != 8 =>
                        {
                            return Err(self.err(
                                pc,
                                format!(
                                    "BTF ctx pointer argument {arg} must be loaded with an \
                                     8-byte read (got {size})"
                                ),
                            ));
                        }
                        crate::btf::CtxSlot::ScalarSized { size: expected }
                            if size != u64::from(expected) =>
                        {
                            return Err(self.err(
                                pc,
                                format!(
                                    "BTF ctx scalar member {arg} must be loaded with a \
                                     {expected}-byte read (got {size})"
                                ),
                            ));
                        }
                        _ => {}
                    }
                    // off%8==0 and size in {1,2,4,8} make the access naturally
                    // aligned and slot-contained; nothing left to bounds-check.
                    return Ok(None);
                }
                if write && !self.cfg.ctx_writable {
                    return Err(self.err(pc, "context is read-only"));
                }
                (self.cfg.ctx_size as u64, "context")
            }
            PtrKind::MapValue { map } => {
                let def = &self.maps[map as usize];
                if write && def.readonly {
                    return Err(self.err(
                        pc,
                        format!("cannot write to read-only map '{}'", def.name),
                    ));
                }
                (def.value_size as u64, "map value")
            }
            PtrKind::MapValueOrNull { .. } => {
                return Err(self.err(
                    pc,
                    "map value pointer may be NULL; compare it against 0 first",
                ));
            }
            PtrKind::MapOrNull { .. } => {
                return Err(self.err(
                    pc,
                    "inner map pointer may be NULL; compare it against 0 first",
                ));
            }
            PtrKind::RingbufMem { size, .. } => (size as u64, "ringbuf record"),
            PtrKind::RingbufMemOrNull { .. } => {
                return Err(self.err(
                    pc,
                    "ringbuf record pointer may be NULL; compare it against 0 first",
                ));
            }
            PtrKind::BtfIdOrNull { .. } => {
                return Err(self.err(
                    pc,
                    "BTF pointer may be NULL; compare it against 0 first",
                ));
            }
            PtrKind::RingbufConsumed { .. } => {
                return Err(self.err(
                    pc,
                    "use of a ringbuf record after it was submitted/discarded",
                ));
            }
            PtrKind::ExternalMemory { size, writable } => {
                if write && !writable {
                    return Err(self.err(pc, "cannot write to read-only external memory"));
                }
                (size as u64, "external memory")
            }
            PtrKind::Packet { range } => {
                // XDP permits both reads and writes after the same proof.
                let lo = p.off.saturating_add(disp).saturating_add(p.var.smin);
                let hi = i64::try_from(p.var.umax)
                    .ok()
                    .and_then(|v| p.off.checked_add(disp)?.checked_add(v));
                if lo < 0
                    || hi.is_none_or(|hi| {
                        hi < lo || hi.saturating_add(size as i64) > range as i64
                    })
                {
                    return Err(self.err(
                        pc,
                        format!(
                            "packet access out of bounds: off {}{} size {size}, only {range} bytes proven by data_end check",
                            p.off + disp,
                            if p.var.is_const() { String::new() } else { format!("+{}", p.var) }
                        ),
                    ));
                }
                (range as u64, "packet")
            }
            PtrKind::PacketEnd => {
                return Err(self.err(pc, "data_end pointer cannot be dereferenced"));
            }
            PtrKind::Map { .. } => {
                return Err(self.err(pc, "map object pointers cannot be dereferenced"));
            }
            PtrKind::BtfId { btf_id } => {
                // The kernel's check_ptr_to_btf_access() (kernel/bpf/verifier.c):
                // PTR_TO_BTF_ID supports only reads, at a constant offset,
                // bounds-checked against the BTF type's size via
                // btf_struct_access().
                if write {
                    return Err(self.err(
                        pc,
                        "writes through a BTF pointer are not allowed (only read is supported)",
                    ));
                }
                if !p.var.is_const() || p.var.umin != 0 {
                    return Err(self.err(
                        pc,
                        "variable offset access on a BTF pointer is not allowed",
                    ));
                }
                let btf = self
                    .cfg
                    .btf_ctx
                    .as_ref()
                    .and_then(|bc| bc.btf.as_deref())
                    .ok_or_else(|| {
                        self.err(pc, "BTF pointer access without a BTF type graph")
                    })?;
                let tsize = btf.type_size(btf_id).map_err(|e| self.err(pc, e))? as i64;
                let off = p.off + disp;
                if off < 0 || off + size as i64 > tsize {
                    return Err(self.err(
                        pc,
                        format!(
                            "access at offset {off} size {size} is outside BTF type \
                             '{}' (size {tsize})",
                            btf.type_name(btf_id)
                        ),
                    ));
                }
                if self.cfg.strict_alignment && size > 1 && off.rem_euclid(size as i64) != 0 {
                    return Err(self.err(
                        pc,
                        format!("misaligned BTF pointer access off {off} size {size}"),
                    ));
                }
                return Ok(None);
            }
        };
        let lo = p.off + disp + p.var.smin;
        let hi = p.off + disp + p.var.smax;
        if p.var.smin == i64::MIN || p.var.smax == i64::MAX {
            return Err(self.err(
                pc,
                format!("{what} access with unbounded variable offset; bound it first"),
            ));
        }
        if lo < 0 {
            return Err(self.err(
                pc,
                format!("{what} access out of bounds: min offset {lo} < 0"),
            ));
        }
        if hi + size as i64 > region_size as i64 {
            return Err(self.err(
                pc,
                format!(
                    "{what} access out of bounds: max offset {} > size {region_size}",
                    hi + size as i64
                ),
            ));
        }
        if self.cfg.strict_alignment {
            let total = p.var.tnum.add(Tnum::const_val((p.off + disp) as u64));
            let amask = size - 1;
            if total.value & amask != 0 || total.mask & amask != 0 {
                return Err(self.err(pc, format!("possibly misaligned {what} access")));
            }
        }
        Ok(None)
    }

    /// What a non-stack load through `p` puts in the destination register.
    /// Plain regions read unknown scalars; BTF-typed ctx slots and BTF
    /// pointer fields read typed pointers (the kernel's `btf_ctx_access()` /
    /// `btf_struct_access()` result typing). Assumes `check_mem_access`
    /// already validated the access.
    fn typed_load(
        &mut self,
        pc: usize,
        p: &Ptr,
        disp: i64,
        size: u64,
    ) -> Result<RegState, VerifyError> {
        match p.kind {
            PtrKind::Ctx => {
                if self.cfg.xdp && size == 4 {
                    return match disp {
                        0 => Ok(RegState::Ptr(Ptr::new(PtrKind::Packet { range: 0 }))),
                        4 => Ok(RegState::Ptr(Ptr::new(PtrKind::PacketEnd))),
                        12 | 16 | 20 => Ok(RegState::Scalar(Scalar::unknown())),
                        _ => unreachable!("validated XDP ctx offset"),
                    };
                }
                if let Some(layout) = self.cfg.metadata_layout {
                    if size == 8 && disp == layout.data_offset() as i64 {
                        return Ok(RegState::Ptr(Ptr::new(PtrKind::Packet { range: 0 })));
                    }
                    if size == 8 && disp == layout.data_end_offset() as i64 {
                        return Ok(RegState::Ptr(Ptr::new(PtrKind::PacketEnd)));
                    }
                }
                if let Some(bc) = &self.cfg.btf_ctx {
                    if size == 8 {
                        match bc.args[(disp / 8) as usize] {
                            crate::btf::CtxSlot::Ptr { btf_id } => {
                                return Ok(RegState::Ptr(Ptr::new(PtrKind::BtfId { btf_id })));
                            }
                            crate::btf::CtxSlot::PtrOrNull { btf_id } => {
                                let id = self.next_null_id;
                                self.next_null_id += 1;
                                return Ok(RegState::Ptr(Ptr::new(PtrKind::BtfIdOrNull {
                                    btf_id,
                                    id,
                                })));
                            }
                            _ => {}
                        }
                    }
                }
            }
            PtrKind::BtfId { btf_id } => {
                let btf = self
                    .cfg
                    .btf_ctx
                    .as_ref()
                    .and_then(|bc| bc.btf.as_deref())
                    .expect("checked by check_mem_access");
                let off = (p.off + disp) as u32; // >= 0, checked
                if let Some(pointee) = btf
                    .read_kind(btf_id, off, size as u32)
                    .map_err(|e| self.err(pc, e))?
                {
                    return Ok(RegState::Ptr(Ptr::new(PtrKind::BtfId { btf_id: pointee })));
                }
            }
            _ => {}
        }
        Ok(RegState::Scalar(Scalar::unknown()))
    }

    /// Record whether the load at `pc` goes through a BTF pointer (and so
    /// must execute as a fault-tolerant probe read, kernel `BPF_PROBE_MEM`)
    /// or through ordinary memory. The kernel rewrites the instruction one
    /// way or the other at load time, so a single insn reached with both
    /// pointer classes on different paths is rejected — same rule and message
    /// as the kernel's do_check().
    fn note_ldx_class(&mut self, pc: usize, probe: bool) -> Result<(), VerifyError> {
        let cls = if probe { 1u8 } else { 2 };
        match self.mem_class[pc] {
            0 => {
                self.mem_class[pc] = cls;
                if probe {
                    self.probe_mem[pc] = true;
                }
                Ok(())
            }
            c if c == cls => Ok(()),
            _ => Err(self.err(pc, "same insn cannot be used with different pointers")),
        }
    }

    #[allow(clippy::too_many_arguments)] // stack location + value provenance are one transfer
    fn stack_store(
        &mut self,
        state: &mut VState,
        pc: usize,
        frame: usize,
        off: i64,
        size: u64,
        val: RegState,
        scalar_id: u32,
    ) -> Result<(), VerifyError> {
        let base = (STACK_SIZE as i64 + off) as usize;
        let frame = &mut state.frames[frame];
        let stack = &mut frame.stack;
        if size == 8 && base.is_multiple_of(8) {
            stack[base / 8] = SlotState::Spill(val);
            frame.spill_ids[base / 8] = scalar_id;
            return Ok(());
        }
        if matches!(val, RegState::Ptr(_)) {
            return Err(self.err(pc, "pointer spills must be 8-byte aligned stores"));
        }
        for b in base..base + size as usize {
            let slot = b / 8;
            let bit = 1u8 << (b % 8);
            stack[slot] = match stack[slot] {
                SlotState::Spill(_) => SlotState::Bytes(0xff), // overwrite keeps init
                SlotState::Bytes(m) => SlotState::Bytes(m | bit),
            };
            frame.spill_ids[slot] = 0;
        }
        Ok(())
    }

    fn stack_load(
        &self,
        state: &VState,
        pc: usize,
        frame: usize,
        off: i64,
        size: u64,
    ) -> Result<RegState, VerifyError> {
        let base = (STACK_SIZE as i64 + off) as usize;
        let stack = &state.frames[frame].stack;
        if size == 8 && base.is_multiple_of(8) {
            match stack[base / 8] {
                SlotState::Spill(v) => return Ok(v),
                SlotState::Bytes(0xff) => return Ok(RegState::Scalar(Scalar::unknown())),
                SlotState::Bytes(_) => {
                    return Err(self.err(
                        pc,
                        format!("read of partially uninitialized stack at off {off}"),
                    ));
                }
            }
        }
        for b in base..base + size as usize {
            let slot = b / 8;
            let bit = 1u8 << (b % 8);
            if stack[slot].init_mask() & bit == 0 {
                return Err(self.err(
                    pc,
                    format!("read of uninitialized stack byte at off {}", b as i64 - STACK_SIZE as i64),
                ));
            }
        }
        Ok(RegState::Scalar(Scalar::unknown()))
    }

    /// Check that `len` bytes at `p` are readable (helper argument).
    fn check_helper_mem(
        &mut self,
        state: &mut VState,
        pc: usize,
        p: &Ptr,
        len: u64,
        write: bool,
    ) -> Result<(), VerifyError> {
        if len == 0 {
            return Ok(());
        }
        // The kernel's ARG_PTR_TO_MEM family never accepts PTR_TO_BTF_ID (a
        // BTF pointer targets unreadable-in-place kernel memory; only probe
        // reads and direct typed loads may touch it).
        if matches!(p.kind, PtrKind::BtfId { .. }) {
            return Err(self.err(
                pc,
                "a BTF pointer cannot be passed as a helper memory buffer \
                 (use probe_read_kernel)",
            ));
        }
        if let Some((frame, off)) = self.check_mem_access(state, pc, p, 0, len, write, false)? {
            if write {
                self.stack_store(
                    state,
                    pc,
                    frame,
                    off,
                    len,
                    RegState::Scalar(Scalar::unknown()),
                    0,
                )?;
            } else {
                // every byte must be initialized
                let base = (STACK_SIZE as i64 + off) as usize;
                for b in base..base + len as usize {
                    let slot = state.frames[frame].stack[b / 8];
                    if slot.init_mask() & (1u8 << (b % 8)) == 0 {
                        return Err(self.err(
                            pc,
                            format!(
                                "helper reads uninitialized stack byte at off {}",
                                b as i64 - STACK_SIZE as i64
                            ),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    // -- helper calls ---------------------------------------------------------

    fn check_helper_call(
        &mut self,
        state: &mut VState,
        pc: usize,
        hid: u32,
    ) -> Result<(), VerifyError> {
        if hid == 0xbad2310 {
            // The CO-RE loader poisons instructions whose relocation found no
            // match in the target BTF (libbpf does the same); reaching one
            // means the program took a path the target kernel can't support.
            return Err(self.err(
                pc,
                "unresolved CO-RE relocation (poisoned instruction) is reachable",
            ));
        }
        let sig = self
            .sig_for(hid)
            .ok_or_else(|| self.err(pc, format!("call to unknown helper #{hid}")))?;
        let args: Vec<RegState> = (1..=5).map(|r| state.cur().regs[r]).collect();
        let mut map_arg: Option<u32> = None;
        // Ringbuf record id to mark consumed after this call (submit/discard).
        let mut consume_id: Option<u32> = None;

        for (i, kind) in sig.args.iter().enumerate() {
            let reg = i as u8 + 1;
            let val = args[i];
            let need_init = !matches!(kind, ArgKind::None | ArgKind::Any);
            if need_init && matches!(val, RegState::Uninit) {
                return Err(self.err(
                    pc,
                    format!("helper {} arg{}: r{reg} is uninitialized", sig.name, i + 1),
                ));
            }
            match kind {
                ArgKind::None | ArgKind::Any => {}
                ArgKind::CtxPtr => match val {
                    RegState::Ptr(Ptr { kind: PtrKind::Ctx, .. }) => {}
                    _ => {
                        return Err(self.err(
                            pc,
                            format!(
                                "helper {} arg{}: expected context pointer in r{reg}",
                                sig.name,
                                i + 1
                            ),
                        ));
                    }
                },
                ArgKind::Scalar | ArgKind::Size => {
                    if !matches!(val, RegState::Scalar(_)) {
                        return Err(self.err(
                            pc,
                            format!("helper {} arg{}: expected scalar in r{reg}", sig.name, i + 1),
                        ));
                    }
                }
                ArgKind::BtfPtr { type_name } => {
                    let p = match val {
                        RegState::Ptr(p) => p,
                        _ => {
                            return Err(self.err(
                                pc,
                                format!(
                                    "helper {} arg{}: expected pointer to struct {type_name} in r{reg}",
                                    sig.name,
                                    i + 1
                                ),
                            ));
                        }
                    };
                    let btf_id = match p.kind {
                        PtrKind::BtfId { btf_id } => btf_id,
                        PtrKind::BtfIdOrNull { .. } => {
                            return Err(self.err(
                                pc,
                                format!(
                                    "helper {} arg{} may be NULL; null-check it before the call",
                                    sig.name,
                                    i + 1
                                ),
                            ));
                        }
                        _ => {
                            return Err(self.err(
                                pc,
                                format!(
                                    "helper {} arg{}: expected pointer to struct {type_name} in r{reg}",
                                    sig.name,
                                    i + 1
                                ),
                            ));
                        }
                    };
                    if p.off != 0 || !p.var.is_const() || p.var.umin != 0 {
                        return Err(self.err(
                            pc,
                            format!(
                                "helper {} arg{} needs the original struct {type_name} pointer (offset 0)",
                                sig.name,
                                i + 1
                            ),
                        ));
                    }
                    let (expected_id, actual) = self
                        .cfg
                        .btf_ctx
                        .as_ref()
                        .and_then(|ctx| ctx.btf.as_ref())
                        .map(|btf| {
                            (
                                btf.composite_id_by_name(type_name),
                                btf.type_name(btf_id),
                            )
                        })
                        .unwrap_or((None, ""));
                    if expected_id != Some(btf_id) {
                        return Err(self.err(
                            pc,
                            format!(
                                "helper {} arg{}: expected pointer to struct {type_name}, got struct {actual}",
                                sig.name,
                                i + 1
                            ),
                        ));
                    }
                }
                ArgKind::ConstMapPtr => match val {
                    RegState::Ptr(Ptr {
                        kind: PtrKind::Map { map },
                        ..
                    }) => map_arg = Some(map),
                    _ => {
                        return Err(self.err(
                            pc,
                            format!(
                                "helper {} arg{}: expected map pointer in r{reg}",
                                sig.name,
                                i + 1
                            ),
                        ));
                    }
                },
                ArgKind::MapKey | ArgKind::MapValue => {
                    let map = map_arg.ok_or_else(|| {
                        self.err(pc, format!("helper {}: map argument missing", sig.name))
                    })?;
                    let len = if matches!(kind, ArgKind::MapKey) {
                        self.maps[map as usize].key_size as u64
                    } else {
                        self.maps[map as usize].value_size as u64
                    };
                    let p = match val {
                        RegState::Ptr(p) => p,
                        _ => {
                            return Err(self.err(
                                pc,
                                format!(
                                    "helper {} arg{}: expected pointer to memory in r{reg}",
                                    sig.name,
                                    i + 1
                                ),
                            ));
                        }
                    };
                    self.check_helper_mem(state, pc, &p, len, false)?;
                }
                ArgKind::MemRead { size_arg } | ArgKind::MemWrite { size_arg } => {
                    let write = matches!(kind, ArgKind::MemWrite { .. });
                    let sz = match args[*size_arg as usize] {
                        RegState::Scalar(s) => s,
                        _ => {
                            return Err(self.err(
                                pc,
                                format!(
                                    "helper {}: size argument r{} must be a scalar",
                                    sig.name,
                                    size_arg + 1
                                ),
                            ));
                        }
                    };
                    if sz.umax > 1 << 20 {
                        return Err(self.err(
                            pc,
                            format!(
                                "helper {}: size in r{} unbounded (umax={})",
                                sig.name,
                                size_arg + 1,
                                sz.umax
                            ),
                        ));
                    }
                    let p = match val {
                        RegState::Ptr(p) => p,
                        _ => {
                            return Err(self.err(
                                pc,
                                format!(
                                    "helper {} arg{}: expected pointer to memory in r{reg}",
                                    sig.name,
                                    i + 1
                                ),
                            ));
                        }
                    };
                    self.check_helper_mem(state, pc, &p, sz.umax, write)?;
                }
                ArgKind::RingbufReserved => {
                    let p = match val {
                        RegState::Ptr(p) => p,
                        _ => {
                            return Err(self.err(
                                pc,
                                format!(
                                    "helper {} arg{}: expected a ringbuf record pointer in r{reg}",
                                    sig.name,
                                    i + 1
                                ),
                            ));
                        }
                    };
                    let id = match p.kind {
                        PtrKind::RingbufMem { id, .. } => id,
                        PtrKind::RingbufMemOrNull { .. } => {
                            return Err(self.err(
                                pc,
                                format!(
                                    "helper {}: ringbuf record may be NULL; null-check it \
                                     before submit/discard",
                                    sig.name
                                ),
                            ));
                        }
                        PtrKind::RingbufConsumed { .. } => {
                            return Err(self.err(
                                pc,
                                format!(
                                    "helper {}: ringbuf record was already submitted/discarded",
                                    sig.name
                                ),
                            ));
                        }
                        _ => {
                            return Err(self.err(
                                pc,
                                format!(
                                    "helper {} arg{}: r{reg} is not a ringbuf-reserved pointer",
                                    sig.name,
                                    i + 1
                                ),
                            ));
                        }
                    };
                    if p.off != 0 || !p.var.is_const() || p.var.umin != 0 {
                        return Err(self.err(
                            pc,
                            format!(
                                "helper {} needs the original ringbuf record pointer (offset 0)",
                                sig.name
                            ),
                        ));
                    }
                    consume_id = Some(id);
                }
            }
        }

        // Consume the ringbuf record (submit/discard): every copy becomes
        // unusable, so a later deref or a second submit is rejected.
        if let Some(id) = consume_id {
            Self::mark_consumed(state, id);
        }

        // Frozen (.rodata) maps cannot be mutated through helpers.
        if let Some(map) = map_arg {
            let def = &self.maps[map as usize];
            if def.readonly
                && matches!(
                    hid,
                    crate::helpers::id::MAP_UPDATE_ELEM | crate::helpers::id::MAP_DELETE_ELEM
                )
            {
                return Err(self.err(
                    pc,
                    format!(
                        "helper {} cannot modify read-only map '{}'",
                        sig.name, def.name
                    ),
                ));
            }
            if def.kind == crate::maps::MapKind::ArrayOfMaps
                && matches!(
                    hid,
                    crate::helpers::id::MAP_UPDATE_ELEM
                        | crate::helpers::id::MAP_DELETE_ELEM
                )
            {
                return Err(self.err(
                    pc,
                    format!(
                        "helper {} cannot modify array_of_maps '{}' from a BPF program",
                        sig.name, def.name
                    ),
                ));
            }
            // Helpers that require a specific map kind (see docs/specs/map-types-2.md).
            let required = match hid {
                crate::helpers::id::PERF_EVENT_OUTPUT => Some(crate::maps::MapKind::PerfEventArray),
                crate::helpers::id::GET_STACKID => Some(crate::maps::MapKind::StackTrace),
                crate::helpers::id::CURRENT_TASK_UNDER_CGROUP => {
                    Some(crate::maps::MapKind::CgroupArray)
                }
                crate::helpers::id::TAIL_CALL => Some(crate::maps::MapKind::ProgArray),
                _ => None,
            };
            if let Some(k) = required {
                if def.kind != k {
                    return Err(self.err(
                        pc,
                        format!(
                            "helper {} requires a {k} map, but '{}' is a {} map",
                            sig.name, def.name, def.kind
                        ),
                    ));
                }
            }
        }

        // effects: r1-r5 clobbered, r0 = return value
        let f = state.cur_mut();
        for id in &mut f.scalar_ids[..=5] {
            *id = 0;
        }
        for r in 1..=5 {
            f.regs[r] = RegState::Uninit;
        }
        f.regs[0] = match sig.ret {
            RetKind::Scalar => RegState::Scalar(Scalar::unknown()),
            RetKind::MapValueOrNull => {
                let map = map_arg.ok_or_else(|| {
                    self.err(
                        pc,
                        format!("helper {}: returns map value but has no map arg", sig.name),
                    )
                })?;
                let id = self.next_null_id;
                self.next_null_id += 1;
                if let Some(origins) = &mut self.replay_null_origin {
                    origins.insert(id, (pc, sig.name.to_string()));
                }
                let def = &self.maps[map as usize];
                if def.kind == crate::maps::MapKind::ArrayOfMaps {
                    let inner = def.inner_map_idx.ok_or_else(|| {
                        self.err(
                            pc,
                            format!("array_of_maps '{}' has no inner-map template", def.name),
                        )
                    })?;
                    RegState::Ptr(Ptr::new(PtrKind::MapOrNull { map: inner, id }))
                } else {
                    RegState::Ptr(Ptr::new(PtrKind::MapValueOrNull { map, id }))
                }
            }
            RetKind::RingbufMemOrNull { size_arg } => {
                let size = match args[size_arg as usize] {
                    RegState::Scalar(s) if s.is_const() => s.umin as u32,
                    RegState::Scalar(_) => {
                        return Err(self.err(
                            pc,
                            format!(
                                "helper {}: reservation size (r{}) must be a known constant",
                                sig.name,
                                size_arg + 1
                            ),
                        ));
                    }
                    _ => {
                        return Err(self.err(
                            pc,
                            format!("helper {}: reservation size must be a scalar", sig.name),
                        ));
                    }
                };
                let id = self.next_null_id;
                self.next_null_id += 1;
                if let Some(origins) = &mut self.replay_null_origin {
                    origins.insert(id, (pc, sig.name.to_string()));
                }
                RegState::Ptr(Ptr::new(PtrKind::RingbufMemOrNull { id, size }))
            }
            RetKind::BtfPtrOrNull { type_name } => {
                let btf_id = self
                    .cfg
                    .btf_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.btf.as_ref())
                    .and_then(|btf| btf.composite_id_by_name(type_name))
                    .ok_or_else(|| {
                        self.err(
                            pc,
                            format!(
                                "helper {}: target BTF has no struct {type_name}",
                                sig.name
                            ),
                        )
                    })?;
                let id = self.next_null_id;
                self.next_null_id += 1;
                if let Some(origins) = &mut self.replay_null_origin {
                    origins.insert(id, (pc, sig.name.to_string()));
                }
                RegState::Ptr(Ptr::new(PtrKind::BtfIdOrNull { btf_id, id }))
            }
            RetKind::ExternalMemory { size, writable } => {
                RegState::Ptr(Ptr::new(PtrKind::ExternalMemory { size, writable }))
            }
        };
        Ok(())
    }

    /// Mark every copy of ringbuf record `id` consumed (after submit/discard).
    fn mark_consumed(state: &mut VState, id: u32) {
        for frame in &mut state.frames {
            let fix = |r: &mut RegState| {
                if let RegState::Ptr(p) = r {
                    let pid = match p.kind {
                        PtrKind::RingbufMem { id, .. } | PtrKind::RingbufMemOrNull { id, .. } => {
                            Some(id)
                        }
                        _ => None,
                    };
                    if pid == Some(id) {
                        p.kind = PtrKind::RingbufConsumed { id };
                    }
                }
            };
            for r in frame.regs.iter_mut() {
                fix(r);
            }
            for s in frame.stack.iter_mut() {
                if let SlotState::Spill(r) = s {
                    fix(r);
                }
            }
        }
    }

    /// Refine every copy of a maybe-null pointer with identity `id`.
    fn mark_ptr_or_null(state: &mut VState, id: u32, becomes_null: bool) {
        for frame in &mut state.frames {
            let fix = |r: &mut RegState| {
                if let RegState::Ptr(p) = r {
                    match p.kind {
                        PtrKind::MapValueOrNull { map, id: pid } if pid == id => {
                            if becomes_null {
                                *r = RegState::Scalar(Scalar::constant(0));
                            } else {
                                p.kind = PtrKind::MapValue { map };
                            }
                        }
                        PtrKind::MapOrNull { map, id: pid } if pid == id => {
                            if becomes_null {
                                *r = RegState::Scalar(Scalar::constant(0));
                            } else {
                                p.kind = PtrKind::Map { map };
                            }
                        }
                        PtrKind::RingbufMemOrNull { id: pid, size } if pid == id => {
                            if becomes_null {
                                *r = RegState::Scalar(Scalar::constant(0));
                            } else {
                                p.kind = PtrKind::RingbufMem { id: pid, size };
                            }
                        }
                        PtrKind::BtfIdOrNull { btf_id, id: pid } if pid == id => {
                            if becomes_null {
                                *r = RegState::Scalar(Scalar::constant(0));
                            } else {
                                p.kind = PtrKind::BtfId { btf_id };
                            }
                        }
                        _ => {}
                    }
                }
            };
            for r in frame.regs.iter_mut() {
                fix(r);
            }
            for s in frame.stack.iter_mut() {
                if let SlotState::Spill(r) = s {
                    fix(r);
                }
            }
        }
    }

    /// Refine every register/spill known equal to the scalar carrying `id`.
    /// Arithmetic clears an individual location's id; plain register moves
    /// and aligned full-width spills preserve it.
    fn mark_scalar_id(state: &mut VState, id: u32, value: Scalar) {
        if id == 0 {
            return;
        }
        for frame in &mut state.frames {
            for (reg, scalar_id) in frame.regs.iter_mut().zip(&frame.scalar_ids) {
                if *scalar_id == id && matches!(reg, RegState::Scalar(_)) {
                    *reg = RegState::Scalar(value);
                }
            }
            for (slot, scalar_id) in frame.stack.iter_mut().zip(&frame.spill_ids) {
                if *scalar_id == id {
                    if let SlotState::Spill(RegState::Scalar(scalar)) = slot {
                        *scalar = value;
                    }
                }
            }
        }
    }

    /// A successful `data`/`data_end` comparison proves a prefix of the
    /// packet accessible. Propagate it to every alias, like the kernel's
    /// packet-pointer id/range tracking.
    fn mark_packet_range(state: &mut VState, range: u32) {
        for frame in &mut state.frames {
            let fix = |r: &mut RegState| {
                if let RegState::Ptr(p) = r {
                    if let PtrKind::Packet { range: old } = p.kind {
                        p.kind = PtrKind::Packet {
                            range: old.max(range),
                        };
                    }
                }
            };
            for r in frame.regs.iter_mut() {
                fix(r);
            }
            for s in frame.stack.iter_mut() {
                if let SlotState::Spill(r) = s {
                    fix(r);
                }
            }
        }
    }

    /// Return `(safe_when_taken, proven_prefix)` for an unsigned comparison
    /// between a packet pointer and its data_end sentinel.
    fn packet_bound(op: u8, a: RegState, b: RegState) -> Option<(bool, u32)> {
        let endpoint = |p: Ptr, strict: bool| -> Option<u32> {
            let end = p.off.checked_add(p.var.umax.try_into().ok()?)?;
            let end = end.checked_add(i64::from(strict))?;
            u32::try_from(end).ok()
        };
        match (a, b) {
            (RegState::Ptr(p @ Ptr { kind: PtrKind::Packet { .. }, .. }),
             RegState::Ptr(Ptr { kind: PtrKind::PacketEnd, .. })) => match op {
                jmp::JGT => endpoint(p, false).map(|r| (false, r)),
                jmp::JGE => endpoint(p, true).map(|r| (false, r)),
                jmp::JLT => endpoint(p, true).map(|r| (true, r)),
                jmp::JLE => endpoint(p, false).map(|r| (true, r)),
                _ => None,
            },
            (RegState::Ptr(Ptr { kind: PtrKind::PacketEnd, .. }),
             RegState::Ptr(p @ Ptr { kind: PtrKind::Packet { .. }, .. })) => match op {
                jmp::JLT => endpoint(p, false).map(|r| (false, r)),
                jmp::JLE => endpoint(p, true).map(|r| (false, r)),
                jmp::JGT => endpoint(p, true).map(|r| (true, r)),
                jmp::JGE => endpoint(p, false).map(|r| (true, r)),
                _ => None,
            },
            _ => None,
        }
    }

    // -- single-step ----------------------------------------------------------

    fn step(&mut self, pc: usize, mut state: VState) -> Result<StepOutcome, VerifyError> {
        let ins = self.insns[pc];
        let cls = ins.class();
        match cls {
            class::ALU | class::ALU64 => {
                self.step_alu(pc, &mut state, ins)?;
                Ok(StepOutcome::Next(vec![(pc + 1, state)]))
            }
            class::LD => {
                if !ins.is_wide() {
                    if self.cfg.legacy_packet == LegacyPacketProfile::Linux {
                        let r6 = self.read_reg(&state, pc, 6)?;
                        if !matches!(
                            r6,
                            RegState::Ptr(Ptr {
                                kind: PtrKind::Ctx,
                                off: 0,
                                var,
                            }) if var.is_const() && var.umin == 0
                        ) {
                            return Err(self.err(
                                pc,
                                "legacy packet access requires r6 to hold the packet context",
                            ));
                        }
                    }
                    if ins.mem_mode() == mode::IND {
                        match self.read_reg(&state, pc, ins.src)? {
                            RegState::Scalar(_) => {}
                            RegState::Ptr(_) => {
                                return Err(self.err(
                                    pc,
                                    format!("legacy packet index r{} must be a scalar", ins.src),
                                ));
                            }
                            RegState::Uninit => unreachable!(),
                        }
                    }
                    let f = state.cur_mut();
                    if self.cfg.legacy_packet == LegacyPacketProfile::Linux {
                        for r in 1..=5 {
                            f.regs[r] = RegState::Uninit;
                            f.scalar_ids[r] = 0;
                        }
                    }
                    f.regs[0] = RegState::Scalar(Scalar::unknown());
                    f.scalar_ids[0] = 0;
                    return Ok(StepOutcome::Next(vec![(pc + 1, state)]));
                }
                // lddw variants
                match ins.src {
                    pseudo::IMM64 => {
                        let v = wide_imm(self.insns, pc);
                        self.write_reg(&mut state, pc, ins.dst, RegState::Scalar(Scalar::constant(v)))?;
                    }
                    pseudo::MAP_ID => {
                        self.write_reg(
                            &mut state,
                            pc,
                            ins.dst,
                            RegState::Ptr(Ptr::new(PtrKind::Map {
                                map: ins.imm as u32,
                            })),
                        )?;
                    }
                    pseudo::MAP_VALUE => {
                        let map = ins.imm as u32;
                        let off = self.insns[pc + 1].imm as i64;
                        let vs = self.maps[map as usize].value_size as i64;
                        if off < 0 || off > vs {
                            return Err(self.err(pc, format!("map value offset {off} out of range")));
                        }
                        let mut p = Ptr::new(PtrKind::MapValue { map });
                        p.off = off;
                        self.write_reg(&mut state, pc, ins.dst, RegState::Ptr(p))?;
                    }
                    _ => unreachable!("checked in prepass"),
                }
                Ok(StepOutcome::Next(vec![(pc + 2, state)]))
            }
            class::LDX => {
                let base = self.read_reg(&state, pc, ins.src)?;
                let p = match base {
                    RegState::Ptr(p) => p,
                    RegState::Scalar(_) => {
                        return Err(self.err(
                            pc,
                            format!("r{} is a scalar; loads need a pointer", ins.src),
                        ));
                    }
                    RegState::Uninit => unreachable!(),
                };
                let size = ins.mem_size() as u64;
                let stack =
                    self.check_mem_access(&state, pc, &p, ins.off as i64, size, false, true)?;
                self.note_ldx_class(pc, matches!(p.kind, PtrKind::BtfId { .. }))?;
                let loaded_id = stack
                    .filter(|(_, off)| size == 8 && (STACK_SIZE as i64 + *off) % 8 == 0)
                    .map(|(frame, off)| {
                        state.frames[frame].spill_ids
                            [((STACK_SIZE as i64 + off) as usize) / 8]
                    })
                    .unwrap_or(0);
                let loaded = match stack {
                    Some((frame, off)) => self.stack_load(&state, pc, frame, off, size)?,
                    None => self.typed_load(pc, &p, ins.off as i64, size)?,
                };
                let loaded = if ins.mem_mode() == mode::MEMSX {
                    match loaded {
                        RegState::Scalar(s) => {
                            RegState::Scalar(scalar_movsx(s, (size * 8) as u16))
                        }
                        other => other,
                    }
                } else if size < 8 {
                    match loaded {
                        RegState::Scalar(s) => {
                            let mut s = s;
                            s.tnum = s.tnum.cast(size as u8);
                            let max = if size == 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
                            s.umin = s.umin.min(max);
                            s.umax = s.umax.min(max);
                            s.smin = s.smin.max(0);
                            s.smax = s.smax.min(max as i64);
                            s.sync();
                            RegState::Scalar(s)
                        }
                        // XDP's u32 data/data_end context fields are typed as
                        // pointers by the program-type access callback.
                        RegState::Ptr(p) => RegState::Ptr(p),
                        RegState::Uninit => unreachable!(),
                    }
                } else {
                    loaded
                };
                self.write_reg(&mut state, pc, ins.dst, loaded)?;
                if loaded_id != 0 && matches!(loaded, RegState::Scalar(_)) {
                    state.cur_mut().scalar_ids[ins.dst as usize] = loaded_id;
                }
                Ok(StepOutcome::Next(vec![(pc + 1, state)]))
            }
            class::ST | class::STX => {
                let base = self.read_reg(&state, pc, ins.dst)?;
                let p = match base {
                    RegState::Ptr(p) => p,
                    _ => {
                        return Err(self.err(
                            pc,
                            format!("r{} is a scalar; stores need a pointer", ins.dst),
                        ));
                    }
                };
                let size = ins.mem_size() as u64;
                if ins.mem_mode() == mode::ATOMIC {
                    return self.step_atomic(pc, state, ins, p, size);
                }
                let val = if cls == class::ST {
                    RegState::Scalar(Scalar::constant(ins.imm as i64 as u64))
                } else {
                    self.read_reg(&state, pc, ins.src)?
                };
                if matches!(val, RegState::Ptr(_)) && !matches!(p.kind, PtrKind::Stack { .. }) {
                    return Err(self.err(
                        pc,
                        "pointers may only be stored to the stack (pointer leak)",
                    ));
                }
                if let Some((frame, off)) = self.check_mem_access(&state, pc, &p, ins.off as i64, size, true, true)? {
                    let scalar_id = if cls == class::STX {
                        state.cur().scalar_ids[ins.src as usize]
                    } else {
                        0
                    };
                    self.stack_store(&mut state, pc, frame, off, size, val, scalar_id)?
                }
                Ok(StepOutcome::Next(vec![(pc + 1, state)]))
            }
            class::JMP | class::JMP32 => self.step_jmp(pc, state, ins),
            _ => unreachable!(),
        }
    }

    fn step_atomic(
        &mut self,
        pc: usize,
        mut state: VState,
        ins: Insn,
        p: Ptr,
        size: u64,
    ) -> Result<StepOutcome, VerifyError> {
        use crate::insn::atomic as a;
        // atomics read and write the target
        self.check_mem_access(&state, pc, &p, ins.off as i64, size, true, true)?;
        if let Some((frame, off)) =
            self.check_mem_access(&state, pc, &p, ins.off as i64, size, false, true)?
        {
            // target must be initialized; result of RMW is an unknown scalar
            self.stack_load(&state, pc, frame, off, size)?;
            self.stack_store(
                &mut state,
                pc,
                frame,
                off,
                size,
                RegState::Scalar(Scalar::unknown()),
                0,
            )?;
        }
        // source operand must be an initialized scalar
        match self.read_reg(&state, pc, ins.src)? {
            RegState::Scalar(_) => {}
            _ => return Err(self.err(pc, "atomic source must be a scalar")),
        }
        if ins.imm == a::CMPXCHG {
            match self.read_reg(&state, pc, 0)? {
                RegState::Scalar(_) => {}
                _ => return Err(self.err(pc, "cmpxchg needs a scalar in r0")),
            }
            self.write_reg(&mut state, pc, 0, RegState::Scalar(Scalar::unknown()))?;
        } else if ins.imm & a::FETCH != 0 || ins.imm == a::XCHG {
            self.write_reg(&mut state, pc, ins.src, RegState::Scalar(Scalar::unknown()))?;
        }
        Ok(StepOutcome::Next(vec![(pc + 1, state)]))
    }

    fn step_alu(&mut self, pc: usize, state: &mut VState, ins: Insn) -> Result<(), VerifyError> {
        let is32 = ins.class() == class::ALU;
        let op = ins.op();
        let dst_scalar_id = state.cur().scalar_ids[ins.dst as usize];
        let src_scalar_id = if ins.is_src_reg() {
            state.cur().scalar_ids[ins.src as usize]
        } else {
            0
        };

        // operand b
        let b: RegState = if op == alu::NEG || op == alu::END {
            RegState::Scalar(Scalar::constant(0))
        } else if ins.is_src_reg() {
            self.read_reg(state, pc, ins.src)?
        } else {
            RegState::Scalar(Scalar::constant(ins.imm as i64 as u64))
        };

        if op == alu::MOV {
            let mut scalar_copy = false;
            let v = match b {
                RegState::Scalar(s) => {
                    let original = s;
                    let s = if ins.off != 0 {
                        // movsx
                        let s = if is32 { s.truncate32() } else { s };
                        let mut r = scalar_movsx(s, ins.off as u16);
                        if is32 {
                            r = r.truncate32();
                        }
                        r
                    } else if is32 {
                        s.truncate32()
                    } else {
                        s
                    };
                    scalar_copy = ins.is_src_reg() && s == original && !s.is_const();
                    RegState::Scalar(s)
                }
                RegState::Ptr(p) => {
                    if ins.off != 0 {
                        return Err(self.err(pc, "sign-extending move of a pointer"));
                    }
                    if is32 {
                        self.warnings.push(format!(
                            "insn {pc}: 32-bit move truncates pointer r{} to scalar",
                            ins.src
                        ));
                        RegState::Scalar(Scalar::from_tnum(Tnum::unknown().cast(4)))
                    } else {
                        RegState::Ptr(p)
                    }
                }
                RegState::Uninit => unreachable!(),
            };
            self.write_reg(state, pc, ins.dst, v)?;
            if scalar_copy {
                let id = if src_scalar_id == 0 {
                    let id = self.fresh_scalar_id();
                    state.cur_mut().scalar_ids[ins.src as usize] = id;
                    id
                } else {
                    src_scalar_id
                };
                state.cur_mut().scalar_ids[ins.dst as usize] = id;
            }
            return Ok(());
        }

        let a = self.read_reg(state, pc, ins.dst)?;

        // pointer arithmetic
        let a_ptr = matches!(a, RegState::Ptr(_));
        let b_ptr = matches!(b, RegState::Ptr(_));
        if a_ptr || b_ptr {
            if is32 {
                return Err(self.err(pc, "32-bit arithmetic on a pointer"));
            }
            match op {
                alu::ADD => {
                    let (p, s) = match (a, b) {
                        (RegState::Ptr(p), RegState::Scalar(s))
                        | (RegState::Scalar(s), RegState::Ptr(p)) => (p, s),
                        _ => return Err(self.err(pc, "cannot add two pointers")),
                    };
                    let np = self.adjust_ptr(pc, p, s, false)?;
                    return self.write_reg(state, pc, ins.dst, RegState::Ptr(np));
                }
                alu::SUB => {
                    match (a, b) {
                        (RegState::Ptr(pa), RegState::Ptr(pb)) => {
                            if core::mem::discriminant(&pa.kind) != core::mem::discriminant(&pb.kind)
                            {
                                return Err(self.err(
                                    pc,
                                    "subtracting pointers into different regions",
                                ));
                            }
                            return self.write_reg(
                                state,
                                pc,
                                ins.dst,
                                RegState::Scalar(Scalar::unknown()),
                            );
                        }
                        (RegState::Ptr(p), RegState::Scalar(s)) => {
                            let np = self.adjust_ptr(pc, p, s, true)?;
                            return self.write_reg(state, pc, ins.dst, RegState::Ptr(np));
                        }
                        _ => return Err(self.err(pc, "cannot subtract a pointer from a scalar")),
                    }
                }
                _ => {
                    return Err(self.err(
                        pc,
                        format!("arithmetic op {:#x} on a pointer is not allowed", op),
                    ));
                }
            }
        }

        // scalar ALU
        let (sa, sb) = match (a, b) {
            (RegState::Scalar(x), RegState::Scalar(y)) => (x, y),
            _ => unreachable!(),
        };
        let result = match op {
            alu::NEG => alu_scalar(alu::SUB, is32, false, Scalar::constant(0), sa)
                .map_err(|m| self.err(pc, m))?,
            alu::END => {
                let is_swap = ins.class() == class::ALU64 || ins.is_src_reg();
                let mut r = scalar_endian(is_swap, ins.imm, sa);
                r.sync();
                r
            }
            op => alu_scalar(op, is32, ins.off == 1, sa, sb).map_err(|m| self.err(pc, m))?,
        };
        let expression_id = if dst_scalar_id != 0 && sb.is_const() && !result.is_const() {
            let rhs = if op == alu::END {
                ins.imm as i64 as u64
            } else {
                sb.umin
            };
            // For values already known zero-extended to 32 bits, bitwise
            // ALU32 and ALU64 forms compute the same mathematical expression.
            // Clang mixes those encodings in real bounds-check patterns.
            let expr_is32 = is32
                && !(matches!(op, alu::AND | alu::OR | alu::XOR)
                    && sa.umax <= u32::MAX as u64
                    && sb.umax <= u32::MAX as u64);
            Some(self.scalar_expr_id(dst_scalar_id, op, expr_is32, rhs, ins.off))
        } else {
            None
        };
        self.write_reg(state, pc, ins.dst, RegState::Scalar(result))?;
        if let Some(id) = expression_id {
            Self::set_scalar_id(state, ins.dst, id, result);
        }
        Ok(())
    }

    fn adjust_ptr(&self, pc: usize, p: Ptr, s: Scalar, sub: bool) -> Result<Ptr, VerifyError> {
        if matches!(
            p.kind,
            PtrKind::Map { .. }
                | PtrKind::MapValueOrNull { .. }
                | PtrKind::MapOrNull { .. }
                | PtrKind::RingbufMemOrNull { .. }
                | PtrKind::BtfIdOrNull { .. }
                | PtrKind::RingbufConsumed { .. }
                | PtrKind::PacketEnd
        ) {
            return Err(self.err(
                pc,
                "arithmetic on this pointer type is not allowed (null-check it first?)",
            ));
        }
        let mut np = p;
        if s.is_const() {
            let c = s.umin as i64;
            let delta = if sub { c.checked_neg() } else { Some(c) };
            let new_off = delta.and_then(|d| np.off.checked_add(d));
            match new_off {
                Some(o) if o.abs() <= 1 << 29 => np.off = o,
                _ => return Err(self.err(pc, "pointer offset out of range")),
            }
        } else {
            if matches!(p.kind, PtrKind::Stack { .. }) {
                return Err(self.err(pc, "variable offset on a stack pointer is not allowed"));
            }
            let nv = if sub {
                scalar_sub(np.var, s)
            } else {
                scalar_add(np.var, s)
            };
            np.var = nv;
        }
        Ok(np)
    }

    fn step_jmp(
        &mut self,
        pc: usize,
        mut state: VState,
        ins: Insn,
    ) -> Result<StepOutcome, VerifyError> {
        let is32 = ins.class() == class::JMP32;
        match ins.op() {
            jmp::JA => {
                let rel = if is32 { ins.imm as i64 } else { ins.off as i64 };
                let t = (pc as i64 + 1 + rel) as usize;
                Ok(StepOutcome::Next(vec![(t, state)]))
            }
            jmp::EXIT => {
                let r0 = state.cur().regs[0];
                let r0_scalar_id = state.cur().scalar_ids[0];
                if state.frames.len() > 1 {
                    match r0 {
                        RegState::Scalar(_) => {}
                        RegState::Uninit => {
                            return Err(self.err(pc, "subprogram exits without setting r0"));
                        }
                        // The kernel lets a static subprogram return a pointer:
                        // prepare_func_exit() copies the callee's r0 to the
                        // caller verbatim (real programs rely on it — e.g.
                        // bcc's cpudist returns a map-value pointer from a
                        // lookup-or-init helper function). The one exception is
                        // PTR_TO_STACK: the kernel rejects returning ANY stack
                        // pointer — even a still-live caller-frame one —
                        // "technically it's ok [...] but let's be conservative"
                        // ("cannot return stack pointer to the caller"). Mirror
                        // that exactly so vfuzz verdict parity holds.
                        RegState::Ptr(p) => {
                            if matches!(p.kind, PtrKind::Stack { .. }) {
                                return Err(self.err(
                                    pc,
                                    "cannot return stack pointer to the caller",
                                ));
                            }
                        }
                    }
                    let ret_pc = state.cur().ret_pc;
                    state.frames.pop();
                    let f = state.cur_mut();
                    f.regs[0] = r0;
                    f.scalar_ids[0] = r0_scalar_id;
                    for r in 1..=5 {
                        f.regs[r] = RegState::Uninit;
                        f.scalar_ids[r] = 0;
                    }
                    Ok(StepOutcome::Next(vec![(ret_pc, state)]))
                } else {
                    match r0 {
                        RegState::Scalar(_) => Ok(StepOutcome::Done),
                        RegState::Uninit => {
                            Err(self.err(pc, "program exits without setting r0"))
                        }
                        RegState::Ptr(_) => Err(self.err(pc, "program may not return a pointer")),
                    }
                }
            }
            jmp::CALL => {
                if ins.src == call_kind::LOCAL {
                    if state.frames.len() >= MAX_CALL_FRAMES {
                        return Err(self.err(
                            pc,
                            format!("call depth exceeds {MAX_CALL_FRAMES} frames"),
                        ));
                    }
                    let target = (pc as i64 + 1 + ins.imm as i64) as usize;
                    let caller = state.cur().clone();
                    let mut callee = Frame::new(pc + 1);
                    callee.regs[1..6].copy_from_slice(&caller.regs[1..6]);
                    callee.scalar_ids[1..6].copy_from_slice(&caller.scalar_ids[1..6]);
                    let frame_idx = state.frames.len();
                    callee.regs[REG_FP as usize] =
                        RegState::Ptr(Ptr::new(PtrKind::Stack { frame: frame_idx }));
                    state.frames.push(callee);
                    Ok(StepOutcome::Next(vec![(target, state)]))
                } else {
                    self.check_helper_call(&mut state, pc, ins.imm as u32)?;
                    Ok(StepOutcome::Next(vec![(pc + 1, state)]))
                }
            }
            op => {
                let target = (pc as i64 + 1 + ins.off as i64) as usize;
                let a = self.read_reg(&state, pc, ins.dst)?;
                let b: RegState = if ins.is_src_reg() {
                    self.read_reg(&state, pc, ins.src)?
                } else {
                    RegState::Scalar(Scalar::constant(ins.imm as i64 as u64))
                };

                // null-check refinement on maybe-null map values / ringbuf records
                let or_null_id = |r: RegState| match r {
                    RegState::Ptr(Ptr {
                        kind:
                            PtrKind::MapValueOrNull { id, .. }
                            | PtrKind::MapOrNull { id, .. }
                            | PtrKind::RingbufMemOrNull { id, .. }
                            | PtrKind::BtfIdOrNull { id, .. },
                        ..
                    }) => Some(id),
                    _ => None,
                };
                if !is32 && matches!(op, jmp::JEQ | jmp::JNE) {
                    if let (Some(id), RegState::Scalar(s)) = (or_null_id(a), b) {
                        if s.is_const() && s.umin == 0 {
                            let mut on_target = state.clone();
                            let eq = op == jmp::JEQ;
                            // taken: condition true
                            Self::mark_ptr_or_null(&mut on_target, id, eq);
                            Self::mark_ptr_or_null(&mut state, id, !eq);
                            self.stats.states_explored += 1;
                            return Ok(StepOutcome::Next(vec![
                                (pc + 1, state),
                                (target, on_target),
                            ]));
                        }
                    }
                }

                if !is32 {
                    if let Some((safe_taken, range)) = Self::packet_bound(op, a, b) {
                        let mut on_target = state.clone();
                        if safe_taken {
                            Self::mark_packet_range(&mut on_target, range);
                        } else {
                            Self::mark_packet_range(&mut state, range);
                        }
                        self.stats.states_explored += 1;
                        return Ok(StepOutcome::Next(vec![
                            (pc + 1, state),
                            (target, on_target),
                        ]));
                    }
                }

                // Other pointer comparisons are allowed, with no refinement.
                let (sa, sb) = match (a, b) {
                    (RegState::Scalar(x), RegState::Scalar(y)) => (x, y),
                    _ => {
                        self.stats.states_explored += 1;
                        return Ok(StepOutcome::Next(vec![
                            (pc + 1, state.clone()),
                            (target, state),
                        ]));
                    }
                };
                let dst_scalar_id = state.cur().scalar_ids[ins.dst as usize];
                let src_scalar_id = if ins.is_src_reg() {
                    state.cur().scalar_ids[ins.src as usize]
                } else {
                    0
                };

                let refined = match analyze_cond_jmp(op, is32, sa, sb) {
                    CondOutcome::Decided(taken) => {
                        let t = if taken { target } else { pc + 1 };
                        return Ok(StepOutcome::Next(vec![(t, state)]));
                    }
                    CondOutcome::Both(refined) => refined,
                };

                let mut succs: Vec<(usize, VState)> = Vec::with_capacity(2);
                for (slot, npc) in [(0usize, pc + 1), (1usize, target)] {
                    let Some((ra, rb)) = refined[slot] else {
                        continue; // contradictory: path is dead
                    };
                    let mut ns = state.clone();
                    Self::mark_scalar_id(&mut ns, dst_scalar_id, ra);
                    Self::mark_scalar_id(&mut ns, src_scalar_id, rb);
                    let f = ns.cur_mut();
                    f.regs[ins.dst as usize] = RegState::Scalar(ra);
                    if ins.is_src_reg() {
                        f.regs[ins.src as usize] = RegState::Scalar(rb);
                    }
                    succs.push((npc, ns));
                }
                if succs.len() > 1 {
                    self.stats.states_explored += 1;
                }
                Ok(StepOutcome::Next(succs))
            }
        }
    }
}

/// Render a rejection's counterexample trace as annotated disassembly.
/// Returns an empty string when the error carries no trace.
pub fn render_trace(insns: &[Insn], err: &VerifyError) -> String {
    let Some(t) = &err.trace else {
        return String::new();
    };
    let mut out = String::new();
    let total = t.steps.len() + t.truncated;
    let _ = writeln!(
        out,
        "counterexample path (entry -> insn {}, {} step{}):",
        err.pc,
        total,
        if total == 1 { "" } else { "s" }
    );
    for (i, step) in t.steps.iter().enumerate() {
        // truncation always cuts right after the fixed-size head window
        if t.truncated > 0 && i == 8 {
            let _ = writeln!(out, "        ... {} steps omitted ...", t.truncated);
        }
        let mut text = disasm::disasm_insn(insns, step.pc);
        if let Some((taken, _)) = step.branch {
            text.push_str(if taken { "  [taken]" } else { "  [not taken]" });
        }
        let is_fail = i + 1 == t.steps.len() && step.pc == err.pc;
        let arrow = if is_fail { "->" } else { "  " };
        if step.state.is_empty() {
            let _ = writeln!(out, "  {arrow}{:4}: {text}", step.pc);
        } else {
            let _ = writeln!(out, "  {arrow}{:4}: {text:<44} ; {}", step.pc, step.state);
        }
        if is_fail {
            let _ = writeln!(out, "          ^ {}", err.msg);
        }
    }
    for n in &t.notes {
        let _ = writeln!(out, "note: {n}");
    }
    out
}

/// Convenience wrapper: verify `insns` against `maps` with `cfg`.
pub fn verify(
    insns: &[Insn],
    maps: &[MapDef],
    user_sigs: &[(u32, HelperSig)],
    cfg: Config,
) -> Result<VerifyOk, VerifyError> {
    if cfg.xdp && cfg.metadata_layout.is_some() {
        return Err(VerifyError { pc: 0,
            msg: "XDP and configurable metadata layouts are mutually exclusive".into(),
            trace: None });
    }
    if cfg.btf_ctx.is_some() && cfg.metadata_layout.is_some() {
        return Err(VerifyError { pc: 0,
            msg: "BTF and configurable metadata context models are mutually exclusive".into(),
            trace: None });
    }
    if let Some(layout) = cfg.metadata_layout {
        if cfg.ctx_size < layout.required_len() {
            return Err(VerifyError { pc: 0, msg: format!(
                "metadata layout needs {} context bytes, but ctx_size is {}",
                layout.required_len(), cfg.ctx_size), trace: None });
        }
    }
    Verifier::new(insns, maps, user_sigs, cfg).verify()
}
