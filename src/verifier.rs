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
use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;

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

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "at insn {}: {}", self.pc, self.msg)
    }
}
impl std::error::Error for VerifyError {}

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
    pub fn sync(&mut self) -> bool {
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
        self.umin <= self.umax && self.smin <= self.smax
    }

    fn from_tnum(t: Tnum) -> Scalar {
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
    fn truncate32(&self) -> Scalar {
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

impl std::fmt::Display for Scalar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    /// A map object pointer (not dereferenceable).
    Map { map: u32 },
    /// Pointer into a map value.
    MapValue { map: u32 },
    /// Result of map_lookup_elem before the null check.
    MapValueOrNull { map: u32, id: u32 },
    /// Writable ringbuf record of `size` bytes (from ringbuf_reserve, after the
    /// null check). `id` ties every copy together for consume-tracking.
    RingbufMem { id: u32, size: u32 },
    /// Result of ringbuf_reserve before the null check.
    RingbufMemOrNull { id: u32, size: u32 },
    /// A ringbuf record already submitted/discarded; any further use is an
    /// error (use-after-consume).
    RingbufConsumed { id: u32 },
    /// A BTF-typed kernel pointer (the kernel's `PTR_TO_BTF_ID`): points at a
    /// struct/union of BTF type id `btf_id` in the target BTF (`Config::
    /// btf_ctx`). Read-only; loads are typed by `Btf::read_kind` (pointer
    /// members chase to another `BtfId`, everything else is a scalar) and are
    /// executed as fault-tolerant probe reads (kernel `BPF_PROBE_MEM`).
    BtfId { btf_id: u32 },
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

impl std::fmt::Display for RegState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegState::Uninit => write!(f, "?"),
            RegState::Scalar(s) => write!(f, "{s}"),
            RegState::Ptr(p) => {
                match p.kind {
                    PtrKind::Stack { frame } => write!(f, "fp{frame}")?,
                    PtrKind::Ctx => write!(f, "ctx")?,
                    PtrKind::Map { map } => write!(f, "map{map}")?,
                    PtrKind::MapValue { map } => write!(f, "map{map}_value")?,
                    PtrKind::MapValueOrNull { map, .. } => write!(f, "map{map}_value_or_null")?,
                    PtrKind::RingbufMem { size, .. } => write!(f, "ringbuf_mem[{size}]")?,
                    PtrKind::RingbufMemOrNull { size, .. } => {
                        write!(f, "ringbuf_mem_or_null[{size}]")?
                    }
                    PtrKind::RingbufConsumed { .. } => write!(f, "ringbuf_consumed")?,
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
    stack: [SlotState; SLOTS],
    /// Where execution resumes in the caller (frames > 0).
    ret_pc: usize,
}

impl Frame {
    fn new(ret_pc: usize) -> Frame {
        Frame {
            regs: [RegState::Uninit; NUM_REGS],
            stack: [SlotState::EMPTY; SLOTS],
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

fn scalar_add(a: Scalar, b: Scalar) -> Scalar {
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

fn scalar_sub(a: Scalar, b: Scalar) -> Scalar {
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

fn scalar_mul(a: Scalar, b: Scalar) -> Scalar {
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
fn scalar_div(a: Scalar, b: Scalar) -> Scalar {
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
fn scalar_mod(a: Scalar, b: Scalar) -> Scalar {
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

fn scalar_bitop(op: u8, a: Scalar, b: Scalar) -> Scalar {
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

fn scalar_shift(op: u8, is32: bool, a: Scalar, b: Scalar) -> Result<Scalar, String> {
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

fn scalar_endian(is_swap: bool, width_bits: i32, a: Scalar) -> Scalar {
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
fn scalar_movsx(b: Scalar, bits: u16) -> Scalar {
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

fn alu_scalar(
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
                    let (av, bv) = (a.umin as i64, b.umin as i64);
                    let v = if bv == 0 { 0 } else { av.wrapping_div(bv) as u64 };
                    Scalar::constant(if is32 { v as u32 as u64 } else { v })
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
                    let (av, bv) = (a.umin as i64, b.umin as i64);
                    let v = if bv == 0 {
                        a.umin
                    } else {
                        av.wrapping_rem(bv) as u64
                    };
                    Scalar::constant(if is32 { v as u32 as u64 } else { v })
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
fn branch_taken(op: u8, a: &Scalar, b: &Scalar) -> Option<bool> {
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
fn refine(op: u8, taken: bool, a: &mut Scalar, b: &mut Scalar) -> bool {
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
    seen: HashMap<usize, PruneList>,
    prune_points: Vec<bool>,
    insn_state: Vec<Option<(String, usize)>>,
    /// Join-over-all-visits of the current frame's registers per insn (see
    /// [`VerifyOk::pc_regs`]).
    pc_regs: Vec<Option<[RegState; NUM_REGS]>>,
    next_null_id: u32,
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
    replay_null_origin: Option<HashMap<u32, (usize, String)>>,
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
            seen: HashMap::new(),
            prune_points: Vec::new(),
            insn_state: Vec::new(),
            pc_regs: Vec::new(),
            next_null_id: 1,
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
        self.replay_null_origin = Some(HashMap::new());
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
                    if let PtrKind::MapValueOrNull { map, id } = p.kind {
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
        if ins.src >= NUM_REGS as u8 && ins.class() != class::LD {
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
                } else {
                    Err(bad(format!(
                        "legacy packet access (opcode {:#04x}) is not supported",
                        ins.opcode
                    )))
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
        state.cur_mut().regs[r as usize] = v;
        Ok(())
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
                    // A pointer slot must be read whole (the kernel types the
                    // full 8-byte load as PTR_TO_BTF_ID; a narrower read of a
                    // pointer is meaningless and rejected).
                    if size != 8
                        && matches!(bc.args[arg as usize], crate::btf::CtxSlot::Ptr { .. })
                    {
                        return Err(self.err(
                            pc,
                            format!(
                                "BTF ctx pointer argument {arg} must be loaded with an \
                                 8-byte read (got {size})"
                            ),
                        ));
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
            PtrKind::RingbufMem { size, .. } => (size as u64, "ringbuf record"),
            PtrKind::RingbufMemOrNull { .. } => {
                return Err(self.err(
                    pc,
                    "ringbuf record pointer may be NULL; compare it against 0 first",
                ));
            }
            PtrKind::RingbufConsumed { .. } => {
                return Err(self.err(
                    pc,
                    "use of a ringbuf record after it was submitted/discarded",
                ));
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
        &self,
        pc: usize,
        p: &Ptr,
        disp: i64,
        size: u64,
    ) -> Result<RegState, VerifyError> {
        match p.kind {
            PtrKind::Ctx => {
                if let Some(bc) = &self.cfg.btf_ctx {
                    if size == 8 {
                        if let crate::btf::CtxSlot::Ptr { btf_id } = bc.args[(disp / 8) as usize]
                        {
                            return Ok(RegState::Ptr(Ptr::new(PtrKind::BtfId { btf_id })));
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

    fn stack_store(
        &mut self,
        state: &mut VState,
        pc: usize,
        frame: usize,
        off: i64,
        size: u64,
        val: RegState,
    ) -> Result<(), VerifyError> {
        let base = (STACK_SIZE as i64 + off) as usize;
        let stack = &mut state.frames[frame].stack;
        if size == 8 && base.is_multiple_of(8) {
            stack[base / 8] = SlotState::Spill(val);
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
                self.stack_store(state, pc, frame, off, len, RegState::Scalar(Scalar::unknown()))?;
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
                ArgKind::Scalar | ArgKind::Size => {
                    if !matches!(val, RegState::Scalar(_)) {
                        return Err(self.err(
                            pc,
                            format!("helper {} arg{}: expected scalar in r{reg}", sig.name, i + 1),
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
            // Helpers that require a specific map kind (see docs/specs/map-types-2.md).
            let required = match hid {
                crate::helpers::id::PERF_EVENT_OUTPUT => Some(crate::maps::MapKind::PerfEventArray),
                crate::helpers::id::GET_STACKID => Some(crate::maps::MapKind::StackTrace),
                crate::helpers::id::CURRENT_TASK_UNDER_CGROUP => {
                    Some(crate::maps::MapKind::CgroupArray)
                }
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
                RegState::Ptr(Ptr::new(PtrKind::MapValueOrNull { map, id }))
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
                        PtrKind::RingbufMemOrNull { id: pid, size } if pid == id => {
                            if becomes_null {
                                *r = RegState::Scalar(Scalar::constant(0));
                            } else {
                                p.kind = PtrKind::RingbufMem { id: pid, size };
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
                        // narrow load can't restore a pointer spill
                        _ => RegState::Scalar(Scalar::unknown()),
                    }
                } else {
                    loaded
                };
                self.write_reg(&mut state, pc, ins.dst, loaded)?;
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
                    self.stack_store(&mut state, pc, frame, off, size, val)?
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

        // operand b
        let b: RegState = if op == alu::NEG || op == alu::END {
            RegState::Scalar(Scalar::constant(0))
        } else if ins.is_src_reg() {
            self.read_reg(state, pc, ins.src)?
        } else {
            RegState::Scalar(Scalar::constant(ins.imm as i64 as u64))
        };

        if op == alu::MOV {
            let v = match b {
                RegState::Scalar(s) => {
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
            return self.write_reg(state, pc, ins.dst, v);
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
                            if std::mem::discriminant(&pa.kind) != std::mem::discriminant(&pb.kind)
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
        self.write_reg(state, pc, ins.dst, RegState::Scalar(result))
    }

    fn adjust_ptr(&self, pc: usize, p: Ptr, s: Scalar, sub: bool) -> Result<Ptr, VerifyError> {
        if matches!(
            p.kind,
            PtrKind::Map { .. }
                | PtrKind::MapValueOrNull { .. }
                | PtrKind::RingbufMemOrNull { .. }
                | PtrKind::RingbufConsumed { .. }
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
                    for r in 1..=5 {
                        f.regs[r] = RegState::Uninit;
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
                            | PtrKind::RingbufMemOrNull { id, .. },
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

                // pointer comparisons: allowed, no refinement
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

                // 32-bit compares refine only when values fit in 32 bits
                let refinable =
                    !is32 || (sa.umax <= u32::MAX as u64 && sb.umax <= u32::MAX as u64);
                let (ca, cb) = if is32 {
                    (sa.truncate32(), sb.truncate32())
                } else {
                    (sa, sb)
                };

                if let Some(taken) = branch_taken(op, &ca, &cb) {
                    let t = if taken { target } else { pc + 1 };
                    return Ok(StepOutcome::Next(vec![(t, state)]));
                }

                let mut succs: Vec<(usize, VState)> = Vec::with_capacity(2);
                for (taken, npc) in [(false, pc + 1), (true, target)] {
                    let mut ns = state.clone();
                    if refinable {
                        let (mut ra, mut rb) = (ca, cb);
                        if !refine(op, taken, &mut ra, &mut rb) {
                            continue; // contradictory: path is dead
                        }
                        let f = ns.cur_mut();
                        f.regs[ins.dst as usize] = RegState::Scalar(ra);
                        if ins.is_src_reg() {
                            f.regs[ins.src as usize] = RegState::Scalar(rb);
                        }
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
    Verifier::new(insns, maps, user_sigs, cfg).verify()
}
