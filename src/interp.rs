//! The eBPF virtual machine: a fast, fully memory-safe interpreter.
//!
//! # Memory model
//!
//! eBPF pointers are *virtual addresses*: `region_handle << 32 | offset`.
//! Every load/store resolves the handle through a region table with an O(1)
//! bounds check — no host pointers ever enter guest registers, so even
//! unverified programs cannot touch memory outside their sandbox (they just
//! get a runtime error). Regions are: the context buffer, one 512-byte stack
//! per call frame, map objects (not dereferenceable) and map values (created
//! lazily, one per value, giving exact per-value bounds).

// The div/mod arms below implement eBPF's defined-by-zero semantics
// (÷0 ⇒ 0, %0 ⇒ unchanged), which `checked_div` would obscure.
#![allow(clippy::manual_checked_ops)]
use crate::helpers::{self, MemBus, UserHelpers};
use crate::insn::*;
use crate::maps::{Map, MapDef, MapSnapshot, MapUpdateMode, ValueRef};
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

/// Monotonic clock for the `ktime_get_ns` helper. `std::time::Instant` panics
/// on `wasm32-unknown-unknown` (no time source), so that target and `no_std`
/// builds get a stub that reports 0 — deterministic and host-independent.
struct Clock {
    #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
    start: std::time::Instant,
}

impl Clock {
    fn start() -> Clock {
        Clock {
            #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
            start: std::time::Instant::now(),
        }
    }
    fn elapsed_nanos(&self) -> u64 {
        #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
        {
            self.start.elapsed().as_nanos() as u64
        }
        #[cfg(any(not(feature = "std"), target_arch = "wasm32"))]
        {
            0
        }
    }
}

#[derive(Debug)]
pub struct EbpfError {
    pub pc: usize,
    pub msg: String,
}

impl core::fmt::Display for EbpfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "runtime error at insn {}: {}", self.pc, self.msg)
    }
}
impl core::error::Error for EbpfError {}

/// A program ready to be loaded into a [`Vm`]: instructions plus map
/// definitions referenced by `lddw` pseudo instructions, plus — for
/// `tp_btf`/`fentry`-style programs — the BTF typing of the context (see
/// docs/specs/btf-ctx-pointers.md).
#[derive(Clone)]
pub struct Program {
    pub insns: Vec<Insn>,
    pub maps: Vec<MapDef>,
    pub btf_ctx: Option<crate::btf::BtfCtx>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Region {
    Invalid,
    Ctx,
    Stack(u32),
    /// Map object pointer; only meaningful as a helper argument.
    MapObj(u32),
    MapValue { map: u32, vref: ValueRef },
    /// A ringbuf record reserved by `ringbuf_reserve` (writable until it is
    /// submitted or discarded, which marks the reservation consumed).
    RingReserved { map: u32, res: u32 },
    /// Synthetic kernel memory for BTF-typed pointers (`tp_btf`/`fentry`
    /// ctx arguments): every read returns zeroes, every write faults. This is
    /// the deterministic stand-in for the kernel's fault-tolerant
    /// `BPF_PROBE_MEM` reads — see docs/specs/btf-ctx-pointers.md.
    KernelMem,
    /// Mutable bytes of the packet supplied to [`Vm::run_xdp`].
    Packet,
    /// VM-owned bytes registered by the embedding host.
    Owned(u32),
}

/// Guest access permitted for a VM-owned external region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionAccess {
    ReadOnly,
    ReadWrite,
}

/// Locations of 64-bit packet start/end virtual addresses in caller metadata.
///
/// The two fields may appear anywhere in the metadata buffer but must not
/// overlap. Addresses use febpf's stable little-endian guest ABI and never
/// contain host pointers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataLayout {
    data_offset: usize,
    data_end_offset: usize,
}

impl MetadataLayout {
    pub fn new(data_offset: usize, data_end_offset: usize) -> Result<Self, String> {
        let data_end = data_offset.checked_add(8)
            .ok_or_else(|| "metadata data offset overflows address space".to_string())?;
        let data_end_end = data_end_offset.checked_add(8)
            .ok_or_else(|| "metadata data_end offset overflows address space".to_string())?;
        if data_offset < data_end_end && data_end_offset < data_end {
            return Err("metadata data and data_end fields overlap".into());
        }
        Ok(Self { data_offset, data_end_offset })
    }

    pub fn data_offset(self) -> usize { self.data_offset }
    pub fn data_end_offset(self) -> usize { self.data_end_offset }
    pub fn required_len(self) -> usize { self.data_offset.max(self.data_end_offset) + 8 }
}

#[derive(Clone, Debug, PartialEq)]
struct OwnedRegion {
    bytes: Vec<u8>,
    access: RegionAccess,
}

const CTX_HANDLE: u32 = 1;
const STACK0_HANDLE: u32 = 2;
const KMEM_HANDLE: u32 = STACK0_HANDLE + MAX_CALL_FRAMES as u32;
const PACKET_HANDLE: u32 = KMEM_HANDLE + 1;

/// Seed for the deterministic `get_prandom_u32` xorshift. A run is a pure
/// function of (program, ctx, this seed, map preload), which is what makes
/// replay files reproducible — see `src/replay.rs`.
pub const DEFAULT_PRANDOM_SEED: u64 = 0x853c49e6748fea9b;
/// Deterministic standalone capacity of the synthetic iterator `seq_file`.
/// `seq_write` fails atomically with `-EOVERFLOW` beyond this bound.
pub const SEQ_OUTPUT_CAPACITY: usize = 1 << 20;

#[inline]
fn mkaddr(handle: u32, off: u32) -> u64 {
    ((handle as u64) << 32) | off as u64
}

pub struct Vm {
    /// Original instructions (as loaded), used for verification & disasm.
    insns: Vec<Insn>,
    /// Executable instructions: map-reference lddw patched to addresses.
    exec: Vec<Insn>,
    pub maps: Vec<Map>,
    map_defs: Vec<MapDef>,
    map_obj_handles: Vec<u32>,
    pub user_helpers: UserHelpers,
    regions: Vec<Region>,
    owned_regions: Vec<OwnedRegion>,
    stack: Vec<u8>,
    start: Clock,
    prandom: u64,
    /// Lines emitted by trace_printk.
    pub printk: Vec<String>,
    /// Bytes emitted through iterator helper `seq_write`.
    pub seq_output: Vec<u8>,
    /// Echo trace_printk lines to stderr as they happen.
    pub echo_printk: bool,
    /// Abort execution after this many instructions.
    pub insn_limit: u64,
    /// When set, per-instruction execution counts (enable with
    /// [`Vm::enable_profiling`]; accumulates across runs).
    pub profile: Option<Vec<u64>>,
    /// Compiled native code, if this VM was JIT-compiled. Taken out during
    /// execution (like `user_helpers`) to satisfy the borrow checker.
    #[cfg(feature = "jit")]
    pub jit: Option<crate::jit::JitProgram>,
    /// Source-level debug info (from `.BTF.ext`/`.BTF`), when the program was
    /// loaded from a `-g` ELF object. Static across a run, so not snapshotted.
    debug: Option<crate::debuginfo::DebugInfo>,
    /// BTF typing of the ctx (`tp_btf`/`fentry` programs, set by the ELF
    /// loader path): pointer slots are prefilled with kernel-memory addresses
    /// on run, and `Vm::verify` verifies under the BTF ctx rules. Static
    /// across a run, like `debug`.
    btf_ctx: Option<crate::btf::BtfCtx>,
    /// Per-insn: loads the verifier proved go through a BTF pointer, executed
    /// as fault-tolerant probe reads (kernel `BPF_PROBE_MEM`: a bad address
    /// reads as zero). Armed by [`Vm::verify`]; empty when unverified, in
    /// which case such loads fault cleanly instead. Static per program.
    probe_mem: Vec<bool>,
    /// Scratch backing for [`Region::KernelMem`] reads; logically an
    /// all-zeroes region, re-zeroed on every resolve. Not run state.
    kmem: Vec<u8>,
    /// Backing for the direct-packet-access virtual region.
    packet: Vec<u8>,
    /// Set after verification with [`crate::verifier::Config::xdp`]; causes
    /// xdp_md data/data_end loads to synthesize full virtual addresses.
    xdp: bool,
    /// Set after verification with the explicit `__sk_buff` model.
    skb: bool,
    /// Configurable pointer-bearing metadata layout armed by verification.
    metadata_layout: Option<MetadataLayout>,
    legacy_packet: crate::verifier::LegacyPacketProfile,
    legacy_packet_used: bool,
    tail_programs: Vec<TailProgram>,
}

struct TailProgram {
    insns: Vec<Insn>,
    exec: Vec<Insn>,
    probe_mem: Vec<bool>,
    #[cfg(feature = "jit")]
    jit: Option<crate::jit::JitProgram>,
}

impl Vm {
    pub fn new(prog: Program) -> Result<Vm, String> {
        let mut regions = vec![Region::Invalid, Region::Ctx];
        for f in 0..MAX_CALL_FRAMES as u32 {
            regions.push(Region::Stack(f));
        }
        regions.push(Region::KernelMem); // KMEM_HANDLE
        regions.push(Region::Packet); // PACKET_HANDLE
        for (outer, def) in prog.maps.iter().enumerate() {
            if !def.kind.is_map_of_maps() {
                continue;
            }
            let template = def.inner_map_idx.ok_or_else(|| {
                format!("map-in-map '{}' has no inner-map template", def.name)
            })? as usize;
            let template_def = prog.maps.get(template).ok_or_else(|| {
                format!(
                    "map-in-map '{}' references unknown template map {template}",
                    def.name
                )
            })?;
            if template == outer || template_def.kind.is_map_of_maps() {
                return Err(format!(
                    "map-in-map '{}' has invalid template '{}'",
                    def.name, template_def.name
                ));
            }
            for &(_, inner) in &def.map_in_map_values {
                let inner_def = prog.maps.get(inner as usize).ok_or_else(|| {
                    format!(
                        "map-in-map '{}' references unknown inner map {inner}",
                        def.name
                    )
                })?;
                if inner_def.kind != template_def.kind
                    || inner_def.key_size != template_def.key_size
                    || inner_def.value_size != template_def.value_size
                    || inner_def.max_entries != template_def.max_entries
                {
                    return Err(format!(
                        "map-in-map '{}' contains incompatible inner map '{}'",
                        def.name, inner_def.name
                    ));
                }
            }
        }
        let maps: Vec<Map> = prog
            .maps
            .iter()
            .map(|d| Map::new(d.clone()))
            .collect::<Result<_, _>>()?;
        let map_obj_handles: Vec<u32> = (0..maps.len())
            .map(|m| {
                regions.push(Region::MapObj(m as u32));
                (regions.len() - 1) as u32
            })
            .collect();

        let mut vm = Vm {
            exec: prog.insns.clone(),
            btf_ctx: prog.btf_ctx,
            insns: prog.insns,
            maps,
            map_defs: prog.maps,
            map_obj_handles: map_obj_handles.clone(),
            user_helpers: UserHelpers::new(),
            regions,
            owned_regions: Vec::new(),
            stack: vec![0u8; MAX_CALL_FRAMES * STACK_SIZE],
            start: Clock::start(),
            prandom: DEFAULT_PRANDOM_SEED,
            printk: Vec::new(),
            seq_output: Vec::new(),
            echo_printk: false,
            insn_limit: u64::MAX,
            profile: None,
            #[cfg(feature = "jit")]
            jit: None,
            debug: None,
            probe_mem: Vec::new(),
            kmem: Vec::new(),
            packet: Vec::new(),
            xdp: false,
            skb: false,
            metadata_layout: None,
            legacy_packet: crate::verifier::LegacyPacketProfile::Disabled,
            legacy_packet_used: false,
            tail_programs: Vec::new(),
        };

        // Patch map-reference lddw instructions into plain 64-bit immediates.
        let mut pc = 0;
        while pc < vm.exec.len() {
            let ins = vm.exec[pc];
            if ins.is_wide() {
                let m = ins.imm as usize;
                match ins.src {
                    pseudo::MAP_ID => {
                        if m >= vm.maps.len() {
                            return Err(format!("insn {pc}: lddw references unknown map {m}"));
                        }
                        let addr = mkaddr(map_obj_handles[m], 0);
                        vm.patch_wide(pc, addr);
                    }
                    pseudo::MAP_VALUE => {
                        if m >= vm.maps.len() {
                            return Err(format!("insn {pc}: lddw references unknown map {m}"));
                        }
                        if vm.maps[m].def.kind != crate::maps::MapKind::Array {
                            return Err(format!(
                                "insn {pc}: direct value access needs an array map"
                            ));
                        }
                        let off = vm.exec[pc + 1].imm as u32;
                        let base = vm.value_addr(m as u32, ValueRef::ArrayElem(0));
                        vm.patch_wide(pc, base + off as u64);
                    }
                    _ => {}
                }
                pc += 2;
            } else {
                pc += 1;
            }
        }
        Ok(vm)
    }

    /// Register VM-owned bytes as a bounded guest virtual region.
    ///
    /// The returned opaque address may be returned by a typed user helper or
    /// otherwise supplied to guest code. It contains no host address. Guest
    /// accesses are checked against both `bytes.len()` and `access`, even when
    /// the program is run without verification.
    pub fn register_owned_region(
        &mut self,
        bytes: Vec<u8>,
        access: RegionAccess,
    ) -> Result<u64, String> {
        if bytes.len() > u32::MAX as usize {
            return Err("owned region is too large for a guest virtual address".into());
        }
        if self.regions.len() > u32::MAX as usize {
            return Err("guest virtual region table is full".into());
        }
        let index = self.owned_regions.len() as u32;
        self.owned_regions.push(OwnedRegion { bytes, access });
        self.regions.push(Region::Owned(index));
        Ok(mkaddr((self.regions.len() - 1) as u32, 0))
    }

    /// Inspect a registered owned region by its opaque base address.
    pub fn owned_region(&self, base: u64) -> Option<&[u8]> {
        if base as u32 != 0 {
            return None;
        }
        let Region::Owned(index) = *self.regions.get((base >> 32) as usize)? else {
            return None;
        };
        Some(&self.owned_regions.get(index as usize)?.bytes)
    }

    /// Replace the entry program and all state derived from it.
    ///
    /// The replacement is transactional: if constructing the new program or
    /// its maps fails, this VM is left unchanged. A successful replacement is
    /// otherwise equivalent to constructing a fresh VM: maps, verification
    /// state, compiled code, debug information, tail-call targets, profiling
    /// counts and execution output are reset. Registered user helpers and the
    /// embedding execution configuration (`echo_printk`, `insn_limit`, the
    /// configured PRNG seed, and whether profiling is enabled) are preserved.
    /// The replacement must be verified explicitly before execution when the
    /// embedding requires verification.
    pub fn replace_program(&mut self, prog: Program) -> Result<(), String> {
        let mut replacement = Vm::new(prog)?;

        replacement.echo_printk = self.echo_printk;
        replacement.insn_limit = self.insn_limit;
        replacement.prandom = self.prandom;
        if self.profile.is_some() {
            replacement.enable_profiling();
        }
        replacement.user_helpers = core::mem::take(&mut self.user_helpers);

        *self = replacement;
        Ok(())
    }

    /// Verify and link a program into one `PROG_ARRAY` slot. Programs in a
    /// bundle share the entry VM's maps and virtual map-object addresses.
    pub fn register_tail_call(
        &mut self,
        map_name: &str,
        index: u32,
        prog: Program,
        mut cfg: crate::verifier::Config,
    ) -> Result<u32, String> {
        if prog.maps != self.map_defs {
            return Err("tail-call target must use the bundle's identical map definitions".into());
        }
        if cfg.btf_ctx.is_none() {
            cfg.btf_ctx = prog.btf_ctx.clone();
        }
        if cfg.legacy_packet != self.legacy_packet {
            return Err("tail-call target legacy packet profile must match the entry program".into());
        }
        let ok = crate::verifier::verify(&prog.insns, &prog.maps, self.user_helpers.sigs(), cfg)
            .map_err(|e| format!("tail-call target verification failed: {e}"))?;
        let exec = self.patch_bundle_program(&prog.insns)?;
        let program_id = self.tail_programs.len() as u32 + 1;
        let map = self
            .maps
            .iter_mut()
            .find(|m| m.def.name == map_name)
            .ok_or_else(|| format!("no map named '{map_name}'"))?;
        if map.def.kind != crate::maps::MapKind::ProgArray {
            return Err(format!("map '{map_name}' is not a prog_array"));
        }
        map.set_program(index, program_id)
            .map_err(|e| format!("cannot set {map_name}[{index}]: errno {}", -e))?;
        let uses_legacy_packet = prog.insns.iter().any(is_legacy_packet_load);
        self.tail_programs.push(TailProgram {
            insns: prog.insns,
            exec,
            probe_mem: ok.probe_mem,
            #[cfg(feature = "jit")]
            jit: None,
        });
        self.legacy_packet_used |= uses_legacy_packet;
        Ok(program_id)
    }

    /// Populate a map-in-map entry from userspace while preserving the inner
    /// template invariant relied upon by the verifier.
    pub fn update_inner_map(
        &mut self,
        outer: u32,
        key: &[u8],
        inner: u32,
        mode: MapUpdateMode,
    ) -> Result<(), i64> {
        let outer_def = self.maps.get(outer as usize).ok_or(-2i64)?.def.clone();
        let template = outer_def.inner_map_idx.ok_or(-22i64)?;
        let template_def = &self.maps.get(template as usize).ok_or(-22i64)?.def;
        let inner_def = &self.maps.get(inner as usize).ok_or(-2i64)?.def;
        if template == outer
            || template_def.kind.is_map_of_maps()
            || inner_def.kind != template_def.kind
            || inner_def.key_size != template_def.key_size
            || inner_def.value_size != template_def.value_size
            || inner_def.max_entries != template_def.max_entries
        {
            return Err(-22);
        }
        let outer_map = &mut self.maps[outer as usize];
        match outer_def.kind {
            crate::maps::MapKind::ArrayOfMaps => {
                let index = u32::from_ne_bytes(key.try_into().map_err(|_| -22i64)?);
                outer_map.set_inner_map(index, inner, mode)
            }
            crate::maps::MapKind::HashOfMaps => {
                outer_map.set_inner_map_key(key, inner, mode)
            }
            _ => Err(-22),
        }
    }

    /// Delete a userspace-populated `HASH_OF_MAPS` entry.
    pub fn delete_inner_map(&mut self, outer: u32, key: &[u8]) -> Result<(), i64> {
        self.maps
            .get_mut(outer as usize)
            .ok_or(-2i64)?
            .delete_inner_map_key(key)
    }

    fn patch_wide(&mut self, pc: usize, value: u64) {
        self.exec[pc].src = pseudo::IMM64;
        self.exec[pc].imm = value as u32 as i32;
        self.exec[pc + 1].imm = (value >> 32) as u32 as i32;
    }

    fn patch_bundle_program(&mut self, insns: &[Insn]) -> Result<Vec<Insn>, String> {
        let mut exec = insns.to_vec();
        let mut pc = 0;
        while pc < exec.len() {
            let ins = exec[pc];
            if ins.is_wide() {
                let map = ins.imm as usize;
                let addr = match ins.src {
                    pseudo::MAP_ID => mkaddr(
                        *self.map_obj_handles.get(map).ok_or_else(|| {
                            format!("insn {pc}: lddw references unknown map {map}")
                        })?,
                        0,
                    ),
                    pseudo::MAP_VALUE => {
                        if self.maps.get(map).map(|m| m.def.kind)
                            != Some(crate::maps::MapKind::Array)
                        {
                            return Err(format!(
                                "insn {pc}: direct value access needs an array map"
                            ));
                        }
                        self.value_addr(map as u32, ValueRef::ArrayElem(0))
                            + exec[pc + 1].imm as u32 as u64
                    }
                    _ => {
                        pc += 2;
                        continue;
                    }
                };
                exec[pc].src = pseudo::IMM64;
                exec[pc].imm = addr as u32 as i32;
                exec[pc + 1].imm = (addr >> 32) as u32 as i32;
                pc += 2;
            } else {
                pc += 1;
            }
        }
        Ok(exec)
    }

    /// Virtual address of a map value, creating its region on first use.
    fn value_addr(&mut self, map: u32, vref: ValueRef) -> u64 {
        let idx = match vref {
            ValueRef::ArrayElem(i) => i as usize,
            ValueRef::Slab(i) => i as usize,
        };
        let h = self.maps[map as usize].region_handles[idx];
        if h != 0 {
            return mkaddr(h, 0);
        }
        self.regions.push(Region::MapValue { map, vref });
        let h = (self.regions.len() - 1) as u32;
        self.maps[map as usize].region_handles[idx] = h;
        mkaddr(h, 0)
    }

    /// Verify the loaded program (uses registered user-helper signatures).
    ///
    /// When this VM carries a BTF-typed ctx (see [`Vm::set_btf_ctx`]) it is
    /// injected into the config, and on success the VM is armed with the
    /// verifier's probe-read bitmap — the kernel does the same in
    /// convert_ctx_accesses(), rewriting BTF-pointer loads to BPF_PROBE_MEM.
    /// An unverified (`--no-verify`) run of a BTF program therefore faults
    /// cleanly on kernel-pointer derefs instead of reading zeroes.
    pub fn verify(
        &mut self,
        mut cfg: crate::verifier::Config,
    ) -> Result<crate::verifier::VerifyOk, crate::verifier::VerifyError> {
        if cfg.btf_ctx.is_none() {
            cfg.btf_ctx = self.btf_ctx.clone();
        }
        let xdp = cfg.xdp;
        let skb = cfg.skb;
        let metadata_layout = cfg.metadata_layout;
        let legacy_packet = cfg.legacy_packet;
        let ok =
            crate::verifier::verify(&self.insns, &self.map_defs, self.user_helpers.sigs(), cfg)?;
        self.xdp = xdp;
        self.skb = skb;
        self.metadata_layout = metadata_layout;
        self.legacy_packet = legacy_packet;
        self.legacy_packet_used = self.insns.iter().any(is_legacy_packet_load);
        self.probe_mem = ok.probe_mem.clone();
        Ok(ok)
    }

    /// Run core verification, then apply an embedding-specific policy.
    ///
    /// `policy` is called only after febpf's structural and memory-safety
    /// verifier succeeds. The VM is armed with verifier-derived XDP and probe
    /// state only if both stages accept the program. Use [`Vm::verify`] when
    /// no application policy is needed.
    pub fn verify_with_policy<F>(
        &mut self,
        mut cfg: crate::verifier::Config,
        policy: F,
    ) -> Result<crate::verifier::VerifyOk, crate::verifier::VerifyWithPolicyError>
    where
        F: FnOnce(&crate::verifier::PolicyView<'_>) -> Result<(), String>,
    {
        use crate::verifier::VerifyWithPolicyError;

        if cfg.btf_ctx.is_none() {
            cfg.btf_ctx = self.btf_ctx.clone();
        }
        let xdp = cfg.xdp;
        let skb = cfg.skb;
        let metadata_layout = cfg.metadata_layout;
        let legacy_packet = cfg.legacy_packet;
        let ok = crate::verifier::verify(
            &self.insns,
            &self.map_defs,
            self.user_helpers.sigs(),
            cfg,
        )
        .map_err(VerifyWithPolicyError::Core)?;
        policy(&crate::verifier::PolicyView {
            insns: &self.insns,
            maps: &self.map_defs,
            evidence: &ok,
        })
        .map_err(VerifyWithPolicyError::Policy)?;
        self.xdp = xdp;
        self.skb = skb;
        self.metadata_layout = metadata_layout;
        self.legacy_packet = legacy_packet;
        self.legacy_packet_used = self.insns.iter().any(is_legacy_packet_load);
        self.probe_mem = ok.probe_mem.clone();
        Ok(ok)
    }

    /// Attach BTF typing of the ctx (set by the ELF loader for
    /// `tp_btf`/`fentry`/iterator-style programs). Non-null pointer ctx slots
    /// are prefilled with kernel-memory addresses on each run; nullable
    /// iterator elements remain zero for a deterministic terminal record.
    /// [`Vm::verify`] verifies under the kernel's typed-ctx rules.
    pub fn set_btf_ctx(&mut self, bc: crate::btf::BtfCtx) {
        self.btf_ctx = Some(bc);
    }

    /// BTF typing of the ctx, if any (see [`Vm::set_btf_ctx`]).
    pub fn btf_ctx(&self) -> Option<&crate::btf::BtfCtx> {
        self.btf_ctx.as_ref()
    }

    pub fn insns(&self) -> &[Insn] {
        &self.insns
    }

    /// Legacy packet semantics armed by the most recent successful verify.
    pub fn legacy_packet_profile(&self) -> crate::verifier::LegacyPacketProfile {
        self.legacy_packet
    }

    /// Whether the entry/tail-call bundle contains a legacy packet load.
    pub fn uses_legacy_packet(&self) -> bool {
        self.legacy_packet_used
    }

    /// Records submitted/output to a named ringbuf map (for tests and tooling).
    pub fn ringbuf_records(&self, name: &str) -> Option<&[Vec<u8>]> {
        self.maps
            .iter()
            .find(|m| m.def.name == name)
            .map(|m| m.ringbuf_records())
    }

    /// Records emitted via `bpf_perf_event_output` to a named perf-event array
    /// map (for tests and tooling), mirroring [`Vm::ringbuf_records`].
    pub fn perf_records(&self, name: &str) -> Option<&[Vec<u8>]> {
        self.maps
            .iter()
            .find(|m| m.def.name == name)
            .map(|m| m.perf_records())
    }

    /// Current `get_prandom_u32` state. Before a run this is the seed the next
    /// run will start from; recorded into replay files for reproducibility.
    pub fn prandom_seed(&self) -> u64 {
        self.prandom
    }

    /// Set the `get_prandom_u32` seed (used when loading a replay file so the
    /// deterministic PRNG stream matches the recorded run).
    pub fn set_prandom_seed(&mut self, seed: u64) {
        self.prandom = seed;
    }

    /// Attach source-level debug info (set by the ELF loader path).
    pub fn set_debug(&mut self, debug: crate::debuginfo::DebugInfo) {
        self.debug = Some(debug);
    }

    /// Source-level debug info, if this program carried any.
    pub fn debug(&self) -> Option<&crate::debuginfo::DebugInfo> {
        self.debug.as_ref()
    }

    /// Start counting executions per instruction (see [`Vm::profile`]).
    pub fn enable_profiling(&mut self) {
        self.profile = Some(vec![0u64; self.insns.len()]);
    }

    /// Execute the program with `ctx` as the memory r1 points to.
    pub fn run(&mut self, ctx: &mut [u8]) -> Result<u64, EbpfError> {
        self.run_with_packet(ctx, LegacyPacketBacking::None)
    }

    fn run_with_packet(
        &mut self,
        ctx: &mut [u8],
        packet: LegacyPacketBacking,
    ) -> Result<u64, EbpfError> {
        self.require_packet_backing(packet)?;
        let mut m = Machine::new_with_packet(self, ctx, packet);
        loop {
            if let Some(ret) = m.step()? {
                return Ok(ret);
            }
        }
    }

    /// Execute a program that takes no input.
    ///
    /// This is the explicit embedding adapter for programs whose `r1` context
    /// is empty. It has the same semantics as `run(&mut [])`.
    pub fn run_no_data(&mut self) -> Result<u64, EbpfError> {
        self.run(&mut [])
    }

    /// Execute with `buffer` as the mutable memory region addressed by `r1`.
    ///
    /// Guest addresses remain bounded virtual addresses; this does not expose
    /// the buffer's host pointer to the program. Writes made by the program are
    /// visible in `buffer` when execution returns.
    pub fn run_raw(&mut self, buffer: &mut [u8]) -> Result<u64, EbpfError> {
        self.run_with_packet(buffer, LegacyPacketBacking::Context)
    }

    fn prepare_metadata(&self, metadata: &mut [u8], packet_base: u64) -> Result<u32, EbpfError> {
        let fail = |msg: String| EbpfError { pc: 0, msg };
        let layout = self.metadata_layout.ok_or_else(|| fail(
            "metadata execution requires successful metadata-layout verification".into()))?;
        if metadata.len() < layout.required_len() {
            return Err(fail(format!("metadata buffer is too short: need {} bytes, got {}",
                layout.required_len(), metadata.len())));
        }
        if packet_base as u32 != 0 {
            return Err(fail("packet address is not an owned-region base".into()));
        }
        let handle = (packet_base >> 32) as usize;
        let Region::Owned(index) = self.regions.get(handle).copied().ok_or_else(|| fail(
            "packet address does not name a registered owned region".into()))? else {
            return Err(fail("packet address does not name a registered owned region".into()));
        };
        let packet = self.owned_regions.get(index as usize)
            .ok_or_else(|| fail("packet address names a stale owned region".into()))?;
        if packet.access != RegionAccess::ReadWrite {
            return Err(fail("metadata packet region must be read-write".into()));
        }
        let packet_end = packet_base.checked_add(packet.bytes.len() as u64)
            .ok_or_else(|| fail("packet end virtual address overflows".into()))?;
        metadata[layout.data_offset()..layout.data_offset() + 8]
            .copy_from_slice(&packet_base.to_le_bytes());
        metadata[layout.data_end_offset()..layout.data_end_offset() + 8]
            .copy_from_slice(&packet_end.to_le_bytes());
        Ok(index)
    }

    /// Execute with caller metadata containing a registered owned packet's
    /// virtual start/end addresses. The layout must first be armed by a
    /// successful verification.
    pub fn run_metadata(&mut self, metadata: &mut [u8], packet_base: u64) -> Result<u64, EbpfError> {
        let index = self.prepare_metadata(metadata, packet_base)?;
        self.run_with_packet(metadata, LegacyPacketBacking::Owned(index))
    }

    /// Execute with a zero-filled fixed metadata buffer of the verified size.
    pub fn run_fixed_metadata(&mut self, packet_base: u64) -> Result<u64, EbpfError> {
        let layout = self.metadata_layout.ok_or_else(|| EbpfError { pc: 0, msg:
            "metadata execution requires successful metadata-layout verification".into() })?;
        self.run_metadata(&mut vec![0u8; layout.required_len()], packet_base)
    }

    /// JIT counterpart of [`Vm::run_metadata`].
    #[cfg(feature = "jit")]
    pub fn run_metadata_jit(
        &mut self,
        metadata: &mut [u8],
        packet_base: u64,
    ) -> Result<u64, EbpfError> {
        let index = self.prepare_metadata(metadata, packet_base)?;
        self.run_jit_with_packet(metadata, LegacyPacketBacking::Owned(index))
    }

    /// JIT counterpart of [`Vm::run_fixed_metadata`].
    #[cfg(feature = "jit")]
    pub fn run_fixed_metadata_jit(&mut self, packet_base: u64) -> Result<u64, EbpfError> {
        let layout = self.metadata_layout.ok_or_else(|| EbpfError { pc: 0, msg:
            "metadata execution requires successful metadata-layout verification".into() })?;
        self.run_metadata_jit(&mut vec![0u8; layout.required_len()], packet_base)
    }

    /// Execute an XDP program over `packet`. The method constructs the
    /// virtual `xdp_md` context internally and copies packet writes back to
    /// the caller on both successful exit and runtime error.
    pub fn run_xdp(&mut self, packet: &mut [u8]) -> Result<u64, EbpfError> {
        let mut ctx = self.prepare_xdp(packet).map_err(|msg| EbpfError { pc: 0, msg })?;
        let result = self.run_with_packet(&mut ctx, LegacyPacketBacking::VmPacket);
        packet.copy_from_slice(&self.packet);
        result
    }

    /// JIT counterpart of [`Vm::run_xdp`].
    #[cfg(feature = "jit")]
    pub fn run_xdp_jit(&mut self, packet: &mut [u8]) -> Result<u64, EbpfError> {
        let mut ctx = self.prepare_xdp(packet).map_err(|msg| EbpfError { pc: 0, msg })?;
        let result = self.run_jit_with_packet(&mut ctx, LegacyPacketBacking::VmPacket);
        packet.copy_from_slice(&self.packet);
        result
    }

    /// Execute an skb-context program over VM-owned packet bytes. The method
    /// constructs a zero-filled `struct __sk_buff` record with `len` set to
    /// the packet length; no host skb or packet pointer is exposed.
    pub fn run_skb(&mut self, packet: &mut [u8]) -> Result<u64, EbpfError> {
        let mut ctx = self.prepare_skb(packet).map_err(|msg| EbpfError { pc: 0, msg })?;
        let result = self.run_with_packet(&mut ctx, LegacyPacketBacking::VmPacket);
        packet.copy_from_slice(&self.packet);
        result
    }

    /// JIT counterpart of [`Vm::run_skb`].
    #[cfg(feature = "jit")]
    pub fn run_skb_jit(&mut self, packet: &mut [u8]) -> Result<u64, EbpfError> {
        let mut ctx = self.prepare_skb(packet).map_err(|msg| EbpfError { pc: 0, msg })?;
        let result = self.run_jit_with_packet(&mut ctx, LegacyPacketBacking::VmPacket);
        packet.copy_from_slice(&self.packet);
        result
    }

    /// Install packet bytes and return febpf's synthetic `struct __sk_buff`.
    pub fn prepare_skb(&mut self, packet: &[u8]) -> Result<Vec<u8>, String> {
        if !self.skb {
            return Err("skb execution requires successful verification with Config::skb".into());
        }
        if packet.len() > u32::MAX as usize {
            return Err("packet is too large for __sk_buff.len".into());
        }
        self.packet.clear();
        self.packet.extend_from_slice(packet);
        let mut ctx = vec![0u8; 192];
        ctx[0..4].copy_from_slice(&(packet.len() as u32).to_le_bytes());
        // For Ethernet packet input, synthesize skb->protocol from the outer
        // EtherType exactly as the little-endian eBPF host observes __be16.
        if packet.len() >= 14 {
            let protocol = u16::from_le_bytes([packet[12], packet[13]]) as u32;
            ctx[16..20].copy_from_slice(&protocol.to_le_bytes());
        }
        Ok(ctx)
    }

    /// Install packet bytes and return the synthetic `xdp_md` context used by
    /// [`Vm::machine`]. This is the debugger/replay counterpart of
    /// [`Vm::run_xdp`]. The VM must first verify under XDP rules.
    pub fn prepare_xdp(&mut self, packet: &[u8]) -> Result<Vec<u8>, String> {
        if !self.xdp {
            return Err("XDP execution requires successful verification with Config::xdp".into());
        }
        if packet.len() > u32::MAX as usize {
            return Err("packet is too large for xdp_md data/data_end".into());
        }
        self.packet.clear();
        self.packet.extend_from_slice(packet);
        Ok(vec![0u8; 24])
    }

    /// Create a single-stepping execution (for the debugger).
    pub fn machine<'a>(&'a mut self, ctx: &'a mut [u8]) -> Machine<'a> {
        Machine::new(self, ctx)
    }

    /// Create a single-stepping execution whose context is also the legacy
    /// packet input. This is the debugger/replay counterpart of
    /// [`Vm::run_raw`].
    pub fn machine_raw<'a>(
        &'a mut self,
        buffer: &'a mut [u8],
    ) -> Result<Machine<'a>, EbpfError> {
        self.require_packet_backing(LegacyPacketBacking::Context)?;
        Ok(Machine::new_with_packet(
            self,
            buffer,
            LegacyPacketBacking::Context,
        ))
    }

    /// Create a single-stepping XDP execution after [`Vm::prepare_xdp`].
    /// Legacy packet loads read the VM's prepared packet region.
    pub fn machine_prepared_xdp<'a>(
        &'a mut self,
        ctx: &'a mut [u8],
    ) -> Result<Machine<'a>, EbpfError> {
        self.require_packet_backing(LegacyPacketBacking::VmPacket)?;
        Ok(Machine::new_with_packet(
            self,
            ctx,
            LegacyPacketBacking::VmPacket,
        ))
    }

    /// Compile the program to native code (idempotent). Requires a supported
    /// host architecture; see [`crate::jit`].
    #[cfg(feature = "jit")]
    pub fn compile(&mut self) -> Result<(), String> {
        if self.jit.is_none() {
            self.jit = Some(crate::jit::compile(&self.exec)?);
        }
        for target in &mut self.tail_programs {
            if target.jit.is_none() {
                target.jit = Some(crate::jit::compile(&target.exec)?);
            }
        }
        Ok(())
    }

    /// Execute via the JIT, compiling on first use. Falls back with an error
    /// if the host architecture is unsupported.
    #[cfg(feature = "jit")]
    pub fn run_jit(&mut self, ctx: &mut [u8]) -> Result<u64, EbpfError> {
        self.run_jit_with_packet(ctx, LegacyPacketBacking::None)
    }

    /// JIT counterpart of [`Vm::run_raw`].
    #[cfg(feature = "jit")]
    pub fn run_raw_jit(&mut self, buffer: &mut [u8]) -> Result<u64, EbpfError> {
        self.run_jit_with_packet(buffer, LegacyPacketBacking::Context)
    }

    #[cfg(feature = "jit")]
    fn run_jit_with_packet(
        &mut self,
        ctx: &mut [u8],
        packet: LegacyPacketBacking,
    ) -> Result<u64, EbpfError> {
        self.require_packet_backing(packet)?;
        if let Err(e) = self.compile() {
            return Err(EbpfError { pc: 0, msg: e });
        }
        let jit = self.jit.take().unwrap();
        let mut tail_jits: Vec<crate::jit::JitProgram> = self
            .tail_programs
            .iter_mut()
            .map(|p| p.jit.take().unwrap())
            .collect();
        let mut m = Machine::new_with_packet(self, ctx, packet);
        let r = loop {
            let native = if m.active_program == 0 {
                &jit
            } else {
                &tail_jits[m.active_program as usize - 1]
            };
            // Safety: same contract as Machine::run_native. A successful tail
            // call returns through STOP and the loop enters the target JIT.
            unsafe { native.enter(&mut m) };
            if let Some(e) = m.jit_fault.take() {
                break Err(e);
            }
            if m.jit_switch_pending {
                m.jit_switch_pending = false;
                continue;
            }
            break Ok(m.regs[0]);
        };
        drop(m);
        self.jit = Some(jit);
        for (target, native) in self.tail_programs.iter_mut().zip(tail_jits.drain(..)) {
            target.jit = Some(native);
        }
        r
    }

    fn require_packet_backing(&self, packet: LegacyPacketBacking) -> Result<(), EbpfError> {
        if self.legacy_packet_used && packet == LegacyPacketBacking::None {
            Err(EbpfError {
                pc: 0,
                msg: "legacy packet input unavailable for this execution adapter".into(),
            })
        } else {
            Ok(())
        }
    }
}

fn is_legacy_packet_load(ins: &Insn) -> bool {
    ins.class() == class::LD && matches!(ins.mem_mode(), mode::ABS | mode::IND)
}

#[derive(Clone, Debug, PartialEq)]
struct SavedFrame {
    ret_pc: usize,
    regs6_9: [u64; 4],
}

/// A point-in-time copy of *everything* an execution reads or writes: machine
/// core, per-frame stacks, context, maps, the region table, prandom state and
/// the printk log. Restoring one and re-stepping replays execution exactly
/// (assuming deterministic helpers — see [`Machine::nondet_calls`]), which is
/// what powers the debugger's time travel.
///
/// A snapshot is only meaningful for the machine it was taken from (same
/// program, same context buffer length).
#[derive(Clone, Debug, PartialEq)]
pub struct Snapshot {
    regs: [u64; NUM_REGS],
    pc: usize,
    insn_count: u64,
    frames: Vec<SavedFrame>,
    stack: Vec<u8>,
    ctx: Vec<u8>,
    packet: Vec<u8>,
    /// Region table: map-value regions are created lazily in execution order,
    /// so replay must resume handle allocation from the snapshotted state or
    /// guest-visible virtual addresses would diverge from the original run.
    regions: Vec<Region>,
    owned_regions: Vec<OwnedRegion>,
    maps: Vec<MapSnapshot>,
    prandom: u64,
    printk: Vec<String>,
    seq_output: Vec<u8>,
    profile: Option<Vec<u64>>,
    nondet_calls: u64,
    logical_boot_ns: u64,
    active_program: u32,
    tail_call_count: u32,
}

impl Snapshot {
    /// Instruction count at which this snapshot was taken.
    pub fn insn_count(&self) -> u64 {
        self.insn_count
    }
}

/// Per-instance execution state for the race explorer (`src/race.rs`):
/// everything that is private to one logical invocation of a program —
/// registers, program counter, call frames, counters, and its own stack and
/// context images. The shared map state, region table and prandom stream live
/// in the [`Vm`] and are deliberately *not* part of this. Only one instance is
/// active in a [`Machine`] at a time; the scheduler swaps these in and out with
/// [`Machine::activate`]/[`Machine::deactivate`].
#[derive(Clone, Debug, PartialEq)]
pub struct InstanceState {
    regs: [u64; NUM_REGS],
    pc: usize,
    frames: Vec<SavedFrame>,
    insn_count: u64,
    nondet_calls: u64,
    logical_boot_ns: u64,
    stack: Vec<u8>,
    ctx: Vec<u8>,
    active_program: u32,
    tail_call_count: u32,
}

impl InstanceState {
    /// A fresh instance positioned at pc 0, with `ctx` as its private context
    /// image and a zeroed stack — mirrors the register setup in
    /// [`Machine::new`].
    pub fn new(ctx: &[u8]) -> InstanceState {
        let mut regs = [0u64; NUM_REGS];
        regs[1] = mkaddr(CTX_HANDLE, 0);
        regs[2] = ctx.len() as u64;
        regs[REG_FP as usize] = mkaddr(STACK0_HANDLE, STACK_SIZE as u32);
        InstanceState {
            regs,
            pc: 0,
            frames: Vec::new(),
            insn_count: 0,
            nondet_calls: 0,
            logical_boot_ns: 0,
            stack: vec![0u8; MAX_CALL_FRAMES * STACK_SIZE],
            ctx: ctx.to_vec(),
            active_program: 0,
            tail_call_count: 0,
        }
    }

    /// Number of instructions this instance has retired so far.
    pub fn insn_count(&self) -> u64 {
        self.insn_count
    }

    /// The instance's current `r0`.
    pub fn r0(&self) -> u64 {
        self.regs[0]
    }
}

/// What kind of map-visible operation an instance is poised to perform. Used
/// by the race scheduler as its preemption points (see the spec).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapOpKind {
    Lookup,
    Update,
    Delete,
    /// Plain load through a pointer into a map value.
    ValueLoad,
    /// Plain store through a pointer into a map value.
    ValueStore,
    /// Atomic RMW (`lock += `, `atomic_fetch_*`, `xchg`, `cmpxchg`) on a value.
    Atomic,
}

impl MapOpKind {
    pub fn as_str(self) -> &'static str {
        match self {
            MapOpKind::Lookup => "lookup",
            MapOpKind::Update => "update",
            MapOpKind::Delete => "delete",
            MapOpKind::ValueLoad => "load",
            MapOpKind::ValueStore => "store",
            MapOpKind::Atomic => "atomic",
        }
    }
}

/// A pending (not-yet-executed) map-visible operation, as classified at the
/// instance's current pc.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapOp {
    pub kind: MapOpKind,
    pub pc: usize,
    /// Map index, when statically known (helper calls, resolvable pointers).
    pub map: Option<usize>,
    /// Key bytes, for helper calls (`lookup`/`update`/`delete`).
    pub key: Option<Vec<u8>>,
    /// Region handle of the map value touched by a value load/store/atomic.
    pub region: Option<u32>,
}

/// Result of running an instance forward to its next scheduling point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MapStep {
    /// The instance is now poised on a map-visible op (not yet executed).
    Pending(MapOp),
    /// The instance's program exited with this `r0`.
    Exited(u64),
}

/// One in-flight execution of a [`Vm`] program. Use [`Machine::step`] to
/// single-step (the debugger does), or [`Vm::run`] to run to completion.
pub struct Machine<'a> {
    vm: &'a mut Vm,
    ctx: &'a mut [u8],
    pub regs: [u64; NUM_REGS],
    pub pc: usize,
    frames: Vec<SavedFrame>,
    pub insn_count: u64,
    /// Calls made so far to helpers whose results replay cannot reproduce
    /// (`ktime_get_ns`, user-registered helpers). The debugger warns before
    /// reverse execution when this is nonzero.
    pub nondet_calls: u64,
    /// Deterministic stand-in for CLOCK_BOOTTIME, advanced by helper #125.
    logical_boot_ns: u64,
    /// Set by the JIT trampoline when a deferred instruction faults.
    #[cfg(feature = "jit")]
    jit_fault: Option<EbpfError>,
    #[cfg(feature = "jit")]
    jit_switch_pending: bool,
    active_program: u32,
    tail_call_count: u32,
    legacy_packet_backing: LegacyPacketBacking,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LegacyPacketBacking {
    None,
    Context,
    VmPacket,
    Owned(u32),
}

/// Memory bus for user helpers: bounds-checked access to the VM's regions.
struct Bus<'b> {
    regions: &'b [Region],
    maps: &'b mut [Map],
    stack: &'b mut [u8],
    ctx: &'b mut [u8],
    kmem: &'b mut Vec<u8>,
    packet: &'b mut [u8],
    owned_regions: &'b mut [OwnedRegion],
}

#[allow(clippy::too_many_arguments)]
fn resolve_slice<'s>(
    regions: &[Region],
    maps: &'s mut [Map],
    stack: &'s mut [u8],
    ctx: &'s mut [u8],
    kmem: &'s mut Vec<u8>,
    packet: &'s mut [u8],
    owned_regions: &'s mut [OwnedRegion],
    addr: u64,
    len: usize,
    write: bool,
) -> Result<&'s mut [u8], String> {
    let handle = (addr >> 32) as usize;
    let off = addr as u32 as usize;
    let region = regions
        .get(handle)
        .copied()
        .ok_or_else(|| format!("bad pointer {addr:#x} (no such region)"))?;
    let buf: &mut [u8] = match region {
        Region::Invalid => return Err(format!("dereference of invalid pointer {addr:#x}")),
        Region::KernelMem => {
            // Deterministic stand-in for kernel memory: any offset reads as
            // zero, all writes fault. The scratch buffer is re-zeroed on each
            // resolve so it is indistinguishable from a true zero region.
            if write {
                return Err(format!("write to kernel memory {addr:#x} is not allowed"));
            }
            if kmem.len() < len {
                kmem.resize(len, 0);
            }
            kmem[..len].fill(0);
            return Ok(&mut kmem[..len]);
        }
        Region::Packet => packet,
        Region::Owned(index) => {
            let owned = owned_regions
                .get_mut(index as usize)
                .ok_or_else(|| format!("bad owned-region pointer {addr:#x}"))?;
            if write && owned.access == RegionAccess::ReadOnly {
                return Err(format!("write to read-only owned region {addr:#x}"));
            }
            &mut owned.bytes
        }
        Region::Ctx => ctx,
        Region::Stack(f) => &mut stack[f as usize * STACK_SIZE..(f as usize + 1) * STACK_SIZE],
        Region::MapObj(_) => {
            return Err(format!("map object pointer {addr:#x} is not dereferenceable"))
        }
        Region::MapValue { map, vref } => {
            let m = &mut maps[map as usize];
            if write && m.def.readonly {
                return Err(format!(
                    "write to read-only map '{}' ({addr:#x})",
                    m.def.name
                ));
            }
            m.value_mut(vref)
        }
        Region::RingReserved { map, res } => maps[map as usize]
            .ringbuf_reservation_mut(res)
            .ok_or_else(|| {
                format!("ringbuf record {addr:#x} was already submitted/discarded")
            })?,
    };
    buf.get_mut(off..off + len)
        .ok_or_else(|| format!("access out of bounds: {addr:#x} len {len}"))
}

impl MemBus for Bus<'_> {
    fn read(&mut self, addr: u64, buf: &mut [u8]) -> Result<(), String> {
        let s = resolve_slice(
            self.regions, self.maps, self.stack, self.ctx, self.kmem, self.packet,
            self.owned_regions, addr, buf.len(), false,
        )?;
        buf.copy_from_slice(s);
        Ok(())
    }
    fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), String> {
        let s = resolve_slice(
            self.regions, self.maps, self.stack, self.ctx, self.kmem, self.packet,
            self.owned_regions, addr, data.len(), true,
        )?;
        s.copy_from_slice(data);
        Ok(())
    }
}

impl<'a> Machine<'a> {
    fn current_exec(&self) -> &[Insn] {
        if self.active_program == 0 {
            &self.vm.exec
        } else {
            &self.vm.tail_programs[self.active_program as usize - 1].exec
        }
    }

    fn current_probe_mem(&self) -> &[bool] {
        if self.active_program == 0 {
            &self.vm.probe_mem
        } else {
            &self.vm.tail_programs[self.active_program as usize - 1].probe_mem
        }
    }

    fn new(vm: &'a mut Vm, ctx: &'a mut [u8]) -> Machine<'a> {
        Self::new_with_packet(vm, ctx, LegacyPacketBacking::None)
    }

    fn new_with_packet(
        vm: &'a mut Vm,
        ctx: &'a mut [u8],
        legacy_packet_backing: LegacyPacketBacking,
    ) -> Machine<'a> {
        vm.stack.iter_mut().for_each(|b| *b = 0);
        // BTF-typed programs: the ctx is an array of 8-byte arguments, and
        // non-null pointer arguments must hold kernel-memory addresses.
        // Prefill each such pointer slot with a distinct deterministic address in the
        // reads-as-zero kernel region (1 MiB apart so distinct arguments
        // compare unequal, like real kernel pointers would).
        if let Some(bc) = &vm.btf_ctx {
            for (i, slot) in bc.args.iter().enumerate() {
                if matches!(slot, crate::btf::CtxSlot::Ptr { .. }) {
                    if let Some(b) = ctx.get_mut(i * 8..i * 8 + 8) {
                        let addr = mkaddr(KMEM_HANDLE, (i as u32 + 1) << 20);
                        b.copy_from_slice(&addr.to_le_bytes());
                    }
                }
            }
        }
        let mut regs = [0u64; NUM_REGS];
        regs[1] = mkaddr(CTX_HANDLE, 0);
        regs[2] = ctx.len() as u64;
        regs[REG_FP as usize] = mkaddr(STACK0_HANDLE, STACK_SIZE as u32);
        Machine {
            vm,
            ctx,
            regs,
            pc: 0,
            frames: Vec::new(),
            insn_count: 0,
            nondet_calls: 0,
            logical_boot_ns: 0,
            #[cfg(feature = "jit")]
            jit_fault: None,
            #[cfg(feature = "jit")]
            jit_switch_pending: false,
            active_program: 0,
            tail_call_count: 0,
            legacy_packet_backing,
        }
    }

    /// Capture the full execution state (see [`Snapshot`]).
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            regs: self.regs,
            pc: self.pc,
            insn_count: self.insn_count,
            frames: self.frames.clone(),
            stack: self.vm.stack.clone(),
            ctx: self.ctx.to_vec(),
            packet: self.vm.packet.clone(),
            regions: self.vm.regions.clone(),
            owned_regions: self.vm.owned_regions.clone(),
            maps: self.vm.maps.iter().map(Map::snapshot).collect(),
            prandom: self.vm.prandom,
            printk: self.vm.printk.clone(),
            seq_output: self.vm.seq_output.clone(),
            profile: self.vm.profile.clone(),
            nondet_calls: self.nondet_calls,
            logical_boot_ns: self.logical_boot_ns,
            active_program: self.active_program,
            tail_call_count: self.tail_call_count,
        }
    }

    /// Restore a snapshot previously taken from *this* machine.
    pub fn restore(&mut self, s: &Snapshot) {
        self.regs = s.regs;
        self.pc = s.pc;
        self.insn_count = s.insn_count;
        self.frames = s.frames.clone();
        self.vm.stack.copy_from_slice(&s.stack);
        self.ctx.copy_from_slice(&s.ctx);
        self.vm.packet.clone_from(&s.packet);
        self.vm.regions = s.regions.clone();
        self.vm.owned_regions.clone_from(&s.owned_regions);
        for (m, ms) in self.vm.maps.iter_mut().zip(&s.maps) {
            m.restore(ms);
        }
        self.vm.prandom = s.prandom;
        self.vm.printk = s.printk.clone();
        self.vm.seq_output = s.seq_output.clone();
        self.vm.profile = s.profile.clone();
        self.nondet_calls = s.nondet_calls;
        self.logical_boot_ns = s.logical_boot_ns;
        self.active_program = s.active_program;
        self.tail_call_count = s.tail_call_count;
        #[cfg(feature = "jit")]
        {
            self.jit_fault = None;
            self.jit_switch_pending = false;
        }
    }

    /// Step until `insn_count` reaches `target` (used to replay after a
    /// [`Machine::restore`]). Returns `Some(r0)` if the program exits first.
    pub fn run_to_count(&mut self, target: u64) -> Result<Option<u64>, EbpfError> {
        while self.insn_count < target {
            if let Some(r0) = self.step()? {
                return Ok(Some(r0));
            }
        }
        Ok(None)
    }

    // -- race explorer hooks (src/race.rs) ----------------------------------

    /// Load per-instance state into this machine, making `st`'s
    /// registers/pc/frames/stack/ctx the live execution context. Shared map
    /// state and the region table are left untouched. Assumes `st` was created
    /// for this machine's program and context length.
    pub fn activate(&mut self, st: &InstanceState) {
        self.regs = st.regs;
        self.pc = st.pc;
        self.frames.clone_from(&st.frames);
        self.insn_count = st.insn_count;
        self.nondet_calls = st.nondet_calls;
        self.logical_boot_ns = st.logical_boot_ns;
        self.active_program = st.active_program;
        self.tail_call_count = st.tail_call_count;
        self.vm.stack.copy_from_slice(&st.stack);
        self.ctx.copy_from_slice(&st.ctx);
    }

    /// Save the live per-instance state back into `st` (inverse of
    /// [`Machine::activate`]).
    pub fn deactivate(&self, st: &mut InstanceState) {
        st.regs = self.regs;
        st.pc = self.pc;
        st.frames.clone_from(&self.frames);
        st.insn_count = self.insn_count;
        st.nondet_calls = self.nondet_calls;
        st.logical_boot_ns = self.logical_boot_ns;
        st.active_program = self.active_program;
        st.tail_call_count = self.tail_call_count;
        st.stack.copy_from_slice(&self.vm.stack);
        st.ctx.copy_from_slice(self.ctx);
    }

    /// Classify the instruction at the current pc as a map-visible operation,
    /// if it is one. Pure inspection — does not execute. Returns `None` for
    /// instance-local instructions (ALU, branches, stack/ctx memory, non-map
    /// helpers, exit).
    pub fn classify_mapop(&self) -> Option<MapOp> {
        let ins = *self.current_exec().get(self.pc)?;
        match ins.class() {
            class::JMP | class::JMP32
                if ins.op() == jmp::CALL && ins.src == call_kind::HELPER =>
            {
                let kind = match ins.imm as u32 {
                    helpers::id::MAP_LOOKUP_ELEM => MapOpKind::Lookup,
                    helpers::id::MAP_UPDATE_ELEM => MapOpKind::Update,
                    helpers::id::MAP_DELETE_ELEM => MapOpKind::Delete,
                    _ => return None,
                };
                let map = self.map_from_ptr(self.regs[1]).ok();
                let key = map.and_then(|m| {
                    let ks = self.vm.maps[m].def.key_size as usize;
                    self.peek_bytes(self.regs[2], ks)
                });
                Some(MapOp { kind, pc: self.pc, map, key, region: None })
            }
            class::LDX => {
                if ins.src as usize >= NUM_REGS {
                    return None;
                }
                let addr = self.regs[ins.src as usize].wrapping_add(ins.off as i64 as u64);
                self.map_value_region(addr).map(|region| MapOp {
                    kind: MapOpKind::ValueLoad,
                    pc: self.pc,
                    map: None,
                    key: None,
                    region: Some(region),
                })
            }
            class::ST | class::STX => {
                if ins.dst as usize >= NUM_REGS {
                    return None;
                }
                let addr = self.regs[ins.dst as usize].wrapping_add(ins.off as i64 as u64);
                let region = self.map_value_region(addr)?;
                let kind = if ins.mem_mode() == mode::ATOMIC {
                    MapOpKind::Atomic
                } else {
                    MapOpKind::ValueStore
                };
                Some(MapOp {
                    kind,
                    pc: self.pc,
                    map: None,
                    key: None,
                    region: Some(region),
                })
            }
            _ => None,
        }
    }

    /// Run instance-local instructions from the current pc until the next
    /// instruction is a map-visible op (returned `Pending`, not executed) or
    /// the program exits (`Exited`).
    pub fn run_to_mapop(&mut self) -> Result<MapStep, EbpfError> {
        loop {
            if let Some(op) = self.classify_mapop() {
                return Ok(MapStep::Pending(op));
            }
            if let Some(r0) = self.step()? {
                return Ok(MapStep::Exited(r0));
            }
        }
    }

    /// Region handle if `addr` points into a map value, else `None`.
    fn map_value_region(&self, addr: u64) -> Option<u32> {
        let handle = (addr >> 32) as usize;
        match self.vm.regions.get(handle) {
            Some(Region::MapValue { .. }) => Some(handle as u32),
            _ => None,
        }
    }

    /// Immutable bounded read of guest memory (for classification/reporting).
    fn peek_bytes(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let handle = (addr >> 32) as usize;
        let off = addr as u32 as usize;
        let buf: &[u8] = match self.vm.regions.get(handle).copied()? {
            Region::Ctx => self.ctx,
            Region::Stack(f) => {
                &self.vm.stack[f as usize * STACK_SIZE..(f as usize + 1) * STACK_SIZE]
            }
            Region::MapValue { map, vref } => self.vm.maps[map as usize].value(vref),
            Region::Owned(index) => &self.vm.owned_regions[index as usize].bytes,
            _ => return None,
        };
        buf.get(off..off + len).map(|s| s.to_vec())
    }

    /// The `(map index, key bytes)` cell a map-value region handle refers to
    /// (for hazard attribution). `None` if the handle isn't a live map value.
    pub fn cell_of_region(&self, handle: u32) -> Option<(usize, Vec<u8>)> {
        match self.vm.regions.get(handle as usize).copied()? {
            Region::MapValue { map, vref } => {
                let key = match vref {
                    ValueRef::ArrayElem(i) => i.to_ne_bytes().to_vec(),
                    ValueRef::Slab(i) => self.vm.maps[map as usize].key_for_slab(i)?,
                };
                Some((map as usize, key))
            }
            _ => None,
        }
    }

    /// Toggle printk echoing (the debugger suppresses it during replay so
    /// reverse execution doesn't repeat output). Returns the previous value.
    pub fn set_echo_printk(&mut self, on: bool) -> bool {
        core::mem::replace(&mut self.vm.echo_printk, on)
    }

    /// A pointer to the register file, for the JIT prologue to load from and
    /// spill to. Stable for the machine's lifetime.
    #[cfg(feature = "jit")]
    pub fn regs_ptr(&mut self) -> *mut u64 {
        self.regs.as_mut_ptr()
    }

    /// Trampoline target: execute exactly the (non-native) instruction at
    /// `pc`, then report where the JIT should resume. Returns
    /// [`crate::jit::abi::STOP`]-tagged value on program exit or fault
    /// (distinguish via [`Machine::take_jit_fault`]); otherwise the next pc.
    #[cfg(feature = "jit")]
    pub fn jit_step_at(&mut self, pc: usize) -> u64 {
        self.pc = pc;
        let before = self.active_program;
        match self.step() {
            Ok(Some(_r0)) => crate::jit::abi::STOP, // program finished; r0 in regs[0]
            Ok(None) if self.active_program != before => {
                self.jit_switch_pending = true;
                crate::jit::abi::STOP
            }
            Ok(None) => self.pc as u64,
            Err(e) => {
                self.jit_fault = Some(e);
                crate::jit::abi::STOP
            }
        }
    }

    #[cfg(feature = "jit")]
    pub fn take_jit_fault(&mut self) -> Option<EbpfError> {
        self.jit_fault.take()
    }

    pub fn current_frame(&self) -> usize {
        self.frames.len()
    }

    /// Instruction indices of the current call stack, innermost first: the
    /// current pc followed by each caller's call site (`ret_pc - 1`). Used to
    /// build a source-level backtrace.
    pub fn backtrace_pcs(&self) -> Vec<usize> {
        let mut pcs = vec![self.pc];
        for f in self.frames.iter().rev() {
            pcs.push(f.ret_pc.saturating_sub(1));
        }
        pcs
    }

    /// Shared access to the underlying VM (for inspection tools).
    pub fn vm_ref(&self) -> &Vm {
        self.vm
    }

    pub fn active_program(&self) -> u32 {
        self.active_program
    }

    pub fn current_insns(&self) -> &[Insn] {
        if self.active_program == 0 {
            &self.vm.insns
        } else {
            &self.vm.tail_programs[self.active_program as usize - 1].insns
        }
    }

    /// Human-readable description of a virtual address' region, for the
    /// dataflow queries (`origin`/`who`/`whenwrite`). Resolves the handle
    /// through the (private) region table: `ctx`, `stack frame N` (with the
    /// live frame's fp-relative offset), `map '<name>' value`, `map object`,
    /// or an out-of-range note. `addr = handle << 32 | offset`.
    pub fn describe_addr(&self, addr: u64) -> String {
        let handle = (addr >> 32) as usize;
        let off = addr as u32;
        match self.vm.regions.get(handle) {
            Some(Region::Ctx) => format!("ctx+{off}"),
            Some(Region::Stack(f)) => {
                // For the currently-live frame, present the fp-relative slot
                // (fp points at the top of the 512-byte stack region).
                let live = STACK0_HANDLE + self.frames.len() as u32 == handle as u32;
                if live {
                    let rel = off as i64 - STACK_SIZE as i64;
                    format!("stack frame {f} (fp{rel:+})")
                } else {
                    format!("stack frame {f} +{off}")
                }
            }
            Some(Region::MapObj(m)) => {
                format!("map '{}' object", self.vm.maps[*m as usize].def.name)
            }
            Some(Region::MapValue { map, .. }) => {
                format!("map '{}' value +{off}", self.vm.maps[*map as usize].def.name)
            }
            Some(Region::RingReserved { map, .. }) => {
                format!("ringbuf '{}' record +{off}", self.vm.maps[*map as usize].def.name)
            }
            Some(Region::KernelMem) => format!("kernel memory +{off} (reads as zero)"),
            Some(Region::Packet) => format!("packet+{off}"),
            Some(Region::Owned(index)) => format!("owned region {index}+{off}"),
            Some(Region::Invalid) | None => format!("<addr {addr:#x}>"),
        }
    }

    fn err(&self, msg: impl Into<String>) -> EbpfError {
        EbpfError {
            pc: self.pc,
            msg: msg.into(),
        }
    }

    #[inline]
    fn mem(&mut self, addr: u64, len: usize, write: bool) -> Result<&mut [u8], EbpfError> {
        let pc = self.pc;
        resolve_slice(
            &self.vm.regions,
            &mut self.vm.maps,
            &mut self.vm.stack,
            self.ctx,
            &mut self.vm.kmem,
            &mut self.vm.packet,
            &mut self.vm.owned_regions,
            addr,
            len,
            write,
        )
        .map_err(|msg| EbpfError { pc, msg })
    }

    /// Read memory for the debugger (no mutation).
    pub fn read_mem(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, EbpfError> {
        Ok(self.mem(addr, len, false)?.to_vec())
    }

    #[inline]
    fn load(&mut self, addr: u64, size: usize) -> Result<u64, EbpfError> {
        let s = self.mem(addr, size, false)?;
        Ok(match size {
            1 => s[0] as u64,
            2 => u16::from_le_bytes([s[0], s[1]]) as u64,
            4 => u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as u64,
            _ => u64::from_le_bytes(s.try_into().unwrap()),
        })
    }

    #[inline]
    fn store(&mut self, addr: u64, size: usize, v: u64) -> Result<(), EbpfError> {
        let s = self.mem(addr, size, true)?;
        match size {
            1 => s[0] = v as u8,
            2 => s.copy_from_slice(&(v as u16).to_le_bytes()),
            4 => s.copy_from_slice(&(v as u32).to_le_bytes()),
            _ => s.copy_from_slice(&v.to_le_bytes()),
        }
        Ok(())
    }

    /// Execute one instruction. Returns `Some(r0)` when the program exits.
    #[inline(always)]
    pub fn step(&mut self) -> Result<Option<u64>, EbpfError> {
        self.insn_count += 1;
        if self.insn_count > self.vm.insn_limit {
            return Err(self.err(format!(
                "instruction limit {} exceeded",
                self.vm.insn_limit
            )));
        }
        let ins = *self
            .current_exec()
            .get(self.pc)
            .ok_or_else(|| self.err("program counter out of bounds"))?;
        if self.active_program == 0 {
            if let Some(prof) = &mut self.vm.profile {
            prof[self.pc] += 1;
            }
        }
        let dst = ins.dst as usize;
        let src = ins.src as usize;
        if dst >= NUM_REGS || (src >= NUM_REGS && ins.class() != class::LD) {
            return Err(self.err("invalid register"));
        }

        match ins.class() {
            class::ALU64 | class::ALU => {
                let is32 = ins.class() == class::ALU;
                let b = if ins.is_src_reg() {
                    self.regs[src]
                } else {
                    ins.imm as i64 as u64
                };
                let a = self.regs[dst];
                let r = if is32 {
                    let a = a as u32;
                    let b = b as u32;
                    (match ins.op() {
                        alu::ADD => a.wrapping_add(b),
                        alu::SUB => a.wrapping_sub(b),
                        alu::MUL => a.wrapping_mul(b),
                        alu::DIV => {
                            if ins.off == 1 {
                                let (a, b) = (a as i32, b as i32);
                                if b == 0 { 0 } else { a.wrapping_div(b) as u32 }
                            } else if b == 0 {
                                0
                            } else {
                                a / b
                            }
                        }
                        alu::MOD => {
                            if ins.off == 1 {
                                let (a, b) = (a as i32, b as i32);
                                if b == 0 { a as u32 } else { a.wrapping_rem(b) as u32 }
                            } else if b == 0 {
                                a
                            } else {
                                a % b
                            }
                        }
                        alu::OR => a | b,
                        alu::AND => a & b,
                        alu::LSH => a.wrapping_shl(b),
                        alu::RSH => a.wrapping_shr(b),
                        alu::ARSH => ((a as i32).wrapping_shr(b)) as u32,
                        alu::XOR => a ^ b,
                        alu::NEG => (a as i32).wrapping_neg() as u32,
                        alu::MOV => match ins.off {
                            8 => b as u8 as i8 as i32 as u32,
                            16 => b as u16 as i16 as i32 as u32,
                            _ => b,
                        },
                        alu::END => {
                            // 16/32-bit le/be conversions (LE host)
                            let w = ins.imm;
                            if ins.is_src_reg() {
                                // to big-endian: swap
                                match w {
                                    16 => (a as u16).swap_bytes() as u32,
                                    _ => a.swap_bytes(),
                                }
                            } else {
                                match w {
                                    16 => a as u16 as u32,
                                    _ => a,
                                }
                            }
                        }
                        _ => return Err(self.err("bad ALU op")),
                    }) as u64
                } else {
                    match ins.op() {
                        alu::ADD => a.wrapping_add(b),
                        alu::SUB => a.wrapping_sub(b),
                        alu::MUL => a.wrapping_mul(b),
                        alu::DIV => {
                            if ins.off == 1 {
                                let (a, b) = (a as i64, b as i64);
                                if b == 0 { 0 } else { a.wrapping_div(b) as u64 }
                            } else if b == 0 {
                                0
                            } else {
                                a / b
                            }
                        }
                        alu::MOD => {
                            if ins.off == 1 {
                                let (a, b) = (a as i64, b as i64);
                                if b == 0 { a as u64 } else { a.wrapping_rem(b) as u64 }
                            } else if b == 0 {
                                a
                            } else {
                                a % b
                            }
                        }
                        alu::OR => a | b,
                        alu::AND => a & b,
                        alu::LSH => a.wrapping_shl(b as u32),
                        alu::RSH => a.wrapping_shr(b as u32),
                        alu::ARSH => ((a as i64).wrapping_shr(b as u32)) as u64,
                        alu::XOR => a ^ b,
                        alu::NEG => (a as i64).wrapping_neg() as u64,
                        alu::MOV => match ins.off {
                            8 => b as u8 as i8 as i64 as u64,
                            16 => b as u16 as i16 as i64 as u64,
                            32 => b as u32 as i32 as i64 as u64,
                            _ => b,
                        },
                        alu::END => match ins.imm {
                            // unconditional bswap
                            16 => (a as u16).swap_bytes() as u64,
                            32 => (a as u32).swap_bytes() as u64,
                            _ => a.swap_bytes(),
                        },
                        _ => return Err(self.err("bad ALU op")),
                    }
                };
                self.regs[dst] = r;
                self.pc += 1;
            }
            class::LD => {
                if !ins.is_wide() {
                    if !matches!(ins.mem_mode(), mode::ABS | mode::IND)
                        || (ins.mem_size() == 8
                            && self.vm.legacy_packet
                                != crate::verifier::LegacyPacketProfile::Rbpf041)
                    {
                        return Err(self.err("invalid legacy packet-load instruction"));
                    }
                    if self.vm.legacy_packet == crate::verifier::LegacyPacketProfile::Disabled {
                        return Err(self.err("legacy packet profile is disabled"));
                    }
                    let effective = if ins.mem_mode() == mode::IND {
                        i128::from(self.regs[src]) + i128::from(ins.imm)
                    } else {
                        i128::from(ins.imm)
                    };
                    let size = ins.mem_size();
                    let range = u64::try_from(effective)
                        .ok()
                        .and_then(|off| usize::try_from(off).ok())
                        .and_then(|start| start.checked_add(size).map(|end| (start, end)))
                        .and_then(|(start, end)| {
                            let packet: &[u8] = match self.legacy_packet_backing {
                                LegacyPacketBacking::None => return None,
                                LegacyPacketBacking::Context => self.ctx,
                                LegacyPacketBacking::VmPacket => &self.vm.packet,
                                LegacyPacketBacking::Owned(index) => self
                                    .vm
                                    .owned_regions
                                    .get(index as usize)
                                    .map(|region| region.bytes.as_slice())?,
                            };
                            (end <= packet.len()).then_some((start, end, packet))
                        });
                    let Some((start, end, packet)) = range else {
                        return match self.vm.legacy_packet {
                            crate::verifier::LegacyPacketProfile::Linux => {
                                self.regs[0] = 0;
                                for r in 1..=5 {
                                    self.regs[r] = 0;
                                }
                                Ok(Some(0))
                            }
                            crate::verifier::LegacyPacketProfile::Rbpf041 => {
                                Err(self.err("legacy packet access out of bounds"))
                            }
                            crate::verifier::LegacyPacketProfile::Disabled => unreachable!(),
                        };
                    };
                    let bytes = &packet[start..end];
                    self.regs[0] = match size {
                        1 => bytes[0] as u64,
                        2 if self.vm.legacy_packet
                            == crate::verifier::LegacyPacketProfile::Linux =>
                        {
                            u16::from_be_bytes(bytes.try_into().unwrap()) as u64
                        }
                        4 if self.vm.legacy_packet
                            == crate::verifier::LegacyPacketProfile::Linux =>
                        {
                            u32::from_be_bytes(bytes.try_into().unwrap()) as u64
                        }
                        2 => u16::from_le_bytes(bytes.try_into().unwrap()) as u64,
                        4 => u32::from_le_bytes(bytes.try_into().unwrap()) as u64,
                        8 => u64::from_le_bytes(bytes.try_into().unwrap()),
                        _ => unreachable!("legacy load form checked by verifier"),
                    };
                    if self.vm.legacy_packet == crate::verifier::LegacyPacketProfile::Linux {
                        for r in 1..=5 {
                            self.regs[r] = 0;
                        }
                    }
                    self.pc += 1;
                    return Ok(None);
                }
                self.regs[dst] = wide_imm(self.current_exec(), self.pc);
                self.pc += 2;
            }
            class::LDX => {
                let addr = self.regs[src].wrapping_add(ins.off as i64 as u64);
                let size = ins.mem_size();
                // xdp_md stores data/data_end as u32 kernel ABI fields, but
                // febpf virtual addresses are 64-bit region handles. Once the
                // verifier has typed this as XDP, synthesize those full
                // addresses at the load boundary.
                let packet_ptr = if size == 4 && addr >> 32 == CTX_HANDLE as u64 {
                    match (self.vm.xdp, self.vm.skb, addr as u32) {
                        (true, _, 0) | (_, true, 76) => Some(mkaddr(PACKET_HANDLE, 0)),
                        (true, _, 4) | (_, true, 80) => {
                            Some(mkaddr(PACKET_HANDLE, self.vm.packet.len() as u32))
                        }
                        _ => None,
                    }
                } else {
                    None
                };
                // Loads the verifier marked as BTF probe reads mirror the
                // kernel's BPF_PROBE_MEM: an unresolvable address reads as
                // zero instead of faulting (e.g. chasing a pointer loaded
                // from zeroed kernel memory, i.e. NULL).
                let v = if let Some(ptr) = packet_ptr {
                    ptr
                } else {
                    match self.load(addr, size) {
                        Err(_) if self.current_probe_mem().get(self.pc) == Some(&true) => 0,
                        r => r?,
                    }
                };
                self.regs[dst] = if ins.mem_mode() == mode::MEMSX {
                    match size {
                        1 => v as u8 as i8 as i64 as u64,
                        2 => v as u16 as i16 as i64 as u64,
                        _ => v as u32 as i32 as i64 as u64,
                    }
                } else {
                    v
                };
                self.pc += 1;
            }
            class::ST | class::STX => {
                let addr = self.regs[dst].wrapping_add(ins.off as i64 as u64);
                let size = ins.mem_size();
                if ins.mem_mode() == mode::ATOMIC {
                    self.atomic(ins, addr, size)?;
                } else {
                    let v = if ins.class() == class::ST {
                        ins.imm as i64 as u64
                    } else {
                        self.regs[src]
                    };
                    self.store(addr, size, v)?;
                }
                self.pc += 1;
            }
            class::JMP | class::JMP32 => {
                let is32 = ins.class() == class::JMP32;
                match ins.op() {
                    jmp::JA => {
                        let rel = if is32 { ins.imm as i64 } else { ins.off as i64 };
                        self.jump(rel)?;
                    }
                    jmp::EXIT => {
                        if let Some(f) = self.frames.pop() {
                            self.regs[6..10].copy_from_slice(&f.regs6_9);
                            self.regs[REG_FP as usize] =
                                mkaddr(STACK0_HANDLE + self.frames.len() as u32, STACK_SIZE as u32);
                            self.pc = f.ret_pc;
                        } else {
                            return Ok(Some(self.regs[0]));
                        }
                    }
                    jmp::CALL => {
                        if ins.src == call_kind::LOCAL {
                            if self.frames.len() + 1 >= MAX_CALL_FRAMES {
                                return Err(self.err(format!(
                                    "call depth exceeds {MAX_CALL_FRAMES} frames"
                                )));
                            }
                            let mut regs6_9 = [0u64; 4];
                            regs6_9.copy_from_slice(&self.regs[6..10]);
                            self.frames.push(SavedFrame {
                                ret_pc: self.pc + 1,
                                regs6_9,
                            });
                            // Each verifier frame starts with invalid stack
                            // slots. The backing bytes are deterministic
                            // zeroes, so a later callee reusing this depth must
                            // not observe an earlier callee's stale bytes.
                            let depth = self.frames.len();
                            self.vm.stack[depth * STACK_SIZE..(depth + 1) * STACK_SIZE].fill(0);
                            self.regs[REG_FP as usize] =
                                mkaddr(STACK0_HANDLE + self.frames.len() as u32, STACK_SIZE as u32);
                            self.jump(ins.imm as i64)?;
                        } else {
                            if !self.helper_call(ins.imm as u32)? {
                                self.pc += 1;
                            }
                        }
                    }
                    op => {
                        let a = self.regs[dst];
                        let b = if ins.is_src_reg() {
                            self.regs[src]
                        } else {
                            ins.imm as i64 as u64
                        };
                        let taken = if is32 {
                            let (a, b) = (a as u32, b as u32);
                            let (sa, sb) = (a as i32, b as i32);
                            match op {
                                jmp::JEQ => a == b,
                                jmp::JGT => a > b,
                                jmp::JGE => a >= b,
                                jmp::JSET => a & b != 0,
                                jmp::JNE => a != b,
                                jmp::JSGT => sa > sb,
                                jmp::JSGE => sa >= sb,
                                jmp::JLT => a < b,
                                jmp::JLE => a <= b,
                                jmp::JSLT => sa < sb,
                                jmp::JSLE => sa <= sb,
                                _ => return Err(self.err("bad JMP op")),
                            }
                        } else {
                            let (sa, sb) = (a as i64, b as i64);
                            match op {
                                jmp::JEQ => a == b,
                                jmp::JGT => a > b,
                                jmp::JGE => a >= b,
                                jmp::JSET => a & b != 0,
                                jmp::JNE => a != b,
                                jmp::JSGT => sa > sb,
                                jmp::JSGE => sa >= sb,
                                jmp::JLT => a < b,
                                jmp::JLE => a <= b,
                                jmp::JSLT => sa < sb,
                                jmp::JSLE => sa <= sb,
                                _ => return Err(self.err("bad JMP op")),
                            }
                        };
                        if taken {
                            self.jump(ins.off as i64)?;
                        } else {
                            self.pc += 1;
                        }
                    }
                }
            }
            _ => unreachable!(),
        }
        Ok(None)
    }

    #[inline]
    fn jump(&mut self, rel: i64) -> Result<(), EbpfError> {
        let t = self.pc as i64 + 1 + rel;
        if t < 0 || t as usize >= self.current_exec().len() {
            return Err(self.err(format!("jump target {t} out of bounds")));
        }
        self.pc = t as usize;
        Ok(())
    }

    fn atomic(&mut self, ins: Insn, addr: u64, size: usize) -> Result<(), EbpfError> {
        use crate::insn::atomic as a;
        let srcv = self.regs[ins.src as usize];
        let old = self.load(addr, size)?;
        let op = ins.imm & !a::FETCH;
        let (new, fetch_dst): (u64, Option<usize>) = match ins.imm {
            x if x == a::XCHG => (srcv, Some(ins.src as usize)),
            x if x == a::CMPXCHG => {
                let expected = self.regs[0];
                let cmp = if size == 4 {
                    old as u32 == expected as u32
                } else {
                    old == expected
                };
                let new = if cmp { srcv } else { old };
                self.store(addr, size, new)?;
                self.regs[0] = old;
                return Ok(());
            }
            _ => {
                let new = match op {
                    a::ADD => old.wrapping_add(srcv),
                    a::OR => old | srcv,
                    a::AND => old & srcv,
                    a::XOR => old ^ srcv,
                    _ => return Err(self.err(format!("bad atomic op {:#x}", ins.imm))),
                };
                let fetch = if ins.imm & a::FETCH != 0 {
                    Some(ins.src as usize)
                } else {
                    None
                };
                (new, fetch)
            }
        };
        let new = if size == 4 { new as u32 as u64 } else { new };
        self.store(addr, size, new)?;
        if let Some(r) = fetch_dst {
            self.regs[r] = if size == 4 { old as u32 as u64 } else { old };
        }
        Ok(())
    }

    // -- helpers -------------------------------------------------------------

    fn map_from_ptr(&self, addr: u64) -> Result<usize, EbpfError> {
        let handle = (addr >> 32) as usize;
        match self.vm.regions.get(handle) {
            Some(Region::MapObj(m)) => Ok(*m as usize),
            _ => Err(self.err(format!("r1 is not a map pointer ({addr:#x})"))),
        }
    }

    fn read_bytes(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, EbpfError> {
        Ok(self.mem(addr, len, false)?.to_vec())
    }

    /// `bpf_ringbuf_reserve`: mint a fresh writable record region of `size`
    /// bytes, or return NULL (0) if `size` is 0 or exceeds the capacity.
    fn ringbuf_reserve(&mut self, map: usize, size: u32) -> u64 {
        let cap = match self.vm.maps[map].ringbuf_capacity() {
            Some(c) => c,
            None => return 0,
        };
        if size == 0 || size > cap {
            return 0;
        }
        let res = self.vm.maps[map].ringbuf_next_res();
        self.vm.regions.push(Region::RingReserved {
            map: map as u32,
            res,
        });
        let handle = (self.vm.regions.len() - 1) as u32;
        self.vm.maps[map].ringbuf_add_reservation(size, handle);
        mkaddr(handle, 0)
    }

    /// `bpf_ringbuf_submit`/`_discard`: consume the reservation `addr` points to.
    fn ringbuf_consume(&mut self, addr: u64, submit: bool) -> Result<(), EbpfError> {
        let handle = (addr >> 32) as usize;
        match self.vm.regions.get(handle).copied() {
            Some(Region::RingReserved { map, res }) => self.vm.maps[map as usize]
                .ringbuf_consume(res, submit)
                .map_err(|_| self.err("ringbuf record already submitted/discarded")),
            _ => Err(self.err(format!(
                "ringbuf submit/discard: {addr:#x} is not a reserved record"
            ))),
        }
    }

    fn helper_call(&mut self, hid: u32) -> Result<bool, EbpfError> {
        let args = [self.regs[1], self.regs[2], self.regs[3], self.regs[4], self.regs[5]];
        if hid == helpers::id::TAIL_CALL {
            let map = self.map_from_ptr(args[1])?;
            if self.vm.maps[map].def.kind != crate::maps::MapKind::ProgArray
                || self.tail_call_count >= 33
            {
                return Ok(self.tail_call_fallthrough());
            }
            let Some(program) = self.vm.maps[map].program_at(args[2] as u32) else {
                return Ok(self.tail_call_fallthrough());
            };
            if program == 0 || program as usize > self.vm.tail_programs.len() {
                return Ok(self.tail_call_fallthrough());
            }
            self.tail_call_count += 1;
            self.active_program = program;
            self.pc = 0;
            self.frames.clear();
            self.vm.stack.fill(0);
            self.regs.fill(0);
            self.regs[1] = args[0];
            self.regs[REG_FP as usize] = mkaddr(STACK0_HANDLE, STACK_SIZE as u32);
            return Ok(true);
        }
        let r0 = match hid {
            helpers::id::MAP_LOOKUP_ELEM => {
                let m = self.map_from_ptr(args[0])?;
                let key = self.read_bytes(args[1], self.vm.maps[m].def.key_size as usize)?;
                if self.vm.maps[m].def.kind.is_map_of_maps() {
                    let inner = if self.vm.maps[m].def.kind
                        == crate::maps::MapKind::ArrayOfMaps
                    {
                        let index = u32::from_ne_bytes(
                            key.as_slice()
                                .try_into()
                                .map_err(|_| self.err("array_of_maps key is not a u32"))?,
                        );
                        self.vm.maps[m].inner_map_at(index)
                    } else {
                        self.vm.maps[m].inner_map_by_key(&key)
                    };
                    match inner {
                        Some(inner) => {
                            let handle = *self
                                .vm
                                .map_obj_handles
                                .get(inner as usize)
                                .ok_or_else(|| self.err("array_of_maps contains an invalid map"))?;
                            mkaddr(handle, 0)
                        }
                        None => 0,
                    }
                } else {
                    match self.vm.maps[m].lookup(&key) {
                        Some(vref) => {
                            // LRU maps: mark the entry recently used (no-op for others).
                            self.vm.maps[m].touch(&key);
                            self.vm.value_addr(m as u32, vref)
                        }
                        None => 0,
                    }
                }
            }
            helpers::id::MAP_UPDATE_ELEM => {
                let m = self.map_from_ptr(args[0])?;
                let key = self.read_bytes(args[1], self.vm.maps[m].def.key_size as usize)?;
                let val = self.read_bytes(args[2], self.vm.maps[m].def.value_size as usize)?;
                match self.vm.maps[m].update(&key, &val) {
                    Ok(_) => 0,
                    Err(e) => e as u64,
                }
            }
            helpers::id::MAP_DELETE_ELEM => {
                let m = self.map_from_ptr(args[0])?;
                let key = self.read_bytes(args[1], self.vm.maps[m].def.key_size as usize)?;
                match self.vm.maps[m].delete(&key) {
                    Ok(()) => 0,
                    Err(e) => e as u64,
                }
            }
            helpers::id::KTIME_GET_NS => {
                self.nondet_calls += 1; // wall clock: replay cannot reproduce it
                self.vm.start.elapsed_nanos()
            }
            // Deterministic stand-in for Linux CLOCK_BOOTTIME: one logical
            // nanosecond per observation. The counter is part of snapshot and
            // race-instance state, so interpreter/JIT replay is exact.
            helpers::id::KTIME_GET_BOOT_NS => {
                self.logical_boot_ns = self.logical_boot_ns.saturating_add(1);
                self.logical_boot_ns
            }
            helpers::id::SEQ_WRITE => {
                let data = self.read_bytes(args[1], args[2] as usize)?;
                let fits = self
                    .vm
                    .seq_output
                    .len()
                    .checked_add(data.len())
                    .is_some_and(|len| len <= SEQ_OUTPUT_CAPACITY);
                if fits {
                    self.vm.seq_output.extend_from_slice(&data);
                    0
                } else {
                    (-75i64) as u64 // -EOVERFLOW; leave prior output intact
                }
            }
            helpers::id::TRACE_PRINTK => {
                let fmt = self.read_bytes(args[0], args[1] as usize)?;
                let line = self.format_printk(&fmt, &[args[2], args[3], args[4]])?;
                #[cfg(feature = "std")]
                if self.vm.echo_printk {
                    eprintln!("printk: {line}");
                }
                let len = line.len() as u64;
                self.vm.printk.push(line);
                len
            }
            helpers::id::TRACE_VPRINTK => {
                let data_len = args[3] as u32 as usize;
                if !data_len.is_multiple_of(8) || data_len > 12 * 8 {
                    (-22i64) as u64 // -EINVAL
                } else {
                    let fmt = self.read_bytes(args[0], args[1] as usize)?;
                    let data = if data_len == 0 {
                        Vec::new()
                    } else {
                        self.read_bytes(args[2], data_len)?
                    };
                    let values = data
                        .chunks_exact(8)
                        .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
                        .collect::<Vec<_>>();
                    let line = self.format_printk(&fmt, &values)?;
                    #[cfg(feature = "std")]
                    if self.vm.echo_printk {
                        eprintln!("printk: {line}");
                    }
                    let len = line.len() as u64;
                    self.vm.printk.push(line);
                    len
                }
            }
            helpers::id::GET_PRANDOM_U32 => {
                // xorshift64*: deterministic across runs for debuggability
                let mut x = self.vm.prandom;
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                self.vm.prandom = x;
                (x.wrapping_mul(0x2545F4914F6CDD1D) >> 32) as u32 as u64
            }
            helpers::id::GET_SMP_PROCESSOR_ID => 0,
            // Core tracing helpers: febpf has no processes/tasks, so these
            // return fixed, documented constants (docs/specs/map-types-2.md).
            helpers::id::GET_CURRENT_PID_TGID => 0x0000_0001_0000_0001, // tgid=1, pid=1
            helpers::id::GET_CURRENT_UID_GID => 0,                      // uid=gid=0
            helpers::id::GET_CURRENT_TASK => 0xffff_0000_0000_0001, // opaque, non-deref token
            helpers::id::GET_NS_CURRENT_PID_TGID => {
                // No host PID namespace is imported into the standalone VM,
                // so dev/inode cannot match. The kernel zeroes the caller's
                // requested buffer on every failure path.
                self.mem(args[2], args[3] as u32 as usize, true)?.fill(0);
                (-22i64) as u64 // -EINVAL
            }
            // febpf has no sockets: a fixed, nonzero, documented token in the
            // same spirit as get_current_task (docs/specs/tracing-helpers.md).
            helpers::id::GET_SOCKET_COOKIE => 0x0000_0000_c00c_1e01,
            helpers::id::REDIRECT_MAP => {
                let m = self.map_from_ptr(args[0])?;
                let key = (args[1] as u32).to_ne_bytes();
                let populated = self.vm.maps[m]
                    .lookup(&key)
                    .is_some_and(|value| self.vm.maps[m].value(value).iter().any(|&byte| byte != 0));
                if populated {
                    4 // XDP_REDIRECT; standalone execution records only the verdict
                } else {
                    args[2] & 3 // kernel fallback action encoded in flag bits 0..1
                }
            }
            // febpf has no attach point: the "traced function address" is an
            // opaque, nonzero, non-dereferenceable token like get_current_task.
            helpers::id::GET_FUNC_IP => 0xffff_0000_0000_0002,
            helpers::id::XDP_LOAD_BYTES => {
                let start = args[1] as u32 as usize;
                let len = args[3] as u32 as usize;
                if self.legacy_packet_backing != LegacyPacketBacking::VmPacket
                    || start > 0xffff
                    || len > 0xffff
                {
                    (-14i64) as u64 // -EFAULT
                } else {
                    match start.checked_add(len) {
                        Some(end) if end <= self.vm.packet.len() => {
                            let data = self.vm.packet[start..end].to_vec();
                            self.mem(args[2], len, true)?.copy_from_slice(&data);
                            0
                        }
                        _ => (-22i64) as u64, // -EINVAL
                    }
                }
            }
            helpers::id::XDP_STORE_BYTES => {
                let start = args[1] as u32 as usize;
                let len = args[3] as u32 as usize;
                if self.legacy_packet_backing != LegacyPacketBacking::VmPacket
                    || start > 0xffff
                    || len > 0xffff
                {
                    (-14i64) as u64 // -EFAULT
                } else {
                    match start.checked_add(len) {
                        Some(end) if end <= self.vm.packet.len() => {
                            let data = self.read_bytes(args[2], len)?;
                            self.vm.packet[start..end].copy_from_slice(&data);
                            0
                        }
                        _ => (-22i64) as u64, // -EINVAL
                    }
                }
            }
            helpers::id::GET_CURRENT_COMM => {
                let size = args[1] as usize;
                let buf = self.mem(args[0], size, true)?;
                buf.fill(0);
                let comm = b"febpf";
                let n = comm.len().min(size.saturating_sub(1));
                buf[..n].copy_from_slice(&comm[..n]);
                0
            }
            helpers::id::REDIRECT => {
                if self.vm.xdp {
                    if args[1] == 0 { 4 } else { 0 } // XDP_REDIRECT / XDP_ABORTED
                } else if self.vm.skb {
                    if args[1] & !1 == 0 { 7 } else { 2 } // TC_ACT_REDIRECT / SHOT
                } else {
                    0
                }
            }
            helpers::id::SKB_LOAD_BYTES => {
                let start = args[1] as u32 as usize;
                let len = args[3] as u32 as usize;
                match start.checked_add(len) {
                    Some(end)
                        if end <= self.vm.packet.len()
                            && self.legacy_packet_backing == LegacyPacketBacking::VmPacket =>
                    {
                        let data = self.vm.packet[start..end].to_vec();
                        self.mem(args[2], len, true)?.copy_from_slice(&data);
                        0
                    }
                    _ => (-14i64) as u64, // -EFAULT
                }
            }
            helpers::id::SKB_PULL_DATA => {
                let len = args[1] as u32 as usize;
                if self.legacy_packet_backing != LegacyPacketBacking::VmPacket {
                    (-14i64) as u64 // no skb packet backing
                } else if len == 0 || len <= self.vm.packet.len() {
                    0 // the VM-owned packet is already linear and writable
                } else {
                    (-12i64) as u64 // -ENOMEM, matching skb_ensure_writable
                }
            }
            helpers::id::GET_STACKID => {
                // (ctx, map, flags). Deterministic model: the id is the FNV-1a
                // hash of the call stack's instruction indices, masked to 31
                // bits; the stored "stack" is those pcs as LE u64s, padded to
                // value_size. Same call site => same id and stored stack.
                let m = self.map_from_ptr(args[1])?;
                let pcs = self.backtrace_pcs();
                let mut h: u64 = 0xcbf2_9ce4_8422_2325;
                for pc in &pcs {
                    for b in (*pc as u64).to_le_bytes() {
                        h ^= b as u64;
                        h = h.wrapping_mul(0x100_0000_01b3);
                    }
                }
                let id = (h & 0x7fff_ffff) as u32;
                let vsize = self.vm.maps[m].def.value_size as usize;
                let mut val = vec![0u8; vsize];
                for (i, pc) in pcs.iter().enumerate() {
                    let off = i * 8;
                    if off + 8 > vsize {
                        break;
                    }
                    val[off..off + 8].copy_from_slice(&(*pc as u64).to_le_bytes());
                }
                // A full map drops the store but still returns the id (like
                // the kernel, which may drop without BPF_F_REUSE_STACKID).
                let _ = self.vm.maps[m].update(&id.to_le_bytes(), &val);
                id as u64
            }
            helpers::id::GET_STACK => {
                // (ctx, buf, size, flags). Same deterministic stack model as
                // get_stackid, but written into the caller's buffer: the call
                // stack's instruction indices (innermost first) as LE u64s.
                // The buffer is zeroed first so the result is deterministic;
                // returns the number of bytes written (a multiple of 8).
                let size = args[2] as usize;
                let pcs = self.backtrace_pcs();
                let buf = self.mem(args[1], size, true)?;
                buf.fill(0);
                let mut written = 0usize;
                for pc in &pcs {
                    if written + 8 > size {
                        break;
                    }
                    buf[written..written + 8].copy_from_slice(&(*pc as u64).to_le_bytes());
                    written += 8;
                }
                written as u64
            }
            helpers::id::GET_TASK_STACK => {
                // Standalone febpf has one synthetic task. Its stack is the
                // same deterministic sequence of BPF call-site pcs exposed by
                // get_stack: innermost first, whole LE u64 frames only. The
                // exact task pointer was checked against target BTF.
                let size = args[2] as usize;
                let pcs = self.backtrace_pcs();
                let buf = self.mem(args[1], size, true)?;
                buf.fill(0);
                let mut written = 0usize;
                for pc in &pcs {
                    if written + 8 > size {
                        break;
                    }
                    buf[written..written + 8].copy_from_slice(&(*pc as u64).to_le_bytes());
                    written += 8;
                }
                written as u64
            }
            helpers::id::PROBE_READ
            | helpers::id::PROBE_READ_KERNEL
            | helpers::id::PROBE_READ_USER => {
                // (dst, size, unsafe_ptr). The source is an arbitrary address;
                // resolve it through the virtual-address model. Success copies;
                // anything unresolvable zero-fills dst and returns -EFAULT,
                // exactly the kernel's fault behaviour (and deterministic).
                let size = args[1] as usize;
                let src = self.read_bytes(args[2], size);
                let dst = self.mem(args[0], size, true)?;
                match src {
                    Ok(bytes) => {
                        dst.copy_from_slice(&bytes);
                        0
                    }
                    Err(_) => {
                        dst.fill(0);
                        (-14i64) as u64 // -EFAULT
                    }
                }
            }
            helpers::id::PROBE_READ_STR
            | helpers::id::PROBE_READ_KERNEL_STR
            | helpers::id::PROBE_READ_USER_STR => {
                // (dst, size, unsafe_ptr): copy a NUL-terminated string of at
                // most `size` bytes (truncating with a forced NUL, like the
                // kernel) and return the copied length including the NUL. The
                // dst is zeroed first so the result is deterministic; a fault
                // on any source byte zero-fills and returns -EFAULT.
                let size = args[1] as usize;
                let mut copied = Vec::with_capacity(size);
                let mut fault = false;
                for i in 0..size {
                    match self.read_bytes(args[2] + i as u64, 1) {
                        Ok(b) => {
                            copied.push(b[0]);
                            if b[0] == 0 {
                                break;
                            }
                        }
                        Err(_) => {
                            fault = true;
                            break;
                        }
                    }
                }
                let dst = self.mem(args[0], size, true)?;
                dst.fill(0);
                if fault {
                    (-14i64) as u64 // -EFAULT
                } else if size == 0 {
                    0
                } else {
                    if *copied.last().unwrap() != 0 {
                        *copied.last_mut().unwrap() = 0; // truncated: force NUL
                    }
                    dst[..copied.len()].copy_from_slice(&copied);
                    copied.len() as u64
                }
            }
            helpers::id::CURRENT_TASK_UNDER_CGROUP => {
                // febpf's single synthetic task belongs to no cgroup: always
                // 0 ("not under"), deterministically. Validate the index like
                // the kernel (-EINVAL beyond the array) for fidelity.
                let m = self.map_from_ptr(args[0])?;
                if args[1] >= self.vm.maps[m].def.max_entries as u64 {
                    (-22i64) as u64 // -EINVAL
                } else {
                    0
                }
            }
            helpers::id::RINGBUF_RESERVE => {
                let m = self.map_from_ptr(args[0])?;
                self.ringbuf_reserve(m, args[1] as u32)
            }
            helpers::id::RINGBUF_SUBMIT => {
                self.ringbuf_consume(args[0], true)?;
                0
            }
            helpers::id::RINGBUF_DISCARD => {
                self.ringbuf_consume(args[0], false)?;
                0
            }
            helpers::id::SKC_TO_TCP_SOCK
            | helpers::id::SKC_TO_TCP_TIMEWAIT_SOCK
            | helpers::id::SKC_TO_TCP_REQUEST_SOCK => {
                // febpf does not expose host sockets or fabricate synthetic
                // socket layouts. A caller-supplied common socket therefore
                // has no safe standalone conversion target.
                0
            }
            helpers::id::RINGBUF_OUTPUT => {
                let m = self.map_from_ptr(args[0])?;
                let data = self.read_bytes(args[1], args[2] as usize)?;
                match self.vm.maps[m].ringbuf_output(data) {
                    Ok(()) => 0,
                    Err(e) => e as u64,
                }
            }
            helpers::id::PERF_EVENT_OUTPUT => {
                // (ctx, map, flags, data, size). Low 32 bits of flags select a
                // CPU index; BPF_F_CURRENT_CPU (0xffffffff) = current = CPU 0.
                let m = self.map_from_ptr(args[1])?;
                let cpu = match args[2] as u32 {
                    0xffff_ffff => 0,
                    c => c,
                };
                let data = self.read_bytes(args[3], args[4] as usize)?;
                match self.vm.maps[m].perf_output(cpu, data) {
                    Ok(()) => 0,
                    Err(e) => e as u64,
                }
            }
            0xbad2310 => {
                // CO-RE poison value: the loader replaced an instruction
                // whose relocation had no match in the target BTF.
                return Err(self.err(
                    "unresolved CO-RE relocation (poisoned instruction) executed".to_string(),
                ));
            }
            _ => {
                // user-registered helper: arbitrary code, assume non-deterministic
                self.nondet_calls += 1;
                let pc = self.pc;
                let mut helper = self
                    .vm
                    .user_helpers
                    .take(hid)
                    .ok_or_else(|| self.err(format!("call to unknown helper #{hid}")))?;
                let mut bus = Bus {
                    regions: &self.vm.regions,
                    maps: &mut self.vm.maps,
                    stack: &mut self.vm.stack,
                    ctx: self.ctx,
                    kmem: &mut self.vm.kmem,
                    packet: &mut self.vm.packet,
                    owned_regions: &mut self.vm.owned_regions,
                };
                let result = helper.call(args, &mut bus);
                self.vm.user_helpers.put_back(hid, helper);
                result.map_err(|msg| EbpfError {
                    pc,
                    msg: format!("helper #{hid}: {msg}"),
                })?
            }
        };
        self.regs[0] = r0;
        // r1-r5 are clobbered by calls; scrub for determinism
        for r in 1..=5 {
            self.regs[r] = 0;
        }
        Ok(false)
    }

    fn tail_call_fallthrough(&mut self) -> bool {
        self.regs[0] = 0;
        for r in 1..=5 {
            self.regs[r] = 0;
        }
        false
    }

    /// Minimal printk-style formatter: %d %u %x %s and l/ll length modifiers.
    fn format_printk(&mut self, fmt: &[u8], args: &[u64]) -> Result<String, EbpfError> {
        let mut out = String::new();
        let mut argi = 0;
        let mut i = 0;
        // treat as NUL-terminated within the given size
        let end = fmt.iter().position(|&b| b == 0).unwrap_or(fmt.len());
        let fmt = &fmt[..end];
        while i < fmt.len() {
            let c = fmt[i];
            if c != b'%' {
                out.push(c as char);
                i += 1;
                continue;
            }
            i += 1;
            if i >= fmt.len() {
                break;
            }
            if fmt[i] == b'%' {
                out.push('%');
                i += 1;
                continue;
            }
            let mut longs = 0;
            while i < fmt.len() && fmt[i] == b'l' {
                longs += 1;
                i += 1;
            }
            if i >= fmt.len() {
                break;
            }
            let conv = fmt[i];
            i += 1;
            let arg = args.get(argi).copied().unwrap_or(0);
            match conv {
                b's' => {
                    // bounded C-string read
                    let mut s = String::new();
                    for k in 0..256u64 {
                        let byte = self.load(arg + k, 1)? as u8;
                        if byte == 0 {
                            break;
                        }
                        s.push(byte as char);
                    }
                    out.push_str(&s);
                }
                b'd' | b'i' => {
                    let v = if longs >= 1 {
                        arg as i64
                    } else {
                        arg as u32 as i32 as i64
                    };
                    out.push_str(&v.to_string());
                }
                b'u' => {
                    let v = if longs >= 1 { arg } else { arg as u32 as u64 };
                    out.push_str(&v.to_string());
                }
                b'x' => {
                    let v = if longs >= 1 { arg } else { arg as u32 as u64 };
                    out.push_str(&format!("{v:x}"));
                }
                b'p' => out.push_str(&format!("{arg:#x}")),
                b'c' => out.push(arg as u8 as char),
                other => {
                    return Err(self.err(format!(
                        "trace_printk: unsupported conversion %{}",
                        other as char
                    )));
                }
            }
            argi += 1;
        }
        Ok(out)
    }
}
