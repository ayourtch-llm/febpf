//! Shareable **replay files** (`.febpf`): a small, self-contained, versioned
//! binary that captures everything needed to deterministically reproduce one
//! run of a program and re-open it in the time-travel debugger.
//!
//! febpf execution is a pure function of `(program, ctx, prandom_seed,
//! map_preload)` (HANDOFF §7), so a replay file stores only those inputs plus
//! an optional cursor and a determinism guard — never a state trace. Replay
//! rebuilds a fresh [`Vm`] and re-executes; the debugger's time travel is
//! itself replay-based, so it comes for free.
//!
//! Serialization is hand-written (zero dependencies, no serde). See
//! `docs/specs/replay-files.md` for the byte layout. All integers are
//! little-endian.

use crate::insn::{self, Insn};
use crate::interp::{Program, Vm};
use crate::maps::{MapDef, MapKind};
use crate::verifier::LegacyPacketProfile;
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

/// Container magic; the first 8 bytes of every replay file.
pub const MAGIC: &[u8; 8] = b"FEBPFRPL";
/// On-disk format version. Bump on any incompatible layout change.
pub const FORMAT_VERSION: u16 = 1;

// Section tags (see the spec table).
const TAG_META: u8 = 0x01;
const TAG_INSNS: u8 = 0x02;
const TAG_MAPS: u8 = 0x03;
const TAG_CTX: u8 = 0x04;
const TAG_SEED: u8 = 0x05;
const TAG_CURSOR: u8 = 0x06;
const TAG_PRELOAD: u8 = 0x07;
const TAG_OUTCOME: u8 = 0x08;
const TAG_PACKET: u8 = 0x09;
const TAG_TAIL_CALLS: u8 = 0x0a;
const TAG_MAP_IN_MAP: u8 = 0x0b;
const TAG_LEGACY_PACKET: u8 = 0x0c;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TailCallProgram {
    pub map_name: String,
    pub index: u32,
    pub insns: Vec<Insn>,
}

/// The febpf version stamped into a recorded file (its `CARGO_PKG_VERSION`).
pub fn febpf_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// User-supplied map contents, applied after map init and before the run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapPreload {
    pub map_index: u32,
    pub entries: Vec<(Vec<u8>, Vec<u8>)>,
}

/// The determinism guard: what the recorder observed the run produce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Program exited with this r0.
    Exit(u64),
    /// Program faulted with this message.
    Error(String),
}

fn outcome(result: Result<u64, crate::interp::EbpfError>) -> Outcome {
    match result {
        Ok(r0) => Outcome::Exit(r0),
        Err(error) => Outcome::Error(error.to_string()),
    }
}

/// A decoded replay file. Round-trips exactly through
/// [`Replay::to_bytes`]/[`Replay::from_bytes`].
#[derive(Clone, Debug, PartialEq)]
pub struct Replay {
    /// Recorder's `CARGO_PKG_VERSION`.
    pub febpf_version: String,
    pub insns: Vec<Insn>,
    pub maps: Vec<MapDef>,
    pub ctx: Vec<u8>,
    /// XDP packet input. When present, `ctx` is the synthetic xdp_md image and
    /// replay verifies/executes under packet data/data_end rules.
    pub packet: Option<Vec<u8>>,
    /// Deprecated packet-load semantics used for this invocation. Disabled
    /// replays omit the additive LEGACY_PACKET section byte-for-byte.
    pub legacy_packet: LegacyPacketProfile,
    pub seed: u64,
    /// Optional "stop at instruction count N" cursor for the debugger.
    pub stop_at: Option<u64>,
    pub preload: Vec<MapPreload>,
    /// Recorded result, for the determinism guard (`None` if not captured).
    pub outcome: Option<Outcome>,
    pub tail_calls: Vec<TailCallProgram>,
}

impl Replay {
    /// Build a replay by running `prog` once against `ctx` with the given seed
    /// and preload, capturing the [`Outcome`] as the determinism guard. `ctx`
    /// is stored as-is (the recorded *input*); the run executes on a clone so
    /// context writes don't perturb what we save.
    pub fn record(
        prog: &Program,
        ctx: Vec<u8>,
        seed: u64,
        stop_at: Option<u64>,
        preload: Vec<MapPreload>,
    ) -> Result<Replay, String> {
        let mut vm = Vm::new(prog.clone())?;
        vm.set_prandom_seed(seed);
        apply_preload(&mut vm, &preload)?;
        let mut runctx = ctx.clone();
        let outcome = match vm.run(&mut runctx) {
            Ok(r0) => Outcome::Exit(r0),
            Err(e) => Outcome::Error(e.to_string()),
        };
        Ok(Replay {
            febpf_version: febpf_version(),
            insns: prog.insns.clone(),
            maps: prog.maps.clone(),
            ctx,
            packet: None,
            legacy_packet: LegacyPacketProfile::Disabled,
            seed,
            stop_at,
            preload,
            outcome: Some(outcome),
            tail_calls: Vec::new(),
        })
    }

    /// Record one XDP packet invocation, including the packet bytes required
    /// to reconstruct data/data_end virtual pointers in the debugger.
    pub fn record_xdp(
        prog: &Program,
        packet: Vec<u8>,
        seed: u64,
        stop_at: Option<u64>,
        preload: Vec<MapPreload>,
    ) -> Result<Replay, String> {
        let mut vm = Vm::new(prog.clone())?;
        vm.set_prandom_seed(seed);
        apply_preload(&mut vm, &preload)?;
        vm.verify(crate::verifier::Config {
            ctx_size: 24,
            ctx_writable: false,
            xdp: true,
            ..Default::default()
        })
        .map_err(|e| format!("XDP verification failed: {e}"))?;
        let mut run_packet = packet.clone();
        let outcome = match vm.run_xdp(&mut run_packet) {
            Ok(r0) => Outcome::Exit(r0),
            Err(e) => Outcome::Error(e.to_string()),
        };
        Ok(Replay {
            febpf_version: febpf_version(),
            insns: prog.insns.clone(),
            maps: prog.maps.clone(),
            ctx: vec![0u8; 24],
            packet: Some(packet),
            legacy_packet: LegacyPacketProfile::Disabled,
            seed,
            stop_at,
            preload,
            outcome: Some(outcome),
            tail_calls: Vec::new(),
        })
    }

    pub fn record_tail_calls(
        prog: &Program,
        tail_calls: Vec<TailCallProgram>,
        ctx: Vec<u8>,
        seed: u64,
        stop_at: Option<u64>,
        preload: Vec<MapPreload>,
    ) -> Result<Replay, String> {
        let mut vm = Vm::new(prog.clone())?;
        vm.verify(crate::verifier::Config::default())
            .map_err(|e| format!("entry verification failed: {e}"))?;
        for link in &tail_calls {
            vm.register_tail_call(
                &link.map_name,
                link.index,
                Program {
                    insns: link.insns.clone(),
                    maps: prog.maps.clone(),
                    btf_ctx: None,
                },
                crate::verifier::Config::default(),
            )?;
        }
        vm.set_prandom_seed(seed);
        apply_preload(&mut vm, &preload)?;
        let mut runctx = ctx.clone();
        let outcome = match vm.run(&mut runctx) {
            Ok(r0) => Outcome::Exit(r0),
            Err(e) => Outcome::Error(e.to_string()),
        };
        Ok(Replay {
            febpf_version: febpf_version(),
            insns: prog.insns.clone(),
            maps: prog.maps.clone(),
            ctx,
            packet: None,
            legacy_packet: LegacyPacketProfile::Disabled,
            seed,
            stop_at,
            preload,
            outcome: Some(outcome),
            tail_calls,
        })
    }

    pub fn record_xdp_tail_calls(
        prog: &Program,
        tail_calls: Vec<TailCallProgram>,
        packet: Vec<u8>,
        seed: u64,
        stop_at: Option<u64>,
        preload: Vec<MapPreload>,
    ) -> Result<Replay, String> {
        let cfg = crate::verifier::Config {
            ctx_size: 24,
            ctx_writable: false,
            xdp: true,
            ..Default::default()
        };
        let mut vm = Vm::new(prog.clone())?;
        for link in &tail_calls {
            vm.register_tail_call(
                &link.map_name,
                link.index,
                Program {
                    insns: link.insns.clone(),
                    maps: prog.maps.clone(),
                    btf_ctx: None,
                },
                cfg.clone(),
            )?;
        }
        vm.verify(cfg)
            .map_err(|e| format!("XDP entry verification failed: {e}"))?;
        vm.set_prandom_seed(seed);
        apply_preload(&mut vm, &preload)?;
        let mut run_packet = packet.clone();
        let outcome = match vm.run_xdp(&mut run_packet) {
            Ok(r0) => Outcome::Exit(r0),
            Err(e) => Outcome::Error(e.to_string()),
        };
        Ok(Replay {
            febpf_version: febpf_version(),
            insns: prog.insns.clone(),
            maps: prog.maps.clone(),
            ctx: vec![0u8; 24],
            packet: Some(packet),
            legacy_packet: LegacyPacketProfile::Disabled,
            seed,
            stop_at,
            preload,
            outcome: Some(outcome),
            tail_calls,
        })
    }

    /// Record a raw-buffer invocation using an explicit legacy packet-load
    /// profile. The recorded CTX bytes are also the packet backing.
    pub fn record_legacy_raw(
        prog: &Program,
        packet: Vec<u8>,
        profile: LegacyPacketProfile,
        seed: u64,
        stop_at: Option<u64>,
        preload: Vec<MapPreload>,
    ) -> Result<Replay, String> {
        if profile == LegacyPacketProfile::Disabled {
            return Err("legacy replay requires Linux or Rbpf041 profile".into());
        }
        let mut vm = Vm::new(prog.clone())?;
        vm.verify(crate::verifier::Config {
            ctx_size: packet.len(),
            legacy_packet: profile,
            ..Default::default()
        })
        .map_err(|e| format!("legacy packet verification failed: {e}"))?;
        if !vm.uses_legacy_packet() {
            return Err("legacy replay program contains no legacy packet loads".into());
        }
        vm.set_prandom_seed(seed);
        apply_preload(&mut vm, &preload)?;
        let mut run_packet = packet.clone();
        let outcome = outcome(vm.run_raw(&mut run_packet));
        Ok(Replay {
            febpf_version: febpf_version(),
            insns: prog.insns.clone(),
            maps: prog.maps.clone(),
            ctx: packet,
            packet: None,
            legacy_packet: profile,
            seed,
            stop_at,
            preload,
            outcome: Some(outcome),
            tail_calls: Vec::new(),
        })
    }

    /// Record an XDP-backed invocation using an explicit legacy packet-load
    /// profile. PACKET remains the only serialized packet data; no virtual or
    /// host addresses enter the replay file.
    pub fn record_legacy_xdp(
        prog: &Program,
        packet: Vec<u8>,
        profile: LegacyPacketProfile,
        seed: u64,
        stop_at: Option<u64>,
        preload: Vec<MapPreload>,
    ) -> Result<Replay, String> {
        if profile == LegacyPacketProfile::Disabled {
            return Err("legacy replay requires Linux or Rbpf041 profile".into());
        }
        let mut vm = Vm::new(prog.clone())?;
        vm.verify(crate::verifier::Config {
            ctx_size: 24,
            ctx_writable: false,
            xdp: true,
            legacy_packet: profile,
            ..Default::default()
        })
        .map_err(|e| format!("legacy XDP verification failed: {e}"))?;
        if !vm.uses_legacy_packet() {
            return Err("legacy replay program contains no legacy packet loads".into());
        }
        vm.set_prandom_seed(seed);
        apply_preload(&mut vm, &preload)?;
        let mut run_packet = packet.clone();
        let outcome = outcome(vm.run_xdp(&mut run_packet));
        Ok(Replay {
            febpf_version: febpf_version(),
            insns: prog.insns.clone(),
            maps: prog.maps.clone(),
            ctx: vec![0u8; 24],
            packet: Some(packet),
            legacy_packet: profile,
            seed,
            stop_at,
            preload,
            outcome: Some(outcome),
            tail_calls: Vec::new(),
        })
    }

    /// The program (instructions + map defs) this replay reproduces.
    pub fn program(&self) -> Program {
        Program {
            insns: self.insns.clone(),
            maps: self.maps.clone(),
            btf_ctx: None,
        }
    }

    /// Build a `Vm` from this replay with the seed and preload applied, ready
    /// to run or drop into the debugger. `ctx` is the (mutable) working copy.
    pub fn build_vm(&self) -> Result<(Vm, Vec<u8>), String> {
        let mut vm = Vm::new(self.program())?;
        let config = self.verifier_config();
        if !self.tail_calls.is_empty()
            || self.packet.is_some()
            || self.legacy_packet != LegacyPacketProfile::Disabled
        {
            vm.verify(config.clone())
                .map_err(|e| format!("replayed entry no longer verifies: {e}"))?;
        }
        for link in &self.tail_calls {
            vm.register_tail_call(
                &link.map_name,
                link.index,
                Program {
                    insns: link.insns.clone(),
                    maps: self.maps.clone(),
                    btf_ctx: None,
                },
                config.clone(),
            )?;
        }
        vm.set_prandom_seed(self.seed);
        apply_preload(&mut vm, &self.preload)?;
        let ctx = if let Some(packet) = &self.packet {
            vm.prepare_xdp(packet)?
        } else {
            self.ctx.clone()
        };
        Ok((vm, ctx))
    }

    /// Execute a VM returned by [`Replay::build_vm`] with the recorded input
    /// adapter, including the packet backing required by legacy loads.
    pub fn run(&self, vm: &mut Vm, ctx: &mut [u8]) -> Result<u64, crate::interp::EbpfError> {
        match (self.legacy_packet, self.packet.is_some()) {
            (LegacyPacketProfile::Disabled, _) => vm.run(ctx),
            (_, false) => vm.run_raw(ctx),
            (_, true) => {
                let mut machine = vm.machine_prepared_xdp(ctx)?;
                loop {
                    if let Some(result) = machine.step()? {
                        return Ok(result);
                    }
                }
            }
        }
    }

    fn verifier_config(&self) -> crate::verifier::Config {
        if self.packet.is_some() {
            crate::verifier::Config {
                ctx_size: 24,
                ctx_writable: false,
                xdp: true,
                legacy_packet: self.legacy_packet,
                ..Default::default()
            }
        } else if self.legacy_packet != LegacyPacketProfile::Disabled {
            crate::verifier::Config {
                ctx_size: self.ctx.len(),
                legacy_packet: self.legacy_packet,
                ..Default::default()
            }
        } else {
            crate::verifier::Config::default()
        }
    }

    // -- serialization ------------------------------------------------------

    /// Serialize to the on-disk `.febpf` byte format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());

        // META
        let mut p = Vec::new();
        w_str(&mut p, &self.febpf_version);
        section(&mut out, TAG_META, &p);

        // INSNS: count + encoded slots.
        let mut p = Vec::new();
        p.extend_from_slice(&(self.insns.len() as u32).to_le_bytes());
        p.extend_from_slice(&insn::encode_program(&self.insns));
        section(&mut out, TAG_INSNS, &p);

        // MAPS
        let mut p = Vec::new();
        p.extend_from_slice(&(self.maps.len() as u32).to_le_bytes());
        for m in &self.maps {
            w_str(&mut p, &m.name);
            p.push(match m.kind {
                MapKind::Array => 0,
                MapKind::Hash => 1,
                MapKind::PerCpuArray => 2,
                MapKind::PerCpuHash => 3,
                MapKind::LruHash => 4,
                MapKind::RingBuf => 5,
                MapKind::PerfEventArray => 6,
                MapKind::CgroupArray => 7,
                MapKind::StackTrace => 8,
                MapKind::ProgArray => 9,
                MapKind::ArrayOfMaps => 10,
                MapKind::DevMap => 11,
                MapKind::CpuMap => 12,
                MapKind::DevMapHash => 13,
                MapKind::HashOfMaps => 14,
            });
            p.extend_from_slice(&m.key_size.to_le_bytes());
            p.extend_from_slice(&m.value_size.to_le_bytes());
            p.extend_from_slice(&m.max_entries.to_le_bytes());
            p.push(m.readonly as u8);
            w_bytes(&mut p, &m.init);
        }
        section(&mut out, TAG_MAPS, &p);

        let nested: Vec<(usize, &MapDef)> = self
            .maps
            .iter()
            .enumerate()
            .filter(|(_, map)| map.kind.is_map_of_maps())
            .collect();
        if !nested.is_empty() {
            let mut p = Vec::new();
            p.extend_from_slice(&(nested.len() as u32).to_le_bytes());
            for (outer, map) in nested {
                p.extend_from_slice(&(outer as u32).to_le_bytes());
                p.extend_from_slice(&map.inner_map_idx.unwrap_or(u32::MAX).to_le_bytes());
                p.extend_from_slice(&(map.map_in_map_values.len() as u32).to_le_bytes());
                for &(slot, inner) in &map.map_in_map_values {
                    p.extend_from_slice(&slot.to_le_bytes());
                    p.extend_from_slice(&inner.to_le_bytes());
                }
            }
            section(&mut out, TAG_MAP_IN_MAP, &p);
        }

        // CTX (raw bytes, length is the section length)
        section(&mut out, TAG_CTX, &self.ctx);

        // PACKET marks an XDP replay and carries the original packet input.
        if let Some(packet) = &self.packet {
            section(&mut out, TAG_PACKET, packet);
        }

        if self.legacy_packet != LegacyPacketProfile::Disabled {
            let profile = match self.legacy_packet {
                LegacyPacketProfile::Linux => 1,
                LegacyPacketProfile::Rbpf041 => 2,
                LegacyPacketProfile::Disabled => unreachable!(),
            };
            section(&mut out, TAG_LEGACY_PACKET, &[profile]);
        }

        // SEED
        section(&mut out, TAG_SEED, &self.seed.to_le_bytes());

        // CURSOR (optional)
        if let Some(n) = self.stop_at {
            section(&mut out, TAG_CURSOR, &n.to_le_bytes());
        }

        // PRELOAD (optional; omit if empty)
        if !self.preload.is_empty() {
            let mut p = Vec::new();
            let total: usize = self.preload.iter().map(|g| g.entries.len()).sum();
            p.extend_from_slice(&(total as u32).to_le_bytes());
            for g in &self.preload {
                for (k, v) in &g.entries {
                    p.extend_from_slice(&g.map_index.to_le_bytes());
                    w_bytes(&mut p, k);
                    w_bytes(&mut p, v);
                }
            }
            section(&mut out, TAG_PRELOAD, &p);
        }

        // OUTCOME (optional)
        if let Some(o) = &self.outcome {
            let mut p = Vec::new();
            match o {
                Outcome::Exit(r0) => {
                    p.push(0);
                    p.extend_from_slice(&r0.to_le_bytes());
                }
                Outcome::Error(msg) => {
                    p.push(1);
                    w_str(&mut p, msg);
                }
            }
            section(&mut out, TAG_OUTCOME, &p);
        }

        if !self.tail_calls.is_empty() {
            let mut p = Vec::new();
            p.extend_from_slice(&(self.tail_calls.len() as u32).to_le_bytes());
            for link in &self.tail_calls {
                w_str(&mut p, &link.map_name);
                p.extend_from_slice(&link.index.to_le_bytes());
                p.extend_from_slice(&(link.insns.len() as u32).to_le_bytes());
                p.extend_from_slice(&insn::encode_program(&link.insns));
            }
            section(&mut out, TAG_TAIL_CALLS, &p);
        }

        out
    }

    /// Parse a replay file. Never panics; returns a clean error on a
    /// short/corrupt file, a version it can't read, or a missing required
    /// section. Unknown section tags are skipped for forward compatibility.
    pub fn from_bytes(bytes: &[u8]) -> Result<Replay, String> {
        if bytes.len() < 10 || &bytes[0..8] != MAGIC {
            return Err("not a febpf replay file (bad magic)".into());
        }
        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if version != FORMAT_VERSION {
            return Err(format!(
                "unsupported replay format version {version} (this build reads {FORMAT_VERSION})"
            ));
        }

        let mut febpf_version = None;
        let mut insns = None;
        let mut maps = None;
        let mut ctx = None;
        let mut seed = None;
        let mut stop_at = None;
        let mut preload = Vec::new();
        let mut outcome = None;
        let mut packet = None;
        let mut tail_calls = Vec::new();
        let mut map_in_map = Vec::new();
        let mut legacy_packet = LegacyPacketProfile::Disabled;

        let mut pos = 10usize;
        while pos < bytes.len() {
            if pos + 5 > bytes.len() {
                return Err("truncated section header".into());
            }
            let tag = bytes[pos];
            let len = u32::from_le_bytes([bytes[pos + 1], bytes[pos + 2], bytes[pos + 3], bytes[pos + 4]])
                as usize;
            pos += 5;
            if pos + len > bytes.len() {
                return Err(format!("section {tag:#x} runs past end of file"));
            }
            let payload = &bytes[pos..pos + len];
            pos += len;

            match tag {
                TAG_META => {
                    let mut r = Reader::new(payload);
                    febpf_version = Some(r.str()?);
                }
                TAG_INSNS => {
                    let mut r = Reader::new(payload);
                    let count = r.u32()? as usize;
                    let raw = r.rest();
                    if raw.len() != count * insn::INSN_SIZE {
                        return Err("INSNS section length inconsistent with count".into());
                    }
                    insns = Some(insn::decode_program(raw)?);
                }
                TAG_MAPS => {
                    let mut r = Reader::new(payload);
                    let n = r.u32()? as usize;
                    // Do not pre-allocate from an untrusted count; grow as each
                    // element is read (bounds-checked), so a corrupt count fails
                    // fast instead of attempting a huge allocation.
                    let mut v = Vec::new();
                    for _ in 0..n {
                        let name = r.str()?;
                        let kind = match r.u8()? {
                            0 => MapKind::Array,
                            1 => MapKind::Hash,
                            2 => MapKind::PerCpuArray,
                            3 => MapKind::PerCpuHash,
                            4 => MapKind::LruHash,
                            5 => MapKind::RingBuf,
                            6 => MapKind::PerfEventArray,
                            7 => MapKind::CgroupArray,
                            8 => MapKind::StackTrace,
                            9 => MapKind::ProgArray,
                            10 => MapKind::ArrayOfMaps,
                            11 => MapKind::DevMap,
                            12 => MapKind::CpuMap,
                            13 => MapKind::DevMapHash,
                            14 => MapKind::HashOfMaps,
                            k => return Err(format!("unknown map kind {k}")),
                        };
                        let key_size = r.u32()?;
                        let value_size = r.u32()?;
                        let max_entries = r.u32()?;
                        let readonly = r.u8()? != 0;
                        let init = r.bytes()?;
                        v.push(MapDef {
                            name,
                            kind,
                            key_size,
                            value_size,
                            max_entries,
                            readonly,
                            init,
                            inner_map_idx: None,
                            map_in_map_values: Vec::new(),
                        });
                    }
                    maps = Some(v);
                }
                TAG_CTX => ctx = Some(payload.to_vec()),
                TAG_SEED => {
                    let mut r = Reader::new(payload);
                    seed = Some(r.u64()?);
                }
                TAG_CURSOR => {
                    let mut r = Reader::new(payload);
                    stop_at = Some(r.u64()?);
                }
                TAG_PRELOAD => {
                    let mut r = Reader::new(payload);
                    let n = r.u32()? as usize;
                    // Group consecutive entries by map_index into MapPreload.
                    // Grow lazily (untrusted count — see MAPS above).
                    let mut flat: Vec<(u32, Vec<u8>, Vec<u8>)> = Vec::new();
                    for _ in 0..n {
                        let mi = r.u32()?;
                        let k = r.bytes()?;
                        let val = r.bytes()?;
                        flat.push((mi, k, val));
                    }
                    for (mi, k, val) in flat {
                        match preload.iter_mut().find(|g: &&mut MapPreload| g.map_index == mi) {
                            Some(g) => g.entries.push((k, val)),
                            None => preload.push(MapPreload {
                                map_index: mi,
                                entries: vec![(k, val)],
                            }),
                        }
                    }
                }
                TAG_OUTCOME => {
                    let mut r = Reader::new(payload);
                    outcome = Some(match r.u8()? {
                        0 => Outcome::Exit(r.u64()?),
                        1 => Outcome::Error(r.str()?),
                        k => return Err(format!("unknown outcome kind {k}")),
                    });
                }
                TAG_PACKET => packet = Some(payload.to_vec()),
                TAG_TAIL_CALLS => {
                    let mut r = Reader::new(payload);
                    let n = r.u32()? as usize;
                    for _ in 0..n {
                        let map_name = r.str()?;
                        let index = r.u32()?;
                        let count = r.u32()? as usize;
                        let raw = r.take(count.checked_mul(insn::INSN_SIZE).ok_or(
                            "TAIL_CALLS instruction count overflow",
                        )?)?;
                        tail_calls.push(TailCallProgram {
                            map_name,
                            index,
                            insns: insn::decode_program(raw)?,
                        });
                    }
                }
                TAG_MAP_IN_MAP => {
                    let mut r = Reader::new(payload);
                    let n = r.u32()? as usize;
                    for _ in 0..n {
                        let outer = r.u32()?;
                        let template = r.u32()?;
                        let count = r.u32()? as usize;
                        let mut values = Vec::new();
                        for _ in 0..count {
                            values.push((r.u32()?, r.u32()?));
                        }
                        map_in_map.push((outer, template, values));
                    }
                }
                TAG_LEGACY_PACKET => {
                    let mut r = Reader::new(payload);
                    legacy_packet = match r.u8()? {
                        1 => LegacyPacketProfile::Linux,
                        2 => LegacyPacketProfile::Rbpf041,
                        profile => return Err(format!("unknown legacy packet profile {profile}")),
                    };
                    if !r.rest().is_empty() {
                        return Err("LEGACY_PACKET section has trailing bytes".into());
                    }
                }
                _ => {} // unknown section: skip (forward compatibility)
            }
        }

        let mut maps = maps.ok_or("replay file missing MAPS section")?;
        for (outer, template, values) in map_in_map {
            let map = maps
                .get_mut(outer as usize)
                .ok_or("MAP_IN_MAP references an unknown outer map")?;
            if !map.kind.is_map_of_maps() || template == u32::MAX {
                return Err("invalid MAP_IN_MAP template".into());
            }
            map.inner_map_idx = Some(template);
            map.map_in_map_values = values;
        }
        Ok(Replay {
            febpf_version: febpf_version.ok_or("replay file missing META section")?,
            insns: insns.ok_or("replay file missing INSNS section")?,
            maps,
            ctx: ctx.ok_or("replay file missing CTX section")?,
            packet,
            legacy_packet,
            seed: seed.ok_or("replay file missing SEED section")?,
            stop_at,
            preload,
            outcome,
            tail_calls,
        })
    }
}

/// Apply user-supplied map contents to a freshly built `Vm`.
pub fn apply_preload(vm: &mut Vm, preload: &[MapPreload]) -> Result<(), String> {
    for g in preload {
        let m = vm
            .maps
            .get_mut(g.map_index as usize)
            .ok_or_else(|| format!("preload references unknown map index {}", g.map_index))?;
        for (k, val) in &g.entries {
            m.update(k, val)
                .map_err(|e| format!("preload update of map {} failed (errno {e})", g.map_index))?;
        }
    }
    Ok(())
}

// -- low-level writers -------------------------------------------------------

fn section(out: &mut Vec<u8>, tag: u8, payload: &[u8]) {
    out.push(tag);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
}

fn w_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

fn w_str(out: &mut Vec<u8>, s: &str) {
    w_bytes(out, s.as_bytes());
}

// -- low-level reader (never panics) -----------------------------------------

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { b, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.pos + n > self.b.len() {
            return Err("unexpected end of section payload".into());
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, String> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn u64(&mut self) -> Result<u64, String> {
        let s = self.take(8)?;
        Ok(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
    }

    fn bytes(&mut self) -> Result<Vec<u8>, String> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }

    fn str(&mut self) -> Result<String, String> {
        let b = self.bytes()?;
        String::from_utf8(b).map_err(|_| "invalid UTF-8 in string field".to_string())
    }

    /// Remaining unread bytes.
    fn rest(&self) -> &'a [u8] {
        &self.b[self.pos..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asm;

    fn prog(src: &str) -> Program {
        let a = asm::assemble(src).unwrap();
        Program {
            insns: a.insns,
            maps: a.maps,
            btf_ctx: None,
        }
    }

    const SUM: &str = "
        r0 = 0
        r2 = 10
    loop:
        r0 += r2
        r2 -= 1
        if r2 != 0 goto loop
        exit
    ";

    #[test]
    fn round_trip_exact() {
        let p = prog(SUM);
        let r = Replay::record(&p, vec![0u8; 16], 12345, Some(3), Vec::new()).unwrap();
        let bytes = r.to_bytes();
        let back = Replay::from_bytes(&bytes).unwrap();
        assert_eq!(r, back);
        assert_eq!(back.seed, 12345);
        assert_eq!(back.stop_at, Some(3));
        assert_eq!(back.outcome, Some(Outcome::Exit(55)));
    }

    #[test]
    fn round_trip_with_maps_and_preload() {
        let p = prog("
            .map arr array 4 8 4
            .map h hash 4 8 8
            r0 = 0
            exit
        ");
        let preload = vec![MapPreload {
            map_index: 1, // the hash map
            entries: vec![(1u32.to_le_bytes().to_vec(), 0xdeadbeefu64.to_le_bytes().to_vec())],
        }];
        let r = Replay::record(&p, vec![], DEFAULT_SEED, None, preload).unwrap();
        let back = Replay::from_bytes(&r.to_bytes()).unwrap();
        assert_eq!(r, back);
        assert_eq!(back.maps.len(), 2);
        assert_eq!(back.preload.len(), 1);
        assert_eq!(back.preload[0].map_index, 1);
    }

    const DEFAULT_SEED: u64 = crate::interp::DEFAULT_PRANDOM_SEED;

    #[test]
    fn rejects_short_and_bad_magic() {
        assert!(Replay::from_bytes(&[]).is_err());
        assert!(Replay::from_bytes(b"FEBPF").is_err());
        assert!(Replay::from_bytes(b"NOTAFILE!!\x01\x00").is_err());
    }

    #[test]
    fn rejects_version_mismatch() {
        let p = prog(SUM);
        let r = Replay::record(&p, vec![], DEFAULT_SEED, None, Vec::new()).unwrap();
        let mut bytes = r.to_bytes();
        bytes[8] = 0xff; // corrupt the version word
        bytes[9] = 0xff;
        let err = Replay::from_bytes(&bytes).unwrap_err();
        assert!(err.contains("unsupported replay format version"), "{err}");
    }

    #[test]
    fn rejects_truncated_section() {
        let p = prog(SUM);
        let r = Replay::record(&p, vec![0u8; 8], DEFAULT_SEED, None, Vec::new()).unwrap();
        let bytes = r.to_bytes();
        // Cut off mid-file: every prefix past the header must fail cleanly,
        // never panic.
        for cut in 10..bytes.len() {
            let _ = Replay::from_bytes(&bytes[..cut]); // just must not panic
        }
        // A file missing a required section is rejected: keep only the header.
        assert!(Replay::from_bytes(&bytes[..10]).is_err());
    }

    #[test]
    fn error_outcome_round_trips() {
        // A program that faults (out-of-bounds load) records an Error outcome.
        let p = prog("
            r1 = 0
            r0 = *(u64 *)(r1 + 0)
            exit
        ");
        let r = Replay::record(&p, vec![], DEFAULT_SEED, None, Vec::new()).unwrap();
        assert!(matches!(r.outcome, Some(Outcome::Error(_))));
        let back = Replay::from_bytes(&r.to_bytes()).unwrap();
        assert_eq!(r, back);
    }
}
