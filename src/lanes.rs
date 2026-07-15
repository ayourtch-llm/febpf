//! Conservative architecture-neutral lane execution for pure XDP programs.
//!
//! This is the semantic boundary consumed by graph runtimes before any CPU
//! backend chooses scalar interleaving or SIMD instructions. Only verified,
//! forward-only programs with independent packet reads are accepted. Programs
//! with maps, helpers, stores, stack accesses, local calls, or loops remain on
//! the ordinary scalar VM path.

use alloc::{string::String, vec, vec::Vec};
use core::fmt;

use crate::{
    insn::{alu, call_kind, class, jmp, mode, Insn, NUM_REGS},
    packet::{XdpFrame, XdpVerdict},
    verifier::{Config, PtrKind, RegState, VerifyOk},
    Program, Vm,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LaneWidth {
    Two,
    Four,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct LaneCpuFeatures {
    pub sse2: bool,
    pub avx2: bool,
}

impl LaneCpuFeatures {
    pub fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self {
                sse2: std::is_x86_feature_detected!("sse2"),
                avx2: std::is_x86_feature_detected!("avx2"),
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Self::default()
        }
    }

    pub const fn bits(self) -> u8 {
        self.sse2 as u8 | ((self.avx2 as u8) << 1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LaneBackend {
    ScalarInterleaved,
    X86Sse2,
    X86Avx2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LanePlanKey {
    pub program: u64,
    pub width: LaneWidth,
    pub backend: LaneBackend,
    pub cpu_features: u8,
}

impl LaneWidth {
    pub const fn lanes(self) -> usize {
        match self {
            Self::Two => 2,
            Self::Four => 4,
        }
    }
}

/// One operation in the architecture-independent XDP lane plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XdpLaneOp {
    Dead,
    Alu(Insn),
    Data {
        dst: u8,
    },
    DataEnd {
        dst: u8,
    },
    PacketLoad {
        dst: u8,
        offset: usize,
        size: usize,
        signed: bool,
    },
    Branch(Insn),
    Exit,
}

#[derive(Clone, Debug)]
pub struct XdpLaneProgram {
    width: LaneWidth,
    ops: Vec<XdpLaneOp>,
    features: LaneCpuFeatures,
    backend: LaneBackend,
    program_key: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LanePlanStats {
    pub reachable_ops: usize,
    pub context_loads: usize,
    pub packet_loads: usize,
    pub branches: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneRuntimeError {
    pub lane: usize,
    pub pc: usize,
    pub message: String,
}

impl fmt::Display for LaneRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lane {} pc {}: {}", self.lane, self.pc, self.message)
    }
}

impl std::error::Error for LaneRuntimeError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneValidation {
    pub inputs: usize,
    pub width: LaneWidth,
    pub backend: LaneBackend,
    pub plan_key: LanePlanKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneMismatch {
    pub input: usize,
    pub scalar: Result<XdpVerdict, String>,
    pub lanes: Result<XdpVerdict, String>,
}

impl fmt::Display for LaneMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "lane translation diverged on input {}: scalar={:?}, lanes={:?}",
            self.input, self.scalar, self.lanes
        )
    }
}

impl std::error::Error for LaneMismatch {}

impl XdpLaneProgram {
    /// Lower a verified XDP program to the conservative pure-packet lane IR.
    pub fn compile(
        program: &Program,
        verified: &VerifyOk,
        width: LaneWidth,
    ) -> Result<Self, String> {
        if !program.maps.is_empty() {
            return Err("lane translation requires a map-free program".into());
        }
        if verified.pc_regs.len() != program.insns.len() {
            return Err("verification result does not match the program".into());
        }

        let mut ops = vec![XdpLaneOp::Dead; program.insns.len()];
        for (pc, insn) in program.insns.iter().copied().enumerate() {
            let Some(regs) = verified.regs_at(pc) else {
                continue;
            };
            ops[pc] = match insn.class() {
                class::ALU | class::ALU64 => {
                    if insn.dst as usize >= NUM_REGS
                        || (insn.is_src_reg() && insn.src as usize >= NUM_REGS)
                    {
                        return Err(format!("pc {pc}: invalid ALU register"));
                    }
                    XdpLaneOp::Alu(insn)
                }
                class::LDX if matches!(insn.mem_mode(), mode::MEM | mode::MEMSX) => {
                    lower_load(pc, insn, regs)?
                }
                class::JMP | class::JMP32 => match insn.op() {
                    jmp::EXIT if insn.class() == class::JMP => XdpLaneOp::Exit,
                    jmp::CALL => {
                        let kind = if insn.src == call_kind::LOCAL {
                            "local calls"
                        } else {
                            "helpers"
                        };
                        return Err(format!("pc {pc}: lane translation rejects {kind}"));
                    }
                    _ => {
                        let relative = if insn.class() == class::JMP32 && insn.op() == jmp::JA {
                            insn.imm as i64
                        } else {
                            insn.off as i64
                        };
                        let target = pc as i64 + 1 + relative;
                        if target <= pc as i64 {
                            return Err(format!(
                                "pc {pc}: lane translation rejects backward control flow"
                            ));
                        }
                        if target < 0 || target as usize >= program.insns.len() {
                            return Err(format!("pc {pc}: branch target is outside the program"));
                        }
                        XdpLaneOp::Branch(insn)
                    }
                },
                class::ST | class::STX => {
                    return Err(format!(
                        "pc {pc}: lane translation rejects stores and atomics"
                    ));
                }
                class::LD => {
                    return Err(format!("pc {pc}: lane translation rejects generic loads"));
                }
                _ => return Err(format!("pc {pc}: unsupported instruction class")),
            };
        }
        let features = LaneCpuFeatures::detect();
        let backend = select_backend(width, &ops, features, verified);
        let program_key = program_fingerprint(&program.insns);
        Ok(Self {
            width,
            ops,
            features,
            backend,
            program_key,
        })
    }

    pub fn width(&self) -> LaneWidth {
        self.width
    }

    pub fn ops(&self) -> &[XdpLaneOp] {
        &self.ops
    }

    pub fn backend(&self) -> LaneBackend {
        self.backend
    }

    pub fn cpu_features(&self) -> LaneCpuFeatures {
        self.features
    }

    pub fn plan_key(&self) -> LanePlanKey {
        LanePlanKey {
            program: self.program_key,
            width: self.width,
            backend: self.backend,
            cpu_features: self.features.bits(),
        }
    }

    pub fn stats(&self) -> LanePlanStats {
        let mut stats = LanePlanStats::default();
        for op in &self.ops {
            match op {
                XdpLaneOp::Dead => continue,
                XdpLaneOp::Data { .. } | XdpLaneOp::DataEnd { .. } => stats.context_loads += 1,
                XdpLaneOp::PacketLoad { .. } => stats.packet_loads += 1,
                XdpLaneOp::Branch(_) => stats.branches += 1,
                XdpLaneOp::Alu(_) | XdpLaneOp::Exit => {}
            }
            stats.reachable_ops += 1;
        }
        stats
    }

    /// Execute independent frames in lockstep groups with a scalar remainder.
    pub fn execute(&self, frames: &[XdpFrame]) -> Result<Vec<XdpVerdict>, LaneRuntimeError> {
        self.execute_backend(frames, self.backend)
    }

    /// Execute through the portable reference backend even when SIMD is
    /// available. Used for translation validation and same-binary benchmarks.
    pub fn execute_scalar(&self, frames: &[XdpFrame]) -> Result<Vec<XdpVerdict>, LaneRuntimeError> {
        self.execute_backend(frames, LaneBackend::ScalarInterleaved)
    }

    fn execute_backend(
        &self,
        frames: &[XdpFrame],
        backend: LaneBackend,
    ) -> Result<Vec<XdpVerdict>, LaneRuntimeError> {
        let mut verdicts = Vec::with_capacity(frames.len());
        while verdicts.len() < frames.len() {
            let base = verdicts.len();
            let remaining = frames.len() - base;
            let backend_width = match backend {
                LaneBackend::X86Avx2 => 4,
                LaneBackend::X86Sse2 => 2,
                LaneBackend::ScalarInterleaved => self.width.lanes(),
            };
            let group_len = if remaining >= backend_width {
                backend_width
            } else if remaining >= 2 {
                2
            } else {
                1
            };
            let chunk = &frames[base..base + group_len];
            let group = self
                .execute_group_backend(chunk, backend)
                .map_err(|mut error| {
                    error.lane += base;
                    error
                })?;
            verdicts.extend(group);
        }
        Ok(verdicts)
    }

    fn execute_group_backend(
        &self,
        frames: &[XdpFrame],
        backend: LaneBackend,
    ) -> Result<Vec<XdpVerdict>, LaneRuntimeError> {
        #[cfg(not(target_arch = "x86_64"))]
        let _ = backend;
        #[cfg(target_arch = "x86_64")]
        match (backend, frames.len()) {
            (LaneBackend::X86Avx2, 4) => {
                // SAFETY: the backend is selected only after runtime AVX2
                // detection and the plan eligibility check.
                return unsafe { x86::execute_avx2(&self.ops) };
            }
            (LaneBackend::X86Avx2 | LaneBackend::X86Sse2, 2) => {
                // SAFETY: SSE2 is recorded in the selected plan features.
                return unsafe { x86::execute_sse2(&self.ops) };
            }
            _ => {}
        }
        self.execute_group(frames)
    }

    /// Differentially validate this lane plan against ordinary scalar XDP.
    /// A successful result is empirical evidence over the supplied corpus,
    /// not a universal equivalence proof.
    pub fn validate(
        &self,
        program: &Program,
        frames: &[XdpFrame],
    ) -> Result<LaneValidation, LaneMismatch> {
        let lane_results = self.execute(frames).map_err(|error| LaneMismatch {
            input: error.lane,
            scalar: Err("not executed".into()),
            lanes: Err(error.to_string()),
        })?;
        let mut vm = Vm::new(program.clone()).map_err(|error| LaneMismatch {
            input: 0,
            scalar: Err(error),
            lanes: Ok(XdpVerdict::new(0)),
        })?;
        vm.verify(Config {
            ctx_size: 24,
            ctx_writable: false,
            xdp: true,
            ..Config::default()
        })
        .map_err(|error| LaneMismatch {
            input: 0,
            scalar: Err(error.to_string()),
            lanes: Ok(XdpVerdict::new(0)),
        })?;

        for (input, (frame, lane_result)) in frames.iter().zip(lane_results).enumerate() {
            let mut scalar_frame = frame.clone();
            let scalar_result = vm
                .run_xdp_frame(&mut scalar_frame)
                .map_err(|error| error.to_string());
            if scalar_result.as_ref() != Ok(&lane_result) || scalar_frame != *frame {
                return Err(LaneMismatch {
                    input,
                    scalar: scalar_result,
                    lanes: Ok(lane_result),
                });
            }
        }
        Ok(LaneValidation {
            inputs: frames.len(),
            width: self.width,
            backend: self.backend,
            plan_key: self.plan_key(),
        })
    }

    fn execute_group(&self, frames: &[XdpFrame]) -> Result<Vec<XdpVerdict>, LaneRuntimeError> {
        debug_assert!(frames.len() <= 4);
        let mut regs = [[0u64; NUM_REGS]; 4];
        let mut pcs = [0usize; 4];
        let mut active = (1u8 << frames.len()) - 1;
        let mut results = [0u64; 4];

        while active != 0 {
            for lane in 0..frames.len() {
                if active & (1 << lane) == 0 {
                    continue;
                }
                let pc = pcs[lane];
                let op = self.ops.get(pc).copied().ok_or_else(|| LaneRuntimeError {
                    lane,
                    pc,
                    message: "program counter is outside the lane plan".into(),
                })?;
                match op {
                    XdpLaneOp::Dead => return Err(runtime_error(lane, pc, "entered dead code")),
                    XdpLaneOp::Alu(insn) => {
                        execute_alu(insn, &mut regs[lane])
                            .map_err(|message| runtime_error(lane, pc, message))?;
                        pcs[lane] += 1;
                    }
                    XdpLaneOp::Data { dst } => {
                        regs[lane][dst as usize] = 0;
                        pcs[lane] += 1;
                    }
                    XdpLaneOp::DataEnd { dst } => {
                        regs[lane][dst as usize] = frames[lane].data().len() as u64;
                        pcs[lane] += 1;
                    }
                    XdpLaneOp::PacketLoad {
                        dst,
                        offset,
                        size,
                        signed,
                    } => {
                        let bytes =
                            frames[lane]
                                .data()
                                .get(offset..offset + size)
                                .ok_or_else(|| {
                                    runtime_error(lane, pc, "packet load is out of bounds")
                                })?;
                        let value = load_le(bytes, signed);
                        regs[lane][dst as usize] = value;
                        pcs[lane] += 1;
                    }
                    XdpLaneOp::Branch(insn) => {
                        pcs[lane] = branch_target(pc, insn, &regs[lane])
                            .map_err(|message| runtime_error(lane, pc, message))?;
                    }
                    XdpLaneOp::Exit => {
                        results[lane] = regs[lane][0];
                        active &= !(1 << lane);
                    }
                }
            }
        }
        Ok(results[..frames.len()]
            .iter()
            .copied()
            .map(XdpVerdict::new)
            .collect())
    }
}

fn program_fingerprint(insns: &[Insn]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for insn in insns {
        for byte in [insn.opcode, insn.dst, insn.src]
            .into_iter()
            .chain(insn.off.to_le_bytes())
            .chain(insn.imm.to_le_bytes())
        {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    hash
}

fn select_backend(
    width: LaneWidth,
    ops: &[XdpLaneOp],
    features: LaneCpuFeatures,
    verified: &VerifyOk,
) -> LaneBackend {
    if !ops
        .iter()
        .enumerate()
        .all(|(pc, op)| simd_supported(pc, op, verified))
    {
        return LaneBackend::ScalarInterleaved;
    }
    if width == LaneWidth::Four && features.avx2 {
        LaneBackend::X86Avx2
    } else if features.sse2 {
        LaneBackend::X86Sse2
    } else {
        LaneBackend::ScalarInterleaved
    }
}

fn simd_supported(pc: usize, op: &XdpLaneOp, verified: &VerifyOk) -> bool {
    match op {
        XdpLaneOp::Dead | XdpLaneOp::Exit => true,
        XdpLaneOp::Alu(insn) if insn.class() == class::ALU64 => {
            let Some(regs) = verified.regs_at(pc) else {
                return false;
            };
            let scalar = |register: u8| matches!(regs[register as usize], RegState::Scalar(_));
            match insn.op() {
                alu::MOV if !insn.is_src_reg() => insn.off == 0,
                alu::MOV => insn.off == 0 && scalar(insn.src),
                alu::ADD | alu::SUB | alu::OR | alu::AND | alu::XOR => {
                    scalar(insn.dst) && (!insn.is_src_reg() || scalar(insn.src))
                }
                alu::NEG => scalar(insn.dst),
                _ => false,
            }
        }
        _ => false,
    }
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::*;
    use core::arch::x86_64::*;

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn execute_avx2(
        ops: &[XdpLaneOp],
    ) -> Result<Vec<XdpVerdict>, LaneRuntimeError> {
        let zero = _mm256_setzero_si256();
        let mut regs = [zero; NUM_REGS];
        for (pc, op) in ops.iter().copied().enumerate() {
            match op {
                XdpLaneOp::Dead => {}
                XdpLaneOp::Alu(insn) => {
                    let dst = insn.dst as usize;
                    let a = regs[dst];
                    let b = if insn.is_src_reg() {
                        regs[insn.src as usize]
                    } else {
                        _mm256_set1_epi64x(insn.imm as i64)
                    };
                    regs[dst] = match insn.op() {
                        alu::MOV => b,
                        alu::ADD => _mm256_add_epi64(a, b),
                        alu::SUB => _mm256_sub_epi64(a, b),
                        alu::OR => _mm256_or_si256(a, b),
                        alu::AND => _mm256_and_si256(a, b),
                        alu::XOR => _mm256_xor_si256(a, b),
                        alu::NEG => _mm256_sub_epi64(zero, a),
                        _ => return Err(runtime_error(0, pc, "unsupported AVX2 lane operation")),
                    };
                }
                XdpLaneOp::Exit => {
                    let mut values = [0u64; 4];
                    // SAFETY: values has exactly 32 writable bytes and an
                    // unaligned store accepts its alignment.
                    unsafe {
                        _mm256_storeu_si256(values.as_mut_ptr().cast::<__m256i>(), regs[0]);
                    }
                    return Ok(values.into_iter().map(XdpVerdict::new).collect());
                }
                _ => return Err(runtime_error(0, pc, "non-AVX2 operation entered AVX2 plan")),
            }
        }
        Err(runtime_error(0, ops.len(), "AVX2 lane plan has no exit"))
    }

    #[target_feature(enable = "sse2")]
    pub(super) unsafe fn execute_sse2(
        ops: &[XdpLaneOp],
    ) -> Result<Vec<XdpVerdict>, LaneRuntimeError> {
        let zero = _mm_setzero_si128();
        let mut regs = [zero; NUM_REGS];
        for (pc, op) in ops.iter().copied().enumerate() {
            match op {
                XdpLaneOp::Dead => {}
                XdpLaneOp::Alu(insn) => {
                    let dst = insn.dst as usize;
                    let a = regs[dst];
                    let b = if insn.is_src_reg() {
                        regs[insn.src as usize]
                    } else {
                        _mm_set1_epi64x(insn.imm as i64)
                    };
                    regs[dst] = match insn.op() {
                        alu::MOV => b,
                        alu::ADD => _mm_add_epi64(a, b),
                        alu::SUB => _mm_sub_epi64(a, b),
                        alu::OR => _mm_or_si128(a, b),
                        alu::AND => _mm_and_si128(a, b),
                        alu::XOR => _mm_xor_si128(a, b),
                        alu::NEG => _mm_sub_epi64(zero, a),
                        _ => return Err(runtime_error(0, pc, "unsupported SSE2 lane operation")),
                    };
                }
                XdpLaneOp::Exit => {
                    let mut values = [0u64; 2];
                    // SAFETY: values has exactly 16 writable bytes and an
                    // unaligned store accepts its alignment.
                    unsafe {
                        _mm_storeu_si128(values.as_mut_ptr().cast::<__m128i>(), regs[0]);
                    }
                    return Ok(values.into_iter().map(XdpVerdict::new).collect());
                }
                _ => return Err(runtime_error(0, pc, "non-SSE2 operation entered SSE2 plan")),
            }
        }
        Err(runtime_error(0, ops.len(), "SSE2 lane plan has no exit"))
    }
}

fn lower_load(pc: usize, insn: Insn, regs: &[RegState; NUM_REGS]) -> Result<XdpLaneOp, String> {
    if insn.src as usize >= NUM_REGS || insn.dst as usize >= NUM_REGS {
        return Err(format!("pc {pc}: invalid load register"));
    }
    let RegState::Ptr(pointer) = regs[insn.src as usize] else {
        return Err(format!("pc {pc}: load source is not a verified pointer"));
    };
    if !pointer.var.is_const() {
        return Err(format!(
            "pc {pc}: load offset is not constant on every path"
        ));
    }
    let variable = i64::try_from(pointer.var.umin)
        .map_err(|_| format!("pc {pc}: load offset exceeds signed address range"))?;
    let offset = pointer
        .off
        .checked_add(variable)
        .and_then(|value| value.checked_add(insn.off as i64))
        .ok_or_else(|| format!("pc {pc}: load offset overflows"))?;
    let size = insn.mem_size();
    match pointer.kind {
        PtrKind::Ctx if size == 4 && offset == 0 => Ok(XdpLaneOp::Data { dst: insn.dst }),
        PtrKind::Ctx if size == 4 && offset == 4 => Ok(XdpLaneOp::DataEnd { dst: insn.dst }),
        PtrKind::Packet { range } => {
            let offset = usize::try_from(offset)
                .map_err(|_| format!("pc {pc}: packet load has a negative offset"))?;
            let end = offset
                .checked_add(size)
                .ok_or_else(|| format!("pc {pc}: packet load range overflows"))?;
            if end > range as usize {
                return Err(format!(
                    "pc {pc}: packet load exceeds its verifier-proven range"
                ));
            }
            Ok(XdpLaneOp::PacketLoad {
                dst: insn.dst,
                offset,
                size,
                signed: insn.mem_mode() == mode::MEMSX,
            })
        }
        _ => Err(format!(
            "pc {pc}: lane translation only accepts XDP data/data_end and packet loads"
        )),
    }
}

fn execute_alu(insn: Insn, regs: &mut [u64; NUM_REGS]) -> Result<(), &'static str> {
    let dst = insn.dst as usize;
    let b = if insn.is_src_reg() {
        regs[insn.src as usize]
    } else {
        insn.imm as i64 as u64
    };
    let a = regs[dst];
    regs[dst] = if insn.class() == class::ALU {
        let (a, b) = (a as u32, b as u32);
        (match insn.op() {
            alu::ADD => a.wrapping_add(b),
            alu::SUB => a.wrapping_sub(b),
            alu::MUL => a.wrapping_mul(b),
            alu::DIV if insn.off == 1 => signed_div32(a, b),
            alu::DIV => a.checked_div(b).unwrap_or(0),
            alu::MOD if insn.off == 1 => signed_mod32(a, b),
            alu::MOD => a.checked_rem(b).unwrap_or(a),
            alu::OR => a | b,
            alu::AND => a & b,
            alu::LSH => a.wrapping_shl(b),
            alu::RSH => a.wrapping_shr(b),
            alu::ARSH => (a as i32).wrapping_shr(b) as u32,
            alu::XOR => a ^ b,
            alu::NEG => (a as i32).wrapping_neg() as u32,
            alu::MOV => match insn.off {
                8 => b as u8 as i8 as i32 as u32,
                16 => b as u16 as i16 as i32 as u32,
                _ => b,
            },
            alu::END if insn.is_src_reg() => match insn.imm {
                16 => (a as u16).swap_bytes() as u32,
                _ => a.swap_bytes(),
            },
            alu::END => match insn.imm {
                16 => a as u16 as u32,
                _ => a,
            },
            _ => return Err("bad ALU operation"),
        }) as u64
    } else {
        match insn.op() {
            alu::ADD => a.wrapping_add(b),
            alu::SUB => a.wrapping_sub(b),
            alu::MUL => a.wrapping_mul(b),
            alu::DIV if insn.off == 1 => signed_div64(a, b),
            alu::DIV => a.checked_div(b).unwrap_or(0),
            alu::MOD if insn.off == 1 => signed_mod64(a, b),
            alu::MOD => a.checked_rem(b).unwrap_or(a),
            alu::OR => a | b,
            alu::AND => a & b,
            alu::LSH => a.wrapping_shl(b as u32),
            alu::RSH => a.wrapping_shr(b as u32),
            alu::ARSH => (a as i64).wrapping_shr(b as u32) as u64,
            alu::XOR => a ^ b,
            alu::NEG => (a as i64).wrapping_neg() as u64,
            alu::MOV => match insn.off {
                8 => b as u8 as i8 as i64 as u64,
                16 => b as u16 as i16 as i64 as u64,
                32 => b as u32 as i32 as i64 as u64,
                _ => b,
            },
            alu::END => match insn.imm {
                16 => (a as u16).swap_bytes() as u64,
                32 => (a as u32).swap_bytes() as u64,
                _ => a.swap_bytes(),
            },
            _ => return Err("bad ALU operation"),
        }
    };
    Ok(())
}

fn branch_target(pc: usize, insn: Insn, regs: &[u64; NUM_REGS]) -> Result<usize, &'static str> {
    if insn.op() == jmp::JA {
        let relative = if insn.class() == class::JMP32 {
            insn.imm as i64
        } else {
            insn.off as i64
        };
        return Ok((pc as i64 + 1 + relative) as usize);
    }
    let a = regs[insn.dst as usize];
    let b = if insn.is_src_reg() {
        regs[insn.src as usize]
    } else {
        insn.imm as i64 as u64
    };
    let taken = if insn.class() == class::JMP32 {
        compare32(insn.op(), a as u32, b as u32)?
    } else {
        compare64(insn.op(), a, b)?
    };
    Ok(if taken {
        (pc as i64 + 1 + insn.off as i64) as usize
    } else {
        pc + 1
    })
}

fn compare32(op: u8, a: u32, b: u32) -> Result<bool, &'static str> {
    let (sa, sb) = (a as i32, b as i32);
    Ok(match op {
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
        _ => return Err("bad branch operation"),
    })
}

fn compare64(op: u8, a: u64, b: u64) -> Result<bool, &'static str> {
    let (sa, sb) = (a as i64, b as i64);
    Ok(match op {
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
        _ => return Err("bad branch operation"),
    })
}

fn load_le(bytes: &[u8], signed: bool) -> u64 {
    match (bytes.len(), signed) {
        (1, true) => bytes[0] as i8 as i64 as u64,
        (2, true) => i16::from_le_bytes(bytes.try_into().unwrap()) as i64 as u64,
        (4, true) => i32::from_le_bytes(bytes.try_into().unwrap()) as i64 as u64,
        (1, false) => bytes[0] as u64,
        (2, false) => u16::from_le_bytes(bytes.try_into().unwrap()) as u64,
        (4, false) => u32::from_le_bytes(bytes.try_into().unwrap()) as u64,
        (8, false) => u64::from_le_bytes(bytes.try_into().unwrap()),
        _ => unreachable!("verifier-approved load size"),
    }
}

fn signed_div32(a: u32, b: u32) -> u32 {
    if b == 0 {
        0
    } else {
        (a as i32).wrapping_div(b as i32) as u32
    }
}
fn signed_mod32(a: u32, b: u32) -> u32 {
    if b == 0 {
        a
    } else {
        (a as i32).wrapping_rem(b as i32) as u32
    }
}
fn signed_div64(a: u64, b: u64) -> u64 {
    if b == 0 {
        0
    } else {
        (a as i64).wrapping_div(b as i64) as u64
    }
}
fn signed_mod64(a: u64, b: u64) -> u64 {
    if b == 0 {
        a
    } else {
        (a as i64).wrapping_rem(b as i64) as u64
    }
}

fn runtime_error(lane: usize, pc: usize, message: impl Into<String>) -> LaneRuntimeError {
    LaneRuntimeError {
        lane,
        pc,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asm;

    fn compile(source: &str) -> (Program, XdpLaneProgram) {
        let assembled = asm::assemble(source).unwrap();
        let program = Program {
            insns: assembled.insns,
            maps: assembled.maps,
            btf_ctx: None,
        };
        let verified = crate::verifier::verify(
            &program.insns,
            &program.maps,
            &[],
            Config {
                ctx_size: 24,
                ctx_writable: false,
                xdp: true,
                ..Config::default()
            },
        )
        .unwrap();
        let lanes = XdpLaneProgram::compile(&program, &verified, LaneWidth::Four).unwrap();
        (program, lanes)
    }

    #[test]
    fn validates_divergent_ethernet_lanes_and_scalar_remainder() {
        let (program, lanes) = compile(
            "r0 = 18\n\
             r2 = *(u32 *)(r1 + 4)\n\
             r1 = *(u32 *)(r1 + 0)\n\
             r3 = r1\n\
             r3 += 14\n\
             if r3 > r2 goto +4\n\
             r1 = *(u16 *)(r1 + 12)\n\
             r0 = 16\n\
             if r1 == 8 goto +1\n\
             r0 = 17\n\
             exit",
        );
        let mut ipv4 = vec![0u8; 14];
        ipv4[12..14].copy_from_slice(&[0x08, 0x00]);
        let mut ipv6 = vec![0u8; 14];
        ipv6[12..14].copy_from_slice(&[0x86, 0xdd]);
        let frames = vec![
            XdpFrame::new(&[]),
            XdpFrame::new(&[0; 13]),
            XdpFrame::new(&ipv4),
            XdpFrame::new(&ipv6),
            XdpFrame::new(&ipv4),
            XdpFrame::new(&ipv6),
            XdpFrame::new(&ipv4),
        ];
        assert_eq!(lanes.validate(&program, &frames).unwrap().inputs, 7);
        let results: Vec<_> = lanes
            .execute(&frames)
            .unwrap()
            .into_iter()
            .map(|v| v.return_value)
            .collect();
        assert_eq!(results, [18, 18, 16, 17, 16, 17, 16]);
    }

    #[test]
    fn rejects_effectful_and_backward_programs() {
        let stored = asm::assemble("*(u32 *)(r1 + 8) = 1\nr0 = 0\nexit").unwrap();
        let verified = crate::verifier::verify(
            &stored.insns,
            &stored.maps,
            &[],
            Config {
                ctx_size: 24,
                ctx_writable: true,
                ..Config::default()
            },
        )
        .unwrap();
        let program = Program {
            insns: stored.insns,
            maps: stored.maps,
            btf_ctx: None,
        };
        assert!(
            XdpLaneProgram::compile(&program, &verified, LaneWidth::Four)
                .unwrap_err()
                .contains("stores")
        );

        let looped = asm::assemble("r0 = 2\nr1 = 1\nr1 -= 1\nif r1 != 0 goto -2\nexit").unwrap();
        let verified =
            crate::verifier::verify(&looped.insns, &looped.maps, &[], Config::default()).unwrap();
        let program = Program {
            insns: looped.insns,
            maps: looped.maps,
            btf_ctx: None,
        };
        assert!(XdpLaneProgram::compile(&program, &verified, LaneWidth::Two)
            .unwrap_err()
            .contains("backward"));
    }

    #[test]
    fn branchless_plan_selects_host_simd_and_matches_scalar_lanes() {
        let (program, lanes) = compile("r0 = 5\nr0 += 3\nexit");
        let frames = vec![XdpFrame::new(&[]); 7];
        assert_eq!(
            lanes.execute(&frames).unwrap(),
            lanes.execute_scalar(&frames).unwrap()
        );
        assert_eq!(lanes.validate(&program, &frames).unwrap().inputs, 7);
        assert_eq!(
            lanes.plan_key().cpu_features,
            LaneCpuFeatures::detect().bits()
        );
        let (_, other) = compile("r0 = 9\nexit");
        assert_ne!(lanes.plan_key().program, other.plan_key().program);
        let features = LaneCpuFeatures::detect();
        if features.avx2 {
            assert_eq!(lanes.backend(), LaneBackend::X86Avx2);
        } else if features.sse2 {
            assert_eq!(lanes.backend(), LaneBackend::X86Sse2);
        } else {
            assert_eq!(lanes.backend(), LaneBackend::ScalarInterleaved);
        }
    }
}
