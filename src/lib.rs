#![cfg_attr(not(feature = "std"), no_std)]

//! # febpf — a fast userland eBPF engine
//!
//! A zero-dependency eBPF virtual machine with its own kernel-style verifier,
//! an assembler/disassembler for the kernel-documentation "pseudo-C" syntax,
//! program analysis tooling and an interactive debugger.
//!
//! ```
//! let prog = febpf::asm::assemble(r#"
//!     r0 = 0
//!     r2 = 10
//! loop:
//!     r0 += r2
//!     r2 -= 1
//!     if r2 != 0 goto loop
//!     exit
//! "#).unwrap();
//! let mut vm = febpf::Vm::new(febpf::Program { insns: prog.insns, maps: prog.maps, btf_ctx: None }).unwrap();
//! vm.verify(febpf::verifier::Config::default()).unwrap();
//! assert_eq!(vm.run(&mut []).unwrap(), 55);
//! ```

extern crate alloc;

#[cfg(feature = "std")]
pub mod analysis;
pub mod asm;
pub mod btf;
pub mod builder;
#[cfg(feature = "std")]
pub mod dce;
#[cfg(feature = "std")]
pub mod debug;
pub mod debuginfo;
pub mod disasm;
#[cfg(feature = "std")]
pub mod elf;
#[cfg(feature = "std")]
pub mod equiv;
#[cfg(feature = "std")]
pub mod fuzz;
pub mod helpers;
pub mod insn;
pub mod interp;
#[cfg(feature = "jit")]
pub mod jit;
#[cfg(feature = "std")]
pub mod kbpf;
pub mod maps;
#[cfg(feature = "std")]
pub mod optimize;
#[cfg(feature = "std")]
pub mod pcap;
#[cfg(feature = "std")]
pub mod playground;
#[cfg(feature = "std")]
pub mod race;
#[cfg(feature = "std")]
pub mod relo;
pub mod replay;
pub mod tnum;
pub mod verifier;

#[cfg(all(test, feature = "std"))]
mod soundness;

#[cfg(all(target_arch = "wasm32", feature = "std"))]
mod wasm;

pub use interp::{EbpfError, Machine, MetadataLayout, Program, RegionAccess, Vm};
pub use verifier::{Config as VerifierConfig, VerifyError};
