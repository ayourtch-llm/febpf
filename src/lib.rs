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
//! let mut vm = febpf::Vm::new(febpf::Program { insns: prog.insns, maps: prog.maps }).unwrap();
//! vm.verify(febpf::verifier::Config::default()).unwrap();
//! assert_eq!(vm.run(&mut []).unwrap(), 55);
//! ```

pub mod analysis;
pub mod asm;
pub mod btf;
pub mod debug;
pub mod disasm;
pub mod elf;
pub mod fuzz;
pub mod helpers;
pub mod insn;
pub mod interp;
pub mod jit;
pub mod kbpf;
pub mod maps;
pub mod relo;
pub mod tnum;
pub mod verifier;

pub use interp::{EbpfError, Machine, Program, Vm};
pub use verifier::{Config as VerifierConfig, VerifyError};
