//! Versioned native C ABI.
//!
//! This module owns only marshalling and opaque handles. Invocation resources
//! are translated into [`crate::ExecutionEnvironment`] values for one call;
//! no C pointer or callback becomes durable VM state.

use crate::execution::{ExecutionEnvironment, ExecutionOutcome};
use crate::verifier::{Config, UninitStackPolicy};
use crate::{asm, elf, insn, Program, Vm};
use std::cell::RefCell;
use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr::null_mut;
use std::slice;
use std::str;

pub const ABI_VERSION: u32 = 1;

pub const STATUS_OK: u32 = 0;
pub const STATUS_INVALID_ARGUMENT: u32 = 1;
pub const STATUS_PROGRAM: u32 = 2;
pub const STATUS_VERIFY: u32 = 3;
pub const STATUS_RUNTIME: u32 = 4;
pub const STATUS_UNSUPPORTED: u32 = 5;
pub const STATUS_PANIC: u32 = 255;

pub const CONTEXT_FLAT: u32 = 0;
pub const CONTEXT_XDP: u32 = 1;
pub const CONTEXT_SKB: u32 = 2;

pub const VERIFY_CONTEXT_WRITABLE: u32 = 1 << 0;
pub const VERIFY_STRICT_ALIGNMENT: u32 = 1 << 1;
pub const VERIFY_ALLOW_UNINITIALIZED_STACK: u32 = 1 << 2;
const VERIFY_KNOWN_FLAGS: u32 =
    VERIFY_CONTEXT_WRITABLE | VERIFY_STRICT_ALIGNMENT | VERIFY_ALLOW_UNINITIALIZED_STACK;

pub const INVOCATION_JIT: u32 = 1 << 0;
const INVOCATION_KNOWN_FLAGS: u32 = INVOCATION_JIT;

pub const OUTPUT_PRINTK: u32 = 1;
pub const OUTPUT_SEQUENCE: u32 = 2;

const ELF_KNOWN_FLAGS: u32 = 0;

pub type OutputFn =
    unsafe extern "C" fn(user_data: *mut c_void, kind: u32, data: *const u8, len: usize);

/// Verification configuration. Set `struct_size = sizeof(febpf_verify_options_v1)`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VerifyOptionsV1 {
    pub struct_size: usize,
    pub context_model: u32,
    pub flags: u32,
    pub context_size: usize,
    pub verifier_instruction_budget: usize,
    pub runtime_instruction_limit: u64,
}

/// Per-call resources. Set `struct_size = sizeof(febpf_invocation_v1)`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct InvocationV1 {
    pub struct_size: usize,
    pub flags: u32,
    pub reserved: u32,
    pub context: *mut u8,
    pub context_len: usize,
    pub packet: *mut u8,
    pub packet_len: usize,
    pub output: Option<OutputFn>,
    pub output_user_data: *mut c_void,
}

/// ELF loading configuration. Set `struct_size = sizeof(febpf_elf_options_v1)`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ElfOptionsV1 {
    pub struct_size: usize,
    pub flags: u32,
    pub reserved: u32,
    pub program_name: *const u8,
    pub program_name_len: usize,
    pub target_btf: *const u8,
    pub target_btf_len: usize,
}

/// Opaque to C callers.
pub struct CApiVm {
    vm: Vm,
    verified_model: Option<VerifiedModel>,
    required_model: Option<VerifiedModel>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VerifiedModel {
    Flat,
    Xdp,
    Skb,
}

type CResult<T> = Result<T, (u32, String)>;

thread_local! {
    static LAST_ERROR: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn clear_error() {
    LAST_ERROR.with(|slot| slot.borrow_mut().clear());
}

fn set_error(message: impl AsRef<str>) {
    LAST_ERROR.with(|slot| {
        let mut bytes = slot.borrow_mut();
        bytes.clear();
        bytes.extend(
            message
                .as_ref()
                .as_bytes()
                .iter()
                .map(|byte| if *byte == 0 { b'?' } else { *byte }),
        );
    });
}

fn boundary(action: impl FnOnce() -> CResult<()>) -> u32 {
    clear_error();
    match catch_unwind(AssertUnwindSafe(action)) {
        Ok(Ok(())) => STATUS_OK,
        Ok(Err((status, message))) => {
            set_error(message);
            status
        }
        Err(_) => {
            set_error("panic caught at febpf C ABI boundary");
            STATUS_PANIC
        }
    }
}

fn invalid(message: impl Into<String>) -> (u32, String) {
    (STATUS_INVALID_ARGUMENT, message.into())
}

unsafe fn bytes<'a>(pointer: *const u8, len: usize, name: &str) -> CResult<&'a [u8]> {
    if len == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() {
        return Err(invalid(format!("{name} is null but length is {len}")));
    }
    // SAFETY: the C caller promises a readable region of `len` bytes.
    Ok(unsafe { slice::from_raw_parts(pointer, len) })
}

unsafe fn bytes_mut<'a>(pointer: *mut u8, len: usize, name: &str) -> CResult<&'a mut [u8]> {
    if len == 0 {
        return Ok(&mut []);
    }
    if pointer.is_null() {
        return Err(invalid(format!("{name} is null but length is {len}")));
    }
    // SAFETY: the C caller promises a uniquely borrowed writable region of
    // `len` bytes for the duration of this call.
    Ok(unsafe { slice::from_raw_parts_mut(pointer, len) })
}

unsafe fn vm_mut<'a>(pointer: *mut CApiVm) -> CResult<&'a mut CApiVm> {
    // SAFETY: validation below excludes null; the caller owns this handle and
    // promises exclusive access for the call.
    unsafe { pointer.as_mut() }.ok_or_else(|| invalid("VM handle is null"))
}

fn require_struct(actual: usize, expected: usize, name: &str) -> CResult<()> {
    if actual < expected {
        Err(invalid(format!(
            "{name}.struct_size is {actual}, need at least {expected}"
        )))
    } else {
        Ok(())
    }
}

unsafe fn input_struct<T: Copy>(pointer: *const T, name: &str) -> CResult<T> {
    if pointer.is_null() {
        return Err(invalid(format!("{name} is null")));
    }
    // SAFETY: every versioned C input starts with `size_t struct_size`; this
    // reads only that word before assuming the current structure is present.
    let actual = unsafe { pointer.cast::<usize>().read_unaligned() };
    require_struct(actual, core::mem::size_of::<T>(), name)?;
    // SAFETY: after the size check the caller promises a complete T. Copying
    // snapshots the descriptor and avoids retaining a reference into C memory.
    Ok(unsafe { pointer.read_unaligned() })
}

/// Return the native ABI version implemented by this library.
#[no_mangle]
pub extern "C" fn febpf_c_abi_version() -> u32 {
    ABI_VERSION
}

/// Copy the calling thread's last diagnostic and return its full byte length.
/// The destination is always NUL-terminated when `capacity > 0`.
///
/// # Safety
/// A non-null `destination` must be writable for `capacity` bytes.
#[no_mangle]
pub unsafe extern "C" fn febpf_last_error(destination: *mut u8, capacity: usize) -> usize {
    LAST_ERROR.with(|slot| {
        let error = slot.borrow();
        if capacity != 0 && !destination.is_null() {
            let copied = error.len().min(capacity - 1);
            // SAFETY: the caller supplies a writable destination and `copied`
            // is bounded by its declared capacity.
            unsafe {
                destination.copy_from_nonoverlapping(error.as_ptr(), copied);
                destination.add(copied).write(0);
            }
        }
        error.len()
    })
}

/// Construct an opaque VM from febpf assembly source.
///
/// # Safety
/// `source` must be readable for `source_len`; `output` must be writable.
#[no_mangle]
pub unsafe extern "C" fn febpf_vm_create_assembly(
    source: *const u8,
    source_len: usize,
    output: *mut *mut CApiVm,
) -> u32 {
    boundary(|| {
        if output.is_null() {
            return Err(invalid("output VM pointer is null"));
        }
        // SAFETY: output was checked and is caller-owned.
        unsafe { output.write(null_mut()) };
        // SAFETY: caller contract is forwarded to the checked helper.
        let source = unsafe { bytes(source, source_len, "assembly source")? };
        let source = str::from_utf8(source)
            .map_err(|error| (STATUS_PROGRAM, format!("assembly is not UTF-8: {error}")))?;
        let assembled = asm::assemble(source)
            .map_err(|error| (STATUS_PROGRAM, format!("assembly failed: {error}")))?;
        let vm = Vm::new(Program {
            insns: assembled.insns,
            maps: assembled.maps,
            btf_ctx: None,
        })
        .map_err(|error| (STATUS_PROGRAM, format!("program creation failed: {error}")))?;
        let handle = Box::into_raw(Box::new(CApiVm {
            vm,
            verified_model: None,
            required_model: None,
        }));
        // SAFETY: output was checked and receives the newly owned handle.
        unsafe { output.write(handle) };
        Ok(())
    })
}

/// Construct an opaque VM from raw little-endian 8-byte eBPF instruction slots.
///
/// # Safety
/// `program` must be readable for `program_len`; `output` must be writable.
#[no_mangle]
pub unsafe extern "C" fn febpf_vm_create_bytecode(
    program: *const u8,
    program_len: usize,
    output: *mut *mut CApiVm,
) -> u32 {
    boundary(|| {
        if output.is_null() {
            return Err(invalid("output VM pointer is null"));
        }
        // SAFETY: output was checked and is caller-owned.
        unsafe { output.write(null_mut()) };
        // SAFETY: caller contract is forwarded to the checked helper.
        let program = unsafe { bytes(program, program_len, "bytecode")? };
        let insns = insn::decode_program(program)
            .map_err(|error| (STATUS_PROGRAM, format!("bytecode decode failed: {error}")))?;
        let vm = Vm::new(Program {
            insns,
            maps: Vec::new(),
            btf_ctx: None,
        })
        .map_err(|error| (STATUS_PROGRAM, format!("program creation failed: {error}")))?;
        let handle = Box::into_raw(Box::new(CApiVm {
            vm,
            verified_model: None,
            required_model: None,
        }));
        // SAFETY: output was checked and receives the newly owned handle.
        unsafe { output.write(handle) };
        Ok(())
    })
}

fn required_model(kind: elf::ProgramKind) -> Option<VerifiedModel> {
    if kind.is_xdp() {
        Some(VerifiedModel::Xdp)
    } else if kind.is_skb() {
        Some(VerifiedModel::Skb)
    } else {
        None
    }
}

fn model_name(model: VerifiedModel) -> &'static str {
    match model {
        VerifiedModel::Flat => "Flat",
        VerifiedModel::Xdp => "XDP",
        VerifiedModel::Skb => "skb",
    }
}

/// Construct an opaque VM from a relocatable eBPF ELF object.
///
/// # Safety
/// Object/options-selected byte regions must be readable and `output` writable.
#[no_mangle]
pub unsafe extern "C" fn febpf_vm_create_elf(
    object: *const u8,
    object_len: usize,
    options: *const ElfOptionsV1,
    output: *mut *mut CApiVm,
) -> u32 {
    boundary(|| {
        if output.is_null() {
            return Err(invalid("output VM pointer is null"));
        }
        // SAFETY: output was checked and is caller-owned.
        unsafe { output.write(null_mut()) };
        // SAFETY: caller promises a versioned readable input structure.
        let options = unsafe { input_struct(options, "ELF options")? };
        if options.flags & !ELF_KNOWN_FLAGS != 0 {
            return Err(invalid(format!(
                "unknown ELF flags 0x{:x}",
                options.flags & !ELF_KNOWN_FLAGS
            )));
        }
        if options.reserved != 0 {
            return Err(invalid("ELF options.reserved must be zero"));
        }
        // SAFETY: caller contracts are forwarded to checked helpers.
        let object = unsafe { bytes(object, object_len, "ELF object")? };
        let selector = unsafe {
            bytes(
                options.program_name,
                options.program_name_len,
                "ELF program name",
            )?
        };
        let selector = str::from_utf8(selector)
            .map_err(|error| invalid(format!("ELF program name is not UTF-8: {error}")))?;
        let target_input =
            unsafe { bytes(options.target_btf, options.target_btf_len, "target BTF")? };
        if target_input.is_empty() && elf::needs_kernel_btf(object) {
            return Err((
                STATUS_PROGRAM,
                "ELF object requires target BTF for CO-RE or a BTF-typed context".into(),
            ));
        }
        let target = if target_input.is_empty() {
            None
        } else if target_input.starts_with(b"\x7fELF") {
            Some(
                elf::read_section(target_input, ".BTF")
                    .map_err(|error| (STATUS_PROGRAM, format!("target BTF ELF: {error}")))?
                    .ok_or_else(|| {
                        (
                            STATUS_PROGRAM,
                            "target BTF ELF has no nonempty .BTF section".into(),
                        )
                    })?
                    .0,
            )
        } else {
            Some(target_input.to_vec())
        };
        let mut loaded = elf::load_with_target_btf(object, target.as_deref())
            .map_err(|error| (STATUS_PROGRAM, format!("ELF loading failed: {error}")))?;
        if !loaded.warnings.is_empty() {
            return Err((
                STATUS_PROGRAM,
                format!(
                    "ELF loading produced unsupported warnings: {}",
                    loaded.warnings.join("; ")
                ),
            ));
        }
        if !loaded.prog_array_inits.is_empty() {
            return Err((
                STATUS_UNSUPPORTED,
                "ELF static PROG_ARRAY initialization is not supported by C ABI v1".into(),
            ));
        }
        let index = if selector.is_empty() {
            if loaded.programs.len() != 1 {
                let names: Vec<&str> = loaded
                    .programs
                    .iter()
                    .map(|program| program.name.as_str())
                    .collect();
                return Err((
                    STATUS_PROGRAM,
                    format!(
                        "ELF program name is required; available: {}",
                        names.join(", ")
                    ),
                ));
            }
            0
        } else {
            loaded
                .programs
                .iter()
                .position(|program| program.name == selector)
                .ok_or_else(|| {
                    let names: Vec<&str> = loaded
                        .programs
                        .iter()
                        .map(|program| program.name.as_str())
                        .collect();
                    (
                        STATUS_PROGRAM,
                        format!(
                            "no ELF program '{selector}'; available: {}",
                            names.join(", ")
                        ),
                    )
                })?
        };
        let chosen = loaded.programs.swap_remove(index);
        let model = required_model(chosen.kind);
        let vm = Vm::new(Program {
            insns: chosen.insns,
            maps: loaded.maps,
            btf_ctx: chosen.btf_ctx,
        })
        .map_err(|error| (STATUS_PROGRAM, format!("program creation failed: {error}")))?;
        let handle = Box::into_raw(Box::new(CApiVm {
            vm,
            verified_model: None,
            required_model: model,
        }));
        // SAFETY: output was checked and receives the newly owned handle.
        unsafe { output.write(handle) };
        Ok(())
    })
}

/// Destroy one VM handle. A handle must be destroyed exactly once.
///
/// # Safety
/// `handle` must be null or returned by a successful febpf create call.
#[no_mangle]
pub unsafe extern "C" fn febpf_vm_destroy(handle: *mut CApiVm) -> u32 {
    boundary(|| {
        if handle.is_null() {
            return Ok(());
        }
        // SAFETY: caller promises unique ownership of this live handle.
        drop(unsafe { Box::from_raw(handle) });
        Ok(())
    })
}

/// Verify a VM and select the context ABI accepted by later invocations.
///
/// # Safety
/// Both pointers must be live and exclusively borrowed for this call.
#[no_mangle]
pub unsafe extern "C" fn febpf_vm_verify(
    handle: *mut CApiVm,
    options: *const VerifyOptionsV1,
) -> u32 {
    boundary(|| {
        // SAFETY: caller contract is forwarded to the checked helper.
        let handle = unsafe { vm_mut(handle)? };
        // SAFETY: caller promises a versioned readable input structure.
        let options = unsafe { input_struct(options, "verify options")? };
        if options.flags & !VERIFY_KNOWN_FLAGS != 0 {
            return Err(invalid(format!(
                "unknown verify flags 0x{:x}",
                options.flags & !VERIFY_KNOWN_FLAGS
            )));
        }
        let (model, ctx_size, xdp, skb) = match options.context_model {
            CONTEXT_FLAT => (VerifiedModel::Flat, options.context_size, false, false),
            CONTEXT_XDP => (VerifiedModel::Xdp, 24, true, false),
            CONTEXT_SKB => (VerifiedModel::Skb, 192, false, true),
            value => {
                return Err((
                    STATUS_UNSUPPORTED,
                    format!("unsupported C ABI context model {value}"),
                ))
            }
        };
        if let Some(required) = handle.required_model {
            if model != required {
                return Err((
                    STATUS_VERIFY,
                    format!(
                        "ELF entry requires {} context model, got {}",
                        model_name(required),
                        model_name(model)
                    ),
                ));
            }
        }
        let mut config = Config {
            ctx_size,
            ctx_writable: options.flags & VERIFY_CONTEXT_WRITABLE != 0,
            strict_alignment: options.flags & VERIFY_STRICT_ALIGNMENT != 0,
            xdp,
            skb,
            uninit_stack: if options.flags & VERIFY_ALLOW_UNINITIALIZED_STACK != 0 {
                UninitStackPolicy::Allow
            } else {
                UninitStackPolicy::Strict
            },
            ..Config::default()
        };
        if xdp || skb {
            config.ctx_writable = false;
        }
        if options.verifier_instruction_budget != 0 {
            config.insn_budget = options.verifier_instruction_budget;
        }
        handle
            .vm
            .verify(config)
            .map_err(|error| (STATUS_VERIFY, error.to_string()))?;
        handle.vm.insn_limit = if options.runtime_instruction_limit == 0 {
            u64::MAX
        } else {
            options.runtime_instruction_limit
        };
        handle.verified_model = Some(model);
        Ok(())
    })
}

fn execute(
    vm: &mut Vm,
    environment: ExecutionEnvironment<'_>,
    jit: bool,
) -> CResult<ExecutionOutcome> {
    if !jit {
        return vm
            .run_environment(environment)
            .map_err(|error| (STATUS_RUNTIME, error.to_string()));
    }
    #[cfg(feature = "jit")]
    {
        vm.run_environment_jit(environment)
            .map_err(|error| (STATUS_RUNTIME, error.to_string()))
    }
    #[cfg(not(feature = "jit"))]
    {
        let _ = (vm, environment);
        Err((
            STATUS_UNSUPPORTED,
            "this febpf library was built without JIT support".into(),
        ))
    }
}

fn emit_outputs(invocation: &InvocationV1, printk: &[String], sequence: &[u8]) {
    let Some(output) = invocation.output else {
        return;
    };
    for line in printk {
        // SAFETY: the C caller supplied this callback and user-data token; the
        // byte slice remains live for the duration of the call.
        unsafe {
            output(
                invocation.output_user_data,
                OUTPUT_PRINTK,
                line.as_ptr(),
                line.len(),
            )
        };
    }
    if !sequence.is_empty() {
        // SAFETY: same callback contract as above.
        unsafe {
            output(
                invocation.output_user_data,
                OUTPUT_SEQUENCE,
                sequence.as_ptr(),
                sequence.len(),
            )
        };
    }
}

fn run_flat(handle: &mut CApiVm, invocation: &InvocationV1, jit: bool) -> CResult<u64> {
    if invocation.packet_len != 0 {
        return Err(invalid("flat invocation must not supply a packet"));
    }
    // SAFETY: pointer validity is part of the invocation's C contract.
    let context = unsafe { bytes_mut(invocation.context, invocation.context_len, "context")? };
    let mut printk = Vec::new();
    let mut sequence = Vec::new();
    let environment = ExecutionEnvironment::plain(context)
        .with_printk(&mut printk, false)
        .with_seq_output(&mut sequence);
    let outcome = execute(&mut handle.vm, environment, jit);
    emit_outputs(invocation, &printk, &sequence);
    Ok(outcome?.return_value)
}

fn run_xdp(handle: &mut CApiVm, invocation: &InvocationV1, jit: bool) -> CResult<u64> {
    if invocation.context_len != 0 {
        return Err(invalid(
            "XDP invocation uses synthesized context; context_len must be zero",
        ));
    }
    // SAFETY: pointer validity is part of the invocation's C contract.
    let packet = unsafe { bytes_mut(invocation.packet, invocation.packet_len, "packet")? };
    let mut printk = Vec::new();
    let mut sequence = Vec::new();
    let environment = ExecutionEnvironment::xdp_slice(packet)
        .map_err(|error| (STATUS_RUNTIME, error))?
        .with_printk(&mut printk, false)
        .with_seq_output(&mut sequence);
    let outcome = execute(&mut handle.vm, environment, jit);
    emit_outputs(invocation, &printk, &sequence);
    Ok(outcome?.return_value)
}

fn run_skb(handle: &mut CApiVm, invocation: &InvocationV1, jit: bool) -> CResult<u64> {
    if invocation.context_len != 0 {
        return Err(invalid(
            "skb invocation uses synthesized context; context_len must be zero",
        ));
    }
    // SAFETY: pointer validity is part of the invocation's C contract.
    let packet = unsafe { bytes_mut(invocation.packet, invocation.packet_len, "packet")? };
    let mut printk = Vec::new();
    let mut sequence = Vec::new();
    let environment = ExecutionEnvironment::skb(packet)
        .map_err(|error| (STATUS_RUNTIME, error))?
        .with_printk(&mut printk, false)
        .with_seq_output(&mut sequence);
    let outcome = execute(&mut handle.vm, environment, jit);
    emit_outputs(invocation, &printk, &sequence);
    Ok(outcome?.return_value)
}

/// Execute once with caller-owned invocation resources.
///
/// # Safety
/// The handle, descriptor, result pointer, and descriptor-selected buffers
/// must be live and exclusively borrowed for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn febpf_vm_run(
    handle: *mut CApiVm,
    invocation: *const InvocationV1,
    result: *mut u64,
) -> u32 {
    boundary(|| {
        if result.is_null() {
            return Err(invalid("result pointer is null"));
        }
        // SAFETY: caller contract is forwarded to the checked helper.
        let handle = unsafe { vm_mut(handle)? };
        // SAFETY: caller promises a versioned readable input structure.
        let invocation = unsafe { input_struct(invocation, "invocation")? };
        if invocation.reserved != 0 {
            return Err(invalid("invocation.reserved must be zero"));
        }
        if invocation.flags & !INVOCATION_KNOWN_FLAGS != 0 {
            return Err(invalid(format!(
                "unknown invocation flags 0x{:x}",
                invocation.flags & !INVOCATION_KNOWN_FLAGS
            )));
        }
        let model = handle.verified_model.ok_or_else(|| {
            (
                STATUS_VERIFY,
                "VM has not been successfully verified".into(),
            )
        })?;
        let jit = invocation.flags & INVOCATION_JIT != 0;
        let value = match model {
            VerifiedModel::Flat => run_flat(handle, &invocation, jit)?,
            VerifiedModel::Xdp => run_xdp(handle, &invocation, jit)?,
            VerifiedModel::Skb => run_skb(handle, &invocation, jit)?,
        };
        // SAFETY: result was checked and is caller-owned.
        unsafe { result.write(value) };
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    fn create(source: &str) -> *mut CApiVm {
        let mut vm = null_mut();
        // SAFETY: all pointers refer to live Rust-owned test storage.
        let status = unsafe { febpf_vm_create_assembly(source.as_ptr(), source.len(), &mut vm) };
        assert_eq!(status, STATUS_OK, "{}", last_error());
        assert!(!vm.is_null());
        vm
    }

    fn last_error() -> String {
        let needed = unsafe { febpf_last_error(null_mut(), 0) };
        let mut output = vec![0u8; needed + 1];
        unsafe { febpf_last_error(output.as_mut_ptr(), output.len()) };
        String::from_utf8(output[..needed].to_vec()).unwrap()
    }

    unsafe fn verify(vm: *mut CApiVm, model: u32, context_size: usize) -> u32 {
        let options = VerifyOptionsV1 {
            struct_size: size_of::<VerifyOptionsV1>(),
            context_model: model,
            flags: VERIFY_CONTEXT_WRITABLE,
            context_size,
            verifier_instruction_budget: 0,
            runtime_instruction_limit: 0,
        };
        unsafe { febpf_vm_verify(vm, &options) }
    }

    #[test]
    fn flat_invocation_mutates_context_and_reports_printk() {
        let vm = create(
            "r6 = r1\n\
             r1 = 0x0064253d6e ll\n\
             *(u64 *)(r10 - 8) = r1\n\
             r1 = r10\n\
             r1 += -8\n\
             r2 = 5\n\
             r3 = 42\n\
             call trace_printk\n\
             *(u8 *)(r6 + 1) = 7\n\
             r0 = *(u8 *)(r6 + 0)\n\
             exit",
        );
        assert_eq!(unsafe { verify(vm, CONTEXT_FLAT, 2) }, STATUS_OK);
        let mut context = [9u8, 0];
        let mut output = Vec::<(u32, Vec<u8>)>::new();
        unsafe extern "C" fn collect(
            user_data: *mut c_void,
            kind: u32,
            data: *const u8,
            len: usize,
        ) {
            // SAFETY: the test passes a live vector and callback bytes.
            let output = unsafe { &mut *user_data.cast::<Vec<(u32, Vec<u8>)>>() };
            let bytes = unsafe { slice::from_raw_parts(data, len) };
            output.push((kind, bytes.to_vec()));
        }
        let invocation = InvocationV1 {
            struct_size: size_of::<InvocationV1>(),
            flags: 0,
            reserved: 0,
            context: context.as_mut_ptr(),
            context_len: context.len(),
            packet: null_mut(),
            packet_len: 0,
            output: Some(collect),
            output_user_data: (&mut output as *mut Vec<(u32, Vec<u8>)>).cast(),
        };
        let mut result = 0;
        assert_eq!(
            unsafe { febpf_vm_run(vm, &invocation, &mut result) },
            STATUS_OK,
            "{}",
            last_error()
        );
        assert_eq!(result, 9);
        assert_eq!(context, [9, 7]);
        assert_eq!(output, [(OUTPUT_PRINTK, b"n=42".to_vec())]);
        assert_eq!(unsafe { febpf_vm_destroy(vm) }, STATUS_OK);
    }

    #[test]
    fn xdp_invocation_uses_composed_packet_environment() {
        let vm = create(
            "r2 = *(u32 *)(r1 + 0)\n\
             r3 = *(u32 *)(r1 + 4)\n\
             r4 = r2\n\
             r4 += 1\n\
             if r4 > r3 goto short\n\
             *(u8 *)(r2 + 0) = 99\n\
             r0 = 2\n\
             exit\n\
             short:\n\
             r0 = 1\n\
             exit",
        );
        assert_eq!(unsafe { verify(vm, CONTEXT_XDP, 0) }, STATUS_OK);
        let mut packet = [1u8, 2];
        let invocation = InvocationV1 {
            struct_size: size_of::<InvocationV1>(),
            flags: 0,
            reserved: 0,
            context: null_mut(),
            context_len: 0,
            packet: packet.as_mut_ptr(),
            packet_len: packet.len(),
            output: None,
            output_user_data: null_mut(),
        };
        let mut result = 0;
        assert_eq!(
            unsafe { febpf_vm_run(vm, &invocation, &mut result) },
            STATUS_OK
        );
        assert_eq!(result, 2);
        assert_eq!(packet, [99, 2]);
        assert_eq!(unsafe { febpf_vm_destroy(vm) }, STATUS_OK);
    }

    #[test]
    fn diagnostics_cover_invalid_arguments_and_verifier_rejection() {
        let mut vm = null_mut();
        assert_eq!(
            unsafe { febpf_vm_create_assembly(null_mut(), 1, &mut vm) },
            STATUS_INVALID_ARGUMENT
        );
        assert!(last_error().contains("assembly source is null"));
        let vm = create("exit");
        let truncated = VerifyOptionsV1 {
            struct_size: size_of::<VerifyOptionsV1>() - 1,
            context_model: CONTEXT_FLAT,
            flags: 0,
            context_size: 0,
            verifier_instruction_budget: 0,
            runtime_instruction_limit: 0,
        };
        assert_eq!(
            unsafe { febpf_vm_verify(vm, &truncated) },
            STATUS_INVALID_ARGUMENT
        );
        assert!(last_error().contains("struct_size"));
        assert_eq!(unsafe { verify(vm, CONTEXT_FLAT, 0) }, STATUS_VERIFY);
        assert!(last_error().contains("r0"));
        assert_eq!(unsafe { febpf_vm_destroy(vm) }, STATUS_OK);
    }

    #[test]
    fn output_before_a_runtime_limit_is_still_delivered() {
        let vm = create(
            "r1 = 0x0064253d6e ll\n\
             *(u64 *)(r10 - 8) = r1\n\
             r1 = r10\n\
             r1 += -8\n\
             r2 = 5\n\
             r3 = 42\n\
             call trace_printk\n\
             r0 = 0\n\
             exit",
        );
        let options = VerifyOptionsV1 {
            struct_size: size_of::<VerifyOptionsV1>(),
            context_model: CONTEXT_FLAT,
            flags: 0,
            context_size: 0,
            verifier_instruction_budget: 0,
            runtime_instruction_limit: 8,
        };
        assert_eq!(unsafe { febpf_vm_verify(vm, &options) }, STATUS_OK);
        let mut lines = Vec::<Vec<u8>>::new();
        unsafe extern "C" fn collect(
            user_data: *mut c_void,
            kind: u32,
            data: *const u8,
            len: usize,
        ) {
            if kind == OUTPUT_PRINTK {
                // SAFETY: the test passes live callback state and bytes.
                unsafe { &mut *user_data.cast::<Vec<Vec<u8>>>() }
                    .push(unsafe { slice::from_raw_parts(data, len) }.to_vec());
            }
        }
        let invocation = InvocationV1 {
            struct_size: size_of::<InvocationV1>(),
            flags: 0,
            reserved: 0,
            context: null_mut(),
            context_len: 0,
            packet: null_mut(),
            packet_len: 0,
            output: Some(collect),
            output_user_data: (&mut lines as *mut Vec<Vec<u8>>).cast(),
        };
        let mut result = 99;
        assert_eq!(
            unsafe { febpf_vm_run(vm, &invocation, &mut result) },
            STATUS_RUNTIME
        );
        assert!(last_error().contains("instruction limit"));
        assert_eq!(result, 99, "result is written only on successful exit");
        assert_eq!(lines, [b"n=42".to_vec()]);
        assert_eq!(unsafe { febpf_vm_destroy(vm) }, STATUS_OK);
    }

    #[test]
    fn raw_bytecode_constructor_and_execution_backend_contract() {
        let assembled = asm::assemble("r0 = 55\nexit").unwrap();
        let encoded = insn::encode_program(&assembled.insns);
        let mut vm = null_mut();
        assert_eq!(
            unsafe { febpf_vm_create_bytecode(encoded.as_ptr(), encoded.len(), &mut vm) },
            STATUS_OK
        );
        assert_eq!(unsafe { verify(vm, CONTEXT_FLAT, 0) }, STATUS_OK);
        let invocation = InvocationV1 {
            struct_size: size_of::<InvocationV1>(),
            flags: 0,
            reserved: 0,
            context: null_mut(),
            context_len: 0,
            packet: null_mut(),
            packet_len: 0,
            output: None,
            output_user_data: null_mut(),
        };
        let mut result = 0;
        let truncated_invocation = InvocationV1 {
            struct_size: size_of::<InvocationV1>() - 1,
            ..invocation
        };
        assert_eq!(
            unsafe { febpf_vm_run(vm, &truncated_invocation, &mut result) },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(
            unsafe { febpf_vm_run(vm, &invocation, &mut result) },
            STATUS_OK
        );
        assert_eq!(result, 55);
        let jit_invocation = InvocationV1 {
            flags: INVOCATION_JIT,
            ..invocation
        };
        #[cfg(feature = "jit")]
        {
            result = 0;
            assert_eq!(
                unsafe { febpf_vm_run(vm, &jit_invocation, &mut result) },
                STATUS_OK
            );
            assert_eq!(result, 55);
        }
        #[cfg(not(feature = "jit"))]
        {
            assert_eq!(
                unsafe { febpf_vm_run(vm, &jit_invocation, &mut result) },
                STATUS_UNSUPPORTED
            );
            assert!(last_error().contains("without JIT support"));
        }
        assert_eq!(unsafe { febpf_vm_destroy(vm) }, STATUS_OK);
    }

    #[test]
    fn elf_constructor_selects_and_core_relocates_without_retaining_inputs() {
        let object = include_bytes!("../tests/core_probe.o").to_vec();
        let target = include_bytes!("../tests/core_target.o").to_vec();
        let name = b"text".to_vec();
        let options = ElfOptionsV1 {
            struct_size: size_of::<ElfOptionsV1>(),
            flags: 0,
            reserved: 0,
            program_name: name.as_ptr(),
            program_name_len: name.len(),
            target_btf: target.as_ptr(),
            target_btf_len: target.len(),
        };
        let mut vm = null_mut();
        assert_eq!(
            unsafe { febpf_vm_create_elf(object.as_ptr(), object.len(), &options, &mut vm) },
            STATUS_OK,
            "{}",
            last_error()
        );
        drop((object, target, name));
        assert_eq!(unsafe { verify(vm, CONTEXT_FLAT, 64) }, STATUS_OK);

        let mut context = [0u8; 64];
        context[4..8].copy_from_slice(&100i32.to_le_bytes());
        context[12..16].copy_from_slice(&20i32.to_le_bytes());
        context[16..24].copy_from_slice(&3i64.to_le_bytes());
        let invocation = InvocationV1 {
            struct_size: size_of::<InvocationV1>(),
            flags: 0,
            reserved: 0,
            context: context.as_mut_ptr(),
            context_len: context.len(),
            packet: null_mut(),
            packet_len: 0,
            output: None,
            output_user_data: null_mut(),
        };
        let mut result = 0;
        assert_eq!(
            unsafe { febpf_vm_run(vm, &invocation, &mut result) },
            STATUS_OK
        );
        assert_eq!(result, 123);
        assert_eq!(unsafe { febpf_vm_destroy(vm) }, STATUS_OK);
    }

    #[test]
    fn elf_constructor_rejects_ambiguous_bundles_and_enforces_section_model() {
        let multi = include_bytes!("../tests/multi_entry.o");
        let empty = ElfOptionsV1 {
            struct_size: size_of::<ElfOptionsV1>(),
            flags: 0,
            reserved: 0,
            program_name: null_mut(),
            program_name_len: 0,
            target_btf: null_mut(),
            target_btf_len: 0,
        };
        let mut vm = null_mut();
        assert_eq!(
            unsafe { febpf_vm_create_elf(multi.as_ptr(), multi.len(), &empty, &mut vm) },
            STATUS_PROGRAM
        );
        assert!(last_error().contains("program name is required"));
        assert!(vm.is_null());

        let core = include_bytes!("../tests/core_probe.o");
        let core_name = b"text";
        let no_target = ElfOptionsV1 {
            program_name: core_name.as_ptr(),
            program_name_len: core_name.len(),
            ..empty
        };
        assert_eq!(
            unsafe { febpf_vm_create_elf(core.as_ptr(), core.len(), &no_target, &mut vm) },
            STATUS_PROGRAM
        );
        assert!(last_error().contains("requires target BTF"));
        assert!(vm.is_null());

        let object = include_bytes!("../tests/btf_maps.o");
        let name = b"xdp";
        let options = ElfOptionsV1 {
            program_name: name.as_ptr(),
            program_name_len: name.len(),
            ..empty
        };
        assert_eq!(
            unsafe { febpf_vm_create_elf(object.as_ptr(), object.len(), &options, &mut vm) },
            STATUS_OK,
            "{}",
            last_error()
        );
        assert_eq!(unsafe { verify(vm, CONTEXT_FLAT, 0) }, STATUS_VERIFY);
        assert!(last_error().contains("requires XDP context model"));
        assert_eq!(unsafe { verify(vm, CONTEXT_XDP, 0) }, STATUS_OK);
        let mut packet = [0u8; 1];
        let invocation = InvocationV1 {
            struct_size: size_of::<InvocationV1>(),
            flags: 0,
            reserved: 0,
            context: null_mut(),
            context_len: 0,
            packet: packet.as_mut_ptr(),
            packet_len: packet.len(),
            output: None,
            output_user_data: null_mut(),
        };
        let mut result = 0;
        assert_eq!(
            unsafe { febpf_vm_run(vm, &invocation, &mut result) },
            STATUS_OK,
            "{}",
            last_error()
        );
        assert_eq!(result, 5);
        assert_eq!(unsafe { febpf_vm_destroy(vm) }, STATUS_OK);

        let tail = include_bytes!("../tests/tail_call.o");
        let tail_name = b"xdp/entry";
        let tail_options = ElfOptionsV1 {
            program_name: tail_name.as_ptr(),
            program_name_len: tail_name.len(),
            ..empty
        };
        assert_eq!(
            unsafe { febpf_vm_create_elf(tail.as_ptr(), tail.len(), &tail_options, &mut vm) },
            STATUS_UNSUPPORTED
        );
        assert!(last_error().contains("PROG_ARRAY"));
        assert!(vm.is_null());
    }
}
