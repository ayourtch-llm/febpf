//! Versioned native C ABI.
//!
//! This module owns only marshalling and opaque handles. Invocation resources
//! are translated into [`crate::ExecutionEnvironment`] values for one call;
//! no invocation buffer, callback, or user token becomes durable VM state.

use crate::execution::{ExecutionEnvironment, ExecutionOutcome};
use crate::helpers::{self, ArgKind, HelperSig, MemBus, RetKind, UserHelper};
use crate::maps::{MapKind, MapUpdateMode, NR_CPUS};
use crate::verifier::{Config, UninitStackPolicy};
use crate::{asm, elf, insn, Program, Vm};
use std::cell::RefCell;
use std::ffi::c_void;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
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
pub const STATUS_NOT_FOUND: u32 = 6;
pub const STATUS_MAP: u32 = 7;
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

pub const HELPER_ARG_UNUSED: u32 = 0;
pub const HELPER_ARG_SCALAR: u32 = 1;
pub const HELPER_ARG_MEMORY_READ: u32 = 2;
pub const HELPER_ARG_MEMORY_WRITE: u32 = 3;
pub const HELPER_ARG_MEMORY_READ_WRITE: u32 = 4;
pub const HELPER_ARG_SIZE: u32 = 5;

pub const HELPER_VALUE_READABLE: u32 = 1 << 0;
pub const HELPER_VALUE_WRITABLE: u32 = 1 << 1;

pub type HelperFn = unsafe extern "C" fn(
    user_data: *mut c_void,
    helper_id: u32,
    args: *const HelperValueV1,
    result: *mut u64,
) -> u32;

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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HelperArgV1 {
    pub kind: u32,
    pub size_arg: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HelperSignatureV1 {
    pub struct_size: usize,
    pub helper_id: u32,
    pub flags: u32,
    pub args: [HelperArgV1; 5],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HelperValueV1 {
    pub kind: u32,
    pub flags: u32,
    pub scalar: u64,
    pub data: *mut u8,
    pub data_len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HelperBindingV1 {
    pub struct_size: usize,
    pub helper_id: u32,
    pub reserved: u32,
    pub callback: Option<HelperFn>,
    pub user_data: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct InvocationV2 {
    pub struct_size: usize,
    pub flags: u32,
    pub reserved: u32,
    pub context: *mut u8,
    pub context_len: usize,
    pub packet: *mut u8,
    pub packet_len: usize,
    pub output: Option<OutputFn>,
    pub output_user_data: *mut c_void,
    pub helpers: *const HelperBindingV1,
    pub helper_count: usize,
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

/// One exact-name map capacity override used before ELF map instantiation.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MapMaxEntriesV1 {
    pub struct_size: usize,
    pub map_name: *const u8,
    pub map_name_len: usize,
    pub max_entries: u32,
    pub reserved: u32,
}

/// ELF loading configuration with pre-construction map capacity overrides.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ElfOptionsV2 {
    pub struct_size: usize,
    pub flags: u32,
    pub reserved: u32,
    pub program_name: *const u8,
    pub program_name_len: usize,
    pub target_btf: *const u8,
    pub target_btf_len: usize,
    pub map_overrides: *const MapMaxEntriesV1,
    pub map_override_count: usize,
}

/// Copied metadata for one exact-name map.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MapInfoV1 {
    pub struct_size: usize,
    pub kind: u32,
    pub flags: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub cpu_count: u32,
}

pub const MAP_READONLY: u32 = 1 << 0;
pub const MAP_PER_CPU: u32 = 1 << 1;

pub const MAP_UPDATE_ANY: u32 = 0;
pub const MAP_UPDATE_NOEXIST: u32 = 1;
pub const MAP_UPDATE_EXIST: u32 = 2;

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

fn check_elf_options(flags: u32, reserved: u32) -> CResult<()> {
    if flags & !ELF_KNOWN_FLAGS != 0 {
        return Err(invalid(format!(
            "unknown ELF flags 0x{:x}",
            flags & !ELF_KNOWN_FLAGS
        )));
    }
    if reserved != 0 {
        return Err(invalid("ELF options.reserved must be zero"));
    }
    Ok(())
}

unsafe fn map_overrides(
    pointer: *const MapMaxEntriesV1,
    count: usize,
) -> CResult<Vec<(String, u32)>> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if pointer.is_null() {
        return Err(invalid("map_overrides is null but count is nonzero"));
    }
    let total_bytes = count
        .checked_mul(core::mem::size_of::<MapMaxEntriesV1>())
        .filter(|size| *size <= isize::MAX as usize)
        .ok_or_else(|| invalid("map override array is too large"))?;
    let _ = total_bytes;
    let mut result = Vec::with_capacity(count);
    for index in 0..count {
        // SAFETY: the caller promises an array containing `count` descriptors.
        let item = unsafe { input_struct(pointer.add(index), "map override")? };
        if item.struct_size != core::mem::size_of::<MapMaxEntriesV1>() {
            return Err(invalid(format!(
                "map_overrides[{index}].struct_size must equal {} for this fixed-stride array",
                core::mem::size_of::<MapMaxEntriesV1>()
            )));
        }
        if item.reserved != 0 {
            return Err(invalid(format!(
                "map_overrides[{index}].reserved must be zero"
            )));
        }
        if item.max_entries == 0 {
            return Err(invalid(format!(
                "map_overrides[{index}].max_entries must be nonzero"
            )));
        }
        // SAFETY: the descriptor's byte region is caller-owned for this call.
        let name = unsafe { bytes(item.map_name, item.map_name_len, "map override name")? };
        let name = str::from_utf8(name)
            .map_err(|error| invalid(format!("map override name is not UTF-8: {error}")))?;
        if name.is_empty() {
            return Err(invalid(format!("map_overrides[{index}] has an empty name")));
        }
        if result.iter().any(|(existing, _)| existing == name) {
            return Err(invalid(format!("duplicate map override '{name}'")));
        }
        result.push((name.to_owned(), item.max_entries));
    }
    Ok(result)
}

fn create_elf_handle(
    object: &[u8],
    selector: &str,
    target_input: &[u8],
    overrides: &[(String, u32)],
) -> CResult<*mut CApiVm> {
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
    for (name, max_entries) in overrides {
        loaded
            .set_map_max_entries(name, *max_entries)
            .map_err(|error| (STATUS_PROGRAM, error))?;
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
    Ok(Box::into_raw(Box::new(CApiVm {
        vm,
        verified_model: None,
        required_model: model,
    })))
}

unsafe fn elf_inputs<'a>(
    object: *const u8,
    object_len: usize,
    program_name: *const u8,
    program_name_len: usize,
    target_btf: *const u8,
    target_btf_len: usize,
) -> CResult<(&'a [u8], &'a str, &'a [u8])> {
    // SAFETY: all byte-region contracts are supplied by the C caller.
    let object = unsafe { bytes(object, object_len, "ELF object")? };
    let selector = unsafe { bytes(program_name, program_name_len, "ELF program name")? };
    let selector = str::from_utf8(selector)
        .map_err(|error| invalid(format!("ELF program name is not UTF-8: {error}")))?;
    let target = unsafe { bytes(target_btf, target_btf_len, "target BTF")? };
    Ok((object, selector, target))
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
        check_elf_options(options.flags, options.reserved)?;
        let (object, selector, target) = unsafe {
            elf_inputs(
                object,
                object_len,
                options.program_name,
                options.program_name_len,
                options.target_btf,
                options.target_btf_len,
            )?
        };
        let handle = create_elf_handle(object, selector, target, &[])?;
        // SAFETY: output was checked and receives the newly owned handle.
        unsafe { output.write(handle) };
        Ok(())
    })
}

/// Construct an ELF VM with pre-instantiation map-capacity overrides.
///
/// # Safety
/// All descriptor-selected regions must be readable and `output` writable.
#[no_mangle]
pub unsafe extern "C" fn febpf_vm_create_elf_v2(
    object: *const u8,
    object_len: usize,
    options: *const ElfOptionsV2,
    output: *mut *mut CApiVm,
) -> u32 {
    boundary(|| {
        if output.is_null() {
            return Err(invalid("output VM pointer is null"));
        }
        // SAFETY: output was checked and is caller-owned.
        unsafe { output.write(null_mut()) };
        // SAFETY: caller promises a versioned readable input structure.
        let options = unsafe { input_struct(options, "ELF v2 options")? };
        check_elf_options(options.flags, options.reserved)?;
        let (object, selector, target) = unsafe {
            elf_inputs(
                object,
                object_len,
                options.program_name,
                options.program_name_len,
                options.target_btf,
                options.target_btf_len,
            )?
        };
        // SAFETY: caller promises an array of versioned descriptors.
        let overrides =
            unsafe { map_overrides(options.map_overrides, options.map_override_count)? };
        let handle = create_elf_handle(object, selector, target, &overrides)?;
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

fn helper_arg(desc: HelperArgV1, index: usize) -> CResult<ArgKind> {
    let kind = match desc.kind {
        HELPER_ARG_UNUSED => ArgKind::None,
        HELPER_ARG_SCALAR => ArgKind::Scalar,
        HELPER_ARG_SIZE => ArgKind::Size,
        HELPER_ARG_MEMORY_READ | HELPER_ARG_MEMORY_WRITE | HELPER_ARG_MEMORY_READ_WRITE => {
            if desc.size_arg >= 5 {
                return Err(invalid(format!(
                    "helper argument {index} size_arg {} is outside 0..5",
                    desc.size_arg
                )));
            }
            match desc.kind {
                HELPER_ARG_MEMORY_READ => ArgKind::MemRead {
                    size_arg: desc.size_arg as u8,
                },
                HELPER_ARG_MEMORY_WRITE => ArgKind::MemWrite {
                    size_arg: desc.size_arg as u8,
                },
                _ => ArgKind::MemReadWrite {
                    size_arg: desc.size_arg as u8,
                },
            }
        }
        other => {
            return Err(invalid(format!(
                "helper argument {index} has unknown kind {other}"
            )))
        }
    };
    if !matches!(
        desc.kind,
        HELPER_ARG_MEMORY_READ | HELPER_ARG_MEMORY_WRITE | HELPER_ARG_MEMORY_READ_WRITE
    ) && desc.size_arg != 0
    {
        return Err(invalid(format!(
            "helper argument {index} size_arg must be zero for this kind"
        )));
    }
    Ok(kind)
}

fn unavailable_helper(helper_id: u32) -> Box<dyn UserHelper> {
    Box::new(move |_: [u64; 5], _: &mut dyn MemBus| {
        Err(format!(
            "C helper #{helper_id} has no binding for this invocation"
        ))
    })
}

/// Define a verifier-visible custom helper. Its callback remains per-run.
///
/// # Safety
/// Both pointers must be live and exclusively borrowed for this call.
#[no_mangle]
pub unsafe extern "C" fn febpf_vm_define_helper(
    handle: *mut CApiVm,
    signature: *const HelperSignatureV1,
) -> u32 {
    boundary(|| {
        // SAFETY: caller contracts are forwarded to checked helpers.
        let handle = unsafe { vm_mut(handle)? };
        let signature = unsafe { input_struct(signature, "helper signature")? };
        if handle.verified_model.is_some() {
            return Err((
                STATUS_VERIFY,
                "helpers must be defined before successful verification".into(),
            ));
        }
        if signature.helper_id < helpers::id::FIRST_USER {
            return Err(invalid(format!(
                "custom helper id {} is below the first user id {}",
                signature.helper_id,
                helpers::id::FIRST_USER
            )));
        }
        if signature.flags != 0 {
            return Err(invalid(format!(
                "unknown helper signature flags 0x{:x}",
                signature.flags
            )));
        }
        let mut args = [ArgKind::None; 5];
        for (index, desc) in signature.args.into_iter().enumerate() {
            args[index] = helper_arg(desc, index)?;
        }
        for (index, arg) in args.iter().enumerate() {
            let size_arg = match arg {
                ArgKind::MemRead { size_arg }
                | ArgKind::MemWrite { size_arg }
                | ArgKind::MemReadWrite { size_arg } => Some(*size_arg as usize),
                _ => None,
            };
            if let Some(size_arg) = size_arg {
                if !matches!(args[size_arg], ArgKind::Size) {
                    return Err(invalid(format!(
                        "helper argument {index} names argument {size_arg} as its size, but that argument is not SIZE"
                    )));
                }
            }
        }
        let helper_id = signature.helper_id;
        handle.vm.user_helpers.register(
            helper_id,
            HelperSig {
                name: "c_helper",
                args,
                ret: RetKind::Scalar,
            },
            unavailable_helper(helper_id),
        );
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

fn invoke_c_helper(
    binding: HelperBindingV1,
    kinds: [ArgKind; 5],
    args: [u64; 5],
    mem: &mut dyn MemBus,
) -> Result<u64, String> {
    let callback = binding
        .callback
        .ok_or_else(|| format!("C helper #{} callback is null", binding.helper_id))?;
    let mut storage: [Vec<u8>; 5] = core::array::from_fn(|_| Vec::new());
    for (index, kind) in kinds.iter().enumerate() {
        let (size_arg, zero_for_write) = match kind {
            ArgKind::MemRead { size_arg } | ArgKind::MemReadWrite { size_arg } => {
                (Some(*size_arg), false)
            }
            ArgKind::MemWrite { size_arg } => (Some(*size_arg), true),
            _ => (None, false),
        };
        let Some(size_arg) = size_arg else {
            continue;
        };
        let len = usize::try_from(args[size_arg as usize])
            .map_err(|_| format!("C helper #{} memory length is too large", binding.helper_id))?;
        storage[index].resize(len, 0);
        // Reading first validates the complete view. Write-only callbacks see
        // zeroes, and no guest mutation occurs before callback success.
        mem.read(args[index], &mut storage[index])?;
        if zero_for_write {
            storage[index].fill(0);
        }
    }
    let values: [HelperValueV1; 5] = core::array::from_fn(|index| {
        let (kind, flags) = match kinds[index] {
            ArgKind::None => (HELPER_ARG_UNUSED, 0),
            ArgKind::Scalar => (HELPER_ARG_SCALAR, 0),
            ArgKind::Size => (HELPER_ARG_SIZE, 0),
            ArgKind::MemRead { .. } => (HELPER_ARG_MEMORY_READ, HELPER_VALUE_READABLE),
            ArgKind::MemWrite { .. } => (HELPER_ARG_MEMORY_WRITE, HELPER_VALUE_WRITABLE),
            ArgKind::MemReadWrite { .. } => (
                HELPER_ARG_MEMORY_READ_WRITE,
                HELPER_VALUE_READABLE | HELPER_VALUE_WRITABLE,
            ),
            _ => unreachable!("C helper signatures expose only the checked subset"),
        };
        let memory = matches!(
            kinds[index],
            ArgKind::MemRead { .. } | ArgKind::MemWrite { .. } | ArgKind::MemReadWrite { .. }
        );
        HelperValueV1 {
            kind,
            flags,
            scalar: if memory { 0 } else { args[index] },
            data: if memory {
                storage[index].as_mut_ptr()
            } else {
                null_mut()
            },
            data_len: if memory { storage[index].len() } else { 0 },
        }
    });
    let mut result = 0u64;
    // SAFETY: the callback and user token are supplied for this invocation;
    // values and copied buffers remain live until the callback returns.
    let status = unsafe {
        callback(
            binding.user_data,
            binding.helper_id,
            values.as_ptr(),
            &mut result,
        )
    };
    if status != STATUS_OK {
        return Err(format!(
            "C helper #{} callback returned status {status}",
            binding.helper_id
        ));
    }
    for (index, kind) in kinds.iter().enumerate() {
        if matches!(kind, ArgKind::MemWrite { .. } | ArgKind::MemReadWrite { .. }) {
            mem.write(args[index], &storage[index])?;
        }
    }
    Ok(result)
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
        let value = run_invocation(handle, &invocation)?;
        // SAFETY: result was checked and is caller-owned.
        unsafe { result.write(value) };
        Ok(())
    })
}

fn run_invocation(handle: &mut CApiVm, invocation: &InvocationV1) -> CResult<u64> {
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
    match model {
        VerifiedModel::Flat => run_flat(handle, invocation, jit),
        VerifiedModel::Xdp => run_xdp(handle, invocation, jit),
        VerifiedModel::Skb => run_skb(handle, invocation, jit),
    }
}

unsafe fn helper_bindings(
    pointer: *const HelperBindingV1,
    count: usize,
) -> CResult<Vec<HelperBindingV1>> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if pointer.is_null() {
        return Err(invalid("helper bindings are null but helper_count is nonzero"));
    }
    // SAFETY: caller promises a readable fixed-stride array of `count` items.
    let bindings = unsafe { slice::from_raw_parts(pointer, count) };
    let mut copied = Vec::with_capacity(count);
    for (index, binding) in bindings.iter().copied().enumerate() {
        if binding.struct_size != core::mem::size_of::<HelperBindingV1>() {
            return Err(invalid(format!(
                "helpers[{index}].struct_size must equal {} for this fixed-stride array",
                core::mem::size_of::<HelperBindingV1>()
            )));
        }
        if binding.reserved != 0 {
            return Err(invalid(format!("helpers[{index}].reserved must be zero")));
        }
        if binding.callback.is_none() {
            return Err(invalid(format!("helpers[{index}].callback is null")));
        }
        if copied
            .iter()
            .any(|existing: &HelperBindingV1| existing.helper_id == binding.helper_id)
        {
            return Err(invalid(format!(
                "duplicate binding for helper #{}",
                binding.helper_id
            )));
        }
        copied.push(binding);
    }
    Ok(copied)
}

fn run_with_helper_bindings(
    handle: &mut CApiVm,
    invocation: &InvocationV1,
    bindings: &[HelperBindingV1],
) -> CResult<u64> {
    let mut configured = Vec::with_capacity(bindings.len());
    for binding in bindings {
        let signature = handle
            .vm
            .user_helpers
            .sigs()
            .iter()
            .find(|(helper_id, _)| *helper_id == binding.helper_id)
            .map(|(_, signature)| signature.clone())
            .ok_or_else(|| {
                invalid(format!(
                    "helper #{} was not defined before verification",
                    binding.helper_id
                ))
            })?;
        configured.push((*binding, signature));
    }
    for (binding, signature) in &configured {
        let binding = *binding;
        let kinds = signature.args;
        handle.vm.user_helpers.register(
            binding.helper_id,
            signature.clone(),
            Box::new(move |args: [u64; 5], mem: &mut dyn MemBus| {
                invoke_c_helper(binding, kinds, args, mem)
            }),
        );
    }
    let outcome = catch_unwind(AssertUnwindSafe(|| run_invocation(handle, invocation)));
    for (binding, signature) in configured {
        handle.vm.user_helpers.register(
            binding.helper_id,
            signature,
            unavailable_helper(binding.helper_id),
        );
    }
    match outcome {
        Ok(result) => result,
        Err(payload) => resume_unwind(payload),
    }
}

/// Execute once with invocation-local custom helper bindings.
///
/// # Safety
/// The handle, descriptor, result, bindings, callbacks, user tokens, and
/// descriptor-selected buffers must remain live for this call.
#[no_mangle]
pub unsafe extern "C" fn febpf_vm_run_v2(
    handle: *mut CApiVm,
    invocation: *const InvocationV2,
    result: *mut u64,
) -> u32 {
    boundary(|| {
        if result.is_null() {
            return Err(invalid("result pointer is null"));
        }
        // SAFETY: caller contracts are forwarded to checked helpers.
        let handle = unsafe { vm_mut(handle)? };
        let invocation = unsafe { input_struct(invocation, "v2 invocation")? };
        let bindings = unsafe { helper_bindings(invocation.helpers, invocation.helper_count)? };
        let base = InvocationV1 {
            struct_size: core::mem::size_of::<InvocationV1>(),
            flags: invocation.flags,
            reserved: invocation.reserved,
            context: invocation.context,
            context_len: invocation.context_len,
            packet: invocation.packet,
            packet_len: invocation.packet_len,
            output: invocation.output,
            output_user_data: invocation.output_user_data,
        };
        let value = run_with_helper_bindings(handle, &base, &bindings)?;
        // SAFETY: result was checked and is caller-owned.
        unsafe { result.write(value) };
        Ok(())
    })
}

fn map_kind_code(kind: MapKind) -> u32 {
    match kind {
        MapKind::Hash => 1,
        MapKind::Array => 2,
        MapKind::ProgArray => 3,
        MapKind::PerfEventArray => 4,
        MapKind::PerCpuHash => 5,
        MapKind::PerCpuArray => 6,
        MapKind::StackTrace => 7,
        MapKind::CgroupArray => 8,
        MapKind::LruHash => 9,
        MapKind::ArrayOfMaps => 12,
        MapKind::HashOfMaps => 13,
        MapKind::DevMap => 14,
        MapKind::CpuMap => 16,
        MapKind::XskMap => 17,
        MapKind::Queue => 22,
        MapKind::DevMapHash => 25,
        MapKind::RingBuf => 27,
    }
}

fn byte_map_kind(kind: MapKind) -> bool {
    matches!(
        kind,
        MapKind::Hash
            | MapKind::Array
            | MapKind::PerCpuHash
            | MapKind::PerCpuArray
            | MapKind::StackTrace
            | MapKind::CgroupArray
            | MapKind::LruHash
            | MapKind::DevMap
            | MapKind::CpuMap
            | MapKind::XskMap
            | MapKind::DevMapHash
    )
}

unsafe fn map_name<'a>(pointer: *const u8, len: usize) -> CResult<&'a str> {
    // SAFETY: caller promises a readable exact-name byte region.
    let name = unsafe { bytes(pointer, len, "map name")? };
    let name =
        str::from_utf8(name).map_err(|error| invalid(format!("map name is not UTF-8: {error}")))?;
    if name.is_empty() {
        return Err(invalid("map name is empty"));
    }
    Ok(name)
}

fn map_index(handle: &CApiVm, name: &str) -> CResult<usize> {
    let mut matches = handle
        .vm
        .maps
        .iter()
        .enumerate()
        .filter(|(_, map)| map.def.name == name)
        .map(|(index, _)| index);
    let index = matches
        .next()
        .ok_or_else(|| (STATUS_NOT_FOUND, format!("no map named '{name}'")))?;
    if matches.next().is_some() {
        return Err((STATUS_MAP, format!("map name '{name}' is ambiguous")));
    }
    Ok(index)
}

fn require_map_lengths(
    name: &str,
    key_len: usize,
    value_len: Option<usize>,
    key_size: u32,
    value_size: u32,
) -> CResult<()> {
    if key_len != key_size as usize {
        return Err(invalid(format!(
            "map '{name}' key length is {key_len}, need {key_size}"
        )));
    }
    if let Some(value_len) = value_len {
        if value_len != value_size as usize {
            return Err(invalid(format!(
                "map '{name}' value length is {value_len}, need {value_size}"
            )));
        }
    }
    Ok(())
}

fn map_error(operation: &str, name: &str, errno: i64) -> (u32, String) {
    let status = if errno == -2 {
        STATUS_NOT_FOUND
    } else {
        STATUS_MAP
    };
    (
        status,
        format!("map '{name}' {operation} failed with errno {}", -errno),
    )
}

unsafe fn require_output_struct<T>(pointer: *mut T, name: &str) -> CResult<()> {
    if pointer.is_null() {
        return Err(invalid(format!("{name} is null")));
    }
    // SAFETY: every versioned output starts with a caller-initialized size_t.
    let actual = unsafe { pointer.cast::<usize>().read_unaligned() };
    require_struct(actual, core::mem::size_of::<T>(), name)
}

/// Copy metadata for one exact-name map.
///
/// # Safety
/// Name bytes must be readable and `info` must name a writable versioned struct.
#[no_mangle]
pub unsafe extern "C" fn febpf_vm_map_info(
    handle: *mut CApiVm,
    name: *const u8,
    name_len: usize,
    info: *mut MapInfoV1,
) -> u32 {
    boundary(|| {
        // SAFETY: caller contracts are forwarded to checked helpers.
        let handle = unsafe { vm_mut(handle)? };
        let name = unsafe { map_name(name, name_len)? };
        unsafe { require_output_struct(info, "map info")? };
        let index = map_index(handle, name)?;
        let map = &handle.vm.maps[index];
        let per_cpu = matches!(map.def.kind, MapKind::PerCpuArray | MapKind::PerCpuHash);
        let result = MapInfoV1 {
            struct_size: core::mem::size_of::<MapInfoV1>(),
            kind: map_kind_code(map.def.kind),
            flags: if map.def.readonly { MAP_READONLY } else { 0 }
                | if per_cpu { MAP_PER_CPU } else { 0 },
            key_size: map.def.key_size,
            value_size: map.def.value_size,
            max_entries: map.def.max_entries,
            cpu_count: if per_cpu { NR_CPUS } else { 1 },
        };
        // SAFETY: output size and writability were checked by contract.
        unsafe { info.write_unaligned(result) };
        Ok(())
    })
}

/// Copy CPU 0's value for one key.
///
/// # Safety
/// All byte regions must be live for this call and the value region writable.
#[no_mangle]
pub unsafe extern "C" fn febpf_vm_map_lookup(
    handle: *mut CApiVm,
    name: *const u8,
    name_len: usize,
    key: *const u8,
    key_len: usize,
    value: *mut u8,
    value_len: usize,
) -> u32 {
    boundary(|| {
        // SAFETY: caller contracts are forwarded to checked helpers.
        let handle = unsafe { vm_mut(handle)? };
        let name = unsafe { map_name(name, name_len)? };
        let key = unsafe { bytes(key, key_len, "map key")? };
        let value = unsafe { bytes_mut(value, value_len, "map value output")? };
        let index = map_index(handle, name)?;
        let map = &mut handle.vm.maps[index];
        require_map_lengths(
            name,
            key.len(),
            Some(value.len()),
            map.def.key_size,
            map.def.value_size,
        )?;
        if !byte_map_kind(map.def.kind) {
            return Err((
                STATUS_MAP,
                format!(
                    "map '{name}' kind {} has no byte-value lookup",
                    map.def.kind
                ),
            ));
        }
        let reference = map
            .lookup(key)
            .ok_or_else(|| (STATUS_NOT_FOUND, format!("map '{name}' key not found")))?;
        value.copy_from_slice(map.value(reference));
        map.touch(key);
        Ok(())
    })
}

/// Insert or replace CPU 0's value for one key.
///
/// # Safety
/// All descriptor-selected byte regions must be readable for this call.
#[no_mangle]
pub unsafe extern "C" fn febpf_vm_map_update(
    handle: *mut CApiVm,
    name: *const u8,
    name_len: usize,
    key: *const u8,
    key_len: usize,
    value: *const u8,
    value_len: usize,
    mode: u32,
) -> u32 {
    boundary(|| {
        let mode = match mode {
            MAP_UPDATE_ANY => MapUpdateMode::Any,
            MAP_UPDATE_NOEXIST => MapUpdateMode::NoExist,
            MAP_UPDATE_EXIST => MapUpdateMode::Exist,
            other => return Err(invalid(format!("unknown map update mode {other}"))),
        };
        // SAFETY: caller contracts are forwarded to checked helpers.
        let handle = unsafe { vm_mut(handle)? };
        let name = unsafe { map_name(name, name_len)? };
        let key = unsafe { bytes(key, key_len, "map key")? };
        let value = unsafe { bytes(value, value_len, "map value")? };
        let index = map_index(handle, name)?;
        let map = &mut handle.vm.maps[index];
        require_map_lengths(
            name,
            key.len(),
            Some(value.len()),
            map.def.key_size,
            map.def.value_size,
        )?;
        if !byte_map_kind(map.def.kind) {
            return Err((
                STATUS_MAP,
                format!(
                    "map '{name}' kind {} has no byte-value update",
                    map.def.kind
                ),
            ));
        }
        if map.def.readonly {
            return Err(map_error("update", name, -1));
        }
        let exists = map.lookup(key).is_some();
        if mode == MapUpdateMode::NoExist && exists {
            return Err(map_error("update", name, -17));
        }
        if mode == MapUpdateMode::Exist && !exists {
            return Err(map_error("update", name, -2));
        }
        map.update(key, value)
            .map(|_| ())
            .map_err(|errno| map_error("update", name, errno))
    })
}

/// Delete one key from a byte-value map.
///
/// # Safety
/// Name and key regions must be readable for this call.
#[no_mangle]
pub unsafe extern "C" fn febpf_vm_map_delete(
    handle: *mut CApiVm,
    name: *const u8,
    name_len: usize,
    key: *const u8,
    key_len: usize,
) -> u32 {
    boundary(|| {
        // SAFETY: caller contracts are forwarded to checked helpers.
        let handle = unsafe { vm_mut(handle)? };
        let name = unsafe { map_name(name, name_len)? };
        let key = unsafe { bytes(key, key_len, "map key")? };
        let index = map_index(handle, name)?;
        let map = &mut handle.vm.maps[index];
        require_map_lengths(name, key.len(), None, map.def.key_size, map.def.value_size)?;
        if !byte_map_kind(map.def.kind) {
            return Err((
                STATUS_MAP,
                format!(
                    "map '{name}' kind {} has no byte-value delete",
                    map.def.kind
                ),
            ));
        }
        map.delete(key)
            .map_err(|errno| map_error("delete", name, errno))
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
    fn custom_helpers_use_invocation_local_copied_views() {
        const HELPER_ID: u32 = helpers::id::FIRST_USER;
        let vm = create("r2 = 4\ncall 65536\nexit");
        let signature = HelperSignatureV1 {
            struct_size: size_of::<HelperSignatureV1>(),
            helper_id: HELPER_ID,
            flags: 0,
            args: [
                HelperArgV1 {
                    kind: HELPER_ARG_MEMORY_READ_WRITE,
                    size_arg: 1,
                },
                HelperArgV1 {
                    kind: HELPER_ARG_SIZE,
                    size_arg: 0,
                },
                HelperArgV1 {
                    kind: HELPER_ARG_UNUSED,
                    size_arg: 0,
                },
                HelperArgV1 {
                    kind: HELPER_ARG_UNUSED,
                    size_arg: 0,
                },
                HelperArgV1 {
                    kind: HELPER_ARG_UNUSED,
                    size_arg: 0,
                },
            ],
        };
        assert_eq!(
            unsafe { febpf_vm_define_helper(vm, &signature) },
            STATUS_OK,
            "{}",
            last_error()
        );
        assert_eq!(unsafe { verify(vm, CONTEXT_FLAT, 4) }, STATUS_OK);

        #[repr(C)]
        struct CallbackState {
            calls: u32,
            fail: bool,
            contract_ok: bool,
        }
        unsafe extern "C" fn callback(
            user_data: *mut c_void,
            helper_id: u32,
            args: *const HelperValueV1,
            result: *mut u64,
        ) -> u32 {
            // SAFETY: the test supplies live callback state and five values.
            let state = unsafe { &mut *user_data.cast::<CallbackState>() };
            let args = unsafe { slice::from_raw_parts(args, 5) };
            state.calls += 1;
            state.contract_ok = helper_id == HELPER_ID
                && args[0].kind == HELPER_ARG_MEMORY_READ_WRITE
                && args[0].flags == HELPER_VALUE_READABLE | HELPER_VALUE_WRITABLE
                && args[0].scalar == 0
                && !args[0].data.is_null()
                && args[0].data_len == 4
                && args[1].kind == HELPER_ARG_SIZE
                && args[1].scalar == 4;
            unsafe { *args[0].data = (*args[0].data).wrapping_add(1) };
            if state.fail {
                return 91;
            }
            unsafe { result.write(0x55) };
            STATUS_OK
        }

        let mut state = CallbackState {
            calls: 0,
            fail: true,
            contract_ok: false,
        };
        let binding = HelperBindingV1 {
            struct_size: size_of::<HelperBindingV1>(),
            helper_id: HELPER_ID,
            reserved: 0,
            callback: Some(callback),
            user_data: (&mut state as *mut CallbackState).cast(),
        };
        let mut context = [7u8, 8, 9, 10];
        let invocation = |flags, context: &mut [u8; 4]| InvocationV2 {
            struct_size: size_of::<InvocationV2>(),
            flags,
            reserved: 0,
            context: context.as_mut_ptr(),
            context_len: context.len(),
            packet: null_mut(),
            packet_len: 0,
            output: None,
            output_user_data: null_mut(),
            helpers: &binding,
            helper_count: 1,
        };
        let mut result = 0;
        assert_eq!(
            unsafe { febpf_vm_run_v2(vm, &invocation(0, &mut context), &mut result) },
            STATUS_RUNTIME
        );
        assert!(last_error().contains("returned status 91"));
        assert_eq!(context, [7, 8, 9, 10], "failed callback must not write back");
        assert!(state.contract_ok);

        // SAFETY: the callback is not active and the binding points at state.
        unsafe { (*binding.user_data.cast::<CallbackState>()).fail = false };
        assert_eq!(
            unsafe { febpf_vm_run_v2(vm, &invocation(0, &mut context), &mut result) },
            STATUS_OK,
            "{}",
            last_error()
        );
        assert_eq!(result, 0x55);
        assert_eq!(context, [8, 8, 9, 10]);

        #[cfg(feature = "jit")]
        {
            let mut jit_context = [20u8, 1, 2, 3];
            assert_eq!(
                unsafe {
                    febpf_vm_run_v2(
                        vm,
                        &invocation(INVOCATION_JIT, &mut jit_context),
                        &mut result,
                    )
                },
                STATUS_OK,
                "{}",
                last_error()
            );
            assert_eq!(result, 0x55);
            assert_eq!(jit_context, [21, 1, 2, 3]);
        }
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

    #[test]
    fn elf_v2_configures_capacity_and_runtime_map_operations_are_exact() {
        let object = include_bytes!("../tests/legacy_maps.o");
        let program_name = b"socket";
        let map_name = b"counts";
        let override_ = MapMaxEntriesV1 {
            struct_size: size_of::<MapMaxEntriesV1>(),
            map_name: map_name.as_ptr(),
            map_name_len: map_name.len(),
            max_entries: 1,
            reserved: 0,
        };
        let options = ElfOptionsV2 {
            struct_size: size_of::<ElfOptionsV2>(),
            flags: 0,
            reserved: 0,
            program_name: program_name.as_ptr(),
            program_name_len: program_name.len(),
            target_btf: null_mut(),
            target_btf_len: 0,
            map_overrides: &override_,
            map_override_count: 1,
        };
        let mut vm = null_mut();
        assert_eq!(
            unsafe { febpf_vm_create_elf_v2(object.as_ptr(), object.len(), &options, &mut vm) },
            STATUS_OK,
            "{}",
            last_error()
        );
        let mut info = MapInfoV1 {
            struct_size: size_of::<MapInfoV1>(),
            kind: 0,
            flags: 0,
            key_size: 0,
            value_size: 0,
            max_entries: 0,
            cpu_count: 0,
        };
        assert_eq!(
            unsafe { febpf_vm_map_info(vm, map_name.as_ptr(), map_name.len(), &mut info) },
            STATUS_OK
        );
        assert_eq!(
            (info.kind, info.key_size, info.value_size, info.max_entries),
            (1, 4, 8, 1)
        );
        assert_eq!((info.flags, info.cpu_count), (0, 1));

        let key0 = 0u32.to_ne_bytes();
        let key1 = 1u32.to_ne_bytes();
        let value = 77u64.to_ne_bytes();
        assert_eq!(
            unsafe {
                febpf_vm_map_update(
                    vm,
                    map_name.as_ptr(),
                    map_name.len(),
                    key0.as_ptr(),
                    key0.len(),
                    value.as_ptr(),
                    value.len(),
                    MAP_UPDATE_NOEXIST,
                )
            },
            STATUS_OK
        );
        assert_eq!(
            unsafe {
                febpf_vm_map_update(
                    vm,
                    map_name.as_ptr(),
                    map_name.len(),
                    key0.as_ptr(),
                    key0.len(),
                    value.as_ptr(),
                    value.len(),
                    MAP_UPDATE_NOEXIST,
                )
            },
            STATUS_MAP
        );
        assert!(last_error().contains("errno 17"));
        assert_eq!(
            unsafe {
                febpf_vm_map_update(
                    vm,
                    map_name.as_ptr(),
                    map_name.len(),
                    key1.as_ptr(),
                    key1.len(),
                    value.as_ptr(),
                    value.len(),
                    MAP_UPDATE_ANY,
                )
            },
            STATUS_MAP
        );
        assert!(last_error().contains("errno 7"));
        let mut copied = [0u8; 8];
        assert_eq!(
            unsafe {
                febpf_vm_map_lookup(
                    vm,
                    map_name.as_ptr(),
                    map_name.len(),
                    key0.as_ptr(),
                    key0.len(),
                    copied.as_mut_ptr(),
                    copied.len(),
                )
            },
            STATUS_OK
        );
        assert_eq!(u64::from_ne_bytes(copied), 77);
        assert_eq!(
            unsafe {
                febpf_vm_map_delete(
                    vm,
                    map_name.as_ptr(),
                    map_name.len(),
                    key0.as_ptr(),
                    key0.len(),
                )
            },
            STATUS_OK
        );
        assert_eq!(
            unsafe {
                febpf_vm_map_lookup(
                    vm,
                    map_name.as_ptr(),
                    map_name.len(),
                    key0.as_ptr(),
                    key0.len(),
                    copied.as_mut_ptr(),
                    copied.len(),
                )
            },
            STATUS_NOT_FOUND
        );
        assert_eq!(unsafe { febpf_vm_destroy(vm) }, STATUS_OK);
    }

    #[test]
    fn elf_maps_remain_durable_across_runs_and_frozen_maps_reject_updates() {
        let object = include_bytes!("../tests/global_data.o");
        let program_name = b"socket";
        let options = ElfOptionsV1 {
            struct_size: size_of::<ElfOptionsV1>(),
            flags: 0,
            reserved: 0,
            program_name: program_name.as_ptr(),
            program_name_len: program_name.len(),
            target_btf: null_mut(),
            target_btf_len: 0,
        };
        let mut vm = null_mut();
        assert_eq!(
            unsafe { febpf_vm_create_elf(object.as_ptr(), object.len(), &options, &mut vm) },
            STATUS_OK
        );
        let rodata = b".rodata.cst16";
        let mut info = MapInfoV1 {
            struct_size: size_of::<MapInfoV1>(),
            kind: 0,
            flags: 0,
            key_size: 0,
            value_size: 0,
            max_entries: 0,
            cpu_count: 0,
        };
        assert_eq!(
            unsafe { febpf_vm_map_info(vm, rodata.as_ptr(), rodata.len(), &mut info) },
            STATUS_OK
        );
        assert_ne!(info.flags & MAP_READONLY, 0);
        assert_eq!(unsafe { verify(vm, CONTEXT_SKB, 0) }, STATUS_OK);

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
        assert_eq!(
            unsafe { febpf_vm_run(vm, &invocation, &mut result) },
            STATUS_OK
        );
        assert_eq!(result, 410);

        let key = 0u32.to_ne_bytes();
        let data_name = b".data";
        let bss_name = b".bss";
        let mut value = [0u8; 8];
        assert_eq!(
            unsafe {
                febpf_vm_map_lookup(
                    vm,
                    bss_name.as_ptr(),
                    bss_name.len(),
                    key.as_ptr(),
                    key.len(),
                    value.as_mut_ptr(),
                    value.len(),
                )
            },
            STATUS_OK
        );
        assert_eq!(u64::from_ne_bytes(value), 10);
        let seven = 7u64.to_ne_bytes();
        assert_eq!(
            unsafe {
                febpf_vm_map_update(
                    vm,
                    data_name.as_ptr(),
                    data_name.len(),
                    key.as_ptr(),
                    key.len(),
                    seven.as_ptr(),
                    seven.len(),
                    MAP_UPDATE_EXIST,
                )
            },
            STATUS_OK
        );
        assert_eq!(
            unsafe { febpf_vm_run(vm, &invocation, &mut result) },
            STATUS_OK
        );
        assert_eq!(result, 820);
        let zero = [0u8; 16];
        assert_eq!(
            unsafe {
                febpf_vm_map_update(
                    vm,
                    rodata.as_ptr(),
                    rodata.len(),
                    key.as_ptr(),
                    key.len(),
                    zero.as_ptr(),
                    zero.len(),
                    MAP_UPDATE_EXIST,
                )
            },
            STATUS_MAP
        );
        assert!(last_error().contains("errno 1"));
        assert_eq!(unsafe { febpf_vm_destroy(vm) }, STATUS_OK);
    }
}
