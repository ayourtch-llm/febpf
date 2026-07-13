#ifndef FEBPF_H
#define FEBPF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FEBPF_C_ABI_VERSION 1u

typedef uint32_t febpf_status;

#define FEBPF_STATUS_OK 0u
#define FEBPF_STATUS_INVALID_ARGUMENT 1u
#define FEBPF_STATUS_PROGRAM 2u
#define FEBPF_STATUS_VERIFY 3u
#define FEBPF_STATUS_RUNTIME 4u
#define FEBPF_STATUS_UNSUPPORTED 5u
#define FEBPF_STATUS_NOT_FOUND 6u
#define FEBPF_STATUS_MAP 7u
#define FEBPF_STATUS_PANIC 255u

typedef struct febpf_vm febpf_vm;

typedef struct febpf_elf_options_v1 {
    size_t struct_size;
    uint32_t flags;
    uint32_t reserved;

    /* Exact loaded-program name. Required when the object has multiple entries. */
    const uint8_t *program_name;
    size_t program_name_len;

    /* Raw BTF or an ELF containing .BTF; required when the object needs it. */
    const uint8_t *target_btf;
    size_t target_btf_len;
} febpf_elf_options_v1;

typedef struct febpf_map_max_entries_v1 {
    size_t struct_size;
    const uint8_t *map_name;
    size_t map_name_len;
    uint32_t max_entries;
    uint32_t reserved;
} febpf_map_max_entries_v1;

typedef struct febpf_elf_options_v2 {
    size_t struct_size;
    uint32_t flags;
    uint32_t reserved;
    const uint8_t *program_name;
    size_t program_name_len;
    const uint8_t *target_btf;
    size_t target_btf_len;
    const febpf_map_max_entries_v1 *map_overrides;
    size_t map_override_count;
} febpf_elf_options_v2;

typedef uint32_t febpf_map_kind;
#define FEBPF_MAP_HASH 1u
#define FEBPF_MAP_ARRAY 2u
#define FEBPF_MAP_PROG_ARRAY 3u
#define FEBPF_MAP_PERF_EVENT_ARRAY 4u
#define FEBPF_MAP_PERCPU_HASH 5u
#define FEBPF_MAP_PERCPU_ARRAY 6u
#define FEBPF_MAP_STACK_TRACE 7u
#define FEBPF_MAP_CGROUP_ARRAY 8u
#define FEBPF_MAP_LRU_HASH 9u
#define FEBPF_MAP_ARRAY_OF_MAPS 12u
#define FEBPF_MAP_HASH_OF_MAPS 13u
#define FEBPF_MAP_DEVMAP 14u
#define FEBPF_MAP_CPUMAP 16u
#define FEBPF_MAP_XSKMAP 17u
#define FEBPF_MAP_QUEUE 22u
#define FEBPF_MAP_DEVMAP_HASH 25u
#define FEBPF_MAP_RINGBUF 27u

#define FEBPF_MAP_READONLY (1u << 0)
#define FEBPF_MAP_PER_CPU (1u << 1)

typedef struct febpf_map_info_v1 {
    size_t struct_size;
    febpf_map_kind kind;
    uint32_t flags;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t cpu_count;
} febpf_map_info_v1;

typedef uint32_t febpf_map_update_mode;
#define FEBPF_MAP_UPDATE_ANY 0u
#define FEBPF_MAP_UPDATE_NOEXIST 1u
#define FEBPF_MAP_UPDATE_EXIST 2u

typedef uint32_t febpf_context_model;
#define FEBPF_CONTEXT_FLAT 0u
#define FEBPF_CONTEXT_XDP 1u
#define FEBPF_CONTEXT_SKB 2u

#define FEBPF_VERIFY_CONTEXT_WRITABLE (1u << 0)
#define FEBPF_VERIFY_STRICT_ALIGNMENT (1u << 1)
#define FEBPF_VERIFY_ALLOW_UNINITIALIZED_STACK (1u << 2)

typedef struct febpf_verify_options_v1 {
    size_t struct_size;
    febpf_context_model context_model;
    uint32_t flags;
    size_t context_size;
    /* Zero selects febpf's default verifier budget. */
    size_t verifier_instruction_budget;
    /* Zero disables the runtime instruction limit. */
    uint64_t runtime_instruction_limit;
} febpf_verify_options_v1;

#define FEBPF_INVOCATION_JIT (1u << 0)

typedef uint32_t febpf_output_kind;
#define FEBPF_OUTPUT_PRINTK 1u
#define FEBPF_OUTPUT_SEQUENCE 2u

/* `data` is borrowed only for the callback and is not NUL-terminated. */
typedef void (*febpf_output_fn)(void *user_data,
                                febpf_output_kind kind,
                                const uint8_t *data,
                                size_t len);

typedef struct febpf_invocation_v1 {
    size_t struct_size;
    uint32_t flags;
    uint32_t reserved;

    /* FLAT uses context/context_len. XDP and SKB require context_len == 0. */
    uint8_t *context;
    size_t context_len;

    /* XDP and SKB use packet/packet_len. FLAT requires packet_len == 0. */
    uint8_t *packet;
    size_t packet_len;

    /* Optional invocation-local printk/sequence sink. */
    febpf_output_fn output;
    void *output_user_data;
} febpf_invocation_v1;

typedef uint32_t febpf_helper_arg_kind;
#define FEBPF_HELPER_ARG_UNUSED 0u
#define FEBPF_HELPER_ARG_SCALAR 1u
#define FEBPF_HELPER_ARG_MEMORY_READ 2u
#define FEBPF_HELPER_ARG_MEMORY_WRITE 3u
#define FEBPF_HELPER_ARG_MEMORY_READ_WRITE 4u
#define FEBPF_HELPER_ARG_SIZE 5u

typedef struct febpf_helper_arg_v1 {
    febpf_helper_arg_kind kind;
    /* Zero-based argument index carrying this memory view's byte length. */
    uint32_t size_arg;
} febpf_helper_arg_v1;

typedef struct febpf_helper_signature_v1 {
    size_t struct_size;
    uint32_t helper_id;
    uint32_t flags;
    febpf_helper_arg_v1 args[5];
} febpf_helper_signature_v1;

#define FEBPF_HELPER_VALUE_READABLE (1u << 0)
#define FEBPF_HELPER_VALUE_WRITABLE (1u << 1)

typedef struct febpf_helper_value_v1 {
    febpf_helper_arg_kind kind;
    uint32_t flags;
    uint64_t scalar;
    /* A bounded copied view, borrowed only for the callback. */
    uint8_t *data;
    size_t data_len;
} febpf_helper_value_v1;

/*
 * Return FEBPF_STATUS_OK to commit writable views and `result`. Any other
 * status aborts the helper call without copying writable views back.
 */
typedef febpf_status (*febpf_helper_fn)(void *user_data,
                                        uint32_t helper_id,
                                        const febpf_helper_value_v1 args[5],
                                        uint64_t *result);

typedef struct febpf_helper_binding_v1 {
    size_t struct_size;
    uint32_t helper_id;
    uint32_t reserved;
    febpf_helper_fn callback;
    void *user_data;
} febpf_helper_binding_v1;

typedef struct febpf_invocation_v2 {
    size_t struct_size;
    uint32_t flags;
    uint32_t reserved;
    uint8_t *context;
    size_t context_len;
    uint8_t *packet;
    size_t packet_len;
    febpf_output_fn output;
    void *output_user_data;
    const febpf_helper_binding_v1 *helpers;
    size_t helper_count;
} febpf_invocation_v2;

uint32_t febpf_c_abi_version(void);

/*
 * Copy the calling thread's most recent error. The return value is its byte
 * length excluding NUL; allocate return_value + 1 bytes for a full copy.
 * Passing NULL/0 is a length query. A nonempty destination is NUL-terminated.
 */
size_t febpf_last_error(uint8_t *destination, size_t capacity);

/* Source/bytecode is copied during construction. On failure, *output is NULL. */
febpf_status febpf_vm_create_assembly(const uint8_t *source,
                                      size_t source_len,
                                      febpf_vm **output);
febpf_status febpf_vm_create_bytecode(const uint8_t *program,
                                      size_t program_len,
                                      febpf_vm **output);
/* Object, selector, and target-BTF bytes are copied/consumed during the call. */
febpf_status febpf_vm_create_elf(const uint8_t *object,
                                 size_t object_len,
                                 const febpf_elf_options_v1 *options,
                                 febpf_vm **output);
febpf_status febpf_vm_create_elf_v2(const uint8_t *object,
                                    size_t object_len,
                                    const febpf_elf_options_v2 *options,
                                    febpf_vm **output);

/* NULL is accepted. Every non-NULL handle must be destroyed exactly once. */
febpf_status febpf_vm_destroy(febpf_vm *handle);

/* A successful verification selects the context model for later runs. */
febpf_status febpf_vm_verify(febpf_vm *handle,
                             const febpf_verify_options_v1 *options);

/* Define a verifier-visible scalar-returning helper before verification. */
febpf_status febpf_vm_define_helper(febpf_vm *handle,
                                    const febpf_helper_signature_v1 *signature);

/*
 * Invocation buffers are borrowed exclusively for this call. The VM handle
 * must not be used concurrently. `result` receives r0 only on success.
 */
febpf_status febpf_vm_run(febpf_vm *handle,
                          const febpf_invocation_v1 *invocation,
                          uint64_t *result);
febpf_status febpf_vm_run_v2(febpf_vm *handle,
                             const febpf_invocation_v2 *invocation,
                             uint64_t *result);

/* Runtime map access uses exact names and CPU 0 values for per-CPU maps. */
febpf_status febpf_vm_map_info(febpf_vm *handle,
                               const uint8_t *map_name,
                               size_t map_name_len,
                               febpf_map_info_v1 *info);
febpf_status febpf_vm_map_lookup(febpf_vm *handle,
                                 const uint8_t *map_name,
                                 size_t map_name_len,
                                 const uint8_t *key,
                                 size_t key_len,
                                 uint8_t *value,
                                 size_t value_len);
febpf_status febpf_vm_map_update(febpf_vm *handle,
                                 const uint8_t *map_name,
                                 size_t map_name_len,
                                 const uint8_t *key,
                                 size_t key_len,
                                 const uint8_t *value,
                                 size_t value_len,
                                 febpf_map_update_mode mode);
febpf_status febpf_vm_map_delete(febpf_vm *handle,
                                 const uint8_t *map_name,
                                 size_t map_name_len,
                                 const uint8_t *key,
                                 size_t key_len);

#ifdef __cplusplus
}
#endif

#endif /* FEBPF_H */
