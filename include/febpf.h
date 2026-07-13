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
#define FEBPF_STATUS_PANIC 255u

typedef struct febpf_vm febpf_vm;

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

/* NULL is accepted. Every non-NULL handle must be destroyed exactly once. */
febpf_status febpf_vm_destroy(febpf_vm *handle);

/* A successful verification selects the context model for later runs. */
febpf_status febpf_vm_verify(febpf_vm *handle,
                             const febpf_verify_options_v1 *options);

/*
 * Invocation buffers are borrowed exclusively for this call. The VM handle
 * must not be used concurrently. `result` receives r0 only on success.
 */
febpf_status febpf_vm_run(febpf_vm *handle,
                          const febpf_invocation_v1 *invocation,
                          uint64_t *result);

#ifdef __cplusplus
}
#endif

#endif /* FEBPF_H */
