#include "febpf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HOST_HELPER_ID 65536u

struct host_state {
    unsigned calls;
    int fail;
};

static void die(const char *operation, febpf_status status)
{
    size_t len = febpf_last_error(NULL, 0);
    char *message = malloc(len + 1);
    if (message != NULL)
        febpf_last_error((uint8_t *)message, len + 1);
    fprintf(stderr, "%s failed (%u): %s\n", operation, status,
            message != NULL ? message : "out of memory reading diagnostic");
    free(message);
    exit(1);
}

static febpf_status host_helper(void *user_data, uint32_t helper_id,
                                const febpf_helper_value_v1 args[5],
                                uint64_t *result)
{
    struct host_state *state = user_data;
    uint32_t value;

    state->calls++;
    if (helper_id != HOST_HELPER_ID ||
        args[0].kind != FEBPF_HELPER_ARG_MEMORY_READ_WRITE ||
        args[0].flags !=
            (FEBPF_HELPER_VALUE_READABLE | FEBPF_HELPER_VALUE_WRITABLE) ||
        args[0].scalar != 0 || args[0].data == NULL ||
        args[0].data_len != sizeof(value) ||
        args[1].kind != FEBPF_HELPER_ARG_SIZE || args[1].scalar != sizeof(value))
        return FEBPF_STATUS_INVALID_ARGUMENT;

    memcpy(&value, args[0].data, sizeof(value));
    value++;
    memcpy(args[0].data, &value, sizeof(value));
    if (state->fail)
        return FEBPF_STATUS_RUNTIME;
    *result = 123;
    return FEBPF_STATUS_OK;
}

static uint64_t run(febpf_vm *vm, uint32_t flags, uint32_t *context,
                    const febpf_helper_binding_v1 *binding,
                    febpf_status expected)
{
    febpf_invocation_v2 invocation = {
        .struct_size = sizeof(invocation),
        .flags = flags,
        .context = (uint8_t *)context,
        .context_len = sizeof(*context),
        .helpers = binding,
        .helper_count = 1,
    };
    uint64_t result = 0;
    febpf_status status = febpf_vm_run_v2(vm, &invocation, &result);
    if (status != expected)
        die("febpf_vm_run_v2", status);
    return result;
}

int main(void)
{
    static const char program[] = "r2 = 4\ncall 65536\nexit\n";
    febpf_vm *vm = NULL;
    febpf_status status = febpf_vm_create_assembly(
        (const uint8_t *)program, sizeof(program) - 1, &vm);
    if (status != FEBPF_STATUS_OK)
        die("febpf_vm_create_assembly", status);

    febpf_helper_signature_v1 signature = {
        .struct_size = sizeof(signature),
        .helper_id = HOST_HELPER_ID,
        .args = {
            { FEBPF_HELPER_ARG_MEMORY_READ_WRITE, 1 },
            { FEBPF_HELPER_ARG_SIZE, 0 },
            { FEBPF_HELPER_ARG_UNUSED, 0 },
            { FEBPF_HELPER_ARG_UNUSED, 0 },
            { FEBPF_HELPER_ARG_UNUSED, 0 },
        },
    };
    status = febpf_vm_define_helper(vm, &signature);
    if (status != FEBPF_STATUS_OK)
        die("febpf_vm_define_helper", status);

    febpf_verify_options_v1 verify = {
        .struct_size = sizeof(verify),
        .context_model = FEBPF_CONTEXT_FLAT,
        .flags = FEBPF_VERIFY_CONTEXT_WRITABLE,
        .context_size = sizeof(uint32_t),
    };
    status = febpf_vm_verify(vm, &verify);
    if (status != FEBPF_STATUS_OK)
        die("febpf_vm_verify", status);

    struct host_state state = { .fail = 1 };
    febpf_helper_binding_v1 binding = {
        .struct_size = sizeof(binding),
        .helper_id = HOST_HELPER_ID,
        .callback = host_helper,
        .user_data = &state,
    };
    uint32_t failed = 10;
    (void)run(vm, 0, &failed, &binding, FEBPF_STATUS_RUNTIME);
    if (failed != 10) {
        fprintf(stderr, "failed helper modified context\n");
        return 1;
    }

    state.fail = 0;
    uint32_t interpreted = 41;
    uint64_t interpreted_result =
        run(vm, 0, &interpreted, &binding, FEBPF_STATUS_OK);
    uint32_t jitted = 99;
    uint64_t jitted_result =
        run(vm, FEBPF_INVOCATION_JIT, &jitted, &binding, FEBPF_STATUS_OK);
    printf("helper-state: interp=%llu/%u jit=%llu/%u calls=%u\n",
           (unsigned long long)interpreted_result, interpreted,
           (unsigned long long)jitted_result, jitted, state.calls);

    status = febpf_vm_destroy(vm);
    if (status != FEBPF_STATUS_OK)
        die("febpf_vm_destroy", status);
    return 0;
}
