#include "febpf.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fail(febpf_status status, const char *operation) {
    size_t len = febpf_last_error(NULL, 0);
    char *message = malloc(len + 1);
    if (message == NULL) {
        fprintf(stderr, "%s failed with status %" PRIu32 "\n", operation, status);
        exit(2);
    }
    febpf_last_error((uint8_t *)message, len + 1);
    fprintf(stderr, "%s failed with status %" PRIu32 ": %s\n",
            operation, status, message);
    free(message);
    exit(2);
}

static void output(void *user_data,
                   febpf_output_kind kind,
                   const uint8_t *data,
                   size_t len) {
    unsigned *lines = user_data;
    if (kind == FEBPF_OUTPUT_PRINTK) {
        printf("printk: %.*s\n", (int)len, (const char *)data);
        *lines += 1;
    }
}

int main(void) {
    static const char plugin[] =
        "r6 = r1\n"
        "r1 = 0x0064253d6e ll\n"
        "*(u64 *)(r10 - 8) = r1\n"
        "r1 = r10\n"
        "r1 += -8\n"
        "r2 = 5\n"
        "r3 = 42\n"
        "call trace_printk\n"
        "*(u8 *)(r6 + 1) = 7\n"
        "r0 = *(u8 *)(r6 + 0)\n"
        "exit\n";

    if (febpf_c_abi_version() != FEBPF_C_ABI_VERSION) {
        fprintf(stderr, "febpf C ABI version mismatch\n");
        return 2;
    }

    febpf_vm *vm = NULL;
    febpf_status status = febpf_vm_create_assembly(
        (const uint8_t *)plugin, strlen(plugin), &vm);
    if (status != FEBPF_STATUS_OK) {
        fail(status, "create");
    }

    febpf_verify_options_v1 verify = {
        .struct_size = sizeof(verify),
        .context_model = FEBPF_CONTEXT_FLAT,
        .flags = FEBPF_VERIFY_CONTEXT_WRITABLE,
        .context_size = 2,
        .verifier_instruction_budget = 0,
        .runtime_instruction_limit = 1000,
    };
    status = febpf_vm_verify(vm, &verify);
    if (status != FEBPF_STATUS_OK) {
        fail(status, "verify");
    }

    uint8_t context[2] = {9, 0};
    unsigned lines = 0;
    febpf_invocation_v1 invocation = {
        .struct_size = sizeof(invocation),
        .flags = 0,
        .reserved = 0,
        .context = context,
        .context_len = sizeof(context),
        .packet = NULL,
        .packet_len = 0,
        .output = output,
        .output_user_data = &lines,
    };
    uint64_t result = 0;
    status = febpf_vm_run(vm, &invocation, &result);
    if (status != FEBPF_STATUS_OK) {
        fail(status, "run");
    }

    printf("result=%" PRIu64 " context=[%u,%u]\n",
           result, context[0], context[1]);
    status = febpf_vm_destroy(vm);
    if (status != FEBPF_STATUS_OK) {
        fail(status, "destroy");
    }

    return result == 9 && context[1] == 7 && lines == 1 ? 0 : 1;
}
