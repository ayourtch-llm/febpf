#include "febpf.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_CONTEXT_ABI_VERSION 1u
#define LOG_RECORD_CAPACITY 4096u

#define LOG_DROP 0u
#define LOG_ACCEPT 1u

typedef struct log_context_v1 {
    uint32_t abi_version;
    uint32_t record_len;
    uint8_t record[LOG_RECORD_CAPACITY];
} log_context_v1;

_Static_assert(offsetof(log_context_v1, record) == 8,
               "plugin record offset changed");

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

static uint8_t *read_file(const char *path, size_t *length) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        perror(path);
        exit(2);
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        perror("seek plugin");
        exit(2);
    }
    long end = ftell(file);
    if (end < 0 || fseek(file, 0, SEEK_SET) != 0) {
        perror("size plugin");
        exit(2);
    }
    uint8_t *bytes = malloc((size_t)end + 1);
    if (bytes == NULL) {
        fprintf(stderr, "plugin is too large\n");
        exit(2);
    }
    *length = fread(bytes, 1, (size_t)end, file);
    if (*length != (size_t)end || fclose(file) != 0) {
        fprintf(stderr, "could not read plugin %s\n", path);
        exit(2);
    }
    return bytes;
}

static void plugin_output(void *user_data,
                          febpf_output_kind kind,
                          const uint8_t *data,
                          size_t len) {
    (void)user_data;
    if (kind == FEBPF_OUTPUT_PRINTK) {
        fprintf(stderr, "plugin: %.*s\n", (int)len, (const char *)data);
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s FILTER.s < input.log\n", argv[0]);
        return 2;
    }

    size_t source_len = 0;
    uint8_t *source = read_file(argv[1], &source_len);
    febpf_vm *vm = NULL;
    febpf_status status = febpf_vm_create_assembly(source, source_len, &vm);
    free(source);
    if (status != FEBPF_STATUS_OK) {
        fail(status, "create plugin");
    }

    febpf_verify_options_v1 verify = {
        .struct_size = sizeof(verify),
        .context_model = FEBPF_CONTEXT_FLAT,
        .flags = FEBPF_VERIFY_CONTEXT_WRITABLE,
        .context_size = sizeof(log_context_v1),
        .verifier_instruction_budget = 0,
        .runtime_instruction_limit = 10000,
    };
    status = febpf_vm_verify(vm, &verify);
    if (status != FEBPF_STATUS_OK) {
        fail(status, "verify plugin");
    }

    log_context_v1 context;
    for (;;) {
        memset(&context, 0, sizeof(context));
        if (fgets((char *)context.record, sizeof(context.record), stdin) == NULL) {
            break;
        }
        context.abi_version = LOG_CONTEXT_ABI_VERSION;
        context.record_len = (uint32_t)strlen((const char *)context.record);
        if (context.record_len == LOG_RECORD_CAPACITY - 1 &&
            context.record[context.record_len - 1] != '\n' && !feof(stdin)) {
            fprintf(stderr, "input record exceeds %u bytes\n", LOG_RECORD_CAPACITY - 1);
            febpf_vm_destroy(vm);
            return 2;
        }

        febpf_invocation_v1 invocation = {
            .struct_size = sizeof(invocation),
            .flags = 0,
            .reserved = 0,
            .context = (uint8_t *)&context,
            .context_len = sizeof(context),
            .packet = NULL,
            .packet_len = 0,
            .output = plugin_output,
            .output_user_data = NULL,
        };
        uint64_t action = UINT64_MAX;
        status = febpf_vm_run(vm, &invocation, &action);
        if (status != FEBPF_STATUS_OK) {
            fail(status, "run plugin");
        }
        if (context.record_len > LOG_RECORD_CAPACITY) {
            fprintf(stderr, "plugin returned an invalid record length\n");
            febpf_vm_destroy(vm);
            return 2;
        }
        if (action == LOG_ACCEPT) {
            if (fwrite(context.record, 1, context.record_len, stdout) !=
                context.record_len) {
                perror("write output");
                febpf_vm_destroy(vm);
                return 2;
            }
        } else if (action != LOG_DROP) {
            fprintf(stderr, "plugin returned unknown action %" PRIu64 "\n", action);
            febpf_vm_destroy(vm);
            return 2;
        }
    }
    if (ferror(stdin)) {
        perror("read input");
        febpf_vm_destroy(vm);
        return 2;
    }

    status = febpf_vm_destroy(vm);
    if (status != FEBPF_STATUS_OK) {
        fail(status, "destroy plugin");
    }
    return 0;
}
