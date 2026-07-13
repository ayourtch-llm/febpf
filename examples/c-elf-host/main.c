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

static uint8_t *read_file(const char *path, size_t *length) {
    FILE *file = fopen(path, "rb");
    if (file == NULL || fseek(file, 0, SEEK_END) != 0) {
        perror(path);
        exit(2);
    }
    long end = ftell(file);
    if (end < 0 || fseek(file, 0, SEEK_SET) != 0) {
        perror(path);
        exit(2);
    }
    uint8_t *bytes = malloc((size_t)end + 1);
    if (bytes == NULL) {
        fprintf(stderr, "%s is too large\n", path);
        exit(2);
    }
    *length = fread(bytes, 1, (size_t)end, file);
    if (*length != (size_t)end || fclose(file) != 0) {
        fprintf(stderr, "could not read %s\n", path);
        exit(2);
    }
    return bytes;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s PROGRAM.o PROGRAM-NAME TARGET-BTF\n", argv[0]);
        return 2;
    }
    size_t object_len = 0;
    size_t target_len = 0;
    uint8_t *object = read_file(argv[1], &object_len);
    uint8_t *target = read_file(argv[3], &target_len);
    febpf_elf_options_v1 elf = {
        .struct_size = sizeof(elf),
        .flags = 0,
        .reserved = 0,
        .program_name = (const uint8_t *)argv[2],
        .program_name_len = strlen(argv[2]),
        .target_btf = target,
        .target_btf_len = target_len,
    };
    febpf_vm *vm = NULL;
    febpf_status status = febpf_vm_create_elf(object, object_len, &elf, &vm);
    free(object);
    free(target);
    if (status != FEBPF_STATUS_OK) {
        fail(status, "load ELF");
    }

    febpf_verify_options_v1 verify = {
        .struct_size = sizeof(verify),
        .context_model = FEBPF_CONTEXT_FLAT,
        .flags = 0,
        .context_size = 64,
        .verifier_instruction_budget = 0,
        .runtime_instruction_limit = 10000,
    };
    status = febpf_vm_verify(vm, &verify);
    if (status != FEBPF_STATUS_OK) {
        fail(status, "verify ELF program");
    }

    uint8_t context[64] = {0};
    int32_t x = 100;
    int32_t y = 20;
    int64_t z = 3;
    memcpy(context + 4, &x, sizeof(x));
    memcpy(context + 12, &y, sizeof(y));
    memcpy(context + 16, &z, sizeof(z));
    febpf_invocation_v1 invocation = {
        .struct_size = sizeof(invocation),
        .flags = 0,
        .reserved = 0,
        .context = context,
        .context_len = sizeof(context),
        .packet = NULL,
        .packet_len = 0,
        .output = NULL,
        .output_user_data = NULL,
    };
    uint64_t result = 0;
    status = febpf_vm_run(vm, &invocation, &result);
    if (status != FEBPF_STATUS_OK) {
        fail(status, "run ELF program");
    }
    printf("core-result=%" PRIu64 "\n", result);
    status = febpf_vm_destroy(vm);
    if (status != FEBPF_STATUS_OK) {
        fail(status, "destroy ELF program");
    }
    return result == 123 ? 0 : 1;
}
