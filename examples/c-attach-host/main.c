#include "febpf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fail(const char *operation, febpf_status status)
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

static uint8_t *read_file(const char *path, size_t *length)
{
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

int main(int argc, char **argv)
{
    if (argc != 6) {
        fprintf(stderr,
                "usage: %s PROGRAM.o PROGRAM-NAME TARGET-BTF SECTION FUNCTION\n",
                argv[0]);
        return 2;
    }
    size_t object_len = 0;
    size_t target_len = 0;
    uint8_t *object = read_file(argv[1], &object_len);
    uint8_t *target = read_file(argv[3], &target_len);
    febpf_elf_options_v2 old_options = {
        .struct_size = sizeof(old_options),
        .program_name = (const uint8_t *)argv[2],
        .program_name_len = strlen(argv[2]),
        .target_btf = target,
        .target_btf_len = target_len,
    };
    febpf_vm *vm = NULL;
    febpf_status status =
        febpf_vm_create_elf_v2(object, object_len, &old_options, &vm);
    if (status != FEBPF_STATUS_PROGRAM || vm != NULL) {
        fprintf(stderr, "unretargeted BTF section was not rejected honestly\n");
        return 1;
    }

    febpf_attach_target_v1 target_override = {
        .struct_size = sizeof(target_override),
        .selector_kind = FEBPF_ATTACH_TARGET_SECTION,
        .selector = (const uint8_t *)argv[4],
        .selector_len = strlen(argv[4]),
        .function = (const uint8_t *)argv[5],
        .function_len = strlen(argv[5]),
    };
    febpf_elf_options_v3 options = {
        .struct_size = sizeof(options),
        .program_name = (const uint8_t *)argv[2],
        .program_name_len = strlen(argv[2]),
        .target_btf = target,
        .target_btf_len = target_len,
        .attach_targets = &target_override,
        .attach_target_count = 1,
    };
    status = febpf_vm_create_elf_v3(object, object_len, &options, &vm);
    free(object);
    free(target);
    if (status != FEBPF_STATUS_OK)
        fail("retarget ELF", status);

    febpf_verify_options_v1 verify = {
        .struct_size = sizeof(verify),
        .context_model = FEBPF_CONTEXT_FLAT,
        .context_size = sizeof(uint64_t),
    };
    status = febpf_vm_verify(vm, &verify);
    if (status != FEBPF_STATUS_OK)
        fail("verify retargeted ELF", status);
    printf("attach-target: %s -> %s verified\n", argv[4], argv[5]);
    status = febpf_vm_destroy(vm);
    if (status != FEBPF_STATUS_OK)
        fail("destroy retargeted ELF", status);
    return 0;
}
