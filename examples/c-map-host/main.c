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

static void require_status(febpf_status actual,
                           febpf_status expected,
                           const char *operation) {
    if (actual != expected) {
        fail(actual, operation);
    }
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

static febpf_map_info_v1 map_info(febpf_vm *vm, const char *name) {
    febpf_map_info_v1 info = {.struct_size = sizeof(info)};
    febpf_status status = febpf_vm_map_info(
        vm, (const uint8_t *)name, strlen(name), &info);
    if (status != FEBPF_STATUS_OK) {
        fail(status, "map info");
    }
    return info;
}

static void prove_preconstruction_configuration(const char *path) {
    size_t object_len = 0;
    uint8_t *object = read_file(path, &object_len);
    static const char program[] = "socket";
    static const char map[] = "counts";
    febpf_map_max_entries_v1 override = {
        .struct_size = sizeof(override),
        .map_name = (const uint8_t *)map,
        .map_name_len = sizeof(map) - 1,
        .max_entries = 1,
        .reserved = 0,
    };
    febpf_elf_options_v2 options = {
        .struct_size = sizeof(options),
        .flags = 0,
        .reserved = 0,
        .program_name = (const uint8_t *)program,
        .program_name_len = sizeof(program) - 1,
        .target_btf = NULL,
        .target_btf_len = 0,
        .map_overrides = &override,
        .map_override_count = 1,
    };
    febpf_vm *vm = NULL;
    febpf_status status = febpf_vm_create_elf_v2(
        object, object_len, &options, &vm);
    free(object);
    if (status != FEBPF_STATUS_OK) {
        fail(status, "load configured ELF");
    }
    febpf_map_info_v1 info = map_info(vm, map);
    if (info.kind != FEBPF_MAP_HASH || info.max_entries != 1 ||
        info.key_size != 4 || info.value_size != 8) {
        fprintf(stderr, "configured map metadata mismatch\n");
        exit(2);
    }

    uint32_t key0 = 0;
    uint32_t key1 = 1;
    uint64_t value = 11;
    require_status(febpf_vm_map_update(
                       vm, (const uint8_t *)map, sizeof(map) - 1,
                       (const uint8_t *)&key0, sizeof(key0),
                       (const uint8_t *)&value, sizeof(value),
                       FEBPF_MAP_UPDATE_NOEXIST),
                   FEBPF_STATUS_OK, "insert configured map");
    require_status(febpf_vm_map_update(
                       vm, (const uint8_t *)map, sizeof(map) - 1,
                       (const uint8_t *)&key1, sizeof(key1),
                       (const uint8_t *)&value, sizeof(value),
                       FEBPF_MAP_UPDATE_ANY),
                   FEBPF_STATUS_MAP, "enforce configured capacity");
    require_status(febpf_vm_destroy(vm), FEBPF_STATUS_OK,
                   "destroy configured VM");
}

static void prove_durable_runtime_state(const char *path) {
    size_t object_len = 0;
    uint8_t *object = read_file(path, &object_len);
    static const char program[] = "socket";
    febpf_elf_options_v1 options = {
        .struct_size = sizeof(options),
        .flags = 0,
        .reserved = 0,
        .program_name = (const uint8_t *)program,
        .program_name_len = sizeof(program) - 1,
        .target_btf = NULL,
        .target_btf_len = 0,
    };
    febpf_vm *vm = NULL;
    febpf_status status = febpf_vm_create_elf(object, object_len, &options, &vm);
    free(object);
    if (status != FEBPF_STATUS_OK) {
        fail(status, "load global-data ELF");
    }

    febpf_map_info_v1 rodata = map_info(vm, ".rodata.cst16");
    if ((rodata.flags & FEBPF_MAP_READONLY) == 0) {
        fprintf(stderr, "rodata map is not frozen\n");
        exit(2);
    }
    febpf_verify_options_v1 verify = {
        .struct_size = sizeof(verify),
        .context_model = FEBPF_CONTEXT_SKB,
        .flags = 0,
        .context_size = 0,
        .verifier_instruction_budget = 0,
        .runtime_instruction_limit = 10000,
    };
    require_status(febpf_vm_verify(vm, &verify), FEBPF_STATUS_OK,
                   "verify global-data ELF");
    febpf_invocation_v1 invocation = {
        .struct_size = sizeof(invocation),
        .flags = 0,
        .reserved = 0,
        .context = NULL,
        .context_len = 0,
        .packet = NULL,
        .packet_len = 0,
        .output = NULL,
        .output_user_data = NULL,
    };
    uint64_t first = 0;
    uint64_t second = 0;
    require_status(febpf_vm_run(vm, &invocation, &first), FEBPF_STATUS_OK,
                   "first global-data run");

    static const char data[] = ".data";
    uint32_t key = 0;
    uint64_t scale = 7;
    require_status(febpf_vm_map_update(
                       vm, (const uint8_t *)data, sizeof(data) - 1,
                       (const uint8_t *)&key, sizeof(key),
                       (const uint8_t *)&scale, sizeof(scale),
                       FEBPF_MAP_UPDATE_EXIST),
                   FEBPF_STATUS_OK, "update data map");
    require_status(febpf_vm_run(vm, &invocation, &second), FEBPF_STATUS_OK,
                   "second global-data run");

    static const char bss[] = ".bss";
    uint64_t counter = 0;
    require_status(febpf_vm_map_lookup(
                       vm, (const uint8_t *)bss, sizeof(bss) - 1,
                       (const uint8_t *)&key, sizeof(key),
                       (uint8_t *)&counter, sizeof(counter)),
                   FEBPF_STATUS_OK, "lookup bss map");
    require_status(febpf_vm_map_lookup(
                       vm, (const uint8_t *)data, sizeof(data) - 1,
                       (const uint8_t *)&key, sizeof(key),
                       (uint8_t *)&scale, sizeof(scale)),
                   FEBPF_STATUS_OK, "lookup data map");
    uint8_t zeros[16] = {0};
    require_status(febpf_vm_map_update(
                       vm, (const uint8_t *)".rodata.cst16", 13,
                       (const uint8_t *)&key, sizeof(key), zeros, sizeof(zeros),
                       FEBPF_MAP_UPDATE_EXIST),
                   FEBPF_STATUS_MAP, "reject frozen-map update");
    printf("map-state: first=%" PRIu64 " second=%" PRIu64
           " counter=%" PRIu64 " scale=%" PRIu64 "\n",
           first, second, counter, scale);
    require_status(febpf_vm_destroy(vm), FEBPF_STATUS_OK,
                   "destroy global-data VM");
    if (first != 410 || second != 820 || counter != 20 || scale != 8) {
        exit(1);
    }
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s LEGACY-MAPS.o GLOBAL-DATA.o\n", argv[0]);
        return 2;
    }
    prove_preconstruction_configuration(argv[1]);
    prove_durable_runtime_state(argv[2]);
    return 0;
}
