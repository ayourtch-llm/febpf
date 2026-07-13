#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

# This command-line crate type is intentionally built outside Cargo's normal
# release graph. Keep it in an isolated directory and disable profile LTO for
# this artifact: some GNU linkers cannot consume the LLVM bitcode objects that
# rustc otherwise emits for a dynamically requested cdylib. Ordinary release
# builds still use the manifest's LTO setting.
C_API_BUILD_DIR=${C_API_BUILD_DIR:-target/c-api-build}
CARGO_PROFILE_RELEASE_LTO=false cargo rustc \
    --target-dir "$C_API_BUILD_DIR" \
    --lib --release --features c-api -- --crate-type=cdylib

case "$(uname -s)" in
    Linux)
        LIB_PATTERN="$C_API_BUILD_DIR/release/deps/libfebpf-*.so"
        LIB_NAME='libfebpf.so'
        RPATH='$ORIGIN/c-api'
        ;;
    Darwin)
        LIB_PATTERN="$C_API_BUILD_DIR/release/deps/libfebpf-*.dylib"
        LIB_NAME='libfebpf.dylib'
        RPATH='@loader_path/c-api'
        ;;
    *)
        echo "native C ABI smoke test is supported on Linux and macOS" >&2
        exit 2
        ;;
esac

# Cargo keeps a command-line crate type under its hashed dependency filename
# because the manifest deliberately remains rlib-only for no-std builds.
LIBRARY=$(ls -t $LIB_PATTERN 2>/dev/null | head -n 1)
if [[ -z "$LIBRARY" ]]; then
    echo "cargo did not produce the expected C ABI shared library" >&2
    exit 2
fi
mkdir -p target/c-api
cp "$LIBRARY" "target/c-api/$LIB_NAME"

"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    -I include examples/c-host/main.c \
    -L target/c-api -Wl,-rpath,"$RPATH" -lfebpf \
    -o target/c-api-example

target/c-api-example

"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    -I include examples/c-log-filter/main.c \
    -L target/c-api -Wl,-rpath,"$RPATH" -lfebpf \
    -o target/c-log-filter-example

ACTUAL=$(printf 'INFO ready\nDEBUG noisy\nTOKEN=secret\n' | \
    target/c-log-filter-example examples/c-log-filter/filter.s)
EXPECTED=$'INFO ready\nTOKEN=*ecret'
if [[ "$ACTUAL" != "$EXPECTED" ]]; then
    echo "C log-filter output did not match" >&2
    printf 'expected:\n%s\nactual:\n%s\n' "$EXPECTED" "$ACTUAL" >&2
    exit 1
fi

"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    -I include examples/c-elf-host/main.c \
    -L target/c-api -Wl,-rpath,"$RPATH" -lfebpf \
    -o target/c-elf-example

target/c-elf-example tests/core_probe.o text tests/core_target.o

"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    -I include examples/c-map-host/main.c \
    -L target/c-api -Wl,-rpath,"$RPATH" -lfebpf \
    -o target/c-map-example

target/c-map-example tests/legacy_maps.o tests/global_data.o

"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    -I include examples/c-helper-host/main.c \
    -L target/c-api -Wl,-rpath,"$RPATH" -lfebpf \
    -o target/c-helper-example

HELPER_ACTUAL=$(target/c-helper-example)
HELPER_EXPECTED='helper-state: interp=123/42 jit=123/100 calls=3'
if [[ "$HELPER_ACTUAL" != "$HELPER_EXPECTED" ]]; then
    echo "C helper output did not match" >&2
    printf 'expected:\n%s\nactual:\n%s\n' "$HELPER_EXPECTED" "$HELPER_ACTUAL" >&2
    exit 1
fi

"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    -I include examples/c-attach-host/main.c \
    -L target/c-api -Wl,-rpath,"$RPATH" -lfebpf \
    -o target/c-attach-example

ATTACH_ACTUAL=$(target/c-attach-example \
    tests/attach_target.o fentry/dummy_target tests/attach_target.o \
    fentry/dummy_target actual_target)
ATTACH_EXPECTED='attach-target: fentry/dummy_target -> actual_target verified'
if [[ "$ATTACH_ACTUAL" != "$ATTACH_EXPECTED" ]]; then
    echo "C attach-target output did not match" >&2
    printf 'expected:\n%s\nactual:\n%s\n' "$ATTACH_EXPECTED" "$ATTACH_ACTUAL" >&2
    exit 1
fi

# When the honest pinned corpus and live kernel BTF are provisioned, exercise
# the same host against BCC cachestat's real application-side retargeting.
if [[ -r corpus/obj/bcc__cachestat.o && -r /sys/kernel/btf/vmlinux ]]; then
    target/c-attach-example \
        corpus/obj/bcc__cachestat.o fentry/account_page_dirtied \
        /sys/kernel/btf/vmlinux fentry/account_page_dirtied folio_account_dirtied
fi
