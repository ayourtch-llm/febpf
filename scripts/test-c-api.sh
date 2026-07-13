#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

cargo rustc --lib --release --features c-api -- --crate-type=cdylib

case "$(uname -s)" in
    Linux)
        LIB_PATTERN='target/release/deps/libfebpf-*.so'
        LIB_NAME='libfebpf.so'
        RPATH='$ORIGIN/c-api'
        ;;
    Darwin)
        LIB_PATTERN='target/release/deps/libfebpf-*.dylib'
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
