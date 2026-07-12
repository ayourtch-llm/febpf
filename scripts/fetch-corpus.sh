#!/usr/bin/env bash
#
# fetch-corpus.sh — gently assemble a reproducible corpus of REAL-WORLD eBPF
# object files for measuring febpf's coverage. See docs/specs/corpus-tooling.md.
#
# WHAT IT DOES
#   1. generates corpus/include/vmlinux.h from the running kernel's BTF
#      (bpftool btf dump file /sys/kernel/btf/vmlinux format c),
#   2. shallow-clones a small, PINNED set of upstream repos into corpus/cache/
#      (one at a time, with a polite sleep between network operations),
#   3. copies libbpf's headers into corpus/include/,
#   4. compiles every discovered *.bpf.c with the local clang into
#      corpus/obj/<repo>__<name>.o, logging failures to corpus/build.log
#      and continuing (compile failures for some programs are EXPECTED).
#
# REQUIREMENTS: bash, git, clang (tested with clang 21), bpftool, and a
#   readable /sys/kernel/btf/vmlinux. Network access unless --offline.
#   (Shell scripts are exempt from febpf's zero-dependency rule.)
#
# USAGE
#   ./scripts/fetch-corpus.sh            # gentle, pinned, cached fetch + build
#   ./scripts/fetch-corpus.sh --offline  # build only from corpus/cache (no net)
#
# ENV
#   CORPUS_MIRROR  base URL for clones (default https://github.com)
#   SLEEP          seconds to sleep between network ops (default 2)
#
# GENTLE POLICY: shallow single-branch clones, pinned to a tag/commit, one repo
# at a time, cached and skipped if already present, never parallel. This is a
# deliberate requirement — do not turn it into a firehose.

set -u

# ---------------------------------------------------------------------------
# Pinned repo list. Format, one per line:
#   name|github-path|pinned-tag-or-commit|space-separated globs of *.bpf.c
# Keep this SMALL, self-contained, and always PINNED. Extend here.
# ---------------------------------------------------------------------------
REPOS="
libbpf-bootstrap|libbpf/libbpf-bootstrap|v1.4|examples/c/*.bpf.c
bcc|iovisor/bcc|v0.31.0|libbpf-tools/*.bpf.c
cilium-ebpf|cilium/ebpf|v0.21.0|testdata/btf_map_init.c
"

# libbpf itself: source of the header files programs #include. Pinned.
LIBBPF_REPO="libbpf/libbpf"
LIBBPF_PIN="v1.4.7"

# libbpf headers we make available under corpus/include (best-effort: we copy
# all of libbpf/src/*.h, this list documents the load-bearing ones).
LIBBPF_HEADERS="bpf_helpers.h bpf_helper_defs.h bpf_core_read.h bpf_tracing.h bpf_endian.h"

MIRROR="${CORPUS_MIRROR:-https://github.com}"
SLEEP="${SLEEP:-2}"
VMLINUX_BTF="/sys/kernel/btf/vmlinux"

OFFLINE=0
for arg in "$@"; do
    case "$arg" in
        --offline) OFFLINE=1 ;;
        -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

# Resolve paths relative to the repo root (script lives in scripts/).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CORPUS="$ROOT/corpus"
CACHE="$CORPUS/cache"
INCLUDE="$CORPUS/include"
OBJ="$CORPUS/obj"
BUILD_LOG="$CORPUS/build.log"

mkdir -p "$CACHE" "$INCLUDE" "$OBJ"
: > "$BUILD_LOG"

log()  { printf '%s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 1; }; }
need clang

# ---------------------------------------------------------------------------
# 1. vmlinux.h from the running kernel's BTF (local, no network).
# ---------------------------------------------------------------------------
if [ -f "$INCLUDE/vmlinux.h" ]; then
    log "vmlinux.h: cached ($INCLUDE/vmlinux.h)"
elif command -v bpftool >/dev/null 2>&1 && [ -r "$VMLINUX_BTF" ]; then
    log "generating vmlinux.h from $VMLINUX_BTF ..."
    if bpftool btf dump file "$VMLINUX_BTF" format c > "$INCLUDE/vmlinux.h" 2>>"$BUILD_LOG"; then
        log "  wrote $INCLUDE/vmlinux.h ($(wc -l < "$INCLUDE/vmlinux.h") lines)"
    else
        warn "bpftool failed to dump vmlinux.h (see build.log); CO-RE programs may not compile"
        rm -f "$INCLUDE/vmlinux.h"
    fi
else
    warn "no bpftool or unreadable $VMLINUX_BTF: cannot generate vmlinux.h; many programs will fail to compile"
fi

# ---------------------------------------------------------------------------
# Clone helper: shallow, single-branch, pinned, cached. Gentle.
#   clone_repo <dest-dir> <github-path> <pin>
# ---------------------------------------------------------------------------
clone_repo() {
    dest="$1"; path="$2"; pin="$3"
    if [ -d "$dest" ] && [ -n "$(ls -A "$dest" 2>/dev/null)" ]; then
        log "  cached: $dest (skipping download)"
        return 0
    fi
    if [ "$OFFLINE" = 1 ]; then
        warn "offline: $path not in cache; skipping"
        return 1
    fi
    if ! command -v git >/dev/null 2>&1; then
        warn "git not installed; cannot clone $path"
        return 1
    fi
    url="$MIRROR/$path"
    log "  cloning $url @ $pin (shallow) ..."
    if git clone --depth 1 --single-branch --branch "$pin" "$url" "$dest" >>"$BUILD_LOG" 2>&1; then
        log "  ok: $dest"
        sleep "$SLEEP"   # polite pause between network operations
        return 0
    fi
    warn "clone failed for $path @ $pin (see build.log)"
    rm -rf "$dest"
    sleep "$SLEEP"
    return 1
}

# ---------------------------------------------------------------------------
# 2. libbpf headers.
# ---------------------------------------------------------------------------
LIBBPF_DIR="$CACHE/libbpf"
if clone_repo "$LIBBPF_DIR" "$LIBBPF_REPO" "$LIBBPF_PIN"; then
    if [ -d "$LIBBPF_DIR/src" ]; then
        cp -f "$LIBBPF_DIR"/src/*.h "$INCLUDE/" 2>/dev/null || true
        # bpf/ subdir layout used by some programs (#include <bpf/bpf_helpers.h>)
        mkdir -p "$INCLUDE/bpf"
        cp -f "$LIBBPF_DIR"/src/*.h "$INCLUDE/bpf/" 2>/dev/null || true
        log "  copied libbpf headers into $INCLUDE (and $INCLUDE/bpf)"
        for h in $LIBBPF_HEADERS; do
            [ -f "$INCLUDE/$h" ] || warn "expected libbpf header missing: $h"
        done
    else
        warn "libbpf/src not found; headers unavailable"
    fi
else
    warn "libbpf headers unavailable; most programs will fail to compile"
fi

# ---------------------------------------------------------------------------
# 3 + 4. Clone each corpus repo and compile its *.bpf.c.
# ---------------------------------------------------------------------------
CFLAGS="-O2 -g -target bpf -D__TARGET_ARCH_x86 -Wno-unknown-attributes -Wno-compare-distinct-pointer-types"
INCLUDES="-I$INCLUDE -I$INCLUDE/bpf"
[ -d "$LIBBPF_DIR/src" ] && INCLUDES="$INCLUDES -I$LIBBPF_DIR/src"

n_repos=0
n_found=0
n_built=0

# Expand globs relative to a repo dir; print matching files (may be none).
expand_globs() {
    base="$1"; shift
    for g in "$@"; do
        # shellcheck disable=SC2086
        for f in $base/$g; do
            [ -f "$f" ] && printf '%s\n' "$f"
        done
    done
}

printf '%s\n' "$REPOS" | while IFS='|' read -r name path pin globs; do
    [ -z "$name" ] && continue
    n_repos=$((n_repos + 1))
    dest="$CACHE/$name"
    log ""
    log "== repo: $name ($path @ $pin) =="
    clone_repo "$dest" "$path" "$pin" || { log "  (unavailable, skipping)"; continue; }

    # shellcheck disable=SC2086
    files=$(expand_globs "$dest" $globs)
    if [ -z "$files" ]; then
        warn "no *.bpf.c matched [$globs] in $name"
        continue
    fi

    # Extra include dirs some repos want (their own headers next to sources).
    repo_inc=""
    for d in "$dest" "$dest/libbpf-tools" "$dest/examples/c" "$dest/testdata"; do
        [ -d "$d" ] && repo_inc="$repo_inc -I$d"
    done

    printf '%s\n' "$files" | while read -r src; do
        [ -z "$src" ] && continue
        n_found=$((n_found + 1))
        base=$(basename "$src")
        base=${base%.bpf.c}
        base=${base%.c}
        out="$OBJ/${name}__${base}.o"
        {
            echo "### $name: $src -> $out"
            echo "clang $CFLAGS $INCLUDES$repo_inc -c $src -o $out"
        } >> "$BUILD_LOG"
        # shellcheck disable=SC2086
        if clang $CFLAGS $INCLUDES $repo_inc -c "$src" -o "$out" >>"$BUILD_LOG" 2>&1; then
            n_built=$((n_built + 1))
            echo "  built: $(basename "$out")"
        else
            echo "  FAILED (logged): $name/$base"
            rm -f "$out"
        fi
    done
done

# The while|read subshell above can't export counters; recompute from disk so
# the summary is accurate regardless of shell.
built_now=$(ls -1 "$OBJ"/*.o 2>/dev/null | wc -l | tr -d ' ')
repos_present=$(ls -1d "$CACHE"/*/ 2>/dev/null | wc -l | tr -d ' ')

log ""
log "==================== corpus summary ===================="
log "  repos in cache : $repos_present (under $CACHE)"
log "  objects built  : $built_now (in $OBJ)"
log "  build log      : $BUILD_LOG"
log "  includes       : $INCLUDE"
if [ "$built_now" = 0 ]; then
    log ""
    log "  No objects built. If offline, populate $CACHE first; otherwise check"
    log "  $BUILD_LOG for clang/clone errors (missing vmlinux.h or headers is the"
    log "  usual cause). Compile failures for SOME programs are expected."
fi
log ""
log "  Next: ./scripts/scan-corpus.sh    # classify + histogram"
log "========================================================"
