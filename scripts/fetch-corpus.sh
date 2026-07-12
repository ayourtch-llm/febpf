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
# REQUIREMENTS: bash, git, clang (tested with clang 21), sha256sum, bpftool, and a
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
# GENTLE POLICY: shallow pinned fetches, one repo
# at a time, cached and skipped if already present, never parallel. This is a
# deliberate requirement — do not turn it into a firehose.

set -u
export LC_ALL=C

# ---------------------------------------------------------------------------
# Pinned repo list. Format, one per line:
#   name|github-path|clone-ref|expected-commit|space-separated globs of *.bpf.c
# Keep this SMALL, self-contained, and always PINNED. Extend here.
# ---------------------------------------------------------------------------
REPOS="
libbpf-bootstrap|libbpf/libbpf-bootstrap|fac4e8ddf011aead8e14962bf8db74542331264b|fac4e8ddf011aead8e14962bf8db74542331264b|examples/c/*.bpf.c
bcc|iovisor/bcc|v0.31.0|052022b0d128f56405b0c4fab818b7479fd0eacc|libbpf-tools/*.bpf.c
cilium-ebpf|cilium/ebpf|v0.21.0|fd33a781ea9ebf9d1bff748707793deccc412c05|testdata/btf_map_init.c
xdp-tools|xdp-project/xdp-tools|v1.6.3|8fbad9f0af621a22aa87ff2520b3735915b1f0fd|xdp-bench/*.bpf.c
inspektor-gadget|inspektor-gadget/inspektor-gadget|v0.54.0|0c733324b97dbbbe8d85b64ae93622a86fe7bf45|gadgets/*/program.bpf.c
"

# libbpf itself: source of the header files programs #include. Pinned.
LIBBPF_REPO="libbpf/libbpf"
LIBBPF_PIN="v1.4.7"
LIBBPF_COMMIT="ca72d0731f8c693bd98caba70d951fc0bfe20788"

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
need sha256sum

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
#   clone_repo <dest-dir> <github-path> <pin> <expected-commit>
# ---------------------------------------------------------------------------
clone_repo() {
    dest="$1"; path="$2"; pin="$3"; expected="$4"
    if [ -d "$dest" ] && [ -n "$(ls -A "$dest" 2>/dev/null)" ]; then
        if [ ! -d "$dest/.git" ]; then
            echo "ERROR: cached repo is not a git checkout: $dest" >&2
            echo "       remove it and rerun fetch-corpus.sh" >&2
            return 2
        fi
        if ! command -v git >/dev/null 2>&1; then
            echo "ERROR: git is required to validate cached repo $dest" >&2
            return 2
        fi
        actual=$(git -C "$dest" rev-parse HEAD 2>/dev/null) || {
            echo "ERROR: cannot read cached repo HEAD: $dest" >&2
            return 2
        }
        if [ "$actual" != "$expected" ]; then
            echo "ERROR: cached repo pin mismatch: $dest" >&2
            echo "       expected $expected ($pin), found $actual" >&2
            echo "       remove $dest and rerun fetch-corpus.sh" >&2
            return 2
        fi
        log "  cached: $dest @ $actual (validated; skipping download)"
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
    if printf '%s' "$pin" | grep -Eq '^[0-9a-f]{40}$'; then
        clone_ok=0
        if git init -q "$dest" >>"$BUILD_LOG" 2>&1 \
            && git -C "$dest" remote add origin "$url" >>"$BUILD_LOG" 2>&1 \
            && git -C "$dest" fetch --depth 1 origin "$pin" >>"$BUILD_LOG" 2>&1 \
            && git -C "$dest" checkout -q --detach FETCH_HEAD >>"$BUILD_LOG" 2>&1; then
            clone_ok=1
        fi
    else
        clone_ok=0
        if git clone --depth 1 --single-branch --branch "$pin" "$url" "$dest" >>"$BUILD_LOG" 2>&1; then
            clone_ok=1
        fi
    fi
    if [ "$clone_ok" -eq 1 ]; then
        actual=$(git -C "$dest" rev-parse HEAD 2>/dev/null) || actual=""
        if [ "$actual" != "$expected" ]; then
            warn "clone resolved $pin to $actual, expected $expected; refusing moving/mismatched pin"
            rm -rf "$dest"
            sleep "$SLEEP"
            return 2
        fi
        log "  ok: $dest @ $actual"
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
clone_repo "$LIBBPF_DIR" "$LIBBPF_REPO" "$LIBBPF_PIN" "$LIBBPF_COMMIT"
clone_status=$?
if [ "$clone_status" -eq 0 ]; then
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
    [ "$clone_status" -eq 2 ] && exit 1
    warn "libbpf headers unavailable; most programs will fail to compile"
fi

# ---------------------------------------------------------------------------
# 3 + 4. Clone each corpus repo and compile its *.bpf.c.
# ---------------------------------------------------------------------------
CFLAGS="-O2 -g -target bpf -D__TARGET_ARCH_x86 -Wno-unknown-attributes -Wno-compare-distinct-pointer-types"
INCLUDES="-I$INCLUDE -I$INCLUDE/bpf"
[ -d "$LIBBPF_DIR/src" ] && INCLUDES="$INCLUDES -I$LIBBPF_DIR/src"

# xdp-tools follows the host distro's Linux headers for asm/types.h. Clang's
# BPF target does not automatically add the host multiarch include directory,
# so add the first installed linux-gnu directory that provides asm/. This is
# optional for the older lanes and keeps the script usable on non-Debian hosts.
for arch_inc in /usr/include/*-linux-gnu; do
    if [ -d "$arch_inc/asm" ]; then
        INCLUDES="$INCLUDES -I$arch_inc"
        break
    fi
done

# libbpf v1.4.7 exposes the xdp load/store helpers used by xdp-tools. The
# pinned xdp-tools sources retain fallback declarations unless this feature is
# advertised, matching their configure-time HAVE_LIBBPF_BPF_PROGRAM__TYPE.
CFLAGS="$CFLAGS -DHAVE_LIBBPF_BPF_PROGRAM__TYPE"

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

while IFS='|' read -r name path pin expected globs; do
    [ -z "$name" ] && continue
    n_repos=$((n_repos + 1))
    dest="$CACHE/$name"
    log ""
    log "== repo: $name ($path @ $pin) =="
    clone_repo "$dest" "$path" "$pin" "$expected"
    clone_status=$?
    if [ "$clone_status" -ne 0 ]; then
        [ "$clone_status" -eq 2 ] && exit 1
        log "  (unavailable, skipping)"
        continue
    fi

    # shellcheck disable=SC2086
    files=$(expand_globs "$dest" $globs)
    if [ -z "$files" ]; then
        warn "no *.bpf.c matched [$globs] in $name"
        continue
    fi

    if [ "$name" = inspektor-gadget ]; then
        source_count=$(printf '%s\n' "$files" | wc -l | tr -d ' ')
        if [ "$source_count" -ne 39 ]; then
            echo "ERROR: pinned Inspektor Gadget lane expected 39 top-level production sources, found $source_count" >&2
            exit 1
        fi
        # Remove only outputs owned by this lane so deleted/renamed upstream
        # sources cannot survive a rebuild as stale corpus objects.
        rm -f "$OBJ"/inspektor-gadget__*.o
    fi

    # Extra include dirs some repos want (their own headers next to sources).
    repo_inc=""
    for d in "$dest" "$dest/headers" "$dest/libbpf-tools" "$dest/examples/c" "$dest/testdata"; do
        [ -d "$d" ] && repo_inc="$repo_inc -I$d"
    done
    if [ "$name" = inspektor-gadget ]; then
        # The pinned gadget sources use their checked-in architecture and
        # shared gadget headers; keep these ahead of the generic corpus headers.
        repo_inc="-I$dest/include/gadget/amd64 -I$dest/include $repo_inc"
    fi

    printf '%s\n' "$files" | while read -r src; do
        [ -z "$src" ] && continue
        n_found=$((n_found + 1))
        base=$(basename "$src")
        base=${base%.bpf.c}
        base=${base%.c}
        if [ "$name" = inspektor-gadget ]; then
            base=$(basename "$(dirname "$src")")
        fi
        out="$OBJ/${name}__${base}.o"
        if [ "$name" = inspektor-gadget ]; then
            compile_includes="$repo_inc $INCLUDES"
        else
            compile_includes="$INCLUDES $repo_inc"
        fi
        {
            echo "### $name: $src -> $out"
            echo "clang $CFLAGS $compile_includes -c $src -o $out"
        } >> "$BUILD_LOG"
        # shellcheck disable=SC2086
        if clang $CFLAGS $compile_includes -c "$src" -o "$out" >>"$BUILD_LOG" 2>&1; then
            n_built=$((n_built + 1))
            echo "  built: $(basename "$out")"
        else
            echo "  FAILED (logged): $name/$base"
            rm -f "$out"
        fi
    done
done <<EOF
$REPOS
EOF

# Deterministic, timestamp-free provenance for the production gadget lane.
# Paths are relative/stable and hashes cover both pinned inputs and outputs.
IG_MANIFEST="$CORPUS/inspektor-gadget-manifest.sha256"
IG_DIR="$CACHE/inspektor-gadget"
if [ -d "$IG_DIR/.git" ]; then
    : > "$IG_MANIFEST"
    printf 'commit\t%s\n' "$(git -C "$IG_DIR" rev-parse HEAD)" >> "$IG_MANIFEST"
    printf 'clang\t%s\n' "$(clang --version | head -1)" >> "$IG_MANIFEST"
    for src in "$IG_DIR"/gadgets/*/program.bpf.c; do
        [ -f "$src" ] || continue
        rel=${src#"$IG_DIR"/}
        hash=$(sha256sum "$src" | awk '{print $1}')
        printf 'source\t%s\t%s\n' "$hash" "$rel" >> "$IG_MANIFEST"
    done
    for out in "$OBJ"/inspektor-gadget__*.o; do
        [ -f "$out" ] || continue
        hash=$(sha256sum "$out" | awk '{print $1}')
        printf 'object\t%s\t%s\n' "$hash" "$(basename "$out")" >> "$IG_MANIFEST"
    done
    log "  Inspektor Gadget manifest: $IG_MANIFEST"
fi

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
