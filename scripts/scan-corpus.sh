#!/usr/bin/env bash
#
# scan-corpus.sh — run febpf over a corpus of real eBPF objects and produce a
# coverage report: % that load, % that verify, and a HISTOGRAM ranked by the
# specific unsupported map types / helper ids blocking the most programs.
# See docs/specs/corpus-tooling.md.
#
# USAGE
#   ./scripts/scan-corpus.sh                 # scans corpus/obj/*.o
#   ./scripts/scan-corpus.sh path/to/*.o     # scans an explicit set (smoke test)
#   ./scripts/scan-corpus.sh tests/*.o       # smoke-test on febpf's own fixtures
#
# ENV
#   FEBPF        path to the febpf binary (default: build target/release/febpf)
#   TARGET_BTF   BTF for CO-RE relocation (default /sys/kernel/btf/vmlinux)
#   NO_BUILD=1   skip `cargo build --release`
#
# Classification keys off febpf's OUTPUT TEXT (unambiguous), not exit codes:
#   OK                                       "verification PASSED"
#   LOAD-FAIL:unsupported-map-type:<NAME>    "error: ... unsupported map type N (NAME)"
#   LOAD-FAIL:relocation                     "error: ..." mentioning reloc/CO-RE
#   LOAD-FAIL:other                          any other "error: ..." (load stage)
#   VERIFY-REJECT:unsupported-helper:#<id>   "verification FAILED: ... unknown helper #id"
#   VERIFY-REJECT:poisoned-relocation        "verification FAILED: ... unresolved CO-RE"
#   VERIFY-REJECT:other                      any other "verification FAILED:"

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CORPUS="$ROOT/corpus"
REPORT="$CORPUS/coverage-report.txt"
TARGET_BTF="${TARGET_BTF:-/sys/kernel/btf/vmlinux}"

# Collect the object list: explicit args, else corpus/obj/*.o.
if [ "$#" -gt 0 ]; then
    OBJS="$*"
else
    OBJS=$(ls -1 "$CORPUS"/obj/*.o 2>/dev/null)
fi
if [ -z "${OBJS:-}" ]; then
    echo "no objects to scan (pass paths, or run scripts/fetch-corpus.sh first)" >&2
    exit 1
fi

# Locate / build febpf.
FEBPF="${FEBPF:-$ROOT/target/release/febpf}"
if [ "${NO_BUILD:-0}" != 1 ] && [ ! -x "$FEBPF" ]; then
    echo "building febpf (release) ..." >&2
    ( cd "$ROOT" && cargo build --release ) >&2 || { echo "cargo build failed" >&2; exit 1; }
fi
[ -x "$FEBPF" ] || { echo "febpf binary not found at $FEBPF" >&2; exit 1; }

BTF_ARG=""
[ -r "$TARGET_BTF" ] && BTF_ARG="--target-btf $TARGET_BTF"

mkdir -p "$CORPUS"

# Kernel helper id -> name. Prefer reading the authoritative
# ___BPF_FUNC_MAPPER list from the installed uapi header (id = declared value);
# fall back to a small built-in table. Unknown ids show as helper#<id>.
BPF_UAPI_H=/usr/include/linux/bpf.h
helper_name() {
    if [ -r "$BPF_UAPI_H" ]; then
        local n
        n="$(sed -n "s/^[[:space:]]*FN(\([a-z0-9_]*\), $1,.*/\1/p" "$BPF_UAPI_H" | head -1)"
        if [ -n "$n" ]; then echo "$n"; return; fi
    fi
    case "$1" in
        1) echo map_lookup_elem ;;         2) echo map_update_elem ;;
        3) echo map_delete_elem ;;         4) echo probe_read ;;
        5) echo ktime_get_ns ;;            6) echo trace_printk ;;
        7) echo get_prandom_u32 ;;         8) echo get_smp_processor_id ;;
        12) echo tail_call ;;              14) echo get_current_pid_tgid ;;
        15) echo get_current_uid_gid ;;    16) echo get_current_comm ;;
        22) echo perf_event_read ;;        25) echo perf_event_output ;;
        26) echo skb_load_bytes ;;         27) echo get_stackid ;;
        35) echo get_current_task ;;       37) echo current_task_under_cgroup ;;
        45) echo probe_read_str ;;         80) echo get_current_cgroup_id ;;
        112) echo probe_read_user ;;       113) echo probe_read_kernel ;;
        114) echo probe_read_user_str ;;   115) echo probe_read_kernel_str ;;
        130) echo ringbuf_output ;;        131) echo ringbuf_reserve ;;
        132) echo ringbuf_submit ;;        133) echo ringbuf_discard ;;
        134) echo ringbuf_query ;;         141) echo get_task_stack ;;
        158) echo get_current_task_btf ;;  165) echo snprintf ;;
        173) echo get_func_ip ;;
        *) echo "helper#$1" ;;
    esac
}

# Per-object scratch tallies (written as lines to temp files, aggregated after).
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
BUCKETS="$TMP/buckets"      # one bucket label per line
MAPHIST="$TMP/maphist"      # one map-type NAME per blocked object
HELPHIST="$TMP/helphist"    # one helper id per blocked object
DETAIL="$TMP/detail"        # "<bucket>\t<obj>" per object
GRAPHS="$TMP/graphs"        # one object name per detected static tail-call graph
: > "$BUCKETS"; : > "$MAPHIST"; : > "$HELPHIST"; : > "$DETAIL"; : > "$GRAPHS"

total=0
for obj in $OBJS; do
    [ -f "$obj" ] || continue
    total=$((total + 1))
    name=$(basename "$obj")
    # shellcheck disable=SC2086
    out=$("$FEBPF" verify "$obj" $BTF_ARG 2>&1)

    if printf '%s' "$out" | grep -q "static tail-call link"; then
        echo "$name" >> "$GRAPHS"
    fi

    if printf '%s' "$out" | grep -q "verification PASSED"; then
        bucket="OK"
    elif line=$(printf '%s\n' "$out" | grep -m1 "unsupported map type"); then
        # "error: ... unsupported map type 27 (RINGBUF); ..."
        mt=$(printf '%s' "$line" | sed -n 's/.*unsupported map type [0-9]* (\([A-Za-z0-9_]*\)).*/\1/p')
        [ -z "$mt" ] && mt=$(printf '%s' "$line" | sed -n 's/.*unsupported map type \([0-9]*\).*/type-\1/p')
        [ -z "$mt" ] && mt="unknown"
        bucket="LOAD-FAIL:unsupported-map-type:$mt"
        echo "$mt" >> "$MAPHIST"
    elif line=$(printf '%s\n' "$out" | grep -m1 "verification FAILED:.*unknown helper #"); then
        hid=$(printf '%s' "$line" | sed -n 's/.*unknown helper #\([0-9]*\).*/\1/p')
        bucket="VERIFY-REJECT:unsupported-helper:#$hid"
        echo "$hid" >> "$HELPHIST"
    elif printf '%s' "$out" | grep -q "verification FAILED:.*unresolved CO-RE"; then
        bucket="VERIFY-REJECT:poisoned-relocation"
    elif printf '%s' "$out" | grep -q "verification FAILED:"; then
        bucket="VERIFY-REJECT:other"
    elif printf '%s' "$out" | grep -qiE "error:.*(relocation|CO-RE|unknown symbol)"; then
        bucket="LOAD-FAIL:relocation"
    elif printf '%s' "$out" | grep -q "error:"; then
        bucket="LOAD-FAIL:other"
    else
        bucket="LOAD-FAIL:other"
    fi

    echo "$bucket" >> "$BUCKETS"
    printf '%s\t%s\n' "$bucket" "$name" >> "$DETAIL"
done

# --- Aggregate ------------------------------------------------------------
n_ok=$(grep -c '^OK$' "$BUCKETS" || true)
n_load_fail=$(grep -c '^LOAD-FAIL:' "$BUCKETS" || true)
n_verify_reject=$(grep -c '^VERIFY-REJECT:' "$BUCKETS" || true)
# "loaded" = reached the verifier (OK or any VERIFY-REJECT).
n_loaded=$((n_ok + n_verify_reject))
n_graphs=$(wc -l < "$GRAPHS" | tr -d ' ')

pct() { # pct <num> <den>
    if [ "$2" -eq 0 ]; then echo "0.0"; else
        awk "BEGIN{printf \"%.1f\", ($1/$2)*100}"
    fi
}

{
    echo "======================================================================"
    echo " febpf corpus coverage report"
    echo " generated: $(date -u '+%Y-%m-%d %H:%M:%SZ')   febpf: $FEBPF"
    echo " target BTF: ${BTF_ARG:-<none>}"
    echo "======================================================================"
    echo ""
    echo "objects scanned : $total"
    echo "loaded (reached verifier) : $n_loaded  ($(pct "$n_loaded" "$total")%)"
    echo "verified OK               : $n_ok  ($(pct "$n_ok" "$total")%)"
    echo "load failures             : $n_load_fail  ($(pct "$n_load_fail" "$total")%)"
    echo "verify rejections         : $n_verify_reject  ($(pct "$n_verify_reject" "$total")%)"
    echo "static tail-call graphs   : $n_graphs  ($(pct "$n_graphs" "$total")%)"
    echo ""
    echo "---- outcome buckets (by count) --------------------------------------"
    sort "$BUCKETS" | uniq -c | sort -rn | while read -r c b; do
        printf "  %5d  %s\n" "$c" "$b"
    done
    echo ""
    echo "==== HISTOGRAM 1: unsupported MAP TYPES (top load blockers) ==========="
    if [ -s "$MAPHIST" ]; then
        sort "$MAPHIST" | uniq -c | sort -rn | while read -r c mt; do
            printf "  %5d programs blocked by map type  %s\n" "$c" "$mt"
        done
    else
        echo "  (none — no object was blocked by an unsupported map type)"
    fi
    echo ""
    echo "==== HISTOGRAM 2: unknown HELPERS (top verify blockers) =============="
    if [ -s "$HELPHIST" ]; then
        sort -n "$HELPHIST" | uniq -c | sort -rn | while read -r c hid; do
            printf "  %5d programs blocked by helper #%-4s %s\n" "$c" "$hid" "$(helper_name "$hid")"
        done
    else
        echo "  (none — no object was blocked by an unknown helper)"
    fi
    echo ""
    echo "---- per-object detail -----------------------------------------------"
    sort "$DETAIL" | while IFS="$(printf '\t')" read -r b n; do
        printf "  %-48s %s\n" "$n" "$b"
    done
    echo ""
    echo "----------------------------------------------------------------------"
    echo "The two histograms are the worklist: implement the map types / helpers"
    echo "at the top to unblock the most real-world programs. See"
    echo "docs/specs/corpus-tooling.md."
} | tee "$REPORT"

echo "" >&2
echo "report written to $REPORT" >&2
