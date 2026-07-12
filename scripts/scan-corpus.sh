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
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CORPUS="$ROOT/corpus"
REPORT="${CORPUS_REPORT:-$CORPUS/coverage-report.txt}"
TARGET_BTF="${TARGET_BTF:-/sys/kernel/btf/vmlinux}"

# Collect the object list: explicit args, else corpus/obj/*.o.
if [ "$#" -gt 0 ]; then
    OBJS=("$@")
else
    mapfile -t OBJS < <(find "$CORPUS/obj" -maxdepth 1 -type f -name '*.o' -print 2>/dev/null | sort)
fi
if [ "${#OBJS[@]}" -eq 0 ]; then
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

BTF_ARGS=()
[ -r "$TARGET_BTF" ] && BTF_ARGS=(--target-btf "$TARGET_BTF")

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
DETAIL="$TMP/detail"        # "<bucket>\t<obj>::<program>" per entry
OBJECT_DETAIL="$TMP/object-detail"
OBJECT_BUCKETS="$TMP/object-buckets"
GRAPHS="$TMP/graphs"        # one object name per detected static tail-call graph
LINKS="$TMP/links"          # one line per static tail-call edge
EMPTY_PACKET="$TMP/empty-packet"
: > "$BUCKETS"; : > "$MAPHIST"; : > "$HELPHIST"; : > "$DETAIL"
: > "$OBJECT_DETAIL"; : > "$OBJECT_BUCKETS"; : > "$GRAPHS"; : > "$LINKS"
: > "$EMPTY_PACKET"

# Application-side loader configuration for the pinned Gadget lane. These
# exact objects include user_stack_map.h's explicit max_entries=0 map and the
# Gadget loader resizes it to the adjacent 1024 parameter before creation.
# Keep this list exact: a new explicit-zero object must be audited rather than
# inheriting a global default silently.
map_args_for_object() {
    MAP_ARGS=()
    case "$1" in
        inspektor-gadget__audit_seccomp.o|\
        inspektor-gadget__profile_cpu.o|\
        inspektor-gadget__profile_cuda.o|\
        inspektor-gadget__trace_capabilities.o|\
        inspektor-gadget__trace_malloc.o|\
        inspektor-gadget__trace_open.o)
            MAP_ARGS=(--map-max-entries ig_build_id=1024)
            ;;
    esac
}

classify() {
    classified_output="$1"
    if printf '%s' "$classified_output" | grep -q "verification PASSED"; then
        bucket="OK"
    elif line=$(printf '%s\n' "$classified_output" | grep -m1 "unsupported map type"); then
        mt=$(printf '%s' "$line" | sed -n 's/.*unsupported map type [0-9]* (\([A-Za-z0-9_]*\)).*/\1/p')
        [ -z "$mt" ] && mt=$(printf '%s' "$line" | sed -n 's/.*unsupported map type \([0-9]*\).*/type-\1/p')
        [ -z "$mt" ] && mt="unknown"
        bucket="LOAD-FAIL:unsupported-map-type:$mt"
        echo "$mt" >> "$MAPHIST"
    elif line=$(printf '%s\n' "$classified_output" | grep -m1 "verification FAILED:.*unknown helper #"); then
        hid=$(printf '%s' "$line" | sed -n 's/.*unknown helper #\([0-9]*\).*/\1/p')
        bucket="VERIFY-REJECT:unsupported-helper:#$hid"
        echo "$hid" >> "$HELPHIST"
    elif printf '%s' "$classified_output" | grep -q "verification FAILED:.*unresolved CO-RE"; then
        bucket="VERIFY-REJECT:poisoned-relocation"
    elif printf '%s' "$classified_output" | grep -q "verification FAILED:"; then
        bucket="VERIFY-REJECT:other"
    elif printf '%s' "$classified_output" | grep -qiE "error:.*(relocation|CO-RE|unknown symbol)"; then
        bucket="LOAD-FAIL:relocation"
    else
        bucket="LOAD-FAIL:other"
    fi
}

total=0
objects_loaded=0
objects_ok=0
entry_total=0
for obj in "${OBJS[@]}"; do
    [ -f "$obj" ] || continue
    total=$((total + 1))
    name=$(basename "$obj")
    map_args_for_object "$name"
    listing="$TMP/programs.$total"
    listing_err="$TMP/programs.$total.err"
    if ! "$FEBPF" programs "$obj" "${BTF_ARGS[@]}" "${MAP_ARGS[@]}" >"$listing" 2>"$listing_err"; then
        out="$(<"$listing_err")"
        classify "$out"
        echo "$bucket" >> "$OBJECT_BUCKETS"
        printf '%s\t%s\n' "$bucket" "$name" >> "$OBJECT_DETAIL"
        continue
    fi

    objects_loaded=$((objects_loaded + 1))
    object_ok=1
    object_bucket="OK"
    object_entries=0
    object_links=0
    while IFS=$'\t' read -r record field2 field3 field4 extra; do
        [ -z "$record" ] && continue
        case "$record" in
            program)
                object_entries=$((object_entries + 1))
                entry_total=$((entry_total + 1))
                kind="$field3"
                program_name="$field4"
                out=$("$FEBPF" verify "$obj" --prog "$program_name" \
                    "${BTF_ARGS[@]}" "${MAP_ARGS[@]}" 2>&1)
                if [ "$kind" = socket ] \
                    && printf '%s' "$out" | grep -q "legacy packet access"; then
                    out=$("$FEBPF" verify "$obj" --prog "$program_name" \
                        "${BTF_ARGS[@]}" "${MAP_ARGS[@]}" \
                        --legacy-packet linux --packet "$EMPTY_PACKET" 2>&1)
                fi
                classify "$out"
                echo "$bucket" >> "$BUCKETS"
                printf '%s\t%s::%s\n' "$bucket" "$name" "$program_name" >> "$DETAIL"
                if [ "$bucket" != OK ]; then
                    object_ok=0
                    [ "$object_bucket" = OK ] && object_bucket="$bucket"
                fi
                ;;
            link)
                object_links=$((object_links + 1))
                printf '%s::%s[%s]->%s\n' "$name" "$field2" "$field3" "$field4" >> "$LINKS"
                ;;
            *)
                object_ok=0
                [ "$object_bucket" = OK ] && object_bucket="LOAD-FAIL:other"
                ;;
        esac
    done < "$listing"
    if [ "$object_entries" -eq 0 ]; then
        object_ok=0
        object_bucket="LOAD-FAIL:other"
    fi
    [ "$object_links" -gt 0 ] && echo "$name" >> "$GRAPHS"
    if [ "$object_ok" -eq 1 ]; then
        objects_ok=$((objects_ok + 1))
    fi
    echo "$object_bucket" >> "$OBJECT_BUCKETS"
    printf '%s\t%s\n' "$object_bucket" "$name" >> "$OBJECT_DETAIL"
done

# --- Aggregate ------------------------------------------------------------
n_ok=$(grep -c '^OK$' "$BUCKETS" || true)
n_load_fail=$(grep -c '^LOAD-FAIL:' "$BUCKETS" || true)
n_verify_reject=$(grep -c '^VERIFY-REJECT:' "$BUCKETS" || true)
# "loaded" = reached the verifier (OK or any VERIFY-REJECT).
n_loaded=$((n_ok + n_verify_reject))
n_graphs=$(wc -l < "$GRAPHS" | tr -d ' ')
n_links=$(wc -l < "$LINKS" | tr -d ' ')

pct() { # pct <num> <den>
    if [ "$2" -eq 0 ]; then echo "0.0"; else
        awk "BEGIN{printf \"%.1f\", ($1/$2)*100}"
    fi
}

{
    echo "======================================================================"
    echo " febpf corpus coverage report"
    echo " generated: $(date -u '+%Y-%m-%d %H:%M:%SZ')   febpf: $FEBPF"
    echo " target BTF: ${BTF_ARGS[*]:-<none>}"
    echo "======================================================================"
    echo ""
    echo "objects/families scanned  : $total"
    echo "objects loaded            : $objects_loaded  ($(pct "$objects_loaded" "$total")%)"
    echo "objects fully compatible  : $objects_ok  ($(pct "$objects_ok" "$total")%)"
    echo "entry programs scanned    : $entry_total"
    echo "entries loaded            : $n_loaded  ($(pct "$n_loaded" "$entry_total")%)"
    echo "entries verified OK       : $n_ok  ($(pct "$n_ok" "$entry_total")%)"
    echo "entry load failures       : $n_load_fail  ($(pct "$n_load_fail" "$entry_total")%)"
    echo "entry verify rejections   : $n_verify_reject  ($(pct "$n_verify_reject" "$entry_total")%)"
    echo "static tail-call graphs   : $n_graphs  ($(pct "$n_graphs" "$total")%)"
    echo "static tail-call links    : $n_links"
    echo ""
    echo "---- object/family outcome buckets -----------------------------------"
    sort "$OBJECT_BUCKETS" | uniq -c | sort -rn | while read -r c b; do
        printf "  %5d  %s\n" "$c" "$b"
    done
    echo ""
    echo "---- entry outcome buckets -------------------------------------------"
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
    echo "---- per-object/family detail ----------------------------------------"
    sort "$OBJECT_DETAIL" | while IFS="$(printf '\t')" read -r b n; do
        printf "  %-48s %s\n" "$n" "$b"
    done
    echo ""
    echo "---- per-entry detail ------------------------------------------------"
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
