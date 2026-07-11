; Racy counter: read-modify-write of a shared map value WITHOUT an atomic.
; Each invocation does lookup -> load count -> +1 -> map_update_elem. Run two
; instances against the shared map and the update is lost under some schedule.
;   febpf race examples/race_rmw.s --procs 2
        .map counter array 4 8 1

        r0 = 0
        *(u32 *)(r10 - 4) = r0          ; key = 0
        r1 = map[counter]
        r2 = r10
        r2 += -4
        call map_lookup_elem            ; array[0] is always present
        if r0 == 0 goto out
        r6 = *(u64 *)(r0 + 0)           ; READ current count  (staleness window)
        r6 += 1
        *(u64 *)(r10 - 16) = r6         ; new count on the stack
        r1 = map[counter]
        r2 = r10
        r2 += -4
        r3 = r10
        r3 += -16
        r4 = 0
        call map_update_elem            ; WRITE it back  (may clobber a peer)
out:
        r0 = 0
        exit
