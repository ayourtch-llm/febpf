; Safe counter: the same increment done with an ATOMIC add on the shared map
; value. Every interleaving of two instances commits the same final count, so
; the race explorer reports it RACE-FREE.
;   febpf race examples/race_atomic.s --procs 2
        .map counter array 4 8 1

        r0 = 0
        *(u32 *)(r10 - 4) = r0          ; key = 0
        r1 = map[counter]
        r2 = r10
        r2 += -4
        call map_lookup_elem            ; array[0] is always present
        if r0 == 0 goto out
        r1 = 1
        lock *(u64 *)(r0 + 0) += r1     ; atomic RMW: no lost update possible
out:
        r0 = 0
        exit
