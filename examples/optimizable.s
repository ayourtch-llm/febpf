; A program full of provably-sound optimization opportunities, for
;   febpf optimize examples/optimizable.s --stats
; and
;   febpf equiv examples/optimizable.s <optimized-out>
;
; r0 is derived from a context byte, so behavior is input-dependent — the
; optimizer must prove observable equivalence (r0 + printk + maps + ctx)
; empirically, not just fold to a constant.
        r0 = *(u8 *)(r1 + 0)    ; r0 in 0..=255
        r2 = *(u8 *)(r1 + 1)    ; r2 in 0..=255 (non-constant)
        r0 *= 8                 ; strength reduction: *8  -> <<3
        r0 &= 0xff              ; NOT redundant here (r0 can exceed 0xff)
        r2 &= 0xff              ; redundant mask: r2 already fits in 8 bits
        r2 += 0                 ; algebraic identity: +0 dropped (64-bit)
        r2 *= 1                 ; algebraic identity: *1 dropped
        r3 = 0
        if r3 != 0 goto dead    ; dead branch: r3 proven 0, never taken
        r0 += r2
dead:
        exit
