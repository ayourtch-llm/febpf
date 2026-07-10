; Toy packet-protocol counter: treats the context as an Ethernet+IPv4
; frame, counts the IP protocol byte into a hash map, returns the proto.
;   febpf run examples/proto_count.s --ctx @packet.bin
        .map counts hash 4 8 256

        r6 = r1               ; save ctx
        r2 = *(u8 *)(r1 + 12) ; ethertype (be)
        r3 = *(u8 *)(r1 + 13)
        if r2 != 0x08 goto out
        if r3 != 0x00 goto out        ; not IPv4
        r7 = *(u8 *)(r6 + 23)         ; IP protocol
        *(u32 *)(r10 - 4) = r7        ; key = proto

        r1 = map[counts]
        r2 = r10
        r2 += -4
        call map_lookup_elem
        if r0 != 0 goto bump

        r1 = 1                        ; first sighting: insert 1
        *(u64 *)(r10 - 16) = r1
        r1 = map[counts]
        r2 = r10
        r2 += -4
        r3 = r10
        r3 += -16
        r4 = 0
        call map_update_elem
        goto ret
bump:
        r1 = 1
        lock *(u64 *)(r0) += r1
ret:
        r0 = r7                       ; return the protocol number
        exit
out:
        r0 = -1
        exit
