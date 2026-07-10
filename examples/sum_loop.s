; Sum 1..=1000 — a tight loop, good for `febpf bench`.
        r0 = 0
        r2 = 1000
loop:
        r0 += r2
        r2 -= 1
        if r2 != 0 goto loop
        exit
