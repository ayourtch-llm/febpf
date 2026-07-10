; Iterative Fibonacci: reads n from the first byte of the context,
; returns fib(n). Try:  febpf run examples/fib.s --ctx 5a   (n = 90)
        r6 = *(u8 *)(r1)      ; n
        r0 = 0                ; fib(0)
        if r6 == 0 goto done
        r7 = 1                ; fib(1)
loop:
        r8 = r0
        r8 += r7              ; next = a + b
        r0 = r7               ; a = b
        r7 = r8               ; b = next
        r6 -= 1
        if r6 != 0 goto loop
done:
        exit
