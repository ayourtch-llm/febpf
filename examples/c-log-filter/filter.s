# log_context_v1 is two u32 fields followed by 4096 writable record bytes.
# Drop records prefixed with "DEBUG ". For accepted records prefixed with
# "TOKEN=", redact the first byte of the value in place.

r6 = r1
r2 = *(u32 *)(r6 + 0)
if r2 != 1 goto drop
r2 = *(u32 *)(r6 + 4)
if r2 < 6 goto accept

r3 = *(u8 *)(r6 + 8)
if r3 != 68 goto token
r3 = *(u8 *)(r6 + 9)
if r3 != 69 goto token
r3 = *(u8 *)(r6 + 10)
if r3 != 66 goto token
r3 = *(u8 *)(r6 + 11)
if r3 != 85 goto token
r3 = *(u8 *)(r6 + 12)
if r3 != 71 goto token
r3 = *(u8 *)(r6 + 13)
if r3 == 32 goto drop

token:
r3 = *(u8 *)(r6 + 8)
if r3 != 84 goto accept
r3 = *(u8 *)(r6 + 9)
if r3 != 79 goto accept
r3 = *(u8 *)(r6 + 10)
if r3 != 75 goto accept
r3 = *(u8 *)(r6 + 11)
if r3 != 69 goto accept
r3 = *(u8 *)(r6 + 12)
if r3 != 78 goto accept
r3 = *(u8 *)(r6 + 13)
if r3 != 61 goto accept
if r2 <= 6 goto accept
*(u8 *)(r6 + 14) = 42

accept:
r0 = 1
exit

drop:
r0 = 0
exit
