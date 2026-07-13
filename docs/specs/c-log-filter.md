# C log-filter host

STATUS: example implemented (2026-07-13)

`examples/c-log-filter` is a production-shaped test of the native embedding
boundary. It is a streaming C11 process, not a new febpf execution mode:

```sh
./scripts/test-c-api.sh
target/c-log-filter-example examples/c-log-filter/filter.s < input.log
```

The host loads an assembly plugin once, verifies it once, then supplies a fresh
writable Flat context for each bounded input record. A plugin returns 0 to drop
the record or 1 to accept it and may redact bytes in place. Any other action,
runtime failure, or length outside the fixed capacity fails closed.

## Record ABI v1

The guest sees one inline structure:

```c
struct log_context_v1 {
    uint32_t abi_version;  /* 1 */
    uint32_t record_len;
    uint8_t record[4096];
};
```

The record starts at byte offset 8; a C static assertion locks that layout.
There are deliberately no embedded host pointers. febpf gives the entire
structure one bounds-checked virtual context region, so ordinary eBPF loads and
stores cannot escape it. The host zeroes all 4104 bytes before reading each
record: the verified program may legally inspect the fixed capacity, and must
never observe stale host stack contents beyond `record_len`.

After execution the host revalidates `record_len` before using it, even though
the VM already confines stores. This is application-level validation: memory
safety does not imply that a guest-written length is semantically trustworthy.
Oversized input records, unknown return actions, and output errors terminate
the stream rather than silently truncating or passing data.

## What the example says about the architecture

No runtime extension was needed. The existing Flat context, writable-context
verification option, runtime instruction limit, and per-call
`ExecutionEnvironment` express a non-packet application cleanly. Durable VM
state contains the verified program and its maps; record storage and output
policy remain invocation/host state.

The example therefore does not justify adding a log model, record provider, or
generic untyped callback to ABI v1. ELF entry selection is now an independent
construction descriptor. Future needs should still be measured separately:
custom helpers expose host services and map handles expose durable control
state. They have different ownership and compatibility contracts and should
not be combined into a miscellaneous VM adapter.

## Validation

`scripts/test-c-api.sh` compiles this host with C11, `-Wall -Wextra -Werror`,
then pipes three records through the example plugin. It requires exact output
`INFO ready` and `TOKEN=*ecret`; the intervening `DEBUG noisy` record must be
absent. The same run rebuilds and dynamically links the native C API. All nine
Rust C-boundary tests and strict all-target C-API Clippy also pass.
