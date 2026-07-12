# rbpf 0.4.1 legacy-load black-box audit

This audit compares public behavior only. It does not copy or link rbpf code
into febpf, and it adds no Cargo dependency. The upstream reference is the
annotated `v0.4.1` tag, whose peeled commit is
`2b335775baf8ef15f7a73953025ce3e2d052c462`.

## Reproduce the upstream evidence

Use a disposable directory and verify the peeled commit before running tests:

```sh
git clone --branch v0.4.1 --depth 1 https://github.com/qmonnet/rbpf.git /tmp/rbpf-0.4.1
test "$(git -C /tmp/rbpf-0.4.1 rev-parse HEAD)" = 2b335775baf8ef15f7a73953025ce3e2d052c462
cargo test --manifest-path /tmp/rbpf-0.4.1/Cargo.toml --test assembler --test disassembler
cargo test --manifest-path /tmp/rbpf-0.4.1/Cargo.toml --test misc ldabs
cargo test --manifest-path /tmp/rbpf-0.4.1/Cargo.toml --test misc ldind
cargo test --manifest-path /tmp/rbpf-0.4.1/Cargo.toml --features cranelift --test cranelift ldabs
cargo test --manifest-path /tmp/rbpf-0.4.1/Cargo.toml --features cranelift --test cranelift ldind
```

The public raw-buffer vectors use
`00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff` and report:

| form | effective offset | rbpf 0.4.1 result |
| --- | ---: | ---: |
| `ldabsb 3` | 3 | `0x33` |
| `ldabsh 3` | 3 | `0x4433` |
| `ldabsw 3` | 3 | `0x66554433` |
| `ldabsdw 3` | 3 | `0xaa99887766554433` |
| `r1=5; ldindb r1,3` | 8 | `0x88` |
| `r1=5; ldindh r1,3` | 8 | `0x9988` |
| `r1=4; ldindw r1,1` | 5 | `0x88776655` |
| `r1=2; ldinddw r1,3` | 5 | `0xccbbaa9988776655` |

Run febpf's corresponding checked profile with:

```sh
cargo test --test legacy_packet rbpf_041_public_raw_vectors_match_all_legacy_encodings
```

The upstream `misc` tests also make the safety boundary explicit: interpreter
no-data and out-of-bounds loads return errors, while comments state that the
handwritten JIT does not implement these bounds checks. febpf's `Rbpf041`
profile matches the deterministic successful values and checked-interpreter
errors; it intentionally keeps bounds checks in every backend.

## CLI profile selection

The CLI keeps legacy loads disabled unless explicitly selected. Both profiles
require explicit packet input, for example:

```sh
febpf verify --legacy-packet rbpf-0.4.1 --packet frame.bin program.s
febpf run --legacy-packet linux --packet frame.bin program.s
```

`linux` selects network-byte-order B/H/W behavior and rejects DW.
`rbpf-0.4.1` selects the measured little-endian B/H/W/DW behavior. The
`--packet` path uses febpf's bounded XDP packet adapter; it never exposes a
host pointer.
