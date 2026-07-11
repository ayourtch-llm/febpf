# WASM playground

Compile febpf's pure-std core (interpreter + verifier + assembler +
disassembler + analysis + a replay-based debugger) to
`wasm32-unknown-unknown` and drive it from a single offline HTML page. The JIT
— the only part that uses `asm!` and executable memory — is feature-gated off.

This is item #5 in `HANDOFF.md`'s wow list.

## Constraints (inherited, load-bearing)

- **Zero dependencies.** No `wasm-bindgen`, no `js-sys`. The WASM ABI is
  hand-written: `extern "C"` exports + manual linear-memory string passing, and
  hand-written JS glue.
- `cargo clippy --all-targets` stays at 0 warnings.
- All existing native tests stay green, **with and without** the `jit` feature
  (`cargo test` and `cargo test --no-default-features`).
- The native default build keeps the JIT; `bench --jit` must still work.

## Stage 1 — feature-gate the JIT

The JIT already isolates its `asm!`/executable-memory code behind
`#[cfg(all(target_arch = "x86_64", target_os = "linux"))]` (see
`src/jit/mod.rs`, `src/jit/x64.rs`). But the *module* is always compiled, and
`interp.rs`/`main.rs` reference it unconditionally. We add a cargo feature so
the JIT can be dropped entirely — both to shrink the wasm build and to prove the
core is JIT-independent.

```toml
[features]
default = ["jit"]
jit = []
```

- `src/lib.rs`: `#[cfg(feature = "jit")] pub mod jit;`
- `src/interp.rs`: gate the `Vm::jit` field, `Machine::jit_fault` field, and the
  methods `compile`, `run_jit`, `run_native`, `jit_step_at`, `take_jit_fault`,
  `regs_ptr` behind `#[cfg(feature = "jit")]`.
- `src/main.rs`: gate `--jit` handling; without the feature, `--jit` is a clear
  error.
- `tests/jit.rs`: `#![cfg(feature = "jit")]` so `--no-default-features` skips it.

The wasm build uses `--no-default-features`, so the whole `jit` module is gone
and no `asm!` reaches the wasm backend. Native builds keep `default = ["jit"]`.

Verification loop for this stage:

```
cargo test                       # jit on   (all tests incl. tests/jit.rs)
cargo test --no-default-features  # jit off  (tests/jit.rs skipped)
cargo clippy --all-targets        # 0 warnings, both ways
cargo build --release && ./target/release/febpf bench examples/sum_loop.s --iters 50000 --jit
```

## Stage 2 — the API surface

Two layers:

1. **`src/playground.rs` (compiled on every target, pure std).** All the actual
   logic, returning `String`. Native tests exercise this directly so the
   playground is covered by the normal `cargo test` loop.
   - `load_program(bytes) -> Result<Program, String>` — ELF magic ⇒ `elf::load`,
     otherwise treat bytes as UTF-8 pseudo-C assembler source.
   - `verify_text(bytes) -> String` — PASS + stats, or FAILED + the failing
     instruction and a disassembly window. The rejection message is whatever
     `VerifyError::Display` produces; when the richer verifier-explainer lands on
     `main`, this wrapper surfaces it unchanged (forward-compatible).
   - `run_text(bytes, ctx_hex) -> String` — verify-then-run; prints `r0` and any
     `trace_printk` output.
   - `disasm_text(bytes) -> String`.
   - `analyze_text(bytes, mode) -> String` — `mode` 0 = verifier-annotated
     listing, 1 = Graphviz DOT, 2 = execution heatmap (runs the program).
   - `Session` — a debugger driven by string commands (see below).

2. **`src/wasm.rs` (`#[cfg(target_arch = "wasm32")]`).** The thin ABI: an
   allocator and `extern "C"` wrappers that read UTF-8 out of linear memory,
   call the `playground` layer, and return results back into linear memory.

### The debugger: replay-based time travel

`src/debug.rs` today is a stdin REPL, not a headless session object. Rather than
depend on the (concurrently developed, not-yet-merged) time-travel branch, the
playground `Session` gets time travel *for free* from the engine's determinism
(fixed-seed prandom, stable map storage — see HANDOFF §7):

- A `Session` stores the `Program`, a context template, and a target
  instruction count `steps`.
- Every state query rebuilds a fresh `Vm` from the program and replays exactly
  `steps` instructions, then reads registers / stack / maps. `Vm::new` resets
  maps, prandom and printk, so replay is bit-identical every time.
- `step N` advances the target, `rstep N` rewinds it, `goto N` jumps — all just
  change `steps` and re-replay. This is genuine time-travel debugging.
- Replay caps `insn_limit` (1,000,000) so a runaway loop can't hang the browser.

`Session::command(line) -> String` accepts: `step [N]`, `rstep [N]`,
`goto N`, `continue`, `reset`, `regs`, `stack`, `list`, `x <addr> [len]`,
`maps`, `printk`, `help`. This mirrors the `handle_command` shape and gives the
whole debugger (including time travel) through one entry point.

### ABI (hand-written, no wasm-bindgen)

Linear-memory strings, length-prefixed via a packed return value. wasm32
pointers are 32-bit, so a result `(ptr, len)` packs into one `u64`:
`(ptr as u64) << 32 | len as u64`. JS reads both halves, copies the UTF-8 out of
the wasm memory, then frees the buffer.

Memory is owned as boxed slices so `alloc`/free capacities always match:

```
febpf_alloc(len: usize) -> *mut u8          // Box<[u8]> of len, leaked
febpf_free(ptr: *mut u8, len: usize)        // reconstruct + drop

febpf_verify (src_ptr, src_len) -> u64
febpf_run    (src_ptr, src_len, ctx_ptr, ctx_len) -> u64
febpf_disasm (src_ptr, src_len) -> u64
febpf_analyze(src_ptr, src_len, mode: u32) -> u64

// debugger: the host picks the handle id; no return-value plumbing.
febpf_dbg_new (handle: u32, src_ptr, src_len, ctx_ptr, ctx_len) -> u64  // "OK"/"ERR .."
febpf_dbg_cmd (handle: u32, cmd_ptr, cmd_len) -> u64                    // result text
febpf_dbg_free(handle: u32)

febpf_selftest() -> i64   // runs the engine end-to-end in-wasm; for smoke tests
```

`ctx` is a hex string (whitespace ignored); empty ⇒ 4096 zero bytes. Sessions
live in a `thread_local` `HashMap<u32, Session>` (wasm is single-threaded).

`febpf_selftest` exists so the wasm binary can be exercised with nothing but an
integer-returning call (see stage 4): it assembles a demo, verifies+runs it,
verifies a deliberately-bad program (expecting rejection), and drives a debug
session, returning a fixed sentinel on success.

## Stage 3 — the page

`web/index.html` + `web/febpf.js`, vanilla, no framework, no CDN, fully offline:

- A source `<textarea>` prefilled with a demo (a map + a loop).
- A second prefill that **fails** verification, to show the rejection output.
- Buttons: verify / run / disasm / analyze (annotated · DOT · heatmap).
- A debugger panel: step / rstep / continue / reset, registers, stack, maps.
- A file input to load a clang `.o` (ArrayBuffer → wasm memory → the same
  entry points, which sniff the ELF magic).
- Verifier-rejection output shown prominently.
- Self-contained CSS, theme-aware.

## Stage 4 — packaging (Makefile) & docs

Per the updated requirement, packaging is a **Makefile in `web/`**, not a shell
script:

```
cd web && make        # → web/dist/  (index.html, febpf.js, febpf.wasm)
make clean            # removes web/dist and the build artifact
```

`make` runs `cargo build --target wasm32-unknown-unknown --release
--no-default-features`, then copies the `.wasm` and the static files into
`web/dist/`. `web/dist/` is fully self-contained — `rsync` it to any static
host. Serving needs a real server for the `application/wasm` MIME type
(`file://` will not instantiate streaming); `python3 -m http.server` works.

## Verification / test bar

- `cargo test` and `cargo test --no-default-features`: all native tests green
  (adds `tests/playground.rs`, which exercises the `playground` layer end-to-end
  independent of the wasm ABI).
- `cargo clippy --all-targets` clean both ways.
- `cargo build --target wasm32-unknown-unknown --release --no-default-features`
  produces a valid `.wasm`.
- **Real wasm execution.** No node/browser is installed in this environment, but
  a `wasmtime` binary is available. `web/test/smoke.sh` invokes the exported
  `febpf_selftest` (and `febpf_alloc`/`febpf_free`) via
  `wasmtime --invoke`, actually running the febpf engine compiled to wasm and
  checking the sentinel result. This is the "verify the real binary runs"
  evidence. In a browser, `web/index.html` drives the full string ABI.

## Status

- [x] Spec written
- [ ] Stage 1 — JIT feature gate
- [ ] Stage 2 — playground + wasm ABI
- [ ] Stage 3 — web page
- [ ] Stage 4 — Makefile, docs, smoke test
</content>
</invoke>
