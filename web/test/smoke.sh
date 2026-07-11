#!/usr/bin/env sh
# Smoke-test the compiled febpf.wasm without a browser, using a wasm runtime.
#
# No node is available in the reference environment, but any wasm runtime with
# an --invoke facility works. Set WASMTIME to a wasmtime binary (any recent
# version), or put `wasmtime` on PATH. Get one from
# https://github.com/bytecodealliance/wasmtime/releases.
#
# This runs febpf_selftest, which assembles + verifies + runs a demo program
# and drives a debug session entirely inside wasm, returning 15 on success.
# It proves the real .wasm binary loads and the engine executes under wasm32.
#
# The string-passing ABI (alloc/write/call/read) is additionally exercised by
# the Rust harness in web/test/abi-harness (`cargo run`), and by the browser.
set -eu

here=$(dirname "$0")
wasm="${1:-$here/../../target/wasm32-unknown-unknown/release/febpf.wasm}"
WASMTIME="${WASMTIME:-wasmtime}"

if [ ! -f "$wasm" ]; then
  echo "wasm not built: $wasm"
  echo "build it with:  (cd $here/.. && make)"
  exit 1
fi

if ! command -v "$WASMTIME" >/dev/null 2>&1; then
  echo "no wasm runtime found (set WASMTIME=/path/to/wasmtime)."
  echo "skipping automated smoke test; see web/README section for manual steps."
  exit 0
fi

echo "runtime: $("$WASMTIME" --version)"
echo "module:  $wasm"

result=$("$WASMTIME" --invoke febpf_selftest "$wasm" 2>/dev/null | tail -n1 | tr -d '[:space:]')
echo "febpf_selftest() = $result  (expected 15)"

alloc=$("$WASMTIME" --invoke febpf_alloc "$wasm" 32 2>/dev/null | tail -n1 | tr -d '[:space:]')
echo "febpf_alloc(32)  = $alloc  (expected non-zero pointer)"

if [ "$result" = "15" ] && [ -n "$alloc" ] && [ "$alloc" != "0" ]; then
  echo "SMOKE TEST PASSED"
else
  echo "SMOKE TEST FAILED"
  exit 1
fi
