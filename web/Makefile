# Build the febpf WASM playground into ./dist — a single, self-contained
# directory (index.html, febpf.js, febpf.wasm) ready to rsync to any static
# web server. No external fetches at runtime.
#
#   make          build wasm and assemble dist/
#   make clean    remove dist/
#
# Serving: the .wasm needs the application/wasm MIME type, so use a real
# server (`python3 -m http.server` in dist/). file:// will not instantiate it.

WASM := ../target/wasm32-unknown-unknown/release/febpf.wasm
DIST := dist
STATIC := index.html febpf.js

.PHONY: all wasm clean serve

all: wasm
	@mkdir -p $(DIST)
	cp $(WASM) $(DIST)/febpf.wasm
	cp $(STATIC) $(DIST)/
	@echo "==> $(DIST)/ is ready ($$(du -h $(DIST)/febpf.wasm | cut -f1) wasm). rsync it anywhere."

# Cargo decides whether a rebuild is needed. This keeps std for the browser ABI
# while dropping the native JIT, and explicitly requests the wasm cdylib.
wasm:
	cd .. && cargo rustc --lib --target wasm32-unknown-unknown --release --no-default-features --features std -- --crate-type=cdylib

# Convenience: serve the built dist/ locally.
serve: all
	cd $(DIST) && python3 -m http.server 8000

clean:
	rm -rf $(DIST)
