// Hand-written glue for the febpf WASM module. No framework, no bundler.
//
// ABI (see docs/specs/wasm-playground.md): inputs are (ptr,len) buffers we
// obtain from febpf_alloc and write UTF-8/bytes into; results come back packed
// into a BigInt u64 = (ptr << 32) | len, which we decode and then free.

const Febpf = (() => {
  let exports = null;
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  let dbgSeq = 0; // monotonic debug-session handle

  // Memory can be reallocated by alloc; always take a fresh view.
  const u8 = () => new Uint8Array(exports.memory.buffer);

  function writeBytes(bytes) {
    const len = bytes.length;
    const ptr = exports.febpf_alloc(len);
    u8().set(bytes, ptr);
    return { ptr, len };
  }

  function readResult(packed) {
    // packed is a BigInt (i64/u64 return).
    const ptr = Number(packed >> 32n);
    const len = Number(packed & 0xffffffffn);
    const copy = u8().slice(ptr, ptr + len);
    exports.febpf_free(ptr, len);
    return dec.decode(copy);
  }

  // Accept a string (assembler source) or a Uint8Array (a clang .o).
  function asBytes(src) {
    return typeof src === "string" ? enc.encode(src) : src;
  }

  async function init(url = "febpf.wasm") {
    let instance;
    try {
      ({ instance } = await WebAssembly.instantiateStreaming(fetch(url), {}));
    } catch (e) {
      // Fallback: some servers send the wrong MIME type for streaming.
      const bytes = await (await fetch(url)).arrayBuffer();
      ({ instance } = await WebAssembly.instantiate(bytes, {}));
    }
    exports = instance.exports;
    return Febpf;
  }

  function call1(fn, src) {
    const a = writeBytes(asBytes(src));
    const out = readResult(fn(a.ptr, a.len));
    exports.febpf_free(a.ptr, a.len);
    return out;
  }

  return {
    init,
    ready: () => exports !== null,

    selftest: () => Number(exports.febpf_selftest()),

    verify: (src) => call1(exports.febpf_verify, src),
    disasm: (src) => call1(exports.febpf_disasm, src),
    analyze: (src, mode) => {
      const a = writeBytes(asBytes(src));
      const out = readResult(exports.febpf_analyze(a.ptr, a.len, mode >>> 0));
      exports.febpf_free(a.ptr, a.len);
      return out;
    },
    run: (src, ctxHex) => {
      const a = writeBytes(asBytes(src));
      const c = writeBytes(enc.encode(ctxHex || ""));
      const out = readResult(exports.febpf_run(a.ptr, a.len, c.ptr, c.len));
      exports.febpf_free(a.ptr, a.len);
      exports.febpf_free(c.ptr, c.len);
      return out;
    },

    // Debugger: returns a handle, or throws with the error text.
    dbgNew: (src, ctxHex) => {
      const handle = ++dbgSeq;
      const a = writeBytes(asBytes(src));
      const c = writeBytes(enc.encode(ctxHex || ""));
      const status = readResult(
        exports.febpf_dbg_new(handle, a.ptr, a.len, c.ptr, c.len),
      );
      exports.febpf_free(a.ptr, a.len);
      exports.febpf_free(c.ptr, c.len);
      if (!status.startsWith("OK")) throw new Error(status.replace(/^ERR /, ""));
      return handle;
    },
    dbgCmd: (handle, cmd) => {
      const c = writeBytes(enc.encode(cmd));
      const out = readResult(exports.febpf_dbg_cmd(handle, c.ptr, c.len));
      exports.febpf_free(c.ptr, c.len);
      return out;
    },
    dbgFree: (handle) => exports.febpf_dbg_free(handle >>> 0),
  };
})();
