//! Drive the compiled febpf.wasm through its full string ABI with the pure-Rust
//! `wasmi` interpreter — the same alloc/write/call/unpack/read/free dance that
//! web/febpf.js performs in the browser. This verifies the marshalling layer
//! the CLI `--invoke` smoke test cannot reach.
//!
//! Run: `cargo run` (from web/test/abi-harness). Optionally pass a path to the
//! .wasm; defaults to the workspace release artifact.

use wasmi::{Engine, Instance, Linker, Memory, Module, Store, TypedFunc};

type S = Store<()>;

struct Wasm {
    store: S,
    mem: Memory,
    alloc: TypedFunc<i32, i32>,
    free: TypedFunc<(i32, i32), ()>,
    f_run: TypedFunc<(i32, i32, i32, i32), i64>, // src,ctx -> packed
    f_analyze: TypedFunc<(i32, i32, i32), i64>,
    f_dbg_new: TypedFunc<(i32, i32, i32, i32, i32), i64>,
    f_dbg_cmd: TypedFunc<(i32, i32, i32), i64>,
    disasm: TypedFunc<(i32, i32), i64>,
    verify: TypedFunc<(i32, i32), i64>,
    f_race: TypedFunc<(i32, i32, i32, i32), i64>, // src,procs,schedules -> packed
}

impl Wasm {
    fn load(path: &str) -> Wasm {
        let engine = Engine::default();
        let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let module = Module::new(&engine, &bytes[..]).expect("parse module");
        let mut store: S = Store::new(&engine, ());
        let linker = Linker::<()>::new(&engine);
        let instance: Instance = linker
            .instantiate(&mut store, &module)
            .expect("instantiate")
            .start(&mut store)
            .expect("start");
        let mem = instance.get_memory(&store, "memory").expect("memory export");
        macro_rules! tf {
            ($name:literal, $p:ty, $r:ty) => {
                instance
                    .get_typed_func::<$p, $r>(&store, $name)
                    .unwrap_or_else(|e| panic!("export {}: {e}", $name))
            };
        }
        let alloc = tf!("febpf_alloc", i32, i32);
        let free = tf!("febpf_free", (i32, i32), ());
        let verify = tf!("febpf_verify", (i32, i32), i64);
        let disasm = tf!("febpf_disasm", (i32, i32), i64);
        let f_run = tf!("febpf_run", (i32, i32, i32, i32), i64);
        let f_analyze = tf!("febpf_analyze", (i32, i32, i32), i64);
        let f_dbg_new = tf!("febpf_dbg_new", (i32, i32, i32, i32, i32), i64);
        let f_dbg_cmd = tf!("febpf_dbg_cmd", (i32, i32, i32), i64);
        let f_race = tf!("febpf_race", (i32, i32, i32, i32), i64);
        Wasm { store, mem, alloc, free, f_run, f_analyze, f_dbg_new, f_dbg_cmd, disasm, verify, f_race }
    }

    /// Write bytes into a fresh wasm buffer; return (ptr, len).
    fn write(&mut self, data: &[u8]) -> (i32, i32) {
        let len = data.len() as i32;
        let ptr = self.alloc.call(&mut self.store, len).expect("alloc");
        self.mem
            .write(&mut self.store, ptr as usize, data)
            .expect("mem write");
        (ptr, len)
    }

    /// Decode a packed (ptr<<32|len) result into a String and free it.
    fn read(&mut self, packed: i64) -> String {
        let p = packed as u64;
        let ptr = (p >> 32) as usize;
        let len = (p & 0xffff_ffff) as usize;
        let mut buf = vec![0u8; len];
        self.mem.read(&self.store, ptr, &mut buf).expect("mem read");
        self.free
            .call(&mut self.store, (ptr as i32, len as i32))
            .expect("free result");
        String::from_utf8_lossy(&buf).into_owned()
    }

    fn call1(&mut self, f: TypedFunc<(i32, i32), i64>, src: &[u8]) -> String {
        let (p, l) = self.write(src);
        let packed = f.call(&mut self.store, (p, l)).expect("call");
        let out = self.read(packed);
        self.free.call(&mut self.store, (p, l)).expect("free in");
        out
    }

    fn verify(&mut self, src: &[u8]) -> String {
        self.call1(self.verify, src)
    }
    fn disasm(&mut self, src: &[u8]) -> String {
        self.call1(self.disasm, src)
    }
    fn analyze(&mut self, src: &[u8], mode: i32) -> String {
        let (p, l) = self.write(src);
        let packed = self.f_analyze.call(&mut self.store, (p, l, mode)).expect("analyze");
        let out = self.read(packed);
        self.free.call(&mut self.store, (p, l)).expect("free");
        out
    }
    fn run(&mut self, src: &[u8], ctx: &[u8]) -> String {
        let (sp, sl) = self.write(src);
        let (cp, cl) = self.write(ctx);
        let packed = self.f_run.call(&mut self.store, (sp, sl, cp, cl)).expect("run");
        let out = self.read(packed);
        self.free.call(&mut self.store, (sp, sl)).unwrap();
        self.free.call(&mut self.store, (cp, cl)).unwrap();
        out
    }
    fn dbg_new(&mut self, handle: i32, src: &[u8], ctx: &[u8]) -> String {
        let (sp, sl) = self.write(src);
        let (cp, cl) = self.write(ctx);
        let packed = self
            .f_dbg_new
            .call(&mut self.store, (handle, sp, sl, cp, cl))
            .expect("dbg_new");
        let out = self.read(packed);
        self.free.call(&mut self.store, (sp, sl)).unwrap();
        self.free.call(&mut self.store, (cp, cl)).unwrap();
        out
    }
    fn dbg_cmd(&mut self, handle: i32, cmd: &str) -> String {
        let (cp, cl) = self.write(cmd.as_bytes());
        let packed = self.f_dbg_cmd.call(&mut self.store, (handle, cp, cl)).expect("dbg_cmd");
        let out = self.read(packed);
        self.free.call(&mut self.store, (cp, cl)).unwrap();
        out
    }
    fn race(&mut self, src: &[u8], procs: i32, schedules: i32) -> String {
        let (p, l) = self.write(src);
        let packed = self.f_race.call(&mut self.store, (p, l, procs, schedules)).expect("race");
        let out = self.read(packed);
        self.free.call(&mut self.store, (p, l)).unwrap();
        out
    }
}

const RACE_RMW: &[u8] = b".map counter array 4 8 1\n\
r0 = 0\n*(u32 *)(r10 - 4) = r0\nr1 = map[counter]\nr2 = r10\nr2 += -4\n\
call map_lookup_elem\nif r0 == 0 goto out\nr6 = *(u64 *)(r0 + 0)\nr6 += 1\n\
*(u64 *)(r10 - 16) = r6\nr1 = map[counter]\nr2 = r10\nr2 += -4\nr3 = r10\n\
r3 += -16\nr4 = 0\ncall map_update_elem\nout:\nr0 = 0\nexit\n";
const RACE_ATOMIC: &[u8] = b".map counter array 4 8 1\n\
r0 = 0\n*(u32 *)(r10 - 4) = r0\nr1 = map[counter]\nr2 = r10\nr2 += -4\n\
call map_lookup_elem\nif r0 == 0 goto out\nr1 = 1\n\
lock *(u64 *)(r0 + 0) += r1\nout:\nr0 = 0\nexit\n";

const GOOD: &[u8] =
    b"r0 = 0\nr1 = 10\nloop:\nr0 += r1\nr1 -= 1\nif r1 != 0 goto loop\nexit\n";
const BAD: &[u8] = b"exit\n";

fn check(name: &str, cond: bool, detail: &str) -> bool {
    println!("[{}] {}", if cond { "PASS" } else { "FAIL" }, name);
    if !cond {
        println!("    got: {}", detail.replace('\n', "\n    "));
    }
    cond
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        "../../../target/wasm32-unknown-unknown/release/febpf.wasm".to_string()
    });
    println!("driving {path} through the string ABI via wasmi\n");
    let mut w = Wasm::load(&path);

    let mut ok = true;

    let v = w.verify(GOOD);
    ok &= check("verify(good) contains PASSED", v.contains("PASSED"), &v);

    let vb = w.verify(BAD);
    ok &= check(
        "verify(bad) rejected with counterexample",
        vb.contains("FAILED") && vb.contains("counterexample"),
        &vb,
    );

    let r = w.run(GOOD, &[]);
    ok &= check("run(good) reports r0 = 55", r.contains("r0 = 55"), &r);

    let d = w.disasm(GOOD);
    ok &= check("disasm contains exit", d.contains("exit"), &d);

    let dot = w.analyze(GOOD, 1);
    ok &= check("analyze DOT is a digraph", dot.contains("digraph"), &dot);

    // Debugger + time travel across the ABI.
    let status = w.dbg_new(1, GOOD, &[]);
    ok &= check("dbg_new OK", status.starts_with("OK"), &status);
    w.dbg_cmd(1, "goto 4");
    let at4 = w.dbg_cmd(1, "regs");
    w.dbg_cmd(1, "step 3");
    w.dbg_cmd(1, "rstep 3");
    let back = w.dbg_cmd(1, "regs");
    ok &= check("rstep reproduces earlier register state", at4 == back, &back);
    ok &= check(
        "position is insns executed = 4",
        back.contains("insns executed = 4"),
        &back,
    );
    let cont = w.dbg_cmd(1, "continue");
    ok &= check("continue exits with r0 = 55", cont.contains("r0 = 55"), &cont);

    // Race explorer via the wasm ABI: the RMW program must race, the atomic one must not.
    let racy = w.race(RACE_RMW, 2, 0);
    ok &= check("race(rmw) reports RACE", racy.contains("RESULT: RACE"), &racy);
    ok &= check("race(rmw) witnesses a lost update", racy.contains("lost-update witnessed: true"), &racy);
    let safe = w.race(RACE_ATOMIC, 3, 0);
    ok &= check("race(atomic) reports RACE-FREE", safe.contains("RACE-FREE"), &safe);

    println!("\n{}", if ok { "ALL ABI CHECKS PASSED" } else { "SOME CHECKS FAILED" });
    std::process::exit(if ok { 0 } else { 1 });
}
