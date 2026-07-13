# febpf performance suite

This directory is a self-contained Criterion consumer of febpf's public API.
It has its own manifest and committed lockfile, so Criterion and its transitive
packages remain development tooling rather than dependencies of the engine.

From the repository root, run every benchmark with:

```sh
./perf/run
```

Pass a Criterion filter to run one group:

```sh
./perf/run execution/sum_loop
./perf/run verifier
```

For a same-machine before/after comparison:

```sh
./perf/run --save-baseline before
# make the change
./perf/run --baseline before
```

The harness uses committed source and ELF/BTF fixtures from the parent
repository. Warm interpreter and JIT execution exclude construction; JIT
compilation, verification, and ELF/CO-RE loading are measured separately.
Compare saved baselines only on the same quiet machine because CPU frequency,
thermal state, kernel scheduling, and toolchain changes can dominate small
engine changes.
