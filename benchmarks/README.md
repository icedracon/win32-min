# Reproducible dependency/build comparison

These three programs perform the same operation: print the current Windows
process ID. They differ only in the binding crate used:

- `win32-min` with `process`;
- `windows-sys` with `Win32_System_Threading`; and
- `windows` with `Win32_System_Threading`.

Run from PowerShell:

```powershell
./benchmarks/compare.ps1
```

The script validates every cleanup path, removes only each benchmark crate's
own `target` directory, and writes the ignored `benchmarks/results.csv` with:

- mean cold build duration over the requested run count;
- application-only incremental rebuild duration with dependencies cached;
- rustdoc duration with dependency documentation disabled;
- executable size; and
- resolved dependency-package count from `cargo metadata` (excluding the tiny
  benchmark program itself);
- binding-crate Rust source file count and byte size; and
- the exact `rustc` and host information used for the run.

Peak memory is deliberately not reported: Cargo launches compiler and linker
children, so the parent process working set is not a defensible aggregate
compile-memory measurement on Windows. Use ETW/WPA or another process-tree
profiler when that metric matters.

Run on the same machine and Rust toolchain for a meaningful comparison. The
result is not a universal performance claim.
