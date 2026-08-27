# Reproducible dependency/build comparison

These three programs perform the same operation: print the current Windows
process ID. They differ only in the binding crate used:

- `win32-min` with `process-thread`;
- `windows-sys` with `Win32_System_Threading`; and
- `windows` with `Win32_System_Threading`.

Run from PowerShell:

```powershell
./benchmarks/compare.ps1
```

The script removes only each benchmark crate's own `target` directory, performs
a release build, and writes `benchmarks/results.csv` with:

- cold build duration;
- executable size; and
- resolved dependency-package count from `cargo metadata` (excluding the tiny
  benchmark program itself).

Run on the same machine and Rust toolchain for a meaningful comparison. The
result is not a universal performance claim.
