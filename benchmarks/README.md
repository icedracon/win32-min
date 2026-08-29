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

The default is five runs; three to twenty can be requested with `-Runs`. The
three committed lockfiles pin every resolved package, and the script fetches
them before timing. It validates every cleanup path, removes only each
benchmark crate's own `target` directory, rotates the build order on every run,
and writes the ignored `benchmarks/results.csv` with:

- every clean-target build observation plus its mean and sample standard
  deviation;
- application-only incremental rebuild duration with dependencies cached;
- rustdoc duration with dependency documentation disabled;
- executable size; and
- resolved dependency-package count from `cargo metadata` (excluding the tiny
  benchmark program itself);
- binding-crate Rust source file count and byte size; and
- the exact binding version, timestamp, `rustc`, Cargo, OS, and CPU information
  used for the run.

"Clean-target" is precise here: the benchmark crate's Cargo artifacts are
removed before each observation, while downloaded registry sources and the
operating-system file cache remain warm. It is not a powered-off cold-machine
measurement.

Peak memory is deliberately not reported: Cargo launches compiler and linker
children, so the parent process working set is not a defensible aggregate
compile-memory measurement on Windows. Use ETW/WPA or another process-tree
profiler when that metric matters.

Run on the same machine and Rust toolchain for a meaningful comparison. The
result is not a universal performance claim.

## Published baseline

The latest checked-in run is the
[2026-08-30 Windows report](results/2026-08-30-windows.md), with its
[raw CSV](results/2026-08-30-windows.csv). Keep both files together so the
summary remains auditable against the exact observations.
