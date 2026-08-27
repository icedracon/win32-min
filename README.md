# win32-min

[![Crates.io](https://img.shields.io/crates/v/win32-min.svg)](https://crates.io/crates/win32-min)
[![Docs.rs](https://docs.rs/win32-min/badge.svg)](https://docs.rs/win32-min)
[![CI](https://github.com/icedracon/win32-min/actions/workflows/ci.yml/badge.svg)](https://github.com/icedracon/win32-min/actions/workflows/ci.yml)

Minimal, hand-rolled Win32 FFI for Windows security, administration, and audit
tooling, packaged as one small crate with **zero runtime dependencies**.

The crate stays raw by design: every declaration mirrors the Windows ABI and
remains `unsafe`. Safe ownership and RAII live in focused companion crates such
as [`windows-token`](https://crates.io/crates/windows-token) and
[`windows-scm`](https://crates.io/crates/windows-scm).

## Why

- **`windows-rs`** — official Microsoft, correct + comprehensive, but 100+ MB
  artifacts, feature-flag puzzle, and version churn (0.48 → 0.51 → 0.58 → 0.61)
  creates dep-graph duplication in binaries that pull multiple `windows-rs`-
  based crates. Use it for COM (which this crate does not cover).
- **`winapi`** — deprecated de-facto since 2021.
- **`win32-min`** — pure `extern "system"` declarations + `#[repr(C)]` structs,
  feature-gated by subsystem. Zero deps, sub-second cold compile, no version
  drift for you or your consumers.

## Features

| Feature | Subsystem | Downstream consumer |
|---|---|---|
| `security-token` | Token / privilege / impersonation / SID | [`windows-token`](https://crates.io/crates/windows-token) |
| `services` | Service Control Manager (local) | [`windows-scm`](https://crates.io/crates/windows-scm) |
| `lsa-auth` | LSA authentication package | [`windows-lsa`](https://crates.io/crates/windows-lsa) |
| `eventlog` | EventLog v6 (Evt* API) | [`windows-eventlog-native`](https://crates.io/crates/windows-eventlog-native) |
| `process-thread` | Process/thread discovery and inspection | security inventory tools |
| `registry` | Registry open/query/enumeration/update | configuration and audit tools |
| `security-descriptor` | ACL/security-descriptor and SDDL conversion APIs | [`windows-sddl`](https://crates.io/crates/windows-sddl) ecosystem |
| `full` | all seven subsystems | — |

Default = only [`foundation`] baseline (HANDLE, LUID, NTSTATUS, PCWSTR, …).
Enable only what you need.

All feature combinations remain `no_std`; higher-level allocation belongs to
the safe wrapper crates.

## ABI verification

Hand-written bindings are only useful when they are demonstrably correct.
`win32-min` therefore verifies:

- structure size, alignment, and field offsets;
- security, registry, token, and service constant values;
- x86, x64, and ARM64 compilation;
- harmless runtime symbol/link smoke tests on Windows; and
- the same layouts and values against the installed Microsoft Windows SDK C
  headers via [`scripts/verify-abi.ps1`](scripts/verify-abi.ps1).

The current coverage is summarized in [`ABI-REPORT.md`](ABI-REPORT.md).

New declarations should not be accepted without an ABI assertion and a real
downstream use case.

## Live-validated

Live-verified against Windows 11 build 22621 through downstream consumers:

- `windows-scm 0.2.0` `list_services` example — **316 services enumerated**
  through `OpenSCManagerW` + `EnumServicesStatusExW` two-call idiom, correct
  struct layouts, correct wide-string pointer walk, paging cursor works.
- `windows-token 0.2.0` smoke test — `OpenProcessToken` + `DuplicateTokenEx`
  live against the calling process.
- Registry, process, and SDDL conversion symbols are exercised by non-mutating
  Windows smoke tests.

## Reproducible size/build comparison

The [`benchmarks`](benchmarks) directory builds the same tiny process-ID program
with `win32-min`, `windows-sys`, and `windows`. Run `benchmarks/compare.ps1` from
PowerShell to produce a local CSV containing cold build time, binary size, and
dependency count. Results are intentionally not hard-coded because toolchain,
cache, CPU, and crate-version changes materially affect them.

## Non-goals

- Not a Win32 SDK replacement — missing ~99% of the surface. If you need
  DirectX / WinRT / obscure COM interfaces, use `windows-rs`.
- Not a COM host — COM interfaces require vtable layouts + `IUnknown` support
  that `windows-rs` handles cleanly; hand-rolling that is not worth the LOC.
- Not portable — Windows-only, no fallback stubs.

## License

MIT.
