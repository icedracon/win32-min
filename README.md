# win32-min

Minimal, hand-rolled Win32 FFI shim — the ~50 functions and types 90% of
Windows Rust security / admin / audit tooling actually calls, packaged as one
small crate with **zero `windows-rs` or `winapi` dependency**.

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
| `full` | all four | — |

Default = only [`foundation`] baseline (HANDLE, LUID, NTSTATUS, PCWSTR, …).
Enable only what you need.

## Live-validated

Live-verified against Windows 11 build 22621 through downstream consumers:

- `windows-scm 0.2.0` `list_services` example — **316 services enumerated**
  through `OpenSCManagerW` + `EnumServicesStatusExW` two-call idiom, correct
  struct layouts, correct wide-string pointer walk, paging cursor works.
- `windows-token 0.2.0` smoke test — `OpenProcessToken` + `DuplicateTokenEx`
  live against the calling process.

## Non-goals

- Not a Win32 SDK replacement — missing ~99% of the surface. If you need
  DirectX / WinRT / obscure COM interfaces, use `windows-rs`.
- Not a COM host — COM interfaces require vtable layouts + `IUnknown` support
  that `windows-rs` handles cleanly; hand-rolling that is not worth the LOC.
- Not portable — Windows-only, no fallback stubs.

## License

MIT.
