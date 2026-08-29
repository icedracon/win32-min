# win32-min

[![Crates.io](https://img.shields.io/crates/v/win32-min.svg)](https://crates.io/crates/win32-min)
[![Docs.rs](https://docs.rs/win32-min/badge.svg)](https://docs.rs/win32-min)
[![CI](https://github.com/icedracon/win32-min/actions/workflows/ci.yml/badge.svg)](https://github.com/icedracon/win32-min/actions/workflows/ci.yml)

Minimal, hand-rolled Win32 FFI for Windows security, administration, and audit
tooling, packaged as one small crate with **zero runtime dependencies**.

The broader crate family, maturity levels, compatibility policy, and research
use cases are indexed in [`ECOSYSTEM.md`](ECOSYSTEM.md). AI agents and coding
assistants can use [`llms.txt`](llms.txt) as the concise machine-readable map.
Independent reviewers can use [`REVIEWING.md`](REVIEWING.md); contribution and
private vulnerability-reporting paths are in [`CONTRIBUTING.md`](CONTRIBUTING.md).

The raw declarations mirror the Windows ABI and remain `unsafe`. A small
zero-dependency ownership layer handles the easy-to-get-wrong close functions
for kernel, process, thread, token, registry, and SCM handles; policy and
higher-level behavior remain in focused companion crates.

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
| `process` | Process discovery, image lookup, Toolhelp | security inventory tools |
| `thread` | Thread discovery, suspend/resume, Toolhelp | diagnostics tools |
| `module` | DLL load/free and symbol lookup | dynamic integrations |
| `file` | File identity, metadata, final paths, moves | DFIR and collection tools |
| `registry` | Registry open/query/enumeration/update | configuration and audit tools |
| `security` | ACL, ACE, SID, SDDL, security-info, `AccessCheck` | [`windows-sddl`](https://crates.io/crates/windows-sddl) ecosystem |
| `security-token` | Token / privilege / impersonation / SID | [`windows-token`](https://crates.io/crates/windows-token) |
| `services` | Service Control Manager (local) | [`windows-scm`](https://crates.io/crates/windows-scm) |
| `lsa-auth` | LSA authentication package | [`windows-lsa`](https://crates.io/crates/windows-lsa) |
| `eventlog` | EventLog v6 (Evt* API) | [`windows-eventlog-native`](https://crates.io/crates/windows-eventlog-native) |
| `full` | all ten subsystems | — |

Default = the [`foundation`](https://docs.rs/win32-min/latest/win32_min/foundation/)
baseline plus `Handle` and `Win32Error`. Enable only the raw subsystems you
need. The 0.1.1 feature names `process-thread` and `security-descriptor` remain
as compatibility aliases.

All feature combinations remain `no_std` and dependency-free.

## Owned handles and errors

```rust
use win32_min::handles::ProcessHandle;
use win32_min::process::{GetCurrentProcessId, PROCESS_QUERY_LIMITED_INFORMATION};

let pid = unsafe { GetCurrentProcessId() };
let process = ProcessHandle::open(pid, PROCESS_QUERY_LIMITED_INFORMATION, false)?;
assert_eq!(process.id()?, pid);
# Ok::<(), win32_min::Win32Error>(())
```

`Handle`, `ProcessHandle`, `ThreadHandle`, and `TokenHandle` close with
`CloseHandle`; `RegistryKey` uses `RegCloseKey`; `ServiceHandle` uses
`CloseServiceHandle`. Each supports `raw()`, `is_valid()`, `into_raw()`, and an
unsafe ownership-taking `from_raw()`. `Win32Error` exposes `code()`, `raw()`,
and a zero-allocation `message()` into caller-provided UTF-16 storage.

## Safety contracts

Every exported FFI function documents pointer validity, buffer sizing,
nullability, handle requirements, ownership, and output lifetimes in a
`# Safety` section. CI rejects a declaration without that section and builds
the complete API with missing documentation denied.

Six runnable examples cover process, token, registry, service, Event Log, and
security-descriptor workflows:

```powershell
cargo run --example process --features process
cargo run --example token --features security-token
cargo run --example registry --features registry
cargo run --example service --features services
cargo run --example eventlog --features eventlog
cargo run --example security --features security
```

The companion crates add five higher-level, copy-paste workflows for current
token identity, local service inventory, the Kerberos ticket cache, recent
Security-channel events, and offline ACL analysis. Start with
[`RESEARCH-WORKFLOWS.md`](RESEARCH-WORKFLOWS.md), or run the combined
[`research-kit`](https://github.com/icedracon/win32-min/tree/master/research-kit)
to exercise the public ecosystem in one process.

## ABI verification

Hand-written bindings are only useful when they are demonstrably correct.
`win32-min` therefore verifies:

- structure size, alignment, and field offsets;
- security, registry, token, and service constant values;
- x86, x64, and ARM64 compilation;
- harmless runtime symbol/link smoke tests on Windows;
- live API lifecycle tests for every feature, with temporary registry, file,
  token, Event Log, LSA, module, process, thread, and service resources; and
- the same layouts and values against the installed Microsoft Windows SDK C
  headers via [`scripts/verify-abi.ps1`](scripts/verify-abi.ps1).

The current coverage and commands are summarized in
[`ABI-REPORT.md`](ABI-REPORT.md) and [`TEST-COVERAGE.md`](TEST-COVERAGE.md).

New declarations should not be accepted without an ABI assertion and a real
downstream use case.

## Live-validated

Live-verified directly on Windows 10 build 19044 and through downstream
consumers on Windows 11 build 22621:

- `windows-scm 0.2.0` `list_services` example — **316 services enumerated**
  through `OpenSCManagerW` + `EnumServicesStatusExW` two-call idiom, correct
  struct layouts, correct wide-string pointer walk, paging cursor works.
- `windows-token 0.2.0` smoke test — `OpenProcessToken` + `DuplicateTokenEx`
  live against the calling process.
- Every feature has a live Windows lifecycle test. The elevated SCM test
  creates and deletes a uniquely named, stopped temporary service; the other
  mutable tests likewise use unique test-owned resources and clean them up.
- The 0.1.2 compatibility gate builds `windows-token`, `windows-scm`,
  `windows-lsa`, `windows-eventlog-native`, and the standalone benchmark client
  against the local release source.

## Reproducible size/build comparison

The [`benchmarks`](benchmarks) directory builds the same tiny process-ID program
with `win32-min`, `windows-sys`, and `windows`. Run `benchmarks/compare.ps1` from
PowerShell to produce a local CSV containing cold and incremental build time,
rustdoc time, binary size, dependency count, and binding-source size. Results
are generated locally rather than hard-coded because hardware, toolchain, and
cache state materially affect them.

## Non-goals

- Not a Win32 SDK replacement — missing ~99% of the surface. If you need
  DirectX / WinRT / obscure COM interfaces, use `windows-rs`.
- Not a COM host — COM interfaces require vtable layouts + `IUnknown` support
  that `windows-rs` handles cleanly; hand-rolling that is not worth the LOC.
- Not portable — Windows-only, no fallback stubs.

## License

MIT.
