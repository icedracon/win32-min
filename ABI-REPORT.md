# ABI verification report

`win32-min` 0.1.1 is checked against the Microsoft Windows SDK rather than
relying only on hand-maintained expected values.

## Verification layers

| Layer | x86 | x64 | ARM64 |
|---|---:|---:|---:|
| Rust compile-time size assertions | yes | yes | yes |
| Rust integration size/alignment/offset tests | yes | yes | compile-checked |
| Microsoft SDK C-header assertions | yes | yes | yes |
| Harmless runtime symbol smoke tests | CI runner | yes | compile-checked |

The SDK probe is [`tests/sdk/abi.c`](tests/sdk/abi.c) and is compiled with MSVC
by [`scripts/verify-abi.ps1`](scripts/verify-abi.ps1). It covers representative
foundation, token, service, LSA, EventLog, process/thread, registry, ACL, and
security-descriptor types and constants.

## Verified invariants

- `BOOL`, `LUID`, `GUID`, `FILETIME`, `UNICODE_STRING`, and
  `SECURITY_ATTRIBUTES` sizes and key offsets.
- `TOKEN_ALL_ACCESS`, `TOKEN_PRIVILEGES`, SID authority, and SID tail layout.
- Service status and enumeration layouts.
- `PROCESSENTRY32W` and `THREADENTRY32` sizes and key offsets.
- ACL, ACE header, and self-relative security-descriptor layouts.
- Registry access masks/value types and EventLog handle width.
- Link/load behavior for `kernel32`, `advapi32`, and SDDL conversion APIs.

## Local verification

Validated on 2026-08-27 against Windows SDK `10.0.26100.0` using:

```powershell
./scripts/verify-abi.ps1 -Arch x64
./scripts/verify-abi.ps1 -Arch x86
./scripts/verify-abi.ps1 -Arch arm64
cargo test --all-features
```

CI repeats these checks and cross-compiles the crate for the three MSVC Rust
targets on every push and pull request.
