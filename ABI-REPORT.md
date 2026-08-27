# ABI verification report

`win32-min` 0.1.2 is checked against the Microsoft Windows SDK rather than
relying only on hand-maintained expected values.

## Verification layers

| Layer | x86 | x64 | ARM64 |
|---|---:|---:|---:|
| Rust compile-time size assertions | yes | yes | yes |
| Rust integration size/alignment/offset tests | yes | yes | compile-checked |
| Microsoft SDK C-header assertions | yes | yes | yes |
| Runtime ABI/API lifecycle tests | CI runner | yes | native ARM64 CI |

The SDK probe is [`tests/sdk/abi.c`](tests/sdk/abi.c) and is compiled with MSVC
by [`scripts/verify-abi.ps1`](scripts/verify-abi.ps1). It covers representative
foundation, token, service, LSA, EventLog, process/thread, module, file,
registry, ACL, and security-descriptor types and constants.

## Verified invariants

- `BOOL`, `LUID`, `GUID`, `FILETIME`, `UNICODE_STRING`, and
  `SECURITY_ATTRIBUTES` sizes and key offsets.
- `TOKEN_ALL_ACCESS`, `TOKEN_PRIVILEGES`, SID authority, and SID tail layout.
- Service status and enumeration layouts.
- `PROCESS_INFORMATION`, `PROCESSENTRY32W`, and `THREADENTRY32` sizes and key
  offsets.
- File attribute and by-handle identity structures.
- ACL, allowed/denied ACE, SID, privilege-set, generic-mapping, absolute
  security-descriptor, and self-relative security-descriptor layouts.
- Registry access masks/value types and EventLog handle width.
- Module/function-pointer width plus link/load behavior for `kernel32`,
  `advapi32`, `wevtapi`, `secur32`, and SDDL conversion APIs.

## Local verification

Validated on 2026-08-27 against Windows SDK `10.0.26100.0` using:

```powershell
./scripts/verify-abi.ps1 -Arch x64
./scripts/verify-abi.ps1 -Arch x86
./scripts/verify-abi.ps1 -Arch arm64
cargo test --all-features
```

CI repeats these checks and cross-compiles the crate for the three MSVC Rust
targets on every push and pull request. It also runs the functional suite on
native x64 and ARM64 Windows runners.
