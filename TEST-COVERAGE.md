# Test coverage

`win32-min` tests both the ABI surface and live Windows behavior. The normal
suite is safe to run as a standard user:

```powershell
cargo test --all-features
```

The one ignored test needs permission to create a service. It creates a
uniquely named, stopped service, queries it, and deletes it without starting
the configured executable:

```powershell
cargo test --all-features --test services_live -- --ignored --test-threads=1
```

## Runtime matrix

| Test file | APIs and behavior exercised |
|---|---|
| `abi.rs` | Windows SDK-compatible sizes, alignment, offsets, constants, and checked counted-string constructors |
| `windows_smoke.rs` | Kernel32 and Advapi32 linking, current-process access, HKCU access, and SDDL conversion |
| `process_thread_live.rs` | Last-error state, process/thread pseudo and owned handles, image path lookup, Toolhelp enumeration, and termination of a test-owned child |
| `registry_live.rs` | Create, set, query, enumerate, flush, reopen, and delete a unique HKCU key tree |
| `security_descriptor_live.rs` | SDDL conversion plus named-file and handle-based security descriptor round trips on a unique temporary file |
| `security_token_live.rs` | Process and thread tokens, duplication, information get/set, SID helpers, privilege adjustment, and impersonation/revert |
| `lsa_live.rs` | Untrusted LSA connection, Kerberos package lookup and query, returned-buffer release, and deregistration |
| `eventlog_live.rs` | Application log query, event retrieval, two-call XML rendering, and handle closure |
| `services_live.rs` | SCM/service enumeration and status queries, interrogation, access-denied behavior, plus elevated create/query/delete lifecycle |

Mutable tests use uniquely named test-owned resources and `Drop` cleanup
guards. The process termination test only targets the child it created. The
service lifecycle test never starts its temporary service.

## Build and ABI matrix

CI additionally runs:

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo check --all-features --target i686-pc-windows-msvc
cargo check --all-features --target x86_64-pc-windows-msvc
cargo check --all-features --target aarch64-pc-windows-msvc
./scripts/verify-abi.ps1 -Arch x64
./scripts/verify-abi.ps1 -Arch x86
./scripts/verify-abi.ps1 -Arch arm64
cargo package
```

The minimum supported Rust version is also checked locally with Rust 1.74.1.

## Validated systems

- Windows 10 Enterprise Evaluation 10.0.19044, x86_64: 23 normal tests and
  the separate elevated service lifecycle test passed on 2026-08-27.
- Windows 11 build 22621: downstream SCM and token consumers have been
  exercised live as described in the README.

On local-account sessions without Kerberos credentials, the LSA dispatch call
can succeed while the Kerberos package returns
`STATUS_NO_SUCH_LOGON_SESSION`. The test accepts that specific environment
result and rejects all other unexpected protocol statuses.
