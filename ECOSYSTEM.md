# win32-min ecosystem

This repository is the dependency-free ABI foundation for a focused family of
Rust crates used in Windows security research, digital forensics and incident
response (DFIR), detection engineering, identity research, and administration.
The ecosystem deliberately separates raw Win32 bindings from safe workflow
crates and from portable binary parsers.

## Component map

| Crate | Layer | Primary use | Maturity |
|---|---|---|---|
| [`win32-min`](https://crates.io/crates/win32-min) | Raw FFI plus small ownership layer | Windows SDK-checked Win32 ABI for process, thread, file, module, registry, ACL, token, SCM, LSA, and Event Log APIs | CI-tested; independent review pending |
| [`windows-token`](https://crates.io/crates/windows-token) | Safe companion | Access tokens, privileges, duplication, and scoped impersonation | CI-tested; external adoption pending |
| [`windows-scm`](https://crates.io/crates/windows-scm) | Safe companion | Local Service Control Manager enumeration and service lifecycle | CI-tested; external adoption pending |
| [`windows-lsa`](https://crates.io/crates/windows-lsa) | Safe companion | LSA Kerberos package and ticket-cache operations | CI-tested; external adoption pending |
| [`windows-eventlog-native`](https://crates.io/crates/windows-eventlog-native) | Safe companion | Native Event Log query, render, and structured XML parsing | CI-tested; external adoption pending |
| [`windows-sddl`](https://crates.io/crates/windows-sddl) | Portable parser | Self-relative security descriptors, ACLs, ACEs, SIDs, GUIDs, and AD rights | CI/fuzz-tested; external adoption pending |
| [`windows-sspi-shim`](https://crates.io/crates/windows-sspi-shim) | Experimental adjacent crate | Proposed Negotiate and message-sealing API | Prototype; current sealing backend is not cryptographic |

`windows-sddl` is intentionally independent of `win32-min`: it parses binary
security descriptors on Windows, Linux, and macOS. `windows-sspi-shim` is
listed so researchers can discover its status, not because it is production
ready or currently built on `win32-min`.

## Choose the right crate

- Use `win32-min` when writing your own policy layer and you need a small,
  verified, feature-gated Win32 ABI surface.
- Use `windows-token` when token ownership, privilege adjustment, or guaranteed
  impersonation reversion is the workflow.
- Use `windows-scm` for typed local SCM enumeration, status, control, creation,
  and deletion.
- Use `windows-lsa` for direct Kerberos authentication-package and ticket-cache
  calls through LSA.
- Use `windows-eventlog-native` to query and parse modern Windows Event Log
  records without spawning PowerShell or `wevtutil`.
- Use `windows-sddl` to inspect hostile or offline self-relative security
  descriptor bytes without requiring Windows.

## Research workflows

| Research question | Recommended components |
|---|---|
| Which identity and privileges does this process hold? | `windows-token` + `win32-min/process` |
| What services exist and which process owns each service? | `windows-scm` + `win32-min/process` |
| What Kerberos tickets exist for the current logon session? | `windows-lsa` |
| Which security events did an experiment generate? | `windows-eventlog-native` |
| Who can modify an AD object or perform DCSync/RBCD? | `windows-sddl` |
| Does a hand-written FFI structure match the Windows SDK? | `win32-min` ABI tests and SDK probe |

## Compatibility and evidence

- The tested companions require `win32-min` 0.1.2 or newer within the 0.1
  compatibility line.
- `win32-min` has no normal, development, or build dependencies.
- ABI probes compile against Microsoft SDK headers for x86, x64, and ARM64.
- Runtime tests execute on Windows x64 and native Windows ARM64 in CI.
- Mutable tests use test-owned processes, files, registry keys, tokens, and
  stopped temporary services with cleanup guards.
- [`ABI-REPORT.md`](ABI-REPORT.md) and
  [`TEST-COVERAGE.md`](TEST-COVERAGE.md) contain the reproducible evidence.
- The independent-review gate and evidence requirements are public in
  [`REVIEWING.md`](REVIEWING.md). Maintainer testing and download counts do not
  satisfy that gate.

## Search vocabulary

Relevant research and implementation terms include: Windows security, Win32
FFI, Rust FFI, DFIR, digital forensics, EDR, detection engineering, Active
Directory, access tokens, token impersonation, Windows privileges, Service
Control Manager, LSA, Kerberos ticket cache, Windows Event Log, SDDL, security
descriptors, ACL, ACE, SID, DCSync, RBCD, ABI verification, x64, and ARM64.

## Boundaries

- This is not a complete Windows SDK or COM framework.
- Remote memory access and code-injection primitives are deliberately absent.
- `windows-sddl` parses the binary self-relative security-descriptor format;
  its crate name does not imply complete SDDL string-language support.
- `windows-sspi-shim` must not be described as providing real encryption until
  its platform backend replaces the documented deterministic test framing.
