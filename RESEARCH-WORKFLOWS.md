# Windows security research workflows

These workflows demonstrate the focused safe crates built on `win32-min`.
They use public APIs, state their privilege requirements, and avoid destructive
operations. Run them from a Windows PowerShell terminal after cloning the
corresponding repository.

## 1. Inspect the current Windows access token

Repository: [`windows-token`](https://github.com/icedracon/windows-token)

```powershell
cargo run --example current_identity
```

Prints the current user SID and integrity level, then duplicates the token and
performs scoped self-impersonation. `ImpersonationGuard` restores the original
thread identity on drop, including during unwinding. No elevation is required.

## 2. Inventory local Windows services

Repository: [`windows-scm`](https://github.com/icedracon/windows-scm)

```powershell
cargo run --example list_services
```

Enumerates local Win32 services with state, process ID, service name, and
display name. This is read-only and normally works without elevation. The
current safe API does not yet return full service configuration or executable
paths, so the workflow does not claim unquoted-path or ACL analysis.

## 3. Inspect the current Kerberos ticket cache

Repository: [`windows-lsa`](https://github.com/icedracon/windows-lsa)

```powershell
cargo run --example kerberos_cache
```

Uses an untrusted LSA connection to print the current logon session's cached
ticket metadata. It does not export ticket material, decode ASN.1, or modify
the cache. A local-account session can legitimately return an empty cache.

## 4. Review recent Windows security events

Repository: [`windows-eventlog-native`](https://github.com/icedracon/windows-eventlog-native)

```powershell
cargo run --example recent_security_events -- 30
```

Queries common authentication and directory-service audit event IDs from the
last 30 minutes. Reading the Security channel requires Administrator or Event
Log Readers membership. The query is local and read-only.

## 5. Audit an offline Windows security descriptor

Repository: [`windows-sddl`](https://github.com/icedracon/windows-sddl)

```powershell
cargo run --example parse_sd -- 0100048014000000...
```

Parses a hexadecimal self-relative binary `SECURITY_DESCRIPTOR` and highlights
dangerous allow ACEs such as GenericAll, WriteDacl, WriteOwner, DCSync, shadow
credentials, and RBCD. This workflow is cross-platform and performs no FFI.
Despite the crate name, it does not parse the complete textual SDDL language.

## Combined ecosystem inventory

The [`research-kit`](https://github.com/icedracon/win32-min/tree/master/research-kit)
is a standalone binary crate that depends on the published ecosystem versions
rather than unpublished path dependencies. It produces a compact identity,
service, Kerberos, Event Log, and ACL snapshot:

```powershell
cargo run --manifest-path research-kit/Cargo.toml
```

The program continues when a subsystem is unavailable, so a non-domain or
non-elevated workstation still produces useful partial results. It makes no
changes to services, tickets, tokens, logs, or system security descriptors.

## Choosing the lower-level crate

Use `win32-min` directly when you need raw, audited declarations or the
zero-dependency handle layer. Use a companion when its typed workflow matches
the task. Use Microsoft's `windows` or `windows-sys` crates when you need broad
Win32, WinRT, or COM coverage outside this intentionally narrow ecosystem.
