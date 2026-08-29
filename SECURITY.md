# Security Policy

## Scope

This policy covers the `win32-min` repository: its raw Win32 declarations,
public ownership wrappers, feature boundaries, tests, examples, and release
artifacts. Findings in companion crates should be reported through the private
Security channel of the affected companion repository.

## Threat Model and Trust Boundaries

Raw `extern "system"` declarations are unsafe and require callers to uphold
their documented contracts. Safe ownership wrappers must not require callers
to prevent memory corruption, invalid handle closure, double close, use after
close, or failed cleanup.

Windows API output buffers, lengths, handles, SIDs, security descriptors, and
event data may be malformed, concurrently changed, or attacker influenced.

## Security Invariants

- Rust declarations must match Windows SDK calling conventions, layouts,
  signedness, pointer types, and constants on x86, x64, and ARM64.
- Safe APIs must not expose undefined behavior for documented inputs.
- Every owned handle must use its exact matching close function and close once.
- Two-call buffer APIs must handle size changes, overflow, null pointers, and
  truncated output without reading uninitialized or out-of-bounds memory.
- Impersonation and privilege operations must restore prior state on every
  success and error path.
- Tests that mutate Windows state must use uniquely named test-owned resources
  and attempt cleanup on failure.

## Reportable Findings and Severity

Report memory-safety defects, exploitable ABI mismatches, unsafe safe
abstractions, handle-type confusion, privilege or impersonation failures,
attacker-controlled resource exhaustion, and cleanup failures that can affect
resources not owned by the test.

Severity depends on realistic reachability and impact. Memory corruption,
privilege escalation, credential disclosure, persistent impersonation, or
reliable denial of service through a safe or normally used interface may be
high or critical.

## Reporting

Use GitHub's private **Security → Report a vulnerability** channel:

https://github.com/icedracon/win32-min/security/advisories/new

Include the affected version or commit, Windows build and architecture,
required privilege level, reproduction steps, impact, and any proposed test or
fix. Do not publish exploit details in a public issue.

## Boundaries and Known Limitations

Demonstrating that an arbitrary unsafe caller can violate a documented raw FFI
precondition is not by itself a vulnerability. Incorrect declarations,
incomplete safety contracts, or safe wrappers that permit the violation are
reportable.

The project is not a complete Windows SDK, COM framework, remote
administration framework, or injection library. No accepted security risks are
currently documented.
