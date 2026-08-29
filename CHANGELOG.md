# Changelog

All notable changes to this project are documented here.

## Unreleased

## 0.1.3 - 2026-08-29

### Added

- A research-facing ecosystem map covering the raw binding crate, safe
  companion crates, pure-Rust parsers, and explicitly experimental projects.
- An `llms.txt` index that gives AI agents a concise, status-aware route to the
  API, verification evidence, examples, and companion crates.

### Changed

- Refined package metadata around Windows security research, DFIR, and EDR
  discovery without changing the API or feature set.

## 0.1.2 - 2026-08-27

### Added

- Independent `process`, `thread`, `module`, `file`, and `security` features;
  the 0.1.1 feature names remain as compatibility aliases.
- Process/thread access types and `PROCESS_INFORMATION`, plus test-owned
  suspend/resume validation.
- Security-focused file metadata, identity, final-path, move, and delete APIs.
- Minimal DLL loading, module lookup, symbol resolution, and release APIs.
- ACL inspection and access-check primitives including absolute security
  descriptors, allowed/denied ACEs, SIDs, generic mappings, and privilege sets.
- `RegQueryInfoKeyW` for correct registry enumeration buffer sizing.
- Zero-dependency `Win32Error` message formatting and subsystem-specific owned
  `Handle`, `ProcessHandle`, `ThreadHandle`, `TokenHandle`, `RegistryKey`, and
  `ServiceHandle` wrappers.
- Six runnable process, token, registry, service, Event Log, and security
  examples.
- Live Windows lifecycle tests for process/thread, registry, security
  descriptor, token, LSA authentication, Event Log, module, file, handle, and
  service APIs.
- An elevated CI test that creates, queries, and deletes a temporary stopped
  service.
- Native Windows ARM64 CI, Rust 1.74.1 MSRV CI, missing-documentation checks,
  per-function FFI safety-contract checks, and a zero-dependency policy gate.

### Changed

- Expanded the reproducible `win32-min` / `windows-sys` / `windows` comparison
  with incremental rebuild, rustdoc, and binding-source-size measurements.
- Documented every public item and added an explicit `# Safety` contract to
  every exported FFI function.

## 0.1.1 - 2026-08-27

### Fixed

- Correct `TOKEN_ALL_ACCESS` to include `TOKEN_ADJUST_SESSIONID` on modern
  Windows (`0x000f_01ff`).
- Link `OpenProcess` from `kernel32` rather than `advapi32`.
- Keep the crate `no_std` when the `eventlog` feature is enabled.
- Reject counted strings whose byte length cannot fit in the Win32 `u16`
  length fields instead of silently truncating them.

### Added

- `process-thread` feature for process/thread discovery and inspection.
- `registry` feature for registry open/query/enumeration/update operations.
- `security-descriptor` feature for ACL, SDDL, and security-info operations.
- Rust ABI tests covering sizes, alignments, offsets, and constants.
- Microsoft Windows SDK C-header verification and a Windows CI target matrix.
- Reproducible comparison scaffold for `win32-min`, `windows-sys`, and
  `windows`.
