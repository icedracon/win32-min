# Changelog

All notable changes to this project are documented here.

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
