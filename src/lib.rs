//! # win32-min
//!
//! Minimal, hand-rolled Win32 FFI shim — the ~50 functions and types 90% of
//! Windows Rust security / admin / audit tooling actually calls, packaged as one
//! small crate with **zero `windows-rs` or `winapi` dependency**.
//!
//! ## Design
//!
//! - Pure `extern "system"` declarations + `#[repr(C)]` structs. No proc macros,
//!   no build script, no code generation.
//! - Feature-gated by Win32 subsystem. Default = only the [`foundation`] types
//!   (HANDLE, LUID, NTSTATUS, PCWSTR, …). Enable only what you need.
//! - Every declaration `unsafe` because Win32 FFI is `unsafe`; callers wrap.
//! - Sub-second cold compile. Constant-fold in linker. No transitive deps.
//!
//! ## Features
//!
//! | Feature | Subsystem | Downstream consumer |
//! |---|---|---|
//! | `security-token` | Token / privilege / impersonation | `windows-token` |
//! | `services` | Service Control Manager (local) | `windows-scm` |
//! | `lsa-auth` | LSA authentication package | `windows-lsa` |
//! | `eventlog` | EventLog v6 (Evt* API) | `windows-eventlog-native` |
//! | `full` | all four | — |
//!
//! ## Why not `windows-rs` or `winapi`
//!
//! - `windows-rs` — official Microsoft, correct + comprehensive, but 100+ MB
//!   artifacts, feature-flag puzzle, and version churn (0.48 → 0.51 → 0.58 → 0.61)
//!   creates dep-graph duplication in binaries that pull multiple `windows-rs`-
//!   based crates. Use it for COM (which this crate does not attempt to cover).
//! - `winapi` — deprecated de-facto since 2021. Last release 0.3.9.
//!
//! `win32-min` covers only what a hand-audited surface actually needs — no COM,
//! no WinRT, no DirectX, no auto-generated bindings. If you need those, use
//! `windows-rs`. If you need one of the four subsystems above and don't want to
//! pay the `windows-rs` cost, use this.
//!
//! ## Non-goals
//!
//! - Not a Win32 SDK replacement. Missing ~99% of the Win32 API surface.
//! - Not a COM host. COM interfaces require vtable layouts + `IUnknown` support
//!   that `windows-rs` handles cleanly; hand-rolling that is not worth the LOC.
//! - Not portable — Windows-only, no fallback stubs.

// Win32 header convention — mirror upstream naming so cross-reference with MSDN docs is
// mechanical. Not a style choice we can override.
#![allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    clippy::upper_case_acronyms
)]
#![cfg_attr(not(feature = "eventlog"), no_std)] // eventlog needs alloc for XML

pub mod foundation;

#[cfg(feature = "security-token")]
pub mod security_token;

#[cfg(feature = "services")]
pub mod services;

#[cfg(feature = "lsa-auth")]
pub mod lsa_auth;

#[cfg(feature = "eventlog")]
pub mod eventlog;
