//! Feature `lsa-auth` — LSA authentication package client surface.
//!
//! Covers what `windows-lsa` needs: connect (untrusted) to the LSA server,
//! look up an auth package (`Kerberos`, `Negotiate`, `NTLM`, `MSV1_0`), and
//! call it with a protocol-specific request buffer (KerbRetrieveTicket,
//! KerbSubmitTicket, KerbQueryTicketCache, KerbPurgeTicketCache, etc.).
//!
//! `KERB_*` request/response structures are NOT declared here — every
//! consumer defines them locally as `#[repr(C)]` because the fine-grained
//! layout varies per Windows version. This module only exposes the LSA
//! transport (five functions + LSA_STRING).

use crate::foundation::{HANDLE, NTSTATUS};
use core::ffi::c_void;

// ---- LSA_STRING (ntsecapi.h) — ANSI counted string ------------------------

/// `LSA_STRING` — ANSI counted string. Note: different from `UNICODE_STRING`
/// in that `Buffer` points to bytes (not wchars) and `Length` counts bytes
/// (not wchars × 2).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LSA_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u8,
}

impl LSA_STRING {
    /// Build an `LSA_STRING` view over an ANSI byte slice (typically an ASCII
    /// package name like `"Kerberos"` or `"Negotiate"`). Caller keeps the
    /// slice alive for the lifetime of the returned struct.
    pub fn from_slice(slice: &mut [u8]) -> Self {
        let len = slice.len() as u16;
        Self {
            Length: len,
            MaximumLength: len,
            Buffer: slice.as_mut_ptr(),
        }
    }
}

// ---- Functions ------------------------------------------------------------

#[link(name = "secur32")]
extern "system" {
    /// `LsaConnectUntrusted` — connect to LSA without registering a logon process.
    /// Sufficient for read + submit operations against auth packages.
    pub fn LsaConnectUntrusted(LsaHandle: *mut HANDLE) -> NTSTATUS;

    /// `LsaLookupAuthenticationPackage` — resolve an ANSI package name to its
    /// numeric ID (out-param). Values are stable per boot session.
    pub fn LsaLookupAuthenticationPackage(
        LsaHandle: HANDLE,
        PackageName: *const LSA_STRING,
        AuthenticationPackage: *mut u32,
    ) -> NTSTATUS;

    /// `LsaCallAuthenticationPackage` — package-specific request (KERB_*, MSV1_0_*, …).
    ///
    /// - `ProtocolSubmitBuffer` is a `#[repr(C)]` request struct whose first field
    ///   is a `message_type: u32` identifying the operation within the package.
    /// - `ProtocolReturnBuffer` receives an LSA-allocated pointer that MUST be
    ///   freed with `LsaFreeReturnBuffer`.
    /// - `ProtocolStatus` receives the package-level status code (distinct from
    ///   the transport-level `NTSTATUS` return).
    pub fn LsaCallAuthenticationPackage(
        LsaHandle: HANDLE,
        AuthenticationPackage: u32,
        ProtocolSubmitBuffer: *const c_void,
        SubmitBufferLength: u32,
        ProtocolReturnBuffer: *mut *mut c_void,
        ReturnBufferLength: *mut u32,
        ProtocolStatus: *mut NTSTATUS,
    ) -> NTSTATUS;

    /// `LsaDeregisterLogonProcess` — close an LSA handle from
    /// `LsaConnectUntrusted` / `LsaRegisterLogonProcess`.
    pub fn LsaDeregisterLogonProcess(LsaHandle: HANDLE) -> NTSTATUS;

    /// `LsaFreeReturnBuffer` — free an LSA-allocated buffer returned via
    /// `LsaCallAuthenticationPackage`. Must be called for every non-null
    /// return-buffer to avoid leaking LSA memory.
    pub fn LsaFreeReturnBuffer(Buffer: *mut c_void) -> NTSTATUS;
}

// ---- Compile-time layout assertions ----------------------------------------

#[cfg(target_pointer_width = "64")]
const _: () = {
    // LSA_STRING: u16(2) + u16(2) + *mut u8(8) = align 8 → 16
    assert!(core::mem::size_of::<LSA_STRING>() == 16);
};
