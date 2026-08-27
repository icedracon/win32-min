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
    /// Current byte length, excluding any terminator.
    pub Length: u16,
    /// Capacity in bytes.
    pub MaximumLength: u16,
    /// Borrowed pointer to ANSI bytes.
    pub Buffer: *mut u8,
}

impl LSA_STRING {
    /// Maximum byte length representable by an `LSA_STRING`.
    pub const MAX_BYTES: usize = u16::MAX as usize;

    /// Build a checked `LSA_STRING` view over an ANSI byte slice.
    pub fn try_from_slice(slice: &mut [u8]) -> Option<Self> {
        let len = u16::try_from(slice.len()).ok()?;
        Some(Self {
            Length: len,
            MaximumLength: len,
            Buffer: slice.as_mut_ptr(),
        })
    }

    /// Build an `LSA_STRING` view over an ANSI byte slice (typically an ASCII
    /// package name like `"Kerberos"` or `"Negotiate"`). Caller keeps the
    /// slice alive for the lifetime of the returned struct.
    ///
    /// # Panics
    ///
    /// Panics when the slice is longer than [`Self::MAX_BYTES`]. Use
    /// [`Self::try_from_slice`] for fallible construction.
    pub fn from_slice(slice: &mut [u8]) -> Self {
        Self::try_from_slice(slice).expect("LSA_STRING length exceeds u16::MAX")
    }
}

// ---- Functions ------------------------------------------------------------

#[link(name = "secur32")]
extern "system" {
    /// `LsaConnectUntrusted` — connect to LSA without registering a logon process.
    /// Sufficient for read + submit operations against auth packages.
    ///
    /// # Safety
    ///
    /// `LsaHandle` must point to writable handle storage. On success the
    /// returned handle is owned and must be passed once to
    /// [`LsaDeregisterLogonProcess`].
    pub fn LsaConnectUntrusted(LsaHandle: *mut HANDLE) -> NTSTATUS;

    /// `LsaLookupAuthenticationPackage` — resolve an ANSI package name to its
    /// numeric ID (out-param). Values are stable per boot session.
    ///
    /// # Safety
    ///
    /// The LSA handle must be valid, `PackageName` must point to a readable
    /// counted string whose buffer remains alive for the call, and
    /// `AuthenticationPackage` must be writable.
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
    ///
    /// # Safety
    ///
    /// The LSA handle and package ID must be valid. The submit pointer must be
    /// readable for `SubmitBufferLength` bytes with the package-specific ABI.
    /// All three outputs must be writable. Every non-null returned buffer is
    /// owned and must be released with [`LsaFreeReturnBuffer`].
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
    ///
    /// # Safety
    ///
    /// `LsaHandle` must be a valid uniquely owned LSA handle that has not
    /// already been deregistered.
    pub fn LsaDeregisterLogonProcess(LsaHandle: HANDLE) -> NTSTATUS;

    /// `LsaFreeReturnBuffer` — free an LSA-allocated buffer returned via
    /// `LsaCallAuthenticationPackage`. Must be called for every non-null
    /// return-buffer to avoid leaking LSA memory.
    ///
    /// # Safety
    ///
    /// `Buffer` must be a non-null uniquely owned allocation returned by LSA,
    /// and it must not already have been released.
    pub fn LsaFreeReturnBuffer(Buffer: *mut c_void) -> NTSTATUS;
}

// ---- Compile-time layout assertions ----------------------------------------

#[cfg(target_pointer_width = "64")]
const _: () = {
    // LSA_STRING: u16(2) + u16(2) + *mut u8(8) = align 8 → 16
    assert!(core::mem::size_of::<LSA_STRING>() == 16);
};

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::size_of::<LSA_STRING>() == 8);
};
