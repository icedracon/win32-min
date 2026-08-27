//! Feature `security-token` — access-token / privilege / impersonation surface.
//!
//! Covers what `windows-token` needs: `OpenProcessToken`, `OpenThreadToken`,
//! `DuplicateTokenEx`, `SetThreadToken`, `ImpersonateLoggedOnUser`,
//! `RevertToSelf`, `LookupPrivilegeValueW`, `AdjustTokenPrivileges`,
//! `GetTokenInformation`.

use crate::foundation::{BOOL, HANDLE, LUID, PCWSTR};
use core::ffi::c_void;

// ---- Constants ------------------------------------------------------------

/// `PROCESS_QUERY_LIMITED_INFORMATION` per processthreadsapi.h.
pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
/// `PROCESS_QUERY_INFORMATION`.
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;

// TOKEN_ACCESS_MASK bits (winnt.h).
pub const TOKEN_QUERY: u32 = 0x0008;
pub const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
pub const TOKEN_ADJUST_GROUPS: u32 = 0x0040;
pub const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
pub const TOKEN_ADJUST_SESSIONID: u32 = 0x0100;
pub const TOKEN_DUPLICATE: u32 = 0x0002;
pub const TOKEN_IMPERSONATE: u32 = 0x0004;
pub const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
pub const TOKEN_READ: u32 = 0x0002_0008;
pub const TOKEN_WRITE: u32 = 0x0002_00e0;
pub const TOKEN_EXECUTE: u32 = 0x0002_0000;
pub const TOKEN_ALL_ACCESS: u32 = 0x000f_01ff;

// Privilege-attribute bits (winnt.h `SE_PRIVILEGE_*`).
pub const SE_PRIVILEGE_ENABLED_BY_DEFAULT: u32 = 0x0000_0001;
pub const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;
pub const SE_PRIVILEGE_REMOVED: u32 = 0x0000_0004;
pub const SE_PRIVILEGE_USED_FOR_ACCESS: u32 = 0x8000_0000;

// ---- Enum-shape constants (kept as u32 to match `#[repr(i32)]` in winnt.h) -

/// `SECURITY_IMPERSONATION_LEVEL` variants.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SECURITY_IMPERSONATION_LEVEL {
    SecurityAnonymous = 0,
    SecurityIdentification = 1,
    SecurityImpersonation = 2,
    SecurityDelegation = 3,
}

/// `TOKEN_TYPE` variants.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TOKEN_TYPE {
    TokenPrimary = 1,
    TokenImpersonation = 2,
}

/// `TOKEN_INFORMATION_CLASS` — only the values our downstream consumers use.
/// Full enum is ~40 values; add on demand.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TOKEN_INFORMATION_CLASS {
    TokenUser = 1,
    TokenGroups = 2,
    TokenPrivileges = 3,
    TokenOwner = 4,
    TokenPrimaryGroup = 5,
    TokenDefaultDacl = 6,
    TokenSource = 7,
    TokenType = 8,
    TokenImpersonationLevel = 9,
    TokenStatistics = 10,
    TokenRestrictedSids = 11,
    TokenSessionId = 12,
    TokenGroupsAndPrivileges = 13,
    TokenSandBoxInert = 15,
    TokenOrigin = 17,
    TokenElevationType = 18,
    TokenLinkedToken = 19,
    TokenElevation = 20,
    TokenHasRestrictions = 21,
    TokenAccessInformation = 22,
    TokenVirtualizationAllowed = 23,
    TokenVirtualizationEnabled = 24,
    TokenIntegrityLevel = 25,
    TokenUIAccess = 26,
    TokenMandatoryPolicy = 27,
    TokenLogonSid = 28,
    TokenIsAppContainer = 29,
    TokenCapabilities = 30,
    TokenAppContainerSid = 31,
    TokenAppContainerNumber = 32,
    TokenUserClaimAttributes = 33,
    TokenDeviceClaimAttributes = 34,
    TokenDeviceGroups = 37,
    TokenRestrictedDeviceGroups = 38,
}

// ---- Structs --------------------------------------------------------------

/// `LUID_AND_ATTRIBUTES` per winnt.h.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LUID_AND_ATTRIBUTES {
    pub Luid: LUID,
    pub Attributes: u32,
}

/// `TOKEN_PRIVILEGES` — variadic tail. Only the fixed prefix + one entry is
/// represented; callers manage arrays inline via `bytes::BytesMut` or a
/// custom `#[repr(C)]` struct for known-length cases.
#[repr(C)]
pub struct TOKEN_PRIVILEGES {
    pub PrivilegeCount: u32,
    pub Privileges: [LUID_AND_ATTRIBUTES; 1],
}

/// `SID_IDENTIFIER_AUTHORITY` per winnt.h.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SID_IDENTIFIER_AUTHORITY {
    pub Value: [u8; 6],
}

/// `SID` — variadic tail. Fixed prefix; callers walk sub-authorities inline
/// via pointer arithmetic on `SID*`.
#[repr(C)]
pub struct SID {
    pub Revision: u8,
    pub SubAuthorityCount: u8,
    pub IdentifierAuthority: SID_IDENTIFIER_AUTHORITY,
    pub SubAuthority: [u32; 1],
}

/// `PSID` — opaque pointer to a SID (per Windows headers `PSID` is `PVOID`).
/// Matches the `[SID]` blob callers pass to `IsValidSid` / `GetLengthSid` /
/// `GetSidSubAuthority`.
pub type PSID = *mut c_void;

/// `SID_AND_ATTRIBUTES` per winnt.h.
#[repr(C)]
pub struct SID_AND_ATTRIBUTES {
    pub Sid: PSID,
    pub Attributes: u32,
}

/// `TOKEN_USER` per winnt.h.
#[repr(C)]
pub struct TOKEN_USER {
    pub User: SID_AND_ATTRIBUTES,
}

/// `TOKEN_MANDATORY_LABEL` per winnt.h.
#[repr(C)]
pub struct TOKEN_MANDATORY_LABEL {
    pub Label: SID_AND_ATTRIBUTES,
}

// ---- Functions ------------------------------------------------------------

#[link(name = "kernel32")]
extern "system" {
    pub fn GetCurrentProcess() -> HANDLE;
    pub fn GetCurrentThread() -> HANDLE;

    pub fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: BOOL, dwProcessId: u32) -> HANDLE;
}

#[link(name = "advapi32")]
extern "system" {
    pub fn OpenProcessToken(
        ProcessHandle: HANDLE,
        DesiredAccess: u32,
        TokenHandle: *mut HANDLE,
    ) -> BOOL;

    pub fn OpenThreadToken(
        ThreadHandle: HANDLE,
        DesiredAccess: u32,
        OpenAsSelf: BOOL,
        TokenHandle: *mut HANDLE,
    ) -> BOOL;

    pub fn DuplicateTokenEx(
        hExistingToken: HANDLE,
        dwDesiredAccess: u32,
        lpTokenAttributes: *const c_void,
        ImpersonationLevel: SECURITY_IMPERSONATION_LEVEL,
        TokenType: TOKEN_TYPE,
        phNewToken: *mut HANDLE,
    ) -> BOOL;

    pub fn SetThreadToken(Thread: *const HANDLE, Token: HANDLE) -> BOOL;

    pub fn ImpersonateLoggedOnUser(hToken: HANDLE) -> BOOL;

    pub fn RevertToSelf() -> BOOL;

    pub fn LookupPrivilegeValueW(lpSystemName: PCWSTR, lpName: PCWSTR, lpLuid: *mut LUID) -> BOOL;

    pub fn AdjustTokenPrivileges(
        TokenHandle: HANDLE,
        DisableAllPrivileges: BOOL,
        NewState: *const TOKEN_PRIVILEGES,
        BufferLength: u32,
        PreviousState: *mut TOKEN_PRIVILEGES,
        ReturnLength: *mut u32,
    ) -> BOOL;

    pub fn GetTokenInformation(
        TokenHandle: HANDLE,
        TokenInformationClass: TOKEN_INFORMATION_CLASS,
        TokenInformation: *mut c_void,
        TokenInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> BOOL;

    pub fn SetTokenInformation(
        TokenHandle: HANDLE,
        TokenInformationClass: TOKEN_INFORMATION_CLASS,
        TokenInformation: *const c_void,
        TokenInformationLength: u32,
    ) -> BOOL;

    // ---- SID helpers (winnt.h / winbase.h — all in advapi32) ----

    pub fn IsValidSid(pSid: PSID) -> BOOL;

    pub fn GetLengthSid(pSid: PSID) -> u32;

    /// Returns a pointer to one 32-bit subauthority in the SID's inline array.
    pub fn GetSidSubAuthority(pSid: PSID, nSubAuthority: u32) -> *mut u32;

    /// Returns a pointer to the u8 count of subauthorities.
    pub fn GetSidSubAuthorityCount(pSid: PSID) -> *mut u8;

    /// Returns a pointer to the SID's `SID_IDENTIFIER_AUTHORITY`.
    pub fn GetSidIdentifierAuthority(pSid: PSID) -> *mut SID_IDENTIFIER_AUTHORITY;
}

// ---- Compile-time layout assertions ----------------------------------------

#[cfg(target_pointer_width = "64")]
const _: () = {
    // LUID_AND_ATTRIBUTES: LUID(8) + u32(4) = 12
    assert!(core::mem::size_of::<LUID_AND_ATTRIBUTES>() == 12);
    // SID_IDENTIFIER_AUTHORITY: [u8;6] = 6
    assert!(core::mem::size_of::<SID_IDENTIFIER_AUTHORITY>() == 6);
    // TOKEN_PRIVILEGES: PrivilegeCount u32(4) + [LUID_AND_ATTRIBUTES;1](12) = 16
    assert!(core::mem::size_of::<TOKEN_PRIVILEGES>() == 16);
};

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::size_of::<LUID_AND_ATTRIBUTES>() == 12);
    assert!(core::mem::size_of::<SID_IDENTIFIER_AUTHORITY>() == 6);
    assert!(core::mem::size_of::<TOKEN_PRIVILEGES>() == 16);
};
