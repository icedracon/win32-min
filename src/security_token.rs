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
/// Permission to query token information.
pub const TOKEN_QUERY: u32 = 0x0008;
/// Permission to enable, disable, or remove privileges.
pub const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
/// Permission to adjust token groups.
pub const TOKEN_ADJUST_GROUPS: u32 = 0x0040;
/// Permission to change owner, group, or default DACL.
pub const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
/// Permission to change the token session identifier.
pub const TOKEN_ADJUST_SESSIONID: u32 = 0x0100;
/// Permission to duplicate a token.
pub const TOKEN_DUPLICATE: u32 = 0x0002;
/// Permission to attach an impersonation token.
pub const TOKEN_IMPERSONATE: u32 = 0x0004;
/// Permission to assign a primary token to a process.
pub const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
/// Standard token read permissions.
pub const TOKEN_READ: u32 = 0x0002_0008;
/// Standard token write permissions.
pub const TOKEN_WRITE: u32 = 0x0002_00e0;
/// Standard token execute permissions.
pub const TOKEN_EXECUTE: u32 = 0x0002_0000;
/// All token-specific and standard permissions on modern Windows.
pub const TOKEN_ALL_ACCESS: u32 = 0x000f_01ff;

// Privilege-attribute bits (winnt.h `SE_PRIVILEGE_*`).
/// Privilege is enabled when a token is created.
pub const SE_PRIVILEGE_ENABLED_BY_DEFAULT: u32 = 0x0000_0001;
/// Privilege is currently enabled.
pub const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;
/// Privilege is removed from the token.
pub const SE_PRIVILEGE_REMOVED: u32 = 0x0000_0004;
/// Privilege contributed to an access check.
pub const SE_PRIVILEGE_USED_FOR_ACCESS: u32 = 0x8000_0000;

// ---- Enum-shape constants (kept as u32 to match `#[repr(i32)]` in winnt.h) -

/// `SECURITY_IMPERSONATION_LEVEL` variants.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SECURITY_IMPERSONATION_LEVEL {
    /// The server cannot identify or impersonate the client.
    SecurityAnonymous = 0,
    /// The server may identify but not impersonate the client.
    SecurityIdentification = 1,
    /// The server may impersonate the client on the local system.
    SecurityImpersonation = 2,
    /// The server may impersonate the client on remote systems.
    SecurityDelegation = 3,
}

/// `TOKEN_TYPE` variants.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TOKEN_TYPE {
    /// Primary token assignable to a process.
    TokenPrimary = 1,
    /// Token used for thread impersonation.
    TokenImpersonation = 2,
}

/// `TOKEN_INFORMATION_CLASS` — only the values our downstream consumers use.
/// Full enum is ~40 values; add on demand.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TOKEN_INFORMATION_CLASS {
    /// Token user SID and attributes.
    TokenUser = 1,
    /// Token group SIDs and attributes.
    TokenGroups = 2,
    /// Token privileges.
    TokenPrivileges = 3,
    /// Token owner SID.
    TokenOwner = 4,
    /// Token primary group SID.
    TokenPrimaryGroup = 5,
    /// Token default DACL.
    TokenDefaultDacl = 6,
    /// Token source information.
    TokenSource = 7,
    /// Primary or impersonation token type.
    TokenType = 8,
    /// Impersonation level.
    TokenImpersonationLevel = 9,
    /// Token statistics.
    TokenStatistics = 10,
    /// Restricted SIDs.
    TokenRestrictedSids = 11,
    /// Terminal Services session identifier.
    TokenSessionId = 12,
    /// Combined group and privilege information.
    TokenGroupsAndPrivileges = 13,
    /// Sandbox-inert state.
    TokenSandBoxInert = 15,
    /// Token origin.
    TokenOrigin = 17,
    /// Elevation type.
    TokenElevationType = 18,
    /// Linked elevated or limited token.
    TokenLinkedToken = 19,
    /// Elevation state.
    TokenElevation = 20,
    /// Whether restrictions are present.
    TokenHasRestrictions = 21,
    /// Consolidated access information.
    TokenAccessInformation = 22,
    /// Whether file/registry virtualization is allowed.
    TokenVirtualizationAllowed = 23,
    /// Whether virtualization is enabled.
    TokenVirtualizationEnabled = 24,
    /// Mandatory integrity label.
    TokenIntegrityLevel = 25,
    /// UIAccess state.
    TokenUIAccess = 26,
    /// Mandatory policy.
    TokenMandatoryPolicy = 27,
    /// Logon SID.
    TokenLogonSid = 28,
    /// Whether the token belongs to an app container.
    TokenIsAppContainer = 29,
    /// Capability SIDs.
    TokenCapabilities = 30,
    /// App-container SID.
    TokenAppContainerSid = 31,
    /// App-container instance number.
    TokenAppContainerNumber = 32,
    /// User claim attributes.
    TokenUserClaimAttributes = 33,
    /// Device claim attributes.
    TokenDeviceClaimAttributes = 34,
    /// Device group SIDs.
    TokenDeviceGroups = 37,
    /// Restricted device group SIDs.
    TokenRestrictedDeviceGroups = 38,
}

// ---- Structs --------------------------------------------------------------

/// `LUID_AND_ATTRIBUTES` per winnt.h.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LUID_AND_ATTRIBUTES {
    /// Locally unique privilege identifier.
    pub Luid: LUID,
    /// Privilege attribute flags.
    pub Attributes: u32,
}

/// `TOKEN_PRIVILEGES` — variadic tail. Only the fixed prefix + one entry is
/// represented; callers manage arrays inline via `bytes::BytesMut` or a
/// custom `#[repr(C)]` struct for known-length cases.
#[repr(C)]
pub struct TOKEN_PRIVILEGES {
    /// Number of valid privilege array entries.
    pub PrivilegeCount: u32,
    /// First entry of the variable-length privilege array.
    pub Privileges: [LUID_AND_ATTRIBUTES; 1],
}

/// `SID_IDENTIFIER_AUTHORITY` per winnt.h.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SID_IDENTIFIER_AUTHORITY {
    /// Big-endian authority value.
    pub Value: [u8; 6],
}

/// `SID` — variadic tail. Fixed prefix; callers walk sub-authorities inline
/// via pointer arithmetic on `SID*`.
#[repr(C)]
pub struct SID {
    /// SID format revision.
    pub Revision: u8,
    /// Number of sub-authorities.
    pub SubAuthorityCount: u8,
    /// SID identifier authority.
    pub IdentifierAuthority: SID_IDENTIFIER_AUTHORITY,
    /// First entry of the variable-length sub-authority array.
    pub SubAuthority: [u32; 1],
}

/// `PSID` — opaque pointer to a SID (per Windows headers `PSID` is `PVOID`).
/// Matches the `[SID]` blob callers pass to `IsValidSid` / `GetLengthSid` /
/// `GetSidSubAuthority`.
pub type PSID = *mut c_void;

/// `SID_AND_ATTRIBUTES` per winnt.h.
#[repr(C)]
pub struct SID_AND_ATTRIBUTES {
    /// SID pointer.
    pub Sid: PSID,
    /// SID attribute flags.
    pub Attributes: u32,
}

/// `TOKEN_USER` per winnt.h.
#[repr(C)]
pub struct TOKEN_USER {
    /// User SID and attributes.
    pub User: SID_AND_ATTRIBUTES,
}

/// `TOKEN_MANDATORY_LABEL` per winnt.h.
#[repr(C)]
pub struct TOKEN_MANDATORY_LABEL {
    /// Integrity SID and attributes.
    pub Label: SID_AND_ATTRIBUTES,
}

// ---- Functions ------------------------------------------------------------

#[link(name = "kernel32")]
extern "system" {
    /// Returns the current process pseudo-handle.
    ///
    /// # Safety
    ///
    /// This function has no memory-safety preconditions. The pseudo-handle is
    /// borrowed and must not be closed.
    pub fn GetCurrentProcess() -> HANDLE;
    /// Returns the current thread pseudo-handle.
    ///
    /// # Safety
    ///
    /// This function has no memory-safety preconditions. The pseudo-handle is
    /// borrowed and must not be closed.
    pub fn GetCurrentThread() -> HANDLE;

    /// Opens a process by identifier.
    ///
    /// # Safety
    ///
    /// Access and inheritance values must be valid. A non-null returned handle
    /// is owned by the caller and must be closed exactly once.
    pub fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: BOOL, dwProcessId: u32) -> HANDLE;
}

#[link(name = "advapi32")]
extern "system" {
    /// Opens a process's primary access token.
    ///
    /// # Safety
    ///
    /// The process handle must be valid with query access and `TokenHandle`
    /// must be writable. A successful output handle is owned and must be closed.
    pub fn OpenProcessToken(
        ProcessHandle: HANDLE,
        DesiredAccess: u32,
        TokenHandle: *mut HANDLE,
    ) -> BOOL;

    /// Opens a thread's impersonation token.
    ///
    /// # Safety
    ///
    /// The thread handle must be valid and `TokenHandle` writable. The output
    /// handle is owned. `OpenAsSelf` changes which security context performs
    /// the access check.
    pub fn OpenThreadToken(
        ThreadHandle: HANDLE,
        DesiredAccess: u32,
        OpenAsSelf: BOOL,
        TokenHandle: *mut HANDLE,
    ) -> BOOL;

    /// Creates a primary or impersonation token derived from another token.
    ///
    /// # Safety
    ///
    /// The source handle must have duplicate access, optional attributes must
    /// be readable, and `phNewToken` writable. The output is owned and must be
    /// closed exactly once.
    pub fn DuplicateTokenEx(
        hExistingToken: HANDLE,
        dwDesiredAccess: u32,
        lpTokenAttributes: *const c_void,
        ImpersonationLevel: SECURITY_IMPERSONATION_LEVEL,
        TokenType: TOKEN_TYPE,
        phNewToken: *mut HANDLE,
    ) -> BOOL;

    /// Assigns or clears a thread impersonation token.
    ///
    /// # Safety
    ///
    /// `Thread` may be null for the current thread or point to a valid thread
    /// handle value. `Token` must be null or a valid impersonation token, and
    /// both handles must have the required rights.
    pub fn SetThreadToken(Thread: *const HANDLE, Token: HANDLE) -> BOOL;

    /// Causes the calling thread to impersonate a token's security context.
    ///
    /// # Safety
    ///
    /// `hToken` must be a valid token with a usable impersonation level. The
    /// caller must reliably restore its prior context, normally with
    /// [`RevertToSelf`], including on failure paths.
    pub fn ImpersonateLoggedOnUser(hToken: HANDLE) -> BOOL;

    /// Ends impersonation for the calling thread.
    ///
    /// # Safety
    ///
    /// This has no pointer preconditions, but the caller must account for the
    /// security-context change and treat failure as security-critical.
    pub fn RevertToSelf() -> BOOL;

    /// Resolves a privilege name to a locally unique identifier.
    ///
    /// # Safety
    ///
    /// The optional system and required name pointers must be readable
    /// null-terminated UTF-16 strings. `lpLuid` must be writable.
    pub fn LookupPrivilegeValueW(lpSystemName: PCWSTR, lpName: PCWSTR, lpLuid: *mut LUID) -> BOOL;

    /// Enables, disables, or removes token privileges.
    ///
    /// # Safety
    ///
    /// The token must have the required access. `NewState` must describe a
    /// readable variable-length privilege array. Optional previous-state and
    /// return-length outputs must be writable for `BufferLength` bytes.
    pub fn AdjustTokenPrivileges(
        TokenHandle: HANDLE,
        DisableAllPrivileges: BOOL,
        NewState: *const TOKEN_PRIVILEGES,
        BufferLength: u32,
        PreviousState: *mut TOKEN_PRIVILEGES,
        ReturnLength: *mut u32,
    ) -> BOOL;

    /// Retrieves one class of token information.
    ///
    /// # Safety
    ///
    /// The token must be valid. `ReturnLength` must be writable.
    /// `TokenInformation` may be null for a size query; otherwise it must be
    /// writable for `TokenInformationLength` bytes and correctly aligned for
    /// the requested class.
    pub fn GetTokenInformation(
        TokenHandle: HANDLE,
        TokenInformationClass: TOKEN_INFORMATION_CLASS,
        TokenInformation: *mut c_void,
        TokenInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> BOOL;

    /// Replaces one writable class of token information.
    ///
    /// # Safety
    ///
    /// The token must have the class-specific adjustment right, and
    /// `TokenInformation` must point to a readable, correctly aligned value of
    /// `TokenInformationLength` bytes matching the requested class.
    pub fn SetTokenInformation(
        TokenHandle: HANDLE,
        TokenInformationClass: TOKEN_INFORMATION_CLASS,
        TokenInformation: *const c_void,
        TokenInformationLength: u32,
    ) -> BOOL;

    // ---- SID helpers (winnt.h / winbase.h — all in advapi32) ----

    /// Checks whether a SID has a valid in-memory representation.
    ///
    /// # Safety
    ///
    /// `pSid` must point to readable storage large enough for the SID header
    /// and its declared sub-authorities.
    pub fn IsValidSid(pSid: PSID) -> BOOL;

    /// Returns the size in bytes of a valid SID.
    ///
    /// # Safety
    ///
    /// `pSid` must point to a readable valid SID.
    pub fn GetLengthSid(pSid: PSID) -> u32;

    /// Returns a pointer to one 32-bit subauthority in the SID's inline array.
    ///
    /// # Safety
    ///
    /// `pSid` must remain valid and writable, and `nSubAuthority` must be less
    /// than its sub-authority count. The returned pointer borrows the SID.
    pub fn GetSidSubAuthority(pSid: PSID, nSubAuthority: u32) -> *mut u32;

    /// Returns a pointer to the u8 count of subauthorities.
    ///
    /// # Safety
    ///
    /// `pSid` must remain valid and writable for the lifetime of the returned
    /// pointer, which borrows the SID storage.
    pub fn GetSidSubAuthorityCount(pSid: PSID) -> *mut u8;

    /// Returns a pointer to the SID's `SID_IDENTIFIER_AUTHORITY`.
    ///
    /// # Safety
    ///
    /// `pSid` must remain valid and writable for the lifetime of the returned
    /// pointer, which borrows the SID storage.
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
