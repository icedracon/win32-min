//! Foundation types + a handful of always-linked functions.
//!
//! Shared vocabulary for every other subsystem module. Kept in sync with
//! the Win32 headers as of Windows 10 build 22621 (same ABI as Windows 11 +
//! Server 2016/2019/2022/2025 — Microsoft's stable-ABI guarantee).

use core::ffi::c_void;

/// Opaque Win32 handle (`HANDLE` in wincrypt.h / winnt.h). Nullable via [`INVALID_HANDLE_VALUE`]
/// (== `-1isize as *mut c_void`) or `null`.
pub type HANDLE = *mut c_void;

/// `INVALID_HANDLE_VALUE` per WINNT.H.
pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

/// `TRUE` per WINDEF.H (`BOOL` is `i32`).
pub const TRUE: BOOL = 1;
/// `FALSE` per WINDEF.H.
pub const FALSE: BOOL = 0;

/// `BOOL` — Win32's 32-bit truth type (not `bool`).
pub type BOOL = i32;

/// `NTSTATUS` — LSA / NT-kernel status code.
pub type NTSTATUS = i32;

/// `STATUS_SUCCESS`.
pub const STATUS_SUCCESS: NTSTATUS = 0;

/// `HRESULT` — COM status code.
pub type HRESULT = i32;

/// `LSTATUS` — signed Win32 status returned by registry APIs.
pub type LSTATUS = i32;

/// Locally-unique identifier (`LUID` in ntdef.h) — 64-bit ID unique within a boot session.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LUID {
    pub LowPart: u32,
    pub HighPart: i32,
}

/// `UNICODE_STRING` — the LSA / NT-kernel counted UTF-16 string.
/// `Length` and `MaximumLength` are BYTE counts (not wchar counts).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

impl UNICODE_STRING {
    /// Maximum UTF-16 code units representable by `UNICODE_STRING::Length`.
    pub const MAX_CODE_UNITS: usize = u16::MAX as usize / 2;

    /// Build a checked `UNICODE_STRING` view over a UTF-16 slice.
    ///
    /// Returns `None` when the byte length cannot be represented by the Win32
    /// `u16` length fields.
    pub fn try_from_slice(slice: &mut [u16]) -> Option<Self> {
        let len_bytes = slice.len().checked_mul(core::mem::size_of::<u16>())?;
        let len_bytes = u16::try_from(len_bytes).ok()?;
        Some(Self {
            Length: len_bytes,
            MaximumLength: len_bytes,
            Buffer: slice.as_mut_ptr(),
        })
    }

    /// Build a `UNICODE_STRING` view over a UTF-16 slice. Caller keeps the slice
    /// alive for the lifetime of the returned struct.
    ///
    /// # Panics
    ///
    /// Panics when the slice is longer than [`Self::MAX_CODE_UNITS`]. Use
    /// [`Self::try_from_slice`] for fallible construction.
    pub fn from_slice(slice: &mut [u16]) -> Self {
        Self::try_from_slice(slice).expect("UNICODE_STRING byte length exceeds u16::MAX")
    }
}

/// `FILETIME` — a 64-bit count split into two 32-bit words.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FILETIME {
    pub dwLowDateTime: u32,
    pub dwHighDateTime: u32,
}

/// `SECURITY_ATTRIBUTES` used by object-creation APIs.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SECURITY_ATTRIBUTES {
    pub nLength: u32,
    pub lpSecurityDescriptor: *mut c_void,
    pub bInheritHandle: BOOL,
}

/// `LARGE_INTEGER` (union type in C; we use the 64-bit signed variant).
pub type LARGE_INTEGER = i64;

/// Pointer to a null-terminated UTF-16 string (Win32 `LPCWSTR` / `PCWSTR`).
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct PCWSTR(pub *const u16);

impl PCWSTR {
    /// Null pointer (no string).
    pub const NULL: Self = PCWSTR(core::ptr::null());
}

/// Pointer to a mutable null-terminated UTF-16 string (Win32 `LPWSTR` / `PWSTR`).
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct PWSTR(pub *mut u16);

impl PWSTR {
    pub const NULL: Self = PWSTR(core::ptr::null_mut());
}

/// Pointer to a null-terminated ANSI string (Win32 `LPSTR` / `PSTR`).
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct PSTR(pub *mut u8);

impl PSTR {
    pub const NULL: Self = PSTR(core::ptr::null_mut());
}

/// `GUID` — 128-bit interface / class ID.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GUID {
    pub Data1: u32,
    pub Data2: u16,
    pub Data3: u16,
    pub Data4: [u8; 8],
}

// ---- Foundation functions (always linked) --------------------------------

#[link(name = "kernel32")]
extern "system" {
    /// Close a Win32 kernel object handle.
    pub fn CloseHandle(hObject: HANDLE) -> BOOL;

    /// `GetLastError` — thread-local Win32 error code from the last failing call.
    pub fn GetLastError() -> u32;

    /// `SetLastError` — mostly used in error-path composition.
    pub fn SetLastError(dwErrCode: u32);
}

// ---- Compile-time layout assertions ----------------------------------------

#[cfg(target_pointer_width = "64")]
const _: () = {
    // LUID: u32(4) + i32(4) = 8
    assert!(core::mem::size_of::<LUID>() == 8);
    // UNICODE_STRING: u16(2) + u16(2) + pad(4) + *mut u16(8) = 16
    assert!(core::mem::size_of::<UNICODE_STRING>() == 16);
    // GUID: u32(4) + u16(2) + u16(2) + [u8;8] = 16
    assert!(core::mem::size_of::<GUID>() == 16);
    assert!(core::mem::size_of::<FILETIME>() == 8);
    assert!(core::mem::size_of::<SECURITY_ATTRIBUTES>() == 24);
};

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::size_of::<LUID>() == 8);
    assert!(core::mem::size_of::<UNICODE_STRING>() == 8);
    assert!(core::mem::size_of::<GUID>() == 16);
    assert!(core::mem::size_of::<FILETIME>() == 8);
    assert!(core::mem::size_of::<SECURITY_ATTRIBUTES>() == 12);
};
