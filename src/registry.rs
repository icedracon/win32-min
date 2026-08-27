//! Feature `registry` — minimal local Windows Registry surface.
//!
//! Covers opening, creating, querying, enumerating, updating, and closing keys.
//! Remote-registry and transaction APIs remain out of scope until a consumer
//! needs them.

use crate::foundation::{FILETIME, LSTATUS, PCWSTR, PWSTR, SECURITY_ATTRIBUTES};
use core::ffi::c_void;

/// Opaque registry-key handle.
pub type HKEY = *mut c_void;
/// Registry access mask.
pub type REGSAM = u32;

/// Null registry-key handle.
pub const NULL_HKEY: HKEY = core::ptr::null_mut();

// Predefined key handles. The intermediate i32 cast preserves the sign
// extension used by the Windows SDK macros on 64-bit targets.
/// Predefined handle for per-file-type and COM registration data.
pub const HKEY_CLASSES_ROOT: HKEY = 0x8000_0000u32 as i32 as isize as HKEY;
/// Predefined handle for the calling user's profile.
pub const HKEY_CURRENT_USER: HKEY = 0x8000_0001u32 as i32 as isize as HKEY;
/// Predefined handle for machine-wide configuration.
pub const HKEY_LOCAL_MACHINE: HKEY = 0x8000_0002u32 as i32 as isize as HKEY;
/// Predefined handle for loaded user profiles.
pub const HKEY_USERS: HKEY = 0x8000_0003u32 as i32 as isize as HKEY;
/// Predefined handle for performance data.
pub const HKEY_PERFORMANCE_DATA: HKEY = 0x8000_0004u32 as i32 as isize as HKEY;
/// Predefined handle for current hardware-profile configuration.
pub const HKEY_CURRENT_CONFIG: HKEY = 0x8000_0005u32 as i32 as isize as HKEY;

// Registry-key access rights (winnt.h).
/// Permission to query key values.
pub const KEY_QUERY_VALUE: REGSAM = 0x0001;
/// Permission to set key values.
pub const KEY_SET_VALUE: REGSAM = 0x0002;
/// Permission to create subkeys.
pub const KEY_CREATE_SUB_KEY: REGSAM = 0x0004;
/// Permission to enumerate subkeys.
pub const KEY_ENUMERATE_SUB_KEYS: REGSAM = 0x0008;
/// Permission to request change notifications.
pub const KEY_NOTIFY: REGSAM = 0x0010;
/// Permission to create symbolic-link keys.
pub const KEY_CREATE_LINK: REGSAM = 0x0020;
/// Select the 64-bit registry view.
pub const KEY_WOW64_64KEY: REGSAM = 0x0100;
/// Select the 32-bit registry view.
pub const KEY_WOW64_32KEY: REGSAM = 0x0200;
/// Mask of registry-view selector bits.
pub const KEY_WOW64_RES: REGSAM = 0x0300;
/// Standard read permissions for a key.
pub const KEY_READ: REGSAM = 0x0002_0019;
/// Standard write permissions for a key.
pub const KEY_WRITE: REGSAM = 0x0002_0006;
/// Standard execute permissions for a key.
pub const KEY_EXECUTE: REGSAM = KEY_READ;
/// All key-specific and standard permissions.
pub const KEY_ALL_ACCESS: REGSAM = 0x000f_003f;

// Registry value types (winnt.h).
/// Value data with no defined type.
pub const REG_NONE: u32 = 0;
/// Null-terminated UTF-16 string value.
pub const REG_SZ: u32 = 1;
/// Expandable null-terminated UTF-16 string value.
pub const REG_EXPAND_SZ: u32 = 2;
/// Arbitrary binary value.
pub const REG_BINARY: u32 = 3;
/// Little-endian 32-bit integer value.
pub const REG_DWORD: u32 = 4;
/// Explicit alias for a little-endian 32-bit integer value.
pub const REG_DWORD_LITTLE_ENDIAN: u32 = 4;
/// Big-endian 32-bit integer value.
pub const REG_DWORD_BIG_ENDIAN: u32 = 5;
/// Registry symbolic-link target.
pub const REG_LINK: u32 = 6;
/// Sequence of null-terminated UTF-16 strings terminated by an extra null.
pub const REG_MULTI_SZ: u32 = 7;
/// Resource-list value.
pub const REG_RESOURCE_LIST: u32 = 8;
/// Full resource-descriptor value.
pub const REG_FULL_RESOURCE_DESCRIPTOR: u32 = 9;
/// Resource-requirements-list value.
pub const REG_RESOURCE_REQUIREMENTS_LIST: u32 = 10;
/// Little-endian 64-bit integer value.
pub const REG_QWORD: u32 = 11;

/// Create a key persisted to the registry backing store.
pub const REG_OPTION_NON_VOLATILE: u32 = 0;
/// Create an in-memory key discarded at shutdown.
pub const REG_OPTION_VOLATILE: u32 = 1;
/// Disposition indicating that `RegCreateKeyExW` created a key.
pub const REG_CREATED_NEW_KEY: u32 = 1;
/// Disposition indicating that `RegCreateKeyExW` opened an existing key.
pub const REG_OPENED_EXISTING_KEY: u32 = 2;

#[link(name = "advapi32")]
extern "system" {
    /// Opens a registry key.
    ///
    /// # Safety
    ///
    /// `hKey` must be valid, `lpSubKey` must be null or a readable
    /// null-terminated UTF-16 string, and `phkResult` must point to writable
    /// handle storage. A successful output handle is owned and must be closed.
    pub fn RegOpenKeyExW(
        hKey: HKEY,
        lpSubKey: PCWSTR,
        ulOptions: u32,
        samDesired: REGSAM,
        phkResult: *mut HKEY,
    ) -> LSTATUS;

    /// Creates or opens a registry key.
    ///
    /// # Safety
    ///
    /// The parent and string pointers must be valid for the call. Optional
    /// security attributes must be readable. `phkResult` must be writable and
    /// `lpdwDisposition` may be null or writable. The output key is owned.
    pub fn RegCreateKeyExW(
        hKey: HKEY,
        lpSubKey: PCWSTR,
        Reserved: u32,
        lpClass: PWSTR,
        dwOptions: u32,
        samDesired: REGSAM,
        lpSecurityAttributes: *const SECURITY_ATTRIBUTES,
        phkResult: *mut HKEY,
        lpdwDisposition: *mut u32,
    ) -> LSTATUS;

    /// Closes an owned registry key.
    ///
    /// # Safety
    ///
    /// `hKey` must be a valid, uniquely owned closeable key and must not have
    /// been closed previously. Predefined `HKEY_*` values need not be closed.
    pub fn RegCloseKey(hKey: HKEY) -> LSTATUS;

    /// Queries the type, size, or bytes of a registry value.
    ///
    /// # Safety
    ///
    /// The key and value-name pointer must be valid. `lpReserved` must be null.
    /// Each non-null output must be writable; `lpData` must provide at least
    /// the input byte count in `*lpcbData`, which is updated on return.
    pub fn RegQueryValueExW(
        hKey: HKEY,
        lpValueName: PCWSTR,
        lpReserved: *mut u32,
        lpType: *mut u32,
        lpData: *mut u8,
        lpcbData: *mut u32,
    ) -> LSTATUS;

    /// Creates or replaces a registry value.
    ///
    /// # Safety
    ///
    /// The key and value name must be valid, `Reserved` must be zero, and
    /// `lpData` must be null for zero bytes or readable for `cbData` bytes. The
    /// byte representation must match `dwType`.
    pub fn RegSetValueExW(
        hKey: HKEY,
        lpValueName: PCWSTR,
        Reserved: u32,
        dwType: u32,
        lpData: *const u8,
        cbData: u32,
    ) -> LSTATUS;

    /// Enumerates a subkey name and optional metadata.
    ///
    /// # Safety
    ///
    /// The key must be valid. `lpName` must have the UTF-16 capacity supplied
    /// by writable `lpcchName`. Every other non-null output pointer must be
    /// valid for its documented type and buffer size.
    pub fn RegEnumKeyExW(
        hKey: HKEY,
        dwIndex: u32,
        lpName: PWSTR,
        lpcchName: *mut u32,
        lpReserved: *mut u32,
        lpClass: PWSTR,
        lpcchClass: *mut u32,
        lpftLastWriteTime: *mut FILETIME,
    ) -> LSTATUS;

    /// Enumerates a value name, type, and optional data.
    ///
    /// # Safety
    ///
    /// The key must be valid. The name and data buffers must have the
    /// capacities supplied through their writable length pointers. Optional
    /// scalar outputs must be writable; `lpReserved` must be null.
    pub fn RegEnumValueW(
        hKey: HKEY,
        dwIndex: u32,
        lpValueName: PWSTR,
        lpcchValueName: *mut u32,
        lpReserved: *mut u32,
        lpType: *mut u32,
        lpData: *mut u8,
        lpcbData: *mut u32,
    ) -> LSTATUS;

    /// Retrieves key metadata and maximum child/value buffer sizes.
    ///
    /// # Safety
    ///
    /// `hKey` must be valid. Every non-null output pointer must remain writable
    /// for the call. `lpClass` must have the UTF-16 capacity supplied through
    /// `lpcchClass`; all other size/count pointers address one `u32`, and the
    /// optional timestamp points to one writable [`FILETIME`].
    pub fn RegQueryInfoKeyW(
        hKey: HKEY,
        lpClass: PWSTR,
        lpcchClass: *mut u32,
        lpReserved: *mut u32,
        lpcSubKeys: *mut u32,
        lpcbMaxSubKeyLen: *mut u32,
        lpcbMaxClassLen: *mut u32,
        lpcValues: *mut u32,
        lpcbMaxValueNameLen: *mut u32,
        lpcbMaxValueLen: *mut u32,
        lpcbSecurityDescriptor: *mut u32,
        lpftLastWriteTime: *mut FILETIME,
    ) -> LSTATUS;

    /// Deletes a registry value.
    ///
    /// # Safety
    ///
    /// `hKey` must have set-value access and `lpValueName` must point to a
    /// readable null-terminated UTF-16 value name. The deletion is immediate.
    pub fn RegDeleteValueW(hKey: HKEY, lpValueName: PCWSTR) -> LSTATUS;

    /// Deletes a subkey from a selected registry view.
    ///
    /// # Safety
    ///
    /// The parent and null-terminated subkey name must be valid, `Reserved`
    /// must be zero, and the caller is responsible for the destructive effect.
    pub fn RegDeleteKeyExW(
        hKey: HKEY,
        lpSubKey: PCWSTR,
        samDesired: REGSAM,
        Reserved: u32,
    ) -> LSTATUS;

    /// Flushes pending changes for a registry key to disk.
    ///
    /// # Safety
    ///
    /// `hKey` must be a valid key handle and remain valid for the call.
    pub fn RegFlushKey(hKey: HKEY) -> LSTATUS;
}
