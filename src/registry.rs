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

pub const NULL_HKEY: HKEY = core::ptr::null_mut();

// Predefined key handles. The intermediate i32 cast preserves the sign
// extension used by the Windows SDK macros on 64-bit targets.
pub const HKEY_CLASSES_ROOT: HKEY = 0x8000_0000u32 as i32 as isize as HKEY;
pub const HKEY_CURRENT_USER: HKEY = 0x8000_0001u32 as i32 as isize as HKEY;
pub const HKEY_LOCAL_MACHINE: HKEY = 0x8000_0002u32 as i32 as isize as HKEY;
pub const HKEY_USERS: HKEY = 0x8000_0003u32 as i32 as isize as HKEY;
pub const HKEY_PERFORMANCE_DATA: HKEY = 0x8000_0004u32 as i32 as isize as HKEY;
pub const HKEY_CURRENT_CONFIG: HKEY = 0x8000_0005u32 as i32 as isize as HKEY;

// Registry-key access rights (winnt.h).
pub const KEY_QUERY_VALUE: REGSAM = 0x0001;
pub const KEY_SET_VALUE: REGSAM = 0x0002;
pub const KEY_CREATE_SUB_KEY: REGSAM = 0x0004;
pub const KEY_ENUMERATE_SUB_KEYS: REGSAM = 0x0008;
pub const KEY_NOTIFY: REGSAM = 0x0010;
pub const KEY_CREATE_LINK: REGSAM = 0x0020;
pub const KEY_WOW64_64KEY: REGSAM = 0x0100;
pub const KEY_WOW64_32KEY: REGSAM = 0x0200;
pub const KEY_WOW64_RES: REGSAM = 0x0300;
pub const KEY_READ: REGSAM = 0x0002_0019;
pub const KEY_WRITE: REGSAM = 0x0002_0006;
pub const KEY_EXECUTE: REGSAM = KEY_READ;
pub const KEY_ALL_ACCESS: REGSAM = 0x000f_003f;

// Registry value types (winnt.h).
pub const REG_NONE: u32 = 0;
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_DWORD_LITTLE_ENDIAN: u32 = 4;
pub const REG_DWORD_BIG_ENDIAN: u32 = 5;
pub const REG_LINK: u32 = 6;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_RESOURCE_LIST: u32 = 8;
pub const REG_FULL_RESOURCE_DESCRIPTOR: u32 = 9;
pub const REG_RESOURCE_REQUIREMENTS_LIST: u32 = 10;
pub const REG_QWORD: u32 = 11;

pub const REG_OPTION_NON_VOLATILE: u32 = 0;
pub const REG_OPTION_VOLATILE: u32 = 1;
pub const REG_CREATED_NEW_KEY: u32 = 1;
pub const REG_OPENED_EXISTING_KEY: u32 = 2;

#[link(name = "advapi32")]
extern "system" {
    pub fn RegOpenKeyExW(
        hKey: HKEY,
        lpSubKey: PCWSTR,
        ulOptions: u32,
        samDesired: REGSAM,
        phkResult: *mut HKEY,
    ) -> LSTATUS;

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

    pub fn RegCloseKey(hKey: HKEY) -> LSTATUS;

    pub fn RegQueryValueExW(
        hKey: HKEY,
        lpValueName: PCWSTR,
        lpReserved: *mut u32,
        lpType: *mut u32,
        lpData: *mut u8,
        lpcbData: *mut u32,
    ) -> LSTATUS;

    pub fn RegSetValueExW(
        hKey: HKEY,
        lpValueName: PCWSTR,
        Reserved: u32,
        dwType: u32,
        lpData: *const u8,
        cbData: u32,
    ) -> LSTATUS;

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

    pub fn RegDeleteValueW(hKey: HKEY, lpValueName: PCWSTR) -> LSTATUS;
    pub fn RegDeleteKeyExW(
        hKey: HKEY,
        lpSubKey: PCWSTR,
        samDesired: REGSAM,
        Reserved: u32,
    ) -> LSTATUS;
    pub fn RegFlushKey(hKey: HKEY) -> LSTATUS;
}
