#![cfg(all(windows, feature = "registry"))]

use std::mem::size_of;
use std::time::{SystemTime, UNIX_EPOCH};

use win32_min::foundation::{PCWSTR, PWSTR};
use win32_min::registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyExW, RegDeleteValueW, RegEnumKeyExW, RegEnumValueW,
    RegFlushKey, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
    KEY_ALL_ACCESS, NULL_HKEY, REG_CREATED_NEW_KEY, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ,
};

const ERROR_SUCCESS: i32 = 0;
const ERROR_NO_MORE_ITEMS: i32 = 259;

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

struct RegistryCleanup {
    root_path: Vec<u16>,
    parent: HKEY,
    child: HKEY,
    root_deleted: bool,
}

impl Drop for RegistryCleanup {
    fn drop(&mut self) {
        unsafe {
            if !self.child.is_null() {
                let _ = RegCloseKey(self.child);
                self.child = NULL_HKEY;
            }
            if !self.parent.is_null() {
                let child_name = wide("child");
                let _ = RegDeleteKeyExW(self.parent, PCWSTR(child_name.as_ptr()), 0, 0);
                let _ = RegCloseKey(self.parent);
                self.parent = NULL_HKEY;
            }
            if !self.root_deleted {
                let _ = RegDeleteKeyExW(HKEY_CURRENT_USER, PCWSTR(self.root_path.as_ptr()), 0, 0);
            }
        }
    }
}

#[test]
fn temporary_registry_key_full_lifecycle() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_path = wide(&format!(
        "Software\\win32-min-test-{}-{unique}",
        std::process::id()
    ));
    let mut cleanup = RegistryCleanup {
        root_path,
        parent: NULL_HKEY,
        child: NULL_HKEY,
        root_deleted: false,
    };

    let mut disposition = 0u32;
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(cleanup.root_path.as_ptr()),
            0,
            PWSTR::NULL,
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            std::ptr::null(),
            &mut cleanup.parent,
            &mut disposition,
        )
    };
    assert_eq!(status, ERROR_SUCCESS);
    assert_eq!(disposition, REG_CREATED_NEW_KEY);
    assert!(!cleanup.parent.is_null());

    let dword_name = wide("Answer");
    let dword_value = 0x1234_5678u32;
    assert_eq!(
        unsafe {
            RegSetValueExW(
                cleanup.parent,
                PCWSTR(dword_name.as_ptr()),
                0,
                REG_DWORD,
                &dword_value as *const u32 as *const u8,
                size_of::<u32>() as u32,
            )
        },
        ERROR_SUCCESS
    );

    let string_name = wide("Label");
    let string_value = wide("win32-min");
    assert_eq!(
        unsafe {
            RegSetValueExW(
                cleanup.parent,
                PCWSTR(string_name.as_ptr()),
                0,
                REG_SZ,
                string_value.as_ptr() as *const u8,
                (string_value.len() * size_of::<u16>()) as u32,
            )
        },
        ERROR_SUCCESS
    );
    assert_eq!(unsafe { RegFlushKey(cleanup.parent) }, ERROR_SUCCESS);

    let mut value_type = 0u32;
    let mut value_size = 0u32;
    assert_eq!(
        unsafe {
            RegQueryValueExW(
                cleanup.parent,
                PCWSTR(dword_name.as_ptr()),
                std::ptr::null_mut(),
                &mut value_type,
                std::ptr::null_mut(),
                &mut value_size,
            )
        },
        ERROR_SUCCESS
    );
    assert_eq!(value_type, REG_DWORD);
    assert_eq!(value_size, size_of::<u32>() as u32);

    let mut queried_dword = 0u32;
    assert_eq!(
        unsafe {
            RegQueryValueExW(
                cleanup.parent,
                PCWSTR(dword_name.as_ptr()),
                std::ptr::null_mut(),
                &mut value_type,
                &mut queried_dword as *mut u32 as *mut u8,
                &mut value_size,
            )
        },
        ERROR_SUCCESS
    );
    assert_eq!(queried_dword, dword_value);

    let mut enumerated_values = Vec::new();
    for index in 0.. {
        let mut name = [0u16; 256];
        let mut name_len = name.len() as u32;
        let mut data_type = 0u32;
        let mut data_len = 0u32;
        let status = unsafe {
            RegEnumValueW(
                cleanup.parent,
                index,
                PWSTR(name.as_mut_ptr()),
                &mut name_len,
                std::ptr::null_mut(),
                &mut data_type,
                std::ptr::null_mut(),
                &mut data_len,
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        assert_eq!(status, ERROR_SUCCESS);
        enumerated_values.push(String::from_utf16(&name[..name_len as usize]).unwrap());
    }
    enumerated_values.sort();
    assert_eq!(enumerated_values, ["Answer", "Label"]);

    let child_name = wide("child");
    assert_eq!(
        unsafe {
            RegCreateKeyExW(
                cleanup.parent,
                PCWSTR(child_name.as_ptr()),
                0,
                PWSTR::NULL,
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS,
                std::ptr::null(),
                &mut cleanup.child,
                &mut disposition,
            )
        },
        ERROR_SUCCESS
    );

    let mut child_buffer = [0u16; 256];
    let mut child_len = child_buffer.len() as u32;
    assert_eq!(
        unsafe {
            RegEnumKeyExW(
                cleanup.parent,
                0,
                PWSTR(child_buffer.as_mut_ptr()),
                &mut child_len,
                std::ptr::null_mut(),
                PWSTR::NULL,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        ERROR_SUCCESS
    );
    assert_eq!(
        String::from_utf16(&child_buffer[..child_len as usize]).unwrap(),
        "child"
    );

    let mut reopened = NULL_HKEY;
    assert_eq!(
        unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(cleanup.root_path.as_ptr()),
                0,
                KEY_ALL_ACCESS,
                &mut reopened,
            )
        },
        ERROR_SUCCESS
    );
    assert!(!reopened.is_null());
    assert_eq!(unsafe { RegCloseKey(reopened) }, ERROR_SUCCESS);

    assert_eq!(unsafe { RegCloseKey(cleanup.child) }, ERROR_SUCCESS);
    cleanup.child = NULL_HKEY;
    assert_eq!(
        unsafe { RegDeleteKeyExW(cleanup.parent, PCWSTR(child_name.as_ptr()), 0, 0) },
        ERROR_SUCCESS
    );
    assert_eq!(
        unsafe { RegDeleteValueW(cleanup.parent, PCWSTR(dword_name.as_ptr())) },
        ERROR_SUCCESS
    );
    assert_eq!(
        unsafe { RegDeleteValueW(cleanup.parent, PCWSTR(string_name.as_ptr())) },
        ERROR_SUCCESS
    );

    assert_eq!(unsafe { RegCloseKey(cleanup.parent) }, ERROR_SUCCESS);
    cleanup.parent = NULL_HKEY;
    assert_eq!(
        unsafe { RegDeleteKeyExW(HKEY_CURRENT_USER, PCWSTR(cleanup.root_path.as_ptr()), 0, 0,) },
        ERROR_SUCCESS
    );
    cleanup.root_deleted = true;
}
