#![cfg(all(windows, feature = "module"))]

use win32_min::foundation::{GetLastError, PCSTR, PCWSTR, PWSTR};
use win32_min::module::{
    FreeLibrary, GetModuleFileNameW, GetModuleHandleW, GetProcAddress, LoadLibraryW,
};

#[test]
fn borrowed_main_module_and_owned_kernel32_symbol_lifecycle() {
    let main = unsafe { GetModuleHandleW(PCWSTR::NULL) };
    assert!(!main.is_null());

    let mut path = vec![0u16; 32_768];
    let written = unsafe { GetModuleFileNameW(main, PWSTR(path.as_mut_ptr()), path.len() as u32) };
    assert!(written > 4, "GetModuleFileNameW: {}", unsafe {
        GetLastError()
    });
    let path = String::from_utf16(&path[..written as usize]).unwrap();
    assert!(path.to_ascii_lowercase().ends_with(".exe"), "{path}");

    let kernel32: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
    let owned = unsafe { LoadLibraryW(PCWSTR(kernel32.as_ptr())) };
    assert!(!owned.is_null(), "LoadLibraryW: {}", unsafe {
        GetLastError()
    });
    let symbol = b"GetCurrentProcessId\0";
    assert!(unsafe { GetProcAddress(owned, PCSTR(symbol.as_ptr())) }.is_some());
    assert_ne!(unsafe { FreeLibrary(owned) }, 0);
}
