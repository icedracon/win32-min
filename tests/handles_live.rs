#![cfg(all(
    windows,
    feature = "process",
    feature = "thread",
    feature = "security-token",
    feature = "registry",
    feature = "services"
))]

use win32_min::foundation::SetLastError;
use win32_min::handles::{
    Handle, ProcessHandle, RegistryKey, ServiceHandle, ThreadHandle, TokenHandle,
};
use win32_min::process::{GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
use win32_min::registry::KEY_READ;
use win32_min::security_token::TOKEN_QUERY;
use win32_min::services::SC_MANAGER_CONNECT;
use win32_min::thread::{GetCurrentThreadId, THREAD_QUERY_LIMITED_INFORMATION};
use win32_min::Win32Error;

#[test]
fn win32_error_captures_code_and_formats_without_allocation() {
    unsafe { SetLastError(2) };
    let error = Win32Error::last();
    assert_eq!(error.code(), 2);
    assert_eq!(error.raw(), 2);
    let mut buffer = [0u16; 256];
    let message = error.message(&mut buffer).unwrap();
    assert!(!message.is_empty());
    assert!(format!("{error}").contains("Win32 error 2"));
}

#[test]
fn typed_handle_open_raw_transfer_and_subsystem_closers() {
    let pid = unsafe { GetCurrentProcessId() };
    let process = ProcessHandle::open(pid, PROCESS_QUERY_LIMITED_INFORMATION, false).unwrap();
    assert!(process.is_valid());
    assert_eq!(process.id().unwrap(), pid);

    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    assert!(!raw.is_null());
    let generic = unsafe { Handle::from_raw(raw) };
    let raw = generic.into_raw();
    assert!(!raw.is_null());
    drop(unsafe { Handle::from_raw(raw) });

    let thread = ThreadHandle::open(
        unsafe { GetCurrentThreadId() },
        THREAD_QUERY_LIMITED_INFORMATION,
        false,
    )
    .unwrap();
    assert!(thread.is_valid());
    assert_eq!(thread.id().unwrap(), unsafe { GetCurrentThreadId() });

    let token = TokenHandle::open(&process, TOKEN_QUERY).unwrap();
    assert!(token.is_valid());

    let software: Vec<u16> = "Software\0".encode_utf16().collect();
    let registry = RegistryKey::open_current_user(&software, KEY_READ).unwrap();
    assert!(registry.is_valid());

    let manager = ServiceHandle::open_manager(SC_MANAGER_CONNECT).unwrap();
    assert!(manager.is_valid());
}
