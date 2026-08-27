#![cfg(windows)]

#[cfg(all(feature = "process", feature = "thread"))]
#[test]
fn opens_current_process_and_resolves_kernel32_symbols() {
    use win32_min::foundation::CloseHandle;
    use win32_min::process_thread::{
        GetCurrentProcessId, GetProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let pid = unsafe { GetCurrentProcessId() };
    assert_ne!(pid, 0);

    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    assert!(!process.is_null());
    assert_eq!(unsafe { GetProcessId(process) }, pid);
    assert_ne!(unsafe { CloseHandle(process) }, 0);
}

#[cfg(feature = "registry")]
#[test]
fn opens_current_user_registry_and_resolves_advapi32_symbols() {
    use win32_min::foundation::PCWSTR;
    use win32_min::registry::{RegCloseKey, RegOpenKeyExW, HKEY_CURRENT_USER, KEY_READ, NULL_HKEY};

    let mut key = NULL_HKEY;
    let status = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR::NULL, 0, KEY_READ, &mut key) };
    assert_eq!(status, 0);
    assert!(!key.is_null());
    assert_eq!(unsafe { RegCloseKey(key) }, 0);
}

#[cfg(feature = "security")]
#[test]
fn converts_sddl_and_resolves_security_descriptor_symbols() {
    use win32_min::foundation::PCWSTR;
    use win32_min::security_descriptor::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityDescriptorLength,
        IsValidSecurityDescriptor, LocalFree, NULL_SECURITY_DESCRIPTOR, SDDL_REVISION_1,
    };

    let sddl: Vec<u16> = "O:SYG:SYD:(A;;GA;;;SY)\0".encode_utf16().collect();
    let mut descriptor = NULL_SECURITY_DESCRIPTOR;
    let mut descriptor_len = 0;
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            &mut descriptor_len,
        )
    };
    assert_ne!(ok, 0);
    assert!(!descriptor.is_null());
    assert_ne!(unsafe { IsValidSecurityDescriptor(descriptor) }, 0);
    assert_eq!(
        unsafe { GetSecurityDescriptorLength(descriptor) },
        descriptor_len
    );
    assert!(unsafe { LocalFree(descriptor) }.is_null());
}
