#![cfg(all(windows, feature = "security-descriptor"))]

use std::fs::{File, OpenOptions};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use win32_min::foundation::{HANDLE, PCWSTR, PWSTR};
use win32_min::security_descriptor::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
    GetSecurityDescriptorLength, GetSecurityInfo, IsValidSecurityDescriptor, LocalFree,
    SetNamedSecurityInfoW, SetSecurityInfo, DACL_SECURITY_INFORMATION, NULL_SECURITY_DESCRIPTOR,
    SDDL_REVISION_1, SE_OBJECT_TYPE,
};

const ERROR_SUCCESS: u32 = 0;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

struct TempFileCleanup(PathBuf);

impl Drop for TempFileCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn sddl_conversion_round_trip_and_local_free() {
    let sddl = wide("O:SYG:SYD:(A;;GR;;;WD)");
    let mut descriptor = NULL_SECURITY_DESCRIPTOR;
    let mut descriptor_len = 0u32;
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                &mut descriptor_len,
            )
        },
        0
    );
    assert!(!descriptor.is_null());
    assert_ne!(unsafe { IsValidSecurityDescriptor(descriptor) }, 0);
    assert_eq!(
        unsafe { GetSecurityDescriptorLength(descriptor) },
        descriptor_len
    );

    let mut rendered = PWSTR::NULL;
    let mut rendered_len = 0u32;
    assert_ne!(
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut rendered,
                &mut rendered_len,
            )
        },
        0
    );
    assert!(!rendered.0.is_null());
    assert!(rendered_len > 0);
    let rendered_slice = unsafe { std::slice::from_raw_parts(rendered.0, rendered_len as usize) };
    let rendered_text = String::from_utf16_lossy(rendered_slice)
        .trim_end_matches('\0')
        .to_owned();
    assert!(rendered_text.starts_with("D:"), "{rendered_text}");
    assert!(rendered_text.contains("WD"), "{rendered_text}");

    assert!(unsafe { LocalFree(rendered.0.cast()) }.is_null());
    assert!(unsafe { LocalFree(descriptor) }.is_null());
}

#[test]
fn temporary_file_named_and_handle_security_round_trip() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "win32-min-security-{}-{unique}.tmp",
        std::process::id()
    ));
    File::create(&path).expect("create isolated temporary file");
    let _cleanup = TempFileCleanup(path.clone());

    let file = OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(&path)
        .expect("reopen temporary file with security access");

    let mut path_wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut named_dacl = std::ptr::null_mut();
    let mut named_descriptor = NULL_SECURITY_DESCRIPTOR;
    assert_eq!(
        unsafe {
            GetNamedSecurityInfoW(
                PWSTR(path_wide.as_mut_ptr()),
                SE_OBJECT_TYPE::SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut named_dacl,
                std::ptr::null_mut(),
                &mut named_descriptor,
            )
        },
        ERROR_SUCCESS
    );
    assert!(!named_descriptor.is_null());
    assert!(!named_dacl.is_null());
    assert_ne!(unsafe { IsValidSecurityDescriptor(named_descriptor) }, 0);
    assert_eq!(
        unsafe {
            SetNamedSecurityInfoW(
                PWSTR(path_wide.as_mut_ptr()),
                SE_OBJECT_TYPE::SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                named_dacl,
                std::ptr::null_mut(),
            )
        },
        ERROR_SUCCESS
    );
    assert!(unsafe { LocalFree(named_descriptor) }.is_null());

    let handle = file.as_raw_handle() as HANDLE;
    let mut handle_dacl = std::ptr::null_mut();
    let mut handle_descriptor = NULL_SECURITY_DESCRIPTOR;
    assert_eq!(
        unsafe {
            GetSecurityInfo(
                handle,
                SE_OBJECT_TYPE::SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut handle_dacl,
                std::ptr::null_mut(),
                &mut handle_descriptor,
            )
        },
        ERROR_SUCCESS
    );
    assert!(!handle_descriptor.is_null());
    assert!(!handle_dacl.is_null());
    assert_ne!(unsafe { IsValidSecurityDescriptor(handle_descriptor) }, 0);
    assert_eq!(
        unsafe {
            SetSecurityInfo(
                handle,
                SE_OBJECT_TYPE::SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                handle_dacl,
                std::ptr::null_mut(),
            )
        },
        ERROR_SUCCESS
    );
    assert!(unsafe { LocalFree(handle_descriptor) }.is_null());
}
