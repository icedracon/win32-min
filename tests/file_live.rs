#![cfg(all(windows, feature = "file"))]

use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use win32_min::file::{
    CreateFileW, DeleteFileW, GetFileAttributesExW, GetFileAttributesW, GetFileInformationByHandle,
    GetFinalPathNameByHandleW, MoveFileExW, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_NORMAL,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE,
    GET_FILEEX_INFO_LEVELS, OPEN_EXISTING, WIN32_FILE_ATTRIBUTE_DATA,
};
use win32_min::foundation::{GetLastError, INVALID_HANDLE_VALUE, PCWSTR, PWSTR};
use win32_min::handles::Handle;

fn wide_path(path: &std::path::Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

struct Cleanup {
    paths: Vec<PathBuf>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for path in &self.paths {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[test]
fn temporary_file_identity_path_metadata_move_and_delete() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let original = std::env::temp_dir().join(format!(
        "win32-min-file-{}-{unique}.tmp",
        std::process::id()
    ));
    let moved = original.with_extension("moved.tmp");
    std::fs::write(&original, b"win32-min file lifecycle").unwrap();
    let _cleanup = Cleanup {
        paths: vec![original.clone(), moved.clone()],
    };
    let original_wide = wide_path(&original);

    let attributes = unsafe { GetFileAttributesW(PCWSTR(original_wide.as_ptr())) };
    assert_ne!(attributes, u32::MAX, "GetFileAttributesW: {}", unsafe {
        GetLastError()
    });

    let mut attribute_data: WIN32_FILE_ATTRIBUTE_DATA = unsafe { core::mem::zeroed() };
    assert_ne!(
        unsafe {
            GetFileAttributesExW(
                PCWSTR(original_wide.as_ptr()),
                GET_FILEEX_INFO_LEVELS::GetFileExInfoStandard,
                (&mut attribute_data as *mut WIN32_FILE_ATTRIBUTE_DATA).cast(),
            )
        },
        0
    );
    assert_eq!(attribute_data.dwFileAttributes, attributes);
    assert_eq!(attribute_data.nFileSizeLow, 24);

    let raw = unsafe {
        CreateFileW(
            PCWSTR(original_wide.as_ptr()),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            core::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            core::ptr::null_mut(),
        )
    };
    assert_ne!(raw, INVALID_HANDLE_VALUE, "CreateFileW: {}", unsafe {
        GetLastError()
    });
    let handle = unsafe { Handle::from_raw(raw) };

    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { core::mem::zeroed() };
    assert_ne!(
        unsafe { GetFileInformationByHandle(handle.raw(), &mut information) },
        0
    );
    assert_ne!(information.dwVolumeSerialNumber, 0);
    assert_eq!(information.nFileSizeLow, 24);

    let required = unsafe { GetFinalPathNameByHandleW(handle.raw(), PWSTR::NULL, 0, 0) } as usize;
    assert!(required > 4);
    let mut resolved = vec![0u16; required];
    let written = unsafe {
        GetFinalPathNameByHandleW(
            handle.raw(),
            PWSTR(resolved.as_mut_ptr()),
            resolved.len() as u32,
            0,
        )
    } as usize;
    assert!(written > 4 && written < resolved.len());
    let resolved = String::from_utf16(&resolved[..written]).unwrap();
    assert!(
        resolved.to_ascii_lowercase().ends_with(".tmp"),
        "{resolved}"
    );
    drop(handle);

    let moved_wide = wide_path(&moved);
    assert_ne!(
        unsafe {
            MoveFileExW(
                PCWSTR(original_wide.as_ptr()),
                PCWSTR(moved_wide.as_ptr()),
                0,
            )
        },
        0
    );
    assert_ne!(
        unsafe { GetFileAttributesW(PCWSTR(moved_wide.as_ptr())) },
        u32::MAX
    );
    assert_ne!(unsafe { DeleteFileW(PCWSTR(moved_wide.as_ptr())) }, 0);
    assert!(!moved.exists());
}
