//! File identity, metadata, and path primitives for security tooling.
//!
//! This module complements `std::fs`; it does not try to replace it.

use core::ffi::c_void;

use crate::foundation::{BOOL, FILETIME, HANDLE, PCWSTR, PWSTR, SECURITY_ATTRIBUTES};

/// Read access through a generic access mask.
pub const GENERIC_READ: u32 = 0x8000_0000;
/// Write access through a generic access mask.
pub const GENERIC_WRITE: u32 = 0x4000_0000;
/// Execute access through a generic access mask.
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
/// All access through a generic access mask.
pub const GENERIC_ALL: u32 = 0x1000_0000;

/// Permit other handles to read an open file.
pub const FILE_SHARE_READ: u32 = 0x0000_0001;
/// Permit other handles to write an open file.
pub const FILE_SHARE_WRITE: u32 = 0x0000_0002;
/// Permit other handles to delete or rename an open file.
pub const FILE_SHARE_DELETE: u32 = 0x0000_0004;

/// Create a new file and fail if it exists.
pub const CREATE_NEW: u32 = 1;
/// Create or overwrite a file.
pub const CREATE_ALWAYS: u32 = 2;
/// Open an existing file.
pub const OPEN_EXISTING: u32 = 3;
/// Open or create a file.
pub const OPEN_ALWAYS: u32 = 4;
/// Open and truncate an existing file.
pub const TRUNCATE_EXISTING: u32 = 5;

/// Read-only file attribute.
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
/// Hidden file attribute.
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
/// System file attribute.
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
/// Directory attribute.
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
/// Archive attribute.
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
/// Normal file attribute.
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
/// Temporary file attribute.
pub const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x0000_0100;
/// Sparse-file attribute.
pub const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x0000_0200;
/// Reparse-point attribute.
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
/// Compressed file attribute.
pub const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x0000_0800;
/// Offline file attribute.
pub const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
/// Exclude the file from content indexing.
pub const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: u32 = 0x0000_2000;
/// Encrypted file attribute.
pub const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x0000_4000;
/// Error sentinel returned by [`GetFileAttributesW`].
pub const INVALID_FILE_ATTRIBUTES: u32 = 0xffff_ffff;

/// Write changes through intermediate caches.
pub const FILE_FLAG_WRITE_THROUGH: u32 = 0x8000_0000;
/// Enable overlapped I/O.
pub const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
/// Disable system caching.
pub const FILE_FLAG_NO_BUFFERING: u32 = 0x2000_0000;
/// Hint that access will be random.
pub const FILE_FLAG_RANDOM_ACCESS: u32 = 0x1000_0000;
/// Hint that access will be sequential.
pub const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
/// Delete the file after its final handle closes.
pub const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
/// Allow opening a directory or backup-only object.
pub const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
/// Open the reparse point rather than its target.
pub const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// Avoid recalling offline data.
pub const FILE_FLAG_OPEN_NO_RECALL: u32 = 0x0010_0000;

/// Replace an existing destination during a move.
pub const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
/// Permit a copy-and-delete move across volumes.
pub const MOVEFILE_COPY_ALLOWED: u32 = 0x0000_0002;
/// Defer a move until reboot.
pub const MOVEFILE_DELAY_UNTIL_REBOOT: u32 = 0x0000_0004;
/// Flush a move before returning.
pub const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

/// Return a normalized final path.
pub const FILE_NAME_NORMALIZED: u32 = 0;
/// Return the path form used to open the handle.
pub const FILE_NAME_OPENED: u32 = 0x8;
/// Return a DOS volume path.
pub const VOLUME_NAME_DOS: u32 = 0;
/// Return a volume GUID path.
pub const VOLUME_NAME_GUID: u32 = 1;
/// Return an NT device path.
pub const VOLUME_NAME_NT: u32 = 2;
/// Return no volume prefix.
pub const VOLUME_NAME_NONE: u32 = 4;

/// Information level accepted by [`GetFileAttributesExW`].
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GET_FILEEX_INFO_LEVELS {
    /// Populate [`WIN32_FILE_ATTRIBUTE_DATA`].
    GetFileExInfoStandard = 0,
    /// Sentinel; not a valid query level.
    GetFileExMaxInfoLevel = 1,
}

/// File attributes and timestamps returned by [`GetFileAttributesExW`].
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WIN32_FILE_ATTRIBUTE_DATA {
    /// File attribute flags.
    pub dwFileAttributes: u32,
    /// Creation time.
    pub ftCreationTime: FILETIME,
    /// Last-access time.
    pub ftLastAccessTime: FILETIME,
    /// Last-write time.
    pub ftLastWriteTime: FILETIME,
    /// High 32 bits of the file size.
    pub nFileSizeHigh: u32,
    /// Low 32 bits of the file size.
    pub nFileSizeLow: u32,
}

/// Stable file identity and metadata returned for an open handle.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BY_HANDLE_FILE_INFORMATION {
    /// File attribute flags.
    pub dwFileAttributes: u32,
    /// Creation time.
    pub ftCreationTime: FILETIME,
    /// Last-access time.
    pub ftLastAccessTime: FILETIME,
    /// Last-write time.
    pub ftLastWriteTime: FILETIME,
    /// Serial number of the containing volume.
    pub dwVolumeSerialNumber: u32,
    /// High 32 bits of the file size.
    pub nFileSizeHigh: u32,
    /// Low 32 bits of the file size.
    pub nFileSizeLow: u32,
    /// Number of hard links.
    pub nNumberOfLinks: u32,
    /// High 32 bits of the file identifier.
    pub nFileIndexHigh: u32,
    /// Low 32 bits of the file identifier.
    pub nFileIndexLow: u32,
}

#[link(name = "kernel32")]
extern "system" {
    /// Opens or creates a file-system object.
    ///
    /// # Safety
    ///
    /// `lpFileName` must be null-terminated and valid for reads. Optional
    /// security attributes must remain valid for the call, and `hTemplateFile`
    /// must be null or valid. A successful handle is owned and must be closed.
    pub fn CreateFileW(
        lpFileName: PCWSTR,
        dwDesiredAccess: u32,
        dwShareMode: u32,
        lpSecurityAttributes: *const SECURITY_ATTRIBUTES,
        dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32,
        hTemplateFile: HANDLE,
    ) -> HANDLE;

    /// Retrieves file attributes for a path.
    ///
    /// # Safety
    ///
    /// `lpFileName` must point to a readable null-terminated UTF-16 string for
    /// the duration of the call.
    pub fn GetFileAttributesW(lpFileName: PCWSTR) -> u32;

    /// Retrieves file attributes and timestamps for a path.
    ///
    /// # Safety
    ///
    /// `lpFileName` must be a readable null-terminated string and
    /// `lpFileInformation` must point to writable storage appropriate for
    /// `fInfoLevelId`.
    pub fn GetFileAttributesExW(
        lpFileName: PCWSTR,
        fInfoLevelId: GET_FILEEX_INFO_LEVELS,
        lpFileInformation: *mut c_void,
    ) -> BOOL;

    /// Deletes a file by path.
    ///
    /// # Safety
    ///
    /// `lpFileName` must point to a readable null-terminated UTF-16 string.
    /// The caller is responsible for the destructive effect.
    pub fn DeleteFileW(lpFileName: PCWSTR) -> BOOL;

    /// Renames or moves a file-system object.
    ///
    /// # Safety
    ///
    /// Both path pointers must be readable null-terminated strings (the new
    /// path may be null only when the selected flags permit it). The caller is
    /// responsible for overwrite and delayed-operation effects.
    pub fn MoveFileExW(lpExistingFileName: PCWSTR, lpNewFileName: PCWSTR, dwFlags: u32) -> BOOL;

    /// Resolves the final path for an open file handle.
    ///
    /// # Safety
    ///
    /// `hFile` must be valid. `lpszFilePath` must point to writable storage for
    /// `cchFilePath` UTF-16 units, or may be null only for a documented size
    /// query. The buffer must remain valid for the call.
    pub fn GetFinalPathNameByHandleW(
        hFile: HANDLE,
        lpszFilePath: PWSTR,
        cchFilePath: u32,
        dwFlags: u32,
    ) -> u32;

    /// Retrieves metadata and identity for an open file handle.
    ///
    /// # Safety
    ///
    /// `hFile` must be valid and `lpFileInformation` must point to writable
    /// [`BY_HANDLE_FILE_INFORMATION`] storage.
    pub fn GetFileInformationByHandle(
        hFile: HANDLE,
        lpFileInformation: *mut BY_HANDLE_FILE_INFORMATION,
    ) -> BOOL;
}

const _: () = {
    assert!(core::mem::size_of::<WIN32_FILE_ATTRIBUTE_DATA>() == 36);
    assert!(core::mem::align_of::<WIN32_FILE_ATTRIBUTE_DATA>() == 4);
    assert!(core::mem::size_of::<BY_HANDLE_FILE_INFORMATION>() == 52);
    assert!(core::mem::align_of::<BY_HANDLE_FILE_INFORMATION>() == 4);
};
