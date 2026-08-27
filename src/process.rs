//! Process discovery and inspection primitives.
//!
//! The surface follows the security-tool workflow from PID to process handle,
//! image path, and process token. Remote-memory and injection APIs remain out
//! of scope.

use crate::foundation::{BOOL, HANDLE, PWSTR};

/// Process access-mask type.
pub type PROCESS_ACCESS = u32;

/// Maximum legacy Win32 path length used by [`PROCESSENTRY32W`].
pub const MAX_PATH: usize = 260;

/// Permission to terminate a process.
pub const PROCESS_TERMINATE: PROCESS_ACCESS = 0x0001;
/// Permission to create a thread in a process.
pub const PROCESS_CREATE_THREAD: PROCESS_ACCESS = 0x0002;
/// Reserved process session-ID permission.
pub const PROCESS_SET_SESSIONID: PROCESS_ACCESS = 0x0004;
/// Permission to modify a process address space.
pub const PROCESS_VM_OPERATION: PROCESS_ACCESS = 0x0008;
/// Permission to read a process address space.
pub const PROCESS_VM_READ: PROCESS_ACCESS = 0x0010;
/// Permission to write a process address space.
pub const PROCESS_VM_WRITE: PROCESS_ACCESS = 0x0020;
/// Permission to duplicate handles from a process.
pub const PROCESS_DUP_HANDLE: PROCESS_ACCESS = 0x0040;
/// Permission to use a process as a parent.
pub const PROCESS_CREATE_PROCESS: PROCESS_ACCESS = 0x0080;
/// Permission to set process quotas.
pub const PROCESS_SET_QUOTA: PROCESS_ACCESS = 0x0100;
/// Permission to set process information.
pub const PROCESS_SET_INFORMATION: PROCESS_ACCESS = 0x0200;
/// Permission to query process information.
pub const PROCESS_QUERY_INFORMATION: PROCESS_ACCESS = 0x0400;
/// Permission to suspend or resume a process.
pub const PROCESS_SUSPEND_RESUME: PROCESS_ACCESS = 0x0800;
/// Permission to query limited process information.
pub const PROCESS_QUERY_LIMITED_INFORMATION: PROCESS_ACCESS = 0x1000;
/// Permission to set limited process information.
pub const PROCESS_SET_LIMITED_INFORMATION: PROCESS_ACCESS = 0x2000;

/// Include process entries in a Toolhelp snapshot.
pub const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
/// Include thread entries in a Toolhelp snapshot.
pub const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
/// Include all Toolhelp entry classes in a snapshot.
pub const TH32CS_SNAPALL: u32 = 0x0000_000f;
/// Make the Toolhelp snapshot handle inheritable.
pub const TH32CS_INHERIT: u32 = 0x8000_0000;

/// Exit code reported while a process is still running.
pub const STILL_ACTIVE: u32 = 259;
/// Request a native device path from [`QueryFullProcessImageNameW`].
pub const PROCESS_NAME_NATIVE: u32 = 0x0000_0001;

/// Handles and identifiers returned by process-creation APIs.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PROCESS_INFORMATION {
    /// Newly created process handle.
    pub hProcess: HANDLE,
    /// Primary thread handle.
    pub hThread: HANDLE,
    /// Process identifier.
    pub dwProcessId: u32,
    /// Primary thread identifier.
    pub dwThreadId: u32,
}

/// Process entry returned by the Toolhelp snapshot API.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PROCESSENTRY32W {
    /// Size of this structure in bytes; initialize before the first call.
    pub dwSize: u32,
    /// Reserved usage count.
    pub cntUsage: u32,
    /// Process identifier.
    pub th32ProcessID: u32,
    /// Reserved default-heap identifier.
    pub th32DefaultHeapID: usize,
    /// Reserved module identifier.
    pub th32ModuleID: u32,
    /// Number of execution threads.
    pub cntThreads: u32,
    /// Parent process identifier.
    pub th32ParentProcessID: u32,
    /// Base priority of threads created by the process.
    pub pcPriClassBase: i32,
    /// Reserved flags.
    pub dwFlags: u32,
    /// Executable file name.
    pub szExeFile: [u16; MAX_PATH],
}

#[link(name = "kernel32")]
extern "system" {
    /// Returns the current process pseudo-handle.
    ///
    /// # Safety
    ///
    /// This function has no memory-safety preconditions. The returned pseudo-
    /// handle must not be passed to `CloseHandle`.
    pub fn GetCurrentProcess() -> HANDLE;

    /// Returns the current process identifier.
    ///
    /// # Safety
    ///
    /// This function has no memory-safety preconditions.
    pub fn GetCurrentProcessId() -> u32;

    /// Returns the identifier associated with a process handle.
    ///
    /// # Safety
    ///
    /// `Process` must be a valid process handle with query access.
    pub fn GetProcessId(Process: HANDLE) -> u32;

    /// Opens a process and returns an owned kernel handle on success.
    ///
    /// # Safety
    ///
    /// The access mask and inheritance flag must be valid. A non-null return
    /// value is owned by the caller and must eventually be closed once.
    pub fn OpenProcess(
        dwDesiredAccess: PROCESS_ACCESS,
        bInheritHandle: BOOL,
        dwProcessId: u32,
    ) -> HANDLE;

    /// Writes the executable path of a process into a UTF-16 buffer.
    ///
    /// # Safety
    ///
    /// `hProcess` must have query access. `lpExeName` must point to writable
    /// storage for the input number of UTF-16 units in `*lpdwSize`, and
    /// `lpdwSize` must be valid for reads and writes.
    pub fn QueryFullProcessImageNameW(
        hProcess: HANDLE,
        dwFlags: u32,
        lpExeName: PWSTR,
        lpdwSize: *mut u32,
    ) -> BOOL;

    /// Retrieves a process exit code.
    ///
    /// # Safety
    ///
    /// `hProcess` must be valid with query access and `lpExitCode` must point
    /// to writable `u32` storage.
    pub fn GetExitCodeProcess(hProcess: HANDLE, lpExitCode: *mut u32) -> BOOL;

    /// Terminates a process.
    ///
    /// # Safety
    ///
    /// `hProcess` must be valid with `PROCESS_TERMINATE` access. The caller is
    /// responsible for the system-wide effects of asynchronous termination.
    pub fn TerminateProcess(hProcess: HANDLE, uExitCode: u32) -> BOOL;

    /// Creates a Toolhelp snapshot.
    ///
    /// # Safety
    ///
    /// Flags and process ID must form a supported combination. A successful
    /// returned handle is owned and must be closed exactly once.
    pub fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> HANDLE;

    /// Retrieves the first process entry from a snapshot.
    ///
    /// # Safety
    ///
    /// `hSnapshot` must contain process entries. `lppe` must point to writable
    /// storage whose `dwSize` field was initialized to the structure size.
    pub fn Process32FirstW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;

    /// Retrieves the next process entry from a snapshot.
    ///
    /// # Safety
    ///
    /// `hSnapshot` and `lppe` must satisfy the requirements of
    /// [`Process32FirstW`] for the duration of the call.
    pub fn Process32NextW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;
}

#[link(name = "advapi32")]
extern "system" {
    /// Opens the primary token associated with a process.
    ///
    /// # Safety
    ///
    /// `ProcessHandle` must be a valid process handle with query access and
    /// `TokenHandle` must point to writable handle storage. On success the
    /// output handle is owned and must be closed exactly once.
    pub fn OpenProcessToken(
        ProcessHandle: HANDLE,
        DesiredAccess: u32,
        TokenHandle: *mut HANDLE,
    ) -> BOOL;
}

#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(core::mem::size_of::<PROCESS_INFORMATION>() == 24);
    assert!(core::mem::align_of::<PROCESS_INFORMATION>() == 8);
    assert!(core::mem::size_of::<PROCESSENTRY32W>() == 568);
    assert!(core::mem::align_of::<PROCESSENTRY32W>() == 8);
};

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::size_of::<PROCESS_INFORMATION>() == 16);
    assert!(core::mem::align_of::<PROCESS_INFORMATION>() == 4);
    assert!(core::mem::size_of::<PROCESSENTRY32W>() == 556);
    assert!(core::mem::align_of::<PROCESSENTRY32W>() == 4);
};
