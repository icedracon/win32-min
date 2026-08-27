//! Thread discovery and control primitives.

use crate::foundation::{BOOL, HANDLE};

/// Thread access-mask type.
pub type THREAD_ACCESS = u32;

/// Permission to terminate a thread.
pub const THREAD_TERMINATE: THREAD_ACCESS = 0x0001;
/// Permission to suspend or resume a thread.
pub const THREAD_SUSPEND_RESUME: THREAD_ACCESS = 0x0002;
/// Permission to read a thread context.
pub const THREAD_GET_CONTEXT: THREAD_ACCESS = 0x0008;
/// Permission to set a thread context.
pub const THREAD_SET_CONTEXT: THREAD_ACCESS = 0x0010;
/// Permission to set thread information.
pub const THREAD_SET_INFORMATION: THREAD_ACCESS = 0x0020;
/// Permission to query thread information.
pub const THREAD_QUERY_INFORMATION: THREAD_ACCESS = 0x0040;
/// Permission to assign a thread token.
pub const THREAD_SET_THREAD_TOKEN: THREAD_ACCESS = 0x0080;
/// Permission to impersonate a thread.
pub const THREAD_IMPERSONATE: THREAD_ACCESS = 0x0100;
/// Permission for direct impersonation.
pub const THREAD_DIRECT_IMPERSONATION: THREAD_ACCESS = 0x0200;
/// Permission to set limited thread information.
pub const THREAD_SET_LIMITED_INFORMATION: THREAD_ACCESS = 0x0400;
/// Permission to query limited thread information.
pub const THREAD_QUERY_LIMITED_INFORMATION: THREAD_ACCESS = 0x0800;

/// Thread entry returned by the Toolhelp snapshot API.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct THREADENTRY32 {
    /// Size of this structure in bytes; initialize before the first call.
    pub dwSize: u32,
    /// Reserved usage count.
    pub cntUsage: u32,
    /// Thread identifier.
    pub th32ThreadID: u32,
    /// Identifier of the owning process.
    pub th32OwnerProcessID: u32,
    /// Base priority.
    pub tpBasePri: i32,
    /// Reserved priority delta.
    pub tpDeltaPri: i32,
    /// Reserved flags.
    pub dwFlags: u32,
}

#[link(name = "kernel32")]
extern "system" {
    /// Returns the current thread pseudo-handle.
    ///
    /// # Safety
    ///
    /// This function has no memory-safety preconditions. The returned pseudo-
    /// handle must not be closed.
    pub fn GetCurrentThread() -> HANDLE;

    /// Returns the current thread identifier.
    ///
    /// # Safety
    ///
    /// This function has no memory-safety preconditions.
    pub fn GetCurrentThreadId() -> u32;

    /// Returns the identifier associated with a thread handle.
    ///
    /// # Safety
    ///
    /// `Thread` must be a valid thread handle with query access.
    pub fn GetThreadId(Thread: HANDLE) -> u32;

    /// Opens a thread and returns an owned kernel handle on success.
    ///
    /// # Safety
    ///
    /// The access mask and inheritance flag must be valid. A non-null return
    /// value is owned by the caller and must eventually be closed once.
    pub fn OpenThread(
        dwDesiredAccess: THREAD_ACCESS,
        bInheritHandle: BOOL,
        dwThreadId: u32,
    ) -> HANDLE;

    /// Suspends a thread and returns its previous suspend count.
    ///
    /// # Safety
    ///
    /// `hThread` must be valid with `THREAD_SUSPEND_RESUME` access. Suspending
    /// an arbitrary thread can deadlock a process; callers own that risk.
    pub fn SuspendThread(hThread: HANDLE) -> u32;

    /// Decrements a thread's suspend count.
    ///
    /// # Safety
    ///
    /// `hThread` must be valid with `THREAD_SUSPEND_RESUME` access and must have
    /// a suspend count the caller is entitled to modify.
    pub fn ResumeThread(hThread: HANDLE) -> u32;

    /// Creates a Toolhelp snapshot.
    ///
    /// # Safety
    ///
    /// Flags and process ID must be supported. A successful returned handle is
    /// owned and must be closed exactly once.
    pub fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> HANDLE;

    /// Retrieves the first thread entry from a snapshot.
    ///
    /// # Safety
    ///
    /// `hSnapshot` must contain thread entries. `lpte` must point to writable
    /// storage whose `dwSize` field was initialized to the structure size.
    pub fn Thread32First(hSnapshot: HANDLE, lpte: *mut THREADENTRY32) -> BOOL;

    /// Retrieves the next thread entry from a snapshot.
    ///
    /// # Safety
    ///
    /// `hSnapshot` and `lpte` must satisfy the requirements of
    /// [`Thread32First`] for the duration of the call.
    pub fn Thread32Next(hSnapshot: HANDLE, lpte: *mut THREADENTRY32) -> BOOL;
}

const _: () = {
    assert!(core::mem::size_of::<THREADENTRY32>() == 28);
    assert!(core::mem::align_of::<THREADENTRY32>() == 4);
};
