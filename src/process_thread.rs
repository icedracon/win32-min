//! Feature `process-thread` — process/thread discovery and inspection surface.
//!
//! This module deliberately stops short of remote-memory and code-injection
//! primitives. It covers the process and thread operations commonly needed by
//! inventory, auditing, token inspection, and administration tools.

use crate::foundation::{BOOL, HANDLE, PWSTR};

/// Maximum legacy Win32 path length used by `PROCESSENTRY32W`.
pub const MAX_PATH: usize = 260;

// Process access rights (winnt.h).
pub const PROCESS_TERMINATE: u32 = 0x0001;
pub const PROCESS_CREATE_THREAD: u32 = 0x0002;
pub const PROCESS_SET_SESSIONID: u32 = 0x0004;
pub const PROCESS_VM_OPERATION: u32 = 0x0008;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_VM_WRITE: u32 = 0x0020;
pub const PROCESS_DUP_HANDLE: u32 = 0x0040;
pub const PROCESS_CREATE_PROCESS: u32 = 0x0080;
pub const PROCESS_SET_QUOTA: u32 = 0x0100;
pub const PROCESS_SET_INFORMATION: u32 = 0x0200;
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
pub const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
pub const PROCESS_SET_LIMITED_INFORMATION: u32 = 0x2000;

// Thread access rights (winnt.h).
pub const THREAD_TERMINATE: u32 = 0x0001;
pub const THREAD_SUSPEND_RESUME: u32 = 0x0002;
pub const THREAD_GET_CONTEXT: u32 = 0x0008;
pub const THREAD_SET_CONTEXT: u32 = 0x0010;
pub const THREAD_SET_INFORMATION: u32 = 0x0020;
pub const THREAD_QUERY_INFORMATION: u32 = 0x0040;
pub const THREAD_SET_THREAD_TOKEN: u32 = 0x0080;
pub const THREAD_IMPERSONATE: u32 = 0x0100;
pub const THREAD_DIRECT_IMPERSONATION: u32 = 0x0200;
pub const THREAD_SET_LIMITED_INFORMATION: u32 = 0x0400;
pub const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;

// Toolhelp snapshot flags (tlhelp32.h).
pub const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
pub const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
pub const TH32CS_SNAPALL: u32 = 0x0000_000f;
pub const TH32CS_INHERIT: u32 = 0x8000_0000;

/// Return code from `GetExitCodeProcess` while a process is still running.
pub const STILL_ACTIVE: u32 = 259;

/// Request the native device-form path from `QueryFullProcessImageNameW`.
pub const PROCESS_NAME_NATIVE: u32 = 0x0000_0001;

/// Process entry returned by the Toolhelp snapshot API.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PROCESSENTRY32W {
    pub dwSize: u32,
    pub cntUsage: u32,
    pub th32ProcessID: u32,
    pub th32DefaultHeapID: usize,
    pub th32ModuleID: u32,
    pub cntThreads: u32,
    pub th32ParentProcessID: u32,
    pub pcPriClassBase: i32,
    pub dwFlags: u32,
    pub szExeFile: [u16; MAX_PATH],
}

/// Thread entry returned by the Toolhelp snapshot API.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct THREADENTRY32 {
    pub dwSize: u32,
    pub cntUsage: u32,
    pub th32ThreadID: u32,
    pub th32OwnerProcessID: u32,
    pub tpBasePri: i32,
    pub tpDeltaPri: i32,
    pub dwFlags: u32,
}

#[link(name = "kernel32")]
extern "system" {
    pub fn GetCurrentProcess() -> HANDLE;
    pub fn GetCurrentProcessId() -> u32;
    pub fn GetProcessId(Process: HANDLE) -> u32;

    pub fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: BOOL, dwProcessId: u32) -> HANDLE;

    pub fn QueryFullProcessImageNameW(
        hProcess: HANDLE,
        dwFlags: u32,
        lpExeName: PWSTR,
        lpdwSize: *mut u32,
    ) -> BOOL;

    pub fn GetExitCodeProcess(hProcess: HANDLE, lpExitCode: *mut u32) -> BOOL;
    pub fn TerminateProcess(hProcess: HANDLE, uExitCode: u32) -> BOOL;

    pub fn GetCurrentThread() -> HANDLE;
    pub fn GetCurrentThreadId() -> u32;
    pub fn GetThreadId(Thread: HANDLE) -> u32;

    pub fn OpenThread(dwDesiredAccess: u32, bInheritHandle: BOOL, dwThreadId: u32) -> HANDLE;

    pub fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> HANDLE;
    pub fn Process32FirstW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;
    pub fn Process32NextW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;
    pub fn Thread32First(hSnapshot: HANDLE, lpte: *mut THREADENTRY32) -> BOOL;
    pub fn Thread32Next(hSnapshot: HANDLE, lpte: *mut THREADENTRY32) -> BOOL;
}

#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(core::mem::size_of::<PROCESSENTRY32W>() == 568);
    assert!(core::mem::align_of::<PROCESSENTRY32W>() == 8);
    assert!(core::mem::size_of::<THREADENTRY32>() == 28);
};

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::size_of::<PROCESSENTRY32W>() == 556);
    assert!(core::mem::align_of::<PROCESSENTRY32W>() == 4);
    assert!(core::mem::size_of::<THREADENTRY32>() == 28);
};
