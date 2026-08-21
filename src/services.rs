//! Feature `services` — Service Control Manager (local) surface.
//!
//! Covers what `windows-scm` needs: open the SCM, open a service, start / stop /
//! control it, query status, enumerate. Local-only — remote SCM (`\SVCCTL` DCE/RPC)
//! is handled by the `dcerpc` crate, not here.

use crate::foundation::{BOOL, PCWSTR, PWSTR};
use core::ffi::c_void;

// ---- Handle type ----------------------------------------------------------

/// `SC_HANDLE` per winsvc.h — SCM / service handle (opaque). Same shape as a `HANDLE`
/// but a distinct type so the compiler catches SCM-vs-kernel handle mixups.
pub type SC_HANDLE = *mut c_void;

pub const NULL_SC_HANDLE: SC_HANDLE = core::ptr::null_mut();

// ---- SCM access rights (winsvc.h) -----------------------------------------

pub const SC_MANAGER_CONNECT: u32 = 0x0001;
pub const SC_MANAGER_CREATE_SERVICE: u32 = 0x0002;
pub const SC_MANAGER_ENUMERATE_SERVICE: u32 = 0x0004;
pub const SC_MANAGER_LOCK: u32 = 0x0008;
pub const SC_MANAGER_QUERY_LOCK_STATUS: u32 = 0x0010;
pub const SC_MANAGER_MODIFY_BOOT_CONFIG: u32 = 0x0020;
pub const SC_MANAGER_ALL_ACCESS: u32 = 0xF003F;

// ---- Service access rights ------------------------------------------------

pub const SERVICE_QUERY_CONFIG: u32 = 0x0001;
pub const SERVICE_CHANGE_CONFIG: u32 = 0x0002;
pub const SERVICE_QUERY_STATUS: u32 = 0x0004;
pub const SERVICE_ENUMERATE_DEPENDENTS: u32 = 0x0008;
pub const SERVICE_START: u32 = 0x0010;
pub const SERVICE_STOP: u32 = 0x0020;
pub const SERVICE_PAUSE_CONTINUE: u32 = 0x0040;
pub const SERVICE_INTERROGATE: u32 = 0x0080;
pub const SERVICE_USER_DEFINED_CONTROL: u32 = 0x0100;
pub const SERVICE_ALL_ACCESS: u32 = 0xF01FF;

// ---- Service state (dwCurrentState in SERVICE_STATUS) ---------------------

pub const SERVICE_STOPPED: u32 = 0x00000001;
pub const SERVICE_START_PENDING: u32 = 0x00000002;
pub const SERVICE_STOP_PENDING: u32 = 0x00000003;
pub const SERVICE_RUNNING: u32 = 0x00000004;
pub const SERVICE_CONTINUE_PENDING: u32 = 0x00000005;
pub const SERVICE_PAUSE_PENDING: u32 = 0x00000006;
pub const SERVICE_PAUSED: u32 = 0x00000007;

// ---- Service type ---------------------------------------------------------

pub const SERVICE_KERNEL_DRIVER: u32 = 0x00000001;
pub const SERVICE_FILE_SYSTEM_DRIVER: u32 = 0x00000002;
pub const SERVICE_WIN32_OWN_PROCESS: u32 = 0x00000010;
pub const SERVICE_WIN32_SHARE_PROCESS: u32 = 0x00000020;
pub const SERVICE_INTERACTIVE_PROCESS: u32 = 0x00000100;
/// Combined kernel-mode driver filter (`SERVICE_DRIVER`).
pub const SERVICE_DRIVER: u32 = SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER;

// ---- Service start type ---------------------------------------------------

pub const SERVICE_BOOT_START: u32 = 0x00000000;
pub const SERVICE_SYSTEM_START: u32 = 0x00000001;
pub const SERVICE_AUTO_START: u32 = 0x00000002;
pub const SERVICE_DEMAND_START: u32 = 0x00000003;
pub const SERVICE_DISABLED: u32 = 0x00000004;

// ---- Service error control ------------------------------------------------

pub const SERVICE_ERROR_IGNORE: u32 = 0x00000000;
pub const SERVICE_ERROR_NORMAL: u32 = 0x00000001;
pub const SERVICE_ERROR_SEVERE: u32 = 0x00000002;
pub const SERVICE_ERROR_CRITICAL: u32 = 0x00000003;

// ---- EnumServicesStatusEx filter ------------------------------------------

pub const SERVICE_ACTIVE: u32 = 0x00000001;
pub const SERVICE_INACTIVE: u32 = 0x00000002;
pub const SERVICE_STATE_ALL: u32 = SERVICE_ACTIVE | SERVICE_INACTIVE;

// ---- ControlService codes -------------------------------------------------

pub const SERVICE_CONTROL_STOP: u32 = 0x00000001;
pub const SERVICE_CONTROL_PAUSE: u32 = 0x00000002;
pub const SERVICE_CONTROL_CONTINUE: u32 = 0x00000003;
pub const SERVICE_CONTROL_INTERROGATE: u32 = 0x00000004;
pub const SERVICE_CONTROL_SHUTDOWN: u32 = 0x00000005;
pub const SERVICE_CONTROL_PARAMCHANGE: u32 = 0x00000006;

// ---- ControlsAccepted bits in SERVICE_STATUS ------------------------------

pub const SERVICE_ACCEPT_STOP: u32 = 0x00000001;
pub const SERVICE_ACCEPT_PAUSE_CONTINUE: u32 = 0x00000002;
pub const SERVICE_ACCEPT_SHUTDOWN: u32 = 0x00000004;
pub const SERVICE_ACCEPT_PARAMCHANGE: u32 = 0x00000008;
pub const SERVICE_ACCEPT_NETBINDCHANGE: u32 = 0x00000010;
pub const SERVICE_ACCEPT_HARDWAREPROFILECHANGE: u32 = 0x00000020;
pub const SERVICE_ACCEPT_POWEREVENT: u32 = 0x00000040;
pub const SERVICE_ACCEPT_SESSIONCHANGE: u32 = 0x00000080;

// ---- QueryServiceStatusEx / EnumServicesStatusEx classes ------------------

/// `SC_STATUS_TYPE` — only one value defined in Windows headers.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SC_STATUS_TYPE {
    SC_STATUS_PROCESS_INFO = 0,
}

/// `SC_ENUM_TYPE` — only one value defined.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SC_ENUM_TYPE {
    SC_ENUM_PROCESS_INFO = 0,
}

// ---- Structs --------------------------------------------------------------

/// `SERVICE_STATUS` per winsvc.h.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SERVICE_STATUS {
    pub dwServiceType: u32,
    pub dwCurrentState: u32,
    pub dwControlsAccepted: u32,
    pub dwWin32ExitCode: u32,
    pub dwServiceSpecificExitCode: u32,
    pub dwCheckPoint: u32,
    pub dwWaitHint: u32,
}

/// `SERVICE_STATUS_PROCESS` per winsvc.h — extended status incl. PID + flags.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SERVICE_STATUS_PROCESS {
    pub dwServiceType: u32,
    pub dwCurrentState: u32,
    pub dwControlsAccepted: u32,
    pub dwWin32ExitCode: u32,
    pub dwServiceSpecificExitCode: u32,
    pub dwCheckPoint: u32,
    pub dwWaitHint: u32,
    pub dwProcessId: u32,
    pub dwServiceFlags: u32,
}

/// `ENUM_SERVICE_STATUS_PROCESSW` per winsvc.h — one row of `EnumServicesStatusExW`.
/// `lpServiceName` / `lpDisplayName` are inline pointers into the caller-supplied buffer.
#[repr(C)]
pub struct ENUM_SERVICE_STATUS_PROCESSW {
    pub lpServiceName: PWSTR,
    pub lpDisplayName: PWSTR,
    pub ServiceStatusProcess: SERVICE_STATUS_PROCESS,
}

// ---- Functions ------------------------------------------------------------

#[link(name = "advapi32")]
extern "system" {
    pub fn OpenSCManagerW(
        lpMachineName: PCWSTR,
        lpDatabaseName: PCWSTR,
        dwDesiredAccess: u32,
    ) -> SC_HANDLE;

    pub fn OpenServiceW(
        hSCManager: SC_HANDLE,
        lpServiceName: PCWSTR,
        dwDesiredAccess: u32,
    ) -> SC_HANDLE;

    pub fn CloseServiceHandle(hSCObject: SC_HANDLE) -> BOOL;

    pub fn StartServiceW(
        hService: SC_HANDLE,
        dwNumServiceArgs: u32,
        lpServiceArgVectors: *const PCWSTR,
    ) -> BOOL;

    pub fn ControlService(
        hService: SC_HANDLE,
        dwControl: u32,
        lpServiceStatus: *mut SERVICE_STATUS,
    ) -> BOOL;

    pub fn QueryServiceStatusEx(
        hService: SC_HANDLE,
        InfoLevel: SC_STATUS_TYPE,
        lpBuffer: *mut c_void,
        cbBufSize: u32,
        pcbBytesNeeded: *mut u32,
    ) -> BOOL;

    pub fn QueryServiceStatus(
        hService: SC_HANDLE,
        lpServiceStatus: *mut SERVICE_STATUS,
    ) -> BOOL;

    pub fn EnumServicesStatusExW(
        hSCManager: SC_HANDLE,
        InfoLevel: SC_ENUM_TYPE,
        dwServiceType: u32,
        dwServiceState: u32,
        lpServices: *mut c_void,
        cbBufSize: u32,
        pcbBytesNeeded: *mut u32,
        lpServicesReturned: *mut u32,
        lpResumeHandle: *mut u32,
        pszGroupName: PCWSTR,
    ) -> BOOL;

    pub fn CreateServiceW(
        hSCManager: SC_HANDLE,
        lpServiceName: PCWSTR,
        lpDisplayName: PCWSTR,
        dwDesiredAccess: u32,
        dwServiceType: u32,
        dwStartType: u32,
        dwErrorControl: u32,
        lpBinaryPathName: PCWSTR,
        lpLoadOrderGroup: PCWSTR,
        lpdwTagId: *mut u32,
        lpDependencies: PCWSTR,
        lpServiceStartName: PCWSTR,
        lpPassword: PCWSTR,
    ) -> SC_HANDLE;

    pub fn DeleteService(hService: SC_HANDLE) -> BOOL;
}

// ---- Compile-time layout assertions ----------------------------------------

#[cfg(target_pointer_width = "64")]
const _: () = {
    // SERVICE_STATUS: 7 × u32 = 28
    assert!(core::mem::size_of::<SERVICE_STATUS>() == 28);
    // SERVICE_STATUS_PROCESS: 9 × u32 = 36
    assert!(core::mem::size_of::<SERVICE_STATUS_PROCESS>() == 36);
    // ENUM_SERVICE_STATUS_PROCESSW: 2 × PWSTR(8) + SERVICE_STATUS_PROCESS(36) = 52 → align 8 → 56
    assert!(core::mem::size_of::<ENUM_SERVICE_STATUS_PROCESSW>() == 56);
};
