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

/// Null SCM/service handle.
pub const NULL_SC_HANDLE: SC_HANDLE = core::ptr::null_mut();

// ---- SCM access rights (winsvc.h) -----------------------------------------

/// Permission to connect to the SCM database.
pub const SC_MANAGER_CONNECT: u32 = 0x0001;
/// Permission to create a service.
pub const SC_MANAGER_CREATE_SERVICE: u32 = 0x0002;
/// Permission to enumerate services.
pub const SC_MANAGER_ENUMERATE_SERVICE: u32 = 0x0004;
/// Permission to lock the SCM database.
pub const SC_MANAGER_LOCK: u32 = 0x0008;
/// Permission to query SCM lock status.
pub const SC_MANAGER_QUERY_LOCK_STATUS: u32 = 0x0010;
/// Permission to modify the last-known-good configuration.
pub const SC_MANAGER_MODIFY_BOOT_CONFIG: u32 = 0x0020;
/// All SCM-specific and standard permissions.
pub const SC_MANAGER_ALL_ACCESS: u32 = 0xF003F;

// ---- Service access rights ------------------------------------------------

/// Permission to query service configuration.
pub const SERVICE_QUERY_CONFIG: u32 = 0x0001;
/// Permission to change service configuration.
pub const SERVICE_CHANGE_CONFIG: u32 = 0x0002;
/// Permission to query service status.
pub const SERVICE_QUERY_STATUS: u32 = 0x0004;
/// Permission to enumerate dependent services.
pub const SERVICE_ENUMERATE_DEPENDENTS: u32 = 0x0008;
/// Permission to start a service.
pub const SERVICE_START: u32 = 0x0010;
/// Permission to stop a service.
pub const SERVICE_STOP: u32 = 0x0020;
/// Permission to pause or continue a service.
pub const SERVICE_PAUSE_CONTINUE: u32 = 0x0040;
/// Permission to interrogate a service.
pub const SERVICE_INTERROGATE: u32 = 0x0080;
/// Permission to send user-defined controls.
pub const SERVICE_USER_DEFINED_CONTROL: u32 = 0x0100;
/// All service-specific and standard permissions.
pub const SERVICE_ALL_ACCESS: u32 = 0xF01FF;

// ---- Service state (dwCurrentState in SERVICE_STATUS) ---------------------

/// Service is stopped.
pub const SERVICE_STOPPED: u32 = 0x00000001;
/// Service is starting.
pub const SERVICE_START_PENDING: u32 = 0x00000002;
/// Service is stopping.
pub const SERVICE_STOP_PENDING: u32 = 0x00000003;
/// Service is running.
pub const SERVICE_RUNNING: u32 = 0x00000004;
/// Service is continuing.
pub const SERVICE_CONTINUE_PENDING: u32 = 0x00000005;
/// Service is pausing.
pub const SERVICE_PAUSE_PENDING: u32 = 0x00000006;
/// Service is paused.
pub const SERVICE_PAUSED: u32 = 0x00000007;

// ---- Service type ---------------------------------------------------------

/// Kernel-driver service.
pub const SERVICE_KERNEL_DRIVER: u32 = 0x00000001;
/// File-system driver service.
pub const SERVICE_FILE_SYSTEM_DRIVER: u32 = 0x00000002;
/// Win32 service in its own process.
pub const SERVICE_WIN32_OWN_PROCESS: u32 = 0x00000010;
/// Win32 service sharing a host process.
pub const SERVICE_WIN32_SHARE_PROCESS: u32 = 0x00000020;
/// Service permitted to interact with the desktop.
pub const SERVICE_INTERACTIVE_PROCESS: u32 = 0x00000100;
/// Combined kernel-mode driver filter (`SERVICE_DRIVER`).
pub const SERVICE_DRIVER: u32 = SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER;

// ---- Service start type ---------------------------------------------------

/// Driver loaded by the boot loader.
pub const SERVICE_BOOT_START: u32 = 0x00000000;
/// Driver loaded during kernel initialization.
pub const SERVICE_SYSTEM_START: u32 = 0x00000001;
/// Service started automatically.
pub const SERVICE_AUTO_START: u32 = 0x00000002;
/// Service started on demand.
pub const SERVICE_DEMAND_START: u32 = 0x00000003;
/// Disabled service.
pub const SERVICE_DISABLED: u32 = 0x00000004;

// ---- Service error control ------------------------------------------------

/// Ignore a driver startup error.
pub const SERVICE_ERROR_IGNORE: u32 = 0x00000000;
/// Log a driver startup error and continue.
pub const SERVICE_ERROR_NORMAL: u32 = 0x00000001;
/// Restart with last-known-good configuration on error when possible.
pub const SERVICE_ERROR_SEVERE: u32 = 0x00000002;
/// Treat startup failure as critical.
pub const SERVICE_ERROR_CRITICAL: u32 = 0x00000003;

// ---- EnumServicesStatusEx filter ------------------------------------------

/// Enumerate active services.
pub const SERVICE_ACTIVE: u32 = 0x00000001;
/// Enumerate inactive services.
pub const SERVICE_INACTIVE: u32 = 0x00000002;
/// Enumerate services in every state.
pub const SERVICE_STATE_ALL: u32 = SERVICE_ACTIVE | SERVICE_INACTIVE;

// ---- ControlService codes -------------------------------------------------

/// Stop control code.
pub const SERVICE_CONTROL_STOP: u32 = 0x00000001;
/// Pause control code.
pub const SERVICE_CONTROL_PAUSE: u32 = 0x00000002;
/// Continue control code.
pub const SERVICE_CONTROL_CONTINUE: u32 = 0x00000003;
/// Interrogate control code.
pub const SERVICE_CONTROL_INTERROGATE: u32 = 0x00000004;
/// System-shutdown control code.
pub const SERVICE_CONTROL_SHUTDOWN: u32 = 0x00000005;
/// Configuration-parameter-change control code.
pub const SERVICE_CONTROL_PARAMCHANGE: u32 = 0x00000006;

// ---- ControlsAccepted bits in SERVICE_STATUS ------------------------------

/// Service accepts stop controls.
pub const SERVICE_ACCEPT_STOP: u32 = 0x00000001;
/// Service accepts pause and continue controls.
pub const SERVICE_ACCEPT_PAUSE_CONTINUE: u32 = 0x00000002;
/// Service accepts shutdown controls.
pub const SERVICE_ACCEPT_SHUTDOWN: u32 = 0x00000004;
/// Service accepts parameter-change controls.
pub const SERVICE_ACCEPT_PARAMCHANGE: u32 = 0x00000008;
/// Service accepts network-binding-change controls.
pub const SERVICE_ACCEPT_NETBINDCHANGE: u32 = 0x00000010;
/// Service accepts hardware-profile-change controls.
pub const SERVICE_ACCEPT_HARDWAREPROFILECHANGE: u32 = 0x00000020;
/// Service accepts power-event controls.
pub const SERVICE_ACCEPT_POWEREVENT: u32 = 0x00000040;
/// Service accepts terminal-session-change controls.
pub const SERVICE_ACCEPT_SESSIONCHANGE: u32 = 0x00000080;

// ---- QueryServiceStatusEx / EnumServicesStatusEx classes ------------------

/// `SC_STATUS_TYPE` — only one value defined in Windows headers.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SC_STATUS_TYPE {
    /// Return a [`SERVICE_STATUS_PROCESS`] structure.
    SC_STATUS_PROCESS_INFO = 0,
}

/// `SC_ENUM_TYPE` — only one value defined.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SC_ENUM_TYPE {
    /// Return [`ENUM_SERVICE_STATUS_PROCESSW`] records.
    SC_ENUM_PROCESS_INFO = 0,
}

// ---- Structs --------------------------------------------------------------

/// `SERVICE_STATUS` per winsvc.h.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SERVICE_STATUS {
    /// Service type flags.
    pub dwServiceType: u32,
    /// Current service state.
    pub dwCurrentState: u32,
    /// Control codes accepted in the current state.
    pub dwControlsAccepted: u32,
    /// Win32 exit code.
    pub dwWin32ExitCode: u32,
    /// Service-specific exit code.
    pub dwServiceSpecificExitCode: u32,
    /// Progress checkpoint for a pending operation.
    pub dwCheckPoint: u32,
    /// Estimated pending-operation duration in milliseconds.
    pub dwWaitHint: u32,
}

/// `SERVICE_STATUS_PROCESS` per winsvc.h — extended status incl. PID + flags.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SERVICE_STATUS_PROCESS {
    /// Service type flags.
    pub dwServiceType: u32,
    /// Current service state.
    pub dwCurrentState: u32,
    /// Control codes accepted in the current state.
    pub dwControlsAccepted: u32,
    /// Win32 exit code.
    pub dwWin32ExitCode: u32,
    /// Service-specific exit code.
    pub dwServiceSpecificExitCode: u32,
    /// Progress checkpoint for a pending operation.
    pub dwCheckPoint: u32,
    /// Estimated pending-operation duration in milliseconds.
    pub dwWaitHint: u32,
    /// Service process identifier, or zero.
    pub dwProcessId: u32,
    /// Service process flags.
    pub dwServiceFlags: u32,
}

/// `ENUM_SERVICE_STATUS_PROCESSW` per winsvc.h — one row of `EnumServicesStatusExW`.
/// `lpServiceName` / `lpDisplayName` are inline pointers into the caller-supplied buffer.
#[repr(C)]
pub struct ENUM_SERVICE_STATUS_PROCESSW {
    /// Borrowed null-terminated service name inside the enumeration buffer.
    pub lpServiceName: PWSTR,
    /// Borrowed null-terminated display name inside the enumeration buffer.
    pub lpDisplayName: PWSTR,
    /// Extended service status.
    pub ServiceStatusProcess: SERVICE_STATUS_PROCESS,
}

// ---- Functions ------------------------------------------------------------

#[link(name = "advapi32")]
extern "system" {
    /// Opens a Service Control Manager database.
    ///
    /// # Safety
    ///
    /// Optional machine and database names must be null or readable
    /// null-terminated UTF-16 strings. A successful returned handle is owned
    /// and must be released with [`CloseServiceHandle`].
    pub fn OpenSCManagerW(
        lpMachineName: PCWSTR,
        lpDatabaseName: PCWSTR,
        dwDesiredAccess: u32,
    ) -> SC_HANDLE;

    /// Opens a service in an SCM database.
    ///
    /// # Safety
    ///
    /// `hSCManager` must be valid and `lpServiceName` a readable
    /// null-terminated UTF-16 string. The successful output is owned and must
    /// be released with [`CloseServiceHandle`].
    pub fn OpenServiceW(
        hSCManager: SC_HANDLE,
        lpServiceName: PCWSTR,
        dwDesiredAccess: u32,
    ) -> SC_HANDLE;

    /// Closes an SCM or service handle.
    ///
    /// # Safety
    ///
    /// `hSCObject` must be a valid uniquely owned SCM handle, not already
    /// closed, and no concurrent user may depend on its continued validity.
    pub fn CloseServiceHandle(hSCObject: SC_HANDLE) -> BOOL;

    /// Starts a service with optional argument strings.
    ///
    /// # Safety
    ///
    /// The service handle must have start access. If the argument count is
    /// nonzero, `lpServiceArgVectors` must reference that many readable PCWSTR
    /// values whose null-terminated strings remain valid through the call.
    pub fn StartServiceW(
        hService: SC_HANDLE,
        dwNumServiceArgs: u32,
        lpServiceArgVectors: *const PCWSTR,
    ) -> BOOL;

    /// Sends a control code to a service.
    ///
    /// # Safety
    ///
    /// The service handle must have the access required by `dwControl`, and
    /// `lpServiceStatus` must point to writable status storage.
    pub fn ControlService(
        hService: SC_HANDLE,
        dwControl: u32,
        lpServiceStatus: *mut SERVICE_STATUS,
    ) -> BOOL;

    /// Queries extended service status.
    ///
    /// # Safety
    ///
    /// The service handle must be valid. `pcbBytesNeeded` must be writable.
    /// `lpBuffer` may be null for a size query; otherwise it must be writable
    /// for `cbBufSize` bytes and correctly aligned for `InfoLevel`.
    pub fn QueryServiceStatusEx(
        hService: SC_HANDLE,
        InfoLevel: SC_STATUS_TYPE,
        lpBuffer: *mut c_void,
        cbBufSize: u32,
        pcbBytesNeeded: *mut u32,
    ) -> BOOL;

    /// Queries basic service status.
    ///
    /// # Safety
    ///
    /// `hService` must be valid with query-status access and
    /// `lpServiceStatus` must point to writable [`SERVICE_STATUS`] storage.
    pub fn QueryServiceStatus(hService: SC_HANDLE, lpServiceStatus: *mut SERVICE_STATUS) -> BOOL;

    /// Enumerates services and their process status.
    ///
    /// # Safety
    ///
    /// The manager handle must have enumeration access. `pcbBytesNeeded` and
    /// `lpServicesReturned` must be writable. `lpServices` may be null for a
    /// size query; otherwise it must hold `cbBufSize` writable bytes. The resume
    /// handle is optional but, when non-null, must be writable. Group name must
    /// be null or a readable null-terminated UTF-16 string.
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

    /// Creates a service record in an SCM database.
    ///
    /// # Safety
    ///
    /// The manager must have create access. Required names and binary path must
    /// be readable null-terminated UTF-16 strings; each optional string must be
    /// null or valid. Dependency data must be a valid multi-string. A non-null
    /// tag pointer must be writable. The successful returned handle is owned,
    /// and the persistent service remains until explicitly deleted.
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

    /// Marks a service for deletion after its final handle closes.
    ///
    /// # Safety
    ///
    /// `hService` must be valid with delete access and refer to the intended
    /// service. The caller is responsible for this persistent mutation.
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

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::size_of::<SERVICE_STATUS>() == 28);
    assert!(core::mem::size_of::<SERVICE_STATUS_PROCESS>() == 36);
    assert!(core::mem::size_of::<ENUM_SERVICE_STATUS_PROCESSW>() == 44);
};
