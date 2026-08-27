#![cfg(all(windows, feature = "services"))]

use std::ffi::c_void;
use std::mem::size_of;
use std::time::{SystemTime, UNIX_EPOCH};

use win32_min::foundation::{GetLastError, PCWSTR};
use win32_min::services::{
    CloseServiceHandle, ControlService, CreateServiceW, DeleteService, EnumServicesStatusExW,
    OpenSCManagerW, OpenServiceW, QueryServiceStatus, QueryServiceStatusEx, StartServiceW,
    SC_ENUM_TYPE, SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE,
    SC_MANAGER_ENUMERATE_SERVICE, SC_STATUS_TYPE, SERVICE_ALL_ACCESS, SERVICE_CONTROL_INTERROGATE,
    SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, SERVICE_INTERROGATE, SERVICE_QUERY_STATUS,
    SERVICE_RUNNING, SERVICE_STATE_ALL, SERVICE_STATUS, SERVICE_STATUS_PROCESS,
    SERVICE_WIN32_OWN_PROCESS, SERVICE_WIN32_SHARE_PROCESS,
};

const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_MORE_DATA: u32 = 234;

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

struct ServiceHandle(SC_HANDLE);

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseServiceHandle(self.0) };
        }
    }
}

struct TemporaryService {
    handle: SC_HANDLE,
    deleted: bool,
}

impl Drop for TemporaryService {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                if !self.deleted {
                    let _ = DeleteService(self.handle);
                }
                let _ = CloseServiceHandle(self.handle);
            }
        }
    }
}

#[test]
fn enumerate_and_query_eventlog_service_read_only() {
    let scm = ServiceHandle(unsafe {
        OpenSCManagerW(
            PCWSTR::NULL,
            PCWSTR::NULL,
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
        )
    });
    assert!(!scm.0.is_null(), "OpenSCManagerW failed: {}", unsafe {
        GetLastError()
    });

    let mut needed = 0u32;
    let mut returned = 0u32;
    let mut resume = 0u32;
    assert_eq!(
        unsafe {
            EnumServicesStatusExW(
                scm.0,
                SC_ENUM_TYPE::SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS,
                SERVICE_STATE_ALL,
                std::ptr::null_mut(),
                0,
                &mut needed,
                &mut returned,
                &mut resume,
                PCWSTR::NULL,
            )
        },
        0
    );
    assert_eq!(unsafe { GetLastError() }, ERROR_MORE_DATA);
    assert!(needed > 0);

    let words = (needed as usize + 65_536).div_ceil(size_of::<usize>());
    let mut buffer = vec![0usize; words];
    resume = 0;
    assert_ne!(
        unsafe {
            EnumServicesStatusExW(
                scm.0,
                SC_ENUM_TYPE::SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS,
                SERVICE_STATE_ALL,
                buffer.as_mut_ptr() as *mut c_void,
                (buffer.len() * size_of::<usize>()) as u32,
                &mut needed,
                &mut returned,
                &mut resume,
                PCWSTR::NULL,
            )
        },
        0,
        "EnumServicesStatusExW failed: {}",
        unsafe { GetLastError() }
    );
    assert!(returned > 0);

    let eventlog_name = wide("EventLog");
    let service = ServiceHandle(unsafe {
        OpenServiceW(
            scm.0,
            PCWSTR(eventlog_name.as_ptr()),
            SERVICE_QUERY_STATUS | SERVICE_INTERROGATE,
        )
    });
    assert!(!service.0.is_null(), "OpenServiceW failed: {}", unsafe {
        GetLastError()
    });

    let mut basic_status = SERVICE_STATUS {
        dwServiceType: 0,
        dwCurrentState: 0,
        dwControlsAccepted: 0,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    assert_ne!(
        unsafe { QueryServiceStatus(service.0, &mut basic_status) },
        0
    );
    assert_eq!(basic_status.dwCurrentState, SERVICE_RUNNING);

    let mut process_status = SERVICE_STATUS_PROCESS {
        dwServiceType: 0,
        dwCurrentState: 0,
        dwControlsAccepted: 0,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
        dwProcessId: 0,
        dwServiceFlags: 0,
    };
    assert_ne!(
        unsafe {
            QueryServiceStatusEx(
                service.0,
                SC_STATUS_TYPE::SC_STATUS_PROCESS_INFO,
                &mut process_status as *mut _ as *mut c_void,
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            )
        },
        0
    );
    assert_eq!(process_status.dwCurrentState, SERVICE_RUNNING);
    assert_ne!(process_status.dwProcessId, 0);

    assert_ne!(
        unsafe { ControlService(service.0, SERVICE_CONTROL_INTERROGATE, &mut basic_status,) },
        0
    );
    assert_eq!(basic_status.dwCurrentState, SERVICE_RUNNING);

    assert_eq!(unsafe { StartServiceW(service.0, 0, std::ptr::null()) }, 0);
    assert_eq!(unsafe { GetLastError() }, ERROR_ACCESS_DENIED);

    // Link-check the two intentionally non-invoked mutating functions. Their
    // success-path test requires creating a real Windows service and is kept
    // out of the default suite.
    assert_ne!(CreateServiceW as *const () as usize, 0);
    assert_ne!(DeleteService as *const () as usize, 0);
}

#[test]
#[ignore = "requires elevated SCM create-service rights"]
fn elevated_create_query_delete_temporary_service() {
    let scm = ServiceHandle(unsafe {
        OpenSCManagerW(
            PCWSTR::NULL,
            PCWSTR::NULL,
            SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
        )
    });
    assert!(!scm.0.is_null(), "OpenSCManagerW failed: {}", unsafe {
        GetLastError()
    });

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = wide(&format!("win32-min-test-{}-{unique}", std::process::id()));
    let display = wide("win32-min isolated API test");
    let binary = wide(r#""C:\Windows\System32\cmd.exe" /c exit 0"#);
    let mut service = TemporaryService {
        handle: unsafe {
            CreateServiceW(
                scm.0,
                PCWSTR(name.as_ptr()),
                PCWSTR(display.as_ptr()),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                PCWSTR(binary.as_ptr()),
                PCWSTR::NULL,
                std::ptr::null_mut(),
                PCWSTR::NULL,
                PCWSTR::NULL,
                PCWSTR::NULL,
            )
        },
        deleted: false,
    };
    assert!(
        !service.handle.is_null(),
        "CreateServiceW failed: {}",
        unsafe { GetLastError() }
    );

    let mut status = SERVICE_STATUS {
        dwServiceType: 0,
        dwCurrentState: 0,
        dwControlsAccepted: 0,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    assert_ne!(
        unsafe { QueryServiceStatus(service.handle, &mut status) },
        0
    );
    assert_eq!(status.dwCurrentState, win32_min::services::SERVICE_STOPPED);
    assert_ne!(unsafe { DeleteService(service.handle) }, 0);
    service.deleted = true;
}
