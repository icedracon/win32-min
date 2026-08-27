#![cfg(all(windows, feature = "security-token"))]

use std::ffi::c_void;
use std::mem::size_of;

use win32_min::foundation::{CloseHandle, GetLastError, SetLastError, HANDLE, LUID, PCWSTR};
use win32_min::security_token::{
    AdjustTokenPrivileges, DuplicateTokenEx, GetCurrentProcess, GetCurrentThread, GetLengthSid,
    GetSidIdentifierAuthority, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    ImpersonateLoggedOnUser, IsValidSid, LookupPrivilegeValueW, OpenProcess, OpenProcessToken,
    OpenThreadToken, RevertToSelf, SetThreadToken, SetTokenInformation, LUID_AND_ATTRIBUTES,
    PROCESS_QUERY_LIMITED_INFORMATION, SECURITY_IMPERSONATION_LEVEL, SE_PRIVILEGE_ENABLED,
    TOKEN_ALL_ACCESS, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_TYPE,
    TOKEN_USER,
};

const ERROR_NO_TOKEN: u32 = 1008;
const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

struct RevertGuard(bool);

impl Drop for RevertGuard {
    fn drop(&mut self) {
        if self.0 {
            unsafe { RevertToSelf() };
        }
    }
}

fn aligned_buffer(bytes: u32) -> Vec<usize> {
    vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())]
}

#[test]
fn raw_token_sid_privilege_and_impersonation_lifecycle() {
    let pseudo_process = unsafe { GetCurrentProcess() };
    let pseudo_thread = unsafe { GetCurrentThread() };
    assert!(!pseudo_process.is_null());
    assert!(!pseudo_thread.is_null());

    let opened_process = OwnedHandle(unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, std::process::id())
    });
    assert!(!opened_process.0.is_null());

    let mut process_token = std::ptr::null_mut();
    assert_ne!(
        unsafe { OpenProcessToken(opened_process.0, TOKEN_ALL_ACCESS, &mut process_token) },
        0,
        "OpenProcessToken failed: {}",
        unsafe { GetLastError() }
    );
    let process_token = OwnedHandle(process_token);

    let mut duplicate = std::ptr::null_mut();
    assert_ne!(
        unsafe {
            DuplicateTokenEx(
                process_token.0,
                TOKEN_ALL_ACCESS,
                std::ptr::null(),
                SECURITY_IMPERSONATION_LEVEL::SecurityImpersonation,
                TOKEN_TYPE::TokenImpersonation,
                &mut duplicate,
            )
        },
        0,
        "DuplicateTokenEx failed: {}",
        unsafe { GetLastError() }
    );
    let duplicate = OwnedHandle(duplicate);

    let mut needed = 0u32;
    assert_eq!(
        unsafe {
            GetTokenInformation(
                process_token.0,
                TOKEN_INFORMATION_CLASS::TokenUser,
                std::ptr::null_mut(),
                0,
                &mut needed,
            )
        },
        0
    );
    assert!(needed >= size_of::<TOKEN_USER>() as u32);
    let mut user_buffer = aligned_buffer(needed);
    assert_ne!(
        unsafe {
            GetTokenInformation(
                process_token.0,
                TOKEN_INFORMATION_CLASS::TokenUser,
                user_buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        },
        0
    );
    let token_user = unsafe { &*(user_buffer.as_ptr() as *const TOKEN_USER) };
    let sid = token_user.User.Sid;
    assert_ne!(unsafe { IsValidSid(sid) }, 0);
    assert!(unsafe { GetLengthSid(sid) } >= 12);
    let subauthority_count = unsafe { *GetSidSubAuthorityCount(sid) };
    assert!(subauthority_count > 0);
    let _first_subauthority = unsafe { *GetSidSubAuthority(sid, 0) };
    let authority = unsafe { &*GetSidIdentifierAuthority(sid) };
    assert_ne!(authority.Value, [0u8; 6]);

    let privilege_name = wide("SeChangeNotifyPrivilege");
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    assert_ne!(
        unsafe { LookupPrivilegeValueW(PCWSTR::NULL, PCWSTR(privilege_name.as_ptr()), &mut luid) },
        0
    );
    let privilege_state = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    unsafe { SetLastError(0) };
    assert_ne!(
        unsafe {
            AdjustTokenPrivileges(
                duplicate.0,
                0,
                &privilege_state,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        0
    );
    assert_ne!(unsafe { GetLastError() }, ERROR_NOT_ALL_ASSIGNED);

    let mut integrity_len = 0u32;
    assert_eq!(
        unsafe {
            GetTokenInformation(
                duplicate.0,
                TOKEN_INFORMATION_CLASS::TokenIntegrityLevel,
                std::ptr::null_mut(),
                0,
                &mut integrity_len,
            )
        },
        0
    );
    assert!(integrity_len >= size_of::<TOKEN_MANDATORY_LABEL>() as u32);
    let mut integrity = aligned_buffer(integrity_len);
    assert_ne!(
        unsafe {
            GetTokenInformation(
                duplicate.0,
                TOKEN_INFORMATION_CLASS::TokenIntegrityLevel,
                integrity.as_mut_ptr().cast(),
                integrity_len,
                &mut integrity_len,
            )
        },
        0
    );
    assert_ne!(
        unsafe {
            SetTokenInformation(
                duplicate.0,
                TOKEN_INFORMATION_CLASS::TokenIntegrityLevel,
                integrity.as_ptr().cast::<c_void>(),
                integrity_len,
            )
        },
        0,
        "SetTokenInformation failed: {}",
        unsafe { GetLastError() }
    );

    let mut thread_token = std::ptr::null_mut();
    unsafe { SetLastError(0) };
    assert_eq!(
        unsafe { OpenThreadToken(pseudo_thread, TOKEN_ALL_ACCESS, 1, &mut thread_token) },
        0
    );
    assert_eq!(unsafe { GetLastError() }, ERROR_NO_TOKEN);

    let mut revert = RevertGuard(false);
    assert_ne!(unsafe { ImpersonateLoggedOnUser(duplicate.0) }, 0);
    revert.0 = true;
    assert_ne!(
        unsafe { OpenThreadToken(pseudo_thread, TOKEN_ALL_ACCESS, 1, &mut thread_token) },
        0
    );
    let thread_token = OwnedHandle(thread_token);
    assert_ne!(unsafe { RevertToSelf() }, 0);
    revert.0 = false;
    drop(thread_token);

    assert_ne!(unsafe { SetThreadToken(std::ptr::null(), duplicate.0) }, 0);
    revert.0 = true;
    assert_ne!(unsafe { RevertToSelf() }, 0);
    revert.0 = false;
}
