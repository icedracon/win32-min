#![cfg(all(windows, feature = "lsa-auth"))]

use std::ffi::c_void;
use std::mem::size_of;

use win32_min::foundation::{HANDLE, LUID, STATUS_SUCCESS};
use win32_min::lsa_auth::{
    LsaCallAuthenticationPackage, LsaConnectUntrusted, LsaDeregisterLogonProcess,
    LsaFreeReturnBuffer, LsaLookupAuthenticationPackage, LSA_STRING,
};

// A local account (including the OpenSSH account used by the Windows 10 VM)
// can have no Kerberos logon session at all.  The authentication-package call
// itself still succeeds, while Kerberos reports this package-specific status.
const STATUS_NO_SUCH_LOGON_SESSION: i32 = 0xC000_005Fu32 as i32;

#[repr(C)]
struct KerbQueryTicketCacheRequest {
    message_type: u32,
    logon_id: LUID,
}

struct LsaGuard {
    handle: HANDLE,
    buffer: *mut c_void,
}

impl Drop for LsaGuard {
    fn drop(&mut self) {
        unsafe {
            if !self.buffer.is_null() {
                let _ = LsaFreeReturnBuffer(self.buffer);
            }
            if !self.handle.is_null() {
                let _ = LsaDeregisterLogonProcess(self.handle);
            }
        }
    }
}

#[test]
fn untrusted_kerberos_ticket_cache_query_lifecycle() {
    let mut guard = LsaGuard {
        handle: std::ptr::null_mut(),
        buffer: std::ptr::null_mut(),
    };
    assert_eq!(
        unsafe { LsaConnectUntrusted(&mut guard.handle) },
        STATUS_SUCCESS
    );
    assert!(!guard.handle.is_null());

    let mut package_name = *b"Kerberos";
    let package_name = LSA_STRING::from_slice(&mut package_name);
    let mut package_id = 0u32;
    assert_eq!(
        unsafe { LsaLookupAuthenticationPackage(guard.handle, &package_name, &mut package_id) },
        STATUS_SUCCESS
    );
    assert_ne!(package_id, 0);

    // KerbQueryTicketCacheMessage is value 1 in KERB_PROTOCOL_MESSAGE_TYPE.
    // An all-zero LUID asks an untrusted client for its current logon session.
    let request = KerbQueryTicketCacheRequest {
        message_type: 1,
        logon_id: LUID {
            LowPart: 0,
            HighPart: 0,
        },
    };
    let mut return_len = 0u32;
    let mut protocol_status = -1;
    assert_eq!(
        unsafe {
            LsaCallAuthenticationPackage(
                guard.handle,
                package_id,
                &request as *const _ as *const c_void,
                size_of::<KerbQueryTicketCacheRequest>() as u32,
                &mut guard.buffer,
                &mut return_len,
                &mut protocol_status,
            )
        },
        STATUS_SUCCESS
    );
    match protocol_status {
        STATUS_SUCCESS => {
            assert!(!guard.buffer.is_null());
            assert!(return_len >= size_of::<u32>() as u32);
            assert_eq!(unsafe { LsaFreeReturnBuffer(guard.buffer) }, STATUS_SUCCESS);
            guard.buffer = std::ptr::null_mut();
        }
        STATUS_NO_SUCH_LOGON_SESSION => {
            assert!(guard.buffer.is_null());
            assert_eq!(return_len, 0);
        }
        status => panic!("unexpected Kerberos protocol status: {status:#010x}"),
    }
    assert_eq!(
        unsafe { LsaDeregisterLogonProcess(guard.handle) },
        STATUS_SUCCESS
    );
    guard.handle = std::ptr::null_mut();
}
