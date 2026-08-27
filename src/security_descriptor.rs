//! Feature `security-descriptor` — ACL and security-descriptor primitives.
//!
//! The functions here expose raw Win32 ownership rules. In particular, buffers
//! returned by the SDDL conversion and `Get*SecurityInfo` APIs must be released
//! with [`LocalFree`]. Safe ownership belongs in a higher-level companion crate.

use crate::foundation::{BOOL, HANDLE, PCWSTR, PWSTR};
use core::ffi::c_void;

pub type PSID = *mut c_void;
pub type PSECURITY_DESCRIPTOR = *mut c_void;
pub type HLOCAL = *mut c_void;
pub type SECURITY_DESCRIPTOR_CONTROL = u16;
pub type SECURITY_INFORMATION = u32;

pub const NULL_PSID: PSID = core::ptr::null_mut();
pub const NULL_PACL: *mut ACL = core::ptr::null_mut();
pub const NULL_SECURITY_DESCRIPTOR: PSECURITY_DESCRIPTOR = core::ptr::null_mut();

pub const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
pub const SDDL_REVISION_1: u32 = 1;

// SECURITY_DESCRIPTOR_CONTROL flags (winnt.h).
pub const SE_OWNER_DEFAULTED: SECURITY_DESCRIPTOR_CONTROL = 0x0001;
pub const SE_GROUP_DEFAULTED: SECURITY_DESCRIPTOR_CONTROL = 0x0002;
pub const SE_DACL_PRESENT: SECURITY_DESCRIPTOR_CONTROL = 0x0004;
pub const SE_DACL_DEFAULTED: SECURITY_DESCRIPTOR_CONTROL = 0x0008;
pub const SE_SACL_PRESENT: SECURITY_DESCRIPTOR_CONTROL = 0x0010;
pub const SE_SACL_DEFAULTED: SECURITY_DESCRIPTOR_CONTROL = 0x0020;
pub const SE_DACL_AUTO_INHERIT_REQ: SECURITY_DESCRIPTOR_CONTROL = 0x0100;
pub const SE_SACL_AUTO_INHERIT_REQ: SECURITY_DESCRIPTOR_CONTROL = 0x0200;
pub const SE_DACL_AUTO_INHERITED: SECURITY_DESCRIPTOR_CONTROL = 0x0400;
pub const SE_SACL_AUTO_INHERITED: SECURITY_DESCRIPTOR_CONTROL = 0x0800;
pub const SE_DACL_PROTECTED: SECURITY_DESCRIPTOR_CONTROL = 0x1000;
pub const SE_SACL_PROTECTED: SECURITY_DESCRIPTOR_CONTROL = 0x2000;
pub const SE_SELF_RELATIVE: SECURITY_DESCRIPTOR_CONTROL = 0x8000;

// SECURITY_INFORMATION flags (winnt.h).
pub const OWNER_SECURITY_INFORMATION: SECURITY_INFORMATION = 0x0000_0001;
pub const GROUP_SECURITY_INFORMATION: SECURITY_INFORMATION = 0x0000_0002;
pub const DACL_SECURITY_INFORMATION: SECURITY_INFORMATION = 0x0000_0004;
pub const SACL_SECURITY_INFORMATION: SECURITY_INFORMATION = 0x0000_0008;
pub const LABEL_SECURITY_INFORMATION: SECURITY_INFORMATION = 0x0000_0010;
pub const ATTRIBUTE_SECURITY_INFORMATION: SECURITY_INFORMATION = 0x0000_0020;
pub const SCOPE_SECURITY_INFORMATION: SECURITY_INFORMATION = 0x0000_0040;
pub const PROCESS_TRUST_LABEL_SECURITY_INFORMATION: SECURITY_INFORMATION = 0x0000_0080;
pub const ACCESS_FILTER_SECURITY_INFORMATION: SECURITY_INFORMATION = 0x0000_0100;
pub const BACKUP_SECURITY_INFORMATION: SECURITY_INFORMATION = 0x0001_0000;
pub const UNPROTECTED_SACL_SECURITY_INFORMATION: SECURITY_INFORMATION = 0x1000_0000;
pub const UNPROTECTED_DACL_SECURITY_INFORMATION: SECURITY_INFORMATION = 0x2000_0000;
pub const PROTECTED_SACL_SECURITY_INFORMATION: SECURITY_INFORMATION = 0x4000_0000;
pub const PROTECTED_DACL_SECURITY_INFORMATION: SECURITY_INFORMATION = 0x8000_0000;

/// Object kinds accepted by the `Get*SecurityInfo` family.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SE_OBJECT_TYPE {
    SE_UNKNOWN_OBJECT_TYPE = 0,
    SE_FILE_OBJECT = 1,
    SE_SERVICE = 2,
    SE_PRINTER = 3,
    SE_REGISTRY_KEY = 4,
    SE_LMSHARE = 5,
    SE_KERNEL_OBJECT = 6,
    SE_WINDOW_OBJECT = 7,
    SE_DS_OBJECT = 8,
    SE_DS_OBJECT_ALL = 9,
    SE_PROVIDER_DEFINED_OBJECT = 10,
    SE_WMIGUID_OBJECT = 11,
    SE_REGISTRY_WOW64_32KEY = 12,
    SE_REGISTRY_WOW64_64KEY = 13,
}

/// Fixed header of a Windows ACL.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ACL {
    pub AclRevision: u8,
    pub Sbz1: u8,
    pub AclSize: u16,
    pub AceCount: u16,
    pub Sbz2: u16,
}

/// Header common to every ACE variant.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ACE_HEADER {
    pub AceType: u8,
    pub AceFlags: u8,
    pub AceSize: u16,
}

/// Self-relative security descriptor header. Offset fields are byte offsets
/// from the beginning of the descriptor, not pointers.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SECURITY_DESCRIPTOR_RELATIVE {
    pub Revision: u8,
    pub Sbz1: u8,
    pub Control: SECURITY_DESCRIPTOR_CONTROL,
    pub Owner: u32,
    pub Group: u32,
    pub Sacl: u32,
    pub Dacl: u32,
}

#[link(name = "advapi32")]
extern "system" {
    pub fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        StringSecurityDescriptor: PCWSTR,
        StringSDRevision: u32,
        SecurityDescriptor: *mut PSECURITY_DESCRIPTOR,
        SecurityDescriptorSize: *mut u32,
    ) -> BOOL;

    pub fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
        SecurityDescriptor: PSECURITY_DESCRIPTOR,
        RequestedStringSDRevision: u32,
        SecurityInformation: SECURITY_INFORMATION,
        StringSecurityDescriptor: *mut PWSTR,
        StringSecurityDescriptorLen: *mut u32,
    ) -> BOOL;

    pub fn GetNamedSecurityInfoW(
        pObjectName: PWSTR,
        ObjectType: SE_OBJECT_TYPE,
        SecurityInfo: SECURITY_INFORMATION,
        ppsidOwner: *mut PSID,
        ppsidGroup: *mut PSID,
        ppDacl: *mut *mut ACL,
        ppSacl: *mut *mut ACL,
        ppSecurityDescriptor: *mut PSECURITY_DESCRIPTOR,
    ) -> u32;

    pub fn SetNamedSecurityInfoW(
        pObjectName: PWSTR,
        ObjectType: SE_OBJECT_TYPE,
        SecurityInfo: SECURITY_INFORMATION,
        psidOwner: PSID,
        psidGroup: PSID,
        pDacl: *mut ACL,
        pSacl: *mut ACL,
    ) -> u32;

    pub fn GetSecurityInfo(
        handle: HANDLE,
        ObjectType: SE_OBJECT_TYPE,
        SecurityInfo: SECURITY_INFORMATION,
        ppsidOwner: *mut PSID,
        ppsidGroup: *mut PSID,
        ppDacl: *mut *mut ACL,
        ppSacl: *mut *mut ACL,
        ppSecurityDescriptor: *mut PSECURITY_DESCRIPTOR,
    ) -> u32;

    pub fn SetSecurityInfo(
        handle: HANDLE,
        ObjectType: SE_OBJECT_TYPE,
        SecurityInfo: SECURITY_INFORMATION,
        psidOwner: PSID,
        psidGroup: PSID,
        pDacl: *mut ACL,
        pSacl: *mut ACL,
    ) -> u32;

    pub fn IsValidSecurityDescriptor(pSecurityDescriptor: PSECURITY_DESCRIPTOR) -> BOOL;
    pub fn GetSecurityDescriptorLength(pSecurityDescriptor: PSECURITY_DESCRIPTOR) -> u32;
}

#[link(name = "kernel32")]
extern "system" {
    pub fn LocalFree(hMem: HLOCAL) -> HLOCAL;
}

const _: () = {
    assert!(core::mem::size_of::<ACL>() == 8);
    assert!(core::mem::align_of::<ACL>() == 2);
    assert!(core::mem::size_of::<ACE_HEADER>() == 4);
    assert!(core::mem::align_of::<ACE_HEADER>() == 2);
    assert!(core::mem::size_of::<SECURITY_DESCRIPTOR_RELATIVE>() == 20);
    assert!(core::mem::align_of::<SECURITY_DESCRIPTOR_RELATIVE>() == 4);
};
