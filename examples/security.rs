//! Convert a small SDDL string and inspect its owner and DACL pointers.

use win32_min::foundation::{BOOL, PCWSTR};
use win32_min::security::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityDescriptorDacl,
    GetSecurityDescriptorOwner, LocalFree, PSECURITY_DESCRIPTOR, PSID, SDDL_REVISION_1,
};
use win32_min::Win32Error;

fn main() -> Result<(), Win32Error> {
    let sddl: Vec<u16> = "O:BAG:BAD:(A;;GR;;;WD)\0".encode_utf16().collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = core::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            core::ptr::null_mut(),
        )
    } == 0
    {
        return Err(Win32Error::last());
    }

    let mut owner: PSID = core::ptr::null_mut();
    let mut owner_defaulted: BOOL = 0;
    let mut dacl = core::ptr::null_mut();
    let mut dacl_present: BOOL = 0;
    let mut dacl_defaulted: BOOL = 0;
    let ok = unsafe {
        GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) != 0
            && GetSecurityDescriptorDacl(
                descriptor,
                &mut dacl_present,
                &mut dacl,
                &mut dacl_defaulted,
            ) != 0
    };
    println!("owner={owner:?}, dacl_present={}", dacl_present != 0);
    unsafe {
        let _ = LocalFree(descriptor);
    }
    if ok {
        Ok(())
    } else {
        Err(Win32Error::last())
    }
}
