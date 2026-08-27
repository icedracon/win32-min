//! Open the calling process token and perform a two-call user query.

use core::ffi::c_void;

use win32_min::handles::TokenHandle;
use win32_min::security_token::{
    GetTokenInformation, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER,
};
use win32_min::Win32Error;

fn main() -> Result<(), Win32Error> {
    let token = TokenHandle::open_current_process(TOKEN_QUERY)?;
    let mut required = 0u32;
    unsafe {
        let _ = GetTokenInformation(
            token.raw(),
            TOKEN_INFORMATION_CLASS::TokenUser,
            core::ptr::null_mut(),
            0,
            &mut required,
        );
    }
    if required < core::mem::size_of::<TOKEN_USER>() as u32 {
        return Err(Win32Error::last());
    }

    let mut buffer = vec![0u8; required as usize];
    if unsafe {
        GetTokenInformation(
            token.raw(),
            TOKEN_INFORMATION_CLASS::TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(Win32Error::last());
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    println!("token user SID pointer: {:?}", user.User.Sid);
    Ok(())
}
