//! Query metadata for `HKEY_CURRENT_USER\Software`.

use win32_min::foundation::PWSTR;
use win32_min::handles::RegistryKey;
use win32_min::registry::{RegQueryInfoKeyW, KEY_READ};
use win32_min::Win32Error;

fn main() -> Result<(), Win32Error> {
    let software: Vec<u16> = "Software\0".encode_utf16().collect();
    let key = RegistryKey::open_current_user(&software, KEY_READ)?;
    let mut subkeys = 0u32;
    let mut values = 0u32;
    let status = unsafe {
        RegQueryInfoKeyW(
            key.raw(),
            PWSTR::NULL,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &mut subkeys,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &mut values,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(Win32Error::from_raw(status as u32));
    }
    println!("Software: {subkeys} subkeys, {values} values");
    Ok(())
}
