//! Open the current process and print its executable path.

use win32_min::foundation::PWSTR;
use win32_min::handles::ProcessHandle;
use win32_min::process::{GetCurrentProcessId, QueryFullProcessImageNameW};
use win32_min::{process::PROCESS_QUERY_LIMITED_INFORMATION, Win32Error};

fn main() -> Result<(), Win32Error> {
    let process_id = unsafe { GetCurrentProcessId() };
    let process = ProcessHandle::open(process_id, PROCESS_QUERY_LIMITED_INFORMATION, false)?;
    let mut path = [0u16; 32_768];
    let mut len = path.len() as u32;
    if unsafe { QueryFullProcessImageNameW(process.raw(), 0, PWSTR(path.as_mut_ptr()), &mut len) }
        == 0
    {
        return Err(Win32Error::last());
    }
    println!("{}", String::from_utf16_lossy(&path[..len as usize]));
    Ok(())
}
