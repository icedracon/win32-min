//! Open and query the built-in Windows Event Log service.

use win32_min::handles::ServiceHandle;
use win32_min::services::{
    QueryServiceStatus, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS, SERVICE_STATUS,
};
use win32_min::Win32Error;

fn main() -> Result<(), Win32Error> {
    let manager = ServiceHandle::open_manager(SC_MANAGER_CONNECT)?;
    let name: Vec<u16> = "EventLog\0".encode_utf16().collect();
    let service = manager.open(&name, SERVICE_QUERY_STATUS)?;
    let mut status = unsafe { core::mem::zeroed::<SERVICE_STATUS>() };
    if unsafe { QueryServiceStatus(service.raw(), &mut status) } == 0 {
        return Err(Win32Error::last());
    }
    println!("EventLog service state: {}", status.dwCurrentState);
    Ok(())
}
