//! Read and render one event from the Application channel.

use win32_min::eventlog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtRender, EvtRenderEventXml, NULL_EVT_HANDLE,
};
use win32_min::foundation::{PCWSTR, PWSTR};
use win32_min::Win32Error;

fn main() -> Result<(), Win32Error> {
    let channel: Vec<u16> = "Application\0".encode_utf16().collect();
    let query: Vec<u16> = "*\0".encode_utf16().collect();
    let result = unsafe {
        EvtQuery(
            NULL_EVT_HANDLE,
            PCWSTR(channel.as_ptr()),
            PCWSTR(query.as_ptr()),
            EvtQueryChannelPath,
        )
    };
    if result == NULL_EVT_HANDLE {
        return Err(Win32Error::last());
    }

    let mut event = NULL_EVT_HANDLE;
    let next_ok = unsafe { EvtNext(result, 1, &mut event, 0, 0, core::ptr::null_mut()) };
    if next_ok == 0 {
        unsafe {
            let _ = EvtClose(result);
        }
        return Err(Win32Error::last());
    }

    let mut used = 0u32;
    let mut properties = 0u32;
    unsafe {
        let _ = EvtRender(
            NULL_EVT_HANDLE,
            event,
            EvtRenderEventXml,
            0,
            PWSTR::NULL.0.cast(),
            &mut used,
            &mut properties,
        );
    }
    let mut bytes = vec![0u8; used as usize];
    let render_ok = unsafe {
        EvtRender(
            NULL_EVT_HANDLE,
            event,
            EvtRenderEventXml,
            used,
            bytes.as_mut_ptr().cast(),
            &mut used,
            &mut properties,
        )
    };
    unsafe {
        let _ = EvtClose(event);
        let _ = EvtClose(result);
    }
    if render_ok == 0 {
        return Err(Win32Error::last());
    }
    let words =
        unsafe { core::slice::from_raw_parts(bytes.as_ptr().cast::<u16>(), used as usize / 2) };
    let end = words
        .iter()
        .position(|word| *word == 0)
        .unwrap_or(words.len());
    println!("{}", String::from_utf16_lossy(&words[..end]));
    Ok(())
}
