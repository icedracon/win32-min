#![cfg(all(windows, feature = "eventlog"))]

use std::ffi::c_void;

use win32_min::eventlog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection,
    EvtQueryTolerateQueryErrors, EvtRender, EvtRenderEventXml, EVT_HANDLE, NULL_EVT_HANDLE,
};
use win32_min::foundation::{GetLastError, PCWSTR};

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

struct EventHandles {
    query: EVT_HANDLE,
    event: EVT_HANDLE,
}

impl Drop for EventHandles {
    fn drop(&mut self) {
        unsafe {
            if self.event != NULL_EVT_HANDLE {
                let _ = EvtClose(self.event);
            }
            if self.query != NULL_EVT_HANDLE {
                let _ = EvtClose(self.query);
            }
        }
    }
}

#[test]
fn query_next_render_and_close_application_event() {
    let channel = wide("Application");
    let query = wide("*");
    let mut handles = EventHandles {
        query: unsafe {
            EvtQuery(
                NULL_EVT_HANDLE,
                PCWSTR(channel.as_ptr()),
                PCWSTR(query.as_ptr()),
                EvtQueryChannelPath | EvtQueryReverseDirection | EvtQueryTolerateQueryErrors,
            )
        },
        event: NULL_EVT_HANDLE,
    };
    assert_ne!(
        handles.query,
        NULL_EVT_HANDLE,
        "EvtQuery failed: {}",
        unsafe { GetLastError() }
    );

    let mut returned = 0u32;
    assert_ne!(
        unsafe {
            EvtNext(
                handles.query,
                1,
                &mut handles.event,
                5_000,
                0,
                &mut returned,
            )
        },
        0,
        "EvtNext failed: {}",
        unsafe { GetLastError() }
    );
    assert_eq!(returned, 1);
    assert_ne!(handles.event, NULL_EVT_HANDLE);

    let mut bytes_used = 0u32;
    let mut property_count = 0u32;
    assert_eq!(
        unsafe {
            EvtRender(
                NULL_EVT_HANDLE,
                handles.event,
                EvtRenderEventXml,
                0,
                std::ptr::null_mut(),
                &mut bytes_used,
                &mut property_count,
            )
        },
        0
    );
    assert_eq!(unsafe { GetLastError() }, ERROR_INSUFFICIENT_BUFFER);
    assert!(bytes_used >= 2);

    let mut xml = vec![0u16; (bytes_used as usize).div_ceil(2)];
    assert_ne!(
        unsafe {
            EvtRender(
                NULL_EVT_HANDLE,
                handles.event,
                EvtRenderEventXml,
                bytes_used,
                xml.as_mut_ptr() as *mut c_void,
                &mut bytes_used,
                &mut property_count,
            )
        },
        0,
        "EvtRender failed: {}",
        unsafe { GetLastError() }
    );
    let nul = xml
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(xml.len());
    let xml = String::from_utf16(&xml[..nul]).expect("EventLog XML is UTF-16");
    assert!(xml.starts_with("<Event"), "{xml}");
    assert!(xml.contains("<System>"), "{xml}");

    assert_ne!(unsafe { EvtClose(handles.event) }, 0);
    handles.event = NULL_EVT_HANDLE;
    assert_ne!(unsafe { EvtClose(handles.query) }, 0);
    handles.query = NULL_EVT_HANDLE;
}
