//! Feature `eventlog` — Windows Event Log v6 (`Evt*` API).
//!
//! Covers what `windows-eventlog-native` needs: `EvtQuery` to open a
//! channel-path query, `EvtNext` to iterate event handles, `EvtRender` to
//! serialize an event to XML, `EvtClose` to release a handle.
//!
//! DLL: `wevtapi.dll` (loaded by the linker at startup).

use crate::foundation::{BOOL, PCWSTR};
use core::ffi::c_void;

/// `EVT_HANDLE` — opaque event / query / bookmark handle. Freed with [`EvtClose`].
pub type EVT_HANDLE = isize;

/// `NULL` event handle (per wevtapi.h — `EVT_HANDLE` is `HANDLE`-shaped but 0 is null).
pub const NULL_EVT_HANDLE: EVT_HANDLE = 0;

// ---- EVT_QUERY_FLAGS (wevtapi.h) ------------------------------------------

/// Query a channel by path (as opposed to a saved event log file / `EvtQueryFilePath`).
pub const EvtQueryChannelPath: u32 = 0x0000_0001;
/// Query a saved `.evtx` file rather than a live channel.
pub const EvtQueryFilePath: u32 = 0x0000_0002;
/// Iterate oldest → newest (default).
pub const EvtQueryForwardDirection: u32 = 0x0000_0100;
/// Iterate newest → oldest.
pub const EvtQueryReverseDirection: u32 = 0x0000_0200;
/// Skip records the log cannot parse rather than aborting the query.
pub const EvtQueryTolerateQueryErrors: u32 = 0x0000_1000;

// ---- EVT_RENDER_FLAGS (wevtapi.h) -----------------------------------------

/// Render as an array of typed variant values (RENDER_VARIANT array).
pub const EvtRenderEventValues: u32 = 0;
/// Render as a UTF-16 XML string.
pub const EvtRenderEventXml: u32 = 1;
/// Render a bookmark handle as XML.
pub const EvtRenderBookmark: u32 = 2;

// ---- Functions ------------------------------------------------------------

#[link(name = "wevtapi")]
extern "system" {
    /// `EvtQuery` — open a query on a channel path or saved-log file.
    /// Returns a query handle to feed to [`EvtNext`]. `Session` is `NULL` for
    /// local; remote sessions come from `EvtOpenSession` (not exposed here yet).
    pub fn EvtQuery(
        Session: EVT_HANDLE,
        Path: PCWSTR,
        Query: PCWSTR,
        Flags: u32,
    ) -> EVT_HANDLE;

    /// `EvtNext` — advance the query cursor, retrieving up to
    /// `EventsSize` event handles at once.
    pub fn EvtNext(
        ResultSet: EVT_HANDLE,
        EventsSize: u32,
        Events: *mut EVT_HANDLE,
        Timeout: u32,
        Flags: u32,
        Returned: *mut u32,
    ) -> BOOL;

    /// `EvtRender` — serialize an event (or bookmark) into `Buffer` at the requested `Flags`.
    /// If `BufferSize` is 0, fills `BufferUsed` with the required byte count.
    pub fn EvtRender(
        Context: EVT_HANDLE,
        Fragment: EVT_HANDLE,
        Flags: u32,
        BufferSize: u32,
        Buffer: *mut c_void,
        BufferUsed: *mut u32,
        PropertyCount: *mut u32,
    ) -> BOOL;

    /// `EvtClose` — release any `EVT_HANDLE` (query, event, session, bookmark, context).
    pub fn EvtClose(Object: EVT_HANDLE) -> BOOL;
}
