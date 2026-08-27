//! Compatibility module combining [`crate::process`] and [`crate::thread`].
//!
//! This module preserves the 0.1.1 path. New code should enable and import the
//! independently selectable `process` and `thread` features instead.

pub use crate::process::*;
pub use crate::thread::{
    GetCurrentThread, GetCurrentThreadId, GetThreadId, OpenThread, ResumeThread, SuspendThread,
    Thread32First, Thread32Next, THREADENTRY32, THREAD_ACCESS, THREAD_DIRECT_IMPERSONATION,
    THREAD_GET_CONTEXT, THREAD_IMPERSONATE, THREAD_QUERY_INFORMATION,
    THREAD_QUERY_LIMITED_INFORMATION, THREAD_SET_CONTEXT, THREAD_SET_INFORMATION,
    THREAD_SET_LIMITED_INFORMATION, THREAD_SET_THREAD_TOKEN, THREAD_SUSPEND_RESUME,
    THREAD_TERMINATE,
};
