//! Zero-allocation Win32 error support.

use core::ffi::c_void;
use core::fmt::{self, Write};

use crate::foundation::{GetLastError, PWSTR};

const FORMAT_MESSAGE_IGNORE_INSERTS: u32 = 0x0000_0200;
const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x0000_1000;
const ERROR_INVALID_PARAMETER: u32 = 87;

#[link(name = "kernel32")]
extern "system" {
    fn FormatMessageW(
        dwFlags: u32,
        lpSource: *const c_void,
        dwMessageId: u32,
        dwLanguageId: u32,
        lpBuffer: PWSTR,
        nSize: u32,
        Arguments: *const c_void,
    ) -> u32;
}

/// A raw Win32 error code with zero-allocation message formatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Win32Error(u32);

impl Win32Error {
    /// Captures the calling thread's current `GetLastError` value.
    pub fn last() -> Self {
        Self(unsafe { GetLastError() })
    }

    /// Constructs an error from a raw Win32 code.
    pub const fn from_raw(code: u32) -> Self {
        Self(code)
    }

    /// Returns the numeric Win32 error code.
    pub const fn code(self) -> u32 {
        self.0
    }

    /// Returns the unmodified numeric representation.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Formats the system message into caller-provided UTF-16 storage.
    ///
    /// The returned slice borrows `buffer`, excludes the terminating null, and
    /// trims Windows' trailing CR/LF characters. This method allocates nothing.
    pub fn message(self, buffer: &mut [u16]) -> Result<&[u16], Self> {
        let capacity = u32::try_from(buffer.len()).map_err(|_| Self(ERROR_INVALID_PARAMETER))?;
        if capacity == 0 {
            return Err(Self(ERROR_INVALID_PARAMETER));
        }

        let written = unsafe {
            FormatMessageW(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                core::ptr::null(),
                self.0,
                0,
                PWSTR(buffer.as_mut_ptr()),
                capacity,
                core::ptr::null(),
            )
        };
        if written == 0 {
            return Err(Self::last());
        }

        let mut len = written as usize;
        while len > 0 && matches!(buffer[len - 1], 0 | 10 | 13) {
            len -= 1;
        }
        Ok(&buffer[..len])
    }
}

impl fmt::Display for Win32Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buffer = [0u16; 512];
        if let Ok(message) = self.message(&mut buffer) {
            for item in core::char::decode_utf16(message.iter().copied()) {
                formatter.write_char(item.unwrap_or(core::char::REPLACEMENT_CHARACTER))?;
            }
            write!(formatter, " (Win32 error {})", self.0)
        } else {
            write!(formatter, "Win32 error {}", self.0)
        }
    }
}

impl From<u32> for Win32Error {
    fn from(code: u32) -> Self {
        Self::from_raw(code)
    }
}

impl From<Win32Error> for u32 {
    fn from(error: Win32Error) -> Self {
        error.raw()
    }
}
