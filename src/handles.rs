//! Small subsystem-specific owned-handle wrappers.
//!
//! Kernel handles, registry keys, and SCM handles deliberately use different
//! wrappers because Windows requires different close functions for them.

use core::mem::ManuallyDrop;

use crate::foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
#[cfg(any(
    feature = "process",
    feature = "thread",
    feature = "security-token",
    feature = "registry",
    feature = "services"
))]
use crate::Win32Error;

#[cfg(any(feature = "registry", feature = "services"))]
const ERROR_INVALID_PARAMETER: u32 = 87;

/// An owned Win32 kernel handle closed with `CloseHandle`.
#[derive(Debug)]
pub struct Handle {
    raw: HANDLE,
}

impl Handle {
    /// Takes ownership of a valid closeable kernel handle.
    ///
    /// # Safety
    ///
    /// `raw` must be a valid owned kernel handle, not a pseudo-handle, registry
    /// key, SCM handle, module handle, or other resource with a different close
    /// function. Ownership must not be duplicated elsewhere.
    pub unsafe fn from_raw(raw: HANDLE) -> Self {
        Self { raw }
    }

    /// Returns the borrowed raw handle without transferring ownership.
    pub const fn raw(&self) -> HANDLE {
        self.raw
    }

    /// Returns whether the handle is neither null nor `INVALID_HANDLE_VALUE`.
    pub fn is_valid(&self) -> bool {
        !self.raw.is_null() && self.raw != INVALID_HANDLE_VALUE
    }

    /// Transfers ownership to the caller without closing the handle.
    pub fn into_raw(self) -> HANDLE {
        let this = ManuallyDrop::new(self);
        this.raw
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if self.is_valid() {
            unsafe {
                let _ = CloseHandle(self.raw);
            }
        }
    }
}

#[cfg(any(feature = "process", feature = "thread", feature = "security-token"))]
macro_rules! kernel_handle_wrapper {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Debug)]
        pub struct $name(Handle);

        impl $name {
            /// Takes ownership of a valid handle of this resource type.
            ///
            /// # Safety
            ///
            /// `raw` must be valid, closeable with `CloseHandle`, uniquely
            /// owned by the caller, and of the resource type represented here.
            pub unsafe fn from_raw(raw: HANDLE) -> Self {
                Self(unsafe { Handle::from_raw(raw) })
            }

            /// Returns the borrowed raw handle.
            pub const fn raw(&self) -> HANDLE {
                self.0.raw()
            }

            /// Reports whether the raw value is a valid owned handle value.
            pub fn is_valid(&self) -> bool {
                self.0.is_valid()
            }

            /// Transfers ownership to the caller without closing the handle.
            pub fn into_raw(self) -> HANDLE {
                self.0.into_raw()
            }
        }
    };
}

#[cfg(feature = "process")]
kernel_handle_wrapper!(ProcessHandle, "An owned process handle.");

#[cfg(feature = "process")]
impl ProcessHandle {
    /// Opens a process by identifier.
    pub fn open(
        process_id: u32,
        desired_access: crate::process::PROCESS_ACCESS,
        inherit: bool,
    ) -> Result<Self, Win32Error> {
        let raw =
            unsafe { crate::process::OpenProcess(desired_access, inherit as i32, process_id) };
        if raw.is_null() {
            Err(Win32Error::last())
        } else {
            Ok(unsafe { Self::from_raw(raw) })
        }
    }

    /// Returns the process identifier associated with this handle.
    pub fn id(&self) -> Result<u32, Win32Error> {
        let id = unsafe { crate::process::GetProcessId(self.raw()) };
        if id == 0 {
            Err(Win32Error::last())
        } else {
            Ok(id)
        }
    }
}

#[cfg(feature = "thread")]
kernel_handle_wrapper!(ThreadHandle, "An owned thread handle.");

#[cfg(feature = "thread")]
impl ThreadHandle {
    /// Opens a thread by identifier.
    pub fn open(
        thread_id: u32,
        desired_access: crate::thread::THREAD_ACCESS,
        inherit: bool,
    ) -> Result<Self, Win32Error> {
        let raw = unsafe { crate::thread::OpenThread(desired_access, inherit as i32, thread_id) };
        if raw.is_null() {
            Err(Win32Error::last())
        } else {
            Ok(unsafe { Self::from_raw(raw) })
        }
    }

    /// Returns the thread identifier associated with this handle.
    pub fn id(&self) -> Result<u32, Win32Error> {
        let id = unsafe { crate::thread::GetThreadId(self.raw()) };
        if id == 0 {
            Err(Win32Error::last())
        } else {
            Ok(id)
        }
    }
}

#[cfg(feature = "security-token")]
kernel_handle_wrapper!(TokenHandle, "An owned access-token handle.");

#[cfg(feature = "security-token")]
impl TokenHandle {
    /// Opens the current process token.
    pub fn open_current_process(desired_access: u32) -> Result<Self, Win32Error> {
        let mut raw = core::ptr::null_mut();
        let ok = unsafe {
            crate::security_token::OpenProcessToken(
                crate::security_token::GetCurrentProcess(),
                desired_access,
                &mut raw,
            )
        };
        if ok == 0 {
            Err(Win32Error::last())
        } else {
            Ok(unsafe { Self::from_raw(raw) })
        }
    }

    /// Opens the primary token of an owned process handle.
    #[cfg(feature = "process")]
    pub fn open(process: &ProcessHandle, desired_access: u32) -> Result<Self, Win32Error> {
        let mut raw = core::ptr::null_mut();
        let ok = unsafe {
            crate::security_token::OpenProcessToken(process.raw(), desired_access, &mut raw)
        };
        if ok == 0 {
            Err(Win32Error::last())
        } else {
            Ok(unsafe { Self::from_raw(raw) })
        }
    }
}

#[cfg(feature = "registry")]
/// An owned registry key closed with `RegCloseKey`.
#[derive(Debug)]
pub struct RegistryKey {
    raw: crate::registry::HKEY,
}

#[cfg(feature = "registry")]
impl RegistryKey {
    /// Takes ownership of a closeable registry-key handle.
    ///
    /// # Safety
    ///
    /// `raw` must be a valid, uniquely owned key returned by a registry open or
    /// create API. Predefined `HKEY_*` values must not be wrapped as owned.
    pub unsafe fn from_raw(raw: crate::registry::HKEY) -> Self {
        Self { raw }
    }

    /// Opens a child of this key.
    pub fn open(&self, sub_key: &[u16], desired_access: u32) -> Result<Self, Win32Error> {
        Self::open_raw(self.raw, sub_key, desired_access)
    }

    /// Opens a key relative to `HKEY_CURRENT_USER`.
    pub fn open_current_user(sub_key: &[u16], desired_access: u32) -> Result<Self, Win32Error> {
        Self::open_raw(crate::registry::HKEY_CURRENT_USER, sub_key, desired_access)
    }

    fn open_raw(
        parent: crate::registry::HKEY,
        sub_key: &[u16],
        desired_access: u32,
    ) -> Result<Self, Win32Error> {
        if sub_key.last() != Some(&0) {
            return Err(Win32Error::from_raw(ERROR_INVALID_PARAMETER));
        }
        let mut raw = core::ptr::null_mut();
        let status = unsafe {
            crate::registry::RegOpenKeyExW(
                parent,
                crate::foundation::PCWSTR(sub_key.as_ptr()),
                0,
                desired_access,
                &mut raw,
            )
        };
        if status != 0 {
            Err(Win32Error::from_raw(status as u32))
        } else {
            Ok(unsafe { Self::from_raw(raw) })
        }
    }

    /// Returns the borrowed raw key handle.
    pub const fn raw(&self) -> crate::registry::HKEY {
        self.raw
    }

    /// Reports whether the key handle is non-null.
    pub fn is_valid(&self) -> bool {
        !self.raw.is_null()
    }

    /// Transfers ownership to the caller without closing the key.
    pub fn into_raw(self) -> crate::registry::HKEY {
        let this = ManuallyDrop::new(self);
        this.raw
    }
}

#[cfg(feature = "registry")]
impl Drop for RegistryKey {
    fn drop(&mut self) {
        if self.is_valid() {
            unsafe {
                let _ = crate::registry::RegCloseKey(self.raw);
            }
        }
    }
}

#[cfg(feature = "services")]
/// An owned Service Control Manager or service handle.
#[derive(Debug)]
pub struct ServiceHandle {
    raw: crate::services::SC_HANDLE,
}

#[cfg(feature = "services")]
impl ServiceHandle {
    /// Takes ownership of a closeable SCM handle.
    ///
    /// # Safety
    ///
    /// `raw` must be valid, uniquely owned, and closeable exactly once with
    /// `CloseServiceHandle`.
    pub unsafe fn from_raw(raw: crate::services::SC_HANDLE) -> Self {
        Self { raw }
    }

    /// Opens the local Service Control Manager database.
    pub fn open_manager(desired_access: u32) -> Result<Self, Win32Error> {
        let raw = unsafe {
            crate::services::OpenSCManagerW(
                crate::foundation::PCWSTR::NULL,
                crate::foundation::PCWSTR::NULL,
                desired_access,
            )
        };
        if raw.is_null() {
            Err(Win32Error::last())
        } else {
            Ok(unsafe { Self::from_raw(raw) })
        }
    }

    /// Opens a service by its null-terminated UTF-16 name.
    pub fn open(&self, service_name: &[u16], desired_access: u32) -> Result<Self, Win32Error> {
        if service_name.last() != Some(&0) {
            return Err(Win32Error::from_raw(ERROR_INVALID_PARAMETER));
        }
        let raw = unsafe {
            crate::services::OpenServiceW(
                self.raw,
                crate::foundation::PCWSTR(service_name.as_ptr()),
                desired_access,
            )
        };
        if raw.is_null() {
            Err(Win32Error::last())
        } else {
            Ok(unsafe { Self::from_raw(raw) })
        }
    }

    /// Returns the borrowed raw SCM handle.
    pub const fn raw(&self) -> crate::services::SC_HANDLE {
        self.raw
    }

    /// Reports whether the SCM handle is non-null.
    pub fn is_valid(&self) -> bool {
        !self.raw.is_null()
    }

    /// Transfers ownership to the caller without closing the handle.
    pub fn into_raw(self) -> crate::services::SC_HANDLE {
        let this = ManuallyDrop::new(self);
        this.raw
    }
}

#[cfg(feature = "services")]
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if self.is_valid() {
            unsafe {
                let _ = crate::services::CloseServiceHandle(self.raw);
            }
        }
    }
}
