//! Minimal DLL loading, module lookup, and symbol resolution primitives.

use core::ffi::c_void;

use crate::foundation::{BOOL, PCSTR, PCWSTR, PWSTR};

/// Opaque loaded-module handle.
pub type HMODULE = *mut c_void;

/// Untyped address of an exported function.
///
/// Consumers must cast this value to the exact exported signature before use.
pub type FARPROC = Option<unsafe extern "system" fn() -> isize>;

/// Null module handle.
pub const NULL_HMODULE: HMODULE = core::ptr::null_mut();

#[link(name = "kernel32")]
extern "system" {
    /// Returns a borrowed handle for a module loaded in the calling process.
    ///
    /// # Safety
    ///
    /// `lpModuleName` must be null or point to a readable null-terminated
    /// UTF-16 string. The returned handle is borrowed and must not be freed.
    pub fn GetModuleHandleW(lpModuleName: PCWSTR) -> HMODULE;

    /// Writes the path of a loaded module into a UTF-16 buffer.
    ///
    /// # Safety
    ///
    /// `hModule` must be null or a valid loaded-module handle. `lpFilename`
    /// must point to writable storage for `nSize` UTF-16 units.
    pub fn GetModuleFileNameW(hModule: HMODULE, lpFilename: PWSTR, nSize: u32) -> u32;

    /// Resolves an exported symbol from a loaded module.
    ///
    /// # Safety
    ///
    /// `hModule` must remain loaded and `lpProcName` must be a readable
    /// null-terminated ANSI name or a valid ordinal encoding. Any returned
    /// pointer must be called only with its exact ABI and signature.
    pub fn GetProcAddress(hModule: HMODULE, lpProcName: PCSTR) -> FARPROC;

    /// Loads a DLL into the calling process.
    ///
    /// # Safety
    ///
    /// `lpLibFileName` must be a readable null-terminated UTF-16 path. Loading
    /// executes loader behavior and possibly DLL initialization code. A
    /// successful returned handle owns one reference and must be freed once.
    pub fn LoadLibraryW(lpLibFileName: PCWSTR) -> HMODULE;

    /// Releases one reference to a loaded DLL.
    ///
    /// # Safety
    ///
    /// `hLibModule` must be a valid owned module reference not already freed.
    /// No code or data from the module may be used after its final unload.
    pub fn FreeLibrary(hLibModule: HMODULE) -> BOOL;
}
