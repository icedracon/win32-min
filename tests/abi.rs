use core::mem::{align_of, size_of, MaybeUninit};

macro_rules! offset_of {
    ($ty:ty, $field:ident) => {{
        let uninit = MaybeUninit::<$ty>::uninit();
        let base = uninit.as_ptr();
        // SAFETY: `addr_of!` forms a field pointer without reading or creating
        // a reference to the uninitialized value.
        unsafe { core::ptr::addr_of!((*base).$field) as usize - base as usize }
    }};
}

#[test]
fn foundation_layout_matches_windows_sdk() {
    use win32_min::foundation::{FILETIME, GUID, LUID, SECURITY_ATTRIBUTES, UNICODE_STRING};

    assert_eq!(size_of::<LUID>(), 8);
    assert_eq!(align_of::<LUID>(), 4);
    assert_eq!(offset_of!(LUID, HighPart), 4);

    assert_eq!(size_of::<GUID>(), 16);
    assert_eq!(align_of::<GUID>(), 4);
    assert_eq!(offset_of!(GUID, Data4), 8);

    assert_eq!(size_of::<FILETIME>(), 8);
    assert_eq!(align_of::<FILETIME>(), 4);
    assert_eq!(offset_of!(FILETIME, dwHighDateTime), 4);

    #[cfg(target_pointer_width = "64")]
    {
        assert_eq!(size_of::<UNICODE_STRING>(), 16);
        assert_eq!(align_of::<UNICODE_STRING>(), 8);
        assert_eq!(offset_of!(UNICODE_STRING, Buffer), 8);
        assert_eq!(size_of::<SECURITY_ATTRIBUTES>(), 24);
        assert_eq!(offset_of!(SECURITY_ATTRIBUTES, lpSecurityDescriptor), 8);
        assert_eq!(offset_of!(SECURITY_ATTRIBUTES, bInheritHandle), 16);
    }

    #[cfg(target_pointer_width = "32")]
    {
        assert_eq!(size_of::<UNICODE_STRING>(), 8);
        assert_eq!(align_of::<UNICODE_STRING>(), 4);
        assert_eq!(offset_of!(UNICODE_STRING, Buffer), 4);
        assert_eq!(size_of::<SECURITY_ATTRIBUTES>(), 12);
        assert_eq!(offset_of!(SECURITY_ATTRIBUTES, lpSecurityDescriptor), 4);
        assert_eq!(offset_of!(SECURITY_ATTRIBUTES, bInheritHandle), 8);
    }
}

#[test]
fn counted_string_constructors_are_checked() {
    use win32_min::foundation::UNICODE_STRING;

    let mut utf16 = [b'A' as u16, b'B' as u16];
    let value = UNICODE_STRING::try_from_slice(&mut utf16).expect("small string is valid");
    assert_eq!(value.Length, 4);
    assert_eq!(value.MaximumLength, 4);

    let mut oversized = vec![0u16; UNICODE_STRING::MAX_CODE_UNITS + 1];
    assert!(UNICODE_STRING::try_from_slice(&mut oversized).is_none());
}

#[cfg(feature = "lsa-auth")]
#[test]
fn lsa_string_constructor_is_checked() {
    use win32_min::lsa_auth::LSA_STRING;

    let mut package = *b"Kerberos";
    let value = LSA_STRING::try_from_slice(&mut package).expect("small string is valid");
    assert_eq!(value.Length, 8);

    let mut oversized = vec![0u8; LSA_STRING::MAX_BYTES + 1];
    assert!(LSA_STRING::try_from_slice(&mut oversized).is_none());
}

#[cfg(feature = "security-token")]
#[test]
fn token_constants_and_layout_match_windows_sdk() {
    use win32_min::security_token::{
        LUID_AND_ATTRIBUTES, SID, SID_IDENTIFIER_AUTHORITY, TOKEN_ALL_ACCESS,
        TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_USER,
    };

    assert_eq!(TOKEN_ALL_ACCESS, 0x000f_01ff);
    assert_eq!(size_of::<LUID_AND_ATTRIBUTES>(), 12);
    assert_eq!(offset_of!(LUID_AND_ATTRIBUTES, Attributes), 8);
    assert_eq!(size_of::<SID_IDENTIFIER_AUTHORITY>(), 6);
    assert_eq!(offset_of!(SID, IdentifierAuthority), 2);
    assert_eq!(offset_of!(SID, SubAuthority), 8);
    assert_eq!(size_of::<TOKEN_PRIVILEGES>(), 16);
    assert_eq!(offset_of!(TOKEN_PRIVILEGES, Privileges), 4);

    #[cfg(target_pointer_width = "64")]
    {
        assert_eq!(size_of::<TOKEN_USER>(), 16);
        assert_eq!(size_of::<TOKEN_MANDATORY_LABEL>(), 16);
    }

    #[cfg(target_pointer_width = "32")]
    {
        assert_eq!(size_of::<TOKEN_USER>(), 8);
        assert_eq!(size_of::<TOKEN_MANDATORY_LABEL>(), 8);
    }
}

#[cfg(feature = "services")]
#[test]
fn service_layout_matches_windows_sdk() {
    use win32_min::services::{
        ENUM_SERVICE_STATUS_PROCESSW, SERVICE_STATUS, SERVICE_STATUS_PROCESS,
    };

    assert_eq!(size_of::<SERVICE_STATUS>(), 28);
    assert_eq!(size_of::<SERVICE_STATUS_PROCESS>(), 36);
    assert_eq!(offset_of!(SERVICE_STATUS_PROCESS, dwProcessId), 28);

    #[cfg(target_pointer_width = "64")]
    {
        assert_eq!(size_of::<ENUM_SERVICE_STATUS_PROCESSW>(), 56);
        assert_eq!(
            offset_of!(ENUM_SERVICE_STATUS_PROCESSW, ServiceStatusProcess),
            16
        );
    }

    #[cfg(target_pointer_width = "32")]
    {
        assert_eq!(size_of::<ENUM_SERVICE_STATUS_PROCESSW>(), 44);
        assert_eq!(
            offset_of!(ENUM_SERVICE_STATUS_PROCESSW, ServiceStatusProcess),
            8
        );
    }
}

#[cfg(feature = "process-thread")]
#[test]
fn process_thread_layout_matches_windows_sdk() {
    use win32_min::process_thread::{PROCESSENTRY32W, THREADENTRY32};

    assert_eq!(size_of::<THREADENTRY32>(), 28);
    assert_eq!(offset_of!(THREADENTRY32, th32ThreadID), 8);
    assert_eq!(offset_of!(THREADENTRY32, dwFlags), 24);

    #[cfg(target_pointer_width = "64")]
    {
        assert_eq!(size_of::<PROCESSENTRY32W>(), 568);
        assert_eq!(align_of::<PROCESSENTRY32W>(), 8);
        assert_eq!(offset_of!(PROCESSENTRY32W, th32DefaultHeapID), 16);
        assert_eq!(offset_of!(PROCESSENTRY32W, szExeFile), 44);
    }

    #[cfg(target_pointer_width = "32")]
    {
        assert_eq!(size_of::<PROCESSENTRY32W>(), 556);
        assert_eq!(align_of::<PROCESSENTRY32W>(), 4);
        assert_eq!(offset_of!(PROCESSENTRY32W, th32DefaultHeapID), 12);
        assert_eq!(offset_of!(PROCESSENTRY32W, szExeFile), 36);
    }
}

#[cfg(feature = "security-descriptor")]
#[test]
fn security_descriptor_layout_and_constants_match_windows_sdk() {
    use win32_min::security_descriptor::{
        ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        SECURITY_DESCRIPTOR_RELATIVE, SE_SELF_RELATIVE,
    };

    assert_eq!(size_of::<ACL>(), 8);
    assert_eq!(align_of::<ACL>(), 2);
    assert_eq!(offset_of!(ACL, AceCount), 4);
    assert_eq!(size_of::<ACE_HEADER>(), 4);
    assert_eq!(offset_of!(ACE_HEADER, AceSize), 2);
    assert_eq!(size_of::<SECURITY_DESCRIPTOR_RELATIVE>(), 20);
    assert_eq!(offset_of!(SECURITY_DESCRIPTOR_RELATIVE, Owner), 4);
    assert_eq!(offset_of!(SECURITY_DESCRIPTOR_RELATIVE, Dacl), 16);
    assert_eq!(SE_SELF_RELATIVE, 0x8000);
    assert_eq!(DACL_SECURITY_INFORMATION, 0x0000_0004);
    assert_eq!(PROTECTED_DACL_SECURITY_INFORMATION, 0x8000_0000);
}

#[cfg(feature = "registry")]
#[test]
fn registry_constants_match_windows_sdk() {
    use win32_min::registry::{HKEY_CURRENT_USER, KEY_ALL_ACCESS, KEY_READ, REG_DWORD, REG_QWORD};

    assert_eq!(KEY_READ, 0x0002_0019);
    assert_eq!(KEY_ALL_ACCESS, 0x000f_003f);
    assert_eq!(REG_DWORD, 4);
    assert_eq!(REG_QWORD, 11);
    assert_eq!(HKEY_CURRENT_USER as isize, -2_147_483_647isize);
}
