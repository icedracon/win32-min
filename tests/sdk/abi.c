#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <stddef.h>
#include <tlhelp32.h>
#include <winevt.h>

#define ABI_ASSERT(name, expression) \
    typedef char abi_assert_##name[(expression) ? 1 : -1]

ABI_ASSERT(bool_size, sizeof(BOOL) == 4);
ABI_ASSERT(luid_size, sizeof(LUID) == 8);
ABI_ASSERT(luid_high_offset, offsetof(LUID, HighPart) == 4);
ABI_ASSERT(guid_size, sizeof(GUID) == 16);
ABI_ASSERT(filetime_size, sizeof(FILETIME) == 8);
ABI_ASSERT(unicode_string_length_offset, offsetof(UNICODE_STRING, Length) == 0);
ABI_ASSERT(unicode_string_maximum_length_offset,
           offsetof(UNICODE_STRING, MaximumLength) == 2);

ABI_ASSERT(token_all_access_value, TOKEN_ALL_ACCESS == 0x000F01FF);
ABI_ASSERT(token_privileges_size, sizeof(TOKEN_PRIVILEGES) == 16);
ABI_ASSERT(token_privileges_array_offset,
           offsetof(TOKEN_PRIVILEGES, Privileges) == 4);
ABI_ASSERT(sid_identifier_authority_size,
           sizeof(SID_IDENTIFIER_AUTHORITY) == 6);
ABI_ASSERT(sid_subauthority_offset, offsetof(SID, SubAuthority) == 8);

ABI_ASSERT(service_status_size, sizeof(SERVICE_STATUS) == 28);
ABI_ASSERT(service_status_process_size, sizeof(SERVICE_STATUS_PROCESS) == 36);
ABI_ASSERT(service_status_process_pid_offset,
           offsetof(SERVICE_STATUS_PROCESS, dwProcessId) == 28);

ABI_ASSERT(thread_entry_size, sizeof(THREADENTRY32) == 28);
ABI_ASSERT(thread_entry_id_offset, offsetof(THREADENTRY32, th32ThreadID) == 8);
ABI_ASSERT(thread_entry_flags_offset, offsetof(THREADENTRY32, dwFlags) == 24);
ABI_ASSERT(process_information_process_id_offset,
           offsetof(PROCESS_INFORMATION, dwProcessId) == (sizeof(void *) * 2));

ABI_ASSERT(file_attribute_data_size,
           sizeof(WIN32_FILE_ATTRIBUTE_DATA) == 36);
ABI_ASSERT(file_attribute_size_high_offset,
           offsetof(WIN32_FILE_ATTRIBUTE_DATA, nFileSizeHigh) == 28);
ABI_ASSERT(by_handle_file_information_size,
           sizeof(BY_HANDLE_FILE_INFORMATION) == 52);
ABI_ASSERT(by_handle_file_index_low_offset,
           offsetof(BY_HANDLE_FILE_INFORMATION, nFileIndexLow) == 48);
ABI_ASSERT(open_existing_value, OPEN_EXISTING == 3);
ABI_ASSERT(file_open_reparse_value,
           FILE_FLAG_OPEN_REPARSE_POINT == 0x00200000);

ABI_ASSERT(acl_size, sizeof(ACL) == 8);
ABI_ASSERT(acl_ace_count_offset, offsetof(ACL, AceCount) == 4);
ABI_ASSERT(ace_header_size, sizeof(ACE_HEADER) == 4);
ABI_ASSERT(sd_relative_size, sizeof(SECURITY_DESCRIPTOR_RELATIVE) == 20);
ABI_ASSERT(sd_relative_owner_offset,
           offsetof(SECURITY_DESCRIPTOR_RELATIVE, Owner) == 4);
ABI_ASSERT(sd_relative_dacl_offset,
           offsetof(SECURITY_DESCRIPTOR_RELATIVE, Dacl) == 16);
ABI_ASSERT(se_self_relative_value, SE_SELF_RELATIVE == 0x8000);
ABI_ASSERT(dacl_security_information_value,
           DACL_SECURITY_INFORMATION == 0x00000004);
ABI_ASSERT(access_allowed_ace_size, sizeof(ACCESS_ALLOWED_ACE) == 12);
ABI_ASSERT(access_denied_ace_size, sizeof(ACCESS_DENIED_ACE) == 12);
ABI_ASSERT(generic_mapping_size, sizeof(GENERIC_MAPPING) == 16);
ABI_ASSERT(privilege_set_size, sizeof(PRIVILEGE_SET) == 20);
ABI_ASSERT(sid_size, sizeof(SID) == 12);

ABI_ASSERT(key_read_value, KEY_READ == 0x00020019);
ABI_ASSERT(key_all_access_value, KEY_ALL_ACCESS == 0x000F003F);
ABI_ASSERT(reg_qword_value, REG_QWORD == 11);
ABI_ASSERT(evt_handle_pointer_size, sizeof(EVT_HANDLE) == sizeof(void *));

#ifdef _WIN64
ABI_ASSERT(unicode_string_size_x64, sizeof(UNICODE_STRING) == 16);
ABI_ASSERT(unicode_string_buffer_offset_x64,
           offsetof(UNICODE_STRING, Buffer) == 8);
ABI_ASSERT(security_attributes_size_x64, sizeof(SECURITY_ATTRIBUTES) == 24);
ABI_ASSERT(process_entry_size_x64, sizeof(PROCESSENTRY32W) == 568);
ABI_ASSERT(process_entry_heap_offset_x64,
           offsetof(PROCESSENTRY32W, th32DefaultHeapID) == 16);
ABI_ASSERT(process_entry_name_offset_x64,
           offsetof(PROCESSENTRY32W, szExeFile) == 44);
ABI_ASSERT(process_information_size_x64, sizeof(PROCESS_INFORMATION) == 24);
ABI_ASSERT(security_descriptor_size_x64, sizeof(SECURITY_DESCRIPTOR) == 40);
ABI_ASSERT(security_descriptor_owner_offset_x64,
           offsetof(SECURITY_DESCRIPTOR, Owner) == 8);
ABI_ASSERT(enum_service_status_size_x64,
           sizeof(ENUM_SERVICE_STATUS_PROCESSW) == 56);
ABI_ASSERT(lsa_string_size_x64, sizeof(LSA_STRING) == 16);
#else
ABI_ASSERT(unicode_string_size_x86, sizeof(UNICODE_STRING) == 8);
ABI_ASSERT(unicode_string_buffer_offset_x86,
           offsetof(UNICODE_STRING, Buffer) == 4);
ABI_ASSERT(security_attributes_size_x86, sizeof(SECURITY_ATTRIBUTES) == 12);
ABI_ASSERT(process_entry_size_x86, sizeof(PROCESSENTRY32W) == 556);
ABI_ASSERT(process_entry_heap_offset_x86,
           offsetof(PROCESSENTRY32W, th32DefaultHeapID) == 12);
ABI_ASSERT(process_entry_name_offset_x86,
           offsetof(PROCESSENTRY32W, szExeFile) == 36);
ABI_ASSERT(process_information_size_x86, sizeof(PROCESS_INFORMATION) == 16);
ABI_ASSERT(security_descriptor_size_x86, sizeof(SECURITY_DESCRIPTOR) == 20);
ABI_ASSERT(security_descriptor_owner_offset_x86,
           offsetof(SECURITY_DESCRIPTOR, Owner) == 4);
ABI_ASSERT(enum_service_status_size_x86,
           sizeof(ENUM_SERVICE_STATUS_PROCESSW) == 44);
ABI_ASSERT(lsa_string_size_x86, sizeof(LSA_STRING) == 8);
#endif

int main(void) { return 0; }
