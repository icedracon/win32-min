#![cfg(all(windows, feature = "process", feature = "thread"))]

use std::mem::{size_of, zeroed};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};

use win32_min::foundation::{CloseHandle, GetLastError, SetLastError, INVALID_HANDLE_VALUE};
use win32_min::process_thread::{
    CreateToolhelp32Snapshot, GetCurrentProcess, GetCurrentProcessId, GetCurrentThread,
    GetCurrentThreadId, GetExitCodeProcess, GetProcessId, GetThreadId, OpenProcess, OpenThread,
    Process32FirstW, Process32NextW, QueryFullProcessImageNameW, ResumeThread, SuspendThread,
    TerminateProcess, Thread32First, Thread32Next, PROCESSENTRY32W,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, STILL_ACTIVE, TH32CS_SNAPPROCESS,
    TH32CS_SNAPTHREAD, THREADENTRY32, THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
};

struct ChildGuard(Option<Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn suspends_and_resumes_only_a_test_owned_thread() {
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let (sender, receiver) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        sender.send(unsafe { GetCurrentThreadId() }).unwrap();
        while !worker_stop.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
    });
    let thread_id = receiver.recv().unwrap();
    let handle = unsafe {
        OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
            0,
            thread_id,
        )
    };
    assert!(!handle.is_null());
    assert_ne!(unsafe { SuspendThread(handle) }, u32::MAX);
    assert_ne!(unsafe { ResumeThread(handle) }, u32::MAX);
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
    assert_ne!(unsafe { CloseHandle(handle) }, 0);
}

#[test]
fn foundation_last_error_round_trip() {
    const SENTINEL: u32 = 0x5a17_c0de;
    unsafe { SetLastError(SENTINEL) };
    assert_eq!(unsafe { GetLastError() }, SENTINEL);
}

#[test]
fn current_process_and_thread_handles_round_trip() {
    let pid = unsafe { GetCurrentProcessId() };
    let tid = unsafe { GetCurrentThreadId() };
    assert_ne!(pid, 0);
    assert_ne!(tid, 0);

    let pseudo_process = unsafe { GetCurrentProcess() };
    let pseudo_thread = unsafe { GetCurrentThread() };
    assert_eq!(unsafe { GetProcessId(pseudo_process) }, pid);
    assert_eq!(unsafe { GetThreadId(pseudo_thread) }, tid);

    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    assert!(!process.is_null(), "OpenProcess failed: {}", unsafe {
        GetLastError()
    });
    assert_eq!(unsafe { GetProcessId(process) }, pid);

    let thread = unsafe { OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, tid) };
    assert!(!thread.is_null(), "OpenThread failed: {}", unsafe {
        GetLastError()
    });
    assert_eq!(unsafe { GetThreadId(thread) }, tid);

    assert_ne!(unsafe { CloseHandle(thread) }, 0);
    assert_ne!(unsafe { CloseHandle(process) }, 0);
}

#[test]
fn resolves_current_process_image_path() {
    let process =
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, GetCurrentProcessId()) };
    assert!(!process.is_null());

    let mut buffer = vec![0u16; 32_768];
    let mut len = buffer.len() as u32;
    let ok = unsafe {
        QueryFullProcessImageNameW(
            process,
            0,
            win32_min::foundation::PWSTR(buffer.as_mut_ptr()),
            &mut len,
        )
    };
    assert_ne!(ok, 0, "QueryFullProcessImageNameW failed: {}", unsafe {
        GetLastError()
    });
    assert!(len > 4);

    let path = String::from_utf16(&buffer[..len as usize]).expect("valid Windows path");
    assert!(path.to_ascii_lowercase().ends_with(".exe"), "{path}");
    assert_ne!(unsafe { CloseHandle(process) }, 0);
}

#[test]
fn toolhelp_enumerates_current_process_and_thread() {
    let pid = unsafe { GetCurrentProcessId() };
    let tid = unsafe { GetCurrentThreadId() };

    let process_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    assert_ne!(process_snapshot, INVALID_HANDLE_VALUE);
    let mut process_entry: PROCESSENTRY32W = unsafe { zeroed() };
    process_entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    assert_ne!(
        unsafe { Process32FirstW(process_snapshot, &mut process_entry) },
        0
    );
    let mut found_process = false;
    let mut process_count = 0usize;
    loop {
        process_count += 1;
        found_process |= process_entry.th32ProcessID == pid;
        if unsafe { Process32NextW(process_snapshot, &mut process_entry) } == 0 {
            break;
        }
    }
    assert!(found_process);
    assert!(process_count > 1);
    assert_ne!(unsafe { CloseHandle(process_snapshot) }, 0);

    let thread_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    assert_ne!(thread_snapshot, INVALID_HANDLE_VALUE);
    let mut thread_entry: THREADENTRY32 = unsafe { zeroed() };
    thread_entry.dwSize = size_of::<THREADENTRY32>() as u32;
    assert_ne!(
        unsafe { Thread32First(thread_snapshot, &mut thread_entry) },
        0
    );
    let mut found_thread = false;
    let mut thread_count = 0usize;
    loop {
        thread_count += 1;
        found_thread |= thread_entry.th32ThreadID == tid && thread_entry.th32OwnerProcessID == pid;
        if unsafe { Thread32Next(thread_snapshot, &mut thread_entry) } == 0 {
            break;
        }
    }
    assert!(found_thread);
    assert!(thread_count > 1);
    assert_ne!(unsafe { CloseHandle(thread_snapshot) }, 0);
}

#[test]
fn terminates_only_the_child_process_created_by_the_test() {
    let child = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Sleep -Seconds 30",
        ])
        .spawn()
        .expect("spawn isolated child process");
    let child_pid = child.id();
    let mut child = ChildGuard(Some(child));

    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
            0,
            child_pid,
        )
    };
    assert!(!process.is_null(), "OpenProcess failed: {}", unsafe {
        GetLastError()
    });

    let mut exit_code = 0u32;
    assert_ne!(unsafe { GetExitCodeProcess(process, &mut exit_code) }, 0);
    assert_eq!(exit_code, STILL_ACTIVE);

    const TEST_EXIT_CODE: u32 = 123;
    assert_ne!(unsafe { TerminateProcess(process, TEST_EXIT_CODE) }, 0);
    let status = child.0.as_mut().unwrap().wait().expect("wait for child");
    assert_eq!(status.code(), Some(TEST_EXIT_CODE as i32));

    assert_ne!(unsafe { GetExitCodeProcess(process, &mut exit_code) }, 0);
    assert_eq!(exit_code, TEST_EXIT_CODE);
    assert_ne!(unsafe { CloseHandle(process) }, 0);
    child.0 = None;
}
