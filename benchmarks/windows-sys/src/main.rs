fn main() {
    let pid = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() };
    println!("{pid}");
}
