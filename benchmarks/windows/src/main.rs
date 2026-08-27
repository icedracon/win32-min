fn main() {
    let pid = unsafe { windows::Win32::System::Threading::GetCurrentProcessId() };
    println!("{pid}");
}
