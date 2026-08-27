fn main() {
    let pid = unsafe { win32_min::process_thread::GetCurrentProcessId() };
    println!("{pid}");
}
