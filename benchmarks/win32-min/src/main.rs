fn main() {
    let pid = unsafe { win32_min::process::GetCurrentProcessId() };
    println!("{pid}");
}
