# win32-min research kit

A read-only end-to-end demonstration of the published `win32-min` companion
ecosystem. It inventories the current identity, local services, current
Kerberos cache, recent Application events, and a generated security descriptor.

```powershell
cargo run --manifest-path research-kit/Cargo.toml
```

Run on Windows with Rust 1.85 or newer. Administrator access is not required
for the default Application-channel query. Missing Kerberos context or access
to an individual subsystem is reported without preventing the other probes.

The demo does not enable privileges, alter impersonation state, control
services, extract tickets, clear logs, or change a security descriptor.
