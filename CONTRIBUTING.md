# Contributing

Bug reports, Windows SDK corrections, focused bindings, tests, documentation,
and independent verification are welcome. Keep changes narrow: `win32-min` is
an intentionally small raw-FFI crate, not a generated replacement for the
Windows SDK.

## Report the right way

- Potential vulnerabilities must use GitHub's private
  [Report a vulnerability](https://github.com/icedracon/win32-min/security/advisories/new)
  channel. Do not publish exploit details in a public issue.
- Reproducible non-security defects can use a normal GitHub issue.
- Independent validation belongs in the
  [technical review form](https://github.com/icedracon/win32-min/issues/new?template=independent-review.yml).

Include the commit, Windows build, architecture, Rust version, exact commands,
and smallest useful output or reproducer. Redact credentials and machine- or
organization-specific identifiers.

## Development checks

Run the checks relevant to your change from Windows PowerShell:

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
./scripts/verify-safety-docs.ps1
./scripts/verify-zero-deps.ps1
cargo test --all-features
cargo test --no-default-features
cargo check --all-features --examples
$env:RUSTDOCFLAGS = '-D warnings -D missing-docs'
cargo doc --all-features --no-deps
Remove-Item Env:RUSTDOCFLAGS
cargo package
```

The repository's CI additionally checks Rust 1.74.1, x86, x64, ARM64, native
ARM64 execution, an elevated temporary-service lifecycle, and C-header ABI
conformance against the installed Windows SDK. Run the ABI check locally when
Visual Studio C++ tools are available:

```powershell
./scripts/verify-abi.ps1 -Arch x64
./scripts/verify-abi.ps1 -Arch x86
./scripts/verify-abi.ps1 -Arch arm64
```

## Pull requests

- Add or update a live or compile-time regression test for behavior changes.
- Preserve `extern "system"`, Windows SDK types, `#[repr(C)]` layouts, and
  explicit `# Safety` contracts on public FFI functions.
- Keep the root crate dependency-free and `no_std` compatible.
- Document feature/API additions in the README, `llms.txt`, and changelog when
  they change public discovery or usage.
- Do not combine unrelated formatting or generated-file churn with the change.

See [REVIEWING.md](REVIEWING.md) for bounded independent-review lanes and the
evidence expected for each.
