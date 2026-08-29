# Independent technical review

Independent review is requested before this ecosystem is described as mature.
A useful review may cover one lane; nobody is expected to audit every crate.
Positive and negative results are equally valuable when they include enough
evidence to reproduce them.

## Review lanes

1. **Windows ABI:** compare declarations, constants, calling conventions, and
   structure layouts with current Windows SDK headers on x86, x64, or ARM64.
   Start with `./scripts/verify-abi.ps1 -Arch <arch>` and extend `tests/sdk/abi.c`
   for any uncovered declaration.
2. **Unsafe contracts and ownership:** inspect public `unsafe` functions,
   buffer-size idioms, nullability, pointer lifetimes, and the exact close
   function used by every owned handle.
3. **Live Windows behavior:** reproduce feature tests on a clean Windows 10,
   Windows 11, Server, or native ARM64 host. Identify the elevation level and
   never use production services, registry keys, logs, or credentials.
4. **Hostile parsing:** review and fuzz `windows-sddl` self-relative security
   descriptors and `windows-eventlog-native` XML. Report corpus/crash details
   privately if they may be security-sensitive.
5. **Research workflows:** run the five read-only workflows and the standalone
   research kit, checking permission boundaries, cleanup, error semantics, and
   whether output supports real DFIR or identity work.
6. **Benchmark reproduction:** run `./benchmarks/compare.ps1` and compare the
   raw observations with the published baseline. Treat machine-specific timing
   differences as data, not automatically as defects.

## Evidence to return

- Repository and exact commit or crate version.
- Windows edition/build and target architecture.
- `rustc --version` and `cargo --version`.
- Commands, feature flags, privilege level, and whether a VM was used.
- Minimal output, added test, or SDK citation supporting the conclusion.
- Any relevant reviewer relationship or conflict of interest.

Submit non-sensitive results with the
[independent-review issue form](https://github.com/icedracon/win32-min/issues/new?template=independent-review.yml).
Potential vulnerabilities must instead use the private
[Report a vulnerability](https://github.com/icedracon/win32-min/security/advisories/new)
channel.

An issue opened by the maintainer is an invitation, not an independent review.
This gate is satisfied only by evidence from an unaffiliated reviewer or a
real downstream adopter.
