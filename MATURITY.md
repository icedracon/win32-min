# Maturity and release gates

`win32-min` is not currently described as a 10/10 ecosystem. That label is
earned by sustained evidence and independent use, not by a release number,
download count, maintainer-authored demo, or search position.

## Honest 10/10 gate

All of the following must be true at the same time:

| Gate | Required evidence | Current state (2026-08-30) |
| --- | --- | --- |
| Release correctness | Every published crate is unyanked, documented on docs.rs, and green at its exact release commit | Pass |
| ABI and architecture | Windows SDK probes on x86/x64/ARM64; x64 and native ARM64 runtime coverage | Pass |
| Windows behavior | Reproducible live evidence on Windows 10, Windows 11, and Windows Server, with privileged tests isolated to test-owned resources | Pass, but must remain green |
| Supply chain | No known unacknowledged RustSec advisory; pinned weekly audit and dependency monitoring | Pass, streak started 2026-08-29 |
| Hostile-input resilience | Scheduled parser fuzzing remains crash-free and regressions become permanent tests | Pass, streak started 2026-08-29 |
| Independent review | At least two unaffiliated reviewers cover different lanes, including one ABI/unsafe-code lane | Pending |
| Independent adoption | At least three verifiable downstream projects, with at least one using a safe companion crate | Pending |
| Maintenance record | Ninety days of weekly checks, release-head CI, and public issue triage without an unresolved critical/high defect | Pending |

A gate returns to pending when its evidence becomes stale or a material defect
invalidates it. Download traffic may be reported as reach, but never substitutes
for review or adoption because bots, mirrors, and CI can generate downloads.

## Discovery goal

Search ranking is tracked separately from quality. “Top 10” means a visible
top-ten result for at least three stable, high-intent queries relevant to the
actual scope, such as `win32 rust ffi`, `windows security research rust`, and
`rust dfir windows`. Broad queries such as `windows` are recorded but are not a
credible near-term gate.

The 2026-08-29 baseline was:

- crates.io `win32`: #4;
- crates.io `windows security research`: #1;
- crates.io `dfir`: #12;
- GitHub `win32 rust ffi`: #5;
- broad `windows ffi`, `windows security`, and `windows`: below #100.

Rank can move without a code change and does not prove reliability. Keywords,
topics, descriptions, `llms.txt`, and citations must remain accurate rather
than repeat irrelevant search terms.

## Version policy

- The `0.1.x` line receives compatible fixes, verification, documentation,
  workflows, and narrowly scoped additions.
- `0.2.0` is reserved for meaningful API or compatibility changes justified by
  independent review, downstream adoption, or a demonstrated design problem.
- No release is cut solely to refresh search indexes, increase download count,
  or claim maturity.

Weekly checks report registry/docs health, search position, CI/fuzz/audit
status, review evidence, downstream use, and the single best next action. The
maintainer should update this document only when evidence changes a gate.
