# Contributing to yayatht

Thank you for contributing to yayatht. The project welcomes bug reports,
documentation improvements, tests, and focused code changes.

## Before You Start

- Search existing issues before opening a new one.
- Use GitHub Private Vulnerability Reporting for security issues. Do not
  disclose vulnerabilities in a public issue; see [SECURITY.md](SECURITY.md).
- Discuss large protocol, architecture, security-boundary, or scope changes in
  an issue before investing in an implementation.

## Development Environment

Development requires Linux 6.6 or newer, unprivileged user namespaces, and
`/dev/net/tun`. The workspace uses Rust 2024 and has a minimum supported Rust
version of 1.93.

Clone the repository and verify the workspace:

```sh
cargo check --workspace --all-targets
cargo test --workspace -- --test-threads=1
```

The rootless integration suite changes network namespaces and must run
serially. Proxy-related tests should clearly state any external proxy, DNS,
host routing, or TUN assumptions.

## Code Style

- Use standard `rustfmt` formatting and Rust naming conventions.
- Keep Linux-specific `unsafe` blocks narrow and document their safety
  invariants.
- Keep warnings clean under the workspace's strict Clippy policy.
- Add behavior-based tests beside changed logic and integration tests for CLI
  or namespace behavior.
- Preserve the SPDX copyright and license header in source files.

Before submitting a pull request, run:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace -- --test-threads=1
cargo check --workspace --all-targets
cargo deny check
```

If `cargo-deny` is not installed locally, note that in the pull request and
let CI perform the check.

## Pull Requests

Keep commits focused and use concise, imperative, capitalized subjects.
Explain non-obvious design decisions in the commit body or pull request.

Pull requests should:

- describe user-visible and internal behavior changes;
- list the commands used for verification;
- identify kernel, privilege, architecture, or networking assumptions;
- document compatibility implications and remaining risks;
- identify any code, test vectors, or ideas derived from another project.

## Licensing

Unless explicitly stated otherwise, every contribution intentionally submitted
for inclusion in yayatht is licensed under `GPL-3.0-only`, without additional
terms or conditions. By submitting a contribution, you confirm that you have
the right to license it on those terms.
