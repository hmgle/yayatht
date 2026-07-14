# Repository Guidelines

## Project Structure & Module Organization

This Rust 2024 workspace implements a rootless Linux namespace TCP proxy. The binary is in `crates/cli`; supporting crates are:

- `namespace`: lifecycle and supervision.
- `dataplane`: packet processing and reactor.
- `packet`: Ethernet, IP, TCP, and neighbor parsing.
- `tcp-adapter`: TCP flow state and timers.
- `sys`: TUN, netlink, sockets, and process control.
- `test-support`: integration-test helpers.

Unit tests live beside code in `#[cfg(test)]` modules. Rootless end-to-end tests are in `crates/cli/tests/rootless.rs`; design notes are in `docs/`.

## Build, Test, and Development Commands

- `cargo build --release`: build the optimized binary.
- `cargo test --workspace -- --test-threads=1`: run tests serially, matching CI.
- `cargo fmt --all --check`: verify Rust formatting; run `cargo fmt --all` to apply fixes.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: enforce the workspace's strict Clippy policy.
- `cargo check --workspace --all-targets`: type-check all targets.
- `cargo deny check`: validate supply-chain policy when installed.

Development and integration testing require Linux 5.11+, unprivileged user namespaces, and `/dev/net/tun`.

## Reference Design & Network Environment

The original design is `/home/gle/tmp/ext4/data/ubuntu_backup/code_repo/tcp_x/proxy_x/rproxy-ns/docs/rust-namespace-proxy-design.md`; consult it before changing architecture, protocol state machines, security boundaries, or scope. The local pasta reference source is `/home/gle/tmp/ext4/data/ubuntu_backup/code_repo/tcp_x/proxy_x/passt-github`, with proxy usage documented in `.github/README.md`. Treat pasta as a behavioral/design reference and follow `docs/provenance.md` before reusing implementation details.

Reference repositories used by the phase 1A audit, with the exact revisions recorded in `docs/phase1a-exit-audit.md`, are available at:

- Official pasta (`6ef3d1c86ffc690a17a9a4445df4a741446bcd44`): `/tmp/passt-upstream-review`
- proxy-dev pasta (`c7568f543bdf69684e175b237298fb444c51669d`): `/home/gle/tmp/ext4/data/ubuntu_backup/code_repo/tcp_x/proxy_x/passt-github`
- nsproxy (`2029a6257f53aef19451ac99fb5e160f76f7c179`): `/home/gle/tmp/ext4/data/ubuntu_backup/code_repo/tcp_x/proxy_x/nsproxy`
- proxy-ns (`5d08d18f9171d7e65fabad06ee81021d9bca0a21`): `/home/gle/tmp/ext4/data/ubuntu_backup/code_repo/tcp_x/proxy_x/proxy-ns`

Unless a task states otherwise, the host network runs under mihomo TUN mode. Use the SOCKS5 endpoint `127.0.0.1:7890` for proxy-related runs and tests, and record deviations from this environment when reporting results. Distinguish failures caused by yayatht from routing or DNS behavior introduced by the host TUN layer.

### Comparator Harness Compatibility

The comparator CLIs are not interchangeable. Before changing benchmark command construction, check the exact pinned binary's `--help` output.

- proxy-dev pasta at `c7568f5` does not support `-c`. Configure it with `--proxy`, `--proxy-type`, `--proxy-user`, and `--proxy-passwd`. Never pass the generated proxy-ns JSON file to this backend.
- proxy-ns at `5d08d18` expects `-c <generated-private-json>` even when relevant values are overridden on the command line. The Phase 1A harness creates this file with mode 0600.
- A backend that exits before the transfer with no usable diagnostics is unavailable, not a zero-throughput result. Do not grant host file capabilities only to make a comparator run.
- The corrected backend-specific command construction is in `scripts/bench_tcp_phase1a.py`; do not reintroduce a shared `-c` option across proxy-dev and proxy-ns.

## Coding Style & Naming Conventions

Use standard `rustfmt` output (four-space indentation). Follow Rust naming conventions: `snake_case` for modules, functions, and tests; `UpperCamelCase` for types and traits; `SCREAMING_SNAKE_CASE` for constants. Keep system-specific `unsafe` blocks narrow and documented. Workspace lints deny all Clippy warnings and `unsafe_op_in_unsafe_fn`, so add targeted allowances only with a clear reason.

## Testing Guidelines

Add unit tests beside changed logic and integration tests for CLI or namespace behavior. Use behavior-based names such as `retransmit_advances_sequence`. Run the serial workspace suite before submission; there is no numeric coverage threshold.

## Commit & Pull Request Guidelines

History is minimal; the existing commit uses a concise, imperative, capitalized subject (`Implement ...`). Keep commits atomic and explain non-obvious design decisions. Pull requests should summarize changes, list verification commands, link issues, and state kernel, privilege, or networking assumptions. Include logs for CLI changes; screenshots are generally unnecessary.
