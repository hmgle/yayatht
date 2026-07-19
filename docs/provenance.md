# Provenance

The yayatht implementation is independently structured from public protocol
specifications, Linux UAPI documentation, and black-box interoperability tests.

The primary behavioral reference is the `proxy-dev` branch of
[hmgle/passt](https://github.com/hmgle/passt) at commit
[`c7568f543bdf69684e175b237298fb444c51669d`](https://github.com/hmgle/passt/commit/c7568f543bdf69684e175b237298fb444c51669d).
It was reviewed for behavior and architecture, not translated line by line.

- Relevant reference files: `.github/README.md`, `tcp.c`, `tcp_conn.h`,
  `tap.c`, `packet.c`, `pasta.c`, `netlink.c`, `arp.c`, and `ndp.c`.
- Those files are generally `GPL-2.0-or-later`; `checksum.c` also carries a
  BSD-3-Clause component.

Separately built comparison and interoperability tools were pinned to these
revisions during development:

- Official [passt](https://passt.top/passt), commit
  `6ef3d1c86ffc690a17a9a4445df4a741446bcd44`.
- [nlzy/nsproxy](https://github.com/nlzy/nsproxy), commit
  `2029a6257f53aef19451ac99fb5e160f76f7c179`.
- [OkamiW/proxy-ns](https://github.com/OkamiW/proxy-ns), commit
  `5d08d18f9171d7e65fabad06ee81021d9bca0a21`.

No source or test vectors from `nsproxy` or `proxy-ns` are copied into
yayatht. In particular, `nsproxy` is GPL-2.0-only and is used only as a
separately built interoperability oracle.
