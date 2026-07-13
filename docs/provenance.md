# Provenance

The implementation is independently structured from public specifications,
Linux UAPI documentation and black-box tests.

The following source tree is used as a behavioral reference, not translated
line-by-line:

- `passt-github`, branch `proxy-dev`, commit
  `c7568f543bdf69684e175b237298fb444c51669d`.
- Relevant reference files: `.github/README.md`, `tcp.c`, `tcp_conn.h`,
  `tap.c`, `packet.c`, `pasta.c`, `netlink.c`, `arp.c`, and `ndp.c`.
- Those files are generally `GPL-2.0-or-later`; `checksum.c` also carries a
  BSD-3-Clause component.

No source or test vector from `nsproxy` is copied because its code is
GPL-2.0-only. It may be used as a separately built interoperability oracle.
