# Security Policy

## Supported Versions

yayatht is an experimental pre-1.0 project. Only the latest commit on the
default branch receives security fixes. Older commits, development branches,
and unlisted tags are not supported.

## Reporting a Vulnerability

Use GitHub Private Vulnerability Reporting:

1. Open the repository's **Security** tab.
2. Select **Advisories** and **Report a vulnerability**.
3. Include the affected revision, prerequisites, impact, reproduction steps,
   and any suggested mitigation.

Do not report suspected vulnerabilities in a public issue, discussion, pull
request, or test log. Avoid including real credentials, private network
details, or unrelated personal data in the report.

The maintainer will coordinate validation, remediation, and disclosure through
the private advisory. This project does not promise a fixed response or release
service level.

## Security Scope

The target command's filesystem is not isolated from files already accessible
to the invoking user. yayatht is not intended to execute untrusted commands or
to serve as a complete application sandbox. See the README's security model
before evaluating a report.
