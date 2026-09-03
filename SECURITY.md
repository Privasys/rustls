# Security Policy

This repository is the **Privasys fork of rustls**. It adds the RA-TLS challenge
extension (0xFFBB) and the RA-TLS channel binding used by the Privasys platform.
It is maintained by Privasys, not by the rustls project.

## Reporting a vulnerability

**Do not report vulnerabilities in this fork to the rustls project.** They do not
accept reports for forks, and the code that differs from upstream is ours.

Report privately, one of:

- GitHub private vulnerability reporting on this repository:
  https://github.com/Privasys/rustls/security/advisories/new
- Email: security@privasys.org

We acknowledge reports within three business days and keep you informed until
the issue is fixed and disclosed. Please include the release tag
(`privasys-vX.Y.Z`) or commit you tested against.

If your finding concerns rustls itself rather than the Privasys changes, please
follow the upstream policy at https://github.com/rustls/rustls/security/policy.

## Supported versions

Only the latest `privasys-v*` release tag on the `privasys` branch is supported.
The `main` branch mirrors upstream rustls and carries no Privasys changes.
