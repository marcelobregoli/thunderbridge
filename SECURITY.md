# Security status

**Do not use this fork with a real Proton account yet.**

Audit performed on 2026-11-24 with cargo-audit against the checked-in
Cargo.lock. After updating the ordinary dependencies, two advisories remain:

- RUSTSEC-2026-0387 — crypto-bigint 0.5.5: timing variability in operations
  intended to be constant-time. The current proton-srp and OpenPGP dependency
  graph still requires this major version.
- RUSTSEC-2023-0071 — rsa 0.9.10: Marvin timing side-channel. The current
  pgp 0.21.1 dependency still requires this major version.

The patched versions require dependency/API changes upstream. This fork does not
attempt to implement cryptographic fixes locally. A successful compile does not
mitigate either advisory.

Additional limits:

- The upstream project has no automated tests; the test command reports zero tests.
- Proton's web API is unofficial and may change or reject third-party clients.
- This project is not endorsed or supported by Proton AG.
- Never treat this bridge as the only copy of mail. Keep Proton web access and
  independent mail backups available.

Hardening already applied on the opti/free-plan-hardening branch includes
owner-only local session/TLS-key permissions, TLS-only listeners when --tls is
used, bounded protocol input, nonce-protected CAPTCHA callback, redacted token
output, and secret-buffer zeroization. These measures do not resolve the two
cryptographic advisories above.
