# Security status

**Dependency security checks: clear as of 2026-11-24. Live Proton-account use is
still gated on an end-to-end account test.**

## Cryptographic dependency replacement

The previous Rust-only crypto chain was removed:

- The pgp 0.21.x crate is no longer in the dependency graph.
- rsa 0.9.10 is no longer in the dependency graph.
- crypto-bigint is now 0.7.11 through Proton proton-srp 0.9.0.
- SRP modulus signatures and all OpenPGP operations use Proton's
  gopenpgp-sys 0.3.10 / GopenPGP Go backend.

The local vendored gopenpgp-sys copy is from ProtonMail/proton-crypto-rs
(MIT). Its Go dependencies were updated to golang.org/x/crypto 0.59.0 and
golang.org/x/sys 0.50.0. The test-only golang.org/x/crypto/openpgp module
reference from a dependency's forwarding test was removed from the production
module graph; no legacy x/crypto OpenPGP package is used by this bridge.

## Verification performed on 2026-11-24

- cargo-audit audit --json: 0 Rust advisories across the locked graph.
- govulncheck v1.10.0 ./...: no Go vulnerabilities found in imported packages
  or reachable symbols.
- go mod verify: all Go modules verified against their checksums.
- cargo test --locked: 6 tests pass:
  - GopenPGP keyring self-encryption/decryption.
  - The actual send-body + recipient PKESK path round-trips and verifies.
  - SRP modulus signature verification accepts a valid signer and rejects a
    different public key.
  - Session storage round-trips encrypted credentials, confirms no plaintext
    secrets appear in the file, and checks directory/file modes 0700/0600.
  - SMTP AUTH PLAIN and AUTH LOGIN both parse bridge passwords correctly into
    zeroizing buffers.
- cargo build --release --locked: succeeds.
- run.sh/build.sh shell syntax and Fedora bindgen environment detection pass.
- Local-only TLS smoke test confirmed IMAPS 127.0.0.1:1993 and SMTPS
  127.0.0.1:1465, no plaintext listeners in TLS mode, and private key mode 0600.

## Remaining limits

- No real Proton password, 2FA code, CAPTCHA token, session, or mailbox data has
  been entered into this fork.
- Proton's web API is undocumented for third-party bridge use and can change,
  rate-limit, challenge, or reject clients. Free-plan compatibility remains
  unverified until a controlled account login and read/send test succeeds.
- GopenPGP runs inside a Go runtime. Its key/session handles expose explicit
  destruction paths, but Go garbage collection means complete zeroization of
  every transient plaintext copy in process memory cannot be guaranteed.
- The project is not affiliated with, endorsed, or supported by Proton AG.
- The upstream bridge began with no tests; this fork now has focused crypto
  tests, but still needs integration tests against real Proton API responses,
  key formats, folder sync, attachments, and send behavior.
- Keep Proton web access and independent mail backups. Do not make this bridge
  the only copy or access path for important mail.

## Local security controls

The auth-local.sh helper accepts the Proton username in a local terminal, uses
no-echo prompts for passwords and verification codes, and copies the generated
bridge password to the Wayland clipboard without displaying or logging it.
Clear the clipboard after saving the password in Thunderbird.

The branch also retains restrictive owner-only session/config/key permissions,
TLS-only listeners when --tls is enabled, loopback-only binding, bounded
protocol input, nonce-protected CAPTCHA callback, redacted token output, and
zeroization for SRP proofs, login/mailbox passwords, IMAP/SMTP AUTH buffers,
bridge/session keys, OTP/CAPTCHA buffers, incoming/outgoing message buffers,
IMAP FETCH response assembly, and encrypted-session plaintext. These controls
reduce local exposure but do not replace account-level testing or a full
independent security review.
