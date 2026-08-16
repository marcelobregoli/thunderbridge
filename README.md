# thunderbridge

A small, self-hosted bridge that exposes a **ProtonMail** account to any standard mail
client (Thunderbird, mutt, Evolution, ...) over local **IMAP** and **SMTP**. It speaks
the ProtonMail web API, performs the SRP login (including 2FA and the human-verification
CAPTCHA), unlocks your PGP keys locally, and presents your mailbox as an ordinary
IMAP/SMTP server bound to `127.0.0.1`.

Written in Rust. No telemetry and no third parties: everything runs on your machine, and
your ProtonMail password is never written to disk in plaintext.

Not affiliated with or endorsed by Proton AG. Use it with your own account.

## Why this exists

ProtonMail does not expose plain IMAP/SMTP. The official Proton Bridge requires a paid
plan; this is an independent, open-source alternative that works with free accounts. It
translates the standard mail protocols into ProtonMail API calls and performs all PGP
encryption/decryption locally, so a normal mail client never sees the Proton API or the
raw ciphertext.

## Architecture

### High-level data flow

```
  Mail client (Thunderbird)
        |  IMAP 1143 / SMTP 1025  (localhost, plain or TLS)
        v
  +-----------------------------+
  |         thunderbridge       |
  |                             |
  |  imap.rs        smtp.rs     |   protocol front-ends
  |     \             /         |
  |      session.rs             |   opens/refreshes a Proton session,
  |         |                   |   unlocks the PGP keyring
  |    proton/ (API client)     |
  |         |                   |
  |    store.rs (encrypted)     |   on-disk session, sealed with the
  +---------|-------------------+   bridge password
            |  HTTPS/TLS
            v
     mail.proton.me/api
```

### Module layout (`src/`)

| Module            | Responsibility |
|-------------------|----------------|
| `main.rs`         | CLI (clap): `auth`, `status`, `logout`, `imap`, `smtp`, `serve`, `install-service`. |
| `session.rs`      | Opens a stored session: refresh access token, load key-salts, unlock the PGP keyring. Shared by the IMAP and SMTP servers. |
| `store.rs`        | On-disk session store. Session data is serialized to JSON and sealed with XChaCha20-Poly1305; the random key is handed to the user as the *bridge password* and never stored. |
| `imap.rs`         | Hand-written IMAP4rev1 server. Lists all folders, fetches every message in a folder, serves ENVELOPE/BODY (PGP-decrypted), keeps persistent UIDs, and reflects `\Seen` back to Proton. |
| `smtp.rs`         | Minimal SMTP server. Accepts a message from the client, authenticates with the bridge password, and hands the raw MIME to the send pipeline. |
| `uidmap.rs`       | Persistent Proton-message-ID to IMAP-UID mapping (per folder), so clients do not re-download messages across reconnects. |
| `tls.rs`          | Self-signed certificate generation/loading and the `TlsAcceptor` used by the optional TLS listeners. |
| `proton/`         | ProtonMail API client (see below). |

### The `proton/` API layer (`src/proton/`)

| Module          | Responsibility |
|-----------------|----------------|
| `client.rs`     | HTTP transport (reqwest + rustls). Adds the required app/version headers, decodes the API envelope, and turns a `9001` response into a typed human-verification error. |
| `auth.rs`       | SRP login flow via `proton-srp`: fetch `/auth/info`, produce the client proof, submit `/auth`, verify the server proof; plus 2FA (TOTP) and refresh-token renewal. |
| `humanverify.rs`| Resolves the `9001` CAPTCHA / email / SMS challenge. For CAPTCHA it opens the verification page and receives the solved token from a userscript over a local port. |
| `mail.rs`       | Account layer: current user, addresses, PGP key structures, key-salts. |
| `messages.rs`   | Message listing and single-message fetch; read/unread marking. |
| `crypto.rs`     | PGP with `rpgp`: unlocks the keyring (user key via bcrypt-derived passphrase, address keys via the encrypted token), decrypts incoming bodies, and builds encrypted+signed bodies for sending. |
| `send.rs`       | Outbound pipeline: parse the client MIME, create a Proton draft, and build one send package per recipient (encrypted PKESK for Proton recipients, cleartext session key for external recipients). |

### Key technical points

- **Login and CAPTCHA.** Free-account third-party logins hit a `9001` CAPTCHA. The
  CAPTCHA only renders on Proton's own origin, so it cannot be embedded; the user solves
  it in the browser and the solved token is captured by a userscript and delivered to
  `auth` over `127.0.0.1:8722`. There is no automated solving. After the first login the
  session is renewed with the refresh token, so the CAPTCHA rarely reappears.

- **Key-salts scope.** The `/keys/salts` endpoint requires a short-lived post-login
  "password scope" that a refreshed token does not carry. thunderbridge captures the
  salts at login time and reuses that copy.

- **PGP key model.** The primary key is typically signing-only (EdDSA); the encryption
  subkey (ECDH) is used for encrypting session keys. Bodies are always signed with the
  sender's key, which Proton requires for external delivery.

- **Persistent UIDs.** IMAP requires stable UIDs. Proton message IDs are strings, so a
  per-folder map assigns increasing integer UIDs and persists them, keeping clients from
  re-downloading on every reconnect.

## Build

```sh
cargo build --release
# binary: target/release/thunderbridge
```

## Usage

### 1. Log in (once)

```sh
thunderbridge auth <proton-username>
```

You are asked for your ProtonMail password (and TOTP if 2FA is enabled). If Proton asks
for human verification, solve the CAPTCHA in the browser window that opens; with the
userscript installed (see below) the token is delivered automatically. On success a
**bridge password** is printed. This is what you give your mail client, not your real
Proton password.

### 2. Run the bridge

```sh
thunderbridge serve <proton-username>          # plain: IMAP 1143, SMTP 1025
thunderbridge serve <proton-username> --tls    # also TLS: IMAPS 1993, SMTPS 1465
```

### 3. Configure the mail client

| Setting             | Value                                     |
|---------------------|-------------------------------------------|
| IMAP host / port    | `127.0.0.1` / `1143` (or `1993` for TLS)  |
| SMTP host / port    | `127.0.0.1` / `1025` (or `1465` for TLS)  |
| Connection security | None (plain ports) or SSL/TLS (TLS ports) |
| Authentication      | Normal password                           |
| Username            | your Proton address                       |
| Password            | the bridge password from step 1           |

On the plain ports the client warns about an unencrypted connection; this is loopback
traffic that never leaves the machine. Use `--tls` to avoid the warning (you trust the
self-signed certificate once).

### Auto-start (systemd)

```sh
thunderbridge install-service <proton-username>   # add --tls to enable TLS ports
systemctl --user daemon-reload
systemctl --user enable --now thunderbridge
```

## CAPTCHA userscript

Install `tools/proton-hv-capture.user.js` in a userscript manager (Violentmonkey or
Tampermonkey). It runs on `verify.proton.me`, captures the solved CAPTCHA token, and
POSTs it to the running `auth` command, so no copy-paste is needed. It does not solve the
CAPTCHA; you still solve it yourself.

## Security notes

- All servers bind to `127.0.0.1` only.
- The on-disk session (`~/.config/thunderbridge/sessions.json`) is encrypted; the key is
  the bridge password and is never stored.
- Traffic to Proton is HTTPS/TLS. PGP decryption happens in memory, locally.
- Treat the bridge password like a password: anyone who has it, with access to your
  machine, can read your mail.

## Dependencies of note

`tokio`, `reqwest` (rustls), `proton-srp` (SRP), `rpgp` (OpenPGP), `chacha20poly1305`
(session store), `tokio-rustls` + `rcgen` (TLS), `mail-parser`, `clap`.

## License

MIT. See [LICENSE](LICENSE).
