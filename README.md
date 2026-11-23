# thunderbridge

> **Security status — 24 November 2026:** This fork is experimental and is **not
> approved for real Proton credentials yet**. The dependency audit still reports
> RUSTSEC-2026-0387 (crypto-bigint 0.5.5) and RUSTSEC-2023-0071 (rsa 0.9.10).
> Do not authenticate a real account or use this as a live mail bridge until those
> cryptographic dependencies are patched and the project has meaningful tests.


A small, self-hosted bridge that exposes a **ProtonMail** account to any standard mail
client (Thunderbird, mutt, Evolution, ...) over local **IMAP** and **SMTP**. It speaks
the ProtonMail web API, performs the SRP login (including 2FA and the human-verification
CAPTCHA), unlocks your PGP keys locally, and presents your mailbox as an ordinary
IMAP/SMTP server bound to `127.0.0.1`.

Written in Rust. No telemetry or third-party bridge service: the local bridge connects
directly to Proton's API. Your ProtonMail password is not intentionally persisted in
plaintext.

Not affiliated with or endorsed by Proton AG. Use it with your own account.

## Why this exists

ProtonMail does not expose plain IMAP/SMTP. The official Proton Bridge requires a paid
plan; this is an independent, open-source alternative designed to support free-plan
accounts through the unofficial Proton web API. Compatibility has not been validated
against every account state or current Proton challenge flow. It translates standard mail
protocols into Proton API calls and performs PGP
encryption/decryption locally, so a normal mail client never sees the Proton API or the
raw ciphertext.

## Architecture

### High-level data flow

```
  Mail client (Thunderbird)
        |  IMAPS 1993 / SMTPS 1465  (localhost, TLS only in --tls mode)
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
| `main.rs`         | CLI (clap): `auth`, `status`, `logout`, `imap`, `smtp`, `serve`, `install-service`, `trust-thunderbird`, `export-cert`. |
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
  it in the browser and the optional userscript delivers the solved token through a
  nonce-protected callback bound to `127.0.0.1:8722`. There is no automated solving.
  If the callback is unavailable, authentication fails closed. After first login the
  session is renewed with the refresh token, so the CAPTCHA may not reappear.

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

### Quick start (`run.sh`)

A helper script wraps the two common steps (build + auth, build + serve over TLS):

```sh
./run.sh auth <proton-username>    # first time: log in, prints the bridge password
./run.sh <proton-username>         # then: start IMAP+SMTP with TLS enabled
```

What it does:

- `./run.sh auth <user>` — runs `cargo build --release`, then `thunderbridge auth <user>`.
  You are prompted for your Proton password and, if needed, solve the CAPTCHA in the
  browser (see [CAPTCHA userscript](#captcha-userscript)). On success it prints the
  **bridge password** — save it securely; enter it in your mail client.
- `./run.sh <user>` — builds, then runs `thunderbridge serve <user> --tls` and prints the
  host/port/security values to enter in Thunderbird.

The script `cd`s to its own directory, so it works from anywhere. `Address already in
use` on start means an instance is already running — most often the systemd service (see
[Auto-start](#auto-start-systemd)); stop it first with `systemctl --user stop
thunderbridge`, or just use the service instead of running the script by hand.

The steps below explain each part in full.

### 1. Log in (once)

```sh
thunderbridge auth <proton-username>
```

You are asked for your ProtonMail password (and TOTP if 2FA is enabled). If Proton asks
for human verification, solve the CAPTCHA in the browser window that opens; with the
reviewed userscript installed (see below) the token is delivered automatically. On
success a **bridge password** is printed. This is what you give your mail client, not your real
Proton password.

### 2. Run the bridge

```sh
thunderbridge serve <proton-username>          # plain: IMAP 1143, SMTP 1025
thunderbridge serve <proton-username> --tls    # TLS-only: IMAP 1993, SMTP 1465
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

#### Thunderbird, step by step (TLS)

When Thunderbird's account setup cannot autodetect the server, open **manual config** and
enter the values by hand — do not leave "Autodetect", the self-signed certificate trips it
up.

**Incoming (IMAP):**

| Field                 | Value                 |
|-----------------------|-----------------------|
| Protocol              | IMAP                  |
| Hostname              | `127.0.0.1`           |
| Port                  | `1993`                |
| Connection security   | SSL/TLS               |
| Authentication method | Normal password       |
| Username              | your Proton address   |

**Outgoing (SMTP):**

| Field                 | Value                 |
|-----------------------|-----------------------|
| Hostname              | `127.0.0.1`           |
| Port                  | `1465`                |
| Connection security   | SSL/TLS               |
| Authentication method | Normal password       |
| Username              | your Proton address   |

The password for both is the **bridge password**, not your Proton password.

##### Trust the certificate first (important)

Thunderbird's account-setup wizard does **not** offer the usual "Confirm Security
Exception" dialog for a self-signed certificate — it just fails the connection test with
**"Can't find a server"** (and the running service logs a `BadCertificate` TLS alert). So
trust the certificate *before* adding the account:

```sh
# quit Thunderbird completely first, then:
thunderbridge trust-thunderbird
```

This imports the bridge's self-signed certificate into every Thunderbird profile's NSS
store (`cert9.db`) with CA + peer SSL trust, so the TLS ports validate cleanly. The
certificate covers `localhost` and `127.0.0.1` and is stable across restarts, so you only
do this once (re-run it if you ever delete the cert or add a new profile). Requires the
NSS `certutil` tool (Arch: `nss`, Debian/Ubuntu: `libnss3-tools`, Fedora: `nss-tools`).

Now start Thunderbird and run the connection test — it succeeds without a warning.

> Other clients (mutt, Evolution, ...): `thunderbridge export-cert` writes a PEM copy of
> the certificate to import as trusted in that client instead.

For the plain (non-TLS) ports use `1143` / `1025` with Connection security **None** — no
certificate trust needed, since loopback traffic never leaves the machine.

#### Only the Inbox shows up?

Thunderbird subscribes to `INBOX` only by default, so All Mail, Sent, Drafts, Spam, Trash,
Starred, and Archive can be missing at first even though the bridge serves them. To show
them:

- Right-click the account → **Subscribe…**, tick the folders you want, **OK**; or
- **Account Settings → Server Settings → Advanced…** and untick **Show only subscribed
  folders** to show every folder without subscribing.

If the Subscribe list is empty, refresh the folder list first (right-click the account →
**Refresh folder list**, or reopen the Subscribe dialog). The bridge tags special folders
with RFC 6154 attributes (`\All` for All Mail, `\Sent`, `\Trash`, ...), so Thunderbird maps
them to the right roles once they are subscribed.

### Auto-start (systemd)

```sh
thunderbridge install-service <proton-username>   # add --tls to enable TLS ports
systemctl --user daemon-reload
systemctl --user enable --now thunderbridge
```

The service runs the **installed** binary (e.g. `~/.local/bin/thunderbridge`), not
`target/release`. After rebuilding, refresh it so the service picks up your changes:

```sh
cargo build --release
cp -f target/release/thunderbridge ~/.local/bin/thunderbridge
systemctl --user restart thunderbridge
```

Follow the logs with `journalctl --user -u thunderbridge -f`.

## CAPTCHA userscript

If Proton requires a CAPTCHA, the user must solve it manually in Proton's own
verification page. The optional userscript at
`tools/proton-hv-capture.user.js` only transfers the resulting token to the
one-time local callback.

The callback uses a fresh 192-bit random path for each authentication attempt,
accepts a maximum 4 KiB body, and listens only on `127.0.0.1:8722`. The userscript
requires a userscript manager with `GM_xmlhttpRequest` and `unsafeWindow`
permissions. It does not print or display the CAPTCHA token. If delivery fails,
stop the authentication attempt and retry; do not paste tokens into random web
pages, public chats, issue trackers, or shell command arguments.

Do not install the userscript until you have reviewed its source. The project is
independent of Proton and is not endorsed or supported by Proton AG.

## Security notes

- IMAP, SMTP and the CAPTCHA callback bind to `127.0.0.1` only.
- The configuration directory is owner-only (`0700`); the encrypted session file,
  UID metadata and TLS private key are owner-only (`0600`).
- Session JSON is encrypted with XChaCha20-Poly1305; its random key is the bridge
  password and is not stored alongside the ciphertext.
- Temporary serialized session plaintext buffers are zeroized after encryption/decryption.
- Traffic to Proton uses HTTPS/TLS. PGP decryption happens locally in memory.
- These hardening measures do not constitute an independent security audit. Treat this
  third-party bridge as experimental and do not rely on it as your only mail archive.
- Treat the bridge password like a password: anyone who has it, with access to your
  machine, can read your mail.

## Dependencies of note

`tokio`, `reqwest` (rustls), `proton-srp` (SRP), `rpgp` (OpenPGP), `chacha20poly1305`
(session store), `tokio-rustls` + `rcgen` (TLS), `mail-parser`, `clap`.

## License

MIT. See [LICENSE](LICENSE).
