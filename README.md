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
  **bridge password** — save it, you enter it in your mail client.
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

Install `tools/proton-hv-capture.user.js` in a userscript manager (Violentmonkey or
Tampermonkey). It runs on `verify.proton.me`, captures the solved CAPTCHA token, and
POSTs it to the running `auth` command, so no copy-paste is needed. It does not solve the
CAPTCHA; you still solve it yourself.

`auth` opens the verification page in your **system default browser**, so the userscript
manager must be installed and enabled in that browser.

### Verify the script is running

Open DevTools (F12) → Console on the `verify.proton.me` page. You should see:

```
[thunderbridge] HV capture active — solve the CAPTCHA, the rest is automatic.
```

After you solve the CAPTCHA it logs `token captured -> sending to thunderbridge`. If the
`HV capture active` line is missing, the script is not running (see below).

### Chromium browsers (Chrome, Brave, Edge)

Under Manifest V3, Tampermonkey needs userscripts explicitly allowed or it silently runs
nothing — and a browser update can reset this. If the `HV capture active` line does not
appear, in the browser that opened the page:

1. Open the extensions page (`brave://extensions`, `chrome://extensions`, ...).
2. Enable **Developer mode** (top-right toggle), and/or open **Tampermonkey → Details**
   and enable **Allow User Scripts** if that toggle is present.
3. Confirm the extension and the `thunderbridge HV token capture` script are both enabled,
   then reload `verify.proton.me`.

### Manual fallback (console, no userscript)

If you cannot install a userscript manager, paste this into the DevTools Console on
`verify.proton.me` **before** solving the CAPTCHA. It captures the solved token, tries to
POST it to the running `auth` command automatically, and also copies it to the clipboard and
prints it so you can paste it into the terminal `>` prompt if the auto-POST is blocked:

```js
(() => {
  const PORT = 8722, seen = new Set();

  function fromMessage(m) {
    if (!m) return null;
    if (typeof m === 'string') { try { m = JSON.parse(m); } catch { return null; } }
    if (typeof m !== 'object') return null;
    const token = m.token || (m.payload && m.payload.token) || (m.data && m.data.token);
    if (!token) return null;
    const kind = String(m.type || (m.payload && m.payload.type) || '');
    if (/captcha|human[_-]?verification/i.test(kind)) return token;
    if (/captcha|human[_-]?verification/i.test(JSON.stringify(m))) return token;
    return null;
  }

  function deliver(token) {
    if (!token || seen.has(token)) return;
    seen.add(token);
    console.log('%c[thunderbridge] TOKEN captured:', 'color:#0f0;font-weight:bold');
    console.log('%c' + token, 'color:#0f0');
    try { navigator.clipboard.writeText(token); console.log('[thunderbridge] copied to clipboard'); } catch {}
    try {
      fetch('http://127.0.0.1:' + PORT + '/token', {
        method: 'POST', body: token, headers: { 'Content-Type': 'text/plain' }, mode: 'no-cors'
      }).then(() => console.log('%c[thunderbridge] sent to thunderbridge — back to the terminal.', 'color:#0f0'))
        .catch(() => console.warn('[thunderbridge] auto-send blocked — paste the token into the terminal.'));
    } catch { console.warn('[thunderbridge] auto-send blocked — paste the token into the terminal.'); }
  }

  // 1) Hook the page's window.parent.postMessage call.
  try {
    const orig = window.postMessage;
    if (orig && !orig.__tb) {
      const hooked = function (m) { const t = fromMessage(m); if (t) deliver(t); return orig.apply(this, arguments); };
      hooked.__tb = true; window.postMessage = hooked;
    }
  } catch {}

  // 2) Also listen for messages delivered to this window (iframe -> parent).
  window.addEventListener('message', (e) => { const t = fromMessage(e.data); if (t) deliver(t); }, true);

  console.log('%c[thunderbridge] HV capture active — solve the CAPTCHA, the rest is automatic.', 'color:#0f0;font-weight:bold');
})();
```

Browsers may block the cross-origin POST to `127.0.0.1` (Chrome/Brave Private Network
Access); that is fine — the token is on your clipboard and in the console, so paste it into
the terminal `>` prompt and press Enter. For a setup that always auto-delivers, install the
userscript above instead.

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
