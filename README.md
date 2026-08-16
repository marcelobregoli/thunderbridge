# thunderbridge

A small, self-hosted bridge that connects a **ProtonMail** account to any standard
mail client (Thunderbird, mutt, …) over local **IMAP** and **SMTP**. It speaks the
ProtonMail API, handles login (including the human-verification/CAPTCHA challenge),
unlocks your PGP keys locally, and exposes your mailbox as a normal IMAP/SMTP server on
`127.0.0.1`.

Written in Rust. No telemetry, no third parties — everything runs on your machine and
your ProtonMail password is never stored in plaintext.

> Not affiliated with or endorsed by Proton AG. Use it with your own account.

## Features

- **Login** via Proton SRP, with 2FA (TOTP) and human-verification (CAPTCHA) support.
- **IMAP server** — all folders (Inbox, Sent, Drafts, Archive, Spam, Trash, Starred,
  All Mail + custom labels), full message download, persistent UIDs, read/unread sync.
- **SMTP server** — send to Proton (internal, PGP) and external (e.g. Gmail) recipients.
- **PGP handled locally** — messages are decrypted on your machine before reaching the client.
- **Encrypted session store** — the session is sealed on disk with XChaCha20-Poly1305;
  the key is your "bridge password".
- **Optional self-signed TLS** for the local IMAP/SMTP ports.
- **systemd user service** for auto-start.

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

You'll be asked for your ProtonMail password (and TOTP if 2FA is on). If Proton requires
human verification, only the **captcha** method is offered for third-party logins:
solve it in the browser window that opens and the token is captured automatically (see
[CAPTCHA](#captcha) below). On success a **bridge password** is printed — this is what
you give your mail client, *not* your real Proton password.

### 2. Run the bridge

```sh
thunderbridge serve <proton-username>            # plain, IMAP 1143 / SMTP 1025
thunderbridge serve <proton-username> --tls      # also TLS, IMAPS 1993 / SMTPS 1465
```

### 3. Configure your mail client

| Setting            | Value                                   |
|--------------------|-----------------------------------------|
| IMAP host / port   | `127.0.0.1` / `1143` (or `1993` for TLS)|
| SMTP host / port   | `127.0.0.1` / `1025` (or `1465` for TLS)|
| Connection security| `None` (plain) or `SSL/TLS` (TLS ports) |
| Authentication     | Normal password                         |
| Username           | your Proton address                     |
| Password           | the **bridge password** from step 1     |

For plain ports the client will warn about an unencrypted connection — this is local
loopback traffic that never leaves your machine, so it is safe. Use `--tls` if you'd
rather not see the warning (you'll trust the self-signed certificate once).

### Auto-start (systemd)

```sh
thunderbridge install-service <proton-username>        # or: --tls
systemctl --user daemon-reload
systemctl --user enable --now thunderbridge
```

## CAPTCHA

ProtonMail protects third-party logins with a CAPTCHA that only renders on Proton's own
origin, so it cannot be embedded. thunderbridge opens the real verification page in your
browser; you solve it yourself (no automated solving). A small userscript
(`tools/proton-hv-capture.user.js`, install it in Violentmonkey/Tampermonkey) captures
the solved token and hands it to the running `auth` command automatically — no copy and
paste. Once a session exists it is refreshed with the refresh token, so the CAPTCHA
usually won't reappear for a long time.

## Security notes

- Servers bind to `127.0.0.1` only.
- The on-disk session (`~/.config/thunderbridge/sessions.json`) is encrypted; the key is
  the bridge password and is never stored.
- Traffic to Proton is HTTPS/TLS. PGP decryption happens in memory, locally.
- Treat the bridge password like a password: anyone with it (and access to your machine)
  can read your mail.

## License

MIT — see [LICENSE](LICENSE).
