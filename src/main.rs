//! thunderbridge — a local bridge that connects a ProtonMail account to Thunderbird.
//!
//! The `auth` command logs in via SRP, clears the `9001` human-verification wall with
//! a CAPTCHA (browser) or an email/sms code, stores the session encrypted on disk, and
//! prints the bridge password to enter into Thunderbird.

mod imap;
mod proton;
mod session;
mod smtp;
mod store;
mod tls;
mod uidmap;

use std::io::{self, Write};

use clap::{Parser, Subcommand};

use proton::client::ApiError;
use proton::{humanverify, Client};

#[derive(Parser)]
#[command(name = "thunderbridge", about = "ProtonMail ↔ Thunderbird bridge")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Log in to a ProtonMail account and save the session.
    Auth {
        /// ProtonMail username (the part before @ in the email).
        username: String,
    },
    /// List saved sessions.
    Status,
    /// Remove a saved session.
    Logout {
        username: String,
    },
    /// Start the IMAP server (Thunderbird connects to 127.0.0.1:1143).
    Imap {
        username: String,
        #[arg(long, default_value_t = 1143)]
        port: u16,
    },
    /// Start the SMTP server (Thunderbird sends via 127.0.0.1:1025).
    Smtp {
        username: String,
        #[arg(long, default_value_t = 1025)]
        port: u16,
    },
    /// Run IMAP + SMTP together (plaintext + optional TLS ports).
    Serve {
        username: String,
        #[arg(long, default_value_t = 1143)]
        imap_port: u16,
        #[arg(long, default_value_t = 1025)]
        smtp_port: u16,
        /// Also open TLS (self-signed) ports.
        #[arg(long)]
        tls: bool,
        #[arg(long, default_value_t = 1993)]
        imaps_port: u16,
        #[arg(long, default_value_t = 1465)]
        smtps_port: u16,
    },
    /// Install and enable the systemd user service (starts automatically at login).
    InstallService {
        username: String,
        /// Also open TLS ports.
        #[arg(long)]
        tls: bool,
    },
    /// Trust the bridge's self-signed TLS certificate in Thunderbird (NSS), so the
    /// SSL/TLS ports connect without a certificate error. Quit Thunderbird first.
    TrustThunderbird,
    /// Write a PEM copy of the self-signed TLS certificate (to trust in other clients).
    ExportCert {
        /// Output path for the PEM file (default: next to the DER cert).
        #[arg(long)]
        out: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Auth { username } => cmd_auth(&username).await,
        Command::Status => cmd_status(),
        Command::Logout { username } => cmd_logout(&username),
        Command::Imap { username, port } => imap::serve(username, port).await,
        Command::Smtp { username, port } => smtp::serve(username, port).await,
        Command::Serve {
            username,
            imap_port,
            smtp_port,
            tls,
            imaps_port,
            smtps_port,
        } => run_serve(username, imap_port, smtp_port, tls, imaps_port, smtps_port).await,
        Command::InstallService { username, tls } => cmd_install_service(&username, tls),
        Command::TrustThunderbird => cmd_trust_thunderbird(),
        Command::ExportCert { out } => cmd_export_cert(out),
    };
    if let Err(e) = result {
        eprintln!("\nerror: {e}");
        std::process::exit(1);
    }
}

/// Writes and enables the systemd user service.
fn cmd_install_service(username: &str, tls: bool) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let dirs = directories::BaseDirs::new()
        .ok_or_else(|| anyhow::anyhow!("home directory not found"))?;
    let unit_dir = dirs.config_dir().join("systemd/user");
    std::fs::create_dir_all(&unit_dir)?;
    let unit_path = unit_dir.join("thunderbridge.service");

    let tls_flag = if tls { " --tls" } else { "" };
    let unit = format!(
        "[Unit]\n\
         Description=thunderbridge ProtonMail bridge\n\
         After=network-online.target\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         ExecStart={exe} serve {username}{tls_flag}\n\
         Restart=on-failure\n\
         RestartSec=5\n\n\
         [Install]\n\
         WantedBy=default.target\n",
        exe = exe.display(),
    );
    std::fs::write(&unit_path, unit)?;
    println!("✓ Service written: {}", unit_path.display());
    println!("\nTo enable it:");
    println!("  systemctl --user daemon-reload");
    println!("  systemctl --user enable --now thunderbridge");
    println!("\nStatus: systemctl --user status thunderbridge");
    println!("Logs:   journalctl --user -u thunderbridge -f");
    Ok(())
}

/// Trusts the self-signed TLS certificate in every local Thunderbird profile.
///
/// Thunderbird's account-setup wizard rejects a self-signed cert outright ("Can't find
/// a server") instead of offering the security-exception dialog, so the reliable fix is
/// to import the cert into each profile's NSS store (`cert9.db`) with CA+peer SSL trust.
fn cmd_trust_thunderbird() -> anyhow::Result<()> {
    if !certutil_available() {
        anyhow::bail!(
            "`certutil` not found — install the NSS tools and re-run:\n  \
             Arch: sudo pacman -S nss   Debian/Ubuntu: sudo apt install libnss3-tools   Fedora: sudo dnf install nss-tools"
        );
    }
    let cert = tls::cert_der_path()?;
    let profiles = thunderbird_profiles();
    if profiles.is_empty() {
        anyhow::bail!(
            "no Thunderbird profile found (looked under ~/.thunderbird, ~/.config/thunderbird, \
             and the Flatpak path). Start Thunderbird once so it creates a profile, then re-run."
        );
    }
    if thunderbird_running() {
        println!(
            "⚠  Thunderbird looks like it is running. Quit it completely first — NSS may otherwise overwrite this change."
        );
    }
    const NICK: &str = "thunderbridge (local)";
    let mut trusted = 0usize;
    for p in &profiles {
        let db = format!("sql:{}", p.display());
        // Drop any stale entry (ignore failure), then add with CA+peer SSL trust.
        let _ = std::process::Command::new("certutil")
            .args(["-D", "-d", &db, "-n", NICK])
            .output();
        let status = std::process::Command::new("certutil")
            .args(["-A", "-d", &db, "-n", NICK, "-t", "CP,,", "-i"])
            .arg(&cert)
            .status()?;
        if status.success() {
            println!("✓ trusted in {}", p.display());
            trusted += 1;
        } else {
            eprintln!("✗ could not import into {}", p.display());
        }
    }
    if trusted == 0 {
        anyhow::bail!("failed to trust the certificate in any profile");
    }
    println!(
        "\n✓ Done ({trusted} profile(s)). Start Thunderbird and use the TLS ports:\n  \
         IMAP 127.0.0.1:1993 (SSL/TLS)   SMTP 127.0.0.1:1465 (SSL/TLS)"
    );
    Ok(())
}

/// Writes a PEM copy of the self-signed certificate for trusting in other mail clients.
fn cmd_export_cert(out: Option<String>) -> anyhow::Result<()> {
    let der_path = tls::cert_der_path()?;
    let out_path = match out {
        Some(p) => std::path::PathBuf::from(p),
        None => der_path.with_file_name("tls-cert.pem"),
    };
    std::fs::write(&out_path, tls::cert_pem()?)?;
    println!("✓ PEM certificate written: {}", out_path.display());
    println!("  (DER original:           {})", der_path.display());
    println!(
        "\nImport it as a trusted certificate in your mail client to use the TLS ports without a warning.\n\
         Thunderbird: `thunderbridge trust-thunderbird` does this automatically."
    );
    Ok(())
}

/// Whether the NSS `certutil` binary is available on PATH.
fn certutil_available() -> bool {
    std::process::Command::new("certutil")
        .arg("-H")
        .output()
        .is_ok()
}

/// Best-effort check for a running Thunderbird (via `pgrep`); false if `pgrep` is absent.
fn thunderbird_running() -> bool {
    std::process::Command::new("pgrep")
        .args(["-x", "thunderbird"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Finds Thunderbird profile directories (any dir containing `prefs.js`) across the
/// standard and Flatpak locations.
fn thunderbird_profiles() -> Vec<std::path::PathBuf> {
    let mut roots: Vec<std::path::PathBuf> = Vec::new();
    if let Some(dirs) = directories::BaseDirs::new() {
        let home = dirs.home_dir();
        roots.push(home.join(".thunderbird"));
        roots.push(home.join(".config/thunderbird"));
        roots.push(home.join(".var/app/org.mozilla.Thunderbird/.thunderbird"));
    }
    let mut profiles = Vec::new();
    for root in roots {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            if path.is_dir() && path.join("prefs.js").exists() {
                profiles.push(path);
            }
        }
    }
    profiles
}

/// Runs IMAP + SMTP (plaintext + optional TLS) concurrently.
async fn run_serve(
    username: String,
    imap_port: u16,
    smtp_port: u16,
    tls: bool,
    imaps_port: u16,
    smtps_port: u16,
) -> anyhow::Result<()> {
    let mut tasks: Vec<tokio::task::JoinHandle<anyhow::Result<()>>> = Vec::new();
    {
        let u = username.clone();
        tasks.push(tokio::spawn(async move { imap::serve(u, imap_port).await }));
    }
    {
        let u = username.clone();
        tasks.push(tokio::spawn(async move { smtp::serve(u, smtp_port).await }));
    }
    if tls {
        let acceptor = tls::acceptor()?;
        {
            let (u, acc) = (username.clone(), acceptor.clone());
            tasks.push(tokio::spawn(async move {
                imap::serve_tls(u, imaps_port, acc).await
            }));
        }
        {
            let (u, acc) = (username.clone(), acceptor.clone());
            tasks.push(tokio::spawn(async move {
                smtp::serve_tls(u, smtps_port, acc).await
            }));
        }
    }
    // Stop on the first error/exit.
    for t in tasks {
        t.await??;
    }
    Ok(())
}

fn prompt_line(label: &str) -> anyhow::Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

async fn cmd_auth(username: &str) -> anyhow::Result<()> {
    let mut client = Client::new()?;

    let password = rpassword::prompt_password("Password: ")?;

    // Prepare the SRP proof.
    let prepared = client.prepare_auth(username, &password).await?;

    // Send /auth; on 9001, resolve human-verification and retry once.
    let auth = match client.submit_auth(&prepared, None).await {
        Ok(auth) => auth,
        Err(ApiError::HumanVerification(hv)) => {
            let headers = humanverify::resolve(&client, &hv).await?;
            client.submit_auth(&prepared, Some(&headers)).await?
        }
        Err(e) => return Err(e.into()),
    };

    // Second factor (TOTP).
    if auth.two_factor.enabled != 0 {
        if auth.two_factor.totp != 1 {
            anyhow::bail!("only TOTP 2FA is supported");
        }
        let code = prompt_line("2FA TOTP code: ")?;
        client.auth_totp(&code).await?;
    }

    // Mailbox password: the login password in single-password mode, asked separately
    // in two-password mode.
    let mailbox_password = if auth.password_mode == 1 {
        password.clone()
    } else {
        rpassword::prompt_password("Mailbox password: ")?
    };

    // Fetch the key salts (needed to unlock keys later); if it fails, still save the session.
    let mut session =
        store::CachedSession::from_auth(&auth, password.clone(), mailbox_password);
    match client
        .get_json::<serde_json::Value>("/keys/salts")
        .await
    {
        Ok(v) => session.key_salts = v,
        Err(e) => eprintln!("warning: could not fetch key salts ({e}); will retry later"),
    }

    let bridge_password = store::encrypt_and_save(username, &session)?;

    println!("\n✓ Login successful. Session saved encrypted.");
    println!("\n  Bridge password (enter this in Thunderbird, NOT your real Proton password):");
    println!("      {bridge_password}");
    println!("\n  Thunderbird settings (once the servers are running):");
    println!("      IMAP  127.0.0.1:1143   user: {username}   password: bridge password");
    println!("      SMTP  127.0.0.1:1025   user: {username}   password: bridge password");
    Ok(())
}

fn cmd_status() -> anyhow::Result<()> {
    let users = store::list_usernames()?;
    if users.is_empty() {
        println!("No saved sessions.");
    } else {
        println!("Saved sessions:");
        for u in users {
            println!("  - {u}");
        }
    }
    Ok(())
}


fn cmd_logout(username: &str) -> anyhow::Result<()> {
    if store::remove(username)? {
        println!("Session removed: {username}");
    } else {
        println!("No such session: {username}");
    }
    Ok(())
}
