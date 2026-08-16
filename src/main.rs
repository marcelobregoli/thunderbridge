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
