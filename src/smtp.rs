//! Minimal SMTP sending server (127.0.0.1:1025). Receives a message from Thunderbird,
//! opens the session with the bridge password, and sends it through Proton.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::proton::send::send_mail;
use crate::session::Session;

/// Plain TCP SMTP listener.
pub async fn serve(username: String, port: u16) -> anyhow::Result<()> {
    accept_loop(username, port, None).await
}

/// TLS (implicit) SMTP listener.
pub async fn serve_tls(username: String, port: u16, acceptor: TlsAcceptor) -> anyhow::Result<()> {
    accept_loop(username, port, Some(acceptor)).await
}

async fn accept_loop(username: String, port: u16, tls: Option<TlsAcceptor>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!(
        "SMTP{}: listening on 127.0.0.1:{port} (user: {username})",
        if tls.is_some() { " (TLS)" } else { "" }
    );
    let username = Arc::new(username);
    loop {
        let (tcp, peer) = listener.accept().await?;
        let username = username.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let res = match tls {
                Some(acc) => match acc.accept(tcp).await {
                    Ok(s) => handle(s, &username).await,
                    Err(e) => {
                        eprintln!("SMTP [{peer}] TLS handshake: {e}");
                        return;
                    }
                },
                None => handle(tcp, &username).await,
            };
            if let Err(e) = res {
                eprintln!("SMTP [{peer}] ended: {e}");
            }
        });
    }
}

struct Conn<S: AsyncRead + AsyncWrite + Unpin> {
    reader: BufReader<ReadHalf<S>>,
    writer: WriteHalf<S>,
}
impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    async fn send(&mut self, s: &str) -> std::io::Result<()> {
        self.writer.write_all(s.as_bytes()).await?;
        self.writer.flush().await
    }
    async fn line(&mut self) -> std::io::Result<Option<String>> {
        let mut buf = Vec::new();
        loop {
            let b = match self.reader.read_u8().await {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e),
            };
            if b == b'\n' {
                break;
            }
            if b != b'\r' {
                buf.push(b);
            }
        }
        Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
    }
}

async fn handle<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: S,
    username: &str,
) -> anyhow::Result<()> {
    let (r, w) = split(stream);
    let mut c = Conn {
        reader: BufReader::new(r),
        writer: w,
    };
    c.send("220 thunderbridge SMTP ready\r\n").await?;

    let mut session: Option<Session> = None;
    let mut rcpts: Vec<String> = Vec::new();

    while let Some(line) = c.line().await? {
        let up = line.trim_end().to_ascii_uppercase();
        let cmd = up.split_whitespace().next().unwrap_or("");
        match cmd {
            "EHLO" | "HELO" => {
                c.send("250-thunderbridge\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n").await?;
            }
            "AUTH" => {
                let pass = smtp_auth(&mut c, &line).await?;
                match pass {
                    Some(p) => match Session::open(username, &p).await {
                        Ok(s) => {
                            session = Some(s);
                            c.send("235 2.7.0 Authentication successful\r\n").await?;
                        }
                        Err(e) => {
                            eprintln!("SMTP auth error: {e}");
                            c.send("535 5.7.8 Authentication failed\r\n").await?;
                        }
                    },
                    None => c.send("535 5.7.8 Authentication failed\r\n").await?,
                }
            }
            "MAIL" => {
                rcpts.clear();
                c.send("250 2.1.0 OK\r\n").await?;
            }
            "RCPT" => {
                if let Some(addr) = extract_addr(&line) {
                    rcpts.push(addr);
                }
                c.send("250 2.1.5 OK\r\n").await?;
            }
            "DATA" => {
                if session.is_none() {
                    c.send("530 5.7.0 Authentication required\r\n").await?;
                    continue;
                }
                c.send("354 End data with <CR><LF>.<CR><LF>\r\n").await?;
                let data = read_data(&mut c).await?;
                match send_mail(session.as_ref().unwrap(), &data, &rcpts).await {
                    Ok(()) => c.send("250 2.0.0 Message sent\r\n").await?,
                    Err(e) => {
                        eprintln!("SMTP send error: {e}");
                        c.send(&format!("554 5.0.0 send failed: {e}\r\n")).await?;
                    }
                }
                rcpts.clear();
            }
            "RSET" => {
                rcpts.clear();
                c.send("250 2.0.0 OK\r\n").await?;
            }
            "NOOP" => {
                c.send("250 2.0.0 OK\r\n").await?;
            }
            "QUIT" => {
                c.send("221 2.0.0 Bye\r\n").await?;
                break;
            }
            _ => {
                c.send("502 5.5.2 Command not implemented\r\n").await?;
            }
        }
    }
    Ok(())
}

/// Runs the AUTH LOGIN / PLAIN flow; returns the bridge password.
async fn smtp_auth<S: AsyncRead + AsyncWrite + Unpin + Send>(
    c: &mut Conn<S>,
    line: &str,
) -> anyhow::Result<Option<String>> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let mech = parts.get(1).map(|s| s.to_ascii_uppercase()).unwrap_or_default();
    if mech == "PLAIN" {
        // AUTH PLAIN [<b64>]
        let b64 = if let Some(arg) = parts.get(2) {
            (*arg).to_string()
        } else {
            c.send("334 \r\n").await?;
            c.line().await?.unwrap_or_default()
        };
        let decoded = B64.decode(b64.trim()).unwrap_or_default();
        // \0user\0pass
        let mut it = decoded.split(|&b| b == 0);
        it.next(); // authzid
        it.next(); // authcid (username)
        let pass = it.next().map(|p| String::from_utf8_lossy(p).into_owned());
        Ok(pass)
    } else if mech == "LOGIN" {
        c.send("334 VXNlcm5hbWU6\r\n").await?; // "Username:"
        let _user = c.line().await?.unwrap_or_default();
        c.send("334 UGFzc3dvcmQ6\r\n").await?; // "Password:"
        let pass_b64 = c.line().await?.unwrap_or_default();
        let pass = String::from_utf8_lossy(&B64.decode(pass_b64.trim()).unwrap_or_default()).into_owned();
        Ok(Some(pass))
    } else {
        Ok(None)
    }
}

/// Reads the DATA body until the "." line (dot-unstuffing).
async fn read_data<S: AsyncRead + AsyncWrite + Unpin + Send>(
    c: &mut Conn<S>,
) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(line) = c.line().await? {
        if line == "." {
            break;
        }
        let l = line.strip_prefix('.').unwrap_or(&line);
        out.extend_from_slice(l.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    Ok(out)
}

/// "RCPT TO:<addr>" -> addr
fn extract_addr(line: &str) -> Option<String> {
    let start = line.find('<')?;
    let end = line.find('>')?;
    if end > start + 1 {
        Some(line[start + 1..end].to_string())
    } else {
        None
    }
}
