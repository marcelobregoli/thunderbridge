//! Thunderbird-compatible IMAP server (reading + flag sync).
//!
//! Plain TCP on localhost (127.0.0.1:1143). LOGIN opens the stored session with the
//! bridge password. All system + custom folders are listed; SELECT fetches ALL of a
//! folder's messages; UIDs are persistent (uidmap.json). FETCH serves
//! metadata/ENVELOPE/body (PGP-decrypted); STORE \Seen reflects read/unread back to Proton.

use std::sync::Arc;

use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::proton::messages::Message;
use crate::session::Session;
use crate::uidmap::UidStore;

/// Plain TCP IMAP listener.
pub async fn serve(username: String, port: u16) -> anyhow::Result<()> {
    accept_loop(username, port, None).await
}

/// TLS (implicit) IMAP listener.
pub async fn serve_tls(username: String, port: u16, acceptor: TlsAcceptor) -> anyhow::Result<()> {
    accept_loop(username, port, Some(acceptor)).await
}

async fn accept_loop(
    username: String,
    port: u16,
    tls: Option<TlsAcceptor>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!(
        "IMAP{}: listening on 127.0.0.1:{port} (user: {username})",
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
                    Ok(s) => handle_conn(s, &username).await,
                    Err(e) => {
                        eprintln!("IMAP [{peer}] TLS handshake: {e}");
                        return;
                    }
                },
                None => handle_conn(tcp, &username).await,
            };
            if let Err(e) = res {
                eprintln!("IMAP [{peer}] connection ended: {e}");
            }
        });
    }
}

/// A folder (system or custom).
#[derive(Clone)]
struct Folder {
    name: String,
    label: String,
}

/// A message in the selected folder (persistent UID + metadata).
struct Msg {
    uid: u32,
    meta: Message,
}

struct Conn<S: AsyncRead + AsyncWrite + Unpin> {
    reader: BufReader<ReadHalf<S>>,
    writer: WriteHalf<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    async fn send(&mut self, s: &str) -> std::io::Result<()> {
        self.writer.write_all(s.as_bytes()).await
    }
    async fn read_line(&mut self) -> std::io::Result<Option<String>> {
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

/// Proton system folders (display name -> label ID).
const SYSTEM_FOLDERS: &[(&str, &str)] = &[
    ("INBOX", "0"),
    ("Archive", "6"),
    ("Sent", "7"),
    ("Drafts", "8"),
    ("Spam", "4"),
    ("Trash", "3"),
    ("Starred", "10"),
    ("All Mail", "5"),
];

async fn build_folders(s: &Session) -> Vec<Folder> {
    let mut folders: Vec<Folder> = SYSTEM_FOLDERS
        .iter()
        .map(|(n, l)| Folder {
            name: n.to_string(),
            label: l.to_string(),
        })
        .collect();
    // Custom folders/labels (best-effort).
    if let Ok(labels) = s.client.list_labels().await {
        for l in labels {
            if folders.iter().any(|f| f.name.eq_ignore_ascii_case(&l.name)) {
                continue;
            }
            folders.push(Folder {
                name: l.name,
                label: l.id,
            });
        }
    }
    folders
}

async fn handle_conn<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: S,
    username: &str,
) -> anyhow::Result<()> {
    let (r, w) = split(stream);
    let mut c = Conn {
        reader: BufReader::new(r),
        writer: w,
    };
    c.send("* OK thunderbridge IMAP4rev1 ready\r\n").await?;

    let mut session: Option<Session> = None;
    let mut folders: Vec<Folder> = Vec::new();
    let mut mailbox: Vec<Msg> = Vec::new();
    let mut selected_label: Option<String> = None;
    let mut uidmap = UidStore::load();

    while let Some(line) = c.read_line().await? {
        let (tag, rest) = split_tag(&line);
        if tag.is_empty() {
            continue;
        }
        let (cmd, args) = split_cmd(rest);
        let cmd_up = cmd.to_ascii_uppercase();
        // "UID FETCH/STORE/SEARCH" sub-command split
        let (eff_cmd, eff_args, is_uid) = if cmd_up == "UID" {
            let (sub, rst) = split_cmd(args);
            (sub.to_ascii_uppercase(), rst, true)
        } else {
            (cmd_up.clone(), args, false)
        };

        match eff_cmd.as_str() {
            "CAPABILITY" => {
                c.send("* CAPABILITY IMAP4rev1 IDLE UIDPLUS LITERAL+\r\n").await?;
                c.send(&format!("{tag} OK CAPABILITY completed\r\n")).await?;
            }
            "LOGIN" => {
                let (_user, pass) = {
                    let toks = tokenize(eff_args);
                    (
                        toks.first().cloned().unwrap_or_default(),
                        toks.get(1).cloned().unwrap_or_default(),
                    )
                };
                match Session::open(username, &pass).await {
                    Ok(s) => {
                        folders = build_folders(&s).await;
                        session = Some(s);
                        c.send(&format!("{tag} OK LOGIN completed\r\n")).await?;
                    }
                    Err(e) => {
                        eprintln!("IMAP login error: {e}");
                        c.send(&format!("{tag} NO [AUTHENTICATIONFAILED] {e}\r\n")).await?;
                    }
                }
            }
            "LOGOUT" => {
                c.send("* BYE thunderbridge logging out\r\n").await?;
                c.send(&format!("{tag} OK LOGOUT completed\r\n")).await?;
                break;
            }
            "NOOP" | "CHECK" => {
                c.send(&format!("{tag} OK {eff_cmd} completed\r\n")).await?;
            }
            "LIST" | "LSUB" => {
                for f in &folders {
                    c.send(&format!(
                        "* {eff_cmd} (\\HasNoChildren) \"/\" \"{}\"\r\n",
                        f.name
                    ))
                    .await?;
                }
                c.send(&format!("{tag} OK {eff_cmd} completed\r\n")).await?;
            }
            "SELECT" | "EXAMINE" => {
                if session.is_none() {
                    c.send(&format!("{tag} NO not authenticated\r\n")).await?;
                    continue;
                }
                let name = unquote(eff_args.trim());
                let Some(folder) = folders
                    .iter()
                    .find(|f| f.name.eq_ignore_ascii_case(&name))
                    .cloned()
                else {
                    c.send(&format!("{tag} NO no such mailbox\r\n")).await?;
                    continue;
                };
                let s = session.as_ref().unwrap();
                match load_folder(s, &folder.label, &mut uidmap).await {
                    Ok(msgs) => {
                        mailbox = msgs;
                        selected_label = Some(folder.label.clone());
                        let n = mailbox.len();
                        let uidvalidity = uidmap.uidvalidity(&folder.label);
                        let uidnext = uidmap.uidnext(&folder.label);
                        let unseen = mailbox.iter().filter(|m| m.meta.unread != 0).count();
                        c.send(&format!("* {n} EXISTS\r\n")).await?;
                        c.send("* 0 RECENT\r\n").await?;
                        c.send("* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n").await?;
                        c.send("* OK [PERMANENTFLAGS (\\Seen \\Flagged \\Deleted)] limited\r\n").await?;
                        c.send(&format!("* OK [UIDVALIDITY {uidvalidity}] uids\r\n")).await?;
                        c.send(&format!("* OK [UIDNEXT {uidnext}] next\r\n")).await?;
                        c.send(&format!("* OK [UNSEEN {}] first unseen\r\n", unseen)).await?;
                        let access = if eff_cmd == "EXAMINE" { "READ-ONLY" } else { "READ-WRITE" };
                        c.send(&format!("{tag} OK [{access}] {eff_cmd} completed\r\n")).await?;
                    }
                    Err(e) => {
                        c.send(&format!("{tag} NO {e}\r\n")).await?;
                    }
                }
            }
            "STATUS" => {
                // STATUS "<mbox>" (items)
                let name = unquote(eff_args.split('(').next().unwrap_or("INBOX").trim());
                let label = folders
                    .iter()
                    .find(|f| f.name.eq_ignore_ascii_case(&name))
                    .map(|f| f.label.clone())
                    .unwrap_or_else(|| "0".to_string());
                let uidvalidity = uidmap.uidvalidity(&label);
                let uidnext = uidmap.uidnext(&label);
                let n = if Some(&label) == selected_label.as_ref() {
                    mailbox.len()
                } else {
                    0
                };
                c.send(&format!(
                    "* STATUS \"{name}\" (MESSAGES {n} UIDNEXT {uidnext} UIDVALIDITY {uidvalidity} UNSEEN 0 RECENT 0)\r\n"
                ))
                .await?;
                c.send(&format!("{tag} OK STATUS completed\r\n")).await?;
            }
            "FETCH" => {
                if session.is_none() {
                    c.send(&format!("{tag} NO not authenticated\r\n")).await?;
                    continue;
                }
                handle_fetch(&mut c, session.as_ref().unwrap(), &mailbox, eff_args, is_uid).await?;
                c.send(&format!("{tag} OK FETCH completed\r\n")).await?;
            }
            "STORE" => {
                if let (Some(s), Some(label)) = (session.as_ref(), selected_label.as_ref()) {
                    handle_store(&mut c, s, &mut mailbox, label, eff_args, is_uid).await?;
                }
                c.send(&format!("{tag} OK STORE completed\r\n")).await?;
            }
            "SEARCH" => {
                // Simple: ALL -> all seq/uid
                let ids: Vec<String> = if is_uid {
                    mailbox.iter().map(|m| m.uid.to_string()).collect()
                } else {
                    (1..=mailbox.len()).map(|i| i.to_string()).collect()
                };
                c.send(&format!("* SEARCH {}\r\n", ids.join(" "))).await?;
                c.send(&format!("{tag} OK SEARCH completed\r\n")).await?;
            }
            "CLOSE" => {
                mailbox.clear();
                selected_label = None;
                c.send(&format!("{tag} OK CLOSE completed\r\n")).await?;
            }
            "IDLE" => {
                c.send("+ idling\r\n").await?;
                loop {
                    match c.read_line().await? {
                        Some(l) if l.trim().eq_ignore_ascii_case("DONE") => break,
                        Some(_) => {}
                        None => return Ok(()),
                    }
                }
                c.send(&format!("{tag} OK IDLE terminated\r\n")).await?;
            }
            _ => {
                c.send(&format!("{tag} BAD unknown command\r\n")).await?;
            }
        }
    }
    Ok(())
}

/// Fetches ALL of a folder's messages by paging, assigns persistent UIDs, sorts by UID.
async fn load_folder(
    s: &Session,
    label: &str,
    uidmap: &mut UidStore,
) -> anyhow::Result<Vec<Msg>> {
    let mut metas: Vec<Message> = Vec::new();
    let mut page = 0;
    loop {
        let (total, msgs) = s.client.list_messages(label, page, 150).await?;
        let got = msgs.len();
        metas.extend(msgs);
        if got == 0 || metas.len() >= total as usize || page > 300 {
            break;
        }
        page += 1;
        if page % 5 == 0 {
            eprintln!("  IMAP: {label} fetched {} messages...", metas.len());
        }
    }
    // Ascending time (oldest first) -> persistent UID; then order by UID.
    metas.sort_by_key(|m| m.time);
    let mut out: Vec<Msg> = metas
        .into_iter()
        .map(|m| {
            let uid = uidmap.uid_for(label, &m.id);
            Msg { uid, meta: m }
        })
        .collect();
    out.sort_by_key(|m| m.uid);
    uidmap.save();
    Ok(out)
}

/// Resolves the FETCH set (seq or uid) and returns (seq, &Msg) pairs.
fn select_targets<'a>(set: &str, is_uid: bool, mailbox: &'a [Msg]) -> Vec<(usize, &'a Msg)> {
    let mut out = Vec::new();
    let max_seq = mailbox.len();
    let max_uid = mailbox.last().map(|m| m.uid).unwrap_or(0);
    for part in set.split(',') {
        let (lo, hi) = if let Some((a, b)) = part.split_once(':') {
            let hi_default = if is_uid { max_uid } else { max_seq as u32 };
            let lo = a.parse::<u32>().unwrap_or(1);
            let hi = if b == "*" {
                hi_default
            } else {
                b.parse::<u32>().unwrap_or(hi_default)
            };
            (lo.min(hi), lo.max(hi))
        } else if part == "*" {
            let v = if is_uid { max_uid } else { max_seq as u32 };
            (v, v)
        } else {
            let v = part.parse::<u32>().unwrap_or(0);
            (v, v)
        };
        for (i, m) in mailbox.iter().enumerate() {
            let key = if is_uid { m.uid } else { (i + 1) as u32 };
            if key >= lo && key <= hi {
                out.push((i + 1, m));
            }
        }
    }
    out
}

async fn handle_fetch<S: AsyncRead + AsyncWrite + Unpin + Send>(
    c: &mut Conn<S>,
    session: &Session,
    mailbox: &[Msg],
    args: &str,
    is_uid: bool,
) -> anyhow::Result<()> {
    let (set, items) = split_once_ws(args);
    let items_up = items.to_ascii_uppercase();

    for (seq, m) in select_targets(set, is_uid, mailbox) {
        let msg = &m.meta;
        let mut parts: Vec<String> = Vec::new();

        if is_uid || items_up.contains("UID") {
            parts.push(format!("UID {}", m.uid));
        }
        if items_up.contains("FLAGS") {
            parts.push(format!("FLAGS ({})", flags_str(msg)));
        }
        if items_up.contains("RFC822.SIZE") {
            parts.push(format!("RFC822.SIZE {}", msg.size.max(0)));
        }
        if items_up.contains("INTERNALDATE") {
            parts.push(format!("INTERNALDATE \"{}\"", rfc2822_date(msg.time)));
        }
        if items_up.contains("ENVELOPE") {
            parts.push(format!("ENVELOPE {}", envelope(msg)));
        }
        if items_up.contains("BODYSTRUCTURE") {
            parts.push("BODYSTRUCTURE (\"text\" \"html\" (\"charset\" \"utf-8\") NIL NIL \"quoted-printable\" 0 0)".to_string());
        }

        let wants_body = (items_up.contains("RFC822") && !items_up.contains("RFC822.SIZE")
            && !items_up.contains("RFC822.HEADER"))
            || items_up.contains("BODY[]")
            || items_up.contains("BODY.PEEK[]");
        let wants_header = items_up.contains("BODY[HEADER")
            || items_up.contains("BODY.PEEK[HEADER")
            || items_up.contains("RFC822.HEADER");

        if wants_body {
            let raw = build_rfc822(session, msg).await;
            let section = if items_up.contains("RFC822") && !items_up.contains("BODY") {
                "RFC822"
            } else {
                "BODY[]"
            };
            parts.push(format!("{section} {{{}}}\r\n{raw}", raw.len()));
        } else if wants_header {
            let hdr = header_block(session, msg).await;
            let section = if items_up.contains("RFC822.HEADER") {
                "RFC822.HEADER"
            } else {
                "BODY[HEADER]"
            };
            parts.push(format!("{section} {{{}}}\r\n{hdr}", hdr.len()));
        }

        c.send(&format!("* {seq} FETCH ({})\r\n", parts.join(" "))).await?;
    }
    Ok(())
}

async fn handle_store<S: AsyncRead + AsyncWrite + Unpin + Send>(
    c: &mut Conn<S>,
    session: &Session,
    mailbox: &mut [Msg],
    _label: &str,
    args: &str,
    is_uid: bool,
) -> anyhow::Result<()> {
    // STORE <set> <+FLAGS/-FLAGS/FLAGS[.SILENT]> (<flags>)
    let (set, rest) = split_once_ws(args);
    let rest_up = rest.to_ascii_uppercase();
    let add = rest_up.starts_with("+FLAGS");
    let remove = rest_up.starts_with("-FLAGS");
    let touches_seen = rest_up.contains("\\SEEN");
    let silent = rest_up.contains(".SILENT");

    // Target message indices
    let targets: Vec<usize> = {
        let max_seq = mailbox.len();
        let max_uid = mailbox.last().map(|m| m.uid).unwrap_or(0);
        let mut idxs = Vec::new();
        for part in set.split(',') {
            let (lo, hi) = if let Some((a, b)) = part.split_once(':') {
                let hidef = if is_uid { max_uid } else { max_seq as u32 };
                let lo = a.parse::<u32>().unwrap_or(1);
                let hi = if b == "*" { hidef } else { b.parse().unwrap_or(hidef) };
                (lo.min(hi), lo.max(hi))
            } else if part == "*" {
                let v = if is_uid { max_uid } else { max_seq as u32 };
                (v, v)
            } else {
                let v = part.parse::<u32>().unwrap_or(0);
                (v, v)
            };
            for (i, m) in mailbox.iter().enumerate() {
                let key = if is_uid { m.uid } else { (i + 1) as u32 };
                if key >= lo && key <= hi {
                    idxs.push(i);
                }
            }
        }
        idxs
    };

    if touches_seen && (add || remove) {
        let ids: Vec<String> = targets.iter().map(|&i| mailbox[i].meta.id.clone()).collect();
        let res = if add {
            session.client.mark_read(&ids).await
        } else {
            session.client.mark_unread(&ids).await
        };
        if res.is_ok() {
            for &i in &targets {
                mailbox[i].meta.unread = if add { 0 } else { 1 };
            }
        }
    }

    if !silent {
        for &i in &targets {
            let m = &mailbox[i];
            let seq = i + 1;
            c.send(&format!(
                "* {seq} FETCH (UID {} FLAGS ({}))\r\n",
                m.uid,
                flags_str(&m.meta)
            ))
            .await?;
        }
    }
    Ok(())
}

fn flags_str(msg: &Message) -> String {
    if msg.unread == 0 {
        "\\Seen".to_string()
    } else {
        String::new()
    }
}

/// Converts a Proton message to RFC822: original Header + decrypted body.
async fn build_rfc822(session: &Session, meta: &Message) -> String {
    let full = match session.client.get_message(&meta.id).await {
        Ok(m) => m,
        Err(_) => return synth_headers(meta) + "\r\n\r\n(message unavailable)",
    };
    let body = if full.is_encrypted == 0 {
        full.body.clone()
    } else {
        session
            .keyring
            .decrypt_body(&full.body)
            .unwrap_or_else(|_| "(could not decrypt)".to_string())
    };
    if !full.header.trim().is_empty() {
        format!("{}\r\n\r\n{}", full.header.trim_end(), body)
    } else {
        format!("{}\r\n\r\n{}", synth_headers(&full), body)
    }
}

async fn header_block(session: &Session, meta: &Message) -> String {
    match session.client.get_message(&meta.id).await {
        Ok(m) if !m.header.trim().is_empty() => format!("{}\r\n\r\n", m.header.trim_end()),
        Ok(m) => format!("{}\r\n\r\n", synth_headers(&m)),
        Err(_) => format!("{}\r\n\r\n", synth_headers(meta)),
    }
}

fn synth_headers(m: &Message) -> String {
    let from = m
        .sender
        .as_ref()
        .map(|s| fmt_addr(&s.name, &s.address))
        .unwrap_or_default();
    let to = m
        .to_list
        .iter()
        .map(|a| fmt_addr(&a.name, &a.address))
        .collect::<Vec<_>>()
        .join(", ");
    let ct = if m.mime_type.is_empty() {
        "text/html; charset=utf-8"
    } else {
        &m.mime_type
    };
    format!(
        "From: {from}\r\nTo: {to}\r\nSubject: {}\r\nDate: {}\r\nContent-Type: {ct}\r\nMIME-Version: 1.0",
        m.subject,
        rfc2822_date(m.time),
    )
}

fn fmt_addr(name: &str, addr: &str) -> String {
    if name.is_empty() {
        addr.to_string()
    } else {
        format!("{name} <{addr}>")
    }
}

fn envelope(m: &Message) -> String {
    let date = q(&rfc2822_date(m.time));
    let subject = q(&m.subject);
    let sender_slice = m.sender.as_slice();
    let from = addr_list(sender_slice);
    let sender = from.clone();
    let reply_to = from.clone();
    let to = addr_list(&m.to_list);
    let cc = addr_list(&m.cc_list);
    let bcc = addr_list(&m.bcc_list);
    format!("({date} {subject} {from} {sender} {reply_to} {to} {cc} {bcc} NIL NIL)")
}

fn addr_list(list: &[crate::proton::messages::MessageAddress]) -> String {
    if list.is_empty() {
        return "NIL".to_string();
    }
    let items: Vec<String> = list
        .iter()
        .map(|a| {
            let (mbox, host) = a.address.split_once('@').unwrap_or((&a.address, ""));
            format!("({} NIL {} {})", nstr(&a.name), q(mbox), q(host))
        })
        .collect();
    format!("({})", items.join(""))
}

// ---- parsing / formatting ----

fn split_tag(line: &str) -> (&str, &str) {
    line.split_once(' ').unwrap_or((line, ""))
}
fn split_cmd(rest: &str) -> (&str, &str) {
    rest.split_once(' ').unwrap_or((rest, ""))
}
fn split_once_ws(s: &str) -> (&str, &str) {
    let s = s.trim();
    s.split_once(' ').map(|(a, b)| (a.trim(), b.trim())).unwrap_or((s, ""))
}

fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    for ch in s.chars() {
        match ch {
            '"' => in_q = !in_q,
            c if c.is_whitespace() && !in_q => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches('"').to_string()
}

fn q(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}
fn nstr(s: &str) -> String {
    if s.is_empty() {
        "NIL".to_string()
    } else {
        q(s)
    }
}

fn rfc2822_date(unix: i64) -> String {
    let days = unix.div_euclid(86400);
    let secs = unix.rem_euclid(86400);
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let (y, mo, d) = civil_from_days(days);
    let wd = ((days % 7 + 4) % 7 + 7) % 7;
    let wdn = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][wd as usize];
    let mon = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][(mo - 1) as usize];
    format!("{wdn}, {d:02} {mon} {y} {h:02}:{m:02}:{s:02} +0000")
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}
