//! Outgoing mail: parse the MIME, create a Proton draft, encrypt the body with a
//! session key, produce a PKESK (internal) or cleartext (external) key packet per
//! recipient, and send via `POST /messages/{id}`.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use super::client::{ApiError, Client};
use super::crypto::pkesk_for_recipient;
use crate::session::Session;

#[derive(Serialize)]
struct AddrRef {
    #[serde(rename = "Address")]
    address: String,
    #[serde(rename = "Name")]
    name: String,
}

#[derive(Serialize)]
struct DraftMessage {
    #[serde(rename = "Subject")]
    subject: String,
    #[serde(rename = "Sender")]
    sender: AddrRef,
    #[serde(rename = "ToList")]
    to_list: Vec<AddrRef>,
    #[serde(rename = "CCList")]
    cc_list: Vec<AddrRef>,
    #[serde(rename = "BCCList")]
    bcc_list: Vec<AddrRef>,
    #[serde(rename = "Body")]
    body: String,
    #[serde(rename = "MIMEType")]
    mime_type: String,
    #[serde(rename = "AddressID")]
    address_id: String,
    #[serde(rename = "Unread")]
    unread: i32,
}

#[derive(Serialize)]
struct CreateDraftReq {
    #[serde(rename = "Message")]
    message: DraftMessage,
}

#[derive(Deserialize)]
struct DraftResp {
    #[serde(rename = "Message")]
    message: MsgId,
}
#[derive(Deserialize)]
struct MsgId {
    #[serde(rename = "ID")]
    id: String,
}

#[derive(Deserialize)]
struct PubKeysResp {
    #[serde(rename = "RecipientType", default)]
    recipient_type: i32,
    #[serde(rename = "Keys", default)]
    keys: Vec<PubKey>,
}
#[derive(Deserialize)]
struct PubKey {
    #[serde(rename = "PublicKey", default)]
    public_key: String,
}

#[derive(Serialize)]
struct AddressPkg {
    #[serde(rename = "Type")]
    typ: i32,
    #[serde(rename = "BodyKeyPacket", skip_serializing_if = "Option::is_none")]
    body_key_packet: Option<String>,
    #[serde(rename = "Signature")]
    signature: i32,
}
#[derive(Serialize)]
struct PackedKey {
    #[serde(rename = "Algorithm")]
    algorithm: String,
    #[serde(rename = "Key")]
    key: String,
}
#[derive(Serialize)]
struct PackageSet {
    #[serde(rename = "Type")]
    typ: i32,
    #[serde(rename = "Addresses")]
    addresses: HashMap<String, AddressPkg>,
    #[serde(rename = "MIMEType")]
    mime_type: String,
    #[serde(rename = "Body")]
    body: String,
    #[serde(rename = "BodyKey", skip_serializing_if = "Option::is_none")]
    body_key: Option<PackedKey>,
}
#[derive(Serialize)]
struct SendReq {
    #[serde(rename = "Packages")]
    packages: Vec<PackageSet>,
}

impl Client {
    async fn get_public_keys(&self, email: &str) -> Result<PubKeysResp, ApiError> {
        let enc: String = url::form_urlencoded::byte_serialize(email.as_bytes()).collect();
        self.get_json(&format!("/keys?Email={enc}")).await
    }
    async fn create_draft(&self, req: &CreateDraftReq) -> Result<String, ApiError> {
        let r: DraftResp = self.post_json("/messages", req, None).await?;
        Ok(r.message.id)
    }
    async fn send_message(&self, id: &str, req: &SendReq) -> Result<(), ApiError> {
        let _: serde_json::Value = self.post_json(&format!("/messages/{id}"), req, None).await?;
        Ok(())
    }
}

/// Sends the raw RFC822 outgoing message through Proton. `envelope_rcpts` = the
/// recipients from the SMTP RCPT TO envelope (delivery goes to these).
pub async fn send_mail(
    session: &Session,
    raw: &[u8],
    envelope_rcpts: &[String],
) -> anyhow::Result<()> {
    let parsed = mail_parser::MessageParser::default()
        .parse(raw)
        .ok_or_else(|| anyhow::anyhow!("could not parse MIME"))?;

    let subject = parsed.subject().unwrap_or("").to_string();
    let html = parsed.body_html(0).map(|h| h.into_owned());
    let text = parsed.body_text(0).map(|t| t.into_owned());
    // Internal: prefer HTML. External (ClearScheme) REQUIRES text/plain on Proton.
    let (body, mime_type) = match &html {
        Some(h) => (h.clone(), "text/html".to_string()),
        None => (text.clone().unwrap_or_default(), "text/plain".to_string()),
    };
    let external_body = text.clone().or_else(|| html.clone()).unwrap_or_default();

    // Sender address (the first address).
    let addr = session
        .addresses
        .first()
        .ok_or_else(|| anyhow::anyhow!("no sender address"))?;

    let to_list = header_addrs(parsed.to());
    let cc_list = header_addrs(parsed.cc());

    // 1) Draft (body encrypted to self).
    let enc_body = session.keyring.encrypt_to_self(&body)?;
    let draft = CreateDraftReq {
        message: DraftMessage {
            subject: subject.clone(),
            sender: AddrRef {
                address: addr.email.clone(),
                name: addr.display_name.clone(),
            },
            to_list,
            cc_list,
            bcc_list: Vec::new(),
            body: enc_body,
            mime_type: mime_type.clone(),
            address_id: addr.id.clone(),
            unread: 0,
        },
    };
    let draft_id = session.client.create_draft(&draft).await?;

    // 2) Split recipients into internal (Proton, has a PGP key) / external (cleartext).
    let mut internal: Vec<(String, String)> = Vec::new(); // (email, armored pubkey)
    let mut external: Vec<String> = Vec::new();
    for rcpt in envelope_rcpts {
        match session.client.get_public_keys(rcpt).await {
            Ok(p) if p.recipient_type == 1 => {
                match p.keys.into_iter().find(|k| !k.public_key.is_empty()) {
                    Some(k) => internal.push((rcpt.clone(), k.public_key)),
                    None => external.push(rcpt.clone()),
                }
            }
            _ => external.push(rcpt.clone()),
        }
    }

    // 3) Packages: internal = encrypted+signed SEIPD + PKESK; external = signed cleartext.
    let mut packages: Vec<PackageSet> = Vec::new();

    if !internal.is_empty() {
        let (body_b64, sk) = session.keyring.seal_body(&body)?;
        let mut addrs: HashMap<String, AddressPkg> = HashMap::new();
        for (email, pubkey) in &internal {
            let pkesk = pkesk_for_recipient(&sk, pubkey)?;
            addrs.insert(
                email.clone(),
                AddressPkg {
                    typ: 1,
                    body_key_packet: Some(pkesk),
                    signature: 1,
                },
            );
        }
        packages.push(PackageSet {
            typ: 1,
            addresses: addrs,
            mime_type: mime_type.clone(),
            body: body_b64,
            body_key: None,
        });
    }

    if !external.is_empty() {
        // ClearScheme: signed+encrypted body (text/plain) + session key IN THE CLEAR (BodyKey).
        let (body_b64, sk) = session.keyring.seal_body(&external_body)?;
        let mut addrs: HashMap<String, AddressPkg> = HashMap::new();
        for email in &external {
            addrs.insert(
                email.clone(),
                AddressPkg {
                    typ: 4,
                    body_key_packet: None,
                    signature: 1,
                },
            );
        }
        packages.push(PackageSet {
            typ: 4,
            addresses: addrs,
            mime_type: "text/plain".to_string(),
            body: body_b64,
            body_key: Some(PackedKey {
                algorithm: "aes256".to_string(),
                key: B64.encode(&sk),
            }),
        });
    }

    session
        .client
        .send_message(&draft_id, &SendReq { packages })
        .await?;
    Ok(())
}

fn header_addrs(addr: Option<&mail_parser::Address>) -> Vec<AddrRef> {
    let Some(a) = addr else {
        return Vec::new();
    };
    a.iter()
        .filter_map(|x| {
            x.address().map(|em| AddrRef {
                address: em.to_string(),
                name: x.name().unwrap_or("").to_string(),
            })
        })
        .collect()
}
