//! Proton message API: listing and fetching individual messages.
//! Body decryption (PGP) lives in the `crypto` module.

use serde::Deserialize;

use super::client::{ApiError, Client};

/// Standard Proton system label IDs (for folder mapping).
#[allow(dead_code)] // full reference set; not all are used directly
pub mod label {
    pub const INBOX: &str = "0";
    pub const ALL_DRAFTS: &str = "1";
    pub const ALL_SENT: &str = "2";
    pub const TRASH: &str = "3";
    pub const SPAM: &str = "4";
    pub const ALL_MAIL: &str = "5";
    pub const ARCHIVE: &str = "6";
    pub const SENT: &str = "7";
    pub const DRAFTS: &str = "8";
    pub const STARRED: &str = "10";
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct MessageAddress {
    #[serde(rename = "Address", default)]
    pub address: String,
    #[serde(rename = "Name", default)]
    pub name: String,
}

/// Message (metadata in listings; `body` is also populated when fetched individually).
#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)] // mirrors the API schema; not every field is consumed
pub struct Message {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Order", default)]
    pub order: i64,
    #[serde(rename = "Subject", default)]
    pub subject: String,
    #[serde(rename = "Unread", default)]
    pub unread: i32,
    #[serde(rename = "Sender", default)]
    pub sender: Option<MessageAddress>,
    #[serde(rename = "ToList", default)]
    pub to_list: Vec<MessageAddress>,
    #[serde(rename = "CCList", default)]
    pub cc_list: Vec<MessageAddress>,
    #[serde(rename = "BCCList", default)]
    pub bcc_list: Vec<MessageAddress>,
    #[serde(rename = "ReplyTos", default)]
    pub reply_tos: Vec<MessageAddress>,
    #[serde(rename = "Time", default)]
    pub time: i64,
    #[serde(rename = "Size", default)]
    pub size: i64,
    #[serde(rename = "NumAttachments", default)]
    pub num_attachments: i32,
    /// 0 = plaintext; other values are PGP-encrypted.
    #[serde(rename = "IsEncrypted", default)]
    pub is_encrypted: i32,
    #[serde(rename = "AddressID", default)]
    pub address_id: String,
    #[serde(rename = "Body", default)]
    pub body: String,
    #[serde(rename = "MIMEType", default)]
    pub mime_type: String,
    /// Raw RFC822 headers (present when fetched individually).
    #[serde(rename = "Header", default)]
    pub header: String,
    #[serde(rename = "LabelIDs", default)]
    pub label_ids: Vec<String>,
}

impl Client {
    /// Lists messages (metadata) under a label (folder).
    pub async fn list_messages(
        &self,
        label: &str,
        page: i32,
        page_size: i32,
    ) -> Result<(i32, Vec<Message>), ApiError> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Total", default)]
            total: i32,
            #[serde(rename = "Messages", default)]
            messages: Vec<Message>,
        }
        let path = format!(
            "/messages?Label={label}&Page={page}&PageSize={page_size}&Sort=Time&Desc=1"
        );
        let r: R = self.get_json(&path).await?;
        Ok((r.total, r.messages))
    }

    /// Fetches a single message with its full body.
    pub async fn get_message(&self, id: &str) -> Result<Message, ApiError> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Message")]
            message: Message,
        }
        let r: R = self.get_json(&format!("/messages/{id}")).await?;
        Ok(r.message)
    }

    /// Marks messages as read.
    pub async fn mark_read(&self, ids: &[String]) -> Result<(), ApiError> {
        self.mark("/messages/read", ids).await
    }

    /// Marks messages as unread.
    pub async fn mark_unread(&self, ids: &[String]) -> Result<(), ApiError> {
        self.mark("/messages/unread", ids).await
    }

    async fn mark(&self, path: &str, ids: &[String]) -> Result<(), ApiError> {
        #[derive(serde::Serialize)]
        struct Req<'a> {
            #[serde(rename = "IDs")]
            ids: &'a [String],
        }
        let _: serde_json::Value = self.put_json(path, &Req { ids }).await?;
        Ok(())
    }
}
