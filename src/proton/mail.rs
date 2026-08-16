//! Proton mail account layer: user, addresses, keys, key salts.
//! (Message listing/decryption lives in a separate module.)

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;

use super::client::{ApiError, Client};

/// Proton PGP private key (address or user key).
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)] // mirrors the API schema
pub struct PrivateKey {
    #[serde(rename = "ID")]
    pub id: String,
    /// Armored PGP private key.
    #[serde(rename = "PrivateKey")]
    pub private_key: String,
    /// If non-empty: the key is unlocked via a token encrypted to the user key.
    #[serde(rename = "Token", default)]
    pub token: String,
    #[serde(rename = "Signature", default)]
    pub signature: String,
    #[serde(rename = "Primary", default)]
    pub primary: i32,
    #[serde(rename = "Active", default)]
    pub active: i32,
    #[serde(rename = "Fingerprint", default)]
    pub fingerprint: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // mirrors the API schema
pub struct User {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "Keys", default)]
    pub keys: Vec<PrivateKey>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // mirrors the API schema
pub struct Address {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Email")]
    pub email: String,
    #[serde(rename = "Status", default)]
    pub status: i32,
    #[serde(rename = "Receive", default)]
    pub receive: i32,
    #[serde(rename = "Order", default)]
    pub order: i64,
    #[serde(rename = "DisplayName", default)]
    pub display_name: String,
    #[serde(rename = "HasKeys", default)]
    pub has_keys: i32,
    #[serde(rename = "Keys", default)]
    pub keys: Vec<PrivateKey>,
}

/// keyID → salt bytes (None if there is no salt).
#[derive(Debug, Clone)]
pub struct KeySalt {
    pub id: String,
    pub salt: Option<Vec<u8>>,
}

/// Builds a KeySalt list from the raw `/keys/salts` JSON captured at login time.
/// (The sensitive endpoint requires the "password scope" and can't be called again
/// after refresh, so we use the copy captured at login.)
pub fn key_salts_from_value(v: &serde_json::Value) -> Result<Vec<KeySalt>, ApiError> {
    #[derive(Deserialize)]
    struct Raw {
        #[serde(rename = "ID")]
        id: String,
        #[serde(rename = "KeySalt")]
        key_salt: Option<String>,
    }
    let arr = v.get("KeySalts").cloned().unwrap_or(serde_json::Value::Null);
    let raws: Vec<Raw> = serde_json::from_value(arr).unwrap_or_default();
    let mut out = Vec::with_capacity(raws.len());
    for k in raws {
        let salt = match k.key_salt {
            Some(s) if !s.is_empty() => Some(
                B64.decode(&s)
                    .map_err(|e| ApiError::Other(format!("bad key salt: {e}")))?,
            ),
            _ => None,
        };
        out.push(KeySalt { id: k.id, salt });
    }
    Ok(out)
}

/// User folder/label.
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)] // mirrors the API schema
pub struct Label {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Type", default)]
    pub label_type: i32,
    #[serde(rename = "Exclusive", default)]
    pub exclusive: i32,
}

impl Client {
    /// Lists custom folders/labels (excluding system folders).
    pub async fn list_labels(&self) -> Result<Vec<Label>, ApiError> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Labels", default)]
            labels: Vec<Label>,
        }
        let r: R = self.get_json("/labels").await?;
        Ok(r.labels)
    }

    pub async fn get_current_user(&self) -> Result<User, ApiError> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "User")]
            user: User,
        }
        let r: R = self.get_json("/users").await?;
        Ok(r.user)
    }

    pub async fn list_addresses(&self) -> Result<Vec<Address>, ApiError> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Addresses")]
            addresses: Vec<Address>,
        }
        let r: R = self.get_json("/addresses").await?;
        Ok(r.addresses)
    }

}
