//! On-disk AEAD-encrypted session store.
//!
//! Per-user session data (UID, tokens, passwords, key salts) is serialized to JSON and
//! encrypted with a random 32-byte key using XChaCha20-Poly1305. The base64 of that key
//! is handed to the user as the **bridge password**; the disk holds only the encrypted
//! data, never the key.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::proton::auth::Auth;

const NONCE_LEN: usize = 24;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("config dir not found")]
    NoConfigDir,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid bridge password")]
    BadPassword,
    #[error("decryption error (wrong bridge password?)")]
    Decrypt,
    #[error("user not found: {0}")]
    NotFound(String),
}

/// Data persisted on disk, sufficient to reconstruct a Proton session for the bridge.
#[derive(Serialize, Deserialize)]
pub struct CachedSession {
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    pub password_mode: i32,
    pub login_password: String,
    pub mailbox_password: String,
    /// Raw `/keys/salts` response (used to unlock keys later).
    pub key_salts: serde_json::Value,
}

impl Drop for CachedSession {
    fn drop(&mut self) {
        self.uid.zeroize();
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.login_password.zeroize();
        self.mailbox_password.zeroize();
    }
}

impl CachedSession {
    pub fn from_auth(auth: &Auth, login_password: String, mailbox_password: String) -> Self {
        CachedSession {
            uid: auth.uid.clone(),
            access_token: auth.access_token.clone(),
            refresh_token: auth.refresh_token.clone(),
            password_mode: auth.password_mode,
            login_password,
            mailbox_password,
            key_salts: serde_json::Value::Null,
        }
    }
}

fn store_path() -> Result<PathBuf, StoreError> {
    let dirs = directories::ProjectDirs::from("", "", "thunderbridge")
        .ok_or(StoreError::NoConfigDir)?;
    let dir = dirs.config_dir().to_path_buf();
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    Ok(dir.join("sessions.json"))
}

fn read_all() -> Result<HashMap<String, String>, StoreError> {
    let path = store_path()?;
    match fs::read_to_string(&path) {
        Ok(s) if !s.trim().is_empty() => Ok(serde_json::from_str(&s)?),
        Ok(_) => Ok(HashMap::new()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
        Err(e) => Err(e.into()),
    }
}

fn write_all(map: &HashMap<String, String>) -> Result<(), StoreError> {
    let path = store_path()?;
    let data = serde_json::to_string_pretty(map)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(data.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

/// Encrypts the session with the given 32-byte key and writes it to disk.
fn store_blob(username: &str, session: &CachedSession, key: &[u8; 32]) -> Result<(), StoreError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).map_err(|_| StoreError::Decrypt)?;

    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| StoreError::BadPassword)?;
    let nonce = XNonce::try_from(&nonce_bytes[..]).map_err(|_| StoreError::Decrypt)?;

    let mut plaintext = serde_json::to_vec(session)?;
    let encrypted = cipher.encrypt(&nonce, plaintext.as_ref());
    plaintext.zeroize();
    let ciphertext = encrypted.map_err(|_| StoreError::Decrypt)?;

    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    let mut map = read_all()?;
    map.insert(username.to_string(), B64.encode(&blob));
    write_all(&map)
}

/// Encrypts the session with a new random key, saves it, and returns the base64 bridge password.
pub fn encrypt_and_save(
    username: &str,
    session: &CachedSession,
) -> Result<String, StoreError> {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|_| StoreError::Decrypt)?;
    store_blob(username, session, &key)?;
    let bridge_password = B64.encode(key);
    key.zeroize();
    Ok(bridge_password)
}

/// Re-saves with the existing bridge password (for refresh-token rotation).
#[allow(dead_code)] // used by serve
pub fn save_with_password(
    username: &str,
    session: &CachedSession,
    bridge_password: &str,
) -> Result<(), StoreError> {
    let mut kb = B64
        .decode(bridge_password.trim())
        .map_err(|_| StoreError::BadPassword)?;
    if kb.len() != 32 {
        kb.zeroize();
        return Err(StoreError::BadPassword);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&kb);
    kb.zeroize();
    let r = store_blob(username, session, &key);
    key.zeroize();
    r
}

/// Decrypts a user's session with the bridge password.
#[allow(dead_code)] // used by serve
pub fn load(username: &str, bridge_password: &str) -> Result<CachedSession, StoreError> {
    let mut key_bytes = B64
        .decode(bridge_password.trim())
        .map_err(|_| StoreError::BadPassword)?;
    if key_bytes.len() != 32 {
        key_bytes.zeroize();
        return Err(StoreError::BadPassword);
    }

    let map = read_all()?;
    let blob_b64 = map
        .get(username)
        .ok_or_else(|| StoreError::NotFound(username.to_string()))?;
    let blob = B64.decode(blob_b64).map_err(|_| StoreError::Decrypt)?;
    if blob.len() <= NONCE_LEN {
        return Err(StoreError::Decrypt);
    }

    let cipher = XChaCha20Poly1305::new_from_slice(&key_bytes).map_err(|_| StoreError::BadPassword)?;
    key_bytes.zeroize();
    let nonce = XNonce::try_from(&blob[..NONCE_LEN]).map_err(|_| StoreError::Decrypt)?;
    let mut plaintext = cipher
        .decrypt(&nonce, &blob[NONCE_LEN..])
        .map_err(|_| StoreError::Decrypt)?;
    let parsed = serde_json::from_slice(&plaintext);
    plaintext.zeroize();
    Ok(parsed?)
}

pub fn list_usernames() -> Result<Vec<String>, StoreError> {
    Ok(read_all()?.into_keys().collect())
}

pub fn remove(username: &str) -> Result<bool, StoreError> {
    let mut map = read_all()?;
    let existed = map.remove(username).is_some();
    write_all(&map)?;
    Ok(existed)
}
