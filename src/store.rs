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

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

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
    let dirs =
        directories::ProjectDirs::from("", "", "thunderbridge").ok_or(StoreError::NoConfigDir)?;
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

    let plaintext = Zeroizing::new(serde_json::to_vec(session)?);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_slice())
        .map_err(|_| StoreError::Decrypt)?;

    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    let mut map = read_all()?;
    map.insert(username.to_string(), B64.encode(&blob));
    write_all(&map)
}

/// Encrypts the session with a new random key, saves it, and returns the base64 bridge password.
pub fn encrypt_and_save(username: &str, session: &CachedSession) -> Result<String, StoreError> {
    let key = Zeroizing::new({
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).map_err(|_| StoreError::Decrypt)?;
        key
    });
    store_blob(username, session, &key)?;
    Ok(B64.encode(&*key))
}

/// Re-saves with the existing bridge password (for refresh-token rotation).
#[allow(dead_code)] // used by serve
pub fn save_with_password(
    username: &str,
    session: &CachedSession,
    bridge_password: &str,
) -> Result<(), StoreError> {
    let kb = Zeroizing::new(
        B64.decode(bridge_password.trim())
            .map_err(|_| StoreError::BadPassword)?,
    );
    if kb.len() != 32 {
        return Err(StoreError::BadPassword);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&kb);
    store_blob(username, session, &key)
}

/// Decrypts a user's session with the bridge password.
#[allow(dead_code)] // used by serve
pub fn load(username: &str, bridge_password: &str) -> Result<CachedSession, StoreError> {
    let key_bytes = Zeroizing::new(
        B64.decode(bridge_password.trim())
            .map_err(|_| StoreError::BadPassword)?,
    );
    if key_bytes.len() != 32 {
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

    let cipher =
        XChaCha20Poly1305::new_from_slice(&key_bytes).map_err(|_| StoreError::BadPassword)?;
    let nonce = XNonce::try_from(&blob[..NONCE_LEN]).map_err(|_| StoreError::Decrypt)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(&nonce, &blob[NONCE_LEN..])
            .map_err(|_| StoreError::Decrypt)?,
    );
    Ok(serde_json::from_slice(plaintext.as_slice())?)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct RestoreXdgConfig(Option<std::ffi::OsString>);

    impl Drop for RestoreXdgConfig {
        fn drop(&mut self) {
            // Tests run serially for this process; restore the caller's environment.
            unsafe {
                if let Some(value) = self.0.take() {
                    std::env::set_var("XDG_CONFIG_HOME", value);
                } else {
                    std::env::remove_var("XDG_CONFIG_HOME");
                }
            }
        }
    }

    #[test]
    fn session_store_encrypts_secrets_and_uses_private_file_modes() {
        let _guard = ENV_LOCK.lock().expect("lock XDG environment");
        let old_xdg = std::env::var_os("XDG_CONFIG_HOME");
        let _restore = RestoreXdgConfig(old_xdg);

        let root =
            std::env::temp_dir().join(format!("thunderbridge-store-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create temporary XDG config root");
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &root);
        }

        let session = CachedSession {
            uid: "test-uid".to_string(),
            access_token: "access-secret-should-not-appear".to_string(),
            refresh_token: "refresh-secret-should-not-appear".to_string(),
            password_mode: 1,
            login_password: "login-secret-should-not-appear".to_string(),
            mailbox_password: "mailbox-secret-should-not-appear".to_string(),
            key_salts: serde_json::json!({"key": "salt"}),
        };
        let bridge_password =
            Zeroizing::new(encrypt_and_save("test-user", &session).expect("save session"));

        let config_dir = root.join("thunderbridge");
        let session_file = config_dir.join("sessions.json");
        let disk = fs::read_to_string(&session_file).expect("read encrypted session file");
        for secret in [
            "access-secret-should-not-appear",
            "refresh-secret-should-not-appear",
            "login-secret-should-not-appear",
            "mailbox-secret-should-not-appear",
        ] {
            assert!(
                !disk.contains(secret),
                "plaintext secret leaked to disk: {secret}"
            );
        }

        assert_eq!(
            fs::metadata(&config_dir)
                .expect("config directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&session_file)
                .expect("session file metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let loaded = load("test-user", bridge_password.as_str()).expect("decrypt session");
        assert_eq!(loaded.uid, "test-uid");
        assert_eq!(loaded.login_password, "login-secret-should-not-appear");
        assert_eq!(loaded.mailbox_password, "mailbox-secret-should-not-appear");
        assert!(load("test-user", "incorrect-bridge-password").is_err());

        drop(loaded);
        drop(session);
        drop(bridge_password);
        fs::remove_dir_all(&root).expect("remove temporary session store");
    }
}
