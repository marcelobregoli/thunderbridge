//! Persistent IMAP UID mapping. Proton message IDs (strings) are mapped to the
//! increasing integer UIDs IMAP expects, per folder and STABLE across reconnects, so
//! Thunderbird doesn't re-download messages over and over.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FolderUids {
    /// Highest UID assigned in this folder.
    pub next: u32,
    /// ProtonMsgID → UID.
    pub map: HashMap<String, u32>,
    /// Stable UIDVALIDITY for the folder (assigned when first seen).
    pub uidvalidity: u32,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct UidStore {
    /// labelID → folder UID state.
    pub folders: HashMap<String, FolderUids>,
}

fn path() -> Option<std::path::PathBuf> {
    let dirs = directories::ProjectDirs::from("", "", "thunderbridge")?;
    let dir = dirs.config_dir().to_path_buf();
    std::fs::create_dir_all(&dir).ok()?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok()?;
    Some(dir.join("uidmap.json"))
}

impl UidStore {
    pub fn load() -> Self {
        let Some(p) = path() else {
            return Self::default();
        };
        match std::fs::read_to_string(&p) {
            Ok(s) if !s.trim().is_empty() => serde_json::from_str(&s).unwrap_or_default(),
            _ => Self::default(),
        }
    }

    pub fn save(&self) {
        if let Some(p) = path()
            && let Ok(s) = serde_json::to_string(self) {
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .write(true).create(true).truncate(true).mode(0o600).open(&p) {
                    let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
                    let _ = file.write_all(s.as_bytes());
                    let _ = file.sync_all();
                }
            }
    }

    /// Returns a folder's UIDVALIDITY (deterministically assigned on first call).
    pub fn uidvalidity(&mut self, label: &str) -> u32 {
        let f = self.folders.entry(label.to_string()).or_default();
        if f.uidvalidity == 0 {
            f.uidvalidity = fnv1a(label).max(1);
        }
        f.uidvalidity
    }

    /// Persistent UID for a ProtonMsgID; assigns a new (increasing) one if absent.
    pub fn uid_for(&mut self, label: &str, msg_id: &str) -> u32 {
        let f = self.folders.entry(label.to_string()).or_default();
        if f.uidvalidity == 0 {
            f.uidvalidity = fnv1a(label).max(1);
        }
        if let Some(u) = f.map.get(msg_id) {
            return *u;
        }
        f.next += 1;
        let u = f.next;
        f.map.insert(msg_id.to_string(), u);
        u
    }

    pub fn uidnext(&self, label: &str) -> u32 {
        self.folders.get(label).map(|f| f.next + 1).unwrap_or(1)
    }
}

fn fnv1a(s: &str) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for b in s.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}
