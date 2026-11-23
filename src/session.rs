//! Opens a stored session: load from store -> refresh access token -> persist
//! rotation -> fetch user/addresses/key-salts -> unlock the PGP keyring.
//! The IMAP/SMTP servers use this to obtain a ready-to-use Proton context.

use crate::proton::crypto::Keyring;
use crate::proton::mail::Address;
use crate::proton::Client;
use crate::store::{self, CachedSession};
use zeroize::{Zeroize, Zeroizing};

#[allow(dead_code)] // cached/bridge_password kept for future reuse
pub struct Session {
    pub client: Client,
    pub keyring: Keyring,
    pub addresses: Vec<Address>,
    pub cached: CachedSession,
    pub bridge_password: String,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.bridge_password.zeroize();
    }
}

impl Session {
    /// Opens the stored session with the bridge password and makes it mail-ready.
    pub async fn open(username: &str, bridge_password: &str) -> anyhow::Result<Session> {
        let mut cached = store::load(username, bridge_password)?;

        let mut client = Client::new()?;

        // Refresh for a fresh, full-scope access token (required by the sensitive
        // /keys/salts endpoint). Persist the rotated tokens.
        let auth = client
            .auth_refresh(&cached.uid, &cached.refresh_token)
            .await?;
        cached.uid = auth.uid.clone();
        cached.access_token = auth.access_token.clone();
        if !auth.refresh_token.is_empty() {
            cached.refresh_token = auth.refresh_token.clone();
        }
        store::save_with_password(username, &cached, bridge_password)?;

        // Persist rotated tokens whenever the transport auto-refreshes mid-session, so the
        // on-disk refresh token (single-use) never falls behind the in-memory one.
        let persist_user = username.to_string();
        let persist_pw = Zeroizing::new(bridge_password.to_string());
        client.set_persist(move |uid, access, refresh| {
            if let Ok(mut c) = store::load(&persist_user, &persist_pw) {
                c.uid = uid.to_string();
                c.access_token = access.to_string();
                if !refresh.is_empty() {
                    c.refresh_token = refresh.to_string();
                }
                let _ = store::save_with_password(&persist_user, &c, &persist_pw);
            }
        });

        let user = client.get_current_user().await?;
        let addresses = client.list_addresses().await?;
        // Salts were captured at login time (they can't be re-fetched after refresh
        // because that endpoint needs the short-lived post-login password scope).
        let salts = crate::proton::mail::key_salts_from_value(&cached.key_salts)?;
        if salts.is_empty() {
            anyhow::bail!("no stored key salts — run `auth` again (captcha)");
        }
        let keyring = Keyring::unlock(&user, &addresses, &salts, &cached.mailbox_password)?;

        Ok(Session {
            client,
            keyring,
            addresses,
            cached,
            bridge_password: bridge_password.to_string(),
        })
    }
}
