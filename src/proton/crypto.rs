//! PGP key unlocking and message decryption (rpgp 0.20).
//!
//! Proton's modern key model: the user key is unlocked with the bcrypt derivation of
//! the mailbox password (proton-srp `mailbox_password_hash().hashed_password()`);
//! address keys are unlocked via the `Token` field (encrypted to the user key). On
//! older accounts the address key is unlocked directly with the bcrypt-derived password.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use pgp::composed::{ArmorOptions, Deserializable, Message, MessageBuilder, SignedPublicKey, SignedSecretKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::PublicKeyEncryptedSessionKey;
use pgp::ser::Serialize as PgpSerialize;
use pgp::types::{Password, SigningKey};
use proton_srp::mailbox_password_hash;

use super::mail::{Address, KeySalt, User};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("pgp: {0}")]
    Pgp(String),
    #[error("no key salt: {0}")]
    NoSalt(String),
    #[error("no usable key")]
    NoKey,
    #[error("could not decrypt with any key")]
    DecryptFailed,
}

struct AddrKey {
    skey: SignedSecretKey,
    /// Key passphrase (Password is not Clone; built with Password::from when needed).
    pw: String,
}

/// Unlocked address keys; used to decrypt message bodies.
pub struct Keyring {
    keys: Vec<AddrKey>,
}

fn key_pw(mailbox_password: &str, salt: &[u8]) -> Result<String, CryptoError> {
    let h = mailbox_password_hash(mailbox_password, salt)
        .map_err(|e| CryptoError::Pgp(format!("bcrypt: {e:?}")))?;
    // Proton PGP passphrase = the last 31 chars of the bcrypt hash (prefix+salt dropped).
    Ok(String::from_utf8_lossy(h.hashed_password()).into_owned())
}

impl Keyring {
    pub fn unlock(
        user: &User,
        addresses: &[Address],
        salts: &[KeySalt],
        mailbox_password: &str,
    ) -> Result<Self, CryptoError> {
        let salt_for = |id: &str| salts.iter().find(|s| s.id == id).and_then(|s| s.salt.clone());

        // The user's primary key (address key tokens are encrypted to it).
        let user_key = user
            .keys
            .iter()
            .find(|k| k.primary == 1)
            .or_else(|| user.keys.first())
            .ok_or(CryptoError::NoKey)?;
        let (user_skey, _) = SignedSecretKey::from_string(&user_key.private_key)
            .map_err(|e| CryptoError::Pgp(format!("user key: {e}")))?;
        let user_salt =
            salt_for(&user_key.id).ok_or_else(|| CryptoError::NoSalt(user_key.id.clone()))?;
        let user_pw = Password::from(key_pw(mailbox_password, &user_salt)?);

        let mut keys = Vec::new();
        for addr in addresses {
            for k in &addr.keys {
                if k.active != 1 {
                    continue;
                }
                let skey = match SignedSecretKey::from_string(&k.private_key) {
                    Ok((s, _)) => s,
                    Err(_) => continue,
                };
                let pw = if !k.token.is_empty() {
                    // The token is a PGP message encrypted to the user key; decrypt → address passphrase.
                    match decrypt_to_string(&k.token, &user_pw, &user_skey) {
                        Ok(s) => s.trim().to_string(),
                        Err(_) => continue,
                    }
                } else {
                    match salt_for(&k.id) {
                        Some(s) => key_pw(mailbox_password, &s)?,
                        None => continue,
                    }
                };
                keys.push(AddrKey { skey, pw });
            }
        }
        if keys.is_empty() {
            return Err(CryptoError::NoKey);
        }
        Ok(Keyring { keys })
    }

    /// Decrypts an armored PGP message body with the matching address key.
    pub fn decrypt_body(&self, armored: &str) -> Result<String, CryptoError> {
        for k in &self.keys {
            let pw = Password::from(k.pw.clone());
            if let Ok(s) = decrypt_to_string(armored, &pw, &k.skey) {
                return Ok(s);
            }
        }
        Err(CryptoError::DecryptFailed)
    }

    /// Encrypts plaintext to the sender's (own) key as armored PGP (draft body).
    pub fn encrypt_to_self(&self, plaintext: &str) -> Result<String, CryptoError> {
        let key = self.keys.first().ok_or(CryptoError::NoKey)?;
        let pubkey = key.skey.to_public_key();
        let mut rng = rand::thread_rng();
        let mut builder =
            MessageBuilder::from_bytes("", plaintext.as_bytes().to_vec())
                .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        // Use the encryption subkey (the primary is often signing-only EdDSA).
        if let Some(sub) = pubkey.public_subkeys.first() {
            builder.encrypt_to_key(&mut rng, sub)
        } else {
            builder.encrypt_to_key(&mut rng, &pubkey)
        }
        .map_err(|e| CryptoError::Pgp(e.to_string()))?;
        builder
            .to_armored_string(&mut rng, ArmorOptions::default())
            .map_err(|e| CryptoError::Pgp(e.to_string()))
    }

    /// For sending: encrypts plaintext into a SEIPD body with a random session key.
    /// Returns (base64 SEIPD packet, session key bytes). PKESK/cleartext keys are added
    /// per-recipient on top of this.
    pub fn seal_body(&self, plaintext: &str) -> Result<(String, Vec<u8>), CryptoError> {
        let key = self.keys.first().ok_or(CryptoError::NoKey)?;
        let mut rng = rand::thread_rng();
        let sym = SymmetricKeyAlgorithm::AES256;
        let sk = sym.new_session_key(&mut rng);
        let sk_bytes = sk.as_ref().to_vec();

        let mut builder = MessageBuilder::from_bytes("", plaintext.as_bytes().to_vec())
            .seipd_v1(&mut rng, sym);
        builder
            .set_session_key(sk)
            .map_err(|e| CryptoError::Pgp(e.to_string()))?;
        // Sign with the sender's key (external cleartext recipients require a signature).
        builder.sign(
            &key.skey.primary_key as &dyn SigningKey,
            Password::from(key.pw.clone()),
            HashAlgorithm::Sha256,
        );
        // No ESK added → output is only the (signed) SEIPD packet; PKESK/cleartext key added on top.
        let bytes = builder
            .to_vec(&mut rng)
            .map_err(|e| CryptoError::Pgp(e.to_string()))?;
        Ok((B64.encode(&bytes), sk_bytes))
    }

}

/// Encrypts the session key as a PKESK for a recipient's armored public key (base64 packet).
pub fn pkesk_for_recipient(
    session_key_bytes: &[u8],
    recipient_pubkey_armored: &str,
) -> Result<String, CryptoError> {
    let (pubkey, _) = SignedPublicKey::from_string(recipient_pubkey_armored)
        .map_err(|e| CryptoError::Pgp(format!("recipient key: {e}")))?;
    let mut rng = rand::thread_rng();
    let sym = SymmetricKeyAlgorithm::AES256;
    // Rebuild the RawSessionKey from bytes.
    let sk: pgp::composed::RawSessionKey = session_key_bytes.into();
    // Prefer the encryption subkey (the primary may be signing-only).
    let pkesk = if let Some(sub) = pubkey.public_subkeys.first() {
        PublicKeyEncryptedSessionKey::from_session_key_v3(&mut rng, &sk, sym, sub)
    } else {
        PublicKeyEncryptedSessionKey::from_session_key_v3(&mut rng, &sk, sym, &pubkey)
    }
    .map_err(|e| CryptoError::Pgp(e.to_string()))?;
    let packet = frame_packet(
        1,
        &pkesk.to_bytes().map_err(|e| CryptoError::Pgp(e.to_string()))?,
    );
    Ok(B64.encode(&packet))
}

/// OpenPGP new-format packet header + body.
fn frame_packet(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 6);
    out.push(0xC0 | tag);
    let len = body.len();
    if len < 192 {
        out.push(len as u8);
    } else if len < 8384 {
        let l = len - 192;
        out.push(((l >> 8) as u8) + 192);
        out.push((l & 0xff) as u8);
    } else {
        out.push(0xff);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
    out.extend_from_slice(body);
    out
}

fn decrypt_to_string(
    armored: &str,
    pw: &Password,
    skey: &SignedSecretKey,
) -> Result<String, CryptoError> {
    let (m, _) = Message::from_armor(armored.as_bytes())
        .map_err(|e| CryptoError::Pgp(e.to_string()))?;
    let mut dec = m
        .decrypt(pw, skey)
        .map_err(|e| CryptoError::Pgp(e.to_string()))?;
    if let Ok(s) = dec.as_data_string() {
        return Ok(s);
    }
    // May be compressed: decrypt again + decompress.
    let (m2, _) = Message::from_armor(armored.as_bytes())
        .map_err(|e| CryptoError::Pgp(e.to_string()))?;
    let mut dec2 = m2
        .decrypt(pw, skey)
        .map_err(|e| CryptoError::Pgp(e.to_string()))?
        .decompress()
        .map_err(|e| CryptoError::Pgp(e.to_string()))?;
    dec2.as_data_string()
        .map_err(|e| CryptoError::Pgp(e.to_string()))
}
