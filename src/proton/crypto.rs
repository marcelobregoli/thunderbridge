//! Proton account key unlocking and message crypto using Proton's GopenPGP backend.
//!
//! SRP and PGP no longer use the older pure-Rust PGP / proton-srp 0.8
//! dependency chain. SRP 0.9 is built without its legacy internal PGP verifier;
//! the signed server modulus is verified with Proton's GopenPGP implementation.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use gopenpgp_sys::{
    DataEncoding, Decryptor, Encryptor, PrivateKey, PublicKey, SessionKey, SessionKeyAlgorithm,
    VerificationStatus, Verifier,
};
#[cfg(test)]
use gopenpgp_sys::{KeyGenerator, Signer};
use proton_srp::{ModulusSignatureVerifier, ModulusVerifyError, mailbox_password_hash};
use zeroize::Zeroizing;

use super::mail::{Address, KeySalt, User};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("OpenPGP: {0}")]
    Pgp(String),
    #[error("no key salt: {0}")]
    NoSalt(String),
    #[error("no usable key")]
    NoKey,
    #[error("could not decrypt with any key")]
    DecryptFailed,
}

struct AddrKey {
    skey: PrivateKey,
}

/// Proton SRP's modulus verifier, implemented with Proton's Go-backed OpenPGP.
/// Verification fails closed unless GopenPGP reports a valid signature.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProtonModulusVerifier;

impl ModulusSignatureVerifier for ProtonModulusVerifier {
    fn verify_and_extract_modulus(
        &self,
        modulus: &str,
        server_key: &str,
    ) -> Result<String, ModulusVerifyError> {
        let public_key = PublicKey::import(server_key.as_bytes(), DataEncoding::Armor)
            .map_err(|e| ModulusVerifyError::KeyImport(e.to_string()))?;
        let verified = Verifier::new()
            .with_verification_key(&public_key)
            .verify_cleartext(modulus.as_bytes())
            .map_err(|e| ModulusVerifyError::CleartextParse(e.to_string()))?;

        let status = verified.verification_result().map(|result| result.status());
        if !matches!(status, Some(VerificationStatus::Ok)) {
            return Err(ModulusVerifyError::SignatureVerification(
                "GopenPGP did not validate the SRP modulus signature".to_string(),
            ));
        }

        String::from_utf8(verified.into_vec())
            .map_err(|e| ModulusVerifyError::CleartextParse(e.to_string()))
    }
}

fn key_pw(mailbox_password: &str, salt: &[u8]) -> Result<String, CryptoError> {
    let hash = mailbox_password_hash(mailbox_password, salt)
        .map_err(|e| CryptoError::Pgp(format!("mailbox password hash: {e}")))?;
    String::from_utf8(hash.hashed_password().to_vec())
        .map_err(|e| CryptoError::Pgp(format!("mailbox password hash encoding: {e}")))
}

/// Unlocked Proton address keys, retained only in the local GopenPGP process.
pub struct Keyring {
    keys: Vec<AddrKey>,
}

impl Keyring {
    pub fn unlock(
        user: &User,
        addresses: &[Address],
        salts: &[KeySalt],
        mailbox_password: &str,
    ) -> Result<Self, CryptoError> {
        let salt_for = |id: &str| {
            salts
                .iter()
                .find(|s| s.id == id)
                .and_then(|s| s.salt.clone())
        };

        let user_key = user
            .keys
            .iter()
            .find(|k| k.primary == 1)
            .or_else(|| user.keys.first())
            .ok_or(CryptoError::NoKey)?;
        let user_salt =
            salt_for(&user_key.id).ok_or_else(|| CryptoError::NoSalt(user_key.id.clone()))?;
        let user_pw = Zeroizing::new(key_pw(mailbox_password, &user_salt)?);
        let user_skey = PrivateKey::import(
            user_key.private_key.as_bytes(),
            user_pw.as_bytes(),
            DataEncoding::Armor,
        )
        .map_err(|e| CryptoError::Pgp(format!("user key unlock: {e}")))?;

        let mut keys = Vec::new();
        for addr in addresses {
            for k in &addr.keys {
                if k.active != 1 {
                    continue;
                }

                // Modern Proton accounts wrap the address-key passphrase in a PGP
                // token encrypted to the primary user key. Older accounts derive it
                // directly from the address key's own salt.
                let passphrase = if !k.token.is_empty() {
                    match decrypt_to_string(&k.token, &user_skey) {
                        Ok(value) => {
                            let value = Zeroizing::new(value);
                            Zeroizing::new(value.trim().to_string())
                        }
                        Err(_) => continue,
                    }
                } else {
                    match salt_for(&k.id) {
                        Some(salt) => match key_pw(mailbox_password, &salt) {
                            Ok(value) => Zeroizing::new(value),
                            Err(_) => continue,
                        },
                        None => continue,
                    }
                };

                match PrivateKey::import(
                    k.private_key.as_bytes(),
                    passphrase.as_bytes(),
                    DataEncoding::Armor,
                ) {
                    Ok(skey) => keys.push(AddrKey { skey }),
                    Err(_) => continue,
                }
            }
        }

        if keys.is_empty() {
            return Err(CryptoError::NoKey);
        }
        Ok(Keyring { keys })
    }

    /// Decrypts an armored Proton message body with the matching address key.
    pub fn decrypt_body(&self, armored: &str) -> Result<String, CryptoError> {
        for key in &self.keys {
            if let Ok(value) = decrypt_to_string(armored, &key.skey) {
                return Ok(value);
            }
        }
        Err(CryptoError::DecryptFailed)
    }

    /// Encrypts a draft body to the sender's own public key.
    pub fn encrypt_to_self(&self, plaintext: &str) -> Result<String, CryptoError> {
        let key = self.keys.first().ok_or(CryptoError::NoKey)?;
        let public_key = key
            .skey
            .to_public_key()
            .map_err(|e| CryptoError::Pgp(e.to_string()))?;
        let message = Encryptor::new()
            .with_encryption_key(&public_key)
            .encrypt(plaintext.as_bytes())
            .map_err(|e| CryptoError::Pgp(e.to_string()))?;
        String::from_utf8(
            message
                .armored()
                .map_err(|e| CryptoError::Pgp(e.to_string()))?,
        )
        .map_err(|e| CryptoError::Pgp(e.to_string()))
    }

    /// Produces the signed SEIPD body packet and a zeroizing AES-256 session key.
    /// Recipient-specific PKESK packets are added separately by the send workflow.
    pub fn seal_body(&self, plaintext: &str) -> Result<(String, Zeroizing<Vec<u8>>), CryptoError> {
        let key = self.keys.first().ok_or(CryptoError::NoKey)?;
        let session_key = SessionKey::generate(SessionKeyAlgorithm::Aes256)
            .map_err(|e| CryptoError::Pgp(e.to_string()))?;
        let message = Encryptor::new()
            .with_signing_key(&key.skey)
            .with_session_key(&session_key)
            .encrypt(plaintext.as_bytes())
            .map_err(|e| CryptoError::Pgp(e.to_string()))?;

        let body_packet = message.data_packet();
        let session_key_bytes = Zeroizing::new(session_key.export_token().as_ref().to_vec());
        Ok((B64.encode(body_packet), session_key_bytes))
    }
}

fn decrypt_to_string(armored: &str, key: &PrivateKey) -> Result<String, CryptoError> {
    let decrypted = Decryptor::new()
        .with_decryption_key(key)
        .decrypt(armored.as_bytes(), DataEncoding::Armor)
        .map_err(|e| CryptoError::Pgp(e.to_string()))?;
    String::from_utf8(decrypted.into_vec()).map_err(|e| CryptoError::Pgp(e.to_string()))
}

/// Encrypts a session key into a complete OpenPGP PKESK packet for a recipient.
pub fn pkesk_for_recipient(
    session_key_bytes: &[u8],
    recipient_pubkey_armored: &str,
) -> Result<String, CryptoError> {
    let public_key = PublicKey::import(recipient_pubkey_armored.as_bytes(), DataEncoding::Armor)
        .map_err(|e| CryptoError::Pgp(format!("recipient public key: {e}")))?;
    let session_key = SessionKey::from_token(session_key_bytes, SessionKeyAlgorithm::Aes256);
    let packet = Encryptor::new()
        .with_encryption_key(&public_key)
        .encrypt_session_key(&session_key)
        .map_err(|e| CryptoError::Pgp(e.to_string()))?;
    Ok(B64.encode(packet))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proton_gopenpgp_round_trips_keyring_self_encryption() {
        let private = KeyGenerator::new()
            .with_user_id("Bridge Test", "bridge-test@example.invalid")
            .generate()
            .expect("generate test key");
        let keyring = Keyring {
            keys: vec![AddrKey {
                skey: private.clone(),
            }],
        };
        let armored = keyring
            .encrypt_to_self("local PGP round-trip test")
            .expect("encrypt to self");
        let decrypted = decrypt_to_string(&armored, &private).expect("decrypt self message");
        assert_eq!(decrypted, "local PGP round-trip test");
    }

    #[test]
    fn proton_gopenpgp_round_trips_real_send_body_and_pkesk_functions() {
        let private = KeyGenerator::new()
            .with_user_id("Bridge Test", "bridge-test@example.invalid")
            .generate()
            .expect("generate test key");
        let public = private.to_public_key().expect("export public key");
        let public_armored = String::from_utf8(public.export(true).expect("armor public key"))
            .expect("public key UTF-8");
        let keyring = Keyring {
            keys: vec![AddrKey {
                skey: private.clone(),
            }],
        };
        let plaintext = "split Proton body test";

        let (body_b64, session_key_bytes) = keyring.seal_body(plaintext).expect("seal signed body");
        let body_packet = B64.decode(body_b64).expect("decode body packet");
        let pkesk_b64 = pkesk_for_recipient(&session_key_bytes, &public_armored)
            .expect("create recipient PKESK");
        let key_packet = B64.decode(pkesk_b64).expect("decode PKESK");

        let recovered_key = Decryptor::new()
            .with_decryption_key(&private)
            .decrypt_session_key(&key_packet)
            .expect("recover PKESK");
        let decrypted = Decryptor::new()
            .with_decryption_key(&private)
            .with_session_key(&recovered_key)
            .with_verification_key(&public)
            .decrypt(&body_packet, DataEncoding::Bytes)
            .expect("decrypt split body");
        assert_eq!(decrypted.as_bytes(), plaintext.as_bytes());
        assert!(matches!(
            decrypted.verification_result().map(|r| r.status()),
            Some(VerificationStatus::Ok)
        ));
    }

    #[test]
    fn proton_gopenpgp_verifies_signed_srp_modulus_text() {
        let private = KeyGenerator::new()
            .with_user_id("Bridge Test", "bridge-test@example.invalid")
            .generate()
            .expect("generate test key");
        let public = private.to_public_key().expect("export public key");
        let public_armored = String::from_utf8(public.export(true).expect("armor public key"))
            .expect("public key UTF-8");
        let signed_modulus = String::from_utf8(
            Signer::new()
                .with_signing_key(&private)
                .sign_cleartext(b"test modulus")
                .expect("sign modulus"),
        )
        .expect("signed modulus UTF-8");

        let modulus = ProtonModulusVerifier
            .verify_and_extract_modulus(&signed_modulus, &public_armored)
            .expect("verify modulus");
        assert_eq!(modulus, "test modulus");

        let other_private = KeyGenerator::new()
            .with_user_id("Wrong Test Key", "wrong-key@example.invalid")
            .generate()
            .expect("generate wrong key");
        let other_public = other_private.to_public_key().expect("wrong public key");
        let other_armored = String::from_utf8(other_public.export(true).expect("armor wrong key"))
            .expect("wrong public key UTF-8");
        assert!(
            ProtonModulusVerifier
                .verify_and_extract_modulus(&signed_modulus, &other_armored)
                .is_err()
        );
    }
}
