//! ProtonMail SRP login flow.
//!
//! `/auth/info` provides the SRP parameters, `proton-srp` produces the client proof,
//! `/auth` submits it, and the server proof is verified. Preparation (`PreparedAuth`)
//! is separated from submission (`submit_auth`) so that the same SRP session and proof
//! can be reused across a human-verification retry.

use proton_srp::{SRPAuth, SRPProofB64, SrpHashVersion};
use serde::{Deserialize, Serialize};

use super::client::{ApiError, Client, HvHeaders};

#[derive(Serialize)]
struct AuthInfoReq<'a> {
    #[serde(rename = "Username")]
    username: &'a str,
}

#[derive(Deserialize)]
pub struct AuthInfo {
    #[serde(rename = "Version")]
    pub version: u8,
    #[serde(rename = "Modulus")]
    pub modulus: String,
    #[serde(rename = "ServerEphemeral")]
    pub server_ephemeral: String,
    #[serde(rename = "Salt")]
    pub salt: String,
    #[serde(rename = "SRPSession")]
    pub srp_session: String,
}

#[derive(Deserialize, Default)]
pub struct TwoFactor {
    #[serde(rename = "Enabled")]
    pub enabled: i32,
    #[serde(rename = "TOTP")]
    pub totp: i32,
}

#[derive(Deserialize)]
pub struct Auth {
    #[serde(rename = "UID")]
    pub uid: String,
    #[serde(rename = "AccessToken")]
    pub access_token: String,
    #[serde(rename = "RefreshToken")]
    pub refresh_token: String,
    #[serde(rename = "Scope", default)]
    #[allow(dead_code)] // kept for future scope checks
    pub scope: String,
    #[serde(rename = "PasswordMode", default)]
    pub password_mode: i32,
    #[serde(rename = "ServerProof", default)]
    pub server_proof: String,
    #[serde(rename = "2FA", default)]
    pub two_factor: TwoFactor,
}

#[derive(Serialize)]
struct AuthReq<'a> {
    #[serde(rename = "Username")]
    username: &'a str,
    #[serde(rename = "SRPSession")]
    srp_session: &'a str,
    #[serde(rename = "ClientEphemeral")]
    client_ephemeral: &'a str,
    #[serde(rename = "ClientProof")]
    client_proof: &'a str,
}

/// State with a generated SRP proof, ready to submit to `/auth`. On an HV retry the
/// same `srp_session` + proof are reused (no new `/auth/info` call).
pub struct PreparedAuth {
    username: String,
    srp_session: String,
    client_ephemeral: String,
    client_proof: String,
    expected_server_proof: String,
}

impl Client {
    pub async fn auth_info(
        &self,
        username: &str,
        hv: Option<&HvHeaders>,
    ) -> Result<AuthInfo, ApiError> {
        self.post_json("/auth/info", &AuthInfoReq { username }, hv).await
    }

    /// Fetches `/auth/info` and produces the SRP client proof.
    pub async fn prepare_auth(
        &self,
        username: &str,
        password: &str,
    ) -> Result<PreparedAuth, ApiError> {
        let info = self.auth_info(username, None).await?;
        let version = SrpHashVersion::try_from(info.version)
            .map_err(|e| ApiError::Other(format!("unsupported SRP version: {e}")))?;

        let client = SRPAuth::with_pgp(
            None,
            password,
            version,
            &info.salt,
            &info.modulus,
            &info.server_ephemeral,
        )
        .map_err(|e| ApiError::Other(format!("SRP init failed: {e}")))?;

        let proof: SRPProofB64 = client
            .generate_proofs()
            .map_err(|e| ApiError::Other(format!("SRP proof generation failed: {e}")))?
            .into();

        Ok(PreparedAuth {
            username: username.to_string(),
            srp_session: info.srp_session,
            client_ephemeral: proof.client_ephemeral,
            client_proof: proof.client_proof,
            expected_server_proof: proof.expected_server_proof,
        })
    }

    /// Submits the prepared proof to `/auth`. On `9001` it returns
    /// `ApiError::HumanVerification`; the caller solves HV and calls again with the
    /// `hv` headers.
    pub async fn submit_auth(
        &mut self,
        prepared: &PreparedAuth,
        hv: Option<&HvHeaders>,
    ) -> Result<Auth, ApiError> {
        let req = AuthReq {
            username: &prepared.username,
            srp_session: &prepared.srp_session,
            client_ephemeral: &prepared.client_ephemeral,
            client_proof: &prepared.client_proof,
        };
        let auth: Auth = self.post_json("/auth", &req, hv).await?;

        if auth.server_proof != prepared.expected_server_proof {
            return Err(ApiError::Other(
                "server proof mismatch — aborting (possible MITM)".to_string(),
            ));
        }

        self.set_session(auth.uid.clone(), auth.access_token.clone());
        Ok(auth)
    }

    /// Obtains a new access token via the refresh token (captcha-free session renewal).
    /// Also seeds the transport's refresh token so later access-token expiries are
    /// renewed transparently on a 401.
    pub async fn auth_refresh(
        &mut self,
        uid: &str,
        refresh_token: &str,
    ) -> Result<Auth, ApiError> {
        self.set_uid(uid.to_string());
        let auth = self.refresh_request(uid, refresh_token).await?;
        self.set_session(auth.uid.clone(), auth.access_token.clone());
        let stored_refresh = if auth.refresh_token.is_empty() {
            refresh_token.to_string()
        } else {
            auth.refresh_token.clone()
        };
        self.set_refresh_token(stored_refresh);
        Ok(auth)
    }

    /// Submits the TOTP second factor.
    pub async fn auth_totp(&self, code: &str) -> Result<(), ApiError> {
        #[derive(Serialize)]
        struct Req<'a> {
            #[serde(rename = "TwoFactorCode")]
            code: &'a str,
        }
        let _: serde_json::Value = self.post_json("/auth/2fa", &Req { code }, None).await?;
        Ok(())
    }
}
