//! ProtonMail API HTTP transport layer.
//!
//! Every request carries the `X-Pm-Appversion` / `X-Pm-Apiversion` headers. If the
//! response body's `Code` field is not 1000/1001 an error is produced; `9001` is
//! specifically turned into a typed error that triggers the human-verification flow.

use reqwest::{header, Client as HttpClient};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

pub const API_BASE: &str = "https://mail.proton.me/api";
pub const APP_VERSION: &str = "Other";
pub const API_VERSION: &str = "3";
const USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";

/// Human-verification headers to attach to a request on resubmission.
#[derive(Debug, Clone)]
pub struct HvHeaders {
    pub token: String,
    pub token_type: String,
}

/// Human-verification challenge parsed from a `9001` response.
#[derive(Debug, Clone)]
pub struct HumanVerification {
    pub methods: Vec<String>,
    pub token: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("[{code}] {message}")]
    Api { code: i64, message: String },
    #[error("human verification required (methods: {:?})", .0.methods)]
    HumanVerification(HumanVerification),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}

/// ProtonMail API client carrying the authentication state.
pub struct Client {
    http: HttpClient,
    base: String,
    pub uid: Option<String>,
    pub access_token: Option<String>,
}

impl Client {
    pub fn new() -> Result<Self, ApiError> {
        let http = HttpClient::builder()
            .cookie_store(true)
            .user_agent(USER_AGENT)
            .build()?;
        Ok(Self {
            http,
            base: API_BASE.to_string(),
            uid: None,
            access_token: None,
        })
    }

    pub fn set_session(&mut self, uid: String, access_token: String) {
        self.uid = Some(uid);
        self.access_token = Some(access_token);
    }

    pub fn set_uid(&mut self, uid: String) {
        self.uid = Some(uid);
    }

    fn decorate(
        &self,
        rb: reqwest::RequestBuilder,
        hv: Option<&HvHeaders>,
    ) -> reqwest::RequestBuilder {
        let mut rb = rb
            .header("X-Pm-Appversion", APP_VERSION)
            .header("X-Pm-Apiversion", API_VERSION)
            .header(header::ACCEPT, "application/json");
        if let Some(uid) = &self.uid {
            rb = rb.header("X-Pm-Uid", uid);
        }
        if let Some(token) = &self.access_token {
            rb = rb.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(hv) = hv {
            rb = rb
                .header("x-pm-human-verification-token", &hv.token)
                .header("x-pm-human-verification-token-type", &hv.token_type);
        }
        rb
    }

    pub async fn post_json<B, T>(
        &self,
        path: &str,
        body: &B,
        hv: Option<&HvHeaders>,
    ) -> Result<T, ApiError>
    where
        B: Serialize,
        T: DeserializeOwned,
    {
        let rb = self.http.post(format!("{}{}", self.base, path)).json(body);
        self.send(self.decorate(rb, hv)).await
    }

    pub async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        let rb = self.http.get(format!("{}{}", self.base, path));
        self.send(self.decorate(rb, None)).await
    }

    pub async fn put_json<B, T>(&self, path: &str, body: &B) -> Result<T, ApiError>
    where
        B: Serialize,
        T: DeserializeOwned,
    {
        let rb = self.http.put(format!("{}{}", self.base, path)).json(body);
        self.send(self.decorate(rb, None)).await
    }

    async fn send<T: DeserializeOwned>(
        &self,
        rb: reqwest::RequestBuilder,
    ) -> Result<T, ApiError> {
        let resp = rb.send().await?;
        let text = resp.text().await?;
        let value: Value = serde_json::from_str(&text).map_err(|e| {
            ApiError::Other(format!("invalid JSON response: {e}; body={}", truncate(&text)))
        })?;

        if let Some(code) = value.get("Code").and_then(Value::as_i64)
            && code != 1000 && code != 1001 {
                let message = value
                    .get("Error")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error")
                    .to_string();
                if code == 9001 {
                    return Err(ApiError::HumanVerification(parse_hv(&value)));
                }
                return Err(ApiError::Api { code, message });
            }
        Ok(serde_json::from_value(value)?)
    }
}

fn parse_hv(value: &Value) -> HumanVerification {
    let details = value.get("Details");
    let methods = details
        .and_then(|d| d.get("HumanVerificationMethods"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let token = details
        .and_then(|d| d.get("HumanVerificationToken"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    HumanVerification { methods, token }
}

fn truncate(s: &str) -> String {
    let t: String = s.chars().take(300).collect();
    if t.len() < s.len() {
        format!("{t}…")
    } else {
        t
    }
}
