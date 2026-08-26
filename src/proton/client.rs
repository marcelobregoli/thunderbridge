//! ProtonMail API HTTP transport layer.
//!
//! Every request carries the `X-Pm-Appversion` / `X-Pm-Apiversion` headers. If the
//! response body's `Code` field is not 1000/1001 an error is produced; `9001` is
//! specifically turned into a typed error that triggers the human-verification flow.
//!
//! Access tokens are short-lived. The transport refreshes them transparently: when a
//! request comes back with `Code 401` it uses the stored refresh token to obtain a new
//! access token (once, serialized across concurrent callers) and replays the request, so
//! a long-running `serve` session never goes stale. Rotated tokens are handed to the
//! `persist` callback so the on-disk session stays in sync.

use std::sync::Mutex;

use reqwest::{header, Client as HttpClient, RequestBuilder};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use super::auth::Auth;

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

/// Mutable authentication state, shared behind a lock so `&self` request methods can
/// rotate the access token on a 401 without threading `&mut` through every call site.
#[derive(Default)]
struct AuthState {
    uid: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
}

/// Callback invoked with `(uid, access_token, refresh_token)` after a token rotation, so
/// the caller can persist the rotated (single-use) refresh token to disk.
type PersistFn = dyn Fn(&str, &str, &str) + Send + Sync;

/// ProtonMail API client carrying the authentication state.
pub struct Client {
    http: HttpClient,
    base: String,
    auth: Mutex<AuthState>,
    persist: Mutex<Option<Box<PersistFn>>>,
    /// Serializes concurrent refreshes so a single-use refresh token is spent once.
    refresh_lock: tokio::sync::Mutex<()>,
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
            auth: Mutex::new(AuthState::default()),
            persist: Mutex::new(None),
            refresh_lock: tokio::sync::Mutex::new(()),
        })
    }

    pub fn set_session(&self, uid: String, access_token: String) {
        let mut a = self.auth.lock().unwrap();
        a.uid = Some(uid);
        a.access_token = Some(access_token);
    }

    pub fn set_uid(&self, uid: String) {
        self.auth.lock().unwrap().uid = Some(uid);
    }

    /// Stores the refresh token so the transport can auto-renew the access token on 401.
    pub fn set_refresh_token(&self, refresh_token: String) {
        self.auth.lock().unwrap().refresh_token = Some(refresh_token);
    }

    /// Registers a callback that persists rotated tokens (uid, access, refresh) to disk.
    pub fn set_persist<F>(&self, f: F)
    where
        F: Fn(&str, &str, &str) + Send + Sync + 'static,
    {
        *self.persist.lock().unwrap() = Some(Box::new(f));
    }

    fn has_refresh(&self) -> bool {
        self.auth
            .lock()
            .unwrap()
            .refresh_token
            .as_deref()
            .is_some_and(|r| !r.is_empty())
    }

    fn base_headers(&self, rb: RequestBuilder) -> RequestBuilder {
        rb.header("X-Pm-Appversion", APP_VERSION)
            .header("X-Pm-Apiversion", API_VERSION)
            .header(header::ACCEPT, "application/json")
    }

    fn decorate(&self, rb: RequestBuilder, hv: Option<&HvHeaders>) -> RequestBuilder {
        let mut rb = self.base_headers(rb);
        let (uid, token) = {
            let a = self.auth.lock().unwrap();
            (a.uid.clone(), a.access_token.clone())
        };
        if let Some(uid) = uid {
            rb = rb.header("X-Pm-Uid", uid);
        }
        if let Some(token) = token {
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
        self.send_auth(rb, hv).await
    }

    pub async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        let rb = self.http.get(format!("{}{}", self.base, path));
        self.send_auth(rb, None).await
    }

    pub async fn put_json<B, T>(&self, path: &str, body: &B) -> Result<T, ApiError>
    where
        B: Serialize,
        T: DeserializeOwned,
    {
        let rb = self.http.put(format!("{}{}", self.base, path)).json(body);
        self.send_auth(rb, None).await
    }

    /// Sends a request with authentication, transparently refreshing the access token and
    /// replaying once if the server reports it expired (`Code 401`).
    async fn send_auth<T: DeserializeOwned>(
        &self,
        rb: RequestBuilder,
        hv: Option<&HvHeaders>,
    ) -> Result<T, ApiError> {
        for attempt in 0..2u32 {
            let req = rb.try_clone().ok_or_else(|| {
                ApiError::Other("request body not cloneable for auth retry".to_string())
            })?;
            // Capture the token this attempt uses, so a concurrent refresh can be detected.
            let used_token = self.auth.lock().unwrap().access_token.clone();
            let value = self.send_raw(self.decorate(req, hv)).await?;

            let code = value.get("Code").and_then(Value::as_i64);
            match code {
                Some(401) if attempt == 0 && self.has_refresh() => {
                    self.refresh_access_token(used_token).await?;
                    // fall through to retry with the fresh token
                }
                Some(9001) => return Err(ApiError::HumanVerification(parse_hv(&value))),
                Some(c) if c != 1000 && c != 1001 => {
                    let message = value
                        .get("Error")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown error")
                        .to_string();
                    return Err(ApiError::Api { code: c, message });
                }
                _ => return Ok(serde_json::from_value(value)?),
            }
        }
        Err(ApiError::Other(
            "authentication retry exhausted (token still rejected after refresh)".to_string(),
        ))
    }

    /// Sends one request and parses the JSON body (no auth-retry logic).
    async fn send_raw(&self, rb: RequestBuilder) -> Result<Value, ApiError> {
        let resp = rb.send().await?;
        let text = resp.text().await?;
        serde_json::from_str(&text).map_err(|e| {
            ApiError::Other(format!("invalid JSON response: {e}; body={}", truncate(&text)))
        })
    }

    /// Renews the access token via the stored refresh token. Serialized by `refresh_lock`;
    /// if another caller already rotated the token while we waited, this is a no-op.
    async fn refresh_access_token(&self, stale: Option<String>) -> Result<(), ApiError> {
        let _guard = self.refresh_lock.lock().await;

        let (cur_token, uid, refresh) = {
            let a = self.auth.lock().unwrap();
            (a.access_token.clone(), a.uid.clone(), a.refresh_token.clone())
        };
        // Someone else refreshed between our 401 and acquiring the lock — just retry.
        if cur_token != stale {
            return Ok(());
        }
        let uid = uid.ok_or_else(|| ApiError::Other("no session uid for refresh".to_string()))?;
        let refresh = refresh
            .filter(|r| !r.is_empty())
            .ok_or_else(|| ApiError::Other("no refresh token available".to_string()))?;

        let auth = self.refresh_request(&uid, &refresh).await?;
        let new_refresh = if auth.refresh_token.is_empty() {
            refresh
        } else {
            auth.refresh_token.clone()
        };
        {
            let mut a = self.auth.lock().unwrap();
            a.uid = Some(auth.uid.clone());
            a.access_token = Some(auth.access_token.clone());
            a.refresh_token = Some(new_refresh.clone());
        }
        if let Some(f) = self.persist.lock().unwrap().as_ref() {
            f(&auth.uid, &auth.access_token, &new_refresh);
        }
        Ok(())
    }

    /// Performs the raw `/auth/refresh` exchange (uid header only, no bearer, no retry).
    pub(crate) async fn refresh_request(
        &self,
        uid: &str,
        refresh_token: &str,
    ) -> Result<Auth, ApiError> {
        #[derive(Serialize)]
        struct Req<'a> {
            #[serde(rename = "RefreshToken")]
            refresh_token: &'a str,
            #[serde(rename = "ResponseType")]
            response_type: &'a str,
            #[serde(rename = "GrantType")]
            grant_type: &'a str,
            #[serde(rename = "RedirectURI")]
            redirect_uri: &'a str,
        }
        let req = Req {
            refresh_token,
            response_type: "token",
            grant_type: "refresh_token",
            redirect_uri: "http://www.protonmail.ch",
        };
        let rb = self
            .http
            .post(format!("{}/auth/refresh", self.base))
            .json(&req);
        let rb = self.base_headers(rb).header("X-Pm-Uid", uid);
        let value = self.send_raw(rb).await?;
        if let Some(code) = value.get("Code").and_then(Value::as_i64)
            && code != 1000
            && code != 1001
        {
            let message = value
                .get("Error")
                .and_then(Value::as_str)
                .unwrap_or("refresh failed")
                .to_string();
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
