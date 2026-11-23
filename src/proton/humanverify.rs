//! Human-verification (9001) resolution.
//!
//! Preferred order is email/sms (browserless, reliable); otherwise CAPTCHA. For CAPTCHA
//! the user solves the challenge in the browser on `verify.proton.me`; a userscript
//! captures the solved token and POSTs it to a nonce-protected local listener.
//! CAPTCHA authentication fails closed if the local callback is unavailable.
//! For email/sms the 6-digit code method is used.

use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroize;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use axum::extract::State;
use axum::extract::DefaultBodyLimit;
use axum::routing::post;
use axum::Router;
use tokio::sync::{oneshot, Mutex};

use super::client::{ApiError, Client, HumanVerification, HvHeaders};

/// Local port where the userscript POSTs the solved captcha token.
pub const CAPTURE_PORT: u16 = 8722;

/// Runs the appropriate HV flow for the offered methods and returns the retry headers.
pub async fn resolve(
    _client: &Client,
    hv: &HumanVerification,
) -> Result<HvHeaders, ApiError> {
    println!("\n⚠  Proton requires human verification.");
    println!("   Offered methods: {:?}", hv.methods);

    // Prefer email/sms over captcha: browserless and reliable.
    if let Some(method) = hv.methods.iter().find(|m| *m == "email" || *m == "sms") {
        return code_flow(method);
    }
    if hv.methods.iter().any(|m| m == "captcha") {
        return captcha_flow(&hv.token).await;
    }
    Err(ApiError::Other(format!(
        "no automatable HV method for this account: {:?}",
        hv.methods
    )))
}

/// email/sms: take the 6-digit code Proton sent and use it as the HV token.
fn code_flow(method: &str) -> Result<HvHeaders, ApiError> {
    println!(
        "   Proton sent a verification code to your account's {}.",
        if method == "email" { "email address" } else { "phone number" }
    );
    print!("   Enter the 6-digit code: ");
    io::stdout().flush().ok();
    let mut code = String::new();
    io::stdin()
        .read_line(&mut code)
        .map_err(|e| ApiError::Other(format!("stdin read failed: {e}")))?;
    let code = code.trim().to_string();
    if code.is_empty() {
        return Err(ApiError::Other("empty code".to_string()));
    }
    Ok(HvHeaders {
        token: code,
        token_type: method.to_string(),
    })
}

type TokenSink = Arc<Mutex<Option<oneshot::Sender<String>>>>;

/// CAPTCHA: the user solves the captcha MANUALLY in the browser. The solved token is
/// automatically POSTed to a nonce-protected 127.0.0.1:CAPTURE_PORT listener by the
/// userscript running on `verify.proton.me`. No token is displayed or pasted manually.
/// No automated solving — the proof of humanity is provided only by the user.
async fn captcha_flow(hv_token: &str) -> Result<HvHeaders, ApiError> {
    // Per-attempt random path prevents a different local web page from racing this
    // one-shot listener and injecting an arbitrary CAPTCHA token.
    let mut nonce_bytes = [0u8; 24];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|e| ApiError::Other(format!("could not create CAPTCHA callback nonce: {e}")))?;
    let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);
    let url = format!("https://verify.proton.me/?methods=captcha&embed=1&token={hv_token}&tb_nonce={nonce}");

    // Local listener the userscript will POST the token to automatically.
    let (tx, rx) = oneshot::channel::<String>();
    let sink: TokenSink = Arc::new(Mutex::new(Some(tx)));
    let app = Router::new()
        .route(&format!("/token/{nonce}"), post(recv_token))
        .layer(DefaultBodyLimit::max(4096))
        .with_state(sink);

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", CAPTURE_PORT))
        .await
        .map_err(|e| ApiError::Other(format!("could not start the protected local CAPTCHA callback: {e}")))?;
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    println!("\n   Opening Proton's CAPTCHA page. The challenge token is hidden from terminal output.");
    if let Err(e) = open::that(&url) {
        println!("   (could not open automatically: {e} — open the URL manually)");
    }
    println!();
    println!("   Solve the CAPTCHA. The reviewed userscript sends the result to the");
    println!("   one-time local callback. If it is not installed, cancel and retry after");
    println!("   installing it; this flow will not expose the token in terminal or logs.");

    let token = tokio::time::timeout(Duration::from_secs(300), rx).await;
    server.abort();

    let mut token = match token {
        Ok(Ok(value)) => value,
        _ => return Err(ApiError::Other("CAPTCHA callback timed out or was cancelled; no token was accepted".to_string())),
    };
    if token.trim().is_empty() {
        token.zeroize();
        return Err(ApiError::Other(
            "captcha cancelled (empty token)".to_string(),
        ));
    }
    println!("   ✓ captcha token received");
    let result = HvHeaders {
        token: token.trim().to_string(),
        token_type: "captcha".to_string(),
    };
    token.zeroize();
    Ok(result)
}

/// Passes the token received from the userscript to the channel.
async fn recv_token(State(sink): State<TokenSink>, mut body: String) -> &'static str {
    let mut token = body.trim().to_string();
    body.zeroize();
    if !token.is_empty() && token.len() <= 4096 {
        if let Some(tx) = sink.lock().await.take() {
            let _ = tx.send(token.clone());
        }
    }
    token.zeroize();
    "ok"
}
