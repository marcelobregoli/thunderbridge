//! Human-verification (9001) resolution.
//!
//! Preferred order is email/sms (browserless, reliable); otherwise CAPTCHA. For CAPTCHA
//! the user solves the challenge in the browser on `verify.proton.me`; a userscript
//! captures the solved token and POSTs it back to a local listener (no copy-paste). If
//! the userscript is not installed, the token can be pasted manually into the terminal.
//! For email/sms the 6-digit code method is used.

use std::io::{self, Write};
use std::sync::Arc;

use axum::extract::State;
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
/// automatically POSTed to 127.0.0.1:CAPTURE_PORT by the userscript running on
/// `verify.proton.me`, so no copy-paste is needed. Without the userscript the token can
/// be pasted manually into the terminal. No automated solving — the proof of humanity
/// is provided only by the user.
async fn captcha_flow(hv_token: &str) -> Result<HvHeaders, ApiError> {
    let url = format!("https://verify.proton.me/?methods=captcha&embed=1&token={hv_token}");

    // Local listener the userscript will POST the token to automatically.
    let (tx, rx) = oneshot::channel::<String>();
    let sink: TokenSink = Arc::new(Mutex::new(Some(tx)));
    let app = Router::new()
        .route("/token", post(recv_token))
        .with_state(sink);

    let server = match tokio::net::TcpListener::bind(("127.0.0.1", CAPTURE_PORT)).await {
        Ok(listener) => Some(tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        })),
        Err(e) => {
            println!("   (could not start local listener: {e} — manual paste only)");
            None
        }
    };

    println!("\n   Proton captcha — solve it in the browser. Opening the page:");
    println!("   {url}");
    if let Err(e) = open::that(&url) {
        println!("   (could not open automatically: {e} — open the URL manually)");
    }
    println!();
    println!("   Solve the CAPTCHA. If the userscript is installed the token arrives");
    println!("   AUTOMATICALLY — just wait. (Otherwise paste the solved token here and");
    println!("   press Enter.)");
    print!("   > ");
    io::stdout().flush().ok();

    // The token arrives either from the userscript (local POST) or manually (stdin).
    let token = tokio::select! {
        auto = rx => auto.ok(),
        manual = read_line_async() => manual.ok().map(|s| s.trim().to_string()),
    };

    if let Some(s) = server {
        s.abort();
    }

    let token = token.unwrap_or_default();
    if token.trim().is_empty() {
        return Err(ApiError::Other(
            "captcha cancelled (empty token)".to_string(),
        ));
    }
    println!("   ✓ captcha token received");
    Ok(HvHeaders {
        token: token.trim().to_string(),
        token_type: "captcha".to_string(),
    })
}

/// Passes the token received from the userscript to the channel.
async fn recv_token(State(sink): State<TokenSink>, body: String) -> &'static str {
    if let Some(tx) = sink.lock().await.take() {
        let _ = tx.send(body);
    }
    "ok"
}

async fn read_line_async() -> Result<String, ApiError> {
    tokio::task::spawn_blocking(|| {
        let mut s = String::new();
        io::stdin().read_line(&mut s).map(|_| s)
    })
    .await
    .map_err(|e| ApiError::Other(format!("join error: {e}")))?
    .map_err(|e| ApiError::Other(format!("stdin read failed: {e}")))
}
