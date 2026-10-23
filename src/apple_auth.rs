//! Apple Account SRP-6a primitives used by iCloud's private web-service login.
//!
//! This module deliberately does not change the existing app-specific-password
//! flow used by CalDAV, CardDAV, and IMAP. Apple private services use a separate
//! Apple Account password exchange and a follow-up trusted-device challenge.

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use pbkdf2::pbkdf2_hmac;
use reqwest::{Url, blocking::Client as HttpClient};
use reqwest_cookie_store::{CookieStore, CookieStoreMutex};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use srp::{Client, ClientVerifier, EphemeralSecret, Generate, groups::G2048, utils::compute_m2};
use srp_sha2::{Digest as SrpDigest, Sha256 as SrpSha256};
use std::{
    io::{Cursor, Read, Write},
    sync::Arc,
    thread,
    time::Duration,
};
use uuid::Uuid;

const SUPPORTED_PROTOCOLS: [&str; 2] = ["s2k", "s2k_fo"];
const AUTH_ROOT: &str = "https://idmsa.apple.com/appleauth/auth";
const SETUP_ROOT: &str = "https://setup.icloud.com/setup/ws/1";
const APPLE_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Safari/605.1.15";
const OAUTH_CLIENT_ID: &str = "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d";

/// Apple private-service auth state. Store its serialized form only in the OS
/// credential store because it contains trusted cookies and session tokens.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SavedAppleSession {
    pub account: String,
    pub client_id: String,
    pub account_data: Value,
    pub session_headers: std::collections::BTreeMap<String, String>,
    pub cookies_json: String,
    #[serde(default)]
    pub reminders_pcs_ready: bool,
    #[serde(default)]
    pub pending: Option<PendingChallenge>,
}

/// Pending challenge metadata, saved with session secrets in the OS store.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PendingChallenge {
    pub method: VerificationMethod,
    phone: Option<Value>,
    #[serde(default)]
    pub code_accepted: bool,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum VerificationMethod {
    Device,
    Sms,
}

/// A recoverable authentication state with a command an agent can execute.
#[derive(Debug)]
pub struct AuthRecovery {
    pub code: &'static str,
    pub message: String,
    pub next_command: String,
}
impl std::fmt::Display for AuthRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for AuthRecovery {}

#[derive(Debug)]
pub struct RemindersAccessRecovery {
    pub code: &'static str,
    pub message: String,
    pub next_command: String,
}
impl std::fmt::Display for RemindersAccessRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for RemindersAccessRecovery {}

pub fn recovery(
    account: &str,
    code: &'static str,
    message: impl Into<String>,
    operation: &str,
) -> anyhow::Error {
    AuthRecovery {
        code,
        message: message.into(),
        next_command: format!(
            "icli auth {operation} {}{}",
            crate::cli_quote(account),
            match operation {
                "verify" => " --code-stdin",
                "add" | "app-password" => " --password-stdin",
                _ => "",
            }
        ),
    }
    .into()
}

pub fn sign_in_required(account: &str, message: impl Into<String>) -> anyhow::Error {
    recovery(account, "auth_sign_in_required", message, "add")
}

/// One authenticated request context for Apple private web services.
pub struct AppleConnection {
    pub session: SavedAppleSession,
    client: HttpClient,
    cookies: Arc<CookieStoreMutex>,
    endpoints: AuthEndpoints,
}

struct AuthEndpoints {
    auth: String,
    setup_override: Option<String>,
}
impl Default for AuthEndpoints {
    fn default() -> Self {
        Self {
            auth: AUTH_ROOT.into(),
            setup_override: None,
        }
    }
}

impl AppleConnection {
    /// Start SRP sign-in. Return after requesting a code, without waiting for input.
    pub fn begin_login(account: &str, password: &str) -> Result<Self> {
        Self::begin_login_with_endpoints(account, password, AuthEndpoints::default())
    }

    fn begin_login_with_endpoints(
        account: &str,
        password: &str,
        endpoints: AuthEndpoints,
    ) -> Result<Self> {
        let auth_root = &endpoints.auth;
        if account.trim().is_empty() || password.is_empty() {
            bail!("Apple Account email and password are required");
        }
        let client_id = Uuid::new_v4().to_string();
        let (client, cookies) = make_client(None)?;
        let mut headers = auth_headers(&client_id, &std::collections::BTreeMap::new());
        let mut authorize = Url::parse(&format!("{auth_root}/authorize/signin"))?;
        authorize.query_pairs_mut().extend_pairs([
            ("frame_id", client_id.as_str()),
            ("skVersion", "7"),
            ("iframeid", client_id.as_str()),
            ("client_id", OAUTH_CLIENT_ID),
            ("response_type", "code"),
            ("redirect_uri", "https://www.icloud.com"),
            ("response_mode", "web_message"),
            ("state", client_id.as_str()),
            ("authVersion", "latest"),
        ]);
        let response = client
            .get(authorize)
            .headers(headers.clone())
            .send()
            .context("Could not reach Apple Account sign-in")?;
        headers = update_headers(headers, &response);
        response
            .error_for_status()
            .context("Apple Account sign-in could not be initialized")?;
        let (mut srp, init) = AppleSrpHandshake::start(&account.to_lowercase())?;
        let response = client
            .post(format!("{auth_root}/signin/init"))
            .headers(headers.clone())
            .json(&init)
            .send()
            .context("Could not start Apple Account password verification")?;
        headers = update_headers(headers, &response);
        let challenge: Value = response
            .error_for_status()
            .context("Apple rejected the sign-in initialization")?
            .json()
            .context("Apple returned an invalid sign-in challenge")?;
        let complete = srp.complete(password, &challenge)?;
        let response = client
            .post(format!("{auth_root}/signin/complete"))
            .query(&[("isRememberMeEnabled", "true")])
            .headers(headers.clone())
            .json(&complete)
            .send()
            .context("Could not complete Apple Account sign-in")?;
        headers = update_headers(headers, &response);
        let status = response.status();
        let body = response.json::<Value>().unwrap_or(Value::Null);
        if !status.is_success() && status.as_u16() != 409 {
            bail!(
                "Apple Account sign-in failed (HTTP {status}){}",
                error_hint(&body)
            );
        }
        let mut connection = Self {
            session: SavedAppleSession {
                account: account.to_string(),
                client_id,
                account_data: Value::Null,
                session_headers: header_subset(headers),
                cookies_json: String::new(),
                reminders_pcs_ready: false,
                pending: None,
            },
            client,
            cookies,
            endpoints,
        };
        if status.as_u16() == 409
            || body.get("hsaChallengeRequired").and_then(Value::as_bool) == Some(true)
        {
            let (status, challenge, _) = connection.auth_request(reqwest::Method::GET, "", None)?;
            if !status.is_success() {
                bail!("Apple verification challenge request failed (HTTP {status})");
            }
            if challenge
                .get("hsaChallengeRequired")
                .and_then(Value::as_bool)
                != Some(false)
            {
                let phone = trusted_phone_number(&challenge).map(phone_number_payload);
                let bridge_route = challenge
                    .pointer("/direct/authInitialRoute")
                    .or_else(|| challenge.get("authInitialRoute"))
                    .and_then(Value::as_str)
                    == Some("auth/bridge/step");
                if bridge_route && phone.is_none() {
                    bail!(
                        "Apple requires a trusted-device bridge or hardware security key unsupported by this CLI, with no SMS fallback available"
                    );
                }
                let method = if bridge_route {
                    VerificationMethod::Sms
                } else {
                    VerificationMethod::Device
                };
                connection.session.pending = Some(PendingChallenge {
                    method,
                    phone,
                    code_accepted: false,
                });
                connection.resend_code(method)?;
                return Ok(connection);
            }
        }
        connection.establish_session()?;
        Ok(connection)
    }

    pub fn auth_state(&self) -> &'static str {
        match self.session.pending.as_ref() {
            Some(challenge) if challenge.code_accepted => "refresh_required",
            Some(_) => "verification_required",
            None => "authenticated",
        }
    }

    pub fn require_authenticated(&self) -> Result<()> {
        if let Some(challenge) = &self.session.pending {
            let (code, message, operation) = if challenge.code_accepted {
                (
                    "auth_refresh_required",
                    "Apple accepted the code; finish establishing the session with auth refresh",
                    "refresh",
                )
            } else {
                (
                    "auth_verification_required",
                    "Apple sign-in requires a verification code; submit it with auth verify",
                    "verify",
                )
            };
            return Err(recovery(&self.session.account, code, message, operation));
        }
        Ok(())
    }

    fn auth_request(
        &mut self,
        method: reqwest::Method,
        path: &str,
        payload: Option<&Value>,
    ) -> Result<(reqwest::StatusCode, Value, bool)> {
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.endpoints.auth))
            .headers(auth_headers(
                &self.session.client_id,
                &self.session.session_headers,
            ));
        if let Some(payload) = payload {
            request = request.json(payload);
        }
        let response = request
            .send()
            .context("Could not reach Apple authentication service")?;
        for (name, value) in
            header_subset(update_headers(reqwest::header::HeaderMap::new(), &response))
        {
            self.session.session_headers.insert(name, value);
        }
        let status = response.status();
        let issued_token = response
            .headers()
            .get("x-apple-session-token")
            .is_some_and(|v| !v.as_bytes().is_empty());
        let body = response.json::<Value>().unwrap_or(Value::Null);
        self.save_cookies()?;
        Ok((status, body, issued_token))
    }

    /// Request a fresh code for the persisted challenge; never prompt or verify.
    pub fn resend_code(&mut self, method: VerificationMethod) -> Result<()> {
        let pending = self.session.pending.as_ref().ok_or_else(|| {
            recovery(
                &self.session.account,
                "auth_verification_not_pending",
                "No pending verification challenge; check the saved session",
                "check",
            )
        })?;
        if pending.code_accepted {
            return self.require_authenticated();
        }
        let (path, payload) = match method {
            VerificationMethod::Device => ("/verify/trusteddevice/securitycode", None),
            VerificationMethod::Sms => {
                let phone = pending
                    .phone
                    .as_ref()
                    .context("Apple did not offer SMS verification for this sign-in")?;
                (
                    "/verify/phone",
                    Some(json!({"phoneNumber":{"id":phone.get("id")},"mode":"sms"})),
                )
            }
        };
        let (status, _, _) = self.auth_request(reqwest::Method::PUT, path, payload.as_ref())?;
        if matches!(status.as_u16(), 401 | 421 | 410) {
            return Err(sign_in_required(
                &self.session.account,
                format!("Apple verification challenge expired (HTTP {status})"),
            ));
        }
        if !status.is_success() {
            bail!("Apple could not request a verification code (HTTP {status})");
        }
        self.session.pending.as_mut().unwrap().method = method;
        Ok(())
    }

    /// Verify a code against the saved challenge and establish a trusted session.
    pub fn verify_code(&mut self, code: &str) -> Result<()> {
        if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
            bail!("Verification code must contain exactly six digits");
        }
        let pending = self.session.pending.as_ref().ok_or_else(|| {
            recovery(
                &self.session.account,
                "auth_verification_not_pending",
                "No pending verification challenge; check the saved session",
                "check",
            )
        })?;
        if pending.code_accepted {
            return self.require_authenticated();
        }
        let (path, payload) = match pending.method {
            VerificationMethod::Device => (
                "/verify/trusteddevice/securitycode",
                json!({"securityCode":{"code":code}}),
            ),
            VerificationMethod::Sms => (
                "/verify/phone/securitycode",
                json!({"phoneNumber":pending.phone,"securityCode":{"code":code},"mode":"sms"}),
            ),
        };
        let (status, _, issued_token) =
            self.auth_request(reqwest::Method::POST, path, Some(&payload))?;
        // Apple can signal accepted verification with 409. A token issued by
        // this response, rather than a stale token from SRP, confirms acceptance.
        let accepted_conflict = status.as_u16() == 409 && issued_token;
        if !status.is_success() && !accepted_conflict {
            if matches!(status.as_u16(), 401 | 410 | 421) {
                return Err(sign_in_required(
                    &self.session.account,
                    format!("Apple verification challenge expired (HTTP {status})"),
                ));
            }
            return Err(recovery(
                &self.session.account,
                "auth_verification_failed",
                format!(
                    "Apple did not accept the verification code (HTTP {status}); retry with a current code or use auth resend"
                ),
                "verify",
            ));
        }
        self.session.pending.as_mut().unwrap().code_accepted = true;
        self.finish_verification().map_err(|error| {
            if error.downcast_ref::<AuthRecovery>().is_some() { error }
            else { recovery(&self.session.account, "auth_refresh_required", format!("Apple accepted the verification code, but the session exchange failed: {error}"), "refresh") }
        })
    }

    fn finish_verification(&mut self) -> Result<()> {
        let (status, _, _) = self.auth_request(reqwest::Method::GET, "/2sv/trust", None)?;
        if !status.is_success() {
            bail!("Apple could not trust this sign-in (HTTP {status}); use auth refresh to retry");
        }
        self.establish_session()
    }

    fn establish_session(&mut self) -> Result<()> {
        let setup = self.setup_root();
        let response = account_login(
            &self.client,
            &stored_headers(&self.session.session_headers),
            &setup,
        )?;
        for (name, value) in
            header_subset(update_headers(reqwest::header::HeaderMap::new(), &response))
        {
            self.session.session_headers.insert(name, value);
        }
        let status = response.status();
        let data = response.json::<Value>().unwrap_or(Value::Null);
        self.save_cookies()?;
        if matches!(status.as_u16(), 401 | 421) {
            return Err(sign_in_required(
                &self.session.account,
                format!("Apple rejected the account session exchange (HTTP {status})"),
            ));
        }
        if !status.is_success() {
            bail!(
                "Apple account session exchange failed (HTTP {status}){}",
                error_hint(&data)
            );
        }
        if data.get("hsaChallengeRequired").and_then(Value::as_bool) == Some(true)
            || data.get("hsaTrustedBrowser").and_then(Value::as_bool) == Some(false)
        {
            return Err(sign_in_required(
                &self.session.account,
                "Apple requires a new sign-in challenge",
            ));
        }
        if !data.get("webservices").is_some_and(Value::is_object) {
            bail!("Apple returned an invalid account session without service endpoints");
        }
        self.session.account_data = data;
        self.session.pending = None;
        Ok(())
    }

    /// Restore cookies from a keyring-backed session record.
    pub fn restore(session: SavedAppleSession) -> Result<Self> {
        let (client, cookies) = make_client(Some(&session.cookies_json))?;
        Ok(Self {
            session,
            client,
            cookies,
            endpoints: AuthEndpoints::default(),
        })
    }

    fn setup_root(&self) -> String {
        if let Some(setup) = &self.endpoints.setup_override {
            return setup.clone();
        }
        if self
            .session
            .session_headers
            .get("x-apple-id-account-country")
            .is_some_and(|v| v.eq_ignore_ascii_case("CHN"))
        {
            "https://setup.icloud.com.cn/setup/ws/1".into()
        } else {
            setup_endpoint(&self.session.account_data)
        }
    }

    pub fn client(&self) -> &HttpClient {
        &self.client
    }

    /// Check the cached session without replacing its tokens or persisted cookies.
    pub fn check_session(&self) -> Result<()> {
        self.require_authenticated()?;
        let setup = self.setup_root();
        let response = self
            .client
            .post(format!("{setup}/validate"))
            .header("origin", "https://www.icloud.com")
            .header("referer", "https://www.icloud.com/")
            .header("content-type", "application/json")
            .body("null")
            .send()
            .context("Could not validate the saved Apple session")?;
        let status = response.status();
        let data = response.json::<Value>().unwrap_or(Value::Null);
        if matches!(status.as_u16(), 401 | 421)
            || data.get("hsaChallengeRequired").and_then(Value::as_bool) == Some(true)
        {
            return Err(sign_in_required(
                &self.session.account,
                format!("Apple no longer accepts the saved session (HTTP {status})"),
            ));
        }
        if !status.is_success() {
            bail!("Apple session validation failed (HTTP {status})");
        }
        if !data.get("dsInfo").is_some_and(Value::is_object) {
            bail!("Apple returned invalid session validation data");
        }
        Ok(())
    }

    /// Renew tokens explicitly. A code already accepted can finish its trust exchange.
    pub fn refresh_session(&mut self) -> Result<()> {
        if self
            .session
            .pending
            .as_ref()
            .is_some_and(|p| p.code_accepted)
        {
            return self.finish_verification();
        }
        self.require_authenticated()?;
        self.establish_session()
    }

    /// Refresh the serialized cookie jar after a service request.
    pub fn save_cookies(&mut self) -> Result<()> {
        let store = self
            .cookies
            .lock()
            .map_err(|_| anyhow::anyhow!("Apple cookie store was poisoned"))?;
        // The library's default serializer drops session-only cookies. They
        // must survive the process boundary between auth add and auth verify.
        self.session.cookies_json =
            serde_json::to_string(&store.iter_unexpired().collect::<Vec<_>>())
                .context("Could not serialize Apple session cookies")?;
        Ok(())
    }

    /// Fetch Apple Reminders' startup snapshot using the private service API
    /// used by pyicloud (`/rd/startup`).
    fn reminders_startup(&self) -> Result<Value> {
        self.require_authenticated()?;
        let service = self
            .session
            .account_data
            .pointer("/webservices/reminders/url")
            .and_then(Value::as_str)
            .context("Apple did not advertise its Reminders service")?;
        let service =
            Url::parse(service).context("Apple advertised an invalid Reminders service URL")?;
        if service.scheme() != "https" {
            bail!("Apple advertised a non-HTTPS Reminders service URL");
        }
        self.request_reminders_startup(service)
    }

    fn request_reminders_startup(&self, service: Url) -> Result<Value> {
        let mut url = service.join("rd/startup")?;
        url.query_pairs_mut()
            .append_pair("clientVersion", "4.0")
            .append_pair("lang", "en-us")
            .append_pair("usertz", "Etc/UTC");
        for (name, value) in service_params(&self.session) {
            url.query_pairs_mut().append_pair(&name, &value);
        }
        let response = self
            .client
            .get(url)
            .headers(icloud_headers())
            .send()
            .context("Could not contact Apple's Reminders service")?;
        let status = response.status();
        if matches!(status.as_u16(), 401 | 421) {
            return Err(recovery(
                &self.session.account,
                "auth_refresh_required",
                format!("Apple Reminders rejected the saved session (HTTP {status})"),
                "refresh",
            ));
        }
        let body = response
            .json::<Value>()
            .context("Apple Reminders service returned invalid JSON")?;
        if !status.is_success() {
            bail!(
                "Apple Reminders startup request failed (HTTP {status}){}",
                error_hint(&body)
            );
        }
        Ok(body)
    }

    fn has_cloudkit_reminders(&self) -> bool {
        self.session
            .account_data
            .pointer("/webservices/ckdatabasews/url")
            .and_then(Value::as_str)
            .is_some()
    }

    fn reminders_cloudkit_root(&self) -> Result<Url> {
        let service = self
            .session
            .account_data
            .pointer("/webservices/ckdatabasews/url")
            .and_then(Value::as_str)
            .context("Apple did not advertise its CloudKit service")?;
        let service = Url::parse(&format!("{}/", service.trim_end_matches('/')))
            .context("Apple advertised an invalid CloudKit service URL")?;
        if service.scheme() != "https"
            && !(self.endpoints.setup_override.is_some() && service.host_str() == Some("127.0.0.1"))
        {
            bail!("Apple advertised a non-HTTPS CloudKit service URL");
        }
        let mut url = service.join("database/1/com.apple.reminders/production/private")?;
        url.query_pairs_mut()
            .append_pair("remapEnums", "true")
            .append_pair("getCurrentSyncToken", "true");
        for (name, value) in service_params(&self.session) {
            url.query_pairs_mut().append_pair(&name, &value);
        }
        Ok(url)
    }

    fn reminders_cloudkit_request(&self, path: &str, payload: &Value) -> Result<Value> {
        let mut url = self.reminders_cloudkit_root()?;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow::anyhow!("Apple advertised an invalid CloudKit URL"))?;
            segments.pop_if_empty();
            for segment in path.split('/') {
                segments.push(segment);
            }
        }
        let response = self
            .client
            .post(url)
            .headers(icloud_headers())
            .json(payload)
            .send()
            .map_err(|_| anyhow::anyhow!("Could not contact Apple's Reminders CloudKit service"))?;
        let status = response.status();
        let body = response.json::<Value>().unwrap_or(Value::Null);
        if matches!(status.as_u16(), 401 | 403 | 421)
            || body.get("hsaChallengeRequired").and_then(Value::as_bool) == Some(true)
        {
            return Err(recovery(
                &self.session.account,
                "auth_refresh_required",
                format!("Apple Reminders CloudKit rejected the saved session (HTTP {status})"),
                "refresh",
            ));
        }
        if !status.is_success() {
            bail!("Apple Reminders CloudKit request failed (HTTP {status})");
        }
        Ok(body)
    }

    fn reminders_pcs_post(&self, endpoint: &str, payload: Option<&Value>) -> Result<Value> {
        let setup = if let Some(setup) = &self.endpoints.setup_override {
            setup.clone()
        } else {
            setup_endpoint(&self.session.account_data)
        };
        let mut url = Url::parse(&format!("{}/", setup.trim_end_matches('/')))?;
        url = url.join(endpoint)?;
        url.query_pairs_mut()
            .extend_pairs(service_params(&self.session));
        let mut request = self.client.post(url).headers(icloud_headers());
        if let Some(payload) = payload {
            request = request.json(payload);
        }
        let response = request
            .send()
            .map_err(|_| anyhow::anyhow!("Could not contact Apple's data-protection service"))?;
        let status = response.status();
        let body = response.json::<Value>().unwrap_or(Value::Null);
        if matches!(status.as_u16(), 401 | 403 | 421)
            || body.get("hsaChallengeRequired").and_then(Value::as_bool) == Some(true)
        {
            return Err(recovery(
                &self.session.account,
                "auth_refresh_required",
                format!(
                    "Apple rejected the saved session during Reminders data access (HTTP {status})"
                ),
                "refresh",
            ));
        }
        if !status.is_success() {
            bail!("Apple Reminders data-access request failed (HTTP {status})");
        }
        Ok(body)
    }

    /// Ask Apple's data-protection service to make this signed-in device's
    /// Reminders keys available to CloudKit. This mirrors pyicloud's PCS flow.
    fn request_reminders_pcs_access(&mut self, next_command: &str) -> Result<()> {
        if self.session.reminders_pcs_ready {
            return Ok(());
        }
        let state = self.reminders_pcs_post("requestWebAccessState", None)?;
        if state.get("isICDRSDisabled").and_then(Value::as_bool) != Some(true) {
            self.session.reminders_pcs_ready = true;
            return Ok(());
        }

        if state
            .get("isDeviceConsentedForPCS")
            .and_then(Value::as_bool)
            == Some(false)
        {
            let consent = self.reminders_pcs_post("enableDeviceConsentForPCS", None)?;
            if consent
                .get("isDeviceConsentNotificationSent")
                .and_then(Value::as_bool)
                != Some(true)
            {
                return Err(RemindersAccessRecovery {
                    code: "reminders_access_required",
                    message:
                        "Apple could not request trusted-device approval for Reminders data access"
                            .into(),
                    next_command: next_command.into(),
                }
                .into());
            }
            return Err(RemindersAccessRecovery {
                code: "reminders_access_required",
                message: "Apple requested trusted-device approval for Reminders data access; approve it, then retry the Reminders command".into(),
                next_command: next_command.into(),
            }
            .into());
        }

        for attempt in 0..10 {
            let response = self.reminders_pcs_post(
                "requestPCS",
                Some(&json!({
                    "appName": "reminders",
                    "derivedFromUserAction": attempt == 0,
                })),
            )?;
            if response.get("status").and_then(Value::as_str) == Some("success") {
                self.session.reminders_pcs_ready = true;
                return Ok(());
            }
            let message = response.get("message").and_then(Value::as_str);
            if !matches!(
                message,
                Some("Requested the device to upload cookies.")
                    | Some("Cookies not available yet on server.")
            ) {
                return Err(RemindersAccessRecovery {
                    code: "reminders_access_required",
                    message: "Apple has not granted Reminders data access yet; approve the request on a trusted device, then retry".into(),
                    next_command: next_command.into(),
                }
                .into());
            }
            if attempt < 9 {
                thread::sleep(Duration::from_secs(5));
            }
        }
        Err(RemindersAccessRecovery {
            code: "reminders_access_required",
            message: "Apple Reminders data access is still pending; approve the request on a trusted device, then retry".into(),
            next_command: next_command.into(),
        }
        .into())
    }

    fn cloudkit_zone_records(&self, record_type: &str) -> Result<Vec<Value>> {
        let mut request = json!({
            "zones": [{
                "zoneID": {"zoneName": "Reminders", "zoneType": "REGULAR_CUSTOM_ZONE"},
                "desiredRecordTypes": [record_type],
            }]
        });
        let mut records = Vec::new();
        loop {
            let response = self.reminders_cloudkit_request("changes/zone", &request)?;
            let zones = response
                .get("zones")
                .and_then(Value::as_array)
                .context("Apple returned an invalid Reminders zone response")?;
            if zones.is_empty() {
                break;
            }
            let zone = &zones[0];
            if let Some(code) = zone.get("serverErrorCode").and_then(Value::as_str) {
                bail!("Apple Reminders zone read failed ({code})");
            }
            if let Some(items) = zone.get("records").and_then(Value::as_array) {
                for item in items {
                    if let Some(code) = item.get("serverErrorCode").and_then(Value::as_str) {
                        bail!("Apple Reminders record read failed ({code})");
                    }
                    records.push(item.clone());
                }
            }
            if zone.get("moreComing").and_then(Value::as_bool) != Some(true) {
                break;
            }
            let sync_token = zone
                .get("syncToken")
                .and_then(Value::as_str)
                .context("Apple omitted the Reminders pagination token")?;
            request["zones"][0]["syncToken"] = json!(sync_token);
        }
        Ok(records)
    }

    fn append_cloudkit_reminders_for_list(
        &self,
        list_id: &str,
        list: &str,
        skip: &mut usize,
        take: usize,
        reminders: &mut Vec<Value>,
    ) -> Result<()> {
        let mut request = json!({
            "query": {
                "recordType": "reminderList",
                "filterBy": [
                    {"comparator":"EQUALS", "fieldName":"List", "fieldValue":{"type":"REFERENCE", "value":{"recordName":list_id, "action":"VALIDATE"}}},
                    {"comparator":"EQUALS", "fieldName":"includeCompleted", "fieldValue":{"type":"INT64", "value":1}},
                    {"comparator":"EQUALS", "fieldName":"LookupValidatingReference", "fieldValue":{"type":"INT64", "value":1}}
                ]
            },
            "zoneID": {"zoneName":"Reminders", "zoneType":"REGULAR_CUSTOM_ZONE"},
            "resultsLimit": skip.saturating_add(take).clamp(1, 200)
        });
        loop {
            let response = self.reminders_cloudkit_request("records/query", &request)?;
            let items = response
                .get("records")
                .and_then(Value::as_array)
                .context("Apple returned an invalid Reminders query response")?;
            for item in items {
                if let Some(code) = item.get("serverErrorCode").and_then(Value::as_str) {
                    bail!("Apple Reminders record query failed ({code})");
                }
                if item.get("recordType").and_then(Value::as_str) != Some("Reminder")
                    || cloudkit_field_truthy(item.get("fields"), "Deleted")
                {
                    continue;
                }
                let fields = item.get("fields");
                let relation = fields
                    .and_then(|v| v.get("List"))
                    .and_then(|v| v.get("value"))
                    .and_then(|v| v.get("recordName"))
                    .and_then(Value::as_str);
                if relation != Some(list_id) {
                    continue;
                }
                if *skip > 0 {
                    *skip -= 1;
                    continue;
                }
                reminders.push(json!({
                    "id":item.get("recordName").cloned().unwrap_or(Value::Null),
                    "title":cloudkit_text_field(fields, "TitleDocument")?,
                    "list_id":list_id,
                    "list":list,
                    "completed":cloudkit_field_truthy(fields, "Completed"),
                    "due":cloudkit_due_date(cloudkit_field_value(fields, "DueDate")),
                }));
                if reminders.len() >= take {
                    return Ok(());
                }
            }
            match response.get("continuationMarker").and_then(Value::as_str) {
                Some(marker) if !marker.is_empty() => request["continuationMarker"] = json!(marker),
                _ => break,
            }
        }
        Ok(())
    }

    /// Fetch available Apple Reminders lists and stable service IDs.
    pub fn reminder_lists(&mut self) -> Result<Vec<Value>> {
        self.require_authenticated()?;
        if self.has_cloudkit_reminders() {
            let next_command = format!(
                "icli reminders lists --email {}",
                crate::cli_quote(&self.session.account)
            );
            self.request_reminders_pcs_access(&next_command)?;
            let mut lists = Vec::new();
            for record in self.cloudkit_zone_records("List")? {
                if record.get("recordType").and_then(Value::as_str) != Some("List") {
                    continue;
                }
                let id = record.get("recordName").cloned().unwrap_or(Value::Null);
                let fields = record.get("fields");
                let name = cloudkit_field_value(fields, "Name")
                    .and_then(Value::as_str)
                    .unwrap_or("Untitled");
                let mut count = cloudkit_field_value(fields, "Count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as usize;
                if count == 0 {
                    if let Some(ids) = cloudkit_field_value(fields, "ReminderIDs")
                        .and_then(Value::as_str)
                        .and_then(|value| serde_json::from_str::<Vec<String>>(value).ok())
                    {
                        count = ids.len();
                    }
                }
                lists.push(json!({"id":id,"name":name,"count":count}));
            }
            return Ok(lists);
        }

        let data = self.reminders_startup()?;
        let reminders = data
            .get("Reminders")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(data
            .get("Collections")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|collection| {
                let id = collection.get("guid")?.clone();
                let name = collection
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or("Untitled");
                let count = reminders
                    .iter()
                    .filter(|reminder| reminder.get("pGuid") == Some(&id))
                    .count();
                Some(json!({"id":id,"name":name,"count":count}))
            })
            .collect())
    }

    /// Fetch one page of reminders from all current lists, including completed items.
    pub fn reminders(&mut self, skip: usize, limit: usize) -> Result<(Vec<Value>, bool)> {
        self.require_authenticated()?;
        if limit == 0 {
            return Ok((Vec::new(), false));
        }
        if self.has_cloudkit_reminders() {
            let next_command = format!(
                "icli reminders list --email {} --skip {skip} --limit {limit}",
                crate::cli_quote(&self.session.account),
            );
            self.request_reminders_pcs_access(&next_command)?;
            let mut lists = self
                .cloudkit_zone_records("List")?
                .into_iter()
                .filter(|record| record.get("recordType").and_then(Value::as_str) == Some("List"))
                .collect::<Vec<_>>();
            lists.sort_by(|a, b| {
                a.get("recordName")
                    .and_then(Value::as_str)
                    .cmp(&b.get("recordName").and_then(Value::as_str))
            });
            let mut reminders = Vec::new();
            let mut remaining_skip = skip;
            let take = limit.saturating_add(1);
            for collection in lists {
                let list_id = collection
                    .get("recordName")
                    .and_then(Value::as_str)
                    .context("Apple returned a Reminders list without an ID")?;
                let list = cloudkit_field_value(collection.get("fields"), "Name")
                    .and_then(Value::as_str)
                    .unwrap_or("Untitled");
                self.append_cloudkit_reminders_for_list(
                    list_id,
                    list,
                    &mut remaining_skip,
                    take,
                    &mut reminders,
                )?;
                if reminders.len() >= take {
                    break;
                }
            }
            let has_more = reminders.len() > limit;
            reminders.truncate(limit);
            return Ok((reminders, has_more));
        }

        let data = self.reminders_startup()?;
        let collections = data
            .get("Collections")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut reminders = data
            .get("Reminders")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|reminder| {
                let id = reminder.get("guid")?.clone();
                let list_id = reminder.get("pGuid")?.clone();
                let list = collections
                    .iter()
                    .find(|collection| collection.get("guid") == Some(&list_id))
                    .and_then(|collection| collection.get("title"))
                    .cloned()
                    .unwrap_or(Value::Null);
                let completed = reminder
                    .get("isCompleted")
                    .and_then(Value::as_bool)
                    .unwrap_or_else(|| {
                        reminder
                            .get("completedDate")
                            .is_some_and(|date| !date.is_null())
                    });
                Some(json!({
                    "id":id,
                    "title":reminder.get("title").cloned().unwrap_or(Value::Null),
                    "list_id":list_id,
                    "list":list,
                    "completed":completed,
                    "due":reminder.get("dueDate").cloned().unwrap_or(Value::Null)
                }))
            })
            .collect::<Vec<_>>();
        let has_more = skip.saturating_add(limit) < reminders.len();
        let rows = reminders.drain(..).skip(skip).take(limit).collect();
        Ok((rows, has_more))
    }

    fn reminders_require_cloudkit(&self) -> Result<()> {
        if !self.has_cloudkit_reminders() {
            bail!(
                "This Reminders operation requires Apple's CloudKit Reminders service; this account only advertises the legacy read service"
            );
        }
        Ok(())
    }

    fn reminders_lookup(&self, record_names: &[String]) -> Result<Vec<Value>> {
        let response = self.reminders_cloudkit_request(
            "records/lookup",
            &json!({
                "records": record_names.iter().map(|name| json!({"recordName":name})).collect::<Vec<_>>(),
                "zoneID":{"zoneName":"Reminders","zoneType":"REGULAR_CUSTOM_ZONE"}
            }),
        )?;
        let records = response
            .get("records")
            .and_then(Value::as_array)
            .context("Apple returned an invalid Reminders lookup response")?;
        for record in records {
            if let Some(code) = record.get("serverErrorCode").and_then(Value::as_str)
                && code != "NOT_FOUND"
            {
                let reason = record.get("reason").and_then(Value::as_str).unwrap_or("");
                bail!("Apple Reminders lookup failed ({code}): {reason}");
            }
        }
        Ok(records.clone())
    }

    fn reminders_modify(&self, operations: Vec<Value>, atomic: bool) -> Result<Value> {
        let response = self.reminders_cloudkit_request(
            "records/modify",
            &json!({
                "operations":operations,
                "zoneID":{"zoneName":"Reminders","zoneType":"REGULAR_CUSTOM_ZONE"},
                "atomic":atomic
            }),
        )?;
        for record in response
            .get("records")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(code) = record.get("serverErrorCode").and_then(Value::as_str) {
                let reason = record.get("reason").and_then(Value::as_str).unwrap_or("");
                bail!("Apple rejected a Reminders write ({code}): {reason}");
            }
        }
        Ok(response)
    }

    fn reminders_record(&self, record_name: &str) -> Result<Value> {
        let records = self.reminders_lookup(&[record_name.to_string()])?;
        records
            .into_iter()
            .find(|record| {
                record.get("recordName").and_then(Value::as_str) == Some(record_name)
                    && record.get("fields").is_some()
            })
            .with_context(|| format!("Reminders record not found: {record_name}"))
    }

    fn reminders_require_access(&mut self, command: &str) -> Result<()> {
        self.require_authenticated()?;
        self.reminders_require_cloudkit()?;
        self.request_reminders_pcs_access(command)
    }

    /// Fetch a reminder by its stable CloudKit record ID.
    pub fn reminder_get(&mut self, id: &str) -> Result<Value> {
        self.reminders_require_access(&format!("icli reminders get {}", crate::cli_quote(id)))?;
        let record_name = reminders_record_name(id, "Reminder");
        reminders_record_to_value(&self.reminders_record(&record_name)?)
    }

    /// Create a reminder in a known list. The server assigned ID is read back
    /// after the create so callers receive the stable ID and normalized fields.
    #[allow(clippy::too_many_arguments)]
    pub fn reminder_create(
        &mut self,
        list_id: &str,
        title: &str,
        notes: &str,
        due_date_ms: Option<i64>,
        all_day: bool,
        priority: i64,
        flagged: bool,
    ) -> Result<Value> {
        self.reminders_require_access("icli reminders lists")?;
        let list_name = reminders_record_name(list_id, "List");
        let list = self.reminders_record(&list_name)?;
        if list.get("recordType").and_then(Value::as_str) != Some("List") {
            bail!("The selected CloudKit record is not a Reminders list");
        }
        let reminder_name = format!(
            "Reminder/{}",
            Uuid::new_v4().simple().to_string().to_uppercase()
        );
        let now = reminders_now_ms();
        let mut fields = json!({
            "AllDay":{"type":"INT64","value":i64::from(all_day)},
            "Completed":{"type":"INT64","value":0},
            "CompletionDate":{"type":"TIMESTAMP","value":Value::Null},
            "CreationDate":{"type":"TIMESTAMP","value":now},
            "Deleted":{"type":"INT64","value":0},
            "Flagged":{"type":"INT64","value":i64::from(flagged)},
            "Imported":{"type":"INT64","value":0},
            "LastModifiedDate":{"type":"TIMESTAMP","value":now},
            "List":{"type":"REFERENCE","value":{"recordName":list_name,"action":"VALIDATE"}},
            "NotesDocument":{"type":"STRING","value":encode_reminders_text_document(notes)?},
            "Priority":{"type":"INT64","value":priority},
            "TitleDocument":{"type":"STRING","value":encode_reminders_text_document(title)?},
            "ResolutionTokenMap":{"type":"STRING","value":reminders_resolution_tokens(&["allDay","titleDocument","notesDocument","priority","list","flagged","completed","completionDate","creationDate","lastModifiedDate","dueDate","timeZone"])?}
        });
        if let Some(ms) = due_date_ms {
            fields["DueDate"] = json!({"type":"TIMESTAMP","value":ms});
            if !all_day {
                fields["TimeZone"] = json!({"type":"STRING","value":"UTC"});
            }
        }
        self.reminders_modify(
            vec![json!({
                "operationType":"create",
                "record":{
                    "recordName":reminder_name,
                    "recordType":"Reminder",
                    "fields":fields,
                    "parent":{"recordName":list_name}
                }
            })],
            false,
        )?;
        reminders_record_to_value(&self.reminders_record(&reminder_name)?)
    }

    /// Update supported reminder fields. Only fields present in `patch` are
    /// sent, preserving the rest of the server record.
    pub fn reminder_update(&mut self, id: &str, patch: &Value) -> Result<Value> {
        self.reminders_require_access(&format!("icli reminders get {}", crate::cli_quote(id)))?;
        let record_name = reminders_record_name(id, "Reminder");
        let record = self.reminders_record(&record_name)?;
        let mut fields = serde_json::Map::new();
        let mut token_names = Vec::new();
        for (name, token, document_name) in [
            ("title", "titleDocument", Some("TitleDocument")),
            ("notes", "notesDocument", Some("NotesDocument")),
        ] {
            if let Some(text) = patch.get(name).and_then(Value::as_str) {
                let field_name = document_name.unwrap();
                let existing = record
                    .get("fields")
                    .and_then(|fields| fields.get(field_name));
                let encoded = edit_reminders_text_document(existing, text)?;
                fields.insert(field_name.into(), json!({"type":"STRING","value":encoded}));
                token_names.push(token);
            }
        }
        for (name, cloud_name, token) in [
            ("completed", "Completed", "completed"),
            ("flagged", "Flagged", "flagged"),
            ("all_day", "AllDay", "allDay"),
        ] {
            if let Some(value) = patch.get(name).and_then(Value::as_bool) {
                fields.insert(
                    cloud_name.into(),
                    json!({"type":"INT64","value":i64::from(value)}),
                );
                token_names.push(token);
                if name == "completed" {
                    let completion_date = if value {
                        json!(reminders_now_ms())
                    } else {
                        Value::Null
                    };
                    fields.insert(
                        "CompletionDate".into(),
                        json!({"type":"TIMESTAMP","value":completion_date}),
                    );
                    token_names.push("completionDate");
                }
            }
        }
        if let Some(priority) = patch.get("priority").and_then(Value::as_i64) {
            if !(0..=9).contains(&priority) {
                bail!("Reminder priority must be between 0 and 9");
            }
            fields.insert("Priority".into(), json!({"type":"INT64","value":priority}));
            token_names.push("priority");
        }
        if let Some(due) = patch.get("due_date_ms") {
            fields.insert("DueDate".into(), json!({"type":"TIMESTAMP","value":due}));
            token_names.push("dueDate");
            if !due.is_null() {
                fields.insert("TimeZone".into(), json!({"type":"STRING","value":"UTC"}));
                token_names.push("timeZone");
            } else {
                fields.insert(
                    "TimeZone".into(),
                    json!({"type":"STRING","value":Value::Null}),
                );
                token_names.push("timeZone");
            }
        }
        if fields.is_empty() {
            bail!("No Reminders fields were supplied to update");
        }
        fields.insert(
            "LastModifiedDate".into(),
            json!({"type":"TIMESTAMP","value":reminders_now_ms()}),
        );
        token_names.push("lastModifiedDate");
        fields.insert("ResolutionTokenMap".into(), json!({"type":"STRING","value":reminders_merge_tokens(cloudkit_field_value(record.get("fields"),"ResolutionTokenMap").and_then(Value::as_str), &token_names)?}));
        let record_tag = record
            .get("recordChangeTag")
            .cloned()
            .unwrap_or(Value::Null);
        self.reminders_modify(vec![json!({
            "operationType":"update",
            "record":{"recordName":record_name,"recordType":"Reminder","recordChangeTag":record_tag,"fields":Value::Object(fields)}
        })], false)?;
        reminders_record_to_value(&self.reminders_record(&record_name)?)
    }

    pub fn reminder_set_status(&mut self, id: &str, completed: bool) -> Result<Value> {
        self.reminder_update(id, &json!({"completed":completed}))
    }

    /// Soft-delete: Apple retains a tombstone-compatible record and clients
    /// treat `Deleted=1` as removed from the user's visible list.
    pub fn reminder_delete(&mut self, id: &str) -> Result<Value> {
        self.reminders_require_access(&format!("icli reminders get {}", crate::cli_quote(id)))?;
        let record_name = reminders_record_name(id, "Reminder");
        let record = self.reminders_record(&record_name)?;
        let fields = json!({
            "Deleted":{"type":"INT64","value":1},
            "LastModifiedDate":{"type":"TIMESTAMP","value":reminders_now_ms()},
            "ResolutionTokenMap":{"type":"STRING","value":reminders_resolution_tokens(&["deleted","lastModifiedDate"])?}
        });
        self.reminders_modify(vec![json!({"operationType":"update","record":{"recordName":record_name,"recordType":"Reminder","recordChangeTag":record.get("recordChangeTag"),"fields":fields}})], false)?;
        Ok(json!({"id":record_name,"deleted":true}))
    }

    /// Return a list snapshot including related records for the selected list.
    pub fn reminder_snapshot(&mut self, list_id: &str, limit: usize) -> Result<Value> {
        self.reminders_require_access("icli reminders lists")?;
        let list_name = reminders_record_name(list_id, "List");
        let list = self.reminders_record(&list_name)?;
        let mut request = json!({"query":{"recordType":"reminderList","filterBy":[
            {"comparator":"EQUALS","fieldName":"List","fieldValue":{"type":"REFERENCE","value":{"recordName":list_name,"action":"VALIDATE"}}},
            {"comparator":"EQUALS","fieldName":"includeCompleted","fieldValue":{"type":"INT64","value":1}},
            {"comparator":"EQUALS","fieldName":"LookupValidatingReference","fieldValue":{"type":"INT64","value":1}}
        ]},"zoneID":{"zoneName":"Reminders","zoneType":"REGULAR_CUSTOM_ZONE"},"resultsLimit":200});
        let mut groups = serde_json::Map::new();
        let mut truncated_types = std::collections::BTreeSet::new();
        for key in [
            "reminders",
            "alarms",
            "alarm_triggers",
            "attachments",
            "hashtags",
            "recurrence_rules",
        ] {
            groups.insert(key.into(), json!([]));
        }
        loop {
            let response = self.reminders_cloudkit_request("records/query", &request)?;
            let records = response
                .get("records")
                .and_then(Value::as_array)
                .context("Apple returned an invalid Reminders snapshot")?;
            for record in records {
                let typ = record
                    .get("recordType")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let row = reminders_related_record_to_value(record)?;
                let key = match typ {
                    "Reminder" => "reminders",
                    "Alarm" => "alarms",
                    "AlarmTrigger" => "alarm_triggers",
                    "Attachment" => "attachments",
                    "Hashtag" => "hashtags",
                    "RecurrenceRule" => "recurrence_rules",
                    _ => continue,
                };
                let rows = groups.get_mut(key).and_then(Value::as_array_mut).unwrap();
                if rows.len() < limit {
                    rows.push(row);
                } else {
                    truncated_types.insert(key);
                }
            }
            match response.get("continuationMarker").and_then(Value::as_str) {
                Some(marker) if !marker.is_empty() => request["continuationMarker"] = json!(marker),
                _ => break,
            }
        }
        Ok(
            json!({"list":reminder_list_to_value(&list),"records":Value::Object(groups),"limit_per_type":limit,"truncated_types":truncated_types}),
        )
    }

    pub fn reminders_sync_cursor(&mut self) -> Result<String> {
        self.reminders_require_access("icli reminders sync-cursor")?;
        let query = self.reminders_cloudkit_request(
            "records/query",
            &json!({
                "query":{"recordType":"reminderList"},
                "zoneID":{"zoneName":"Reminders","zoneType":"REGULAR_CUSTOM_ZONE"},
                "resultsLimit":1
            }),
        );
        if let Ok(response) = query
            && let Some(cursor) = response.get("syncToken").and_then(Value::as_str)
        {
            return Ok(cursor.to_owned());
        }

        // Some CloudKit deployments reject the lightweight query. Match
        // pyicloud's fallback and ask the zone changes endpoint for its token.
        let response = self.reminders_cloudkit_request(
            "changes/zone",
            &json!({"zones":[{
                "zoneID":{"zoneName":"Reminders","zoneType":"REGULAR_CUSTOM_ZONE"},
                "desiredRecordTypes":[],
                "desiredKeys":[],
                "reverse":false
            }]}),
        )?;
        response
            .get("zones")
            .and_then(Value::as_array)
            .and_then(|zones| zones.first())
            .and_then(|zone| zone.get("syncToken"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .context("Apple did not return a Reminders sync cursor")
    }

    pub fn reminders_changes(&mut self, since: Option<&str>, limit: usize) -> Result<Value> {
        self.reminders_require_access("icli reminders sync-cursor")?;
        let mut zone = json!({"zoneID":{"zoneName":"Reminders","zoneType":"REGULAR_CUSTOM_ZONE"},"desiredRecordTypes":["Reminder"]});
        if let Some(cursor) = since {
            zone["syncToken"] = json!(cursor);
        }
        let response = self.reminders_cloudkit_request(
            "changes/zone",
            &json!({"zones":[zone],"resultsLimit":limit.max(1)}),
        )?;
        let zone = response
            .get("zones")
            .and_then(Value::as_array)
            .and_then(|zones| zones.first())
            .context("Apple returned no Reminders changes zone")?;
        if let Some(code) = zone.get("serverErrorCode").and_then(Value::as_str) {
            bail!("Apple Reminders change feed failed ({code})");
        }
        let cursor = zone
            .get("syncToken")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let events = zone.get("records").and_then(Value::as_array).into_iter().flatten().take(limit).map(|record| -> Result<Value> {
            if record.get("deleted").and_then(Value::as_bool)==Some(true) { Ok(json!({"type":"deleted","id":record.get("recordName")})) }
            else { Ok(json!({"type":if cloudkit_field_truthy(record.get("fields"),"Deleted"){"deleted"}else{"updated"},"reminder":reminders_record_to_value(record)?})) }
        }).collect::<Result<Vec<_>>>()?;
        Ok(
            json!({"changes":events,"cursor":cursor,"more_available":zone.get("moreComing").and_then(Value::as_bool).unwrap_or(false)}),
        )
    }

    fn reminder_related_records(
        &self,
        reminder_id: &str,
        field: &str,
        prefix: &str,
        record_type: &str,
    ) -> Result<(Value, Vec<Value>)> {
        let reminder_name = reminders_record_name(reminder_id, "Reminder");
        let reminder = self.reminders_record(&reminder_name)?;
        let ids = reminders_linked_ids(reminder.get("fields"), field, prefix);
        let records = self.reminders_lookup(&ids)?;
        let records = records
            .into_iter()
            .filter(|record| record.get("recordType").and_then(Value::as_str) == Some(record_type))
            .collect();
        Ok((reminder, records))
    }

    fn reminders_create_child(
        &self,
        reminder: &Value,
        prefix: &str,
        record_type: &str,
        ids_field: &str,
        token_name: &str,
        fields: Value,
    ) -> Result<String> {
        let reminder_name = reminder
            .get("recordName")
            .and_then(Value::as_str)
            .context("Apple returned a reminder without an ID")?;
        let uuid = Uuid::new_v4().simple().to_string().to_uppercase();
        let child_name = format!("{prefix}/{uuid}");
        let mut ids = reminders_linked_ids(reminder.get("fields"), ids_field, prefix)
            .into_iter()
            .map(|id| id.rsplit('/').next().unwrap_or(&id).to_string())
            .collect::<Vec<_>>();
        ids.push(uuid);
        let last_modified = reminders_now_ms();
        let resolution = reminders_merge_tokens(
            cloudkit_field_value(reminder.get("fields"), "ResolutionTokenMap")
                .and_then(Value::as_str),
            &[token_name, "lastModifiedDate"],
        )?;
        let reminder_update = json!({"operationType":"update","record":{"recordName":reminder_name,"recordType":"Reminder","recordChangeTag":reminder.get("recordChangeTag"),"fields":{
            (ids_field):{"type":"STRING_LIST","value":ids},
            "LastModifiedDate":{"type":"TIMESTAMP","value":last_modified},
            "ResolutionTokenMap":{"type":"STRING","value":resolution}
        }}});
        let child_create = json!({"operationType":"create","record":{"recordName":child_name,"recordType":record_type,"fields":fields,"parent":{"recordName":reminder_name}}});
        self.reminders_modify(vec![reminder_update, child_create], true)?;
        Ok(child_name)
    }

    fn reminders_delete_child(
        &self,
        reminder: &Value,
        child_id: &str,
        prefix: &str,
        record_type: &str,
        ids_field: &str,
        token_name: &str,
    ) -> Result<Value> {
        let reminder_name = reminder
            .get("recordName")
            .and_then(Value::as_str)
            .context("Apple returned a reminder without an ID")?;
        let child_name = reminders_record_name(child_id, prefix);
        let child = self.reminders_record(&child_name)?;
        if reminders_reference(child.get("fields"), "Reminder").as_deref() != Some(reminder_name) {
            bail!("The {record_type} is not attached to the selected reminder");
        }
        let raw_child_id = child_name.rsplit('/').next().unwrap_or(&child_name);
        let ids = reminders_linked_ids(reminder.get("fields"), ids_field, prefix)
            .into_iter()
            .map(|id| id.rsplit('/').next().unwrap_or(&id).to_string())
            .filter(|id| id != raw_child_id)
            .collect::<Vec<_>>();
        let last_modified = reminders_now_ms();
        let resolution = reminders_merge_tokens(
            cloudkit_field_value(reminder.get("fields"), "ResolutionTokenMap")
                .and_then(Value::as_str),
            &[token_name, "lastModifiedDate"],
        )?;
        let reminder_update = json!({"operationType":"update","record":{"recordName":reminder_name,"recordType":"Reminder","recordChangeTag":reminder.get("recordChangeTag"),"fields":{
            (ids_field):{"type":"STRING_LIST","value":ids},"LastModifiedDate":{"type":"TIMESTAMP","value":last_modified},"ResolutionTokenMap":{"type":"STRING","value":resolution}
        }}});
        let child_update = json!({"operationType":"update","record":{"recordName":child_name,"recordType":record_type,"recordChangeTag":child.get("recordChangeTag"),"fields":{"Deleted":{"type":"INT64","value":1},"Reminder":{"type":"REFERENCE","value":{"recordName":reminder_name,"action":"VALIDATE"}}}}});
        self.reminders_modify(vec![reminder_update, child_update], true)?;
        Ok(json!({"id":child_name,"deleted":true}))
    }

    fn reminders_update_child(
        &self,
        child_id: &str,
        prefix: &str,
        record_type: &str,
        mut fields: serde_json::Map<String, Value>,
    ) -> Result<Value> {
        let name = reminders_record_name(child_id, prefix);
        let child = self.reminders_record(&name)?;
        if let Some(reminder) = reminders_reference(child.get("fields"), "Reminder") {
            fields.insert(
                "Reminder".into(),
                json!({"type":"REFERENCE","value":{"recordName":reminder,"action":"VALIDATE"}}),
            );
        }
        self.reminders_modify(vec![json!({"operationType":"update","record":{"recordName":name,"recordType":record_type,"recordChangeTag":child.get("recordChangeTag"),"fields":Value::Object(fields)}})],false)?;
        self.reminders_record(&name)
    }

    pub fn reminder_alarms(&mut self, id: &str) -> Result<Vec<Value>> {
        self.reminders_require_access(&format!(
            "icli reminders alarm list {}",
            crate::cli_quote(id)
        ))?;
        let (_, alarms) = self.reminder_related_records(id, "AlarmIDs", "Alarm", "Alarm")?;
        let mut result = Vec::new();
        for alarm in alarms {
            let mut row = reminders_related_record_to_value(&alarm)?;
            let trigger_id = cloudkit_field_value(alarm.get("fields"), "TriggerID")
                .and_then(Value::as_str)
                .map(|id| reminders_record_name(id, "AlarmTrigger"));
            if let Some(trigger_id) = trigger_id {
                let trigger = self.reminders_record(&trigger_id)?;
                row["trigger"] = reminders_related_record_to_value(&trigger)?;
            }
            result.push(row);
        }
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn reminder_add_location_alarm(
        &mut self,
        id: &str,
        title: &str,
        address: &str,
        latitude: f64,
        longitude: f64,
        radius: f64,
        proximity: i64,
    ) -> Result<Value> {
        self.reminders_require_access(&format!(
            "icli reminders alarm list {}",
            crate::cli_quote(id)
        ))?;
        if !(-90.0..=90.0).contains(&latitude)
            || !(-180.0..=180.0).contains(&longitude)
            || radius <= 0.0
            || !(1..=2).contains(&proximity)
        {
            bail!(
                "Location alarm requires latitude -90..90, longitude -180..180, positive radius, and proximity 1 (arrive) or 2 (leave)"
            );
        }
        let reminder_name = reminders_record_name(id, "Reminder");
        let reminder = self.reminders_record(&reminder_name)?;
        let alarm_uuid = Uuid::new_v4().simple().to_string().to_uppercase();
        let trigger_uuid = Uuid::new_v4().simple().to_string().to_uppercase();
        let location_uid = Uuid::new_v4().simple().to_string().to_uppercase();
        let alarm_name = format!("Alarm/{alarm_uuid}");
        let trigger_name = format!("AlarmTrigger/{trigger_uuid}");
        let mut ids = reminders_linked_ids(reminder.get("fields"), "AlarmIDs", "Alarm")
            .into_iter()
            .map(|v| v.rsplit('/').next().unwrap_or(&v).to_string())
            .collect::<Vec<_>>();
        ids.push(alarm_uuid.clone());
        let now = reminders_now_ms();
        let token = reminders_merge_tokens(
            cloudkit_field_value(reminder.get("fields"), "ResolutionTokenMap")
                .and_then(Value::as_str),
            &["alarmIDs", "lastModifiedDate"],
        )?;
        let nonce = 100_000_000_000f64 + (now as f64 / 1000.0) - 978_307_200.0;
        let ops = vec![
            json!({"operationType":"update","record":{"recordName":reminder_name,"recordType":"Reminder","recordChangeTag":reminder.get("recordChangeTag"),"fields":{"AlarmIDs":{"type":"STRING_LIST","value":ids},"LastModifiedDate":{"type":"TIMESTAMP","value":now},"ResolutionTokenMap":{"type":"STRING","value":token}}}}),
            json!({"operationType":"create","record":{"recordName":alarm_name,"recordType":"Alarm","parent":{"recordName":reminder_name},"fields":{"AlarmUID":{"type":"STRING","value":alarm_uuid},"Deleted":{"type":"INT64","value":0},"Imported":{"type":"INT64","value":0},"Reminder":{"type":"REFERENCE","value":{"recordName":reminder_name,"action":"VALIDATE"}},"TriggerID":{"type":"STRING","value":trigger_uuid},"DueDateResolutionTokenAsNonce":{"type":"DOUBLE","value":nonce}}}}),
            json!({"operationType":"create","record":{"recordName":trigger_name,"recordType":"AlarmTrigger","parent":{"recordName":alarm_name},"fields":{"Address":{"type":"STRING","value":address,"isEncrypted":true},"Alarm":{"type":"REFERENCE","value":{"recordName":alarm_name,"action":"VALIDATE"}},"Deleted":{"type":"INT64","value":0},"Latitude":{"type":"DOUBLE","value":latitude,"isEncrypted":true},"LocationUID":{"type":"STRING","value":location_uid},"Longitude":{"type":"DOUBLE","value":longitude,"isEncrypted":true},"Proximity":{"type":"INT64","value":proximity},"Radius":{"type":"DOUBLE","value":radius},"ReferenceFrameString":{"type":"STRING","value":"1","isEncrypted":true},"Title":{"type":"STRING","value":title,"isEncrypted":true},"Type":{"type":"STRING","value":"Location"}}}}),
        ];
        self.reminders_modify(ops, true)?;
        let alarm = self.reminders_record(&alarm_name)?;
        let trigger = self.reminders_record(&trigger_name)?;
        Ok(
            json!({"alarm":reminders_related_record_to_value(&alarm)?,"trigger":reminders_related_record_to_value(&trigger)?}),
        )
    }

    pub fn reminder_hashtags(&mut self, id: &str) -> Result<Vec<Value>> {
        self.reminders_require_access(&format!(
            "icli reminders hashtag list {}",
            crate::cli_quote(id)
        ))?;
        let (_, records) = self.reminder_related_records(id, "HashtagIDs", "Hashtag", "Hashtag")?;
        records
            .iter()
            .map(|record| {
                let mut row = reminders_related_record_to_value(record)?;
                row["name"] = json!(cloudkit_encoded_text(cloudkit_field_value(
                    record.get("fields"),
                    "Name"
                )));
                Ok(row)
            })
            .collect()
    }

    pub fn reminder_hashtag_create(&mut self, id: &str, name: &str) -> Result<Value> {
        self.reminders_require_access(&format!(
            "icli reminders hashtag list {}",
            crate::cli_quote(id)
        ))?;
        let reminder = self.reminders_record(&reminders_record_name(id, "Reminder"))?;
        let bytes = STANDARD.encode(name.as_bytes());
        let now = reminders_now_ms();
        let fields = json!({"Name":{"type":"ENCRYPTED_BYTES","value":bytes},"Deleted":{"type":"INT64","value":0},"Reminder":{"type":"REFERENCE","value":{"recordName":reminder.get("recordName"),"action":"VALIDATE"}},"CreationDate":{"type":"TIMESTAMP","value":now}});
        let child = self.reminders_create_child(
            &reminder,
            "Hashtag",
            "Hashtag",
            "HashtagIDs",
            "hashtagIDs",
            fields,
        )?;
        let record = self.reminders_record(&child)?;
        let mut row = reminders_related_record_to_value(&record)?;
        row["name"] = json!(name);
        Ok(row)
    }

    pub fn reminder_hashtag_update(&mut self, id: &str, tag_id: &str, name: &str) -> Result<Value> {
        self.reminders_require_access(&format!(
            "icli reminders hashtag list {}",
            crate::cli_quote(id)
        ))?;
        let (_, records) = self.reminder_related_records(id, "HashtagIDs", "Hashtag", "Hashtag")?;
        if !records.iter().any(|record| {
            record.get("recordName").and_then(Value::as_str)
                == Some(reminders_record_name(tag_id, "Hashtag").as_str())
        }) {
            bail!("Hashtag does not belong to the selected reminder");
        }
        let bytes = STANDARD.encode(name.as_bytes());
        let mut fields = serde_json::Map::new();
        fields.insert(
            "Name".into(),
            json!({"type":"ENCRYPTED_BYTES","value":bytes}),
        );
        let record = self.reminders_update_child(tag_id, "Hashtag", "Hashtag", fields)?;
        let mut row = reminders_related_record_to_value(&record)?;
        row["name"] = json!(name);
        Ok(row)
    }

    pub fn reminder_hashtag_delete(&mut self, id: &str, tag_id: &str) -> Result<Value> {
        self.reminders_require_access(&format!(
            "icli reminders hashtag list {}",
            crate::cli_quote(id)
        ))?;
        let (reminder, _) =
            self.reminder_related_records(id, "HashtagIDs", "Hashtag", "Hashtag")?;
        self.reminders_delete_child(
            &reminder,
            tag_id,
            "Hashtag",
            "Hashtag",
            "HashtagIDs",
            "hashtagIDs",
        )
    }

    pub fn reminder_attachments(&mut self, id: &str) -> Result<Vec<Value>> {
        self.reminders_require_access(&format!(
            "icli reminders attachment list {}",
            crate::cli_quote(id)
        ))?;
        let (_, records) =
            self.reminder_related_records(id, "AttachmentIDs", "Attachment", "Attachment")?;
        records
            .iter()
            .map(|record| {
                let mut row = reminders_related_record_to_value(record)?;
                row["url"] = json!(cloudkit_attachment_url(cloudkit_field_value(
                    record.get("fields"),
                    "URL"
                )));
                Ok(row)
            })
            .collect()
    }

    pub fn reminder_attachment_create_url(
        &mut self,
        id: &str,
        url: &str,
        uti: &str,
    ) -> Result<Value> {
        let parsed = Url::parse(url).context("Attachment URL must be an absolute URL")?;
        if !matches!(parsed.scheme(), "https" | "http") {
            bail!("Attachment URL must use HTTP or HTTPS");
        }
        self.reminders_require_access(&format!(
            "icli reminders attachment list {}",
            crate::cli_quote(id)
        ))?;
        let reminder = self.reminders_record(&reminders_record_name(id, "Reminder"))?;
        let fields = json!({"Type":{"type":"STRING","value":"URL"},"Reminder":{"type":"REFERENCE","value":{"recordName":reminder.get("recordName"),"action":"VALIDATE"}},"URL":{"type":"STRING","value":url,"isEncrypted":true},"UTI":{"type":"STRING","value":uti},"Imported":{"type":"INT64","value":0},"Deleted":{"type":"INT64","value":0}});
        let child = self.reminders_create_child(
            &reminder,
            "Attachment",
            "Attachment",
            "AttachmentIDs",
            "attachmentIDs",
            fields,
        )?;
        let record = self.reminders_record(&child)?;
        let mut row = reminders_related_record_to_value(&record)?;
        row["url"] = json!(url);
        Ok(row)
    }

    pub fn reminder_attachment_update(
        &mut self,
        id: &str,
        attachment_id: &str,
        url: Option<&str>,
        uti: Option<&str>,
    ) -> Result<Value> {
        self.reminders_require_access(&format!(
            "icli reminders attachment list {}",
            crate::cli_quote(id)
        ))?;
        if url.is_none() && uti.is_none() {
            bail!("Supply --url or --uti to update an attachment");
        }
        let (_, records) =
            self.reminder_related_records(id, "AttachmentIDs", "Attachment", "Attachment")?;
        if !records.iter().any(|record| {
            record.get("recordName").and_then(Value::as_str)
                == Some(reminders_record_name(attachment_id, "Attachment").as_str())
        }) {
            bail!("Attachment does not belong to the selected reminder");
        }
        let attachment = records
            .iter()
            .find(|record| {
                record.get("recordName").and_then(Value::as_str)
                    == Some(reminders_record_name(attachment_id, "Attachment").as_str())
            })
            .context("Attachment does not belong to the selected reminder")?;
        if cloudkit_field_value(attachment.get("fields"), "Type").and_then(Value::as_str)
            != Some("URL")
        {
            bail!("Only URL attachments can be updated; this attachment is not a URL");
        }
        let mut fields = serde_json::Map::new();
        fields.insert("Type".into(), json!({"type":"STRING","value":"URL"}));
        if let Some(url) = url {
            let parsed = Url::parse(url).context("Attachment URL must be an absolute URL")?;
            if !matches!(parsed.scheme(), "https" | "http") {
                bail!("Attachment URL must use HTTP or HTTPS");
            }
            fields.insert(
                "URL".into(),
                json!({"type":"STRING","value":url,"isEncrypted":true}),
            );
        }
        if let Some(uti) = uti {
            fields.insert("UTI".into(), json!({"type":"STRING","value":uti}));
        }
        let record =
            self.reminders_update_child(attachment_id, "Attachment", "Attachment", fields)?;
        let mut row = reminders_related_record_to_value(&record)?;
        row["url"] = json!(cloudkit_attachment_url(cloudkit_field_value(
            record.get("fields"),
            "URL"
        )));
        Ok(row)
    }

    pub fn reminder_attachment_delete(&mut self, id: &str, attachment_id: &str) -> Result<Value> {
        self.reminders_require_access(&format!(
            "icli reminders attachment list {}",
            crate::cli_quote(id)
        ))?;
        let (reminder, _) =
            self.reminder_related_records(id, "AttachmentIDs", "Attachment", "Attachment")?;
        self.reminders_delete_child(
            &reminder,
            attachment_id,
            "Attachment",
            "Attachment",
            "AttachmentIDs",
            "attachmentIDs",
        )
    }

    pub fn reminder_recurrences(&mut self, id: &str) -> Result<Vec<Value>> {
        self.reminders_require_access(&format!(
            "icli reminders recurrence list {}",
            crate::cli_quote(id)
        ))?;
        let (_, records) = self.reminder_related_records(
            id,
            "RecurrenceRuleIDs",
            "RecurrenceRule",
            "RecurrenceRule",
        )?;
        records
            .iter()
            .map(reminders_related_record_to_value)
            .collect()
    }

    pub fn reminder_recurrence_create(
        &mut self,
        id: &str,
        frequency: i64,
        interval: i64,
        count: i64,
        first_day: i64,
    ) -> Result<Value> {
        if !(0..=3).contains(&frequency)
            || interval < 1
            || count < 0
            || !(0..=6).contains(&first_day)
        {
            bail!(
                "Recurrence frequency must be 0..3, interval >=1, occurrence count >=0, and first day 0..6"
            );
        }
        self.reminders_require_access(&format!(
            "icli reminders recurrence list {}",
            crate::cli_quote(id)
        ))?;
        let reminder = self.reminders_record(&reminders_record_name(id, "Reminder"))?;
        let fields = json!({"Reminder":{"type":"REFERENCE","value":{"recordName":reminder.get("recordName"),"action":"VALIDATE"}},"Frequency":{"type":"INT64","value":frequency},"Interval":{"type":"INT64","value":interval},"OccurrenceCount":{"type":"INT64","value":count},"FirstDayOfTheWeek":{"type":"INT64","value":first_day},"Imported":{"type":"INT64","value":0},"Deleted":{"type":"INT64","value":0}});
        let child = self.reminders_create_child(
            &reminder,
            "RecurrenceRule",
            "RecurrenceRule",
            "RecurrenceRuleIDs",
            "recurrenceRuleIDs",
            fields,
        )?;
        reminders_related_record_to_value(&self.reminders_record(&child)?)
    }

    pub fn reminder_recurrence_update(
        &mut self,
        id: &str,
        rule_id: &str,
        patch: &Value,
    ) -> Result<Value> {
        self.reminders_require_access(&format!(
            "icli reminders recurrence list {}",
            crate::cli_quote(id)
        ))?;
        let (_, records) = self.reminder_related_records(
            id,
            "RecurrenceRuleIDs",
            "RecurrenceRule",
            "RecurrenceRule",
        )?;
        let name = reminders_record_name(rule_id, "RecurrenceRule");
        if !records
            .iter()
            .any(|record| record.get("recordName").and_then(Value::as_str) == Some(name.as_str()))
        {
            bail!("Recurrence rule does not belong to the selected reminder");
        }
        let mut fields = serde_json::Map::new();
        for (arg, field, range) in [
            ("frequency", "Frequency", 0i64..=3),
            ("interval", "Interval", 1..=i64::MAX),
            ("occurrence_count", "OccurrenceCount", 0..=i64::MAX),
            ("first_day_of_week", "FirstDayOfTheWeek", 0..=6),
        ] {
            if let Some(value) = patch.get(arg).and_then(Value::as_i64) {
                if !range.contains(&value) {
                    bail!("Invalid recurrence value for {arg}");
                }
                fields.insert(field.into(), json!({"type":"INT64","value":value}));
            }
        }
        if fields.is_empty() {
            bail!("No recurrence updates were provided");
        }
        let record =
            self.reminders_update_child(rule_id, "RecurrenceRule", "RecurrenceRule", fields)?;
        reminders_related_record_to_value(&record)
    }

    pub fn reminder_recurrence_delete(&mut self, id: &str, rule_id: &str) -> Result<Value> {
        self.reminders_require_access(&format!(
            "icli reminders recurrence list {}",
            crate::cli_quote(id)
        ))?;
        let (reminder, _) = self.reminder_related_records(
            id,
            "RecurrenceRuleIDs",
            "RecurrenceRule",
            "RecurrenceRule",
        )?;
        self.reminders_delete_child(
            &reminder,
            rule_id,
            "RecurrenceRule",
            "RecurrenceRule",
            "RecurrenceRuleIDs",
            "recurrenceRuleIDs",
        )
    }
}

fn cloudkit_field_value<'a>(fields: Option<&'a Value>, name: &str) -> Option<&'a Value> {
    fields?.get(name)?.get("value")
}

fn reminders_now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

fn reminders_record_name(id: &str, prefix: &str) -> String {
    if id.starts_with(&format!("{prefix}/")) {
        id.to_string()
    } else {
        format!("{prefix}/{id}")
    }
}

fn reminders_reference(fields: Option<&Value>, name: &str) -> Option<String> {
    fields?
        .get(name)?
        .get("value")?
        .get("recordName")?
        .as_str()
        .map(str::to_owned)
}

fn reminders_linked_ids(fields: Option<&Value>, name: &str, prefix: &str) -> Vec<String> {
    cloudkit_field_value(fields, name)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|id| reminders_record_name(id, prefix))
        .collect()
}

fn reminders_record_to_value(record: &Value) -> Result<Value> {
    let fields = record.get("fields");
    let typ = record
        .get("recordType")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if typ != "Reminder" {
        bail!("Apple returned a non-reminder record where a reminder was expected");
    }
    let id = record.get("recordName").cloned().unwrap_or(Value::Null);
    Ok(json!({
        "id":id,
        "title":cloudkit_text_field(fields,"TitleDocument")?,
        "notes":cloudkit_text_field(fields,"NotesDocument")?,
        "list_id":reminders_reference(fields,"List"),
        "parent_id":reminders_reference(fields,"ParentReminder"),
        "completed":cloudkit_field_truthy(fields,"Completed"),
        "completed_date":cloudkit_due_date(cloudkit_field_value(fields,"CompletionDate")),
        "due":cloudkit_due_date(cloudkit_field_value(fields,"DueDate")),
        "all_day":cloudkit_field_truthy(fields,"AllDay"),
        "priority":cloudkit_field_value(fields,"Priority").cloned().unwrap_or(json!(0)),
        "flagged":cloudkit_field_truthy(fields,"Flagged"),
        "deleted":cloudkit_field_truthy(fields,"Deleted"),
        "time_zone":cloudkit_field_value(fields,"TimeZone"),
        "alarm_ids":reminders_linked_ids(fields,"AlarmIDs","Alarm"),
        "hashtag_ids":reminders_linked_ids(fields,"HashtagIDs","Hashtag"),
        "attachment_ids":reminders_linked_ids(fields,"AttachmentIDs","Attachment"),
        "recurrence_rule_ids":reminders_linked_ids(fields,"RecurrenceRuleIDs","RecurrenceRule"),
        "created":cloudkit_due_date(cloudkit_field_value(fields,"CreationDate")),
        "modified":cloudkit_due_date(cloudkit_field_value(fields,"LastModifiedDate")),
        "record_change_tag":record.get("recordChangeTag")
    }))
}

fn reminder_list_to_value(record: &Value) -> Value {
    let fields = record.get("fields");
    json!({
        "id":record.get("recordName"),
        "name":cloudkit_field_value(fields,"Name").and_then(Value::as_str).unwrap_or("Untitled"),
        "count":cloudkit_field_value(fields,"Count").and_then(Value::as_u64).unwrap_or(0),
        "color":cloudkit_field_value(fields,"Color"),
        "deleted":cloudkit_field_truthy(fields,"Deleted"),
        "record_change_tag":record.get("recordChangeTag")
    })
}

fn reminders_related_record_to_value(record: &Value) -> Result<Value> {
    let typ = record
        .get("recordType")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let fields = record.get("fields");
    let id = record.get("recordName");
    let tag = record.get("recordChangeTag");
    match typ {
        "Reminder" => reminders_record_to_value(record),
        "Alarm" => Ok(
            json!({"id":id,"uid":cloudkit_field_value(fields,"AlarmUID"),"reminder_id":reminders_reference(fields,"Reminder"),"trigger_id":cloudkit_field_value(fields,"TriggerID"),"deleted":cloudkit_field_truthy(fields,"Deleted"),"record_change_tag":tag}),
        ),
        "AlarmTrigger" => Ok(
            json!({"id":id,"alarm_id":reminders_reference(fields,"Alarm"),"type":cloudkit_field_value(fields,"Type"),"title":cloudkit_field_value(fields,"Title"),"address":cloudkit_field_value(fields,"Address"),"latitude":cloudkit_field_value(fields,"Latitude"),"longitude":cloudkit_field_value(fields,"Longitude"),"radius":cloudkit_field_value(fields,"Radius"),"proximity":cloudkit_field_value(fields,"Proximity"),"record_change_tag":tag}),
        ),
        "Attachment" => Ok(
            json!({"id":id,"reminder_id":reminders_reference(fields,"Reminder"),"type":cloudkit_field_value(fields,"Type"),"url":cloudkit_field_value(fields,"URL"),"uti":cloudkit_field_value(fields,"UTI"),"filename":cloudkit_field_value(fields,"FileName"),"file_size":cloudkit_field_value(fields,"FileSize"),"deleted":cloudkit_field_truthy(fields,"Deleted"),"record_change_tag":tag}),
        ),
        "Hashtag" => Ok(
            json!({"id":id,"reminder_id":reminders_reference(fields,"Reminder"),"name":cloudkit_field_value(fields,"Name"),"deleted":cloudkit_field_truthy(fields,"Deleted"),"record_change_tag":tag}),
        ),
        "RecurrenceRule" => Ok(
            json!({"id":id,"reminder_id":reminders_reference(fields,"Reminder"),"frequency":cloudkit_field_value(fields,"Frequency"),"interval":cloudkit_field_value(fields,"Interval"),"occurrence_count":cloudkit_field_value(fields,"OccurrenceCount"),"first_day_of_week":cloudkit_field_value(fields,"FirstDayOfTheWeek"),"deleted":cloudkit_field_truthy(fields,"Deleted"),"record_change_tag":tag}),
        ),
        _ => bail!("Unsupported Reminders record type: {typ}"),
    }
}

fn protobuf_put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn protobuf_put_bytes(out: &mut Vec<u8>, field: u32, bytes: &[u8]) {
    protobuf_put_varint(out, u64::from((field << 3) | 2));
    protobuf_put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn protobuf_put_uint(out: &mut Vec<u8>, field: u32, value: u64) {
    protobuf_put_varint(out, u64::from(field << 3));
    protobuf_put_varint(out, value);
}

fn encode_reminders_text_document(text: &str) -> Result<String> {
    let utf16_len = text.encode_utf16().count() as u64;
    let mut topotext = Vec::new();
    protobuf_put_bytes(&mut topotext, 2, text.as_bytes());

    let mut sentinel_char = Vec::new();
    protobuf_put_uint(&mut sentinel_char, 1, 0);
    protobuf_put_uint(&mut sentinel_char, 2, 0);
    let mut sentinel_timestamp = Vec::new();
    protobuf_put_uint(&mut sentinel_timestamp, 1, 0);
    protobuf_put_uint(&mut sentinel_timestamp, 2, 0);
    let mut sentinel = Vec::new();
    protobuf_put_bytes(&mut sentinel, 1, &sentinel_char);
    protobuf_put_uint(&mut sentinel, 2, 0);
    protobuf_put_bytes(&mut sentinel, 3, &sentinel_timestamp);
    protobuf_put_uint(&mut sentinel, 5, 1);
    protobuf_put_bytes(&mut topotext, 3, &sentinel);

    if utf16_len > 0 {
        let mut content_char = Vec::new();
        protobuf_put_uint(&mut content_char, 1, 1);
        protobuf_put_uint(&mut content_char, 2, 0);
        let mut content_timestamp = Vec::new();
        protobuf_put_uint(&mut content_timestamp, 1, 1);
        protobuf_put_uint(&mut content_timestamp, 2, 0);
        let mut content = Vec::new();
        protobuf_put_bytes(&mut content, 1, &content_char);
        protobuf_put_uint(&mut content, 2, utf16_len);
        protobuf_put_bytes(&mut content, 3, &content_timestamp);
        protobuf_put_uint(&mut content, 5, 2);
        protobuf_put_bytes(&mut topotext, 3, &content);
    }

    let mut terminal_char = Vec::new();
    protobuf_put_uint(&mut terminal_char, 1, 0);
    protobuf_put_uint(&mut terminal_char, 2, u64::from(u32::MAX));
    let mut terminal_timestamp = Vec::new();
    protobuf_put_uint(&mut terminal_timestamp, 1, 0);
    protobuf_put_uint(&mut terminal_timestamp, 2, u64::from(u32::MAX));
    let mut terminal = Vec::new();
    protobuf_put_bytes(&mut terminal, 1, &terminal_char);
    protobuf_put_uint(&mut terminal, 2, 0);
    protobuf_put_bytes(&mut terminal, 3, &terminal_timestamp);
    protobuf_put_bytes(&mut topotext, 3, &terminal);

    let mut clock = Vec::new();
    protobuf_put_bytes(
        &mut clock,
        1,
        &[
            0xd4, 0x6b, 0xca, 0xe4, 0x1b, 0x87, 0x66, 0xc1, 0x8d, 0x75, 0xef, 0xe3, 0x5c, 0x91,
            0x45, 0xc3,
        ],
    );
    let mut content_clock = Vec::new();
    protobuf_put_uint(&mut content_clock, 1, utf16_len);
    protobuf_put_bytes(&mut clock, 2, &content_clock);
    let mut sentinel_clock = Vec::new();
    protobuf_put_uint(&mut sentinel_clock, 1, 1);
    protobuf_put_bytes(&mut clock, 2, &sentinel_clock);
    let mut vector = Vec::new();
    protobuf_put_bytes(&mut vector, 1, &clock);
    protobuf_put_bytes(&mut topotext, 4, &vector);
    if utf16_len > 0 {
        let mut attribute = Vec::new();
        protobuf_put_uint(&mut attribute, 1, utf16_len);
        protobuf_put_bytes(&mut topotext, 5, &attribute);
    }

    let mut version = Vec::new();
    protobuf_put_uint(&mut version, 1, 0);
    protobuf_put_uint(&mut version, 2, 0);
    protobuf_put_bytes(&mut version, 3, &topotext);
    let mut document = Vec::new();
    protobuf_put_uint(&mut document, 1, 0);
    protobuf_put_bytes(&mut document, 2, &version);

    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(&document)
        .context("Could not compress Reminders text")?;
    Ok(STANDARD.encode(
        encoder
            .finish()
            .context("Could not finish Reminders compression")?,
    ))
}

#[derive(Clone)]
struct ProtoWireField {
    number: u32,
    wire: u8,
    value: Vec<u8>,
}

fn protobuf_parse_message(bytes: &[u8]) -> Result<Vec<ProtoWireField>> {
    let mut fields = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let key = protobuf_varint(bytes, &mut offset)?;
        let number = u32::try_from(key >> 3).context("Invalid protobuf field number")?;
        let wire = (key & 7) as u8;
        if number == 0 {
            bail!("Invalid protobuf field number");
        }
        let value = match wire {
            0 => {
                let start = offset;
                protobuf_varint(bytes, &mut offset)?;
                bytes[start..offset].to_vec()
            }
            1 => {
                let end = offset
                    .checked_add(8)
                    .filter(|end| *end <= bytes.len())
                    .context("Invalid protobuf fixed64")?;
                let value = bytes[offset..end].to_vec();
                offset = end;
                value
            }
            2 => {
                let len = usize::try_from(protobuf_varint(bytes, &mut offset)?)
                    .context("Invalid protobuf length")?;
                let end = offset
                    .checked_add(len)
                    .filter(|end| *end <= bytes.len())
                    .context("Invalid protobuf length")?;
                let value = bytes[offset..end].to_vec();
                offset = end;
                value
            }
            5 => {
                let end = offset
                    .checked_add(4)
                    .filter(|end| *end <= bytes.len())
                    .context("Invalid protobuf fixed32")?;
                let value = bytes[offset..end].to_vec();
                offset = end;
                value
            }
            _ => bail!("Unsupported protobuf wire type {wire}"),
        };
        fields.push(ProtoWireField {
            number,
            wire,
            value,
        });
    }
    Ok(fields)
}

fn protobuf_encode_message(fields: &[ProtoWireField]) -> Vec<u8> {
    let mut out = Vec::new();
    for field in fields {
        protobuf_put_varint(
            &mut out,
            u64::from((field.number << 3) | u32::from(field.wire)),
        );
        match field.wire {
            0 => out.extend_from_slice(&field.value),
            1 | 5 => out.extend_from_slice(&field.value),
            2 => {
                protobuf_put_varint(&mut out, field.value.len() as u64);
                out.extend_from_slice(&field.value);
            }
            _ => {}
        }
    }
    out
}

fn protobuf_field_varint(fields: &[ProtoWireField], number: u32) -> Option<u64> {
    let field = fields
        .iter()
        .rev()
        .find(|field| field.number == number && field.wire == 0)?;
    let mut offset = 0;
    protobuf_varint(&field.value, &mut offset).ok()
}

fn protobuf_field_bytes(fields: &[ProtoWireField], number: u32) -> Option<&[u8]> {
    fields
        .iter()
        .rev()
        .find(|field| field.number == number && field.wire == 2)
        .map(|field| field.value.as_slice())
}

fn protobuf_set_varint(fields: &mut Vec<ProtoWireField>, number: u32, value: u64) {
    fields.retain(|field| field.number != number);
    let mut encoded = Vec::new();
    protobuf_put_varint(&mut encoded, value);
    fields.push(ProtoWireField {
        number,
        wire: 0,
        value: encoded,
    });
}

fn protobuf_set_bytes(fields: &mut Vec<ProtoWireField>, number: u32, value: Vec<u8>) {
    fields.retain(|field| field.number != number);
    fields.push(ProtoWireField {
        number,
        wire: 2,
        value,
    });
}

fn protobuf_message_put_bytes(fields: &mut Vec<ProtoWireField>, number: u32, value: Vec<u8>) {
    fields.push(ProtoWireField {
        number,
        wire: 2,
        value,
    });
}
fn protobuf_message_put_varint(fields: &mut Vec<ProtoWireField>, number: u32, value: u64) {
    let mut encoded = Vec::new();
    protobuf_put_varint(&mut encoded, value);
    fields.push(ProtoWireField {
        number,
        wire: 0,
        value: encoded,
    });
}

fn decode_reminders_topotext(encoded: &str) -> Result<Vec<u8>> {
    let mut padded = encoded.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    let bytes = STANDARD
        .decode(padded)
        .context("Invalid base64 Reminders text document")?;
    let document = decompress_crdt_document(&bytes);
    for (number, version) in protobuf_length_fields(&document)? {
        if number != 2 {
            continue;
        }
        for (version_field, topotext) in protobuf_length_fields(version)? {
            if version_field == 3 {
                return Ok(topotext.to_vec());
            }
        }
    }
    bail!("Stored Reminders text has no versioned topotext payload")
}

fn remap_reminders_char_id(
    bytes: &[u8],
    remap: &std::collections::BTreeMap<u64, u64>,
) -> Result<Vec<u8>> {
    let mut fields = protobuf_parse_message(bytes)?;
    if let Some(old) = protobuf_field_varint(&fields, 1).filter(|id| *id > 0)
        && let Some(new) = remap.get(&old)
    {
        protobuf_set_varint(&mut fields, 1, *new);
    }
    Ok(protobuf_encode_message(&fields))
}

fn encode_reminders_text_edit(existing: &str, text: &str) -> Result<String> {
    let mut topotext = protobuf_parse_message(&decode_reminders_topotext(existing)?)?;
    let vector_bytes = protobuf_field_bytes(&topotext, 4)
        .context("Stored Reminders text has no vector timestamp")?
        .to_vec();
    let mut vector = protobuf_parse_message(&vector_bytes)?;
    let mut clocks = vector
        .iter()
        .filter(|field| field.number == 1 && field.wire == 2)
        .map(|field| protobuf_parse_message(&field.value))
        .collect::<Result<Vec<_>>>()?;
    if clocks.is_empty() {
        bail!("Stored Reminders text has no replica clocks");
    }
    let mut uuids = clocks
        .iter()
        .map(|clock| {
            protobuf_field_bytes(clock, 1)
                .map(ToOwned::to_owned)
                .context("Stored Reminders replica has no UUID")
        })
        .collect::<Result<Vec<_>>>()?;
    let new_uuid = Uuid::new_v4().as_bytes().to_vec();
    if uuids.iter().any(|uuid| uuid == &new_uuid) {
        bail!("Generated a duplicate Reminders replica UUID");
    }
    let original_uuids = uuids.clone();
    uuids.push(new_uuid.clone());
    uuids.sort();
    let remap = original_uuids
        .iter()
        .enumerate()
        .map(|(index, uuid)| {
            Ok((
                (index + 1) as u64,
                (uuids
                    .iter()
                    .position(|candidate| candidate == uuid)
                    .context("Missing Reminders replica UUID")?
                    + 1) as u64,
            ))
        })
        .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
    let new_replica = (uuids
        .iter()
        .position(|uuid| uuid == &new_uuid)
        .context("Missing new Reminders replica")?
        + 1) as u64;
    let mut next_clock = 0u64;
    for clock in &clocks {
        for encoded in clock
            .iter()
            .filter(|field| field.number == 2 && field.wire == 2)
        {
            let replica_clock = protobuf_parse_message(&encoded.value)?;
            next_clock = next_clock.max(protobuf_field_varint(&replica_clock, 1).unwrap_or(0));
        }
    }

    let mut substrings = topotext
        .iter()
        .filter(|field| field.number == 3 && field.wire == 2)
        .map(|field| protobuf_parse_message(&field.value))
        .collect::<Result<Vec<_>>>()?;
    if substrings.is_empty() {
        bail!("Stored Reminders text has no CRDT substrings");
    }
    let mut sentinel_index = None;
    let mut sentinel_children = Vec::new();
    let mut deleted_visible = false;
    for (index, substring) in substrings.iter_mut().enumerate() {
        let char_bytes = protobuf_field_bytes(substring, 1)
            .context("Stored Reminders substring has no character ID")?;
        let char_id = protobuf_parse_message(char_bytes)?;
        let original_replica = protobuf_field_varint(&char_id, 1).unwrap_or(0);
        let original_clock = protobuf_field_varint(&char_id, 2).unwrap_or(0);
        if original_replica == 0 && original_clock == 0 {
            sentinel_index = Some(index);
            sentinel_children = substring
                .iter()
                .filter(|field| field.number == 5 && field.wire == 0)
                .map(|field| {
                    let mut offset = 0;
                    protobuf_varint(&field.value, &mut offset)
                })
                .collect::<Result<Vec<_>>>()?;
        }
        let remapped = remap_reminders_char_id(char_bytes, &remap)?;
        protobuf_set_bytes(substring, 1, remapped);
        if let Some(timestamp) = protobuf_field_bytes(substring, 3).map(ToOwned::to_owned) {
            protobuf_set_bytes(substring, 3, remap_reminders_char_id(&timestamp, &remap)?);
        }
        let length = protobuf_field_varint(substring, 2).unwrap_or(0);
        let tombstone = protobuf_field_varint(substring, 4).unwrap_or(0) != 0;
        if !(original_replica == 0 && original_clock == 0) && !tombstone && length > 0 {
            protobuf_set_varint(substring, 4, 1);
            let mut timestamp = Vec::new();
            protobuf_put_uint(&mut timestamp, 1, new_replica);
            protobuf_put_uint(&mut timestamp, 2, 1);
            protobuf_set_bytes(substring, 3, timestamp);
            deleted_visible = true;
        }
    }
    let sentinel_index = sentinel_index.context("Stored Reminders text has no start sentinel")?;
    let text_len = text.encode_utf16().count() as u64;
    let mut style_clock = 0;
    if text_len > 0 {
        let mut content = Vec::new();
        let mut char_id = Vec::new();
        protobuf_put_uint(&mut char_id, 1, new_replica);
        protobuf_put_uint(&mut char_id, 2, next_clock);
        protobuf_put_bytes(&mut content, 1, &char_id);
        protobuf_put_uint(&mut content, 2, text_len);
        let mut timestamp = Vec::new();
        protobuf_put_uint(&mut timestamp, 1, new_replica);
        protobuf_put_uint(&mut timestamp, 2, 0);
        protobuf_put_bytes(&mut content, 3, &timestamp);
        for child in &sentinel_children {
            protobuf_put_uint(&mut content, 5, *child);
        }
        style_clock = 1;
        let child_index = (substrings.len() + 1) as u64;
        let mut sentinel = substrings[sentinel_index].clone();
        sentinel.retain(|field| field.number != 5);
        protobuf_message_put_varint(&mut sentinel, 5, child_index);
        substrings[sentinel_index] = sentinel;
        substrings.push(protobuf_parse_message(&content)?);
    }
    if deleted_visible {
        style_clock = 2;
    }

    let mut new_clock = Vec::new();
    protobuf_put_bytes(&mut new_clock, 1, &new_uuid);
    let mut content_clock = Vec::new();
    protobuf_put_uint(&mut content_clock, 1, next_clock + text_len);
    protobuf_put_bytes(&mut new_clock, 2, &content_clock);
    let mut style = Vec::new();
    protobuf_put_uint(&mut style, 1, style_clock);
    protobuf_put_bytes(&mut new_clock, 2, &style);
    let mut indexed = clocks
        .drain(..)
        .zip(original_uuids.iter().cloned())
        .collect::<Vec<_>>();
    indexed.sort_by(|a, b| a.1.cmp(&b.1));
    vector.retain(|field| field.number != 1);
    for (clock, _) in indexed {
        protobuf_message_put_bytes(&mut vector, 1, protobuf_encode_message(&clock));
    }
    protobuf_message_put_bytes(
        &mut vector,
        1,
        protobuf_encode_message(&protobuf_parse_message(&new_clock)?),
    );
    topotext.retain(|field| !matches!(field.number, 2..=5));
    protobuf_message_put_bytes(&mut topotext, 2, text.as_bytes().to_vec());
    for substring in substrings {
        protobuf_message_put_bytes(&mut topotext, 3, protobuf_encode_message(&substring));
    }
    protobuf_message_put_bytes(&mut topotext, 4, protobuf_encode_message(&vector));
    if text_len > 0 {
        let mut run = Vec::new();
        protobuf_put_uint(&mut run, 1, text_len);
        protobuf_message_put_bytes(&mut topotext, 5, run);
    }
    let mut version = Vec::new();
    protobuf_put_uint(&mut version, 1, 0);
    protobuf_put_uint(&mut version, 2, 0);
    protobuf_put_bytes(&mut version, 3, &protobuf_encode_message(&topotext));
    let mut document = Vec::new();
    protobuf_put_uint(&mut document, 1, 0);
    protobuf_put_bytes(&mut document, 2, &version);
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(&document)
        .context("Could not compress edited Reminders text")?;
    Ok(STANDARD.encode(
        encoder
            .finish()
            .context("Could not finish edited Reminders compression")?,
    ))
}

fn edit_reminders_text_document(existing: Option<&Value>, text: &str) -> Result<String> {
    let Some(field) = existing else {
        return encode_reminders_text_document(text);
    };
    let value = field
        .get("value")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if field.get("type").and_then(Value::as_str) == Some("STRING")
        && field.get("isEncrypted").and_then(Value::as_bool) != Some(true)
    {
        return encode_reminders_text_document(text);
    }
    encode_reminders_text_edit(value, text)
}

fn reminders_resolution_tokens(fields: &[&str]) -> Result<String> {
    let now_apple = Utc::now().timestamp_millis() as f64 / 1000.0 - 978_307_200.0;
    let mut tokens = serde_json::Map::new();
    for field in fields {
        tokens.insert((*field).to_string(), json!({"counter":1,"modificationTime":now_apple,"replicaID":Uuid::new_v4().simple().to_string().to_uppercase()}));
    }
    serde_json::to_string(&json!({"map":tokens}))
        .context("Could not encode Reminders conflict tokens")
}

fn reminders_merge_tokens(existing: Option<&str>, fields: &[&str]) -> Result<String> {
    let mut map = existing
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .and_then(|v| v.get("map").cloned())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    let now_apple = Utc::now().timestamp_millis() as f64 / 1000.0 - 978_307_200.0;
    let replica = Uuid::new_v4().simple().to_string().to_uppercase();
    for field in fields {
        let counter = map
            .get(*field)
            .and_then(|v| v.get("counter"))
            .and_then(Value::as_u64)
            .unwrap_or(0)
            + 1;
        map.insert(
            (*field).to_string(),
            json!({"counter":counter,"modificationTime":now_apple,"replicaID":replica}),
        );
    }
    serde_json::to_string(&json!({"map":map})).context("Could not update Reminders conflict tokens")
}

fn cloudkit_field_truthy(fields: Option<&Value>, name: &str) -> bool {
    let value = cloudkit_field_value(fields, name);
    value.is_some_and(|value| {
        value.as_bool().unwrap_or_else(|| {
            value
                .as_i64()
                .map(|number| number != 0)
                .or_else(|| value.as_u64().map(|number| number != 0))
                .or_else(|| value.as_str().map(|text| text.eq_ignore_ascii_case("true")))
                .unwrap_or(false)
        })
    })
}

fn cloudkit_due_date(value: Option<&Value>) -> Value {
    let Some(value) = value else {
        return Value::Null;
    };
    let millis = value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|n| i64::try_from(n).ok()));
    millis
        .and_then(DateTime::<Utc>::from_timestamp_millis)
        .map(|date| json!(date.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)))
        .unwrap_or(Value::Null)
}

fn cloudkit_text_field(fields: Option<&Value>, name: &str) -> Result<String> {
    let Some(field) = fields.and_then(|fields| fields.get(name)) else {
        return Ok(String::new());
    };
    let value = field
        .get("value")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match field.get("type").and_then(Value::as_str) {
        Some("STRING") if field.get("isEncrypted").and_then(Value::as_bool) != Some(true) => {
            let mut encoded = value.to_string();
            while encoded.len() % 4 != 0 {
                encoded.push('=');
            }
            if let Ok(bytes) = STANDARD.decode(encoded) {
                let document = decompress_crdt_document(&bytes);
                if let Ok(text) = decode_crdt_document_text(&document) {
                    return Ok(text);
                }
            }
            Ok(value.to_string())
        }
        Some("STRING" | "ENCRYPTED_BYTES") => {
            let mut encoded = value.to_string();
            while encoded.len() % 4 != 0 {
                encoded.push('=');
            }
            let bytes = STANDARD
                .decode(encoded)
                .context("Apple returned an invalid encoded Reminders title")?;
            let document = decompress_crdt_document(&bytes);
            decode_crdt_document_text(&document)
                .context("Apple returned a Reminders title iCLI could not decode")
        }
        _ => bail!("Apple returned an unsupported Reminders title field"),
    }
}

fn cloudkit_encoded_text(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return String::new();
    };
    let Some(encoded) = value.as_str() else {
        return value.to_string();
    };
    let mut padded = encoded.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    if let Ok(bytes) = STANDARD.decode(padded) {
        if let Ok(text) = String::from_utf8(bytes) {
            return text;
        }
    }
    encoded.to_string()
}

fn cloudkit_attachment_url(value: Option<&Value>) -> Value {
    let Some(value) = value.and_then(Value::as_str) else {
        return Value::Null;
    };
    if value.starts_with("http://") || value.starts_with("https://") {
        return json!(value);
    }
    let mut padded = value.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    STANDARD
        .decode(padded)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .filter(|text| text.starts_with("http://") || text.starts_with("https://"))
        .map_or_else(|| json!(value), |text| json!(text))
}

fn decompress_crdt_document(bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut zlib = flate2::read::ZlibDecoder::new(bytes);
    if zlib.read_to_end(&mut output).is_ok() && !output.is_empty() {
        return output;
    }
    output.clear();
    let mut gzip = flate2::read::GzDecoder::new(bytes);
    if gzip.read_to_end(&mut output).is_ok() && !output.is_empty() {
        return output;
    }
    bytes.to_vec()
}

fn protobuf_varint(bytes: &[u8], offset: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *bytes.get(*offset).context("Invalid Reminders protobuf")?;
        *offset += 1;
        if shift == 63 && byte > 1 {
            bail!("Invalid Reminders protobuf varint");
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("Invalid Reminders protobuf varint")
}

fn protobuf_length_fields(bytes: &[u8]) -> Result<Vec<(u32, &[u8])>> {
    let mut fields = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let key = protobuf_varint(bytes, &mut offset)?;
        let field_number = u32::try_from(key >> 3).context("Invalid Reminders protobuf field")?;
        if field_number == 0 {
            bail!("Invalid Reminders protobuf field");
        }
        match key & 7 {
            0 => {
                protobuf_varint(bytes, &mut offset)?;
            }
            1 => {
                offset = offset
                    .checked_add(8)
                    .context("Invalid Reminders protobuf")?
            }
            2 => {
                let length = usize::try_from(protobuf_varint(bytes, &mut offset)?)
                    .context("Invalid Reminders protobuf length")?;
                let end = offset
                    .checked_add(length)
                    .filter(|end| *end <= bytes.len())
                    .context("Invalid Reminders protobuf length")?;
                fields.push((field_number, &bytes[offset..end]));
                offset = end;
            }
            5 => {
                offset = offset
                    .checked_add(4)
                    .context("Invalid Reminders protobuf")?
            }
            _ => bail!("Unsupported Reminders protobuf wire type"),
        }
        if offset > bytes.len() {
            bail!("Invalid Reminders protobuf length");
        }
    }
    Ok(fields)
}

fn protobuf_string(bytes: &[u8]) -> Result<String> {
    for (field, value) in protobuf_length_fields(bytes)? {
        if field == 2 {
            if let Ok(text) = std::str::from_utf8(value) {
                return Ok(text.to_string());
            }
        }
    }
    bail!("Reminders text document has no UTF-8 string")
}

fn decode_crdt_document_text(bytes: &[u8]) -> Result<String> {
    let fields = protobuf_length_fields(bytes)?;
    // VersionedDocument.Document stores Version messages in field 2; each
    // Version stores the topotext String bytes in field 3.
    for (field, version) in &fields {
        if *field != 2 {
            continue;
        }
        if let Ok(version_fields) = protobuf_length_fields(version) {
            for (version_field, text) in version_fields {
                if version_field == 3
                    && let Ok(decoded) = protobuf_string(text)
                {
                    return Ok(decoded);
                }
            }
        }
    }
    // Some server responses contain a bare Version or topotext String.
    for (field, text) in &fields {
        if *field == 3
            && let Ok(decoded) = protobuf_string(text)
        {
            return Ok(decoded);
        }
    }
    protobuf_string(bytes)
}

fn make_client(cookies_json: Option<&str>) -> Result<(HttpClient, Arc<CookieStoreMutex>)> {
    let store = if let Some(serialized) = cookies_json.filter(|v| !v.is_empty()) {
        cookie_store::serde::json::load(Cursor::new(serialized.as_bytes())).map_err(|error| {
            anyhow::anyhow!("Saved Apple session cookies could not be read: {error}")
        })?
    } else {
        CookieStore::new(None)
    };
    let cookies = Arc::new(CookieStoreMutex::new(store));
    let client = HttpClient::builder()
        .cookie_provider(cookies.clone())
        .user_agent(APPLE_USER_AGENT)
        // Match pyicloud's requests-based HTTP/1.1 transport. Some iCloud
        // edges reject requests routed over a coalesced HTTP/2 connection.
        .http1_only()
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .context("Could not create Apple sign-in client")?;
    Ok((client, cookies))
}

fn auth_headers(
    client_id: &str,
    previous: &std::collections::BTreeMap<String, String>,
) -> reqwest::header::HeaderMap {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    let mut headers = HeaderMap::new();
    let values = [
        ("accept", "application/json, text/javascript".to_string()),
        ("content-type", "application/json".to_string()),
        ("origin", "https://www.icloud.com".to_string()),
        ("referer", "https://idmsa.apple.com/".to_string()),
        ("x-apple-oauth-client-id", OAUTH_CLIENT_ID.to_string()),
        ("x-apple-oauth-client-type", "firstPartyAuth".to_string()),
        (
            "x-apple-oauth-redirect-uri",
            "https://www.icloud.com".to_string(),
        ),
        ("x-apple-oauth-require-grant-code", "true".to_string()),
        ("x-apple-oauth-response-mode", "web_message".to_string()),
        ("x-apple-oauth-response-type", "code".to_string()),
        ("x-apple-oauth-state", client_id.to_string()),
        ("x-apple-widget-key", OAUTH_CLIENT_ID.to_string()),
        ("x-apple-frame-id", client_id.to_string()),
        (
            "x-apple-fd-client-info",
            format!(r#"{{"U":"{APPLE_USER_AGENT}","L":"en-US","Z":"GMT+00:00","V":"1.1","F":""}}"#),
        ),
    ];
    for (name, value) in values {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            headers.insert(n, v);
        }
    }
    for name in ["scnt", "x-apple-id-session-id", "x-apple-auth-attributes"] {
        if let (Some(value), Ok(n)) = (previous.get(name), HeaderName::from_bytes(name.as_bytes()))
        {
            if let Ok(v) = HeaderValue::from_str(value) {
                headers.insert(n, v);
            }
        }
    }
    headers
}

fn update_headers(
    mut headers: reqwest::header::HeaderMap,
    response: &reqwest::blocking::Response,
) -> reqwest::header::HeaderMap {
    for name in [
        "x-apple-id-account-country",
        "x-apple-id-session-id",
        "x-apple-auth-attributes",
        "x-apple-session-token",
        "x-apple-twosv-trust-token",
        "scnt",
    ] {
        if let Some(v) = response.headers().get(name) {
            headers.insert(name, v.clone());
        }
    }
    headers
}

fn header_subset(
    headers: reqwest::header::HeaderMap,
) -> std::collections::BTreeMap<String, String> {
    [
        "x-apple-id-account-country",
        "x-apple-id-session-id",
        "x-apple-auth-attributes",
        "x-apple-session-token",
        "x-apple-twosv-trust-token",
        "scnt",
    ]
    .iter()
    .filter_map(|name| {
        headers
            .get(*name)
            .and_then(|v| v.to_str().ok())
            .map(|v| (name.to_string(), v.to_string()))
    })
    .collect()
}

fn stored_headers(
    values: &std::collections::BTreeMap<String, String>,
) -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in values {
        if let (Ok(name), Ok(value)) = (
            reqwest::header::HeaderName::from_bytes(name.as_bytes()),
            reqwest::header::HeaderValue::from_str(value),
        ) {
            headers.insert(name, value);
        }
    }
    headers
}

fn icloud_headers() -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in [
        ("origin", "https://www.icloud.com"),
        ("referer", "https://www.icloud.com/"),
        ("user-agent", APPLE_USER_AGENT),
        ("accept", "application/json"),
    ] {
        headers.insert(
            reqwest::header::HeaderName::from_static(name),
            reqwest::header::HeaderValue::from_static(value),
        );
    }
    headers
}

fn account_login(
    client: &HttpClient,
    headers: &reqwest::header::HeaderMap,
    setup: &str,
) -> Result<reqwest::blocking::Response> {
    let saved = header_subset(headers.clone());
    let token = saved
        .get("x-apple-session-token")
        .context("Apple did not return an account session token")?;
    let payload = json!({"accountCountryCode":saved.get("x-apple-id-account-country").map(String::as_str).unwrap_or("US"),"dsWebAuthToken":token,"extended_login":true,"trustToken":saved.get("x-apple-twosv-trust-token").map(String::as_str).unwrap_or("")});
    client
        .post(format!("{setup}/accountLogin"))
        .headers(icloud_headers())
        .json(&payload)
        // IDMSA OAuth headers and sign-in parameters do not belong on setup requests.
        .send()
        .context("Could not establish the iCloud account session")
}

fn setup_endpoint(data: &Value) -> String {
    if data
        .pointer("/dsInfo/countryCode")
        .and_then(Value::as_str)
        .is_some_and(|v| v.eq_ignore_ascii_case("CHN"))
    {
        "https://setup.icloud.com.cn/setup/ws/1".into()
    } else {
        SETUP_ROOT.into()
    }
}

fn trusted_phone_number(challenge: &Value) -> Option<&Value> {
    challenge
        .get("trustedPhoneNumber")
        .or_else(|| challenge.pointer("/phoneNumberVerification/trustedPhoneNumber"))
        .or_else(|| challenge.pointer("/phoneNumberVerification/trustedPhoneNumbers/0"))
        .or_else(|| challenge.pointer("/direct/twoSV/trustedPhoneNumber"))
        .or_else(|| challenge.pointer("/direct/twoSV/phoneNumberVerification/trustedPhoneNumber"))
        .or_else(|| {
            challenge.pointer("/direct/twoSV/phoneNumberVerification/trustedPhoneNumbers/0")
        })
        .or_else(|| {
            challenge.pointer(
                "/direct/twoSV/bridgeInitiateData/phoneNumberVerification/trustedPhoneNumber",
            )
        })
        .or_else(|| {
            challenge.pointer(
                "/direct/twoSV/bridgeInitiateData/phoneNumberVerification/trustedPhoneNumbers/0",
            )
        })
        .filter(|phone| phone.get("id").is_some())
}

fn phone_number_payload(phone: &Value) -> Value {
    let mut payload = serde_json::Map::new();
    if let Some(id) = phone.get("id") {
        payload.insert("id".into(), id.clone());
    }
    if let Some(non_fteu) = phone.get("nonFTEU") {
        payload.insert("nonFTEU".into(), non_fteu.clone());
    }
    Value::Object(payload)
}

fn service_params(session: &SavedAppleSession) -> Vec<(String, String)> {
    let mut params = vec![
        ("clientBuildNumber".into(), "2534Project66".into()),
        ("clientMasteringNumber".into(), "2534B22".into()),
        ("clientId".into(), session.client_id.clone()),
    ];
    if let Some(dsid) = session
        .account_data
        .pointer("/dsInfo/dsid")
        .and_then(Value::as_str)
    {
        params.push(("dsid".into(), dsid.to_string()));
    }
    params
}

fn error_hint(value: &Value) -> String {
    value
        .get("errorMessage")
        .or_else(|| value.get("message"))
        .and_then(Value::as_str)
        .map(|v| format!(": {v}"))
        .unwrap_or_default()
}

/// One in-flight Apple SRP exchange. The ephemeral value and verifier are
/// memory-only and must never be serialized or logged.
pub struct AppleSrpHandshake {
    account: String,
    ephemeral: EphemeralSecret,
    public_ephemeral: Vec<u8>,
    verifier: Option<ClientVerifier<SrpSha256>>,
}

impl AppleSrpHandshake {
    /// Start an SRP exchange and return Apple's `/signin/init` JSON payload.
    pub fn start(account: &str) -> Result<(Self, Value)> {
        if account.trim().is_empty() {
            bail!("Apple Account email cannot be empty");
        }
        let ephemeral = EphemeralSecret::generate();
        let client = Client::<G2048, SrpSha256>::new_with_options(false);
        let public_ephemeral = client.compute_public_ephemeral(&ephemeral);
        let payload = json!({
            "accountName": account,
            "a": STANDARD.encode(&public_ephemeral),
            "protocols": SUPPORTED_PROTOCOLS,
        });
        Ok((
            Self {
                account: account.to_string(),
                ephemeral,
                public_ephemeral,
                verifier: None,
            },
            payload,
        ))
    }

    /// Build Apple's `/signin/complete` body from the challenge returned by
    /// `/signin/init`. `password` is the real Apple Account password, not an
    /// app-specific password.
    pub fn complete(&mut self, password: &str, challenge: &Value) -> Result<Value> {
        let salt = decode_challenge(challenge, "salt")?;
        let server_ephemeral = decode_challenge(challenge, "b")?;
        let protocol = challenge["protocol"]
            .as_str()
            .context("Apple SRP response omitted protocol")?;
        let iterations = challenge["iteration"]
            .as_u64()
            .context("Apple SRP response omitted iteration count")?
            as usize;
        if !(1..=10_000_000).contains(&iterations) {
            bail!("Apple SRP iteration count is outside the accepted range");
        }
        let challenge_id = challenge["c"]
            .as_str()
            .context("Apple SRP response omitted challenge id")?;
        let derived_password =
            zeroize::Zeroizing::new(derive_password(password, &salt, iterations, protocol)?);
        let client = Client::<G2048, SrpSha256>::new_with_options(false);
        let verifier = client
            .process_reply(
                &self.ephemeral,
                self.account.as_bytes(),
                &derived_password[..],
                &salt,
                &server_ephemeral,
            )
            .context("Apple SRP challenge could not be verified")?;
        let session_key = SrpSha256::digest(verifier.key());
        let server_proof = compute_m2::<SrpSha256>(
            &self.public_ephemeral,
            &proof_output(verifier.proof()),
            &session_key,
        );
        let client_proof = verifier.proof().to_vec();
        self.verifier = Some(verifier);
        Ok(json!({
            "accountName": self.account,
            "c": challenge_id,
            "m1": STANDARD.encode(client_proof),
            "m2": STANDARD.encode(server_proof),
            "rememberMe": true,
            "trustTokens": [],
        }))
    }

    /// Confirm the server's SRP proof before trusting the resulting session.
    pub fn verify_server(&self, encoded_proof: &str) -> Result<()> {
        let proof = STANDARD
            .decode(encoded_proof)
            .context("Invalid Apple SRP proof encoding")?;
        self.verifier
            .as_ref()
            .context("Apple SRP exchange has not been completed")?
            .verify_server(&proof)
            .context("Apple server SRP proof did not match")?;
        Ok(())
    }
}

fn proof_output(bytes: &[u8]) -> srp_sha2::digest::Output<SrpSha256> {
    let mut output = srp_sha2::digest::Output::<SrpSha256>::default();
    output.copy_from_slice(bytes);
    output
}

fn decode_challenge(challenge: &Value, name: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(
            challenge[name]
                .as_str()
                .with_context(|| format!("Apple SRP response omitted {name}"))?,
        )
        .with_context(|| format!("Apple SRP response contained invalid {name}"))
}

fn derive_password(
    password: &str,
    salt: &[u8],
    iterations: usize,
    protocol: &str,
) -> Result<[u8; 32]> {
    let password_hash = Sha256::digest(password.as_bytes());
    let password_material = match protocol {
        "s2k" => password_hash.to_vec(),
        "s2k_fo" => format!("{password_hash:x}").into_bytes(),
        other => bail!("Apple selected an unsupported SRP password protocol: {other}"),
    };
    let mut output = [0u8; 32];
    pbkdf2_hmac::<Sha256>(&password_material, salt, iterations as u32, &mut output);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::BTreeMap,
        io::{BufRead, BufReader, Read, Write},
        net::TcpListener,
        thread,
        time::Instant,
    };

    struct Reply {
        method: &'static str,
        path: &'static str,
        status: u16,
        body: Value,
        headers: Vec<(&'static str, &'static str)>,
    }
    fn reply(method: &'static str, path: &'static str, status: u16, body: Value) -> Reply {
        Reply {
            method,
            path,
            status,
            body,
            headers: vec![],
        }
    }
    struct Captured {
        target: String,
        headers: BTreeMap<String, String>,
        body: Value,
    }
    fn server(replies: Vec<Reply>) -> (String, thread::JoinHandle<Vec<Captured>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let mut captured = Vec::new();
            for reply in replies {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            thread::sleep(Duration::from_millis(5))
                        }
                        Err(error) => panic!(
                            "Mock Apple service did not receive {} {}: {error}",
                            reply.method, reply.path
                        ),
                    }
                };
                // On Windows accepted sockets inherit the listener's
                // nonblocking mode; reads must wait for the complete request.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let request_line = line.split_whitespace().collect::<Vec<_>>();
                assert_eq!(request_line[0], reply.method);
                let target = request_line[1].to_string();
                assert_eq!(
                    request_line[1].split('?').next().unwrap(),
                    if reply.path.is_empty() {
                        "/"
                    } else {
                        reply.path
                    }
                );
                let mut headers = BTreeMap::new();
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    let (name, value) = line.split_once(':').unwrap();
                    headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
                }
                let length = headers
                    .get("content-length")
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0);
                let mut bytes = vec![0; length];
                reader.read_exact(&mut bytes).unwrap();
                captured.push(Captured {
                    target,
                    headers,
                    body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
                });
                let body = serde_json::to_string(&reply.body).unwrap();
                write!(stream, "HTTP/1.1 {} Mock\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n", reply.status, body.len()).unwrap();
                for (name, value) in reply.headers {
                    write!(stream, "{name}: {value}\r\n").unwrap();
                }
                write!(stream, "\r\n{body}").unwrap();
            }
            captured
        });
        (base, handle)
    }
    fn endpoints(base: &str) -> AuthEndpoints {
        AuthEndpoints {
            auth: base.into(),
            setup_override: Some(base.into()),
        }
    }
    fn restored(session: SavedAppleSession, base: &str) -> AppleConnection {
        let mut connection = AppleConnection::restore(session).unwrap();
        connection.endpoints = endpoints(base);
        connection
    }
    fn cloudkit_connection(base: &str) -> AppleConnection {
        restored(
            SavedAppleSession {
                account: "synthetic@example.invalid".into(),
                client_id: "test-client".into(),
                account_data: json!({"dsInfo":{"dsid":"synthetic-dsid"},"webservices":{"ckdatabasews":{"url":base}}}),
                session_headers: BTreeMap::new(),
                cookies_json: "[]".into(),
                reminders_pcs_ready: true,
                pending: None,
            },
            base,
        )
    }
    fn pending(base: &str) -> AppleConnection {
        restored(
            SavedAppleSession {
                account: "synthetic@example.invalid".into(),
                client_id: "test-client".into(),
                account_data: Value::Null,
                session_headers: BTreeMap::from([(
                    "x-apple-session-token".into(),
                    "initial-token".into(),
                )]),
                cookies_json: "[]".into(),
                reminders_pcs_ready: false,
                pending: Some(PendingChallenge {
                    method: VerificationMethod::Device,
                    phone: Some(json!({"id":1})),
                    code_accepted: false,
                }),
            },
            base,
        )
    }
    fn round_trip(connection: AppleConnection, base: &str) -> AppleConnection {
        let serialized = serde_json::to_string(&connection.session).unwrap();
        restored(serde_json::from_str(&serialized).unwrap(), base)
    }
    fn session_reply() -> Value {
        json!({"hsaTrustedBrowser":true,"hsaChallengeRequired":false,"webservices":{},"dsInfo":{"dsid":"synthetic"}})
    }

    #[test]
    fn sign_in_exits_pending_and_verification_resumes_with_session_cookies() {
        let mut authorize = reply("GET", "/authorize/signin", 200, json!({}));
        authorize.headers = vec![
            ("set-cookie", "challenge=synthetic; Path=/; HttpOnly"),
            ("scnt", "authorize-header"),
        ];
        let mut complete = reply(
            "POST",
            "/signin/complete",
            409,
            json!({"hsaChallengeRequired":true}),
        );
        complete.headers = vec![
            ("x-apple-session-token", "initial-token"),
            ("x-apple-id-session-id", "synthetic-session"),
        ];
        let mut push = reply("PUT", "/verify/trusteddevice/securitycode", 200, json!({}));
        push.headers = vec![("scnt", "push-header")];
        let mut verified = reply("POST", "/verify/trusteddevice/securitycode", 200, json!({}));
        verified.headers = vec![("x-apple-session-token", "verified-token")];
        let mut trust = reply("GET", "/2sv/trust", 200, json!({}));
        trust.headers = vec![("x-apple-twosv-trust-token", "trusted-token")];
        let (base, server) = server(vec![
            authorize,
            reply(
                "POST",
                "/signin/init",
                200,
                json!({"salt":STANDARD.encode(b"synthetic-salt"),"b":STANDARD.encode([2]),"iteration":1,"protocol":"s2k","c":"test-challenge"}),
            ),
            complete,
            reply(
                "GET",
                "",
                200,
                json!({"hsaChallengeRequired":true,"trustedPhoneNumber":{"id":1}}),
            ),
            push,
            verified,
            trust,
            reply("POST", "/accountLogin", 200, session_reply()),
        ]);
        let connection = AppleConnection::begin_login_with_endpoints(
            "synthetic@example.invalid",
            "synthetic-password",
            endpoints(&base),
        )
        .unwrap();
        assert_eq!(connection.auth_state(), "verification_required");
        assert!(connection.session.cookies_json.contains("challenge"));
        let persisted = serde_json::to_string(&connection.session).unwrap();
        assert!(!persisted.contains("synthetic-password"));
        let mut resumed = round_trip(connection, &base);
        resumed.verify_code("012345").unwrap();
        assert_eq!(resumed.auth_state(), "authenticated");
        assert!(
            !serde_json::to_string(&resumed.session)
                .unwrap()
                .contains("012345")
        );
        let requests = server.join().unwrap();
        assert_eq!(requests[1].headers["scnt"], "authorize-header");
        assert_eq!(requests[5].headers["scnt"], "push-header");
        assert!(requests[5].headers["cookie"].contains("challenge=synthetic"));
        assert_eq!(requests[7].body["dsWebAuthToken"], "verified-token");
        assert_eq!(requests[7].body["trustToken"], "trusted-token");
        assert_eq!(requests[7].headers["origin"], "https://www.icloud.com");
        assert!(!requests[7].headers.contains_key("x-apple-widget-key"));
    }

    #[test]
    fn rejected_code_keeps_challenge_and_rotated_headers_for_sms_retry() {
        let mut rejected = reply(
            "POST",
            "/verify/trusteddevice/securitycode",
            400,
            json!({"securityCode":{"valid":false}}),
        );
        rejected.headers = vec![("scnt", "rotated-header")];
        let (base, server) = server(vec![
            rejected,
            reply("PUT", "/verify/phone", 200, json!({})),
            reply("POST", "/verify/phone/securitycode", 200, json!({})),
            reply("GET", "/2sv/trust", 200, json!({})),
            reply("POST", "/accountLogin", 200, session_reply()),
        ]);
        let mut connection = pending(&base);
        let error = connection.verify_code("012345").unwrap_err();
        assert_eq!(
            error.downcast_ref::<AuthRecovery>().unwrap().code,
            "auth_verification_failed"
        );
        let mut connection = round_trip(connection, &base);
        connection.resend_code(VerificationMethod::Sms).unwrap();
        connection.verify_code("123450").unwrap();
        let requests = server.join().unwrap();
        assert_eq!(requests[1].headers["scnt"], "rotated-header");
        assert_eq!(
            requests[1].body,
            json!({"phoneNumber":{"id":1},"mode":"sms"})
        );
        assert_eq!(
            requests[2].body,
            json!({"phoneNumber":{"id":1},"mode":"sms","securityCode":{"code":"123450"}})
        );
    }

    #[test]
    fn accepted_code_with_failed_setup_can_refresh_without_another_code() {
        let mut verified = reply(
            "POST",
            "/verify/trusteddevice/securitycode",
            409,
            json!({"securityCode":{"valid":true}}),
        );
        verified.headers = vec![("x-apple-session-token", "verified-token")];
        let (base, server) = server(vec![
            verified,
            reply("GET", "/2sv/trust", 200, json!({})),
            reply("POST", "/accountLogin", 500, json!({})),
            reply("GET", "/2sv/trust", 200, json!({})),
            reply("POST", "/accountLogin", 200, session_reply()),
        ]);
        let mut connection = pending(&base);
        let error = connection.verify_code("012345").unwrap_err();
        assert_eq!(
            error.downcast_ref::<AuthRecovery>().unwrap().code,
            "auth_refresh_required"
        );
        let mut connection = round_trip(connection, &base);
        assert_eq!(connection.auth_state(), "refresh_required");
        assert!(connection.verify_code("012345").is_err());
        connection.refresh_session().unwrap();
        assert_eq!(connection.auth_state(), "authenticated");
        assert_eq!(server.join().unwrap().len(), 5);
    }

    #[test]
    fn check_does_not_persist_rotated_tokens_and_refresh_reports_rejected_session() {
        let mut checked = reply("POST", "/validate", 200, session_reply());
        checked.headers = vec![
            ("x-apple-session-token", "do-not-save"),
            ("set-cookie", "temporary=synthetic; Path=/"),
        ];
        let (base, server) = server(vec![
            checked,
            reply("POST", "/accountLogin", 421, json!({})),
        ]);
        let mut connection = pending(&base);
        connection.session.pending = None;
        connection.session.account_data = session_reply();
        let before = serde_json::to_string(&connection.session).unwrap();
        connection.check_session().unwrap();
        assert_eq!(serde_json::to_string(&connection.session).unwrap(), before);
        let error = connection.refresh_session().unwrap_err();
        let recovery = error.downcast_ref::<AuthRecovery>().unwrap();
        assert_eq!(recovery.code, "auth_sign_in_required");
        assert!(recovery.next_command.contains("auth add"));
        assert!(recovery.next_command.ends_with("--password-stdin"));
        let requests = server.join().unwrap();
        assert_eq!(requests[1].body["dsWebAuthToken"], "initial-token");
    }

    #[test]
    fn conflict_without_a_new_token_does_not_accept_the_old_srp_token() {
        let (base, server) = server(vec![reply(
            "POST",
            "/verify/trusteddevice/securitycode",
            409,
            json!({"securityCode":{"valid":true}}),
        )]);
        let mut connection = pending(&base);
        let error = connection.verify_code("012345").unwrap_err();
        assert_eq!(
            error.downcast_ref::<AuthRecovery>().unwrap().code,
            "auth_verification_failed"
        );
        assert_eq!(connection.auth_state(), "verification_required");
        assert_eq!(server.join().unwrap().len(), 1);
    }

    #[test]
    fn pending_refresh_and_invalid_code_stop_before_any_network_request() {
        let mut connection = pending("http://127.0.0.1:1");
        let error = connection.refresh_session().unwrap_err();
        let recovery = error.downcast_ref::<AuthRecovery>().unwrap();
        assert_eq!(recovery.code, "auth_verification_required");
        assert!(recovery.next_command.ends_with("--code-stdin"));
        for code in ["", "12345", "1234567", "12a456", "??????"] {
            assert!(
                connection
                    .verify_code(code)
                    .unwrap_err()
                    .to_string()
                    .contains("six digits")
            );
        }
    }

    #[test]
    fn reminders_startup_sends_icloud_web_headers_and_timezone() {
        let (base, query_server) = server(vec![reply(
            "GET",
            "/rd/startup",
            200,
            json!({"Collections":[],"Reminders":[]}),
        )]);
        let mut connection = pending(&base);
        connection.session.pending = None;
        let data = connection
            .request_reminders_startup(Url::parse(&base).unwrap())
            .unwrap();
        assert!(data["Collections"].is_array());
        let requests = query_server.join().unwrap();
        assert_eq!(requests[0].headers["origin"], "https://www.icloud.com");
        assert_eq!(requests[0].headers["referer"], "https://www.icloud.com/");
        let url = Url::parse(&format!("{base}{}", requests[0].target)).unwrap();
        let params = url.query_pairs().collect::<BTreeMap<_, _>>();
        assert_eq!(params["usertz"], "Etc/UTC");
        assert_eq!(params["clientVersion"], "4.0");
        assert!(!requests[0].headers.contains_key("x-apple-session-token"));
    }

    #[test]
    fn upgraded_reminders_use_cloudkit_and_decode_title_documents() {
        let changes = json!({
            "zones": [{
                "zoneID": {"zoneName":"Reminders", "zoneType":"REGULAR_CUSTOM_ZONE"},
                "syncToken":"synthetic-sync-token",
                "moreComing":false,
                "records":[{
                    "recordName":"List/LIST-A",
                    "recordType":"List",
                    "fields":{
                        "Name":{"type":"STRING", "value":"Synthetic List"},
                        "Count":{"type":"INT64", "value":1}
                    }
                }]
            }]
        });
        let query = json!({
            "records":[{
                "recordName":"Reminder/REMINDER-A",
                "recordType":"Reminder",
                "fields":{
                    "TitleDocument":{"type":"ENCRYPTED_BYTES", "value":"eJzjYBCS4GAQYJASEhJwy6woKS1KVQhKzc3MS0ktAgBBdwbW"},
                    "List":{"type":"REFERENCE", "value":{"recordName":"List/LIST-A", "action":"VALIDATE"}},
                    "Completed":{"type":"INT64", "value":0},
                    "DueDate":{"type":"TIMESTAMP", "value":1735862400000i64},
                    "Deleted":{"type":"INT64", "value":0}
                }
            }]
        });
        let (base, fallback_server) = server(vec![
            reply(
                "POST",
                "/requestWebAccessState",
                200,
                json!({"isICDRSDisabled":false}),
            ),
            reply(
                "POST",
                "/database/1/com.apple.reminders/production/private/changes/zone",
                200,
                changes,
            ),
            reply(
                "POST",
                "/database/1/com.apple.reminders/production/private/records/query",
                200,
                query,
            ),
        ]);
        let mut connection = pending(&base);
        connection.session.pending = None;
        connection.session.account_data = json!({
            "dsInfo":{"dsid":"synthetic-dsid"},
            "webservices":{"ckdatabasews":{"url":base}}
        });

        let (reminders, has_more) = connection.reminders(0, 100).unwrap();

        assert!(!has_more);
        assert_eq!(reminders.len(), 1);
        assert_eq!(reminders[0]["id"], "Reminder/REMINDER-A");
        assert_eq!(reminders[0]["title"], "Fixture Reminder");
        assert_eq!(reminders[0]["list"], "Synthetic List");
        assert_eq!(reminders[0]["completed"], false);
        assert_eq!(reminders[0]["due"], "2025-01-03T00:00:00Z");
        let requests = fallback_server.join().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests[0].target.split('?').next().unwrap(),
            "/requestWebAccessState"
        );
        let zone_request = &requests[1].body;
        assert_eq!(zone_request["zones"][0]["desiredRecordTypes"][0], "List");
        let query_request = &requests[2].body;
        assert_eq!(query_request["query"]["recordType"], "reminderList");
        assert_eq!(
            query_request["query"]["filterBy"][1]["fieldName"],
            "includeCompleted"
        );
        let url = Url::parse(&format!("{base}{}", requests[1].target)).unwrap();
        let params = url.query_pairs().collect::<BTreeMap<_, _>>();
        assert_eq!(params["dsid"], "synthetic-dsid");
        assert_eq!(params["remapEnums"], "true");
    }

    #[test]
    fn cloudkit_reminders_stop_after_one_extra_record_for_pagination() {
        let list_zone = json!({
            "zones":[{"zoneID":{"zoneName":"Reminders"},"syncToken":"token","moreComing":false,"records":[{
                "recordName":"List/LIST-A","recordType":"List","fields":{"Name":{"type":"STRING","value":"Synthetic List"}}
            }]}]
        });
        let reminder_record = |name: &str| {
            json!({
                "recordName":name,
                "recordType":"Reminder",
                "fields":{
                    "TitleDocument":{"type":"ENCRYPTED_BYTES","value":"eJzjYBCS4GAQYJASEhJwy6woKS1KVQhKzc3MS0ktAgBBdwbW"},
                    "List":{"type":"REFERENCE","value":{"recordName":"List/LIST-A","action":"VALIDATE"}},
                    "Completed":{"type":"INT64","value":0},
                    "Deleted":{"type":"INT64","value":0}
                }
            })
        };
        let (base, server) = server(vec![
            reply(
                "POST",
                "/requestWebAccessState",
                200,
                json!({"isICDRSDisabled":false}),
            ),
            reply(
                "POST",
                "/database/1/com.apple.reminders/production/private/changes/zone",
                200,
                list_zone,
            ),
            reply(
                "POST",
                "/database/1/com.apple.reminders/production/private/records/query",
                200,
                json!({
                    "records":[reminder_record("Reminder/A"), reminder_record("Reminder/B")]
                }),
            ),
        ]);
        let mut connection = pending(&base);
        connection.session.pending = None;
        connection.session.account_data = json!({
            "dsInfo":{"dsid":"synthetic-dsid"},
            "webservices":{"ckdatabasews":{"url":base}}
        });

        let (reminders, has_more) = connection.reminders(0, 1).unwrap();

        assert!(has_more);
        assert_eq!(reminders.len(), 1);
        assert_eq!(reminders[0]["id"], "Reminder/A");
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[2].body["resultsLimit"], 2);
    }

    #[test]
    fn cloudkit_list_count_uses_list_metadata() {
        let (base, fallback_server) = server(vec![
            reply(
                "POST",
                "/requestWebAccessState",
                200,
                json!({"isICDRSDisabled":false}),
            ),
            reply(
                "POST",
                "/database/1/com.apple.reminders/production/private/changes/zone",
                200,
                json!({
                    "zones":[{"zoneID":{"zoneName":"Reminders"},"syncToken":"token","moreComing":false,"records":[{
                        "recordName":"List/LIST-A","recordType":"List","fields":{
                            "Name":{"type":"STRING","value":"Synthetic List"},"Count":{"type":"INT64","value":4}
                        }
                    }]}]
                }),
            ),
        ]);
        let mut connection = pending(&base);
        connection.session.pending = None;
        connection.session.account_data = json!({
            "dsInfo":{"dsid":"synthetic-dsid"},
            "webservices":{"ckdatabasews":{"url":base}}
        });

        let lists = connection.reminder_lists().unwrap();

        assert_eq!(
            lists,
            vec![json!({"id":"List/LIST-A","name":"Synthetic List","count":4})]
        );
        assert_eq!(fallback_server.join().unwrap().len(), 2);
    }

    #[test]
    fn saved_pcs_approval_skips_rechecking_device_access() {
        let (base, server) = server(vec![reply(
            "POST",
            "/database/1/com.apple.reminders/production/private/changes/zone",
            200,
            json!({
                "zones":[{"zoneID":{"zoneName":"Reminders"},"syncToken":"token","moreComing":false,"records":[]}]
            }),
        )]);
        let mut connection = pending(&base);
        connection.session.pending = None;
        connection.session.reminders_pcs_ready = true;
        connection.session.account_data = json!({
            "dsInfo":{"dsid":"synthetic-dsid"},
            "webservices":{"ckdatabasews":{"url":base}}
        });

        assert!(connection.reminder_lists().unwrap().is_empty());
        assert_eq!(server.join().unwrap().len(), 1);
    }

    #[test]
    fn reminders_pcs_consent_returns_the_exact_retry_command() {
        let (base, server) = server(vec![
            reply(
                "POST",
                "/requestWebAccessState",
                200,
                json!({"isICDRSDisabled":true,"isDeviceConsentedForPCS":false}),
            ),
            reply(
                "POST",
                "/enableDeviceConsentForPCS",
                200,
                json!({"isDeviceConsentNotificationSent":true}),
            ),
        ]);
        let mut connection = pending(&base);
        connection.session.pending = None;
        connection.session.account_data = json!({
            "dsInfo":{"dsid":"synthetic-dsid"},
            "webservices":{"ckdatabasews":{"url":base}}
        });

        let error = connection.reminder_lists().unwrap_err();
        let recovery = error.downcast_ref::<RemindersAccessRecovery>().unwrap();
        assert_eq!(recovery.code, "reminders_access_required");
        assert!(recovery.message.contains("trusted-device approval"));
        assert!(
            recovery
                .next_command
                .contains("icli reminders lists --email")
        );
        assert_eq!(server.join().unwrap().len(), 2);
    }

    #[test]
    fn cloudkit_title_decoder_handles_plain_and_compressed_protobuf() {
        // VersionedDocument { version: [Version { data: topotext.String }] }.
        let bare_string = [0x12, 0x05, b'H', b'e', b'l', b'l', b'o'];
        let version = [0x1a, 0x07, 0x12, 0x05, b'H', b'e', b'l', b'l', b'o'];
        let mut document = vec![0x12, version.len() as u8];
        document.extend_from_slice(&version);
        assert_eq!(decode_crdt_document_text(&bare_string).unwrap(), "Hello");
        assert_eq!(decode_crdt_document_text(&document).unwrap(), "Hello");
    }

    #[test]
    fn reminders_text_update_preserves_crdt_and_handles_unicode_and_clear() {
        let original = encode_reminders_text_document("Old title").unwrap();
        let edited = encode_reminders_text_edit(&original, "New 🧾 title").unwrap();
        assert_eq!(
            cloudkit_text_field(
                Some(&json!({"TitleDocument":{"type":"STRING","value":edited}})),
                "TitleDocument"
            )
            .unwrap(),
            "New 🧾 title"
        );
        let cleared = encode_reminders_text_edit(&edited, "").unwrap();
        assert_eq!(
            cloudkit_text_field(
                Some(&json!({"TitleDocument":{"type":"STRING","value":cleared}})),
                "TitleDocument"
            )
            .unwrap(),
            ""
        );
    }

    #[test]
    fn reminder_update_sends_crdt_and_clears_due_metadata() {
        let old_title = encode_reminders_text_document("Old title").unwrap();
        let new_title = encode_reminders_text_edit(&old_title, "New title").unwrap();
        let base_record = json!({
            "recordName":"Reminder/REM-1","recordType":"Reminder","recordChangeTag":"tag-1",
            "fields":{
                "TitleDocument":{"type":"STRING","value":old_title},
                "NotesDocument":{"type":"STRING","value":encode_reminders_text_document("notes").unwrap()},
                "DueDate":{"type":"TIMESTAMP","value":1234},
                "TimeZone":{"type":"STRING","value":"Europe/Amsterdam"},
                "ResolutionTokenMap":{"type":"STRING","value":reminders_resolution_tokens(&["titleDocument","dueDate","timeZone"]).unwrap()},
                "Completed":{"type":"INT64","value":0}
            }
        });
        let updated_record = json!({
            "recordName":"Reminder/REM-1","recordType":"Reminder","recordChangeTag":"tag-2",
            "fields":{
                "TitleDocument":{"type":"STRING","value":new_title},
                "NotesDocument":{"type":"STRING","value":encode_reminders_text_document("notes").unwrap()},
                "DueDate":{"type":"TIMESTAMP","value":null},
                "TimeZone":{"type":"STRING","value":null},
                "ResolutionTokenMap":{"type":"STRING","value":reminders_resolution_tokens(&["titleDocument","dueDate","timeZone","lastModifiedDate"]).unwrap()},
                "Completed":{"type":"INT64","value":0}
            }
        });
        let lookup_path = "/database/1/com.apple.reminders/production/private/records/lookup";
        let (base, server) = server(vec![
            reply("POST", lookup_path, 200, json!({"records":[base_record]})),
            reply(
                "POST",
                "/database/1/com.apple.reminders/production/private/records/modify",
                200,
                json!({"records":[]}),
            ),
            reply(
                "POST",
                lookup_path,
                200,
                json!({"records":[updated_record]}),
            ),
        ]);
        let mut connection = cloudkit_connection(&base);

        let value = connection
            .reminder_update("REM-1", &json!({"title":"New title","due_date_ms":null}))
            .unwrap();

        assert_eq!(value["title"], "New title");
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 3);
        let operation = &requests[1].body["operations"][0];
        assert_eq!(operation["operationType"], "update");
        assert_eq!(operation["record"]["recordChangeTag"], "tag-1");
        assert_eq!(
            operation["record"]["fields"]["DueDate"]["value"],
            Value::Null
        );
        assert_eq!(
            operation["record"]["fields"]["TimeZone"]["value"],
            Value::Null
        );
        assert_eq!(
            cloudkit_text_field(Some(&operation["record"]["fields"]), "TitleDocument").unwrap(),
            "New title"
        );
    }

    #[test]
    fn reminders_changes_returns_cursor_and_pagination_state() {
        let (base, server) = server(vec![reply(
            "POST",
            "/database/1/com.apple.reminders/production/private/changes/zone",
            200,
            json!({"zones":[{"syncToken":"next-cursor","moreComing":true,"records":[
                {"recordName":"Reminder/REM-1","recordType":"Reminder","fields":{"Completed":{"type":"INT64","value":1}}},
                {"recordName":"Reminder/REM-2","deleted":true}
            ]}]}),
        )]);
        let mut connection = cloudkit_connection(&base);

        let changes = connection.reminders_changes(Some("old-cursor"), 2).unwrap();

        assert_eq!(changes["cursor"], "next-cursor");
        assert_eq!(changes["more_available"], true);
        assert_eq!(changes["changes"][0]["type"], "updated");
        assert_eq!(changes["changes"][1]["type"], "deleted");
        let requests = server.join().unwrap();
        assert_eq!(requests[0].body["zones"][0]["syncToken"], "old-cursor");
        assert_eq!(requests[0].body["resultsLimit"], 2);
    }

    #[test]
    fn sync_cursor_uses_reminder_list_query_and_zone_fallback() {
        let query_path = "/database/1/com.apple.reminders/production/private/records/query";
        let (base, query_server) = server(vec![reply(
            "POST",
            query_path,
            200,
            json!({"syncToken":"query-cursor"}),
        )]);
        let mut connection = cloudkit_connection(&base);

        assert_eq!(connection.reminders_sync_cursor().unwrap(), "query-cursor");
        let requests = query_server.join().unwrap();
        assert_eq!(requests[0].body["query"]["recordType"], "reminderList");
        assert!(requests[0].target.contains("getCurrentSyncToken=true"));

        let (base, fallback_server) = server(vec![
            reply(
                "POST",
                query_path,
                400,
                json!({"reason":"query unavailable"}),
            ),
            reply(
                "POST",
                "/database/1/com.apple.reminders/production/private/changes/zone",
                200,
                json!({"zones":[{"syncToken":"zone-cursor","records":[]}]}),
            ),
        ]);
        let mut connection = cloudkit_connection(&base);

        assert_eq!(connection.reminders_sync_cursor().unwrap(), "zone-cursor");
        let requests = fallback_server.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[1].body["zones"][0]["desiredRecordTypes"],
            json!([])
        );
    }

    #[test]
    fn hashtag_create_updates_parent_and_creates_child_atomically() {
        let reminder = json!({
            "recordName":"Reminder/REM-1","recordType":"Reminder","recordChangeTag":"tag-reminder",
            "fields":{
                "HashtagIDs":{"type":"STRING_LIST","value":[]},
                "ResolutionTokenMap":{"type":"STRING","value":reminders_resolution_tokens(&["hashtagIDs"]).unwrap()}
            }
        });
        let (base, server) = server(vec![reply(
            "POST",
            "/database/1/com.apple.reminders/production/private/records/modify",
            200,
            json!({"records":[]}),
        )]);
        let connection = cloudkit_connection(&base);

        let child = connection
            .reminders_create_child(
                &reminder,
                "Hashtag",
                "Hashtag",
                "HashtagIDs",
                "hashtagIDs",
                json!({"Name":{"type":"ENCRYPTED_BYTES","value":STANDARD.encode("work")}}),
            )
            .unwrap();

        assert!(child.starts_with("Hashtag/"));
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 1);
        let modify = &requests[0].body;
        assert_eq!(modify["atomic"], true);
        assert_eq!(modify["operations"].as_array().unwrap().len(), 2);
        assert_eq!(
            modify["operations"][0]["record"]["fields"]["HashtagIDs"]["type"],
            "STRING_LIST"
        );
        assert_eq!(modify["operations"][1]["operationType"], "create");
        assert_eq!(modify["operations"][1]["record"]["recordType"], "Hashtag");
        assert_eq!(
            modify["operations"][1]["record"]["fields"]["Name"]["value"],
            STANDARD.encode("work")
        );
    }

    #[test]
    fn saved_sessions_from_before_pending_support_remain_readable() {
        let session: SavedAppleSession = serde_json::from_value(json!({
            "account":"synthetic@example.invalid", "client_id":"test", "account_data":session_reply(),
            "session_headers":{},"cookies_json":"[]"
        })).unwrap();
        assert!(session.pending.is_none());
        assert_eq!(
            AppleConnection::restore(session).unwrap().auth_state(),
            "authenticated"
        );
    }
}
