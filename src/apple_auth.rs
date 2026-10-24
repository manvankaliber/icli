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
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{Cursor, Read, Write},
    path::Path,
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
    pub notes_pcs_ready: bool,
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

struct NotesAttachment {
    id: String,
    filename: String,
    uti: Option<String>,
    size: Option<u64>,
    download_url: Option<String>,
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
                notes_pcs_ready: false,
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

    /// Ask Apple to log out the current web session, then let the CLI clear
    /// its local session persistence independently. Stored app passwords are
    /// intentionally unaffected.
    pub fn logout(&self, keep_trusted: bool, all_sessions: bool) -> Value {
        let payload = json!({"trustBrowser":keep_trusted,"allBrowsers":all_sessions});
        if self.auth_state() != "authenticated" {
            return json!({
                "remote_logout_confirmed":false,
                "remote_logout_reason":"no established Apple session was available",
                "local_session_cleared":false,
                "keep_trusted":keep_trusted,
                "all_sessions":all_sessions
            });
        }
        let result = (|| -> Result<(u16, bool)> {
            let mut url = Url::parse(&self.setup_root())?.join("logout")?;
            url.query_pairs_mut()
                .extend_pairs(service_params(&self.session));
            let response = self
                .client
                .post(url)
                .headers(icloud_headers())
                .header(reqwest::header::CONTENT_TYPE, "text/plain;charset=UTF-8")
                .body(payload.to_string())
                .send()
                .context("Could not contact Apple's session logout endpoint")?;
            let status = response.status();
            let confirmed = response
                .json::<Value>()
                .ok()
                .and_then(|data| data.get("success").and_then(Value::as_bool))
                .unwrap_or(false);
            Ok((status.as_u16(), confirmed))
        })();
        match result {
            Ok((status, confirmed)) => json!({
                "remote_logout_confirmed":confirmed,
                "remote_http_status":status,
                "local_session_cleared":false,
                "keep_trusted":keep_trusted,
                "all_sessions":all_sessions
            }),
            Err(_) => json!({
                "remote_logout_confirmed":false,
                "remote_logout_reason":"Apple did not confirm remote logout",
                "local_session_cleared":false,
                "keep_trusted":keep_trusted,
                "all_sessions":all_sessions
            }),
        }
    }

    fn account_service_request(&self, path: &str, post: bool) -> Result<Value> {
        self.require_authenticated()?;
        let setup = setup_endpoint(&self.session.account_data);
        let url = if path.starts_with("setup/web/") {
            format!("{}/{}", setup.trim_end_matches("/setup/ws/1"), path)
        } else {
            format!(
                "{}/{}",
                setup.trim_end_matches('/'),
                path.trim_start_matches('/')
            )
        };
        let mut request = if post {
            self.client.post(url)
        } else {
            self.client.get(url)
        }
        .headers(icloud_headers())
        .query(&service_params(&self.session));
        if post {
            request = request.json(&json!({}));
        }
        let response = request
            .send()
            .context("Could not contact Apple's iCloud account service")?;
        let status = response.status();
        let body = response.json::<Value>().unwrap_or(Value::Null);
        if matches!(status.as_u16(), 401 | 403 | 421) {
            return Err(recovery(
                &self.session.account,
                "auth_refresh_required",
                format!(
                    "Apple rejected the saved session during account data access (HTTP {status})"
                ),
                "refresh",
            ));
        }
        if !status.is_success() {
            bail!("Apple account service request failed (HTTP {status})");
        }
        Ok(body)
    }

    pub fn account_devices(&self) -> Result<Value> {
        self.account_service_request("setup/web/device/getDevices", false)
    }

    pub fn account_family(&self) -> Result<Value> {
        self.account_service_request("setup/web/family/getFamilyDetails", false)
    }

    pub fn account_storage(&self) -> Result<Value> {
        self.account_service_request("storageUsageInfo", true)
    }

    pub fn account_summary(&self) -> Result<Value> {
        let devices = self.account_devices()?;
        let family = self.account_family()?;
        let storage = self.account_storage()?;
        Ok(
            json!({"devices":devices.get("devices").and_then(Value::as_array).map(Vec::len),"family_members":family.get("familyMembers").and_then(Value::as_array).map(Vec::len),"storage":storage}),
        )
    }

    pub fn find_my_devices(&self, locate: bool) -> Result<Value> {
        self.require_authenticated()?;
        let service = self
            .session
            .account_data
            .pointer("/webservices/findme/url")
            .and_then(Value::as_str)
            .context("Apple did not advertise the Find My service")?;
        let mut url = Url::parse(&format!("{}/", service.trim_end_matches('/')))
            .context("Apple advertised an invalid Find My service URL")?;
        if url.scheme() != "https" {
            bail!("Apple advertised a non-HTTPS Find My service URL");
        }
        url = url.join(if locate {
            "fmipservice/client/web/refreshClient"
        } else {
            "fmipservice/client/web/initClient"
        })?;
        url.query_pairs_mut()
            .extend_pairs(service_params(&self.session));
        let mut client_context = json!({"appName":"iCloud Find (Web)","appVersion":"2.0","apiVersion":"3.0","deviceListVersion":1,"fmly":false,"timezone":"UTC","inactiveTime":0});
        if locate {
            client_context["shouldLocate"] = json!(true);
            client_context["selectedDevice"] = json!("all");
        }
        let response = self
            .client
            .post(url)
            .headers(icloud_headers())
            .json(&json!({
                "clientContext":client_context
            }))
            .send()
            .context("Could not contact Apple's Find My service")?;
        let status = response.status();
        let data = response.json::<Value>().unwrap_or(Value::Null);
        if matches!(status.as_u16(), 401 | 403 | 421) {
            return Err(recovery(
                &self.session.account,
                "auth_refresh_required",
                format!("Apple rejected the saved session during Find My access (HTTP {status})"),
                "refresh",
            ));
        }
        if !status.is_success() {
            bail!("Apple Find My request failed (HTTP {status})");
        }
        Ok(data.get("content").cloned().unwrap_or_else(|| json!([])))
    }

    pub fn find_my_action(
        &self,
        device_id: &str,
        action: &str,
        subject: Option<&str>,
        message: Option<&str>,
        phone_number: Option<&str>,
        play_sound: bool,
    ) -> Result<Value> {
        self.require_authenticated()?;
        if device_id.is_empty() || device_id.chars().any(char::is_control) {
            bail!("Provide a valid Find My device ID");
        }
        let devices = self.find_my_devices(false)?;
        if !devices.as_array().is_some_and(|rows| {
            rows.iter()
                .any(|row| row.get("id").and_then(Value::as_str) == Some(device_id))
        }) {
            bail!("No Find My device matched that ID; no device action was sent");
        }
        let service = self
            .session
            .account_data
            .pointer("/webservices/findme/url")
            .and_then(Value::as_str)
            .context("Apple did not advertise the Find My service")?;
        let root = Url::parse(&format!("{}/", service.trim_end_matches('/')))
            .context("Apple advertised an invalid Find My service URL")?;
        if root.scheme() != "https" {
            bail!("Apple advertised a non-HTTPS Find My service URL");
        }
        let (path, payload) = match action {
            "sound" => (
                "playSound",
                json!({"device":device_id,"subject":subject.unwrap_or("Find My Alert"),"clientContext":{"fmly":false}}),
            ),
            "message" => (
                "sendMessage",
                json!({"device":device_id,"subject":subject.unwrap_or("Find My Alert"),"sound":play_sound,"userText":true,"text":message.context("A message is required for this Find My action")?}),
            ),
            "lost-mode" => (
                "lostDevice",
                json!({"device":device_id,"ownerNbr":phone_number.unwrap_or_default(),"text":message.unwrap_or("This device has been lost. Please contact me."),"userText":true,"lostModeEnabled":true,"trackingEnabled":true,"passcode":""}),
            ),
            _ => bail!("Unsupported Find My device action"),
        };
        let mut url = root.join(&format!("fmipservice/client/web/{path}"))?;
        url.query_pairs_mut()
            .extend_pairs(service_params(&self.session));
        let response = self
            .client
            .post(url)
            .headers(icloud_headers())
            .json(&payload)
            .send()
            .context("Could not contact Apple's Find My service")?;
        let status = response.status();
        let data = response.json::<Value>().unwrap_or(Value::Null);
        if matches!(status.as_u16(), 401 | 403 | 421) {
            return Err(recovery(
                &self.session.account,
                "auth_refresh_required",
                format!("Apple rejected the saved session during Find My action (HTTP {status})"),
                "refresh",
            ));
        }
        if !status.is_success() {
            bail!("Apple Find My action failed (HTTP {status})");
        }
        if data.get("error").is_some_and(|error| !error.is_null()) {
            bail!("Apple Find My action returned an error: {}", data["error"]);
        }
        Ok(json!({"device_id":device_id,"action":action,"response":data}))
    }

    /// Request an irreversible remote erase. Apple requires a short-lived
    /// erase authorization token in addition to the saved web session.
    pub fn find_my_erase(&self, device_id: &str, message: Option<&str>) -> Result<Value> {
        self.require_authenticated()?;
        if device_id.is_empty() || device_id.chars().any(char::is_control) {
            bail!("Provide a valid Find My device ID");
        }
        let devices = self.find_my_devices(false)?;
        let device = devices
            .as_array()
            .and_then(|rows| {
                rows.iter()
                    .find(|row| row.get("id").and_then(Value::as_str) == Some(device_id))
            })
            .context("No Find My device matched that ID; no erase was requested")?;
        if device.get("canWipeAfterLock").and_then(Value::as_bool) != Some(true) {
            bail!("Apple does not report this device as remotely erasable; no erase was requested");
        }

        let session_token = self
            .session
            .session_headers
            .get("x-apple-session-token")
            .context("Saved session has no Apple session token; refresh authentication first")?;
        let setup = self.setup_root();
        let mut token_url = Url::parse(&setup)?.join("fmipWebAuthenticate")?;
        token_url
            .query_pairs_mut()
            .extend_pairs(service_params(&self.session));
        let token_response = self
            .client
            .post(token_url)
            .headers(icloud_headers())
            .json(&json!({"dsWebAuthToken":session_token}))
            .send()
            .context("Could not request Apple's Find My erase authorization")?;
        let token_status = token_response.status();
        let token_data = token_response.json::<Value>().unwrap_or(Value::Null);
        if matches!(token_status.as_u16(), 401 | 403 | 421) {
            return Err(recovery(
                &self.session.account,
                "auth_refresh_required",
                format!(
                    "Apple rejected authentication for the Find My erase token (HTTP {token_status})"
                ),
                "refresh",
            ));
        }
        if !token_status.is_success() {
            bail!("Apple Find My erase authorization failed (HTTP {token_status})");
        }
        let erase_token = token_data
            .pointer("/tokens/mmeFMIPWebEraseDeviceToken")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .context("Apple did not return a Find My erase authorization token")?;

        let service = self
            .session
            .account_data
            .pointer("/webservices/findme/url")
            .and_then(Value::as_str)
            .context("Apple did not advertise the Find My service")?;
        let root = Url::parse(&format!("{}/", service.trim_end_matches('/')))?;
        if root.scheme() != "https" {
            bail!("Apple advertised a non-HTTPS Find My service URL");
        }
        let mut erase_url = root.join("fmipservice/client/web/remoteWipeWithUserAuth")?;
        erase_url
            .query_pairs_mut()
            .extend_pairs(service_params(&self.session));
        let erase_response = self
            .client
            .post(erase_url)
            .headers(icloud_headers())
            .json(&json!({
                "authToken":erase_token,
                "device":device_id,
                "text":message.unwrap_or("This device has been erased."),
                "passcode":""
            }))
            .send()
            .context("Could not contact Apple's Find My erase service")?;
        let erase_status = erase_response.status();
        let erase_data = erase_response.json::<Value>().unwrap_or(Value::Null);
        if matches!(erase_status.as_u16(), 401 | 403 | 421) {
            return Err(recovery(
                &self.session.account,
                "auth_refresh_required",
                format!("Apple rejected the Find My erase request (HTTP {erase_status})"),
                "refresh",
            ));
        }
        if !erase_status.is_success() {
            bail!("Apple Find My erase request failed (HTTP {erase_status})");
        }
        let erase_result_code = erase_data.get("statusCode").and_then(|code| {
            code.as_i64()
                .or_else(|| code.as_str().and_then(|value| value.parse::<i64>().ok()))
        });
        if erase_data
            .get("error")
            .is_some_and(|error| !error.is_null())
            || erase_result_code.is_some_and(|code| code != 200)
        {
            bail!(
                "Apple Find My erase request returned an error: {}",
                erase_data
                    .get("error")
                    .or_else(|| erase_data.get("statusCode"))
                    .unwrap_or(&Value::Null)
            );
        }
        if erase_result_code != Some(200)
            && erase_data.get("success").and_then(Value::as_bool) != Some(true)
        {
            bail!(
                "Apple did not confirm the Find My erase request; inspect the device before retrying"
            );
        }
        Ok(json!({"device_id":device_id,"action":"erase","accepted":true,"response":erase_data}))
    }

    fn advertised_service_url(&self, key: &str) -> Result<Url> {
        let value = self
            .session
            .account_data
            .pointer(&format!("/webservices/{key}/url"))
            .and_then(Value::as_str)
            .with_context(|| format!("Apple did not advertise the {key} service"))?;
        let url = Url::parse(&format!("{}/", value.trim_end_matches('/')))
            .with_context(|| format!("Apple advertised an invalid {key} service URL"))?;
        if url.scheme() != "https" {
            bail!("Apple advertised a non-HTTPS {key} service URL");
        }
        Ok(url)
    }

    fn advertised_service_post(&self, key: &str, path: &str, payload: &Value) -> Result<Value> {
        self.require_authenticated()?;
        let mut url = self.advertised_service_url(key)?.join(path)?;
        url.query_pairs_mut()
            .extend_pairs(service_params(&self.session));
        let response = self
            .client
            .post(url)
            .headers(icloud_headers())
            .json(payload)
            .send()
            .with_context(|| format!("Could not contact Apple's {key} service"))?;
        let status = response.status();
        let data = response.json::<Value>().unwrap_or(Value::Null);
        if matches!(status.as_u16(), 401 | 403 | 421) {
            return Err(recovery(
                &self.session.account,
                "auth_refresh_required",
                format!("Apple rejected the saved session during {key} access (HTTP {status})"),
                "refresh",
            ));
        }
        if !status.is_success() {
            bail!("Apple {key} request failed (HTTP {status})");
        }
        Ok(data)
    }

    pub fn hide_my_email_request(
        &self,
        path: &str,
        method: &str,
        payload: Option<&Value>,
    ) -> Result<Value> {
        self.require_authenticated()?;
        let url = self.advertised_service_url("hidemyemail")?.join(path)?;
        let mut request = self
            .client
            .request(method.parse()?, url)
            .headers(icloud_headers())
            .query(&service_params(&self.session));
        if let Some(payload) = payload {
            request = request.json(payload);
        }
        let response = request
            .send()
            .context("Could not contact Apple's Hide My Email service")?;
        let status = response.status();
        let data = response.json::<Value>().unwrap_or(Value::Null);
        if matches!(status.as_u16(), 401 | 403 | 421) {
            return Err(recovery(
                &self.session.account,
                "auth_refresh_required",
                format!(
                    "Apple rejected the saved session during Hide My Email access (HTTP {status})"
                ),
                "refresh",
            ));
        }
        if !status.is_success() {
            bail!("Apple Hide My Email request failed (HTTP {status})");
        }
        if data.get("success").and_then(Value::as_bool) == Some(false) {
            bail!(
                "Apple Hide My Email rejected the request{}",
                data.get("errorMessage")
                    .and_then(Value::as_str)
                    .map(|s| format!(": {s}"))
                    .unwrap_or_default()
            );
        }
        Ok(data.get("result").cloned().unwrap_or(data))
    }

    fn drive_node(&self, id: &str, share_id: Option<&Value>) -> Result<Value> {
        let mut node = json!({"drivewsid":id,"partialData":false});
        if let Some(share) = share_id {
            node["shareID"] = share.clone();
        }
        let rows = self.advertised_service_post(
            "drivews",
            "retrieveItemDetailsInFolders",
            &json!([node]),
        )?;
        rows.as_array()
            .and_then(|items| items.first())
            .cloned()
            .context("Apple returned no iCloud Drive item")
    }

    pub fn drive_list(&self, path: &str) -> Result<Value> {
        if path.chars().any(char::is_control) {
            bail!("Drive path cannot contain control characters");
        }
        let parts = path
            .split('/')
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>();
        if parts.iter().any(|part| *part == "." || *part == "..") {
            bail!("Drive path cannot contain . or .. segments");
        }
        let mut node = self.drive_node("FOLDER::com.apple.CloudDocs::root", None)?;
        for part in parts {
            let items = node
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_else(|| vec![]);
            let child = items
                .iter()
                .find(|item| item.get("name").and_then(Value::as_str) == Some(part))
                .cloned()
                .with_context(|| {
                    format!(
                        "No iCloud Drive item named {part:?} in {}",
                        node.get("name").and_then(Value::as_str).unwrap_or("/")
                    )
                })?;
            if child
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind.eq_ignore_ascii_case("file"))
            {
                bail!("Drive path component {part:?} is a file, not a folder");
            }
            node = self.drive_node(
                child
                    .get("drivewsid")
                    .and_then(Value::as_str)
                    .context("Apple Drive folder has no ID")?,
                child.get("shareID"),
            )?;
        }
        let items = node
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_else(|| vec![]);
        let items = items.into_iter().map(|item| json!({
            "name":item.get("name"),"type":item.get("type"),"id":item.get("docwsid"),
            "drive_id":item.get("drivewsid"),"zone":item.get("zone"),"size":item.get("size"),
            "modified":item.get("dateModified"),"etag":item.get("etag")
        })).collect::<Vec<_>>();
        Ok(json!({"path":path,"folder":node.get("name"),"id":node.get("drivewsid"),"items":items}))
    }

    pub fn drive_download(&self, id: &str, zone: &str, output: &Path) -> Result<Value> {
        if zone.is_empty() || zone.chars().any(|c| c.is_control() || c == '/') {
            bail!("Invalid Drive zone");
        }
        let mut url = self
            .advertised_service_url("docws")?
            .join(&format!("ws/{zone}/download/by_id"))?;
        url.query_pairs_mut()
            .append_pair("document_id", id)
            .extend_pairs(service_params(&self.session));
        let response = self
            .client
            .get(url)
            .headers(icloud_headers())
            .send()
            .context("Could not request the iCloud Drive download")?;
        let status = response.status();
        let body = response.json::<Value>().unwrap_or(Value::Null);
        if matches!(status.as_u16(), 401 | 403 | 421) {
            return Err(recovery(
                &self.session.account,
                "auth_refresh_required",
                format!("Apple rejected the saved session during Drive download (HTTP {status})"),
                "refresh",
            ));
        }
        if !status.is_success() {
            bail!("Apple Drive download request failed (HTTP {status})");
        }
        let download_url = body
            .pointer("/data_token/url")
            .or_else(|| body.pointer("/package_token/url"))
            .and_then(Value::as_str)
            .context("Apple returned no iCloud Drive download URL")?;
        let download_url =
            Url::parse(download_url).context("Apple returned an invalid Drive download URL")?;
        if download_url.scheme() != "https" {
            bail!("Apple returned a non-HTTPS Drive download URL");
        }
        let mut response = self
            .client
            .get(download_url)
            .send()
            .context("Could not download the iCloud Drive file")?;
        if !response.status().is_success() {
            bail!(
                "iCloud Drive file download failed (HTTP {})",
                response.status()
            );
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)
            .with_context(|| {
                format!(
                    "Could not create {} without overwriting an existing file",
                    output.display()
                )
            })?;
        let bytes = std::io::copy(&mut response, &mut file)
            .context("Could not write the iCloud Drive download")?;
        Ok(json!({"id":id,"path":output,"bytes":bytes}))
    }

    fn photos_cloudkit_request(&self, path: &str, payload: &Value) -> Result<Value> {
        self.require_authenticated()?;
        let mut url = self
            .advertised_service_url("photos")?
            .join("database/1/com.apple.photos.cloud/production/private/")?;
        url = url.join(path)?;
        url.query_pairs_mut()
            .append_pair("remapEnums", "true")
            .append_pair("getCurrentSyncToken", "true")
            .extend_pairs(service_params(&self.session));
        let response = self
            .client
            .post(url)
            .headers(icloud_headers())
            .header("content-type", "text/plain")
            .body(payload.to_string())
            .send()
            .context("Could not contact Apple's Photos service")?;
        let status = response.status();
        let data = response.json::<Value>().unwrap_or(Value::Null);
        if matches!(status.as_u16(), 401 | 403 | 421) {
            return Err(recovery(
                &self.session.account,
                "auth_refresh_required",
                format!("Apple rejected the saved session during Photos access (HTTP {status})"),
                "refresh",
            ));
        }
        if !status.is_success() {
            bail!("Apple Photos request failed (HTTP {status})");
        }
        Ok(data)
    }

    fn invites_cloudkit_request(&self, scope: &str, path: &str, payload: &Value) -> Result<Value> {
        self.require_authenticated()?;
        if !matches!(scope, "private" | "shared" | "public") {
            bail!("Invalid Apple Invites database scope");
        }
        let service = self
            .session
            .account_data
            .pointer("/webservices/ckdatabasews/url")
            .and_then(Value::as_str)
            .context("Apple did not advertise its CloudKit service")?;
        let root = Url::parse(&format!("{}/", service.trim_end_matches('/')))
            .context("Apple advertised an invalid CloudKit service URL")?;
        if root.scheme() != "https" {
            bail!("Apple advertised a non-HTTPS CloudKit service URL");
        }
        let mut url = root.join(&format!(
            "database/1/com.apple.icloud.events/production/{scope}/{path}"
        ))?;
        url.query_pairs_mut()
            .append_pair("remapEnums", "true")
            .append_pair("getCurrentSyncToken", "true")
            .extend_pairs(service_params(&self.session));
        let response = self
            .client
            .post(url)
            .headers(icloud_headers())
            .json(payload)
            .send()
            .context("Could not contact Apple's Invites CloudKit service")?;
        let status = response.status();
        let data = response.json::<Value>().unwrap_or(Value::Null);
        if matches!(status.as_u16(), 401 | 403 | 421)
            || data.get("hsaChallengeRequired").and_then(Value::as_bool) == Some(true)
        {
            return Err(recovery(
                &self.session.account,
                "auth_refresh_required",
                format!("Apple Invites rejected the saved session (HTTP {status})"),
                "refresh",
            ));
        }
        if !status.is_success() {
            bail!("Apple Invites request failed (HTTP {status})");
        }
        Ok(data)
    }

    pub fn invites_list(&self) -> Result<Value> {
        let mut records = self.invites_query_private()?;
        let mut shared_zones = self
            .invites_cloudkit_request("shared", "zones/list", &json!({}))?
            .get("zones")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for zone in shared_zones.drain(..) {
            let zone_id = match zone.get("zoneID") {
                Some(zone_id) => zone_id.clone(),
                None => continue,
            };
            let event_records = self.invites_zone_changes("shared", &zone_id, None)?;
            for record in event_records {
                if record.get("recordType").and_then(Value::as_str) == Some("EventDetails") {
                    records.push((record, "shared", zone.get("zoneID").cloned()));
                }
            }
        }
        let mut seen = BTreeSet::new();
        let events = records
            .into_iter()
            .filter_map(|(record, scope, zone)| {
                if record.get("recordType").and_then(Value::as_str) != Some("EventDetails") {
                    return None;
                }
                let id = invites_event_id(&record)?;
                if !seen.insert((scope, id.clone())) {
                    return None;
                }
                Some(invites_event_summary(&record, &id, scope, zone.as_ref()))
            })
            .collect::<Vec<_>>();
        Ok(json!({"events":events,"more_available":false}))
    }

    fn invites_query_private(&self) -> Result<Vec<(Value, &'static str, Option<Value>)>> {
        let mut output = Vec::new();
        let mut continuation: Option<String> = None;
        for _ in 0..200 {
            let mut request =
                json!({"query":{"recordType":"EventDetails"},"zoneWide":true,"resultsLimit":200});
            if let Some(marker) = &continuation {
                request["continuationMarker"] = json!(marker);
            }
            let response = self.invites_cloudkit_request("private", "records/query", &request)?;
            for record in response
                .get("records")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if record.get("serverErrorCode").is_some() {
                    continue;
                }
                output.push((record.clone(), "private", None));
            }
            continuation = response
                .get("continuationMarker")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if continuation.is_none() {
                return Ok(output);
            }
        }
        bail!("Apple Invites query exceeded 200 pages; narrow the request and retry")
    }

    fn invites_zone_changes(
        &self,
        scope: &str,
        zone_id: &Value,
        desired_record_type: Option<&str>,
    ) -> Result<Vec<Value>> {
        let mut output = Vec::new();
        let mut sync_token: Option<Value> = None;
        for _ in 0..200 {
            let mut zone = json!({"zoneID":zone_id});
            if let Some(token) = &sync_token {
                zone["syncToken"] = token.clone();
            }
            if let Some(record_type) = desired_record_type {
                zone["desiredRecordTypes"] = json!([record_type]);
            }
            let response =
                self.invites_cloudkit_request(scope, "changes/zone", &json!({"zones":[zone]}))?;
            let page = response
                .get("zones")
                .and_then(Value::as_array)
                .and_then(|zones| zones.first())
                .context("Apple returned an invalid Invites changes response")?;
            if let Some(code) = page.get("serverErrorCode").and_then(Value::as_str) {
                bail!("Apple Invites zone read failed ({code})");
            }
            output.extend(
                page.get("records")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .cloned(),
            );
            sync_token = page.get("syncToken").cloned();
            if page.get("moreComing").and_then(Value::as_bool) != Some(true) {
                return Ok(output);
            }
        }
        bail!("Apple Invites zone exceeded 200 change pages; retry later")
    }

    pub fn invites_event(&self, id: &str) -> Result<Value> {
        let all = self.invites_list()?;
        let event = all
            .get("events")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|row| row.get("id").and_then(Value::as_str) == Some(id))
            .cloned()
            .context("No Apple Invites event matched that ID")?;
        let scope = event
            .get("scope")
            .and_then(Value::as_str)
            .unwrap_or("private");
        let zone_id = event
            .get("zone_id")
            .cloned()
            .unwrap_or_else(|| json!({"zoneName":id,"zoneType":"REGULAR_CUSTOM_ZONE"}));
        let response = self.invites_cloudkit_request(scope, "records/lookup", &json!({
            "records":[{"recordName":format!("EventDetails:{id}")},{"recordName":"cloudkit.zoneshare"}],"zoneID":zone_id
        }))?;
        let records = response
            .get("records")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let event_record = records
            .iter()
            .find(|record| record.get("recordType").and_then(Value::as_str) == Some("EventDetails"))
            .context("Apple Invites event details were not returned")?;
        let share = records.iter().find(|record| {
            record.get("recordType").and_then(Value::as_str) == Some("cloudkit.share")
        });
        let mut full = invites_event_summary(event_record, id, scope, Some(&zone_id));
        if let Some(share) = share {
            full["share"] = invites_share_summary(share);
        }
        Ok(full)
    }

    pub fn invites_rsvps(&self, id: &str) -> Result<Value> {
        let event = self.invites_event(id)?;
        let scope = event
            .get("scope")
            .and_then(Value::as_str)
            .unwrap_or("private");
        let zone_id = event
            .get("zone_id")
            .cloned()
            .unwrap_or_else(|| json!({"zoneName":id,"zoneType":"REGULAR_CUSTOM_ZONE"}));
        let records = self.invites_zone_changes(scope, &zone_id, Some("RSVP"))?;
        let mut latest = BTreeMap::new();
        for record in records {
            let Some(name) = record.get("recordName").and_then(Value::as_str) else {
                continue;
            };
            if record.get("deleted").and_then(Value::as_bool) == Some(true)
                || record.get("recordType").is_none()
            {
                latest.remove(name);
            } else if record.get("recordType").and_then(Value::as_str) == Some("RSVP") {
                latest.insert(name.to_owned(), record);
            }
        }
        let rsvps = latest
            .values()
            .map(invites_rsvp_summary)
            .collect::<Vec<_>>();
        Ok(json!({"event_id":id,"rsvps":rsvps}))
    }

    pub fn invites_resolve(&self, input: &str) -> Result<Value> {
        let short_guid = invites_short_guid(input)?;
        let response = self.invites_cloudkit_request(
            "public",
            "records/resolve",
            &json!({"shortGUIDs":[{"value":short_guid}]}),
        )?;
        let result = response
            .get("results")
            .and_then(Value::as_array)
            .and_then(|results| results.first())
            .context("Apple Invites resolve returned no result")?;
        Ok(json!({
            "short_guid":result.pointer("/shortGUID/value"),
            "event_id":result.pointer("/zoneID/zoneName"),
            "owner":result.get("ownerIdentity"),
            "participant_status":result.get("participantStatus"),
            "participant_type":result.get("participantType"),
            "participant_permission":result.get("participantPermission")
        }))
    }

    /// Join an Apple Invites event from its short link. Apple acceptance is a
    /// write; the caller can preview the target first with `invites_resolve`.
    pub fn invites_accept(&self, input: &str) -> Result<Value> {
        let short_guid = invites_short_guid(input)?;
        let response = self.invites_cloudkit_request(
            "public",
            "records/accept",
            &json!({"shortGUIDs":[{"value":short_guid}]}),
        )?;
        let result = response
            .get("results")
            .and_then(Value::as_array)
            .and_then(|results| results.first())
            .context("Apple Invites accept returned no result")?;
        if let Some(code) = result.get("serverErrorCode").and_then(Value::as_str) {
            bail!("Apple Invites could not accept the link ({code})");
        }
        let event_id = result
            .pointer("/zoneID/zoneName")
            .and_then(Value::as_str)
            .context("Apple Invites accept response omitted its event ID")?;
        let mut event = self.invites_event(event_id)?;
        event["accepted"] = json!(true);
        Ok(event)
    }

    /// Submit or update the current user's RSVP for an Apple Invites event.
    pub fn invites_rsvp(
        &self,
        id: &str,
        status: i64,
        name: Option<&str>,
        message: Option<&str>,
        additional_adults: u32,
        additional_kids: u32,
    ) -> Result<Value> {
        if !(0..=3).contains(&status) {
            bail!("RSVP status must be no-response, not-going, maybe, or going");
        }
        let event = self.invites_event(id)?;
        let share = event
            .get("share")
            .context("Apple Invites event has no share record; no RSVP was sent")?;
        let participant_id = share
            .pointer("/current_user_participant/participantId")
            .and_then(Value::as_str)
            .context(
                "Apple did not identify the current participant for this event; no RSVP was sent",
            )?;
        let scope = event
            .get("scope")
            .and_then(Value::as_str)
            .filter(|scope| matches!(*scope, "private" | "shared"))
            .context("Apple Invites event has an invalid database scope")?;
        let zone_id = event
            .get("zone_id")
            .cloned()
            .unwrap_or_else(|| json!({"zoneName":id,"zoneType":"REGULAR_CUSTOM_ZONE"}));
        let record_name = format!("{participant_id}_rsvp");
        let current = self
            .invites_zone_changes(scope, &zone_id, Some("RSVP"))?
            .into_iter()
            .filter(|record| {
                record.get("recordName").and_then(Value::as_str) == Some(record_name.as_str())
            })
            .last();
        let current = current.filter(|record| {
            record.get("recordType").and_then(Value::as_str) == Some("RSVP")
                && record.get("deleted").and_then(Value::as_bool) != Some(true)
        });
        let change_tag = current
            .as_ref()
            .and_then(|record| record.get("recordChangeTag"))
            .cloned();
        let op = if current.is_some() {
            "update"
        } else {
            "create"
        };
        let (additional_adults, additional_kids) = if status == 1 {
            (0, 0)
        } else {
            (additional_adults, additional_kids)
        };
        let mut fields = json!({
            "status":{"type":"INT64","value":status,"isEncrypted":true},
            "numAdditionalAdults":{"type":"INT64","value":additional_adults,"isEncrypted":true},
            "numAdditionalKids":{"type":"INT64","value":additional_kids,"isEncrypted":true},
            "numAdditionalGuests":{"type":"INT64","value":additional_adults + additional_kids,"isEncrypted":true}
        });
        if let Some(name) = name {
            fields["name"] = json!({"type":"STRING","value":name,"isEncrypted":true});
        }
        if let Some(message) = message {
            fields["message"] = json!({"type":"STRING","value":message,"isEncrypted":true});
        }
        let mut record = json!({"recordName":record_name,"recordType":"RSVP","fields":fields});
        if let Some(change_tag) = change_tag {
            record["recordChangeTag"] = change_tag;
        }
        let result = self.invites_cloudkit_request(
            scope,
            "records/modify",
            &json!({
                "atomic":true,"zoneID":zone_id,
                "operations":[{"operationType":op,"record":record}]
            }),
        )?;
        let saved = result
            .get("records")
            .and_then(Value::as_array)
            .and_then(|records| records.iter().find(|r| r.get("recordName").and_then(Value::as_str) == Some(record_name.as_str())))
            .context("Apple accepted the RSVP request without confirming its record; inspect the event before retrying")?;
        if let Some(code) = saved.get("serverErrorCode").and_then(Value::as_str) {
            bail!("Apple Invites RSVP failed ({code})");
        }
        let verify = self.invites_cloudkit_request(
            scope,
            "records/lookup",
            &json!({
                "records":[{"recordName":record_name}],"zoneID":zone_id
            }),
        )?;
        let verified = verify
            .get("records")
            .and_then(Value::as_array)
            .and_then(|records| records.iter().find(|r| r.get("recordName").and_then(Value::as_str) == Some(record_name.as_str())))
            .context("Apple accepted the RSVP but readback did not confirm it; inspect the event before retrying")?;
        if invites_field(verified.get("fields"), "status").and_then(Value::as_i64) != Some(status) {
            bail!(
                "Apple accepted the RSVP but readback differs; inspect the event before retrying"
            );
        }
        Ok(json!({"event_id":id,"rsvp":invites_rsvp_summary(verified),"verified":true}))
    }

    pub fn photos_shared_album(&self, shared_url: &str, limit: usize) -> Result<Value> {
        if limit == 0 || limit > 1000 {
            bail!("Shared Photos --limit must be from 1 to 1000");
        }
        let token = shared_album_token(shared_url)?;
        let partition = shared_album_partition(&token)?;
        let base = format!("https://p{partition}-sharedstreams.icloud.com");
        let (host, response) =
            self.shared_album_request(&base, &token, "webstream", &json!({"streamCtag":null}))?;
        let photos = response
            .get("photos")
            .and_then(Value::as_array)
            .context("Apple returned a shared album response without a photos array")?;
        let photos = photos
            .iter()
            .take(limit)
            .map(|photo| {
                json!({
                    "id":photo.get("photoGuid"),
                    "caption":photo.get("caption"),
                    "created":photo.get("dateCreated"),
                    "media_type":photo.get("mediaAssetType"),
                    "derivatives":photo.get("derivatives")
                })
            })
            .collect::<Vec<_>>();
        Ok(json!({
            "kind":"shared-album",
            "album_id":token,
            "album_name":response.get("streamName"),
            "owner":response.get("streamOwnerContactName"),
            "sharedstreams_host":host,
            "photos":photos,
            "count":photos.len(),
            "truncated":response.get("photos").and_then(Value::as_array).is_some_and(|all|all.len()>limit)
        }))
    }

    pub fn photos_shared_streams(&self) -> Result<Value> {
        self.require_authenticated()?;
        let dsid = self
            .session
            .account_data
            .pointer("/dsInfo/dsid")
            .and_then(Value::as_str)
            .context("Apple did not provide an account identifier for Shared Albums")?;
        let mut url = self
            .advertised_service_url("sharedstreams")?
            .join(&format!("{dsid}/sharedstreams/webgetalbumslist"))?;
        url.query_pairs_mut()
            .extend_pairs(service_params(&self.session));
        let response = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "text/plain")
            .json(&json!({}))
            .send()
            .context("Could not contact Apple's Shared Albums service")?;
        let status = response.status();
        let data = response.json::<Value>().unwrap_or(Value::Null);
        if matches!(status.as_u16(), 401 | 403 | 421) {
            return Err(recovery(
                &self.session.account,
                "auth_refresh_required",
                format!(
                    "Apple rejected the saved session during Shared Albums access (HTTP {status})"
                ),
                "refresh",
            ));
        }
        if !status.is_success() {
            bail!("Apple Shared Albums request failed (HTTP {status})");
        }
        let albums = data
            .get("albums")
            .and_then(Value::as_array)
            .context("Apple returned a Shared Albums response without an albums array")?;
        Ok(json!({"kind":"shared-streams","albums":albums,"count":albums.len()}))
    }

    pub fn photos_shared_album_download(
        &self,
        shared_url: &str,
        output_dir: &Path,
        limit: usize,
    ) -> Result<Value> {
        if limit == 0 || limit > 1000 {
            bail!("Shared Photos --limit must be from 1 to 1000");
        }
        let token = shared_album_token(shared_url)?;
        let partition = shared_album_partition(&token)?;
        let base = format!("https://p{partition}-sharedstreams.icloud.com");
        let (host, album) =
            self.shared_album_request(&base, &token, "webstream", &json!({"streamCtag":null}))?;
        let photos = album
            .get("photos")
            .and_then(Value::as_array)
            .context("Apple returned a shared album response without a photos array")?;
        let photos = photos.iter().take(limit).collect::<Vec<_>>();
        let ids = photos
            .iter()
            .filter_map(|photo| photo.get("photoGuid").and_then(Value::as_str))
            .collect::<Vec<_>>();
        if ids.len() != photos.len() {
            bail!("Shared album response included an asset without a photo ID");
        }
        fs::create_dir_all(output_dir).with_context(|| {
            format!(
                "Could not create shared Photos directory {}",
                output_dir.display()
            )
        })?;
        let mut downloaded = Vec::new();
        let mut skipped = 0usize;
        for batch in ids.chunks(100) {
            let (_, urls) = self.shared_album_request(
                &host,
                &token,
                "webasseturls",
                &json!({"photoGuids":batch}),
            )?;
            let items = urls
                .get("items")
                .and_then(Value::as_object)
                .context("Apple returned invalid shared Photos asset URLs")?;
            for photo in photos.iter().filter(|photo| {
                photo
                    .get("photoGuid")
                    .and_then(Value::as_str)
                    .is_some_and(|id| batch.contains(&id))
            }) {
                let photo_id = photo["photoGuid"].as_str().unwrap_or_default();
                let derivatives = photo
                    .get("derivatives")
                    .and_then(Value::as_object)
                    .context("Shared photo has no downloadable derivatives")?;
                let (checksum, _) = derivatives
                    .iter()
                    .filter_map(|(size, derivative)| {
                        let checksum = derivative.get("checksum")?.as_str()?;
                        Some((checksum, size.parse::<u64>().unwrap_or(0)))
                    })
                    .max_by_key(|(_, size)| *size)
                    .context("Shared photo has no derivative checksum")?;
                let item = items
                    .get(checksum)
                    .context("Apple omitted a signed shared photo URL")?;
                let asset_host = item
                    .get("url_location")
                    .and_then(Value::as_str)
                    .context("Apple returned a shared photo URL without a host")?;
                if !(asset_host == "icloud-content.com"
                    || asset_host.ends_with(".icloud-content.com"))
                {
                    bail!("Apple returned an unexpected shared photo asset host");
                }
                let path = item
                    .get("url_path")
                    .and_then(Value::as_str)
                    .context("Apple returned a shared photo URL without a path")?;
                let asset_url = Url::parse(&format!("https://{asset_host}{path}"))?;
                if asset_url.scheme() != "https" {
                    bail!("Apple returned a non-HTTPS shared photo asset URL");
                }
                let response = self
                    .client
                    .get(asset_url.as_str())
                    .send()
                    .context("Could not download a shared Photos asset")?;
                if !response.status().is_success() {
                    bail!(
                        "Shared Photos asset download failed (HTTP {})",
                        response.status()
                    );
                }
                let content_type = response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("");
                let extension = if content_type.contains("video/quicktime") {
                    "mov"
                } else if content_type.contains("video/") {
                    "mp4"
                } else if content_type.contains("png") {
                    "png"
                } else if content_type.contains("webp") {
                    "webp"
                } else {
                    "jpg"
                };
                let filename =
                    photos_safe_filename(&format!("shared-{photo_id}.{extension}"), photo_id);
                let target = output_dir.join(filename);
                if target.exists() {
                    skipped += 1;
                    continue;
                }
                let bytes = response
                    .bytes()
                    .context("Could not read shared Photos asset bytes")?;
                let temporary = output_dir.join(format!(".icli-shared-{}.part", Uuid::new_v4()));
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temporary)
                    .context("Could not create a temporary Shared Album download")?;
                if let Err(error) = file.write_all(&bytes) {
                    let _ = fs::remove_file(&temporary);
                    return Err(error).context("Could not write Shared Album asset bytes");
                }
                drop(file);
                if let Err(error) = fs::hard_link(&temporary, &target) {
                    let _ = fs::remove_file(&temporary);
                    if error.kind() == std::io::ErrorKind::AlreadyExists {
                        skipped += 1;
                        continue;
                    }
                    return Err(error).with_context(|| {
                        format!("Could not create {} without overwriting", target.display())
                    });
                }
                fs::remove_file(&temporary)
                    .context("Could not remove temporary Shared Album download")?;
                downloaded.push(json!({"id":photo_id,"path":target,"bytes":bytes.len()}));
            }
        }
        Ok(
            json!({"album_id":token,"directory":output_dir,"downloaded":downloaded,"downloaded_count":downloaded.len(),"already_present":skipped,"truncated":album.get("photos").and_then(Value::as_array).is_some_and(|all|all.len()>limit)}),
        )
    }

    fn shared_album_request(
        &self,
        base: &str,
        token: &str,
        endpoint: &str,
        payload: &Value,
    ) -> Result<(String, Value)> {
        let mut current_base = base.to_owned();
        for attempt in 0..=1 {
            let url = format!("{current_base}/{token}/sharedstreams/{endpoint}");
            let response = self
                .client
                .post(&url)
                .header(reqwest::header::CONTENT_TYPE, "text/plain")
                .header(reqwest::header::CACHE_CONTROL, "no-cache")
                .json(payload)
                .send()
                .context("Could not contact Apple's shared Photos service")?;
            let status = response.status();
            let data = response.json::<Value>().unwrap_or(Value::Null);
            if status.as_u16() == 330 && attempt == 0 {
                let redirected = data
                    .get("X-Apple-MMe-Host")
                    .and_then(Value::as_str)
                    .context("Apple redirected shared Photos without a host")?;
                let parsed = Url::parse(&format!("https://{redirected}"))
                    .context("Apple returned an invalid shared Photos redirect")?;
                if parsed.scheme() != "https"
                    || parsed.host_str() != Some(redirected)
                    || !redirected.ends_with(".icloud.com")
                {
                    bail!("Apple returned an unexpected shared Photos redirect host");
                }
                current_base = parsed
                    .origin()
                    .ascii_serialization()
                    .trim_end_matches('/')
                    .to_owned();
                continue;
            }
            if !status.is_success() {
                bail!("Apple shared Photos request failed (HTTP {status})");
            }
            return Ok((current_base, data));
        }
        bail!("Apple shared Photos redirect could not be resolved")
    }

    pub fn photos_albums(&self) -> Result<Value> {
        let response = self.photos_cloudkit_request("records/query", &json!({"query":{"recordType":"CPLAlbumByPositionLive"},"zoneID":{"zoneName":"PrimarySync"},"resultsLimit":200}))?;
        let records = response
            .get("records")
            .and_then(Value::as_array)
            .context("Apple returned an invalid Photos albums response")?;
        let mut albums = records.iter().filter_map(|record| {
            let fields=record.get("fields")?;
            let name=fields.get("albumNameEnc")?.get("value")?.as_str()?;
            let decoded=STANDARD.decode(name).ok()?;
            let name=String::from_utf8(decoded).ok()?;
            Some(json!({"id":record.get("recordName"),"name":name,"deleted":fields.get("isDeleted").and_then(|v|v.get("value")).and_then(Value::as_i64).unwrap_or(0)!=0}))
        }).filter(|album| album["deleted"].as_bool()!=Some(true)).collect::<Vec<_>>();
        albums.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        Ok(
            json!({"library":"private","albums":albums,"smart_albums":["All Photos","Videos","Favorites","Screenshots","Recently Deleted","Hidden"]}),
        )
    }

    pub fn photos_libraries(&self) -> Result<Value> {
        let response = self.photos_cloudkit_request("zones/list", &json!({}))?;
        let zones = response
            .get("zones")
            .and_then(Value::as_array)
            .context("Apple returned an invalid Photos libraries response")?;
        let mut libraries = zones
            .iter()
            .filter(|zone| zone.get("deleted").and_then(Value::as_bool) != Some(true))
            .filter_map(|zone| {
                let name = zone.pointer("/zoneID/zoneName")?.as_str()?;
                Some(json!({
                    "id": if name == "PrimarySync" { "private".to_owned() } else { name.to_owned() },
                    "name": if name == "PrimarySync" { "Private Library".to_owned() } else { format!("Shared Library ({name})") },
                    "zone_name": name,
                    "scope": if name == "PrimarySync" { "private" } else { "shared" }
                }))
            })
            .collect::<Vec<_>>();
        if !libraries.iter().any(|library| library["id"] == "private") {
            libraries.insert(0, json!({"id":"private","name":"Private Library","zone_name":"PrimarySync","scope":"private"}));
        }
        Ok(json!({"libraries":libraries,"count":libraries.len()}))
    }

    pub fn photos_sync_cursor(&self) -> Result<Value> {
        let response = self.photos_cloudkit_request("zones/list", &json!({}))?;
        let zone = response
            .get("zones")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|zone| {
                zone.pointer("/zoneID/zoneName").and_then(Value::as_str) == Some("PrimarySync")
            })
            .context("Apple did not return the private Photos library zone")?;
        let cursor = zone
            .get("syncToken")
            .cloned()
            .context("Apple did not return a Photos sync cursor")?;
        Ok(json!({"library":"private","sync_cursor":cursor}))
    }

    pub fn photos_changes(&self, since: &str, limit: usize) -> Result<Value> {
        if since.is_empty() || since.chars().any(char::is_control) {
            bail!("Provide a Photos sync cursor from `icli photos sync-cursor`");
        }
        if limit == 0 || limit > 1000 {
            bail!("Photos changes --limit must be from 1 to 1000");
        }
        let mut cursor = serde_json::from_str::<Value>(since).unwrap_or_else(|_| json!(since));
        let mut changes = Vec::new();
        let mut pages = 0usize;
        let mut more = true;
        while more && changes.len() < limit && pages < 200 {
            let response = self.photos_cloudkit_request("changes/zone", &json!({
                "zones":[{"zoneID":{"zoneName":"PrimarySync","zoneType":"REGULAR_CUSTOM_ZONE"},"syncToken":cursor,"reverse":false,"desiredRecordTypes":["CPLAsset","CPLMaster"]}],
                "resultsLimit":limit.saturating_sub(changes.len()).max(1)
            }))?;
            let zone = response
                .get("zones")
                .and_then(Value::as_array)
                .and_then(|zones| zones.first())
                .context("Apple returned an invalid Photos changes response")?;
            if let Some(code) = zone.get("serverErrorCode").and_then(Value::as_str) {
                bail!("Apple Photos changes request failed ({code})");
            }
            if let Some(next_cursor) = zone.get("syncToken") {
                cursor = next_cursor.clone();
            }
            changes.extend(
                zone.get("records")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|record| {
                        let id = record.get("recordName")?.as_str()?;
                        Some(json!({
                            "id":id,
                            "type":record.get("recordType"),
                            "master_id":if record.get("recordType").and_then(Value::as_str) == Some("CPLAsset") { record.pointer("/fields/masterRef/value/recordName") } else { None },
                            "deleted":record.get("deleted").and_then(Value::as_bool).unwrap_or(record.get("recordType").is_none()),
                            "modified":record.get("modified")
                        }))
                    }),
            );
            if changes.len() > limit {
                changes.truncate(limit);
            }
            more = zone.get("moreComing").and_then(Value::as_bool) == Some(true);
            pages += 1;
        }
        if more && pages >= 200 {
            bail!(
                "Photos changes exceeded 200 pages; save the returned cursor and retry with a narrower workflow"
            );
        }
        Ok(
            json!({"library":"private","changes":changes,"sync_cursor":cursor,"more_available":more}),
        )
    }

    pub fn photos_list(&self, skip: usize, limit: usize, album: Option<&str>) -> Result<Value> {
        if limit == 0 || limit > 100 {
            bail!("Photos --limit must be from 1 to 100");
        }
        let (record_type, album_filter) = match album.map(str::trim).filter(|name| !name.is_empty())
        {
            None | Some("All Photos") | Some("Library") => ("CPLAssetAndMasterByAddedDate", None),
            Some(name) => {
                let smart = match name.to_ascii_lowercase().as_str() {
                    "favorites" => Some(("CPLAssetAndMasterInSmartAlbumByAssetDate", "Favorite")),
                    "screenshots" => {
                        Some(("CPLAssetAndMasterInSmartAlbumByAssetDate", "Screenshot"))
                    }
                    "videos" => Some(("CPLAssetAndMasterInSmartAlbumByAssetDate", "Video")),
                    "live" => Some(("CPLAssetAndMasterInSmartAlbumByAssetDate", "Live")),
                    "panoramas" => Some(("CPLAssetAndMasterInSmartAlbumByAssetDate", "Panorama")),
                    "slo-mo" => Some(("CPLAssetAndMasterInSmartAlbumByAssetDate", "Slomo")),
                    "time-lapse" => Some(("CPLAssetAndMasterInSmartAlbumByAssetDate", "Timelapse")),
                    "hidden" => Some(("CPLAssetAndMasterHiddenByAssetDate", "")),
                    "recently deleted" => Some(("CPLAssetAndMasterDeletedByExpungedDate", "")),
                    _ => None,
                };
                if let Some((record_type, smart_album)) = smart {
                    let filter = (!smart_album.is_empty()).then(|| json!({"fieldName":"smartAlbum","fieldValue":{"type":"STRING","value":smart_album},"comparator":"EQUALS"}));
                    (record_type, filter)
                } else {
                    let albums = self.photos_albums()?;
                    let album_id = albums
                        .get("albums")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .find(|item| {
                            item.get("name")
                                .and_then(Value::as_str)
                                .is_some_and(|album_name| album_name.eq_ignore_ascii_case(name))
                        })
                        .and_then(|item| item.get("id"))
                        .and_then(Value::as_str)
                        .with_context(|| format!("No iCloud Photos album matched '{name}'"))?;
                    (
                        "CPLContainerRelationLiveByAssetDate",
                        Some(
                            json!({"fieldName":"parentId","fieldValue":{"type":"STRING","value":album_id},"comparator":"EQUALS"}),
                        ),
                    )
                }
            }
        };
        let mut filters = vec![
            json!({"fieldName":"startRank","fieldValue":{"type":"INT64","value":skip as i64},"comparator":"EQUALS"}),
            json!({"fieldName":"direction","fieldValue":{"type":"STRING","value":"ASCENDING"},"comparator":"EQUALS"}),
        ];
        if let Some(filter) = album_filter {
            filters.push(filter);
        }
        let request = json!({
            "query":{"recordType":record_type,"filterBy":filters},"resultsLimit":limit.saturating_mul(2).min(200),"zoneID":{"zoneName":"PrimarySync"},
            "desiredKeys":["filenameEnc","assetDate","addedDate","isFavorite","isHidden","itemType","resOriginalWidth","resOriginalHeight","resOriginalRes","masterRef","recordName","recordType"]
        });
        let response = self.photos_cloudkit_request("records/query", &request)?;
        let records = response
            .get("records")
            .and_then(Value::as_array)
            .context("Apple returned an invalid Photos asset response")?;
        let assets = records
            .iter()
            .filter(|r| r.get("recordType").and_then(Value::as_str) == Some("CPLAsset"))
            .filter_map(|r| {
                r.get("fields")
                    .and_then(|f| f.get("masterRef"))
                    .and_then(|v| v.get("value"))
                    .and_then(|v| v.get("recordName"))
                    .and_then(Value::as_str)
                    .map(|name| (name, r))
            })
            .collect::<BTreeMap<_, _>>();
        let masters=records.iter().filter(|r|r.get("recordType").and_then(Value::as_str)==Some("CPLMaster")).take(limit).map(|master| {
            let fields=master.get("fields");
            let name=fields.and_then(|f|f.get("filenameEnc")).and_then(|v|v.get("value")).and_then(Value::as_str).and_then(|v|STANDARD.decode(v).ok()).map(|v|String::from_utf8_lossy(&v).to_string());
            let asset_id=master.get("recordName").and_then(Value::as_str).unwrap_or_default();
            let asset=assets.get(asset_id).and_then(|r|r.get("fields"));
            json!({"id":asset_id,"filename":name,"date":asset.and_then(|f|f.get("assetDate")).and_then(|v|v.get("value")),"added":asset.and_then(|f|f.get("addedDate")).and_then(|v|v.get("value")),"favorite":asset.and_then(|f|f.get("isFavorite")).and_then(|v|v.get("value")),"hidden":asset.and_then(|f|f.get("isHidden")).and_then(|v|v.get("value")),"width":fields.and_then(|f|f.get("resOriginalWidth")).and_then(|v|v.get("value")),"height":fields.and_then(|f|f.get("resOriginalHeight")).and_then(|v|v.get("value")),"size":fields.and_then(|f|f.get("resOriginalRes")).and_then(|v|v.get("value")).and_then(|v|v.get("size"))})
        }).collect::<Vec<_>>();
        Ok(
            json!({"skip":skip,"limit":limit,"photos":masters,"more_available":response.get("continuationMarker").and_then(Value::as_str).is_some()}),
        )
    }

    pub fn photos_get(&self, id: &str) -> Result<Value> {
        let response = self.photos_cloudkit_request(
            "records/lookup",
            &json!({
                "records":[{"recordName":id}],
                "zoneID":{"zoneName":"PrimarySync"},
                "desiredKeys":[
                    "filenameEnc","assetDate","addedDate","isFavorite","isHidden","itemType",
                    "resOriginalWidth","resOriginalHeight","resOriginalRes",
                    "resJPEGMedRes","resJPEGMedWidth","resJPEGMedHeight",
                    "resJPEGThumbRes","resJPEGThumbWidth","resJPEGThumbHeight",
                    "resVidMedRes","resVidSmallRes","recordChangeTag"
                ]
            }),
        )?;
        let record = response
            .get("records")
            .and_then(Value::as_array)
            .and_then(|rows| {
                rows.iter()
                    .find(|r| r.get("recordName").and_then(Value::as_str) == Some(id))
            })
            .context("No iCloud Photos asset matched that ID")?;
        if let Some(code) = record.get("serverErrorCode").and_then(Value::as_str) {
            bail!("Apple Photos lookup failed ({code})")
        }
        Ok(record.clone())
    }

    pub fn photos_download(&self, id: &str, version: &str, output: &Path) -> Result<Value> {
        let record = self.photos_get(id)?;
        let version_key = match version {
            "original" => "resOriginalRes",
            "medium" => {
                if record.pointer("/fields/resVidMedRes").is_some() {
                    "resVidMedRes"
                } else {
                    "resJPEGMedRes"
                }
            }
            "thumbnail" => {
                if record.pointer("/fields/resVidSmallRes").is_some() {
                    "resVidSmallRes"
                } else {
                    "resJPEGThumbRes"
                }
            }
            _ => bail!("Photo version must be original, medium, or thumbnail"),
        };
        let url = record
            .pointer(&format!("/fields/{version_key}/value/downloadURL"))
            .and_then(Value::as_str)
            .context("Apple did not return an original photo download URL")?;
        let url = Url::parse(url).context("Apple returned an invalid photo download URL")?;
        if url.scheme() != "https" {
            bail!("Apple returned a non-HTTPS photo download URL")
        }
        let mut response = self
            .client
            .get(url)
            .send()
            .context("Could not download the iCloud photo")?;
        if !response.status().is_success() {
            bail!("iCloud Photos download failed (HTTP {})", response.status())
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)
            .with_context(|| {
                format!(
                    "Could not create {} without overwriting an existing file",
                    output.display()
                )
            })?;
        let bytes =
            std::io::copy(&mut response, &mut file).context("Could not save the iCloud photo")?;
        Ok(json!({"id":id,"version":version,"path":output,"bytes":bytes}))
    }

    pub fn photos_sync(&self, directory: &Path, album: Option<&str>) -> Result<Value> {
        fs::create_dir_all(directory).with_context(|| {
            format!(
                "Could not create Photos sync directory {}",
                directory.display()
            )
        })?;
        let mut skip = 0usize;
        let mut downloaded = Vec::new();
        let mut present = 0usize;
        loop {
            let page = self.photos_list(skip, 100, album)?;
            let photos = page
                .get("photos")
                .and_then(Value::as_array)
                .context("Photos list response omitted its photos array")?;
            if photos.is_empty() {
                break;
            }
            for photo in photos {
                let id = photo
                    .get("id")
                    .and_then(Value::as_str)
                    .context("Photos list returned an asset without an ID")?;
                let name = photo
                    .get("filename")
                    .and_then(Value::as_str)
                    .unwrap_or("photo");
                if let Some(saved) = self.photos_sync_one(directory, id, name)? {
                    downloaded.push(saved);
                } else {
                    present += 1;
                }
            }
            skip = skip.saturating_add(photos.len());
            if photos.len() < 100 {
                break;
            }
        }
        Ok(
            json!({"directory":directory,"album":album,"downloaded":downloaded,"downloaded_count":downloaded.len(),"already_present":present}),
        )
    }

    pub fn photos_watch(&self, directory: &Path, album: Option<&str>, interval: u64) -> Result<()> {
        if !(60..=86_400).contains(&interval) {
            bail!("Photos watch interval must be from 60 to 86400 seconds");
        }
        let mut cursor = self
            .photos_sync_cursor()?
            .pointer("/sync_cursor")
            .and_then(Value::as_str)
            .context("Apple returned an invalid Photos sync cursor")?
            .to_owned();
        let initial = self.photos_sync(directory, album)?;
        eprintln!(
            "Initial Photos sync: {} new, {} already present",
            initial["downloaded_count"], initial["already_present"]
        );
        loop {
            thread::sleep(Duration::from_secs(interval));
            let mut new_count = 0usize;
            loop {
                let changes = self.photos_changes(&cursor, 1000)?;
                cursor = changes
                    .pointer("/sync_cursor")
                    .and_then(Value::as_str)
                    .context("Apple omitted the next Photos sync cursor")?
                    .to_owned();
                for change in changes
                    .get("changes")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if change.get("deleted").and_then(Value::as_bool) == Some(true) {
                        continue;
                    }
                    let id = match change.get("type").and_then(Value::as_str) {
                        Some("CPLMaster") => change.get("id").and_then(Value::as_str),
                        Some("CPLAsset") => change.get("master_id").and_then(Value::as_str),
                        _ => None,
                    };
                    let Some(id) = id else { continue };
                    if self.photos_sync_changed_asset(directory, id)?.is_some() {
                        new_count += 1;
                    }
                }
                if changes.get("more_available").and_then(Value::as_bool) != Some(true) {
                    break;
                }
            }
            eprintln!("Photos changes applied: {new_count} new files");
        }
    }

    fn photos_sync_one(&self, directory: &Path, id: &str, filename: &str) -> Result<Option<Value>> {
        let target = directory.join(photos_safe_filename(filename, id));
        if target.exists() {
            return Ok(None);
        }
        let temporary = directory.join(format!(".icli-photos-{}.part", Uuid::new_v4()));
        if let Err(error) = self.photos_download(id, "original", &temporary) {
            let _ = fs::remove_file(&temporary);
            return Err(error).with_context(|| format!("Could not sync photo {id}"));
        }
        if let Err(error) = fs::hard_link(&temporary, &target) {
            let _ = fs::remove_file(&temporary);
            return Err(error).with_context(|| {
                format!(
                    "Could not create Photos sync file {} without overwriting",
                    target.display()
                )
            });
        }
        fs::remove_file(&temporary).with_context(|| {
            format!(
                "Could not remove temporary Photos file {}",
                temporary.display()
            )
        })?;
        Ok(Some(json!({"id":id,"path":target})))
    }

    fn photos_sync_changed_asset(&self, directory: &Path, id: &str) -> Result<Option<Value>> {
        let record = self.photos_get(id)?;
        let filename = record
            .pointer("/fields/filenameEnc/value")
            .and_then(Value::as_str)
            .and_then(|encoded| STANDARD.decode(encoded).ok())
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_else(|| "photo".to_owned());
        self.photos_sync_one(directory, id, &filename)
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

    fn notes_cloudkit_root(&self) -> Result<Url> {
        let service = self
            .session
            .account_data
            .pointer("/webservices/ckdatabasews/url")
            .and_then(Value::as_str)
            .context("Apple did not advertise its Notes CloudKit service")?;
        let service = Url::parse(&format!("{}/", service.trim_end_matches('/')))
            .context("Apple advertised an invalid CloudKit service URL")?;
        if service.scheme() != "https"
            && !(self.endpoints.setup_override.is_some() && service.host_str() == Some("127.0.0.1"))
        {
            bail!("Apple advertised a non-HTTPS CloudKit service URL");
        }
        let mut url = service.join("database/1/com.apple.notes/production/private")?;
        url.query_pairs_mut()
            .append_pair("remapEnums", "true")
            .append_pair("getCurrentSyncToken", "true");
        for (name, value) in service_params(&self.session) {
            url.query_pairs_mut().append_pair(&name, &value);
        }
        Ok(url)
    }

    fn notes_cloudkit_request(&self, path: &str, payload: &Value) -> Result<Value> {
        let mut url = self.notes_cloudkit_root()?;
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
            .context("Could not contact Apple's Notes CloudKit service")?;
        let status = response.status();
        let body = response.json::<Value>().unwrap_or(Value::Null);
        if matches!(status.as_u16(), 401 | 403 | 421)
            || body.get("hsaChallengeRequired").and_then(Value::as_bool) == Some(true)
        {
            return Err(recovery(
                &self.session.account,
                "auth_refresh_required",
                format!("Apple Notes CloudKit rejected the saved session (HTTP {status})"),
                "refresh",
            ));
        }
        if !status.is_success() {
            bail!("Apple Notes CloudKit request failed (HTTP {status})");
        }
        Ok(body)
    }

    fn request_notes_pcs_access(&mut self, next_command: &str) -> Result<()> {
        if self.session.notes_pcs_ready {
            return Ok(());
        }
        let state = self.apple_pcs_post("requestWebAccessState", None)?;
        if state.get("isICDRSDisabled").and_then(Value::as_bool) != Some(true) {
            self.session.notes_pcs_ready = true;
            return Ok(());
        }
        if state
            .get("isDeviceConsentedForPCS")
            .and_then(Value::as_bool)
            == Some(false)
        {
            let consent = self.apple_pcs_post("enableDeviceConsentForPCS", None)?;
            if consent
                .get("isDeviceConsentNotificationSent")
                .and_then(Value::as_bool)
                != Some(true)
            {
                return Err(RemindersAccessRecovery {
                    code: "notes_access_required",
                    message:
                        "Apple could not request trusted-device approval for Notes data access"
                            .into(),
                    next_command: next_command.into(),
                }
                .into());
            }
            return Err(RemindersAccessRecovery {
                code: "notes_access_required",
                message: "Apple requested trusted-device approval for Notes data access; approve it, then retry the Notes command".into(),
                next_command: next_command.into(),
            }
            .into());
        }
        for attempt in 0..10 {
            let response = self.apple_pcs_post(
                "requestPCS",
                Some(&json!({
                    "appName": "notes",
                    "derivedFromUserAction": attempt == 0,
                })),
            )?;
            if response.get("status").and_then(Value::as_str) == Some("success") {
                self.session.notes_pcs_ready = true;
                return Ok(());
            }
            let message = response.get("message").and_then(Value::as_str);
            if !matches!(
                message,
                Some("Requested the device to upload cookies.")
                    | Some("Cookies not available yet on server.")
            ) {
                return Err(RemindersAccessRecovery {
                    code: "notes_access_required",
                    message: "Apple has not granted Notes data access yet; approve the request on a trusted device, then retry".into(),
                    next_command: next_command.into(),
                }
                .into());
            }
            if attempt < 9 {
                thread::sleep(Duration::from_secs(5));
            }
        }
        Err(RemindersAccessRecovery {
            code: "notes_access_required",
            message: "Apple Notes data access is still pending; approve it on a trusted device, then retry".into(),
            next_command: next_command.into(),
        }
        .into())
    }

    fn notes_zone_records(&self, record_type: &str, sync_token: Option<&str>) -> Result<Value> {
        let mut request = json!({
            "zones": [{
                "zoneID": {"zoneName": "Notes", "zoneType": "REGULAR_CUSTOM_ZONE"},
                "desiredRecordTypes": if record_type == "Note" { json!(["Note", "PasswordProtectedNote"]) } else { json!([record_type]) },
                "desiredKeys": ["TitleEncrypted", "SnippetEncrypted", "ModificationDate", "Deleted", "Folder", "ParentFolder", "HasSubfolder", "share", "participants"],
                "reverse": true,
            }]
        });
        if let Some(token) = sync_token {
            request["zones"][0]["syncToken"] = json!(token);
        }
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = std::collections::HashSet::new();
        if let Some(token) = sync_token {
            seen_cursors.insert(token.to_owned());
        }
        loop {
            if let Some(token) = cursor.take() {
                if !seen_cursors.insert(token.clone()) {
                    bail!("Apple repeated a Notes pagination cursor");
                }
                request["zones"][0]["syncToken"] = json!(token);
            }
            let response = self.notes_cloudkit_request("changes/zone", &request)?;
            let zone = response
                .get("zones")
                .and_then(Value::as_array)
                .and_then(|zones| zones.first())
                .context("Apple returned an invalid Notes zone response")?;
            if let Some(code) = zone.get("serverErrorCode").and_then(Value::as_str) {
                bail!("Apple Notes zone read failed ({code})");
            }
            if let Some(items) = zone.get("records").and_then(Value::as_array) {
                all.extend(items.iter().cloned());
            }
            if zone.get("moreComing").and_then(Value::as_bool) != Some(true) {
                return Ok(json!({"records":all,"sync_token":zone.get("syncToken")}));
            }
            cursor = Some(
                zone.get("syncToken")
                    .and_then(Value::as_str)
                    .context("Apple omitted the Notes pagination token")?
                    .to_owned(),
            );
        }
    }

    pub fn notes_folders(&mut self) -> Result<Vec<Value>> {
        let next = format!(
            "icli notes folders --email {}",
            crate::cli_quote(&self.session.account)
        );
        self.request_notes_pcs_access(&next)?;
        let response = self.notes_zone_records("Folder", None)?;
        let mut rows = response["records"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|record| record.get("recordType").and_then(Value::as_str) == Some("Folder"))
            .filter(|record| !cloudkit_field_truthy(record.get("fields"), "Deleted"))
            .map(|record| {
                let fields = record.get("fields");
                json!({
                    "id":record.get("recordName"),
                    "name":notes_field_text(fields, "TitleEncrypted"),
                    "parent_id":notes_reference(fields, "ParentFolder"),
                    "has_subfolders":cloudkit_field_truthy(fields, "HasSubfolder"),
                    "deleted":cloudkit_field_truthy(fields, "Deleted"),
                })
            })
            .collect::<Vec<_>>();
        rows.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        Ok(rows)
    }

    pub fn notes_recent(&mut self, skip: usize, limit: usize) -> Result<(Vec<Value>, bool)> {
        self.notes_search(None, skip, limit)
    }

    pub fn notes_search(
        &mut self,
        title: Option<&str>,
        skip: usize,
        limit: usize,
    ) -> Result<(Vec<Value>, bool)> {
        if let Some(title) = title {
            let title = title.trim();
            if title.is_empty() || title.len() > 256 || title.chars().any(char::is_control) {
                bail!(
                    "Invalid Notes title query; use 1 to 256 characters without control characters"
                );
            }
        }
        self.notes_search_in_folder(title, None, skip, limit)
    }

    pub fn notes_search_all(
        &mut self,
        title: &str,
        skip: usize,
        limit: usize,
    ) -> Result<(Vec<Value>, bool, Option<String>)> {
        let title = title.trim();
        if title.is_empty() || title.len() > 256 || title.chars().any(char::is_control) {
            bail!("Invalid Notes title query; use 1 to 256 characters without control characters");
        }
        if limit == 0 {
            return Ok((Vec::new(), false, None));
        }
        let next = format!(
            "icli notes search {} --all --email {} --skip {skip} --limit {limit}",
            crate::cli_quote(title),
            crate::cli_quote(&self.session.account)
        );
        self.request_notes_pcs_access(&next)?;
        let response = self.notes_zone_records("Note", None)?;
        let cursor = response
            .get("sync_token")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let query = title.to_lowercase();
        let mut rows = response["records"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|record| {
                matches!(
                    record.get("recordType").and_then(Value::as_str),
                    Some("Note" | "PasswordProtectedNote")
                )
            })
            .map(notes_summary)
            .filter(|row| row["deleted"].as_bool() != Some(true))
            .filter(|row| {
                row["title"]
                    .as_str()
                    .unwrap_or_default()
                    .to_lowercase()
                    .contains(&query)
            })
            .collect::<Vec<_>>();
        rows.sort_by(|a, b| b["modified"].as_str().cmp(&a["modified"].as_str()));
        let more = rows.len() > skip.saturating_add(limit);
        let rows = rows.into_iter().skip(skip).take(limit).collect();
        Ok((rows, more, cursor))
    }

    /// Search decrypted note titles and bodies. This is intentionally opt-in
    /// and restricted to --all so callers know it scans and downloads notes.
    pub fn notes_search_content(
        &mut self,
        query: &str,
        skip: usize,
        limit: usize,
    ) -> Result<(Vec<Value>, bool, usize)> {
        let query = query.trim();
        if query.is_empty() || query.len() > 256 || query.chars().any(char::is_control) {
            bail!(
                "Invalid Notes content query; use 1 to 256 characters without control characters"
            );
        }
        if limit == 0 {
            return Ok((Vec::new(), false, 0));
        }
        let (notes, _, _) = self.notes_list_all(0, usize::MAX, None, None)?;
        let needle = query.to_lowercase();
        let mut matches = Vec::new();
        let mut unavailable = 0;
        for note in notes {
            if note["deleted"].as_bool() == Some(true) {
                continue;
            }
            let Some(id) = note["id"].as_str() else {
                continue;
            };
            let full = self.notes_get(id, false)?;
            let text = full["text"].as_str();
            if text.is_none() {
                unavailable += 1;
            }
            let title = note["title"].as_str().unwrap_or_default();
            if title.to_lowercase().contains(&needle)
                || text.is_some_and(|body| body.to_lowercase().contains(&needle))
            {
                matches.push(note);
            }
        }
        let more = matches.len() > skip.saturating_add(limit);
        Ok((
            matches.into_iter().skip(skip).take(limit).collect(),
            more,
            unavailable,
        ))
    }

    pub fn notes_recent_in_folder(
        &mut self,
        folder_id: &str,
        skip: usize,
        limit: usize,
    ) -> Result<(Vec<Value>, bool, Option<String>)> {
        let (rows, more) = self.notes_search_in_folder(None, Some(folder_id), skip, limit)?;
        Ok((rows, more, None))
    }

    fn notes_search_in_folder(
        &mut self,
        title: Option<&str>,
        folder_id: Option<&str>,
        skip: usize,
        limit: usize,
    ) -> Result<(Vec<Value>, bool)> {
        if limit == 0 {
            return Ok((Vec::new(), false));
        }
        let operation = if let Some(folder) = folder_id {
            format!("list --folder-id {}", crate::cli_quote(folder))
        } else if let Some(title) = title {
            format!("search {}", crate::cli_quote(title))
        } else {
            "recent".to_owned()
        };
        let next = format!(
            "icli notes {operation} --email {} --skip {skip} --limit {limit}",
            crate::cli_quote(&self.session.account)
        );
        self.request_notes_pcs_access(&next)?;
        let filters = vec![
            json!({"comparator":"EQUALS","fieldName":"indexName","fieldValue":{"type":"STRING","value":"recents"}}),
        ];
        let mut request = json!({
            "query": {
                "recordType": "SearchIndexes",
                "filterBy": filters,
                "sortBy": [{"fieldName":"modTime","ascending":false}]
            },
            "zoneID": {"zoneName":"Notes","zoneType":"REGULAR_CUSTOM_ZONE"},
            "desiredKeys": ["TitleEncrypted","SnippetEncrypted","ModificationDate","Deleted","Folder"],
            "resultsLimit": 200
        });
        let mut rows = Vec::new();
        let mut remaining_skip = skip;
        let mut seen_markers = std::collections::HashSet::new();
        loop {
            let response = self.notes_cloudkit_request("records/query", &request)?;
            let records = response
                .get("records")
                .and_then(Value::as_array)
                .context("Apple returned an invalid Notes query response")?;
            for record in records {
                if let Some(code) = record.get("serverErrorCode").and_then(Value::as_str) {
                    bail!("Apple Notes query failed ({code})");
                }
                let row = notes_summary(record);
                if row["deleted"].as_bool() == Some(true) {
                    continue;
                }
                if folder_id.is_some_and(|folder| {
                    row["folder_id"].as_str() != Some(folder)
                        && row["folder_id"].as_str()
                            != Some(notes_record_name(folder, "Folder").as_str())
                }) {
                    continue;
                }
                if title.is_some_and(|query| {
                    !row["title"]
                        .as_str()
                        .unwrap_or_default()
                        .to_lowercase()
                        .contains(&query.to_lowercase())
                }) {
                    continue;
                }
                if remaining_skip > 0 {
                    remaining_skip -= 1;
                    continue;
                }
                rows.push(row);
                if rows.len() > limit {
                    break;
                }
            }
            if rows.len() > limit {
                break;
            }
            match response.get("continuationMarker").and_then(Value::as_str) {
                Some(marker) if !marker.is_empty() => {
                    if !seen_markers.insert(marker.to_owned()) {
                        bail!("Apple repeated a Notes search pagination marker");
                    }
                    request["continuationMarker"] = json!(marker);
                }
                _ => break,
            }
        }
        let more = rows.len() > limit;
        rows.truncate(limit);
        Ok((rows, more))
    }

    pub fn notes_list_all(
        &mut self,
        skip: usize,
        limit: usize,
        since: Option<&str>,
        folder_id: Option<&str>,
    ) -> Result<(Vec<Value>, bool, Option<String>)> {
        if limit == 0 {
            return Ok((Vec::new(), false, None));
        }
        let mut next = format!(
            "icli notes list --email {} --all --skip {skip} --limit {limit}",
            crate::cli_quote(&self.session.account)
        );
        if let Some(folder) = folder_id {
            next.push_str(&format!(" --folder-id {}", crate::cli_quote(folder)));
        }
        if let Some(cursor) = since {
            next.push_str(&format!(" --since {}", crate::cli_quote(cursor)));
        }
        self.request_notes_pcs_access(&next)?;
        let response = self.notes_zone_records("Note", since)?;
        let token = response
            .get("sync_token")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut rows = response["records"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|record| {
                matches!(
                    record.get("recordType").and_then(Value::as_str),
                    Some("Note" | "PasswordProtectedNote")
                )
            })
            .map(notes_summary)
            .collect::<Vec<_>>();
        if let Some(folder_id) = folder_id {
            let folder_id = notes_record_name(folder_id, "Folder");
            let short_folder_id = folder_id.rsplit('/').next().unwrap_or(&folder_id);
            rows.retain(|row| {
                row["folder_id"].as_str() == Some(folder_id.as_str())
                    || row["folder_id"].as_str() == Some(short_folder_id)
            });
        }
        rows.sort_by(|a, b| b["modified"].as_str().cmp(&a["modified"].as_str()));
        let more = rows.len() > skip.saturating_add(limit);
        let rows = rows.into_iter().skip(skip).take(limit).collect();
        Ok((rows, more, token))
    }

    pub fn notes_get(&mut self, id: &str, with_attachments: bool) -> Result<Value> {
        let next = format!(
            "icli notes get {} --email {}",
            crate::cli_quote(id),
            crate::cli_quote(&self.session.account)
        );
        self.request_notes_pcs_access(&next)?;
        let response = self.notes_cloudkit_request("records/lookup", &json!({
            "records":[{"recordName":notes_record_name(id,"Note")}],
            "zoneID":{"zoneName":"Notes","zoneType":"REGULAR_CUSTOM_ZONE"},
            "desiredKeys":["TitleEncrypted","SnippetEncrypted","TextDataEncrypted","ModificationDate","Deleted","Folder","Attachments","ReplicaIDToNotesVersionDataEncrypted"]
        }))?;
        let record_name = notes_record_name(id, "Note");
        let record = response
            .get("records")
            .and_then(Value::as_array)
            .and_then(|items| {
                items.iter().find(|item| {
                    item.get("recordName").and_then(Value::as_str) == Some(record_name.as_str())
                })
            })
            .context("No Apple Notes record found with that ID")?;
        if let Some(code) = record.get("serverErrorCode").and_then(Value::as_str) {
            bail!("Apple Notes record lookup failed ({code})");
        }
        if record.get("fields").and_then(Value::as_object).is_none() {
            bail!("Apple returned a Notes lookup record without fields");
        }
        let mut row = notes_summary(record);
        let body = notes_field_bytes(record.get("fields"), "TextDataEncrypted");
        row["text"] = body
            .and_then(decode_notes_body)
            .map(Value::String)
            .unwrap_or(Value::Null);
        if with_attachments {
            row["attachments"] = json!(self.notes_attachment_metadata(id)?);
        }
        Ok(row)
    }

    /// Create a basic plaintext Apple Note. Notes stores body text in a
    /// compressed topotext document; CloudKit handles field encryption.
    pub fn notes_create(&mut self, title: &str, body: &str, folder: Option<&str>) -> Result<Value> {
        let next = format!("icli notes create --title {}", crate::cli_quote(title));
        self.request_notes_pcs_access(&next)?;
        let title = title.trim();
        if title.is_empty() && body.trim().is_empty() {
            bail!("A note needs a non-empty title or body");
        }
        let folder_id = folder.unwrap_or("DefaultFolder-CloudKit");
        if folder_id.is_empty() || folder_id.chars().any(char::is_control) {
            bail!("Invalid Notes folder ID");
        }
        let (note_text, note_title, snippet) = notes_compose_text(title, body);
        let replica = Uuid::new_v4().into_bytes();
        let encoded = encode_new_note_body(&replica, &note_text)?;
        let now = Utc::now().timestamp_millis();
        let record_name = Uuid::new_v4().to_string().to_uppercase();
        let response = self.notes_cloudkit_request(
            "records/modify",
            &json!({
                "atomic":true,
                "zoneID":{"zoneName":"Notes","zoneType":"REGULAR_CUSTOM_ZONE"},
                "operations":[{"operationType":"create","record":{
                    "recordName":record_name,"recordType":"Note","fields":{
                        "TextDataEncrypted":{"type":"ENCRYPTED_BYTES","value":STANDARD.encode(encoded)},
                        "TitleEncrypted":{"type":"ENCRYPTED_STRING","value":STANDARD.encode(note_title.as_bytes())},
                        "SnippetEncrypted":{"type":"ENCRYPTED_STRING","value":STANDARD.encode(snippet.as_bytes())},
                        "Folder":{"type":"REFERENCE","value":{"recordName":folder_id,"action":"NONE","zoneID":{"zoneName":"Notes","zoneType":"REGULAR_CUSTOM_ZONE"}}},
                        "CreationDate":{"type":"TIMESTAMP","value":now},
                        "ModificationDate":{"type":"TIMESTAMP","value":now}
                    }
                }}]
            }),
        )?;
        let result = cloudkit_single_record(&response, "Apple Notes create")?;
        if let Some(code) = result.get("serverErrorCode").and_then(Value::as_str) {
            bail!("Apple Notes create failed ({code})");
        }
        let id = result
            .get("recordName")
            .and_then(Value::as_str)
            .unwrap_or(&record_name);
        let verified = self.notes_get(id, false)?;
        if verified.get("title").and_then(Value::as_str) != Some(note_title.as_str())
            || verified.get("text").and_then(Value::as_str) != Some(note_text.as_str())
        {
            bail!(
                "Apple accepted the note create, but readback differs; inspect Notes before retrying"
            );
        }
        Ok(json!({"id":id,"title":note_title,"folder_id":folder_id,"created":true,"verified":true}))
    }

    /// Replace a note's plain text while preserving its folder and creation
    /// date. Rich formatting and attachments are intentionally not round-tripped.
    pub fn notes_update(
        &mut self,
        id: &str,
        title: Option<&str>,
        body: Option<&str>,
    ) -> Result<Value> {
        if title.is_none() && body.is_none() {
            bail!("Provide --title or --body to update");
        }
        let next = format!("icli notes update {} --body TEXT", crate::cli_quote(id));
        self.request_notes_pcs_access(&next)?;
        let record_name = notes_record_name(id, "Note");
        let lookup = self.notes_cloudkit_request(
            "records/lookup",
            &json!({
                "records":[{"recordName":record_name}],
                "zoneID":{"zoneName":"Notes","zoneType":"REGULAR_CUSTOM_ZONE"},
                "desiredKeys":["TitleEncrypted","SnippetEncrypted","TextDataEncrypted","Folder","Deleted","Attachments","share","participants","ReplicaIDToNotesVersionDataEncrypted"]
            }),
        )?;
        let record = cloudkit_single_record(&lookup, "Apple Notes lookup")?;
        if let Some(code) = record.get("serverErrorCode").and_then(Value::as_str) {
            bail!("Apple Notes lookup failed ({code})");
        }
        if record.get("recordType").and_then(Value::as_str) != Some("Note") {
            bail!("Only regular Apple Notes can be edited by this command");
        }
        let fields = record
            .get("fields")
            .context("Apple Notes record has no fields")?;
        if notes_summary(record)["shared"].as_bool() == Some(true) {
            bail!("This Apple note is shared; no update was sent");
        }
        if cloudkit_field_truthy(Some(fields), "Deleted") {
            bail!("This Apple note is deleted; no update was sent");
        }
        if notes_attachment_ids(Some(fields))
            .as_array()
            .is_some_and(|items| !items.is_empty())
        {
            bail!(
                "This note has attachments; plain-text update would remove or detach them, so no update was sent"
            );
        }
        let old_title = notes_field_text(Some(fields), "TitleEncrypted")
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let encoded_body = notes_field_bytes(Some(fields), "TextDataEncrypted")
            .context("Apple omitted this note's text; no update was sent")?;
        if !notes_body_attachment_ids(&encoded_body).is_empty() {
            bail!(
                "This note has inline attachments; plain-text update would remove them, so no update was sent"
            );
        }
        if !notes_plain_text_body_compatible(&encoded_body)? {
            bail!(
                "This note contains rich text or a complex body; plain-text update could discard formatting, so no update was sent"
            );
        }
        let old_text = decode_notes_body(encoded_body)
            .context("Could not decode this note's text; no update was sent")?;
        if !old_title.is_empty()
            && old_text != old_title
            && !old_text.starts_with(&format!("{old_title}\n"))
        {
            bail!(
                "This note's title and text are not in the supported simple-text layout; no update was sent"
            );
        }
        let old_body = notes_body_without_title(&old_text, &old_title);
        let new_title = title.unwrap_or(&old_title).trim().to_owned();
        let new_body = body.unwrap_or(&old_body).to_owned();
        let (note_text, note_title, snippet) = notes_compose_text(&new_title, &new_body);
        let replica = Uuid::new_v4().into_bytes();
        let encoded = encode_new_note_body(&replica, &note_text)?;
        let change_tag = record
            .get("recordChangeTag")
            .and_then(Value::as_str)
            .context("Apple omitted the Notes change tag; no update was sent")?;
        let mut updated_fields = json!({
            "TextDataEncrypted":{"type":"ENCRYPTED_BYTES","value":STANDARD.encode(encoded)},
            "TitleEncrypted":{"type":"ENCRYPTED_STRING","value":STANDARD.encode(note_title.as_bytes())},
            "SnippetEncrypted":{"type":"ENCRYPTED_STRING","value":STANDARD.encode(snippet.as_bytes())},
            "ModificationDate":{"type":"TIMESTAMP","value":Utc::now().timestamp_millis()}
        });
        if let Some(version) = fields.get("ReplicaIDToNotesVersionDataEncrypted") {
            updated_fields["ReplicaIDToNotesVersionDataEncrypted"] = version.clone();
        }
        let response = self.notes_cloudkit_request(
            "records/modify",
            &json!({
                "atomic":true,
                "zoneID":{"zoneName":"Notes","zoneType":"REGULAR_CUSTOM_ZONE"},
                "operations":[{"operationType":"update","record":{
                    "recordName":record_name,"recordType":"Note","recordChangeTag":change_tag,"fields":updated_fields
                }}]
            }),
        )?;
        let result = cloudkit_single_record(&response, "Apple Notes update")?;
        if let Some(code) = result.get("serverErrorCode").and_then(Value::as_str) {
            bail!("Apple Notes update failed ({code}); inspect the note before retrying");
        }
        let verified = self.notes_get(&record_name, false)?;
        if verified.get("title").and_then(Value::as_str) != Some(note_title.as_str())
            || verified.get("text").and_then(Value::as_str) != Some(note_text.as_str())
        {
            bail!(
                "Apple accepted the note update, but readback differs; inspect Notes before retrying"
            );
        }
        Ok(
            json!({"id":record_name,"title":note_title,"updated":true,"verified":true,"formatting_preserved":false}),
        )
    }

    fn notes_attachment_metadata(&mut self, id: &str) -> Result<Vec<Value>> {
        Ok(self
            .notes_attachment_records(id)?
            .into_iter()
            .map(|attachment| {
                json!({
                    "id":attachment.id,
                    "filename":attachment.filename,
                    "uti":attachment.uti,
                    "size":attachment.size,
                    "downloadable":attachment.download_url.is_some()
                })
            })
            .collect())
    }

    pub fn notes_download_attachments(&mut self, id: &str, output_dir: &Path) -> Result<Value> {
        let next = format!(
            "icli notes download {} --output-dir ./attachments --email {}",
            crate::cli_quote(id),
            crate::cli_quote(&self.session.account)
        );
        self.request_notes_pcs_access(&next)?;
        let attachments = self.notes_attachment_records(id)?;
        fs::create_dir_all(output_dir).with_context(|| {
            format!(
                "Could not create attachment directory {}",
                output_dir.display()
            )
        })?;
        let mut downloaded = Vec::new();
        let mut failed = Vec::new();
        for (index, attachment) in attachments.into_iter().enumerate() {
            let Some(url) = attachment.download_url.as_deref() else {
                failed.push(json!({"id":attachment.id,"status":"failed","reason":"Apple did not provide a downloadable asset"}));
                continue;
            };
            let filename = safe_notes_attachment_filename(
                &attachment.filename,
                attachment.uti.as_deref(),
                &attachment.id,
                index,
            );
            let path = unique_notes_attachment_path(output_dir, &filename, &attachment.id);
            match download_notes_asset(url, &path) {
                Ok(bytes) => downloaded.push(json!({
                    "id":attachment.id,
                    "filename":path.file_name().and_then(|name| name.to_str()).unwrap_or(&filename),
                    "path":path,
                    "bytes":bytes,
                    "status":"downloaded"
                })),
                Err(error) => failed.push(json!({
                    "id":attachment.id,
                    "filename":filename,
                    "status":"failed",
                    "reason":format!("{error:#}")
                })),
            }
        }
        Ok(json!({
            "note_id":notes_record_name(id,"Note"),
            "output_dir":output_dir,
            "downloaded":downloaded,
            "failed":failed
        }))
    }

    fn notes_attachment_records(&mut self, id: &str) -> Result<Vec<NotesAttachment>> {
        let record_name = notes_record_name(id, "Note");
        let lookup = self.notes_cloudkit_request(
            "records/lookup",
            &json!({
                "records":[{"recordName":record_name}],
                "zoneID":{"zoneName":"Notes","zoneType":"REGULAR_CUSTOM_ZONE"},
                "desiredKeys":["Attachments"]
            }),
        )?;
        let note = lookup
            .get("records")
            .and_then(Value::as_array)
            .and_then(|records| {
                records.iter().find(|record| {
                    record.get("recordName").and_then(Value::as_str) == Some(record_name.as_str())
                })
            })
            .context("No Apple Notes record found with that ID")?;
        if let Some(code) = note.get("serverErrorCode").and_then(Value::as_str) {
            bail!("Apple Notes record lookup failed ({code})");
        }
        let ids = notes_attachment_ids(note.get("fields"))
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect::<Vec<_>>();
        let mut ids = ids;
        let inline_ids = notes_field_bytes(note.get("fields"), "TextDataEncrypted")
            .as_deref()
            .map(notes_body_attachment_ids)
            .unwrap_or_default();
        for attachment_id in &inline_ids {
            if !ids.contains(attachment_id) {
                ids.push(attachment_id.clone());
            }
        }
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let response = self.notes_cloudkit_request(
            "records/lookup",
            &json!({
                "records":ids.iter().map(|id| json!({"recordName":id})).collect::<Vec<_>>(),
                "zoneID":{"zoneName":"Notes","zoneType":"REGULAR_CUSTOM_ZONE"},
                "desiredKeys":["Filename","Name","FileName","AttachmentUTI","UTI","Size","FileSize","AttachmentIdentifier","attachmentIdentifier","Identifier","PrimaryAsset","FallbackPDF","PaperAssets","PreviewImages","FallbackImage","Thumbnail","FirstAttachmentThumbnail","Media"]
            }),
        )?;
        let records = response
            .get("records")
            .and_then(Value::as_array)
            .context("Apple returned an invalid Notes attachment response")?;
        let mut attachments = Vec::new();
        let mut media_for_attachment = Vec::new();
        for id in ids {
            let record = records.iter().find(|record| {
                record.get("recordName").and_then(Value::as_str) == Some(id.as_str())
                    || ["AttachmentIdentifier", "attachmentIdentifier", "Identifier"]
                        .iter()
                        .any(|key| {
                            cloudkit_field_value(record.get("fields"), key).and_then(Value::as_str)
                                == Some(id.as_str())
                        })
            });
            let Some(record) = record else {
                if inline_ids.contains(&id) {
                    continue;
                }
                bail!("Apple omitted a linked Notes attachment");
            };
            if let Some(code) = record.get("serverErrorCode").and_then(Value::as_str) {
                if inline_ids.contains(&id) {
                    continue;
                }
                bail!("Apple Notes attachment lookup failed ({code})");
            }
            let fields = record.get("fields");
            let filename = ["Filename", "Name", "FileName"]
                .iter()
                .find_map(|key| cloudkit_field_value(fields, key).and_then(Value::as_str))
                .map(str::to_owned)
                .unwrap_or_else(|| format!("attachment-{}", attachments.len() + 1));
            let uti = ["AttachmentUTI", "UTI"]
                .iter()
                .find_map(|key| cloudkit_field_value(fields, key).and_then(Value::as_str))
                .map(str::to_owned);
            let size = ["Size", "FileSize"]
                .iter()
                .find_map(|key| cloudkit_field_value(fields, key).and_then(Value::as_u64));
            let download_url = [
                "PrimaryAsset",
                "FallbackPDF",
                "PaperAssets",
                "PreviewImages",
                "FallbackImage",
                "Thumbnail",
                "FirstAttachmentThumbnail",
            ]
            .iter()
            .find_map(|key| cloudkit_asset_url(fields.and_then(|fields| fields.get(*key))));
            if let Some(media_id) = notes_reference(fields, "Media") {
                media_for_attachment.push((id.clone(), media_id));
            }
            attachments.push(NotesAttachment {
                id,
                filename,
                uti,
                size,
                download_url,
            });
        }

        let media_ids = media_for_attachment
            .iter()
            .map(|(_, media_id)| media_id.clone())
            .collect::<std::collections::HashSet<_>>();
        if !media_ids.is_empty() {
            let media_response = self.notes_cloudkit_request(
                "records/lookup",
                &json!({
                    "records":media_ids.iter().map(|id| json!({"recordName":id})).collect::<Vec<_>>(),
                    "zoneID":{"zoneName":"Notes","zoneType":"REGULAR_CUSTOM_ZONE"}
                }),
            )?;
            let media_records = media_response
                .get("records")
                .and_then(Value::as_array)
                .context("Apple returned an invalid Notes media response")?;
            for (attachment_id, media_id) in media_for_attachment {
                let Some(media_record) = media_records.iter().find(|record| {
                    record.get("recordName").and_then(Value::as_str) == Some(media_id.as_str())
                }) else {
                    continue;
                };
                let media_url = cloudkit_asset_url(media_record.get("fields"));
                if let Some(attachment) = attachments
                    .iter_mut()
                    .find(|attachment| attachment.id == attachment_id)
                {
                    if attachment.download_url.is_none() {
                        attachment.download_url = media_url;
                    }
                }
            }
        }
        Ok(attachments)
    }

    pub fn notes_delete(&mut self, id: &str) -> Result<Value> {
        let next = format!(
            "icli notes delete {} --yes --email {}",
            crate::cli_quote(id),
            crate::cli_quote(&self.session.account)
        );
        self.request_notes_pcs_access(&next)?;
        let record_name = notes_record_name(id, "Note");
        let lookup = self.notes_cloudkit_request(
            "records/lookup",
            &json!({
                "records":[{"recordName":record_name}],
                "zoneID":{"zoneName":"Notes","zoneType":"REGULAR_CUSTOM_ZONE"},
                "desiredKeys":["Deleted","Folder","TitleEncrypted","share","participants"]
            }),
        )?;
        let record = lookup
            .get("records")
            .and_then(Value::as_array)
            .and_then(|records| {
                records.iter().find(|record| {
                    record.get("recordName").and_then(Value::as_str) == Some(record_name.as_str())
                })
            })
            .context("No Apple Notes record found with that ID")?;
        if let Some(code) = record.get("serverErrorCode").and_then(Value::as_str) {
            bail!("Apple Notes record lookup failed ({code})");
        }
        record
            .get("fields")
            .and_then(Value::as_object)
            .context("Apple returned a Notes lookup record without fields")?;
        let record_type = record
            .get("recordType")
            .and_then(Value::as_str)
            .filter(|record_type| matches!(*record_type, "Note" | "PasswordProtectedNote"))
            .context("Apple returned an unsupported Notes record type")?;
        if notes_summary(record)["shared"].as_bool() == Some(true) {
            bail!("This Apple note is shared; no delete was sent");
        }
        if cloudkit_field_truthy(record.get("fields"), "Deleted")
            || record.get("deleted").and_then(Value::as_bool) == Some(true)
        {
            return Ok(json!({"id":record_name,"deleted":true,"already_deleted":true}));
        }
        let change_tag = record
            .get("recordChangeTag")
            .and_then(Value::as_str)
            .context("Apple omitted the Notes change tag; no delete was sent")?;
        let modified = self.notes_cloudkit_request(
            "records/modify",
            &json!({
                "atomic":true,
                "zoneID":{"zoneName":"Notes","zoneType":"REGULAR_CUSTOM_ZONE"},
                "operations":[{
                    "operationType":"update",
                    "record":{
                        "recordName":record_name,
                        "recordType":record_type,
                        "recordChangeTag":change_tag,
                        "fields":{"Deleted":{"type":"INT64","value":1}}
                    }
                }]
            }),
        )?;
        let result = modified
            .get("records")
            .and_then(Value::as_array)
            .and_then(|records| records.first())
            .context("Apple returned an invalid Notes delete response")?;
        if let Some(code) = result.get("serverErrorCode").and_then(Value::as_str) {
            bail!("Apple Notes soft-delete failed ({code})");
        }

        let verification = self.notes_cloudkit_request(
            "records/lookup",
            &json!({
                "records":[{"recordName":record_name}],
                "zoneID":{"zoneName":"Notes","zoneType":"REGULAR_CUSTOM_ZONE"},
                "desiredKeys":["Deleted","share","participants"]
            }),
        )?;
        let verified_record = verification
            .get("records")
            .and_then(Value::as_array)
            .and_then(|records| {
                records.iter().find(|record| {
                    record.get("recordName").and_then(Value::as_str) == Some(record_name.as_str())
                })
            })
            .context("Apple accepted the Notes delete, but readback found no record")?;
        if let Some(code) = verified_record
            .get("serverErrorCode")
            .and_then(Value::as_str)
        {
            bail!("Apple accepted the Notes delete, but readback failed ({code})");
        }
        if !cloudkit_field_truthy(verified_record.get("fields"), "Deleted") {
            bail!("Apple accepted the Notes delete, but readback did not confirm it");
        }
        Ok(json!({"id":record_name,"deleted":true,"already_deleted":false}))
    }

    pub fn notes_delete_unshared(&mut self) -> Result<Value> {
        self.request_notes_pcs_access("icli notes delete-unshared --yes")?;
        let response = self.notes_zone_records("Note", None)?;
        let records = response["records"].as_array().cloned().unwrap_or_default();
        let listing_errors = records
            .iter()
            .filter(|record| {
                record
                    .get("serverErrorCode")
                    .and_then(Value::as_str)
                    .is_some()
            })
            .count();
        if listing_errors > 0 {
            bail!("Apple returned {listing_errors} errored Notes records; no notes were deleted");
        }
        let mut deleted = Vec::new();
        let mut already_deleted = Vec::new();
        let mut skipped_shared = Vec::new();
        let mut failed = Vec::new();

        for record in records.iter().filter(|record| {
            matches!(
                record.get("recordType").and_then(Value::as_str),
                Some("Note" | "PasswordProtectedNote")
            )
        }) {
            let id = record
                .get("recordName")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if id.is_empty() {
                failed.push(json!({"status":"failed","reason":"Apple returned a Notes record without an ID"}));
                continue;
            }
            if let Some(code) = record.get("serverErrorCode").and_then(Value::as_str) {
                failed.push(
                    json!({"id":id,"status":"failed","reason":format!("CloudKit returned {code}")}),
                );
                continue;
            }
            let summary = notes_summary(record);
            if summary["deleted"].as_bool() == Some(true) {
                already_deleted.push(json!({"id":id,"status":"already_deleted"}));
            } else if summary["shared"].as_bool() == Some(true) {
                skipped_shared.push(json!({"id":id,"status":"skipped_shared"}));
            } else {
                match self.notes_delete(id) {
                    Ok(result) if result["already_deleted"].as_bool() == Some(true) => {
                        already_deleted.push(json!({"id":id,"status":"already_deleted"}));
                    }
                    Ok(result) => deleted
                        .push(json!({"id":id,"status":"deleted","verified":result["deleted"]})),
                    Err(error) if format!("{error:#}").contains("This Apple note is shared") => {
                        skipped_shared.push(json!({"id":id,"status":"skipped_shared"}));
                    }
                    Err(error) => failed
                        .push(json!({"id":id,"status":"failed","reason":format!("{error:#}")})),
                }
            }
        }
        Ok(json!({
            "total_notes":deleted.len()+already_deleted.len()+skipped_shared.len()+failed.len(),
            "deleted":deleted,
            "already_deleted":already_deleted,
            "skipped_shared":skipped_shared,
            "failed":failed
        }))
    }

    pub fn notes_sync_cursor(&mut self) -> Result<String> {
        self.request_notes_pcs_access("icli notes sync-cursor")?;
        let query = self.notes_cloudkit_request("records/query", &json!({
            "query":{"recordType":"SearchIndexes","filterBy":[{"comparator":"EQUALS","fieldName":"indexName","fieldValue":{"type":"STRING","value":"recents"}}]},
            "zoneID":{"zoneName":"Notes","zoneType":"REGULAR_CUSTOM_ZONE"},"resultsLimit":1
        }));
        if let Ok(response) = query
            && let Some(cursor) = response.get("syncToken").and_then(Value::as_str)
        {
            return Ok(cursor.to_owned());
        }

        let response = self.notes_cloudkit_request(
            "changes/zone",
            &json!({"zones":[{
                "zoneID":{"zoneName":"Notes","zoneType":"REGULAR_CUSTOM_ZONE"},
                "desiredRecordTypes":[],"desiredKeys":[],"reverse":false
            }]}),
        )?;
        response
            .get("zones")
            .and_then(Value::as_array)
            .and_then(|zones| zones.first())
            .and_then(|zone| zone.get("syncToken"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .context("Apple did not return a Notes sync cursor")
    }

    pub fn notes_changes(&mut self, since: Option<&str>) -> Result<Value> {
        let mut next = format!(
            "icli notes changes --email {}",
            crate::cli_quote(&self.session.account)
        );
        if let Some(cursor) = since {
            next.push_str(&format!(" --since {}", crate::cli_quote(cursor)));
        }
        self.request_notes_pcs_access(&next)?;
        let response = self.notes_zone_records("Note", since)?;
        let token = response.get("sync_token").cloned().unwrap_or(Value::Null);
        let changes = response["records"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|record| {
                if record.get("deleted").and_then(Value::as_bool) == Some(true) {
                    json!({"id":record.get("recordName"),"deleted":true})
                } else {
                    let mut summary = notes_summary(record);
                    summary["deleted"] = json!(summary["deleted"].as_bool() == Some(true));
                    json!({"note":summary,"deleted":summary["deleted"]})
                }
            })
            .collect::<Vec<_>>();
        Ok(json!({"changes":changes,"cursor":token,"more_available":false}))
    }

    fn apple_pcs_post(&self, endpoint: &str, payload: Option<&Value>) -> Result<Value> {
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
                    "Apple rejected the saved session during private data access (HTTP {status})"
                ),
                "refresh",
            ));
        }
        if !status.is_success() {
            bail!("Apple private data-access request failed (HTTP {status})");
        }
        Ok(body)
    }

    /// Ask Apple's data-protection service to make this signed-in device's
    /// Reminders keys available to CloudKit. This mirrors pyicloud's PCS flow.
    fn request_reminders_pcs_access(&mut self, next_command: &str) -> Result<()> {
        if self.session.reminders_pcs_ready {
            return Ok(());
        }
        let state = self.apple_pcs_post("requestWebAccessState", None)?;
        if state.get("isICDRSDisabled").and_then(Value::as_bool) != Some(true) {
            self.session.reminders_pcs_ready = true;
            return Ok(());
        }

        if state
            .get("isDeviceConsentedForPCS")
            .and_then(Value::as_bool)
            == Some(false)
        {
            let consent = self.apple_pcs_post("enableDeviceConsentForPCS", None)?;
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
            let response = self.apple_pcs_post(
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

    pub fn reminder_list_create(&mut self, name: &str) -> Result<Value> {
        self.reminders_require_access("icli reminders lists")?;
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 256 || name.chars().any(char::is_control) {
            bail!("List name must contain 1 to 256 printable characters");
        }
        let record_name = format!(
            "List/{}",
            Uuid::new_v4().simple().to_string().to_uppercase()
        );
        self.reminders_modify(vec![json!({
            "operationType":"create",
            "record":{"recordName":record_name,"recordType":"List","fields":{"Name":{"type":"STRING","value":name}}}
        })], false)?;
        let record = self.reminders_record(&record_name)?;
        Ok(
            json!({"id":record_name,"name":cloudkit_field_value(record.get("fields"),"Name").and_then(Value::as_str).unwrap_or(name),"created":true}),
        )
    }

    pub fn reminder_list_update(&mut self, id: &str, name: &str) -> Result<Value> {
        self.reminders_require_access("icli reminders lists")?;
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 256 || name.chars().any(char::is_control) {
            bail!("List name must contain 1 to 256 printable characters");
        }
        let record_name = reminders_record_name(id, "List");
        let record = self.reminders_record(&record_name)?;
        if record.get("recordType").and_then(Value::as_str) != Some("List") {
            bail!("The selected CloudKit record is not a Reminders list");
        }
        let change_tag = record
            .get("recordChangeTag")
            .and_then(Value::as_str)
            .context("Apple omitted the list change tag; no update was sent")?;
        self.reminders_modify(vec![json!({"operationType":"update","record":{"recordName":record_name,"recordType":"List","recordChangeTag":change_tag,"fields":{"Name":{"type":"STRING","value":name}}}})], false)?;
        let updated = self.reminders_record(&record_name)?;
        Ok(
            json!({"id":record_name,"name":cloudkit_field_value(updated.get("fields"),"Name").and_then(Value::as_str).unwrap_or(name),"updated":true}),
        )
    }

    pub fn reminder_list_delete(&mut self, id: &str) -> Result<Value> {
        self.reminders_require_access("icli reminders lists")?;
        let record_name = reminders_record_name(id, "List");
        let list = self.reminders_record(&record_name)?;
        if list.get("recordType").and_then(Value::as_str) != Some("List") {
            bail!("The selected CloudKit record is not a Reminders list");
        }
        let mut query = json!({"query":{"recordType":"reminderList","filterBy":[
            {"comparator":"EQUALS","fieldName":"List","fieldValue":{"type":"REFERENCE","value":{"recordName":record_name,"action":"VALIDATE"}}},
            {"comparator":"EQUALS","fieldName":"includeCompleted","fieldValue":{"type":"INT64","value":1}},
            {"comparator":"EQUALS","fieldName":"LookupValidatingReference","fieldValue":{"type":"INT64","value":1}}
        ]},"zoneID":{"zoneName":"Reminders","zoneType":"REGULAR_CUSTOM_ZONE"},"resultsLimit":100});
        loop {
            let response = self.reminders_cloudkit_request("records/query", &query)?;
            let records = response
                .get("records")
                .and_then(Value::as_array)
                .context("Apple returned an invalid list-membership response")?;
            for reminder in records {
                if let Some(code) = reminder.get("serverErrorCode").and_then(Value::as_str) {
                    bail!("Apple could not verify whether the Reminders list is empty ({code})");
                }
                if reminder.get("recordType").and_then(Value::as_str) == Some("Reminder")
                    && !cloudkit_field_truthy(reminder.get("fields"), "Deleted")
                {
                    bail!(
                        "This list still contains reminders; move or delete them before deleting the list"
                    );
                }
            }
            match response.get("continuationMarker").and_then(Value::as_str) {
                Some(marker) if !marker.is_empty() => query["continuationMarker"] = json!(marker),
                _ => break,
            }
        }
        let change_tag = list
            .get("recordChangeTag")
            .and_then(Value::as_str)
            .context("Apple omitted the list change tag; no delete was sent")?;
        self.reminders_modify(vec![json!({"operationType":"delete","record":{"recordName":record_name,"recordType":"List","recordChangeTag":change_tag}})], false)?;
        Ok(json!({"id":record_name,"deleted":true}))
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

fn notes_record_name(id: &str, prefix: &str) -> String {
    id.strip_prefix(&format!("{prefix}/"))
        .unwrap_or(id)
        .to_owned()
}

fn cloudkit_single_record<'a>(response: &'a Value, operation: &str) -> Result<&'a Value> {
    response
        .get("records")
        .and_then(Value::as_array)
        .and_then(|records| records.first())
        .with_context(|| format!("Apple returned an invalid {operation} response"))
}

fn invites_event_id(record: &Value) -> Option<String> {
    let name = record.get("recordName")?.as_str()?;
    Some(
        name.strip_prefix("EventDetails:")
            .unwrap_or(name)
            .to_owned(),
    )
}

fn invites_field<'a>(fields: Option<&'a Value>, name: &str) -> Option<&'a Value> {
    fields?.get(name)?.get("value")
}

fn invites_short_guid(input: &str) -> Result<String> {
    let short_guid = input.rsplit('/').next().unwrap_or(input).trim();
    if short_guid.is_empty() || short_guid.chars().any(char::is_control) {
        bail!("Provide an Apple Invites short link ID or icloud.com/invites URL");
    }
    Ok(short_guid.to_owned())
}

fn photos_safe_filename(filename: &str, id: &str) -> String {
    let last_component = filename.rsplit(['/', '\\']).next().unwrap_or(filename);
    let clean = |value: &str| -> String {
        let safe = value
            .chars()
            .map(|ch| {
                if ch.is_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                    ch
                } else {
                    '_'
                }
            })
            .collect::<String>();
        safe.trim_matches(['.', ' ']).chars().take(80).collect()
    };
    let safe_id = clean(id);
    let (stem, extension) = last_component
        .rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .unwrap_or((last_component, ""));
    let stem = clean(stem);
    let extension = clean(extension);
    let stem = if stem.is_empty() { "photo" } else { &stem };
    if extension.is_empty() {
        format!("{stem}__{safe_id}")
    } else {
        format!("{stem}__{safe_id}.{extension}")
    }
}

fn shared_album_token(input: &str) -> Result<String> {
    let input = input.trim();
    let token = if let Ok(url) = Url::parse(input) {
        if url.scheme() != "https"
            || !url
                .host_str()
                .is_some_and(|host| host == "icloud.com" || host.ends_with(".icloud.com"))
        {
            bail!("Provide an HTTPS iCloud Shared Album URL or its album token");
        }
        url.fragment()
            .context("Shared Album URL has no album token in its fragment")?
            .split(';')
            .next()
            .unwrap_or_default()
            .to_owned()
    } else {
        input
            .trim_start_matches('#')
            .split(';')
            .next()
            .unwrap_or_default()
            .to_owned()
    };
    if !(6..=128).contains(&token.len()) || !token.chars().all(|ch| ch.is_ascii_alphanumeric()) {
        bail!("Provide a valid Apple Shared Album URL or token");
    }
    Ok(token)
}

fn shared_album_partition(token: &str) -> Result<String> {
    let bytes = token.as_bytes();
    let encoded = if bytes.first() == Some(&b'A') {
        bytes.get(1..2)
    } else {
        bytes.get(1..3)
    }
    .context("Shared Album token is too short to determine its service host")?;
    let mut partition = 0u32;
    for byte in encoded {
        let digit = match *byte {
            b'0'..=b'9' => u32::from(*byte - b'0'),
            b'A'..=b'Z' => u32::from(*byte - b'A') + 10,
            b'a'..=b'z' => u32::from(*byte - b'a') + 36,
            _ => bail!("Shared Album token contains an invalid host partition"),
        };
        partition = partition * 62 + digit;
    }
    Ok(format!("{partition:02}"))
}

fn invites_text(fields: Option<&Value>, name: &str) -> Value {
    let Some(field) = fields.and_then(|fields| fields.get(name)) else {
        return Value::Null;
    };
    let Some(value) = field.get("value") else {
        return Value::Null;
    };
    if matches!(
        field.get("type").and_then(Value::as_str),
        Some("ENCRYPTED_STRING" | "BYTES" | "ENCRYPTED_BYTES")
    ) {
        if let Some(text) = value.as_str() {
            if let Ok(bytes) = STANDARD.decode(text) {
                if let Ok(decoded) = String::from_utf8(bytes) {
                    return json!(decoded);
                }
            }
        }
    }
    if let Some(bytes) = value.as_array().and_then(|items| {
        items
            .iter()
            .map(|item| item.as_u64().and_then(|n| u8::try_from(n).ok()))
            .collect::<Option<Vec<_>>>()
    }) {
        return String::from_utf8(bytes)
            .map(Value::String)
            .unwrap_or(Value::Null);
    }
    value.clone()
}

fn invites_json_value(fields: Option<&Value>, name: &str) -> Value {
    let Some(value) = invites_field(fields, name) else {
        return Value::Null;
    };
    if value.is_object() || value.is_array() {
        return value.clone();
    }
    let Some(encoded) = value.as_str() else {
        return Value::Null;
    };
    if let Ok(parsed) = serde_json::from_str::<Value>(encoded) {
        return parsed;
    }
    let mut padded = encoded.to_owned();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    STANDARD
        .decode(padded)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .unwrap_or(Value::Null)
}

fn invites_bool(fields: Option<&Value>, name: &str) -> bool {
    match invites_field(fields, name) {
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(value)) => value.as_i64().unwrap_or_default() != 0,
        _ => false,
    }
}

fn invites_event_summary(record: &Value, id: &str, scope: &str, zone: Option<&Value>) -> Value {
    let fields = record.get("fields");
    let time = invites_json_value(fields, "time");
    let start = time
        .get("startSince1970")
        .and_then(Value::as_i64)
        .and_then(DateTime::<Utc>::from_timestamp_millis)
        .map(|date| date.to_rfc3339());
    let end = time
        .get("endSince1970")
        .and_then(Value::as_i64)
        .and_then(DateTime::<Utc>::from_timestamp_millis)
        .map(|date| date.to_rfc3339());
    json!({
        "id":id,"scope":scope,"title":invites_text(fields,"title"),"notes":invites_text(fields,"notes"),
        "host":invites_text(fields,"hostDisplayName"),"start":start,"end":end,
        "all_day":time.get("isAllDay").and_then(Value::as_bool).unwrap_or(false),"time":time,
        "place":invites_json_value(fields,"place"),"published":invites_bool(fields,"isPublished"),
        "cancelled":invites_bool(fields,"isCancelled"),"is_private":invites_bool(fields,"isPrivate"),
        "record_change_tag":record.get("recordChangeTag"),
        "zone_id":zone.cloned().unwrap_or_else(||json!({"zoneName":id,"zoneType":"REGULAR_CUSTOM_ZONE"}))
    })
}

fn invites_share_summary(record: &Value) -> Value {
    let fields = record.get("fields");
    let participants = record
        .get("participants")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    json!({
        "short_guid":record.get("shortGUID").or_else(||invites_field(fields,"shortGUID")),
        "stable_url":record.get("stableUrl").or_else(||invites_field(fields,"stableUrl")),
        "public_permission":record.get("publicPermission").or_else(||invites_field(fields,"publicPermission")),
        "participants":participants,"current_user_participant":record.get("currentUserParticipant")
    })
}

fn invites_rsvp_summary(record: &Value) -> Value {
    let fields = record.get("fields");
    json!({
        "id":record.get("recordName"),"status":invites_field(fields,"status"),
        "name":invites_text(fields,"name"),"message":invites_text(fields,"message"),
        "additional_adults":invites_field(fields,"numAdditionalAdults"),
        "additional_kids":invites_field(fields,"numAdditionalKids"),
        "additional_guests":invites_field(fields,"numAdditionalGuests"),
        "modified":record.get("modified"),"record_change_tag":record.get("recordChangeTag")
    })
}

fn notes_compose_text(title: &str, body: &str) -> (String, String, String) {
    let title = title.trim().to_owned();
    let text = match (title.is_empty(), body.is_empty()) {
        (false, false) => format!("{title}\n{body}"),
        (false, true) => title.clone(),
        (true, _) => body.to_owned(),
    };
    (text, title, body.chars().take(120).collect())
}

fn notes_body_without_title(text: &str, title: &str) -> String {
    if title.is_empty() {
        return text.to_owned();
    }
    text.strip_prefix(title)
        .and_then(|rest| rest.strip_prefix('\n'))
        .unwrap_or(text)
        .to_owned()
}

fn notes_plain_text_body_compatible(encoded: &[u8]) -> Result<bool> {
    let document = decompress_crdt_document(encoded);
    let root = protobuf_parse_message(&document)?;
    let Some(version) = protobuf_field_bytes(&root, 2) else {
        return Ok(false);
    };
    let version = protobuf_parse_message(version)?;
    let Some(topotext) = protobuf_field_bytes(&version, 3) else {
        return Ok(false);
    };
    let topotext = protobuf_parse_message(topotext)?;
    let runs = topotext
        .iter()
        .filter(|field| field.number == 5 && field.wire == 2)
        .collect::<Vec<_>>();
    if runs.len() > 1 {
        return Ok(false);
    }
    for run in runs {
        let fields = protobuf_parse_message(&run.value)?;
        if fields.len() != 1 || fields[0].number != 1 || fields[0].wire != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Encode the minimal compressed topotext document used by plain text notes.
/// Field numbering follows the observed `versioned_document.Document` and
/// `topotext.String` wire schemas; Notes/CloudKit performs field encryption.
fn encode_new_note_body(replica_id: &[u8; 16], text: &str) -> Result<Vec<u8>> {
    fn varint(mut value: u64, out: &mut Vec<u8>) {
        while value >= 0x80 {
            out.push((value as u8) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }
    fn varint_field(field: u64, value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        varint((field << 3) | 0, &mut out);
        varint(value, &mut out);
        out
    }
    fn bytes_field(field: u64, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(value.len() + 8);
        varint((field << 3) | 2, &mut out);
        varint(value.len() as u64, &mut out);
        out.extend_from_slice(value);
        out
    }
    fn char_id(replica: u64, clock: u64) -> Vec<u8> {
        [varint_field(1, replica), varint_field(2, clock)].concat()
    }
    fn substring(
        replica: u64,
        clock: u64,
        length: u64,
        timestamp_replica: u64,
        timestamp_clock: u64,
        child: Option<u64>,
    ) -> Vec<u8> {
        let mut inner = bytes_field(1, &char_id(replica, clock));
        inner.extend(varint_field(2, length));
        inner.extend(bytes_field(3, &char_id(timestamp_replica, timestamp_clock)));
        if let Some(child) = child {
            inner.extend(varint_field(5, child));
        }
        bytes_field(3, &inner)
    }

    let utf16_len = text.encode_utf16().count() as u64;
    let mut topotext = bytes_field(2, text.as_bytes());
    topotext.extend(substring(0, 0, 0, 0, 0, Some(1)));
    if utf16_len > 0 {
        topotext.extend(substring(1, 0, utf16_len, 1, 0, Some(2)));
    }
    topotext.extend(substring(0, u32::MAX as u64, 0, 0, u32::MAX as u64, None));

    let replica_clock = varint_field(1, utf16_len);
    let timestamp_clock = varint_field(1, u64::from(utf16_len > 0));
    let mut clock = bytes_field(1, replica_id);
    clock.extend(bytes_field(2, &replica_clock));
    clock.extend(bytes_field(2, &timestamp_clock));
    topotext.extend(bytes_field(4, &bytes_field(1, &clock)));
    if utf16_len > 0 {
        topotext.extend(bytes_field(5, &varint_field(1, utf16_len)));
    }

    let mut version = varint_field(2, 0);
    version.extend(bytes_field(3, &topotext));
    let document = bytes_field(2, &version);
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(&document)
        .context("Could not compress the Apple Notes body")?;
    encoder
        .finish()
        .context("Could not finish compressing the Apple Notes body")
}

fn notes_reference(fields: Option<&Value>, name: &str) -> Option<String> {
    fields?
        .get(name)?
        .get("value")?
        .get("recordName")?
        .as_str()
        .map(str::to_owned)
}

fn notes_field_bytes(fields: Option<&Value>, name: &str) -> Option<Vec<u8>> {
    let value = cloudkit_field_value(fields, name)?;
    if let Some(text) = value.as_str() {
        let mut padded = text.to_owned();
        while padded.len() % 4 != 0 {
            padded.push('=');
        }
        STANDARD
            .decode(padded)
            .ok()
            .or_else(|| Some(text.as_bytes().to_vec()))
    } else if let Some(items) = value.as_array() {
        items
            .iter()
            .map(|item| item.as_u64().and_then(|n| u8::try_from(n).ok()))
            .collect()
    } else {
        None
    }
}

fn notes_field_text(fields: Option<&Value>, name: &str) -> Value {
    let Some(field) = fields.and_then(|fields| fields.get(name)) else {
        return Value::Null;
    };
    let Some(value) = field.get("value") else {
        return Value::Null;
    };
    let field_type = field.get("type").and_then(Value::as_str);
    if field_type == Some("ENCRYPTED_STRING") {
        return value
            .as_str()
            .and_then(|text| STANDARD.decode(text).ok())
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .map(Value::String)
            .unwrap_or_else(|| value.clone());
    }
    let is_bytes = matches!(field_type, Some("ENCRYPTED_BYTES" | "BYTES"));
    if !is_bytes {
        return value.clone();
    }
    let bytes = if let Some(text) = value.as_str() {
        let mut padded = text.to_owned();
        while padded.len() % 4 != 0 {
            padded.push('=');
        }
        STANDARD.decode(padded).ok()
    } else if let Some(items) = value.as_array() {
        items
            .iter()
            .map(|item| item.as_u64().and_then(|number| u8::try_from(number).ok()))
            .collect::<Option<Vec<_>>>()
    } else {
        None
    };
    bytes
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .map(Value::String)
        .unwrap_or(Value::Null)
}

fn notes_summary(record: &Value) -> Value {
    let fields = record.get("fields");
    let modified = cloudkit_due_date(cloudkit_field_value(fields, "ModificationDate"))
        .as_str()
        .map(str::to_owned)
        .or_else(|| {
            record
                .pointer("/modified/timestamp")
                .and_then(|stamp| cloudkit_due_date(Some(stamp)).as_str().map(str::to_owned))
        });
    let record_type = record
        .get("recordType")
        .and_then(Value::as_str)
        .unwrap_or("Note");
    let folder_id =
        notes_reference(fields, "Folder").or_else(|| notes_reference(fields, "Folders"));
    let shared = record.get("share").is_some_and(|share| !share.is_null())
        || record
            .get("participants")
            .and_then(Value::as_array)
            .is_some_and(|participants| participants.len() > 1);
    json!({
        "id":record.get("recordName"),
        "title":notes_field_text(fields,"TitleEncrypted"),
        "snippet":notes_field_text(fields,"SnippetEncrypted"),
        "modified":modified,
        "folder_id":folder_id,
        "deleted":cloudkit_field_truthy(fields,"Deleted") || record.get("deleted").and_then(Value::as_bool) == Some(true),
        "locked":record_type == "PasswordProtectedNote",
        "shared":shared
    })
}

fn decode_notes_body(encoded: Vec<u8>) -> Option<String> {
    let document = decompress_crdt_document(&encoded);
    // NoteStoreProto.document is field 2, Document.note is field 3, and
    // Note.note_text is field 2. Keep unknown protobuf fields safely skippable.
    let root = protobuf_length_fields(&document).ok()?;
    let document = root.iter().find(|(number, _)| *number == 2)?.1;
    let document_fields = protobuf_length_fields(document).ok()?;
    let note = document_fields.iter().find(|(number, _)| *number == 3)?.1;
    let note_fields = protobuf_length_fields(note).ok()?;
    let text = note_fields.iter().find(|(number, _)| *number == 2)?.1;
    String::from_utf8(text.to_vec()).ok()
}

fn notes_attachment_ids(fields: Option<&Value>) -> Value {
    let ids = cloudkit_field_value(fields, "Attachments")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|reference| {
            reference
                .get("recordName")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    json!(ids)
}

fn notes_body_attachment_ids(encoded: &[u8]) -> Vec<String> {
    let document = decompress_crdt_document(encoded);
    let Ok(root_fields) = protobuf_length_fields(&document) else {
        return Vec::new();
    };
    let Some(document) = root_fields
        .iter()
        .find_map(|(field, value)| (*field == 2).then_some(*value))
    else {
        return Vec::new();
    };
    let Ok(document_fields) = protobuf_length_fields(document) else {
        return Vec::new();
    };
    let Some(note) = document_fields
        .iter()
        .find_map(|(field, value)| (*field == 3).then_some(*value))
    else {
        return Vec::new();
    };
    let Ok(note_fields) = protobuf_length_fields(note) else {
        return Vec::new();
    };

    let mut ids = Vec::new();
    for run in note_fields
        .iter()
        .filter_map(|(field, value)| (*field == 5).then_some(*value))
    {
        let Ok(run_fields) = protobuf_length_fields(run) else {
            continue;
        };
        let Some(attachment_info) = run_fields
            .iter()
            .find_map(|(field, value)| (*field == 12).then_some(*value))
        else {
            continue;
        };
        let Ok(attachment_fields) = protobuf_length_fields(attachment_info) else {
            continue;
        };
        let Some(id) = attachment_fields
            .iter()
            .find_map(|(field, value)| (*field == 1).then_some(*value))
            .and_then(|value| std::str::from_utf8(value).ok())
            .filter(|id| !id.is_empty())
        else {
            continue;
        };
        if !ids.iter().any(|existing| existing == id) {
            ids.push(id.to_owned());
        }
    }
    ids
}

fn cloudkit_asset_url(asset_field: Option<&Value>) -> Option<String> {
    fn find(value: &Value) -> Option<String> {
        match value {
            Value::Object(object) => {
                if let Some(url) = object.get("downloadURL").and_then(Value::as_str) {
                    return Some(url.to_owned());
                }
                object.values().find_map(find)
            }
            Value::Array(values) => values.iter().find_map(find),
            _ => None,
        }
    }
    find(asset_field?)
}

fn safe_notes_attachment_filename(
    filename: &str,
    uti: Option<&str>,
    id: &str,
    index: usize,
) -> String {
    let leaf = Path::new(filename)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let mut safe = leaf
        .chars()
        .map(|ch| {
            if ch.is_control() || "<>:\"/\\|?*".contains(ch) {
                '_'
            } else {
                ch
            }
        })
        .collect::<String>()
        .trim_matches([' ', '.'])
        .to_owned();
    if safe.is_empty() {
        let suffix = match uti.unwrap_or_default() {
            "public.jpeg" | "public.jpg" => ".jpg",
            "public.png" => ".png",
            "com.adobe.pdf" => ".pdf",
            "public.mpeg-4" => ".mp4",
            _ => "",
        };
        let short_id = id
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .take(12)
            .collect::<String>();
        safe = format!(
            "attachment-{}{}",
            if short_id.is_empty() {
                (index + 1).to_string()
            } else {
                short_id
            },
            suffix
        );
    }
    if safe.len() > 180 {
        safe.truncate(180);
    }
    safe
}

fn split_path_extension(filename: &str) -> (&str, &str) {
    match filename.rfind('.') {
        Some(index) if index > 0 => (&filename[..index], &filename[index..]),
        _ => (filename, ""),
    }
}

fn unique_notes_attachment_path(output_dir: &Path, filename: &str, id: &str) -> std::path::PathBuf {
    let base_path = output_dir.join(filename);
    if !base_path.exists() {
        return base_path;
    }
    let (stem, extension) = split_path_extension(filename);
    let id_suffix = id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .rev()
        .take(8)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    let id_suffix = if id_suffix.is_empty() {
        "attachment".to_owned()
    } else {
        id_suffix
    };
    let mut attempt = 1u64;
    loop {
        let suffix = if attempt == 1 {
            id_suffix.clone()
        } else {
            format!("{id_suffix}-{attempt}")
        };
        let path = output_dir.join(format!("{stem}-{suffix}{extension}"));
        if !path.exists() {
            return path;
        }
        attempt = attempt.saturating_add(1);
    }
}

fn download_notes_asset(url: &str, path: &Path) -> Result<u64> {
    let parsed = Url::parse(url).context("Apple returned an invalid Notes asset URL")?;
    if parsed.scheme() != "https" || parsed.host_str().is_none() {
        bail!("Apple returned a non-HTTPS Notes asset URL; download refused");
    }
    let client = HttpClient::builder()
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.url().scheme() == "https" {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
        .build()
        .context("Could not initialize the Notes asset downloader")?;
    let mut response = client
        .get(parsed)
        .send()
        .map_err(|_| anyhow::anyhow!("Could not download the Apple Notes attachment"))?;
    if !response.status().is_success() {
        bail!(
            "Apple Notes asset download failed (HTTP {})",
            response.status()
        );
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("Could not create attachment file {}", path.display()))?;
    match std::io::copy(&mut response, &mut file) {
        Ok(bytes) => {
            file.flush()?;
            Ok(bytes)
        }
        Err(error) => {
            let _ = fs::remove_file(path);
            Err(error).with_context(|| "Could not write the downloaded Notes attachment")
        }
    }
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
    output.clear();
    let mut deflate = flate2::read::DeflateDecoder::new(bytes);
    if deflate.read_to_end(&mut output).is_ok() && !output.is_empty() {
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
                notes_pcs_ready: false,
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
                notes_pcs_ready: false,
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
        let edited = encode_reminders_text_edit(&original, "New ðŸ§¾ title").unwrap();
        assert_eq!(
            cloudkit_text_field(
                Some(&json!({"TitleDocument":{"type":"STRING","value":edited}})),
                "TitleDocument"
            )
            .unwrap(),
            "New ðŸ§¾ title"
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

    #[test]
    fn notes_recents_uses_notes_container_and_maps_search_index_fields() {
        let path = "/database/1/com.apple.notes/production/private/records/query";
        let (base, server) = server(vec![reply(
            "POST",
            path,
            200,
            json!({"records":[{
                "recordName":"NOTE-1","recordType":"SearchIndexes",
                "fields":{"TitleEncrypted":{"type":"STRING","value":"Alpha project"},
                    "SnippetEncrypted":{"type":"STRING","value":"First words"},
                    "ModificationDate":{"type":"TIMESTAMP","value":1735776000000i64},
                    "Folder":{"type":"REFERENCE","value":{"recordName":"FOLDER-1"}},
                    "Deleted":{"type":"INT64","value":0}}
            }],"continuationMarker":null}),
        )]);
        let mut connection = cloudkit_connection(&base);
        connection.session.notes_pcs_ready = true;

        let (rows, more) = connection.notes_search(Some("PROJECT"), 0, 10).unwrap();

        assert!(!more);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["id"], "NOTE-1");
        assert_eq!(rows[0]["title"], "Alpha project");
        assert_eq!(rows[0]["folder_id"], "FOLDER-1");
        let requests = server.join().unwrap();
        assert!(requests[0].target.starts_with(path));
        assert_eq!(requests[0].body["query"]["recordType"], "SearchIndexes");
    }

    #[test]
    fn notes_body_decoder_reads_gzipped_notestore_protobuf() {
        let text = "Synthetic note body";
        let mut note = Vec::new();
        protobuf_put_bytes(&mut note, 2, text.as_bytes());
        let mut document = Vec::new();
        protobuf_put_bytes(&mut document, 3, &note);
        let mut root = Vec::new();
        protobuf_put_bytes(&mut root, 2, &document);
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&root).unwrap();
        let encoded = STANDARD.encode(encoder.finish().unwrap());

        assert_eq!(
            decode_notes_body(STANDARD.decode(encoded).unwrap()),
            Some(text.into())
        );
        assert_eq!(
            notes_field_text(
                Some(
                    &json!({"TitleEncrypted":{"type":"ENCRYPTED_BYTES","value":STANDARD.encode("Title")}})
                ),
                "TitleEncrypted"
            ),
            json!("Title")
        );
    }

    #[test]
    fn notes_body_decoder_reads_raw_deflate_notestore_protobuf() {
        let text = "Synthetic raw-deflate note body";
        let mut note = Vec::new();
        protobuf_put_bytes(&mut note, 2, text.as_bytes());
        let mut document = Vec::new();
        protobuf_put_bytes(&mut document, 3, &note);
        let mut root = Vec::new();
        protobuf_put_bytes(&mut root, 2, &document);
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&root).unwrap();

        assert_eq!(
            decode_notes_body(encoder.finish().unwrap()),
            Some(text.into())
        );
    }

    #[test]
    fn notes_record_names_preserve_raw_cloudkit_ids() {
        assert_eq!(notes_record_name("NOTE-1", "Note"), "NOTE-1");
        assert_eq!(notes_record_name("Note/NOTE-1", "Note"), "NOTE-1");
        assert_eq!(notes_record_name("FOLDER-1", "Folder"), "FOLDER-1");
    }

    #[test]
    fn notes_private_data_access_uses_notes_pcs_service_name() {
        let (base, server) = server(vec![
            reply(
                "POST",
                "/requestWebAccessState",
                200,
                json!({"isICDRSDisabled":true,"isDeviceConsentedForPCS":true}),
            ),
            reply("POST", "/requestPCS", 200, json!({"status":"success"})),
            reply(
                "POST",
                "/database/1/com.apple.notes/production/private/changes/zone",
                200,
                json!({"zones":[{"records":[],"syncToken":"notes-test-cursor","moreComing":false}]}),
            ),
        ]);
        let mut connection = cloudkit_connection(&base);
        connection.session.reminders_pcs_ready = false;
        connection.session.notes_pcs_ready = false;

        assert!(connection.notes_folders().unwrap().is_empty());

        let requests = server.join().unwrap();
        assert_eq!(requests[1].body["appName"], "notes");
        assert!(connection.session.notes_pcs_ready);
    }
}
