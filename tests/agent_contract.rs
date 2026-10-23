use std::{
    fs,
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "icli-contract-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_icli"))
            .args(args)
            .env("APPDATA", &self.0)
            .env("XDG_CONFIG_HOME", &self.0)
            .env("HOME", &self.0)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn format_changes_and_explicit_overrides_work_without_an_account() {
    let sandbox = Sandbox::new();
    let result = sandbox.run(&["config", "format", "json"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["data"]["response_format"], "json");
    assert_eq!(value["action"], "config.format");
    assert_eq!(value.as_object().unwrap().len(), 7);
    assert_eq!(value["error"], serde_json::Value::Null);
    let result = sandbox.run(&["--format", "agent", "config", "format", "json"]);
    assert!(String::from_utf8_lossy(&result.stdout).starts_with("Status: success"));
    let result = sandbox.run(&["--format", "csv", "--json", "auth", "list"]);
    assert!(result.status.success());
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["data"], serde_json::json!([]));
    let result = sandbox.run(&["auth", "list"]);
    assert!(serde_json::from_slice::<serde_json::Value>(&result.stdout).is_ok());
}

#[test]
fn json_usage_failures_have_one_stderr_envelope_and_exit_two() {
    let sandbox = Sandbox::new();
    for args in [
        vec![
            "--json",
            "calendar",
            "events",
            "delete",
            "uid",
            "--calendar",
            "work",
        ],
        vec!["contacts", "get", "--unknown", "--json"],
        vec!["--json", "mail", "update", "1", "--flag", "invalid"],
        vec![
            "--json",
            "auth",
            "add",
            "person@icloud.com",
            "--password-stdin",
            "--password",
            "example",
        ],
        vec!["--json", "calendar"],
    ] {
        let result = sandbox.run(&args);
        assert_eq!(result.status.code(), Some(2), "{args:?}");
        assert!(result.stdout.is_empty());
        let value: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"]["code"], "invalid_arguments");
        assert!(value["error"]["hint"].as_str().unwrap().contains("--help"));
    }
}

#[test]
fn empty_event_group_is_a_structured_usage_failure_in_json_mode() {
    let result = Sandbox::new().run(&["--json", "calendar", "events"]);
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
    assert_eq!(value["error"]["code"], "invalid_input");
    assert_eq!(value["action"], "calendar.events.list");
}

#[test]
fn invalid_search_queries_fail_before_account_access_with_scoped_recovery() {
    let sandbox = Sandbox::new();
    for command in [
        vec!["contacts", "search"],
        vec!["calendar", "events", "search"],
    ] {
        for query in [
            " ".to_string(),
            "\nplanning".to_string(),
            "x".repeat(257),
            "\u{fffe}".to_string(),
        ] {
            let mut args = vec!["--json"];
            args.extend(command.iter().copied());
            args.push(&query);
            let result = sandbox.run(&args);
            assert_eq!(result.status.code(), Some(2), "{args:?}");
            assert!(result.stdout.is_empty());
            let value: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
            assert_eq!(value["error"]["code"], "invalid_input");
            assert_eq!(
                value["error"]["help"],
                format!("icli {} --help", command.join(" "))
            );
            assert!(value["error"]["hint"].as_str().unwrap().contains("256"));
        }
    }
}

#[test]
fn pagination_rejects_invalid_counts_before_account_access() {
    let sandbox = Sandbox::new();
    for command in [
        vec!["calendar", "events", "search", "planning"],
        vec!["contacts", "list"],
        vec!["contacts", "search", "alex"],
        vec!["mail", "list"],
        vec!["mail", "search", "invoice"],
    ] {
        for (option, value) in [
            ("--skip", "-1"),
            ("--limit", "-1"),
            ("--skip", "lots"),
            ("--limit", "184467440737095516160"),
        ] {
            let mut args = vec!["--json"];
            args.extend(command.iter().copied());
            args.extend([option, value]);
            let result = sandbox.run(&args);
            assert_eq!(result.status.code(), Some(2), "{args:?}");
            assert!(result.stdout.is_empty());
            let value: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
            assert_eq!(value["error"]["code"], "invalid_arguments");
            assert!(value["error"]["help"].as_str().unwrap().ends_with("--help"));
        }
    }
}

#[test]
fn noninteractive_auth_add_fails_without_prompting_or_storing_credentials() {
    let sandbox = Sandbox::new();
    let result = sandbox.run(&[
        "--json",
        "auth",
        "add",
        "unused-contract-test@example.invalid",
    ]);
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
    assert_eq!(value["error"]["code"], "invalid_input");
    assert!(
        value["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("--password-stdin")
    );
    let listed = sandbox.run(&["--json", "auth", "list"]);
    let value: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(value["data"], serde_json::json!([]));
}

#[test]
fn auth_commands_explain_the_split_flow_and_app_password_migration() {
    let sandbox = Sandbox::new();
    let result = sandbox.run(&["auth", "--help"]);
    assert!(result.status.success());
    let help = String::from_utf8(result.stdout).unwrap();
    for command in [
        "add",
        "verify",
        "resend",
        "check",
        "refresh",
        "app-password",
    ] {
        assert!(help.contains(command), "{command} missing from auth help");
    }
    for command in [
        "add",
        "verify",
        "resend",
        "check",
        "refresh",
        "app-password",
        "apple-login",
    ] {
        let result = sandbox.run(&["auth", command, "--help"]);
        assert!(result.status.success(), "{command}");
        assert!(result.stderr.is_empty());
    }
    let result = sandbox.run(&["auth", "add", "--help"]);
    let help = String::from_utf8(result.stdout).unwrap();
    assert!(help.contains("verification_required"));
    assert!(help.contains("app-specific passwords use auth app-password"));
}

#[test]
fn new_auth_inputs_fail_locally_without_prompts_or_creating_an_account() {
    let sandbox = Sandbox::new();
    for command in ["add", "app-password", "apple-login", "verify"] {
        let result = sandbox.run(&["--json", "auth", command, "synthetic@example.invalid"]);
        assert_eq!(result.status.code(), Some(2), "{command}");
        assert!(result.stdout.is_empty());
        let envelope: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
        assert_eq!(envelope["error"]["code"], "invalid_input");
        assert!(
            envelope["error"]["hint"]
                .as_str()
                .unwrap()
                .contains("stdin")
        );
        let result = sandbox.run(&["--json", "auth", "list"]);
        let envelope: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(envelope["data"], serde_json::json!([]));
    }
}

#[test]
fn auth_secret_sources_and_methods_are_exclusive_with_scoped_errors() {
    let sandbox = Sandbox::new();
    for arguments in [
        vec![
            "verify",
            "synthetic@example.invalid",
            "012345",
            "--code-stdin",
        ],
        vec![
            "verify",
            "--email",
            "synthetic@example.invalid",
            "--code",
            "012345",
            "--code-stdin",
        ],
        vec![
            "app-password",
            "synthetic@example.invalid",
            "--password-stdin",
            "--password",
            "synthetic",
        ],
        vec!["resend", "--method", "invalid"],
        vec!["check", "--password-stdin"],
        vec!["refresh", "--password", "synthetic"],
    ] {
        let mut args = vec!["--json", "auth"];
        args.extend(arguments.iter().copied());
        let result = sandbox.run(&args);
        assert_eq!(result.status.code(), Some(2), "{arguments:?}");
        assert!(result.stdout.is_empty());
        let envelope: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
        assert_eq!(envelope["error"]["code"], "invalid_arguments");
        assert_eq!(
            envelope["error"]["help"],
            format!("icli auth {} --help", arguments[0])
        );
    }
}
