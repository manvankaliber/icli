use crate::{OutputFormat, csv_cell, format_value};
use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};
use std::{cell::RefCell, fmt::Write};

#[derive(Default)]
struct Context {
    pub action: String,
    pub format: OutputFormat,
    pub warnings: Vec<String>,
    pub next_steps: Vec<String>,
    pub exit_code: i32,
}

thread_local! { static CONTEXT: RefCell<Context> = RefCell::new(Context::default()); }

pub fn configure(action: String, format: OutputFormat) {
    CONTEXT.with(|c| {
        *c.borrow_mut() = Context {
            action,
            format,
            ..Context::default()
        }
    });
}
pub fn warning(message: impl Into<String>) {
    CONTEXT.with(|c| c.borrow_mut().warnings.push(message.into()));
}
pub fn next(command: impl Into<String>) {
    CONTEXT.with(|c| c.borrow_mut().next_steps.push(command.into()));
}
pub fn status(exit_code: i32) {
    CONTEXT.with(|c| c.borrow_mut().exit_code = exit_code);
}
pub fn exit_code() -> i32 {
    CONTEXT.with(|c| c.borrow().exit_code)
}
pub fn selected<T: Serialize>(data: &T, title: &str) -> Result<()> {
    let format = CONTEXT.with(|c| c.borrow().format);
    output(data, format, title)
}
pub fn envelope(data: Value, error: Value) -> Value {
    CONTEXT.with(|c| {
        let c = c.borrow();
        json!({"ok": c.exit_code == 0, "status": match c.exit_code { 0 => "success", 3 => "partial", _ => "error" },
            "action": c.action, "data": data, "next_steps": c.next_steps, "warnings": c.warnings, "error": error})
    })
}
pub fn output<T: Serialize>(data: &T, format: OutputFormat, title: &str) -> Result<()> {
    let data = serde_json::to_value(data)?;
    let error = if exit_code() == 1 {
        json!({"code":"operation_failed","message":title,"hint":"Inspect the per-service or per-item results.","help":format!("{} --help",crate::help_target()),"retryable":null})
    } else {
        Value::Null
    };
    let result = envelope(data.clone(), error);
    let mut rendered = String::new();
    macro_rules! emit { ($($arg:tt)*) => { writeln!(&mut rendered, $($arg)*)? }; }
    match format {
        OutputFormat::Json => emit!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Agent => {
            emit!(
                "Status: {}\nAction: {}\nResult: {title}",
                result["status"].as_str().unwrap_or_default(),
                result["action"].as_str().unwrap_or_default()
            );
            emit!("{}", serde_json::to_string_pretty(&data)?);
            if !result["error"].is_null() {
                emit!("Error: {}", serde_json::to_string_pretty(&result["error"])?);
            }
            let rows = data
                .as_array()
                .cloned()
                .unwrap_or_else(|| vec![data.clone()]);
            let ids = rows
                .iter()
                .flat_map(|row| {
                    ["uid", "id", "href"].into_iter().filter_map(move |key| {
                        row.get(key).map(|v| format!("{key}={}", format_value(v)))
                    })
                })
                .collect::<Vec<_>>();
            emit!(
                "IDs: {}",
                if ids.is_empty() {
                    "none".into()
                } else {
                    ids.join(", ")
                }
            );
            for (key, label) in [("warnings", "Warnings"), ("next_steps", "Next command")] {
                let values = result[key].as_array().unwrap();
                if values.is_empty() {
                    emit!("{label}: none");
                } else {
                    for value in values {
                        emit!("{label}: {}", value.as_str().unwrap_or_default());
                    }
                }
            }
        }
        OutputFormat::Csv => {
            let rows = data.as_array().cloned().unwrap_or_else(|| vec![data]);
            let rows = rows
                .into_iter()
                .map(|row| {
                    let mut fields = row
                        .as_object()
                        .cloned()
                        .unwrap_or_else(|| serde_json::Map::from_iter([("value".into(), row)]));
                    fields.insert("action".into(), result["action"].clone());
                    fields.entry("status").or_insert(result["status"].clone());
                    fields.insert("response_status".into(), result["status"].clone());
                    fields.insert("warnings".into(), result["warnings"].clone());
                    fields.insert("next_steps".into(), result["next_steps"].clone());
                    fields
                })
                .collect::<Vec<_>>();
            let columns = rows
                .iter()
                .flat_map(|r| r.keys().cloned())
                .chain(["action".into(), "status".into()])
                .collect::<std::collections::BTreeSet<_>>();
            emit!(
                "{}",
                columns
                    .iter()
                    .map(|s| csv_cell(s))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            for row in rows {
                emit!(
                    "{}",
                    columns
                        .iter()
                        .map(|key| csv_cell(&row.get(key).map(format_value).unwrap_or_default()))
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
        }
    }
    if exit_code() == 1 {
        eprint!("{rendered}");
    } else {
        print!("{rendered}");
    }
    Ok(())
}

pub fn error_details(error: &anyhow::Error) -> Value {
    let (code, retryable) = crate::error_code(error);
    json!({"code":code,"message":format!("{error:#}"),"hint":crate::next_step(error),"help":format!("{} --help",crate::help_target()),"retryable":retryable})
}

pub fn failure(
    message: &str,
    code: &str,
    hint: &str,
    help: &str,
    retryable: Option<bool>,
    format: OutputFormat,
    exit: i32,
) {
    failure_with_data(
        Value::Null,
        message,
        code,
        hint,
        help,
        retryable,
        format,
        exit,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn failure_with_data(
    data: Value,
    message: &str,
    code: &str,
    hint: &str,
    help: &str,
    retryable: Option<bool>,
    format: OutputFormat,
    exit: i32,
) {
    status(exit);
    let error =
        json!({"code":code,"message":message,"hint":hint,"help":help,"retryable":retryable});
    let result = envelope(data.clone(), error.clone());
    if format == OutputFormat::Json {
        eprintln!("{}", serde_json::to_string_pretty(&result).unwrap());
    } else if format == OutputFormat::Csv {
        if data.is_null() {
            eprintln!("action,status,code,message,hint,help,retryable");
            eprintln!(
                "{},{},{},{},{},{},{}",
                csv_cell(&format_value(&result["action"])),
                csv_cell("error"),
                csv_cell(&format_value(&error["code"])),
                csv_cell(&format_value(&error["message"])),
                csv_cell(&format_value(&error["hint"])),
                csv_cell(&format_value(&error["help"])),
                csv_cell(&format_value(&error["retryable"])),
            );
            return;
        }
        let mut row = data.as_object().cloned().unwrap_or_default();
        row.insert("action".into(), result["action"].clone());
        row.insert("status".into(), result["status"].clone());
        row.insert("response_status".into(), result["status"].clone());
        row.insert("code".into(), error["code"].clone());
        row.insert("message".into(), error["message"].clone());
        row.insert("hint".into(), error["hint"].clone());
        row.insert("help".into(), error["help"].clone());
        row.insert("retryable".into(), error["retryable"].clone());
        let columns = row.keys().cloned().collect::<Vec<_>>();
        eprintln!(
            "{}",
            columns
                .iter()
                .map(|key| csv_cell(key))
                .collect::<Vec<_>>()
                .join(",")
        );
        eprintln!(
            "{}",
            columns
                .iter()
                .map(|key| csv_cell(&format_value(&row[key])))
                .collect::<Vec<_>>()
                .join(",")
        );
    } else {
        eprintln!(
            "Status: error\nCode: {code}\nError: {message}\nNext command: {hint}\nHelp: {help}"
        );
        if !data.is_null() {
            eprintln!(
                "Diagnostics: {}",
                serde_json::to_string_pretty(&data).unwrap()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_envelopes_preserve_results_warnings_and_next_steps() {
        configure("calendar.events.import".into(), OutputFormat::Json);
        warning("Successful imports remain saved");
        next("icli calendar events get uid --calendar id");
        status(3);
        let value = envelope(
            json!([{"uid":"uid","status":"success"},{"uid":"bad","status":"error"}]),
            Value::Null,
        );
        assert_eq!(value["ok"], false);
        assert_eq!(value["status"], "partial");
        assert_eq!(value["data"].as_array().unwrap().len(), 2);
        assert_eq!(value["warnings"].as_array().unwrap().len(), 1);
        assert_eq!(value["next_steps"].as_array().unwrap().len(), 1);
        configure("contacts.list".into(), OutputFormat::Json);
        let value = envelope(json!([]), Value::Null);
        assert_eq!(value["ok"], true);
        assert_eq!(value["warnings"], json!([]));
    }
}
