use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use clap::{Args, FromArgMatches, Parser, Subcommand};
pub mod apple_auth;
mod help;
mod response;
mod update;
fn agent_command() -> clap::Command {
    help::command()
}
use ical::parser::{ical::IcalParser, vcard::VcardParser};
use mailparse::MailHeaderMap;
use response::output;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead, BufReader, IsTerminal, Read, Write},
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(
    name = "icli",
    version,
    about = "Read and manage iCloud Calendar, Contacts, Mail, and Reminders",
    long_about = "Read and manage iCloud Calendar, Mail, Contacts, and Apple Reminders. Start Apple Account sign-in with `icli auth add EMAIL`, then submit its verification code with `icli auth verify EMAIL CODE`. The trusted session is saved in the OS credential store and reused by default. For Mail, Calendar, and Contacts, save a recommended app-specific password with `icli auth app-password EMAIL`. Choose the default account with `icli config default-user EMAIL`. Output defaults to agent text; use --json or --format agent|csv|json.",
    before_help = concat!(
        "Running icli v",
        env!("CARGO_PKG_VERSION"),
        " released on ",
        env!("ICLI_RELEASE_DATE"),
        "."
    ),
    override_usage = "icli <update|config|auth|calendar|agenda|calender|mail|contacts|reminders|help> [OPTIONS]",
    after_help = "Run `icli <command> --help` to read that command's instructions and accepted arguments. Put command-specific options after the command.\n\nOptions available: --json, --format <agent|csv|json>, --help, --version."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true, value_enum)]
    format: Option<OutputFormat>,
}
// Clap parses this command tree once; boxing adds indirection without changing CLI behavior.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Command {
    #[command(
        about = "Update this executable to the latest stable iCLI release",
        long_about = "Check GitHub for the latest stable manvankaliber/icli release. Without --check, download the matching binary, verify its published SHA-256 checksum, and replace this executable in place. Current or newer versions are left unchanged. Supports release targets on Windows, macOS, and GNU Linux for x86-64/ARM64. Requires network access and write access to the executable directory; no iCloud account is needed. Source and package-managed installations should use their original update method to preserve that installation. Restart a running MCP adapter after updating its executable.",
        after_help = "Options available: --check (inspect without downloading/replacing a binary), --json, --format <agent|csv|json>, --help. A successful update takes effect on the next invocation. Download/checksum failures happen before replacement. Replacement failures attempt to restore the original executable and report any retained recovery path; consult the error hint before retrying."
    )]
    Update {
        #[arg(
            long,
            help = "Check the latest stable version without replacing the executable"
        )]
        check: bool,
    },
    #[command(
        about = "Set the default account or response format",
        long_about = "Use the config commands to choose which configured iCloud account commands use by default and which response format they print. Set the default account with `icli config default-user EMAIL`; EMAIL must already be configured with `icli auth add` or `icli auth app-password`. Set the saved response format to `agent`, `csv`, or `json` with `icli config format FORMAT`. These settings are stored in iCLI's local configuration.",
        after_help = "Run `icli config <subcommand> --help` to read that operation's instructions and accepted arguments.\n\nOptions available: --json, --format <agent|csv|json>, --help."
    )]
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    #[command(
        about = "Manage app-specific-password accounts and Apple private-service sign-in",
        long_about = "Start Apple Account sign-in with auth add, finish its code challenge with auth verify, inspect the saved session with auth check, and renew it with auth refresh. Commands return structured state and recovery instructions. Save a recommended app-specific password for Mail, Calendar, and Contacts with auth app-password. Passwords, pending challenges, and trusted sessions are kept in the OS credential store; the Apple Account password itself is never saved.",
        after_help = "Commands: add, verify, resend, check, refresh, app-password, list, remove. auth apple-login is a deprecated alias for auth add. Run each command with --help for input options and side effects."
    )]
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    #[command(
        aliases = ["agenda", "calender"],
        about = "List calendars and manage calendars and events",
        long_about = "Use `icli calendar list` to see available calendar names and IDs. The calendar commands create, rename, delete, set color, and share owner calendars by invitation. Use `icli calendar events` for event reads and writes, including listing in a date range, searching text, retrieving by UID, creating, updating, deleting, and importing iCalendar files. Events support recurrence rules and display alarms. Set a default account with `icli config default-user EMAIL` or select one with `--email EMAIL`.",
        override_usage = "icli calendar <list|create|update|delete|color|share|events|help> [OPTIONS]",
        after_help = "Run `icli calendar <subcommand> --help` to read that operation's instructions, required values, and available options. Put operation-specific options after the subcommand.\n\nOptions available: --json, --format <agent|csv|json>, --help."
    )]
    Calendar {
        #[command(subcommand)]
        command: CalendarCommand,
    },
    #[command(
        about = "Read and manage iCloud Mail messages",
        long_about = "Use the Mail operations to list folders, read/search messages in any folder, download attachments, create drafts, send messages, change flags, move, or delete messages. Message identifiers are IMAP UIDs from list/search. Create saves a draft; send delivers mail through iCloud SMTP.",
        after_help = "Run `icli mail <folders|list|search|get|download|create|send|update|move|delete> --help` for operation details. Running `icli mail` displays this operation list without contacting iCloud. Options available: --email, --folder, --skip, --limit, --json, --format <agent|csv|json>, --help."
    )]
    Mail {
        #[command(subcommand)]
        action: Option<MailCommand>,
    },
    #[command(
        disable_help_subcommand = true,
        about = "Read and manage iCloud contacts",
        long_about = "Use Contacts to search, list, and manage contacts, find your own card, and manage contact groups. Contact identifiers are vCard UIDs shown by list and search commands. Select an account with --email EMAIL or the configured default account.",
        after_help = "Run `icli contacts help` to list vCard properties. Use `--include PROPERTY` or comma-separate properties to add them to list/get/search output; X- custom properties are supported. Run `icli contacts groups --help` for group operations. Running `icli contacts` displays this operation list without contacting iCloud."
    )]
    Contacts {
        #[command(subcommand)]
        action: Option<ContactsCommand>,
    },
    #[command(
        about = "Read and manage Apple Reminders",
        long_about = "Read and manage Apple Reminders through Apple's private CloudKit service. Start with `icli auth add EMAIL`, then `icli auth verify EMAIL CODE` when required; the saved trusted session is reused. The first read may request trusted-device approval for encrypted Reminders data. The command group supports reminder and list reads, reminder create/update/complete/delete, snapshots and incremental sync, alarms, hashtags, URL attachments, and recurrence rules. This is Apple Reminders, not Calendar tasks.",
        after_help = "Use `icli reminders lists` and `icli reminders list` to inspect data before writing. IDs are stable CloudKit record names. Remote deletes require `--yes`. All writes target Apple CloudKit and are not rolled back if a later separate operation fails."
    )]
    Reminders {
        #[arg(
            long,
            value_name = "EMAIL",
            global = true,
            help = "Apple Account address used for Reminders sign-in"
        )]
        email: Option<String>,
        #[command(subcommand)]
        action: Option<RemindersCommand>,
    },
}
#[derive(Subcommand)]
enum ConfigCommand {
    #[command(
        about = "Choose the account used when a command omits EMAIL",
        long_about = "Set EMAIL as the account iCLI selects when a command does not specify an account. The account must already be configured with `icli auth add EMAIL` or `icli auth app-password EMAIL`. This setting is useful when more than one account is configured; commands that include EMAIL continue to use the explicitly selected account.",
        after_help = "Argument: EMAIL is the email address of an account already added to iCLI.\n\nOptions available: --json, --format <agent|csv|json>, --help."
    )]
    DefaultUser { email: String },
    #[command(
        about = "Choose the saved response format",
        long_about = "Save the format used by commands when neither `--format` nor `--json` overrides it. Choose `agent` for readable descriptions with structured fields, `csv` for comma-separated rows, or `json` for JSON. The initial default is `agent`.",
        after_help = "Argument: FORMAT must be `agent`, `csv`, or `json`.\n\nOptions available: --json, --format <agent|csv|json>, --help."
    )]
    Format { response_format: OutputFormat },
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum OutputFormat {
    #[default]
    Agent,
    Csv,
    Json,
}
#[derive(Args)]
struct AuthCredentialArgs {
    #[arg(value_name = "EMAIL", required_unless_present = "email_flag")]
    email: Option<String>,
    #[arg(value_name = "PASSWORD")]
    password: Option<String>,
    #[arg(long = "email", value_name = "EMAIL", conflicts_with = "email")]
    email_flag: Option<String>,
    #[arg(
        long = "password",
        value_name = "PASSWORD",
        conflicts_with = "password"
    )]
    password_flag: Option<String>,
    #[arg(long, conflicts_with_all = ["password", "password_flag"], help = "Read the password from stdin; remove only its trailing line ending")]
    password_stdin: bool,
}
#[derive(Subcommand)]
enum AuthCommand {
    #[command(
        visible_alias = "apple-login",
        about = "Start Apple Account sign-in; submit its code with auth verify"
    )]
    Add(AuthCredentialArgs),
    #[command(about = "Save or replace an app-specific password for Mail, Calendar, and Contacts")]
    AppPassword(AuthCredentialArgs),
    #[command(about = "Submit the verification code for a pending Apple sign-in")]
    Verify {
        #[arg(value_name = "EMAIL")]
        email: Option<String>,
        #[arg(value_name = "CODE", conflicts_with_all = ["code_flag", "code_stdin"])]
        code: Option<String>,
        #[arg(long = "email", conflicts_with = "email")]
        email_flag: Option<String>,
        #[arg(long = "code", value_name = "CODE", conflicts_with = "code_stdin")]
        code_flag: Option<String>,
        #[arg(long, help = "Read the six-digit code from stdin")]
        code_stdin: bool,
    },
    #[command(about = "Request another verification code for a pending sign-in")]
    Resend {
        #[arg(value_name = "EMAIL")]
        email: Option<String>,
        #[arg(long = "email", conflicts_with = "email")]
        email_flag: Option<String>,
        #[arg(long, value_enum, default_value = "device")]
        method: apple_auth::VerificationMethod,
    },
    #[command(about = "Renew the selected Apple session using saved tokens")]
    Refresh {
        #[arg(value_name = "EMAIL")]
        email: Option<String>,
        #[arg(long = "email", conflicts_with = "email")]
        email_flag: Option<String>,
    },
    #[command(about = "List configured accounts; never display secrets")]
    List,
    #[command(about = "Remove the account and its saved credentials and sessions locally")]
    Remove {
        #[arg(value_name = "EMAIL", required_unless_present = "email_flag")]
        email: Option<String>,
        #[arg(long = "email", conflicts_with = "email")]
        email_flag: Option<String>,
    },
    #[command(about = "Check a saved Apple session, or app-password services with --app-password")]
    Check {
        #[arg(value_name = "EMAIL")]
        email: Option<String>,
        #[arg(value_name = "PASSWORD", requires = "app_password")]
        password: Option<String>,
        #[arg(long = "email", conflicts_with = "email")]
        email_flag: Option<String>,
        #[arg(
            long = "password",
            value_name = "PASSWORD",
            conflicts_with = "password",
            requires = "app_password"
        )]
        password_flag: Option<String>,
        #[arg(long, conflicts_with_all = ["password", "password_flag"], requires = "app_password")]
        password_stdin: bool,
        #[arg(
            long,
            help = "Check Mail, Calendar, and Contacts using an app-specific password"
        )]
        app_password: bool,
    },
}
#[derive(Subcommand)]
enum RemindersCommand {
    #[command(
        about = "List Reminders lists",
        long_about = "Read Apple Reminders lists from the selected Apple Account. Output includes each list name and its stable service ID. Sign in with `icli auth add EMAIL`, then `icli auth verify EMAIL CODE` when requested. The first read may request trusted-device approval for encrypted Reminders data.",
        after_help = "Options: --email EMAIL, --json, --format <agent|csv|json>, --help."
    )]
    Lists,
    #[command(
        about = "List reminders across all lists",
        long_about = "Read active and completed Apple Reminders across all lists. Output includes reminder ID, title, list, completion state, and due date where available. Results default to the first 100 reminders; use --skip and --limit to page through more. Sign in with `icli auth add EMAIL`, then `icli auth verify EMAIL CODE` when requested. The first read may request trusted-device approval for encrypted Reminders data.",
        after_help = "Options: --skip N (default 0), --limit N (default 100), --email EMAIL, --json, --format <agent|csv|json>, --help. This command does not change reminder data."
    )]
    List {
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        skip: usize,
    },
    #[command(about = "Read one reminder by its stable ID")]
    Get { id: String },
    #[command(about = "Create a reminder in a list")]
    Create {
        #[arg(long, value_name = "LIST_ID", required = true)]
        list: String,
        #[arg(long, value_name = "TITLE", required = true)]
        title: String,
        #[arg(long, value_name = "TEXT", default_value = "")]
        notes: String,
        #[arg(
            long,
            value_name = "DATE_OR_TIME",
            help = "Due date YYYY-MM-DD or RFC3339 date-time"
        )]
        due: Option<String>,
        #[arg(long)]
        all_day: bool,
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(i64).range(0..=9))]
        priority: i64,
        #[arg(long)]
        flagged: bool,
    },
    #[command(about = "Update selected fields on one reminder")]
    Update {
        id: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(
            long,
            value_name = "DATE_OR_TIME",
            help = "Due date YYYY-MM-DD or RFC3339 date-time"
        )]
        due: Option<String>,
        #[arg(long, conflicts_with = "due")]
        clear_due: bool,
        #[arg(long, value_parser = clap::value_parser!(i64).range(0..=9))]
        priority: Option<i64>,
        #[arg(long, action = clap::ArgAction::Set)]
        flagged: Option<bool>,
        #[arg(long, action = clap::ArgAction::Set)]
        completed: Option<bool>,
        #[arg(long, action = clap::ArgAction::Set)]
        all_day: Option<bool>,
    },
    #[command(about = "Mark a reminder complete or incomplete")]
    SetStatus {
        id: String,
        #[arg(value_enum)]
        status: ReminderStatus,
    },
    #[command(about = "Delete one reminder; requires --yes")]
    Delete {
        id: String,
        #[arg(long, required = true)]
        yes: bool,
    },
    #[command(about = "Read a full snapshot of one list and its related records")]
    Snapshot {
        #[arg(long, value_name = "LIST_ID", required = true)]
        list: String,
        #[arg(long, default_value_t = 500)]
        limit: usize,
    },
    #[command(about = "Read incremental reminder changes from a sync cursor")]
    Changes {
        #[arg(long, value_name = "CURSOR")]
        since: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    #[command(about = "Read the current opaque Reminders sync cursor")]
    SyncCursor,
    #[command(about = "List or create reminder alarms")]
    Alarm {
        #[command(subcommand)]
        action: ReminderAlarmCommand,
    },
    #[command(about = "List and manage reminder hashtags")]
    Hashtag {
        #[command(subcommand)]
        action: ReminderHashtagCommand,
    },
    #[command(about = "List and manage reminder attachments")]
    Attachment {
        #[command(subcommand)]
        action: ReminderAttachmentCommand,
    },
    #[command(about = "List and manage recurrence rules")]
    Recurrence {
        #[command(subcommand)]
        action: ReminderRecurrenceCommand,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum ReminderStatus {
    Completed,
    Incomplete,
}

#[derive(Subcommand)]
enum ReminderAlarmCommand {
    #[command(about = "List alarms on one reminder")]
    List { id: String },
    #[command(about = "Add a location alarm to one reminder")]
    AddLocation {
        id: String,
        #[arg(long, default_value = "")]
        title: String,
        #[arg(long, default_value = "")]
        address: String,
        #[arg(long)]
        latitude: f64,
        #[arg(long)]
        longitude: f64,
        #[arg(long, default_value_t = 100.0)]
        radius: f64,
        #[arg(long, value_enum, default_value = "arriving")]
        proximity: ReminderProximity,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum ReminderProximity {
    Arriving,
    Leaving,
}

#[derive(Subcommand)]
enum ReminderHashtagCommand {
    #[command(about = "List hashtags attached to a reminder")]
    List { id: String },
    #[command(about = "Attach a hashtag to a reminder")]
    Create { id: String, name: String },
    #[command(about = "Rename a hashtag")]
    Update {
        id: String,
        hashtag_id: String,
        name: String,
    },
    #[command(about = "Remove a hashtag; requires --yes")]
    Delete {
        id: String,
        hashtag_id: String,
        #[arg(long, required = true)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum ReminderAttachmentCommand {
    #[command(about = "List attachments on a reminder")]
    List { id: String },
    #[command(about = "Attach a URL to a reminder")]
    CreateUrl {
        id: String,
        #[arg(long)]
        url: String,
        #[arg(long, default_value = "public.url")]
        uti: String,
    },
    #[command(about = "Update a URL attachment")]
    Update {
        id: String,
        attachment_id: String,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        uti: Option<String>,
    },
    #[command(about = "Remove an attachment; requires --yes")]
    Delete {
        id: String,
        attachment_id: String,
        #[arg(long, required = true)]
        yes: bool,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum ReminderFrequency {
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

#[derive(Subcommand)]
enum ReminderRecurrenceCommand {
    #[command(about = "List recurrence rules on a reminder")]
    List { id: String },
    #[command(about = "Add a recurrence rule")]
    Create {
        id: String,
        #[arg(long, value_enum, default_value = "daily")]
        frequency: ReminderFrequency,
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(i64).range(1..))]
        interval: i64,
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(i64).range(0..))]
        occurrence_count: i64,
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(i64).range(0..=6))]
        first_day_of_week: i64,
    },
    #[command(about = "Update a recurrence rule")]
    Update {
        id: String,
        rule_id: String,
        #[arg(long, value_enum)]
        frequency: Option<ReminderFrequency>,
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        interval: Option<i64>,
        #[arg(long, value_parser = clap::value_parser!(i64).range(0..))]
        occurrence_count: Option<i64>,
        #[arg(long, value_parser = clap::value_parser!(i64).range(0..=6))]
        first_day_of_week: Option<i64>,
    },
    #[command(about = "Remove a recurrence rule; requires --yes")]
    Delete {
        id: String,
        rule_id: String,
        #[arg(long, required = true)]
        yes: bool,
    },
}
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum CalendarCommand {
    #[command(
        about = "List calendars",
        long_about = "Read the calendars available in the selected iCloud account. The default output contains each calendar's name and stable ID. Use `--include href`, `--include dsid`, or `--include color` to request the full CalDAV URL, server identifier, or Apple's calendar color. Repeat `--include` or comma-separate fields. Color values are normalized to uppercase #RRGGBBAA; a missing server property is returned as null. Select the account with EMAIL or use the configured default account.",
        after_help = "EMAIL can be provided as the first argument or with `--email`. Available extra fields for `--include`: href, dsid, color.\n\nOptions available: --email, --include, --json, --format <agent|csv|json>, --help."
    )]
    List {
        #[arg(value_name = "EMAIL")]
        email: Option<String>,
        #[arg(long = "email", value_name = "EMAIL", conflicts_with = "email")]
        email_flag: Option<String>,
        #[arg(
            long,
            value_name = "FIELD",
            value_delimiter = ',',
            help = "Include extra calendar fields: href, dsid, color; repeat or comma-separate"
        )]
        include: Vec<String>,
    },
    #[command(
        about = "Create a calendar",
        long_about = "Create a new calendar in the selected iCloud account. Provide the calendar NAME as a positional argument. iCloud decides which calendar properties are available after creation; use `icli calendar list` to confirm its name and ID. Select an account with `--email` or use the configured default account.",
        after_help = "Required argument: NAME is the name for the new calendar.\n\nOptions available: --email, --json, --format <agent|csv|json>, --help."
    )]
    Create {
        #[arg(value_name = "NAME")]
        name: String,
        #[arg(long, value_name = "EMAIL")]
        email: Option<String>,
    },
    #[command(
        about = "Rename a calendar",
        long_about = "Rename an existing calendar in the selected iCloud account. CALENDAR_OR_ID may be the calendar name or its ID from `icli calendar list`. Supply the new name with `--name`. This operation changes the calendar name; it does not move or modify its events.",
        after_help = "Required arguments: CALENDAR_OR_ID identifies the existing calendar; --name supplies its new name.\n\nOptions available: --name, --email, --json, --format <agent|csv|json>, --help."
    )]
    Update {
        #[arg(value_name = "CALENDAR_OR_ID")]
        calendar: String,
        #[arg(long, value_name = "NAME", required = true)]
        name: String,
        #[arg(long, value_name = "EMAIL")]
        email: Option<String>,
    },
    #[command(
        about = "Delete a calendar",
        long_about = "Permanently delete a calendar from the selected iCloud account. CALENDAR_OR_ID may be its name or ID from `icli calendar list`. The command requires `--yes` as explicit confirmation. Check the target calendar before confirming; deletion affects the remote iCloud calendar and its contents.",
        after_help = "Required arguments: CALENDAR_OR_ID identifies the calendar; --yes confirms the remote deletion.\n\nOptions available: --email, --yes, --json, --format <agent|csv|json>, --help."
    )]
    Delete {
        #[arg(value_name = "CALENDAR_OR_ID")]
        calendar: String,
        #[arg(long, value_name = "EMAIL")]
        email: Option<String>,
        #[arg(long, required = true)]
        yes: bool,
    },
    #[command(about = "Set a calendar color")]
    Color(CalendarColorArgs),
    #[command(about = "Manage calendar sharing permissions")]
    Share {
        #[command(subcommand)]
        action: CalendarShareCommand,
    },
    #[command(
        about = "List or manage calendar events",
        long_about = "Use the event subcommands to list events for a date range, search event text, retrieve an event by UID, create, update, delete, or import events from an iCalendar file. List takes FROM and TO dates in YYYY-MM-DD form, interpreted as UTC with TO inclusive. Search accepts an optional date range and searches selected event properties across one or all calendars. Add `--calendar NAME_OR_ID` to restrict either operation to one calendar. The legacy form `icli calendar events [CALENDAR] FROM TO` is also accepted. List and import can run independent CalDAV requests concurrently; both default to 2 requests and accept `--concurrency` from 1 to 8. Event reads include common fields by default; use `--include PROPERTY,...` to request other properties returned by CalDAV.",
        after_help = "For an operation, use `icli calendar events <list|search|get|create|update|delete|import> --help`. EMAIL can be selected with `--email` or the configured default account.\n\nOptions available: --calendar, --from, --to, --email, --include, --concurrency (list/import/search), --json, --format <agent|csv|json>, --help."
    )]
    Events {
        #[command(subcommand)]
        action: Option<CalendarEventsCommand>,
        // Preserve the original `calendar events [CALENDAR] FROM TO` form.
        #[arg(value_name = "CALENDAR_OR_ID")]
        calendar_pos: Option<String>,
        #[arg(value_name = "FROM")]
        from_pos: Option<String>,
        #[arg(value_name = "TO")]
        to_pos: Option<String>,
        #[arg(value_name = "EMAIL")]
        email_pos: Option<String>,
        #[arg(long, value_name = "CALENDAR_OR_ID")]
        calendar: Option<String>,
        #[arg(long, value_name = "DATE")]
        from: Option<String>,
        #[arg(long, value_name = "DATE")]
        to: Option<String>,
        #[arg(long = "email", value_name = "EMAIL", conflicts_with = "email_pos")]
        email_flag: Option<String>,
        #[arg(long, value_name = "PROPERTY", value_delimiter = ',')]
        include: Vec<String>,
    },
}
#[derive(Args)]
struct CalendarColorArgs {
    #[arg(value_name = "CALENDAR_OR_ID")]
    calendar: String,
    #[arg(long, required = true, value_name = "COLOR")]
    color: String,
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
}
#[derive(Subcommand)]
enum CalendarShareCommand {
    #[command(about = "List calendar sharees and invitation status")]
    List(CalendarShareListArgs),
    #[command(about = "Invite a person to a calendar")]
    Grant(CalendarShareGrantArgs),
    #[command(about = "Remove a person's calendar invitation")]
    Revoke(CalendarShareGrantArgs),
}
#[derive(Args)]
struct CalendarShareListArgs {
    #[arg(value_name = "CALENDAR_OR_ID")]
    calendar: String,
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
    #[arg(long, help = "Include redacted DAV ACL and principal diagnostics")]
    debug: bool,
}
#[derive(Args)]
struct CalendarShareGrantArgs {
    #[arg(value_name = "CALENDAR_OR_ID")]
    calendar: String,
    #[arg(long, value_name = "EMAIL", required = true)]
    person: String,
    #[arg(long,value_parser=["read","write"],default_value="read")]
    permission: String,
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
    #[arg(long, help = "Include redacted DAV request and response diagnostics")]
    debug: bool,
}

#[derive(Subcommand)]
enum CalendarEventsCommand {
    #[command(
        about = "List events in a date range",
        long_about = "List events between FROM and TO for one calendar or all calendars in the selected iCloud account. Use dates in YYYY-MM-DD form; they are interpreted as UTC and TO is inclusive. Omit `--calendar` to search all calendars. Independent calendar queries run concurrently, up to 2 at a time by default; set `--concurrency` from 1 to 8 to tune request parallelism. The default output includes summary, start, end, location, description, UID, status, organizer, attendees, recurrence, and nested `alarms`. Add `--include PROPERTY` or comma-separate properties to include top-level iCalendar properties returned by CalDAV; matching `*_params` fields are included when available. VALARM properties are nested under `alarms` and are not top-level include names. Arbitrary provider and custom property names are accepted; absent names are reported as warnings.",
        after_help = "Required arguments: FROM and TO use YYYY-MM-DD. CALENDAR_OR_ID is optional; omitting it searches every calendar. Include names are iCalendar VEVENT property names such as url, geo, or class. Repeat --include or comma-separate names.\n\nOptions available: --calendar, --email, --include, --concurrency 1..8 (default 2), --json, --format <agent|csv|json>, --help."
    )]
    List {
        #[arg(value_name = "FROM")]
        from: String,
        #[arg(value_name = "TO")]
        to: String,
        #[arg(long, value_name = "CALENDAR_OR_ID")]
        calendar: Option<String>,
        #[arg(long = "email", value_name = "EMAIL")]
        email: Option<String>,
        #[arg(long, value_name = "PROPERTY", value_delimiter = ',')]
        include: Vec<String>,
        #[arg(long, value_name = "N", default_value_t = 2, value_parser = parse_dav_concurrency)]
        concurrency: usize,
    },
    #[command(
        about = "Search event text",
        long_about = "Search event properties using CalDAV text-match filters. The default fields are SUMMARY, DESCRIPTION, and LOCATION. Results match the query as a substring, case-insensitively, in any selected field. Add --from and --to together to limit matching events to an inclusive UTC date range; omit both to search all events. Add --calendar to restrict the search to one calendar, otherwise every calendar is queried. The server performs property matching when supported; iCLI falls back to fetching that calendar's events and matching locally if the server rejects a filter. After matching, --skip skips results and --limit caps the returned page.",
        after_help = "The query is a literal string, not a regular expression or a CalDAV expression. --field accepts summary, description, location, attendee, organizer, and categories. Search returns the regular event fields plus the selected search properties, and honors --include.\n\nOptions available: --calendar, --from, --to, --field, --skip, --limit, --concurrency, --email, --include, --json, --format <agent|csv|json>, --help."
    )]
    Search(CalendarEventsSearchArgs),
    #[command(
        about = "Retrieve one event by UID",
        long_about = "Retrieve an event using its iCalendar UID. The UID is shown by event list results. CALENDAR_OR_ID is required to identify the calendar containing the event. Event fields shown by default match the event list; use `--include PROPERTY` or comma-separate names to request top-level iCalendar properties. VALARM values are nested under `alarms`. Arbitrary provider and custom property names are accepted; absent names are reported as warnings.",
        after_help = "Required arguments: UID is the event's iCalendar UID; --calendar identifies its calendar by name or ID.\n\nOptions available: --calendar, --email, --include, --json, --format <agent|csv|json>, --help."
    )]
    Get {
        #[arg(value_name = "UID")]
        uid: String,
        #[arg(long, value_name = "CALENDAR_OR_ID")]
        calendar: String,
        #[arg(long = "email", value_name = "EMAIL")]
        email: Option<String>,
        #[arg(long, value_name = "PROPERTY", value_delimiter = ',')]
        include: Vec<String>,
    },
    #[command(
        about = "Create an event",
        long_about = "Create an event in the selected calendar. Provide --summary and either both --start and --end as RFC3339 date-times, or --all-day as a YYYY-MM-DD date. Optional --location and --description values are written to the event. Repeat --participant EMAIL to add invitees, --alarm-minutes MINUTES to add display alarms, and use --rrule for recurrence. iCLI reads back CalDAV SCHEDULE-STATUS when available; this reports server delivery state, not whether a recipient saw a notification.",
        after_help = "Required arguments: --calendar identifies the calendar; --summary is the event title. Provide --start and --end together, or use --all-day DATE instead. Recurrence rules use iCalendar KEY=VALUE syntax, e.g. FREQ=WEEKLY;BYDAY=MO.\n\nOptions available: --calendar, --summary, --start, --end, --all-day, --location, --description, --rrule, --alarm-minutes, --participant, --attendee, --email, --json, --format <agent|csv|json>, --help."
    )]
    Create(EventCreateArgs),
    #[command(
        about = "Update an existing event",
        long_about = "Update an event identified by its iCalendar UID in the required calendar. Provide one or more fields to change: --summary, --start, --end, --all-day, --location, --description, --rrule, or --alarm-minutes. Repeat --participant EMAIL to add invitees while retaining existing attendees. iCLI reads back CalDAV SCHEDULE-STATUS when available; this reports server delivery state, not whether a recipient saw a notification. --clear-recurrence removes RRULE; --clear-alarms removes all alarms. When changing a timed event, provide both --start and --end as RFC3339 date-times. Unspecified fields are left as they are.",
        after_help = "Required arguments: UID is the event's iCalendar UID; --calendar identifies its calendar. Supply at least one field to update. Use --start and --end together, or use --all-day DATE; those options cannot be combined. Use --alarm-minutes to replace alarms; use --clear-alarms to remove them.\n\nOptions available: --calendar, --summary, --start, --end, --all-day, --location, --description, --rrule, --alarm-minutes, --participant, --attendee, --clear-alarms, --clear-recurrence, --email, --json, --format <agent|csv|json>, --help."
    )]
    Update(EventUpdateArgs),
    #[command(
        about = "Delete an event",
        long_about = "Permanently delete an event from iCloud. Use the event's iCalendar UID shown in event list results and identify its calendar by name or ID. This changes the remote calendar immediately.",
        after_help = "Required arguments: UID is the event's iCalendar UID; --calendar identifies its calendar.\n\nOptions available: --calendar, --email, --json, --format <agent|csv|json>, --help."
    )]
    Delete {
        #[arg(value_name = "UID")]
        uid: String,
        #[arg(long, value_name = "CALENDAR_OR_ID")]
        calendar: String,
        #[arg(long = "email", value_name = "EMAIL")]
        email: Option<String>,
        #[arg(long, required = true, help = "Confirm permanent event deletion")]
        yes: bool,
    },
    #[command(
        about = "Import events from an iCalendar file",
        long_about = "Read an ICS_FILE and create its VEVENT entries in the selected calendar using up to 2 concurrent CalDAV requests by default. Set --concurrency from 1 to 8 to tune request parallelism. Each event write automatically retries transient server and connection failures up to 2 times with backoff, honoring Retry-After when provided. The import may create several remote events and is not atomic: successful entries remain if another entry ultimately fails. Existing events are not overwritten by UID. Review the file and target calendar before importing; inspect per-item attempt_errors and final failures in the command result.",
        after_help = "Required arguments: ICS_FILE is the path to an iCalendar file; --calendar identifies the destination calendar by name or ID.\n\nOptions available: --calendar, --email, --concurrency 1..8 (default 2), --json, --format <agent|csv|json>, --help."
    )]
    Import {
        #[arg(value_name = "ICS_FILE")]
        file: PathBuf,
        #[arg(long, value_name = "CALENDAR_OR_ID", required = true)]
        calendar: String,
        #[arg(long = "email", value_name = "EMAIL")]
        email: Option<String>,
        #[arg(long, value_name = "N", default_value_t = 2, value_parser = parse_dav_concurrency)]
        concurrency: usize,
    },
}

#[derive(Args)]
struct CalendarEventsSearchArgs {
    #[arg(value_name = "QUERY")]
    query: String,
    #[arg(long, value_name = "CALENDAR_OR_ID")]
    calendar: Option<String>,
    #[arg(long, value_name = "DATE", requires = "to")]
    from: Option<String>,
    #[arg(long, value_name = "DATE", requires = "from")]
    to: Option<String>,
    #[arg(long = "field", value_name = "FIELD", value_delimiter = ',', value_parser = ["summary", "description", "location", "attendee", "organizer", "categories"])]
    fields: Vec<String>,
    #[arg(long, default_value_t = 100)]
    limit: usize,
    #[arg(long, default_value_t = 0)]
    skip: usize,
    #[arg(long, default_value_t = 2, value_parser = parse_dav_concurrency)]
    concurrency: usize,
    #[arg(long = "email", value_name = "EMAIL")]
    email: Option<String>,
    #[arg(long, value_name = "PROPERTY", value_delimiter = ',')]
    include: Vec<String>,
}

#[derive(Args)]
struct EventCreateArgs {
    #[arg(long, value_name = "CALENDAR_OR_ID", required = true)]
    calendar: String,
    #[arg(long, required = true)]
    summary: String,
    #[arg(long, value_name = "RFC3339")]
    start: Option<String>,
    #[arg(long, value_name = "RFC3339")]
    end: Option<String>,
    #[arg(long, value_name = "DATE", conflicts_with_all = ["start", "end"])]
    all_day: Option<String>,
    #[arg(long)]
    location: Option<String>,
    #[arg(long)]
    description: Option<String>,
    #[arg(
        long,
        value_name = "RRULE",
        help = "iCalendar recurrence rule, e.g. FREQ=WEEKLY;BYDAY=MO"
    )]
    rrule: Option<String>,
    #[arg(
        long = "alarm-minutes",
        value_name = "MINUTES",
        help = "Add a display alarm this many minutes before the event; repeat for more alarms"
    )]
    alarm_minutes: Vec<u32>,
    #[arg(
        long = "participant",
        visible_alias = "attendee",
        value_name = "EMAIL",
        help = "Add an invitee as an iCalendar ATTENDEE property; repeat for more invitees"
    )]
    participants: Vec<String>,
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
}

#[derive(Args)]
struct EventUpdateArgs {
    #[arg(value_name = "UID")]
    uid: String,
    #[arg(long, value_name = "CALENDAR_OR_ID", required = true)]
    calendar: String,
    #[arg(long)]
    summary: Option<String>,
    #[arg(long, value_name = "RFC3339")]
    start: Option<String>,
    #[arg(long, value_name = "RFC3339")]
    end: Option<String>,
    #[arg(long, value_name = "DATE", conflicts_with_all = ["start", "end"])]
    all_day: Option<String>,
    #[arg(long)]
    location: Option<String>,
    #[arg(long)]
    description: Option<String>,
    #[arg(
        long,
        value_name = "RRULE",
        help = "Replace recurrence rule, e.g. FREQ=WEEKLY;BYDAY=MO"
    )]
    rrule: Option<String>,
    #[arg(
        long = "alarm-minutes",
        value_name = "MINUTES",
        help = "Replace alarms with these minutes-before-start values; repeat for more alarms"
    )]
    alarm_minutes: Vec<u32>,
    #[arg(
        long = "participant",
        visible_alias = "attendee",
        value_name = "EMAIL",
        help = "Add an invitee to the event; repeat for more invitees"
    )]
    participants: Vec<String>,
    #[arg(long, conflicts_with = "alarm_minutes")]
    clear_alarms: bool,
    #[arg(long, conflicts_with = "rrule")]
    clear_recurrence: bool,
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
}
#[derive(Subcommand)]
enum MailCommand {
    #[command(about = "List mail folders")]
    Folders(MailAccountArgs),
    #[command(about = "List recent messages from a folder")]
    List(MailListArgs),
    #[command(about = "Search a mail folder")]
    Search(MailSearchArgs),
    #[command(about = "Read a message by UID")]
    Get(MailIdArgs),
    #[command(about = "Download a message attachment")]
    Download(MailDownloadArgs),
    #[command(about = "Create a draft in Drafts; this does not send it")]
    Create(MailCreateArgs),
    #[command(about = "Change read or flagged state for a message")]
    Update(MailUpdateArgs),
    #[command(about = "Permanently delete a message from a folder")]
    Delete(MailDeleteArgs),
    #[command(about = "Move a message to another folder")]
    Move(MailMoveArgs),
    #[command(about = "Send a message")]
    Send(MailCreateArgs),
}
#[derive(Args)]
struct MailAccountArgs {
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
}
#[derive(Args)]
struct MailListArgs {
    #[arg(long, default_value_t = 10)]
    limit: usize,
    #[arg(long, default_value_t = 0)]
    skip: usize,
    #[arg(long, default_value = "INBOX")]
    folder: String,
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
}
#[derive(Args)]
struct MailSearchArgs {
    #[arg(value_name = "QUERY")]
    query: String,
    #[arg(long, default_value = "INBOX")]
    folder: String,
    #[arg(long, default_value_t = 50)]
    limit: usize,
    #[arg(long, default_value_t = 0)]
    skip: usize,
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
}
#[derive(Args)]
struct MailIdArgs {
    #[arg(value_name = "UID")]
    uid: u32,
    #[arg(long, default_value = "INBOX")]
    folder: String,
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
}
#[derive(Args)]
struct MailCreateArgs {
    #[arg(long, value_name = "EMAIL", required = true)]
    to: String,
    #[arg(long, required = true)]
    subject: String,
    #[arg(long, required = true)]
    body: String,
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
}
#[derive(Args)]
struct MailUpdateArgs {
    #[arg(value_name = "UID")]
    uid: u32,
    #[arg(
        long,
        value_name = "FLAG",
        required = true,
        value_parser = ["seen", "unseen", "flagged", "unflagged"],
        help = "Set message state: seen, unseen, flagged, or unflagged"
    )]
    flag: String,
    #[arg(long, default_value = "INBOX")]
    folder: String,
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
}
#[derive(Args)]
struct MailDeleteArgs {
    #[arg(value_name = "UID")]
    uid: u32,
    #[arg(long, default_value = "INBOX")]
    folder: String,
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
    #[arg(long, required = true, help = "Confirm permanent message deletion")]
    yes: bool,
}
#[derive(Args)]
struct MailMoveArgs {
    #[arg(value_name = "UID")]
    uid: u32,
    #[arg(long, value_name = "FOLDER", required = true)]
    destination: String,
    #[arg(long, default_value = "INBOX")]
    source: String,
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
}
#[derive(Args)]
struct MailDownloadArgs {
    #[arg(value_name = "UID")]
    uid: u32,
    #[arg(long, value_name = "PART_ID", required = true)]
    part: String,
    #[arg(long, value_name = "FILE", required = true)]
    output: PathBuf,
    #[arg(long, default_value = "INBOX")]
    folder: String,
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
}
#[derive(Subcommand)]
enum ContactsCommand {
    #[command(about = "Find the contact matching the configured account address")]
    Me(ContactMeArgs),
    #[command(about = "Manage contact groups")]
    Groups {
        #[command(subcommand)]
        action: ContactGroupCommand,
    },
    #[command(
        about = "List contacts",
        long_about = "List contacts. Use --include PROPERTY or a comma-separated list to return additional vCard properties under each contact's properties object. Repeat --include or comma-separate names. Property names are case-insensitive; standard and custom X- properties are supported. `--include all` returns every property, including parameters."
    )]
    List(ContactsListArgs),
    #[command(
        about = "Search contacts",
        long_about = "Search CardDAV address books for a case-insensitive substring in any selected vCard property. By default, search formatted name (FN), email (EMAIL), and phone (TEL). Use --field to choose name, email, phone, or organization. Results include the same summary fields as contacts list and return the selected search properties under properties; --include adds more vCard properties. After matching, contacts are sorted by UID and --skip is applied before --limit. iCLI falls back to fetching the address book and matching locally if the server rejects a supported-field filter. Contact groups are excluded.",
        after_help = "Examples:\n  icli contacts search \"Alex Kim\"\n  icli contacts search example.com --field email --include ORG\n\nThe query is literal text, not a regular expression or a CardDAV expression. Matching uses a Unicode-aware case-insensitive contains search.\n\nOptions available: --field, --skip, --limit, --email, --include, --json, --format <agent|csv|json>, --help."
    )]
    Search(ContactsSearchArgs),
    #[command(
        about = "Retrieve a contact by UID",
        long_about = "Retrieve a contact by UID. Use --include PROPERTY or a comma-separated list to return additional vCard properties under the contact's properties object. Repeat --include or comma-separate names. Property names are case-insensitive; standard and custom X- properties are supported. `--include all` returns every property, including parameters."
    )]
    Get(ContactIdArgs),
    #[command(about = "List vCard properties available in this account")]
    Help(ContactHelpArgs),
    #[command(about = "Create a contact")]
    Create(ContactCreateArgs),
    #[command(about = "Update a contact by UID")]
    Update(ContactUpdateArgs),
    #[command(about = "Delete a contact by UID")]
    Delete(ContactDeleteArgs),
}

#[derive(Args)]
struct ContactsSearchArgs {
    #[arg(value_name = "QUERY")]
    query: String,
    #[arg(long = "field", value_name = "FIELD", value_delimiter = ',', value_parser = ["name", "email", "phone", "organization"])]
    fields: Vec<String>,
    #[arg(long, default_value_t = 100)]
    limit: usize,
    #[arg(long, default_value_t = 0)]
    skip: usize,
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
    #[arg(long, value_name = "PROPERTY", value_delimiter = ',')]
    include: Vec<String>,
}
#[derive(Subcommand)]
enum ContactGroupCommand {
    #[command(about = "List contact groups")]
    List(ContactHelpArgs),
    #[command(about = "Create a contact group")]
    Create(ContactGroupCreateArgs),
    #[command(about = "Update a contact group's name or members")]
    Update(ContactGroupUpdateArgs),
    #[command(about = "Delete a contact group")]
    Delete(ContactDeleteArgs),
}
#[derive(Args)]
struct ContactGroupCreateArgs {
    #[arg(long, required = true)]
    name: String,
    #[arg(long = "member", value_name = "CONTACT_UID", required = true)]
    members: Vec<String>,
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
}
#[derive(Args)]
struct ContactGroupUpdateArgs {
    #[arg(value_name = "UID")]
    uid: String,
    #[arg(long)]
    name: Option<String>,
    #[arg(long = "member", value_name = "CONTACT_UID")]
    members: Vec<String>,
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
}
#[derive(Args)]
struct ContactsListArgs {
    #[arg(long, default_value_t = 100)]
    limit: usize,
    #[arg(long, default_value_t = 0)]
    skip: usize,
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
    #[arg(long, value_name = "PROPERTY", value_delimiter = ',')]
    include: Vec<String>,
}
#[derive(Args)]
struct ContactIdArgs {
    #[arg(value_name = "UID")]
    uid: String,
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
    #[arg(long, value_name = "PROPERTY", value_delimiter = ',')]
    include: Vec<String>,
}
#[derive(Args)]
struct ContactHelpArgs {
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
}
#[derive(Args)]
struct ContactMeArgs {
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
    #[arg(
        long,
        help = "Show account identity, address books, and card identity properties without guessing a match"
    )]
    diagnose: bool,
}
#[derive(Args)]
struct ContactFields {
    #[arg(
        long,
        value_name = "NAME",
        help = "Set formatted name and structured name"
    )]
    name: Option<String>,
    #[arg(
        long = "contact-email",
        value_name = "EMAIL",
        help = "Set the contact email, distinct from the account selected by --email"
    )]
    address: Option<String>,
    #[arg(long, value_name = "PHONE")]
    phone: Option<String>,
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
    #[arg(
        long = "property",
        value_name = "NAME=VALUE",
        help = "Set any vCard property as a text value; repeat to set multiple values of one property"
    )]
    properties: Vec<String>,
    #[arg(
        long,
        value_name = "VCF_FILE",
        help = "Merge one complete vCard, preserving parameters and structured values; overlapping flags are rejected"
    )]
    vcard_file: Option<PathBuf>,
}
#[derive(Args)]
struct ContactCreateArgs {
    #[command(flatten)]
    fields: ContactFields,
}
#[derive(Args)]
struct ContactUpdateArgs {
    #[arg(value_name = "UID")]
    uid: String,
    #[command(flatten)]
    fields: ContactFields,
}
#[derive(Args)]
struct ContactDeleteArgs {
    #[arg(value_name = "UID")]
    uid: String,
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,
    #[arg(long, required = true)]
    yes: bool,
}

#[derive(Serialize, Deserialize, Clone)]
struct Account {
    email: String,
}
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct Config {
    accounts: Vec<Account>,
    default_user: Option<String>,
    response_format: OutputFormat,
}
#[derive(Serialize)]
struct Event {
    summary: String,
    start: String,
    end: String,
    location: String,
    description: String,
    uid: String,
    alarms: Vec<BTreeMap<String, serde_json::Value>>,
    #[serde(flatten)]
    other_properties: BTreeMap<String, serde_json::Value>,
}
#[derive(Serialize, Deserialize)]
struct Contact {
    uid: String,
    name: String,
    emails: Vec<String>,
    phones: Vec<String>,
    #[serde(default)]
    birthday: String,
    #[serde(rename = "_all_properties", default)]
    all_properties: BTreeMap<String, Vec<serde_json::Value>>,
}
#[derive(Serialize)]
struct Message {
    uid: u32,
    from: String,
    subject: String,
    date: String,
}

fn is_group_contact(contact: &Contact) -> bool {
    ["KIND", "X-ADDRESSBOOKSERVER-KIND"].iter().any(|key| {
        contact.all_properties.get(*key).is_some_and(|values| {
            values.iter().any(|v| {
                v.get("value")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|s| s.eq_ignore_ascii_case("group"))
            })
        })
    })
}

fn validate_group_values(name: &str, members: &[String]) -> Result<()> {
    if name.trim().is_empty() || name.contains(['\r', '\n']) {
        bail!("Group name must be non-empty and contain no line breaks");
    }
    if members.is_empty() {
        bail!("A contact group must include at least one --member CONTACT_UID");
    }
    if members
        .iter()
        .any(|uid| uid.trim().is_empty() || uid.contains(['\r', '\n']))
    {
        bail!("Group member UIDs must be non-empty and contain no line breaks");
    }
    Ok(())
}

fn make_contact_group(uid: &str, name: &str, members: &[String]) -> String {
    let mut lines = vec![
        "BEGIN:VCARD".to_string(),
        "VERSION:3.0".into(),
        format!("UID:{}", escape_ical_text(uid)),
        format!("FN:{}", escape_ical_text(name)),
        format!("N:{};;;;", escape_ical_text(name)),
        "X-ADDRESSBOOKSERVER-KIND:group".into(),
    ];
    lines.extend(members.iter().map(|member| {
        format!(
            "X-ADDRESSBOOKSERVER-MEMBER:urn:uuid:{}",
            escape_ical_text(member.trim_start_matches("urn:uuid:"))
        )
    }));
    lines.push("END:VCARD".into());
    serialize_vcard_lines(&lines)
}

fn run_contacts(action: ContactsCommand, format: OutputFormat) -> Result<()> {
    match action {
        ContactsCommand::Me(args) => {
            let a = account(args.email)?;
            let p = secret(&a)?;
            let vals = dav_items(
                "https://contacts.icloud.com/",
                &a.email,
                &p,
                "contact",
                None,
                None,
            )?;
            let contacts: Vec<Contact> = vals
                .into_iter()
                .map(serde_json::from_value)
                .collect::<std::result::Result<_, _>>()?;
            if args.diagnose {
                let addressbooks = discover_contact_addressbooks(&a.email, &p)?;
                let cards = contacts
                    .iter()
                    .filter(|contact| !is_group_contact(contact))
                    .map(|contact| {
                        let apple_properties = contact
                            .all_properties
                            .iter()
                            .filter(|(name, _)| {
                                name.rsplit('.')
                                    .next()
                                    .unwrap_or(name)
                                    .to_ascii_uppercase()
                                    .starts_with("X-")
                            })
                            .map(|(name, values)| (name.clone(), serde_json::json!(values)))
                            .collect::<serde_json::Map<_, _>>();
                        serde_json::json!({
                            "uid": contact.uid,
                            "fn": contact.name,
                            "emails": contact.emails,
                            "apple_properties": apple_properties
                        })
                    })
                    .collect::<Vec<_>>();
                let exact_matches = contacts
                    .iter()
                    .filter(|contact| {
                        !is_group_contact(contact)
                            && contact
                                .emails
                                .iter()
                                .any(|email| email.eq_ignore_ascii_case(&a.email))
                    })
                    .map(|contact| contact.uid.clone())
                    .collect::<Vec<_>>();
                return output(
                    &serde_json::json!({
                        "account_email": a.email,
                        "match_rule": "case-insensitive exact match against card EMAIL values",
                        "addressbooks": addressbooks,
                        "contact_count": cards.len(),
                        "exact_match_uids": exact_matches,
                        "cards": cards
                    }),
                    format,
                    "Account contact diagnostics",
                );
            }
            let matching = contacts
                .into_iter()
                .filter(|c| {
                    !is_group_contact(c)
                        && c.emails.iter().any(|e| e.eq_ignore_ascii_case(&a.email))
                })
                .collect::<Vec<_>>();
            if matching.is_empty() {
                bail!("No contact card matched account email {}", a.email);
            }
            if matching.len() > 1 {
                bail!(
                    "Several contact cards match account email {}: {}. Retrieve one by UID with `icli contacts get UID`.",
                    a.email,
                    matching
                        .iter()
                        .map(|c| c.uid.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            output_contacts(matching, None, format, "Account contact", &["all".into()])
        }
        ContactsCommand::Groups { action } => match action {
            ContactGroupCommand::List(args) => {
                let a = account(args.email)?;
                let p = secret(&a)?;
                let vals = dav_items(
                    "https://contacts.icloud.com/",
                    &a.email,
                    &p,
                    "contact",
                    None,
                    None,
                )?;
                let groups = vals
                    .into_iter()
                    .map(serde_json::from_value::<Contact>)
                    .collect::<std::result::Result<Vec<_>, _>>()?
                    .into_iter()
                    .filter(is_group_contact)
                    .collect::<Vec<_>>();
                output_contacts(groups, None, format, "Contact groups", &["all".into()])
            }
            ContactGroupCommand::Create(args) => {
                validate_group_values(&args.name, &args.members)?;
                let a = account(args.email)?;
                let p = secret(&a)?;
                let uid = format!(
                    "{}-{}@icli",
                    Utc::now().timestamp_nanos_opt().unwrap_or_default(),
                    std::process::id()
                );
                let card = make_contact_group(&uid, &args.name, &args.members);
                let url = contact_resource_url(&a.email, &p, &uid, true)?;
                carddav_write(
                    &url,
                    &a.email,
                    &p,
                    "PUT",
                    &card,
                    Some(("If-None-Match", "*")),
                )?;
                output(
                    &serde_json::json!({"uid":uid,"name":args.name,"members":args.members,"created":true}),
                    format,
                    "Created contact group",
                )
            }
            ContactGroupCommand::Update(args) => {
                if args.name.is_none() && args.members.is_empty() {
                    bail!("Provide --name or at least one --member to update");
                }
                let a = account(args.email)?;
                let p = secret(&a)?;
                let url = contact_resource_url(&a.email, &p, &args.uid, false)?;
                let (existing, etag) = carddav_read(&url, &a.email, &p)?;
                let current = parse_vcards(&existing)
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow!("Invalid group vCard"))?;
                if !is_group_contact(&current) {
                    bail!("UID {} is not a contact group", args.uid);
                }
                let name = args.name.unwrap_or(current.name);
                let members = if args.members.is_empty() {
                    current
                        .all_properties
                        .get("X-ADDRESSBOOKSERVER-MEMBER")
                        .or_else(|| current.all_properties.get("MEMBER"))
                        .into_iter()
                        .flatten()
                        .filter_map(|v| {
                            v.get("value")
                                .and_then(serde_json::Value::as_str)
                                .map(|s| s.trim_start_matches("urn:uuid:").to_string())
                        })
                        .collect::<Vec<_>>()
                } else {
                    args.members
                };
                validate_group_values(&name, &members)?;
                let card = make_contact_group(&current.uid, &name, &members);
                carddav_write(
                    &url,
                    &a.email,
                    &p,
                    "PUT",
                    &card,
                    etag.as_deref().map(|tag| ("If-Match", tag)),
                )?;
                output(
                    &serde_json::json!({"uid":current.uid,"name":name,"members":members,"updated":true}),
                    format,
                    "Updated contact group",
                )
            }
            ContactGroupCommand::Delete(args) => {
                let a = account(args.email)?;
                let p = secret(&a)?;
                let url = contact_resource_url(&a.email, &p, &args.uid, false)?;
                let (data, _) = carddav_read(&url, &a.email, &p)?;
                let contact = parse_vcards(&data)
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow!("Invalid group vCard"))?;
                if !is_group_contact(&contact) {
                    bail!("UID {} is not a contact group", args.uid);
                }
                carddav_write(&url, &a.email, &p, "DELETE", "", None)?;
                output(
                    &serde_json::json!({"uid":args.uid,"deleted":true}),
                    format,
                    "Deleted contact group",
                )
            }
        },
        ContactsCommand::List(args) => {
            let a = account(args.email)?;
            let p = secret(&a)?;
            let vals = dav_items(
                "https://contacts.icloud.com/",
                &a.email,
                &p,
                "contact",
                None,
                None,
            )?;
            let contacts: Vec<Contact> = vals
                .into_iter()
                .map(serde_json::from_value)
                .collect::<std::result::Result<Vec<Contact>, _>>()?
                .into_iter()
                .filter(|c| !is_group_contact(c))
                .collect();
            output_contacts(
                contacts,
                Some((args.skip, args.limit)),
                format,
                "Here are the contacts",
                &args.include,
            )
        }
        ContactsCommand::Search(args) => {
            let query = validate_search_query(&args.query)?;
            let fields = if args.fields.is_empty() {
                vec!["name".into(), "email".into(), "phone".into()]
            } else {
                args.fields
            };
            let a = account(args.email)?;
            let p = secret(&a)?;
            let vals = dav_items_with_search(
                "https://contacts.icloud.com/",
                &a.email,
                &p,
                "contact",
                None,
                None,
                1,
                Some(DavSearch::Contacts {
                    query: query.clone(),
                    fields: fields.clone(),
                }),
            )?;
            let contacts: Vec<Contact> = vals
                .into_iter()
                .map(serde_json::from_value)
                .collect::<std::result::Result<_, _>>()?;
            let contacts = contacts
                .into_iter()
                .filter(|contact| {
                    !is_group_contact(contact) && contact_matches_query(contact, &query, &fields)
                })
                .collect();
            let mut include = args.include;
            for field in &fields {
                let property = contact_field_property(field);
                if !include
                    .iter()
                    .any(|requested| requested.eq_ignore_ascii_case(property))
                {
                    include.push(property.to_string());
                }
            }
            output_contacts(
                contacts,
                Some((args.skip, args.limit)),
                format,
                "Contact search results",
                &include,
            )
        }
        ContactsCommand::Get(args) => {
            let a = account(args.email)?;
            let p = secret(&a)?;
            let url = contact_resource_url(&a.email, &p, &args.uid, false)?;
            let (card, _) = carddav_read(&url, &a.email, &p)?;
            let contacts = parse_vcards(&card);
            if contacts.len() != 1 {
                bail!("Invalid vCard response: expected exactly one contact");
            }
            output_contacts(contacts, None, format, "Contact", &args.include)
        }
        ContactsCommand::Help(args) => {
            let a = account(args.email)?;
            let p = secret(&a)?;
            let vals = dav_items(
                "https://contacts.icloud.com/",
                &a.email,
                &p,
                "contact",
                None,
                None,
            )?;
            let contacts: Vec<Contact> = vals
                .into_iter()
                .map(serde_json::from_value)
                .collect::<std::result::Result<_, _>>()?;
            let available = contacts
                .iter()
                .flat_map(|c| c.all_properties.keys().cloned())
                .collect::<BTreeSet<_>>();
            let parameters = contacts
                .iter()
                .flat_map(|c| c.all_properties.values())
                .flatten()
                .filter_map(|property| property.get("params"))
                .filter_map(serde_json::Value::as_object)
                .flat_map(|params| params.keys().cloned())
                .collect::<BTreeSet<_>>();
            let standard = [
                "ADR",
                "ANNIVERSARY",
                "BDAY",
                "CALADRURI",
                "CALURI",
                "CATEGORIES",
                "CLASS",
                "CLIENTPIDMAP",
                "EMAIL",
                "FBURL",
                "FN",
                "GENDER",
                "GEO",
                "IM",
                "IMPP",
                "KEY",
                "KIND",
                "LABEL",
                "LANG",
                "LOGO",
                "MAILER",
                "MEMBER",
                "N",
                "NICKNAME",
                "NOTE",
                "ORG",
                "PHOTO",
                "PROFILE",
                "PRODID",
                "RELATED",
                "REV",
                "ROLE",
                "SORT-STRING",
                "SOUND",
                "SOURCE",
                "TEL",
                "TITLE",
                "TZ",
                "UID",
                "URL",
                "VERSION",
                "XML",
            ];
            let standard = standard.iter().map(|s| s.to_string()).collect::<Vec<_>>();
            let custom = available
                .iter()
                .filter(|p| p.rsplit('.').next().unwrap_or(p).starts_with("X-"))
                .cloned()
                .collect::<Vec<_>>();
            let response = serde_json::json!({"default_fields": ["uid", "name", "emails", "phones", "birthday"], "standard_vcard_properties": standard, "properties_found_in_account": available, "custom_properties_found_in_account": custom, "property_parameter_names_found_in_account": parameters, "usage": "icli contacts list --include BDAY,ADR; requested fields are returned under properties, property names are case-insensitive, and custom X- properties are supported"});
            output(&response, format, "Available contact properties")
        }
        ContactsCommand::Create(args) => {
            let fields = args.fields;
            let generated_uid = format!(
                "{}-{}@icli",
                Utc::now().timestamp_nanos_opt().unwrap_or_default(),
                std::process::id()
            );
            let patch = contact_patch(&fields)?;
            let uid = patch
                .iter()
                .find(|line| property_key(line) == "UID")
                .and_then(|line| line.split_once(':'))
                .map(|(_, value)| value.to_string())
                .unwrap_or(generated_uid);
            let card = apply_contact_patch(None, &uid, &patch)?;
            let a = account(fields.email)?;
            let p = secret(&a)?;
            let url = contact_resource_url(&a.email, &p, &uid, true)?;
            carddav_write(
                &url,
                &a.email,
                &p,
                "PUT",
                &card,
                Some(("If-None-Match", "*")),
            )?;
            response::next(format!(
                "icli contacts get {} --include all --email {}",
                cli_quote(&uid),
                a.email
            ));
            output(
                &serde_json::json!({"uid":uid,"email":a.email,"changed_properties":patch.iter().map(|line|property_key(line)).collect::<BTreeSet<_>>()}),
                format,
                "Created contact",
            )
        }
        ContactsCommand::Update(args) => {
            let fields = args.fields;
            let patch = contact_patch(&fields)?;
            let a = account(fields.email)?;
            let p = secret(&a)?;
            let url = contact_resource_url(&a.email, &p, &args.uid, false)?;
            let (existing, etag) = carddav_read(&url, &a.email, &p)?;
            let uid = parse_vcards(&existing)
                .into_iter()
                .next()
                .filter(|card| !card.uid.is_empty())
                .map(|card| card.uid)
                .ok_or_else(|| anyhow!("Invalid vCard response: missing contact UID"))?;
            let card = apply_contact_patch(Some(&existing), &uid, &patch)?;
            carddav_write(
                &url,
                &a.email,
                &p,
                "PUT",
                &card,
                etag.as_deref().map(|tag| ("If-Match", tag)),
            )?;
            response::next(format!(
                "icli contacts get {} --include all --email {}",
                cli_quote(&url),
                a.email
            ));
            output(
                &serde_json::json!({"uid":uid,"email":a.email,"changed_properties":patch.iter().map(|line|property_key(line)).collect::<BTreeSet<_>>()}),
                format,
                "Updated contact",
            )
        }
        ContactsCommand::Delete(args) => {
            let a = account(args.email)?;
            let p = secret(&a)?;
            let url = contact_resource_url(&a.email, &p, &args.uid, false)?;
            carddav_write(&url, &a.email, &p, "DELETE", "", None)?;
            output(
                &serde_json::json!({"uid":args.uid,"deleted":true}),
                format,
                "Deleted contact",
            )
        }
    }
}

fn run_mail(action: MailCommand, format: OutputFormat) -> Result<()> {
    match action {
        MailCommand::Folders(args) => {
            let a = account(args.email)?;
            let p = secret(&a)?;
            let mut s = mail_session(&a.email, &p)?;
            let folders = s.list(Some(""), Some("*"))?;
            let rows = folders.iter().map(|f| serde_json::json!({"name":f.name(),"delimiter":f.delimiter(),"attributes":f.attributes().iter().map(|a|format!("{a:?}")).collect::<Vec<_>>() })).collect::<Vec<_>>();
            mail_logout(&mut s);
            output(&rows, format, "Mail folders")
        }
        MailCommand::List(args) => {
            let a = account(args.email)?;
            let p = secret(&a)?;
            let mut s = mail_session(&a.email, &p)?;
            s.select(&args.folder)
                .with_context(|| format!("Could not select iCloud Mail folder {}", args.folder))?;
            let ids: Vec<u32> = s
                .uid_search("ALL")
                .with_context(|| format!("Could not search iCloud Mail folder {}", args.folder))?
                .into_iter()
                .collect();
            let mut rows = Vec::new();
            for id in mail_page_ids(ids, args.skip, args.limit) {
                let fetched = s.uid_fetch(
                    id.to_string(),
                    "(UID BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])",
                )?;
                if let Some(b) = fetched.iter().next().and_then(|f| f.body()) {
                    if let Ok(parsed) = mailparse::parse_mail(b) {
                        let get = |n: &str| parsed.headers.get_first_value(n).unwrap_or_default();
                        rows.push(Message {
                            uid: id,
                            from: get("From"),
                            subject: get("Subject"),
                            date: get("Date"),
                        });
                    }
                }
            }
            mail_logout(&mut s);
            output(&rows, format, "Here are the latest messages")
        }
        MailCommand::Get(args) => {
            let a = account(args.email)?;
            let p = secret(&a)?;
            let mut s = mail_session(&a.email, &p)?;
            s.select(&args.folder)
                .with_context(|| format!("Could not select iCloud Mail folder {}", args.folder))?;
            let fetched = s.uid_fetch(args.uid.to_string(), "(UID BODY.PEEK[])")?;
            let body = fetched
                .iter()
                .next()
                .and_then(|f| f.body())
                .ok_or_else(|| {
                    anyhow!("No message found with UID {} in {}", args.uid, args.folder)
                })?;
            let parsed =
                mailparse::parse_mail(body).context("Could not parse the requested message")?;
            let get = |n: &str| parsed.headers.get_first_value(n).unwrap_or_default();
            let result = serde_json::json!({"uid":args.uid,"folder":args.folder,"from":get("From"),"to":get("To"),"subject":get("Subject"),"date":get("Date"),"body":mail_text_body(&parsed),"attachments":mail_attachment_parts(&parsed)});
            mail_logout(&mut s);
            output(&result, format, "Message")
        }
        MailCommand::Search(args) => {
            validate_mail_header("search query", &args.query)?;
            let a = account(args.email)?;
            let p = secret(&a)?;
            let mut s = mail_session(&a.email, &p)?;
            s.select(&args.folder)
                .with_context(|| format!("Could not select mail folder {}", args.folder))?;
            let quoted = args.query.replace('\\', "\\\\").replace('"', "\\\"");
            let query = format!("TEXT \"{quoted}\"");
            let ids: Vec<u32> = s
                .uid_search(&query)
                .context("Mail search failed")?
                .into_iter()
                .collect();
            let mut rows = Vec::new();
            for id in mail_page_ids(ids, args.skip, args.limit) {
                let fetched = s.uid_fetch(
                    id.to_string(),
                    "(UID BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])",
                )?;
                if let Some(b) = fetched.iter().next().and_then(|f| f.body()) {
                    if let Ok(parsed) = mailparse::parse_mail(b) {
                        let get = |n: &str| parsed.headers.get_first_value(n).unwrap_or_default();
                        rows.push(serde_json::json!({"uid":id,"from":get("From"),"subject":get("Subject"),"date":get("Date"),"folder":args.folder}));
                    }
                }
            }
            mail_logout(&mut s);
            output(&rows, format, "Mail search results")
        }
        MailCommand::Download(args) => {
            let a = account(args.email)?;
            let p = secret(&a)?;
            let mut s = mail_session(&a.email, &p)?;
            s.select(&args.folder)
                .with_context(|| format!("Could not select mail folder {}", args.folder))?;
            let fetched = s.uid_fetch(args.uid.to_string(), "(UID BODY.PEEK[])")?;
            let raw = fetched
                .iter()
                .next()
                .and_then(|f| f.body())
                .ok_or_else(|| {
                    anyhow!("No message found with UID {} in {}", args.uid, args.folder)
                })?;
            let parsed =
                mailparse::parse_mail(raw).context("Could not parse message MIME structure")?;
            let part = mail_attachment_by_id(&parsed, &args.part).ok_or_else(|| anyhow!("Attachment part {} was not found; use `icli mail get UID --folder {}` to inspect attachment part IDs",args.part,args.folder))?;
            let bytes = part.get_body_raw().context("Could not decode attachment")?;
            fs::write(&args.output, &bytes)
                .with_context(|| format!("Could not write {}", args.output.display()))?;
            mail_logout(&mut s);
            output(
                &serde_json::json!({"uid":args.uid,"folder":args.folder,"part":args.part,"path":args.output,"bytes":bytes.len()}),
                format,
                "Downloaded attachment",
            )
        }
        MailCommand::Create(args) => {
            validate_mail_header("recipient", &args.to)?;
            validate_mail_header("subject", &args.subject)?;
            let a = account(args.email)?;
            let p = secret(&a)?;
            let mut s = mail_session(&a.email, &p)?;
            let raw = format!(
                "To: {}\r\nFrom: {}\r\nSubject: {}\r\nDate: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{}",
                args.to,
                a.email,
                args.subject,
                chrono::Utc::now().to_rfc2822(),
                args.body
            );
            s.append_with_flags("Drafts", raw.as_bytes(), &["\\Draft".into()])
                .context("Could not save the message to the Drafts folder")?;
            mail_logout(&mut s);
            output(
                &serde_json::json!({"to":args.to,"subject":args.subject,"folder":"Drafts","sent":false}),
                format,
                "Created draft",
            )
        }
        MailCommand::Send(args) => {
            let a = account(args.email.clone())?;
            let p = secret(&a)?;
            send_mail(&a, &p, &args)?;
            output(
                &serde_json::json!({"to":args.to,"subject":args.subject,"sent":true}),
                format,
                "Sent message",
            )
        }
        MailCommand::Update(args) => {
            let a = account(args.email)?;
            let p = secret(&a)?;
            let mut s = mail_session(&a.email, &p)?;
            s.select(&args.folder)
                .with_context(|| format!("Could not select mail folder {}", args.folder))?;
            if s.uid_fetch(args.uid.to_string(), "(UID)")?.is_empty() {
                bail!("No message found with UID {} in {}", args.uid, args.folder);
            }
            let (op, flag) = match args.flag.to_ascii_lowercase().as_str() {
                "seen" => ("+FLAGS.SILENT", "\\Seen"),
                "unseen" => ("-FLAGS.SILENT", "\\Seen"),
                "flagged" => ("+FLAGS.SILENT", "\\Flagged"),
                "unflagged" => ("-FLAGS.SILENT", "\\Flagged"),
                v => bail!("Unknown message flag '{v}'. Use seen, unseen, flagged, or unflagged"),
            };
            s.uid_store(args.uid.to_string(), format!("{op} ({flag})"))?;
            mail_logout(&mut s);
            response::next(format!("icli mail get {} --email {}", args.uid, a.email));
            output(
                &serde_json::json!({"uid":args.uid,"flag":args.flag,"updated":true}),
                format,
                "Updated message",
            )
        }
        MailCommand::Delete(args) => {
            let a = account(args.email)?;
            let p = secret(&a)?;
            let mut s = mail_session(&a.email, &p)?;
            s.select(&args.folder)
                .with_context(|| format!("Could not select mail folder {}", args.folder))?;
            if s.uid_fetch(args.uid.to_string(), "(UID)")?.is_empty() {
                bail!("No message found with UID {} in {}", args.uid, args.folder);
            }
            s.uid_store(args.uid.to_string(), "+FLAGS.SILENT (\\Deleted)")?;
            s.uid_expunge(args.uid.to_string())?;
            mail_logout(&mut s);
            output(
                &serde_json::json!({"uid":args.uid,"folder":args.folder,"deleted":true}),
                format,
                "Deleted message",
            )
        }
        MailCommand::Move(args) => {
            validate_mail_header("destination folder", &args.destination)?;
            let a = account(args.email)?;
            let p = secret(&a)?;
            let mut s = mail_session(&a.email, &p)?;
            s.select(&args.source)
                .with_context(|| format!("Could not select mail folder {}", args.source))?;
            if s.uid_fetch(args.uid.to_string(), "(UID)")?.is_empty() {
                bail!("No message found with UID {} in {}", args.uid, args.source);
            }
            s.uid_copy(args.uid.to_string(), &args.destination)
                .context(
                    "Could not copy message to destination folder; source remains unchanged",
                )?;
            s.uid_store(args.uid.to_string(), "+FLAGS.SILENT (\\Deleted)")
                .context("Message was copied, but could not mark the source for deletion")?;
            s.uid_expunge(args.uid.to_string())
                .context("Message was copied, but source deletion could not be confirmed")?;
            mail_logout(&mut s);
            output(
                &serde_json::json!({"uid":args.uid,"source":args.source,"destination":args.destination,"moved":true}),
                format,
                "Moved message",
            )
        }
    }
}

fn mail_session(
    email: &str,
    password: &str,
) -> Result<imap::Session<native_tls::TlsStream<std::net::TcpStream>>> {
    let tls = native_tls::TlsConnector::new()?;
    let client = imap::connect(("imap.mail.me.com", 993), "imap.mail.me.com", &tls)
        .context("Could not connect to iCloud Mail IMAP")?;
    client
        .login(email, password)
        .map_err(|e| anyhow!("iCloud Mail rejected authentication for {email}: {}", e.0))
}

fn mail_logout(session: &mut imap::Session<native_tls::TlsStream<std::net::TcpStream>>) {
    if let Err(error) = session.logout() {
        response::warning(format!(
            "Mail operation completed, but logout could not be confirmed: {error}. The connection is closed locally; do not repeat a completed write."
        ));
    }
}

fn mail_attachment_parts(mail: &mailparse::ParsedMail<'_>) -> Vec<serde_json::Value> {
    fn walk(mail: &mailparse::ParsedMail<'_>, prefix: String, out: &mut Vec<serde_json::Value>) {
        if mail.subparts.is_empty() {
            let disposition = mail
                .headers
                .get_first_value("Content-Disposition")
                .unwrap_or_default();
            if disposition.to_ascii_lowercase().contains("attachment")
                || !mail.ctype.mimetype.starts_with("text/")
            {
                let id = if prefix.is_empty() {
                    "1".to_string()
                } else {
                    prefix
                };
                out.push(serde_json::json!({"part_id":id,"content_type":mail.ctype.mimetype,"content_disposition":disposition}));
            }
            return;
        }
        for (index, part) in mail.subparts.iter().enumerate() {
            let id = if prefix.is_empty() {
                format!("{}", index + 1)
            } else {
                format!("{prefix}.{}", index + 1)
            };
            if part.subparts.is_empty() {
                let disposition = part
                    .headers
                    .get_first_value("Content-Disposition")
                    .unwrap_or_default();
                if disposition.to_ascii_lowercase().contains("attachment")
                    || !part.ctype.mimetype.starts_with("text/")
                {
                    out.push(serde_json::json!({"part_id":id,"content_type":part.ctype.mimetype,"content_disposition":disposition}));
                }
            } else {
                walk(part, id, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(mail, String::new(), &mut out);
    out
}

fn mail_text_body(mail: &mailparse::ParsedMail<'_>) -> String {
    fn find<'a>(
        mail: &'a mailparse::ParsedMail<'a>,
        html_fallback: &mut Option<String>,
    ) -> Option<String> {
        if mail.subparts.is_empty() {
            let disposition = mail
                .headers
                .get_first_value("Content-Disposition")
                .unwrap_or_default();
            if disposition.to_ascii_lowercase().contains("attachment") {
                return None;
            }
            if mail.ctype.mimetype.eq_ignore_ascii_case("text/plain") {
                return mail.get_body().ok();
            }
            if mail.ctype.mimetype.eq_ignore_ascii_case("text/html") && html_fallback.is_none() {
                *html_fallback = mail.get_body().ok();
            }
            return None;
        }
        for part in &mail.subparts {
            if let Some(body) = find(part, html_fallback) {
                return Some(body);
            }
        }
        None
    }
    let mut html = None;
    find(mail, &mut html).or(html).unwrap_or_default()
}

fn mail_attachment_by_id<'a>(
    mail: &'a mailparse::ParsedMail<'_>,
    id: &str,
) -> Option<&'a mailparse::ParsedMail<'a>> {
    if mail.subparts.is_empty() && id == "1" {
        return Some(mail);
    }
    let indexes = id
        .split('.')
        .map(|part| part.parse::<usize>().ok().filter(|i| *i > 0))
        .collect::<Option<Vec<_>>>()?;
    let mut current = mail;
    for index in indexes {
        current = current.subparts.get(index - 1)?;
    }
    Some(current)
}

fn smtp_response(reader: &mut impl BufRead) -> Result<String> {
    let mut response = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            bail!("SMTP server closed the connection")
        }
        let done = line.as_bytes().get(3).is_some_and(|c| *c == b' ');
        response.push_str(&line);
        if done {
            break;
        }
    }
    let code = response
        .get(..3)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..400).contains(&code) {
        bail!("SMTP server rejected the request: {}", response.trim())
    }
    Ok(response)
}

fn smtp_command<S: Read + Write>(stream: &mut S, command: &str) -> Result<String> {
    stream.write_all(command.as_bytes())?;
    stream.write_all(b"\r\n")?;
    stream.flush()?;
    smtp_response(&mut BufReader::new(stream))
}

fn encode_base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let a = chunk[0] as u32;
        let b = *chunk.get(1).unwrap_or(&0) as u32;
        let c = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (a << 16) | (b << 8) | c;
        for (shift, present) in [
            (18, true),
            (12, true),
            (6, chunk.len() > 1),
            (0, chunk.len() > 2),
        ] {
            out.push(if present {
                TABLE[((n >> shift) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

fn send_mail(account: &Account, password: &str, args: &MailCreateArgs) -> Result<()> {
    validate_mail_header("recipient", &args.to)?;
    validate_mail_header("subject", &args.subject)?;
    let recipients = args
        .to
        .split(',')
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .collect::<Vec<_>>();
    if recipients.is_empty() || recipients.iter().any(|r| !is_simple_email(r)) {
        bail!("Provide one or more valid recipient email addresses separated by commas")
    }
    let connector = native_tls::TlsConnector::new()?;
    let mut tcp = std::net::TcpStream::connect(("smtp.mail.me.com", 587))
        .context("Could not connect to iCloud Mail SMTP")?;
    tcp.set_read_timeout(Some(Duration::from_secs(30)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(30)))?;
    smtp_response(&mut BufReader::new(&mut tcp))?;
    smtp_command(&mut tcp, "EHLO icli.local")?;
    smtp_command(&mut tcp, "STARTTLS")?;
    let mut stream = connector
        .connect("smtp.mail.me.com", tcp)
        .context("Could not establish TLS to iCloud Mail SMTP")?;
    smtp_command(&mut stream, "EHLO icli.local")?;
    let auth = encode_base64(format!("\0{}\0{}", account.email, password).as_bytes());
    smtp_command(&mut stream, &format!("AUTH PLAIN {auth}"))?;
    smtp_command(&mut stream, &format!("MAIL FROM:<{}>", account.email))?;
    for recipient in recipients {
        smtp_command(&mut stream, &format!("RCPT TO:<{recipient}>"))?;
    }
    smtp_command(&mut stream, "DATA")?;
    let raw = format!(
        "To: {}\r\nFrom: {}\r\nSubject: {}\r\nDate: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{}",
        args.to,
        account.email,
        args.subject,
        chrono::Utc::now().to_rfc2822(),
        args.body
            .replace("\r\n", "\n")
            .replace('\r', "\n")
            .replace('\n', "\r\n")
    );
    for line in raw.split("\r\n") {
        if line.starts_with('.') {
            stream.write_all(b".")?;
        }
        stream.write_all(line.as_bytes())?;
        stream.write_all(b"\r\n")?;
    }
    stream.write_all(b".\r\n")?;
    stream.flush()?;
    smtp_response(&mut BufReader::new(&mut stream))?;
    let _ = smtp_command(&mut stream, "QUIT");
    Ok(())
}

fn validate_mail_header(name: &str, value: &str) -> Result<()> {
    if value.contains(['\r', '\n']) {
        bail!("The {name} must not contain a line break");
    }
    Ok(())
}

fn contact_resource_url(email: &str, password: &str, uid: &str, create: bool) -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(5))
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut pacer = RequestPacer::default();
    let probe =
        "<d:propfind xmlns:d=\"DAV:\"><d:prop><d:current-user-principal/></d:prop></d:propfind>";
    let response = dav(
        &client,
        &mut pacer,
        "https://contacts.icloud.com/",
        email,
        password,
        "PROPFIND",
        "0",
        probe,
    )?;
    let doc = roxmltree::Document::parse(&response)?;
    let principal = doc
        .descendants()
        .find(|n| n.tag_name().name() == "current-user-principal")
        .and_then(|n| n.descendants().find(|x| x.tag_name().name() == "href"))
        .and_then(|n| n.text())
        .ok_or_else(|| anyhow!("CardDAV response did not include current-user-principal"))?;
    let principal = resolve_dav_href("https://contacts.icloud.com/", principal)?;
    let probe = "<d:propfind xmlns:d=\"DAV:\" xmlns:card=\"urn:ietf:params:xml:ns:carddav\"><d:prop><card:addressbook-home-set/></d:prop></d:propfind>";
    let response = dav(
        &client, &mut pacer, &principal, email, password, "PROPFIND", "0", probe,
    )?;
    let doc = roxmltree::Document::parse(&response)?;
    let home = doc
        .descendants()
        .find(|n| n.tag_name().name() == "addressbook-home-set")
        .and_then(|n| n.descendants().find(|x| x.tag_name().name() == "href"))
        .and_then(|n| n.text())
        .ok_or_else(|| anyhow!("CardDAV response did not include addressbook-home-set"))?;
    let home = resolve_dav_href(&principal, home)?;
    let probe = "<d:propfind xmlns:d=\"DAV:\" xmlns:card=\"urn:ietf:params:xml:ns:carddav\"><d:prop><d:resourcetype/></d:prop></d:propfind>";
    let response = dav(
        &client, &mut pacer, &home, email, password, "PROPFIND", "1", probe,
    )?;
    let doc = roxmltree::Document::parse(&response)?;
    let href = doc
        .descendants()
        .filter(|n| n.tag_name().name() == "response")
        .find(|r| {
            r.descendants()
                .any(|n| n.tag_name().name() == "addressbook")
        })
        .and_then(|r| r.descendants().find(|n| n.tag_name().name() == "href"))
        .and_then(|n| n.text())
        .ok_or_else(|| anyhow!("No writable address book was found"))?;
    let collection = resolve_dav_href(&home, href)?;
    if create {
        let mut url = reqwest::Url::parse(&collection)?;
        url.path_segments_mut()
            .map_err(|_| anyhow!("Address book URL cannot accept a contact path"))?
            .push(&format!("{uid}.vcf"));
        return Ok(url.to_string());
    }
    let report = "<card:addressbook-query xmlns:d=\"DAV:\" xmlns:card=\"urn:ietf:params:xml:ns:carddav\"><d:prop><card:address-data/></d:prop></card:addressbook-query>";
    let response = dav(
        &client,
        &mut pacer,
        &collection,
        email,
        password,
        "REPORT",
        "1",
        report,
    )?;
    let doc = roxmltree::Document::parse(&response)?;
    let mut matches = Vec::new();
    for item in doc
        .descendants()
        .filter(|n| n.tag_name().name() == "response")
    {
        let href = item
            .descendants()
            .find(|n| n.tag_name().name() == "href")
            .and_then(|n| n.text());
        let Some(href) = href else {
            continue;
        };
        let url = resolve_dav_href(&collection, href)?;
        let uid_matches = item
            .descendants()
            .filter(|n| n.tag_name().name() == "address-data")
            .filter_map(|n| n.text())
            .flat_map(parse_vcards)
            .any(|c| c.uid == uid);
        if uid_matches || url == uid {
            matches.push(url);
        }
    }
    if matches.len() == 1 {
        return Ok(matches.remove(0));
    }
    if matches.len() > 1 {
        bail!(
            "Ambiguous contact UID {uid}. Candidates: {}. Supply an exact href instead of UID.",
            matches.join(", ")
        );
    }

    bail!("No contact found with UID {uid}")
}

fn carddav_write(
    url: &str,
    email: &str,
    password: &str,
    method: &str,
    card: &str,
    condition: Option<(&str, &str)>,
) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(5))
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut pacer = RequestPacer::default();
    for attempt in 0..=DAV_RETRIES {
        pacer.wait();
        let mut request = client
            .request(reqwest::Method::from_bytes(method.as_bytes())?, url)
            .basic_auth(email, Some(password))
            .header("Content-Type", "text/vcard; charset=utf-8");
        if let Some((name, value)) = condition {
            request = request.header(name, value);
        }
        let response = request.body(card.to_owned()).send();
        match response {
            Ok(r)
                if r.status().is_success()
                    || (method == "DELETE" && r.status() == reqwest::StatusCode::NOT_FOUND) =>
            {
                return Ok(());
            }
            Ok(r) => {
                let status = r.status();
                let body = r.text().unwrap_or_default();
                if !retryable_status(status) || attempt == DAV_RETRIES {
                    bail!(
                        "CardDAV {method} request returned {status}: {}",
                        body.chars().take(400).collect::<String>()
                    )
                }
                thread::sleep(backoff_delay(attempt));
            }
            Err(e) => {
                if attempt == DAV_RETRIES {
                    return Err(e).context("CardDAV request failed");
                }
                thread::sleep(backoff_delay(attempt));
            }
        }
    }
    unreachable!()
}

fn carddav_read(url: &str, email: &str, password: &str) -> Result<(String, Option<String>)> {
    let response = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(5))
        .timeout(Duration::from_secs(30))
        .build()?
        .get(url)
        .basic_auth(email, Some(password))
        .header("Accept", "text/vcard")
        .send()
        .context("Could not read the contact before updating it")?;
    let status = response.status();
    if !status.is_success() {
        bail!("CardDAV GET request returned {status}");
    }
    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    Ok((response.text()?, etag))
}

fn property_key(line: &str) -> String {
    line.split(':')
        .next()
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase()
}

fn unfold_vcard(data: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for line in data.lines() {
        if line.starts_with([' ', '\t']) {
            if let Some(previous) = lines.last_mut() {
                previous.push_str(&line[1..]);
            }
        } else if !line.is_empty() {
            lines.push(line.to_string());
        }
    }
    lines
}

fn validate_vcard(data: &str) -> Result<()> {
    let cards = VcardParser::new(BufReader::new(data.as_bytes()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Invalid vCard file")?;
    if cards.len() != 1
        || unfold_vcard(data)
            .iter()
            .filter(|line| line.eq_ignore_ascii_case("BEGIN:VCARD"))
            .count()
            != 1
    {
        bail!("Provide exactly one complete vCard per file");
    }
    if unfold_vcard(data)
        .iter()
        .filter(|line| property_key(line) == "VERSION")
        .count()
        != 1
    {
        bail!("Invalid vCard file: provide exactly one VERSION property");
    }
    if !data.trim_end().to_ascii_uppercase().ends_with("END:VCARD") {
        bail!("Invalid vCard: missing END:VCARD");
    }
    Ok(())
}

fn contact_patch(fields: &ContactFields) -> Result<Vec<String>> {
    let mut patch = if let Some(file) = &fields.vcard_file {
        let data = fs::read_to_string(file)
            .with_context(|| format!("Could not read vCard file {}", file.display()))?;
        validate_vcard(&data)?;
        unfold_vcard(&data)
            .into_iter()
            .filter(|line| !["BEGIN", "END"].contains(&property_key(line).as_str()))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let file_keys = patch
        .iter()
        .map(|line| property_key(line))
        .collect::<BTreeSet<_>>();
    let mut flags = Vec::new();
    if let Some(name) = &fields.name {
        flags.push(format!("FN:{}", escape_ical_text(name)));
        flags.push(format!("N:{};;;;", escape_ical_text(name)));
    }
    if let Some(email) = &fields.address {
        flags.push(format!("EMAIL:{}", escape_ical_text(email)));
    }
    if let Some(phone) = &fields.phone {
        flags.push(format!("TEL:{}", escape_ical_text(phone)));
    }
    let common_keys = flags
        .iter()
        .map(|line| property_key(line))
        .collect::<BTreeSet<_>>();
    for property in &fields.properties {
        let (name,value) = property.split_once('=').ok_or_else(||anyhow!("Invalid --property {property:?}. Use NAME=VALUE; use --vcard-file for parameters and structured values."))?;
        let name = name.to_ascii_uppercase();
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-.".contains(&b))
            || ["BEGIN", "END", "UID", "VERSION"].contains(&name.as_str())
        {
            bail!(
                "Invalid property name {name:?}. UID and VERSION can be supplied using --vcard-file."
            );
        }
        if common_keys.contains(&name) {
            bail!(
                "Property {name} supplied by both a common flag and --property; choose one input."
            );
        }
        flags.push(format!("{name}:{}", escape_ical_text(value)));
    }
    for line in &flags {
        if file_keys.contains(&property_key(line)) {
            bail!(
                "Property {} supplied by both --vcard-file and a flag; choose one input.",
                property_key(line)
            );
        }
    }
    patch.extend(flags);
    if patch.is_empty() {
        bail!(
            "Provide at least one contact property using --name, --contact-email, --phone, --property, or --vcard-file"
        );
    }
    Ok(patch)
}

fn serialize_vcard_lines(lines: &[String]) -> String {
    let mut card = String::new();
    for line in lines {
        let mut octets = 0;
        for character in line.chars() {
            if octets + character.len_utf8() > 75 {
                card.push_str("\r\n ");
                octets = 1;
            }
            card.push(character);
            octets += character.len_utf8();
        }
        card.push_str("\r\n");
    }
    card
}

fn apply_contact_patch(existing: Option<&str>, uid: &str, patch: &[String]) -> Result<String> {
    if uid.is_empty() || uid.contains(['\r', '\n']) {
        bail!("Invalid contact UID");
    }
    let keys = patch
        .iter()
        .map(|line| property_key(line))
        .collect::<BTreeSet<_>>();
    for line in patch.iter().filter(|line| property_key(line) == "UID") {
        if line.split_once(':').map(|(_, value)| value) != Some(uid) {
            bail!("vCard UID must match the contact being updated");
        }
    }
    let mut lines = existing.map(unfold_vcard).unwrap_or_else(|| {
        vec![
            "BEGIN:VCARD".into(),
            "VERSION:3.0".into(),
            format!("UID:{uid}"),
        ]
    });
    lines.retain(|line| {
        let key = property_key(line);
        if key == "END" {
            return false;
        }
        if key == "BEGIN" || key == "UID" {
            return true;
        }
        !keys.contains(&key) && !keys.contains(key.rsplit('.').next().unwrap_or(&key))
    });
    lines.extend(
        patch
            .iter()
            .filter(|line| property_key(line) != "UID")
            .cloned(),
    );
    lines.push("END:VCARD".into());
    if !lines.iter().any(|line| property_key(line) == "FN") {
        bail!(
            "Contact requires a formatted name. Supply --name NAME or FN in the vCard file/--property."
        );
    }
    let card = serialize_vcard_lines(&lines);
    validate_vcard(&card)?;
    Ok(card)
}

fn config_path() -> Result<PathBuf> {
    let root = if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow!("APPDATA is not set"))?
    } else if cfg!(target_os = "macos") {
        PathBuf::from(std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?)
            .join("Library/Application Support")
    } else {
        if let Some(p) = std::env::var_os("XDG_CONFIG_HOME") {
            PathBuf::from(p)
        } else {
            PathBuf::from(std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?)
                .join(".config")
        }
    };
    let dir = if cfg!(any(windows, target_os = "macos")) {
        root.join("iCLI")
    } else {
        root.join("icli")
    };
    fs::create_dir_all(&dir)?;
    Ok(dir.join("config.toml"))
}
fn load_config() -> Result<Config> {
    let p = config_path()?;
    if !p.exists() {
        return Ok(Config::default());
    }
    Ok(toml::from_str(&fs::read_to_string(p)?)?)
}
fn save_config(c: &Config) -> Result<()> {
    fs::write(config_path()?, toml::to_string_pretty(c)?)?;
    Ok(())
}
fn add_account_config(config: &mut Config, email: &str) {
    if config
        .accounts
        .iter()
        .any(|a| a.email.eq_ignore_ascii_case(email))
    {
        return;
    }
    if config.accounts.is_empty() {
        config.default_user = Some(email.to_string());
    }
    config.accounts.push(Account {
        email: email.to_string(),
    });
}

fn remove_account_config(config: &mut Config, email: &str) -> Result<()> {
    let count = config.accounts.len();
    config
        .accounts
        .retain(|account| !account.email.eq_ignore_ascii_case(email));
    if config.accounts.len() == count {
        bail!("Account not configured: {email}");
    }
    if config
        .default_user
        .as_deref()
        .is_some_and(|default| default.eq_ignore_ascii_case(email))
    {
        config.default_user = if config.accounts.len() == 1 {
            Some(config.accounts[0].email.clone())
        } else {
            None
        };
    }
    Ok(())
}

fn credential(email: &str) -> Result<keyring::Entry> {
    Ok(keyring::Entry::new("icli-icloud", email)?)
}
fn apple_session_credential(email: &str) -> Result<keyring::Entry> {
    Ok(keyring::Entry::new("icli-apple-private-session", email)?)
}
fn apple_session_chunk_credential(
    email: &str,
    generation: &str,
    index: usize,
) -> Result<keyring::Entry> {
    Ok(keyring::Entry::new(
        "icli-apple-private-session",
        &format!("{email}#session-{generation}-chunk-{index}"),
    )?)
}
#[derive(serde::Serialize, serde::Deserialize)]
struct AppleSessionManifest {
    format_version: u8,
    generation: String,
    chunks: usize,
}
// Windows Credential Manager limits the credential blob to 2560 bytes. The
// keyring crate encodes each stored password as UTF-16, so leave room for the
// two-byte encoding and platform metadata.
const APPLE_SESSION_CHUNK_BYTES: usize = 1000;

fn save_apple_session(session: &apple_auth::SavedAppleSession) -> Result<()> {
    let serialized = serde_json::to_string(session)
        .context("Could not serialize the Apple private-service session")?;
    let entry = apple_session_credential(&session.account)?;
    let previous = match entry.get_password() {
        Ok(raw) => serde_json::from_str::<AppleSessionManifest>(&raw)
            .ok()
            .filter(|m| m.format_version == 1),
        Err(keyring::Error::NoEntry) => None,
        Err(error) => {
            return Err(error)
                .context("Could not read previous Apple session from credential store");
        }
    };
    let generation = uuid::Uuid::new_v4().to_string();
    let chunks = split_secret_chunks(&serialized, APPLE_SESSION_CHUNK_BYTES);
    if !(1..=1024).contains(&chunks.len()) {
        bail!("Apple session exceeds the supported credential store size");
    }
    // Publish the index only after every chunk is stored. Keep the previous
    // generation usable if a chunk or the final index write fails.
    let write = (|| -> Result<()> {
        for (index, chunk) in chunks.iter().enumerate() {
            apple_session_chunk_credential(&session.account, &generation, index)?.set_password(chunk)
                .with_context(|| format!("Could not save Apple session chunk {} to the operating system credential store", index + 1))?;
        }
        let manifest = serde_json::to_string(&AppleSessionManifest {
            format_version: 1,
            generation: generation.clone(),
            chunks: chunks.len(),
        })?;
        entry
            .set_password(&manifest)
            .context("Could not save Apple session index to the operating system credential store")
    })();
    if write.is_err() {
        clean_session_chunks(&session.account, &generation, chunks.len());
        return write;
    }
    if let Some(previous) = previous {
        clean_session_chunks(
            &session.account,
            &previous.generation,
            previous.chunks.min(1024),
        );
    }
    Ok(())
}
fn clean_session_chunks(email: &str, generation: &str, count: usize) {
    for index in 0..count {
        if let Ok(entry) = apple_session_chunk_credential(email, generation, index) {
            let _ = entry.delete_credential();
        }
    }
}
fn delete_apple_session(email: &str) -> Result<()> {
    let entry = apple_session_credential(email)?;
    let raw = match entry.get_password() {
        Ok(raw) => raw,
        Err(keyring::Error::NoEntry) => return Ok(()),
        Err(error) => {
            return Err(error)
                .context("Could not read Apple session from credential store before removal");
        }
    };
    if let Ok(manifest) = serde_json::from_str::<AppleSessionManifest>(&raw) {
        if manifest.format_version == 1 && (1..=1024).contains(&manifest.chunks) {
            for index in 0..manifest.chunks {
                match apple_session_chunk_credential(email, &manifest.generation, index)?
                    .delete_credential()
                {
                    Ok(()) | Err(keyring::Error::NoEntry) => (),
                    Err(error) => {
                        return Err(error)
                            .context("Could not delete Apple session chunk from credential store");
                    }
                }
            }
        }
    }
    entry
        .delete_credential()
        .context("Could not delete Apple session from credential store")
}

fn load_apple_connection(email: &str) -> Result<apple_auth::AppleConnection> {
    let raw = apple_session_credential(email)?
        .get_password()
        .map_err(|error| match error {
            keyring::Error::NoEntry => apple_auth::sign_in_required(
                email,
                "No saved Apple Account session; start sign-in with auth add",
            ),
            other => anyhow!(
                "Could not read Apple session from the operating system credential store: {other}"
            ),
        })?;
    let manifest = serde_json::from_str::<AppleSessionManifest>(&raw)
        .ok()
        .filter(|manifest| {
            manifest.format_version == 1
                && !manifest.generation.is_empty()
                && (1..=1024).contains(&manifest.chunks)
        });
    let session: apple_auth::SavedAppleSession = if let Some(manifest) = manifest {
        let mut serialized = String::new();
        for index in 0..manifest.chunks {
            let chunk = apple_session_chunk_credential(email, &manifest.generation, index)?
                .get_password()
                .map_err(|error| match error {
                    keyring::Error::NoEntry => apple_auth::sign_in_required(email, format!("Saved Apple session is missing credential chunk {}; start sign-in again", index + 1)),
                    other => anyhow!("Could not read Apple session chunk from credential store: {other}"),
                })?;
            serialized.push_str(&chunk);
        }
        serde_json::from_str(&serialized).map_err(|_| {
            apple_auth::sign_in_required(
                email,
                "Saved Apple session data is invalid; start sign-in again",
            )
        })?
    } else {
        // Read sessions saved by the first implementation before chunking.
        serde_json::from_str(&raw).map_err(|_| {
            apple_auth::sign_in_required(
                email,
                "Saved Apple session data is invalid; start sign-in again",
            )
        })?
    };
    if !session.account.eq_ignore_ascii_case(email) {
        bail!("Saved Apple session does not match the selected account");
    }
    apple_auth::AppleConnection::restore(session)
}
fn split_secret_chunks(value: &str, maximum_bytes: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut chunk = String::new();
    for character in value.chars() {
        if chunk.len() + character.len_utf8() > maximum_bytes {
            chunks.push(std::mem::take(&mut chunk));
        }
        chunk.push(character);
    }
    if !chunk.is_empty() {
        chunks.push(chunk);
    }
    chunks
}
fn account(email: Option<String>) -> Result<Account> {
    let c = load_config()?;
    if let Some(e) = email {
        c.accounts
            .into_iter()
            .find(|a| a.email.eq_ignore_ascii_case(&e))
            .ok_or_else(|| anyhow!("Account not configured: {e}"))
    } else {
        if let Some(default_user) = c.default_user {
            return c
                .accounts
                .into_iter()
                .find(|a| a.email.eq_ignore_ascii_case(&default_user))
                .ok_or_else(|| {
                    anyhow!("Configured default user is not an added account: {default_user}")
                });
        }
        if c.accounts.len() != 1 {
            bail!(
                "Choose an account by passing EMAIL or set a default with `icli config default-user EMAIL`; configured accounts: {}",
                c.accounts
                    .iter()
                    .map(|a| a.email.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        Ok(c.accounts[0].clone())
    }
}
fn secret(a: &Account) -> Result<String> {
    credential(&a.email)?
        .get_password()
        .map_err(|error| match error {
            keyring::Error::NoEntry => apple_auth::recovery(&a.email, "app_password_required", "Mail, Calendar, and Contacts require an app-specific password. Save one with auth app-password.", "app-password"),
            other => anyhow!("Could not read app-specific password from the system credential store: {other}"),
        })
}
fn format_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Null => String::new(),
        _ => value.to_string(),
    }
}

fn csv_cell(value: &str) -> String {
    if value.chars().any(|c| matches!(c, ',' | '"' | '\n' | '\r')) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn page_items<T>(items: Vec<T>, skip: usize, limit: usize) -> Vec<T> {
    if limit > 0 {
        if let Some(next_skip) = skip.checked_add(limit).filter(|next| *next < items.len()) {
            response::next(format!(
                "More results are available. Repeat this command with --skip {next_skip} --limit {limit}, keeping the same query, account, and scope."
            ));
        }
    }
    items.into_iter().skip(skip).take(limit).collect()
}

fn dav_page_items<T>(items: Vec<T>, skip: usize, limit: usize) -> Vec<T> {
    if skip > 0 {
        response::warning(
            "Using --skip with --limit for Calendar/Contacts pagination is not recommended: loading all matches in one call is faster than requesting multiple pages. iCLI still downloads every matching event or contact card, including skipped results, because CalDAV and CardDAV do not provide offset pagination for these queries; iCLI applies --skip locally.",
        );
    }
    page_items(items, skip, limit)
}

fn mail_page_ids(mut ids: Vec<u32>, skip: usize, limit: usize) -> Vec<u32> {
    ids.sort_unstable_by(|a, b| b.cmp(a));
    page_items(ids, skip, limit)
}

fn contact_page(mut contacts: Vec<Contact>, skip: usize, limit: usize) -> Vec<Contact> {
    contacts.sort_by(|a, b| {
        a.uid.cmp(&b.uid).then_with(|| {
            // DAV report order is unspecified. Break duplicate/missing UID
            // ties using card data so repeated reads have a consistent order.
            serde_json::to_string(a)
                .unwrap_or_default()
                .cmp(&serde_json::to_string(b).unwrap_or_default())
        })
    });
    dav_page_items(contacts, skip, limit)
}

fn output_contacts(
    contacts: Vec<Contact>,
    page: Option<(usize, usize)>,
    format: OutputFormat,
    title: &str,
    include: &[String],
) -> Result<()> {
    let requested = include
        .iter()
        .flat_map(|entry| entry.split(','))
        .map(|name| name.trim().to_ascii_uppercase())
        .filter(|name| !name.is_empty())
        .collect::<BTreeSet<_>>();
    let available = contacts
        .iter()
        .flat_map(|contact| contact.all_properties.keys().cloned())
        .collect::<BTreeSet<_>>();
    let unknown = requested
        .iter()
        .filter(|name| {
            name.as_str() != "ALL"
                && !available.iter().any(|field| {
                    field.eq_ignore_ascii_case(name)
                        || field
                            .rsplit('.')
                            .next()
                            .is_some_and(|base| base.eq_ignore_ascii_case(name))
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        response::warning(format!(
            "Requested contact properties are absent from this result set: {}. Run icli contacts help to discover account properties.",
            unknown.join(", ")
        ));
    }
    let contacts = match page {
        Some((skip, limit)) => contact_page(contacts, skip, limit),
        None => contacts,
    };
    let mut value = serde_json::to_value(&contacts)?;
    if let serde_json::Value::Array(rows) = &mut value {
        for (contact, row) in contacts.iter().zip(rows.iter_mut()) {
            if let serde_json::Value::Object(fields) = row {
                fields.remove("_all_properties");
                let mut included_properties = serde_json::Map::new();
                let selected = if requested.contains("ALL") {
                    &available
                } else {
                    &requested
                };
                for (actual_name, property_values) in &contact.all_properties {
                    if selected.iter().any(|property| {
                        actual_name.eq_ignore_ascii_case(property)
                            || actual_name
                                .rsplit('.')
                                .next()
                                .is_some_and(|base| base.eq_ignore_ascii_case(property))
                    }) {
                        included_properties.insert(
                            actual_name.clone(),
                            serde_json::Value::Array(property_values.clone()),
                        );
                    }
                }
                if !included_properties.is_empty() {
                    fields.insert(
                        "properties".to_string(),
                        serde_json::Value::Object(included_properties),
                    );
                }
            }
        }
    }
    output(&value, format, title)
}

fn output_calendars(
    calendars: &[serde_json::Value],
    format: OutputFormat,
    include: &[String],
) -> Result<()> {
    validate_calendar_include(include)?;
    let mut columns = vec!["name".to_string(), "id".to_string()];
    for requested in include {
        let field = requested.trim().to_ascii_lowercase().replace('-', "_");
        if field.is_empty() {
            continue;
        }
        if !columns.contains(&field) {
            columns.push(field);
        }
    }

    let rows = calendars
        .iter()
        .map(|calendar| {
            let mut row = serde_json::Map::new();
            for field in &columns {
                if let Some(value) = calendar.get(field) {
                    row.insert(field.clone(), value.clone());
                } else {
                    row.insert(field.clone(), serde_json::Value::Null);
                }
            }
            serde_json::Value::Object(row)
        })
        .collect::<Vec<_>>();

    output(&rows, format, "Calendars")
}

fn validate_calendar_include(include: &[String]) -> Result<()> {
    for requested in include {
        let field = requested.trim().to_ascii_lowercase().replace('-', "_");
        if !field.is_empty() && !["href", "dsid", "color"].contains(&field.as_str()) {
            bail!(
                "Unknown calendar list field '{requested}'. Available fields for --include: href, dsid, color"
            );
        }
    }
    Ok(())
}

fn output_events(
    mut events: Vec<serde_json::Value>,
    format: OutputFormat,
    include: &[String],
    no_results_hint: Option<&str>,
) -> Result<()> {
    const DEFAULT_FIELDS: &[&str] = &[
        "summary",
        "start",
        "end",
        "location",
        "description",
        "uid",
        "status",
        "organizer",
        "organizer_params",
        "attendee",
        "attendee_params",
        "rrule",
        "alarms",
    ];

    let requested = include
        .iter()
        .map(|name| name.trim().to_ascii_lowercase().replace('-', "_"))
        .filter(|name| !name.is_empty())
        .collect::<BTreeSet<_>>();
    let mut included = requested.clone();
    let included_params = included
        .iter()
        .filter(|name| !name.ends_with("_params"))
        .map(|name| format!("{name}_params"))
        .collect::<Vec<_>>();
    included.extend(included_params);
    let mut available = BTreeSet::new();
    let mut present = BTreeSet::new();
    for event in &mut events {
        if let Some(fields) = event.as_object_mut() {
            for name in fields.keys() {
                present.insert(name.clone());
                if !DEFAULT_FIELDS.contains(&name.as_str()) && !included.contains(name) {
                    available.insert(name.clone());
                }
            }
            fields.retain(|name, _| {
                DEFAULT_FIELDS.contains(&name.as_str()) || included.contains(name)
            });
        }
    }

    let absent = requested
        .iter()
        .filter(|name| !present.contains(*name))
        .cloned()
        .collect::<Vec<_>>();
    if !absent.is_empty() {
        response::warning(format!(
            "Requested properties absent from this result: {}",
            absent.join(", ")
        ));
    }
    if !available.is_empty() {
        response::warning(format!(
            "Additional properties available with --include: {}",
            available.into_iter().collect::<Vec<_>>().join(",")
        ));
    }
    if events.is_empty() {
        if let Some(hint) = no_results_hint {
            response::next(hint);
        }
    }
    output(&events, format, "Calendar events")
}

fn help_target() -> String {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let mut command_words = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--json" => index += 1,
            "--format" => index = (index + 2).min(args.len()),
            value if value.starts_with("--format=") => index += 1,
            value if value.starts_with('-') && command_words.is_empty() => return "icli".into(),
            value => {
                command_words.push(value.to_string());
                index += 1;
            }
        }
    }

    let mut path = vec!["icli"];
    match command_words.first().map(String::as_str) {
        Some("update") => path.push("update"),
        Some("config") | Some("auth") | Some("mail") | Some("contacts") => {
            path.push(command_words[0].as_str());
            if matches!(
                command_words[0].as_str(),
                "config" | "auth" | "mail" | "contacts"
            ) {
                if let Some(subcommand) = command_words.get(1).filter(|v| {
                    [
                        "add",
                        "list",
                        "check",
                        "verify",
                        "refresh",
                        "resend",
                        "app-password",
                        "apple-login",
                        "remove",
                        "default-user",
                        "format",
                        "get",
                        "folders",
                        "search",
                        "download",
                        "create",
                        "send",
                        "update",
                        "move",
                        "delete",
                        "me",
                        "groups",
                        "help",
                    ]
                    .contains(&v.as_str())
                }) {
                    path.push(subcommand);
                    if command_words[0] == "contacts" && subcommand == "groups" {
                        if let Some(group_action) = command_words.get(2).filter(|v| {
                            ["list", "create", "update", "delete"].contains(&v.as_str())
                        }) {
                            path.push(group_action);
                        }
                    }
                }
            }
        }
        Some("reminders") => {
            path.push("reminders");
            if let Some(action) = command_words
                .get(1)
                .filter(|v| ["lists", "list"].contains(&v.as_str()))
            {
                path.push(action);
            }
        }
        Some("calendar") => {
            path.push("calendar");
            if let Some(calendar_command) = command_words.get(1) {
                path.push(calendar_command);
                if calendar_command == "events" {
                    if let Some(action) = command_words.get(2).filter(|action| {
                        [
                            "list", "search", "get", "create", "update", "delete", "import",
                        ]
                        .contains(&action.as_str())
                    }) {
                        path.push(action);
                    }
                } else if calendar_command == "share" {
                    if let Some(action) = command_words
                        .get(2)
                        .filter(|action| ["list", "grant", "revoke"].contains(&action.as_str()))
                    {
                        path.push(action);
                    }
                }
            }
        }
        _ => return "icli".into(),
    }
    path.join(" ")
}

fn next_step(error: &anyhow::Error) -> String {
    if let Some(recovery) = error.downcast_ref::<apple_auth::AuthRecovery>() {
        return recovery.next_command.clone();
    }
    if let Some(recovery) = error.downcast_ref::<apple_auth::RemindersAccessRecovery>() {
        return recovery.next_command.clone();
    }
    let message = format!("{error:#}");
    let lower = message.to_ascii_lowercase();
    if lower.contains("invalid search query") {
        return format!(
            "Use 1 to 256 characters after trimming surrounding whitespace. Remove control characters and characters XML cannot represent. See {} --help.",
            help_target()
        );
    }

    if help_target() == "icli update" {
        return "Check network access to GitHub, release availability for this platform, and write permissions on the executable directory. Run `icli update --check` or use the original installer/package manager. An update failure does not require changing iCloud credentials; continue with the installed CLI if its help supports the task.".into();
    }

    if lower.contains("account not configured")
        || lower.contains("configured default user is not an added account")
    {
        return "Run `icli auth list` to see configured accounts. Add the intended account with `icli auth add EMAIL`, or select one with `--email EMAIL` / `icli config default-user EMAIL`.".into();
    }
    if lower.contains("choose an account by passing") {
        return "Run `icli auth list`, then pass one listed address as EMAIL or set it with `icli config default-user EMAIL`.".into();
    }
    if lower.contains("account already configured") {
        return "Use `icli auth app-password EMAIL --password-stdin` to replace an app-specific password, or `icli auth add EMAIL --password-stdin` to restart Apple sign-in.".into();
    }
    if lower.contains("the account was not added") && lower.contains("401 unauthorized") {
        return "The account was not saved. Retry `icli auth app-password EMAIL` with an Apple app-specific password. Create one at https://account.apple.com/; Apple's instructions are at https://support.apple.com/en-us/102654.".into();
    }
    if lower.contains("could not read app-specific password")
        || lower.contains("returned 401")
        || lower.contains("rejected authentication")
    {
        return "Check the Apple Account email and app-specific password. If you supplied PASSWORD, retry with the correct app-specific password. If the saved password is wrong, run `icli auth app-password EMAIL --password-stdin` with the replacement through stdin; run `icli auth check EMAIL --app-password` after saving.".into();
    }
    if lower.contains("no calendar matched") {
        return "Run `icli calendar list`, then retry with the exact calendar name or ID shown."
            .into();
    }
    if lower.contains("no event with uid") {
        return "Confirm the event UID (not its title) with `icli calendar events list FROM TO --calendar CALENDAR`, then retry with that UID and calendar.".into();
    }
    if lower.contains("noninteractive") || lower.contains("password required") {
        return format!(
            "Use {} --help for accepted inputs. Provide the secret through --password-stdin, or use --code-stdin with auth verify. Never paste a secret in chat.",
            help_target()
        );
    }
    if lower.contains("ambiguous") || lower.contains("more than one") {
        return "Select one of the exact hrefs in the candidate list; use the same argument that held the ambiguous selector.".into();
    }
    if lower.contains("contact property")
        || lower.contains("vcard")
        || lower.contains("property name")
        || lower.contains("supplied by both")
    {
        return "Run icli contacts create --help or icli contacts update --help. Use --property NAME=VALUE for text and a complete --vcard-file for structured values or parameters.".into();
    }
    if lower.contains("unknown calendar list field") {
        return "Use `--include href`, `--include dsid`, or `--include dsid,href`; see `icli calendar list --help`.".into();
    }
    if lower.contains("invalid date") || lower.contains("all-day date") {
        return "Use a real date in YYYY-MM-DD form, for example `2026-10-19`. For positional event dates, use `icli calendar events FROM TO` or add `--from` and `--to`.".into();
    }
    if lower.contains("invalid event time") {
        return "Use RFC 3339 date-times with an explicit timezone, such as `2026-10-20T10:00:00+02:00`.".into();
    }
    if lower.contains("provide a start date") {
        return "Provide both date bounds, for example `icli calendar events --from 2026-10-17 --to 2026-10-24`, or `icli calendar events Work 2026-10-17 2026-10-24`.".into();
    }
    if lower.contains("provide an end date") {
        return "Add the end date as TO or `--to YYYY-MM-DD`; for example `icli calendar events --from 2026-10-17 --to 2026-10-24`.".into();
    }
    if lower.contains("provide both --start and --end")
        || lower.contains("provide --start and --end")
    {
        return "For a timed event, provide both `--start` and `--end` with timezone offsets; use `--all-day YYYY-MM-DD` for a whole-day event.".into();
    }
    if lower.contains("event end must be after") {
        return "Choose an end time later than the start time; both times must use RFC 3339 with an explicit timezone.".into();
    }
    if lower.contains("end date must be after the start date") {
        return "Set TO to a date after FROM, for example `icli calendar events 2026-10-17 2026-10-24`. The end date is inclusive.".into();
    }
    if lower.contains("provide at least one event property") {
        return "Add a property to change, such as `--summary`, `--location`, `--description`, or both `--start` and `--end`.".into();
    }
    if lower.contains("invalid participant email") {
        return "Pass a participant as a simple email address, such as `--participant person@example.com`.".into();
    }
    if lower.contains("some ics events were not imported") {
        return "Review the per-UID failures above. Some events may already have been created, so do not rerun the entire import without checking those UIDs first.".into();
    }
    if lower.contains("could not read ics file") {
        return "Check that the ICS_FILE path exists and that iCLI can read it, then retry `icli calendar events import ICS_FILE --calendar CALENDAR`.".into();
    }
    if lower.contains("ics file did not contain any vevent")
        || lower.contains("could not parse vevent")
        || lower.contains("vevent without end:vevent")
        || lower.contains("every imported vevent must have a uid")
    {
        return "Use an iCalendar `.ics` file with complete `BEGIN:VEVENT` / `END:VEVENT` blocks and a `UID` on each event. Review `icli calendar events import --help` for the command form.".into();
    }
    if lower.contains("returned 403") {
        if lower.contains("valid-organizer") {
            return "The server did not accept the configured account email as this calendar's organizer. Check that `--email` selects the account that owns the calendar and that the address is enabled for invitations in iCloud Calendar.".into();
        }
        if lower.contains("valid-calendar-user") {
            return "The server did not recognize an organizer or attendee address. Check the address spelling and whether the organizer account is allowed to send invitations from iCloud Calendar.".into();
        }
        return "The server refused this operation. Confirm the selected calendar is writable and that iCloud allows this operation; retrying the same request is unlikely to help.".into();
    }
    if lower.contains("returned 404") {
        return "The requested server resource was not found. Refresh the corresponding service list and retry with the current resource ID, UID, or href.".into();
    }
    if lower.contains("returned 400") {
        return "The server rejected the request format. Check the command syntax with its `--help`, and review the server response included above before retrying.".into();
    }
    if lower.contains("returned 409") || lower.contains("returned 412") {
        return "The server reports a conflict or changed resource. Re-read the target resource with its get/list command. For a create, check whether the resource already exists before retrying; for an update, merge against the current data.".into();
    }
    if lower.contains("returned 429")
        || lower.contains("returned 5")
        || lower.contains("request failed for")
    {
        return "The service may be busy or unreachable. Wait briefly and retry once; avoid repeating a create/import command if it may already have succeeded.".into();
    }
    if lower.contains("did not include calendar-home-set") {
        return "Confirm iCloud Calendar is enabled for this Apple Account, then retry. If it is enabled and the error persists, the account's CalDAV discovery response is incomplete.".into();
    }
    if lower.contains("could not save to system credential store") {
        return "Unlock or configure the operating system credential store, then retry `icli auth add EMAIL`. iCLI does not save the password in its config file.".into();
    }
    if lower.contains("could not connect to icloud mail imap") {
        return "Check the network connection and iCloud Mail availability, then retry. If the connection works but login fails, use an Apple app-specific password.".into();
    }
    format!(
        "Review the command instructions and accepted arguments with `{} --help`, then correct the command and retry.",
        help_target()
    )
}

fn cli_quote(value: &str) -> String {
    if cfg!(windows) {
        format!("'{}'", value.replace('\'', "''"))
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn invocation_action() -> String {
    let mut action = help_target().trim_start_matches("icli ").replace(' ', ".");
    if ["mail", "contacts", "calendar.events"].contains(&action.as_str()) {
        action.push_str(".list");
    }
    action
}

fn invocation_format() -> OutputFormat {
    let args = std::env::args().collect::<Vec<_>>();
    if args.iter().any(|a| a == "--json") {
        return OutputFormat::Json;
    }
    let selected = args
        .iter()
        .enumerate()
        .filter_map(|(i, a)| {
            a.strip_prefix("--format=").map(str::to_string).or_else(|| {
                if a == "--format" {
                    args.get(i + 1).cloned()
                } else {
                    None
                }
            })
        })
        .next_back();
    match selected.as_deref() {
        Some("json") => OutputFormat::Json,
        Some("csv") => OutputFormat::Csv,
        Some("agent") => OutputFormat::Agent,
        _ => load_config().map(|c| c.response_format).unwrap_or_default(),
    }
}

fn error_code(error: &anyhow::Error) -> (&'static str, Option<bool>) {
    if let Some(recovery) = error.downcast_ref::<apple_auth::AuthRecovery>() {
        return (recovery.code, Some(false));
    }
    if let Some(recovery) = error.downcast_ref::<apple_auth::RemindersAccessRecovery>() {
        return (recovery.code, Some(false));
    }
    let message = format!("{error:#}").to_ascii_lowercase();
    if message.contains("ambiguous") || message.contains("more than one") {
        ("ambiguous_resource", Some(false))
    } else if message.contains("401") || message.contains("rejected authentication") {
        ("authentication_failed", Some(false))
    } else if message.contains("403") {
        ("permission_denied", Some(false))
    } else if message.contains("412") {
        ("resource_changed", Some(true))
    } else if message.contains("429") {
        ("rate_limited", Some(true))
    } else if message.contains("not configured") || message.contains("choose an account") {
        ("account_required", Some(false))
    } else if message.contains("credential store") {
        ("credential_store_error", None)
    } else if message.contains("no ") && (message.contains("found") || message.contains("matched"))
    {
        ("resource_not_found", Some(false))
    } else if message.contains("timeout")
        || message.contains("connect")
        || message.contains("timed out")
    {
        ("connection_failed", Some(true))
    } else if message.contains("provide")
        || message.contains("invalid")
        || message.contains("unknown")
        || message.contains("must ")
        || message.contains("required")
        || message.contains("supplied by both")
    {
        ("invalid_input", Some(false))
    } else {
        ("operation_failed", None)
    }
}

fn main() {
    if std::env::args_os().len() == 1 {
        print_startup_summary();
        return;
    }
    let format = invocation_format();
    response::configure(invocation_action(), format);
    let cli = match agent_command()
        .try_get_matches()
        .and_then(|m| Cli::from_arg_matches(&m))
    {
        Ok(cli) => cli,
        Err(error) => {
            let kind = error.kind();
            if matches!(
                kind,
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                print!("{error}");
                return;
            }
            if format != OutputFormat::Json
                && kind == clap::error::ErrorKind::MissingSubcommand
                && print_help_for_current_invocation()
            {
                return;
            }
            response::failure(
                &error.to_string(),
                "invalid_arguments",
                &parser_next_step(kind),
                &format!("{} --help", help_target()),
                Some(false),
                format,
                2,
            );
            std::process::exit(2);
        }
    };
    if let Err(error) = run_cli(cli) {
        let (code, retryable) = error_code(&error);
        if let Some(recovery) = error.downcast_ref::<apple_auth::AuthRecovery>() {
            response::next(&recovery.next_command);
        }
        if let Some(recovery) = error.downcast_ref::<apple_auth::RemindersAccessRecovery>() {
            response::next(&recovery.next_command);
        }
        response::failure(
            &format!("{error:#}"),
            code,
            &next_step(&error),
            &format!("{} --help", help_target()),
            retryable,
            format,
            if code == "invalid_input" { 2 } else { 1 },
        );
    }
    std::process::exit(response::exit_code());
}

fn auth_email(email: Option<String>) -> Result<String> {
    let email = email.context("Provide an email address")?;
    let email = email.trim().to_lowercase();
    if !is_simple_email(&email) {
        bail!("Invalid account email address");
    }
    // Preserve the configured spelling because it is also the keyring entry
    // name for accounts created by earlier CLI versions.
    Ok(load_config()?
        .accounts
        .into_iter()
        .find(|a| a.email.eq_ignore_ascii_case(&email))
        .map(|a| a.email)
        .unwrap_or(email))
}

fn selected_auth_email(email: Option<String>) -> Result<String> {
    if let Some(email) = email {
        auth_email(Some(email))
    } else {
        Ok(account(None)?.email)
    }
}

fn read_auth_secret(
    value: Option<String>,
    from_stdin: bool,
    label: &str,
    stdin_flag: &str,
) -> Result<String> {
    let secret = if let Some(value) = value {
        value
    } else if from_stdin {
        let mut value = String::new();
        std::io::stdin()
            .read_to_string(&mut value)
            .with_context(|| format!("Could not read {label} from stdin"))?;
        value.truncate(value.trim_end_matches(['\r', '\n']).len());
        value
    } else if std::io::stdin().is_terminal() {
        rpassword::prompt_password(format!("{label}: "))?
    } else {
        bail!(
            "{label} required in noninteractive mode. Use --{stdin_flag} with a private secret source piped to stdin."
        );
    };
    if secret.is_empty() {
        bail!("{label} must not be empty");
    }
    Ok(secret)
}

fn output_auth_state(
    connection: &apple_auth::AppleConnection,
    format: OutputFormat,
    title: &str,
) -> Result<()> {
    let email = &connection.session.account;
    let pending = connection.session.pending.as_ref();
    match connection.auth_state() {
        "verification_required" => response::next(format!(
            "icli auth verify {} --code-stdin",
            cli_quote(email)
        )),
        "refresh_required" => response::next(format!("icli auth refresh {}", cli_quote(email))),
        _ => response::next(
            "Retry the command that required authentication, or run icli reminders lists.",
        ),
    }
    output(
        &serde_json::json!({
            "email":email,"auth_state":connection.auth_state(),
            "apple_account_authenticated":pending.is_none(),"trusted_session_saved":pending.is_none(),
            "verification_method":pending.map(|p| p.method),
        }),
        format,
        title,
    )
}

fn read_password(value: Option<String>, from_stdin: bool, account: &Account) -> Result<String> {
    if value.is_some() || from_stdin {
        read_auth_secret(
            value,
            from_stdin,
            "Apple app-specific password",
            "password-stdin",
        )
    } else {
        secret(account)
    }
}

fn print_startup_summary() {
    println!(
        "Running icli v{} released on {}.",
        env!("CARGO_PKG_VERSION"),
        env!("ICLI_RELEASE_DATE")
    );

    let auth_configured = load_config().is_ok_and(|config| !config.accounts.is_empty());
    if auth_configured {
        println!("iCloud auth is configured. Run `icli auth` to manage accounts.");
    } else {
        println!("No iCloud account is configured yet.");
        println!(
            "Use `icli auth add EMAIL` for Apple sign-in, or `icli auth app-password EMAIL` for Mail, Calendar, and Contacts."
        );
    }

    println!("\nOther available commands:");
    println!("  icli calendar list");
    println!("  icli calendar <create|update|delete>");
    println!("  icli calendar events <list|search|get|create|update|delete|import>");
    println!("  icli auth add EMAIL");
    println!("  icli reminders <lists|list> --email EMAIL");
    println!("  icli config <default-user|format>");
    println!("  icli mail");
    println!("  icli contacts");
    println!("\nOptions: --json, --format <agent|csv|json>, --help, --version.");
}

fn print_help_for_current_invocation() -> bool {
    let mut args = std::env::args_os().collect::<Vec<_>>();
    args.push("--help".into());
    match agent_command().try_get_matches_from(args) {
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            print!("{error}");
            true
        }
        _ => false,
    }
}

fn parser_next_step(kind: clap::error::ErrorKind) -> String {
    let help = format!(
        "Run `{} --help` for the command instructions and accepted arguments.",
        help_target()
    );
    match kind {
        clap::error::ErrorKind::MissingRequiredArgument => {
            format!("Add the required argument(s) listed above. {help}")
        }
        clap::error::ErrorKind::ArgumentConflict => {
            format!("Remove one of the conflicting arguments listed above. {help}")
        }
        clap::error::ErrorKind::UnknownArgument => {
            format!(
                "Check the option spelling, or use a positional value where the usage shows one. {help}"
            )
        }
        clap::error::ErrorKind::InvalidValue | clap::error::ErrorKind::ValueValidation => {
            format!("Use one of the accepted values listed above. {help}")
        }
        clap::error::ErrorKind::TooManyValues => {
            format!("Remove extra values that are not shown in the usage line. {help}")
        }
        clap::error::ErrorKind::MissingSubcommand => {
            format!("Choose one of the subcommands listed above. {help}")
        }
        _ => format!("Correct the command using the usage line above. {help}"),
    }
}

fn run_cli(cli: Cli) -> Result<()> {
    let saved_format = load_config()?.response_format;
    let output_format = if cli.json {
        OutputFormat::Json
    } else {
        cli.format.unwrap_or(saved_format)
    };
    response::configure(invocation_action(), output_format);
    match cli.command {
        Command::Update { check } => update::run(check)?,
        Command::Config { command } => {
            let mut config = load_config()?;
            match command {
                ConfigCommand::DefaultUser { email } => {
                    let default_user = config
                        .accounts
                        .iter()
                        .find(|account| account.email.eq_ignore_ascii_case(&email))
                        .map(|account| account.email.clone())
                        .ok_or_else(|| anyhow!("Account not configured: {email}"))?;
                    config.default_user = Some(default_user.clone());
                    save_config(&config)?;
                    output(
                        &serde_json::json!({"default_user":default_user}),
                        output_format,
                        "Default account saved",
                    )?;
                }
                ConfigCommand::Format { response_format } => {
                    config.response_format = response_format;
                    save_config(&config)?;
                    let format = if cli.json {
                        OutputFormat::Json
                    } else {
                        cli.format.unwrap_or(response_format)
                    };
                    output(
                        &serde_json::json!({"response_format":response_format}),
                        format,
                        "Default response format saved",
                    )?;
                }
            }
        }
        Command::Auth { command } => match command {
            AuthCommand::Add(args) => {
                let email = auth_email(args.email.or(args.email_flag))?;
                let password = zeroize::Zeroizing::new(read_auth_secret(
                    args.password.or(args.password_flag),
                    args.password_stdin,
                    "Apple Account password",
                    "password-stdin",
                )?);
                if help_target() == "icli auth apple-login" {
                    response::warning(
                        "auth apple-login is deprecated; use auth add, then auth verify for the code.",
                    );
                }
                let connection = apple_auth::AppleConnection::begin_login(&email, &password)?;
                save_apple_session(&connection.session)?;
                let mut config = load_config()?;
                add_account_config(&mut config, &email);
                save_config(&config)?;
                output_auth_state(&connection, output_format, "Apple sign-in started")?;
            }
            AuthCommand::AppPassword(args) => {
                let email = auth_email(args.email.or(args.email_flag))?;
                let password = zeroize::Zeroizing::new(read_auth_secret(
                    args.password.or(args.password_flag),
                    args.password_stdin,
                    "Apple app-specific password",
                    "password-stdin",
                )?);
                credential(&email)?
                    .set_password(&password)
                    .context("Could not save app-specific password to system credential store")?;
                let mut config = load_config()?;
                add_account_config(&mut config, &email);
                save_config(&config)?;
                response::next(format!(
                    "icli auth check --email {} --app-password",
                    cli_quote(&email)
                ));
                output(
                    &serde_json::json!({"email":email,"default_user":config.default_user,"app_specific_password_saved":true,"verified":false}),
                    output_format,
                    "Saved app-specific password",
                )?;
            }
            AuthCommand::Verify {
                email,
                email_flag,
                code,
                code_flag,
                code_stdin,
            } => {
                let email = selected_auth_email(email.or(email_flag))?;
                let code = zeroize::Zeroizing::new(read_auth_secret(
                    code.or(code_flag),
                    code_stdin,
                    "Apple verification code",
                    "code-stdin",
                )?);
                let mut connection = load_apple_connection(&email)?;
                let result = connection.verify_code(&code);
                save_apple_session(&connection.session)?;
                result?;
                output_auth_state(&connection, output_format, "Apple sign-in verified")?;
            }
            AuthCommand::Resend {
                email,
                email_flag,
                method,
            } => {
                let email = selected_auth_email(email.or(email_flag))?;
                let mut connection = load_apple_connection(&email)?;
                let result = connection.resend_code(method);
                save_apple_session(&connection.session)?;
                result?;
                output_auth_state(
                    &connection,
                    output_format,
                    "Apple verification code requested",
                )?;
            }
            AuthCommand::Refresh { email, email_flag } => {
                let email = selected_auth_email(email.or(email_flag))?;
                let mut connection = load_apple_connection(&email)?;
                let result = connection.refresh_session();
                save_apple_session(&connection.session)?;
                result?;
                output_auth_state(&connection, output_format, "Apple session refreshed")?;
            }
            AuthCommand::List => {
                let config = load_config()?;
                let rows = config.accounts.iter().map(|a|serde_json::json!({"email":a.email,"default":config.default_user.as_deref().is_some_and(|default|default.eq_ignore_ascii_case(&a.email))})).collect::<Vec<_>>();
                output(&rows, output_format, "Configured accounts")?;
            }
            AuthCommand::Remove { email, email_flag } => {
                let email = selected_auth_email(email.or(email_flag))?;
                let mut c = load_config()?;
                remove_account_config(&mut c, &email)?;
                match credential(&email)?.delete_credential() {
                    Ok(()) | Err(keyring::Error::NoEntry) => (),
                    Err(error) => {
                        return Err(error)
                            .context("Could not delete password from the system credential store");
                    }
                }
                delete_apple_session(&email)?;
                save_config(&c)?;
                if c.default_user.is_none() {
                    for a in &c.accounts {
                        response::next(format!("icli config default-user {}", a.email));
                    }
                }
                output(
                    &serde_json::json!({"email":email,"removed":true,"default_user":c.default_user,"accounts":c.accounts}),
                    output_format,
                    "Removed account",
                )?;
            }
            AuthCommand::Check {
                email,
                password,
                email_flag,
                password_flag,
                password_stdin,
                app_password,
            } => {
                if !app_password {
                    let email = selected_auth_email(email.or(email_flag))?;
                    let connection = load_apple_connection(&email)?;
                    connection.check_session()?;
                    output_auth_state(&connection, output_format, "Apple session is valid")?;
                    return Ok(());
                }
                let a = account(email.or(email_flag))?;
                let p = read_password(password.or(password_flag), password_stdin, &a)?;
                let mut results = Vec::new();
                let mail = mail_session(&a.email, &p).map(|mut session| mail_logout(&mut session));
                let calendar = check_dav_auth(&a.email, &p);
                let contacts = contact_resource_url(&a.email, &p, "auth-check", true).map(|_| ());
                let mut passed = 0;
                for (service, result) in [
                    ("mail", mail),
                    ("calendar", calendar),
                    ("contacts", contacts),
                ] {
                    match result {
                        Ok(()) => { passed += 1; results.push(serde_json::json!({"service":service,"status":"success","authenticated":true})); }
                        Err(error) => results.push(serde_json::json!({"service":service,"status":"error","authenticated":false,"error":response::error_details(&error)})),
                    }
                }
                response::status(match passed {
                    3 => 0,
                    0 => 1,
                    _ => 3,
                });
                response::warning("Checks are read-only. Write access is not verified.");
                output(&results, output_format, "Authentication checks")?;
            }
        },
        Command::Calendar { command } => match command {
            CalendarCommand::List {
                email,
                email_flag,
                include,
            } => {
                validate_calendar_include(&include)?;
                let a = account(email.or(email_flag))?;
                let p = secret(&a)?;
                let vals = dav_items(
                    "https://caldav.icloud.com/",
                    &a.email,
                    &p,
                    "calendar",
                    None,
                    None,
                )?;
                output_calendars(&vals, output_format, &include)?
            }
            CalendarCommand::Create { name, email } => run_calendar_create(&name, email)?,
            CalendarCommand::Update {
                calendar,
                name,
                email,
            } => run_calendar_update(&calendar, &name, email)?,
            CalendarCommand::Delete {
                calendar,
                email,
                yes: _,
            } => run_calendar_delete(&calendar, email)?,
            CalendarCommand::Color(args) => run_calendar_color(args, output_format)?,
            CalendarCommand::Share { action } => run_calendar_share(action, output_format)?,
            CalendarCommand::Events {
                action,
                calendar_pos,
                from_pos,
                to_pos,
                email_pos,
                calendar,
                from,
                to,
                email_flag,
                include,
            } => match action {
                Some(CalendarEventsCommand::List {
                    from,
                    to,
                    calendar,
                    email,
                    include,
                    concurrency,
                }) => run_event_list(
                    &from,
                    &to,
                    calendar.as_deref(),
                    email,
                    &include,
                    output_format,
                    concurrency,
                )?,
                Some(CalendarEventsCommand::Search(args)) => run_event_search(args, output_format)?,
                Some(CalendarEventsCommand::Get {
                    uid,
                    calendar,
                    email,
                    include,
                }) => {
                    let account = account(email)?;
                    let password = secret(&account)?;
                    let resource = locate_event(&account.email, &password, &calendar, &uid)?;
                    let values = parse_ical_events(&resource.calendar_data)
                        .into_iter()
                        .filter(|event| event.uid == uid || resource.url == uid)
                        .map(serde_json::to_value)
                        .collect::<std::result::Result<Vec<_>, _>>()?;
                    output_events(values, output_format, &include, None)?;
                }
                Some(CalendarEventsCommand::Create(args)) => run_event_create(args)?,
                Some(CalendarEventsCommand::Update(args)) => run_event_update(args)?,
                Some(CalendarEventsCommand::Delete {
                    uid,
                    calendar,
                    email,
                    yes: _,
                }) => run_event_delete(&uid, &calendar, email)?,
                Some(CalendarEventsCommand::Import {
                    file,
                    calendar,
                    email,
                    concurrency,
                }) => run_event_import(file, &calendar, email, concurrency)?,
                None => {
                    if calendar_pos.is_none()
                        && from_pos.is_none()
                        && to_pos.is_none()
                        && email_pos.is_none()
                        && calendar.is_none()
                        && from.is_none()
                        && to.is_none()
                        && email_flag.is_none()
                        && include.is_empty()
                    {
                        if output_format == OutputFormat::Json {
                            bail!(
                                "Provide an event subcommand or a FROM and TO date range. Run icli calendar events --help for accepted arguments."
                            );
                        }
                        print_help_for_current_invocation();
                        return Ok(());
                    }
                    let positionals = [calendar_pos, from_pos, to_pos, email_pos]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>();
                    let positional_email = positionals
                        .iter()
                        .find(|value| value.contains('@'))
                        .cloned();
                    let positional_dates = positionals
                        .iter()
                        .filter(|value| looks_like_date_input(value))
                        .cloned()
                        .collect::<Vec<_>>();
                    let calendar = calendar.or_else(|| {
                        positionals
                            .iter()
                            .find(|value| !value.contains('@') && !looks_like_date_input(value))
                            .cloned()
                    });
                    let from = from
                        .or_else(|| positional_dates.first().cloned())
                        .ok_or_else(|| {
                            anyhow!("Provide a start date with FROM or --from YYYY-MM-DD")
                        })?;
                    let to = to
                        .or_else(|| positional_dates.get(1).cloned())
                        .ok_or_else(|| anyhow!("Provide an end date with TO or --to YYYY-MM-DD"))?;
                    run_event_list(
                        &from,
                        &to,
                        calendar.as_deref(),
                        email_flag.or(positional_email),
                        &include,
                        output_format,
                        4,
                    )?;
                }
            },
        },
        Command::Contacts {
            action: Some(action),
        } => run_contacts(action, output_format)?,
        Command::Contacts { action: None } => {
            if output_format == OutputFormat::Json {
                bail!(
                    "Provide a contacts subcommand. Run icli contacts --help for available operations."
                );
            }
            print_help_for_current_invocation();
        }
        Command::Mail {
            action: Some(action),
        } => run_mail(action, output_format)?,
        Command::Mail { action: None } => {
            if output_format == OutputFormat::Json {
                bail!("Provide a mail subcommand. Run icli mail --help for available operations.");
            }
            print_help_for_current_invocation();
        }
        Command::Reminders {
            email,
            action: Some(action),
        } => {
            let email = selected_auth_email(email)?;
            let mut connection = load_apple_connection(&email)?;
            connection.require_authenticated()?;
            let result = match action {
                RemindersCommand::Lists => connection
                    .reminder_lists()
                    .map(|rows| (serde_json::json!(rows), "Apple Reminders lists")),
                RemindersCommand::List { skip, limit } => {
                    connection.reminders(skip, limit).map(|(rows, has_more)| {
                        if has_more {
                            let next_skip = skip.saturating_add(rows.len());
                            response::next(format!(
                                "icli reminders list --email {} --skip {next_skip} --limit {limit}",
                                cli_quote(&connection.session.account)
                            ));
                        }
                        (serde_json::json!(rows), "Apple Reminders")
                    })
                }
                RemindersCommand::Get { id } => connection
                    .reminder_get(&id)
                    .map(|row| (row, "Apple reminder")),
                RemindersCommand::Create {
                    list,
                    title,
                    notes,
                    due,
                    all_day,
                    priority,
                    flagged,
                } => {
                    let due_ms = due.as_deref().map(parse_reminder_due_ms).transpose()?;
                    connection
                        .reminder_create(&list, &title, &notes, due_ms, all_day, priority, flagged)
                        .map(|row| (row, "Created Apple reminder"))
                }
                RemindersCommand::Update {
                    id,
                    title,
                    notes,
                    due,
                    clear_due,
                    priority,
                    flagged,
                    completed,
                    all_day,
                } => {
                    let mut patch = serde_json::Map::new();
                    if let Some(title) = title {
                        patch.insert("title".into(), serde_json::json!(title));
                    }
                    if let Some(notes) = notes {
                        patch.insert("notes".into(), serde_json::json!(notes));
                    }
                    if let Some(due) = due {
                        patch.insert(
                            "due_date_ms".into(),
                            serde_json::json!(parse_reminder_due_ms(&due)?),
                        );
                    }
                    if clear_due {
                        patch.insert("due_date_ms".into(), serde_json::Value::Null);
                    }
                    if let Some(priority) = priority {
                        patch.insert("priority".into(), serde_json::json!(priority));
                    }
                    if let Some(flagged) = flagged {
                        patch.insert("flagged".into(), serde_json::json!(flagged));
                    }
                    if let Some(completed) = completed {
                        patch.insert("completed".into(), serde_json::json!(completed));
                    }
                    if let Some(all_day) = all_day {
                        patch.insert("all_day".into(), serde_json::json!(all_day));
                    }
                    connection
                        .reminder_update(&id, &serde_json::Value::Object(patch))
                        .map(|row| (row, "Updated Apple reminder"))
                }
                RemindersCommand::SetStatus { id, status } => connection
                    .reminder_set_status(&id, matches!(status, ReminderStatus::Completed))
                    .map(|row| (row, "Updated Apple reminder status")),
                RemindersCommand::Delete { id, yes: _ } => connection
                    .reminder_delete(&id)
                    .map(|row| (row, "Deleted Apple reminder")),
                RemindersCommand::Snapshot { list, limit } => connection
                    .reminder_snapshot(&list, limit)
                    .map(|row| (row, "Apple Reminders snapshot")),
                RemindersCommand::Changes { since, limit } => connection
                    .reminders_changes(since.as_deref(), limit)
                    .map(|row| {
                        if row
                            .get("more_available")
                            .and_then(serde_json::Value::as_bool)
                            == Some(true)
                        {
                            if let Some(cursor) =
                                row.get("cursor").and_then(serde_json::Value::as_str)
                            {
                                response::next(format!(
                                    "icli reminders changes --email {} --since {} --limit {limit}",
                                    cli_quote(&connection.session.account),
                                    cli_quote(cursor)
                                ));
                            }
                        }
                        (row, "Apple Reminders changes")
                    }),
                RemindersCommand::SyncCursor => connection.reminders_sync_cursor().map(|cursor| {
                    (
                        serde_json::json!({"cursor":cursor}),
                        "Apple Reminders sync cursor",
                    )
                }),
                RemindersCommand::Alarm { action } => match action {
                    ReminderAlarmCommand::List { id } => connection
                        .reminder_alarms(&id)
                        .map(|rows| (serde_json::json!(rows), "Apple reminder alarms")),
                    ReminderAlarmCommand::AddLocation {
                        id,
                        title,
                        address,
                        latitude,
                        longitude,
                        radius,
                        proximity,
                    } => connection
                        .reminder_add_location_alarm(
                            &id,
                            &title,
                            &address,
                            latitude,
                            longitude,
                            radius,
                            match proximity {
                                ReminderProximity::Arriving => 1,
                                ReminderProximity::Leaving => 2,
                            },
                        )
                        .map(|row| (row, "Added Apple reminder location alarm")),
                },
                RemindersCommand::Hashtag { action } => match action {
                    ReminderHashtagCommand::List { id } => connection
                        .reminder_hashtags(&id)
                        .map(|rows| (serde_json::json!(rows), "Apple reminder hashtags")),
                    ReminderHashtagCommand::Create { id, name } => connection
                        .reminder_hashtag_create(&id, &name)
                        .map(|row| (row, "Created Apple reminder hashtag")),
                    ReminderHashtagCommand::Update {
                        id,
                        hashtag_id,
                        name,
                    } => connection
                        .reminder_hashtag_update(&id, &hashtag_id, &name)
                        .map(|row| (row, "Updated Apple reminder hashtag")),
                    ReminderHashtagCommand::Delete {
                        id,
                        hashtag_id,
                        yes: _,
                    } => connection
                        .reminder_hashtag_delete(&id, &hashtag_id)
                        .map(|row| (row, "Deleted Apple reminder hashtag")),
                },
                RemindersCommand::Attachment { action } => match action {
                    ReminderAttachmentCommand::List { id } => connection
                        .reminder_attachments(&id)
                        .map(|rows| (serde_json::json!(rows), "Apple reminder attachments")),
                    ReminderAttachmentCommand::CreateUrl { id, url, uti } => connection
                        .reminder_attachment_create_url(&id, &url, &uti)
                        .map(|row| (row, "Created Apple reminder URL attachment")),
                    ReminderAttachmentCommand::Update {
                        id,
                        attachment_id,
                        url,
                        uti,
                    } => connection
                        .reminder_attachment_update(
                            &id,
                            &attachment_id,
                            url.as_deref(),
                            uti.as_deref(),
                        )
                        .map(|row| (row, "Updated Apple reminder attachment")),
                    ReminderAttachmentCommand::Delete {
                        id,
                        attachment_id,
                        yes: _,
                    } => connection
                        .reminder_attachment_delete(&id, &attachment_id)
                        .map(|row| (row, "Deleted Apple reminder attachment")),
                },
                RemindersCommand::Recurrence { action } => match action {
                    ReminderRecurrenceCommand::List { id } => connection
                        .reminder_recurrences(&id)
                        .map(|rows| (serde_json::json!(rows), "Apple reminder recurrence rules")),
                    ReminderRecurrenceCommand::Create {
                        id,
                        frequency,
                        interval,
                        occurrence_count,
                        first_day_of_week,
                    } => connection
                        .reminder_recurrence_create(
                            &id,
                            match frequency {
                                ReminderFrequency::Daily => 0,
                                ReminderFrequency::Weekly => 1,
                                ReminderFrequency::Monthly => 2,
                                ReminderFrequency::Yearly => 3,
                            },
                            interval,
                            occurrence_count,
                            first_day_of_week,
                        )
                        .map(|row| (row, "Created Apple reminder recurrence rule")),
                    ReminderRecurrenceCommand::Update {
                        id,
                        rule_id,
                        frequency,
                        interval,
                        occurrence_count,
                        first_day_of_week,
                    } => {
                        let mut patch = serde_json::Map::new();
                        if let Some(value) = frequency {
                            patch.insert(
                                "frequency".into(),
                                serde_json::json!(match value {
                                    ReminderFrequency::Daily => 0,
                                    ReminderFrequency::Weekly => 1,
                                    ReminderFrequency::Monthly => 2,
                                    ReminderFrequency::Yearly => 3,
                                }),
                            );
                        }
                        if let Some(value) = interval {
                            patch.insert("interval".into(), serde_json::json!(value));
                        }
                        if let Some(value) = occurrence_count {
                            patch.insert("occurrence_count".into(), serde_json::json!(value));
                        }
                        if let Some(value) = first_day_of_week {
                            patch.insert("first_day_of_week".into(), serde_json::json!(value));
                        }
                        connection
                            .reminder_recurrence_update(
                                &id,
                                &rule_id,
                                &serde_json::Value::Object(patch),
                            )
                            .map(|row| (row, "Updated Apple reminder recurrence rule"))
                    }
                    ReminderRecurrenceCommand::Delete {
                        id,
                        rule_id,
                        yes: _,
                    } => connection
                        .reminder_recurrence_delete(&id, &rule_id)
                        .map(|row| (row, "Deleted Apple reminder recurrence rule")),
                },
            };
            let persist_result = connection
                .save_cookies()
                .and_then(|()| save_apple_session(&connection.session));
            let (data, title) = result?;
            persist_result?;
            output(&data, output_format, title)?;
        }
        Command::Reminders { action: None, .. } => {
            if output_format == OutputFormat::Json {
                bail!(
                    "Provide a Reminders subcommand. Run `icli reminders --help` for available operations."
                );
            }
            print_help_for_current_invocation();
        }
    }
    Ok(())
}

fn looks_like_date_input(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 5 && bytes[..4].iter().all(u8::is_ascii_digit) && bytes[4] == b'-'
}

fn date_bound(s: &str, end: bool) -> Result<DateTime<Utc>> {
    let d = NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .with_context(|| format!("Invalid date {s}; use YYYY-MM-DD"))?;
    let d = if end {
        d.succ_opt().ok_or_else(|| anyhow!("Date out of range"))?
    } else {
        d
    };
    Ok(Utc.from_utc_datetime(&d.and_hms_opt(0, 0, 0).unwrap()))
}

fn parse_reminder_due_ms(value: &str) -> Result<i64> {
    if let Ok(date) = DateTime::parse_from_rfc3339(value) {
        return Ok(date.timestamp_millis());
    }
    let date = NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .with_context(|| format!("Invalid reminder due date {value}; use YYYY-MM-DD or RFC3339"))?;
    Ok(Utc
        .from_utc_datetime(&date.and_hms_opt(0, 0, 0).unwrap())
        .timestamp_millis())
}

fn check_dav_auth(email: &str, password: &str) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(5))
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut pacer = RequestPacer::default();
    let probe = "<?xml version=\"1.0\"?><d:propfind xmlns:d=\"DAV:\"><d:prop><d:current-user-principal/></d:prop></d:propfind>";
    dav(
        &client,
        &mut pacer,
        "https://caldav.icloud.com/",
        email,
        password,
        "PROPFIND",
        "0",
        probe,
    )?;
    Ok(())
}

fn resolve_dav_href(base: &str, href: &str) -> Result<String> {
    Ok(reqwest::Url::parse(base)?.join(href)?.to_string())
}

fn calendar_path_ids(href: &str) -> (String, String) {
    let path = reqwest::Url::parse(href)
        .map(|url| url.path().to_string())
        .unwrap_or_else(|_| href.to_string());
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let id = segments.last().copied().unwrap_or_default().to_string();
    let dsid = segments.first().copied().unwrap_or_default().to_string();
    (dsid, id)
}

fn calendar_url(email: &str, password: &str, selector: &str) -> Result<String> {
    let calendars = dav_items(
        "https://caldav.icloud.com/",
        email,
        password,
        "calendar",
        None,
        None,
    )?;
    select_calendar_url(&calendars, selector)
}

fn select_calendar_url(calendars: &[serde_json::Value], selector: &str) -> Result<String> {
    let mut matches = Vec::new();
    for calendar in calendars {
        let name = calendar.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let href = calendar.get("href").and_then(|v| v.as_str()).unwrap_or("");
        let (_, fallback_id) = calendar_path_ids(href);
        let id = calendar
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or(&fallback_id);
        let href_path = reqwest::Url::parse(href)
            .map(|url| url.path().to_string())
            .unwrap_or_else(|_| href.to_string());
        if name.eq_ignore_ascii_case(selector)
            || id.eq_ignore_ascii_case(selector)
            || href.eq_ignore_ascii_case(selector)
            || href_path.eq_ignore_ascii_case(selector)
        {
            matches.push((name.to_string(), id.to_string(), href.to_string()));
        }
    }
    if matches.len() == 1 {
        return resolve_dav_href("https://caldav.icloud.com/", &matches[0].2);
    }
    if matches.len() > 1 {
        bail!(
            "Ambiguous calendar selector '{selector}'. Candidates: {}. Select an exact href using --calendar HREF or the calendar argument.",
            matches
                .iter()
                .map(|(name, id, href)| format!("{name} (id={id}, href={href})"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let available = calendars
        .iter()
        .map(|calendar| {
            let name = calendar.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let id = calendar.get("id").and_then(|v| v.as_str()).unwrap_or("");
            if name.is_empty() {
                id.to_string()
            } else {
                format!("{name} ({id})")
            }
        })
        .collect::<Vec<_>>();
    bail!(
        "No calendar matched '{selector}'. Available calendars: {}. Run `icli calendar list` for the current names and IDs.",
        if available.is_empty() {
            "none".to_string()
        } else {
            available.join(", ")
        }
    )
}

fn calendar_home_url(email: &str, password: &str) -> Result<String> {
    let client = dav_client()?;
    let mut pacer = RequestPacer::default();
    let probe = "<?xml version=\"1.0\"?><d:propfind xmlns:d=\"DAV:\"><d:prop><d:current-user-principal/></d:prop></d:propfind>";
    let response = dav(
        &client,
        &mut pacer,
        "https://caldav.icloud.com/",
        email,
        password,
        "PROPFIND",
        "0",
        probe,
    )?;
    let doc = roxmltree::Document::parse(&response)?;
    let principal = doc
        .descendants()
        .find(|node| node.tag_name().name() == "current-user-principal")
        .and_then(|node| node.descendants().find(|n| n.tag_name().name() == "href"))
        .and_then(|node| node.text())
        .ok_or_else(|| anyhow!("DAV response did not include current-user-principal"))?;
    let principal_url = resolve_dav_href("https://caldav.icloud.com/", principal)?;
    let probe = "<?xml version=\"1.0\"?><d:propfind xmlns:d=\"DAV:\" xmlns:c=\"urn:ietf:params:xml:ns:caldav\"><d:prop><c:calendar-home-set/></d:prop></d:propfind>";
    let response = dav(
        &client,
        &mut pacer,
        &principal_url,
        email,
        password,
        "PROPFIND",
        "0",
        probe,
    )?;
    let doc = roxmltree::Document::parse(&response)?;
    let home = doc
        .descendants()
        .find(|node| node.tag_name().name() == "calendar-home-set")
        .and_then(|node| node.descendants().find(|n| n.tag_name().name() == "href"))
        .and_then(|node| node.text())
        .ok_or_else(|| anyhow!("DAV response did not include calendar-home-set"))?;
    resolve_dav_href(&principal_url, home)
}

fn dav_client() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(5))
        .timeout(Duration::from_secs(30))
        .build()?)
}

#[allow(clippy::too_many_arguments)]
fn dav_write(
    client: &reqwest::blocking::Client,
    pacer: &mut RequestPacer,
    url: &str,
    email: &str,
    password: &str,
    method: &str,
    content_type: Option<&str>,
    body: &str,
    if_match: Option<&str>,
    if_none_match: Option<&str>,
) -> Result<String> {
    let response = dav_write_exchange(
        client,
        pacer,
        url,
        email,
        password,
        method,
        content_type,
        body,
        if_match,
        if_none_match,
    )?;
    if !response.status.is_success() {
        bail!(
            "DAV request {method} {url} returned {}: {}",
            response.status,
            response.body.chars().take(400).collect::<String>()
        );
    }
    Ok(response.body)
}

struct DavWriteExchange {
    status: reqwest::StatusCode,
    headers: serde_json::Map<String, serde_json::Value>,
    body: String,
}

#[allow(clippy::too_many_arguments)]
fn dav_write_exchange(
    client: &reqwest::blocking::Client,
    pacer: &mut RequestPacer,
    url: &str,
    email: &str,
    password: &str,
    method: &str,
    content_type: Option<&str>,
    body: &str,
    if_match: Option<&str>,
    if_none_match: Option<&str>,
) -> Result<DavWriteExchange> {
    pacer.wait();
    let method = reqwest::Method::from_bytes(method.as_bytes())?;
    let mut request = client
        .request(method.clone(), url)
        .basic_auth(email, Some(password));
    if let Some(content_type) = content_type {
        request = request.header(reqwest::header::CONTENT_TYPE, content_type);
    }
    if let Some(tag) = if_match {
        request = request.header(reqwest::header::IF_MATCH, tag);
    }
    if let Some(tag) = if_none_match {
        request = request.header(reqwest::header::IF_NONE_MATCH, tag);
    }
    let response = request.body(body.to_string()).send()?;
    let status = response.status();
    let mut headers = serde_json::Map::new();
    for (name, value) in response.headers() {
        let name = name.as_str();
        if name.eq_ignore_ascii_case("dav")
            || name.eq_ignore_ascii_case("allow")
            || name.eq_ignore_ascii_case("content-type")
            || name.eq_ignore_ascii_case("server")
            || name.eq_ignore_ascii_case("retry-after")
            || name.eq_ignore_ascii_case("request-id")
            || name.eq_ignore_ascii_case("x-request-id")
            || name.to_ascii_lowercase().starts_with("x-apple-")
        {
            if let Ok(value) = value.to_str() {
                headers.insert(
                    name.to_string(),
                    serde_json::Value::String(value.to_string()),
                );
            }
        }
    }
    let text = response.text()?;
    Ok(DavWriteExchange {
        status,
        headers,
        body: text,
    })
}

struct EventResource {
    url: String,
    etag: String,
    calendar_data: String,
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn locate_event(email: &str, password: &str, calendar: &str, uid: &str) -> Result<EventResource> {
    let collection = calendar_url(email, password, calendar)?;
    let exact_href = uid.starts_with("https://");
    let mut found = match query_event_resources(
        email,
        password,
        &collection,
        if exact_href { None } else { Some(uid) },
    ) {
        Ok(found) => found,
        Err(error) if is_filter_query_rejection(&error) => {
            query_event_resources(email, password, &collection, None)?
                .into_iter()
                .filter(|resource| {
                    resource.url == uid
                        || parse_ical_events(&resource.calendar_data)
                            .iter()
                            .any(|event| event.uid == uid)
                })
                .collect()
        }
        Err(error) => return Err(error),
    };
    if exact_href {
        found.retain(|resource| resource.url == uid);
    }
    match found.len() {
        0 => bail!("No event with UID '{uid}' found in calendar '{calendar}'"),
        1 => Ok(found.remove(0)),
        _ => bail!(
            "Ambiguous event UID '{uid}' in calendar '{calendar}'. Candidates: {}. Supply an exact href instead of UID.",
            found
                .iter()
                .map(|resource| resource.url.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn is_filter_query_rejection(error: &anyhow::Error) -> bool {
    let message = error.to_string();
    ["returned 400", "returned 403", "returned 412"]
        .iter()
        .any(|status| message.contains(status))
}

fn query_event_resources(
    email: &str,
    password: &str,
    collection: &str,
    uid_filter: Option<&str>,
) -> Result<Vec<EventResource>> {
    let client = dav_client()?;
    let mut pacer = RequestPacer::default();
    let filter = match uid_filter {
        Some(uid) => format!(
            "<c:comp-filter name=\"VCALENDAR\"><c:comp-filter name=\"VEVENT\"><c:prop-filter name=\"UID\"><c:text-match collation=\"i;octet\" match-type=\"equals\">{}</c:text-match></c:prop-filter></c:comp-filter></c:comp-filter>",
            xml_escape(uid)
        ),
        None => {
            "<c:comp-filter name=\"VCALENDAR\"><c:comp-filter name=\"VEVENT\"/></c:comp-filter>"
                .to_string()
        }
    };
    let body = format!(
        "<c:calendar-query xmlns:d=\"DAV:\" xmlns:c=\"urn:ietf:params:xml:ns:caldav\"><d:prop><d:getetag/><c:calendar-data/></d:prop><c:filter>{filter}</c:filter></c:calendar-query>"
    );
    let response = dav(
        &client, &mut pacer, collection, email, password, "REPORT", "1", &body,
    )?;
    let doc = roxmltree::Document::parse(&response)?;
    let mut found = Vec::new();
    for node in doc
        .descendants()
        .filter(|node| node.tag_name().name() == "response")
    {
        let href = node
            .descendants()
            .find(|child| child.tag_name().name() == "href")
            .and_then(|child| child.text());
        let etag = node
            .descendants()
            .find(|child| child.tag_name().name() == "getetag")
            .and_then(|child| child.text());
        let data = node
            .descendants()
            .find(|child| child.tag_name().name() == "calendar-data")
            .and_then(|child| child.text());
        if let (Some(href), Some(etag), Some(data)) = (href, etag, data) {
            if uid_filter
                .is_none_or(|uid| parse_ical_events(data).iter().any(|event| event.uid == uid))
            {
                found.push(EventResource {
                    url: resolve_dav_href(collection, href)?,
                    etag: etag.to_string(),
                    calendar_data: data.to_string(),
                });
            }
        }
    }
    Ok(found)
}

fn parse_event_time(value: &str) -> Result<String> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("Invalid event time '{value}'. Use RFC 3339 with a timezone, such as 2026-10-20T09:00:00+02:00"))?;
    Ok(parsed
        .with_timezone(&Utc)
        .format("%Y%m%dT%H%M%SZ")
        .to_string())
}

fn escape_ical_text(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace(';', "\\;")
        .replace(',', "\\,")
        .replace('\n', "\\n")
        .replace('\r', "")
}

fn replace_ical_property(ical: &str, property: &str, value: &str) -> String {
    let mut lines = ical.lines().map(str::to_string).collect::<Vec<_>>();
    let mut i = 0;
    let mut replaced = false;
    while i < lines.len() {
        let key = lines[i]
            .split_once(':')
            .map(|(head, _)| head.split(';').next().unwrap_or(head));
        if key.is_some_and(|key| key.eq_ignore_ascii_case(property)) {
            lines[i] = format!("{property}:{value}");
            i += 1;
            while i < lines.len() && lines[i].starts_with([' ', '\t']) {
                lines.remove(i);
            }
            replaced = true;
            break;
        }
        i += 1;
    }
    if !replaced {
        if let Some(index) = lines
            .iter()
            .rposition(|line| line.eq_ignore_ascii_case("END:VEVENT"))
        {
            lines.insert(index, format!("{property}:{value}"));
        }
    }
    format!("{}\r\n", lines.join("\r\n"))
}

fn replace_ical_date_property(ical: &str, property: &str, date: NaiveDate) -> String {
    let mut lines = ical.lines().map(str::to_string).collect::<Vec<_>>();
    let mut i = 0;
    let mut replaced = false;
    while i < lines.len() {
        let key = lines[i]
            .split_once(':')
            .map(|(head, _)| head.split(';').next().unwrap_or(head));
        if key.is_some_and(|key| key.eq_ignore_ascii_case(property)) {
            lines[i] = format!("{property};VALUE=DATE:{}", date.format("%Y%m%d"));
            i += 1;
            while i < lines.len() && lines[i].starts_with([' ', '\t']) {
                lines.remove(i);
            }
            replaced = true;
            break;
        }
        i += 1;
    }
    if !replaced {
        if let Some(index) = lines
            .iter()
            .rposition(|line| line.eq_ignore_ascii_case("END:VEVENT"))
        {
            lines.insert(
                index,
                format!("{property};VALUE=DATE:{}", date.format("%Y%m%d")),
            );
        }
    }
    format!("{}\r\n", lines.join("\r\n"))
}

fn update_ical_property(ical: &str, property: &str, value: Option<&str>) -> String {
    match value {
        Some(value) => replace_ical_property(ical, property, value),
        None => ical.to_string(),
    }
}

fn remove_ical_property(ical: &str, property: &str) -> String {
    let mut lines = Vec::new();
    let mut skip_fold = false;
    let mut in_event = false;
    let mut handled_event = false;
    for line in ical.lines() {
        if line.eq_ignore_ascii_case("BEGIN:VEVENT") {
            in_event = !handled_event;
            handled_event = true;
        }
        if line.starts_with([' ', '\t']) && skip_fold {
            continue;
        }
        skip_fold = false;
        if line.eq_ignore_ascii_case("END:VEVENT") && in_event {
            in_event = false;
        }
        let key = line
            .split_once(':')
            .map(|(head, _)| head.split(';').next().unwrap_or(head));
        if in_event && key.is_some_and(|key| key.eq_ignore_ascii_case(property)) {
            skip_fold = true;
            continue;
        }
        lines.push(line.to_string());
    }
    format!("{}\r\n", lines.join("\r\n"))
}

fn is_simple_email(value: &str) -> bool {
    value.split_once('@').is_some_and(|(local, domain)| {
        !local.is_empty()
            && !domain.is_empty()
            && !domain.starts_with('.')
            && !domain.ends_with('.')
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"@._+-".contains(&byte))
    })
}

fn add_ical_attendees(
    ical: &str,
    organizer: &str,
    participants: &[String],
) -> Result<(String, Vec<String>)> {
    if !is_simple_email(organizer) {
        bail!("The configured account email cannot be used as an event organizer")
    }
    for participant in participants {
        if !is_simple_email(participant) {
            bail!("Invalid participant email '{participant}'")
        }
    }

    let mut lines = ical.lines().map(str::to_string).collect::<Vec<_>>();
    let start = lines
        .iter()
        .position(|line| line.eq_ignore_ascii_case("BEGIN:VEVENT"))
        .ok_or_else(|| anyhow!("Calendar resource does not contain a VEVENT"))?;
    let end = lines[start + 1..]
        .iter()
        .position(|line| line.eq_ignore_ascii_case("END:VEVENT"))
        .map(|offset| start + 1 + offset)
        .ok_or_else(|| anyhow!("Calendar resource contains an unterminated VEVENT"))?;
    let event_lines = &lines[start + 1..end];
    let has_organizer = event_lines.iter().any(|line| {
        line.split_once(':').is_some_and(|(head, _)| {
            head.split(';')
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("ORGANIZER"))
        })
    });
    let existing = event_lines
        .iter()
        .filter_map(|line| {
            let (head, value) = line.split_once(':')?;
            head.split(';')
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("ATTENDEE"))
                .then(|| {
                    value
                        .trim()
                        .strip_prefix("mailto:")
                        .unwrap_or(value.trim())
                        .to_ascii_lowercase()
                })
        })
        .collect::<std::collections::HashSet<_>>();
    let added = participants
        .iter()
        .filter(|email| !existing.contains(&email.to_ascii_lowercase()))
        .cloned()
        .collect::<Vec<_>>();

    let mut insert = Vec::new();
    if !has_organizer {
        insert.push(format!("ORGANIZER:mailto:{organizer}"));
    }
    for participant in &added {
        insert.push(format!(
            "ATTENDEE;RSVP=TRUE;PARTSTAT=NEEDS-ACTION;ROLE=REQ-PARTICIPANT:mailto:{participant}"
        ));
    }
    lines.splice(end..end, insert);
    Ok((format!("{}\r\n", lines.join("\r\n")), added))
}

fn increment_ical_sequence(ical: &str) -> String {
    let mut lines = ical.lines().map(str::to_string).collect::<Vec<_>>();
    let Some(start) = lines
        .iter()
        .position(|line| line.eq_ignore_ascii_case("BEGIN:VEVENT"))
    else {
        return ical.to_string();
    };
    let Some(end) = lines[start + 1..]
        .iter()
        .position(|line| line.eq_ignore_ascii_case("END:VEVENT"))
        .map(|offset| start + 1 + offset)
    else {
        return ical.to_string();
    };
    let sequence = lines[start + 1..end].iter().position(|line| {
        line.split_once(':').is_some_and(|(head, _)| {
            head.split(';')
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("SEQUENCE"))
        })
    });
    if let Some(offset) = sequence {
        let index = start + 1 + offset;
        let next = lines[index]
            .split_once(':')
            .and_then(|(_, value)| value.trim().parse::<u64>().ok())
            .unwrap_or(0)
            .saturating_add(1);
        lines[index] = format!("SEQUENCE:{next}");
    } else {
        lines.insert(end, "SEQUENCE:1".to_string());
    }
    format!("{}\r\n", lines.join("\r\n"))
}

fn create_event_ical(args: &EventCreateArgs, uid: &str, organizer: &str) -> Result<String> {
    if let Some(rule) = &args.rrule {
        validate_recurrence_rule(rule)?;
    }
    if args.alarm_minutes.contains(&0) {
        bail!("--alarm-minutes must be greater than zero");
    }
    if args.all_day.is_none() && args.start.is_some() != args.end.is_some() {
        bail!("Provide both --start and --end")
    }
    let (start, end) = if let Some(date) = &args.all_day {
        let date = NaiveDate::parse_from_str(date, "%Y-%m-%d")
            .with_context(|| format!("Invalid all-day date '{date}'. Use YYYY-MM-DD"))?;
        let end = date
            .succ_opt()
            .ok_or_else(|| anyhow!("All-day event date is out of range"))?;
        (
            format!("DTSTART;VALUE=DATE:{}", date.format("%Y%m%d")),
            format!("DTEND;VALUE=DATE:{}", end.format("%Y%m%d")),
        )
    } else {
        let start = args
            .start
            .as_deref()
            .ok_or_else(|| anyhow!("Provide --start and --end, or use --all-day DATE"))?;
        let end = args
            .end
            .as_deref()
            .ok_or_else(|| anyhow!("Provide --start and --end, or use --all-day DATE"))?;
        let start = parse_event_time(start)?;
        let end = parse_event_time(end)?;
        if start >= end {
            bail!("Event end must be after event start")
        }
        (format!("DTSTART:{start}"), format!("DTEND:{end}"))
    };
    let now = Utc::now().format("%Y%m%dT%H%M%SZ");
    let mut event = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//iCLI//CalDAV Client//EN\r\nBEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:{now}\r\nSEQUENCE:0\r\n{start}\r\n{end}\r\nSUMMARY:{}\r\n",
        escape_ical_text(&args.summary)
    );
    if !args.participants.is_empty() {
        if !is_simple_email(organizer) {
            bail!("The configured account email cannot be used as an event organizer")
        }
        event.push_str(&format!("ORGANIZER:mailto:{organizer}\r\n"));
        for participant in &args.participants {
            if !is_simple_email(participant) {
                bail!("Invalid participant email '{participant}'")
            }
            event.push_str(&format!(
                "ATTENDEE;RSVP=TRUE;PARTSTAT=NEEDS-ACTION;ROLE=REQ-PARTICIPANT:mailto:{participant}\r\n"
            ));
        }
    }
    if let Some(location) = &args.location {
        event.push_str(&format!("LOCATION:{}\r\n", escape_ical_text(location)));
    }
    if let Some(description) = &args.description {
        event.push_str(&format!(
            "DESCRIPTION:{}\r\n",
            escape_ical_text(description)
        ));
    }
    if let Some(rule) = &args.rrule {
        event.push_str(&format!("RRULE:{rule}\r\n"));
    }
    for minutes in &args.alarm_minutes {
        event.push_str(&format!("BEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:{}\r\nTRIGGER:-PT{minutes}M\r\nEND:VALARM\r\n",escape_ical_text(&args.summary)));
    }
    event.push_str("END:VEVENT\r\nEND:VCALENDAR\r\n");
    Ok(event)
}

fn validate_recurrence_rule(rule: &str) -> Result<()> {
    if rule.is_empty()
        || rule.contains(['\r', '\n'])
        || !rule.split(';').all(|part| {
            part.split_once('=')
                .is_some_and(|(k, v)| !k.is_empty() && !v.is_empty())
        })
    {
        bail!(
            "Invalid recurrence rule; use semicolon-separated KEY=VALUE fields such as FREQ=WEEKLY;BYDAY=MO"
        );
    }
    if !rule.split(';').any(|part| {
        part.split_once('=')
            .is_some_and(|(k, _)| k.eq_ignore_ascii_case("FREQ"))
    }) {
        bail!("Recurrence rule must include FREQ");
    }
    Ok(())
}

fn replace_ical_alarms(ical: &str, alarms: &[u32]) -> String {
    let mut filtered = Vec::new();
    let mut in_event = false;
    let mut handled_event = false;
    let mut in_alarm = false;
    for line in ical.lines() {
        if line.eq_ignore_ascii_case("BEGIN:VEVENT") {
            in_event = !handled_event;
            handled_event = true;
        }
        if in_event && line.eq_ignore_ascii_case("BEGIN:VALARM") {
            in_alarm = true;
            continue;
        }
        if in_event && in_alarm {
            if line.eq_ignore_ascii_case("END:VALARM") {
                in_alarm = false;
            }
            continue;
        }
        if in_event && line.eq_ignore_ascii_case("END:VEVENT") {
            for minutes in alarms {
                filtered.extend([
                    "BEGIN:VALARM".to_string(),
                    "ACTION:DISPLAY".into(),
                    "DESCRIPTION:Reminder".into(),
                    format!("TRIGGER:-PT{minutes}M"),
                    "END:VALARM".into(),
                ]);
            }
            in_event = false;
        }
        filtered.push(line.to_string());
    }
    format!(
        "{}\r\n",
        filtered
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\r\n")
    )
}

fn run_event_create(args: EventCreateArgs) -> Result<()> {
    let account = account(args.email.clone())?;
    let uid = format!(
        "icli-{}@icli",
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    );
    let data = create_event_ical(&args, &uid, &account.email)?;
    let password = secret(&account)?;
    let collection = calendar_url(&account.email, &password, &args.calendar)?;
    let mut url = reqwest::Url::parse(&collection)?;
    url.path_segments_mut()
        .map_err(|_| anyhow!("Calendar URL cannot accept an event resource"))?
        .pop_if_empty()
        .push(&format!("{uid}.ics"));
    let client = dav_client()?;
    dav_write(
        &client,
        &mut RequestPacer::default(),
        url.as_str(),
        &account.email,
        &password,
        "PUT",
        Some("text/calendar; charset=utf-8"),
        &data,
        None,
        Some("*"),
    )?;
    let mut invitation_status = Vec::new();
    if !args.participants.is_empty() {
        match locate_event(&account.email, &password, &args.calendar, &uid) {
            Ok(resource) => {
                invitation_status =
                    attendee_delivery_status(&resource.calendar_data, &uid, &args.participants)
            }
            Err(error) => response::warning(format!(
                "Event created, but attendee status could not be read: {error:#}"
            )),
        }
        response::warning(
            "Invitation delivery status does not confirm the recipient saw a notification. No separate invite link is created.",
        );
    }
    response::next(format!(
        "icli calendar events get {} --calendar {} --email {}",
        cli_quote(&uid),
        cli_quote(&collection),
        account.email
    ));
    response::selected(
        &serde_json::json!({"uid":uid,"summary":args.summary,"calendar":args.calendar,"email":account.email,"participants":args.participants,"invitation_status":invitation_status}),
        "Created event",
    )?;
    Ok(())
}

fn property_values(value: &serde_json::Value) -> Vec<&serde_json::Value> {
    match value {
        serde_json::Value::Array(values) => values.iter().collect(),
        _ => vec![value],
    }
}

fn attendee_delivery_status(data: &str, uid: &str, participants: &[String]) -> Vec<String> {
    let Some(event) = parse_ical_events(data)
        .into_iter()
        .find(|event| event.uid == uid)
    else {
        return participants
            .iter()
            .map(|participant| {
                format!("{participant}: event was not present in iCloud's read-back response")
            })
            .collect();
    };
    let attendees = event
        .other_properties
        .get("attendee")
        .map(property_values)
        .unwrap_or_default();
    let params = event
        .other_properties
        .get("attendee_params")
        .map(property_values)
        .unwrap_or_default();

    participants
        .iter()
        .map(|participant| {
            let index = attendees.iter().position(|attendee| {
                attendee
                    .as_str()
                    .and_then(|value| value.split_once(':'))
                    .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("mailto"))
                    .map(|(_, address)| address)
                    .is_some_and(|address| address.eq_ignore_ascii_case(participant))
            });
            let Some(index) = index else {
                return format!("{participant}: ATTENDEE was not present in iCloud's stored event");
            };
            let param = params.get(index).and_then(|value| value.as_object());
            let status = param
                .and_then(|values| {
                    values
                        .get("schedule-status")
                        .or_else(|| values.get("schedule_status"))
                })
                .and_then(serde_json::Value::as_str);
            match status {
                Some("1.0") => format!("{participant}: invitation is pending with the server (SCHEDULE-STATUS 1.0)"),
                Some("1.1") => format!("{participant}: server sent the invitation, but delivery to the recipient is unconfirmed (SCHEDULE-STATUS 1.1)"),
                Some("1.2") => format!("{participant}: server reports the invitation was delivered (SCHEDULE-STATUS 1.2)"),
                Some("3.7") => format!("{participant}: server did not recognize this calendar address (SCHEDULE-STATUS 3.7)"),
                Some("3.8") => format!("{participant}: server could not send because of insufficient privileges (SCHEDULE-STATUS 3.8)"),
                Some("5.1") => format!("{participant}: temporary delivery failure reported by the server (SCHEDULE-STATUS 5.1)"),
                Some("5.2") => format!("{participant}: server could not find a delivery route for this address (SCHEDULE-STATUS 5.2)"),
                Some("5.3") => format!("{participant}: server refused to schedule with this recipient (SCHEDULE-STATUS 5.3)"),
                Some(other) => format!("{participant}: CalDAV reported SCHEDULE-STATUS {other}"),
                None => format!("{participant}: ATTENDEE is stored, but iCloud returned no SCHEDULE-STATUS, so delivery is unconfirmed"),
            }
        })
        .collect()
}

fn run_event_update(mut args: EventUpdateArgs) -> Result<()> {
    if args.summary.is_none()
        && args.start.is_none()
        && args.end.is_none()
        && args.all_day.is_none()
        && args.location.is_none()
        && args.description.is_none()
        && args.rrule.is_none()
        && args.alarm_minutes.is_empty()
        && args.participants.is_empty()
        && !args.clear_alarms
        && !args.clear_recurrence
    {
        bail!("Provide at least one event property to update")
    }
    if args.start.is_some() != args.end.is_some() {
        bail!("Provide both --start and --end when changing event times")
    }
    if let Some(rule) = &args.rrule {
        validate_recurrence_rule(rule)?;
    }
    if args.alarm_minutes.contains(&0) {
        bail!("--alarm-minutes must be greater than zero");
    }
    if let (Some(start), Some(end)) = (&args.start, &args.end) {
        if parse_event_time(start)? >= parse_event_time(end)? {
            bail!("Event end must be after event start")
        }
    }
    let all_day_dates = args
        .all_day
        .as_deref()
        .map(|date| {
            let start = NaiveDate::parse_from_str(date, "%Y-%m-%d")
                .with_context(|| format!("Invalid all-day date '{date}'. Use YYYY-MM-DD"))?;
            let end = start
                .succ_opt()
                .ok_or_else(|| anyhow!("All-day event date is out of range"))?;
            Ok::<_, anyhow::Error>((start, end))
        })
        .transpose()?;
    let changed_properties = [
        ("summary", args.summary.is_some()),
        ("start", args.start.is_some()),
        ("end", args.end.is_some()),
        ("all_day", args.all_day.is_some()),
        ("location", args.location.is_some()),
        ("description", args.description.is_some()),
        ("recurrence", args.rrule.is_some() || args.clear_recurrence),
        (
            "alarms",
            !args.alarm_minutes.is_empty() || args.clear_alarms,
        ),
        ("participants", !args.participants.is_empty()),
    ]
    .into_iter()
    .filter_map(|(key, present)| present.then_some(key))
    .collect::<Vec<_>>();
    let account = account(args.email.clone())?;
    let password = secret(&account)?;
    let resource = locate_event(&account.email, &password, &args.calendar, &args.uid)?;
    if let Some(event) = parse_ical_events(&resource.calendar_data).first() {
        args.uid = event.uid.clone();
    }
    let data = update_ical_property(
        &resource.calendar_data,
        "SUMMARY",
        args.summary.as_deref().map(escape_ical_text).as_deref(),
    );
    let data = if let Some((start, end)) = all_day_dates {
        let data = replace_ical_date_property(&data, "DTSTART", start);
        replace_ical_date_property(&data, "DTEND", end)
    } else {
        let data = update_ical_property(
            &data,
            "DTSTART",
            args.start
                .as_deref()
                .map(parse_event_time)
                .transpose()?
                .as_deref(),
        );
        update_ical_property(
            &data,
            "DTEND",
            args.end
                .as_deref()
                .map(parse_event_time)
                .transpose()?
                .as_deref(),
        )
    };
    let data = update_ical_property(
        &data,
        "LOCATION",
        args.location.as_deref().map(escape_ical_text).as_deref(),
    );
    let data = update_ical_property(
        &data,
        "DESCRIPTION",
        args.description.as_deref().map(escape_ical_text).as_deref(),
    );
    let data = if let Some(rule) = args.rrule.as_deref() {
        replace_ical_property(&data, "RRULE", rule)
    } else if args.clear_recurrence {
        remove_ical_property(&data, "RRULE")
    } else {
        data
    };
    let data = if !args.alarm_minutes.is_empty() {
        replace_ical_alarms(&data, &args.alarm_minutes)
    } else if args.clear_alarms {
        replace_ical_alarms(&data, &[])
    } else {
        data
    };
    let (data, participants_added) = if args.participants.is_empty() {
        (data, Vec::new())
    } else {
        add_ical_attendees(&data, &account.email, &args.participants)?
    };
    if !args.participants.is_empty()
        && participants_added.is_empty()
        && changed_properties.len() == 1
    {
        bail!("All requested participants are already attendees of this event")
    }
    let data = if participants_added.is_empty() {
        data
    } else {
        increment_ical_sequence(&data)
    };
    let data = replace_ical_property(
        &data,
        "DTSTAMP",
        &Utc::now().format("%Y%m%dT%H%M%SZ").to_string(),
    );
    let client = dav_client()?;
    dav_write(
        &client,
        &mut RequestPacer::default(),
        &resource.url,
        &account.email,
        &password,
        "PUT",
        Some("text/calendar; charset=utf-8"),
        &data,
        Some(&resource.etag),
        None,
    )?;
    let mut invitation_status = Vec::new();
    if !participants_added.is_empty() {
        match locate_event(&account.email, &password, &args.calendar, &args.uid) {
            Ok(resource) => {
                invitation_status = attendee_delivery_status(
                    &resource.calendar_data,
                    &args.uid,
                    &participants_added,
                )
            }
            Err(error) => response::warning(format!(
                "Event updated, but attendee status could not be read: {error:#}"
            )),
        }
        response::warning(
            "Invitation delivery status does not confirm the recipient saw a notification. No separate invite link is created.",
        );
    }
    response::next(format!(
        "icli calendar events get {} --calendar {} --email {}",
        cli_quote(&args.uid),
        cli_quote(&args.calendar),
        account.email
    ));
    response::selected(
        &serde_json::json!({"uid":args.uid,"calendar":args.calendar,"email":account.email,"updated":true,"changed_properties":changed_properties,"participants_added":participants_added,"invitation_status":invitation_status}),
        "Updated event",
    )?;
    Ok(())
}

fn run_event_delete(uid: &str, calendar: &str, email: Option<String>) -> Result<()> {
    let account = account(email)?;
    let password = secret(&account)?;
    let resource = locate_event(&account.email, &password, calendar, uid)?;
    let actual_uid = parse_ical_events(&resource.calendar_data)
        .first()
        .map(|event| event.uid.clone())
        .unwrap_or_else(|| uid.to_string());
    let client = dav_client()?;
    dav_write(
        &client,
        &mut RequestPacer::default(),
        &resource.url,
        &account.email,
        &password,
        "DELETE",
        None,
        "",
        Some(&resource.etag),
        None,
    )?;
    response::selected(
        &serde_json::json!({"uid":actual_uid,"calendar":calendar,"email":account.email,"deleted":true}),
        "Deleted event",
    )?;
    Ok(())
}

fn ical_event_resources(input: &str) -> Result<Vec<(String, String)>> {
    let lines = input.lines().collect::<Vec<_>>();
    let mut timezones = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].eq_ignore_ascii_case("BEGIN:VTIMEZONE") {
            let start = i;
            i += 1;
            while i < lines.len() && !lines[i].eq_ignore_ascii_case("END:VTIMEZONE") {
                i += 1;
            }
            if i < lines.len() {
                i += 1;
                timezones.push(lines[start..i].join("\r\n"));
            }
            continue;
        }
        i += 1;
    }

    let mut components_by_uid: BTreeMap<String, Vec<String>> = BTreeMap::new();
    i = 0;
    while i < lines.len() {
        if lines[i].eq_ignore_ascii_case("BEGIN:VEVENT") {
            let start = i;
            i += 1;
            while i < lines.len() && !lines[i].eq_ignore_ascii_case("END:VEVENT") {
                i += 1;
            }
            if i == lines.len() {
                bail!("ICS file contains a VEVENT without END:VEVENT")
            }
            i += 1;
            let component = lines[start..i].join("\r\n");
            let mut resource = String::from(
                "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//iCLI//CalDAV Client//EN\r\n",
            );
            for timezone in &timezones {
                resource.push_str(timezone);
                resource.push_str("\r\n");
            }
            resource.push_str(&component);
            resource.push_str("\r\nEND:VCALENDAR\r\n");
            let parsed = parse_ical_events(&resource);
            let event = parsed
                .first()
                .ok_or_else(|| anyhow!("Could not parse VEVENT in ICS file"))?;
            if event.uid.trim().is_empty() {
                bail!("Every imported VEVENT must have a UID")
            }
            components_by_uid
                .entry(event.uid.clone())
                .or_default()
                .push(component);
            continue;
        }
        i += 1;
    }
    if components_by_uid.is_empty() {
        bail!("ICS file did not contain any VEVENT components")
    }
    let mut events = Vec::with_capacity(components_by_uid.len());
    for (uid, components) in components_by_uid {
        let mut resource =
            String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//iCLI//CalDAV Client//EN\r\n");
        for timezone in &timezones {
            resource.push_str(timezone);
            resource.push_str("\r\n");
        }
        for component in components {
            resource.push_str(&component);
            resource.push_str("\r\n");
        }
        resource.push_str("END:VCALENDAR\r\n");
        events.push((uid, resource));
    }
    Ok(events)
}

fn run_event_import(
    file: PathBuf,
    calendar: &str,
    email: Option<String>,
    concurrency: usize,
) -> Result<()> {
    let content = fs::read_to_string(&file)
        .with_context(|| format!("Could not read ICS file {}", file.display()))?;
    let events = ical_event_resources(&content)?;
    let account = account(email)?;
    let password = secret(&account)?;
    let collection = calendar_url(&account.email, &password, calendar)?;
    let client = dav_client()?;
    let worker_count = concurrency.min(events.len()).max(1);
    let mut buckets = (0..worker_count).map(|_| Vec::new()).collect::<Vec<_>>();
    for (index, event) in events.into_iter().enumerate() {
        buckets[index % worker_count].push((index, event));
    }

    let mut outcomes = thread::scope(|scope| -> Result<Vec<_>> {
        let handles = buckets
            .into_iter()
            .map(|bucket| {
                let client = client.clone();
                let email = account.email.clone();
                let password = password.clone();
                let collection = collection.clone();
                scope.spawn(move || {
                    let mut pacer = RequestPacer::default();
                    bucket
                        .into_iter()
                        .map(|(index, (uid, data))| {
                            let outcome = (|| -> Result<EventImportResult> {
                                let mut url = reqwest::Url::parse(&collection)?;
                                url.path_segments_mut()
                                    .map_err(|_| {
                                        anyhow!("Calendar URL cannot accept an event resource")
                                    })?
                                    .pop_if_empty()
                                    .push(&format!("{uid}.ics"));
                                Ok(import_event_with_retries(
                                    &client,
                                    &mut pacer,
                                    url.as_str(),
                                    &email,
                                    &password,
                                    &uid,
                                    &data,
                                ))
                            })();
                            (index, uid, outcome)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        let mut outcomes = Vec::new();
        for handle in handles {
            outcomes.extend(
                handle
                    .join()
                    .map_err(|_| anyhow!("An event import worker exited unexpectedly"))?,
            );
        }
        Ok(outcomes)
    })?;
    outcomes.sort_by_key(|(index, _, _)| *index);
    let mut created = 0usize;
    let mut failures = Vec::new();
    let results = outcomes
        .into_iter()
        .map(|(_, uid, outcome)| match outcome {
            Ok(EventImportResult {
                result: Ok(()),
                retries,
                attempt_errors,
            }) => {
                created += 1;
                serde_json::json!({"uid":uid,"status":"success","created":true,"retries":retries,"attempt_errors":attempt_errors})
            }
            Ok(EventImportResult {
                result: Err(error),
                retries,
                attempt_errors,
            }) => {
                failures.push(format!("{uid}: {error:#}"));
                serde_json::json!({"uid":uid,"status":"error","retries":retries,"attempt_errors":attempt_errors,"error":response::error_details(&error)})
            }
            Err(error) => {
                failures.push(format!("{uid}: {error:#}"));
                serde_json::json!({"uid":uid,"status":"error","retries":0,"attempt_errors":[],"error":response::error_details(&error)})
            }
        })
        .collect::<Vec<_>>();
    if !failures.is_empty() {
        response::status(if created > 0 { 3 } else { 1 });
        response::warning(
            "Import is not atomic. Successful items remain in iCloud; retry only failed UIDs.",
        );
    }
    if let Some(uid) = results
        .iter()
        .find(|row| row["status"] == "success")
        .and_then(|row| row["uid"].as_str())
    {
        response::next(format!(
            "icli calendar events get {} --calendar {} --email {}",
            cli_quote(uid),
            cli_quote(calendar),
            account.email
        ));
    }
    response::selected(&results, "ICS import results")?;
    Ok(())
}

fn parse_dav_concurrency(value: &str) -> std::result::Result<usize, String> {
    let concurrency = value
        .parse::<usize>()
        .map_err(|_| format!("invalid concurrency `{value}`; expected an integer from 1 to 8"))?;
    if (1..=8).contains(&concurrency) {
        Ok(concurrency)
    } else {
        Err(format!(
            "invalid concurrency `{value}`; expected an integer from 1 to 8"
        ))
    }
}

struct EventImportResult {
    result: Result<()>,
    retries: u32,
    attempt_errors: Vec<serde_json::Value>,
}

fn import_event_with_retries(
    client: &reqwest::blocking::Client,
    pacer: &mut RequestPacer,
    url: &str,
    email: &str,
    password: &str,
    uid: &str,
    data: &str,
) -> EventImportResult {
    let mut retries = 0;
    let mut attempt_errors = Vec::new();

    for attempt in 0..=EVENT_IMPORT_RETRIES {
        match dav_write_exchange(
            client,
            pacer,
            url,
            email,
            password,
            "PUT",
            Some("text/calendar; charset=utf-8"),
            data,
            None,
            Some("*"),
        ) {
            Ok(response) if response.status.is_success() => {
                return EventImportResult {
                    result: Ok(()),
                    retries,
                    attempt_errors,
                };
            }
            Ok(response) => {
                let status = response.status;
                let error = anyhow!(
                    "DAV request PUT {url} returned {status}: {}",
                    response.body.chars().take(400).collect::<String>()
                );
                attempt_errors.push(response::error_details(&error));

                // A retried conditional PUT can return 412 if iCloud committed the
                // first PUT but lost or replaced its response. Confirm that exact UID
                // before treating the import as complete.
                if status == reqwest::StatusCode::PRECONDITION_FAILED && retries > 0 {
                    let exists =
                        import_resource_contains_uid(client, pacer, url, email, password, uid);
                    match exists {
                        Ok(true) => {
                            return EventImportResult {
                                result: Ok(()),
                                retries,
                                attempt_errors,
                            };
                        }
                        Ok(false) => {}
                        Err(verify_error) => {
                            attempt_errors.push(response::error_details(&verify_error));
                        }
                    }
                    return EventImportResult {
                        result: Err(error),
                        retries,
                        attempt_errors,
                    };
                }

                if !retryable_status(status) {
                    return EventImportResult {
                        result: Err(error),
                        retries,
                        attempt_errors,
                    };
                }
                if attempt == EVENT_IMPORT_RETRIES {
                    return EventImportResult {
                        result: Err(error),
                        retries,
                        attempt_errors,
                    };
                }

                let retry_after = response
                    .headers
                    .get("retry-after")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|value| retry_after_delay(Some(value)));
                if let Some(delay) = retry_after {
                    if delay > DAV_RETRY_AFTER_LIMIT {
                        return EventImportResult {
                            result: Err(anyhow!(
                                "DAV server returned {status} and asked for a retry delay over five minutes; stopping. Try the command again later."
                            )),
                            retries,
                            attempt_errors,
                        };
                    }
                    thread::sleep(delay);
                } else {
                    thread::sleep(backoff_delay(attempt));
                }
                retries += 1;
            }
            Err(error) => {
                let retryable_transport = error
                    .downcast_ref::<reqwest::Error>()
                    .is_some_and(|error| error.is_timeout() || error.is_connect());
                attempt_errors.push(response::error_details(&error));
                if !retryable_transport {
                    return EventImportResult {
                        result: Err(error),
                        retries,
                        attempt_errors,
                    };
                }
                if attempt == EVENT_IMPORT_RETRIES {
                    return EventImportResult {
                        result: Err(error),
                        retries,
                        attempt_errors,
                    };
                }
                thread::sleep(backoff_delay(attempt));
                retries += 1;
            }
        }
    }

    unreachable!("bounded event import retry loop always returns")
}

fn import_resource_contains_uid(
    client: &reqwest::blocking::Client,
    pacer: &mut RequestPacer,
    url: &str,
    email: &str,
    password: &str,
    uid: &str,
) -> Result<bool> {
    pacer.wait();
    let response = client
        .get(url)
        .basic_auth(email, Some(password))
        .header(reqwest::header::ACCEPT, "text/calendar")
        .send()
        .context("Could not verify a possibly completed event import")?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(false);
    }
    let status = response.status();
    if !status.is_success() {
        bail!("CalDAV event verification GET returned {status}");
    }
    let contents = response.text()?;
    Ok(ical_event_resources(&contents)?
        .iter()
        .any(|(existing_uid, _)| existing_uid == uid))
}

fn run_calendar_create(name: &str, email: Option<String>) -> Result<()> {
    let account = account(email)?;
    let password = secret(&account)?;
    let home = calendar_home_url(&account.email, &password)?;
    let mut url = reqwest::Url::parse(&home)?;
    // Calendar collection URLs are opaque identifiers on iCloud. Keep the
    // user-facing name in DAV:displayname instead of deriving the URL from it.
    let calendar_id = uuid::Uuid::new_v4().to_string();
    url.path_segments_mut()
        .map_err(|_| anyhow!("Calendar home URL cannot accept a child collection"))?
        .pop_if_empty()
        .push(&calendar_id)
        .push("");
    let body = format!(
        "<c:mkcalendar xmlns:d=\"DAV:\" xmlns:c=\"urn:ietf:params:xml:ns:caldav\"><d:set><d:prop><d:displayname>{}</d:displayname></d:prop></d:set></c:mkcalendar>",
        xml_escape(name)
    );
    let client = dav_client()?;
    dav_write(
        &client,
        &mut RequestPacer::default(),
        url.as_str(),
        &account.email,
        &password,
        "MKCALENDAR",
        Some("application/xml; charset=utf-8"),
        &body,
        None,
        None,
    )?;
    response::next(format!("icli calendar list --email {}", account.email));
    response::selected(
        &serde_json::json!({"id":calendar_id,"href":url.as_str(),"name":name,"email":account.email}),
        "Created calendar",
    )?;
    Ok(())
}

fn run_calendar_update(selector: &str, name: &str, email: Option<String>) -> Result<()> {
    let account = account(email)?;
    let password = secret(&account)?;
    let url = calendar_url(&account.email, &password, selector)?;
    let body = format!(
        "<d:propertyupdate xmlns:d=\"DAV:\"><d:set><d:prop><d:displayname>{}</d:displayname></d:prop></d:set></d:propertyupdate>",
        xml_escape(name)
    );
    let client = dav_client()?;
    dav_write(
        &client,
        &mut RequestPacer::default(),
        &url,
        &account.email,
        &password,
        "PROPPATCH",
        Some("application/xml; charset=utf-8"),
        &body,
        None,
        None,
    )?;
    response::next(format!("icli calendar list --email {}", account.email));
    response::selected(
        &serde_json::json!({"id":calendar_path_ids(&url).1,"href":url,"name":name,"email":account.email}),
        "Renamed calendar",
    )?;
    Ok(())
}

fn run_calendar_color(args: CalendarColorArgs, format: OutputFormat) -> Result<()> {
    let requested_color = normalize_calendar_color(&args.color)?;
    let account = account(args.email)?;
    let password = secret(&account)?;
    let url = calendar_url(&account.email, &password, &args.calendar)?;
    let body = format!(
        "<d:propertyupdate xmlns:d=\"DAV:\" xmlns:a=\"http://apple.com/ns/ical/\"><d:set><d:prop><a:calendar-color>{}</a:calendar-color></d:prop></d:set></d:propertyupdate>",
        xml_escape(&requested_color)
    );
    dav_write(
        &dav_client()?,
        &mut RequestPacer::default(),
        &url,
        &account.email,
        &password,
        "PROPPATCH",
        Some("application/xml; charset=utf-8"),
        &body,
        None,
        None,
    )?;
    let (color, verified) = match read_calendar_color(&url, &account.email, &password) {
        Ok(Some(color)) => (Some(color), true),
        Ok(None) => {
            response::warning(
                "Color update succeeded, but iCloud returned no calendar-color value to verify it.",
            );
            (None, false)
        }
        Err(_) => {
            response::warning(
                "Color update succeeded, but reading the stored calendar color failed; the requested value was not confirmed.",
            );
            (None, false)
        }
    };
    output(
        &serde_json::json!({
            "calendar": args.calendar,
            "color": color,
            "requested_color": requested_color,
            "updated": true,
            "verified": verified
        }),
        format,
        "Updated calendar color",
    )
}

fn normalize_calendar_color(color: &str) -> Result<String> {
    let color = color.trim();
    let hex = color.strip_prefix('#').unwrap_or(color);
    if !matches!(hex.len(), 6 | 8) || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("Calendar color must be #RRGGBB or #RRGGBBAA");
    }
    let hex = hex.to_ascii_uppercase();
    Ok(if hex.len() == 6 {
        format!("#{hex}FF")
    } else {
        format!("#{hex}")
    })
}

fn calendar_color_from_xml(xml: &str) -> Result<Option<String>> {
    let doc = roxmltree::Document::parse(xml)?;
    let Some(raw) = doc
        .descendants()
        .find(|node| node.tag_name().name() == "calendar-color")
        .and_then(|node| node.text())
    else {
        return Ok(None);
    };
    normalize_calendar_color(raw).map(Some)
}

fn read_calendar_color(url: &str, email: &str, password: &str) -> Result<Option<String>> {
    let request = "<d:propfind xmlns:d=\"DAV:\" xmlns:a=\"http://apple.com/ns/ical/\"><d:prop><a:calendar-color/></d:prop></d:propfind>";
    let response = dav(
        &dav_client()?,
        &mut RequestPacer::default(),
        url,
        email,
        password,
        "PROPFIND",
        "0",
        request,
    )?;
    calendar_color_from_xml(&response)
}

fn calendar_share_resource_diagnostics(
    url: &str,
    email: &str,
    password: &str,
) -> serde_json::Value {
    let result = (|| -> Result<serde_json::Value> {
        let request = "<d:propfind xmlns:d=\"DAV:\" xmlns:c=\"urn:ietf:params:xml:ns:caldav\" xmlns:a=\"http://apple.com/ns/ical/\" xmlns:cs=\"http://calendarserver.org/ns/\"><d:prop><d:resourcetype/><d:displayname/><d:owner/><d:current-user-privilege-set/><d:supported-privilege-set/><d:acl/><c:calendar-user-address-set/><a:calendar-color/><cs:invite/><cs:allowed-sharing-modes/><cs:shared-url/></d:prop></d:propfind>";
        let response = dav(
            &dav_client()?,
            &mut RequestPacer::default(),
            url,
            email,
            password,
            "PROPFIND",
            "0",
            request,
        )?;
        let doc = roxmltree::Document::parse(&response)?;
        let mut properties = serde_json::Map::new();
        for propstat in doc
            .descendants()
            .filter(|node| node.tag_name().name() == "propstat")
        {
            let status = propstat
                .descendants()
                .find(|node| node.tag_name().name() == "status")
                .and_then(|node| node.text())
                .unwrap_or("unknown")
                .to_string();
            let Some(prop) = propstat
                .children()
                .find(|node| node.is_element() && node.tag_name().name() == "prop")
            else {
                continue;
            };
            for property in prop.children().filter(|node| node.is_element()) {
                let local = property.tag_name().name();
                let namespace = property.tag_name().namespace().unwrap_or("");
                let name = match namespace {
                    "DAV:" => format!("DAV:{local}"),
                    "urn:ietf:params:xml:ns:caldav" => format!("CalDAV:{local}"),
                    "http://apple.com/ns/ical/" => format!("Apple:{local}"),
                    "http://calendarserver.org/ns/" => format!("CalendarServer:{local}"),
                    _ => format!("{{{namespace}}}{local}"),
                };
                let details = match local {
                    "resourcetype" => serde_json::json!({
                        "types": property.children().filter(|node| node.is_element()).map(|node| node.tag_name().name()).collect::<Vec<_>>()
                    }),
                    "owner" => serde_json::json!({
                        "href_count": property.descendants().filter(|node| node.tag_name().name() == "href").count()
                    }),
                    "current-user-privilege-set" | "supported-privilege-set" => serde_json::json!({
                        "privileges": property.descendants().filter(|node| node.tag_name().name() == "privilege").flat_map(|node| node.children()).filter(|node| node.is_element()).map(|node| node.tag_name().name()).collect::<Vec<_>>()
                    }),
                    "acl" => serde_json::json!({
                        "ace_count": property.descendants().filter(|node| node.tag_name().name() == "ace").count()
                    }),
                    "calendar-user-address-set" => serde_json::json!({
                        "address_count": property.descendants().filter(|node| node.tag_name().name() == "href").count()
                    }),
                    "invite" => serde_json::json!({
                        "organizer_count": property.descendants().filter(|node| node.tag_name().name() == "organizer").count(),
                        "sharee_count": property.descendants().filter(|node| node.tag_name().name() == "user").count(),
                        "sharees": property.descendants().filter(|node| node.tag_name().name() == "user").map(|user| {
                            let status = user.children().find(|node| node.is_element() && matches!(node.tag_name().name(), "invite-noresponse" | "invite-accepted" | "invite-declined" | "invite-invalid")).map(|node| node.tag_name().name());
                            let access = user.descendants().find(|node| matches!(node.tag_name().name(), "read" | "read-write")).map(|node| node.tag_name().name());
                            serde_json::json!({"status":status,"access":access})
                        }).collect::<Vec<_>>()
                    }),
                    "allowed-sharing-modes" => serde_json::json!({
                        "modes": property.descendants().filter(|node| matches!(node.tag_name().name(), "can-be-shared" | "can-be-published")).map(|node| node.tag_name().name()).collect::<Vec<_>>()
                    }),
                    "shared-url" => serde_json::json!({
                        "href_count": property.descendants().filter(|node| node.tag_name().name() == "href").count()
                    }),
                    "calendar-color" => serde_json::json!({
                        "present": property.text().is_some_and(|text| !text.trim().is_empty())
                    }),
                    _ => serde_json::json!({
                        "present": property.children().any(|node| node.is_element() || node.text().is_some_and(|text| !text.trim().is_empty()))
                    }),
                };
                let entry = properties
                    .entry(name)
                    .or_insert_with(|| serde_json::json!({"statuses": []}));
                if let Some(statuses) = entry
                    .get_mut("statuses")
                    .and_then(|value| value.as_array_mut())
                {
                    statuses.push(serde_json::json!({"status":status,"details":details}));
                }
            }
        }
        Ok(serde_json::json!({
            "available": true,
            "response_count": doc.descendants().filter(|node| node.tag_name().name() == "response").count(),
            "properties": properties
        }))
    })();
    result.unwrap_or_else(|_| {
        serde_json::json!({
            "available": false,
            "error": "Could not read calendar metadata properties"
        })
    })
}

fn calendar_share_options_diagnostics(url: &str, email: &str, password: &str) -> serde_json::Value {
    let result = (|| -> Result<serde_json::Value> {
        let response = dav_client()?
            .request(reqwest::Method::OPTIONS, url)
            .basic_auth(email, Some(password))
            .send()?;
        let headers = response.headers();
        let header = |name: reqwest::header::HeaderName| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
        };
        Ok(serde_json::json!({
            "available": true,
            "status": response.status().as_u16(),
            "allow": header(reqwest::header::ALLOW),
            "dav": header(reqwest::header::HeaderName::from_static("dav")),
            "ms_author_via": header(reqwest::header::HeaderName::from_static("ms-author-via"))
        }))
    })();
    result.unwrap_or_else(|_| serde_json::json!({"available": false}))
}

fn calendar_share_owner_href(url: &str, email: &str, password: &str) -> Option<String> {
    let request = "<d:propfind xmlns:d=\"DAV:\"><d:prop><d:owner/></d:prop></d:propfind>";
    let response = dav(
        &dav_client().ok()?,
        &mut RequestPacer::default(),
        url,
        email,
        password,
        "PROPFIND",
        "0",
        request,
    )
    .ok()?;
    let doc = roxmltree::Document::parse(&response).ok()?;
    let owner = doc
        .descendants()
        .find(|node| node.tag_name().name() == "owner")?;
    let href = owner
        .descendants()
        .find(|node| node.tag_name().name() == "href")?
        .text()?;
    resolve_dav_href(url, href).ok()
}

fn calendar_share_parent_url(url: &str) -> Option<String> {
    let mut parsed = reqwest::Url::parse(url).ok()?;
    let path = parsed.path().trim_end_matches('/').to_string();
    let parent_end = path.rfind('/')? + 1;
    parsed.set_path(&path[..parent_end]);
    Some(parsed.to_string())
}

fn calendar_share_owner_home_diagnostics(
    url: &str,
    email: &str,
    password: &str,
) -> serde_json::Value {
    let result = (|| -> Result<serde_json::Value> {
        let owner_url = calendar_share_owner_href(url, email, password)
            .ok_or_else(|| anyhow!("DAV owner principal was not available"))?;
        let probe = "<d:propfind xmlns:d=\"DAV:\" xmlns:c=\"urn:ietf:params:xml:ns:caldav\"><d:prop><c:calendar-home-set/></d:prop></d:propfind>";
        let response = dav(
            &dav_client()?,
            &mut RequestPacer::default(),
            &owner_url,
            email,
            password,
            "PROPFIND",
            "0",
            probe,
        )?;
        let doc = roxmltree::Document::parse(&response)?;
        let home_href = doc
            .descendants()
            .find(|node| node.tag_name().name() == "calendar-home-set")
            .and_then(|node| {
                node.descendants()
                    .find(|child| child.tag_name().name() == "href")
            })
            .and_then(|node| node.text())
            .ok_or_else(|| anyhow!("Owner principal did not expose calendar-home-set"))?;
        let home_url = resolve_dav_href(&owner_url, home_href)?;
        let listing = "<d:propfind xmlns:d=\"DAV:\" xmlns:c=\"urn:ietf:params:xml:ns:caldav\" xmlns:cs=\"http://calendarserver.org/ns/\"><d:prop><d:displayname/><d:resourcetype/><cs:allowed-sharing-modes/></d:prop></d:propfind>";
        let response = dav(
            &dav_client()?,
            &mut RequestPacer::default(),
            &home_url,
            email,
            password,
            "PROPFIND",
            "1",
            listing,
        )?;
        let doc = roxmltree::Document::parse(&response)?;
        let mut matches = Vec::new();
        for entry in doc
            .descendants()
            .filter(|node| node.tag_name().name() == "response")
        {
            let Some(prop) = entry
                .descendants()
                .find(|node| node.tag_name().name() == "prop")
            else {
                continue;
            };
            let displayname = prop
                .children()
                .find(|node| node.is_element() && node.tag_name().name() == "displayname")
                .and_then(|node| node.text())
                .unwrap_or("");
            if displayname.eq_ignore_ascii_case("BirbParronts")
                || displayname.eq_ignore_ascii_case("BirdParrotns")
            {
                let resource = prop
                    .children()
                    .find(|node| node.is_element() && node.tag_name().name() == "resourcetype");
                let types = resource
                    .into_iter()
                    .flat_map(|node| node.children())
                    .filter(|node| node.is_element())
                    .map(|node| node.tag_name().name().to_string())
                    .collect::<Vec<_>>();
                let modes = prop
                    .descendants()
                    .filter(|node| {
                        matches!(node.tag_name().name(), "can-be-shared" | "can-be-published")
                    })
                    .map(|node| node.tag_name().name())
                    .collect::<Vec<_>>();
                matches.push(serde_json::json!({"displayname":displayname,"resourcetype":types,"sharing_modes":modes}));
            }
        }
        Ok(serde_json::json!({"owner_calendar_home_readable":true,"matching_calendars":matches}))
    })();
    result.unwrap_or_else(|_error| {
        serde_json::json!({
            "owner_calendar_home_readable":false,
            "error":"Owner calendar-home discovery failed; this account may not have access to the owner's calendar home"
        })
    })
}

fn calendar_share_capability_diagnostics(
    url: &str,
    email: &str,
    password: &str,
) -> serde_json::Value {
    let parent = calendar_share_parent_url(url);
    let owner = calendar_share_owner_href(url, email, password);
    serde_json::json!({
        "calendar": {
            "options": calendar_share_options_diagnostics(url, email, password),
            "properties": calendar_share_resource_diagnostics(url, email, password)
        },
        "parent": parent.as_ref().map(|parent_url| serde_json::json!({
            "options": calendar_share_options_diagnostics(parent_url, email, password),
            "properties": calendar_share_resource_diagnostics(parent_url, email, password)
        })),
        "owner_principal": owner.as_ref().map(|owner_url| serde_json::json!({
            "options": calendar_share_options_diagnostics(owner_url, email, password),
            "properties": calendar_share_resource_diagnostics(owner_url, email, password)
        })),
        "owner_calendar_home": calendar_share_owner_home_diagnostics(url, email, password)
    })
}

fn redact_href_values(xml: &str) -> String {
    let mut output = String::with_capacity(xml.len());
    let mut cursor = 0;
    while cursor < xml.len() {
        let Some(open_rel) = xml[cursor..].find('<') else {
            output.push_str(&xml[cursor..]);
            break;
        };
        let open = cursor + open_rel;
        output.push_str(&xml[cursor..open]);
        let Some(close_tag_start_rel) = xml[open..].find('>') else {
            output.push_str(&xml[open..]);
            break;
        };
        let open_end = open + close_tag_start_rel + 1;
        let tag = xml[open + 1..open_end - 1].trim();
        let local_name = tag
            .trim_start_matches('/')
            .split_whitespace()
            .next()
            .unwrap_or("")
            .rsplit(':')
            .next()
            .unwrap_or("");
        if tag.starts_with('/') || !local_name.eq_ignore_ascii_case("href") {
            output.push_str(&xml[open..open_end]);
            cursor = open_end;
            continue;
        }
        let close_tag = format!("</{}>", tag.split_whitespace().next().unwrap_or("href"));
        let Some(value_end_rel) = xml[open_end..].find(&close_tag) else {
            output.push_str(&xml[open..open_end]);
            cursor = open_end;
            continue;
        };
        let value_end = open_end + value_end_rel;
        output.push_str(&xml[open..open_end]);
        output.push_str("[REDACTED_PRINCIPAL]");
        output.push_str(&xml[value_end..value_end + close_tag.len()]);
        cursor = value_end + close_tag.len();
    }
    output
}

fn redact_share_diagnostics(text: &str, account_email: &str, recipient: &str) -> String {
    let mut text = redact_href_values(text);
    for value in [account_email, recipient]
        .into_iter()
        .filter(|value| !value.is_empty())
    {
        text = replace_ascii_case_insensitive(&text, value, "[REDACTED_EMAIL]");
    }
    text
}

fn replace_ascii_case_insensitive(text: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() {
        return text.to_string();
    }
    let lower_text = text.to_ascii_lowercase();
    let lower_needle = needle.to_ascii_lowercase();
    let mut output = String::with_capacity(text.len());
    let mut cursor = 0;
    while let Some(relative) = lower_text[cursor..].find(&lower_needle) {
        let start = cursor + relative;
        let end = start + needle.len();
        output.push_str(&text[cursor..start]);
        output.push_str(replacement);
        cursor = end;
    }
    output.push_str(&text[cursor..]);
    output
}

fn calendar_share_principal_diagnostics(
    email: &str,
    password: &str,
    recipient: Option<&str>,
) -> serde_json::Value {
    let result = (|| -> Result<serde_json::Value> {
        let base = "https://caldav.icloud.com/";
        let client = dav_client()?;
        let mut pacer = RequestPacer::default();
        let probe = "<d:propfind xmlns:d=\"DAV:\"><d:prop><d:current-user-principal/></d:prop></d:propfind>";
        let response = dav(
            &client, &mut pacer, base, email, password, "PROPFIND", "0", probe,
        )?;
        let doc = roxmltree::Document::parse(&response)?;
        let principal_href = doc
            .descendants()
            .find(|node| node.tag_name().name() == "current-user-principal")
            .and_then(|node| {
                node.descendants()
                    .find(|child| child.tag_name().name() == "href")
            })
            .and_then(|node| node.text())
            .ok_or_else(|| anyhow!("DAV response did not include current-user-principal"))?;
        let principal_url = resolve_dav_href(base, principal_href)?;
        let properties = "<d:propfind xmlns:d=\"DAV:\" xmlns:c=\"urn:ietf:params:xml:ns:caldav\"><d:prop><d:principal-URL/><d:alternate-URI-set/><d:displayname/><c:calendar-user-address-set/></d:prop></d:propfind>";
        let response = dav(
            &client,
            &mut pacer,
            &principal_url,
            email,
            password,
            "PROPFIND",
            "0",
            properties,
        )?;
        let doc = roxmltree::Document::parse(&response)?;
        let address_sets = doc
            .descendants()
            .filter(|node| node.tag_name().name() == "calendar-user-address-set")
            .flat_map(|node| {
                node.descendants()
                    .filter(|child| child.tag_name().name() == "href")
                    .filter_map(|child| child.text())
            })
            .collect::<Vec<_>>();
        let recipient_matches_current_user = recipient.is_some_and(|recipient| {
            let target = format!("mailto:{}", recipient.to_ascii_lowercase());
            address_sets
                .iter()
                .any(|address| address.eq_ignore_ascii_case(&target))
        });
        let available_properties = doc
            .descendants()
            .filter(|node| {
                matches!(
                    node.tag_name().name(),
                    "principal-URL"
                        | "alternate-URI-set"
                        | "displayname"
                        | "calendar-user-address-set"
                )
            })
            .map(|node| node.tag_name().name().to_string())
            .collect::<BTreeSet<_>>();
        Ok(serde_json::json!({
            "current_user_principal_found": true,
            "recipient_matches_current_user": recipient_matches_current_user,
            "principal_properties_returned": available_properties
        }))
    })();
    match result {
        Ok(value) => value,
        Err(error) => serde_json::json!({
            "current_user_principal_found": false,
            "error": redact_share_diagnostics(&format!("{error:#}"), email, recipient.unwrap_or("") )
        }),
    }
}

fn calendar_share_debug_failure(format: OutputFormat, message: &str, details: serde_json::Value) {
    response::failure_with_data(
        details,
        message,
        "operation_failed",
        "Inspect the redacted DAV diagnostics. No retry was attempted.",
        &help_target(),
        Some(false),
        format,
        1,
    );
}

fn calendar_share_invites(
    url: &str,
    email: &str,
    password: &str,
) -> Result<Vec<serde_json::Value>> {
    let request = "<d:propfind xmlns:d=\"DAV:\" xmlns:cs=\"http://calendarserver.org/ns/\"><d:prop><cs:invite/></d:prop></d:propfind>";
    let response = dav(
        &dav_client()?,
        &mut RequestPacer::default(),
        url,
        email,
        password,
        "PROPFIND",
        "0",
        request,
    )?;
    let doc = roxmltree::Document::parse(&response)?;
    let Some(invite) = doc.descendants().find(|node| {
        node.tag_name().namespace() == Some("http://calendarserver.org/ns/")
            && node.tag_name().name() == "invite"
    }) else {
        return Ok(Vec::new());
    };
    let mut rows = Vec::new();
    for user in invite
        .children()
        .filter(|node| node.is_element() && node.tag_name().name() == "user")
    {
        let person = user
            .children()
            .find(|node| node.is_element() && node.tag_name().name() == "href")
            .and_then(|node| node.text())
            .unwrap_or("");
        let status = user
            .children()
            .find(|node| {
                node.is_element()
                    && matches!(
                        node.tag_name().name(),
                        "invite-noresponse"
                            | "invite-accepted"
                            | "invite-declined"
                            | "invite-invalid"
                    )
            })
            .map(|node| node.tag_name().name().to_string());
        let privileges = match user
            .descendants()
            .find(|node| {
                node.is_element() && matches!(node.tag_name().name(), "read" | "read-write")
            })
            .map(|node| node.tag_name().name())
        {
            Some("read-write") => vec!["read".to_string(), "write".to_string()],
            Some("read") => vec!["read".to_string()],
            _ => Vec::new(),
        };
        rows.push(serde_json::json!({"principal":person,"privileges":privileges,"status":status}));
    }
    Ok(rows)
}

fn ensure_calendar_share_owner(url: &str, email: &str, password: &str) -> Result<()> {
    let request = "<d:propfind xmlns:d=\"DAV:\" xmlns:cs=\"http://calendarserver.org/ns/\"><d:prop><d:resourcetype/><cs:allowed-sharing-modes/></d:prop></d:propfind>";
    let response = dav(
        &dav_client()?,
        &mut RequestPacer::default(),
        url,
        email,
        password,
        "PROPFIND",
        "0",
        request,
    )?;
    let doc = roxmltree::Document::parse(&response)?;
    let is_shared_copy = doc.descendants().any(|node| {
        node.tag_name().name() == "resourcetype"
            && node
                .children()
                .any(|child| child.is_element() && child.tag_name().name() == "shared")
    });
    let is_owner_copy = doc.descendants().any(|node| {
        node.tag_name().name() == "resourcetype"
            && node
                .children()
                .any(|child| child.is_element() && child.tag_name().name() == "shared-owner")
    });
    let can_be_shared = doc
        .descendants()
        .any(|node| node.tag_name().name() == "can-be-shared");
    if is_shared_copy && !is_owner_copy {
        bail!(
            "This calendar is a shared copy; only its owner can change the share list. No write was sent."
        );
    }
    if !is_owner_copy && !can_be_shared {
        bail!("iCloud did not advertise this calendar as shareable. No write was sent.");
    }
    Ok(())
}

fn run_calendar_share(action: CalendarShareCommand, format: OutputFormat) -> Result<()> {
    match action {
        CalendarShareCommand::List(args) => {
            let a = account(args.email)?;
            let p = secret(&a)?;
            let url = calendar_url(&a.email, &p, &args.calendar)?;
            let rows = match calendar_share_invites(&url, &a.email, &p) {
                Ok(rows) => rows,
                Err(error) if args.debug => {
                    let principal = calendar_share_principal_diagnostics(&a.email, &p, None);
                    let capabilities = calendar_share_capability_diagnostics(&url, &a.email, &p);
                    calendar_share_debug_failure(
                        format,
                        &format!("Could not read CalendarServer share invitations: {error:#}"),
                        serde_json::json!({"diagnostics":{"principal":principal,"capabilities":capabilities}}),
                    );
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            if args.debug {
                let principal = calendar_share_principal_diagnostics(&a.email, &p, None);
                let capabilities = calendar_share_capability_diagnostics(&url, &a.email, &p);
                let redacted_grants = rows
                    .iter()
                    .map(|row| {
                        serde_json::json!({
                            "principal": "[REDACTED_PRINCIPAL]",
                            "privileges": row["privileges"]
                        })
                    })
                    .collect::<Vec<_>>();
                output(
                    &serde_json::json!({
                        "grants": redacted_grants,
                        "diagnostics": {
                            "sharee_count": rows.len(),
                            "principal": principal,
                        "capabilities": capabilities
                        }
                    }),
                    format,
                    "Calendar access and DAV diagnostics",
                )
            } else {
                output(&rows, format, "Calendar access grants")
            }
        }
        CalendarShareCommand::Grant(args) => update_calendar_share(args, false, format),
        CalendarShareCommand::Revoke(args) => update_calendar_share(args, true, format),
    }
}

fn update_calendar_share(
    args: CalendarShareGrantArgs,
    revoke: bool,
    format: OutputFormat,
) -> Result<()> {
    if !is_simple_email(&args.person) {
        bail!("Share recipient must be a valid email address");
    }
    let a = account(args.email)?;
    let p = secret(&a)?;
    let url = calendar_url(&a.email, &p, &args.calendar)?;
    ensure_calendar_share_owner(&url, &a.email, &p)?;
    let person = format!("mailto:{}", args.person.to_ascii_lowercase());
    let xml = if revoke {
        format!(
            "<cs:share xmlns:d=\"DAV:\" xmlns:cs=\"http://calendarserver.org/ns/\"><cs:remove><d:href>{}</d:href></cs:remove></cs:share>",
            xml_escape(&person)
        )
    } else {
        let access = if args.permission == "write" {
            "read-write"
        } else {
            "read"
        };
        format!(
            "<cs:share xmlns:d=\"DAV:\" xmlns:cs=\"http://calendarserver.org/ns/\"><cs:set><d:href>{}</d:href><cs:common-name>{}</cs:common-name><cs:{access}/></cs:set></cs:share>",
            xml_escape(&person),
            xml_escape(&args.person)
        )
    };
    let exchange = dav_write_exchange(
        &dav_client()?,
        &mut RequestPacer::default(),
        &url,
        &a.email,
        &p,
        "POST",
        Some("application/xml; charset=utf-8"),
        &xml,
        None,
        None,
    );
    let exchange = match exchange {
        Ok(exchange) => exchange,
        Err(error) if args.debug => {
            calendar_share_debug_failure(
                format,
                "CalendarServer share request failed before a response was received",
                serde_json::json!({
                    "calendar":args.calendar,
                    "write_sent":false,
                    "diagnostics":{
                        "method":"POST",
                        "request_xml":redact_share_diagnostics(&xml,&a.email,&args.person),
                        "transport_error":redact_share_diagnostics(&format!("{error:#}"),&a.email,&args.person),
                        "resource":calendar_share_resource_diagnostics(&url,&a.email,&p)
                    }
                }),
            );
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let headers = exchange
        .headers
        .iter()
        .map(|(name, value)| {
            (
                name.clone(),
                serde_json::Value::String(redact_share_diagnostics(
                    value.as_str().unwrap_or_default(),
                    &a.email,
                    &args.person,
                )),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let diagnostics = serde_json::json!({
        "method":"POST",
        "status":exchange.status.as_u16(),
        "headers":headers,
        "body":redact_share_diagnostics(&exchange.body.chars().take(2000).collect::<String>(),&a.email,&args.person),
        "request_xml":redact_share_diagnostics(&xml,&a.email,&args.person),
        "readback":calendar_share_resource_diagnostics(&url,&a.email,&p)
    });
    if !exchange.status.is_success() {
        let message = format!("CalendarServer share request returned {}", exchange.status);
        if args.debug {
            calendar_share_debug_failure(
                format,
                &message,
                serde_json::json!({"calendar":args.calendar,"write_sent":true,"diagnostics":diagnostics}),
            );
            return Ok(());
        }
        bail!(
            "{message}: {}",
            diagnostics["body"].as_str().unwrap_or_default()
        );
    }
    let readback_rows = calendar_share_invites(&url, &a.email, &p)?;
    let readback_sharee = readback_rows.iter().find(|row| {
        row["principal"]
            .as_str()
            .is_some_and(|value| value.eq_ignore_ascii_case(&person))
    });
    let verified = if revoke {
        readback_sharee.is_none()
    } else {
        readback_sharee.is_some()
    };
    if !verified {
        bail!(
            "iCloud accepted the CalendarServer share request, but the invitation readback did not confirm the requested state. Use --debug to inspect redacted diagnostics."
        );
    }
    let invitation_status = readback_sharee.and_then(|row| row["status"].as_str());
    let debug_details = if args.debug { Some(diagnostics) } else { None };
    output(
        &serde_json::json!({"calendar":args.calendar,"person":args.person,"permission":args.permission,"revoked":revoke,"verified":verified,"invitation_status":invitation_status,"debug":debug_details}),
        format,
        if revoke {
            "Revoked calendar access"
        } else {
            "Granted calendar access"
        },
    )
}

fn run_calendar_delete(selector: &str, email: Option<String>) -> Result<()> {
    let account = account(email)?;
    let password = secret(&account)?;
    let url = calendar_url(&account.email, &password, selector)?;
    let client = dav_client()?;
    dav_write(
        &client,
        &mut RequestPacer::default(),
        &url,
        &account.email,
        &password,
        "DELETE",
        None,
        "",
        None,
        None,
    )?;
    response::selected(
        &serde_json::json!({"id":calendar_path_ids(&url).1,"href":url,"deleted":true,"email":account.email}),
        "Deleted calendar",
    )?;
    Ok(())
}

fn run_event_list(
    from: &str,
    to: &str,
    calendar: Option<&str>,
    email: Option<String>,
    include: &[String],
    output_format: OutputFormat,
    concurrency: usize,
) -> Result<()> {
    let start = date_bound(from, false)?;
    let end = date_bound(to, true)?;
    if start >= end {
        bail!("The end date must be after the start date")
    }
    let account = account(email)?;
    let password = secret(&account)?;
    let values = dav_items_with_concurrency(
        "https://caldav.icloud.com/",
        &account.email,
        &password,
        "event",
        Some((start, end)),
        calendar,
        concurrency,
    )?;
    output_events(
        values,
        output_format,
        include,
        Some("Check the UTC date range or omit --calendar to search all calendars."),
    )
}

fn run_event_search(args: CalendarEventsSearchArgs, output_format: OutputFormat) -> Result<()> {
    let query = validate_search_query(&args.query)?;
    let fields = if args.fields.is_empty() {
        vec!["summary".into(), "description".into(), "location".into()]
    } else {
        args.fields
    };
    let range = match (args.from.as_deref(), args.to.as_deref()) {
        (Some(from), Some(to)) => {
            let start = date_bound(from, false)?;
            let end = date_bound(to, true)?;
            if start >= end {
                bail!("The end date must be after the start date")
            }
            Some((start, end))
        }
        (None, None) => None,
        _ => bail!("Provide both --from and --to, or omit both"),
    };
    let account = account(args.email)?;
    let password = secret(&account)?;
    let mut values = dav_items_with_search(
        "https://caldav.icloud.com/",
        &account.email,
        &password,
        "event",
        range,
        args.calendar.as_deref(),
        args.concurrency,
        Some(DavSearch::Calendar {
            query: query.clone(),
            fields: fields.clone(),
        }),
    )?;
    values.retain(|value| calendar_event_matches(value, &query, &fields));
    let values = dav_page_items(values, args.skip, args.limit);
    let mut include = args.include;
    for field in fields {
        if !include
            .iter()
            .any(|requested| requested.eq_ignore_ascii_case(&field))
        {
            include.push(field);
        }
    }
    output_events(
        values,
        output_format,
        &include,
        Some(if args.limit == 0 {
            "Set --limit above 0 to return results."
        } else if args.skip > 0 {
            "No results at this offset. Use a smaller --skip or start again with --skip 0."
        } else {
            "Try a broader query, different --field values, date range, or calendar."
        }),
    )
}

#[derive(Clone)]
enum DavSearch {
    Calendar { query: String, fields: Vec<String> },
    Contacts { query: String, fields: Vec<String> },
}

fn validate_search_query(query: &str) -> Result<String> {
    if query.chars().any(char::is_control) {
        bail!("Invalid search query: control characters are not allowed")
    }
    if query
        .chars()
        .any(|ch| matches!(ch, '\u{fffe}' | '\u{ffff}'))
    {
        bail!("Invalid search query: contains characters XML cannot represent")
    }
    let query = query.trim();
    if query.is_empty() {
        bail!("Invalid search query: cannot be empty or whitespace")
    }
    if query.chars().count() > 256 {
        bail!("Invalid search query: cannot exceed 256 characters")
    }
    Ok(query.to_string())
}

fn contact_field_property(field: &str) -> &'static str {
    match field {
        "name" => "FN",
        "email" => "EMAIL",
        "phone" => "TEL",
        "organization" => "ORG",
        _ => unreachable!("field values are validated by clap"),
    }
}

fn carddav_search_body(query: &str, fields: &[String]) -> String {
    let filters = fields
        .iter()
        .map(|field| {
            format!(
                "<card:prop-filter name=\"{}\"><card:text-match collation=\"i;unicode-casemap\" match-type=\"contains\">{}</card:text-match></card:prop-filter>",
                contact_field_property(field),
                xml_escape(query)
            )
        })
        .collect::<String>();
    format!(
        "<card:addressbook-query xmlns:d=\"DAV:\" xmlns:card=\"urn:ietf:params:xml:ns:carddav\"><d:prop><card:address-data/></d:prop><card:filter test=\"anyof\">{filters}</card:filter></card:addressbook-query>"
    )
}

fn carddav_all_body() -> &'static str {
    "<card:addressbook-query xmlns:d=\"DAV:\" xmlns:card=\"urn:ietf:params:xml:ns:carddav\"><d:prop><card:address-data/></d:prop></card:addressbook-query>"
}

fn contact_matches_query(contact: &Contact, query: &str, fields: &[String]) -> bool {
    let needle = unicode_casemap(query);
    fields.iter().any(|field| {
        let property = contact_field_property(field);
        contact
            .all_properties
            .iter()
            .filter(|(name, _)| {
                name.rsplit('.')
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case(property))
            })
            .flat_map(|(_, values)| values)
            .filter_map(|value| value.get("value").and_then(serde_json::Value::as_str))
            .any(|value| unicode_casemap(&unescape_ical_text(value)).contains(&needle))
    })
}

fn unicode_casemap(value: &str) -> String {
    // RFC 5051 uses UnicodeData's simple titlecase mapping, followed by
    // compatibility decomposition. Multi-character SpecialCasing expansions
    // are not simple mappings and must leave the original character intact.
    let mut result = String::with_capacity(value.len());
    for ch in value.chars() {
        let mapped = match unicode_case_mapping::to_titlecase(ch) {
            [first, 0, 0] if first != 0 => char::from_u32(first).unwrap_or(ch),
            _ => ch,
        };
        unicode_normalization::char::decompose_compatible(mapped, |ch| result.push(ch));
    }
    result
}

fn calendar_event_matches(value: &serde_json::Value, query: &str, fields: &[String]) -> bool {
    let needle = query.to_ascii_lowercase();
    fields.iter().any(|field| {
        value.get(field).is_some_and(|field_value| {
            let mut values = Vec::new();
            flatten_search_values(field_value, &mut values);
            values.into_iter().any(|value| {
                // Standard text fields are decoded by parse_ical_events;
                // CATEGORIES retains its serialized iCalendar text value.
                let value = if field == "categories" {
                    unescape_ical_text(value)
                } else {
                    value.to_string()
                };
                value.to_ascii_lowercase().contains(&needle)
            })
        })
    })
}

fn flatten_search_values<'a>(value: &'a serde_json::Value, output: &mut Vec<&'a str>) {
    match value {
        serde_json::Value::String(value) => output.push(value),
        serde_json::Value::Array(values) => {
            for value in values {
                flatten_search_values(value, output);
            }
        }
        _ => {}
    }
}

// DAV discovery is kept small and standards-based. The service may redirect to an account-specific iCloud host.
fn dav_items(
    base: &str,
    email: &str,
    password: &str,
    kind: &str,
    range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    calendar_filter: Option<&str>,
) -> Result<Vec<serde_json::Value>> {
    dav_items_with_concurrency(base, email, password, kind, range, calendar_filter, 1)
}

fn dav_items_with_concurrency(
    base: &str,
    email: &str,
    password: &str,
    kind: &str,
    range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    calendar_filter: Option<&str>,
    concurrency: usize,
) -> Result<Vec<serde_json::Value>> {
    dav_items_with_search(
        base,
        email,
        password,
        kind,
        range,
        calendar_filter,
        concurrency,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn dav_items_with_search(
    base: &str,
    email: &str,
    password: &str,
    kind: &str,
    range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    calendar_filter: Option<&str>,
    concurrency: usize,
    search: Option<DavSearch>,
) -> Result<Vec<serde_json::Value>> {
    let client = dav_client()?;
    let mut pacer = RequestPacer::default();
    let principal_probe = "<?xml version=\"1.0\"?><d:propfind xmlns:d=\"DAV:\"><d:prop><d:current-user-principal/></d:prop></d:propfind>";
    let response = dav(
        &client,
        &mut pacer,
        base,
        email,
        password,
        "PROPFIND",
        "0",
        principal_probe,
    )?;
    let doc = roxmltree::Document::parse(&response)?;
    let principal = doc
        .descendants()
        .find(|n| n.tag_name().name() == "current-user-principal")
        .and_then(|n| n.descendants().find(|x| x.tag_name().name() == "href"))
        .and_then(|n| n.text())
        .ok_or_else(|| anyhow!("DAV response did not include current-user-principal"))?;
    let principal_url = resolve_dav_href(base, principal)?;

    let (home_property, home_probe) = if kind == "contact" {
        (
            "addressbook-home-set",
            "<?xml version=\"1.0\"?><d:propfind xmlns:d=\"DAV:\" xmlns:card=\"urn:ietf:params:xml:ns:carddav\"><d:prop><card:addressbook-home-set/></d:prop></d:propfind>",
        )
    } else {
        (
            "calendar-home-set",
            "<?xml version=\"1.0\"?><d:propfind xmlns:d=\"DAV:\" xmlns:c=\"urn:ietf:params:xml:ns:caldav\"><d:prop><c:calendar-home-set/></d:prop></d:propfind>",
        )
    };
    let response = dav(
        &client,
        &mut pacer,
        &principal_url,
        email,
        password,
        "PROPFIND",
        "0",
        home_probe,
    )?;
    let doc = roxmltree::Document::parse(&response)?;
    let home = doc
        .descendants()
        .find(|n| n.tag_name().name() == home_property)
        .and_then(|n| n.descendants().find(|x| x.tag_name().name() == "href"))
        .and_then(|n| n.text())
        .ok_or_else(|| anyhow!("DAV response did not include {home_property}"))?;
    let home_url = resolve_dav_href(&principal_url, home)?;
    let listing = if kind == "calendar" {
        "<d:propfind xmlns:d=\"DAV:\" xmlns:c=\"urn:ietf:params:xml:ns:caldav\" xmlns:card=\"urn:ietf:params:xml:ns:carddav\" xmlns:a=\"http://apple.com/ns/ical/\"><d:prop><d:resourcetype/><d:displayname/><a:calendar-color/></d:prop></d:propfind>"
    } else {
        "<d:propfind xmlns:d=\"DAV:\" xmlns:c=\"urn:ietf:params:xml:ns:caldav\" xmlns:card=\"urn:ietf:params:xml:ns:carddav\"><d:prop><d:resourcetype/><d:displayname/></d:prop></d:propfind>"
    };
    let response = dav(
        &client, &mut pacer, &home_url, email, password, "PROPFIND", "1", listing,
    )?;
    let doc = roxmltree::Document::parse(&response)?;
    let mut collections = Vec::new();
    for resp in doc
        .descendants()
        .filter(|n| n.tag_name().name() == "response")
    {
        let href = resp
            .descendants()
            .find(|n| n.tag_name().name() == "href")
            .and_then(|n| n.text())
            .unwrap_or("");
        let is = resp.descendants().any(|n| {
            n.tag_name().name()
                == if kind == "contact" {
                    "addressbook"
                } else {
                    "calendar"
                }
        });
        if is && !href.is_empty() {
            let name = resp
                .descendants()
                .find(|n| n.tag_name().name() == "displayname")
                .and_then(|n| n.text())
                .unwrap_or("")
                .to_string();
            collections.push((resolve_dav_href(&home_url, href)?, name, href.to_string()));
        }
    }
    if kind == "calendar" {
        let mut items = Vec::new();
        for resp in doc
            .descendants()
            .filter(|n| n.tag_name().name() == "response")
        {
            let href = resp
                .descendants()
                .find(|n| n.tag_name().name() == "href")
                .and_then(|n| n.text())
                .unwrap_or("");
            let is = resp
                .descendants()
                .any(|n| n.tag_name().name() == "calendar");
            if is {
                let name = resp
                    .descendants()
                    .find(|n| n.tag_name().name() == "displayname")
                    .and_then(|n| n.text())
                    .unwrap_or("");
                let full_href = resolve_dav_href(&home_url, href)?;
                let (dsid, id) = calendar_path_ids(&full_href);
                let mut item = serde_json::json!({
                    "name": name,
                    "id": id,
                    "href": full_href,
                    "dsid": dsid
                });
                if let Some(raw_color) = resp
                    .descendants()
                    .find(|node| node.tag_name().name() == "calendar-color")
                    .and_then(|node| node.text())
                {
                    match normalize_calendar_color(raw_color) {
                        Ok(color) => item["color"] = serde_json::Value::String(color),
                        Err(_) => response::warning(format!(
                            "Calendar '{}' returned an invalid calendar-color; its color was omitted.",
                            name
                        )),
                    }
                }
                items.push(item);
            }
        }
        return Ok(items);
    }
    let mut out = Vec::new();
    let collections = if let Some(filter) = calendar_filter {
        let calendars = collections
            .iter()
            .map(|(url, name, _)| {
                serde_json::json!({"name": name, "href": url, "id": calendar_path_ids(url).1})
            })
            .collect::<Vec<_>>();
        let selected = select_calendar_url(&calendars, filter)?;
        collections
            .into_iter()
            .filter(|(url, _, _)| url == &selected)
            .collect()
    } else {
        collections
    };
    if kind == "event" {
        if let Some(DavSearch::Calendar { query, fields }) = search.as_ref() {
            return dav_event_search_collections(
                &client,
                &collections,
                email,
                password,
                range,
                query,
                fields,
                concurrency,
            );
        }
        return dav_event_collections(
            &client,
            &collections,
            email,
            password,
            range.ok_or_else(|| anyhow!("Event listing requires a date range"))?,
            concurrency,
        );
    }
    for (collection, _calendar_name, _calendar_id) in collections {
        let body = if kind == "event" {
            let (from, to) = range.unwrap();
            format!(
                "<c:calendar-query xmlns:d=\"DAV:\" xmlns:c=\"urn:ietf:params:xml:ns:caldav\"><d:prop><c:calendar-data/></d:prop><c:filter><c:comp-filter name=\"VCALENDAR\"><c:comp-filter name=\"VEVENT\"><c:time-range start=\"{}\" end=\"{}\"/></c:comp-filter></c:comp-filter></c:filter></c:calendar-query>",
                from.format("%Y%m%dT%H%M%SZ"),
                to.format("%Y%m%dT%H%M%SZ")
            )
        } else if kind == "contact" {
            match search.as_ref() {
                Some(DavSearch::Contacts { query, fields }) => carddav_search_body(query, fields),
                _ => carddav_all_body().to_string(),
            }
        } else {
            continue;
        };
        let method = if kind == "calendar" {
            "PROPFIND"
        } else {
            "REPORT"
        };
        let depth = "1";
        let response = match dav(
            &client,
            &mut pacer,
            &collection,
            email,
            password,
            method,
            depth,
            &body,
        ) {
            Ok(response) => response,
            Err(error)
                if kind == "contact"
                    && matches!(search.as_ref(), Some(DavSearch::Contacts { .. }))
                    && is_filter_query_rejection(&error) =>
            {
                dav(
                    &client,
                    &mut pacer,
                    &collection,
                    email,
                    password,
                    "REPORT",
                    depth,
                    carddav_all_body(),
                )?
            }
            Err(error) => return Err(error),
        };
        let doc = roxmltree::Document::parse(&response)?;
        for node in doc.descendants().filter(|n| {
            n.tag_name().name()
                == if kind == "contact" {
                    "address-data"
                } else {
                    "calendar-data"
                }
        }) {
            if let Some(data) = node.text() {
                if kind == "event" {
                    for event in parse_ical_events(data) {
                        out.push(serde_json::to_value(event)?);
                    }
                } else if kind == "contact" {
                    for contact in parse_vcards(data) {
                        out.push(serde_json::to_value(contact)?);
                    }
                }
            }
        }
    }
    Ok(out)
}

fn calendar_search_property(field: &str) -> &'static str {
    match field {
        "summary" => "SUMMARY",
        "description" => "DESCRIPTION",
        "location" => "LOCATION",
        "attendee" => "ATTENDEE",
        "organizer" => "ORGANIZER",
        "categories" => "CATEGORIES",
        _ => unreachable!("field values are validated by clap"),
    }
}

fn calendar_search_body(
    query: &str,
    field: &str,
    range: Option<(DateTime<Utc>, DateTime<Utc>)>,
) -> String {
    let time_range = range
        .map(|(from, to)| {
            format!(
                "<c:time-range start=\"{}\" end=\"{}\"/>",
                from.format("%Y%m%dT%H%M%SZ"),
                to.format("%Y%m%dT%H%M%SZ")
            )
        })
        .unwrap_or_default();
    let text_match = format!(
        "<c:prop-filter name=\"{}\"><c:text-match>{}</c:text-match></c:prop-filter>",
        calendar_search_property(field),
        xml_escape(query)
    );
    format!(
        "<c:calendar-query xmlns:d=\"DAV:\" xmlns:c=\"urn:ietf:params:xml:ns:caldav\"><d:prop><c:calendar-data/></d:prop><c:filter><c:comp-filter name=\"VCALENDAR\"><c:comp-filter name=\"VEVENT\">{time_range}{text_match}</c:comp-filter></c:comp-filter></c:filter></c:calendar-query>"
    )
}

fn calendar_all_body(range: Option<(DateTime<Utc>, DateTime<Utc>)>) -> String {
    let time_range = range
        .map(|(from, to)| {
            format!(
                "<c:time-range start=\"{}\" end=\"{}\"/>",
                from.format("%Y%m%dT%H%M%SZ"),
                to.format("%Y%m%dT%H%M%SZ")
            )
        })
        .unwrap_or_default();
    format!(
        "<c:calendar-query xmlns:d=\"DAV:\" xmlns:c=\"urn:ietf:params:xml:ns:caldav\"><d:prop><c:calendar-data/></d:prop><c:filter><c:comp-filter name=\"VCALENDAR\"><c:comp-filter name=\"VEVENT\">{time_range}</c:comp-filter></c:comp-filter></c:filter></c:calendar-query>"
    )
}

#[allow(clippy::too_many_arguments)]
fn dav_event_search_collections(
    client: &reqwest::blocking::Client,
    collections: &[(String, String, String)],
    email: &str,
    password: &str,
    range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    query: &str,
    fields: &[String],
    concurrency: usize,
) -> Result<Vec<serde_json::Value>> {
    let worker_count = concurrency.min(collections.len()).max(1);
    let mut buckets = (0..worker_count).map(|_| Vec::new()).collect::<Vec<_>>();
    for (index, collection) in collections.iter().cloned().enumerate() {
        buckets[index % worker_count].push((index, collection));
    }
    let mut outcomes = thread::scope(|scope| -> Result<Vec<_>> {
        let handles = buckets
            .into_iter()
            .map(|bucket| {
                let client = client.clone();
                let email = email.to_string();
                let password = password.to_string();
                let query = query.to_string();
                let fields = fields.to_vec();
                scope.spawn(move || {
                    bucket
                        .into_iter()
                        .map(|(index, (collection, _, _))| {
                            let result = search_calendar_collection(
                                &client,
                                &collection,
                                &email,
                                &password,
                                range,
                                &query,
                                &fields,
                            );
                            (index, result)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        let mut outcomes = Vec::new();
        for handle in handles {
            outcomes.extend(
                handle
                    .join()
                    .map_err(|_| anyhow!("A CalDAV event-search worker exited unexpectedly"))?,
            );
        }
        Ok(outcomes)
    })?;
    outcomes.sort_by_key(|(index, _)| *index);
    let mut results = BTreeMap::<String, String>::new();
    for (_, result) in outcomes {
        results.extend(result?);
    }
    let mut events = Vec::new();
    for data in results.into_values() {
        for event in parse_ical_events(&data) {
            let value = serde_json::to_value(event)?;
            if calendar_event_matches(&value, query, fields) {
                events.push(value);
            }
        }
    }
    Ok(events)
}

fn search_calendar_collection(
    client: &reqwest::blocking::Client,
    collection: &str,
    email: &str,
    password: &str,
    range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    query: &str,
    fields: &[String],
) -> Result<BTreeMap<String, String>> {
    let mut pacer = RequestPacer::default();
    let mut results = BTreeMap::new();
    let mut fallback = false;
    for field in fields {
        let body = calendar_search_body(query, field, range);
        let response = match dav(
            client, &mut pacer, collection, email, password, "REPORT", "1", &body,
        ) {
            Ok(response) => response,
            Err(error) if is_filter_query_rejection(&error) => {
                fallback = true;
                break;
            }
            Err(error) => return Err(error),
        };
        collect_calendar_data(collection, &response, &mut results)?;
    }
    if fallback {
        let response = dav(
            client,
            &mut pacer,
            collection,
            email,
            password,
            "REPORT",
            "1",
            &calendar_all_body(range),
        )?;
        collect_calendar_data(collection, &response, &mut results)?;
    }
    Ok(results)
}

fn collect_calendar_data(
    collection: &str,
    response: &str,
    results: &mut BTreeMap<String, String>,
) -> Result<()> {
    let doc = roxmltree::Document::parse(response)?;
    for item in doc
        .descendants()
        .filter(|node| node.tag_name().name() == "response")
    {
        let href = item
            .descendants()
            .find(|child| child.tag_name().name() == "href")
            .and_then(|child| child.text());
        let data = item
            .descendants()
            .find(|child| child.tag_name().name() == "calendar-data")
            .and_then(|child| child.text());
        if let (Some(href), Some(data)) = (href, data) {
            let url = resolve_dav_href(collection, href)?;
            results.insert(url, data.to_string());
        }
    }
    Ok(())
}

fn dav_event_collections(
    client: &reqwest::blocking::Client,
    collections: &[(String, String, String)],
    email: &str,
    password: &str,
    range: (DateTime<Utc>, DateTime<Utc>),
    concurrency: usize,
) -> Result<Vec<serde_json::Value>> {
    let (from, to) = range;
    let body = format!(
        "<c:calendar-query xmlns:d=\"DAV:\" xmlns:c=\"urn:ietf:params:xml:ns:caldav\"><d:prop><c:calendar-data/></d:prop><c:filter><c:comp-filter name=\"VCALENDAR\"><c:comp-filter name=\"VEVENT\"><c:time-range start=\"{}\" end=\"{}\"/></c:comp-filter></c:comp-filter></c:filter></c:calendar-query>",
        from.format("%Y%m%dT%H%M%SZ"),
        to.format("%Y%m%dT%H%M%SZ")
    );
    let worker_count = concurrency.min(collections.len()).max(1);
    let mut buckets = (0..worker_count).map(|_| Vec::new()).collect::<Vec<_>>();
    for (index, collection) in collections.iter().cloned().enumerate() {
        buckets[index % worker_count].push((index, collection));
    }

    let mut outcomes = thread::scope(|scope| -> Result<Vec<_>> {
        let handles = buckets
            .into_iter()
            .map(|bucket| {
                let client = client.clone();
                let email = email.to_string();
                let password = password.to_string();
                let body = body.clone();
                scope.spawn(move || {
                    let mut pacer = RequestPacer::default();
                    bucket
                        .into_iter()
                        .map(|(index, (collection, _, _))| {
                            let result = (|| -> Result<Vec<serde_json::Value>> {
                                let response = dav(
                                    &client,
                                    &mut pacer,
                                    &collection,
                                    &email,
                                    &password,
                                    "REPORT",
                                    "1",
                                    &body,
                                )?;
                                let doc = roxmltree::Document::parse(&response)?;
                                let mut events = Vec::new();
                                for node in doc
                                    .descendants()
                                    .filter(|node| node.tag_name().name() == "calendar-data")
                                {
                                    if let Some(data) = node.text() {
                                        for event in parse_ical_events(data) {
                                            events.push(serde_json::to_value(event)?);
                                        }
                                    }
                                }
                                Ok(events)
                            })();
                            (index, result)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        let mut outcomes = Vec::new();
        for handle in handles {
            outcomes.extend(
                handle
                    .join()
                    .map_err(|_| anyhow!("A CalDAV event-list worker exited unexpectedly"))?,
            );
        }
        Ok(outcomes)
    })?;
    outcomes.sort_by_key(|(index, _)| *index);
    let mut events = Vec::new();
    for (_, result) in outcomes {
        events.extend(result?);
    }
    Ok(events)
}

fn discover_contact_addressbooks(email: &str, password: &str) -> Result<Vec<serde_json::Value>> {
    let client = dav_client()?;
    let mut pacer = RequestPacer::default();
    let base = "https://contacts.icloud.com/";
    let principal_probe =
        "<d:propfind xmlns:d=\"DAV:\"><d:prop><d:current-user-principal/></d:prop></d:propfind>";
    let response = dav(
        &client,
        &mut pacer,
        base,
        email,
        password,
        "PROPFIND",
        "0",
        principal_probe,
    )?;
    let doc = roxmltree::Document::parse(&response)?;
    let principal = doc
        .descendants()
        .find(|node| node.tag_name().name() == "current-user-principal")
        .and_then(|node| {
            node.descendants()
                .find(|child| child.tag_name().name() == "href")
        })
        .and_then(|node| node.text())
        .ok_or_else(|| anyhow!("CardDAV response did not include current-user-principal"))?;
    let principal_url = resolve_dav_href(base, principal)?;
    let home_probe = "<d:propfind xmlns:d=\"DAV:\" xmlns:card=\"urn:ietf:params:xml:ns:carddav\"><d:prop><card:addressbook-home-set/></d:prop></d:propfind>";
    let response = dav(
        &client,
        &mut pacer,
        &principal_url,
        email,
        password,
        "PROPFIND",
        "0",
        home_probe,
    )?;
    let doc = roxmltree::Document::parse(&response)?;
    let home = doc
        .descendants()
        .find(|node| node.tag_name().name() == "addressbook-home-set")
        .and_then(|node| {
            node.descendants()
                .find(|child| child.tag_name().name() == "href")
        })
        .and_then(|node| node.text())
        .ok_or_else(|| anyhow!("CardDAV response did not include addressbook-home-set"))?;
    let home_url = resolve_dav_href(&principal_url, home)?;
    let listing = "<d:propfind xmlns:d=\"DAV:\" xmlns:card=\"urn:ietf:params:xml:ns:carddav\"><d:prop><d:resourcetype/><d:displayname/></d:prop></d:propfind>";
    let response = dav(
        &client, &mut pacer, &home_url, email, password, "PROPFIND", "1", listing,
    )?;
    let doc = roxmltree::Document::parse(&response)?;
    let mut addressbooks = Vec::new();
    for response in doc
        .descendants()
        .filter(|node| node.tag_name().name() == "response")
    {
        if !response
            .descendants()
            .any(|node| node.tag_name().name() == "addressbook")
        {
            continue;
        }
        let href = response
            .descendants()
            .find(|node| node.tag_name().name() == "href")
            .and_then(|node| node.text())
            .unwrap_or("");
        if href.is_empty() {
            continue;
        }
        let name = response
            .descendants()
            .find(|node| node.tag_name().name() == "displayname")
            .and_then(|node| node.text())
            .unwrap_or("");
        addressbooks.push(serde_json::json!({
            "name": name,
            "href": resolve_dav_href(&home_url, href)?
        }));
    }
    Ok(addressbooks)
}

fn parse_ical_events(data: &str) -> Vec<Event> {
    IcalParser::new(BufReader::new(data.as_bytes()))
        .flatten()
        .flat_map(|calendar| calendar.events)
        .map(|event| {
            let mut other_values: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
            let mut other_params: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
            for property in &event.properties {
                let key = property.name.to_ascii_lowercase().replace('-', "_");
                if !matches!(
                    property.name.as_str(),
                    "SUMMARY" | "DTSTART" | "DTEND" | "LOCATION" | "DESCRIPTION" | "UID"
                ) {
                    other_values
                        .entry(key.clone())
                        .or_default()
                        .push(serde_json::Value::String(
                            property.value.clone().unwrap_or_default(),
                        ));
                }
                if let Some(params) = &property.params {
                    let values = params
                        .iter()
                        .map(|(name, values)| {
                            let value = if values.len() == 1 {
                                serde_json::Value::String(values[0].clone())
                            } else {
                                serde_json::Value::Array(
                                    values
                                        .iter()
                                        .cloned()
                                        .map(serde_json::Value::String)
                                        .collect(),
                                )
                            };
                            (name.to_ascii_lowercase(), value)
                        })
                        .collect::<serde_json::Map<_, _>>();
                    other_params
                        .entry(format!("{key}_params"))
                        .or_default()
                        .push(serde_json::Value::Object(values));
                }
            }
            let pack_values = |values: Vec<serde_json::Value>| {
                if values.len() == 1 {
                    values.into_iter().next().unwrap_or(serde_json::Value::Null)
                } else {
                    serde_json::Value::Array(values)
                }
            };
            let mut other_properties = other_values
                .into_iter()
                .map(|(key, values)| (key, pack_values(values)))
                .collect::<BTreeMap<_, _>>();
            other_properties.extend(
                other_params
                    .into_iter()
                    .map(|(key, values)| (key, pack_values(values))),
            );
            let val = |name: &str| {
                event
                    .properties
                    .iter()
                    .find(|property| {
                        property
                            .name
                            .rsplit('.')
                            .next()
                            .is_some_and(|base| base.eq_ignore_ascii_case(name))
                    })
                    .and_then(|property| property.value.clone())
                    .unwrap_or_default()
            };
            let alarms = event
                .alarms
                .iter()
                .map(|alarm| {
                    alarm
                        .properties
                        .iter()
                        .filter_map(|property| {
                            property.value.as_ref().map(|value| {
                                (
                                    property.name.to_ascii_lowercase().replace('-', "_"),
                                    serde_json::json!({"value":value,"params":property.params}),
                                )
                            })
                        })
                        .collect::<BTreeMap<_, _>>()
                })
                .collect();
            Event {
                summary: unescape_ical_text(&val("SUMMARY")),
                start: val("DTSTART"),
                end: val("DTEND"),
                location: unescape_ical_text(&val("LOCATION")),
                description: unescape_ical_text(&val("DESCRIPTION")),
                uid: val("UID"),
                alarms,
                other_properties,
            }
        })
        .collect()
}

fn unescape_ical_text(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n' | 'N') => result.push('\n'),
                Some(escaped) => result.push(escaped),
                None => result.push('\\'),
            }
        } else {
            result.push(ch);
        }
    }
    result
}

fn parse_vcards(data: &str) -> Vec<Contact> {
    VcardParser::new(BufReader::new(data.as_bytes()))
        .flatten()
        .map(|card| {
            let val = |name: &str| {
                card.properties
                    .iter()
                    .find(|property| {
                        property
                            .name
                            .rsplit('.')
                            .next()
                            .is_some_and(|base| base.eq_ignore_ascii_case(name))
                    })
                    .and_then(|property| property.value.clone())
                    .unwrap_or_default()
            };
            let emails = card
                .properties
                .iter()
                .filter(|property| {
                    property
                        .name
                        .rsplit('.')
                        .next()
                        .is_some_and(|base| base.eq_ignore_ascii_case("EMAIL"))
                })
                .filter_map(|property| property.value.clone())
                .collect();
            let phones = card
                .properties
                .iter()
                .filter(|property| {
                    property
                        .name
                        .rsplit('.')
                        .next()
                        .is_some_and(|base| base.eq_ignore_ascii_case("TEL"))
                })
                .filter_map(|property| property.value.clone())
                .collect();
            let mut all_properties = BTreeMap::<String, Vec<serde_json::Value>>::new();
            for property in &card.properties {
                let mut params = BTreeMap::<String, Vec<String>>::new();
                for (name, values) in property.params.clone().unwrap_or_default() {
                    params
                        .entry(name.to_ascii_uppercase())
                        .or_default()
                        .extend(values);
                }
                all_properties
                    .entry(property.name.to_ascii_uppercase())
                    .or_default()
                    .push(serde_json::json!({
                        "value": property.value,
                        "params": params
                    }));
            }
            Contact {
                uid: val("UID"),
                name: val("FN"),
                emails,
                phones,
                birthday: val("BDAY"),
                all_properties,
            }
        })
        .collect()
}
const DAV_RETRIES: u32 = 4;
const EVENT_IMPORT_RETRIES: u32 = 2;
const DAV_RETRY_AFTER_LIMIT: Duration = Duration::from_secs(300);

#[derive(Default)]
struct RequestPacer {
    next_allowed: Option<Instant>,
}

impl RequestPacer {
    fn wait(&mut self) {
        if let Some(next_allowed) = self.next_allowed {
            thread::sleep(next_allowed.saturating_duration_since(Instant::now()));
        }
        self.next_allowed = Some(Instant::now() + Duration::from_secs(1));
    }
}

fn retryable_status(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status == reqwest::StatusCode::REQUEST_TIMEOUT
        || status == reqwest::StatusCode::TOO_EARLY
        || status.is_server_error()
}

fn retry_after_delay(value: Option<&str>) -> Option<Duration> {
    let value = value?;
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let date = DateTime::parse_from_rfc2822(value)
        .ok()?
        .with_timezone(&Utc);
    Some(Duration::from_secs(
        (date - Utc::now()).num_seconds().max(0) as u64,
    ))
}

fn backoff_delay(retry: u32) -> Duration {
    Duration::from_millis(500 * 2u64.pow(retry.min(4)))
}

#[allow(clippy::too_many_arguments)]
fn dav(
    c: &reqwest::blocking::Client,
    pacer: &mut RequestPacer,
    url: &str,
    email: &str,
    password: &str,
    method: &str,
    depth: &str,
    body: &str,
) -> Result<String> {
    let method = reqwest::Method::from_bytes(method.as_bytes())?;
    for attempt in 0..=DAV_RETRIES {
        pacer.wait();
        let response = c
            .request(method.clone(), url)
            .basic_auth(email, Some(password))
            .header("Depth", depth)
            .header("Content-Type", "application/xml; charset=utf-8")
            .body(body.to_string())
            .send();

        match response {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    return Ok(response.text()?);
                }
                if !retryable_status(status) || attempt == DAV_RETRIES {
                    let text = response.text()?;
                    bail!(
                        "DAV request {method} {url} returned {status}: {}",
                        text.chars().take(400).collect::<String>()
                    )
                }
                let retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| retry_after_delay(Some(value)));
                if let Some(delay) = retry_after {
                    if delay > DAV_RETRY_AFTER_LIMIT {
                        bail!(
                            "DAV server returned {status} and asked for a retry delay over five minutes; stopping. Try the command again later."
                        )
                    }
                }
                thread::sleep(retry_after.unwrap_or_else(|| backoff_delay(attempt)));
            }
            Err(error) => {
                if !(error.is_timeout() || error.is_connect()) || attempt == DAV_RETRIES {
                    return Err(error).with_context(|| format!("DAV request failed for {url}"));
                }
                thread::sleep(backoff_delay(attempt));
            }
        }
    }
    unreachable!("DAV retry loop always returns or fails")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apple_session_chunks_round_trip_unicode_within_windows_blob_limit() {
        let value = "synthetic-token/?/\u{1f600}/".repeat(1000);
        let chunks = split_secret_chunks(&value, APPLE_SESSION_CHUNK_BYTES);
        assert!(chunks.len() > 1);
        assert_eq!(chunks.concat(), value);
        for chunk in chunks {
            assert!(!chunk.is_empty());
            assert!(chunk.len() <= APPLE_SESSION_CHUNK_BYTES);
            assert!(chunk.encode_utf16().count() * 2 <= 2560);
        }
    }

    #[test]
    fn readding_account_preserves_default_and_does_not_duplicate_it() {
        let mut config = Config::default();
        add_account_config(&mut config, "first@example.invalid");
        add_account_config(&mut config, "second@example.invalid");
        add_account_config(&mut config, "SECOND@example.invalid");
        assert_eq!(config.accounts.len(), 2);
        assert_eq!(
            config.default_user.as_deref(),
            Some("first@example.invalid")
        );
    }

    #[test]
    fn typed_auth_recovery_takes_precedence_over_http_error_string_matching() {
        let error = apple_auth::recovery(
            "synthetic@example.invalid",
            "auth_refresh_required",
            "Apple rejected the session (HTTP 421)",
            "refresh",
        );
        assert_eq!(error_code(&error), ("auth_refresh_required", Some(false)));
        assert!(next_step(&error).starts_with("icli auth refresh"));
    }

    fn mock_dav_server(replies: Vec<(u16, String)>) -> (String, thread::JoinHandle<Vec<String>>) {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}/", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, body) in replies {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => {
                            socket.set_nonblocking(false).unwrap();
                            break socket;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "Missing mock DAV request");
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("Mock DAV accept failed: {error}"),
                    }
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(&mut socket);
                let mut request = String::new();
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    request.push_str(&line);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse::<usize>().unwrap();
                        }
                    }
                }
                let mut request_body = vec![0; length];
                reader.read_exact(&mut request_body).unwrap();
                request.push_str(std::str::from_utf8(&request_body).unwrap());
                requests.push(request);
                write!(socket, "HTTP/1.1 {status} Mock\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
            requests
        });
        (base, worker)
    }

    fn mock_calendar_report(hrefs: &[&str]) -> String {
        let data = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:one\r\nSUMMARY:Planning\r\nLOCATION:Planning room\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let rows = hrefs.iter().map(|href| format!("<d:response><d:href>{href}</d:href><d:propstat><d:prop><c:calendar-data>{}</c:calendar-data></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>", xml_escape(data))).collect::<String>();
        format!(
            "<d:multistatus xmlns:d=\"DAV:\" xmlns:c=\"urn:ietf:params:xml:ns:caldav\">{rows}</d:multistatus>"
        )
    }

    #[test]
    fn calendar_search_unions_reports_by_href_and_keeps_fallback_date_bounds() {
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .build()
            .unwrap();
        let fields = vec!["summary".into(), "location".into()];
        let (base, server) = mock_dav_server(vec![
            (207, mock_calendar_report(&["/calendar/a.ics"])),
            (
                207,
                mock_calendar_report(&["/calendar/a.ics", "/calendar/b.ics"]),
            ),
        ]);
        let events = dav_event_search_collections(
            &client,
            &[(base.clone(), "Work".into(), "/".into())],
            "test@example.invalid",
            "unused",
            None,
            "planning",
            &fields,
            2,
        )
        .unwrap();
        assert_eq!(events.len(), 2);
        let requests = server.join().unwrap();
        assert!(requests[0].contains("REPORT / HTTP/1.1"));
        assert!(requests[0].contains("name=\"SUMMARY\""));
        assert!(requests[1].contains("name=\"LOCATION\""));

        let (base, server) = mock_dav_server(vec![
            (403, "Unsupported filter".into()),
            (207, mock_calendar_report(&["/calendar/a.ics"])),
        ]);
        let range = Some((
            date_bound("2026-10-01", false).unwrap(),
            date_bound("2026-10-31", true).unwrap(),
        ));
        let results = search_calendar_collection(
            &client,
            &base,
            "test@example.invalid",
            "unused",
            range,
            "planning",
            &fields,
        )
        .unwrap();
        assert_eq!(results.len(), 1);
        let requests = server.join().unwrap();
        assert!(requests[0].contains("<c:prop-filter"));
        assert!(!requests[1].contains("<c:prop-filter"));
        assert!(requests[1].contains("end=\"20261101T000000Z\""));
    }

    #[test]
    fn contact_search_discovers_addressbooks_and_falls_back_after_filter_rejection() {
        let card = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:one\r\nFN:Alex Kim\r\nEND:VCARD\r\n";
        let (base, server) = mock_dav_server(vec![
            (207, "<d:multistatus xmlns:d=\"DAV:\"><d:current-user-principal><d:href>/principal/</d:href></d:current-user-principal></d:multistatus>".into()),
            (207, "<d:multistatus xmlns:d=\"DAV:\" xmlns:card=\"urn:ietf:params:xml:ns:carddav\"><card:addressbook-home-set><d:href>/home/</d:href></card:addressbook-home-set></d:multistatus>".into()),
            (207, "<d:multistatus xmlns:d=\"DAV:\" xmlns:card=\"urn:ietf:params:xml:ns:carddav\"><d:response><d:href>/book/</d:href><d:resourcetype><card:addressbook/></d:resourcetype></d:response></d:multistatus>".into()),
            (400, "Unsupported filter".into()),
            (207, format!("<d:multistatus xmlns:d=\"DAV:\" xmlns:card=\"urn:ietf:params:xml:ns:carddav\"><d:response><card:address-data>{}</card:address-data></d:response></d:multistatus>", xml_escape(card))),
        ]);
        let results = dav_items_with_search(
            &base,
            "test@example.invalid",
            "unused",
            "contact",
            None,
            None,
            1,
            Some(DavSearch::Contacts {
                query: "alex".into(),
                fields: vec!["name".into()],
            }),
        )
        .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["uid"], "one");
        let requests = server.join().unwrap();
        assert!(requests[3].contains("REPORT /book/ HTTP/1.1"));
        assert!(requests[3].contains("test=\"anyof\""));
        assert!(requests[3].contains("name=\"FN\""));
        assert!(!requests[4].contains("<card:filter"));
    }

    #[test]
    fn long_unicode_and_photo_values_survive_vcard_folding() {
        let note = format!("NOTE:{}", "?".repeat(150));
        let photo = format!("PHOTO;ENCODING=b:{}", "YWJj".repeat(100));
        let card = apply_contact_patch(
            None,
            "abc",
            &["FN:Example".into(), note.clone(), photo.clone()],
        )
        .unwrap();
        assert!(card.lines().all(|line| line.len() <= 75));
        let unfolded = unfold_vcard(&card);
        assert!(unfolded.contains(&note));
        assert!(unfolded.contains(&photo));
        let parsed = parse_vcards(&card);
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed[0].all_properties["PHOTO"][0]["value"],
            "YWJj".repeat(100)
        );
    }

    #[test]
    fn repeated_vcard_parameters_keep_every_value() {
        let cards = parse_vcards(
            "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Example\r\nTEL;TYPE=HOME;TYPE=VOICE:+123\r\nEND:VCARD\r\n",
        );
        assert_eq!(
            cards[0].all_properties["TEL"][0]["params"]["TYPE"],
            serde_json::json!(["HOME", "VOICE"])
        );
    }

    #[test]
    fn account_defaults_follow_addition_and_removal_rules() {
        let mut config = Config::default();
        add_account_config(&mut config, "first@example.com");
        assert_eq!(config.default_user.as_deref(), Some("first@example.com"));
        add_account_config(&mut config, "second@example.com");
        add_account_config(&mut config, "third@example.com");
        assert_eq!(config.default_user.as_deref(), Some("first@example.com"));
        remove_account_config(&mut config, "FIRST@example.com").unwrap();
        assert!(config.default_user.is_none());
        config.default_user = Some("second@example.com".into());
        remove_account_config(&mut config, "second@example.com").unwrap();
        assert_eq!(config.default_user.as_deref(), Some("third@example.com"));
        remove_account_config(&mut config, "third@example.com").unwrap();
        assert!(config.default_user.is_none());
        assert!(remove_account_config(&mut config, "missing@example.com").is_err());
    }

    #[test]
    fn contact_patch_preserves_apple_fields_and_replaces_repeated_values() {
        let original = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:abc\r\nFN:Jane\r\nitem1.EMAIL;TYPE=HOME:old@example.com\r\nitem1.X-ABLabel:Personal\r\nBDAY:1990-01-02\r\nPHOTO;ENCODING=b:YWJj\r\n ZA==\r\nX-CUSTOM;TYPE=PRIVATE:original\r\nEND:VCARD\r\n";
        let patch = vec![
            "EMAIL:one@example.com".into(),
            "EMAIL:two@example.com".into(),
        ];
        let updated = apply_contact_patch(Some(original), "abc", &patch).unwrap();
        assert!(!updated.contains("old@example.com"));
        assert_eq!(updated.matches("EMAIL:").count(), 2);
        assert!(updated.contains("item1.X-ABLabel:Personal"));
        assert!(updated.contains("X-CUSTOM;TYPE=PRIVATE:original"));
        assert!(updated.contains("PHOTO;ENCODING=b:YWJjZA=="));
        assert!(updated.contains("BDAY:1990-01-02"));
        assert!(updated.ends_with("END:VCARD\r\n"));
        let cards = parse_vcards(&updated);
        assert_eq!(cards.len(), 1);
        assert_eq!(cards[0].emails, ["one@example.com", "two@example.com"]);
        assert_eq!(cards[0].birthday, "1990-01-02");
        assert_eq!(
            cards[0].all_properties["X-CUSTOM"][0]["params"]["TYPE"],
            serde_json::json!(["PRIVATE"])
        );
    }

    #[test]
    fn contact_patch_preserves_structures_and_rejects_uid_changes() {
        let patch = vec![
            "FN:Jane".into(),
            "N:Doe;Jane;;;".into(),
            "item1.ADR;TYPE=HOME:;;One Street;City;State;1000;Country".into(),
            "item1.X-ABLabel:Home".into(),
        ];
        let card = apply_contact_patch(None, "abc", &patch).unwrap();
        assert!(card.contains("N:Doe;Jane;;;"));
        assert!(card.contains("item1.ADR;TYPE=HOME:;;One Street;City;State;1000;Country"));
        assert!(apply_contact_patch(Some(&card), "abc", &["UID:other".into()]).is_err());
        assert!(apply_contact_patch(None, "abc", &["EMAIL:one@example.com".into()]).is_err());
    }

    #[test]
    fn arbitrary_contact_text_is_escaped_and_grouped_defaults_are_read() {
        let fields = ContactFields {
            name: Some("Jane".into()),
            address: None,
            phone: None,
            email: None,
            properties: vec!["X-CUSTOM=one,two;three\nfour".into()],
            vcard_file: None,
        };
        let patch = contact_patch(&fields).unwrap();
        assert!(
            patch
                .iter()
                .any(|line| line == "X-CUSTOM:one\\,two\\;three\\nfour")
        );
        let card = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:a\r\nFN:Jane\r\nitem1.EMAIL;TYPE=HOME:jane@example.com\r\nitem2.TEL:+123\r\nEND:VCARD\r\n";
        let contacts = parse_vcards(card);
        assert_eq!(contacts[0].emails, ["jane@example.com"]);
        assert_eq!(contacts[0].phones, ["+123"]);
        assert!(contacts[0].all_properties.contains_key("ITEM1.EMAIL"));
    }

    #[test]
    fn ambiguous_calendar_names_require_exact_selection() {
        let calendars = vec![
            serde_json::json!({"name":"Work","id":"a","href":"https://caldav.icloud.com/1/a/"}),
            serde_json::json!({"name":"Work","id":"b","href":"https://caldav.icloud.com/1/b/"}),
        ];
        let error = select_calendar_url(&calendars, "work").unwrap_err();
        assert_eq!(error_code(&error).0, "ambiguous_resource");
        assert!(error.to_string().contains("https://caldav.icloud.com/1/b/"));
        assert_eq!(
            select_calendar_url(&calendars, "a").unwrap(),
            "https://caldav.icloud.com/1/a/"
        );
    }

    #[test]
    fn every_leaf_help_has_examples_and_response_contract() {
        fn walk(command: &clap::Command) {
            if command.get_subcommands().next().is_none() && command.get_name() != "help" {
                let mut command = command.clone();
                let help = command.render_long_help().to_string();
                assert!(
                    help.contains("Examples:"),
                    "{} lacks examples",
                    command.get_name()
                );
                assert!(
                    help.contains("Exit codes:"),
                    "{} lacks exit codes",
                    command.get_name()
                );
                for arg in command.get_arguments() {
                    assert!(
                        arg.get_help().is_some(),
                        "{}: {} lacks help",
                        command.get_name(),
                        arg.get_id()
                    );
                }
            }
            for child in command.get_subcommands() {
                walk(child);
            }
        }
        let command = agent_command();
        command.clone().debug_assert();
        walk(&command);
    }

    #[test]
    fn date_range_bounds_are_utc_and_end_date_is_inclusive() {
        assert_eq!(
            date_bound("2026-10-17", false).unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 17, 0, 0, 0).unwrap()
        );
        assert_eq!(
            date_bound("2026-10-17", true).unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 18, 0, 0, 0).unwrap()
        );
    }

    #[test]
    fn invalid_date_is_rejected() {
        assert!(date_bound("tomorrow", false).is_err());
    }

    #[test]
    fn pagination_handles_boundaries_and_reports_only_real_next_pages() {
        for (skip, limit, expected, next_skip) in [
            (0, 2, vec![0, 1], Some(2)),
            (2, 2, vec![2, 3], Some(4)),
            (4, 2, vec![4], None),
            (5, 2, vec![], None),
            (6, 2, vec![], None),
            (0, 0, vec![], None),
            (usize::MAX, usize::MAX, vec![], None),
            (0, usize::MAX, vec![0, 1, 2, 3, 4], None),
        ] {
            response::configure("test.pagination".into(), OutputFormat::Json);
            assert_eq!(page_items(vec![0, 1, 2, 3, 4], skip, limit), expected);
            let result = response::envelope(serde_json::Value::Null, serde_json::Value::Null);
            let hints = result["next_steps"].as_array().unwrap();
            if let Some(next_skip) = next_skip {
                assert_eq!(hints.len(), 1);
                assert!(
                    hints[0]
                        .as_str()
                        .unwrap()
                        .contains(&format!("--skip {next_skip} --limit {limit}"))
                );
            } else {
                assert!(hints.is_empty(), "skip={skip}, limit={limit}");
            }
        }
        response::configure("test.pagination".into(), OutputFormat::Json);
        assert!(page_items(Vec::<u32>::new(), 0, 10).is_empty());
        let result = response::envelope(serde_json::Value::Null, serde_json::Value::Null);
        assert_eq!(result["next_steps"], serde_json::json!([]));
    }

    #[test]
    fn mail_pagination_selects_uids_in_newest_first_order() {
        assert_eq!(mail_page_ids(vec![2, 9, 5, 1, 8], 0, 2), vec![9, 8]);
        assert_eq!(mail_page_ids(vec![2, 9, 5, 1, 8], 2, 2), vec![5, 2]);
        assert_eq!(mail_page_ids(vec![2, 9, 5, 1, 8], 4, 2), vec![1]);
    }

    #[test]
    fn dav_pagination_warns_when_skip_requires_downloading_matches() {
        response::configure("test.dav-pagination".into(), OutputFormat::Json);
        assert_eq!(dav_page_items(vec![0, 1, 2], 1, 1), vec![1]);
        let result = response::envelope(serde_json::Value::Null, serde_json::Value::Null);
        assert_eq!(
            result["warnings"][0].as_str(),
            Some(
                "Using --skip with --limit for Calendar/Contacts pagination is not recommended: loading all matches in one call is faster than requesting multiple pages. iCLI still downloads every matching event or contact card, including skipped results, because CalDAV and CardDAV do not provide offset pagination for these queries; iCLI applies --skip locally."
            )
        );

        response::configure("test.dav-pagination".into(), OutputFormat::Json);
        assert_eq!(dav_page_items(vec![0, 1, 2], 0, 1), vec![0]);
        assert_eq!(
            response::envelope(serde_json::Value::Null, serde_json::Value::Null)["warnings"],
            serde_json::json!([])
        );

        response::configure("test.mail-pagination".into(), OutputFormat::Json);
        assert_eq!(mail_page_ids(vec![1, 2, 3], 1, 1), vec![2]);
        assert_eq!(
            response::envelope(serde_json::Value::Null, serde_json::Value::Null)["warnings"],
            serde_json::json!([])
        );
    }

    #[test]
    fn contact_pages_keep_uid_order_when_reports_are_shuffled_or_uids_repeat() {
        let cards = [
            ("c", "Third"),
            ("a", "First"),
            ("b", "Beta"),
            ("b", "Alpha"),
        ];
        for reversed in [false, true] {
            let contacts = || {
                let mut rows = cards
                    .iter()
                    .map(|(uid, name)| Contact {
                        uid: (*uid).into(),
                        name: (*name).into(),
                        emails: vec![],
                        phones: vec![],
                        birthday: String::new(),
                        all_properties: BTreeMap::new(),
                    })
                    .collect::<Vec<_>>();
                if reversed {
                    rows.reverse();
                }
                rows
            };
            let first = contact_page(contacts(), 0, 2);
            assert_eq!(
                first
                    .iter()
                    .map(|contact| contact.name.as_str())
                    .collect::<Vec<_>>(),
                vec!["First", "Alpha"]
            );
            let second = contact_page(contacts(), 2, 2);
            assert_eq!(
                second
                    .iter()
                    .map(|contact| contact.name.as_str())
                    .collect::<Vec<_>>(),
                vec!["Beta", "Third"]
            );
        }
    }

    #[test]
    fn pagination_flags_keep_expected_defaults_for_all_six_commands() {
        for (args, default_limit) in [
            (
                vec!["icli", "calendar", "events", "search", "planning"],
                100,
            ),
            (vec!["icli", "contacts", "list"], 100),
            (vec!["icli", "contacts", "search", "alex"], 100),
            (vec!["icli", "mail", "list"], 10),
            (vec!["icli", "mail", "search", "invoice"], 50),
            (vec!["icli", "reminders", "list"], 100),
        ] {
            for explicit in [false, true] {
                let mut args = args.clone();
                if explicit {
                    args.extend(["--skip", "50", "--limit", "20"]);
                }
                let matches = agent_command().try_get_matches_from(args).unwrap();
                let mut leaf = &matches;
                while let Some((_, child)) = leaf.subcommand() {
                    leaf = child;
                }
                assert_eq!(
                    leaf.get_one::<usize>("skip"),
                    Some(&if explicit { 50 } else { 0 })
                );
                assert_eq!(
                    leaf.get_one::<usize>("limit"),
                    Some(&if explicit { 20 } else { default_limit })
                );
            }
        }
    }

    #[test]
    fn search_query_validation_rejects_blank_controls_and_oversized_input() {
        assert_eq!(validate_search_query("  planning ").unwrap(), "planning");
        assert!(validate_search_query("  ").is_err());
        assert!(validate_search_query("two\nlines").is_err());
        assert!(validate_search_query("\nplanning").is_err());
        assert!(validate_search_query("planning\t").is_err());
        assert!(validate_search_query("\u{fffe}").is_err());
        assert!(validate_search_query("\u{ffff}").is_err());
        assert!(validate_search_query(&"é".repeat(256)).is_ok());
        assert!(validate_search_query(&"é".repeat(257)).is_err());
        assert!(validate_search_query(&"x".repeat(257)).is_err());
    }

    #[test]
    fn search_matches_decoded_text_and_uses_each_protocols_collation() {
        let contact = parse_vcards(
            "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:one\r\nFN:José\\, Example\r\nORG:ACME\\; Labs\r\nEND:VCARD\r\n",
        ).remove(0);
        assert!(contact_matches_query(
            &contact,
            "JOSE\u{301}, EXAMPLE",
            &["name".into()]
        ));
        assert!(contact_matches_query(
            &contact,
            "Acme; Labs",
            &["organization".into()]
        ));
        assert_eq!(unicode_casemap("Ǆ"), "Dz\u{30c}");
        assert_eq!(unicode_casemap("ǆ"), unicode_casemap("Ǆ"));
        assert_eq!(unicode_casemap("ß"), "ß");
        assert_eq!(unicode_casemap("ﬄ"), "ffl");
        assert_eq!(unicode_casemap("Ａ"), unicode_casemap("a"));

        let event = parse_ical_events(
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:one\r\nSUMMARY:Équipe Planning\r\nCATEGORIES:Research\\, development\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        );
        let event = serde_json::to_value(&event[0]).unwrap();
        assert!(calendar_event_matches(
            &event,
            "ÉQUIPE",
            &["summary".into()]
        ));
        assert!(!calendar_event_matches(
            &event,
            "équipe",
            &["summary".into()]
        ));
        assert!(calendar_event_matches(
            &event,
            "Research, development",
            &["categories".into()]
        ));
    }

    #[test]
    fn dav_search_reports_escape_queries_and_parse_as_xml() {
        let calendar = calendar_search_body("R&D <Planning>", "summary", None);
        let contacts = carddav_search_body("R&D <Planning>", &["name".into(), "email".into()]);
        assert!(roxmltree::Document::parse(&calendar).is_ok());
        assert!(roxmltree::Document::parse(&contacts).is_ok());
        assert!(calendar.contains("R&amp;D &lt;Planning&gt;"));
        assert!(contacts.contains("test=\"anyof\""));
        assert!(contacts.contains("name=\"FN\""));
        assert!(contacts.contains("name=\"EMAIL\""));
        assert!(!contacts.contains("name=\"TEL\""));
        let start = date_bound("2026-10-01", false).unwrap();
        let end = date_bound("2026-10-31", true).unwrap();
        let ranged = calendar_search_body("planning", "summary", Some((start, end)));
        assert!(ranged.contains("start=\"20261001T000000Z\""));
        assert!(ranged.contains("end=\"20261101T000000Z\""));
        assert!(roxmltree::Document::parse(&ranged).is_ok());
    }

    #[test]
    fn rejected_dav_filters_trigger_only_on_filter_related_statuses() {
        assert!(is_filter_query_rejection(&anyhow!(
            "DAV request returned 403"
        )));
        assert!(is_filter_query_rejection(&anyhow!(
            "DAV request returned 412"
        )));
        assert!(!is_filter_query_rejection(&anyhow!(
            "DAV request returned 401"
        )));
        assert!(!is_filter_query_rejection(&anyhow!("connection timed out")));
    }

    #[test]
    fn search_matching_is_case_insensitive_and_or_across_selected_fields() {
        let event = parse_ical_events(
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:one\r\nSUMMARY:Quarterly Planning\r\nLOCATION:Room 7\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        );
        let event = serde_json::to_value(&event[0]).unwrap();
        assert!(calendar_event_matches(
            &event,
            "QUARTERLY",
            &["summary".into(), "location".into()]
        ));
        assert!(!calendar_event_matches(
            &event,
            "missing",
            &["summary".into()]
        ));

        let contact = parse_vcards(
            "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:one\r\nFN:Alex Kim\r\nEMAIL:alex@example.invalid\r\nEND:VCARD\r\n",
        )
        .remove(0);
        assert!(contact_matches_query(
            &contact,
            "EXAMPLE.INVALID",
            &["name".into(), "email".into()]
        ));
        assert!(!contact_matches_query(
            &contact,
            "example.invalid",
            &["name".into()]
        ));
    }

    #[test]
    fn search_cli_rejects_unpaired_dates_and_unknown_fields() {
        assert!(
            Cli::try_parse_from([
                "icli",
                "calendar",
                "events",
                "search",
                "planning",
                "--from",
                "2026-10-01"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "icli", "calendar", "events", "search", "planning", "--field", "title"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "icli",
                "contacts",
                "search",
                "alex",
                "--field",
                "email,phone"
            ])
            .is_ok()
        );
    }

    #[test]
    fn dav_retries_are_bounded_and_rate_limit_responses_are_retryable() {
        assert!(retryable_status(reqwest::StatusCode::TOO_MANY_REQUESTS));
        assert!(retryable_status(reqwest::StatusCode::SERVICE_UNAVAILABLE));
        assert!(!retryable_status(reqwest::StatusCode::UNAUTHORIZED));
        assert_eq!(retry_after_delay(Some("3")), Some(Duration::from_secs(3)));
        assert_eq!(backoff_delay(0), Duration::from_millis(500));
        assert_eq!(backoff_delay(3), Duration::from_secs(4));
    }

    #[test]
    fn parses_calendar_events_from_ical_data() {
        let data = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:event-1\r\nSUMMARY:Planning\r\nDTSTART:20261017T090000Z\r\nDTEND:20261017T100000Z\r\nLOCATION:Room 2\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let events = parse_ical_events(data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].summary, "Planning");
        assert_eq!(events[0].start, "20261017T090000Z");
        assert_eq!(events[0].location, "Room 2");
        assert_eq!(events[0].uid, "event-1");
    }

    #[test]
    fn parses_contact_name_emails_and_phones_from_vcard() {
        let data = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Jane Doe\r\nEMAIL:jane@example.com\r\nTEL:+1-555-0100\r\nEND:VCARD\r\n";
        let contacts = parse_vcards(data);
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].name, "Jane Doe");
        assert_eq!(contacts[0].emails, ["jane@example.com"]);
        assert_eq!(contacts[0].phones, ["+1-555-0100"]);
    }

    #[test]
    fn parses_agent_json_event_command() {
        let parsed = Cli::try_parse_from([
            "icli",
            "--json",
            "calendar",
            "events",
            "--from",
            "2026-10-17",
            "--to",
            "2026-10-18",
        ])
        .unwrap();
        assert!(parsed.json);
    }

    #[test]
    fn parses_auth_add_email_as_positional_or_flag() {
        assert!(Cli::try_parse_from(["icli", "auth", "add"]).is_err());

        let positional = Cli::try_parse_from(["icli", "auth", "add", "jane@icloud.com"]).unwrap();
        assert!(matches!(
            positional.command,
            Command::Auth { command: AuthCommand::Add(AuthCredentialArgs { email: Some(ref email), email_flag: None, .. }) }
                if email == "jane@icloud.com"
        ));

        let flagged =
            Cli::try_parse_from(["icli", "auth", "add", "--email", "jane@icloud.com"]).unwrap();
        assert!(matches!(
            flagged.command,
            Command::Auth { command: AuthCommand::Add(AuthCredentialArgs { email: None, email_flag: Some(ref email), .. }) }
                if email == "jane@icloud.com"
        ));

        assert!(
            Cli::try_parse_from([
                "icli",
                "auth",
                "add",
                "jane@icloud.com",
                "--email",
                "other@icloud.com",
            ])
            .is_err()
        );
    }

    #[test]
    fn help_subcommand_and_other_commands_are_available() {
        let help = match Cli::try_parse_from(["icli", "help"]) {
            Err(error) => error,
            Ok(_) => panic!("help should return Clap's display-help result"),
        };
        assert_eq!(help.kind(), clap::error::ErrorKind::DisplayHelp);
        assert!(Cli::try_parse_from(["icli", "calendar", "list"]).is_ok());
        assert!(Cli::try_parse_from(["icli", "contacts"]).is_ok());
        assert!(Cli::try_parse_from(["icli", "mail"]).is_ok());
    }
}
