use clap::{Command, CommandFactory};

pub fn command() -> Command {
    enrich(crate::Cli::command(), "icli".into())
}

fn enrich(mut command: Command, path: String) -> Command {
    command = command.mut_args(|arg| {
        if arg.get_help().is_some() { return arg; }
        let description = match arg.get_id().as_str() {
            "json" => "Force JSON, overriding --format and the saved format",
            "format" => "Response format for this invocation; overrides saved config unless --json is present",
            "email" if path.starts_with("icli reminders") => "Apple Account email; defaults to the saved default account, then the sole configured account",
            "email" | "email_flag" | "email_pos" => "Configured account email; otherwise use the default account, then the sole saved account; multiple accounts require a choice",
            "password" | "password_flag" if path == "icli auth add" => "Apple Account password used only for sign-in; prefer --password-stdin over arguments",
            "password" | "password_flag" => "Apple app-specific password; arguments may be exposed in shell history/process listings; prefer --password-stdin",
            "code" | "code_flag" => "Six-digit Apple verification code; prefer --code-stdin over arguments",
            "code_stdin" => "Read the verification code from stdin; remove only the trailing line ending",
            "method" if path == "icli auth resend" => "Request a code on a trusted device, or by SMS when Apple offers a trusted phone",
            "app_password" => "Check Mail, Calendar, and Contacts with the saved or supplied app-specific password",
            "password_stdin" => "Read the password from stdin; remove only the trailing line ending",
            "response_format" => "Save agent, csv, or json as the default; this response uses the new format unless explicitly overridden",
            "calendar" | "calendar_pos" => "Calendar name, stable ID, full href, or href path from calendar list; ambiguous matches fail with candidates",
            "id" if path.starts_with("icli reminders") => "Stable reminder ID from `icli reminders list` or `icli reminders get`",
            "hashtag_id" => "Stable hashtag ID from `icli reminders hashtag list`",
            "attachment_id" => "Stable attachment ID from `icli reminders attachment list`",
            "rule_id" => "Stable recurrence rule ID from `icli reminders recurrence list`",
            "uid" => "Resource UID from this service's list command; contacts/events also accept an exact resource href from ambiguity errors; mail UIDs are scoped to --folder (INBOX by default)",
            "folder" => "IMAP folder name; defaults to INBOX",
            "source" => "Source IMAP folder for a move; defaults to INBOX",
            "destination" => "Destination IMAP folder for a move",
            "query" if path == "icli mail search" => "Text to find in the selected folder; IMAP searches message text",
            "query" if path == "icli calendar events search" => "Literal text to match with CalDAV's case-insensitive ASCII collation",
            "query" if path == "icli contacts search" => "Literal text to match as a Unicode-aware case-insensitive substring",
            "query" => "Literal text to match as a case-insensitive substring in the selected fields",
            "fields" if path == "icli calendar events search" => "Event fields to search: summary, description, location, attendee, organizer, or categories; repeat or comma-separate",
            "fields" if path == "icli contacts search" => "Contact fields to search: name, email, phone, or organization; repeat or comma-separate",
            "fields" => "Properties searched for the query; repeat or comma-separate field names",
            "part" => "MIME part ID reported by mail get, such as 1.2",
            "output" => "Local path to write the decoded attachment bytes",
            "rrule" => "iCalendar recurrence rule such as FREQ=WEEKLY;BYDAY=MO",
            "alarm_minutes" => "Display alarm minutes before start; repeat to set multiple alarms",
            "clear_alarms" => "Remove VALARM components from the event's master component",
            "clear_recurrence" => "Remove the RRULE property from the event's master component",
            "color" => "Calendar color as #RRGGBB or #RRGGBBAA",
            "person" => "Email address receiving or losing calendar access",
            "permission" => "Permission granted: read or write",
            "members" => "Contact UIDs included in this group; repeat --member",
            "include" => "Extra properties to return; repeat or comma-separate names; contacts also accepts all",
            "limit" if path == "icli calendar events search" => "Maximum results after --skip in resource href order, not chronological order; 0 returns none",
            "limit" if path.starts_with("icli contacts") => "Maximum results after --skip in ascending UID order; 0 returns none",
            "limit" if path == "icli reminders list" => "Maximum reminders returned after --skip; 0 returns none",
            "limit" if path == "icli reminders snapshot" => "Maximum rows per record type; truncated_types identifies capped arrays",
            "limit" if path == "icli reminders changes" => "Maximum changed reminder records returned in this sync page",
            "limit" => "Maximum message UIDs fetched after --skip, newest IMAP UIDs first; 0 returns none",
            "skip" if path.starts_with("icli mail") => "Matching message UIDs to skip, newest first, before fetching headers; zero-based offset",
            "skip" if path == "icli calendar events search" => "Matching events to skip in resource href order; DAV downloads all matches, so use one sufficiently large --limit when possible",
            "skip" if path.starts_with("icli contacts") => "Matching contacts to skip in ascending UID order; DAV downloads skipped matches, so use one sufficiently large --limit when possible",
            "skip" if path == "icli reminders list" => "Matching reminders to skip before applying --limit; CloudKit still reads skipped rows to reach this offset",
            "skip" => "Matching results to skip before applying --limit; zero-based offset",
            "concurrency" => "Maximum concurrent calendar requests, from 1 to 8; defaults to 2",
            "from" | "from_pos" => "First date, YYYY-MM-DD, inclusive at 00:00 UTC",
            "to_pos" => "Last date, YYYY-MM-DD, inclusive through the end of that UTC date",
            "to" if path.starts_with("icli calendar") => "Last date, YYYY-MM-DD, inclusive through the end of that UTC date",
            "to" => "Recipient emails, comma-separated; mail create saves a draft, mail send delivers it",
            "start" => "Timed event start as RFC3339 with timezone, for example 2026-10-20T10:00:00+02:00; provide --end too",
            "end" => "Timed event end as RFC3339 with timezone; must be after --start",
            "all_day" if path == "icli reminders create" => "Treat the due date as an all-day date",
            "all_day" if path.starts_with("icli reminders") => "Set or clear all-day status on the reminder",
            "all_day" => "Single all-day date, YYYY-MM-DD; exclusive with --start/--end; update can convert a timed event",
            "title" if path == "icli reminders create" => "Title for the new reminder",
            "title" if path.starts_with("icli reminders") => "New reminder title; update changes only the supplied field",
            "notes" if path == "icli reminders create" => "Notes for the new reminder",
            "notes" if path.starts_with("icli reminders") => "New reminder notes; update changes only the supplied field",
            "due" if path.starts_with("icli reminders") => "Due date as YYYY-MM-DD or RFC3339; update accepts --clear-due to remove it",
            "clear_due" => "Clear the reminder due date",
            "priority" if path.starts_with("icli reminders") => "Reminder priority from 0 to 9; 0 is no priority",
            "flagged" if path == "icli reminders create" => "Create the reminder with its flagged state set",
            "flagged" if path.starts_with("icli reminders") => "Set or clear the reminder's flagged state",
            "completed" => "Set or clear completion; completion time is updated with the status",
            "status" => "Completion state: completed or incomplete",
            "latitude" => "Location latitude in degrees, from -90 through 90",
            "longitude" => "Location longitude in degrees, from -180 through 180",
            "radius" => "Location trigger radius in meters; must be positive",
            "proximity" => "Trigger when arriving or leaving the location",
            "address" => "Human-readable address stored with the location trigger",
            "frequency" if path.starts_with("icli reminders recurrence") => "Recurrence interval unit: daily, weekly, monthly, or yearly",
            "interval" => "Number of frequency units between occurrences; must be at least 1",
            "occurrence_count" => "Stop after this many occurrences; 0 means no fixed count",
            "first_day_of_week" => "Week start day from 0 (Sunday) through 6 (Saturday)",
            "url" if path.starts_with("icli reminders attachment") => "Absolute HTTP or HTTPS URL for the attachment",
            "uti" => "Uniform Type Identifier stored with the attachment",
            "summary" => "Event title; update changes only supplied fields",
            "location" => "Event location; an empty string clears it on update",
            "description" => "Event description; an empty string clears it on update",
            "name" if path.starts_with("icli reminders hashtag") => "Hashtag text to attach or set; do not include the leading #",
            "name" => "Calendar or contact name; quote names containing spaces",
            "list" if path == "icli reminders create" => "Stable list ID from `icli reminders lists`",
            "list" if path == "icli reminders snapshot" => "Stable list ID from `icli reminders lists`",
            "subject" => "Message subject, without header line breaks",
            "body" => "Plain-text message body; quote multiline values according to your shell",
            "file" => "Readable local .ics file containing VEVENT entries with UIDs",
            "phone" => "Contact phone number; replaces existing TEL values on update",
            "yes" if path.starts_with("icli reminders") => "Confirm remote soft-delete; the command fails without this flag",
            "yes" => "Confirm permanent remote deletion; the command fails without this flag",
            _ => "Value for this operation; see the command description and examples",
        };
        arg.help(description)
    });
    let override_about = match path.as_str() {
        "icli auth" => Some(
            "Start Apple Account sign-in with auth add and submit the code separately with auth verify. Trusted tokens and pending challenges are saved in the OS credential store; the Apple Account password is never saved. Commands reuse the default account and session. auth check checks the session, auth refresh renews saved tokens, and auth resend requests a new code. Mail, Calendar, and Contacts currently require a recommended app-specific password: save it with auth app-password and check it with auth check --app-password. auth add no longer saves app-specific passwords; migrate old scripts to auth app-password. auth apple-login is a deprecated alias for auth add.",
        ),
        "icli auth add" => Some(
            "Start or restart Apple Account sign-in with EMAIL and the Apple Account password. Accepts positional EMAIL [PASSWORD], --email/--password, or --password-stdin; arguments can expose secrets in history/process listings, so agents should use a private secret source piped to stdin. Only terminal stdin gets a hidden password prompt. This contacts Apple and requests trusted-device verification, or SMS for supported fallback challenges, then exits without waiting for the code. A successful start has exit 0 and data.auth_state=verification_required or authenticated. Follow next_steps and submit the code with auth verify. Pending cookies/tokens are saved in the OS credential store; the Apple Account password is never saved. The first configured account becomes default; re-signing in preserves the default and any app-specific password. Newer bridge-only challenges and hardware keys are unsupported. Deprecated alias: apple-login. For app-specific passwords use auth app-password instead.",
        ),
        "icli auth app-password" => Some(
            "Save or replace an Apple app-specific password for Mail, Calendar, and Contacts. Recommended for those services. Creates the account if needed; Apple Account sign-in is not required. Makes no network requests and does not validate credentials. Accepts EMAIL [PASSWORD], --email/--password, or --password-stdin. Prefer private stdin for agents; a hidden prompt is available only with terminal stdin. Password arguments may appear in shell history/process listings. Stores the password in the OS credential store and preserves any Apple session and current default. The first account becomes default. Next run auth check --app-password. Apple's setup instructions: https://support.apple.com/en-us/102654.",
        ),
        "icli auth verify" => Some(
            "Submit a six-digit verification code to the saved pending Apple sign-in. Use EMAIL CODE, --email EMAIL --code CODE, or EMAIL --code-stdin; prefer a private stdin source. When omitted in a terminal the code uses a hidden prompt; it never prompts in noninteractive mode. EMAIL otherwise defaults to the saved default, then the sole configured account. On success saves the trusted session; the agent must retry its original command. It never replays that command. Incorrect codes retain the pending challenge. Expired challenges return an auth add recovery command. If Apple accepted the code but the trust/session exchange failed, use auth refresh to finish it without resubmitting the code.",
        ),
        "icli auth resend" => Some(
            "Request another code for the selected account's saved pending sign-in. --method device is the default; --method sms requests a text when Apple supplied a trusted phone. This contacts Apple but never submits a code or waits for input. It saves updated challenge headers and cookies. Then run auth verify with the new code. If the challenge expired, restart with auth add.",
        ),
        "icli auth refresh" => Some(
            "Renew the selected Apple Account session with its saved tokens. Also finishes the trust/session exchange when a verification code was already accepted. Contacts Apple, updates the OS credential store, and never asks for a password or code. A pending code challenge returns auth_verification_required; rejected tokens return auth_sign_in_required with an exact auth add command. No original service command is replayed. Retry that command after recovery succeeds.",
        ),
        "icli auth check" => Some(
            "Without --app-password, contact Apple to check the selected saved session without persisting new tokens or cookies. Never prompts, reauthenticates, or updates credentials. Pending verification and rejected sessions return structured recovery commands. With --app-password, independently check Mail, Calendar, and Contacts with the saved or supplied password/--password-stdin. All three run even if one fails; all pass exits 0, some pass is partial exit 3, none pass exits 1. These checks read only and do not verify write access. PASSWORD inputs require --app-password.",
        ),
        "icli reminders" => Some(
            "Read and manage Apple Reminders through Apple's private CloudKit service. Start with `icli auth add EMAIL`, then `icli auth verify EMAIL CODE` when requested. The saved default account and trusted session are reused. The first read may request trusted-device approval for encrypted Reminders data. Inspect stable list and reminder IDs before writing. Deletes require --yes.",
        ),
        "icli reminders lists" => Some(
            "Read reminder lists and their stable service IDs from Apple's CloudKit Reminders service, falling back to the legacy endpoint when CloudKit is not advertised. The first read may request trusted-device approval for encrypted Reminders data. This command does not change reminder data.",
        ),
        "icli reminders list" => Some(
            "Read active and completed reminders in all current lists. Each row includes its stable record ID, list ID/name, completion state, and due date when present. By default, return the first 100 reminders; use --skip and --limit to page through more results. The first read may request trusted-device approval for encrypted Reminders data. This command does not change reminder data.",
        ),
        "icli reminders get" => Some(
            "Read one reminder by stable ID, including notes, due date, status, flags, priority, list and related-record IDs. This command does not change data.",
        ),
        "icli reminders create" => Some(
            "Create one reminder in the specified stable list ID. Due dates accept YYYY-MM-DD or RFC3339. All-day due dates are interpreted at UTC midnight. Apple assigns a stable ID and the command reads the new record back.",
        ),
        "icli reminders update" => Some(
            "Update only supplied fields on one reminder. Omitted fields are preserved. Use --clear-due to remove its due date. Apple CloudKit text fields use a versioned topotext document; inspect the saved record if a write is rejected.",
        ),
        "icli reminders set-status" => Some(
            "Set one reminder to completed or incomplete. Completion timestamps are written or cleared with the status.",
        ),
        "icli reminders delete" => Some(
            "Soft-delete one reminder in Apple CloudKit. The required --yes flag confirms the remote write; the service keeps a deleted record for sync.",
        ),
        "icli reminders snapshot" => Some(
            "Fetch one list's reminders and related alarms, triggers, attachments, hashtags, and recurrence rules as a snapshot. --limit caps each record-type array independently; truncated_types identifies arrays that hit the cap. This reads CloudKit records and does not change them.",
        ),
        "icli reminders changes" => Some(
            "Fetch one page of changed or deleted reminders from the CloudKit zone. Save the returned cursor and pass it as --since on the next call. A response with more_available=true has another page.",
        ),
        "icli reminders sync-cursor" => Some(
            "Read Apple's opaque current zone cursor for use with `icli reminders changes --since CURSOR`. Do not edit or interpret the cursor.",
        ),
        "icli reminders alarm list" => {
            Some("Read alarm records and their date or location triggers for one reminder.")
        }
        "icli reminders alarm add-location" => Some(
            "Add a location trigger and alarm to one reminder. Latitude, longitude, radius, and arrival/departure proximity are sent to Apple as an atomic CloudKit record group.",
        ),
        "icli reminders hashtag list" => Some("Read hashtags attached to one reminder."),
        "icli reminders hashtag create" => Some("Attach a hashtag to one reminder."),
        "icli reminders hashtag update" => {
            Some("Rename a hashtag attached to the selected reminder.")
        }
        "icli reminders hashtag delete" => Some(
            "Detach and soft-delete one hashtag. The required --yes flag confirms the remote write.",
        ),
        "icli reminders attachment list" => Some(
            "Read attachments linked to one reminder. URL attachment links are decoded when Apple returns their encoded form.",
        ),
        "icli reminders attachment create-url" => Some(
            "Attach an HTTP or HTTPS URL to one reminder. This creates a URL attachment record, not an uploaded file.",
        ),
        "icli reminders attachment update" => {
            Some("Update the URL or UTI of a URL attachment linked to the selected reminder.")
        }
        "icli reminders attachment delete" => Some(
            "Detach and soft-delete one attachment. The required --yes flag confirms the remote write.",
        ),
        "icli reminders recurrence list" => Some("Read recurrence rules attached to one reminder."),
        "icli reminders recurrence create" => Some(
            "Attach a daily, weekly, monthly, or yearly recurrence rule. An occurrence count of zero means no fixed count.",
        ),
        "icli reminders recurrence update" => {
            Some("Update supplied fields of a recurrence rule attached to the selected reminder.")
        }
        "icli reminders recurrence delete" => Some(
            "Detach and soft-delete one recurrence rule. The required --yes flag confirms the remote write.",
        ),
        "icli auth remove" => Some(
            "Remove the local account, app-specific password, pending Apple challenge, and trusted session including its credential chunks. Remote Apple data is unaffected. Removing the default selects the sole remaining account; with several remaining accounts the default is cleared and exact selection commands are returned.",
        ),
        "icli contacts list" | "icli contacts get" => Some(
            "Read contact summaries containing uid, name, emails, phones, and birthday. Use --include PROPERTY, repeat it, or comma-separate property names to add values under properties. Names are case-insensitive. --include all returns every property, including Apple X- fields, custom fields, repeated values, and parameters. Grouped Apple properties retain their full names; requesting ADR also selects grouped names such as ITEM1.ADR. Requested properties absent from the result are reported. List reads the address book, sorts contacts by UID, and applies --skip before --limit. These commands do not modify cards.",
        ),
        "icli calendar events search" => Some(
            "Search iCloud calendars by literal text. CalDAV text-match filters are issued for each selected property and their results are combined as an OR. The default fields are summary, description, and location. Matching ignores ASCII letter case; non-ASCII letters retain their case. Search returns the selected search properties along with regular event fields. If iCloud rejects a field filter, iCLI reads events from that calendar and applies the same substring match locally. Optional --from and --to dates are inclusive UTC dates and must be supplied together. CalDAV applies dates to calendar resources; recurring series are not expanded into individual occurrences, and returned series components can have dates outside the range. Surrounding whitespace is trimmed. Queries must then be 1 to 256 characters and cannot contain control characters or characters XML cannot represent. After matching, --skip is applied before --limit in resource href order, not chronological order. This command only reads calendar data.",
        ),
        "icli contacts search" => Some(
            "Search iCloud address books by literal text using CardDAV addressbook-query filters. The default fields are formatted name, email, and phone. CardDAV matches any selected field using Unicode-aware case-insensitive substring matching with i;unicode-casemap normalization. Selected search properties are included under properties in the result. If iCloud rejects a field filter, iCLI reads the address book and applies the same substring match locally. Groups are excluded. Surrounding whitespace is trimmed. Queries must then be 1 to 256 characters and cannot contain control characters or characters XML cannot represent. Phone matching is literal: punctuation, spacing, and country codes are not normalized. After matching, contacts are sorted by UID and --skip is applied before --limit. --include adds other properties to returned contacts. This command only reads contact data.",
        ),
        "icli contacts help" => Some(
            "Read the selected account's cards and list default output fields, the standard vCard property catalog, every property found in that account, custom X- names, and parameter names. This discovers custom properties without external documentation. Use --include all to retrieve complete property data. This operation reads cards and does not modify them.",
        ),
        "icli contacts create" => Some(
            "Create one contact using common fields, repeated --property NAME=VALUE text values, and/or --vcard-file FILE. A formatted name is required via --name or FN. UID is generated unless provided in the file. Use a complete single-card vCard file for parameters, grouped Apple fields, PHOTO data, or structured values such as ADR and N. Simple --property values are escaped as text. Overlapping properties from a file and flags, or a common flag and --property, are rejected. Creation refuses to overwrite an existing resource. The result returns UID, account, changed properties, and a get command.",
        ),
        "icli contacts update" => Some(
            "Merge supplied properties into the existing card identified by UID. Omitted properties remain unchanged. Repeated --property NAME=VALUE values replace that property's existing values as a group. A complete --vcard-file follows the same merge rule and preserves parameters/structured values. A file UID must match the target UID. Common --name changes FN and N; --contact-email replaces EMAIL; --phone replaces TEL. Ungrouped properties replace matching grouped properties too; a grouped name targets that exact group. Overlapping input sources are rejected. An empty text value sets an empty value. At least one change is required. Updates use the server ETag when provided and fail on concurrent changes; read the latest card before retrying.",
        ),
        "icli contacts delete" => Some(
            "Permanently delete the contact identified by its vCard UID from contacts list. Requires --yes. The result contains the UID and deleted state. If the server reports the resource is already absent, the desired deleted state is treated as success.",
        ),
        "icli mail list" => Some(
            "Read recent message headers from --folder (INBOX by default), using IMAP UIDs in descending order. Default --skip is 0 and --limit is 10; --limit 0 returns none. Paging skips matching UIDs before fetching headers. Results contain uid, from, subject, and date. Reading uses BODY.PEEK and does not mark messages as read. Use mail get UID --folder FOLDER for content.",
        ),
        "icli mail folders" => Some(
            "List folders exposed by iCloud IMAP. Folder names can be passed to mail list, search, get, download, update, move, and delete.",
        ),
        "icli mail search" => Some(
            "Search message text in the selected folder using IMAP TEXT. Returns matching header summaries, newest UIDs first, after --skip and up to --limit. Defaults are --skip 0 and --limit 50. Use --folder to select a mailbox.",
        ),
        "icli mail get" => Some(
            "Read one message by its IMAP UID from mail list/search. Returns headers, parsed body, and MIME attachment part IDs using BODY.PEEK without marking the message read. Select the mailbox with --folder. UIDs are scoped to account and folder.",
        ),
        "icli mail download" => Some(
            "Download and decode one MIME attachment part. Get part IDs from `icli mail get UID --folder FOLDER`; the output path is written locally.",
        ),
        "icli mail create" => Some(
            "Save an unsent plain-text message in the selected account's Drafts folder. Requires --to, --subject, and --body. This creates a remote draft and does not send mail. Header line breaks are rejected. Returns recipient, subject, folder, and sent=false. The server does not return a draft UID through the current IMAP append operation.",
        ),
        "icli mail send" => Some(
            "Send a plain-text message through iCloud SMTP. Requires --to, --subject, and --body. Use commas to separate recipients. Header line breaks are rejected. Sending is a remote action and cannot be undone.",
        ),
        "icli mail update" => Some(
            "Change one message's state by UID in --folder. --flag accepts seen, unseen, flagged, or unflagged. This leaves message contents intact. A missing UID fails.",
        ),
        "icli mail delete" => Some(
            "Permanently delete one message by IMAP UID from --folder (INBOX by default). Requires --yes. Only the selected UID is expunged. This cannot be undone through iCLI.",
        ),
        "icli mail move" => Some(
            "Move one message by copying it to the destination folder and expunging the source UID. If copying fails, the source is retained. If source expunge fails, the result explains that the copy may already exist.",
        ),
        "icli contacts me" => Some(
            "Find the contact whose EMAIL exactly matches the selected account address, ignoring case. It does not infer identity from names or UIDs. Use --diagnose to show the configured account email, discovered address books, and identity fields (UID, FN, EMAIL, and Apple X- properties) for cards so you can inspect alternate identifiers without guessing. Use contacts list --include all for complete vCard properties.",
        ),
        "icli contacts groups list" => {
            Some("List vCards marked KIND:group with their MEMBER properties.")
        }
        "icli contacts groups create" => Some(
            "Create an Apple-compatible vCard group with a name and one or more contact UIDs. Members are stored as urn:uuid values.",
        ),
        "icli contacts groups update" => Some(
            "Replace a group's name and/or member list. Supplying --member values replaces the full membership list.",
        ),
        "icli contacts groups delete" => Some(
            "Permanently delete a contact group resource. Contact cards that were members are not deleted.",
        ),
        "icli calendar color" => Some(
            "Set the selected calendar's Apple calendar-color property. Provide #RRGGBB or #RRGGBBAA. Input and verified output use uppercase #RRGGBBAA; six-digit colors mean opaque (FF). The command reads the property back after setting it and reports when iCloud cannot confirm the stored value.",
        ),
        "icli calendar share list" => Some(
            "Read CalendarServer invitations and list sharees, their access level, and invitation status. Add --debug for redacted calendar-resource and current-user-principal diagnostics.",
        ),
        "icli calendar share grant" => Some(
            "Grant a person read or read/write access with the CalendarServer sharing extension. iCLI checks that the selected calendar is an owner copy that iCloud allows to be shared. Add --debug for redacted DAV request/response diagnostics.",
        ),
        "icli calendar share revoke" => Some(
            "Remove a person's CalendarServer share invitation. iCLI checks that the selected calendar is an owner copy. Add --debug for redacted DAV request/response diagnostics.",
        ),
        "icli calendar events delete" => Some(
            "Permanently delete one remote event by iCalendar UID and calendar selector. Requires --yes. An exact resource href can replace UID to resolve duplicates. Use calendar events list to find the UID; event titles are not identifiers. Returns UID, calendar, account, and deleted state.",
        ),
        _ => None,
    };
    if let Some(about) = override_about {
        command = command.long_about(about);
    }
    let example = match path.as_str() {
        "icli update" => "icli update\nicli update --check --json",
        "icli config default-user" => "icli config default-user person@icloud.com",
        "icli config format" => "icli config format json\nicli --format agent config format json",
        "icli auth add" if cfg!(windows) => {
            "Get-Content -Raw password.txt | icli auth add person@icloud.com --password-stdin\nicli auth add person@icloud.com"
        }
        "icli auth add" => {
            "icli auth add person@icloud.com --password-stdin < password.txt\nicli auth add person@icloud.com"
        }
        "icli auth app-password" => {
            "icli auth app-password person@icloud.com\nicli auth check --email person@icloud.com --app-password"
        }
        "icli auth verify" => {
            "icli auth verify person@icloud.com --code-stdin\nicli auth verify --email person@icloud.com --code-stdin"
        }
        "icli auth resend" => "icli auth resend person@icloud.com --method sms",
        "icli auth refresh" => "icli auth refresh\nicli auth refresh --email person@icloud.com",
        "icli auth check" => {
            "icli auth check\nicli auth check --email person@icloud.com --app-password"
        }
        "icli auth list" => "icli auth list --json",
        "icli auth remove" => "icli auth remove person@icloud.com",
        "icli reminders lists" => "icli reminders lists --email person@icloud.com",
        "icli reminders list" => {
            "icli reminders list --email person@icloud.com --limit 100\nicli reminders list --email person@icloud.com --skip 100 --limit 100"
        }
        "icli reminders get" => "icli reminders get REMINDER_ID --json",
        "icli reminders create" => {
            "icli reminders create --list LIST_ID --title \"Buy oat milk\" --due 2026-10-25\nicli reminders create --list LIST_ID --title \"Call Alex\" --due 2026-10-25T10:00:00+02:00 --priority 1"
        }
        "icli reminders update" => {
            "icli reminders update REMINDER_ID --title \"Updated title\"\nicli reminders update REMINDER_ID --clear-due --completed true"
        }
        "icli reminders set-status" => {
            "icli reminders set-status REMINDER_ID completed\nicli reminders set-status REMINDER_ID incomplete"
        }
        "icli reminders delete" => "icli reminders delete REMINDER_ID --yes",
        "icli reminders snapshot" => "icli reminders snapshot --list LIST_ID --json",
        "icli reminders changes" => "icli reminders changes --since CURSOR --limit 100",
        "icli reminders sync-cursor" => "icli reminders sync-cursor --json",
        "icli reminders alarm list" => "icli reminders alarm list REMINDER_ID",
        "icli reminders alarm add-location" => {
            "icli reminders alarm add-location REMINDER_ID --title Home --address \"Home\" --latitude 37.3318 --longitude -122.0312 --proximity arriving"
        }
        "icli reminders hashtag list" => "icli reminders hashtag list REMINDER_ID",
        "icli reminders hashtag create" => "icli reminders hashtag create REMINDER_ID errands",
        "icli reminders hashtag update" => {
            "icli reminders hashtag update REMINDER_ID HASHTAG_ID errands"
        }
        "icli reminders hashtag delete" => {
            "icli reminders hashtag delete REMINDER_ID HASHTAG_ID --yes"
        }
        "icli reminders attachment list" => "icli reminders attachment list REMINDER_ID",
        "icli reminders attachment create-url" => {
            "icli reminders attachment create-url REMINDER_ID --url https://example.com/checklist"
        }
        "icli reminders attachment update" => {
            "icli reminders attachment update REMINDER_ID ATTACHMENT_ID --url https://example.com/new-checklist"
        }
        "icli reminders attachment delete" => {
            "icli reminders attachment delete REMINDER_ID ATTACHMENT_ID --yes"
        }
        "icli reminders recurrence list" => "icli reminders recurrence list REMINDER_ID",
        "icli reminders recurrence create" => {
            "icli reminders recurrence create REMINDER_ID --frequency weekly --interval 1"
        }
        "icli reminders recurrence update" => {
            "icli reminders recurrence update REMINDER_ID RULE_ID --frequency monthly"
        }
        "icli reminders recurrence delete" => {
            "icli reminders recurrence delete REMINDER_ID RULE_ID --yes"
        }
        "icli calendar list" => {
            "icli calendar list --email person@icloud.com --include href,dsid,color"
        }
        "icli calendar create" => {
            "icli calendar create \"Project schedule\" --email person@icloud.com"
        }
        "icli calendar update" => "icli calendar update CALENDAR_ID --name \"New name\"",
        "icli calendar delete" => "icli calendar delete CALENDAR_ID --yes",
        "icli calendar events list" => {
            "icli calendar events list 2026-10-01 2026-10-31 --concurrency 4\nicli calendar events list 2026-10-01 2026-10-31 --calendar CALENDAR_ID --include url"
        }
        "icli calendar events search" => {
            "icli calendar events search planning\nicli calendar events search planning --from 2026-10-01 --to 2026-10-31 --calendar Work --field summary,location --skip 50 --limit 50"
        }
        "icli calendar events get" => {
            "icli calendar events get EVENT_UID --calendar CALENDAR_ID --include attendee,organizer"
        }
        "icli calendar events create" => {
            "icli calendar events create --calendar CALENDAR_ID --summary \"Planning\" --start 2026-10-20T10:00:00+02:00 --end 2026-10-20T11:00:00+02:00 --participant person@example.com --rrule FREQ=WEEKLY;BYDAY=MO --alarm-minutes 15\nicli calendar events create --calendar CALENDAR_ID --summary \"Holiday\" --all-day 2026-10-21"
        }
        "icli calendar events update" => {
            "icli calendar events update EVENT_UID --calendar CALENDAR_ID --summary \"Updated title\"\nicli calendar events update EVENT_UID --calendar CALENDAR_ID --participant person@example.com\nicli calendar events update EVENT_UID --calendar CALENDAR_ID --all-day 2026-10-22"
        }
        "icli calendar events delete" => {
            "icli calendar events delete EVENT_UID --calendar CALENDAR_ID --yes"
        }
        "icli calendar events import" => {
            "icli calendar events import events.ics --calendar CALENDAR_ID --concurrency 4"
        }
        "icli mail folders" => "icli mail folders --email person@icloud.com",
        "icli mail list" => {
            "icli mail list --folder INBOX --skip 20 --limit 20 --email person@icloud.com"
        }
        "icli mail search" => "icli mail search invoice --folder INBOX --skip 20 --limit 20",
        "icli mail get" => "icli mail get 123 --folder INBOX --email person@icloud.com",
        "icli mail download" => {
            "icli mail download 123 --folder INBOX --part 1.2 --output attachment.pdf"
        }
        "icli mail create" => {
            "icli mail create --to person@example.com --subject \"Meeting notes\" --body \"Here are the notes.\""
        }
        "icli mail send" => {
            "icli mail send --to person@example.com --subject \"Hello\" --body \"Message text\""
        }
        "icli mail update" => {
            "icli mail update 123 --flag seen\nicli mail update 123 --flag unflagged"
        }
        "icli mail delete" => "icli mail delete 123 --yes",
        "icli mail move" => "icli mail move 123 --source INBOX --destination Archive",
        "icli contacts list" => {
            "icli contacts list --include BDAY,ADR,X-SOCIALPROFILE\nicli contacts list --include all --skip 100 --limit 100"
        }
        "icli contacts search" => {
            "icli contacts search \"Alex Kim\"\nicli contacts search example.com --field email --include ORG --skip 50 --limit 50"
        }
        "icli contacts get" => "icli contacts get CONTACT_UID --include all",
        "icli contacts me" => {
            "icli contacts me --email person@icloud.com\nicli contacts me --diagnose"
        }
        "icli contacts groups list" => "icli contacts groups list",
        "icli contacts groups create" => {
            "icli contacts groups create --name \"Project team\" --member CONTACT_UID"
        }
        "icli contacts groups update" => {
            "icli contacts groups update GROUP_UID --member CONTACT_UID"
        }
        "icli contacts groups delete" => "icli contacts groups delete GROUP_UID --yes",
        "icli calendar color" => "icli calendar color CALENDAR_ID --color \"#3366CC\"",
        "icli calendar share list" => "icli calendar share list CALENDAR_ID",
        "icli calendar share grant" => {
            "icli calendar share grant CALENDAR_ID --person person@example.com --permission read"
        }
        "icli calendar share revoke" => {
            "icli calendar share revoke CALENDAR_ID --person person@example.com"
        }
        "icli contacts help" => "icli contacts help --email person@icloud.com --json",
        "icli contacts create" => {
            "icli contacts create --name \"Jane Doe\" --contact-email jane@example.com --property BDAY=1990-10-20 --property X-CUSTOM=example\nicli contacts create --vcard-file contact.vcf"
        }
        "icli contacts update" => {
            "icli contacts update CONTACT_UID --property EMAIL=one@example.com --property EMAIL=two@example.com\nicli contacts update CONTACT_UID --vcard-file changes.vcf"
        }
        "icli contacts delete" => "icli contacts delete CONTACT_UID --yes",
        _ => "",
    };
    let data_shape = match path.as_str() {
        "icli update" => {
            "object: current_version, latest_version, update_available, updated, check_only, target, executable, release_url. --check never replaces files. Current/newer versions are not downgraded. Downloads and checksum validation finish before replacement; failures return a structured error."
        }
        "icli config default-user" => "object: default_user",
        "icli config format" => "object: response_format",
        "icli auth add" | "icli auth verify" | "icli auth resend" | "icli auth refresh" => {
            "object: email, auth_state=verification_required|refresh_required|authenticated, apple_account_authenticated, trusted_session_saved, verification_method. A successful pending sign-in is exit 0, not an authentication failure."
        }
        "icli auth app-password" => {
            "object: email, default_user, app_specific_password_saved=true, verified=false"
        }
        "icli auth list" => "array of {email, default}; passwords are never returned",
        "icli auth remove" => "object: email, removed=true, default_user, accounts=[{email}]",
        "icli auth check" => {
            "default: object describing the valid Apple session. With --app-password: array of {service, status, authenticated, error?} for mail/calendar/contacts"
        }
        "icli reminders lists" => "array of {id, name, count}",
        "icli reminders list" => "array of {id, title, list_id, list, completed, due}",
        "icli reminders get"
        | "icli reminders create"
        | "icli reminders update"
        | "icli reminders set-status" => {
            "object: id, title, notes, list_id, parent_id, due, completed, priority, flagged, all_day, related IDs, timestamps"
        }
        "icli reminders delete" => "object: id, deleted=true",
        "icli reminders snapshot" => {
            "object: list, records={reminders, alarms, alarm_triggers, attachments, hashtags, recurrence_rules}"
        }
        "icli reminders changes" => {
            "object: changes=[updated/deleted events], cursor, more_available"
        }
        "icli reminders sync-cursor" => "object: cursor (opaque Apple CloudKit token)",
        "icli reminders alarm list"
        | "icli reminders hashtag list"
        | "icli reminders attachment list"
        | "icli reminders recurrence list" => {
            "array of related records attached to the selected reminder"
        }
        "icli reminders alarm add-location" => "object: alarm, trigger",
        "icli reminders hashtag create"
        | "icli reminders hashtag update"
        | "icli reminders attachment create-url"
        | "icli reminders attachment update"
        | "icli reminders recurrence create"
        | "icli reminders recurrence update" => {
            "object: related record with stable ID and selected fields"
        }
        "icli reminders hashtag delete"
        | "icli reminders attachment delete"
        | "icli reminders recurrence delete" => "object: id, deleted=true",
        "icli calendar list" => {
            "array of {name, id, href?, dsid?, color?}; optional fields are selected with --include; color is canonical uppercase #RRGGBBAA or null"
        }
        "icli calendar create" | "icli calendar update" => "object: id, href, name, email",
        "icli calendar delete" => "object: id, href, deleted=true, email",
        "icli calendar events list" | "icli calendar events get" => {
            "array of event objects: summary, start, end, location, description, uid, plus status/organizer/attendee when present and selected extra properties. Repeated properties are arrays; *_params contains associated parameters. Get can return recurring components sharing a UID. start/end preserve server iCalendar date/time representations. List can query calendars concurrently with --concurrency (1..8, default 2)."
        }
        "icli calendar events search" => {
            "array of matching events with the standard event fields and selected search properties. Match occurs when any selected field contains the query. Repeated properties are arrays; *_params contains associated parameters. Search can query calendars concurrently with --concurrency (1..8, default 2). Optional --include adds other iCalendar properties."
        }
        "icli calendar events create" => {
            "object: uid, summary, calendar, email, participants, invitation_status"
        }
        "icli calendar events update" => {
            "object: uid, calendar, email, updated=true, changed_properties, participants_added, invitation_status; invitation_status reports CalDAV server scheduling state when available, not recipient notification"
        }
        "icli calendar events delete" => "object: uid, calendar, email, deleted=true",
        "icli calendar events import" => {
            "array of {uid, status, created?=true, retries, attempt_errors, error?}; item status is success/error and error is structured. Each event write retries transient server and connection failures up to 2 times with backoff and Retry-After support. attempt_errors records each failed request, including errors recovered by a later retry. Successful writes remain after final failures. Import writes event resources concurrently with --concurrency (1..8, default 2)."
        }
        "icli mail folders" => "array of {name, delimiter, attributes}",
        "icli mail list" | "icli mail search" => "array of {uid, from, subject, date, folder}",
        "icli mail get" => {
            "object: uid, folder, from, to, subject, date, body, attachments=[{part_id, content_type, content_disposition}]"
        }
        "icli mail download" => "object: uid, folder, part, path, bytes",
        "icli mail create" => {
            "object: to, subject, folder=Drafts, sent=false; this IMAP operation does not return the draft UID"
        }
        "icli mail send" => "object: to, subject, sent=true",
        "icli mail update" => "object: uid, flag, updated=true",
        "icli mail delete" => "object: uid, deleted=true",
        "icli mail move" => "object: uid, source, destination, moved=true",
        "icli contacts list" | "icli contacts get" => {
            "array of {uid, name, emails, phones, birthday, properties?}; get returns one card. properties maps each vCard name to an array of {value, params}; params maps parameter names to their value arrays. value preserves vCard serialization, including escapes and photo encodings; it is not automatically decoded. Missing summary text is an empty string; absent optional properties are omitted."
        }
        "icli contacts search" => {
            "array of matching contact summaries. Each selected search property is also returned under properties. --include adds other vCard property values. Groups are excluded."
        }
        "icli contacts me" => {
            "one matching contact object with all vCard properties; with --diagnose, an object containing account_email, match_rule, addressbooks, contact_count, exact_match_uids, and identity-relevant cards"
        }
        "icli contacts groups list" => "array of contact objects with vCard properties",
        "icli contacts groups create" | "icli contacts groups update" => {
            "object: uid, name, members, created/updated=true"
        }
        "icli contacts groups delete" => "object: uid, deleted=true",
        "icli calendar color" => {
            "object: calendar, color (server-confirmed canonical RGBA or null), requested_color, updated=true, verified"
        }
        "icli calendar share list" => {
            "array of {principal, privileges, status}; with --debug, object contains redacted sharees and calendar-resource and current-user-principal diagnostics"
        }
        "icli calendar share grant" | "icli calendar share revoke" => {
            "object: calendar, person, permission, revoked, verified, invitation_status; grant reports the server's invitation status, not proof that the recipient has accepted"
        }
        "icli contacts help" => {
            "object: default_fields, standard_vcard_properties, properties_found_in_account, custom_properties_found_in_account, property_parameter_names_found_in_account, usage"
        }
        "icli contacts create" | "icli contacts update" => "object: uid, email, changed_properties",
        "icli contacts delete" => "object: uid, deleted=true",
        _ => "",
    };
    let file_example = if matches!(
        path.as_str(),
        "icli contacts create" | "icli contacts update"
    ) {
        "\n\nExample vCard file, UTF-8 text with one complete card. VERSION is required; UID is optional, but when supplied on update it must match the target. Use parameters after semicolons and structured components separated by semicolons. Escape literal commas/semicolons/backslashes with a backslash, and embedded newlines as \\n. Group prefixes pair values with Apple labels:\nBEGIN:VCARD\nVERSION:3.0\nFN:Jane Doe\nN:Doe;Jane;;;\nitem1.ADR;TYPE=HOME:;;One Street;Amsterdam;;1000 AA;Netherlands\nitem1.X-ABLabel:Home\nX-CUSTOM;TYPE=PRIVATE:Example\nEND:VCARD"
    } else {
        ""
    };
    let common = "Output: --json overrides --format, which overrides saved config, then agent is the default. JSON always contains ok, status, action, data, next_steps, warnings, error. Success has error=null; errors provide code, message, hint, help, retryable. Agent output labels Status, Result, IDs, Warnings, Next command. CSV lists use one row per result; mutations use one row; batches use one row per item. response_status is the overall result; status retains a resource/item status when present. Complete failures go to stderr; successful and partial results go to stdout. Explicit --help and --version remain readable text. Exit codes: 0 success, 1 operation failure, 2 invalid command/arguments, 3 partial success. Partial operations retain completed changes; inspect each item before retrying.\n\nAccount selection: All services use --email EMAIL, otherwise the saved default, otherwise the sole configured account. Apple sessions and app-specific passwords belong to the same account; a missing service credential returns its setup command. Calendar positional account forms remain compatibility aliases.\n\nRecovery: follow returned error.hint/Next command and scoped --help. Ambiguous resources return candidates; choose an exact identifier instead of retrying the same selector.";
    let pagination = if matches!(
        path.as_str(),
        "icli calendar events search"
            | "icli contacts list"
            | "icli contacts search"
            | "icli mail list"
            | "icli mail search"
    ) {
        let cost = if path.starts_with("icli mail") {
            "IMAP searches all matching UIDs on each call, then fetches headers only for the selected page. Missing or unreadable message headers can produce fewer rows than --limit; follow next_steps when present."
        } else {
            "Using --skip with --limit is not recommended for Calendar/Contacts: loading all matches in one call is faster than requesting multiple pages. CalDAV/CardDAV do not provide offset pagination for these queries, so iCLI downloads the complete matching scope, including skipped results, and applies the offset locally."
        };
        format!(
            "\n\nPagination: --skip defaults to 0 and counts matching results before --limit. For pages of 50, use --skip 0 --limit 50, then --skip 50 --limit 50. Negative values are rejected; --limit 0 or an offset beyond the matches returns an empty array. next_steps provides the next offset when more matches remain. Keep the query, filters, account, and scope unchanged between pages. Each call reads current data; additions, updates, or deletions can shift offsets. {cost}"
        )
    } else {
        String::new()
    };
    if path == "icli" {
        command = command.after_help(format!("Tasks:\n  Update iCLI: update [--check]\n  Set up Mail/Calendar/Contacts: auth app-password, then auth check --app-password\n  Set up Apple Reminders: auth add EMAIL, then auth verify EMAIL CODE\n  Select account/output: config default-user, config format\n  Find calendars: calendar list; set color/share: calendar color, calendar share\n  Read/search events: calendar events list|search|get; write: create|update|delete|import\n  Read/search/send mail: mail folders|list|search|get|download|create|send|update|move|delete\n  Read/search contacts: contacts list|search|get|me; write: create|update|delete; groups\n  Read and manage Apple Reminders: reminders\n  Discover contact properties: contacts help\n\nRun icli <command> --help for complete instructions.\n\n{common}"));
    } else if !example.is_empty() {
        let previous = command
            .get_after_help()
            .map(ToString::to_string)
            .unwrap_or_default();
        // Overrides describe the final option contract; avoid stale option summaries.
        let previous = if override_about.is_some() {
            String::new()
        } else {
            previous
        };
        command = command.after_help(format!("{previous}\n\nData returned: {data_shape}\n\nExamples:\n{example}{file_example}{pagination}\n\n{common}"));
    }
    for child in command.get_subcommands_mut() {
        let child_path = format!("{path} {}", child.get_name());
        *child = enrich(child.clone(), child_path);
    }
    command
}
