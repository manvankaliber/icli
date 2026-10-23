---
title: Apple Reminders
description: Sign in to Apple private services and read, edit, and sync Apple Reminders with iCLI.
---

# Apple Reminders

Apple Reminders is separate from Calendar events. iCLI connects to Apple's
private CloudKit Reminders service with a saved Apple Account session. Calendar,
Contacts, and Mail continue to use app-specific passwords.

The CLI reads Reminders lists but does not create, rename, or delete list
records. Commands use the saved default account, or the sole configured
account. Pass `--email EMAIL` to select another configured account.

## Sign in

Start sign-in and submit Apple's code separately:

```sh
icli auth add you@icloud.com
icli auth verify you@icloud.com
```

In a terminal the password and code use hidden prompts. Agents can pipe private
input to `auth add EMAIL --password-stdin` and `auth verify EMAIL --code-stdin`.
`auth add` exits after Apple requests verification. The Apple Account password
is never saved. Pending challenges, trusted tokens, and cookies are stored in
the OS credential store and reused by default. The first Reminders request may
ask Apple to approve encrypted data access on a trusted device; approve it and
retry the command.

## Read reminders

```sh
icli reminders lists
icli reminders list --limit 100
icli reminders get REMINDER_ID
icli reminders snapshot --list LIST_ID
```

List results include stable IDs. Reminder reads return active and completed
items, with list, due date, notes, flags, priority, and related record IDs where
available. `list` defaults to 100 rows; follow `next_steps` and keep the account
scope unchanged when paging with `--skip` and `--limit`. Snapshots include
reminders and related alarms, triggers, attachments, hashtags, and recurrence
rules. The snapshot limit applies per record type; `truncated_types` names any
arrays capped by that limit.

## Create and edit reminders

```sh
icli reminders create --list LIST_ID --title "Call the dentist" --due 2026-10-27
icli reminders update REMINDER_ID --title "Call the clinic" --notes "Ask about Tuesday"
icli reminders update REMINDER_ID --clear-due
icli reminders set-status REMINDER_ID completed
icli reminders delete REMINDER_ID --yes
```

Due dates accept `YYYY-MM-DD` or RFC3339 date-times. All-day dates are
interpreted at UTC midnight. Create supports priority 0 through 9 and a flagged
state. Updates change only the fields supplied; use `--clear-due` to remove a
due date or `--all-day true|false` to change its all-day status. Completion can
be set with `set-status` or the update command's `--completed` option. Deletes
set Apple's deleted marker so sync clients can process the change; `--yes` is
required for remote deletion.

## Related records

```sh
icli reminders alarm list REMINDER_ID
icli reminders alarm add-location REMINDER_ID --latitude 37.3349 --longitude -122.0090 --proximity arriving
icli reminders hashtag list REMINDER_ID
icli reminders hashtag create REMINDER_ID work
icli reminders attachment list REMINDER_ID
icli reminders attachment create-url REMINDER_ID --url https://example.com
icli reminders recurrence create REMINDER_ID --frequency weekly --interval 1
```

The available alarm commands list alarms and add a location alarm. Location
alarms use latitude, longitude, radius, and arrival or departure proximity.
Hashtags, URL attachments, and recurrence rules have `list`, `create`, `update`,
and `delete` subcommands. Hashtag names omit the leading `#`. URL attachment
commands manage links, not uploaded files. Recurrence frequency is daily,
weekly, monthly, or yearly; `--interval` sets how many frequency units to wait,
and an occurrence count of zero means no fixed count. Related-record deletes
also require `--yes`.

## Incremental sync

```sh
icli reminders sync-cursor
icli reminders changes --since CURSOR
```

Save the opaque cursor from `sync-cursor` and pass it unchanged as `--since` to
`changes`. Keep the same account between calls. After each response, save its
returned cursor. If `more_available` is true, call again with that cursor. Do
not edit or interpret cursors.

The private Apple interfaces may change. Use `icli reminders --help` and each
subcommand's `--help` for the behavior supported by the installed build.
