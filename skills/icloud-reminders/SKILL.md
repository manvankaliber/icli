---
name: icloud-reminders
description: Read and manage Apple Reminders, including due dates, completion, location alarms, hashtags, URL attachments, recurrence, and incremental sync, using iCLI. Applies to Reminders synced with iCloud. Requires an Apple Account session and does not operate on Calendar events or device-only data.
---

# Apple Reminders with iCLI

Read [references/agent-guide.md](references/agent-guide.md) for standalone setup, updating, private authentication, output handling, and recovery. Use an existing connected tool when it already meets the request.

Reminders uses a saved Apple Account session, not the app-specific password used by Calendar, Contacts, and Mail. Check `icli reminders --help` and the relevant leaf command's `--help` in the installed build. Apple may require trusted-device approval on the first read of encrypted Reminders data. Approve it and retry the command.

List Reminders lists with `icli reminders lists`, then read reminders with `icli reminders list` or `icli reminders get ID`. Use the stable IDs returned by iCLI and keep account scope consistent. Commands use the saved default account, or the sole configured account; pass `--email EMAIL` when the user selected another account. List reads include active and completed reminders and return 100 rows by default. Follow `next_steps` when paging with `--skip` and `--limit`.

Before a write, check the target IDs and requested changes. Create reminders in a list ID returned by `reminders lists`. Updates preserve fields that were not supplied. Due dates accept `YYYY-MM-DD` or RFC3339 date-times. All-day dates use UTC midnight. Set completion with `reminders set-status ID completed|incomplete` or the update command's `--completed` option. Use `--clear-due` to remove a due date. Priority ranges from 0 to 9.

The CLI can read lists but does not create, rename, or delete list records. Reminder deletes are remote soft-deletes and require `--yes`. The same explicit flag is required when deleting hashtags, URL attachments, or recurrence rules. A confirmed delete is limited to the target the user requested.

Supported related records include alarm reads and location-alarm creation, hashtags, URL attachments, and recurrence rules. Location alarms use coordinates, radius, and arrival or departure proximity. URL attachments store links, not uploaded files. Recurrence can be daily, weekly, monthly, or yearly, with an interval and optional occurrence count. Inspect the relevant subcommand help before changing related records.

For incremental sync, save the opaque cursor from `icli reminders sync-cursor` or a `reminders changes` response. Pass it unchanged as `--since` on the next `changes` call, keep the same account, and continue with the returned cursor while `more_available` is true. Do not edit or infer cursor contents.

Remote writes are separate operations and are not rolled back if a later command fails. Check each result. If a write's outcome is uncertain, read the target before retrying it. Follow structured `error.hint`, `error.help`, and `next_steps` when a command fails.

Detailed recipe: https://managing.software/docs/guide/usage/icloud-cli/reminders.md. Installed CLI help is the exact command reference.
