---
title: Agent guide
description: Install, authenticate, and complete iCloud tasks with iCLI as an agent.
---

# iCLI agent guide

Use iCLI to complete tasks in iCloud Calendar, Contacts, and Mail. If a connected tool already meets the request, use it. iCLI accesses iCloud data, including data synced from Apple apps; it does not access contacts, calendars, or messages stored only on a device or another provider.

Keep this operating procedure in context. For later tasks, use the installed CLI's help as the authority for commands, flags, defaults, and side effects. Do not infer options from old examples or research Apple protocols when CLI help answers the question.

## Install and update

Check whether `icli --version` works. If absent, install the latest published release for the current platform.

macOS or Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/manvankaliber/icli/main/install.sh | sh
```

Windows PowerShell:

```powershell
& ([scriptblock]::Create((Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/manvankaliber/icli/main/install.ps1')))
```

The installers verify the release archive checksum. Unix installs normally use `~/.local/bin/icli`; Windows uses `%LOCALAPPDATA%\Programs\icli\bin\icli.exe`. If the current process cannot find the command after installation, use its installed path or refresh PATH. Do not repeatedly reinstall because of a stale PATH.

Before the first iCLI task in each session, run `icli update`, then consult help from the resulting executable. This checks for a stable release and replaces an older release binary in place after checksum verification. It leaves current/newer versions alone. `icli update --check` only inspects availability. Respect deliberate version pins; update source/package-managed installs using their original method. If an older release lacks the updater, rerun its installer. After updating an MCP executable, restart that adapter before using its generated tools.

If updating fails, report it and continue when the installed version's help supports the task. Do not claim an update succeeded or assume unpublished features are available.

## Connect once

Run `icli auth list` to inspect configured accounts. Reuse the intended account. With several accounts, pass `--email EMAIL` rather than choosing silently.

If credentials are missing, explain the single human handoff: create an [Apple app-specific password](https://support.apple.com/en-us/102654), then authenticate locally. Apple requires two-factor authentication.

```sh
icli auth add you@icloud.com
icli auth check you@icloud.com
```

The first command uses a hidden terminal prompt. For noninteractive execution, use `icli auth add EMAIL --password-stdin` with a supported private secret source piped directly to stdin. Never ask for a password in chat, place it in command arguments, or include it in logs. When private input is unavailable, have the user run the hidden-prompt command locally. iCLI stores credentials in the operating system credential store. Inspect `auth check` per-service results; an unrelated service failure need not block the requested service.

## Find the operation

Start with `icli --help`, then the relevant command group and leaf help. Help is local; `icli contacts help` without `--help` instead reads account data to discover vCard properties.

- Calendars and event list/search: `icli calendar --help`, `icli calendar events --help`.
- Contacts and contact search/groups: `icli contacts --help`, `icli contacts groups --help`.
- Mail search, folders, drafts, sending, attachments: `icli mail --help`.
- Machine parsing: add `--json`. Human/agent text is the initial default; saved format settings may change it.

For text search, use `icli calendar events search QUERY`, `icli contacts search QUERY`, or `icli mail search QUERY`. Read each command's `--help` for field selection, date or folder scope, and matching rules before constructing a query.

Calendar event search, contact list/search, and mail list/search support `--skip N --limit N`. Start at `--skip 0` and follow `next_steps` for the next offset. Keep query and account/resource scope unchanged between pages. Calls read current data, so changes can shift offsets. For Calendar and Contacts, avoid requesting multiple pages when possible: CalDAV/CardDAV do not provide offset pagination for these queries, so iCLI downloads the full matching scope, including skipped results, on every call and applies offsets locally. A single call with a sufficiently large `--limit` is faster. Mail searches all matching UIDs but fetches headers only for the selected page.

Discover actual calendar IDs, contact/event UIDs, mail folder names, and message UIDs through list/search output. Preserve account and resource scope. Mail UIDs belong to a particular folder and account. Follow returned commands only when they advance the user's request.

## Finish and recover

JSON responses contain `ok`, `status`, `action`, `data`, `next_steps`, `warnings`, and `error`. Read the status and warnings before interpreting `data` or delivering an export. Exit codes are 0 for success, 1 for operation failure, 2 for invalid input, and 3 for partial success. Full failures go to stderr; successful and partial results go to stdout.

Use `error.hint`, `error.help`, and `next_steps` for recovery. Check per-item outcomes after partial writes and retry only unresolved items. Imports are not atomic. Import results preserve `retries` and `attempt_errors`, including recovered request failures. Inspect a remote resource before repeating a write whose outcome is uncertain.

Perform the requested actions within existing authorization. Remote deletes require `--yes`; it confirms an authorized deletion, not permission for a broader cleanup. Calendar sharing sends invitations, mail create saves a draft, and mail send delivers it. Use the operation the user requested.

For downloads, check range/limit completeness and distinguish structured JSON from native `.vcf`, `.ics`, or mailbox archives. Do not promise an export format the installed CLI cannot produce. Report the resulting artifact, completed work, and remaining failures without exposing private account data.

## Detailed recipes

- [Getting started](https://managing.software/docs/guide/usage/icloud-cli/getting-started.md)
- [Calendar tasks](https://managing.software/docs/guide/usage/icloud-cli/calendar.md)
- [Download and manage contacts](https://managing.software/docs/guide/usage/icloud-cli/contacts.md)
- [Search and manage mail](https://managing.software/docs/guide/usage/icloud-cli/mail.md)
- [Recovery](https://managing.software/docs/guide/usage/icloud-cli/recovery.md)

Use these when a workflow needs explanation. Use the installed CLI's help for the exact invocation.
