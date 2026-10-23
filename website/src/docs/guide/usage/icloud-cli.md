---
title: iCloud CLI
description: Use iCLI to work with iCloud Calendar, Contacts, Mail, and Apple Reminders from the command line.
---

# iCloud CLI

iCLI reads and manages iCloud Calendar, Contacts, and Mail through CalDAV,
CardDAV, and IMAP. Apple Reminders uses a separate private CloudKit integration
with reads, writes, and incremental sync.
It provides command help, explicit identifiers, structured
results, and recovery instructions for agents and shell scripts.

**Using an agent? Start with the [agent guide](./icloud-cli/agent-guide).**
It covers installation, updating, private authentication, and how to discover
the right command from the installed CLI. [Standalone skills](./icloud-cli/skills)
provide the same setup for Calendar, Contacts, Mail, and cross-app tasks.

The [agent documentation index](/llms.txt) links to clean Markdown versions.
iCLI works with iCloud-hosted data, including data synced from Apple apps.
Data stored only on a device or with another provider is outside its scope.

This guide describes the current source on `main`. Published release binaries
can lag behind it. Run `icli --version` and the relevant command's `--help` to
check your installed version. [Update iCLI](./icloud-cli/updating) to use
changes that have not reached a published release.

## Find the command for a task

| Task                                                              | Command                                                                     |
| ----------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Save credentials for Calendar, Contacts, and Mail                 | `icli auth app-password`                                                    |
| Sign in to Apple private services for Reminders                   | `icli auth add EMAIL`, `icli auth verify EMAIL CODE`                        |
| Check service authentication                                      | `icli auth check`, `icli auth check --app-password`                         |
| List or remove local accounts                                     | `icli auth list`, `icli auth remove`                                        |
| Set account or output defaults                                    | `icli config default-user`, `icli config format`                            |
| Find or manage calendars                                          | `icli calendar list/create/update/delete/color/share`                       |
| Read, search, or manage events                                    | `icli calendar events list/search/get/create/update/delete/import`          |
| Discover Mail operations                                          | `icli mail`                                                                 |
| Discover Contacts operations                                      | `icli contacts`                                                             |
| Read, edit, or sync Apple Reminders                               | `icli reminders`                                                            |
| Discover contact properties                                       | `icli contacts help`                                                        |
| Read, search, or manage contacts and groups                       | `icli contacts list/search/get/me/create/update/delete/groups`              |
| Search mail, download attachments, draft/send, or manage messages | `icli mail folders/list/search/get/download/create/send/update/move/delete` |

Slash-separated command names in this table are alternatives. For example,
run `icli contacts list` or `icli contacts get CONTACT_UID`.
Running `icli mail` or `icli contacts` displays the available subcommands
without contacting iCloud. Choose an operation such as `list` explicitly to
read account data.

Calendar event search, contact list/search, and mail list/search support
`--skip N --limit N` for offset pagination. Start with `--skip 0` and follow
`next_steps` for the next offset. Keep the query and account/resource scope
unchanged between pages. Each call reads current data, so changes can shift
offsets. Using multiple pages for Calendar or Contacts is not recommended:
CalDAV/CardDAV download all matches, including skipped results, on every call,
so one call with a sufficiently large `--limit` is faster. Mail fetches headers
only for the selected page. See each command's `--help` for ordering and defaults.

```sh
icli --help
icli auth add --help
icli calendar events create --help
icli contacts update --help
```

Each leaf command's help describes its arguments, defaults, interactions,
returned data, examples, side effects, and recovery steps. `contacts help`
is an account-aware property discovery command; `contacts --help` explains
how to use the contact commands.

Event listing across calendars and iCalendar imports can run independent
CalDAV requests concurrently. Use `--concurrency 1..8` on `calendar events list`
or `calendar events import`; both default to two requests. See the
[calendar guide](./icloud-cli/calendar) for details.

## Guides

- [Getting started](./icloud-cli/getting-started): install iCLI and connect your iCloud account.
- [Agent guide](./icloud-cli/agent-guide): the compact operating procedure for task-oriented agents.
- [Agent skills](./icloud-cli/skills): install one standalone app skill or the four-skill bundle.
- [Update iCLI](./icloud-cli/updating): install the latest release or update a source build.
- [Account and output settings](./icloud-cli/account-and-output): manage credentials, accounts, and response formats.
- [Calendar](./icloud-cli/calendar): manage calendars and events.
- [Contacts](./icloud-cli/contacts): find, create, and update contacts.
- [Mail](./icloud-cli/mail): read messages, save drafts, and manage flags.
- [Apple Reminders](./icloud-cli/reminders): sign in, read and edit reminders, sync changes, and manage supported related records.
- [Errors and recovery](./icloud-cli/recovery): interpret failures and partial results.

Use `icli --help` and `icli <command> --help` for options and side effects in your installed version. iCLI is an independent project and is not affiliated with or endorsed by Apple.
