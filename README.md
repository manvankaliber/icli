# iCLI

**Give your agent access to iCloud Calendar, Contacts, Mail, Apple Reminders, and Notes.**

iCLI is an agent-first command-line tool written in Rust. It provides dedicated commands and structured output for iCloud Calendar, Contacts, Mail, Apple Reminders, and Apple Notes. Calendar, Contacts, and Mail use app-specific passwords. Reminders and Notes use a saved Apple Account session and Apple's private CloudKit service. Notes supports browsing, recent or full-zone title search, attachment metadata and downloads, text/Markdown/HTML export with local attachment copies, incremental changes, and guarded soft deletion of unshared notes.

Use the CLI directly or connect an agent through the local MCP adapter. Each operation reports structured results and recovery instructions. Calendar batch operations support bounded concurrency.

Use the same CLI yourself, or connect an agent through the local MCP adapter. 

**Agents: start with [AGENT_GUIDE.md](AGENT_GUIDE.md).** It covers installation, updating, authentication, and how to use the CLI to complete any supported task.

[Quick start](#quick-start) | [Documentation](https://managing.software/docs/guide/usage/icloud-cli) | [Agent skills](skills/README.md) | [MCP setup](mcp/README.md)

## iCloud app coverage

Calendar, Contacts, and Mail cover every workflow listed for those apps in the comparison below. For Apple Reminders, iCLI can read lists and reminders, create and update reminders, change completion status, soft-delete records, read snapshots and incremental changes, and manage alarms, hashtags, URL attachments, and recurrence rules. Apple Notes support includes browsing folders and notes, searching recent or all titles, reading note text and attachment metadata, downloading linked attachment files, exporting text/Markdown/HTML with local asset copies, reading incremental changes, and soft-deleting unshared notes. HTML and Markdown preserve decoded text and include available attachments; they do not reconstruct every rich Notes style. The comparison marks workflows that still have no matching command.

Calendar supports event search, recurrence, alarms, sharing, imports, and parallel queries. Contacts supports search, selected or complete property data, card updates, and groups. Mail supports folders, search, attachments, drafts, sending, flags, moves, and deletion. Reminders supports reads and writes for reminder records and their supported related records. Notes reads text and attachment metadata, downloads assets, and exports local text, Markdown, or HTML through Apple's private CloudKit service. These operate on iCloud data; data stored only on a device or another provider is outside iCLI's scope.

![iCLI workflow coverage across iCloud apps, with a percentage and stage for each app.](assets/app-coverage.svg)

Each percentage is iCLI's share of the workflows exposed by either CLI for that app. Each workflow counts once. A 100% score means iCLI covers every listed workflow, not every feature in Apple's app. "No CLI coverage" means neither tool exposes a command for that app. Notes coverage refers to the listed workflows, not full Notes feature parity. App icons come from [Apple's iCloud guide](https://support.apple.com/guide/icloud/mm203ae070a2).

## Quick start
**We recommend you task your agent to do the work below for you.** 

Install the latest release:

On Linux and macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/manvankaliber/icli/main/install.sh | sh
```

On Windows PowerShell:

```powershell
& ([scriptblock]::Create((Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/manvankaliber/icli/main/install.ps1')))
```

Start Apple Account sign-in, then submit Apple's code with a separate command:

```sh
icli auth add you@icloud.com
icli auth verify you@icloud.com
icli reminders lists
icli reminders list --limit 100
icli notes folders
icli notes recent --limit 50
icli notes search "project plan" --all --limit 20
icli notes get NOTE_ID --with-attachments
icli notes download NOTE_ID --output-dir ./note-assets
icli notes export NOTE_ID --output ./note.md --export-format markdown
icli notes export NOTE_ID --output ./note.html --export-format html
```

The password and code use hidden prompts in a terminal. Agents can pipe private input to `auth add EMAIL --password-stdin` and `auth verify EMAIL --code-stdin`. Follow `data.auth_state` and `next_steps`: starting a pending sign-in succeeds with `verification_required` and exits immediately. The Apple Account password is never saved. Pending challenges, trusted tokens, and cookies are stored in the operating system credential store and reused by subsequent commands.

`icli auth check` checks the saved session without changing it. `icli auth refresh` renews saved tokens. When authentication needs attention, follow the returned recovery command, then retry the original service command. Request another code with `icli auth resend --method device` or `--method sms`. SMS requires an Apple-provided trusted phone. Newer bridge-only challenges and hardware security keys remain unsupported.

For Mail, Calendar, and Contacts, we recommend an [Apple app-specific password](https://support.apple.com/en-us/102654). Those backends currently require one; Apple Account sign-in alone does not unlock them. Save it on the same account, or create an app-password-only account without Apple sign-in:

```sh
icli auth app-password you@icloud.com
icli auth check --app-password
icli calendar list
icli contacts list
icli mail list
```

The first configured account becomes the default for every service. Select another with `--email EMAIL` or `icli config default-user EMAIL`. Adding or replacing either credential preserves the other and the current default.

| Authentication task | Command |
| --- | --- |
| Start Apple sign-in | `auth add EMAIL [--password-stdin]` |
| Complete verification | `auth verify EMAIL [--code-stdin]` |
| Request another code | `auth resend [--method device\|sms]` |
| Check or renew the saved session | `auth check`, `auth refresh` |
| Save an app-specific password | `auth app-password EMAIL [--password-stdin]` |
| Check Mail, Calendar, and Contacts | `auth check --app-password` |
| Remove local credentials and sessions | `auth remove EMAIL` |

**Migration:** `auth add` now starts Apple Account sign-in. Scripts that used it to save app-specific passwords must use `auth app-password` instead, and add `--app-password` to their service checks. `auth apple-login` is a deprecated alias for `auth add` and now returns before code verification.

Run `icli version` or `icli --version` to see the installed version, executable installation timestamp, and last successful update check. When the executable is older than three months and no successful check ran in the last two weeks, the report recommends `icli update --check` to inspect availability or `icli update` to install the latest stable release. The version commands do not contact GitHub. Update iCLI with `icli update`; use `icli update --check` to check for a newer stable release without downloading it. Source builds and package-managed installations should use their original update method. A successful update takes effect the next time you run iCLI.

Run for example `icli mail` or any other `icli <category>` to see their available operations; these commands show help without contacting iCloud. Use `icli <command> --help` for accepted options and side effects. Connect an agent through the [local MCP adapter](mcp/README.md). Repository guidance for coding agents is in [AGENTS.md](AGENTS.md).

The calendar command also accepts `agenda` and the common typo `calender` as aliases, for example `icli agenda list`.

For an existing release installation, run `icli update` to check and install the latest stable binary, or `icli update --check` to inspect availability. Older releases without that command can rerun the installer. Source and package-managed installations should use their original update method. Published releases can lag behind `main`; consult your installed command's help.

## Documentation

- [Getting started](https://managing.software/docs/guide/usage/icloud-cli/getting-started): installation and authentication.
- [Calendar](https://managing.software/docs/guide/usage/icloud-cli/calendar): search events, import events, share calendars, and download calendars.
- [Contacts](https://managing.software/docs/guide/usage/icloud-cli/contacts): search and download contacts, discover properties, and manage cards.
- [Mail](https://managing.software/docs/guide/usage/icloud-cli/mail): search, attachments, drafts, sending, and folders.
- [Apple Reminders](https://managing.software/docs/guide/usage/icloud-cli/reminders): sign in, read and edit reminders, sync changes, and manage supported related records.
- [Apple Notes](https://managing.software/docs/guide/usage/icloud-cli/notes): browse folders and notes, search titles, read or export text, and sync changes.
- [Updating](https://managing.software/docs/guide/usage/icloud-cli/updating) and [recovery](https://managing.software/docs/guide/usage/icloud-cli/recovery).
- [Agent skills](skills/README.md), [agent guide](AGENT_GUIDE.md), and [agent documentation index](https://managing.software/llms.txt).

## Compare CLI workflows

Each card groups workflows by iCloud app. A green check means the CLI has a command for that workflow. A red cross means it does not. The app icon sits in the card's top-right corner.

![Feature-by-feature comparison of iCLI and pyicloud command-line workflows, grouped into app cards, plus a shared CLI access card.](assets/feature-comparison.svg)

The comparison covers iCLI 1.2.0 and [pyicloud 2026.10.1](https://pypi.org/project/pyicloud/2026.10.1/), released October 15, 2026. It counts commands in the [released CLI command tree](https://github.com/timlaing/pyicloud/tree/2d3d137e17cdd06e4e58a4d0e0e400dccb31b08f/pyicloud/cli), not library methods or documentation alone. The source revision is [2d3d137](https://github.com/timlaing/pyicloud/commit/2d3d137e17cdd06e4e58a4d0e0e400dccb31b08f). Calendar sharing in iCLI uses iCloud invitations, and the list reports invitation status. A newer release may change the comparison.

## Benchmarks

No measurements yet. The zeroes below are placeholders marked `TBD`.

![Benchmark placeholders for command latency, task time, model tokens, task success, and local resource use. All values are zero and marked TBD.](assets/benchmark-placeholders.svg)

The scenarios below turn those measures into repeatable tasks. Values remain TBD until runs use the same account snapshot, model, and tool setup. Compare equivalent workflows only; pyicloud has no native Mail commands, so the email-draft scenario is not a like-for-like comparison. Keep direct CLI runtime separate from agent time and model cost.

![Planned performance scenarios and the measurements to collect: annual meeting report, event and contact lookup, email draft, and direct CLI runtime. Results are TBD.](assets/benchmark-scenarios.svg)

For each scenario, record repeated runs, median and p95 time, task success, and the relevant resource costs. The direct-runtime scenario excludes model calls; agent scenarios should include model tokens and API cost.

## Build and contribute

Building from source requires Rust 1.85 or newer. Run `cargo build --release`. See [AGENTS.md](AGENTS.md) for project guidance, [CONTRIBUTING.md](CONTRIBUTING.md) for pull requests, and [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

MIT. See [LICENSE](LICENSE).

Independent project. Not affiliated with or endorsed by Apple.
