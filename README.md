<div align="center">
  <h1>☁️ iCLI</h1>
  <p><strong>iCloud, ready for your agents.</strong></p>
  <p>Connect agents to Apple's iCloud with a fast, safe CLI and clear guidance for services without an official Apple command-line tool.</p>
<p>📅 Calendar · 👥 Contacts · ✉️ Mail · ⏰ Reminders · 📝 Notes · ☁️ Drive · 📷 Photos</p>
  <p><strong>Agents:</strong> start with the <a href="AGENT_GUIDE.md">agent guide</a> for setup, authentication, and task workflows.</p>
</div>

[Quick start](#quick-start) | [Documentation](https://managing.software/docs/guide/usage/icloud-cli) | [Agent skills](skills/README.md) | [MCP setup](mcp/README.md)

## iCloud app coverage

![iCLI workflow coverage across iCloud apps, with a percentage and support label for each app.](assets/app-coverage-3x5.svg)

The percentage shows implemented workflows in the comparison below. “Supported” means all listed workflows for that app have a command; partially implemented apps remain “Unsupported.”

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
icli notes create --title "Trip plan" --body "Check train times and hotel options."
icli notes update NOTE_ID --body "Revised plain text body"
icli calendar events availability 2026-11-01 2026-11-07
icli reminders lists create "Errands"
icli contacts export --all --output-dir ./contacts
icli mail export-folder --folder INBOX --limit 100 --output-dir ./mail-export
icli drive list /
icli photos list --album Favorites --limit 50
icli photos download PHOTO_ID --size thumbnail --output ./photo-thumb.jpg
icli photos sync --directory ./icloud-photos --album Favorites
icli photos watch --directory ./icloud-photos --interval 300
icli photos shared-streams
icli photos shared-album "https://www.icloud.com/sharedalbum/#ALBUM_TOKEN" --limit 100
icli photos shared-album-download "https://www.icloud.com/sharedalbum/#ALBUM_TOKEN" --directory ./shared-photos
icli photos sync-cursor
icli photos changes --since CURSOR --limit 1000
icli find-my list --locate
icli find-my export DEVICE_ID --output ./device-snapshot.json
icli find-my sound DEVICE_ID
icli find-my message DEVICE_ID --text "Please call me"
icli find-my lost-mode DEVICE_ID --phone "+15550100" --yes
icli find-my erase DEVICE_ID --yes
icli account storage
icli invites list
icli invites resolve https://www.icloud.com/invites/SHORT_GUID
icli invites accept SHORT_GUID
icli invites rsvp EVENT_ID going --name "Sample Name"
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
| Check, renew, or log out of the saved session | `auth check`, `auth refresh`, `auth logout` |
| Save an app-specific password | `auth app-password EMAIL [--password-stdin]` |
| Ask Apple to log out all browser sessions | `auth logout --all-sessions --yes` |
| Check Mail, Calendar, and Contacts | `auth check --app-password` |
| Remove local credentials and sessions | `auth remove EMAIL` |

**Migration:** `auth add` now starts Apple Account sign-in. Scripts that used it to save app-specific passwords must use `auth app-password` instead, and add `--app-password` to their service checks. `auth apple-login` is a deprecated alias for `auth add` and now returns before code verification.

Run `icli version` or `icli --version` to see the installed version, executable installation timestamp, and last successful update check. When the executable is older than three months and no successful check ran in the last two weeks, the report recommends `icli update --check` to inspect availability or `icli update` to install the latest stable release. The version commands do not contact GitHub. Update iCLI with `icli update`; use `icli update --check` to check for a newer stable release without downloading it. Source builds and package-managed installations should use their original update method. A successful update takes effect the next time you run iCLI.

Run for example `icli mail` or any other `icli <category>` to see their available operations; these commands show help without contacting iCloud. Use `icli <command> --help` for accepted options and side effects. Connect an agent through the [local MCP adapter](mcp/README.md). Repository guidance for coding agents is in [AGENTS.md](AGENTS.md).

### Additional iCloud services

The CLI also has private-service command paths for iCloud Drive (`drive list`, `drive download`), Photos (`photos libraries|albums|shared-streams|list|get|download|sync|watch|changes|sync-cursor|shared-album|shared-album-download`), Find My (`find-my list|get|sound|message|lost-mode|export|erase`), Hide My Email (`hide-my-email`), account information (`account summary|devices|family|storage`), and Apple Invites (`invites list|show|rsvps|resolve|accept|rsvp`). These use Apple web-service endpoints that Apple does not publish as a stable public API. Treat these commands as experimental; endpoint behavior can change, and they have not been verified against a live account in this release. Find My can request fresh locations with `--locate`; its actions can make a device play a sound, show a message, enter Lost Mode, or request remote erase. Lost Mode and erase require `--yes`; erase is irreversible and also requires Apple to report the device as remotely erasable. `find-my export ID --output FILE` writes a local JSON snapshot without overwriting an existing file. Invites commands can join an event or submit/update the current user's response. Photos supports custom/smart album browse, original/medium/thumbnail downloads, safe local folder sync, polling watch, opaque incremental change cursors, listing account Shared Albums, and reading/downloading public Shared Albums from their iCloud URL. `photos watch` starts with a full sync and polls changes during that process; deleted assets are left in the local folder. Hide My Email commands can create, pause, resume, or delete aliases; deletion requires `--yes`.

Contacts can import vCards with `icli contacts import FILE` and export one or all contacts with `icli contacts export UID --output FILE` or `icli contacts export --all --output-dir DIR`. Mail can save an RFC822 message as `.eml` with `icli mail export UID --output FILE`, or export a bounded folder page with `icli mail export-folder --folder INBOX --limit 100 --output-dir DIR`. Calendar availability is inferred from visible, non-cancelled, non-transparent events and does not include calendars the account cannot read. Notes body search is available as `icli notes search QUERY --all --content`. `icli notes create --title TITLE [--body TEXT]` creates a basic text note; `icli notes update ID --title TITLE --body TEXT` replaces supplied fields. Plain-text updates rebuild the note body and do not preserve rich formatting; updates are refused for shared, deleted, or attachment-bearing notes. Apple Invites supports event listing/details, RSVP listing and submission, invite preview and acceptance with `icli invites list|show|rsvps|resolve|accept|rsvp`.

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

The comparison covers iCLI 1.3.0 and [pyicloud 2026.10.1](https://pypi.org/project/pyicloud/2026.10.1/), released October 15, 2026. It counts commands in the [released CLI command tree](https://github.com/timlaing/pyicloud/tree/2d3d137e17cdd06e4e58a4d0e0e400dccb31b08f/pyicloud/cli), not library methods or documentation alone. The source revision is [2d3d137](https://github.com/timlaing/pyicloud/commit/2d3d137e17cdd06e4e58a4d0e0e400dccb31b08f). Calendar sharing in iCLI uses iCloud invitations, and the list reports invitation status. The new Drive, Photos, Find My, Hide My Email, and account endpoints are private Apple web APIs and remain experimental; no live-account validation is claimed here. A newer release may change the comparison.

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
