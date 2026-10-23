# iCLI MCP server

This local stdio server exposes one MCP tool for every command path reported by
the selected iCLI executable. It also exposes the root command as `icli`.
It uses Python 3.10 or newer and the standard library. No Python packages or
additional Rust dependencies are required.

## Build and run

Build iCLI from the repository root with Rust 1.85 or newer:

```sh
cargo build --release --bin icli
```

On Windows, start the server with:

```powershell
python mcp/server.py --icli .\target\release\icli.exe
```

On macOS or Linux:

```sh
python3 mcp/server.py --icli ./target/release/icli
```

The server waits for newline-delimited JSON-RPC on stdin. Stdout contains only
MCP messages. The client must initialize the session, then send
`notifications/initialized` before listing or calling tools. Protocol versions
2025-11-25, 2025-06-18, 2025-03-26, and 2024-11-05 are supported. Older versions
receive JSON in text content; newer versions also receive `structuredContent`.
The transport follows the [MCP stdio specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
and the [MCP tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).

Use absolute paths in an MCP client's configuration. For example, on Windows:

```json
{
  "mcpServers": {
    "icli": {
      "command": "C:/Python315/python.exe",
      "args": [
        "C:/path/to/icli/mcp/server.py",
        "--icli",
        "C:/path/to/icli/target/release/icli.exe"
      ]
    }
  }
}
```

Replace all three paths with your actual paths. The executable can also be
selected through `ICLI_MCP_BINARY`, or found as `icli` on `PATH`. `--icli` takes
precedence. The MCP process inherits the launching user's environment and uses
that user's iCLI configuration and operating system credential store. It does
not create a separate account configuration.

## Command and argument mapping

Tool names join command names with underscores and replace hyphens with
underscores. Examples:

- `icli config default-user` becomes `icli_config_default_user`.
- `icli calendar events import` becomes `icli_calendar_events_import`.
- `icli mail get` becomes `icli_mail_get`.
- `icli contacts help` becomes `icli_contacts_help`. This is the real account
  property discovery operation; call it with `args: ["--help"]` for instructions.

Every tool has the same input schema. `args` is an optional string array of
tokens after the tool's command path. Empty input means no trailing arguments.
Descriptions include the selected executable's full command help, including
required values, defaults, option interactions, side effects, and recovery hints.
The CLI validates these values. There is no second hand-maintained argument
schema. Positional aliases, optional command forms, repeated options, file paths,
comma-separated values, empty strings, and flags remain available.

For example, call `icli_calendar_events_list` with `--concurrency` to query
multiple calendars in parallel (the default is 2, and accepted values are 1
through 8):

```json
{
  "args": ["2026-10-20", "2026-10-21", "--concurrency", "6", "--include", "RRULE"]
}
```

The same option is available to `icli_calendar_events_import` for parallel
event writes. Imports retry transient server and connection failures up to two
times per event, using backoff and `Retry-After` when provided. Per-event
results include `retries` and structured `attempt_errors`, so recovered errors
remain visible; final failures still produce partial-success results.

Call `icli_contacts_get` with:

```json
{"args": ["example-contact-uid", "--include", "all"]}
```

No shell interprets these tokens. Do not add shell quotes around values that
contain spaces. A single value such as `Work calendar` is one array element.
Local file paths resolve relative to the server process's working directory;
absolute file paths avoid dependence on how the client launches the process.

For first-use setup, read [AGENT_GUIDE.md](../AGENT_GUIDE.md). `icli update`
also appears as `icli_update`; `args: ["--check"]` only checks release
availability. A normal update replaces the executable. Restart the MCP
adapter afterward so its command descriptions come from the updated help.
Source/package-managed installs should update using their original method.

Parent commands get tools too. `icli_calendar_events` retains the legacy event
listing form. Calling `icli_mail` or `icli_contacts` without a subcommand
returns the CLI help listing available operations without contacting iCloud;
provide a subcommand such as `list` to read account data. Groups that require
a subcommand return the CLI's usual missing-command error.
Generated `help` commands have their own tools and accept further command names
in `args`. `--help` and `--version` remain available wherever the CLI accepts
them and return readable text inside the structured result.

Discovery runs only `--help`, starting at the root and walking each `Commands:`
section. It makes no account requests. Generated `help` commands stop recursive
discovery. Real `contacts help` is inspected with `--help`, which does not read
contacts. Discovery fails at startup if a command's help fails or has an
unrecognized layout. The catalog covers the built executable, so rebuild iCLI
and restart the server after changing CLI commands. It will discover additional
Mail operations and any other new subcommands without server edits.

Print the complete catalog without starting an MCP session:

```powershell
python mcp/server.py --icli .\target\release\icli.exe --list-tools
```

## Credentials and writes

Configure credentials with iCLI first, or call `icli_auth_add` with the dedicated `password` input containing the Apple Account password. It starts sign-in and returns the pending state. Submit the code separately using `icli_auth_verify` with `{"args": ["account@example.com"], "code": "CODE_FROM_PRIVATE_INPUT"}`. Replace placeholders through the MCP client's private input handling. The adapter forwards secrets through child stdin with `--password-stdin` or `--code-stdin`, and redacts them from child output.

For Mail, Calendar, and Contacts, the recommended app-specific password belongs in the `password` input of `icli_auth_app_password`. `icli_auth_check` checks the saved Apple session by default. To check app-password services, pass `args: ["--app-password"]`; an optional `password` input checks that supplied value without saving it. `icli_auth_refresh` renews saved tokens and never requires a secret input. Follow recovery commands, then retry the original service operation.

Password/code flags and positional secrets in `args` are rejected, including calls through root/group tools. An explicit stdin flag requires its matching dedicated secret input. Input commands without a secret return a CLI error because the child has no interactive terminal. Migration: older MCP clients using `icli_auth_add` for app-specific passwords must use `icli_auth_app_password` instead. Restart the adapter after rebuilding the CLI to refresh its catalog.

The server does not log requests, CLI arguments, passwords, or account output.
MCP clients still receive the tool input and private account results; use a
trusted local client and its credential controls. Password and code inputs remain in
process memory and follow normal Python memory management.

Writes have the same effects as running the corresponding CLI command. Remote
deletions still require an explicit `"--yes"` token supplied by the caller. The
adapter never adds confirmation flags. Mail send sends mail when that command
exists in the selected build; mail create saves a draft. Account removal and
configuration commands change local state. Downloads write local files. Imports
can complete some items before failing; inspect their per-item results.

Calendar sharing commands use iCloud's CalendarServer invitations. Grant and
revoke change the invite list, and grant sends an invitation to the selected
person. The calendar must be an owner calendar that iCloud allows the account
to share. A shared copy cannot change its owner's invite list. Share results
include the permission and, for grants, the invitation status confirmed by a
readback.

## Results and limits

The server prepends `--json` to each invocation. This overrides `--format` and
the saved output format while retaining all other CLI argument behavior. Each
tool result contains:

- `command`, the tool's fixed CLI command path, without user argument values.
- `exit_code`, the CLI's actual process exit code.
- `result`, the parsed CLI JSON envelope, or `{ "text": "..." }` for readable
  help, version output, or a non-JSON diagnostic.
- `stderr`, the CLI's stderr text, retained even when stdout has a result.

Complete CLI failures can put their JSON envelope on stderr; the adapter parses
it when stdout is empty. CLI fields such as `ok`, `status`, `action`, `data`,
`next_steps`, `warnings`, `error`, and partial import results remain inside
`result`. Nonzero exit codes, including partial completion with exit code 3,
set MCP `isError: true`. Invalid MCP requests return JSON-RPC errors. Command
launch failures, credential-input errors, and timeouts return structured tool
errors. Tool results follow the [MCP result format](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).

Calls run sequentially. Set `--timeout SECONDS` to change the per-process limit
from 120 seconds. A timeout kills the direct child process and returns
`command_timeout`; completed remote changes cannot be rolled back. No automatic
retries occur. Cancellation notifications do not interrupt an active command.
Closing the client's stdin exits after the current call. Output is buffered in
memory, so very large reads/imports should be constrained using CLI options.

The adapter exposes CLI tokens rather than individual named JSON properties for
each CLI option. All commands and argument forms are forwarded except password
arguments, which use the dedicated stdin-backed input, and output format, which
is forced to JSON. It adds no service capabilities beyond those implemented in
the selected executable. This server does not imply Apple endorsement.
