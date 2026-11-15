# iCLI

A stable, agent-friendly CLI for iCloud. Project complete; the CLI remains the product.

**Apps:** Calendar, Contacts, Mail, Reminders, Notes, Drive, Photos, Find My, Hide My Email, and Apple Invites. Account and storage commands are also included. Available operations and service limitations are documented in the [agent guide](AGENT_GUIDE.md) and command help.

## Install

macOS / Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/manvankaliber/icli/main/install.sh | sh
```

Windows PowerShell:

```powershell
& ([scriptblock]::Create((Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/manvankaliber/icli/main/install.ps1')))
```

## Connect and use

For Calendar, Contacts, and Mail, save an [Apple app-specific password](https://support.apple.com/en-us/102654):

```sh
icli auth app-password you@icloud.com
icli calendar list
icli mail list
```

For the other services, sign in with your Apple Account:

```sh
icli auth add you@icloud.com
icli auth verify you@icloud.com
icli notes recent
```

Passwords and verification codes use hidden terminal prompts. Agents: follow the [private-input instructions](AGENT_GUIDE.md#connect-once).

Use `icli <command> --help` to discover operations, `--json` for structured results, and `--email EMAIL` to select an account. Update release installations with `icli update`.

[Agent guide](AGENT_GUIDE.md) ? [Agent skills](skills/README.md) ? [Optional local MCP adapter](mcp/README.md)

## Development

Rust 1.88+: `cargo build --release` and `cargo test`.
See [AGENTS.md](AGENTS.md), [contributing](CONTRIBUTING.md), and [security](SECURITY.md).

[MIT license](LICENSE). Independent project; not affiliated with Apple.
