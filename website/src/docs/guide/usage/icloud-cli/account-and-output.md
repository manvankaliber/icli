---
title: Account and output settings
description: Configure iCLI accounts, credentials, and response formats.
---

# Account and output settings

## Configure iCloud access

### Sign in to Apple

Run `auth add EMAIL` with your Apple Account password, then `auth verify EMAIL CODE` when requested. Use `--password-stdin` and `--code-stdin` with private input for automation. The first configured account becomes default for all services. The Apple Account password is never saved; pending challenges and trusted sessions are stored in the OS credential store.

`auth check` contacts Apple without updating saved session data; `auth refresh` renews tokens. Neither prompts for input. Follow structured recovery commands, then retry your original operation. `auth resend --method device|sms` requests another code for a pending challenge. `auth apple-login` remains a deprecated alias for starting sign-in.

Migration: `auth add` previously saved an app-specific password. Use `auth app-password` for that operation now, and `auth check --app-password` for the old service checks.

### Prepare an Apple app-specific password

Before authenticating, read [Apple's current app-specific password
instructions](https://support.apple.com/en-us/102654). Create the password at
[account.apple.com](https://account.apple.com/). Apple requires two-factor
authentication for this flow.

Use the Apple Account email for the iCloud account and an app-specific
password. iCLI stores the password in the operating system credential store
and account addresses/defaults in a local TOML configuration file.

### Save credentials

With an interactive terminal, omit the password to use a hidden prompt:

```sh
icli auth app-password you@icloud.com
```

For agents, use `--password-stdin` and provide the password through stdin.
These examples read a file you have already supplied.

::: code-group

```sh [macOS / Linux]
icli auth app-password you@icloud.com --password-stdin < password.txt
```

```powershell [PowerShell]
Get-Content -Raw password.txt | icli auth app-password you@icloud.com --password-stdin
```

:::

`auth app-password` stores credentials locally without contacting Apple or validating
them. The first saved account becomes the default. Adding further accounts
preserves the current default and returns the command to change it.

| Input                                          | Behavior                                                                |
| ---------------------------------------------- | ----------------------------------------------------------------------- |
| `EMAIL` or `--email EMAIL`                     | Account address; choose one form                                        |
| Omitted password, terminal stdin               | Hidden prompt                                                           |
| Omitted password, noninteractive stdin         | Fails with guidance to use `--password-stdin`                           |
| `--password-stdin`                             | Reads until EOF and removes trailing line endings; empty input fails    |
| Positional `PASSWORD` or `--password PASSWORD` | Supported; may expose the password in shell history or process listings |

Password input forms cannot be combined. Passwords use Keychain on macOS,
Credential Manager on Windows, or the configured system keyring on Linux.
A headless environment needs a working credential store.

### Check each service

```sh
icli auth list
icli auth check --app-password --email you@icloud.com --json
```

`auth check --app-password` independently probes Mail, Calendar, and Contacts. It runs all
three checks even if one fails. By default it uses the saved password and
never prompts. A supplied password or `--password-stdin` checks that value
without changing the saved credentials.

```powershell
Get-Content -Raw password.txt | icli auth check --app-password --email you@icloud.com --password-stdin
```

Checks are read-only and do not verify write access. All services passing
produces exit `0`. Some passing produces `status: "partial"` and exit `3`.
None passing produces an error result on stderr and exit `1`. Each service
has its own `status`, `authenticated` flag, and structured error when it fails.

A logout warning after a successful Mail operation means the operation
completed, but the IMAP logout response could not be confirmed. Do not repeat
a completed write because of this warning.

### Choose the account

```sh
icli config default-user you@icloud.com
icli calendar list --email another@icloud.com
```

Account selection follows this order:

1. Explicit `--email EMAIL`.
2. The saved default account.
3. The sole configured account.
4. An error with the available account choices if several exist without a default.

Use `--email` for new scripts. Positional account forms in Calendar and Auth
remain available for compatibility. `auth list` returns account addresses
and whether each is the default, without returning passwords.

### Remove or replace credentials

```sh
icli auth remove you@icloud.com
```

This removes local account configuration and its saved credential. It does
not delete remote iCloud data. Removing the default automatically selects the
sole remaining account. If several remain, it clears the default and returns
commands for selecting one.

To replace an app-specific password, run `auth app-password EMAIL` again. It preserves the default and any Apple session. Restart Apple sign-in with `auth add EMAIL` if needed. Removing an account also deletes its pending challenge, trusted session, and all session credential chunks.

## Select the response format

```sh
icli config format agent
icli contacts list --format csv
icli --json calendar list
```

Format precedence is `--json`, then `--format`, then the saved format, then
`agent`. Global output flags can appear before or after the command.
`--json` wins when both flags are supplied.

`config format FORMAT` responds in the newly saved format unless this
invocation explicitly overrides it:

```sh
icli config format json
icli --format agent config format json
```

The second command saves JSON as the default but prints that response in
agent format.

### Agent output

The default format uses labeled sections: `Status`, `Action`, `Result`,
`IDs`, `Warnings`, and `Next command`. Result fields remain structured.
Successful writes return useful identifiers and, when available, a command
for inspecting the saved resource.

### JSON output

Reads and writes share the same top-level fields:

```json
{
  "ok": true,
  "status": "success",
  "action": "contacts.get",
  "data": [
    {
      "uid": "example-contact",
      "name": "Jane Doe",
      "emails": ["jane@example.com"],
      "phones": [],
      "birthday": "1990-10-20"
    }
  ],
  "next_steps": [],
  "warnings": [],
  "error": null
}
```

`data` depends on the command. List operations return arrays. Contact get and
event get also return arrays; recurring event components can share a UID.
Other get operations and single-resource mutations return objects. Imports
and auth checks return one row per event or service.

Read values from `.data` when piping to `jq`:

```sh
icli contacts list --json | jq '.data[].emails[]'
icli calendar list --json | jq '.data[] | {name, id}'
icli contacts help --json | jq '.data.properties_found_in_account'
```

### CSV output

CSV lists have one row per result, single-resource mutations have one row,
and batches have one row per item. Rows include the action, warnings, and
next steps. Nested arrays and objects are encoded as JSON within CSV cells.
`response_status` is the overall result. `status` retains a resource's status
or a batch item's status when present, otherwise it uses the overall status.
An empty list prints a header without data rows.

Explicit `--help` and `--version` always produce readable text.
