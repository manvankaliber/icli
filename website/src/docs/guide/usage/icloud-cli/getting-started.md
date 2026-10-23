---
title: Getting started
description: Install iCLI and connect your iCloud account.
---

# Getting started

Agents can start with the [agent guide](./agent-guide), which combines setup
and the operating procedure in one short document. If an existing connected
tool already completes the user's request, it can be used directly.

## Install

Install the latest published release without installing Rust.

### macOS or Linux

```sh
curl -fsSL https://raw.githubusercontent.com/manvankaliber/icli/main/install.sh | sh
```

The installer supports x86-64 and ARM64, checks the downloaded archive's
SHA-256 checksum, and installs to `~/.local/bin`. Set `ICLI_INSTALL_DIR` to
choose another directory. It adds the directory to shell startup files when
needed. Open a new terminal if `icli` is not immediately on `PATH`.

### Windows PowerShell

```powershell
irm https://raw.githubusercontent.com/manvankaliber/icli/main/install.ps1 | iex
```

The installer supports x64 and ARM64 Windows, verifies the archive checksum,
and installs to `%LOCALAPPDATA%\Programs\icli\bin`. It updates your user
`PATH` and the current PowerShell session.

Both installers require a published GitHub release with a binary for your
platform. Run `icli update` to update a release installation later. For an
older release without that command, rerun the installer.

## Connect your iCloud account

Start Apple Account sign-in, then submit the code in a separate command:

```sh
icli auth add you@icloud.com
icli auth verify you@icloud.com
icli auth check
icli reminders lists
```

In a terminal, the password and code use hidden prompts. For agents, pipe private input into `auth add EMAIL --password-stdin` and `auth verify EMAIL --code-stdin`. Do not paste secrets into chat or command arguments. Follow the returned `auth_state` and `next_steps`; `auth add` exits after requesting verification. The OS credential store holds pending and trusted session data, so later commands reuse sign-in. The Apple Account password is never saved. `auth refresh` renews saved tokens; after authentication recovery, retry the original command.

For Calendar, Contacts, and Mail, create a recommended [Apple app-specific password](https://support.apple.com/en-us/102654) and save it on the same account:

```sh
icli auth app-password you@icloud.com
icli auth check --app-password
```

These backends currently require an app-specific password. `auth app-password` also supports setup without Apple Account sign-in and accepts `--password-stdin`. Inspect the requested service's result; an unrelated service failure need not block it. For account selection and formats, see [Account and output settings](./account-and-output).

Migration: older scripts using `auth add` for app-specific passwords must use `auth app-password` and check with `auth check --app-password`. `auth apple-login` is a deprecated alias for starting sign-in; verification is now separate.

Start with a read command:

```sh
icli calendar list
icli contacts list
icli mail list
```

Each command's `--help` describes its options and side effects. See [Update iCLI](./updating) to update later.
