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

Create an [Apple app-specific password](https://support.apple.com/en-us/102654), then save it with iCLI. In an interactive terminal, iCLI prompts without displaying the password:

```sh
icli auth add you@icloud.com
icli auth check you@icloud.com
```

The password is stored in your operating system credential store. For account selection, noninteractive password input, and output format options, see [Account and output settings](./account-and-output).

An agent should first inspect `icli auth list` and reuse an intended configured
account. If none is available, the human creates the app-specific password and
enters it through the local hidden prompt or a private secret input piped to
`--password-stdin`. Do not paste credentials into chat or command arguments.
Inspect the requested service's result from `auth check`; another service's
failure need not block it.

Start with a read command:

```sh
icli calendar list
icli contacts list
icli mail list
```

Each command's `--help` describes its options and side effects. See [Update iCLI](./updating) to update later.
