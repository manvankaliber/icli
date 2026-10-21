---
title: Update iCLI
description: Update a release installation or rebuild iCLI from source.
---

# Update iCLI

## Update a release installation

```sh
icli update
icli update --check --json
```

`icli update` checks the latest stable GitHub release, downloads the binary
for the running platform, verifies its published SHA-256 checksum, and
replaces the running executable in place. The next invocation uses the new
version. It does not downgrade a current or newer version. `--check` only
reports availability and never downloads or replaces a binary.

The updater supports the published x86-64 and ARM64 Windows, macOS, and GNU
Linux binaries. It needs network access and write access to the executable
directory; it does not need an iCloud account or change account credentials.
It downloads and verifies the archive before replacing the executable.
Failures return the CLI's structured error envelope and recovery hint.

JSON output includes `current_version`, `latest_version`, `update_available`,
`updated`, `check_only`, `target`, `executable`, and `release_url`. Check
`updated` before claiming a replacement occurred. Restart any running local
MCP adapter after updating its executable so tool discovery uses new help.

Agents should check/update before their first iCLI task in a session, then
use the installed CLI's help for exact commands and options. Respect a
deliberate version pin. If updating fails, report it and continue with the
installed version when its help supports the task.

## Older releases without the updater

If `icli update --help` is unavailable, rerun the installer. It verifies the
archive checksum and updates the release installation.

### macOS or Linux

```sh
curl -fsSL https://raw.githubusercontent.com/manvankaliber/icli/main/install.sh | sh
```

### Windows PowerShell

```powershell
irm https://raw.githubusercontent.com/manvankaliber/icli/main/install.ps1 | iex
```

## Source and package-managed installations

Use the original installation method to preserve a source or package-managed
installation. For a source installation, update the checkout and reinstall:

```sh
git pull --ff-only origin main
cargo install --path . --force --locked
```

Rust 1.85 or newer is required to build from source.

For a package-managed installation, use that package manager's update
command. The native updater replaces the executable; it does not maintain
package-manager records or rebuild a source checkout.

## Build from source

Rust 1.85 or newer is required.

```sh
git clone https://github.com/manvankaliber/icli.git
cd icli
cargo build --release
cargo install --path . --force --locked
```

The build writes the binary to `target/release/`. `cargo install` installs it
to Cargo's binary directory so `icli` can run from your shell when that
directory is on `PATH`. To update a source installation, pull the latest
`main` and run the install command again.

Tests run without an iCloud account:

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

iCLI is independent and is not affiliated with or endorsed by Apple. Treat
command output as private account data. Keep passwords, tokens, and personal
calendar, mail, and contact values out of public bug reports.
