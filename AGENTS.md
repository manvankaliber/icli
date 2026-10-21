# Contributor agent guide

This file gives coding agents the project context and contribution rules. Agents using iCLI to perform iCloud tasks should read [AGENT_GUIDE.md](AGENT_GUIDE.md). For the product introduction and human setup, see [README.md](README.md). The CLI's own help is the source of truth for command behavior in a specific build: run `icli --help`, then `icli <command> --help`.

## Project overview

iCLI is a Rust command-line tool for iCloud Calendar, Contacts, and Mail. It connects through CalDAV, CardDAV, and IMAP. Its default output is intended for agents, with stable resource identifiers, follow-up suggestions, structured errors, and recovery hints. JSON and CSV formats are also available.

The project is independent of Apple. Changes should not imply Apple endorsement or use private iCloud data in fixtures, examples, or reports.

## Repository map

- `src/main.rs` defines the CLI commands and much of their behavior.
- `src/help.rs` contains detailed command help text.
- `src/update.rs` checks stable releases, verifies archives, and updates the executable.
- `AGENT_GUIDE.md` is the consumer agent operating procedure. `skills/` packages it for individual agent skills.
- `scripts/sync-agent-docs.mjs` generates bundled skill references, the website agent guide, and `llms.txt`; use `--check` to detect drift.
- `tests/` contains integration and behavior tests.
- `README.md` documents user workflows and the current feature comparison.
- `CONTRIBUTING.md` has contribution and pull request guidance.
- `SECURITY.md` explains how to report vulnerabilities.

## Working rules

- Keep changes focused on the CLI and its iCloud integrations.
- Keep command help accurate about prerequisites, defaults, option interactions, output, side effects, and recovery steps.
- Preserve the output contract across agent text, JSON, and CSV. Keep errors structured and actionable.
- Remote deletes must keep their explicit `--yes` confirmation. Do not make multi-item imports appear atomic; report completed and failed items.
- Contact updates should preserve omitted properties and use server ETags for concurrent-change detection when available.
- Credentials belong in the operating system credential store. Do not log passwords, tokens, cookies, or private iCloud data.
- Tests should not need a live iCloud account. For live integration work, use a test account and app-specific password, prefer reads, and report whether account data changed.

## Build and test

The project requires Rust 1.85 or newer.

```sh
cargo build
cargo test
```

Tests should run without an iCloud account. Live requests can read or change real account data, so inspect the target before any write.

## Before handing off

Update README feature and comparison rows when behavior changes. Run the checks relevant to the change, review the final diff, and report any live iCloud testing or account changes. Never include credentials or personal calendar, mail, or contact data in the handoff.
