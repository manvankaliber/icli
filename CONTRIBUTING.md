# Contributing

Thanks for helping improve iCLI. Keep changes focused on the command-line interface and its iCloud integrations.

## Before you start

- Check existing issues and pull requests for related work.
- For a larger change, open an issue first to agree on its scope.
- Do not include credentials or personal iCloud data in issues, commits, or test fixtures.

## Development

You need Rust 1.85 or newer.

```sh
cargo build
cargo test
```

Tests should run without an iCloud account. If you need to exercise live iCloud requests, use a test account and app-specific password. Live commands can read or change real account data, so prefer read operations and verify any target before writing.

## Documentation and agent skills

`README.md` introduces the product. `AGENT_GUIDE.md` is the short operating
procedure for agents using iCLI; `AGENTS.md` is contributor guidance. Detailed
workflows belong in `website/src/docs/guide/usage/icloud-cli/`. Exact command
behavior belongs in CLI help, not a second handwritten flag catalog.

After editing the agent guide or discovery links, run:

```sh
node scripts/sync-agent-docs.mjs
node scripts/sync-agent-docs.mjs --check
```

The generator updates each standalone skill's bundled guide, the website
agent page, and the curated `llms.txt`. Website dev/build runs it too. The
existing VitePress plugin generates individual Markdown pages; its broad
indexes are disabled so they do not overwrite the curated index.

Validate each `skills/*/SKILL.md` as an Agent Skill. Descriptions should match
real iCloud tasks and distinguish local-only Apple app data. Keep shared
setup information in the root guide and generate portable copies. Avoid
claims of automatic discovery or numerical model savings without evidence.

## Pull requests

- Explain the user problem and the change.
- Keep command help and README examples in sync when behavior or options change.
- Add or update tests for behavior changes.
- Note any live iCloud testing and whether it changed account data.
- Do not commit secrets, generated credentials, or private account data.

The maintainers may ask for changes before merging. By submitting a contribution, you agree that it will be distributed under the project's MIT license.
