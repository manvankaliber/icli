# iCLI 1.4.1

Fix the remaining dependency security alert, [GHSA-2326-pfpj-vx3h](https://github.com/advisories/GHSA-2326-pfpj-vx3h) / RUSTSEC-2024-0377, by removing the old IMAP parser dependency chain containing `lexical-core`.

- Pin upstream `imap` to `3.0.0-alpha.15`, which uses the newer parser without `lexical-core`. This dependency is a prerelease; iCLI's command and response contracts remain unchanged.
- Require TLS for iCloud IMAP connections and preserve Drafts plus the draft flag with the new append API.
- Verify mail parsing, draft persistence commands, rejection handling, and UID-scoped operations with synthetic in-memory IMAP replies. No live iCloud data is used.

Validation: Rust tests, formatting, bundled guide checks, MCP tests, and all six release builds.
