# iCLI 1.4.0

iCLI is complete as a standalone CLI. The README now focuses on installation and supported apps; the documentation website, benchmark placeholders, and comparison graphics have been removed. Detailed instructions remain in the agent guide, bundled skills, and command help.

- Preserve calendar timezone/all-day metadata in default event output.
- Keep account/folder scope in Mail follow-ups and folder/cursor filters in Notes pagination.
- Improve draft confirmation, authentication recovery, Notes help, and agent completion guidance.
- Update ZIP and time dependencies to patched versions; source builds now require Rust 1.88 or newer.
- Add an offline calendar-to-draft-and-note rehearsal with no live account access.

Validation: Rust tests, Python MCP tests, formatting, and generated-guide checks. See [workflow review](tests/agent-workflow-review.md) for findings and simulation limits. Private Apple web-service integrations retain their documented limitations.
