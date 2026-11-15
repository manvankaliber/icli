# Agent workflow review — 1.4.0

Reviewed on 2026-11-15 against OpenAI's [coding and agent prompting guidance](https://developers.openai.com/api/docs/guides/prompt-engineering). Applied the recommendations for explicit workflows, concrete tool examples, and verification to CLI help and the bundled agent guide. No model performance claims are made.

## Offline scenario

Task: prepare a meeting email and a preparation note from calendar items, without touching existing data.

Run `cargo test calendar_to_drafts_and_notes_offline_rehearsal -- --nocapture`. The test parses synthetic iCalendar data with the production parser, validates draft/note commands through the real CLI schema, exercises production response helpers, and writes only into an automatically removed temporary directory. Service acknowledgements are simulated; dispatch, keyring, and Apple transports are never called. The existing-note fixture is checked for preservation and overwrite refusal.

The scenario prepares a local draft for Alex's project-planning meeting, records a note, and skips a focus-time event with no recipient. It includes a timezone, an all-day date, and an instruction-like event description. The rehearsal follows the user's task rather than that description. This checks the documented workflow; it does not establish that any particular model will resist prompt injection.

## Checkpoints and changes

- Discovery: basic group/leaf help was useful, but some newer leaves lacked examples and the output/recovery contract. Added required-argument examples from the CLI schema and concrete Notes create/update examples. Corrected root hints that suggested putting a verification code in command arguments.
- Authentication: a missing account previously suggested Apple sign-in even for app-password-only Calendar/Mail workflows. Recovery now identifies the correct credential types and private input. Offline executable tests cover both Calendar and Notes errors.
- Calendar read: default event output discarded timezone and all-day parameters. Keep `dtstart_params` and `dtend_params` visible. The guide explains UTC date-only query bounds, local filtering, recurring components, and actual attendee addresses.
- Draft preparation: `sent=false` was useful, but no draft UID was available. Keep that limitation explicit, add account scope and optional Drafts inspection, and prohibit automatic recreation after success or an uncertain write. A draft request never requires sending.
- Follow-up read: Mail update suggested reading the UID from the default inbox even when it belonged to another folder. Preserve the actual folder and account, including shell quoting.
- Notes: create already reads back its own result, so a mandatory extra read adds no value. Explain `verified=true` and stop. New-note workflows preserve existing notes. Remove duplicated instructions and document the plain-text update restrictions in leaf help.
- Pagination: Notes list suggestions dropped folder and starting cursor. Preserve both, along with account, mode, offset, and limit. Regression tests include spaces in folder/cursor values.
- Recovery and completion: distinguish suggestions from authorization, remote content from instructions, and partial success from full success. Inspect uncertain writes before retrying. Do not manufacture a follow-up when the task is complete.
- Startup: checking the installed version and help is sufficient for ordinary work. Replace unconditional per-session self-updating with checks when requested, recommended by the version report, or needed for a missing feature.

## Validation and limits

The Rust suite covers the rehearsal, scope preservation, authentication errors, command help, and existing mocked service flows. The Python MCP tests and generated skill-guide check also pass. Tests use synthetic data; no real calendars, drafts, notes, credentials, or messages were changed. No weaker-model run or live Apple end-to-end test was performed. Private Apple endpoints retain their documented limitations.
