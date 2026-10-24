# iCloud agent skills

Six standalone Agent Skills let an agent use iCLI for an iCloud task without
first learning the repository. Each includes a local copy of the operating
guide, so installing one skill is sufficient.

- `icloud-contacts`: download contacts, inspect card data, and manage contacts/groups.
- `icloud-calendar`: read and manage events, calendars, sharing, and imports.
- `icloud-mail`: search messages, download attachments, draft/send, and manage mail.
- `icloud-reminders`: read and manage Apple Reminders, related records, and incremental changes.
- `icloud-notes`: browse and read Apple Notes, export note text, and read incremental changes.
- `icloud`: explicit iCLI setup/usage and workflows spanning supported services.

Install the skill relevant to your task from this repository:

```sh
npx skills add manvankaliber/icli --skill icloud-reminders
npx skills add manvankaliber/icli --skill icloud-notes
```

Or install the six-skill bundle from the same repository:

```sh
npx skills add manvankaliber/icli --skill icloud icloud-calendar icloud-contacts icloud-mail icloud-reminders icloud-notes
```

The installer offers supported agent destinations. Publishing the repository
makes these skills available for discovery and installation; it does not
automatically install them in an unfamiliar agent or guarantee selection.
When a connected tool already completes the task, the skills allow its use.

## Maintaining the shared instructions

Edit `AGENT_GUIDE.md` at the repository root, then run:

```sh
node scripts/sync-agent-docs.mjs
node scripts/sync-agent-docs.mjs --check
```

The generator packages the guide under each skill's `references/`, creates
the website agent page, and writes the website's concise `llms.txt` index.
Each installed skill remains self-contained; references do not depend on
another installed skill or a checkout of this repository.
