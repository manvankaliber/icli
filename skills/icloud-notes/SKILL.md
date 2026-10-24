---
name: icloud-notes
description: Use iCLI to browse, read, search, export, download attachments, sync, and soft-delete unshared iCloud Apple Notes. Applies to notes stored in iCloud, not notes stored only on a device.
---

# Apple Notes with iCLI

Read [references/agent-guide.md](references/agent-guide.md) for installation,
authentication, output handling, and recovery. This skill works without any
other iCloud skill.

Use `icli notes --help`, then the relevant leaf command's help. Notes uses the
saved Apple Account session. The first request may require trusted-device
approval for encrypted Notes data; follow `next_steps`, approve, and retry.

Notes commands browse folders and summaries, search recent or all titles, read
decoded plain text and attachment metadata, download available attachment
files, render basic HTML, export text/Markdown/HTML, and read incremental
changes. HTML and Markdown exports download available attachments beside the
output by default. `--no-assets` skips those downloads. Search matches titles,
not note bodies. HTML and Markdown export decoded text and local attachment
copies, but do not recreate every rich Notes style.

`icli notes delete NOTE_ID --yes` soft-deletes one unshared note;
`icli notes delete-unshared --yes` soft-deletes every active unshared note.
Both commands check share metadata, and the bulk command skips shared notes.
Each deletion is read back for verification. Treat Note IDs and sync cursors
as opaque values and retain the same account when continuing a paginated read
or change feed.
