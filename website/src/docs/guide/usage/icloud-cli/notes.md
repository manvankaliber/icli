---
title: Apple Notes
description: Browse and search iCloud Notes, download attachments, export text/Markdown/HTML, and resume incremental changes with iCLI.
---

# Apple Notes

iCLI reads Apple Notes through Apple's private CloudKit service. The integration
uses the saved Apple Account session created by `icli auth add EMAIL` and
`icli auth verify EMAIL CODE`. Apple may require trusted-device approval before
granting access to encrypted Notes data. Follow the command's `next_steps`,
approve on a trusted device, and retry the Notes command.

The Notes command group can browse folders and notes, search recent or all note
titles, read decoded plain text and attachment metadata, download linked files,
export text/Markdown/HTML, read incremental changes, and soft-delete notes.
Delete commands require `--yes`, check share metadata before each write, and
verify the Deleted flag by reading the note back. The bulk command leaves
shared notes unchanged. HTML and Markdown exports preserve decoded text and
include available attachment copies, but do not reconstruct every Apple Notes
style. Apple can change this undocumented service at any time.

## Browse notes

```sh
icli notes folders
icli notes recent --limit 50
icli notes list --skip 0 --limit 100
icli notes list --all --skip 0 --limit 100
icli notes list --folder-id FOLDER_ID
icli notes search "project plan" --limit 20
icli notes search "project plan" --all --limit 20
```

`recent` and the default `list` read Apple's recents index. `list --all` reads
the complete Notes zone, which may be slower. Use `--folder-id` with the recent
feed to narrow results to a folder. Search matches a case-insensitive substring
of note titles; by default it searches recent notes, and `search QUERY --all`
scans the complete Notes zone. Search does not inspect note bodies. List and
search commands default to 100 rows and return pagination guidance where
available. Keep the account and query scope unchanged when following `--skip`
offsets.

Note summaries include `shared`, derived from CloudKit's share metadata. A true
value means the note is shared; the Notes integration does not modify share
settings.

## Read or export a note

```sh
icli notes get NOTE_ID
icli notes get NOTE_ID --with-attachments
icli notes render NOTE_ID
icli notes export NOTE_ID --output ./note.txt
icli notes export NOTE_ID --output ./note.md --export-format markdown
icli notes export NOTE_ID --output ./note.html --export-format html
icli notes export NOTE_ID --output ./note.html --export-format html --no-assets
icli notes download NOTE_ID --output-dir ./note-assets
```

Note IDs are stable CloudKit record names. `get --with-attachments` resolves
attachment filenames, UTIs, sizes, and download availability without fetching
file contents. `download` saves available attachments to the requested folder
and never overwrites existing files. `render` wraps decoded plain text in a
simple HTML fragment. `export` defaults to text; choose `--export-format
markdown|html` for those formats. Markdown and HTML exports download available
attachments to a sibling `<output-name>_assets` folder by default and link them
from the output. `--no-assets` skips downloads. HTML/Markdown preserve the text
and available attachments, but do not reconstruct every rich Notes style.
Review the destination because the export file itself may be replaced.

## Delete unshared notes

```sh
icli notes delete NOTE_ID --yes
icli notes delete-unshared --yes
```

`delete` soft-deletes one note and refuses to change a shared note.
`delete-unshared` enumerates the Notes zone, checks share metadata, and
soft-deletes each active unshared note. It rechecks each note immediately before
writing and verifies the result with a readback. Output lists per-note results;
partial failures are reported without hiding successful deletions. Review the
target account before running the bulk command. `--yes` is required for both
commands.

## Resume changes

```sh
icli notes sync-cursor
icli notes changes
icli notes changes --since CURSOR
icli notes list --all --since CURSOR
```

Treat cursors as opaque values. Save the cursor returned by a successful
changes/list response and pass it unchanged to continue. Change records may
include deletions. A full-zone listing can include current records as well as
records after a cursor, depending on the CloudKit response; use `changes` for
an incremental feed.

For exact accepted flags and output fields in your installed version, run
`icli notes --help` and `icli notes COMMAND --help`.
