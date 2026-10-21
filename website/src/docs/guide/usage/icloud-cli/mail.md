---
title: Mail
description: Read iCloud Mail, save drafts, and manage message flags with iCLI.
---

# Mail

## Search iCloud email

Use [Getting started](./getting-started) to install and authenticate iCLI,
or the [agent guide](./agent-guide) for agent setup. Discover the actual
folder names, then search the requested folder:

```sh
icli mail folders
icli mail search --help
icli mail search "invoice" --folder INBOX --limit 50 --json
icli mail search "invoice" --folder INBOX --skip 50 --limit 50 --json
icli mail get MESSAGE_UID --folder INBOX --json
```

Search uses IMAP TEXT and returns header summaries for matches, newest UIDs
first, after `--skip` and up to the chosen `--limit`. Search defaults to
`--skip 0 --limit 50`. For pages of 50, use offsets 0, 50, 100, and so on.
`next_steps` gives the next offset when more matching UIDs remain.
Get retrieves a selected message's contents. Inspect the status and warnings;
a single page may not contain every match. Use `--email` to select the
intended account.

Mail list and search both search all matching IMAP UIDs on every call, then
fetch headers only for the selected page. Missing or unreadable headers can
produce fewer rows than the limit; follow `next_steps` when present. Keep the
query, folder, account, and other options unchanged between pages. New mail,
moves, or deletions can shift offsets because each call reads current data.

## Download an iCloud email attachment

Get the message first and choose a MIME part ID from its attachment list:

```sh
icli mail get MESSAGE_UID --folder INBOX --json
icli mail download --help
icli mail download MESSAGE_UID --folder INBOX --part PART_ID --output invoice.pdf
```

Keep the account, folder, and message UID from the search/get result. A
successful download writes the decoded attachment bytes to the requested
local path. Verify success before delivering it. A JSON message result is
not an EML or complete mailbox archive.

## Read and manage Mail

### Read inbox messages

```sh
icli mail list --limit 20
icli mail list --skip 20 --limit 20
icli mail get 123 --email you@icloud.com --json
```

List returns up to 10 messages by default, ordered by newest IMAP UID first.
`--skip` defaults to 0 and skips UIDs before fetching headers. `--limit 0`
or an offset beyond the matching UIDs returns an empty array. List reads headers and returns UID, sender,
subject, and date. Get returns UID, sender, recipient, subject, date, and
parsed body. Both use `BODY.PEEK`, so reading does not mark a message as seen.

Mail UIDs are scoped to the selected account and folder. Reads, flags, and
deletions accept `--folder`, which defaults to `INBOX`. Use `mail folders`
to discover names rather than assuming every message is in the inbox.

### Save a draft

```sh
icli mail create --to person@example.com --subject "Meeting notes" --body "Here are the notes."
```

All three fields are required. iCLI saves a plain-text message in `Drafts`
with the draft flag. It does not send the message. Header line breaks in the
recipient or subject are rejected. The result includes `to`, `subject`,
`folder: "Drafts"`, and `sent: false`. The current append operation does not
return the draft's UID.

### Change message flags or delete a message

```sh
icli mail update 123 --flag seen
icli mail update 123 --flag unseen
icli mail update 123 --flag flagged
icli mail update 123 --flag unflagged
icli mail delete 123 --yes
```

`--flag` accepts exactly `seen`, `unseen`, `flagged`, or `unflagged`. Updates
return the UID, requested flag, and `updated: true`, plus a get command.
Deletion permanently expunges the selected UID and returns `deleted: true`.
It requires `--yes`.

## Send an email through iCloud

```sh
icli mail send --help
icli mail send --to person@example.com --subject "Meeting notes" --body "Here are the notes."
```

Send delivers a plain-text message through iCloud SMTP. A request to prepare
a draft should use `mail create` instead. Sending cannot be undone; follow
the user's intended recipients and content, and inspect any returned error
before repeating a request whose delivery outcome is uncertain.

## Move an iCloud email to another folder

```sh
icli mail folders
icli mail move --help
icli mail move MESSAGE_UID --source INBOX --destination "Archive"
```

Use a destination returned by the folder list. Moving copies the message,
then expunges the selected source UID. A copy failure retains the source;
an expunge failure can leave a destination copy already present. Inspect
the result before retrying, and discover the destination UID rather than
reusing a UID scoped to the old folder.
