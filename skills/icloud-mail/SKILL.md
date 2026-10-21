---
name: icloud-mail
description: Search and read iCloud email, download attachments, save drafts, send mail, and manage folders, flags, moves, or deletion using iCLI. Applies to Apple Mail messages hosted by iCloud. Does not access mail stored only locally or with another email provider.
---

# iCloud Mail

Read [references/agent-guide.md](references/agent-guide.md) for standalone installation, updating, private authentication, and response handling. No other skill needs to be installed. Reuse a connected tool if it already meets the request.

Inspect `icli mail --help`, then the operation's help. Discover real folder names using `mail folders`; use search/list output for message UIDs. Retain account and folder scope when retrieving, downloading, changing, or moving a message.

Search/list return message summaries; get a message when its content or MIME part IDs are needed. Respect query and result limits before claiming a search is exhaustive. Reading uses PEEK and does not itself mark messages as read.

Download an attachment using its returned part ID and a suitable local destination. Check the result before delivering the file. Do not call a JSON message download a complete mailbox or EML archive unless that format is supported by the installed CLI.

Distinguish creating a draft from sending. `mail create` saves a remote draft; `mail send` delivers the message. Follow the user's actual authorization, preserve the requested recipients/content, and do not infer permission to send from a request to draft. Moving and deletion change the mailbox; after a move, use newly returned identifiers rather than assuming the old UID remains valid.

Detailed recipes: https://managing.software/docs/guide/usage/icloud-cli/mail.md. Treat installed CLI help as the exact command reference.
