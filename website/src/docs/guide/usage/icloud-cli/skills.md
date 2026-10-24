---
title: iCloud agent skills
description: Install standalone skills for iCloud Calendar, Contacts, Mail, Reminders, and cross-app tasks with iCLI.
---

# iCloud agent skills

An Agent Skill gives an agent a task-specific procedure and a compact copy
of the [iCLI agent guide](./agent-guide). Each skill can install iCLI, guide
the private authentication handoff, discover commands, and handle results
without requiring another skill to be installed.

- `icloud-contacts`: download contacts, inspect properties, and manage cards/groups.
- `icloud-calendar`: download events, schedule, share calendars, and import ICS files.
- `icloud-mail`: search messages, download attachments, draft/send, and manage folders.
- `icloud-reminders`: read and manage reminders, related records, and incremental changes.
- `icloud`: explicit iCLI requests and workflows across the supported services.

Install the relevant skill:

```sh
npx skills add manvankaliber/icli --skill icloud-reminders
```

Install the six-skill bundle:

```sh
npx skills add manvankaliber/icli --skill icloud icloud-calendar icloud-contacts icloud-mail icloud-reminders icloud-notes
```

The skills CLI lets you choose the supported agent destination. Installing a
skill gives that agent instructions; it does not itself authenticate an
iCloud account. Follow the private authentication handoff in the guide.

These skills cover iCloud-hosted data, including data synced from Apple
Calendar, Apple Contacts, Apple Mail, and Apple Reminders. They do not cover
device-only data, iCloud Drive, or Photos. Use an already connected tool when it
meets the request. Skills are available for discovery and installation; publication
does not guarantee that an arbitrary agent automatically loads them.

The [source packages](https://github.com/manvankaliber/icli/tree/main/skills)
bundle common instructions generated from one maintained operating guide.
For exact commands and defaults, use the installed CLI's help.
