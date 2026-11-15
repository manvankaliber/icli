---
name: icloud
description: Use iCLI for requests involving iCloud Calendar, Contacts, Mail, Apple Reminders, Apple Notes, Drive, Photos, Find My, Hide My Email, Apple Invites, and account/storage. Applies to explicit iCLI setup and usage requests and work spanning multiple supported services. Use an existing connected tool when it already meets the request. Private Apple endpoints are experimental; device-only Apple app data is out of scope.
---

# iCloud with iCLI

Read [references/agent-guide.md](references/agent-guide.md) for installation, version checks and updates, private authentication, command discovery, output handling, and recovery. This skill works without another skill being installed.

Identify which services the user's task needs, then inspect their installed CLI help. Use `icli calendar --help`, `icli contacts --help`, `icli mail --help`, `icli reminders --help`, `icli notes --help`, or the relevant experimental group (`drive`, `photos`, `find-my`, `hide-my-email`, `account`, `invites`), followed by leaf help. For a single core service, the corresponding app skill may provide more specific guidance if installed; it is optional.

Keep resource identities scoped to the service and account. A contact UID is not a calendar-event UID, and mail UIDs also require the folder. When combining service data, join through actual fields such as email addresses rather than matching display names alone.

Perform only the requested workflow. For a multi-step write, report each completed action and unresolved step; do not describe the whole operation as atomic. Treat experimental Apple web-service commands as subject to endpoint changes and not live-account verified. Find My commands are read-only; Invites commands list/read/preview only; Hide My Email includes mutations that can change alias forwarding. When a capability is missing from installed help, state the gap instead of inventing a command.
