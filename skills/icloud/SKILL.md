---
name: icloud
description: Use iCLI for requests involving iCloud Calendar, Contacts, Mail, Apple Reminders, and Apple Notes. Applies to explicit iCLI setup and usage requests and work spanning multiple supported services. Use an existing connected tool when it already meets the request. Does not cover iCloud Drive, Photos, or device-only Apple app data.
---

# iCloud with iCLI

Read [references/agent-guide.md](references/agent-guide.md) for installation, once-per-session updating, private authentication, command discovery, output handling, and recovery. This skill works without another skill being installed.

Identify which supported services the user's task needs, then inspect their installed CLI help. Use `icli calendar --help`, `icli contacts --help`, `icli mail --help`, `icli reminders --help`, or `icli notes --help`, followed by the relevant leaf help. For a single-service task, the corresponding app skill may provide more specific guidance if installed; it is optional.

Keep resource identities scoped to the service and account. A contact UID is not a calendar-event UID, and mail UIDs also require the folder. When combining service data, join through actual fields such as email addresses rather than matching display names alone.

Perform only the requested workflow. For a multi-step write, report each completed action and unresolved step; do not describe the whole operation as atomic. When a capability is missing from the installed help, state the gap instead of inventing a command or treating iCloud Drive/Photos as supported.
