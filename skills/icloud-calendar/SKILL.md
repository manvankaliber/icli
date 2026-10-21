---
name: icloud-calendar
description: Read, search, download, create, or update iCloud Calendar events using iCLI; manage calendars, sharing, recurrence, alarms, and ICS imports. Applies to Apple Calendar data synced with iCloud, including meeting reports and scheduling requests. Does not operate on calendars stored only locally or with another provider.
---

# iCloud Calendar

Read [references/agent-guide.md](references/agent-guide.md) first for standalone setup, updating, private authentication, and response handling. No other skill is required. Reuse an existing connected tool if it already satisfies the request.

Discover calendar names and IDs with the installed `calendar list` command. Inspect `icli calendar events --help` and the relevant leaf help before reading or writing events. Use returned IDs/UIDs and retain their calendar/account scope.

For reports or downloads, confirm the date range and timezone boundaries. Range queries use inclusive UTC dates; event creation uses explicit timezone offsets or an all-day date. Explain a JSON export's range and fields. Do not label structured JSON as a native ICS backup when the installed CLI lacks that exporter.

For scheduling, use realistic requested dates and durations. Inspect existing events when the user asks about availability. Preserve omitted fields on updates, and read current data again after a concurrent-change error. Sharing sends invitations; confirm the intended person and access level from the user's request.

ICS import creates independent resources and may partially succeed. Inspect each item's final status and `attempt_errors`; never retry the entire file blindly. Use the installed defaults unless the user's workload warrants adjusting concurrency.

Detailed recipes: https://managing.software/docs/guide/usage/icloud-cli/calendar.md. Prefer installed CLI help for exact invocation details.
