---
title: Calendar
description: Manage iCloud calendars and events with iCLI.
---

# Calendar

## Export an iCloud calendar

Start with [Getting started](./getting-started), or the [agent guide](./agent-guide)
for an agent. Select a calendar returned by the installed CLI, then download
events for an explicit date range:

```sh
icli calendar list
icli calendar events list --help
icli calendar events list 2026-01-01 2026-12-31 --calendar CALENDAR_ID --json > calendar-events.json
```

Inspect the JSON envelope's `ok`, `status`, and `warnings` before delivering
the file; successful event data is in `data`. Report the calendar and covered
dates. Dates use inclusive UTC boundaries. Choose dates that cover the user's
request rather than treating this example's year as an unrestricted backup.

This is a structured JSON event download, not a native ICS export or a complete
calendar archive. Check installed help for fields needed by the task, including
recurrence and alarms, before claiming the download supports round-trip restore.
The ICS import command accepts iCalendar files, not this JSON response.

## Manage calendars

```sh
icli calendar list
icli calendar list --include href,dsid --json
icli calendar create "Project schedule"
icli calendar update CALENDAR_ID --name "Project planning"
icli calendar delete CALENDAR_ID --yes
```

Calendar list returns `name` and `id`. Optional `--include href` adds the full
CalDAV collection URL, and `--include dsid` adds its server identifier. Repeat
`--include` or comma-separate the fields.

Selectors accept a calendar name, stable ID, full href, or href path. A name
matching several calendars fails with candidates. Use an exact returned href
to select the intended calendar. Create and update return `id`, `href`,
`name`, and the account email. Delete returns the resource identity and
`deleted: true`.

Deleting a calendar permanently removes the remote calendar and its events.
Every remote delete command requires `--yes`.

## Share a calendar

```sh
icli calendar share grant "Project schedule" --person teammate@example.com --permission read
icli calendar share list "Project schedule"
icli calendar share grant "Project schedule" --person editor@example.com --permission write
icli calendar share revoke "Project schedule" --person teammate@example.com
```

Sharing sends invitations through iCloud's CalendarServer extension. Select
an owner calendar that iCloud allows you to share. A shared copy cannot
change its owner's invite list. `read` grants read access; `write` grants
read and write access. The list reports invitation status, including
`invite-noresponse` when someone has not accepted or declined.

A successful change is read back before it is reported as verified. Add
`--debug` for redacted DAV diagnostics. Inspect each command's installed
`--help` before changing access, and use the person's intended email address.

## Set a calendar color

```sh
icli calendar color CALENDAR_ID --color "#3366FF"
```

Colors accept `#RRGGBB` or `#RRGGBBAA`. Six digits imply opaque alpha.
iCLI reads the property back and reports whether iCloud confirmed it;
calendar color is separate from any per-event color property.

## Read and manage events

### List and get

```sh
icli calendar events list 2026-10-01 2026-10-31
icli calendar events list 2026-10-01 2026-10-31 --calendar CALENDAR_ID
icli calendar events list 2026-10-01 2026-10-31 --concurrency 6
icli calendar events get EVENT_UID --calendar CALENDAR_ID
```

Range dates use `YYYY-MM-DD` and UTC boundaries. Both dates are inclusive.
Omitting `--calendar` searches all calendars for a list operation. Get,
create, update, delete, and import require a calendar.

When listing all calendars, iCLI sends up to two independent CalDAV queries at
once by default. Set `--concurrency` from 1 to 8 to tune the number of requests.
The option has no effect on a list restricted to one calendar.

The older range forms remain available:

```sh
icli calendar events --from 2026-10-01 --to 2026-10-31
icli calendar events Work 2026-10-01 2026-10-31
```

Event reads return summary, start, end, location, description, and UID, plus
status, organizer, and attendees when present. Date/time values preserve
the server's iCalendar representation. Request extra server properties by
name; matching `*_params` fields are included automatically:

```sh
icli calendar events get EVENT_UID --calendar CALENDAR_ID --include url,rrule
icli calendar events list 2026-10-01 2026-10-31 --include attendee,organizer
```

Property names are normalized to lowercase with hyphens changed to
underscores. Repeated properties can be arrays. Warnings identify requested
properties absent from the result and additional properties available with
`--include`.

Use UIDs from list output. If duplicate UIDs match several resources, the
error lists candidate resource URLs. An exact resource href can replace the
UID in get, update, or delete.

### Search event text

```sh
icli calendar events search planning
icli calendar events search planning --from 2026-10-01 --to 2026-10-31 --calendar CALENDAR_ID
icli calendar events search planning --field summary,location
icli calendar events search planning --skip 50 --limit 50
```

Search matches a literal substring in `summary`, `description`, and `location`
by default, ignoring ASCII letter case. Non-ASCII letters retain their case.
`--field` selects any combination of `summary`, `description`,
`location`, `attendee`, `organizer`, and `categories`.
The query is not a regular expression. Search properties
are included in each result along with the usual event fields.

Search all events by default. Supply both `--from` and `--to` to restrict the
search to inclusive UTC dates. `--calendar` selects one calendar; otherwise
iCLI searches all calendars. CalDAV has text-match filters for individual
properties, so iCLI sends a query for each selected field and combines those
results. If iCloud rejects a field filter, iCLI fetches events in scope and
matches locally. CalDAV applies dates to calendar resources. Recurring series
are not expanded into individual occurrences, and returned series components
can have dates outside the range. Results use resource href order, not
chronological order. After matching, `--skip` skips results and `--limit`
caps the returned page. Defaults are `--skip 0 --limit 100`. For pages of 50,
use `--skip 0 --limit 50`, then `--skip 50 --limit 50`. An offset beyond the
matches or `--limit 0` returns an empty array. `next_steps` gives the next
offset when more matches remain.

Each page reads current calendar data. Keep the query, fields, date range,
calendar, and account unchanged between calls. Changes to events can shift
offsets. CalDAV does not provide offset pagination for these queries, so iCLI
downloads all matching event data, including skipped results, on every call
and applies the offset locally. Using `--skip` with `--limit` for multiple
pages is not recommended; one call with a sufficiently large `--limit` is
faster.

Surrounding query whitespace is trimmed. Queries must then contain 1 to 256
characters. Control characters and characters XML cannot represent are rejected.
Inspect `icli calendar events search --help` for defaults and options.

### Create a timed or all-day event

```sh
icli calendar events create --calendar CALENDAR_ID --summary "Planning" --start 2026-10-20T10:00:00+02:00 --end 2026-10-20T11:00:00+02:00 --location "Meeting room" --description "Review the project"
icli calendar events create --calendar CALENDAR_ID --summary "Holiday" --all-day 2026-10-21
```

| Option                                  | Meaning                                                             |
| --------------------------------------- | ------------------------------------------------------------------- |
| `--calendar SELECTOR`                   | Required destination calendar                                       |
| `--summary TEXT`                        | Required title                                                      |
| `--start RFC3339`, `--end RFC3339`      | Provide both, with explicit timezone offsets; end must follow start |
| `--all-day YYYY-MM-DD`                  | Creates a single all-day date; cannot be combined with start/end    |
| `--location TEXT`, `--description TEXT` | Optional event fields                                               |
| `--participant EMAIL`                   | Adds an invitee; repeat for more people; `--attendee` is an alias   |
| `--email EMAIL`                         | Selects the configured account                                      |

Invitees are written as iCalendar attendees. iCloud controls invitation
delivery. iCLI reads back scheduling status when available and returns it
under `invitation_status`; a read-back failure becomes a warning after the
event has been created. A server delivery status does not prove the recipient
saw a notification. iCLI does not create a separate invitation link.

The create result includes UID, summary, calendar, account, participants,
and invitation status, with a follow-up get command.

### Update or delete an event

```sh
icli calendar events update EVENT_UID --calendar CALENDAR_ID --summary "New title"
icli calendar events update EVENT_UID --calendar CALENDAR_ID --start 2026-10-22T10:00:00+02:00 --end 2026-10-22T11:00:00+02:00
icli calendar events update EVENT_UID --calendar CALENDAR_ID --all-day 2026-10-23
icli calendar events update EVENT_UID --calendar CALENDAR_ID --location "" --description ""
icli calendar events delete EVENT_UID --calendar CALENDAR_ID --yes
```

Supply at least one field on update. Omitted fields stay unchanged. Timed
updates require both start and end; `--all-day` can move or convert an event
to a single all-day date. Empty location or description strings clear those
values. Updates use the server's version tag to detect concurrent changes.
The result includes UID, calendar, account, `updated: true`, and the supplied
`changed_properties`.

Deletion is permanent and returns UID, calendar, account, and `deleted: true`.

### Import an iCalendar file

```sh
icli calendar events import events.ics --calendar CALENDAR_ID --concurrency 6 --json
```

The file must contain complete `VEVENT` components with UIDs. Imports create
resources without overwriting existing ones. Recurrence components sharing
a UID are grouped into one resource, and timezone components are retained.
Imports send up to two independent event writes concurrently by default. Set
`--concurrency` from 1 to 8 to tune the request load. Each event still gets its
own CalDAV request. Transient server errors and connection failures are retried
up to two times per event with backoff; a server-provided `Retry-After` is
honored. Results include the retry count and structured `attempt_errors`, even
when a later attempt succeeds, so recovered errors remain visible.

Imports are not atomic. Each resource gets a result row with its UID, status,
and either `created: true` or a structured error. Completed writes remain
when another item ultimately fails. Some succeeding produces exit `3`; all
failing produces exit `1`. Inspect saved UIDs and retry only failed resources
after resolving the cause.
