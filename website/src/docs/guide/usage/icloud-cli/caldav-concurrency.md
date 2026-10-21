---
title: Parallel CalDAV requests
description: Tune concurrent event listing and iCalendar imports in iCLI.
---

# Parallel CalDAV requests

Event listing across calendars and iCalendar imports can run independent
CalDAV requests at the same time. Both commands default to two concurrent
requests. Set `--concurrency` from 1 to 8 to tune the request load.

```sh
icli calendar events list 2026-10-01 2026-10-31 --concurrency 6
icli calendar events import events.ics --calendar CALENDAR_ID --concurrency 6
```

When an event list omits `--calendar`, iCLI queries each calendar separately.
Concurrency controls how many of those calendar queries run at once. A list
restricted to one calendar makes one query, so increasing concurrency has no
effect.

An import sends one `PUT` request for each event resource. Concurrency controls
how many writes can be in flight; `--concurrency 1` sends them one at a time.
The requests may share an HTTP/2 connection when the server negotiates HTTP/2.
The default value is 2, and the maximum is 8.

Imports retry transient server and connection failures up to two times per
event, with backoff and `Retry-After` support. Per-event results include the
retry count and each failed request. Imports are not atomic. If an event still
fails, successful writes remain in the calendar; inspect the per-UID results
before retrying failed events.
`--concurrency` does not change the result format or partial-success behavior.
