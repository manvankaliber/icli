---
title: Errors and recovery
description: Understand iCLI errors, partial results, and safe recovery steps.
---

# Errors and recovery

## Handle failures and partial results

| Exit code | Meaning                      | Next action                                                     |
| --------- | ---------------------------- | --------------------------------------------------------------- |
| `0`       | Success                      | Use `data`; inspect any warnings                                |
| `1`       | Operation failure            | Inspect the structured error and any per-item results           |
| `2`       | Invalid command or arguments | Follow the hint and scoped command help                         |
| `3`       | Partial success              | Keep completed results and resolve failed items before retrying |

Success and partial results go to stdout. Complete failures go to stderr.
In JSON mode, argument errors use the same envelope as operation failures:

```json
{
  "ok": false,
  "status": "error",
  "action": "calendar.events.delete",
  "data": null,
  "next_steps": [],
  "warnings": [],
  "error": {
    "code": "invalid_arguments",
    "message": "The required --yes argument was not provided.",
    "hint": "Add --yes after confirming the intended event.",
    "help": "icli calendar events delete --help",
    "retryable": false
  }
}
```

The example illustrates the envelope; exact messages depend on the failure.
`retryable` is `true`, `false`, or `null` when unknown. Error codes include
`invalid_arguments`, `invalid_input`, `account_required`,
`ambiguous_resource`, `resource_not_found`, `authentication_failed`,
`permission_denied`, `resource_changed`, `rate_limited`, `connection_failed`,
`credential_store_error`, and the fallback `operation_failed`.

Use `error.hint`, `error.help`, and `next_steps` for recovery. Missing or
ambiguous resources need a current ID, UID, or exact href. Credential errors
need a configured account, working credential store, and correct app-specific
password. A concurrent-change error needs a fresh read before updating.

DAV reads pace requests and retry transient failures with bounded backoff.
A rate-limited or unavailable service may need time before another attempt.
After an uncertain write outcome, inspect the remote resource before
repeating a create, delete, or import. A warning after a completed write is
not a reason to create it again.
