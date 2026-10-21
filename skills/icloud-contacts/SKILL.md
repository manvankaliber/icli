---
name: icloud-contacts
description: Download or export contacts from iCloud, find people and contact properties, and create or update iCloud contact cards and groups using iCLI. Applies to Apple Contacts and address-book data synced with iCloud. Does not access contacts stored only on a device or another provider.
---

# iCloud Contacts

Read [references/agent-guide.md](references/agent-guide.md) for installation, updating, private authentication, command discovery, and recovery. This skill works independently of the other iCloud skills. Use an existing connected tool when it meets the request.

Inspect `icli contacts --help` and the relevant leaf help. Contact identifiers are vCard UIDs from list output. `icli contacts help` reads account data to discover properties; append `--help` for local command instructions instead.

For a contact download, choose the required output format and completeness. Listing returns a limited summary by default. Inspect the current `--limit` and `--include` options; request complete properties when the user needs full card data, and check whether the limit was reached before claiming all contacts were exported. Validate the response status before writing or delivering the artifact. Structured JSON is not a native VCF file.

Use actual contact fields to disambiguate people. For edits, specify only intended properties. Preserve omitted properties and pay attention to grouped Apple fields and structured vCard values; read the file-input help when those matter. A supplied group of values can replace existing values for that property. Re-read and merge after an ETag conflict rather than repeating an outdated update.

Detailed recipes: https://managing.software/docs/guide/usage/icloud-cli/contacts.md. Use installed CLI help for exact flags and supported export formats.
