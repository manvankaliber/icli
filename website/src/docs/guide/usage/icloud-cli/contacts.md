---
title: Contacts
description: Find, create, and update iCloud contacts with iCLI.
---

# Contacts

## Download contacts from iCloud

Follow [Getting started](./getting-started) to install iCLI and connect your
account, or give an agent the [agent guide](./agent-guide). Reuse an existing
configured account when possible. Inspect the installed command first:

```sh
icli contacts list --help
icli contacts list --email you@icloud.com --include all --limit 1000000 --json > contacts.json
```

This example writes a JSON response envelope containing complete property
data for up to one million contacts. Inspect `ok`, `status`, and `warnings`
before delivering the file. On success, contacts are in `data`. If the count
reaches the chosen limit, raise the limit and repeat the read before claiming
that all contacts were downloaded. The default limit is only 100.

The result is structured JSON, not a native VCF export. Apple grouped fields,
parameter arrays, escaped values, and encoded photo data retain their stored
representations. Conversion to another format is a separate step and should
preserve those properties. Use the installed CLI's help to check current
format support, and report any gap if the user specifically requires VCF.

## Read and manage contacts

### Summaries, selected properties, or complete property data

```sh
icli contacts list
icli contacts list --limit 1000 --include all --json
icli contacts get CONTACT_UID --include all
icli contacts list --include BDAY,ADR,X-SOCIALPROFILE
icli contacts list --skip 100 --limit 100
icli contacts get CONTACT_UID --include EMAIL --include TEL
```

List returns up to 100 contacts by default, sorted by UID in ascending order.
`--skip` defaults to 0. For pages of 100, use `--skip 0 --limit 100`, then
`--skip 100 --limit 100`. `--limit 0` or an offset beyond the matches returns
an empty array. `next_steps` gives the next offset when more contacts remain.
Keep the account and options unchanged between pages. Each call reads current
data, so changes to contacts can shift offsets.

CardDAV does not provide offset pagination for these queries, so iCLI downloads
the address book, including skipped contact cards, on every call and applies
the offset locally. Using `--skip` with `--limit` for multiple pages is not
recommended; one call with a sufficiently large `--limit` is faster. Choose a
sufficiently large limit when exporting an entire account in one call.

Default fields are `uid`, `name`, `emails`, `phones`, and `birthday`. Use
case-insensitive `--include PROPERTY`, repeated or comma-separated, to add
properties under each card's `properties` object. `--include all` returns
every stored property, including native Apple fields, custom extensions,
repeated values, groups, and parameters.

Each property maps to an array of `{value, params}` objects. Parameter values
are also arrays, including repeated parameters. Values preserve vCard
serialization, such as escaped text, structured addresses, and photo
encodings; iCLI does not automatically decode them. A selected property
absent from the result produces a warning.

Apple property groups keep their full names, such as `ITEM1.ADR` and
`ITEM1.X-ABLABEL`. Requesting `ADR` also selects grouped address properties.
Group labels and values are separate properties; use `--include all` when
you need their complete relationship.

### Search contacts

```sh
icli contacts search "Alex Kim"
icli contacts search example.com --field email
icli contacts search Acme --field name,organization --include ORG
icli contacts search example.com --field email --skip 50 --limit 50
```

Search matches a case-insensitive substring in formatted name, email, or
phone by default. Use `--field` to search any combination of `name`, `email`,
`phone`, and `organization`. Queries are literal text, not regular
expressions. Matching uses CardDAV's Unicode casemap normalization, including
equivalent composed and decomposed accents. Phone punctuation, spaces, and
country codes are matched literally. CardDAV returns cards matching any
selected field. If iCloud
rejects a property filter, iCLI reads the address book and applies the same
match locally. Groups are excluded. Results include the usual contact
summaries and the selected search properties under `properties`. `--include`
adds other requested vCard properties. After filtering and excluding groups,
matches are sorted by UID. `--skip` is applied before `--limit`, using the
same pagination rules as contact list. Defaults are `--skip 0 --limit 100`.
CardDAV returns all matching cards, including cards before the requested
offset. Each page downloads those skipped cards again, so one call with a
sufficiently large `--limit` is faster than multiple pages.

Surrounding query whitespace is trimmed. Queries must then contain 1 to 256
characters. Control characters and characters XML cannot represent are rejected. See
`icli contacts search --help` for the full command contract.

### Discover available properties

```sh
icli contacts help --json
```

This reads the selected account and returns:

- `default_fields` for the summary output.
- `standard_vcard_properties` for the standard property catalog.
- `properties_found_in_account` for every discovered property name.
- `custom_properties_found_in_account` for custom and Apple `X-` names.
- `property_parameter_names_found_in_account` for discovered parameter names.
- `usage` for the inclusion syntax.

The parser preserves arbitrary property names. Fields such as birthdays,
addresses, organizations, photos, related names, social profiles, and custom
card data do not require a dedicated CLI flag to be read.

### Create a contact

```sh
icli contacts create --name "Jane Doe" --contact-email jane@example.com --phone "+1 555 0100"
icli contacts create --name "Jane Doe" --property BDAY=1990-10-20 --property X-CUSTOM=example
```

| Option                  | Meaning                                                                                     |
| ----------------------- | ------------------------------------------------------------------------------------------- |
| `--name TEXT`           | Sets formatted name `FN` and structured name `N`                                            |
| `--contact-email EMAIL` | Sets the contact's email; `--email` selects the iCloud account                              |
| `--phone TEXT`          | Sets `TEL`                                                                                  |
| `--property NAME=VALUE` | Sets any property as a text value; repeat for multiple values                               |
| `--vcard-file FILE`     | Loads one complete UTF-8 vCard, including grouped fields, parameters, and structured values |

Creation requires a formatted name through `--name`, `--property FN=...`, or
`FN` in a file. A UID is generated unless the file supplies one. Creation
refuses to overwrite an existing resource. Results return UID, account, and
`changed_properties`, plus a command to inspect the card.

### Update a contact

```sh
icli contacts update CONTACT_UID --name "Jane Smith"
icli contacts update CONTACT_UID --property EMAIL=one@example.com --property EMAIL=two@example.com
icli contacts update CONTACT_UID --property X-CUSTOM="New value"
icli contacts update CONTACT_UID --phone "+1 555 0200"
```

Update changes only supplied properties. Omitted properties remain intact.
Repeated inputs for one property replace its existing values as a group.
`--name` changes both `FN` and `N`; `--contact-email` replaces email values;
`--phone` replaces phone values.

An ungrouped property name also replaces existing values of that property
inside Apple groups. A grouped name targets that exact group. Use file input
when retaining or setting a group's type parameters and labels matters.
An empty text value sets an empty property value.

At least one property is required. Inputs from a file and flags must not
overlap, and a common flag must not also set a property supplied through
`--property`. Updates use the server ETag when available; if the resource
changed concurrently, read it again before merging and retrying.

### Write structured or Apple-specific fields with a vCard file

Save this UTF-8 text as `contact.vcf`:

```text
BEGIN:VCARD
VERSION:3.0
FN:Jane Doe
N:Doe;Jane;;;
item1.ADR;TYPE=HOME:;;One Street;Amsterdam;;1000 AA;Netherlands
item1.X-ABLabel:Home
X-CUSTOM;TYPE=PRIVATE:Example
END:VCARD
```

```sh
icli contacts create --vcard-file contact.vcf
icli contacts update CONTACT_UID --vcard-file contact.vcf
```

A file must contain one complete `BEGIN:VCARD` / `END:VCARD` block and exactly
one `VERSION`. A file UID is optional; on update it must match the selected
contact. `UID` and `VERSION` are supplied through file input rather than
`--property`.

For updates, the file follows the same merge rule as flags: supplied
properties replace those properties, and omitted properties remain. The
example changes the name, home address group, label, and custom property.
Include only properties you intend to change.

Use a file for structured `N`/`ADR` values, property parameters, photos, and
other encoded data. Components use semicolons; escape literal semicolons,
commas, and backslashes with a backslash, and embedded text newlines as
`\n`. Simple `--property` values are escaped as text automatically. Long
lines are folded without splitting UTF-8 characters.

### Delete a contact

```sh
icli contacts delete CONTACT_UID --yes
```

The command permanently deletes the remote card and returns its UID and
`deleted: true`. A DELETE response indicating the resource is already absent
is treated as the desired deleted state. An initial lookup that cannot find
the contact still fails. When duplicate UIDs match several resources,
get/update/delete accept an exact resource href from the candidate list.

## Manage iCloud contact groups

```sh
icli contacts groups --help
icli contacts groups list
icli contacts groups create --name "Project team" --member CONTACT_UID
icli contacts groups update --help
```

Groups are Apple-compatible vCards whose members refer to contact UIDs.
Choose UIDs from contact list output; creating a group does not create new
copies of its contacts. Inspect update help before replacing membership,
and retain the group's own UID for subsequent operations. Group deletion
requires `--yes` and removes the group, not its member contact cards.
