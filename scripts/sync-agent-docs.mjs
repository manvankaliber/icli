// Keep each distributable skill self-contained without maintaining four copies.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const check = process.argv.includes('--check');
const guide = readFileSync(resolve(root, 'AGENT_GUIDE.md'), 'utf8').replaceAll('\r\n', '\n');
const files = new Map();
for (const skill of ['icloud', 'icloud-calendar', 'icloud-contacts', 'icloud-mail', 'icloud-reminders']) {
  files.set(`skills/${skill}/references/agent-guide.md`, guide);
}
files.set('website/src/docs/guide/usage/icloud-cli/agent-guide.md',
  '---\ntitle: Agent guide\ndescription: Install, authenticate, and complete iCloud tasks with iCLI as an agent.\n---\n\n' + guide);
const base = 'https://managing.software/docs/guide/usage/icloud-cli';
files.set('website/public/llms.txt', `# iCLI

> iCLI gives agents access to iCloud Calendar, Contacts, Mail, and Apple Reminders through a local CLI with self-contained help, resource IDs, structured results, and recovery instructions.

Start with the agent guide. Before the first iCLI task in a session, update a release installation using \`icli update\`, then use the installed CLI's help for exact commands, defaults, and side effects. Follow the guide's fallback for older, source, or package-managed installations. Authenticate through private input; credentials are stored in the operating system credential store. Use a connected tool when it already meets the request.

## Start here

- [Agent operating guide](${base}/agent-guide.md): installation, updating, authentication, task routing, outputs, and recovery.
- [Getting started](${base}/getting-started.md): human setup and the authentication handoff.
- [Update iCLI](${base}/updating.md): native updates, older releases, and source installations.
- [Account and output settings](${base}/account-and-output.md): selecting accounts, private stdin, and response formats.

## Task recipes

- [Download contacts from iCloud](${base}/contacts.md): JSON export completeness, card properties, contact edits, and groups.
- [Export, search, and manage an iCloud calendar](${base}/calendar.md): range downloads, event text search with skip/limit pagination, writes, sharing, recurrence, and imports.
- [Search iCloud contacts](${base}/contacts.md): CardDAV text search, skip/limit pagination, complete contact properties, edits, and groups.
- [Search iCloud email and download attachments](${base}/mail.md): skip/limit pagination, folders, scoped UIDs, drafts, sending, and mailbox changes.
- [Apple Reminders](${base}/reminders.md): Apple Account sign-in, trusted-device verification, reminder reads and writes, incremental sync, and supported related records.
- [Errors and recovery](${base}/recovery.md): structured failures, partial results, and uncertain writes.

## Optional integrations

- [Five standalone iCloud skills](https://github.com/manvankaliber/icli/tree/main/skills): install one app skill or the five-skill bundle.
- [Local MCP adapter](https://github.com/manvankaliber/icli/blob/main/mcp/README.md): tools discovered from installed CLI help.

The linked pages are Markdown versions of the website documentation. iCLI operates on iCloud-hosted data, not device-only data, iCloud Drive, or Photos. Structured JSON downloads are not native VCF, ICS, or mailbox archives. The installed CLI's help is authoritative; this index is navigation, not a complete command reference.
`);

let stale = false;
for (const [relative, expected] of files) {
  const path = resolve(root, relative);
  const actual = existsSync(path) ? readFileSync(path, 'utf8').replaceAll('\r\n', '\n') : null;
  if (actual === expected) continue;
  if (check) {
    console.error(`Out of date: ${relative}`);
    stale = true;
  } else {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, expected);
    console.log(`Updated ${relative}`);
  }
}
if (stale) process.exitCode = 1;
