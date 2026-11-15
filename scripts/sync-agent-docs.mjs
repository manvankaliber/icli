// Keep each distributable skill self-contained without maintaining four copies.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const check = process.argv.includes('--check');
const guide = readFileSync(resolve(root, 'AGENT_GUIDE.md'), 'utf8').replaceAll('\r\n', '\n');
const files = new Map();
for (const skill of ['icloud', 'icloud-calendar', 'icloud-contacts', 'icloud-mail', 'icloud-reminders', 'icloud-notes']) {
  files.set(`skills/${skill}/references/agent-guide.md`, guide);
}
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
