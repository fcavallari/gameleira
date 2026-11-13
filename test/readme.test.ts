import fs from 'node:fs';
import path from 'node:path';
import { expect, test } from 'vitest';
import { RULES } from '../src/rules/rules';

/** The rules table in README.md, as id -> [severity cell, description cell]. */
function readmeRules(): Map<string, [string, string]> {
  const text = fs.readFileSync(path.resolve(__dirname, '..', 'README.md'), 'utf8');
  const section = text.slice(text.indexOf('\n## Rules'), text.indexOf('\n## What the queue means'));
  const rows = new Map<string, [string, string]>();
  for (const line of section.split('\n')) {
    const m = /^\| `([a-z-]+)` \| ([^|]+) \| (.+) \|$/.exec(line);
    if (m) rows.set(m[1]!, [m[2]!, m[3]!]);
  }
  return rows;
}

test('the README rules table lists exactly the rules in the code, with their severity and MITRE IDs', () => {
  const rows = readmeRules();
  expect([...rows.keys()].sort()).toEqual(RULES.map(r => r.id).sort());
  for (const r of RULES) {
    const [severity, what] = rows.get(r.id)!;
    expect(severity, r.id).toContain(r.severity);
    for (const id of r.mitre) expect(what, `${r.id} ${id}`).toContain(id);
  }
});
