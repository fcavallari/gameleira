import { describe, expect, test } from 'vitest';
import { analyze, type Finding } from '../src/rules/engine';
import { MITRE_NAMES } from '../src/rules/mitre';
import { RULES } from '../src/rules/rules';
import type { FixtureName } from './fixtures';
import { queued } from './helpers';
import { apple, capture, img, persistenceItem, proc } from './synth';

const FIXTURES: FixtureName[] = ['es-lab.jsonl', 'atomic_stealer.json', 'rustbucket.json', 'shlayer.json', 'spritetree_demo.json'];

/** Every finding of an analysis: queued and context-only. */
function allFindings(a: ReturnType<typeof analyze>): Finding[] {
  return [...a.queue.flatMap(q => q.findings), ...[...a.contextOnly.values()].flat()];
}

describe('MITRE names', () => {
  test('every MITRE ID a rule can cite has a name', () => {
    for (const r of RULES) {
      expect(r.mitre.length, r.id).toBeGreaterThan(0);
      for (const id of r.mitre) expect(MITRE_NAMES[id], `${r.id} ${id}`).toBeTruthy();
    }
  });
  test('findings on the fixtures cite only IDs their rule declares', () => {
    for (const f of FIXTURES) {
      for (const fd of allFindings(queued(f).a)) {
        const rule = RULES.find(r => r.id === fd.ruleId)!;
        for (const id of fd.mitre) expect(rule.mitre, `${f} ${fd.ruleId}`).toContain(id);
      }
    }
  });
});

describe('MITRE fit', () => {
  const mitreOf = (id: string) => RULES.find(r => r.id === id)!.mitre;
  test('orphaned is Break Process Trees', () => expect(mitreOf('orphaned')).toEqual(['T1036.009']));
  test('unsigned and adhoc are Masquerading, explained as a trait', () => {
    for (const id of ['unsigned', 'adhoc']) {
      const r = RULES.find(x => x.id === id)!;
      expect(r.mitre).toEqual(['T1036']);
      expect(r.explanation).toMatch(/not a technique by itself/);
    }
  });
  test('dscl -authonly is GUI Input Capture only', () => {
    const r = RULES.find(x => x.id === 'dscl-authonly')!;
    expect(r.mitre).toEqual(['T1056.002']);
    expect(r.explanation).toMatch(/verif\w+ a password the attacker just phished/);
  });
});

describe('persistence chip and title follow the item type', () => {
  const finding = (o: Parameters<typeof persistenceItem>[0]) =>
    analyze(capture([], [persistenceItem({ executablePath: '/Applications/X.app/Contents/MacOS/X', ...o })])).queue[0]!.findings[0]!;
  test('agent', () => {
    const f = finding({ itemType: 3, plistPath: '/Library/LaunchAgents/x.plist' });
    expect(f.mitre).toEqual(['T1543.001']);
    expect(f.title).toBe('Launch agent registered');
  });
  test('daemon', () => {
    const f = finding({ itemType: 4, plistPath: '/Library/LaunchDaemons/x.plist' });
    expect(f.mitre).toEqual(['T1543.004']);
    expect(f.title).toBe('Launch daemon registered');
  });
  test('login item and app are Login Items', () => {
    for (const t of [0, 1, 2]) expect(finding({ itemType: t, appPath: '/Applications/X.app/' }).mitre).toEqual(['T1547.015']);
    expect(finding({ itemType: 2 }).title).toBe('Login item registered');
  });
  test('unknown type falls back to the plist directory', () => {
    expect(finding({ plistPath: '/Users/u/Library/LaunchAgents/x.plist' }).mitre).toEqual(['T1543.001']);
    expect(finding({ plistPath: '/Library/LaunchDaemons/x.plist' }).mitre).toEqual(['T1543.004']);
  });
  test('es-lab studyguide is a launch agent', () => {
    const f = queued('es-lab.jsonl').items.find(x => x.p?.pid === 41865)!.item.findings.find(x => x.ruleId === 'persistence-item')!;
    expect(f.mitre).toEqual(['T1543.001']);
    expect(f.title).toBe('Launch agent registered');
  });
  test('a plist written into LaunchDaemons cites the daemon technique only', () => {
    const p = proc('100:1', [apple('/bin/cp', ['cp', 'a', '/Library/LaunchDaemons/x.plist'])]);
    p.fileOps.push({ kind: 'create', path: '/Library/LaunchDaemons/x.plist', time: 't', seq: 2 });
    const f = analyze(capture([p])).queue[0]!.findings.find(x => x.ruleId === 'persistence-plist')!;
    expect(f.mitre).toEqual(['T1543.004']);
    expect(f.title).toBe('Launch daemon plist written');
  });
});

// keep `img` referenced for later suites
void img;
