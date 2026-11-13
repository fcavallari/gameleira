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

describe('persistence findings attach to app, then instigator, then plist creator', () => {
  const smd = proc('558:1', [apple('/usr/libexec/smd', [])]);
  const btmd = proc('750:1', [apple('/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd', [])]);
  const evil = proc('900:1', [img({ path: '/Applications/Evil.app/Contents/MacOS/Evil', signingId: 'evil', teamId: 'ABCDE12345' })]);
  const helper = proc('901:1', [img({ path: '/Applications/Evil.app/Contents/MacOS/Helper', signingId: 'helper', teamId: 'ABCDE12345' })]);
  const cat = proc('902:1', [apple('/bin/cat', ['cat'])]);
  const ghost = proc('903:1', [], { ghost: true });
  const where = (o: Parameters<typeof persistenceItem>[0]) => {
    const a = analyze(capture([smd, btmd, evil, helper, cat, ghost], [persistenceItem({ itemType: 2, appPath: '/Applications/Evil.app/', ...o })]));
    const q = a.queue.find(x => x.findings.some(f => f.ruleId === 'persistence-item'))!;
    return q.procId ?? q.key;
  };
  test('the registering app', () => expect(where({ app: '900:1', instigator: '901:1', creator: '902:1' })).toBe('900:1'));
  test('the instigator when there is no app', () => expect(where({ instigator: '901:1', creator: '902:1' })).toBe('901:1'));
  test('never the system smd or backgroundtaskmanagementd: the plist creator instead', () => {
    expect(where({ instigator: '558:1', creator: '902:1' })).toBe('902:1');
    expect(where({ app: '750:1', instigator: '558:1', creator: '902:1' })).toBe('902:1');
  });
  test('a ghost or pathless app or instigator is skipped', () => expect(where({ app: '903:1', instigator: '903:1', creator: '902:1' })).toBe('902:1'));
  test('standalone when nothing usable is captured', () => expect(where({ instigator: '558:1' })).toBe('i:btm:9'));
  test('es-lab: studyguide stays on cat, GoogleUpdater stays standalone (both instigated by smd)', () => {
    const q = queued('es-lab.jsonl');
    expect(q.items.find(x => x.p?.pid === 41865)!.item.findings.map(f => f.ruleId)).toContain('persistence-item');
    expect(q.items.some(x => x.item.key === 'i:btm:7710')).toBe(true);
  });
});

describe('odd-location-exec: build folders, nesting, and explanations from the trigger', () => {
  const adhoc = (path: string) => analyze(capture([proc('100:1', [img({ path, signingId: 'x', csFlags: 0x2 })])]));
  const oddFinding = (a: ReturnType<typeof analyze>) =>
    allFindings(a).find(f => f.ruleId === 'odd-location-exec');
  test('ad-hoc tools in build folders are context-only', () => {
    for (const p of ['/Users/u/proj/.build/debug/tool', '/Users/u/infra/.terraform/providers/x/tf-provider',
      '/Users/u/web/.next/cache/x', '/Users/u/proj/target/.fingerprint/x', '/Users/u/proj/.gradle/x/y']) {
      const a = adhoc(p);
      expect(a.queue, p).toHaveLength(0);
      expect(oddFinding(a)?.severity, p).toBe('low');
    }
  });
  test('a tooling folder under a buried hidden folder stays strong', () =>
    expect(adhoc('/Users/u/Desktop/.hidden/node_modules/x').queue[0]?.severity).toBe('high'));
  test('a tooling folder with no hidden folder is not an odd location', () =>
    expect(oddFinding(adhoc('/Users/u/proj/node_modules/esbuild/bin/esbuild'))).toBeUndefined());
  test('locations compare case-insensitively', () =>
    expect(adhoc('/Users/shared/agent').queue[0]?.severity).toBe('high'));
  test('the explanation names the location', () => {
    const cases: [string, RegExp][] = [
      ['/private/tmp/x', /temporary folder/], ['/var/tmp/x', /temporary folder/],
      ['/Users/u/Downloads/x', /Downloads folder/], ['/Users/Shared/x', /shared folder/],
      ['/Volumes/Installer/x', /disk image or external volume/],
      ['/private/var/folders/ab/T/AppTranslocation/1/d/X.app/Contents/MacOS/X', /translocated/],
      ['/Users/u/Desktop/.hidden/x', /hidden folder/],
    ];
    for (const [p, re] of cases) {
      const f = oddFinding(adhoc(p))!;
      expect(f.explanation, p).toMatch(re);
      expect(f.explanation, p).toMatch(/^Ran a program from/);
    }
    expect(oddFinding(adhoc('/Users/u/.cargo/bin/x'))!.explanation).toMatch(/developer tools/);
  });
  test('a script hit says it was a script', () => {
    const bash = apple('/bin/bash', ['/bin/bash', '/Users/u/Desktop/.hidden/run.command'], { script: '/Users/u/Desktop/.hidden/run.command' });
    const f = oddFinding(analyze(capture([proc('100:1', [bash])])))!;
    expect(f.explanation).toMatch(/^Ran a script from a hidden folder/);
    expect(f.evidence).toMatch(/hidden folder/);
  });
});
