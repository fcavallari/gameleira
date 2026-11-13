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

describe('persistence-item severity says why', () => {
  const sevOf = (exe: string, images: ReturnType<typeof img>[] = []) => {
    const procs = images.map((i, n) => proc(`${500 + n}:1`, [i]));
    const f = analyze(capture(procs, [persistenceItem({ itemType: 3, plistPath: '/Users/u/Library/LaunchAgents/x.plist', executablePath: exe })]))
      .queue.flatMap(q => q.findings).find(x => x.ruleId === 'persistence-item')!;
    return { severity: f.severity, evidence: f.evidence };
  };
  test('a loose program in the home folder is high, even unseen', () => {
    const r = sevOf('/Users/u/Library/Application Support/com.apple.updates/agent');
    expect(r.severity).toBe('high');
    expect(r.evidence).toMatch(/high: .*home folder/);
  });
  test('ad-hoc counts as unsigned', () => {
    const exe = '/Users/u/Applications/Tool.app/Contents/MacOS/Tool';
    const r = sevOf(exe, [img({ path: exe, signingId: 'tool', csFlags: 0x2 })]);
    expect(r.severity).toBe('high');
    expect(r.evidence).toMatch(/high: the program ran ad-hoc signed in this capture/);
  });
  test('temp, shared, caches and interpreter paths are high, case-insensitively', () => {
    for (const exe of ['/users/shared/agent', '/Users/Shared/agent', '/var/tmp/agent', '/private/var/tmp/agent',
      '/Users/u/Library/Caches/x/agent', '/usr/bin/python', '/usr/bin/python3', '/usr/bin/perl5.30', '/bin/zsh'])
      expect(sevOf(exe).severity, exe).toBe('high');
  });
  test('an app bundle in the home folder whose signature was not seen stays med, and says so', () => {
    const r = sevOf('/Users/u/Library/Application Support/Google/GoogleUpdater/Current/GoogleUpdater.app/Contents/MacOS/GoogleUpdater');
    expect(r.severity).toBe('med');
    expect(r.evidence).toMatch(/med: .*signature was not seen in this capture/);
  });
  test('a team-signed app outside user-writable folders is med', () => {
    const exe = '/Applications/X.app/Contents/MacOS/X';
    const r = sevOf(exe, [img({ path: exe, signingId: 'x', teamId: 'ABCDE12345' })]);
    expect(r.severity).toBe('med');
    expect(r.evidence).toMatch(/med: /);
  });
  test('es-lab: studyguide high for its shell, GoogleUpdater med', () => {
    const q = queued('es-lab.jsonl');
    expect(q.items.find(x => x.p?.pid === 41865)!.item.findings.find(f => f.ruleId === 'persistence-item')!.evidence).toMatch(/high: it runs a shell \(sh\)/);
    expect(q.items.find(x => x.item.key === 'i:btm:7710')!.item.severity).toBe('med');
  });
});

describe('process-scoped rules see processes that fork and never exec', () => {
  const zsh = proc('500:1', [apple('/bin/zsh', ['zsh'])], { exitTime: '2026-11-12T00:00:01.000Z' });
  const forkOnly = (o: Parameters<typeof proc>[2] = {}) =>
    proc('501:1', [apple('/bin/zsh', ['zsh'], { token: '501:1', inherited: true, seq: 3 })],
      { forkParent: '500:1', originalParent: '500:1', originalPpid: 500, ppid: 1, ...o });
  test('a fork-only child reparented to launchd is orphaned', () => {
    const q = analyze(capture([zsh, forkOnly()])).queue.find(x => x.procId === '501:1');
    expect(q?.findings.map(f => f.ruleId)).toContain('orphaned');
  });
  test('a fork-only child writing a launch agent plist is high', () => {
    const p = forkOnly({ ppid: 500 });
    p.fileOps.push({ kind: 'create', path: '/Users/u/Library/LaunchAgents/evil.plist', time: 't', seq: 4 });
    const q = analyze(capture([zsh, p])).queue.find(x => x.procId === '501:1');
    expect(q?.severity).toBe('high');
    expect(q?.findings.map(f => f.ruleId)).toEqual(['persistence-plist']);
  });
  test('a renamed-into-place plist counts too', () => {
    const p = forkOnly({ ppid: 500 });
    p.fileOps.push({ kind: 'rename', path: '/tmp/x', toPath: '/Library/LaunchDaemons/evil.plist', time: 't', seq: 4 });
    expect(analyze(capture([zsh, p])).queue.find(x => x.procId === '501:1')?.findings.map(f => f.ruleId)).toEqual(['persistence-plist']);
  });
  test('ghosts are skipped', () => {
    const g = proc('502:1', [], { ghost: true, ppid: 1, originalPpid: 500 });
    expect(analyze(capture([zsh, g])).queue.some(x => x.procId === '502:1')).toBe(false);
  });
  test('fire once per process, even with several exec images', () => {
    const p = proc('503:1', [apple('/bin/sh', ['sh'], { seq: 1 }), apple('/bin/bash', ['sh'], { seq: 2 })], { originalPpid: 500, originalParent: '500:1', ppid: 1 });
    const fs = analyze(capture([zsh, p])).queue.find(x => x.procId === '503:1')!.findings.filter(f => f.ruleId === 'orphaned');
    expect(fs).toHaveLength(1);
  });
});

describe('keychain access and recon by technique', () => {
  const run = (path: string, args: string[]) => analyze(capture([proc('100:1', [apple(path, args)])]));
  test('security reading or exporting keychain items is high T1555.001', () => {
    for (const args of [['security', 'find-generic-password', '-ga', 'Chrome'], ['security', 'find-internet-password', '-s', 'x'],
      ['security', 'dump-keychain', '-d'], ['security', 'export', '-k', 'login.keychain'], ['security', '-q', 'unlock-keychain', '-p', 'pw']]) {
      const q = run('/usr/bin/security', args).queue[0];
      expect(q?.severity, args.join(' ')).toBe('high');
      const f = q!.findings.find(x => x.ruleId === 'keychain-access')!;
      expect(f.mitre).toEqual(['T1555.001']);
      expect(f.explanation).toContain(`security ${args.find(a => !a.startsWith('-') && a !== 'security')}`);
    }
  });
  test('other security subcommands are not keychain access, and security is no longer recon', () => {
    const a = run('/usr/bin/security', ['security', 'find-certificate', '-c', 'export']);
    expect(allFindings(a).map(f => f.ruleId)).toEqual([]);
  });
  test('recon cites the technique of the tool that ran', () => {
    const cases: [string, string][] = [['ps', 'T1057'], ['networksetup', 'T1016'], ['scutil', 'T1016'], ['airport', 'T1016'],
      ['csrutil', 'T1518.001'], ['spctl', 'T1518.001'], ['whoami', 'T1033'], ['id', 'T1033'], ['system_profiler', 'T1082'],
      ['sw_vers', 'T1082'], ['sysctl', 'T1082'], ['ioreg', 'T1082'], ['uname', 'T1082'], ['hostname', 'T1082']];
    for (const [tool, id] of cases) {
      const f = allFindings(run(`/usr/bin/${tool}`, [tool])).find(x => x.ruleId === 'recon')!;
      expect(f.mitre, tool).toEqual([id]);
    }
  });
});
