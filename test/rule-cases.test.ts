import { describe, expect, test } from 'vitest';
import { analyze, type Finding } from '../src/rules/engine';
import { MITRE_NAMES } from '../src/rules/mitre';
import { RULES } from '../src/rules/rules';
import type { FixtureName } from './fixtures';
import { queued } from './helpers';
import { apple, capture, img, op, persistenceItem, proc } from './synth';

const FIXTURES: FixtureName[] = ['es-lab.jsonl', 'atomic_stealer.json', 'rustbucket.json', 'shlayer.json', 'spritetree_demo.json'];

/** Every finding of an analysis: queued and context-only. */
function allFindings(a: ReturnType<typeof analyze>): Finding[] {
  return [...a.queue.flatMap(q => q.findings), ...[...a.contextOnly.values()].flat()];
}

describe('MITRE names', () => {
  test('every MITRE ID a rule can cite has a name; only trait rules cite none', () => {
    for (const r of RULES) {
      if (r.trait) expect(r.mitre, r.id).toEqual([]);
      else expect(r.mitre.length, r.id).toBeGreaterThan(0);
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
  test('unsigned and adhoc are traits with no technique, and say so', () => {
    for (const id of ['unsigned', 'adhoc']) {
      const r = RULES.find(x => x.id === id)!;
      expect(r.trait).toBe(true);
      expect(r.mitre).toEqual([]);
      expect(r.explanation).toMatch(/not a technique by itself/);
    }
    const f = analyze(capture([proc('100:1', [img({ path: '/opt/x/tool', signingId: null })])])).queue[0]!.findings.find(x => x.ruleId === 'unsigned')!;
    expect(f.trait).toBe(true);
    expect(f.mitre).toEqual([]);
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
  const kc = (args: string[]) => allFindings(run('/usr/bin/security', ['security', ...args])).find(x => x.ruleId === 'keychain-access');
  test('high: printing a browser Safe Storage key or a wallet entry, or dump-keychain -d', () => {
    for (const args of [['find-generic-password', '-ga', 'Chrome'], ['find-generic-password', '-w', '-s', 'Chrome Safe Storage'],
      ['find-generic-password', '-wa', 'Microsoft Edge'], ['find-generic-password', '-g', '-s', 'Brave Safe Storage'],
      ['find-internet-password', '-w', '-s', 'exodus.com'], ['find-generic-password', '-w', '-l', 'MetaMask vault'],
      ['dump-keychain', '-d']]) {
      const f = kc(args);
      expect(f?.severity, args.join(' ')).toBe('high');
      expect(f?.mitre).toEqual(['T1555.001']);
    }
    expect(kc(['find-generic-password', '-ga', 'Chrome'])!.explanation).toMatch(/Safe Storage/);
    expect(kc(['find-generic-password', '-wa', 'Exodus'])!.explanation).toMatch(/wallet/);
    expect(kc(['dump-keychain', '-d'])!.explanation).toMatch(/every item/);
  });
  test('med: printing any other saved password', () => {
    const f = kc(['find-internet-password', '-s', 'github.com', '-w'])!;
    expect(f.severity).toBe('med');
    expect(f.explanation).toMatch(/prints a saved password/);
  });
  test('low and context-only: attribute lookups, unlock, export, dump without -d', () => {
    for (const args of [['find-generic-password', '-s', 'Chrome Safe Storage'], ['unlock-keychain', '-p', 'pw'],
      ['export', '-k', 'login.keychain'], ['dump-keychain'], ['-q', 'unlock-keychain']]) {
      const a = run('/usr/bin/security', ['security', ...args]);
      expect(a.queue, args.join(' ')).toHaveLength(0);
      expect(a.contextOnly.get('100:1')?.find(x => x.ruleId === 'keychain-access')?.severity, args.join(' ')).toBe('low');
    }
    expect(kc(['find-generic-password', '-s', 'x'])!.explanation).toMatch(/not its secret/);
  });
  test('other security subcommands are not keychain access, and security is no longer recon', () => {
    const a = run('/usr/bin/security', ['security', 'find-certificate', '-c', 'export']);
    expect(allFindings(a).map(f => f.ruleId)).toEqual([]);
  });
  test('recon cites the technique of the tool that ran', () => {
    const cases: [string, string][] = [['ps', 'T1057'], ['networksetup', 'T1016'], ['scutil', 'T1016'], ['airport', 'T1016.002'],
      ['csrutil', 'T1518.001'], ['spctl', 'T1518.001'], ['whoami', 'T1033'], ['id', 'T1033'], ['system_profiler', 'T1082'],
      ['sw_vers', 'T1082'], ['sysctl', 'T1082'], ['ioreg', 'T1082'], ['uname', 'T1082'], ['hostname', 'T1082']];
    for (const [tool, id] of cases) {
      const f = allFindings(run(`/usr/bin/${tool}`, [tool])).find(x => x.ruleId === 'recon')!;
      expect(f.mitre, tool).toEqual([id]);
    }
  });
});

describe('osascript: dialogs and script sources', () => {
  const osa = (args: string[], o: Parameters<typeof apple>[2] = {}) =>
    allFindings(analyze(capture([proc('100:1', [apple('/usr/bin/osascript', ['osascript', ...args], o)])])));
  const ids = (fs: Finding[]) => fs.map(f => f.ruleId);
  test('mentioning "password" is not a fake prompt', () =>
    expect(ids(osa(['-e', 'set f to (path to desktop as text) & "passwords.txt"']))).toEqual([]));
  test('display dialog is, and hidden answer is explained as a password-style prompt', () => {
    expect(ids(osa(['-e', 'display dialog "Error" buttons {"OK"}']))).toEqual(['fake-prompt']);
    expect(osa(['-e', 'display dialog "pw" default answer "" with hidden answer'])[0]!.explanation).toMatch(/hides it as dots/);
    expect(ids(osa(['-l', 'JavaScript', '-e', 'app.displayDialog("x", {defaultAnswer: "", hiddenAnswer: true})']))).toEqual(['fake-prompt']);
  });
  test('a script file in an odd location is osascript-script, med, T1059.002 (T1059.007 for JavaScript)', () => {
    for (const args of [['/tmp/x.scpt'], ['-l', 'JavaScript', '/private/tmp/x.js'], ['-s', 'o', '/Users/u/Downloads/a.scpt', 'arg']]) {
      const f = osa(args).find(x => x.ruleId === 'osascript-script');
      expect(f?.severity, args.join(' ')).toBe('med');
      expect(f?.mitre).toEqual(args.includes('JavaScript') ? ['T1059.007'] : ['T1059.002']);
    }
    expect(osa(['x.scpt'], { cwd: '/tmp/work' }).find(x => x.ruleId === 'osascript-script')?.evidence).toContain('/tmp/work/x.scpt');
  });
  test('a script file in a normal place is not flagged', () =>
    expect(ids(osa(['/Users/u/Library/Scripts/ok.scpt']))).toEqual([]));
  test('AppleScript piped into osascript is osascript-script', () => {
    expect(ids(osa([], { stdinIsPipe: true }))).toEqual(['osascript-script']);
    expect(ids(osa(['-'], { stdinIsPipe: true }))).toEqual(['osascript-script']);
    expect(osa([], { stdinIsPipe: true })[0]!.explanation).toMatch(/piped/);
  });
  test('no pipe, or an inline -e script, is not', () => {
    expect(ids(osa([], { stdinIsPipe: false }))).toEqual([]);
    expect(ids(osa(['-e', 'beep'], { stdinIsPipe: true }))).toEqual([]);
  });
});

describe('recon bursts: a sliding 60 s window under one parent', () => {
  const at = (s: number) => new Date(Date.UTC(2026, 10, 12, 0, 0, s)).toISOString();
  const parent = proc('1:1', [apple('/bin/zsh', ['zsh'])]);
  const tool = (n: number, name: string, s: number) =>
    proc(`${200 + n}:1`, [apple(`/usr/bin/${name}`, [name], { time: at(s), seq: 10 + n })], { originalParent: '1:1', originalPpid: 1 });
  const run = (...ts: [string, number][]) => analyze(capture([parent, ...ts.map(([name, s], n) => tool(n, name, s))]));
  test('three tools spread over 110 s are not a burst (no 60 s window holds three)', () =>
    expect(run(['whoami', 0], ['sw_vers', 55], ['hostname', 110]).queue).toHaveLength(0));
  test('three tools within 60 s queue every member, marked as a burst', () => {
    const a = run(['whoami', 0], ['sw_vers', 30], ['hostname', 59], ['uname', 200]);
    expect(a.queue.map(q => q.procId).sort()).toEqual(['200:1', '201:1', '202:1']);
    expect(a.queue.every(q => q.reconBurst && !q.inFlaggedChain)).toBe(true);
  });
  test('a window that later gains a third tool takes in its earlier members', () => {
    const a = run(['ps', 0], ['ps', 20], ['whoami', 40], ['sw_vers', 70]);
    expect(a.queue.map(q => q.procId).sort()).toEqual(['201:1', '202:1', '203:1']);
  });
  test('rows queued for another reason are not bursts', () => {
    const q = queued('es-lab.jsonl').items;
    expect(q.every(x => !x.item.reconBurst)).toBe(true);
    expect(queued('atomic_stealer.json').items.filter(x => x.item.reconBurst).length).toBeGreaterThanOrEqual(3);
  });
});

describe('smaller rule gaps', () => {
  const findings = (path: string, args: string[], o: Parameters<typeof apple>[2] = {}) =>
    allFindings(analyze(capture([proc('100:1', [apple(path, args, o)])])));
  const has = (id: string, path: string, args: string[], o: Parameters<typeof apple>[2] = {}) =>
    findings(path, args, o).some(f => f.ruleId === id);

  describe('download', () => {
    const wget = (...a: string[]) => has('download', '/usr/local/bin/wget', ['wget', ...a, 'https://example.com/x']);
    const curl = (...a: string[]) => has('download', '/usr/bin/curl', ['curl', ...a, 'https://example.com/x']);
    test('wget saves to a file by default; -o is only its log', () => {
      expect(wget()).toBe(true);
      expect(wget('-o', '/dev/null')).toBe(true);
      expect(wget('-q', '-o', 'log.txt')).toBe(true);
    });
    test('wget writing to stdout or /dev/null, or only checking (--spider), does not fire', () => {
      expect(wget('-O', '-')).toBe(false);
      expect(wget('-qO-')).toBe(false);
      expect(wget('--output-document=/dev/null')).toBe(false);
      expect(wget('--output-document', '-')).toBe(false);
      expect(wget('--spider')).toBe(false);
    });
    test('curl --remote-name and --remote-name-all fire', () => {
      expect(curl('--remote-name')).toBe(true);
      expect(curl('--remote-name-all')).toBe(true);
      expect(curl('-o/tmp/x')).toBe(true);
      expect(curl('-o/dev/null')).toBe(false);
    });
  });

  describe('shell-from-pipe covers -s and interpreters', () => {
    const piped = { stdinIsPipe: true };
    const pipe = (path: string, args: string[]) => findings(path, args, piped).find(f => f.ruleId === 'shell-from-pipe');
    test('bash -s and sh -s read their commands from stdin', () => {
      expect(pipe('/bin/bash', ['bash', '-s'])?.mitre).toEqual(['T1059.004']);
      expect(pipe('/bin/sh', ['sh', '-s', 'arg1', 'arg2'])).toBeDefined();
      expect(pipe('/bin/bash', ['bash', '-x'])).toBeDefined();
    });
    test('python, perl and ruby reading a piped script', () => {
      expect(pipe('/usr/bin/python3', ['python3'])?.mitre).toEqual(['T1059.006']);
      expect(pipe('/usr/bin/python3', ['python3', '-'])?.mitre).toEqual(['T1059.006']);
      expect(pipe('/usr/bin/perl', ['perl'])?.mitre).toEqual(['T1059']);
      expect(pipe('/usr/bin/ruby', ['ruby', '-'])?.mitre).toEqual(['T1059']);
      expect(pipe('/usr/bin/python3', ['python3'])?.explanation).toMatch(/python3 ran a script piped into it/);
    });
    test('inline code, a script file or -c is not reading from the pipe', () => {
      expect(pipe('/bin/sh', ['sh', '-c', 'grep "Model Name"'])).toBeUndefined();
      expect(pipe('/bin/bash', ['bash', '/tmp/x.sh'])).toBeUndefined();
      expect(pipe('/usr/bin/perl', ['perl', '-0777pe', 's|a|b|gs'])).toBeUndefined();
      expect(pipe('/usr/bin/perl', ['perl', '-MData::Dumper', '-ne', 'print'])).toBeUndefined();
      expect(pipe('/usr/bin/python3', ['python3', '-c', 'print(1)'])).toBeUndefined();
      expect(pipe('/usr/bin/python3', ['python3', '-m', 'json.tool'])).toBeUndefined();
      expect(pipe('/usr/bin/python3', ['python3', 'x.py'])).toBeUndefined();
      expect(findings('/usr/bin/python3', ['python3'], { stdinIsPipe: false }).some(f => f.ruleId === 'shell-from-pipe')).toBe(false);
    });
    test('perl re-exec into perl5.30 fires once', () => {
      const p = proc('100:1', [apple('/usr/bin/perl', ['perl'], { ...piped, seq: 1 }), apple('/usr/bin/perl5.30', ['perl'], { ...piped, seq: 2 })]);
      expect(analyze(capture([p])).queue[0]!.findings.filter(f => f.ruleId === 'shell-from-pipe')).toHaveLength(1);
    });
  });

  test('dscl . authonly (no dash) is a password check', () =>
    expect(has('dscl-authonly', '/usr/bin/dscl', ['dscl', '.', 'authonly', 'sandy', 'pw'])).toBe(true));

  describe('archive-staging', () => {
    const arch = (args: string[], o: Parameters<typeof apple>[2] = {}) =>
      findings(`/usr/bin/${args[0]}`, args, o).find(f => f.ruleId === 'archive-staging');
    test('tar create mode anywhere in the args', () => {
      expect(arch(['tar', '-C', '/tmp', '-czf', 'out.tgz', 'stage'])?.severity).toBe('high');
      expect(arch(['tar', '--exclude', '*.log', '--create', '-f', 'x.tar', 'dir'])?.severity).toBe('med');
      expect(arch(['tar', '-xzf', 'x.tgz'])).toBeUndefined();
    });
    test('the staging path from any arg: attached, --opt=value, or relative to a temp working dir', () => {
      expect(arch(['tar', '-czf', 'out.tgz', '-C/tmp/stage', '.'])?.severity).toBe('high');
      expect(arch(['tar', '--directory=/private/tmp/s', '-czf', 'o.tgz', '.'])?.severity).toBe('high');
      expect(arch(['zip', '-r', 'out.zip', 'loot'], { cwd: '/private/tmp/w' })?.severity).toBe('high');
      expect(arch(['zip', '-r', 'out.zip', 'docs'], { cwd: '/Users/u/Documents' })?.severity).toBe('med');
    });
  });

  test('payload-decode: openssl base64 -d and openssl <cipher> -d; -md is not -d', () => {
    expect(has('payload-decode', '/usr/bin/openssl', ['openssl', 'base64', '-d', '-in', 'x'])).toBe(true);
    expect(has('payload-decode', '/usr/bin/openssl', ['openssl', 'aes-256-cbc', '-d', '-in', 'x'])).toBe(true);
    expect(has('payload-decode', '/usr/bin/openssl', ['openssl', 'enc', '-md', 'md5', '-aes-256-cbc', '-in', 'x'])).toBe(false);
    expect(has('payload-decode', '/usr/bin/openssl', ['openssl', 'req', '-days', '3', '-nodes'])).toBe(false);
  });

  test('an empty signing ID is unsigned', () => {
    const fs = allFindings(analyze(capture([proc('100:1', [img({ path: '/opt/x/tool', signingId: '' })])])));
    expect(fs.map(f => f.ruleId)).toContain('unsigned');
  });

  describe('shell-under-app uses the parent image at the time of the fork', () => {
    const app = img({ path: '/Applications/Evil.app/Contents/MacOS/Evil', signingId: 'evil', teamId: 'T', seq: 1 });
    const later = apple('/usr/bin/true', ['true'], { seq: 10 });
    const child = (parentImages: ReturnType<typeof img>[]) => {
      const parent = proc('50:1', parentImages);
      const sh = proc('51:1', [apple('/bin/sh', ['sh', '-c', 'id'], { seq: 5 })], { originalParent: '50:1', firstSeq: 5 });
      return allFindings(analyze(capture([parent, sh]))).some(f => f.ruleId === 'shell-under-app');
    };
    test('an app that later exec\'d something else still launched the shell', () => expect(child([app, later])).toBe(true));
    test('a process that became an app only after the fork did not', () =>
      expect(child([apple('/bin/zsh', ['zsh'], { seq: 1 }), { ...app, seq: 10 }])).toBe(false));
  });
});

describe('review follow-ups', () => {
  const itemFinding = (o: Parameters<typeof persistenceItem>[0], procs: ReturnType<typeof proc>[] = []) =>
    analyze(capture(procs, [persistenceItem(o)])).queue.flatMap(q => q.findings).find(f => f.ruleId === 'persistence-item')!;
  test('a login item whose URL is the app is not called a plist, and is judged by the app\'s location', () => {
    const f = itemFinding({ itemType: 2, plistPath: '/Users/Shared/Evil.app/', appPath: '/Users/Shared/Evil.app/', executablePath: null });
    expect(f.evidence).not.toMatch(/plist/);
    expect(f.evidence).toMatch(/^item \/Users\/Shared\/Evil\.app/);
    expect(f.severity).toBe('high');
    expect(f.evidence).toMatch(/high: the app is in \/Users\/Shared, which every user can write to/);
  });
  test('a relative executable path is resolved against the app', () => {
    const f = itemFinding({ itemType: 2, appPath: '/private/tmp/X.app/', executablePath: 'Contents/MacOS/X' });
    expect(f.severity).toBe('high');
    expect(f.evidence).toMatch(/runs \/private\/tmp\/X\.app\/Contents\/MacOS\/X/);
  });
  test('a relative executable with no app is not placed anywhere', () => {
    const f = itemFinding({ itemType: 3, executablePath: 'bin/agent' });
    expect(f.severity).toBe('med');
    expect(f.evidence).toMatch(/med: the event names no program it can place/);
  });
  test('an app in /Applications that ran ad-hoc signed is high', () => {
    const exe = '/Applications/X.app/Contents/MacOS/X';
    const f = itemFinding({ itemType: 1, appPath: '/Applications/X.app/' }, [proc('5:1', [img({ path: exe, signingId: 'x', csFlags: 0x2 })])]);
    expect(f.severity).toBe('high');
  });

  describe('archive-staging is not high for ordinary project folders', () => {
    const arch = (args: string[], cwd: string) =>
      allFindings(analyze(capture([proc('100:1', [apple(`/usr/bin/${args[0]}`, args, { cwd })])]))).find(f => f.ruleId === 'archive-staging')!;
    test('exclude patterns and hidden project folders', () => {
      expect(arch(['zip', '-r', 'site.zip', '.', '-x', '.git/*', '*.log'], '/Users/u/proj').severity).toBe('med');
      expect(arch(['zip', '-r', 'x.zip', '.github'], '/Users/u/proj').severity).toBe('med');
      expect(arch(['tar', '-czf', 'o.tgz', '--exclude=.venv/lib', 'src'], '/Users/u/proj').severity).toBe('med');
      expect(arch(['tar', '-czf', 'o.tgz', '--exclude', '/tmp/x', 'src'], '/Users/u/proj').severity).toBe('med');
    });
    test('a developer tooling folder given as an absolute path is not staging', () =>
      expect(arch(['zip', '-r', '/Users/u/proj/.git/x.zip', 'a'], '/Users/u').severity).toBe('med'));
    test('a buried hidden folder still is', () =>
      expect(arch(['zip', '-r', '/Users/u/Desktop/.loot/x.zip', 'a'], '/Users/u').severity).toBe('high'));
  });

  test('persistence-plist says it saw a plist written, not a registration', () => {
    const p = proc('100:1', [apple('/bin/cp', ['cp', 'a', '/Users/u/Library/LaunchAgents/x.plist'])]);
    p.fileOps.push({ kind: 'create', path: '/Users/u/Library/LaunchAgents/x.plist', time: 't', seq: 2 });
    const f = analyze(capture([p])).queue[0]!.findings.find(x => x.ruleId === 'persistence-plist')!;
    expect(f.explanation).toMatch(/^Wrote a launch agent plist/);
    expect(f.explanation).toMatch(/No registration event/);
  });

  test('osascript -l JavaScript is JavaScript for Automation, T1059.007', () => {
    const f = allFindings(analyze(capture([proc('100:1', [apple('/usr/bin/osascript', ['osascript', '-l', 'JavaScript', '/tmp/x.js'])])])))
      .find(x => x.ruleId === 'osascript-script')!;
    expect(f.mitre).toEqual(['T1059.007']);
    expect(f.explanation).toMatch(/JavaScript/);
    expect(f.explanation).not.toMatch(/AppleScript/);
  });
});

describe('fix round 1', () => {
  const findingsOf = (path: string, args: string[], o: Parameters<typeof apple>[2] = {}) =>
    allFindings(analyze(capture([proc('100:1', [apple(path, args, o)])])));
  const ruleIds = (path: string, args: string[], o: Parameters<typeof apple>[2] = {}) => findingsOf(path, args, o).map(f => f.ruleId);

  describe('shell-from-pipe ignores version and help probes', () => {
    const piped = { stdinIsPipe: true };
    const fires = (path: string, args: string[]) => ruleIds(path, args, piped).includes('shell-from-pipe');
    test('probes', () => {
      for (const [path, args] of [['/usr/bin/python3', ['python3', '--version']], ['/usr/bin/python3', ['python3', '-V']],
        ['/bin/bash', ['bash', '--version']], ['/bin/bash', ['bash', '--help']], ['/bin/zsh', ['zsh', '--version']],
        ['/usr/bin/perl', ['perl', '-v']], ['/usr/bin/ruby', ['ruby', '-v']], ['/usr/bin/ruby', ['ruby', '--version']],
        ['/usr/bin/python3', ['python3', '-h']]] as [string, string[]][])
        expect(fires(path, args), args.join(' ')).toBe(false);
    });
    test('unknown long options do not make it fire', () => {
      expect(fires('/usr/bin/python3', ['python3', '--something'])).toBe(false);
      expect(fires('/usr/bin/ruby', ['ruby', '--yjit'])).toBe(false);
    });
    test('bash --rcfile f reads no script from f; known long options still allow a pipe', () => {
      expect(fires('/bin/bash', ['bash', '--rcfile', 'f'])).toBe(true);
      expect(fires('/bin/bash', ['bash', '--norc', '--noprofile'])).toBe(true);
      expect(fires('/bin/bash', ['bash', '--rcfile', 'f', 'script.sh'])).toBe(false);
    });
  });

  describe('download parses short-flag clusters', () => {
    const curl = (...a: string[]) => ruleIds('/usr/bin/curl', ['curl', ...a]).includes('download');
    const wget = (...a: string[]) => ruleIds('/usr/local/bin/wget', ['wget', ...a]).includes('download');
    test('curl -XPOST and -XOPTIONS are a method, not -O', () => {
      expect(curl('-XPOST', 'https://example.com/api')).toBe(false);
      expect(curl('-XOPTIONS', 'https://example.com/')).toBe(false);
      expect(curl('-H', 'X-Opt: O', 'https://example.com/')).toBe(false);
    });
    test('curl -sLo f and -LO write files', () => {
      expect(curl('-sLo', 'f', 'https://example.com/x')).toBe(true);
      expect(curl('-LO', 'https://example.com/x')).toBe(true);
      expect(curl('-f0L', '-o', '/tmp/x', 'http://example.com/x')).toBe(true);
    });
    test('wget needs a URL; --version and --help are not downloads', () => {
      expect(wget('--version')).toBe(false);
      expect(wget('--help')).toBe(false);
      expect(wget('-V')).toBe(false);
      expect(wget('example.com/file.zip')).toBe(true);
      expect(wget('-q', 'https://example.com/x')).toBe(true);
      expect(wget('-i', 'urls.txt')).toBe(true);
      expect(wget('-U', 'Mozilla/5.0', '-qO-', 'https://example.com/x')).toBe(false);
    });
  });

  describe('security setting changes', () => {
    const f = (path: string, args: string[]) => findingsOf(path, args);
    test('spctl turning Gatekeeper off is high T1562.001', () => {
      for (const flag of ['--master-disable', '--global-disable', '--disable']) {
        const x = f('/usr/sbin/spctl', ['spctl', flag]).find(y => y.ruleId === 'security-setting-change')!;
        expect(x.severity, flag).toBe('high');
        expect(x.mitre).toEqual(['T1562.001']);
        expect(x.explanation).toMatch(/Gatekeeper/);
        expect(f('/usr/sbin/spctl', ['spctl', flag]).some(y => y.ruleId === 'recon'), flag).toBe(false);
      }
    });
    test('spctl --add is a Gatekeeper exception, high T1553.001', () => {
      const x = f('/usr/sbin/spctl', ['spctl', '--add', '/Applications/X.app']).find(y => y.ruleId === 'security-setting-change')!;
      expect(x.severity).toBe('high');
      expect(x.mitre).toEqual(['T1553.001']);
    });
    test('networksetup changing the proxy or DNS is med T1557', () => {
      for (const flag of ['-setwebproxy', '-setsecurewebproxy', '-setautoproxyurl', '-setsocksfirewallproxy', '-setdnsservers']) {
        const fs = f('/usr/sbin/networksetup', ['networksetup', flag, 'Wi-Fi', '127.0.0.1', '8080']);
        const x = fs.find(y => y.ruleId === 'security-setting-change')!;
        expect(x.severity, flag).toBe('med');
        expect(x.mitre).toEqual(['T1557']);
        expect(x.explanation).toMatch(/adware/);
        expect(fs.some(y => y.ruleId === 'recon'), flag).toBe(false);
      }
    });
    test('reading settings is still recon', () => {
      expect(f('/usr/sbin/spctl', ['spctl', '--status']).map(y => y.ruleId)).toEqual(['recon']);
      expect(f('/usr/sbin/networksetup', ['networksetup', '-getwebproxy', 'Wi-Fi']).map(y => y.ruleId)).toEqual(['recon']);
    });
    test('scutil --get is system information; sysctl -w is not recon', () => {
      expect(f('/usr/sbin/scutil', ['scutil', '--get', 'ComputerName']).find(y => y.ruleId === 'recon')!.mitre).toEqual(['T1082']);
      expect(f('/usr/sbin/scutil', ['scutil', '--dns']).find(y => y.ruleId === 'recon')!.mitre).toEqual(['T1016']);
      expect(f('/usr/sbin/sysctl', ['sysctl', '-w', 'kern.x=1'])).toEqual([]);
      expect(f('/usr/sbin/sysctl', ['sysctl', '-n', 'hw.model']).map(y => y.ruleId)).toEqual(['recon']);
    });
  });

  test('persistence reasons are worded for persistence, not for developer tools', () => {
    const r = analyze(capture([], [persistenceItem({ itemType: 3, plistPath: '/Users/u/Library/LaunchAgents/x.plist', executablePath: '/Users/u/.local/bin/agent' })]))
      .queue[0]!.findings[0]!;
    expect(r.severity).toBe('high');
    expect(r.evidence).toMatch(/high: the program is in a dot-folder in the home folder, which the user can write to/);
    expect(r.evidence).not.toMatch(/developer tools/);
  });

  describe('a registration attributed to the app', () => {
    const evil = proc('900:1', [img({ path: '/Applications/Evil.app/Contents/MacOS/Evil', signingId: 'evil', teamId: 'T', seq: 1 })]);
    // whoami has only a gated recon finding, so it is queued only as part of a flagged chain.
    const child = proc('901:1', [apple('/usr/bin/whoami', ['whoami'], { seq: 5 })], { originalParent: '900:1', firstSeq: 5 });
    const cp = proc('902:1', [apple('/bin/cp', ['cp', 'a', 'b'], { seq: 3 })]);
    cp.fileOps.push({ kind: 'create', path: '/Library/LaunchAgents/com.evil.plist', time: 't', seq: 4 });
    const run = (exe: string) => analyze(capture([evil, child, cp], [persistenceItem({
      itemType: 3, plistPath: '/Library/LaunchAgents/com.evil.plist', executablePath: exe, app: '900:1', creator: '902:1',
    })]));
    test('a med finding on the app does not make its children a chain', () => {
      const a = run('/Applications/Evil.app/Contents/MacOS/Evil');
      expect(a.queue.find(q => q.procId === '900:1')!.severity).toBe('med');
      expect(a.queue.some(q => q.procId === '901:1')).toBe(false);
    });
    test('a high one does', () => {
      const a = run('/Users/Shared/evil');
      expect(a.queue.find(q => q.procId === '900:1')!.severity).toBe('high');
      expect(a.queue.find(q => q.procId === '901:1')?.inFlaggedChain).toBe(true);
    });
    test('the plist writer still gets persistence-plist, saying where the registration went', () => {
      const f = run('/Applications/Evil.app/Contents/MacOS/Evil').queue.find(q => q.procId === '902:1')!.findings.find(x => x.ruleId === 'persistence-plist')!;
      expect(f.explanation).toMatch(/attributed to Evil/);
      expect(f.explanation).not.toMatch(/No registration event/);
    });
  });

  describe('launch dirs and plists', () => {
    const writer = (...ops: ReturnType<typeof op>[]) => {
      const p = proc('100:1', [apple('/bin/cp', ['cp'])]);
      p.fileOps.push(...ops);
      return allFindings(analyze(capture([p]))).find(f => f.ruleId === 'persistence-plist');
    };
    test('only .plist files count; a temp file renamed over a plist counts through the rename', () => {
      expect(writer(op('create', '/Users/u/Library/LaunchAgents/.DS_Store'))).toBeUndefined();
      expect(writer(op('create', '/Users/u/Library/LaunchAgents/x.plist.tmp'))).toBeUndefined();
      expect(writer(op('create', '/Users/u/Library/LaunchAgents/x.plist.tmp'), op('rename', '/Users/u/Library/LaunchAgents/x.plist.tmp', 3, '/Users/u/Library/LaunchAgents/x.plist'))?.evidence)
        .toMatch(/x\.plist$/);
    });
    test('explanations say RunAtLoad/KeepAlive, and /Library/LaunchAgents is every user', () => {
      const f = analyze(capture([], [persistenceItem({ itemType: 3, plistPath: '/Library/LaunchAgents/x.plist', executablePath: '/Applications/X.app/Contents/MacOS/X' })])).queue[0]!.findings[0]!;
      expect(f.explanation).toMatch(/every user/);
      expect(f.explanation).toMatch(/RunAtLoad\/KeepAlive/);
    });
  });

  describe('persistence wording', () => {
    const ev = (exe: string, images: ReturnType<typeof img>[] = []) =>
      analyze(capture(images.map((i, n) => proc(`${600 + n}:1`, [i])), [persistenceItem({ itemType: 3, executablePath: exe })])).queue
        .flatMap(q => q.findings).find(f => f.ruleId === 'persistence-item')!.evidence;
    test('fallthrough names a system or package-manager location', () =>
      expect(ev('/opt/homebrew/bin/thing')).toMatch(/med: the program is in a system, \/Applications or package-manager location/));
    test('an app bundle in home seen signed without a team says so', () => {
      const exe = '/Users/u/Applications/T.app/Contents/MacOS/T';
      expect(ev(exe, [img({ path: exe, signingId: 'com.x.t', teamId: null })])).toMatch(/med: an app bundle in a home folder; it ran signed without a team ID/);
      expect(ev(exe)).toMatch(/signature was not seen in this capture/);
    });
  });

  test('payload-decode ignores openssl digest commands, where -d is debug', () => {
    for (const sub of ['dgst', 'sha1', 'sha256', 'sha512', 'md5'])
      expect(ruleIds('/usr/bin/openssl', ['openssl', sub, '-d', 'f']), sub).not.toContain('payload-decode');
  });

  test('osascript -l is read from osascript\'s own options only', () => {
    const f = findingsOf('/usr/bin/osascript', ['osascript', '/tmp/x.scpt', '-l', 'JavaScript']).find(x => x.ruleId === 'osascript-script')!;
    expect(f.mitre).toEqual(['T1059.002']);
  });

  test('fake-prompt and osascript-script wording', () => {
    const fp = RULES.find(r => r.id === 'fake-prompt')!;
    expect(fp.explanation).toMatch(/AppleScript/);
    expect(fp.explanation).toMatch(/JavaScript/);
    const os = RULES.find(r => r.id === 'osascript-script')!;
    expect(os.explanation).toMatch(/volume/);
    expect(os.explanation).toMatch(/translocated/);
  });

  describe('archive-staging', () => {
    const sev = (args: string[], cwd: string) =>
      findingsOf(`/usr/bin/${args[0]}`, args, { cwd }).find(f => f.ruleId === 'archive-staging')!.severity;
    test('zip -X takes no value', () => expect(sev(['zip', '-X', '/tmp/out.zip', 'a'], '/Users/u')).toBe('high'));
    test('a build dir under /var/folders/…/T does not make relative args high', () =>
      expect(sev(['zip', '-r', 'out.zip', 'pkg'], '/private/var/folders/ab/cd/T/go-build123/b001')).toBe('med'));
    test('an ordinary /tmp working dir still does', () => expect(sev(['zip', '-r', 'out.zip', 'loot'], '/tmp/w')).toBe('high'));
  });

  test('go test binaries in /var/folders/…/T/go-build are not high', () => {
    const a = analyze(capture([proc('100:1', [img({ path: '/private/var/folders/ab/cd/T/go-build123/b001/pkg.test', signingId: 'pkg.test', csFlags: 0x2 })])]));
    expect(a.queue).toHaveLength(0);
    expect(a.contextOnly.get('100:1')?.find(f => f.ruleId === 'odd-location-exec')?.severity).toBe('low');
  });

  describe('recon window and burst flag', () => {
    const at = (ms: number) => new Date(Date.UTC(2026, 10, 12) + ms).toISOString();
    const parent = proc('1:1', [apple('/bin/zsh', ['zsh'])]);
    const tool = (n: number, name: string, ms: number) =>
      proc(`${300 + n}:1`, [apple(`/usr/bin/${name}`, [name], { time: at(ms), seq: 10 + n })], { originalParent: '1:1', originalPpid: 1 });
    test('the 60 s window is inclusive', () => {
      expect(analyze(capture([parent, tool(0, 'whoami', 0), tool(1, 'sw_vers', 30_000), tool(2, 'hostname', 60_000)])).queue).toHaveLength(3);
      expect(analyze(capture([parent, tool(0, 'whoami', 0), tool(1, 'sw_vers', 30_000), tool(2, 'hostname', 60_001)])).queue).toHaveLength(0);
    });
    test('a row queued for its own finding, or for a chain, is not a burst', () => {
      const curl = proc('400:1', [apple('/usr/bin/curl', ['curl', '-o', '/tmp/x', 'https://e.com/x'], { seq: 2 })], { originalParent: '1:1' });
      const who = proc('401:1', [apple('/usr/bin/whoami', ['whoami'], { seq: 3 })], { originalParent: '400:1' });
      const a = analyze(capture([parent, curl, who]));
      expect(a.queue.map(q => [q.procId, q.reconBurst])).toEqual(expect.arrayContaining([['400:1', false], ['401:1', false]]));
      expect(a.queue.find(q => q.procId === '401:1')!.inFlaggedChain).toBe(true);
    });
  });

  describe('attachment edge cases', () => {
    const cat = proc('902:1', [apple('/bin/cat', ['cat'])]);
    const owner = (inst: ReturnType<typeof proc>) => {
      const a = analyze(capture([inst, cat], [persistenceItem({ itemType: 3, instigator: inst.id, creator: '902:1', executablePath: '/Applications/X.app/Contents/MacOS/X' })]));
      return a.queue.find(q => q.findings.some(f => f.ruleId === 'persistence-item'))!.procId;
    };
    test('an Apple platform binary outside /System, /usr/libexec, /usr/sbin is attached to', () =>
      expect(owner(proc('903:1', [apple('/bin/launchctl', ['launchctl', 'load', 'x'])]))).toBe('903:1'));
    test('a non-platform binary under /Library is attached to', () =>
      expect(owner(proc('904:1', [img({ path: '/Library/Application Support/X/helper', signingId: 'x', teamId: 'T' })]))).toBe('904:1'));
  });
});
