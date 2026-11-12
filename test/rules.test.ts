import { describe, expect, test } from 'vitest';
import { basename } from '../src/model/util';
import { analyze } from '../src/rules/engine';
import { RULES } from '../src/rules/rules';
import type { CaptureModel, Image, Process } from '../src/model/types';
import type { FixtureName } from './fixtures';
import { count, item, model, queued, rules, sev } from './helpers';

describe('es-lab must flag', () => {
  test('fake prompt high', () => expect(sev('es-lab.jsonl', x => x.p?.pid === 40753)).toBe('high'));
  test('launchctl bootstrap high', () => expect(sev('es-lab.jsonl', x => x.p?.pid === 42279)).toBe('high'));
  test('studyguide persistence on cat, high', () => {
    const it = item('es-lab.jsonl', x => x.p?.pid === 41865)!;
    expect(it.findings.map(f => f.ruleId)).toContain('persistence-item');
    expect(it.severity).toBe('high');
  });
  test('bash from pipe med', () => expect(rules('es-lab.jsonl', x => x.p?.pid === 40489)).toContain('shell-from-pipe'));
  test('whoami queued in flagged chain', () => expect(item('es-lab.jsonl', x => x.p?.pid === 40490)!.inFlaggedChain).toBe(true));
  test('curl download', () => expect(rules('es-lab.jsonl', x => x.p?.pid === 39838)).toContain('download'));
  test('ditto staging', () => expect(rules('es-lab.jsonl', x => x.p?.pid === 41080)).toContain('archive-staging'));
  test('sleep 90 orphaned', () => expect(rules('es-lab.jsonl', x => x.p?.pid === 41282)).toContain('orphaned'));
  test('GoogleUpdater item med, standalone', () => {
    const it = item('es-lab.jsonl', x => x.item.kind === 'persistence')!;
    expect(it.severity).toBe('med');
  });
});

test('es-lab must not queue routine noise', () => {
  const names = queued('es-lab.jsonl').items.map(x => basename(x.paths.at(-1) ?? null));
  for (const n of ['ps', 'git', 'docker-tools', 'mdworker_shared']) expect(names).not.toContain(n);
});

test('es-lab queue stays small', () => expect(queued('es-lab.jsonl').items.length).toBeLessThanOrEqual(14));

test('es-lab team-signed Chrome clone under /var/folders is context-only', () => {
  const q = queued('es-lab.jsonl');
  expect(q.items.some(x => x.p?.pid === 8573)).toBe(false);
  const chrome = [...q.m.processes.values()].find(p => p.pid === 8573)!;
  expect(q.a.contextOnly.get(chrome.id)?.map(f => f.ruleId)).toContain('odd-location-exec');
});

describe('atomic stealer', () => {
  test('two fake prompts', () => expect(count('atomic_stealer.json', x => basename(x.paths.at(-1) ?? null) === 'osascript' && x.item.findings.some(f => f.ruleId === 'fake-prompt'))).toBe(2));
  test('dscl authonly high', () => expect(sev('atomic_stealer.json', x => x.args.includes('-authonly'))).toBe('high'));
  test('translocated ad-hoc app', () => expect(rules('atomic_stealer.json', x => x.paths.some(p => p?.includes('AppTranslocation')))).toContain('odd-location-exec')); // severity high: ad-hoc + odd location
  test('recon burst queued', () => expect(count('atomic_stealer.json', x => x.item.findings.every(f => f.ruleId === 'recon'))).toBeGreaterThanOrEqual(3));
});

describe('recon gating', () => {
  const reconOnly = RULES.filter(r => r.id === 'recon');
  test('a burst of distinct tools under one parent queues without a flagged chain', () => {
    const a = analyze(model('atomic_stealer.json'), reconOnly);
    expect(a.queue.length).toBeGreaterThanOrEqual(3);
    expect(a.queue.every(q => !q.inFlaggedChain)).toBe(true);
  });
  test('background ps runs stay context-only', () => {
    const a = analyze(model('es-lab.jsonl'), reconOnly);
    expect(a.queue).toHaveLength(0);
    expect(a.contextOnly.size).toBeGreaterThanOrEqual(28);
  });
});

describe('rustbucket', () => {
  test('applet shell curl', () => expect(rules('rustbucket.json', x => x.args.includes('curl -o /users/shared/1.zip'))).toContain('shell-under-app'));
  test('Internal PDF Viewer', () => expect(sev('rustbucket.json', x => x.paths.some(p => p?.startsWith('/Users/Shared/Internal PDF Viewer.app')))).toBe('high'));
});

describe('shlayer', () => {
  test('payload in /tmp high', () => expect(sev('shlayer.json', x => x.paths.includes('/private/tmp/FaF74ncqmHBe/8CMt7kQ2jM3'))).toBe('high'));
  test('quarantine strip', () => expect(count('shlayer.json', x => x.item.findings.some(f => f.ruleId === 'quarantine-strip'))).toBeGreaterThanOrEqual(1));
  test('curl downloads', () => expect(count('shlayer.json', x => x.item.findings.some(f => f.ruleId === 'download'))).toBeGreaterThanOrEqual(1));
  test('hidden Install.command entry script flagged', () => expect(rules('shlayer.json', x => x.p?.pid === 35901)).toContain('odd-location-exec'));
  test('xattr, openssl and payload sit in the flagged chain', () => {
    for (const pid of [35967, 35968, 35970]) expect(item('shlayer.json', x => x.p?.pid === pid)!.inFlaggedChain).toBe(true);
  });
});

function img(o: Partial<Image>): Image {
  return {
    token: '100:1', path: '/bin/x', signingId: 'com.example.x', teamId: null, isPlatform: false, csFlags: 0,
    args: null, cwd: null, env: null, stdinIsPipe: null, script: null,
    time: '2026-11-12T00:00:00.000Z', seq: 1, inherited: false, ...o,
  };
}
const apple = (path: string, args: string[]): Image =>
  img({ path, args, signingId: `com.apple.${path.split('/').pop()}`, isPlatform: true });

/** A one-process capture holding the given images. */
function synth(images: Image[]): CaptureModel {
  const p: Process = {
    id: '100:1', pid: 100, ghost: false, images, forkParent: null,
    originalPpid: null, ppid: null, parentToken: null, responsibleToken: null,
    originalParent: null, currentParent: null, responsible: null,
    startTime: null, exitTime: null, firstSeq: 1, fileOps: [],
  };
  return {
    processes: new Map([[p.id, p]]), tokenIndex: new Map([[p.id, p.id]]), persistence: [],
    stats: { lines: 0, events: 0, badLines: 0, otherEvents: {}, versions: [], firstSeq: null, firstTime: null, lastTime: null },
  };
}
const analyzed = (i: Image) => analyze(synth([i]));
const queuedRules = (i: Image) => analyzed(i).queue[0]?.findings.map(f => f.ruleId) ?? [];

describe('odd-location strong/weak split', () => {
  test('ad-hoc tool under ~/.cargo is context-only outside a chain', () => {
    const a = analyzed(img({ path: '/Users/u/.cargo/bin/yr', signingId: 'yr', csFlags: 0x2 }));
    expect(a.queue).toHaveLength(0);
    expect(a.contextOnly.get('100:1')?.map(f => f.ruleId)).toContain('odd-location-exec');
  });
  test('team-signed binary under ~/.local is not queued', () =>
    expect(analyzed(img({ path: '/Users/u/.local/share/x', teamId: 'ABCDE12345' })).queue).toHaveLength(0));
  test('unsigned binary in a nested hidden dir is high', () => {
    const a = analyzed(img({ path: '/Users/u/Desktop/.hidden/x', signingId: null }));
    expect(a.queue[0]?.severity).toBe('high');
    expect(a.queue[0]?.findings.find(f => f.ruleId === 'odd-location-exec')?.severity).toBe('high');
  });
  test('unsigned binary under a home dot-dir is med', () => {
    const a = analyzed(img({ path: '/Users/u/.foo/bin/x', signingId: null }));
    expect(a.queue[0]?.severity).toBe('med');
    expect(a.queue[0]?.findings.find(f => f.ruleId === 'odd-location-exec')?.severity).toBe('med');
  });
  test('script in a strong location is med and names the script', () => {
    const bash = apple('/bin/bash', ['/bin/bash', '/Users/u/Desktop/.hidden/run.command']);
    const f = analyzed({ ...bash, script: '/Users/u/Desktop/.hidden/run.command' }).queue[0]?.findings[0];
    expect(f?.ruleId).toBe('odd-location-exec');
    expect(f?.severity).toBe('med');
    expect(f?.evidence).toContain('/Users/u/Desktop/.hidden/run.command');
  });
});

describe('project tooling dirs are weak', () => {
  const script = (path: string) =>
    ({ ...apple('/bin/sh', ['/bin/sh', path]), script: path });
  test('git hook script is not queued outside a chain', () => {
    const a = analyzed(script('/Users/u/proj/.git/hooks/pre-commit'));
    expect(a.queue).toHaveLength(0);
    expect(a.contextOnly.get('100:1')?.map(f => f.ruleId)).toContain('odd-location-exec');
  });
  test('virtualenv pip script is not queued', () =>
    expect(analyzed(script('/Users/u/proj/.venv/bin/pip')).queue).toHaveLength(0));
  test('a .git under /tmp stays strong', () => {
    const a = analyzed(script('/tmp/x/.git/hooks/y'));
    expect(a.queue[0]?.severity).toBe('med');
    expect(a.queue[0]?.findings.map(f => f.ruleId)).toContain('odd-location-exec');
  });
});

describe('short-flag clusters', () => {
  test('xattr -cr strips quarantine', () => expect(queuedRules(apple('/usr/bin/xattr', ['xattr', '-cr', 'X.app']))).toContain('quarantine-strip'));
  test('xattr -rd com.apple.quarantine strips quarantine', () =>
    expect(queuedRules(apple('/usr/bin/xattr', ['xattr', '-rd', 'com.apple.quarantine', 'X']))).toContain('quarantine-strip'));
  test('xattr -l does not', () => expect(queuedRules(apple('/usr/bin/xattr', ['xattr', '-l', 'f']))).not.toContain('quarantine-strip'));
  test('ditto -ck archives', () => expect(queuedRules(apple('/usr/bin/ditto', ['ditto', '-ck', 'a', 'b']))).toContain('archive-staging'));
  test('curl -sLo downloads', () => expect(queuedRules(apple('/usr/bin/curl', ['curl', '-sLo', 'f', 'https://example.com']))).toContain('download'));
});

describe('download rule needs a file on disk', () => {
  const curl = (...args: string[]) => queuedRules(apple('/usr/bin/curl', ['curl', ...args, 'https://example.com']));
  const wget = (...args: string[]) => queuedRules(apple('/usr/bin/wget', ['wget', ...args, 'https://example.com']));
  test('curl -o /dev/null does not fire', () => {
    expect(curl('-o', '/dev/null')).not.toContain('download');
    expect(curl('-sLo', '/dev/null')).not.toContain('download');
    expect(curl('--output', '/dev/null')).not.toContain('download');
    expect(curl('--output=/dev/null')).not.toContain('download');
  });
  test('curl -o - (stdout) does not fire', () => {
    expect(curl('-s', '-o', '-')).not.toContain('download');
    expect(curl('--output', '-')).not.toContain('download');
  });
  test('wget -O - and -O /dev/null do not fire', () => {
    expect(wget('-qO', '-')).not.toContain('download');
    expect(wget('-O', '/dev/null')).not.toContain('download');
  });
  test('a real output file still fires', () => {
    expect(curl('-o', '/tmp/payload')).toContain('download');
    expect(curl('--output=/tmp/payload')).toContain('download');
    expect(curl('-o', '/dev/null', '-o', 'out.bin')).toContain('download');
    expect(wget('-qO', '/tmp/payload')).toContain('download');
  });
  test('curl -O writes a file named after the URL, even next to -o /dev/null', () => {
    expect(curl('-O')).toContain('download');
    expect(curl('-o', '/dev/null', '-O')).toContain('download');
  });
  test('the create-FileOp path is unchanged: no output flag, but the process created a file', () => {
    const m = synth([apple('/usr/bin/curl', ['curl', 'https://example.com'])]);
    expect(analyze(m).queue).toHaveLength(0);
    m.processes.get('100:1')!.fileOps.push({ kind: 'create', path: '/tmp/x', time: 't', seq: 2 });
    const f = analyze(m).queue[0]?.findings.find(x => x.ruleId === 'download');
    expect(f?.evidence).toContain('created /tmp/x');
  });
});

test('every finding explains itself', () => {
  for (const f of ['es-lab.jsonl', 'atomic_stealer.json', 'rustbucket.json', 'shlayer.json'] as const)
    for (const x of queued(f).items) for (const fd of x.item.findings) {
      expect(fd.explanation.length).toBeGreaterThan(20); expect(fd.mitre.length).toBeGreaterThan(0);
    }
});

test('queue size per fixture is recorded', () => {
  const sizes: Partial<Record<FixtureName, number>> = {};
  for (const f of ['es-lab.jsonl', 'atomic_stealer.json', 'rustbucket.json', 'shlayer.json'] as const)
    sizes[f] = queued(f).items.length;
  console.log('queue sizes', sizes);
  expect(sizes['es-lab.jsonl']).toBeLessThanOrEqual(14);
});
