import { expect, test } from 'vitest';
import { buildModel } from '../src/model/builder';
import { displayName } from '../src/model/relations';
import { imagePaths, model, procByPid } from './helpers';
import { readLines } from './fixtures';
import { realTest } from './real';

const esLab = () => model('es-lab.jsonl');

realTest('exec chain is one process', () => {
  const m = esLab();
  const p = procByPid(m, 41283);
  expect(p.id).toBe('41283:3563742');
  expect(imagePaths(p)).toEqual(['/bin/zsh', '/usr/bin/nohup', '/bin/sleep']);
  expect(m.tokenIndex.get('41283:3563751')).toBe(p.id);
});
realTest('fork edge recorded', () => {
  const m = esLab();
  expect(procByPid(m, 41282).forkParent).toBe('41281:3563740');
});
realTest('pre-capture process referenced only by token is a ghost', () => {
  const m = esLab();
  const zsh = m.processes.get(m.tokenIndex.get('35213:3556708')!)!;
  expect(zsh.parentToken).toBe('35212:3556705');
  expect(zsh.responsibleToken).toBe('35209:3556698');
});
realTest('file op lands on the merged process (plist on cat)', () => {
  const m = esLab();
  const cat = procByPid(m, 41865);
  expect(imagePaths(cat).at(-1)).toBe('/bin/cat');
  expect(cat.fileOps.some(f => f.path.endsWith('/Library/LaunchAgents/com.test.studyguide.plist'))).toBe(true);
});
realTest('fork child image is inherited, exec image is not', () => {
  const m = esLab();
  const p = procByPid(m, 41283);
  expect(p.images[0]!.inherited).toBe(true);
  expect(p.images[1]!.inherited).toBe(false);
});
realTest('exit sets exitTime', () => {
  const m = esLab();
  expect(procByPid(m, 40490).exitTime).not.toBeNull();   // whoami
});
realTest('process seen only in its own events keeps its path', () => {
  const sh = model('shlayer.json');
  const ps = [...sh.processes.values()].filter(p => p.pid === 35970);
  expect(ps).toHaveLength(1);
  const payload = ps[0]!;
  expect(imagePaths(payload)).toEqual(['/bin/bash', '/private/tmp/FaF74ncqmHBe/8CMt7kQ2jM3']);
  expect(payload.forkParent).toBe(sh.tokenIndex.get('35917:103436'));
  const img = payload.images.find(i => i.path === '/private/tmp/FaF74ncqmHBe/8CMt7kQ2jM3')!;
  expect(img.signingId).toBeNull();
  expect(img.inherited).toBe(false);
});
realTest('stats', () => {
  const m = esLab();
  expect(m.stats.events).toBe(11610);
  expect(m.stats.badLines).toBe(0);
  expect(m.stats.versions).toEqual([11]);
});
realTest('es-lab builds in under 5s', () => {
  const lines = readLines('es-lab.jsonl');
  const t0 = performance.now();
  buildModel(lines);
  expect(performance.now() - t0).toBeLessThan(5000);
});

// ---- synthetic events ----

interface ProcOpts { path?: string; ppid?: number; parent?: string; responsible?: string; start?: string }
function tok(t: string) {
  const [pid, pidversion] = t.split(':').map(Number);
  return { pid, pidversion };
}
function proc(t: string, o: ProcOpts = {}) {
  return {
    audit_token: tok(t),
    ...(o.path ? { executable: { path: o.path } } : {}),
    ...(o.ppid !== undefined ? { ppid: o.ppid } : {}),
    ...(o.parent ? { parent_audit_token: tok(o.parent) } : {}),
    ...(o.responsible ? { responsible_audit_token: tok(o.responsible) } : {}),
    ...(o.start ? { start_time: o.start } : {}),
  };
}
function ev(seq: number, p: ReturnType<typeof proc>, event: Record<string, unknown>): string {
  return JSON.stringify({ global_seq_num: seq, time: `2026-01-01T00:00:${String(seq).padStart(2, '0')}Z`, version: 11, process: p, event });
}
const forkLine = (seq: number, parent: string, child: string) =>
  ev(seq, proc(parent), { fork: { child: proc(child) } });
const exitLine = (seq: number, t: string) => ev(seq, proc(t), { exit: { stat: 0 } });
const execLine = (seq: number, t: string, target: string, path: string) =>
  ev(seq, proc(t), { exec: { target: proc(target, { path }), args: [path] } });

test('pid reuse makes a new process', () => {
  // fork 500:1 → exit 500:1 → fork 500:9 (same pid, new pidversion)
  const m2 = buildModel([forkLine(1,'100:1','500:1'), exitLine(2,'500:1'), forkLine(3,'100:1','500:9')]);
  expect([...m2.processes.values()].filter(p => p.pid === 500)).toHaveLength(2);
});
test('events applied in global_seq_num order, not file order', () => {
  const m3 = buildModel([execLine(2,'500:1','500:2','/bin/ls'), forkLine(1,'100:1','500:1')]);
  expect(imagePaths(m3.processes.get('500:1')!)).toEqual([null, '/bin/ls']);
});
test('known token with a new path gets a non-inherited image (missing exec)', () => {
  const m4 = buildModel([
    ev(1, proc('500:1', { path: '/bin/bash' }), { write: { target: { path: '/tmp/a' } } }),
    ev(2, proc('500:1', { path: '/tmp/payload' }), { write: { target: { path: '/tmp/b' } } }),
    ev(3, proc('500:1'), { write: { target: { path: '/tmp/c' } } }),   // null path: no new image
  ]);
  const p = m4.processes.get('500:1')!;
  expect(imagePaths(p)).toEqual(['/bin/bash', '/tmp/payload']);
  expect(p.images[1]!.inherited).toBe(false);
  expect(p.images[1]!.args).toBeNull();
  expect(p.images[1]!.seq).toBe(2);
  expect(p.fileOps.map(f => f.path)).toEqual(['/tmp/a', '/tmp/b', '/tmp/c']);
});
test('later null parent info does not erase known values', () => {
  const m5 = buildModel([
    ev(1, proc('500:1', { ppid: 7, parent: '7:1', responsible: '3:1' }), { exit: {} }),
    ev(2, proc('500:1'), { exit: {} }),
  ]);
  const p = m5.processes.get('500:1')!;
  expect([p.ppid, p.parentToken, p.responsibleToken]).toEqual([7, '7:1', '3:1']);
});
test('btm, other events and line stats', () => {
  const m6 = buildModel([
    ev(1, proc('600:1', { path: '/usr/libexec/smd' }),
      { btm_launch_item_add: { item: { item_url: 'file:///Users/u/Library/LaunchAgents/x.plist' }, executable_path: '/bin/sh' } }),
    ev(2, proc('600:1'), { mmap: {} }),
    '',
    'not json',
  ]);
  expect(m6.persistence).toHaveLength(1);
  expect(m6.persistence[0]).toMatchObject({
    id: 'btm:1', kind: 'add', plistPath: '/Users/u/Library/LaunchAgents/x.plist',
    executablePath: '/bin/sh', emitter: '600:1', instigator: null, app: null, itemType: null, creator: null, seq: 1,
  });
  expect(m6.stats).toMatchObject({
    lines: 4, events: 2, badLines: 1, otherEvents: { mmap: 1 }, versions: [11], firstSeq: 1,
  });
});
test('a btm item URL relative to the app is made absolute against the app URL, like the executable path', () => {
  const m = buildModel([
    ev(1, proc('600:1', { path: '/usr/libexec/smd' }), { btm_launch_item_add: {
      item: { item_type: 3, item_url: 'Contents/Library/LaunchAgents/com.evil.helper.plist', app_url: 'file:///Applications/Evil.app/' },
      executable_path: 'Contents/MacOS/helper',
    } }),
    ev(2, proc('600:1'), { btm_launch_item_add: { item: { item_type: 3, item_url: 'relative/x.plist' } } }),   // no app: stays as given
    ev(3, proc('600:1'), { btm_launch_item_add: { item: { item_type: 1, item_url: 'file:///Applications/Evil.app/', app_url: 'file:///Applications/Evil.app/' } } }),
  ]);
  const [a, b, c] = m.persistence;
  expect(a!.plistPath).toBe('/Applications/Evil.app/Contents/Library/LaunchAgents/com.evil.helper.plist');
  expect(a!.appPath).toBe('/Applications/Evil.app/');
  expect(b!.plistPath).toBe('relative/x.plist');
  expect(c!.plistPath).toBe('/Applications/Evil.app/');
});
test('a relative btm item URL with ./ and .. segments resolves the way the executable path does', () => {
  const m = buildModel([ev(1, proc('600:1', { path: '/usr/libexec/smd' }), { btm_launch_item_add: {
    item: { item_type: 3, item_url: 'Contents/../Library/./LaunchAgents/x.plist', app_url: 'file:///Applications/Evil.app/' },
  } })]);
  expect(m.persistence[0]!.plistPath).toBe('/Applications/Evil.app/Library/LaunchAgents/x.plist');
});
test('events named after Object.prototype keys are counted as other', () => {
  const lines = ['constructor', 'toString', '__proto__', 'constructor'].map((k, i) =>
    `{"global_seq_num":${i + 1},"time":"t","version":11,"process":{"audit_token":{"pid":1,"pidversion":1}},"event":{"${k}":{}}}`);
  const m9 = buildModel(lines);
  expect(m9.stats.events).toBe(4);
  expect(m9.stats.otherEvents).toEqual({ constructor: 2, toString: 1, ['__proto__']: 1 });
  expect(Object.getPrototypeOf(m9.stats.otherEvents)).toBe(Object.prototype);
});
realTest('es-lab studyguide btm item: agent type, emitted by backgroundtaskmanagementd, instigated by smd', () => {
  const m = esLab();
  const item = m.persistence.find(p => p.plistPath?.endsWith('/Library/LaunchAgents/com.test.studyguide.plist'))!;
  expect(item.itemType).toBe(3);
  expect(displayName(m, item.emitter)).toBe('backgroundtaskmanagementd');
  expect(item.instigator).not.toBeNull();
  const smd = m.processes.get(item.instigator!)!;
  expect(smd.ghost).toBe(false);
  expect(smd.pid).toBe(558);
  expect(displayName(m, smd.id)).toBe('smd');
  expect(item.app).toBeNull();
});
test('login item registered by an app resolves app and instigator through their tokens', () => {
  const BTM = '/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd';
  const EVIL = '/Applications/Evil.app/Contents/MacOS/Evil';
  const m10 = buildModel([
    forkLine(1, '1:1', '900:1'),
    execLine(2, '900:1', '900:2', EVIL),
    ev(3, proc('750:1', { path: BTM }), { btm_launch_item_add: {
      item: { item_type: 2, item_url: 'file:///Applications/Evil.app/', app_url: 'file:///Applications/Evil.app/' },
      executable_path: EVIL,
      instigator: proc('558:1', { path: '/usr/libexec/smd' }), instigator_token: tok('558:1'),
      app: null, app_token: tok('900:2'),    // exec'd image token, no process object
    } }),
    ev(4, proc('750:1'), { btm_launch_item_add: {
      item: { item_type: 2 }, instigator: null, instigator_token: tok('777:5'), app: null, app_token: null,
    } }),
    ev(5, proc('300:1', { path: '/bin/sleep', ppid: 777 }), { exit: {} }),
    ev(6, proc('750:1'), { btm_launch_item_add: { item: { item_type: 4 }, instigator_token: tok('750:1') } }),
  ]);
  expect(m10.stats.badLines).toBe(0);
  const [a, b] = m10.persistence;
  expect(a).toMatchObject({ itemType: 2, emitter: '750:1', app: '900:1', creator: null });
  expect(displayName(m10, a!.instigator!)).toBe('smd');
  expect(m10.processes.get(a!.instigator!)!.ghost).toBe(false);
  // Token only and never captured: a ghost, shared with a pid reference to the same pid.
  expect(b).toMatchObject({ itemType: 2, app: null, instigator: '777:5' });
  expect(m10.processes.get('777:5')!.ghost).toBe(true);
  expect(m10.processes.get('300:1')!.currentParent).toBe('777:5');
  expect([...m10.processes.values()].filter(p => p.pid === 777)).toHaveLength(1);
  // An instigator that is the emitting process resolves to it, not to null.
  expect(m10.persistence[2]).toMatchObject({ itemType: 4, emitter: '750:1', instigator: '750:1' });
});
test('new token with same pid and start_time as a live process is a missed exec', () => {
  const T = '2026-01-01T00:00:00.5Z';
  const m7 = buildModel([
    ev(1, proc('100:1'), { fork: { child: proc('500:1', { path: '/bin/bash', start: T }) } }),
    ev(2, proc('500:2', { path: '/tmp/payload', start: T }), { write: { target: { path: '/tmp/x' } } }),
  ]);
  const ps = [...m7.processes.values()].filter(p => p.pid === 500);
  expect(ps).toHaveLength(1);
  const p = ps[0]!;
  expect(imagePaths(p)).toEqual(['/bin/bash', '/tmp/payload']);
  expect(p.images[1]).toMatchObject({ inherited: false, args: null, env: null, seq: 2, time: '2026-01-01T00:00:02Z' });
  expect(m7.tokenIndex.get('500:2')).toBe(p.id);
  expect(p.forkParent).toBe('100:1');
  expect(p.fileOps.map(f => f.path)).toEqual(['/tmp/x']);
});
test('new token with same pid but different start_time is a new process', () => {
  const m8 = buildModel([
    ev(1, proc('100:1'), { fork: { child: proc('500:1', { path: '/bin/bash', start: '2026-01-01T00:00:00.5Z' }) } }),
    ev(2, proc('500:2', { path: '/tmp/payload', start: '2026-01-01T00:00:01.5Z' }), { write: { target: { path: '/tmp/x' } } }),
  ]);
  expect([...m8.processes.values()].filter(p => p.pid === 500)).toHaveLength(2);
});
