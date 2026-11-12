import { expect, test } from 'vitest';
import { buildModel } from '../src/model/builder';
import { imagePaths, model, procByPid } from './helpers';
import { readLines } from './fixtures';

const m = model('es-lab.jsonl');

test('exec chain is one process', () => {
  const p = procByPid(m, 41283);
  expect(p.id).toBe('41283:3563742');
  expect(imagePaths(p)).toEqual(['/bin/zsh', '/usr/bin/nohup', '/bin/sleep']);
  expect(m.tokenIndex.get('41283:3563751')).toBe(p.id);
});
test('fork edge recorded', () => {
  expect(procByPid(m, 41282).forkParent).toBe('41281:3563740');
});
test('pre-capture process referenced only by token is a ghost', () => {
  const zsh = m.processes.get(m.tokenIndex.get('35213:3556708')!)!;
  expect(zsh.parentToken).toBe('35212:3556705');
  expect(zsh.responsibleToken).toBe('35209:3556698');
});
test('file op lands on the merged process (plist on cat)', () => {
  const cat = procByPid(m, 41865);
  expect(imagePaths(cat).at(-1)).toBe('/bin/cat');
  expect(cat.fileOps.map(f => f.path)).toContain('/Users/alice/Library/LaunchAgents/com.test.studyguide.plist');
});
test('fork child image is inherited, exec image is not', () => {
  const p = procByPid(m, 41283);
  expect(p.images[0]!.inherited).toBe(true);
  expect(p.images[1]!.inherited).toBe(false);
});
test('exit sets exitTime', () => {
  expect(procByPid(m, 40490).exitTime).not.toBeNull();   // whoami
});
test('process seen only in its own events keeps its path', () => {
  const sh = model('shlayer.json');
  const payload = [...sh.processes.values()].find(p => imagePaths(p).includes('/private/tmp/FaF74ncqmHBe/8CMt7kQ2jM3'));
  expect(payload).toBeDefined();
  expect(payload!.images[0]!.signingId).toBeNull();
});
test('stats', () => {
  expect(m.stats.events).toBe(11610);
  expect(m.stats.badLines).toBe(0);
  expect(m.stats.versions).toEqual([11]);
});
test('es-lab builds in under 5s', () => {
  const lines = readLines('es-lab.jsonl');
  const t0 = performance.now();
  buildModel(lines);
  expect(performance.now() - t0).toBeLessThan(5000);
});

// ---- synthetic events ----

interface ProcOpts { path?: string; ppid?: number; parent?: string; responsible?: string }
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
    executablePath: '/bin/sh', instigator: '600:1', creator: null, seq: 1,
  });
  expect(m6.stats).toMatchObject({
    lines: 4, events: 2, badLines: 1, otherEvents: { mmap: 1 }, versions: [11], firstSeq: 1,
  });
});
