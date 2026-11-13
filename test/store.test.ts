import 'fake-indexeddb/auto';
import { beforeEach, expect, test } from 'vitest';
import type { Image } from '../src/model/types';
import { latestImage } from '../src/model/util';
import { applyRoutine, isRiskyRoutine, programKey } from '../src/session/routine';
import { openStore, type CaptureRec, type Store, type Verdict } from '../src/session/store';
import { procByPid, queued } from './helpers';

let store: Store;
let n = 0;
beforeEach(async () => { store = await openStore(`test-store-${n++}`); });

const rec = (sessionId: string, fingerprint: string, size: number): CaptureRec =>
  ({ sessionId, fingerprint, fileName: 'x.jsonl', size, events: 1, processes: 1, flagged: 0, added: 't' });
const verdict = (sessionId: string, fingerprint: string, procKey: string, status: Verdict['status']): Verdict => ({
  sessionId, fingerprint, procKey, status, note: '', updated: 't',
  snapshot: { name: 'x', path: null, args: null, ruleIds: [], severity: null, startTime: null },
});
const img = (path: string | null, over: Partial<Image> = {}): Image => ({
  token: '1:1', path, signingId: null, teamId: null, isPlatform: false, csFlags: 0,
  args: null, cwd: null, env: null, stdinIsPipe: null, script: null, time: null, seq: 0, inherited: false, ...over,
});

test('same fingerprint dedupes', async () => {
  const s = await store.createSession('lab');
  expect(await store.upsertCapture(rec(s.id, 'fp1', 100))).toBe('added');
  expect(await store.upsertCapture(rec(s.id, 'fp1', 200))).toBe('updated');
  const caps = await store.listCaptures(s.id);
  expect(caps).toHaveLength(1); expect(caps[0]!.size).toBe(200);
});
test('verdicts scoped to session and fingerprint', async () => {
  const a = await store.createSession('a'); const b = await store.createSession('b');
  await store.setVerdict(verdict(a.id, 'fp', 'p1', 'confirmed'));
  await store.setVerdict(verdict(a.id, 'fp2', 'p1', 'benign'));
  expect(await store.listVerdicts(b.id)).toHaveLength(0);
  expect(await store.listVerdicts(a.id)).toHaveLength(2);
  expect((await store.listVerdicts(a.id, 'fp2')).map(v => v.status)).toEqual(['benign']);
  await store.setVerdict(verdict(a.id, 'fp', 'p1', 'benign'));   // same key replaces
  expect(await store.listVerdicts(a.id, 'fp')).toHaveLength(1);
});
test('rename and delete cascade', async () => {
  const a = await store.createSession('a'); const b = await store.createSession('b');
  await store.renameSession(a.id, 'renamed');
  expect((await store.listSessions()).find(s => s.id === a.id)!.name).toBe('renamed');
  for (const s of [a, b]) {
    await store.upsertCapture(rec(s.id, 'fp', 1));
    await store.setVerdict(verdict(s.id, 'fp', 'p', 'confirmed'));
    await store.addRoutine({ sessionId: s.id, programKey: 'k', label: 'l', added: 't' });
  }
  await store.deleteSession(a.id);
  expect((await store.listSessions()).map(s => s.id)).toEqual([b.id]);
  expect(await store.listCaptures(a.id)).toHaveLength(0);
  expect(await store.listVerdicts(a.id)).toHaveLength(0);
  expect(await store.listRoutine(a.id)).toHaveLength(0);
  expect(await store.listCaptures(b.id)).toHaveLength(1);
  expect(await store.listVerdicts(b.id)).toHaveLength(1);
  expect(await store.listRoutine(b.id)).toHaveLength(1);
});
test('routine add/list/remove', async () => {
  const s = await store.createSession('a');
  await store.addRoutine({ sessionId: s.id, programKey: 'k', label: 'l', added: 't' });
  expect(await store.listRoutine(s.id)).toHaveLength(1);
  await store.removeRoutine(s.id, 'k');
  expect(await store.listRoutine(s.id)).toHaveLength(0);
});
test('routine hides matching programs and counts them', () => {
  const { m, a } = queued('es-lab.jsonl');
  const curl = procByPid(m, 39838);
  const r = applyRoutine(a, m, new Set([programKey(latestImage(curl)!)]));
  expect(r.queue.some(q => q.procId === curl.id)).toBe(false);
  expect(r.hiddenCount).toBeGreaterThanOrEqual(1);
  expect(r.queue.length + r.hiddenCount).toBe(a.queue.length);
});
test('routine never hides persistence-only items', () => {
  const { m, a } = queued('es-lab.jsonl');
  const keys = new Set([...m.processes.values()].flatMap(p => p.images.map(programKey)));
  const r = applyRoutine(a, m, keys);
  expect(r.queue.filter(q => q.kind === 'persistence')).toHaveLength(a.queue.filter(q => q.kind === 'persistence').length);
});
test('programKey format', () => {
  expect(programKey(img('/bin/ls'))).toBe('-|-|/bin/ls');
  expect(programKey(img('/x', { signingId: 'com.a', teamId: 'T1' }))).toBe('com.a|T1|/x');
});
test('isRiskyRoutine warns for shells', () => {
  expect(isRiskyRoutine(img('/bin/bash'))).toBe(true);
  expect(isRiskyRoutine(img('/usr/bin/osascript'))).toBe(true);
  expect(isRiskyRoutine(img(null))).toBe(false);
  expect(isRiskyRoutine(img('/Applications/OrbStack.app/Contents/MacOS/xbin/docker-tools'))).toBe(false);
});

test('touchSession bumps updated and nothing else', async () => {
  const s = await store.createSession('lab');
  await new Promise(r => setTimeout(r, 5));
  await store.touchSession(s.id);
  const [after] = await store.listSessions();
  expect(after!.updated > s.updated).toBe(true);
  expect(after!.name).toBe('lab');
  expect(after!.created).toBe(s.created);
  await store.touchSession('missing');   // unknown id is a no-op
  expect(await store.listSessions()).toHaveLength(1);
});
