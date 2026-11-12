import 'fake-indexeddb/auto';
import { beforeEach, expect, test } from 'vitest';
import type { LoadedCapture } from '../src/ingest/load';
import { exportSession, importSession } from '../src/session/export';
import { openStore, type Session, type Store } from '../src/session/store';
import { procByPid, queued } from './helpers';

let store: Store;
let s: Session;
let loaded: Map<string, LoadedCapture>;
let n = 0;

beforeEach(async () => {
  store = await openStore(`test-export-${n++}`);
  s = await store.createSession('lab');
  const { m, a } = queued('es-lab.jsonl');
  loaded = new Map([['fp', { fingerprint: 'fp', fileName: 'es-lab.jsonl', size: 1, model: m, analysis: a }]]);
  const p = procByPid(m, 40753);
  await store.upsertCapture({ sessionId: s.id, fingerprint: 'fp', fileName: 'es-lab.jsonl', size: 1,
    events: 1, processes: 1, flagged: 1, added: 't' });
  await store.setVerdict({ sessionId: s.id, fingerprint: 'fp', procKey: p.id, status: 'confirmed', note: 'n',
    updated: 't', snapshot: { name: 'osascript', path: '/usr/bin/osascript', args: null, ruleIds: ['fake-prompt'],
      severity: 'high', startTime: p.startTime } });
  await store.setVerdict({ sessionId: s.id, fingerprint: 'fp', procKey: procByPid(m, 39838).id, status: 'benign',
    note: '', updated: 't', snapshot: { name: 'curl', path: null, args: null, ruleIds: [], severity: null, startTime: null } });
  await store.addRoutine({ sessionId: s.id, programKey: 'k', label: 'l', added: 't' });
});

test('export excludes env by default', async () => {
  const out = await exportSession(store, s.id, { includeEnv: false }, loaded);
  expect(JSON.stringify(out)).not.toContain('"env"');
  const withEnv = await exportSession(store, s.id, { includeEnv: true }, loaded);
  expect(Object.values(withEnv.details)[0]!.images.some(i => Array.isArray(i.env))).toBe(true);
});
test('details cover confirmed processes with a loaded capture only', async () => {
  const out = await exportSession(store, s.id, { includeEnv: false }, loaded);
  const d = Object.values(out.details);
  expect(d).toHaveLength(1);
  expect(d[0]!.name).toBe('osascript');
  expect(d[0]!.ancestry.length).toBeGreaterThan(1);
  expect(d[0]!.images.length).toBeGreaterThan(0);
  expect((await exportSession(store, s.id, { includeEnv: false })).details).toEqual({});
});
test('export is deterministic and JSON-serializable', async () => {
  const a = JSON.stringify(await exportSession(store, s.id, { includeEnv: true }, loaded));
  const b = JSON.stringify(await exportSession(store, s.id, { includeEnv: true }, loaded));
  expect(a).toBe(b);
  expect(JSON.parse(a).format).toBe('eslogger-viewer-session');
});
test('import round-trips as a new session', async () => {
  const out = await exportSession(store, s.id, { includeEnv: false });
  const s2 = await importSession(store, out);
  expect(s2.id).not.toBe(s.id); expect(s2.name).toBe('lab (imported)');
  expect(await store.listVerdicts(s2.id)).toHaveLength((await store.listVerdicts(s.id)).length);
  expect(await store.listCaptures(s2.id)).toHaveLength(1);
  expect(await store.listRoutine(s2.id)).toHaveLength(1);
  expect((await store.listVerdicts(s.id)).every(v => v.sessionId === s.id)).toBe(true);
});
test('import rejects foreign data', async () => {
  await expect(importSession(store, { format: 'nope' } as never)).rejects.toThrow('not an eslogger-viewer session export');
});
test('import rejects an unsupported version with its own message', async () => {
  const out = await exportSession(store, s.id, { includeEnv: false });
  await expect(importSession(store, { ...out, version: 2 } as never))
    .rejects.toThrow('unsupported session export version 2 (this build reads version 1)');
  expect(await store.listSessions()).toHaveLength(1);
});
test('import of a malformed payload leaves no session behind', async () => {
  const out = await exportSession(store, s.id, { includeEnv: false });
  const before = await store.listSessions();
  const badRow = { ...out, verdicts: [...out.verdicts, { ...out.verdicts[0]!, procKey: undefined }] };
  await expect(importSession(store, badRow as never)).rejects.toThrow(/bad row 2 in "verdicts"/);
  await expect(importSession(store, { ...out, routine: undefined } as never)).rejects.toThrow(/"routine" must be an array/);
  await expect(importSession(store, { ...out, verdicts: [{ ...out.verdicts[0]!, snapshot: undefined }] } as never))
    .rejects.toThrow(/bad row 0/);
  expect(await store.listSessions()).toEqual(before);
});
test('import rejects verdicts the screens could not render (bad status, snapshot name or ruleIds)', async () => {
  const out = await exportSession(store, s.id, { includeEnv: false });
  const before = await store.listSessions();
  const v = out.verdicts[0]!;
  const bad = [
    { ...v, status: 'maybe' },
    { ...v, snapshot: { ...v.snapshot, name: 42 } },
    { ...v, snapshot: { ...v.snapshot, ruleIds: undefined } },
    { ...v, snapshot: { ...v.snapshot, ruleIds: [1, 2] } },
    { ...v, snapshot: { ...v.snapshot, args: 'ls -l' } },
  ];
  for (const row of bad) {
    await expect(importSession(store, { ...out, verdicts: [row] } as never)).rejects.toThrow(/bad row 0 in "verdicts"/);
  }
  expect(await store.listSessions()).toEqual(before);
  await importSession(store, out);   // the untouched export still imports
});
test('store.importAll is atomic when a write fails mid-transaction', async () => {
  const before = await store.listSessions();
  const good = (await store.listCaptures(s.id))[0]!;
  const bad = { ...good, fingerprint: { x: 1 } as never };   // invalid key: DataError after earlier puts were queued
  await expect(store.importAll('x', [good, bad], [], [])).rejects.toThrow();
  expect(await store.listSessions()).toEqual(before);
});
