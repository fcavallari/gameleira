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
  await expect(importSession(store, { format: 'nope' } as never)).rejects.toThrow();
});
