import { expect, test } from 'vitest';
import { latestImage } from '../src/model/util';
import { applyRoutine, keepReason, NO_IDENTITY, programKey, routineImpact } from '../src/session/routine';
import { procByPid, queued } from './helpers';

/** es-lab: the persistence rows are attached to the process that wrote the plist (the shell that ran `cat`). */
function plistWriter() {
  const { m, a } = queued('es-lab.jsonl');
  const row = a.queue.find(q => q.findings.some(f => f.ruleId === 'persistence-item' && f.persistenceId === 'btm:7709'))!;
  const p = m.processes.get(row.procId!)!;
  return { m, a, row, p, key: programKey(latestImage(p)!) };
}

test('routine never hides a row with a high or persistence finding, and says why it stayed', () => {
  const { m, a, row, key } = plistWriter();
  expect(row.severity).toBe('high');
  const r = applyRoutine(a, m, new Set([key]));
  expect(r.queue.some(q => q.key === row.key)).toBe(true);
  expect(r.kept.get(row.key)).toMatch(/persistence/);
  expect(r.queue.length + r.hiddenCount).toBe(a.queue.length);
});

test('routine still hides a low or med process row without a persistence finding', () => {
  const { m, a } = queued('es-lab.jsonl');
  const curl = procByPid(m, 39838);
  const q = a.queue.find(x => x.procId === curl.id)!;
  expect(keepReason(q)).toBeNull();
  const r = applyRoutine(a, m, new Set([programKey(latestImage(curl)!)]));
  expect(r.queue.some(x => x.key === q.key)).toBe(false);
  expect(r.kept.has(q.key)).toBe(false);
});

test('marking every program routine keeps exactly the high and persistence rows', () => {
  const { m, a } = queued('es-lab.jsonl');
  const keys = new Set([...m.processes.values()].flatMap(p => p.images.map(programKey)));
  const r = applyRoutine(a, m, keys);
  const mustStay = a.queue.filter(q => q.kind === 'persistence' || keepReason(q) !== null);
  expect(r.queue.map(q => q.key).sort()).toEqual(mustStay.map(q => q.key).sort());
  expect(mustStay.some(q => q.severity === 'high')).toBe(true);
  for (const q of mustStay.filter(x => x.kind === 'process')) expect(r.kept.has(q.key)).toBe(true);
});

test('routineImpact counts the rows that would be hidden and the high or persistence rows that stay', () => {
  const { m, a, key } = plistWriter();
  const impact = routineImpact(a, m, key);
  expect(impact.kept).toBeGreaterThanOrEqual(1);
  const curl = procByPid(m, 39838);
  expect(routineImpact(a, m, programKey(latestImage(curl)!))).toEqual({ hidden: 1, kept: 0 });
});

test('NO_IDENTITY is the identity-less program key', () => {
  expect(programKey({ signingId: null, teamId: null, path: null } as never)).toBe(NO_IDENTITY);
});
