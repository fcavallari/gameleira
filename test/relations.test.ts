import { expect, test } from 'vitest';
import { ancestry, childrenIndex, displayName } from '../src/model/relations';
import { model, procByPid } from './helpers';

const m = model('es-lab.jsonl');

test('orphan: current parent is launchd, original is the subshell', () => {
  const s = procByPid(m, 41282);
  expect(m.processes.get(s.currentParent!)!.pid).toBe(1);
  expect(s.originalParent).toBe('41281:3563740');
});
test('ghost nodes for pre-capture parents', () => {
  const zsh = m.processes.get(m.tokenIndex.get('35213:3556708')!)!;
  const parent = m.processes.get(zsh.originalParent!)!;
  expect(parent.ghost).toBe(true);
  expect(parent.pid).toBe(35212);
  expect(displayName(m, parent.id)).toBe('pid 35212 · started before capture');
  expect(m.processes.get(zsh.responsible!)!.pid).toBe(35209);
});
test('persistence item attributed to the plist creator', () => {
  const item = m.persistence.find(p => p.plistPath?.endsWith('com.test.studyguide.plist'))!;
  expect(procByPid(m, 41865).id).toBe(item.creator);
});
test('GoogleUpdater item has no creator in capture', () => {
  expect(m.persistence.find(p => p.plistPath?.includes('GoogleUpdater'))!.creator).toBeNull();
});
test('ancestry of osascript reaches zsh 35213', () => {
  const chain = ancestry(m, procByPid(m, 40753).id).map(id => m.processes.get(id)!.pid);
  expect(chain.slice(0, 2)).toEqual([35213, 35212]);
});
test('pre-capture parent is one ghost across modes', () => {
  const zsh = m.processes.get(m.tokenIndex.get('35213:3556708')!)!;
  expect(zsh.originalParent).toBe(zsh.currentParent);
  expect([...m.processes.values()].filter(p => p.pid === 35212)).toHaveLength(1);
});
test('childrenIndex has no process under two parents', () => {
  const idx = childrenIndex(m, 'original');
  const all = [...idx.values()].flat();
  expect(new Set(all).size).toBe(all.length);
});
