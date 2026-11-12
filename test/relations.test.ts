import { expect, test } from 'vitest';
import { ancestry, childrenIndex, displayName, resolveRelations, type ParentMode } from '../src/model/relations';
import type { CaptureModel, Process } from '../src/model/types';
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
test('every process appears exactly once in childrenIndex for each mode', () => {
  const ids = [...m.processes.keys()].sort();
  for (const mode of ['original', 'current', 'responsible'] as ParentMode[]) {
    const all = [...childrenIndex(m, mode).values()].flat();
    expect(all.slice().sort()).toEqual(ids);
  }
});

/** A captured process with the given token as its id; raw relation fields default to null. */
function proc(token: string, firstSeq: number, raw: Partial<Process> = {}): Process {
  return {
    id: token, pid: Number(token.split(':')[0]), ghost: false, images: [],
    forkParent: null, originalPpid: null, ppid: null, parentToken: null, responsibleToken: null,
    originalParent: null, currentParent: null, responsible: null,
    startTime: null, exitTime: null, firstSeq, fileOps: [], ...raw,
  };
}

function handBuilt(...procs: Process[]): CaptureModel {
  const m: CaptureModel = {
    processes: new Map(procs.map(p => [p.id, p])),
    tokenIndex: new Map(procs.map(p => [p.id, p.id])),
    persistence: [],
    stats: { lines: 0, events: 0, badLines: 0, otherEvents: {}, versions: [],
      firstSeq: null, firstTime: null, lastTime: null },
  };
  resolveRelations(m);
  return m;
}

test('unseen older token of a pre-capture process is that process (self-responsibility is null)', () => {
  const h = handBuilt(proc('100:2', 1, { responsibleToken: '100:1' }));
  expect(h.processes.get('100:2')!.responsible).toBeNull();
  expect([...h.processes.values()].filter(p => p.pid === 100)).toHaveLength(1);
});
test('siblings referencing seen and unseen tokens of one parent share its id', () => {
  const h = handBuilt(
    proc('100:2', 1),
    proc('200:1', 2, { ppid: 100, originalPpid: 100, parentToken: '100:1' }),
    proc('201:1', 3, { ppid: 100, originalPpid: 100, parentToken: '100:2' }),
  );
  for (const id of ['200:1', '201:1']) {
    expect(h.processes.get(id)!.currentParent).toBe('100:2');
    expect(h.processes.get(id)!.originalParent).toBe('100:2');
  }
  expect(h.tokenIndex.get('100:1')).toBe('100:2');
  expect([...h.processes.values()].filter(p => p.pid === 100)).toHaveLength(1);
});
test('PID reuse: unseen older token of an in-capture fork child stays a ghost', () => {
  const h = handBuilt(
    proc('1:1', 1),
    proc('100:5', 2, { forkParent: '1:1' }),
    proc('200:1', 3, { ppid: 100, originalPpid: 100, parentToken: '100:1' }),
  );
  const parent = h.processes.get(h.processes.get('200:1')!.currentParent!)!;
  expect(parent.id).toBe('100:1');
  expect(parent.ghost).toBe(true);
});
