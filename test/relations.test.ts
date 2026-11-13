import { expect, test } from 'vitest';
import { ancestry, childrenIndex, displayName, resolveRelations, type ParentMode } from '../src/model/relations';
import type { CaptureModel, Process } from '../src/model/types';
import { model, procByPid } from './helpers';
import type { FixtureName } from './fixtures';
import { realTest } from './real';

const esLab = () => model('es-lab.jsonl');

realTest('orphan: current parent is launchd, original is the subshell', () => {
  const m = esLab();
  const s = procByPid(m, 41282);
  expect(m.processes.get(s.currentParent!)!.pid).toBe(1);
  expect(s.originalParent).toBe('41281:3563740');
});
realTest('ghost nodes for pre-capture parents', () => {
  const m = esLab();
  const zsh = m.processes.get(m.tokenIndex.get('35213:3556708')!)!;
  const parent = m.processes.get(zsh.originalParent!)!;
  expect(parent.ghost).toBe(true);
  expect(parent.pid).toBe(35212);
  expect(displayName(m, parent.id)).toBe('pid 35212 · started before capture');
  expect(m.processes.get(zsh.responsible!)!.pid).toBe(35209);
});
realTest('persistence item attributed to the plist creator', () => {
  const m = esLab();
  const item = m.persistence.find(p => p.plistPath?.endsWith('com.test.studyguide.plist'))!;
  expect(procByPid(m, 41865).id).toBe(item.creator);
});
realTest('GoogleUpdater item has no creator in capture', () => {
  const m = esLab();
  expect(m.persistence.find(p => p.plistPath?.includes('GoogleUpdater'))!.creator).toBeNull();
});
realTest('ancestry of osascript reaches zsh 35213', () => {
  const m = esLab();
  const chain = ancestry(m, procByPid(m, 40753).id).map(id => m.processes.get(id)!.pid);
  expect(chain.slice(0, 2)).toEqual([35213, 35212]);
});
realTest('pre-capture parent is one ghost across modes', () => {
  const m = esLab();
  const zsh = m.processes.get(m.tokenIndex.get('35213:3556708')!)!;
  expect(zsh.originalParent).toBe(zsh.currentParent);
  expect([...m.processes.values()].filter(p => p.pid === 35212)).toHaveLength(1);
});
realTest('every process appears exactly once in childrenIndex for each mode', () => {
  const m = esLab();
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

// ---- PID reuse against start times ----

const DAEMON_START = '2025-12-01T09:00:00.000000Z';
const IN_CAPTURE = '2026-01-01T10:00:00.123456Z';

test('PID reuse: a pre-capture daemon is not parented to a later process that reused its parent pid', () => {
  const h = handBuilt(
    proc('1:1', 1, { startTime: IN_CAPTURE }),                    // launchd with an odd start time: exempt
    proc('500:7', 2, { startTime: IN_CAPTURE, forkParent: '1:1' }), // osascript born during the capture
    proc('300:1', 3, { startTime: DAEMON_START, originalPpid: 500, ppid: 1 }),
  );
  const d = h.processes.get('300:1')!;
  const orig = h.processes.get(d.originalParent!)!;
  expect(orig.ghost).toBe(true);
  expect(orig.pid).toBe(500);
  expect(d.currentParent).toBe('1:1');
});
test('PID reuse: an unseen parent token is not owned by a later-started process with that pid', () => {
  const h = handBuilt(
    proc('500:7', 2, { startTime: IN_CAPTURE }),
    proc('300:1', 3, { startTime: DAEMON_START, originalPpid: 500, ppid: 500, parentToken: '500:3' }),
  );
  const d = h.processes.get('300:1')!;
  expect(d.currentParent).toBe('500:3');
  expect(h.processes.get('500:3')!.ghost).toBe(true);
  expect(d.originalParent).toBe('500:3');
});
test('PID reuse: the latest earlier-started holder of the pid is still the parent', () => {
  const h = handBuilt(
    proc('500:2', 1, { startTime: '2025-11-01T00:00:00Z' }),
    proc('500:7', 2, { startTime: IN_CAPTURE }),
    proc('300:1', 3, { startTime: DAEMON_START, originalPpid: 500, ppid: 500, parentToken: '500:1' }),
  );
  const d = h.processes.get('300:1')!;
  expect(d.originalParent).toBe('500:2');
  expect(d.currentParent).toBe('500:2');
  expect(h.tokenIndex.get('500:1')).toBe('500:2');
});
/** No resolved parent other than launchd started after its child; returns the ghost count. */
function ghostsAndStartOrder(name: FixtureName): number {
  const fm = model(name);
  for (const p of fm.processes.values()) {
    for (const id of [p.originalParent, p.currentParent]) {
      const par = id === null ? undefined : fm.processes.get(id);
      if (!par || par.pid === 1 || !par.startTime || !p.startTime) continue;
      expect(Date.parse(par.startTime) <= Date.parse(p.startTime), `${name} ${p.id} <- ${par.id}`).toBe(true);
    }
  }
  return [...fm.processes.values()].filter(p => p.ghost).length;
}

test('synthetic lab: no resolved parent other than launchd started after its child; four pre-capture ghosts', () => {
  expect(ghostsAndStartOrder('synthetic-lab.jsonl')).toBe(4);   // login, Terminal, the second shell's parent and responsible
});
test('synthetic lab: every process appears exactly once in childrenIndex for each mode', () => {
  const m = model('synthetic-lab.jsonl');
  const ids = [...m.processes.keys()].sort();
  for (const mode of ['original', 'current', 'responsible'] as ParentMode[]) {
    expect([...childrenIndex(m, mode).values()].flat().sort()).toEqual(ids);
  }
});
realTest('fixtures: no resolved parent other than launchd started after its child; ghost counts unchanged', () => {
  const ghosts: Record<string, number> = {
    'es-lab.jsonl': 6, 'atomic_stealer.json': 3, 'rustbucket.json': 0, 'shlayer.json': 2, 'spritetree_demo.json': 0,
  };
  for (const [name, n] of Object.entries(ghosts) as [FixtureName, number][]) {
    expect(ghostsAndStartOrder(name), name).toBe(n);
  }
  // v6: launchd's start time is later than its pre-capture children's, and it stays their parent.
  const v6 = model('atomic_stealer.json');
  const nehelper = procByPid(v6, 215);
  expect(v6.processes.get(nehelper.originalParent!)!.pid).toBe(1);
  expect(v6.processes.get(nehelper.currentParent!)!.ghost).toBe(false);
});
