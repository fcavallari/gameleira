import { buildModel } from '../src/model/builder';
import type { CaptureModel, Process } from '../src/model/types';
import { analyze, type Analysis, type QueueItem } from '../src/rules/engine';
import type { Severity } from '../src/rules/rules';
import { readLines, type FixtureName } from './fixtures';

const cache = new Map<FixtureName, CaptureModel>();

/** Model built from a fixture, memoized per fixture. */
export function model(name: FixtureName): CaptureModel {
  let m = cache.get(name);
  if (!m) {
    m = buildModel(readLines(name));
    cache.set(name, m);
  }
  return m;
}

/** The nth process (by firstSeq) with this pid; throws when there is none. */
export function procByPid(m: CaptureModel, pid: number, nth = 0): Process {
  const ps = [...m.processes.values()].filter(p => p.pid === pid).sort((a, b) => a.firstSeq - b.firstSeq);
  const p = ps[nth];
  if (!p) throw new Error(`no process #${nth} with pid ${pid} (found ${ps.length})`);
  return p;
}

export function imagePaths(p: Process): (string | null)[] {
  return p.images.map(i => i.path);
}

export interface QueuedRow { item: QueueItem; p: Process | null; paths: (string | null)[]; args: string }
export interface Queued { m: CaptureModel; a: Analysis; items: QueuedRow[] }

const analyses = new Map<FixtureName, Queued>();

/** The fixture's triage queue, each row with its process, image paths and joined args of all images. */
export function queued(name: FixtureName): Queued {
  let q = analyses.get(name);
  if (!q) {
    const m = model(name);
    const a = analyze(m);
    const items = a.queue.map(item => {
      const p = item.procId !== null ? m.processes.get(item.procId) ?? null : null;
      return {
        item, p,
        paths: p ? imagePaths(p) : [],
        args: p ? p.images.map(i => (i.args ?? []).join(' ')).join(' ') : '',
      };
    });
    q = { m, a, items };
    analyses.set(name, q);
  }
  return q;
}

export function item(name: FixtureName, pred: (x: QueuedRow) => boolean): QueueItem | undefined {
  return queued(name).items.find(pred)?.item;
}

export function hasQueued(name: FixtureName, pred: (x: QueuedRow) => boolean): boolean {
  return queued(name).items.some(pred);
}

/** Rule ids of the first matching queue row; empty when nothing matches. */
export function rules(name: FixtureName, pred: (x: QueuedRow) => boolean): string[] {
  return item(name, pred)?.findings.map(f => f.ruleId) ?? [];
}

export function sev(name: FixtureName, pred: (x: QueuedRow) => boolean): Severity | undefined {
  return item(name, pred)?.severity;
}

export function count(name: FixtureName, pred: (x: QueuedRow) => boolean): number {
  return queued(name).items.filter(pred).length;
}
