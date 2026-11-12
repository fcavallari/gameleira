import { buildModel } from '../src/model/builder';
import type { CaptureModel, Process } from '../src/model/types';
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
