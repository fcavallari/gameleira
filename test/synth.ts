import type { CaptureModel, FileOp, Image, PersistenceItem, Process } from '../src/model/types';

/** An exec'd (non-inherited) image; override any field. */
export function img(o: Partial<Image>): Image {
  return {
    token: '100:1', path: '/bin/x', signingId: 'com.example.x', teamId: null, isPlatform: false, csFlags: 0,
    args: null, cwd: null, env: null, stdinIsPipe: null, script: null,
    time: '2026-11-12T00:00:00.000Z', seq: 1, inherited: false, ...o,
  };
}

/** An Apple platform image with these args. */
export const apple = (path: string, args: string[], o: Partial<Image> = {}): Image =>
  img({ path, args, signingId: `com.apple.${path.split('/').pop()}`, isPlatform: true, ...o });

/** A process; `id` doubles as its first token. */
export function proc(id: string, images: Image[], o: Partial<Process> = {}): Process {
  return {
    id, pid: Number(id.split(':')[0]), ghost: false, images, forkParent: null,
    originalPpid: null, ppid: null, parentToken: null, responsibleToken: null,
    originalParent: null, currentParent: null, responsible: null,
    startTime: null, exitTime: null, firstSeq: images[0]?.seq ?? 1, fileOps: [], ...o,
  };
}

export const op = (kind: FileOp['kind'], path: string, seq = 2, toPath?: string): FileOp =>
  ({ kind, path, ...(toPath !== undefined ? { toPath } : {}), time: '2026-11-12T00:00:01.000Z', seq });

export function persistenceItem(o: Partial<PersistenceItem>): PersistenceItem {
  return {
    id: 'btm:9', kind: 'add', plistPath: null, executablePath: null, appPath: null,
    time: '2026-11-12T00:00:02.000Z', seq: 9, itemType: null, emitter: 'ghost:1',
    instigatorToken: null, appToken: null, instigator: null, app: null, creator: null, ...o,
  };
}

/** A capture holding these processes and persistence items. */
export function capture(procs: Process[], persistence: PersistenceItem[] = []): CaptureModel {
  return {
    processes: new Map(procs.map(p => [p.id, p])), tokenIndex: new Map(procs.map(p => [p.id, p.id])), persistence,
    stats: { lines: 0, events: 0, badLines: 0, otherEvents: {}, versions: [], firstSeq: null, firstTime: null, lastTime: null },
  };
}

/** A one-process capture holding the given images (process id `100:1`). */
export const synth = (images: Image[]): CaptureModel => capture([proc('100:1', images)]);
