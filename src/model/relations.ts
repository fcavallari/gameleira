import type { CaptureModel, ProcId, Process, TokenKey } from './types';
import { basename, latestImage, normPath } from './util';

export type ParentMode = 'original' | 'current' | 'responsible';

function ghost(id: ProcId, pid: number, firstSeq: number): Process {
  return {
    id, pid, ghost: true, images: [],
    forkParent: null,
    originalPpid: null, ppid: null, parentToken: null, responsibleToken: null,
    originalParent: null, currentParent: null, responsible: null,
    startTime: null, exitTime: null, firstSeq, fileOps: [],
  };
}

function tokenPid(token: TokenKey): number {
  return Number(token.split(':')[0]);
}

/** Fills originalParent, currentParent and responsible on every process, creating ghosts
 *  for pre-capture references, then attributes each persistence item to the plist's creator. */
export function resolveRelations(m: CaptureModel): void {
  const procs = [...m.processes.values()].filter(p => !p.ghost);
  const byPid = new Map<number, Process[]>();
  for (const p of procs) {
    const list = byPid.get(p.pid);
    if (list) list.push(p);
    else byPid.set(p.pid, [p]);
  }
  const tokenGhosts = new Map<number, Process[]>();

  const adopt = (g: Process, child: Process): ProcId => {
    if (child.firstSeq < g.firstSeq) g.firstSeq = child.firstSeq;
    return g.id;
  };

  const byToken = (token: TokenKey | null, child: Process): ProcId | null => {
    if (token === null) return null;
    const pid = tokenPid(token);
    if (!Number.isFinite(pid) || pid === 0) return null;
    let id = m.tokenIndex.get(token);
    if (id === undefined) {
      const g = ghost(token, pid, child.firstSeq);
      m.processes.set(g.id, g);
      m.tokenIndex.set(token, g.id);
      const list = tokenGhosts.get(pid);
      if (list) list.push(g);
      else tokenGhosts.set(pid, [g]);
      id = g.id;
    } else {
      const known = m.processes.get(id);
      if (known?.ghost) adopt(known, child);
    }
    return id === child.id ? null : id;
  };

  const latestAtOrBefore = (list: Process[] | undefined, seq: number): Process | undefined => {
    let best: Process | undefined;
    for (const p of list ?? []) {
      if (p.firstSeq <= seq && (!best || p.firstSeq > best.firstSeq)) best = p;
    }
    return best;
  };

  const byPidRef = (pid: number | null, child: Process): ProcId | null => {
    if (pid === null || pid === 0) return null;
    let id: ProcId;
    const real = latestAtOrBefore(byPid.get(pid), child.firstSeq);
    if (real) {
      id = real.id;
    } else {
      const ghosts = tokenGhosts.get(pid);
      const g = ghosts ? latestAtOrBefore(ghosts, child.firstSeq) ?? ghosts[0]! : undefined;
      if (g) {
        id = adopt(g, child);
      } else {
        const gid = `ghost:${pid}`;
        const existing = m.processes.get(gid);
        if (existing) id = adopt(existing, child);
        else {
          m.processes.set(gid, ghost(gid, pid, child.firstSeq));
          id = gid;
        }
      }
    }
    return id === child.id ? null : id;
  };

  // Pass A: token references first, so pid lookups can reuse the token ghosts they create.
  const viaToken = new Map<ProcId, ProcId | null>();
  for (const p of procs) {
    viaToken.set(p.id, byToken(p.parentToken, p));
    p.responsible = byToken(p.responsibleToken, p);
  }

  // Pass B: original and current parents, with by-pid fallbacks.
  for (const p of procs) {
    const fromToken = viaToken.get(p.id) ?? null;
    if (p.forkParent !== null) p.originalParent = p.forkParent === p.id ? null : p.forkParent;
    else if (p.parentToken !== null && p.originalPpid === p.ppid) p.originalParent = fromToken;
    else p.originalParent = byPidRef(p.originalPpid, p);
    p.currentParent = p.parentToken !== null ? fromToken : byPidRef(p.ppid, p);
  }

  // Pass C: persistence creators.
  const writers = new Map<string, { seq: number; proc: ProcId }[]>();
  for (const p of procs) {
    for (const op of p.fileOps) {
      const target = op.kind === 'create' ? op.path : op.kind === 'rename' ? op.toPath : undefined;
      if (target === undefined) continue;
      const key = normPath(target);
      const list = writers.get(key);
      const entry = { seq: op.seq, proc: p.id };
      if (list) list.push(entry);
      else writers.set(key, [entry]);
    }
  }
  for (const item of m.persistence) {
    if (item.plistPath === null) { item.creator = null; continue; }
    let best: { seq: number; proc: ProcId } | undefined;
    for (const w of writers.get(normPath(item.plistPath)) ?? []) {
      if (w.seq < item.seq && (!best || w.seq > best.seq)) best = w;
    }
    item.creator = best ? best.proc : null;
  }
}

export function parentOf(m: CaptureModel, id: ProcId, mode: ParentMode): ProcId | null {
  const p = m.processes.get(id);
  if (!p) return null;
  return mode === 'original' ? p.originalParent : mode === 'current' ? p.currentParent : p.responsible;
}

/** Parent first, up to the root; stops when an id repeats. */
export function ancestry(m: CaptureModel, id: ProcId, mode: ParentMode = 'original'): ProcId[] {
  const seen = new Set<ProcId>([id]);
  const chain: ProcId[] = [];
  let cur = parentOf(m, id, mode);
  while (cur !== null && !seen.has(cur)) {
    seen.add(cur);
    chain.push(cur);
    cur = parentOf(m, cur, mode);
  }
  return chain;
}

/** Children per parent under the given mode; the null key holds roots. */
export function childrenIndex(m: CaptureModel, mode: ParentMode): Map<ProcId | null, ProcId[]> {
  const idx = new Map<ProcId | null, ProcId[]>();
  for (const p of m.processes.values()) {
    const parent = parentOf(m, p.id, mode);
    const list = idx.get(parent);
    if (list) list.push(p.id);
    else idx.set(parent, [p.id]);
  }
  return idx;
}

export function displayName(m: CaptureModel, id: ProcId): string {
  const p = m.processes.get(id);
  if (!p) return id;
  const path = latestImage(p)?.path ?? null;
  if (path) return basename(path);
  return p.ghost ? `pid ${p.pid} · started before capture` : `pid ${p.pid}`;
}
