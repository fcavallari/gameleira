import { childrenIndex, displayName, type ParentMode } from '../model/relations';
import type { CaptureModel, ProcId } from '../model/types';
import { basename, latestImage } from '../model/util';

/** Forest keys. A ProcId is `pid:pidversion` or `ghost:pid`, so these cannot collide with one. */
export const ROOT = 'root';
export const UNREACHABLE = 'unreachable';

export const nodeKey = (id: ProcId): string => `n:${id}`;
export const foldKey = (parentKey: string): string => `f:${parentKey}`;
export const GROUP_KEY = 'g:unreachable';

/** Every process exactly once: `kids` lists children per parent key (ROOT, UNREACHABLE or a ProcId). */
export interface Forest {
  kids: Map<string, ProcId[]>;
  /** Parent key of every process. */
  parent: Map<ProcId, string>;
  /** Processes no root reaches because of a parent cycle; they hang under UNREACHABLE. */
  unreachable: number;
}

const forests = new WeakMap<CaptureModel, Map<ParentMode, Forest>>();

/**
 * The parent tree under one mode, built once per capture and mode (not on every selection).
 * `childrenIndex` places each process under one parent, but a parent cycle would leave its members
 * unreachable from the roots: those are gathered under UNREACHABLE so nothing is dropped.
 */
export function forestOf(m: CaptureModel, mode: ParentMode): Forest {
  let byMode = forests.get(m);
  if (!byMode) { byMode = new Map(); forests.set(m, byMode); }
  const cached = byMode.get(mode);
  if (cached) return cached;

  const idx = childrenIndex(m, mode);
  const seq = (id: ProcId): number => m.processes.get(id)?.firstSeq ?? 0;
  const kids = new Map<string, ProcId[]>();
  const parent = new Map<ProcId, string>();
  const placed = new Set<ProcId>();
  /** Adopts the not-yet-placed `start` ids under `key`, then their descendants (iteratively: chains can be deep). */
  const grow = (key: string, start: ProcId[]): void => {
    const work: [string, ProcId[]][] = [[key, start]];
    while (work.length > 0) {
      const [k, list] = work.pop()!;
      const fresh = list.filter(id => !placed.has(id)).sort((a, b) => seq(a) - seq(b));
      if (fresh.length === 0) continue;
      for (const id of fresh) { placed.add(id); parent.set(id, k); }
      let mine = kids.get(k);
      if (!mine) { mine = []; kids.set(k, mine); }
      for (const id of fresh) { mine.push(id); }
      for (const id of fresh) work.push([id, idx.get(id) ?? []]);
    }
  };
  grow(ROOT, idx.get(null) ?? []);
  const unreachable = m.processes.size - placed.size;
  if (unreachable > 0) {
    const rest = [...m.processes.keys()].filter(id => !placed.has(id)).sort((a, b) => seq(a) - seq(b));
    for (const id of rest) if (!placed.has(id)) grow(UNREACHABLE, [id]);
  }
  const f: Forest = { kids, parent, unreachable };
  byMode.set(mode, f);
  return f;
}

/** The given processes and every ancestor of them: the part of the tree that must stay visible. */
export function keepSet(forest: Forest, ids: Iterable<ProcId>): Set<ProcId> {
  const keep = new Set<ProcId>();
  for (const id of ids) {
    let cur: string | undefined = id;
    while (cur !== undefined && cur !== ROOT && cur !== UNREACHABLE && !keep.has(cur)) {
      keep.add(cur);
      cur = forest.parent.get(cur);
    }
  }
  return keep;
}

// --- search ----------------------------------------------------------------------------------------------------

const haystacks = new WeakMap<CaptureModel, Map<ProcId, string>>();

/** Lower-cased text the tree search matches: name, pid, paths, args, script, signing and team IDs of every image. */
function haystackOf(m: CaptureModel, id: ProcId): string {
  let cache = haystacks.get(m);
  if (!cache) { cache = new Map(); haystacks.set(m, cache); }
  let h = cache.get(id);
  if (h === undefined) {
    const p = m.processes.get(id);
    const parts: (string | null)[] = [displayName(m, id), p ? `pid ${p.pid}` : null];
    for (const i of p?.images ?? []) parts.push(i.path, i.signingId, i.teamId, i.script, ...(i.args ?? []));
    h = parts.filter(Boolean).join('\n').toLowerCase();
    cache.set(id, h);
  }
  return h;
}

/** Matching processes plus their ancestors; null when there is nothing to search for. */
export function searchSet(m: CaptureModel, forest: Forest, query: string): { visible: Set<ProcId>; matches: number } | null {
  const needle = query.trim().toLowerCase();
  if (!needle) return null;
  const hits: ProcId[] = [];
  for (const id of m.processes.keys()) if (haystackOf(m, id).includes(needle)) hits.push(id);
  return { visible: keepSet(forest, hits), matches: hits.length };
}

// --- folding ---------------------------------------------------------------------------------------------------

export interface FoldInfo { total: number; label: string; members: ProcId[] }

const procName = (m: CaptureModel, id: ProcId): string => {
  const p = m.processes.get(id);
  return basename((p && latestImage(p)?.path) ?? null) || '(unknown)';
};

/** `routine: docker-tools ×292, git ×88, sh ×5 …`: every process in the folded subtrees, top three by count. */
export function foldLabel(counts: Map<string, number>): string {
  const top = [...counts].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
  return `routine: ${top.slice(0, 3).map(([n, c]) => `${n} ×${c}`).join(', ')}${top.length > 3 ? ' …' : ''}`;
}

/** Counts the folded subtrees once per fold row (cached for this forest and keep set). */
export function makeFoldInfo(m: CaptureModel, forest: Forest, keep: Set<ProcId>): (parentKey: string) => FoldInfo | null {
  const cache = new Map<string, FoldInfo | null>();
  return parentKey => {
    if (cache.has(parentKey)) return cache.get(parentKey)!;
    const members = (forest.kids.get(parentKey) ?? []).filter(id => !keep.has(id));
    let info: FoldInfo | null = null;
    if (members.length > 0) {
      const counts = new Map<string, number>();
      let total = 0;
      const stack = [...members];
      while (stack.length > 0) {
        const id = stack.pop()!;
        total++;
        const n = procName(m, id);
        counts.set(n, (counts.get(n) ?? 0) + 1);
        for (const kid of forest.kids.get(id) ?? []) stack.push(kid);   // no spread: a parent can have 100k+ children
      }
      info = { total, label: foldLabel(counts), members };
    }
    cache.set(parentKey, info);
    return info;
  };
}

// --- rows ------------------------------------------------------------------------------------------------------

export interface NodeRow { kind: 'node'; key: string; id: ProcId; depth: number; expandable: boolean; expanded: boolean }
export interface FoldRow { kind: 'fold'; key: string; depth: number; total: number; label: string; expanded: boolean }
export interface GroupRow { kind: 'group'; key: string; depth: number; total: number; expanded: boolean }
export type TreeRow = NodeRow | FoldRow | GroupRow;

export interface FlattenInput {
  forest: Forest;
  /** Flagged processes and their ancestors. */
  keep: Set<ProcId>;
  fold: boolean;
  foldInfo: (parentKey: string) => FoldInfo | null;
  /** Search result (matches and ancestors); folding is off while it is set. */
  visible: Set<ProcId> | null;
  /** The user's expand/collapse choices by row key; they win over the defaults. */
  overrides: Map<string, boolean>;
}

/** `foldable`: folding applies here. `inGroup`: inside the unreachable group, whose members all start open. */
interface Item { type: 'node' | 'fold' | 'group'; id?: ProcId; parentKey?: string; depth: number; foldable: boolean; inGroup?: boolean }

/**
 * The visible rows, in order. Defaults: flagged processes and their ancestors are open, everything else is closed.
 * Folded rows and the unreachable group are rows too, so every process is either shown or counted in a visible row.
 */
export function flatten(inp: FlattenInput): { rows: TreeRow[]; folded: number; foldRows: number } {
  const { forest, keep, visible, overrides } = inp;
  const useFold = inp.fold && visible === null;
  const open = (key: string, dflt: boolean): boolean => overrides.get(key) ?? dflt;
  const shown = (parentKey: string): ProcId[] => {
    const list = forest.kids.get(parentKey) ?? [];
    return visible ? list.filter(id => visible.has(id)) : list;
  };

  const rows: TreeRow[] = [];
  let folded = 0;
  let foldRows = 0;
  /** Items of one parent: its kept children as nodes, then the fold row for the rest. */
  const itemsOf = (parentKey: string, depth: number, foldable: boolean, inGroup?: boolean): Item[] => {
    const list = shown(parentKey);
    const doFold = useFold && foldable;
    const out: Item[] = list.filter(id => !doFold || keep.has(id)).map(id => ({ type: 'node', id, depth, foldable, inGroup }));
    if (doFold && inp.foldInfo(parentKey)) out.push({ type: 'fold', parentKey, depth, foldable });
    return out;
  };

  const stack: Item[] = itemsOf(ROOT, 0, true).reverse();
  if (forest.unreachable > 0 && (visible === null || shown(UNREACHABLE).length > 0)) {
    stack.unshift({ type: 'group', depth: 0, foldable: false });
  }
  /** Pushes so the first item pops first. A loop, not `push(...items)`: a parent can have 100k+ children. */
  const pushReversed = (items: Item[]): void => { for (let i = items.length - 1; i >= 0; i--) stack.push(items[i]!); };
  while (stack.length > 0) {
    const it = stack.pop()!;
    if (it.type === 'node') {
      const id = it.id!;
      const key = nodeKey(id);
      const kids = shown(id);
      const dflt = visible ? kids.length > 0 : keep.has(id) || it.inGroup === true;
      const expanded = kids.length > 0 && open(key, dflt);
      rows.push({ kind: 'node', key, id, depth: it.depth, expandable: kids.length > 0, expanded });
      if (expanded) pushReversed(itemsOf(id, it.depth + 1, it.foldable, it.inGroup));
    } else if (it.type === 'fold') {
      const info = inp.foldInfo(it.parentKey!)!;
      const key = foldKey(it.parentKey!);
      const expanded = open(key, false);
      folded += info.total;
      foldRows++;
      rows.push({ kind: 'fold', key, depth: it.depth, total: info.total, label: info.label, expanded });
      // Members are unflagged with no flagged descendants, so their subtrees need no folding.
      if (expanded) pushReversed(info.members.map<Item>(id => ({ type: 'node', id, depth: it.depth + 1, foldable: false })));
    } else {
      const members = shown(UNREACHABLE);
      const dflt = visible !== null || members.some(id => keep.has(id));
      const expanded = open(GROUP_KEY, dflt);
      rows.push({ kind: 'group', key: GROUP_KEY, depth: 0, total: forest.unreachable, expanded });
      if (expanded) pushReversed(members.map<Item>(id => ({ type: 'node', id, depth: 1, foldable: false, inGroup: true })));
    }
  }
  return { rows, folded, foldRows };
}

/** Row keys to open so that `id` is on screen: its ancestors, and the fold row it sits in (just that one). */
export function revealKeys(forest: Forest, keep: Set<ProcId>, fold: boolean, id: ProcId): string[] {
  const keys: string[] = [];
  let child: ProcId = id;
  let p = forest.parent.get(id);
  while (p !== undefined) {
    if (p === UNREACHABLE) { keys.push(GROUP_KEY); break; }
    const underFold = fold && !keep.has(child) && (p === ROOT || keep.has(p));
    if (underFold) keys.push(foldKey(p));
    if (p === ROOT) break;
    keys.push(nodeKey(p));
    child = p;
    p = forest.parent.get(p);
  }
  return keys;
}
