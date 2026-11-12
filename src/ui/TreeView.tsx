import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties, type KeyboardEvent } from 'react';
import type { LoadedCapture } from '../ingest/load';
import { displayName, type ParentMode } from '../model/relations';
import type { ProcId } from '../model/types';
import type { QueueItem } from '../rules/engine';
import type { Status } from '../session/store';
import { DetailPane } from './DetailPane';
import { STATUS_ICON } from './QueueList';
import { useSession } from './session-context';
import { firstArgs } from './triage-model';
import {
  flatten, forestOf, keepSet, makeFoldInfo, revealKeys, searchSet,
  type FoldRow, type GroupRow, type NodeRow, type TreeRow,
} from './tree-model';
import { useVirtualRows } from './virtual';

const ROW_H = 28;
const MAX_INDENT = 24;
const MODES: { value: ParentMode; label: string }[] = [
  { value: 'original', label: 'Original parent' },
  { value: 'current', label: 'Current parent' },
  { value: 'responsible', label: 'Responsible' },
];
const NO_OVERRIDES: Map<string, boolean> = new Map();

const indent = (depth: number): number => 8 + Math.min(depth, MAX_INDENT) * 16;

interface RowProps { style?: CSSProperties; onToggle(key: string, open: boolean): void }

function Twisty({ show, open, onClick }: { show: boolean; open: boolean; onClick?(): void }) {
  return <span className="twisty" aria-hidden="true" onClick={onClick}>{show ? (open ? '▾' : '▸') : ''}</span>;
}

function NodeItem({ row, cap, flag, routine, status, selected, onSelect, style, onToggle }: RowProps & {
  row: NodeRow; cap: LoadedCapture; flag: QueueItem | undefined; routine: boolean; status: Status | undefined;
  selected: boolean; onSelect(id: ProcId): void;
}) {
  const proc = cap.model.processes.get(row.id);
  const name = displayName(cap.model, row.id);
  const args = proc && !proc.ghost ? firstArgs(proc) : '';
  const label = args ? `${name} ${args}` : name;
  const st: Status = status ?? 'unreviewed';
  return (
    <div role="treeitem" aria-level={row.depth + 1} aria-selected={selected} aria-expanded={row.expandable ? row.expanded : undefined}
      style={{ ...style, paddingLeft: indent(row.depth) }}
      className={`trow${selected ? ' sel' : ''}${routine ? ' routine' : ''}${proc?.ghost ? ' ghost' : ''}`}
      onClick={() => { onSelect(row.id); }}>
      <Twisty show={row.expandable} open={row.expanded}
        onClick={row.expandable ? () => { onToggle(row.key, !row.expanded); } : undefined} />
      {flag && <span className={`badge sev-${flag.severity}`}>{flag.severity}</span>}
      {flag && <span className={`status st-${st}`} title={st} aria-label={st}>{STATUS_ICON[st]}</span>}
      <span className="tname truncate" title={label}>{label}</span>{' '}
      {proc && !proc.ghost && <span className="tpid muted">pid {proc.pid}</span>}
      {flag?.inFlaggedChain && (
        <span className="chain-mark" title="Part of a flagged chain: it ran under, or as part of, something that was flagged">in chain</span>
      )}
    </div>
  );
}

/** The grey rows: a fold of routine processes, or the group of processes caught in a parent cycle. */
function GreyItem({ row, text, count, style, onToggle }: RowProps & { row: FoldRow | GroupRow; text: string; count?: string }) {
  const flip = () => { onToggle(row.key, !row.expanded); };
  return (
    <div role="treeitem" aria-level={row.depth + 1} aria-selected={false} aria-expanded={row.expanded} tabIndex={0}
      style={{ ...style, paddingLeft: indent(row.depth) }} className="trow fold" onClick={flip}
      onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); flip(); } }}>
      <Twisty show open={row.expanded} />
      <span className="tname truncate" title={text}>{text}</span>
      {count && <span className="tpid muted">{count}</span>}
    </div>
  );
}

const fmt = (n: number): string => n.toLocaleString('en-US');

function TreeInner({ cap, queue: triageQueue }: { cap: LoadedCapture; queue: QueueItem[] }) {
  const c = useSession();
  const { selected, verdicts } = c;
  const [mode, setMode] = useState<ParentMode>('original');
  const [fold, setFold] = useState(true);
  const [search, setSearch] = useState('');
  /** Expand/collapse choices; they belong to one search text (a new search starts from the defaults). */
  const [ovState, setOvState] = useState<{ search: string; map: Map<string, boolean> }>({ search: '', map: NO_OVERRIDES });
  const overrides = ovState.search === search ? ovState.map : NO_OVERRIDES;
  const noteRef = useRef<HTMLTextAreaElement>(null);
  /** A process to centre once the rows that show it exist (Show in tree, mode change, leaving a search). */
  const [revealTo, setRevealTo] = useState<ProcId | null>(null);

  const forest = useMemo(() => forestOf(cap.model, mode), [cap, mode]);
  /** Flagged processes the triage queue still shows; routine-marked ones are left out, so they fold. */
  const flagged = useMemo(() => triageQueue.filter(q => q.procId !== null).map(q => q.procId!), [triageQueue]);
  const flaggedSet = useMemo(() => new Set(flagged), [flagged]);
  const keep = useMemo(() => keepSet(forest, flagged), [forest, flagged]);
  const foldInfo = useMemo(() => makeFoldInfo(cap.model, forest, keep), [cap, forest, keep]);
  const found = useMemo(() => searchSet(cap.model, forest, search), [cap, forest, search]);
  const visible = found?.visible ?? null;
  /** Badges come from the whole analysis, so a routine-marked flagged process still shows its severity. */
  const badge = useMemo(() => {
    const m = new Map<ProcId, QueueItem>();
    for (const q of cap.analysis.queue) if (q.procId !== null) m.set(q.procId, q);
    return m;
  }, [cap]);

  const { rows, folded, foldRows } = useMemo(
    () => flatten({ forest, keep, fold, foldInfo, visible, overrides }),
    [forest, keep, fold, foldInfo, visible, overrides]);

  /** Opens `keys`; `resetSearch` also clears the search, since a hidden target cannot be revealed under it. */
  const open = useCallback((keys: string[], resetSearch: boolean) => {
    const next = resetSearch ? '' : search;
    setSearch(next);
    setOvState(cur => {
      const map = new Map(cur.search === next ? cur.map : NO_OVERRIDES);
      for (const k of keys) map.set(k, true);
      return { search: next, map };
    });
  }, [search]);

  /** Opens just enough of the tree under `m` to show `id`; the scroll follows once those rows exist. */
  const reveal = useCallback((id: ProcId, m: ParentMode, resetSearch: boolean) => {
    const f = forestOf(cap.model, m);
    if (!f.parent.has(id)) return;
    open(revealKeys(f, keepSet(f, flagged), fold, id), resetSearch);
    setRevealTo(id);
  }, [cap, flagged, fold, open]);

  // "Show in tree": reveal the process, whatever hid it (collapsed ancestors, a fold, the search).
  useEffect(() => {
    if (c.focusId !== null) reveal(c.focusId, mode, true);
  }, [c.focusNonce, cap]);

  const changeMode = (m: ParentMode) => {
    setMode(m);
    if (selected !== null) reveal(selected, m, false);
  };

  const toggle = useCallback((key: string, openIt: boolean) => {
    setOvState(cur => {
      const map = new Map(cur.search === search ? cur.map : NO_OVERRIDES);
      map.set(key, openIt);
      return { search, map };
    });
  }, [search]);

  const { scroller, mode: vmode, v } = useVirtualRows(rows.length, ROW_H);
  /** Moves the row into view: `centre` for a reveal, otherwise only as far as needed (keys, clicks). */
  const scrollTo = (id: ProcId, centre: boolean): boolean => {
    const i = rows.findIndex(r => r.kind === 'node' && r.id === id);
    if (i < 0) return false;
    if (vmode === 'virtual') v.scrollToIndex(i, { align: centre ? 'center' : 'auto' });
    else scroller.current?.querySelector('[aria-selected="true"]')?.scrollIntoView?.({ block: centre ? 'center' : 'nearest' });
    return true;
  };
  // The selection follows keys and clicks. Rows do not change then, so this must not wait for them.
  useEffect(() => {
    if (selected === null || revealTo !== null || vmode === 'pending') return;
    scrollTo(selected, false);
  }, [selected, vmode]);
  // A reveal waits for the render that carries its expanded rows, then is done: it never lingers.
  useEffect(() => {
    if (revealTo === null || vmode === 'pending') return;
    scrollTo(revealTo, true);
    setRevealTo(null);
  }, [revealTo, rows, vmode]);

  const select = useCallback((id: ProcId) => {
    setRevealTo(null);
    c.selectProc(id);
    scroller.current?.focus({ preventScroll: true });
  }, [c, scroller]);

  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.metaKey || e.ctrlKey || e.altKey || e.target !== e.currentTarget) return;
    const nodes = rows.filter((r): r is NodeRow => r.kind === 'node');
    const cur = nodes.find(r => r.id === selected);
    const go = (to: TreeRow | undefined) => {
      if (to?.kind !== 'node') return;
      e.preventDefault();
      setRevealTo(null);
      c.selectProc(to.id);
    };
    const at = cur ? rows.indexOf(cur) : -1;
    switch (e.key) {
      case 'ArrowDown': go(cur ? nodes[nodes.indexOf(cur) + 1] : nodes[0]); break;
      case 'ArrowUp': go(cur ? nodes[nodes.indexOf(cur) - 1] : nodes[nodes.length - 1]); break;
      case 'ArrowRight':
        if (!cur?.expandable) break;
        e.preventDefault();
        if (cur.expanded) go(rows[at + 1]); else toggle(cur.key, true);
        break;
      case 'ArrowLeft':
        if (!cur) break;
        e.preventDefault();
        if (cur.expanded) { toggle(cur.key, false); break; }
        for (let j = at - 1; j >= 0; j--) if (rows[j]!.depth < cur.depth) { go(rows[j]); break; }
        break;
    }
  };

  const renderRow = (row: TreeRow, style?: CSSProperties) => {
    if (row.kind === 'fold') return <GreyItem key={row.key} row={row} text={row.label} count={`${fmt(row.total)} processes`} style={style} onToggle={toggle} />;
    if (row.kind === 'group') return <GreyItem key={row.key} row={row} text={`unreachable (parent cycle) ×${row.total}`} style={style} onToggle={toggle} />;
    const flag = badge.get(row.id);
    return <NodeItem key={row.key} row={row} cap={cap} flag={flag} routine={flag !== undefined && !flaggedSet.has(row.id)}
      status={verdicts.get(row.id)?.status} selected={row.id === selected} style={style} onToggle={toggle} onSelect={select} />;
  };
  const rowStyle = (start: number): CSSProperties =>
    ({ position: 'absolute', top: 0, left: 0, right: 0, height: ROW_H, transform: `translateY(${start}px)` });

  return (
    <div className="triage tree">
      <section className="queue" aria-label="Process tree view">
        <div className="qtools">
          <input type="text" aria-label="Search processes" placeholder="Search name, path, args, signing ID, pid" value={search}
            onChange={e => {
              const text = e.target.value;
              // Leaving a search with something selected: keep it on screen (it may sit in a fold or a collapsed branch).
              setSearch(text);
              if (text.trim() === '' && selected !== null) reveal(selected, mode, true);
            }} />
          <div className="row">
            <label className="inline">Parent mode{' '}
              <select value={mode} onChange={e => { changeMode(e.target.value as ParentMode); }}>
                {MODES.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
              </select>
            </label>
            <label className="inline">
              <input type="checkbox" checked={fold} onChange={e => { setFold(e.target.checked); }} />Fold routine
            </label>
          </div>
        </div>
        <div ref={scroller} role="tree" aria-label="Process tree" tabIndex={0} className="qscroll tscroll" onKeyDown={onKey}>
          {vmode === 'virtual' && (
            <div style={{ height: v.getTotalSize(), position: 'relative' }}>
              {v.getVirtualItems().map(vi => renderRow(rows[vi.index]!, rowStyle(vi.start)))}
            </div>
          )}
          {vmode === 'plain' && rows.map(r => renderRow(r, { height: ROW_H }))}
        </div>
        {rows.length === 0 && <p className="muted qempty">{found ? 'Nothing matches the search.' : 'No processes.'}</p>}
        <div className="qfoot small muted">
          <span>
            {found
              ? `${found.matches} ${found.matches === 1 ? 'match' : 'matches'} · other processes are hidden while searching`
              : `${fmt(cap.model.processes.size)} processes · ${fmt(folded)} folded into ${foldRows} grey ${foldRows === 1 ? 'row' : 'rows'} (click to expand)`}
          </span>
          {forest.unreachable > 0 && <span>{forest.unreachable} in a parent cycle</span>}
        </div>
      </section>
      <section className="detail" aria-label="Selected process">
        {selected !== null
          ? <DetailPane selKey={selected} onSelectProc={c.showInTree} noteRef={noteRef} />
          : <p className="muted detail-empty">Select a process to see its details. Grey rows fold routine processes: click one to list them.</p>}
      </section>
    </div>
  );
}

export function TreeView() {
  const { capture, triage, active } = useSession();
  if (!capture || !triage) return null;
  return <TreeInner key={active} cap={capture} queue={triage.queue} />;
}
