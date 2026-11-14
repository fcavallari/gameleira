import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { QueueItem } from '../rules/engine';
import type { Severity } from '../rules/rules';
import { DetailPane } from './DetailPane';
import { QueueList, type QueueRow } from './QueueList';
import { useSession } from './session-context';
import { haystack, itemArgs, itemName, triageAction, verdictKey, type TriageFilters } from './triage-model';

const STATUS_FILTERS: TriageFilters['status'][] = ['all', 'unreviewed', 'confirmed', 'benign'];
const SEVERITIES: Severity[] = ['high', 'med', 'low'];

const NON_TEXT_INPUTS = new Set(['radio', 'checkbox', 'button', 'submit', 'reset', 'range']);
/** True where letters belong to the field. Radios and checkboxes keep focus after a click, so they do not count. */
const isTyping = (t: EventTarget | null): boolean => {
  const el = t as HTMLInputElement | null;
  if (!el) return false;
  if (el.isContentEditable || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT') return true;
  return el.tagName === 'INPUT' && !NON_TEXT_INPUTS.has(el.type);
};
/** A focused radio uses the arrow keys to change its own selection. */
const ownsArrows = (t: EventTarget | null): boolean => (t as HTMLInputElement | null)?.type === 'radio';

export function TriageView() {
  const c = useSession();
  const { capture, triage, selected, selectedItem } = c;
  const { verdicts } = c;
  const { status, sev, search, showHidden, chainOnly } = c.triageFilters;
  const setFilters = c.updateTriageFilters;
  const noteRef = useRef<HTMLTextAreaElement>(null);
  /** Where the selected row last stood in the list, for when a verdict or routine mark takes it out of the list. */
  const anchor = useRef<{ key: string; index: number } | null>(null);

  // Lower-cased search text per queue item, once per capture.
  const haystacks = useMemo(() => {
    const m = new Map<string, string>();
    if (capture) for (const q of capture.analysis.queue) m.set(q.key, haystack(capture, q));
    return m;
  }, [capture]);

  const rows = useMemo<QueueRow[]>(() => {
    if (!capture || !triage) return [];
    const visible = new Set(triage.queue.map(q => q.key));
    const base = showHidden ? capture.analysis.queue : triage.queue;
    const needle = search.trim().toLowerCase();
    const out: QueueRow[] = [];
    for (const item of base) {
      if (!sev.has(item.severity)) continue;
      if (chainOnly && !item.inFlaggedChain) continue;
      const st = verdicts.get(verdictKey(item))?.status ?? 'unreviewed';
      if (status !== 'all' && st !== status) continue;
      if (needle && !(haystacks.get(item.key) ?? '').includes(needle)) continue;
      out.push({ item, name: itemName(capture, item), args: itemArgs(capture, item), status: st, routine: !visible.has(item.key), routineKept: triage.kept.get(item.key) ?? null });
    }
    return out;
  }, [capture, triage, verdicts, status, sev, search, showHidden, chainOnly, haystacks]);

  const selKey: string | null = selected ?? selectedItem;
  const selectedRowKey = rows.find(r => verdictKey(r.item) === selKey)?.item.key ?? null;
  useEffect(() => {
    const index = rows.findIndex(r => verdictKey(r.item) === selKey);
    if (index >= 0) anchor.current = { key: selKey!, index };
  });

  const { selectProc, selectItem } = c;
  const choose = useCallback((item: QueueItem) => {
    if (item.procId !== null) selectProc(item.procId);
    else selectItem(item.key);
  }, [selectProc, selectItem]);

  const onKey = (e: KeyboardEvent) => {
    if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey || isTyping(e.target)) return;
    if (e.key.startsWith('Arrow') && ownsArrows(e.target)) return;
    const move = (d: 1 | -1) => {
      e.preventDefault();
      if (rows.length === 0) return;
      const i = rows.findIndex(r => verdictKey(r.item) === selKey);
      // The selected row can have left the list (confirming it under the "unreviewed" filter): carry on from where it
      // stood. The row now at that index took its place, so "next" is that row and "previous" the one before it.
      const at = i < 0 && selKey !== null && anchor.current?.key === selKey ? anchor.current.index : null;
      const next = at !== null ? Math.min(rows.length - 1, Math.max(0, d === 1 ? at : at - 1))
        : i < 0 ? (d === 1 ? 0 : rows.length - 1) : Math.min(rows.length - 1, Math.max(0, i + d));
      choose(rows[next]!.item);
    };
    switch (triageAction(e.key)) {
      case 'next': move(1); break;
      case 'prev': move(-1); break;
      case 'confirm': if (selKey !== null) void c.toggleVerdict(selKey, 'confirmed'); break;
      case 'benign': if (selKey !== null) void c.toggleVerdict(selKey, 'benign'); break;
      case 'note': if (selKey !== null && noteRef.current) { e.preventDefault(); noteRef.current.focus(); } break;
      case 'tree': if (selected !== null) c.showInTree(selected); break;
    }
  };
  const onKeyRef = useRef(onKey);
  onKeyRef.current = onKey;
  useEffect(() => {
    const h = (e: KeyboardEvent) => { onKeyRef.current(e); };
    window.addEventListener('keydown', h);
    return () => { window.removeEventListener('keydown', h); };
  }, []);

  if (!capture || !triage) return null;

  const toggleSev = (s: Severity) => {
    const n = new Set(sev);
    if (n.has(s)) n.delete(s); else n.add(s);
    setFilters({ sev: n });
  };
  const total = triage.queue.length;

  return (
    <div className="triage">
      <section className="queue" aria-label="Queue">
        <div className="qtools">
          <input type="text" aria-label="Search flagged processes" placeholder="Search name, path, args, signing ID" value={search}
            onChange={e => { setFilters({ search: e.target.value }); }} />
          <div className="row" role="radiogroup" aria-label="Status">
            {STATUS_FILTERS.map(f => (
              <label key={f} className="inline">
                <input type="radio" name="status-filter" checked={status === f} onChange={() => { setFilters({ status: f }); }} />{f}
              </label>
            ))}
          </div>
          <div className="row" role="group" aria-label="Severity">
            {SEVERITIES.map(s => (
              <label key={s} className="inline">
                <input type="checkbox" checked={sev.has(s)} onChange={() => { toggleSev(s); }} />{s}
              </label>
            ))}
          </div>
          <div className="row">
            <label className="inline chain-only" title="Rows queued because they ran under, or as part of, something that was flagged">
              <input type="checkbox" checked={chainOnly} onChange={e => { setFilters({ chainOnly: e.target.checked }); }} />Show only in-chain processes
            </label>
          </div>
        </div>
        <QueueList rows={rows} selectedKey={selectedRowKey} onSelect={choose} />
        {rows.length === 0 && (
          <p className="muted qempty">{total === 0 && !showHidden ? 'Nothing flagged in this capture.' : 'No rows match the filters.'}</p>
        )}
        <div className="qfoot small muted">
          <span>Showing {rows.length} of {showHidden ? capture.analysis.queue.length : total}</span>
          <span>
            {triage.hiddenCount} routine hidden
            {triage.hiddenCount > 0 && <> · <button className="link" onClick={() => { setFilters({ showHidden: !showHidden }); }}>{showHidden ? 'hide' : 'show'}</button></>}
          </span>
        </div>
      </section>
      <section className="detail" aria-label="Selected process">
        <DetailPane selKey={selKey} onSelectProc={selectProc} noteRef={noteRef} />
      </section>
    </div>
  );
}
