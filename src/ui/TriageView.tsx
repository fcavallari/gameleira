import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ProcId } from '../model/types';
import type { QueueItem } from '../rules/engine';
import type { Severity } from '../rules/rules';
import type { Status } from '../session/store';
import { DetailPane } from './DetailPane';
import { QueueList, type QueueRow } from './QueueList';
import { useSession } from './session-context';
import { haystack, itemArgs, itemName, verdictKey } from './triage-model';

type StatusFilter = 'all' | Status;
const STATUS_FILTERS: StatusFilter[] = ['all', 'unreviewed', 'confirmed', 'benign'];
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
  const { capture, triage, verdicts, selected } = c;
  const [status, setStatus] = useState<StatusFilter>('all');
  const [sev, setSev] = useState<Set<Severity>>(new Set(SEVERITIES));
  const [search, setSearch] = useState('');
  const [showHidden, setShowHidden] = useState(false);
  /** A persistence-only item has no ProcId, so the context cannot hold it: its queue key lives here. */
  const [persSel, setPersSel] = useState<string | null>(null);
  const noteRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => { setPersSel(null); }, [c.active]);

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
      const st = verdicts.get(verdictKey(item))?.status ?? 'unreviewed';
      if (status !== 'all' && st !== status) continue;
      if (needle && !(haystacks.get(item.key) ?? '').includes(needle)) continue;
      out.push({ item, name: itemName(capture, item), args: itemArgs(capture, item), status: st, routine: !visible.has(item.key) });
    }
    return out;
  }, [capture, triage, verdicts, status, sev, search, showHidden, haystacks]);

  const selKey: string | null = selected ?? persSel;
  const selectedRowKey = rows.find(r => verdictKey(r.item) === selKey)?.item.key ?? null;

  const selectProc = useCallback((id: ProcId) => { setPersSel(null); c.selectProc(id); }, [c]);
  const choose = useCallback((item: QueueItem) => {
    if (item.procId !== null) { setPersSel(null); c.selectProc(item.procId); }
    else { setPersSel(item.key); c.selectProc(null); }
  }, [c]);

  const onKey = (e: KeyboardEvent) => {
    if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey || isTyping(e.target)) return;
    if (e.key.startsWith('Arrow') && ownsArrows(e.target)) return;
    const move = (d: 1 | -1) => {
      e.preventDefault();
      if (rows.length === 0) return;
      const i = rows.findIndex(r => verdictKey(r.item) === selKey);
      const next = i < 0 ? (d === 1 ? 0 : rows.length - 1) : Math.min(rows.length - 1, Math.max(0, i + d));
      choose(rows[next]!.item);
    };
    switch (e.key) {
      case 'j': case 'ArrowDown': move(1); break;
      case 'k': case 'ArrowUp': move(-1); break;
      case 'c': if (selKey !== null) void c.setVerdict(selKey, 'confirmed', undefined); break;
      case 'b': if (selKey !== null) void c.setVerdict(selKey, 'benign', undefined); break;
      case 'n': if (selKey !== null && noteRef.current) { e.preventDefault(); noteRef.current.focus(); } break;
      case 't': if (selected !== null) c.showInTree(selected); break;
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
    setSev(cur => { const n = new Set(cur); if (n.has(s)) n.delete(s); else n.add(s); return n; });
  };
  const total = triage.queue.length;

  return (
    <div className="triage">
      <section className="queue" aria-label="Queue">
        <div className="qtools">
          <input type="text" aria-label="Search flagged processes" placeholder="Search name, path, args, signing ID" value={search}
            onChange={e => { setSearch(e.target.value); }} />
          <div className="row" role="radiogroup" aria-label="Status">
            {STATUS_FILTERS.map(f => (
              <label key={f} className="inline">
                <input type="radio" name="status-filter" checked={status === f} onChange={() => { setStatus(f); }} />{f}
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
        </div>
        <QueueList rows={rows} selectedKey={selectedRowKey} onSelect={choose} />
        {rows.length === 0 && (
          <p className="muted qempty">{total === 0 && !showHidden ? 'Nothing flagged in this capture.' : 'No rows match the filters.'}</p>
        )}
        <div className="qfoot small muted">
          <span>Showing {rows.length} of {showHidden ? capture.analysis.queue.length : total}</span>
          <span>
            {triage.hiddenCount} routine hidden
            {triage.hiddenCount > 0 && <> · <button className="link" onClick={() => { setShowHidden(h => !h); }}>{showHidden ? 'hide' : 'show'}</button></>}
          </span>
        </div>
      </section>
      <section className="detail" aria-label="Selected process">
        <DetailPane selKey={selKey} onSelectProc={selectProc} noteRef={noteRef} />
      </section>
    </div>
  );
}
