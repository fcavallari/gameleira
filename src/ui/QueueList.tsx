import { useEffect, useState } from 'react';
import { useVirtualRows } from './virtual';
import type { QueueItem } from '../rules/engine';
import type { Status } from '../session/store';

export interface QueueRow {
  item: QueueItem;
  name: string;
  args: string;
  status: Status;
  /** Hidden by a routine mark; only listed (greyed) when the user asks to see them. */
  routine: boolean;
  /** The program is marked routine but the row stays visible: why (a high or persistence finding). */
  routineKept: string | null;
}

const ROW_H = 32;
export const STATUS_ICON: Record<Status, string> = { unreviewed: '○', confirmed: '●', benign: '–' };

/** The full text of a cell the row cuts short, shown under it while the pointer is on it. */
interface Tip { text: string; left: number; top: number }
type ShowTip = (el: HTMLElement, text: string) => void;

function Row({ row, selected, onSelect, style, showTip, hideTip }: {
  row: QueueRow; selected: boolean; onSelect(item: QueueItem): void; style?: React.CSSProperties; showTip: ShowTip; hideTip(): void;
}) {
  const { item } = row;
  return (
    <div role="option" aria-selected={selected} style={style}
      className={`qrow${selected ? ' sel' : ''}${row.routine ? ' routine' : ''}`}
      onClick={() => { onSelect(item); }}>
      <span className={`badge sev-${item.severity}`}>{item.severity}</span>
      <span className={`status st-${row.status}`} title={row.status} aria-label={row.status}>{STATUS_ICON[row.status]}</span>
      <span className="qname truncate" onMouseEnter={e => { showTip(e.currentTarget, row.name); }} onMouseLeave={hideTip}>{row.name}</span>
      <span className="args truncate" onMouseEnter={e => { showTip(e.currentTarget, row.args); }} onMouseLeave={hideTip}>{row.args}</span>
      {row.routineKept !== null && (
        <span className="chain-mark" title="This program is marked routine, but a routine mark never hides a row with a high or persistence finding">
          routine program — kept: {row.routineKept}
        </span>
      )}
      {item.reconBurst && (
        <span className="chain-mark" title="One of 3 or more different reconnaissance tools run under the same parent within 60 seconds">recon burst</span>
      )}
    </div>
  );
}

/**
 * The queue, virtualized. Where the browser has not laid the scroll box out (zero height, e.g. jsdom) the rows are
 * rendered plainly instead, so the list never comes up empty.
 */
export function QueueList({ rows, selectedKey, onSelect }: {
  rows: QueueRow[]; selectedKey: string | null; onSelect(item: QueueItem): void;
}) {
  const { scroller, mode, v } = useVirtualRows(rows.length, ROW_H);
  const [tip, setTip] = useState<Tip | null>(null);
  // Only a cell that is actually cut short gets a tooltip; it opens under the cell, kept inside the window.
  const showTip: ShowTip = (el, text) => {
    if (el.scrollWidth <= el.clientWidth || !text) return;
    const r = el.getBoundingClientRect();
    setTip({ text, left: Math.max(8, Math.min(r.left, window.innerWidth - 728)), top: r.bottom + 6 });
  };
  const hideTip = () => { setTip(null); };

  // Keep the selected row visible when keys move it.
  useEffect(() => {
    if (selectedKey === null) return;
    const i = rows.findIndex(r => r.item.key === selectedKey);
    if (i < 0) return;
    if (mode === 'virtual') v.scrollToIndex(i);
    else scroller.current?.querySelector('[aria-selected="true"]')?.scrollIntoView?.({ block: 'nearest' });
  }, [selectedKey, mode]);

  return (
    <>
    <div ref={scroller} role="listbox" aria-label="Flagged processes" className="qscroll" onScroll={hideTip}>
      {mode === 'virtual' && (
        <div style={{ height: v.getTotalSize(), position: 'relative' }}>
          {v.getVirtualItems().map(vi => {
            const row = rows[vi.index]!;
            return <Row key={row.item.key} row={row} selected={row.item.key === selectedKey} onSelect={onSelect} showTip={showTip} hideTip={hideTip}
              style={{ position: 'absolute', top: 0, left: 0, right: 0, height: ROW_H, transform: `translateY(${vi.start}px)` }} />;
          })}
        </div>
      )}
      {mode === 'plain' && rows.map(row => (
        <Row key={row.item.key} row={row} selected={row.item.key === selectedKey} onSelect={onSelect} showTip={showTip} hideTip={hideTip} style={{ height: ROW_H }} />
      ))}
    </div>
    {tip && <div className="ftip" role="tooltip" style={{ left: tip.left, top: tip.top }}>{tip.text}</div>}
    </>
  );
}
