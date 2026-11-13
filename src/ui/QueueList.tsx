import { useEffect } from 'react';
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
export const STATUS_ICON: Record<Status, string> = { unreviewed: '○', confirmed: '✔', benign: '✕' };

function Row({ row, selected, onSelect, style }: {
  row: QueueRow; selected: boolean; onSelect(item: QueueItem): void; style?: React.CSSProperties;
}) {
  const { item } = row;
  return (
    <div role="option" aria-selected={selected} style={style}
      className={`qrow${selected ? ' sel' : ''}${row.routine ? ' routine' : ''}`}
      onClick={() => { onSelect(item); }}>
      <span className={`badge sev-${item.severity}`}>{item.severity}</span>
      <span className={`status st-${row.status}`} title={row.status} aria-label={row.status}>{STATUS_ICON[row.status]}</span>
      <span className="qname truncate">{row.name}</span>
      <span className="args truncate">{row.args}</span>
      {row.routineKept !== null && (
        <span className="chain-mark" title="This program is marked routine, but a routine mark never hides a row with a high or persistence finding">
          routine program — kept: {row.routineKept}
        </span>
      )}
      {item.inFlaggedChain && (
        <span className="chain-mark" title="Part of a flagged chain: it ran under, or as part of, something that was flagged">in chain</span>
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

  // Keep the selected row visible when keys move it.
  useEffect(() => {
    if (selectedKey === null) return;
    const i = rows.findIndex(r => r.item.key === selectedKey);
    if (i < 0) return;
    if (mode === 'virtual') v.scrollToIndex(i);
    else scroller.current?.querySelector('[aria-selected="true"]')?.scrollIntoView?.({ block: 'nearest' });
  }, [selectedKey, mode]);

  return (
    <div ref={scroller} role="listbox" aria-label="Flagged processes" className="qscroll">
      {mode === 'virtual' && (
        <div style={{ height: v.getTotalSize(), position: 'relative' }}>
          {v.getVirtualItems().map(vi => {
            const row = rows[vi.index]!;
            return <Row key={row.item.key} row={row} selected={row.item.key === selectedKey} onSelect={onSelect}
              style={{ position: 'absolute', top: 0, left: 0, right: 0, height: ROW_H, transform: `translateY(${vi.start}px)` }} />;
          })}
        </div>
      )}
      {mode === 'plain' && rows.map(row => (
        <Row key={row.item.key} row={row} selected={row.item.key === selectedKey} onSelect={onSelect} style={{ height: ROW_H }} />
      ))}
    </div>
  );
}
