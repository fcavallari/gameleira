import { useLayoutEffect, useRef, useState } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';

/**
 * A fixed-row-height virtualized list. Where the browser has not laid the scroll box out (zero height, e.g. jsdom)
 * `mode` is 'plain' and the caller renders every row instead, so the list never comes up empty.
 */
export function useVirtualRows(count: number, rowHeight: number) {
  const scroller = useRef<HTMLDivElement>(null);
  const [mode, setMode] = useState<'pending' | 'virtual' | 'plain'>('pending');
  useLayoutEffect(() => { setMode((scroller.current?.clientHeight ?? 0) > 0 ? 'virtual' : 'plain'); }, [count]);
  const v = useVirtualizer({ count, getScrollElement: () => scroller.current, estimateSize: () => rowHeight, overscan: 12 });
  return { scroller, mode, v };
}
