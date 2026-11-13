/** Loaded captures are kept in memory up to this much input file (the file sizes added up): 300 MB. */
export const MAX_LOADED_BYTES = 300 * 1024 * 1024;

/**
 * A copy of `m` with `key` last, so the Map's order is recency: first = least recently used. With `value`, `key` is
 * set to it (a capture was loaded or re-loaded); without, an existing entry is just moved.
 */
export function touch<T>(m: Map<string, T>, key: string, value?: T): Map<string, T> {
  const v = value ?? m.get(key);
  if (v === undefined) return m;
  const next = new Map(m);
  next.delete(key);
  next.set(key, v);
  return next;
}

/**
 * Drops the least recently used entries until the sizes add up to at most `budget`. `active` is never dropped, even
 * when it alone is over the budget. Returns `m` itself when nothing had to go, so a state update can bail out.
 */
export function evictLru<T extends { size: number }>(m: Map<string, T>, active: string | null, budget: number): Map<string, T> {
  let total = 0;
  for (const v of m.values()) total += v.size;
  if (total <= budget) return m;
  const next = new Map(m);
  for (const [k, v] of m) {
    if (total <= budget) break;
    if (k === active) continue;
    next.delete(k);
    total -= v.size;
  }
  return next.size === m.size ? m : next;
}
