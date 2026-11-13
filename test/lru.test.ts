import { expect, test } from 'vitest';
import { evictLru, MAX_LOADED_BYTES, touch } from '../src/session/lru';

const caps = (...sizes: [string, number][]): Map<string, { size: number }> => new Map(sizes.map(([k, size]) => [k, { size }]));
const keys = (m: Map<string, unknown>): string[] => [...m.keys()];

test('the budget is 300 MB of input files', () => {
  expect(MAX_LOADED_BYTES).toBe(300 * 1024 * 1024);
});

test('under the budget nothing is dropped and the same Map comes back', () => {
  const m = caps(['a', 100], ['b', 100]);
  expect(evictLru(m, 'b', 200)).toBe(m);
});

test('drops the least recently used first, until the total fits', () => {
  const m = caps(['a', 100], ['b', 100], ['c', 100], ['d', 100]);
  expect(keys(evictLru(m, 'd', 250))).toEqual(['c', 'd']);
  expect(keys(evictLru(m, 'd', 350))).toEqual(['b', 'c', 'd']);
});

test('never drops the active capture, even over the budget on its own', () => {
  const m = caps(['a', 100], ['b', 900]);
  expect(keys(evictLru(m, 'a', 500))).toEqual(['a']);
  expect(keys(evictLru(caps(['big', 900]), 'big', 500))).toEqual(['big']);
});

test('the active one is skipped, not counted as recent: an older active survives and newer ones go', () => {
  const m = caps(['a', 100], ['b', 100], ['c', 100]);
  expect(keys(evictLru(m, 'a', 150))).toEqual(['a']);
});

test('touch moves an entry to the end (most recent) and adds new ones last', () => {
  const m = caps(['a', 1], ['b', 1], ['c', 1]);
  expect(keys(touch(m, 'a'))).toEqual(['b', 'c', 'a']);
  expect(keys(touch(m, 'z', { size: 1 }))).toEqual(['a', 'b', 'c', 'z']);
  expect(keys(touch(m, 'b', { size: 9 })).join()).toBe('a,c,b');
  expect(touch(m, 'missing')).toBe(m);
  expect(keys(m)).toEqual(['a', 'b', 'c']);   // the original is not changed
});
