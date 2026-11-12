import fs from 'node:fs';
import { expect, test } from 'vitest';
import { fingerprint } from '../src/ingest/fingerprint';
import { loadCapture } from '../src/ingest/load';
import { streamLines } from '../src/ingest/lines';
import { fixture } from './fixtures';

test('lines split across chunk boundaries', async () => {
  const text = 'a\nbb\n' + 'c'.repeat(10) + '\nlast-no-newline';
  const out: string[] = [];
  await streamLines(new Blob([text]), (l) => out.push(l), undefined, 3);
  expect(out).toEqual(['a', 'bb', 'c'.repeat(10), 'last-no-newline']);
});

test('multi-byte UTF-8 split across chunks', async () => {
  const out: string[] = [];
  await streamLines(new Blob(['é—x\n']), (l) => out.push(l), undefined, 1);
  expect(out).toEqual(['é—x']);
});

test('progress reports bytes read against total', async () => {
  const seen: Array<[number, number]> = [];
  await streamLines(new Blob(['abc\ndef\n']), () => {}, (b, t) => seen.push([b, t]), 4);
  expect(seen).toEqual([[4, 8], [8, 8]]);
});

test('loadCapture on es-lab', async () => {
  const c = await loadCapture(new Blob([fs.readFileSync(fixture('es-lab.jsonl'))]));
  expect(c.model.stats.events).toBe(11610);
  expect(c.analysis.queue.length).toBeGreaterThan(0);
  expect(c.fileName).toBe('');
  expect(c.fingerprint).toMatch(/^[0-9a-f]{16}:/);
});

test('fingerprint stable for a grown file', async () => {
  const buf = fs.readFileSync(fixture('es-lab.jsonl'));
  expect(buf.length).toBeGreaterThan((1 << 20) + 5000);
  const a = await fingerprint(new Blob([buf.subarray(0, buf.length - 5000)]), 1, 't');
  const b = await fingerprint(new Blob([buf]), 1, 't');
  expect(a).toBe(b);
});

test('fingerprint differs when head bytes differ', async () => {
  const a = await fingerprint(new Blob(['aaaa']), 1, 't');
  const b = await fingerprint(new Blob(['aaab']), 1, 't');
  expect(a).not.toBe(b);
  expect(a.endsWith(':1:t')).toBe(true);
});

test('non-eslogger file rejected', async () => {
  await expect(loadCapture(new Blob(['{"foo":1}\n']))).rejects.toThrow('No eslogger events found');
});
