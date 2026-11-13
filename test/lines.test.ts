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

const MIB = 1 << 20;

test('a growing capture keeps its fingerprint, under 1 MiB and above it (the first 200 lines do not change)', async () => {
  const buf = fs.readFileSync(fixture('es-lab.jsonl'));
  const whole = await fingerprint(new Blob([buf]), 1, 't');
  // 0.5 and 0.9 MiB used to differ from each other: the old hash covered the first 1 MiB, whatever the file held then.
  for (const size of [Math.round(0.5 * MIB), Math.round(0.9 * MIB), 2 * MIB, 5 * MIB]) {
    expect(await fingerprint(new Blob([buf.subarray(0, size)]), 1, 't'), `${size} bytes`).toBe(whole);
  }
});

test('the hash covers the first 200 complete lines: a change in line 200 shows, one in line 201 does not', async () => {
  const line = (i: number, tail = '') => `{"seq_num":${i},"pad":"${'x'.repeat(80)}${tail}"}\n`;
  const lines = (n: number, edit?: { at: number; tail: string }): string =>
    Array.from({ length: n }, (_, i) => line(i, edit?.at === i ? edit.tail : '')).join('');
  const base = await fingerprint(new Blob([lines(300)]), 0, 't');
  expect(await fingerprint(new Blob([lines(300, { at: 199, tail: 'y' })]), 0, 't')).not.toBe(base);   // line 200
  expect(await fingerprint(new Blob([lines(300, { at: 200, tail: 'y' })]), 0, 't')).toBe(base);       // line 201
  expect(await fingerprint(new Blob([lines(250)]), 0, 't')).toBe(base);
});

test('CRLF and LF line endings give the same fingerprint', async () => {
  const lf = Array.from({ length: 250 }, (_, i) => `{"n":${i}}\n`).join('');
  expect(await fingerprint(new Blob([lf.replace(/\n/g, '\r\n')]), 1, 't')).toBe(await fingerprint(new Blob([lf]), 1, 't'));
});

test('a last line cut in the middle is not part of the hash', async () => {
  const text = Array.from({ length: 50 }, (_, i) => `{"n":${i}}\n`).join('');
  const whole = await fingerprint(new Blob([text]), 1, 't');
  expect(await fingerprint(new Blob([text + '{"n":5']), 1, 't')).toBe(whole);
  expect(await fingerprint(new Blob([text.slice(0, -3)]), 1, 't')).not.toBe(whole);   // line 50 is gone: fewer complete lines
});

test('a file with no complete line is still hashed (its first line, as far as it goes)', async () => {
  expect(await fingerprint(new Blob(['{"a":1']), 1, 't')).not.toBe(await fingerprint(new Blob(['{"a":2']), 1, 't'));
  expect(await fingerprint(new Blob([]), null, null)).toMatch(/^[0-9a-f]{16}:null:null$/);
});

test('reads at most 4 MiB, however long the lines are, and the result does not depend on the rest', async () => {
  const line = `${'z'.repeat(100_000)}\n`;
  const small = new Blob([line.repeat(100)]);   // 10 MB: 40 whole lines fit in 4 MiB
  const slices: number[] = [];
  const spied = Object.create(small, { slice: { value: (a?: number, b?: number) => { slices.push(b ?? small.size); return small.slice(a, b); } } }) as Blob;
  Object.defineProperty(spied, 'size', { value: small.size });
  const a = await fingerprint(spied, 1, 't');
  expect(Math.max(...slices)).toBeLessThanOrEqual(4 * MIB);
  expect(a).toBe(await fingerprint(new Blob([line.repeat(60)]), 1, 't'));
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
