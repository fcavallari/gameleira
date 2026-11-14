import { expect, test } from 'vitest';
import { fingerprint } from '../src/ingest/fingerprint';
import { loadCapture } from '../src/ingest/load';
import { detectLayout, streamObjects } from '../src/ingest/records';
import { captureInfo } from '../src/ui/triage-model';
import { readLines } from './fixtures';

/** A record as Mac Monitor 3 writes it: eslogger's keys untouched, its own enrichments beside them. */
function macMonitor(line: string): unknown {
  const o = JSON.parse(line);
  Object.assign(o, {
    telemetry_version: '1.1.0', context: 'summary', es_event_type: 'ES_EVENT_TYPE_NOTIFY_X', sensor_id: 'S',
    macOS: '27.0 (Build 26A1)', target_path: 'Not supported', indicators: [],
  });
  o.process.process_age_ms = 5;
  o.process.audit_token_string = 'token';
  const kind = Object.keys(o.event)[0]!;
  if (kind === 'exec' || kind === 'fork') o.event[kind].launched_by_parent = null;
  return o;
}
const lab = readLines('synthetic-lab.jsonl');
/** Mac Monitor's pretty export: each record pretty-printed, joined by "\n", no trailing newline. */
const pretty = (ls: string[]) => ls.map(l => JSON.stringify(macMonitor(l), null, 2)).join('\n');

async function objects(text: string, chunkSize?: number): Promise<Array<[string, boolean]>> {
  const out: Array<[string, boolean]> = [];
  await streamObjects(new Blob([text]), (t, complete) => out.push([t, complete]), undefined, chunkSize);
  return out;
}

test('pretty objects joined by newlines are split into records, at any chunk size', async () => {
  const a = { a: 1, nested: { b: [1, 2, { c: 3 }] } };
  const b = { s: 'braces { and } and "quotes" and \\ in a string' };
  const text = JSON.stringify(a, null, 2) + '\n' + JSON.stringify(b, null, 2);
  for (const size of [1, 3, 7, 4 << 20]) {
    const out = await objects(text, size);
    expect(out.map(([t, c]) => [JSON.parse(t), c]), `chunk ${size}`).toEqual([[a, true], [b, true]]);
  }
});

test('a JSON array of objects gives its elements', async () => {
  const arr = [{ a: 1 }, { b: [2] }, { c: '[' }];
  for (const text of [JSON.stringify(arr), JSON.stringify(arr, null, 2), JSON.stringify(arr, null, '\t')]) {
    expect((await objects(text)).map(([t]) => JSON.parse(t))).toEqual(arr);
  }
});

test('multi-byte UTF-8 split across chunks', async () => {
  expect(await objects('{\n  "s": "é—x"\n}', 1)).toEqual([['{\n  "s": "é—x"\n}', true]]);
});

test('a record cut short ends where the next one starts at the start of a line, and is not complete', async () => {
  const text = '{\n  "a": {\n    "b": 1\n{\n  "c": 2\n}\n';
  expect(await objects(text)).toEqual([['{\n  "a": {\n    "b": 1\n', false], ['{\n  "c": 2\n}', true]]);
});

test('a string broken by a raw newline ends its record; the rest of the file still reads', async () => {
  const text = '{\n  "a": "cut\n}\n{\n  "c": 2\n}';
  const out = await objects(text);
  expect(out.at(-1)).toEqual(['{\n  "c": 2\n}', true]);
  expect(out.slice(0, -1).every(([, c]) => !c)).toBe(true);
});

test('a last record cut by the end of the file is reported, not complete', async () => {
  expect(await objects('{"a":1}\n{\n  "b": ')).toEqual([['{"a":1}', true], ['{\n  "b": ', false]]);
});

test('text between records is reported as an unreadable record, line by line', async () => {
  expect(await objects('junk here\n{"a":1}\nmore\n')).toEqual([['junk here', false], ['{"a":1}', true], ['more', false]]);
});

test('progress reports bytes read against total', async () => {
  const seen: Array<[number, number]> = [];
  await streamObjects(new Blob(['{"a":1}\n']), () => {}, (b, t) => seen.push([b, t]), 4);
  expect(seen).toEqual([[4, 8], [8, 8]]);
});

test('detectLayout: JSONL reads by line, pretty JSON and arrays by object', async () => {
  const at = (s: string) => detectLayout(new Blob([s]));
  expect(await at(lab.join('\n'))).toBe('lines');
  expect(await at('﻿' + lab.join('\n'))).toBe('lines');
  expect(await at(pretty(lab))).toBe('objects');
  expect(await at('\r\n' + pretty(lab).replace(/\n/g, '\r\n'))).toBe('objects');
  expect(await at('[{"a":1}]')).toBe('objects');
  expect(await at('  [\n')).toBe('objects');
  expect(await at('')).toBe('lines');
  expect(await at('not json\n{"a":1}')).toBe('lines');
});

/** What the queue flags, without anything built from sequence numbers (persistence ids are). */
const shape = (q: Awaited<ReturnType<typeof loadCapture>>['analysis']['queue']) =>
  q.map(i => [i.kind, i.procId, i.severity, i.findings.map(f => `${f.ruleId}:${f.evidence}`)]);

test('Mac Monitor JSONL and pretty exports load like the eslogger capture they extend', async () => {
  const base = await loadCapture(new Blob([lab.join('\n')]));
  const jsonl = await loadCapture(new Blob([lab.map(l => JSON.stringify(macMonitor(l))).join('\n')]));
  const pre = await loadCapture(new Blob([pretty(lab)]));
  for (const c of [jsonl, pre]) {
    expect(c.model.stats.events).toBe(111);
    expect(c.model.stats.badLines).toBe(0);
    expect(shape(c.analysis.queue)).toEqual(shape(base.analysis.queue));
  }
  expect(pre.model.stats.layout).toBe('objects');
  expect(pre.model.stats.lines).toBe(111);
  expect(base.model.stats.layout).toBeUndefined();
});

test('a JSON array export loads too', async () => {
  const c = await loadCapture(new Blob([JSON.stringify(lab.map(l => JSON.parse(l)), null, 2)]));
  expect(c.model.stats.events).toBe(111);
});

test('a pretty capture is identified by its first 200 records: a change in record 200 shows, one in 201 does not', async () => {
  const long = [...lab, ...lab, ...lab];   // 327 records
  const fp = (ls: string[]) => fingerprint(new Blob([pretty(ls)]), 0, 't', 'objects');
  const base = await fp(long);
  expect(await fp(long.slice(0, 250))).toBe(base);
  expect(await fp(long.slice(0, 60))).not.toBe(base);
  const edit = (i: number) => long.map((l, j) => (j === i ? l.replace('"time":"', '"time":"9') : l));
  expect(await fp(edit(199))).not.toBe(base);
  expect(await fp(edit(200))).toBe(base);
  // CRLF and LF are the same capture, and so is a copy cut in the middle of a record past the 200th.
  expect(await fingerprint(new Blob([pretty(long).replace(/\n/g, '\r\n')]), 0, 't', 'objects')).toBe(base);
  const text = pretty(long);
  expect(await fingerprint(new Blob([text.slice(0, text.length - 100)]), 0, 't', 'objects')).toBe(base);
});

test('the summary line counts unreadable records, not lines, in a pretty capture', () => {
  const stats = { lines: 3, events: 2, badLines: 1, otherEvents: {}, versions: [], firstSeq: 0, firstTime: '', lastTime: '' };
  expect(captureInfo(stats).line).toBe('1 unreadable line');
  expect(captureInfo({ ...stats, layout: 'objects' }).line).toBe('1 unreadable record');
  expect(captureInfo({ ...stats, layout: 'objects', badLines: 2 }).line).toBe('2 unreadable records');
});

test('Mac Monitor records are ordered by mach_time: its sequence numbers are per ES client, not one order', async () => {
  const base = await loadCapture(new Blob([lab.join('\n')]));
  // Two clients numbering their own messages from 0 (process events and the rest), and the file in reverse order.
  const counters = { proc: 0, other: 0 };
  const records = lab.map((l) => {
    const o = macMonitor(l) as { event: Record<string, unknown>; global_seq_num: number };
    const client = ['fork', 'exec', 'exit'].includes(Object.keys(o.event)[0]!) ? 'proc' : 'other';
    o.global_seq_num = counters[client]++;
    return JSON.stringify(o, null, 2);
  }).reverse();
  const c = await loadCapture(new Blob([records.join('\n')]));
  expect(c.model.stats.events).toBe(111);
  expect(shape(c.analysis.queue)).toEqual(shape(base.analysis.queue));
  // seq is the record's place in mach_time order, so it stays unique (btm ids and React keys are built from it).
  expect(c.model.stats.firstSeq).toBe(0);
  expect(c.model.stats.firstTime).toBe(base.model.stats.firstTime);
  const ids = c.model.persistence.map(p => p.id);
  expect(new Set(ids).size).toBe(ids.length);
  expect(ids.length).toBe(base.model.persistence.length);
});
