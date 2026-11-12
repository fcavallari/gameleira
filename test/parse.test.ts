import { expect, test } from 'vitest';
import { parseLine } from '../src/model/parse';
import type { NormEvent } from '../src/model/types';
import { basename, fileUrlToPath, normPath } from '../src/model/util';
import { readLines, type FixtureName } from './fixtures';

function isEvent(e: NormEvent | null | 'bad'): e is NormEvent {
  return e !== null && e !== 'bad';
}
function parseAll(name: FixtureName): NormEvent[] {
  return readLines(name).map(parseLine).filter(isEvent);
}

test('exec v11 normalizes target, args, stdin pipe', () => {
  const ev = parseAll('es-lab.jsonl').find(e => e.kind === 'exec' && e.target!.pid === 40489)!;
  expect(ev.target!.path).toBe('/bin/bash');
  expect(ev.args).toEqual(['bash']);
  expect(ev.stdinIsPipe).toBe(true);
  expect(ev.script).toBeNull();
  expect(ev.proc.path).toBe('/bin/zsh');
});
test('fork gives child token', () => {
  const ev = parseAll('es-lab.jsonl').find(e => e.kind === 'fork' && e.child!.pid === 41282)!;
  expect(ev.proc.token).toBe('41281:3563740');
  expect(ev.child!.token).toBe('41282:3563741');
});
test('create with existing_file and new_path both yield a path', () => {
  const creates = parseAll('es-lab.jsonl').filter(e => e.kind === 'create');
  expect(creates.every(e => typeof e.path === 'string' && e.path.length > 0)).toBe(true);
  expect(creates.some(e => e.path === '/Users/alice/Library/LaunchAgents/com.test.studyguide.plist')).toBe(true);
});
test('btm add extracts plist path and executable', () => {
  const b = parseAll('es-lab.jsonl').filter(e => e.kind === 'btm_add');
  expect(b.map(e => e.btm!.plistPath)).toContain('/Users/alice/Library/LaunchAgents/com.test.studyguide.plist');
  expect(b.find(e => e.btm!.plistPath!.endsWith('studyguide.plist'))!.btm!.executablePath).toBe('/bin/sh');
});
test('v6 parses', () => {
  const evs = parseAll('atomic_stealer.json');
  expect(evs.length).toBe(556);
  expect(evs.every(e => e.version === 6)).toBe(true);
});
test('truncated last line', () => {
  expect(parseLine('{"event":{"exec":')).toBe('bad');
});
test('non-eslogger input', () => {
  expect(parseLine('{"foo":1}')).toBe('bad');
  expect(parseLine('')).toBeNull();
});

test('rename carries source and destination in both shapes', () => {
  const renames = parseAll('es-lab.jsonl').filter(e => e.kind === 'rename');
  expect(renames.length).toBeGreaterThan(0);
  expect(renames.every(e => !!e.path && !!e.toPath)).toBe(true);
  const v6 = parseAll('atomic_stealer.json').find(e => e.kind === 'rename')!;
  expect(v6.path).toMatch(/ContextStoreAgent\.plist\./);
  expect(v6.toPath).toBe('/Users/sandy/Library/Preferences/ContextStoreAgent.plist');
});
test('new_path destination joins dir and filename', () => {
  const line = JSON.stringify({
    version: 11, time: 't', global_seq_num: 5,
    process: { audit_token: { pid: 1, pidversion: 2 } },
    event: { create: { destination_type: 1, destination: { new_path: { dir: { path: '/tmp/d' }, filename: 'f.txt' } } } },
  });
  const ev = parseLine(line) as NormEvent;
  expect(ev.kind).toBe('create');
  expect(ev.path).toBe('/tmp/d/f.txt');
});
test('unlink, write, setextattr, unknown events', () => {
  const mk = (event: object) => parseLine(JSON.stringify({
    version: 11, time: 't', global_seq_num: 1,
    process: { audit_token: { pid: 1, pidversion: 2 } }, event,
  })) as NormEvent;
  expect(mk({ unlink: { target: { path: '/a' } } })).toMatchObject({ kind: 'unlink', path: '/a' });
  expect(mk({ write: { target: { path: '/b' } } })).toMatchObject({ kind: 'write', path: '/b' });
  expect(mk({ setextattr: { target: { path: '/c' }, extattr: 'com.apple.quarantine' } }))
    .toMatchObject({ kind: 'setextattr', path: '/c', xattr: 'com.apple.quarantine' });
  expect(mk({ mmap: {} })).toMatchObject({ kind: 'other', rawType: 'mmap' });
});
test('v6 exec stdinIsPipe is boolean; process without audit_token is bad', () => {
  const evs = parseAll('atomic_stealer.json').filter(e => e.kind === 'exec');
  expect(evs.every(e => typeof e.stdinIsPipe === 'boolean')).toBe(true); // v6 fixture has fds
  expect(parseLine('{"event":{"exit":{}},"process":{}}')).toBe('bad');
});
test('fixtures parse without bad lines', () => {
  for (const n of ['es-lab.jsonl', 'atomic_stealer.json', 'rustbucket.json', 'shlayer.json', 'spritetree_demo.json'] as const) {
    expect(readLines(n).map(parseLine).filter(e => e === 'bad').length).toBe(0);
  }
});

test('util helpers', () => {
  expect(basename('/usr/bin/zsh')).toBe('zsh');
  expect(basename(null)).toBe('');
  expect(normPath('/private/tmp/x')).toBe('/tmp/x');
  expect(normPath('/private/var/folders/a')).toBe('/var/folders/a');
  expect(normPath('/private/other')).toBe('/private/other');
  expect(normPath('/users/bob/a')).toBe('/Users/bob/a');
  expect(fileUrlToPath('file:///Users/a/My%20App.app/')).toBe('/Users/a/My App.app/');
  expect(fileUrlToPath(null)).toBeNull();
});
