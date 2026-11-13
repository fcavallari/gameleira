import { expect, test } from 'vitest';
import { parseLine } from '../src/model/parse';
import type { NormEvent } from '../src/model/types';
import { basename, fileUrlToPath, normPath } from '../src/model/util';
import { readLines, type FixtureName } from './fixtures';
import { realTest } from './real';

function isEvent(e: NormEvent | null | 'bad'): e is NormEvent {
  return e !== null && e !== 'bad';
}
function parseAll(name: FixtureName): NormEvent[] {
  return readLines(name).map(parseLine).filter(isEvent);
}

const lab = () => parseAll('synthetic-lab.jsonl');

test('synthetic lab: exec v11 normalizes target, args, stdin pipe', () => {
  const ev = lab().find(e => e.kind === 'exec' && e.target!.pid === 7004)!;
  expect(ev.target!.path).toBe('/bin/bash');
  expect(ev.args).toEqual(['bash']);
  expect(ev.stdinIsPipe).toBe(true);
  expect(ev.script).toBeNull();
  expect(ev.proc.path).toBe('/bin/zsh');
  expect(ev.cwd).toBe('/Users/alice/work');
});
test('synthetic lab: fork gives child token', () => {
  const ev = lab().find(e => e.kind === 'fork' && e.child!.pid === 7001)!;
  expect(ev.proc.token).toBe('6130:8130');
  expect(ev.child!.token).toBe('7001:9001');
  expect(ev.child!.ppid).toBe(6130);
});
test('synthetic lab: create with existing_file and new_path both yield a path', () => {
  const creates = lab().filter(e => e.kind === 'create');
  expect(creates.every(e => typeof e.path === 'string' && e.path.length > 0)).toBe(true);
  expect(creates.some(e => e.path === '/Users/alice/Library/LaunchAgents/com.test.labdemo.plist')).toBe(true);   // existing_file
  expect(creates.some(e => e.path === '/private/tmp/page.html')).toBe(true);                                       // new_path
});
test('synthetic lab: rename carries source and destination', () => {
  const renames = lab().filter(e => e.kind === 'rename');
  expect(renames).toHaveLength(1);
  expect(renames[0]).toMatchObject({
    path: '/Users/alice/Library/LaunchAgents/.com.test.labdemo.helper.plist.tmp',
    toPath: '/Users/alice/Library/LaunchAgents/com.test.labdemo.helper.plist',
  });
});
test('synthetic lab: btm add extracts plist path, executable, item type, instigator and app', () => {
  const b = lab().filter(e => e.kind === 'btm_add');
  expect(b).toHaveLength(3);
  const agent = b.find(e => e.btm!.plistPath!.endsWith('com.test.labdemo.plist'))!;
  expect(agent.btm).toMatchObject({ executablePath: '/bin/sh', itemType: 3, appToken: null, app: null, instigatorToken: '560:1390' });
  expect(agent.btm!.instigator).toMatchObject({ pid: 560, path: '/usr/libexec/smd' });
  const login = b.find(e => e.btm!.plistPath === '/Users/alice/Downloads/Installer.app/')!;
  expect(login.btm).toMatchObject({ itemType: 2, appToken: '7100:9101', appPath: '/Users/alice/Downloads/Installer.app/' });
  expect(login.btm!.app).toMatchObject({ pid: 7100, path: '/Users/alice/Downloads/Installer.app/Contents/MacOS/Installer' });
});
test('synthetic lab: nanosecond times and a launchd parent token parse', () => {
  const ev = lab()[0]!;
  expect(ev.time).toMatch(/^2026-03-14T10:00:01\.\d{9}Z$/);
  expect(lab().every(e => e.proc.parentToken !== null)).toBe(true);
});

realTest('exec v11 normalizes target, args, stdin pipe', () => {
  const ev = parseAll('es-lab.jsonl').find(e => e.kind === 'exec' && e.target!.pid === 40489)!;
  expect(ev.target!.path).toBe('/bin/bash');
  expect(ev.args).toEqual(['bash']);
  expect(ev.stdinIsPipe).toBe(true);
  expect(ev.script).toBeNull();
  expect(ev.proc.path).toBe('/bin/zsh');
});
realTest('fork gives child token', () => {
  const ev = parseAll('es-lab.jsonl').find(e => e.kind === 'fork' && e.child!.pid === 41282)!;
  expect(ev.proc.token).toBe('41281:3563740');
  expect(ev.child!.token).toBe('41282:3563741');
});
realTest('create with existing_file and new_path both yield a path', () => {
  const creates = parseAll('es-lab.jsonl').filter(e => e.kind === 'create');
  expect(creates.every(e => typeof e.path === 'string' && e.path.length > 0)).toBe(true);
  expect(creates.some(e => e.path!.endsWith('/Library/LaunchAgents/com.test.studyguide.plist'))).toBe(true);
});
realTest('btm add extracts plist path and executable', () => {
  const b = parseAll('es-lab.jsonl').filter(e => e.kind === 'btm_add');
  expect(b.some(e => e.btm!.plistPath!.endsWith('/Library/LaunchAgents/com.test.studyguide.plist'))).toBe(true);
  expect(b.find(e => e.btm!.plistPath!.endsWith('studyguide.plist'))!.btm!.executablePath).toBe('/bin/sh');
});
realTest('btm add carries item type, instigator and app with their tokens', () => {
  const sg = parseAll('es-lab.jsonl').find(e => e.kind === 'btm_add' && e.btm!.plistPath!.endsWith('studyguide.plist'))!;
  expect(sg.btm).toMatchObject({ itemType: 3, instigatorToken: '558:1379', app: null, appToken: null });
  expect(sg.btm!.instigator).toMatchObject({ token: '558:1379', pid: 558, path: '/usr/libexec/smd' });
});
test('btm add with missing or malformed instigator, app and item still parses', () => {
  const mk = (body: object) => parseLine(JSON.stringify({
    version: 11, time: 't', global_seq_num: 1,
    process: { audit_token: { pid: 1, pidversion: 2 } }, event: { btm_launch_item_add: body },
  }));
  const cases: object[] = [
    {},
    { item: null, instigator: null, instigator_token: null, app: null, app_token: null },
    { item: { item_type: 'x' }, instigator: {}, instigator_token: {}, app: 5, app_token: { pid: 'a' } },
  ];
  for (const body of cases) {
    const ev = mk(body);
    expect(ev).not.toBe('bad');
    expect((ev as NormEvent).btm).toEqual({
      plistPath: null, executablePath: null, appPath: null, itemType: null,
      instigator: null, instigatorToken: null, app: null, appToken: null,
    });
  }
  // Token only: the process object is gone, the token remains.
  const tokOnly = mk({ instigator: null, instigator_token: { pid: 9, pidversion: 4 }, app: null, app_token: { pid: 8, pidversion: 3 } });
  expect((tokOnly as NormEvent).btm).toMatchObject({ instigator: null, instigatorToken: '9:4', app: null, appToken: '8:3' });
  // Object only: the token comes from its audit_token.
  const objOnly = mk({ app: { audit_token: { pid: 8, pidversion: 3 }, executable: { path: '/Applications/A.app/Contents/MacOS/A' } } });
  expect((objOnly as NormEvent).btm).toMatchObject({ appToken: '8:3', app: { token: '8:3', path: '/Applications/A.app/Contents/MacOS/A' } });
});
realTest('v6 parses', () => {
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

realTest('rename carries source and destination in both shapes', () => {
  const renames = parseAll('es-lab.jsonl').filter(e => e.kind === 'rename');
  expect(renames.length).toBeGreaterThan(0);
  expect(renames.every(e => !!e.path && !!e.toPath)).toBe(true);
  const v6 = parseAll('atomic_stealer.json').find(e => e.kind === 'rename')!;
  expect(v6.path).toMatch(/ContextStoreAgent\.plist\./);
  expect(v6.toPath).toMatch(/\/Library\/Preferences\/ContextStoreAgent\.plist$/);
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
test('event keys that are Object.prototype names are other events', () => {
  const mk = (event: object) => parseLine(JSON.stringify({
    version: 11, time: 't', global_seq_num: 1,
    process: { audit_token: { pid: 1, pidversion: 2 } }, event,
  })) as NormEvent;
  for (const k of ['constructor', 'toString', 'hasOwnProperty', '__proto__']) {
    expect(mk({ [k]: {} })).toMatchObject({ kind: 'other', rawType: k });
  }
});
realTest('v6 exec stdinIsPipe is boolean; process without audit_token is bad', () => {
  const evs = parseAll('atomic_stealer.json').filter(e => e.kind === 'exec');
  expect(evs.every(e => typeof e.stdinIsPipe === 'boolean')).toBe(true); // v6 fixture has fds
  expect(parseLine('{"event":{"exit":{}},"process":{}}')).toBe('bad');
});
realTest('fixtures parse without bad lines', () => {
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
