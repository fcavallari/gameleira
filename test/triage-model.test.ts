import { expect, test } from 'vitest';
import type { LoadedCapture } from '../src/ingest/load';
import type { Image, Process } from '../src/model/types';
import { itemArgs, rowArgs } from '../src/ui/triage-model';
import { procByPid, queued } from './helpers';

const img = (o: Partial<Image>): Image => ({
  token: '1:1', path: null, signingId: null, teamId: null, isPlatform: false, csFlags: 0,
  args: null, cwd: null, env: null, stdinIsPipe: null, script: null, time: null, seq: 0, inherited: false, ...o,
});
const proc = (images: Image[]): Process => ({
  id: '1:1', pid: 1, ghost: false, images, forkParent: null, originalPpid: null, ppid: null, parentToken: null,
  responsibleToken: null, originalParent: null, currentParent: null, responsible: null, startTime: null, exitTime: null,
  firstSeq: 1, fileOps: [],
});

test("atomic's dscl row shows dscl's own arguments, not the sh -c wrapper's", () => {
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
  expect(rowArgs(procByPid(queued('es-lab.jsonl').m, 40753))).toContain('display dialog');
});
