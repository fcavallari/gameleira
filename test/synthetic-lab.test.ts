import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { displayName } from '../src/model/relations';
import { basename } from '../src/model/util';
import { fixture, readLines } from './fixtures';
import { imagePaths, item, model, procByPid, queued, type QueuedRow } from './helpers';

// The synthetic capture is in the repo, so these tests run on a fresh clone. What happens in it is told at the top of
// scripts/make-synthetic-lab.mjs; every pid below is one of the invented ones.
const LAB = 'synthetic-lab.jsonl';
const m = model(LAB);
const q = queued(LAB);
const row = (pid: number): QueuedRow | undefined => q.items.find(x => x.p?.pid === pid);
const rowItem = (pid: number) => row(pid)?.item;
const ruleIds = (pid: number): string[] => rowItem(pid)?.findings.map(f => f.ruleId) ?? [];

describe('the fixture itself', () => {
  test('is exactly what scripts/make-synthetic-lab.mjs writes', () => {
    const script = path.resolve(__dirname, '..', 'scripts', 'make-synthetic-lab.mjs');
    const out = execFileSync(process.execPath, [script, '--stdout'], { maxBuffer: 16 << 20 }).toString('utf8');
    expect(out).toBe(fs.readFileSync(fixture(LAB), 'utf8'));
  });
  test('stays small and carries no real home folder', () => {
    const text = fs.readFileSync(fixture(LAB), 'utf8');
    expect(text.length).toBeLessThan(200 * 1024);
    const users = new Set([...text.matchAll(/\/Users\/([^/"\s]+)/g)].map(x => x[1]));
    expect([...users].sort()).toEqual(['alice']);
  });
  test('parses cleanly as schema 11, with the events the viewer does not model counted', () => {
    expect(m.stats).toMatchObject({ events: 111, badLines: 0, versions: [11], otherEvents: { open: 3 } });
    expect(readLines(LAB)).toHaveLength(111);
  });
});

describe('the process model', () => {
  test('an exec chain is one process', () => {
    const nohup = procByPid(m, 7012);
    expect(imagePaths(nohup)).toEqual(['/bin/zsh', '/usr/bin/nohup', '/bin/sleep']);
    expect(nohup.images[0]!.inherited).toBe(true);
    expect(nohup.images[1]!.inherited).toBe(false);
    expect(m.tokenIndex.get('7012:9113')).toBe(nohup.id);
  });
  test('a child that only forks keeps the inherited image and nothing else', () => {
    const echo = procByPid(m, 7003);
    expect(echo.images).toHaveLength(1);
    expect(echo.images[0]!.inherited).toBe(true);
    expect(echo.exitTime).not.toBeNull();
  });
  test('the shell\'s parent and responsible process, never seen, are ghosts', () => {
    const zsh = procByPid(m, 6130);
    const login = m.processes.get(zsh.originalParent!)!;
    expect(login.ghost).toBe(true);
    expect(displayName(m, login.id)).toBe('pid 6120 · started before capture');
    expect(m.processes.get(zsh.responsible!)!.pid).toBe(6100);
    expect(m.processes.get(zsh.responsible!)!.ghost).toBe(true);
    // a second reference to the same pre-capture parent is the same ghost
    expect([...m.processes.values()].filter(p => p.pid === 6120)).toHaveLength(1);
  });
  test('an exec the capture missed merges into one process: same pid and start_time, next pidversion', () => {
    const merged = [...m.processes.values()].filter(p => p.pid === 7500);
    expect(merged).toHaveLength(1);
    expect(imagePaths(merged[0]!)).toEqual(['/bin/sh', '/usr/bin/curl']);
    expect(m.tokenIndex.get('7500:9500')).toBe(merged[0]!.id);
    expect(m.tokenIndex.get('7500:9501')).toBe(merged[0]!.id);
    expect(merged[0]!.fileOps.map(f => f.path)).toEqual(['/private/tmp/payload.bin']);
  });
  test('an orphan: the original parent is the subshell, the current parent is launchd', () => {
    const sleep = procByPid(m, 7011);
    expect(sleep.originalParent).toBe(procByPid(m, 7010).id);
    const launchd = m.processes.get(sleep.currentParent!)!;
    expect(launchd.pid).toBe(1);
    expect(launchd.ghost).toBe(false);   // launchd forks Installer.app in the capture
    expect(displayName(m, launchd.id)).toBe('launchd');
  });
  test('file operations land on the process that made them, across its exec', () => {
    const cat = procByPid(m, 7013);
    expect(imagePaths(cat)).toEqual(['/bin/zsh', '/bin/cat']);
    expect(cat.fileOps.map(f => f.path)).toEqual(['/Users/alice/Library/LaunchAgents/com.test.labdemo.plist']);
    expect(procByPid(m, 7001).fileOps.map(f => f.path)).toEqual(['/private/tmp/page.html']);
  });
  test('piped stdin is read from the exec event', () => {
    expect(procByPid(m, 7004).images.at(-1)!.stdinIsPipe).toBe(true);
    expect(procByPid(m, 7006).images.at(-1)!.stdinIsPipe).toBe(false);
  });
});

describe('launch items: item type, who registered them, where the finding lands', () => {
  const byPlist = (suffix: string) => m.persistence.find(i => i.plistPath?.endsWith(suffix))!;

  test('an agent plist written by a shell redirect: instigated by smd, so the writer carries the finding', () => {
    const it = byPlist('/com.test.labdemo.plist');
    expect(it.itemType).toBe(3);
    expect(m.processes.get(it.emitter)!.images[0]!.path).toMatch(/backgroundtaskmanagementd$/);
    expect(m.processes.get(it.instigator!)!.pid).toBe(560);
    expect(it.app).toBeNull();
    expect(it.creator).toBe(procByPid(m, 7013).id);
    const f = rowItem(7013)!.findings.find(x => x.ruleId === 'persistence-item')!;
    expect(f).toMatchObject({ severity: 'high', title: 'Launch agent registered', mitre: ['T1543.001'] });
    expect(f.evidence).toContain('runs /bin/sh');
    expect(rowItem(7013)!.severity).toBe('high');
    // the plist rule does not repeat it on the writer: its registration is accounted for there
    expect(ruleIds(7013)).not.toContain('persistence-plist');
  });
  test('a login item registered by an app in ~/Downloads: the event names the app, so its row carries the finding', () => {
    const it = byPlist('/Downloads/Installer.app/');
    expect(it.itemType).toBe(2);
    expect(m.processes.get(it.app!)!.pid).toBe(7100);
    expect(it.creator).toBeNull();
    const r = rowItem(7100)!;
    const f = r.findings.find(x => x.ruleId === 'persistence-item')!;
    expect(f).toMatchObject({ severity: 'high', title: 'Login item registered', mitre: ['T1547.015'] });
    expect(f.evidence).toContain('app /Users/alice/Downloads/Installer.app');
    expect(f.evidence).toContain('Downloads folder');
    expect(r.findings.map(x => x.ruleId)).toEqual(expect.arrayContaining(['odd-location-exec', 'persistence-item', 'adhoc']));
    expect(q.items.some(x => x.item.persistenceId === it.id)).toBe(false);   // no separate standalone row
  });
  test('an agent with no captured process behind it is a standalone row, med', () => {
    const it = byPlist('/com.example.updater.wake.plist');
    const standalone = q.items.filter(x => x.item.kind === 'persistence');
    expect(standalone).toHaveLength(1);
    expect(standalone[0]!.item).toMatchObject({ persistenceId: it.id, procId: null, severity: 'med' });
    expect(standalone[0]!.item.findings[0]).toMatchObject({ ruleId: 'persistence-item', mitre: ['T1543.001'] });
  });
  test('a plist written by a process that forked and never exec\'d, with no btm event, is flagged on that process', () => {
    const p = procByPid(m, 7015);
    expect(p.images.every(i => i.inherited)).toBe(true);
    expect(ruleIds(7015)).toEqual(['persistence-plist']);
    expect(rowItem(7015)!.findings[0]).toMatchObject({ severity: 'high', mitre: ['T1543.001'] });
    expect(rowItem(7015)!.findings[0]!.evidence).toContain('com.test.labdemo.helper.plist');
    // written as a temp file renamed onto the plist: the rename's destination counts
    expect(p.fileOps.map(f => f.kind)).toEqual(['create', 'rename']);
    expect(p.fileOps[1]!.toPath).toBe('/Users/alice/Library/LaunchAgents/com.test.labdemo.helper.plist');
  });
});

describe('the queue: what must be flagged', () => {
  const must: [string, number, string, string][] = [
    ['fake password prompt', 7006, 'fake-prompt', 'high'],
    ['dscl -authonly with the password in its arguments', 7016, 'dscl-authonly', 'high'],
    ['launchctl bootstrap', 7014, 'launchctl-load', 'high'],
    ['ditto staging in /tmp', 7009, 'archive-staging', 'high'],
    ['xattr -cr on the app it came in', 7101, 'quarantine-strip', 'high'],
    ['curl -o /tmp/page.html', 7001, 'download', 'med'],
    ['bash fed from a pipe', 7004, 'shell-from-pipe', 'med'],
    ['curl whose exec the capture missed, creating a file', 7500, 'download', 'med'],
    ['sleep whose subshell exited', 7011, 'orphaned', 'low'],
  ];
  test.each(must)('%s', (_name, pid, rule, severity) => {
    expect(ruleIds(pid)).toContain(rule);
    expect(rowItem(pid)!.severity).toBe(severity);
  });
  test('whoami under the piped bash is queued because it is in a flagged chain', () => {
    expect(rowItem(7005)).toMatchObject({ inFlaggedChain: true, reconBurst: false, severity: 'low' });
    expect(ruleIds(7005)).toEqual(['recon']);
  });
  test('the xattr under Installer is in its chain, and Installer itself is not a descendant of anything flagged', () => {
    expect(rowItem(7101)!.inFlaggedChain).toBe(true);
    expect(rowItem(7100)!.inFlaggedChain).toBe(false);
  });
  test('the queue is exactly these rows, high first', () => {
    const rows = q.items.map(x => `${x.item.severity} ${x.p ? x.p.pid : 'item'}`);
    expect(rows).toEqual([
      'high 7006', 'high 7016', 'high 7009', 'high 7013', 'high 7014', 'high 7015', 'high 7100', 'high 7101',
      'med 7001', 'med 7004', 'med item', 'med 7500',
      'low 7005', 'low 7011', 'low 7400', 'low 7401', 'low 7402',
    ]);
  });
});

describe('the queue: noise that must not be in it', () => {
  const names = q.items.map(x => basename(x.paths.at(-1) ?? null));
  test('ps, git, mdworker_shared and the quiet helpers are absent', () => {
    for (const n of ['ps', 'git', 'mdworker_shared', 'mkdir', 'cp', 'nohup', 'smd', 'backgroundtaskmanagementd', 'hostname', 'Monitor', 'Lab Editor']) {
      expect(names, n).not.toContain(n);
    }
    // xattr is queued once, for the quarantine strip under Installer; `xattr -l` is not
    expect(row(7002)).toBeUndefined();
    // the echo subshell and the second sleep (an ordinary nohup) are not flagged either
    expect(row(7003)).toBeUndefined();
    expect(row(7012)).toBeUndefined();
  });
  test('six ps runs under one parent are one tool: context only, and not a burst', () => {
    const ps = [...m.processes.values()].filter(p => p.images.some(i => basename(i.path) === 'ps'));
    expect(ps).toHaveLength(6);
    for (const p of ps) {
      expect(q.a.contextOnly.get(p.id)?.map(f => f.ruleId)).toEqual(['recon']);
      expect(q.a.queue.some(x => x.procId === p.id)).toBe(false);
    }
  });
  test('a team-signed build running from /var/folders is context only', () => {
    expect(row(7310)).toBeUndefined();
    expect(q.a.contextOnly.get(procByPid(m, 7310).id)?.map(f => f.ruleId)).toEqual(['odd-location-exec']);
  });
  test('hostname, run long after the burst, is context only', () => {
    expect(row(7403)).toBeUndefined();
    expect(q.a.contextOnly.get(procByPid(m, 7403).id)?.map(f => f.ruleId)).toEqual(['recon']);
  });
  test('git status runs and the plain /tmp steps raise nothing at all', () => {
    for (const pid of [7300, 7301, 7302, 7007, 7008, 7002]) {
      const id = procByPid(m, pid).id;
      expect(q.a.findings.has(id), String(pid)).toBe(false);
      expect(q.a.contextOnly.has(id), String(pid)).toBe(false);
    }
  });
});

describe('recon bursts', () => {
  test('three different tools under one parent within 60 s are all queued and marked', () => {
    for (const pid of [7400, 7401, 7402]) {
      expect(rowItem(pid), String(pid)).toMatchObject({ reconBurst: true, inFlaggedChain: false, severity: 'low' });
      expect(ruleIds(pid)).toEqual(['recon']);
    }
    expect(q.items.filter(x => x.item.reconBurst)).toHaveLength(3);
  });
  test('the burst rows carry the tools\' own techniques', () => {
    expect(item(LAB, x => x.p?.pid === 7400)!.findings[0]!.mitre).toEqual(['T1082']);
    expect(item(LAB, x => x.p?.pid === 7005)!.findings[0]!.mitre).toEqual(['T1033']);
  });
});
