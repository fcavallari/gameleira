import { describe, expect, test } from 'vitest';
import { basename } from '../src/model/util';
import { analyze } from '../src/rules/engine';
import { RULES } from '../src/rules/rules';
import type { FixtureName } from './fixtures';
import { count, item, model, queued, rules, sev } from './helpers';

describe('es-lab must flag', () => {
  test('fake prompt high', () => expect(sev('es-lab.jsonl', x => x.p?.pid === 40753)).toBe('high'));
  test('launchctl bootstrap high', () => expect(sev('es-lab.jsonl', x => x.p?.pid === 42279)).toBe('high'));
  test('studyguide persistence on cat, high', () => {
    const it = item('es-lab.jsonl', x => x.p?.pid === 41865)!;
    expect(it.findings.map(f => f.ruleId)).toContain('persistence-item');
    expect(it.severity).toBe('high');
  });
  test('bash from pipe med', () => expect(rules('es-lab.jsonl', x => x.p?.pid === 40489)).toContain('shell-from-pipe'));
  test('whoami queued in flagged chain', () => expect(item('es-lab.jsonl', x => x.p?.pid === 40490)!.inFlaggedChain).toBe(true));
  test('curl download', () => expect(rules('es-lab.jsonl', x => x.p?.pid === 39838)).toContain('download'));
  test('ditto staging', () => expect(rules('es-lab.jsonl', x => x.p?.pid === 41080)).toContain('archive-staging'));
  test('sleep 90 orphaned', () => expect(rules('es-lab.jsonl', x => x.p?.pid === 41282)).toContain('orphaned'));
  test('GoogleUpdater item med, standalone', () => {
    const it = item('es-lab.jsonl', x => x.item.kind === 'persistence')!;
    expect(it.severity).toBe('med');
  });
});

test('es-lab must not queue routine noise', () => {
  const names = queued('es-lab.jsonl').items.map(x => basename(x.paths.at(-1) ?? null));
  for (const n of ['ps', 'git', 'docker-tools', 'mdworker_shared']) expect(names).not.toContain(n);
});

test('es-lab queue stays small', () => expect(queued('es-lab.jsonl').items.length).toBeLessThanOrEqual(15));

describe('atomic stealer', () => {
  test('two fake prompts', () => expect(count('atomic_stealer.json', x => basename(x.paths.at(-1) ?? null) === 'osascript' && x.item.findings.some(f => f.ruleId === 'fake-prompt'))).toBe(2));
  test('dscl authonly high', () => expect(sev('atomic_stealer.json', x => x.args.includes('-authonly'))).toBe('high'));
  test('translocated ad-hoc app', () => expect(rules('atomic_stealer.json', x => x.paths.some(p => p?.includes('AppTranslocation')))).toContain('odd-location-exec')); // severity high: ad-hoc + odd location
  test('recon burst queued', () => expect(count('atomic_stealer.json', x => x.item.findings.every(f => f.ruleId === 'recon'))).toBeGreaterThanOrEqual(3));
});

describe('recon gating', () => {
  const reconOnly = RULES.filter(r => r.id === 'recon');
  test('a burst of distinct tools under one parent queues without a flagged chain', () => {
    const a = analyze(model('atomic_stealer.json'), reconOnly);
    expect(a.queue.length).toBeGreaterThanOrEqual(3);
    expect(a.queue.every(q => !q.inFlaggedChain)).toBe(true);
  });
  test('background ps runs stay context-only', () => {
    const a = analyze(model('es-lab.jsonl'), reconOnly);
    expect(a.queue).toHaveLength(0);
    expect(a.contextOnly.size).toBeGreaterThanOrEqual(28);
  });
});

describe('rustbucket', () => {
  test('applet shell curl', () => expect(rules('rustbucket.json', x => x.args.includes('curl -o /users/shared/1.zip'))).toContain('shell-under-app'));
  test('Internal PDF Viewer', () => expect(sev('rustbucket.json', x => x.paths.some(p => p?.startsWith('/Users/Shared/Internal PDF Viewer.app')))).toBe('high'));
});

describe('shlayer', () => {
  test('payload in /tmp high', () => expect(sev('shlayer.json', x => x.paths.includes('/private/tmp/FaF74ncqmHBe/8CMt7kQ2jM3'))).toBe('high'));
  test('quarantine strip', () => expect(count('shlayer.json', x => x.item.findings.some(f => f.ruleId === 'quarantine-strip'))).toBeGreaterThanOrEqual(1));
  test('curl downloads', () => expect(count('shlayer.json', x => x.item.findings.some(f => f.ruleId === 'download'))).toBeGreaterThanOrEqual(1));
});

test('every finding explains itself', () => {
  for (const f of ['es-lab.jsonl', 'atomic_stealer.json', 'rustbucket.json', 'shlayer.json'] as const)
    for (const x of queued(f).items) for (const fd of x.item.findings) {
      expect(fd.explanation.length).toBeGreaterThan(20); expect(fd.mitre.length).toBeGreaterThan(0);
    }
});

test('queue size per fixture is recorded', () => {
  const sizes: Partial<Record<FixtureName, number>> = {};
  for (const f of ['es-lab.jsonl', 'atomic_stealer.json', 'rustbucket.json', 'shlayer.json'] as const)
    sizes[f] = queued(f).items.length;
  console.log('queue sizes', sizes);
  expect(sizes['es-lab.jsonl']).toBeLessThanOrEqual(15);
});
