import { ancestry } from '../model/relations';
import type { CaptureModel, PersistenceItem, ProcId } from '../model/types';
import { basename, imageAt } from '../model/util';
import { RULES, SEVERITY_RANK as RANK, type MatchResult, type Rule, type Severity } from './rules';

export interface Finding { ruleId: string; severity: Severity; title: string; explanation: string;
  mitre: string[]; evidence: string; imgIndex: number | null; persistenceId: string | null }
export interface QueueItem { key: string; kind: 'process' | 'persistence'; procId: ProcId | null;
  persistenceId: string | null; severity: Severity; findings: Finding[]; inFlaggedChain: boolean;
  sortSeq: number }
export interface Analysis { queue: QueueItem[]; findings: Map<ProcId, Finding[]>;
  contextOnly: Map<ProcId, Finding[]> }

/** Low-signal rules that queue a process only in context (spec §6.3). */
const GATED = new Set(['recon', 'adhoc']);
/** Gated findings; a low `odd-location-exec` (team-signed, or a tooling dot-dir) is gated like `adhoc`. */
const isGated = (f: Finding): boolean =>
  GATED.has(f.ruleId) || (f.ruleId === 'odd-location-exec' && f.severity === 'low');
const CLUSTER_TOOLS = 3;
const CLUSTER_WINDOW_MS = 60_000;

interface Hit { f: Finding; seq: number; time: string | null }

function maxSeverity(hits: Hit[]): Severity {
  let best: Severity = 'low';
  for (const h of hits) if (RANK[h.f.severity] > RANK[best]) best = h.f.severity;
  return best;
}

function ordered(hits: Hit[]): Finding[] {
  return [...hits].sort((a, b) => RANK[b.f.severity] - RANK[a.f.severity] || a.seq - b.seq).map(h => h.f);
}

/** Milliseconds since the epoch; tolerates eslogger's nanosecond fractions. */
function timeMs(t: string | null): number | null {
  if (t === null) return null;
  const ms = Date.parse(t.replace(/(\.\d{3})\d+/, '$1'));
  return Number.isNaN(ms) ? null : ms;
}

function finding(rule: Rule, res: MatchResult, imgIndex: number | null, persistenceId: string | null): Finding {
  return {
    ruleId: rule.id, severity: res.severity ?? rule.severity, title: res.title ?? rule.title,
    explanation: res.explanation ?? rule.explanation, mitre: res.mitre ?? rule.mitre, evidence: res.evidence,
    imgIndex, persistenceId,
  };
}

/** Apple's own system daemons (smd, backgroundtaskmanagementd) instigate most launch item registrations. */
const SYSTEM_DIRS = /^\/(?:System|usr\/libexec|usr\/sbin)\//;

/**
 * The process a persistence finding attaches to: the app that registered the item, else the instigator (the XPC
 * caller), else the plist's creator; null means a standalone row. An app or instigator counts only when it is a
 * captured process with a known path and is not an Apple platform binary under /System, /usr/libexec or /usr/sbin:
 * pinning a finding on smd would point at the messenger, and a pathless ghost cannot be told apart from it.
 */
function persistenceOwner(m: CaptureModel, item: PersistenceItem): ProcId | null {
  for (const id of [item.app, item.instigator]) {
    const p = id !== null ? m.processes.get(id) : undefined;
    const img = p && !p.ghost ? imageAt(p, item.seq) : undefined;
    if (!img || img.path === null) continue;
    if (img.isPlatform && SYSTEM_DIRS.test(img.path)) continue;
    return p!.id;
  }
  return item.creator !== null && m.processes.has(item.creator) ? item.creator : null;
}

export function analyze(m: CaptureModel, rules: Rule[] = RULES): Analysis {
  const imageRules = rules.filter(r => r.scope === 'image');
  const itemRules = rules.filter(r => r.scope === 'persistence');

  // 1. Run the rules.
  const hits = new Map<ProcId, Hit[]>();
  const add = (id: ProcId, h: Hit) => {
    const list = hits.get(id);
    if (list) list.push(h);
    else hits.set(id, [h]);
  };
  for (const p of m.processes.values()) {
    p.images.forEach((img, imgIndex) => {
      if (img.inherited || img.path === null) return;
      for (const rule of imageRules) {
        const res = rule.match?.({ m, p, img, imgIndex });
        if (res) add(p.id, { f: finding(rule, res, imgIndex, null), seq: img.seq, time: img.time });
      }
    });
  }
  const queue: QueueItem[] = [];
  for (const item of m.persistence) {
    const own: Hit[] = [];
    for (const rule of itemRules) {
      const res = rule.matchItem?.(item, m);
      if (res) own.push({ f: finding(rule, res, null, item.id), seq: item.seq, time: item.time });
    }
    if (own.length === 0) continue;
    const owner = persistenceOwner(m, item);
    if (owner !== null) {
      for (const h of own) add(owner, h);
    } else {
      queue.push({
        key: `i:${item.id}`, kind: 'persistence', procId: null, persistenceId: item.id,
        severity: maxSeverity(own), findings: ordered(own), inFlaggedChain: false, sortSeq: item.seq,
      });
    }
  }

  // 2-3. Flagged processes, and the med/high ones that mark a chain.
  const flagged = new Set<ProcId>();
  const chainSources = new Set<ProcId>();
  for (const [id, list] of hits) {
    for (const h of list) {
      if (isGated(h.f)) continue;
      flagged.add(id);
      if (h.f.severity !== 'low') chainSources.add(id);
    }
  }
  const inChain = (id: ProcId): boolean => ancestry(m, id, 'original').some(a => chainSources.has(a));

  // 4. Recon clusters: recon hits per original parent, as (tool, time).
  const reconByParent = new Map<ProcId, { tool: string; ms: number }[]>();
  for (const [id, list] of hits) {
    const parent = m.processes.get(id)?.originalParent ?? null;
    if (parent === null) continue;
    for (const h of list) {
      const ms = timeMs(h.time);
      if (h.f.ruleId !== 'recon' || h.f.imgIndex === null || ms === null) continue;
      const tool = basename(m.processes.get(id)!.images[h.f.imgIndex]!.path);
      const group = reconByParent.get(parent);
      if (group) group.push({ tool, ms });
      else reconByParent.set(parent, [{ tool, ms }]);
    }
  }
  const inReconCluster = (id: ProcId, list: Hit[]): boolean => {
    const parent = m.processes.get(id)?.originalParent ?? null;
    const group = parent !== null ? reconByParent.get(parent) : undefined;
    if (!group) return false;
    for (const h of list) {
      const ms = timeMs(h.time);
      if (h.f.ruleId !== 'recon' || ms === null) continue;
      const tools = new Set(group.filter(g => Math.abs(g.ms - ms) <= CLUSTER_WINDOW_MS).map(g => g.tool));
      if (tools.size >= CLUSTER_TOOLS) return true;
    }
    return false;
  };

  // 5. Queue.
  const findings = new Map<ProcId, Finding[]>();
  const contextOnly = new Map<ProcId, Finding[]>();
  for (const [id, list] of hits) {
    const chain = inChain(id);
    if (!flagged.has(id) && !chain && !inReconCluster(id, list)) {
      contextOnly.set(id, ordered(list));
      continue;
    }
    const fs = ordered(list);
    findings.set(id, fs);
    queue.push({
      key: `p:${id}`, kind: 'process', procId: id, persistenceId: null,
      severity: maxSeverity(list), findings: fs, inFlaggedChain: chain,
      sortSeq: Math.min(...list.map(h => h.seq)),
    });
  }
  queue.sort((a, b) => RANK[b.severity] - RANK[a.severity] || a.sortSeq - b.sortSeq);
  return { queue, findings, contextOnly };
}
