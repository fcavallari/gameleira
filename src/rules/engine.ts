import { ancestry } from '../model/relations';
import type { CaptureModel, Image, ProcId, Process } from '../model/types';
import { basename } from '../model/util';
import { persistenceOwner, RULES, SEVERITY_RANK as RANK, type MatchResult, type Rule, type Severity } from './rules';

export interface Finding { ruleId: string; severity: Severity; title: string; explanation: string;
  mitre: string[]; evidence: string; imgIndex: number | null; persistenceId: string | null;
  /** A trait of the binary (unsigned, ad-hoc), not a technique: it cites no MITRE ID. */
  trait: boolean }
export interface QueueItem { key: string; kind: 'process' | 'persistence'; procId: ProcId | null;
  persistenceId: string | null; severity: Severity; findings: Finding[]; inFlaggedChain: boolean;
  /** One of 3 or more different recon tools run under the same parent within 60 s. */
  reconBurst: boolean;
  sortSeq: number }
export interface Analysis { queue: QueueItem[]; findings: Map<ProcId, Finding[]>;
  contextOnly: Map<ProcId, Finding[]> }

const CLUSTER_TOOLS = 3;
const CLUSTER_WINDOW_MS = 60_000;

/** `chainable`: the finding may mark its process as the source of a flagged chain. */
interface Hit { f: Finding; seq: number; time: string | null; chainable: boolean }

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
    imgIndex, persistenceId, trait: rule.trait ?? false,
  };
}

/** The latest image the process exec'd itself (not the copy a fork child starts with). */
function lastExecImage(p: Process): Image | undefined {
  for (let i = p.images.length - 1; i >= 0; i--) if (!p.images[i]!.inherited && p.images[i]!.path !== null) return p.images[i];
  return undefined;
}

export function analyze(m: CaptureModel, rules: Rule[] = RULES): Analysis {
  const imageRules = rules.filter(r => r.scope === 'image');
  const processRules = rules.filter(r => r.scope === 'process');
  const itemRules = rules.filter(r => r.scope === 'persistence');
  // Low-signal findings queue a process only in context: recon and adhoc always, odd-location-exec and keychain-access when low.
  const gate = new Map(rules.map(r => [r.id, r.gated]));
  const isGated = (f: Finding): boolean => {
    const g = gate.get(f.ruleId);
    return g === 'always' || (g === 'when-low' && f.severity === 'low');
  };

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
        if (res) add(p.id, { f: finding(rule, res, imgIndex, null), seq: img.seq, time: img.time, chainable: true });
      }
    });
    // Process-scoped rules run once per process, including one that forked and never exec'd; ghosts have no events.
    if (p.ghost) continue;
    const at = lastExecImage(p) ?? p.images[p.images.length - 1];
    for (const rule of processRules) {
      const res = rule.matchProcess?.(p, m);
      if (res) add(p.id, { f: finding(rule, res, null, null), seq: at?.seq ?? p.firstSeq, time: at?.time ?? p.startTime, chainable: true });
    }
  }
  const queue: QueueItem[] = [];
  for (const item of m.persistence) {
    const own: Hit[] = [];
    for (const rule of itemRules) {
      const res = rule.matchItem?.(item, m);
      if (res) own.push({ f: finding(rule, res, null, item.id), seq: item.seq, time: item.time, chainable: true });
    }
    if (own.length === 0) continue;
    const owner = persistenceOwner(m, item);
    if (owner !== null) {
      // Attached to the registering app or the instigator, only a high finding marks a chain: an ordinary app that
      // registers a login item would otherwise drag everything it ever launched into the queue.
      for (const h of own) add(owner.id, { ...h, chainable: owner.via === 'creator' || h.f.severity === 'high' });
    } else {
      queue.push({
        key: `i:${item.id}`, kind: 'persistence', procId: null, persistenceId: item.id,
        severity: maxSeverity(own), findings: ordered(own), inFlaggedChain: false, reconBurst: false, sortSeq: item.seq,
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
      if (h.f.severity !== 'low' && h.chainable) chainSources.add(id);
    }
  }
  const inChain = (id: ProcId): boolean => ancestry(m, id, 'original').some(a => chainSources.has(a));

  // 4. Recon bursts: per original parent, any 60 s window holding 3 or more different recon tools; all its members count.
  const reconByParent = new Map<ProcId, { id: ProcId; tool: string; ms: number }[]>();
  for (const [id, list] of hits) {
    const parent = m.processes.get(id)?.originalParent ?? null;
    if (parent === null) continue;
    for (const h of list) {
      const ms = timeMs(h.time);
      if (h.f.ruleId !== 'recon' || h.f.imgIndex === null || ms === null) continue;
      const tool = basename(m.processes.get(id)!.images[h.f.imgIndex]!.path);
      const group = reconByParent.get(parent);
      if (group) group.push({ id, tool, ms });
      else reconByParent.set(parent, [{ id, tool, ms }]);
    }
  }
  const burst = new Set<ProcId>();
  for (const g of reconByParent.values()) {
    g.sort((x, y) => x.ms - y.ms);
    const counts = new Map<string, number>();
    let j = -1;
    let marked = -1;
    for (let i = 0; i < g.length; i++) {
      // Window [i, j]: every hit within 60 s after g[i].
      while (j + 1 < g.length && g[j + 1]!.ms - g[i]!.ms <= CLUSTER_WINDOW_MS) {
        j++;
        counts.set(g[j]!.tool, (counts.get(g[j]!.tool) ?? 0) + 1);
      }
      if (counts.size >= CLUSTER_TOOLS) {
        for (let k = Math.max(i, marked + 1); k <= j; k++) burst.add(g[k]!.id);
        marked = j;
      }
      const left = counts.get(g[i]!.tool)! - 1;
      if (left === 0) counts.delete(g[i]!.tool);
      else counts.set(g[i]!.tool, left);
    }
  }

  // 5. Queue.
  const findings = new Map<ProcId, Finding[]>();
  const contextOnly = new Map<ProcId, Finding[]>();
  for (const [id, list] of hits) {
    const chain = inChain(id);
    if (!flagged.has(id) && !chain && !burst.has(id)) {
      contextOnly.set(id, ordered(list));
      continue;
    }
    const fs = ordered(list);
    findings.set(id, fs);
    queue.push({
      key: `p:${id}`, kind: 'process', procId: id, persistenceId: null,
      severity: maxSeverity(list), findings: fs, inFlaggedChain: chain, reconBurst: burst.has(id),
      sortSeq: Math.min(...list.map(h => h.seq)),
    });
  }
  queue.sort((a, b) => RANK[b.severity] - RANK[a.severity] || a.sortSeq - b.sortSeq);
  return { queue, findings, contextOnly };
}
