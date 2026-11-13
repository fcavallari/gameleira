import type { CaptureModel, Image } from '../model/types';
import { basename, latestImage } from '../model/util';
import type { Analysis, QueueItem } from '../rules/engine';
import { SHELLS } from '../rules/rules';

/** Programs with no signing id, team id or path cannot be told apart: a routine mark would hide everything. */
export const NO_IDENTITY = '-|-|-';

export function programKey(img: Image): string {
  return `${img.signingId ?? '-'}|${img.teamId ?? '-'}|${img.path ?? '-'}`;
}

const RISKY_NAMES = new Set([
  ...[...SHELLS].map(basename),
  'osascript', 'curl', 'wget', 'launchctl', 'python3', 'perl', 'ruby', 'osacompile', 'open',
]);

/** Programs an attacker also uses: marking one routine hides every run of it, so the UI warns first. */
export function isRiskyRoutine(img: Image): boolean {
  return img.path !== null && (SHELLS.has(img.path) || RISKY_NAMES.has(basename(img.path)));
}

const PERSISTENCE_RULES = new Set(['persistence-item', 'persistence-plist']);

/**
 * Why a routine mark must not hide this row, or null when it may. A high finding or a persistence finding is the
 * kind of thing a learner must not lose behind a mark made for another reason (marking `cat` routine must not
 * hide the launch agent that `cat` wrote).
 */
export function keepReason(q: QueueItem): string | null {
  const high = q.findings.some(f => f.severity === 'high');
  const persistence = q.findings.some(f => PERSISTENCE_RULES.has(f.ruleId));
  if (high && persistence) return 'high severity, persistence';
  return high ? 'high severity' : persistence ? 'persistence' : null;
}

export interface RoutineResult {
  queue: QueueItem[];
  /** Rows a routine mark removed. */
  hiddenCount: number;
  /** Queue key → why the row stayed although its program is marked routine. */
  kept: Map<string, string>;
}

/**
 * Drops process items whose latest image is a routine program, except rows with a high or persistence finding: those
 * stay, and `kept` says why. Persistence-only items have no process and always stay.
 */
export function applyRoutine(a: Analysis, m: CaptureModel, keys: Set<string>): RoutineResult {
  const queue: QueueItem[] = [];
  const kept = new Map<string, string>();
  let hiddenCount = 0;
  for (const q of a.queue) {
    const p = q.kind === 'process' && q.procId !== null ? m.processes.get(q.procId) : undefined;
    const img = p ? latestImage(p) : undefined;
    if (img && keys.has(programKey(img))) {
      const why = keepReason(q);
      if (why === null) { hiddenCount++; continue; }
      kept.set(q.key, why);
    }
    queue.push(q);
  }
  return { queue, hiddenCount, kept };
}

/** What marking one program routine does to a capture's queue: rows hidden, and high or persistence rows that stay. */
export function routineImpact(a: Analysis, m: CaptureModel, key: string): { hidden: number; kept: number } {
  const r = applyRoutine(a, m, new Set([key]));
  return { hidden: r.hiddenCount, kept: r.kept.size };
}
