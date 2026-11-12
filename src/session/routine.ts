import type { CaptureModel, Image } from '../model/types';
import { basename, latestImage } from '../model/util';
import type { Analysis, QueueItem } from '../rules/engine';
import { SHELLS } from '../rules/rules';

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

/** Drops process items whose latest image is a routine program. Persistence items always stay. */
export function applyRoutine(a: Analysis, m: CaptureModel, keys: Set<string>): { queue: QueueItem[]; hiddenCount: number } {
  const queue: QueueItem[] = [];
  let hiddenCount = 0;
  for (const q of a.queue) {
    const p = q.kind === 'process' && q.procId !== null ? m.processes.get(q.procId) : undefined;
    const img = p ? latestImage(p) : undefined;
    if (img && keys.has(programKey(img))) hiddenCount++;
    else queue.push(q);
  }
  return { queue, hiddenCount };
}
