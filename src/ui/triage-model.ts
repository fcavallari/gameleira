import type { LoadedCapture } from '../ingest/load';
import { displayName } from '../model/relations';
import type { Process } from '../model/types';
import { basename } from '../model/util';
import type { QueueItem } from '../rules/engine';
import type { Severity } from '../rules/rules';
import type { Status } from '../session/store';

export interface TriageFilters {
  status: 'all' | Status;
  sev: Set<Severity>;
  search: string;
  showHidden: boolean;
}
export const DEFAULT_FILTERS: TriageFilters = { status: 'all', sev: new Set<Severity>(['high', 'med', 'low']), search: '', showHidden: false };

/** Verdicts are keyed by the process id; a persistence-only item has none, so it uses its queue key (`i:<id>`). */
export const verdictKey = (q: QueueItem): string => q.procId ?? q.key;

/** Name shown for a queue item: the process name, or `persistence: <plist>` for a persistence-only item. */
export function itemName(cap: LoadedCapture, q: QueueItem): string {
  if (q.procId !== null) return displayName(cap.model, q.procId);
  const item = cap.model.persistence.find(i => i.id === q.persistenceId);
  return `persistence: ${basename(item?.plistPath ?? null) || q.persistenceId || 'launch item'}`;
}

/** Arguments of the first exec'd image, without argv[0] (the name already shown). */
export function firstArgs(p: Process): string {
  const img = p.images.find(i => i.args !== null && !i.inherited) ?? p.images.find(i => i.args !== null);
  return img?.args ? img.args.slice(1).join(' ') : '';
}

/** What the row shows after the name: args, or the launched program for a persistence item. */
export function itemArgs(cap: LoadedCapture, q: QueueItem): string {
  if (q.procId !== null) {
    const p = cap.model.processes.get(q.procId);
    const args = p ? firstArgs(p) : '';
    return args || (q.findings[0]?.title ?? '');
  }
  const item = cap.model.persistence.find(i => i.id === q.persistenceId);
  return item?.executablePath ?? item?.appPath ?? '';
}

/** Lower-cased text the search box matches against: name, paths, args, signing and team IDs. */
export function haystack(cap: LoadedCapture, q: QueueItem): string {
  const parts: (string | null)[] = [itemName(cap, q)];
  if (q.procId !== null) {
    const p = cap.model.processes.get(q.procId);
    for (const i of p?.images ?? []) parts.push(i.path, i.signingId, i.teamId, i.script, ...(i.args ?? []));
  } else {
    const item = cap.model.persistence.find(i => i.id === q.persistenceId);
    parts.push(item?.plistPath ?? null, item?.executablePath ?? null, item?.appPath ?? null);
  }
  return parts.filter(Boolean).join('\n').toLowerCase();
}

/** Technique names for the MITRE IDs the rules cite, so the learner sees a word next to the number. */
export const MITRE_NAMES: Record<string, string> = {
  'T1033': 'System Owner/User Discovery',
  'T1056': 'Input Capture',
  'T1056.002': 'GUI Input Capture',
  'T1059.004': 'Unix Shell',
  'T1082': 'System Information Discovery',
  'T1105': 'Ingress Tool Transfer',
  'T1110': 'Brute Force',
  'T1140': 'Deobfuscate/Decode Files or Information',
  'T1204.002': 'Malicious File',
  'T1543.001': 'Launch Agent',
  'T1543.004': 'Launch Daemon',
  'T1553.001': 'Gatekeeper Bypass',
  'T1553.002': 'Code Signing',
  'T1560.001': 'Archive via Utility',
  'T1564': 'Hide Artifacts',
  'T1569.001': 'Launchctl',
};

/** `2026-11-12T16:43:52.123456789Z` → `2026-11-12 16:43:52.123Z`. */
export const fmtTime = (t: string | null): string =>
  t ? t.replace('T', ' ').replace(/(\.\d{3})\d*Z$/, '$1Z') : 'n/a';

/** Command line for display: elements with spaces (or empty ones) are quoted so the boundaries stay visible. */
export const fmtArgs = (args: string[]): string =>
  args.map(a => (a === '' || /\s/.test(a) ? `"${a}"` : a)).join(' ');

/** True when programKey() would be the identity-less `-|-|-`: marking it routine would hide everything. */
export const NO_IDENTITY = '-|-|-';
