import type { LoadedCapture } from '../ingest/load';
import { displayName } from '../model/relations';
import type { CaptureStats, Process } from '../model/types';
import { basename } from '../model/util';
import type { QueueItem } from '../rules/engine';
import type { Severity } from '../rules/rules';
import type { Status } from '../session/store';

export interface TriageFilters {
  status: 'all' | Status;
  sev: Set<Severity>;
  search: string;
  showHidden: boolean;
  /** Only rows queued because they sit under, or in, a flagged chain. */
  chainOnly: boolean;
}
export const DEFAULT_FILTERS: TriageFilters = { status: 'all', sev: new Set<Severity>(['high', 'med', 'low']), search: '', showHidden: false, chainOnly: false };

/** Verdicts are keyed by the process id; a persistence-only item has none, so it uses its queue key (`i:<id>`). */
export const verdictKey = (q: QueueItem): string => q.procId ?? q.key;

/** Pressing the verdict a queue item already has takes it back to unreviewed (the note is kept). */
export const toggleStatus = (current: Status, pressed: 'confirmed' | 'benign'): Status => (current === pressed ? 'unreviewed' : pressed);

/** The Triage shortcuts: the key handler and the legend in the empty detail pane both read this table. */
export type TriageAction = 'next' | 'prev' | 'confirm' | 'benign' | 'note' | 'tree';
export const TRIAGE_KEYS: { key: string; also?: string; action: TriageAction; what: string }[] = [
  { key: 'j', also: 'ArrowDown', action: 'next', what: 'next row' },
  { key: 'k', also: 'ArrowUp', action: 'prev', what: 'previous row' },
  { key: 'c', action: 'confirm', what: 'confirm suspicious' },
  { key: 'b', action: 'benign', what: 'mark benign' },
  { key: 'n', action: 'note', what: 'write a note' },
  { key: 't', action: 'tree', what: 'show in the tree' },
];
export const triageAction = (key: string): TriageAction | undefined => TRIAGE_KEYS.find(k => k.key === key || k.also === key)?.action;

/** Name shown for a queue item: the process name, or `persistence: <plist>` for a persistence-only item. */
export function itemName(cap: LoadedCapture, q: QueueItem): string {
  if (q.procId !== null) return displayName(cap.model, q.procId);
  const item = cap.model.persistence.find(i => i.id === q.persistenceId);
  return `persistence: ${basename(item?.plistPath ?? null) || q.persistenceId || 'launch item'}`;
}

/**
 * What a row shows after its name (the latest image's program): the arguments of the latest exec that was captured,
 * without argv[0]. When the latest image itself has no captured args (its exec was not seen), the args come from an
 * earlier image and are prefixed with that image's program, so they are not read as the arguments of the name beside them.
 */
export function rowArgs(p: Process): string {
  let i = p.images.length - 1;
  while (i >= 0 && p.images[i]!.args === null) i--;
  const img = p.images[i];
  if (!img?.args) return '';
  const args = img.args.slice(1).join(' ');
  if (i === p.images.length - 1) return args;
  return [basename(img.path), args].filter(Boolean).join(' ');
}

/** What the row shows after the name: args, or the launched program for a persistence item. */
export function itemArgs(cap: LoadedCapture, q: QueueItem): string {
  if (q.procId !== null) {
    const p = cap.model.processes.get(q.procId);
    const args = p ? rowArgs(p) : '';
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

/** `2026-11-12T16:43:52.123456789Z` → `2026-11-12 16:43:52.123Z`. */
export const fmtTime = (t: string | null): string =>
  t ? t.replace('T', ' ').replace(/(\.\d{3})\d*Z$/, '$1Z') : 'n/a';

/** Command line for display: elements with spaces (or empty ones) are quoted so the boundaries stay visible. */
export const fmtArgs = (args: string[]): string =>
  args.map(a => (a === '' || /\s/.test(a) ? `"${a}"` : a)).join(' ');

/** The first schema version with the exec stdin data the `shell-from-pipe` rule needs. */
export const MODERN_SCHEMA = 11;
const MAX_OTHER_SHOWN = 5;

/**
 * What the loader skipped or could not use, so nothing is dropped silently: unreadable lines, event types the viewer
 * does not model, and the eslogger schema version(s). `line` is null when there is nothing to say.
 */
export function captureInfo(stats: CaptureStats): { line: string | null; older: boolean } {
  const parts: string[] = [];
  if (stats.badLines > 0) parts.push(`${stats.badLines.toLocaleString('en-US')} unreadable ${stats.badLines === 1 ? 'line' : 'lines'}`);
  const other = Object.entries(stats.otherEvents).sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
  if (other.length > 0) {
    const shown = other.slice(0, MAX_OTHER_SHOWN).map(([t, n]) => `${t} ×${n.toLocaleString('en-US')}`);
    if (other.length > MAX_OTHER_SHOWN) shown.push(`${other.length - MAX_OTHER_SHOWN} more`);
    parts.push(`other events: ${shown.join(', ')}`);
  }
  const versions = stats.versions.filter(v => v > 0);
  if (versions.length > 0) parts.push(`schema ${versions.map(v => `v${v}`).join(', ')}`);
  return { line: parts.length > 0 ? parts.join(' · ') : null, older: versions.length > 0 && versions.every(v => v < MODERN_SCHEMA) };
}
