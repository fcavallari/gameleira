import type { LoadedCapture } from '../ingest/load';
import { ancestry, displayName } from '../model/relations';
import type { FileOp, Image } from '../model/types';
import type { CaptureRec, RoutineRec, Session, Store, Verdict, VerdictSnapshot } from './store';

export type ExportImage = Omit<Image, 'env'> & { env?: string[] | null };
/** The format name an export carries; the app was called eslogger viewer before it was Gameleira, and its files still import. */
const FORMAT = 'gameleira-session';
const LEGACY_FORMAT = 'eslogger-viewer-session';

export interface ProcessDetail extends VerdictSnapshot {
  images: ExportImage[]; fileOps: FileOp[]; ancestry: string[];
}
export interface SessionExport {
  format: typeof FORMAT; version: 1;
  session: Session; captures: CaptureRec[]; verdicts: Verdict[]; routine: RoutineRec[];
  /** Keyed `${fingerprint}|${procKey}`; only confirmed processes whose capture is loaded. */
  details: Record<string, ProcessDetail>;
}

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** What replaces each argument after argv[0] when the export is asked to redact command lines. */
export const REDACTED = '[redacted]';
const redactArgv = (args: string[] | null): string[] | null => (args === null ? null : args.map((a, i) => (i === 0 ? a : REDACTED)));

/**
 * `includeEnv`: environment variables of each image. `redactArgs`: every argument after argv[0] becomes "[redacted]" in
 * verdict snapshots and process details. Command lines are exported otherwise, and they can hold secrets (a password
 * passed to `dscl -authonly`, `openssl -pass pass:…`). Only the export changes: the stored verdicts keep their arguments.
 */
export async function exportSession(
  store: Store, sessionId: string, opts: { includeEnv: boolean; redactArgs?: boolean }, loaded?: Map<string, LoadedCapture>,
): Promise<SessionExport> {
  const session = (await store.listSessions()).find(s => s.id === sessionId);
  if (!session) throw new Error(`no such session: ${sessionId}`);
  const captures = (await store.listCaptures(sessionId)).sort((a, b) => cmp(a.fingerprint, b.fingerprint));
  const redact = (sn: VerdictSnapshot): VerdictSnapshot => (opts.redactArgs ? { ...sn, args: redactArgv(sn.args) } : sn);
  const verdicts = (await store.listVerdicts(sessionId))
    .sort((a, b) => cmp(a.fingerprint, b.fingerprint) || cmp(a.procKey, b.procKey))
    .map(v => (opts.redactArgs ? { ...v, snapshot: redact(v.snapshot) } : v));
  const routine = (await store.listRoutine(sessionId)).sort((a, b) => cmp(a.programKey, b.programKey));

  const details: Record<string, ProcessDetail> = {};
  for (const v of verdicts) {
    if (v.status !== 'confirmed') continue;
    const cap = loaded?.get(v.fingerprint);
    const p = cap?.model.processes.get(v.procKey);
    if (!cap || !p) continue;
    details[`${v.fingerprint}|${v.procKey}`] = {
      ...v.snapshot,
      images: p.images.map(({ env, args, ...rest }): ExportImage =>
        ({ ...rest, args: opts.redactArgs ? redactArgv(args) : args, ...(opts.includeEnv ? { env } : {}) })),
      fileOps: p.fileOps,
      ancestry: ancestry(cap.model, p.id, 'original').map(id => displayName(cap.model, id)),
    };
  }
  return { format: FORMAT, version: 1, session, captures, verdicts, routine, details };
}

const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);

const STATUSES: readonly string[] = ['unreviewed', 'confirmed', 'benign'];
const isStrings = (x: unknown): x is string[] => Array.isArray(x) && x.every(e => typeof e === 'string');
const SEVERITIES: readonly unknown[] = [null, 'high', 'med', 'low'];
const nullableString = (x: unknown): boolean => x === null || typeof x === 'string';
const isCount = (x: unknown): boolean => typeof x === 'number' && Number.isFinite(x);

/** The screens read these fields without checking: a hand-edited file must not get past here with them wrong. */
const validVerdict = (r: Record<string, unknown>): boolean => {
  const sn = r.snapshot;
  return STATUSES.includes(r.status as string) && isObj(sn) && typeof sn.name === 'string' && isStrings(sn.ruleIds) &&
    nullableString(sn.path) && (sn.args === null || isStrings(sn.args)) &&
    SEVERITIES.includes(sn.severity) && nullableString(sn.startTime);
};

const validCapture = (r: Record<string, unknown>): boolean =>
  ['size', 'events', 'processes', 'flagged'].every(k => isCount(r[k]));

function rows(data: Record<string, unknown>, field: string, keys: string[], extra?: (r: Record<string, unknown>) => boolean): void {
  const list = data[field];
  if (!Array.isArray(list)) throw new Error(`invalid session export: "${field}" must be an array`);
  list.forEach((r, i) => {
    const ok = isObj(r) && keys.every(k => typeof r[k] === 'string') && (extra?.(r) ?? true);
    if (!ok) throw new Error(`invalid session export: bad row ${i} in "${field}"`);
  });
}

/** Throws a clear error unless `data` is a complete, readable session export. Writes nothing. */
function validateExport(data: unknown): asserts data is SessionExport {
  if (!isObj(data) || (data.format !== FORMAT && data.format !== LEGACY_FORMAT)) throw new Error('not a Gameleira session export');
  if (data.version !== 1) throw new Error(`unsupported session export version ${String(data.version)} (this build reads version 1)`);
  if (!isObj(data.session) || typeof data.session.name !== 'string') throw new Error('invalid session export: "session" must have a name');
  rows(data, 'captures', ['fingerprint', 'fileName', 'added'], validCapture);
  rows(data, 'verdicts', ['fingerprint', 'procKey', 'status', 'note', 'updated'], validVerdict);
  rows(data, 'routine', ['programKey', 'label', 'added']);
}

/** Always creates a new session; the export's own id is never reused. Details are informational and not stored.
 *  The whole payload is validated first and written in one transaction, so a bad file imports nothing. */
export async function importSession(store: Store, data: SessionExport): Promise<Session> {
  validateExport(data);
  return store.importAll(`${data.session.name} (imported)`, data.captures, data.verdicts, data.routine);
}
