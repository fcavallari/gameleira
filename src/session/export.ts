import type { LoadedCapture } from '../ingest/load';
import { ancestry, displayName } from '../model/relations';
import type { FileOp, Image } from '../model/types';
import type { CaptureRec, RoutineRec, Session, Store, Verdict, VerdictSnapshot } from './store';

export type ExportImage = Omit<Image, 'env'> & { env?: string[] | null };
export interface ProcessDetail extends VerdictSnapshot {
  images: ExportImage[]; fileOps: FileOp[]; ancestry: string[];
}
export interface SessionExport {
  format: 'eslogger-viewer-session'; version: 1;
  session: Session; captures: CaptureRec[]; verdicts: Verdict[]; routine: RoutineRec[];
  /** Keyed `${fingerprint}|${procKey}`; only confirmed processes whose capture is loaded. */
  details: Record<string, ProcessDetail>;
}

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

export async function exportSession(
  store: Store, sessionId: string, opts: { includeEnv: boolean }, loaded?: Map<string, LoadedCapture>,
): Promise<SessionExport> {
  const session = (await store.listSessions()).find(s => s.id === sessionId);
  if (!session) throw new Error(`no such session: ${sessionId}`);
  const captures = (await store.listCaptures(sessionId)).sort((a, b) => cmp(a.fingerprint, b.fingerprint));
  const verdicts = (await store.listVerdicts(sessionId))
    .sort((a, b) => cmp(a.fingerprint, b.fingerprint) || cmp(a.procKey, b.procKey));
  const routine = (await store.listRoutine(sessionId)).sort((a, b) => cmp(a.programKey, b.programKey));

  const details: Record<string, ProcessDetail> = {};
  for (const v of verdicts) {
    if (v.status !== 'confirmed') continue;
    const cap = loaded?.get(v.fingerprint);
    const p = cap?.model.processes.get(v.procKey);
    if (!cap || !p) continue;
    details[`${v.fingerprint}|${v.procKey}`] = {
      ...v.snapshot,
      images: p.images.map(({ env, ...rest }): ExportImage => (opts.includeEnv ? { ...rest, env } : rest)),
      fileOps: p.fileOps,
      ancestry: ancestry(cap.model, p.id, 'original').map(id => displayName(cap.model, id)),
    };
  }
  return { format: 'eslogger-viewer-session', version: 1, session, captures, verdicts, routine, details };
}

const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);

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
  if (!isObj(data) || data.format !== 'eslogger-viewer-session') throw new Error('not an eslogger-viewer session export');
  if (data.version !== 1) throw new Error(`unsupported session export version ${String(data.version)} (this build reads version 1)`);
  if (!isObj(data.session) || typeof data.session.name !== 'string') throw new Error('invalid session export: "session" must have a name');
  rows(data, 'captures', ['fingerprint']);
  rows(data, 'verdicts', ['fingerprint', 'procKey', 'status'], r => isObj(r.snapshot));
  rows(data, 'routine', ['programKey']);
}

/** Always creates a new session; the export's own id is never reused. Details are informational and not stored.
 *  The whole payload is validated first and written in one transaction, so a bad file imports nothing. */
export async function importSession(store: Store, data: SessionExport): Promise<Session> {
  validateExport(data);
  return store.importAll(`${data.session.name} (imported)`, data.captures, data.verdicts, data.routine);
}
