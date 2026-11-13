import { openDB, type DBSchema, type IDBPDatabase } from 'idb';
import type { Severity } from '../rules/rules';

export type Status = 'unreviewed' | 'confirmed' | 'benign';
export interface Session { id: string; name: string; created: string; updated: string }
export interface CaptureRec { sessionId: string; fingerprint: string; fileName: string; size: number;
  events: number; processes: number; flagged: number; added: string }
export interface VerdictSnapshot { name: string; path: string | null; args: string[] | null;
  ruleIds: string[]; severity: Severity | null; startTime: string | null }
/** `procKey` is the process's ProcId (its first token). */
export interface Verdict { sessionId: string; fingerprint: string; procKey: string; status: Status;
  note: string; updated: string; snapshot: VerdictSnapshot }
export interface RoutineRec { sessionId: string; programKey: string; label: string; added: string }

export interface Store {
  listSessions(): Promise<Session[]>;
  createSession(name: string): Promise<Session>;
  renameSession(id: string, name: string): Promise<void>;
  /** Bumps `updated` to now (a capture was added or a verdict changed). No-op for an unknown id. */
  touchSession(id: string): Promise<void>;
  deleteSession(id: string): Promise<void>;
  /** Same (session, fingerprint) → 'updated': size and counts are refreshed, `added` is kept. */
  upsertCapture(rec: CaptureRec): Promise<'added' | 'updated'>;
  listCaptures(sessionId: string): Promise<CaptureRec[]>;
  setVerdict(v: Verdict): Promise<void>;
  listVerdicts(sessionId: string, fingerprint?: string): Promise<Verdict[]>;
  addRoutine(r: RoutineRec): Promise<void>;
  removeRoutine(sessionId: string, programKey: string): Promise<void>;
  listRoutine(sessionId: string): Promise<RoutineRec[]>;
  /** Creates a session named `name` and stores all rows under it in ONE transaction: all or nothing. */
  importAll(name: string, captures: CaptureRec[], verdicts: Verdict[], routine: RoutineRec[]): Promise<Session>;
}

interface Schema extends DBSchema {
  sessions: { key: string; value: Session };
  captures: { key: [string, string]; value: CaptureRec };
  verdicts: { key: [string, string, string]; value: Verdict };
  routine: { key: [string, string]; value: RoutineRec };
}

const DB_NAME = 'gameleira';

/** Every composite key beginning with `prefix`: arrays sort above any string, so `[...prefix, []]` closes the range. */
function prefixRange(...prefix: string[]): IDBKeyRange {
  return IDBKeyRange.bound(prefix, [...prefix, []]);
}

function newId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  return `s-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

const now = (): string => new Date().toISOString();

/** `name` exists for test isolation; the app uses the default. */
export async function openStore(name: string = DB_NAME): Promise<Store> {
  let db: IDBPDatabase<Schema>;
  /** False once the browser took the connection away (another tab upgrading the database, or the browser closing it). */
  let live = true;
  const connect = (version?: number): Promise<IDBPDatabase<Schema>> => openDB<Schema>(name, version, {
    upgrade(d) {
      d.createObjectStore('sessions', { keyPath: 'id' });
      d.createObjectStore('captures', { keyPath: ['sessionId', 'fingerprint'] });
      d.createObjectStore('verdicts', { keyPath: ['sessionId', 'fingerprint', 'procKey'] });
      d.createObjectStore('routine', { keyPath: ['sessionId', 'programKey'] });
    },
    // Another tab wants a newer version: close, or its upgrade waits for this tab for ever. The next operation reopens.
    blocking(_cur, _next, event) { live = false; (event.target as IDBDatabase).close(); },
    // The browser dropped the connection (storage cleared, profile closed…). The next operation reopens.
    terminated() { live = false; },
    // Our open is waiting on an older connection of ours or of another tab; nothing to do but wait.
    blocked() { /* the open resolves once the other connection closes */ },
  });
  db = await connect(1);
  let reopening: Promise<void> | null = null;
  /** The live connection, reopened (at whatever version exists now) when it was taken away. */
  const conn = async (): Promise<IDBPDatabase<Schema>> => {
    if (!live) {
      reopening ??= connect().then(d => { db = d; live = true; }).finally(() => { reopening = null; });
      await reopening;
    }
    return db;
  };

  return {
    async listSessions() {
      const all = await (await conn()).getAll('sessions');
      return all.sort((a, b) => b.updated.localeCompare(a.updated) || a.id.localeCompare(b.id));
    },
    async createSession(sessionName) {
      const t = now();
      const s: Session = { id: newId(), name: sessionName, created: t, updated: t };
      await (await conn()).put('sessions', s);
      return s;
    },
    async renameSession(id, sessionName) {
      const tx = (await conn()).transaction('sessions', 'readwrite');
      const s = await tx.store.get(id);
      if (s) await tx.store.put({ ...s, name: sessionName, updated: now() });
      await tx.done;
    },
    async touchSession(id) {
      const tx = (await conn()).transaction('sessions', 'readwrite');
      const s = await tx.store.get(id);
      if (s) await tx.store.put({ ...s, updated: now() });
      await tx.done;
    },
    async deleteSession(id) {
      const tx = (await conn()).transaction(['sessions', 'captures', 'verdicts', 'routine'], 'readwrite');
      await Promise.all([
        tx.objectStore('sessions').delete(id),
        tx.objectStore('captures').delete(prefixRange(id)),
        tx.objectStore('verdicts').delete(prefixRange(id)),
        tx.objectStore('routine').delete(prefixRange(id)),
        tx.done,
      ]);
    },
    async upsertCapture(rec) {
      const tx = (await conn()).transaction('captures', 'readwrite');
      const prev = await tx.store.get([rec.sessionId, rec.fingerprint]);
      await tx.store.put(prev ? { ...rec, added: prev.added } : rec);
      await tx.done;
      return prev ? 'updated' : 'added';
    },
    listCaptures: async sessionId => (await conn()).getAll('captures', prefixRange(sessionId)),
    async setVerdict(v) {
      await (await conn()).put('verdicts', v);
    },
    listVerdicts: async (sessionId, fingerprint) =>
      (await conn()).getAll('verdicts', fingerprint === undefined ? prefixRange(sessionId) : prefixRange(sessionId, fingerprint)),
    async addRoutine(r) {
      await (await conn()).put('routine', r);
    },
    async removeRoutine(sessionId, programKey) {
      await (await conn()).delete('routine', [sessionId, programKey]);
    },
    listRoutine: async sessionId => (await conn()).getAll('routine', prefixRange(sessionId)),
    async importAll(sessionName, captures, verdicts, routine) {
      const t = now();
      const s: Session = { id: newId(), name: sessionName, created: t, updated: t };
      const tx = (await conn()).transaction(['sessions', 'captures', 'verdicts', 'routine'], 'readwrite');
      const pending: Promise<unknown>[] = [tx.done];
      try {
        // put() can throw synchronously (invalid key) after earlier puts were queued: collect every promise
        // as we go so all of them can be settled once the transaction is aborted.
        pending.push(tx.objectStore('sessions').put(s));
        for (const c of captures) pending.push(tx.objectStore('captures').put({ ...c, sessionId: s.id }));
        for (const v of verdicts) pending.push(tx.objectStore('verdicts').put({ ...v, sessionId: s.id }));
        for (const r of routine) pending.push(tx.objectStore('routine').put({ ...r, sessionId: s.id }));
        await Promise.all(pending);
      } catch (e) {
        try { tx.abort(); } catch { /* already finished or aborted */ }
        await Promise.allSettled(pending);
        throw e;
      }
      return s;
    },
  };
}
