import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { runLoad } from '../ingest/run';
import type { LoadedCapture } from '../ingest/load';
import { displayName } from '../model/relations';
import type { Image, ProcId } from '../model/types';
import { basename, latestImage } from '../model/util';
import { SEVERITY_RANK, type Severity } from '../rules/rules';
import type { QueueItem } from '../rules/engine';
import { importSession } from '../session/export';
import { applyRoutine, isRiskyRoutine, programKey } from '../session/routine';
import type { CaptureRec, RoutineRec, Session, Status, Store, Verdict } from '../session/store';
import { fetchDevFixture } from './dev';

export type View = 'triage' | 'tree' | 'confirmed';
export interface Progress { fileName: string; bytes: number; total: number }

/** Programs with no signing id, team id or path cannot be told apart: a routine mark would hide everything. */
const NO_IDENTITY = '-|-|-';

export interface SessionCtx {
  store: Store;
  // start screen
  sessions: Session[];
  captureCounts: Map<string, number>;
  persisted: boolean | null;
  createSession(name: string): Promise<Session>;
  renameSession(id: string, name: string): Promise<void>;
  deleteSession(id: string): Promise<void>;
  /** Parses a session export file and imports it as a NEW session. Rejects with a readable message. */
  importSessionFile(file: File): Promise<Session>;
  // the open session
  session: Session | null;
  /** Every capture recorded for the session, loaded or not. */
  capRecs: CaptureRec[];
  /** Loaded captures by fingerprint. */
  captures: Map<string, LoadedCapture>;
  /** Fingerprint of the capture on screen (it may be recorded but not loaded). */
  active: string | null;
  /** The active capture when it is loaded. */
  capture: LoadedCapture | null;
  view: View;
  /** Verdicts of every capture in the session. */
  allVerdicts: Verdict[];
  /** procKey → verdict, for the active capture. */
  verdicts: Map<string, Verdict>;
  routine: RoutineRec[];
  routineKeys: Set<string>;
  /** The active capture's queue with routine programs removed, and how many were hidden. */
  triage: { queue: QueueItem[]; hiddenCount: number } | null;
  selected: ProcId | null;
  progress: Progress | null;
  loadError: string | null;
  openSession(id: string): Promise<void>;
  closeSession(): void;
  loadFiles(files: File[]): Promise<void>;
  setActive(fingerprint: string): void;
  setView(v: View): void;
  /** `note` omitted keeps the existing note. */
  setVerdict(procId: ProcId, status: Status, note?: string): Promise<void>;
  /** Resolves false when refused (no program identity) or declined at the risky-program prompt. */
  addRoutine(img: Image): Promise<boolean>;
  removeRoutine(key: string): Promise<void>;
  selectProc(id: ProcId | null): void;
  showInTree(id: ProcId): void;
}

export const SessionContext = createContext<SessionCtx | null>(null);

export function useSession(): SessionCtx {
  const c = useContext(SessionContext);
  if (!c) throw new Error('useSession must be used inside <SessionProvider>');
  return c;
}

const now = (): string => new Date().toISOString();
const message = (e: unknown): string => (e instanceof Error ? e.message : String(e));

export function SessionProvider({ store, children }: { store: Store; children: ReactNode }) {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [captureCounts, setCaptureCounts] = useState<Map<string, number>>(new Map());
  const [persisted, setPersisted] = useState<boolean | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [capRecs, setCapRecs] = useState<CaptureRec[]>([]);
  const [captures, setCaptures] = useState<Map<string, LoadedCapture>>(new Map());
  const [active, setActiveFp] = useState<string | null>(null);
  const [view, setView] = useState<View>('triage');
  const [allVerdicts, setAllVerdicts] = useState<Verdict[]>([]);
  const [routine, setRoutine] = useState<RoutineRec[]>([]);
  const [selected, setSelected] = useState<ProcId | null>(null);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  // Synchronous mirrors: async actions must see the session that is open NOW, not the one they were created in.
  const sessionId = useRef<string | null>(null);
  const openToken = useRef(0);
  const queue = useRef<Promise<void>>(Promise.resolve());
  const latest = useRef({ session, capRecs, captures, active, allVerdicts, routine });
  latest.current = { session, capRecs, captures, active, allVerdicts, routine };

  const refreshSessions = useCallback(async () => {
    const list = await store.listSessions();
    const counts = await Promise.all(list.map(async s => [s.id, (await store.listCaptures(s.id)).length] as const));
    setSessions(list);
    setCaptureCounts(new Map(counts));
  }, [store]);

  const refreshPersisted = useCallback(async () => {
    try { setPersisted((await navigator.storage?.persisted?.()) ?? false); } catch { setPersisted(false); }
  }, []);

  useEffect(() => { void refreshSessions(); void refreshPersisted(); }, [refreshSessions, refreshPersisted]);

  const createSession = useCallback(async (name: string) => {
    const first = (await store.listSessions()).length === 0;
    const s = await store.createSession(name);
    if (first) {
      // Spec §3: sessions must survive closing the tab, so ask the browser not to evict them. Failure is not fatal.
      void (async () => {
        try { await navigator.storage?.persist?.(); } catch { /* best-effort */ }
        await refreshPersisted();
      })();
    }
    await refreshSessions();
    return s;
  }, [store, refreshSessions, refreshPersisted]);

  const closeSession = useCallback(() => {
    sessionId.current = null;
    openToken.current++;
    setSession(null); setCapRecs([]); setCaptures(new Map()); setActiveFp(null); setView('triage');
    setAllVerdicts([]); setRoutine([]); setSelected(null); setProgress(null); setLoadError(null);
    void refreshSessions();
  }, [refreshSessions]);

  const openSession = useCallback(async (id: string) => {
    const token = ++openToken.current;
    const s = (await store.listSessions()).find(x => x.id === id);
    if (!s) return;
    const [recs, vs, rs] = await Promise.all([store.listCaptures(id), store.listVerdicts(id), store.listRoutine(id)]);
    if (token !== openToken.current) return;
    sessionId.current = id;
    setSession(s); setCapRecs(recs); setAllVerdicts(vs); setRoutine(rs);
    setCaptures(new Map()); setActiveFp(null); setView('triage'); setSelected(null); setProgress(null); setLoadError(null);
  }, [store]);

  const renameSession = useCallback(async (id: string, name: string) => {
    await store.renameSession(id, name);
    if (sessionId.current === id) setSession(s => (s ? { ...s, name } : s));
    await refreshSessions();
  }, [store, refreshSessions]);

  const deleteSession = useCallback(async (id: string) => {
    await store.deleteSession(id);
    if (sessionId.current === id) closeSession();
    else await refreshSessions();
  }, [store, closeSession, refreshSessions]);

  const importSessionFile = useCallback(async (file: File) => {
    let data: unknown;
    try { data = JSON.parse(await file.text()); } catch { throw new Error('Not a JSON file'); }
    const s = await importSession(store, data as Parameters<typeof importSession>[1]);
    await refreshSessions();
    return s;
  }, [store, refreshSessions]);

  const loadOne = useCallback(async (sid: string, file: File): Promise<void> => {
    setProgress({ fileName: file.name, bytes: 0, total: file.size });
    const cap = await runLoad(file, (bytes, total) => setProgress({ fileName: file.name, bytes, total }));
    const rec: CaptureRec = {
      sessionId: sid, fingerprint: cap.fingerprint, fileName: cap.fileName || file.name, size: cap.size,
      events: cap.model.stats.events, processes: cap.model.processes.size, flagged: cap.analysis.queue.length, added: now(),
    };
    // Same fingerprint as a stored capture: the store updates size and counts and keeps the verdicts' key.
    await store.upsertCapture(rec);
    await store.touchSession(sid);
    if (sessionId.current !== sid) return;   // the user left the session while it was loading
    const recs = await store.listCaptures(sid);
    if (sessionId.current !== sid) return;
    setCapRecs(recs);
    setCaptures(m => new Map(m).set(cap.fingerprint, cap));
    setActiveFp(cap.fingerprint);
    setSelected(null);
  }, [store]);

  const loadFiles = useCallback((files: File[]): Promise<void> => {
    const sid = sessionId.current;
    if (!sid || files.length === 0) return Promise.resolve();
    // Serialised: a drop while another file is still parsing waits its turn.
    const run = async () => {
      const errors: string[] = [];
      setLoadError(null);
      for (const file of files) {
        try { await loadOne(sid, file); }
        catch (e) { errors.push(files.length > 1 ? `${file.name}: ${message(e)}` : message(e)); }
      }
      if (sessionId.current === sid) { setProgress(null); setLoadError(errors.length ? errors.join('\n') : null); }
    };
    queue.current = queue.current.then(run);
    return queue.current;
  }, [loadOne]);

  // Dev only: `?load=es-lab.jsonl` opens a session named "dev" with that fixture.
  useEffect(() => {
    if (!import.meta.env.DEV) return;
    const name = new URLSearchParams(window.location.search).get('load');
    if (!name) return;
    void (async () => {
      const file = await fetchDevFixture(name);
      const s = (await store.listSessions()).find(x => x.name === 'dev') ?? await store.createSession('dev');
      await openSession(s.id);
      await loadFiles([file]);
    })().catch(e => { setLoadError(message(e)); });
  }, [store, openSession, loadFiles]);

  const setActive = useCallback((fp: string) => { setActiveFp(fp); setSelected(null); }, []);
  const selectProc = useCallback((id: ProcId | null) => { setSelected(id); }, []);
  const showInTree = useCallback((id: ProcId) => { setSelected(id); setView('tree'); }, []);

  const capture = active ? captures.get(active) ?? null : null;
  const verdicts = useMemo(
    () => new Map(allVerdicts.filter(v => v.fingerprint === active).map(v => [v.procKey, v])),
    [allVerdicts, active]);
  const routineKeys = useMemo(() => new Set(routine.map(r => r.programKey)), [routine]);
  const triage = useMemo(
    () => (capture ? applyRoutine(capture.analysis, capture.model, routineKeys) : null),
    [capture, routineKeys]);

  const setVerdict = useCallback(async (procId: ProcId, status: Status, note?: string) => {
    const { session: s, active: fp, captures: caps, allVerdicts: all } = latest.current;
    const cap = fp ? caps.get(fp) : undefined;
    const p = cap?.model.processes.get(procId);
    if (!s || !fp || !cap || !p) return;
    const img = latestImage(p);
    const findings = cap.analysis.findings.get(procId) ?? [];
    const severity = findings.reduce<Severity | null>(
      (best, f) => (best === null || SEVERITY_RANK[f.severity] > SEVERITY_RANK[best] ? f.severity : best), null);
    const prev = all.find(v => v.fingerprint === fp && v.procKey === procId);
    const v: Verdict = {
      sessionId: s.id, fingerprint: fp, procKey: procId, status, note: note ?? prev?.note ?? '', updated: now(),
      snapshot: {
        name: displayName(cap.model, procId), path: img?.path ?? null, args: img?.args ?? null,
        ruleIds: [...new Set(findings.map(f => f.ruleId))], severity, startTime: p.startTime,
      },
    };
    await store.setVerdict(v);
    await store.touchSession(s.id);
    if (sessionId.current !== s.id) return;
    setAllVerdicts(list => [...list.filter(x => !(x.fingerprint === fp && x.procKey === procId)), v]);
    setSession(cur => (cur ? { ...cur, updated: v.updated } : cur));
  }, [store]);

  const addRoutine = useCallback(async (img: Image): Promise<boolean> => {
    const sid = sessionId.current;
    const key = programKey(img);
    if (!sid || key === NO_IDENTITY) return false;
    const name = basename(img.path) || img.signingId || key;
    if (isRiskyRoutine(img) &&
        !window.confirm(`“${name}” is a shell, interpreter or download tool that attackers also use. Marking it routine hides every run of it, in every capture of this session. Mark it anyway?`)) {
      return false;
    }
    const rec: RoutineRec = { sessionId: sid, programKey: key, label: name, added: now() };
    await store.addRoutine(rec);
    if (sessionId.current === sid) setRoutine(list => [...list.filter(r => r.programKey !== key), rec]);
    return true;
  }, [store]);

  const removeRoutine = useCallback(async (key: string) => {
    const sid = sessionId.current;
    if (!sid) return;
    await store.removeRoutine(sid, key);
    if (sessionId.current === sid) setRoutine(list => list.filter(r => r.programKey !== key));
  }, [store]);

  const value: SessionCtx = {
    store, sessions, captureCounts, persisted, createSession, renameSession, deleteSession, importSessionFile,
    session, capRecs, captures, active, capture, view, allVerdicts, verdicts, routine, routineKeys, triage,
    selected, progress, loadError, openSession, closeSession, loadFiles, setActive, setView,
    setVerdict, addRoutine, removeRoutine, selectProc, showInTree,
  };
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}
