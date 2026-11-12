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
import { DEFAULT_FILTERS, type TriageFilters } from './triage-model';

export type View = 'triage' | 'tree' | 'confirmed';
export interface Progress { fileName: string; bytes: number; total: number }

/** Programs with no signing id, team id or path cannot be told apart: a routine mark would hide everything. */
const NO_IDENTITY = '-|-|-';

export interface SessionCtx {
  store: Store;
  // start screen
  sessions: Session[];
  captureCounts: Map<string, number>;
  /** False until the session list was read successfully (so a failed read is not shown as "no sessions"). */
  sessionsLoaded: boolean;
  persisted: boolean | null;
  /** Last failed store operation, shown as a banner on both screens until dismissed. */
  storeError: string | null;
  dismissStoreError(): void;
  /** Resolves null when the store refused (the error is reported in `storeError`). */
  createSession(name: string): Promise<Session | null>;
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
  /** The process "Show in tree" asked for, until the user picks another one. */
  focusId: ProcId | null;
  /** Changes on every showInTree call, so asking for the same process again is seen. */
  focusNonce: number;
  /** Triage filters and search. They live here so they survive a trip to another tab. */
  triageFilters: TriageFilters;
  updateTriageFilters(patch: Partial<TriageFilters>): void;
  progress: Progress | null;
  loadError: string | null;
  openSession(id: string): Promise<void>;
  closeSession(): void;
  loadFiles(files: File[]): Promise<void>;
  setActive(fingerprint: string): void;
  setView(v: View): void;
  /** `note` omitted keeps the existing note. A persistence-only queue item has no process: pass its queue key (`i:<persistenceId>`). */
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
  const [sessionsLoaded, setSessionsLoaded] = useState(false);
  const [storeError, setStoreError] = useState<string | null>(null);
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
  const [focus, setFocus] = useState<{ id: ProcId; n: number } | null>(null);
  const [triageFilters, setTriageFilters] = useState<TriageFilters>(DEFAULT_FILTERS);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  // Synchronous mirrors: async actions must see the session that is open NOW, not the one they were created in.
  const sessionId = useRef<string | null>(null);
  const openToken = useRef(0);
  /** Bumped whenever the open session changes: work started under an older value must not touch state or the store. */
  const gen = useRef(0);
  /** Session verdicts, updated synchronously so two calls in one tick see each other. */
  const verdictRef = useRef<Verdict[]>([]);
  const queue = useRef<Promise<void>>(Promise.resolve());
  const latest = useRef({ session, capRecs, captures, active, allVerdicts, routine });
  latest.current = { session, capRecs, captures, active, allVerdicts, routine };

  const report = useCallback((what: string, e: unknown) => { setStoreError(`${what}: ${message(e)}`); }, []);

  const refreshSessions = useCallback(async () => {
    try {
      const list = await store.listSessions();
      const counts = await Promise.all(list.map(async s => [s.id, (await store.listCaptures(s.id)).length] as const));
      setSessions(list);
      setCaptureCounts(new Map(counts));
      setSessionsLoaded(true);
    } catch (e) { report('Could not read sessions', e); }
  }, [store, report]);

  const refreshPersisted = useCallback(async () => {
    try { setPersisted((await navigator.storage?.persisted?.()) ?? false); } catch { setPersisted(false); }
  }, []);

  useEffect(() => { void refreshSessions(); void refreshPersisted(); }, [refreshSessions, refreshPersisted]);

  const createSession = useCallback(async (name: string) => {
    let s: Session;
    let first: boolean;
    try {
      first = (await store.listSessions()).length === 0;
      s = await store.createSession(name);
    } catch (e) { report('Could not create the session', e); return null; }
    if (first) {
      // Spec §3: sessions must survive closing the tab, so ask the browser not to evict them. Failure is not fatal.
      void (async () => {
        try { await navigator.storage?.persist?.(); } catch { /* best-effort */ }
        await refreshPersisted();
      })();
    }
    await refreshSessions();
    return s;
  }, [store, refreshSessions, refreshPersisted, report]);

  const closeSession = useCallback(() => {
    sessionId.current = null;
    openToken.current++;
    gen.current++;
    queue.current = Promise.resolve();
    verdictRef.current = [];
    setSession(null); setCapRecs([]); setCaptures(new Map()); setActiveFp(null); setView('triage');
    setAllVerdicts([]); setRoutine([]); setSelected(null); setFocus(null); setTriageFilters(DEFAULT_FILTERS); setProgress(null); setLoadError(null);
    void refreshSessions();
  }, [refreshSessions]);

  const openSession = useCallback(async (id: string) => {
    const token = ++openToken.current;
    let s: Session | undefined;
    let recs: CaptureRec[]; let vs: Verdict[]; let rs: RoutineRec[];
    try {
      s = (await store.listSessions()).find(x => x.id === id);
      if (!s) return;
      [recs, vs, rs] = await Promise.all([store.listCaptures(id), store.listVerdicts(id), store.listRoutine(id)]);
    } catch (e) { report('Could not open the session', e); return; }
    if (token !== openToken.current) return;
    gen.current++;   // loads still running for the previous session are now stale
    queue.current = Promise.resolve();   // …and the new session's loads must not wait for them
    sessionId.current = id;
    verdictRef.current = vs;
    setSession(s); setCapRecs(recs); setAllVerdicts(vs); setRoutine(rs);
    setCaptures(new Map()); setActiveFp(null); setView('triage'); setSelected(null); setFocus(null); setTriageFilters(DEFAULT_FILTERS); setProgress(null); setLoadError(null);
  }, [store, report]);

  const renameSession = useCallback(async (id: string, name: string) => {
    try { await store.renameSession(id, name); } catch (e) { report('Could not rename the session', e); return; }
    if (sessionId.current === id) setSession(s => (s ? { ...s, name } : s));
    await refreshSessions();
  }, [store, refreshSessions, report]);

  const deleteSession = useCallback(async (id: string) => {
    try { await store.deleteSession(id); } catch (e) { report('Could not delete the session', e); return; }
    if (sessionId.current === id) closeSession();
    else await refreshSessions();
  }, [store, closeSession, refreshSessions, report]);

  const importSessionFile = useCallback(async (file: File) => {
    let data: unknown;
    try { data = JSON.parse(await file.text()); } catch { throw new Error('Not a JSON file'); }
    const s = await importSession(store, data as Parameters<typeof importSession>[1]);
    await refreshSessions();
    return s;
  }, [store, refreshSessions]);

  /** `g` is the session generation the load started under; every state or store write re-checks it. */
  const loadOne = useCallback(async (sid: string, g: number, file: File): Promise<void> => {
    const live = () => gen.current === g;
    setProgress({ fileName: file.name, bytes: 0, total: file.size });
    const cap = await runLoad(file, (bytes, total) => { if (live()) setProgress({ fileName: file.name, bytes, total }); });
    if (!live()) return;   // the user left the session while it was loading: drop the result
    const rec: CaptureRec = {
      sessionId: sid, fingerprint: cap.fingerprint, fileName: cap.fileName || file.name, size: cap.size,
      events: cap.model.stats.events, processes: cap.model.processes.size, flagged: cap.analysis.queue.length, added: now(),
    };
    // Same fingerprint as a stored capture: the store updates size and counts and keeps the verdicts' key.
    await store.upsertCapture(rec);
    store.touchSession(sid).catch(() => { /* best-effort: only the "updated" time is lost */ });
    if (!live()) return;
    const recs = await store.listCaptures(sid);
    if (!live()) return;
    setCapRecs(recs);
    setCaptures(m => new Map(m).set(cap.fingerprint, cap));
    setActiveFp(cap.fingerprint);
    setSelected(null);
    setFocus(null);
  }, [store]);

  const loadFiles = useCallback((files: File[]): Promise<void> => {
    const sid = sessionId.current;
    if (!sid || files.length === 0) return Promise.resolve();
    const g = gen.current;
    // Serialised: a drop while another file is still parsing waits its turn. A run queued under an older
    // generation does nothing when its turn comes.
    const run = async () => {
      if (gen.current !== g) return;
      const errors: string[] = [];
      setLoadError(null);
      for (const file of files) {
        if (gen.current !== g) return;
        try { await loadOne(sid, g, file); }
        catch (e) { errors.push(files.length > 1 ? `${file.name}: ${message(e)}` : message(e)); }
      }
      if (gen.current === g) { setProgress(null); setLoadError(errors.length ? errors.join('\n') : null); }
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

  const setActive = useCallback((fp: string) => { setActiveFp(fp); setSelected(null); setFocus(null); }, []);
  const selectProc = useCallback((id: ProcId | null) => { setSelected(id); setFocus(null); }, []);
  const showInTree = useCallback((id: ProcId) => {
    setSelected(id);
    setFocus(f => ({ id, n: (f?.n ?? 0) + 1 }));
    setView('tree');
  }, []);
  const updateTriageFilters = useCallback((patch: Partial<TriageFilters>) => { setTriageFilters(f => ({ ...f, ...patch })); }, []);

  const capture = active ? captures.get(active) ?? null : null;
  const verdicts = useMemo(
    () => new Map(allVerdicts.filter(v => v.fingerprint === active).map(v => [v.procKey, v])),
    [allVerdicts, active]);
  const routineKeys = useMemo(() => new Set(routine.map(r => r.programKey)), [routine]);
  const triage = useMemo(
    () => (capture ? applyRoutine(capture.analysis, capture.model, routineKeys) : null),
    [capture, routineKeys]);

  const setVerdict = useCallback(async (procId: ProcId, status: Status, note?: string) => {
    const { session: s, active: fp, captures: caps } = latest.current;
    const cap = fp ? caps.get(fp) : undefined;
    const p = cap?.model.processes.get(procId);
    const queued = cap?.analysis.queue.find(q => q.key === procId);
    const item = !p && queued?.persistenceId != null ? cap?.model.persistence.find(i => i.id === queued.persistenceId) : undefined;
    if (!s || !fp || !cap || (!p && !item)) return;
    const img = p ? latestImage(p) : undefined;
    const findings = p ? cap.analysis.findings.get(procId) ?? [] : queued?.findings ?? [];
    const severity = findings.reduce<Severity | null>(
      (best, f) => (best === null || SEVERITY_RANK[f.severity] > SEVERITY_RANK[best] ? f.severity : best), null);
    const same = (x: Verdict) => x.fingerprint === fp && x.procKey === procId;
    const prev = verdictRef.current.find(same);
    const v: Verdict = {
      sessionId: s.id, fingerprint: fp, procKey: procId, status, note: note ?? prev?.note ?? '', updated: now(),
      snapshot: {
        name: p ? displayName(cap.model, procId) : `persistence: ${basename(item?.plistPath ?? null) || procId}`,
        path: p ? img?.path ?? null : item?.executablePath ?? null, args: img?.args ?? null,
        ruleIds: [...new Set(findings.map(f => f.ruleId))], severity, startTime: p ? p.startTime : item?.time ?? null,
      },
    };
    // Synchronous, so a second call in the same tick sees this verdict (and its note); undone if the write fails.
    verdictRef.current = [...verdictRef.current.filter(x => !same(x)), v];
    const open = () => sessionId.current === s.id;
    try {
      await store.setVerdict(v);
    } catch (e) {
      if (open()) {
        if (verdictRef.current.includes(v)) {
          verdictRef.current = [...verdictRef.current.filter(x => x !== v), ...(prev ? [prev] : [])];
          setAllVerdicts(verdictRef.current);
        }
        report('Could not save the verdict', e);
      }
      return;
    }
    if (open()) {
      setAllVerdicts(verdictRef.current);
      setSession(cur => (cur ? { ...cur, updated: v.updated } : cur));
    }
    store.touchSession(s.id).catch(() => { /* best-effort: only the "updated" time is lost */ });
  }, [store, report]);

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
    try { await store.addRoutine(rec); } catch (e) { report('Could not save the routine mark', e); return false; }
    if (sessionId.current === sid) setRoutine(list => [...list.filter(r => r.programKey !== key), rec]);
    return true;
  }, [store, report]);

  const removeRoutine = useCallback(async (key: string) => {
    const sid = sessionId.current;
    if (!sid) return;
    try { await store.removeRoutine(sid, key); } catch (e) { report('Could not remove the routine mark', e); return; }
    if (sessionId.current === sid) setRoutine(list => list.filter(r => r.programKey !== key));
  }, [store, report]);

  const dismissStoreError = useCallback(() => { setStoreError(null); }, []);

  const value: SessionCtx = {
    store, sessions, sessionsLoaded, captureCounts, persisted, storeError, dismissStoreError, createSession, renameSession, deleteSession, importSessionFile,
    session, capRecs, captures, active, capture, view, allVerdicts, verdicts, routine, routineKeys, triage,
    selected, focusId: focus?.id ?? null, focusNonce: focus?.n ?? 0, triageFilters, updateTriageFilters, progress, loadError, openSession, closeSession, loadFiles, setActive, setView,
    setVerdict, addRoutine, removeRoutine, selectProc, showInTree,
  };
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}
