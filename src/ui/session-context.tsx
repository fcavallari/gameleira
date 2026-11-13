import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { runLoad } from '../ingest/run';
import type { LoadedCapture } from '../ingest/load';
import { displayName } from '../model/relations';
import type { Image, ProcId } from '../model/types';
import { basename, latestImage } from '../model/util';
import { SEVERITY_RANK, type Severity } from '../rules/rules';
import type { QueueItem } from '../rules/engine';
import { importSession, reimportSession, type SessionExport } from '../session/export';
import { forgetCaptureFiles, handlesSupported, rememberCaptureFile, rememberedCaptureFiles, reopenCaptureFile, type CaptureFileHandle } from '../session/capture-files';
import { folderSupported, pickFolder, rememberedFolder, rememberFolder, type DirHandle } from '../session/folder';
import { evictLru, MAX_LOADED_BYTES, touch } from '../session/lru';
import { applyRoutine, isRiskyRoutine, NO_IDENTITY, programKey, routineImpact, type RoutineResult } from '../session/routine';
import type { CaptureRec, RoutineRec, Session, Status, Store, Verdict } from '../session/store';
import { fetchDevFixture } from './dev';
import { DEFAULT_FILTERS, toggleStatus, type TriageFilters } from './triage-model';

export type View = 'triage' | 'tree' | 'confirmed';
export interface Progress { fileName: string; bytes: number; total: number }

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
  /** Swaps session `id`'s captures, verdicts, notes and routine marks for the file's; it keeps its name. Rejects with a readable message. */
  reimportSession(id: string, data: SessionExport): Promise<void>;
  /** The folder Save session writes into and opening a session looks in. Null until one is chosen, and where the browser cannot. */
  saveFolder: DirHandle | null;
  /** Asks for a folder and remembers it. Resolves null when the picker was closed. */
  chooseSaveFolder(): Promise<DirHandle | null>;
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
  triage: RoutineResult | null;
  selected: ProcId | null;
  /** The queue key (`i:<id>`) of the selected persistence-only item, which has no ProcId. At most one of this and `selected` is set. */
  selectedItem: string | null;
  /** The process "Show in tree" asked for, until the user picks another one. */
  focusId: ProcId | null;
  /** Changes on every showInTree call, so asking for the same process again is seen. */
  focusNonce: number;
  /** Triage filters and search. They live here so they survive a trip to another tab. */
  triageFilters: TriageFilters;
  updateTriageFilters(patch: Partial<TriageFilters>): void;
  progress: Progress | null;
  loadError: string | null;
  /** The Confirmed tab's export choices. They live here so they survive a trip to another tab. */
  exportOpts: { includeEnv: boolean; redactArgs: boolean };
  setExportOpts(patch: Partial<{ includeEnv: boolean; redactArgs: boolean }>): void;
  openSession(id: string): Promise<void>;
  closeSession(): void;
  /** `handles[i]`, where given, is where `files[i]` came from: it is remembered so the capture can be reloaded. */
  loadFiles(files: File[], handles?: (CaptureFileHandle | null)[]): Promise<void>;
  /** The open session's remembered capture files, by fingerprint (Chromium only; empty elsewhere). */
  captureFiles: Map<string, CaptureFileHandle>;
  /**
   * Reads the remembered files of these captures (default: every capture that has one) again and loads them. Call it
   * from a click: the browser may ask for access. Files that cannot be read are listed in `loadError`.
   */
  reloadCaptures(fingerprints?: string[]): Promise<void>;
  setActive(fingerprint: string): void;
  setView(v: View): void;
  /**
   * `note` omitted keeps the existing note. A persistence-only queue item has no process: pass its queue key (`i:<persistenceId>`).
   * `fingerprint` names the capture the verdict belongs to (default: the active one). Anything that saves later than it
   * was started, like a note, must pass the capture it began under: the active capture may have changed since.
   */
  setVerdict(procId: ProcId, status: Status, note?: string, fingerprint?: string): Promise<void>;
  /**
   * Pressing Confirm or Benign: sets it, or takes it back to unreviewed when the verdict already has it. The current
   * status is read when the call runs (not from what is rendered, which can lag a write that has not finished).
   */
  toggleVerdict(procId: ProcId, pressed: 'confirmed' | 'benign', fingerprint?: string): Promise<void>;
  /** Saves a note and nothing else: the status is whatever the verdict has when the write runs. */
  setNote(procId: ProcId, note: string, fingerprint: string): Promise<void>;
  /** Resolves false when refused (no program identity) or declined at the risky-program prompt. */
  addRoutine(img: Image): Promise<boolean>;
  removeRoutine(key: string): Promise<void>;
  selectProc(id: ProcId | null): void;
  /** Selects a persistence-only item by its queue key. */
  selectItem(key: string): void;
  showInTree(id: ProcId): void;
}

export const SessionContext = createContext<SessionCtx | null>(null);

export function useSession(): SessionCtx {
  const c = useContext(SessionContext);
  if (!c) throw new Error('useSession must be used inside <SessionProvider>');
  return c;
}

/** A verdict write that has not settled by now is given up on, so one stuck write cannot hold every later one. */
const WRITE_TIMEOUT_MS = 10_000;
class WriteTimeout extends Error {}
function settleWithin<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => { reject(new WriteTimeout('the store is not responding')); }, ms);
    p.then(v => { clearTimeout(t); resolve(v); }, e => { clearTimeout(t); reject(e as Error); });
  });
}

const now = (): string => new Date().toISOString();
const message = (e: unknown): string => (e instanceof Error ? e.message : String(e));

/** `maxLoadedBytes` is a test seam: the budget for parsed captures kept in memory (default 300 MB of input files). */
export function SessionProvider({ store, maxLoadedBytes = MAX_LOADED_BYTES, children }: { store: Store; maxLoadedBytes?: number; children: ReactNode }) {
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
  const [selectedItem, setSelectedItem] = useState<string | null>(null);
  const [focus, setFocus] = useState<{ id: ProcId; n: number } | null>(null);
  const [triageFilters, setTriageFilters] = useState<TriageFilters>(DEFAULT_FILTERS);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [exportOpts, setExportOptsState] = useState({ includeEnv: false, redactArgs: false });
  const [saveFolder, setSaveFolder] = useState<DirHandle | null>(null);
  const [captureFiles, setCaptureFiles] = useState<Map<string, CaptureFileHandle>>(new Map());

  // Synchronous mirrors: async actions must see the session that is open NOW, not the one they were created in.
  const sessionId = useRef<string | null>(null);
  const openToken = useRef(0);
  /** Bumped whenever the open session changes: work started under an older value must not touch state or the store. */
  const gen = useRef(0);
  /** Session verdicts, updated synchronously so two calls in one tick see each other. */
  const verdictRef = useRef<Verdict[]>([]);
  const queue = useRef<Promise<void>>(Promise.resolve());
  /** Verdict writes run one after another in the order they were made, so an older write can never land last. */
  const writes = useRef<Promise<unknown>>(Promise.resolve());
  /** The verdict the store last accepted, per `${fingerprint}|${procKey}`: what a failed write goes back to. */
  const stored = useRef(new Map<string, Verdict>());
  const latest = useRef({ session, capRecs, captures, active, allVerdicts, routine, captureFiles });
  latest.current = { session, capRecs, captures, active, allVerdicts, routine, captureFiles };

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

  useEffect(() => {
    if (!folderSupported()) return;
    let live = true;
    // Best-effort: without the remembered folder the next save asks for one.
    rememberedFolder().then(d => { if (live && d) setSaveFolder(prev => prev ?? d); }, () => { /* see above */ });
    return () => { live = false; };
  }, []);

  const chooseSaveFolder = useCallback(async () => {
    const d = await pickFolder();
    if (!d) return null;
    setSaveFolder(d);
    try { await rememberFolder(d); } catch { /* it is still used until the tab closes */ }
    return d;
  }, []);

  const createSession = useCallback(async (name: string) => {
    let s: Session;
    let first: boolean;
    try {
      first = (await store.listSessions()).length === 0;
      s = await store.createSession(name);
    } catch (e) { report('Could not create the session', e); return null; }
    if (first) {
      // Sessions must survive closing the tab, so ask the browser not to evict them. Failure is not fatal.
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
    writes.current = Promise.resolve();
    verdictRef.current = [];
    stored.current = new Map();
    setSession(null); setCapRecs([]); setCaptures(new Map()); setActiveFp(null); setView('triage');
    setAllVerdicts([]); setRoutine([]); setCaptureFiles(new Map()); setSelected(null); setSelectedItem(null); setFocus(null); setTriageFilters(DEFAULT_FILTERS); setProgress(null); setLoadError(null);
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
    writes.current = Promise.resolve();
    sessionId.current = id;
    verdictRef.current = vs;
    stored.current = new Map(vs.map(v => [`${v.fingerprint}|${v.procKey}`, v]));
    setSession(s); setCapRecs(recs); setAllVerdicts(vs); setRoutine(rs); setCaptureFiles(new Map());
    if (handlesSupported()) {
      // Best-effort: without them the captures are re-added by hand, as in browsers that have no handles.
      rememberedCaptureFiles(id).then(m => { if (token === openToken.current) setCaptureFiles(m); }, () => { /* see above */ });
    }
    setCaptures(new Map()); setActiveFp(null); setView('triage'); setSelected(null); setSelectedItem(null); setFocus(null); setTriageFilters(DEFAULT_FILTERS); setProgress(null); setLoadError(null);
  }, [store, report]);

  const renameSession = useCallback(async (id: string, name: string) => {
    try { await store.renameSession(id, name); } catch (e) { report('Could not rename the session', e); return; }
    if (sessionId.current === id) setSession(s => (s ? { ...s, name } : s));
    await refreshSessions();
  }, [store, refreshSessions, report]);

  const deleteSession = useCallback(async (id: string) => {
    try { await store.deleteSession(id); } catch (e) { report('Could not delete the session', e); return; }
    if (handlesSupported()) forgetCaptureFiles(id).catch(() => { /* a stray handle only takes a few bytes */ });
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

  const reimport = useCallback(async (id: string, data: SessionExport) => {
    await reimportSession(store, id, data);
    await refreshSessions();
  }, [store, refreshSessions]);

  /** `g` is the session generation the load started under; every state or store write re-checks it. */
  const loadOne = useCallback(async (sid: string, g: number, file: File, handle: CaptureFileHandle | null): Promise<void> => {
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
    if (handle) {
      rememberCaptureFile(sid, cap.fingerprint, handle).catch(() => { /* it can still be reloaded until the tab closes */ });
      if (live()) setCaptureFiles(m => new Map(m).set(cap.fingerprint, handle));
    }
    if (!live()) return;
    const recs = await store.listCaptures(sid);
    if (!live()) return;
    setCapRecs(recs);
    setCaptures(m => touch(m, cap.fingerprint, cap));
    setActiveFp(cap.fingerprint);
    setSelected(null);
    setSelectedItem(null);
    setFocus(null);
  }, [store]);

  const loadFiles = useCallback((files: File[], handles?: (CaptureFileHandle | null)[]): Promise<void> => {
    const sid = sessionId.current;
    if (!sid || files.length === 0) return Promise.resolve();
    const g = gen.current;
    // Serialised: a drop while another file is still parsing waits its turn. A run queued under an older
    // generation does nothing when its turn comes.
    const run = async () => {
      if (gen.current !== g) return;
      const errors: string[] = [];
      setLoadError(null);
      for (const [i, file] of files.entries()) {
        if (gen.current !== g) return;
        try { await loadOne(sid, g, file, handles?.[i] ?? null); }
        catch (e) { errors.push(files.length > 1 ? `${file.name}: ${message(e)}` : message(e)); }
      }
      if (gen.current === g) { setProgress(null); setLoadError(errors.length ? errors.join('\n') : null); }
    };
    queue.current = queue.current.then(run);
    return queue.current;
  }, [loadOne]);

  const reloadCaptures = useCallback(async (fingerprints?: string[]) => {
    const sid = sessionId.current;
    if (!sid) return;
    const g = gen.current;
    const { capRecs: recs, captureFiles: known } = latest.current;
    const wanted = (fingerprints ?? recs.map(r => r.fingerprint)).flatMap(fp => {
      const h = known.get(fp);
      return h ? [{ h, name: recs.find(r => r.fingerprint === fp)?.fileName ?? h.name }] : [];
    });
    setLoadError(null);
    const files: File[] = [];
    const handles: CaptureFileHandle[] = [];
    const errors: string[] = [];
    // One at a time: each may need the browser to ask for access.
    for (const { h, name } of wanted) {
      try { files.push(await reopenCaptureFile(h)); handles.push(h); }
      catch (e) { errors.push(`${name}: ${message(e)}`); }
    }
    if (gen.current !== g) return;
    if (files.length > 0) await loadFiles(files, handles);
    if (gen.current === g && errors.length > 0) setLoadError(prev => [prev, ...errors].filter(Boolean).join('\n'));
  }, [loadFiles]);

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

  const setActive = useCallback((fp: string) => {
    setActiveFp(fp); setSelected(null); setSelectedItem(null); setFocus(null);
    setCaptures(m => touch(m, fp));   // on screen = recently used
  }, []);
  const selectProc = useCallback((id: ProcId | null) => { setSelected(id); setSelectedItem(null); setFocus(null); }, []);
  const selectItem = useCallback((key: string) => { setSelected(null); setSelectedItem(key); setFocus(null); }, []);
  const showInTree = useCallback((id: ProcId) => {
    setSelected(id);
    setSelectedItem(null);
    setFocus(f => ({ id, n: (f?.n ?? 0) + 1 }));
    setView('tree');
  }, []);
  const setExportOpts = useCallback((patch: Partial<{ includeEnv: boolean; redactArgs: boolean }>) => { setExportOptsState(o => ({ ...o, ...patch })); }, []);
  const updateTriageFilters = useCallback((patch: Partial<TriageFilters>) => { setTriageFilters(f => ({ ...f, ...patch })); }, []);

  // Drop the least recently used captures once the loaded ones outgrow the budget. This is an effect, not part of the
  // load: a note field that unmounts because the active capture changed saves in that same commit's cleanup, and it
  // must still find the capture it was typed on.
  useEffect(() => { setCaptures(m => evictLru(m, active, maxLoadedBytes)); }, [captures, active, maxLoadedBytes]);

  const capture = active ? captures.get(active) ?? null : null;
  const verdicts = useMemo(
    () => new Map(allVerdicts.filter(v => v.fingerprint === active).map(v => [v.procKey, v])),
    [allVerdicts, active]);
  const routineKeys = useMemo(() => new Set(routine.map(r => r.programKey)), [routine]);
  const triage = useMemo(
    () => (capture ? applyRoutine(capture.analysis, capture.model, routineKeys) : null),
    [capture, routineKeys]);

  /**
   * Every verdict write goes through here. `change` gets the verdict as it is when the write runs (verdictRef is updated
   * synchronously, so two calls in one tick see each other) and returns the status and note to store.
   */
  const save = useCallback(async (
    procId: ProcId, fingerprint: string | undefined, change: (prev: Verdict | undefined) => { status: Status; note: string },
  ): Promise<void> => {
    const { session: s, active, captures: caps } = latest.current;
    const fp = fingerprint ?? active;
    const cap = fp ? caps.get(fp) : undefined;
    const p = cap?.model.processes.get(procId);
    const queued = cap?.analysis.queue.find(q => q.key === procId);
    const item = !p && queued?.persistenceId != null ? cap?.model.persistence.find(i => i.id === queued.persistenceId) : undefined;
    const same = (x: Verdict) => x.fingerprint === fp && x.procKey === procId;
    const prev = verdictRef.current.find(same);
    if (!s || !fp) return;
    let snapshot = prev?.snapshot;   // a capture that is no longer loaded still has the snapshot its verdict was saved with
    if (cap && (p || item)) {
      const img = p ? latestImage(p) : undefined;
      const findings = p ? cap.analysis.findings.get(procId) ?? [] : queued?.findings ?? [];
      const severity = findings.reduce<Severity | null>(
        (best, f) => (best === null || SEVERITY_RANK[f.severity] > SEVERITY_RANK[best] ? f.severity : best), null);
      snapshot = {
        name: p ? displayName(cap.model, procId) : `persistence: ${basename(item?.plistPath ?? null) || procId}`,
        path: p ? img?.path ?? null : item?.executablePath ?? null, args: img?.args ?? null,
        ruleIds: [...new Set(findings.map(f => f.ruleId))], severity, startTime: p ? p.startTime : item?.time ?? null,
      };
    }
    if (!snapshot) return;
    const v: Verdict = { sessionId: s.id, fingerprint: fp, procKey: procId, ...change(prev), updated: now(), snapshot };
    // Synchronous, so a second call in the same tick sees this verdict (and its note); undone if the write fails.
    verdictRef.current = [...verdictRef.current.filter(x => !same(x)), v];
    const open = () => sessionId.current === s.id;
    const key = `${fp}|${procId}`;
    try {
      const done = writes.current.then(() => settleWithin(store.setVerdict(v), WRITE_TIMEOUT_MS));
      writes.current = done.catch(() => { /* reported below, by the call that made it */ });
      await done;
      if (open()) stored.current.set(key, v);
    } catch (e) {
      if (open()) {
        // Back to what the store holds, not to the previous in-memory verdict: that one may itself never have been saved.
        // A later write built on this one (still queued) is the current verdict and answers for itself when it settles.
        if (verdictRef.current.includes(v)) {
          const last = stored.current.get(key);
          verdictRef.current = [...verdictRef.current.filter(x => x !== v), ...(last ? [last] : [])];
          setAllVerdicts(verdictRef.current);
        }
        if (e instanceof WriteTimeout) setStoreError('Could not confirm the verdict was saved (the store is not responding); it may still be saved.');
        else report('Could not save the verdict', e);
      }
      return;
    }
    if (open()) {
      setAllVerdicts(verdictRef.current);
      setSession(cur => (cur ? { ...cur, updated: v.updated } : cur));
    }
    store.touchSession(s.id).catch(() => { /* best-effort: only the "updated" time is lost */ });
  }, [store, report]);

  const setVerdict = useCallback(
    (procId: ProcId, status: Status, note?: string, fingerprint?: string) =>
      save(procId, fingerprint, prev => ({ status, note: note ?? prev?.note ?? '' })),
    [save]);
  const toggleVerdict = useCallback(
    (procId: ProcId, pressed: 'confirmed' | 'benign', fingerprint?: string) =>
      save(procId, fingerprint, prev => ({ status: toggleStatus(prev?.status ?? 'unreviewed', pressed), note: prev?.note ?? '' })),
    [save]);
  const setNote = useCallback(
    (procId: ProcId, note: string, fingerprint: string) =>
      save(procId, fingerprint, prev => ({ status: prev?.status ?? 'unreviewed', note })),
    [save]);

  const addRoutine = useCallback(async (img: Image): Promise<boolean> => {
    const sid = sessionId.current;
    const key = programKey(img);
    if (!sid || key === NO_IDENTITY) return false;
    const name = basename(img.path) || img.signingId || key;
    // One prompt for both reasons to stop: an attacker-favoured program, and high or persistence rows that stay visible.
    let kept = 0;
    for (const cap of latest.current.captures.values()) kept += routineImpact(cap.analysis, cap.model, key).kept;
    const warn: string[] = [];
    if (isRiskyRoutine(img)) {
      warn.push(`“${name}” is a shell, interpreter or download tool that attackers also use. Marking it routine hides every run of it, in every capture of this session.`);
    }
    if (kept > 0) {
      warn.push(`${kept} high-severity or persistence ${kept === 1 ? 'row' : 'rows'} of “${name}” in the loaded captures will stay visible, because a routine mark never hides those.`);
    }
    if (warn.length > 0 && !window.confirm(`${warn.join(' ')} Mark it anyway?`)) return false;
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
    reimportSession: reimport, saveFolder, chooseSaveFolder,
    session, capRecs, captures, active, capture, view, allVerdicts, verdicts, routine, routineKeys, triage,
    selected, selectedItem, focusId: focus?.id ?? null, focusNonce: focus?.n ?? 0, triageFilters, updateTriageFilters, progress, loadError, exportOpts, setExportOpts, openSession, closeSession, loadFiles, captureFiles, reloadCaptures, setActive, setView,
    setVerdict, toggleVerdict, setNote, addRoutine, removeRoutine, selectProc, selectItem, showInTree,
  };
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}
