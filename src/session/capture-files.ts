import { openDB } from 'idb';

/*
 * Where each capture of a session was read from, so it can be read again without picking the file. A web page never
 * learns a file's path; what Chromium browsers give instead is a file handle (from their file picker, or from a drop),
 * which can be kept in IndexedDB and read later once the user allows it again. Safari and Firefox give no handles:
 * there nothing is remembered and captures are re-added by hand.
 */

export interface CaptureFileHandle {
  kind: 'file'; name: string;
  getFile(): Promise<File>;
  queryPermission?(opts: { mode: 'read' }): Promise<PermissionState>;
  requestPermission?(opts: { mode: 'read' }): Promise<PermissionState>;
}
export interface Sourced { file: File; handle: CaptureFileHandle | null }

type OpenPicker = (opts: { multiple?: boolean; id?: string }) => Promise<CaptureFileHandle[]>;
const openPicker = (): OpenPicker | undefined => (globalThis as { showOpenFilePicker?: OpenPicker }).showOpenFilePicker;

/** True where the browser hands out file handles, so captures can be reloaded later. */
export const handlesSupported = (): boolean => typeof openPicker() === 'function';

/** Asks for capture files with the browser's picker. Empty when the user closes it. */
export async function pickCaptureFiles(): Promise<Sourced[]> {
  let handles: CaptureFileHandle[];
  try {
    handles = await openPicker()!({ multiple: true, id: 'gameleira-captures' });
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') return [];
    throw e;
  }
  return Promise.all(handles.map(async handle => ({ file: await handle.getFile(), handle })));
}

type HandleItem = DataTransferItem & { getAsFileSystemHandle?(): Promise<{ kind: string } | null> };

/**
 * The files of a drop, each with its handle where the browser gives one. Call it while handling the drop event: the
 * items are only readable then, so everything is taken from them before the first await.
 */
export function sourcedFromDrop(dt: DataTransfer): Promise<Sourced[]> {
  const items = [...dt.items].filter(i => i.kind === 'file') as HandleItem[];
  if (items.length === 0) return Promise.resolve([...dt.files].map(file => ({ file, handle: null })));
  const taken = items.map(i => ({ file: i.getAsFile(), handle: i.getAsFileSystemHandle?.() ?? Promise.resolve(null) }));
  return Promise.all(taken.map(async ({ file, handle }) => {
    let h: { kind: string } | null = null;
    try { h = await handle; } catch { /* no handle: the file still loads, it just cannot be reloaded */ }
    return { file, handle: h?.kind === 'file' ? h as CaptureFileHandle : null };
  })).then(list => list.filter((x): x is Sourced => x.file !== null));
}

/**
 * Reads a remembered capture file again. Asks for access when the browser has forgotten it (it usually has after a
 * restart); that only works while handling a click. Rejects with a readable message.
 */
export async function reopenCaptureFile(h: CaptureFileHandle): Promise<File> {
  let state: PermissionState = 'granted';
  if (h.queryPermission) state = await h.queryPermission({ mode: 'read' });
  if (state !== 'granted' && h.requestPermission) {
    try { state = await h.requestPermission({ mode: 'read' }); } catch (e) {
      // No click to ask on (several files, and the browser allows one prompt per click).
      if (e instanceof DOMException && e.name === 'SecurityError') throw new Error('the browser needs another click to ask for access; press Reload again');
      throw e;
    }
  }
  if (state !== 'granted') throw new Error('access to the file was refused');
  try { return await h.getFile(); } catch (e) {
    if (e instanceof DOMException && e.name === 'NotFoundError') throw new Error('the file is no longer where it was; add it again');
    throw e;
  }
}

/*
 * Kept in their own small database, not the sessions one, so the sessions schema stays as it is. Keyed by
 * [session id, capture fingerprint].
 */
const db = () => openDB('gameleira-capture-files', 1, { upgrade(d) { d.createObjectStore('handles'); } });
const range = (sessionId: string) => IDBKeyRange.bound([sessionId], [sessionId, []]);

export async function rememberCaptureFile(sessionId: string, fingerprint: string, h: CaptureFileHandle): Promise<void> {
  await (await db()).put('handles', h, [sessionId, fingerprint]);
}

/** The remembered files of a session, by capture fingerprint. */
export async function rememberedCaptureFiles(sessionId: string): Promise<Map<string, CaptureFileHandle>> {
  const d = await db();
  const [keys, values] = await Promise.all([d.getAllKeys('handles', range(sessionId)), d.getAll('handles', range(sessionId))]);
  return new Map(keys.map((k, i) => [(k as [string, string])[1], values[i] as CaptureFileHandle]));
}

export async function forgetCaptureFiles(sessionId: string): Promise<void> {
  await (await db()).delete('handles', range(sessionId));
}
