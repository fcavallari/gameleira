import { openDB } from 'idb';
import { idHash, parseExport, SAVE_SUFFIX, slug, type SessionExport } from './export';
import type { Session } from './store';

/*
 * The folder Save session writes into, through the File System Access API (Chrome, Edge and other Chromium browsers).
 * Elsewhere the API is missing and Save session downloads the file instead; nothing here is used.
 * Only the parts of the API this app calls are typed here: the DOM library does not have them all yet.
 */

type Mode = 'read' | 'readwrite';
export interface FileEntry {
  kind: 'file'; name: string;
  getFile(): Promise<{ lastModified: number; text(): Promise<string> }>;
  createWritable(): Promise<{ write(data: string): Promise<void>; close(): Promise<void> }>;
}
export interface DirHandle {
  kind: 'directory'; name: string;
  values(): AsyncIterable<FileEntry | { kind: 'directory'; name: string }>;
  getFileHandle(name: string, opts?: { create?: boolean }): Promise<FileEntry>;
  queryPermission?(opts: { mode: Mode }): Promise<PermissionState>;
  requestPermission?(opts: { mode: Mode }): Promise<PermissionState>;
}
type Picker = (opts: { id?: string; mode?: Mode }) => Promise<DirHandle>;
const picker = (): Picker | undefined => (globalThis as { showDirectoryPicker?: Picker }).showDirectoryPicker;

/** True where the browser can save into a folder and read it back later. */
export const folderSupported = (): boolean => typeof picker() === 'function';

/** Asks for a folder. Null when the user closes the picker. */
export async function pickFolder(): Promise<DirHandle | null> {
  try {
    // `id` makes the picker open where it was last used for this purpose.
    return await picker()!({ id: 'gameleira-sessions', mode: 'readwrite' });
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') return null;
    throw e;
  }
}

/**
 * Whether the page may use `dir` for `mode`. With `ask`, a browser that has forgotten the grant (it usually does after a
 * restart) asks the user; that only works while handling a click, so call it before any slow work.
 */
export async function permitted(dir: DirHandle, mode: Mode, ask: boolean): Promise<boolean> {
  if (!dir.queryPermission) return true;
  if (await dir.queryPermission({ mode }) === 'granted') return true;
  if (!ask || !dir.requestPermission) return false;
  return await dir.requestPermission({ mode }) === 'granted';
}

export async function writeFile(dir: DirHandle, name: string, text: string): Promise<void> {
  const w = await (await dir.getFileHandle(name, { create: true })).createWritable();
  await w.write(text);
  await w.close();
}

export interface SavedCopy {
  fileName: string; lastModified: number; data: SessionExport;
  /** True when the file holds this very session (same id); false when it only has the same name. */
  byId: boolean;
}

/**
 * The saved file of `session` in `dir`, if there is one: a session file whose name has the session's id hash or starts
 * with its name, and whose content has the same session id or, failing that, the same session name. A file with the
 * same id wins over one with the same name; among equals, the newest. Unreadable or invalid files are skipped.
 */
export async function findSavedCopy(dir: DirHandle, session: Pick<Session, 'id' | 'name'>): Promise<SavedCopy | null> {
  const hash = `.${idHash(session.id)}.`;
  const prefix = `${slug(session.name)}.`;
  let best: SavedCopy | null = null;
  for await (const entry of dir.values()) {
    if (entry.kind !== 'file' || !entry.name.endsWith(SAVE_SUFFIX)) continue;
    if (!entry.name.includes(hash) && !entry.name.startsWith(prefix)) continue;
    let copy: SavedCopy;
    try {
      const file = await entry.getFile();
      const data = parseExport(await file.text());
      const byId = data.session.id === session.id;
      if (!byId && data.session.name !== session.name) continue;
      copy = { fileName: entry.name, lastModified: file.lastModified, data, byId };
    } catch { continue; }
    if (!best || (copy.byId && !best.byId) || (copy.byId === best.byId && copy.lastModified > best.lastModified)) best = copy;
  }
  return best;
}

/*
 * The chosen folder is remembered in its own small database, not the sessions one, so the sessions schema stays as it
 * is. A directory handle can be stored in IndexedDB; the browser asks again for access when it is used after a restart.
 */
const DB = 'gameleira-save-folder';
const KEY = 'folder';
const db = () => openDB(DB, 1, { upgrade(d) { d.createObjectStore('kv'); } });

export async function rememberedFolder(): Promise<DirHandle | null> {
  return ((await (await db()).get('kv', KEY)) as DirHandle | undefined) ?? null;
}

export async function rememberFolder(dir: DirHandle): Promise<void> {
  await (await db()).put('kv', dir, KEY);
}
