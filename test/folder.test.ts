import 'fake-indexeddb/auto';
import { beforeEach, expect, test } from 'vitest';
import { exportSession, saveFileName } from '../src/session/export';
import { findSavedCopy, permitted, writeFile } from '../src/session/folder';
import { openStore, type Session, type Store } from '../src/session/store';
import { fakeFolder } from './fake-folder';

let store: Store;
let s: Session;
let n = 0;
beforeEach(async () => {
  store = await openStore(`test-folder-${n++}`);
  s = await store.createSession('lab');
  await store.addRoutine({ sessionId: s.id, programKey: 'k', label: 'l', added: 't' });
});

const saved = async (session: Session, lastModified: number) =>
  ({ text: JSON.stringify(await exportSession(store, session.id, { includeEnv: false })), lastModified });

test('finds the saved copy of a session by the id hash in its file name, and by its name', async () => {
  const dir = fakeFolder('cases', {
    [saveFileName(s)]: await saved(s, 1),
    'notes.txt': { text: 'x', lastModified: 9 },
  });
  const copy = await findSavedCopy(dir, s);
  expect(copy).toMatchObject({ fileName: saveFileName(s), lastModified: 1, byId: true });
  expect(copy!.data.session.id).toBe(s.id);

  // Renamed by hand, or saved by an older build without the hash: found by the session name.
  const renamed = fakeFolder('cases', { 'lab.gameleira-session.json': await saved(s, 1) });
  expect((await findSavedCopy(renamed, s))?.byId).toBe(true);
});

test('a file of this very session wins over a newer one from another session with the same name', async () => {
  const twin = await store.createSession('lab');
  const dir = fakeFolder('cases', { [saveFileName(s)]: await saved(s, 1), [saveFileName(twin)]: await saved(twin, 5) });
  expect((await findSavedCopy(dir, s))?.fileName).toBe(saveFileName(s));
  // With only the twin's file there, it is offered, marked as not this session.
  const onlyTwin = fakeFolder('cases', { [saveFileName(twin)]: await saved(twin, 5) });
  expect(await findSavedCopy(onlyTwin, s)).toMatchObject({ fileName: saveFileName(twin), byId: false });
});

test('the newest of several copies wins; unrelated, broken and other sessions’ files are skipped', async () => {
  const other = await store.createSession('other');
  const dir = fakeFolder('cases', {
    'lab.old.gameleira-session.json': await saved(s, 1),
    'lab.new.gameleira-session.json': await saved(s, 3),
    'lab.broken.gameleira-session.json': { text: '{', lastModified: 9 },
    [saveFileName(other)]: await saved(other, 9),
  });
  expect((await findSavedCopy(dir, s))?.fileName).toBe('lab.new.gameleira-session.json');
  expect(await findSavedCopy(fakeFolder('empty'), s)).toBeNull();
});

test('writeFile creates or replaces the file; permitted asks only when allowed to', async () => {
  const dir = fakeFolder('cases');
  await writeFile(dir, 'a.json', 'one');
  await writeFile(dir, 'a.json', 'two');
  expect(dir.files['a.json']!.text).toBe('two');

  const locked = fakeFolder('cases', {}, 'prompt');
  expect(await permitted(locked, 'read', false)).toBe(false);
  expect(locked.requestPermission).not.toHaveBeenCalled();
  expect(await permitted(locked, 'read', true)).toBe(false);
  expect(locked.requestPermission).toHaveBeenCalledWith({ mode: 'read' });
  expect(await permitted(fakeFolder('cases'), 'readwrite', true)).toBe(true);
});
