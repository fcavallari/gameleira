// @vitest-environment jsdom
import 'fake-indexeddb/auto';
import '@testing-library/jest-dom/vitest';
import fs from 'node:fs';
import { File as NodeFile } from 'node:buffer';
import { IDBFactory } from 'fake-indexeddb';
import { useMemo, useState } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { loadCapture, type LoadedCapture } from '../src/ingest/load';
import { runLoad } from '../src/ingest/run';
import { displayName } from '../src/model/relations';
import type { CaptureModel, Image, Process } from '../src/model/types';
import { basename, latestImage } from '../src/model/util';
import { forestOf, flatten, keepSet, makeFoldInfo, revealKeys } from '../src/ui/tree-model';
import { ErrorBoundary } from '../src/ui/ErrorBoundary';
import { LaunchItem } from '../src/ui/LaunchItem';
import { App, SessionContext, SessionProvider, useSession, type SessionCtx } from '../src/ui/App';
import { SessionScreen } from '../src/ui/SessionScreen';
import { TreeView } from '../src/ui/TreeView';
import { TriageView } from '../src/ui/TriageView';
import { DEFAULT_FILTERS, toggleStatus, type TriageFilters } from '../src/ui/triage-model';
import { MITRE_NAMES } from '../src/rules/mitre';
import { applyRoutine, keepReason, programKey } from '../src/session/routine';
import { analyze } from '../src/rules/engine';
import { procByPid, queued } from './helpers';
import { apple, capture, img as synthImg, persistenceItem, proc } from './synth';
import { StoreErrorBanner } from '../src/ui/StoreErrorBanner';
import { openStore, type CaptureRec, type Status, type Store, type Verdict } from '../src/session/store';
import { fixture, type FixtureName } from './fixtures';
import { exportSession, saveFileName } from '../src/session/export';
import type { DirHandle } from '../src/session/folder';
import { fakeFolder } from './fake-folder';

// The real runLoad starts an inline Worker, which jsdom lacks; delegate to loadCapture instead.
vi.mock('../src/ingest/run', () => ({ runLoad: vi.fn() }));
const runLoadMock = vi.mocked(runLoad);

// A directory handle cannot go through fake-indexeddb's structured clone: remember the save folder in memory instead.
const folderMemory = vi.hoisted(() => ({ dir: null as unknown }));
vi.mock('../src/session/folder', async importOriginal => ({
  ...await importOriginal<typeof import('../src/session/folder')>(),
  rememberedFolder: async () => folderMemory.dir,
  rememberFolder: async (d: unknown) => { folderMemory.dir = d; },
}));
// Same for remembered capture files: kept in a map, keyed `${sessionId}|${fingerprint}`.
const captureFileMemory = vi.hoisted(() => new Map<string, unknown>());
vi.mock('../src/session/capture-files', async importOriginal => ({
  ...await importOriginal<typeof import('../src/session/capture-files')>(),
  rememberCaptureFile: async (sid: string, fp: string, h: unknown) => { captureFileMemory.set(`${sid}|${fp}`, h); },
  rememberedCaptureFiles: async (sid: string) => new Map([...captureFileMemory].filter(([k]) => k.startsWith(`${sid}|`))
    .map(([k, h]) => [k.slice(sid.length + 1), h])),
  forgetCaptureFiles: async (sid: string) => { for (const k of [...captureFileMemory.keys()]) if (k.startsWith(`${sid}|`)) captureFileMemory.delete(k); },
}));
/** A file handle as Chromium gives one, for a fixture; `state` answers both permission calls; `gone` makes it unreadable. */
function fileHandle(name: LabName, state: PermissionState = 'granted', gone = false) {
  return {
    kind: 'file' as const, name,
    getFile: vi.fn(async () => { if (gone) throw new DOMException('gone', 'NotFoundError'); return dropped(name); }),
    queryPermission: vi.fn(async () => state),
    requestPermission: vi.fn(async () => state),
  };
}
/** Makes the page see a browser with file handles whose picker hands out `handles`. */
function handleBrowser(handles: ReturnType<typeof fileHandle>[]): void {
  Object.defineProperty(window, 'showOpenFilePicker', { configurable: true, writable: true, value: vi.fn(async () => handles) });
}
/** Makes the page see a folder-capable browser (Chromium) whose picker hands out `dir`. */
function folderBrowser(dir: DirHandle | null): ReturnType<typeof vi.fn> {
  const pick = vi.fn(async () => { if (!dir) throw new DOMException('closed', 'AbortError'); return dir; });
  Object.defineProperty(window, 'showDirectoryPicker', { configurable: true, writable: true, value: pick });
  return pick;
}

const CMD = /sudo eslogger fork exec exit create rename unlink setextattr btm_launch_item_add btm_launch_item_remove/;

/**
 * `synthetic-lab-2.jsonl`, `-3`...: the synthetic lab with n trailing spaces on its first line. Each is its own capture
 * (the fingerprint covers the bytes of the first lines) of the same size and content, for tests that need several.
 */
type LabName = FixtureName | `synthetic-lab-${number}.jsonl`;
function labVariant(name: string): string | null {
  const n = /^synthetic-lab-(\d+)\.jsonl$/.exec(name)?.[1];
  if (n === undefined) return null;
  const text = fs.readFileSync(fixture('synthetic-lab.jsonl'), 'utf8');
  const nl = text.indexOf('\n');
  return text.slice(0, nl) + ' '.repeat(Number(n)) + text.slice(nl);
}

/** A Node File (jsdom's Blob has no reliable arrayBuffer) holding a small fixture, named like it. */
const nodeFile = (name: LabName): File =>
  new NodeFile([labVariant(name) ?? fs.readFileSync(fixture(name as FixtureName))], name) as unknown as File;
/** What the user "drops": the bytes are never read, the mocked runLoad looks the fixture up by name. */
const dropped = (name: LabName): File => new File(['x'], name);

const loadFixture = (name: LabName): Promise<LoadedCapture> => loadCapture(nodeFile(name));

let user: ReturnType<typeof userEvent.setup>;
beforeEach(() => {
  globalThis.indexedDB = new IDBFactory();   // App opens the default DB: isolate every test
  user = userEvent.setup();
  runLoadMock.mockReset();
  runLoadMock.mockImplementation((file, onProgress) => loadCapture(nodeFile(file.name as LabName), onProgress));
  Object.defineProperty(navigator, 'storage', {
    configurable: true,
    value: { persist: vi.fn().mockResolvedValue(true), persisted: vi.fn().mockResolvedValue(false) },
  });
  window.confirm = vi.fn(() => true);
  URL.createObjectURL = vi.fn(() => 'blob:fake');
  URL.revokeObjectURL = vi.fn();
  folderMemory.dir = null;
  delete (window as { showDirectoryPicker?: unknown }).showDirectoryPicker;
  captureFileMemory.clear();
  delete (window as { showOpenFilePicker?: unknown }).showOpenFilePicker;
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

/** The header's counts group; waits until it shows `text`. */
async function headerShows(text: string | RegExp): Promise<void> {
  const group = await screen.findByRole('group', { name: 'Capture counts' });
  await waitFor(() => { expect(within(group).getByText(text)).toBeInTheDocument(); });
}

async function newSession(name: string): Promise<void> {
  await user.click(await screen.findByRole('button', { name: /new session/i }));
  await user.type(screen.getByLabelText(/session name/i), `${name}{enter}`);
}

test('create session and see empty drop zone with capture command', async () => {
  render(<App />);
  await newSession('lab MacBook');
  expect(await screen.findByRole('heading', { name: 'lab MacBook' })).toBeInTheDocument();
  expect(screen.getByText(CMD)).toBeInTheDocument();
});

test('the header shows what was skipped: unreadable lines, other event types, schema version, older-format note', async () => {
  const withStats = (stats: Partial<CaptureModel['stats']>) => async (file: File, onProgress?: Parameters<typeof loadCapture>[1]) => {
    const cap = await loadCapture(nodeFile(file.name as LabName), onProgress);
    return { ...cap, model: { ...cap.model, stats: { ...cap.model.stats, ...stats } } };
  };
  runLoadMock.mockImplementation(withStats({ badLines: 2, otherEvents: { xyz: 3 }, versions: [6] }));
  render(<App />);
  await newSession('lab');
  await user.upload(await screen.findByLabelText(/capture files/i), dropped('synthetic-lab-2.jsonl'));
  const info = await screen.findByLabelText('Capture details');
  expect(info).toHaveTextContent('2 unreadable lines · other events: xyz ×3 · schema v6');
  expect(info).toHaveTextContent('older eslogger format: some checks (e.g. piped shells) may not apply');
});

test('a schema 11 capture with nothing skipped shows its version and no older-format note', async () => {
  runLoadMock.mockImplementation(async file => {
    const cap = await loadCapture(nodeFile(file.name as LabName));
    return { ...cap, model: { ...cap.model, stats: { ...cap.model.stats, versions: [11] } } };
  });
  render(<App />);
  await newSession('lab');
  await user.upload(await screen.findByLabelText(/capture files/i), dropped('synthetic-lab-2.jsonl'));
  const info = await screen.findByLabelText('Capture details');
  expect(info).toHaveTextContent('schema v11');
  expect(info).not.toHaveTextContent(/older eslogger format/);
});

test('shows load error in the drop zone', async () => {
  runLoadMock.mockRejectedValue(new Error('No eslogger events found in this file'));
  render(<App />);
  await newSession('lab');
  await user.upload(await screen.findByLabelText(/capture files/i), dropped('synthetic-lab-2.jsonl'));
  expect(await screen.findByText(/No eslogger events found/)).toBeInTheDocument();
});

test('loads a capture: header counts, tabs and placeholders', async () => {
  render(<App />);
  await newSession('lab');
  await user.upload(await screen.findByLabelText(/capture files/i), dropped('synthetic-lab-2.jsonl'));
  await headerShows('111 events');
  const group = screen.getByRole('group', { name: 'Capture counts' });
  for (const re of [/^\d+ processes$/, /^\d+ flagged$/, /^\d+ confirmed$/, /^\d+ routine hidden$/]) {
    expect(within(group).getByText(re)).toBeInTheDocument();
  }
  const queue = within(await screen.findByRole('listbox', { name: 'Flagged processes' }));
  const flagged = Number(within(group).getByText(/^\d+ flagged$/).textContent!.split(' ')[0]);
  if (flagged === 0) expect(screen.getByText(/nothing flagged/i)).toBeInTheDocument();
  else expect(queue.getAllByRole('option')).toHaveLength(flagged);
  await user.click(screen.getByRole('tab', { name: 'Tree' }));
  expect(screen.getByRole('tree', { name: 'Process tree' })).toBeInTheDocument();
  await user.click(screen.getByRole('tab', { name: 'Confirmed' }));
  expect(screen.getByText(/nothing confirmed/i)).toBeInTheDocument();
});

test('progress bar, then Analysing… once all bytes are read and until the capture arrives', async () => {
  let finish!: (c: LoadedCapture) => void;
  runLoadMock.mockImplementation((_f, onProgress) => new Promise<LoadedCapture>((res) => {
    onProgress(50, 100);
    finish = (c) => { res(c); };
  }));
  render(<App />);
  await newSession('lab');
  await user.upload(await screen.findByLabelText(/capture files/i), dropped('synthetic-lab-2.jsonl'));
  expect(await screen.findByRole('progressbar')).toHaveAttribute('value', '50');
  expect(screen.queryByText(/Analysing/)).not.toBeInTheDocument();
  const progress = runLoadMock.mock.calls[0]![1];
  act(() => { progress(100, 100); });
  expect(await screen.findByText(/Analysing…/)).toBeInTheDocument();
  await act(async () => { finish(await loadFixture('synthetic-lab-2.jsonl')); });
  await headerShows('111 events');
  expect(screen.queryByText(/Analysing/)).not.toBeInTheDocument();
});

test('a stored capture that is not loaded asks for a re-add; a matching drop restores it, another is new', async () => {
  const store = await openStore();
  const s = await store.createSession('old lab');
  const demo = await loadFixture('synthetic-lab-2.jsonl');
  const rec = (c: LoadedCapture, size = 1): CaptureRec => ({ sessionId: s.id, fingerprint: c.fingerprint, fileName: c.fileName,
    size, events: c.model.stats.events, processes: c.model.processes.size, flagged: 0, added: 't' });
  await store.upsertCapture(rec(demo));
  render(<App />);
  await user.click(await screen.findByRole('button', { name: 'old lab' }));
  expect(await screen.findByText('Re-add synthetic-lab-2.jsonl to continue')).toBeInTheDocument();

  await user.upload(screen.getByLabelText(/capture files/i), dropped('synthetic-lab-2.jsonl'));
  await headerShows('111 events');
  expect(screen.queryByText(/Re-add/)).not.toBeInTheDocument();
  expect(await store.listCaptures(s.id)).toHaveLength(1);   // same fingerprint: restored, not duplicated
  expect((await store.listCaptures(s.id))[0]!.size).toBe(demo.size);

  await user.upload(screen.getByLabelText(/capture files/i), dropped('synthetic-lab.jsonl'));
  await headerShows('111 events');
  expect(await store.listCaptures(s.id)).toHaveLength(2);
  const switcher = screen.getByLabelText(/capture/i, { selector: 'select' });
  expect(within(switcher).getAllByRole('option')).toHaveLength(2);
});

test('switching to a capture that is not loaded shows the re-add prompt instead of tabs', async () => {
  const store = await openStore();
  const s = await store.createSession('lab');
  const demo = await loadFixture('synthetic-lab-2.jsonl');
  await store.upsertCapture({ sessionId: s.id, fingerprint: 'other-fp', fileName: 'gone.jsonl', size: 1,
    events: 5, processes: 2, flagged: 0, added: 't' });
  render(<App />);
  await user.click(await screen.findByRole('button', { name: 'lab' }));
  await user.upload(await screen.findByLabelText(/capture files/i), dropped('synthetic-lab-2.jsonl'));
  await headerShows('111 events');
  await user.selectOptions(screen.getByLabelText(/capture/i, { selector: 'select' }), 'other-fp');
  expect(screen.getAllByText('Re-add gone.jsonl to continue').length).toBeGreaterThan(0);
  expect(screen.getByText(/gone\.jsonl is not loaded/)).toBeInTheDocument();
  expect(screen.queryByText(/^Triage:/)).not.toBeInTheDocument();
  expect(screen.queryByRole('group', { name: 'Capture counts' })).not.toBeInTheDocument();
  expect(demo.fingerprint).not.toBe('other-fp');
});

test('Save session, beside the session name, downloads the session while triaging', async () => {
  render(<App />);
  await newSession('lab');
  await user.upload(await screen.findByLabelText(/capture files/i), dropped('synthetic-lab-2.jsonl'));
  await headerShows('111 events');
  const clicked: string[] = [];
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) { clicked.push(this.download); });
  const before = vi.mocked(URL.createObjectURL).mock.calls.length;
  await user.click(screen.getByRole('button', { name: 'Save session' }));
  await waitFor(() => { expect(clicked).toEqual([expect.stringMatching(/^lab\.[0-9a-f]{8}\.gameleira-session\.json$/)]); });
  const saved = JSON.parse(await readBlob(vi.mocked(URL.createObjectURL).mock.calls[before]![0] as Blob)) as { format: string };
  expect(saved.format).toBe('gameleira-session');
});

test('where the browser can, Save session asks for a folder once, then saves into it without asking', async () => {
  const dir = fakeFolder('cases');
  const pick = folderBrowser(dir);
  render(<App />);
  await newSession('lab');
  expect(await screen.findByText(/The first save asks for a folder/)).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Save session' }));
  await waitFor(() => { expect(Object.keys(dir.files)).toHaveLength(1); });
  const name = Object.keys(dir.files)[0]!;
  expect(name).toMatch(/^lab\.[0-9a-f]{8}\.gameleira-session\.json$/);
  expect(JSON.parse(dir.files[name]!.text)).toMatchObject({ format: 'gameleira-session', session: { name: 'lab' } });
  expect(await screen.findByText(`Saved ${name} in “cases”.`)).toBeInTheDocument();
  expect(screen.getByText(/Saves into “cases”/)).toBeInTheDocument();
  expect(folderMemory.dir).toBe(dir);

  await user.click(screen.getByRole('button', { name: 'Save session' }));
  await screen.findByText(`Saved ${name} in “cases”.`);
  expect(pick).toHaveBeenCalledTimes(1);
  expect(Object.keys(dir.files)).toEqual([name]);   // the same file, replaced
});

test('closing the folder picker saves nothing and reports nothing', async () => {
  folderBrowser(null);
  render(<App />);
  await newSession('lab');
  await user.click(await screen.findByRole('button', { name: 'Save session' }));
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(screen.queryByText(/^Saved /)).not.toBeInTheDocument();
});

test('beside Save session, a warning says the file holds command lines until redaction is ticked on the Confirmed tab', async () => {
  render(<App />);
  await newSession('lab');
  expect(await screen.findByText(/Save session includes full command lines, which can hold secrets/)).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Confirmed tab' }));
  expect(screen.queryByText(/Save session includes/)).not.toBeInTheDocument();
  await user.click(screen.getByLabelText(/redact command-line arguments/i));
  await user.click(screen.getByRole('tab', { name: 'Triage' }));
  expect(screen.getByText('Save session redacts command-line arguments.')).toBeInTheDocument();
});

test('with more than one capture, the list of captures and their counts stays on screen after they load', async () => {
  render(<App />);
  await newSession('lab');
  await user.upload(await screen.findByLabelText(/capture files/i), dropped('synthetic-lab-2.jsonl'));
  await headerShows('111 events');
  expect(screen.queryByRole('list', { name: 'Captures' })).not.toBeInTheDocument();   // one capture: the counts above say it all
  await user.upload(screen.getByLabelText(/capture files/i), dropped('synthetic-lab.jsonl'));
  const list = within(await screen.findByRole('list', { name: 'Captures' }));
  expect(list.getAllByRole('listitem')).toHaveLength(2);
  expect(list.getByText(/^synthetic-lab-2\.jsonl · 111 events/)).toBeInTheDocument();
});

test('a file dropped on the page is a capture on Triage, and is not taken for one on the Confirmed tab', async () => {
  render(<App />);
  await newSession('lab');
  const heading = await screen.findByRole('heading', { name: 'lab' });
  const drag = () => ({ dataTransfer: { types: ['Files'], files: [dropped('synthetic-lab-2.jsonl')], dropEffect: 'copy' } });
  await user.click(screen.getByRole('tab', { name: 'Confirmed' }));
  fireEvent.dragEnter(heading, drag());
  fireEvent.dragOver(heading, drag());
  expect(document.querySelector('.sheet.over')).toBeNull();
  fireEvent.drop(heading, drag());
  expect(runLoadMock).not.toHaveBeenCalled();

  await user.click(screen.getByRole('tab', { name: 'Triage' }));
  fireEvent.drop(heading, drag());
  await headerShows('111 events');
});

test('the drop highlight stays while the drag crosses child elements, and goes when it leaves the page', async () => {
  render(<App />);
  await newSession('lab');
  await user.upload(await screen.findByLabelText(/capture files/i), dropped('synthetic-lab-2.jsonl'));
  await headerShows('111 events');
  const heading = screen.getByRole('heading', { name: 'lab' });
  const tab = screen.getByRole('tab', { name: 'Tree' });
  const drag = { dataTransfer: { types: ['Files'], files: [], dropEffect: 'copy' } };
  const lit = () => document.querySelector('.sheet.over');
  fireEvent.dragEnter(heading, drag);
  fireEvent.dragOver(heading, drag);
  expect(lit()).not.toBeNull();
  fireEvent.dragEnter(tab, drag);       // into another element, then out of the first: no relatedTarget to go by
  fireEvent.dragLeave(heading, drag);
  expect(lit()).not.toBeNull();
  fireEvent.dragLeave(tab, drag);
  expect(lit()).toBeNull();
});

test('the Sessions list holds sessions only: the import block is beside it, not an item of it', async () => {
  const store = await openStore();
  await store.createSession('one');
  render(<App />);
  await screen.findByRole('button', { name: 'one' });
  expect(within(screen.getByRole('list', { name: 'Sessions' })).getAllByRole('listitem')).toHaveLength(1);
  expect(screen.getByRole('region', { name: 'Import a session' })).toBeInTheDocument();
  expect(screen.getByText(/nothing is uploaded/)).toBeInTheDocument();
});

const seedVerdict = (sessionId: string, fingerprint: string, procKey: string, status: Verdict['status'], note: string): Verdict => ({
  sessionId, fingerprint, procKey, status, note, updated: 't',
  snapshot: { name: `proc-${procKey}`, path: `/tmp/${procKey}`, args: ['a', 'b'], ruleIds: ['r1'], severity: 'high', startTime: null },
});

test('Confirmed tab lists confirmed verdicts of every capture, labelled; export and import', async () => {
  const store = await openStore();
  const s = await store.createSession('lab');
  const base = { sessionId: s.id, size: 1, events: 1, processes: 1, flagged: 0, added: 't' };
  await store.upsertCapture({ ...base, fingerprint: 'fpA', fileName: 'monday.jsonl' });
  await store.upsertCapture({ ...base, fingerprint: 'fpB', fileName: 'tuesday.jsonl' });
  await store.setVerdict(seedVerdict(s.id, 'fpA', 'p1', 'confirmed', 'dropper from phishing'));
  await store.setVerdict(seedVerdict(s.id, 'fpB', 'p2', 'confirmed', 'same dropper again'));
  await store.setVerdict(seedVerdict(s.id, 'fpB', 'p3', 'benign', 'fine'));

  render(<App />);
  await user.click(await screen.findByRole('button', { name: 'lab' }));
  await user.click(await screen.findByRole('tab', { name: 'Confirmed' }));
  const list = within(await screen.findByRole('list', { name: 'Confirmed processes' }));
  expect(list.getAllByRole('listitem')).toHaveLength(2);
  expect(list.getByText('dropper from phishing')).toBeInTheDocument();
  expect(list.getByText('same dropper again')).toBeInTheDocument();
  expect(list.queryByText('fine')).not.toBeInTheDocument();
  expect(list.getByText('monday.jsonl')).toBeInTheDocument();
  expect(list.getByText('tuesday.jsonl')).toBeInTheDocument();

  // export: environment variables are opt-in
  const env = screen.getByLabelText(/include environment variables/i);
  expect(env).not.toBeChecked();
  const clicked: string[] = [];
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) { clicked.push(this.download); });
  await user.click(screen.getByRole('button', { name: /export session/i }));
  await waitFor(() => { expect(clicked).toHaveLength(1); });
  expect(clicked[0]).toMatch(/^lab.*\.json$/);
  const blob = vi.mocked(URL.createObjectURL).mock.calls[0]![0] as Blob;
  const exported = JSON.parse(await readBlob(blob)) as { format: string; verdicts: unknown[] };
  expect(exported.format).toBe('gameleira-session');
  expect(exported.verdicts).toHaveLength(3);

  // import creates a new session, never touches this one
  const file = new File([JSON.stringify(exported)], 'lab.json', { type: 'application/json' });
  await user.upload(screen.getByLabelText(/import session/i), file);
  expect(await screen.findByText(/Imported as “lab \(imported\)”/)).toBeInTheDocument();
  expect((await store.listSessions()).map(x => x.name).sort()).toEqual(['lab', 'lab (imported)']);
});

test('the export says it carries command lines (which can hold secrets), and "Redact command-line arguments" strips them', async () => {
  const store = await openStore();
  const s = await store.createSession('lab');
  await store.upsertCapture({ sessionId: s.id, fingerprint: 'fpA', fileName: 'monday.jsonl', size: 1, events: 1, processes: 1, flagged: 0, added: 't' });
  const v = seedVerdict(s.id, 'fpA', 'p1', 'confirmed', 'x');
  await store.setVerdict({ ...v, snapshot: { ...v.snapshot, args: ['dscl', '.', '-authonly', 'labuser', 'hunter2'] } });
  render(<App />);
  await user.click(await screen.findByRole('button', { name: 'lab' }));
  await user.click(await screen.findByRole('tab', { name: 'Confirmed' }));
  expect(screen.getByText(/full command line/i)).toHaveTextContent(/secrets such as passwords/);
  const redact = screen.getByLabelText(/redact command-line arguments/i);
  expect(redact).not.toBeChecked();
  const exportText = async (nth: number): Promise<string> => {
    await user.click(screen.getByRole('button', { name: /export session/i }));
    await waitFor(() => { expect(vi.mocked(URL.createObjectURL).mock.calls.length).toBeGreaterThan(nth); });
    return readBlob(vi.mocked(URL.createObjectURL).mock.calls[nth]![0] as Blob);
  };
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
  expect(await exportText(0)).toContain('hunter2');
  await user.click(redact);
  const redacted = await exportText(1);
  expect(redacted).not.toContain('hunter2');
  expect(redacted).toContain('[redacted]');
  // the Confirmed list itself still shows what is stored
  expect(screen.getByText(/hunter2/)).toBeInTheDocument();
});

test('import shows the error for a file that is not a session export', async () => {
  render(<App />);
  await newSession('lab');
  await user.click(await screen.findByRole('tab', { name: 'Confirmed' }));
  await user.upload(screen.getByLabelText(/import session/i), new File(['{"nope":1}'], 'x.json'));
  expect(await screen.findByText(/not a Gameleira session export/)).toBeInTheDocument();
});

function Boom(): never { throw new Error('boom'); }

test('an error in a screen shows a reload message and leaves stored sessions alone', async () => {
  const store = await openStore();
  const s = await store.createSession('keep me');
  await store.upsertCapture({ sessionId: s.id, fingerprint: 'fp', fileName: 'a.jsonl', size: 1, events: 1, processes: 1, flagged: 0, added: 't' });
  await store.setVerdict(seedVerdict(s.id, 'fp', 'p1', 'confirmed', 'note'));
  vi.spyOn(console, 'error').mockImplementation(() => undefined);   // React logs the caught error
  const reload = vi.fn();
  render(<ErrorBoundary onReload={reload}><Boom /></ErrorBoundary>);
  expect(screen.getByRole('alert')).toHaveTextContent('Something went wrong — reload. Your saved sessions are kept in this browser. A change you made in the last few seconds may not have been saved.');
  await user.click(screen.getByRole('button', { name: 'Reload' }));
  expect(reload).toHaveBeenCalledTimes(1);
  expect((await store.listSessions()).map(x => x.name)).toEqual(['keep me']);
  expect(await store.listVerdicts(s.id)).toHaveLength(1);
});

test('App shows the boundary instead of a blank page when a screen throws', async () => {
  const real = await openStore();
  const store = new Proxy(real, { get: (t, k: string) => (k === 'listSessions' ? () => Promise.resolve([{ id: 'x', name: { not: 'text' }, created: 't', updated: 't' }]) : t[k as keyof Store]) });
  vi.spyOn(console, 'error').mockImplementation(() => undefined);
  render(<App store={store as Store} />);
  expect(await screen.findByRole('alert')).toHaveTextContent(/Something went wrong — reload\. Your saved sessions are kept in this browser\. A change you made in the last few seconds may not have been saved\./);
  expect(screen.getByRole('button', { name: 'Reload' })).toBeInTheDocument();
});

test('start screen: rename and delete (with confirm); storage footer', async () => {
  const store = await openStore();
  const s = await store.createSession('one');
  await store.createSession('two');
  render(<App />);
  expect(await screen.findByText(/Storage: best-effort/)).toBeInTheDocument();
  await user.click(await screen.findByRole('button', { name: 'Rename one' }));
  const input = screen.getByLabelText(/new name/i);
  await user.clear(input);
  await user.type(input, 'uno{enter}');
  expect(await screen.findByRole('button', { name: 'uno' })).toBeInTheDocument();
  expect((await store.listSessions()).find(x => x.id === s.id)!.name).toBe('uno');

  vi.mocked(window.confirm).mockReturnValueOnce(false);
  await user.click(screen.getByRole('button', { name: 'Delete uno' }));
  expect(await store.listSessions()).toHaveLength(2);
  await user.click(screen.getByRole('button', { name: 'Delete uno' }));
  await waitFor(() => { expect(screen.queryByRole('button', { name: 'uno' })).not.toBeInTheDocument(); });
  expect(await store.listSessions()).toHaveLength(1);
});

test('persist() is requested once, when the first session is created', async () => {
  const persist = vi.fn().mockResolvedValue(true);
  Object.defineProperty(navigator, 'storage', { configurable: true, value: { persist, persisted: vi.fn().mockResolvedValue(true) } });
  render(<App />);
  expect(await screen.findByText(/Storage: persistent/)).toBeInTheDocument();
  await newSession('first');
  await screen.findByText(CMD);
  expect(persist).toHaveBeenCalledTimes(1);
  await user.click(screen.getByRole('button', { name: /sessions/i }));
  await newSession('second');
  await screen.findByText(CMD);
  expect(persist).toHaveBeenCalledTimes(1);
});

test('a persist() failure is ignored', async () => {
  Object.defineProperty(navigator, 'storage', { configurable: true,
    value: { persist: vi.fn().mockRejectedValue(new Error('no')), persisted: vi.fn().mockResolvedValue(false) } });
  render(<App />);
  await newSession('first');
  expect(await screen.findByRole('heading', { name: 'first' })).toBeInTheDocument();
  expect(screen.getByText(CMD)).toBeInTheDocument();
});

// --- SessionContext -------------------------------------------------------------------------------------------

const readBlob = (b: Blob): Promise<string> => new Promise((res, rej) => {
  const fr = new FileReader();
  fr.onload = () => { res(String(fr.result)); };
  fr.onerror = () => { rej(fr.error); };
  fr.readAsText(b);
});

let ctx: SessionCtx;
function Probe() { ctx = useSession(); return null; }
function Header() { return <span data-testid="hidden">{useSession().triage?.hiddenCount ?? 0} routine hidden</span>; }

async function withSession(name: LabName = 'synthetic-lab.jsonl'): Promise<{ store: Store; sessionId: string; demo: LoadedCapture }> {
  const store = await openStore();
  const s = await store.createSession('ctx');
  render(<SessionProvider store={store}><Probe /></SessionProvider>);
  await waitFor(() => { expect(ctx).toBeDefined(); });
  await act(async () => { await ctx.openSession(s.id); });
  await act(async () => { await ctx.loadFiles([dropped(name)]); });
  const demo = ctx.captures.get(ctx.active!)!;
  return { store, sessionId: s.id, demo };
}

const img = (over: Partial<Image>): Image => ({
  token: '1:1', path: null, signingId: null, teamId: null, isPlatform: false, csFlags: 0,
  args: null, cwd: null, env: null, stdinIsPipe: null, script: null, time: null, seq: 0, inherited: false, ...over,
});

test('setVerdict stores a snapshot, keeps the note when omitted, and bumps session.updated', async () => {
  const { store, sessionId, demo } = await withSession();
  const before = (await store.listSessions())[0]!.updated;
  const flagged = demo.analysis.queue.find(q => q.kind === 'process')!;
  const procId = flagged.procId!;
  await new Promise(r => setTimeout(r, 5));
  await act(async () => { await ctx.setVerdict(procId, 'confirmed', 'looks bad'); });
  const [v] = await store.listVerdicts(sessionId, demo.fingerprint);
  expect(v).toMatchObject({ procKey: procId, status: 'confirmed', note: 'looks bad' });
  expect(v!.snapshot.name).toBeTruthy();
  expect(v!.snapshot.ruleIds.length).toBeGreaterThan(0);
  expect(v!.snapshot.severity).toBe(flagged.severity);
  expect(ctx.verdicts.get(procId)?.status).toBe('confirmed');
  expect((await store.listSessions())[0]!.updated > before).toBe(true);

  await act(async () => { await ctx.setVerdict(procId, 'benign'); });   // note omitted: kept
  expect((await store.listVerdicts(sessionId, demo.fingerprint))[0]).toMatchObject({ status: 'benign', note: 'looks bad' });
});

test('addRoutine refuses an image without identity and asks before a risky one', async () => {
  const { store, sessionId } = await withSession();
  await act(async () => { await ctx.addRoutine(img({})); });
  expect(window.confirm).not.toHaveBeenCalled();
  expect(await store.listRoutine(sessionId)).toHaveLength(0);

  const bash = img({ path: '/bin/bash', signingId: 'com.apple.bash', teamId: null });
  vi.mocked(window.confirm).mockReturnValueOnce(false);
  await act(async () => { await ctx.addRoutine(bash); });
  expect(window.confirm).toHaveBeenCalledTimes(1);
  expect(await store.listRoutine(sessionId)).toHaveLength(0);

  await act(async () => { await ctx.addRoutine(bash); });   // confirm() → true
  expect(await store.listRoutine(sessionId)).toHaveLength(1);
  expect(ctx.routineKeys.has('com.apple.bash|-|/bin/bash')).toBe(true);

  const calm = img({ path: '/Applications/Foo.app/Contents/MacOS/Foo', signingId: 'com.foo', teamId: 'ABCDE12345' });
  await act(async () => { await ctx.addRoutine(calm); });
  expect(window.confirm).toHaveBeenCalledTimes(2);   // no extra prompt for a non-risky program
  expect(ctx.routineKeys.size).toBe(2);

  await act(async () => { await ctx.removeRoutine('com.apple.bash|-|/bin/bash'); });
  expect(ctx.routineKeys.has('com.apple.bash|-|/bin/bash')).toBe(false);
  expect(await store.listRoutine(sessionId)).toHaveLength(1);
});

test('selectProc and showInTree', async () => {
  await withSession();
  act(() => { ctx.selectProc('1:1'); });
  expect(ctx.selected).toBe('1:1');
  expect(ctx.view).toBe('triage');
  act(() => { ctx.showInTree('2:2'); });
  expect(ctx.selected).toBe('2:2');
  expect(ctx.view).toBe('tree');
});

test('routine marks hide queue items; the count shows in the header', async () => {
  const store = await openStore();
  const s = await store.createSession('ctx');
  render(<SessionProvider store={store}><Probe /><Header /></SessionProvider>);
  await waitFor(() => { expect(ctx).toBeDefined(); });
  await act(async () => { await ctx.openSession(s.id); });
  await act(async () => { await ctx.loadFiles([dropped('synthetic-lab.jsonl')]); });
  const cap = ctx.captures.get(ctx.active!)!;
  // A row a routine mark may hide: neither high nor persistence (those stay visible).
  const item = cap.analysis.queue.find(q => q.kind === 'process' && keepReason(q) === null && latestImage(cap.model.processes.get(q.procId!)!)?.path)!;
  const total = ctx.triage!.queue.length;
  expect(ctx.triage!.hiddenCount).toBe(0);
  await act(async () => { await ctx.addRoutine(latestImage(cap.model.processes.get(item.procId!)!)!); });
  expect(ctx.triage!.hiddenCount).toBeGreaterThan(0);
  expect(ctx.triage!.queue.length + ctx.triage!.hiddenCount).toBe(total);
  expect(screen.getByTestId('hidden')).toHaveTextContent(`${ctx.triage!.hiddenCount} routine hidden`);
});

// --- loads that outlive their session ----------------------------------------------------------------------------------------------

test('a load that finishes after leaving the session writes nothing and leaves no progress behind', async () => {
  const store = await openStore();
  const a = await store.createSession('a');
  const b = await store.createSession('b');
  let report!: (bytes: number, total: number) => void;
  let finish!: (c: LoadedCapture) => void;
  runLoadMock.mockImplementation((_f, onProgress) => new Promise<LoadedCapture>((res) => { report = onProgress; finish = res; }));
  render(<SessionProvider store={store}><Probe /></SessionProvider>);
  await waitFor(() => { expect(ctx).toBeDefined(); });
  await act(async () => { await ctx.openSession(a.id); });
  let loading!: Promise<void>;
  await act(async () => { loading = ctx.loadFiles([dropped('synthetic-lab-2.jsonl')]); });
  expect(ctx.progress).not.toBeNull();

  act(() => { ctx.closeSession(); });          // "← Sessions"
  await act(async () => { await ctx.openSession(b.id); });   // …and into another session
  const demo = await loadFixture('synthetic-lab-2.jsonl');
  await act(async () => { report(100, 100); finish(demo); await loading; });

  expect(ctx.progress).toBeNull();
  expect(ctx.session!.id).toBe(b.id);
  expect(ctx.capRecs).toHaveLength(0);
  expect(ctx.captures.size).toBe(0);
  expect(await store.listCaptures(a.id)).toHaveLength(0);
  expect(await store.listCaptures(b.id)).toHaveLength(0);
});

test('a queued load of the old session is skipped and does not clear the new session\'s error', async () => {
  const store = await openStore();
  const a = await store.createSession('a');
  const b = await store.createSession('b');
  let finish!: (c: LoadedCapture) => void;
  runLoadMock.mockImplementationOnce(() => new Promise<LoadedCapture>((res) => { finish = res; }));
  render(<SessionProvider store={store}><Probe /></SessionProvider>);
  await waitFor(() => { expect(ctx).toBeDefined(); });
  await act(async () => { await ctx.openSession(a.id); });
  let first!: Promise<void>; let second!: Promise<void>;
  await act(async () => {
    first = ctx.loadFiles([dropped('synthetic-lab-2.jsonl')]);
    second = ctx.loadFiles([dropped('synthetic-lab.jsonl')]);   // queued behind the first
  });
  act(() => { ctx.closeSession(); });
  await act(async () => { await ctx.openSession(b.id); });
  runLoadMock.mockRejectedValueOnce(new Error('boom in b'));
  await act(async () => { void ctx.loadFiles([dropped('synthetic-lab.jsonl')]); });
  await act(async () => { finish(await loadFixture('synthetic-lab-2.jsonl')); await first; await second; });
  expect(runLoadMock).toHaveBeenCalledTimes(2);   // a's queued second run never started
  expect(await store.listCaptures(a.id)).toHaveLength(0);
  expect(ctx.loadError).toBe('boom in b');
});

/** A store whose listed methods fail. */
const failing = async (fail: Partial<Record<keyof Store, string>>): Promise<Store> => {
  const real = await openStore();
  return new Proxy(real, {
    get: (t, k: string) => (k in fail
      ? () => Promise.reject(new Error(fail[k as keyof Store]))
      : t[k as keyof Store]),
  });
};

test('a failing setVerdict shows a banner and does not pretend the verdict was saved', async () => {
  const real = await openStore();
  const s = await real.createSession('ctx');
  const store = await failing({ setVerdict: 'quota exceeded' });
  render(<SessionProvider store={store}><Probe /><StoreErrorBanner /></SessionProvider>);
  await waitFor(() => { expect(ctx).toBeDefined(); });
  await act(async () => { await ctx.openSession(s.id); });
  await act(async () => { await ctx.loadFiles([dropped('synthetic-lab.jsonl')]); });
  const cap = ctx.captures.get(ctx.active!)!;
  const procId = cap.analysis.queue.find(q => q.kind === 'process')!.procId!;
  await act(async () => { await ctx.setVerdict(procId, 'confirmed', 'n'); });
  expect(await screen.findByRole('alert')).toHaveTextContent(/Could not save the verdict: quota exceeded/);
  expect(ctx.verdicts.size).toBe(0);
  await user.click(screen.getByRole('button', { name: 'Dismiss' }));
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

test('a failing touchSession is best-effort: the verdict is saved and shown, no banner', async () => {
  const real = await openStore();
  const s = await real.createSession('ctx');
  const store = await failing({ touchSession: 'nope' });
  render(<SessionProvider store={store}><Probe /><StoreErrorBanner /></SessionProvider>);
  await waitFor(() => { expect(ctx).toBeDefined(); });
  await act(async () => { await ctx.openSession(s.id); });
  await act(async () => { await ctx.loadFiles([dropped('synthetic-lab.jsonl')]); });
  const procId = ctx.capture!.analysis.queue.find(q => q.kind === 'process')!.procId!;
  await act(async () => { await ctx.setVerdict(procId, 'confirmed'); });
  expect(ctx.verdicts.get(procId)?.status).toBe('confirmed');
  expect(await real.listVerdicts(s.id)).toHaveLength(1);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

test('a failing listSessions shows the error, not "No sessions yet"', async () => {
  const store = await failing({ listSessions: 'IDB is broken' });
  render(<App store={store} />);
  expect(await screen.findByRole('alert')).toHaveTextContent(/Could not read sessions: IDB is broken/);
  expect(screen.queryByText(/No sessions yet/)).not.toBeInTheDocument();
});

test('a failing createSession shows a banner on the start screen', async () => {
  const store = await failing({ createSession: 'disk full' });
  render(<App store={store} />);
  await newSession('x');
  expect(await screen.findByRole('alert')).toHaveTextContent(/Could not create the session: disk full/);
});

test('two setVerdict calls in one tick keep the note', async () => {
  const { store, sessionId, demo } = await withSession();
  const procId = demo.analysis.queue.find(q => q.kind === 'process')!.procId!;
  await act(async () => {
    const a = ctx.setVerdict(procId, 'confirmed', 'dropper');
    const b = ctx.setVerdict(procId, 'benign');   // note omitted: must keep 'dropper'
    await Promise.all([a, b]);
  });
  expect(await store.listVerdicts(sessionId, demo.fingerprint)).toMatchObject([{ status: 'benign', note: 'dropper' }]);
  expect(ctx.verdicts.get(procId)).toMatchObject({ status: 'benign', note: 'dropper' });
});

// --- fix: loaded-capture budget, writes that read the verdict when they run -----------------------------------------

/** The session screen once a session is open (it assumes one). */
function Gate() { return useSession().session ? <SessionScreen /> : null; }

async function openWith(store: Store, maxLoadedBytes?: number): Promise<string> {
  const s = await store.createSession('ctx');
  render(<SessionProvider store={store} maxLoadedBytes={maxLoadedBytes}><Probe /><Gate /></SessionProvider>);
  await waitFor(() => { expect(ctx).toBeDefined(); });
  await act(async () => { await ctx.openSession(s.id); });
  return s.id;
}
const drop = (name: LabName): Promise<void> => act(async () => { await ctx.loadFiles([dropped(name)]); });

test('loaded captures stay within the budget: the least recently used goes, the active one never does', async () => {
  const store = await openStore();
  await openWith(store, 400_000);   // two 176 KB labs fit; a third does not
  await drop('synthetic-lab.jsonl');
  const first = ctx.active!;
  await drop('synthetic-lab-3.jsonl');
  const second = ctx.active!;
  expect([...ctx.captures.keys()]).toEqual([first, second]);
  act(() => { ctx.setActive(first); });   // the first is now the most recently used
  await drop('synthetic-lab-2.jsonl');
  const third = ctx.active!;
  expect([...ctx.captures.keys()].sort()).toEqual([first, third].sort());   // the second went, not the first
  expect(ctx.capRecs).toHaveLength(3);   // still recorded: only the parsed copy is dropped
  expect(await screen.findByText('Re-add synthetic-lab-3.jsonl to continue')).toBeInTheDocument();
  expect(ctx.capture).not.toBeNull();
}, 60_000);

test('a capture that alone is over the budget is kept while it is on screen', async () => {
  await openWith(await openStore(), 1000);
  await drop('synthetic-lab.jsonl');
  expect(ctx.captures.size).toBe(1);
  expect(ctx.capture).not.toBeNull();
}, 60_000);

test('a note typed on a capture that then gets evicted is still saved to it', async () => {
  const store = await openStore();
  const sid = await openWith(store, 300_000);   // two labs do not fit together
  await drop('synthetic-lab.jsonl');
  const a = ctx.active!;
  await user.click(await firstQueueRow());
  await user.type(screen.getByLabelText(/note/i), 'typed before the eviction');
  await drop('synthetic-lab-3.jsonl');   // evicts the first, and unmounts the note field that has not saved yet
  expect(ctx.captures.has(a)).toBe(false);
  await waitFor(async () => { expect(await store.listVerdicts(sid, a)).toMatchObject([{ note: 'typed before the eviction', status: 'unreviewed' }]); });
}, 60_000);

/** A store whose first verdict write waits for `release()`; later writes are applied in the order they were issued. */
async function heldStore(): Promise<{ store: Store; real: Store; release(): void; writes: string[] }> {
  const real = await openStore();
  let release!: () => void;
  const gate = new Promise<void>(r => { release = r; });
  const writes: string[] = [];
  let n = 0;
  const store = new Proxy(real, {
    get: (t, k: string) => (k === 'setVerdict'
      ? async (v: Verdict) => {
        if (n++ === 0) await gate;
        writes.push(`${v.status}:${v.note}`);
        return t.setVerdict(v);
      }
      : t[k as keyof Store]),
  });
  return { store, real, release, writes };
}
/** The first row of the queue (the capture drop-down has options too, so the list is picked by its role). */
const firstQueueRow = async (): Promise<HTMLElement> => within(await screen.findByRole('listbox', { name: /flagged/i })).getAllByRole('option')[0]!;
const firstProc = (): string => ctx.capture!.analysis.queue.find(q => q.kind === 'process')!.procId!;

test('a note saved while a verdict write is still held keeps the verdict, and the store ends on the last write', async () => {
  const { store, real, release, writes } = await heldStore();
  const sid = await openWith(store);
  await drop('synthetic-lab.jsonl');
  const id = firstProc();
  const fp = ctx.active!;
  await act(async () => {
    const confirm = ctx.toggleVerdict(id, 'confirmed');   // the store holds this write
    const note = ctx.setNote(id, 'dropper', fp);          // the rendered status is still "unreviewed"; the verdict is not
    release();
    await Promise.all([confirm, note]);
  });
  expect(await real.listVerdicts(sid, fp)).toMatchObject([{ status: 'confirmed', note: 'dropper' }]);
  expect(writes).toEqual(['confirmed:', 'confirmed:dropper']);   // in order: the older write cannot land last
  expect(ctx.verdicts.get(id)).toMatchObject({ status: 'confirmed', note: 'dropper' });
}, 60_000);

test('pressing a verdict twice while its first write is held toggles back, whatever is rendered', async () => {
  const { store, real, release } = await heldStore();
  const sid = await openWith(store);
  await drop('synthetic-lab.jsonl');
  const id = firstProc();
  await act(async () => {
    const a = ctx.toggleVerdict(id, 'confirmed');
    const b = ctx.toggleVerdict(id, 'confirmed');
    release();
    await Promise.all([a, b]);
  });
  expect(await real.listVerdicts(sid)).toMatchObject([{ status: 'unreviewed' }]);
}, 60_000);

test('the c key twice under a held write ends unreviewed in the store', async () => {
  const { store, real, release } = await heldStore();
  const sid = await openWith(store);
  await drop('synthetic-lab.jsonl');
  await user.click(await firstQueueRow());
  await user.keyboard('cc');
  release();
  await waitFor(async () => { expect(await real.listVerdicts(sid)).toMatchObject([{ status: 'unreviewed' }]); });
}, 60_000);

// --- Triage view --------------------------------------------------------------------------------------

let labLoad: Promise<LoadedCapture> | undefined;
/** Parse the synthetic lab once for every triage test. */
const loadLab = (): Promise<LoadedCapture> => (labLoad ??= loadFixture('synthetic-lab.jsonl'));

interface Mocks { setVerdict: ReturnType<typeof vi.fn>; setNote: ReturnType<typeof vi.fn>; addRoutine: ReturnType<typeof vi.fn>;
  removeRoutine: ReturnType<typeof vi.fn>; showInTree: ReturnType<typeof vi.fn> }

/** TriageView on a loaded capture with a real `selected` state; verdict writes are mocks that update the shown verdicts. */
function renderTriage(cap: LoadedCapture, opts: { routineKeys?: Set<string> } = {}): Mocks {
  const mocks: Mocks = { setVerdict: vi.fn(), setNote: vi.fn(), addRoutine: vi.fn().mockResolvedValue(true), removeRoutine: vi.fn(), showInTree: vi.fn() };
  const routineKeys = opts.routineKeys ?? new Set<string>();
  function Harness() {
    const [selected, setSelected] = useState<string | null>(null);
    const [selectedItem, setSelectedItem] = useState<string | null>(null);
    const [verdicts, setVerdicts] = useState(new Map<string, Verdict>());
    const [triageFilters, setFilters] = useState(DEFAULT_FILTERS);
    const triage = useMemo(() => applyRoutine(cap.analysis, cap.model, routineKeys), []);
    mocks.setVerdict.mockImplementation((id: string, status: Status, note?: string) => {
      setVerdicts(m => new Map(m).set(id, { ...seedVerdict('s', cap.fingerprint, id, status, note ?? m.get(id)?.note ?? '') }));
      return Promise.resolve();
    });
    mocks.setNote.mockImplementation((id: string, note: string) => {
      setVerdicts(m => new Map(m).set(id, { ...seedVerdict('s', cap.fingerprint, id, m.get(id)?.status ?? 'unreviewed', note) }));
      return Promise.resolve();
    });
    // The real toggle reads the status when it runs; here the harness's current verdicts stand in for that.
    const toggleVerdict = (id: string, pressed: 'confirmed' | 'benign') =>
      (mocks.setVerdict as (...a: unknown[]) => unknown)(id, toggleStatus(verdicts.get(id)?.status ?? 'unreviewed', pressed), undefined);
    const value = { capture: cap, active: cap.fingerprint, captures: new Map([[cap.fingerprint, cap]]), triage, verdicts,
      routineKeys, selected, selectedItem, toggleVerdict,
      selectProc: (id: string | null) => { setSelected(id); setSelectedItem(null); },
      selectItem: (key: string) => { setSelected(null); setSelectedItem(key); }, triageFilters,
      updateTriageFilters: (patch: Partial<TriageFilters>) => { setFilters(f => ({ ...f, ...patch })); }, ...mocks } as unknown as SessionCtx;
    return <SessionContext.Provider value={value}><TriageView /></SessionContext.Provider>;
  }
  render(<Harness />);
  return mocks;
}

const osascriptId = async (): Promise<string> => procByPid((await loadLab()).model, 7006).id;

test('queue sorted high first and fake prompt explains itself', async () => {
  renderTriage(await loadLab());
  const rows = await screen.findAllByRole('option');
  expect(within(rows[0]!).getByText('high')).toBeInTheDocument();
  await user.click(screen.getByText(/display dialog/));
  expect(screen.getByText(/fake a system password prompt/i)).toBeInTheDocument();
  expect(screen.getByText(/T1056\.002/)).toBeInTheDocument();
}, 60_000);

test('launched-by chain ends in ghost label', async () => {
  renderTriage(await loadLab());
  await user.click(screen.getByText(/display dialog/));
  expect(screen.getByText('pid 6120 · started before capture')).toBeInTheDocument();
}, 60_000);

const pickRow = async (text: string): Promise<void> => {
  const row = (await screen.findAllByRole('option')).find(r => r.querySelector('.qname')?.textContent === text)!;
  await user.click(row);
};
const rootList = (name: RegExp) => screen.queryByRole('list', { name });

test('roots: a root that agrees with the original parent is named once, not drawn twice', async () => {
  renderTriage(await loadLab());
  await pickRow('osascript');
  expect(rootList(/^launch chain/i)).toBeInTheDocument();
  expect(rootList(/^responsible chain/i)).toBeInTheDocument();
  expect(rootList(/^current-parent chain/i)).not.toBeInTheDocument();
  expect(screen.getByText(/The current parent is the same chain\./)).toBeInTheDocument();
}, 60_000);

test('roots: an orphan shows all three, its current parent ending at launchd', async () => {
  renderTriage(await loadLab());
  await pickRow('sleep');
  const current = rootList(/^current-parent chain/i)!;
  expect(within(current).getByRole('button', { name: 'launchd' })).toBeInTheDocument();
  expect(rootList(/^launch chain/i)).toBeInTheDocument();
  expect(rootList(/^responsible chain/i)).toBeInTheDocument();
  expect(screen.queryByText(/same chain/)).not.toBeInTheDocument();
}, 60_000);

test('roots: a process with no responsible process says so', async () => {
  renderTriage(await loadLab());
  await pickRow('Installer');
  expect(rootList(/^responsible chain/i)).not.toBeInTheDocument();
  expect(screen.getByText(/No responsible recorded\./)).toBeInTheDocument();
}, 60_000);

test('before a row is picked, the pane counts the unreviewed rows by severity', async () => {
  const cap = await loadLab();
  renderTriage(cap);
  const rows = await screen.findAllByRole('option');
  const n = rows.length;
  expect(screen.getByText(`of ${n} flagged rows are unreviewed`, { exact: false })).toBeInTheDocument();
  const high = cap.analysis.queue.filter(q => q.severity === 'high').length;
  const split = document.querySelector('.sev-split')!;
  expect(split.textContent).toContain(`high ${high}`);
}, 60_000);

test('confirm via keyboard persists verdict', async () => {
  const { setVerdict } = renderTriage(await loadLab());
  await user.click(screen.getByText(/display dialog/));
  await user.keyboard('c');
  expect(setVerdict).toHaveBeenCalledWith(await osascriptId(), 'confirmed', undefined);
  expect(await osascriptId()).toBe('7006:9051');
}, 60_000);

test('long args truncate in queue row', async () => {
  renderTriage(await loadLab());
  const row = (await screen.findAllByRole('option'))[0]!;
  expect(row.querySelector('.args')).toHaveClass('truncate');   // jsdom doesn't load styles.css; .truncate carries text-overflow: ellipsis
}, 60_000);

test('rows: persistence-only row, status icon, no in-chain badge; nothing is selected until the user picks a row', async () => {
  renderTriage(await loadLab());
  const rows = await screen.findAllByRole('option');
  expect(rows.some(r => r.textContent?.includes('persistence: com.example.updater.wake.plist'))).toBe(true);
  const whoami = rows.find(r => r.textContent?.includes('whoami'))!;
  expect(within(whoami).queryByText('in chain')).not.toBeInTheDocument();
  expect(rows.every(r => r.getAttribute('aria-selected') === 'false')).toBe(true);
  expect(screen.getByText(/select a flagged process/i)).toBeInTheDocument();
}, 60_000);

test('"Show only in-chain processes" keeps exactly the rows queued for sitting in a flagged chain', async () => {
  const cap = await loadLab();
  renderTriage(cap);
  const all = (await screen.findAllByRole('option')).length;
  await user.click(screen.getByRole('checkbox', { name: /show only in-chain processes/i }));
  const names = screen.getAllByRole('option').map(r => r.querySelector('.qname')!.textContent);
  const inChain = cap.analysis.queue.filter(q => q.inFlaggedChain).length;
  expect(names).toHaveLength(inChain);
  expect(inChain).toBeGreaterThan(0);
  expect(inChain).toBeLessThan(all);
  expect(names).toContain('whoami');
}, 60_000);

test('detail sections: why, launched by, details, what it did, actions', async () => {
  renderTriage(await loadLab());
  await user.click(screen.getByText(/display dialog/));
  for (const h of [/why flagged/i, /launched by/i, /^details$/i, /what it did/i, /^actions$/i]) {
    expect(screen.getByRole('heading', { name: h })).toBeInTheDocument();
  }
  expect(screen.getByText('com.apple.osascript')).toBeInTheDocument();
  for (const b of [/confirm suspicious/i, /benign/i, /treat as routine/i, /show in tree/i]) {
    expect(screen.getByRole('button', { name: b })).toBeInTheDocument();
  }
  expect(screen.getByLabelText(/note/i)).toBeInTheDocument();
}, 60_000);

test('a chain step selects that process; an unflagged one has an empty Why flagged', async () => {
  renderTriage(await loadLab());
  await user.click(screen.getByText(/display dialog/));
  const steps = within(screen.getByRole('list', { name: /launch chain/i })).getAllByRole('button');
  await user.click(steps[steps.length - 1]!);   // the nearest ancestor (a shell)
  expect(screen.getByText(/not flagged on its own/i)).toBeInTheDocument();
  expect(screen.queryByText(/fake a system password prompt/i)).not.toBeInTheDocument();
}, 60_000);

test('keys: j/k move, b marks benign, t shows in tree, n focuses the note; typing in a field is not a command', async () => {
  const { setVerdict, showInTree } = renderTriage(await loadLab());
  const sel = () => screen.getAllByRole('option').findIndex(r => r.getAttribute('aria-selected') === 'true');
  await user.keyboard('j');
  expect(sel()).toBe(0);
  await user.keyboard('jj');
  expect(sel()).toBe(2);
  await user.keyboard('k');
  expect(sel()).toBe(1);
  await user.keyboard('{ArrowDown}');
  expect(sel()).toBe(2);
  await user.keyboard('b');
  expect(setVerdict).toHaveBeenCalledWith(expect.any(String), 'benign', undefined);
  await user.keyboard('t');
  expect(showInTree).toHaveBeenCalledTimes(1);
  await user.keyboard('n');
  expect(screen.getByLabelText(/note/i)).toHaveFocus();
  expect(screen.getByLabelText(/note/i)).toHaveValue('');   // the letter n was not typed into it

  setVerdict.mockClear();
  await user.type(screen.getByRole('textbox', { name: /search/i }), 'cbn');
  expect(setVerdict).not.toHaveBeenCalled();
}, 60_000);

test('keys still work after clicking a filter (radios and checkboxes keep focus)', async () => {
  renderTriage(await loadLab());
  const sel = () => screen.getAllByRole('option').findIndex(r => r.getAttribute('aria-selected') === 'true');
  await user.click(screen.getByRole('radio', { name: /^unreviewed$/i }));
  await user.keyboard('j');
  expect(sel()).toBe(0);
  await user.click(screen.getByRole('checkbox', { name: 'low' }));
  await user.keyboard('j');
  expect(sel()).toBe(1);
}, 60_000);

test('persistence-only item: paths, no tree or routine, verdict keyed by its queue key', async () => {
  const cap = await loadLab();
  const { setVerdict } = renderTriage(cap);
  const row = (await screen.findAllByRole('option')).find(r => r.textContent?.includes('updater.wake.plist'))!;
  await user.click(row);
  const detail = within(screen.getByRole('region', { name: /selected process/i }));
  expect(detail.getByText(/^\/Users\/[^/]+\/Library\/LaunchAgents\/com\.example\.updater\.wake\.plist$/)).toBeInTheDocument();
  expect(detail.getByText('Runs').nextElementSibling).toHaveTextContent(/Updater\/Current\/Updater\.app\/Contents\/MacOS\/Updater$/);
  expect(detail.getByText('App').nextElementSibling).toHaveTextContent(/1\.2\.3\/Updater\.app/);
  expect(detail.getByText(/Registered a launch agent for this user: launchd loads it/)).toBeInTheDocument();
  expect(detail.queryByRole('button', { name: /show in tree/i })).not.toBeInTheDocument();
  expect(detail.queryByRole('button', { name: /routine/i })).not.toBeInTheDocument();
  await user.keyboard('c');
  expect(setVerdict).toHaveBeenCalledWith(cap.analysis.queue.find(q => q.kind === 'persistence')!.key, 'confirmed', undefined);
}, 60_000);

/** Index of the selected row, and the visible text of every row, in order. */
const queueState = (): { sel: number; names: string[] } => {
  const rows = within(screen.getByRole('listbox', { name: /flagged/i })).getAllByRole('option');
  return { sel: rows.findIndex(r => r.getAttribute('aria-selected') === 'true'), names: rows.map(r => r.querySelector('.qname')!.textContent!) };
};

test('confirming under the unreviewed filter keeps your place: j goes to the row that took its place, k to the one before', async () => {
  renderTriage(await loadLab());
  await user.click(screen.getByRole('radio', { name: /^unreviewed$/i }));
  const before = queueState();
  await user.click(screen.getAllByRole('option')[2]!);
  expect(queueState().sel).toBe(2);
  await user.keyboard('c');
  const after = queueState();
  expect(after.names).toHaveLength(before.names.length - 1);   // the confirmed row left the list
  expect(after.sel).toBe(-1);
  expect(screen.getByText('Confirmed suspicious')).toBeInTheDocument();   // …and the pane still shows the verdict you just set
  await user.keyboard('j');
  expect(queueState().sel).toBe(2);
  expect(queueState().names[2]).toBe(before.names[3]);   // the row that took its place
  // same again, going up
  await user.keyboard('c');
  await user.keyboard('k');
  expect(queueState().sel).toBe(1);
}, 60_000);

test('c then n then typing under the unreviewed filter puts the note on the process you confirmed', async () => {
  const cap = await loadLab();
  const { setNote } = renderTriage(cap);
  await user.click(screen.getByRole('radio', { name: /^unreviewed$/i }));
  await user.click(screen.getAllByRole('option')[2]!);
  const id = cap.analysis.queue[2]!.procId!;   // third row of the unreviewed list = third of the queue
  await user.keyboard('c');
  await user.keyboard('n');
  await user.keyboard('seen in the capture');
  await user.tab();
  expect(setNote).toHaveBeenCalledTimes(1);
  expect(setNote).toHaveBeenCalledWith(id, 'seen in the capture', cap.fingerprint);
}, 60_000);

test('a selected persistence-only row is still selected after Triage, Tree, Triage', async () => {
  const cap = await loadLab();
  runLoadMock.mockResolvedValue(cap);
  await openWith(await openStore());
  await drop('synthetic-lab.jsonl');
  const list = () => within(screen.getByRole('listbox', { name: /flagged/i }));
  await user.click(list().getAllByRole('option').find(r => r.textContent?.includes('updater.wake.plist'))!);
  const pane = () => within(screen.getByRole('region', { name: /selected process/i }));
  expect(pane().getByRole('heading', { name: 'persistence: com.example.updater.wake.plist' })).toBeInTheDocument();
  await user.click(screen.getByRole('tab', { name: 'Tree' }));
  await user.click(screen.getByRole('tab', { name: 'Triage' }));
  const back = list().getAllByRole('option').find(r => r.textContent?.includes('updater.wake.plist'))!;
  expect(back).toHaveAttribute('aria-selected', 'true');
  expect(pane().getByRole('heading', { name: 'persistence: com.example.updater.wake.plist' })).toBeInTheDocument();
  // picking a process takes the item selection away, and keys still move from the process
  await user.click(list().getAllByRole('option').find(r => /display dialog/.test(r.textContent ?? ''))!);
  expect(back).toHaveAttribute('aria-selected', 'false');
}, 60_000);

// --- launch items, traits, recon bursts, the newer rules ------------------------------------------------------------

/** A loaded capture built from hand-made processes, with the real rules run over it. */
const synthCapture = (model: CaptureModel): LoadedCapture => ({ fingerprint: 'syn', fileName: 'syn.jsonl', size: 1, model, analysis: analyze(model) });
const pane = () => within(screen.getByRole('region', { name: /selected process/i }));
/** The value next to a label in the pane's description lists. */
const field = (label: string): HTMLElement => pane().getByText(label, { selector: 'dt' }).nextElementSibling as HTMLElement;

test('a process row that carries a persistence finding shows its launch item: type, plist, who registered it, who the finding is on', async () => {
  const cap = await loadLab();
  renderTriage(cap);
  await user.click(screen.getAllByRole('option').find(r => r.textContent?.startsWith('high') && r.textContent.includes('cat'))!);
  expect(pane().getByRole('heading', { name: 'Launch item' })).toBeInTheDocument();
  expect(field('Item type')).toHaveTextContent('Launch agent');
  expect(field('Plist')).toHaveTextContent(/\/Library\/LaunchAgents\/com\.test\.labdemo\.plist$/);
  expect(field('Runs')).toHaveTextContent('/bin/sh');
  expect(field('Registered by')).toHaveTextContent(/^smd \(instigator; an Apple system process/);   // the XPC caller; this event has no app
  expect(field('Reported by')).toHaveTextContent(/backgroundtaskmanagementd/);   // the daemon that emitted the event is not the registrant
  expect(field('Finding on')).toHaveTextContent('this process (plist writer)');
  expect(pane().getAllByText(/T1543\.001 · Launch Agent/).length).toBeGreaterThan(0);
}, 60_000);

test('a launch item no process owns says it stands alone, and an Apple system registrant is glossed as possibly a relay', async () => {
  renderTriage(await loadLab());
  await user.click(screen.getAllByRole('option').find(r => r.textContent?.includes('updater.wake.plist'))!);
  expect(field('Item type')).toHaveTextContent('Launch agent');
  expect(field('Registered by')).toHaveTextContent(/smd \(instigator; an Apple system process, which may only be relaying/);
  expect(field('Finding on')).toHaveTextContent(/no process: this item stands alone/);
}, 60_000);

test('a launch item with no captured app, instigator, creator or emitter says so instead of naming anyone', async () => {
  const cap = synthCapture(capture([], [persistenceItem({
    id: 'btm:8', itemType: 4, plistPath: '/Library/LaunchDaemons/com.x.plist', executablePath: '/usr/local/bin/x', emitter: 'ghost:1',
  })]));
  renderTriage(cap);
  await user.click(screen.getAllByRole('option').find(r => r.textContent?.includes('persistence: com.x.plist'))!);
  expect(field('Item type')).toHaveTextContent('Launch daemon');
  expect(field('Registered by')).toHaveTextContent('no captured process');
  expect(field('Finding on')).toHaveTextContent('no process: this item stands alone');
  expect(pane().queryByText('Reported by', { selector: 'dt' })).not.toBeInTheDocument();
});

/** LaunchItem on its own, for cases a whole capture would only get in the way of. */
const renderItem = (model: CaptureModel, item: ReturnType<typeof persistenceItem>): void => {
  render(<LaunchItem cap={{ model } as unknown as LoadedCapture} item={item} current={null} onSelect={() => undefined} />);
};
const row = (label: string): HTMLElement => screen.getByText(label, { selector: 'dt' }).nextElementSibling as HTMLElement;

test('a login item that is a helper app inside the app bundle: two differently labelled rows, unique keys, Runs names the helper', () => {
  const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  const helper = '/Applications/Foo.app/Contents/Library/LoginItems/Helper.app';
  renderItem(capture([]), persistenceItem({ id: 'btm:1', itemType: 2, plistPath: `${helper}/`, appPath: '/Applications/Foo.app/', emitter: 'ghost:1' }));
  expect(screen.getAllByText('App', { selector: 'dt' })).toHaveLength(1);
  expect(row('App')).toHaveTextContent('/Applications/Foo.app/');
  expect(row('Login item app')).toHaveTextContent(helper);
  expect(row('Runs')).toHaveTextContent(helper);
  expect(row('Runs')).not.toHaveTextContent('the app itself');
  expect(errors).not.toHaveBeenCalled();   // no "same key" warning
});

test('"Registered by" glosses an instigator that is an Apple system messenger, not a plist writer or a tool', () => {
  const smd = proc('1:1', [apple('/usr/libexec/smd', ['smd'])]);
  const sh = proc('2:1', [apple('/bin/sh', ['sh', '-c', 'x'])]);
  const launchctl = proc('3:1', [apple('/bin/launchctl', ['launchctl'])]);
  const m = capture([smd, sh, launchctl]);
  const base = { itemType: 3, plistPath: '/Users/a/Library/LaunchAgents/x.plist', emitter: 'ghost:1' };
  const gloss = /may only be relaying/;
  renderItem(m, persistenceItem({ ...base, instigator: '1:1' }));
  expect(row('Registered by')).toHaveTextContent(gloss);
  cleanup();
  renderItem(m, persistenceItem({ ...base, creator: '2:1' }));   // sh wrote the plist: a real finding, no excuse offered
  expect(row('Registered by')).toHaveTextContent('sh (plist writer)');
  expect(row('Registered by')).not.toHaveTextContent(gloss);
  cleanup();
  renderItem(m, persistenceItem({ ...base, instigator: '3:1' }));   // an Apple tool in /bin is not a system messenger
  expect(row('Registered by')).not.toHaveTextContent(gloss);
});

// --- failed and stuck verdict writes ----------------------------------------------------------------------------------

/** A store whose verdict writes follow a script: 'fail' rejects, 'ok' stores, 'hang' never settles. The first one waits for `release()`. */
async function scriptedStore(script: ('ok' | 'fail' | 'hang')[]): Promise<{ store: Store; real: Store; release(): void }> {
  const real = await openStore();
  let release!: () => void;
  const gate = new Promise<void>(r => { release = r; });
  let n = 0;
  const store = new Proxy(real, {
    get: (t, k: string) => (k === 'setVerdict'
      ? async (v: Verdict) => {
        const i = n++;
        if (i === 0) await gate;
        const what = script[i] ?? 'ok';
        if (what === 'hang') return new Promise<void>(() => undefined);
        if (what === 'fail') throw new Error(`disk full ${i}`);
        return t.setVerdict(v);
      }
      : t[k as keyof Store]),
  });
  return { store, real, release };
}

test('write A fails then write B fails: nothing unsaved stays on screen, and the next press starts from the stored state', async () => {
  const { store, real, release } = await scriptedStore(['fail', 'fail', 'ok']);
  const sid = await openWith(store);
  await drop('synthetic-lab.jsonl');
  const id = firstProc();
  await act(async () => {
    const a = ctx.toggleVerdict(id, 'confirmed');
    const b = ctx.setNote(id, 'maybe', ctx.active!);
    release();
    await Promise.all([a, b]);
  });
  expect(ctx.verdicts.size).toBe(0);
  expect(await real.listVerdicts(sid)).toHaveLength(0);
  await act(async () => { await ctx.toggleVerdict(id, 'confirmed'); });   // would read "confirmed" and flip to unreviewed if A's unsaved verdict lingered
  expect(ctx.verdicts.get(id)?.status).toBe('confirmed');
  expect(await real.listVerdicts(sid)).toMatchObject([{ status: 'confirmed' }]);
}, 60_000);

test('write A fails then write B succeeds: B, built on A, is what is stored and shown', async () => {
  const { store, real, release } = await scriptedStore(['fail', 'ok']);
  const sid = await openWith(store);
  await drop('synthetic-lab.jsonl');
  const id = firstProc();
  await act(async () => {
    const a = ctx.toggleVerdict(id, 'confirmed');
    const b = ctx.setNote(id, 'n', ctx.active!);
    release();
    await Promise.all([a, b]);
  });
  expect(await real.listVerdicts(sid)).toMatchObject([{ status: 'confirmed', note: 'n' }]);
  expect(ctx.verdicts.get(id)).toMatchObject({ status: 'confirmed', note: 'n' });
}, 60_000);

test('write A succeeds then write B fails: the screen goes back to A, which is what the store holds', async () => {
  const { store, real, release } = await scriptedStore(['ok', 'fail']);
  const sid = await openWith(store);
  await drop('synthetic-lab.jsonl');
  const id = firstProc();
  await act(async () => {
    const a = ctx.toggleVerdict(id, 'confirmed');
    const b = ctx.setNote(id, 'lost', ctx.active!);
    release();
    await Promise.all([a, b]);
  });
  expect(await real.listVerdicts(sid)).toMatchObject([{ status: 'confirmed', note: '' }]);
  expect(ctx.verdicts.get(id)).toMatchObject({ status: 'confirmed', note: '' });
}, 60_000);

test('a write that never settles is reported after 10 s, rolled back, and does not block the next write', async () => {
  const { store, real, release } = await scriptedStore(['hang', 'ok']);
  const sid = await openWith(store);
  await drop('synthetic-lab.jsonl');
  const id = firstProc();
  release();   // the gate only matters for the first call; it hangs after it
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
  try {
    let first!: Promise<void>;
    act(() => { first = ctx.toggleVerdict(id, 'confirmed'); });
    await act(async () => { await vi.advanceTimersByTimeAsync(9_900); });
    expect(ctx.storeError).toBeNull();
    await act(async () => { await vi.advanceTimersByTimeAsync(200); await first; });
    expect(ctx.storeError).toBe('Could not confirm the verdict was saved (the store is not responding); it may still be saved.');
    expect(ctx.verdicts.size).toBe(0);   // rolled back to what was last stored: nothing
    await act(async () => { await ctx.toggleVerdict(id, 'benign'); });   // the queue is free again
    expect(ctx.verdicts.get(id)?.status).toBe('benign');
    expect(await real.listVerdicts(sid)).toMatchObject([{ status: 'benign' }]);
  } finally { vi.useRealTimers(); }
}, 60_000);

// --- the Confirmed tab's export choices ------------------------------------------------------------------------------

test('the export choices survive a trip to another tab, and the tab says how many details are left out', async () => {
  const store = await openStore();
  const s = await store.createSession('lab');
  await store.upsertCapture({ sessionId: s.id, fingerprint: 'fpA', fileName: 'monday.jsonl', size: 1, events: 1, processes: 1, flagged: 0, added: 't' });
  await store.setVerdict(seedVerdict(s.id, 'fpA', 'p1', 'confirmed', 'a'));
  await store.setVerdict(seedVerdict(s.id, 'fpA', 'p2', 'confirmed', 'b'));
  render(<App />);
  await user.click(await screen.findByRole('button', { name: 'lab' }));
  await user.click(await screen.findByRole('tab', { name: 'Confirmed' }));
  expect(screen.getByText(/Details for 2 confirmed processes are left out because their captures aren.t loaded; re-add them to include/)).toBeInTheDocument();
  await user.click(screen.getByLabelText(/redact command-line arguments/i));
  await user.click(screen.getByLabelText(/include environment variables/i));
  await user.click(screen.getByRole('tab', { name: 'Triage' }));
  await user.click(screen.getByRole('tab', { name: 'Confirmed' }));
  expect(screen.getByLabelText(/redact command-line arguments/i)).toBeChecked();
  expect(screen.getByLabelText(/include environment variables/i)).toBeChecked();
});

/** A session with a stored capture that is not loaded and these confirmed verdicts (keys), opened on the Confirmed tab. */
async function confirmedTab(...keys: string[]): Promise<void> {
  const store = await openStore();
  const s = await store.createSession('lab');
  await store.upsertCapture({ sessionId: s.id, fingerprint: 'fpA', fileName: 'monday.jsonl', size: 1, events: 1, processes: 1, flagged: 0, added: 't' });
  for (const k of keys) await store.setVerdict(seedVerdict(s.id, 'fpA', k, 'confirmed', `note ${k}`));
  render(<App />);
  await user.click(await screen.findByRole('button', { name: 'lab' }));
  await user.click(await screen.findByRole('tab', { name: 'Confirmed' }));
}

test('confirmed launch items are never counted as left out: they have no process details to re-add a capture for', async () => {
  await confirmedTab('i:btm:12');
  expect(await screen.findByText('note i:btm:12')).toBeInTheDocument();
  expect(screen.queryByText(/left out/)).not.toBeInTheDocument();
  expect(screen.getByText(/Launch items are exported from their snapshot/)).toBeInTheDocument();
});

test('next to a confirmed launch item, only the confirmed process is counted as left out', async () => {
  await confirmedTab('i:btm:12', '700:1');
  expect(await screen.findByText(/Details for 1 confirmed process is left out because its capture isn.t loaded; re-add it to include/)).toBeInTheDocument();
  expect(screen.getByText(/Launch items are exported from their snapshot/)).toBeInTheDocument();
});

test('a session with no confirmed launch item does not mention them', async () => {
  await confirmedTab('700:1');
  expect(await screen.findByText(/Details for 1 confirmed process is left out/)).toBeInTheDocument();
  expect(screen.queryByText(/Launch items are exported/)).not.toBeInTheDocument();
});

test('no "left out" notice when every confirmed process has its capture loaded', async () => {
  await openWith(await openStore());
  await drop('synthetic-lab.jsonl');
  await act(async () => { await ctx.setVerdict(firstProc(), 'confirmed'); });
  await user.click(screen.getByRole('tab', { name: 'Confirmed' }));
  expect(screen.queryByText(/are left out because/)).not.toBeInTheDocument();
});

test('a login item whose URL is the app bundle is labelled App, not Plist, and names its app as the registrant', async () => {
  const exe = '/Applications/Evil.app/Contents/MacOS/Evil';
  const evil = proc('900:1', [synthImg({ path: exe, args: ['Evil'], signingId: 'evil', csFlags: 0x2, seq: 1, token: '900:1' })], { originalParent: null });
  const cap = synthCapture(capture([evil], [persistenceItem({
    id: 'btm:5', itemType: 2, plistPath: '/Applications/Evil.app/', appPath: '/Applications/Evil.app/', executablePath: exe,
    app: '900:1', emitter: '900:1', seq: 5,
  })]));
  renderTriage(cap);
  await user.click(screen.getAllByRole('option').find(r => r.textContent?.includes('Evil'))!);
  expect(field('Item type')).toHaveTextContent('Login item');
  expect(pane().queryByText('Plist', { selector: 'dt' })).not.toBeInTheDocument();
  expect(field('App')).toHaveTextContent('/Applications/Evil.app/');
  expect(pane().getAllByText('App', { selector: 'dt' })).toHaveLength(1);   // the same URL is not listed twice
  expect(field('Runs')).toHaveTextContent(exe);
  expect(field('Registered by')).toHaveTextContent('Evil (app)');
  expect(field('Finding on')).toHaveTextContent('this process (app)');
  expect(pane().getAllByText(/T1547\.015 · Login Items/).length).toBeGreaterThan(0);
  expect(pane().queryByText(/T1543/)).not.toBeInTheDocument();
});

test('a trait finding says it is a trait, not an attack technique, instead of an empty MITRE row', async () => {
  const cap = await loadFixture('synthetic-lab.jsonl');
  renderTriage(cap);
  const i = cap.analysis.queue.findIndex(q => q.findings.some(f => f.ruleId === 'adhoc'));
  await user.click(screen.getAllByRole('option')[i]!);
  const label = screen.getByText('trait, not an attack technique');
  const block = label.closest('article')!;
  expect(block).toHaveTextContent(/ad-hoc/i);
  expect(block.querySelectorAll('[title="MITRE ATT&CK technique"]')).toHaveLength(0);
  // a technique finding shows technique chips and no trait label
  const other = cap.analysis.queue.findIndex(q => q.findings.some(f => !f.trait && f.mitre.length > 0));
  await user.click(screen.getAllByRole('option')[other]!);
  expect(pane().queryByText('trait, not an attack technique')).not.toBeInTheDocument();
}, 60_000);

test('recon burst rows are marked in the queue, the tree and the detail pane', async () => {
  const cap = await loadFixture('synthetic-lab-3.jsonl');
  const bursts = cap.analysis.queue.filter(q => q.reconBurst);
  expect(bursts.length).toBeGreaterThan(0);
  runLoadMock.mockResolvedValue(cap);
  await openWith(await openStore());
  await drop('synthetic-lab-3.jsonl');
  const list = () => within(screen.getByRole('listbox', { name: /flagged/i }));
  expect(list().getAllByText('recon burst')).toHaveLength(bursts.length);
  const row = list().getAllByRole('option').find(r => r.textContent?.includes('recon burst'))!;
  await user.click(row);
  expect(pane().getByText(/3 or more different reconnaissance tools run under the same parent within 60 seconds/)).toBeInTheDocument();
  await user.click(screen.getByRole('tab', { name: 'Tree' }));
  expect(within(screen.getByRole('tree', { name: 'Process tree' })).getAllByText('recon burst').length).toBeGreaterThan(0);
}, 60_000);

test('the newer rules show title, explanation, evidence and their technique', async () => {
  const sec = apple('/usr/bin/security', ['security', 'find-generic-password', '-ga', 'Chrome']);
  const osa = apple('/usr/bin/osascript', ['osascript', '/tmp/x.scpt'], { token: '101:1' });
  const csr = apple('/usr/sbin/spctl', ['spctl', '--master-disable'], { token: '102:1' });
  const cap = synthCapture(capture([proc('100:1', [{ ...sec, token: '100:1' }]), proc('101:1', [osa]), proc('102:1', [csr])]));
  renderTriage(cap);
  const rows = screen.getAllByRole('option');
  // Each finding's title, explanation, evidence and every technique it cites (with the technique's name) are on screen.
  const open = async (ruleId: string, evidence: RegExp): Promise<void> => {
    const q = cap.analysis.queue.find(x => x.findings.some(f => f.ruleId === ruleId))!;
    const f = q.findings.find(x => x.ruleId === ruleId)!;
    await user.click(rows[cap.analysis.queue.indexOf(q)]!);
    expect(pane().getAllByText(f.title).length).toBeGreaterThan(0);
    expect(pane().getByText(f.explanation)).toBeInTheDocument();
    expect(pane().getAllByText(evidence).length).toBeGreaterThan(0);
    expect(f.mitre.length).toBeGreaterThan(0);
    for (const id of f.mitre) expect(pane().getByText(`${id} · ${MITRE_NAMES[id]}`)).toBeInTheDocument();
  };
  await open('keychain-access', /find-generic-password -ga Chrome/);
  await open('osascript-script', /\/tmp\/x\.scpt/);
  await open('security-setting-change', /spctl --master-disable/);
});

test('filters: search, status and severity', async () => {
  renderTriage(await loadLab());
  const count = async () => (await screen.findAllByRole('option')).length;
  const all = await count();
  await user.type(screen.getByRole('textbox', { name: /search/i }), 'DITTO');
  expect(await count()).toBe(1);
  await user.clear(screen.getByRole('textbox', { name: /search/i }));
  await user.type(screen.getByRole('textbox', { name: /search/i }), 'com.apple.osascript');   // signing ID
  expect(await count()).toBe(1);
  await user.clear(screen.getByRole('textbox', { name: /search/i }));
  expect(await count()).toBe(all);

  await user.click(screen.getByRole('checkbox', { name: 'high' }));   // untick high
  expect((await screen.findAllByRole('option')).some(r => within(r).queryByText('high'))).toBe(false);
  await user.click(screen.getByRole('checkbox', { name: 'high' }));

  await user.click(screen.getByText(/display dialog/));
  await user.keyboard('c');
  await user.click(screen.getByRole('radio', { name: /^confirmed$/i }));
  expect(await count()).toBe(1);
  await user.click(screen.getByRole('radio', { name: /^unreviewed$/i }));
  expect(await count()).toBe(all - 1);
}, 60_000);

test('routine hidden: counted in the footer, shown greyed on request; Treat as routine passes the image', async () => {
  const cap = await loadLab();
  const bash = procByPid(cap.model, 7004);   // the only queued row that runs bash
  const { addRoutine } = renderTriage(cap, { routineKeys: new Set([programKey(latestImage(bash)!)]) });
  const total = cap.analysis.queue.length;
  expect(await screen.findAllByRole('option')).toHaveLength(total - 1);
  expect(screen.getByText(/1 routine hidden/)).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'show' }));
  const rows = screen.getAllByRole('option');
  expect(rows).toHaveLength(total);
  const greyed = rows.filter(r => r.classList.contains('routine'));
  expect(greyed).toHaveLength(1);
  expect(greyed[0]).toHaveTextContent('bash');
  await user.click(screen.getByRole('button', { name: 'hide' }));
  expect(screen.getAllByRole('option')).toHaveLength(total - 1);

  await user.click(screen.getByText(/display dialog/));
  await user.click(screen.getByRole('button', { name: /treat as routine/i }));
  expect(addRoutine).toHaveBeenCalledWith(latestImage(procByPid(cap.model, 7006)));
}, 60_000);

/** The process that wrote com.test.labdemo.plist (the shell child that became `cat`): its row carries the high persistence finding. */
async function plistWriterImage(): Promise<Image> {
  const cap = await loadLab();
  return latestImage(procByPid(cap.model, 7013))!;
}

test('a routine mark never hides the row with a persistence finding: the row says why it stayed', async () => {
  const cap = await loadLab();
  const writer = await plistWriterImage();
  renderTriage(cap, { routineKeys: new Set([programKey(writer)]) });
  const rows = await screen.findAllByRole('option');
  const kept = rows.filter(r => /routine program — kept: high severity, persistence/.test(r.textContent ?? ''));
  expect(kept).toHaveLength(1);
  expect(kept[0]).not.toHaveClass('routine');
  expect(screen.getByText(/0 routine hidden/)).toBeInTheDocument();
  await user.click(kept[0]!);
  expect(screen.getByText(/marked routine, but this row stays visible: high severity, persistence/)).toBeInTheDocument();
}, 60_000);

test('Treat as routine asks first when high or persistence rows of that program would stay visible', async () => {
  const { store, sessionId } = await withSession('synthetic-lab.jsonl');
  const writer = await plistWriterImage();
  vi.mocked(window.confirm).mockReturnValueOnce(false);
  await act(async () => { expect(await ctx.addRoutine(writer)).toBe(false); });
  expect(window.confirm).toHaveBeenCalledTimes(1);
  const asked = String(vi.mocked(window.confirm).mock.calls[0]![0]);
  expect(asked).toMatch(/1 high-severity or persistence row of .* will stay visible/);
  expect(asked.match(/Mark it anyway\?/g)).toHaveLength(1);   // one prompt, merged with the risky-program text
  expect(await store.listRoutine(sessionId)).toHaveLength(0);
  await act(async () => { expect(await ctx.addRoutine(writer)).toBe(true); });
  expect(await store.listRoutine(sessionId)).toHaveLength(1);
  // the kept row is still in the queue the user sees
  expect(ctx.triage!.queue.some(q => q.findings.some(f => f.persistenceId !== null) && q.procId === procByPid(ctx.capture!.model, 7013).id)).toBe(true);
}, 60_000);

test('note is saved on blur, only when it changed', async () => {
  const { setNote } = renderTriage(await loadLab());
  await user.click(screen.getByText(/display dialog/));
  const note = screen.getByLabelText(/note/i);
  await user.click(note);
  await user.tab();
  expect(setNote).not.toHaveBeenCalled();
  await user.type(note, 'phishing prompt');
  await user.tab();
  expect(setNote).toHaveBeenCalledWith(await osascriptId(), 'phishing prompt', (await loadLab()).fingerprint);
}, 60_000);

test('pressing the verdict a process already has takes it back to unreviewed (button and key)', async () => {
  const { setVerdict } = renderTriage(await loadLab());
  await user.click(screen.getByText(/display dialog/));
  const confirm = screen.getByRole('button', { name: /confirm suspicious/i });
  const benign = screen.getByRole('button', { name: /^benign/i });
  expect(confirm).toHaveAttribute('aria-pressed', 'false');
  await user.click(confirm);
  expect(setVerdict).toHaveBeenLastCalledWith(await osascriptId(), 'confirmed', undefined);
  expect(confirm).toHaveAttribute('aria-pressed', 'true');
  expect(benign).toHaveAttribute('aria-pressed', 'false');
  await user.click(confirm);
  expect(setVerdict).toHaveBeenLastCalledWith(await osascriptId(), 'unreviewed', undefined);
  expect(confirm).toHaveAttribute('aria-pressed', 'false');

  await user.click(benign);
  expect(benign).toHaveAttribute('aria-pressed', 'true');
  await user.click(confirm);   // a different verdict switches, it does not toggle off
  expect(setVerdict).toHaveBeenLastCalledWith(await osascriptId(), 'confirmed', undefined);
  expect(benign).toHaveAttribute('aria-pressed', 'false');

  // keys: c on a confirmed process un-confirms it; b on an unreviewed one marks it benign, a second b undoes it
  await user.click(document.body);
  await user.keyboard('c');
  expect(setVerdict).toHaveBeenLastCalledWith(await osascriptId(), 'unreviewed', undefined);
  await user.keyboard('b');
  expect(setVerdict).toHaveBeenLastCalledWith(await osascriptId(), 'benign', undefined);
  await user.keyboard('b');
  expect(setVerdict).toHaveBeenLastCalledWith(await osascriptId(), 'unreviewed', undefined);
}, 60_000);

test('empty queue says so', async () => {
  const cap = await loadLab();
  renderTriage({ ...cap, analysis: { ...cap.analysis, queue: [] } });
  expect(await screen.findByText(/nothing flagged/i)).toBeInTheDocument();
}, 60_000);

test('setVerdict accepts a persistence-only item by its queue key', async () => {
  const { store, sessionId, demo } = await withSession('synthetic-lab.jsonl');
  const item = demo.analysis.queue.find(q => q.kind === 'persistence')!;
  expect(item.key).toMatch(/^i:btm:\d+$/);
  await act(async () => { await ctx.setVerdict(item.key, 'benign', 'Updater, expected'); });
  const [v] = await store.listVerdicts(sessionId, demo.fingerprint);
  expect(v).toMatchObject({ procKey: item.key, status: 'benign', note: 'Updater, expected' });
  expect(v!.snapshot).toMatchObject({ name: 'persistence: com.example.updater.wake.plist', severity: 'med', ruleIds: ['persistence-item'] });
  expect(ctx.verdicts.get(item.key)?.status).toBe('benign');
}, 60_000);

// --- Tree view ------------------------------------------------------------------------------------------

/** A session on the synthetic lab (parsed once, see loadLab), opened on the Tree tab. */
async function treeSession(view: 'tree' | 'triage' = 'tree'): Promise<LoadedCapture> {
  const cap = await loadLab();
  runLoadMock.mockImplementation(() => Promise.resolve(cap));
  const store = await openStore();
  const s = await store.createSession('tree');
  function Screen() { return useSession().session ? <SessionScreen /> : null; }
  render(<SessionProvider store={store}><Probe /><Screen /></SessionProvider>);
  await waitFor(() => { expect(ctx).toBeDefined(); });
  await act(async () => { await ctx.openSession(s.id); });
  await act(async () => { await ctx.loadFiles([dropped('synthetic-lab.jsonl')]); });
  act(() => { ctx.setView(view); });
  return cap;
}

const items = (): HTMLElement[] => screen.getAllByRole('treeitem');
const itemWith = (re: RegExp): HTMLElement | undefined => items().find(el => re.test(el.textContent ?? ''));
const level = (el: HTMLElement): number => Number(el.getAttribute('aria-level'));
/** Flat rows: the parent is the nearest earlier row one level up. */
function parentRow(el: HTMLElement): HTMLElement | undefined {
  const all = items();
  for (let i = all.indexOf(el) - 1; i >= 0; i--) if (level(all[i]!) === level(el) - 1) return all[i];
  return undefined;
}
const procNamed = (m: CaptureModel, name: string): Process =>
  [...m.processes.values()].find(p => basename(latestImage(p)?.path ?? null) === name)!;

test('noise folded with counts', async () => {
  await treeSession();
  expect(await screen.findByText(/unflagged: .*\bps ×\d+/)).toBeInTheDocument();
  expect(screen.getByRole('tree', { name: 'Process tree' })).toBeInTheDocument();
}, 60_000);

test('show in tree focuses osascript under zsh', async () => {
  const cap = await treeSession();
  act(() => { ctx.showInTree(procByPid(cap.model, 7006).id); });
  const sel = await screen.findByRole('treeitem', { selected: true });
  expect(sel).toHaveTextContent('osascript');
  expect(parentRow(sel)).toHaveTextContent('zsh');
  expect(screen.getAllByRole('treeitem', { selected: true })).toHaveLength(1);
  expect(screen.getByRole('region', { name: 'Selected process' })).toHaveTextContent('osascript');
}, 60_000);

test('mode switch moves sleep 90 under launchd', async () => {
  await treeSession();
  const sleep = await screen.findByText(/sleep 90/);
  expect(parentRow(sleep.closest('[role="treeitem"]')!)).toHaveTextContent('zsh');   // original: its subshell
  await user.selectOptions(screen.getByLabelText(/parent mode/i), 'current');
  const moved = (await screen.findByText(/sleep 90/)).closest('[role="treeitem"]') as HTMLElement;
  expect(parentRow(moved)).toHaveTextContent(/launchd/);
}, 60_000);

test('Show in tree reveals an unflagged process inside a fold, opening just that fold', async () => {
  const cap = await treeSession();
  const target = procNamed(cap.model, 'git');
  expect(cap.analysis.queue.some(q => q.procId === target.id)).toBe(false);
  expect(screen.queryByText(/^git /)).not.toBeInTheDocument();
  act(() => { ctx.showInTree(target.id); });
  const sel = await screen.findByRole('treeitem', { selected: true });
  expect(sel).toHaveTextContent('git');
  expect(level(sel)).toBeGreaterThan(1);
  const folds = items().filter(el => /^unflagged/.test(el.textContent?.replace(/^[▸▾\s]+/, '') ?? ''));
  expect(folds.filter(el => el.getAttribute('aria-expanded') === 'true')).toHaveLength(1);   // the other fold stays closed
  expect(folds.some(el => el.getAttribute('aria-expanded') === 'false')).toBe(true);
}, 60_000);

test('Show in tree from the triage screen (key t) lands on the process', async () => {
  await treeSession('triage');
  await user.click(await screen.findByText(/display dialog/));
  await user.keyboard('t');
  expect(await screen.findByRole('treeitem', { selected: true })).toHaveTextContent('osascript');
  await user.click(screen.getByRole('tab', { name: 'Triage' }));
  expect(await screen.findByRole('listbox', { name: 'Flagged processes' })).toBeInTheDocument();
}, 60_000);

test('Show in tree on a ghost parent keeps it visible with its pre-capture label', async () => {
  const cap = await treeSession();
  const ghost = procByPid(cap.model, 6120);
  act(() => { ctx.showInTree(ghost.id); });
  expect(await screen.findByRole('treeitem', { selected: true })).toHaveTextContent('pid 6120 · started before capture');
}, 60_000);

test('a fold row expands on click and lists what it counted; Fold unflagged off shows everything unfolded', async () => {
  await treeSession();
  const fold = (await screen.findByText(/unflagged: .*\bps ×6/)).closest('[role="treeitem"]') as HTMLElement;
  expect(fold).toHaveAttribute('aria-expanded', 'false');
  expect(fold).toHaveTextContent(/\d+ processes/);
  const before = items().length;
  await user.click(fold);
  expect(fold).toHaveAttribute('aria-expanded', 'true');
  expect(items().length).toBeGreaterThan(before + 1);
  expect(items().some(el => level(el) === level(fold) + 1 && el.previousElementSibling === fold)).toBe(true);   // its members, one level down

  await user.click(screen.getByRole('checkbox', { name: /fold unflagged/i }));
  expect(screen.queryByText(/unflagged[:(]/)).not.toBeInTheDocument();
}, 60_000);

test('marking a flagged program routine folds it, with the count going up by one', async () => {
  const cap = await treeSession();
  const curl = procByPid(cap.model, 7001);   // flagged, but neither high nor persistence: a routine mark may hide it
  const parentName = displayName(cap.model, curl.originalParent!);
  const foldUnderParent = (): HTMLElement | undefined => {
    const parent = itemWith(new RegExp(`^[▸▾\\s]*${parentName}`))!;
    const all = items();
    return all.slice(all.indexOf(parent)).find(el => /^[▸▾\s]*unflagged/.test(el.textContent ?? '') && level(el) === level(parent) + 1);
  };
  const total = (el: HTMLElement): number => Number(/(\d+) processes/.exec(el.textContent ?? '')![1]);
  await screen.findByText(/^curl -s/);
  const fold0 = foldUnderParent();
  const before = fold0 ? total(fold0) : 0;
  await act(async () => { await ctx.addRoutine(latestImage(curl)!); });
  await waitFor(() => { expect(itemWith(/curl -s https/)).toBeUndefined(); });
  expect(total(foldUnderParent()!)).toBe(before + 1);
  expect(foldUnderParent()).toHaveTextContent(/unflagged \(incl\. 1 marked routine\)/);   // not just "routine": the user's mark is named
  await user.click(foldUnderParent()!);
  expect(itemWith(/curl -s https/)).toBeDefined();
}, 60_000);

test('fold labels say "unflagged", and count the programs the user marked routine separately', async () => {
  const { m, a } = queued('synthetic-lab.jsonl');
  const flagged = a.queue.filter(q => q.procId !== null).map(q => q.procId!);
  const f = forestOf(m, 'original');
  const keep = keepSet(f, flagged);
  const plain = makeFoldInfo(m, f, keep);
  const git = [...m.processes.values()].filter(p => latestImage(p)?.path?.endsWith('/git') && !keep.has(p.id));
  expect(git.length).toBeGreaterThan(0);
  const marked = makeFoldInfo(m, f, keep, new Set([programKey(latestImage(git[0]!)!)]));
  const labels = (fi: typeof plain): string[] => [...f.kids.keys()].map(k => fi(k)?.label).filter((l): l is string => l !== undefined);
  expect(labels(plain).length).toBeGreaterThan(0);
  expect(labels(plain).every(l => l.startsWith('unflagged: '))).toBe(true);
  expect(labels(plain).some(l => /routine/.test(l))).toBe(false);
  expect(labels(marked).some(l => /^unflagged \(incl\. \d+ marked routine\): /.test(l))).toBe(true);
});

test('marking the program that raised a high finding routine does not fold its row', async () => {
  const cap = await treeSession();
  const osa = procByPid(cap.model, 7006);   // fake-prompt, high
  await screen.findByText(/osascript/);
  await act(async () => { await ctx.addRoutine(latestImage(osa)!); });
  expect(ctx.routineKeys.has(programKey(latestImage(osa)!))).toBe(true);
  expect(ctx.triage!.queue.some(q => q.procId === osa.id)).toBe(true);
  expect(itemWith(/osascript/)).toBeDefined();
}, 60_000);

test('search keeps matches and their ancestors, hides the rest, and says so', async () => {
  const cap = await treeSession();
  await user.type(screen.getByRole('textbox', { name: /search/i }), 'osascript');
  await waitFor(() => { expect(screen.queryByText(/unflagged[:(]/)).not.toBeInTheDocument(); });
  const chain = items().map(el => el.textContent!.replace(/^[▸▾\s]+/, ''));
  expect(chain).toHaveLength(3);   // ghost 6120 > zsh 6130 > osascript
  expect(chain[2]).toMatch(/osascript/);
  expect(screen.getByText(/1 match/)).toBeInTheDocument();
  await user.clear(screen.getByRole('textbox', { name: /search/i }));
  expect(await screen.findByText(/unflagged: .*\bps ×6/)).toBeInTheDocument();
  expect(cap).toBeDefined();
}, 60_000);

test('clearing the search keeps the selected process on screen even when it sits in a fold', async () => {
  await treeSession();
  await user.type(screen.getByRole('textbox', { name: /search/i }), 'git');
  await user.click((await screen.findAllByText(/^git /))[0]!);
  await user.clear(screen.getByRole('textbox', { name: /search/i }));
  expect(await screen.findByRole('treeitem', { selected: true })).toHaveTextContent('git');
  expect(await screen.findByText(/unflagged: .*\bps ×6/)).toBeInTheDocument();
}, 60_000);

/** Gives every element a 3-row-high box, so useVirtualRows picks the virtual list; returns the scrollTo spy and a restore. */
function fakeLayout(height = 84): { scrollTo: ReturnType<typeof vi.fn>; restore(): void } {
  const scrollTo = vi.fn();
  const keys = ['clientHeight', 'offsetHeight', 'clientWidth', 'offsetWidth', 'scrollHeight'] as const;
  const saved = keys.map(k => [k, Object.getOwnPropertyDescriptor(HTMLElement.prototype, k)] as const);
  for (const k of keys) Object.defineProperty(HTMLElement.prototype, k, { configurable: true, get: () => (k === 'scrollHeight' ? 1_000_000 : k.endsWith('Height') ? height : 400) });
  const rect = HTMLElement.prototype.getBoundingClientRect;
  HTMLElement.prototype.getBoundingClientRect = () => ({ x: 0, y: 0, top: 0, left: 0, right: 400, bottom: height, width: 400, height, toJSON() { return {}; } });
  const hadScrollTo = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'scrollTo');
  HTMLElement.prototype.scrollTo = scrollTo as unknown as typeof HTMLElement.prototype.scrollTo;
  return {
    scrollTo,
    restore() {
      for (const [k, d] of saved) { if (d) Object.defineProperty(HTMLElement.prototype, k, d); else delete (HTMLElement.prototype as unknown as Record<string, unknown>)[k]; }
      HTMLElement.prototype.getBoundingClientRect = rect;
      if (hadScrollTo) Object.defineProperty(HTMLElement.prototype, 'scrollTo', hadScrollTo); else delete (HTMLElement.prototype as unknown as Record<string, unknown>).scrollTo;
    },
  };
}

test('virtual list: arrow keys scroll the selection into view, and a stale target never fires on a later rows change', async () => {
  const layout = fakeLayout();
  try {
    await treeSession();
    const tree = screen.getByRole('tree', { name: 'Process tree' });
    expect(tree.querySelector('[role="treeitem"]')!.getAttribute('style')).toMatch(/translateY/);   // really the virtual list
    await user.click(await screen.findByText(/^curl/));
    layout.scrollTo.mockClear();
    await user.keyboard('{ArrowDown}{ArrowDown}{ArrowDown}{ArrowDown}{ArrowDown}');
    expect(layout.scrollTo).toHaveBeenCalled();   // the selection walked past the 3 visible rows
    const sel = screen.getByRole('treeitem', { selected: true });
    expect(sel).toBeInTheDocument();

    // Click somewhere else, then change the rows: nothing may jump to the earlier arrow target.
    await user.click(await screen.findByText(/^curl/));
    const calls = layout.scrollTo.mock.calls.length;
    await user.click(screen.getByRole('checkbox', { name: /fold unflagged/i }));   // rows change
    await user.click(screen.getByRole('checkbox', { name: /fold unflagged/i }));
    expect(layout.scrollTo.mock.calls.length).toBe(calls);
  } finally { layout.restore(); }
}, 60_000);

test('virtual list: Show in tree centres a process hidden in a fold', async () => {
  const layout = fakeLayout();
  try {
    const cap = await treeSession();
    layout.scrollTo.mockClear();
    act(() => { ctx.showInTree(procNamed(cap.model, 'git').id); });
    // scrollTo is a spy, so the window does not move; the target offset is well past the first rows.
    await waitFor(() => { expect(layout.scrollTo.mock.calls.some(([o]) => (o as { top: number }).top > 84)).toBe(true); });
  } finally { layout.restore(); }
}, 60_000);

test('a parent with 200,000 children flattens, folds and reveals without a stack overflow', () => {
  const N = 200_000;
  const ps: Process[] = [hand('1:1', 1, null, 'root', 1), hand('2:1', 2, '1:1', 'flagged', 2)];
  for (let i = 0; i < N; i++) ps.push(hand(`${i + 10}:1`, i + 10, '1:1', 'kid', i + 10));
  const m = handModel(ps);
  const f = forestOf(m, 'original');
  expect(f.kids.get('1:1')).toHaveLength(N + 1);
  const keep = keepSet(f, ['2:1']);
  const fi = makeFoldInfo(m, f, keep);
  const folded = flatten({ forest: f, keep, fold: true, foldInfo: fi, visible: null, overrides: new Map() });
  expect(folded.rows.map(r => r.kind)).toEqual(['node', 'node', 'fold']);
  expect(folded.folded).toBe(N);
  expect(folded.rows[2]).toMatchObject({ label: `unflagged: kid ×${N}` });
  const openFold = flatten({ forest: f, keep, fold: true, foldInfo: fi, visible: null, overrides: new Map([['f:1:1', true]]) });
  expect(openFold.rows).toHaveLength(3 + N);
  const unfolded = flatten({ forest: f, keep, fold: false, foldInfo: fi, visible: null, overrides: new Map() });
  expect(unfolded.rows).toHaveLength(N + 2);   // root, its flagged child and every kid
});

test('flag badges show the highest severity, status icons follow verdicts, arrow keys move the selection', async () => {
  const cap = await treeSession();
  const osa = procByPid(cap.model, 7006);
  const row = await screen.findByText(/osascript/);
  const item = row.closest('[role="treeitem"]') as HTMLElement;
  expect(within(item).getByText('high')).toBeInTheDocument();
  await user.click(item);
  expect(ctx.selected).toBe(osa.id);
  await act(async () => { await ctx.setVerdict(osa.id, 'confirmed'); });
  expect(within(screen.getByRole('treeitem', { selected: true })).getByLabelText('confirmed')).toBeInTheDocument();
  await user.keyboard('{ArrowUp}');
  expect(screen.getByRole('treeitem', { selected: true })).not.toHaveTextContent('osascript');
}, 60_000);

test('switching the mode keeps the selected process on screen', async () => {
  const cap = await treeSession();
  const target = procNamed(cap.model, 'git');
  act(() => { ctx.showInTree(target.id); });
  await screen.findByRole('treeitem', { selected: true });
  await user.selectOptions(screen.getByLabelText(/parent mode/i), 'responsible');
  expect(await screen.findByRole('treeitem', { selected: true })).toHaveTextContent('git');
}, 60_000);

test('triage filters and search survive a trip to another tab', async () => {
  render(<App />);
  await newSession('lab');
  await user.upload(await screen.findByLabelText(/capture files/i), dropped('synthetic-lab-2.jsonl'));
  await screen.findByRole('listbox', { name: 'Flagged processes' });
  await user.type(screen.getByRole('textbox', { name: /search/i }), 'curl');
  await user.click(screen.getByRole('checkbox', { name: 'low' }));
  await user.click(screen.getByRole('radio', { name: /^unreviewed$/i }));
  await user.click(screen.getByRole('tab', { name: 'Tree' }));
  expect(await screen.findByRole('tree', { name: 'Process tree' })).toBeInTheDocument();
  await user.click(screen.getByRole('tab', { name: 'Triage' }));
  expect(screen.getByRole('textbox', { name: /search/i })).toHaveValue('curl');
  expect(screen.getByRole('checkbox', { name: 'low' })).not.toBeChecked();
  expect(screen.getByRole('radio', { name: /^unreviewed$/i })).toBeChecked();
});

test('showInTree sets focusId, and picking another process clears it', async () => {
  await withSession();
  act(() => { ctx.showInTree('2:2'); });
  expect(ctx.focusId).toBe('2:2');
  const n = ctx.focusNonce;
  act(() => { ctx.showInTree('2:2'); });
  expect(ctx.focusNonce).toBeGreaterThan(n);
  act(() => { ctx.selectProc('3:3'); });
  expect(ctx.focusId).toBeNull();
});

// --- tree model on hand-built captures --------------------------------------------------------------------------

const hand = (id: string, pid: number, parent: string | null, name: string, seq: number): Process => ({
  id, pid, ghost: false, forkParent: null, originalPpid: null, ppid: null, parentToken: null, responsibleToken: null,
  originalParent: parent, currentParent: parent, responsible: parent, startTime: null, exitTime: null, firstSeq: seq, fileOps: [],
  images: [img({ token: id, path: `/bin/${name}`, args: [name] })],
});
const handModel = (ps: Process[]): CaptureModel => ({
  processes: new Map(ps.map(p => [p.id, p])), tokenIndex: new Map(), persistence: [],
  stats: { lines: 0, events: 0, badLines: 0, otherEvents: {}, versions: [], firstSeq: null, firstTime: null, lastTime: null },
});
/** r > c1, c2; and a parent cycle a > b > a with b's child leaf (none of the three is reachable from a root). */
const cyclic = (): CaptureModel => handModel([
  hand('1:1', 1, null, 'root', 1), hand('2:1', 2, '1:1', 'c1', 2), hand('3:1', 3, '1:1', 'c2', 3),
  hand('4:1', 4, '5:1', 'a', 4), hand('5:1', 5, '4:1', 'b', 5), hand('6:1', 6, '5:1', 'leaf', 6),
]);

test('forestOf is built once per capture and mode, and places every process exactly once even with a parent cycle', () => {
  const m = cyclic();
  expect(forestOf(m, 'original')).toBe(forestOf(m, 'original'));
  expect(forestOf(m, 'current')).not.toBe(forestOf(m, 'original'));
  const f = forestOf(m, 'original');
  expect(f.unreachable).toBe(3);
  expect([...f.kids.values()].flat().sort()).toEqual([...m.processes.keys()].sort());
  expect(f.parent.size).toBe(m.processes.size);
});

test('a parent cycle shows as a grey "unreachable (parent cycle)" group that lists its members', async () => {
  const model = cyclic();
  const cap = { model, analysis: { queue: [], findings: new Map(), contextOnly: new Map() }, fingerprint: 'cyc', fileName: 'c.jsonl', size: 0 } as unknown as LoadedCapture;
  function Harness() {
    const [selected, setSelected] = useState<string | null>(null);
    const triage = useMemo(() => applyRoutine(cap.analysis, cap.model, new Set()), []);
    const value = { capture: cap, active: 'cyc', captures: new Map(), triage, verdicts: new Map(), routineKeys: new Set(), selected, selectProc: setSelected,
      focusId: null, focusNonce: 0, showInTree: vi.fn() } as unknown as SessionCtx;
    return <SessionContext.Provider value={value}><TreeView /></SessionContext.Provider>;
  }
  render(<Harness />);
  const group = await screen.findByText(/unreachable \(parent cycle\) ×3/);
  const names = () => items().map(el => el.textContent!.replace(/^[▸▾\s]+/, ''));
  expect(names().some(n => /^a\b/.test(n))).toBe(false);
  await user.click(group);
  for (const n of ['a', 'b', 'leaf']) expect(names().some(t => new RegExp(`^${n}\\b`).test(t))).toBe(true);
  expect(names().filter(t => /^(root|c1|c2|unflagged)/.test(t)).length).toBeGreaterThan(0);
});

test('flatten: every process is a row or counted in a fold row; reveal opens only the fold the target sits in', () => {
  const m = cyclic();
  const f = forestOf(m, 'original');
  const keep = keepSet(f, ['2:1']);
  const fi = makeFoldInfo(m, f, keep);
  const base = { forest: f, keep, fold: true, foldInfo: fi, visible: null };
  const { rows, folded, foldRows } = flatten({ ...base, overrides: new Map() });
  const nodes = rows.filter(r => r.kind === 'node').length;
  expect(rows.map(r => r.kind)).toEqual(['node', 'node', 'fold', 'group']);   // root, c1 (flagged), fold of c2, cycle group
  expect(nodes + folded + 3).toBe(m.processes.size);   // the group hides 3 more, counted in its own row
  expect(foldRows).toBe(1);
  expect(revealKeys(f, keep, true, '3:1')).toEqual(['f:1:1', 'n:1:1']);   // the fold it sits in, and its parent
  expect(revealKeys(f, keep, false, '3:1')).toEqual(['n:1:1']);
  expect(revealKeys(f, keep, true, '6:1')).toEqual(['n:5:1', 'n:4:1', 'g:unreachable']);   // leaf < b < a, the group's first member
});

// --- Notes survive a capture switch and unmounting ----------------------------------------------------------------

/** The real provider with the triage view, on a session that has loaded `first`; `selectFirstFlagged` picks a process. */
async function triageSession(first: FixtureName): Promise<{ store: Store; sessionId: string; demo: LoadedCapture; procId: string }> {
  const store = await openStore();
  const s = await store.createSession('notes');
  render(<SessionProvider store={store}><Probe /><TriageView /></SessionProvider>);
  await waitFor(() => { expect(ctx).toBeDefined(); });
  await act(async () => { await ctx.openSession(s.id); });
  await act(async () => { await ctx.loadFiles([dropped(first)]); });
  const demo = ctx.captures.get(ctx.active!)!;
  const procId = demo.analysis.queue.find(q => q.kind === 'process')!.procId!;
  act(() => { ctx.selectProc(procId); });
  return { store, sessionId: s.id, demo, procId };
}

test('a note typed on capture A is saved under A when capture B finishes loading before blur', async () => {
  const { store, sessionId, demo, procId } = await triageSession('synthetic-lab.jsonl');
  await user.type(screen.getByLabelText(/note/i), 'drops a payload');   // still focused, not yet saved
  expect(await store.listVerdicts(sessionId, demo.fingerprint)).toHaveLength(0);

  await act(async () => { await ctx.loadFiles([dropped('synthetic-lab-4.jsonl')]); });   // switches `active`, unmounts the note
  expect(ctx.active).not.toBe(demo.fingerprint);
  await waitFor(async () => { expect(await store.listVerdicts(sessionId, demo.fingerprint)).toHaveLength(1); });
  const [v] = await store.listVerdicts(sessionId, demo.fingerprint);
  expect(v).toMatchObject({ procKey: procId, status: 'unreviewed', note: 'drops a payload' });
  expect(await store.listVerdicts(sessionId, ctx.active!)).toHaveLength(0);
  expect(ctx.storeError).toBeNull();

  act(() => { ctx.setActive(demo.fingerprint); ctx.selectProc(procId); });   // back on A: the note is there
  expect(await screen.findByLabelText(/note/i)).toHaveValue('drops a payload');
}, 60_000);

test('a note is saved while typing (debounced) and when the pane unmounts', async () => {
  const { store, sessionId, demo, procId } = await triageSession('synthetic-lab.jsonl');
  await user.type(screen.getByLabelText(/note/i), 'first');
  await waitFor(async () => { expect((await store.listVerdicts(sessionId, demo.fingerprint))[0]?.note).toBe('first'); }, { timeout: 3000 });

  await user.type(screen.getByLabelText(/note/i), ' second');   // not saved yet: the debounce has not fired
  expect((await store.listVerdicts(sessionId, demo.fingerprint))[0]?.note).toBe('first');
  act(() => { ctx.selectProc(null); });   // the note unmounts: it flushes
  await waitFor(async () => { expect((await store.listVerdicts(sessionId, demo.fingerprint))[0]?.note).toBe('first second'); });
  expect((await store.listVerdicts(sessionId, demo.fingerprint))[0]?.procKey).toBe(procId);
}, 60_000);

test('a note is saved when the page is hidden', async () => {
  const { store, sessionId, demo } = await triageSession('synthetic-lab.jsonl');
  await user.type(screen.getByLabelText(/note/i), 'leaving');
  act(() => { window.dispatchEvent(new Event('pagehide')); });
  await waitFor(async () => { expect((await store.listVerdicts(sessionId, demo.fingerprint))[0]?.note).toBe('leaving'); });
}, 60_000);

test('setVerdict can target a capture that is not the active one', async () => {
  const { store, sessionId, demo, procId } = await triageSession('synthetic-lab.jsonl');
  await act(async () => { await ctx.loadFiles([dropped('synthetic-lab-4.jsonl')]); });
  await act(async () => { await ctx.setVerdict(procId, 'benign', 'on A', demo.fingerprint); });
  expect(await store.listVerdicts(sessionId, demo.fingerprint)).toHaveLength(1);
  expect(await store.listVerdicts(sessionId, ctx.active!)).toHaveLength(0);
}, 60_000);


// --- reopening a session: a saved copy in the save folder -----------------------------------------------------------

/** A session "lab" with one confirmed verdict, and its saved file in the folder with that verdict made benign. */
async function savedCopyThatDiffers() {
  const store = await openStore();
  const s = await store.createSession('lab');
  const v: Verdict = { sessionId: s.id, fingerprint: 'fp', procKey: 'p1', status: 'confirmed', note: 'here', updated: 't',
    snapshot: { name: 'osascript', path: null, args: null, ruleIds: [], severity: null, startTime: null } };
  await store.setVerdict(v);
  const out = await exportSession(store, s.id, { includeEnv: false });
  const file = { ...out, verdicts: [{ ...out.verdicts[0]!, status: 'benign', note: 'from the file' }] };
  const dir = fakeFolder('cases', { [saveFileName(s)]: { text: JSON.stringify(file), lastModified: Date.now() + 60_000 } });
  folderBrowser(dir);
  folderMemory.dir = dir;
  return { store, s, dir };
}

test('opening a session finds a different saved copy in the save folder and offers to reimport it', async () => {
  const { store, s } = await savedCopyThatDiffers();
  render(<App />);
  await user.click(await screen.findByRole('button', { name: 'lab' }));
  const offer = await screen.findByRole('region', { name: 'Saved copy of lab' });
  expect(offer).toHaveTextContent('A saved copy of “lab” is in “cases”');
  expect(offer).toHaveTextContent(saveFileName(s));
  expect(offer).toHaveTextContent('The file has 1 reviewed process, 0 routine marks; this browser has 1 reviewed process, 0 routine marks.');
  expect(screen.queryByRole('heading', { level: 1, name: 'lab' })).not.toBeInTheDocument();   // not opened yet

  await user.click(within(offer).getByRole('button', { name: 'Reimport and open' }));
  expect(await screen.findByRole('heading', { level: 1, name: 'lab' })).toBeInTheDocument();
  const vs = await store.listVerdicts(s.id);
  expect(vs.map(v => [v.status, v.note])).toEqual([['benign', 'from the file']]);
  expect((await store.listSessions()).map(x => [x.id, x.name])).toEqual([[s.id, 'lab']]);   // replaced in place
});

test('"Open without it" opens the session as this browser holds it', async () => {
  const { store, s } = await savedCopyThatDiffers();
  render(<App />);
  await user.click(await screen.findByRole('button', { name: 'lab' }));
  await user.click(await screen.findByRole('button', { name: 'Open without it' }));
  expect(await screen.findByRole('heading', { level: 1, name: 'lab' })).toBeInTheDocument();
  expect((await store.listVerdicts(s.id)).map(v => v.status)).toEqual(['confirmed']);
});

test('a saved copy older than this browser’s changes is offered with a warning that they would be lost', async () => {
  const { s, dir } = await savedCopyThatDiffers();
  dir.files[saveFileName(s)]!.lastModified = Date.parse(s.updated) - 60_000;
  render(<App />);
  await user.click(await screen.findByRole('button', { name: 'lab' }));
  expect(await screen.findByText(/This browser has changes made after the file was saved; they would be lost/)).toBeInTheDocument();
});

test('a saved copy that matches this browser opens the session without asking', async () => {
  const store = await openStore();
  const s = await store.createSession('lab');
  const out = await exportSession(store, s.id, { includeEnv: false });
  const dir = fakeFolder('cases', { [saveFileName(s)]: { text: JSON.stringify(out), lastModified: Date.now() } });
  folderBrowser(dir);
  folderMemory.dir = dir;
  render(<App />);
  await user.click(await screen.findByRole('button', { name: 'lab' }));
  expect(await screen.findByRole('heading', { level: 1, name: 'lab' })).toBeInTheDocument();
  expect(screen.queryByRole('region', { name: /Saved copy/ })).not.toBeInTheDocument();
});

test('when access to the save folder is refused, the session opens without looking', async () => {
  const { store, s } = await savedCopyThatDiffers();
  const refused = fakeFolder('cases', {}, 'denied');
  folderMemory.dir = refused;
  render(<App />);
  await user.click(await screen.findByRole('button', { name: 'lab' }));
  expect(await screen.findByRole('heading', { level: 1, name: 'lab' })).toBeInTheDocument();
  expect(refused.requestPermission).toHaveBeenCalledWith({ mode: 'read' });
  expect((await store.listVerdicts(s.id)).map(v => v.status)).toEqual(['confirmed']);
});

test('without a folder-capable browser, opening a session never looks for a saved copy', async () => {
  await savedCopyThatDiffers();
  delete (window as { showDirectoryPicker?: unknown }).showDirectoryPicker;
  render(<App />);
  await user.click(await screen.findByRole('button', { name: 'lab' }));
  expect(await screen.findByRole('heading', { level: 1, name: 'lab' })).toBeInTheDocument();
});


// --- remembered capture files: reload one, reload all -------------------------------------------------------------

/** Session "lab" with both labs added through the browser's picker, then closed and opened again from the home page. */
async function reopenedWithTwoCaptures(handles = [fileHandle('synthetic-lab-2.jsonl'), fileHandle('synthetic-lab-3.jsonl')]) {
  handleBrowser(handles);
  render(<App />);
  await newSession('lab');
  await user.click(await screen.findByRole('button', { name: 'Choose capture files' }));
  await headerShows('111 events');
  expect(within(screen.getByRole('list', { name: 'Captures' })).getAllByRole('listitem')).toHaveLength(2);
  await user.click(screen.getByRole('button', { name: 'Sessions' }));
  await user.click(await screen.findByRole('button', { name: 'lab' }));
  await screen.findByRole('heading', { level: 1, name: 'lab' });
  return handles;
}

test('captures added through the browser’s picker are remembered; Reload all captures reads them all again', async () => {
  const handles = await reopenedWithTwoCaptures();
  expect(captureFileMemory.size).toBe(2);
  expect(await screen.findByText('Re-add synthetic-lab-3.jsonl to continue')).toBeInTheDocument();
  await user.click(await screen.findByRole('button', { name: 'Reload all captures' }));
  await headerShows('111 events');
  await waitFor(() => { expect(screen.queryByText(/^Re-add/)).not.toBeInTheDocument(); });
  for (const h of handles) expect(h.getFile).toHaveBeenCalledTimes(2);
});

test('one capture that is not loaded can be reloaded on its own, from the drop zone or the capture list', async () => {
  const [first, second] = await reopenedWithTwoCaptures();
  expect(await screen.findByText('Reload this session’s captures, or drop a capture file')).toBeInTheDocument();
  const switcher = screen.getByLabelText(/capture/i, { selector: 'select' });
  await user.selectOptions(switcher, within(switcher).getByRole('option', { name: 'synthetic-lab-3.jsonl (not loaded)' }));
  expect(await screen.findByText(/synthetic-lab-3\.jsonl is not loaded\. Reload it, or drop its file to continue\./)).toBeInTheDocument();
  const zone = screen.getByRole('region', { name: 'Add a capture' });
  await user.click(within(zone).getByRole('button', { name: 'Reload synthetic-lab-3.jsonl' }));
  await headerShows('111 events');
  expect(second!.getFile).toHaveBeenCalledTimes(2);
  expect(first!.getFile).toHaveBeenCalledTimes(1);
  // The other one is listed with its own Reload.
  await user.click(await screen.findByRole('button', { name: 'Reload synthetic-lab-2.jsonl' }));
  await waitFor(() => { expect(first!.getFile).toHaveBeenCalledTimes(2); });
  await waitFor(() => { expect(screen.queryByText(/^Re-add/)).not.toBeInTheDocument(); });
});

test('a reload asks for access when the browser forgot it; a file that moved or was refused is named, the rest load', async () => {
  const moved = fileHandle('synthetic-lab-2.jsonl');
  const refusedLater = fileHandle('synthetic-lab-3.jsonl');
  await reopenedWithTwoCaptures([moved, refusedLater]);
  moved.getFile.mockRejectedValue(new DOMException('gone', 'NotFoundError'));
  refusedLater.queryPermission.mockResolvedValue('prompt');
  refusedLater.requestPermission.mockResolvedValue('denied');
  await user.click(await screen.findByRole('button', { name: 'Reload all captures' }));
  const alert = await screen.findByRole('alert');
  expect(alert).toHaveTextContent('synthetic-lab-2.jsonl: the file is no longer where it was; add it again');
  expect(alert).toHaveTextContent('synthetic-lab-3.jsonl: access to the file was refused');
  expect(refusedLater.requestPermission).toHaveBeenCalledWith({ mode: 'read' });
});

test('a dropped file is remembered too, when the browser gives its handle', async () => {
  handleBrowser([]);
  render(<App />);
  await newSession('lab');
  const h = fileHandle('synthetic-lab-2.jsonl');
  const file = dropped('synthetic-lab-2.jsonl');
  const item = { kind: 'file', getAsFile: () => file, getAsFileSystemHandle: vi.fn(async () => h) };
  fireEvent.drop(await screen.findByRole('heading', { level: 1, name: 'lab' }),
    { dataTransfer: { types: ['Files'], files: [file], items: [item], dropEffect: 'copy' } });
  await headerShows('111 events');
  expect(item.getAsFileSystemHandle).toHaveBeenCalled();
  expect([...captureFileMemory.values()]).toEqual([h]);
  expect(await screen.findByRole('button', { name: 'Reload all captures' })).toBeInTheDocument();
});

test('deleting a session forgets its capture files', async () => {
  await reopenedWithTwoCaptures();
  await user.click(screen.getByRole('button', { name: 'Sessions' }));
  await user.click(await screen.findByRole('button', { name: 'Delete lab' }));
  await waitFor(() => { expect(captureFileMemory.size).toBe(0); });
});

test('without file handles (Safari, Firefox) nothing is remembered and there is no Reload', async () => {
  render(<App />);
  await newSession('lab');
  await user.upload(await screen.findByLabelText(/capture files/i), dropped('synthetic-lab-2.jsonl'));
  await headerShows('111 events');
  expect(captureFileMemory.size).toBe(0);
  expect(screen.queryByRole('button', { name: /Reload/ })).not.toBeInTheDocument();
});
