// @vitest-environment jsdom
import 'fake-indexeddb/auto';
import '@testing-library/jest-dom/vitest';
import fs from 'node:fs';
import { File as NodeFile } from 'node:buffer';
import { IDBFactory } from 'fake-indexeddb';
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { loadCapture, type LoadedCapture } from '../src/ingest/load';
import { runLoad } from '../src/ingest/run';
import type { Image } from '../src/model/types';
import { latestImage } from '../src/model/util';
import { App, SessionProvider, useSession, type SessionCtx } from '../src/ui/App';
import { openStore, type CaptureRec, type Store, type Verdict } from '../src/session/store';
import { fixture, type FixtureName } from './fixtures';

// The real runLoad starts an inline Worker, which jsdom lacks; delegate to loadCapture instead.
vi.mock('../src/ingest/run', () => ({ runLoad: vi.fn() }));
const runLoadMock = vi.mocked(runLoad);

const CMD = /sudo eslogger fork exec exit create rename unlink setextattr btm_launch_item_add btm_launch_item_remove/;

/** A Node File (jsdom's Blob has no reliable arrayBuffer) holding a small fixture, named like it. */
const nodeFile = (name: FixtureName): File =>
  new NodeFile([fs.readFileSync(fixture(name))], name) as unknown as File;
/** What the user "drops": the bytes are never read, the mocked runLoad looks the fixture up by name. */
const dropped = (name: FixtureName): File => new File(['x'], name);

const loadFixture = (name: FixtureName): Promise<LoadedCapture> => loadCapture(nodeFile(name));

let user: ReturnType<typeof userEvent.setup>;
beforeEach(() => {
  globalThis.indexedDB = new IDBFactory();   // App opens the default DB: isolate every test
  user = userEvent.setup();
  runLoadMock.mockReset();
  runLoadMock.mockImplementation((file, onProgress) => loadCapture(nodeFile(file.name as FixtureName), onProgress));
  Object.defineProperty(navigator, 'storage', {
    configurable: true,
    value: { persist: vi.fn().mockResolvedValue(true), persisted: vi.fn().mockResolvedValue(false) },
  });
  window.confirm = vi.fn(() => true);
  URL.createObjectURL = vi.fn(() => 'blob:fake');
  URL.revokeObjectURL = vi.fn();
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
  expect(await screen.findByText(CMD)).toBeInTheDocument();
  expect(screen.getByRole('heading', { name: 'lab MacBook' })).toBeInTheDocument();
});

test('shows load error in the drop zone', async () => {
  runLoadMock.mockRejectedValue(new Error('No eslogger events found in this file'));
  render(<App />);
  await newSession('lab');
  await user.upload(await screen.findByLabelText(/capture files/i), dropped('spritetree_demo.json'));
  expect(await screen.findByText(/No eslogger events found/)).toBeInTheDocument();
});

test('loads a capture: header counts, tabs and placeholders', async () => {
  render(<App />);
  await newSession('lab');
  await user.upload(await screen.findByLabelText(/capture files/i), dropped('spritetree_demo.json'));
  await headerShows('242 events');
  const group = screen.getByRole('group', { name: 'Capture counts' });
  for (const re of [/^\d+ processes$/, /^\d+ flagged$/, /^\d+ confirmed$/, /^\d+ routine hidden$/]) {
    expect(within(group).getByText(re)).toBeInTheDocument();
  }
  expect(screen.getByText(/^Triage: \d+ flagged$/)).toBeInTheDocument();
  await user.click(screen.getByRole('tab', { name: 'Tree' }));
  expect(screen.getByText(/^Tree: \d+ processes$/)).toBeInTheDocument();
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
  await user.upload(await screen.findByLabelText(/capture files/i), dropped('spritetree_demo.json'));
  expect(await screen.findByRole('progressbar')).toHaveAttribute('value', '50');
  expect(screen.queryByText(/Analysing/)).not.toBeInTheDocument();
  const progress = runLoadMock.mock.calls[0]![1];
  act(() => { progress(100, 100); });
  expect(await screen.findByText(/Analysing…/)).toBeInTheDocument();
  await act(async () => { finish(await loadFixture('spritetree_demo.json')); });
  await headerShows('242 events');
  expect(screen.queryByText(/Analysing/)).not.toBeInTheDocument();
});

test('a stored capture that is not loaded asks for a re-add; a matching drop restores it, another is new', async () => {
  const store = await openStore();
  const s = await store.createSession('old lab');
  const demo = await loadFixture('spritetree_demo.json');
  const rec = (c: LoadedCapture, size = 1): CaptureRec => ({ sessionId: s.id, fingerprint: c.fingerprint, fileName: c.fileName,
    size, events: c.model.stats.events, processes: c.model.processes.size, flagged: 0, added: 't' });
  await store.upsertCapture(rec(demo));
  render(<App />);
  await user.click(await screen.findByRole('button', { name: 'old lab' }));
  expect(await screen.findByText('Re-add spritetree_demo.json to continue')).toBeInTheDocument();

  await user.upload(screen.getByLabelText(/capture files/i), dropped('spritetree_demo.json'));
  await headerShows('242 events');
  expect(screen.queryByText(/Re-add/)).not.toBeInTheDocument();
  expect(await store.listCaptures(s.id)).toHaveLength(1);   // same fingerprint: restored, not duplicated
  expect((await store.listCaptures(s.id))[0]!.size).toBe(demo.size);

  await user.upload(screen.getByLabelText(/capture files/i), dropped('shlayer.json'));
  await headerShows('616 events');
  expect(await store.listCaptures(s.id)).toHaveLength(2);
  const switcher = screen.getByLabelText(/capture/i, { selector: 'select' });
  expect(within(switcher).getAllByRole('option')).toHaveLength(2);
});

test('switching to a capture that is not loaded shows the re-add prompt instead of tabs', async () => {
  const store = await openStore();
  const s = await store.createSession('lab');
  const demo = await loadFixture('spritetree_demo.json');
  await store.upsertCapture({ sessionId: s.id, fingerprint: 'other-fp', fileName: 'gone.jsonl', size: 1,
    events: 5, processes: 2, flagged: 0, added: 't' });
  render(<App />);
  await user.click(await screen.findByRole('button', { name: 'lab' }));
  await user.upload(await screen.findByLabelText(/capture files/i), dropped('spritetree_demo.json'));
  await headerShows('242 events');
  await user.selectOptions(screen.getByLabelText(/capture/i, { selector: 'select' }), 'other-fp');
  expect(screen.getAllByText('Re-add gone.jsonl to continue').length).toBeGreaterThan(0);
  expect(screen.getByText(/gone\.jsonl is not loaded/)).toBeInTheDocument();
  expect(screen.queryByText(/^Triage:/)).not.toBeInTheDocument();
  expect(screen.queryByRole('group', { name: 'Capture counts' })).not.toBeInTheDocument();
  expect(demo.fingerprint).not.toBe('other-fp');
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
  expect(exported.format).toBe('eslogger-viewer-session');
  expect(exported.verdicts).toHaveLength(3);

  // import creates a new session, never touches this one
  const file = new File([JSON.stringify(exported)], 'lab.json', { type: 'application/json' });
  await user.upload(screen.getByLabelText(/import session/i), file);
  expect(await screen.findByText(/Imported as “lab \(imported\)”/)).toBeInTheDocument();
  expect((await store.listSessions()).map(x => x.name).sort()).toEqual(['lab', 'lab (imported)']);
});

test('import shows the error for a file that is not a session export', async () => {
  render(<App />);
  await newSession('lab');
  await user.click(await screen.findByRole('tab', { name: 'Confirmed' }));
  await user.upload(screen.getByLabelText(/import session/i), new File(['{"nope":1}'], 'x.json'));
  expect(await screen.findByText(/not an eslogger-viewer session export/)).toBeInTheDocument();
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
  expect(await screen.findByText(CMD)).toBeInTheDocument();
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

async function withSession(name: FixtureName = 'shlayer.json'): Promise<{ store: Store; sessionId: string; demo: LoadedCapture }> {
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
  await act(async () => { await ctx.loadFiles([dropped('shlayer.json')]); });
  const cap = ctx.captures.get(ctx.active!)!;
  const item = cap.analysis.queue.find(q => q.kind === 'process' && latestImage(cap.model.processes.get(q.procId!)!)?.path)!;
  const total = ctx.triage!.queue.length;
  expect(ctx.triage!.hiddenCount).toBe(0);
  await act(async () => { await ctx.addRoutine(latestImage(cap.model.processes.get(item.procId!)!)!); });
  expect(ctx.triage!.hiddenCount).toBeGreaterThan(0);
  expect(ctx.triage!.queue.length + ctx.triage!.hiddenCount).toBe(total);
  expect(screen.getByTestId('hidden')).toHaveTextContent(`${ctx.triage!.hiddenCount} routine hidden`);
});
