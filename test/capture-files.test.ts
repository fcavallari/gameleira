import 'fake-indexeddb/auto';
import { expect, test, vi } from 'vitest';
import { forgetCaptureFiles, rememberCaptureFile, rememberedCaptureFiles, reopenCaptureFile, sourcedFromDrop, type CaptureFileHandle } from '../src/session/capture-files';

const handle = (over: Partial<CaptureFileHandle> = {}): CaptureFileHandle => ({
  kind: 'file', name: 'c.jsonl', getFile: async () => new File(['x'], 'c.jsonl'),
  queryPermission: async () => 'granted', requestPermission: async () => 'granted', ...over,
});

test('remembered files are kept per session and fingerprint, and forgotten per session', async () => {
  // Structured clone keeps data, not methods: a plain record stands in for a real handle here.
  const h = (name: string) => ({ kind: 'file', name }) as unknown as CaptureFileHandle;
  await rememberCaptureFile('s1', 'fpA', h('a'));
  await rememberCaptureFile('s1', 'fpB', h('b'));
  await rememberCaptureFile('s2', 'fpA', h('other'));
  const s1 = await rememberedCaptureFiles('s1');
  expect([...s1.keys()].sort()).toEqual(['fpA', 'fpB']);
  expect(s1.get('fpB')!.name).toBe('b');
  await forgetCaptureFiles('s1');
  expect((await rememberedCaptureFiles('s1')).size).toBe(0);
  expect((await rememberedCaptureFiles('s2')).get('fpA')!.name).toBe('other');
});

test('reopenCaptureFile asks only when needed and says why a file cannot be read', async () => {
  const request = vi.fn(async () => 'granted' as const);
  await expect(reopenCaptureFile(handle({ requestPermission: request }))).resolves.toBeInstanceOf(File);
  expect(request).not.toHaveBeenCalled();
  await expect(reopenCaptureFile(handle({ queryPermission: async () => 'prompt', requestPermission: request }))).resolves.toBeInstanceOf(File);
  expect(request).toHaveBeenCalledWith({ mode: 'read' });

  await expect(reopenCaptureFile(handle({ queryPermission: async () => 'prompt', requestPermission: async () => 'denied' })))
    .rejects.toThrow('access to the file was refused');
  await expect(reopenCaptureFile(handle({ queryPermission: async () => 'prompt',
    requestPermission: async () => { throw new DOMException('no activation', 'SecurityError'); } })))
    .rejects.toThrow(/needs another click/);
  await expect(reopenCaptureFile(handle({ getFile: async () => { throw new DOMException('gone', 'NotFoundError'); } })))
    .rejects.toThrow('the file is no longer where it was; add it again');
});

test('sourcedFromDrop pairs each dropped file with its handle; folders and missing handles give none', async () => {
  const f1 = new File(['1'], 'one.jsonl');
  const f2 = new File(['2'], 'two.jsonl');
  const h1 = handle({ name: 'one.jsonl' });
  const dt = { files: [f1, f2], items: [
    { kind: 'file', getAsFile: () => f1, getAsFileSystemHandle: async () => h1 },
    { kind: 'file', getAsFile: () => f2, getAsFileSystemHandle: async () => ({ kind: 'directory' }) },
    { kind: 'string', getAsFile: () => null },
  ] } as unknown as DataTransfer;
  expect(await sourcedFromDrop(dt)).toEqual([{ file: f1, handle: h1 }, { file: f2, handle: null }]);
  // A browser without getAsFileSystemHandle, or a drop with no items: the files load without handles.
  expect(await sourcedFromDrop({ files: [f1], items: [{ kind: 'file', getAsFile: () => f1 }] } as unknown as DataTransfer))
    .toEqual([{ file: f1, handle: null }]);
  expect(await sourcedFromDrop({ files: [f2], items: [] } as unknown as DataTransfer)).toEqual([{ file: f2, handle: null }]);
});
