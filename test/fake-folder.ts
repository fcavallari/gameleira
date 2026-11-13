import { vi } from 'vitest';
import type { DirHandle, FileEntry } from '../src/session/folder';

export interface FakeFile { text: string; lastModified: number }

/**
 * An in-memory folder shaped like the File System Access API's directory handle (jsdom has none). `files` is live: tests
 * read what was written and add files. `permission` is what both queryPermission and requestPermission answer.
 */
export function fakeFolder(name: string, files: Record<string, FakeFile> = {}, permission: PermissionState = 'granted') {
  const entry = (n: string): FileEntry => ({
    kind: 'file', name: n,
    getFile: async () => {
      const f = files[n];
      if (!f) throw new DOMException(`${n} is gone`, 'NotFoundError');
      return { lastModified: f.lastModified, text: async () => f.text };
    },
    createWritable: async () => {
      let buf = '';
      return { write: async (d: string) => { buf += d; }, close: async () => { files[n] = { text: buf, lastModified: Date.now() }; } };
    },
  });
  const dir = {
    kind: 'directory' as const, name, files,
    async *values() { for (const n of Object.keys(files)) yield entry(n); },
    getFileHandle: async (n: string, opts?: { create?: boolean }) => {
      if (!(n in files) && !opts?.create) throw new DOMException(`${n} not found`, 'NotFoundError');
      return entry(n);
    },
    queryPermission: vi.fn(async () => permission),
    requestPermission: vi.fn(async () => permission),
  };
  return dir satisfies DirHandle;
}
