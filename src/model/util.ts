import type { Image, Process } from './types';

export function basename(p: string | null): string {
  if (!p) return '';
  const trimmed = p.length > 1 ? p.replace(/\/+$/, '') : p;
  const i = trimmed.lastIndexOf('/');
  return i < 0 ? trimmed : trimmed.slice(i + 1);
}

export function latestImage(p: Process): Image | undefined {
  return p.images[p.images.length - 1];
}

/** The image a process was running at `seq`: its latest image with seq <= `seq`, else its first. */
export function imageAt(p: Process, seq: number): Image | undefined {
  for (let i = p.images.length - 1; i >= 0; i--) if (p.images[i]!.seq <= seq) return p.images[i];
  return p.images[0];
}

/** Canonical form for path matching only: /private/{tmp,var,etc} -> /{tmp,var,etc}; /users/ -> /Users/. */
export function normPath(p: string): string {
  return p
    .replace(/^\/private(?=\/(?:tmp|var|etc)(?:\/|$))/, '')
    .replace(/^\/users\//, '/Users/');
}

export function fileUrlToPath(u: string | null): string | null {
  if (!u) return null;
  if (!u.startsWith('file://')) return u;
  let rest = u.slice('file://'.length);
  if (rest.startsWith('localhost/')) rest = rest.slice('localhost'.length);
  try {
    return decodeURIComponent(rest);
  } catch {
    return rest;
  }
}

/**
 * What a btm item's URL (PersistenceItem.plistPath) points at. The field name is older than this: for a launch agent or
 * daemon the URL is its plist, but for a login item or an app it is the app bundle (`file:///Applications/Evil.app/`),
 * and for a user item some other path. Screens use this to label it correctly.
 */
export function itemPathKind(path: string | null): 'plist' | 'app' | 'other' | null {
  if (path === null || path === '') return null;
  if (/\.plist$/i.test(path)) return 'plist';
  return /\.app\/*$/i.test(path) ? 'app' : 'other';
}

/**
 * An absolute path, or a relative one joined to `base` (a working directory, or the app bundle a btm path is relative
 * to) with `.` and `..` segments folded. `base` null or not absolute: returned as it is. The one resolver for both.
 */
export function resolvePath(path: string, base: string | null): string {
  if (path.startsWith('/') || base === null || !base.startsWith('/')) return path;
  const out: string[] = [];
  for (const seg of `${base}/${path}`.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') out.pop();
    else out.push(seg);
  }
  return `/${out.join('/')}`;
}

/** A relative path resolved against the app bundle it is relative to; null stays null. */
export function resolveAgainstApp(path: string | null, app: string | null): string | null {
  return path === null ? null : resolvePath(path, app);
}
