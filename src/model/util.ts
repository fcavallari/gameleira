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
