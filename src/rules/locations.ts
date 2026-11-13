import { normPath } from '../model/util';

/**
 * Where an odd location is. Strong kinds are places a normal install never runs from: temporary folders, Downloads,
 * /Users/Shared, mounted volumes, App Translocation, and a hidden folder buried below a visible one under home.
 * Weak kinds are where developer tools live: a dot-folder directly under home (~/.cargo, ~/.local), a hidden folder
 * inside a project build or tooling folder (.git/hooks, node_modules/.bin, .build, .terraform), or Go's build folder
 * in the temporary area (go test and go run binaries).
 */
export type LocationKind = 'translocated' | 'temp' | 'shared' | 'downloads' | 'volume' | 'hidden' | 'home-dot' | 'tooling' | 'go-build';
export interface OddLocation { strength: 'strong' | 'weak'; kind: LocationKind }

/** How each kind reads where a program ran from it ("Ran a program from …") and, shorter, in evidence. */
export const LOCATION_WORDS: Record<LocationKind, { long: string; short: string }> = {
  translocated: { long: 'a translocated app (macOS ran a quarantined download from a random read-only copy)', short: 'App Translocation' },
  temp: { long: 'a temporary folder', short: 'temporary folder' },
  shared: { long: 'the shared folder /Users/Shared, which every user can write to', short: '/Users/Shared' },
  downloads: { long: 'the Downloads folder', short: 'Downloads' },
  volume: { long: 'a mounted disk image or external volume (/Volumes)', short: '/Volumes' },
  hidden: { long: 'a hidden folder inside a visible one', short: 'hidden folder' },
  'home-dot': { long: 'a dot-folder in the home folder, where developer tools usually live', short: 'home dot-folder' },
  tooling: { long: 'a hidden folder inside a project build or tooling folder, where developer tools usually live', short: 'build or tooling folder' },
  'go-build': { long: 'a Go build folder in the temporary area, where go test and go run put their binaries', short: 'go-build folder' },
};

const STRONG_LOCATIONS: [RegExp, LocationKind][] = [
  [/\/AppTranslocation\//i, 'translocated'],
  [/^\/(?:tmp|var\/tmp|var\/folders)\//i, 'temp'],
  [/^\/Users\/Shared\//i, 'shared'],
  [/^\/Users\/[^/]+\/Downloads\//i, 'downloads'],
  [/^\/Volumes\//i, 'volume'],
];
/** Go's per-build folder in the per-user temporary area: /var/folders/xx/yyyy/T/go-build1234/. */
const GO_BUILD_TEMP = /^\/var\/folders\/[^/]+\/[^/]+\/T\/go-build[^/]*\//i;
export const HOME = /^\/Users\/[^/]+\//i;
/** Project tooling and build folders (hooks, virtualenvs, package installs, build output), compared lower-case. */
const TOOLING_DIRS = new Set([
  '.git', '.venv', 'venv', '.tox', '.direnv', '.husky', 'node_modules', '.pnpm-store',
  '.build', '.terraform', '.next', '.cargo', '.gradle', '.m2', '.cache', '.npm', '.yarn', 'target', 'deriveddata',
]);
const isToolingDir = (seg: string): boolean => TOOLING_DIRS.has(seg.toLowerCase()) || /^go-build/i.test(seg);

/** The temporary, shared, download, volume or translocation place a (normalized) path is in, if any. */
export function strongPlace(p: string): OddLocation | null {
  for (const [re, kind] of STRONG_LOCATIONS) if (re.test(p)) return { strength: 'strong', kind };
  return null;
}

/** True when some folder on the path is a project build or tooling folder (node_modules, .build, go-build…). */
export function inBuildDir(path: string): boolean {
  return normPath(path).split('/').some(isToolingDir);
}

export function oddLocation(path: string): OddLocation | null {
  const p = normPath(path);
  if (GO_BUILD_TEMP.test(p)) return { strength: 'weak', kind: 'go-build' };
  const strong = strongPlace(p);
  if (strong !== null) return strong;
  const home = HOME.exec(p);
  if (!home) return null;
  // Walk the folders below home, top down. A tooling folder only softens hidden folders found below it, so
  // ~/Desktop/.hidden/node_modules/x is still strong: the buried hidden folder comes first.
  const dirs = p.slice(home[0].length).split('/').slice(0, -1);
  let inTooling = false;
  for (let i = 0; i < dirs.length; i++) {
    const seg = dirs[i]!;
    const tooling = isToolingDir(seg);
    if (seg.startsWith('.')) {
      if (i === 0) return { strength: 'weak', kind: 'home-dot' };
      return inTooling || tooling ? { strength: 'weak', kind: 'tooling' } : { strength: 'strong', kind: 'hidden' };
    }
    if (tooling) inTooling = true;
  }
  return null;
}

/** An absolute path, or a relative one joined to the working directory when it is known. */
export function resolvePath(path: string, cwd: string | null): string {
  if (path.startsWith('/') || cwd === null) return path;
  return `${cwd.replace(/\/+$/, '')}/${path.replace(/^\.\//, '')}`;
}
