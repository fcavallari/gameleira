import type { CaptureModel, Image, PersistenceItem, Process } from '../model/types';
import { basename, latestImage, normPath } from '../model/util';

export type Severity = 'high' | 'med' | 'low';
export const SEVERITY_RANK: Record<Severity, number> = { high: 3, med: 2, low: 1 };
export interface RuleCtx { m: CaptureModel; p: Process; img: Image; imgIndex: number }
/** What a match reports. `mitre`, `title` and `explanation` override the rule's own for this finding. */
export interface MatchResult { evidence: string; severity?: Severity; mitre?: string[]; title?: string; explanation?: string }
export interface Rule {
  id: string; title: string; severity: Severity; explanation: string;
  /** Every MITRE ID the rule can cite; a finding cites the subset its trigger fits. */
  mitre: string[];
  scope: 'image' | 'persistence';
  match?(ctx: RuleCtx): MatchResult | null;                                  // scope 'image'
  matchItem?(item: PersistenceItem, m: CaptureModel): MatchResult | null;  // scope 'persistence'
}

export const SHELLS: Set<string> = new Set([
  '/bin/sh', '/bin/bash', '/bin/zsh', '/bin/dash', '/bin/ksh', '/bin/csh', '/bin/tcsh',
]);
const SHELL_NAMES = new Set([...SHELLS].map(basename));
const INTERPRETERS = new Set(['python3', 'osascript', 'perl', 'ruby']);

export const RECON_TOOLS: Set<string> = new Set([
  'system_profiler', 'sw_vers', 'whoami', 'id', 'hostname', 'sysctl', 'ioreg', 'uname', 'ps',
  'airport', 'scutil', 'networksetup', 'security', 'csrutil', 'spctl',
]);

/**
 * Where an odd location is. Strong kinds are places a normal install never runs from: temporary folders, Downloads,
 * /Users/Shared, mounted volumes, App Translocation, and a hidden folder buried below a visible one under home.
 * Weak kinds are where developer tools live: a dot-folder directly under home (~/.cargo, ~/.local), or a hidden
 * folder inside a project tooling or build folder (.git/hooks, node_modules/.bin, .build, .terraform).
 */
export type LocationKind = 'translocated' | 'temp' | 'shared' | 'downloads' | 'volume' | 'hidden' | 'home-dot' | 'tooling';
export interface OddLocation { strength: 'strong' | 'weak'; kind: LocationKind }

/** How each kind reads in an explanation ("Ran a program from …") and, shorter, in evidence. */
export const LOCATION_WORDS: Record<LocationKind, { long: string; short: string }> = {
  translocated: { long: 'a translocated app (macOS ran a quarantined download from a random read-only copy)', short: 'App Translocation' },
  temp: { long: 'a temporary folder', short: 'temporary folder' },
  shared: { long: 'the shared folder /Users/Shared, which every user can write to', short: '/Users/Shared' },
  downloads: { long: 'the Downloads folder', short: 'Downloads' },
  volume: { long: 'a mounted disk image or external volume (/Volumes)', short: '/Volumes' },
  hidden: { long: 'a hidden folder inside a visible one', short: 'hidden folder' },
  'home-dot': { long: 'a dot-folder in the home folder, where developer tools usually live', short: 'home dot-folder' },
  tooling: { long: 'a hidden folder inside a project tooling or build folder, where developer tools usually live', short: 'developer tooling folder' },
};

const STRONG_LOCATIONS: [RegExp, LocationKind][] = [
  [/\/AppTranslocation\//i, 'translocated'],
  [/^\/(?:tmp|var\/tmp|var\/folders)\//i, 'temp'],
  [/^\/Users\/Shared\//i, 'shared'],
  [/^\/Users\/[^/]+\/Downloads\//i, 'downloads'],
  [/^\/Volumes\//i, 'volume'],
];
const HOME = /^\/Users\/[^/]+\//i;
/** Project tooling and build folders (hooks, virtualenvs, package installs, build output), compared lower-case. */
const TOOLING_DIRS = new Set([
  '.git', '.venv', 'venv', '.tox', '.direnv', '.husky', 'node_modules', '.pnpm-store',
  '.build', '.terraform', '.next', '.cargo', '.gradle', '.m2', '.cache', '.npm', '.yarn', 'target', 'deriveddata',
]);

export function oddLocation(path: string): OddLocation | null {
  const p = normPath(path);
  for (const [re, kind] of STRONG_LOCATIONS) if (re.test(p)) return { strength: 'strong', kind };
  const home = HOME.exec(p);
  if (!home) return null;
  // Walk the folders below home, top down. A tooling folder only softens hidden folders found below it, so
  // ~/Desktop/.hidden/node_modules/x is still strong: the buried hidden folder comes first.
  const dirs = p.slice(home[0].length).split('/').slice(0, -1);
  let inTooling = false;
  for (let i = 0; i < dirs.length; i++) {
    const seg = dirs[i]!;
    const tooling = TOOLING_DIRS.has(seg.toLowerCase());
    if (seg.startsWith('.')) {
      if (i === 0) return { strength: 'weak', kind: 'home-dot' };
      return inTooling || tooling ? { strength: 'weak', kind: 'tooling' } : { strength: 'strong', kind: 'hidden' };
    }
    if (tooling) inTooling = true;
  }
  return null;
}

/** `-x`, or a short-option cluster such as `-cr` containing x; `--long` options never match. */
export function hasShortFlag(args: string[], letter: string): boolean {
  return args.some(a => a === `-${letter}` || (/^-[A-Za-z]+$/.test(a) && a.includes(letter)));
}

/** Output targets that are not a file on disk: curl's `-o /dev/null` and `-o -` (stdout). */
const NOT_A_FILE = new Set(['/dev/null', '-']);

/** What the output flag (`-o` for curl, `-O` for wget, or `--output`) points at; undefined when the flag has no value. */
function outputTargets(a: string[], letter: string): (string | undefined)[] {
  const out: (string | undefined)[] = [];
  a.forEach((x, i) => {
    if (x === '--output') out.push(a[i + 1]);
    else if (x.startsWith('--output=')) out.push(x.slice('--output='.length));
    else if (/^-[A-Za-z]+$/.test(x) && x.includes(letter)) out.push(a[i + 1]);
  });
  return out;
}

const LAUNCH_DIR = /^(?:\/Users\/[^/]+\/Library\/LaunchAgents|\/Library\/Launch(?:Agents|Daemons))\//i;
const DAEMON_DIR = /^\/Library\/LaunchDaemons\//i;

type LaunchKind = 'agent' | 'daemon' | 'login' | 'app' | 'user' | null;
/** The kind of launch item, from the btm item type (0 user item, 1 app, 2 login item, 3 agent, 4 daemon) or its plist directory. */
function launchKind(itemType: number | null, plistPath: string | null): LaunchKind {
  const byType: LaunchKind[] = ['user', 'app', 'login', 'agent', 'daemon'];
  if (itemType !== null && byType[itemType] !== undefined) return byType[itemType]!;
  if (plistPath === null) return null;
  const n = normPath(plistPath);
  return DAEMON_DIR.test(n) ? 'daemon' : LAUNCH_DIR.test(n) ? 'agent' : null;
}
const LAUNCH_MITRE: Record<NonNullable<LaunchKind>, string> = {
  agent: 'T1543.001', daemon: 'T1543.004', login: 'T1547.015', app: 'T1547.015', user: 'T1547.015',
};
const launchMitre = (k: LaunchKind): string[] => (k === null ? ['T1543.001', 'T1543.004'] : [LAUNCH_MITRE[k]]);
const LAUNCH_TITLE: Record<NonNullable<LaunchKind>, string> = {
  agent: 'Launch agent registered', daemon: 'Launch daemon registered', login: 'Login item registered',
  app: 'App registered to open at login', user: 'Login item registered (user item)',
};
const LAUNCH_EXPLANATION: Record<NonNullable<LaunchKind>, string> = {
  agent: 'Registered a launch agent: launchd starts the program it names each time this user logs in.',
  daemon: 'Registered a launch daemon: launchd starts the program it names at boot, usually as root, before anyone logs in.',
  login: 'Registered a login item: macOS opens it each time this user logs in.',
  app: 'Registered an app to open each time this user logs in.',
  user: 'Added a login item to the user\'s list: macOS opens it each time this user logs in.',
};
const TERMINALS_EDITORS =
  /\/(?:Terminal|iTerm2?|Visual Studio Code|Code|Cursor|Xcode|Claude|Warp|Ghostty|Alacritty|kitty|WezTerm)\.app\//;

const MAX_EVIDENCE = 300;

function cmdline(img: Image): string {
  const s = img.args && img.args.length > 0 ? img.args.join(' ') : (img.path ?? '');
  return s.length > MAX_EVIDENCE ? `${s.slice(0, MAX_EVIDENCE)}…` : s;
}

function rest(img: Image): string[] {
  return img.args?.slice(1) ?? [];
}

const isAdhoc = (img: Image): boolean => (img.csFlags & 0x2) !== 0;
const isUnsigned = (img: Image): boolean => !img.isPlatform && img.signingId === null;

/** Last image the rules run on, so per-process rules fire once. */
function lastRuleImage(p: Process): number {
  for (let i = p.images.length - 1; i >= 0; i--) {
    const img = p.images[i]!;
    if (!img.inherited && img.path !== null) return i;
  }
  return -1;
}

function originalParentImage(m: CaptureModel, p: Process): Image | undefined {
  const parent = p.originalParent !== null ? m.processes.get(p.originalParent) : undefined;
  return parent ? latestImage(parent) : undefined;
}

function trimSlash(p: string): string {
  return p.length > 1 ? p.replace(/\/+$/, '') : p;
}

/** "Ran a program from a temporary folder, …": the explanation of an odd-location-exec finding, from what triggered it. */
function oddLocationExplanation(hits: { what: 'program' | 'script'; where: OddLocation }[]): string {
  const parts = hits.map(h => `${h.what} from ${LOCATION_WORDS[h.where.kind].long}`);
  const weakOnly = hits.every(h => h.where.strength === 'weak');
  return `Ran a ${parts.join(', and a ')}, not from /Applications or a system folder.`
    + (weakOnly ? ' On its own this is a weak signal.' : ' Malware is commonly run from places like this.');
}

const PERSISTENCE_EXPLANATION = 'Something registered itself to run automatically at login or boot.';

export const RULES: Rule[] = [
  {
    id: 'fake-prompt', title: 'Dialog box from osascript', severity: 'high',
    explanation: 'Shows a dialog box. Info-stealers use this to fake a system password prompt.',
    mitre: ['T1056.002'], scope: 'image',
    match: ({ img }) => {
      if (basename(img.path) !== 'osascript' || !img.args) return null;
      return /display dialog|password|hidden answer/i.test(img.args.join(' ')) ? { evidence: cmdline(img) } : null;
    },
  },
  {
    id: 'dscl-authonly', title: 'Password check with dscl', severity: 'high',
    explanation: 'Checks whether a password is correct for a local account. Stealers run it to verify a password the attacker just phished with a fake prompt.',
    mitre: ['T1056.002'], scope: 'image',
    match: ({ img }) =>
      basename(img.path) === 'dscl' && rest(img).includes('-authonly') ? { evidence: cmdline(img) } : null,
  },
  {
    id: 'persistence-item', title: 'Launch item registered', severity: 'high',
    explanation: PERSISTENCE_EXPLANATION,
    mitre: ['T1543.001', 'T1543.004', 'T1547.015'], scope: 'persistence',
    matchItem: (item, m) => {
      if (item.kind !== 'add') return null;
      const exe = item.executablePath;
      const app = item.appPath !== null ? trimSlash(item.appPath) : null;
      const evidence = [
        item.plistPath !== null ? `plist ${item.plistPath}` : null,
        exe !== null ? `runs ${exe}` : null,
        app !== null ? `app ${app}` : null,
      ].filter(Boolean).join('; ') || 'launch item with no paths';
      let high = false;
      if (exe !== null) {
        const n = basename(exe);
        if (SHELL_NAMES.has(n) || INTERPRETERS.has(n) || oddLocation(exe) !== null) high = true;
        else {
          const key = normPath(exe);
          for (const p of m.processes.values()) {
            if (p.images.some(i => i.path !== null && normPath(i.path) === key && i.signingId === null)) { high = true; break; }
          }
        }
      }
      const kind = launchKind(item.itemType, item.plistPath);
      return {
        evidence, severity: high ? 'high' : 'med', mitre: launchMitre(kind),
        ...(kind !== null ? { title: LAUNCH_TITLE[kind], explanation: LAUNCH_EXPLANATION[kind] } : {}),
      };
    },
  },
  {
    id: 'persistence-plist', title: 'Launch agent/daemon plist written', severity: 'high',
    explanation: PERSISTENCE_EXPLANATION,
    mitre: ['T1543.001', 'T1543.004'], scope: 'image',
    match: ({ m, p, imgIndex }) => {
      if (imgIndex !== lastRuleImage(p)) return null;
      const folded = new Set<string>();
      for (const it of m.persistence) {
        if (it.kind === 'add' && it.creator === p.id && it.plistPath !== null) folded.add(normPath(it.plistPath));
      }
      const hits = new Set<string>();
      for (const op of p.fileOps) {
        const target = op.kind === 'create' ? op.path : op.kind === 'rename' ? op.toPath : undefined;
        if (target === undefined) continue;
        const n = normPath(target);
        if (LAUNCH_DIR.test(n) && !folded.has(n)) hits.add(target);
      }
      if (hits.size === 0) return null;
      const kinds = new Set([...hits].map(h => launchKind(null, h)));
      const only = kinds.size === 1 ? [...kinds][0]! : null;
      return {
        evidence: `wrote ${[...hits].join(', ')}`,
        mitre: [...new Set([...kinds].flatMap(launchMitre))].sort(),
        ...(only === 'agent' ? { title: 'Launch agent plist written', explanation: LAUNCH_EXPLANATION.agent }
          : only === 'daemon' ? { title: 'Launch daemon plist written', explanation: LAUNCH_EXPLANATION.daemon } : {}),
      };
    },
  },
  {
    id: 'launchctl-load', title: 'launchctl loaded a job', severity: 'high',
    explanation: 'Loads a launch agent/daemon immediately instead of waiting for login.',
    mitre: ['T1569.001'], scope: 'image',
    match: ({ img }) => {
      if (basename(img.path) !== 'launchctl') return null;
      const sub = img.args?.[1];
      return sub === 'load' || sub === 'bootstrap' || sub === 'submit' ? { evidence: cmdline(img) } : null;
    },
  },
  {
    id: 'quarantine-strip', title: 'Quarantine flag removed', severity: 'high',
    explanation: "Removed the quarantine flag macOS puts on downloaded files, so Gatekeeper won't check it.",
    mitre: ['T1553.001'], scope: 'image',
    match: ({ img }) => {
      if (basename(img.path) !== 'xattr') return null;
      const a = rest(img);
      return hasShortFlag(a, 'c') || (hasShortFlag(a, 'd') && a.includes('com.apple.quarantine'))
        ? { evidence: cmdline(img) } : null;
    },
  },
  {
    id: 'payload-decode', title: 'Data decoded on the fly', severity: 'med',
    explanation: 'Decoded or decrypted data on the fly, a common way to unpack a hidden payload.',
    mitre: ['T1140'], scope: 'image',
    match: ({ img }) => {
      const n = basename(img.path);
      const a = rest(img);
      if (n === 'openssl' && a.includes('enc') && a.includes('-d')) return { evidence: cmdline(img) };
      if (n === 'base64' && (hasShortFlag(a, 'd') || hasShortFlag(a, 'D') || a.includes('--decode'))) return { evidence: cmdline(img) };
      return null;
    },
  },
  {
    id: 'shell-from-pipe', title: 'Shell reading commands from a pipe', severity: 'med',
    explanation: "A shell ran commands piped into it (`curl … | bash` pattern), so there's no script file on disk to inspect.",
    mitre: ['T1059.004'], scope: 'image',
    match: ({ img }) =>
      img.path !== null && SHELLS.has(img.path) && img.args?.length === 1 && img.stdinIsPipe === true && img.script === null
        ? { evidence: `${cmdline(img)} with stdin from a pipe` } : null,
  },
  {
    id: 'shell-under-app', title: 'App launched a shell', severity: 'med',
    explanation: 'An app launched a shell. Malicious apps and droppers do this to run commands.',
    mitre: ['T1059.004'], scope: 'image',
    match: ({ m, p, img, imgIndex }) => {
      if (img.path === null || !SHELLS.has(img.path)) return null;
      // Once per process: macOS /bin/sh re-execs /bin/bash, which would repeat the finding.
      if (imgIndex !== p.images.findIndex(i => !i.inherited && i.path !== null && SHELLS.has(i.path))) return null;
      const parent = originalParentImage(m, p)?.path ?? null;
      if (parent === null || !parent.includes('.app/')) return null;
      if (TERMINALS_EDITORS.test(parent) || parent.includes('Code Helper')) return null;
      return { evidence: `${parent} ran ${cmdline(img)}` };
    },
  },
  {
    id: 'download', title: 'Download to disk', severity: 'med',
    explanation: 'Fetched something from the network and wrote it to disk.',
    mitre: ['T1105'], scope: 'image',
    match: ({ p, img }) => {
      const n = basename(img.path);
      if (n !== 'curl' && n !== 'wget') return null;
      const a = rest(img);
      let toFile = hasShortFlag(a, 'o') || hasShortFlag(a, 'O') || a.some(x => x === '--output' || x.startsWith('--output='));
      // `curl -o /dev/null` (or `-o -`) throws the body away: nothing was written to disk. curl's `-O` names the file after the URL.
      const targets = outputTargets(a, n === 'curl' ? 'o' : 'O');
      const remoteName = n === 'curl' && hasShortFlag(a, 'O');
      if (targets.length > 0 && !remoteName && targets.every(t => t !== undefined && NOT_A_FILE.has(t))) toFile = false;
      if (toFile) return { evidence: cmdline(img) };
      const created = p.fileOps.find(op => op.kind === 'create');
      return created ? { evidence: `${cmdline(img)}; created ${created.path}` } : null;
    },
  },
  {
    id: 'archive-staging', title: 'Files packed into an archive', severity: 'med',
    explanation: 'Packed files into an archive. Stealers stage collected data this way before sending it out.',
    mitre: ['T1560.001'], scope: 'image',
    match: ({ img }) => {
      const n = basename(img.path);
      const a = rest(img);
      const first = a[0] ?? '';
      const hit = (n === 'ditto' && hasShortFlag(a, 'c')) || n === 'zip'
        // tar's first arg: `--create`, or a mode cluster such as `czf` / `-czf` (not long options like --exclude).
        || (n === 'tar' && (first === '--create' || /^-?[A-Za-z]*c[A-Za-z]*$/.test(first)));
      if (!hit) return null;
      const staged = a.some(x => x.startsWith('/') && oddLocation(x) !== null);
      return { evidence: cmdline(img), severity: staged ? 'high' : 'med' };
    },
  },
  {
    id: 'odd-location-exec', title: 'Ran from an unusual location', severity: 'med',
    explanation: 'Ran a program or script from a temporary folder, Downloads, /Users/Shared, a mounted volume, a translocated app or a hidden folder, not from /Applications or a system folder.',
    mitre: ['T1204.002'], scope: 'image',
    // Low results (team-signed, or a developer tooling location) are gated chain-only by the engine.
    match: ({ img }) => {
      const hits: { severity: Severity; evidence: string; what: 'program' | 'script'; where: OddLocation }[] = [];
      const where = img.path !== null ? oddLocation(img.path) : null;
      if (where !== null) {
        const adhoc = isAdhoc(img);
        const weak: Severity = isUnsigned(img) ? 'med' : 'low';
        const strong: Severity = isUnsigned(img) || adhoc ? 'high' : img.teamId !== null ? 'low' : 'med';
        const signing = !img.signingId ? 'unsigned'
          : adhoc ? `ad-hoc signed (${img.signingId})`
          : img.teamId !== null ? `signed by team ${img.teamId}` : `signed (${img.signingId})`;
        hits.push({
          severity: where.strength === 'strong' ? strong : weak, what: 'program', where,
          evidence: `${img.path} (${LOCATION_WORDS[where.kind].short}), ${signing}`,
        });
      }
      // A script has no signature of its own, so its location alone never makes it high.
      const scriptWhere = img.script !== null ? oddLocation(img.script) : null;
      if (scriptWhere !== null) {
        hits.push({
          severity: scriptWhere.strength === 'strong' ? 'med' : 'low', what: 'script', where: scriptWhere,
          evidence: `script ${img.script} (${LOCATION_WORDS[scriptWhere.kind].short})`,
        });
      }
      if (hits.length === 0) return null;
      const severity = hits.reduce<Severity>((s, h) => (SEVERITY_RANK[h.severity] > SEVERITY_RANK[s] ? h.severity : s), 'low');
      return { evidence: hits.map(h => h.evidence).join('; '), severity, explanation: oddLocationExplanation(hits) };
    },
  },
  {
    id: 'unsigned', title: 'Unsigned binary', severity: 'med',
    explanation: 'Not signed at all. Unsigned binaries are a common trait of malware; not a technique by itself.',
    mitre: ['T1036'], scope: 'image',
    match: ({ img }) => isUnsigned(img) ? { evidence: `${img.path} has no code signature` } : null,
  },
  {
    id: 'adhoc', title: 'Ad-hoc signed binary', severity: 'low',
    explanation: 'Ad-hoc signed: it carries a signature but no developer identity. Common for Homebrew and locally built tools, and for malware; a trait, not a technique by itself.',
    mitre: ['T1036'], scope: 'image',
    match: ({ img }) =>
      !img.isPlatform && img.signingId !== null && isAdhoc(img)
        ? { evidence: `${img.path} is ad-hoc signed (${img.signingId}), with no developer identity` } : null,
  },
  {
    id: 'orphaned', title: 'Detached from its parent', severity: 'low',
    explanation: 'Detached from the process that started it, so it keeps running after its parent exits and no longer shows up under it. Malware double-forks like this to break the link to whatever launched it.',
    mitre: ['T1036.009'], scope: 'image',
    match: ({ m, p, imgIndex }) => {
      if (imgIndex !== lastRuleImage(p)) return null;
      if (p.ppid !== 1 || p.originalPpid === null || p.originalPpid === 1) return null;
      const parent = originalParentImage(m, p)?.path ?? null;
      if (basename(parent) === 'xpcproxy') return null;
      return { evidence: `parent pid ${p.originalPpid}${parent ? ` (${basename(parent)})` : ''} gone; now under launchd` };
    },
  },
  {
    id: 'recon', title: 'System or user discovery', severity: 'low',
    explanation: 'Gathers information about the machine or user.',
    mitre: ['T1082', 'T1033'], scope: 'image',
    match: ({ img }) => RECON_TOOLS.has(basename(img.path)) ? { evidence: cmdline(img) } : null,
  },
];
