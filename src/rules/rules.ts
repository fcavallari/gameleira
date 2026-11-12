import type { CaptureModel, Image, PersistenceItem, Process } from '../model/types';
import { basename, latestImage, normPath } from '../model/util';

export type Severity = 'high' | 'med' | 'low';
export interface RuleCtx { m: CaptureModel; p: Process; img: Image; imgIndex: number }
export interface Rule {
  id: string; title: string; severity: Severity; explanation: string; mitre: string[];
  scope: 'image' | 'persistence';
  match(ctx: RuleCtx): { evidence: string; severity?: Severity } | null;               // scope 'image'
  matchItem?(item: PersistenceItem, m: CaptureModel): { evidence: string; severity?: Severity } | null; // scope 'persistence'
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

/** Temporary, download, removable-media and hidden locations a normal install never runs from. */
const USER_WRITABLE: RegExp[] = [
  /^\/tmp\//, /^\/var\/folders\//, /^\/Users\/Shared\//, /^\/Users\/[^/]+\/Downloads\//,
  /^\/Volumes\//, /\/AppTranslocation\//, /^\/Users\/(?:[^/]+\/)*\.[^/]+\//,
];
export function isUserWritable(path: string): boolean {
  const p = normPath(path);
  return USER_WRITABLE.some(re => re.test(p));
}

const LAUNCH_DIR = /^(?:\/Users\/[^/]+\/Library\/LaunchAgents|\/Library\/Launch(?:Agents|Daemons))\//;
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

const PERSISTENCE_EXPLANATION = 'Something registered itself to run automatically at login or boot.';
const UNSIGNED_EXPLANATION = 'Not signed by an identified developer.';

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
    explanation: 'Checks whether a password is correct. Stealers use it to verify a password they just phished.',
    mitre: ['T1110', 'T1056'], scope: 'image',
    match: ({ img }) =>
      basename(img.path) === 'dscl' && rest(img).includes('-authonly') ? { evidence: cmdline(img) } : null,
  },
  {
    id: 'persistence-item', title: 'Launch item registered', severity: 'high',
    explanation: PERSISTENCE_EXPLANATION,
    mitre: ['T1543.001', 'T1543.004'], scope: 'persistence',
    match: () => null,
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
        if (SHELL_NAMES.has(n) || INTERPRETERS.has(n) || isUserWritable(exe)) high = true;
        else {
          const key = normPath(exe);
          for (const p of m.processes.values()) {
            if (p.images.some(i => i.path !== null && normPath(i.path) === key && i.signingId === null)) { high = true; break; }
          }
        }
      }
      return { evidence, severity: high ? 'high' : 'med' };
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
      return hits.size > 0 ? { evidence: `wrote ${[...hits].join(', ')}` } : null;
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
      return a.includes('-c') || (a.includes('-d') && a.includes('com.apple.quarantine'))
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
      if (n === 'base64' && a.some(x => x === '-d' || x === '-D' || x === '--decode')) return { evidence: cmdline(img) };
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
      const toFile = rest(img).some(x => x === '-o' || x === '-O' || x === '--output' || x.startsWith('--output='));
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
      const hit = (n === 'ditto' && a.includes('-c')) || n === 'zip'
        // tar's first arg: `--create`, or a mode cluster such as `czf` / `-czf` (not long options like --exclude).
        || (n === 'tar' && (first === '--create' || /^-?[A-Za-z]*c[A-Za-z]*$/.test(first)));
      if (!hit) return null;
      const staged = a.some(x => x.startsWith('/') && isUserWritable(x));
      return { evidence: cmdline(img), severity: staged ? 'high' : 'med' };
    },
  },
  {
    id: 'odd-location-exec', title: 'Ran from an unusual location', severity: 'med',
    explanation: 'A program ran from a temporary or downloads location rather than `/Applications` or system paths.',
    mitre: ['T1204.002'], scope: 'image',
    match: ({ img }) => {
      if (img.path === null || !isUserWritable(img.path)) return null;
      const severity: Severity = isUnsigned(img) || isAdhoc(img) ? 'high'
        : img.teamId !== null ? 'low' : 'med';
      const signing = img.signingId === null ? 'unsigned'
        : isAdhoc(img) ? `ad-hoc signed (${img.signingId})`
        : img.teamId !== null ? `signed by team ${img.teamId}` : `signed (${img.signingId})`;
      return { evidence: `${img.path}, ${signing}`, severity };
    },
  },
  {
    id: 'unsigned', title: 'Unsigned binary', severity: 'med',
    explanation: UNSIGNED_EXPLANATION,
    mitre: ['T1553.002'], scope: 'image',
    match: ({ img }) => isUnsigned(img) ? { evidence: `${img.path} has no code signature` } : null,
  },
  {
    id: 'adhoc', title: 'Ad-hoc signed binary', severity: 'low',
    explanation: UNSIGNED_EXPLANATION,
    mitre: ['T1553.002'], scope: 'image',
    match: ({ img }) =>
      !img.isPlatform && img.signingId !== null && isAdhoc(img)
        ? { evidence: `${img.path} is ad-hoc signed (${img.signingId}), with no developer identity` } : null,
  },
  {
    id: 'orphaned', title: 'Detached from its parent', severity: 'low',
    explanation: 'Detached from the process that started it, so it keeps running after its parent exits.',
    mitre: ['T1564'], scope: 'image',
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
