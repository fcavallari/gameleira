import type { CaptureModel, Image, PersistenceItem, ProcId, Process } from '../model/types';
import { basename, imageAt, normPath } from '../model/util';
import {
  CURL_SPEC, hasOpt, hasShortFlag, looksLikeUrl, optValues, osascriptArgs, parseOpts, PIPE_LANGS, readsStdin,
  SECURITY_FIND_SPEC, securityArgs, stagingPlace, tarCreates, WGET_SPEC, type PipeLang,
} from './args';
import { HOME, LOCATION_WORDS, oddLocation, resolvePath, type LocationKind, type OddLocation } from './locations';

export type Severity = 'high' | 'med' | 'low';
export const SEVERITY_RANK: Record<Severity, number> = { high: 3, med: 2, low: 1 };
export interface RuleCtx { m: CaptureModel; p: Process; img: Image; imgIndex: number }
/** What a match reports. `mitre`, `title` and `explanation` override the rule's own for this finding. */
export interface MatchResult { evidence: string; severity?: Severity; mitre?: string[]; title?: string; explanation?: string }
export interface Rule {
  id: string; title: string; severity: Severity; explanation: string;
  /** Every MITRE ID the rule can cite; a finding cites the subset its trigger fits. Empty only for a trait rule. */
  mitre: string[];
  /** A trait of the binary (unsigned, ad-hoc) rather than a technique: it cites no MITRE ID. */
  trait?: boolean;
  /** Context-only unless the process is in a flagged chain (or a recon burst): always, or only for low findings. */
  gated?: 'always' | 'when-low';
  /** 'image' runs on every exec'd image; 'process' once per captured process, exec'd or fork-only; 'persistence' per launch item. */
  scope: 'image' | 'process' | 'persistence';
  match?(ctx: RuleCtx): MatchResult | null;                                  // scope 'image'
  matchProcess?(p: Process, m: CaptureModel): MatchResult | null;          // scope 'process'
  matchItem?(item: PersistenceItem, m: CaptureModel): MatchResult | null;  // scope 'persistence'
}

export const SHELLS: Set<string> = new Set([
  '/bin/sh', '/bin/bash', '/bin/zsh', '/bin/dash', '/bin/ksh', '/bin/csh', '/bin/tcsh',
]);
const SHELL_NAMES = new Set([...SHELLS].map(basename));
/** Script interpreters, versioned names included (python3.11, perl5.30). */
const INTERPRETER = /^(?:python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|osascript|node|php)$/;

const MAX_EVIDENCE = 300;

function cmdline(img: Image): string {
  const s = img.args && img.args.length > 0 ? img.args.join(' ') : (img.path ?? '');
  return s.length > MAX_EVIDENCE ? `${s.slice(0, MAX_EVIDENCE)}…` : s;
}

function rest(img: Image): string[] {
  return img.args?.slice(1) ?? [];
}

const isAdhoc = (img: Image): boolean => (img.csFlags & 0x2) !== 0;
/** No signature at all; an empty signing ID counts as none. */
const isUnsigned = (img: Image): boolean => !img.isPlatform && !img.signingId;

/** The original parent's image when this process was born (the parent may exec something else later). */
function originalParentImage(m: CaptureModel, p: Process): Image | undefined {
  const parent = p.originalParent !== null ? m.processes.get(p.originalParent) : undefined;
  return parent ? imageAt(parent, p.firstSeq) : undefined;
}

function trimSlash(p: string): string {
  return p.length > 1 ? p.replace(/\/+$/, '') : p;
}

// ---------------------------------------------------------------------------------------------------------------
// Recon and security settings

/** Discovery tools, each with the technique it fits and what it finds out. */
const RECON_KINDS = {
  process: { mitre: 'T1057', what: 'Lists the running processes.' },
  network: { mitre: 'T1016', what: 'Reads the network configuration (interfaces, DNS, proxies).' },
  wifi: { mitre: 'T1016.002', what: 'Reads Wi-Fi information (the current network, or nearby ones).' },
  security: { mitre: 'T1518.001', what: 'Checks the security settings (System Integrity Protection, Gatekeeper).' },
  user: { mitre: 'T1033', what: 'Finds out which user it is running as.' },
  system: { mitre: 'T1082', what: 'Gathers information about the machine (hardware, macOS version, name).' },
} as const;
type ReconKind = keyof typeof RECON_KINDS;
export const RECON_TOOLS: Map<string, ReconKind> = new Map<string, ReconKind>([
  ['ps', 'process'], ['networksetup', 'network'], ['scutil', 'network'], ['airport', 'wifi'],
  ['csrutil', 'security'], ['spctl', 'security'], ['whoami', 'user'], ['id', 'user'],
  ['system_profiler', 'system'], ['sw_vers', 'system'], ['sysctl', 'system'], ['ioreg', 'system'], ['uname', 'system'], ['hostname', 'system'],
]);
const RECON_TAIL = ' Attackers do this to size up a machine, but so does plenty of normal software, so on its own it is only context.';

const SPCTL_DISABLE = ['--master-disable', '--global-disable', '--disable'];
/** spctl options that change Gatekeeper rather than read it. */
const SPCTL_WRITES = [...SPCTL_DISABLE, '--add', '--remove', '--enable', '--master-enable', '--global-enable', '--reset-default'];
const NETWORK_REDIRECTS: Record<string, string> = {
  '-setwebproxy': 'web proxy', '-setsecurewebproxy': 'secure web proxy', '-setautoproxyurl': 'automatic proxy URL',
  '-setsocksfirewallproxy': 'SOCKS proxy', '-setdnsservers': 'DNS servers',
};
/** csrutil subcommands that change SIP rather than report it. */
const CSRUTIL_WRITES = ['disable', 'enable', 'clear', 'add', 'remove'];
/** networksetup switches that turn a proxy on or off: `-setwebproxystate <service> on`. */
const PROXY_SWITCHES = ['-setwebproxystate', '-setsecurewebproxystate', '-setautoproxystate', '-setproxyautodiscovery', '-setsocksfirewallproxystate'];
/** networksetup options that change the configuration rather than read it. */
const NETWORKSETUP_WRITE = /^-(?:set|create|delete|remove|add|order|switch|import|detect)/i;

const MACOS15 = 'From macOS 15, spctl no longer supports changing the rule database or the global state, so there it is only an attempt.';

/** A command that weakens a macOS protection or redirects traffic, with what it tried to do. */
function settingChange(n: string, a: string[], cmd: string): MatchResult | null {
  if (n === 'spctl') {
    const off = a.find(x => SPCTL_DISABLE.includes(x));
    if (off === '--global-disable' || off === '--master-disable') {
      return { evidence: cmd, severity: 'high', mitre: ['T1562.001'], title: 'Tried to turn Gatekeeper off',
        explanation: `Ran \`spctl ${off}\`, which asks macOS to turn Gatekeeper off. On macOS 14 and earlier (as root) this disables it; from macOS 15 it only reveals the "Allow applications from Anywhere" option in Privacy & Security, which someone must still pick.` };
    }
    if (off === '--disable') {
      return { evidence: cmd, severity: 'high', mitre: ['T1562.001'], title: 'Tried to turn Gatekeeper off',
        explanation: `Ran \`spctl --disable\`, which tries to disable Gatekeeper assessment rules (all of them, or the one named). On older macOS (as root) this stops those checks. ${MACOS15}` };
    }
    if (a.includes('--add')) {
      return { evidence: cmd, severity: 'high', mitre: ['T1553.001'], title: 'Tried to add a Gatekeeper exception',
        explanation: `Ran \`spctl --add\`, which tries to add a Gatekeeper rule so the named app passes without the usual check. On older macOS (as root) this works. ${MACOS15}` };
    }
    return null;
  }
  if (n === 'csrutil' && a.includes('disable')) {
    const root = a.includes('authenticated-root');
    return { evidence: cmd, severity: 'high', mitre: ['T1562.001'],
      title: root ? 'Tried to turn off the sealed system volume check' : 'Tried to turn off System Integrity Protection',
      explanation: `Ran \`${root ? 'csrutil authenticated-root disable' : 'csrutil disable'}\`, which turns off ${root ? 'the check that the system volume is Apple\'s sealed original' : 'System Integrity Protection'}. It only works from Recovery; seeing it on a normal boot means an attempt.` };
  }
  if (n === 'security') {
    const s = securityArgs(a);
    if (s?.sub === 'add-trusted-cert') {
      const root = s.rest.includes('trustRoot') || hasShortFlag(s.rest, 'd');
      return { evidence: cmd, severity: 'high', mitre: ['T1553.004'], title: 'Certificate trusted',
        explanation: `Ran \`security add-trusted-cert\`, which marks a certificate as trusted${root ? ' (here as a trusted root, or in the admin trust settings for every user)' : ''}. A trusted root lets whoever holds its key intercept HTTPS traffic or sign things the Mac will accept.` };
    }
    if (s?.sub === 'authorizationdb' && s.rest[0] === 'write') {
      return { evidence: cmd, severity: 'med', mitre: ['T1548'], title: 'Authorization rule changed',
        explanation: 'Ran `security authorizationdb write`, which changes an authorization rule: who may do what, and whether a password is asked for. Malware loosens these rules to get admin rights without asking.' };
    }
    return null;
  }
  if (n === 'networksetup') {
    const flag = a.find(x => Object.hasOwn(NETWORK_REDIRECTS, x.toLowerCase()));
    if (flag !== undefined) {
      const values = a.slice(a.indexOf(flag) + 2);
      // `-setdnsservers <service> Empty` clears the list: nothing is redirected.
      if (flag.toLowerCase() === '-setdnsservers' && values.length > 0 && values.every(v => /^empty$/i.test(v))) return null;
      return { evidence: cmd, severity: 'med', mitre: ['T1557'], title: 'Web proxy or DNS changed',
        explanation: `Changed the ${NETWORK_REDIRECTS[flag.toLowerCase()]} with \`networksetup ${flag}\`, which redirects web or DNS traffic through a server someone chose. A common adware trick.` };
    }
    const sw = a.find(x => PROXY_SWITCHES.includes(x.toLowerCase()));
    if (sw !== undefined && a.slice(a.indexOf(sw) + 1).some(v => /^on$/i.test(v))) {
      return { evidence: cmd, severity: 'med', mitre: ['T1557'], title: 'Proxy setting turned on',
        explanation: `Turned a proxy setting on with \`networksetup ${sw} … on\`, so web traffic goes through whatever proxy is configured. A common adware trick.` };
    }
  }
  return null;
}

/** What a recon tool finds out with these arguments, or null when the arguments make it a change, not a read. */
function reconKind(img: Image): ReconKind | null {
  const n = basename(img.path);
  const kind = RECON_TOOLS.get(n);
  if (kind === undefined) return null;
  const a = rest(img);
  if (n === 'spctl' && a.some(x => SPCTL_WRITES.includes(x))) return null;
  if (n === 'networksetup' && a.some(x => NETWORKSETUP_WRITE.test(x))) return null;
  if (n === 'sysctl' && (hasShortFlag(a, 'w') || a.some(x => x.includes('=')))) return null;
  if (n === 'csrutil' && a.some(x => CSRUTIL_WRITES.includes(x))) return null;
  if (n === 'scutil') {
    if (a.includes('--set')) return null;
    if (a.includes('--get')) return 'system';
  }
  return kind;
}

// ---------------------------------------------------------------------------------------------------------------
// Keychain

/** Browser "Safe Storage" keychain entries (service "Chrome Safe Storage", account "Chrome", …): they decrypt saved logins and cookies. */
const SAFE_STORAGE = /safe storage$/i;
const BROWSER_ACCOUNT = /^(?:google )?(?:chrome|chromium|brave|microsoft edge|edge|opera|vivaldi|arc)(?: browser)?$/i;
/** Crypto wallet apps, by whole name. */
const WALLET = /\b(?:exodus|electrum|metamask|ledger live|atomic wallet|coinomi)\b/i;

function keychainFinding(args: string[]): MatchResult | null {
  const s = securityArgs(args);
  if (s === null) return null;
  const cmd = `security ${s.sub}`;
  if (s.sub === 'find-generic-password' || s.sub === 'find-internet-password') {
    const o = parseOpts(s.rest, SECURITY_FIND_SPEC);
    const prints = hasOpt(o, 'g') || hasOpt(o, 'w');
    if (!prints) {
      return { evidence: '', severity: 'low',
        explanation: `Looked up a keychain item's attributes, not its secret, with \`${cmd}\` (no -g or -w). On its own this is only context.` };
    }
    const vals = (letter: string) => optValues(o, letter, []).filter((v): v is string => !!v);
    const services = vals('s');
    const names = [...services, ...vals('a'), ...vals('l')];
    // A browser name as the account counts only when no other service is named: `-s mysvc -a Edge` is someone else's item.
    const safeService = services.some(v => SAFE_STORAGE.test(v));
    const browser = safeService || vals('l').some(v => SAFE_STORAGE.test(v))
      || ((services.length === 0 || safeService) && vals('a').some(v => BROWSER_ACCOUNT.test(v)));
    if (browser) {
      return { evidence: '', severity: 'high',
        explanation: `Printed a browser's Safe Storage key with \`${cmd}\`. That key decrypts the browser's saved passwords and cookies; stealers grab it first.` };
    }
    if (names.some(v => WALLET.test(v))) {
      return { evidence: '', severity: 'high',
        explanation: `Printed a crypto wallet's keychain entry with \`${cmd}\`. Stealers go after wallet passwords to empty the wallet.` };
    }
    return { evidence: '', severity: 'med',
      explanation: `Ran \`${cmd}\` with -g or -w, which prints a saved password. Tools such as gh and git credential helpers do this too; check which item it asked for.` };
  }
  if (s.sub === 'dump-keychain') {
    return hasShortFlag(s.rest, 'd')
      ? { evidence: '', severity: 'high', explanation: 'Ran `security dump-keychain -d`, which prints every item in a keychain together with its secret.' }
      : { evidence: '', severity: 'low', explanation: 'Listed the items in a keychain with `security dump-keychain`: names and attributes only (with -d it would include the secrets). On its own this is only context.' };
  }
  if (s.sub === 'unlock-keychain') {
    return { evidence: '', severity: 'low', explanation: 'Unlocked a keychain with `security unlock-keychain`, so its items can be read. On its own this is only context.' };
  }
  if (s.sub === 'export') {
    return { evidence: '', severity: 'low', explanation: 'Exported keys or certificates out of a keychain with `security export`. On its own this is only context.' };
  }
  return null;
}

// ---------------------------------------------------------------------------------------------------------------
// Odd locations (program and script)

/** "Ran a program from a temporary folder, …": the explanation of an odd-location-exec finding, from what triggered it. */
function oddLocationExplanation(hits: { what: 'program' | 'script'; where: OddLocation }[]): string {
  const parts = hits.map(h => `${h.what} from ${LOCATION_WORDS[h.where.kind].long}`);
  const weakOnly = hits.every(h => h.where.strength === 'weak');
  return `Ran a ${parts.join(', and a ')}, not from /Applications or a system folder.`
    + (weakOnly ? ' On its own this is a weak signal.' : ' Malware is commonly run from places like this.');
}

// ---------------------------------------------------------------------------------------------------------------
// Persistence

const LAUNCH_DIR = /^(?:\/Users\/[^/]+\/Library\/LaunchAgents|\/Library\/Launch(?:Agents|Daemons))\/[^/]+\.plist$/i;
const DAEMON_DIR = /^\/Library\/LaunchDaemons\//i;
const ALL_USERS_AGENT_DIR = /^\/Library\/LaunchAgents\//i;
const USER_AGENT_DIR = /^\/Users\/[^/]+\/Library\/LaunchAgents\//i;

type LaunchKind = 'agent' | 'daemon' | 'login' | 'app' | 'user' | null;
/** The kind of launch item, from the btm item type (0 user item, 1 app, 2 login item, 3 agent, 4 daemon) or its plist directory. */
function launchKind(itemType: number | null, plistPath: string | null): LaunchKind {
  const byType: LaunchKind[] = ['user', 'app', 'login', 'agent', 'daemon'];
  if (itemType !== null && byType[itemType] !== undefined) return byType[itemType]!;
  if (plistPath === null) return null;
  const n = normPath(plistPath);
  return DAEMON_DIR.test(n) ? 'daemon' : ALL_USERS_AGENT_DIR.test(n) || USER_AGENT_DIR.test(n) ? 'agent' : null;
}
const LAUNCH_MITRE: Record<NonNullable<LaunchKind>, string> = {
  agent: 'T1543.001', daemon: 'T1543.004', login: 'T1547.015', app: 'T1547.015', user: 'T1547.015',
};
const launchMitre = (k: LaunchKind): string[] => (k === null ? ['T1543.001', 'T1543.004'] : [LAUNCH_MITRE[k]]);
const LAUNCH_TITLE: Record<NonNullable<LaunchKind>, string> = {
  agent: 'Launch agent registered', daemon: 'Launch daemon registered', login: 'Login item registered',
  app: 'App registered to open at login', user: 'Login item registered (user item)',
};
/** When launchd actually starts the program: whatever the plist asks for. */
const TRIGGERS = 'and starts the program it names when the plist says: at load (RunAtLoad), to keep it running (KeepAlive), on a schedule (StartInterval, StartCalendarInterval) or when files change (WatchPaths), for example';
/** Where launchd loads an agent or daemon plist from this place: "…loads it <when> …". */
function launchdStarts(kind: 'agent' | 'daemon', plistPath: string | null): { scope: string; when: string } {
  if (kind === 'daemon') return { scope: '', when: 'at boot, usually to run as root,' };
  const n = plistPath !== null ? normPath(plistPath) : '';
  if (ALL_USERS_AGENT_DIR.test(n)) return { scope: ' for every user', when: 'whenever anyone logs in' };
  if (USER_AGENT_DIR.test(n)) return { scope: ' for this user', when: 'each time this user logs in' };
  return { scope: '', when: 'at login' };
}
function launchExplanation(kind: NonNullable<LaunchKind>, plistPath: string | null): string {
  if (kind === 'agent' || kind === 'daemon') {
    const { scope, when } = launchdStarts(kind, plistPath);
    return `Registered a launch ${kind}${scope}: launchd loads it ${when} ${TRIGGERS}.`;
  }
  return {
    login: 'Registered a login item: macOS opens it each time this user logs in.',
    app: 'Registered an app to open each time this user logs in.',
    user: 'Added a login item to the user\'s list: macOS opens it each time this user logs in.',
  }[kind];
}

/** Where a launch item's program sits, worded for persistence: why that place makes it worse. */
const PERSIST_WORDS: Record<LocationKind, string> = {
  translocated: 'inside a translocated app (a quarantined download macOS ran from a random read-only copy)',
  temp: 'in /tmp or /var/tmp, which every user and process can write to',
  shared: 'in /Users/Shared, which every user can write to',
  downloads: 'in the Downloads folder, which the user can write to',
  volume: 'on a mounted disk image or external volume, which can be swapped or disappear',
  hidden: 'in a hidden folder in the home folder, which the user can write to',
  'home-dot': 'in a dot-folder in the home folder, which the user can write to',
  tooling: 'inside a project build or tooling folder in the home folder, which the user can write to',
  'go-build': 'in a Go build folder in the per-user temporary area, which the user (or anything running as them) can write to',
};

const APP_BUNDLE_EXE = /\.app\/Contents\/MacOS\/[^/]+$/i;
const HOME_CACHES = /^\/Users\/[^/]+\/Library\/Caches\//i;

/**
 * What a launch item runs, as an absolute path. The event's executable path is optional, and its item URL may be the app
 * itself (a login item) or relative to the app URL; so: an absolute executable, else the executable joined to the app,
 * else the app bundle. null when nothing can be placed.
 */
function launchTarget(item: PersistenceItem): { path: string; isApp: boolean } | null {
  const exe = item.executablePath !== null && item.executablePath !== '' ? item.executablePath : null;
  const app = item.appPath !== null && item.appPath.startsWith('/') ? trimSlash(item.appPath) : null;
  if (exe !== null && exe.startsWith('/')) return { path: exe, isApp: false };
  if (exe !== null) return app !== null ? { path: resolvePath(exe, app), isApp: false } : null;
  return app !== null ? { path: app, isApp: true } : null;
}

/**
 * How bad a launch item is, from what it runs. High when it runs a shell or interpreter, sits anywhere a user process
 * can write (temporary folders, /Users/Shared, Downloads, ~/Library/Caches, hidden folders, or a loose program anywhere
 * in a home folder), or ran unsigned or ad-hoc signed in this capture. An app bundle in a home folder that was not seen
 * unsigned (a per-user updater such as GoogleUpdater) stays med, as does everything else.
 */
function persistenceSeverity(target: { path: string; isApp: boolean } | null, m: CaptureModel): { severity: Severity; reason: string } {
  if (target === null) return { severity: 'med', reason: 'the event names no program it can place' };
  const what = target.isApp ? 'the app' : 'the program';
  const n = basename(target.path);
  if (!target.isApp && SHELL_NAMES.has(n)) return { severity: 'high', reason: `it runs a shell (${n})` };
  if (!target.isApp && INTERPRETER.test(n)) return { severity: 'high', reason: `it runs a script interpreter (${n})` };
  const p = normPath(target.path);
  const where = oddLocation(target.isApp ? `${p}/` : p);
  if (where !== null) {
    // /tmp and /var/tmp are world-writable; /var/folders/…/T belongs to one user.
    const words = where.kind === 'temp' && /^\/var\/folders\//i.test(p)
      ? 'in the per-user temporary folder (/var/folders/…), which the user (or anything running as them) can write to'
      : PERSIST_WORDS[where.kind];
    return { severity: 'high', reason: `${what} is ${words}` };
  }
  if (HOME_CACHES.test(p)) return { severity: 'high', reason: `${what} is in ~/Library/Caches, which the user can write to` };
  const key = p.toLowerCase();
  const matches = (i: Image) => {
    if (i.path === null) return false;
    const ip = normPath(i.path).toLowerCase();
    return target.isApp ? ip.startsWith(`${key}/`) : ip === key;
  };
  const seen = [...m.processes.values()].flatMap(q => q.images).filter(matches);
  const bad = seen.find(i => isUnsigned(i) || (!i.isPlatform && isAdhoc(i)));
  if (bad) return { severity: 'high', reason: `${what} ran ${isUnsigned(bad) ? 'unsigned' : 'ad-hoc signed'} in this capture` };
  if (HOME.test(p)) {
    if (!target.isApp && !APP_BUNDLE_EXE.test(p)) return { severity: 'high', reason: 'a loose program in a home folder, which the user (or anything running as them) can overwrite' };
    const team = seen.find(i => i.teamId !== null)?.teamId;
    return { severity: 'med', reason: team ? `an app bundle in a home folder, signed by team ${team}`
      : seen.length > 0 ? 'an app bundle in a home folder; it ran signed without a team ID'
      : 'an app bundle in a home folder; its signature was not seen in this capture' };
  }
  return { severity: 'med', reason: `${what} is in a system, /Applications or package-manager location` };
}

/** Apple's own system daemons (smd, backgroundtaskmanagementd) instigate most launch item registrations. */
const SYSTEM_DIRS = /^\/(?:System|usr\/libexec|usr\/sbin)\//;

/**
 * The process a persistence finding attaches to, and through which link: the app that registered the item, else the
 * instigator (the XPC caller), else the plist's creator; null means a standalone row. An app or instigator counts
 * only when it is a captured process with a known path and is not an Apple platform binary under /System,
 * /usr/libexec or /usr/sbin: pinning a finding on smd would point at the messenger, and a pathless ghost cannot be
 * told apart from it.
 */
export function persistenceOwner(m: CaptureModel, item: PersistenceItem): { id: ProcId; via: 'app' | 'instigator' | 'creator' } | null {
  for (const via of ['app', 'instigator'] as const) {
    const id = item[via];
    const p = id !== null ? m.processes.get(id) : undefined;
    const img = p && !p.ghost ? imageAt(p, item.seq) : undefined;
    if (!img || img.path === null) continue;
    if (img.isPlatform && SYSTEM_DIRS.test(img.path)) continue;
    return { id: p!.id, via };
  }
  return item.creator !== null && m.processes.has(item.creator) ? { id: item.creator, via: 'creator' } : null;
}

/** "Evil (pid 900)", or "a standalone launch item" when the registration attaches to no process. */
function ownerName(m: CaptureModel, owner: { id: ProcId } | null, seq: number): string {
  const p = owner ? m.processes.get(owner.id) : undefined;
  if (!p) return 'a standalone launch item row';
  const img = imageAt(p, seq);
  return `${basename(img?.path ?? null) || 'pid'} (pid ${p.pid})`;
}

const PERSISTENCE_EXPLANATION = 'Something registered itself to run automatically at login or boot.';
const PLIST_GENERIC = `Wrote a launch agent or daemon plist: launchd loads it at login or boot ${TRIGGERS}.`;

function plistBase(plists: string[]): string {
  const kinds = new Set(plists.map(h => launchKind(null, h)));
  if (kinds.size !== 1) return PLIST_GENERIC;
  const kind = [...kinds][0];
  if (kind !== 'agent' && kind !== 'daemon') return PLIST_GENERIC;
  const scopes = new Set(plists.map(h => launchdStarts(kind, h).scope));
  const { scope, when } = scopes.size === 1 ? launchdStarts(kind, plists[0]!) : launchdStarts(kind, null);
  return `Wrote a launch ${kind} plist${scope}: launchd loads it ${when} ${TRIGGERS}.`;
}

// ---------------------------------------------------------------------------------------------------------------
// Pipes

/** The language an exec'd image reads from a piped stdin, or null. */
function pipeLang(img: Image): PipeLang | null {
  if (img.stdinIsPipe !== true || img.script !== null || !img.args) return null;
  const lang = PIPE_LANGS.find(([re]) => re.test(basename(img.path)))?.[1];
  return lang && readsStdin(lang, img.args) ? lang : null;
}

/** openssl digest commands, where -d means debug output rather than decode. */
const OPENSSL_DIGESTS = /^(?:dgst|md4|md5|sha1|sha224|sha256|sha384|sha512|rmd160|ripemd160)$/;

export const RULES: Rule[] = [
  {
    id: 'fake-prompt', title: 'Dialog box from osascript', severity: 'high',
    explanation: 'Shows a dialog box from an osascript script (AppleScript `display dialog`, or JavaScript for Automation `displayDialog`). Info-stealers use this to fake a system password prompt.',
    mitre: ['T1056.002'], scope: 'image',
    match: ({ img }) => {
      if (basename(img.path) !== 'osascript' || !img.args) return null;
      const text = img.args.join(' ');
      if (!/display dialog|displayDialog|hidden answer|hiddenAnswer/i.test(text)) return null;
      return {
        evidence: cmdline(img),
        explanation: /hidden answer|hiddenAnswer/i.test(text)
          ? 'Shows a dialog box that asks for typed text and hides it as dots, the way a password prompt does. Info-stealers use this to fake a system password prompt.'
          : 'Shows a dialog box from an osascript script (AppleScript `display dialog`, or JavaScript for Automation `displayDialog`). Info-stealers use this to fake a system password prompt, or a fake error message once they are done.',
      };
    },
  },
  {
    id: 'osascript-script', title: 'osascript script from a file in an odd place, or from a pipe', severity: 'med',
    explanation: 'osascript ran a script (AppleScript, or JavaScript for Automation) from a file in a temporary, download, shared or hidden folder, a mounted volume or a translocated app, or piped into it with no file on disk.',
    mitre: ['T1059.002', 'T1059.007'], scope: 'image',
    match: ({ img }) => {
      if (basename(img.path) !== 'osascript' || !img.args) return null;
      const o = osascriptArgs(rest(img));
      const mitre = o.js ? ['T1059.007'] : ['T1059.002'];
      const what = o.js ? 'a JavaScript for Automation script' : 'an AppleScript';
      if (o.source === 'stdin') {
        return img.stdinIsPipe === true
          ? { evidence: `${cmdline(img)} with stdin from a pipe`, mitre,
            explanation: `osascript ran ${what} piped into it, so there is no script file on disk to inspect.` }
          : null;
      }
      if (o.source !== 'file') return null;
      const file = resolvePath(o.file!, img.cwd);
      const where = oddLocation(file);
      if (where === null || where.strength !== 'strong') return null;
      return {
        evidence: `${cmdline(img)} (script ${file}, ${LOCATION_WORDS[where.kind].short})`, mitre,
        explanation: `osascript ran ${what} file from ${LOCATION_WORDS[where.kind].long}. Malware drops scripts in places like this and runs them with osascript.`,
      };
    },
  },
  {
    id: 'keychain-access', title: 'Keychain read with security', severity: 'high', gated: 'when-low',
    explanation: 'Ran `security` against the macOS keychain. High when it prints a browser Safe Storage key or a crypto wallet entry (find-generic-password / find-internet-password with -g or -w), or dumps every secret (dump-keychain -d); med when it prints any other saved password; low (context only) for attribute lookups, unlock-keychain, export and dump-keychain without -d.',
    mitre: ['T1555.001'], scope: 'image',
    match: ({ img }) => {
      if (basename(img.path) !== 'security') return null;
      const res = keychainFinding(rest(img));
      return res ? { ...res, evidence: cmdline(img) } : null;
    },
  },
  {
    id: 'security-setting-change', title: 'Security setting changed', severity: 'high',
    explanation: 'Tried to weaken a macOS protection: turn Gatekeeper off or add an exception (spctl --master-disable, --global-disable, --disable, --add), turn System Integrity Protection off (csrutil disable, csrutil authenticated-root disable), trust a root certificate (security add-trusted-cert), or change an authorization rule (security authorizationdb write); or pointed web or DNS traffic elsewhere (networksetup -setwebproxy, -setsecurewebproxy, -setautoproxyurl, -setsocksfirewallproxy, -setdnsservers, or switching a proxy on).',
    mitre: ['T1562.001', 'T1553.001', 'T1553.004', 'T1548', 'T1557'], scope: 'image',
    match: ({ img }) => settingChange(basename(img.path), rest(img), cmdline(img)),
  },
  {
    id: 'dscl-authonly', title: 'Password check with dscl', severity: 'high',
    explanation: 'Checks whether a password is correct for a local account. Stealers run it to verify a password the attacker just phished with a fake prompt.',
    mitre: ['T1056.002'], scope: 'image',
    match: ({ img }) =>
      basename(img.path) === 'dscl' && rest(img).some(a => a === '-authonly' || a === 'authonly') ? { evidence: cmdline(img) } : null,
  },
  {
    id: 'persistence-item', title: 'Launch item registered', severity: 'high',
    explanation: PERSISTENCE_EXPLANATION,
    mitre: ['T1543.001', 'T1543.004', 'T1547.015'], scope: 'persistence',
    matchItem: (item, m) => {
      if (item.kind !== 'add') return null;
      const app = item.appPath !== null ? trimSlash(item.appPath) : null;
      const target = launchTarget(item);
      // The item URL is a plist only for launch agents and daemons; for a login item it is usually the app.
      const itemPath = item.plistPath;
      const evidence = [
        itemPath !== null ? `${/\.plist$/i.test(itemPath) ? 'plist' : 'item'} ${itemPath}` : null,
        target !== null && !target.isApp ? `runs ${target.path}` : item.executablePath ? `runs ${item.executablePath}` : null,
        app !== null ? `app ${app}` : null,
      ].filter(Boolean).join('; ') || 'launch item with no paths';
      const { severity, reason } = persistenceSeverity(target, m);
      const kind = launchKind(item.itemType, item.plistPath);
      return {
        evidence: `${evidence}; ${severity}: ${reason}`, severity, mitre: launchMitre(kind),
        ...(kind !== null ? { title: LAUNCH_TITLE[kind], explanation: launchExplanation(kind, item.plistPath) } : {}),
      };
    },
  },
  {
    id: 'persistence-plist', title: 'Launch agent/daemon plist written', severity: 'high',
    explanation: `${PLIST_GENERIC} Says whether a registration event in the capture accounts for it, and which process that registration is attributed to.`,
    mitre: ['T1543.001', 'T1543.004'], scope: 'process',
    matchProcess: (p, m) => {
      const unregistered: string[] = [];
      const elsewhere = new Map<string, string>();     // plist -> who its registration is attributed to
      const seen = new Set<string>();
      for (const op of p.fileOps) {
        // A temp file renamed over the plist counts through the rename's destination.
        const target = op.kind === 'create' ? op.path : op.kind === 'rename' ? op.toPath : undefined;
        if (target === undefined) continue;
        const n = normPath(target);
        const key = n.toLowerCase();
        if (!LAUNCH_DIR.test(n) || seen.has(key)) continue;
        seen.add(key);
        const items = m.persistence.filter(it => it.kind === 'add' && it.plistPath !== null && normPath(it.plistPath).toLowerCase() === key);
        if (items.length === 0) { unregistered.push(target); continue; }
        const owners = items.map(it => ({ it, owner: persistenceOwner(m, it) }));
        if (owners.some(o => o.owner?.id === p.id)) continue;   // the registration's own finding is on this process
        elsewhere.set(target, [...new Set(owners.map(o => ownerName(m, o.owner, o.it.seq)))].join(', '));
      }
      const hits = [...unregistered, ...elsewhere.keys()];
      if (hits.length === 0) return null;
      const kinds = new Set(hits.map(h => launchKind(null, normPath(h))));
      const only = kinds.size === 1 ? [...kinds][0]! : null;
      const names = [...new Set(elsewhere.values())].join(', ');
      const suffix = elsewhere.size === 0 ? ' No registration event in the capture accounts for it.'
        : unregistered.length === 0 ? ` Its registration in the capture is attributed to ${names}, so that finding is on that row.`
        : ` Some have no registration event in the capture; the registration of the others is attributed to ${names}.`;
      return {
        evidence: `wrote ${hits.map(h => (elsewhere.has(h) ? `${h} (registration attributed to ${elsewhere.get(h)})` : h)).join(', ')}`,
        mitre: [...new Set([...kinds].flatMap(launchMitre))].sort(),
        explanation: `${plistBase(hits)}${suffix}`,
        ...(only === 'agent' ? { title: 'Launch agent plist written' } : only === 'daemon' ? { title: 'Launch daemon plist written' } : {}),
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
      // openssl options are single-dash words, never clusters: only `-d` itself means decode/decrypt (`-md`, `-days` do not).
      // In the digest commands (dgst, sha256, md5…) -d means debug output.
      if (n === 'openssl' && a.includes('-d') && !OPENSSL_DIGESTS.test(a[0] ?? '')) return { evidence: cmdline(img) };
      if (n === 'base64' && (hasShortFlag(a, 'd') || hasShortFlag(a, 'D') || a.includes('--decode'))) return { evidence: cmdline(img) };
      return null;
    },
  },
  {
    id: 'shell-from-pipe', title: 'Shell or interpreter reading commands from a pipe', severity: 'med',
    explanation: "A shell, or python, perl or ruby, ran commands piped into it (the `curl … | bash` pattern), so there's no script file on disk to inspect. Version and help probes before the script starts do not count: --version and --help, and for python, perl and ruby also -V, -VV, -h (and perl/ruby -v).",
    mitre: ['T1059.004', 'T1059.006', 'T1059'], scope: 'image',
    match: ({ p, img, imgIndex }) => {
      const lang = pipeLang(img);
      if (lang === null) return null;
      // Once per process: /bin/sh re-execs /bin/bash and perl re-execs perl5.30 with the same arguments.
      if (p.images.slice(0, imgIndex).some(i => !i.inherited && i.path !== null && pipeLang(i) !== null)) return null;
      const n = basename(img.path);
      return {
        evidence: `${cmdline(img)} with stdin from a pipe`, mitre: [lang.mitre],
        explanation: SHELL_NAMES.has(n)
          ? "A shell ran commands piped into it (the `curl … | bash` pattern), so there's no script file on disk to inspect."
          : `${n} ran a script piped into it (the \`curl … | ${n}\` pattern), so there's no script file on disk to inspect.`,
      };
    },
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
      if (/\/(?:Terminal|iTerm2?|Visual Studio Code|Code|Cursor|Xcode|Claude|Warp|Ghostty|Alacritty|kitty|WezTerm)\.app\//.test(parent)
        || parent.includes('Code Helper')) return null;
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
      // `-`, /dev/null, /dev/stdout, /dev/stderr and /dev/fd/N are not files on disk.
      const isFile = (t: string | undefined): boolean =>
        t !== undefined && t !== '-' && !/^\/dev\/(?:null|stdout|stderr|fd\/\d+)$/.test(t);
      if (n === 'wget') {
        const o = parseOpts(a, WGET_SPEC);
        // --spider only checks that the URL exists; --version and --help print and exit.
        if (hasOpt(o, 'V', ['--spider', '--version', '--help']) || hasOpt(o, 'h')) return null;
        if (!o.positionals.some(looksLikeUrl) && !hasOpt(o, 'i', ['--input-file'])) return null;
        // wget saves to a file named after the URL unless -O / --output-document says otherwise; its -o is the log file.
        const targets = optValues(o, 'O', ['--output-document']);
        if (targets.length === 0) return { evidence: `${cmdline(img)}; wget saves to a file named after the URL by default` };
        if (targets.some(isFile)) return { evidence: cmdline(img) };
      } else {
        // curl writes to stdout unless -o / --output names a file (not /dev/null or -) or -O / --remote-name names it after the URL.
        const o = parseOpts(a, CURL_SPEC);
        if (hasOpt(o, 'O', ['--remote-name', '--remote-name-all']) || optValues(o, 'o', ['--output']).some(isFile)) return { evidence: cmdline(img) };
      }
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
      const tool = n === 'ditto' && hasShortFlag(a, 'c') ? 'ditto' : n === 'zip' ? 'zip' : n === 'tar' && tarCreates(a) ? 'tar' : null;
      if (tool === null) return null;
      const where = stagingPlace(tool, a, img.cwd);
      if (where === null) return { evidence: cmdline(img), severity: 'med' };
      return {
        evidence: `${cmdline(img)} (staged in ${LOCATION_WORDS[where.kind].short})`, severity: 'high',
        explanation: `Packed files into an archive, in or from ${LOCATION_WORDS[where.kind].long}. Stealers stage collected data this way before sending it out.`,
      };
    },
  },
  {
    id: 'odd-location-exec', title: 'Ran from an unusual location', severity: 'med', gated: 'when-low',
    explanation: 'Ran a program or script from a temporary folder, Downloads, /Users/Shared, a mounted volume, a translocated app or a hidden folder, not from /Applications or a system folder.',
    mitre: ['T1204.002'], scope: 'image',
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
    id: 'unsigned', title: 'Unsigned binary', severity: 'med', trait: true,
    explanation: 'Not signed at all. Unsigned binaries are a common trait of malware; not a technique by itself.',
    mitre: [], scope: 'image',
    match: ({ img }) => isUnsigned(img) ? { evidence: `${img.path} has no code signature` } : null,
  },
  {
    id: 'adhoc', title: 'Ad-hoc signed binary', severity: 'low', trait: true, gated: 'always',
    explanation: 'Ad-hoc signed: it carries a signature but no developer identity. Common for Homebrew and locally built tools, and for malware; a trait, not a technique by itself.',
    mitre: [], scope: 'image',
    match: ({ img }) =>
      !img.isPlatform && !!img.signingId && isAdhoc(img)
        ? { evidence: `${img.path} is ad-hoc signed (${img.signingId}), with no developer identity` } : null,
  },
  {
    id: 'orphaned', title: 'Detached from its parent', severity: 'low',
    explanation: 'Detached from the process that started it, so it keeps running after its parent exits and no longer shows up under it. Malware double-forks like this to break the link to whatever launched it.',
    mitre: ['T1036.009'], scope: 'process',
    matchProcess: (p, m) => {
      if (p.ppid !== 1 || p.originalPpid === null || p.originalPpid === 1) return null;
      const parent = originalParentImage(m, p)?.path ?? null;
      if (basename(parent) === 'xpcproxy') return null;
      return { evidence: `parent pid ${p.originalPpid}${parent ? ` (${basename(parent)})` : ''} gone; now under launchd` };
    },
  },
  {
    id: 'recon', title: 'System or user discovery', severity: 'low', gated: 'always',
    explanation: `Runs a tool that reads the machine, its user, network, Wi-Fi, processes or security settings (ps, networksetup, scutil, airport, csrutil, spctl, whoami, id, system_profiler, sw_vers, sysctl, ioreg, uname, hostname). Forms that change a setting are not recon.${RECON_TAIL}`,
    mitre: ['T1057', 'T1016', 'T1016.002', 'T1518.001', 'T1033', 'T1082'], scope: 'image',
    match: ({ img }) => {
      const kind = reconKind(img);
      if (kind === null) return null;
      const { mitre, what } = RECON_KINDS[kind];
      return { evidence: cmdline(img), mitre: [mitre], explanation: `${what}${RECON_TAIL}` };
    },
  },
];
