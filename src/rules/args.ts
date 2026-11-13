import { normPath } from '../model/util';
import { inBuildDir, oddLocation, resolvePath, strongPlace, type OddLocation } from './locations';

/** `-x`, or a short-option cluster such as `-cr` containing x; `--long` options never match. */
export function hasShortFlag(args: string[], letter: string): boolean {
  return args.some(a => a === `-${letter}` || (/^-[A-Za-z]+$/.test(a) && a.includes(letter)));
}

/** Which options take a value: short letters (the value is the rest of the cluster, or the next argument) and long names. */
export interface OptSpec { shortValues: string; longValues: string[] }
export interface ParsedOpts {
  shorts: { opt: string; value?: string }[];
  longs: { name: string; value?: string }[];
  positionals: string[];
}

/**
 * getopt-style parse of the arguments after argv[0]. A short cluster such as `-sLo f` is s, L, then o with value f;
 * `-XPOST` is X with value POST. `--name=value`, or `--name value` when the spec says it takes one. `--` ends options.
 */
export function parseOpts(args: string[], spec: OptSpec): ParsedOpts {
  const out: ParsedOpts = { shorts: [], longs: [], positionals: [] };
  for (let i = 0; i < args.length; i++) {
    const x = args[i]!;
    if (x === '--') { out.positionals.push(...args.slice(i + 1)); break; }
    if (x.startsWith('--')) {
      const eq = x.indexOf('=');
      const name = eq > 0 ? x.slice(0, eq) : x;
      out.longs.push({ name, value: eq > 0 ? x.slice(eq + 1) : spec.longValues.includes(name) ? args[++i] : undefined });
    } else if (x.startsWith('-') && x.length > 1) {
      for (let k = 1; k < x.length; k++) {
        const ch = x[k]!;
        if (spec.shortValues.includes(ch)) {
          const attached = x.slice(k + 1);
          out.shorts.push({ opt: ch, value: attached !== '' ? attached : args[++i] });
          break;
        }
        out.shorts.push({ opt: ch });
      }
    } else out.positionals.push(x);
  }
  return out;
}

/** Values given to a short letter or any of the long names. */
export function optValues(p: ParsedOpts, letter: string | null, longs: string[]): (string | undefined)[] {
  return [
    ...p.shorts.filter(s => s.opt === letter).map(s => s.value),
    ...p.longs.filter(l => longs.includes(l.name)).map(l => l.value),
  ];
}
export const hasOpt = (p: ParsedOpts, letter: string | null, longs: string[] = []): boolean =>
  p.shorts.some(s => s.opt === letter) || p.longs.some(l => longs.includes(l.name));

export const CURL_SPEC: OptSpec = {
  shortValues: 'AbcCdDeEFHKmoPQrtTuUwxXyYz',
  longValues: ['--output', '--header', '--data', '--data-raw', '--data-binary', '--data-urlencode', '--request', '--user-agent',
    '--user', '--referer', '--cookie', '--cookie-jar', '--form', '--max-time', '--connect-timeout', '--proxy', '--output-dir',
    '--config', '--dump-header', '--write-out', '--upload-file', '--cert', '--retry', '--range', '--resolve', '--url'],
};
/** wget; `-n` takes a letter (`-nc`, `-nv`, `-nd`). */
export const WGET_SPEC: OptSpec = {
  shortValues: 'aABDeiIlnoOPQRtTUwX',
  longValues: ['--output-document', '--output-file', '--append-output', '--input-file', '--user-agent', '--header',
    '--post-data', '--post-file', '--directory-prefix', '--tries', '--timeout', '--wait', '--user', '--password', '--referer',
    '--load-cookies', '--save-cookies', '--execute', '--base', '--level', '--accept', '--reject', '--domains', '--quota',
    '--limit-rate', '--method', '--body-data', '--body-file', '--ca-certificate', '--ca-directory', '--certificate',
    '--private-key'],
};
/** A URL: `scheme://…`; `host.tld` with an optional port and path; or a single-label host with a port or path (`localhost:8080`, `intranet/x`). */
export const looksLikeUrl = (s: string): boolean =>
  /^[a-z][a-z0-9+.-]*:\/\//i.test(s)
  || /^[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?(?:\/|$)/i.test(s)
  || /^[a-z0-9-]+(?::\d+(?:\/|$)|\/)/i.test(s);

/** Interpreters that read a script from stdin when given none, and how their arguments say otherwise. */
export interface PipeLang {
  mitre: string;
  inline: string;          // short letters whose value is the code (or a module) itself
  stdinFlag: string;       // short letter meaning "read commands from stdin"
  valueOpts: string[];     // short options taking the next argument as a value
  attached: string;        // short letters that carry their value in the same argument
  probes: string[];        // arguments that only print a version or help and exit (only before the program starts)
  probeLetters: string;    // the same, as letters inside a short cluster (`python3 -uV`, `perl -wv`)
  probesYield: string[];   // probes that still run a script named after them: `ruby -v -` prints the version, then reads stdin
  probeLettersYield: string; // the same, as cluster letters: `ruby -wv -` also reads stdin
  longs: string[];         // long options known to take no value; any other long option means "can't tell"
  longValues: string[];    // long options taking the next argument as a value
}
/** For shells only the long forms are probes: `bash -h` is `set -h` and `zsh -V` / `dash -V` set options, and both still run piped commands. */
const SHELL_PROBES = ['--version', '--help'];
const SHELL_LONGS = ['--login', '--norc', '--noprofile', '--posix', '--noediting', '--restricted', '--verbose', '--no-rcs', '--no-globalrcs', '--interactive'];
const SHELL = { mitre: 'T1059.004', inline: 'c', stdinFlag: 's', attached: '', probes: SHELL_PROBES, probeLetters: '', probesYield: [], probeLettersYield: '',
  longs: SHELL_LONGS, longValues: ['--rcfile', '--init-file'] };
export const PIPE_LANGS: [RegExp, PipeLang][] = [
  // -c: the command is an argument; -s: read commands from stdin (the rest are positional parameters); -o/+o take an
  // option name, and in bash (macOS sh is bash) so do -O/+O. In zsh -O is a plain option letter.
  [/^(?:sh|bash)$/, { ...SHELL, valueOpts: ['-o', '+o', '-O', '+O'] }],
  [/^(?:zsh|dash|ksh|csh|tcsh)$/, { ...SHELL, valueOpts: ['-o', '+o'] }],
  // -c code, -m module; -W and -X take a value; -V, -VV, -h print and exit.
  [/^python[0-9.]*$/, { mitre: 'T1059.006', inline: 'cm', stdinFlag: '', valueOpts: ['-W', '-X'], attached: 'WX',
    probes: ['--version', '--help', '-V', '-VV', '-h'], probeLetters: 'Vh', probesYield: [], probeLettersYield: '', longs: [], longValues: [] }],
  // -e/-E code (also in clusters such as -ne, -0777pe); -I, -M, -m, -x, -d, -i (in-place extension) carry their
  // value attached; -v, -V, -h print and exit (even with a `-` after them).
  [/^perl[0-9.]*$/, { mitre: 'T1059', inline: 'eE', stdinFlag: '', valueOpts: [], attached: 'IMmxdi',
    probes: ['--version', '--help', '-V', '-h', '-v'], probeLetters: 'Vvh', probesYield: [], probeLettersYield: '', longs: [], longValues: [] }],
  // -e code; -I, -r, -C, -E take a value; -h prints help and exits. -v (alone or in a cluster such as -wv) prints the
  // version and exits when no script is named, but a `-` after it still reads the piped script (`ruby -wv -`).
  // -V is not a ruby option: ruby rejects it and exits.
  [/^ruby[0-9.]*$/, { mitre: 'T1059', inline: 'e', stdinFlag: '', valueOpts: ['-I', '-r', '-C', '-E'], attached: 'IrCE',
    probes: ['--version', '--help', '-h', '-v', '-V', '-VV'], probeLetters: 'hvV', probesYield: ['-v'], probeLettersYield: 'v', longs: [], longValues: [] }],
];

/**
 * True when an interpreter with these arguments (argv[0] first) reads its program from stdin: no inline code, no
 * script file argument (or `-`), not a version/help probe, and no long option we can't account for. Options are read
 * only up to the first `-`, `--`, `-s` or script argument: what follows belongs to the script (`sh -s -- --version 1.2`).
 */
export function readsStdin(lang: PipeLang, a: string[]): boolean {
  const valueLetters = lang.attached + lang.valueOpts.map(o => o.slice(1)).join('');
  let probe = false;                                                   // a probe that still runs a script named after it
  for (let i = 1; i < a.length; i++) {
    const x = a[i]!;
    if (lang.probes.includes(x)) {
      if (!lang.probesYield.includes(x)) return false;
      probe = true;
      continue;
    }
    if (x === '-') return true;
    if (x === '--') return a[i + 1] === undefined && !probe;
    if (x.startsWith('--')) {
      if (lang.longValues.includes(x)) { i++; continue; }
      if (lang.longs.includes(x)) continue;
      return false;
    }
    if (x.length > 1 && (x.startsWith('-') || (lang.stdinFlag !== '' && x.startsWith('+')))) {
      if (lang.valueOpts.includes(x)) { i++; continue; }
      if (lang.attached.includes(x[1]!)) continue;
      const letters = x.slice(1);
      if ([...letters].some(ch => lang.inline.includes(ch))) return false;
      // A probe letter in a cluster (`-uV`) counts when nothing in the cluster takes a value. If every probe letter in
      // it yields (ruby's v), it waits like `-v`: a later `-` still reads stdin.
      const probeHits = [...letters].filter(ch => lang.probeLetters.includes(ch));
      if (probeHits.length > 0 && ![...letters].some(ch => valueLetters.includes(ch))) {
        if (!probeHits.every(ch => lang.probeLettersYield.includes(ch))) return false;
        probe = true;
        continue;
      }
      if (lang.stdinFlag !== '' && letters.includes(lang.stdinFlag)) return true;
      continue;
    }
    return false;                                                       // a script file
  }
  return !probe;
}

/**
 * osascript's own options, per `osascript [-l lang] [-i] [-s flags] [-e statement | programfile | -] [args]`: where the
 * program comes from (inline -e, a file, or stdin) and whether it is JavaScript for Automation. Arguments after the
 * program file belong to the script and are not read.
 */
export function osascriptArgs(args: string[]): { source: 'inline' | 'stdin' | 'file'; file?: string; js: boolean } {
  let js = false;
  let inline = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === '-') return { source: 'stdin', js };
    if (a === '--') {
      const f = args[i + 1];
      return inline ? { source: 'inline', js } : f !== undefined && f !== '-' ? { source: 'file', file: f, js } : { source: 'stdin', js };
    }
    if (a.startsWith('-') && a.length > 1) {
      const flag = a[1]!;
      if (flag === 'e' || flag === 'l' || flag === 's') {
        const value = a.length > 2 ? a.slice(2) : args[++i];
        if (flag === 'e') inline = true;
        if (flag === 'l') js = /^javascript$/i.test(value ?? '');
      }
      continue;                                                        // -i, or an unknown flag
    }
    return inline ? { source: 'inline', js } : { source: 'file', file: a, js };
  }
  return { source: inline ? 'inline' : 'stdin', js };
}

/** tar is in create mode: `--create`, a short cluster with c (`-czf`), or a bundled first arg (`czf`). */
export function tarCreates(a: string[]): boolean {
  return a.some(x => x === '--create' || /^-[A-Za-z]*c[A-Za-z]*$/.test(x)) || /^[A-Za-z]*c[A-Za-z]*$/.test(a[0] ?? '');
}

/**
 * Where an archiver stages its files: a strong odd location (temporary, Downloads, /Users/Shared, /Volumes,
 * translocated, a buried hidden folder) named by an argument. Absolute paths come from plain args, `--opt=/path`
 * and attached `-C/path`; a relative arg counts only when the working directory is itself a strong place and not a
 * build folder (go-build, node_modules…). Exclude/include patterns are skipped: zip's `-x`/`-i` lists, tar's
 * `--exclude`/`--include`/`-X file`. zip's `-X` takes no value.
 */
export function stagingPlace(tool: 'ditto' | 'zip' | 'tar', a: string[], cwd: string | null): OddLocation | null {
  const paths: string[] = [];
  for (let i = 0; i < a.length; i++) {
    const x = a[i]!;
    if (tool === 'zip' && (x === '-x' || x === '-i')) {               // a list of patterns up to the next option
      while (i + 1 < a.length && !a[i + 1]!.startsWith('-')) i++;
      continue;
    }
    if (tool === 'tar' && (x === '--exclude' || x === '--include' || x === '--exclude-from' || x === '-X')) { i++; continue; }
    if (/^--(?:exclude|include|exclude-from)=/.test(x) || (tool === 'zip' && /^-[xi]./.test(x))) continue;
    if (x.startsWith('--')) { if (x.includes('=')) paths.push(x.slice(x.indexOf('=') + 1)); continue; }
    if (x.startsWith('-')) { if (x.includes('/')) paths.push(x.slice(x.indexOf('/'))); continue; }
    paths.push(x);
  }
  const cwdCounts = cwd !== null && strongPlace(normPath(`${cwd}/`)) !== null && !inBuildDir(cwd);
  for (const x of paths) {
    if (x.startsWith('/')) {
      // The argument may be the folder itself (`-C /tmp`), so it is also checked as a folder.
      const w = oddLocation(x) ?? strongPlace(normPath(`${x}/`));
      if (w !== null && w.strength === 'strong') return w;
    } else if (cwdCounts) {
      const w = strongPlace(normPath(resolvePath(x, cwd)));
      if (w !== null) return w;
    }
  }
  return null;
}

/** The `security` subcommand (after the global options; `-p` takes a prompt) and that subcommand's arguments. */
export function securityArgs(args: string[]): { sub: string; rest: string[] } | null {
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '-p') { i++; continue; }
    if (!args[i]!.startsWith('-')) return { sub: args[i]!, rest: args.slice(i + 1) };
  }
  return null;
}
/** find-generic-password / find-internet-password: every option takes a value except -g and -w. */
export const SECURITY_FIND_SPEC: OptSpec = { shortValues: 'aAcCdDGjklpPrst', longValues: [] };
