import type { BtmInfo, EventKind, NormEvent, ProcInfo, TokenKey } from './types';
import { fileUrlToPath } from './util';

/* eslint-disable @typescript-eslint/no-explicit-any */
type Json = any;

const KIND_BY_KEY: Record<string, EventKind> = {
  fork: 'fork', exec: 'exec', exit: 'exit', create: 'create', rename: 'rename',
  unlink: 'unlink', write: 'write', setextattr: 'setextattr',
  btm_launch_item_add: 'btm_add', btm_launch_item_remove: 'btm_remove',
};

function tokenOf(t: Json): TokenKey | null {
  if (!t || typeof t.pid !== 'number' || typeof t.pidversion !== 'number') return null;
  return `${t.pid}:${t.pidversion}`;
}

function procInfo(p: Json): ProcInfo {
  const token = tokenOf(p.audit_token);
  if (token === null) throw new Error('process without audit_token');
  return {
    token,
    pid: p.audit_token.pid,
    path: p.executable?.path ?? null,
    signingId: p.signing_id ?? null,
    teamId: p.team_id ?? null,
    isPlatform: p.is_platform_binary === true,
    csFlags: p.codesigning_flags ?? 0,
    ppid: p.ppid ?? null,
    originalPpid: p.original_ppid ?? null,
    parentToken: tokenOf(p.parent_audit_token),
    responsibleToken: tokenOf(p.responsible_audit_token),
    startTime: p.start_time ?? null,
  };
}

/** create/rename destination: existing_file.path, else new_path.dir.path + '/' + filename. */
function destPath(d: Json): string | undefined {
  if (!d) return undefined;
  if (d.existing_file?.path) return d.existing_file.path;
  const np = d.new_path;
  if (np?.dir?.path != null && np.filename != null) {
    const dir: string = np.dir.path;
    return (dir.endsWith('/') ? dir : dir + '/') + np.filename;
  }
  return undefined;
}

function btmInfo(e: Json): BtmInfo {
  return {
    plistPath: fileUrlToPath(e.item?.item_url ?? null),
    executablePath: e.executable_path ?? null,
    appPath: fileUrlToPath(e.item?.app_url ?? null),
  };
}

function normalize(o: Json): NormEvent {
  const rawType = Object.keys(o.event)[0];
  if (rawType === undefined) throw new Error('empty event');
  const e = o.event[rawType] ?? {};
  const kind = KIND_BY_KEY[rawType] ?? 'other';
  const ev: NormEvent = {
    seq: o.global_seq_num ?? 0,
    time: o.time ?? '',
    kind,
    rawType,
    version: o.version ?? 0,
    proc: procInfo(o.process),
  };
  switch (kind) {
    case 'fork':
      ev.child = procInfo(e.child);
      break;
    case 'exec': {
      ev.target = procInfo(e.target);
      ev.args = Array.isArray(e.args) ? e.args : [];
      ev.cwd = e.cwd?.path ?? null;
      ev.env = Array.isArray(e.env) ? e.env : [];
      ev.stdinIsPipe = Array.isArray(e.fds)
        ? e.fds.some((f: Json) => f.fd === 0 && 'pipe' in f)
        : null;
      ev.script = e.script?.path ?? null;
      break;
    }
    case 'create':
      ev.path = destPath(e.destination);
      break;
    case 'rename':
      ev.path = e.source?.path;
      ev.toPath = destPath(e.destination);
      break;
    case 'unlink':
    case 'write':
      ev.path = e.target?.path;
      break;
    case 'setextattr':
      ev.path = e.target?.path;
      ev.xattr = e.extattr;
      break;
    case 'btm_add':
    case 'btm_remove':
      ev.btm = btmInfo(e);
      break;
    default:
      break;
  }
  return ev;
}

/** Blank -> null; unparseable or not an eslogger event -> 'bad'. */
export function parseLine(line: string): NormEvent | null | 'bad' {
  if (line.trim() === '') return null;
  let o: Json;
  try {
    o = JSON.parse(line);
  } catch {
    return 'bad';
  }
  if (!o || typeof o !== 'object' || !o.event || typeof o.event !== 'object' || !o.process) {
    return 'bad';
  }
  try {
    return normalize(o);
  } catch {
    return 'bad';
  }
}
