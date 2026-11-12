import { parseLine } from './parse';
import { resolveRelations } from './relations';
import type { CaptureModel, CaptureStats, FileOp, Image, NormEvent, ProcId, ProcInfo, Process } from './types';
import { latestImage } from './util';

function imageFrom(info: ProcInfo, seq: number): Image {
  return {
    token: info.token, path: info.path, signingId: info.signingId, teamId: info.teamId,
    isPlatform: info.isPlatform, csFlags: info.csFlags,
    args: null, cwd: null, env: null, stdinIsPipe: null, script: null,
    time: null, seq, inherited: false,
  };
}

function newProcess(info: ProcInfo, image: Image, seq: number): Process {
  return {
    id: info.token, pid: info.pid, ghost: false, images: [image],
    forkParent: null,
    originalPpid: info.originalPpid, ppid: info.ppid,
    parentToken: info.parentToken, responsibleToken: info.responsibleToken,
    originalParent: null, currentParent: null, responsible: null,
    startTime: info.startTime, exitTime: null, firstSeq: seq, fileOps: [],
  };
}

/** Buffers parsed lines; finish() applies them in global_seq_num order. */
export class ModelBuilder {
  private events: NormEvent[] = [];
  private lines = 0;
  private badLines = 0;
  private processes = new Map<ProcId, Process>();
  private tokenIndex = new Map<string, ProcId>();
  private latestByPid = new Map<number, Process>();
  private persistence: CaptureModel['persistence'] = [];
  private otherEvents: Record<string, number> = {};

  addLine(line: string): void {
    this.lines++;
    const ev = parseLine(line);
    if (ev === 'bad') this.badLines++;
    else if (ev !== null) this.events.push(ev);
  }

  finish(): CaptureModel {
    const events = this.events.sort((a, b) => a.seq - b.seq);
    for (const ev of events) this.apply(ev);
    const first = events[0];
    const last = events[events.length - 1];
    const stats: CaptureStats = {
      lines: this.lines, events: events.length, badLines: this.badLines,
      otherEvents: this.otherEvents,
      versions: [...new Set(events.map(e => e.version))].sort((a, b) => a - b),
      firstSeq: first ? first.seq : null,
      firstTime: first ? first.time : null,
      lastTime: last ? last.time : null,
    };
    const m: CaptureModel = {
      processes: this.processes, tokenIndex: this.tokenIndex, persistence: this.persistence, stats,
    };
    resolveRelations(m);
    return m;
  }

  private add(p: Process, token: string): void {
    this.processes.set(p.id, p);
    this.tokenIndex.set(token, p.id);
    this.latestByPid.set(p.pid, p);
  }

  /** The process owning info.token, created on first sight; refreshes raw parent fields. */
  private ensure(info: ProcInfo, seq: number, time: string): Process {
    const id = this.tokenIndex.get(info.token);
    const known = id !== undefined ? this.processes.get(id) : undefined;
    if (known) {
      this.refresh(known, info, seq);
      return known;
    }
    // Missed exec: an unseen token of a live process with the same start_time
    // (start_time survives exec and changes on PID reuse).
    const live = this.latestByPid.get(info.pid);
    if (live && live.exitTime === null && live.startTime !== null && live.startTime === info.startTime) {
      live.images.push({ ...imageFrom(info, seq), time });
      this.tokenIndex.set(info.token, live.id);
      this.refresh(live, info, seq);
      return live;
    }
    const p = newProcess(info, imageFrom(info, seq), seq);
    this.add(p, info.token);
    return p;
  }

  private refresh(known: Process, info: ProcInfo, seq: number): void {
    // Latest seen, but a later event without the field doesn't erase it.
    if (info.ppid !== null) known.ppid = info.ppid;
    if (info.originalPpid !== null) known.originalPpid = info.originalPpid;
    if (info.parentToken !== null) known.parentToken = info.parentToken;
    if (info.responsibleToken !== null) known.responsibleToken = info.responsibleToken;
    if (known.startTime === null) known.startTime = info.startTime;
    // Missing exec: same token, different executable.
    const cur = latestImage(known)?.path ?? null;
    if (info.path !== null && cur !== null && info.path !== cur) known.images.push(imageFrom(info, seq));
  }

  private apply(ev: NormEvent): void {
    const p = this.ensure(ev.proc, ev.seq, ev.time);
    switch (ev.kind) {
      case 'fork': {
        const child = ev.child!;
        const existing = this.tokenIndex.get(child.token);
        if (existing !== undefined) {
          this.processes.get(existing)!.forkParent = p.id;
          break;
        }
        const c = newProcess(child, { ...imageFrom(child, ev.seq), inherited: true }, ev.seq);
        c.forkParent = p.id;
        this.add(c, child.token);
        break;
      }
      case 'exec': {
        const target = ev.target!;
        p.images.push({
          ...imageFrom(target, ev.seq),
          args: ev.args ?? null, cwd: ev.cwd ?? null, env: ev.env ?? null,
          stdinIsPipe: ev.stdinIsPipe ?? null, script: ev.script ?? null, time: ev.time,
        });
        this.tokenIndex.set(target.token, p.id);
        break;
      }
      case 'exit':
        p.exitTime = ev.time;
        break;
      case 'create': case 'rename': case 'unlink': case 'write': case 'setextattr': {
        if (ev.path === undefined) break;
        const op: FileOp = { kind: ev.kind, path: ev.path, time: ev.time, seq: ev.seq };
        if (ev.toPath !== undefined) op.toPath = ev.toPath;
        if (ev.xattr !== undefined) op.xattr = ev.xattr;
        p.fileOps.push(op);
        break;
      }
      case 'btm_add': case 'btm_remove': {
        const b = ev.btm!;
        this.persistence.push({
          id: 'btm:' + ev.seq, kind: ev.kind === 'btm_add' ? 'add' : 'remove',
          plistPath: b.plistPath, executablePath: b.executablePath, appPath: b.appPath,
          time: ev.time, seq: ev.seq, instigator: p.id, creator: null,
        });
        break;
      }
      case 'other':
        this.otherEvents[ev.rawType] = (this.otherEvents[ev.rawType] ?? 0) + 1;
        break;
    }
  }
}

export function buildModel(lines: Iterable<string>): CaptureModel {
  const b = new ModelBuilder();
  for (const line of lines) b.addLine(line);
  return b.finish();
}
