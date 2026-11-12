export type TokenKey = string;            // `${pid}:${pidversion}`
export type ProcId = string;              // first TokenKey of the exec chain, or `ghost:${pid}`
export interface ProcInfo {               // normalized es process object
  token: TokenKey; pid: number; path: string | null;
  signingId: string | null; teamId: string | null;
  isPlatform: boolean; csFlags: number;
  ppid: number | null; originalPpid: number | null;
  parentToken: TokenKey | null; responsibleToken: TokenKey | null;
  startTime: string | null;
}
export type EventKind = 'fork' | 'exec' | 'exit' | 'create' | 'rename' | 'unlink'
  | 'write' | 'setextattr' | 'btm_add' | 'btm_remove' | 'other';
export interface BtmInfo { plistPath: string | null; executablePath: string | null; appPath: string | null }
export interface NormEvent {
  seq: number; time: string; kind: EventKind; rawType: string; version: number;
  proc: ProcInfo;
  child?: ProcInfo;                                         // fork
  target?: ProcInfo; args?: string[]; cwd?: string | null;  // exec
  env?: string[]; stdinIsPipe?: boolean | null; script?: string | null;
  path?: string; toPath?: string; xattr?: string;           // file ops
  btm?: BtmInfo;
}
export interface Image {
  token: TokenKey; path: string | null; signingId: string | null; teamId: string | null;
  isPlatform: boolean; csFlags: number;
  args: string[] | null; cwd: string | null; env: string[] | null;   // null when not from an exec event
  stdinIsPipe: boolean | null; script: string | null;
  time: string | null; seq: number;
  inherited: boolean;   // true for the copy a fork child starts with; rules skip these
}
export interface FileOp { kind: 'create' | 'rename' | 'unlink' | 'write' | 'setextattr';
  path: string; toPath?: string; xattr?: string; time: string; seq: number }
export interface Process {
  id: ProcId; pid: number; ghost: boolean; images: Image[];
  forkParent: ProcId | null;
  originalPpid: number | null; ppid: number | null;
  parentToken: TokenKey | null; responsibleToken: TokenKey | null;   // raw, latest seen
  originalParent: ProcId | null; currentParent: ProcId | null; responsible: ProcId | null; // resolved in Task 5
  startTime: string | null; exitTime: string | null; firstSeq: number; fileOps: FileOp[];
}
export interface PersistenceItem { id: string; kind: 'add' | 'remove'; plistPath: string | null;
  executablePath: string | null; appPath: string | null; time: string; seq: number;
  instigator: ProcId; creator: ProcId | null }
export interface CaptureStats { lines: number; events: number; badLines: number;
  otherEvents: Record<string, number>; versions: number[];
  firstSeq: number | null; firstTime: string | null; lastTime: string | null }
export interface CaptureModel { processes: Map<ProcId, Process>; tokenIndex: Map<TokenKey, ProcId>;
  persistence: PersistenceItem[]; stats: CaptureStats }
