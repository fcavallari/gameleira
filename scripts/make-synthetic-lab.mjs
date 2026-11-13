// Writes test/fixtures/synthetic-lab.jsonl: a small, hand-built eslogger capture (schema version 11) that tells the
// story of a lab intrusion on a made-up Mac, plus ordinary background noise. Nothing in it comes from a real machine.
//
//   node scripts/make-synthetic-lab.mjs            write the fixture
//   node scripts/make-synthetic-lab.mjs --stdout   print it instead (test/synthetic-lab.test.ts compares the two)
//
// The output is deterministic: no clock, no randomness. Users, pids, tokens, team IDs and hashes are invented. The
// field layout follows eslogger's JSON for the events the viewer reads (stat blocks are left out; the viewer ignores them).
//
// What happens (times are seconds into the capture; `alice` is the user, 501 her uid):
//    1  zsh (shell, started before the capture; its parent `login` was never seen) runs
//         curl -o /tmp/page.html, then xattr -l
//    5  echo ... | bash   -> bash reads commands from a pipe; bash runs whoami
//    9  osascript -e 'display dialog ...', then dscl . -authonly with a made-up password in its arguments
//   12  mkdir/cp/ditto -c staging in /tmp
//   16  (sleep 90 &)      -> the sleep outlives its subshell and ends up under launchd (orphaned)
//   17  nohup sleep 120   -> exec chain: zsh -> nohup -> sleep, one process
//   20  cat > ~/Library/LaunchAgents/com.test.labdemo.plist   (the redirect creates the file), then a
//         btm_launch_item_add for it (instigated by smd, so the finding stays on cat), then launchctl bootstrap
//   24  a forked child that never execs writes ~/Library/LaunchAgents/com.test.labdemo.helper.plist (a temp file renamed
//         onto it); no btm event
//   27  launchd starts Installer.app (ad-hoc signed, in ~/Downloads), which at 28 registers itself as a login item (btm event names it as `app`),
//         and runs xattr -cr on itself
//   40  a standalone launch agent for an updater app: no process in the capture is tied to it
//    2..50  Monitor.app (team-signed) runs `ps` six times: noise, one tool, never a burst
//   10..  Lab Editor.app runs `git status` three times, and a team-signed browser build from /var/folders
//   60  a second shell runs sw_vers, uname, system_profiler within 4 s: a recon burst; `hostname` at 300 s is alone
//   70  pid 7500 (started before the capture, under the second shell): an exec the capture missed. Its first event
//         carries token 7500:9500 as /bin/sh, its second 7500:9501 as curl, same start_time, no exec event in between
//   two mdworker_shared processes that only show up in their exit events

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(root, 'test', 'fixtures', 'synthetic-lab.jsonl');

// ---- clock and sequence -------------------------------------------------------------------------------------
const CAPTURE_START = Date.parse('2026-03-14T10:00:00.000Z');
const iso = (ms, micro = 0) => new Date(ms).toISOString().replace('Z', `${String(micro).padStart(3, '0')}Z`);
const at = (sec) => CAPTURE_START + Math.round(sec * 1000);

const timeline = [];                  // { ms, order, event } sorted by time, then insertion order
let order = 0;
let thread = 4100;

// ---- processes ----------------------------------------------------------------------------------------------
const LAUNCHD = { pid: 1, pv: 1021 };
const hex40 = (s) => crypto.createHash('sha1').update(s).digest('hex').toUpperCase();
const PLATFORM_FLAGS = 637631233;     // platform binary, hardened, valid
const TEAM_FLAGS = 570491649;         // developer-signed, valid
const ADHOC_FLAGS = 0x20003;          // valid, ad-hoc (0x2), linker-signed

const token = (t) => ({
  auid: 501, ruid: 501, rgid: 20, egid: 20, euid: 501, asid: 100020, pid: t.pid, pidversion: t.pv,
});
const rootToken = (t) => ({
  auid: 4294967295, ruid: 0, rgid: 0, egid: 0, euid: 0, asid: 100019, pid: t.pid, pidversion: t.pv,
});

/**
 * A process: pid, pv (pidversion), path, signing (id, team, flags), start (ms), parent and responsible tokens.
 * `kind`: 'platform' (Apple), 'team' (developer-signed), 'adhoc' or 'unsigned'.
 */
function image(path, kind, signingId, teamId) {
  if (kind === 'platform') return { path, signingId, teamId: null, platform: true, flags: PLATFORM_FLAGS };
  if (kind === 'team') return { path, signingId, teamId, platform: false, flags: TEAM_FLAGS };
  if (kind === 'adhoc') return { path, signingId, teamId: null, platform: false, flags: ADHOC_FLAGS };
  return { path, signingId: null, teamId: null, platform: false, flags: 0 };
}
const apple = (p) => image(p, 'platform', `com.apple.${p.split('/').pop()}`);

function spawn(pid, pv, img, o = {}) {
  return {
    pid, pv, img, start: o.start, ppid: o.ppid ?? 1, oppid: o.oppid ?? o.ppid ?? 1,
    parent: o.parent ?? LAUNCHD, resp: o.resp ?? { pid, pv }, root: o.root ?? false, session: o.session ?? 1,
    group: o.group ?? pid, startMicro: o.startMicro ?? 0,
  };
}

/** The eslogger process object for p as it is right now. */
function procObj(p) {
  const tok = p.root ? rootToken : token;
  return {
    tty: null,
    start_time: iso(p.start, p.startMicro),
    session_id: p.session,
    is_es_client: false,
    ppid: p.ppid,
    is_platform_binary: p.img.platform,
    original_ppid: p.oppid,
    team_id: p.img.teamId,
    cdhash: hex40(p.img.path + (p.img.signingId ?? '')),
    parent_audit_token: p.parent.pid === 1 ? rootToken(p.parent) : token(p.parent),
    cs_validation_category: p.img.platform ? 1 : 6,
    executable: { path_truncated: false, path: p.img.path },
    signing_id: p.img.signingId,
    group_id: p.group,
    codesigning_flags: p.img.flags,
    audit_token: tok({ pid: p.pid, pv: p.pv }),
    responsible_audit_token: tok(p.resp),
  };
}

const EVENT_TYPE = { exec: 9, open: 10, fork: 11, create: 13, exit: 15, rename: 25, btm_launch_item_add: 124 };

function emit(sec, p, name, body, micro = 0) {
  timeline.push({
    ms: at(sec), micro, order: order++,
    base: {
      action: { result: { result_type: 0, result: { auth: 0 } } },
      version: 11,
      action_type: 1,
      event_type: EVENT_TYPE[name],
      thread: { thread_id: thread++ },
      process: procObj(p),
      schema_version: 1,
      seq_num: 0,
      event: { [name]: body },
    },
  });
}

/** `parent` forks a child (new pid, inherited image and responsible process); returns the child. */
function fork(sec, parent, pid, pv, over = {}) {
  const child = spawn(pid, pv, { ...parent.img }, {
    start: at(sec) - 1, startMicro: 400 + (pid % 500), ppid: parent.pid, oppid: parent.pid,
    parent: { pid: parent.pid, pv: parent.pv }, resp: parent.resp, root: parent.root, session: parent.session, group: parent.group,
    ...over,
  });
  emit(sec, parent, 'fork', { child: procObj(child) });
  return child;
}

const ENV = ['HOME=/Users/alice', 'LANG=C.UTF-8', 'LOGNAME=alice', 'PATH=/usr/local/bin:/usr/bin:/bin', 'SHELL=/bin/zsh', 'USER=alice'];
const TTY_FDS = [{ fd: 0, fdtype: 1 }, { fd: 1, fdtype: 1 }, { fd: 2, fdtype: 1 }];
const PIPE_FDS = [{ fd: 0, fdtype: 6, pipe: { pipe_id: 100231 } }, { fd: 1, fdtype: 1 }, { fd: 2, fdtype: 1 }];

/** p execs `img` with these arguments: the event carries the process before exec, the target after it. */
function exec(sec, p, img, args, o = {}) {
  const before = { ...p };
  p.img = img;
  p.pv += 1;
  const cwd = o.cwd ?? '/Users/alice/work';
  timeline.push({
    ms: at(sec), micro: 0, order: order++,
    base: {
      action: { result: { result_type: 0, result: { auth: 0 } } },
      version: 11, action_type: 1, event_type: EVENT_TYPE.exec, thread: { thread_id: thread++ },
      process: procObj(before),
      schema_version: 1, seq_num: 0,
      event: {
        exec: {
          image_cpusubtype: 2, script: o.script ? { path_truncated: false, path: o.script } : null,
          cwd: { path_truncated: false, path: cwd }, target: procObj(p), entitlements: {},
          dyld_exec_path: img.path, fds: o.fds ?? TTY_FDS, env: ENV, args, image_cputype: 16777228, last_fd: 2,
        },
      },
    },
  });
}

const exit = (sec, p, stat = 0) => emit(sec, p, 'exit', { stat });

const file = (path) => ({ path_truncated: false, path });
/** A new file: eslogger reports where it will be (new_path) or the file that now exists (existing_file). */
const createdNew = (sec, p, fullPath) => {
  const i = fullPath.lastIndexOf('/');
  emit(sec, p, 'create', {
    destination: { new_path: { dir: file(fullPath.slice(0, i)), filename: fullPath.slice(i + 1), mode: 33188 } },
    destination_type: 1, acl: null,
  });
};
const createdExisting = (sec, p, fullPath) =>
  emit(sec, p, 'create', { destination: { existing_file: file(fullPath) }, destination_type: 0, acl: null });
const renamed = (sec, p, from, to) =>
  emit(sec, p, 'rename', { destination: { existing_file: file(to) }, destination_type: 0, source: file(from) });

// ---- the cast -----------------------------------------------------------------------------------------------
// Before the capture. Terminal (6100) and login (6120) are never seen: they are the ghosts behind the shell.
const TERMINAL = { pid: 6100, pv: 8100 };
const LOGIN = { pid: 6120, pv: 8120 };
const t0 = Date.parse('2026-03-14T09:12:03.000Z');

// launchd (pid 1) is seen: it starts Installer.app. Everything else that "started before the capture" is only a parent token.
const launchd = spawn(LAUNCHD.pid, LAUNCHD.pv, apple('/sbin/launchd'), {
  start: Date.parse('2026-03-14T08:55:00.000Z'), ppid: 0, oppid: 0, parent: { pid: 0, pv: 0 }, root: true, session: 0, group: 1,
});

const zsh = spawn(6130, 8130, apple('/bin/zsh'), {
  start: t0, ppid: LOGIN.pid, oppid: LOGIN.pid, parent: LOGIN, resp: TERMINAL, group: 6130,
});

// ---- 1. curl, xattr -----------------------------------------------------------------------------------------
{
  const c = fork(1.0, zsh, 7001, 9001);
  exec(1.2, c, apple('/usr/bin/curl'), ['curl', '-s', 'https://example.com', '-o', '/tmp/page.html']);
  createdNew(1.5, c, '/private/tmp/page.html');
  exit(1.8, c);
  const x = fork(3.0, zsh, 7002, 9011);
  exec(3.1, x, apple('/usr/bin/xattr'), ['xattr', '-l', '/tmp/page.html']);
  exit(3.2, x);
}

// ---- 2. echo ... | bash, bash runs whoami -----------------------------------------------------------------
{
  const echo = fork(5.0, zsh, 7003, 9021);          // the builtin's subshell: forks and never execs
  exit(5.1, echo);
  const bash = fork(5.0, zsh, 7004, 9031);
  exec(5.2, bash, apple('/bin/bash'), ['bash'], { fds: PIPE_FDS });
  const w = fork(5.6, bash, 7005, 9041);
  exec(5.7, w, apple('/usr/bin/whoami'), ['whoami']);
  exit(5.8, w);
  exit(6.0, bash);
}

// ---- 3. fake password prompt ------------------------------------------------------------------------------
{
  const o = fork(9.0, zsh, 7006, 9051);
  exec(9.2, o, apple('/usr/bin/osascript'), ['osascript', '-e', 'display dialog "LAB DEMO - not a real prompt" buttons {"OK"}']);
  exit(10.5, o);
  // ...and then checks the password it just "collected": the secret is in the command line.
  const d = fork(11.0, zsh, 7016, 9052);
  exec(11.1, d, apple('/usr/bin/dscl'), ['dscl', '.', '-authonly', 'labuser', 'labpass-not-real']);
  exit(11.3, d);
}

// ---- 4. staging in /tmp -------------------------------------------------------------------------------------
{
  const mk = fork(12.0, zsh, 7007, 9061);
  exec(12.1, mk, apple('/bin/mkdir'), ['mkdir', '-p', '/tmp/stage']);
  createdNew(12.15, mk, '/private/tmp/stage');
  exit(12.2, mk);
  const cp = fork(12.4, zsh, 7008, 9071);
  exec(12.5, cp, apple('/bin/cp'), ['cp', '/etc/hosts', '/tmp/stage/']);
  createdNew(12.55, cp, '/private/tmp/stage/hosts');
  exit(12.6, cp);
  const di = fork(12.8, zsh, 7009, 9081);
  exec(12.9, di, apple('/usr/bin/ditto'), ['ditto', '-c', '-k', '/tmp/stage', '/tmp/stage.zip']);
  createdNew(13.1, di, '/private/tmp/stage.zip');
  exit(13.3, di);
}

// ---- 5. orphaned sleep, nohup chain ---------------------------------------------------------------------
{
  const sub = fork(16.0, zsh, 7010, 9091);          // `( ... )`: a subshell that forks and never execs
  const sl = fork(16.1, sub, 7011, 9101);
  exec(16.2, sl, apple('/bin/sleep'), ['sleep', '90']);
  exit(16.4, sub);
  // The subshell is gone: from now on the sleep's parent is launchd, though its original parent is the subshell.
  sl.ppid = 1; sl.parent = LAUNCHD;
  exit(106.3, sl);

  const nh = fork(17.0, zsh, 7012, 9111);
  exec(17.1, nh, apple('/usr/bin/nohup'), ['nohup', 'sleep', '120']);
  exec(17.2, nh, apple('/bin/sleep'), ['sleep', '120']);
  exit(137.2, nh);
}

// ---- 6. persistence: a plist written by a shell redirect, its btm event, launchctl ----------------------------
// backgroundtaskmanagementd emits the btm events; smd is the XPC caller (instigator).
const btmd = spawn(770, 1730, apple('/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd'), {
  start: Date.parse('2026-03-14T09:00:11.000Z'), root: true, session: 770, group: 770,
});
const smd = spawn(560, 1390, apple('/usr/libexec/smd'), {
  start: Date.parse('2026-03-14T09:00:10.000Z'), root: true, session: 560, group: 560,
});
smd.img.signingId = 'com.apple.xpc.smd';

function btmAdd(sec, item, extra = {}) {
  const body = {
    app_token: extra.app ? token({ pid: extra.app.pid, pv: extra.app.pv }) : null,
    executable_path: extra.executable ?? null,
    instigator_token: rootToken({ pid: smd.pid, pv: smd.pv }),
    app: extra.app ? procObj(extra.app) : null,
    instigator: procObj(smd),
    item,
  };
  emit(sec, btmd, 'btm_launch_item_add', body);
}

{
  const cat = fork(20.0, zsh, 7013, 9121);
  createdExisting(20.1, cat, '/Users/alice/Library/LaunchAgents/com.test.labdemo.plist');   // the shell's redirect, before cat starts
  exec(20.2, cat, apple('/bin/cat'), ['cat']);
  exit(20.6, cat);
  btmAdd(20.8, {
    uid: 501, item_url: 'file:///Users/alice/Library/LaunchAgents/com.test.labdemo.plist', app_url: null,
    legacy: true, item_type: 3, managed: false,
  }, { executable: '/bin/sh' });
  const lc = fork(22.0, zsh, 7014, 9131);
  exec(22.1, lc, apple('/bin/launchctl'), ['launchctl', 'bootstrap', 'gui/501', '/Users/alice/Library/LaunchAgents/com.test.labdemo.plist']);
  exit(22.4, lc);
}

// ---- 7. a forked child that never execs writes a plist by rename; nothing registers it --------------------------------
{
  const d = fork(24.0, zsh, 7015, 9141);
  createdNew(24.1, d, '/Users/alice/Library/LaunchAgents/.com.test.labdemo.helper.plist.tmp');
  renamed(24.2, d, '/Users/alice/Library/LaunchAgents/.com.test.labdemo.helper.plist.tmp', '/Users/alice/Library/LaunchAgents/com.test.labdemo.helper.plist');
  exit(24.4, d);
}

// ---- 8. Installer.app registers itself as a login item (the event names it as `app`) --------------------------
{
  const inst = fork(27.0, launchd, 7100, 9100, { root: false, resp: { pid: 7100, pv: 9101 }, session: 100020, group: 7100 });
  exec(27.1, inst, image('/Users/alice/Downloads/Installer.app/Contents/MacOS/Installer', 'adhoc', 'Installer'), ['/Users/alice/Downloads/Installer.app/Contents/MacOS/Installer'], { cwd: '/' });
  const xa = fork(28.0, inst, 7101, 9151);
  exec(28.1, xa, apple('/usr/bin/xattr'), ['xattr', '-cr', '/Users/alice/Downloads/Installer.app']);
  exit(28.3, xa);
  btmAdd(29.0, {
    uid: 501, item_url: 'file:///Users/alice/Downloads/Installer.app/', app_url: 'file:///Users/alice/Downloads/Installer.app/',
    legacy: false, item_type: 2, managed: false,
  }, { app: inst });
  exit(41.0, inst);
}

// ---- 9. a standalone launch agent: no captured process is tied to it ---------------------------------------
btmAdd(40.0, {
  uid: 501, item_url: 'file:///Users/alice/Library/LaunchAgents/com.example.updater.wake.plist',
  app_url: 'file:///Users/alice/Library/Application%20Support/Example/Updater/1.2.3/Updater.app/',
  legacy: true, item_type: 3, managed: false,
}, { executable: '/Users/alice/Library/Application Support/Example/Updater/Current/Updater.app/Contents/MacOS/Updater' });

// ---- 10. noise ------------------------------------------------------------------------------------------------
const TEAM_A = 'LAB0AAAA01';
const TEAM_B = 'LAB0BBBB02';
{
  // Monitor.app: ps six times. One tool is not a burst.
  const mon = spawn(5200, 5201, image('/Applications/Monitor.app/Contents/MacOS/Monitor', 'team', 'com.example.monitor', TEAM_A), {
    start: Date.parse('2026-03-14T08:00:00.000Z'), ppid: 1, parent: LAUNCHD,
  });
  [2, 10, 18, 26, 34, 50].forEach((sec, i) => {
    const ps = fork(sec, mon, 7200 + i, 9200 + 10 * i);
    exec(sec + 0.1, ps, apple('/bin/ps'), ['ps', '-axo', 'pid,ppid,comm'], { cwd: '/' });
    exit(sec + 0.3, ps);
  });

  // Lab Editor.app: git status three times, and a team-signed browser build run from /var/folders.
  const ed = spawn(5300, 5301, image('/Applications/Lab Editor.app/Contents/MacOS/Lab Editor', 'team', 'com.example.labeditor', TEAM_B), {
    start: Date.parse('2026-03-14T08:30:00.000Z'), ppid: 1, parent: LAUNCHD,
  });
  [10, 30, 55].forEach((sec, i) => {
    const g = fork(sec, ed, 7300 + i, 9300 + 10 * i);
    exec(sec + 0.1, g, apple('/usr/bin/git'), ['git', 'status', '--porcelain'], { cwd: '/Users/alice/proj' });
    exit(sec + 0.4, g);
  });
  const br = fork(33.0, ed, 7310, 9350);
  exec(33.1, br, image('/private/var/folders/zz/lab00000000000000000000000/T/lab-browser/Lab Browser.app/Contents/MacOS/Lab Browser', 'team', 'com.example.labbrowser', TEAM_B), ['Lab Browser', '--headless']);
  exit(45.0, br);

  // mdworker_shared: seen only in its exit events.
  [8, 36].forEach((sec, i) => {
    const mw = spawn(5400 + i, 5410 + i, apple('/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared'), {
      start: at(sec - 4), ppid: 1, parent: LAUNCHD,
    });
    exit(sec, mw, 9);
  });

  // `open` is an event the viewer does not model: counted under "other events".
  emit(46.0, ed, 'open', { fflag: 1, file: file('/Users/alice/proj/README.md') });
  emit(47.0, ed, 'open', { fflag: 1, file: file('/Users/alice/proj/package.json') });
}

// ---- 11. a recon burst: three different tools under one shell within 4 s; a fourth tool far later ------------
{
  const z2 = spawn(6400, 8400, apple('/bin/zsh'), {
    start: Date.parse('2026-03-14T09:40:00.000Z'), ppid: 6390, oppid: 6390, parent: { pid: 6390, pv: 8390 }, resp: { pid: 6101, pv: 8101 }, group: 6400,
  });
  const run = (sec, pid, pv, img, args) => {
    const c = fork(sec, z2, pid, pv);
    exec(sec + 0.1, c, img, args);
    exit(sec + 0.3, c);
  };
  run(60.0, 7400, 9400, apple('/usr/bin/sw_vers'), ['sw_vers']);
  run(61.5, 7401, 9410, apple('/usr/bin/uname'), ['uname', '-a']);
  run(63.0, 7402, 9420, apple('/usr/sbin/system_profiler'), ['system_profiler', 'SPHardwareDataType']);
  run(300.0, 7403, 9430, apple('/bin/hostname'), ['hostname']);
}

// ---- 12. a missed exec: one process, two tokens, no exec event between them ---------------------------------
{
  const startMs = Date.parse('2026-03-14T09:59:50.000Z');
  const w = spawn(7500, 9500, apple('/bin/sh'), {
    start: startMs, ppid: 6400, oppid: 6400, parent: { pid: 6400, pv: 8400 }, resp: { pid: 6101, pv: 8101 },
  });
  emit(69.0, w, 'open', { fflag: 1, file: file('/Users/alice/work/job.sh') });   // its first event: token 7500:9500, /bin/sh
  w.pv += 1;                                         // the exec happened; its event was dropped
  w.img = apple('/usr/bin/curl');
  createdNew(70.0, w, '/private/tmp/payload.bin');   // its second: token 7500:9501, curl
  exit(71.0, w);
}

// ---- write ---------------------------------------------------------------------------------------------------
timeline.sort((a, b) => a.ms - b.ms || a.micro - b.micro || a.order - b.order);
const lines = timeline.map((e, i) => {
  // Nanosecond precision, like eslogger's: nine fractional digits.
  const time = iso(e.ms, 100 + (i % 800)).replace('Z', `${String((i * 7) % 1000).padStart(3, '0')}Z`);
  return JSON.stringify({ ...e.base, time, global_seq_num: i, mach_time: 2400000000000 + i * 40000 });
});
const text = lines.join('\n') + '\n';

if (process.argv.includes('--stdout')) process.stdout.write(text);
else {
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, text);
  console.log(`wrote ${path.relative(root, OUT)}: ${lines.length} events, ${(text.length / 1024).toFixed(1)} KB`);
}
