# Gameleira

Gameleira: a macOS process tree viewer for eslogger captures that follows every root, not just the parent PID.

A single-file web app for triaging Apple `eslogger` captures. You drop a JSONL capture onto it; it rebuilds the process tree, flags suspicious processes with plain-language, MITRE-tagged explanations, and gives you a queue to confirm or dismiss them. Verdicts are kept per session (one investigation, usually one Mac) in the browser's IndexedDB, so they survive closing the tab. Everything runs locally: the page ships with a Content-Security-Policy of `connect-src 'none'`, so it cannot send a capture anywhere.

## Why “Gameleira”?

The gameleira is a Brazilian fig tree (Ficus spp.) known for its aerial roots. They drop from its branches, reach the ground and thicken into new trunks, until it’s hard to tell which trunk the tree started from.

Process trees on macOS work the same way. A plain ppid view says almost everything descends from launchd, but the real lineage runs through several connections: the original parent, the responsible process, XPC services, exec chains. Gameleira follows all of those roots, so you can see where a process actually came from, not just the parent the OS reports.

The name is also a nod to its creator’s Brazilian roots. The gameleira grows across Brazil and is a sacred tree in Afro-Brazilian traditions.

## Running it

Build once, then serve the result on localhost:

```
npm install
npm run build        # writes dist/index.html, a single self-contained file
npm run serve        # vite preview, http://localhost:4173
```

This is the way that has been tested: the measurements below were taken over HTTP, with sessions persisting in IndexedDB.

You can also open `dist/index.html` straight from Finder (double-click, or Open With a browser). That should work, since the page needs no server, but it has not been verified in every browser. If your browser does not keep sessions when the page is opened from disk (they are gone after you quit and reopen it), use `npm run serve`. Browsers may also give every `file://` page one shared storage origin.

Sessions are stored per origin, so a session made at `file://` is not visible at `http://localhost:4173` and the other way round. Use one and stick to it. Parsed captures are not stored; after reopening a session, re-drop the capture file and your verdicts reattach to it.

A capture is identified by its first 200 complete lines (plus the first event's sequence number and time), so a capture that is still growing keeps its verdicts when you drop it again later. A capture shorter than 200 complete lines can change identity as it grows: until it has 200 lines, a longer version of the file counts as a new capture.

Loaded captures stay in memory up to 300 MB of input file size per page; the least recently used one is dropped first (never the one on screen) and shows “Re-add <file> to continue”. Its verdicts are kept.

## Capturing

Run this on the Mac you are investigating, stop it with Ctrl-C, then drop `capture.jsonl` into a session:

```
sudo eslogger fork exec exit create rename unlink setextattr btm_launch_item_add btm_launch_item_remove > capture.jsonl
```

- `exec` and `fork` build the tree; `exit` gives process lifetimes.
- `create` and `rename` show what a process wrote (a launch agent plist, a download, an archive). `setextattr` records extended-attribute writes on files (shown under “What it did” in the detail pane). No rule uses them yet; a future rule could check whether a downloaded file got its quarantine flag.
- `btm_*` captures persistence registrations (login items, launch agents and daemons).
- `write` is left out on purpose because it is very noisy; the tool still handles it if it is present.
- Needs `eslogger` schema version 11 for the checks that read a process's stdin, such as `shell-from-pipe`. Older captures load, and the header says which checks may not apply.

## Using it

- **Triage** lists the queue (see below). Click a row, or move with `j` / `k`; `c` confirms a process as suspicious, `b` marks it benign, `n` puts the cursor in its note, `t` shows it in the tree. Pressing the verdict a process already has takes it back to unreviewed.
- **Tree** shows every process. The parent mode picks which root to follow: *Original parent* (who forked it), *Current parent* (who it sits under now, so an orphan is under launchd) or *Responsible* (the app that caused it). Unflagged processes are folded into grey “unflagged” rows with counts; the checkbox unfolds them. Search keeps the matches and their ancestors.
- **Confirmed** lists the confirmed processes of every capture in the session and exports the session as JSON, or imports one. The export includes the full command line of each verdict, and command lines can hold secrets (a password passed to `dscl -authonly`); tick “Redact command-line arguments” to replace every argument after the program name. Environment variables are left out unless you ask. Exports made by earlier builds (format `eslogger-viewer-session`) still import.

## Rules

The rules are data: each has an id, a severity, a plain explanation and MITRE ATT&CK IDs. The full list, with the exact matching logic, is in [`src/rules/rules.ts`](src/rules/rules.ts), and every finding also states in the app which trigger it matched. Summary:

| id | Severity | What it catches |
|---|---|---|
| `fake-prompt` | high | `osascript` whose arguments contain `display dialog` (or JavaScript for Automation's `displayDialog`) or `hidden answer`: a fake system password prompt (T1056.002). |
| `osascript-script` | med | `osascript` running a script file from a temporary, Downloads, shared, hidden, mounted-volume or translocated location, or reading its script from a pipe with no file on disk (T1059.002, or T1059.007 with `-l JavaScript`). |
| `keychain-access` | high, med or low | `security` against the keychain. High: `find-generic-password` or `find-internet-password` with `-g` or `-w` for a browser's or app's “Safe Storage” key or a crypto wallet entry, or `dump-keychain -d`. Med: any other `find-*-password -g` or `-w`. Low, context only: attribute lookups, `unlock-keychain`, `export`, `dump-keychain` without `-d` (T1555.001). |
| `security-setting-change` | high or med | Commands that weaken a protection or redirect traffic. High: `spctl --master-disable`, `--global-disable`, `--disable` naming no rule, `--add` (T1562.001, T1553.001); `csrutil disable`, `csrutil authenticated-root disable`, `csrutil enable --without` (T1562.001); `security add-trusted-cert` that trusts a root (T1553.004). Med: `spctl --disable` naming a rule; `add-trusted-cert -r deny` or `-r unspecified` (T1553); `security authorizationdb write` (T1548); `networksetup` setting a web, secure web, automatic, SOCKS proxy or DNS servers, or turning a proxy on (T1557). The text says when the command only works on older macOS or from Recovery, so it may be an attempt. |
| `dscl-authonly` | high | `dscl ... -authonly` (or `authonly`): verifying a password the attacker just phished with a fake prompt (T1056.002). |
| `persistence-item` | high or med | A launch item registered with the background task manager (`btm_launch_item_add`). High if it runs a shell or interpreter (python, perl, ruby, osascript, node, php), runs from a place a user process can write to (a temporary folder, `/Users/Shared`, Downloads, a mounted volume, a hidden or dot-folder, `~/Library/Caches`), ran unsigned or ad-hoc signed in this capture, or is a loose program (not an app bundle) anywhere in a home folder. Med otherwise, for example a per-user updater app in `~/Library`, or anything under `/Applications` or a system folder. The evidence says which reason applied. MITRE follows the item type: launch agent T1543.001, launch daemon T1543.004, login item, app or user item T1547.015. |
| `persistence-plist` | high | A process (one that exec'd, or one that only forked) wrote or renamed a `.plist` into a `LaunchAgents` folder (`~/Library`, `/Library`) or `/Library/LaunchDaemons`, and no registration event attaches its finding to that same process (T1543.001 or T1543.004, by folder). |
| `launchctl-load` | high | `launchctl load`, `bootstrap` or `submit`: starting a launch job right now (T1569.001). |
| `quarantine-strip` | high | `xattr -c` (also in clusters such as `-cr`), or `xattr -d com.apple.quarantine`: removing the flag that makes Gatekeeper check a download (T1553.001). |
| `payload-decode` | med | `openssl ... -d` (but not the digest commands such as `dgst`, where `-d` is debug), or `base64 -d`: unpacking a hidden payload (T1140). |
| `shell-from-pipe` | med | stdin is a pipe and no script file runs: a shell with no arguments or `-s` and no `-c`, or `python`, `perl` or `ruby` with no inline code and no script: the `curl ... \| bash` pattern, with no script on disk to inspect. `--version`/`--help` and similar probes do not count, but a ruby `-v` probe followed by `-` still reads the piped script. Needs `eslogger` schema 11 (T1059.004, T1059.006 for Python, T1059 for Perl and Ruby). |
| `shell-under-app` | med | A shell launched, when it was born, by an app inside a `.app` bundle other than terminals and editors (T1059.004). |
| `download` | med | `curl` writing to a file (`-o`/`--output`, `-O`/`--remote-name`), `wget` with a URL (it saves a file by default, unless `-O` points at `-` or `/dev/null`; `-o` is only the log), or either one that created a file (T1105). |
| `archive-staging` | med or high | `ditto -c`, `zip`, or `tar` in create mode. High if a path it names is in a temporary, Downloads, shared, volume, translocated or hidden location; med otherwise (T1560.001). |
| `odd-location-exec` | high, med or low | A program or its script run from a place a normal install does not run from. Strong places: `/tmp`, `/var/tmp`, `/var/folders`, `/Users/Shared`, `~/Downloads`, `/Volumes`, App Translocation, and a hidden folder below a visible one in a home folder. For a program there: high if unsigned or ad-hoc signed, med if signed without a team ID, low if team-signed; a script there is med. Weak places: a dot-folder directly in home (`~/.cargo`, `~/.local`), a hidden folder inside a project build or tooling folder (`.git`, `node_modules`, `.build`, `.terraform`, `.venv`, `target`, ...), Go's build folder: med if unsigned, else low. Low findings are context only (T1204.002). |
| `unsigned` | med | A non-Apple binary with no code signature at all. A trait of the binary, not a technique, so it cites no MITRE ID. |
| `adhoc` | low | A non-Apple binary that is ad-hoc signed, so it has no developer identity. Common for Homebrew and locally built tools, so it is context only. Also a trait. |
| `orphaned` | low | A process whose parent exited so it now sits under launchd (pid 1), though it was started by something else (not `xpcproxy`): the double fork that detaches a daemon (T1036.009). |
| `recon` | low | `ps` (T1057); `networksetup`, `scutil` (T1016); `airport` (T1016.002); `csrutil`, `spctl` (T1518.001); `whoami`, `id` (T1033); `system_profiler`, `sw_vers`, `sysctl`, `ioreg`, `uname`, `hostname`, `scutil --get` (T1082). Forms that change a setting are not recon. Queued only in a flagged chain or a recon burst; otherwise shown as context in the detail pane (see below). |

## What the queue means

The queue on the Triage tab lists the processes (and the launch items no process owns) the rules flagged. Each row says why, with the evidence from the capture. A flag is a lead to look at, not a verdict: you decide, and mark the process confirmed or benign.

- **Severity (high, med, low)** is how strongly the strongest finding on that row suggests something worth your time. High is things almost no ordinary software does, such as a fake password dialog or a launch agent that runs a shell. Low is weak signals that matter mainly in company. Rows are sorted high first, then by time.
- **Trait findings** (`unsigned`, `adhoc`) describe the binary, not an attack technique, and say so instead of showing a MITRE ID.
- **`in chain`** on a row means the process did nothing alarming itself, or only a low-signal thing, but it descends from a process with a med or high finding. A `whoami` is nothing on its own; under a shell that was fed from a pipe it is probably part of the same intrusion. Look at the parent first. A launch item registered by an app (or by its instigator) puts that app's descendants in a chain only when the item is high.
- **`recon burst`** marks a row queued because it was one of 3 or more different recon tools run under the same parent within 60 seconds (any 60-second window; every tool in it is queued). A burst of one tool, such as `ps` six times from a monitoring app, is not a burst.
- **Context-only** findings are the low-signal ones (`recon`, `adhoc`, low `odd-location-exec`, low `keychain-access`) on processes that are not in a flagged chain or a burst. They would flood the queue (a normal Mac runs `ps` all the time), so they are kept out of it and shown only in that process's detail pane.
- **Launch items.** The detail pane shows the item's type (launch agent, daemon, login item, app, user item), whether the item is a plist or an app, what it runs, and who registered it: the app that registered it if the event names one, otherwise the instigator (the XPC caller that asked for it), otherwise the process that wrote the plist. The finding sits on that process's row. An Apple system process such as `smd` is skipped for that purpose, since it may only be relaying the request for someone else; with no usable process the item is its own row, “persistence: <plist>”, with no process or tree entry. The daemon that reported the event (`backgroundtaskmanagementd`) is shown as the reporter, not the registrant.
- **Routine** is a mark you set on a program (“Treat as routine”) to say you have seen it and it is normal on this machine. It hides every run of that program, in every capture of the session, and the header counts how many queue rows are hidden. A program is identified by its signing ID, team ID and executable path together, so a re-signed or relocated copy counts as a different program and is not hidden. A routine mark never hides a row with a high finding or a persistence finding (marking `cat` routine must not hide the launch agent that `cat` wrote): that row stays, marked “routine program — kept: <reason>”, and the app asks first when marking a program would leave such rows visible. Launch items with no process are never hidden. The mark is reversible from the same button.

## Performance

Targets: an 11,610-event, 28.6 MB capture from drop to the triage screen in under 5 seconds; a 500 MB capture loads without crashing the tab, slower is acceptable. The worker streams the file in 4 MB slices and keeps only the fields the model needs.

Measured on an Apple M5 Max, 48 GB, Node 24, and the in-app browser pane (Chromium) with `dist/index.html` served over HTTP:

| Capture | Where | Result |
|---|---|---|
| a lab capture, 28.6 MB, 11,610 events | browser, from the file input's change event to the triage screen | 0.09 s on first load, 0.3 to 0.5 s on later ones (includes writing the capture record to IndexedDB). Under the 5 s target. |
| a schema v6 sample, 1.5 MB | browser, same measure | about 0.1 s |
| `scratch/big.jsonl`, 516 MB, 208,980 events | browser, same measure | 4.6 s, no crash. Switching from Triage to Tree and back took about 1.2 s and the tree rendered rows; I did not otherwise test interactivity. Tab heap read 69 MB afterwards. |
| `scratch/big.jsonl` | Node: stream lines through `ModelBuilder`, then `analyze` | 1.1 s total (parse 1.0 s, analyze 0.04 s). Peak `heapUsed` 292 MB, peak RSS 587 MB, 232 MB retained after GC. For comparison the 28.6 MB capture alone peaks at 23 MB heap. |

Caveat: `scratch/big.jsonl` is the 28.6 MB capture repeated 18 times with `global_seq_num` offset by `n x 10,000,000` per copy (`node scripts/make-big.mjs [capture.jsonl]`). Every copy repeats the same pids and audit tokens, so the model still sees 4,722 processes, not 18 times as many; the test proves load volume and memory behaviour on very large inputs, not a capture with 500 MB of distinct processes. A real capture with many distinct processes would retain more memory per event. The browser was driven by feeding the file to the page's file input from script, not by a physical drag from Finder. Because the capture fingerprint is taken from the file's head, `big.jsonl` has the same fingerprint as the capture it was made from and replaces it within a session; that is the “a capture that grows keeps its verdicts” behaviour working as designed.

To reproduce: `node scripts/make-big.mjs path/to/capture.jsonl` (writes `scratch/big.jsonl`, 516 MB for that capture, gitignored), load it, then delete it.

## Tests

```
npm test             # builds dist/ first (pretest), then runs the whole suite
npx vitest run test/rules.test.ts   # one file while iterating (needs dist/ only for build.test.ts)
```

A fresh clone runs most of the suite. `test/fixtures/synthetic-lab.jsonl` is a small hand-built capture (eslogger schema 11, an invented user `alice`, invented pids and tokens) that tells the steps of a lab intrusion, plus noise: a download, a script piped into `bash`, a fake password dialog, staging in `/tmp`, an orphaned process, a launch agent written by a shell redirect with its `btm` event, a login item registered by an app in Downloads, a recon burst, a process whose `exec` the capture missed, and a parent that started before the capture. `scripts/make-synthetic-lab.mjs` writes it (`node scripts/make-synthetic-lab.mjs`); a test checks the committed file is exactly what the script produces. The parser, model, rules, session and UI tests run on it.

The tests that check the code against real captures are kept, but they need files that are not in this repo (one is a capture of a private Mac, the others are third-party malware samples): `es-lab.jsonl` and `SpriteTreeSamples/*.json` in the repo's parent directory. When they are missing those tests are skipped and the run prints one note saying so. Set `FIXTURES_DIR` to a directory with the same layout (the `.json` samples are read from `$FIXTURES_DIR/SpriteTreeSamples/`) to run them:

```
FIXTURES_DIR=/path/to/captures npm test
```

`npm run dev` also accepts `?load=<file>` to open a development session named `dev` with a capture from the directory above the repo already loaded. That code is compiled out of the production build, and `test/build.test.ts` checks that it stays out.

## Roadmap

XPC connection edges are planned.

## License

MIT, see [LICENSE](LICENSE).
