# eslogger viewer

A single-file web app for triaging Apple `eslogger` captures. You drop a JSONL capture onto it; it rebuilds the process tree, flags suspicious processes with plain-language, MITRE-tagged explanations, and gives you a queue to confirm or dismiss them. Verdicts are kept per session (one investigation, usually one Mac) in the browser's IndexedDB, so they survive closing the tab. Everything runs locally: the page ships with a Content-Security-Policy of `connect-src 'none'`, so it cannot send a capture anywhere.

## Opening it

Build once:

```
npm install
npm run build        # writes dist/index.html, a single self-contained file
```

Then open `dist/index.html` from Finder (double-click, or Open With a browser). No server is needed.

If your browser does not keep sessions when the page is opened from disk (they are gone after you quit and reopen it), serve the same file on localhost instead:

```
npm run serve        # vite preview, http://localhost:4173
```

Sessions are stored per origin, so a session made at `file://` is not visible at `http://localhost:4173` and the other way round. Use one and stick to it. Parsed captures are not stored; after reopening a session, re-drop the capture file and your verdicts reattach to it.

## Capturing

Run this on the Mac you are investigating, stop it with Ctrl-C, then drop `capture.jsonl` into a session:

```
sudo eslogger fork exec exit create rename unlink setextattr btm_launch_item_add btm_launch_item_remove > capture.jsonl
```

- `exit` gives process lifetimes.
- `setextattr` records extended-attribute writes on files (shown under "What it did" in the detail pane). No rule uses them yet; a future rule could check whether a downloaded file got its quarantine flag.
- `btm_*` captures persistence registrations (login items, launch agents and daemons).
- `write` is left out on purpose because it is very noisy; the tool still handles it if it is present.

## Tests

```
npm test             # builds dist/ first (pretest), then runs the whole suite
npx vitest run test/rules.test.ts   # one file while iterating (needs dist/ only for build.test.ts)
```

The parser, model and rule tests run against real captures that live outside this repo, in the parent directory: `../es-lab.jsonl` and `../SpriteTreeSamples/*.json`. Set `FIXTURES_DIR` to point at a different directory with the same layout (the `.json` samples are read from `$FIXTURES_DIR/SpriteTreeSamples/`):

```
FIXTURES_DIR=/path/to/captures npm test
```

`npm run dev` also accepts `?load=es-lab.jsonl` to open a development session named `dev` with a fixture already loaded. That code is compiled out of the production build, and `test/build.test.ts` checks that it stays out.

## Rules

The rules are data: each has an id, a severity, a plain explanation and MITRE ATT&CK IDs. The full list, with the exact matching logic, is in [`src/rules/rules.ts`](src/rules/rules.ts). Summary:

| id | Severity | What it catches |
|---|---|---|
| `fake-prompt` | high | `osascript` whose arguments contain `display dialog`, `password` or `hidden answer`: a fake system password prompt (T1056.002). |
| `dscl-authonly` | high | `dscl ... -authonly`: checking whether a (possibly phished) password is correct (T1110, T1056). |
| `persistence-item` | high or med | A launch item registered with the background task manager (`btm_launch_item_add`). High if it launches a shell or interpreter, an unsigned program, or something in a user-writable or temporary path; otherwise med (T1543.001, T1543.004). |
| `persistence-plist` | high | A launch agent/daemon plist written into `~/Library/LaunchAgents`, `/Library/LaunchAgents` or `/Library/LaunchDaemons` that no registration event accounts for (T1543.001, T1543.004). |
| `launchctl-load` | high | `launchctl load`, `bootstrap` or `submit`: starting a launch job right now (T1569.001). |
| `quarantine-strip` | high | `xattr -c`, or `xattr -d com.apple.quarantine`: removing the flag that makes Gatekeeper check a download (T1553.001). |
| `payload-decode` | med | `openssl enc -d` or `base64 -d`: unpacking a hidden payload (T1140). |
| `shell-from-pipe` | med | A shell that was started with no arguments, whose stdin was a pipe, and that ran no script file: the `curl ... \| bash` pattern, with no script on disk to inspect (T1059.004). Needs `eslogger` version 11 or later. |
| `shell-under-app` | med | A shell launched by an app inside a `.app` bundle, other than terminals and editors (T1059.004). |
| `download` | med | `curl` or `wget` writing to a file (`-o`, `-O`, `--output`) or creating a file (T1105). |
| `archive-staging` | med or high | `ditto -c`, `zip` or `tar c`. High if a source path is in a temporary or user-writable location (T1560.001). |
| `odd-location-exec` | high, med or low | A program or its script run from `/tmp`, `/var/folders`, `/Users/Shared`, `~/Downloads`, `/Volumes`, `AppTranslocation` or a hidden folder below a visible one. High if unsigned or ad-hoc signed, med if signed without a team ID, low if team-signed. Developer tooling locations (`~/.cargo`, `.git`, `.venv`, `node_modules`, ...) are only ever low or med (T1204.002). |
| `unsigned` | med | A non-Apple binary with no code signature at all (T1553.002). |
| `adhoc` | low | A non-Apple binary that is ad-hoc signed, so it has no developer identity. Common for Homebrew and locally built tools, so it is context only (T1553.002). |
| `orphaned` | low | A process whose parent exited, so it now sits under launchd (pid 1) (T1564). |
| `recon` | low | `system_profiler`, `sw_vers`, `whoami`, `id`, `hostname`, `sysctl`, `ioreg`, `uname`, `ps`, `airport`, `scutil`, `networksetup`, `security`, `csrutil`, `spctl` (T1082, T1033). Queued only when it is in a flagged chain or part of a burst of 3 or more different recon tools under the same parent within 60 s; otherwise shown as context in the detail pane (see below). |

## What the queue means

The queue on the Triage tab lists the processes (and a few standalone persistence items) the rules flagged. Each row says why, with the evidence from the capture. A flag is a lead to look at, not a verdict: you decide, and mark the process confirmed or benign.

- **Severity (high, med, low)** is how strongly the strongest finding on that row suggests something worth your time. High is things almost no ordinary software does, such as a fake password dialog or a launch agent that runs a shell. Low is weak signals that matter mainly in company. Rows are sorted high first, then by time.
- **Part of a flagged chain** (`in chain` on a row) means the process did nothing alarming itself, or only a low-signal thing, but it descends from a process with a med or high finding. A `whoami` is nothing on its own; under a shell that was fed from a pipe it is probably part of the same intrusion. Look at the parent first.
- **Context-only** findings are the low-signal ones (`recon`, `adhoc`, and low `odd-location-exec`) on processes that are not in a flagged chain. They would flood the queue (a normal Mac runs `ps` all the time), so they are kept out of it and shown only in that process's detail pane. A burst of three or more different recon tools under one parent within a minute is the exception and is queued.
- **Routine** is a mark you set on a program ("Treat as routine") to say you have seen it and it is normal on this machine. It hides every run of that program, in every capture of the session, and the header counts how many queue rows are hidden. A program is identified by its signing ID, team ID and executable path together, so a re-signed or relocated copy counts as a different program and is not hidden. Persistence items (launch items with no creating process) are never hidden by routine. It is reversible from the same button.

## Performance

Targets from the design spec: `es-lab.jsonl` (28.6 MB, 11,610 events) from drop to the triage screen in under 5 seconds; a 500 MB capture loads without crashing the tab, slower is acceptable. The worker streams the file in 4 MB slices and keeps only the fields the model needs.

Measured on an Apple M5 Max, 48 GB, Node 24, and the in-app browser pane (Chromium) with `dist/index.html` served over HTTP:

| Capture | Where | Result |
|---|---|---|
| `es-lab.jsonl`, 28.6 MB | browser, from the file input's change event to the triage screen | 0.09 s on first load, 0.3 to 0.5 s on later ones (includes writing the capture record to IndexedDB). Under the 5 s target. |
| `atomic_stealer.json`, 1.5 MB | browser, same measure | about 0.1 s |
| `scratch/big.jsonl`, 516 MB, 208,980 events | browser, same measure | 4.6 s, no crash. Switching from Triage to Tree and back took about 1.2 s and the tree rendered rows; I did not otherwise test interactivity. Tab heap read 69 MB afterwards. |
| `scratch/big.jsonl` | Node: stream lines through `ModelBuilder`, then `analyze` | 1.1 s total (parse 1.0 s, analyze 0.04 s). Peak `heapUsed` 292 MB, peak RSS 587 MB, 232 MB retained after GC. For comparison `es-lab.jsonl` alone peaks at 23 MB heap. |

Caveat: `scratch/big.jsonl` is `es-lab.jsonl` repeated 18 times with `global_seq_num` offset by `n x 10,000,000` per copy (`node scripts/make-big.mjs`). Every copy repeats the same pids and audit tokens, so the model still sees 4,722 processes, not 18 times as many; the test proves load volume and memory behaviour on very large inputs, not a capture with 500 MB of distinct processes. A real capture with many distinct processes would retain more memory per event. The browser was driven by feeding the file to the page's file input from script, not by a physical drag from Finder. Because the capture fingerprint is taken from the file's head, `big.jsonl` has the same fingerprint as `es-lab.jsonl` and replaces it within a session; that is the "a capture that grows keeps its verdicts" behaviour working as designed.

To reproduce: `node scripts/make-big.mjs` (writes `scratch/big.jsonl`, 516 MB, gitignored), load it, then delete it.
