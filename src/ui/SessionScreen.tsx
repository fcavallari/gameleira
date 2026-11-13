import { useState, type DragEvent } from 'react';
import { Mark, Wordmark } from './Brand';
import { ConfirmedTab } from './ConfirmedTab';
import { StoreErrorBanner } from './StoreErrorBanner';
import { TreeView } from './TreeView';
import { TriageView } from './TriageView';
import { useSession, type View } from './session-context';
import { captureInfo } from './triage-model';

// The command the capture screen tells the user to run: the events the rules and the tree need.
const CAPTURE_CMD =
  'sudo eslogger fork exec exit create rename unlink setextattr btm_launch_item_add btm_launch_item_remove > capture.jsonl';

const TABS: { id: View; label: string }[] = [
  { id: 'triage', label: 'Triage' },
  { id: 'tree', label: 'Tree' },
  { id: 'confirmed', label: 'Confirmed' },
];

const fmt = (n: number): string => n.toLocaleString('en-US');

export function CaptureCommand({ hint = 'Run this, stop it with Ctrl-C, then drop capture.jsonl here.' }: { hint?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(CAPTURE_CMD); setCopied(true); setTimeout(() => { setCopied(false); }, 1500); }
    catch { /* clipboard unavailable (e.g. file://): the command is selectable */ }
  };
  return (
    <div className="cmd">
      <h2>Capture on the Mac you are investigating</h2>
      <p className="muted">{hint}</p>
      <pre><code>{CAPTURE_CMD}</code></pre>
      <button onClick={() => { void copy(); }}>{copied ? 'Copied' : 'Copy'}</button>
      <ul>
        <li><code>fork</code>, <code>exec</code> and <code>exit</code> build the tree and its lifetimes.</li>
        <li><code>create</code>, <code>rename</code>, <code>unlink</code> and <code>setextattr</code> show what each process wrote.</li>
        <li><code>btm_*</code> records login items, launch agents and daemons.</li>
      </ul>
    </div>
  );
}

function FilePicker({ label, primary }: { label: string; primary?: boolean }) {
  const c = useSession();
  return (
    <label className={`filebtn${primary ? ' primary' : ''}`}>{label}
      <input type="file" multiple onChange={e => { void c.loadFiles([...(e.target.files ?? [])]); e.target.value = ''; }} />
    </label>
  );
}

/** Progress, load errors, and captures that must be dropped again: shown wherever files are added. */
function LoadStatus({ withList }: { withList: boolean }) {
  const c = useSession();
  const p = c.progress;
  const reading = p !== null && p.bytes < p.total;
  const missing = c.capRecs.filter(r => !c.captures.has(r.fingerprint));
  return (
    <>
      {p && (
        <div className="loading" aria-live="polite">
          <progress className="grow" value={p.bytes} max={p.total} aria-label={`Reading ${p.fileName}`} />
          <span className="muted small">{reading ? `Reading ${p.fileName} · ${Math.round((p.bytes / p.total) * 100)}%` : `Analysing… ${p.fileName}`}</span>
        </div>
      )}
      {c.loadError && <p role="alert" className="error">{c.loadError}</p>}
      {withList && c.capRecs.length > 0 && (
        <ul className="list" aria-label="Captures">
          {c.capRecs.map(r => (
            <li key={r.fingerprint} className={r.fingerprint === c.active ? 'active' : ''}>
              {c.captures.has(r.fingerprint)
                ? <span>{r.fileName} · {fmt(r.events)} events · {fmt(r.processes)} processes · {fmt(r.flagged)} flagged</span>
                : <span className="warn">Re-add {r.fileName} to continue</span>}
            </li>
          ))}
        </ul>
      )}
      {!withList && missing.length > 0 && (
        <ul className="reload" aria-label="Captures to add again">
          {missing.map(r => <li key={r.fingerprint} className="warn">Re-add {r.fileName} to continue</li>)}
        </ul>
      )}
    </>
  );
}

/** The first thing a session shows until a capture is loaded: where to drop it, and how to make one. */
function DropZone({ over }: { over: boolean }) {
  const c = useSession();
  const activeRec = c.capRecs.find(r => r.fingerprint === c.active);
  return (
    <section className="drop" aria-label="Add a capture">
      <div>
        <div className={`drop-target${over ? ' over' : ''}`}>
          <Mark size={44} />
          <div>
            <p className="big">{activeRec ? `${activeRec.fileName} is not loaded. Drop its file to continue.` : 'Drop a capture file to begin'}</p>
            <p className="muted">eslogger JSONL, any size. It is read here and never leaves this browser.</p>
          </div>
          <FilePicker label="Choose capture files" primary />
        </div>
        <LoadStatus withList />
      </div>
      <CaptureCommand />
    </section>
  );
}

function Counts() {
  const c = useSession();
  if (!c.capture || !c.triage) return null;
  const confirmed = [...c.verdicts.values()].filter(v => v.status === 'confirmed').length;
  return (
    <div className="counts" role="group" aria-label="Capture counts">
      <span className="lead">{fmt(c.triage.queue.length)} flagged</span>
      <span className="lead">{fmt(confirmed)} confirmed</span>
      <span>{fmt(c.triage.hiddenCount)} routine hidden</span>
      <span>{fmt(c.capture.model.stats.events)} events</span>
      <span>{fmt(c.capture.model.processes.size)} processes</span>
    </div>
  );
}

/** Lines that could not be read, event types that are not modelled and the schema version: counted, never hidden. */
function CaptureInfo() {
  const c = useSession();
  if (!c.capture) return null;
  const { line, older } = captureInfo(c.capture.model.stats);
  if (line === null) return null;
  return (
    <p className="capture-info muted small" aria-label="Capture details">
      {line}
      {older && <> · <span className="warn">older eslogger format: some checks (e.g. piped shells) may not apply</span></>}
    </p>
  );
}

export function SessionScreen() {
  const c = useSession();
  const session = c.session!;
  const [over, setOver] = useState(false);
  const bigDrop = !c.capture && c.view !== 'confirmed';

  // Only files count, and a control that takes its own drop (Import session) keeps it.
  const ours = (e: DragEvent): boolean =>
    e.dataTransfer.types.includes('Files') && !(e.target as Element).closest('[data-own-drop]');
  const onOver = (e: DragEvent) => {
    if (!ours(e)) return;
    e.preventDefault();
    setOver(true);
  };
  const onDrop = (e: DragEvent) => {
    setOver(false);
    if (!ours(e)) return;
    e.preventDefault();
    void c.loadFiles([...e.dataTransfer.files]);
  };
  const onLeave = (e: DragEvent) => {
    if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setOver(false);
  };

  return (
    <div className="app" onDragOver={onOver} onDragLeave={onLeave} onDrop={onDrop}>
      <header className="topbar">
        <nav className="crumb" aria-label="Breadcrumb">
          <Wordmark />
          <span className="crumb-sep" aria-hidden="true">/</span>
          <button className="link crumb-link" onClick={c.closeSession}>Sessions</button>
        </nav>
        <span className="spacer" />
        <span className="meta">Everything stays in this browser</span>
      </header>
      <main className={`sheet${over && !bigDrop ? ' over' : ''}`}>
        <StoreErrorBanner />
        <div className="title-row">
          <h1>{session.name}</h1>
          {c.capRecs.length > 0 && (
            <label className="inline muted small">Capture{' '}
              <select value={c.active ?? ''} onChange={e => { c.setActive(e.target.value); }}>
                {c.active === null && <option value="" disabled>Select a capture</option>}
                {c.capRecs.map(r => (
                  <option key={r.fingerprint} value={r.fingerprint}>
                    {c.captures.has(r.fingerprint) ? r.fileName : `${r.fileName} (not loaded)`}
                  </option>
                ))}
              </select>
            </label>
          )}
          {!bigDrop && <FilePicker label="Add capture files" />}
        </div>
        <Counts />
        <CaptureInfo />
        {!bigDrop && <LoadStatus withList={false} />}

        <div role="tablist" className="tabs">
          {TABS.map(t => (
            <button key={t.id} role="tab" aria-selected={c.view === t.id} className={c.view === t.id ? 'on' : ''}
              onClick={() => { c.setView(t.id); }}>{t.label}</button>
          ))}
        </div>

        <section role="tabpanel" className="tabpanel">
          {c.view === 'confirmed' ? <ConfirmedTab /> : bigDrop ? <DropZone over={over} /> : c.view === 'triage' ? <TriageView /> : <TreeView />}
        </section>
      </main>
    </div>
  );
}
