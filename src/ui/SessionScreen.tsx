import { useState, type DragEvent } from 'react';
import { ConfirmedTab } from './ConfirmedTab';
import { StoreErrorBanner } from './StoreErrorBanner';
import { TreeView } from './TreeView';
import { TriageView } from './TriageView';
import { useSession, type View } from './session-context';

// Spec §4.2, verbatim.
const CAPTURE_CMD =
  'sudo eslogger fork exec exit create rename unlink setextattr btm_launch_item_add btm_launch_item_remove > capture.jsonl';

const TABS: { id: View; label: string }[] = [
  { id: 'triage', label: 'Triage' },
  { id: 'tree', label: 'Tree' },
  { id: 'confirmed', label: 'Confirmed' },
];

const fmt = (n: number): string => n.toLocaleString('en-US');

function CaptureCommand() {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(CAPTURE_CMD); setCopied(true); setTimeout(() => { setCopied(false); }, 1500); }
    catch { /* clipboard unavailable (e.g. file://): the command is selectable */ }
  };
  return (
    <div className="cmd">
      <p className="muted small">On the Mac you are investigating, run this, stop it with Ctrl-C, then drop capture.jsonl here.</p>
      <div className="row">
        <pre className="grow"><code>{CAPTURE_CMD}</code></pre>
        <button onClick={() => { void copy(); }}>{copied ? 'Copied' : 'Copy'}</button>
      </div>
    </div>
  );
}

function DropZone() {
  const c = useSession();
  const [over, setOver] = useState(false);
  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setOver(false);
    void c.loadFiles([...e.dataTransfer.files]);
  };
  const p = c.progress;
  const reading = p !== null && p.bytes < p.total;

  return (
    <section
      className={`drop${over ? ' over' : ''}`}
      onDragOver={e => { e.preventDefault(); setOver(true); }}
      onDragLeave={() => { setOver(false); }}
      onDrop={onDrop}
    >
      <p>Drop capture files here, or{' '}
        <label className="filebtn">Choose capture files
          <input type="file" multiple onChange={e => { void c.loadFiles([...(e.target.files ?? [])]); e.target.value = ''; }} />
        </label>
      </p>
      {p && (
        <div className="row" aria-live="polite">
          <progress className="grow" value={p.bytes} max={p.total} aria-label={`Reading ${p.fileName}`} />
          <span className="muted small">{reading ? `Reading ${p.fileName} · ${Math.round((p.bytes / p.total) * 100)}%` : `Analysing… ${p.fileName}`}</span>
        </div>
      )}
      {c.loadError && <p role="alert" className="error">{c.loadError}</p>}
      <CaptureCommand />
      {c.capRecs.length > 0 && (
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
    </section>
  );
}

function Counts() {
  const c = useSession();
  if (!c.capture || !c.triage) return null;
  const confirmed = [...c.verdicts.values()].filter(v => v.status === 'confirmed').length;
  return (
    <div className="counts" role="group" aria-label="Capture counts">
      <span>{fmt(c.capture.model.stats.events)} events</span>
      <span>{fmt(c.capture.model.processes.size)} processes</span>
      <span>{fmt(c.triage.queue.length)} flagged</span>
      <span>{fmt(confirmed)} confirmed</span>
      <span>{fmt(c.triage.hiddenCount)} routine hidden</span>
    </div>
  );
}

export function SessionScreen() {
  const c = useSession();
  const session = c.session!;
  const activeRec = c.capRecs.find(r => r.fingerprint === c.active);

  return (
    <main className="shell">
      <StoreErrorBanner />
      <header className="bar">
        <div className="row">
          <button onClick={c.closeSession}>← Sessions</button>
          <h1 className="grow">{session.name}</h1>
          {c.capRecs.length > 0 && (
            <label className="inline">Capture{' '}
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
        </div>
        <Counts />
        <div role="tablist" className="tabs">
          {TABS.map(t => (
            <button key={t.id} role="tab" aria-selected={c.view === t.id} className={c.view === t.id ? 'on' : ''}
              onClick={() => { c.setView(t.id); }}>{t.label}</button>
          ))}
        </div>
      </header>

      <DropZone />

      <section role="tabpanel" className="panel">
        {c.view === 'confirmed' ? <ConfirmedTab /> : !c.capture ? (
          <p className="muted">
            {activeRec ? `${activeRec.fileName} is not loaded. Drop its file above to continue.` : 'Drop a capture file above to begin.'}
          </p>
        ) : c.view === 'triage' ? (
          <TriageView />
        ) : (
          <TreeView />
        )}
      </section>
    </main>
  );
}
