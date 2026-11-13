import { useState } from 'react';
import { exportSession } from '../session/export';
import { useSession } from './session-context';

const slug = (s: string): string => s.replace(/[^\w.-]+/g, '-').replace(/^-+|-+$/g, '') || 'session';

/** File input that imports a session export as a new session. */
export function ImportSession() {
  const c = useSession();
  const [done, setDone] = useState<{ id: string; name: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const onFile = async (file: File | undefined) => {
    if (!file) return;
    setDone(null); setError(null);
    try { setDone(await c.importSessionFile(file)); }
    catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };

  return (
    <div>
      <label className="filebtn" data-own-drop>Import session <input type="file" accept="application/json,.json"
        onChange={e => { void onFile(e.target.files?.[0]); e.target.value = ''; }} /></label>
      {done && (
        <p role="status">Imported as “{done.name}”. <button onClick={() => { void c.openSession(done.id); }}>Open</button></p>
      )}
      {error && <p role="alert" className="error">{error}</p>}
    </div>
  );
}

export function ConfirmedTab() {
  const c = useSession();
  const [error, setError] = useState<string | null>(null);
  const session = c.session!;
  const { includeEnv, redactArgs } = c.exportOpts;
  const fileName = (fp: string): string => c.capRecs.find(r => r.fingerprint === fp)?.fileName ?? 'unknown capture';
  const confirmed = c.allVerdicts
    .filter(v => v.status === 'confirmed')
    .sort((a, b) => fileName(a.fingerprint).localeCompare(fileName(b.fingerprint)) || a.snapshot.name.localeCompare(b.snapshot.name));

  /** exportSession adds process details only for loaded captures; a launch item (key `i:…`) has no process, so none to add. */
  const isLaunchItem = (key: string): boolean => key.startsWith('i:');
  const leftOut = confirmed.filter(v => !isLaunchItem(v.procKey) && !c.captures.has(v.fingerprint)).length;
  const hasLaunchItems = confirmed.some(v => isLaunchItem(v.procKey));

  const doExport = async () => {
    setError(null);
    try {
      const data = await exportSession(c.store, session.id, { includeEnv, redactArgs }, c.captures);
      const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `${slug(session.name)}.gameleira-session.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => { URL.revokeObjectURL(url); }, 1000);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="confirmed-tab">
      <section aria-labelledby="confirmed-h">
        <h2 id="confirmed-h">Confirmed in this session <span className="muted num">{confirmed.length}</span></h2>
        {confirmed.length === 0 ? (
          <p className="empty">Nothing confirmed yet in this session. Press <kbd>c</kbd> on a row in Triage to confirm it.</p>
        ) : (
          <ul className="list" aria-label="Confirmed processes">
            {confirmed.map(v => (
              <li key={`${v.fingerprint}|${v.procKey}`} className="confirmed">
                <div className="row">
                  {v.snapshot.severity && <span className={`badge sev-${v.snapshot.severity}`}>{v.snapshot.severity}</span>}
                  <strong>{v.snapshot.name}</strong>
                  <span className="chip">{fileName(v.fingerprint)}</span>
                </div>
                {v.snapshot.path && <code className="small">{[v.snapshot.path, ...(v.snapshot.args?.slice(1) ?? [])].join(' ')}</code>}
                {v.snapshot.ruleIds.length > 0 && <div className="muted small">rules: {v.snapshot.ruleIds.join(', ')}</div>}
                {v.note && <p className="note">{v.note}</p>}
              </li>
            ))}
          </ul>
        )}
      </section>

      <aside className="export" aria-labelledby="export-h">
        <h2 id="export-h">Export</h2>
        <div className="checks">
          <label className="inline"><input type="checkbox" checked={redactArgs} onChange={e => { c.setExportOpts({ redactArgs: e.target.checked }); }} /> Redact command-line arguments</label>
          <label className="inline"><input type="checkbox" checked={includeEnv} onChange={e => { c.setExportOpts({ includeEnv: e.target.checked }); }} /> Include environment variables</label>
        </div>
        <div><button className="primary" onClick={() => { void doExport(); }}>Export session</button></div>
        <p className="muted small">
          The export includes the full command line of every verdict, and those can contain secrets such as passwords
          (for example <code>dscl . -authonly user password</code>). Tick “Redact command-line arguments” to replace every argument
          after the program name with [redacted]. Process details are exported for captures that are loaded now.
          Environment variables can hold secrets too; leave them out unless needed.
        </p>
        {leftOut > 0 && (
          <p className="warn small">
            Details for {leftOut} confirmed {leftOut === 1 ? 'process is' : 'processes are'} left out because {leftOut === 1 ? 'its capture isn’t' : 'their captures aren’t'} loaded; re-add {leftOut === 1 ? 'it' : 'them'} to include.
          </p>
        )}
        {hasLaunchItems && <p className="muted small">Launch items are exported from their snapshot.</p>}
        {error && <p role="alert" className="error">{error}</p>}
        <h2 className="import-h">Import</h2>
        <ImportSession />
      </aside>
    </div>
  );
}
