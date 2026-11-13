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
      <label>Import session <input type="file" accept="application/json,.json"
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
  const [includeEnv, setIncludeEnv] = useState(false);
  const [redactArgs, setRedactArgs] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const session = c.session!;
  const fileName = (fp: string): string => c.capRecs.find(r => r.fingerprint === fp)?.fileName ?? 'unknown capture';
  const confirmed = c.allVerdicts
    .filter(v => v.status === 'confirmed')
    .sort((a, b) => fileName(a.fingerprint).localeCompare(fileName(b.fingerprint)) || a.snapshot.name.localeCompare(b.snapshot.name));

  const doExport = async () => {
    setError(null);
    try {
      const data = await exportSession(c.store, session.id, { includeEnv, redactArgs }, c.captures);
      const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `${slug(session.name)}.eslogger-session.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => { URL.revokeObjectURL(url); }, 1000);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div>
      <div className="row">
        <button className="primary" onClick={() => { void doExport(); }}>Export session</button>
        <label className="inline"><input type="checkbox" checked={includeEnv} onChange={e => { setIncludeEnv(e.target.checked); }} /> Include environment variables</label>
        <label className="inline"><input type="checkbox" checked={redactArgs} onChange={e => { setRedactArgs(e.target.checked); }} /> Redact command-line arguments</label>
      </div>
      <p className="muted small">
        The export includes the full command line of every verdict, and those can contain secrets such as passwords
        (for example <code>dscl . -authonly user password</code>). Tick “Redact command-line arguments” to replace every argument
        after the program name with [redacted]. Process details are exported for captures that are loaded now.
        Environment variables can hold secrets too; leave them out unless needed.
      </p>
      {error && <p role="alert" className="error">{error}</p>}

      {confirmed.length === 0 ? (
        <p className="muted">Nothing confirmed yet in this session.</p>
      ) : (
        <ul className="list" aria-label="Confirmed processes">
          {confirmed.map(v => (
            <li key={`${v.fingerprint}|${v.procKey}`} className="confirmed">
              <div className="row">
                <strong>{v.snapshot.name}</strong>
                {v.snapshot.severity && <span className={`badge sev-${v.snapshot.severity}`}>{v.snapshot.severity}</span>}
                <span className="chip">{fileName(v.fingerprint)}</span>
              </div>
              {v.snapshot.path && <code className="small">{[v.snapshot.path, ...(v.snapshot.args?.slice(1) ?? [])].join(' ')}</code>}
              {v.snapshot.ruleIds.length > 0 && <div className="muted small">rules: {v.snapshot.ruleIds.join(', ')}</div>}
              {v.note && <p className="note">{v.note}</p>}
            </li>
          ))}
        </ul>
      )}

      <h3>Import</h3>
      <ImportSession />
    </div>
  );
}
