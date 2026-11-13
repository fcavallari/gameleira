import { useState, type FormEvent } from 'react';
import { GameleiraFigure, RootSwatch, Wordmark } from './Brand';
import { ImportSession } from './ConfirmedTab';
import { StoreErrorBanner } from './StoreErrorBanner';
import { useSession } from './session-context';

const when = (iso: string): string => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
};

export function StartScreen() {
  const c = useSession();
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState('');
  const [renaming, setRenaming] = useState<string | null>(null);
  const [newName, setNewName] = useState('');

  const create = async (e: FormEvent) => {
    e.preventDefault();
    const n = name.trim();
    if (!n) return;
    const s = await c.createSession(n);
    if (!s) return;   // the banner explains; keep the form open
    setName(''); setCreating(false);
    await c.openSession(s.id);
  };
  const rename = async (e: FormEvent, id: string) => {
    e.preventDefault();
    const n = newName.trim();
    setRenaming(null);
    if (n) await c.renameSession(id, n);
  };
  const remove = async (id: string, sessionName: string) => {
    if (window.confirm(`Delete session “${sessionName}”, with its verdicts and routine marks? This cannot be undone.`)) {
      await c.deleteSession(id);
    }
  };

  return (
    <div className="app">
      <header className="topbar">
        <Wordmark />
        <span className="spacer" />
        {c.persisted !== null && <span className="meta">Storage: {c.persisted ? 'persistent' : 'best-effort'}</span>}
      </header>
      <main className="sheet">
        <StoreErrorBanner />
        <div className="start">
          <div className="start-main">
            <section className="start-sec" aria-labelledby="sessions-h">
              <div className="row">
                <h1 id="sessions-h">Sessions</h1>
                {!creating && <button className="primary" onClick={() => { setCreating(true); }}>New session</button>}
              </div>
              <div className="start-head">
                <p className="muted">One session per investigation, usually one Mac. Verdicts and notes stay in this browser; nothing is uploaded.</p>
              </div>
              {creating && (
                <form className="new-session" onSubmit={e => { void create(e); }}>
                  <label>Session name <input autoFocus value={name} placeholder="e.g. finance MacBook, 12 Nov" onChange={e => { setName(e.target.value); }} /></label>
                  <button type="submit" className="primary">Create</button>
                  <button type="button" className="ghost" onClick={() => { setCreating(false); setName(''); }}>Cancel</button>
                </form>
              )}
              {c.sessionsLoaded && c.sessions.length === 0 && !creating && (
                <p className="empty">No sessions yet. Create one for each investigation.</p>
              )}
              <ul className="sessions">
                {c.sessions.map(s => (
                  <li key={s.id}>
                    {renaming === s.id ? (
                      <form className="new-session" onSubmit={e => { void rename(e, s.id); }}>
                        <label>New name <input autoFocus value={newName} onChange={e => { setNewName(e.target.value); }} /></label>
                        <button type="submit" className="primary">Save</button>
                        <button type="button" className="ghost" onClick={() => { setRenaming(null); }}>Cancel</button>
                      </form>
                    ) : (
                      <>
                        <button className="link sname truncate" onClick={() => { void c.openSession(s.id); }}>{s.name}</button>
                        <span className="muted num">{c.captureCounts.get(s.id) ?? 0} {(c.captureCounts.get(s.id) ?? 0) === 1 ? 'capture' : 'captures'}</span>
                        <span className="muted small when">updated {when(s.updated)}</span>
                        <span className="acts">
                          <button className="ghost" aria-label={`Rename ${s.name}`} onClick={() => { setRenaming(s.id); setNewName(s.name); }}>Rename</button>
                          <button className="ghost danger" aria-label={`Delete ${s.name}`} onClick={() => { void remove(s.id, s.name); }}>Delete</button>
                        </span>
                      </>
                    )}
                  </li>
                ))}
              </ul>
            </section>

            <section className="start-sec import" aria-labelledby="import-h">
              <h2 id="import-h">Import</h2>
              <p className="muted small">A session exported from the Confirmed tab, on this machine or another.</p>
              <ImportSession />
            </section>
          </div>

          <aside className="start-aside" aria-labelledby="why-h">
            <GameleiraFigure />
            <h2 id="why-h">Every root, not just the parent PID</h2>
            <p>The gameleira is a Brazilian fig whose aerial roots drop from its branches, reach the ground and become new trunks.
              A macOS process has several roots too. Gameleira follows all three:</p>
            <ul className="legend">
              <li><RootSwatch kind="original" /><span><strong>Original parent</strong> <span className="muted">who forked it</span></span></li>
              <li><RootSwatch kind="current" /><span><strong>Current parent</strong> <span className="muted">who it sits under now; an orphan sits under launchd</span></span></li>
              <li><RootSwatch kind="responsible" /><span><strong>Responsible</strong> <span className="muted">the app that caused it</span></span></li>
            </ul>
          </aside>
        </div>
      </main>
    </div>
  );
}
