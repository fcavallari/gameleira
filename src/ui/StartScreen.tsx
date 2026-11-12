import { useState, type FormEvent } from 'react';
import { ImportSession } from './ConfirmedTab';
import { useSession } from './session-context';

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
    <main className="shell">
      <h1>eslogger viewer</h1>
      <p className="muted">Triage Apple eslogger captures. Everything stays in this browser; nothing is uploaded.</p>

      <section>
        <div className="row">
          <h2>Sessions</h2>
          {!creating && <button className="primary" onClick={() => { setCreating(true); }}>New session</button>}
        </div>
        {creating && (
          <form className="row" onSubmit={e => { void create(e); }}>
            <label>Session name <input autoFocus value={name} onChange={e => { setName(e.target.value); }} /></label>
            <button type="submit" className="primary">Create</button>
            <button type="button" onClick={() => { setCreating(false); setName(''); }}>Cancel</button>
          </form>
        )}
        {c.sessions.length === 0 && !creating && <p className="muted">No sessions yet. Create one for each investigation.</p>}
        <ul className="list">
          {c.sessions.map(s => (
            <li key={s.id} className="row">
              {renaming === s.id ? (
                <form className="row grow" onSubmit={e => { void rename(e, s.id); }}>
                  <label>New name <input autoFocus value={newName} onChange={e => { setNewName(e.target.value); }} /></label>
                  <button type="submit">Save</button>
                  <button type="button" onClick={() => { setRenaming(null); }}>Cancel</button>
                </form>
              ) : (
                <>
                  <button className="link grow" onClick={() => { void c.openSession(s.id); }}>{s.name}</button>
                  <span className="muted">{c.captureCounts.get(s.id) ?? 0} captures</span>
                  <span className="muted">updated {new Date(s.updated).toLocaleString()}</span>
                  <button aria-label={`Rename ${s.name}`} onClick={() => { setRenaming(s.id); setNewName(s.name); }}>Rename</button>
                  <button aria-label={`Delete ${s.name}`} className="danger" onClick={() => { void remove(s.id, s.name); }}>Delete</button>
                </>
              )}
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2>Import</h2>
        <ImportSession />
      </section>

      <footer className="muted">
        {c.persisted !== null && <span>Storage: {c.persisted ? 'persistent' : 'best-effort'}</span>}
      </footer>
    </main>
  );
}
