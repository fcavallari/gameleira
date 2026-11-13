import { useState, type FormEvent } from 'react';
import { diffExport, type ExportDiff } from '../session/export';
import { findSavedCopy, folderSupported, permitted, type SavedCopy } from '../session/folder';
import type { Session } from '../session/store';
import { Canopy, RootField, TRUNKS, Wordmark } from './Brand';
import { ImportSession } from './ConfirmedTab';
import { CaptureCommand } from './SessionScreen';
import { StoreErrorBanner } from './StoreErrorBanner';
import { useSession } from './session-context';

const when = (iso: string): string => {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
};

/**
 * The home page. A gameleira runs through it: the crown beside the introduction, one limb across the sheet, a root from
 * the limb's end down the session list (each session is a node on it), and on the right the roots that reached the
 * ground as the three trunks Gameleira follows. The drawing stays behind and beside the controls, never under them.
 */
export function StartScreen() {
  const c = useSession();
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState('');
  const [renaming, setRenaming] = useState<string | null>(null);
  const [newName, setNewName] = useState('');
  /** The session being looked up in the save folder before it opens. */
  const [checking, setChecking] = useState<string | null>(null);
  /** A saved copy that differs from what this browser holds, offered for reimport in its session's row. */
  const [offer, setOffer] = useState<{ id: string; folder: string; copy: SavedCopy; diff: ExportDiff } | null>(null);
  const [offerError, setOfferError] = useState<string | null>(null);

  /**
   * Opens a session, first looking in the folder Save session writes into for a saved copy of it. When one turns up
   * and it differs from what this browser holds, the session's row asks whether to reimport it instead of opening.
   * A folder that cannot be read (access refused, folder gone) is passed over: the session opens as it is.
   */
  const open = async (s: Session) => {
    const dir = c.saveFolder;
    if (dir && folderSupported()) {
      setChecking(s.id);
      try {
        // Asked first, while the click still counts: the browser forgets the grant after a restart.
        if (await permitted(dir, 'read', true)) {
          const copy = await findSavedCopy(dir, s);
          if (copy) {
            const [caps, vs, rs] = await Promise.all([c.store.listCaptures(s.id), c.store.listVerdicts(s.id), c.store.listRoutine(s.id)]);
            const diff = diffExport(copy.data, caps, vs, rs);
            if (!diff.same) {
              setOfferError(null);
              setOffer({ id: s.id, folder: dir.name, copy, diff });
              return;
            }
          }
        }
      } catch { /* see above */ } finally { setChecking(null); }
    }
    await c.openSession(s.id);
  };
  const reimport = async (id: string, copy: SavedCopy) => {
    setOfferError(null);
    try { await c.reimportSession(id, copy.data); } catch (e) {
      setOfferError(`Could not reimport ${copy.fileName}: ${e instanceof Error ? e.message : String(e)}`);
      return;
    }
    setOffer(null);
    await c.openSession(id);
  };

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
  const count = (id: string): number => c.captureCounts.get(id) ?? 0;

  return (
    <div className="app">
      <header className="topbar">
        <Wordmark />
        <span className="spacer" />
        <span className="meta">
          <span className="mono">IndexedDB · this browser</span>
          {c.persisted !== null && <span>Storage: {c.persisted ? 'persistent' : 'best-effort'}</span>}
        </span>
      </header>
      <main className="sheet home">
        <div className="home-banner"><StoreErrorBanner /></div>

        <section className="intro" aria-labelledby="home-h">
          <h1 id="home-h" className="home-title">Gameleira</h1>
          <p className="tagline">Every root, not just the parent PID.</p>
          <p className="lede">Reconstruct macOS process lineage from eslogger captures. Follow original parents, responsible
            processes, XPC services and exec chains to discover where processes actually came from. Everything stays in
            this browser; nothing is uploaded.</p>
        </section>
        <div className="canopy"><Canopy /></div>
        <div className="limb" aria-hidden="true" />

        <section className="workspace" aria-labelledby="sessions-h">
          <div className="stree">
            <div className="shead">
              <div>
                <h2 id="sessions-h">Sessions</h2>
                <p className="muted">One session per investigation, usually one Mac. Verdicts, notes and routine marks are kept
                  here; capture files are read again from disk when you reopen a session.</p>
              </div>
              {!creating && <button className="primary accent" onClick={() => { setCreating(true); }}>New session</button>}
            </div>

            {creating && (
              <form className="new-session" onSubmit={e => { void create(e); }}>
                <label>Session name <input autoFocus value={name} placeholder="e.g. finance MacBook, 12 Nov" onChange={e => { setName(e.target.value); }} /></label>
                <button type="submit" className="primary accent">Create</button>
                <button type="button" className="ghost" onClick={() => { setCreating(false); setName(''); }}>Cancel</button>
              </form>
            )}

            {c.sessions.length > 0 && (
              <div className="srow shdr" aria-hidden="true"><span>Session</span><span className="num">Captures</span><span>Last updated</span><span /></div>
            )}
            {c.sessionsLoaded && c.sessions.length === 0 && !creating && (
              <p className="node open muted">No sessions yet. Create one for each investigation.</p>
            )}
            <ul className="sessions" aria-label="Sessions">
              {c.sessions.map(s => (
                <li key={s.id} className={renaming === s.id || offer?.id === s.id ? 'node editing' : 'node srow'}>
                  {offer?.id === s.id ? (
                    <ReimportOffer session={s} folder={offer.folder} copy={offer.copy} diff={offer.diff} error={offerError}
                      onReimport={() => { void reimport(s.id, offer.copy); }}
                      onOpen={() => { setOffer(null); void c.openSession(s.id); }}
                      onCancel={() => { setOffer(null); }} />
                  ) : renaming === s.id ? (
                    <form className="new-session" onSubmit={e => { void rename(e, s.id); }}>
                      <label>New name <input autoFocus value={newName} onChange={e => { setNewName(e.target.value); }} /></label>
                      <button type="submit" className="primary accent">Save</button>
                      <button type="button" className="ghost" onClick={() => { setRenaming(null); }}>Cancel</button>
                    </form>
                  ) : (
                    <>
                      <button className="link sname truncate" aria-busy={checking === s.id} disabled={checking !== null}
                        onClick={() => { void open(s); }}>{s.name}</button>
                      <span className="num">{count(s.id)} <span className="muted">{count(s.id) === 1 ? 'capture' : 'captures'}</span></span>
                      <span className="mono muted when">{checking === s.id
                        ? <span role="status">Looking in “{c.saveFolder?.name}”…</span>
                        : <><span className="sr-only">updated </span>{when(s.updated)}</>}</span>
                      <span className="acts">
                        <button className="ghost" aria-label={`Rename ${s.name}`} onClick={() => { setRenaming(s.id); setNewName(s.name); }}>Rename</button>
                        <button className="ghost danger" aria-label={`Delete ${s.name}`} onClick={() => { void remove(s.id, s.name); }}>Delete</button>
                      </span>
                    </>
                  )}
                </li>
              ))}
            </ul>
            <section className="node open import" aria-labelledby="import-h">
              <div>
                <h3 id="import-h">Import a session</h3>
                <p className="muted small">A session saved from a session’s page, on this machine or another.</p>
              </div>
              <ImportSession />
            </section>
          </div>

          <div className="howto">
            <CaptureCommand hint="Run this on the Mac you are investigating and stop it with Ctrl-C. Then open a session and drop capture.jsonl into it." />
          </div>
        </section>

        <div className="field">
          <RootField />
          <div className="ground">
            <div className="specimens">
              {TRUNKS.map(t => <span key={t.kind} className={`specimen ${t.kind}`} style={{ left: `${t.x}%` }}>{t.label}</span>)}
            </div>
            <p className="caption"><i>Ficus</i> spp., the gameleira: aerial roots drop from its limbs, reach the ground and become
              trunks. Gameleira follows the roots of every process, not only the one its parent PID names.</p>
          </div>
        </div>
      </main>
    </div>
  );
}

const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;
const counts = (d: ExportDiff['file']): string => `${plural(d.reviewed, 'reviewed process', 'reviewed processes')}, ${plural(d.routine, 'routine mark', 'routine marks')}`;

/** Shown in a session's row instead of opening it, when the save folder holds a copy that differs from this browser's. */
function ReimportOffer({ session, folder, copy, diff, error, onReimport, onOpen, onCancel }: {
  session: Session; folder: string; copy: SavedCopy; diff: ExportDiff; error: string | null;
  onReimport(): void; onOpen(): void; onCancel(): void;
}) {
  const saved = new Date(copy.lastModified).toISOString();
  // Something changed here after the file was written: reimporting would drop it.
  const newerHere = session.updated > saved;
  return (
    <section className="reimport" aria-label={`Saved copy of ${session.name}`}>
      <h3>A saved copy of “{session.name}” is in “{folder}”</h3>
      <p className="small"><span className="mono">{copy.fileName}</span>, saved {when(saved)}.{' '}
        {copy.byId ? null : <span className="warn">It was saved from another session with the same name. </span>}
        The file has {counts(diff.file)}; this browser has {counts(diff.stored)}.</p>
      <p className="muted small">Reimporting replaces this session’s verdicts, notes and routine marks with the file’s.
        {newerHere && <> <span className="warn">This browser has changes made after the file was saved; they would be lost.</span></>}</p>
      <div className="acts">
        <button className="primary accent" onClick={onReimport}>Reimport and open</button>
        <button className="ghost" onClick={onOpen}>Open without it</button>
        <button className="ghost" onClick={onCancel}>Cancel</button>
      </div>
      {error && <p role="alert" className="error">{error}</p>}
    </section>
  );
}
