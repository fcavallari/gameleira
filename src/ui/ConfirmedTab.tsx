import { useState } from 'react';
import { exportSession, saveFileName } from '../session/export';
import { folderSupported, permitted, writeFile } from '../session/folder';
import { useSession } from './session-context';

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

export interface SaveSession {
  save(): Promise<void>;
  /** Picks another folder for later saves (folder saving only). */
  changeFolder(): Promise<void>;
  error: string | null;
  /** What the last save or folder change did, for a status line. */
  done: string | null;
}

/**
 * Saves the open session as a JSON file, with the export options chosen on the Confirmed tab. Where the browser can
 * write into a folder (Chromium), the file goes into the remembered folder, asking for one the first time, and replaces
 * the previous save of this session there; opening the session from the home page later looks in that folder.
 * Elsewhere the file is downloaded. Either way it is named `<name>.<id hash>.gameleira-session.json`.
 */
export function useSaveSession(): SaveSession {
  const c = useSession();
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const session = c.session!;
  const fail = (e: unknown) => { setError(e instanceof Error ? e.message : String(e)); };

  const save = async () => {
    setError(null); setDone(null);
    const name = saveFileName(session);
    try {
      if (folderSupported()) {
        // Permission first: the browser only asks while it is handling the click.
        let dir = c.saveFolder && await permitted(c.saveFolder, 'readwrite', true) ? c.saveFolder : null;
        dir ??= await c.chooseSaveFolder();
        if (!dir) return;   // picker closed: nothing saved, nothing to report
        const data = await exportSession(c.store, session.id, c.exportOpts, c.captures);
        await writeFile(dir, name, JSON.stringify(data, null, 2));
        setDone(`Saved ${name} in “${dir.name}”.`);
        return;
      }
      const data = await exportSession(c.store, session.id, c.exportOpts, c.captures);
      const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => { URL.revokeObjectURL(url); }, 1000);
    } catch (e) { fail(e); }
  };

  const changeFolder = async () => {
    setError(null); setDone(null);
    try {
      const dir = await c.chooseSaveFolder();
      if (dir) setDone(`Sessions will be saved in “${dir.name}”.`);
    } catch (e) { fail(e); }
  };
  return { save, changeFolder, error, done };
}

/** Where Save session puts the file, with a way to change it: only where the browser saves into a folder. */
export function SaveFolderNote({ s }: { s: SaveSession }) {
  const c = useSession();
  if (!folderSupported()) return null;
  return c.saveFolder
    ? <>Saves into “{c.saveFolder.name}”. <button className="link" onClick={() => { void s.changeFolder(); }}>Change folder</button></>
    : <>The first save asks for a folder; opening a session later looks there for a newer copy.</>;
}

export function ConfirmedTab() {
  const c = useSession();
  const saver = useSaveSession();
  const { save: doExport, error } = saver;
  const { includeEnv, redactArgs } = c.exportOpts;
  const fileName = (fp: string): string => c.capRecs.find(r => r.fingerprint === fp)?.fileName ?? 'unknown capture';
  const confirmed = c.allVerdicts
    .filter(v => v.status === 'confirmed')
    .sort((a, b) => fileName(a.fingerprint).localeCompare(fileName(b.fingerprint)) || a.snapshot.name.localeCompare(b.snapshot.name));

  /** exportSession adds process details only for loaded captures; a launch item (key `i:…`) has no process, so none to add. */
  const isLaunchItem = (key: string): boolean => key.startsWith('i:');
  const leftOut = confirmed.filter(v => !isLaunchItem(v.procKey) && !c.captures.has(v.fingerprint)).length;
  const hasLaunchItems = confirmed.some(v => isLaunchItem(v.procKey));

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
        {folderSupported() && <p className="muted small"><SaveFolderNote s={saver} /></p>}
        {saver.done && <p role="status" className="small">{saver.done}</p>}
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
