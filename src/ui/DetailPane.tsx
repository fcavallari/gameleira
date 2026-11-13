import { useEffect, useMemo, useRef, useState, type ReactNode, type RefObject } from 'react';
import type { LoadedCapture } from '../ingest/load';
import { ancestry, childrenIndex, displayName } from '../model/relations';
import type { ProcId, Process } from '../model/types';
import { basename, latestImage } from '../model/util';
import type { Finding, QueueItem } from '../rules/engine';
import { MITRE_NAMES } from '../rules/mitre';
import type { Severity } from '../rules/rules';
import { programKey } from '../session/routine';
import type { Status } from '../session/store';
import { useSession } from './session-context';
import { fmtArgs, fmtTime, NO_IDENTITY, toggleStatus } from './triage-model';

const SHOW_FIRST = 40;
const yesNo = (b: boolean): string => (b ? 'yes' : 'no');
const STATUS_TEXT: Record<Status, string> = { unreviewed: 'Unreviewed', confirmed: 'Confirmed suspicious', benign: 'Marked benign' };

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section aria-labelledby={id} className="dsec">
      <h3 id={id}>{title}</h3>
      {children}
    </section>
  );
}

function Sev({ s }: { s: Severity }) { return <span className={`badge sev-${s}`}>{s}</span>; }

/** One finding, written for a learner: what it means first, then the technique, then the evidence. */
function FindingBlock({ f }: { f: Finding }) {
  return (
    <article className={`why sev-border-${f.severity}`}>
      <div className="row"><Sev s={f.severity} /><strong>{f.title}</strong></div>
      <p className="explain">{f.explanation}</p>
      <div className="row mitre">
        {f.mitre.map(id => (
          <span key={id} className="chip" title="MITRE ATT&CK technique">{MITRE_NAMES[id] ? `${id} · ${MITRE_NAMES[id]}` : id}</span>
        ))}
      </div>
      <div className="evidence"><span className="muted small">Evidence</span><code className="mono wrap">{f.evidence}</code></div>
    </article>
  );
}

function Why({ findings }: { findings: Finding[] }) {
  return (
    <Section id="d-why" title="Why flagged">
      {findings.length > 0
        ? findings.map((f, i) => <FindingBlock key={`${f.ruleId}:${i}`} f={f} />)
        : <p className="muted">Not flagged on its own. You are looking at it because of where it sits in a chain or tree.</p>}
    </Section>
  );
}

function Step({ cap, id, onSelect }: { cap: LoadedCapture; id: ProcId; onSelect(id: ProcId): void }) {
  const p = cap.model.processes.get(id);
  return (
    <li>
      <button className="link" onClick={() => { onSelect(id); }}>{displayName(cap.model, id)}</button>
      {p && !p.ghost && <span className="muted small"> pid {p.pid}</span>}
    </li>
  );
}

function LaunchedBy({ cap, p, onSelect }: { cap: LoadedCapture; p: Process; onSelect(id: ProcId): void }) {
  const chain = useMemo(() => ancestry(cap.model, p.id, 'original').reverse(), [cap, p.id]);
  const responsible = p.responsible !== null && p.responsible !== p.id && !chain.includes(p.responsible) ? p.responsible : null;
  return (
    <Section id="d-launch" title="Launched by">
      <ol className="chain" aria-label="Launch chain, oldest first">
        {chain.map(id => <Step key={id} cap={cap} id={id} onSelect={onSelect} />)}
        <li className="self"><strong>{displayName(cap.model, p.id)}</strong>{!p.ghost && <span className="muted small"> pid {p.pid}</span>}</li>
      </ol>
      {chain.length === 0 && <p className="muted small">No parent is known for this process.</p>}
      {responsible !== null && (
        <p className="small"><span className="muted">Responsible process (the app that caused it): </span>
          <button className="link" onClick={() => { onSelect(responsible); }}>{displayName(cap.model, responsible)}</button></p>
      )}
    </Section>
  );
}

function Dl({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="dl">
      {rows.map(([k, v]) => <div key={k} className="dlrow"><dt>{k}</dt><dd>{v}</dd></div>)}
    </dl>
  );
}

function Details({ p }: { p: Process }) {
  const img = latestImage(p);
  const exec = [...p.images].reverse().find(i => i.args !== null);
  const history = p.images.filter(i => !i.inherited);
  const shown = history.length > 0 ? history : p.images;
  if (!img) {
    return (
      <Section id="d-details" title="Details">
        <p className="muted">This process started before the capture began, so only its pid is known. Its program, arguments and signature were never logged.</p>
      </Section>
    );
  }
  const rows: [string, ReactNode][] = [
    ['Command line', exec?.args ? <code className="mono wrap">{fmtArgs(exec.args)}</code> : <span className="muted">no exec event captured</span>],
    ['Working dir', exec?.cwd ? <code className="mono wrap">{exec.cwd}</code> : <span className="muted">unknown</span>],
    ['Program', <code className="mono wrap">{img.path ?? 'unknown'}</code>],
  ];
  if (shown.length > 1) rows.push(['Image history', <code className="mono wrap">{shown.map(i => i.path ?? '?').join(' → ')}</code>]);
  rows.push(
    ['Signing ID', img.signingId ?? <span className="muted">none</span>],
    ['Team ID', img.teamId ?? <span className="muted">none</span>],
    ['Apple platform binary', yesNo(img.isPlatform)],
    ['Ad-hoc signed', yesNo((img.csFlags & 0x2) !== 0)],
    ['Started', <span className="mono">{fmtTime(p.startTime)}</span>],
    ['Exited', <span className="mono">{p.exitTime ? fmtTime(p.exitTime) : 'not seen (still running, or the capture ended first)'}</span>],
  );
  return <Section id="d-details" title="Details"><Dl rows={rows} /></Section>;
}

function DidWhat({ cap, p, onSelect }: { cap: LoadedCapture; p: Process; onSelect(id: ProcId): void }) {
  const [allKids, setAllKids] = useState(false);
  const [allOps, setAllOps] = useState(false);
  const kids = useMemo(() => childrenIndex(cap.model, 'original').get(p.id) ?? [], [cap, p.id]);
  const severity = useMemo(() => {
    const m = new Map<ProcId, Severity>();
    for (const q of cap.analysis.queue) if (q.procId !== null) m.set(q.procId, q.severity);
    return m;
  }, [cap]);
  const kidsShown = allKids ? kids : kids.slice(0, SHOW_FIRST);
  const opsShown = allOps ? p.fileOps : p.fileOps.slice(0, SHOW_FIRST);
  return (
    <Section id="d-did" title="What it did">
      <h4>Started {kids.length} {kids.length === 1 ? 'process' : 'processes'}</h4>
      {kids.length === 0 ? <p className="muted small">None.</p> : (
        <ul className="kids">
          {kidsShown.map(id => {
            const sev = severity.get(id);
            const kid = cap.model.processes.get(id);
            return (
              <li key={id}>
                {sev && <Sev s={sev} />}
                <button className="link" onClick={() => { onSelect(id); }}>{displayName(cap.model, id)}</button>
                {kid && !kid.ghost && <span className="muted small"> pid {kid.pid}</span>}
              </li>
            );
          })}
        </ul>
      )}
      {kids.length > SHOW_FIRST && !allKids && <button onClick={() => { setAllKids(true); }}>Show all {kids.length}</button>}
      <h4>File activity ({p.fileOps.length})</h4>
      {p.fileOps.length === 0 ? <p className="muted small">None recorded.</p> : (
        <table className="ops">
          <thead><tr><th>Kind</th><th>Path</th></tr></thead>
          <tbody>
            {opsShown.map(op => (
              <tr key={op.seq}>
                <td>{op.kind}</td>
                <td className="mono wrap">
                  {op.path}
                  {op.toPath !== undefined && <> <span className="muted">→</span> {op.toPath}</>}
                  {op.xattr !== undefined && <span className="muted"> ({op.xattr})</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {p.fileOps.length > SHOW_FIRST && !allOps && <button onClick={() => { setAllOps(true); }}>Show all {p.fileOps.length}</button>}
    </Section>
  );
}

function ContextOnly({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) return null;
  return (
    <Section id="d-ctx" title="Low-signal observations">
      <p className="muted small">These were noticed but are common on their own, so they did not put this process in the queue.</p>
      {findings.map((f, i) => <FindingBlock key={`${f.ruleId}:${i}`} f={f} />)}
    </Section>
  );
}

const NOTE_DEBOUNCE_MS = 500;

/**
 * The note saves while typing (debounced), on blur, when the pane goes away and when the page is hidden. The save always
 * goes to the capture and process the note was opened on (`fingerprint`, `vkey`), never to whatever is active by then:
 * a capture that finishes loading switches the active capture and unmounts this field while the user is still typing.
 */
function Note({ vkey, fingerprint, status, saved, noteRef }: {
  vkey: string; fingerprint: string; status: Status; saved: string; noteRef: RefObject<HTMLTextAreaElement | null>;
}) {
  const { setVerdict } = useSession();
  const [text, setText] = useState(saved);
  const textRef = useRef(saved);
  const savedRef = useRef(saved);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  // The latest status and saver, read when a save fires (a click on Confirm may have come after the first keystroke).
  const live = useRef({ status, setVerdict });
  live.current = { status, setVerdict };
  // The saved note changing from outside (another save) is not a local edit.
  useEffect(() => { savedRef.current = saved; }, [saved]);

  const flush = useRef(() => {
    clearTimeout(timer.current);
    timer.current = undefined;
    if (textRef.current === savedRef.current) return;
    savedRef.current = textRef.current;
    void live.current.setVerdict(vkey, live.current.status, textRef.current, fingerprint);
  });

  useEffect(() => {
    const f = flush.current;
    window.addEventListener('pagehide', f);
    return () => { window.removeEventListener('pagehide', f); f(); };
  }, []);

  return (
    <label className="note-label">Note
      <textarea ref={noteRef} rows={3} value={text}
        onChange={e => {
          setText(e.target.value);
          textRef.current = e.target.value;
          clearTimeout(timer.current);
          timer.current = setTimeout(flush.current, NOTE_DEBOUNCE_MS);
        }}
        onBlur={flush.current} />
    </label>
  );
}

function Actions({ vkey, p, noteRef }: { vkey: string; p: Process | null; noteRef: RefObject<HTMLTextAreaElement | null> }) {
  const c = useSession();
  const fingerprint = c.active ?? '';
  const verdict = c.verdicts.get(vkey);
  const status: Status = verdict?.status ?? 'unreviewed';
  const img = p ? latestImage(p) : undefined;
  const pkey = img ? programKey(img) : null;
  const noIdentity = pkey === null || pkey === NO_IDENTITY;
  return (
    <Section id="d-actions" title="Actions">
      <p className="small"><span className="muted">Status: </span><strong>{STATUS_TEXT[status]}</strong></p>
      <div className="row">
        <button className="primary" aria-pressed={status === 'confirmed'} onClick={() => { void c.setVerdict(vkey, toggleStatus(status, 'confirmed'), undefined); }}>✔ Confirm suspicious <kbd>c</kbd></button>
        <button aria-pressed={status === 'benign'} onClick={() => { void c.setVerdict(vkey, toggleStatus(status, 'benign'), undefined); }}>✕ Benign <kbd>b</kbd></button>
        {p && (pkey !== null && c.routineKeys.has(pkey)
          ? <button onClick={() => { void c.removeRoutine(pkey); }}>Stop treating as routine</button>
          : <button disabled={noIdentity} title={noIdentity ? 'No signing ID, team ID or path: it cannot be told apart from other programs' : undefined}
              onClick={() => { if (img) void c.addRoutine(img); }}>Treat as routine</button>)}
        {p && <button onClick={() => { c.showInTree(p.id); }}>Show in tree <kbd>t</kbd></button>}
      </div>
      {p && <p className="muted small">“Treat as routine” hides every run of this program, in every capture of this session.</p>}
      <Note key={`${fingerprint}:${vkey}`} vkey={vkey} fingerprint={fingerprint} status={status} saved={verdict?.note ?? ''} noteRef={noteRef} />
      <p className="muted small">Press <kbd>n</kbd> to jump to the note. Press Confirm or Benign again to go back to unreviewed.</p>
    </Section>
  );
}

function PersistenceDetail({ cap, q, noteRef }: { cap: LoadedCapture; q: QueueItem; noteRef: RefObject<HTMLTextAreaElement | null> }) {
  const item = cap.model.persistence.find(i => i.id === q.persistenceId);
  const emitterId = item && cap.model.processes.has(item.emitter) ? item.emitter : undefined;
  const rows: [string, ReactNode][] = [];
  if (item) {
    rows.push(['Plist', <code className="mono wrap">{item.plistPath ?? 'unknown'}</code>]);
    rows.push(['Runs', <code className="mono wrap">{item.executablePath ?? 'unknown'}</code>]);
    if (item.appPath) rows.push(['App', <code className="mono wrap">{item.appPath}</code>]);
    rows.push(['Time', <span className="mono">{fmtTime(item.time)}</span>]);
    if (emitterId) rows.push(['Registered by', displayName(cap.model, emitterId)]);
  }
  return (
    <>
      <header className="dhead">
        <h2>{`persistence: ${basename(item?.plistPath ?? null) || q.key}`}</h2>
        <p className="muted small">A launch item registered while the capture ran. No captured process is tied to it, so there is no launch chain.</p>
      </header>
      <Why findings={q.findings} />
      <Section id="d-details" title="Details">
        {item ? <Dl rows={rows} /> : <p className="muted">Launch item details are not available.</p>}
      </Section>
      <Actions vkey={q.key} p={null} noteRef={noteRef} />
    </>
  );
}

/** The right-hand pane. `selKey` is the selected process id, or the queue key of a persistence-only item. */
export function DetailPane({ selKey, onSelectProc, noteRef }: {
  selKey: string | null; onSelectProc(id: ProcId): void; noteRef: RefObject<HTMLTextAreaElement | null>;
}) {
  const { capture: cap } = useSession();
  if (!cap) return null;
  if (selKey === null) {
    return (
      <p className="muted detail-empty">
        Select a flagged process on the left to see why it was flagged.
        Keys: <kbd>j</kbd>/<kbd>k</kbd> move, <kbd>c</kbd> confirm, <kbd>b</kbd> benign, <kbd>n</kbd> note, <kbd>t</kbd> show in tree.
      </p>
    );
  }
  const p = cap.model.processes.get(selKey);
  if (!p) {
    const q = cap.analysis.queue.find(x => x.key === selKey && x.kind === 'persistence');
    return q ? <PersistenceDetail cap={cap} q={q} noteRef={noteRef} /> : null;
  }
  const img = latestImage(p);
  return (
    <>
      <header className="dhead">
        <h2>{displayName(cap.model, p.id)}</h2>
        <p className="muted small">
          {p.ghost ? 'started before the capture' : `pid ${p.pid}`}
          {img?.signingId ? ` · ${img.signingId}` : ''}
          {img?.isPlatform ? ' · Apple platform binary' : ''}
        </p>
      </header>
      <Why findings={cap.analysis.findings.get(p.id) ?? []} />
      <LaunchedBy cap={cap} p={p} onSelect={onSelectProc} />
      <Details p={p} />
      <DidWhat cap={cap} p={p} onSelect={onSelectProc} />
      <ContextOnly findings={cap.analysis.contextOnly.get(p.id) ?? []} />
      <Actions vkey={p.id} p={p} noteRef={noteRef} />
    </>
  );
}
